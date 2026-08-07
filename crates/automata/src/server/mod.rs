//! Product composition for one horizontally scalable control-plane replica.

mod composition;
mod config;
mod maintenance;
mod readiness;

use std::future::Future;

use anyhow::{Context as _, Result};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{app::http, build_info::BuildInfo, cli::ServerArgs, shutdown};

use composition::ProductionComponents;
pub use composition::ServerCompositionError;
pub use config::{SecretLoadError, SecretSource, ServerConfig, ServerConfigError};
pub use maintenance::{
    ControlPlaneMaintenanceLoop, MaintenanceClock, MaintenanceLoopConfigError,
    SystemMaintenanceClock,
};
pub use readiness::{
    Readiness, ReadinessMonitor, ReadinessMonitorError, ReadinessProbe, ReadinessProbeError,
    ReadinessSnapshot,
};

/// Binds both product listeners, composes concrete adapters, and serves until shutdown.
///
/// # Errors
///
/// Returns a sanitized startup or service error. Configuration secrets, PEM
/// material, database URLs, and object-store endpoints are never included.
pub async fn serve(args: &ServerArgs) -> Result<()> {
    let config = ServerConfig::from_args(args).context("invalid server configuration")?;
    let http_listener = TcpListener::bind(config.http_listen)
        .await
        .context("failed to bind human HTTP listener")?;
    let runner_listener = TcpListener::bind(config.runner_listen)
        .await
        .context("failed to bind runner-control listener")?;
    let results_listener = TcpListener::bind(config.results_listen)
        .await
        .context("failed to bind Results listener")?;
    let http_address = http_listener
        .local_addr()
        .context("failed to inspect human HTTP listener")?;
    let runner_address = runner_listener
        .local_addr()
        .context("failed to inspect runner-control listener")?;
    let results_address = results_listener
        .local_addr()
        .context("failed to inspect Results listener")?;

    let process_cancellation = CancellationToken::new();
    let signal_cancellation = process_cancellation.clone();
    let signal_task = tokio::spawn(async move {
        tokio::select! {
            () = shutdown::wait() => signal_cancellation.cancel(),
            () = signal_cancellation.cancelled() => {}
        }
    });

    let readiness = Readiness::initializing();
    let components = tokio::select! {
        result = ProductionComponents::initialize(&config, runner_listener, &readiness) => {
            match result {
                Ok(components) => components,
                Err(error) => {
                    process_cancellation.cancel();
                    let _ = signal_task.await;
                    return Err(error).context("failed to initialize control-plane adapters");
                }
            }
        }
        () = process_cancellation.cancelled() => {
            let _ = signal_task.await;
            return Ok(());
        }
    };
    let router = match http::router_with_readiness(readiness.clone()) {
        Ok(router) => router.merge(components.human_api.clone()),
        Err(error) => {
            process_cancellation.cancel();
            let _ = signal_task.await;
            return Err(error).context("failed to initialize HTTP application");
        }
    };

    let build = BuildInfo::current();
    info!(
        http_address = %http_address,
        runner_address = %runner_address,
        results_address = %results_address,
        results_public_url = %config.results_public_endpoint.url(),
        version = build.version,
        commit = build.commit,
        "control plane listening"
    );
    let shutdown_signal = process_cancellation.clone().cancelled_owned();
    let result = run_services(
        http_listener,
        results_listener,
        router,
        components,
        readiness,
        shutdown_signal,
        process_cancellation.clone(),
    )
    .await;
    process_cancellation.cancel();
    let _ = signal_task.await;
    result
}

async fn run_services<S>(
    http_listener: TcpListener,
    results_listener: TcpListener,
    router: axum::Router,
    components: ProductionComponents,
    readiness: Readiness,
    shutdown_signal: S,
    cancellation: CancellationToken,
) -> Result<()>
where
    S: Future<Output = ()>,
{
    let http_cancellation = cancellation.clone();
    let runner_cancellation = cancellation.child_token();
    let results_cancellation = cancellation.child_token();
    let monitor_cancellation = cancellation.child_token();
    let maintenance_cancellation = cancellation.child_token();

    let http = async move {
        axum::serve(http_listener, router)
            .with_graceful_shutdown(async move {
                http_cancellation.cancelled().await;
            })
            .await
            .map_err(|_| ManagedServiceError::HumanHttp)
    };
    let runner = async move {
        components
            .runner_server
            .serve(runner_cancellation)
            .await
            .map_err(|_| ManagedServiceError::RunnerControl)
    };
    let results = async move {
        axum::serve(results_listener, components.results_api.clone())
            .with_graceful_shutdown(async move {
                results_cancellation.cancelled().await;
            })
            .await
            .map_err(|_| ManagedServiceError::ResultsHttp)
    };
    let monitor = async move {
        components
            .readiness_monitor
            .run(readiness, monitor_cancellation)
            .await;
        Ok(())
    };
    let maintenance = async move {
        components
            .maintenance_loop
            .run(maintenance_cancellation)
            .await;
        Ok(())
    };
    supervise_services(
        (http, runner, results, monitor, maintenance),
        shutdown_signal,
        cancellation,
    )
    .await
    .context("control-plane service supervision failed")
}

/// Stable identities for the continuously supervised replica services.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedService {
    /// Human/API HTTP and SSR listener.
    HumanHttp,
    /// Direct-mTLS runner-control listener.
    RunnerControl,
    /// GitHub Actions Results compatibility listener.
    ResultsHttp,
    /// Active database and object-store readiness monitor.
    ReadinessMonitor,
    /// Bounded expired-lease and stale-session maintenance loop.
    ControlPlaneMaintenance,
}

/// Sanitized fatal failure returned by one managed service.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ManagedServiceError {
    /// The human HTTP listener failed.
    #[error("human HTTP service failed")]
    HumanHttp,
    /// The runner-control listener failed.
    #[error("runner-control service failed")]
    RunnerControl,
    /// The GitHub Actions Results HTTP listener failed.
    #[error("Results HTTP service failed")]
    ResultsHttp,
    /// The readiness monitor failed.
    #[error("readiness monitor failed")]
    ReadinessMonitor,
    /// The control-plane maintenance loop failed.
    #[error("control-plane maintenance service failed")]
    ControlPlaneMaintenance,
}

/// Fatal result from shared service supervision.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ServiceSupervisorError {
    /// One service returned a fatal error.
    #[error(transparent)]
    Service(#[from] ManagedServiceError),
    /// A long-running service exited successfully without process shutdown.
    #[error("{0:?} stopped unexpectedly")]
    UnexpectedStop(ManagedService),
}

enum ServiceExit {
    Shutdown,
    Service(ManagedService, Result<(), ManagedServiceError>),
}

/// Runs all replica services under one cancellation boundary.
///
/// A shutdown signal cancels every service and waits for all of them to drain.
/// An early service exit cancels its siblings and is fatal, including an
/// otherwise-successful return. Keeping this coordinator generic makes process
/// semantics testable with fake service ports and keeps provider adapters out of
/// the orchestration policy.
///
/// # Errors
///
/// Returns the first fatal service failure or identifies an unexpected clean exit.
pub async fn supervise_services<H, R, A, M, C, S>(
    services: (H, R, A, M, C),
    shutdown_signal: S,
    cancellation: CancellationToken,
) -> Result<(), ServiceSupervisorError>
where
    H: Future<Output = Result<(), ManagedServiceError>>,
    R: Future<Output = Result<(), ManagedServiceError>>,
    A: Future<Output = Result<(), ManagedServiceError>>,
    M: Future<Output = Result<(), ManagedServiceError>>,
    C: Future<Output = Result<(), ManagedServiceError>>,
    S: Future<Output = ()>,
{
    let (http, runner, results, monitor, maintenance) = services;
    tokio::pin!(http);
    tokio::pin!(runner);
    tokio::pin!(results);
    tokio::pin!(monitor);
    tokio::pin!(maintenance);
    tokio::pin!(shutdown_signal);

    let exit = tokio::select! {
        biased;
        () = &mut shutdown_signal => ServiceExit::Shutdown,
        result = &mut http => ServiceExit::Service(ManagedService::HumanHttp, result),
        result = &mut runner => ServiceExit::Service(ManagedService::RunnerControl, result),
        result = &mut results => ServiceExit::Service(ManagedService::ResultsHttp, result),
        result = &mut monitor => ServiceExit::Service(ManagedService::ReadinessMonitor, result),
        result = &mut maintenance => ServiceExit::Service(ManagedService::ControlPlaneMaintenance, result),
    };
    cancellation.cancel();

    match exit {
        ServiceExit::Shutdown => {
            let (http_result, runner_result, results_result, monitor_result, maintenance_result) =
                tokio::join!(http, runner, results, monitor, maintenance);
            http_result?;
            runner_result?;
            results_result?;
            monitor_result?;
            maintenance_result?;
            Ok(())
        }
        ServiceExit::Service(service, result) => {
            let sibling_result = match service {
                ManagedService::HumanHttp => {
                    let (runner_result, results_result, monitor_result, maintenance_result) =
                        tokio::join!(runner, results, monitor, maintenance);
                    runner_result
                        .and(monitor_result)
                        .and(maintenance_result)
                        .and(results_result)
                }
                ManagedService::RunnerControl => {
                    let (http_result, results_result, monitor_result, maintenance_result) =
                        tokio::join!(http, results, monitor, maintenance);
                    http_result
                        .and(monitor_result)
                        .and(maintenance_result)
                        .and(results_result)
                }
                ManagedService::ResultsHttp => {
                    let (http_result, runner_result, monitor_result, maintenance_result) =
                        tokio::join!(http, runner, monitor, maintenance);
                    http_result
                        .and(runner_result)
                        .and(monitor_result)
                        .and(maintenance_result)
                }
                ManagedService::ReadinessMonitor => {
                    let (http_result, runner_result, results_result, maintenance_result) =
                        tokio::join!(http, runner, results, maintenance);
                    http_result
                        .and(runner_result)
                        .and(results_result)
                        .and(maintenance_result)
                }
                ManagedService::ControlPlaneMaintenance => {
                    let (http_result, runner_result, results_result, monitor_result) =
                        tokio::join!(http, runner, results, monitor);
                    http_result
                        .and(runner_result)
                        .and(results_result)
                        .and(monitor_result)
                }
            };
            result?;
            sibling_result?;
            Err(ServiceSupervisorError::UnexpectedStop(service))
        }
    }
}
