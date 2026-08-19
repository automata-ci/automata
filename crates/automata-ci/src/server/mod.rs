//! Product composition for one horizontally scalable control-plane replica.

mod composition;
mod config;
mod github_job_runtime_authority;
mod github_provider;
mod github_provider_config;
mod github_provider_credentials;
mod github_provider_runtime;
mod github_webhook;
pub(crate) mod human_auth;
pub(crate) mod installation_setup;
mod maintenance;
mod managed_secret_delivery;
pub(crate) mod metrics;
mod protected_environment_gate;
mod protected_environment_review;
mod provider_webhook;
mod provisioning_workload_auth;
mod readiness;
mod secret_cleanup;
mod secret_custody;
mod secret_loop_support;
mod secret_management;
mod secret_mutation_recovery;
mod state_metrics;
mod windows_runner_admission;
mod workflow_dispatch;
mod workflow_rerun;
mod workload_oidc;

use std::{future::Future, net::SocketAddr, pin::Pin, sync::Arc, time::Duration};

use anyhow::{Context as _, Result};
use automata_ci_blob::BlobStoreErrorKind;
use automata_ci_provisioning_grpc::ManagementGrpcServer;
use automata_ci_runner_transport::RunnerControlServer;
use automata_ci_store::{
    HumanLogCommitNotificationHub, HumanLogCommitNotificationSource,
    LogicalInstanceResultStoreError, LogicalInstanceResultValueError, LogicalJobResultStoreError,
    LogicalJobResultValueError, StoreError,
};
use automata_ci_store_postgres::PostgresLogCommitListener;
use automata_ci_workflow_service::{
    AutonomousWorkflowService, LogicalResultProjectionError, LogicalResultProjectionOutcome,
    LogicalResultProjectionService, LogicalRunFinalizationService, ReusableWorkflowRuntimeService,
};
use axum::{
    extract::Request,
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse as _, Response},
};
use futures::{StreamExt as _, stream::FuturesUnordered};
use thiserror::Error;
use tokio::{net::TcpListener, sync::oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{app::http, build_info::BuildInfo, cli::ServerArgs, shutdown};

use composition::ProductionComponents;
pub use composition::ServerCompositionError;
pub use config::{
    AuthEncryptionConfig, BootstrapConfig, ControlPlaneEncryptionConfig, HumanAuthConfig,
    ManagementConfig, SecretEncryptionConfig, SecretEncryptionLoadError, SecretLoadError,
    SecretSource, ServerConfig, ServerConfigError, VersionedSecretSource,
    VersionedSecretSourceParseError,
};
pub(crate) use config::{S3ConnectionConfig, S3Transport};
pub use github_provider::{
    GithubProviderBootstrapError, GithubProviderBootstrapPlan, GithubProviderBootstrapReady,
    GithubProviderCredentialRequestResolver,
};
pub(crate) use github_provider_config::DatabaseGithubProviderConfig;
pub use github_provider_config::{
    GithubProviderAppConfig, GithubProviderAuthorityConfig, GithubProviderAuthorityId,
    GithubProviderConfig, GithubProviderConfigError, GithubProviderConnectionId,
    GithubProviderInternalRepositoryId, GithubProviderRepositoryConfig,
    GithubProviderScheduleConfig, GithubProviderTransport, GithubProviderWebhookConfig,
    MAX_GITHUB_PROVIDER_REPOSITORIES,
};
pub use github_provider_credentials::{
    GithubProviderCredentialAdapterConfigurationError, GithubProviderCredentialAdapters,
    GithubProviderCredentialReleaseSupervisor, GithubWorkflowPermissionObservationError,
    MAX_GITHUB_PROVIDER_SUPERVISED_RELEASES,
};
use github_provider_runtime::GithubProviderFatalNotification;
pub use github_provider_runtime::{
    GithubProviderRuntime, GithubProviderRuntimeBuildError, GithubProviderRuntimeBuilder,
    GithubProviderRuntimeError, GithubProviderRuntimePolicy, GithubProviderRuntimePolicyError,
    GithubProviderRuntimeShape,
};
pub use github_webhook::{
    GITHUB_WEBHOOK_HTTP_DEADLINE, GITHUB_WEBHOOK_PATH, MAX_GITHUB_WEBHOOK_HTTP_BODY_BYTES,
    router_with_github_webhook_outside_human_auth,
};
pub use maintenance::{
    ControlPlaneMaintenanceLoop, MaintenanceClock, MaintenanceLoopConfigError,
    SystemMaintenanceClock,
};
pub use metrics::ControlPlaneMetrics;
pub use provider_webhook::{
    PROVIDER_WEBHOOK_HTTP_DEADLINE, PROVIDER_WEBHOOK_PATH_PREFIX,
    router_with_provider_webhooks_outside_human_auth,
};
pub use readiness::{
    Readiness, ReadinessMonitor, ReadinessMonitorError, ReadinessProbe, ReadinessProbeError,
    ReadinessSnapshot,
};
pub use windows_runner_admission::{
    MAX_WINDOWS_RUNNER_ADMISSION_CONFIG_BYTES, WindowsRunnerAdmissionConfigError,
    WindowsRunnerAdmissionPolicy,
};
pub use workload_oidc::{WorkloadOidcConfig, WorkloadOidcProductError};

const RESULTS_HTTP_REQUEST_TIMEOUT: Duration = Duration::from_mins(5);
const LOGICAL_RESULT_PROJECTION_IDLE_POLL: Duration = Duration::from_millis(250);
const LOGICAL_RESULT_PROJECTION_RETRY_INITIAL: Duration = Duration::from_secs(1);
const LOGICAL_RESULT_PROJECTION_RETRY_MAX: Duration = Duration::from_secs(30);
const LOGICAL_RESULT_PROJECTION_MAX_CONSECUTIVE_FAILURES: u8 = 8;

/// Binds all product listeners, composes concrete adapters, and serves until shutdown.
///
/// # Errors
///
/// Returns a sanitized startup or service error. Configuration secrets, PEM
/// material, database URLs, and object-store endpoints are never included.
#[allow(clippy::too_many_lines)] // One cancellation tree keeps listener startup and teardown ordering explicit.
pub async fn serve(args: &ServerArgs) -> Result<()> {
    let config = ServerConfig::from_args(args).context("invalid server configuration")?;
    let build = BuildInfo::current();
    let metrics = ControlPlaneMetrics::new(build).context("failed to initialize metrics")?;
    let BoundListeners {
        http_listener,
        runner_listener,
        management_listener,
        results_listener,
        metrics_listener,
        http_address,
        runner_address,
        management_address,
        results_address,
        metrics_address,
    } = BoundListeners::bind(&config).await?;

    let process_cancellation = CancellationToken::new();
    let signal_cancellation = process_cancellation.clone();
    let signal_task = tokio::spawn(async move {
        tokio::select! {
            () = shutdown::wait() => signal_cancellation.cancel(),
            () = signal_cancellation.cancelled() => {}
        }
    });

    let readiness = Readiness::initializing();
    let metrics_cancellation = process_cancellation.child_token();
    let (state_sampler_sender, state_sampler_receiver) = oneshot::channel();
    let mut metrics_http = metrics_http_service(
        metrics_listener,
        metrics.clone(),
        metrics_cancellation,
        state_sampler_receiver,
    );
    let initialization = ProductionComponents::initialize(
        &config,
        runner_listener,
        management_listener,
        &readiness,
        &metrics,
    );
    let components = match Box::pin(race_initialization(
        initialization,
        &mut metrics_http,
        &process_cancellation,
    ))
    .await
    {
        InitializationRace::Initialization(Ok(components)) => components,
        InitializationRace::Initialization(Err(error)) => {
            process_cancellation.cancel();
            let _ = metrics_http.as_mut().await;
            let _ = signal_task.await;
            return Err(error).context("failed to initialize control-plane adapters");
        }
        InitializationRace::Metrics(Err(error)) => {
            process_cancellation.cancel();
            let _ = signal_task.await;
            return Err(error).context("metrics HTTP service failed during initialization");
        }
        InitializationRace::Metrics(Ok(())) => {
            process_cancellation.cancel();
            let _ = signal_task.await;
            return Err(ServiceSupervisorError::UnexpectedStop(ManagedService::MetricsHttp).into());
        }
        InitializationRace::Shutdown => {
            process_cancellation.cancel();
            metrics_http
                .as_mut()
                .await
                .context("metrics HTTP service failed during shutdown")?;
            let _ = signal_task.await;
            return Ok(());
        }
    };
    if state_sampler_sender
        .send(components.state_sampler.clone())
        .is_err()
    {
        process_cancellation.cancel();
        let _ = metrics_http.as_mut().await;
        let _ = signal_task.await;
        return Err(ServiceSupervisorError::UnexpectedStop(ManagedService::MetricsHttp).into());
    }
    let github_provider_ingress = components
        .github_provider
        .as_ref()
        .map(GithubProviderRuntime::ingress);
    let router = match http::router_with_readiness_web_data(
        readiness.clone(),
        components.web_data.clone(),
        components.rbac_web_data.clone(),
        components.setup_page_availability.clone(),
        components.web_fallback_context.clone(),
    ) {
        Ok(router) => {
            let router = router.merge(components.human_api.clone());
            let router = match components.human_request_authentication.clone() {
                Some(authentication) => router.layer(axum::middleware::from_fn_with_state(
                    authentication,
                    crate::app::human_auth_middleware::authenticate_human_request,
                )),
                None => router,
            };
            // One-time enrollment possession is the complete authentication
            // boundary and must not depend on a configured human identity provider.
            let router = router.merge(components.runner_enrollment_redeem_api.clone());
            // Live transports authenticate only the one-time, origin-bound
            // ticket and must remain outside browser/CLI session parsing.
            let router = router.merge(components.live_log_stream_api.clone());
            let router = match config.management() {
                Some(management) => {
                    let router = router.merge(crate::app::shard_capabilities::router(
                        management.authority().shard_id(),
                    ));
                    match components.delegated_actor_api.clone() {
                        Some(delegated_actor_api) => router.merge(delegated_actor_api),
                        None => router,
                    }
                }
                None => router,
            };
            let router = router_with_optional_github_webhook(router, github_provider_ingress);
            http::finalize_combined_router(router, metrics.clone())
        }
        Err(error) => {
            process_cancellation.cancel();
            let _ = metrics_http.as_mut().await;
            let _ = signal_task.await;
            return Err(error).context("failed to initialize HTTP application");
        }
    };

    info!(
        http_address = %http_address,
        runner_address = %runner_address,
        management_address = ?management_address,
        results_address = %results_address,
        metrics_address = ?metrics_address,
        results_public_url = %config.results_public_endpoint.url(),
        version = build.version,
        commit = build.commit,
        "control plane listening"
    );
    let shutdown_signal = process_cancellation.clone().cancelled_owned();
    let services = ServiceInputs {
        http_listener,
        results_listener,
        metrics_http,
        router,
        components,
        readiness,
        metrics,
    };
    let result = Box::pin(run_services(
        services,
        shutdown_signal,
        process_cancellation.clone(),
    ))
    .await;
    process_cancellation.cancel();
    let _ = signal_task.await;
    result
}

fn router_with_optional_github_webhook(
    human_router: axum::Router,
    ingress: Option<std::sync::Arc<automata_ci_github_delivery::GithubDeliveryIngress>>,
) -> axum::Router {
    match ingress {
        Some(ingress) => router_with_github_webhook_outside_human_auth(human_router, ingress),
        None => human_router,
    }
}

struct BoundListeners {
    http_listener: TcpListener,
    runner_listener: TcpListener,
    management_listener: Option<TcpListener>,
    results_listener: TcpListener,
    metrics_listener: Option<TcpListener>,
    http_address: SocketAddr,
    runner_address: SocketAddr,
    management_address: Option<SocketAddr>,
    results_address: SocketAddr,
    metrics_address: Option<SocketAddr>,
}

impl BoundListeners {
    async fn bind(config: &ServerConfig) -> Result<Self> {
        let http_listener = TcpListener::bind(config.http_listen)
            .await
            .context("failed to bind human HTTP listener")?;
        let runner_listener = TcpListener::bind(config.runner_listen)
            .await
            .context("failed to bind runner-control listener")?;
        let management_listener = if let Some(management) = config.management() {
            Some(
                TcpListener::bind(management.listen)
                    .await
                    .context("failed to bind management listener")?,
            )
        } else {
            None
        };
        let results_listener = TcpListener::bind(config.results_listen)
            .await
            .context("failed to bind Results listener")?;
        let metrics_listener = if let Some(listen) = config.metrics_listen {
            Some(
                TcpListener::bind(listen)
                    .await
                    .context("failed to bind metrics listener")?,
            )
        } else {
            None
        };
        Ok(Self {
            http_address: http_listener
                .local_addr()
                .context("failed to inspect human HTTP listener")?,
            runner_address: runner_listener
                .local_addr()
                .context("failed to inspect runner-control listener")?,
            management_address: management_listener
                .as_ref()
                .map(TcpListener::local_addr)
                .transpose()
                .context("failed to inspect management listener")?,
            results_address: results_listener
                .local_addr()
                .context("failed to inspect Results listener")?,
            metrics_address: metrics_listener
                .as_ref()
                .map(TcpListener::local_addr)
                .transpose()
                .context("failed to inspect metrics listener")?,
            http_listener,
            runner_listener,
            management_listener,
            results_listener,
            metrics_listener,
        })
    }
}

type MetricsHttpFuture = Pin<Box<dyn Future<Output = Result<(), ManagedServiceError>> + Send>>;

enum InitializationRace<T, E> {
    Initialization(Result<T, E>),
    Metrics(Result<(), ManagedServiceError>),
    Shutdown,
}

async fn race_initialization<F, T, E>(
    initialization: F,
    metrics_http: &mut MetricsHttpFuture,
    cancellation: &CancellationToken,
) -> InitializationRace<T, E>
where
    F: Future<Output = Result<T, E>>,
{
    tokio::select! {
        biased;
        result = metrics_http.as_mut() => InitializationRace::Metrics(result),
        result = initialization => InitializationRace::Initialization(result),
        () = cancellation.cancelled() => InitializationRace::Shutdown,
    }
}

fn metrics_http_service(
    listener: Option<TcpListener>,
    metrics: ControlPlaneMetrics,
    cancellation: CancellationToken,
    state_sampler_receiver: oneshot::Receiver<state_metrics::ControlPlaneStateSampler>,
) -> MetricsHttpFuture {
    Box::pin(async move {
        let Some(listener) = listener else {
            let _state_sampler_receiver = state_sampler_receiver;
            cancellation.cancelled().await;
            return Ok(());
        };

        let server_cancellation = cancellation.clone();
        let process_sampler_cancellation = cancellation.clone();
        let state_sampler_cancellation = cancellation.clone();
        let handoff_cancellation = cancellation.clone();
        let metrics_router = metrics.exporter().router();
        let process_sampler = metrics.process_sampler();
        let server = async move {
            axum::serve(listener, metrics_router)
                .with_graceful_shutdown(async move {
                    server_cancellation.cancelled().await;
                })
                .await
        };
        let samplers = async move {
            let state_sampler = async move {
                let state_sampler = tokio::select! {
                    biased;
                    () = handoff_cancellation.cancelled() => None,
                    result = state_sampler_receiver => result.ok(),
                };
                if let Some(state_sampler) = state_sampler {
                    state_sampler
                        .run_until_cancelled(state_sampler_cancellation.cancelled_owned())
                        .await;
                }
            };
            tokio::join!(
                process_sampler.run_until_cancelled(process_sampler_cancellation.cancelled_owned()),
                state_sampler,
            );
        };
        tokio::pin!(server);
        tokio::pin!(samplers);

        let result = tokio::select! {
            result = &mut server => {
                cancellation.cancel();
                samplers.await;
                result
            }
            () = &mut samplers => server.await,
        };
        result.map_err(|_| ManagedServiceError::MetricsHttp)
    })
}

struct ServiceInputs {
    http_listener: TcpListener,
    results_listener: TcpListener,
    metrics_http: MetricsHttpFuture,
    router: axum::Router,
    components: ProductionComponents,
    readiness: Readiness,
    metrics: ControlPlaneMetrics,
}

#[allow(clippy::too_many_lines)] // The fixed cancellation tree keeps every managed child explicit.
async fn run_services<S>(
    services: ServiceInputs,
    shutdown_signal: S,
    cancellation: CancellationToken,
) -> Result<()>
where
    S: Future<Output = ()> + Send,
{
    let ServiceInputs {
        http_listener,
        results_listener,
        metrics_http,
        router,
        components,
        readiness,
        metrics,
    } = services;
    let mut components = components;
    let github_provider = components.github_provider.take();
    let management_server = components.management_server.take();
    let mut log_commit_listener = components
        .log_commit_listener
        .take()
        .expect("production composition always installs the log notification listener");
    let log_commit_notifications = Arc::clone(&components.log_commit_notifications);
    let http_cancellation = cancellation.clone();
    let log_notification_cancellation = cancellation.child_token();
    let runner_cancellation = cancellation.child_token();
    let results_cancellation = cancellation.child_token();
    let monitor_cancellation = cancellation.child_token();
    let maintenance_cancellation = cancellation.child_token();
    let logical_run_finalization_cancellation = cancellation.child_token();
    let logical_result_projection_cancellation = cancellation.child_token();
    let autonomous_workflow_cancellation = cancellation.child_token();
    let secret_cleanup_cancellation = cancellation.child_token();
    let secret_recovery_cancellation = cancellation.child_token();
    let github_provider_cancellation = cancellation.child_token();

    let http = async move {
        let server_cancellation = http_cancellation.clone();
        let server = async move {
            axum::serve(http_listener, router)
                .with_graceful_shutdown(async move {
                    server_cancellation.cancelled().await;
                })
                .await
        };
        let notifications = run_log_commit_notifications(
            &mut log_commit_listener,
            &log_commit_notifications,
            log_notification_cancellation,
        );
        tokio::pin!(server);
        tokio::pin!(notifications);
        tokio::select! {
            result = &mut server => {
                http_cancellation.cancel();
                notifications.await;
                result.map_err(|_| ManagedServiceError::HumanHttp)
            }
            () = &mut notifications => {
                server.await.map_err(|_| ManagedServiceError::HumanHttp)
            }
        }
    };
    let runner = run_machine_listeners(
        components.runner_server,
        management_server,
        runner_cancellation,
    );
    let results_api =
        results_router_with_deadline(components.results_api.clone(), RESULTS_HTTP_REQUEST_TIMEOUT);
    let results = async move {
        axum::serve(results_listener, results_api)
            .with_graceful_shutdown(async move {
                results_cancellation.cancelled().await;
            })
            .await
            .map_err(|_| ManagedServiceError::ResultsHttp)
    };
    let autonomous_workflow_readiness = readiness.clone();
    let monitor = async move {
        components
            .readiness_monitor
            .run(readiness, monitor_cancellation)
            .await;
        Ok(())
    };
    let maintenance = async move {
        match (
            components.secret_cleanup_loop,
            components.secret_mutation_recovery_loop,
        ) {
            (Some(secret_cleanup_loop), Some(secret_recovery_loop)) => {
                tokio::join!(
                    components.maintenance_loop.run(maintenance_cancellation),
                    secret_cleanup_loop.run(secret_cleanup_cancellation),
                    secret_recovery_loop.run(secret_recovery_cancellation),
                );
            }
            (None, None) => {
                components
                    .maintenance_loop
                    .run(maintenance_cancellation)
                    .await;
            }
            _ => {
                return Err(ManagedServiceError::ControlPlaneMaintenance);
            }
        }
        Ok(())
    };
    let logical_run_finalization = run_logical_run_finalization(
        components.logical_run_finalization,
        logical_run_finalization_cancellation,
    );
    let logical_result_projection = run_logical_result_projection(
        components.logical_result_projection,
        logical_result_projection_cancellation,
    );
    let autonomous_workflow = run_autonomous_workflow(
        components.autonomous_workflow,
        components.reusable_workflow_runtime,
        autonomous_workflow_readiness,
        metrics.clone(),
        autonomous_workflow_cancellation,
    );
    let result = supervise_optional_github_provider(
        (
            http,
            runner,
            results,
            metrics_http,
            monitor,
            maintenance,
            logical_run_finalization,
            logical_result_projection,
            autonomous_workflow,
        ),
        github_provider,
        github_provider_cancellation,
        shutdown_signal,
        cancellation,
        metrics,
    )
    .await;
    result.context("control-plane service supervision failed")
}

async fn run_log_commit_notifications(
    listener: &mut PostgresLogCommitListener,
    hub: &HumanLogCommitNotificationHub,
    cancellation: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => return,
            result = listener.receive() => match result {
                Ok(hint) => {
                    hub.publish(hint);
                }
                Err(error) => {
                    // Durable readers poll independently, so listener failure
                    // degrades latency without losing output or correctness.
                    warn!(%error, "live-log commit notification receive failed; retrying");
                    tokio::select! {
                        biased;
                        () = cancellation.cancelled() => return,
                        () = tokio::time::sleep(Duration::from_secs(1)) => {}
                    }
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
enum MachineListener {
    RunnerControl,
    Management,
}

impl MachineListener {
    const fn failure(self) -> ManagedServiceError {
        match self {
            Self::RunnerControl => ManagedServiceError::RunnerControl,
            Self::Management => ManagedServiceError::ManagementGrpc,
        }
    }
}

async fn run_machine_listeners(
    runner: RunnerControlServer,
    management: Option<ManagementGrpcServer>,
    cancellation: CancellationToken,
) -> Result<(), ManagedServiceError> {
    let Some(management) = management else {
        return runner
            .serve(cancellation)
            .await
            .map_err(|_| ManagedServiceError::RunnerControl);
    };

    let runner_cancellation = cancellation.clone();
    let management_cancellation = cancellation.clone();
    let runner = async move {
        runner
            .serve(runner_cancellation)
            .await
            .map_err(|_| ManagedServiceError::RunnerControl)
    };
    let management = async move {
        management
            .serve(management_cancellation)
            .await
            .map_err(|_| ManagedServiceError::ManagementGrpc)
    };
    supervise_machine_listener_futures(runner, management, cancellation).await
}

async fn supervise_machine_listener_futures<R, M>(
    runner: R,
    management: M,
    cancellation: CancellationToken,
) -> Result<(), ManagedServiceError>
where
    R: Future<Output = Result<(), ManagedServiceError>>,
    M: Future<Output = Result<(), ManagedServiceError>>,
{
    tokio::pin!(runner);
    tokio::pin!(management);

    let (first_listener, first_result, sibling_result, shutdown_requested) = tokio::select! {
        result = &mut runner => {
            let shutdown_requested = cancellation.is_cancelled();
            cancellation.cancel();
            (
                MachineListener::RunnerControl,
                result,
                management.await,
                shutdown_requested,
            )
        }
        result = &mut management => {
            let shutdown_requested = cancellation.is_cancelled();
            cancellation.cancel();
            (
                MachineListener::Management,
                result,
                runner.await,
                shutdown_requested,
            )
        }
    };
    first_result?;
    sibling_result?;
    if shutdown_requested {
        Ok(())
    } else {
        Err(first_listener.failure())
    }
}

async fn run_autonomous_workflow(
    service: AutonomousWorkflowService,
    reusable_workflow: ReusableWorkflowRuntimeService,
    readiness: Readiness,
    metrics: ControlPlaneMetrics,
    cancellation: CancellationToken,
) -> Result<(), ManagedServiceError> {
    let reusable_cancellation = cancellation.child_token();
    let workflow_cancellation = cancellation.child_token();
    let combined = async move {
        tokio::try_join!(
            async move {
                service.run(workflow_cancellation).await.map_err(|error| {
                    warn!(%error, component = "logical_workflow", "autonomous workflow runtime failed");
                })
            },
            async move {
                reusable_workflow
                    .run(reusable_cancellation)
                    .await
                    .map_err(|error| {
                        warn!(%error, component = "reusable_workflow", "autonomous workflow runtime failed");
                    })
            },
        )
        .map(|_| ())
    };
    run_autonomous_workflow_with_readiness(combined, readiness, metrics).await
}

async fn run_autonomous_workflow_with_readiness<F, E>(
    service: F,
    readiness: Readiness,
    metrics: ControlPlaneMetrics,
) -> Result<(), ManagedServiceError>
where
    F: Future<Output = Result<(), E>>,
{
    let _readiness_guard = AutonomousWorkflowReadinessGuard::publish(&readiness, &metrics);
    service
        .await
        .map_err(|_| ManagedServiceError::AutonomousWorkflow)
}

struct AutonomousWorkflowReadinessGuard<'a> {
    readiness: &'a Readiness,
    metrics: &'a ControlPlaneMetrics,
}

impl<'a> AutonomousWorkflowReadinessGuard<'a> {
    fn publish(readiness: &'a Readiness, metrics: &'a ControlPlaneMetrics) -> Self {
        readiness.set_autonomous_workflow_ready(true);
        metrics.set_ready(readiness.snapshot().is_ready());
        Self { readiness, metrics }
    }
}

impl Drop for AutonomousWorkflowReadinessGuard<'_> {
    fn drop(&mut self) {
        self.readiness.set_autonomous_workflow_ready(false);
        self.metrics.set_ready(false);
    }
}

async fn run_logical_run_finalization(
    service: LogicalRunFinalizationService,
    cancellation: CancellationToken,
) -> Result<(), ManagedServiceError> {
    service
        .run(cancellation)
        .await
        .map_err(|_| ManagedServiceError::LogicalRunFinalization)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LogicalResultProjectionBackoff {
    next: Duration,
    consecutive_failures: u8,
}

impl LogicalResultProjectionBackoff {
    const fn new() -> Self {
        Self {
            next: LOGICAL_RESULT_PROJECTION_RETRY_INITIAL,
            consecutive_failures: 0,
        }
    }

    fn reset(&mut self) {
        self.next = LOGICAL_RESULT_PROJECTION_RETRY_INITIAL;
        self.consecutive_failures = 0;
    }

    fn next_retry_delay(&mut self) -> Option<Duration> {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= LOGICAL_RESULT_PROJECTION_MAX_CONSECUTIVE_FAILURES {
            return None;
        }
        let delay = self.next;
        self.next = self
            .next
            .saturating_mul(2)
            .min(LOGICAL_RESULT_PROJECTION_RETRY_MAX);
        Some(delay)
    }
}

async fn run_logical_result_projection(
    service: LogicalResultProjectionService,
    cancellation: CancellationToken,
) -> Result<(), ManagedServiceError> {
    let mut backoff = LogicalResultProjectionBackoff::new();
    loop {
        if cancellation.is_cancelled() {
            return Ok(());
        }
        match service.run_once(cancellation.child_token()).await {
            Ok(LogicalResultProjectionOutcome::Idle) => {
                backoff.reset();
                if !wait_for_logical_result_projection(
                    &cancellation,
                    LOGICAL_RESULT_PROJECTION_IDLE_POLL,
                )
                .await
                {
                    return Ok(());
                }
            }
            Ok(_) => {
                backoff.reset();
                tokio::task::yield_now().await;
            }
            Err(LogicalResultProjectionError::Shutdown) if cancellation.is_cancelled() => {
                return Ok(());
            }
            Err(error) if logical_result_projection_error_is_retryable(&error) => {
                let Some(delay) = backoff.next_retry_delay() else {
                    return Err(ManagedServiceError::LogicalResultProjection);
                };
                tracing::warn!(
                    retry_attempt = u64::from(backoff.consecutive_failures),
                    retry_limit = u64::from(LOGICAL_RESULT_PROJECTION_MAX_CONSECUTIVE_FAILURES - 1),
                    retry_delay_millis = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                    "logical result-projection dependency failure; retrying"
                );
                if !wait_for_logical_result_projection(&cancellation, delay).await {
                    return Ok(());
                }
            }
            Err(_) => return Err(ManagedServiceError::LogicalResultProjection),
        }
    }
}

async fn wait_for_logical_result_projection(
    cancellation: &CancellationToken,
    duration: Duration,
) -> bool {
    tokio::select! {
        () = cancellation.cancelled() => false,
        () = tokio::time::sleep(duration) => true,
    }
}

fn logical_result_projection_error_is_retryable(error: &LogicalResultProjectionError) -> bool {
    match error {
        LogicalResultProjectionError::Blob(error) => {
            error.kind() == BlobStoreErrorKind::Unavailable
        }
        LogicalResultProjectionError::InstanceStore(error) => {
            logical_instance_result_store_error_is_retryable(error)
        }
        LogicalResultProjectionError::JobStore(error) => {
            logical_job_result_store_error_is_retryable(error)
        }
        LogicalResultProjectionError::InstanceValue(
            LogicalInstanceResultValueError::CommitOutsideClaim,
        )
        | LogicalResultProjectionError::JobValue(LogicalJobResultValueError::CommitOutsideClaim) => {
            true
        }
        LogicalResultProjectionError::Shutdown
        | LogicalResultProjectionError::InvalidTimestamp
        | LogicalResultProjectionError::InvalidObject
        | LogicalResultProjectionError::InstanceValue(_)
        | LogicalResultProjectionError::JobValue(_) => false,
    }
}

fn logical_instance_result_store_error_is_retryable(
    error: &LogicalInstanceResultStoreError,
) -> bool {
    matches!(
        error,
        LogicalInstanceResultStoreError::Store(StoreError::Operation(_))
            | LogicalInstanceResultStoreError::ClaimRejected
            | LogicalInstanceResultStoreError::ClaimClockSkew
            | LogicalInstanceResultStoreError::ClaimExpired
            | LogicalInstanceResultStoreError::SelectionExpired
            | LogicalInstanceResultStoreError::SelectionClockSkew
    )
}

fn logical_job_result_store_error_is_retryable(error: &LogicalJobResultStoreError) -> bool {
    matches!(
        error,
        LogicalJobResultStoreError::Store(StoreError::Operation(_))
            | LogicalJobResultStoreError::ClaimRejected
            | LogicalJobResultStoreError::ClaimClockSkew
            | LogicalJobResultStoreError::ClaimExpired
            | LogicalJobResultStoreError::SelectionExpired
            | LogicalJobResultStoreError::SelectionClockSkew
    )
}

async fn supervise_optional_github_provider<H, R, A, O, M, C, F, P, W, S>(
    services: (H, R, A, O, M, C, F, P, W),
    github_provider: Option<GithubProviderRuntime>,
    provider_cancellation: CancellationToken,
    shutdown_signal: S,
    cancellation: CancellationToken,
    metrics: ControlPlaneMetrics,
) -> Result<(), ServiceSupervisorError>
where
    H: Future<Output = Result<(), ManagedServiceError>> + Send,
    R: Future<Output = Result<(), ManagedServiceError>> + Send,
    A: Future<Output = Result<(), ManagedServiceError>> + Send,
    O: Future<Output = Result<(), ManagedServiceError>> + Send,
    M: Future<Output = Result<(), ManagedServiceError>> + Send,
    C: Future<Output = Result<(), ManagedServiceError>> + Send,
    F: Future<Output = Result<(), ManagedServiceError>> + Send,
    P: Future<Output = Result<(), ManagedServiceError>> + Send,
    W: Future<Output = Result<(), ManagedServiceError>> + Send,
    S: Future<Output = ()> + Send,
{
    let (
        http,
        runner,
        results,
        metrics_http,
        monitor,
        maintenance,
        logical_run_finalization,
        logical_result_projection,
        autonomous_workflow,
    ) = services;
    let Some(provider) = github_provider else {
        return supervise_nine_services(
            (
                http,
                runner,
                results,
                metrics_http,
                monitor,
                maintenance,
                logical_run_finalization,
                logical_result_projection,
                autonomous_workflow,
            ),
            shutdown_signal,
            cancellation,
            Some(metrics),
        )
        .await;
    };
    let (fatal_notification, fatal_signal) = oneshot::channel();
    let provider = async move {
        provider
            .run_with_fatal_notification(provider_cancellation, fatal_notification)
            .await
            .map_err(|error| {
                tracing::error!(%error, "GitHub provider runtime failed");
                ManagedServiceError::GithubProvider
            })
    };
    supervise_services_with_metrics_and_provider(
        (
            http,
            runner,
            results,
            metrics_http,
            monitor,
            maintenance,
            logical_run_finalization,
            logical_result_projection,
            autonomous_workflow,
            provider,
        ),
        wait_for_github_provider_fatal_signal(fatal_signal),
        shutdown_signal,
        cancellation,
        metrics,
    )
    .await
}

async fn wait_for_github_provider_fatal_signal(
    signal: oneshot::Receiver<GithubProviderFatalNotification>,
) {
    match signal.await {
        Ok(GithubProviderFatalNotification) => {}
        Err(_) => std::future::pending().await,
    }
}

fn results_router_with_deadline(router: axum::Router, timeout: Duration) -> axum::Router {
    router.layer(axum::middleware::from_fn(move |request, next| {
        enforce_results_request_deadline(request, next, timeout)
    }))
}

async fn enforce_results_request_deadline(
    request: Request,
    next: Next,
    timeout: Duration,
) -> Response {
    let deadline = tokio::time::Instant::now() + timeout;
    match tokio::time::timeout_at(deadline, next.run(request)).await {
        Ok(response) => response,
        Err(_) => (
            StatusCode::GATEWAY_TIMEOUT,
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            ],
            "Request timed out.\n",
        )
            .into_response(),
    }
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
    /// Private Prometheus/OpenMetrics operations listener.
    MetricsHttp,
    /// Active database and object-store readiness monitor.
    ReadinessMonitor,
    /// Bounded expired-lease and stale-session maintenance loop.
    ControlPlaneMaintenance,
    /// Database-time logical workflow run-finalization worker.
    LogicalRunFinalization,
    /// Autonomous terminal-attempt and logical-job result projection worker.
    LogicalResultProjection,
    /// Autonomous logical workflow preparation, activation, and materialization worker.
    AutonomousWorkflow,
    /// Exact mixed Public/Private GitHub provider runtime.
    GithubProvider,
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
    /// The private mTLS shard-management listener failed.
    #[error("management gRPC service failed")]
    ManagementGrpc,
    /// The GitHub Actions Results HTTP listener failed.
    #[error("Results HTTP service failed")]
    ResultsHttp,
    /// The Prometheus/OpenMetrics listener failed.
    #[error("metrics HTTP service failed")]
    MetricsHttp,
    /// The readiness monitor failed.
    #[error("readiness monitor failed")]
    ReadinessMonitor,
    /// The control-plane maintenance loop failed.
    #[error("control-plane maintenance service failed")]
    ControlPlaneMaintenance,
    /// The logical-run finalization worker failed.
    #[error("logical run-finalization service failed")]
    LogicalRunFinalization,
    /// The logical result-projection worker failed.
    #[error("logical result-projection service failed")]
    LogicalResultProjection,
    /// The autonomous logical workflow worker failed.
    #[error("autonomous workflow service failed")]
    AutonomousWorkflow,
    /// The configured GitHub provider runtime failed.
    #[error("GitHub provider service failed")]
    GithubProvider,
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

type ManagedServiceResult = (ManagedService, Result<(), ManagedServiceError>);
type ManagedServiceFuture<'a> = Pin<Box<dyn Future<Output = ManagedServiceResult> + Send + 'a>>;

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
pub async fn supervise_services<H, R, A, M, C, F, P, W, S>(
    services: (H, R, A, M, C, F, P, W),
    shutdown_signal: S,
    cancellation: CancellationToken,
) -> Result<(), ServiceSupervisorError>
where
    H: Future<Output = Result<(), ManagedServiceError>> + Send,
    R: Future<Output = Result<(), ManagedServiceError>> + Send,
    A: Future<Output = Result<(), ManagedServiceError>> + Send,
    M: Future<Output = Result<(), ManagedServiceError>> + Send,
    C: Future<Output = Result<(), ManagedServiceError>> + Send,
    F: Future<Output = Result<(), ManagedServiceError>> + Send,
    P: Future<Output = Result<(), ManagedServiceError>> + Send,
    W: Future<Output = Result<(), ManagedServiceError>> + Send,
    S: Future<Output = ()> + Send,
{
    let (
        http,
        runner,
        results,
        monitor,
        maintenance,
        logical_run_finalization,
        logical_result_projection,
        autonomous_workflow,
    ) = services;
    let metrics_cancellation = cancellation.child_token();
    let metrics = async move {
        metrics_cancellation.cancelled().await;
        Ok(())
    };
    supervise_nine_services(
        (
            http,
            runner,
            results,
            metrics,
            monitor,
            maintenance,
            logical_run_finalization,
            logical_result_projection,
            autonomous_workflow,
        ),
        shutdown_signal,
        cancellation,
        None,
    )
    .await
}

/// Runs the nine always-on production services with exit observations.
///
/// # Errors
///
/// Returns the first fatal service failure or identifies an unexpected clean exit.
pub async fn supervise_services_with_metrics<H, R, A, O, M, C, F, P, W, S>(
    services: (H, R, A, O, M, C, F, P, W),
    shutdown_signal: S,
    cancellation: CancellationToken,
    metrics: ControlPlaneMetrics,
) -> Result<(), ServiceSupervisorError>
where
    H: Future<Output = Result<(), ManagedServiceError>> + Send,
    R: Future<Output = Result<(), ManagedServiceError>> + Send,
    A: Future<Output = Result<(), ManagedServiceError>> + Send,
    O: Future<Output = Result<(), ManagedServiceError>> + Send,
    M: Future<Output = Result<(), ManagedServiceError>> + Send,
    C: Future<Output = Result<(), ManagedServiceError>> + Send,
    F: Future<Output = Result<(), ManagedServiceError>> + Send,
    P: Future<Output = Result<(), ManagedServiceError>> + Send,
    W: Future<Output = Result<(), ManagedServiceError>> + Send,
    S: Future<Output = ()> + Send,
{
    supervise_nine_services(services, shutdown_signal, cancellation, Some(metrics)).await
}

/// Runs the ten configured production services, including GitHub provider work.
///
/// This boundary is selected only when GitHub provider configuration built a
/// live runtime. Disabled deployments continue to use the nine-service
/// supervisor and never create a placeholder provider task.
///
/// # Errors
///
/// Returns the first fatal service failure or identifies an unexpected clean exit.
pub async fn supervise_services_with_metrics_and_provider<H, R, A, O, M, C, F, P, W, G, N, S>(
    services: (H, R, A, O, M, C, F, P, W, G),
    provider_fatal_signal: N,
    shutdown_signal: S,
    cancellation: CancellationToken,
    metrics: ControlPlaneMetrics,
) -> Result<(), ServiceSupervisorError>
where
    H: Future<Output = Result<(), ManagedServiceError>> + Send,
    R: Future<Output = Result<(), ManagedServiceError>> + Send,
    A: Future<Output = Result<(), ManagedServiceError>> + Send,
    O: Future<Output = Result<(), ManagedServiceError>> + Send,
    M: Future<Output = Result<(), ManagedServiceError>> + Send,
    C: Future<Output = Result<(), ManagedServiceError>> + Send,
    F: Future<Output = Result<(), ManagedServiceError>> + Send,
    P: Future<Output = Result<(), ManagedServiceError>> + Send,
    W: Future<Output = Result<(), ManagedServiceError>> + Send,
    G: Future<Output = Result<(), ManagedServiceError>> + Send,
    N: Future<Output = ()> + Send,
    S: Future<Output = ()> + Send,
{
    supervise_ten_services(
        services,
        provider_fatal_signal,
        shutdown_signal,
        cancellation,
        Some(metrics),
    )
    .await
}

async fn supervise_nine_services<H, R, A, O, M, C, F, P, W, S>(
    services: (H, R, A, O, M, C, F, P, W),
    shutdown_signal: S,
    cancellation: CancellationToken,
    metrics: Option<ControlPlaneMetrics>,
) -> Result<(), ServiceSupervisorError>
where
    H: Future<Output = Result<(), ManagedServiceError>> + Send,
    R: Future<Output = Result<(), ManagedServiceError>> + Send,
    A: Future<Output = Result<(), ManagedServiceError>> + Send,
    O: Future<Output = Result<(), ManagedServiceError>> + Send,
    M: Future<Output = Result<(), ManagedServiceError>> + Send,
    C: Future<Output = Result<(), ManagedServiceError>> + Send,
    F: Future<Output = Result<(), ManagedServiceError>> + Send,
    P: Future<Output = Result<(), ManagedServiceError>> + Send,
    W: Future<Output = Result<(), ManagedServiceError>> + Send,
    S: Future<Output = ()> + Send,
{
    let (
        http,
        runner,
        results,
        metrics_http,
        monitor,
        maintenance,
        logical_run_finalization,
        logical_result_projection,
        autonomous_workflow,
    ) = services;
    let running = FuturesUnordered::new();
    running.push(managed_service_future(
        http,
        ManagedService::HumanHttp,
        metrics.clone(),
        cancellation.clone(),
    ));
    running.push(managed_service_future(
        runner,
        ManagedService::RunnerControl,
        metrics.clone(),
        cancellation.clone(),
    ));
    running.push(managed_service_future(
        results,
        ManagedService::ResultsHttp,
        metrics.clone(),
        cancellation.clone(),
    ));
    running.push(managed_service_future(
        metrics_http,
        ManagedService::MetricsHttp,
        metrics.clone(),
        cancellation.clone(),
    ));
    running.push(managed_service_future(
        monitor,
        ManagedService::ReadinessMonitor,
        metrics.clone(),
        cancellation.clone(),
    ));
    running.push(managed_service_future(
        maintenance,
        ManagedService::ControlPlaneMaintenance,
        metrics.clone(),
        cancellation.clone(),
    ));
    running.push(managed_service_future(
        logical_run_finalization,
        ManagedService::LogicalRunFinalization,
        metrics.clone(),
        cancellation.clone(),
    ));
    running.push(managed_service_future(
        logical_result_projection,
        ManagedService::LogicalResultProjection,
        metrics.clone(),
        cancellation.clone(),
    ));
    running.push(managed_service_future(
        autonomous_workflow,
        ManagedService::AutonomousWorkflow,
        metrics,
        cancellation.clone(),
    ));

    supervise_running_services(
        running,
        std::future::pending::<ManagedServiceError>(),
        shutdown_signal,
        cancellation,
    )
    .await
}

async fn supervise_ten_services<H, R, A, O, M, C, F, P, W, G, N, S>(
    services: (H, R, A, O, M, C, F, P, W, G),
    provider_fatal_signal: N,
    shutdown_signal: S,
    cancellation: CancellationToken,
    metrics: Option<ControlPlaneMetrics>,
) -> Result<(), ServiceSupervisorError>
where
    H: Future<Output = Result<(), ManagedServiceError>> + Send,
    R: Future<Output = Result<(), ManagedServiceError>> + Send,
    A: Future<Output = Result<(), ManagedServiceError>> + Send,
    O: Future<Output = Result<(), ManagedServiceError>> + Send,
    M: Future<Output = Result<(), ManagedServiceError>> + Send,
    C: Future<Output = Result<(), ManagedServiceError>> + Send,
    F: Future<Output = Result<(), ManagedServiceError>> + Send,
    P: Future<Output = Result<(), ManagedServiceError>> + Send,
    W: Future<Output = Result<(), ManagedServiceError>> + Send,
    G: Future<Output = Result<(), ManagedServiceError>> + Send,
    N: Future<Output = ()> + Send,
    S: Future<Output = ()> + Send,
{
    let (
        http,
        runner,
        results,
        metrics_http,
        monitor,
        maintenance,
        logical_run_finalization,
        logical_result_projection,
        autonomous_workflow,
        github_provider,
    ) = services;
    let running = FuturesUnordered::new();
    for service in [
        managed_service_future(
            http,
            ManagedService::HumanHttp,
            metrics.clone(),
            cancellation.clone(),
        ),
        managed_service_future(
            runner,
            ManagedService::RunnerControl,
            metrics.clone(),
            cancellation.clone(),
        ),
        managed_service_future(
            results,
            ManagedService::ResultsHttp,
            metrics.clone(),
            cancellation.clone(),
        ),
        managed_service_future(
            metrics_http,
            ManagedService::MetricsHttp,
            metrics.clone(),
            cancellation.clone(),
        ),
        managed_service_future(
            monitor,
            ManagedService::ReadinessMonitor,
            metrics.clone(),
            cancellation.clone(),
        ),
        managed_service_future(
            maintenance,
            ManagedService::ControlPlaneMaintenance,
            metrics.clone(),
            cancellation.clone(),
        ),
        managed_service_future(
            logical_run_finalization,
            ManagedService::LogicalRunFinalization,
            metrics.clone(),
            cancellation.clone(),
        ),
        managed_service_future(
            logical_result_projection,
            ManagedService::LogicalResultProjection,
            metrics.clone(),
            cancellation.clone(),
        ),
        managed_service_future(
            autonomous_workflow,
            ManagedService::AutonomousWorkflow,
            metrics.clone(),
            cancellation.clone(),
        ),
        managed_service_future(
            github_provider,
            ManagedService::GithubProvider,
            metrics,
            cancellation.clone(),
        ),
    ] {
        running.push(service);
    }
    supervise_running_services(
        running,
        async move {
            provider_fatal_signal.await;
            ManagedServiceError::GithubProvider
        },
        shutdown_signal,
        cancellation,
    )
    .await
}

enum SupervisionWake {
    Shutdown,
    EarlyFailure(ManagedServiceError),
    Service(ManagedServiceResult),
}

async fn supervise_running_services<E, S>(
    mut running: FuturesUnordered<ManagedServiceFuture<'_>>,
    early_failure: E,
    shutdown_signal: S,
    cancellation: CancellationToken,
) -> Result<(), ServiceSupervisorError>
where
    E: Future<Output = ManagedServiceError> + Send,
    S: Future<Output = ()> + Send,
{
    let first_exit = tokio::select! {
        biased;
        error = early_failure => SupervisionWake::EarlyFailure(error),
        () = shutdown_signal => SupervisionWake::Shutdown,
        exit = running.next() => SupervisionWake::Service(
            exit.expect("the managed service set is nonempty")
        ),
    };
    cancellation.cancel();

    let mut sibling_result = Ok(());
    while let Some((_service, result)) = running.next().await {
        if sibling_result.is_ok() {
            sibling_result = result;
        }
    }
    match first_exit {
        SupervisionWake::Shutdown => sibling_result.map_err(ServiceSupervisorError::from),
        SupervisionWake::EarlyFailure(error) => Err(error.into()),
        SupervisionWake::Service((service, result)) => {
            result?;
            sibling_result?;
            Err(ServiceSupervisorError::UnexpectedStop(service))
        }
    }
}

fn managed_service_future<'a, F>(
    service: F,
    identity: ManagedService,
    metrics: Option<ControlPlaneMetrics>,
    cancellation: CancellationToken,
) -> ManagedServiceFuture<'a>
where
    F: Future<Output = Result<(), ManagedServiceError>> + Send + 'a,
{
    Box::pin(async move {
        let result = service.await;
        if let Some(metrics) = metrics {
            let outcome = if result.is_err() {
                "failure"
            } else if cancellation.is_cancelled() {
                "graceful"
            } else {
                "unexpected_stop"
            };
            metrics.observe_service_exit(managed_service_label(identity), outcome);
        }
        (identity, result)
    })
}

const fn managed_service_label(service: ManagedService) -> &'static str {
    match service {
        ManagedService::HumanHttp => "human_http",
        ManagedService::RunnerControl => "runner_control",
        ManagedService::ResultsHttp => "results_http",
        ManagedService::MetricsHttp => "metrics_http",
        ManagedService::ReadinessMonitor => "readiness_monitor",
        ManagedService::ControlPlaneMaintenance => "control_plane_maintenance",
        ManagedService::LogicalRunFinalization => "logical_run_finalization",
        ManagedService::LogicalResultProjection => "logical_result_projection",
        ManagedService::AutonomousWorkflow => "autonomous_workflow",
        ManagedService::GithubProvider => "github_provider",
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::Poll,
        time::Duration,
    };

    use axum::{
        body::Body,
        routing::{get, post},
    };
    use bytes::Bytes;
    use tower::ServiceExt as _;

    use super::*;

    struct DropSignal(Arc<AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct SyntheticInitializationError;

    #[tokio::test]
    async fn absent_github_provider_omits_the_public_webhook_route() {
        let router = router_with_optional_github_webhook(
            axum::Router::new().route("/human", get(|| async { StatusCode::NO_CONTENT })),
            None,
        );
        let human = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/human")
                    .body(Body::empty())
                    .expect("human request"),
            )
            .await
            .expect("human response");
        assert_eq!(human.status(), StatusCode::NO_CONTENT);

        let webhook = router
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri(GITHUB_WEBHOOK_PATH)
                    .body(Body::empty())
                    .expect("webhook request"),
            )
            .await
            .expect("webhook response");
        assert_eq!(webhook.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn metrics_are_scrapeable_and_not_ready_while_production_composition_fails() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback metrics listener");
        let address = listener.local_addr().expect("metrics listener address");
        let metrics =
            ControlPlaneMetrics::new(BuildInfo::current()).expect("control-plane metrics");
        let cancellation = CancellationToken::new();
        let (state_sampler_sender, state_sampler_receiver) = oneshot::channel();
        let mut metrics_http = metrics_http_service(
            Some(listener),
            metrics,
            cancellation.child_token(),
            state_sampler_receiver,
        );
        let initialization = async move {
            let client = reqwest::Client::builder()
                .no_proxy()
                .build()
                .expect("loopback HTTP client");
            let response = client
                .get(format!("http://{address}/metrics"))
                .send()
                .await
                .expect("metrics endpoint available during composition");
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            let exposition = response.text().await.expect("OpenMetrics body");
            assert!(exposition.contains("automata_ci_control_plane_ready 0"));
            Err::<(), SyntheticInitializationError>(SyntheticInitializationError)
        };

        let race = tokio::time::timeout(
            Duration::from_secs(2),
            race_initialization(initialization, &mut metrics_http, &cancellation),
        )
        .await
        .expect("initialization race must complete");
        assert!(matches!(
            race,
            InitializationRace::Initialization(Err(SyntheticInitializationError))
        ));

        drop(state_sampler_sender);
        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(2), metrics_http.as_mut())
            .await
            .expect("metrics service must drain")
            .expect("metrics service shutdown must succeed");
    }

    #[tokio::test]
    async fn autonomous_workflow_first_poll_publishes_readiness_until_clean_exit() {
        let readiness = Readiness::all_ready();
        readiness.set_autonomous_workflow_ready(false);
        let metrics =
            ControlPlaneMetrics::new(BuildInfo::current()).expect("control-plane metrics");
        let (release_sender, release_receiver) = oneshot::channel();
        let managed = run_autonomous_workflow_with_readiness(
            async move {
                let _ = release_receiver.await;
                Ok::<(), ()>(())
            },
            readiness.clone(),
            metrics.clone(),
        );
        assert!(!readiness.snapshot().autonomous_workflow());
        let task = tokio::spawn(managed);

        tokio::time::timeout(Duration::from_secs(1), async {
            while !readiness.snapshot().autonomous_workflow() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the worker wrapper must publish readiness on its first poll");
        assert!(
            metrics
                .exporter()
                .encode_openmetrics()
                .expect("bounded exposition")
                .as_str()
                .contains("automata_ci_control_plane_ready 1")
        );

        release_sender.send(()).expect("worker remains supervised");
        assert_eq!(task.await.expect("worker wrapper joins"), Ok(()));
        assert!(!readiness.snapshot().autonomous_workflow());
        assert!(
            metrics
                .exporter()
                .encode_openmetrics()
                .expect("bounded exposition")
                .as_str()
                .contains("automata_ci_control_plane_ready 0")
        );
    }

    #[tokio::test]
    async fn autonomous_workflow_failure_clears_readiness_and_is_sanitized() {
        let readiness = Readiness::all_ready();
        readiness.set_autonomous_workflow_ready(false);
        let metrics =
            ControlPlaneMetrics::new(BuildInfo::current()).expect("control-plane metrics");

        let result = run_autonomous_workflow_with_readiness(
            async { Err::<(), _>("sensitive worker detail") },
            readiness.clone(),
            metrics.clone(),
        )
        .await;

        assert_eq!(result, Err(ManagedServiceError::AutonomousWorkflow));
        assert!(!readiness.snapshot().autonomous_workflow());
        assert!(
            metrics
                .exporter()
                .encode_openmetrics()
                .expect("bounded exposition")
                .as_str()
                .contains("automata_ci_control_plane_ready 0")
        );
    }

    #[tokio::test]
    async fn aborting_autonomous_workflow_clears_readiness_and_metric() {
        let readiness = Readiness::all_ready();
        readiness.set_autonomous_workflow_ready(false);
        let metrics =
            ControlPlaneMetrics::new(BuildInfo::current()).expect("control-plane metrics");
        let managed = run_autonomous_workflow_with_readiness(
            std::future::pending::<Result<(), ()>>(),
            readiness.clone(),
            metrics.clone(),
        );
        let task = tokio::spawn(managed);

        tokio::time::timeout(Duration::from_secs(1), async {
            while !readiness.snapshot().autonomous_workflow() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the worker wrapper must publish readiness on its first poll");

        task.abort();
        assert!(
            task.await
                .expect_err("the worker task must be cancelled")
                .is_cancelled()
        );
        assert!(!readiness.snapshot().autonomous_workflow());
        assert!(
            metrics
                .exporter()
                .encode_openmetrics()
                .expect("bounded exposition")
                .as_str()
                .contains("automata_ci_control_plane_ready 0")
        );
    }

    #[tokio::test]
    async fn results_deadline_cancels_a_stalled_request_body_before_authentication() {
        let body_dropped = Arc::new(AtomicBool::new(false));
        let handler_started = Arc::new(AtomicBool::new(false));
        let handler_started_for_route = Arc::clone(&handler_started);
        let router = results_router_with_deadline(
            axum::Router::new().route(
                "/upload",
                post(move |_: Bytes| {
                    let handler_started = Arc::clone(&handler_started_for_route);
                    async move {
                        handler_started.store(true, Ordering::SeqCst);
                        StatusCode::NO_CONTENT
                    }
                }),
            ),
            Duration::from_millis(25),
        );
        let drop_signal = DropSignal(Arc::clone(&body_dropped));
        let stalled = futures::stream::poll_fn(move |_| {
            let _ = &drop_signal;
            Poll::<Option<Result<Bytes, Infallible>>>::Pending
        });
        let request = Request::builder()
            .method(axum::http::Method::POST)
            .uri("/upload")
            .body(Body::from_stream(stalled))
            .expect("stalled Results request");

        let response = tokio::time::timeout(Duration::from_secs(2), router.oneshot(request))
            .await
            .expect("outer test timeout")
            .expect("infallible Results router");

        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(
            response
                .headers()
                .get(header::X_CONTENT_TYPE_OPTIONS)
                .and_then(|value| value.to_str().ok()),
            Some("nosniff")
        );
        assert!(!handler_started.load(Ordering::SeqCst));
        assert!(body_dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn results_deadline_is_one_budget_across_extraction_and_handler_work() {
        let handler_started = Arc::new(AtomicBool::new(false));
        let handler_finished = Arc::new(AtomicBool::new(false));
        let handler_started_for_route = Arc::clone(&handler_started);
        let handler_finished_for_route = Arc::clone(&handler_finished);
        let router = results_router_with_deadline(
            axum::Router::new().route(
                "/upload",
                post(move |_: Bytes| {
                    let handler_started = Arc::clone(&handler_started_for_route);
                    let handler_finished = Arc::clone(&handler_finished_for_route);
                    async move {
                        handler_started.store(true, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        handler_finished.store(true, Ordering::SeqCst);
                        StatusCode::NO_CONTENT
                    }
                }),
            ),
            Duration::from_millis(250),
        );
        let delayed_body = futures::stream::once(async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok::<Bytes, Infallible>(Bytes::from_static(b"payload"))
        });
        let request = Request::builder()
            .method(axum::http::Method::POST)
            .uri("/upload")
            .body(Body::from_stream(delayed_body))
            .expect("delayed Results request");

        let response = tokio::time::timeout(Duration::from_secs(2), router.oneshot(request))
            .await
            .expect("outer test timeout")
            .expect("infallible Results router");

        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert!(handler_started.load(Ordering::SeqCst));
        assert!(!handler_finished.load(Ordering::SeqCst));
    }

    #[test]
    fn logical_result_projection_backoff_is_bounded_and_resettable() {
        let mut backoff = LogicalResultProjectionBackoff::new();
        let delays = (0..7)
            .map(|_| backoff.next_retry_delay())
            .collect::<Vec<_>>();
        assert_eq!(
            delays,
            [1, 2, 4, 8, 16, 30, 30].map(|seconds| Some(Duration::from_secs(seconds)))
        );
        assert_eq!(backoff.next_retry_delay(), None);

        backoff.reset();
        assert_eq!(backoff.next_retry_delay(), Some(Duration::from_secs(1)));
    }

    #[test]
    fn logical_result_projection_retries_only_dependency_and_stale_fence_failures() {
        use automata_ci_blob::BlobStoreError;

        assert!(logical_result_projection_error_is_retryable(
            &LogicalResultProjectionError::Blob(BlobStoreError::new(
                BlobStoreErrorKind::Unavailable
            ))
        ));
        for kind in [
            BlobStoreErrorKind::InvalidResponse,
            BlobStoreErrorKind::Unauthorized,
        ] {
            assert!(!logical_result_projection_error_is_retryable(
                &LogicalResultProjectionError::Blob(BlobStoreError::new(kind))
            ));
        }
        assert!(logical_result_projection_error_is_retryable(
            &LogicalResultProjectionError::InstanceStore(
                LogicalInstanceResultStoreError::SelectionClockSkew
            )
        ));
        assert!(logical_result_projection_error_is_retryable(
            &LogicalResultProjectionError::InstanceStore(LogicalInstanceResultStoreError::Store(
                StoreError::operation(std::io::Error::other("synthetic dependency failure"))
            ))
        ));
        assert!(logical_result_projection_error_is_retryable(
            &LogicalResultProjectionError::JobValue(LogicalJobResultValueError::CommitOutsideClaim)
        ));
        assert!(!logical_result_projection_error_is_retryable(
            &LogicalResultProjectionError::JobStore(
                LogicalJobResultStoreError::GenerationExhausted
            )
        ));
        assert!(!logical_result_projection_error_is_retryable(
            &LogicalResultProjectionError::JobStore(LogicalJobResultStoreError::Store(
                StoreError::corrupt_data("synthetic corrupt durable data")
            ))
        ));
        assert!(!logical_result_projection_error_is_retryable(
            &LogicalResultProjectionError::InvalidTimestamp
        ));
    }

    #[tokio::test]
    async fn logical_result_projection_retry_wait_is_immediately_cancellable() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let completed = tokio::time::timeout(
            Duration::from_millis(100),
            wait_for_logical_result_projection(&cancellation, Duration::from_secs(30)),
        )
        .await
        .expect("cancelled retry wait must finish immediately");
        assert!(!completed);
    }

    #[tokio::test]
    async fn management_failure_cancels_and_drains_runner_control() {
        let cancellation = CancellationToken::new();
        let runner_cancellation = cancellation.clone();
        let runner_drained = Arc::new(AtomicBool::new(false));
        let runner_drained_task = Arc::clone(&runner_drained);
        let runner = async move {
            runner_cancellation.cancelled().await;
            runner_drained_task.store(true, Ordering::SeqCst);
            Ok(())
        };
        let management = async { Err(ManagedServiceError::ManagementGrpc) };

        let result = supervise_machine_listener_futures(runner, management, cancellation).await;

        assert_eq!(result, Err(ManagedServiceError::ManagementGrpc));
        assert!(runner_drained.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn process_shutdown_drains_both_machine_listeners_cleanly() {
        let cancellation = CancellationToken::new();
        let runner_cancellation = cancellation.clone();
        let management_cancellation = cancellation.clone();
        let runner_drained = Arc::new(AtomicBool::new(false));
        let management_drained = Arc::new(AtomicBool::new(false));
        let runner_drained_task = Arc::clone(&runner_drained);
        let management_drained_task = Arc::clone(&management_drained);
        let runner = async move {
            runner_cancellation.cancelled().await;
            runner_drained_task.store(true, Ordering::SeqCst);
            Ok(())
        };
        let management = async move {
            management_cancellation.cancelled().await;
            management_drained_task.store(true, Ordering::SeqCst);
            Ok(())
        };
        let shutdown = cancellation.clone();
        let task = tokio::spawn(supervise_machine_listener_futures(
            runner,
            management,
            cancellation,
        ));

        shutdown.cancel();
        let result = task.await.expect("machine listener supervisor joins");

        assert_eq!(result, Ok(()));
        assert!(runner_drained.load(Ordering::SeqCst));
        assert!(management_drained.load(Ordering::SeqCst));
    }
}
