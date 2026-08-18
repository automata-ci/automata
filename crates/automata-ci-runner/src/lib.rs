//! Automata execution-host runner.
//!
//! The crate diagnoses host capabilities and validates runner configuration.
//! Before the production command opens a control-plane session, Linux execution
//! either requires the configured rootless-Podman network probe and cleanup to
//! succeed or constructs the authenticated Kubernetes adapter. Trusted Windows
//! execution uses fresh Hyper-V-isolated Windows containers with networking
//! disabled and no host mounts; macOS execution uses one
//! disposable Virtualization.framework machine per job.
//! Every path exercises configured environments through exact lifecycle
//! admission before supervising fenced job execution.
//! [`run`] is the `automata-runner` process entry point; diagnostic and product
//! modules expose the same typed boundaries for embedding and tests.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Build-time version and source-revision provenance.
pub mod build_info;
/// Read-only and opt-in active host capability discovery.
pub mod capability_probe;
mod certificate_renewal;
mod cli;
/// Runner host and control-plane health diagnostics.
pub mod doctor;
mod enrollment;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod local_ready;
/// Rootless-Podman network isolation verification.
pub mod podman_probe;
mod probe_http;
pub mod product;

use std::io::Write as _;

use anyhow::Result;
use clap::Parser as _;
use tracing_subscriber::EnvFilter;

use crate::cli::{Cli, Command};

/// Parses process arguments and runs the runner supervisor command.
///
/// # Errors
///
/// Returns an error when production runner startup/supervision fails, canonical
/// capability rendering cannot load or write its configuration-derived
/// durable-registration ceiling,
/// a requested diagnostic cannot be serialized, or a required capability or
/// server health check fails. This process-terminal entry point owns SIGINT and
/// SIGTERM handling for long-running commands; embedding hosts should call
/// [`product::run`] with their own [`product::RunnerShutdown`] instead.
pub async fn run() -> Result<()> {
    init_tracing();
    Box::pin(execute(Cli::parse())).await
}

async fn execute(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Run(args) => {
            let shutdown = product::RunnerShutdown::new();
            let signal_shutdown = shutdown.clone();
            let request_shutdown = move || signal_shutdown.request();
            #[cfg(unix)]
            let _signal_observer = ProcessSignalObserver::start(request_shutdown)?;
            #[cfg(not(unix))]
            let _signal_observer = ProcessSignalObserver::start(request_shutdown);
            Box::pin(product::run(&args.config, shutdown))
                .await
                .map_err(Into::into)
        }
        Command::Enroll(args) => enrollment::enroll(&args).await,
        Command::Capabilities(args) => print_capabilities(&args.config),
        Command::Doctor(args) => {
            let cancellation = podman_probe::ProbeCancellation::default();
            let _signal_observer = if args.active {
                let signal_cancellation = cancellation.clone();
                let request_shutdown = move || {
                    signal_cancellation.cancel();
                };
                #[cfg(unix)]
                let observer = ProcessSignalObserver::start(request_shutdown)?;
                #[cfg(not(unix))]
                let observer = ProcessSignalObserver::start(request_shutdown);
                Some(observer)
            } else {
                None
            };
            doctor::run(args, &cancellation).await
        }
        Command::InternalProbeHttp(args) => probe_http::serve(args).await,
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        Command::InternalLocalCheckReady => local_ready::check(),
    }
}

fn print_capabilities(config_path: &std::path::Path) -> Result<()> {
    let config = product::RunnerProductConfig::load(config_path)?;
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, config.inventory())?;
    output.write_all(b"\n")?;
    Ok(())
}

struct ProcessSignalObserver {
    task: tokio::task::JoinHandle<()>,
}

impl ProcessSignalObserver {
    #[cfg(unix)]
    fn start(request_shutdown: impl Fn() + Send + 'static) -> Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};

        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut terminate = signal(SignalKind::terminate())?;
        let task = tokio::spawn(async move {
            loop {
                let received = tokio::select! {
                    received = interrupt.recv() => received,
                    received = terminate.recv() => received,
                };
                if received.is_none() {
                    break;
                }
                request_shutdown();
            }
        });
        Ok(Self { task })
    }

    #[cfg(not(unix))]
    fn start(request_shutdown: impl Fn() + Send + 'static) -> Self {
        let task = tokio::spawn(async move {
            while tokio::signal::ctrl_c().await.is_ok() {
                request_shutdown();
            }
        });
        Self { task }
    }
}

impl Drop for ProcessSignalObserver {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ignored = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
