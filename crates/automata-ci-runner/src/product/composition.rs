use std::{future::Future, path::Path, pin::Pin, sync::Arc};

use automata_ci_action::{ActionBundleLimits, ActionResolver, ImmutableActionResolver};
use automata_ci_action_github::{
    GithubActionMetadataDecoder, GithubActionMetadataLimits, JavascriptRuntime,
};
use automata_ci_blob::ImmutableBlobStore;
use automata_ci_blob_s3::{MAX_S3_PRIVATE_CA_PEM_BYTES, S3TlsTrust, StaticS3Credentials};
use automata_ci_core::{ContainerCapabilities, ContainerFeature, RunnerCapabilities};
use automata_ci_execution::{ProviderCapabilities, SandboxCapability};
use automata_ci_job_executor_github::{
    ActionPreparationPort, DeterministicOperationIds, GithubJobExecutor, GithubJobExecutorConfig,
    GithubJobExecutorPorts, ImmutableJobContent, ImmutableSandboxEnvironmentCatalog,
    NoRepositoryCredentials, NoSecrets, ResolvedBundleActionPreparer, StaticGithubToolchain,
    SystemExecutionClock,
};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_runner_journal::{FileJournal, FileJournalOptions};
use automata_ci_runner_runtime::{
    JobExecutor, RunnerRuntimeConfig, RunnerRuntimePorts, RunnerSessionSupervisor,
    SystemRuntimeClock, SystemRuntimeIds, TokioRuntimeSleeper, TransportControlClientAdapter,
};
use automata_ci_runner_spool::{ContentProtector, FileSpool, FileSpoolOptions};
use automata_ci_runner_transport::{
    HyperRunnerCertificateRenewalClient, HyperRunnerControlClient, HyperRunnerEphemeralClient,
    RunnerCertificateRenewalClient, RunnerControlClient, RunnerEphemeralClient, TransportLimits,
};
use automata_ci_sandbox_macos::{MacosVirtualizationProvider, MacosVirtualizationProviderOptions};
#[cfg(not(target_os = "linux"))]
use automata_ci_sandbox_podman::PodmanLaunchTrust;
use automata_ci_sandbox_podman::{
    PodmanBinary, PodmanLaunchTrustHandle, PodmanOptions, PodmanProcessEnvironment, PodmanStateRoot,
};
#[cfg(target_os = "linux")]
use automata_ci_sandbox_podman::{
    PodmanCommandExecutor, RootlessPodmanProvider, SystemCommandExecutor,
};
use automata_ci_sandbox_windows::{
    WindowsHyperVContainerProvider, WindowsHyperVContainerProviderOptions,
};
use automata_ci_scm::ScmProvider;
use automata_ci_workflow_github::GithubConditionCompiler;
use thiserror::Error;
use tokio::{net::TcpListener, task::JoinError};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
#[path = "podman_process_trust.rs"]
mod podman_process_trust;
#[cfg(target_os = "linux")]
use podman_process_trust::PodmanProcessTrust;

#[cfg(unix)]
use super::action_cache::{
    ActionArchiveCacheLimits, ActionArchiveCacheRoot, ActionReferenceIndexLimits,
    ActionReferenceIndexRoot, FileActionArchiveCache, FileActionReferenceIndex,
};
use super::managed_secret_delivery::ManagedSecretJobExecutor;
#[cfg(not(target_os = "linux"))]
use super::state::RuntimeMountSnapshot;
use super::{
    ClientTlsMaterialError, ProductStateRootError, RunnerProductConfig, RunnerProductConfigError,
    RunnerProviderConfig, SecretSource, StandardGithubContext,
    config::{ObjectStoreTlsTrust, required_podman_state_root},
    metrics::RunnerMetrics,
    profile_admission::{
        ProfileAdmissionError, ProfileAdmissionOutcome, ProfileAdmissionPolicy,
        admit_environment_profiles,
    },
    spool_crypto::{AES_256_GCM_KEY_BYTES, Aes256GcmContentKeyring, Aes256GcmContentProtector},
    state::{capture_dedicated_runtime_mount, ensure_private_directory},
    tls::load_client_tls,
};
use crate::certificate_renewal::{CertificateRenewal, CertificateRenewalOutcome};

const MAX_S3_ACCESS_KEY_BYTES: usize = 1_024;
const MAX_S3_SECRET_BYTES: usize = 65_536;
const RECOMPOSITION_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(2);

#[cfg(not(target_os = "linux"))]
#[derive(Clone, Debug)]
struct PodmanProcessTrust;

#[cfg(not(target_os = "linux"))]
impl PodmanProcessTrust {
    fn capture(_options: &PodmanOptions, _runtime_mount: RuntimeMountSnapshot) -> Self {
        Self
    }
}

#[cfg(not(target_os = "linux"))]
impl PodmanLaunchTrust for PodmanProcessTrust {
    fn revalidate(&self) -> bool {
        false
    }
}

/// Caller-owned shutdown state for an embedded production runner.
///
/// The first request stops active-probe provisioning and begins bounded cleanup
/// before stopping the supervisor. A second request may force probe cleanup to
/// stop promptly. The process CLI maps SIGINT and SIGTERM into this value; an
/// embedding host remains responsible for its own process-signal policy.
#[derive(Clone, Debug, Default)]
pub struct RunnerShutdown {
    runtime: CancellationToken,
    probe: crate::podman_probe::ProbeCancellation,
}

impl RunnerShutdown {
    /// Creates independent runner shutdown state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one graceful-shutdown request.
    pub fn request(&self) {
        self.probe.cancel();
        self.runtime.cancel();
    }

    /// Reports whether shutdown has been requested.
    pub fn is_requested(&self) -> bool {
        self.runtime.is_cancelled()
    }
}

/// Starts the production runner composition and blocks until graceful shutdown.
///
/// # Errors
///
/// Returns a sanitized startup/runtime category. Secret values, PEM contents,
/// provider output, and action output are never embedded in this error.
pub async fn run(config_path: &Path, shutdown: RunnerShutdown) -> Result<(), RunnerProductError> {
    run_recomposition_loop(shutdown, |generation_shutdown| {
        Box::pin(run_generation(config_path, generation_shutdown))
    })
    .await
}

async fn run_generation(
    config_path: &Path,
    shutdown: RunnerShutdown,
) -> Result<SupervisionDisposition, RunnerProductError> {
    let config = RunnerProductConfig::load(config_path)?;
    if shutdown.is_requested() {
        return Ok(SupervisionDisposition::Complete);
    }
    match config.provider() {
        RunnerProviderConfig::Podman(_) => Box::pin(run_podman(&config, shutdown)).await,
        RunnerProviderConfig::LocalDocker(_) => Box::pin(run_local_docker(&config, shutdown)).await,
        RunnerProviderConfig::Kubernetes(_) => Box::pin(run_kubernetes(&config, shutdown)).await,
        RunnerProviderConfig::WindowsHyperV(_) => {
            Box::pin(run_windows_hyperv(&config, shutdown)).await
        }
        RunnerProviderConfig::MacosVirtualization(_) => {
            Box::pin(run_macos_virtualization(&config, shutdown)).await
        }
    }
}

async fn run_recomposition_loop<Generation, GenerationFuture>(
    shutdown: RunnerShutdown,
    mut run_generation: Generation,
) -> Result<(), RunnerProductError>
where
    Generation: FnMut(RunnerShutdown) -> GenerationFuture,
    GenerationFuture: Future<Output = Result<SupervisionDisposition, RunnerProductError>>,
{
    loop {
        if shutdown.is_requested() {
            return Ok(());
        }
        let disposition = run_generation(shutdown.clone()).await?;
        match disposition {
            SupervisionDisposition::Complete => return Ok(()),
            SupervisionDisposition::Recompose if shutdown.is_requested() => return Ok(()),
            SupervisionDisposition::Recompose => {
                info!("runner certificate renewed; rebuilding the runner composition");
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SupervisionDisposition {
    Complete,
    Recompose,
}

#[cfg(target_os = "linux")]
async fn run_local_docker(
    config: &RunnerProductConfig,
    shutdown: RunnerShutdown,
) -> Result<SupervisionDisposition, RunnerProductError> {
    require_dedicated_runner_user()?;
    let local = config
        .local_docker()
        .ok_or(RunnerProductError::ProviderConfiguration)?;
    let provider = automata_ci_local::connect_local_docker_provider(
        local.installation_binding().clone(),
        local.guest_image().clone(),
        local.results_transport().clone(),
        config.runner_id(),
        config.inventory().platform().architecture(),
    )
    .await?;
    if shutdown.is_requested() {
        return Ok(SupervisionDisposition::Complete);
    }
    let metrics = build_metrics(config, None)?;
    let provider = match &metrics {
        Some(metrics) => metrics.instrument_sandbox_provider(provider),
        None => provider,
    };
    let metrics_listener = match config.metrics() {
        Some(metrics) => Some(bind_metrics_listener(metrics.listen()).await?),
        None => None,
    };
    let composition = compose_with_provider(
        config,
        provider,
        metrics,
        &shutdown.probe,
        false,
        false,
        || Ok(()),
    )?
    .filter(|_| !shutdown.is_requested());
    let Some(composition) = composition else {
        return Ok(SupervisionDisposition::Complete);
    };
    supervise_composition(config, composition, metrics_listener, shutdown).await
}

#[cfg(not(target_os = "linux"))]
async fn run_local_docker(
    _config: &RunnerProductConfig,
    _shutdown: RunnerShutdown,
) -> Result<SupervisionDisposition, RunnerProductError> {
    Err(RunnerProductError::UnsupportedPlatform)
}

async fn run_podman(
    config: &RunnerProductConfig,
    shutdown: RunnerShutdown,
) -> Result<SupervisionDisposition, RunnerProductError> {
    require_dedicated_runner_user()?;
    let podman_options = prepare_admitted_podman(config)?;
    let network_policy = config.executor().network();
    let capability_admission =
        verify_configured_capabilities(&podman_options, network_policy, &shutdown.probe).await;
    let admission = finish_capability_admission(
        capability_admission,
        || revalidate_podman_launch_trust(&podman_options),
        || shutdown.is_requested(),
    )?;
    let Some(admission) = admission else {
        return Ok(SupervisionDisposition::Complete);
    };
    let metrics_listener = match config.metrics() {
        Some(metrics) => Some(bind_metrics_listener(metrics.listen()).await?),
        None => None,
    };
    let composition =
        compose_podman(config, &podman_options, &shutdown.probe, admission).map(|composition| {
            if shutdown.is_requested() {
                None
            } else {
                composition
            }
        });
    let started = after_admitted_value(composition, |composition| {
        revalidate_podman_launch_trust(&podman_options)?;
        Ok(composition)
    })?;
    let Some(composition) = started else {
        return Ok(SupervisionDisposition::Complete);
    };
    supervise_composition(config, composition, metrics_listener, shutdown).await
}

async fn run_kubernetes(
    config: &RunnerProductConfig,
    shutdown: RunnerShutdown,
) -> Result<SupervisionDisposition, RunnerProductError> {
    require_dedicated_runner_user()?;
    let kubernetes = config
        .kubernetes()
        .ok_or(RunnerProductError::ProviderConfiguration)?;
    let client = kube::Client::try_default()
        .await
        .map_err(RunnerProductError::KubernetesClient)?;
    if shutdown.is_requested() {
        return Ok(SupervisionDisposition::Complete);
    }
    let metrics = build_metrics(config, None)?;
    let provider: Arc<dyn automata_ci_execution::SandboxProvider> = Arc::new(
        automata_ci_sandbox_kubernetes::KubernetesSandboxProvider::new(
            client,
            kubernetes.adapter().clone(),
        )?,
    );
    let provider = match &metrics {
        Some(metrics) => metrics.instrument_sandbox_provider(provider),
        None => provider,
    };
    let metrics_listener = match config.metrics() {
        Some(metrics) => Some(bind_metrics_listener(metrics.listen()).await?),
        None => None,
    };
    let composition = compose_with_provider(
        config,
        provider,
        metrics,
        &shutdown.probe,
        false,
        false,
        || Ok(()),
    )?
    .filter(|_| !shutdown.is_requested());
    let Some(composition) = composition else {
        return Ok(SupervisionDisposition::Complete);
    };
    supervise_composition(config, composition, metrics_listener, shutdown).await
}

async fn run_windows_hyperv(
    config: &RunnerProductConfig,
    shutdown: RunnerShutdown,
) -> Result<SupervisionDisposition, RunnerProductError> {
    if shutdown.is_requested() {
        return Ok(SupervisionDisposition::Complete);
    }
    let metrics = build_metrics(config, None)?;
    let provider = build_windows_provider(config, metrics.as_ref())?;
    let metrics_listener = match config.metrics() {
        Some(metrics) => Some(bind_metrics_listener(metrics.listen()).await?),
        None => None,
    };
    let composition = compose_with_provider(
        config,
        provider,
        metrics,
        &shutdown.probe,
        false,
        false,
        || Ok(()),
    )?
    .filter(|_| !shutdown.is_requested());
    let Some(composition) = composition else {
        return Ok(SupervisionDisposition::Complete);
    };
    supervise_composition(config, composition, metrics_listener, shutdown).await
}

async fn run_macos_virtualization(
    config: &RunnerProductConfig,
    shutdown: RunnerShutdown,
) -> Result<SupervisionDisposition, RunnerProductError> {
    if shutdown.is_requested() {
        return Ok(SupervisionDisposition::Complete);
    }
    let metrics = build_metrics(config, None)?;
    let provider = build_macos_provider(config, metrics.as_ref())?;
    let metrics_listener = match config.metrics() {
        Some(metrics) => Some(bind_metrics_listener(metrics.listen()).await?),
        None => None,
    };
    let composition = compose_with_provider(
        config,
        provider,
        metrics,
        &shutdown.probe,
        false,
        false,
        || Ok(()),
    )?
    .filter(|_| !shutdown.is_requested());
    let Some(composition) = composition else {
        return Ok(SupervisionDisposition::Complete);
    };
    supervise_composition(config, composition, metrics_listener, shutdown).await
}

async fn supervise_composition(
    config: &RunnerProductConfig,
    composition: RunnerComposition,
    metrics_listener: Option<TcpListener>,
    shutdown: RunnerShutdown,
) -> Result<SupervisionDisposition, RunnerProductError> {
    mark_admitted_composition_ready(config, &composition);
    let RunnerComposition {
        supervisor,
        certificate_renewal,
        certificate_renewal_client,
        metrics,
        journal,
        spool,
    } = composition;
    let inner_shutdown = CancellationToken::new();
    let runtime_shutdown = inner_shutdown.clone();
    let runtime = async move { supervisor.run(runtime_shutdown).await };
    let exporter = metrics.as_ref().map(RunnerMetrics::exporter);
    let metrics_service = serve_metrics(metrics_listener, exporter, inner_shutdown.clone());
    let metrics_sampler = sample_metrics(metrics.clone(), journal, spool, inner_shutdown.clone());
    let renewal =
        certificate_renewal.run(config, certificate_renewal_client, shutdown.runtime.clone());
    tokio::pin!(runtime);
    tokio::pin!(metrics_service);
    tokio::pin!(metrics_sampler);
    tokio::pin!(renewal);
    let selected = select_composition_exit(
        &shutdown.runtime,
        runtime.as_mut(),
        metrics_service.as_mut(),
        metrics_sampler.as_mut(),
        renewal.as_mut(),
    )
    .await;
    let result = match selected {
        CompositionExit::Shutdown => {
            inner_shutdown.cancel();
            let runtime_result = (&mut runtime).await;
            let metrics_result = (&mut metrics_service).await;
            (&mut metrics_sampler).await?;
            info!("runner shutdown requested");
            metrics_result?;
            runtime_result.map_err(RunnerProductError::Runtime)?;
            Ok(SupervisionDisposition::Complete)
        }
        CompositionExit::Runtime(runtime_result) => {
            inner_shutdown.cancel();
            let metrics_result = (&mut metrics_service).await;
            (&mut metrics_sampler).await?;
            metrics_result?;
            runtime_result.map_err(RunnerProductError::Runtime)?;
            Ok(SupervisionDisposition::Complete)
        }
        CompositionExit::Metrics(metrics_result) => {
            inner_shutdown.cancel();
            let _runtime_result = (&mut runtime).await;
            (&mut metrics_sampler).await?;
            match metrics_result {
                Ok(()) => Err(RunnerProductError::MetricsExited),
                Err(error) => Err(error),
            }
        }
        CompositionExit::Sampler(sampler_result) => {
            inner_shutdown.cancel();
            let _runtime_result = (&mut runtime).await;
            let _metrics_result = (&mut metrics_service).await;
            match sampler_result {
                Ok(()) => Err(RunnerProductError::MetricsSamplerExited),
                Err(error) => Err(error),
            }
        }
        CompositionExit::Renewal(renewal_result) => {
            inner_shutdown.cancel();
            drain_recomposition_generation(
                runtime.as_mut(),
                metrics_service.as_mut(),
                metrics_sampler.as_mut(),
            )
            .await?;
            if shutdown.is_requested() {
                Ok(SupervisionDisposition::Complete)
            } else {
                match renewal_result.map_err(|_| RunnerProductError::CertificateRenewal)? {
                    CertificateRenewalOutcome::Renewed => Ok(SupervisionDisposition::Recompose),
                    CertificateRenewalOutcome::Cancelled => Ok(SupervisionDisposition::Complete),
                }
            }
        }
    };
    if let Some(metrics) = &metrics {
        metrics.set_ready(false);
    }
    result
}

async fn drain_recomposition_generation<RuntimeFuture, MetricsFuture, SamplerFuture>(
    runtime: Pin<&mut RuntimeFuture>,
    metrics: Pin<&mut MetricsFuture>,
    sampler: Pin<&mut SamplerFuture>,
) -> Result<(), RunnerProductError>
where
    RuntimeFuture: Future<Output = Result<(), automata_ci_runner_runtime::RunnerRuntimeError>>,
    MetricsFuture: Future<Output = Result<(), RunnerProductError>>,
    SamplerFuture: Future<Output = Result<(), RunnerProductError>>,
{
    let drain = async {
        let runtime_result = runtime.await;
        let metrics_result = metrics.await;
        let sampler_result = sampler.await;
        runtime_result.map_err(RunnerProductError::Runtime)?;
        metrics_result?;
        sampler_result?;
        Ok(())
    };
    tokio::time::timeout(RECOMPOSITION_DRAIN_TIMEOUT, drain)
        .await
        .map_err(|_| RunnerProductError::RecompositionDrainTimeout)?
}

enum CompositionExit<Runtime, Metrics, Sampler, Renewal> {
    Shutdown,
    Runtime(Runtime),
    Metrics(Metrics),
    Sampler(Sampler),
    Renewal(Renewal),
}

async fn select_composition_exit<RuntimeFuture, MetricsFuture, SamplerFuture, RenewalFuture>(
    shutdown: &CancellationToken,
    runtime: Pin<&mut RuntimeFuture>,
    metrics: Pin<&mut MetricsFuture>,
    sampler: Pin<&mut SamplerFuture>,
    renewal: Pin<&mut RenewalFuture>,
) -> CompositionExit<
    RuntimeFuture::Output,
    MetricsFuture::Output,
    SamplerFuture::Output,
    RenewalFuture::Output,
>
where
    RuntimeFuture: Future,
    MetricsFuture: Future,
    SamplerFuture: Future,
    RenewalFuture: Future,
{
    tokio::select! {
        biased;
        () = shutdown.cancelled() => CompositionExit::Shutdown,
        result = runtime => CompositionExit::Runtime(result),
        result = metrics => CompositionExit::Metrics(result),
        result = sampler => CompositionExit::Sampler(result),
        result = renewal => CompositionExit::Renewal(result),
    }
}

#[cfg(target_os = "linux")]
fn require_dedicated_runner_user() -> Result<(), RunnerProductError> {
    admit_effective_runner_user_id(rustix::process::geteuid().as_raw())
}

#[cfg(not(target_os = "linux"))]
fn require_dedicated_runner_user() -> Result<(), RunnerProductError> {
    Err(RunnerProductError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
fn admit_effective_runner_user_id(user: u32) -> Result<(), RunnerProductError> {
    if user == 0 {
        Err(RunnerProductError::RunnerUserTrust)
    } else {
        Ok(())
    }
}

fn prepare_admitted_podman(
    config: &RunnerProductConfig,
) -> Result<PodmanOptions, RunnerProductError> {
    let podman = config
        .podman()
        .ok_or(RunnerProductError::ProviderConfiguration)?;
    let runtime_mount =
        capture_dedicated_runtime_mount(podman.runtime_directory()).map_err(|reason| {
            error!(
                stage = "runtime_mount",
                ?reason,
                "runner Podman process trust validation failed"
            );
            RunnerProductError::PodmanProcessTrust
        })?;
    let podman_options = build_podman_options(config)?;
    prepare_probe_directories(&podman_options)?;
    #[cfg(target_os = "linux")]
    let trust = PodmanProcessTrust::capture(&podman_options, runtime_mount).map_err(|reason| {
        error!(
            stage = "process_inputs",
            ?reason,
            "runner Podman process trust validation failed"
        );
        RunnerProductError::PodmanProcessTrust
    })?;
    #[cfg(not(target_os = "linux"))]
    let trust = PodmanProcessTrust::capture(&podman_options, runtime_mount);
    Ok(podman_options.with_launch_trust(PodmanLaunchTrustHandle::new(Arc::new(trust))))
}

struct RunnerComposition {
    supervisor: RunnerSessionSupervisor,
    certificate_renewal: CertificateRenewal,
    certificate_renewal_client: Arc<dyn RunnerCertificateRenewalClient>,
    metrics: Option<RunnerMetrics>,
    journal: Arc<FileJournal>,
    spool: Arc<FileSpool>,
}

#[derive(Debug)]
struct CapabilityAdmission;

fn revalidate_podman_launch_trust(options: &PodmanOptions) -> Result<(), RunnerProductError> {
    options
        .process_environment()
        .validate_launch()
        .map_err(|_| RunnerProductError::PodmanProcessTrust)
}

fn finish_capability_admission(
    capability: Result<bool, RunnerProductError>,
    revalidate_process_trust: impl FnOnce() -> Result<(), RunnerProductError>,
    cancellation_requested: impl FnOnce() -> bool,
) -> Result<Option<CapabilityAdmission>, RunnerProductError> {
    let admitted = capability?;
    revalidate_process_trust()?;
    Ok((admitted && !cancellation_requested()).then_some(CapabilityAdmission))
}

fn mark_admitted_composition_ready(config: &RunnerProductConfig, composition: &RunnerComposition) {
    info!(
        runner_id = %config.runner_id(),
        control_authority = config
            .control_endpoint()
            .authority()
            .map_or("unknown", http::uri::Authority::as_str),
        slots = config.inventory().max_parallel_jobs(),
        "runner session supervisor starting"
    );
    if let Some(metrics) = &composition.metrics {
        metrics.set_ready(true);
    }
}

#[cfg(target_os = "linux")]
fn compose_podman(
    config: &RunnerProductConfig,
    podman_options: &PodmanOptions,
    cancellation: &crate::podman_probe::ProbeCancellation,
    _admission: CapabilityAdmission,
) -> Result<Option<RunnerComposition>, RunnerProductError> {
    let runner_cgroup = config
        .metrics()
        .and_then(|_| PodmanCommandExecutor::delegated_no_swap_cgroup(&SystemCommandExecutor));
    let metrics = build_metrics(config, runner_cgroup)?;
    revalidate_podman_launch_trust(podman_options)?;
    let provider = build_podman_provider(podman_options.clone(), metrics.as_ref())?;
    let podman = config
        .podman()
        .ok_or(RunnerProductError::ProviderConfiguration)?;
    compose_with_provider(
        config,
        provider,
        metrics,
        cancellation,
        podman.service_proxy_image().is_some(),
        podman.buildkit_runtime().is_some(),
        || revalidate_podman_launch_trust(podman_options),
    )
}

#[cfg(not(target_os = "linux"))]
fn compose_podman(
    _config: &RunnerProductConfig,
    _podman_options: &PodmanOptions,
    _cancellation: &crate::podman_probe::ProbeCancellation,
    _admission: CapabilityAdmission,
) -> Result<Option<RunnerComposition>, RunnerProductError> {
    Err(RunnerProductError::UnsupportedPlatform)
}

fn build_metrics(
    config: &RunnerProductConfig,
    runner_cgroup: Option<String>,
) -> Result<Option<RunnerMetrics>, RunnerProductError> {
    config
        .metrics()
        .map(|_| RunnerMetrics::new(config.inventory().max_parallel_jobs(), runner_cgroup))
        .transpose()
        .map_err(RunnerProductError::MetricsConfiguration)
}

fn compose_with_provider(
    config: &RunnerProductConfig,
    provider: Arc<dyn automata_ci_execution::SandboxProvider>,
    metrics: Option<RunnerMetrics>,
    cancellation: &crate::podman_probe::ProbeCancellation,
    service_proxy_configured: bool,
    buildkit_configured: bool,
    revalidate_provider_trust: impl FnOnce() -> Result<(), RunnerProductError>,
) -> Result<Option<RunnerComposition>, RunnerProductError> {
    let protocol_limits = ProtocolLimits::default();
    let certificate_renewal =
        CertificateRenewal::open(config).map_err(|_| RunnerProductError::CertificateRenewal)?;
    let tls = load_client_tls(config.tls())?;
    let transport = match &metrics {
        Some(metrics) => HyperRunnerControlClient::new_with_observer(
            config.control_endpoint(),
            &tls,
            protocol_limits,
            TransportLimits::default(),
            metrics.control_transport_observer(),
        ),
        None => HyperRunnerControlClient::new(
            config.control_endpoint(),
            &tls,
            protocol_limits,
            TransportLimits::default(),
        ),
    }?;
    let mut transport: Arc<dyn RunnerControlClient> = Arc::new(transport);
    if let Some(metrics) = &metrics {
        transport = metrics.instrument_control(transport);
    }
    let control = Arc::new(TransportControlClientAdapter::new(transport));
    let ephemeral: Arc<dyn RunnerEphemeralClient> = Arc::new(HyperRunnerEphemeralClient::new(
        config.control_endpoint(),
        &tls,
        TransportLimits::default(),
    )?);
    let certificate_renewal_client: Arc<dyn RunnerCertificateRenewalClient> =
        Arc::new(HyperRunnerCertificateRenewalClient::new(
            config.control_endpoint(),
            &tls,
            TransportLimits::default(),
        )?);

    let journal_options = metrics
        .as_ref()
        .map_or_else(FileJournalOptions::default, |metrics| {
            FileJournalOptions::default().with_observer(metrics.journal_observer())
        });
    let journal = Arc::new(FileJournal::open_with_options(
        config.state().journal().clone(),
        config.runner_id(),
        journal_options,
    )?);
    let protector = load_spool_keyring(config.spool())?;
    let spool_options = metrics
        .as_ref()
        .map_or_else(FileSpoolOptions::default, |metrics| {
            FileSpoolOptions::default().with_observer(metrics.spool_observer())
        });
    let spool = Arc::new(FileSpool::open_with_options(
        config.state().spool().clone(),
        protector,
        spool_options,
    )?);

    let runtime_inventory = build_admitted_runtime_inventory(
        config,
        provider.as_ref(),
        cancellation,
        service_proxy_configured,
        buildkit_configured,
        revalidate_provider_trust,
    );
    after_admitted_value(runtime_inventory, |runtime_inventory| {
        let executor = build_executor(config, provider, ephemeral)?;
        let runtime_config = RunnerRuntimeConfig::new(
            runtime_inventory,
            protocol_limits,
            automata_ci_runner_runtime::RunnerRuntimeLimits::default(),
        )?;
        let journal_port: Arc<dyn automata_ci_runner_journal::RunnerJournal> = journal.clone();
        let spool_port: Arc<dyn automata_ci_runner_spool::DurableContentStore> = spool.clone();
        let mut ports = RunnerRuntimePorts::new(
            control,
            journal_port,
            spool_port,
            executor,
            Arc::new(SystemRuntimeClock::new()),
            Arc::new(TokioRuntimeSleeper),
            Arc::new(SystemRuntimeIds),
        );
        if let Some(metrics) = &metrics {
            ports = ports.with_observer(metrics.runtime_observer());
            metrics.refresh(&journal, &spool);
        }
        Ok(RunnerComposition {
            supervisor: RunnerSessionSupervisor::new(runtime_config, ports),
            certificate_renewal,
            certificate_renewal_client,
            metrics,
            journal,
            spool,
        })
    })
}

fn after_admitted_value<Value, Next>(
    admitted: Result<Option<Value>, RunnerProductError>,
    continue_startup: impl FnOnce(Value) -> Result<Next, RunnerProductError>,
) -> Result<Option<Next>, RunnerProductError> {
    admitted?.map(continue_startup).transpose()
}

fn build_admitted_runtime_inventory(
    config: &RunnerProductConfig,
    provider: &dyn automata_ci_execution::SandboxProvider,
    cancellation: &crate::podman_probe::ProbeCancellation,
    service_proxy_configured: bool,
    buildkit_configured: bool,
    revalidate_provider_trust: impl FnOnce() -> Result<(), RunnerProductError>,
) -> Result<Option<RunnerCapabilities>, RunnerProductError> {
    let admission = admit_configured_environment_profiles(config, provider, cancellation);
    after_profile_admission(admission, || {
        revalidate_provider_trust()?;
        Ok(inventory_for_verified_provider(
            config.inventory(),
            service_proxy_configured,
            buildkit_configured,
            provider.capabilities(),
        ))
    })
}

fn after_profile_admission<Inventory>(
    admission: Result<ProfileAdmissionOutcome, RunnerProductError>,
    build_inventory: impl FnOnce() -> Result<Inventory, RunnerProductError>,
) -> Result<Option<Inventory>, RunnerProductError> {
    match admission? {
        ProfileAdmissionOutcome::Admitted => build_inventory().map(Some),
        ProfileAdmissionOutcome::Cancelled => Ok(None),
    }
}

fn admit_configured_environment_profiles(
    config: &RunnerProductConfig,
    provider: &dyn automata_ci_execution::SandboxProvider,
    cancellation: &crate::podman_probe::ProbeCancellation,
) -> Result<ProfileAdmissionOutcome, RunnerProductError> {
    // The provider's exact create path also provisions the attempt-scoped
    // Docker API when configured, so its advertised feature is covered by the
    // same lifecycle evidence as every environment profile.
    let capacity = config.executor().resource_capacity();
    let allocation = automata_ci_core::JobResourceAllocation::new(capacity, capacity)
        .map_err(|_| RunnerProductError::SandboxProviderInvariant)?;
    let policy = ProfileAdmissionPolicy::new(
        config.executor().network(),
        config.executor().root_filesystem(),
        config.executor().privilege(),
        config.executor().resources(),
        allocation,
    );
    let toolchain = config.executor().toolchain();
    let policy = match config.provider() {
        RunnerProviderConfig::WindowsHyperV(_) => policy
            .with_windows_hyperv_shells(
                toolchain
                    .pwsh()
                    .ok_or(RunnerProductError::ProviderConfiguration)?
                    .clone(),
                toolchain
                    .powershell()
                    .ok_or(RunnerProductError::ProviderConfiguration)?
                    .clone(),
                toolchain
                    .cmd()
                    .ok_or(RunnerProductError::ProviderConfiguration)?
                    .clone(),
                toolchain.python().cloned(),
            )
            .map_err(|_| RunnerProductError::ProviderConfiguration)?,
        RunnerProviderConfig::MacosVirtualization(_) => policy
            .with_virtualized_macos_shells(
                config.executor().runner_root().clone(),
                toolchain
                    .bash()
                    .ok_or(RunnerProductError::ProviderConfiguration)?
                    .clone(),
                toolchain
                    .sh()
                    .ok_or(RunnerProductError::ProviderConfiguration)?
                    .clone(),
                toolchain.python().cloned(),
                toolchain.pwsh().cloned(),
            )
            .map_err(|_| RunnerProductError::ProviderConfiguration)?,
        RunnerProviderConfig::Podman(_)
        | RunnerProviderConfig::LocalDocker(_)
        | RunnerProviderConfig::Kubernetes(_) => policy
            .with_linux_tools(
                toolchain
                    .bash()
                    .ok_or(RunnerProductError::ProviderConfiguration)?
                    .clone(),
                toolchain
                    .sh()
                    .ok_or(RunnerProductError::ProviderConfiguration)?
                    .clone(),
                toolchain.python().cloned(),
                toolchain.pwsh().cloned(),
                toolchain
                    .install()
                    .ok_or(RunnerProductError::ProviderConfiguration)?
                    .clone(),
                toolchain
                    .tar()
                    .ok_or(RunnerProductError::ProviderConfiguration)?
                    .clone(),
                toolchain
                    .sha256sum()
                    .ok_or(RunnerProductError::ProviderConfiguration)?
                    .clone(),
                toolchain.node12().cloned(),
                toolchain.node16().cloned(),
                toolchain.node20().cloned(),
                toolchain.node24().cloned(),
            )
            .map_err(|_| RunnerProductError::ProviderConfiguration)?,
    };
    report_profile_admission(
        admit_runner_profiles(config, provider, policy, cancellation),
        config.environments().len(),
    )
}

fn report_profile_admission(
    result: Result<ProfileAdmissionOutcome, ProfileAdmissionError>,
    profile_count: usize,
) -> Result<ProfileAdmissionOutcome, RunnerProductError> {
    match result {
        Ok(ProfileAdmissionOutcome::Admitted) => {
            info!(
                profiles = profile_count,
                "runner environment profiles admitted by provider lifecycle"
            );
            Ok(ProfileAdmissionOutcome::Admitted)
        }
        Ok(ProfileAdmissionOutcome::Cancelled) => Ok(ProfileAdmissionOutcome::Cancelled),
        Err(error) => {
            error!(
                kind = ?error.kind(),
                cleanup = ?error.cleanup_status(),
                provider_kind = ?error.provider_error().map(automata_ci_execution::ProviderError::kind),
                provider_stage = ?error.provider_error().map(automata_ci_execution::ProviderError::stage),
                execution_kind = ?error.execution_error().map(|error| error.kind()),
                execution_stage = ?error.execution_error().map(|error| error.stage()),
                cleanup_provider_kind = ?error.cleanup_error().map(automata_ci_execution::ProviderError::kind),
                cleanup_provider_stage = ?error.cleanup_error().map(automata_ci_execution::ProviderError::stage),
                "runner environment-profile admission failed"
            );
            Err(RunnerProductError::EnvironmentProfileAdmission)
        }
    }
}

fn admit_runner_profiles(
    config: &RunnerProductConfig,
    provider: &dyn automata_ci_execution::SandboxProvider,
    policy: ProfileAdmissionPolicy,
    cancellation: &crate::podman_probe::ProbeCancellation,
) -> Result<ProfileAdmissionOutcome, ProfileAdmissionError> {
    admit_environment_profiles(
        provider,
        config.runner_id(),
        config.environments(),
        policy,
        cancellation,
    )
}

async fn bind_metrics_listener(
    listen: std::net::SocketAddr,
) -> Result<TcpListener, RunnerProductError> {
    TcpListener::bind(listen)
        .await
        .map_err(RunnerProductError::MetricsBind)
}

async fn serve_metrics(
    listener: Option<TcpListener>,
    exporter: Option<automata_ci_metrics::Metrics>,
    shutdown: CancellationToken,
) -> Result<(), RunnerProductError> {
    match (listener, exporter) {
        (Some(listener), Some(exporter)) => axum::serve(listener, exporter.router())
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await
            .map_err(RunnerProductError::MetricsServe),
        (None, None) => {
            shutdown.cancelled().await;
            Ok(())
        }
        _ => Err(RunnerProductError::MetricsConfigurationInvariant),
    }
}

async fn sample_metrics(
    metrics: Option<RunnerMetrics>,
    journal: Arc<FileJournal>,
    spool: Arc<FileSpool>,
    shutdown: CancellationToken,
) -> Result<(), RunnerProductError> {
    let Some(metrics) = metrics else {
        shutdown.cancelled().await;
        return Ok(());
    };
    tokio::spawn(metrics.sample_until_cancelled(journal, spool, shutdown))
        .await
        .map_err(RunnerProductError::MetricsSampler)
}

fn build_podman_options(config: &RunnerProductConfig) -> Result<PodmanOptions, RunnerProductError> {
    let podman = config
        .podman()
        .ok_or(RunnerProductError::ProviderConfiguration)?;
    let state_root = config
        .state()
        .podman()
        .ok_or(RunnerProductError::ProviderConfiguration)?;
    if state_root.as_os_str() != required_podman_state_root(podman.runtime_directory()).as_os_str()
    {
        return Err(RunnerProductError::PodmanProcessTrust);
    }
    ensure_private_directory(state_root)?;
    let podman_root = PodmanStateRoot::existing(state_root.to_path_buf())?;
    let podman_environment = PodmanProcessEnvironment::new(
        podman.home().to_path_buf(),
        podman.runtime_directory().to_path_buf(),
        state_root.to_path_buf(),
        podman.approved_helper_directory().to_path_buf(),
        podman.conmon_path().to_path_buf(),
        podman.oci_runtime_path().to_path_buf(),
        podman.init_path().to_path_buf(),
        podman.seccomp_profile_path().to_path_buf(),
    )?;
    let mut podman_options = PodmanOptions::new(
        PodmanBinary::new(podman.binary().to_path_buf())?,
        podman_root,
        podman_environment,
    )?
    .with_job_container_engine(podman.job_container_engine());
    if let Some(alias) = podman.github_server_host_gateway_alias() {
        podman_options = podman_options.with_host_gateway_alias(alias.clone())?;
    }
    if let Some(image) = podman.service_proxy_image() {
        podman_options = podman_options.with_service_proxy_image(image.clone());
    }
    if let Some(runtime) = podman.buildkit_runtime() {
        podman_options = podman_options.with_buildkit_runtime(runtime.clone());
    }
    Ok(podman_options)
}

fn inventory_for_verified_provider(
    configured: &RunnerCapabilities,
    service_proxy_configured: bool,
    buildkit_configured: bool,
    provider: &ProviderCapabilities,
) -> RunnerCapabilities {
    let mut container_features = configured.containers().features().clone();
    container_features.remove(&ContainerFeature::SERVICE_CONTAINERS);
    container_features.remove(&ContainerFeature::BUILDKIT);
    if service_proxy_configured && provider.supports(SandboxCapability::ServiceContainers) {
        container_features.insert(ContainerFeature::SERVICE_CONTAINERS);
    }
    if buildkit_configured && provider.supports(SandboxCapability::BuildKit) {
        container_features.insert(ContainerFeature::BUILDKIT);
    }
    configured
        .clone()
        .with_containers(ContainerCapabilities::new(container_features))
}

fn prepare_probe_directories(options: &PodmanOptions) -> Result<(), RunnerProductError> {
    options.prepare_state()?;
    ensure_private_directory(&options.state_root().as_path().join("active-probe"))?;
    Ok(())
}

async fn verify_configured_capabilities(
    podman_options: &PodmanOptions,
    network_policy: automata_ci_execution::NetworkPolicy,
    cancellation: &crate::podman_probe::ProbeCancellation,
) -> Result<bool, RunnerProductError> {
    let probe = crate::podman_probe::probe_configured_current_executable_with_control(
        podman_options,
        network_policy,
        cancellation,
    )
    .await;
    if probe.is_usable() {
        info!(
            capability = probe.capability(),
            cleanup = ?probe.cleanup_status(),
            "runner capability admitted by active probe"
        );
        return Ok(true);
    }
    if cancellation.is_cancelled() {
        if probe.cleanup_status() == crate::capability_probe::ProbeCleanupStatus::Failed {
            error!(
                capability = probe.capability(),
                cleanup = ?probe.cleanup_status(),
                "runner capability admission was interrupted and probe cleanup failed"
            );
        }
        return Ok(false);
    }
    error!(
        capability = probe.capability(),
        status = ?probe.status(),
        cleanup = ?probe.cleanup_status(),
        reason = ?probe
            .reason()
            .map(crate::capability_probe::ProbeReason::code),
        "runner capability admission failed"
    );
    Err(RunnerProductError::CapabilityAdmission)
}

#[cfg(target_os = "linux")]
fn build_podman_provider(
    podman_options: PodmanOptions,
    metrics: Option<&RunnerMetrics>,
) -> Result<Arc<dyn automata_ci_execution::SandboxProvider>, RunnerProductError> {
    let provider: Arc<dyn automata_ci_execution::SandboxProvider> = match metrics {
        Some(metrics) => Arc::new(RootlessPodmanProvider::open_with_observer(
            podman_options,
            metrics.podman_observer(),
        )?),
        None => Arc::new(RootlessPodmanProvider::open(podman_options)?),
    };
    match metrics {
        Some(metrics) => Ok(metrics.instrument_sandbox_provider(provider)),
        None => Ok(provider),
    }
}

fn build_windows_provider(
    config: &RunnerProductConfig,
    metrics: Option<&RunnerMetrics>,
) -> Result<Arc<dyn automata_ci_execution::SandboxProvider>, RunnerProductError> {
    let windows = config
        .windows_hyperv()
        .ok_or(RunnerProductError::ProviderConfiguration)?;
    let state_root = config
        .state()
        .windows_hyperv()
        .ok_or(RunnerProductError::ProviderConfiguration)?;
    let options = WindowsHyperVContainerProviderOptions::new(
        state_root.to_path_buf(),
        windows.runtime_executable().to_path_buf(),
        windows.runtime_sha256(),
        windows.guest_agent_path().clone(),
    )?
    .with_operation_timeout(windows.operation_timeout())?;
    let provider: Arc<dyn automata_ci_execution::SandboxProvider> =
        Arc::new(WindowsHyperVContainerProvider::open(options)?);
    match metrics {
        Some(metrics) => Ok(metrics.instrument_sandbox_provider(provider)),
        None => Ok(provider),
    }
}

fn build_macos_provider(
    config: &RunnerProductConfig,
    metrics: Option<&RunnerMetrics>,
) -> Result<Arc<dyn automata_ci_execution::SandboxProvider>, RunnerProductError> {
    if config.macos_virtualization().is_none() {
        return Err(RunnerProductError::ProviderConfiguration);
    }
    let state_root = config
        .state()
        .macos_virtualization()
        .ok_or(RunnerProductError::ProviderConfiguration)?;
    let macos = config
        .macos_virtualization()
        .ok_or(RunnerProductError::ProviderConfiguration)?;
    let options = MacosVirtualizationProviderOptions::new(
        state_root.to_path_buf(),
        macos.helper_executable().to_path_buf(),
        macos.helper_sha256(),
        macos.helper_code_requirement().to_owned(),
        macos.template_manifest().to_path_buf(),
        macos.template_manifest_sha256(),
        macos.storage_volume_uuid(),
        macos.storage_quota_bytes(),
        macos.boot_timeout(),
        macos.stop_timeout(),
    )?;
    let provider: Arc<dyn automata_ci_execution::SandboxProvider> =
        Arc::new(MacosVirtualizationProvider::open(options)?);
    match metrics {
        Some(metrics) => Ok(metrics.instrument_sandbox_provider(provider)),
        None => Ok(provider),
    }
}

fn build_executor(
    config: &RunnerProductConfig,
    provider: Arc<dyn automata_ci_execution::SandboxProvider>,
    ephemeral: Arc<dyn RunnerEphemeralClient>,
) -> Result<Arc<dyn JobExecutor>, RunnerProductError> {
    let blobs = build_object_store(config)?;
    let action_preparer = build_action_preparer(config, &blobs)?;
    let job_content = Arc::new(ImmutableJobContent::new(
        blobs,
        automata_ci_execution::MAX_COPY_BYTES as u64,
    )?);
    let environments = Arc::new(ImmutableSandboxEnvironmentCatalog::new(
        config.environments().values().cloned(),
    )?);
    let toolchain = Arc::new(build_toolchain(config)?);
    let contexts = Arc::new(StandardGithubContext::new(
        config.runner_id(),
        config.inventory().platform().clone(),
        config.environments(),
        config.executor(),
        config.github().clone(),
    )?);
    let executor_config = GithubJobExecutorConfig::new(
        config.executor().resources(),
        config.executor().network(),
        config.executor().root_filesystem(),
        config.executor().privilege(),
        config.executor().default_step_timeout(),
        config.executor().maximum_output_bytes(),
        config.executor().runner_root().clone(),
    )?;
    let executor = Arc::new(GithubJobExecutor::new(
        executor_config,
        GithubJobExecutorPorts::new(
            provider,
            environments,
            action_preparer,
            job_content,
            // The reusable base stays secretless. ManagedSecretJobExecutor
            // replaces this port only on one verified execution.
            Arc::new(NoSecrets),
            contexts,
            toolchain,
            Arc::new(DeterministicOperationIds),
            Arc::new(SystemExecutionClock),
        ),
    ));
    Ok(Arc::new(ManagedSecretJobExecutor::new(
        config.runner_id(),
        executor,
        ephemeral,
        Arc::new(automata_ci_auth::secret::SystemSecureRandom),
    )))
}

fn build_action_preparer(
    config: &RunnerProductConfig,
    blobs: &Arc<dyn ImmutableBlobStore>,
) -> Result<Arc<dyn ActionPreparationPort>, RunnerProductError> {
    let github_endpoint = config.github().http_endpoint()?;
    let scm: Arc<dyn ScmProvider> = Arc::new(github_endpoint);
    let resolver = ImmutableActionResolver::new(scm, Arc::clone(blobs));
    #[cfg(unix)]
    let resolver = {
        let state_root = config.state().journal().as_path();
        let references = Arc::new(FileActionReferenceIndex::open(
            ActionReferenceIndexRoot::explicit(state_root.join("action-reference-cache"))?,
            ActionReferenceIndexLimits::default(),
        )?);
        let archives = Arc::new(FileActionArchiveCache::open(
            ActionArchiveCacheRoot::explicit(state_root.join("action-archive-cache"))?,
            ActionArchiveCacheLimits::default(),
        )?);
        // The resolver itself enforces that only credential-free, canonical
        // exact commits can consult or populate these caches. Private and
        // mutable references always re-authorize through SCM.
        resolver
            .with_reference_index(references)
            .with_local_blob_cache(archives)
    };
    let resolver: Arc<dyn ActionResolver> = Arc::new(resolver);
    Ok(Arc::new(ResolvedBundleActionPreparer::new(
        resolver,
        Arc::new(NoRepositoryCredentials),
        Arc::new(GithubActionMetadataDecoder::new(
            GithubActionMetadataLimits::default(),
        )),
        GithubConditionCompiler::default(),
        ActionBundleLimits::default(),
        automata_ci_execution::MAX_COPY_BYTES as u64,
    )?))
}

fn build_object_store(
    config: &RunnerProductConfig,
) -> Result<Arc<dyn ImmutableBlobStore>, RunnerProductError> {
    let object_store = config.object_store();
    let store_config = match object_store.tls_trust() {
        ObjectStoreTlsTrust::WebPki => object_store.store_config().clone(),
        ObjectStoreTlsTrust::PrivateCa { certificate_source } => object_store
            .store_config()
            .clone()
            .with_tls_trust(load_s3_private_ca(certificate_source)?)?,
    };
    let credentials = load_s3_credentials(
        object_store.access_key_id(),
        object_store.secret_access_key(),
        object_store.session_token(),
    )?;
    Ok(Arc::new(store_config.connect(credentials)?))
}

/// Loads the exact configured S3 HTTPS trust policy from its bounded source.
///
/// # Errors
///
/// Returns a sanitized product error when a private CA source is unavailable,
/// excessive, malformed, or not exactly one X.509 CA certificate.
fn load_s3_private_ca(certificate_source: &SecretSource) -> Result<S3TlsTrust, RunnerProductError> {
    let mut certificate_pem = certificate_source.read(MAX_S3_PRIVATE_CA_PEM_BYTES)?;
    S3TlsTrust::private_ca(std::mem::take(&mut *certificate_pem))
        .map_err(RunnerProductError::ObjectStore)
}

fn build_toolchain(
    config: &RunnerProductConfig,
) -> Result<StaticGithubToolchain, RunnerProductError> {
    let configured = config.executor().toolchain();
    let mut toolchain = match config.provider() {
        RunnerProviderConfig::Podman(_)
        | RunnerProviderConfig::LocalDocker(_)
        | RunnerProviderConfig::Kubernetes(_) => StaticGithubToolchain::new(
            configured
                .bash()
                .ok_or(RunnerProductError::ProviderConfiguration)?
                .clone(),
            configured
                .sh()
                .ok_or(RunnerProductError::ProviderConfiguration)?
                .clone(),
            configured
                .install()
                .ok_or(RunnerProductError::ProviderConfiguration)?
                .clone(),
            configured
                .tar()
                .ok_or(RunnerProductError::ProviderConfiguration)?
                .clone(),
            configured
                .sha256sum()
                .ok_or(RunnerProductError::ProviderConfiguration)?
                .clone(),
        )?,
        RunnerProviderConfig::WindowsHyperV(_) => StaticGithubToolchain::windows(
            configured
                .pwsh()
                .ok_or(RunnerProductError::ProviderConfiguration)?
                .clone(),
            configured
                .powershell()
                .ok_or(RunnerProductError::ProviderConfiguration)?
                .clone(),
            configured
                .cmd()
                .ok_or(RunnerProductError::ProviderConfiguration)?
                .clone(),
        )?,
        RunnerProviderConfig::MacosVirtualization(_) => StaticGithubToolchain::macos(
            configured
                .bash()
                .ok_or(RunnerProductError::ProviderConfiguration)?
                .clone(),
            configured
                .sh()
                .ok_or(RunnerProductError::ProviderConfiguration)?
                .clone(),
            configured
                .install()
                .ok_or(RunnerProductError::ProviderConfiguration)?
                .clone(),
            configured
                .tar()
                .ok_or(RunnerProductError::ProviderConfiguration)?
                .clone(),
            configured
                .sha256sum()
                .ok_or(RunnerProductError::ProviderConfiguration)?
                .clone(),
        )?,
    };
    if let Some(path) = configured.python() {
        toolchain = toolchain.with_python(path.clone())?;
    }
    if matches!(
        config.provider(),
        RunnerProviderConfig::Podman(_)
            | RunnerProviderConfig::LocalDocker(_)
            | RunnerProviderConfig::Kubernetes(_)
            | RunnerProviderConfig::MacosVirtualization(_)
    ) && let Some(path) = configured.pwsh()
    {
        toolchain = toolchain.with_pwsh(path.clone())?;
    }
    for (runtime, path) in [
        (JavascriptRuntime::Node12, configured.node12()),
        (JavascriptRuntime::Node16, configured.node16()),
        (JavascriptRuntime::Node20, configured.node20()),
        (JavascriptRuntime::Node24, configured.node24()),
    ] {
        if let Some(path) = path {
            toolchain = toolchain.with_node(runtime, path.clone())?;
        }
    }
    Ok(toolchain)
}

/// Loads one file- or environment-backed AES-256 spool key from hexadecimal text.
///
/// # Errors
///
/// Returns a sanitized product error when the scalar source is unavailable,
/// malformed, or not exactly one AES-256 key.
pub fn load_spool_key(source: &SecretSource) -> Result<Zeroizing<Vec<u8>>, RunnerProductError> {
    let encoded = source.read_scalar(AES_256_GCM_KEY_BYTES * 2)?;
    if encoded.len() != AES_256_GCM_KEY_BYTES * 2 {
        return Err(RunnerProductError::InvalidSpoolKey);
    }
    let mut decoded = Zeroizing::new(vec![0_u8; AES_256_GCM_KEY_BYTES]);
    for (index, pair) in encoded.chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or(RunnerProductError::InvalidSpoolKey)?;
        let low = hex_nibble(pair[1]).ok_or(RunnerProductError::InvalidSpoolKey)?;
        decoded[index] = (high << 4) | low;
    }
    Ok(decoded)
}

/// Loads every configured spool key and constructs the bounded active/decrypt-only keyring.
///
/// # Errors
///
/// Returns a sanitized product error if any source is unavailable or malformed,
/// or if the cryptographic keyring rejects the configuration. A partially
/// loaded keyring is never returned.
pub fn load_spool_keyring(
    config: &super::SpoolProtectionConfig,
) -> Result<Arc<dyn ContentProtector>, RunnerProductError> {
    let active =
        Aes256GcmContentProtector::new(config.protection_id(), load_spool_key(config.key_hex())?)
            .map_err(|_| RunnerProductError::Protector)?;
    let decrypt_only = config
        .decrypt_only_keys()
        .map(|(protection_id, source)| {
            Aes256GcmContentProtector::new(protection_id, load_spool_key(source)?)
                .map_err(|_| RunnerProductError::Protector)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let keyring = Aes256GcmContentKeyring::new(active, decrypt_only)
        .map_err(|_| RunnerProductError::Protector)?;
    Ok(Arc::new(keyring))
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn read_secret_text(
    source: &SecretSource,
    maximum_bytes: usize,
) -> Result<String, RunnerProductError> {
    let mut bytes = source.read_scalar(maximum_bytes)?;
    let value = String::from_utf8(std::mem::take(&mut *bytes))
        .map_err(|_| RunnerProductError::InvalidSecretText)?;
    if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(RunnerProductError::InvalidSecretText);
    }
    Ok(value)
}

/// Loads bounded static S3 credentials from secret references.
///
/// # Errors
///
/// Returns a sanitized product error when any source is unavailable, not one
/// valid scalar, or rejected by the S3 credential boundary.
pub fn load_s3_credentials(
    access_key_id: &SecretSource,
    secret_access_key: &SecretSource,
    session_token: Option<&SecretSource>,
) -> Result<StaticS3Credentials, RunnerProductError> {
    let access_key_id = read_secret_text(access_key_id, MAX_S3_ACCESS_KEY_BYTES)?;
    let secret_access_key = read_secret_text(secret_access_key, MAX_S3_SECRET_BYTES)?;
    let session_token = session_token
        .map(|source| read_secret_text(source, MAX_S3_SECRET_BYTES))
        .transpose()?;
    StaticS3Credentials::new(access_key_id, secret_access_key, session_token)
        .map_err(RunnerProductError::ObjectStore)
}

/// Sanitized production runner startup or supervision failure.
#[derive(Debug, Error)]
pub enum RunnerProductError {
    /// Product configuration failed validation.
    #[error("runner product configuration failed")]
    Configuration(#[from] RunnerProductConfigError),
    /// One explicitly configured input could not be loaded securely.
    #[error("runner secure input failed")]
    SecureInput(#[from] super::SecureInputError),
    /// Spool key text was not exactly one AES-256 key in hexadecimal form.
    #[error("runner spool key is invalid")]
    InvalidSpoolKey,
    /// A secret text source contained invalid encoding or control bytes.
    #[error("runner secret text source is invalid")]
    InvalidSecretText,
    /// Outbound mTLS identity material was invalid.
    #[error("runner mTLS configuration failed")]
    Tls(#[from] ClientTlsMaterialError),
    /// Runner control transport configuration failed.
    #[error("runner control transport configuration failed")]
    TransportConfiguration(#[from] automata_ci_runner_transport::ConfigurationError),
    /// Runner certificate renewal or durable identity rotation failed.
    #[error("runner certificate renewal failed")]
    CertificateRenewal,
    /// Old runner tasks did not stop inside the bounded identity-reload drain.
    #[error("runner certificate recomposition drain timed out")]
    RecompositionDrainTimeout,
    /// Crash-durable journal initialization failed.
    #[error("runner durable journal initialization failed")]
    Journal(#[from] automata_ci_runner_journal::JournalError),
    /// Local immutable action-reference cache initialization failed.
    #[cfg(unix)]
    #[error("runner action reference cache initialization failed")]
    ActionReferenceCache(#[from] automata_ci_action::ActionReferenceIndexError),
    /// Local immutable action archive cache initialization failed.
    #[cfg(unix)]
    #[error("runner action archive cache initialization failed")]
    ActionArchiveCache(#[from] automata_ci_blob::BlobStoreError),
    /// Protected spool initialization failed.
    #[error("runner protected spool initialization failed")]
    Spool(#[from] automata_ci_runner_spool::SpoolError),
    /// At-rest content protector initialization failed.
    #[error("runner content protector initialization failed")]
    Protector,
    /// Provider state-root preparation failed.
    #[error("runner provider state-root initialization failed")]
    StateRoot(#[from] ProductStateRootError),
    /// The production runner was not launched as a dedicated non-root user.
    #[error("runner user trust validation failed")]
    RunnerUserTrust,
    /// Rootless Podman configuration failed.
    #[error("runner Podman configuration failed")]
    PodmanConfiguration(#[from] automata_ci_sandbox_podman::PodmanConfigurationError),
    /// The configured Podman executable or process filesystem trust boundary was unsafe.
    #[error("runner Podman process trust validation failed")]
    PodmanProcessTrust,
    /// The configured rootless Podman state root was not a safe existing directory.
    #[error("runner Podman state-root validation failed")]
    PodmanState(#[from] automata_ci_sandbox_podman::PodmanStateRootError),
    /// Rootless Podman initialization failed.
    #[error("runner Podman provider initialization failed")]
    PodmanOpen(#[from] automata_ci_sandbox_podman::PodmanOpenError),
    /// Fixed-relay local Docker provider initialization failed.
    #[error("runner local Docker provider initialization failed")]
    LocalDocker(#[from] automata_ci_local::LocalDockerError),
    /// The provider-specific product configuration was internally inconsistent.
    #[error("runner provider configuration is inconsistent")]
    ProviderConfiguration,
    /// Ambient Kubernetes client discovery or authentication failed.
    #[error("runner Kubernetes client initialization failed")]
    KubernetesClient(#[source] kube::Error),
    /// Kubernetes sandbox adapter configuration failed.
    #[error("runner Kubernetes provider configuration failed")]
    KubernetesConfiguration(#[from] automata_ci_sandbox_kubernetes::KubernetesConfigurationError),
    /// Sandbox provider initialization failed.
    #[error("runner sandbox provider initialization failed")]
    SandboxProvider(#[from] automata_ci_execution::ProviderError),
    /// Product configuration and the selected provider path disagreed.
    #[error("runner sandbox provider composition invariant failed")]
    SandboxProviderInvariant,
    /// The configured Podman network admission boundary did not produce usable evidence.
    #[error("runner capability admission failed")]
    CapabilityAdmission,
    /// A configured environment did not pass the exact provider lifecycle admission boundary.
    #[error("runner environment-profile admission failed")]
    EnvironmentProfileAdmission,
    /// S3-compatible immutable object-store configuration failed.
    #[error("runner object-store configuration failed")]
    ObjectStore(#[from] automata_ci_blob_s3::S3BlobStoreConfigError),
    /// GitHub SCM endpoint construction failed.
    #[error("runner GitHub endpoint configuration failed")]
    Github(#[from] automata_ci_github::GithubHttpConfigurationError),
    /// GitHub action preparation composition failed.
    #[error("runner action preparation configuration failed")]
    ActionPreparation(#[from] automata_ci_job_executor_github::ActionPreparationError),
    /// GitHub executor port configuration failed.
    #[error("runner executor port configuration failed")]
    ExecutorPort(#[from] automata_ci_job_executor_github::PortError),
    /// GitHub executor policy failed validation.
    #[error("runner executor policy configuration failed")]
    ExecutorConfiguration(#[from] automata_ci_job_executor_github::GithubJobExecutorConfigError),
    /// Runner session runtime policy failed validation.
    #[error("runner session runtime configuration failed")]
    RuntimeConfiguration(#[from] automata_ci_runner_runtime::RunnerRuntimeConfigError),
    /// Runner session supervision failed.
    #[error("runner session supervision failed")]
    Runtime(#[source] automata_ci_runner_runtime::RunnerRuntimeError),
    /// Common metric provenance or registry construction failed validation.
    #[error("runner metrics configuration failed")]
    MetricsConfiguration(#[source] automata_ci_metrics::BuildInfoError),
    /// Metrics listener binding failed after observability was explicitly enabled.
    #[error("runner metrics listener bind failed")]
    MetricsBind(#[source] std::io::Error),
    /// Metrics listener serving failed.
    #[error("runner metrics listener failed")]
    MetricsServe(#[source] std::io::Error),
    /// Metrics listener stopped while the runner supervisor was still active.
    #[error("runner metrics listener exited unexpectedly")]
    MetricsExited,
    /// Metrics registry and listener configuration were internally inconsistent.
    #[error("runner metrics composition is inconsistent")]
    MetricsConfigurationInvariant,
    /// The bounded in-memory metrics sampler task panicked or was cancelled unexpectedly.
    #[error("runner metrics sampler failed")]
    MetricsSampler(#[source] JoinError),
    /// The metrics sampler stopped while the runner supervisor was still active.
    #[error("runner metrics sampler exited unexpectedly")]
    MetricsSamplerExited,
    /// Production execution is unsupported on this platform.
    #[error("runner production mode is unsupported on this platform")]
    UnsupportedPlatform,
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        net::{IpAddr, Ipv4Addr, SocketAddr},
    };

    #[cfg(unix)]
    use std::{fs, os::unix::fs::PermissionsExt as _, path::PathBuf};

    use automata_ci_metrics::OPENMETRICS_CONTENT_TYPE;

    #[cfg(unix)]
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};

    use super::*;

    #[cfg(unix)]
    struct PrivateCaFixture {
        root: PathBuf,
        source: SecretSource,
    }

    #[cfg(unix)]
    impl PrivateCaFixture {
        fn new(bytes: &[u8]) -> Self {
            let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .and_then(std::path::Path::parent)
                .expect("workspace root")
                .join("target/runner-s3-private-ca-tests")
                .join(uuid::Uuid::new_v4().simple().to_string());
            fs::create_dir_all(&root).expect("create private CA fixture root");
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("restrict private CA fixture root");
            let path = root.join("ca.pem");
            fs::write(&path, bytes).expect("write private CA fixture");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("restrict private CA fixture");
            Self {
                root,
                source: SecretSource::File { path },
            }
        }
    }

    #[cfg(unix)]
    impl Drop for PrivateCaFixture {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.root);
        }
    }

    #[cfg(unix)]
    #[test]
    fn private_ca_binding_loads_one_bounded_exact_redacted_source() {
        let key = KeyPair::generate().expect("private CA key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("private CA params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let pem = params
            .self_signed(&key)
            .expect("self-signed private CA")
            .pem();
        let certificate = PrivateCaFixture::new(pem.as_bytes());
        let trust = load_s3_private_ca(&certificate.source).expect("one exact private CA");
        assert_eq!(
            format!("{trust:?}"),
            "S3TlsTrust::PrivateCa([certificate redacted])"
        );
        assert!(!format!("{trust:?}").contains(&pem));

        let malformed = PrivateCaFixture::new(b"private CA content must never escape");
        assert!(matches!(
            load_s3_private_ca(&malformed.source),
            Err(RunnerProductError::ObjectStore(
                automata_ci_blob_s3::S3BlobStoreConfigError::InvalidPrivateCa
            ))
        ));

        let oversized = PrivateCaFixture::new(&vec![
            b'x';
            automata_ci_blob_s3::MAX_S3_PRIVATE_CA_PEM_BYTES
                + 1
        ]);
        assert!(matches!(
            load_s3_private_ca(&oversized.source),
            Err(RunnerProductError::SecureInput(
                super::super::SecureInputError::InvalidSize
            ))
        ));
    }

    #[derive(Debug, Default)]
    struct StartupEffects {
        inventories: Cell<u8>,
        supervisors: Cell<u8>,
        supervisor_runs: Cell<u8>,
        control_handshakes: Cell<u8>,
        registrations: Cell<u8>,
    }

    impl StartupEffects {
        fn assert_none(&self) {
            assert_eq!(self.inventories.get(), 0);
            assert_eq!(self.supervisors.get(), 0);
            assert_eq!(self.supervisor_runs.get(), 0);
            assert_eq!(self.control_handshakes.get(), 0);
            assert_eq!(self.registrations.get(), 0);
        }
    }

    fn observe_startup_boundaries(
        capability: Result<bool, RunnerProductError>,
        process_trust: Result<(), RunnerProductError>,
        cancellation_requested: bool,
        profile: Result<ProfileAdmissionOutcome, RunnerProductError>,
        final_process_trust: Result<(), RunnerProductError>,
        effects: &StartupEffects,
    ) -> Result<Option<()>, RunnerProductError> {
        let capability_admission =
            finish_capability_admission(capability, || process_trust, || cancellation_requested);
        let inventory = after_admitted_value(capability_admission, |_| {
            after_profile_admission(profile, || {
                effects.inventories.set(effects.inventories.get() + 1);
                Ok(())
            })
        })?
        .flatten();
        let composition = after_admitted_value(Ok(inventory), |()| {
            effects.supervisors.set(effects.supervisors.get() + 1);
            Ok(())
        });
        after_admitted_value(composition, |()| {
            final_process_trust?;
            effects
                .supervisor_runs
                .set(effects.supervisor_runs.get() + 1);
            effects
                .control_handshakes
                .set(effects.control_handshakes.get() + 1);
            effects.registrations.set(effects.registrations.get() + 1);
            Ok(())
        })
    }

    fn assert_clean_startup_stop(
        result: &Result<Option<()>, RunnerProductError>,
        effects: &StartupEffects,
        stage: &str,
    ) {
        assert!(matches!(result, Ok(None)), "{stage} must stop cleanly");
        effects.assert_none();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn root_is_rejected_by_runner_user_trust_boundary() {
        assert!(matches!(
            admit_effective_runner_user_id(0),
            Err(RunnerProductError::RunnerUserTrust)
        ));
        assert!(admit_effective_runner_user_id(1).is_ok());
    }

    #[test]
    fn capability_or_trust_rejection_never_reaches_runtime_or_control_plane() {
        for (stage, error) in [
            (
                "passive capability",
                RunnerProductError::CapabilityAdmission,
            ),
            ("active capability", RunnerProductError::CapabilityAdmission),
            (
                "process trust capture",
                RunnerProductError::PodmanProcessTrust,
            ),
        ] {
            let effects = StartupEffects::default();
            let result = observe_startup_boundaries(
                Err(error),
                Ok(()),
                false,
                Ok(ProfileAdmissionOutcome::Admitted),
                Ok(()),
                &effects,
            );
            assert!(result.is_err(), "{stage} failure must remain terminal");
            effects.assert_none();
        }

        for stage in ["passive capability", "active capability"] {
            let effects = StartupEffects::default();
            assert_clean_startup_stop(
                &observe_startup_boundaries(
                    Ok(false),
                    Ok(()),
                    false,
                    Ok(ProfileAdmissionOutcome::Admitted),
                    Ok(()),
                    &effects,
                ),
                &effects,
                stage,
            );
        }

        let process_trust_revalidation_failed = StartupEffects::default();
        assert!(matches!(
            observe_startup_boundaries(
                Ok(true),
                Err(RunnerProductError::PodmanProcessTrust),
                false,
                Ok(ProfileAdmissionOutcome::Admitted),
                Ok(()),
                &process_trust_revalidation_failed,
            ),
            Err(RunnerProductError::PodmanProcessTrust)
        ));
        process_trust_revalidation_failed.assert_none();

        let shutdown_cancelled = StartupEffects::default();
        assert_clean_startup_stop(
            &observe_startup_boundaries(
                Ok(true),
                Ok(()),
                true,
                Ok(ProfileAdmissionOutcome::Admitted),
                Ok(()),
                &shutdown_cancelled,
            ),
            &shutdown_cancelled,
            "shutdown cancellation",
        );
    }

    #[test]
    fn profile_rejection_never_reaches_runtime_or_control_plane() {
        let profile_failed = StartupEffects::default();
        assert!(matches!(
            observe_startup_boundaries(
                Ok(true),
                Ok(()),
                false,
                Err(RunnerProductError::EnvironmentProfileAdmission),
                Ok(()),
                &profile_failed,
            ),
            Err(RunnerProductError::EnvironmentProfileAdmission)
        ));
        profile_failed.assert_none();

        let profile_cancelled = StartupEffects::default();
        assert_clean_startup_stop(
            &observe_startup_boundaries(
                Ok(true),
                Ok(()),
                false,
                Ok(ProfileAdmissionOutcome::Cancelled),
                Ok(()),
                &profile_cancelled,
            ),
            &profile_cancelled,
            "profile cancellation",
        );

        let final_trust_failed = StartupEffects::default();
        assert!(matches!(
            observe_startup_boundaries(
                Ok(true),
                Ok(()),
                false,
                Ok(ProfileAdmissionOutcome::Admitted),
                Err(RunnerProductError::PodmanProcessTrust),
                &final_trust_failed,
            ),
            Err(RunnerProductError::PodmanProcessTrust)
        ));
        assert_eq!(final_trust_failed.inventories.get(), 1);
        assert_eq!(final_trust_failed.supervisors.get(), 1);
        assert_eq!(final_trust_failed.supervisor_runs.get(), 0);
        assert_eq!(final_trust_failed.control_handshakes.get(), 0);
        assert_eq!(final_trust_failed.registrations.get(), 0);

        let admitted = StartupEffects::default();
        assert!(
            observe_startup_boundaries(
                Ok(true),
                Ok(()),
                false,
                Ok(ProfileAdmissionOutcome::Admitted),
                Ok(()),
                &admitted,
            )
            .expect("fully admitted startup")
            .is_some()
        );
        assert_eq!(admitted.inventories.get(), 1);
        assert_eq!(admitted.supervisors.get(), 1);
        assert_eq!(admitted.supervisor_runs.get(), 1);
        assert_eq!(admitted.control_handshakes.get(), 1);
        assert_eq!(admitted.registrations.get(), 1);
    }

    #[test]
    fn registered_helper_ceiling_is_reduced_to_the_verified_provider() {
        #[cfg(target_os = "linux")]
        let configuration = include_bytes!("../../config/runner.local-1.example.json").as_slice();
        #[cfg(target_os = "macos")]
        let configuration = include_bytes!("../../config/runner.macos.example.json").as_slice();
        #[cfg(target_os = "windows")]
        let configuration =
            include_bytes!("../../tests/fixtures/runner.windows.product.json").as_slice();
        let config = RunnerProductConfig::from_json(configuration)
            .expect("checked-in host runner configuration");
        let mut registered_features = config.inventory().containers().features().clone();
        registered_features.extend([
            ContainerFeature::SERVICE_CONTAINERS,
            ContainerFeature::BUILDKIT,
        ]);
        let registered = config
            .inventory()
            .clone()
            .with_containers(ContainerCapabilities::new(registered_features));
        let without_helpers = ProviderCapabilities::new([SandboxCapability::WholeJob])
            .expect("provider capabilities");
        let with_helpers = ProviderCapabilities::new([
            SandboxCapability::WholeJob,
            SandboxCapability::ServiceContainers,
            SandboxCapability::BuildKit,
        ])
        .expect("provider capabilities");

        assert!(
            !inventory_for_verified_provider(config.inventory(), false, false, &without_helpers)
                .containers()
                .features()
                .contains(&ContainerFeature::SERVICE_CONTAINERS)
        );
        assert!(
            !inventory_for_verified_provider(config.inventory(), false, false, &with_helpers)
                .containers()
                .features()
                .contains(&ContainerFeature::SERVICE_CONTAINERS)
        );
        assert!(
            !inventory_for_verified_provider(&registered, true, true, &without_helpers)
                .containers()
                .features()
                .contains(&ContainerFeature::SERVICE_CONTAINERS)
        );
        assert!(
            inventory_for_verified_provider(&registered, true, true, &with_helpers)
                .containers()
                .features()
                .contains(&ContainerFeature::SERVICE_CONTAINERS)
        );
        assert!(
            !inventory_for_verified_provider(&registered, true, false, &with_helpers)
                .containers()
                .features()
                .contains(&ContainerFeature::BUILDKIT)
        );
        assert!(
            !inventory_for_verified_provider(&registered, true, true, &without_helpers)
                .containers()
                .features()
                .contains(&ContainerFeature::BUILDKIT)
        );
        assert!(
            inventory_for_verified_provider(&registered, true, true, &with_helpers)
                .containers()
                .features()
                .contains(&ContainerFeature::BUILDKIT)
        );
    }

    #[tokio::test]
    async fn explicitly_enabled_metrics_bind_failure_is_fatal() {
        let occupied = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("reserve a loopback port");
        let address = occupied.local_addr().expect("occupied address");

        assert!(matches!(
            bind_metrics_listener(address).await,
            Err(RunnerProductError::MetricsBind(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn requested_shutdown_wins_when_every_composition_future_is_ready() {
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let runtime = std::future::ready("runtime");
        let metrics = std::future::ready("metrics");
        let sampler = std::future::ready("sampler");
        let renewal = std::future::ready("renewal");
        tokio::pin!(runtime);
        tokio::pin!(metrics);
        tokio::pin!(sampler);
        tokio::pin!(renewal);

        assert!(matches!(
            select_composition_exit(
                &shutdown,
                runtime.as_mut(),
                metrics.as_mut(),
                sampler.as_mut(),
                renewal.as_mut(),
            )
            .await,
            CompositionExit::Shutdown
        ));
    }

    #[tokio::test]
    async fn renewal_is_selected_without_waiting_for_an_old_generation_exit() {
        let shutdown = CancellationToken::new();
        let runtime = std::future::pending::<()>();
        let metrics = std::future::pending::<()>();
        let sampler = std::future::pending::<()>();
        let renewal = std::future::ready("renewed");
        tokio::pin!(runtime);
        tokio::pin!(metrics);
        tokio::pin!(sampler);
        tokio::pin!(renewal);

        assert!(matches!(
            select_composition_exit(
                &shutdown,
                runtime.as_mut(),
                metrics.as_mut(),
                sampler.as_mut(),
                renewal.as_mut(),
            )
            .await,
            CompositionExit::Renewal("renewed")
        ));
    }

    #[tokio::test]
    async fn renewed_generation_is_rebuilt_before_normal_completion() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let shutdown = RunnerShutdown::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let generation_calls = Arc::clone(&calls);
        run_recomposition_loop(shutdown, move |_| {
            let call = generation_calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(if call == 0 {
                SupervisionDisposition::Recompose
            } else {
                SupervisionDisposition::Complete
            }))
        })
        .await
        .expect("renewed runner generation is rebuilt");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn shutdown_after_renewal_prevents_a_new_generation() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let shutdown = RunnerShutdown::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let generation_calls = Arc::clone(&calls);
        run_recomposition_loop(shutdown, move |generation_shutdown| {
            generation_calls.fetch_add(1, Ordering::SeqCst);
            generation_shutdown.request();
            std::future::ready(Ok(SupervisionDisposition::Recompose))
        })
        .await
        .expect("shutdown remains authoritative after renewal");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn recomposition_drain_waits_for_every_old_generation_task() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let completed = Arc::new(AtomicUsize::new(0));
        let (runtime_sender, runtime_receiver) = tokio::sync::oneshot::channel();
        let (metrics_sender, metrics_receiver) = tokio::sync::oneshot::channel();
        let (sampler_sender, sampler_receiver) = tokio::sync::oneshot::channel();
        let drain_completed = Arc::clone(&completed);
        let drain = tokio::spawn(async move {
            let runtime_completed = Arc::clone(&drain_completed);
            let runtime = async move {
                runtime_receiver.await.expect("release runtime");
                runtime_completed.fetch_add(1, Ordering::SeqCst);
                Ok::<(), automata_ci_runner_runtime::RunnerRuntimeError>(())
            };
            let metrics_completed = Arc::clone(&drain_completed);
            let metrics = async move {
                metrics_receiver.await.expect("release metrics");
                metrics_completed.fetch_add(1, Ordering::SeqCst);
                Ok::<(), RunnerProductError>(())
            };
            let sampler = async move {
                sampler_receiver.await.expect("release sampler");
                drain_completed.fetch_add(1, Ordering::SeqCst);
                Ok::<(), RunnerProductError>(())
            };
            tokio::pin!(runtime);
            tokio::pin!(metrics);
            tokio::pin!(sampler);
            drain_recomposition_generation(runtime.as_mut(), metrics.as_mut(), sampler.as_mut())
                .await
        });

        runtime_sender.send(()).expect("release runtime");
        metrics_sender.send(()).expect("release metrics");
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while completed.load(Ordering::SeqCst) != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first two old-generation tasks drained");
        assert_eq!(completed.load(Ordering::SeqCst), 2);
        assert!(!drain.is_finished());
        sampler_sender.send(()).expect("release sampler");
        drain
            .await
            .expect("drain task")
            .expect("bounded generation drain");
        assert_eq!(completed.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn metrics_listener_serves_only_the_shared_registry_and_shuts_down_cleanly() {
        let listener = bind_metrics_listener(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind loopback metrics listener");
        let address = listener.local_addr().expect("metrics listener address");
        let metrics = RunnerMetrics::new(2, None).expect("runner metrics");
        metrics.set_ready(true);
        let shutdown = CancellationToken::new();
        let service = tokio::spawn(serve_metrics(
            Some(listener),
            Some(metrics.exporter()),
            shutdown.clone(),
        ));

        let response = reqwest::Client::new()
            .get(format!("http://{address}/metrics"))
            .header("accept", "application/openmetrics-text; version=1.0.0")
            .send()
            .await
            .expect("scrape metrics listener");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .expect("content type"),
            OPENMETRICS_CONTENT_TYPE
        );
        let body = response.text().await.expect("metrics body");
        assert!(body.contains("automata_ci_runner_ready 1"));
        assert!(body.ends_with("# EOF\n"));

        shutdown.cancel();
        service
            .await
            .expect("metrics task must not panic")
            .expect("graceful metrics shutdown");
    }
}
