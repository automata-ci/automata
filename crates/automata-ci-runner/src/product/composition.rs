use std::{path::Path, sync::Arc};

use automata_ci_action::{ActionBundleLimits, ActionResolver, ImmutableActionResolver};
use automata_ci_action_github::{
    GithubActionMetadataDecoder, GithubActionMetadataLimits, JavascriptRuntime,
};
use automata_ci_blob::ImmutableBlobStore;
use automata_ci_blob_s3::{S3BlobStore, S3BlobStoreConfig, StaticS3Credentials};
use automata_ci_core::{ContainerCapabilities, ContainerFeature, RunnerCapabilities};
use automata_ci_execution::{ProviderCapabilities, SandboxCapability};
use automata_ci_github::GithubHttpEndpoint;
use automata_ci_job_executor_github::{
    ActionPreparationPort, DeterministicOperationIds, GithubJobExecutor, GithubJobExecutorConfig,
    GithubJobExecutorPorts, ImmutableJobContent, ImmutableSandboxEnvironmentCatalog,
    NoRepositoryCredentials, NoSecrets, ResolvedBundleActionPreparer, StaticGithubToolchain,
    SystemExecutionClock,
};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_runner_crypto::{
    AES_256_GCM_KEY_BYTES, Aes256GcmContentKeyring, Aes256GcmContentProtector,
};
use automata_ci_runner_journal::{FileJournal, FileJournalOptions};
use automata_ci_runner_runtime::{
    JobExecutor, RunnerRuntimeConfig, RunnerRuntimePorts, RunnerSessionSupervisor,
    SystemRuntimeClock, SystemRuntimeIds, TokioRuntimeSleeper, TransportControlClientAdapter,
};
use automata_ci_runner_spool::{FileSpool, FileSpoolOptions};
use automata_ci_runner_transport::{
    HyperRunnerControlClient, RunnerControlClient, TransportLimits,
};
#[cfg(not(target_os = "linux"))]
use automata_ci_sandbox_podman::PodmanLaunchTrust;
use automata_ci_sandbox_podman::{
    PodmanBinary, PodmanCommandExecutor, PodmanLaunchTrustHandle, PodmanOptions,
    PodmanProcessEnvironment, PodmanStateRoot, RootlessPodmanProvider, SystemCommandExecutor,
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

#[cfg(not(target_os = "linux"))]
use super::state::RuntimeMountSnapshot;
use super::{
    ClientTlsMaterialError, ProductStateRootError, RunnerProductConfig, RunnerProductConfigError,
    SecretSource, StandardGithubContext,
    config::required_podman_state_root,
    metrics::RunnerMetrics,
    profile_admission::{
        ProfileAdmissionOutcome, ProfileAdmissionPolicy, admit_environment_profiles,
    },
    state::{capture_dedicated_runtime_mount, ensure_private_directory},
    tls::load_client_tls,
};

const MAX_S3_ACCESS_KEY_BYTES: usize = 1_024;
const MAX_S3_SECRET_BYTES: usize = 65_536;

#[cfg(not(target_os = "linux"))]
#[derive(Clone, Debug)]
struct PodmanProcessTrust;

#[cfg(not(target_os = "linux"))]
impl PodmanProcessTrust {
    fn capture(_options: &PodmanOptions, _runtime_mount: RuntimeMountSnapshot) -> Result<Self, ()> {
        Ok(Self)
    }

    fn revalidate(&self) -> Result<(), ()> {
        Ok(())
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
    let config = RunnerProductConfig::load(config_path)?;
    if shutdown.is_requested() {
        return Ok(());
    }
    require_dedicated_rootless_user()?;
    let podman_options = prepare_admitted_podman(&config)?;
    let network_policy = config.executor().network();
    let capability_admission =
        verify_configured_capabilities(&podman_options, network_policy, &shutdown.probe).await;
    let admission = finish_capability_admission(
        capability_admission,
        || revalidate_podman_launch_trust(&podman_options),
        || shutdown.is_requested(),
    )?;
    let Some(admission) = admission else {
        return Ok(());
    };
    let metrics_listener = match config.metrics() {
        Some(metrics) => Some(bind_metrics_listener(metrics.listen()).await?),
        None => None,
    };
    let composition =
        compose(&config, &podman_options, &shutdown.probe, admission).map(|composition| {
            if shutdown.is_requested() {
                None
            } else {
                composition
            }
        });
    let started = after_admitted_value(composition, |composition| {
        revalidate_podman_launch_trust(&podman_options)?;
        mark_admitted_composition_ready(&config, &composition);
        let supervisor = composition.supervisor.clone();
        let runtime_shutdown = shutdown.runtime.clone();
        let runtime = async move { supervisor.run(runtime_shutdown).await };
        Ok((composition, runtime))
    })?;
    let Some((composition, runtime)) = started else {
        return Ok(());
    };
    let exporter = composition.metrics.as_ref().map(RunnerMetrics::exporter);
    let metrics_service = serve_metrics(metrics_listener, exporter, shutdown.runtime.clone());
    let metrics_sampler = sample_metrics(
        composition.metrics.clone(),
        Arc::clone(&composition.journal),
        Arc::clone(&composition.spool),
        shutdown.runtime.clone(),
    );
    tokio::pin!(runtime);
    tokio::pin!(metrics_service);
    tokio::pin!(metrics_sampler);
    let result = tokio::select! {
        runtime_result = &mut runtime => {
            shutdown.runtime.cancel();
            let metrics_result = (&mut metrics_service).await;
            (&mut metrics_sampler).await?;
            metrics_result?;
            runtime_result.map_err(RunnerProductError::Runtime)
        },
        metrics_result = &mut metrics_service => {
            shutdown.runtime.cancel();
            let _runtime_result = (&mut runtime).await;
            (&mut metrics_sampler).await?;
            match metrics_result {
                Ok(()) => Err(RunnerProductError::MetricsExited),
                Err(error) => Err(error),
            }
        },
        sampler_result = &mut metrics_sampler => {
            shutdown.runtime.cancel();
            let _runtime_result = (&mut runtime).await;
            let _metrics_result = (&mut metrics_service).await;
            match sampler_result {
                Ok(()) => Err(RunnerProductError::MetricsSamplerExited),
                Err(error) => Err(error),
            }
        },
        () = shutdown.runtime.cancelled() => {
            let runtime_result = (&mut runtime).await;
            let metrics_result = (&mut metrics_service).await;
            (&mut metrics_sampler).await?;
            info!("runner shutdown requested");
            metrics_result?;
            runtime_result.map_err(RunnerProductError::Runtime)
        }
    };
    if let Some(metrics) = &composition.metrics {
        metrics.set_ready(false);
    }
    result
}

#[cfg(target_os = "linux")]
fn require_dedicated_rootless_user() -> Result<(), RunnerProductError> {
    admit_effective_user_id(rustix::process::geteuid().as_raw())
}

#[cfg(not(target_os = "linux"))]
fn require_dedicated_rootless_user() -> Result<(), RunnerProductError> {
    Err(RunnerProductError::UnsupportedPlatform)
}

fn admit_effective_user_id(user: u32) -> Result<(), RunnerProductError> {
    if user == 0 {
        Err(RunnerProductError::PodmanProcessTrust)
    } else {
        Ok(())
    }
}

fn prepare_admitted_podman(
    config: &RunnerProductConfig,
) -> Result<PodmanOptions, RunnerProductError> {
    let runtime_mount = capture_dedicated_runtime_mount(config.podman().runtime_directory())
        .map_err(|_| RunnerProductError::PodmanProcessTrust)?;
    let podman_options = build_podman_options(config)?;
    prepare_probe_directories(&podman_options)?;
    let trust = PodmanProcessTrust::capture(&podman_options, runtime_mount)
        .map_err(|_| RunnerProductError::PodmanProcessTrust)?;
    Ok(podman_options.with_launch_trust(PodmanLaunchTrustHandle::new(Arc::new(trust))))
}

struct RunnerComposition {
    supervisor: RunnerSessionSupervisor,
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

fn compose(
    config: &RunnerProductConfig,
    podman_options: &PodmanOptions,
    cancellation: &crate::podman_probe::ProbeCancellation,
    _admission: CapabilityAdmission,
) -> Result<Option<RunnerComposition>, RunnerProductError> {
    #[cfg(not(target_os = "linux"))]
    return Err(RunnerProductError::UnsupportedPlatform);

    let runner_cgroup = config
        .metrics()
        .and_then(|_| PodmanCommandExecutor::delegated_no_swap_cgroup(&SystemCommandExecutor));
    let metrics = config
        .metrics()
        .map(|_| RunnerMetrics::new(config.inventory().max_parallel_jobs(), runner_cgroup))
        .transpose()
        .map_err(RunnerProductError::MetricsConfiguration)?;
    let protocol_limits = ProtocolLimits::default();
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
    let protector = Arc::new(load_spool_keyring(config.spool())?);
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

    revalidate_podman_launch_trust(podman_options)?;
    let provider = build_provider(podman_options.clone(), metrics.as_ref())?;
    let runtime_inventory =
        build_admitted_runtime_inventory(config, provider.as_ref(), cancellation, podman_options);
    after_admitted_value(runtime_inventory, |runtime_inventory| {
        let executor = build_executor(config, provider)?;
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
    podman_options: &PodmanOptions,
) -> Result<Option<RunnerCapabilities>, RunnerProductError> {
    let admission = admit_configured_environment_profiles(config, provider, cancellation);
    after_profile_admission(admission, || {
        revalidate_podman_launch_trust(podman_options)?;
        Ok(inventory_for_verified_provider(
            config.inventory(),
            config.podman().service_proxy_image().is_some(),
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
    let result = admit_environment_profiles(
        provider,
        config.environments(),
        ProfileAdmissionPolicy::new(
            config.executor().network(),
            config.executor().root_filesystem(),
            config.executor().privilege(),
            config.executor().resources(),
        ),
        cancellation,
    );
    match result {
        Ok(ProfileAdmissionOutcome::Admitted) => {
            info!(
                profiles = config.environments().len(),
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
                cleanup_provider_kind = ?error.cleanup_error().map(automata_ci_execution::ProviderError::kind),
                cleanup_provider_stage = ?error.cleanup_error().map(automata_ci_execution::ProviderError::stage),
                "runner environment-profile admission failed"
            );
            Err(RunnerProductError::EnvironmentProfileAdmission)
        }
    }
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
    if config.state().podman().as_os_str()
        != required_podman_state_root(config.podman().runtime_directory()).as_os_str()
    {
        return Err(RunnerProductError::PodmanProcessTrust);
    }
    ensure_private_directory(config.state().podman())?;
    let podman_root = PodmanStateRoot::existing(config.state().podman().to_path_buf())?;
    let podman_environment = PodmanProcessEnvironment::new(
        config.podman().home().to_path_buf(),
        config.podman().runtime_directory().to_path_buf(),
        config.state().podman().to_path_buf(),
        config.podman().approved_helper_directory().to_path_buf(),
        config.podman().conmon_path().to_path_buf(),
        config.podman().oci_runtime_path().to_path_buf(),
        config.podman().init_path().to_path_buf(),
        config.podman().seccomp_profile_path().to_path_buf(),
    )?;
    let mut podman_options = PodmanOptions::new(
        PodmanBinary::new(config.podman().binary().to_path_buf())?,
        podman_root,
        podman_environment,
    )?
    .with_job_container_engine(config.podman().job_container_engine());
    if let Some(alias) = config.podman().github_server_host_gateway_alias() {
        podman_options = podman_options.with_host_gateway_alias(alias.clone());
    }
    if let Some(image) = config.podman().service_proxy_image() {
        podman_options = podman_options.with_service_proxy_image(image.clone());
    }
    Ok(podman_options)
}

fn inventory_for_verified_provider(
    configured: &RunnerCapabilities,
    service_proxy_configured: bool,
    provider: &ProviderCapabilities,
) -> RunnerCapabilities {
    let mut container_features = configured.containers().features().clone();
    container_features.remove(&ContainerFeature::SERVICE_CONTAINERS);
    if service_proxy_configured && provider.supports(SandboxCapability::ServiceContainers) {
        container_features.insert(ContainerFeature::SERVICE_CONTAINERS);
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

fn build_provider(
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

fn build_executor(
    config: &RunnerProductConfig,
    provider: Arc<dyn automata_ci_execution::SandboxProvider>,
) -> Result<Arc<dyn JobExecutor>, RunnerProductError> {
    let blobs = build_object_store(config)?;
    let action_preparer = build_action_preparer(config, Arc::clone(&blobs))?;
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
    Ok(Arc::new(GithubJobExecutor::new(
        executor_config,
        GithubJobExecutorPorts::new(
            provider,
            environments,
            action_preparer,
            job_content,
            // JobIR currently carries only opaque references, not job-scoped
            // values. Fail closed until the control protocol provides a
            // credential authority instead of inventing runner-global data.
            Arc::new(NoSecrets),
            contexts,
            toolchain,
            Arc::new(DeterministicOperationIds),
            Arc::new(SystemExecutionClock),
        ),
    )))
}

fn build_action_preparer(
    config: &RunnerProductConfig,
    blobs: Arc<dyn ImmutableBlobStore>,
) -> Result<Arc<dyn ActionPreparationPort>, RunnerProductError> {
    let github_endpoint = GithubHttpEndpoint::github_dot_com(config.github().user_agent())?;
    let scm: Arc<dyn ScmProvider> = Arc::new(github_endpoint);
    // Do not consult the legacy durable reference index here. Older runner
    // builds could populate it through an ambient repository credential, so a
    // warm hit is not proof that this job may read a private action archive.
    // Anonymous SCM resolution is the authority check until the server supplies
    // a job- and repository-scoped credential with cacheable provenance.
    let resolver: Arc<dyn ActionResolver> =
        Arc::new(ImmutableActionResolver::new(scm, Arc::clone(&blobs)));
    Ok(Arc::new(ResolvedBundleActionPreparer::new(
        resolver,
        blobs,
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
    let store_config = if object_store.loopback_development() {
        S3BlobStoreConfig::loopback_development(
            object_store.endpoint().clone(),
            object_store.region(),
            object_store.bucket(),
            object_store.prefix().map(str::to_owned),
            object_store.operation_timeout(),
        )
    } else {
        S3BlobStoreConfig::new(
            object_store.endpoint().clone(),
            object_store.region(),
            object_store.bucket(),
            object_store.prefix().map(str::to_owned),
            object_store.force_path_style(),
            object_store.operation_timeout(),
        )
    }?;
    let credentials = load_s3_credentials(
        object_store.access_key_id(),
        object_store.secret_access_key(),
        object_store.session_token(),
    )?;
    let client = store_config.client(credentials);
    Ok(Arc::new(S3BlobStore::new(client, &store_config)))
}

fn build_toolchain(
    config: &RunnerProductConfig,
) -> Result<StaticGithubToolchain, RunnerProductError> {
    let configured = config.executor().toolchain();
    let mut toolchain = StaticGithubToolchain::new(
        configured.bash().clone(),
        configured.sh().clone(),
        configured.install().clone(),
        configured.tar().clone(),
        configured.sha256sum().clone(),
    )?;
    if let Some(path) = configured.python() {
        toolchain = toolchain.with_python(path.clone())?;
    }
    if let Some(path) = configured.pwsh() {
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
) -> Result<Aes256GcmContentKeyring, RunnerProductError> {
    let active =
        Aes256GcmContentProtector::new(config.protection_id(), load_spool_key(config.key_hex())?)?;
    let decrypt_only = config
        .decrypt_only_keys()
        .map(|(protection_id, source)| {
            Aes256GcmContentProtector::new(protection_id, load_spool_key(source)?)
                .map_err(RunnerProductError::Protector)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Aes256GcmContentKeyring::new(active, decrypt_only).map_err(RunnerProductError::Protector)
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
    /// Crash-durable journal initialization failed.
    #[error("runner durable journal initialization failed")]
    Journal(#[from] automata_ci_runner_journal::JournalError),
    /// Protected spool initialization failed.
    #[error("runner protected spool initialization failed")]
    Spool(#[from] automata_ci_runner_spool::SpoolError),
    /// At-rest content protector initialization failed.
    #[error("runner content protector initialization failed")]
    Protector(#[from] automata_ci_runner_crypto::ContentProtectorConfigurationError),
    /// Provider state-root preparation failed.
    #[error("runner provider state-root initialization failed")]
    StateRoot(#[from] ProductStateRootError),
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
    /// Production execution is currently Linux-only.
    #[error("runner production mode is unsupported on this platform")]
    UnsupportedPlatform,
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        net::{IpAddr, Ipv4Addr, SocketAddr},
    };

    use automata_ci_metrics::OPENMETRICS_CONTENT_TYPE;

    use super::*;

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

    #[test]
    fn root_is_rejected_before_any_podman_state_preparation() {
        assert!(matches!(
            admit_effective_user_id(0),
            Err(RunnerProductError::PodmanProcessTrust)
        ));
        assert!(admit_effective_user_id(1).is_ok());
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
    fn registered_service_ceiling_is_reduced_to_the_verified_provider() {
        let config = RunnerProductConfig::from_json(include_bytes!(
            "../../config/runner.local.example.json"
        ))
        .expect("checked-in runner configuration");
        let mut registered_features = config.inventory().containers().features().clone();
        registered_features.insert(ContainerFeature::SERVICE_CONTAINERS);
        let registered = config
            .inventory()
            .clone()
            .with_containers(ContainerCapabilities::new(registered_features));
        let without_service = ProviderCapabilities::new([SandboxCapability::WholeJob])
            .expect("provider capabilities");
        let with_service = ProviderCapabilities::new([
            SandboxCapability::WholeJob,
            SandboxCapability::ServiceContainers,
        ])
        .expect("provider capabilities");

        assert!(
            !inventory_for_verified_provider(config.inventory(), false, &without_service)
                .containers()
                .features()
                .contains(&ContainerFeature::SERVICE_CONTAINERS)
        );
        assert!(
            !inventory_for_verified_provider(config.inventory(), false, &with_service)
                .containers()
                .features()
                .contains(&ContainerFeature::SERVICE_CONTAINERS)
        );
        assert!(
            !inventory_for_verified_provider(&registered, true, &without_service)
                .containers()
                .features()
                .contains(&ContainerFeature::SERVICE_CONTAINERS)
        );
        assert!(
            inventory_for_verified_provider(&registered, true, &with_service)
                .containers()
                .features()
                .contains(&ContainerFeature::SERVICE_CONTAINERS)
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
