use std::{fmt, path::Path, sync::Arc};

use automata_action::{ActionBundleLimits, ActionResolver, ImmutableActionResolver};
use automata_action_cache_file::{
    ActionReferenceIndexLimits, ActionReferenceIndexRoot, FileActionReferenceIndex,
};
use automata_action_github::{
    GithubActionMetadataDecoder, GithubActionMetadataLimits, JavascriptRuntime,
};
use automata_auth::secret::SecretString;
use automata_blob::ImmutableBlobStore;
use automata_blob_s3::{S3BlobStore, S3BlobStoreConfig, StaticS3Credentials};
use automata_github::GithubHttpEndpoint;
use automata_job_executor_github::{
    ActionPreparationPort, DeterministicOperationIds, GithubJobExecutor, GithubJobExecutorConfig,
    GithubJobExecutorPorts, ImmutableJobContent, ImmutableSandboxEnvironmentCatalog, NoSecrets,
    PortError, PortErrorKind, RepositoryCredentialPort, ResolvedBundleActionPreparer,
    StaticGithubToolchain, SystemExecutionClock,
};
use automata_protocol::ProtocolLimits;
use automata_runner_crypto::{AES_256_GCM_KEY_BYTES, Aes256GcmContentProtector};
use automata_runner_journal::FileJournal;
use automata_runner_runtime::{
    JobExecutor, RunnerRuntimeConfig, RunnerRuntimePorts, RunnerSessionSupervisor,
    SystemRuntimeClock, SystemRuntimeIds, TokioRuntimeSleeper, TransportControlClientAdapter,
};
use automata_runner_spool::FileSpool;
use automata_runner_transport::{HyperRunnerControlClient, RunnerControlClient, TransportLimits};
use automata_sandbox_podman::{
    PodmanBinary, PodmanOptions, PodmanProcessEnvironment, PodmanStateRoot, RootlessPodmanProvider,
};
use automata_scm::{RepositoryId, ScmProvider};
use automata_workflow_github::GithubConditionCompiler;
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use tracing::info;
use zeroize::Zeroizing;

use super::{
    ClientTlsMaterialError, ProductStateRootError, RunnerProductConfig, RunnerProductConfigError,
    SecretSource, StandardGithubContext, state::ensure_private_directory, tls::load_client_tls,
};

const MAX_S3_ACCESS_KEY_BYTES: usize = 1_024;
const MAX_S3_SECRET_BYTES: usize = 65_536;
const MAX_REPOSITORY_CREDENTIAL_BYTES: usize = 65_536;

/// Starts the production runner composition and blocks until graceful shutdown.
///
/// # Errors
///
/// Returns a sanitized startup/runtime category. Secret values, PEM contents,
/// provider output, and action output are never embedded in this error.
pub async fn run(config_path: &Path) -> Result<(), RunnerProductError> {
    let config = RunnerProductConfig::load(config_path)?;
    let supervisor = compose(&config)?;
    info!(
        runner_id = %config.runner_id(),
        control_authority = config
            .control_endpoint()
            .authority()
            .map_or("unknown", http::uri::Authority::as_str),
        slots = config.inventory().max_parallel_jobs(),
        "runner session supervisor starting"
    );

    let shutdown = CancellationToken::new();
    let runtime = supervisor.run(shutdown.clone());
    let signal = wait_for_shutdown_signal();
    tokio::pin!(runtime);
    tokio::pin!(signal);
    tokio::select! {
        result = &mut runtime => result.map_err(RunnerProductError::Runtime),
        signal_result = &mut signal => {
            signal_result?;
            info!("runner shutdown requested");
            shutdown.cancel();
            runtime.await.map_err(RunnerProductError::Runtime)
        }
    }
}

fn compose(config: &RunnerProductConfig) -> Result<RunnerSessionSupervisor, RunnerProductError> {
    #[cfg(not(target_os = "linux"))]
    return Err(RunnerProductError::UnsupportedPlatform);

    let protocol_limits = ProtocolLimits::default();
    let tls = load_client_tls(config.tls())?;
    let transport = HyperRunnerControlClient::new(
        config.control_endpoint(),
        &tls,
        protocol_limits,
        TransportLimits::default(),
    )?;
    let transport: Arc<dyn RunnerControlClient> = Arc::new(transport);
    let control = Arc::new(TransportControlClientAdapter::new(transport));

    let journal = Arc::new(FileJournal::open(
        config.state().journal().clone(),
        config.runner_id(),
    )?);
    let key = decode_spool_key(config.spool().key_hex())?;
    let protector = Arc::new(Aes256GcmContentProtector::new(
        config.spool().protection_id(),
        key,
    )?);
    let spool = Arc::new(FileSpool::open(config.state().spool().clone(), protector)?);

    let provider = build_provider(config)?;
    let executor = build_executor(config, provider)?;

    let runtime_config = RunnerRuntimeConfig::new(
        config.inventory().clone(),
        protocol_limits,
        automata_runner_runtime::RunnerRuntimeLimits::default(),
    )?;
    let ports = RunnerRuntimePorts::new(
        control,
        journal,
        spool,
        executor,
        Arc::new(SystemRuntimeClock::new()),
        Arc::new(TokioRuntimeSleeper),
        Arc::new(SystemRuntimeIds),
    );
    Ok(RunnerSessionSupervisor::new(runtime_config, ports))
}

fn build_provider(
    config: &RunnerProductConfig,
) -> Result<Arc<dyn automata_execution::SandboxProvider>, RunnerProductError> {
    ensure_private_directory(config.state().podman())?;
    let podman_root = PodmanStateRoot::existing(config.state().podman().to_path_buf())?;
    let podman_environment = PodmanProcessEnvironment::new(
        config.podman().home().to_path_buf(),
        config.podman().runtime_directory().map(Path::to_path_buf),
        config.podman().executable_search_path().clone(),
    )?;
    let mut podman_options = PodmanOptions::new(
        PodmanBinary::new(config.podman().binary().to_path_buf())?,
        podman_root,
        podman_environment,
    )
    .with_job_container_engine(config.podman().job_container_engine());
    if let Some(alias) = config.podman().github_server_host_gateway_alias() {
        podman_options = podman_options.with_host_gateway_alias(alias.clone());
    }
    Ok(Arc::new(RootlessPodmanProvider::open(podman_options)?))
}

fn build_executor(
    config: &RunnerProductConfig,
    provider: Arc<dyn automata_execution::SandboxProvider>,
) -> Result<Arc<dyn JobExecutor>, RunnerProductError> {
    let blobs = build_object_store(config)?;
    let action_preparer = build_action_preparer(config, Arc::clone(&blobs))?;
    let job_content = Arc::new(ImmutableJobContent::new(
        blobs,
        automata_execution::MAX_COPY_BYTES as u64,
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
    let reference_root =
        ActionReferenceIndexRoot::explicit(config.state().journal().as_path().to_path_buf())?;
    let references = Arc::new(FileActionReferenceIndex::open(
        reference_root,
        ActionReferenceIndexLimits::default(),
    )?);
    let resolver: Arc<dyn ActionResolver> = Arc::new(
        ImmutableActionResolver::new(scm, Arc::clone(&blobs)).with_reference_index(references),
    );
    let repository_credentials: Arc<dyn RepositoryCredentialPort> = Arc::new(
        SourceRepositoryCredentials::new(config.github().repository_credential().cloned()),
    );
    Ok(Arc::new(ResolvedBundleActionPreparer::new(
        resolver,
        blobs,
        repository_credentials,
        Arc::new(GithubActionMetadataDecoder::new(
            GithubActionMetadataLimits::default(),
        )),
        GithubConditionCompiler::default(),
        ActionBundleLimits::default(),
        automata_execution::MAX_COPY_BYTES as u64,
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
    let access_key_id = read_secret_text(object_store.access_key_id(), MAX_S3_ACCESS_KEY_BYTES)?;
    let secret_access_key =
        read_secret_text(object_store.secret_access_key(), MAX_S3_SECRET_BYTES)?;
    let session_token = object_store
        .session_token()
        .map(|source| read_secret_text(source, MAX_S3_SECRET_BYTES))
        .transpose()?;
    let credentials = StaticS3Credentials::new(access_key_id, secret_access_key, session_token)?;
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
    )?;
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

fn decode_spool_key(source: &SecretSource) -> Result<Zeroizing<Vec<u8>>, RunnerProductError> {
    let encoded = source.read(AES_256_GCM_KEY_BYTES * 2)?;
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
    let mut bytes = source.read(maximum_bytes)?;
    let value = String::from_utf8(std::mem::take(&mut *bytes))
        .map_err(|_| RunnerProductError::InvalidSecretText)?;
    if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(RunnerProductError::InvalidSecretText);
    }
    Ok(value)
}

#[derive(Clone)]
struct SourceRepositoryCredentials {
    source: Option<SecretSource>,
}

impl SourceRepositoryCredentials {
    const fn new(source: Option<SecretSource>) -> Self {
        Self { source }
    }
}

impl RepositoryCredentialPort for SourceRepositoryCredentials {
    fn credential(&self, _repository: &RepositoryId) -> Result<Option<SecretString>, PortError> {
        self.source.as_ref().map_or(Ok(None), |source| {
            let mut bytes = source
                .read(MAX_REPOSITORY_CREDENTIAL_BYTES)
                .map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
            let value = String::from_utf8(std::mem::take(&mut *bytes))
                .map_err(|_| PortError::new(PortErrorKind::InvalidData))?;
            if value.bytes().any(|byte| byte.is_ascii_whitespace()) {
                return Err(PortError::new(PortErrorKind::InvalidData));
            }
            SecretString::new(value)
                .map(Some)
                .map_err(|_| PortError::new(PortErrorKind::InvalidData))
        })
    }
}

impl fmt::Debug for SourceRepositoryCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceRepositoryCredentials")
            .field("configured", &self.source.is_some())
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

async fn wait_for_shutdown_signal() -> Result<(), RunnerProductError> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|_| RunnerProductError::Signal)?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.map_err(|_| RunnerProductError::Signal),
            signal = terminate.recv() => signal.map_or(Err(RunnerProductError::Signal), |()| Ok(())),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(|_| RunnerProductError::Signal)
    }
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
    TransportConfiguration(#[from] automata_runner_transport::ConfigurationError),
    /// Crash-durable journal initialization failed.
    #[error("runner durable journal initialization failed")]
    Journal(#[from] automata_runner_journal::JournalError),
    /// Protected spool initialization failed.
    #[error("runner protected spool initialization failed")]
    Spool(#[from] automata_runner_spool::SpoolError),
    /// At-rest content protector initialization failed.
    #[error("runner content protector initialization failed")]
    Protector(#[from] automata_runner_crypto::ContentProtectorConfigurationError),
    /// Provider state-root preparation failed.
    #[error("runner provider state-root initialization failed")]
    StateRoot(#[from] ProductStateRootError),
    /// Rootless Podman configuration failed.
    #[error("runner Podman configuration failed")]
    PodmanConfiguration(#[from] automata_sandbox_podman::PodmanConfigurationError),
    /// The configured rootless Podman state root was not a safe existing directory.
    #[error("runner Podman state-root validation failed")]
    PodmanState(#[from] automata_sandbox_podman::PodmanStateRootError),
    /// Rootless Podman initialization failed.
    #[error("runner Podman provider initialization failed")]
    PodmanOpen(#[from] automata_sandbox_podman::PodmanOpenError),
    /// S3-compatible immutable object-store configuration failed.
    #[error("runner object-store configuration failed")]
    ObjectStore(#[from] automata_blob_s3::S3BlobStoreConfigError),
    /// GitHub SCM endpoint construction failed.
    #[error("runner GitHub endpoint configuration failed")]
    Github(#[from] automata_github::GithubHttpConfigurationError),
    /// GitHub action preparation composition failed.
    #[error("runner action preparation configuration failed")]
    ActionPreparation(#[from] automata_job_executor_github::ActionPreparationError),
    /// Durable immutable action-reference index initialization failed.
    #[error("runner action reference index initialization failed")]
    ActionReferenceIndex(#[from] automata_action::ActionReferenceIndexError),
    /// GitHub executor port configuration failed.
    #[error("runner executor port configuration failed")]
    ExecutorPort(#[from] automata_job_executor_github::PortError),
    /// GitHub executor policy failed validation.
    #[error("runner executor policy configuration failed")]
    ExecutorConfiguration(#[from] automata_job_executor_github::GithubJobExecutorConfigError),
    /// Runner session runtime policy failed validation.
    #[error("runner session runtime configuration failed")]
    RuntimeConfiguration(#[from] automata_runner_runtime::RunnerRuntimeConfigError),
    /// Runner session supervision failed.
    #[error("runner session supervision failed")]
    Runtime(#[source] automata_runner_runtime::RunnerRuntimeError),
    /// Signal handler initialization or delivery failed.
    #[error("runner shutdown signal handling failed")]
    Signal,
    /// Production execution is currently Linux-only.
    #[error("runner production mode is unsupported on this platform")]
    UnsupportedPlatform,
}
