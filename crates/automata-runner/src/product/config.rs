use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    path::{Path, PathBuf},
    str::FromStr as _,
    time::Duration,
};

use automata_core::{
    Architecture, ContainerCapabilities, ContainerFeature, EnvironmentProfile,
    EnvironmentProfileId, IsolationLevel, OperatingSystem, ResourceCapacity, RunnerCapabilities,
    RunnerFeature, RunnerGroup, RunnerId, RunnerLabel, RunnerPlatform, SandboxCapabilities,
    SandboxFeature, Sha256Digest,
};
use automata_execution::{
    EnvironmentName, EnvironmentValue, EnvironmentVariable, ExecutionArgv, ExecutionEnvironment,
    ImmutableImage, NetworkPolicy, ResourceLimits, RootFilesystemPolicy, SandboxEnvironment,
    SandboxPrivilegePolicy, TargetPath,
};
use automata_runner_journal::StateRoot;
use automata_runner_spool::SpoolRoot;
use http::Uri;
use serde::Deserialize;
use thiserror::Error;
use url::Url;

use super::files::{
    SecretSource, SecureInputError, read_configuration_file, validate_absolute_path,
};

/// Current on-disk runner product configuration schema.
pub const RUNNER_PRODUCT_CONFIG_SCHEMA_VERSION: u16 = 1;
/// Hard ceiling applied before parsing a runner configuration document.
pub const MAX_RUNNER_CONFIG_BYTES: usize = 256 * 1024;

const MAX_SELECTORS: usize = 256;
const MAX_ENVIRONMENTS: usize = 64;
const MAX_KEEPALIVE_ARGUMENTS: usize = 64;
const MAX_USER_AGENT_BYTES: usize = 256;

/// Fully validated product configuration for one runner process.
pub struct RunnerProductConfig {
    runner_id: RunnerId,
    control_endpoint: Uri,
    state: StateRoots,
    tls: ClientTlsSources,
    spool: SpoolProtectionConfig,
    inventory: RunnerCapabilities,
    environments: BTreeMap<EnvironmentProfile, SandboxEnvironment>,
    podman: PodmanProductConfig,
    executor: ExecutorProductConfig,
    object_store: ObjectStoreProductConfig,
    github: GithubProductConfig,
}

impl RunnerProductConfig {
    /// Loads a bounded, non-writable, no-follow JSON configuration file.
    ///
    /// # Errors
    ///
    /// Returns a sanitized configuration category. Input text and secret
    /// material are never retained in the error.
    pub fn load(path: &Path) -> Result<Self, RunnerProductConfigError> {
        let bytes = read_configuration_file(path, MAX_RUNNER_CONFIG_BYTES)
            .map_err(RunnerProductConfigError::SecureInput)?;
        Self::from_json(&bytes)
    }

    /// Parses an already-bounded configuration document. This exists for
    /// external contract tests and embedded deployment adapters.
    ///
    /// # Errors
    ///
    /// Rejects unknown fields, unsupported schemas, mutable images, unsafe
    /// paths, duplicate profiles, incoherent limits, and invalid endpoints.
    pub fn from_json(bytes: &[u8]) -> Result<Self, RunnerProductConfigError> {
        if bytes.is_empty() || bytes.len() > MAX_RUNNER_CONFIG_BYTES {
            return Err(RunnerProductConfigError::InvalidDocument);
        }
        let raw: RawRunnerProductConfig =
            serde_json::from_slice(bytes).map_err(|_| RunnerProductConfigError::InvalidDocument)?;
        raw.validate()
    }

    #[must_use]
    pub const fn runner_id(&self) -> RunnerId {
        self.runner_id
    }

    #[must_use]
    pub const fn control_endpoint(&self) -> &Uri {
        &self.control_endpoint
    }

    #[must_use]
    pub const fn state(&self) -> &StateRoots {
        &self.state
    }

    #[must_use]
    pub const fn tls(&self) -> &ClientTlsSources {
        &self.tls
    }

    #[must_use]
    pub const fn spool(&self) -> &SpoolProtectionConfig {
        &self.spool
    }

    #[must_use]
    pub const fn inventory(&self) -> &RunnerCapabilities {
        &self.inventory
    }

    #[must_use]
    pub const fn environments(&self) -> &BTreeMap<EnvironmentProfile, SandboxEnvironment> {
        &self.environments
    }

    #[must_use]
    pub const fn podman(&self) -> &PodmanProductConfig {
        &self.podman
    }

    #[must_use]
    pub const fn executor(&self) -> &ExecutorProductConfig {
        &self.executor
    }

    #[must_use]
    pub const fn object_store(&self) -> &ObjectStoreProductConfig {
        &self.object_store
    }

    #[must_use]
    pub const fn github(&self) -> &GithubProductConfig {
        &self.github
    }
}

impl std::fmt::Debug for RunnerProductConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunnerProductConfig")
            .field("runner_id", &self.runner_id)
            .field("control_endpoint", &self.control_endpoint)
            .field("state", &self.state)
            .field("tls", &self.tls)
            .field("spool", &self.spool)
            .field("inventory", &self.inventory)
            .field("environment_count", &self.environments.len())
            .field("podman", &self.podman)
            .field("executor", &self.executor)
            .field("object_store", &self.object_store)
            .field("github", &self.github)
            .finish()
    }
}

/// Distinct roots for semantic state, encrypted content, and provider state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateRoots {
    journal: StateRoot,
    spool: SpoolRoot,
    podman: PathBuf,
}

impl StateRoots {
    #[must_use]
    pub const fn journal(&self) -> &StateRoot {
        &self.journal
    }

    #[must_use]
    pub const fn spool(&self) -> &SpoolRoot {
        &self.spool
    }

    #[must_use]
    pub fn podman(&self) -> &Path {
        &self.podman
    }
}

/// Explicit material locations for outbound runner mTLS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientTlsSources {
    server_roots: SecretSource,
    certificate_chain: SecretSource,
    private_key: SecretSource,
    allow_legacy_tls12: bool,
}

impl ClientTlsSources {
    #[must_use]
    pub const fn server_roots(&self) -> &SecretSource {
        &self.server_roots
    }

    #[must_use]
    pub const fn certificate_chain(&self) -> &SecretSource {
        &self.certificate_chain
    }

    #[must_use]
    pub const fn private_key(&self) -> &SecretSource {
        &self.private_key
    }

    #[must_use]
    pub const fn allow_legacy_tls12(&self) -> bool {
        self.allow_legacy_tls12
    }
}

/// AES-256-GCM spool protection inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpoolProtectionConfig {
    protection_id: String,
    key_hex: SecretSource,
}

impl SpoolProtectionConfig {
    #[must_use]
    pub fn protection_id(&self) -> &str {
        &self.protection_id
    }

    #[must_use]
    pub const fn key_hex(&self) -> &SecretSource {
        &self.key_hex
    }
}

/// Explicit rootless-Podman host process configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PodmanProductConfig {
    binary: PathBuf,
    home: PathBuf,
    runtime_directory: Option<PathBuf>,
    executable_search_path: OsString,
    job_container_engine: automata_sandbox_podman::JobContainerEngine,
    github_server_host_gateway_alias: Option<automata_sandbox_podman::PodmanHostGatewayAlias>,
}

impl PodmanProductConfig {
    #[must_use]
    pub fn binary(&self) -> &Path {
        &self.binary
    }

    #[must_use]
    pub fn home(&self) -> &Path {
        &self.home
    }

    #[must_use]
    pub fn runtime_directory(&self) -> Option<&Path> {
        self.runtime_directory.as_deref()
    }

    #[must_use]
    pub fn executable_search_path(&self) -> &OsString {
        &self.executable_search_path
    }

    #[must_use]
    pub const fn job_container_engine(&self) -> automata_sandbox_podman::JobContainerEngine {
        self.job_container_engine
    }

    /// Exact `github.server_url` hostname mapped to the Podman host gateway
    /// when the deployment explicitly opts into local-host routing.
    #[must_use]
    pub const fn github_server_host_gateway_alias(
        &self,
    ) -> Option<&automata_sandbox_podman::PodmanHostGatewayAlias> {
        self.github_server_host_gateway_alias.as_ref()
    }
}

/// Resource and target-tool policy for GitHub-compatible execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutorProductConfig {
    resources: ResourceLimits,
    network: NetworkPolicy,
    root_filesystem: RootFilesystemPolicy,
    privilege: SandboxPrivilegePolicy,
    default_step_timeout: Duration,
    maximum_output_bytes: usize,
    runner_root: TargetPath,
    home: TargetPath,
    path: String,
    temp: TargetPath,
    tool_cache: TargetPath,
    toolchain: ToolchainConfig,
}

impl ExecutorProductConfig {
    #[must_use]
    pub const fn resources(&self) -> ResourceLimits {
        self.resources
    }

    #[must_use]
    pub const fn network(&self) -> NetworkPolicy {
        self.network
    }

    #[must_use]
    pub const fn root_filesystem(&self) -> RootFilesystemPolicy {
        self.root_filesystem
    }

    #[must_use]
    pub const fn privilege(&self) -> SandboxPrivilegePolicy {
        self.privilege
    }

    #[must_use]
    pub const fn default_step_timeout(&self) -> Duration {
        self.default_step_timeout
    }

    #[must_use]
    pub const fn maximum_output_bytes(&self) -> usize {
        self.maximum_output_bytes
    }

    #[must_use]
    pub const fn runner_root(&self) -> &TargetPath {
        &self.runner_root
    }

    #[must_use]
    pub const fn home(&self) -> &TargetPath {
        &self.home
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub const fn temp(&self) -> &TargetPath {
        &self.temp
    }

    #[must_use]
    pub const fn tool_cache(&self) -> &TargetPath {
        &self.tool_cache
    }

    #[must_use]
    pub const fn toolchain(&self) -> &ToolchainConfig {
        &self.toolchain
    }
}

/// Executable locations baked into every configured environment manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolchainConfig {
    bash: TargetPath,
    sh: TargetPath,
    install: TargetPath,
    tar: TargetPath,
    node12: Option<TargetPath>,
    node16: Option<TargetPath>,
    node20: Option<TargetPath>,
    node24: Option<TargetPath>,
}

impl ToolchainConfig {
    #[must_use]
    pub const fn bash(&self) -> &TargetPath {
        &self.bash
    }

    #[must_use]
    pub const fn sh(&self) -> &TargetPath {
        &self.sh
    }

    #[must_use]
    pub const fn install(&self) -> &TargetPath {
        &self.install
    }

    #[must_use]
    pub const fn tar(&self) -> &TargetPath {
        &self.tar
    }

    #[must_use]
    pub const fn node12(&self) -> Option<&TargetPath> {
        self.node12.as_ref()
    }

    #[must_use]
    pub const fn node16(&self) -> Option<&TargetPath> {
        self.node16.as_ref()
    }

    #[must_use]
    pub const fn node20(&self) -> Option<&TargetPath> {
        self.node20.as_ref()
    }

    #[must_use]
    pub const fn node24(&self) -> Option<&TargetPath> {
        self.node24.as_ref()
    }
}

/// S3-compatible immutable action-bundle store configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectStoreProductConfig {
    endpoint: Url,
    region: String,
    bucket: String,
    prefix: Option<String>,
    force_path_style: bool,
    loopback_development: bool,
    operation_timeout: Duration,
    access_key_id: SecretSource,
    secret_access_key: SecretSource,
    session_token: Option<SecretSource>,
}

impl ObjectStoreProductConfig {
    #[must_use]
    pub const fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }

    #[must_use]
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    #[must_use]
    pub fn prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }

    #[must_use]
    pub const fn force_path_style(&self) -> bool {
        self.force_path_style
    }

    #[must_use]
    pub const fn loopback_development(&self) -> bool {
        self.loopback_development
    }

    #[must_use]
    pub const fn operation_timeout(&self) -> Duration {
        self.operation_timeout
    }

    #[must_use]
    pub const fn access_key_id(&self) -> &SecretSource {
        &self.access_key_id
    }

    #[must_use]
    pub const fn secret_access_key(&self) -> &SecretSource {
        &self.secret_access_key
    }

    #[must_use]
    pub const fn session_token(&self) -> Option<&SecretSource> {
        self.session_token.as_ref()
    }
}

/// GitHub context endpoints and repository/workflow bootstrap credentials.
///
/// Results credentials are intentionally absent: they are always delivered as
/// protected, per-attempt lease authority and can never be runner-scoped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubProductConfig {
    user_agent: String,
    repository_credential: Option<SecretSource>,
    workflow_token: Option<SecretSource>,
    server_url: Url,
    api_url: Url,
    graphql_url: Url,
    allow_insecure_http: bool,
}

impl GithubProductConfig {
    #[must_use]
    pub fn user_agent(&self) -> &str {
        &self.user_agent
    }

    #[must_use]
    pub const fn repository_credential(&self) -> Option<&SecretSource> {
        self.repository_credential.as_ref()
    }

    #[must_use]
    pub const fn workflow_token(&self) -> Option<&SecretSource> {
        self.workflow_token.as_ref()
    }

    #[must_use]
    pub const fn server_url(&self) -> &Url {
        &self.server_url
    }

    #[must_use]
    pub const fn api_url(&self) -> &Url {
        &self.api_url
    }

    #[must_use]
    pub const fn graphql_url(&self) -> &Url {
        &self.graphql_url
    }

    #[must_use]
    pub const fn allow_insecure_http(&self) -> bool {
        self.allow_insecure_http
    }
}

/// Sanitized runner product configuration failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RunnerProductConfigError {
    /// JSON was empty, oversized, malformed, or contained unknown fields.
    #[error("runner configuration document is invalid")]
    InvalidDocument,
    /// The schema version is not implemented by this binary.
    #[error("runner configuration schema is unsupported")]
    UnsupportedSchema,
    /// A secure input descriptor or configuration-file policy failed.
    #[error("runner secure input configuration is invalid")]
    SecureInput(#[source] SecureInputError),
    /// The runner-control endpoint is not a simple credential-free HTTPS origin.
    #[error("runner control endpoint is invalid")]
    InvalidControlEndpoint,
    /// Durable state roots are unsafe, overlapping, or otherwise incoherent.
    #[error("runner state roots are invalid")]
    InvalidStateRoots,
    /// Runner inventory, selectors, resources, or profiles are invalid.
    #[error("runner capability inventory is invalid")]
    InvalidInventory,
    /// Rootless Podman process configuration is invalid.
    #[error("runner Podman configuration is invalid")]
    InvalidPodman,
    /// GitHub executor policy or toolchain paths are invalid.
    #[error("runner executor configuration is invalid")]
    InvalidExecutor,
    /// S3-compatible object-store configuration is invalid.
    #[error("runner object-store configuration is invalid")]
    InvalidObjectStore,
    /// Encrypted spool protection configuration is invalid.
    #[error("runner spool protection configuration is invalid")]
    InvalidSpoolProtection,
    /// GitHub endpoint policy is invalid.
    #[error("runner GitHub configuration is invalid")]
    InvalidGithub,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRunnerProductConfig {
    schema_version: u16,
    runner_id: RunnerId,
    control_endpoint: String,
    state: RawStateRoots,
    tls: RawClientTlsSources,
    spool: RawSpoolProtectionConfig,
    inventory: RawInventory,
    podman: RawPodmanProductConfig,
    executor: RawExecutorProductConfig,
    object_store: RawObjectStoreProductConfig,
    github: RawGithubProductConfig,
}

impl RawRunnerProductConfig {
    fn validate(self) -> Result<RunnerProductConfig, RunnerProductConfigError> {
        if self.schema_version != RUNNER_PRODUCT_CONFIG_SCHEMA_VERSION {
            return Err(RunnerProductConfigError::UnsupportedSchema);
        }
        let control_endpoint = validate_control_endpoint(&self.control_endpoint)?;
        let state = self.state.validate()?;
        let tls = self.tls.validate()?;
        let spool = self.spool.validate()?;
        let executor = self.executor.validate()?;
        let github = self.github.validate()?;
        let podman = self.podman.validate(github.server_url())?;
        let (inventory, environments) =
            self.inventory
                .validate(self.runner_id, &executor, podman.job_container_engine())?;
        let object_store = self.object_store.validate()?;
        Ok(RunnerProductConfig {
            runner_id: self.runner_id,
            control_endpoint,
            state,
            tls,
            spool,
            inventory,
            environments,
            podman,
            executor,
            object_store,
            github,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStateRoots {
    journal: PathBuf,
    spool: PathBuf,
    podman: PathBuf,
}

impl RawStateRoots {
    fn validate(self) -> Result<StateRoots, RunnerProductConfigError> {
        let roots = [&self.journal, &self.spool, &self.podman];
        if roots
            .iter()
            .any(|path| validate_absolute_path(path).is_err())
            || roots.iter().enumerate().any(|(left_index, left)| {
                roots.iter().enumerate().any(|(right_index, right)| {
                    left_index != right_index
                        && (left.starts_with(right.as_path()) || right.starts_with(left.as_path()))
                })
            })
        {
            return Err(RunnerProductConfigError::InvalidStateRoots);
        }
        let journal = StateRoot::explicit(self.journal)
            .map_err(|_| RunnerProductConfigError::InvalidStateRoots)?;
        let spool = SpoolRoot::explicit(self.spool)
            .map_err(|_| RunnerProductConfigError::InvalidStateRoots)?;
        Ok(StateRoots {
            journal,
            spool,
            podman: self.podman,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClientTlsSources {
    server_roots: SecretSource,
    certificate_chain: SecretSource,
    private_key: SecretSource,
    #[serde(default)]
    allow_legacy_tls12: bool,
}

impl RawClientTlsSources {
    fn validate(self) -> Result<ClientTlsSources, RunnerProductConfigError> {
        for source in [
            &self.server_roots,
            &self.certificate_chain,
            &self.private_key,
        ] {
            source
                .validate()
                .map_err(RunnerProductConfigError::SecureInput)?;
        }
        Ok(ClientTlsSources {
            server_roots: self.server_roots,
            certificate_chain: self.certificate_chain,
            private_key: self.private_key,
            allow_legacy_tls12: self.allow_legacy_tls12,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSpoolProtectionConfig {
    protection_id: String,
    key_hex: SecretSource,
}

impl RawSpoolProtectionConfig {
    fn validate(self) -> Result<SpoolProtectionConfig, RunnerProductConfigError> {
        self.key_hex
            .validate()
            .map_err(RunnerProductConfigError::SecureInput)?;
        automata_runner_spool::ProtectionId::new(self.protection_id.clone())
            .map_err(|_| RunnerProductConfigError::InvalidSpoolProtection)?;
        Ok(SpoolProtectionConfig {
            protection_id: self.protection_id,
            key_hex: self.key_hex,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInventory {
    labels: Vec<String>,
    groups: Vec<String>,
    max_parallel_jobs: u16,
    resources_per_job: RawResources,
    environment_profiles: Vec<RawEnvironment>,
}

impl RawInventory {
    fn validate(
        self,
        runner_id: RunnerId,
        executor: &ExecutorProductConfig,
        job_container_engine: automata_sandbox_podman::JobContainerEngine,
    ) -> Result<
        (
            RunnerCapabilities,
            BTreeMap<EnvironmentProfile, SandboxEnvironment>,
        ),
        RunnerProductConfigError,
    > {
        if self.labels.len() > MAX_SELECTORS
            || self.groups.len() > MAX_SELECTORS
            || self.environment_profiles.is_empty()
            || self.environment_profiles.len() > MAX_ENVIRONMENTS
        {
            return Err(RunnerProductConfigError::InvalidInventory);
        }
        let labels = self
            .labels
            .into_iter()
            .map(RunnerLabel::new)
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(|_| RunnerProductConfigError::InvalidInventory)?;
        let groups = self
            .groups
            .into_iter()
            .map(RunnerGroup::new)
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(|_| RunnerProductConfigError::InvalidInventory)?;
        let resources = self.resources_per_job.validate()?;
        if resources.execution != executor.resources() {
            return Err(RunnerProductConfigError::InvalidInventory);
        }
        let mut environments = BTreeMap::new();
        for raw in self.environment_profiles {
            let environment = raw.validate()?;
            if environments
                .insert(environment.attestation().clone(), environment)
                .is_some()
            {
                return Err(RunnerProductConfigError::InvalidInventory);
            }
        }
        let platform = RunnerPlatform::new(host_operating_system()?, host_architecture()?);
        let mut sandbox_features = BTreeSet::from([
            SandboxFeature::CLEAN_WORKSPACE,
            SandboxFeature::NETWORK_ISOLATION,
        ]);
        if executor.root_filesystem() == RootFilesystemPolicy::ReadOnly {
            sandbox_features.insert(SandboxFeature::READ_ONLY_ROOT);
        }
        if executor.privilege() == SandboxPrivilegePolicy::Administrator {
            sandbox_features.insert(SandboxFeature::PRIVILEGED_USER);
        }
        let sandbox = SandboxCapabilities::new(IsolationLevel::SharedKernel, sandbox_features);
        let inventory = RunnerCapabilities::new(runner_id, platform)
            .with_labels(labels)
            .with_groups(groups)
            .with_max_parallel_jobs(self.max_parallel_jobs)
            .map_err(|_| RunnerProductConfigError::InvalidInventory)?
            .with_resources_per_job(resources.capacity)
            .with_sandbox(sandbox)
            .with_containers(match job_container_engine {
                automata_sandbox_podman::JobContainerEngine::Disabled => {
                    ContainerCapabilities::default()
                }
                automata_sandbox_podman::JobContainerEngine::AttemptScopedDockerApi => {
                    ContainerCapabilities::new([ContainerFeature::DOCKER_COMPATIBLE_API])
                }
            })
            .with_features([
                RunnerFeature::SHELL_STEPS,
                RunnerFeature::JAVASCRIPT_ACTIONS,
                RunnerFeature::COMMAND_FILES,
            ])
            .with_environment_profiles(environments.keys().cloned());
        inventory
            .validate()
            .map_err(|_| RunnerProductConfigError::InvalidInventory)?;
        Ok((inventory, environments))
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawResources {
    cpu_millis: u32,
    memory_bytes: u64,
    ephemeral_disk_bytes: u64,
    pids: u32,
}

struct ValidatedResources {
    capacity: ResourceCapacity,
    execution: ResourceLimits,
}

impl RawResources {
    fn validate(self) -> Result<ValidatedResources, RunnerProductConfigError> {
        let execution = ResourceLimits::new(self.memory_bytes, self.cpu_millis, self.pids)
            .map_err(|_| RunnerProductConfigError::InvalidInventory)?;
        Ok(ValidatedResources {
            capacity: ResourceCapacity::new(
                self.cpu_millis,
                self.memory_bytes,
                self.ephemeral_disk_bytes,
                0,
            ),
            execution,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEnvironment {
    id: String,
    manifest_sha256: String,
    image: String,
    keepalive_program: String,
    keepalive_arguments: Vec<String>,
    workspace: String,
    #[serde(default)]
    default_environment: BTreeMap<String, String>,
}

impl RawEnvironment {
    fn validate(self) -> Result<SandboxEnvironment, RunnerProductConfigError> {
        if self.keepalive_arguments.len() > MAX_KEEPALIVE_ARGUMENTS {
            return Err(RunnerProductConfigError::InvalidInventory);
        }
        let id = EnvironmentProfileId::new(self.id)
            .map_err(|_| RunnerProductConfigError::InvalidInventory)?;
        let digest = Sha256Digest::from_str(&self.manifest_sha256)
            .map_err(|_| RunnerProductConfigError::InvalidInventory)?;
        let attestation = EnvironmentProfile::new(id, digest);
        let image = ImmutableImage::new(self.image)
            .map_err(|_| RunnerProductConfigError::InvalidInventory)?;
        let keepalive_program = TargetPath::posix(self.keepalive_program)
            .map_err(|_| RunnerProductConfigError::InvalidInventory)?;
        let keepalive = ExecutionArgv::new(keepalive_program, self.keepalive_arguments)
            .map_err(|_| RunnerProductConfigError::InvalidInventory)?;
        let workspace = TargetPath::posix(self.workspace)
            .map_err(|_| RunnerProductConfigError::InvalidInventory)?;
        let default_environment = self
            .default_environment
            .into_iter()
            .map(|(name, value)| {
                let name = EnvironmentName::new(name)
                    .map_err(|_| RunnerProductConfigError::InvalidInventory)?;
                let value = EnvironmentValue::new(value)
                    .map_err(|_| RunnerProductConfigError::InvalidInventory)?;
                Ok(EnvironmentVariable::new(name, value))
            })
            .collect::<Result<Vec<_>, RunnerProductConfigError>>()?;
        let default_environment = ExecutionEnvironment::new(default_environment)
            .map_err(|_| RunnerProductConfigError::InvalidInventory)?;
        SandboxEnvironment::new(
            attestation,
            image,
            keepalive,
            workspace,
            default_environment,
        )
        .map_err(|_| RunnerProductConfigError::InvalidInventory)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPodmanProductConfig {
    binary: PathBuf,
    home: PathBuf,
    runtime_directory: Option<PathBuf>,
    executable_search_path: String,
    job_container_engine: RawJobContainerEngine,
    #[serde(default)]
    map_github_server_to_host_gateway: bool,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawJobContainerEngine {
    Disabled,
    AttemptScopedDockerApi,
}

impl RawPodmanProductConfig {
    fn validate(
        self,
        github_server_url: &Url,
    ) -> Result<PodmanProductConfig, RunnerProductConfigError> {
        validate_absolute_path(&self.binary)
            .map_err(|_| RunnerProductConfigError::InvalidPodman)?;
        validate_absolute_path(&self.home).map_err(|_| RunnerProductConfigError::InvalidPodman)?;
        if self
            .runtime_directory
            .as_deref()
            .is_some_and(|path| validate_absolute_path(path).is_err())
            || self.executable_search_path.is_empty()
            || self.executable_search_path.len() > 4_096
        {
            return Err(RunnerProductConfigError::InvalidPodman);
        }
        automata_sandbox_podman::PodmanBinary::new(self.binary.clone())
            .map_err(|_| RunnerProductConfigError::InvalidPodman)?;
        automata_sandbox_podman::PodmanProcessEnvironment::new(
            self.home.clone(),
            self.runtime_directory.clone(),
            OsString::from(&self.executable_search_path),
        )
        .map_err(|_| RunnerProductConfigError::InvalidPodman)?;
        let github_server_host_gateway_alias = self
            .map_github_server_to_host_gateway
            .then(|| {
                let hostname = github_server_url
                    .host_str()
                    .ok_or(RunnerProductConfigError::InvalidPodman)?;
                automata_sandbox_podman::PodmanHostGatewayAlias::new(hostname)
                    .map_err(|_| RunnerProductConfigError::InvalidPodman)
            })
            .transpose()?;
        Ok(PodmanProductConfig {
            binary: self.binary,
            home: self.home,
            runtime_directory: self.runtime_directory,
            executable_search_path: OsString::from(self.executable_search_path),
            job_container_engine: match self.job_container_engine {
                RawJobContainerEngine::Disabled => {
                    automata_sandbox_podman::JobContainerEngine::Disabled
                }
                RawJobContainerEngine::AttemptScopedDockerApi => {
                    automata_sandbox_podman::JobContainerEngine::AttemptScopedDockerApi
                }
            },
            github_server_host_gateway_alias,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawNetworkPolicy {
    Disabled,
    PrivateEgress,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawRootFilesystemPolicy {
    ReadOnly,
    Writable,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawPrivilegePolicy {
    Unprivileged,
    Administrator,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExecutorProductConfig {
    resources: RawResources,
    network: RawNetworkPolicy,
    root_filesystem: RawRootFilesystemPolicy,
    privilege: RawPrivilegePolicy,
    default_step_timeout_seconds: u64,
    maximum_output_bytes: usize,
    runner_root: String,
    home: String,
    path: String,
    temp: String,
    tool_cache: String,
    toolchain: RawToolchainConfig,
}

impl RawExecutorProductConfig {
    fn validate(self) -> Result<ExecutorProductConfig, RunnerProductConfigError> {
        let resources = self
            .resources
            .validate()
            .map_err(|_| RunnerProductConfigError::InvalidExecutor)?
            .execution;
        let network = match self.network {
            RawNetworkPolicy::Disabled => NetworkPolicy::Disabled,
            RawNetworkPolicy::PrivateEgress => NetworkPolicy::PrivateEgress,
        };
        let root_filesystem = match self.root_filesystem {
            RawRootFilesystemPolicy::ReadOnly => RootFilesystemPolicy::ReadOnly,
            RawRootFilesystemPolicy::Writable => RootFilesystemPolicy::Writable,
        };
        let privilege = match self.privilege {
            RawPrivilegePolicy::Unprivileged => SandboxPrivilegePolicy::Unprivileged,
            RawPrivilegePolicy::Administrator => SandboxPrivilegePolicy::Administrator,
        };
        let default_step_timeout = Duration::from_secs(self.default_step_timeout_seconds);
        let runner_root = TargetPath::posix(self.runner_root)
            .map_err(|_| RunnerProductConfigError::InvalidExecutor)?;
        if runner_root.as_str() == "/" {
            return Err(RunnerProductConfigError::InvalidExecutor);
        }
        let home =
            TargetPath::posix(self.home).map_err(|_| RunnerProductConfigError::InvalidExecutor)?;
        let tool_cache = TargetPath::posix(self.tool_cache)
            .map_err(|_| RunnerProductConfigError::InvalidExecutor)?;
        let temp =
            TargetPath::posix(self.temp).map_err(|_| RunnerProductConfigError::InvalidExecutor)?;
        if home.as_str() == "/"
            || temp.as_str() == "/"
            || tool_cache.as_str() == "/"
            || self.path.is_empty()
            || self.path.len() > 8_192
            || self
                .path
                .split(':')
                .any(|entry| entry.is_empty() || TargetPath::posix(entry).is_err())
        {
            return Err(RunnerProductConfigError::InvalidExecutor);
        }
        let toolchain = self.toolchain.validate()?;
        automata_job_executor_github::GithubJobExecutorConfig::new(
            resources,
            network,
            root_filesystem,
            privilege,
            default_step_timeout,
            self.maximum_output_bytes,
            runner_root.clone(),
        )
        .map_err(|_| RunnerProductConfigError::InvalidExecutor)?;
        Ok(ExecutorProductConfig {
            resources,
            network,
            root_filesystem,
            privilege,
            default_step_timeout,
            maximum_output_bytes: self.maximum_output_bytes,
            runner_root,
            home,
            path: self.path,
            temp,
            tool_cache,
            toolchain,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawToolchainConfig {
    bash: String,
    sh: String,
    install: String,
    tar: String,
    node12: Option<String>,
    node16: Option<String>,
    node20: Option<String>,
    node24: Option<String>,
}

impl RawToolchainConfig {
    fn validate(self) -> Result<ToolchainConfig, RunnerProductConfigError> {
        let path = |value: String| {
            TargetPath::posix(value).map_err(|_| RunnerProductConfigError::InvalidExecutor)
        };
        Ok(ToolchainConfig {
            bash: path(self.bash)?,
            sh: path(self.sh)?,
            install: path(self.install)?,
            tar: path(self.tar)?,
            node12: self.node12.map(path).transpose()?,
            node16: self.node16.map(path).transpose()?,
            node20: self.node20.map(path).transpose()?,
            node24: self.node24.map(path).transpose()?,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawObjectStoreProductConfig {
    endpoint: String,
    region: String,
    bucket: String,
    prefix: Option<String>,
    #[serde(default)]
    force_path_style: bool,
    #[serde(default)]
    loopback_development: bool,
    operation_timeout_seconds: u64,
    access_key_id: SecretSource,
    secret_access_key: SecretSource,
    session_token: Option<SecretSource>,
}

impl RawObjectStoreProductConfig {
    fn validate(self) -> Result<ObjectStoreProductConfig, RunnerProductConfigError> {
        for source in [
            Some(&self.access_key_id),
            Some(&self.secret_access_key),
            self.session_token.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            source
                .validate()
                .map_err(RunnerProductConfigError::SecureInput)?;
        }
        let endpoint =
            Url::parse(&self.endpoint).map_err(|_| RunnerProductConfigError::InvalidObjectStore)?;
        let operation_timeout = Duration::from_secs(self.operation_timeout_seconds);
        let effective_force_path_style = self.force_path_style || self.loopback_development;
        if self.loopback_development {
            automata_blob_s3::S3BlobStoreConfig::loopback_development(
                endpoint.clone(),
                self.region.clone(),
                self.bucket.clone(),
                self.prefix.clone(),
                operation_timeout,
            )
        } else {
            automata_blob_s3::S3BlobStoreConfig::new(
                endpoint.clone(),
                self.region.clone(),
                self.bucket.clone(),
                self.prefix.clone(),
                self.force_path_style,
                operation_timeout,
            )
        }
        .map_err(|_| RunnerProductConfigError::InvalidObjectStore)?;
        Ok(ObjectStoreProductConfig {
            endpoint,
            region: self.region,
            bucket: self.bucket,
            prefix: self.prefix,
            force_path_style: effective_force_path_style,
            loopback_development: self.loopback_development,
            operation_timeout,
            access_key_id: self.access_key_id,
            secret_access_key: self.secret_access_key,
            session_token: self.session_token,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGithubProductConfig {
    user_agent: String,
    repository_credential: Option<SecretSource>,
    workflow_token: Option<SecretSource>,
    server_url: String,
    api_url: String,
    graphql_url: String,
    #[serde(default)]
    allow_insecure_http: bool,
}

impl RawGithubProductConfig {
    fn validate(self) -> Result<GithubProductConfig, RunnerProductConfigError> {
        if self.user_agent.is_empty()
            || self.user_agent.len() > MAX_USER_AGENT_BYTES
            || !self.user_agent.is_ascii()
            || self.user_agent.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(RunnerProductConfigError::InvalidGithub);
        }
        automata_github::GithubTrustedOrigins::github_dot_com(&self.user_agent)
            .map_err(|_| RunnerProductConfigError::InvalidGithub)?;
        for source in [
            self.repository_credential.as_ref(),
            self.workflow_token.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            source
                .validate()
                .map_err(RunnerProductConfigError::SecureInput)?;
        }
        let server_url =
            validate_github_context_url(&self.server_url, self.allow_insecure_http, true)?;
        let api_url = validate_github_context_url(&self.api_url, self.allow_insecure_http, false)?;
        let graphql_url =
            validate_github_context_url(&self.graphql_url, self.allow_insecure_http, false)?;
        Ok(GithubProductConfig {
            user_agent: self.user_agent,
            repository_credential: self.repository_credential,
            workflow_token: self.workflow_token,
            server_url,
            api_url,
            graphql_url,
            allow_insecure_http: self.allow_insecure_http,
        })
    }
}

fn validate_github_context_url(
    value: &str,
    allow_insecure_http: bool,
    require_origin_path: bool,
) -> Result<Url, RunnerProductConfigError> {
    if value.is_empty() || value.len() > 2_048 {
        return Err(RunnerProductConfigError::InvalidGithub);
    }
    let url = Url::parse(value).map_err(|_| RunnerProductConfigError::InvalidGithub)?;
    let scheme_allowed = url.scheme() == "https" || (allow_insecure_http && url.scheme() == "http");
    let valid = scheme_allowed
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && (!require_origin_path || url.path() == "/");
    valid
        .then_some(url)
        .ok_or(RunnerProductConfigError::InvalidGithub)
}

fn validate_control_endpoint(value: &str) -> Result<Uri, RunnerProductConfigError> {
    if value.len() > 2_048 {
        return Err(RunnerProductConfigError::InvalidControlEndpoint);
    }
    let endpoint =
        Uri::from_str(value).map_err(|_| RunnerProductConfigError::InvalidControlEndpoint)?;
    let valid = endpoint.scheme_str() == Some("https")
        && endpoint.authority().is_some()
        && endpoint.path() == "/"
        && endpoint.query().is_none()
        && endpoint
            .authority()
            .is_some_and(|authority| !authority.as_str().contains('@'));
    valid
        .then_some(endpoint)
        .ok_or(RunnerProductConfigError::InvalidControlEndpoint)
}

fn host_operating_system() -> Result<OperatingSystem, RunnerProductConfigError> {
    match std::env::consts::OS {
        "linux" => Ok(OperatingSystem::Linux),
        _ => Err(RunnerProductConfigError::InvalidInventory),
    }
}

fn host_architecture() -> Result<Architecture, RunnerProductConfigError> {
    match std::env::consts::ARCH {
        "x86_64" => Ok(Architecture::X86_64),
        "aarch64" => Ok(Architecture::Aarch64),
        _ => Err(RunnerProductConfigError::InvalidInventory),
    }
}
