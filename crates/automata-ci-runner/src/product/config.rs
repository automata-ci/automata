use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr as _,
    time::Duration,
};

use automata_ci_core::{
    Architecture, ContainerCapabilities, ContainerFeature, EnvironmentProfile,
    EnvironmentProfileId, IsolationLevel, OperatingSystem, ResourceCapacity, RunnerCapabilities,
    RunnerFeature, RunnerGroup, RunnerId, RunnerLabel, RunnerPlatform, SandboxCapabilities,
    SandboxFeature, Sha256Digest,
};
use automata_ci_execution::{
    EnvironmentName, EnvironmentValue, EnvironmentVariable, ExecutionArgv, ExecutionEnvironment,
    ImmutableImage, NetworkPolicy, ResourceLimits, RootFilesystemPolicy, SandboxEnvironment,
    SandboxPrivilegePolicy, TargetPath, TargetPlatform,
};
use automata_ci_runner_journal::StateRoot;
use automata_ci_runner_spool::{ProtectionId, SpoolRoot};
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
const PODMAN_RUNTIME_ROOT_NAME: &str = "automata-ci-podman";
const PODMAN_STATE_ROOT_NAME: &str = "state";

pub(super) fn required_podman_state_root(runtime_directory: &Path) -> PathBuf {
    runtime_directory
        .join(PODMAN_RUNTIME_ROOT_NAME)
        .join(PODMAN_STATE_ROOT_NAME)
}

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
    provider: RunnerProviderConfig,
    executor: ExecutorProductConfig,
    object_store: ObjectStoreProductConfig,
    github: GithubProductConfig,
    metrics: Option<MetricsProductConfig>,
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

    /// Returns the durable identity authenticated to the control plane.
    #[must_use]
    pub const fn runner_id(&self) -> RunnerId {
        self.runner_id
    }

    /// Returns the validated credential-free HTTPS control-plane origin.
    #[must_use]
    pub const fn control_endpoint(&self) -> &Uri {
        &self.control_endpoint
    }

    /// Returns the three non-overlapping durable provider-state roots.
    #[must_use]
    pub const fn state(&self) -> &StateRoots {
        &self.state
    }

    /// Returns locations from which outbound mTLS material is loaded.
    #[must_use]
    pub const fn tls(&self) -> &ClientTlsSources {
        &self.tls
    }

    /// Returns active-write and decrypt-only encrypted-spool key sources.
    #[must_use]
    pub const fn spool(&self) -> &SpoolProtectionConfig {
        &self.spool
    }

    /// Returns the validated durable registration ceiling for this runner identity.
    ///
    /// Runtime admission independently reduces configured abilities to the
    /// capabilities proved by the live provider before opening a session.
    #[must_use]
    pub const fn inventory(&self) -> &RunnerCapabilities {
        &self.inventory
    }

    /// Returns immutable sandbox environments keyed by their attested profiles.
    #[must_use]
    pub const fn environments(&self) -> &BTreeMap<EnvironmentProfile, SandboxEnvironment> {
        &self.environments
    }

    /// Returns the selected native or container execution provider policy.
    #[must_use]
    pub const fn provider(&self) -> &RunnerProviderConfig {
        &self.provider
    }

    /// Returns rootless-Podman host process policy when selected.
    #[must_use]
    pub const fn podman(&self) -> Option<&PodmanProductConfig> {
        match &self.provider {
            RunnerProviderConfig::Podman(config) => Some(config),
            RunnerProviderConfig::WindowsNative(_) => None,
        }
    }

    /// Returns trusted native-Windows provider policy when selected.
    #[must_use]
    pub const fn windows_native(&self) -> Option<&WindowsNativeProductConfig> {
        match &self.provider {
            RunnerProviderConfig::WindowsNative(config) => Some(config),
            RunnerProviderConfig::Podman(_) => None,
        }
    }

    /// Returns per-job resource, isolation, path, and tool policy.
    #[must_use]
    pub const fn executor(&self) -> &ExecutorProductConfig {
        &self.executor
    }

    /// Returns immutable action-bundle object-store policy and credential sources.
    #[must_use]
    pub const fn object_store(&self) -> &ObjectStoreProductConfig {
        &self.object_store
    }

    /// Returns credential-free GitHub context endpoints.
    #[must_use]
    pub const fn github(&self) -> &GithubProductConfig {
        &self.github
    }

    /// Returns the private metrics listener configuration when observability is enabled.
    #[must_use]
    pub const fn metrics(&self) -> Option<&MetricsProductConfig> {
        self.metrics.as_ref()
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
            .field("provider", &self.provider)
            .field("executor", &self.executor)
            .field("object_store", &self.object_store)
            .field("github", &self.github)
            .field("metrics", &self.metrics)
            .finish()
    }
}

/// Dedicated nonzero-port, loopback-only Prometheus/OpenMetrics listener configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetricsProductConfig {
    listen: SocketAddr,
}

impl MetricsProductConfig {
    /// Returns the independently supervised operations listener address.
    #[must_use]
    pub const fn listen(&self) -> SocketAddr {
        self.listen
    }
}

/// Distinct roots for semantic state, encrypted content, and provider state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateRoots {
    journal: StateRoot,
    spool: SpoolRoot,
    provider: PathBuf,
}

impl StateRoots {
    /// Returns the semantic execution-journal root.
    #[must_use]
    pub const fn journal(&self) -> &StateRoot {
        &self.journal
    }

    /// Returns the encrypted content-spool root.
    #[must_use]
    pub const fn spool(&self) -> &SpoolRoot {
        &self.spool
    }

    /// Returns the selected execution provider's durable state root.
    #[must_use]
    pub fn provider(&self) -> &Path {
        &self.provider
    }
}

/// Validated execution-provider selection for one runner process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunnerProviderConfig {
    /// Rootless Podman on a dedicated Linux execution host.
    Podman(PodmanProductConfig),
    /// Job Object-contained native processes for trusted Windows jobs.
    WindowsNative(WindowsNativeProductConfig),
}

/// Trusted native-Windows execution provider configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsNativeProductConfig;

/// Explicit material locations for outbound runner mTLS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientTlsSources {
    server_roots: SecretSource,
    certificate_chain: SecretSource,
    private_key: SecretSource,
}

impl ClientTlsSources {
    /// Returns the source of PEM trust anchors for server authentication.
    #[must_use]
    pub const fn server_roots(&self) -> &SecretSource {
        &self.server_roots
    }

    /// Returns the source of the runner's PEM client-certificate chain.
    #[must_use]
    pub const fn certificate_chain(&self) -> &SecretSource {
        &self.certificate_chain
    }

    /// Returns the source of the runner's PEM client private key.
    #[must_use]
    pub const fn private_key(&self) -> &SecretSource {
        &self.private_key
    }
}

/// Rotation-aware AES-256-GCM spool protection inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpoolProtectionConfig {
    protection_id: ProtectionId,
    key_hex: SecretSource,
    decrypt_only: Vec<SpoolDecryptionKeyConfig>,
}

impl SpoolProtectionConfig {
    /// Returns the only protection ID permitted for new spool writes.
    #[must_use]
    pub fn protection_id(&self) -> &str {
        self.protection_id.as_str()
    }

    /// Returns the secret source for the active write key.
    #[must_use]
    pub const fn key_hex(&self) -> &SecretSource {
        &self.key_hex
    }

    /// Returns the bounded old-key set used only for exact-ID reads.
    pub fn decrypt_only_keys(&self) -> impl ExactSizeIterator<Item = (&str, &SecretSource)> {
        self.decrypt_only
            .iter()
            .map(|key| (key.protection_id.as_str(), &key.key_hex))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SpoolDecryptionKeyConfig {
    protection_id: ProtectionId,
    key_hex: SecretSource,
}

/// Explicit rootless-Podman host process configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PodmanProductConfig {
    binary: PathBuf,
    home: PathBuf,
    runtime_directory: PathBuf,
    approved_helper_directory: PathBuf,
    conmon_path: PathBuf,
    oci_runtime_path: PathBuf,
    init_path: PathBuf,
    seccomp_profile_path: PathBuf,
    job_container_engine: automata_ci_sandbox_podman::JobContainerEngine,
    github_server_host_gateway_alias: Option<automata_ci_sandbox_podman::PodmanHostGatewayAlias>,
    service_proxy_image: Option<ImmutableImage>,
}

impl PodmanProductConfig {
    /// Returns the validated absolute Podman executable path.
    #[must_use]
    pub fn binary(&self) -> &Path {
        &self.binary
    }

    /// Returns the absolute home directory supplied to the Podman process.
    #[must_use]
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// Returns the required absolute dedicated rootless-runtime mountpoint.
    #[must_use]
    pub fn runtime_directory(&self) -> &Path {
        &self.runtime_directory
    }

    /// Returns the sole administrator-controlled helper directory supplied as `PATH`.
    #[must_use]
    pub fn approved_helper_directory(&self) -> &Path {
        &self.approved_helper_directory
    }

    /// Returns the exact administrator-controlled conmon executable.
    #[must_use]
    pub fn conmon_path(&self) -> &Path {
        &self.conmon_path
    }

    /// Returns the exact administrator-controlled OCI runtime executable.
    #[must_use]
    pub fn oci_runtime_path(&self) -> &Path {
        &self.oci_runtime_path
    }

    /// Returns the exact administrator-controlled container init executable.
    #[must_use]
    pub fn init_path(&self) -> &Path {
        &self.init_path
    }

    /// Returns the exact administrator-controlled seccomp profile.
    #[must_use]
    pub fn seccomp_profile_path(&self) -> &Path {
        &self.seccomp_profile_path
    }

    /// Returns whether jobs receive an attempt-scoped Docker-compatible API.
    #[must_use]
    pub const fn job_container_engine(&self) -> automata_ci_sandbox_podman::JobContainerEngine {
        self.job_container_engine
    }

    /// Exact `github.server_url` hostname mapped to the Podman host gateway
    /// when the deployment explicitly opts into local-host routing.
    #[must_use]
    pub const fn github_server_host_gateway_alias(
        &self,
    ) -> Option<&automata_ci_sandbox_podman::PodmanHostGatewayAlias> {
        self.github_server_host_gateway_alias.as_ref()
    }

    /// Returns the optional immutable helper image used for service port mappings.
    #[must_use]
    pub const fn service_proxy_image(&self) -> Option<&ImmutableImage> {
        self.service_proxy_image.as_ref()
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
    /// Returns the CPU, memory, and process ceilings enforced for each job.
    #[must_use]
    pub const fn resources(&self) -> ResourceLimits {
        self.resources
    }

    /// Returns the job sandbox egress policy.
    #[must_use]
    pub const fn network(&self) -> NetworkPolicy {
        self.network
    }

    /// Returns whether each job container's root filesystem is writable.
    #[must_use]
    pub const fn root_filesystem(&self) -> RootFilesystemPolicy {
        self.root_filesystem
    }

    /// Returns the privilege level allowed inside each job sandbox.
    #[must_use]
    pub const fn privilege(&self) -> SandboxPrivilegePolicy {
        self.privilege
    }

    /// Returns the default deadline applied when a step declares none.
    #[must_use]
    pub const fn default_step_timeout(&self) -> Duration {
        self.default_step_timeout
    }

    /// Returns the maximum step-output bytes accepted by the executor.
    #[must_use]
    pub const fn maximum_output_bytes(&self) -> usize {
        self.maximum_output_bytes
    }

    /// Returns the non-root target path reserved for runner-managed files.
    #[must_use]
    pub const fn runner_root(&self) -> &TargetPath {
        &self.runner_root
    }

    /// Returns the target home directory exposed to job steps.
    #[must_use]
    pub const fn home(&self) -> &TargetPath {
        &self.home
    }

    /// Returns the validated colon-separated target executable search path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the target temporary-work directory.
    #[must_use]
    pub const fn temp(&self) -> &TargetPath {
        &self.temp
    }

    /// Returns the target directory containing preinstalled tools.
    #[must_use]
    pub const fn tool_cache(&self) -> &TargetPath {
        &self.tool_cache
    }

    /// Returns executable paths used for shells, archives, installs, and actions.
    #[must_use]
    pub const fn toolchain(&self) -> &ToolchainConfig {
        &self.toolchain
    }
}

/// Executable locations baked into every configured environment manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolchainConfig {
    bash: Option<TargetPath>,
    sh: Option<TargetPath>,
    python: Option<TargetPath>,
    pwsh: Option<TargetPath>,
    powershell: Option<TargetPath>,
    cmd: Option<TargetPath>,
    install: Option<TargetPath>,
    tar: Option<TargetPath>,
    sha256sum: Option<TargetPath>,
    node12: Option<TargetPath>,
    node16: Option<TargetPath>,
    node20: Option<TargetPath>,
    node24: Option<TargetPath>,
}

impl ToolchainConfig {
    /// Returns the target path to Bash.
    #[must_use]
    pub const fn bash(&self) -> Option<&TargetPath> {
        self.bash.as_ref()
    }

    /// Returns the target path to the POSIX shell.
    #[must_use]
    pub const fn sh(&self) -> Option<&TargetPath> {
        self.sh.as_ref()
    }

    /// Returns the optional target Python executable for `shell: python`.
    #[must_use]
    pub const fn python(&self) -> Option<&TargetPath> {
        self.python.as_ref()
    }

    /// Returns the optional target PowerShell Core executable for `shell: pwsh`.
    #[must_use]
    pub const fn pwsh(&self) -> Option<&TargetPath> {
        self.pwsh.as_ref()
    }

    /// Returns the optional Windows PowerShell executable.
    #[must_use]
    pub const fn powershell(&self) -> Option<&TargetPath> {
        self.powershell.as_ref()
    }

    /// Returns the optional Windows command interpreter.
    #[must_use]
    pub const fn cmd(&self) -> Option<&TargetPath> {
        self.cmd.as_ref()
    }

    /// Returns the target path to the installation utility.
    #[must_use]
    pub const fn install(&self) -> Option<&TargetPath> {
        self.install.as_ref()
    }

    /// Returns the target path to the tar utility.
    #[must_use]
    pub const fn tar(&self) -> Option<&TargetPath> {
        self.tar.as_ref()
    }

    /// Returns the optional POSIX SHA-256 hashing utility.
    #[must_use]
    pub const fn sha256sum(&self) -> Option<&TargetPath> {
        self.sha256sum.as_ref()
    }

    /// Returns the optional target Node.js 12 executable for legacy actions.
    #[must_use]
    pub const fn node12(&self) -> Option<&TargetPath> {
        self.node12.as_ref()
    }

    /// Returns the optional target Node.js 16 executable for actions.
    #[must_use]
    pub const fn node16(&self) -> Option<&TargetPath> {
        self.node16.as_ref()
    }

    /// Returns the optional target Node.js 20 executable for actions.
    #[must_use]
    pub const fn node20(&self) -> Option<&TargetPath> {
        self.node20.as_ref()
    }

    /// Returns the optional target Node.js 24 executable for actions.
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
    /// Returns the validated S3-compatible API endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    /// Returns the signing region.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }

    /// Returns the bucket containing immutable action bundles.
    #[must_use]
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// Returns the optional object-key namespace prefix.
    #[must_use]
    pub fn prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }

    /// Reports whether requests use path-style bucket addressing.
    ///
    /// This is always true for loopback development mode.
    #[must_use]
    pub const fn force_path_style(&self) -> bool {
        self.force_path_style
    }

    /// Reports whether explicitly loopback-only development transport is enabled.
    #[must_use]
    pub const fn loopback_development(&self) -> bool {
        self.loopback_development
    }

    /// Returns the deadline applied to each object-store operation.
    #[must_use]
    pub const fn operation_timeout(&self) -> Duration {
        self.operation_timeout
    }

    /// Returns the source of the S3 access-key identifier.
    #[must_use]
    pub const fn access_key_id(&self) -> &SecretSource {
        &self.access_key_id
    }

    /// Returns the source of the S3 secret access key.
    #[must_use]
    pub const fn secret_access_key(&self) -> &SecretSource {
        &self.secret_access_key
    }

    /// Returns the optional source of a temporary S3 session token.
    #[must_use]
    pub const fn session_token(&self) -> Option<&SecretSource> {
        self.session_token.as_ref()
    }
}

/// Credential-free GitHub context endpoints.
///
/// Repository, workflow, and Results credentials are intentionally absent:
/// they must be delivered as protected, job-scoped authority and can never be
/// runner-scoped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubProductConfig {
    user_agent: String,
    server_url: Url,
    api_url: Url,
    graphql_url: Url,
    allow_insecure_http: bool,
}

impl GithubProductConfig {
    /// Returns the bounded ASCII identifier used for GitHub HTTP clients.
    #[must_use]
    pub fn user_agent(&self) -> &str {
        &self.user_agent
    }

    /// Returns the credential-free `github.server_url` context origin.
    #[must_use]
    pub const fn server_url(&self) -> &Url {
        &self.server_url
    }

    /// Returns the credential-free `github.api_url` context endpoint.
    #[must_use]
    pub const fn api_url(&self) -> &Url {
        &self.api_url
    }

    /// Returns the credential-free `github.graphql_url` context endpoint.
    #[must_use]
    pub const fn graphql_url(&self) -> &Url {
        &self.graphql_url
    }

    /// Reports whether the deployment explicitly permits HTTP context endpoints.
    ///
    /// This does not add credentials or authority to those endpoints.
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
    /// Exactly one host-compatible execution provider must be selected.
    #[error("runner execution provider configuration is invalid")]
    InvalidProvider,
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
    /// The metrics listener is not a literal loopback socket address with a nonzero port.
    #[error("runner metrics configuration is invalid")]
    InvalidMetrics,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProviderKind {
    Podman,
    WindowsNative,
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
    #[serde(default)]
    podman: Option<RawPodmanProductConfig>,
    #[serde(default)]
    windows_native: Option<RawWindowsNativeProductConfig>,
    executor: RawExecutorProductConfig,
    object_store: RawObjectStoreProductConfig,
    github: RawGithubProductConfig,
    #[serde(default)]
    metrics: Option<RawMetricsProductConfig>,
}

impl RawRunnerProductConfig {
    fn validate(self) -> Result<RunnerProductConfig, RunnerProductConfigError> {
        if self.schema_version != RUNNER_PRODUCT_CONFIG_SCHEMA_VERSION {
            return Err(RunnerProductConfigError::UnsupportedSchema);
        }
        let control_endpoint = validate_control_endpoint(&self.control_endpoint)?;
        let tls = self.tls.validate()?;
        let spool = self.spool.validate()?;
        let github = self.github.validate()?;
        let metrics = self
            .metrics
            .map(RawMetricsProductConfig::validate)
            .transpose()?;
        let (provider, provider_kind) = match (self.podman, self.windows_native) {
            (Some(podman), None) => (
                RunnerProviderConfig::Podman(podman.validate(github.server_url())?),
                ProviderKind::Podman,
            ),
            (None, Some(windows_native)) => (
                RunnerProviderConfig::WindowsNative(windows_native.validate()?),
                ProviderKind::WindowsNative,
            ),
            _ => return Err(RunnerProductConfigError::InvalidProvider),
        };
        let state = self.state.validate(provider_kind)?;
        let executor = self.executor.validate(provider_kind)?;
        if let RunnerProviderConfig::Podman(podman) = &provider {
            let required_podman_state = required_podman_state_root(podman.runtime_directory());
            if state.provider().as_os_str() != required_podman_state.as_os_str() {
                return Err(RunnerProductConfigError::InvalidPodman);
            }
            if [state.journal().as_path(), state.spool().as_path()]
                .into_iter()
                .any(|durable| {
                    durable.starts_with(podman.runtime_directory())
                        || podman.runtime_directory().starts_with(durable)
                })
            {
                return Err(RunnerProductConfigError::InvalidStateRoots);
            }
        }
        let (inventory, environments) = self.inventory.validate(
            self.runner_id,
            &executor,
            provider_kind,
            match &provider {
                RunnerProviderConfig::Podman(podman) => podman.job_container_engine(),
                RunnerProviderConfig::WindowsNative(_) => {
                    automata_ci_sandbox_podman::JobContainerEngine::Disabled
                }
            },
            matches!(
                &provider,
                RunnerProviderConfig::Podman(podman) if podman.service_proxy_image().is_some()
            ),
        )?;
        if matches!(&provider, RunnerProviderConfig::WindowsNative(_))
            && !valid_windows_provider_topology(&state, &executor, &environments)
        {
            return Err(RunnerProductConfigError::InvalidInventory);
        }
        let object_store = self.object_store.validate()?;
        Ok(RunnerProductConfig {
            runner_id: self.runner_id,
            control_endpoint,
            state,
            tls,
            spool,
            inventory,
            environments,
            provider,
            executor,
            object_store,
            github,
            metrics,
        })
    }
}

fn valid_windows_provider_topology(
    state: &StateRoots,
    executor: &ExecutorProductConfig,
    environments: &BTreeMap<EnvironmentProfile, SandboxEnvironment>,
) -> bool {
    let Some(provider_root) = state
        .provider()
        .to_str()
        .map(|path| path.trim_end_matches('\\').to_ascii_lowercase())
    else {
        return false;
    };
    let strict_root = |path: &TargetPath| {
        automata_ci_sandbox_windows::WindowsSandboxProviderOptions::new(PathBuf::from(
            path.as_str(),
        ))
        .is_ok()
    };
    let strict_descendant = |path: &TargetPath| {
        let normalized = path.as_str().trim_end_matches('\\').to_ascii_lowercase();
        strict_root(path)
            && normalized
                .strip_prefix(&provider_root)
                .is_some_and(|remainder| remainder.starts_with('\\'))
    };
    if !strict_descendant(executor.runner_root()) {
        return false;
    }
    let runner_root = executor
        .runner_root()
        .as_str()
        .trim_end_matches('\\')
        .to_ascii_lowercase();
    environments.values().all(|environment| {
        let workspace = environment
            .workspace()
            .as_str()
            .trim_end_matches('\\')
            .to_ascii_lowercase();
        strict_descendant(environment.workspace())
            && !windows_roots_overlap(&workspace, &runner_root)
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMetricsProductConfig {
    listen: String,
}

impl RawMetricsProductConfig {
    fn validate(self) -> Result<MetricsProductConfig, RunnerProductConfigError> {
        let listen = self
            .listen
            .parse::<SocketAddr>()
            .map_err(|_| RunnerProductConfigError::InvalidMetrics)?;
        if !listen.ip().is_loopback() || listen.port() == 0 {
            return Err(RunnerProductConfigError::InvalidMetrics);
        }
        Ok(MetricsProductConfig { listen })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStateRoots {
    journal: PathBuf,
    spool: PathBuf,
    #[serde(default)]
    podman: Option<PathBuf>,
    #[serde(default)]
    windows_native: Option<PathBuf>,
}

impl RawStateRoots {
    fn validate(self, provider_kind: ProviderKind) -> Result<StateRoots, RunnerProductConfigError> {
        let provider = match (provider_kind, self.podman, self.windows_native) {
            (ProviderKind::Podman, Some(path), None)
            | (ProviderKind::WindowsNative, None, Some(path)) => path,
            _ => return Err(RunnerProductConfigError::InvalidStateRoots),
        };
        let roots = [&self.journal, &self.spool, &provider];
        let invalid_path = roots
            .iter()
            .any(|path| validate_absolute_path(path).is_err());
        let overlap = match provider_kind {
            ProviderKind::Podman => roots.iter().enumerate().any(|(left_index, left)| {
                roots.iter().enumerate().any(|(right_index, right)| {
                    left_index != right_index
                        && (left.starts_with(right.as_path()) || right.starts_with(left.as_path()))
                })
            }),
            ProviderKind::WindowsNative => {
                let normalized = roots
                    .iter()
                    .map(|path| {
                        automata_ci_sandbox_windows::WindowsSandboxProviderOptions::new(
                            path.to_path_buf(),
                        )
                        .ok()?;
                        Some(path.to_str()?.trim_end_matches('\\').to_ascii_lowercase())
                    })
                    .collect::<Option<Vec<_>>>();
                normalized.is_none_or(|roots| {
                    roots.iter().enumerate().any(|(left_index, left)| {
                        roots.iter().enumerate().any(|(right_index, right)| {
                            left_index != right_index && windows_roots_overlap(left, right)
                        })
                    })
                })
            }
        };
        if invalid_path || overlap {
            return Err(RunnerProductConfigError::InvalidStateRoots);
        }
        let journal = StateRoot::explicit(self.journal)
            .map_err(|_| RunnerProductConfigError::InvalidStateRoots)?;
        let spool = SpoolRoot::explicit(self.spool)
            .map_err(|_| RunnerProductConfigError::InvalidStateRoots)?;
        Ok(StateRoots {
            journal,
            spool,
            provider,
        })
    }
}

fn windows_roots_overlap(left: &str, right: &str) -> bool {
    left == right
        || left
            .strip_prefix(right)
            .is_some_and(|remainder| remainder.starts_with('\\'))
        || right
            .strip_prefix(left)
            .is_some_and(|remainder| remainder.starts_with('\\'))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClientTlsSources {
    server_roots: SecretSource,
    certificate_chain: SecretSource,
    private_key: SecretSource,
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
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSpoolProtectionConfig {
    protection_id: String,
    key_hex: SecretSource,
    #[serde(default)]
    decrypt_only: Vec<RawSpoolDecryptionKeyConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSpoolDecryptionKeyConfig {
    protection_id: String,
    key_hex: SecretSource,
}

impl RawSpoolProtectionConfig {
    fn validate(self) -> Result<SpoolProtectionConfig, RunnerProductConfigError> {
        if self.decrypt_only.len() > automata_ci_runner_crypto::MAX_DECRYPT_ONLY_CONTENT_KEYS {
            return Err(RunnerProductConfigError::InvalidSpoolProtection);
        }
        self.key_hex
            .validate()
            .map_err(RunnerProductConfigError::SecureInput)?;
        let protection_id = ProtectionId::new(self.protection_id)
            .map_err(|_| RunnerProductConfigError::InvalidSpoolProtection)?;
        let mut protection_ids = BTreeSet::from([protection_id.clone()]);
        let mut decrypt_only = Vec::with_capacity(self.decrypt_only.len());
        for old in self.decrypt_only {
            old.key_hex
                .validate()
                .map_err(RunnerProductConfigError::SecureInput)?;
            let old_id = ProtectionId::new(old.protection_id)
                .map_err(|_| RunnerProductConfigError::InvalidSpoolProtection)?;
            if !protection_ids.insert(old_id.clone()) {
                return Err(RunnerProductConfigError::InvalidSpoolProtection);
            }
            decrypt_only.push(SpoolDecryptionKeyConfig {
                protection_id: old_id,
                key_hex: old.key_hex,
            });
        }
        Ok(SpoolProtectionConfig {
            protection_id,
            key_hex: self.key_hex,
            decrypt_only,
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
        provider_kind: ProviderKind,
        job_container_engine: automata_ci_sandbox_podman::JobContainerEngine,
        service_proxy_configured: bool,
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
            || (provider_kind == ProviderKind::WindowsNative && self.max_parallel_jobs != 1)
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
            let environment = raw.validate(provider_kind)?;
            if environments
                .insert(environment.attestation().clone(), environment)
                .is_some()
            {
                return Err(RunnerProductConfigError::InvalidInventory);
            }
        }
        if provider_kind == ProviderKind::WindowsNative
            && environments.values().any(|environment| {
                !valid_windows_process_environment(environment.default_environment(), executor)
            })
        {
            return Err(RunnerProductConfigError::InvalidInventory);
        }
        let host_operating_system = host_operating_system()?;
        if !matches!(
            (provider_kind, &host_operating_system),
            (ProviderKind::Podman, OperatingSystem::Linux)
                | (ProviderKind::WindowsNative, OperatingSystem::Windows)
        ) {
            return Err(RunnerProductConfigError::InvalidProvider);
        }
        let platform = RunnerPlatform::new(host_operating_system, host_architecture()?);
        let (sandbox, container_features, runner_features) = match provider_kind {
            ProviderKind::Podman => {
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
                let mut container_features = match job_container_engine {
                    automata_ci_sandbox_podman::JobContainerEngine::Disabled => BTreeSet::new(),
                    automata_ci_sandbox_podman::JobContainerEngine::AttemptScopedDockerApi => {
                        BTreeSet::from([ContainerFeature::DOCKER_COMPATIBLE_API])
                    }
                };
                if service_proxy_configured {
                    container_features.insert(ContainerFeature::SERVICE_CONTAINERS);
                }
                (
                    SandboxCapabilities::new(IsolationLevel::SharedKernel, sandbox_features),
                    container_features,
                    BTreeSet::from([
                        RunnerFeature::SHELL_STEPS,
                        RunnerFeature::JAVASCRIPT_ACTIONS,
                        RunnerFeature::COMMAND_FILES,
                    ]),
                )
            }
            ProviderKind::WindowsNative => (
                SandboxCapabilities::new(
                    IsolationLevel::Process,
                    [SandboxFeature::CLEAN_WORKSPACE],
                ),
                BTreeSet::new(),
                BTreeSet::from([RunnerFeature::SHELL_STEPS, RunnerFeature::COMMAND_FILES]),
            ),
        };
        let inventory = RunnerCapabilities::new(runner_id, platform)
            .with_labels(labels)
            .with_groups(groups)
            .with_max_parallel_jobs(self.max_parallel_jobs)
            .map_err(|_| RunnerProductConfigError::InvalidInventory)?
            .with_resources_per_job(resources.capacity)
            .with_sandbox(sandbox)
            .with_containers(ContainerCapabilities::new(container_features))
            .with_features(runner_features)
            .with_environment_profiles(environments.keys().cloned());
        inventory
            .validate()
            .map_err(|_| RunnerProductConfigError::InvalidInventory)?;
        Ok((inventory, environments))
    }
}

fn valid_windows_process_environment(
    environment: &ExecutionEnvironment,
    executor: &ExecutorProductConfig,
) -> bool {
    let mut names = BTreeSet::new();
    if !environment
        .values()
        .iter()
        .all(|variable| names.insert(variable.name().as_str().to_lowercase()))
    {
        return false;
    }
    let value = |name: &str| {
        environment
            .values()
            .iter()
            .find(|variable| variable.name().as_str().eq_ignore_ascii_case(name))
            .map(|variable| variable.value().expose())
    };
    let Some(system_root) = value("SystemRoot") else {
        return false;
    };
    let Some(windir) = value("WINDIR") else {
        return false;
    };
    let Some(comspec) = value("ComSpec") else {
        return false;
    };
    let Some(temp) = value("TEMP") else {
        return false;
    };
    let Some(tmp) = value("TMP") else {
        return false;
    };
    let Some(pathext) = value("PATHEXT") else {
        return false;
    };
    let Some(cmd) = executor.toolchain().cmd() else {
        return false;
    };
    let windows_path_matches = |value: &str, expected: &TargetPath| {
        TargetPath::windows(value.to_owned())
            .is_ok_and(|path| path.as_str().eq_ignore_ascii_case(expected.as_str()))
    };
    let Ok(system_root_path) = TargetPath::windows(system_root.to_owned()) else {
        return false;
    };
    let extensions = pathext.split(';').collect::<Vec<_>>();
    system_root_path.as_str().eq_ignore_ascii_case(windir)
        && windows_path_matches(comspec, cmd)
        && windows_path_matches(temp, executor.temp())
        && windows_path_matches(tmp, executor.temp())
        && [".COM", ".EXE", ".BAT", ".CMD"]
            .into_iter()
            .all(|required| {
                extensions
                    .iter()
                    .any(|extension| extension.eq_ignore_ascii_case(required))
            })
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
        // The current rootless-Podman adapter enforces CPU, memory, and PID
        // limits, but it has no proven per-sandbox storage quota. Advertising
        // a nonzero disk capacity would let the scheduler place work against a
        // limit that the runner cannot enforce.
        if self.ephemeral_disk_bytes != 0 {
            return Err(RunnerProductConfigError::InvalidInventory);
        }
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
    #[serde(default)]
    image: Option<String>,
    #[serde(default)]
    keepalive_program: Option<String>,
    #[serde(default)]
    keepalive_arguments: Vec<String>,
    workspace: String,
    #[serde(default)]
    default_environment: BTreeMap<String, String>,
}

impl RawEnvironment {
    fn validate(
        self,
        provider_kind: ProviderKind,
    ) -> Result<SandboxEnvironment, RunnerProductConfigError> {
        if self.keepalive_arguments.len() > MAX_KEEPALIVE_ARGUMENTS {
            return Err(RunnerProductConfigError::InvalidInventory);
        }
        let id = EnvironmentProfileId::new(self.id)
            .map_err(|_| RunnerProductConfigError::InvalidInventory)?;
        let digest = Sha256Digest::from_str(&self.manifest_sha256)
            .map_err(|_| RunnerProductConfigError::InvalidInventory)?;
        let attestation = EnvironmentProfile::new(id, digest);
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
        match provider_kind {
            ProviderKind::Podman => {
                let image = ImmutableImage::new(
                    self.image
                        .ok_or(RunnerProductConfigError::InvalidInventory)?,
                )
                .map_err(|_| RunnerProductConfigError::InvalidInventory)?;
                let keepalive_program = TargetPath::posix(
                    self.keepalive_program
                        .ok_or(RunnerProductConfigError::InvalidInventory)?,
                )
                .map_err(|_| RunnerProductConfigError::InvalidInventory)?;
                let keepalive = ExecutionArgv::new(keepalive_program, self.keepalive_arguments)
                    .map_err(|_| RunnerProductConfigError::InvalidInventory)?;
                let workspace = TargetPath::posix(self.workspace)
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
            ProviderKind::WindowsNative => {
                if self.image.is_some()
                    || self.keepalive_program.is_some()
                    || !self.keepalive_arguments.is_empty()
                    || self.workspace.contains('%')
                {
                    return Err(RunnerProductConfigError::InvalidInventory);
                }
                let workspace = TargetPath::windows(self.workspace)
                    .map_err(|_| RunnerProductConfigError::InvalidInventory)?;
                SandboxEnvironment::native(attestation, workspace, default_environment)
                    .map_err(|_| RunnerProductConfigError::InvalidInventory)
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPodmanProductConfig {
    binary: PathBuf,
    home: PathBuf,
    runtime_directory: PathBuf,
    approved_helper_directory: PathBuf,
    conmon_path: PathBuf,
    oci_runtime_path: PathBuf,
    init_path: PathBuf,
    seccomp_profile_path: PathBuf,
    job_container_engine: RawJobContainerEngine,
    #[serde(default)]
    map_github_server_to_host_gateway: bool,
    #[serde(default)]
    service_proxy_image: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWindowsNativeProductConfig {}

impl RawWindowsNativeProductConfig {
    fn validate(self) -> Result<WindowsNativeProductConfig, RunnerProductConfigError> {
        if std::env::consts::OS != "windows" {
            return Err(RunnerProductConfigError::InvalidProvider);
        }
        Ok(WindowsNativeProductConfig)
    }
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
        if std::env::consts::OS != "linux" {
            return Err(RunnerProductConfigError::InvalidProvider);
        }
        validate_absolute_path(&self.binary)
            .map_err(|_| RunnerProductConfigError::InvalidPodman)?;
        validate_absolute_path(&self.home).map_err(|_| RunnerProductConfigError::InvalidPodman)?;
        if [
            &self.runtime_directory,
            &self.approved_helper_directory,
            &self.conmon_path,
            &self.oci_runtime_path,
            &self.init_path,
            &self.seccomp_profile_path,
        ]
        .into_iter()
        .any(|path| validate_absolute_path(path).is_err())
            || !self
                .approved_helper_directory
                .ends_with(Path::new("usr/sbin"))
            || self
                .approved_helper_directory
                .to_str()
                .is_none_or(|path| path.contains(':') || path.chars().any(char::is_control))
        {
            return Err(RunnerProductConfigError::InvalidPodman);
        }
        automata_ci_sandbox_podman::PodmanBinary::new(self.binary.clone())
            .map_err(|_| RunnerProductConfigError::InvalidPodman)?;
        let github_server_host_gateway_alias = self
            .map_github_server_to_host_gateway
            .then(|| {
                let hostname = github_server_url
                    .host_str()
                    .ok_or(RunnerProductConfigError::InvalidPodman)?;
                automata_ci_sandbox_podman::PodmanHostGatewayAlias::new(hostname)
                    .map_err(|_| RunnerProductConfigError::InvalidPodman)
            })
            .transpose()?;
        let service_proxy_image = self
            .service_proxy_image
            .map(validate_service_proxy_image)
            .transpose()
            .map_err(|()| RunnerProductConfigError::InvalidPodman)?;
        Ok(PodmanProductConfig {
            binary: self.binary,
            home: self.home,
            runtime_directory: self.runtime_directory,
            approved_helper_directory: self.approved_helper_directory,
            conmon_path: self.conmon_path,
            oci_runtime_path: self.oci_runtime_path,
            init_path: self.init_path,
            seccomp_profile_path: self.seccomp_profile_path,
            job_container_engine: match self.job_container_engine {
                RawJobContainerEngine::Disabled => {
                    automata_ci_sandbox_podman::JobContainerEngine::Disabled
                }
                RawJobContainerEngine::AttemptScopedDockerApi => {
                    automata_ci_sandbox_podman::JobContainerEngine::AttemptScopedDockerApi
                }
            },
            github_server_host_gateway_alias,
            service_proxy_image,
        })
    }
}

fn validate_service_proxy_image(value: String) -> Result<ImmutableImage, ()> {
    let repository = value
        .rsplit_once("@sha256:")
        .map(|(repository, _)| repository);
    if repository.is_none_or(|repository| {
        repository
            .rsplit_once('/')
            .map_or(repository, |(_, name)| name)
            .contains(':')
    }) {
        return Err(());
    }
    ImmutableImage::new(value).map_err(|_| ())
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawNetworkPolicy {
    Disabled,
    PrivateEgress,
    Host,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawRootFilesystemPolicy {
    ReadOnly,
    Writable,
    Host,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawPrivilegePolicy {
    Unprivileged,
    Administrator,
    Host,
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
    fn validate(
        self,
        provider_kind: ProviderKind,
    ) -> Result<ExecutorProductConfig, RunnerProductConfigError> {
        let resources = self
            .resources
            .validate()
            .map_err(|_| RunnerProductConfigError::InvalidExecutor)?
            .execution;
        let network = match self.network {
            RawNetworkPolicy::Disabled => NetworkPolicy::Disabled,
            RawNetworkPolicy::PrivateEgress => NetworkPolicy::PrivateEgress,
            RawNetworkPolicy::Host => NetworkPolicy::Host,
        };
        let root_filesystem = match self.root_filesystem {
            RawRootFilesystemPolicy::ReadOnly => RootFilesystemPolicy::ReadOnly,
            RawRootFilesystemPolicy::Writable => RootFilesystemPolicy::Writable,
            RawRootFilesystemPolicy::Host => RootFilesystemPolicy::Host,
        };
        let privilege = match self.privilege {
            RawPrivilegePolicy::Unprivileged => SandboxPrivilegePolicy::Unprivileged,
            RawPrivilegePolicy::Administrator => SandboxPrivilegePolicy::Administrator,
            RawPrivilegePolicy::Host => SandboxPrivilegePolicy::Host,
        };
        if matches!(
            (provider_kind, network, root_filesystem, privilege),
            (ProviderKind::Podman, NetworkPolicy::Host, _, _,)
                | (ProviderKind::Podman, _, RootFilesystemPolicy::Host, _,)
                | (ProviderKind::Podman, _, _, SandboxPrivilegePolicy::Host)
        ) || (provider_kind == ProviderKind::WindowsNative
            && (network != NetworkPolicy::Host
                || root_filesystem != RootFilesystemPolicy::Host
                || privilege != SandboxPrivilegePolicy::Host))
        {
            return Err(RunnerProductConfigError::InvalidExecutor);
        }
        let default_step_timeout = Duration::from_secs(self.default_step_timeout_seconds);
        let parse_path = |value| provider_target_path(provider_kind, value);
        let runner_root = parse_path(self.runner_root)?;
        if target_is_root(&runner_root) {
            return Err(RunnerProductConfigError::InvalidExecutor);
        }
        let home = parse_path(self.home)?;
        let tool_cache = parse_path(self.tool_cache)?;
        let temp = parse_path(self.temp)?;
        let path_separator = match provider_kind {
            ProviderKind::Podman => ':',
            ProviderKind::WindowsNative => ';',
        };
        if target_is_root(&home)
            || target_is_root(&temp)
            || target_is_root(&tool_cache)
            || self.path.is_empty()
            || self.path.len() > 8_192
            || self.path.split(path_separator).any(|entry| {
                entry.is_empty() || provider_target_path(provider_kind, entry).is_err()
            })
        {
            return Err(RunnerProductConfigError::InvalidExecutor);
        }
        let toolchain = self.toolchain.validate(provider_kind)?;
        automata_ci_job_executor_github::GithubJobExecutorConfig::new(
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

fn provider_target_path(
    provider_kind: ProviderKind,
    value: impl Into<String>,
) -> Result<TargetPath, RunnerProductConfigError> {
    let value = value.into();
    if provider_kind == ProviderKind::WindowsNative && value.contains('%') {
        return Err(RunnerProductConfigError::InvalidExecutor);
    }
    match provider_kind {
        ProviderKind::Podman => TargetPath::posix(value),
        ProviderKind::WindowsNative => TargetPath::windows(value),
    }
    .map_err(|_| RunnerProductConfigError::InvalidExecutor)
}

fn target_is_root(path: &TargetPath) -> bool {
    match path.platform() {
        TargetPlatform::Posix => path.as_str() == "/",
        TargetPlatform::Windows => path.as_str().len() == 3 && path.as_str().ends_with("\\"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawToolchainConfig {
    bash: Option<String>,
    sh: Option<String>,
    python: Option<String>,
    pwsh: Option<String>,
    powershell: Option<String>,
    cmd: Option<String>,
    install: Option<String>,
    tar: Option<String>,
    sha256sum: Option<String>,
    node12: Option<String>,
    node16: Option<String>,
    node20: Option<String>,
    node24: Option<String>,
}

impl RawToolchainConfig {
    fn validate(
        self,
        provider_kind: ProviderKind,
    ) -> Result<ToolchainConfig, RunnerProductConfigError> {
        let path = |value: String| provider_target_path(provider_kind, value);
        let config = ToolchainConfig {
            bash: self.bash.map(&path).transpose()?,
            sh: self.sh.map(&path).transpose()?,
            python: self.python.map(&path).transpose()?,
            pwsh: self.pwsh.map(&path).transpose()?,
            powershell: self.powershell.map(&path).transpose()?,
            cmd: self.cmd.map(&path).transpose()?,
            install: self.install.map(&path).transpose()?,
            tar: self.tar.map(&path).transpose()?,
            sha256sum: self.sha256sum.map(&path).transpose()?,
            node12: self.node12.map(path).transpose()?,
            node16: self.node16.map(path).transpose()?,
            node20: self.node20.map(path).transpose()?,
            node24: self.node24.map(path).transpose()?,
        };
        let valid = match provider_kind {
            ProviderKind::Podman => {
                config.bash.is_some()
                    && config.sh.is_some()
                    && config.install.is_some()
                    && config.tar.is_some()
                    && config.sha256sum.is_some()
                    && config.powershell.is_none()
                    && config.cmd.is_none()
            }
            ProviderKind::WindowsNative => {
                config.bash.is_none()
                    && config.sh.is_none()
                    && config.pwsh.is_some()
                    && config.powershell.is_some()
                    && config.cmd.is_some()
                    && [
                        config.python.as_ref(),
                        config.pwsh.as_ref(),
                        config.powershell.as_ref(),
                        config.cmd.as_ref(),
                    ]
                    .into_iter()
                    .flatten()
                    .all(|path| {
                        !path
                            .as_str()
                            .split('\\')
                            .any(|segment| segment.eq_ignore_ascii_case("WindowsApps"))
                    })
                    && config.install.is_none()
                    && config.tar.is_none()
                    && config.sha256sum.is_none()
                    && config.node12.is_none()
                    && config.node16.is_none()
                    && config.node20.is_none()
                    && config.node24.is_none()
            }
        };
        valid
            .then_some(config)
            .ok_or(RunnerProductConfigError::InvalidExecutor)
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
            automata_ci_blob_s3::S3BlobStoreConfig::loopback_development(
                endpoint.clone(),
                self.region.clone(),
                self.bucket.clone(),
                self.prefix.clone(),
                operation_timeout,
            )
        } else {
            automata_ci_blob_s3::S3BlobStoreConfig::new(
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
        automata_ci_github::GithubTrustedOrigins::github_dot_com(&self.user_agent)
            .map_err(|_| RunnerProductConfigError::InvalidGithub)?;
        let server_url =
            validate_github_context_url(&self.server_url, self.allow_insecure_http, true)?;
        let api_url = validate_github_context_url(&self.api_url, self.allow_insecure_http, false)?;
        let graphql_url =
            validate_github_context_url(&self.graphql_url, self.allow_insecure_http, false)?;
        Ok(GithubProductConfig {
            user_agent: self.user_agent,
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
        "windows" => Ok(OperatingSystem::Windows),
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
