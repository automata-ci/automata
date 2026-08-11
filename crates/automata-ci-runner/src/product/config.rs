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
    SandboxPrivilegePolicy, TargetPath,
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
pub const RUNNER_PRODUCT_CONFIG_SCHEMA_VERSION: u16 = 2;
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
    sandbox: SandboxProductConfig,
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

    /// Returns the selected sandbox-provider product policy.
    #[must_use]
    pub const fn sandbox(&self) -> &SandboxProductConfig {
        &self.sandbox
    }

    /// Returns rootless-Podman host process policy when that provider is selected.
    #[must_use]
    pub const fn podman(&self) -> Option<&PodmanProductConfig> {
        match &self.sandbox {
            SandboxProductConfig::Podman(config) => Some(config),
            SandboxProductConfig::Kubernetes(_) => None,
        }
    }

    /// Returns Kubernetes sandbox policy when that provider is selected.
    #[must_use]
    pub const fn kubernetes(&self) -> Option<&KubernetesProductConfig> {
        match &self.sandbox {
            SandboxProductConfig::Podman(_) => None,
            SandboxProductConfig::Kubernetes(config) => Some(config),
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
            .field("sandbox", &self.sandbox)
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
    podman: Option<PathBuf>,
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

    /// Returns the rootless-Podman adapter state root.
    #[must_use]
    pub fn podman(&self) -> Option<&Path> {
        self.podman.as_deref()
    }
}

/// Mutually exclusive sandbox-provider product configuration.
#[derive(Clone, Debug)]
pub enum SandboxProductConfig {
    /// Execute jobs through the local rootless-Podman adapter.
    Podman(PodmanProductConfig),
    /// Execute jobs as Kubernetes Pods through the authenticated ambient client.
    Kubernetes(KubernetesProductConfig),
}

/// Validated Kubernetes product configuration and operator attestations.
#[derive(Clone, Debug)]
pub struct KubernetesProductConfig {
    adapter: automata_ci_sandbox_kubernetes::KubernetesSandboxConfig,
}

impl KubernetesProductConfig {
    /// Returns the secret-free adapter configuration used with the ambient Kubernetes client.
    #[must_use]
    pub const fn adapter(&self) -> &automata_ci_sandbox_kubernetes::KubernetesSandboxConfig {
        &self.adapter
    }
}

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
    resource_capacity: ResourceCapacity,
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

    /// Returns every configured per-job resource dimension.
    #[must_use]
    pub const fn resource_capacity(&self) -> ResourceCapacity {
        self.resource_capacity
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
    bash: TargetPath,
    sh: TargetPath,
    python: Option<TargetPath>,
    pwsh: Option<TargetPath>,
    install: TargetPath,
    tar: TargetPath,
    sha256sum: TargetPath,
    node12: Option<TargetPath>,
    node16: Option<TargetPath>,
    node20: Option<TargetPath>,
    node24: Option<TargetPath>,
}

impl ToolchainConfig {
    /// Returns the target path to Bash.
    #[must_use]
    pub const fn bash(&self) -> &TargetPath {
        &self.bash
    }

    /// Returns the target path to the POSIX shell.
    #[must_use]
    pub const fn sh(&self) -> &TargetPath {
        &self.sh
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

    /// Returns the target path to the installation utility.
    #[must_use]
    pub const fn install(&self) -> &TargetPath {
        &self.install
    }

    /// Returns the target path to the tar utility.
    #[must_use]
    pub const fn tar(&self) -> &TargetPath {
        &self.tar
    }

    /// Returns the target path to the SHA-256 hashing utility.
    #[must_use]
    pub const fn sha256sum(&self) -> &TargetPath {
        &self.sha256sum
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
    /// Exactly one supported sandbox provider was not selected.
    #[error("runner sandbox provider selection is invalid")]
    InvalidSandboxProvider,
    /// Kubernetes adapter policy or operator attestations are invalid.
    #[error("runner Kubernetes configuration is invalid")]
    InvalidKubernetes,
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
    kubernetes: Option<RawKubernetesProductConfig>,
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
        let kubernetes_selected = match (&self.podman, &self.kubernetes) {
            (Some(_), None) => false,
            (None, Some(_)) => true,
            _ => return Err(RunnerProductConfigError::InvalidSandboxProvider),
        };
        let control_endpoint = validate_control_endpoint(&self.control_endpoint)?;
        let state = self.state.validate(!kubernetes_selected)?;
        let tls = self.tls.validate()?;
        let spool = self.spool.validate()?;
        let executor = self.executor.validate(kubernetes_selected)?;
        let github = self.github.validate()?;
        let metrics = self
            .metrics
            .map(RawMetricsProductConfig::validate)
            .transpose()?;
        let sandbox = match (self.podman, self.kubernetes) {
            (Some(raw), None) => {
                let podman = raw.validate(github.server_url())?;
                let required_podman_state = required_podman_state_root(podman.runtime_directory());
                if state.podman().is_none_or(|configured| {
                    configured.as_os_str() != required_podman_state.as_os_str()
                }) {
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
                SandboxProductConfig::Podman(podman)
            }
            (None, Some(raw)) => SandboxProductConfig::Kubernetes(raw.validate(&executor)?),
            _ => return Err(RunnerProductConfigError::InvalidSandboxProvider),
        };
        let podman_features = match &sandbox {
            SandboxProductConfig::Podman(podman) => Some((
                podman.job_container_engine(),
                podman.service_proxy_image().is_some(),
            )),
            SandboxProductConfig::Kubernetes(_) => None,
        };
        let (inventory, environments) =
            self.inventory
                .validate(self.runner_id, &executor, podman_features)?;
        match &sandbox {
            SandboxProductConfig::Podman(_) => {
                if inventory.resources_per_job().ephemeral_disk_bytes() != 0
                    || inventory.resources_per_job().gpu_count() != 0
                {
                    return Err(RunnerProductConfigError::InvalidInventory);
                }
            }
            SandboxProductConfig::Kubernetes(kubernetes) => {
                if inventory.resources_per_job().ephemeral_disk_bytes() != 0
                    && !kubernetes.adapter.ephemeral_storage_enforced()
                {
                    return Err(RunnerProductConfigError::InvalidKubernetes);
                }
                if inventory.resources_per_job().gpu_count() != 0
                    && kubernetes.adapter.gpu_resource_name().is_none()
                {
                    return Err(RunnerProductConfigError::InvalidKubernetes);
                }
            }
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
            sandbox,
            executor,
            object_store,
            github,
            metrics,
        })
    }
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
}

impl RawStateRoots {
    fn validate(self, require_podman: bool) -> Result<StateRoots, RunnerProductConfigError> {
        if require_podman != self.podman.is_some() {
            return Err(RunnerProductConfigError::InvalidStateRoots);
        }
        let mut roots = vec![&self.journal, &self.spool];
        roots.extend(self.podman.iter());
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
        podman_features: Option<(automata_ci_sandbox_podman::JobContainerEngine, bool)>,
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
        if resources.capacity != executor.resource_capacity()
            || resources.execution != executor.resources()
        {
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
        let mut container_features = match podman_features.map(|features| features.0) {
            None | Some(automata_ci_sandbox_podman::JobContainerEngine::Disabled) => {
                BTreeSet::new()
            }
            Some(automata_ci_sandbox_podman::JobContainerEngine::AttemptScopedDockerApi) => {
                BTreeSet::from([ContainerFeature::DOCKER_COMPATIBLE_API])
            }
        };
        if podman_features.is_some_and(|features| features.1) {
            container_features.insert(ContainerFeature::SERVICE_CONTAINERS);
        }
        let inventory = RunnerCapabilities::new(runner_id, platform)
            .with_labels(labels)
            .with_groups(groups)
            .with_max_parallel_jobs(self.max_parallel_jobs)
            .map_err(|_| RunnerProductConfigError::InvalidInventory)?
            .with_resources_per_job(resources.capacity)
            .with_sandbox(sandbox)
            .with_containers(ContainerCapabilities::new(container_features))
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
    #[serde(default)]
    gpu_count: u16,
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
                self.gpu_count,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKubernetesProductConfig {
    namespace: String,
    guest_image: String,
    network_isolation_verified: bool,
    #[serde(default)]
    ephemeral_storage_enforcement_verified: bool,
    process_limit_enforcement: u32,
    #[serde(default)]
    gpu_resource_name: Option<String>,
    node_selector: BTreeMap<String, String>,
    #[serde(default)]
    runtime_class_name: Option<String>,
    #[serde(default = "default_kubernetes_run_as")]
    run_as_user: i64,
    #[serde(default = "default_kubernetes_run_as")]
    run_as_group: i64,
    #[serde(default = "default_kubernetes_operation_timeout_seconds")]
    operation_timeout_seconds: u64,
    #[serde(default = "default_kubernetes_readiness_timeout_seconds")]
    readiness_timeout_seconds: u64,
}

impl RawKubernetesProductConfig {
    fn validate(
        self,
        executor: &ExecutorProductConfig,
    ) -> Result<KubernetesProductConfig, RunnerProductConfigError> {
        if !self.network_isolation_verified
            || executor.network() != NetworkPolicy::Disabled
            || executor.privilege() != SandboxPrivilegePolicy::Unprivileged
            || self.process_limit_enforcement != executor.resources().pids()
            || executor.resources().memory_bytes()
                < automata_ci_sandbox_kubernetes::MINIMUM_KUBERNETES_SANDBOX_MEMORY_BYTES
        {
            return Err(RunnerProductConfigError::InvalidKubernetes);
        }
        let guest_image = ImmutableImage::new(self.guest_image)
            .map_err(|_| RunnerProductConfigError::InvalidKubernetes)?;
        let mut adapter = automata_ci_sandbox_kubernetes::KubernetesSandboxConfig::new(
            self.namespace,
            guest_image,
            automata_ci_sandbox_kubernetes::VerifiedNetworkIsolation,
        )
        .map_err(|_| RunnerProductConfigError::InvalidKubernetes)?
        .with_timeouts(
            Duration::from_secs(self.operation_timeout_seconds),
            Duration::from_secs(self.readiness_timeout_seconds),
        )
        .map_err(|_| RunnerProductConfigError::InvalidKubernetes)?
        .with_run_as(self.run_as_user, self.run_as_group)
        .map_err(|_| RunnerProductConfigError::InvalidKubernetes)?
        .with_verified_process_limit(
            automata_ci_sandbox_kubernetes::VerifiedProcessLimitEnforcement::new(
                self.process_limit_enforcement,
            )
            .map_err(|_| RunnerProductConfigError::InvalidKubernetes)?,
        )
        .with_node_selector(self.node_selector)
        .map_err(|_| RunnerProductConfigError::InvalidKubernetes)?;
        if self.ephemeral_storage_enforcement_verified {
            adapter = adapter.with_verified_ephemeral_storage(
                automata_ci_sandbox_kubernetes::VerifiedEphemeralStorageEnforcement,
            );
        }
        if let Some(resource_name) = self.gpu_resource_name {
            adapter = adapter
                .with_gpu_resource_name(resource_name)
                .map_err(|_| RunnerProductConfigError::InvalidKubernetes)?;
        }
        if let Some(runtime_class_name) = self.runtime_class_name {
            adapter = adapter
                .with_runtime_class_name(runtime_class_name)
                .map_err(|_| RunnerProductConfigError::InvalidKubernetes)?;
        }
        Ok(KubernetesProductConfig { adapter })
    }
}

const fn default_kubernetes_run_as() -> i64 {
    65_532
}

const fn default_kubernetes_operation_timeout_seconds() -> u64 {
    30
}

const fn default_kubernetes_readiness_timeout_seconds() -> u64 {
    300
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
    fn validate(
        self,
        allow_extended_resources: bool,
    ) -> Result<ExecutorProductConfig, RunnerProductConfigError> {
        let validated_resources = self
            .resources
            .validate()
            .map_err(|_| RunnerProductConfigError::InvalidExecutor)?;
        if !allow_extended_resources
            && (validated_resources.capacity.ephemeral_disk_bytes() != 0
                || validated_resources.capacity.gpu_count() != 0)
        {
            return Err(RunnerProductConfigError::InvalidExecutor);
        }
        let resources = validated_resources.execution;
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
            resource_capacity: validated_resources.capacity,
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
    python: Option<String>,
    pwsh: Option<String>,
    install: String,
    tar: String,
    sha256sum: String,
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
            python: self.python.map(&path).transpose()?,
            pwsh: self.pwsh.map(&path).transpose()?,
            install: path(self.install)?,
            tar: path(self.tar)?,
            sha256sum: path(self.sha256sum)?,
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
