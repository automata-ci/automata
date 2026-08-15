use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr as _,
    time::Duration,
};

use automata_ci_blob_s3::S3BlobStoreConfig;
use automata_ci_core::{
    Architecture, ContainerCapabilities, ContainerFeature, EnvironmentProfile,
    EnvironmentProfileId, IsolationLevel, OperatingSystem, ResourceCapacity, RunnerCapabilities,
    RunnerFeature, RunnerGroup, RunnerId, RunnerLabel, RunnerPlatform, SandboxCapabilities,
    SandboxFeature, Sha256Digest,
};
use automata_ci_execution::{
    EnvironmentName, EnvironmentValue, EnvironmentVariable, ExecutionArgv, ExecutionEnvironment,
    ImmutableImage, NetworkPolicy, ResourceLimits, RootFilesystemPolicy, SandboxEnvironment,
    SandboxLaunch, SandboxPrivilegePolicy, TargetPath, TargetPlatform,
};
use automata_ci_github::{
    GithubHttpConfigurationError, GithubHttpEndpoint, GithubHttpLimits, GithubTrustedOrigins,
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
use super::spool_crypto::MAX_DECRYPT_ONLY_CONTENT_KEYS;

/// Current on-disk runner product configuration schema.
pub const RUNNER_PRODUCT_CONFIG_SCHEMA_VERSION: u16 = 4;
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

    /// Returns the non-overlapping durable state roots for the selected provider.
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

    /// Returns the selected execution-provider policy.
    #[must_use]
    pub const fn provider(&self) -> &RunnerProviderConfig {
        &self.provider
    }

    /// Returns rootless-Podman host process policy when selected.
    #[must_use]
    pub const fn podman(&self) -> Option<&PodmanProductConfig> {
        match &self.provider {
            RunnerProviderConfig::Podman(config) => Some(config),
            RunnerProviderConfig::Kubernetes(_)
            | RunnerProviderConfig::WindowsHyperV(_)
            | RunnerProviderConfig::MacosVirtualization(_) => None,
        }
    }

    /// Returns Kubernetes sandbox policy when selected.
    #[must_use]
    pub const fn kubernetes(&self) -> Option<&KubernetesProductConfig> {
        match &self.provider {
            RunnerProviderConfig::Kubernetes(config) => Some(config),
            RunnerProviderConfig::Podman(_)
            | RunnerProviderConfig::WindowsHyperV(_)
            | RunnerProviderConfig::MacosVirtualization(_) => None,
        }
    }

    /// Returns Hyper-V-isolated Windows container policy when selected.
    #[must_use]
    pub const fn windows_hyperv(&self) -> Option<&WindowsHyperVProductConfig> {
        match &self.provider {
            RunnerProviderConfig::WindowsHyperV(config) => Some(config),
            RunnerProviderConfig::Podman(_)
            | RunnerProviderConfig::Kubernetes(_)
            | RunnerProviderConfig::MacosVirtualization(_) => None,
        }
    }

    /// Returns disposable macOS virtual-machine provider policy when selected.
    #[must_use]
    pub const fn macos_virtualization(&self) -> Option<&MacosVirtualizationProductConfig> {
        match &self.provider {
            RunnerProviderConfig::MacosVirtualization(config) => Some(config),
            RunnerProviderConfig::Podman(_)
            | RunnerProviderConfig::Kubernetes(_)
            | RunnerProviderConfig::WindowsHyperV(_) => None,
        }
    }

    /// Returns per-job resource, isolation, path, and tool policy.
    #[must_use]
    pub const fn executor(&self) -> &ExecutorProductConfig {
        &self.executor
    }

    /// Returns immutable action-bundle object-store policy and credential sources.
    #[must_use]
    pub(crate) const fn object_store(&self) -> &ObjectStoreProductConfig {
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
    podman: Option<PathBuf>,
    windows_hyperv: Option<PathBuf>,
    macos_virtualization: Option<PathBuf>,
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

    /// Returns the selected local execution provider's durable state root.
    #[must_use]
    pub fn provider(&self) -> Option<&Path> {
        self.podman
            .as_deref()
            .or(self.windows_hyperv.as_deref())
            .or(self.macos_virtualization.as_deref())
    }

    /// Returns the rootless-Podman durable state root when selected.
    #[must_use]
    pub fn podman(&self) -> Option<&Path> {
        self.podman.as_deref()
    }

    /// Returns the Hyper-V Windows provider state root when selected.
    #[must_use]
    pub fn windows_hyperv(&self) -> Option<&Path> {
        self.windows_hyperv.as_deref()
    }

    /// Returns the macOS virtual-machine durable state root when selected.
    #[must_use]
    pub fn macos_virtualization(&self) -> Option<&Path> {
        self.macos_virtualization.as_deref()
    }
}

/// Validated execution-provider selection for one runner process.
#[derive(Clone, Debug)]
pub enum RunnerProviderConfig {
    /// Rootless Podman on a dedicated Linux execution host.
    Podman(PodmanProductConfig),
    /// Authenticated Kubernetes Pods on a dedicated Linux execution host.
    Kubernetes(KubernetesProductConfig),
    /// Fresh Hyper-V-isolated Windows containers.
    WindowsHyperV(WindowsHyperVProductConfig),
    /// Disposable Virtualization.framework machines for untrusted macOS jobs.
    MacosVirtualization(MacosVirtualizationProductConfig),
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

/// Pinned Hyper-V Windows container runtime and guest-agent configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsHyperVProductConfig {
    runtime_executable: PathBuf,
    runtime_sha256: Sha256Digest,
    guest_agent_path: TargetPath,
    operation_timeout: Duration,
}

impl WindowsHyperVProductConfig {
    /// Returns the exact pinned Windows container CLI executable.
    #[must_use]
    pub fn runtime_executable(&self) -> &Path {
        &self.runtime_executable
    }

    /// Returns the expected runtime executable digest.
    #[must_use]
    pub const fn runtime_sha256(&self) -> Sha256Digest {
        self.runtime_sha256
    }

    /// Returns the exact in-image guest-agent executable path.
    #[must_use]
    pub const fn guest_agent_path(&self) -> &TargetPath {
        &self.guest_agent_path
    }

    /// Returns the container lifecycle operation timeout.
    #[must_use]
    pub const fn operation_timeout(&self) -> Duration {
        self.operation_timeout
    }
}

/// Verified helper and immutable template policy for macOS virtual machines.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacosVirtualizationProductConfig {
    helper_executable: PathBuf,
    helper_sha256: Sha256Digest,
    helper_code_requirement: String,
    template_manifest: PathBuf,
    template_manifest_sha256: Sha256Digest,
    storage_volume_uuid: String,
    storage_quota_bytes: u64,
    boot_timeout: Duration,
    stop_timeout: Duration,
}

impl MacosVirtualizationProductConfig {
    /// Returns the exact signed Swift helper executable.
    #[must_use]
    pub fn helper_executable(&self) -> &Path {
        &self.helper_executable
    }

    /// Returns the pinned helper content digest.
    #[must_use]
    pub const fn helper_sha256(&self) -> Sha256Digest {
        self.helper_sha256
    }

    /// Returns the code-signing requirement applied before every helper launch.
    #[must_use]
    pub fn helper_code_requirement(&self) -> &str {
        &self.helper_code_requirement
    }

    /// Returns the immutable VM-template manifest path.
    #[must_use]
    pub fn template_manifest(&self) -> &Path {
        &self.template_manifest
    }

    /// Returns the pinned VM-template manifest digest.
    #[must_use]
    pub const fn template_manifest_sha256(&self) -> Sha256Digest {
        self.template_manifest_sha256
    }

    /// Returns the exact dedicated APFS volume UUID used by templates and clones.
    #[must_use]
    pub fn storage_volume_uuid(&self) -> &str {
        &self.storage_volume_uuid
    }

    /// Returns the exact required APFS volume quota.
    #[must_use]
    pub const fn storage_quota_bytes(&self) -> u64 {
        self.storage_quota_bytes
    }

    /// Returns the maximum cold-boot and guest-handshake duration.
    #[must_use]
    pub const fn boot_timeout(&self) -> Duration {
        self.boot_timeout
    }

    /// Returns the graceful-stop window before destructive VM termination.
    #[must_use]
    pub const fn stop_timeout(&self) -> Duration {
        self.stop_timeout
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
    paths: Box<PodmanProductPaths>,
    job_container_engine: automata_ci_sandbox_podman::JobContainerEngine,
    github_server_host_gateway_alias: Option<automata_ci_sandbox_podman::PodmanHostGatewayAlias>,
    service_proxy_image: Option<ImmutableImage>,
    buildkit_runtime: Option<automata_ci_sandbox_podman::BuildKitRuntime>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PodmanProductPaths {
    binary: PathBuf,
    home: PathBuf,
    runtime_directory: PathBuf,
    approved_helper_directory: PathBuf,
    conmon_path: PathBuf,
    oci_runtime_path: PathBuf,
    init_path: PathBuf,
    seccomp_profile_path: PathBuf,
}

impl PodmanProductConfig {
    /// Returns the validated absolute Podman executable path.
    #[must_use]
    pub fn binary(&self) -> &Path {
        &self.paths.binary
    }

    /// Returns the absolute home directory supplied to the Podman process.
    #[must_use]
    pub fn home(&self) -> &Path {
        &self.paths.home
    }

    /// Returns the required absolute dedicated rootless-runtime mountpoint.
    #[must_use]
    pub fn runtime_directory(&self) -> &Path {
        &self.paths.runtime_directory
    }

    /// Returns the sole administrator-controlled helper directory supplied as `PATH`.
    #[must_use]
    pub fn approved_helper_directory(&self) -> &Path {
        &self.paths.approved_helper_directory
    }

    /// Returns the exact administrator-controlled conmon executable.
    #[must_use]
    pub fn conmon_path(&self) -> &Path {
        &self.paths.conmon_path
    }

    /// Returns the exact administrator-controlled OCI runtime executable.
    #[must_use]
    pub fn oci_runtime_path(&self) -> &Path {
        &self.paths.oci_runtime_path
    }

    /// Returns the exact administrator-controlled container init executable.
    #[must_use]
    pub fn init_path(&self) -> &Path {
        &self.paths.init_path
    }

    /// Returns the exact administrator-controlled seccomp profile.
    #[must_use]
    pub fn seccomp_profile_path(&self) -> &Path {
        &self.paths.seccomp_profile_path
    }

    /// Returns whether jobs receive an attempt-scoped Docker-compatible API.
    #[must_use]
    pub const fn job_container_engine(&self) -> automata_ci_sandbox_podman::JobContainerEngine {
        self.job_container_engine
    }

    /// Exact `github.server_url` hostname and port mapped to the Podman host
    /// gateway when the deployment explicitly opts into local-host routing.
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

    /// Returns the optional immutable `BuildKit` runtime admitted for the
    /// attempt-scoped Docker-compatible API.
    #[must_use]
    pub const fn buildkit_runtime(&self) -> Option<&automata_ci_sandbox_podman::BuildKitRuntime> {
        self.buildkit_runtime.as_ref()
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObjectStoreProductConfig {
    store_config: S3BlobStoreConfig,
    tls_trust: ObjectStoreTlsTrust,
    access_key_id: SecretSource,
    secret_access_key: SecretSource,
    session_token: Option<SecretSource>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ObjectStoreTlsTrust {
    WebPki,
    PrivateCa { certificate_source: SecretSource },
}

impl ObjectStoreProductConfig {
    pub(crate) const fn store_config(&self) -> &S3BlobStoreConfig {
        &self.store_config
    }

    pub(crate) const fn tls_trust(&self) -> &ObjectStoreTlsTrust {
        &self.tls_trust
    }

    pub(crate) const fn access_key_id(&self) -> &SecretSource {
        &self.access_key_id
    }

    pub(crate) const fn secret_access_key(&self) -> &SecretSource {
        &self.secret_access_key
    }

    pub(crate) const fn session_token(&self) -> Option<&SecretSource> {
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

    pub(crate) fn http_endpoint(&self) -> Result<GithubHttpEndpoint, GithubHttpConfigurationError> {
        if self.allow_insecure_http {
            if self
                .server_url
                .host_str()
                .is_some_and(|host| host.to_ascii_lowercase().ends_with(".invalid"))
            {
                return GithubHttpEndpoint::new_for_mapped_emulator(
                    self.server_url.clone(),
                    self.api_url.clone(),
                    &self.user_agent,
                    GithubHttpLimits::default(),
                );
            }
            return GithubHttpEndpoint::new_for_loopback_emulator(
                self.server_url.clone(),
                self.api_url.clone(),
                &self.user_agent,
                GithubHttpLimits::default(),
            );
        }
        GithubHttpEndpoint::new(GithubTrustedOrigins::new(
            self.server_url.clone(),
            self.api_url.clone(),
            &self.user_agent,
            GithubHttpLimits::default(),
        )?)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProviderKind {
    Podman,
    Kubernetes,
    WindowsHyperV,
    MacosVirtualization,
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
    #[serde(default)]
    windows_hyperv: Option<RawWindowsHyperVProductConfig>,
    #[serde(default)]
    macos_virtualization: Option<RawMacosVirtualizationProductConfig>,
    executor: RawExecutorProductConfig,
    object_store: RawObjectStoreProductConfig,
    github: RawGithubProductConfig,
    #[serde(default)]
    metrics: Option<RawMetricsProductConfig>,
}

impl RawRunnerProductConfig {
    #[allow(clippy::too_many_lines)] // Validation binds the complete closed product document.
    fn validate(self) -> Result<RunnerProductConfig, RunnerProductConfigError> {
        if self.schema_version != RUNNER_PRODUCT_CONFIG_SCHEMA_VERSION {
            return Err(RunnerProductConfigError::UnsupportedSchema);
        }
        let provider_kind = match (
            &self.podman,
            &self.kubernetes,
            &self.windows_hyperv,
            &self.macos_virtualization,
        ) {
            (Some(_), None, None, None) => ProviderKind::Podman,
            (None, Some(_), None, None) => ProviderKind::Kubernetes,
            (None, None, Some(_), None) => ProviderKind::WindowsHyperV,
            (None, None, None, Some(_)) => ProviderKind::MacosVirtualization,
            _ => return Err(RunnerProductConfigError::InvalidProvider),
        };
        let control_endpoint = validate_control_endpoint(&self.control_endpoint)?;
        let state = self.state.validate(provider_kind)?;
        let tls = self.tls.validate()?;
        let spool = self.spool.validate()?;
        let github = self.github.validate()?;
        let metrics = self
            .metrics
            .map(RawMetricsProductConfig::validate)
            .transpose()?;
        let executor = self.executor.validate(provider_kind)?;
        let provider = match (
            self.podman,
            self.kubernetes,
            self.windows_hyperv,
            self.macos_virtualization,
        ) {
            (Some(raw), None, None, None) => {
                RunnerProviderConfig::Podman(raw.validate(github.server_url())?)
            }
            (None, Some(raw), None, None) => {
                RunnerProviderConfig::Kubernetes(raw.validate(&executor)?)
            }
            (None, None, Some(raw), None) => RunnerProviderConfig::WindowsHyperV(raw.validate()?),
            (None, None, None, Some(raw)) => {
                RunnerProviderConfig::MacosVirtualization(raw.validate()?)
            }
            _ => return Err(RunnerProductConfigError::InvalidProvider),
        };
        let mapped_github_transport = is_mapped_github_transport(github.server_url());
        let podman_gateway_enabled = matches!(
            &provider,
            RunnerProviderConfig::Podman(podman)
                if podman.github_server_host_gateway_alias().is_some()
        );
        if mapped_github_transport != podman_gateway_enabled {
            return Err(RunnerProductConfigError::InvalidGithub);
        }
        if mapped_github_transport && executor.network() == NetworkPolicy::Disabled {
            return Err(RunnerProductConfigError::InvalidGithub);
        }
        if let RunnerProviderConfig::Podman(podman) = &provider {
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
        }
        let (job_container_engine, service_proxy_configured, buildkit_configured) = match &provider
        {
            RunnerProviderConfig::Podman(podman) => (
                podman.job_container_engine(),
                podman.service_proxy_image().is_some(),
                podman.buildkit_runtime().is_some(),
            ),
            RunnerProviderConfig::Kubernetes(_)
            | RunnerProviderConfig::WindowsHyperV(_)
            | RunnerProviderConfig::MacosVirtualization(_) => (
                automata_ci_sandbox_podman::JobContainerEngine::Disabled,
                false,
                false,
            ),
        };
        let (inventory, environments) = self.inventory.validate(
            self.runner_id,
            &executor,
            provider_kind,
            job_container_engine,
            service_proxy_configured,
            buildkit_configured,
        )?;
        if let RunnerProviderConfig::MacosVirtualization(macos) = &provider {
            let roots = [state.journal().as_path(), state.spool().as_path()]
                .into_iter()
                .chain(state.macos_virtualization());
            if environments.len() != 1
                || environments.values().any(|environment| {
                    !matches!(
                        environment.launch(),
                        automata_ci_execution::SandboxLaunch::VirtualMachine {
                            template_manifest
                        } if *template_manifest == macos.template_manifest_sha256()
                    )
                })
                || roots.into_iter().any(|root| {
                    macos.helper_executable().starts_with(root)
                        || macos.template_manifest().starts_with(root)
                })
            {
                return Err(RunnerProductConfigError::InvalidProvider);
            }
        }
        match &provider {
            RunnerProviderConfig::Podman(_)
            | RunnerProviderConfig::WindowsHyperV(_)
            | RunnerProviderConfig::MacosVirtualization(_) => {
                if inventory.resources_per_job().ephemeral_disk_bytes() != 0
                    || inventory.resources_per_job().gpu_count() != 0
                {
                    return Err(RunnerProductConfigError::InvalidInventory);
                }
            }
            RunnerProviderConfig::Kubernetes(kubernetes) => {
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
        if matches!(&provider, RunnerProviderConfig::MacosVirtualization(_))
            && !valid_macos_provider_topology(&state, &executor, &environments)
        {
            return Err(RunnerProductConfigError::InvalidInventory);
        }
        if let RunnerProviderConfig::WindowsHyperV(windows) = &provider
            && !valid_windows_hyperv_topology(&state, &executor, &environments, windows)
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

fn valid_macos_provider_topology(
    state: &StateRoots,
    executor: &ExecutorProductConfig,
    environments: &BTreeMap<EnvironmentProfile, SandboxEnvironment>,
) -> bool {
    if state.macos_virtualization().is_none() {
        return false;
    }
    if executor.runner_root().platform() != TargetPlatform::Posix {
        return false;
    }
    let runner_root = Path::new(executor.runner_root().as_str());
    environments.values().all(|environment| {
        let workspace = Path::new(environment.workspace().as_str());
        environment.workspace().platform() == TargetPlatform::Posix
            && !workspace.starts_with(runner_root)
            && !runner_root.starts_with(workspace)
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
    windows_hyperv: Option<PathBuf>,
    #[serde(default)]
    macos_virtualization: Option<PathBuf>,
}

impl RawStateRoots {
    fn validate(self, provider_kind: ProviderKind) -> Result<StateRoots, RunnerProductConfigError> {
        let provider = match (
            provider_kind,
            self.podman.as_ref(),
            self.windows_hyperv.as_ref(),
            self.macos_virtualization.as_ref(),
        ) {
            (ProviderKind::Podman, Some(provider), None, None)
            | (ProviderKind::WindowsHyperV, None, Some(provider), None)
            | (ProviderKind::MacosVirtualization, None, None, Some(provider)) => Some(provider),
            (ProviderKind::Kubernetes, None, None, None) => None,
            _ => return Err(RunnerProductConfigError::InvalidStateRoots),
        };
        let mut roots = vec![&self.journal, &self.spool];
        roots.extend(provider);
        let invalid_path = roots
            .iter()
            .any(|path| validate_absolute_path(path).is_err());
        let overlap = match provider_kind {
            ProviderKind::Podman | ProviderKind::Kubernetes | ProviderKind::MacosVirtualization => {
                roots.iter().enumerate().any(|(left_index, left)| {
                    roots.iter().enumerate().any(|(right_index, right)| {
                        left_index != right_index
                            && (left.starts_with(right.as_path())
                                || right.starts_with(left.as_path()))
                    })
                })
            }
            ProviderKind::WindowsHyperV => {
                let normalized = roots
                    .iter()
                    .map(|path| {
                        let path = path.to_str()?;
                        if !valid_literal_windows_path(path, false) {
                            return None;
                        }
                        Some(path.trim_end_matches('\\').to_ascii_lowercase())
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
            podman: self.podman,
            windows_hyperv: self.windows_hyperv,
            macos_virtualization: self.macos_virtualization,
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

fn valid_windows_hyperv_topology(
    state: &StateRoots,
    executor: &ExecutorProductConfig,
    environments: &BTreeMap<EnvironmentProfile, SandboxEnvironment>,
    windows: &WindowsHyperVProductConfig,
) -> bool {
    if state.windows_hyperv().is_none()
        || executor.runner_root().platform() != TargetPlatform::Windows
    {
        return false;
    }
    let runner_root = executor
        .runner_root()
        .as_str()
        .trim_end_matches('\\')
        .to_ascii_lowercase();
    let protected_paths = [
        Some(executor.runner_root()),
        Some(executor.home()),
        Some(executor.temp()),
        Some(executor.tool_cache()),
        Some(windows.guest_agent_path()),
        executor.toolchain().bash(),
        executor.toolchain().sh(),
        executor.toolchain().python(),
        executor.toolchain().pwsh(),
        executor.toolchain().powershell(),
        executor.toolchain().cmd(),
        executor.toolchain().install(),
        executor.toolchain().tar(),
        executor.toolchain().sha256sum(),
        executor.toolchain().node12(),
        executor.toolchain().node16(),
        executor.toolchain().node20(),
        executor.toolchain().node24(),
    ]
    .into_iter()
    .flatten()
    .map(|path| path.as_str().trim_end_matches('\\').to_ascii_lowercase())
    .collect::<Vec<_>>();
    environments.values().all(|environment| {
        let SandboxLaunch::WindowsHyperVContainer { keepalive, .. } = environment.launch() else {
            return false;
        };
        let workspace = environment
            .workspace()
            .as_str()
            .trim_end_matches('\\')
            .to_ascii_lowercase();
        environment.workspace().platform() == TargetPlatform::Windows
            && keepalive
                .program()
                .as_str()
                .eq_ignore_ascii_case(windows.guest_agent_path().as_str())
            && keepalive.arguments() == ["keepalive"]
            && !windows_roots_overlap(&runner_root, &workspace)
            && protected_paths
                .iter()
                .all(|protected| !windows_roots_overlap(&workspace, protected))
    })
}

fn valid_literal_windows_path(value: &str, executable: bool) -> bool {
    if value.len() < 4
        || !value.is_ascii()
        || value.contains('~')
        || value.contains(['%', '"'])
        || value.chars().any(char::is_control)
        || TargetPath::windows(value.to_owned()).is_err()
    {
        return false;
    }
    let components = value[3..]
        .split('\\')
        .filter(|component| !component.is_empty());
    let mut normal_components = 0_usize;
    for component in components {
        let stem = component.split('.').next().unwrap_or(component);
        if component.ends_with([' ', '.'])
            || component.contains(':')
            || windows_component_is_reserved(stem)
        {
            return false;
        }
        normal_components += 1;
    }
    normal_components > usize::from(executable)
        && (!executable
            || value
                .rsplit('\\')
                .next()
                .is_some_and(|name| name.to_ascii_lowercase().ends_with(".exe")))
}

fn windows_component_is_reserved(component: &str) -> bool {
    let component = component.to_ascii_uppercase();
    matches!(component.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$")
        || component
            .strip_prefix("COM")
            .or_else(|| component.strip_prefix("LPT"))
            .is_some_and(|suffix| suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9'))
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
        if self.decrypt_only.len() > MAX_DECRYPT_ONLY_CONTENT_KEYS {
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
        buildkit_configured: bool,
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
            || (provider_kind == ProviderKind::MacosVirtualization
                && self.environment_profiles.len() != 1)
            || (provider_kind == ProviderKind::MacosVirtualization && self.max_parallel_jobs != 1)
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
            let environment = raw.validate(provider_kind)?;
            if environments
                .insert(environment.attestation().clone(), environment)
                .is_some()
            {
                return Err(RunnerProductConfigError::InvalidInventory);
            }
        }
        if provider_kind == ProviderKind::WindowsHyperV
            && environments.values().any(|environment| {
                !valid_windows_environment(environment.default_environment(), executor)
            })
        {
            return Err(RunnerProductConfigError::InvalidInventory);
        }
        let host_operating_system = host_operating_system()?;
        if !matches!(
            (provider_kind, &host_operating_system),
            (
                ProviderKind::Podman | ProviderKind::Kubernetes,
                OperatingSystem::Linux
            ) | (ProviderKind::WindowsHyperV, OperatingSystem::Windows)
                | (ProviderKind::MacosVirtualization, OperatingSystem::Macos)
        ) {
            return Err(RunnerProductConfigError::InvalidProvider);
        }
        let host_architecture = host_architecture()?;
        if provider_kind == ProviderKind::MacosVirtualization
            && (host_architecture != Architecture::Aarch64
                || resources.capacity.cpu_millis() % 1_000 != 0)
        {
            return Err(RunnerProductConfigError::InvalidProvider);
        }
        let platform = RunnerPlatform::new(host_operating_system, host_architecture);
        let (sandbox, container_features, runner_features) = provider_capabilities(
            provider_kind,
            executor,
            job_container_engine,
            service_proxy_configured,
            buildkit_configured,
        );
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

fn provider_capabilities(
    provider_kind: ProviderKind,
    executor: &ExecutorProductConfig,
    job_container_engine: automata_ci_sandbox_podman::JobContainerEngine,
    service_proxy_configured: bool,
    buildkit_configured: bool,
) -> (
    SandboxCapabilities,
    BTreeSet<ContainerFeature>,
    BTreeSet<RunnerFeature>,
) {
    match provider_kind {
        ProviderKind::Podman | ProviderKind::Kubernetes => {
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
            if buildkit_configured {
                container_features.insert(ContainerFeature::BUILDKIT);
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
        ProviderKind::WindowsHyperV => (
            SandboxCapabilities::new(
                IsolationLevel::VirtualMachine,
                [
                    SandboxFeature::CLEAN_WORKSPACE,
                    SandboxFeature::NETWORK_ISOLATION,
                    SandboxFeature::WINDOWS_HYPERV_CONTAINER,
                ],
            ),
            BTreeSet::new(),
            BTreeSet::from([RunnerFeature::SHELL_STEPS, RunnerFeature::COMMAND_FILES]),
        ),
        ProviderKind::MacosVirtualization => (
            SandboxCapabilities::new(
                IsolationLevel::VirtualMachine,
                [
                    SandboxFeature::CLEAN_WORKSPACE,
                    SandboxFeature::NETWORK_ISOLATION,
                ],
            ),
            BTreeSet::new(),
            BTreeSet::from([RunnerFeature::SHELL_STEPS, RunnerFeature::COMMAND_FILES]),
        ),
    }
}

fn valid_windows_environment(
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
        && ["TEMP", "TMP"]
            .into_iter()
            .all(|name| value(name).is_some_and(|path| windows_path_matches(path, executor.temp())))
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
            ProviderKind::Podman | ProviderKind::Kubernetes => {
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
            ProviderKind::WindowsHyperV => {
                let keepalive_program = self
                    .keepalive_program
                    .ok_or(RunnerProductConfigError::InvalidInventory)?;
                if !valid_literal_windows_path(&self.workspace, false)
                    || !valid_literal_windows_path(&keepalive_program, true)
                {
                    return Err(RunnerProductConfigError::InvalidInventory);
                }
                let image = ImmutableImage::new(
                    self.image
                        .ok_or(RunnerProductConfigError::InvalidInventory)?,
                )
                .map_err(|_| RunnerProductConfigError::InvalidInventory)?;
                let keepalive_program = TargetPath::windows(keepalive_program)
                    .map_err(|_| RunnerProductConfigError::InvalidInventory)?;
                let keepalive = ExecutionArgv::new(keepalive_program, self.keepalive_arguments)
                    .map_err(|_| RunnerProductConfigError::InvalidInventory)?;
                let workspace = TargetPath::windows(self.workspace)
                    .map_err(|_| RunnerProductConfigError::InvalidInventory)?;
                SandboxEnvironment::windows_hyperv_container(
                    attestation,
                    image,
                    keepalive,
                    workspace,
                    default_environment,
                )
                .map_err(|_| RunnerProductConfigError::InvalidInventory)
            }
            ProviderKind::MacosVirtualization => {
                if self.image.is_some()
                    || self.keepalive_program.is_some()
                    || !self.keepalive_arguments.is_empty()
                {
                    return Err(RunnerProductConfigError::InvalidInventory);
                }
                let workspace = TargetPath::posix(self.workspace)
                    .map_err(|_| RunnerProductConfigError::InvalidInventory)?;
                SandboxEnvironment::virtual_machine(
                    attestation,
                    digest,
                    workspace,
                    default_environment,
                )
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
    #[serde(default)]
    buildkit_runtime_image: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWindowsHyperVProductConfig {
    runtime_executable: PathBuf,
    runtime_sha256: String,
    guest_agent_path: String,
    operation_timeout_seconds: u64,
}

impl RawWindowsHyperVProductConfig {
    fn validate(self) -> Result<WindowsHyperVProductConfig, RunnerProductConfigError> {
        if std::env::consts::OS != "windows" {
            return Err(RunnerProductConfigError::InvalidProvider);
        }
        if validate_absolute_path(&self.runtime_executable).is_err()
            || self.runtime_executable.to_str().is_none_or(|path| {
                !valid_literal_windows_path(path, true)
                    || path
                        .rsplit('\\')
                        .next()
                        .is_none_or(|name| !name.eq_ignore_ascii_case("docker.exe"))
            })
        {
            return Err(RunnerProductConfigError::InvalidProvider);
        }
        let runtime_sha256 = Sha256Digest::from_str(&self.runtime_sha256)
            .map_err(|_| RunnerProductConfigError::InvalidProvider)?;
        if !valid_literal_windows_path(&self.guest_agent_path, true) {
            return Err(RunnerProductConfigError::InvalidProvider);
        }
        let guest_agent_path = TargetPath::windows(self.guest_agent_path)
            .map_err(|_| RunnerProductConfigError::InvalidProvider)?;
        let operation_timeout = Duration::from_secs(self.operation_timeout_seconds);
        if operation_timeout.is_zero() || operation_timeout > Duration::from_mins(10) {
            return Err(RunnerProductConfigError::InvalidProvider);
        }
        Ok(WindowsHyperVProductConfig {
            runtime_executable: self.runtime_executable,
            runtime_sha256,
            guest_agent_path,
            operation_timeout,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMacosVirtualizationProductConfig {
    helper_executable: PathBuf,
    helper_sha256: String,
    helper_code_requirement: String,
    template_manifest: PathBuf,
    template_manifest_sha256: String,
    storage_volume_uuid: String,
    storage_quota_bytes: u64,
    boot_timeout_seconds: u64,
    stop_timeout_seconds: u64,
}

impl RawMacosVirtualizationProductConfig {
    fn validate(self) -> Result<MacosVirtualizationProductConfig, RunnerProductConfigError> {
        if std::env::consts::OS != "macos" || std::env::consts::ARCH != "aarch64" {
            return Err(RunnerProductConfigError::InvalidProvider);
        }
        validate_absolute_path(&self.helper_executable)
            .and_then(|()| validate_absolute_path(&self.template_manifest))
            .map_err(|_| RunnerProductConfigError::InvalidProvider)?;
        let helper_sha256 = self
            .helper_sha256
            .parse()
            .map_err(|_| RunnerProductConfigError::InvalidProvider)?;
        let template_manifest_sha256 = self
            .template_manifest_sha256
            .parse()
            .map_err(|_| RunnerProductConfigError::InvalidProvider)?;
        if self.helper_code_requirement.is_empty()
            || self.helper_code_requirement.len() > 4_096
            || !self.helper_code_requirement.is_ascii()
            || self
                .helper_code_requirement
                .bytes()
                .any(|byte| byte.is_ascii_control())
            || !valid_helper_code_requirement(&self.helper_code_requirement)
            || normalized_volume_uuid(&self.storage_volume_uuid).is_none()
            || !(64 * 1024 * 1024 * 1024..=1024 * 1024 * 1024 * 1024)
                .contains(&self.storage_quota_bytes)
            || !self.storage_quota_bytes.is_multiple_of(1024 * 1024 * 1024)
            || !(30..=900).contains(&self.boot_timeout_seconds)
            || !(1..=30).contains(&self.stop_timeout_seconds)
        {
            return Err(RunnerProductConfigError::InvalidProvider);
        }
        Ok(MacosVirtualizationProductConfig {
            helper_executable: self.helper_executable,
            helper_sha256,
            helper_code_requirement: self.helper_code_requirement,
            template_manifest: self.template_manifest,
            template_manifest_sha256,
            storage_volume_uuid: normalized_volume_uuid(&self.storage_volume_uuid)
                .ok_or(RunnerProductConfigError::InvalidProvider)?,
            storage_quota_bytes: self.storage_quota_bytes,
            boot_timeout: Duration::from_secs(self.boot_timeout_seconds),
            stop_timeout: Duration::from_secs(self.stop_timeout_seconds),
        })
    }
}

fn normalized_volume_uuid(value: &str) -> Option<String> {
    let normalized = value.to_ascii_uppercase();
    let valid = normalized.len() == 36
        && normalized.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase()
            }
        });
    valid.then_some(normalized)
}

fn valid_helper_code_requirement(value: &str) -> bool {
    const PREFIX: &str = "identifier \"";
    const MIDDLE: &str = "\" and anchor apple generic and certificate leaf[subject.OU] = \"";
    let Some(remainder) = value.strip_prefix(PREFIX) else {
        return false;
    };
    let Some((identifier, team)) = remainder.split_once(MIDDLE) else {
        return false;
    };
    let Some(team) = team.strip_suffix('"') else {
        return false;
    };
    let identifier_valid = identifier.len() <= 255
        && identifier.split('.').count() >= 2
        && identifier.split('.').all(|component| {
            !component.is_empty()
                && component.len() <= 63
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && component
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && component
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        });
    identifier_valid
        && team.len() == 10
        && team
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
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
                let port = github_server_url
                    .port_or_known_default()
                    .ok_or(RunnerProductConfigError::InvalidPodman)?;
                automata_ci_sandbox_podman::PodmanHostGatewayAlias::new(hostname, port)
                    .map_err(|_| RunnerProductConfigError::InvalidPodman)
            })
            .transpose()?;
        let service_proxy_image = self
            .service_proxy_image
            .map(validate_service_proxy_image)
            .transpose()
            .map_err(|()| RunnerProductConfigError::InvalidPodman)?;
        let buildkit_runtime = self
            .buildkit_runtime_image
            .map(validate_buildkit_runtime_image)
            .transpose()
            .map_err(|()| RunnerProductConfigError::InvalidPodman)?;
        if buildkit_runtime.is_some()
            && matches!(self.job_container_engine, RawJobContainerEngine::Disabled)
        {
            return Err(RunnerProductConfigError::InvalidPodman);
        }
        Ok(PodmanProductConfig {
            paths: Box::new(PodmanProductPaths {
                binary: self.binary,
                home: self.home,
                runtime_directory: self.runtime_directory,
                approved_helper_directory: self.approved_helper_directory,
                conmon_path: self.conmon_path,
                oci_runtime_path: self.oci_runtime_path,
                init_path: self.init_path,
                seccomp_profile_path: self.seccomp_profile_path,
            }),
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
            buildkit_runtime,
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

fn validate_buildkit_runtime_image(
    value: String,
) -> Result<automata_ci_sandbox_podman::BuildKitRuntime, ()> {
    validate_service_proxy_image(value).map(automata_ci_sandbox_podman::BuildKitRuntime::new)
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
    #[allow(clippy::too_many_lines)] // One validation boundary binds every executor policy field.
    fn validate(
        self,
        provider_kind: ProviderKind,
    ) -> Result<ExecutorProductConfig, RunnerProductConfigError> {
        let validated_resources = self
            .resources
            .validate()
            .map_err(|_| RunnerProductConfigError::InvalidExecutor)?;
        if provider_kind != ProviderKind::Kubernetes
            && (validated_resources.capacity.ephemeral_disk_bytes() != 0
                || validated_resources.capacity.gpu_count() != 0)
        {
            return Err(RunnerProductConfigError::InvalidExecutor);
        }
        let resources = validated_resources.execution;
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
            (
                ProviderKind::Podman | ProviderKind::Kubernetes,
                NetworkPolicy::Host,
                _,
                _,
            ) | (
                ProviderKind::Podman | ProviderKind::Kubernetes,
                _,
                RootFilesystemPolicy::Host,
                _,
            ) | (
                ProviderKind::Podman | ProviderKind::Kubernetes,
                _,
                _,
                SandboxPrivilegePolicy::Host
            )
        ) || (matches!(provider_kind, ProviderKind::WindowsHyperV)
            && (network != NetworkPolicy::Disabled
                || root_filesystem != RootFilesystemPolicy::Writable
                || privilege != SandboxPrivilegePolicy::Unprivileged))
            || (provider_kind == ProviderKind::MacosVirtualization
                && (network != NetworkPolicy::Disabled
                    || root_filesystem != RootFilesystemPolicy::Writable
                    || privilege != SandboxPrivilegePolicy::Unprivileged))
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
            ProviderKind::Podman | ProviderKind::Kubernetes | ProviderKind::MacosVirtualization => {
                ':'
            }
            ProviderKind::WindowsHyperV => ';',
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
        let executor_contract = automata_ci_job_executor_github::GithubJobExecutorConfig::new(
            resources,
            network,
            root_filesystem,
            privilege,
            default_step_timeout,
            self.maximum_output_bytes,
            runner_root.clone(),
        );
        executor_contract.map_err(|_| RunnerProductConfigError::InvalidExecutor)?;
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

fn provider_target_path(
    provider_kind: ProviderKind,
    value: impl Into<String>,
) -> Result<TargetPath, RunnerProductConfigError> {
    let value = value.into();
    if provider_kind == ProviderKind::WindowsHyperV && !valid_literal_windows_path(&value, false) {
        return Err(RunnerProductConfigError::InvalidExecutor);
    }
    match provider_kind {
        ProviderKind::Podman | ProviderKind::Kubernetes | ProviderKind::MacosVirtualization => {
            TargetPath::posix(value)
        }
        ProviderKind::WindowsHyperV => TargetPath::windows(value),
    }
    .map_err(|_| RunnerProductConfigError::InvalidExecutor)
}

fn target_is_root(path: &TargetPath) -> bool {
    match path.platform() {
        TargetPlatform::Posix => path.as_str() == "/",
        TargetPlatform::Windows => path.as_str().len() == 3 && path.as_str().ends_with('\\'),
    }
}

fn exact_windows_executable(path: &TargetPath, basename: &str) -> bool {
    path.platform() == TargetPlatform::Windows
        && valid_literal_windows_path(path.as_str(), true)
        && path
            .as_str()
            .rsplit('\\')
            .next()
            .is_some_and(|value| value.eq_ignore_ascii_case(basename))
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
            ProviderKind::Podman | ProviderKind::Kubernetes => {
                config.bash.is_some()
                    && config.sh.is_some()
                    && config.install.is_some()
                    && config.tar.is_some()
                    && config.sha256sum.is_some()
                    && config.powershell.is_none()
                    && config.cmd.is_none()
            }
            ProviderKind::WindowsHyperV => {
                config.bash.is_none()
                    && config.sh.is_none()
                    && config.pwsh.is_some()
                    && config.powershell.is_some()
                    && config.cmd.is_some()
                    && config
                        .pwsh
                        .as_ref()
                        .is_some_and(|path| exact_windows_executable(path, "pwsh.exe"))
                    && config
                        .powershell
                        .as_ref()
                        .is_some_and(|path| exact_windows_executable(path, "powershell.exe"))
                    && config
                        .cmd
                        .as_ref()
                        .is_some_and(|path| exact_windows_executable(path, "cmd.exe"))
                    && config
                        .python
                        .as_ref()
                        .is_none_or(|path| exact_windows_executable(path, "python.exe"))
                    && [
                        config.python.as_ref(),
                        config.pwsh.as_ref(),
                        config.powershell.as_ref(),
                        config.cmd.as_ref(),
                        config.node24.as_ref(),
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
            ProviderKind::MacosVirtualization => {
                config.bash.is_some()
                    && config.sh.is_some()
                    && config.install.is_some()
                    && config.tar.is_some()
                    && config.sha256sum.is_some()
                    && config.powershell.is_none()
                    && config.cmd.is_none()
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
    tls_trust: RawObjectStoreTlsTrust,
    operation_timeout_seconds: u64,
    access_key_id: SecretSource,
    secret_access_key: SecretSource,
    session_token: Option<SecretSource>,
}

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
enum RawObjectStoreTlsTrust {
    WebPki {},
    PrivateCa { certificate_source: SecretSource },
}

impl RawObjectStoreTlsTrust {
    fn validate(self) -> Result<ObjectStoreTlsTrust, RunnerProductConfigError> {
        match self {
            Self::WebPki {} => Ok(ObjectStoreTlsTrust::WebPki),
            Self::PrivateCa { certificate_source } => {
                certificate_source
                    .validate()
                    .map_err(RunnerProductConfigError::SecureInput)?;
                Ok(ObjectStoreTlsTrust::PrivateCa { certificate_source })
            }
        }
    }
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
        let tls_trust = self.tls_trust.validate()?;
        let operation_timeout = Duration::from_secs(self.operation_timeout_seconds);
        let store_config = match (endpoint.scheme(), self.loopback_development, &tls_trust) {
            ("http", true, ObjectStoreTlsTrust::WebPki) => S3BlobStoreConfig::loopback_development(
                endpoint,
                self.region,
                self.bucket,
                self.prefix,
                operation_timeout,
            ),
            ("https", false, _) => S3BlobStoreConfig::new(
                endpoint,
                self.region,
                self.bucket,
                self.prefix,
                self.force_path_style,
                automata_ci_blob_s3::S3TlsTrust::web_pki(),
                operation_timeout,
            ),
            _ => return Err(RunnerProductConfigError::InvalidObjectStore),
        }
        .map_err(|_| RunnerProductConfigError::InvalidObjectStore)?;
        Ok(ObjectStoreProductConfig {
            store_config,
            tls_trust,
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
        let server_url =
            validate_github_context_url(&self.server_url, self.allow_insecure_http, true)?;
        let api_url = validate_github_context_url(&self.api_url, self.allow_insecure_http, false)?;
        let graphql_url =
            validate_github_context_url(&self.graphql_url, self.allow_insecure_http, false)?;
        if is_mapped_github_transport(&server_url)
            && (!same_url_origin(&server_url, &api_url)
                || !same_url_origin(&server_url, &graphql_url))
        {
            return Err(RunnerProductConfigError::InvalidGithub);
        }
        let config = GithubProductConfig {
            user_agent: self.user_agent,
            server_url,
            api_url,
            graphql_url,
            allow_insecure_http: self.allow_insecure_http,
        };
        config
            .http_endpoint()
            .map_err(|_| RunnerProductConfigError::InvalidGithub)?;
        Ok(config)
    }
}

fn is_mapped_github_transport(url: &Url) -> bool {
    url.scheme() == "http"
        && url
            .host_str()
            .is_some_and(|host| host.to_ascii_lowercase().ends_with(".invalid"))
}

fn same_url_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
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
        "macos" => Ok(OperatingSystem::Macos),
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
