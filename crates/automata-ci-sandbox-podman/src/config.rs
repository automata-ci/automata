use std::{
    ffi::OsString,
    fmt,
    net::IpAddr,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use automata_ci_execution::ImmutableImage;

use crate::{
    PodmanConfigurationError, PodmanProcessEnvironment, PodmanStateRoot,
    state::{PODMAN_RUNTIME_ROOT_NAME, SHARED_GRAPH_ROOT_NAME, SHARED_RUN_ROOT_NAME},
};

const MAX_OPERATION_TIMEOUT: Duration = Duration::from_mins(10);
const MAX_COMMAND_OUTPUT: usize = 1024 * 1024;
const USER_NAMESPACE_REMOVE_PROGRAM: &str = "/usr/bin/rm";

/// Revalidation boundary for immutable host inputs admitted before Podman use.
///
/// Production implementations retain the exact admitted filesystem identities
/// and return `false` after any replacement or metadata drift. The sandbox
/// crate deliberately does not infer administrator policy from ambient host
/// state; the runner product supplies that deployment-specific admission.
pub trait PodmanLaunchTrust: fmt::Debug + Send + Sync {
    /// Revalidates the exact immutable snapshot captured before provider use.
    fn revalidate(&self) -> bool;
}

/// Opaque, clonable capability proving that one Podman launch may revalidate
/// the exact external-input snapshot admitted by its trusted caller.
#[derive(Clone)]
pub struct PodmanLaunchTrustHandle(Arc<Mutex<PodmanLaunchTrustState>>);

struct PodmanLaunchTrustState {
    trust: Arc<dyn PodmanLaunchTrust>,
    quarantined: bool,
}

impl PodmanLaunchTrustHandle {
    /// Wraps one trusted external-input revalidation policy.
    #[must_use]
    pub fn new(trust: Arc<dyn PodmanLaunchTrust>) -> Self {
        Self(Arc::new(Mutex::new(PodmanLaunchTrustState {
            trust,
            quarantined: false,
        })))
    }

    pub(crate) fn revalidate(&self) -> bool {
        let Ok(mut state) = self.0.lock() else {
            return false;
        };
        if state.quarantined {
            return false;
        }
        if !state.trust.revalidate() {
            state.quarantined = true;
            return false;
        }
        true
    }
}

impl fmt::Debug for PodmanLaunchTrustHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PodmanLaunchTrustHandle")
            .finish_non_exhaustive()
    }
}

/// Optional container engine exposed inside an individual job sandbox.
///
/// `AttemptScopedDockerApi` starts a fresh, policy-filtered Docker-compatible
/// service for each sandbox. It never exposes Podman's user or system socket.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum JobContainerEngine {
    /// Does not expose a workload container API inside the sandbox.
    #[default]
    Disabled,
    /// Exposes a fresh attempt-local, policy-filtered Docker-compatible API.
    AttemptScopedDockerApi,
}

/// One administrator-selected `BuildKit` runtime admitted to the closed Docker
/// compatibility surface.
///
/// The image is always registry-qualified and digest-pinned. Buildx's mutable
/// default image name is treated only as a client-side compatibility alias;
/// the proxy never pulls it and always substitutes this exact local image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildKitRuntime {
    image: ImmutableImage,
}

impl BuildKitRuntime {
    /// Selects one immutable `BuildKit` image for local verification and use.
    #[must_use]
    pub const fn new(image: ImmutableImage) -> Self {
        Self { image }
    }

    /// Returns the exact digest-pinned image admitted for Buildx builders.
    #[must_use]
    pub const fn image(&self) -> &ImmutableImage {
        &self.image
    }
}

/// An explicit DNS hostname and port mapped to Podman's host gateway inside a job.
///
/// The hostname is intentionally DNS-only: IP addresses, wildcard names, bare
/// `localhost` names, embedded ports, paths, and control characters are
/// rejected. The separate forwarded port must be nonzero.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PodmanHostGatewayAlias {
    hostname: String,
    port: u16,
}

impl PodmanHostGatewayAlias {
    /// Validates a DNS hostname suitable for the left-hand side of Podman's
    /// `--add-host=<hostname>:host-gateway` option.
    ///
    /// # Errors
    ///
    /// Rejects a zero port, non-DNS values, IP addresses, wildcard names,
    /// `localhost` names, and hostnames without a dot.
    pub fn new(hostname: impl Into<String>, port: u16) -> Result<Self, PodmanConfigurationError> {
        let hostname = hostname.into();
        let labels_valid = hostname.len() <= 253
            && hostname.contains('.')
            && hostname.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    && label
                        .as_bytes()
                        .last()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            });
        let valid = port != 0
            && labels_valid
            && hostname.is_ascii()
            && !hostname.eq_ignore_ascii_case("localhost")
            && !hostname.to_ascii_lowercase().ends_with(".localhost")
            && hostname.parse::<IpAddr>().is_err()
            && hostname.bytes().any(|byte| byte.is_ascii_alphabetic());
        valid
            .then_some(Self { hostname, port })
            .ok_or(PodmanConfigurationError::InvalidHostGatewayAlias)
    }

    /// Returns the validated hostname without the Podman mapping suffix.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.hostname
    }

    /// Returns the one host port forwarded into the job network namespace.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

/// Explicit absolute Podman executable path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PodmanBinary(PathBuf);

impl PodmanBinary {
    /// Validates an absolute normalized executable path. Existence is checked
    /// by the system command adapter at execution time.
    ///
    /// # Errors
    ///
    /// Rejects relative paths, traversal, roots, and empty paths.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, PodmanConfigurationError> {
        let path = path.into();
        let valid = path.is_absolute()
            && path.parent().is_some()
            && path
                .components()
                .all(|component| !matches!(component, Component::CurDir | Component::ParentDir));
        valid
            .then_some(Self(path))
            .ok_or(PodmanConfigurationError::InvalidBinary)
    }

    /// Returns the exact absolute executable path supplied at construction.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

/// Aggregate provider-operation and command output bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PodmanLimits {
    operation_timeout: Duration,
    command_timeout: Duration,
    output_limit: usize,
}

impl PodmanLimits {
    /// Creates coherent non-zero bounds.
    ///
    /// # Errors
    ///
    /// Rejects command deadlines beyond the aggregate deadline and output
    /// bounds beyond one MiB.
    pub fn new(
        operation_timeout: Duration,
        command_timeout: Duration,
        output_limit: usize,
    ) -> Result<Self, PodmanConfigurationError> {
        let valid = !operation_timeout.is_zero()
            && operation_timeout <= MAX_OPERATION_TIMEOUT
            && !command_timeout.is_zero()
            && command_timeout <= operation_timeout
            && output_limit > 0
            && output_limit <= MAX_COMMAND_OUTPUT;
        valid
            .then_some(Self {
                operation_timeout,
                command_timeout,
                output_limit,
            })
            .ok_or(PodmanConfigurationError::InvalidLimits)
    }

    /// Returns the maximum wall-clock duration of one aggregate provider operation.
    #[must_use]
    pub const fn operation_timeout(self) -> Duration {
        self.operation_timeout
    }

    /// Returns the per-command timeout, which never exceeds the operation timeout.
    #[must_use]
    pub const fn command_timeout(self) -> Duration {
        self.command_timeout
    }

    /// Returns the maximum retained bytes for each bounded command output.
    #[must_use]
    pub const fn output_limit(self) -> usize {
        self.output_limit
    }
}

impl Default for PodmanLimits {
    fn default() -> Self {
        Self {
            operation_timeout: Duration::from_mins(3),
            command_timeout: Duration::from_secs(30),
            output_limit: 64 * 1024,
        }
    }
}

/// Trusted construction options. Host environment is explicit and contains no
/// registry authentication or remote-connection variables.
#[derive(Clone, Debug)]
pub struct PodmanOptions {
    binary: PodmanBinary,
    state_root: PodmanStateRoot,
    process_environment: PodmanProcessEnvironment,
    limits: PodmanLimits,
    job_container_engine: JobContainerEngine,
    host_gateway_alias: Option<PodmanHostGatewayAlias>,
    service_proxy_image: Option<ImmutableImage>,
    buildkit_runtime: Option<BuildKitRuntime>,
}

impl PodmanOptions {
    /// Binds one exact process environment to the same private state root.
    ///
    /// # Errors
    ///
    /// Rejects a process environment prepared for a different state root.
    pub fn new(
        binary: PodmanBinary,
        state_root: PodmanStateRoot,
        process_environment: PodmanProcessEnvironment,
    ) -> Result<Self, PodmanConfigurationError> {
        if process_environment.state_root() != state_root.as_path() {
            return Err(PodmanConfigurationError::InvalidProcessEnvironment);
        }
        Ok(Self {
            binary,
            state_root,
            process_environment,
            limits: PodmanLimits {
                operation_timeout: Duration::from_mins(3),
                command_timeout: Duration::from_secs(30),
                output_limit: 64 * 1024,
            },
            job_container_engine: JobContainerEngine::Disabled,
            host_gateway_alias: None,
            service_proxy_image: None,
            buildkit_runtime: None,
        })
    }

    /// Installs the exact immutable launch-trust snapshot admitted by the
    /// product before any production Podman process is allowed to start.
    #[must_use]
    pub fn with_launch_trust(mut self, trust: PodmanLaunchTrustHandle) -> Self {
        self.process_environment.install_launch_trust(trust);
        self
    }

    /// Replaces the provider's aggregate, command, and output resource bounds.
    #[must_use]
    pub const fn with_limits(mut self, limits: PodmanLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Selects an optional, sandbox-scoped workload container engine.
    #[must_use]
    pub const fn with_job_container_engine(mut self, engine: JobContainerEngine) -> Self {
        self.job_container_engine = engine;
        self
    }

    /// Maps one explicitly validated hostname to Podman's host gateway and
    /// forwards only its exact port. No mapping is installed by default.
    #[must_use]
    pub fn with_host_gateway_alias(
        mut self,
        alias: PodmanHostGatewayAlias,
    ) -> Result<Self, PodmanConfigurationError> {
        self.process_environment
            .enable_host_gateway_port(alias.port())?;
        self.host_gateway_alias = Some(alias);
        Ok(self)
    }

    /// Configures the locally preloaded immutable helper used to realize
    /// namespace-local service port mappings.
    #[must_use]
    pub fn with_service_proxy_image(mut self, image: ImmutableImage) -> Self {
        self.service_proxy_image = Some(image);
        self
    }

    /// Enables the closed Buildx docker-container compatibility policy with
    /// one locally preloaded, immutable `BuildKit` runtime.
    #[must_use]
    pub fn with_buildkit_runtime(mut self, runtime: BuildKitRuntime) -> Self {
        self.buildkit_runtime = Some(runtime);
        self
    }

    /// Returns the exact executable selected for every Podman invocation.
    #[must_use]
    pub const fn binary(&self) -> &PodmanBinary {
        &self.binary
    }

    /// Returns the fixed host program executed inside `podman unshare` to
    /// remove exact user-namespace-owned workspace content.
    #[must_use]
    pub fn user_namespace_remove_program(&self) -> &Path {
        Path::new(USER_NAMESPACE_REMOVE_PROGRAM)
    }

    /// Returns the private, pre-existing host state root owned by this provider.
    #[must_use]
    pub const fn state_root(&self) -> &PodmanStateRoot {
        &self.state_root
    }

    /// Returns the provider's private shared Podman graph root.
    ///
    /// The path is always the same exact child of the configured rootless
    /// runtime directory; it is created and descriptor-validated when the
    /// provider opens.
    #[must_use]
    pub fn shared_graph_root(&self) -> PathBuf {
        self.state_root.as_path().join(SHARED_GRAPH_ROOT_NAME)
    }

    /// Returns the provider's private shared Podman runtime root.
    ///
    /// The path is always the same exact child of [`Self::state_root`]; it is
    /// created and descriptor-validated when the provider opens.
    #[must_use]
    pub fn shared_run_root(&self) -> PathBuf {
        self.runtime_root().join(SHARED_RUN_ROOT_NAME)
    }

    /// Returns the private per-boot Podman runtime hierarchy.
    #[must_use]
    pub fn runtime_root(&self) -> PathBuf {
        self.process_environment
            .runtime_directory()
            .join(PODMAN_RUNTIME_ROOT_NAME)
    }

    /// Returns the shared engine's private libpod temporary directory.
    #[must_use]
    pub fn shared_tmp_dir(&self) -> PathBuf {
        self.runtime_root().join("shared-tmp")
    }

    /// Constructs the complete invariant global argument prefix for one engine.
    ///
    /// The returned options must precede the Podman subcommand.
    #[must_use]
    pub fn global_arguments(
        &self,
        graph_root: &Path,
        run_root: &Path,
        tmp_dir: &Path,
    ) -> Vec<OsString> {
        let environment = &self.process_environment;
        vec![
            "--remote=false".into(),
            format!("--root={}", graph_root.display()).into(),
            format!("--runroot={}", run_root.display()).into(),
            "--storage-driver=vfs".into(),
            "--storage-opt=".into(),
            "--transient-store=false".into(),
            format!(
                "--hooks-dir={}",
                environment.empty_hooks_directory().display()
            )
            .into(),
            format!(
                "--cdi-spec-dir={}",
                environment.empty_cdi_directory().display()
            )
            .into(),
            format!(
                "--default-mounts-file={}",
                environment.mounts_conf_path().display()
            )
            .into(),
            format!(
                "--network-config-dir={}",
                graph_root.join("networks").display()
            )
            .into(),
            format!("--tmpdir={}", tmp_dir.display()).into(),
            format!("--volumepath={}", graph_root.join("volumes").display()).into(),
            "--events-backend=none".into(),
            format!("--conmon={}", environment.conmon_path().display()).into(),
            format!("--runtime={}", environment.oci_runtime_path().display()).into(),
            "--cgroup-manager=cgroupfs".into(),
        ]
    }

    /// Constructs the invariant global prefix for the provider's shared engine.
    #[must_use]
    pub fn shared_global_arguments(&self) -> Vec<OsString> {
        self.global_arguments(
            &self.shared_graph_root(),
            &self.shared_run_root(),
            &self.shared_tmp_dir(),
        )
    }

    /// Securely materializes and validates the exact generated Podman state.
    ///
    /// # Errors
    ///
    /// Rejects stale, replaced, over-permissive, or mismatched state.
    pub fn prepare_state(&self) -> Result<(), crate::PodmanStateRootError> {
        crate::state::prepare(self)
    }

    /// Returns the fixed allowlisted environment used for Podman host processes.
    #[must_use]
    pub const fn process_environment(&self) -> &PodmanProcessEnvironment {
        &self.process_environment
    }

    /// Returns the configured operation and command resource bounds.
    #[must_use]
    pub const fn limits(&self) -> PodmanLimits {
        self.limits
    }

    /// Returns whether an attempt-scoped workload container API is enabled.
    #[must_use]
    pub const fn job_container_engine(&self) -> JobContainerEngine {
        self.job_container_engine
    }

    /// Returns the optional validated hostname and port mapped to the host gateway.
    #[must_use]
    pub const fn host_gateway_alias(&self) -> Option<&PodmanHostGatewayAlias> {
        self.host_gateway_alias.as_ref()
    }

    /// Returns the optional immutable image used for service-port proxying.
    #[must_use]
    pub const fn service_proxy_image(&self) -> Option<&ImmutableImage> {
        self.service_proxy_image.as_ref()
    }

    /// Returns the optional immutable `BuildKit` runtime admitted to the job API.
    #[must_use]
    pub const fn buildkit_runtime(&self) -> Option<&BuildKitRuntime> {
        self.buildkit_runtime.as_ref()
    }
}

pub(crate) fn safe_host_path(path: &Path) -> bool {
    path.is_absolute()
        && path.parent().is_some()
        && path
            .components()
            .all(|component| !matches!(component, Component::CurDir | Component::ParentDir))
        && !path.as_os_str().is_empty()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[derive(Debug)]
    struct RestorableTrust(AtomicUsize);

    impl PodmanLaunchTrust for RestorableTrust {
        fn revalidate(&self) -> bool {
            self.0.fetch_add(1, Ordering::SeqCst) != 0
        }
    }

    #[test]
    fn launch_trust_quarantine_is_shared_and_irreversible() {
        let trust = Arc::new(RestorableTrust(AtomicUsize::new(0)));
        let handle = PodmanLaunchTrustHandle::new(trust.clone());
        let clone = handle.clone();

        assert!(
            !handle.revalidate(),
            "first drift detection must fail closed"
        );
        assert!(!clone.revalidate(), "every clone must share quarantine");
        assert_eq!(
            trust.0.load(Ordering::SeqCst),
            1,
            "restoration must never be consulted after quarantine"
        );
    }
}
