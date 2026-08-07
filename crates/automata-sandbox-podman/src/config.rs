use std::{
    ffi::OsString,
    net::IpAddr,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use crate::{PodmanConfigurationError, PodmanProcessEnvironment, PodmanStateRoot};

const MAX_OPERATION_TIMEOUT: Duration = Duration::from_mins(10);
const MAX_COMMAND_OUTPUT: usize = 1024 * 1024;

/// Optional container engine exposed inside an individual job sandbox.
///
/// `AttemptScopedDockerApi` starts a fresh, policy-filtered Docker-compatible
/// service for each sandbox. It never exposes Podman's user or system socket.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum JobContainerEngine {
    #[default]
    Disabled,
    AttemptScopedDockerApi,
}

/// An explicit DNS hostname mapped to Podman's host gateway inside a job.
///
/// This is intentionally hostname-only: IP addresses, wildcard names, bare
/// `localhost`, ports, paths, and control characters are rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PodmanHostGatewayAlias(String);

impl PodmanHostGatewayAlias {
    /// Validates a DNS hostname suitable for the left-hand side of Podman's
    /// `--add-host=<hostname>:host-gateway` option.
    ///
    /// # Errors
    ///
    /// Rejects non-DNS values, IP addresses, wildcard names, bare `localhost`,
    /// and hostnames without a dot.
    pub fn new(hostname: impl Into<String>) -> Result<Self, PodmanConfigurationError> {
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
        let valid = labels_valid
            && hostname.is_ascii()
            && !hostname.eq_ignore_ascii_case("localhost")
            && hostname.parse::<IpAddr>().is_err()
            && hostname.bytes().any(|byte| byte.is_ascii_alphabetic());
        valid
            .then_some(Self(hostname))
            .ok_or(PodmanConfigurationError::InvalidHostGatewayAlias)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
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

    #[must_use]
    pub const fn operation_timeout(self) -> Duration {
        self.operation_timeout
    }

    #[must_use]
    pub const fn command_timeout(self) -> Duration {
        self.command_timeout
    }

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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PodmanOptions {
    binary: PodmanBinary,
    state_root: PodmanStateRoot,
    process_environment: PodmanProcessEnvironment,
    limits: PodmanLimits,
    job_container_engine: JobContainerEngine,
    host_gateway_alias: Option<PodmanHostGatewayAlias>,
}

impl PodmanOptions {
    #[must_use]
    pub fn new(
        binary: PodmanBinary,
        state_root: PodmanStateRoot,
        process_environment: PodmanProcessEnvironment,
    ) -> Self {
        let process_environment = process_environment
            .with_temporary_directory(state_root.as_path().join("process-transient"));
        Self {
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
        }
    }

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

    /// Maps one explicitly validated hostname to Podman's host gateway inside
    /// the job container. No alias is installed by default.
    #[must_use]
    pub fn with_host_gateway_alias(mut self, alias: PodmanHostGatewayAlias) -> Self {
        self.host_gateway_alias = Some(alias);
        self
    }

    #[must_use]
    pub const fn binary(&self) -> &PodmanBinary {
        &self.binary
    }

    #[must_use]
    pub const fn state_root(&self) -> &PodmanStateRoot {
        &self.state_root
    }

    #[must_use]
    pub const fn process_environment(&self) -> &PodmanProcessEnvironment {
        &self.process_environment
    }

    #[must_use]
    pub const fn limits(&self) -> PodmanLimits {
        self.limits
    }

    #[must_use]
    pub const fn job_container_engine(&self) -> JobContainerEngine {
        self.job_container_engine
    }

    #[must_use]
    pub const fn host_gateway_alias(&self) -> Option<&PodmanHostGatewayAlias> {
        self.host_gateway_alias.as_ref()
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

pub(crate) fn safe_search_path(value: &OsString) -> bool {
    let Some(value) = value.to_str() else {
        return false;
    };
    !value.is_empty()
        && value.split(':').all(|entry| {
            let path = Path::new(entry);
            safe_host_path(path)
        })
}
