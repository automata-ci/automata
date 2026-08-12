use std::time::Duration;

use automata_ci_execution::{
    MAX_EXECUTION_OUTPUT_BYTES, NetworkPolicy, ResourceLimits, RootFilesystemPolicy,
    SandboxPrivilegePolicy, SandboxResourcePolicy, TargetPath, TargetPlatform, ValueError,
};
use thiserror::Error;

const MAX_POST_JOB_CLEANUP_TIMEOUT: Duration = Duration::from_mins(5);

/// Validated policy for one GitHub job executor instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubJobExecutorConfig {
    resource_policy: SandboxResourcePolicy,
    network: NetworkPolicy,
    root_filesystem: RootFilesystemPolicy,
    privilege: SandboxPrivilegePolicy,
    default_step_timeout: Duration,
    maximum_output_bytes: usize,
    runner_root: TargetPath,
}

impl GithubJobExecutorConfig {
    /// Creates explicit sandbox and process policy.
    ///
    /// # Errors
    ///
    /// Rejects zero or greater-than-24-hour default timeouts, invalid output
    /// bounds, and root or separator-terminated runner scratch paths.
    pub fn new(
        resources: ResourceLimits,
        network: NetworkPolicy,
        root_filesystem: RootFilesystemPolicy,
        privilege: SandboxPrivilegePolicy,
        default_step_timeout: Duration,
        maximum_output_bytes: usize,
        runner_root: TargetPath,
    ) -> Result<Self, GithubJobExecutorConfigError> {
        Self::with_resource_policy(
            SandboxResourcePolicy::Enforced(resources),
            network,
            root_filesystem,
            privilege,
            default_step_timeout,
            maximum_output_bytes,
            runner_root,
        )
    }

    /// Creates trusted-native policy without per-job hard resource limits.
    ///
    /// # Errors
    ///
    /// Applies the same timeout, output, and runner-root validation as
    /// [`Self::new`].
    pub fn host_shared(
        network: NetworkPolicy,
        root_filesystem: RootFilesystemPolicy,
        privilege: SandboxPrivilegePolicy,
        default_step_timeout: Duration,
        maximum_output_bytes: usize,
        runner_root: TargetPath,
    ) -> Result<Self, GithubJobExecutorConfigError> {
        Self::with_resource_policy(
            SandboxResourcePolicy::HostShared,
            network,
            root_filesystem,
            privilege,
            default_step_timeout,
            maximum_output_bytes,
            runner_root,
        )
    }

    fn with_resource_policy(
        resource_policy: SandboxResourcePolicy,
        network: NetworkPolicy,
        root_filesystem: RootFilesystemPolicy,
        privilege: SandboxPrivilegePolicy,
        default_step_timeout: Duration,
        maximum_output_bytes: usize,
        runner_root: TargetPath,
    ) -> Result<Self, GithubJobExecutorConfigError> {
        if default_step_timeout.is_zero() || default_step_timeout > Duration::from_hours(24) {
            return Err(GithubJobExecutorConfigError::InvalidTimeout);
        }
        if maximum_output_bytes == 0 || maximum_output_bytes > MAX_EXECUTION_OUTPUT_BYTES {
            return Err(GithubJobExecutorConfigError::InvalidOutputLimit);
        }
        let invalid_runner_root = match runner_root.platform() {
            TargetPlatform::Posix => {
                runner_root.as_str() == "/" || runner_root.as_str().ends_with('/')
            }
            TargetPlatform::Windows => {
                runner_root.as_str().len() == 3 || runner_root.as_str().ends_with('\\')
            }
        };
        if invalid_runner_root {
            return Err(GithubJobExecutorConfigError::InvalidRunnerRoot);
        }
        Ok(Self {
            resource_policy,
            network,
            root_filesystem,
            privilege,
            default_step_timeout,
            maximum_output_bytes,
            runner_root,
        })
    }

    /// Returns the exact resource-enforcement policy.
    #[must_use]
    pub const fn resource_policy(&self) -> SandboxResourcePolicy {
        self.resource_policy
    }

    /// Returns whole-job hard resource limits when selected.
    #[must_use]
    pub const fn resources(&self) -> Option<ResourceLimits> {
        self.resource_policy.enforced()
    }

    /// Returns whole-job network policy.
    #[must_use]
    pub const fn network(&self) -> NetworkPolicy {
        self.network
    }

    /// Returns root-filesystem policy.
    #[must_use]
    pub const fn root_filesystem(&self) -> RootFilesystemPolicy {
        self.root_filesystem
    }

    /// Returns the identity privilege confined inside the sandbox boundary.
    #[must_use]
    pub const fn privilege(&self) -> SandboxPrivilegePolicy {
        self.privilege
    }

    /// Returns the timeout used when a step does not declare one.
    #[must_use]
    pub const fn default_step_timeout(&self) -> Duration {
        self.default_step_timeout
    }

    /// Returns the whole post-job cleanup budget. It is deliberately capped
    /// independently of a workflow's step timeout.
    #[must_use]
    pub const fn post_job_cleanup_timeout(&self) -> Duration {
        if self.default_step_timeout.as_secs() < MAX_POST_JOB_CLEANUP_TIMEOUT.as_secs() {
            self.default_step_timeout
        } else {
            MAX_POST_JOB_CLEANUP_TIMEOUT
        }
    }

    /// Returns the aggregate stdout/stderr capture bound per command.
    #[must_use]
    pub const fn maximum_output_bytes(&self) -> usize {
        self.maximum_output_bytes
    }

    /// Returns the private scratch root inside each sandbox.
    #[must_use]
    pub const fn runner_root(&self) -> &TargetPath {
        &self.runner_root
    }
}

/// Invalid executor policy.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubJobExecutorConfigError {
    /// Default step timeout was zero or greater than 24 hours.
    #[error("invalid default step timeout")]
    InvalidTimeout,
    /// Per-command output bound was zero or exceeded the endpoint ceiling.
    #[error("invalid command output limit")]
    InvalidOutputLimit,
    /// Runner scratch root was not a private absolute path.
    #[error("invalid sandbox runner root")]
    InvalidRunnerRoot,
}

impl From<ValueError> for GithubJobExecutorConfigError {
    fn from(_: ValueError) -> Self {
        Self::InvalidRunnerRoot
    }
}
