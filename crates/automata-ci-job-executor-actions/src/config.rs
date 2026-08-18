use std::time::Duration;

use automata_ci_execution::{
    MAX_EXECUTION_OUTPUT_BYTES, NetworkPolicy, ResourceLimits, RootFilesystemPolicy,
    SandboxPrivilegePolicy, TargetPath, TargetPlatform, ValueError,
};
use thiserror::Error;

// Cache and artifact actions may each need a bounded final network flush. The
// aggregate budget must accommodate several posts without inheriting an
// unbounded workflow timeout.
const MAX_POST_JOB_CLEANUP_TIMEOUT: Duration = Duration::from_mins(15);

/// Validated policy for one Actions-compatible job executor instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionsJobExecutorConfig {
    resources: ResourceLimits,
    network: NetworkPolicy,
    root_filesystem: RootFilesystemPolicy,
    privilege: SandboxPrivilegePolicy,
    default_step_timeout: Duration,
    maximum_output_bytes: usize,
    runner_root: TargetPath,
}

impl ActionsJobExecutorConfig {
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
    ) -> Result<Self, ActionsJobExecutorConfigError> {
        if default_step_timeout.is_zero() || default_step_timeout > Duration::from_hours(24) {
            return Err(ActionsJobExecutorConfigError::InvalidTimeout);
        }
        if maximum_output_bytes == 0 || maximum_output_bytes > MAX_EXECUTION_OUTPUT_BYTES {
            return Err(ActionsJobExecutorConfigError::InvalidOutputLimit);
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
            return Err(ActionsJobExecutorConfigError::InvalidRunnerRoot);
        }
        Ok(Self {
            resources,
            network,
            root_filesystem,
            privilege,
            default_step_timeout,
            maximum_output_bytes,
            runner_root,
        })
    }

    /// Returns mandatory whole-job hard resource limits.
    #[must_use]
    pub const fn resources(&self) -> ResourceLimits {
        self.resources
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
pub enum ActionsJobExecutorConfigError {
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

impl From<ValueError> for ActionsJobExecutorConfigError {
    fn from(_: ValueError) -> Self {
        Self::InvalidRunnerRoot
    }
}
