//! Least-authority reduction of registered and observed runner abilities.

use automata_ci_core::{
    CapabilityValidationError, ContainerCapabilities, ResourceCapacity, RunnerCapabilities,
    RunnerId, SandboxCapabilities,
};
use thiserror::Error;

/// Computes the execution abilities authorized by both durable registration
/// and live runner observation.
///
/// Administrative labels and groups are always removed. They must be supplied
/// separately from server-owned routing state when constructing an effective
/// runner.
///
/// # Errors
///
/// Rejects invalid advertisements and identity or platform disagreement.
pub fn intersect_runner_capabilities(
    registered: &RunnerCapabilities,
    observed: &RunnerCapabilities,
) -> Result<RunnerCapabilities, RunnerCapabilityIntersectionError> {
    registered
        .validate()
        .map_err(RunnerCapabilityIntersectionError::InvalidRegistered)?;
    observed
        .validate()
        .map_err(RunnerCapabilityIntersectionError::InvalidObserved)?;
    if registered.runner_id() != observed.runner_id() {
        return Err(RunnerCapabilityIntersectionError::RunnerIdentityMismatch {
            registered: registered.runner_id(),
            observed: observed.runner_id(),
        });
    }
    if registered.platform() != observed.platform() {
        return Err(RunnerCapabilityIntersectionError::PlatformMismatch);
    }

    let registered_resources = registered.resources_per_job();
    let observed_resources = observed.resources_per_job();
    let resources = ResourceCapacity::new(
        registered_resources
            .cpu_millis()
            .min(observed_resources.cpu_millis()),
        registered_resources
            .memory_bytes()
            .min(observed_resources.memory_bytes()),
        registered_resources
            .ephemeral_disk_bytes()
            .min(observed_resources.ephemeral_disk_bytes()),
        registered_resources
            .gpu_count()
            .min(observed_resources.gpu_count()),
    );
    let sandbox = SandboxCapabilities::new(
        registered
            .sandbox()
            .maximum_isolation()
            .min(observed.sandbox().maximum_isolation()),
        registered
            .sandbox()
            .features()
            .intersection(observed.sandbox().features())
            .cloned(),
    );
    let containers = ContainerCapabilities::new(
        registered
            .containers()
            .features()
            .intersection(observed.containers().features())
            .cloned(),
    );
    RunnerCapabilities::new(registered.runner_id(), registered.platform().clone())
        .with_max_parallel_jobs(
            registered
                .max_parallel_jobs()
                .min(observed.max_parallel_jobs()),
        )
        .map(|capabilities| {
            capabilities
                .with_resources_per_job(resources)
                .with_sandbox(sandbox)
                .with_containers(containers)
                .with_features(
                    registered
                        .features()
                        .intersection(observed.features())
                        .cloned(),
                )
                .with_environment_profiles(
                    registered
                        .environment_profiles()
                        .intersection(observed.environment_profiles())
                        .cloned(),
                )
        })
        .map_err(RunnerCapabilityIntersectionError::InvalidRegistered)
}

/// Why registered and observed abilities could not be intersected.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RunnerCapabilityIntersectionError {
    /// Durable registration violated the capability schema.
    #[error("registered runner capabilities are invalid")]
    InvalidRegistered(#[source] CapabilityValidationError),
    /// Live observation violated the capability schema.
    #[error("observed runner capabilities are invalid")]
    InvalidObserved(#[source] CapabilityValidationError),
    /// The two inputs identify different durable runners.
    #[error("registered runner {registered} differs from observed runner {observed}")]
    RunnerIdentityMismatch {
        /// Durable runner identity named by the server-owned registration.
        registered: RunnerId,
        /// Durable runner identity named by the live observation.
        observed: RunnerId,
    },
    /// Registration and observation disagree about the execution platform.
    #[error("registered and observed runner platforms differ")]
    PlatformMismatch,
}
