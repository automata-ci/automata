//! Runner advertisements and job scheduling requirements.
//!
//! Labels and groups are deliberately separate. Labels use all-of superset
//! matching, while a non-empty eligible-group set uses any-of membership.

mod advertisement;
mod environment;
mod feature;
mod matching;
mod platform;
mod requirement;
mod resource;
mod selector;

pub use advertisement::{CapabilityValidationError, RunnerCapabilities};
pub use environment::{EnvironmentProfile, EnvironmentProfileError, EnvironmentProfileId};
pub use feature::{
    CapabilityIdError, ContainerFeature, MAX_CAPABILITY_ID_LENGTH, RunnerFeature, SandboxFeature,
};
pub use matching::{RequirementMismatch, RequirementMismatches, ResourceKind};
pub use platform::{Architecture, IsolationLevel, OperatingSystem, RunnerPlatform};
pub use requirement::{RUNNER_REQUIREMENTS_SCHEMA_VERSION, RunnerRequirements};
pub use resource::{
    ContainerCapabilities, JobResourceAllocation, JobResourcePolicy, ResourceAllocationError,
    ResourceCapacity, ResourcePolicyError, ResourceQuantityError, ResourceRequirements,
    SandboxCapabilities, parse_cpu_quantity, parse_storage_quantity,
};
pub use selector::{RunnerGroup, RunnerLabel, SelectorError};

/// Maximum durable runner inventory admitted by enrollment and startup checks.
pub const MAX_REGISTERED_RUNNERS: usize = 64;
