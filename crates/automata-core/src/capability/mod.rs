//! Runner advertisements and job scheduling requirements.
//!
//! Labels and groups are deliberately separate. Labels use all-of superset
//! matching, while a non-empty eligible-group set uses any-of membership.

mod advertisement;
mod feature;
mod matching;
mod platform;
mod requirement;
mod resource;
mod selector;

pub use advertisement::{CapabilityValidationError, RunnerCapabilities};
pub use feature::{
    CapabilityIdError, ContainerFeature, MAX_CAPABILITY_ID_LENGTH, RunnerFeature, SandboxFeature,
};
pub use matching::{RequirementMismatch, RequirementMismatches, ResourceKind};
pub use platform::{Architecture, IsolationLevel, OperatingSystem, RunnerPlatform};
pub use requirement::RunnerRequirements;
pub use resource::{
    ContainerCapabilities, ResourceCapacity, ResourceRequirements, SandboxCapabilities,
};
pub use selector::{RunnerGroup, RunnerLabel, SelectorError};
