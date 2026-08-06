//! Versioned, provider-neutral workflow job intermediate representation.

mod container;
mod error;
mod identifier;
mod model;
mod result;
mod step;

pub use container::{
    ContainerCredentials, ContainerPort, ContainerSpec, MountSource, TransportProtocol, VolumeMount,
};
pub use error::JobValidationError;
pub use identifier::StepId;
pub use model::{Expression, JobIr, JobIrEnvelope, JobSource, ValueSource};
pub use result::{JobConclusion, JobResult, JobResultValidationError, StepResult};
pub use step::{ActionReference, SemanticStep, ShellSpec, StepIr};
