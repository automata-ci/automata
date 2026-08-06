//! Planning-time validation failures for the job IR.

use thiserror::Error;

use super::StepId;

/// Validation failure that must stop a plan before execution.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum JobValidationError {
    #[error("unsupported job IR schema {received}; this build supports {supported}")]
    UnsupportedSchema { supported: u16, received: u16 },
    #[error("unsupported runner-requirements schema {received}; this build supports {supported}")]
    UnsupportedRequirementsSchema { supported: u16, received: u16 },
    #[error("required field `{0}` is empty")]
    EmptyField(&'static str),
    #[error("a job must contain at least one step")]
    NoSteps,
    #[error("job timeout cannot be zero")]
    ZeroTimeout,
    #[error("step ID cannot be empty")]
    EmptyStepId,
    #[error("step ID exceeds {maximum} bytes")]
    StepIdTooLong { maximum: usize },
    #[error("invalid step ID `{0}`; only ASCII letters, numbers, `_`, and `-` are allowed")]
    InvalidStepId(String),
    #[error("duplicate step ID `{0:?}`")]
    DuplicateStepId(StepId),
    #[error("timeout for step `{0:?}` cannot be zero")]
    ZeroStepTimeout(StepId),
    #[error("run command for step `{0:?}` is empty")]
    EmptyRunCommand(StepId),
}
