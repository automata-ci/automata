//! Versioned, provider-neutral workflow job intermediate representation.

mod container;
mod error;
mod expression;
mod identifier;
mod model;
mod result;
mod step;
mod version;

pub use container::{
    ContainerCredentials, ContainerPort, ContainerSpec, MountSource, TransportProtocol, VolumeMount,
};
pub use error::JobValidationError;
pub use expression::{
    EXPRESSION_PROGRAM_SCHEMA_VERSION, ExpressionComparison, ExpressionDialect,
    ExpressionInstruction, ExpressionLiteral, ExpressionLogical, ExpressionProgram,
    ExpressionProgramError, MAX_EXPRESSION_DEPTH, MAX_EXPRESSION_DIALECT_LENGTH,
    MAX_EXPRESSION_INSTRUCTIONS, MAX_EXPRESSION_SOURCE_BYTES, MAX_EXPRESSION_TEXT_BYTES,
};
pub use identifier::StepId;
pub use model::{
    JobContentReference, JobExecutionContext, JobIr, JobIrEnvelope, JobSource, ValueSource,
};
pub use result::{JobConclusion, JobResult, JobResultValidationError, StepResult};
pub use step::{ActionReference, SemanticStep, ShellSpec, StepIr};
pub use version::{JOB_IR_SCHEMA_VERSION, JobIrVersion, JobIrVersionError, JobIrVersionRange};
