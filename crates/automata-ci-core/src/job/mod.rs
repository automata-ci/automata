//! Versioned, provider-neutral workflow job intermediate representation.

mod container;
mod context;
mod error;
mod expression;
mod identifier;
mod instance;
mod model;
mod permission;
mod result;
mod step;
mod template;
mod version;

pub use container::{
    ContainerCredentials, ContainerPort, ContainerSpec, MountSource, TransportProtocol, VolumeMount,
};
pub use context::{
    ContextValue, JOB_RUNTIME_CONTEXT_SCHEMA_VERSION, JobRuntimeContext, MAX_CONTEXT_VALUE_DEPTH,
    MAX_CONTEXT_VALUE_NODES, MAX_CONTEXT_VALUE_TEXT_BYTES, MAX_RUNTIME_CONTEXT_IDENTIFIER_BYTES,
    NeedContext, NeedOutput, RuntimeContextError, SecretBinding, StrategyContext,
};
pub use error::JobValidationError;
pub use expression::{
    EXPRESSION_PROGRAM_SCHEMA_VERSION, ExpressionComparison, ExpressionDialect,
    ExpressionInstruction, ExpressionLiteral, ExpressionLogical, ExpressionProgram,
    ExpressionProgramError, MAX_EXPRESSION_DEPTH, MAX_EXPRESSION_DIALECT_LENGTH,
    MAX_EXPRESSION_INSTRUCTIONS, MAX_EXPRESSION_SOURCE_BYTES, MAX_EXPRESSION_TEXT_BYTES,
};
pub use identifier::StepId;
pub use instance::{
    JobInstanceIdentity, JobOutputDefinition, MAX_JOB_LOGICAL_NAME_BYTES,
    MAX_JOB_OUTPUT_DEFINITIONS,
};
pub use model::{
    JobAuthorityProfile, JobContentReference, JobExecutionContext, JobIr, JobIrEnvelope, JobSource,
    ValueSource,
};
pub use permission::{
    JobPermissionGrant, JobPermissionRequest, MAX_JOB_PERMISSION_GRANTS,
    MAX_JOB_PERMISSION_NAME_BYTES,
};
pub use result::{
    JobConclusion, JobResult, JobResultOutput, JobResultValidationError, JobSecretExposure,
    MAX_JOB_RESULT_OUTPUT_UTF16_BYTES, StepResult,
};
pub use step::{
    ActionReference, RunValueTemplates, RuntimePositiveInteger, RuntimeTimeoutTemplate,
    RuntimeTimeoutUnit, SemanticStep, ShellTemplate, StepIr,
};
pub use template::{
    MAX_VALUE_TEMPLATE_SEGMENTS, MAX_VALUE_TEMPLATE_TEXT_BYTES, RuntimeBoolean, ValueTemplate,
    ValueTemplateError, ValueTemplateSegment,
};
pub use version::{JOB_IR_SCHEMA_VERSION, JobIrVersion, JobIrVersionError, JobIrVersionRange};
