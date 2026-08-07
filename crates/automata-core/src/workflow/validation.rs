//! Workflow-plan validation failures.

use thiserror::Error;

/// A structural or versioning error that prevents scheduling a workflow plan.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkflowPlanError {
    #[error("workflow-plan versions must be positive")]
    ZeroPlanVersion,
    #[error("workflow-expression versions must be positive")]
    ZeroExpressionVersion,
    #[error("unsupported workflow-plan schema {received}; this build supports {supported}")]
    UnsupportedPlanVersion { supported: u16, received: u16 },
    #[error("unsupported workflow-expression schema {received}; this build supports {supported}")]
    UnsupportedExpressionVersion { supported: u16, received: u16 },
    #[error("required field `{0}` is empty")]
    EmptyField(&'static str),
    #[error("source line and column must be one-based")]
    InvalidSourceLocation,
    #[error("source span end precedes its start")]
    ReversedSourceSpan,
    #[error("workflow expression must contain at least one segment")]
    EmptyExpressionSegments,
    #[error("workflow expression contains an empty evaluation")]
    EmptyEvaluation,
    #[error("workflow expression segments do not reconstruct their preserved source")]
    ExpressionSourceMismatch,
    #[error("invalid {kind} `{value}`")]
    InvalidKey { kind: &'static str, value: String },
    #[error("a workflow plan must contain at least one job")]
    NoJobs,
    #[error("job `{0}` appears more than once")]
    DuplicateJob(String),
    #[error("job `{job}` needs unknown job `{dependency}`")]
    UnknownDependency { job: String, dependency: String },
    #[error("job `{0}` cannot need itself")]
    SelfDependency(String),
    #[error("workflow job graph contains a dependency cycle")]
    DependencyCycle,
    #[error("job `{0}` must contain at least one step")]
    NoSteps(String),
    #[error("step `{step}` appears more than once in job `{job}`")]
    DuplicateStep { job: String, step: String },
    #[error("timeout cannot be zero for `{0}`")]
    ZeroTimeout(String),
    #[error("runner profile for job `{0}` has neither a group nor labels")]
    EmptyRunnerProfile(String),
    #[error("key `{0}` appears more than once in one value-map layer")]
    DuplicateValueKey(String),
    #[error("permission `{0}` appears more than once")]
    DuplicatePermission(String),
    #[error(
        "workflow source provider `{source_provider}` does not match event provider `{event_provider}`"
    )]
    ProviderMismatch {
        source_provider: String,
        event_provider: String,
    },
    #[error("workflow plan span belongs to a different source identity")]
    PlanSourceMismatch,
}
