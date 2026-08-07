//! Immutable, provider-neutral workflow DAG produced before job expansion.

mod expression;
mod identifier;
mod job;
mod plan;
mod source;
mod step;
mod validation;
mod value;
mod version;

pub use expression::{
    ExpressionSegment, PlanExpression, PlanValue, WORKFLOW_EXPRESSION_SCHEMA_VERSION,
    WorkflowExpressionVersion,
};
pub use identifier::{WorkflowJobKey, WorkflowStepKey};
pub use job::{PlannedJob, PlannedJobBuilder};
pub use plan::{WorkflowPlan, WorkflowPlanBuilder};
pub use source::{
    Located, PlanSourceLocation, PlanSourceOrigin, PlanSourceSpan, WorkflowEventProvenance,
    WorkflowSourceProvenance,
};
pub use step::{PlannedStep, PlannedStepBuilder, PlannedStepKind};
pub use validation::WorkflowPlanError;
pub use value::{
    ActionInputsPlan, ConcurrencyPlan, DeferredBoolean, EnvironmentPlan, PermissionGrant,
    PermissionLevel, QueuePolicy, RunDefaultsPlan, RunStepPlan, RunnerProfile, UsesStepPlan,
    ValueMapPlan, WorkflowPermissions,
};
pub use version::{WORKFLOW_PLAN_SCHEMA_VERSION, WorkflowPlanVersion};
