//! Immutable, provider-neutral workflow DAG produced before job expansion.

mod expression;
mod identifier;
mod invocation;
mod logical;
mod plan;
mod source;
mod strategy;
mod template;
mod validation;
mod value;
mod version;

pub use expression::{
    ExpressionSegment, PlanExpression, WORKFLOW_EXPRESSION_SCHEMA_VERSION,
    WorkflowExpressionVersion,
};
pub use identifier::{
    WorkflowInputKey, WorkflowJobKey, WorkflowOutputKey, WorkflowSecretKey, WorkflowServiceKey,
    WorkflowStepKey,
};
pub use invocation::{
    InvocationInputDefault, InvocationInputDefinition, InvocationInputType,
    InvocationSecretDefinition, MAX_INVOCATION_DEFINITIONS, MAX_INVOCATION_TEXT_BYTES,
    OutputSensitivity, WorkflowInvocationContract, WorkflowOutputDefinition,
};
pub use logical::{
    DeploymentSelection, LogicalConcurrencyTemplate, LogicalJobKind, LogicalJobOutputDefinition,
    LogicalJobOutputSource, LogicalJobResourcesTemplate, LogicalJobTemplate,
    LogicalJobTemplateBuilder, LogicalOutputMergePolicy, LogicalResourceVectorTemplate,
    LogicalResultReference, LogicalResultValue, LogicalRunDefaultsTemplate, LogicalRunStepTemplate,
    LogicalRunnerTemplate, LogicalServiceContainerTemplate, LogicalStepKind, LogicalStepTemplate,
    LogicalStepTemplateBuilder, LogicalTimeoutTemplate, LogicalTimeoutUnit,
    LogicalUsesStepTemplate, LogicalWorkflowPlan, MAX_LOGICAL_FIELD_BYTES, MAX_LOGICAL_JOB_NEEDS,
    MAX_LOGICAL_JOB_OUTPUTS, MAX_LOGICAL_JOBS, MAX_LOGICAL_RESULT_REFERENCES,
    MAX_LOGICAL_RUNNER_LABELS, MAX_LOGICAL_SERVICE_OPTIONS, MAX_LOGICAL_SERVICE_PORTS,
    MAX_LOGICAL_SERVICES, MAX_LOGICAL_STEPS, MAX_REUSABLE_BINDINGS, MAX_TEMPLATE_MAP_ENTRIES,
    PermissionSnapshotRequest, ReusableInputBinding, ReusableSecretBinding,
    ReusableSecretForwarding, ReusableWorkflowInvocation, StepJobTemplate, TemplateValueMap,
};
pub use plan::{LogicalWorkflowPlanBuilder, WorkflowPlan};
pub use source::{
    Located, PlanSourceLocation, PlanSourceOrigin, PlanSourceSpan, WorkflowEventProvenance,
    WorkflowSourceProvenance,
};
pub use strategy::{
    MAX_MATRIX_AXES, MAX_MATRIX_AXIS_VALUES, MAX_MATRIX_EXPANSION, MAX_MATRIX_OBJECT_ENTRIES,
    MAX_MATRIX_PATCHES, MAX_MATRIX_TEXT_BYTES, MAX_MATRIX_VALUE_DEPTH, MatrixAxis,
    MatrixAxisValues, MatrixPatch, MatrixPatchSet, MatrixTemplate, MatrixValue,
    MatrixValueTemplate, WORKFLOW_STRATEGY_SCHEMA_VERSION, WorkflowStrategyTemplate,
    WorkflowStrategyVersion,
};
pub use template::{
    CompiledBooleanTemplate, CompiledExpressionTemplate, CompiledPositiveIntegerTemplate,
    CompiledValueTemplate, ExpressionContext, MAX_EXPRESSION_CONTEXTS, MAX_TEMPLATE_BYTES,
    MAX_TEMPLATE_SEGMENTS, PlanEvaluationPhase,
};
pub use validation::{MAX_LOGICAL_PLAN_NODES, MAX_LOGICAL_PLAN_TEXT_BYTES, WorkflowPlanError};
pub use value::{PermissionGrant, PermissionLevel, QueuePolicy, WorkflowPermissions};
pub use version::{WORKFLOW_PLAN_SCHEMA_VERSION, WorkflowPlanVersion};
