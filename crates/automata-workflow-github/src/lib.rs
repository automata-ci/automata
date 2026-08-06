#![forbid(unsafe_code)]
#![doc = "A loss-aware, source-level frontend for GitHub Actions workflow YAML."]

mod decode;
mod diagnostic;
mod frontend;
mod model;
mod source;
mod syntax;

pub use diagnostic::{Diagnostic, DiagnosticKind, DiagnosticSeverity, RelatedDiagnostic};
pub use frontend::{
    FrontendReport, GithubFrontendReport, GithubWorkflowFrontend, ParseWorkflowRequest,
    WorkflowFrontend, WorkflowParseLimits,
};
pub use model::{
    ActionStep, BooleanValue, Concurrency, ConcurrencyQueue, Defaults, DetailedConcurrency,
    EnvironmentVariables, EventName, EventTrigger, GithubWorkflow, GithubWorkflowSourcePlan, Job,
    JobId, Needs, PermissionEntry, PermissionLevel, Permissions, PreservedField,
    PushPullRequestFilter, RunDefaults, RunStep, RunnerSelection, SOURCE_PLAN_SCHEMA_VERSION,
    ScalarValue, SourcePlanVersion, Step, StepExecution, StepId, TriggerConfiguration, TriggerSet,
    ValueMap, ValueMapEntry, WorkflowJob, WorkflowTriggers,
};
pub use source::{
    SourceFile, SourceId, SourceLocation, SourceModelError, SourceOrigin, SourceProvenance,
    SourceSpan, Spanned,
};
pub use syntax::{
    AnchorId, ScalarResolution, ScalarStyle, YamlAlias, YamlDocument, YamlMappingEntry, YamlNode,
    YamlNodeKind, YamlScalar, YamlTag,
};
