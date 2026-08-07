#![forbid(unsafe_code)]
#![doc = "A loss-aware, source-level frontend for GitHub Actions workflow YAML."]

mod compiler;
mod decode;
mod diagnostic;
mod evaluator;
mod expression;
mod frontend;
mod model;
mod source;
mod syntax;

pub use compiler::{
    CompilationReport, CompileWorkflowRequest, GithubWorkflowCompiler, WorkflowCompiler,
};
pub use diagnostic::{Diagnostic, DiagnosticKind, DiagnosticSeverity, RelatedDiagnostic};
pub use evaluator::{
    DEFAULT_GITHUB_LINUX_SHELL_TEMPLATE, EvaluateJobRequest, GithubJobContext,
    GithubJobContextBuilder, GithubJobEvaluator, GithubRunnerProfileCatalog,
    GithubRunnerProfileMapping, GithubTargetPathStyle, GithubWorkspacePath,
    JobEvaluationInputError, JobEvaluationReport, WorkflowJobEvaluator,
};
pub use expression::{
    GITHUB_EXPRESSION_DIALECT, GITHUB_EXPRESSION_DIALECT_VERSION,
    GITHUB_EXPRESSION_MAX_UTF16_UNITS, GithubConditionCompiler, GithubConditionPhase,
    GithubExpressionError, GithubExpressionErrorKind, GithubExpressionLimitError,
    GithubExpressionLimits,
};
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
