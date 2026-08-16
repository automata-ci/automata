#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![doc = "A loss-aware, source-level frontend for GitHub Actions workflow YAML."]

mod compiler;
mod decode;
mod diagnostic;
mod expression;
mod frontend;
mod model;
mod repository_archive;
mod repository_path;
mod runner_profile;
mod schedule;
mod source;
mod syntax;

pub use compiler::{
    CompilationDisposition, CompilationReport, CompileWorkflowRequest, GithubWorkflowCompiler,
    WorkflowNotSelectedReason,
};
pub use diagnostic::{Diagnostic, DiagnosticKind, DiagnosticSeverity, RelatedDiagnostic};
pub use expression::{
    GITHUB_EXPRESSION_DIALECT, GITHUB_EXPRESSION_DIALECT_VERSION,
    GITHUB_EXPRESSION_MAX_UTF16_UNITS, GithubConditionCompiler, GithubConditionPhase,
    GithubExpressionError, GithubExpressionErrorKind, GithubExpressionLimitError,
    GithubExpressionLimits,
};
pub use frontend::{
    FrontendReport, GithubFrontendReport, GithubWorkflowFrontend, ParseWorkflowRequest,
    WorkflowFrontend,
};
pub use model::{
    ActionStep, BooleanValue, Concurrency, ConcurrencyQueue, ContainerCredentials,
    ContainerEnvironment, ContainerSequence, Defaults, DetailedConcurrency, DetailedContainer,
    DetailedJobEnvironment, EnvironmentVariables, EventName, EventTrigger, GithubChangedFiles,
    GithubEventMetadata, GithubWorkflow, GithubWorkflowDispatchContract,
    GithubWorkflowDispatchInputDefault, GithubWorkflowDispatchInputDefinition,
    GithubWorkflowDispatchInputType, GithubWorkflowDispatchInputValue,
    GithubWorkflowDispatchInputs, GithubWorkflowDispatchInputsError, GithubWorkflowSourcePlan, Job,
    JobContainer, JobEnvironment, JobId, JobOutputs, JobResourceVector, JobResources, JobService,
    JobServices, JobStrategy, MAX_GITHUB_WORKFLOW_DISPATCH_INPUT_CHARACTERS,
    MAX_GITHUB_WORKFLOW_DISPATCH_INPUTS, MatrixConfiguration, MatrixConfigurations,
    MatrixDimension, MatrixDimensionValues, MatrixMapping, MatrixValue, MatrixValueEntry,
    MergeGroupFilter, Needs, PermissionEntry, PermissionLevel, Permissions, PreservedField,
    PushPullRequestFilter, RepositoryDispatchFilter, ReusableWorkflowCall, ReusableWorkflowInputs,
    ReusableWorkflowSecretMap, ReusableWorkflowSecrets, RunDefaults, RunStep, RunnerSelection,
    ScalarValue, Step, StepExecution, StepId, StrategyMatrix, TriggerConfiguration, TriggerSet,
    ValueMap, ValueMapEntry, WorkflowJob, WorkflowTriggers,
};
pub use repository_archive::{
    MAX_REPOSITORY_WORKFLOW_PATH_BYTES, RepositoryWorkflowDiscoveryError,
    RepositoryWorkflowDiscoveryFailure, RepositoryWorkflowDiscoveryLimits,
    RepositoryWorkflowDiscoveryLimitsError, RepositoryWorkflowDiscoveryOutcome,
    RepositoryWorkflowDiscoveryPolicy, RepositoryWorkflowLocation, discover_repository_workflows,
};
pub use repository_path::{
    RepositoryPathValidationError, RepositoryPathValidator, USTAR_LINK_NAME_BYTES,
};
pub use runner_profile::{
    GithubRunnerProfileCatalog, GithubRunnerProfileError, GithubRunnerProfileMapping,
};
pub use schedule::{
    GithubCronExpression, GithubScheduleEntry, GithubScheduleError, MAX_GITHUB_SCHEDULE_ENTRIES,
    MAX_GITHUB_SCHEDULE_EXPRESSION_BYTES, MAX_GITHUB_SCHEDULE_TIMEZONE_BYTES,
    extract_github_schedule_entries, validate_github_schedule_timezone,
};
pub use source::{
    SourceFile, SourceId, SourceLocation, SourceModelError, SourceOrigin, SourceProvenance,
    SourceSpan, Spanned,
};
pub use syntax::{
    AnchorId, ScalarResolution, ScalarStyle, YamlAlias, YamlAliasExpansion, YamlDocument,
    YamlMappingEntry, YamlNode, YamlNodeKind, YamlScalar, YamlTag,
};
pub use syntax::{MAX_GITHUB_WORKFLOW_SOURCE_BYTES, ParseLimits as WorkflowParseLimits};
