//! Workflow-plan validation failures.

use thiserror::Error;

/// Maximum cumulative number of semantic nodes in one logical-workflow plan.
pub const MAX_LOGICAL_PLAN_NODES: usize = 65_536;
/// Maximum cumulative UTF-8 text retained by one logical-workflow plan.
pub const MAX_LOGICAL_PLAN_TEXT_BYTES: usize = 4 * 1024 * 1024;

pub(super) struct LogicalPlanBudget {
    nodes: usize,
    text_bytes: usize,
}

impl LogicalPlanBudget {
    pub(super) const fn new() -> Self {
        Self {
            nodes: 0,
            text_bytes: 0,
        }
    }

    pub(super) fn charge_node(&mut self, field: &'static str) -> Result<(), WorkflowPlanError> {
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or(WorkflowPlanError::LimitExceeded {
                field,
                maximum: MAX_LOGICAL_PLAN_NODES,
            })?;
        if self.nodes > MAX_LOGICAL_PLAN_NODES {
            return Err(WorkflowPlanError::LimitExceeded {
                field,
                maximum: MAX_LOGICAL_PLAN_NODES,
            });
        }
        Ok(())
    }

    pub(super) fn charge_text(
        &mut self,
        field: &'static str,
        value: &str,
        item_maximum: usize,
    ) -> Result<(), WorkflowPlanError> {
        if value.len() > item_maximum {
            return Err(WorkflowPlanError::LimitExceeded {
                field,
                maximum: item_maximum,
            });
        }
        self.text_bytes =
            self.text_bytes
                .checked_add(value.len())
                .ok_or(WorkflowPlanError::LimitExceeded {
                    field: "logical plan text",
                    maximum: MAX_LOGICAL_PLAN_TEXT_BYTES,
                })?;
        if self.text_bytes > MAX_LOGICAL_PLAN_TEXT_BYTES {
            return Err(WorkflowPlanError::LimitExceeded {
                field: "logical plan text",
                maximum: MAX_LOGICAL_PLAN_TEXT_BYTES,
            });
        }
        Ok(())
    }
}

/// A structural or versioning error that prevents scheduling a workflow plan.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkflowPlanError {
    /// The workflow plan uses reserved schema version zero.
    #[error("workflow-plan versions must be positive")]
    ZeroPlanVersion,
    /// An expression uses reserved schema version zero.
    #[error("workflow-expression versions must be positive")]
    ZeroExpressionVersion,
    /// The workflow plan uses a schema newer than this build understands.
    #[error("unsupported workflow-plan schema {received}; this build supports through {supported}")]
    UnsupportedPlanVersion {
        /// Newest plan schema understood by this build.
        supported: u16,
        /// Schema carried by the plan.
        received: u16,
    },
    /// An expression uses a schema this build cannot evaluate safely.
    #[error("unsupported workflow-expression schema {received}; this build supports {supported}")]
    UnsupportedExpressionVersion {
        /// Expression schema understood by this build.
        supported: u16,
        /// Schema carried by the expression.
        received: u16,
    },
    /// A named required field contains no value.
    #[error("required field `{0}` is empty")]
    EmptyField(&'static str),
    /// A source coordinate uses a zero line or column.
    #[error("source line and column must be one-based")]
    InvalidSourceLocation,
    /// A source span ends before its start coordinate.
    #[error("source span end precedes its start")]
    ReversedSourceSpan,
    /// An expression contains no literal or evaluated segment.
    #[error("workflow expression must contain at least one segment")]
    EmptyExpressionSegments,
    /// One evaluated expression segment contains no source text.
    #[error("workflow expression contains an empty evaluation")]
    EmptyEvaluation,
    /// Concatenating expression segments does not reproduce preserved source.
    #[error("workflow expression segments do not reconstruct their preserved source")]
    ExpressionSourceMismatch,
    /// The number of compiled programs differs from evaluated source segments.
    #[error(
        "compiled expression program count does not match evaluation segments: expected {expected}, received {received}"
    )]
    ExpressionProgramCountMismatch {
        /// Number of programs implied by evaluated segments.
        expected: usize,
        /// Number of compiled programs attached to the expression.
        received: usize,
    },
    /// One compiled program does not retain the source of its evaluated segment.
    #[error("compiled expression program {index} does not preserve its evaluation segment source")]
    ExpressionProgramSourceMismatch {
        /// Zero-based program and evaluation-segment index.
        index: usize,
    },
    /// A typed identifier does not satisfy its canonical key grammar.
    #[error("invalid {kind} `{value}`")]
    InvalidKey {
        /// Human-readable identifier kind.
        kind: &'static str,
        /// Rejected identifier value.
        value: String,
    },
    /// A schedulable plan contains no jobs.
    #[error("a workflow plan must contain at least one job")]
    NoJobs,
    /// The same canonical job identifier appears more than once.
    #[error("job `{0}` appears more than once")]
    DuplicateJob(String),
    /// A job declares a dependency absent from the plan.
    #[error("job `{job}` needs unknown job `{dependency}`")]
    UnknownDependency {
        /// Job that declares the dependency.
        job: String,
        /// Missing dependency identifier.
        dependency: String,
    },
    /// A job declares itself as a dependency.
    #[error("job `{0}` cannot need itself")]
    SelfDependency(String),
    /// The job dependency graph is not acyclic.
    #[error("workflow job graph contains a dependency cycle")]
    DependencyCycle,
    /// A concrete job contains no semantic steps.
    #[error("job `{0}` must contain at least one step")]
    NoSteps(String),
    /// The same canonical step identifier appears twice within one job.
    #[error("step `{step}` appears more than once in job `{job}`")]
    DuplicateStep {
        /// Job containing the duplicate identifier.
        job: String,
        /// Duplicate step identifier.
        step: String,
    },
    /// A named timeout is explicitly zero.
    #[error("timeout cannot be zero for `{0}`")]
    ZeroTimeout(String),
    /// A named positive integer field is zero.
    #[error("{field} must be greater than zero")]
    ZeroPositiveInteger {
        /// Name of the invalid field.
        field: &'static str,
    },
    /// Scaling a timeout into seconds would overflow its representation.
    #[error("{field} cannot be represented in seconds without overflow")]
    TimeoutScaleOverflow {
        /// Name of the overflowing timeout field.
        field: &'static str,
    },
    /// A job runner profile specifies neither a group nor labels.
    #[error("runner profile for job `{0}` has neither a group nor labels")]
    EmptyRunnerProfile(String),
    /// A value-map layer repeats one canonical key.
    #[error("key `{0}` appears more than once in one value-map layer")]
    DuplicateValueKey(String),
    /// A permissions map repeats one canonical permission name.
    #[error("permission `{0}` appears more than once")]
    DuplicatePermission(String),
    /// Workflow source and trigger event come from different providers.
    #[error(
        "workflow source provider `{source_provider}` does not match event provider `{event_provider}`"
    )]
    ProviderMismatch {
        /// Provider that supplied the workflow source.
        source_provider: String,
        /// Provider that supplied the trigger event.
        event_provider: String,
    },
    /// The outer plan span names a different immutable source identity.
    #[error("workflow plan span belongs to a different source identity")]
    PlanSourceMismatch,
    /// A bounded collection, string, or aggregate plan budget is exceeded.
    #[error("{field} exceeds the bounded maximum of {maximum}")]
    LimitExceeded {
        /// Name of the bounded field or aggregate budget.
        field: &'static str,
        /// Maximum accepted count or UTF-8 byte length.
        maximum: usize,
    },
    /// A nested source span names a different immutable source identity.
    #[error("{field} belongs to a different source identity")]
    NestedSourceMismatch {
        /// Name of the nested source-bearing field.
        field: &'static str,
    },
    /// A definition collection repeats one canonical key.
    #[error("{field} contains duplicate key `{key}`")]
    DuplicateDefinition {
        /// Definition collection containing the duplicate.
        field: &'static str,
        /// Duplicate canonical key.
        key: String,
    },
    /// Logical jobs are not stored in strictly increasing source order.
    #[error("logical job source order must be strictly increasing")]
    NonCanonicalJobOrder,
    /// A logical result expression names a job absent from the plan.
    #[error("logical job `{job}` references unknown result job `{dependency}`")]
    UnknownResultJob {
        /// Job containing the result reference.
        job: String,
        /// Missing result-producing job.
        dependency: String,
    },
    /// A logical result references a job not declared as a dependency.
    #[error("logical job `{job}` references `{dependency}` without declaring it in needs")]
    ResultNotDependency {
        /// Job containing the result reference.
        job: String,
        /// Referenced job absent from the dependency set.
        dependency: String,
    },
    /// A logical result names an output not defined by its source job.
    #[error("logical result references unknown output `{output}` on job `{job}`")]
    UnknownResultOutput {
        /// Job expected to define the output.
        job: String,
        /// Missing output identifier.
        output: String,
    },
    /// An expression names a context before that context becomes available.
    #[error(
        "expression context `{context}` is unavailable during `{phase}`; earliest phase is `{minimum}`"
    )]
    ExpressionContextUnavailable {
        /// Named-value context used by the expression.
        context: &'static str,
        /// Phase in which the expression is evaluated.
        phase: &'static str,
        /// Earliest phase that supplies the context.
        minimum: &'static str,
    },
    /// An expression's context declaration repeats one named-value root.
    #[error("expression context `{0}` appears more than once")]
    DuplicateExpressionContext(&'static str),
    /// Declared expression contexts are not stored in canonical sorted order.
    #[error("expression contexts must be stored in canonical sorted order")]
    NonCanonicalExpressionContexts,
    /// Compiled expression bytecode refers to an unsupported named-value root.
    #[error("compiled expression contains an unsupported named-value root")]
    UnsupportedExpressionNamedValue,
    /// Declared named-value contexts disagree with compiled expression usage.
    #[error("declared expression contexts do not match compiled named-value roots")]
    ExpressionProgramContextMismatch,
    /// A template requests a value after its latest supported evaluation phase.
    #[error("{field} is only available through `{latest}`, not `{actual}`")]
    TemplatePhaseTooLate {
        /// Template field whose phase is invalid.
        field: &'static str,
        /// Latest phase in which the field may be evaluated.
        latest: &'static str,
        /// Phase declared by the template.
        actual: &'static str,
    },
    /// A literal template is marked for a non-admission evaluation phase.
    #[error("literal value templates must use the admission phase")]
    NonCanonicalLiteralPhase,
    /// A workflow strategy uses a schema this build cannot interpret safely.
    #[error("unsupported workflow-strategy schema {received}; this build supports {supported}")]
    UnsupportedStrategyVersion {
        /// Strategy schema understood by this build.
        supported: u16,
        /// Schema carried by the strategy.
        received: u16,
    },
    /// A workflow strategy uses reserved schema version zero.
    #[error("workflow-strategy versions must be positive")]
    ZeroStrategyVersion,
    /// A matrix expansion ceiling is zero or above the supported maximum.
    #[error("matrix expansion limit must be between 1 and {maximum}")]
    InvalidMatrixExpansionLimit {
        /// Largest supported matrix expansion.
        maximum: usize,
    },
    /// A named matrix axis contains no candidate values.
    #[error("matrix axis `{0}` has no values")]
    EmptyMatrixAxis(String),
    /// A structured matrix contains neither axes nor explicit include rows.
    #[error("matrix has no axes or include entries")]
    EmptyMatrix,
    /// Whole-matrix expression form is mixed with structured matrix fields.
    #[error("whole-matrix expressions cannot be combined with axes, include, or exclude")]
    MixedMatrixForms,
    /// A number does not use the canonical bounded decimal representation.
    #[error("invalid canonical decimal number `{0}`")]
    InvalidNumber(String),
    /// An invocation input's default does not match its declared type.
    #[error("invocation input `{input}` has a default with the wrong type")]
    InvocationDefaultTypeMismatch {
        /// Invocation input with the incompatible default.
        input: String,
    },
    /// A required invocation input also supplies a default value.
    #[error("required invocation input `{0}` cannot also define a default")]
    RequiredInputHasDefault(String),
    /// A logical job field is incompatible with that job's execution kind.
    #[error("logical job `{job}` has incompatible {field} semantics for its job kind")]
    IncompatibleLogicalJobField {
        /// Logical job containing the incompatible value.
        job: String,
        /// Field whose semantics are incompatible.
        field: &'static str,
    },
    /// A job without a strategy requests a multi-instance output merge policy.
    #[error("logical job `{job}` must use single-instance output merging without a strategy")]
    InvalidOutputMergePolicy {
        /// Logical job with the invalid merge policy.
        job: String,
    },
    /// A public output expression directly depends on the secrets context.
    #[error("output `{0}` directly references secrets but is marked public")]
    PublicOutputReferencesSecrets(String),
}
