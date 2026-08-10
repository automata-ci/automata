//! Deterministic activation of schema-v2 logical jobs into concrete contexts.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    ops::Deref,
    sync::Arc,
};

use automata_ci_core::{
    CompiledBooleanTemplate, CompiledExpressionTemplate, CompiledPositiveIntegerTemplate,
    CompiledValueTemplate, ContextValue, ExpressionContext, JobConclusion, JobInstanceIdentity,
    JobRuntimeContext, JobValidationError, LogicalJobKind, LogicalJobTemplate,
    MAX_CONTEXT_VALUE_NODES, MAX_CONTEXT_VALUE_TEXT_BYTES, MAX_LOGICAL_FIELD_BYTES,
    MAX_MATRIX_AXES, MAX_MATRIX_AXIS_VALUES, MAX_MATRIX_OBJECT_ENTRIES, MAX_MATRIX_PATCHES,
    MAX_MATRIX_TEXT_BYTES, MAX_MATRIX_VALUE_DEPTH, MAX_RUNTIME_CONTEXT_IDENTIFIER_BYTES,
    MatrixAxisValues, MatrixPatch, MatrixPatchSet, MatrixValue, MatrixValueTemplate, NeedContext,
    RunnerGroup, RunnerLabel, RuntimeContextError, SecretBinding, Sha256Digest, StrategyContext,
    WorkflowJobKey, WorkflowPlan, WorkflowPlanError,
};
use automata_ci_protocol::ProtocolLimits;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Maximum aggregate serialized runtime-context bytes emitted by one activation.
pub const MAX_ACTIVATION_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

/// Maximum raw Cartesian candidates inspected before matrix exclusions.
///
/// GitHub's generated-job limit is applied after exclusions and includes. This
/// separate bound prevents an exclusion-heavy matrix from becoming an
/// unbounded control-plane CPU or allocation request.
pub const MAX_MATRIX_CANDIDATE_COMBINATIONS: usize = 4_096;

/// Maximum combination/patch operations performed by one matrix expansion.
pub const MAX_MATRIX_EXPANSION_WORK: usize = 1_048_576;

const MATRIX_DIGEST_DOMAIN: &[u8] = b"automata-ci/matrix-instance/v1\0";

/// Insertion-stable value returned by a provider expression adapter.
///
/// Values are validated and bounded by [`LogicalJobActivator`] before they can
/// affect expansion or enter a durable runtime context. Object insertion order
/// is retained because matrix axis order determines concrete job order.
#[derive(Clone)]
pub enum ActivationValue {
    /// A provider null value.
    Null,
    /// A provider Boolean value.
    Boolean(bool),
    /// Exact IEEE-754 binary64 bits.
    Number(u64),
    /// A provider string value.
    String(String),
    /// An insertion-ordered provider array.
    Array(Vec<Self>),
    /// An insertion-ordered provider object.
    Object(Vec<(String, Self)>),
}

impl ActivationValue {
    /// Creates a canonical number value.
    #[must_use]
    pub const fn number(value: f64) -> Self {
        if value.is_nan() {
            Self::Number(f64::NAN.to_bits())
        } else {
            Self::Number(value.to_bits())
        }
    }

    /// Creates a string value.
    #[must_use]
    pub fn string(value: impl Into<String>) -> Self {
        Self::String(value.into())
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Boolean(_) => "boolean",
            Self::Number(_) => "number",
            Self::String(_) => "string",
            Self::Array(_) => "array",
            Self::Object(_) => "object",
        }
    }
}

impl PartialEq for ActivationValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Null, Self::Null) => true,
            (Self::Boolean(left), Self::Boolean(right)) => left == right,
            (Self::Number(left), Self::Number(right)) => numbers_equal(*left, *right),
            (Self::String(left), Self::String(right)) => left == right,
            (Self::Array(left), Self::Array(right)) => left == right,
            (Self::Object(left), Self::Object(right)) => left == right,
            _ => false,
        }
    }
}

impl Eq for ActivationValue {}

impl fmt::Debug for ActivationValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => formatter.write_str("ActivationValue::Null"),
            Self::Boolean(_) => formatter.write_str("ActivationValue::Boolean([REDACTED])"),
            Self::Number(_) => formatter.write_str("ActivationValue::Number([REDACTED])"),
            Self::String(value) => formatter
                .debug_tuple("ActivationValue::String")
                .field(&format_args!("{} bytes [REDACTED]", value.len()))
                .finish(),
            Self::Array(values) => formatter
                .debug_tuple("ActivationValue::Array")
                .field(&format_args!("{} items [REDACTED]", values.len()))
                .finish(),
            Self::Object(values) => formatter
                .debug_tuple("ActivationValue::Object")
                .field(&format_args!("{} entries [REDACTED]", values.len()))
                .finish(),
        }
    }
}

fn numbers_equal(left: u64, right: u64) -> bool {
    normalized_number_bits(left) == normalized_number_bits(right)
}

fn normalized_number_bits(bits: u64) -> u64 {
    if bits.trailing_zeros() >= 63 {
        0
    } else if f64::from_bits(bits).is_nan() {
        f64::NAN.to_bits()
    } else {
        bits
    }
}

/// Stable field being evaluated during logical-job activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationEvaluationSite {
    /// The job-level execution condition.
    JobCondition,
    /// The concrete job display name.
    JobName,
    /// The runner-group selector.
    RunnerGroup,
    /// One runner-label selector.
    RunnerLabel,
    /// The job timeout.
    JobTimeout,
    /// The strategy's fail-fast setting.
    StrategyFailFast,
    /// The strategy's maximum parallelism.
    StrategyMaxParallel,
    /// An expression producing the entire matrix definition.
    WholeMatrix,
    /// One matrix axis or one of its values.
    MatrixAxis,
    /// A matrix include patch.
    MatrixInclude,
    /// A matrix exclude patch.
    MatrixExclude,
    /// The job-level continue-on-error setting.
    JobContinueOnError,
}

impl fmt::Display for ActivationEvaluationSite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::JobCondition => "job condition",
            Self::JobName => "job name",
            Self::RunnerGroup => "runner group",
            Self::RunnerLabel => "runner label",
            Self::JobTimeout => "job timeout",
            Self::StrategyFailFast => "strategy fail-fast",
            Self::StrategyMaxParallel => "strategy max-parallel",
            Self::WholeMatrix => "whole matrix",
            Self::MatrixAxis => "matrix axis",
            Self::MatrixInclude => "matrix include",
            Self::MatrixExclude => "matrix exclude",
            Self::JobContinueOnError => "job continue-on-error",
        })
    }
}

/// Integrity-bound aggregate status visible to activation-time status functions.
///
/// This is intentionally separate from the direct `needs` map. Providers such
/// as GitHub Actions define `failure()` across the complete prerequisite chain
/// and `cancelled()` from workflow cancellation state, neither of which can be
/// reconstructed from direct prerequisite results alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationStatus {
    /// All prerequisite-chain work relevant to this job succeeded.
    Success,
    /// At least one relevant prerequisite-chain job failed.
    Failure,
    /// Workflow cancellation applies to this activation.
    Cancelled,
    /// Relevant prerequisite-chain work was skipped.
    Skipped,
}

/// Immutable contexts available to a provider expression adapter.
pub struct ActivationEvaluationContext<'a> {
    job_key: &'a WorkflowJobKey,
    inputs: &'a ContextValue,
    vars: &'a ContextValue,
    needs: &'a BTreeMap<String, NeedContext>,
    status: ActivationStatus,
    matrix: Option<&'a ContextValue>,
    strategy: Option<StrategyContext>,
}

impl fmt::Debug for ActivationEvaluationContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActivationEvaluationContext")
            .field("job_key", &self.job_key)
            .field("inputs", &"[REDACTED]")
            .field("vars", &"[REDACTED]")
            .field(
                "needs",
                &format_args!("{} jobs [REDACTED]", self.needs.len()),
            )
            .field("status", &self.status)
            .field("matrix", &self.matrix.map(|_| "[REDACTED]"))
            .field("strategy", &self.strategy)
            .finish()
    }
}

impl ActivationEvaluationContext<'_> {
    /// Returns the logical job being evaluated.
    #[must_use]
    pub const fn job_key(&self) -> &WorkflowJobKey {
        self.job_key
    }

    /// Returns the immutable workflow input context.
    #[must_use]
    pub const fn inputs(&self) -> &ContextValue {
        self.inputs
    }

    /// Returns the immutable repository variable context.
    #[must_use]
    pub const fn vars(&self) -> &ContextValue {
        self.vars
    }

    /// Returns direct prerequisite results and public outputs.
    #[must_use]
    pub const fn needs(&self) -> &BTreeMap<String, NeedContext> {
        self.needs
    }

    /// Returns the integrity-bound aggregate prerequisite status.
    #[must_use]
    pub const fn status(&self) -> ActivationStatus {
        self.status
    }

    /// Returns the current concrete matrix value, when expansion has begun.
    #[must_use]
    pub const fn matrix(&self) -> Option<&ContextValue> {
        self.matrix
    }

    /// Returns the current concrete strategy context, when expansion has begun.
    #[must_use]
    pub const fn strategy(&self) -> Option<StrategyContext> {
        self.strategy
    }
}

/// Provider adapter that prepares one isolated logical-activation session.
pub trait LogicalActivationEvaluator: fmt::Debug + Send + Sync {
    /// Sanitized provider-specific preparation or evaluation failure.
    type Error: Error + Send + Sync + 'static;
    /// Provider-specific state isolated to one logical-job activation.
    type Session<'a>: LogicalActivationSession<Error = Self::Error>
    where
        Self: 'a;

    /// Converts immutable base contexts once for one activation.
    ///
    /// The returned session is local to the activation. Implementations must
    /// not retain mutable cross-request state that could mix concurrent jobs.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error when a base context cannot be represented by
    /// the provider expression dialect.
    fn prepare<'a>(
        &'a self,
        context: &ActivationEvaluationContext<'_>,
    ) -> Result<Self::Session<'a>, Self::Error>;
}

/// Provider-specific semantics bound to one prepared activation session.
pub trait LogicalActivationSession: fmt::Debug + Send + Sync {
    /// Sanitized provider-specific evaluation failure.
    type Error: Error + Send + Sync + 'static;

    /// Verifies provider-specific function availability for an evaluation site.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error when a compiled function is unavailable at
    /// the requested workflow key.
    fn validate_expression_site(
        &self,
        expression: &CompiledExpressionTemplate,
        site: ActivationEvaluationSite,
    ) -> Result<(), Self::Error>;

    /// Evaluates an expression without applying scalar coercion.
    ///
    /// # Errors
    ///
    /// Returns the provider adapter's sanitized evaluation error.
    fn evaluate_value(
        &self,
        expression: &CompiledExpressionTemplate,
        context: &ActivationEvaluationContext<'_>,
    ) -> Result<ActivationValue, Self::Error>;

    /// Renders a possibly interpolated expression template as provider text.
    ///
    /// # Errors
    ///
    /// Returns the provider adapter's sanitized evaluation or resource error.
    fn evaluate_string(
        &self,
        expression: &CompiledExpressionTemplate,
        context: &ActivationEvaluationContext<'_>,
    ) -> Result<String, Self::Error>;

    /// Evaluates a job condition with the provider's exact truthiness semantics.
    ///
    /// # Errors
    ///
    /// Returns the provider adapter's sanitized evaluation error.
    fn evaluate_condition(
        &self,
        expression: &CompiledExpressionTemplate,
        context: &ActivationEvaluationContext<'_>,
    ) -> Result<bool, Self::Error>;

    /// Evaluates a field whose result must be a typed Boolean.
    ///
    /// # Errors
    ///
    /// Returns the provider adapter's sanitized evaluation or type error.
    fn evaluate_boolean(
        &self,
        expression: &CompiledExpressionTemplate,
        context: &ActivationEvaluationContext<'_>,
    ) -> Result<bool, Self::Error>;

    /// Evaluates and coerces a strategy integer using provider semantics.
    ///
    /// # Errors
    ///
    /// Returns the provider adapter's sanitized evaluation or coercion error.
    fn evaluate_positive_integer(
        &self,
        expression: &CompiledExpressionTemplate,
        context: &ActivationEvaluationContext<'_>,
    ) -> Result<u32, Self::Error>;

    /// Produces the provider's canonical lookup key for a matrix property.
    fn normalize_matrix_key(&self, key: &str) -> String;

    /// Compares matrix leaf values using provider semantics.
    fn matrix_values_equal(&self, left: &ActivationValue, right: &ActivationValue) -> bool;

    /// Directionally matches an original matrix value against an exclude patch.
    fn matrix_value_matches(&self, original: &ActivationValue, patch: &ActivationValue) -> bool;
}

/// Schema-v2 plan validated once before any logical-job activation.
#[derive(Clone, Copy)]
pub struct ValidatedLogicalPlan<'a> {
    plan: &'a WorkflowPlan,
}

impl fmt::Debug for ValidatedLogicalPlan<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedLogicalPlan")
            .field("job_count", &self.plan.jobs().len())
            .finish_non_exhaustive()
    }
}

impl<'a> ValidatedLogicalPlan<'a> {
    /// Validates a complete logical plan once at the activation trust boundary.
    ///
    /// # Errors
    ///
    /// Rejects malformed current logical plans.
    pub fn new(plan: &'a WorkflowPlan) -> Result<Self, LogicalActivationRequestError> {
        plan.validate()
            .map_err(LogicalActivationRequestError::InvalidPlan)?;
        Ok(Self { plan })
    }

    /// Selects a job from the already validated logical graph.
    ///
    /// # Errors
    ///
    /// Rejects a key that is not part of this plan.
    pub fn job(
        &self,
        key: &WorkflowJobKey,
    ) -> Result<ValidatedLogicalJob<'a>, LogicalActivationRequestError> {
        let job = self
            .plan
            .jobs()
            .iter()
            .find(|job| job.key().value() == key)
            .ok_or(LogicalActivationRequestError::UnknownLogicalJob)?;
        Ok(ValidatedLogicalJob {
            plan: self.plan,
            job,
        })
    }
}

/// Logical job borrowed from a fully validated schema-v2 workflow plan.
#[derive(Clone, Copy)]
pub struct ValidatedLogicalJob<'a> {
    plan: &'a WorkflowPlan,
    job: &'a LogicalJobTemplate,
}

impl fmt::Debug for ValidatedLogicalJob<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedLogicalJob")
            .field("key", self.job.key().value())
            .finish_non_exhaustive()
    }
}

impl Deref for ValidatedLogicalJob<'_> {
    type Target = LogicalJobTemplate;

    fn deref(&self) -> &Self::Target {
        self.job
    }
}

impl ValidatedLogicalJob<'_> {
    /// Returns the complete validated plan that owns this logical job.
    #[must_use]
    pub const fn plan(&self) -> &WorkflowPlan {
        self.plan
    }
}

/// Invalid activation handle construction.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum LogicalActivationRequestError {
    /// The complete workflow plan failed current-schema validation.
    #[error("workflow plan failed activation-boundary validation")]
    InvalidPlan(#[source] WorkflowPlanError),
    /// The selected logical job key is absent from the validated plan.
    #[error("logical job is not part of the validated workflow plan")]
    UnknownLogicalJob,
}

/// Borrowed immutable inputs for one logical-job activation.
#[derive(Clone, Copy)]
pub struct ActivateLogicalJobRequest<'a> {
    job: ValidatedLogicalJob<'a>,
    inputs: &'a ContextValue,
    vars: &'a ContextValue,
    needs: &'a BTreeMap<String, NeedContext>,
    secrets: &'a BTreeMap<String, SecretBinding>,
    status: ActivationStatus,
}

impl fmt::Debug for ActivateLogicalJobRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActivateLogicalJobRequest")
            .field("job", &self.job.key().value())
            .field("inputs", &"[REDACTED]")
            .field("vars", &"[REDACTED]")
            .field(
                "needs",
                &format_args!("{} jobs [REDACTED]", self.needs.len()),
            )
            .field(
                "secrets",
                &format_args!("{} bindings [REDACTED]", self.secrets.len()),
            )
            .field("status", &self.status)
            .finish()
    }
}

impl<'a> ActivateLogicalJobRequest<'a> {
    /// Binds a validated job to exact immutable activation contexts.
    #[must_use]
    pub const fn new(
        job: ValidatedLogicalJob<'a>,
        inputs: &'a ContextValue,
        vars: &'a ContextValue,
        needs: &'a BTreeMap<String, NeedContext>,
        secrets: &'a BTreeMap<String, SecretBinding>,
        status: ActivationStatus,
    ) -> Self {
        Self {
            job,
            inputs,
            vars,
            needs,
            secrets,
            status,
        }
    }
}

/// Activation-resolved runner selectors for one concrete job instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivatedRunnerSelection {
    group: Option<RunnerGroup>,
    labels: Vec<RunnerLabel>,
}

impl ActivatedRunnerSelection {
    /// Returns the optional activation-resolved runner group.
    #[must_use]
    pub const fn group(&self) -> Option<&RunnerGroup> {
        self.group.as_ref()
    }

    /// Returns the activation-resolved runner labels in source order.
    #[must_use]
    pub fn labels(&self) -> &[RunnerLabel] {
        &self.labels
    }
}

/// One concrete matrix instance with its immutable runtime context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivatedJobInstance {
    identity: JobInstanceIdentity,
    runtime_context: JobRuntimeContext,
    name: String,
    runner: Option<ActivatedRunnerSelection>,
    timeout_seconds: Option<u32>,
    continue_on_error: bool,
}

impl ActivatedJobInstance {
    /// Returns the deterministic concrete job-instance identity.
    #[must_use]
    pub const fn identity(&self) -> &JobInstanceIdentity {
        &self.identity
    }

    /// Returns the immutable runtime context for this instance.
    #[must_use]
    pub const fn runtime_context(&self) -> &JobRuntimeContext {
        &self.runtime_context
    }

    /// Returns the activation-resolved display name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns resolved selectors for a step job, or `None` for a reusable call.
    #[must_use]
    pub const fn runner(&self) -> Option<&ActivatedRunnerSelection> {
        self.runner.as_ref()
    }

    /// Returns the activation-resolved timeout in seconds, when configured.
    #[must_use]
    pub const fn timeout_seconds(&self) -> Option<u32> {
        self.timeout_seconds
    }

    /// Returns the activation-resolved continue-on-error setting.
    #[must_use]
    pub const fn continue_on_error(&self) -> bool {
        self.continue_on_error
    }
}

/// Result of evaluating one logical job after all direct needs are terminal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalJobActivation {
    condition_matched: bool,
    instances: Vec<ActivatedJobInstance>,
}

impl LogicalJobActivation {
    /// Returns whether the job-level activation condition matched.
    #[must_use]
    pub const fn condition_matched(&self) -> bool {
        self.condition_matched
    }

    /// Returns the deterministic concrete instances in matrix order.
    #[must_use]
    pub fn instances(&self) -> &[ActivatedJobInstance] {
        &self.instances
    }
}

/// Deterministic, provider-neutral logical-job activator.
#[derive(Clone, Debug)]
pub struct LogicalJobActivator<E> {
    evaluator: E,
}

impl<E> LogicalJobActivator<E> {
    /// Creates an activator around one provider expression adapter.
    #[must_use]
    pub const fn new(evaluator: E) -> Self {
        Self { evaluator }
    }

    /// Returns the provider expression adapter.
    #[must_use]
    pub const fn evaluator(&self) -> &E {
        &self.evaluator
    }
}

impl<E> LogicalJobActivator<E>
where
    E: LogicalActivationEvaluator,
{
    /// Activates a logical job into zero or more concrete runtime contexts.
    ///
    /// # Errors
    ///
    /// Fails closed on missing/unexpected direct needs, provider evaluation
    /// errors, malformed dynamic matrix values, limit violations, or an
    /// invalid concrete identity/runtime context.
    pub fn activate(
        &self,
        request: ActivateLogicalJobRequest<'_>,
    ) -> Result<LogicalJobActivation, LogicalActivationError<E::Error>> {
        validate_request(&request)?;
        let base_context = ActivationEvaluationContext {
            job_key: request.job.key().value(),
            inputs: request.inputs,
            vars: request.vars,
            needs: request.needs,
            status: request.status,
            matrix: None,
            strategy: None,
        };
        let session = self
            .evaluator
            .prepare(&base_context)
            .map_err(|source| LogicalActivationError::Preparation { source })?;
        let condition_matched = Self::resolve_condition(request, &base_context, &session)?;
        if !condition_matched {
            return Ok(LogicalJobActivation {
                condition_matched: false,
                instances: Vec::new(),
            });
        }
        let strategy = Self::resolve_strategy(request, &base_context, &session)?;
        if strategy.matrices.is_empty() {
            return Ok(LogicalJobActivation {
                condition_matched: true,
                instances: Vec::new(),
            });
        }
        if strategy.matrices.len() > strategy.expansion_limit {
            return Err(LogicalActivationError::MatrixExpansionLimitExceeded {
                maximum: strategy.expansion_limit,
            });
        }
        Self::activate_instances(request, strategy, &session)
    }

    fn resolve_condition<S>(
        request: ActivateLogicalJobRequest<'_>,
        context: &ActivationEvaluationContext<'_>,
        session: &S,
    ) -> Result<bool, LogicalActivationError<E::Error>>
    where
        S: LogicalActivationSession<Error = E::Error>,
    {
        match request.job.condition() {
            Some(condition) => evaluate_condition(
                session,
                condition.value(),
                context,
                ActivationEvaluationSite::JobCondition,
            ),
            None => Ok(request.status == ActivationStatus::Success),
        }
    }

    fn resolve_strategy<S>(
        request: ActivateLogicalJobRequest<'_>,
        context: &ActivationEvaluationContext<'_>,
        session: &S,
    ) -> Result<ResolvedActivationStrategy, LogicalActivationError<E::Error>>
    where
        S: LogicalActivationSession<Error = E::Error>,
    {
        let Some(strategy) = request.job.strategy() else {
            return Ok(ResolvedActivationStrategy {
                matrices: vec![MatrixCombination::default()],
                fail_fast: true,
                max_parallel: Some(1),
                expansion_limit: 1,
                has_strategy: false,
            });
        };
        let fail_fast = resolve_boolean(
            strategy.fail_fast().map(automata_ci_core::Located::value),
            true,
            session,
            context,
            ActivationEvaluationSite::StrategyFailFast,
        )?;
        let max_parallel = resolve_positive_integer(
            strategy
                .max_parallel()
                .map(automata_ci_core::Located::value),
            session,
            context,
            ActivationEvaluationSite::StrategyMaxParallel,
        )?;
        let expansion_limit = usize::from(strategy.expansion_limit());
        Ok(ResolvedActivationStrategy {
            matrices: resolve_matrix(strategy.matrix(), expansion_limit, session, context)?,
            fail_fast,
            max_parallel,
            expansion_limit,
            has_strategy: true,
        })
    }

    fn activate_instances<S>(
        request: ActivateLogicalJobRequest<'_>,
        resolved: ResolvedActivationStrategy,
        session: &S,
    ) -> Result<LogicalJobActivation, LogicalActivationError<E::Error>>
    where
        S: LogicalActivationSession<Error = E::Error>,
    {
        let ResolvedActivationStrategy {
            matrices,
            fail_fast,
            max_parallel,
            expansion_limit,
            has_strategy,
        } = resolved;

        let total = u32::try_from(matrices.len()).map_err(|_| {
            LogicalActivationError::MatrixExpansionLimitExceeded {
                maximum: expansion_limit,
            }
        })?;
        let max_parallel = max_parallel.unwrap_or(total);
        let mut output_bytes = 0_usize;
        let mut instances = Vec::with_capacity(matrices.len());
        for (index, matrix) in matrices.into_iter().enumerate() {
            let matrix = matrix.into_context_value()?;
            let index = u32::try_from(index).map_err(|_| {
                LogicalActivationError::MatrixExpansionLimitExceeded {
                    maximum: expansion_limit,
                }
            })?;
            let strategy = StrategyContext::new(fail_fast, index, total, max_parallel)?;
            let evaluation_context = ActivationEvaluationContext {
                job_key: request.job.key().value(),
                inputs: request.inputs,
                vars: request.vars,
                needs: request.needs,
                status: request.status,
                matrix: has_strategy.then_some(&matrix),
                strategy: has_strategy.then_some(strategy),
            };
            let name = resolve_string(
                request.job.name().map(automata_ci_core::Located::value),
                request.job.key().value().as_str(),
                session,
                &evaluation_context,
                ActivationEvaluationSite::JobName,
            )?;
            if name.trim().is_empty()
                || name.len() > MAX_LOGICAL_FIELD_BYTES
                || name.chars().any(char::is_control)
            {
                return Err(LogicalActivationError::InvalidActivatedJobName);
            }
            let runner = resolve_runner(request.job, session, &evaluation_context)?;
            let timeout_seconds = resolve_timeout(request.job, session, &evaluation_context)?;
            let continue_on_error = resolve_boolean(
                request
                    .job
                    .continue_on_error()
                    .map(automata_ci_core::Located::value),
                false,
                session,
                &evaluation_context,
                ActivationEvaluationSite::JobContinueOnError,
            )?;
            let digest = matrix_digest(request.job.key().value(), &matrix)?;
            let identity =
                JobInstanceIdentity::new(request.job.key().value().as_str(), index, total, digest)?;
            let public_needs = public_runtime_needs(request.needs)?;
            let runtime_context = JobRuntimeContext::new(
                request.inputs.clone(),
                request.vars.clone(),
                matrix,
                strategy,
                public_needs,
                request.secrets.clone(),
            )?;
            let encoded = automata_ci_protocol_protobuf::encode_job_runtime_context(
                &runtime_context,
                &activation_protocol_limits(),
            )
            .map_err(LogicalActivationError::RuntimeContextEncoding)?;
            output_bytes = output_bytes.checked_add(encoded.len()).ok_or(
                LogicalActivationError::LimitExceeded {
                    field: "activation output bytes",
                    maximum: MAX_ACTIVATION_OUTPUT_BYTES,
                },
            )?;
            if output_bytes > MAX_ACTIVATION_OUTPUT_BYTES {
                return Err(LogicalActivationError::LimitExceeded {
                    field: "activation output bytes",
                    maximum: MAX_ACTIVATION_OUTPUT_BYTES,
                });
            }
            instances.push(ActivatedJobInstance {
                identity,
                runtime_context,
                name,
                runner,
                timeout_seconds,
                continue_on_error,
            });
        }
        Ok(LogicalJobActivation {
            condition_matched: true,
            instances,
        })
    }
}

fn public_runtime_needs<E>(
    needs: &BTreeMap<String, NeedContext>,
) -> Result<BTreeMap<String, NeedContext>, LogicalActivationError<E>>
where
    E: Error + Send + Sync + 'static,
{
    needs
        .iter()
        .map(|(job, need)| {
            let outputs = need
                .outputs()
                .iter()
                .filter(|(_, output)| output.public_value().is_some())
                .map(|(key, output)| (key.clone(), output.clone()))
                .collect();
            NeedContext::new(need.result(), outputs)
                .map(|need| (job.clone(), need))
                .map_err(LogicalActivationError::RuntimeContext)
        })
        .collect()
}

fn resolve_runner<E, S>(
    job: ValidatedLogicalJob<'_>,
    session: &S,
    context: &ActivationEvaluationContext<'_>,
) -> Result<Option<ActivatedRunnerSelection>, LogicalActivationError<E>>
where
    E: Error + Send + Sync + 'static,
    S: LogicalActivationSession<Error = E>,
{
    let LogicalJobKind::Steps(step_job) = job.execution() else {
        return Ok(None);
    };
    let runner = step_job.runner();
    let group = runner
        .group()
        .map(|value| {
            resolve_string(
                Some(value.value()),
                "",
                session,
                context,
                ActivationEvaluationSite::RunnerGroup,
            )
            .and_then(|value| {
                RunnerGroup::new(value)
                    .map_err(|_| LogicalActivationError::InvalidActivatedRunnerSelector)
            })
        })
        .transpose()?;
    let labels = runner
        .labels()
        .iter()
        .map(|value| {
            resolve_string(
                Some(value.value()),
                "",
                session,
                context,
                ActivationEvaluationSite::RunnerLabel,
            )
            .and_then(|value| {
                RunnerLabel::new(value)
                    .map_err(|_| LogicalActivationError::InvalidActivatedRunnerSelector)
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if group.is_none() && labels.is_empty() {
        return Err(LogicalActivationError::InvalidActivatedRunnerSelector);
    }
    Ok(Some(ActivatedRunnerSelection { group, labels }))
}

fn resolve_timeout<E, S>(
    job: ValidatedLogicalJob<'_>,
    session: &S,
    context: &ActivationEvaluationContext<'_>,
) -> Result<Option<u32>, LogicalActivationError<E>>
where
    E: Error + Send + Sync + 'static,
    S: LogicalActivationSession<Error = E>,
{
    let Some(timeout) = job.timeout() else {
        return Ok(None);
    };
    let value = resolve_positive_integer(
        Some(timeout.value().value()),
        session,
        context,
        ActivationEvaluationSite::JobTimeout,
    )?
    .expect("a supplied timeout resolves to one value");
    value
        .checked_mul(timeout.value().unit().seconds_multiplier())
        .map(Some)
        .ok_or(LogicalActivationError::TimeoutScaleOverflow)
}

fn activation_protocol_limits() -> ProtocolLimits {
    ProtocolLimits::new(
        MAX_ACTIVATION_OUTPUT_BYTES,
        MAX_CONTEXT_VALUE_NODES,
        MAX_CONTEXT_VALUE_TEXT_BYTES,
        1,
        1,
    )
    .expect("activation limits are statically coherent")
}

struct ResolvedActivationStrategy {
    matrices: Vec<MatrixCombination>,
    fail_fast: bool,
    max_parallel: Option<u32>,
    expansion_limit: usize,
    has_strategy: bool,
}

fn validate_request<E>(
    request: &ActivateLogicalJobRequest<'_>,
) -> Result<(), LogicalActivationError<E>>
where
    E: Error + Send + Sync + 'static,
{
    let expected = request
        .job
        .needs()
        .iter()
        .map(|need| need.value().as_str())
        .collect::<BTreeSet<_>>();
    for key in &expected {
        if !request.needs.contains_key(*key) {
            return Err(LogicalActivationError::MissingNeed {
                job: (*key).to_owned(),
            });
        }
    }
    for key in request.needs.keys() {
        if !expected.contains(key.as_str()) {
            return Err(LogicalActivationError::UnexpectedNeed);
        }
    }
    if request.status == ActivationStatus::Success
        && request
            .needs
            .values()
            .any(|need| need.result() != JobConclusion::Success)
    {
        return Err(LogicalActivationError::InconsistentAggregateStatus);
    }
    let strategy = StrategyContext::new(true, 0, 1, 1)?;
    JobRuntimeContext::new(
        request.inputs.clone(),
        request.vars.clone(),
        ContextValue::empty_object(),
        strategy,
        request.needs.clone(),
        request.secrets.clone(),
    )?;
    Ok(())
}

fn resolve_boolean<E>(
    template: Option<&CompiledBooleanTemplate>,
    default: bool,
    evaluator: &E,
    context: &ActivationEvaluationContext<'_>,
    site: ActivationEvaluationSite,
) -> Result<bool, LogicalActivationError<E::Error>>
where
    E: LogicalActivationSession,
{
    match template {
        None => Ok(default),
        Some(CompiledBooleanTemplate::Literal(value)) => Ok(*value),
        Some(CompiledBooleanTemplate::Expression(expression)) => {
            evaluate_boolean(evaluator, expression, context, site)
        }
    }
}

fn resolve_string<E>(
    template: Option<&CompiledValueTemplate>,
    default: &str,
    evaluator: &E,
    context: &ActivationEvaluationContext<'_>,
    site: ActivationEvaluationSite,
) -> Result<String, LogicalActivationError<E::Error>>
where
    E: LogicalActivationSession,
{
    match template {
        None => Ok(default.to_owned()),
        Some(CompiledValueTemplate::Literal(value)) => Ok(value.clone()),
        Some(CompiledValueTemplate::Expression(expression)) => {
            evaluate_string(evaluator, expression, context, site)
        }
    }
}

fn resolve_positive_integer<E>(
    template: Option<&CompiledPositiveIntegerTemplate>,
    evaluator: &E,
    context: &ActivationEvaluationContext<'_>,
    site: ActivationEvaluationSite,
) -> Result<Option<u32>, LogicalActivationError<E::Error>>
where
    E: LogicalActivationSession,
{
    let value = match template {
        None => return Ok(None),
        Some(CompiledPositiveIntegerTemplate::Literal(value)) => *value,
        Some(CompiledPositiveIntegerTemplate::Expression(expression)) => {
            evaluate_positive_integer(evaluator, expression, context, site)?
        }
    };
    if value == 0 {
        return Err(LogicalActivationError::ZeroPositiveInteger { site });
    }
    Ok(Some(value))
}

fn evaluate_value<E>(
    evaluator: &E,
    expression: &CompiledExpressionTemplate,
    context: &ActivationEvaluationContext<'_>,
    site: ActivationEvaluationSite,
) -> Result<ActivationValue, LogicalActivationError<E::Error>>
where
    E: LogicalActivationSession,
{
    validate_site_contexts(expression, site)?;
    validate_provider_site(evaluator, expression, site)?;
    evaluator
        .evaluate_value(expression, context)
        .map_err(|source| LogicalActivationError::Evaluation { site, source })
}

fn evaluate_string<E>(
    evaluator: &E,
    expression: &CompiledExpressionTemplate,
    context: &ActivationEvaluationContext<'_>,
    site: ActivationEvaluationSite,
) -> Result<String, LogicalActivationError<E::Error>>
where
    E: LogicalActivationSession,
{
    validate_site_contexts(expression, site)?;
    validate_provider_site(evaluator, expression, site)?;
    evaluator
        .evaluate_string(expression, context)
        .map_err(|source| LogicalActivationError::Evaluation { site, source })
}

fn evaluate_condition<E>(
    evaluator: &E,
    expression: &CompiledExpressionTemplate,
    context: &ActivationEvaluationContext<'_>,
    site: ActivationEvaluationSite,
) -> Result<bool, LogicalActivationError<E::Error>>
where
    E: LogicalActivationSession,
{
    validate_site_contexts(expression, site)?;
    validate_provider_site(evaluator, expression, site)?;
    evaluator
        .evaluate_condition(expression, context)
        .map_err(|source| LogicalActivationError::Evaluation { site, source })
}

fn evaluate_boolean<E>(
    evaluator: &E,
    expression: &CompiledExpressionTemplate,
    context: &ActivationEvaluationContext<'_>,
    site: ActivationEvaluationSite,
) -> Result<bool, LogicalActivationError<E::Error>>
where
    E: LogicalActivationSession,
{
    validate_site_contexts(expression, site)?;
    validate_provider_site(evaluator, expression, site)?;
    evaluator
        .evaluate_boolean(expression, context)
        .map_err(|source| LogicalActivationError::Evaluation { site, source })
}

fn evaluate_positive_integer<E>(
    evaluator: &E,
    expression: &CompiledExpressionTemplate,
    context: &ActivationEvaluationContext<'_>,
    site: ActivationEvaluationSite,
) -> Result<u32, LogicalActivationError<E::Error>>
where
    E: LogicalActivationSession,
{
    validate_site_contexts(expression, site)?;
    validate_provider_site(evaluator, expression, site)?;
    evaluator
        .evaluate_positive_integer(expression, context)
        .map_err(|source| LogicalActivationError::Evaluation { site, source })
}

fn validate_site_contexts<E>(
    expression: &CompiledExpressionTemplate,
    site: ActivationEvaluationSite,
) -> Result<(), LogicalActivationError<E>>
where
    E: Error + Send + Sync + 'static,
{
    for context in expression.contexts() {
        let allowed = match site {
            ActivationEvaluationSite::JobName
            | ActivationEvaluationSite::RunnerGroup
            | ActivationEvaluationSite::RunnerLabel
            | ActivationEvaluationSite::JobTimeout
            | ActivationEvaluationSite::JobContinueOnError => matches!(
                context,
                ExpressionContext::Github
                    | ExpressionContext::Inputs
                    | ExpressionContext::Vars
                    | ExpressionContext::Needs
                    | ExpressionContext::Strategy
                    | ExpressionContext::Matrix
            ),
            ActivationEvaluationSite::JobCondition
            | ActivationEvaluationSite::StrategyFailFast
            | ActivationEvaluationSite::StrategyMaxParallel
            | ActivationEvaluationSite::WholeMatrix
            | ActivationEvaluationSite::MatrixAxis
            | ActivationEvaluationSite::MatrixInclude
            | ActivationEvaluationSite::MatrixExclude => matches!(
                context,
                ExpressionContext::Github
                    | ExpressionContext::Inputs
                    | ExpressionContext::Vars
                    | ExpressionContext::Needs
            ),
        };
        if !allowed {
            return Err(LogicalActivationError::UnavailableExpressionContext {
                site,
                context: context.as_str(),
            });
        }
    }
    Ok(())
}

fn validate_provider_site<E>(
    evaluator: &E,
    expression: &CompiledExpressionTemplate,
    site: ActivationEvaluationSite,
) -> Result<(), LogicalActivationError<E::Error>>
where
    E: LogicalActivationSession,
{
    evaluator
        .validate_expression_site(expression, site)
        .map_err(|source| LogicalActivationError::Evaluation { site, source })
}

#[derive(Clone, Default)]
struct MatrixCombination {
    entries: MatrixEntries,
    lookup: BTreeMap<String, usize>,
}

type SharedActivationValue = Arc<ActivationValue>;
type MatrixEntries = Vec<(String, SharedActivationValue)>;
type MatrixPatches = Vec<MatrixEntries>;
type RawMatrixEntries = Vec<(String, ActivationValue)>;

impl MatrixCombination {
    fn get<E>(&self, key: &str, evaluator: &E) -> Option<&ActivationValue>
    where
        E: LogicalActivationSession,
    {
        self.lookup
            .get(&evaluator.normalize_matrix_key(key))
            .map(|index| self.entries[*index].1.as_ref())
    }

    fn set<E>(
        &mut self,
        key: String,
        value: SharedActivationValue,
        evaluator: &E,
    ) -> Result<(), LogicalActivationError<E::Error>>
    where
        E: LogicalActivationSession,
    {
        let normalized = evaluator.normalize_matrix_key(&key);
        if let Some(index) = self.lookup.get(&normalized).copied() {
            self.entries[index].1 = value;
        } else {
            if self.entries.len() >= MAX_MATRIX_OBJECT_ENTRIES {
                return Err(LogicalActivationError::LimitExceeded {
                    field: "expanded matrix entries",
                    maximum: MAX_MATRIX_OBJECT_ENTRIES,
                });
            }
            self.lookup.insert(normalized, self.entries.len());
            self.entries.push((key, value));
        }
        Ok(())
    }

    fn matches<E>(&self, patch: &MatrixEntries, evaluator: &E) -> bool
    where
        E: LogicalActivationSession,
    {
        patch.iter().all(|(key, value)| {
            self.get(key, evaluator)
                .is_some_and(|original| evaluator.matrix_value_matches(original, value.as_ref()))
        })
    }

    fn include_compatible<E>(&self, patch: &MatrixEntries, evaluator: &E) -> bool
    where
        E: LogicalActivationSession,
    {
        patch.iter().all(|(key, value)| {
            self.get(key, evaluator)
                .is_none_or(|original| evaluator.matrix_values_equal(original, value.as_ref()))
        })
    }

    fn merge_include<E>(
        &mut self,
        source: &Self,
        patch: &MatrixEntries,
        evaluator: &E,
    ) -> Result<(), LogicalActivationError<E::Error>>
    where
        E: LogicalActivationSession,
    {
        for (key, value) in patch {
            if source.get(key, evaluator).is_none() {
                self.set(key.clone(), Arc::clone(value), evaluator)?;
            }
        }
        Ok(())
    }

    fn into_context_value<E>(self) -> Result<ContextValue, LogicalActivationError<E>>
    where
        E: Error + Send + Sync + 'static,
    {
        let values = self
            .entries
            .into_iter()
            .map(|(key, value)| value.to_context_value().map(|value| (key, value)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        ContextValue::object(values).map_err(LogicalActivationError::RuntimeContext)
    }
}

impl ActivationValue {
    fn to_context_value<E>(&self) -> Result<ContextValue, LogicalActivationError<E>>
    where
        E: Error + Send + Sync + 'static,
    {
        match self {
            Self::Null => Ok(ContextValue::null()),
            Self::Boolean(value) => Ok(ContextValue::boolean(*value)),
            Self::Number(bits) => {
                let value = f64::from_bits(*bits);
                if !value.is_finite() {
                    return Err(LogicalActivationError::NonFiniteMatrixNumber);
                }
                Ok(ContextValue::number(value))
            }
            Self::String(value) => Ok(ContextValue::string(value.clone())),
            Self::Array(values) => ContextValue::array(
                values
                    .iter()
                    .map(Self::to_context_value)
                    .collect::<Result<Vec<_>, _>>()?,
            )
            .map_err(LogicalActivationError::RuntimeContext),
            Self::Object(entries) => {
                let mut values = BTreeMap::new();
                for (key, value) in entries {
                    if values
                        .insert(key.clone(), value.to_context_value()?)
                        .is_some()
                    {
                        return Err(LogicalActivationError::DuplicateMatrixKey);
                    }
                }
                ContextValue::object(values).map_err(LogicalActivationError::RuntimeContext)
            }
        }
    }
}

fn resolve_matrix<E>(
    matrix: &automata_ci_core::MatrixTemplate,
    expansion_limit: usize,
    evaluator: &E,
    context: &ActivationEvaluationContext<'_>,
) -> Result<Vec<MatrixCombination>, LogicalActivationError<E::Error>>
where
    E: LogicalActivationSession,
{
    let specification = match matrix.expression() {
        Some(expression) => {
            let value = evaluate_value(
                evaluator,
                expression.value(),
                context,
                ActivationEvaluationSite::WholeMatrix,
            )?;
            resolve_whole_matrix(value, evaluator)?
        }
        None => resolve_structured_matrix(matrix, evaluator, context)?,
    };
    expand_matrix(specification, expansion_limit, evaluator)
}

struct ResolvedMatrix {
    axes: Vec<(String, Vec<SharedActivationValue>)>,
    include: MatrixPatches,
    exclude: MatrixPatches,
}

fn resolve_structured_matrix<E>(
    matrix: &automata_ci_core::MatrixTemplate,
    evaluator: &E,
    context: &ActivationEvaluationContext<'_>,
) -> Result<ResolvedMatrix, LogicalActivationError<E::Error>>
where
    E: LogicalActivationSession,
{
    let mut budget = DynamicMatrixBudget::default();
    let mut axes = Vec::with_capacity(matrix.axes().len());
    for axis in matrix.axes() {
        let values = match axis.values() {
            MatrixAxisValues::Static(values) => values
                .iter()
                .map(|value| {
                    resolve_value_template(
                        value.value(),
                        evaluator,
                        context,
                        ActivationEvaluationSite::MatrixAxis,
                        &mut budget,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?,
            MatrixAxisValues::Expression(expression) => {
                let value = evaluate_value(
                    evaluator,
                    expression.value(),
                    context,
                    ActivationEvaluationSite::MatrixAxis,
                )?;
                resolve_axis_values(value, &mut budget, evaluator)?
            }
        };
        if values.is_empty() {
            return Err(LogicalActivationError::EmptyMatrixAxis);
        }
        axes.push((axis.name().value().clone(), values));
    }
    let axis_names = axes
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>();
    let include = resolve_patch_set(
        matrix.include(),
        true,
        &axis_names,
        evaluator,
        context,
        ActivationEvaluationSite::MatrixInclude,
        &mut budget,
    )?;
    let exclude = resolve_patch_set(
        matrix.exclude(),
        false,
        &axis_names,
        evaluator,
        context,
        ActivationEvaluationSite::MatrixExclude,
        &mut budget,
    )?;
    Ok(ResolvedMatrix {
        axes,
        include,
        exclude,
    })
}

fn resolve_whole_matrix<E>(
    value: ActivationValue,
    evaluator: &E,
) -> Result<ResolvedMatrix, LogicalActivationError<E::Error>>
where
    E: LogicalActivationSession,
{
    let ActivationValue::Object(entries) = value else {
        return Err(LogicalActivationError::ExpectedMatrixObject {
            received: value.kind(),
        });
    };
    let mut budget = DynamicMatrixBudget::default();
    budget.charge_node()?;
    if entries.len() > MAX_MATRIX_OBJECT_ENTRIES {
        return Err(LogicalActivationError::LimitExceeded {
            field: "whole matrix entries",
            maximum: MAX_MATRIX_OBJECT_ENTRIES,
        });
    }
    let mut keys = BTreeSet::new();
    let mut axes = Vec::new();
    let mut include = Vec::new();
    let mut exclude = Vec::new();
    for (key, value) in entries {
        budget.charge_text(&key)?;
        let normalized = evaluator.normalize_matrix_key(&key);
        if !valid_matrix_key(&key) || !keys.insert(normalized.clone()) {
            return Err(LogicalActivationError::DuplicateMatrixKey);
        }
        if normalized == evaluator.normalize_matrix_key("include") {
            include = resolve_dynamic_patches(value, &mut budget, evaluator)?;
        } else if normalized == evaluator.normalize_matrix_key("exclude") {
            exclude = resolve_dynamic_patches(value, &mut budget, evaluator)?;
        } else {
            if axes.len() >= MAX_MATRIX_AXES {
                return Err(LogicalActivationError::LimitExceeded {
                    field: "matrix axes",
                    maximum: MAX_MATRIX_AXES,
                });
            }
            let values = resolve_axis_values(value, &mut budget, evaluator)?;
            if values.is_empty() {
                return Err(LogicalActivationError::EmptyMatrixAxis);
            }
            axes.push((key, values));
        }
    }
    if axes.is_empty() && include.is_empty() {
        return Err(LogicalActivationError::EmptyMatrix);
    }
    let axis_names = axes
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>();
    validate_patch_keys(&include, true, &axis_names, evaluator)?;
    validate_patch_keys(&exclude, false, &axis_names, evaluator)?;
    Ok(ResolvedMatrix {
        axes,
        include,
        exclude,
    })
}

fn resolve_axis_values<E>(
    value: ActivationValue,
    budget: &mut DynamicMatrixBudget,
    evaluator: &E,
) -> Result<Vec<SharedActivationValue>, LogicalActivationError<E::Error>>
where
    E: LogicalActivationSession,
{
    let ActivationValue::Array(values) = value else {
        return Err(LogicalActivationError::ExpectedMatrixArray {
            field: "matrix axis",
            received: value.kind(),
        });
    };
    budget.charge_node()?;
    if values.len() > MAX_MATRIX_AXIS_VALUES {
        return Err(LogicalActivationError::LimitExceeded {
            field: "matrix axis values",
            maximum: MAX_MATRIX_AXIS_VALUES,
        });
    }
    for value in &values {
        validate_matrix_value(value, 0, Some(budget), evaluator)?;
    }
    Ok(values.into_iter().map(Arc::new).collect())
}

fn resolve_patch_set<E>(
    patches: &MatrixPatchSet,
    allow_new_keys: bool,
    axes: &[&str],
    evaluator: &E,
    context: &ActivationEvaluationContext<'_>,
    site: ActivationEvaluationSite,
    budget: &mut DynamicMatrixBudget,
) -> Result<MatrixPatches, LogicalActivationError<E::Error>>
where
    E: LogicalActivationSession,
{
    let patches = match patches {
        MatrixPatchSet::Static(patches) => patches
            .iter()
            .map(|patch| resolve_static_patch(patch, evaluator, context, site, budget))
            .collect::<Result<Vec<_>, _>>()?,
        MatrixPatchSet::Expression(expression) => {
            let value = evaluate_value(evaluator, expression.value(), context, site)?;
            resolve_dynamic_patches(value, budget, evaluator)?
        }
    };
    validate_patch_keys(&patches, allow_new_keys, axes, evaluator)?;
    Ok(patches)
}

fn resolve_static_patch<E>(
    patch: &MatrixPatch,
    evaluator: &E,
    context: &ActivationEvaluationContext<'_>,
    site: ActivationEvaluationSite,
    budget: &mut DynamicMatrixBudget,
) -> Result<MatrixEntries, LogicalActivationError<E::Error>>
where
    E: LogicalActivationSession,
{
    patch
        .entries()
        .iter()
        .map(|(key, value)| {
            resolve_value_template(value.value(), evaluator, context, site, budget)
                .map(|value| (key.value().clone(), value))
        })
        .collect()
}

fn resolve_dynamic_patches<E>(
    value: ActivationValue,
    budget: &mut DynamicMatrixBudget,
    evaluator: &E,
) -> Result<MatrixPatches, LogicalActivationError<E::Error>>
where
    E: LogicalActivationSession,
{
    let ActivationValue::Array(patches) = value else {
        return Err(LogicalActivationError::ExpectedMatrixArray {
            field: "matrix patches",
            received: value.kind(),
        });
    };
    budget.charge_node()?;
    if patches.len() > MAX_MATRIX_PATCHES {
        return Err(LogicalActivationError::LimitExceeded {
            field: "matrix patches",
            maximum: MAX_MATRIX_PATCHES,
        });
    }
    patches
        .into_iter()
        .map(|patch| {
            let ActivationValue::Object(entries) = patch else {
                return Err(LogicalActivationError::ExpectedMatrixObject {
                    received: patch.kind(),
                });
            };
            validate_patch(&entries, budget, evaluator)?;
            Ok(entries
                .into_iter()
                .map(|(key, value)| (key, Arc::new(value)))
                .collect())
        })
        .collect()
}

fn validate_patch<E>(
    entries: &RawMatrixEntries,
    budget: &mut DynamicMatrixBudget,
    evaluator: &E,
) -> Result<(), LogicalActivationError<E::Error>>
where
    E: LogicalActivationSession,
{
    budget.charge_node()?;
    if entries.is_empty() {
        return Err(LogicalActivationError::EmptyMatrixPatch);
    }
    if entries.len() > MAX_MATRIX_OBJECT_ENTRIES {
        return Err(LogicalActivationError::LimitExceeded {
            field: "matrix patch entries",
            maximum: MAX_MATRIX_OBJECT_ENTRIES,
        });
    }
    let mut keys = BTreeSet::new();
    for (key, value) in entries {
        budget.charge_text(key)?;
        if !valid_matrix_key(key) || !keys.insert(evaluator.normalize_matrix_key(key)) {
            return Err(LogicalActivationError::DuplicateMatrixKey);
        }
        validate_matrix_value(value, 0, Some(budget), evaluator)?;
    }
    Ok(())
}

fn validate_patch_keys<E>(
    patches: &MatrixPatches,
    allow_new_keys: bool,
    axes: &[&str],
    evaluator: &E,
) -> Result<(), LogicalActivationError<E::Error>>
where
    E: LogicalActivationSession,
{
    let axes = axes
        .iter()
        .map(|axis| evaluator.normalize_matrix_key(axis))
        .collect::<BTreeSet<_>>();
    for patch in patches {
        let mut keys = BTreeSet::new();
        for (key, _) in patch {
            let normalized = evaluator.normalize_matrix_key(key);
            if !keys.insert(normalized.clone()) {
                return Err(LogicalActivationError::DuplicateMatrixKey);
            }
            if !allow_new_keys && !axes.contains(&normalized) {
                return Err(LogicalActivationError::UnknownMatrixAxis);
            }
        }
    }
    Ok(())
}

fn resolve_value_template<E>(
    template: &MatrixValueTemplate,
    evaluator: &E,
    context: &ActivationEvaluationContext<'_>,
    site: ActivationEvaluationSite,
    budget: &mut DynamicMatrixBudget,
) -> Result<SharedActivationValue, LogicalActivationError<E::Error>>
where
    E: LogicalActivationSession,
{
    let (value, dynamic) = match template {
        MatrixValueTemplate::Literal(value) => (activation_value(value)?, false),
        MatrixValueTemplate::Expression(expression) => {
            (evaluate_value(evaluator, expression, context, site)?, true)
        }
    };
    validate_matrix_value(&value, 0, dynamic.then_some(budget), evaluator)?;
    Ok(Arc::new(value))
}

fn activation_value<E>(value: &MatrixValue) -> Result<ActivationValue, LogicalActivationError<E>>
where
    E: Error + Send + Sync + 'static,
{
    Ok(match value {
        MatrixValue::Null => ActivationValue::Null,
        MatrixValue::Boolean(value) => ActivationValue::Boolean(*value),
        MatrixValue::Number(value) => {
            let value = value
                .parse::<f64>()
                .map_err(|_| LogicalActivationError::InvalidMatrixNumber)?;
            if !value.is_finite() {
                return Err(LogicalActivationError::NonFiniteMatrixNumber);
            }
            ActivationValue::number(value)
        }
        MatrixValue::String(value) => ActivationValue::String(value.clone()),
        MatrixValue::Array(values) => ActivationValue::Array(
            values
                .iter()
                .map(activation_value)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        MatrixValue::Object(entries) => ActivationValue::Object(
            entries
                .iter()
                .map(|(key, value)| activation_value(value).map(|value| (key.clone(), value)))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    })
}

fn validate_matrix_value<E>(
    value: &ActivationValue,
    depth: usize,
    mut budget: Option<&mut DynamicMatrixBudget>,
    evaluator: &E,
) -> Result<(), LogicalActivationError<E::Error>>
where
    E: LogicalActivationSession,
{
    if depth > MAX_MATRIX_VALUE_DEPTH {
        return Err(LogicalActivationError::LimitExceeded {
            field: "matrix value depth",
            maximum: MAX_MATRIX_VALUE_DEPTH,
        });
    }
    if let Some(budget) = budget.as_deref_mut() {
        budget.charge_node()?;
    }
    match value {
        ActivationValue::Null | ActivationValue::Boolean(_) => Ok(()),
        ActivationValue::Number(bits) => {
            if f64::from_bits(*bits).is_finite() {
                Ok(())
            } else {
                Err(LogicalActivationError::NonFiniteMatrixNumber)
            }
        }
        ActivationValue::String(value) => {
            if let Some(budget) = budget.as_deref_mut() {
                budget.charge_text(value)?;
            } else if value.len() > MAX_MATRIX_TEXT_BYTES {
                return Err(LogicalActivationError::LimitExceeded {
                    field: "matrix text",
                    maximum: MAX_MATRIX_TEXT_BYTES,
                });
            }
            Ok(())
        }
        ActivationValue::Array(values) => {
            if values.len() > MAX_MATRIX_OBJECT_ENTRIES {
                return Err(LogicalActivationError::LimitExceeded {
                    field: "matrix array values",
                    maximum: MAX_MATRIX_OBJECT_ENTRIES,
                });
            }
            for value in values {
                validate_matrix_value(value, depth + 1, budget.as_deref_mut(), evaluator)?;
            }
            Ok(())
        }
        ActivationValue::Object(entries) => {
            if entries.len() > MAX_MATRIX_OBJECT_ENTRIES {
                return Err(LogicalActivationError::LimitExceeded {
                    field: "matrix object entries",
                    maximum: MAX_MATRIX_OBJECT_ENTRIES,
                });
            }
            let mut keys = BTreeSet::new();
            for (key, value) in entries {
                if let Some(budget) = budget.as_deref_mut() {
                    budget.charge_text(key)?;
                } else if key.len() > MAX_MATRIX_TEXT_BYTES {
                    return Err(LogicalActivationError::LimitExceeded {
                        field: "matrix text",
                        maximum: MAX_MATRIX_TEXT_BYTES,
                    });
                }
                if !valid_matrix_key(key) || !keys.insert(evaluator.normalize_matrix_key(key)) {
                    return Err(LogicalActivationError::DuplicateMatrixKey);
                }
                validate_matrix_value(value, depth + 1, budget.as_deref_mut(), evaluator)?;
            }
            Ok(())
        }
    }
}

fn valid_matrix_key(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && value.len() <= MAX_RUNTIME_CONTEXT_IDENTIFIER_BYTES
        && !value.chars().any(char::is_control)
}

#[derive(Default)]
struct DynamicMatrixBudget {
    nodes: usize,
    text_bytes: usize,
}

impl DynamicMatrixBudget {
    fn charge_node<E>(&mut self) -> Result<(), LogicalActivationError<E>>
    where
        E: Error + Send + Sync + 'static,
    {
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or(LogicalActivationError::LimitExceeded {
                field: "dynamic matrix nodes",
                maximum: MAX_CONTEXT_VALUE_NODES,
            })?;
        if self.nodes > MAX_CONTEXT_VALUE_NODES {
            return Err(LogicalActivationError::LimitExceeded {
                field: "dynamic matrix nodes",
                maximum: MAX_CONTEXT_VALUE_NODES,
            });
        }
        Ok(())
    }

    fn charge_text<E>(&mut self, value: &str) -> Result<(), LogicalActivationError<E>>
    where
        E: Error + Send + Sync + 'static,
    {
        if value.len() > MAX_MATRIX_TEXT_BYTES {
            return Err(LogicalActivationError::LimitExceeded {
                field: "dynamic matrix text",
                maximum: MAX_MATRIX_TEXT_BYTES,
            });
        }
        self.text_bytes = self.text_bytes.checked_add(value.len()).ok_or(
            LogicalActivationError::LimitExceeded {
                field: "dynamic matrix text bytes",
                maximum: MAX_CONTEXT_VALUE_TEXT_BYTES,
            },
        )?;
        if self.text_bytes > MAX_CONTEXT_VALUE_TEXT_BYTES {
            return Err(LogicalActivationError::LimitExceeded {
                field: "dynamic matrix text bytes",
                maximum: MAX_CONTEXT_VALUE_TEXT_BYTES,
            });
        }
        Ok(())
    }
}

#[derive(Default)]
struct MatrixExpansionBudget {
    work: usize,
}

impl MatrixExpansionBudget {
    fn charge<E>(&mut self, work: usize) -> Result<(), LogicalActivationError<E>>
    where
        E: Error + Send + Sync + 'static,
    {
        self.work = self
            .work
            .checked_add(work)
            .ok_or(LogicalActivationError::LimitExceeded {
                field: "matrix expansion work",
                maximum: MAX_MATRIX_EXPANSION_WORK,
            })?;
        if self.work > MAX_MATRIX_EXPANSION_WORK {
            return Err(LogicalActivationError::LimitExceeded {
                field: "matrix expansion work",
                maximum: MAX_MATRIX_EXPANSION_WORK,
            });
        }
        Ok(())
    }

    fn charge_product<E>(
        &mut self,
        left: usize,
        right: usize,
    ) -> Result<(), LogicalActivationError<E>>
    where
        E: Error + Send + Sync + 'static,
    {
        let work = left
            .checked_mul(right)
            .ok_or(LogicalActivationError::LimitExceeded {
                field: "matrix expansion work",
                maximum: MAX_MATRIX_EXPANSION_WORK,
            })?;
        self.charge(work)
    }
}

fn expand_matrix<E>(
    matrix: ResolvedMatrix,
    expansion_limit: usize,
    evaluator: &E,
) -> Result<Vec<MatrixCombination>, LogicalActivationError<E::Error>>
where
    E: LogicalActivationSession,
{
    let mut work = MatrixExpansionBudget::default();
    let mut axis_keys = BTreeSet::new();
    for (axis, _) in &matrix.axes {
        if !axis_keys.insert(evaluator.normalize_matrix_key(axis)) {
            return Err(LogicalActivationError::DuplicateMatrixKey);
        }
    }
    let mut original = if matrix.axes.is_empty() {
        Vec::new()
    } else {
        vec![MatrixCombination::default()]
    };
    for (name, values) in matrix.axes {
        let next_len = original.len().checked_mul(values.len()).ok_or(
            LogicalActivationError::LimitExceeded {
                field: "matrix candidate combinations",
                maximum: MAX_MATRIX_CANDIDATE_COMBINATIONS,
            },
        )?;
        if next_len > MAX_MATRIX_CANDIDATE_COMBINATIONS {
            return Err(LogicalActivationError::LimitExceeded {
                field: "matrix candidate combinations",
                maximum: MAX_MATRIX_CANDIDATE_COMBINATIONS,
            });
        }
        work.charge(next_len)?;
        let mut next = Vec::with_capacity(next_len);
        for combination in &original {
            for value in &values {
                let mut combination = combination.clone();
                combination.set(name.clone(), Arc::clone(value), evaluator)?;
                next.push(combination);
            }
        }
        original = next;
    }
    let exclude_entries = matrix.exclude.iter().map(Vec::len).sum::<usize>();
    work.charge_product(original.len(), exclude_entries)?;
    original.retain(|combination| {
        !matrix
            .exclude
            .iter()
            .any(|patch| combination.matches(patch, evaluator))
    });
    if original.len() > expansion_limit {
        return Err(LogicalActivationError::MatrixExpansionLimitExceeded {
            maximum: expansion_limit,
        });
    }

    let mut expanded = original.clone();
    let include_entries = matrix.include.iter().map(Vec::len).sum::<usize>();
    work.charge_product(original.len(), include_entries)?;
    work.charge_product(original.len(), include_entries)?;
    for patch in matrix.include {
        let mut applied = false;
        for (source, current) in original.iter().zip(expanded.iter_mut()) {
            if source.include_compatible(&patch, evaluator) {
                current.merge_include(source, &patch, evaluator)?;
                applied = true;
            }
        }
        if !applied {
            if expanded.len() >= expansion_limit {
                return Err(LogicalActivationError::MatrixExpansionLimitExceeded {
                    maximum: expansion_limit,
                });
            }
            let mut combination = MatrixCombination::default();
            for (key, value) in patch {
                work.charge(1)?;
                combination.set(key, value, evaluator)?;
            }
            expanded.push(combination);
        }
    }
    Ok(expanded)
}

fn matrix_digest<E>(
    job_key: &WorkflowJobKey,
    matrix: &ContextValue,
) -> Result<Sha256Digest, LogicalActivationError<E>>
where
    E: Error + Send + Sync + 'static,
{
    let encoded =
        serde_json::to_vec(matrix).map_err(LogicalActivationError::MatrixDigestEncoding)?;
    let key = job_key.as_str().as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(MATRIX_DIGEST_DOMAIN);
    hasher.update(u64::try_from(key.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(key);
    hasher.update(
        u64::try_from(encoded.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(encoded);
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

/// Fail-closed logical-job activation error.
#[derive(Debug, Error)]
pub enum LogicalActivationError<E>
where
    E: Error + Send + Sync + 'static,
{
    /// The provider adapter could not prepare the immutable base context.
    #[error("failed to prepare activation expression context")]
    Preparation {
        /// The sanitized provider-specific cause.
        #[source]
        source: E,
    },
    /// A provider expression failed at a known activation site.
    #[error("failed to evaluate {site}")]
    Evaluation {
        /// The logical field being evaluated.
        site: ActivationEvaluationSite,
        /// The sanitized provider-specific cause.
        #[source]
        source: E,
    },
    /// A compiled expression requests a context unavailable at this site.
    #[error("expression context `{context}` is unavailable while evaluating {site}")]
    UnavailableExpressionContext {
        /// The logical field being evaluated.
        site: ActivationEvaluationSite,
        /// The stable unavailable context name.
        context: &'static str,
    },
    /// One declared direct prerequisite is absent from the activation snapshot.
    #[error("direct prerequisite `{job}` is missing from activation context")]
    MissingNeed {
        /// The missing logical job key.
        job: String,
    },
    /// The activation snapshot contains a prerequisite not declared by the job.
    #[error("activation context contains an undeclared prerequisite")]
    UnexpectedNeed,
    /// Aggregate status evidence contradicts direct prerequisite results.
    #[error("aggregate activation status contradicts direct prerequisite results")]
    InconsistentAggregateStatus,
    /// A setting requiring a positive integer evaluated to zero.
    #[error("{site} evaluated to zero")]
    ZeroPositiveInteger {
        /// The logical field being evaluated.
        site: ActivationEvaluationSite,
    },
    /// The resolved job name violates bounded text rules.
    #[error("activated job name is empty, overlong, or contains control characters")]
    InvalidActivatedJobName,
    /// A resolved runner group or label violates its domain grammar.
    #[error("activated runner selector is invalid")]
    InvalidActivatedRunnerSelector,
    /// Scaling the configured timeout into seconds overflowed.
    #[error("activated job timeout overflows seconds")]
    TimeoutScaleOverflow,
    /// A matrix field expected an array but received another provider value.
    #[error("{field} must evaluate to an array, received {received}")]
    ExpectedMatrixArray {
        /// The stable matrix field name.
        field: &'static str,
        /// The stable provider value-kind name.
        received: &'static str,
    },
    /// A whole-matrix expression or patch expected an object.
    #[error("matrix expression must evaluate to an object, received {received}")]
    ExpectedMatrixObject {
        /// The stable provider value-kind name.
        received: &'static str,
    },
    /// A declared matrix axis has no candidate values.
    #[error("matrix axis has no values")]
    EmptyMatrixAxis,
    /// The matrix has neither axes nor standalone include entries.
    #[error("matrix has no axes or include entries")]
    EmptyMatrix,
    /// An include or exclude patch has no entries.
    #[error("matrix patch is empty")]
    EmptyMatrixPatch,
    /// A matrix object contains an empty or provider-equivalent duplicate key.
    #[error("matrix contains a duplicate or empty key")]
    DuplicateMatrixKey,
    /// An exclude patch names a property that is not a declared axis.
    #[error("matrix exclude references an unknown axis")]
    UnknownMatrixAxis,
    /// A source matrix number cannot be represented as binary64.
    #[error("matrix number is not a valid binary64 value")]
    InvalidMatrixNumber,
    /// A dynamic or source matrix number is infinite or NaN.
    #[error("matrix numbers must be finite")]
    NonFiniteMatrixNumber,
    /// Post-exclusion and include expansion exceeds the plan's job limit.
    #[error("matrix expansion exceeds limit {maximum}")]
    MatrixExpansionLimitExceeded {
        /// The maximum concrete instance count.
        maximum: usize,
    },
    /// A bounded activation resource exceeded its fixed maximum.
    #[error("{field} exceeds bounded maximum {maximum}")]
    LimitExceeded {
        /// The stable bounded resource name.
        field: &'static str,
        /// The configured maximum for that resource.
        maximum: usize,
    },
    /// The concrete runtime context violates a domain invariant.
    #[error("invalid runtime context")]
    RuntimeContext(#[from] RuntimeContextError),
    /// The deterministic concrete job identity violates a domain invariant.
    #[error("invalid concrete job identity")]
    JobIdentity(#[from] JobValidationError),
    /// Canonical JSON encoding for a matrix identity failed.
    #[error("canonical matrix identity encoding failed")]
    MatrixDigestEncoding(#[source] serde_json::Error),
    /// Canonical protobuf encoding for a runtime context failed.
    #[error("canonical runtime-context encoding failed")]
    RuntimeContextEncoding(#[source] automata_ci_protocol_protobuf::EncodeError),
}
