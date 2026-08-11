//! GitHub Actions expression adapter for logical-job activation.

use std::{collections::BTreeMap, fmt};

use automata_ci_core::{
    CompiledExpressionTemplate, ContextValue, ExpressionInstruction, ExpressionSegment,
    JobConclusion, MAX_LOGICAL_FIELD_BYTES, NeedContext, StrategyContext,
};
use automata_ci_expression_github::{
    GithubExpressionEvaluationError, GithubExpressionEvaluator, GithubExpressionLimits,
    GithubObject, GithubStatus, GithubValue, GithubValueError, MapContext, MapContextError,
};
use thiserror::Error;

use crate::activation::{
    ActivationEvaluationContext, ActivationEvaluationSite, ActivationStatus, ActivationValue,
    LogicalActivationEvaluator, LogicalActivationSession,
};

/// Closed GitHub context snapshot safe to evaluate before runner execution.
///
/// Construction admits the provider's documented workflow/run/event metadata
/// while rejecting every runner-, step-, action-, filesystem-, and
/// credential-scoped top-level property. Event payload data remains available
/// through `github.event`, but `github.token` and other runtime-only roots can
/// never enter this snapshot.
#[derive(Clone)]
pub struct GithubActivationContext {
    value: GithubValue,
}

impl GithubActivationContext {
    /// Validates an immutable provider snapshot for activation-time use.
    ///
    /// # Errors
    ///
    /// Rejects non-object values and any property outside the closed set of
    /// provider metadata available before a job reaches a runner.
    pub fn new(value: GithubValue) -> Result<Self, GithubActivationEvaluationError> {
        let GithubValue::Object(object) = &value else {
            return Err(GithubActivationEvaluationError::GithubContextMustBeObject);
        };
        if object
            .entries()
            .iter()
            .any(|(key, _)| !is_activation_safe_github_property(key))
        {
            return Err(GithubActivationEvaluationError::UnsafeGithubContextProperty);
        }
        Ok(Self { value })
    }

    fn value(&self) -> &GithubValue {
        &self.value
    }
}

impl fmt::Debug for GithubActivationContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entry_count = match &self.value {
            GithubValue::Object(object) => object.entries().len(),
            _ => unreachable!("constructor proves an object"),
        };
        formatter
            .debug_struct("GithubActivationContext")
            .field("entry_count", &entry_count)
            .field("values", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

fn is_activation_safe_github_property(property: &str) -> bool {
    matches!(
        ordinal_key(property).as_str(),
        "actor"
            | "actor_id"
            | "api_url"
            | "base_ref"
            | "event"
            | "event_name"
            | "graphql_url"
            | "head_ref"
            | "ref"
            | "ref_name"
            | "ref_protected"
            | "ref_type"
            | "repository"
            | "repository_id"
            | "repository_owner"
            | "repository_owner_id"
            | "repositoryurl"
            | "retention_days"
            | "run_attempt"
            | "run_id"
            | "run_number"
            | "server_url"
            | "sha"
            | "triggering_actor"
            | "workflow"
            | "workflow_ref"
            | "workflow_sha"
    )
}

/// GitHub Actions evaluator for schema-v2 logical-job activation.
///
/// The caller supplies the immutable `github` object, including any bounded
/// event data appropriate for this run. The adapter constructs all remaining
/// activation contexts from integrity-bound plan/runtime values and never
/// exposes secret bindings as expression values.
#[derive(Clone, Debug)]
pub struct GithubLogicalActivationEvaluator {
    evaluator: GithubExpressionEvaluator,
    github: GithubActivationContext,
}

impl GithubLogicalActivationEvaluator {
    /// Creates an adapter with default expression limits.
    ///
    #[must_use]
    pub fn new(github: GithubActivationContext) -> Self {
        Self::with_limits(github, GithubExpressionLimits::default())
    }

    /// Creates an adapter with explicit expression limits.
    #[must_use]
    pub fn with_limits(github: GithubActivationContext, limits: GithubExpressionLimits) -> Self {
        Self {
            evaluator: GithubExpressionEvaluator::new(limits),
            github,
        }
    }

    #[must_use]
    /// Returns the configured copyable expression evaluator.
    pub const fn expression_evaluator(&self) -> GithubExpressionEvaluator {
        self.evaluator
    }

    #[must_use]
    /// Returns the immutable provider context used for each activation.
    pub const fn github(&self) -> &GithubActivationContext {
        &self.github
    }
}

impl LogicalActivationEvaluator for GithubLogicalActivationEvaluator {
    type Error = GithubActivationEvaluationError;
    type Session<'a> = GithubActivationSession;

    fn prepare(
        &self,
        context: &ActivationEvaluationContext<'_>,
    ) -> Result<Self::Session<'_>, Self::Error> {
        if context.matrix().is_some() || context.strategy().is_some() {
            return Err(GithubActivationEvaluationError::PreparationRequiresBaseContext);
        }
        let named = BTreeMap::from([
            ("github".to_owned(), self.github.value().clone()),
            (
                "inputs".to_owned(),
                context_to_github_value(context.inputs())?,
            ),
            ("vars".to_owned(), context_to_github_value(context.vars())?),
            ("needs".to_owned(), needs_value(context.needs())?),
        ]);
        let status = github_status(context.status());
        let base_context = MapContext::without_extensions(named.clone(), status)
            .map_err(GithubActivationEvaluationError::Context)?;
        Ok(GithubActivationSession {
            evaluator: self.evaluator,
            named,
            base_context,
            status,
        })
    }
}

/// Immutable GitHub evaluator state prepared for exactly one activation.
#[derive(Clone)]
pub struct GithubActivationSession {
    evaluator: GithubExpressionEvaluator,
    named: BTreeMap<String, GithubValue>,
    base_context: MapContext,
    status: GithubStatus,
}

impl GithubActivationSession {
    fn program(
        expression: &CompiledExpressionTemplate,
    ) -> Result<&automata_ci_core::ExpressionProgram, GithubActivationEvaluationError> {
        let [program] = expression.programs() else {
            return Err(GithubActivationEvaluationError::ExpectedSingleProgram {
                received: expression.programs().len(),
            });
        };
        Ok(program)
    }

    fn context(
        &self,
        context: &ActivationEvaluationContext<'_>,
    ) -> Result<MapContext, GithubActivationEvaluationError> {
        if context.matrix().is_none() && context.strategy().is_none() {
            return Ok(self.base_context.clone());
        }
        let mut named = self.named.clone();
        if let Some(matrix) = context.matrix() {
            named.insert("matrix".to_owned(), context_to_github_value(matrix)?);
        }
        if let Some(strategy) = context.strategy() {
            named.insert("strategy".to_owned(), strategy_value(strategy)?);
        }
        MapContext::without_extensions(named, self.status)
            .map_err(GithubActivationEvaluationError::Context)
    }
}

impl fmt::Debug for GithubActivationSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubActivationSession")
            .field("base_named_value_count", &self.named.len())
            .field("values", &"[REDACTED]")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

impl LogicalActivationSession for GithubActivationSession {
    type Error = GithubActivationEvaluationError;

    fn validate_expression_site(
        &self,
        expression: &CompiledExpressionTemplate,
        site: ActivationEvaluationSite,
    ) -> Result<(), Self::Error> {
        for program in expression.programs() {
            for instruction in program.instructions() {
                let ExpressionInstruction::Call { name, .. } = instruction else {
                    continue;
                };
                let status_function = ["always", "success", "failure", "cancelled"]
                    .iter()
                    .any(|candidate| name.eq_ignore_ascii_case(candidate));
                if name.eq_ignore_ascii_case("hashfiles")
                    || (status_function && site != ActivationEvaluationSite::JobCondition)
                {
                    return Err(GithubActivationEvaluationError::UnavailableFunction);
                }
            }
        }
        Ok(())
    }

    fn evaluate_value(
        &self,
        expression: &CompiledExpressionTemplate,
        context: &ActivationEvaluationContext<'_>,
    ) -> Result<ActivationValue, Self::Error> {
        let value = self
            .evaluator
            .evaluate(Self::program(expression)?, &self.context(context)?)?;
        Ok(activation_value(&value))
    }

    fn evaluate_string(
        &self,
        expression: &CompiledExpressionTemplate,
        context: &ActivationEvaluationContext<'_>,
    ) -> Result<String, Self::Error> {
        let evaluation_context = self.context(context)?;
        let mut programs = expression.programs().iter();
        let mut rendered = String::new();
        for segment in expression.expression().segments() {
            match segment {
                ExpressionSegment::Literal(value) => rendered.push_str(value),
                ExpressionSegment::Evaluation(_) => {
                    let program = programs
                        .next()
                        .ok_or(GithubActivationEvaluationError::TemplateProgramCountMismatch)?;
                    rendered.push_str(
                        &self
                            .evaluator
                            .evaluate(program, &evaluation_context)?
                            .coerce_to_string(),
                    );
                }
            }
            if rendered.len() > MAX_LOGICAL_FIELD_BYTES {
                return Err(GithubActivationEvaluationError::RenderedTemplateTooLarge);
            }
        }
        if programs.next().is_some() {
            return Err(GithubActivationEvaluationError::TemplateProgramCountMismatch);
        }
        Ok(rendered)
    }

    fn evaluate_condition(
        &self,
        expression: &CompiledExpressionTemplate,
        context: &ActivationEvaluationContext<'_>,
    ) -> Result<bool, Self::Error> {
        self.evaluator
            .evaluate_condition(Self::program(expression)?, &self.context(context)?)
            .map_err(GithubActivationEvaluationError::Evaluation)
    }

    fn evaluate_boolean(
        &self,
        expression: &CompiledExpressionTemplate,
        context: &ActivationEvaluationContext<'_>,
    ) -> Result<bool, Self::Error> {
        self.evaluator
            .evaluate(Self::program(expression)?, &self.context(context)?)?
            .as_bool()
            .ok_or(GithubActivationEvaluationError::ExpectedBoolean)
    }

    fn evaluate_positive_integer(
        &self,
        expression: &CompiledExpressionTemplate,
        context: &ActivationEvaluationContext<'_>,
    ) -> Result<u32, Self::Error> {
        let value = self
            .evaluator
            .evaluate(Self::program(expression)?, &self.context(context)?)?;
        let GithubValue::Number(bits) = &value else {
            return Err(GithubActivationEvaluationError::ExpectedPositiveInteger);
        };
        let number = f64::from_bits(*bits);
        if !number.is_finite() || number <= 0.0 {
            return Err(GithubActivationEvaluationError::ExpectedPositiveInteger);
        }
        value
            .coerce_to_string()
            .parse::<u32>()
            .map_err(|_| GithubActivationEvaluationError::ExpectedPositiveInteger)
    }

    fn normalize_matrix_key(&self, key: &str) -> String {
        ordinal_key(key)
    }

    fn matrix_values_equal(&self, left: &ActivationValue, right: &ActivationValue) -> bool {
        github_matrix_values_equal(left, right)
    }

    fn matrix_value_matches(&self, original: &ActivationValue, patch: &ActivationValue) -> bool {
        github_matrix_value_matches(original, patch)
    }
}

const fn github_status(status: ActivationStatus) -> GithubStatus {
    match status {
        ActivationStatus::Success => GithubStatus::Success,
        ActivationStatus::Failure => GithubStatus::Failure,
        ActivationStatus::Cancelled => GithubStatus::Cancelled,
        ActivationStatus::Skipped => GithubStatus::Skipped,
    }
}

fn github_matrix_values_equal(left: &ActivationValue, right: &ActivationValue) -> bool {
    match (left, right) {
        (ActivationValue::Array(left), ActivationValue::Array(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(left, right)| github_matrix_values_equal(left, right))
        }
        (ActivationValue::Object(left), ActivationValue::Object(right)) => {
            left.len() == right.len()
                && left.iter().all(|(left_key, left_value)| {
                    right
                        .iter()
                        .find(|(right_key, _)| ordinal_ignore_case(left_key, right_key))
                        .is_some_and(|(_, right_value)| {
                            github_matrix_values_equal(left_value, right_value)
                        })
                })
        }
        (ActivationValue::Array(_) | ActivationValue::Object(_), _)
        | (_, ActivationValue::Array(_) | ActivationValue::Object(_)) => false,
        _ => github_scalar(left).loosely_equals(&github_scalar(right)),
    }
}

fn github_matrix_value_matches(original: &ActivationValue, patch: &ActivationValue) -> bool {
    match (original, patch) {
        (ActivationValue::Array(original), ActivationValue::Array(patch)) => {
            original.len() == patch.len()
                && original
                    .iter()
                    .zip(patch)
                    .all(|(original, patch)| github_matrix_value_matches(original, patch))
        }
        (ActivationValue::Object(original), ActivationValue::Object(patch)) => {
            patch.iter().all(|(patch_key, patch_value)| {
                original
                    .iter()
                    .find(|(original_key, _)| ordinal_ignore_case(original_key, patch_key))
                    .is_some_and(|(_, original_value)| {
                        github_matrix_value_matches(original_value, patch_value)
                    })
            })
        }
        (ActivationValue::Array(_) | ActivationValue::Object(_), _)
        | (_, ActivationValue::Array(_) | ActivationValue::Object(_)) => false,
        _ => github_scalar(original).loosely_equals(&github_scalar(patch)),
    }
}

fn github_scalar(value: &ActivationValue) -> GithubValue {
    match value {
        ActivationValue::Null => GithubValue::Null,
        ActivationValue::Boolean(value) => GithubValue::Boolean(*value),
        ActivationValue::Number(bits) => GithubValue::number(f64::from_bits(*bits)),
        ActivationValue::String(value) => GithubValue::string(value),
        ActivationValue::Array(_) | ActivationValue::Object(_) => {
            unreachable!("composite matrix values are handled before scalar coercion")
        }
    }
}

fn ordinal_ignore_case(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right) || ordinal_key(left) == ordinal_key(right)
}

fn ordinal_key(value: &str) -> String {
    value.chars().flat_map(char::to_lowercase).collect()
}

fn needs_value(
    needs: &BTreeMap<String, NeedContext>,
) -> Result<GithubValue, GithubActivationEvaluationError> {
    object(
        needs
            .iter()
            .map(|(key, need)| {
                let outputs = object(need.outputs().iter().filter_map(|(key, output)| {
                    output
                        .public_value()
                        .map(|value| (key.clone(), GithubValue::string(value)))
                }))?;
                let result = match need.result() {
                    JobConclusion::Success => "success",
                    JobConclusion::Failure | JobConclusion::TimedOut => "failure",
                    JobConclusion::Cancelled => "cancelled",
                    JobConclusion::Skipped => "skipped",
                };
                object([
                    ("result".to_owned(), GithubValue::string(result)),
                    ("outputs".to_owned(), outputs),
                ])
                .map(|value| (key.clone(), value))
            })
            .collect::<Result<Vec<_>, GithubActivationEvaluationError>>()?,
    )
}

fn strategy_value(
    strategy: StrategyContext,
) -> Result<GithubValue, GithubActivationEvaluationError> {
    object([
        (
            "fail-fast".to_owned(),
            GithubValue::Boolean(strategy.fail_fast()),
        ),
        (
            "job-index".to_owned(),
            GithubValue::number(f64::from(strategy.job_index())),
        ),
        (
            "job-total".to_owned(),
            GithubValue::number(f64::from(strategy.job_total())),
        ),
        (
            "max-parallel".to_owned(),
            GithubValue::number(f64::from(strategy.max_parallel())),
        ),
    ])
}

pub(crate) fn context_to_github_value(
    value: &ContextValue,
) -> Result<GithubValue, GithubActivationEvaluationError> {
    Ok(match value {
        ContextValue::Null => GithubValue::Null,
        ContextValue::Boolean { value } => GithubValue::Boolean(*value),
        ContextValue::Number { ieee754_bits } => GithubValue::number(f64::from_bits(*ieee754_bits)),
        ContextValue::String { value } => GithubValue::string(value),
        ContextValue::Array { values } => GithubValue::array(
            values
                .iter()
                .map(context_to_github_value)
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(GithubActivationEvaluationError::Value)?,
        ContextValue::Object { values } => object(
            values
                .iter()
                .map(|(key, value)| {
                    context_to_github_value(value).map(|value| (key.clone(), value))
                })
                .collect::<Result<Vec<_>, GithubActivationEvaluationError>>()?,
        )?,
    })
}

fn object(
    entries: impl IntoIterator<Item = (String, GithubValue)>,
) -> Result<GithubValue, GithubActivationEvaluationError> {
    GithubObject::new(entries.into_iter().collect())
        .map(GithubValue::object)
        .map_err(GithubActivationEvaluationError::Value)
}

fn activation_value(value: &GithubValue) -> ActivationValue {
    match value {
        GithubValue::Null => ActivationValue::Null,
        GithubValue::Boolean(value) => ActivationValue::Boolean(*value),
        GithubValue::Number(bits) => ActivationValue::Number(*bits),
        GithubValue::String(value) => ActivationValue::String(value.to_string()),
        GithubValue::Array(values) => {
            ActivationValue::Array(values.iter().map(activation_value).collect())
        }
        GithubValue::Object(value) => ActivationValue::Object(
            value
                .entries()
                .iter()
                .map(|(key, value)| (key.clone(), activation_value(value)))
                .collect(),
        ),
    }
}

/// Sanitized GitHub activation-evaluation failure.
#[derive(Debug, Error)]
pub enum GithubActivationEvaluationError {
    /// The supplied `github` root is not an object.
    #[error("GitHub activation context must be an object")]
    GithubContextMustBeObject,
    /// The supplied `github` root contains runner- or credential-scoped data.
    #[error("GitHub activation context contains a property unavailable before runner execution")]
    UnsafeGithubContextProperty,
    /// Evaluator preparation received matrix or strategy overlays too early.
    #[error("GitHub activation preparation requires a base context without matrix overlays")]
    PreparationRequiresBaseContext,
    /// A scalar activation expression compiled to an unexpected program count.
    #[error("activation scalar requires exactly one compiled program; received {received}")]
    ExpectedSingleProgram {
        /// The number of compiled programs that were present.
        received: usize,
    },
    /// Template segments and compiled programs do not correspond one-to-one.
    #[error("activation template program count does not match its expression segments")]
    TemplateProgramCountMismatch,
    /// A rendered activation template exceeded the logical-field size limit.
    #[error("activation template rendered value exceeds its bounded size")]
    RenderedTemplateTooLarge,
    /// The integrity-bound values could not form a valid expression context.
    #[error("invalid GitHub activation expression context")]
    Context(#[source] MapContextError),
    /// An integrity-bound context value cannot be represented by the evaluator.
    #[error("invalid GitHub activation context value")]
    Value(#[source] GithubValueError),
    /// Evaluation of a valid compiled expression failed.
    #[error("GitHub activation expression evaluation failed")]
    Evaluation(#[from] GithubExpressionEvaluationError),
    /// An integer-valued activation setting was non-numeric, non-positive, or out of range.
    #[error("activation value must evaluate to a positive integer")]
    ExpectedPositiveInteger,
    /// A Boolean-valued activation setting evaluated to another type.
    #[error("activation field must evaluate to a Boolean")]
    ExpectedBoolean,
    /// The expression uses a function unavailable at its activation site.
    #[error("expression function is unavailable at this activation site")]
    UnavailableFunction,
}
