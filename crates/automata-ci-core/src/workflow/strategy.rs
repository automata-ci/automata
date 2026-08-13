//! Versioned strategy and matrix source templates for deferred activation.

use std::{collections::BTreeSet, num::NonZeroU16};

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::job::MAX_RUNTIME_CONTEXT_IDENTIFIER_BYTES;

use super::{
    CompiledBooleanTemplate, CompiledExpressionTemplate, CompiledPositiveIntegerTemplate, Located,
    PlanEvaluationPhase, PlanSourceSpan, WorkflowPlanError, source::validate_span_source,
    validation::LogicalPlanBudget,
};

/// Strategy representation emitted by this build.
pub const WORKFLOW_STRATEGY_SCHEMA_VERSION: u16 = WorkflowStrategyVersion::current().get();
/// Maximum logical job instances one matrix may activate.
// foundation-governance: parity-limit
pub const MAX_MATRIX_EXPANSION: usize = 256;
/// Maximum named axes in one matrix.
// foundation-governance: parity-limit
pub const MAX_MATRIX_AXES: usize = 32;
/// Maximum statically listed values in one axis.
// foundation-governance: parity-limit
pub const MAX_MATRIX_AXIS_VALUES: usize = 256;
/// Maximum include or exclude patches in one matrix.
// foundation-governance: parity-limit
pub const MAX_MATRIX_PATCHES: usize = 256;
/// Maximum entries in one matrix object or patch.
// foundation-governance: parity-limit
pub const MAX_MATRIX_OBJECT_ENTRIES: usize = 128;
/// Maximum nesting depth of a literal matrix value.
// foundation-governance: parity-limit
pub const MAX_MATRIX_VALUE_DEPTH: usize = 8;
/// Maximum bytes in a matrix key or string literal.
// foundation-governance: parity-limit
pub const MAX_MATRIX_TEXT_BYTES: usize = 16_384;
/// Maximum fully static Cartesian candidates activation may inspect before
/// include/exclude transformations reduce the emitted instance set.
// foundation-governance: parity-limit
const MAX_STATIC_MATRIX_CANDIDATE_COMBINATIONS: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MatrixLimitRejection {
    Expansion,
    Axes,
    AxisValues,
    Patches,
    ObjectEntries,
    ValueDepth,
    TextBytes,
    StaticCandidates,
}

pub(super) const fn matrix_expansion_rejection(observed: usize) -> Option<MatrixLimitRejection> {
    if observed > MAX_MATRIX_EXPANSION {
        return Some(MatrixLimitRejection::Expansion);
    }
    None
}
const fn matrix_axis_count_rejection(observed: usize) -> Option<MatrixLimitRejection> {
    if observed > MAX_MATRIX_AXES {
        return Some(MatrixLimitRejection::Axes);
    }
    None
}
const fn matrix_axis_value_count_rejection(observed: usize) -> Option<MatrixLimitRejection> {
    if observed > MAX_MATRIX_AXIS_VALUES {
        return Some(MatrixLimitRejection::AxisValues);
    }
    None
}
const fn matrix_patch_count_rejection(observed: usize) -> Option<MatrixLimitRejection> {
    if observed > MAX_MATRIX_PATCHES {
        return Some(MatrixLimitRejection::Patches);
    }
    None
}
const fn matrix_object_entry_count_rejection(observed: usize) -> Option<MatrixLimitRejection> {
    if observed > MAX_MATRIX_OBJECT_ENTRIES {
        return Some(MatrixLimitRejection::ObjectEntries);
    }
    None
}
const fn matrix_value_depth_rejection(observed: usize) -> Option<MatrixLimitRejection> {
    if observed > MAX_MATRIX_VALUE_DEPTH {
        return Some(MatrixLimitRejection::ValueDepth);
    }
    None
}
pub(super) const fn matrix_text_byte_rejection(observed: usize) -> Option<MatrixLimitRejection> {
    if observed > MAX_MATRIX_TEXT_BYTES {
        return Some(MatrixLimitRejection::TextBytes);
    }
    None
}
const fn matrix_static_candidate_count_rejection(observed: usize) -> Option<MatrixLimitRejection> {
    if observed > MAX_STATIC_MATRIX_CANDIDATE_COMBINATIONS {
        return Some(MatrixLimitRejection::StaticCandidates);
    }
    None
}

/// A positive workflow-strategy representation version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct WorkflowStrategyVersion(NonZeroU16);

impl WorkflowStrategyVersion {
    /// Creates a positive strategy version.
    ///
    /// # Errors
    ///
    /// Returns [`WorkflowPlanError::ZeroStrategyVersion`] for zero.
    pub fn new(version: u16) -> Result<Self, WorkflowPlanError> {
        NonZeroU16::new(version)
            .map(Self)
            .ok_or(WorkflowPlanError::ZeroStrategyVersion)
    }

    /// Returns the strategy schema version emitted and accepted by this build.
    #[must_use]
    pub const fn current() -> Self {
        Self(NonZeroU16::MIN)
    }

    /// Returns the positive integer representation of this version.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

impl<'de> Deserialize<'de> for WorkflowStrategyVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let version = u16::deserialize(deserializer)?;
        Self::new(version).map_err(D::Error::custom)
    }
}

/// Bounded literal data retained in a static matrix definition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum MatrixValue {
    /// The null value.
    Null,
    /// A Boolean value.
    Boolean(bool),
    /// A JSON number preserved as text until validation and activation.
    Number(String),
    /// A UTF-8 string bounded by [`MAX_MATRIX_TEXT_BYTES`].
    String(String),
    /// A bounded, recursively validated sequence.
    Array(Vec<MatrixValue>),
    /// A bounded object whose keys must be unique and strictly sorted.
    Object(Vec<(String, MatrixValue)>),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum UncheckedMatrixValue {
    Null,
    Boolean { value: bool },
    Number { value: String },
    String { value: String },
    Array { value: Vec<MatrixValue> },
    Object { value: Vec<(String, MatrixValue)> },
}

impl<'de> Deserialize<'de> for MatrixValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(match UncheckedMatrixValue::deserialize(deserializer)? {
            UncheckedMatrixValue::Null => Self::Null,
            UncheckedMatrixValue::Boolean { value } => Self::Boolean(value),
            UncheckedMatrixValue::Number { value } => Self::Number(value),
            UncheckedMatrixValue::String { value } => Self::String(value),
            UncheckedMatrixValue::Array { value } => Self::Array(value),
            UncheckedMatrixValue::Object { value } => Self::Object(value),
        })
    }
}

impl MatrixValue {
    fn validate(
        &self,
        depth: usize,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        budget.charge_node("matrix value")?;
        if matrix_value_depth_rejection(depth).is_some() {
            return Err(WorkflowPlanError::LimitExceeded {
                field: "matrix value depth",
                maximum: MAX_MATRIX_VALUE_DEPTH,
            });
        }
        match self {
            Self::Null | Self::Boolean(_) => Ok(()),
            Self::Number(value) => {
                budget.charge_text("matrix number", value, 128)?;
                if is_json_number(value) && value.parse::<f64>().is_ok_and(f64::is_finite) {
                    Ok(())
                } else {
                    Err(WorkflowPlanError::InvalidNumber(value.clone()))
                }
            }
            Self::String(value) => {
                budget.charge_text("matrix string", value, MAX_MATRIX_TEXT_BYTES)
            }
            Self::Array(values) => {
                if matrix_object_entry_count_rejection(values.len()).is_some() {
                    return Err(WorkflowPlanError::LimitExceeded {
                        field: "matrix array values",
                        maximum: MAX_MATRIX_OBJECT_ENTRIES,
                    });
                }
                for value in values {
                    value.validate(depth + 1, budget)?;
                }
                Ok(())
            }
            Self::Object(entries) => {
                if matrix_object_entry_count_rejection(entries.len()).is_some() {
                    return Err(WorkflowPlanError::LimitExceeded {
                        field: "matrix object entries",
                        maximum: MAX_MATRIX_OBJECT_ENTRIES,
                    });
                }
                let mut previous: Option<&str> = None;
                for (key, value) in entries {
                    validate_matrix_root_key(key, "matrix object key", budget)?;
                    if previous.is_some_and(|candidate| candidate >= key.as_str()) {
                        return Err(WorkflowPlanError::DuplicateDefinition {
                            field: "matrix object",
                            key: key.clone(),
                        });
                    }
                    previous = Some(key);
                    value.validate(depth + 1, budget)?;
                }
                Ok(())
            }
        }
    }
}

/// One statically shaped matrix value or a compiled activation-time value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum MatrixValueTemplate {
    /// A literal matrix value retained in the logical plan.
    Literal(MatrixValue),
    /// An expression evaluated while activating the logical job.
    Expression(CompiledExpressionTemplate),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum UncheckedMatrixValueTemplate {
    Literal { value: MatrixValue },
    Expression { value: CompiledExpressionTemplate },
}

impl<'de> Deserialize<'de> for MatrixValueTemplate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(
            match UncheckedMatrixValueTemplate::deserialize(deserializer)? {
                UncheckedMatrixValueTemplate::Literal { value } => Self::Literal(value),
                UncheckedMatrixValueTemplate::Expression { value } => Self::Expression(value),
            },
        )
    }
}

impl MatrixValueTemplate {
    fn validate(&self, budget: &mut LogicalPlanBudget) -> Result<(), WorkflowPlanError> {
        match self {
            Self::Literal(value) => value.validate(0, budget),
            Self::Expression(expression) => {
                expression.validate("matrix value", PlanEvaluationPhase::JobActivation, budget)
            }
        }
    }
}

/// Static axis values or one expression expected to produce an array at activation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum MatrixAxisValues {
    /// Source-located values explicitly listed in the workflow.
    Static(Vec<Located<MatrixValueTemplate>>),
    /// An activation-time expression expected to evaluate to an array.
    Expression(Located<CompiledExpressionTemplate>),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum UncheckedMatrixAxisValues {
    Static {
        value: Vec<Located<MatrixValueTemplate>>,
    },
    Expression {
        value: Located<CompiledExpressionTemplate>,
    },
}

impl<'de> Deserialize<'de> for MatrixAxisValues {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(
            match UncheckedMatrixAxisValues::deserialize(deserializer)? {
                UncheckedMatrixAxisValues::Static { value } => Self::Static(value),
                UncheckedMatrixAxisValues::Expression { value } => Self::Expression(value),
            },
        )
    }
}

/// One named matrix dimension.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MatrixAxis {
    name: Located<String>,
    values: MatrixAxisValues,
    span: PlanSourceSpan,
}

impl MatrixAxis {
    /// Creates an axis without validating its name, values, spans, or limits.
    #[must_use]
    pub const fn new(
        name: Located<String>,
        values: MatrixAxisValues,
        span: PlanSourceSpan,
    ) -> Self {
        Self { name, values, span }
    }

    /// Returns the axis name together with its source location.
    #[must_use]
    pub const fn name(&self) -> &Located<String> {
        &self.name
    }

    /// Returns the static or expression-backed axis values.
    #[must_use]
    pub const fn values(&self) -> &MatrixAxisValues {
        &self.values
    }

    /// Returns the source span covering the complete axis.
    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    fn validate(
        &self,
        source_id: &str,
        budget: &mut LogicalPlanBudget,
    ) -> Result<Option<usize>, WorkflowPlanError> {
        budget.charge_node("matrix axis")?;
        validate_span_source(&self.span, source_id, "matrix axis")?;
        validate_span_source(self.name.span(), source_id, "matrix axis name")?;
        validate_matrix_root_key(self.name.value(), "matrix axis name", budget)?;
        match &self.values {
            MatrixAxisValues::Static(values) => {
                if values.is_empty() {
                    return Err(WorkflowPlanError::EmptyMatrixAxis(
                        self.name.value().clone(),
                    ));
                }
                if matrix_axis_value_count_rejection(values.len()).is_some() {
                    return Err(WorkflowPlanError::LimitExceeded {
                        field: "matrix axis values",
                        maximum: MAX_MATRIX_AXIS_VALUES,
                    });
                }
                for value in values {
                    validate_span_source(value.span(), source_id, "matrix axis value")?;
                    value.value().validate(budget)?;
                }
                Ok(Some(values.len()))
            }
            MatrixAxisValues::Expression(expression) => {
                validate_span_source(expression.span(), source_id, "matrix axis expression")?;
                expression.value().validate(
                    "matrix axis expression",
                    PlanEvaluationPhase::JobActivation,
                    budget,
                )?;
                Ok(None)
            }
        }
    }
}

/// One include/exclude mapping retained in source order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MatrixPatch {
    entries: Vec<(Located<String>, Located<MatrixValueTemplate>)>,
    span: PlanSourceSpan,
}

impl MatrixPatch {
    /// Creates a patch without validating entry keys, ordering, spans, or limits.
    #[must_use]
    pub const fn new(
        entries: Vec<(Located<String>, Located<MatrixValueTemplate>)>,
        span: PlanSourceSpan,
    ) -> Self {
        Self { entries, span }
    }

    /// Returns source-ordered key/value assignments in this patch.
    #[must_use]
    pub fn entries(&self) -> &[(Located<String>, Located<MatrixValueTemplate>)] {
        &self.entries
    }

    /// Returns the source span covering the complete patch.
    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    fn validate(
        &self,
        source_id: &str,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        budget.charge_node("matrix patch")?;
        validate_span_source(&self.span, source_id, "matrix patch")?;
        if self.entries.is_empty() {
            return Err(WorkflowPlanError::EmptyField("matrix patch"));
        }
        if matrix_object_entry_count_rejection(self.entries.len()).is_some() {
            return Err(WorkflowPlanError::LimitExceeded {
                field: "matrix patch entries",
                maximum: MAX_MATRIX_OBJECT_ENTRIES,
            });
        }
        let mut keys = BTreeSet::new();
        for (key, value) in &self.entries {
            validate_span_source(key.span(), source_id, "matrix patch key")?;
            validate_span_source(value.span(), source_id, "matrix patch value")?;
            validate_matrix_root_key(key.value(), "matrix patch key", budget)?;
            if !keys.insert(key.value().as_str()) {
                return Err(WorkflowPlanError::DuplicateDefinition {
                    field: "matrix patch",
                    key: key.value().clone(),
                });
            }
            value.value().validate(budget)?;
        }
        Ok(())
    }
}

/// Static patches or an activation-time expression expected to return patches.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum MatrixPatchSet {
    /// Patches explicitly listed in source order.
    Static(Vec<MatrixPatch>),
    /// An activation-time expression expected to evaluate to patches.
    Expression(Located<CompiledExpressionTemplate>),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum UncheckedMatrixPatchSet {
    Static {
        value: Vec<MatrixPatch>,
    },
    Expression {
        value: Located<CompiledExpressionTemplate>,
    },
}

impl<'de> Deserialize<'de> for MatrixPatchSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(match UncheckedMatrixPatchSet::deserialize(deserializer)? {
            UncheckedMatrixPatchSet::Static { value } => Self::Static(value),
            UncheckedMatrixPatchSet::Expression { value } => Self::Expression(value),
        })
    }
}

/// Matrix axes and source-ordered include/exclude transformations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MatrixTemplate {
    axes: Vec<MatrixAxis>,
    include: MatrixPatchSet,
    exclude: MatrixPatchSet,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expression: Option<Located<CompiledExpressionTemplate>>,
    span: PlanSourceSpan,
}

impl MatrixTemplate {
    /// Creates an axes-and-patches matrix without validating spans or bounds.
    #[must_use]
    pub const fn new(
        axes: Vec<MatrixAxis>,
        include: MatrixPatchSet,
        exclude: MatrixPatchSet,
        span: PlanSourceSpan,
    ) -> Self {
        Self {
            axes,
            include,
            exclude,
            expression: None,
            span,
        }
    }

    /// Creates a whole-matrix expression evaluated after prerequisite results
    /// exist. The activator must decode and bound the resulting matrix by the
    /// containing strategy's expansion limit.
    #[must_use]
    pub const fn from_expression(
        expression: Located<CompiledExpressionTemplate>,
        span: PlanSourceSpan,
    ) -> Self {
        Self {
            axes: Vec::new(),
            include: MatrixPatchSet::Static(Vec::new()),
            exclude: MatrixPatchSet::Static(Vec::new()),
            expression: Some(expression),
            span,
        }
    }

    /// Returns the named matrix dimensions in source order.
    #[must_use]
    pub fn axes(&self) -> &[MatrixAxis] {
        &self.axes
    }

    /// Returns patches that add candidates or augment matching candidates.
    #[must_use]
    pub const fn include(&self) -> &MatrixPatchSet {
        &self.include
    }

    /// Returns patches used to remove matching candidates.
    #[must_use]
    pub const fn exclude(&self) -> &MatrixPatchSet {
        &self.exclude
    }

    /// Returns the whole-matrix expression, if this template uses that form.
    ///
    /// Validation rejects mixing a whole-matrix expression with axes or
    /// nonempty static include/exclude patches.
    #[must_use]
    pub const fn expression(&self) -> Option<&Located<CompiledExpressionTemplate>> {
        self.expression.as_ref()
    }

    /// Returns the source span covering the complete matrix definition.
    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    fn validate(
        &self,
        source_id: &str,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        budget.charge_node("matrix")?;
        validate_span_source(&self.span, source_id, "matrix")?;
        if let Some(expression) = &self.expression {
            if !self.axes.is_empty()
                || !matches!(&self.include, MatrixPatchSet::Static(values) if values.is_empty())
                || !matches!(&self.exclude, MatrixPatchSet::Static(values) if values.is_empty())
            {
                return Err(WorkflowPlanError::MixedMatrixForms);
            }
            validate_span_source(expression.span(), source_id, "whole matrix expression")?;
            return expression.value().validate(
                "whole matrix expression",
                PlanEvaluationPhase::JobActivation,
                budget,
            );
        }
        if matrix_axis_count_rejection(self.axes.len()).is_some() {
            return Err(WorkflowPlanError::LimitExceeded {
                field: "matrix axes",
                maximum: MAX_MATRIX_AXES,
            });
        }
        let mut names = BTreeSet::new();
        let mut static_product = Some(1_usize);
        for axis in &self.axes {
            if !names.insert(axis.name().value().as_str()) {
                return Err(WorkflowPlanError::DuplicateDefinition {
                    field: "matrix axes",
                    key: axis.name().value().clone(),
                });
            }
            let count = axis.validate(source_id, budget)?;
            static_product = match (static_product, count) {
                (Some(product), Some(count)) => Some(product.checked_mul(count).ok_or(
                    WorkflowPlanError::LimitExceeded {
                        field: "matrix candidate combinations",
                        maximum: MAX_STATIC_MATRIX_CANDIDATE_COMBINATIONS,
                    },
                )?),
                _ => None,
            };
            if static_product
                .is_some_and(|count| matrix_static_candidate_count_rejection(count).is_some())
            {
                return Err(WorkflowPlanError::LimitExceeded {
                    field: "matrix candidate combinations",
                    maximum: MAX_STATIC_MATRIX_CANDIDATE_COMBINATIONS,
                });
            }
        }
        let includes_empty =
            validate_patch_set(&self.include, source_id, "matrix include", budget)?;
        validate_patch_set(&self.exclude, source_id, "matrix exclude", budget)?;
        if self.axes.is_empty() && includes_empty {
            return Err(WorkflowPlanError::EmptyMatrix);
        }
        Ok(())
    }
}

fn validate_patch_set(
    patches: &MatrixPatchSet,
    source_id: &str,
    field: &'static str,
    budget: &mut LogicalPlanBudget,
) -> Result<bool, WorkflowPlanError> {
    match patches {
        MatrixPatchSet::Static(patches) => {
            if matrix_patch_count_rejection(patches.len()).is_some() {
                return Err(WorkflowPlanError::LimitExceeded {
                    field,
                    maximum: MAX_MATRIX_PATCHES,
                });
            }
            for patch in patches {
                patch.validate(source_id, budget)?;
            }
            Ok(patches.is_empty())
        }
        MatrixPatchSet::Expression(expression) => {
            validate_span_source(expression.span(), source_id, field)?;
            expression
                .value()
                .validate(field, PlanEvaluationPhase::JobActivation, budget)?;
            Ok(false)
        }
    }
}

fn validate_matrix_root_key(
    value: &str,
    field: &'static str,
    budget: &mut LogicalPlanBudget,
) -> Result<(), WorkflowPlanError> {
    budget.charge_text(field, value, MAX_RUNTIME_CONTEXT_IDENTIFIER_BYTES)?;
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        return Err(WorkflowPlanError::InvalidKey {
            kind: field,
            value: value.to_owned(),
        });
    }
    Ok(())
}

/// Versioned strategy metadata evaluated by the logical-job activator.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowStrategyTemplate {
    version: WorkflowStrategyVersion,
    fail_fast: Option<Located<CompiledBooleanTemplate>>,
    max_parallel: Option<Located<CompiledPositiveIntegerTemplate>>,
    matrix: MatrixTemplate,
    expansion_limit: u16,
    span: PlanSourceSpan,
}

impl WorkflowStrategyTemplate {
    /// Creates a strategy at the current schema version without validating it.
    ///
    /// Validation requires `expansion_limit` to be in
    /// `1..=`[`MAX_MATRIX_EXPANSION`] and checks every expression at job
    /// activation phase.
    #[must_use]
    pub const fn new(
        fail_fast: Option<Located<CompiledBooleanTemplate>>,
        max_parallel: Option<Located<CompiledPositiveIntegerTemplate>>,
        matrix: MatrixTemplate,
        expansion_limit: u16,
        span: PlanSourceSpan,
    ) -> Self {
        Self {
            version: WorkflowStrategyVersion::current(),
            fail_fast,
            max_parallel,
            matrix,
            expansion_limit,
            span,
        }
    }

    /// Returns the serialized strategy schema version.
    #[must_use]
    pub const fn version(&self) -> WorkflowStrategyVersion {
        self.version
    }

    /// Returns the optional activation-time fail-fast policy.
    #[must_use]
    pub const fn fail_fast(&self) -> Option<&Located<CompiledBooleanTemplate>> {
        self.fail_fast.as_ref()
    }

    /// Returns the optional activation-time concurrency limit.
    #[must_use]
    pub const fn max_parallel(&self) -> Option<&Located<CompiledPositiveIntegerTemplate>> {
        self.max_parallel.as_ref()
    }

    /// Returns the matrix definition used to activate job instances.
    #[must_use]
    pub const fn matrix(&self) -> &MatrixTemplate {
        &self.matrix
    }

    /// Returns the maximum number of instances this strategy may emit.
    #[must_use]
    pub const fn expansion_limit(&self) -> u16 {
        self.expansion_limit
    }

    /// Returns the source span covering the complete strategy.
    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    pub(super) fn validate(
        &self,
        source_id: &str,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        budget.charge_node("workflow strategy")?;
        if self.version != WorkflowStrategyVersion::current() {
            return Err(WorkflowPlanError::UnsupportedStrategyVersion {
                supported: WorkflowStrategyVersion::current().get(),
                received: self.version.get(),
            });
        }
        let expansion_limit = usize::from(self.expansion_limit);
        if expansion_limit == 0 || matrix_expansion_rejection(expansion_limit).is_some() {
            return Err(WorkflowPlanError::InvalidMatrixExpansionLimit {
                maximum: MAX_MATRIX_EXPANSION,
            });
        }
        validate_span_source(&self.span, source_id, "workflow strategy")?;
        if let Some(fail_fast) = &self.fail_fast {
            validate_span_source(fail_fast.span(), source_id, "strategy fail-fast")?;
            fail_fast.value().validate(
                "strategy fail-fast",
                PlanEvaluationPhase::JobActivation,
                budget,
            )?;
        }
        if let Some(max_parallel) = &self.max_parallel {
            validate_span_source(max_parallel.span(), source_id, "strategy max-parallel")?;
            max_parallel.value().validate(
                "strategy max-parallel",
                PlanEvaluationPhase::JobActivation,
                budget,
            )?;
        }
        self.matrix.validate(source_id, budget)
    }
}

fn is_json_number(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut cursor = 0;
    if bytes.first() == Some(&b'-') {
        cursor += 1;
    }
    match bytes.get(cursor) {
        Some(b'0') => cursor += 1,
        Some(b'1'..=b'9') => {
            cursor += 1;
            while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
                cursor += 1;
            }
        }
        _ => return false,
    }
    if bytes.get(cursor) == Some(&b'.') {
        cursor += 1;
        let fraction_start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if cursor == fraction_start {
            return false;
        }
    }
    if matches!(bytes.get(cursor), Some(b'e' | b'E')) {
        cursor += 1;
        if matches!(bytes.get(cursor), Some(b'+' | b'-')) {
            cursor += 1;
        }
        let exponent_start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if cursor == exponent_start {
            return false;
        }
    }
    cursor == bytes.len()
}

#[cfg(test)]
mod limit_contract_tests {
    use super::*;

    #[test]
    fn matrix_expansion_limit_has_exact_boundaries() {
        assert_eq!(matrix_expansion_rejection(MAX_MATRIX_EXPANSION - 1), None);
        assert_eq!(matrix_expansion_rejection(MAX_MATRIX_EXPANSION), None);
        assert_eq!(
            matrix_expansion_rejection(MAX_MATRIX_EXPANSION + 1),
            Some(MatrixLimitRejection::Expansion)
        );
    }
    #[test]
    fn matrix_axis_count_limit_has_exact_boundaries() {
        assert_eq!(matrix_axis_count_rejection(MAX_MATRIX_AXES - 1), None);
        assert_eq!(matrix_axis_count_rejection(MAX_MATRIX_AXES), None);
        assert_eq!(
            matrix_axis_count_rejection(MAX_MATRIX_AXES + 1),
            Some(MatrixLimitRejection::Axes)
        );
    }
    #[test]
    fn matrix_axis_value_count_limit_has_exact_boundaries() {
        assert_eq!(
            matrix_axis_value_count_rejection(MAX_MATRIX_AXIS_VALUES - 1),
            None
        );
        assert_eq!(
            matrix_axis_value_count_rejection(MAX_MATRIX_AXIS_VALUES),
            None
        );
        assert_eq!(
            matrix_axis_value_count_rejection(MAX_MATRIX_AXIS_VALUES + 1),
            Some(MatrixLimitRejection::AxisValues)
        );
    }
    #[test]
    fn matrix_patch_count_limit_has_exact_boundaries() {
        assert_eq!(matrix_patch_count_rejection(MAX_MATRIX_PATCHES - 1), None);
        assert_eq!(matrix_patch_count_rejection(MAX_MATRIX_PATCHES), None);
        assert_eq!(
            matrix_patch_count_rejection(MAX_MATRIX_PATCHES + 1),
            Some(MatrixLimitRejection::Patches)
        );
    }
    #[test]
    fn matrix_object_entry_count_limit_has_exact_boundaries() {
        assert_eq!(
            matrix_object_entry_count_rejection(MAX_MATRIX_OBJECT_ENTRIES - 1),
            None
        );
        assert_eq!(
            matrix_object_entry_count_rejection(MAX_MATRIX_OBJECT_ENTRIES),
            None
        );
        assert_eq!(
            matrix_object_entry_count_rejection(MAX_MATRIX_OBJECT_ENTRIES + 1),
            Some(MatrixLimitRejection::ObjectEntries)
        );
    }
    #[test]
    fn matrix_value_depth_limit_has_exact_boundaries() {
        assert_eq!(
            matrix_value_depth_rejection(MAX_MATRIX_VALUE_DEPTH - 1),
            None
        );
        assert_eq!(matrix_value_depth_rejection(MAX_MATRIX_VALUE_DEPTH), None);
        assert_eq!(
            matrix_value_depth_rejection(MAX_MATRIX_VALUE_DEPTH + 1),
            Some(MatrixLimitRejection::ValueDepth)
        );
    }
    #[test]
    fn matrix_text_byte_limit_has_exact_boundaries() {
        assert_eq!(matrix_text_byte_rejection(MAX_MATRIX_TEXT_BYTES - 1), None);
        assert_eq!(matrix_text_byte_rejection(MAX_MATRIX_TEXT_BYTES), None);
        assert_eq!(
            matrix_text_byte_rejection(MAX_MATRIX_TEXT_BYTES + 1),
            Some(MatrixLimitRejection::TextBytes)
        );
    }
    #[test]
    fn matrix_static_candidate_count_limit_has_exact_boundaries() {
        assert_eq!(
            matrix_static_candidate_count_rejection(MAX_STATIC_MATRIX_CANDIDATE_COMBINATIONS - 1),
            None
        );
        assert_eq!(
            matrix_static_candidate_count_rejection(MAX_STATIC_MATRIX_CANDIDATE_COMBINATIONS),
            None
        );
        assert_eq!(
            matrix_static_candidate_count_rejection(MAX_STATIC_MATRIX_CANDIDATE_COMBINATIONS + 1),
            Some(MatrixLimitRejection::StaticCandidates)
        );
    }
}
