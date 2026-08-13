//! Phase-tagged expression and value templates retained until activation.

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize};

use super::{PlanExpression, WorkflowPlanError, validation::LogicalPlanBudget};
use crate::{ExpressionInstruction, ExpressionLiteral, ExpressionProgram};

/// Maximum bytes in one literal or compiled expression source.
pub const MAX_TEMPLATE_BYTES: usize = 65_536;
/// Maximum compiled segments in one expression template.
pub const MAX_TEMPLATE_SEGMENTS: usize = 512;
/// Maximum declared context dependencies for one expression template.
pub const MAX_EXPRESSION_CONTEXTS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WorkflowTemplateLimitRejection {
    Bytes,
    Segments,
    Contexts,
}

#[cfg(test)]
mod limit_contract_tests {
    use super::*;

    #[test]
    fn workflow_template_byte_limit_has_exact_boundaries() {
        assert_eq!(
            workflow_template_byte_rejection(MAX_TEMPLATE_BYTES - 1),
            None
        );
        assert_eq!(workflow_template_byte_rejection(MAX_TEMPLATE_BYTES), None);
        assert_eq!(
            workflow_template_byte_rejection(MAX_TEMPLATE_BYTES + 1),
            Some(WorkflowTemplateLimitRejection::Bytes)
        );
    }
    #[test]
    fn workflow_template_segment_limit_has_exact_boundaries() {
        assert_eq!(
            workflow_template_segment_rejection(MAX_TEMPLATE_SEGMENTS - 1),
            None
        );
        assert_eq!(
            workflow_template_segment_rejection(MAX_TEMPLATE_SEGMENTS),
            None
        );
        assert_eq!(
            workflow_template_segment_rejection(MAX_TEMPLATE_SEGMENTS + 1),
            Some(WorkflowTemplateLimitRejection::Segments)
        );
    }
    #[test]
    fn expression_context_limit_has_exact_boundaries() {
        assert_eq!(
            expression_context_rejection(MAX_EXPRESSION_CONTEXTS - 1),
            None
        );
        assert_eq!(expression_context_rejection(MAX_EXPRESSION_CONTEXTS), None);
        assert_eq!(
            expression_context_rejection(MAX_EXPRESSION_CONTEXTS + 1),
            Some(WorkflowTemplateLimitRejection::Contexts)
        );
    }
}

pub(super) const fn workflow_template_byte_rejection(
    observed: usize,
) -> Option<WorkflowTemplateLimitRejection> {
    if observed > MAX_TEMPLATE_BYTES {
        return Some(WorkflowTemplateLimitRejection::Bytes);
    }
    None
}
const fn workflow_template_segment_rejection(
    observed: usize,
) -> Option<WorkflowTemplateLimitRejection> {
    if observed > MAX_TEMPLATE_SEGMENTS {
        return Some(WorkflowTemplateLimitRejection::Segments);
    }
    None
}
const fn expression_context_rejection(observed: usize) -> Option<WorkflowTemplateLimitRejection> {
    if observed > MAX_EXPRESSION_CONTEXTS {
        return Some(WorkflowTemplateLimitRejection::Contexts);
    }
    None
}

/// Durable evaluation boundary for a compiled expression.
///
/// Ordering is intentional: a template may only be consumed at or after the
/// phase stored in the plan, and every declared context must already exist.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanEvaluationPhase {
    /// Evaluation performed while admitting and compiling the workflow run.
    Admission,
    /// Evaluation performed once prerequisite results are available and a job activates.
    JobActivation,
    /// Evaluation performed by the assigned runner while executing a job.
    JobExecution,
    /// Evaluation performed after a job's steps have completed.
    JobFinalization,
    /// Evaluation performed after all workflow jobs have reached terminal state.
    WorkflowFinalization,
}

impl PlanEvaluationPhase {
    /// Returns the stable snake-case representation used in diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admission => "admission",
            Self::JobActivation => "job_activation",
            Self::JobExecution => "job_execution",
            Self::JobFinalization => "job_finalization",
            Self::WorkflowFinalization => "workflow_finalization",
        }
    }
}

/// Context namespaces referenced by a compiled expression program.
///
/// This is dependency metadata, not a value bag. Runtime context values are
/// supplied separately and are integrity-bound to the activation/result that
/// produced them.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpressionContext {
    /// Trigger, repository, ref, and other provider event metadata.
    Github,
    /// Values supplied through the workflow invocation contract.
    Inputs,
    /// Repository or organization configuration variables.
    Vars,
    /// Results and outputs from declared prerequisite jobs.
    Needs,
    /// Metadata for the active job strategy.
    Strategy,
    /// Values selected for the active matrix instance.
    Matrix,
    /// Protected secret bindings available only during execution.
    Secrets,
    /// The environment visible at the current execution scope.
    Env,
    /// State for the currently executing job.
    Job,
    /// Metadata for the runner assigned to the job.
    Runner,
    /// Results and outputs from steps in the current job.
    Steps,
    /// Final results and outputs from reusable-workflow jobs.
    Jobs,
}

impl ExpressionContext {
    /// Returns the canonical case-insensitive namespace name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Inputs => "inputs",
            Self::Vars => "vars",
            Self::Needs => "needs",
            Self::Strategy => "strategy",
            Self::Matrix => "matrix",
            Self::Secrets => "secrets",
            Self::Env => "env",
            Self::Job => "job",
            Self::Runner => "runner",
            Self::Steps => "steps",
            Self::Jobs => "jobs",
        }
    }

    /// Returns the earliest phase at which this namespace can exist.
    #[must_use]
    pub const fn minimum_phase(self) -> PlanEvaluationPhase {
        match self {
            Self::Github | Self::Inputs | Self::Vars => PlanEvaluationPhase::Admission,
            Self::Needs | Self::Strategy | Self::Matrix => PlanEvaluationPhase::JobActivation,
            Self::Secrets | Self::Env | Self::Job | Self::Runner | Self::Steps => {
                PlanEvaluationPhase::JobExecution
            }
            Self::Jobs => PlanEvaluationPhase::WorkflowFinalization,
        }
    }
}

/// Lossless expression source plus canonical provider programs and its exact
/// evaluation boundary.
///
/// `programs` is aligned one-for-one with the evaluation segments in
/// [`PlanExpression`]. Keeping both forms preserves exact source diagnostics
/// while making provider semantics (including implicit status guards) durable
/// across control-plane upgrades.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledExpressionTemplate {
    phase: PlanEvaluationPhase,
    expression: PlanExpression,
    programs: Vec<ExpressionProgram>,
    contexts: Vec<ExpressionContext>,
}

impl CompiledExpressionTemplate {
    /// Creates a compiled template without validating phase availability or
    /// correspondence among source segments, programs, and contexts.
    #[must_use]
    pub const fn new(
        phase: PlanEvaluationPhase,
        expression: PlanExpression,
        programs: Vec<ExpressionProgram>,
        contexts: Vec<ExpressionContext>,
    ) -> Self {
        Self {
            phase,
            expression,
            programs,
            contexts,
        }
    }

    /// Returns the phase at which the expression is intended to be evaluated.
    #[must_use]
    pub const fn phase(&self) -> PlanEvaluationPhase {
        self.phase
    }

    /// Returns the lossless expression source and its parsed segments.
    #[must_use]
    pub const fn expression(&self) -> &PlanExpression {
        &self.expression
    }

    /// Returns canonical programs in evaluation-segment source order.
    #[must_use]
    pub fn programs(&self) -> &[ExpressionProgram] {
        &self.programs
    }

    /// Returns the canonical, sorted context dependencies.
    #[must_use]
    pub fn contexts(&self) -> &[ExpressionContext] {
        &self.contexts
    }

    /// Returns whether the compiled program depends on `context`.
    ///
    /// This lookup relies on the sorted-context invariant enforced by plan
    /// validation.
    #[must_use]
    pub fn references_context(&self, context: ExpressionContext) -> bool {
        self.contexts.binary_search(&context).is_ok()
    }

    pub(super) fn validate(
        &self,
        field: &'static str,
        latest: PlanEvaluationPhase,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        budget.charge_node(field)?;
        if self.phase > latest {
            return Err(WorkflowPlanError::TemplatePhaseTooLate {
                field,
                latest: latest.as_str(),
                actual: self.phase.as_str(),
            });
        }
        if expression_context_rejection(self.contexts.len()).is_some() {
            return Err(WorkflowPlanError::LimitExceeded {
                field: "expression contexts",
                maximum: MAX_EXPRESSION_CONTEXTS,
            });
        }
        let mut previous = None;
        for context in &self.contexts {
            if let Some(previous) = previous {
                if previous == *context {
                    return Err(WorkflowPlanError::DuplicateExpressionContext(
                        context.as_str(),
                    ));
                }
                if previous > *context {
                    return Err(WorkflowPlanError::NonCanonicalExpressionContexts);
                }
            }
            if self.phase < context.minimum_phase() {
                return Err(WorkflowPlanError::ExpressionContextUnavailable {
                    context: context.as_str(),
                    phase: self.phase.as_str(),
                    minimum: context.minimum_phase().as_str(),
                });
            }
            previous = Some(*context);
        }
        self.expression.validate()?;
        budget.charge_text(
            "expression source",
            self.expression.source(),
            MAX_TEMPLATE_BYTES,
        )?;
        if workflow_template_segment_rejection(self.expression.segments().len()).is_some() {
            return Err(WorkflowPlanError::LimitExceeded {
                field: "expression segments",
                maximum: MAX_TEMPLATE_SEGMENTS,
            });
        }
        let evaluation_segments = self
            .expression
            .segments()
            .iter()
            .filter(|segment| matches!(segment, super::ExpressionSegment::Evaluation(_)))
            .collect::<Vec<_>>();
        if self.programs.len() != evaluation_segments.len() {
            return Err(WorkflowPlanError::ExpressionProgramCountMismatch {
                expected: evaluation_segments.len(),
                received: self.programs.len(),
            });
        }
        for segment in self.expression.segments() {
            budget.charge_node("expression segment")?;
            if workflow_template_byte_rejection(segment.source().len()).is_some() {
                return Err(WorkflowPlanError::LimitExceeded {
                    field: "expression segment",
                    maximum: MAX_TEMPLATE_BYTES,
                });
            }
        }
        for (index, (segment, program)) in evaluation_segments
            .into_iter()
            .zip(&self.programs)
            .enumerate()
        {
            if segment.source() != program.source() {
                return Err(WorkflowPlanError::ExpressionProgramSourceMismatch { index });
            }
            charge_program(program, budget)?;
        }
        let mut compiled_contexts = BTreeSet::new();
        for program in &self.programs {
            for instruction in program.instructions() {
                if let ExpressionInstruction::NamedValue { name } = instruction {
                    let context = expression_context(name)
                        .ok_or(WorkflowPlanError::UnsupportedExpressionNamedValue)?;
                    compiled_contexts.insert(context);
                }
            }
        }
        if compiled_contexts.into_iter().collect::<Vec<_>>() != self.contexts {
            return Err(WorkflowPlanError::ExpressionProgramContextMismatch);
        }
        Ok(())
    }
}

fn expression_context(name: &str) -> Option<ExpressionContext> {
    [
        ExpressionContext::Github,
        ExpressionContext::Inputs,
        ExpressionContext::Vars,
        ExpressionContext::Needs,
        ExpressionContext::Strategy,
        ExpressionContext::Matrix,
        ExpressionContext::Secrets,
        ExpressionContext::Env,
        ExpressionContext::Job,
        ExpressionContext::Runner,
        ExpressionContext::Steps,
        ExpressionContext::Jobs,
    ]
    .into_iter()
    .find(|context| name.eq_ignore_ascii_case(context.as_str()))
}

fn charge_program(
    program: &ExpressionProgram,
    budget: &mut LogicalPlanBudget,
) -> Result<(), WorkflowPlanError> {
    budget.charge_node("expression program")?;
    budget.charge_text(
        "expression program dialect",
        program.dialect().name(),
        MAX_TEMPLATE_BYTES,
    )?;
    budget.charge_text(
        "expression program source",
        program.source(),
        MAX_TEMPLATE_BYTES,
    )?;
    for instruction in program.instructions() {
        budget.charge_node("expression instruction")?;
        match instruction {
            ExpressionInstruction::Literal {
                value: ExpressionLiteral::String { value },
            } => budget.charge_text("expression literal", value, MAX_TEMPLATE_BYTES)?,
            ExpressionInstruction::NamedValue { name } => {
                budget.charge_text("expression named value", name, MAX_TEMPLATE_BYTES)?;
            }
            ExpressionInstruction::Call { name, .. } => {
                budget.charge_text("expression function", name, MAX_TEMPLATE_BYTES)?;
            }
            ExpressionInstruction::Literal { .. }
            | ExpressionInstruction::Wildcard
            | ExpressionInstruction::Index
            | ExpressionInstruction::Not
            | ExpressionInstruction::Compare { .. }
            | ExpressionInstruction::Logical { .. } => {}
        }
    }
    Ok(())
}

/// Literal text or a compiled expression template.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum CompiledValueTemplate {
    /// Literal text available from admission onward.
    Literal(String),
    /// A compiled expression evaluated at its declared phase.
    Expression(CompiledExpressionTemplate),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum UncheckedCompiledValueTemplate {
    Literal { value: String },
    Expression { value: CompiledExpressionTemplate },
}

impl<'de> Deserialize<'de> for CompiledValueTemplate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(
            match UncheckedCompiledValueTemplate::deserialize(deserializer)? {
                UncheckedCompiledValueTemplate::Literal { value } => Self::Literal(value),
                UncheckedCompiledValueTemplate::Expression { value } => Self::Expression(value),
            },
        )
    }
}

impl CompiledValueTemplate {
    /// Returns admission for a literal or the expression's declared phase.
    #[must_use]
    pub const fn phase(&self) -> PlanEvaluationPhase {
        match self {
            Self::Literal(_) => PlanEvaluationPhase::Admission,
            Self::Expression(expression) => expression.phase(),
        }
    }

    /// Returns the literal text or lossless expression source.
    #[must_use]
    pub fn source(&self) -> &str {
        match self {
            Self::Literal(value) => value,
            Self::Expression(expression) => expression.expression().source(),
        }
    }

    /// Returns whether this template depends on `context`.
    #[must_use]
    pub fn references_context(&self, context: ExpressionContext) -> bool {
        match self {
            Self::Literal(_) => false,
            Self::Expression(expression) => expression.references_context(context),
        }
    }

    pub(super) fn validate(
        &self,
        field: &'static str,
        latest: PlanEvaluationPhase,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        budget.charge_node(field)?;
        match self {
            Self::Literal(value) => budget.charge_text(field, value, MAX_TEMPLATE_BYTES),
            Self::Expression(expression) => expression.validate(field, latest, budget),
        }
    }
}

/// Boolean literal or a phase-tagged compiled expression.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum CompiledBooleanTemplate {
    /// A Boolean value known when the logical plan is built.
    Literal(bool),
    /// A compiled expression expected to yield a Boolean.
    Expression(CompiledExpressionTemplate),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum UncheckedCompiledBooleanTemplate {
    Literal { value: bool },
    Expression { value: CompiledExpressionTemplate },
}

impl<'de> Deserialize<'de> for CompiledBooleanTemplate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(
            match UncheckedCompiledBooleanTemplate::deserialize(deserializer)? {
                UncheckedCompiledBooleanTemplate::Literal { value } => Self::Literal(value),
                UncheckedCompiledBooleanTemplate::Expression { value } => Self::Expression(value),
            },
        )
    }
}

impl CompiledBooleanTemplate {
    pub(super) fn validate(
        &self,
        field: &'static str,
        latest: PlanEvaluationPhase,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        budget.charge_node(field)?;
        match self {
            Self::Literal(_) => Ok(()),
            Self::Expression(expression) => expression.validate(field, latest, budget),
        }
    }
}

/// Positive integer literal or a phase-tagged compiled expression.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum CompiledPositiveIntegerTemplate {
    /// An integer literal; validation rejects zero.
    Literal(u32),
    /// A compiled expression expected to yield a positive integer.
    Expression(CompiledExpressionTemplate),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum UncheckedCompiledPositiveIntegerTemplate {
    Literal { value: u32 },
    Expression { value: CompiledExpressionTemplate },
}

impl<'de> Deserialize<'de> for CompiledPositiveIntegerTemplate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(
            match UncheckedCompiledPositiveIntegerTemplate::deserialize(deserializer)? {
                UncheckedCompiledPositiveIntegerTemplate::Literal { value } => Self::Literal(value),
                UncheckedCompiledPositiveIntegerTemplate::Expression { value } => {
                    Self::Expression(value)
                }
            },
        )
    }
}

impl CompiledPositiveIntegerTemplate {
    pub(super) fn validate(
        &self,
        field: &'static str,
        latest: PlanEvaluationPhase,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        budget.charge_node(field)?;
        match self {
            Self::Literal(0) => Err(WorkflowPlanError::ZeroPositiveInteger { field }),
            Self::Literal(_) => Ok(()),
            Self::Expression(expression) => expression.validate(field, latest, budget),
        }
    }
}
