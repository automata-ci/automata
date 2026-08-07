//! Immutable semantic run and unresolved-action steps.

use serde::{Deserialize, Deserializer, Serialize};

use super::{
    DeferredBoolean, EnvironmentPlan, Located, PlanExpression, PlanSourceSpan, RunStepPlan,
    UsesStepPlan, WorkflowPlanError, WorkflowStepKey,
};

/// Semantic step kind. `Uses` remains unresolved until an action-resolver adapter runs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum PlannedStepKind {
    Run(Box<RunStepPlan>),
    Uses(UsesStepPlan),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum UncheckedPlannedStepKind {
    Run { value: Box<RunStepPlan> },
    Uses { value: UsesStepPlan },
}

impl<'de> Deserialize<'de> for PlannedStepKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(match UncheckedPlannedStepKind::deserialize(deserializer)? {
            UncheckedPlannedStepKind::Run { value } => Self::Run(value),
            UncheckedPlannedStepKind::Uses { value } => Self::Uses(value),
        })
    }
}

/// One ordered workflow step.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedPlannedStep")]
pub struct PlannedStep {
    key: WorkflowStepKey,
    id: Option<Located<String>>,
    name: Option<Located<String>>,
    condition: Option<Located<PlanExpression>>,
    environment: EnvironmentPlan,
    continue_on_error: Option<Located<DeferredBoolean>>,
    timeout_seconds: Option<u32>,
    execution: PlannedStepKind,
    span: PlanSourceSpan,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedPlannedStep {
    key: WorkflowStepKey,
    id: Option<Located<String>>,
    name: Option<Located<String>>,
    condition: Option<Located<PlanExpression>>,
    environment: EnvironmentPlan,
    continue_on_error: Option<Located<DeferredBoolean>>,
    timeout_seconds: Option<u32>,
    execution: PlannedStepKind,
    span: PlanSourceSpan,
}

impl TryFrom<UncheckedPlannedStep> for PlannedStep {
    type Error = WorkflowPlanError;

    fn try_from(value: UncheckedPlannedStep) -> Result<Self, Self::Error> {
        let step = Self {
            key: value.key,
            id: value.id,
            name: value.name,
            condition: value.condition,
            environment: value.environment,
            continue_on_error: value.continue_on_error,
            timeout_seconds: value.timeout_seconds,
            execution: value.execution,
            span: value.span,
        };
        step.validate()?;
        Ok(step)
    }
}

/// Named construction path for one immutable semantic step.
#[derive(Clone, Debug)]
pub struct PlannedStepBuilder {
    key: WorkflowStepKey,
    id: Option<Located<String>>,
    name: Option<Located<String>>,
    condition: Option<Located<PlanExpression>>,
    environment: EnvironmentPlan,
    continue_on_error: Option<Located<DeferredBoolean>>,
    timeout_seconds: Option<u32>,
    execution: PlannedStepKind,
    span: PlanSourceSpan,
}

impl PlannedStep {
    /// Starts a builder with the fields every semantic step must provide.
    #[must_use]
    pub fn builder(
        key: WorkflowStepKey,
        execution: PlannedStepKind,
        span: PlanSourceSpan,
    ) -> PlannedStepBuilder {
        PlannedStepBuilder {
            key,
            id: None,
            name: None,
            condition: None,
            environment: EnvironmentPlan::default(),
            continue_on_error: None,
            timeout_seconds: None,
            execution,
            span,
        }
    }

    #[must_use]
    pub const fn key(&self) -> &WorkflowStepKey {
        &self.key
    }

    #[must_use]
    pub const fn id(&self) -> Option<&Located<String>> {
        self.id.as_ref()
    }

    #[must_use]
    pub const fn name(&self) -> Option<&Located<String>> {
        self.name.as_ref()
    }

    #[must_use]
    pub const fn condition(&self) -> Option<&Located<PlanExpression>> {
        self.condition.as_ref()
    }

    #[must_use]
    pub const fn environment(&self) -> &EnvironmentPlan {
        &self.environment
    }

    #[must_use]
    pub const fn continue_on_error(&self) -> Option<&Located<DeferredBoolean>> {
        self.continue_on_error.as_ref()
    }

    #[must_use]
    pub const fn timeout_seconds(&self) -> Option<u32> {
        self.timeout_seconds
    }

    #[must_use]
    pub const fn execution(&self) -> &PlannedStepKind {
        &self.execution
    }

    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    pub(crate) fn validate(&self) -> Result<(), WorkflowPlanError> {
        if self.timeout_seconds == Some(0) {
            return Err(WorkflowPlanError::ZeroTimeout(self.key.to_string()));
        }
        if let Some(condition) = &self.condition {
            condition.value().validate()?;
        }
        if let Some(value) = &self.continue_on_error {
            value.value().validate()?;
        }
        self.environment.validate()?;
        match &self.execution {
            PlannedStepKind::Run(run) => run.validate(),
            PlannedStepKind::Uses(uses) => uses.validate(),
        }
    }
}

impl PlannedStepBuilder {
    #[must_use]
    pub fn id(mut self, id: Option<Located<String>>) -> Self {
        self.id = id;
        self
    }

    #[must_use]
    pub fn name(mut self, name: Option<Located<String>>) -> Self {
        self.name = name;
        self
    }

    #[must_use]
    pub fn condition(mut self, condition: Option<Located<PlanExpression>>) -> Self {
        self.condition = condition;
        self
    }

    #[must_use]
    pub fn environment(mut self, environment: EnvironmentPlan) -> Self {
        self.environment = environment;
        self
    }

    #[must_use]
    pub fn continue_on_error(
        mut self,
        continue_on_error: Option<Located<DeferredBoolean>>,
    ) -> Self {
        self.continue_on_error = continue_on_error;
        self
    }

    #[must_use]
    pub const fn timeout_seconds(mut self, timeout_seconds: Option<u32>) -> Self {
        self.timeout_seconds = timeout_seconds;
        self
    }

    /// Validates and freezes the semantic step.
    ///
    /// # Errors
    ///
    /// Returns [`WorkflowPlanError`] for invalid timeouts, expressions, maps,
    /// scripts, or unresolved action references.
    pub fn build(self) -> Result<PlannedStep, WorkflowPlanError> {
        let step = PlannedStep {
            key: self.key,
            id: self.id,
            name: self.name,
            condition: self.condition,
            environment: self.environment,
            continue_on_error: self.continue_on_error,
            timeout_seconds: self.timeout_seconds,
            execution: self.execution,
            span: self.span,
        };
        step.validate()?;
        Ok(step)
    }
}
