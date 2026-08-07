//! Immutable nodes in the workflow dependency graph.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{
    ConcurrencyPlan, DeferredBoolean, EnvironmentPlan, Located, PlanExpression, PlanSourceSpan,
    PlannedStep, RunDefaultsPlan, RunnerProfile, WorkflowJobKey, WorkflowPermissions,
    WorkflowPlanError,
};

/// One node in the immutable workflow dependency graph.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedPlannedJob")]
pub struct PlannedJob {
    key: Located<WorkflowJobKey>,
    name: Option<Located<String>>,
    needs: Vec<Located<WorkflowJobKey>>,
    condition: Option<Located<PlanExpression>>,
    permissions: Option<WorkflowPermissions>,
    concurrency: Option<ConcurrencyPlan>,
    environment: EnvironmentPlan,
    run_defaults: RunDefaultsPlan,
    runner: RunnerProfile,
    timeout_seconds: Option<u32>,
    continue_on_error: Option<Located<DeferredBoolean>>,
    steps: Vec<PlannedStep>,
    span: PlanSourceSpan,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedPlannedJob {
    key: Located<WorkflowJobKey>,
    name: Option<Located<String>>,
    needs: Vec<Located<WorkflowJobKey>>,
    condition: Option<Located<PlanExpression>>,
    permissions: Option<WorkflowPermissions>,
    concurrency: Option<ConcurrencyPlan>,
    environment: EnvironmentPlan,
    run_defaults: RunDefaultsPlan,
    runner: RunnerProfile,
    timeout_seconds: Option<u32>,
    continue_on_error: Option<Located<DeferredBoolean>>,
    steps: Vec<PlannedStep>,
    span: PlanSourceSpan,
}

impl TryFrom<UncheckedPlannedJob> for PlannedJob {
    type Error = WorkflowPlanError;

    fn try_from(value: UncheckedPlannedJob) -> Result<Self, Self::Error> {
        let job = Self {
            key: value.key,
            name: value.name,
            needs: value.needs,
            condition: value.condition,
            permissions: value.permissions,
            concurrency: value.concurrency,
            environment: value.environment,
            run_defaults: value.run_defaults,
            runner: value.runner,
            timeout_seconds: value.timeout_seconds,
            continue_on_error: value.continue_on_error,
            steps: value.steps,
            span: value.span,
        };
        job.validate()?;
        Ok(job)
    }
}

/// Named construction path for one immutable workflow-DAG node.
#[derive(Clone, Debug)]
pub struct PlannedJobBuilder {
    key: Located<WorkflowJobKey>,
    name: Option<Located<String>>,
    needs: Vec<Located<WorkflowJobKey>>,
    condition: Option<Located<PlanExpression>>,
    permissions: Option<WorkflowPermissions>,
    concurrency: Option<ConcurrencyPlan>,
    environment: EnvironmentPlan,
    run_defaults: RunDefaultsPlan,
    runner: RunnerProfile,
    timeout_seconds: Option<u32>,
    continue_on_error: Option<Located<DeferredBoolean>>,
    steps: Vec<PlannedStep>,
    span: PlanSourceSpan,
}

impl PlannedJob {
    /// Starts a builder with the fields every workflow job must provide.
    #[must_use]
    pub fn builder(
        key: Located<WorkflowJobKey>,
        runner: RunnerProfile,
        steps: Vec<PlannedStep>,
        span: PlanSourceSpan,
    ) -> PlannedJobBuilder {
        PlannedJobBuilder {
            key,
            name: None,
            needs: Vec::new(),
            condition: None,
            permissions: None,
            concurrency: None,
            environment: EnvironmentPlan::default(),
            run_defaults: RunDefaultsPlan::default(),
            runner,
            timeout_seconds: None,
            continue_on_error: None,
            steps,
            span,
        }
    }

    #[must_use]
    pub const fn key(&self) -> &Located<WorkflowJobKey> {
        &self.key
    }

    #[must_use]
    pub const fn name(&self) -> Option<&Located<String>> {
        self.name.as_ref()
    }

    #[must_use]
    pub fn needs(&self) -> &[Located<WorkflowJobKey>] {
        &self.needs
    }

    #[must_use]
    pub const fn condition(&self) -> Option<&Located<PlanExpression>> {
        self.condition.as_ref()
    }

    #[must_use]
    pub const fn permissions(&self) -> Option<&WorkflowPermissions> {
        self.permissions.as_ref()
    }

    #[must_use]
    pub const fn concurrency(&self) -> Option<&ConcurrencyPlan> {
        self.concurrency.as_ref()
    }

    #[must_use]
    pub const fn environment(&self) -> &EnvironmentPlan {
        &self.environment
    }

    #[must_use]
    pub const fn run_defaults(&self) -> &RunDefaultsPlan {
        &self.run_defaults
    }

    #[must_use]
    pub const fn runner(&self) -> &RunnerProfile {
        &self.runner
    }

    #[must_use]
    pub const fn timeout_seconds(&self) -> Option<u32> {
        self.timeout_seconds
    }

    #[must_use]
    pub const fn continue_on_error(&self) -> Option<&Located<DeferredBoolean>> {
        self.continue_on_error.as_ref()
    }

    #[must_use]
    pub fn steps(&self) -> &[PlannedStep] {
        &self.steps
    }

    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    pub(crate) fn validate(&self) -> Result<(), WorkflowPlanError> {
        let job = self.key.value();
        if self.timeout_seconds == Some(0) {
            return Err(WorkflowPlanError::ZeroTimeout(job.to_string()));
        }
        if self.steps.is_empty() {
            return Err(WorkflowPlanError::NoSteps(job.to_string()));
        }
        self.runner.validate(job)?;
        self.environment.validate()?;
        self.run_defaults.validate()?;
        if let Some(condition) = &self.condition {
            condition.value().validate()?;
        }
        if let Some(permissions) = &self.permissions {
            permissions.validate()?;
        }
        if let Some(concurrency) = &self.concurrency {
            concurrency.validate()?;
        }
        if let Some(value) = &self.continue_on_error {
            value.value().validate()?;
        }
        let mut step_keys = BTreeSet::new();
        for step in &self.steps {
            if !step_keys.insert(step.key()) {
                return Err(WorkflowPlanError::DuplicateStep {
                    job: job.to_string(),
                    step: step.key().to_string(),
                });
            }
            step.validate()?;
        }
        Ok(())
    }
}

impl PlannedJobBuilder {
    #[must_use]
    pub fn name(mut self, name: Option<Located<String>>) -> Self {
        self.name = name;
        self
    }

    #[must_use]
    pub fn needs(mut self, needs: Vec<Located<WorkflowJobKey>>) -> Self {
        self.needs = needs;
        self
    }

    #[must_use]
    pub fn condition(mut self, condition: Option<Located<PlanExpression>>) -> Self {
        self.condition = condition;
        self
    }

    #[must_use]
    pub fn permissions(mut self, permissions: Option<WorkflowPermissions>) -> Self {
        self.permissions = permissions;
        self
    }

    #[must_use]
    pub fn concurrency(mut self, concurrency: Option<ConcurrencyPlan>) -> Self {
        self.concurrency = concurrency;
        self
    }

    #[must_use]
    pub fn environment(mut self, environment: EnvironmentPlan) -> Self {
        self.environment = environment;
        self
    }

    #[must_use]
    pub fn run_defaults(mut self, run_defaults: RunDefaultsPlan) -> Self {
        self.run_defaults = run_defaults;
        self
    }

    #[must_use]
    pub const fn timeout_seconds(mut self, timeout_seconds: Option<u32>) -> Self {
        self.timeout_seconds = timeout_seconds;
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

    /// Validates and freezes one job node. Graph-wide dependency validation is
    /// performed when the containing [`super::WorkflowPlan`] is built.
    ///
    /// # Errors
    ///
    /// Returns [`WorkflowPlanError`] for invalid job-local semantics.
    pub fn build(self) -> Result<PlannedJob, WorkflowPlanError> {
        let job = PlannedJob {
            key: self.key,
            name: self.name,
            needs: self.needs,
            condition: self.condition,
            permissions: self.permissions,
            concurrency: self.concurrency,
            environment: self.environment,
            run_defaults: self.run_defaults,
            runner: self.runner,
            timeout_seconds: self.timeout_seconds,
            continue_on_error: self.continue_on_error,
            steps: self.steps,
            span: self.span,
        };
        job.validate()?;
        Ok(job)
    }
}
