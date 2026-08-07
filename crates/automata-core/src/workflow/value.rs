//! Layered values, permissions, concurrency, defaults, and runner selection.

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize};

use super::{
    Located, PlanExpression, PlanSourceSpan, PlanValue, WorkflowJobKey, WorkflowPlanError,
};

/// One ordered key/value layer used for environment variables or action inputs.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValueMapPlan {
    entries: Vec<(Located<String>, Located<PlanValue>)>,
}

impl ValueMapPlan {
    #[must_use]
    pub const fn new(entries: Vec<(Located<String>, Located<PlanValue>)>) -> Self {
        Self { entries }
    }

    #[must_use]
    pub fn entries(&self) -> &[(Located<String>, Located<PlanValue>)] {
        &self.entries
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Located<PlanValue>> {
        self.entries
            .iter()
            .rev()
            .find_map(|(candidate, value)| (candidate.value() == key).then_some(value))
    }

    pub(crate) fn validate(&self) -> Result<(), WorkflowPlanError> {
        let mut keys = BTreeSet::new();
        for (key, value) in &self.entries {
            if key.value().is_empty() {
                return Err(WorkflowPlanError::EmptyField("environment key"));
            }
            if !keys.insert(key.value()) {
                return Err(WorkflowPlanError::DuplicateValueKey(key.value().clone()));
            }
            value.value().validate()?;
        }
        Ok(())
    }
}

/// A workflow, job, or step environment layer.
pub type EnvironmentPlan = ValueMapPlan;
/// Exact caller inputs retained for an unresolved action step.
pub type ActionInputsPlan = ValueMapPlan;

/// Deferred boolean accepted by GitHub-compatible fields.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum DeferredBoolean {
    Literal(bool),
    Expression(PlanExpression),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum UncheckedDeferredBoolean {
    Literal { value: bool },
    Expression { value: PlanExpression },
}

impl<'de> Deserialize<'de> for DeferredBoolean {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(match UncheckedDeferredBoolean::deserialize(deserializer)? {
            UncheckedDeferredBoolean::Literal { value } => Self::Literal(value),
            UncheckedDeferredBoolean::Expression { value } => Self::Expression(value),
        })
    }
}

impl DeferredBoolean {
    pub(crate) fn validate(&self) -> Result<(), WorkflowPlanError> {
        match self {
            Self::Literal(_) => Ok(()),
            Self::Expression(expression) => expression.validate(),
        }
    }
}

/// Automata concurrency queue policy. `Single` matches GitHub's one-pending-run behavior.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueuePolicy {
    Single,
    Max,
}

/// Workflow- or job-level concurrency semantics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConcurrencyPlan {
    group: Located<PlanExpression>,
    cancel_in_progress: Option<Located<DeferredBoolean>>,
    queue: QueuePolicy,
    span: PlanSourceSpan,
}

impl ConcurrencyPlan {
    #[must_use]
    pub const fn new(
        group: Located<PlanExpression>,
        cancel_in_progress: Option<Located<DeferredBoolean>>,
        queue: QueuePolicy,
        span: PlanSourceSpan,
    ) -> Self {
        Self {
            group,
            cancel_in_progress,
            queue,
            span,
        }
    }

    #[must_use]
    pub const fn group(&self) -> &Located<PlanExpression> {
        &self.group
    }

    #[must_use]
    pub const fn cancel_in_progress(&self) -> Option<&Located<DeferredBoolean>> {
        self.cancel_in_progress.as_ref()
    }

    #[must_use]
    pub const fn queue(&self) -> QueuePolicy {
        self.queue
    }

    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    pub(crate) fn validate(&self) -> Result<(), WorkflowPlanError> {
        if self.group.value().source().trim().is_empty() {
            return Err(WorkflowPlanError::EmptyField("concurrency group"));
        }
        self.group.value().validate()?;
        if let Some(cancel) = &self.cancel_in_progress {
            cancel.value().validate()?;
        }
        Ok(())
    }
}

/// Token permission level requested from a provider adapter.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionLevel {
    Read,
    Write,
    None,
}

/// One provider permission name and level with source evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionGrant {
    name: Located<String>,
    level: Located<PermissionLevel>,
}

impl PermissionGrant {
    #[must_use]
    pub const fn new(name: Located<String>, level: Located<PermissionLevel>) -> Self {
        Self { name, level }
    }

    #[must_use]
    pub const fn name(&self) -> &Located<String> {
        &self.name
    }

    #[must_use]
    pub const fn level(&self) -> &Located<PermissionLevel> {
        &self.level
    }
}

/// Provider token permissions preserved at their source layer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum WorkflowPermissions {
    ReadAll(PlanSourceSpan),
    WriteAll(PlanSourceSpan),
    Mapping(Vec<PermissionGrant>),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum UncheckedWorkflowPermissions {
    ReadAll { value: PlanSourceSpan },
    WriteAll { value: PlanSourceSpan },
    Mapping { value: Vec<PermissionGrant> },
}

impl<'de> Deserialize<'de> for WorkflowPermissions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(
            match UncheckedWorkflowPermissions::deserialize(deserializer)? {
                UncheckedWorkflowPermissions::ReadAll { value } => Self::ReadAll(value),
                UncheckedWorkflowPermissions::WriteAll { value } => Self::WriteAll(value),
                UncheckedWorkflowPermissions::Mapping { value } => Self::Mapping(value),
            },
        )
    }
}

impl WorkflowPermissions {
    pub(crate) fn validate(&self) -> Result<(), WorkflowPlanError> {
        let Self::Mapping(grants) = self else {
            return Ok(());
        };
        let mut names = BTreeSet::new();
        for grant in grants {
            if grant.name.value().is_empty() {
                return Err(WorkflowPlanError::EmptyField("permission name"));
            }
            if !names.insert(grant.name.value()) {
                return Err(WorkflowPlanError::DuplicatePermission(
                    grant.name.value().clone(),
                ));
            }
        }
        Ok(())
    }
}

/// Defaults applied only to `run` steps in one workflow/job layer.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunDefaultsPlan {
    shell: Option<Located<PlanValue>>,
    working_directory: Option<Located<PlanValue>>,
}

impl RunDefaultsPlan {
    #[must_use]
    pub const fn new(
        shell: Option<Located<PlanValue>>,
        working_directory: Option<Located<PlanValue>>,
    ) -> Self {
        Self {
            shell,
            working_directory,
        }
    }

    #[must_use]
    pub const fn shell(&self) -> Option<&Located<PlanValue>> {
        self.shell.as_ref()
    }

    #[must_use]
    pub const fn working_directory(&self) -> Option<&Located<PlanValue>> {
        self.working_directory.as_ref()
    }

    pub(crate) fn validate(&self) -> Result<(), WorkflowPlanError> {
        for value in [&self.shell, &self.working_directory].into_iter().flatten() {
            value.value().validate()?;
        }
        Ok(())
    }
}

/// Deferred runner group and labels used by the scheduler after expression evaluation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerProfile {
    group: Option<Located<PlanValue>>,
    labels: Vec<Located<PlanValue>>,
    span: PlanSourceSpan,
}

impl RunnerProfile {
    #[must_use]
    pub const fn new(
        group: Option<Located<PlanValue>>,
        labels: Vec<Located<PlanValue>>,
        span: PlanSourceSpan,
    ) -> Self {
        Self {
            group,
            labels,
            span,
        }
    }

    #[must_use]
    pub const fn group(&self) -> Option<&Located<PlanValue>> {
        self.group.as_ref()
    }

    #[must_use]
    pub fn labels(&self) -> &[Located<PlanValue>] {
        &self.labels
    }

    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    pub(crate) fn validate(&self, job: &WorkflowJobKey) -> Result<(), WorkflowPlanError> {
        if self.group.is_none() && self.labels.is_empty() {
            return Err(WorkflowPlanError::EmptyRunnerProfile(job.to_string()));
        }
        for value in self.group.iter().chain(&self.labels) {
            if value.value().source().trim().is_empty() {
                return Err(WorkflowPlanError::EmptyField("runner selector"));
            }
            value.value().validate()?;
        }
        Ok(())
    }
}

/// Script execution semantics. No process or shell handle is embedded.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunStepPlan {
    script: Located<PlanValue>,
    shell: Option<Located<PlanValue>>,
    working_directory: Option<Located<PlanValue>>,
}

impl RunStepPlan {
    #[must_use]
    pub const fn new(
        script: Located<PlanValue>,
        shell: Option<Located<PlanValue>>,
        working_directory: Option<Located<PlanValue>>,
    ) -> Self {
        Self {
            script,
            shell,
            working_directory,
        }
    }

    #[must_use]
    pub const fn script(&self) -> &Located<PlanValue> {
        &self.script
    }

    #[must_use]
    pub const fn shell(&self) -> Option<&Located<PlanValue>> {
        self.shell.as_ref()
    }

    #[must_use]
    pub const fn working_directory(&self) -> Option<&Located<PlanValue>> {
        self.working_directory.as_ref()
    }

    pub(crate) fn validate(&self) -> Result<(), WorkflowPlanError> {
        if self.script.value().source().is_empty() {
            return Err(WorkflowPlanError::EmptyField("run script"));
        }
        self.script.value().validate()?;
        for value in [&self.shell, &self.working_directory].into_iter().flatten() {
            value.value().validate()?;
        }
        Ok(())
    }
}

/// Unresolved action reference and exact caller inputs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UsesStepPlan {
    reference: Located<String>,
    inputs: ActionInputsPlan,
}

impl UsesStepPlan {
    #[must_use]
    pub const fn new(reference: Located<String>, inputs: ActionInputsPlan) -> Self {
        Self { reference, inputs }
    }

    #[must_use]
    pub const fn reference(&self) -> &Located<String> {
        &self.reference
    }

    #[must_use]
    pub const fn inputs(&self) -> &ActionInputsPlan {
        &self.inputs
    }

    pub(crate) fn validate(&self) -> Result<(), WorkflowPlanError> {
        if self.reference.value().is_empty() {
            return Err(WorkflowPlanError::EmptyField("uses reference"));
        }
        self.inputs.validate()
    }
}
