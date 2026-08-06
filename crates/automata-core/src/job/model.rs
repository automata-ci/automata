//! The immutable, versioned job plan and its source coordinates.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{ContainerSpec, JobValidationError, SemanticStep, StepIr};
use crate::{CORE_SCHEMA_VERSION, JobId, RunId, RunnerRequirements, WorkflowId};

/// Original source coordinates for an immutable job plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JobSource {
    /// SCM provider name, such as `github`.
    provider: String,
    /// Provider-native repository identifier without embedding credentials.
    repository: String,
    /// Immutable commit identifier used by this run.
    revision: String,
    /// Repository-relative source workflow path.
    workflow_path: String,
    /// Trigger/event name whose payload was used to plan the job.
    event_name: String,
}

impl JobSource {
    #[must_use]
    pub fn new(
        provider: impl Into<String>,
        repository: impl Into<String>,
        revision: impl Into<String>,
        workflow_path: impl Into<String>,
        event_name: impl Into<String>,
    ) -> Self {
        Self {
            provider: provider.into(),
            repository: repository.into(),
            revision: revision.into(),
            workflow_path: workflow_path.into(),
            event_name: event_name.into(),
        }
    }

    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    #[must_use]
    pub fn repository(&self) -> &str {
        &self.repository
    }

    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }

    #[must_use]
    pub fn workflow_path(&self) -> &str {
        &self.workflow_path
    }

    #[must_use]
    pub fn event_name(&self) -> &str {
        &self.event_name
    }
}

/// Versioned envelope for the semantic job IR.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JobIrEnvelope {
    schema_version: u16,
    workflow_id: WorkflowId,
    source: JobSource,
    job: JobIr,
}

impl JobIrEnvelope {
    /// Creates an envelope using the current domain schema.
    #[must_use]
    pub const fn new(workflow_id: WorkflowId, source: JobSource, job: JobIr) -> Self {
        Self {
            schema_version: CORE_SCHEMA_VERSION,
            workflow_id,
            source,
            job,
        }
    }

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }

    #[must_use]
    pub const fn source(&self) -> &JobSource {
        &self.source
    }

    #[must_use]
    pub const fn job(&self) -> &JobIr {
        &self.job
    }

    /// Validates cross-field and schema invariants before execution.
    ///
    /// # Errors
    ///
    /// Returns [`JobValidationError`] for unsupported schemas or any invalid
    /// semantic field that must be rejected during planning.
    pub fn validate(&self) -> Result<(), JobValidationError> {
        if self.schema_version != CORE_SCHEMA_VERSION {
            return Err(JobValidationError::UnsupportedSchema {
                supported: CORE_SCHEMA_VERSION,
                received: self.schema_version,
            });
        }
        if self.job.requirements.schema_version() != CORE_SCHEMA_VERSION {
            return Err(JobValidationError::UnsupportedRequirementsSchema {
                supported: CORE_SCHEMA_VERSION,
                received: self.job.requirements.schema_version(),
            });
        }
        for (field, value) in [
            ("source.provider", self.source.provider.as_str()),
            ("source.repository", self.source.repository.as_str()),
            ("source.revision", self.source.revision.as_str()),
            ("source.workflow_path", self.source.workflow_path.as_str()),
            ("job.name", self.job.name.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(JobValidationError::EmptyField(field));
            }
        }
        if self.job.steps.is_empty() {
            return Err(JobValidationError::NoSteps);
        }
        if self.job.timeout_seconds == Some(0) {
            return Err(JobValidationError::ZeroTimeout);
        }

        let mut step_ids = BTreeSet::new();
        for step in &self.job.steps {
            if !step_ids.insert(step.id().clone()) {
                return Err(JobValidationError::DuplicateStepId(step.id().clone()));
            }
            if step.timeout_seconds() == Some(0) {
                return Err(JobValidationError::ZeroStepTimeout(step.id().clone()));
            }
            match step.kind() {
                SemanticStep::Run { command, .. } if command.is_empty() => {
                    return Err(JobValidationError::EmptyRunCommand(step.id().clone()));
                }
                SemanticStep::Action { reference, .. } => reference.validate()?,
                SemanticStep::Run { .. } => {}
            }
        }

        if let Some(container) = &self.job.container {
            container.validate("job container")?;
        }
        for (service_id, service) in &self.job.services {
            if service_id.trim().is_empty() {
                return Err(JobValidationError::EmptyField("service id"));
            }
            service.validate("service container")?;
        }
        Ok(())
    }
}

/// Fully planned semantics for one workflow job.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JobIr {
    job_id: JobId,
    run_id: RunId,
    name: String,
    requirements: RunnerRequirements,
    condition: Option<Expression>,
    timeout_seconds: Option<u32>,
    environment: BTreeMap<String, ValueSource>,
    working_directory: Option<String>,
    container: Option<ContainerSpec>,
    services: BTreeMap<String, ContainerSpec>,
    steps: Vec<StepIr>,
}

impl JobIr {
    /// Creates the required portion of a planned job.
    #[must_use]
    pub fn new(
        job_id: JobId,
        run_id: RunId,
        name: impl Into<String>,
        requirements: RunnerRequirements,
        steps: Vec<StepIr>,
    ) -> Self {
        Self {
            job_id,
            run_id,
            name: name.into(),
            requirements,
            condition: None,
            timeout_seconds: None,
            environment: BTreeMap::new(),
            working_directory: None,
            container: None,
            services: BTreeMap::new(),
            steps,
        }
    }

    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn requirements(&self) -> &RunnerRequirements {
        &self.requirements
    }

    #[must_use]
    pub const fn condition(&self) -> Option<&Expression> {
        self.condition.as_ref()
    }

    #[must_use]
    pub const fn timeout_seconds(&self) -> Option<u32> {
        self.timeout_seconds
    }

    #[must_use]
    pub const fn environment(&self) -> &BTreeMap<String, ValueSource> {
        &self.environment
    }

    #[must_use]
    pub fn working_directory(&self) -> Option<&str> {
        self.working_directory.as_deref()
    }

    #[must_use]
    pub const fn container(&self) -> Option<&ContainerSpec> {
        self.container.as_ref()
    }

    #[must_use]
    pub const fn services(&self) -> &BTreeMap<String, ContainerSpec> {
        &self.services
    }

    #[must_use]
    pub fn steps(&self) -> &[StepIr] {
        &self.steps
    }

    #[must_use]
    pub fn with_condition(mut self, condition: Expression) -> Self {
        self.condition = Some(condition);
        self
    }

    #[must_use]
    pub const fn with_timeout_seconds(mut self, timeout_seconds: u32) -> Self {
        self.timeout_seconds = Some(timeout_seconds);
        self
    }

    #[must_use]
    pub fn with_environment(mut self, environment: BTreeMap<String, ValueSource>) -> Self {
        self.environment = environment;
        self
    }

    #[must_use]
    pub fn with_working_directory(mut self, working_directory: impl Into<String>) -> Self {
        self.working_directory = Some(working_directory.into());
        self
    }

    #[must_use]
    pub fn with_container(mut self, container: ContainerSpec) -> Self {
        self.container = Some(container);
        self
    }

    #[must_use]
    pub fn with_services(mut self, services: BTreeMap<String, ContainerSpec>) -> Self {
        self.services = services;
        self
    }
}

/// Expression text retained for evaluation in the correct runtime phase.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Expression(String);

impl Expression {
    #[must_use]
    pub fn new(expression: impl Into<String>) -> Self {
        Self(expression.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl From<String> for Expression {
    fn from(expression: String) -> Self {
        Self(expression)
    }
}

impl From<&str> for Expression {
    fn from(expression: &str) -> Self {
        Self(expression.to_owned())
    }
}

/// A value whose provenance controls when and how it may be resolved.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ValueSource {
    Literal(String),
    Expression(Expression),
    SecretReference(String),
}
