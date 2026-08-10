//! Versioned workflow-plan envelope and graph-wide validation.

use serde::{Deserialize, Serialize};

use super::{
    CompiledValueTemplate, Located, LogicalConcurrencyTemplate, LogicalJobTemplate,
    LogicalRunDefaultsTemplate, LogicalWorkflowPlan, MAX_LOGICAL_FIELD_BYTES,
    PermissionSnapshotRequest, PlanSourceOrigin, PlanSourceSpan, TemplateValueMap,
    WorkflowEventProvenance, WorkflowInvocationContract, WorkflowJobKey, WorkflowPlanError,
    WorkflowPlanVersion, WorkflowSourceProvenance, logical::LogicalWorkflowPlanParts,
    source::validate_span_source,
};

/// Immutable, versioned workflow DAG ready for durable admission.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedWorkflowPlan")]
pub struct WorkflowPlan {
    version: WorkflowPlanVersion,
    source: WorkflowSourceProvenance,
    event: WorkflowEventProvenance,
    name: Option<Located<String>>,
    logical: LogicalWorkflowPlan,
    span: PlanSourceSpan,
}

/// Named construction path for a schema-v2 logical workflow plan.
#[derive(Clone, Debug)]
pub struct LogicalWorkflowPlanBuilder {
    source: WorkflowSourceProvenance,
    event: WorkflowEventProvenance,
    name: Option<Located<String>>,
    invocation: Option<WorkflowInvocationContract>,
    run_name: Option<Located<CompiledValueTemplate>>,
    permissions: Option<PermissionSnapshotRequest>,
    environment: TemplateValueMap,
    run_defaults: LogicalRunDefaultsTemplate,
    concurrency: Option<LogicalConcurrencyTemplate>,
    jobs: Vec<LogicalJobTemplate>,
    span: PlanSourceSpan,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedWorkflowPlan {
    version: WorkflowPlanVersion,
    source: WorkflowSourceProvenance,
    event: WorkflowEventProvenance,
    name: Option<Located<String>>,
    logical: LogicalWorkflowPlan,
    span: PlanSourceSpan,
}

impl TryFrom<UncheckedWorkflowPlan> for WorkflowPlan {
    type Error = WorkflowPlanError;

    fn try_from(value: UncheckedWorkflowPlan) -> Result<Self, Self::Error> {
        let plan = Self {
            version: value.version,
            source: value.source,
            event: value.event,
            name: value.name,
            logical: value.logical,
            span: value.span,
        };
        plan.validate()?;
        Ok(plan)
    }
}

impl WorkflowPlan {
    /// Starts a schema-v2 builder whose jobs remain logical templates until
    /// their prerequisites and matrix inputs have finalized.
    #[must_use]
    pub fn logical_builder(
        source: WorkflowSourceProvenance,
        event: WorkflowEventProvenance,
        jobs: Vec<LogicalJobTemplate>,
        span: PlanSourceSpan,
    ) -> LogicalWorkflowPlanBuilder {
        LogicalWorkflowPlanBuilder {
            source,
            event,
            name: None,
            invocation: None,
            run_name: None,
            permissions: None,
            environment: TemplateValueMap::default(),
            run_defaults: LogicalRunDefaultsTemplate::default(),
            concurrency: None,
            jobs,
            span,
        }
    }

    /// Returns the independently negotiated workflow-plan schema version.
    #[must_use]
    pub const fn version(&self) -> WorkflowPlanVersion {
        self.version
    }

    /// Returns the frontend and immutable source-origin evidence.
    #[must_use]
    pub const fn source(&self) -> &WorkflowSourceProvenance {
        &self.source
    }

    /// Returns the exact event evidence that selected this workflow.
    #[must_use]
    pub const fn event(&self) -> &WorkflowEventProvenance {
        &self.event
    }

    /// Returns the optional workflow display name with source evidence.
    #[must_use]
    pub const fn name(&self) -> Option<&Located<String>> {
        self.name.as_ref()
    }

    /// Returns the current logical jobs in canonical source order.
    #[must_use]
    pub fn jobs(&self) -> &[LogicalJobTemplate] {
        self.logical.jobs()
    }

    /// Finds a logical job by its stable source-level key.
    #[must_use]
    pub fn job(&self, key: &WorkflowJobKey) -> Option<&LogicalJobTemplate> {
        self.jobs().iter().find(|job| job.key().value() == key)
    }

    /// Returns the current logical workflow body.
    #[must_use]
    pub const fn logical(&self) -> &LogicalWorkflowPlan {
        &self.logical
    }

    /// Returns the source span covering the complete workflow definition.
    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    /// Revalidates a deserialized plan before admission or execution.
    ///
    /// # Errors
    ///
    /// Returns [`WorkflowPlanError`] for unsupported versions, invalid fields,
    /// missing edges, or cycles.
    pub fn validate(&self) -> Result<(), WorkflowPlanError> {
        if self.version != WorkflowPlanVersion::current() {
            return Err(WorkflowPlanError::UnsupportedPlanVersion {
                supported: WorkflowPlanVersion::current().get(),
                received: self.version.get(),
            });
        }
        if self.source.provider().trim().is_empty() {
            return Err(WorkflowPlanError::EmptyField("source provider"));
        }
        if self.source.source_id().trim().is_empty() {
            return Err(WorkflowPlanError::EmptyField("source identity"));
        }
        match self.source.origin() {
            PlanSourceOrigin::Repository {
                repository,
                revision,
                path,
            } => {
                for (field, value) in [
                    ("source repository", repository.as_str()),
                    ("source revision", revision.as_str()),
                    ("source workflow path", path.as_str()),
                ] {
                    if value.trim().is_empty() {
                        return Err(WorkflowPlanError::EmptyField(field));
                    }
                }
            }
            PlanSourceOrigin::LocalPath { path } if path.trim().is_empty() => {
                return Err(WorkflowPlanError::EmptyField("source local path"));
            }
            PlanSourceOrigin::Memory { name } if name.trim().is_empty() => {
                return Err(WorkflowPlanError::EmptyField("source memory name"));
            }
            PlanSourceOrigin::LocalPath { .. } | PlanSourceOrigin::Memory { .. } => {}
        }
        if self.event.provider().trim().is_empty() {
            return Err(WorkflowPlanError::EmptyField("event provider"));
        }
        if self.event.name().trim().is_empty() {
            return Err(WorkflowPlanError::EmptyField("event name"));
        }
        if self.source.provider() != self.event.provider() {
            return Err(WorkflowPlanError::ProviderMismatch {
                source_provider: self.source.provider().to_owned(),
                event_provider: self.event.provider().to_owned(),
            });
        }
        if self.span.source_id() != self.source.source_id() {
            return Err(WorkflowPlanError::PlanSourceMismatch);
        }
        self.validate_v2()
    }

    fn validate_v2(&self) -> Result<(), WorkflowPlanError> {
        self.validate_v2_envelope()?;
        validate_span_source(
            self.logical.span(),
            self.source.source_id(),
            "logical workflow",
        )?;
        self.logical.validate(self.source.source_id())
    }

    fn validate_v2_envelope(&self) -> Result<(), WorkflowPlanError> {
        for (field, value) in [
            ("source provider", self.source.provider()),
            ("source identity", self.source.source_id()),
            ("event provider", self.event.provider()),
            ("event name", self.event.name()),
        ] {
            validate_v2_text(field, value)?;
        }
        match self.source.origin() {
            PlanSourceOrigin::Repository {
                repository,
                revision,
                path,
            } => {
                for (field, value) in [
                    ("source repository", repository.as_str()),
                    ("source revision", revision.as_str()),
                    ("source workflow path", path.as_str()),
                ] {
                    validate_v2_text(field, value)?;
                }
            }
            PlanSourceOrigin::LocalPath { path } => validate_v2_text("source local path", path)?,
            PlanSourceOrigin::Memory { name } => validate_v2_text("source memory name", name)?,
        }
        for (field, value) in [
            ("event delivery id", self.event.delivery_id()),
            ("event commit sha", self.event.commit_sha()),
            ("event git ref", self.event.git_ref()),
        ] {
            if let Some(value) = value {
                validate_v2_text(field, value)?;
            }
        }
        if let Some(trigger) = self.event.configured_trigger_span() {
            validate_span_source(trigger, self.source.source_id(), "configured trigger span")?;
        }
        if let Some(name) = &self.name {
            validate_span_source(name.span(), self.source.source_id(), "workflow name")?;
            validate_v2_text("workflow name", name.value())?;
        }
        Ok(())
    }
}

fn validate_v2_text(field: &'static str, value: &str) -> Result<(), WorkflowPlanError> {
    if value.len() > MAX_LOGICAL_FIELD_BYTES {
        return Err(WorkflowPlanError::LimitExceeded {
            field,
            maximum: MAX_LOGICAL_FIELD_BYTES,
        });
    }
    Ok(())
}

impl LogicalWorkflowPlanBuilder {
    /// Sets or clears the source-located workflow display name.
    #[must_use]
    pub fn name(mut self, name: Option<Located<String>>) -> Self {
        self.name = name;
        self
    }

    /// Sets or clears the reusable-workflow invocation contract.
    #[must_use]
    pub fn invocation(mut self, invocation: Option<WorkflowInvocationContract>) -> Self {
        self.invocation = invocation;
        self
    }

    /// Sets or clears the deferred provider run-name template.
    #[must_use]
    pub fn run_name(mut self, run_name: Option<Located<CompiledValueTemplate>>) -> Self {
        self.run_name = run_name;
        self
    }

    /// Sets or clears the source-level provider permission snapshot request.
    #[must_use]
    pub fn permissions(mut self, permissions: Option<PermissionSnapshotRequest>) -> Self {
        self.permissions = permissions;
        self
    }

    /// Replaces the workflow-wide deferred environment mapping.
    #[must_use]
    pub fn environment(mut self, environment: TemplateValueMap) -> Self {
        self.environment = environment;
        self
    }

    /// Replaces workflow-wide run-step defaults.
    #[must_use]
    pub fn run_defaults(mut self, run_defaults: LogicalRunDefaultsTemplate) -> Self {
        self.run_defaults = run_defaults;
        self
    }

    /// Sets or clears the workflow-level concurrency template.
    #[must_use]
    pub fn concurrency(mut self, concurrency: Option<LogicalConcurrencyTemplate>) -> Self {
        self.concurrency = concurrency;
        self
    }

    /// Validates and freezes a schema-v2 logical workflow plan.
    ///
    /// # Errors
    ///
    /// Returns [`WorkflowPlanError`] for invalid source evidence, templates,
    /// contracts, bounded collections, result references, or graph semantics.
    pub fn build(self) -> Result<WorkflowPlan, WorkflowPlanError> {
        let logical = LogicalWorkflowPlan::from_parts(LogicalWorkflowPlanParts {
            invocation: self.invocation,
            run_name: self.run_name,
            permissions: self.permissions,
            environment: self.environment,
            run_defaults: self.run_defaults,
            concurrency: self.concurrency,
            jobs: self.jobs,
            span: self.span.clone(),
        });
        let plan = WorkflowPlan {
            version: WorkflowPlanVersion::current(),
            source: self.source,
            event: self.event,
            name: self.name,
            logical,
            span: self.span,
        };
        plan.validate()?;
        Ok(plan)
    }
}
