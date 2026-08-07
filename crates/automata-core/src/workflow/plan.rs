//! Versioned workflow-plan envelope and graph-wide validation.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{
    ConcurrencyPlan, EnvironmentPlan, Located, PlanSourceOrigin, PlanSourceSpan, PlanValue,
    PlannedJob, RunDefaultsPlan, WorkflowEventProvenance, WorkflowJobKey, WorkflowPermissions,
    WorkflowPlanError, WorkflowPlanVersion, WorkflowSourceProvenance,
};

/// Immutable, versioned workflow DAG ready for durable admission.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedWorkflowPlan")]
pub struct WorkflowPlan {
    version: WorkflowPlanVersion,
    source: WorkflowSourceProvenance,
    event: WorkflowEventProvenance,
    name: Option<Located<String>>,
    run_name: Option<Located<PlanValue>>,
    permissions: Option<WorkflowPermissions>,
    environment: EnvironmentPlan,
    run_defaults: RunDefaultsPlan,
    concurrency: Option<ConcurrencyPlan>,
    jobs: Vec<PlannedJob>,
    span: PlanSourceSpan,
}

/// Named construction path for an immutable, versioned workflow DAG.
#[derive(Clone, Debug)]
pub struct WorkflowPlanBuilder {
    source: WorkflowSourceProvenance,
    event: WorkflowEventProvenance,
    name: Option<Located<String>>,
    run_name: Option<Located<PlanValue>>,
    permissions: Option<WorkflowPermissions>,
    environment: EnvironmentPlan,
    run_defaults: RunDefaultsPlan,
    concurrency: Option<ConcurrencyPlan>,
    jobs: Vec<PlannedJob>,
    span: PlanSourceSpan,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedWorkflowPlan {
    version: WorkflowPlanVersion,
    source: WorkflowSourceProvenance,
    event: WorkflowEventProvenance,
    name: Option<Located<String>>,
    run_name: Option<Located<PlanValue>>,
    permissions: Option<WorkflowPermissions>,
    environment: EnvironmentPlan,
    run_defaults: RunDefaultsPlan,
    concurrency: Option<ConcurrencyPlan>,
    jobs: Vec<PlannedJob>,
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
            run_name: value.run_name,
            permissions: value.permissions,
            environment: value.environment,
            run_defaults: value.run_defaults,
            concurrency: value.concurrency,
            jobs: value.jobs,
            span: value.span,
        };
        plan.validate()?;
        Ok(plan)
    }
}

impl WorkflowPlan {
    /// Starts a builder with source/event evidence, graph nodes, and the root span.
    #[must_use]
    pub fn builder(
        source: WorkflowSourceProvenance,
        event: WorkflowEventProvenance,
        jobs: Vec<PlannedJob>,
        span: PlanSourceSpan,
    ) -> WorkflowPlanBuilder {
        WorkflowPlanBuilder {
            source,
            event,
            name: None,
            run_name: None,
            permissions: None,
            environment: EnvironmentPlan::default(),
            run_defaults: RunDefaultsPlan::default(),
            concurrency: None,
            jobs,
            span,
        }
    }

    #[must_use]
    pub const fn version(&self) -> WorkflowPlanVersion {
        self.version
    }

    #[must_use]
    pub const fn source(&self) -> &WorkflowSourceProvenance {
        &self.source
    }

    #[must_use]
    pub const fn event(&self) -> &WorkflowEventProvenance {
        &self.event
    }

    #[must_use]
    pub const fn name(&self) -> Option<&Located<String>> {
        self.name.as_ref()
    }

    #[must_use]
    pub const fn run_name(&self) -> Option<&Located<PlanValue>> {
        self.run_name.as_ref()
    }

    #[must_use]
    pub const fn permissions(&self) -> Option<&WorkflowPermissions> {
        self.permissions.as_ref()
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
    pub const fn concurrency(&self) -> Option<&ConcurrencyPlan> {
        self.concurrency.as_ref()
    }

    #[must_use]
    pub fn jobs(&self) -> &[PlannedJob] {
        &self.jobs
    }

    #[must_use]
    pub fn job(&self, key: &WorkflowJobKey) -> Option<&PlannedJob> {
        self.jobs.iter().find(|job| job.key().value() == key)
    }

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
        if self.jobs.is_empty() {
            return Err(WorkflowPlanError::NoJobs);
        }
        self.environment.validate()?;
        self.run_defaults.validate()?;
        if let Some(run_name) = &self.run_name {
            run_name.value().validate()?;
        }
        if let Some(permissions) = &self.permissions {
            permissions.validate()?;
        }
        if let Some(concurrency) = &self.concurrency {
            concurrency.validate()?;
        }

        let mut job_keys = BTreeSet::new();
        for job in &self.jobs {
            if !job_keys.insert(job.key().value()) {
                return Err(WorkflowPlanError::DuplicateJob(
                    job.key().value().to_string(),
                ));
            }
            job.validate()?;
        }
        for job in &self.jobs {
            for dependency in job.needs() {
                if dependency.value() == job.key().value() {
                    return Err(WorkflowPlanError::SelfDependency(
                        job.key().value().to_string(),
                    ));
                }
                if !job_keys.contains(dependency.value()) {
                    return Err(WorkflowPlanError::UnknownDependency {
                        job: job.key().value().to_string(),
                        dependency: dependency.value().to_string(),
                    });
                }
            }
        }
        validate_acyclic(&self.jobs)
    }
}

impl WorkflowPlanBuilder {
    #[must_use]
    pub fn name(mut self, name: Option<Located<String>>) -> Self {
        self.name = name;
        self
    }

    #[must_use]
    pub fn run_name(mut self, run_name: Option<Located<PlanValue>>) -> Self {
        self.run_name = run_name;
        self
    }

    #[must_use]
    pub fn permissions(mut self, permissions: Option<WorkflowPermissions>) -> Self {
        self.permissions = permissions;
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
    pub fn concurrency(mut self, concurrency: Option<ConcurrencyPlan>) -> Self {
        self.concurrency = concurrency;
        self
    }

    /// Validates and freezes the current workflow-plan schema.
    ///
    /// # Errors
    ///
    /// Returns [`WorkflowPlanError`] for an invalid DAG or semantic field.
    pub fn build(self) -> Result<WorkflowPlan, WorkflowPlanError> {
        let plan = WorkflowPlan {
            version: WorkflowPlanVersion::current(),
            source: self.source,
            event: self.event,
            name: self.name,
            run_name: self.run_name,
            permissions: self.permissions,
            environment: self.environment,
            run_defaults: self.run_defaults,
            concurrency: self.concurrency,
            jobs: self.jobs,
            span: self.span,
        };
        plan.validate()?;
        Ok(plan)
    }
}

fn validate_acyclic(jobs: &[PlannedJob]) -> Result<(), WorkflowPlanError> {
    let mut complete = BTreeSet::new();
    let mut visiting = BTreeSet::new();
    for job in jobs {
        visit(job.key().value(), jobs, &mut visiting, &mut complete)?;
    }
    Ok(())
}

fn visit<'a>(
    key: &'a WorkflowJobKey,
    jobs: &'a [PlannedJob],
    visiting: &mut BTreeSet<&'a WorkflowJobKey>,
    complete: &mut BTreeSet<&'a WorkflowJobKey>,
) -> Result<(), WorkflowPlanError> {
    if complete.contains(key) {
        return Ok(());
    }
    if !visiting.insert(key) {
        return Err(WorkflowPlanError::DependencyCycle);
    }
    let job = jobs
        .iter()
        .find(|candidate| candidate.key().value() == key)
        .expect("dependency existence was checked");
    for dependency in job.needs() {
        visit(dependency.value(), jobs, visiting, complete)?;
    }
    visiting.remove(key);
    complete.insert(key);
    Ok(())
}
