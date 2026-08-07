//! The immutable, versioned job plan and its source coordinates.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    ContainerSpec, ExpressionProgram, JobIrVersion, JobValidationError, SemanticStep, StepIr,
};
use crate::{
    JobId, RUNNER_REQUIREMENTS_SCHEMA_VERSION, RunId, RunnerRequirements, Sha256Digest, WorkflowId,
};

const MAX_EXECUTION_CONTEXT_TEXT_BYTES: usize = 1_024;
const MAX_CONTENT_KEY_BYTES: usize = 1_024;
const MAX_CONTENT_MEDIA_TYPE_BYTES: usize = 128;
const MAX_EVENT_CONTENT_BYTES: u64 = 16 * 1024 * 1024;

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

/// Credential-free immutable content identity needed to execute a job.
///
/// `object_key` is the provider-neutral logical blob key retained by admission,
/// not an S3 bucket prefix or physical object name.
/// Admission publishers and runners must resolve that same logical key in one
/// shared immutable blob namespace. Adapters must not add a second logical
/// prefix to the reference.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobContentReference {
    object_key: String,
    digest: Sha256Digest,
    encoded_size: u64,
    media_type: String,
}

impl JobContentReference {
    /// Creates an immutable content reference. Validation remains explicit at
    /// the enclosing [`JobIrEnvelope`] trust boundary.
    #[must_use]
    pub fn new(
        object_key: impl Into<String>,
        digest: Sha256Digest,
        encoded_size: u64,
        media_type: impl Into<String>,
    ) -> Self {
        Self {
            object_key: object_key.into(),
            digest,
            encoded_size,
            media_type: media_type.into(),
        }
    }

    #[must_use]
    pub fn object_key(&self) -> &str {
        &self.object_key
    }

    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    #[must_use]
    pub const fn encoded_size(&self) -> u64 {
        self.encoded_size
    }

    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }
}

/// Immutable provider context and target paths required by job execution.
///
/// Optional provider identities remain absent when the authenticated ingress
/// did not supply them. Consumers must not synthesize replacements.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobExecutionContext {
    workflow_name: String,
    git_ref: String,
    workspace: String,
    actor: Option<String>,
    run_number: Option<u64>,
    run_attempt: Option<u32>,
    event: JobContentReference,
}

impl JobExecutionContext {
    /// Creates the required immutable execution context.
    #[must_use]
    pub fn new(
        workflow_name: impl Into<String>,
        git_ref: impl Into<String>,
        workspace: impl Into<String>,
        event: JobContentReference,
    ) -> Self {
        Self {
            workflow_name: workflow_name.into(),
            git_ref: git_ref.into(),
            workspace: workspace.into(),
            actor: None,
            run_number: None,
            run_attempt: None,
            event,
        }
    }

    #[must_use]
    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    #[must_use]
    pub const fn with_run_number(mut self, run_number: u64) -> Self {
        self.run_number = Some(run_number);
        self
    }

    #[must_use]
    pub const fn with_run_attempt(mut self, run_attempt: u32) -> Self {
        self.run_attempt = Some(run_attempt);
        self
    }

    #[must_use]
    pub fn workflow_name(&self) -> &str {
        &self.workflow_name
    }

    #[must_use]
    pub fn git_ref(&self) -> &str {
        &self.git_ref
    }

    #[must_use]
    pub fn workspace(&self) -> &str {
        &self.workspace
    }

    #[must_use]
    pub fn actor(&self) -> Option<&str> {
        self.actor.as_deref()
    }

    #[must_use]
    pub const fn run_number(&self) -> Option<u64> {
        self.run_number
    }

    #[must_use]
    pub const fn run_attempt(&self) -> Option<u32> {
        self.run_attempt
    }

    #[must_use]
    pub const fn event(&self) -> &JobContentReference {
        &self.event
    }
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
    #[serde(rename = "schema_version")]
    version: JobIrVersion,
    workflow_id: WorkflowId,
    source: JobSource,
    execution: JobExecutionContext,
    job: JobIr,
}

impl JobIrEnvelope {
    /// Creates an envelope using the current domain schema.
    #[must_use]
    pub const fn new(
        workflow_id: WorkflowId,
        source: JobSource,
        execution: JobExecutionContext,
        job: JobIr,
    ) -> Self {
        Self {
            version: JobIrVersion::current(),
            workflow_id,
            source,
            execution,
            job,
        }
    }

    #[must_use]
    pub const fn version(&self) -> JobIrVersion {
        self.version
    }

    /// Returns the numeric schema version used by the existing JSON envelope.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.version.get()
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
    pub const fn execution(&self) -> &JobExecutionContext {
        &self.execution
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
        if self.version.get() != JobIrVersion::current().get() {
            return Err(JobValidationError::UnsupportedSchema {
                supported: JobIrVersion::current().get(),
                received: self.version.get(),
            });
        }
        if self.job.requirements.schema_version() != RUNNER_REQUIREMENTS_SCHEMA_VERSION {
            return Err(JobValidationError::UnsupportedRequirementsSchema {
                supported: RUNNER_REQUIREMENTS_SCHEMA_VERSION,
                received: self.job.requirements.schema_version(),
            });
        }
        for (field, value) in [
            ("source.provider", self.source.provider.as_str()),
            ("source.repository", self.source.repository.as_str()),
            ("source.revision", self.source.revision.as_str()),
            ("source.workflow_path", self.source.workflow_path.as_str()),
            (
                "execution.workflow_name",
                self.execution.workflow_name.as_str(),
            ),
            ("execution.git_ref", self.execution.git_ref.as_str()),
            ("execution.workspace", self.execution.workspace.as_str()),
            ("job.name", self.job.name.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(JobValidationError::EmptyField(field));
            }
        }
        validate_execution_context(&self.execution)?;
        if self.job.steps.is_empty() {
            return Err(JobValidationError::NoSteps);
        }
        if self.job.timeout_seconds == Some(0) {
            return Err(JobValidationError::ZeroTimeout);
        }
        if let Some(condition) = &self.job.condition {
            condition
                .validate()
                .map_err(|source| JobValidationError::InvalidExpression {
                    field: "job condition",
                    source,
                })?;
        }

        let mut step_ids = BTreeSet::new();
        for step in &self.job.steps {
            if !step_ids.insert(step.id().clone()) {
                return Err(JobValidationError::DuplicateStepId(step.id().clone()));
            }
            if step.timeout_seconds() == Some(0) {
                return Err(JobValidationError::ZeroStepTimeout(step.id().clone()));
            }
            if let Some(condition) = step.condition() {
                condition
                    .validate()
                    .map_err(|source| JobValidationError::InvalidExpression {
                        field: "step condition",
                        source,
                    })?;
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

fn validate_execution_context(context: &JobExecutionContext) -> Result<(), JobValidationError> {
    for (field, value) in [
        ("execution.workflow_name", context.workflow_name.as_str()),
        ("execution.git_ref", context.git_ref.as_str()),
        ("execution.workspace", context.workspace.as_str()),
    ] {
        validate_bounded_text(value, field)?;
    }
    if !canonical_git_ref(&context.git_ref) {
        return Err(JobValidationError::InvalidGitRef);
    }
    if !canonical_target_path(&context.workspace) {
        return Err(JobValidationError::InvalidWorkspace);
    }
    if let Some(actor) = &context.actor {
        validate_bounded_text(actor, "execution.actor")?;
    }
    if context.run_number == Some(0) {
        return Err(JobValidationError::ZeroRunNumber);
    }
    if context.run_attempt == Some(0) {
        return Err(JobValidationError::ZeroRunAttempt);
    }
    validate_content_reference(&context.event)
}

fn validate_content_reference(reference: &JobContentReference) -> Result<(), JobValidationError> {
    let key = reference.object_key.as_str();
    if key.is_empty()
        || key.len() > MAX_CONTENT_KEY_BYTES
        || key.starts_with('/')
        || key.contains('\\')
        || key.chars().any(char::is_control)
        || key
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(JobValidationError::InvalidContentReference);
    }
    let media_type = reference.media_type.as_str();
    let mut media_type_components = media_type.split('/');
    if reference.encoded_size == 0
        || reference.encoded_size > MAX_EVENT_CONTENT_BYTES
        || media_type.is_empty()
        || media_type.len() > MAX_CONTENT_MEDIA_TYPE_BYTES
        || !media_type.is_ascii()
        || !media_type.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'&'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'|'
                        | b'~'
                        | b'/'
                )
        })
        || media_type_components.next().is_none_or(str::is_empty)
        || media_type_components.next().is_none_or(str::is_empty)
        || media_type_components.next().is_some()
    {
        return Err(JobValidationError::InvalidContentReference);
    }
    Ok(())
}

fn validate_bounded_text(value: &str, field: &'static str) -> Result<(), JobValidationError> {
    if value.trim().is_empty()
        || value.len() > MAX_EXECUTION_CONTEXT_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(JobValidationError::InvalidContextField(field));
    }
    Ok(())
}

fn canonical_git_ref(value: &str) -> bool {
    value.starts_with("refs/")
        && value != "refs/"
        && !value.ends_with(['/', '.'])
        && !value.contains("//")
        && !value.contains("..")
        && !value.contains("@{")
        && value.split('/').all(|component| {
            !component.is_empty()
                && !component.starts_with('.')
                && !component.ends_with('.')
                && !component.as_bytes().ends_with(b".lock")
        })
        && !value.chars().any(|character| {
            character.is_control() || character.is_whitespace() || "\\~^:?*[]".contains(character)
        })
}

fn canonical_target_path(value: &str) -> bool {
    if value.starts_with('/') {
        return !value.contains("//")
            && value != "/"
            && value
                .split('/')
                .skip(1)
                .all(|component| !component.is_empty() && !matches!(component, "." | ".."));
    }
    let bytes = value.as_bytes();
    bytes.len() >= 4
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'\\'
        && !value.contains("\\\\")
        && value
            .split('\\')
            .skip(1)
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
}

/// Fully planned semantics for one workflow job.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JobIr {
    job_id: JobId,
    run_id: RunId,
    name: String,
    requirements: RunnerRequirements,
    condition: Option<ExpressionProgram>,
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
    pub const fn condition(&self) -> Option<&ExpressionProgram> {
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
    pub fn with_condition(mut self, condition: ExpressionProgram) -> Self {
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

/// A value whose provenance controls when and how it may be resolved.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ValueSource {
    Literal(String),
    Expression(ExpressionProgram),
    SecretReference(String),
}
