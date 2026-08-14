//! The immutable, versioned job plan and its source coordinates.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    ActionReference, ContainerSpec, ExpressionInstruction, ExpressionProgram, JobInstanceIdentity,
    JobIrVersion, JobOutputDefinition, JobPermissionRequest, JobValidationError, RuntimeBoolean,
    RuntimePositiveInteger, SemanticStep, StepIr, ValueTemplate,
};

use crate::{
    JobId, OutputSensitivity, RUNNER_REQUIREMENTS_SCHEMA_VERSION, RunId, RunIdAlias, RunnerFeature,
    RunnerRequirements, Sha256Digest, WorkflowId,
};

/// Canonical media type for the exact provider event attached to a job.
pub const WORKFLOW_EVENT_MEDIA_TYPE: &str = "application/json";

const MAX_EXECUTION_CONTEXT_TEXT_BYTES: usize = 1_024;
const MAX_CONTENT_KEY_BYTES: usize = 1_024;
const MAX_CONTENT_MEDIA_TYPE_BYTES: usize = 128;
const MAX_JOB_CONTENT_BYTES: u64 = 16_777_216;
const MAX_SECRET_REFERENCE_BYTES: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JobModelLimitRejection {
    ExecutionContextTextBytes,
    ContentKeyBytes,
    ContentMediaTypeBytes,
    JobContentBytes,
    SecretReferenceBytes,
}

const fn execution_context_text_byte_rejection(observed: usize) -> Option<JobModelLimitRejection> {
    if observed > MAX_EXECUTION_CONTEXT_TEXT_BYTES {
        return Some(JobModelLimitRejection::ExecutionContextTextBytes);
    }
    None
}

const fn content_key_byte_rejection(observed: usize) -> Option<JobModelLimitRejection> {
    if observed > MAX_CONTENT_KEY_BYTES {
        return Some(JobModelLimitRejection::ContentKeyBytes);
    }
    None
}

const fn content_media_type_byte_rejection(observed: usize) -> Option<JobModelLimitRejection> {
    if observed > MAX_CONTENT_MEDIA_TYPE_BYTES {
        return Some(JobModelLimitRejection::ContentMediaTypeBytes);
    }
    None
}

const fn job_content_byte_rejection(observed: u64) -> Option<JobModelLimitRejection> {
    if observed > MAX_JOB_CONTENT_BYTES {
        return Some(JobModelLimitRejection::JobContentBytes);
    }
    None
}

const fn secret_reference_byte_rejection(observed: usize) -> Option<JobModelLimitRejection> {
    if observed > MAX_SECRET_REFERENCE_BYTES {
        return Some(JobModelLimitRejection::SecretReferenceBytes);
    }
    None
}

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

    /// Returns the canonical logical blob key shared by publisher and runner.
    #[must_use]
    pub fn object_key(&self) -> &str {
        &self.object_key
    }

    /// Returns the digest expected for the exact encoded object bytes.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Returns the exact encoded object size admitted for bounded retrieval.
    #[must_use]
    pub const fn encoded_size(&self) -> u64 {
        self.encoded_size
    }

    /// Returns the canonical two-part media type expected for the object.
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
    triggering_actor: Option<String>,
    run_id_alias: Option<RunIdAlias>,
    run_number: Option<u64>,
    run_attempt: Option<u32>,
    event: JobContentReference,
    runtime_context: JobContentReference,
}

impl JobExecutionContext {
    /// Creates the required immutable execution context.
    #[must_use]
    pub fn new(
        workflow_name: impl Into<String>,
        git_ref: impl Into<String>,
        workspace: impl Into<String>,
        event: JobContentReference,
        runtime_context: JobContentReference,
    ) -> Self {
        Self {
            workflow_name: workflow_name.into(),
            git_ref: git_ref.into(),
            workspace: workspace.into(),
            actor: None,
            triggering_actor: None,
            run_id_alias: None,
            run_number: None,
            run_attempt: None,
            event,
            runtime_context,
        }
    }

    /// Attaches the provider actor identity when authenticated ingress supplied one.
    #[must_use]
    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    /// Attaches the current initiator while retaining the original run actor.
    #[must_use]
    pub fn with_triggering_actor(mut self, actor: impl Into<String>) -> Self {
        self.triggering_actor = Some(actor.into());
        self
    }

    /// Attaches the stable positive numeric alias for the internal run ID.
    #[must_use]
    pub const fn with_run_id_alias(mut self, run_id_alias: RunIdAlias) -> Self {
        self.run_id_alias = Some(run_id_alias);
        self
    }

    /// Attaches the positive provider run number; envelope validation rejects zero.
    #[must_use]
    pub const fn with_run_number(mut self, run_number: u64) -> Self {
        self.run_number = Some(run_number);
        self
    }

    /// Attaches the positive provider run-attempt number; validation rejects zero.
    #[must_use]
    pub const fn with_run_attempt(mut self, run_attempt: u32) -> Self {
        self.run_attempt = Some(run_attempt);
        self
    }

    /// Returns the provider-visible workflow name bound at admission.
    #[must_use]
    pub fn workflow_name(&self) -> &str {
        &self.workflow_name
    }

    /// Returns the canonical full Git reference used for the run.
    #[must_use]
    pub fn git_ref(&self) -> &str {
        &self.git_ref
    }

    /// Returns the canonical absolute workspace target path.
    #[must_use]
    pub fn workspace(&self) -> &str {
        &self.workspace
    }

    /// Returns the authenticated provider actor when one was supplied.
    #[must_use]
    pub fn actor(&self) -> Option<&str> {
        self.actor.as_deref()
    }

    /// Returns the actor that initiated this physical attempt when available.
    #[must_use]
    pub fn triggering_actor(&self) -> Option<&str> {
        self.triggering_actor.as_deref()
    }

    /// Returns the stable provider-compatible run alias when present.
    #[must_use]
    pub const fn run_id_alias(&self) -> Option<RunIdAlias> {
        self.run_id_alias
    }

    /// Returns the provider run number without inventing one when absent.
    #[must_use]
    pub const fn run_number(&self) -> Option<u64> {
        self.run_number
    }

    /// Returns the provider run attempt without inventing one when absent.
    #[must_use]
    pub const fn run_attempt(&self) -> Option<u32> {
        self.run_attempt
    }

    /// Returns the immutable event-payload content identity.
    #[must_use]
    pub const fn event(&self) -> &JobContentReference {
        &self.event
    }

    /// Returns the immutable runtime-context content identity.
    #[must_use]
    pub const fn runtime_context(&self) -> &JobContentReference {
        &self.runtime_context
    }
}

impl JobSource {
    /// Creates immutable source coordinates; envelope validation rejects empty fields.
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

    /// Returns the credential-free SCM provider identifier.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Returns the provider-native repository identity without credentials.
    #[must_use]
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// Returns the immutable source revision used to plan the job.
    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }

    /// Returns the repository-relative workflow source path.
    #[must_use]
    pub fn workflow_path(&self) -> &str {
        &self.workflow_path
    }

    /// Returns the trigger name associated with the admitted event payload.
    #[must_use]
    pub fn event_name(&self) -> &str {
        &self.event_name
    }
}

/// Versioned envelope for the semantic job IR.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobIrEnvelope {
    #[serde(rename = "schema_version")]
    version: JobIrVersion,
    workflow_id: WorkflowId,
    source: JobSource,
    execution: JobExecutionContext,
    job: JobIr,
}

impl JobIrEnvelope {
    /// Creates an envelope using the only schema accepted by this build.
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

    /// Returns the strongly typed `JobIR` schema contract.
    #[must_use]
    pub const fn version(&self) -> JobIrVersion {
        self.version
    }

    /// Returns the numeric schema version used by the existing JSON envelope.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.version.get()
    }

    /// Returns the stable workflow definition identity.
    #[must_use]
    pub const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }

    /// Returns immutable SCM and trigger coordinates.
    #[must_use]
    pub const fn source(&self) -> &JobSource {
        &self.source
    }

    /// Returns provider context and immutable content references needed at execution.
    #[must_use]
    pub const fn execution(&self) -> &JobExecutionContext {
        &self.execution
    }

    /// Returns the fully planned semantic job.
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
        if self.version != JobIrVersion::current() {
            return Err(JobValidationError::UnsupportedSchema {
                supported: JobIrVersion::current().get(),
                received: self.version.get(),
            });
        }
        self.validate_common()?;
        self.validate_current()
    }

    fn validate_common(&self) -> Result<(), JobValidationError> {
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
        let mut step_ids = BTreeSet::new();
        for step in &self.job.steps {
            if !step_ids.insert(step.id().clone()) {
                return Err(JobValidationError::DuplicateStepId(step.id().clone()));
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

    fn validate_current(&self) -> Result<(), JobValidationError> {
        validate_content_reference(&self.execution.runtime_context)?;
        self.job.instance.validate()?;
        self.job.permission_request.validate()?;
        validate_authority_profile(&self.job)?;

        validate_values(&self.job.environment, "job.environment")?;
        if let Some(working_directory) = &self.job.working_directory {
            working_directory.validate().map_err(|source| {
                JobValidationError::InvalidValueTemplate {
                    field: "job working directory",
                    source,
                }
            })?;
        }
        if let Some(container) = &self.job.container {
            container.validate_values()?;
        }
        for service in self.job.services.values() {
            service.validate_values()?;
        }

        if super::instance::job_output_definition_rejection(self.job.outputs.len()).is_some() {
            return Err(JobValidationError::TooManyJobOutputs {
                maximum: super::MAX_JOB_OUTPUT_DEFINITIONS,
            });
        }
        let mut previous_output = None;
        for output in &self.job.outputs {
            output.validate()?;
            if previous_output.is_some_and(|previous| previous >= output.name()) {
                return Err(JobValidationError::NonCanonicalJobOutput(
                    output.name().to_owned(),
                ));
            }
            previous_output = Some(output.name());
        }

        for step in &self.job.steps {
            step.name_template().validate().map_err(|source| {
                JobValidationError::InvalidValueTemplate {
                    field: "step name",
                    source,
                }
            })?;
            if let Some(timeout) = step.timeout() {
                timeout.validate(step.id())?;
            }
            step.continue_on_error().validate().map_err(|source| {
                JobValidationError::InvalidValueTemplate {
                    field: "step continue-on-error",
                    source,
                }
            })?;
            validate_values(step.environment(), "step.environment")?;
            match step.kind() {
                SemanticStep::Run { values } => values.validate()?,
                SemanticStep::Action { inputs, .. } => {
                    validate_values(inputs, "action.inputs")?;
                }
            }
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
    if let Some(actor) = &context.triggering_actor {
        validate_bounded_text(actor, "execution.triggering_actor")?;
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
        || content_key_byte_rejection(key.len()).is_some()
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
        || job_content_byte_rejection(reference.encoded_size).is_some()
        || media_type.is_empty()
        || content_media_type_byte_rejection(media_type.len()).is_some()
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
        || execution_context_text_byte_rejection(value.len()).is_some()
        || value.chars().any(char::is_control)
    {
        return Err(JobValidationError::InvalidContextField(field));
    }
    Ok(())
}

/// Returns whether a full Git ref obeys Git's portable canonical name grammar.
///
/// This validates general `refs/...` names. Product operations that accept a
/// narrower namespace, such as manual dispatch, must additionally constrain
/// the allowed prefix.
#[must_use]
pub fn canonical_git_ref(value: &str) -> bool {
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

/// Immutable authority policy applied to one executable job.
///
/// This is deliberately separate from observed secret exposure. `CredentialFree`
/// is an admission promise that no job-visible authority or secret-resolution
/// path exists; it is never inferred from a later masking result.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobAuthorityProfile {
    /// Normal execution may receive one or more exact-fence runtime authorities.
    Standard,
    /// Execution receives no runtime authority or other job-visible credential.
    CredentialFree,
}

/// Fully planned semantics for one workflow job.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobIr {
    job_id: JobId,
    run_id: RunId,
    name: String,
    requirements: RunnerRequirements,
    instance: JobInstanceIdentity,
    continue_on_error: bool,
    authority_profile: JobAuthorityProfile,
    permission_request: JobPermissionRequest,
    outputs: Vec<JobOutputDefinition>,
    timeout_seconds: Option<u32>,
    environment: BTreeMap<String, ValueSource>,
    working_directory: Option<ValueTemplate>,
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
        instance: JobInstanceIdentity,
        continue_on_error: bool,
        steps: Vec<StepIr>,
    ) -> Self {
        Self {
            job_id,
            run_id,
            name: name.into(),
            requirements,
            instance,
            continue_on_error,
            authority_profile: JobAuthorityProfile::Standard,
            permission_request: JobPermissionRequest::ProviderDefault,
            outputs: Vec::new(),
            timeout_seconds: None,
            environment: BTreeMap::new(),
            working_directory: None,
            container: None,
            services: BTreeMap::new(),
            steps,
        }
    }

    /// Returns the opaque identity of this planned job.
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    /// Returns the workflow run containing this job.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Returns the provider-visible job display name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the typed runner-admission constraints.
    #[must_use]
    pub const fn requirements(&self) -> &RunnerRequirements {
        &self.requirements
    }

    /// Returns the logical/matrix identity of this concrete job.
    #[must_use]
    pub const fn instance_identity(&self) -> &JobInstanceIdentity {
        &self.instance
    }

    /// Returns the already-resolved job-level `continue-on-error` value.
    #[must_use]
    pub const fn continue_on_error(&self) -> bool {
        self.continue_on_error
    }

    /// Returns the immutable job-visible authority policy.
    #[must_use]
    pub const fn authority_profile(&self) -> JobAuthorityProfile {
        self.authority_profile
    }

    /// Returns the resolved source permission request for provider authorities.
    #[must_use]
    pub const fn permission_request(&self) -> &JobPermissionRequest {
        &self.permission_request
    }

    /// Returns canonical name-sorted job output definitions.
    #[must_use]
    pub fn output_definitions(&self) -> &[JobOutputDefinition] {
        &self.outputs
    }

    /// Returns the optional positive job deadline in seconds.
    #[must_use]
    pub const fn timeout_seconds(&self) -> Option<u32> {
        self.timeout_seconds
    }

    /// Returns deferred job-level environment values keyed canonically.
    #[must_use]
    pub const fn environment(&self) -> &BTreeMap<String, ValueSource> {
        &self.environment
    }

    /// Returns the optional execution-time working-directory template.
    #[must_use]
    pub const fn working_directory_template(&self) -> Option<&ValueTemplate> {
        self.working_directory.as_ref()
    }

    /// Returns the optional main job-container request.
    #[must_use]
    pub const fn container(&self) -> Option<&ContainerSpec> {
        self.container.as_ref()
    }

    /// Returns service-container requests keyed by logical service ID.
    #[must_use]
    pub const fn services(&self) -> &BTreeMap<String, ContainerSpec> {
        &self.services
    }

    /// Returns semantic steps in execution order.
    #[must_use]
    pub fn steps(&self) -> &[StepIr] {
        &self.steps
    }

    /// Attaches output definitions in canonical name order.
    ///
    /// Duplicate names remain visible and are rejected by envelope validation.
    #[must_use]
    pub fn with_output_definitions(
        mut self,
        outputs: impl IntoIterator<Item = JobOutputDefinition>,
    ) -> Self {
        self.outputs = outputs.into_iter().collect();
        self.outputs
            .sort_by(|left, right| left.name().cmp(right.name()));
        self
    }

    /// Replaces the complete resolved source permission request.
    #[must_use]
    pub fn with_permission_request(mut self, permission_request: JobPermissionRequest) -> Self {
        self.permission_request = permission_request;
        self
    }

    /// Selects the immutable job-visible authority policy.
    #[must_use]
    pub const fn with_authority_profile(mut self, profile: JobAuthorityProfile) -> Self {
        self.authority_profile = profile;
        self
    }

    /// Sets a job deadline; envelope validation rejects a zero value.
    #[must_use]
    pub const fn with_timeout_seconds(mut self, timeout_seconds: u32) -> Self {
        self.timeout_seconds = Some(timeout_seconds);
        self
    }

    /// Replaces the complete deferred job environment.
    #[must_use]
    pub fn with_environment(mut self, environment: BTreeMap<String, ValueSource>) -> Self {
        self.environment = environment;
        self
    }

    /// Sets the execution-time working-directory template.
    #[must_use]
    pub fn with_working_directory(mut self, working_directory: ValueTemplate) -> Self {
        self.working_directory = Some(working_directory);
        self
    }

    /// Sets the main job-container request.
    #[must_use]
    pub fn with_container(mut self, container: ContainerSpec) -> Self {
        self.container = Some(container);
        self
    }

    /// Replaces the complete service-container map.
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
    /// Exact public text requiring no evaluation or secret lookup.
    Literal(String),
    /// Typed expression evaluated by its declared runtime dialect.
    Expression(ExpressionProgram),
    /// Opaque, non-secret locator resolved only at an authorized secret boundary.
    SecretReference(String),
    /// Canonical mixed literal/expression template evaluated at execution time.
    Template(ValueTemplate),
}

impl ValueSource {
    pub(super) fn validate(&self, field: &'static str) -> Result<(), JobValidationError> {
        match self {
            Self::Literal(value) => {
                if value.len() > super::MAX_VALUE_TEMPLATE_TEXT_BYTES {
                    return Err(JobValidationError::InvalidValueTemplate {
                        field,
                        source: super::ValueTemplateError::TextTooLong {
                            maximum: super::MAX_VALUE_TEMPLATE_TEXT_BYTES,
                        },
                    });
                }
                Ok(())
            }
            Self::Expression(program) => program
                .validate()
                .map_err(|source| JobValidationError::InvalidExpression { field, source }),
            Self::SecretReference(reference) => {
                if reference.is_empty()
                    || reference.trim() != reference
                    || secret_reference_byte_rejection(reference.len()).is_some()
                    || reference.chars().any(char::is_control)
                {
                    return Err(JobValidationError::InvalidLogicalName {
                        field: "secret reference",
                    });
                }
                Ok(())
            }
            Self::Template(template) => template
                .validate()
                .map_err(|source| JobValidationError::InvalidValueTemplate { field, source }),
        }
    }
}

fn validate_values(
    values: &BTreeMap<String, ValueSource>,
    field: &'static str,
) -> Result<(), JobValidationError> {
    for (key, value) in values {
        super::instance::validate_logical_name(key, field)?;
        value.validate(field)?;
    }
    Ok(())
}

fn validate_authority_profile(job: &JobIr) -> Result<(), JobValidationError> {
    if job.authority_profile != JobAuthorityProfile::CredentialFree {
        return Ok(());
    }
    if !matches!(&job.permission_request, JobPermissionRequest::Mapping(grants) if grants.is_empty())
    {
        return Err(JobValidationError::CredentialFreePermissions);
    }
    if job
        .requirements
        .features()
        .contains(&RunnerFeature::OIDC_TOKENS)
    {
        return Err(JobValidationError::CredentialFreeRunnerFeature);
    }
    if values_require_secret(&job.environment)
        || job
            .working_directory
            .as_ref()
            .is_some_and(template_requires_secret)
        || job.outputs.iter().any(|output| {
            output.sensitivity() == OutputSensitivity::SecretDerived
                || template_requires_secret(output.value())
        })
        || job
            .container
            .as_ref()
            .is_some_and(container_requires_credential)
        || job.services.values().any(container_requires_credential)
    {
        return Err(JobValidationError::CredentialFreeSecretDependency);
    }
    for step in &job.steps {
        if template_requires_secret(step.name_template())
            || step.condition().is_some_and(program_requires_secret)
            || runtime_boolean_requires_secret(step.continue_on_error())
            || step.timeout().is_some_and(|timeout| {
                matches!(
                    timeout.value(),
                    RuntimePositiveInteger::Expression { program }
                        if program_requires_secret(program)
                )
            })
            || values_require_secret(step.environment())
        {
            return Err(JobValidationError::CredentialFreeSecretDependency);
        }
        match step.kind() {
            SemanticStep::Run { values } => {
                if template_requires_secret(values.command())
                    || values.shell().value().is_some_and(template_requires_secret)
                    || values
                        .working_directory()
                        .is_some_and(template_requires_secret)
                {
                    return Err(JobValidationError::CredentialFreeSecretDependency);
                }
            }
            SemanticStep::Action { reference, inputs } => {
                if results_action(reference) {
                    return Err(JobValidationError::CredentialFreeResultsAction);
                }
                if values_require_secret(inputs) {
                    return Err(JobValidationError::CredentialFreeSecretDependency);
                }
            }
        }
    }
    Ok(())
}

fn values_require_secret(values: &BTreeMap<String, ValueSource>) -> bool {
    values.values().any(value_requires_secret)
}

fn value_requires_secret(value: &ValueSource) -> bool {
    match value {
        ValueSource::SecretReference(_) => true,
        ValueSource::Expression(program) => program_requires_secret(program),
        ValueSource::Template(template) => template_requires_secret(template),
        ValueSource::Literal(_) => false,
    }
}

fn template_requires_secret(template: &ValueTemplate) -> bool {
    template
        .segments()
        .iter()
        .filter_map(super::ValueTemplateSegment::expression_program)
        .any(program_requires_secret)
}

fn program_requires_secret(program: &ExpressionProgram) -> bool {
    program.instructions().iter().any(|instruction| {
        matches!(
            instruction,
            ExpressionInstruction::NamedValue { name } if name == "secrets"
        )
    })
}

fn runtime_boolean_requires_secret(value: &RuntimeBoolean) -> bool {
    value
        .expression_program()
        .is_some_and(program_requires_secret)
}

fn container_requires_credential(container: &ContainerSpec) -> bool {
    container.credentials().is_some() || values_require_secret(container.environment())
}

fn results_action(reference: &ActionReference) -> bool {
    let ActionReference::Repository { repository, .. } = reference else {
        return false;
    };
    let Some((owner, name)) = repository.split_once('/') else {
        return false;
    };
    owner.eq_ignore_ascii_case("actions")
        && (name.eq_ignore_ascii_case("cache") || name.to_ascii_lowercase().contains("artifact"))
}

#[cfg(test)]
mod limit_contract_tests {
    use super::{
        JobModelLimitRejection, MAX_CONTENT_KEY_BYTES, MAX_CONTENT_MEDIA_TYPE_BYTES,
        MAX_EXECUTION_CONTEXT_TEXT_BYTES, MAX_JOB_CONTENT_BYTES, MAX_SECRET_REFERENCE_BYTES,
        content_key_byte_rejection, content_media_type_byte_rejection,
        execution_context_text_byte_rejection, job_content_byte_rejection,
        secret_reference_byte_rejection,
    };

    #[test]
    fn execution_context_text_byte_limit_has_exact_boundaries() {
        assert_eq!(
            execution_context_text_byte_rejection(MAX_EXECUTION_CONTEXT_TEXT_BYTES - 1),
            None
        );
        assert_eq!(
            execution_context_text_byte_rejection(MAX_EXECUTION_CONTEXT_TEXT_BYTES),
            None
        );
        assert_eq!(
            execution_context_text_byte_rejection(MAX_EXECUTION_CONTEXT_TEXT_BYTES + 1),
            Some(JobModelLimitRejection::ExecutionContextTextBytes)
        );
    }

    #[test]
    fn content_key_byte_limit_has_exact_boundaries() {
        assert_eq!(content_key_byte_rejection(MAX_CONTENT_KEY_BYTES - 1), None);
        assert_eq!(content_key_byte_rejection(MAX_CONTENT_KEY_BYTES), None);
        assert_eq!(
            content_key_byte_rejection(MAX_CONTENT_KEY_BYTES + 1),
            Some(JobModelLimitRejection::ContentKeyBytes)
        );
    }

    #[test]
    fn content_media_type_byte_limit_has_exact_boundaries() {
        assert_eq!(
            content_media_type_byte_rejection(MAX_CONTENT_MEDIA_TYPE_BYTES - 1),
            None
        );
        assert_eq!(
            content_media_type_byte_rejection(MAX_CONTENT_MEDIA_TYPE_BYTES),
            None
        );
        assert_eq!(
            content_media_type_byte_rejection(MAX_CONTENT_MEDIA_TYPE_BYTES + 1),
            Some(JobModelLimitRejection::ContentMediaTypeBytes)
        );
    }

    #[test]
    fn job_content_byte_limit_has_exact_boundaries() {
        assert_eq!(job_content_byte_rejection(MAX_JOB_CONTENT_BYTES - 1), None);
        assert_eq!(job_content_byte_rejection(MAX_JOB_CONTENT_BYTES), None);
        assert_eq!(
            job_content_byte_rejection(MAX_JOB_CONTENT_BYTES + 1),
            Some(JobModelLimitRejection::JobContentBytes)
        );
    }

    #[test]
    fn secret_reference_byte_limit_has_exact_boundaries() {
        assert_eq!(
            secret_reference_byte_rejection(MAX_SECRET_REFERENCE_BYTES - 1),
            None
        );
        assert_eq!(
            secret_reference_byte_rejection(MAX_SECRET_REFERENCE_BYTES),
            None
        );
        assert_eq!(
            secret_reference_byte_rejection(MAX_SECRET_REFERENCE_BYTES + 1),
            Some(JobModelLimitRejection::SecretReferenceBytes)
        );
    }
}
