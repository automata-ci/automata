use std::collections::BTreeSet;

use automata_ci_core::{JobRuntimeContext, WorkflowPlan, WorkflowPlanVersion};
use automata_ci_store::{
    LogicalWorkflowAdmissionReceipt, MAX_ADMISSION_EVENT_BYTES, MAX_ADMISSION_OBJECT_BYTES,
    TenantScope, WorkflowAdmissionIdempotency,
};
use bytes::Bytes;
use thiserror::Error;

use crate::WORKFLOW_EVENT_MEDIA_TYPE;

const MAX_IDENTITY_BYTES: usize = 1_024;
const MAX_SOURCE_BYTES: usize = 16_777_216;
const MAX_EVENT_BYTES: usize = 26_214_400;
const _: () = assert!(MAX_SOURCE_BYTES as u64 == MAX_ADMISSION_OBJECT_BYTES);
const _: () = assert!(MAX_EVENT_BYTES as u64 == MAX_ADMISSION_EVENT_BYTES);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkflowAdmissionLimitRejection {
    IdentityBytes,
    SourceBytes,
    EventBytes,
}

const fn admission_identity_byte_rejection(
    observed: usize,
) -> Option<WorkflowAdmissionLimitRejection> {
    if observed > MAX_IDENTITY_BYTES {
        return Some(WorkflowAdmissionLimitRejection::IdentityBytes);
    }
    None
}

const fn admission_source_byte_rejection(
    observed: usize,
) -> Option<WorkflowAdmissionLimitRejection> {
    if observed > MAX_SOURCE_BYTES {
        return Some(WorkflowAdmissionLimitRejection::SourceBytes);
    }
    None
}

const fn admission_event_byte_rejection(
    observed: usize,
) -> Option<WorkflowAdmissionLimitRejection> {
    if observed > MAX_EVENT_BYTES {
        return Some(WorkflowAdmissionLimitRejection::EventBytes);
    }
    None
}

/// Authenticated provider repository coordinates before server ID derivation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionRepositoryCoordinates {
    provider: String,
    provider_repository_id: String,
    owner: String,
    name: String,
}

impl AdmissionRepositoryCoordinates {
    /// Creates validated repository coordinates.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or control-bearing values.
    pub fn new(
        provider: impl Into<String>,
        provider_repository_id: impl Into<String>,
        owner: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self, WorkflowAdmissionRequestError> {
        let provider = provider.into();
        let provider_repository_id = provider_repository_id.into();
        let owner = owner.into();
        let name = name.into();
        for (value, field) in [
            (&provider, "provider"),
            (&provider_repository_id, "provider repository ID"),
            (&owner, "owner"),
            (&name, "repository name"),
        ] {
            validate_text(value, field)?;
        }
        Ok(Self {
            provider,
            provider_repository_id,
            owner,
            name,
        })
    }

    #[must_use]
    /// Returns the normalized provider name used for admission.
    pub fn provider(&self) -> &str {
        &self.provider
    }

    #[must_use]
    /// Returns the provider's stable repository identifier.
    pub fn provider_repository_id(&self) -> &str {
        &self.provider_repository_id
    }

    #[must_use]
    /// Returns the provider repository owner.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    #[must_use]
    /// Returns the provider repository name.
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    /// Returns the display slug in `owner/name` form.
    pub fn slug(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }
}

/// Validated admission request with exact source/event evidence.
#[derive(Clone, Debug)]
pub struct WorkflowAdmissionRequest {
    tenant: TenantScope,
    repository: AdmissionRepositoryCoordinates,
    workflow_path: String,
    source: Bytes,
    event: Bytes,
    event_media_type: String,
    plan: WorkflowPlan,
    base_context: JobRuntimeContext,
    idempotency: WorkflowAdmissionIdempotency,
    commit_sha: String,
    git_ref: String,
    workflow_name: String,
    actor: Option<String>,
    display_title: Option<String>,
    commit_subject: Option<String>,
    run_attempt: Option<u32>,
    repository_workflow_sources: Vec<crate::RepositoryWorkflowSource>,
}

/// Named construction path for [`WorkflowAdmissionRequest`].
#[derive(Clone, Debug)]
pub struct WorkflowAdmissionRequestBuilder {
    request: WorkflowAdmissionRequest,
}

impl WorkflowAdmissionRequest {
    /// Starts a builder. Context fields must be supplied before [`build`](WorkflowAdmissionRequestBuilder::build).
    #[allow(clippy::too_many_arguments)] // Every immutable admission input is explicit at the boundary.
    #[must_use]
    pub fn builder(
        tenant: TenantScope,
        repository: AdmissionRepositoryCoordinates,
        workflow_path: impl Into<String>,
        source: Bytes,
        event: Bytes,
        plan: WorkflowPlan,
        base_context: JobRuntimeContext,
        idempotency: WorkflowAdmissionIdempotency,
    ) -> WorkflowAdmissionRequestBuilder {
        WorkflowAdmissionRequestBuilder {
            request: Self {
                tenant,
                repository,
                workflow_path: workflow_path.into(),
                source,
                event,
                event_media_type: WORKFLOW_EVENT_MEDIA_TYPE.to_owned(),
                plan,
                base_context,
                idempotency,
                commit_sha: String::new(),
                git_ref: String::new(),
                workflow_name: String::new(),
                actor: None,
                display_title: None,
                commit_subject: None,
                run_attempt: None,
                repository_workflow_sources: Vec::new(),
            },
        }
    }

    #[must_use]
    /// Returns the tenant whose durable namespace receives the admission.
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }

    #[must_use]
    /// Returns the authenticated provider repository coordinates.
    pub const fn repository(&self) -> &AdmissionRepositoryCoordinates {
        &self.repository
    }

    #[must_use]
    /// Returns the repository-relative workflow source path.
    pub fn workflow_path(&self) -> &str {
        &self.workflow_path
    }

    #[must_use]
    /// Returns the exact immutable workflow source bytes.
    pub const fn source(&self) -> &Bytes {
        &self.source
    }

    #[must_use]
    /// Returns the exact immutable provider event bytes.
    pub const fn event(&self) -> &Bytes {
        &self.event
    }

    /// Returns the immutable event evidence media type.
    #[must_use]
    pub fn event_media_type(&self) -> &str {
        &self.event_media_type
    }

    #[must_use]
    /// Returns the validated plan that must match exact-source recompilation.
    pub const fn plan(&self) -> &WorkflowPlan {
        &self.plan
    }

    /// Returns the versioned base runtime context admitted for every root job.
    ///
    /// Secret entries are opaque authorization locators, never secret values.
    #[must_use]
    pub const fn base_context(&self) -> &JobRuntimeContext {
        &self.base_context
    }

    #[must_use]
    /// Returns the durable idempotency boundary for this admission.
    pub const fn idempotency(&self) -> &WorkflowAdmissionIdempotency {
        &self.idempotency
    }

    #[must_use]
    /// Returns the canonical source commit identifier.
    pub fn commit_sha(&self) -> &str {
        &self.commit_sha
    }

    #[must_use]
    /// Returns the canonical full provider ref.
    pub fn git_ref(&self) -> &str {
        &self.git_ref
    }

    #[must_use]
    /// Returns the provider workflow's display name.
    pub fn workflow_name(&self) -> &str {
        &self.workflow_name
    }

    #[must_use]
    /// Returns the optional provider actor display value.
    pub fn actor(&self) -> Option<&str> {
        self.actor.as_deref()
    }

    #[must_use]
    /// Returns the optional provider run title.
    pub fn display_title(&self) -> Option<&str> {
        self.display_title.as_deref()
    }

    #[must_use]
    /// Returns the optional source commit subject.
    pub fn commit_subject(&self) -> Option<&str> {
        self.commit_subject.as_deref()
    }

    #[must_use]
    /// Returns the optional positive provider run-attempt number.
    pub const fn run_attempt(&self) -> Option<u32> {
        self.run_attempt
    }

    /// Returns exact-revision repository workflow sources available for local reusable calls.
    #[must_use]
    pub fn repository_workflow_sources(&self) -> &[crate::RepositoryWorkflowSource] {
        &self.repository_workflow_sources
    }
}

impl WorkflowAdmissionRequestBuilder {
    /// Supplies verified exact-revision workflow files for reachable local reusable calls.
    #[must_use]
    pub fn repository_workflow_sources(
        mut self,
        sources: impl IntoIterator<Item = crate::RepositoryWorkflowSource>,
    ) -> Self {
        self.request.repository_workflow_sources = sources.into_iter().collect();
        self
    }

    /// Selects the immutable media type for exact event evidence.
    #[must_use]
    pub fn event_media_type(mut self, media_type: impl Into<String>) -> Self {
        self.request.event_media_type = media_type.into();
        self
    }

    /// Sets the canonical source commit identifier.
    #[must_use]
    pub fn commit_sha(mut self, commit_sha: impl Into<String>) -> Self {
        self.request.commit_sha = commit_sha.into();
        self
    }

    /// Sets the canonical full provider ref.
    #[must_use]
    pub fn git_ref(mut self, git_ref: impl Into<String>) -> Self {
        self.request.git_ref = git_ref.into();
        self
    }

    /// Sets the provider workflow's display name.
    #[must_use]
    pub fn workflow_name(mut self, workflow_name: impl Into<String>) -> Self {
        self.request.workflow_name = workflow_name.into();
        self
    }

    /// Sets the optional provider actor display value.
    #[must_use]
    pub fn actor(mut self, actor: impl Into<String>) -> Self {
        self.request.actor = Some(actor.into());
        self
    }

    /// Sets the optional provider run title.
    #[must_use]
    pub fn display_title(mut self, display_title: impl Into<String>) -> Self {
        self.request.display_title = Some(display_title.into());
        self
    }

    /// Sets the optional source commit subject.
    #[must_use]
    pub fn commit_subject(mut self, commit_subject: impl Into<String>) -> Self {
        self.request.commit_subject = Some(commit_subject.into());
        self
    }

    /// Sets the positive provider run-attempt number.
    #[must_use]
    pub const fn run_attempt(mut self, run_attempt: u32) -> Self {
        self.request.run_attempt = Some(run_attempt);
        self
    }

    /// Validates request/provenance agreement before any object write.
    ///
    /// # Errors
    ///
    /// Rejects malformed context, event JSON, invalid plans, and provenance mismatches.
    pub fn build(self) -> Result<WorkflowAdmissionRequest, WorkflowAdmissionRequestError> {
        let request = self.request;
        validate_text(&request.workflow_path, "workflow path")?;
        validate_text(&request.commit_sha, "commit SHA")?;
        validate_text(&request.git_ref, "Git ref")?;
        validate_text(&request.workflow_name, "workflow name")?;
        validate_text(&request.event_media_type, "event media type")?;
        if let Some(actor) = &request.actor {
            validate_text(actor, "actor")?;
        }
        if let Some(display_title) = &request.display_title {
            validate_text(display_title, "display title")?;
        }
        if let Some(commit_subject) = &request.commit_subject {
            validate_text(commit_subject, "commit subject")?;
        }
        if request
            .run_attempt
            .is_some_and(|attempt| attempt == 0 || attempt > i32::MAX as u32)
        {
            return Err(WorkflowAdmissionRequestError::InvalidRunAttempt);
        }
        if request.source.is_empty() {
            return Err(WorkflowAdmissionRequestError::EmptySource);
        }
        if admission_source_byte_rejection(request.source.len()).is_some() {
            return Err(WorkflowAdmissionRequestError::OversizedSource);
        }
        if request.event.is_empty() || admission_event_byte_rejection(request.event.len()).is_some()
        {
            return Err(WorkflowAdmissionRequestError::InvalidEvent);
        }
        serde_json::from_slice::<serde_json::Value>(&request.event)
            .map_err(|_| WorkflowAdmissionRequestError::InvalidEvent)?;
        request
            .plan
            .validate()
            .map_err(|_| WorkflowAdmissionRequestError::InvalidPlan)?;
        validate_base_context(&request.base_context)?;
        validate_commit_sha(&request.commit_sha)?;
        if request
            .git_ref
            .strip_prefix("refs/")
            .is_none_or(str::is_empty)
        {
            return Err(WorkflowAdmissionRequestError::InvalidGitRef);
        }
        validate_plan_provenance(&request)?;
        Ok(request)
    }
}

/// Successful application-level admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkflowAdmissionResult {
    receipt: LogicalWorkflowAdmissionReceipt,
}

impl WorkflowAdmissionResult {
    /// Creates an application result from a committed logical admission receipt.
    #[must_use]
    pub const fn new(receipt: LogicalWorkflowAdmissionReceipt) -> Self {
        Self { receipt }
    }

    /// Returns the committed logical admission receipt.
    #[must_use]
    pub const fn receipt(self) -> LogicalWorkflowAdmissionReceipt {
        self.receipt
    }
}

/// Invalid admission request.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkflowAdmissionRequestError {
    /// A bounded provider-controlled identity field is invalid.
    #[error("{0} is empty, oversized, or contains a control character")]
    InvalidText(&'static str),
    /// The exact workflow source body is empty.
    #[error("workflow source is empty")]
    EmptySource,
    /// The exact workflow source body exceeds the standard admission-object ceiling.
    #[error("workflow source exceeds the admission-object limit")]
    OversizedSource,
    /// The provider event is empty, oversized, or invalid JSON.
    #[error("provider event body must be bounded valid JSON")]
    InvalidEvent,
    /// The supplied workflow plan fails its domain validation.
    #[error("compiled workflow plan is invalid")]
    InvalidPlan,
    /// The supplied base context was not a canonical root-level snapshot.
    #[error("base runtime context must contain only inputs, variables, and opaque secret bindings")]
    InvalidBaseContext,
    /// The source commit is not a supported canonical hexadecimal identifier.
    #[error("commit SHA must be 40 or 64 lowercase hexadecimal characters")]
    InvalidCommitSha,
    /// The source ref is not a canonical full `refs/...` name.
    #[error("Git ref must be a canonical full refs/... name")]
    InvalidGitRef,
    /// The provider attempt is zero or cannot fit the durable representation.
    #[error("provider run attempt must fit a positive PostgreSQL INTEGER")]
    InvalidRunAttempt,
    /// The plan's source or event identity disagrees with the request evidence.
    #[error("workflow request does not match compiled source/event provenance")]
    ProvenanceMismatch,
    /// Provider-delivery idempotency disagrees with the plan's delivery identity.
    #[error("provider delivery idempotency does not match event provenance")]
    DeliveryMismatch,
}

/// Fail-closed exact-source verification failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkflowPlanVerificationError {
    /// The exact source cannot be decoded as UTF-8 for provider compilation.
    #[error("workflow source is not valid UTF-8")]
    InvalidSourceEncoding,
    /// The provider frontend rejected the exact source.
    #[error("workflow source was rejected by its provider frontend: {0}")]
    FrontendRejected(String),
    /// Event-aware provider compilation rejected the parsed source.
    #[error("workflow source recompilation was rejected: {0}")]
    CompilationRejected(String),
    /// Canonical manual-dispatch evidence or resolved inputs disagreed with replay.
    #[error("workflow dispatch evidence does not match exact-source recompilation")]
    WorkflowDispatchEvidenceMismatch,
    /// Canonical scheduler-owned evidence disagreed with exact-source replay.
    #[error("GitHub schedule evidence does not match exact-source recompilation")]
    ScheduleEvidenceMismatch,
    /// Exact-source recompilation produced a different plan.
    #[error("supplied workflow plan does not match exact source recompilation")]
    PlanMismatch,
}

fn validate_plan_provenance(
    request: &WorkflowAdmissionRequest,
) -> Result<(), WorkflowAdmissionRequestError> {
    let plan = request.plan();
    if plan.version() != WorkflowPlanVersion::current() {
        return Err(WorkflowAdmissionRequestError::InvalidPlan);
    }
    let expected_repository = request.repository.slug();
    let automata_ci_core::PlanSourceOrigin::Repository {
        repository,
        revision,
        path,
    } = plan.source().origin()
    else {
        return Err(WorkflowAdmissionRequestError::ProvenanceMismatch);
    };
    if plan.source().provider() != request.repository.provider()
        || plan.event().provider() != request.repository.provider()
        || repository != &expected_repository
        || revision != request.commit_sha()
        || path != request.workflow_path()
        || plan.source().source_id() != request.workflow_path()
        || plan
            .event()
            .commit_sha()
            .is_some_and(|sha| sha != request.commit_sha())
        || plan
            .event()
            .git_ref()
            .is_some_and(|git_ref| git_ref != request.git_ref())
    {
        return Err(WorkflowAdmissionRequestError::ProvenanceMismatch);
    }
    if let WorkflowAdmissionIdempotency::ProviderDelivery(delivery) = request.idempotency()
        && plan.event().delivery_id() != Some(delivery.as_str())
    {
        return Err(WorkflowAdmissionRequestError::DeliveryMismatch);
    }
    let unique_keys = plan
        .jobs()
        .iter()
        .map(|job| job.key().value())
        .collect::<BTreeSet<_>>();
    if unique_keys.len() != plan.jobs().len() {
        return Err(WorkflowAdmissionRequestError::InvalidPlan);
    }
    Ok(())
}

fn validate_base_context(context: &JobRuntimeContext) -> Result<(), WorkflowAdmissionRequestError> {
    context
        .validate()
        .map_err(|_| WorkflowAdmissionRequestError::InvalidBaseContext)?;
    let strategy = context.strategy();
    let base_shape = context
        .matrix()
        .as_object()
        .is_some_and(std::collections::BTreeMap::is_empty)
        && context.needs().is_empty()
        && strategy.fail_fast()
        && strategy.job_index() == 0
        && strategy.job_total() == 1
        && strategy.max_parallel() == 1;
    if !base_shape {
        return Err(WorkflowAdmissionRequestError::InvalidBaseContext);
    }
    Ok(())
}

fn validate_commit_sha(value: &str) -> Result<(), WorkflowAdmissionRequestError> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(WorkflowAdmissionRequestError::InvalidCommitSha);
    }
    Ok(())
}

fn validate_text(value: &str, field: &'static str) -> Result<(), WorkflowAdmissionRequestError> {
    if value.is_empty()
        || admission_identity_byte_rejection(value.len()).is_some()
        || value.chars().any(char::is_control)
    {
        return Err(WorkflowAdmissionRequestError::InvalidText(field));
    }
    Ok(())
}

#[cfg(test)]
mod limit_contract_tests {
    use super::{
        MAX_EVENT_BYTES, MAX_IDENTITY_BYTES, MAX_SOURCE_BYTES, WorkflowAdmissionLimitRejection,
        admission_event_byte_rejection, admission_identity_byte_rejection,
        admission_source_byte_rejection,
    };

    #[test]
    fn admission_identity_byte_limit_has_exact_boundaries() {
        assert_eq!(
            admission_identity_byte_rejection(MAX_IDENTITY_BYTES - 1),
            None
        );
        assert_eq!(admission_identity_byte_rejection(MAX_IDENTITY_BYTES), None);
        assert_eq!(
            admission_identity_byte_rejection(MAX_IDENTITY_BYTES + 1),
            Some(WorkflowAdmissionLimitRejection::IdentityBytes)
        );
    }

    #[test]
    fn admission_source_byte_limit_has_exact_boundaries() {
        assert_eq!(admission_source_byte_rejection(MAX_SOURCE_BYTES - 1), None);
        assert_eq!(admission_source_byte_rejection(MAX_SOURCE_BYTES), None);
        assert_eq!(
            admission_source_byte_rejection(MAX_SOURCE_BYTES + 1),
            Some(WorkflowAdmissionLimitRejection::SourceBytes)
        );
    }

    #[test]
    fn admission_event_byte_limit_has_exact_boundaries() {
        assert_eq!(admission_event_byte_rejection(MAX_EVENT_BYTES - 1), None);
        assert_eq!(admission_event_byte_rejection(MAX_EVENT_BYTES), None);
        assert_eq!(
            admission_event_byte_rejection(MAX_EVENT_BYTES + 1),
            Some(WorkflowAdmissionLimitRejection::EventBytes)
        );
    }
}
