use std::collections::BTreeSet;

use automata_core::{
    JobContentReference, JobId, JobIrEnvelope, RunId, WorkflowId, WorkflowJobKey, WorkflowPlan,
};
use automata_store::{
    RepositoryId, TenantScope, WorkflowAdmissionIdempotency, WorkflowAdmissionReceipt,
    WorkflowConcurrency,
};
use bytes::Bytes;
use thiserror::Error;

const MAX_IDENTITY_BYTES: usize = 1_024;
const MAX_EVENT_BYTES: usize = 16 * 1024 * 1024;

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
    pub fn provider(&self) -> &str {
        &self.provider
    }

    #[must_use]
    pub fn provider_repository_id(&self) -> &str {
        &self.provider_repository_id
    }

    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
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
    plan: WorkflowPlan,
    idempotency: WorkflowAdmissionIdempotency,
    commit_sha: String,
    git_ref: String,
    workflow_name: String,
    workspace: String,
    actor: Option<String>,
    run_number: Option<u64>,
    run_attempt: Option<u32>,
}

/// Named construction path for [`WorkflowAdmissionRequest`].
#[derive(Clone, Debug)]
pub struct WorkflowAdmissionRequestBuilder {
    request: WorkflowAdmissionRequest,
}

impl WorkflowAdmissionRequest {
    /// Starts a builder. Context fields must be supplied before [`build`](WorkflowAdmissionRequestBuilder::build).
    #[must_use]
    pub fn builder(
        tenant: TenantScope,
        repository: AdmissionRepositoryCoordinates,
        workflow_path: impl Into<String>,
        source: Bytes,
        event: Bytes,
        plan: WorkflowPlan,
        idempotency: WorkflowAdmissionIdempotency,
    ) -> WorkflowAdmissionRequestBuilder {
        WorkflowAdmissionRequestBuilder {
            request: Self {
                tenant,
                repository,
                workflow_path: workflow_path.into(),
                source,
                event,
                plan,
                idempotency,
                commit_sha: String::new(),
                git_ref: String::new(),
                workflow_name: String::new(),
                workspace: String::new(),
                actor: None,
                run_number: None,
                run_attempt: None,
            },
        }
    }

    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }

    #[must_use]
    pub const fn repository(&self) -> &AdmissionRepositoryCoordinates {
        &self.repository
    }

    #[must_use]
    pub fn workflow_path(&self) -> &str {
        &self.workflow_path
    }

    #[must_use]
    pub const fn source(&self) -> &Bytes {
        &self.source
    }

    #[must_use]
    pub const fn event(&self) -> &Bytes {
        &self.event
    }

    #[must_use]
    pub const fn plan(&self) -> &WorkflowPlan {
        &self.plan
    }

    #[must_use]
    pub const fn idempotency(&self) -> &WorkflowAdmissionIdempotency {
        &self.idempotency
    }

    #[must_use]
    pub fn commit_sha(&self) -> &str {
        &self.commit_sha
    }

    #[must_use]
    pub fn git_ref(&self) -> &str {
        &self.git_ref
    }

    #[must_use]
    pub fn workflow_name(&self) -> &str {
        &self.workflow_name
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
}

impl WorkflowAdmissionRequestBuilder {
    #[must_use]
    pub fn commit_sha(mut self, commit_sha: impl Into<String>) -> Self {
        self.request.commit_sha = commit_sha.into();
        self
    }

    #[must_use]
    pub fn git_ref(mut self, git_ref: impl Into<String>) -> Self {
        self.request.git_ref = git_ref.into();
        self
    }

    #[must_use]
    pub fn workflow_name(mut self, workflow_name: impl Into<String>) -> Self {
        self.request.workflow_name = workflow_name.into();
        self
    }

    #[must_use]
    pub fn workspace(mut self, workspace: impl Into<String>) -> Self {
        self.request.workspace = workspace.into();
        self
    }

    #[must_use]
    pub fn actor(mut self, actor: impl Into<String>) -> Self {
        self.request.actor = Some(actor.into());
        self
    }

    #[must_use]
    pub const fn run_number(mut self, run_number: u64) -> Self {
        self.request.run_number = Some(run_number);
        self
    }

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
        validate_text(&request.workspace, "workspace")?;
        if let Some(actor) = &request.actor {
            validate_text(actor, "actor")?;
        }
        if request.run_number == Some(0) {
            return Err(WorkflowAdmissionRequestError::InvalidRunNumber);
        }
        if request.run_attempt == Some(0) {
            return Err(WorkflowAdmissionRequestError::InvalidRunAttempt);
        }
        if request.source.is_empty() {
            return Err(WorkflowAdmissionRequestError::EmptySource);
        }
        if request.event.is_empty() || request.event.len() > MAX_EVENT_BYTES {
            return Err(WorkflowAdmissionRequestError::InvalidEvent);
        }
        serde_json::from_slice::<serde_json::Value>(&request.event)
            .map_err(|_| WorkflowAdmissionRequestError::InvalidEvent)?;
        request
            .plan
            .validate()
            .map_err(|_| WorkflowAdmissionRequestError::InvalidPlan)?;
        validate_commit_sha(&request.commit_sha)?;
        if !request.git_ref.starts_with("refs/") {
            return Err(WorkflowAdmissionRequestError::InvalidGitRef);
        }
        validate_plan_provenance(&request)?;
        Ok(request)
    }
}

/// Server-generated job identity supplied to a materializer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowJobIdentity {
    key: WorkflowJobKey,
    job_id: JobId,
}

impl WorkflowJobIdentity {
    #[must_use]
    pub const fn new(key: WorkflowJobKey, job_id: JobId) -> Self {
        Self { key, job_id }
    }

    #[must_use]
    pub const fn key(&self) -> &WorkflowJobKey {
        &self.key
    }

    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }
}

/// Borrowed materialization input independent of a concrete workflow dialect.
#[derive(Clone, Debug)]
pub struct MaterializeWorkflowRequest<'request> {
    admission: &'request WorkflowAdmissionRequest,
    repository_id: RepositoryId,
    workflow_id: WorkflowId,
    run_id: RunId,
    jobs: &'request [WorkflowJobIdentity],
    event: &'request JobContentReference,
}

impl<'request> MaterializeWorkflowRequest<'request> {
    #[must_use]
    pub const fn new(
        admission: &'request WorkflowAdmissionRequest,
        repository_id: RepositoryId,
        workflow_id: WorkflowId,
        run_id: RunId,
        jobs: &'request [WorkflowJobIdentity],
        event: &'request JobContentReference,
    ) -> Self {
        Self {
            admission,
            repository_id,
            workflow_id,
            run_id,
            jobs,
            event,
        }
    }

    #[must_use]
    pub const fn admission(&self) -> &'request WorkflowAdmissionRequest {
        self.admission
    }

    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    #[must_use]
    pub const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }

    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    #[must_use]
    pub const fn jobs(&self) -> &'request [WorkflowJobIdentity] {
        self.jobs
    }

    #[must_use]
    pub const fn event(&self) -> &'request JobContentReference {
        self.event
    }
}

/// One dialect-materialized executable job.
#[derive(Clone, Debug)]
pub struct MaterializedWorkflowJob {
    key: WorkflowJobKey,
    envelope: JobIrEnvelope,
}

impl MaterializedWorkflowJob {
    #[must_use]
    pub const fn new(key: WorkflowJobKey, envelope: JobIrEnvelope) -> Self {
        Self { key, envelope }
    }

    #[must_use]
    pub const fn key(&self) -> &WorkflowJobKey {
        &self.key
    }

    #[must_use]
    pub const fn envelope(&self) -> &JobIrEnvelope {
        &self.envelope
    }
}

/// Complete result of dialect materialization.
#[derive(Clone, Debug)]
pub struct MaterializedWorkflow {
    jobs: Vec<MaterializedWorkflowJob>,
    concurrency: Option<WorkflowConcurrency>,
}

impl MaterializedWorkflow {
    #[must_use]
    pub fn new(
        jobs: Vec<MaterializedWorkflowJob>,
        concurrency: Option<WorkflowConcurrency>,
    ) -> Self {
        Self { jobs, concurrency }
    }

    #[must_use]
    pub fn jobs(&self) -> &[MaterializedWorkflowJob] {
        &self.jobs
    }

    #[must_use]
    pub const fn concurrency(&self) -> Option<&WorkflowConcurrency> {
        self.concurrency.as_ref()
    }
}

/// Successful application-level admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkflowAdmissionResult {
    receipt: WorkflowAdmissionReceipt,
}

impl WorkflowAdmissionResult {
    #[must_use]
    pub const fn new(receipt: WorkflowAdmissionReceipt) -> Self {
        Self { receipt }
    }

    #[must_use]
    pub const fn receipt(self) -> WorkflowAdmissionReceipt {
        self.receipt
    }
}

/// Invalid admission request.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkflowAdmissionRequestError {
    #[error("{0} is empty, oversized, or contains a control character")]
    InvalidText(&'static str),
    #[error("workflow source is empty")]
    EmptySource,
    #[error("provider event body must be bounded valid JSON")]
    InvalidEvent,
    #[error("compiled workflow plan is invalid")]
    InvalidPlan,
    #[error("commit SHA must be 40 or 64 lowercase hexadecimal characters")]
    InvalidCommitSha,
    #[error("Git ref must be a canonical full refs/... name")]
    InvalidGitRef,
    #[error("provider run number must be non-zero")]
    InvalidRunNumber,
    #[error("provider run attempt must be non-zero")]
    InvalidRunAttempt,
    #[error("workflow request does not match compiled source/event provenance")]
    ProvenanceMismatch,
    #[error("provider delivery idempotency does not match event provenance")]
    DeliveryMismatch,
}

/// Fail-closed dialect planning failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkflowMaterializationError {
    #[error("workflow source is not valid UTF-8")]
    InvalidSourceEncoding,
    #[error("workflow source was rejected by its provider frontend: {0}")]
    FrontendRejected(String),
    #[error("workflow source recompilation was rejected: {0}")]
    CompilationRejected(String),
    #[error("supplied workflow plan does not match exact source recompilation")]
    PlanMismatch,
    #[error("workflow job evaluation was rejected: {0}")]
    EvaluationRejected(String),
    #[error("workflow materialization identities do not match the plan")]
    IdentityMismatch,
    #[error("workflow concurrency expression cannot be resolved safely: {0}")]
    UnsupportedConcurrency(String),
}

fn validate_plan_provenance(
    request: &WorkflowAdmissionRequest,
) -> Result<(), WorkflowAdmissionRequestError> {
    let plan = request.plan();
    let expected_repository = request.repository.slug();
    let automata_core::PlanSourceOrigin::Repository {
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
    if value.is_empty() || value.len() > MAX_IDENTITY_BYTES || value.chars().any(char::is_control) {
        return Err(WorkflowAdmissionRequestError::InvalidText(field));
    }
    Ok(())
}
