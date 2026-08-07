use async_trait::async_trait;
use automata_core::{AttemptId, JobId, OperationId, RunId, UnixMillis, WorkflowId};
use thiserror::Error;
use uuid::Uuid;

use crate::{MAX_JOB_IR_BYTES, ObjectKey, RoutingDocument, Sha256Digest, StoreError, TenantScope};

/// Compatibility epoch required for newly admitted workflow runs.
pub const WORKFLOW_ADMISSION_EPOCH: u16 = 3;
/// Durable workflow-plan JSON schema emitted by the current frontend layer.
pub const WORKFLOW_PLAN_SCHEMA: u16 = 1;
/// Largest immutable source, event, or plan object accepted at admission.
pub const MAX_ADMISSION_OBJECT_BYTES: u64 = 16 * 1024 * 1024;

const MAX_TEXT_BYTES: usize = 1_024;
const MAX_MEDIA_TYPE_BYTES: usize = 128;

macro_rules! uuid_value {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }
    };
}

uuid_value!(/// Tenant-scoped durable repository identity.
    RepositoryId);
uuid_value!(/// Immutable source/plan snapshot identity.
    WorkflowSnapshotId);

/// Complete immutable object identity retained by the relational store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionObject {
    digest: Sha256Digest,
    object_key: ObjectKey,
    encoded_size: u64,
    media_type: String,
}

impl AdmissionObject {
    /// Creates bounded, credential-free immutable object metadata.
    ///
    /// # Errors
    ///
    /// Rejects empty/oversized content or an invalid media type.
    pub fn new(
        digest: Sha256Digest,
        object_key: ObjectKey,
        encoded_size: u64,
        media_type: impl Into<String>,
    ) -> Result<Self, WorkflowAdmissionValueError> {
        let media_type = media_type.into();
        if encoded_size == 0 || encoded_size > MAX_ADMISSION_OBJECT_BYTES {
            return Err(WorkflowAdmissionValueError::InvalidObjectSize);
        }
        if media_type.is_empty()
            || media_type.len() > MAX_MEDIA_TYPE_BYTES
            || !media_type.is_ascii()
            || media_type
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control() || byte == b';')
            || media_type.split_once('/').is_none()
        {
            return Err(WorkflowAdmissionValueError::InvalidMediaType);
        }
        Ok(Self {
            digest,
            object_key,
            encoded_size,
            media_type,
        })
    }

    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    #[must_use]
    pub const fn object_key(&self) -> &ObjectKey {
        &self.object_key
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

/// One durable idempotency identity selected by the authenticated ingress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkflowAdmissionIdempotency {
    /// Opaque provider-delivery identity selected by trusted ingress.
    ProviderDelivery(String),
    /// Caller operation UUID.
    Operation(OperationId),
}

impl WorkflowAdmissionIdempotency {
    /// Creates a bounded provider delivery key.
    ///
    /// # Errors
    ///
    /// Rejects blank, control-bearing, or oversized keys.
    pub fn provider_delivery(key: impl Into<String>) -> Result<Self, WorkflowAdmissionValueError> {
        let key = key.into();
        validate_text(&key, "provider delivery key")?;
        Ok(Self::ProviderDelivery(key))
    }

    #[must_use]
    pub const fn operation(operation_id: OperationId) -> Self {
        Self::Operation(operation_id)
    }

    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::ProviderDelivery(_) => "provider_delivery",
            Self::Operation(_) => "operation",
        }
    }

    #[must_use]
    pub fn key(&self) -> String {
        match self {
            Self::ProviderDelivery(key) => key.clone(),
            Self::Operation(operation_id) => operation_id.to_string(),
        }
    }
}

/// Server-owned repository identity carried into one atomic admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionRepository {
    id: RepositoryId,
    provider: String,
    provider_repository_id: String,
    owner: String,
    name: String,
}

impl AdmissionRepository {
    /// Validates repository identity text.
    ///
    /// # Errors
    ///
    /// Rejects empty, control-bearing, or oversized values.
    pub fn new(
        id: RepositoryId,
        provider: impl Into<String>,
        provider_repository_id: impl Into<String>,
        owner: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self, WorkflowAdmissionValueError> {
        let provider = provider.into();
        let provider_repository_id = provider_repository_id.into();
        let owner = owner.into();
        let name = name.into();
        for (value, field) in [
            (&provider, "SCM provider"),
            (&provider_repository_id, "provider repository ID"),
            (&owner, "repository owner"),
            (&name, "repository name"),
        ] {
            validate_text(value, field)?;
        }
        Ok(Self {
            id,
            provider,
            provider_repository_id,
            owner,
            name,
        })
    }

    #[must_use]
    pub const fn id(&self) -> RepositoryId {
        self.id
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
}

/// Resolved workflow-level concurrency behavior.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowConcurrency {
    display_key: String,
    normalized_key: String,
    cancel_in_progress: bool,
}

impl WorkflowConcurrency {
    /// Creates a case-insensitive concurrency key.
    ///
    /// # Errors
    ///
    /// Rejects blank, control-bearing, or oversized keys.
    pub fn new(
        display_key: impl Into<String>,
        cancel_in_progress: bool,
    ) -> Result<Self, WorkflowAdmissionValueError> {
        let display_key = display_key.into();
        validate_text(&display_key, "concurrency key")?;
        if display_key.trim().is_empty() {
            return Err(WorkflowAdmissionValueError::BlankText("concurrency key"));
        }
        let normalized_key = display_key.to_lowercase();
        validate_text(&normalized_key, "normalized concurrency key")?;
        Ok(Self {
            display_key,
            normalized_key,
            cancel_in_progress,
        })
    }

    #[must_use]
    pub fn display_key(&self) -> &str {
        &self.display_key
    }

    #[must_use]
    pub fn normalized_key(&self) -> &str {
        &self.normalized_key
    }

    #[must_use]
    pub const fn cancel_in_progress(&self) -> bool {
        self.cancel_in_progress
    }
}

/// One evaluated job and its initial attempt in an admission aggregate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedWorkflowJob {
    job_id: JobId,
    attempt_id: AttemptId,
    key: String,
    display_name: String,
    job_ir: AdmissionObject,
    requirements: RoutingDocument,
    prerequisites: Vec<JobId>,
}

impl AdmittedWorkflowJob {
    /// Creates one validated current-epoch job.
    ///
    /// # Errors
    ///
    /// Rejects invalid text, oversized `JobIR`, or a self dependency.
    pub fn new(
        job_id: JobId,
        attempt_id: AttemptId,
        key: impl Into<String>,
        display_name: impl Into<String>,
        job_plan: AdmissionObject,
        requirements: RoutingDocument,
        prerequisites: Vec<JobId>,
    ) -> Result<Self, WorkflowAdmissionValueError> {
        let key = key.into();
        let display_name = display_name.into();
        validate_text(&key, "job key")?;
        validate_text(&display_name, "job display name")?;
        if job_plan.encoded_size() > MAX_JOB_IR_BYTES {
            return Err(WorkflowAdmissionValueError::InvalidJobIrSize);
        }
        if prerequisites.contains(&job_id) {
            return Err(WorkflowAdmissionValueError::SelfDependency);
        }
        Ok(Self {
            job_id,
            attempt_id,
            key,
            display_name,
            job_ir: job_plan,
            requirements,
            prerequisites,
        })
    }

    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    #[must_use]
    pub const fn job_ir(&self) -> &AdmissionObject {
        &self.job_ir
    }

    #[must_use]
    pub const fn requirements(&self) -> &RoutingDocument {
        &self.requirements
    }

    #[must_use]
    pub fn prerequisites(&self) -> &[JobId] {
        &self.prerequisites
    }
}

/// Fully materialized aggregate committed by [`WorkflowAdmissionRepository`].
#[derive(Clone, Debug)]
pub struct AdmitWorkflowRun {
    tenant: TenantScope,
    idempotency: WorkflowAdmissionIdempotency,
    request_digest: Sha256Digest,
    repository: AdmissionRepository,
    workflow_id: WorkflowId,
    workflow_path: String,
    snapshot_id: WorkflowSnapshotId,
    source: AdmissionObject,
    plan: AdmissionObject,
    run_id: RunId,
    event_name: String,
    event: AdmissionObject,
    head_sha: Vec<u8>,
    concurrency: Option<WorkflowConcurrency>,
    jobs: Vec<AdmittedWorkflowJob>,
    admitted_at: UnixMillis,
}

/// Named construction path for [`AdmitWorkflowRun`].
#[derive(Clone, Debug)]
pub struct AdmitWorkflowRunBuilder {
    command: AdmitWorkflowRun,
}

impl AdmitWorkflowRun {
    /// Starts a builder with all identity and immutable object fields.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn builder(
        tenant: TenantScope,
        idempotency: WorkflowAdmissionIdempotency,
        request_digest: Sha256Digest,
        repository: AdmissionRepository,
        workflow_id: WorkflowId,
        workflow_path: impl Into<String>,
        snapshot_id: WorkflowSnapshotId,
        source: AdmissionObject,
        plan: AdmissionObject,
        run_id: RunId,
        event_name: impl Into<String>,
        event: AdmissionObject,
        head_sha: Vec<u8>,
        jobs: Vec<AdmittedWorkflowJob>,
        admitted_at: UnixMillis,
    ) -> AdmitWorkflowRunBuilder {
        AdmitWorkflowRunBuilder {
            command: Self {
                tenant,
                idempotency,
                request_digest,
                repository,
                workflow_id,
                workflow_path: workflow_path.into(),
                snapshot_id,
                source,
                plan,
                run_id,
                event_name: event_name.into(),
                event,
                head_sha,
                concurrency: None,
                jobs,
                admitted_at,
            },
        }
    }

    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }

    #[must_use]
    pub const fn idempotency(&self) -> &WorkflowAdmissionIdempotency {
        &self.idempotency
    }

    #[must_use]
    pub const fn request_digest(&self) -> Sha256Digest {
        self.request_digest
    }

    #[must_use]
    pub const fn repository(&self) -> &AdmissionRepository {
        &self.repository
    }

    #[must_use]
    pub const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }

    #[must_use]
    pub fn workflow_path(&self) -> &str {
        &self.workflow_path
    }

    #[must_use]
    pub const fn snapshot_id(&self) -> WorkflowSnapshotId {
        self.snapshot_id
    }

    #[must_use]
    pub const fn source(&self) -> &AdmissionObject {
        &self.source
    }

    #[must_use]
    pub const fn plan(&self) -> &AdmissionObject {
        &self.plan
    }

    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    #[must_use]
    pub fn event_name(&self) -> &str {
        &self.event_name
    }

    #[must_use]
    pub const fn event(&self) -> &AdmissionObject {
        &self.event
    }

    #[must_use]
    pub fn head_sha(&self) -> &[u8] {
        &self.head_sha
    }

    #[must_use]
    pub const fn concurrency(&self) -> Option<&WorkflowConcurrency> {
        self.concurrency.as_ref()
    }

    #[must_use]
    pub fn jobs(&self) -> &[AdmittedWorkflowJob] {
        &self.jobs
    }

    #[must_use]
    pub const fn admitted_at(&self) -> UnixMillis {
        self.admitted_at
    }
}

impl AdmitWorkflowRunBuilder {
    #[must_use]
    pub fn concurrency(mut self, concurrency: Option<WorkflowConcurrency>) -> Self {
        self.command.concurrency = concurrency;
        self
    }

    /// Validates the complete aggregate.
    ///
    /// # Errors
    ///
    /// Rejects invalid text/SHA shape, duplicate identities, and dangling DAG edges.
    pub fn build(self) -> Result<AdmitWorkflowRun, WorkflowAdmissionValueError> {
        let command = self.command;
        validate_text(&command.workflow_path, "workflow path")?;
        validate_text(&command.event_name, "event name")?;
        if !matches!(command.head_sha.len(), 20 | 32) {
            return Err(WorkflowAdmissionValueError::InvalidHeadSha);
        }
        if command.jobs.is_empty() {
            return Err(WorkflowAdmissionValueError::NoJobs);
        }
        let mut job_ids = std::collections::BTreeSet::new();
        let mut attempt_ids = std::collections::BTreeSet::new();
        let mut keys = std::collections::BTreeSet::new();
        for job in &command.jobs {
            if !job_ids.insert(job.job_id())
                || !attempt_ids.insert(job.attempt_id())
                || !keys.insert(job.key())
            {
                return Err(WorkflowAdmissionValueError::DuplicateJob);
            }
        }
        if command
            .jobs
            .iter()
            .flat_map(AdmittedWorkflowJob::prerequisites)
            .any(|prerequisite| !job_ids.contains(prerequisite))
        {
            return Err(WorkflowAdmissionValueError::UnknownDependency);
        }
        Ok(command)
    }
}

/// Stable receipt for an atomic workflow admission or replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkflowAdmissionReceipt {
    repository_id: RepositoryId,
    workflow_id: WorkflowId,
    snapshot_id: WorkflowSnapshotId,
    run_id: RunId,
    run_number: u64,
    replayed: bool,
}

impl WorkflowAdmissionReceipt {
    /// Constructs a repository adapter result after durable range checks.
    #[must_use]
    pub const fn new(
        repository_id: RepositoryId,
        workflow_id: WorkflowId,
        snapshot_id: WorkflowSnapshotId,
        run_id: RunId,
        run_number: u64,
        replayed: bool,
    ) -> Self {
        Self {
            repository_id,
            workflow_id,
            snapshot_id,
            run_id,
            run_number,
            replayed,
        }
    }

    #[must_use]
    pub const fn repository_id(self) -> RepositoryId {
        self.repository_id
    }

    #[must_use]
    pub const fn workflow_id(self) -> WorkflowId {
        self.workflow_id
    }

    #[must_use]
    pub const fn snapshot_id(self) -> WorkflowSnapshotId {
        self.snapshot_id
    }

    #[must_use]
    pub const fn run_id(self) -> RunId {
        self.run_id
    }

    #[must_use]
    pub const fn run_number(self) -> u64 {
        self.run_number
    }

    #[must_use]
    pub const fn is_replay(self) -> bool {
        self.replayed
    }
}

/// Atomic relational persistence boundary for one materialized workflow DAG.
#[async_trait]
pub trait WorkflowAdmissionRepository: std::fmt::Debug + Send + Sync {
    /// Commits an entire run or returns the exact prior receipt for an
    /// identical idempotent request.
    async fn admit_workflow(
        &self,
        command: AdmitWorkflowRun,
    ) -> Result<WorkflowAdmissionReceipt, WorkflowAdmissionStoreError>;
}

/// Invalid workflow-admission domain value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkflowAdmissionValueError {
    #[error("{0} is empty")]
    EmptyText(&'static str),
    #[error("{0} is blank")]
    BlankText(&'static str),
    #[error("{0} is oversized or contains a control character")]
    InvalidText(&'static str),
    #[error("immutable object size is outside the admission limit")]
    InvalidObjectSize,
    #[error("immutable object media type is invalid")]
    InvalidMediaType,
    #[error("JobIR exceeds its durable size limit")]
    InvalidJobIrSize,
    #[error("head SHA must contain exactly 20 or 32 bytes")]
    InvalidHeadSha,
    #[error("workflow admission requires at least one job")]
    NoJobs,
    #[error("workflow admission contains duplicate job identity")]
    DuplicateJob,
    #[error("workflow admission contains a self dependency")]
    SelfDependency,
    #[error("workflow admission contains a dependency outside its run")]
    UnknownDependency,
}

/// Durable admission failure.
#[derive(Debug, Error)]
pub enum WorkflowAdmissionStoreError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("workflow admission idempotency key was reused for a different request")]
    IdempotencyConflict,
    #[error("durable {0} identity conflicts with the server-owned identity")]
    IdentityConflict(&'static str),
    #[error("workflow run-number sequence is exhausted")]
    RunNumberExhausted,
}

fn validate_text(value: &str, field: &'static str) -> Result<(), WorkflowAdmissionValueError> {
    if value.is_empty() {
        return Err(WorkflowAdmissionValueError::EmptyText(field));
    }
    if value.len() > MAX_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(WorkflowAdmissionValueError::InvalidText(field));
    }
    Ok(())
}
