use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use automata_ci_auth::management::ManagementActor;
use automata_ci_core::{
    MAX_LOGICAL_JOB_NEEDS, MAX_LOGICAL_JOBS, OperationId, RunId, UnixMillis, WorkflowId,
    WorkflowJobKey,
};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    AdmissionObject, AdmissionRepository, AuthenticatedGithubDeliveryClaim,
    LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE, RepositoryId, Sha256Digest, StoreError,
    TenantScope, WorkflowAdmissionIdempotency, WorkflowSnapshotId,
};

/// Relational logical-orchestration schema installed for phase-one admission.
pub const LOGICAL_ORCHESTRATION_SCHEMA: u16 = 1;

const MAX_TEXT_BYTES: usize = 1_024;

macro_rules! uuid_identity {
    ($(#[$meta:meta])* $name:ident, $field:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            /// Constructs a non-nil durable identity.
            ///
            /// # Errors
            ///
            /// Rejects the nil UUID sentinel.
            pub fn from_uuid(value: Uuid) -> Result<Self, LogicalWorkflowAdmissionValueError> {
                if value.is_nil() {
                    return Err(LogicalWorkflowAdmissionValueError::NilUuid($field));
                }
                Ok(Self(value))
            }

            /// Returns the underlying UUID.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }
    };
}

uuid_identity!(
    /// Durable identity of the root invocation admitted for one workflow run.
    LogicalWorkflowInvocationId,
    "logical workflow invocation ID"
);
uuid_identity!(
    /// Durable identity of one source-level logical job.
    LogicalWorkflowJobId,
    "logical workflow job ID"
);

/// Execution shape selected by one logical job template.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogicalWorkflowJobKind {
    /// A job whose template contains executable steps.
    Steps,
    /// A job that invokes another reusable workflow.
    ReusableWorkflow,
}

impl LogicalWorkflowJobKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Steps => "steps",
            Self::ReusableWorkflow => "reusable_workflow",
        }
    }
}

/// One source-level job retained for deterministic later activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedLogicalWorkflowJob {
    id: LogicalWorkflowJobId,
    key: WorkflowJobKey,
    source_order: u16,
    kind: LogicalWorkflowJobKind,
    prerequisites: Vec<LogicalWorkflowJobId>,
}

impl AdmittedLogicalWorkflowJob {
    /// Constructs one logical job descriptor.
    ///
    /// Complete graph validation, including dangling edges, duplicate edges,
    /// cycles, and canonical source order, occurs when the admission command is
    /// built.
    ///
    /// # Errors
    ///
    /// Rejects a self edge or more than [`MAX_LOGICAL_JOB_NEEDS`] direct
    /// prerequisites.
    pub fn new(
        id: LogicalWorkflowJobId,
        key: WorkflowJobKey,
        source_order: u16,
        kind: LogicalWorkflowJobKind,
        prerequisites: Vec<LogicalWorkflowJobId>,
    ) -> Result<Self, LogicalWorkflowAdmissionValueError> {
        if prerequisites.len() > MAX_LOGICAL_JOB_NEEDS {
            return Err(LogicalWorkflowAdmissionValueError::TooManyDependencies);
        }
        if prerequisites.contains(&id) {
            return Err(LogicalWorkflowAdmissionValueError::SelfDependency);
        }
        Ok(Self {
            id,
            key,
            source_order,
            kind,
            prerequisites,
        })
    }

    /// Returns the durable logical-job identity.
    #[must_use]
    pub const fn id(&self) -> LogicalWorkflowJobId {
        self.id
    }

    /// Returns the stable source-level job key.
    #[must_use]
    pub const fn key(&self) -> &WorkflowJobKey {
        &self.key
    }

    /// Returns the zero-based canonical source order.
    #[must_use]
    pub const fn source_order(&self) -> u16 {
        self.source_order
    }

    /// Returns the job execution shape.
    #[must_use]
    pub const fn kind(&self) -> LogicalWorkflowJobKind {
        self.kind
    }

    /// Returns direct prerequisite logical-job identities.
    #[must_use]
    pub fn prerequisites(&self) -> &[LogicalWorkflowJobId] {
        &self.prerequisites
    }
}

/// Current authenticated human authority for one exact control-plane manual
/// dispatch admission.
///
/// Input values are not repeated here. Their immutable event and base-context
/// digests are bound alongside the exact repository, workflow, ref, and
/// operation identity, while [`ManagementActor`] is reauthorized inside the
/// admission transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedWorkflowDispatchClaim {
    actor: ManagementActor,
    repository_id: RepositoryId,
    workflow_id: WorkflowId,
    workflow_path: String,
    git_ref: String,
    operation_id: OperationId,
    event_digest: Sha256Digest,
    base_context_digest: Sha256Digest,
}

impl AuthenticatedWorkflowDispatchClaim {
    /// Creates an exact authenticated dispatch claim.
    ///
    /// # Errors
    ///
    /// Rejects nil durable identities, invalid path text, or a noncanonical
    /// full Git ref before the repository adapter observes authority.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        actor: ManagementActor,
        repository_id: RepositoryId,
        workflow_id: WorkflowId,
        workflow_path: impl Into<String>,
        git_ref: impl Into<String>,
        operation_id: OperationId,
        event_digest: Sha256Digest,
        base_context_digest: Sha256Digest,
    ) -> Result<Self, LogicalWorkflowAdmissionValueError> {
        let workflow_path = workflow_path.into();
        let git_ref = git_ref.into();
        validate_text(&workflow_path, "workflow path")?;
        validate_text(&git_ref, "Git ref")?;
        if git_ref.strip_prefix("refs/").is_none_or(str::is_empty) {
            return Err(LogicalWorkflowAdmissionValueError::InvalidGitRef);
        }
        for (value, field) in [
            (repository_id.as_uuid(), "repository ID"),
            (workflow_id.as_uuid(), "workflow ID"),
            (operation_id.as_uuid(), "workflow dispatch operation ID"),
        ] {
            if value.is_nil() {
                return Err(LogicalWorkflowAdmissionValueError::NilUuid(field));
            }
        }
        Ok(Self {
            actor,
            repository_id,
            workflow_id,
            workflow_path,
            git_ref,
            operation_id,
            event_digest,
            base_context_digest,
        })
    }

    /// Returns the current authenticated actor to reauthorize transactionally.
    #[must_use]
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    /// Returns the exact durable repository target.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Returns the exact durable workflow target.
    #[must_use]
    pub const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }

    /// Returns the exact repository-relative workflow path.
    #[must_use]
    pub fn workflow_path(&self) -> &str {
        &self.workflow_path
    }

    /// Returns the exact canonical source ref.
    #[must_use]
    pub fn git_ref(&self) -> &str {
        &self.git_ref
    }

    /// Returns the caller operation identity used for exact replay.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the immutable synthetic dispatch-evidence digest.
    #[must_use]
    pub const fn event_digest(&self) -> Sha256Digest {
        self.event_digest
    }

    /// Returns the immutable canonical base-context digest.
    #[must_use]
    pub const fn base_context_digest(&self) -> Sha256Digest {
        self.base_context_digest
    }
}

/// Authenticated lookup for one exact, previously signed-GitHub-admitted
/// workflow source used by a control-plane manual dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolveAuthenticatedWorkflowDispatchSource {
    actor: ManagementActor,
    repository_id: RepositoryId,
    workflow_id: WorkflowId,
    git_ref: String,
    commit_sha: String,
    commit_sha_bytes: Vec<u8>,
}

impl ResolveAuthenticatedWorkflowDispatchSource {
    /// Creates an exact source lookup bound to current human-session evidence.
    ///
    /// # Errors
    ///
    /// Rejects nil target identities, a noncanonical full ref, or a commit SHA
    /// other than 40 or 64 lowercase hexadecimal characters.
    pub fn new(
        actor: ManagementActor,
        repository_id: RepositoryId,
        workflow_id: WorkflowId,
        git_ref: impl Into<String>,
        commit_sha: impl Into<String>,
    ) -> Result<Self, LogicalWorkflowAdmissionValueError> {
        let git_ref = git_ref.into();
        validate_text(&git_ref, "Git ref")?;
        if git_ref.strip_prefix("refs/").is_none_or(str::is_empty) {
            return Err(LogicalWorkflowAdmissionValueError::InvalidGitRef);
        }
        if repository_id.as_uuid().is_nil() || workflow_id.as_uuid().is_nil() {
            return Err(LogicalWorkflowAdmissionValueError::NilUuid(
                "workflow dispatch source target",
            ));
        }
        let commit_sha = commit_sha.into();
        let commit_sha_bytes = decode_commit_sha(&commit_sha)?;
        Ok(Self {
            actor,
            repository_id,
            workflow_id,
            git_ref,
            commit_sha,
            commit_sha_bytes,
        })
    }

    /// Returns current human-session evidence to reauthorize transactionally.
    #[must_use]
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    /// Returns the exact durable repository target.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Returns the exact durable workflow target.
    #[must_use]
    pub const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }

    /// Returns the exact full Git ref.
    #[must_use]
    pub fn git_ref(&self) -> &str {
        &self.git_ref
    }

    /// Returns the canonical lowercase commit SHA.
    #[must_use]
    pub fn commit_sha(&self) -> &str {
        &self.commit_sha
    }

    pub(crate) fn commit_sha_bytes(&self) -> &[u8] {
        &self.commit_sha_bytes
    }
}

/// Exact immutable source proven by a prior authenticated GitHub admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedWorkflowDispatchSource {
    repository: AdmissionRepository,
    workflow_id: WorkflowId,
    workflow_path: String,
    git_ref: String,
    commit_sha: String,
    source: AdmissionObject,
}

impl AuthenticatedWorkflowDispatchSource {
    /// Creates a proven exact dispatch source descriptor.
    ///
    /// # Errors
    ///
    /// Rejects an invalid workflow identity, path/ref text, or commit SHA shape.
    pub fn new(
        repository: AdmissionRepository,
        workflow_id: WorkflowId,
        workflow_path: impl Into<String>,
        git_ref: impl Into<String>,
        commit_sha: impl Into<String>,
        source: AdmissionObject,
    ) -> Result<Self, LogicalWorkflowAdmissionValueError> {
        let workflow_path = workflow_path.into();
        let git_ref = git_ref.into();
        let commit_sha = commit_sha.into();
        validate_text(&workflow_path, "workflow path")?;
        validate_text(&git_ref, "Git ref")?;
        if workflow_id.as_uuid().is_nil() {
            return Err(LogicalWorkflowAdmissionValueError::NilUuid("workflow ID"));
        }
        if git_ref.strip_prefix("refs/").is_none_or(str::is_empty) {
            return Err(LogicalWorkflowAdmissionValueError::InvalidGitRef);
        }
        decode_commit_sha(&commit_sha)?;
        Ok(Self {
            repository,
            workflow_id,
            workflow_path,
            git_ref,
            commit_sha,
            source,
        })
    }

    /// Returns exact durable repository coordinates.
    #[must_use]
    pub const fn repository(&self) -> &AdmissionRepository {
        &self.repository
    }

    /// Returns the exact durable workflow identity.
    #[must_use]
    pub const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }

    /// Returns the repository-relative workflow path.
    #[must_use]
    pub fn workflow_path(&self) -> &str {
        &self.workflow_path
    }

    /// Returns the exact full Git ref.
    #[must_use]
    pub fn git_ref(&self) -> &str {
        &self.git_ref
    }

    /// Returns the exact lowercase commit SHA.
    #[must_use]
    pub fn commit_sha(&self) -> &str {
        &self.commit_sha
    }

    /// Returns the immutable workflow-source object descriptor.
    #[must_use]
    pub const fn source(&self) -> &AdmissionObject {
        &self.source
    }
}

/// Current logical workflow aggregate committed atomically at admission.
#[derive(Clone, Debug)]
pub struct AdmitLogicalWorkflowRun {
    tenant: TenantScope,
    idempotency: WorkflowAdmissionIdempotency,
    request_digest: Sha256Digest,
    repository: AdmissionRepository,
    workflow_id: WorkflowId,
    workflow_path: String,
    workflow_name: String,
    git_ref: String,
    snapshot_id: WorkflowSnapshotId,
    source: AdmissionObject,
    plan: AdmissionObject,
    base_context: Option<AdmissionObject>,
    run_id: RunId,
    run_attempt: u32,
    root_invocation_id: LogicalWorkflowInvocationId,
    event_name: String,
    event: AdmissionObject,
    head_sha: Vec<u8>,
    actor: Option<String>,
    display_title: Option<String>,
    commit_subject: Option<String>,
    concurrency: Option<crate::WorkflowConcurrency>,
    jobs: Vec<AdmittedLogicalWorkflowJob>,
    admitted_at: UnixMillis,
}

/// Named construction path for [`AdmitLogicalWorkflowRun`].
#[derive(Clone, Debug)]
pub struct AdmitLogicalWorkflowRunBuilder {
    command: AdmitLogicalWorkflowRun,
}

impl AdmitLogicalWorkflowRun {
    /// Starts a builder with all immutable identity, object, and graph fields.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn builder(
        tenant: TenantScope,
        idempotency: WorkflowAdmissionIdempotency,
        request_digest: Sha256Digest,
        repository: AdmissionRepository,
        workflow_id: WorkflowId,
        workflow_path: impl Into<String>,
        workflow_name: impl Into<String>,
        git_ref: impl Into<String>,
        snapshot_id: WorkflowSnapshotId,
        source: AdmissionObject,
        plan: AdmissionObject,
        run_id: RunId,
        run_attempt: u32,
        root_invocation_id: LogicalWorkflowInvocationId,
        event_name: impl Into<String>,
        event: AdmissionObject,
        head_sha: Vec<u8>,
        jobs: Vec<AdmittedLogicalWorkflowJob>,
        admitted_at: UnixMillis,
    ) -> AdmitLogicalWorkflowRunBuilder {
        AdmitLogicalWorkflowRunBuilder {
            command: Self {
                tenant,
                idempotency,
                request_digest,
                repository,
                workflow_id,
                workflow_path: workflow_path.into(),
                workflow_name: workflow_name.into(),
                git_ref: git_ref.into(),
                snapshot_id,
                source,
                plan,
                base_context: None,
                run_id,
                run_attempt,
                root_invocation_id,
                event_name: event_name.into(),
                event,
                head_sha,
                actor: None,
                display_title: None,
                commit_subject: None,
                concurrency: None,
                jobs,
                admitted_at,
            },
        }
    }

    /// Returns the authenticated tenant scope.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }

    /// Returns the durable idempotency identity.
    #[must_use]
    pub const fn idempotency(&self) -> &WorkflowAdmissionIdempotency {
        &self.idempotency
    }

    /// Returns the trusted canonical request digest.
    #[must_use]
    pub const fn request_digest(&self) -> Sha256Digest {
        self.request_digest
    }

    /// Returns the server-owned repository descriptor.
    #[must_use]
    pub const fn repository(&self) -> &AdmissionRepository {
        &self.repository
    }

    /// Returns the workflow definition identity.
    #[must_use]
    pub const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }

    /// Returns the workflow path within the repository.
    #[must_use]
    pub fn workflow_path(&self) -> &str {
        &self.workflow_path
    }

    /// Returns the admitted workflow display name.
    #[must_use]
    pub fn workflow_name(&self) -> &str {
        &self.workflow_name
    }

    /// Returns the canonical full Git reference.
    #[must_use]
    pub fn git_ref(&self) -> &str {
        &self.git_ref
    }

    /// Returns the immutable source snapshot identity.
    #[must_use]
    pub const fn snapshot_id(&self) -> WorkflowSnapshotId {
        self.snapshot_id
    }

    /// Returns immutable source-object metadata.
    #[must_use]
    pub const fn source(&self) -> &AdmissionObject {
        &self.source
    }

    /// Returns immutable WorkflowPlan-v2 object metadata.
    #[must_use]
    pub const fn plan(&self) -> &AdmissionObject {
        &self.plan
    }

    /// Returns the immutable versioned base runtime-context descriptor.
    #[must_use]
    pub const fn base_context(&self) -> Option<&AdmissionObject> {
        self.base_context.as_ref()
    }

    /// Returns the workflow-run identity.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Returns the one-based run attempt.
    #[must_use]
    pub const fn run_attempt(&self) -> u32 {
        self.run_attempt
    }

    /// Returns the root logical invocation identity.
    #[must_use]
    pub const fn root_invocation_id(&self) -> LogicalWorkflowInvocationId {
        self.root_invocation_id
    }

    /// Returns the normalized event name.
    #[must_use]
    pub fn event_name(&self) -> &str {
        &self.event_name
    }

    /// Returns immutable event-object metadata.
    #[must_use]
    pub const fn event(&self) -> &AdmissionObject {
        &self.event
    }

    /// Returns the immutable head commit digest bytes.
    #[must_use]
    pub fn head_sha(&self) -> &[u8] {
        &self.head_sha
    }

    /// Returns the optional event actor projection.
    #[must_use]
    pub fn actor(&self) -> Option<&str> {
        self.actor.as_deref()
    }

    /// Returns the optional run display title.
    #[must_use]
    pub fn display_title(&self) -> Option<&str> {
        self.display_title.as_deref()
    }

    /// Returns the optional head-commit subject.
    #[must_use]
    pub fn commit_subject(&self) -> Option<&str> {
        self.commit_subject.as_deref()
    }

    /// Returns the evaluated workflow-level concurrency request.
    #[must_use]
    pub const fn concurrency(&self) -> Option<&crate::WorkflowConcurrency> {
        self.concurrency.as_ref()
    }

    /// Returns source-ordered logical jobs.
    #[must_use]
    pub fn jobs(&self) -> &[AdmittedLogicalWorkflowJob] {
        &self.jobs
    }

    /// Returns the trusted admission timestamp.
    #[must_use]
    pub const fn admitted_at(&self) -> UnixMillis {
        self.admitted_at
    }
}

impl AdmitLogicalWorkflowRunBuilder {
    /// Binds the canonical admission-time base runtime-context object.
    #[must_use]
    pub fn base_context(mut self, base_context: AdmissionObject) -> Self {
        self.command.base_context = Some(base_context);
        self
    }

    /// Adds an event actor projection.
    #[must_use]
    pub fn actor(mut self, actor: impl Into<String>) -> Self {
        self.command.actor = Some(actor.into());
        self
    }

    /// Adds a run display title.
    #[must_use]
    pub fn display_title(mut self, display_title: impl Into<String>) -> Self {
        self.command.display_title = Some(display_title.into());
        self
    }

    /// Adds a head-commit subject projection.
    #[must_use]
    pub fn commit_subject(mut self, commit_subject: impl Into<String>) -> Self {
        self.command.commit_subject = Some(commit_subject.into());
        self
    }

    /// Binds an evaluated workflow-level concurrency request.
    #[must_use]
    pub fn concurrency(mut self, concurrency: Option<crate::WorkflowConcurrency>) -> Self {
        self.command.concurrency = concurrency;
        self
    }

    /// Validates the complete logical admission aggregate.
    ///
    /// # Errors
    ///
    /// Rejects invalid durable identities or text, a non-canonical source
    /// order, duplicate/dangling edges, or a cyclic logical graph.
    pub fn build(self) -> Result<AdmitLogicalWorkflowRun, LogicalWorkflowAdmissionValueError> {
        let command = self.command;
        for (value, field) in [
            (command.workflow_path.as_str(), "workflow path"),
            (command.workflow_name.as_str(), "workflow name"),
            (command.git_ref.as_str(), "Git ref"),
            (command.event_name.as_str(), "event name"),
        ] {
            validate_text(value, field)?;
        }
        if command
            .git_ref
            .strip_prefix("refs/")
            .is_none_or(str::is_empty)
        {
            return Err(LogicalWorkflowAdmissionValueError::InvalidGitRef);
        }
        for (value, field) in [
            (command.actor.as_deref(), "actor"),
            (command.display_title.as_deref(), "display title"),
            (command.commit_subject.as_deref(), "commit subject"),
        ] {
            if let Some(value) = value {
                validate_text(value, field)?;
            }
        }
        if command.run_attempt == 0 || command.run_attempt > i32::MAX as u32 {
            return Err(LogicalWorkflowAdmissionValueError::InvalidRunAttempt);
        }
        if command.base_context.as_ref().is_some_and(|context| {
            context.media_type() != LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE
        }) {
            return Err(LogicalWorkflowAdmissionValueError::InvalidBaseContext);
        }
        if !matches!(command.head_sha.len(), 20 | 32) {
            return Err(LogicalWorkflowAdmissionValueError::InvalidHeadSha);
        }
        if command.admitted_at.get() < 0 {
            return Err(LogicalWorkflowAdmissionValueError::InvalidAdmissionTime);
        }
        for (value, field) in [
            (command.repository.id().as_uuid(), "repository ID"),
            (command.workflow_id.as_uuid(), "workflow ID"),
            (command.snapshot_id.as_uuid(), "workflow snapshot ID"),
            (command.run_id.as_uuid(), "workflow run ID"),
        ] {
            if value.is_nil() {
                return Err(LogicalWorkflowAdmissionValueError::NilUuid(field));
            }
        }
        if let WorkflowAdmissionIdempotency::Operation(operation_id) = &command.idempotency
            && operation_id.as_uuid().is_nil()
        {
            return Err(LogicalWorkflowAdmissionValueError::NilUuid(
                "workflow admission operation ID",
            ));
        }
        validate_graph(&command.jobs)?;
        Ok(command)
    }
}

/// Stable receipt returned for initial logical admission and exact replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogicalWorkflowAdmissionReceipt {
    repository_id: RepositoryId,
    workflow_id: WorkflowId,
    snapshot_id: WorkflowSnapshotId,
    run_id: RunId,
    root_invocation_id: LogicalWorkflowInvocationId,
    run_number: u64,
    replayed: bool,
}

impl LogicalWorkflowAdmissionReceipt {
    /// Constructs a validated adapter result.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        repository_id: RepositoryId,
        workflow_id: WorkflowId,
        snapshot_id: WorkflowSnapshotId,
        run_id: RunId,
        root_invocation_id: LogicalWorkflowInvocationId,
        run_number: u64,
        replayed: bool,
    ) -> Self {
        Self {
            repository_id,
            workflow_id,
            snapshot_id,
            run_id,
            root_invocation_id,
            run_number,
            replayed,
        }
    }

    /// Returns the durable repository identity.
    #[must_use]
    pub const fn repository_id(self) -> RepositoryId {
        self.repository_id
    }

    /// Returns the workflow definition identity.
    #[must_use]
    pub const fn workflow_id(self) -> WorkflowId {
        self.workflow_id
    }

    /// Returns the source snapshot identity.
    #[must_use]
    pub const fn snapshot_id(self) -> WorkflowSnapshotId {
        self.snapshot_id
    }

    /// Returns the admitted run identity.
    #[must_use]
    pub const fn run_id(self) -> RunId {
        self.run_id
    }

    /// Returns the admitted root invocation identity.
    #[must_use]
    pub const fn root_invocation_id(self) -> LogicalWorkflowInvocationId {
        self.root_invocation_id
    }

    /// Returns the server-allocated workflow run number.
    #[must_use]
    pub const fn run_number(self) -> u64 {
        self.run_number
    }

    /// Reports whether this receipt came from an exact durable replay.
    #[must_use]
    pub const fn is_replay(self) -> bool {
        self.replayed
    }
}

/// Atomic persistence boundary for current logical workflow admission.
#[async_trait]
pub trait LogicalWorkflowAdmissionRepository: std::fmt::Debug + Send + Sync {
    /// Resolves one exact source only when a current human session is allowed
    /// to dispatch the repository and a prior signed GitHub admission proves
    /// the same repository/workflow/ref/commit source descriptor.
    async fn resolve_authenticated_workflow_dispatch_source(
        &self,
        _request: ResolveAuthenticatedWorkflowDispatchSource,
    ) -> Result<Option<AuthenticatedWorkflowDispatchSource>, LogicalWorkflowAdmissionStoreError>
    {
        Err(LogicalWorkflowAdmissionStoreError::UnsupportedAdmissionSource)
    }

    /// Commits the run marker, root invocation, logical jobs, and dependencies,
    /// or returns the exact prior receipt for an identical request.
    ///
    /// This provider-neutral path never creates or backfills GitHub subject
    /// evidence.
    async fn admit_logical_workflow(
        &self,
        command: AdmitLogicalWorkflowRun,
    ) -> Result<LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionStoreError>;

    /// Commits one logical workflow whose signed GitHub delivery evidence must
    /// be bound atomically to the new run, or validates the exact immutable
    /// evidence receipt on replay.
    ///
    /// The current claim is only authority to attempt this operation.
    /// Implementations must row-lock and reject it unless the exact current
    /// inbox owner, attempt, fence, and lease horizon are live at
    /// `observed_at`, and durable signed-ingress, manifest, queued-Check,
    /// repository, source, plan, and run evidence all agree with `command`.
    /// Exact replay may use a newer live reclaim, but must never replace the
    /// immutable claim that authorized initial run creation.
    async fn admit_authenticated_github_delivery(
        &self,
        command: AdmitLogicalWorkflowRun,
        current_claim: AuthenticatedGithubDeliveryClaim,
        observed_at: UnixMillis,
    ) -> Result<LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionStoreError>;

    /// Commits one manual dispatch authorized by an Automata human session, or
    /// validates its exact immutable evidence and current authority on replay.
    ///
    /// Implementations must reauthorize `runs:dispatch` for the exact existing
    /// tenant/repository inside the admission transaction. They must bind the
    /// claim's workflow path/ref, event digest, base-context digest, operation,
    /// and authenticated subject to the durable admission receipt and audit
    /// evidence. This is a control-plane invocation, not a GitHub webhook.
    async fn admit_authenticated_workflow_dispatch(
        &self,
        _command: AdmitLogicalWorkflowRun,
        _claim: AuthenticatedWorkflowDispatchClaim,
    ) -> Result<LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionStoreError> {
        Err(LogicalWorkflowAdmissionStoreError::UnsupportedAdmissionSource)
    }
}

/// Invalid current logical-admission domain value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LogicalWorkflowAdmissionValueError {
    /// A durable UUID was the nil sentinel.
    #[error("{0} must not be the nil UUID")]
    NilUuid(&'static str),
    /// Required text was empty.
    #[error("{0} is empty")]
    EmptyText(&'static str),
    /// Text exceeded its bound or contained a control character.
    #[error("{0} is oversized or contains a control character")]
    InvalidText(&'static str),
    /// The Git ref was not a full `refs/...` name.
    #[error("Git ref must be a canonical full refs/... name")]
    InvalidGitRef,
    /// The run attempt did not fit a positive SQL integer.
    #[error("workflow run attempt must fit a positive PostgreSQL INTEGER")]
    InvalidRunAttempt,
    /// The base runtime-context object did not use the current canonical media type.
    #[error("workflow base runtime context is not a current canonical object")]
    InvalidBaseContext,
    /// The commit digest did not have a supported byte length.
    #[error("head SHA must contain exactly 20 or 32 bytes")]
    InvalidHeadSha,
    /// The admission timestamp preceded the Unix epoch.
    #[error("workflow admission time must not precede the Unix epoch")]
    InvalidAdmissionTime,
    /// No logical jobs were supplied.
    #[error("logical workflow admission requires at least one job")]
    NoJobs,
    /// The plan exceeded the logical-job bound.
    #[error("logical workflow admission exceeds its job limit")]
    TooManyJobs,
    /// A job exceeded its direct-prerequisite bound.
    #[error("logical workflow job exceeds its direct dependency limit")]
    TooManyDependencies,
    /// A durable logical-job identity or source key was repeated.
    #[error("logical workflow admission contains duplicate job identity")]
    DuplicateJob,
    /// Source order was not the exact canonical zero-based order.
    #[error("logical workflow jobs must use canonical zero-based source order")]
    InvalidSourceOrder,
    /// A prerequisite edge was repeated.
    #[error("logical workflow admission contains a duplicate dependency")]
    DuplicateDependency,
    /// A job depended on itself.
    #[error("logical workflow admission contains a self dependency")]
    SelfDependency,
    /// A prerequisite did not belong to this logical graph.
    #[error("logical workflow admission contains a dependency outside its run")]
    UnknownDependency,
    /// The logical graph contained a dependency cycle.
    #[error("logical workflow admission dependency graph is cyclic")]
    CyclicDependency,
}

/// Durable current logical-admission failure.
#[derive(Debug, Error)]
pub enum LogicalWorkflowAdmissionStoreError {
    /// The relational store failed or contained malformed current data.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// An idempotency identity was reused with different canonical evidence.
    #[error("logical workflow admission idempotency key was reused for a different request")]
    IdempotencyConflict,
    /// A server-owned identity already named a different durable object.
    #[error("durable {0} identity conflicts with the server-owned identity")]
    IdentityConflict(&'static str),
    /// The per-workflow run number counter cannot advance.
    #[error("workflow run-number sequence is exhausted")]
    RunNumberExhausted,
    /// The generalized pending queue reached its hard safety ceiling.
    #[error("workflow concurrency pending queue reached its safety limit")]
    ConcurrencyQueueFull,
    /// This deployment requires immutable authenticated provider evidence.
    #[error("logical workflow admission source is not supported by current policy")]
    UnsupportedAdmissionSource,
    /// Current human-session authority did not authorize the exact dispatch target.
    #[error("workflow dispatch authority was rejected")]
    WorkflowDispatchAuthorityRejected,
}

fn validate_text(
    value: &str,
    field: &'static str,
) -> Result<(), LogicalWorkflowAdmissionValueError> {
    if value.is_empty() {
        return Err(LogicalWorkflowAdmissionValueError::EmptyText(field));
    }
    if value.len() > MAX_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(LogicalWorkflowAdmissionValueError::InvalidText(field));
    }
    Ok(())
}

fn decode_commit_sha(value: &str) -> Result<Vec<u8>, LogicalWorkflowAdmissionValueError> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(LogicalWorkflowAdmissionValueError::InvalidHeadSha);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            };
            let high = digit(pair[0]).ok_or(LogicalWorkflowAdmissionValueError::InvalidHeadSha)?;
            let low = digit(pair[1]).ok_or(LogicalWorkflowAdmissionValueError::InvalidHeadSha)?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn validate_graph(
    jobs: &[AdmittedLogicalWorkflowJob],
) -> Result<(), LogicalWorkflowAdmissionValueError> {
    if jobs.is_empty() {
        return Err(LogicalWorkflowAdmissionValueError::NoJobs);
    }
    if jobs.len() > MAX_LOGICAL_JOBS {
        return Err(LogicalWorkflowAdmissionValueError::TooManyJobs);
    }

    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for (position, job) in jobs.iter().enumerate() {
        if usize::from(job.source_order()) != position {
            return Err(LogicalWorkflowAdmissionValueError::InvalidSourceOrder);
        }
        if !ids.insert(job.id()) || !keys.insert(job.key()) {
            return Err(LogicalWorkflowAdmissionValueError::DuplicateJob);
        }
        let mut prerequisites = BTreeSet::new();
        for prerequisite in job.prerequisites() {
            if !prerequisites.insert(*prerequisite) {
                return Err(LogicalWorkflowAdmissionValueError::DuplicateDependency);
            }
        }
    }

    let mut remaining = BTreeMap::new();
    let mut dependents: BTreeMap<LogicalWorkflowJobId, Vec<LogicalWorkflowJobId>> = BTreeMap::new();
    for job in jobs {
        remaining.insert(job.id(), job.prerequisites().len());
        for prerequisite in job.prerequisites() {
            if !ids.contains(prerequisite) {
                return Err(LogicalWorkflowAdmissionValueError::UnknownDependency);
            }
            dependents.entry(*prerequisite).or_default().push(job.id());
        }
    }

    let mut ready = remaining
        .iter()
        .filter_map(|(id, count)| (*count == 0).then_some(*id))
        .collect::<BTreeSet<_>>();
    let mut visited = 0;
    while let Some(job_id) = ready.pop_first() {
        visited += 1;
        if let Some(children) = dependents.get(&job_id) {
            for child in children {
                let count = remaining
                    .get_mut(child)
                    .expect("validated dependent belongs to the graph");
                *count -= 1;
                if *count == 0 {
                    ready.insert(*child);
                }
            }
        }
    }
    if visited != jobs.len() {
        return Err(LogicalWorkflowAdmissionValueError::CyclicDependency);
    }
    Ok(())
}
