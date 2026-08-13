use async_trait::async_trait;
use automata_ci_auth::authorization::{
    AuthorizationContext, AuthorizationRequest, OutputVisibility, Permission,
    RepositoryPublicationPolicy, RepositoryResource, SecretExposureClass,
};
use automata_ci_blob::{BlobDescriptor, BlobKey, MediaType};
use automata_ci_core::{
    AttemptId, AttemptNumber, JobConclusion, JobId, JobLifecycle, LogSequence, LogStreamId, RunId,
    RunnerId, Sha256Digest, UnixMillis, WorkflowId,
};
use thiserror::Error;

use crate::{DocumentSchema, JobIrMetadata, RepositoryId, StoreError, TenantScope};

/// Default page size for human-facing repository, workflow, and run reads.
pub const DEFAULT_HUMAN_PAGE_SIZE: u16 = 25;
/// Hard page-size ceiling for human-facing repository, workflow, and run reads.
pub const MAX_HUMAN_PAGE_SIZE: u16 = 250;
/// Default number of immutable log-segment descriptors returned at once.
pub const DEFAULT_HUMAN_LOG_SEGMENT_PAGE_SIZE: u16 = 32;
/// Hard log-segment descriptor page-size ceiling.
pub const MAX_HUMAN_LOG_SEGMENT_PAGE_SIZE: u16 = 256;
/// Fixed content type of runner terminal-result objects.
pub const HUMAN_JOB_RESULT_MEDIA_TYPE: &str = "application/vnd.automata.job-result+json";
/// Fixed content type of compressed runner log-segment objects.
pub const HUMAN_LOG_SEGMENT_MEDIA_TYPE: &str = "application/vnd.automata.log-segment+json+gzip";

const MAX_ROUTE_TEXT_BYTES: usize = 1_024;

/// Invalid, untrusted input to a human workflow read.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum HumanReadValueError {
    /// At least one provider, owner, or repository-name component is invalid.
    #[error("repository coordinates must be non-empty, bounded, and control-free")]
    InvalidRepositoryCoordinate,
    /// A run-list ref is not an exact bounded canonical `refs/...` value.
    #[error("a workflow-run git ref must be a canonical bounded refs/... value")]
    InvalidGitRef,
    /// A requested page size is zero or exceeds its closed endpoint limit.
    #[error("page size must be within the human-read bound")]
    InvalidPageSize,
    /// An artifact identifier is not a positive durable database identity.
    #[error("artifact IDs are positive durable integers")]
    InvalidArtifactId,
}

/// Provider-qualified, case-insensitive route coordinates for one repository.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryCoordinate {
    provider: String,
    owner: String,
    name: String,
}

impl RepositoryCoordinate {
    /// Builds a bounded repository route coordinate.
    ///
    /// # Errors
    ///
    /// Returns an error when any component is empty, oversized, or control-bearing.
    pub fn new(
        provider: impl Into<String>,
        owner: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self, HumanReadValueError> {
        let provider = provider.into();
        let owner = owner.into();
        let name = name.into();
        if [&provider, &owner, &name]
            .into_iter()
            .any(|value| !valid_route_text(value))
        {
            return Err(HumanReadValueError::InvalidRepositoryCoordinate);
        }
        Ok(Self {
            provider,
            owner,
            name,
        })
    }

    /// Returns the provider route component exactly as validated.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Returns the repository-owner route component exactly as validated.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Returns the repository-name route component exactly as validated.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Exact canonical git reference used by a run-list filter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanGitRef(String);

impl HumanGitRef {
    /// Creates one exact canonical `refs/...` filter.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-canonical, oversized, or control-bearing ref.
    pub fn new(value: impl Into<String>) -> Result<Self, HumanReadValueError> {
        let value = value.into();
        if !value.starts_with("refs/")
            || value.len() < 6
            || value.len() > MAX_ROUTE_TEXT_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(HumanReadValueError::InvalidGitRef);
        }
        Ok(Self(value))
    }

    /// Returns the exact canonical `refs/...` value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Validated bound shared by repository, workflow, and run pages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HumanPageSize(u16);

impl HumanPageSize {
    /// Creates a non-zero page size within the human-read ceiling.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or a value above [`MAX_HUMAN_PAGE_SIZE`].
    pub fn new(value: u16) -> Result<Self, HumanReadValueError> {
        if value == 0 || value > MAX_HUMAN_PAGE_SIZE {
            return Err(HumanReadValueError::InvalidPageSize);
        }
        Ok(Self(value))
    }

    /// Returns the validated number of rows requested for a human page.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl Default for HumanPageSize {
    fn default() -> Self {
        Self(DEFAULT_HUMAN_PAGE_SIZE)
    }
}

/// Validated bound for one immutable log-segment descriptor page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HumanLogSegmentPageSize(u16);

impl HumanLogSegmentPageSize {
    /// Creates a non-zero log descriptor page size within its ceiling.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or a value above
    /// [`MAX_HUMAN_LOG_SEGMENT_PAGE_SIZE`].
    pub fn new(value: u16) -> Result<Self, HumanReadValueError> {
        if value == 0 || value > MAX_HUMAN_LOG_SEGMENT_PAGE_SIZE {
            return Err(HumanReadValueError::InvalidPageSize);
        }
        Ok(Self(value))
    }

    /// Returns the validated maximum number of log descriptors in a page.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl Default for HumanLogSegmentPageSize {
    fn default() -> Self {
        Self(DEFAULT_HUMAN_LOG_SEGMENT_PAGE_SIZE)
    }
}

/// Keyset position for repositories ordered by normalized owner/name and ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanRepositoryCursor {
    /// Case-folded owner value used as the first keyset component.
    pub normalized_owner: String,
    /// Case-folded repository name used as the second keyset component.
    pub normalized_name: String,
    /// Durable repository identity used to make the keyset ordering total.
    pub id: RepositoryId,
}

/// Bounded tenant repository-list request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanRepositoryListQuery {
    /// Exact tenant whose repositories may be returned.
    pub tenant: TenantScope,
    /// Exclusive keyset boundary, or the first page when absent.
    pub cursor: Option<HumanRepositoryCursor>,
    /// Validated maximum number of repositories to return.
    pub limit: HumanPageSize,
}

impl HumanRepositoryListQuery {
    /// Creates a first-page repository query scoped to `tenant`.
    #[must_use]
    pub fn new(tenant: TenantScope) -> Self {
        Self {
            tenant,
            cursor: None,
            limit: HumanPageSize::default(),
        }
    }
}

/// Canonical repository identity plus its current durable publication policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanRepository {
    /// Tenant-local durable repository identity.
    pub id: RepositoryId,
    /// Authorization resource identifying this exact repository.
    pub resource: RepositoryResource,
    /// Canonical source-control provider discriminator.
    pub scm_provider: String,
    /// Provider-side stable repository identity.
    pub provider_repository_id: String,
    /// Display owner recorded for route and presentation use.
    pub owner: String,
    /// Display repository name recorded for route and presentation use.
    pub name: String,
    /// Current durable repository publication policy.
    pub publication: RepositoryPublicationPolicy,
    /// Positive revision that guards the publication-policy snapshot.
    pub publication_revision: u64,
}

/// One bounded repository page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanRepositoryPage {
    /// Repositories authorized within the exact tenant query.
    pub repositories: Vec<HumanRepository>,
    /// Exclusive cursor for a later page, when more rows exist.
    pub next_cursor: Option<HumanRepositoryCursor>,
}

/// Visibility-bearing projection of a workflow name from one exact run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanWorkflowProjectedName {
    /// Human-facing workflow name projected from an immutable run.
    pub name: String,
    /// Exact run from which the name was projected.
    pub source_run_id: RunId,
    /// Immutable visibility that must authorize presenting the projected name.
    pub effective_visibility: OutputVisibility,
}

/// One durable workflow definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanWorkflow {
    /// Tenant-local durable workflow identity.
    pub id: WorkflowId,
    /// Repository-relative workflow definition path.
    pub path: String,
    /// Whether new events may select this workflow.
    pub enabled: bool,
    /// The newest run projection. Its visibility must be authorized
    /// independently before presentation; `path` remains the honest fallback.
    pub projected_name: Option<HumanWorkflowProjectedName>,
}

/// Keyset position for workflows ordered by path and ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanWorkflowCursor {
    /// Workflow path used as the first keyset component.
    pub path: String,
    /// Durable workflow identity used to make path ordering total.
    pub id: WorkflowId,
}

/// Bounded repository workflow-list request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanWorkflowListQuery {
    /// Exact tenant owning the repository.
    pub tenant: TenantScope,
    /// Exact repository whose workflows may be returned.
    pub repository_id: RepositoryId,
    /// Exclusive keyset boundary, or the first page when absent.
    pub cursor: Option<HumanWorkflowCursor>,
    /// Validated maximum number of workflows to return.
    pub limit: HumanPageSize,
}

impl HumanWorkflowListQuery {
    /// Creates a first-page query for one tenant-scoped repository.
    #[must_use]
    pub fn new(tenant: TenantScope, repository_id: RepositoryId) -> Self {
        Self {
            tenant,
            repository_id,
            cursor: None,
            limit: HumanPageSize::default(),
        }
    }
}

/// One bounded workflow page, or no page when its repository is not in scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanWorkflowPage {
    /// Workflows found under the exact tenant/repository parent.
    pub workflows: Vec<HumanWorkflow>,
    /// Exclusive cursor for a later page, when more rows exist.
    pub next_cursor: Option<HumanWorkflowCursor>,
}

/// Stable aggregate conclusion derived only from every job's latest attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanRunConclusion {
    /// Every relevant latest attempt completed successfully.
    Success,
    /// At least one relevant latest attempt failed.
    Failure,
    /// The run was cancelled.
    Cancelled,
    /// At least one relevant latest attempt timed out.
    TimedOut,
    /// Every relevant latest attempt was skipped.
    Skipped,
    /// At least one relevant latest attempt was lost.
    Lost,
}

/// Exact durable lifecycle filter used by the run index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanRunStatusFilter {
    /// Selects runs that have not started execution.
    Queued,
    /// Selects runs with execution still in progress.
    InProgress,
    /// Includes both normally completed and explicitly cancelled runs.
    Completed,
}

/// Direction from a run keyset boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanRunPageDirection {
    /// Selects rows older than the supplied keyset boundary.
    Older,
    /// Selects rows newer than the supplied keyset boundary.
    Newer,
}

/// Run keyset position ordered by `(created_at DESC, id DESC)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HumanRunCursor {
    /// Run creation time used as the first descending keyset component.
    pub created_at: UnixMillis,
    /// Durable run identity used to make creation-time ordering total.
    pub id: RunId,
}

/// Immutable publication evidence snapshotted with one workflow run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanRunPublication {
    /// Positive repository-policy revision snapshotted at admission.
    pub policy_revision: u64,
    /// Dashboard audience requested by the admitted run.
    pub requested_dashboard_visibility: OutputVisibility,
    /// Immutable dashboard audience after safety narrowing.
    pub effective_dashboard_visibility: OutputVisibility,
    /// Log audience requested by the admitted run.
    pub requested_log_visibility: OutputVisibility,
    /// Artifact audience requested by the admitted run.
    pub requested_artifact_visibility: OutputVisibility,
    /// Closed machine reason for any safety-driven audience decision.
    pub safety_reason: String,
    /// Schema version governing the safety evidence.
    pub safety_schema: u16,
}

/// Git commit identity retained as its exact 20-byte SHA-1 or 32-byte SHA-256 value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanGitCommitId(Vec<u8>);

impl HumanGitCommitId {
    /// Builds an exact SHA-1 or SHA-256 commit identity.
    ///
    /// # Errors
    ///
    /// Returns an error unless `bytes` contains exactly 20 or 32 bytes.
    pub fn new(bytes: Vec<u8>) -> Result<Self, StoreError> {
        Self::from_durable_bytes(bytes)
    }

    pub(crate) fn from_durable_bytes(bytes: Vec<u8>) -> Result<Self, StoreError> {
        if matches!(bytes.len(), 20 | 32) {
            Ok(Self(bytes))
        } else {
            Err(StoreError::corrupt_data(
                "workflow run head digest has an invalid length",
            ))
        }
    }

    /// Returns the exact raw commit identity bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Human-readable workflow run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanRun {
    /// Durable run identity within its tenant and repository.
    pub id: RunId,
    /// Durable workflow definition selected for this run.
    pub workflow_id: WorkflowId,
    /// Repository-relative workflow path snapshotted for the run.
    pub workflow_path: String,
    /// Monotonic human-facing run number.
    pub run_number: u64,
    /// Human-facing rerun attempt number.
    pub run_attempt: u32,
    /// Canonical trigger event name.
    pub event_name: String,
    /// Exact source commit identity admitted for execution.
    pub head_commit: HumanGitCommitId,
    /// Current durable run lifecycle.
    pub status: crate::WorkflowRunStatus,
    /// Stable aggregate conclusion once derivable from latest attempts.
    pub conclusion: Option<HumanRunConclusion>,
    /// Immutable human-facing workflow name.
    pub workflow_name: String,
    /// Optional exact canonical source ref.
    pub git_ref: Option<String>,
    /// Optional sanitized trigger actor label.
    pub actor: Option<String>,
    /// Optional bounded presentation title.
    pub display_title: Option<String>,
    /// Optional bounded source commit subject.
    pub commit_subject: Option<String>,
    /// Time at which the durable run was created.
    pub created_at: UnixMillis,
    /// Time of the latest durable run transition.
    pub updated_at: UnixMillis,
    /// Terminal time, absent while the run remains open.
    pub finished_at: Option<UnixMillis>,
    /// Immutable publication evidence that independently gates presentation.
    pub publication: HumanRunPublication,
}

/// Bounded run-index request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanRunListQuery {
    /// Exact tenant owning the queried repository.
    pub tenant: TenantScope,
    /// Exact repository whose runs may be returned.
    pub repository_id: RepositoryId,
    /// Optional workflow parent filter within the same repository.
    pub workflow_id: Option<WorkflowId>,
    /// Optional durable lifecycle filter.
    pub status: Option<HumanRunStatusFilter>,
    /// Optional exact canonical ref filter.
    pub git_ref: Option<HumanGitRef>,
    /// Optional exclusive run keyset boundary.
    pub cursor: Option<HumanRunCursor>,
    /// Direction in which to traverse from `cursor`.
    pub direction: HumanRunPageDirection,
    /// Validated maximum number of runs to return.
    pub limit: HumanPageSize,
}

impl HumanRunListQuery {
    /// Creates a first, older-facing run page for one exact repository.
    #[must_use]
    pub fn new(tenant: TenantScope, repository_id: RepositoryId) -> Self {
        Self {
            tenant,
            repository_id,
            workflow_id: None,
            status: None,
            git_ref: None,
            cursor: None,
            direction: HumanRunPageDirection::Older,
            limit: HumanPageSize::default(),
        }
    }
}

/// One keyset run page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanRunPage {
    /// Runs authorized under the exact tenant/repository query.
    pub runs: Vec<HumanRun>,
    /// Exclusive boundary for traversing toward older runs.
    pub older_cursor: Option<HumanRunCursor>,
    /// Exclusive boundary for traversing toward newer runs.
    pub newer_cursor: Option<HumanRunCursor>,
}

/// Tenant/repository-bound run lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanRunScope {
    /// Exact tenant owning the run.
    pub tenant: TenantScope,
    /// Exact repository containing the run.
    pub repository_id: RepositoryId,
    /// Exact run to resolve under those parents.
    pub run_id: RunId,
}

impl HumanRunScope {
    /// Creates a fully nested tenant/repository/run lookup scope.
    #[must_use]
    pub const fn new(tenant: TenantScope, repository_id: RepositoryId, run_id: RunId) -> Self {
        Self {
            tenant,
            repository_id,
            run_id,
        }
    }
}

/// Exact runner identity retained for one latest attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanRunner {
    /// Durable identity of the runner that accepted the attempt.
    pub id: RunnerId,
    /// Sanitized runner name retained for presentation.
    pub name: String,
}

/// Exact committed terminal-result object for one attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanTerminalResult {
    /// Exact attempt that committed this terminal object.
    pub attempt_id: AttemptId,
    /// Validated terminal-result document schema.
    pub schema: DocumentSchema,
    /// Immutable terminal-result blob descriptor.
    pub descriptor: BlobDescriptor,
    /// Terminal job conclusion recorded by the runner.
    pub conclusion: JobConclusion,
    /// Runner-reported completion time.
    pub completed_at: UnixMillis,
    /// Time at which the store committed the immutable result.
    pub committed_at: UnixMillis,
}

/// Immutable output-safety evidence for a log stream or artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanOutputPublication {
    /// Closed exposure class observed for this exact output.
    pub secret_exposure: SecretExposureClass,
    /// Audience originally requested for this output kind.
    pub requested_visibility: OutputVisibility,
    /// Immutable audience after exposure-driven narrowing.
    pub effective_visibility: OutputVisibility,
    /// Closed machine reason supporting the effective audience.
    pub safety_reason: String,
    /// Schema version governing the output-safety evidence.
    pub safety_schema: u16,
}

/// Durable handling selected for raw user-controlled log output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanRawLogDisposition {
    /// Runner-redacted user-controlled log frames may be durably persisted.
    Persist,
}

/// Latest durable attempt for one job.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanJobAttempt {
    /// Durable attempt identity.
    pub id: AttemptId,
    /// Monotonic attempt number within the job.
    pub number: AttemptNumber,
    /// Current durable attempt lifecycle.
    pub lifecycle: JobLifecycle,
    /// Time at which the attempt entered the queue.
    pub queued_at: UnixMillis,
    /// Time of the latest durable lifecycle transition.
    pub changed_at: UnixMillis,
    /// Immutable first lease issue time when execution began.
    ///
    /// This is absent for never-leased attempts and historical terminal rows
    /// whose mutable lease custody was cleared before start retention existed.
    pub started_at: Option<UnixMillis>,
    /// Terminal time, absent while the attempt remains open.
    pub finished_at: Option<UnixMillis>,
    /// Runner identity when an assignment remains present.
    pub runner: Option<HumanRunner>,
    /// Exact committed terminal object when finalization completed.
    pub terminal_result: Option<HumanTerminalResult>,
}

/// One job and the immutable objects needed to render its latest attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanJob {
    /// Durable job identity within the run.
    pub id: JobId,
    /// Stable workflow job key.
    pub key: String,
    /// Bounded human-facing job name.
    pub display_name: String,
    /// Time at which the durable job was created.
    pub created_at: UnixMillis,
    /// Exact immutable `JobIR` descriptor.
    pub job_ir: JobIrMetadata,
    /// Latest durable attempt, absent when the job has not entered the queue.
    pub latest_attempt: Option<HumanJobAttempt>,
    /// Publication ceiling for the latest attempt's log stream. Absence means
    /// the job has not opened a durable stream yet.
    pub log_publication: Option<HumanOutputPublication>,
}

/// Finalized artifact metadata discoverable from one run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanArtifactSummary {
    /// Positive durable artifact identity.
    pub id: HumanArtifactId,
    /// Artifact name selected by the workflow.
    pub name: String,
    /// Finalized artifact content type.
    pub mime_type: String,
    /// Exact logical content size in bytes.
    pub content_size: u64,
    /// Exact digest of the finalized logical content.
    pub content_digest: Sha256Digest,
    /// Optional wall-clock expiry in Unix seconds.
    pub expires_at_seconds: Option<i64>,
    /// Wall-clock finalization time in Unix seconds.
    pub finalized_at_seconds: i64,
    /// Immutable audience and exposure evidence for this artifact.
    pub publication: HumanOutputPublication,
}

/// Run detail with bounded, integrity-checked jobs and artifact summaries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanRunDetail {
    /// Exact tenant/repository-scoped run.
    pub run: HumanRun,
    /// Bounded jobs belonging to that exact run.
    pub jobs: Vec<HumanJob>,
    /// Finalized artifact summaries belonging to that exact run.
    pub artifacts: Vec<HumanArtifactSummary>,
}

/// Tenant/repository/run-bound job lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanJobScope {
    /// Exact tenant owning the repository.
    pub tenant: TenantScope,
    /// Exact repository containing the run.
    pub repository_id: RepositoryId,
    /// Exact run containing the job.
    pub run_id: RunId,
    /// Exact job to resolve beneath those parents.
    pub job_id: JobId,
}

impl HumanJobScope {
    /// Creates a fully nested tenant/repository/run/job lookup scope.
    #[must_use]
    pub const fn new(
        tenant: TenantScope,
        repository_id: RepositoryId,
        run_id: RunId,
        job_id: JobId,
    ) -> Self {
        Self {
            tenant,
            repository_id,
            run_id,
            job_id,
        }
    }
}

/// Bounded navigation row for one job in a selected run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanJobNavigation {
    /// Durable job identity within the selected run.
    pub id: JobId,
    /// Bounded human-facing job name.
    pub display_name: String,
    /// Latest attempt lifecycle, or absence when no attempt exists.
    pub lifecycle: Option<JobLifecycle>,
    /// Aggregate latest-attempt conclusion when terminal.
    pub conclusion: Option<HumanRunConclusion>,
    /// Immutable log audience evidence, when a stream exists.
    pub log_publication: Option<HumanOutputPublication>,
}

/// Attempt log stream descriptor without an unbounded segment collection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanLogStream {
    /// Durable stream identity.
    pub id: LogStreamId,
    /// Exact attempt that owns the stream.
    pub attempt_id: AttemptId,
    /// Validated log-document schema.
    pub schema: DocumentSchema,
    /// Time at which the stream was opened.
    pub opened_at: UnixMillis,
    /// Time at which the stream was closed, when terminal.
    pub closed_at: Option<UnixMillis>,
    /// Durable handling selected for raw user output.
    pub raw_log_disposition: HumanRawLogDisposition,
    /// Immutable audience and exposure evidence for the stream.
    pub publication: HumanOutputPublication,
}

/// Selected job plus same-run navigation and at most one latest-attempt log stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanJobDetail {
    /// Exact tenant/repository-scoped parent run.
    pub run: HumanRun,
    /// Bounded sibling navigation already narrowed for presentation.
    pub navigation: Vec<HumanJobNavigation>,
    /// Exact selected job.
    pub job: HumanJob,
    /// Latest-attempt stream, absent when no stream has opened.
    pub log_stream: Option<HumanLogStream>,
}

/// Bounded segment-page request, tied to the complete repository/run/job nesting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanLogSegmentQuery {
    /// Complete tenant/repository/run/job scope of the stream.
    pub scope: HumanJobScope,
    /// Exact stream beneath the selected job's latest attempt.
    pub stream_id: LogStreamId,
    /// Optional exclusive sequence boundary.
    pub cursor: Option<HumanLogSegmentCursor>,
    /// Validated maximum number of descriptors to return.
    pub limit: HumanLogSegmentPageSize,
}

/// Direction from one log-sequence boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanLogSegmentPageDirection {
    /// Selects segments before the supplied sequence boundary.
    Older,
    /// Selects segments after the supplied sequence boundary.
    Newer,
}

/// Sequence-bound log cursor kept typed until the HTTP layer encodes it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HumanLogSegmentCursor {
    /// Exact frame sequence at the exclusive page boundary.
    pub sequence: LogSequence,
    /// Direction in which to traverse from the boundary.
    pub direction: HumanLogSegmentPageDirection,
}

/// Immutable compressed object covering an inclusive log-frame sequence range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanLogSegment {
    /// First frame sequence covered by the immutable object.
    pub first_sequence: LogSequence,
    /// Last frame sequence covered by the immutable object.
    pub last_sequence: LogSequence,
    /// Immutable compressed log object descriptor.
    pub descriptor: BlobDescriptor,
    /// Exact decoded byte size recorded for the object.
    pub uncompressed_size: u64,
    /// Time at which the segment descriptor became durable.
    pub stored_at: UnixMillis,
    /// Whether this segment closes the stream.
    pub end_of_stream: bool,
}

/// One deterministic segment page. Sequence cursors are encoded only by the app.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanLogSegmentPage {
    /// Exact stream whose segments were listed.
    pub stream: HumanLogStream,
    /// Contiguous immutable descriptors in deterministic sequence order.
    pub segments: Vec<HumanLogSegment>,
    /// Exclusive boundary for traversing toward older segments.
    pub older_cursor: Option<HumanLogSegmentCursor>,
    /// Exclusive boundary for traversing toward newer segments.
    pub newer_cursor: Option<HumanLogSegmentCursor>,
}

/// Positive durable artifact identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HumanArtifactId(i64);

impl HumanArtifactId {
    /// Creates one positive durable artifact identity.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or a negative value.
    pub fn new(value: i64) -> Result<Self, HumanReadValueError> {
        if value <= 0 {
            return Err(HumanReadValueError::InvalidArtifactId);
        }
        Ok(Self(value))
    }

    /// Returns the positive durable artifact identity.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// Tenant/repository/run-bound artifact lookup at one trusted wall-clock instant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanArtifactScope {
    /// Exact tenant owning the repository.
    pub tenant: TenantScope,
    /// Exact repository containing the run.
    pub repository_id: RepositoryId,
    /// Exact run containing the artifact.
    pub run_id: RunId,
    /// Exact finalized artifact identity.
    pub artifact_id: HumanArtifactId,
    /// Trusted Unix-seconds instant used to reject expired artifacts.
    pub observed_at_seconds: i64,
}

/// One committed block in exact block-list order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanArtifactBlock {
    /// One-based position in the committed block list.
    pub ordinal: u32,
    /// Exact external block identifier committed by the uploader.
    pub block_id: String,
    /// Immutable descriptor of the ready block object.
    pub descriptor: BlobDescriptor,
}

/// Finalized, unexpired artifact plus every ready block in committed order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanArtifactDownload {
    /// Finalized artifact metadata and immutable publication evidence.
    pub artifact: HumanArtifactSummary,
    /// Immutable manifest object describing the committed artifact.
    pub manifest: BlobDescriptor,
    /// Digest binding the exact ordered block list.
    pub block_list_digest: Sha256Digest,
    /// Unix-seconds instant at which finalization committed.
    pub committed_at_seconds: i64,
    /// Every ready block in exact committed order.
    pub blocks: Vec<HumanArtifactBlock>,
}

/// Exact repository authorization request plus an immutable resource ceiling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanAuthorizationTarget {
    /// Exact repository resource and permission to evaluate.
    pub request: AuthorizationRequest,
    /// `None` uses the repository's current policy. Run, log, and artifact
    /// targets must carry their exact immutable effective visibility.
    pub durable_visibility: Option<OutputVisibility>,
}

impl HumanAuthorizationTarget {
    /// Builds a target governed by the repository's current publication policy.
    #[must_use]
    pub const fn current_policy(request: AuthorizationRequest) -> Self {
        Self {
            request,
            durable_visibility: None,
        }
    }

    /// Builds a target capped by an immutable run, log, or artifact audience.
    #[must_use]
    pub const fn immutable(
        request: AuthorizationRequest,
        durable_visibility: OutputVisibility,
    ) -> Self {
        Self {
            request,
            durable_visibility: Some(durable_visibility),
        }
    }
}

/// Backend-neutral, tenant-scoped reads used by human workflow pages.
///
/// All nested lookups return `Ok(None)` for missing and cross-tenant resources.
/// Implementations must bind tenant, repository, and every parent identity in
/// each child query instead of treating UUID knowledge as authority.
#[async_trait]
pub trait HumanWorkflowReadRepository: std::fmt::Debug + Send + Sync {
    /// Resolves one provider/owner/name coordinate inside `tenant`.
    ///
    /// Missing, denied, and cross-tenant coordinates return `Ok(None)` so the
    /// caller cannot enumerate repository existence.
    async fn resolve_repository(
        &self,
        tenant: &TenantScope,
        coordinate: &RepositoryCoordinate,
    ) -> Result<Option<HumanRepository>, StoreError>;

    /// Lists repositories visible to `context` under any requested discovery
    /// permission.
    ///
    /// The current contract accepts only `repositories:read` and
    /// `secrets:metadata:read`. Implementations must reject an empty,
    /// duplicate, unsupported, or unbounded permission set, evaluate every
    /// accepted permission before keyset pagination, and must not leak
    /// unauthorized rows through scan thresholds, cursors, or counts.
    async fn list_repositories(
        &self,
        query: &HumanRepositoryListQuery,
        context: &AuthorizationContext,
        permissions: &[Permission],
    ) -> Result<HumanRepositoryPage, StoreError>;

    /// Lists workflows beneath one exact tenant/repository parent.
    ///
    /// A missing, denied, or cross-tenant repository returns `Ok(None)`. Any
    /// projected workflow name retains its independent immutable audience.
    async fn list_workflows(
        &self,
        query: &HumanWorkflowListQuery,
        context: &AuthorizationContext,
        permission: &Permission,
    ) -> Result<Option<HumanWorkflowPage>, StoreError>;

    /// Lists runs beneath one exact tenant/repository and optional workflow.
    ///
    /// Authorization uses `context` and `permission`; missing and denied parent
    /// resources remain indistinguishable as `Ok(None)`.
    async fn list_runs(
        &self,
        query: &HumanRunListQuery,
        context: &AuthorizationContext,
        permission: &Permission,
    ) -> Result<Option<HumanRunPage>, StoreError>;

    /// Loads one exact tenant/repository/run tree without granting presentation.
    ///
    /// The immutable dashboard and per-output audiences must still be evaluated
    /// separately, and absent or mismatched parents return `Ok(None)`.
    async fn get_run(&self, scope: &HumanRunScope) -> Result<Option<HumanRunDetail>, StoreError>;

    /// Loads one exact tenant/repository/run/job and its latest-attempt stream.
    ///
    /// This raw scoped read grants no dashboard or log permission. Missing or
    /// mismatched nesting returns `Ok(None)` without revealing which parent failed.
    async fn get_job(&self, scope: &HumanJobScope) -> Result<Option<HumanJobDetail>, StoreError>;

    /// Lists immutable descriptors for one exact latest-attempt log stream.
    ///
    /// Implementations must bind every parent and return `Ok(None)` for stale,
    /// missing, or cross-scope stream identities; log audience remains separate.
    async fn list_log_segments(
        &self,
        query: &HumanLogSegmentQuery,
    ) -> Result<Option<HumanLogSegmentPage>, StoreError>;

    /// Loads one finalized, unexpired artifact under its complete parent scope.
    ///
    /// This raw read grants no download permission. Missing, expired, denied,
    /// and cross-scope identities remain non-enumerating at the caller boundary.
    async fn get_artifact(
        &self,
        scope: &HumanArtifactScope,
    ) -> Result<Option<HumanArtifactDownload>, StoreError>;

    /// Resolves durable grants and publication policy for one exact resource.
    /// Missing, denied, and cross-tenant resources fail closed as `false`. An
    /// immutable target audience is an additional ceiling, never a replacement
    /// for the requested permission or current repository authority.
    async fn is_repository_request_allowed(
        &self,
        tenant: &TenantScope,
        repository_id: RepositoryId,
        context: &AuthorizationContext,
        target: &HumanAuthorizationTarget,
    ) -> Result<bool, StoreError>;
}

pub(crate) fn blob_descriptor(
    object_key: String,
    digest: Sha256Digest,
    encoded_size: u64,
    media_type: String,
) -> Result<BlobDescriptor, StoreError> {
    let key = BlobKey::new(object_key)
        .map_err(|_| StoreError::corrupt_data("immutable object key is invalid"))?;
    let media_type = MediaType::new(media_type)
        .map_err(|_| StoreError::corrupt_data("immutable object media type is invalid"))?;
    Ok(BlobDescriptor::new(key, digest, encoded_size, media_type))
}

fn valid_route_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_ROUTE_TEXT_BYTES && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untrusted_coordinates_refs_and_bounds_are_validated() {
        assert!(RepositoryCoordinate::new("github", "Automata", "CI").is_ok());
        assert!(RepositoryCoordinate::new("", "Automata", "CI").is_err());
        assert!(RepositoryCoordinate::new("github", "Auto\nmata", "CI").is_err());
        assert!(HumanGitRef::new("refs/heads/main").is_ok());
        assert!(HumanGitRef::new("main").is_err());
        assert_eq!(
            HumanGitCommitId::new(vec![0x11; 20])
                .expect("SHA-1 identity")
                .as_bytes(),
            &[0x11; 20]
        );
        assert_eq!(
            HumanGitCommitId::new(vec![0x22; 32])
                .expect("SHA-256 identity")
                .as_bytes(),
            &[0x22; 32]
        );
        assert!(HumanGitCommitId::new(vec![0; 31]).is_err());
        assert!(HumanPageSize::new(1).is_ok());
        assert!(HumanPageSize::new(MAX_HUMAN_PAGE_SIZE).is_ok());
        assert!(HumanPageSize::new(0).is_err());
        assert!(HumanPageSize::new(MAX_HUMAN_PAGE_SIZE + 1).is_err());
    }
}
