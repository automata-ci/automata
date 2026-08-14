//! Domain and schema boundary for authenticated workflow-rerun requests.
//!
//! A rerun creates one fresh physical attempt while preserving the stable
//! provider-visible run identity. Immutable selection, carry-forward, actor,
//! and Check-projection evidence is committed in the same transaction.

use std::fmt;

use async_trait::async_trait;
use automata_ci_auth::management::ManagementActor;
use automata_ci_core::{OperationId, RunId};
use thiserror::Error;

use crate::{LogicalWorkflowJobId, RepositoryId, StoreError};

/// Maximum physical attempts after the original run and its 50 allowed reruns.
pub const MAX_WORKFLOW_RERUN_ATTEMPTS: u32 = 51;
/// Repository-authoritative retention horizon for rerunning a terminal run.
pub const MAX_WORKFLOW_RERUN_AGE_MILLIS: i64 = 2_592_000_000;
const MAX_WORKFLOW_RERUN_REPOSITORY_SEGMENT_BYTES: usize = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkflowRerunLimitRejection {
    AgeMillis,
    RepositorySegmentBytes,
}

pub(crate) const fn workflow_rerun_age_rejection(
    observed: i64,
) -> Option<WorkflowRerunLimitRejection> {
    if observed > MAX_WORKFLOW_RERUN_AGE_MILLIS {
        return Some(WorkflowRerunLimitRejection::AgeMillis);
    }
    None
}

const fn workflow_rerun_repository_segment_byte_rejection(
    observed: usize,
) -> Option<WorkflowRerunLimitRejection> {
    if observed > MAX_WORKFLOW_RERUN_REPOSITORY_SEGMENT_BYTES {
        return Some(WorkflowRerunLimitRejection::RepositorySegmentBytes);
    }
    None
}

/// Returns the next physical attempt while the 50-rerun budget remains.
///
/// Attempt one is the original execution, so attempt 51 is the final allowed
/// physical execution and represents rerun 50.
#[must_use]
pub const fn next_workflow_rerun_attempt(current_attempt: u32) -> Option<u32> {
    if current_attempt >= MAX_WORKFLOW_RERUN_ATTEMPTS {
        None
    } else {
        current_attempt.checked_add(1)
    }
}

/// Closed selection mode for a durable workflow rerun.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkflowRerunSelection {
    /// Re-executes every logical job from the immutable original admission.
    EntireWorkflow,
    /// Re-executes every failed logical job and its exact downstream closure.
    FailedJobsAndDependents,
    /// Re-executes one selected logical job and its exact downstream closure.
    JobAndDependents(LogicalWorkflowJobId),
}

/// Current human authority and idempotency identity for one rerun request.
///
/// The actor is intentionally not treated as historical run metadata. An
/// executable adapter must reauthorize it for `runs:rerun` while holding the
/// source run and idempotency receipt records, then record it as the new attempt's
/// triggering actor and security-audit subject.
#[derive(Clone, Eq, PartialEq)]
pub struct RerunWorkflow {
    actor: ManagementActor,
    repository_id: RepositoryId,
    source_run_id: RunId,
    selection: WorkflowRerunSelection,
    operation_id: OperationId,
}

impl fmt::Debug for RerunWorkflow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RerunWorkflow")
            .field("repository_id", &self.repository_id)
            .field("source_run_id", &self.source_run_id)
            .field("selection", &self.selection)
            .field("operation_id", &self.operation_id)
            .finish_non_exhaustive()
    }
}

impl RerunWorkflow {
    /// Creates one exact, idempotent rerun request.
    ///
    /// # Errors
    ///
    /// Rejects nil durable identities before an adapter observes authority.
    pub fn new(
        actor: ManagementActor,
        repository_id: RepositoryId,
        source_run_id: RunId,
        selection: WorkflowRerunSelection,
        operation_id: OperationId,
    ) -> Result<Self, WorkflowRerunValueError> {
        for (value, field) in [
            (repository_id.as_uuid(), "repository ID"),
            (source_run_id.as_uuid(), "source workflow run ID"),
            (operation_id.as_uuid(), "workflow rerun operation ID"),
        ] {
            if value.is_nil() {
                return Err(WorkflowRerunValueError::NilUuid(field));
            }
        }
        if let WorkflowRerunSelection::JobAndDependents(job_id) = selection
            && job_id.as_uuid().is_nil()
        {
            return Err(WorkflowRerunValueError::NilUuid("selected logical job ID"));
        }
        Ok(Self {
            actor,
            repository_id,
            source_run_id,
            selection,
            operation_id,
        })
    }

    /// Returns the caller that must be transactionally reauthorized.
    #[must_use]
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    /// Returns the exact repository containing the source attempt.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Returns the terminal physical attempt selected as the rerun source.
    #[must_use]
    pub const fn source_run_id(&self) -> RunId {
        self.source_run_id
    }

    /// Returns the immutable selection mode.
    #[must_use]
    pub const fn selection(&self) -> WorkflowRerunSelection {
        self.selection
    }

    /// Returns the caller-supplied idempotency operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }
}

/// Current human authority and human-facing repository coordinate for a rerun.
///
/// An executable adapter resolves the case-insensitive GitHub `owner/name`
/// coordinate and reauthorizes `runs:rerun` in the same transaction. Missing
/// and unauthorized coordinates must remain indistinguishable.
#[derive(Clone, Eq, PartialEq)]
pub struct RerunWorkflowByName {
    actor: ManagementActor,
    repository_owner: String,
    repository_name: String,
    source_run_id: RunId,
    selection: WorkflowRerunSelection,
    operation_id: OperationId,
}

impl fmt::Debug for RerunWorkflowByName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RerunWorkflowByName")
            .field("repository_owner", &self.repository_owner)
            .field("repository_name", &self.repository_name)
            .field("source_run_id", &self.source_run_id)
            .field("selection", &self.selection)
            .field("operation_id", &self.operation_id)
            .finish_non_exhaustive()
    }
}

impl RerunWorkflowByName {
    /// Creates a rerun request addressed by bounded `OWNER/REPOSITORY` text.
    ///
    /// # Errors
    ///
    /// Rejects ambiguous repository coordinates and nil durable identities.
    pub fn new(
        actor: ManagementActor,
        repository_owner: impl Into<String>,
        repository_name: impl Into<String>,
        source_run_id: RunId,
        selection: WorkflowRerunSelection,
        operation_id: OperationId,
    ) -> Result<Self, WorkflowRerunValueError> {
        let repository_owner = repository_owner.into();
        let repository_name = repository_name.into();
        if !valid_repository_segment(&repository_owner)
            || !valid_repository_segment(&repository_name)
        {
            return Err(WorkflowRerunValueError::InvalidRepositoryCoordinate);
        }
        validate_request_tail(source_run_id, selection, operation_id)?;
        Ok(Self {
            actor,
            repository_owner,
            repository_name,
            source_run_id,
            selection,
            operation_id,
        })
    }

    /// Returns the caller that must be transactionally reauthorized.
    #[must_use]
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    /// Returns the exact parsed repository-owner spelling.
    #[must_use]
    pub fn repository_owner(&self) -> &str {
        &self.repository_owner
    }

    /// Returns the exact parsed repository-name spelling.
    #[must_use]
    pub fn repository_name(&self) -> &str {
        &self.repository_name
    }

    /// Returns the terminal physical attempt selected as the rerun source.
    #[must_use]
    pub const fn source_run_id(&self) -> RunId {
        self.source_run_id
    }

    /// Returns the immutable selection mode.
    #[must_use]
    pub const fn selection(&self) -> WorkflowRerunSelection {
        self.selection
    }

    /// Returns the caller-supplied idempotency operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    #[cfg(feature = "adapter-spi")]
    pub(crate) fn into_resolved(
        self,
        repository_id: RepositoryId,
    ) -> Result<RerunWorkflow, WorkflowRerunValueError> {
        RerunWorkflow::new(
            self.actor,
            repository_id,
            self.source_run_id,
            self.selection,
            self.operation_id,
        )
    }
}

fn valid_repository_segment(value: &str) -> bool {
    !value.is_empty()
        && !matches!(value, "." | "..")
        && workflow_rerun_repository_segment_byte_rejection(value.len()).is_none()
        && !value.contains('/')
        && value
            .chars()
            .all(|character| !character.is_control() && !character.is_whitespace())
}

fn validate_request_tail(
    source_run_id: RunId,
    selection: WorkflowRerunSelection,
    operation_id: OperationId,
) -> Result<(), WorkflowRerunValueError> {
    for (value, field) in [
        (source_run_id.as_uuid(), "source workflow run ID"),
        (operation_id.as_uuid(), "workflow rerun operation ID"),
    ] {
        if value.is_nil() {
            return Err(WorkflowRerunValueError::NilUuid(field));
        }
    }
    if let WorkflowRerunSelection::JobAndDependents(job_id) = selection
        && job_id.as_uuid().is_nil()
    {
        return Err(WorkflowRerunValueError::NilUuid("selected logical job ID"));
    }
    Ok(())
}

/// Stable receipt for a newly created physical attempt or exact replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkflowRerunReceipt {
    source_run_id: RunId,
    run_id: RunId,
    public_run_id: u64,
    run_number: u64,
    run_attempt: u32,
    replayed: bool,
}

impl WorkflowRerunReceipt {
    /// Constructs a validated rerun receipt returned by a durable adapter.
    ///
    /// # Errors
    ///
    /// Rejects nil IDs and non-positive public/run attempt identities.
    pub fn new(
        source_run_id: RunId,
        run_id: RunId,
        public_run_id: u64,
        run_number: u64,
        run_attempt: u32,
        replayed: bool,
    ) -> Result<Self, WorkflowRerunValueError> {
        if source_run_id.as_uuid().is_nil() || run_id.as_uuid().is_nil() {
            return Err(WorkflowRerunValueError::NilUuid(
                "workflow rerun receipt ID",
            ));
        }
        if public_run_id == 0 || run_number == 0 || run_attempt == 0 {
            return Err(WorkflowRerunValueError::InvalidReceipt);
        }
        Ok(Self {
            source_run_id,
            run_id,
            public_run_id,
            run_number,
            run_attempt,
            replayed,
        })
    }

    /// Returns the physical terminal attempt used as source evidence.
    #[must_use]
    pub const fn source_run_id(self) -> RunId {
        self.source_run_id
    }

    /// Returns the newly created physical workflow-run identity.
    #[must_use]
    pub const fn run_id(self) -> RunId {
        self.run_id
    }

    /// Returns the stable provider-visible `GITHUB_RUN_ID` value.
    #[must_use]
    pub const fn public_run_id(self) -> u64 {
        self.public_run_id
    }

    /// Returns the stable provider-visible workflow run number.
    #[must_use]
    pub const fn run_number(self) -> u64 {
        self.run_number
    }

    /// Returns the new one-based provider-visible run attempt.
    #[must_use]
    pub const fn run_attempt(self) -> u32 {
        self.run_attempt
    }

    /// Reports whether the durable operation was an exact idempotent replay.
    #[must_use]
    pub const fn is_replay(self) -> bool {
        self.replayed
    }
}

/// Durable workflow rerun boundary.
#[async_trait]
pub trait WorkflowRerunRepository: fmt::Debug + Send + Sync {
    /// Requests a rerun from this repository implementation.
    ///
    /// An implementation that supports reruns must reauthorize the current
    /// actor, record an audit event, and atomically create one new physical
    /// attempt grouped with attempt one and one fresh provider Check subject.
    async fn rerun_workflow(
        &self,
        request: RerunWorkflow,
    ) -> Result<WorkflowRerunReceipt, WorkflowRerunStoreError>;

    /// Resolves a human-facing GitHub coordinate and requests its rerun.
    ///
    /// Resolution, current `runs:rerun` reauthorization, idempotency, and
    /// admission must share one transaction. Missing and unauthorized
    /// coordinates both return [`WorkflowRerunStoreError::AuthorityRejected`].
    async fn rerun_workflow_by_name(
        &self,
        request: RerunWorkflowByName,
    ) -> Result<WorkflowRerunReceipt, WorkflowRerunStoreError>;
}

/// Invalid workflow-rerun request or receipt value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkflowRerunValueError {
    /// A durable UUID used the nil sentinel.
    #[error("{0} must not be the nil UUID")]
    NilUuid(&'static str),
    /// A human-facing repository coordinate was ambiguous or unbounded.
    #[error("workflow rerun repository must be a bounded OWNER/REPOSITORY coordinate")]
    InvalidRepositoryCoordinate,
    /// An adapter returned an invalid positive provider-visible identity.
    #[error("workflow rerun receipt contains an invalid positive identity")]
    InvalidReceipt,
}

/// Closed failures for durable workflow-rerun admission.
#[derive(Debug, Error)]
pub enum WorkflowRerunStoreError {
    /// The backing durable store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Current `runs:rerun` authorization did not hold, or a named repository
    /// was absent; named admission deliberately combines both states.
    #[error("workflow rerun authority was rejected")]
    AuthorityRejected,
    /// The exact repository/run tuple was absent or outside the caller tenant.
    #[error("workflow rerun source was not found")]
    NotFound,
    /// The source physical attempt was not terminal and complete.
    #[error("workflow rerun source is not terminal")]
    SourceNotTerminal,
    /// The source terminal result is beyond the repository-time retention horizon.
    #[error("workflow rerun source is older than the retention horizon")]
    SourceExpired,
    /// The grouped provider-visible run exhausted its physical attempt budget.
    #[error("workflow rerun attempt limit is exhausted")]
    AttemptLimitReached,
    /// The requested exact closure cannot be safely carried forward.
    #[error("workflow rerun selection is unsupported by immutable source evidence")]
    UnsupportedSelection,
    /// The source workflow's bounded concurrency group has no available slot.
    #[error("workflow rerun concurrency queue is full")]
    ConcurrencyQueueFull,
    /// The operation ID was already committed for a non-identical request.
    #[error("workflow rerun operation conflicts with an existing request")]
    IdempotencyConflict,
}

#[cfg(test)]
mod tests {
    use super::*;
    use automata_ci_auth::{
        human::{PrincipalId, TenantId},
        management::ManagementRevision,
        session::SessionId,
        time::UnixTimestamp,
    };
    use uuid::Uuid;

    #[test]
    fn request_rejects_nil_repository_id() {
        let actor = ManagementActor::new(
            TenantId::new("tenant").expect("tenant"),
            PrincipalId::new(Uuid::from_u128(7).hyphenated().to_string()).expect("principal"),
            SessionId::new(Uuid::from_u128(8).hyphenated().to_string()).expect("session"),
            ManagementRevision::new(1).expect("revision"),
            None,
            UnixTimestamp::from_seconds(0),
        );
        let repository_id = RepositoryId::from_uuid(Uuid::nil());
        let source_run_id = RunId::from_uuid(Uuid::from_u128(2));
        let operation_id = OperationId::from_uuid(Uuid::from_u128(3));

        assert_eq!(
            RerunWorkflow::new(
                actor,
                repository_id,
                source_run_id,
                WorkflowRerunSelection::EntireWorkflow,
                operation_id,
            ),
            Err(WorkflowRerunValueError::NilUuid("repository ID"))
        );
    }

    #[test]
    fn named_request_accepts_exact_bounds_and_rejects_ambiguous_segments() {
        let actor = ManagementActor::new(
            TenantId::new("tenant").expect("tenant"),
            PrincipalId::new(Uuid::from_u128(7).hyphenated().to_string()).expect("principal"),
            SessionId::new(Uuid::from_u128(8).hyphenated().to_string()).expect("session"),
            ManagementRevision::new(1).expect("revision"),
            None,
            UnixTimestamp::from_seconds(0),
        );
        let source_run_id = RunId::from_uuid(Uuid::from_u128(2));
        let operation_id = OperationId::from_uuid(Uuid::from_u128(3));
        let bounded = "r".repeat(MAX_WORKFLOW_RERUN_REPOSITORY_SEGMENT_BYTES);
        let request = RerunWorkflowByName::new(
            actor.clone(),
            "Automata-CI",
            bounded.clone(),
            source_run_id,
            WorkflowRerunSelection::EntireWorkflow,
            operation_id,
        )
        .expect("bounded coordinate");
        assert_eq!(request.repository_owner(), "Automata-CI");
        assert_eq!(request.repository_name(), bounded);

        let oversized = "o".repeat(MAX_WORKFLOW_RERUN_REPOSITORY_SEGMENT_BYTES + 1);
        for (owner, name) in [
            ("", "repository"),
            ("owner", ""),
            ("owner/other", "repository"),
            ("owner", "repository/other"),
            (".", "repository"),
            ("owner", ".."),
            ("owner name", "repository"),
            ("owner", "repository\nname"),
            (oversized.as_str(), "repository"),
        ] {
            assert_eq!(
                RerunWorkflowByName::new(
                    actor.clone(),
                    owner,
                    name,
                    source_run_id,
                    WorkflowRerunSelection::EntireWorkflow,
                    operation_id,
                ),
                Err(WorkflowRerunValueError::InvalidRepositoryCoordinate)
            );
        }
    }

    #[test]
    fn receipt_rejects_zero_provider_visible_identities() {
        let source = RunId::from_uuid(Uuid::from_u128(1));
        let rerun = RunId::from_uuid(Uuid::from_u128(2));
        assert_eq!(
            WorkflowRerunReceipt::new(source, rerun, 0, 1, 1, false),
            Err(WorkflowRerunValueError::InvalidReceipt)
        );
        assert_eq!(
            WorkflowRerunReceipt::new(source, rerun, 1, 1, 0, false),
            Err(WorkflowRerunValueError::InvalidReceipt)
        );
    }

    #[test]
    fn fifty_rerun_limit_is_exact_at_minus_one_at_and_plus_one() {
        assert_eq!(
            next_workflow_rerun_attempt(MAX_WORKFLOW_RERUN_ATTEMPTS - 1),
            Some(MAX_WORKFLOW_RERUN_ATTEMPTS),
            "attempt 50 must admit the final (50th) rerun",
        );
        assert_eq!(
            next_workflow_rerun_attempt(MAX_WORKFLOW_RERUN_ATTEMPTS),
            None,
            "attempt 51 has consumed the 50-rerun budget",
        );
        assert_eq!(
            next_workflow_rerun_attempt(MAX_WORKFLOW_RERUN_ATTEMPTS + 1),
            None,
            "a malformed future attempt cannot reopen the budget",
        );
    }

    #[test]
    fn workflow_rerun_age_limit_has_exact_boundaries() {
        assert_eq!(
            workflow_rerun_age_rejection(MAX_WORKFLOW_RERUN_AGE_MILLIS - 1),
            None
        );
        assert_eq!(
            workflow_rerun_age_rejection(MAX_WORKFLOW_RERUN_AGE_MILLIS),
            None
        );
        assert_eq!(
            workflow_rerun_age_rejection(MAX_WORKFLOW_RERUN_AGE_MILLIS + 1),
            Some(WorkflowRerunLimitRejection::AgeMillis)
        );
    }

    #[test]
    fn workflow_rerun_repository_segment_byte_limit_has_exact_boundaries() {
        assert_eq!(
            workflow_rerun_repository_segment_byte_rejection(
                MAX_WORKFLOW_RERUN_REPOSITORY_SEGMENT_BYTES - 1
            ),
            None
        );
        assert_eq!(
            workflow_rerun_repository_segment_byte_rejection(
                MAX_WORKFLOW_RERUN_REPOSITORY_SEGMENT_BYTES
            ),
            None
        );
        assert_eq!(
            workflow_rerun_repository_segment_byte_rejection(
                MAX_WORKFLOW_RERUN_REPOSITORY_SEGMENT_BYTES + 1
            ),
            Some(WorkflowRerunLimitRejection::RepositorySegmentBytes)
        );
    }
}
