//! Domain and schema boundary for authenticated workflow-rerun requests.
//!
//! The schema can retain immutable rerun provenance, but reruns are not yet
//! executable: the current `PostgreSQL` adapter returns
//! [`WorkflowRerunStoreError::Unsupported`] before authorization, provider
//! access, or durable writes. A future executable adapter must create a fresh
//! physical attempt, preserve source and provider-visible identity, and
//! reauthorize the current caller in the same transaction as its audit record.

use std::fmt;

use async_trait::async_trait;
use automata_ci_auth::management::ManagementActor;
use automata_ci_core::{OperationId, RunId};
use thiserror::Error;

use crate::{LogicalWorkflowJobId, RepositoryId, StoreError};

/// Maximum physical attempts retained for one provider-visible workflow run.
pub const MAX_WORKFLOW_RERUN_ATTEMPTS: u32 = 50;
/// Database-time retention horizon for starting a rerun of a terminal run.
pub const MAX_WORKFLOW_RERUN_AGE_MILLIS: i64 = 30 * 24 * 60 * 60 * 1_000;

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
/// source run and idempotency receipt rows, then record it as the new attempt's
/// triggering actor and security-audit subject. The current `PostgreSQL`
/// adapter deliberately fails closed before that work.
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
    /// attempt grouped with attempt one. Implementations without a complete
    /// activation path return [`WorkflowRerunStoreError::Unsupported`] before
    /// observing authority or writing state.
    async fn rerun_workflow(
        &self,
        request: RerunWorkflow,
    ) -> Result<WorkflowRerunReceipt, WorkflowRerunStoreError>;
}

/// Invalid workflow-rerun request or receipt value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkflowRerunValueError {
    /// A durable UUID used the nil sentinel.
    #[error("{0} must not be the nil UUID")]
    NilUuid(&'static str),
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
    /// Current `runs:rerun` authorization did not hold in the transaction.
    #[error("workflow rerun authority was rejected")]
    AuthorityRejected,
    /// The exact repository/run tuple was absent or outside the caller tenant.
    #[error("workflow rerun source was not found")]
    NotFound,
    /// The source physical attempt was not terminal and complete.
    #[error("workflow rerun source is not terminal")]
    SourceNotTerminal,
    /// The source terminal result is beyond the database-time retention horizon.
    #[error("workflow rerun source is older than the retention horizon")]
    SourceExpired,
    /// The grouped provider-visible run exhausted its physical attempt budget.
    #[error("workflow rerun attempt limit is exhausted")]
    AttemptLimitReached,
    /// The requested exact closure cannot be safely carried forward.
    #[error("workflow rerun selection is unsupported by immutable source evidence")]
    UnsupportedSelection,
    /// Workflow reruns are not yet executable by the durable adapter.
    ///
    /// The schema retains immutable rerun and carry-forward evidence, but the
    /// current activation and admission fences do not yet consume it. Stores
    /// must return this state before any durable write or mutable provider
    /// lookup rather than admitting an attempt that cannot execute correctly.
    #[error("workflow reruns are not implemented by this store")]
    Unsupported,
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
}
