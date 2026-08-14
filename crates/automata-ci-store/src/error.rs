use std::error::Error;

use automata_ci_core::{AttemptId, JobLifecycle, LeaseError, UnixMillis};
use thiserror::Error;

use crate::AttemptAssignmentError;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AttemptCommandError {
    #[error("lease expiration must be strictly later than trusted observation time")]
    InvalidLeaseInterval,
    #[error("queued attempts may only be concluded as cancelled or skipped, not {0:?}")]
    InvalidQueuedConclusion(JobLifecycle),
}

/// Why a backend could not construct a valid portable attempt snapshot.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AttemptSnapshotError {
    #[error("snapshot changed at {changed_at:?}, before it was queued at {queued_at:?}")]
    ChangedBeforeQueued {
        queued_at: UnixMillis,
        changed_at: UnixMillis,
    },
    #[error("active lifecycle {0:?} requires a complete lease")]
    ActiveLifecycleMissingLease(JobLifecycle),
    #[error("active lifecycle {0:?} requires a runner-session slot assignment")]
    ActiveLifecycleMissingAssignment(JobLifecycle),
    #[error("inactive lifecycle {0:?} cannot retain an active lease")]
    InactiveLifecycleHasLease(JobLifecycle),
    #[error("inactive lifecycle {0:?} cannot retain a runner-session slot assignment")]
    InactiveLifecycleHasAssignment(JobLifecycle),
    #[error("active lease is invalid: {0}")]
    InvalidLease(#[source] LeaseError),
    #[error(
        "active lease belongs to attempt {lease_attempt_id}, not snapshot attempt {snapshot_attempt_id}"
    )]
    LeaseAttemptMismatch {
        snapshot_attempt_id: AttemptId,
        lease_attempt_id: AttemptId,
    },
    #[error("active lease and runner-session assignment are inconsistent: {0}")]
    InvalidAssignment(#[source] AttemptAssignmentError),
    #[error("active lease was issued at {issued_at:?}, before queuing at {queued_at:?}")]
    LeaseIssuedBeforeQueued {
        queued_at: UnixMillis,
        issued_at: UnixMillis,
    },
    #[error("snapshot changed at {changed_at:?}, before active lease issuance at {issued_at:?}")]
    ChangedBeforeLeaseIssuance {
        issued_at: UnixMillis,
        changed_at: UnixMillis,
    },
    #[error(
        "snapshot changed at {changed_at:?}, at or after active lease expiration {expires_at:?}"
    )]
    ChangedOutsideLease {
        changed_at: UnixMillis,
        expires_at: UnixMillis,
    },
}

/// A backend failure retained for diagnostics behind a portable error surface.
///
/// Its display text is deliberately stable and sanitized. Operators can still
/// inspect the type-erased [`Error::source`] chain in trusted logs, while API
/// handlers and alternative adapters do not depend on a concrete storage
/// driver's error type.
#[derive(Debug, Error)]
#[error("attempt repository operation failed")]
pub struct RepositoryOperationError {
    #[source]
    source: Box<dyn Error + Send + Sync + 'static>,
}

impl RepositoryOperationError {
    /// Erases a concrete backend error without exposing it in display output.
    #[must_use]
    pub fn from_source(source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            source: Box::new(source),
        }
    }
}

#[derive(Debug, Error)]
pub enum AttemptStoreError {
    #[error(transparent)]
    Operation(#[from] RepositoryOperationError),
    #[error("durable data violated an Automata snapshot invariant: {0}")]
    InvalidSnapshot(#[from] AttemptSnapshotError),
    #[error("durable data violated an Automata domain invariant: {0}")]
    CorruptData(String),
    #[error("attempt {0} does not exist")]
    NotFound(AttemptId),
    #[error("attempt {attempt_id} is {lifecycle:?}, not queued")]
    NotQueued {
        attempt_id: AttemptId,
        lifecycle: JobLifecycle,
    },
    #[error("attempt {0} exhausted its durable fencing-token range")]
    FencingTokenExhausted(AttemptId),
    #[error("the lease credential for attempt {0} is stale or does not match")]
    FenceRejected(AttemptId),
    #[error("the authenticated runner does not own the lease for attempt {0}")]
    RunnerRejected(AttemptId),
    #[error("attempt {attempt_id} cannot transition from {from:?} to {to:?}")]
    InvalidTransition {
        attempt_id: AttemptId,
        from: JobLifecycle,
        to: JobLifecycle,
    },
    #[error("lease renewal for attempt {0} must strictly extend its expiration")]
    RenewalDoesNotExtend(AttemptId),
    /// The runtime authority needed by this fenced attempt is no longer usable.
    #[error("runtime authority for attempt {0} is no longer usable")]
    RuntimeAuthorityUnavailable(AttemptId),
    /// A proposed renewal would outlive the runtime authority delivered to the job.
    #[error("lease renewal for attempt {0} exceeds its runtime-authority ceiling")]
    RuntimeAuthorityCeilingExceeded(AttemptId),
    #[error("the lease for attempt {0} had expired when the mutation was observed")]
    LeaseExpired(AttemptId),
    #[error(
        "mutation for attempt {attempt_id} was observed at {observed_at:?}, before its durable state changed at {changed_at:?}"
    )]
    MutationPredatesState {
        attempt_id: AttemptId,
        observed_at: UnixMillis,
        changed_at: UnixMillis,
    },
    #[error("maximum lease failures must be at least one")]
    InvalidRetryPolicy,
}

impl AttemptStoreError {
    /// Creates a sanitized, backend-neutral operation failure.
    #[must_use]
    pub fn operation(source: impl Error + Send + Sync + 'static) -> Self {
        RepositoryOperationError::from_source(source).into()
    }

    /// Reports malformed durable data that cannot be represented by the
    /// strongly typed snapshot builder.
    #[must_use]
    pub fn corrupt_data(message: impl Into<String>) -> Self {
        Self::CorruptData(message.into())
    }
}
