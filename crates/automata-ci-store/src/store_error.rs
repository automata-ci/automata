use automata_ci_core::{
    AttemptId, JobId, OperationId, RunId, RunnerId, RunnerSessionId, UnixMillis,
};
use thiserror::Error;

use crate::{
    AttemptStoreError, CommandCursor, RepositoryOperationError, RunnerGeneration,
    RunnerPayloadTombstone, StableRunnerSlot,
};

/// Backend-neutral failures shared by G1 durability ports.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error(transparent)]
    Attempt(#[from] AttemptStoreError),
    #[error(transparent)]
    Operation(#[from] RepositoryOperationError),
    #[error("durable data violated an Automata invariant: {0}")]
    CorruptData(String),
    #[error("runner {0} does not exist")]
    RunnerNotFound(RunnerId),
    #[error("runner {0} is disabled")]
    RunnerDisabled(RunnerId),
    #[error("runner {0} is not accepting new work")]
    RunnerNotAcceptingWork(RunnerId),
    #[error("runner {0} supplied an invalid observed capability snapshot")]
    InvalidCapabilitySnapshot(RunnerId),
    #[error("runner {runner_id} generation is {actual:?}, not expected generation {expected:?}")]
    RunnerGenerationMismatch {
        runner_id: RunnerId,
        expected: RunnerGeneration,
        actual: RunnerGeneration,
    },
    #[error("runner {0} exhausted its durable session epoch")]
    SessionEpochExhausted(RunnerId),
    #[error("runner session {0} does not exist")]
    SessionNotFound(RunnerSessionId),
    #[error("runner session {0} is no longer live")]
    SessionClosed(RunnerSessionId),
    #[error("runner session {0} does not match its authenticated fence")]
    SessionFenceRejected(RunnerSessionId),
    #[error(
        "mutation for runner session {session_id} was observed at {observed_at:?}, before durable time {durable_at:?}"
    )]
    SessionTimeRegression {
        session_id: RunnerSessionId,
        observed_at: UnixMillis,
        durable_at: UnixMillis,
    },
    #[error("runner session {session_id} slot {slot:?} is outside registered capacity")]
    SlotOutOfRange {
        session_id: RunnerSessionId,
        slot: StableRunnerSlot,
    },
    #[error("runner operation {operation_id} in session {session_id} reused a different request")]
    OperationConflict {
        session_id: RunnerSessionId,
        operation_id: OperationId,
    },
    #[error("runner session {0} exhausted its server-command sequence")]
    CommandSequenceExhausted(RunnerSessionId),
    #[error("runner payload encryption is not configured")]
    RunnerPayloadEncryptionUnavailable,
    #[error("runner session {session_id} payload is intentionally unavailable: {tombstone:?}")]
    RunnerPayloadUnavailable {
        session_id: RunnerSessionId,
        tombstone: RunnerPayloadTombstone,
    },
    #[error("runner session {session_id} acknowledged cursor {requested:?} beyond {available:?}")]
    CommandCursorAhead {
        session_id: RunnerSessionId,
        requested: CommandCursor,
        available: CommandCursor,
    },
    #[error(
        "runner session {session_id} resumed from cursor {requested:?} behind durable cursor {durable:?}"
    )]
    CommandCursorBehind {
        session_id: RunnerSessionId,
        requested: CommandCursor,
        durable: CommandCursor,
    },
    #[error("active attempt {0} cancellation requires a durable delivery command")]
    CancellationDeliveryRequired(AttemptId),
    #[error("attempt {0} cancellation command targets a different runner session")]
    CancellationDeliveryMismatch(AttemptId),
    #[error("attempt {0} does not exist")]
    AttemptNotFound(AttemptId),
    #[error("job {0} does not exist")]
    JobNotFound(JobId),
    #[error("workflow run {0} does not exist")]
    RunNotFound(RunId),
    #[error(
        "workflow run {run_id} reconciliation at {observed_at:?} predates durable state at {updated_at:?}"
    )]
    RunTimeRegression {
        run_id: RunId,
        observed_at: UnixMillis,
        updated_at: UnixMillis,
    },
    #[error("attempt {attempt_id} exhausted its durable fencing-token range")]
    FencingTokenExhausted { attempt_id: AttemptId },
    #[error(
        "attempt {attempt_id} mutation at {observed_at:?} predates durable state at {changed_at:?}"
    )]
    AttemptTimeRegression {
        attempt_id: AttemptId,
        observed_at: UnixMillis,
        changed_at: UnixMillis,
    },
    #[error("attempt {0} rejected a stale lease/session fence")]
    AttemptFenceRejected(AttemptId),
    #[error("immutable metadata already exists with different contents for {0}")]
    ImmutableConflict(&'static str),
}

impl StoreError {
    #[must_use]
    pub fn operation(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        RepositoryOperationError::from_source(source).into()
    }

    #[must_use]
    pub fn corrupt_data(message: impl Into<String>) -> Self {
        Self::CorruptData(message.into())
    }

    pub(crate) fn generation_mismatch(
        runner_id: RunnerId,
        expected: RunnerGeneration,
        actual: RunnerGeneration,
    ) -> Self {
        Self::RunnerGenerationMismatch {
            runner_id,
            expected,
            actual,
        }
    }

    pub(crate) fn fence_rejected(session_id: RunnerSessionId) -> Self {
        Self::SessionFenceRejected(session_id)
    }

    pub(crate) fn epoch_exhausted(runner_id: RunnerId) -> Self {
        Self::SessionEpochExhausted(runner_id)
    }

    pub(crate) fn invalid_session_epoch(value: i64) -> Self {
        Self::corrupt_data(format!("invalid runner session epoch {value}"))
    }

    pub(crate) fn invalid_generation(value: i64) -> Self {
        Self::corrupt_data(format!("invalid runner generation {value}"))
    }

    pub(crate) fn invalid_operation_receipt(message: impl Into<String>) -> Self {
        Self::corrupt_data(format!(
            "invalid runner operation receipt: {}",
            message.into()
        ))
    }
}
