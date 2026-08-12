//! Autonomous finalization of complete logical workflow runs.

use std::{sync::Arc, time::Duration};

use automata_ci_core::UnixMillis;
use automata_ci_store::{
    ClaimLogicalRunFinalization, CommitLogicalRunFinalization, LogicalRunFinalizationReceipt,
    LogicalRunFinalizationRepository, LogicalRunFinalizationStoreError,
    LogicalRunFinalizationValueError, LogicalRunFinalizationWorkerId, StoreError,
};
use thiserror::Error;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

use crate::AdmissionClock;

/// Duration requested for one autonomous run-finalization claim.
pub const LOGICAL_RUN_FINALIZATION_CLAIM_MILLIS: i64 = 5 * 60 * 1_000;
const IDLE_POLL_MILLIS: u64 = 250;
const RETRY_BASE_MILLIS: u64 = 100;
const RETRY_CAP_MILLIS: u64 = 1_600;
const COMMIT_OPERATION_TIMEOUT_MILLIS: u64 = 30_000;
const COMMIT_CANCELLATION_DRAIN_MILLIS: u64 = 1_000;
const MAX_CLAIM_OPERATION_FAILURES: u8 = 5;
const MAX_COMMIT_ATTEMPTS: u8 = 4;

/// Result of one bounded run-finalization poll.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LogicalRunFinalizationOutcome {
    /// No complete unlocked run was available.
    Idle,
    /// A claim expired or lost its fence before commit and may be retried.
    FenceLost,
    /// One complete run was durably finalized, newly or by exact replay.
    Finalized(LogicalRunFinalizationReceipt),
}

/// Exact value-free commit retained after an indeterminate repository outcome.
///
/// Retaining this request is required for exact replay: starting a fresh global
/// claim cannot observe a commit that may already have finalized the run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingLogicalRunFinalizationCommit {
    request: CommitLogicalRunFinalization,
}

impl PendingLogicalRunFinalizationCommit {
    fn new(request: CommitLogicalRunFinalization) -> Self {
        Self { request }
    }

    /// Returns the exact commit request that must be replayed unchanged.
    #[must_use]
    pub const fn request(&self) -> &CommitLogicalRunFinalization {
        &self.request
    }
}

/// Cancellation-aware worker for complete logical-run aggregation.
#[derive(Clone, Debug)]
pub struct LogicalRunFinalizationService {
    repository: Arc<dyn LogicalRunFinalizationRepository>,
    clock: Arc<dyn AdmissionClock>,
    worker: LogicalRunFinalizationWorkerId,
}

impl LogicalRunFinalizationService {
    /// Composes a worker over the durable finalization repository.
    #[must_use]
    pub const fn new(
        repository: Arc<dyn LogicalRunFinalizationRepository>,
        clock: Arc<dyn AdmissionClock>,
        worker: LogicalRunFinalizationWorkerId,
    ) -> Self {
        Self {
            repository,
            clock,
            worker,
        }
    }

    /// Claims and finalizes at most one complete root invocation.
    ///
    /// # Errors
    ///
    /// Returns a sanitized clock, value, storage, or cancellation failure. If
    /// cancellation arrives after a claim is acquired, the error retains the
    /// exact pending commit even if repository I/O has not started.
    pub async fn run_once(
        &self,
        shutdown: CancellationToken,
    ) -> Result<LogicalRunFinalizationOutcome, LogicalRunFinalizationError> {
        if shutdown.is_cancelled() {
            return Err(LogicalRunFinalizationError::Shutdown);
        }
        let observed_at = trusted_now(self.clock.as_ref())?;
        let expires_at = claim_expiration(observed_at)?;
        let claim = ClaimLogicalRunFinalization::new(self.worker, observed_at, expires_at)
            .map_err(LogicalRunFinalizationError::Value)?;
        let claimed = tokio::select! {
            () = shutdown.cancelled() => return Err(LogicalRunFinalizationError::Shutdown),
            result = self.repository.claim_logical_run_finalization(claim) => result?,
        };
        let Some(claimed) = claimed else {
            return Ok(LogicalRunFinalizationOutcome::Idle);
        };
        let claim_duration = claimed
            .claim()
            .expires_at()
            .get()
            .checked_sub(claimed.claim().claimed_at().get());
        if claimed.claim().owner() != self.worker
            || claim_duration != Some(LOGICAL_RUN_FINALIZATION_CLAIM_MILLIS)
        {
            return Err(LogicalRunFinalizationError::ClaimMismatch);
        }

        // The repository may replace caller wall time with its authoritative
        // database clock. Its issued claim start is therefore the only clock
        // value this layer can safely bind into the exact commit digest.
        let finalized_at = claimed.claim().claimed_at();
        let commit = CommitLogicalRunFinalization::new(&claimed, finalized_at)
            .map_err(LogicalRunFinalizationError::Value)?;
        self.commit_exact(commit, &shutdown).await
    }

    /// Replays a previously indeterminate commit without taking a new claim.
    ///
    /// # Errors
    ///
    /// Returns a sanitized repository failure, a mismatched-worker error, or a
    /// new pending value if the exact outcome remains indeterminate.
    pub async fn resume_pending_commit(
        &self,
        pending: &PendingLogicalRunFinalizationCommit,
        shutdown: CancellationToken,
    ) -> Result<LogicalRunFinalizationOutcome, LogicalRunFinalizationError> {
        if pending.request.claim().owner() != self.worker {
            return Err(LogicalRunFinalizationError::ClaimMismatch);
        }
        self.commit_exact(pending.request.clone(), &shutdown).await
    }

    /// Polls until local cancellation or the first non-retryable failure.
    ///
    /// Idle polls and lost fences use the same bounded cancellation-aware
    /// delay; successful commits immediately continue draining ready work. If
    /// a commit has been dispatched, this continuous worker retains and
    /// replays its exact request without cancellation until the repository
    /// classifies it. Shutdown therefore stops new claims but may wait for an
    /// unavailable repository rather than discard commit custody.
    ///
    /// # Errors
    ///
    /// Returns the first sanitized non-retryable worker failure. Cancellation
    /// completes normally before a claim is acquired and while a claim or idle
    /// wait is in flight. After a claim is acquired, this method does not
    /// surface a pending-custody error; it drains that exact commit to a
    /// classified outcome first.
    pub async fn run(
        &self,
        shutdown: CancellationToken,
    ) -> Result<(), LogicalRunFinalizationError> {
        let mut consecutive_claim_failures = 0_u8;
        loop {
            if shutdown.is_cancelled() {
                return Ok(());
            }
            let poll = match self.run_once(shutdown.child_token()).await {
                Err(
                    LogicalRunFinalizationError::CommitIndeterminate(pending)
                    | LogicalRunFinalizationError::ReceiptMismatch(pending),
                ) => {
                    let outcome = self.drain_pending_commit(*pending).await?;
                    if shutdown.is_cancelled() {
                        return Ok(());
                    }
                    Ok(outcome)
                }
                other => other,
            };
            let delay = match poll {
                Ok(LogicalRunFinalizationOutcome::Finalized(_)) => {
                    consecutive_claim_failures = 0;
                    tokio::task::yield_now().await;
                    None
                }
                Ok(
                    LogicalRunFinalizationOutcome::Idle | LogicalRunFinalizationOutcome::FenceLost,
                ) => {
                    consecutive_claim_failures = 0;
                    Some(Duration::from_millis(IDLE_POLL_MILLIS))
                }
                Err(LogicalRunFinalizationError::Shutdown) if shutdown.is_cancelled() => {
                    return Ok(());
                }
                Err(error) if error.is_retryable_claim_operation() => {
                    consecutive_claim_failures = consecutive_claim_failures.saturating_add(1);
                    if consecutive_claim_failures >= MAX_CLAIM_OPERATION_FAILURES {
                        return Err(error);
                    }
                    Some(retry_delay(consecutive_claim_failures))
                }
                Err(error) => return Err(error),
            };
            if let Some(delay) = delay {
                tokio::select! {
                    () = shutdown.cancelled() => return Ok(()),
                    () = sleep(delay) => {}
                }
            }
        }
    }

    async fn drain_pending_commit(
        &self,
        pending: PendingLogicalRunFinalizationCommit,
    ) -> Result<LogicalRunFinalizationOutcome, LogicalRunFinalizationError> {
        loop {
            match self
                .resume_pending_commit(&pending, CancellationToken::new())
                .await
            {
                Err(
                    LogicalRunFinalizationError::CommitIndeterminate(_)
                    | LogicalRunFinalizationError::ReceiptMismatch(_),
                ) => sleep(retry_delay(MAX_COMMIT_ATTEMPTS)).await,
                outcome => return outcome,
            }
        }
    }

    async fn commit_exact(
        &self,
        request: CommitLogicalRunFinalization,
        shutdown: &CancellationToken,
    ) -> Result<LogicalRunFinalizationOutcome, LogicalRunFinalizationError> {
        for attempt in 1..=MAX_COMMIT_ATTEMPTS {
            if shutdown.is_cancelled() {
                return Err(LogicalRunFinalizationError::CommitIndeterminate(Box::new(
                    PendingLogicalRunFinalizationCommit::new(request),
                )));
            }
            let operation = self
                .repository
                .commit_logical_run_finalization(request.clone());
            tokio::pin!(operation);
            let operation_timeout = sleep(Duration::from_millis(COMMIT_OPERATION_TIMEOUT_MILLIS));
            tokio::pin!(operation_timeout);
            let result = tokio::select! {
                result = &mut operation => Some(result),
                () = &mut operation_timeout => None,
                () = shutdown.cancelled() => {
                    let drain = sleep(Duration::from_millis(
                        COMMIT_CANCELLATION_DRAIN_MILLIS,
                    ));
                    tokio::pin!(drain);
                    tokio::select! {
                        result = &mut operation => Some(result),
                        () = &mut drain => {
                            return Err(LogicalRunFinalizationError::CommitIndeterminate(
                                Box::new(PendingLogicalRunFinalizationCommit::new(request)),
                            ));
                        }
                    }
                }
            };
            match result {
                Some(Ok(receipt)) => {
                    let expected =
                        LogicalRunFinalizationReceipt::new(&request, receipt.is_replay());
                    if receipt != expected {
                        return Err(LogicalRunFinalizationError::ReceiptMismatch(Box::new(
                            PendingLogicalRunFinalizationCommit::new(request),
                        )));
                    }
                    return Ok(LogicalRunFinalizationOutcome::Finalized(receipt));
                }
                Some(Err(LogicalRunFinalizationStoreError::ClaimRejected)) => {
                    return Ok(LogicalRunFinalizationOutcome::FenceLost);
                }
                Some(Err(LogicalRunFinalizationStoreError::Store(StoreError::Operation(_))))
                | None => {}
                Some(Err(error)) => return Err(LogicalRunFinalizationError::Store(error)),
            }
            if attempt == MAX_COMMIT_ATTEMPTS || shutdown.is_cancelled() {
                return Err(LogicalRunFinalizationError::CommitIndeterminate(Box::new(
                    PendingLogicalRunFinalizationCommit::new(request),
                )));
            }
            tokio::select! {
                () = shutdown.cancelled() => {
                    return Err(LogicalRunFinalizationError::CommitIndeterminate(
                        Box::new(PendingLogicalRunFinalizationCommit::new(request)),
                    ));
                }
                () = sleep(retry_delay(attempt)) => {}
            }
        }
        unreachable!("the positive bounded commit-attempt loop always returns")
    }
}

/// Sanitized autonomous run-finalization failure.
#[derive(Debug, Error)]
pub enum LogicalRunFinalizationError {
    /// The trusted clock returned a negative, regressed, or overflowing value.
    #[error("trusted run-finalization time is invalid")]
    InvalidTimestamp,
    /// Repository-issued claim evidence did not match this worker request.
    #[error("logical run-finalization claim did not match its request")]
    ClaimMismatch,
    /// The worker was cancelled before completing its current operation.
    #[error("logical run-finalization worker was cancelled")]
    Shutdown,
    /// An exact commit may have succeeded and must be replayed, not replaced.
    #[error("logical run-finalization commit outcome is indeterminate")]
    CommitIndeterminate(Box<PendingLogicalRunFinalizationCommit>),
    /// A repository receipt did not authenticate the exact submitted commit.
    #[error("logical run-finalization receipt did not match its commit")]
    ReceiptMismatch(Box<PendingLogicalRunFinalizationCommit>),
    /// Store-authenticated value validation failed.
    #[error(transparent)]
    Value(#[from] LogicalRunFinalizationValueError),
    /// Durable storage rejected or failed the operation.
    #[error("logical run-finalization storage operation failed")]
    Store(#[from] LogicalRunFinalizationStoreError),
}

impl LogicalRunFinalizationError {
    const fn is_retryable_claim_operation(&self) -> bool {
        matches!(
            self,
            Self::Store(LogicalRunFinalizationStoreError::Store(
                StoreError::Operation(_)
            ))
        )
    }
}

fn retry_delay(failure: u8) -> Duration {
    let shift = u32::from(failure.saturating_sub(1).min(4));
    Duration::from_millis(
        RETRY_BASE_MILLIS
            .saturating_mul(1_u64 << shift)
            .min(RETRY_CAP_MILLIS),
    )
}

fn trusted_now(clock: &dyn AdmissionClock) -> Result<UnixMillis, LogicalRunFinalizationError> {
    let value = clock.now();
    if value.get() < 0 {
        return Err(LogicalRunFinalizationError::InvalidTimestamp);
    }
    Ok(value)
}

fn claim_expiration(observed_at: UnixMillis) -> Result<UnixMillis, LogicalRunFinalizationError> {
    observed_at
        .get()
        .checked_add(LOGICAL_RUN_FINALIZATION_CLAIM_MILLIS)
        .map(UnixMillis::new)
        .ok_or(LogicalRunFinalizationError::InvalidTimestamp)
}
