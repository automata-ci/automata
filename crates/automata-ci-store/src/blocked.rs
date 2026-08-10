use async_trait::async_trait;
use automata_ci_core::{AttemptId, JobId, JobLifecycle, RunId, UnixMillis};

use crate::{RunnableScanLimit, StoreError};

/// Queued work whose complete latest-prerequisite set contains a terminal
/// non-success conclusion and therefore cannot satisfy default `success()`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockedAttempt {
    attempt_id: AttemptId,
    job_id: JobId,
    run_id: RunId,
    queued_at: UnixMillis,
}

impl BlockedAttempt {
    #[must_use]
    pub const fn new(
        attempt_id: AttemptId,
        job_id: JobId,
        run_id: RunId,
        queued_at: UnixMillis,
    ) -> Self {
        Self {
            attempt_id,
            job_id,
            run_id,
            queued_at,
        }
    }

    #[must_use]
    pub const fn attempt_id(self) -> AttemptId {
        self.attempt_id
    }

    #[must_use]
    pub const fn job_id(self) -> JobId {
        self.job_id
    }

    #[must_use]
    pub const fn run_id(self) -> RunId {
        self.run_id
    }

    #[must_use]
    pub const fn queued_at(self) -> UnixMillis {
        self.queued_at
    }
}

/// Transactional request to apply default-success skip propagation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConcludeBlockedAttempt {
    attempt_id: AttemptId,
    observed_at: UnixMillis,
}

impl ConcludeBlockedAttempt {
    #[must_use]
    pub const fn new(attempt_id: AttemptId, observed_at: UnixMillis) -> Self {
        Self {
            attempt_id,
            observed_at,
        }
    }

    #[must_use]
    pub const fn attempt_id(self) -> AttemptId {
        self.attempt_id
    }

    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }
}

/// Result after re-checking dependency state under durable locks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockedConclusion {
    Skipped,
    AlreadySkipped,
    NotQueued(JobLifecycle),
    NoLongerBlocked,
}

/// Default-success dependency reconciliation port.
///
/// Run cancellation or a non-active run state takes precedence over skip
/// propagation. Within an active run, terminal dependency failure takes
/// precedence over concurrency admission, because a blocked job can never use
/// a concurrency slot. Only the latest attempt of every prerequisite counts.
#[async_trait]
pub trait BlockedAttemptRepository: Send + Sync {
    /// Finds deterministic candidates. The transactional conclusion must
    /// re-check every gate because prerequisite retries can race this scan.
    async fn scan_blocked(
        &self,
        limit: RunnableScanLimit,
        observed_at: UnixMillis,
    ) -> Result<Vec<BlockedAttempt>, StoreError>;

    /// Marks a still-blocked queued attempt as skipped after locking its run,
    /// prerequisite jobs, and latest prerequisite attempts.
    async fn conclude_blocked(
        &self,
        request: ConcludeBlockedAttempt,
    ) -> Result<BlockedConclusion, StoreError>;
}
