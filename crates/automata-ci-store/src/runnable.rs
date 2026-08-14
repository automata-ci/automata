use std::num::NonZeroU16;

use async_trait::async_trait;
use automata_ci_core::{AttemptId, JobId, RunId, RunnerRequirements, Sha256Digest, UnixMillis};
use thiserror::Error;

use crate::{JobIrMetadata, RunnerSessionFence, StableRunnerSlot, StoreError};

/// Maximum records returned by one scheduler queue scan.
pub const MAX_RUNNABLE_SCAN_LIMIT: u16 = 1000;

/// Bounded scheduler scan size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunnableScanLimit(NonZeroU16);

impl RunnableScanLimit {
    /// Creates a scan size in `1..=1000`.
    ///
    /// # Errors
    ///
    /// Rejects zero and unbounded scans.
    pub fn new(value: u16) -> Result<Self, RunnableScanError> {
        if value > MAX_RUNNABLE_SCAN_LIMIT {
            return Err(RunnableScanError::InvalidLimit);
        }
        NonZeroU16::new(value)
            .map(Self)
            .ok_or(RunnableScanError::InvalidLimit)
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

/// Authoritative request for one runner slot's next bounded queue page.
///
/// Tenant, selected `JobIR` version, routing fingerprint, and cursor state are
/// deliberately absent. A storage adapter derives them from the live session
/// fence and its server-owned runner registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunnableScanRequest {
    session: RunnerSessionFence,
    slot: StableRunnerSlot,
    limit: RunnableScanLimit,
    observed_at: UnixMillis,
}

impl RunnableScanRequest {
    #[must_use]
    pub const fn new(
        session: RunnerSessionFence,
        slot: StableRunnerSlot,
        limit: RunnableScanLimit,
        observed_at: UnixMillis,
    ) -> Self {
        Self {
            session,
            slot,
            limit,
            observed_at,
        }
    }

    #[must_use]
    pub const fn session(self) -> RunnerSessionFence {
        self.session
    }

    #[must_use]
    pub const fn slot(self) -> StableRunnerSlot {
        self.slot
    }

    #[must_use]
    pub const fn limit(self) -> RunnableScanLimit {
        self.limit
    }

    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }
}

/// Stable keyset position in the runnable FIFO.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RunnableQueueKey {
    queued_at: UnixMillis,
    attempt_id: AttemptId,
}

impl RunnableQueueKey {
    #[must_use]
    pub const fn new(queued_at: UnixMillis, attempt_id: AttemptId) -> Self {
        Self {
            queued_at,
            attempt_id,
        }
    }

    #[must_use]
    pub const fn queued_at(self) -> UnixMillis {
        self.queued_at
    }

    #[must_use]
    pub const fn attempt_id(self) -> AttemptId {
        self.attempt_id
    }
}

/// Opaque compare-and-swap proof for advancing one durable scan cursor.
///
/// This value is neither serializable nor accepted from a runner transport.
/// It can only be obtained from [`RunnableScanPage`] after an authoritative
/// storage scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunnableCursorAdvance {
    session: RunnerSessionFence,
    slot: StableRunnerSlot,
    routing_fingerprint: Sha256Digest,
    expected_version: u64,
    through: Option<RunnableQueueKey>,
    cycle_upper: Option<RunnableQueueKey>,
}

impl RunnableCursorAdvance {
    pub(crate) const fn session(self) -> RunnerSessionFence {
        self.session
    }

    pub(crate) const fn slot(self) -> StableRunnerSlot {
        self.slot
    }

    #[cfg(feature = "adapter-spi")]
    pub(crate) const fn routing_fingerprint(self) -> Sha256Digest {
        self.routing_fingerprint
    }

    #[cfg(feature = "adapter-spi")]
    pub(crate) const fn expected_version(self) -> u64 {
        self.expected_version
    }

    pub(crate) const fn through(self) -> Option<RunnableQueueKey> {
        self.through
    }

    #[cfg(feature = "adapter-spi")]
    pub(crate) const fn cycle_upper(self) -> Option<RunnableQueueKey> {
        self.cycle_upper
    }
}

/// Repository-derived candidate whose run, cancellation, concurrency, queue,
/// and default-success dependency gates all passed at scan time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnableAttempt {
    attempt_id: AttemptId,
    job_id: JobId,
    run_id: RunId,
    queued_at: UnixMillis,
    requirements: RunnerRequirements,
    ir_metadata: JobIrMetadata,
}

impl RunnableAttempt {
    /// Builds a scheduler candidate from one internally consistent job plan.
    ///
    /// # Errors
    ///
    /// Rejects mismatched `JobIR` identity.
    pub fn try_new(
        attempt_id: AttemptId,
        job_id: JobId,
        run_id: RunId,
        queued_at: UnixMillis,
        requirements: RunnerRequirements,
        ir_metadata: JobIrMetadata,
    ) -> Result<Self, RunnableAttemptError> {
        if ir_metadata.job_id() != job_id {
            return Err(RunnableAttemptError::JobMetadataMismatch);
        }
        if ir_metadata.run_id() != run_id {
            return Err(RunnableAttemptError::RunMetadataMismatch);
        }
        Ok(Self {
            attempt_id,
            job_id,
            run_id,
            queued_at,
            requirements,
            ir_metadata,
        })
    }

    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    #[must_use]
    pub const fn queued_at(&self) -> UnixMillis {
        self.queued_at
    }

    #[must_use]
    pub const fn queue_key(&self) -> RunnableQueueKey {
        RunnableQueueKey::new(self.queued_at, self.attempt_id)
    }

    #[must_use]
    pub const fn requirements(&self) -> &RunnerRequirements {
        &self.requirements
    }

    #[must_use]
    pub const fn job_ir(&self) -> &JobIrMetadata {
        &self.ir_metadata
    }
}

/// One bounded queue page and the opaque proof needed to commit progress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnableScanPage {
    candidates: Vec<RunnableAttempt>,
    cursor: RunnableCursorAdvance,
}

impl RunnableScanPage {
    /// Constructs a page at a storage-adapter boundary.
    ///
    /// The candidates must be strictly ordered and no candidate may exceed the
    /// finite cycle high-water mark. Cursor versions use the signed 64-bit
    /// storage boundary.
    ///
    /// # Errors
    ///
    /// Rejects unordered candidates, invalid cursor versions, or candidates
    /// outside the cycle.
    pub fn try_new(
        session: RunnerSessionFence,
        slot: StableRunnerSlot,
        routing_fingerprint: Sha256Digest,
        expected_version: u64,
        cycle_upper: Option<RunnableQueueKey>,
        candidates: Vec<RunnableAttempt>,
    ) -> Result<Self, RunnableScanError> {
        if expected_version >= i64::MAX as u64 {
            return Err(RunnableScanError::InvalidCursorVersion);
        }
        let mut prior = None;
        for candidate in &candidates {
            let key = candidate.queue_key();
            if prior.is_some_and(|value| key <= value) {
                return Err(RunnableScanError::CandidatesNotOrdered);
            }
            if cycle_upper.is_none_or(|upper| key > upper) {
                return Err(RunnableScanError::CandidateOutsideCycle);
            }
            prior = Some(key);
        }
        let through = prior.or(cycle_upper);
        Ok(Self {
            candidates,
            cursor: RunnableCursorAdvance {
                session,
                slot,
                routing_fingerprint,
                expected_version,
                through,
                cycle_upper,
            },
        })
    }

    #[must_use]
    pub fn candidates(&self) -> &[RunnableAttempt] {
        &self.candidates
    }

    #[must_use]
    pub const fn expected_cursor_version(&self) -> u64 {
        self.cursor.expected_version
    }

    /// Produces a compact proof that advances through one selected candidate.
    ///
    /// # Errors
    ///
    /// Rejects an attempt that was not present in this page.
    pub fn claim_advance(
        &self,
        attempt_id: AttemptId,
    ) -> Result<RunnableCursorAdvance, RunnableScanError> {
        let through = self
            .candidates
            .iter()
            .find(|candidate| candidate.attempt_id() == attempt_id)
            .map(RunnableAttempt::queue_key)
            .ok_or(RunnableScanError::CandidateNotInPage)?;
        Ok(RunnableCursorAdvance {
            through: Some(through),
            ..self.cursor
        })
    }

    /// Advances through every candidate inspected for a no-work decision.
    #[must_use]
    pub const fn no_work_advance(&self) -> RunnableCursorAdvance {
        self.cursor
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RunnableScanError {
    #[error("runnable scan limit must be in 1..=1000")]
    InvalidLimit,
    #[error("runnable cursor version exceeds durable range")]
    InvalidCursorVersion,
    #[error("runnable page candidates are not strictly queue ordered")]
    CandidatesNotOrdered,
    #[error("runnable page candidate exceeds its cycle high-water mark")]
    CandidateOutsideCycle,
    #[error("selected attempt is not in the scanned runnable page")]
    CandidateNotInPage,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RunnableAttemptError {
    #[error("runnable attempt and JobIR metadata identify different jobs")]
    JobMetadataMismatch,
    #[error("runnable attempt and JobIR metadata identify different runs")]
    RunMetadataMismatch,
}

/// Authoritative scheduler queue port. Claims/no-work receipts atomically
/// commit the opaque cursor advancement returned with a page.
#[async_trait]
pub trait RunnableAttemptRepository: Send + Sync {
    async fn scan_runnable(
        &self,
        request: RunnableScanRequest,
    ) -> Result<RunnableScanPage, StoreError>;
}
