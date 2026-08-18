//! Runnable-queue scan values and opaque cursor proofs.

use std::num::{NonZeroU16, NonZeroU64};

use automata_ci_core::{
    AttemptId, JobAuthorityProfile, JobId, RunId, RunnerRequirements, Sha256Digest,
    TrustAuthorityDecision, TrustSnapshot, TrustSourceClass, UnixMillis,
};
use automata_ci_store::{JobIrMetadata, RunnerSessionFence, StableRunnerSlot};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Maximum records returned by one scheduler queue scan.
const MAX_RUNNABLE_SCAN_LIMIT: u16 = 1000;

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

    /// Returns the validated scan size.
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
    /// Creates a bounded authoritative scan request.
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

    /// Returns the authenticated runner-session fence.
    #[must_use]
    pub const fn session(self) -> RunnerSessionFence {
        self.session
    }

    /// Returns the stable runner slot requesting work.
    #[must_use]
    pub const fn slot(self) -> StableRunnerSlot {
        self.slot
    }

    /// Returns the maximum queue records to scan.
    #[must_use]
    pub const fn limit(self) -> RunnableScanLimit {
        self.limit
    }

    /// Returns the trusted scan observation time.
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
    /// Creates a stable FIFO keyset position.
    #[must_use]
    pub const fn new(queued_at: UnixMillis, attempt_id: AttemptId) -> Self {
        Self {
            queued_at,
            attempt_id,
        }
    }

    /// Returns the queue time component.
    #[must_use]
    pub const fn queued_at(self) -> UnixMillis {
        self.queued_at
    }

    /// Returns the attempt identity component.
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
    /// Returns the exact session fence.
    #[must_use]
    pub(crate) const fn session(self) -> RunnerSessionFence {
        self.session
    }

    /// Returns the stable runner slot.
    #[must_use]
    pub(crate) const fn slot(self) -> StableRunnerSlot {
        self.slot
    }

    /// Returns the server-derived routing proof root.
    #[must_use]
    #[cfg(feature = "adapter-spi")]
    pub(crate) const fn routing_fingerprint(self) -> Sha256Digest {
        self.routing_fingerprint
    }

    /// Returns the compare-and-swap cursor version.
    #[must_use]
    #[cfg(feature = "adapter-spi")]
    pub(crate) const fn expected_version(self) -> u64 {
        self.expected_version
    }

    /// Returns the inclusive queue position scanned through.
    #[must_use]
    pub(crate) const fn through(self) -> Option<RunnableQueueKey> {
        self.through
    }

    /// Returns the finite scan-cycle upper bound, if established.
    #[must_use]
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
    placement_trust: Option<AuthenticatedPlacementTrust>,
}

/// Compact authenticated trust root used only for pre-lease placement.
///
/// The value is constructed from a fully decoded canonical [`TrustSnapshot`]
/// plus immutable logical-materialization evidence. It deliberately carries no
/// raw event facts, secret values, or externally supplied signature bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedPlacementTrust {
    snapshot_schema: u16,
    policy_revision: NonZeroU64,
    policy_digest: Sha256Digest,
    snapshot_digest: Sha256Digest,
    source: TrustSourceClass,
    authority: TrustAuthorityDecision,
    evidence_complete: bool,
    authority_profile: JobAuthorityProfile,
    requirements_digest: Sha256Digest,
}

impl AuthenticatedPlacementTrust {
    /// Derives compact placement evidence from one canonical trust snapshot.
    ///
    /// # Errors
    ///
    /// Rejects the local construction placeholder, which is never durable
    /// authenticated evidence.
    pub fn try_new(
        snapshot: &TrustSnapshot,
        authority_profile: JobAuthorityProfile,
        requirements: &RunnerRequirements,
    ) -> Result<Self, RunnableAttemptError> {
        if snapshot.is_construction_placeholder() {
            return Err(RunnableAttemptError::UnauthenticatedPlacementTrust);
        }
        let requirements_digest = placement_requirements_digest(requirements)?;
        Ok(Self {
            snapshot_schema: snapshot.schema(),
            policy_revision: snapshot.policy_revision(),
            policy_digest: snapshot.policy_digest(),
            snapshot_digest: snapshot.digest(),
            source: snapshot.source_class(),
            authority: snapshot.authority(),
            evidence_complete: snapshot.evidence_complete(),
            authority_profile,
            requirements_digest,
        })
    }

    /// Returns the canonical trust-snapshot schema.
    #[must_use]
    pub const fn snapshot_schema(&self) -> u16 {
        self.snapshot_schema
    }

    /// Returns the pinned trust-policy revision.
    #[must_use]
    pub const fn policy_revision(&self) -> NonZeroU64 {
        self.policy_revision
    }

    /// Returns the pinned trust-policy digest.
    #[must_use]
    pub const fn policy_digest(&self) -> Sha256Digest {
        self.policy_digest
    }

    /// Returns the canonical snapshot digest.
    #[must_use]
    pub const fn snapshot_digest(&self) -> Sha256Digest {
        self.snapshot_digest
    }

    /// Returns the authenticated source classification.
    #[must_use]
    pub const fn source(&self) -> TrustSourceClass {
        self.source
    }

    /// Returns the shared authority decision.
    #[must_use]
    pub const fn authority(&self) -> TrustAuthorityDecision {
        self.authority
    }

    /// Reports whether all event-specific trust facts were authenticated.
    #[must_use]
    pub const fn evidence_complete(&self) -> bool {
        self.evidence_complete
    }

    /// Returns the immutable job authority profile.
    #[must_use]
    pub const fn authority_profile(&self) -> JobAuthorityProfile {
        self.authority_profile
    }

    /// Returns the immutable logical requirements digest.
    #[must_use]
    pub const fn requirements_digest(&self) -> Sha256Digest {
        self.requirements_digest
    }
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
        placement_trust: Option<AuthenticatedPlacementTrust>,
    ) -> Result<Self, RunnableAttemptError> {
        if ir_metadata.job_id() != job_id {
            return Err(RunnableAttemptError::JobMetadataMismatch);
        }
        if ir_metadata.run_id() != run_id {
            return Err(RunnableAttemptError::RunMetadataMismatch);
        }
        if let Some(trust) = placement_trust.as_ref()
            && trust.requirements_digest() != placement_requirements_digest(&requirements)?
        {
            return Err(RunnableAttemptError::PlacementRequirementsMismatch);
        }
        Ok(Self {
            attempt_id,
            job_id,
            run_id,
            queued_at,
            requirements,
            ir_metadata,
            placement_trust,
        })
    }

    /// Returns the runnable attempt identity.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the owning job identity.
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    /// Returns the owning workflow-run identity.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Returns the durable queue time.
    #[must_use]
    pub const fn queued_at(&self) -> UnixMillis {
        self.queued_at
    }

    /// Returns the stable FIFO keyset position.
    #[must_use]
    pub const fn queue_key(&self) -> RunnableQueueKey {
        RunnableQueueKey::new(self.queued_at, self.attempt_id)
    }

    /// Returns the runner requirements used for routing.
    #[must_use]
    pub const fn requirements(&self) -> &RunnerRequirements {
        &self.requirements
    }

    /// Returns the selected job intermediate-representation metadata.
    #[must_use]
    pub const fn job_ir(&self) -> &JobIrMetadata {
        &self.ir_metadata
    }

    /// Returns authenticated pre-lease trust evidence when the durable job has it.
    #[must_use]
    pub const fn placement_trust(&self) -> Option<&AuthenticatedPlacementTrust> {
        self.placement_trust.as_ref()
    }
}

fn placement_requirements_digest(
    requirements: &RunnerRequirements,
) -> Result<Sha256Digest, RunnableAttemptError> {
    let value = serde_json::to_value(requirements)
        .map_err(|_| RunnableAttemptError::InvalidPlacementRequirements)?;
    let bytes = serde_json::to_vec(&value)
        .map_err(|_| RunnableAttemptError::InvalidPlacementRequirements)?;
    Ok(Sha256Digest::from_bytes(Sha256::digest(bytes).into()))
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

    /// Returns the strictly ordered runnable candidates.
    #[must_use]
    pub fn candidates(&self) -> &[RunnableAttempt] {
        &self.candidates
    }

    /// Returns the cursor version expected by the page.
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

/// Invalid runnable scan request, page, or cursor advancement.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RunnableScanError {
    /// The requested scan limit is zero or exceeds the maximum.
    #[error("runnable scan limit must be in 1..=1000")]
    InvalidLimit,
    /// The cursor version exceeds the signed durable-storage range.
    #[error("runnable cursor version exceeds durable range")]
    InvalidCursorVersion,
    /// Page candidates are not strictly FIFO ordered.
    #[error("runnable page candidates are not strictly queue ordered")]
    CandidatesNotOrdered,
    /// A page candidate exceeds the finite scan-cycle upper bound.
    #[error("runnable page candidate exceeds its cycle high-water mark")]
    CandidateOutsideCycle,
    /// The selected attempt is absent from the authoritative page.
    #[error("selected attempt is not in the scanned runnable page")]
    CandidateNotInPage,
}

/// Inconsistent identity in a runnable attempt projection.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RunnableAttemptError {
    /// The candidate and job metadata identify different jobs.
    #[error("runnable attempt and JobIR metadata identify different jobs")]
    JobMetadataMismatch,
    /// The candidate and job metadata identify different workflow runs.
    #[error("runnable attempt and JobIR metadata identify different runs")]
    RunMetadataMismatch,
    /// A local construction placeholder was presented as authenticated trust.
    #[error("runnable placement trust is not authenticated durable evidence")]
    UnauthenticatedPlacementTrust,
    /// Runner requirements could not be represented by the canonical JSON shape.
    #[error("runnable placement requirements cannot be encoded canonically")]
    InvalidPlacementRequirements,
    /// Materialization trust was derived for different runner requirements.
    #[error("runnable placement trust does not bind the current runner requirements")]
    PlacementRequirementsMismatch,
}
