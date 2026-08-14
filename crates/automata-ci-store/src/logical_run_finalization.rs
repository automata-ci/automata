//! Fenced logical workflow run finalization over immutable logical-job results.
//!
//! The repository selects one ready root invocation with `SKIP LOCKED`, returns
//! a bounded canonical snapshot of every finalized logical-job result, and
//! accepts only an exact live fence when closing the run aggregate.

use std::{collections::BTreeSet, fmt, num::NonZeroU64};

use async_trait::async_trait;
use automata_ci_core::{
    JobConclusion, MAX_LOGICAL_JOB_NEEDS, MAX_LOGICAL_JOB_OUTPUTS, MAX_LOGICAL_JOBS, RunId,
    Sha256Digest, UnixMillis, WorkflowJobKey,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{LogicalWorkflowInvocationId, LogicalWorkflowJobId, StoreError, TenantScope};

/// Maximum duration of one run-finalization claim.
pub const MAX_LOGICAL_RUN_FINALIZATION_CLAIM_MILLIS: i64 = 15 * 60 * 1_000;

const EVIDENCE_DOMAIN: &[u8] = b"automata.store.logical-run-finalization-evidence.v1\0";
const DESCRIPTOR_DOMAIN: &[u8] = b"automata.store.logical-run-finalization-descriptor.v1\0";
const COMMIT_DOMAIN: &[u8] = b"automata.store.logical-run-finalization-commit.v1\0";

/// Non-nil durable identity of one run-finalization worker.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalRunFinalizationWorkerId(Uuid);

impl LogicalRunFinalizationWorkerId {
    /// Constructs a non-nil worker identity.
    ///
    /// # Errors
    ///
    /// Rejects the nil UUID sentinel.
    pub fn from_uuid(value: Uuid) -> Result<Self, LogicalRunFinalizationValueError> {
        if value.is_nil() {
            return Err(LogicalRunFinalizationValueError::NilUuid(
                "logical run-finalization worker ID",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the underlying UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

/// Positive monotonic generation of one run-finalization claim.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalRunFinalizationGeneration(NonZeroU64);

impl LogicalRunFinalizationGeneration {
    /// Constructs a positive generation within the signed 64-bit storage boundary.
    ///
    /// # Errors
    ///
    /// Rejects zero and values larger than `i64::MAX`.
    pub fn new(value: u64) -> Result<Self, LogicalRunFinalizationValueError> {
        let value = NonZeroU64::new(value)
            .filter(|value| i64::try_from(value.get()).is_ok())
            .ok_or(LogicalRunFinalizationValueError::InvalidGeneration)?;
        Ok(Self(value))
    }

    /// Returns the numeric generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Exact tenant-scoped root invocation selected for run finalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalRunFinalizationTarget {
    tenant: TenantScope,
    run_id: RunId,
    root_invocation_id: LogicalWorkflowInvocationId,
}

impl LogicalRunFinalizationTarget {
    /// Constructs an exact current root-invocation target.
    ///
    /// # Errors
    ///
    /// Rejects a nil workflow-run identity.
    pub fn new(
        tenant: TenantScope,
        run_id: RunId,
        root_invocation_id: LogicalWorkflowInvocationId,
    ) -> Result<Self, LogicalRunFinalizationValueError> {
        if run_id.as_uuid().is_nil() {
            return Err(LogicalRunFinalizationValueError::NilUuid("workflow run ID"));
        }
        Ok(Self {
            tenant,
            run_id,
            root_invocation_id,
        })
    }

    /// Returns the authenticated tenant scope.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }

    /// Returns the workflow-run identity.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Returns the exact root-invocation identity.
    #[must_use]
    pub const fn root_invocation_id(&self) -> LogicalWorkflowInvocationId {
        self.root_invocation_id
    }
}

/// Request to claim at most one ready run with `SKIP LOCKED` semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimLogicalRunFinalization {
    owner: LogicalRunFinalizationWorkerId,
    observed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl ClaimLogicalRunFinalization {
    /// Constructs one bounded global claim request.
    ///
    /// # Errors
    ///
    /// Rejects a negative time, empty interval, or interval over fifteen minutes.
    pub fn new(
        owner: LogicalRunFinalizationWorkerId,
        observed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, LogicalRunFinalizationValueError> {
        validate_claim_interval(observed_at, expires_at)?;
        Ok(Self {
            owner,
            observed_at,
            expires_at,
        })
    }

    /// Returns the stable worker identity.
    #[must_use]
    pub const fn owner(&self) -> LogicalRunFinalizationWorkerId {
        self.owner
    }

    /// Returns the trusted claim observation time.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }

    /// Returns the requested claim expiration.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
}

/// Open lifecycle state pinned by a run-finalization descriptor.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LogicalRunFinalizationOpenState {
    /// Admitted but not explicitly marked active.
    Pending,
    /// Execution or orchestration has begun.
    Active,
}

/// Workflow-run status pinned before logical finalization.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LogicalRunFinalizationWorkflowStatus {
    /// The aggregate has not begun visible execution.
    Queued,
    /// At least one part of the aggregate has begun execution.
    InProgress,
    /// Repository concurrency or another trusted server action cancelled the
    /// run before logical aggregation finished.
    Cancelled,
}

/// Exact immutable logical-job result evidence contributing to a run result.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct LogicalRunJobResultEvidence {
    logical_job_id: LogicalWorkflowJobId,
    logical_key: WorkflowJobKey,
    source_order: u16,
    descriptor_digest: Sha256Digest,
    effective_conclusion: JobConclusion,
    closure_has_failure: bool,
    closure_has_cancelled: bool,
    closure_has_skipped: bool,
    instance_count: u32,
    instances_digest: Sha256Digest,
    prerequisite_count: u32,
    prerequisites_digest: Sha256Digest,
    output_count: u32,
    outputs_digest: Sha256Digest,
    commit_digest: Sha256Digest,
    finalized_at: UnixMillis,
}

impl LogicalRunJobResultEvidence {
    /// Rehydrates one complete immutable logical-job result record.
    ///
    /// # Errors
    ///
    /// Rejects out-of-range counts/order, inconsistent closure evidence, or a
    /// timestamp before the Unix epoch.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        logical_job_id: LogicalWorkflowJobId,
        logical_key: WorkflowJobKey,
        source_order: u16,
        descriptor_digest: Sha256Digest,
        effective_conclusion: JobConclusion,
        closure_has_failure: bool,
        closure_has_cancelled: bool,
        closure_has_skipped: bool,
        instance_count: u32,
        instances_digest: Sha256Digest,
        prerequisite_count: u32,
        prerequisites_digest: Sha256Digest,
        output_count: u32,
        outputs_digest: Sha256Digest,
        commit_digest: Sha256Digest,
        finalized_at: UnixMillis,
    ) -> Result<Self, LogicalRunFinalizationValueError> {
        if source_order > 1_023
            || instance_count > 256
            || usize::try_from(prerequisite_count).unwrap_or(usize::MAX) > MAX_LOGICAL_JOB_NEEDS
            || usize::try_from(output_count).unwrap_or(usize::MAX) > MAX_LOGICAL_JOB_OUTPUTS
        {
            return Err(LogicalRunFinalizationValueError::InvalidJobEvidence);
        }
        if (matches!(
            effective_conclusion,
            JobConclusion::Failure | JobConclusion::TimedOut
        ) && !closure_has_failure)
            || (effective_conclusion == JobConclusion::Cancelled && !closure_has_cancelled)
            || (effective_conclusion == JobConclusion::Skipped && !closure_has_skipped)
        {
            return Err(LogicalRunFinalizationValueError::InvalidJobEvidence);
        }
        validate_timestamp(finalized_at, "logical-job result finalization time")?;
        Ok(Self {
            logical_job_id,
            logical_key,
            source_order,
            descriptor_digest,
            effective_conclusion,
            closure_has_failure,
            closure_has_cancelled,
            closure_has_skipped,
            instance_count,
            instances_digest,
            prerequisite_count,
            prerequisites_digest,
            output_count,
            outputs_digest,
            commit_digest,
            finalized_at,
        })
    }

    /// Returns the logical-job identity.
    #[must_use]
    pub const fn logical_job_id(&self) -> LogicalWorkflowJobId {
        self.logical_job_id
    }
    /// Returns the canonical logical key.
    #[must_use]
    pub const fn logical_key(&self) -> &WorkflowJobKey {
        &self.logical_key
    }
    /// Returns the source order.
    #[must_use]
    pub const fn source_order(&self) -> u16 {
        self.source_order
    }
    /// Returns the logical-job descriptor digest.
    #[must_use]
    pub const fn descriptor_digest(&self) -> Sha256Digest {
        self.descriptor_digest
    }
    /// Returns the job conclusion.
    #[must_use]
    pub const fn effective_conclusion(&self) -> JobConclusion {
        self.effective_conclusion
    }
    /// Reports failure in the job's transitive closure.
    #[must_use]
    pub const fn closure_has_failure(&self) -> bool {
        self.closure_has_failure
    }
    /// Reports cancellation in the job's transitive closure.
    #[must_use]
    pub const fn closure_has_cancelled(&self) -> bool {
        self.closure_has_cancelled
    }
    /// Reports a skip in the job's transitive closure.
    #[must_use]
    pub const fn closure_has_skipped(&self) -> bool {
        self.closure_has_skipped
    }
    /// Returns the exact instance count.
    #[must_use]
    pub const fn instance_count(&self) -> u32 {
        self.instance_count
    }
    /// Returns the ordered instance-evidence digest.
    #[must_use]
    pub const fn instances_digest(&self) -> Sha256Digest {
        self.instances_digest
    }
    /// Returns the exact prerequisite count.
    #[must_use]
    pub const fn prerequisite_count(&self) -> u32 {
        self.prerequisite_count
    }
    /// Returns the prerequisite-evidence digest.
    #[must_use]
    pub const fn prerequisites_digest(&self) -> Sha256Digest {
        self.prerequisites_digest
    }
    /// Returns the exact output count.
    #[must_use]
    pub const fn output_count(&self) -> u32 {
        self.output_count
    }
    /// Returns the logical output-set digest.
    #[must_use]
    pub const fn outputs_digest(&self) -> Sha256Digest {
        self.outputs_digest
    }
    /// Returns the exact logical-job commit digest.
    #[must_use]
    pub const fn commit_digest(&self) -> Sha256Digest {
        self.commit_digest
    }
    /// Returns the durable logical-job finalization time.
    #[must_use]
    pub const fn finalized_at(&self) -> UnixMillis {
        self.finalized_at
    }
}

/// Bounded exact descriptor for one ready current root invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalRunFinalizationDescriptor {
    target: LogicalRunFinalizationTarget,
    admission_digest: Sha256Digest,
    marker_state: LogicalRunFinalizationOpenState,
    marker_revision: u64,
    marker_updated_at: UnixMillis,
    invocation_state: LogicalRunFinalizationOpenState,
    invocation_revision: u64,
    invocation_updated_at: UnixMillis,
    workflow_status: LogicalRunFinalizationWorkflowStatus,
    workflow_updated_at: UnixMillis,
    jobs: Vec<LogicalRunJobResultEvidence>,
    evidence_digest: Sha256Digest,
    evidence_ready_at: UnixMillis,
    descriptor_digest: Sha256Digest,
}

impl LogicalRunFinalizationDescriptor {
    /// Rehydrates a complete current root-invocation result snapshot.
    ///
    /// Empty job sets are deliberately invalid: current logical admission
    /// requires at least one job, so treating zero records as vacuous readiness
    /// would turn durable-state corruption into a successful or skipped run.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, duplicated, noncanonical, or time-regressed evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target: LogicalRunFinalizationTarget,
        admission_digest: Sha256Digest,
        marker_state: LogicalRunFinalizationOpenState,
        marker_revision: u64,
        marker_updated_at: UnixMillis,
        invocation_state: LogicalRunFinalizationOpenState,
        invocation_revision: u64,
        invocation_updated_at: UnixMillis,
        workflow_status: LogicalRunFinalizationWorkflowStatus,
        workflow_updated_at: UnixMillis,
        mut jobs: Vec<LogicalRunJobResultEvidence>,
    ) -> Result<Self, LogicalRunFinalizationValueError> {
        if jobs.is_empty() {
            return Err(LogicalRunFinalizationValueError::EmptyJobSet);
        }
        if jobs.len() > MAX_LOGICAL_JOBS {
            return Err(LogicalRunFinalizationValueError::TooManyJobs);
        }
        validate_revision(marker_revision)?;
        validate_revision(invocation_revision)?;
        validate_timestamp(marker_updated_at, "orchestration marker update time")?;
        validate_timestamp(invocation_updated_at, "root invocation update time")?;
        validate_timestamp(workflow_updated_at, "workflow-run update time")?;
        jobs.sort_by_key(LogicalRunJobResultEvidence::source_order);
        let mut ids = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for (expected_order, job) in jobs.iter().enumerate() {
            if usize::from(job.source_order()) != expected_order
                || !ids.insert(job.logical_job_id())
                || !keys.insert(job.logical_key().clone())
            {
                return Err(LogicalRunFinalizationValueError::InvalidJobEvidence);
            }
        }
        let evidence_digest = evidence_digest(&jobs);
        let evidence_ready_at = jobs
            .iter()
            .map(LogicalRunJobResultEvidence::finalized_at)
            .chain([
                marker_updated_at,
                invocation_updated_at,
                workflow_updated_at,
            ])
            .max()
            .unwrap_or(workflow_updated_at);
        let descriptor_digest = descriptor_digest(
            &target,
            admission_digest,
            marker_state,
            marker_revision,
            marker_updated_at,
            invocation_state,
            invocation_revision,
            invocation_updated_at,
            workflow_status,
            workflow_updated_at,
            jobs.len(),
            evidence_digest,
            evidence_ready_at,
        );
        Ok(Self {
            target,
            admission_digest,
            marker_state,
            marker_revision,
            marker_updated_at,
            invocation_state,
            invocation_revision,
            invocation_updated_at,
            workflow_status,
            workflow_updated_at,
            jobs,
            evidence_digest,
            evidence_ready_at,
            descriptor_digest,
        })
    }

    /// Returns the exact target.
    #[must_use]
    pub const fn target(&self) -> &LogicalRunFinalizationTarget {
        &self.target
    }
    /// Returns the immutable admission digest.
    #[must_use]
    pub const fn admission_digest(&self) -> Sha256Digest {
        self.admission_digest
    }
    /// Returns the pinned marker state.
    #[must_use]
    pub const fn marker_state(&self) -> LogicalRunFinalizationOpenState {
        self.marker_state
    }
    /// Returns the pinned marker revision.
    #[must_use]
    pub const fn marker_revision(&self) -> u64 {
        self.marker_revision
    }
    /// Returns the pinned marker update time.
    #[must_use]
    pub const fn marker_updated_at(&self) -> UnixMillis {
        self.marker_updated_at
    }
    /// Returns the pinned invocation state.
    #[must_use]
    pub const fn invocation_state(&self) -> LogicalRunFinalizationOpenState {
        self.invocation_state
    }
    /// Returns the pinned invocation revision.
    #[must_use]
    pub const fn invocation_revision(&self) -> u64 {
        self.invocation_revision
    }
    /// Returns the pinned invocation update time.
    #[must_use]
    pub const fn invocation_updated_at(&self) -> UnixMillis {
        self.invocation_updated_at
    }
    /// Returns the pinned workflow status.
    #[must_use]
    pub const fn workflow_status(&self) -> LogicalRunFinalizationWorkflowStatus {
        self.workflow_status
    }
    /// Returns the pinned workflow update time.
    #[must_use]
    pub const fn workflow_updated_at(&self) -> UnixMillis {
        self.workflow_updated_at
    }
    /// Returns source-ordered complete logical-job evidence.
    #[must_use]
    pub fn jobs(&self) -> &[LogicalRunJobResultEvidence] {
        &self.jobs
    }
    /// Returns the exact logical-job count.
    #[must_use]
    pub fn job_count(&self) -> u32 {
        u32::try_from(self.jobs.len()).unwrap_or(u32::MAX)
    }
    /// Returns the digest of every ordered immutable logical-job result.
    #[must_use]
    pub const fn evidence_digest(&self) -> Sha256Digest {
        self.evidence_digest
    }
    /// Returns the latest time in the pinned mutable and immutable evidence.
    #[must_use]
    pub const fn evidence_ready_at(&self) -> UnixMillis {
        self.evidence_ready_at
    }
    /// Returns the canonical descriptor digest.
    #[must_use]
    pub const fn descriptor_digest(&self) -> Sha256Digest {
        self.descriptor_digest
    }
}

/// Exact live proof required to publish one logical run result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalRunFinalizationClaimFence {
    target: LogicalRunFinalizationTarget,
    owner: LogicalRunFinalizationWorkerId,
    generation: LogicalRunFinalizationGeneration,
    descriptor_digest: Sha256Digest,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl LogicalRunFinalizationClaimFence {
    /// Rehydrates repository-issued claim evidence.
    ///
    /// # Errors
    ///
    /// Rejects an invalid claim interval.
    pub fn new(
        target: LogicalRunFinalizationTarget,
        owner: LogicalRunFinalizationWorkerId,
        generation: LogicalRunFinalizationGeneration,
        descriptor_digest: Sha256Digest,
        claimed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, LogicalRunFinalizationValueError> {
        validate_claim_interval(claimed_at, expires_at)?;
        Ok(Self {
            target,
            owner,
            generation,
            descriptor_digest,
            claimed_at,
            expires_at,
        })
    }

    /// Returns the exact target.
    #[must_use]
    pub const fn target(&self) -> &LogicalRunFinalizationTarget {
        &self.target
    }
    /// Returns the stable claim owner.
    #[must_use]
    pub const fn owner(&self) -> LogicalRunFinalizationWorkerId {
        self.owner
    }
    /// Returns the monotonic generation.
    #[must_use]
    pub const fn generation(&self) -> LogicalRunFinalizationGeneration {
        self.generation
    }
    /// Returns the pinned descriptor digest.
    #[must_use]
    pub const fn descriptor_digest(&self) -> Sha256Digest {
        self.descriptor_digest
    }
    /// Returns the claim start time.
    #[must_use]
    pub const fn claimed_at(&self) -> UnixMillis {
        self.claimed_at
    }
    /// Returns the claim expiration time.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
}

/// Immutable run evidence returned under a live repository claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedLogicalRunFinalization {
    descriptor: LogicalRunFinalizationDescriptor,
    claim: LogicalRunFinalizationClaimFence,
}

impl ClaimedLogicalRunFinalization {
    /// Constructs exact claimed run evidence.
    ///
    /// # Errors
    ///
    /// Rejects a fence that does not bind the descriptor or starts before it is ready.
    pub fn new(
        descriptor: LogicalRunFinalizationDescriptor,
        claim: LogicalRunFinalizationClaimFence,
    ) -> Result<Self, LogicalRunFinalizationValueError> {
        if claim.target() != descriptor.target()
            || claim.descriptor_digest() != descriptor.descriptor_digest()
        {
            return Err(LogicalRunFinalizationValueError::ClaimDescriptorMismatch);
        }
        if claim.claimed_at() < descriptor.evidence_ready_at() {
            return Err(LogicalRunFinalizationValueError::ClaimBeforeEvidence);
        }
        Ok(Self { descriptor, claim })
    }

    /// Returns the exact store-authenticated descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &LogicalRunFinalizationDescriptor {
        &self.descriptor
    }
    /// Returns the live commit fence.
    #[must_use]
    pub const fn claim(&self) -> &LogicalRunFinalizationClaimFence {
        &self.claim
    }
}

/// Validated terminal run aggregate assembled from exact claimed evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitLogicalRunFinalization {
    descriptor: LogicalRunFinalizationDescriptor,
    claim: LogicalRunFinalizationClaimFence,
    conclusion: JobConclusion,
    commit_digest: Sha256Digest,
    finalized_at: UnixMillis,
}

impl CommitLogicalRunFinalization {
    /// Computes the closed aggregate and exact replay digest.
    ///
    /// A pre-terminal server cancellation is authoritative. Otherwise failure
    /// precedes timeout, timeout precedes job cancellation, a non-empty
    /// all-skipped set remains skipped, and every other complete set succeeds.
    ///
    /// # Errors
    ///
    /// Rejects a finalization time outside the live claim.
    pub fn new(
        claimed: &ClaimedLogicalRunFinalization,
        finalized_at: UnixMillis,
    ) -> Result<Self, LogicalRunFinalizationValueError> {
        if finalized_at < claimed.claim().claimed_at()
            || finalized_at >= claimed.claim().expires_at()
        {
            return Err(LogicalRunFinalizationValueError::CommitOutsideClaim);
        }
        let descriptor = claimed.descriptor().clone();
        let claim = claimed.claim().clone();
        let conclusion =
            if descriptor.workflow_status() == LogicalRunFinalizationWorkflowStatus::Cancelled {
                JobConclusion::Cancelled
            } else {
                aggregate_conclusion(descriptor.jobs())
            };
        let commit_digest = commit_digest(&claim, &descriptor, conclusion, finalized_at);
        Ok(Self {
            descriptor,
            claim,
            conclusion,
            commit_digest,
            finalized_at,
        })
    }

    /// Returns the exact descriptor used by the aggregation.
    #[must_use]
    pub const fn descriptor(&self) -> &LogicalRunFinalizationDescriptor {
        &self.descriptor
    }
    /// Returns the exact live claim proof.
    #[must_use]
    pub const fn claim(&self) -> &LogicalRunFinalizationClaimFence {
        &self.claim
    }
    /// Returns the closed run conclusion.
    #[must_use]
    pub const fn conclusion(&self) -> JobConclusion {
        self.conclusion
    }
    /// Returns the canonical exact-replay digest.
    #[must_use]
    pub const fn commit_digest(&self) -> Sha256Digest {
        self.commit_digest
    }
    /// Returns the trusted finalization time.
    #[must_use]
    pub const fn finalized_at(&self) -> UnixMillis {
        self.finalized_at
    }
}

/// Durable receipt for one immutable logical run result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalRunFinalizationReceipt {
    target: LogicalRunFinalizationTarget,
    descriptor_digest: Sha256Digest,
    job_count: u32,
    evidence_digest: Sha256Digest,
    conclusion: JobConclusion,
    commit_digest: Sha256Digest,
    finalized_at: UnixMillis,
    replayed: bool,
}

impl LogicalRunFinalizationReceipt {
    /// Constructs an exact receipt from a validated commit request.
    #[must_use]
    pub fn new(request: &CommitLogicalRunFinalization, replayed: bool) -> Self {
        Self {
            target: request.descriptor().target().clone(),
            descriptor_digest: request.descriptor().descriptor_digest(),
            job_count: request.descriptor().job_count(),
            evidence_digest: request.descriptor().evidence_digest(),
            conclusion: request.conclusion(),
            commit_digest: request.commit_digest(),
            finalized_at: request.finalized_at(),
            replayed,
        }
    }

    /// Rehydrates an authenticated durable receipt.
    ///
    /// # Errors
    ///
    /// Rejects an empty/oversized count or negative finalization time.
    #[allow(clippy::too_many_arguments)]
    pub fn from_durable(
        target: LogicalRunFinalizationTarget,
        descriptor_digest: Sha256Digest,
        job_count: u32,
        evidence_digest: Sha256Digest,
        conclusion: JobConclusion,
        commit_digest: Sha256Digest,
        finalized_at: UnixMillis,
        replayed: bool,
    ) -> Result<Self, LogicalRunFinalizationValueError> {
        if job_count == 0 || usize::try_from(job_count).unwrap_or(usize::MAX) > MAX_LOGICAL_JOBS {
            return Err(LogicalRunFinalizationValueError::InvalidDurableReceipt);
        }
        validate_timestamp(finalized_at, "logical run finalization time")?;
        Ok(Self {
            target,
            descriptor_digest,
            job_count,
            evidence_digest,
            conclusion,
            commit_digest,
            finalized_at,
            replayed,
        })
    }

    /// Returns the exact run/root-invocation target.
    #[must_use]
    pub const fn target(&self) -> &LogicalRunFinalizationTarget {
        &self.target
    }
    /// Returns the pinned descriptor digest.
    #[must_use]
    pub const fn descriptor_digest(&self) -> Sha256Digest {
        self.descriptor_digest
    }
    /// Returns the exact logical-job count.
    #[must_use]
    pub const fn job_count(&self) -> u32 {
        self.job_count
    }
    /// Returns the complete ordered evidence digest.
    #[must_use]
    pub const fn evidence_digest(&self) -> Sha256Digest {
        self.evidence_digest
    }
    /// Returns the closed run conclusion.
    #[must_use]
    pub const fn conclusion(&self) -> JobConclusion {
        self.conclusion
    }
    /// Returns the exact commit digest.
    #[must_use]
    pub const fn commit_digest(&self) -> Sha256Digest {
        self.commit_digest
    }
    /// Returns the durable finalization time.
    #[must_use]
    pub const fn finalized_at(&self) -> UnixMillis {
        self.finalized_at
    }
    /// Reports whether prior durable evidence was replayed.
    #[must_use]
    pub const fn is_replay(&self) -> bool {
        self.replayed
    }
}

/// Invalid logical workflow run-finalization value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LogicalRunFinalizationValueError {
    /// A durable UUID used the nil sentinel.
    #[error("{0} must not be the nil UUID")]
    NilUuid(&'static str),
    /// A trusted timestamp preceded the Unix epoch.
    #[error("{0} must not precede the Unix epoch")]
    NegativeTimestamp(&'static str),
    /// The claim interval was empty or exceeded its bound.
    #[error("logical run-finalization claim interval is invalid or too long")]
    InvalidClaimInterval,
    /// The claim generation was invalid.
    #[error("logical run-finalization generation is invalid")]
    InvalidGeneration,
    /// Current logical admission cannot produce an empty job set.
    #[error("logical run-finalization job set must not be empty")]
    EmptyJobSet,
    /// The job set exceeded the current logical workflow bound.
    #[error("logical run-finalization job set exceeds its bound")]
    TooManyJobs,
    /// Immutable logical-job evidence was malformed, duplicated, or noncanonical.
    #[error("logical run-finalization job evidence is invalid")]
    InvalidJobEvidence,
    /// A durable open-state revision was invalid.
    #[error("logical run-finalization revision is invalid")]
    InvalidRevision,
    /// A claim did not bind its descriptor.
    #[error("logical run-finalization claim does not bind its descriptor")]
    ClaimDescriptorMismatch,
    /// A claim began before all pinned evidence was ready.
    #[error("logical run-finalization claim precedes its evidence")]
    ClaimBeforeEvidence,
    /// The finalization timestamp fell outside the live claim.
    #[error("logical run-finalization commit falls outside its claim")]
    CommitOutsideClaim,
    /// A durable receipt contained impossible count or time evidence.
    #[error("durable logical run-finalization receipt is invalid")]
    InvalidDurableReceipt,
}

/// Durable claim or finalization failure.
#[derive(Debug, Error)]
pub enum LogicalRunFinalizationStoreError {
    /// The repository failed or contained malformed current data.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The monotonic claim generation cannot advance.
    #[error("logical run-finalization claim generation is exhausted")]
    GenerationExhausted,
    /// Commit did not own the exact current live fence and descriptor.
    #[error("logical run-finalization claim fence was rejected")]
    ClaimRejected,
    /// Commit disagreed with immutable durable finalization evidence.
    #[error("logical run-finalization commit conflicts with durable evidence")]
    CommitConflict,
}

/// Persistence boundary for current logical workflow run aggregation.
#[async_trait]
pub trait LogicalRunFinalizationRepository: fmt::Debug + Send + Sync {
    /// Claims at most one exact ready root invocation with `SKIP LOCKED` semantics.
    async fn claim_logical_run_finalization(
        &self,
        request: ClaimLogicalRunFinalization,
    ) -> Result<Option<ClaimedLogicalRunFinalization>, LogicalRunFinalizationStoreError>;

    /// Atomically persists evidence and closes invocation, marker, and workflow run.
    async fn commit_logical_run_finalization(
        &self,
        request: CommitLogicalRunFinalization,
    ) -> Result<LogicalRunFinalizationReceipt, LogicalRunFinalizationStoreError>;
}

fn aggregate_conclusion(jobs: &[LogicalRunJobResultEvidence]) -> JobConclusion {
    debug_assert!(!jobs.is_empty(), "descriptor rejects empty job sets");
    if jobs
        .iter()
        .any(|job| job.effective_conclusion() == JobConclusion::Failure)
    {
        JobConclusion::Failure
    } else if jobs
        .iter()
        .any(|job| job.effective_conclusion() == JobConclusion::TimedOut)
    {
        JobConclusion::TimedOut
    } else if jobs
        .iter()
        .any(|job| job.effective_conclusion() == JobConclusion::Cancelled)
    {
        JobConclusion::Cancelled
    } else if jobs
        .iter()
        .all(|job| job.effective_conclusion() == JobConclusion::Skipped)
    {
        JobConclusion::Skipped
    } else {
        JobConclusion::Success
    }
}

fn evidence_digest(jobs: &[LogicalRunJobResultEvidence]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(EVIDENCE_DOMAIN);
    hasher.update(u64_len(jobs.len()));
    for job in jobs {
        hasher.update(job.logical_job_id().as_uuid().as_bytes());
        hash_text(&mut hasher, job.logical_key().as_str());
        hasher.update(job.source_order().to_be_bytes());
        hasher.update(job.descriptor_digest().as_bytes());
        hasher.update([conclusion_code(job.effective_conclusion())]);
        hasher.update([
            u8::from(job.closure_has_failure()),
            u8::from(job.closure_has_cancelled()),
            u8::from(job.closure_has_skipped()),
        ]);
        hasher.update(job.instance_count().to_be_bytes());
        hasher.update(job.instances_digest().as_bytes());
        hasher.update(job.prerequisite_count().to_be_bytes());
        hasher.update(job.prerequisites_digest().as_bytes());
        hasher.update(job.output_count().to_be_bytes());
        hasher.update(job.outputs_digest().as_bytes());
        hasher.update(job.commit_digest().as_bytes());
        hasher.update(job.finalized_at().get().to_be_bytes());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

#[allow(clippy::too_many_arguments)]
fn descriptor_digest(
    target: &LogicalRunFinalizationTarget,
    admission_digest: Sha256Digest,
    marker_state: LogicalRunFinalizationOpenState,
    marker_revision: u64,
    marker_updated_at: UnixMillis,
    invocation_state: LogicalRunFinalizationOpenState,
    invocation_revision: u64,
    invocation_updated_at: UnixMillis,
    workflow_status: LogicalRunFinalizationWorkflowStatus,
    workflow_updated_at: UnixMillis,
    job_count: usize,
    evidence_digest: Sha256Digest,
    evidence_ready_at: UnixMillis,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(DESCRIPTOR_DOMAIN);
    hash_text(&mut hasher, target.tenant().as_str());
    hasher.update(target.run_id().as_uuid().as_bytes());
    hasher.update(target.root_invocation_id().as_uuid().as_bytes());
    hasher.update(admission_digest.as_bytes());
    hasher.update([open_state_code(marker_state)]);
    hasher.update(marker_revision.to_be_bytes());
    hasher.update(marker_updated_at.get().to_be_bytes());
    hasher.update([open_state_code(invocation_state)]);
    hasher.update(invocation_revision.to_be_bytes());
    hasher.update(invocation_updated_at.get().to_be_bytes());
    hasher.update([workflow_status_code(workflow_status)]);
    hasher.update(workflow_updated_at.get().to_be_bytes());
    hasher.update(u64_len(job_count));
    hasher.update(evidence_digest.as_bytes());
    hasher.update(evidence_ready_at.get().to_be_bytes());
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn commit_digest(
    claim: &LogicalRunFinalizationClaimFence,
    descriptor: &LogicalRunFinalizationDescriptor,
    conclusion: JobConclusion,
    finalized_at: UnixMillis,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(COMMIT_DOMAIN);
    hasher.update(descriptor.descriptor_digest().as_bytes());
    hasher.update(claim.owner().as_uuid().as_bytes());
    hasher.update(claim.generation().get().to_be_bytes());
    hasher.update(claim.claimed_at().get().to_be_bytes());
    hasher.update(claim.expires_at().get().to_be_bytes());
    hasher.update([conclusion_code(conclusion)]);
    hasher.update(finalized_at.get().to_be_bytes());
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn validate_claim_interval(
    observed_at: UnixMillis,
    expires_at: UnixMillis,
) -> Result<(), LogicalRunFinalizationValueError> {
    validate_timestamp(observed_at, "logical run-finalization observation time")?;
    validate_timestamp(expires_at, "logical run-finalization claim expiration")?;
    expires_at
        .get()
        .checked_sub(observed_at.get())
        .filter(|duration| *duration > 0 && *duration <= MAX_LOGICAL_RUN_FINALIZATION_CLAIM_MILLIS)
        .ok_or(LogicalRunFinalizationValueError::InvalidClaimInterval)?;
    Ok(())
}

fn validate_timestamp(
    value: UnixMillis,
    field: &'static str,
) -> Result<(), LogicalRunFinalizationValueError> {
    if value.get() < 0 {
        return Err(LogicalRunFinalizationValueError::NegativeTimestamp(field));
    }
    Ok(())
}

fn validate_revision(value: u64) -> Result<(), LogicalRunFinalizationValueError> {
    if value == 0 || i64::try_from(value).is_err() {
        return Err(LogicalRunFinalizationValueError::InvalidRevision);
    }
    Ok(())
}

fn hash_text(hasher: &mut Sha256, value: &str) {
    hasher.update(u64_len(value.len()));
    hasher.update(value.as_bytes());
}

fn u64_len(value: usize) -> [u8; 8] {
    u64::try_from(value).unwrap_or(u64::MAX).to_be_bytes()
}

const fn conclusion_code(value: JobConclusion) -> u8 {
    match value {
        JobConclusion::Success => 1,
        JobConclusion::Failure => 2,
        JobConclusion::Cancelled => 3,
        JobConclusion::TimedOut => 4,
        JobConclusion::Skipped => 5,
    }
}

const fn open_state_code(value: LogicalRunFinalizationOpenState) -> u8 {
    match value {
        LogicalRunFinalizationOpenState::Pending => 1,
        LogicalRunFinalizationOpenState::Active => 2,
    }
}

const fn workflow_status_code(value: LogicalRunFinalizationWorkflowStatus) -> u8 {
    match value {
        LogicalRunFinalizationWorkflowStatus::Queued => 1,
        LogicalRunFinalizationWorkflowStatus::InProgress => 2,
        LogicalRunFinalizationWorkflowStatus::Cancelled => 3,
    }
}
