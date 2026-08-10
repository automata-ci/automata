//! Fenced aggregation of immutable instance results into one logical-job result.
//!
//! Repository claims authenticate the exact current WorkflowPlan-v2 object,
//! ordered instance-result/output evidence, and direct prerequisite closure.
//! The plan blob is loaded, canonically decoded, and revalidated outside SQL
//! before a sensitivity-safe aggregate is committed.

use std::{collections::BTreeSet, fmt, num::NonZeroU64};

use async_trait::async_trait;
use automata_ci_core::{
    JobConclusion, LogicalJobKind, LogicalJobOutputSource, LogicalOutputMergePolicy,
    MAX_JOB_RESULT_OUTPUT_UTF16_BYTES, MAX_LOGICAL_JOB_NEEDS, MAX_LOGICAL_JOB_OUTPUTS,
    OutputSensitivity, RunId, Sha256Digest, UnixMillis, WorkflowJobKey, WorkflowOutputKey,
    WorkflowPlan, WorkflowPlanVersion,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    AdmissionObject, LogicalInstanceTerminalOrdinal, LogicalWorkflowInstanceId,
    LogicalWorkflowInvocationId, LogicalWorkflowJobId, StoreError, TenantScope,
    WORKFLOW_PLAN_SCHEMA,
};

/// Exact media type of the current canonical WorkflowPlan-v2 object.
pub const LOGICAL_JOB_RESULT_PLAN_MEDIA_TYPE: &str = "application/vnd.automata.workflow-plan+json";
/// Maximum duration of one logical-job result claim.
pub const MAX_LOGICAL_JOB_RESULT_CLAIM_MILLIS: i64 = 15 * 60 * 1_000;

const DESCRIPTOR_DOMAIN: &[u8] = b"automata.store.logical-job-result-descriptor.v1\0";
const INSTANCES_DOMAIN: &[u8] = b"automata.store.logical-job-result-instances.v1\0";
const PREREQUISITES_DOMAIN: &[u8] = b"automata.store.logical-job-result-prerequisites.v1\0";
const INSTANCE_OUTPUTS_DOMAIN: &[u8] = b"automata.store.logical-instance-result-outputs.v1\0";
const OUTPUTS_DOMAIN: &[u8] = b"automata.store.logical-job-result-outputs.v1\0";
const COMMIT_DOMAIN: &[u8] = b"automata.store.logical-job-result-commit.v1\0";

/// Non-nil durable identity of one logical-result worker.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalJobResultWorkerId(Uuid);

impl LogicalJobResultWorkerId {
    /// Constructs a non-nil worker identity.
    ///
    /// # Errors
    ///
    /// Rejects the nil UUID sentinel.
    pub fn from_uuid(value: Uuid) -> Result<Self, LogicalJobResultValueError> {
        if value.is_nil() {
            return Err(LogicalJobResultValueError::NilUuid(
                "logical job-result worker ID",
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

/// Non-nil idempotency key for one autonomous job-result selection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalJobResultSelectionId(Uuid);

impl LogicalJobResultSelectionId {
    /// Constructs a non-nil selection identity.
    ///
    /// # Errors
    ///
    /// Rejects the nil UUID sentinel.
    pub fn from_uuid(value: Uuid) -> Result<Self, LogicalJobResultValueError> {
        if value.is_nil() {
            return Err(LogicalJobResultValueError::NilUuid(
                "logical job-result selection ID",
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

/// Positive monotonic generation of one logical-result claim.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalJobResultGeneration(NonZeroU64);

impl LogicalJobResultGeneration {
    /// Constructs a positive generation representable by `PostgreSQL` `BIGINT`.
    ///
    /// # Errors
    ///
    /// Rejects zero and values larger than `i64::MAX`.
    pub fn new(value: u64) -> Result<Self, LogicalJobResultValueError> {
        let value = NonZeroU64::new(value)
            .filter(|value| i64::try_from(value.get()).is_ok())
            .ok_or(LogicalJobResultValueError::InvalidGeneration)?;
        Ok(Self(value))
    }

    /// Returns the numeric generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    pub(crate) fn as_i64(self) -> i64 {
        i64::try_from(self.get()).expect("validated logical-result generation fits in i64")
    }
}

/// Exact tenant-scoped logical job selected for finalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalJobResultTarget {
    tenant: TenantScope,
    run_id: RunId,
    invocation_id: LogicalWorkflowInvocationId,
    logical_job_id: LogicalWorkflowJobId,
}

impl LogicalJobResultTarget {
    /// Constructs an exact current logical-job target.
    ///
    /// # Errors
    ///
    /// Rejects a nil workflow-run identity.
    pub fn new(
        tenant: TenantScope,
        run_id: RunId,
        invocation_id: LogicalWorkflowInvocationId,
        logical_job_id: LogicalWorkflowJobId,
    ) -> Result<Self, LogicalJobResultValueError> {
        if run_id.as_uuid().is_nil() {
            return Err(LogicalJobResultValueError::NilUuid("workflow run ID"));
        }
        Ok(Self {
            tenant,
            run_id,
            invocation_id,
            logical_job_id,
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

    /// Returns the invocation identity.
    #[must_use]
    pub const fn invocation_id(&self) -> LogicalWorkflowInvocationId {
        self.invocation_id
    }

    /// Returns the logical-job identity.
    #[must_use]
    pub const fn logical_job_id(&self) -> LogicalWorkflowJobId {
        self.logical_job_id
    }
}

/// Request to acquire or take over one logical-result claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimLogicalJobResult {
    target: LogicalJobResultTarget,
    owner: LogicalJobResultWorkerId,
    observed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl ClaimLogicalJobResult {
    /// Constructs one bounded claim request.
    ///
    /// # Errors
    ///
    /// Rejects an invalid or overlong claim interval.
    pub fn new(
        target: LogicalJobResultTarget,
        owner: LogicalJobResultWorkerId,
        observed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, LogicalJobResultValueError> {
        validate_claim_interval(observed_at, expires_at)?;
        Ok(Self {
            target,
            owner,
            observed_at,
            expires_at,
        })
    }

    /// Returns the exact target.
    #[must_use]
    pub const fn target(&self) -> &LogicalJobResultTarget {
        &self.target
    }

    /// Returns the claim owner.
    #[must_use]
    pub const fn owner(&self) -> LogicalJobResultWorkerId {
        self.owner
    }

    /// Returns the trusted observation time.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }

    /// Returns the requested expiration time.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
}

/// Bounded request to select and claim the next globally ready logical job.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimNextLogicalJobResult {
    selection_id: LogicalJobResultSelectionId,
    owner: LogicalJobResultWorkerId,
    observed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl ClaimNextLogicalJobResult {
    /// Constructs one globally bounded claim-next request.
    ///
    /// # Errors
    ///
    /// Rejects an invalid or overlong claim interval.
    pub fn new(
        selection_id: LogicalJobResultSelectionId,
        owner: LogicalJobResultWorkerId,
        observed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, LogicalJobResultValueError> {
        validate_claim_interval(observed_at, expires_at)?;
        Ok(Self {
            selection_id,
            owner,
            observed_at,
            expires_at,
        })
    }

    /// Returns the stable request identity.
    #[must_use]
    pub const fn selection_id(&self) -> LogicalJobResultSelectionId {
        self.selection_id
    }

    /// Returns the claim owner.
    #[must_use]
    pub const fn owner(&self) -> LogicalJobResultWorkerId {
        self.owner
    }

    /// Returns the trusted selection time.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }

    /// Returns the requested expiration time.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
}

/// One sensitivity-safe output captured from an immutable instance result.
#[derive(Clone, Eq, PartialEq)]
pub struct LogicalJobInstanceOutput {
    name: WorkflowOutputKey,
    sensitivity: OutputSensitivity,
    public_value: Option<String>,
}

impl fmt::Debug for LogicalJobInstanceOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LogicalJobInstanceOutput")
            .field("name", &self.name)
            .field("sensitivity", &self.sensitivity)
            .field(
                "public_value",
                &self.public_value.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl LogicalJobInstanceOutput {
    /// Rehydrates a classified instance output.
    ///
    /// # Errors
    ///
    /// Rejects empty public values or a sensitivity/value mismatch.
    pub fn new(
        name: WorkflowOutputKey,
        sensitivity: OutputSensitivity,
        public_value: Option<String>,
    ) -> Result<Self, LogicalJobResultValueError> {
        match (sensitivity, public_value.as_deref()) {
            (OutputSensitivity::Public, Some(value)) if !value.is_empty() => {}
            (OutputSensitivity::SecretDerived, None) => {}
            _ => return Err(LogicalJobResultValueError::InvalidInstanceOutput),
        }
        if public_value.as_deref().is_some_and(|value| {
            value.encode_utf16().count().saturating_mul(2) > MAX_JOB_RESULT_OUTPUT_UTF16_BYTES
        }) {
            return Err(LogicalJobResultValueError::InvalidInstanceOutput);
        }
        Ok(Self {
            name,
            sensitivity,
            public_value,
        })
    }

    /// Returns the canonical output name.
    #[must_use]
    pub const fn name(&self) -> &WorkflowOutputKey {
        &self.name
    }

    /// Returns the durable classification.
    #[must_use]
    pub const fn sensitivity(&self) -> OutputSensitivity {
        self.sensitivity
    }

    /// Returns plaintext only for a public output.
    #[must_use]
    pub fn public_value(&self) -> Option<&str> {
        self.public_value.as_deref()
    }
}

/// Exact immutable instance-result evidence included in a logical claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalJobInstanceResultEvidence {
    instance_id: LogicalWorkflowInstanceId,
    matrix_index: u32,
    terminal_ordinal: LogicalInstanceTerminalOrdinal,
    descriptor_digest: Sha256Digest,
    outputs_digest: Sha256Digest,
    commit_digest: Sha256Digest,
    raw_conclusion: JobConclusion,
    effective_conclusion: JobConclusion,
    outputs: Vec<LogicalJobInstanceOutput>,
    finalized_at: UnixMillis,
}

impl LogicalJobInstanceResultEvidence {
    /// Rehydrates one exact finalized instance result and its ordered outputs.
    ///
    /// # Errors
    ///
    /// Rejects an invalid matrix index, unordered/duplicate outputs, or
    /// negative finalization time.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        instance_id: LogicalWorkflowInstanceId,
        matrix_index: u32,
        terminal_ordinal: LogicalInstanceTerminalOrdinal,
        descriptor_digest: Sha256Digest,
        commit_digest: Sha256Digest,
        raw_conclusion: JobConclusion,
        effective_conclusion: JobConclusion,
        mut outputs: Vec<LogicalJobInstanceOutput>,
        finalized_at: UnixMillis,
    ) -> Result<Self, LogicalJobResultValueError> {
        if matrix_index >= 256 || outputs.len() > MAX_LOGICAL_JOB_OUTPUTS {
            return Err(LogicalJobResultValueError::InvalidInstanceEvidence);
        }
        validate_timestamp(finalized_at, "instance-result finalization time")?;
        outputs.sort_by(|left, right| left.name().cmp(right.name()));
        if outputs
            .windows(2)
            .any(|pair| pair[0].name() == pair[1].name())
        {
            return Err(LogicalJobResultValueError::InvalidInstanceOutput);
        }
        let outputs_digest = instance_outputs_digest(&outputs);
        Ok(Self {
            instance_id,
            matrix_index,
            terminal_ordinal,
            descriptor_digest,
            outputs_digest,
            commit_digest,
            raw_conclusion,
            effective_conclusion,
            outputs,
            finalized_at,
        })
    }

    /// Returns the immutable instance identity.
    #[must_use]
    pub const fn instance_id(&self) -> LogicalWorkflowInstanceId {
        self.instance_id
    }

    /// Returns the stable matrix index.
    #[must_use]
    pub const fn matrix_index(&self) -> u32 {
        self.matrix_index
    }

    /// Returns the server-assigned terminal order.
    #[must_use]
    pub const fn terminal_ordinal(&self) -> LogicalInstanceTerminalOrdinal {
        self.terminal_ordinal
    }

    /// Returns the instance descriptor digest.
    #[must_use]
    pub const fn descriptor_digest(&self) -> Sha256Digest {
        self.descriptor_digest
    }

    /// Returns the instance output-set digest.
    #[must_use]
    pub const fn outputs_digest(&self) -> Sha256Digest {
        self.outputs_digest
    }

    /// Returns the instance commit digest.
    #[must_use]
    pub const fn commit_digest(&self) -> Sha256Digest {
        self.commit_digest
    }

    /// Returns the unmodified runner conclusion.
    #[must_use]
    pub const fn raw_conclusion(&self) -> JobConclusion {
        self.raw_conclusion
    }

    /// Returns the job-level mapped conclusion.
    #[must_use]
    pub const fn effective_conclusion(&self) -> JobConclusion {
        self.effective_conclusion
    }

    /// Returns canonical name-sorted classified outputs.
    #[must_use]
    pub fn outputs(&self) -> &[LogicalJobInstanceOutput] {
        &self.outputs
    }

    /// Returns the durable instance-result finalization time.
    #[must_use]
    pub const fn finalized_at(&self) -> UnixMillis {
        self.finalized_at
    }
}

/// Direct prerequisite result and transitive status-closure evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalJobPrerequisiteEvidence {
    logical_job_id: LogicalWorkflowJobId,
    logical_key: WorkflowJobKey,
    source_order: u16,
    commit_digest: Sha256Digest,
    outputs_digest: Sha256Digest,
    effective_conclusion: JobConclusion,
    closure_has_failure: bool,
    closure_has_cancelled: bool,
    closure_has_skipped: bool,
    finalized_at: UnixMillis,
}

impl LogicalJobPrerequisiteEvidence {
    /// Rehydrates one direct prerequisite's immutable logical result.
    ///
    /// # Errors
    ///
    /// Rejects an out-of-range source order or negative finalization time.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        logical_job_id: LogicalWorkflowJobId,
        logical_key: WorkflowJobKey,
        source_order: u16,
        commit_digest: Sha256Digest,
        outputs_digest: Sha256Digest,
        effective_conclusion: JobConclusion,
        closure_has_failure: bool,
        closure_has_cancelled: bool,
        closure_has_skipped: bool,
        finalized_at: UnixMillis,
    ) -> Result<Self, LogicalJobResultValueError> {
        if source_order > 1_023 {
            return Err(LogicalJobResultValueError::InvalidSourceOrder);
        }
        validate_timestamp(finalized_at, "prerequisite finalization time")?;
        Ok(Self {
            logical_job_id,
            logical_key,
            source_order,
            commit_digest,
            outputs_digest,
            effective_conclusion,
            closure_has_failure,
            closure_has_cancelled,
            closure_has_skipped,
            finalized_at,
        })
    }

    /// Returns the prerequisite logical-job identity.
    #[must_use]
    pub const fn logical_job_id(&self) -> LogicalWorkflowJobId {
        self.logical_job_id
    }

    /// Returns the prerequisite logical key.
    #[must_use]
    pub const fn logical_key(&self) -> &WorkflowJobKey {
        &self.logical_key
    }

    /// Returns the canonical source order.
    #[must_use]
    pub const fn source_order(&self) -> u16 {
        self.source_order
    }

    /// Returns the exact prerequisite commit digest.
    #[must_use]
    pub const fn commit_digest(&self) -> Sha256Digest {
        self.commit_digest
    }

    /// Returns the exact prerequisite output-set digest.
    #[must_use]
    pub const fn outputs_digest(&self) -> Sha256Digest {
        self.outputs_digest
    }

    /// Returns the prerequisite effective conclusion.
    #[must_use]
    pub const fn effective_conclusion(&self) -> JobConclusion {
        self.effective_conclusion
    }

    /// Reports a failure anywhere in the prerequisite's transitive closure.
    #[must_use]
    pub const fn closure_has_failure(&self) -> bool {
        self.closure_has_failure
    }

    /// Reports cancellation anywhere in the prerequisite's transitive closure.
    #[must_use]
    pub const fn closure_has_cancelled(&self) -> bool {
        self.closure_has_cancelled
    }

    /// Reports a skipped job anywhere in the prerequisite's transitive closure.
    #[must_use]
    pub const fn closure_has_skipped(&self) -> bool {
        self.closure_has_skipped
    }

    /// Returns the durable prerequisite finalization time.
    #[must_use]
    pub const fn finalized_at(&self) -> UnixMillis {
        self.finalized_at
    }
}

/// Store-authenticated plan, publication, instance, and prerequisite evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalJobResultDescriptor {
    target: LogicalJobResultTarget,
    logical_key: WorkflowJobKey,
    source_order: u16,
    plan: AdmissionObject,
    activation_output_digest: Sha256Digest,
    condition_matched: bool,
    instance_count: u32,
    instances: Vec<LogicalJobInstanceResultEvidence>,
    instances_digest: Sha256Digest,
    prerequisites: Vec<LogicalJobPrerequisiteEvidence>,
    prerequisites_digest: Sha256Digest,
    evidence_ready_at: UnixMillis,
    descriptor_digest: Sha256Digest,
}

impl LogicalJobResultDescriptor {
    /// Rehydrates one exact ready logical job without performing plan blob I/O.
    ///
    /// # Errors
    ///
    /// Rejects non-current plan metadata, incomplete/noncanonical instance or
    /// prerequisite evidence, invalid counts, or impossible timestamps.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target: LogicalJobResultTarget,
        logical_key: WorkflowJobKey,
        source_order: u16,
        plan: AdmissionObject,
        activation_output_digest: Sha256Digest,
        condition_matched: bool,
        instance_count: u32,
        mut instances: Vec<LogicalJobInstanceResultEvidence>,
        mut prerequisites: Vec<LogicalJobPrerequisiteEvidence>,
        publication_at: UnixMillis,
    ) -> Result<Self, LogicalJobResultValueError> {
        if source_order > 1_023 {
            return Err(LogicalJobResultValueError::InvalidSourceOrder);
        }
        if plan.media_type() != LOGICAL_JOB_RESULT_PLAN_MEDIA_TYPE {
            return Err(LogicalJobResultValueError::InvalidPlanObject);
        }
        if instance_count > 256
            || usize::try_from(instance_count).ok() != Some(instances.len())
            || (!condition_matched && instance_count != 0)
        {
            return Err(LogicalJobResultValueError::IncompleteInstanceEvidence);
        }
        if prerequisites.len() > MAX_LOGICAL_JOB_NEEDS {
            return Err(LogicalJobResultValueError::InvalidPrerequisiteEvidence);
        }
        validate_timestamp(publication_at, "activation publication time")?;
        instances.sort_by_key(LogicalJobInstanceResultEvidence::matrix_index);
        for (expected, instance) in instances.iter().enumerate() {
            if usize::try_from(instance.matrix_index()).ok() != Some(expected) {
                return Err(LogicalJobResultValueError::IncompleteInstanceEvidence);
            }
        }
        prerequisites.sort_by_key(LogicalJobPrerequisiteEvidence::source_order);
        let mut prerequisite_ids = BTreeSet::new();
        let mut prerequisite_keys = BTreeSet::new();
        let mut prerequisite_orders = BTreeSet::new();
        if prerequisites.iter().any(|prerequisite| {
            !prerequisite_ids.insert(prerequisite.logical_job_id())
                || !prerequisite_keys.insert(prerequisite.logical_key().clone())
                || !prerequisite_orders.insert(prerequisite.source_order())
        }) {
            return Err(LogicalJobResultValueError::InvalidPrerequisiteEvidence);
        }
        let instances_digest = instances_digest(&instances);
        let prerequisites_digest = prerequisites_digest(&prerequisites);
        let evidence_ready_at = instances
            .iter()
            .map(LogicalJobInstanceResultEvidence::finalized_at)
            .chain(
                prerequisites
                    .iter()
                    .map(LogicalJobPrerequisiteEvidence::finalized_at),
            )
            .fold(publication_at, std::cmp::max);
        let descriptor_digest = descriptor_digest(
            &target,
            &logical_key,
            source_order,
            &plan,
            activation_output_digest,
            condition_matched,
            instance_count,
            instances_digest,
            prerequisites_digest,
            evidence_ready_at,
        );
        Ok(Self {
            target,
            logical_key,
            source_order,
            plan,
            activation_output_digest,
            condition_matched,
            instance_count,
            instances,
            instances_digest,
            prerequisites,
            prerequisites_digest,
            evidence_ready_at,
            descriptor_digest,
        })
    }

    /// Returns the exact target.
    #[must_use]
    pub const fn target(&self) -> &LogicalJobResultTarget {
        &self.target
    }

    /// Returns the exact source-level job key.
    #[must_use]
    pub const fn logical_key(&self) -> &WorkflowJobKey {
        &self.logical_key
    }

    /// Returns the canonical source order.
    #[must_use]
    pub const fn source_order(&self) -> u16 {
        self.source_order
    }

    /// Returns the immutable current plan object descriptor.
    #[must_use]
    pub const fn plan(&self) -> &AdmissionObject {
        &self.plan
    }

    /// Returns the current plan schema.
    #[must_use]
    pub const fn plan_schema(&self) -> u16 {
        WORKFLOW_PLAN_SCHEMA
    }

    /// Returns the exact activation publication digest.
    #[must_use]
    pub const fn activation_output_digest(&self) -> Sha256Digest {
        self.activation_output_digest
    }

    /// Reports whether the activation condition matched.
    #[must_use]
    pub const fn condition_matched(&self) -> bool {
        self.condition_matched
    }

    /// Returns the exact activated instance count.
    #[must_use]
    pub const fn instance_count(&self) -> u32 {
        self.instance_count
    }

    /// Returns matrix-index-ordered immutable instance evidence.
    #[must_use]
    pub fn instances(&self) -> &[LogicalJobInstanceResultEvidence] {
        &self.instances
    }

    /// Returns the digest of the complete ordered instance evidence.
    #[must_use]
    pub const fn instances_digest(&self) -> Sha256Digest {
        self.instances_digest
    }

    /// Returns source-ordered direct prerequisite closure evidence.
    #[must_use]
    pub fn prerequisites(&self) -> &[LogicalJobPrerequisiteEvidence] {
        &self.prerequisites
    }

    /// Returns the digest of complete direct prerequisite evidence.
    #[must_use]
    pub const fn prerequisites_digest(&self) -> Sha256Digest {
        self.prerequisites_digest
    }

    /// Returns the latest durable time among all pinned evidence.
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

/// Exact live proof required to publish one logical-job result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalJobResultClaimFence {
    target: LogicalJobResultTarget,
    owner: LogicalJobResultWorkerId,
    generation: LogicalJobResultGeneration,
    descriptor_digest: Sha256Digest,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl LogicalJobResultClaimFence {
    /// Rehydrates repository-issued claim evidence.
    ///
    /// # Errors
    ///
    /// Rejects an invalid claim interval.
    pub fn new(
        target: LogicalJobResultTarget,
        owner: LogicalJobResultWorkerId,
        generation: LogicalJobResultGeneration,
        descriptor_digest: Sha256Digest,
        claimed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, LogicalJobResultValueError> {
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
    pub const fn target(&self) -> &LogicalJobResultTarget {
        &self.target
    }

    /// Returns the claim owner.
    #[must_use]
    pub const fn owner(&self) -> LogicalJobResultWorkerId {
        self.owner
    }

    /// Returns the monotonic generation.
    #[must_use]
    pub const fn generation(&self) -> LogicalJobResultGeneration {
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

/// Immutable aggregation inputs returned under a live repository claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedLogicalJobResult {
    descriptor: LogicalJobResultDescriptor,
    claim: LogicalJobResultClaimFence,
    replayed: bool,
}

impl ClaimedLogicalJobResult {
    /// Constructs exact claimed aggregation evidence.
    ///
    /// # Errors
    ///
    /// Rejects a fence that does not bind the descriptor or starts before all
    /// pinned evidence was durable.
    pub fn new(
        descriptor: LogicalJobResultDescriptor,
        claim: LogicalJobResultClaimFence,
        replayed: bool,
    ) -> Result<Self, LogicalJobResultValueError> {
        if claim.target() != descriptor.target()
            || claim.descriptor_digest() != descriptor.descriptor_digest()
        {
            return Err(LogicalJobResultValueError::ClaimDescriptorMismatch);
        }
        if claim.claimed_at() < descriptor.evidence_ready_at() {
            return Err(LogicalJobResultValueError::ClaimBeforeEvidence);
        }
        Ok(Self {
            descriptor,
            claim,
            replayed,
        })
    }

    /// Returns the exact store-authenticated descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &LogicalJobResultDescriptor {
        &self.descriptor
    }

    /// Returns the live commit fence.
    #[must_use]
    pub const fn claim(&self) -> &LogicalJobResultClaimFence {
        &self.claim
    }

    /// Reports whether the exact claim request was replayed.
    #[must_use]
    pub const fn is_replay(&self) -> bool {
        self.replayed
    }
}

/// Outcome of attempting to claim one logical job for finalization.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum LogicalJobResultClaimOutcome {
    /// Every required immutable input is ready and the claim was acquired.
    Claimed(ClaimedLogicalJobResult),
    /// The job exists but zero/all-instance or prerequisite evidence is incomplete.
    NotReady,
    /// Another worker owns the unexpired claim.
    Busy,
    /// The exact logical job already has an immutable result.
    Finalized(LogicalJobResultReceipt),
}

/// Outcome of one idempotent global logical-job result selection.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum LogicalJobResultClaimNextOutcome {
    /// One ready job was claimed, or the exact selection was replayed.
    Claimed(ClaimedLogicalJobResult),
    /// The selected job was finalized before this selection was replayed.
    Finalized(LogicalJobResultReceipt),
    /// Deterministically corrupt target-local relational evidence was isolated.
    Quarantined,
    /// No ready job was available without waiting on another worker.
    Idle,
}

/// Closed, value-free reason for isolating one logical-job result target.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LogicalJobResultQuarantineKind {
    /// Durable relational evidence was internally inconsistent.
    RelationalEvidence,
    /// An immutable object could not be loaded with its exact descriptor.
    ObjectEvidence,
    /// Loaded bytes were malformed or disagreed with current payload semantics.
    PayloadEvidence,
}

/// Exact live fence authorizing isolation of one claimed logical-job result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantineLogicalJobResult {
    descriptor: LogicalJobResultDescriptor,
    claim: LogicalJobResultClaimFence,
    kind: LogicalJobResultQuarantineKind,
}

impl QuarantineLogicalJobResult {
    /// Binds a value-free failure classification to an already validated claim.
    #[must_use]
    pub fn new(claimed: &ClaimedLogicalJobResult, kind: LogicalJobResultQuarantineKind) -> Self {
        Self {
            descriptor: claimed.descriptor().clone(),
            claim: claimed.claim().clone(),
            kind,
        }
    }

    /// Returns the exact store-authenticated target descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &LogicalJobResultDescriptor {
        &self.descriptor
    }

    /// Returns the exact current claim fence.
    #[must_use]
    pub const fn claim(&self) -> &LogicalJobResultClaimFence {
        &self.claim
    }

    /// Returns the closed value-free failure classification.
    #[must_use]
    pub const fn kind(&self) -> LogicalJobResultQuarantineKind {
        self.kind
    }
}

/// Result of idempotently isolating one claimed logical-job result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogicalJobResultQuarantineOutcome {
    /// The exact live target and fence were isolated.
    Quarantined,
    /// The target was already durably isolated.
    AlreadyQuarantined,
    /// The target no longer has the submitted exact live fence and due snapshot.
    FenceRejected,
}

/// One declared logical output, including an allowed empty public value.
#[derive(Clone, Eq, PartialEq)]
pub struct LogicalJobResultOutput {
    name: WorkflowOutputKey,
    sensitivity: OutputSensitivity,
    public_value: Option<String>,
}

impl fmt::Debug for LogicalJobResultOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LogicalJobResultOutput")
            .field("name", &self.name)
            .field("sensitivity", &self.sensitivity)
            .field(
                "public_value",
                &self.public_value.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl LogicalJobResultOutput {
    fn public(name: WorkflowOutputKey, value: String) -> Self {
        Self {
            name,
            sensitivity: OutputSensitivity::Public,
            public_value: Some(value),
        }
    }

    fn secret_derived(name: WorkflowOutputKey) -> Self {
        Self {
            name,
            sensitivity: OutputSensitivity::SecretDerived,
            public_value: None,
        }
    }

    pub(crate) fn from_durable(
        name: WorkflowOutputKey,
        sensitivity: OutputSensitivity,
        public_value: Option<String>,
    ) -> Result<Self, LogicalJobResultValueError> {
        match (sensitivity, public_value) {
            (OutputSensitivity::Public, Some(value)) => Ok(Self::public(name, value)),
            (OutputSensitivity::SecretDerived, None) => Ok(Self::secret_derived(name)),
            _ => Err(LogicalJobResultValueError::InvalidDurableReceipt),
        }
    }

    /// Returns the declared output name.
    #[must_use]
    pub const fn name(&self) -> &WorkflowOutputKey {
        &self.name
    }

    /// Returns the final sensitivity classification.
    #[must_use]
    pub const fn sensitivity(&self) -> OutputSensitivity {
        self.sensitivity
    }

    /// Returns the value only for a public output; the value may be empty.
    #[must_use]
    pub fn public_value(&self) -> Option<&str> {
        self.public_value.as_deref()
    }
}

/// Validated logical-job result assembled from the exact current plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitLogicalJobResult {
    claim: LogicalJobResultClaimFence,
    effective_conclusion: JobConclusion,
    closure_has_failure: bool,
    closure_has_cancelled: bool,
    closure_has_skipped: bool,
    outputs: Vec<LogicalJobResultOutput>,
    outputs_digest: Sha256Digest,
    commit_digest: Sha256Digest,
    finalized_at: UnixMillis,
}

impl CommitLogicalJobResult {
    /// Canonically decodes and revalidates exact WorkflowPlan-v2 bytes, then
    /// aggregates conclusions and every declared output.
    ///
    /// `LastSuccessfulCompletion` uses raw success and the greatest
    /// server-assigned terminal ordinal. Matrix index is the deterministic
    /// secondary key if corrupted synthetic evidence ever repeats an ordinal.
    /// Secret-derived definitions and runtime upgrades never carry plaintext.
    ///
    /// # Errors
    ///
    /// Rejects blob, plan/job/output-definition, claim, conclusion, or
    /// sensitivity disagreements.
    pub fn new(
        claimed: &ClaimedLogicalJobResult,
        encoded_plan: &[u8],
        plan: &WorkflowPlan,
        finalized_at: UnixMillis,
    ) -> Result<Self, LogicalJobResultValueError> {
        let descriptor = claimed.descriptor();
        let claim = claimed.claim().clone();
        if finalized_at < claim.claimed_at() || finalized_at >= claim.expires_at() {
            return Err(LogicalJobResultValueError::CommitOutsideClaim);
        }
        validate_blob(encoded_plan, descriptor.plan())?;
        let decoded: WorkflowPlan = serde_json::from_slice(encoded_plan)
            .map_err(|_| LogicalJobResultValueError::InvalidPlan)?;
        decoded
            .validate()
            .map_err(|_| LogicalJobResultValueError::InvalidPlan)?;
        if decoded != *plan
            || decoded.version() != WorkflowPlanVersion::current()
            || serde_json::to_vec(&decoded).map_err(|_| LogicalJobResultValueError::InvalidPlan)?
                != encoded_plan
        {
            return Err(LogicalJobResultValueError::InvalidPlan);
        }
        let job = decoded
            .job(descriptor.logical_key())
            .ok_or(LogicalJobResultValueError::PlanJobMismatch)?;
        if job.source_order() != u32::from(descriptor.source_order())
            || !matches!(job.execution(), LogicalJobKind::Steps(_))
            || job.needs().len() != descriptor.prerequisites().len()
            || job.needs().iter().any(|need| {
                !descriptor
                    .prerequisites()
                    .iter()
                    .any(|prerequisite| prerequisite.logical_key() == need.value())
            })
        {
            return Err(LogicalJobResultValueError::PlanJobMismatch);
        }
        validate_instance_outputs(job.outputs(), descriptor.instances())?;
        let effective_conclusion = aggregate_conclusion(descriptor.instances());
        let closure_has_failure = matches!(
            effective_conclusion,
            JobConclusion::Failure | JobConclusion::TimedOut
        ) || descriptor
            .prerequisites()
            .iter()
            .any(LogicalJobPrerequisiteEvidence::closure_has_failure);
        let closure_has_cancelled = effective_conclusion == JobConclusion::Cancelled
            || descriptor
                .prerequisites()
                .iter()
                .any(LogicalJobPrerequisiteEvidence::closure_has_cancelled);
        let closure_has_skipped = effective_conclusion == JobConclusion::Skipped
            || descriptor
                .prerequisites()
                .iter()
                .any(LogicalJobPrerequisiteEvidence::closure_has_skipped);
        let outputs = aggregate_outputs(job.outputs(), descriptor.instances())?;
        let outputs_digest = outputs_digest(&outputs);
        let commit_digest = commit_digest(
            &claim,
            descriptor,
            effective_conclusion,
            closure_has_failure,
            closure_has_cancelled,
            closure_has_skipped,
            outputs_digest,
            finalized_at,
        );
        Ok(Self {
            claim,
            effective_conclusion,
            closure_has_failure,
            closure_has_cancelled,
            closure_has_skipped,
            outputs,
            outputs_digest,
            commit_digest,
            finalized_at,
        })
    }

    /// Returns the exact live claim proof.
    #[must_use]
    pub const fn claim(&self) -> &LogicalJobResultClaimFence {
        &self.claim
    }

    /// Returns the aggregate effective conclusion.
    #[must_use]
    pub const fn effective_conclusion(&self) -> JobConclusion {
        self.effective_conclusion
    }

    /// Reports a non-continuable failure in this job's full closure.
    #[must_use]
    pub const fn closure_has_failure(&self) -> bool {
        self.closure_has_failure
    }

    /// Reports cancellation in this job's full closure.
    #[must_use]
    pub const fn closure_has_cancelled(&self) -> bool {
        self.closure_has_cancelled
    }

    /// Reports a skipped job in this job's full closure.
    #[must_use]
    pub const fn closure_has_skipped(&self) -> bool {
        self.closure_has_skipped
    }

    /// Returns every declared output in canonical name order.
    #[must_use]
    pub fn outputs(&self) -> &[LogicalJobResultOutput] {
        &self.outputs
    }

    /// Returns the complete output-set digest.
    #[must_use]
    pub const fn outputs_digest(&self) -> Sha256Digest {
        self.outputs_digest
    }

    /// Returns the exact replay/commit digest.
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

/// Durable receipt for one immutable logical-job result.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct LogicalJobResultReceipt {
    logical_job_id: LogicalWorkflowJobId,
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
    replayed: bool,
}

impl LogicalJobResultReceipt {
    /// Constructs an exact receipt from a validated request and descriptor.
    #[must_use]
    pub fn new(
        request: &CommitLogicalJobResult,
        descriptor: &LogicalJobResultDescriptor,
        replayed: bool,
    ) -> Self {
        Self {
            logical_job_id: descriptor.target().logical_job_id(),
            descriptor_digest: descriptor.descriptor_digest(),
            effective_conclusion: request.effective_conclusion(),
            closure_has_failure: request.closure_has_failure(),
            closure_has_cancelled: request.closure_has_cancelled(),
            closure_has_skipped: request.closure_has_skipped(),
            instance_count: descriptor.instance_count(),
            instances_digest: descriptor.instances_digest(),
            prerequisite_count: u32::try_from(descriptor.prerequisites().len()).unwrap_or(u32::MAX),
            prerequisites_digest: descriptor.prerequisites_digest(),
            output_count: u32::try_from(request.outputs().len()).unwrap_or(u32::MAX),
            outputs_digest: request.outputs_digest(),
            commit_digest: request.commit_digest(),
            finalized_at: request.finalized_at(),
            replayed,
        }
    }

    /// Rehydrates an authenticated durable receipt.
    ///
    /// # Errors
    ///
    /// Rejects impossible counts or timestamps.
    #[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
    pub fn from_durable(
        logical_job_id: LogicalWorkflowJobId,
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
        replayed: bool,
    ) -> Result<Self, LogicalJobResultValueError> {
        if instance_count > 256
            || usize::try_from(prerequisite_count).unwrap_or(usize::MAX) > MAX_LOGICAL_JOB_NEEDS
            || usize::try_from(output_count).unwrap_or(usize::MAX) > MAX_LOGICAL_JOB_OUTPUTS
        {
            return Err(LogicalJobResultValueError::InvalidDurableReceipt);
        }
        validate_timestamp(finalized_at, "logical job-result finalization time")?;
        Ok(Self {
            logical_job_id,
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
            replayed,
        })
    }

    /// Returns the logical-job identity.
    #[must_use]
    pub const fn logical_job_id(&self) -> LogicalWorkflowJobId {
        self.logical_job_id
    }

    /// Returns the pinned descriptor digest.
    #[must_use]
    pub const fn descriptor_digest(&self) -> Sha256Digest {
        self.descriptor_digest
    }

    /// Returns the aggregate effective conclusion.
    #[must_use]
    pub const fn effective_conclusion(&self) -> JobConclusion {
        self.effective_conclusion
    }

    /// Reports failure in the transitive closure.
    #[must_use]
    pub const fn closure_has_failure(&self) -> bool {
        self.closure_has_failure
    }

    /// Reports cancellation in the transitive closure.
    #[must_use]
    pub const fn closure_has_cancelled(&self) -> bool {
        self.closure_has_cancelled
    }

    /// Reports a skip in the transitive closure.
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

    /// Returns the direct prerequisite count.
    #[must_use]
    pub const fn prerequisite_count(&self) -> u32 {
        self.prerequisite_count
    }

    /// Returns the direct prerequisite-evidence digest.
    #[must_use]
    pub const fn prerequisites_digest(&self) -> Sha256Digest {
        self.prerequisites_digest
    }

    /// Returns the declared logical output count.
    #[must_use]
    pub const fn output_count(&self) -> u32 {
        self.output_count
    }

    /// Returns the logical output-set digest.
    #[must_use]
    pub const fn outputs_digest(&self) -> Sha256Digest {
        self.outputs_digest
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

/// Invalid logical-job result value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LogicalJobResultValueError {
    /// A durable UUID used the nil sentinel.
    #[error("{0} must not be the nil UUID")]
    NilUuid(&'static str),
    /// A trusted timestamp preceded the Unix epoch.
    #[error("{0} must not precede the Unix epoch")]
    NegativeTimestamp(&'static str),
    /// The claim interval was empty or exceeded its bound.
    #[error("logical job-result claim interval is invalid or too long")]
    InvalidClaimInterval,
    /// The claim generation was invalid.
    #[error("logical job-result generation is invalid")]
    InvalidGeneration,
    /// Durable source order was out of range.
    #[error("logical job-result source order is invalid")]
    InvalidSourceOrder,
    /// The plan object descriptor was not current WorkflowPlan-v2 JSON.
    #[error("logical job-result plan object is invalid")]
    InvalidPlanObject,
    /// Instance evidence was missing or inconsistent with activation.
    #[error("logical job-result instance evidence is incomplete")]
    IncompleteInstanceEvidence,
    /// One immutable instance evidence row was invalid.
    #[error("logical job-result instance evidence is invalid")]
    InvalidInstanceEvidence,
    /// One classified instance output was invalid.
    #[error("logical job-result instance output is invalid")]
    InvalidInstanceOutput,
    /// Direct prerequisite evidence was malformed or duplicated.
    #[error("logical job-result prerequisite evidence is invalid")]
    InvalidPrerequisiteEvidence,
    /// A claim did not bind its descriptor.
    #[error("logical job-result claim does not bind its descriptor")]
    ClaimDescriptorMismatch,
    /// A claim began before all immutable evidence was ready.
    #[error("logical job-result claim precedes its evidence")]
    ClaimBeforeEvidence,
    /// Loaded plan bytes disagreed with the immutable descriptor.
    #[error("loaded workflow plan bytes disagree with the durable descriptor")]
    PlanBlobMismatch,
    /// The decoded plan was invalid, non-current, or noncanonical.
    #[error("decoded workflow plan is invalid or not canonical v2 JSON")]
    InvalidPlan,
    /// The decoded plan did not contain the exact claimed step job.
    #[error("decoded workflow plan job disagrees with the durable descriptor")]
    PlanJobMismatch,
    /// Plan output definitions disagreed with immutable instance evidence.
    #[error("logical output definitions disagree with instance evidence")]
    OutputDefinitionMismatch,
    /// A merge policy was inconsistent with the activated instance shape.
    #[error("logical output merge policy is invalid for the instance set")]
    InvalidOutputMerge,
    /// Aggregated public outputs exceeded the current bounded budget.
    #[error("logical public output values exceed the current result budget")]
    OutputBudgetExceeded,
    /// The finalization timestamp fell outside the live claim.
    #[error("logical job-result commit falls outside its claim")]
    CommitOutsideClaim,
    /// A durable receipt contained impossible counts or time.
    #[error("durable logical job-result receipt is invalid")]
    InvalidDurableReceipt,
}

/// Durable claim or finalization failure.
#[derive(Debug, Error)]
pub enum LogicalJobResultStoreError {
    /// The relational store failed or contained malformed current data.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The target is absent, cross-tenant, non-current, or unsupported.
    #[error("logical job-result target is not a current step job")]
    InvalidTarget,
    /// The monotonic claim generation cannot advance.
    #[error("logical job-result claim generation is exhausted")]
    GenerationExhausted,
    /// Commit did not own the exact current live fence.
    #[error("logical job-result claim fence was rejected")]
    ClaimRejected,
    /// A new claim's caller observation was not corroborated by database time.
    #[error("logical job-result claim time exceeds the allowed database clock skew")]
    ClaimClockSkew,
    /// A new or exactly replayed claim is no longer live at database time.
    #[error("logical job-result claim has expired")]
    ClaimExpired,
    /// Commit disagreed with immutable durable finalization evidence.
    #[error("logical job-result commit conflicts with durable evidence")]
    CommitConflict,
    /// A selection identity was replayed with different owner or time bounds.
    #[error("logical job-result selection identity was reused inconsistently")]
    SelectionConflict,
    /// The bounded replay horizon has closed for this selection request.
    #[error("logical job-result selection replay horizon has closed")]
    SelectionExpired,
    /// The caller observation is not corroborated by authoritative database time.
    #[error("logical job-result selection time exceeds the allowed database clock skew")]
    SelectionClockSkew,
}

/// Persistence boundary for current logical-job result aggregation.
#[async_trait]
pub trait LogicalJobResultRepository: fmt::Debug + Send + Sync {
    /// Globally selects at most one ready job using nonblocking row locking.
    async fn claim_next_logical_job_result(
        &self,
        request: ClaimNextLogicalJobResult,
    ) -> Result<LogicalJobResultClaimNextOutcome, LogicalJobResultStoreError>;

    /// Claims one exact ready logical job without performing blob I/O.
    async fn claim_logical_job_result(
        &self,
        request: ClaimLogicalJobResult,
    ) -> Result<LogicalJobResultClaimOutcome, LogicalJobResultStoreError>;

    /// Atomically publishes the result, outputs, closure, and terminal state.
    async fn commit_logical_job_result(
        &self,
        request: CommitLogicalJobResult,
    ) -> Result<LogicalJobResultReceipt, LogicalJobResultStoreError>;

    /// Idempotently isolates one exact claimed target after deterministic failure.
    async fn quarantine_logical_job_result(
        &self,
        request: QuarantineLogicalJobResult,
    ) -> Result<LogicalJobResultQuarantineOutcome, LogicalJobResultStoreError>;
}

fn validate_blob(
    encoded: &[u8],
    object: &AdmissionObject,
) -> Result<(), LogicalJobResultValueError> {
    let size =
        u64::try_from(encoded.len()).map_err(|_| LogicalJobResultValueError::PlanBlobMismatch)?;
    let digest = Sha256Digest::from_bytes(Sha256::digest(encoded).into());
    if size == object.encoded_size() && digest == object.digest() {
        Ok(())
    } else {
        Err(LogicalJobResultValueError::PlanBlobMismatch)
    }
}

fn validate_instance_outputs(
    definitions: &[automata_ci_core::LogicalJobOutputDefinition],
    instances: &[LogicalJobInstanceResultEvidence],
) -> Result<(), LogicalJobResultValueError> {
    for instance in instances {
        for output in instance.outputs() {
            let definition = definitions
                .iter()
                .find(|definition| definition.key().value() == output.name())
                .ok_or(LogicalJobResultValueError::OutputDefinitionMismatch)?;
            if !matches!(definition.source(), LogicalJobOutputSource::Template(_))
                || (definition.sensitivity() == OutputSensitivity::SecretDerived
                    && output.sensitivity() != OutputSensitivity::SecretDerived)
            {
                return Err(LogicalJobResultValueError::OutputDefinitionMismatch);
            }
        }
    }
    Ok(())
}

fn aggregate_conclusion(instances: &[LogicalJobInstanceResultEvidence]) -> JobConclusion {
    if instances.is_empty() {
        JobConclusion::Skipped
    } else if instances
        .iter()
        .any(|instance| instance.effective_conclusion() == JobConclusion::Failure)
    {
        JobConclusion::Failure
    } else if instances
        .iter()
        .any(|instance| instance.effective_conclusion() == JobConclusion::TimedOut)
    {
        JobConclusion::TimedOut
    } else if instances
        .iter()
        .any(|instance| instance.effective_conclusion() == JobConclusion::Cancelled)
    {
        JobConclusion::Cancelled
    } else if instances
        .iter()
        .any(|instance| instance.effective_conclusion() == JobConclusion::Success)
    {
        JobConclusion::Success
    } else {
        JobConclusion::Skipped
    }
}

fn aggregate_outputs(
    definitions: &[automata_ci_core::LogicalJobOutputDefinition],
    instances: &[LogicalJobInstanceResultEvidence],
) -> Result<Vec<LogicalJobResultOutput>, LogicalJobResultValueError> {
    let mut outputs = Vec::with_capacity(definitions.len());
    let mut public_utf16_bytes = 0_usize;
    for definition in definitions {
        if !matches!(definition.source(), LogicalJobOutputSource::Template(_)) {
            return Err(LogicalJobResultValueError::OutputDefinitionMismatch);
        }
        let selected = match definition.merge() {
            LogicalOutputMergePolicy::SingleInstance => match instances {
                [] => None,
                [instance] => Some(instance),
                _ => return Err(LogicalJobResultValueError::InvalidOutputMerge),
            },
            LogicalOutputMergePolicy::LastSuccessfulCompletion => instances
                .iter()
                .filter(|instance| instance.raw_conclusion() == JobConclusion::Success)
                .max_by_key(|instance| {
                    (instance.terminal_ordinal().get(), instance.matrix_index())
                }),
        };
        let selected_output = selected.and_then(|instance| {
            instance
                .outputs()
                .iter()
                .find(|output| output.name() == definition.key().value())
        });
        let name = definition.key().value().clone();
        let output = if definition.sensitivity() == OutputSensitivity::SecretDerived
            || selected_output
                .is_some_and(|output| output.sensitivity() == OutputSensitivity::SecretDerived)
        {
            LogicalJobResultOutput::secret_derived(name)
        } else {
            let value = selected_output
                .and_then(LogicalJobInstanceOutput::public_value)
                .unwrap_or("")
                .to_owned();
            public_utf16_bytes = public_utf16_bytes
                .checked_add(value.encode_utf16().count().saturating_mul(2))
                .ok_or(LogicalJobResultValueError::OutputBudgetExceeded)?;
            if public_utf16_bytes > MAX_JOB_RESULT_OUTPUT_UTF16_BYTES {
                return Err(LogicalJobResultValueError::OutputBudgetExceeded);
            }
            LogicalJobResultOutput::public(name, value)
        };
        outputs.push(output);
    }
    outputs.sort_by(|left, right| left.name().cmp(right.name()));
    Ok(outputs)
}

fn instances_digest(instances: &[LogicalJobInstanceResultEvidence]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(INSTANCES_DOMAIN);
    hasher.update(u64_len(instances.len()));
    for instance in instances {
        hasher.update(instance.instance_id().as_uuid().as_bytes());
        hasher.update(instance.matrix_index().to_be_bytes());
        hasher.update(instance.terminal_ordinal().get().to_be_bytes());
        hasher.update(instance.descriptor_digest().as_bytes());
        hasher.update(instance.outputs_digest().as_bytes());
        hasher.update(instance.commit_digest().as_bytes());
        hasher.update([conclusion_code(instance.raw_conclusion())]);
        hasher.update([conclusion_code(instance.effective_conclusion())]);
        hasher.update(u64_len(instance.outputs().len()));
        for output in instance.outputs() {
            hash_text(&mut hasher, output.name().as_str());
            hasher.update([sensitivity_code(output.sensitivity())]);
            hash_optional_text(&mut hasher, output.public_value());
        }
        hasher.update(instance.finalized_at().get().to_be_bytes());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn instance_outputs_digest(outputs: &[LogicalJobInstanceOutput]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(INSTANCE_OUTPUTS_DOMAIN);
    hasher.update(u64_len(outputs.len()));
    for output in outputs {
        hash_text(&mut hasher, output.name().as_str());
        hasher.update([sensitivity_code(output.sensitivity())]);
        hash_optional_text(&mut hasher, output.public_value());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn prerequisites_digest(prerequisites: &[LogicalJobPrerequisiteEvidence]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(PREREQUISITES_DOMAIN);
    hasher.update(u64_len(prerequisites.len()));
    for prerequisite in prerequisites {
        hasher.update(prerequisite.logical_job_id().as_uuid().as_bytes());
        hash_text(&mut hasher, prerequisite.logical_key().as_str());
        hasher.update(prerequisite.source_order().to_be_bytes());
        hasher.update(prerequisite.commit_digest().as_bytes());
        hasher.update(prerequisite.outputs_digest().as_bytes());
        hasher.update([conclusion_code(prerequisite.effective_conclusion())]);
        hasher.update([
            u8::from(prerequisite.closure_has_failure()),
            u8::from(prerequisite.closure_has_cancelled()),
            u8::from(prerequisite.closure_has_skipped()),
        ]);
        hasher.update(prerequisite.finalized_at().get().to_be_bytes());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

#[allow(clippy::too_many_arguments)]
fn descriptor_digest(
    target: &LogicalJobResultTarget,
    logical_key: &WorkflowJobKey,
    source_order: u16,
    plan: &AdmissionObject,
    activation_output_digest: Sha256Digest,
    condition_matched: bool,
    instance_count: u32,
    instances_digest: Sha256Digest,
    prerequisites_digest: Sha256Digest,
    evidence_ready_at: UnixMillis,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(DESCRIPTOR_DOMAIN);
    hasher.update(target.run_id().as_uuid().as_bytes());
    hasher.update(target.invocation_id().as_uuid().as_bytes());
    hasher.update(target.logical_job_id().as_uuid().as_bytes());
    hash_text(&mut hasher, logical_key.as_str());
    hasher.update(source_order.to_be_bytes());
    hash_admission_object(&mut hasher, plan);
    hasher.update(WORKFLOW_PLAN_SCHEMA.to_be_bytes());
    hasher.update(activation_output_digest.as_bytes());
    hasher.update([u8::from(condition_matched)]);
    hasher.update(instance_count.to_be_bytes());
    hasher.update(instances_digest.as_bytes());
    hasher.update(prerequisites_digest.as_bytes());
    hasher.update(evidence_ready_at.get().to_be_bytes());
    Sha256Digest::from_bytes(hasher.finalize().into())
}

pub(crate) fn outputs_digest(outputs: &[LogicalJobResultOutput]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(OUTPUTS_DOMAIN);
    hasher.update(u64_len(outputs.len()));
    for output in outputs {
        hash_text(&mut hasher, output.name().as_str());
        hasher.update([sensitivity_code(output.sensitivity())]);
        hash_optional_text(&mut hasher, output.public_value());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

#[allow(clippy::too_many_arguments)]
fn commit_digest(
    claim: &LogicalJobResultClaimFence,
    descriptor: &LogicalJobResultDescriptor,
    effective_conclusion: JobConclusion,
    closure_has_failure: bool,
    closure_has_cancelled: bool,
    closure_has_skipped: bool,
    outputs_digest: Sha256Digest,
    finalized_at: UnixMillis,
) -> Sha256Digest {
    rederive_commit_digest(
        descriptor.target(),
        claim.owner(),
        claim.generation(),
        claim.descriptor_digest(),
        descriptor.instances_digest(),
        descriptor.prerequisites_digest(),
        effective_conclusion,
        closure_has_failure,
        closure_has_cancelled,
        closure_has_skipped,
        outputs_digest,
        finalized_at,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn rederive_commit_digest(
    target: &LogicalJobResultTarget,
    owner: LogicalJobResultWorkerId,
    generation: LogicalJobResultGeneration,
    descriptor_digest: Sha256Digest,
    instances_digest: Sha256Digest,
    prerequisites_digest: Sha256Digest,
    effective_conclusion: JobConclusion,
    closure_has_failure: bool,
    closure_has_cancelled: bool,
    closure_has_skipped: bool,
    outputs_digest: Sha256Digest,
    finalized_at: UnixMillis,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(COMMIT_DOMAIN);
    hasher.update(target.run_id().as_uuid().as_bytes());
    hasher.update(target.invocation_id().as_uuid().as_bytes());
    hasher.update(target.logical_job_id().as_uuid().as_bytes());
    hasher.update(owner.as_uuid().as_bytes());
    hasher.update(generation.get().to_be_bytes());
    hasher.update(descriptor_digest.as_bytes());
    hasher.update(instances_digest.as_bytes());
    hasher.update(prerequisites_digest.as_bytes());
    hasher.update([conclusion_code(effective_conclusion)]);
    hasher.update([
        u8::from(closure_has_failure),
        u8::from(closure_has_cancelled),
        u8::from(closure_has_skipped),
    ]);
    hasher.update(outputs_digest.as_bytes());
    hasher.update(finalized_at.get().to_be_bytes());
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn hash_admission_object(hasher: &mut Sha256, object: &AdmissionObject) {
    hasher.update(object.digest().as_bytes());
    hash_text(hasher, object.object_key().as_str());
    hasher.update(object.encoded_size().to_be_bytes());
    hash_text(hasher, object.media_type());
}

fn hash_optional_text(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hash_text(hasher, value);
        }
        None => hasher.update([0]),
    }
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

const fn sensitivity_code(value: OutputSensitivity) -> u8 {
    match value {
        OutputSensitivity::Public => 1,
        OutputSensitivity::SecretDerived => 2,
    }
}

fn validate_claim_interval(
    observed_at: UnixMillis,
    expires_at: UnixMillis,
) -> Result<(), LogicalJobResultValueError> {
    validate_timestamp(observed_at, "logical job-result claim start")?;
    validate_timestamp(expires_at, "logical job-result claim expiration")?;
    expires_at
        .get()
        .checked_sub(observed_at.get())
        .filter(|duration| *duration > 0 && *duration <= MAX_LOGICAL_JOB_RESULT_CLAIM_MILLIS)
        .ok_or(LogicalJobResultValueError::InvalidClaimInterval)?;
    Ok(())
}

fn validate_timestamp(
    value: UnixMillis,
    field: &'static str,
) -> Result<(), LogicalJobResultValueError> {
    if value.get() < 0 {
        return Err(LogicalJobResultValueError::NegativeTimestamp(field));
    }
    Ok(())
}
