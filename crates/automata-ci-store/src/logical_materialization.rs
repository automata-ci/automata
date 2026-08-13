//! Fenced materialization of activated logical instances into runnable jobs.
//!
//! The repository returns an immutable instance descriptor and releases its
//! transaction before any blob I/O. Callers load and decode the exact `JobIR`
//! blob, then construct a commit that proves the current v1 envelope matches
//! every store-authenticated identity and content reference.

use std::num::NonZeroU64;

use async_trait::async_trait;
use automata_ci_core::{
    AttemptId, JOB_IR_SCHEMA_VERSION, JOB_RUNTIME_CONTEXT_SCHEMA_VERSION, JobAuthorityProfile,
    JobId, JobIrEnvelope, JobRuntimeContext, RunId, RunnerRequirements, Sha256Digest, UnixMillis,
    WorkflowJobKey,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    AdmissionObject, LOGICAL_ACTIVATION_JOB_IR_MEDIA_TYPE,
    LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE, LogicalActivationExecutionContext,
    LogicalActivationObject, LogicalWorkflowInstanceId, LogicalWorkflowInvocationId,
    LogicalWorkflowJobId, StoreError, TenantScope, WorkflowRuntimePolicyPin,
    WorkflowRuntimePolicyRevision,
};

/// Maximum duration of one concrete-job materialization claim.
pub const MAX_LOGICAL_MATERIALIZATION_CLAIM_MILLIS: i64 = 15 * 60 * 1_000;

// foundation-governance: derived-contract owner=store kind=digest-domain
const DESCRIPTOR_DIGEST_DOMAIN: &[u8] = b"automata.store.logical-materialization-descriptor.v4\0";
// foundation-governance: derived-contract owner=store kind=digest-domain
const COMMIT_DIGEST_DOMAIN: &[u8] = b"automata.store.logical-materialization-commit.v3\0";
// This is the current projector contract. Materialization independently
// derives the identity and verifies the value embedded in the decoded JobIR.
// foundation-governance: derived-contract owner=store kind=digest-domain
const JOB_ID_DOMAIN: &[u8] = b"automata.workflow-service.logical-job-id.v1\0";
// foundation-governance: derived-contract owner=store kind=digest-domain
const ATTEMPT_ID_DOMAIN: &[u8] = b"automata.store.logical-initial-attempt-id.v1\0";

/// Non-nil durable identity of one materialization worker.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalMaterializationWorkerId(Uuid);

impl LogicalMaterializationWorkerId {
    /// Constructs a non-nil worker identity.
    ///
    /// # Errors
    ///
    /// Rejects the nil UUID sentinel.
    pub fn from_uuid(value: Uuid) -> Result<Self, LogicalMaterializationValueError> {
        if value.is_nil() {
            return Err(LogicalMaterializationValueError::NilUuid(
                "logical materialization worker ID",
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

/// Positive monotonic generation of one instance materialization claim.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalMaterializationGeneration(NonZeroU64);

impl LogicalMaterializationGeneration {
    /// Constructs a positive generation representable by `PostgreSQL` `BIGINT`.
    ///
    /// # Errors
    ///
    /// Rejects zero and values larger than `i64::MAX`.
    pub fn new(value: u64) -> Result<Self, LogicalMaterializationValueError> {
        let value = NonZeroU64::new(value)
            .filter(|value| i64::try_from(value.get()).is_ok())
            .ok_or(LogicalMaterializationValueError::InvalidGeneration)?;
        Ok(Self(value))
    }

    /// Returns the numeric generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    pub(crate) fn as_i64(self) -> i64 {
        i64::try_from(self.get()).expect("validated materialization generation fits in i64")
    }
}

/// Exact target of one activated logical-instance materialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalInstanceMaterializationTarget {
    tenant: TenantScope,
    run_id: RunId,
    invocation_id: LogicalWorkflowInvocationId,
    logical_job_id: LogicalWorkflowJobId,
    instance_id: LogicalWorkflowInstanceId,
}

impl LogicalInstanceMaterializationTarget {
    /// Constructs a tenant-scoped target.
    ///
    /// # Errors
    ///
    /// Rejects the nil workflow-run sentinel.
    pub fn new(
        tenant: TenantScope,
        run_id: RunId,
        invocation_id: LogicalWorkflowInvocationId,
        logical_job_id: LogicalWorkflowJobId,
        instance_id: LogicalWorkflowInstanceId,
    ) -> Result<Self, LogicalMaterializationValueError> {
        if run_id.as_uuid().is_nil() {
            return Err(LogicalMaterializationValueError::NilUuid("workflow run ID"));
        }
        Ok(Self {
            tenant,
            run_id,
            invocation_id,
            logical_job_id,
            instance_id,
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

    /// Returns the logical invocation identity.
    #[must_use]
    pub const fn invocation_id(&self) -> LogicalWorkflowInvocationId {
        self.invocation_id
    }

    /// Returns the logical-job identity.
    #[must_use]
    pub const fn logical_job_id(&self) -> LogicalWorkflowJobId {
        self.logical_job_id
    }

    /// Returns the immutable activated-instance identity.
    #[must_use]
    pub const fn instance_id(&self) -> LogicalWorkflowInstanceId {
        self.instance_id
    }
}

/// Request to acquire or take over one instance materialization claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimLogicalInstanceMaterialization {
    target: LogicalInstanceMaterializationTarget,
    owner: LogicalMaterializationWorkerId,
    observed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl ClaimLogicalInstanceMaterialization {
    /// Constructs one bounded claim request.
    ///
    /// # Errors
    ///
    /// Rejects negative time, an empty interval, or an interval longer than
    /// [`MAX_LOGICAL_MATERIALIZATION_CLAIM_MILLIS`].
    pub fn new(
        target: LogicalInstanceMaterializationTarget,
        owner: LogicalMaterializationWorkerId,
        observed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, LogicalMaterializationValueError> {
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
    pub const fn target(&self) -> &LogicalInstanceMaterializationTarget {
        &self.target
    }

    /// Returns the worker identity.
    #[must_use]
    pub const fn owner(&self) -> LogicalMaterializationWorkerId {
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

/// Store-authenticated immutable descriptor loaded under a claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalInstanceMaterializationDescriptor {
    target: LogicalInstanceMaterializationTarget,
    logical_key: WorkflowJobKey,
    matrix_index: u32,
    matrix_total: u32,
    matrix_digest: Sha256Digest,
    workspace: String,
    job_ir: LogicalActivationObject,
    runtime_context: LogicalActivationObject,
    event: AdmissionObject,
    execution: LogicalActivationExecutionContext,
    authority_profile: JobAuthorityProfile,
    runtime_policy: WorkflowRuntimePolicyPin,
    descriptor_digest: Sha256Digest,
    expected_job_id: JobId,
    expected_attempt_id: AttemptId,
    job_key: String,
}

impl LogicalInstanceMaterializationDescriptor {
    /// Rehydrates and authenticates one immutable activated instance.
    ///
    /// Repository adapters use this constructor after reading the exact
    /// relational descriptor. It performs no blob I/O.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical matrix identity, invalid workspace, or object
    /// descriptors occupying the wrong semantic fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target: LogicalInstanceMaterializationTarget,
        logical_key: WorkflowJobKey,
        matrix_index: u32,
        matrix_total: u32,
        matrix_digest: Sha256Digest,
        workspace: String,
        job_ir: LogicalActivationObject,
        runtime_context: LogicalActivationObject,
        event: AdmissionObject,
        execution: LogicalActivationExecutionContext,
        authority_profile: JobAuthorityProfile,
        runtime_policy: WorkflowRuntimePolicyPin,
    ) -> Result<Self, LogicalMaterializationValueError> {
        if matrix_total == 0 || matrix_total > 256 || matrix_index >= matrix_total {
            return Err(LogicalMaterializationValueError::InvalidMatrixIdentity);
        }
        validate_workspace(&workspace)?;
        if !job_ir.is_job_ir() || !runtime_context.is_runtime_context() {
            return Err(LogicalMaterializationValueError::ObjectKindMismatch);
        }
        if job_ir.media_type() != LOGICAL_ACTIVATION_JOB_IR_MEDIA_TYPE
            || runtime_context.media_type() != LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE
        {
            return Err(LogicalMaterializationValueError::ObjectKindMismatch);
        }
        if runtime_policy.tenant() != target.tenant() {
            return Err(LogicalMaterializationValueError::RuntimePolicyMismatch);
        }
        let expected_job_id = derive_job_id(&target, matrix_index, matrix_total, matrix_digest);
        let expected_attempt_id = derive_attempt_id(expected_job_id);
        let job_key = format!("{}[{}]", logical_key.as_str(), matrix_index);
        let descriptor_digest = descriptor_digest(
            &target,
            &logical_key,
            matrix_index,
            matrix_total,
            matrix_digest,
            &workspace,
            &job_ir,
            &runtime_context,
            &event,
            &execution,
            authority_profile,
            &runtime_policy,
        );
        Ok(Self {
            target,
            logical_key,
            matrix_index,
            matrix_total,
            matrix_digest,
            workspace,
            job_ir,
            runtime_context,
            event,
            execution,
            authority_profile,
            runtime_policy,
            descriptor_digest,
            expected_job_id,
            expected_attempt_id,
            job_key,
        })
    }

    /// Returns the exact tenant-scoped target.
    #[must_use]
    pub const fn target(&self) -> &LogicalInstanceMaterializationTarget {
        &self.target
    }

    /// Returns the source-level logical key.
    #[must_use]
    pub const fn logical_key(&self) -> &WorkflowJobKey {
        &self.logical_key
    }

    /// Returns the zero-based matrix index.
    #[must_use]
    pub const fn matrix_index(&self) -> u32 {
        self.matrix_index
    }

    /// Returns the total matrix expansion count.
    #[must_use]
    pub const fn matrix_total(&self) -> u32 {
        self.matrix_total
    }

    /// Returns the exact matrix-value digest.
    #[must_use]
    pub const fn matrix_digest(&self) -> Sha256Digest {
        self.matrix_digest
    }

    /// Returns the canonical target workspace.
    #[must_use]
    pub fn workspace(&self) -> &str {
        &self.workspace
    }

    /// Returns the immutable `JobIR` object descriptor.
    #[must_use]
    pub const fn job_ir(&self) -> &LogicalActivationObject {
        &self.job_ir
    }

    /// Returns the immutable runtime-context object descriptor.
    #[must_use]
    pub const fn runtime_context(&self) -> &LogicalActivationObject {
        &self.runtime_context
    }

    /// Returns the immutable event object descriptor.
    #[must_use]
    pub const fn event(&self) -> &AdmissionObject {
        &self.event
    }

    /// Returns exact workflow execution metadata retained at admission.
    #[must_use]
    pub const fn execution(&self) -> &LogicalActivationExecutionContext {
        &self.execution
    }

    /// Returns the exact authority profile durably published for this job.
    #[must_use]
    pub const fn authority_profile(&self) -> JobAuthorityProfile {
        self.authority_profile
    }

    /// Returns the exact immutable runtime policy pinned to this run.
    #[must_use]
    pub const fn runtime_policy(&self) -> &WorkflowRuntimePolicyPin {
        &self.runtime_policy
    }

    /// Returns the canonical digest of every immutable descriptor field.
    #[must_use]
    pub const fn descriptor_digest(&self) -> Sha256Digest {
        self.descriptor_digest
    }

    /// Returns the concrete identity that must be embedded in `JobIR`.
    #[must_use]
    pub const fn expected_job_id(&self) -> JobId {
        self.expected_job_id
    }

    /// Returns the deterministic initial-attempt identity.
    #[must_use]
    pub const fn expected_attempt_id(&self) -> AttemptId {
        self.expected_attempt_id
    }

    /// Returns the deterministic concrete key, including matrix index.
    #[must_use]
    pub fn job_key(&self) -> &str {
        &self.job_key
    }
}

/// Exact live proof required to commit a concrete job.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalMaterializationClaimFence {
    target: LogicalInstanceMaterializationTarget,
    owner: LogicalMaterializationWorkerId,
    generation: LogicalMaterializationGeneration,
    descriptor_digest: Sha256Digest,
    runtime_policy: WorkflowRuntimePolicyPin,
    selection_origin: crate::LogicalWorkSelectionId,
    expected_job_id: JobId,
    expected_attempt_id: AttemptId,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl LogicalMaterializationClaimFence {
    /// Rehydrates inert selector-origin fence evidence for a repository adapter.
    ///
    /// Construction does not confer durable authority. Commit and quarantine
    /// operations still compare every field under repository locks.
    ///
    /// # Errors
    ///
    /// Rejects invalid identities, policy binding, or claim interval.
    #[allow(clippy::too_many_arguments)]
    pub fn new_for_selection(
        target: LogicalInstanceMaterializationTarget,
        owner: LogicalMaterializationWorkerId,
        generation: LogicalMaterializationGeneration,
        descriptor_digest: Sha256Digest,
        runtime_policy: WorkflowRuntimePolicyPin,
        expected_job_id: JobId,
        expected_attempt_id: AttemptId,
        claimed_at: UnixMillis,
        expires_at: UnixMillis,
        selection_origin: crate::LogicalWorkSelectionId,
    ) -> Result<Self, LogicalMaterializationValueError> {
        if expected_job_id.as_uuid().is_nil() {
            return Err(LogicalMaterializationValueError::NilUuid("concrete job ID"));
        }
        if runtime_policy.tenant() != target.tenant() {
            return Err(LogicalMaterializationValueError::RuntimePolicyMismatch);
        }
        if expected_attempt_id.as_uuid().is_nil() {
            return Err(LogicalMaterializationValueError::NilUuid(
                "initial attempt ID",
            ));
        }
        validate_claim_interval(claimed_at, expires_at)?;
        Ok(Self {
            target,
            owner,
            generation,
            descriptor_digest,
            runtime_policy,
            selection_origin,
            expected_job_id,
            expected_attempt_id,
            claimed_at,
            expires_at,
        })
    }

    /// Returns the exact target.
    #[must_use]
    pub const fn target(&self) -> &LogicalInstanceMaterializationTarget {
        &self.target
    }

    /// Returns the claim owner.
    #[must_use]
    pub const fn owner(&self) -> LogicalMaterializationWorkerId {
        self.owner
    }

    /// Returns the monotonic claim generation.
    #[must_use]
    pub const fn generation(&self) -> LogicalMaterializationGeneration {
        self.generation
    }

    /// Returns the exact immutable instance-descriptor digest.
    #[must_use]
    pub const fn descriptor_digest(&self) -> Sha256Digest {
        self.descriptor_digest
    }

    /// Returns the exact immutable runtime policy pinned to this claim.
    #[must_use]
    pub const fn runtime_policy(&self) -> &WorkflowRuntimePolicyPin {
        &self.runtime_policy
    }

    /// Returns the mandatory exact selector origin.
    #[must_use]
    pub const fn selection_origin(&self) -> crate::LogicalWorkSelectionId {
        self.selection_origin
    }

    /// Returns the required concrete job identity.
    #[must_use]
    pub const fn expected_job_id(&self) -> JobId {
        self.expected_job_id
    }

    /// Returns the required initial-attempt identity.
    #[must_use]
    pub const fn expected_attempt_id(&self) -> AttemptId {
        self.expected_attempt_id
    }

    /// Returns the durable claim start.
    #[must_use]
    pub const fn claimed_at(&self) -> UnixMillis {
        self.claimed_at
    }

    /// Returns the durable claim expiration.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
}

/// Immutable descriptor and claim evidence returned before blob I/O.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedLogicalInstanceMaterialization {
    descriptor: LogicalInstanceMaterializationDescriptor,
    claim: LogicalMaterializationClaimFence,
    replayed: bool,
}

impl ClaimedLogicalInstanceMaterialization {
    /// Constructs a repository result after exact descriptor/fence checks.
    ///
    /// # Errors
    ///
    /// Rejects a fence that does not bind the supplied descriptor.
    pub fn new(
        descriptor: LogicalInstanceMaterializationDescriptor,
        claim: LogicalMaterializationClaimFence,
        replayed: bool,
    ) -> Result<Self, LogicalMaterializationValueError> {
        if claim.target() != descriptor.target()
            || claim.descriptor_digest() != descriptor.descriptor_digest()
            || claim.runtime_policy() != descriptor.runtime_policy()
            || claim.expected_job_id() != descriptor.expected_job_id()
            || claim.expected_attempt_id() != descriptor.expected_attempt_id()
        {
            return Err(LogicalMaterializationValueError::ClaimDescriptorMismatch);
        }
        Ok(Self {
            descriptor,
            claim,
            replayed,
        })
    }

    /// Returns the exact immutable instance descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &LogicalInstanceMaterializationDescriptor {
        &self.descriptor
    }

    /// Returns the live commit fence.
    #[must_use]
    pub const fn claim(&self) -> &LogicalMaterializationClaimFence {
        &self.claim
    }

    /// Reports whether the exact same claim request was replayed.
    #[must_use]
    pub const fn is_replay(&self) -> bool {
        self.replayed
    }
}

/// Request to replace one live materialization fence with its next generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenewLogicalInstanceMaterialization {
    claim: LogicalMaterializationClaimFence,
    duration_ms: i64,
}

impl RenewLogicalInstanceMaterialization {
    /// Constructs one bounded, extending materialization renewal.
    ///
    /// # Errors
    ///
    /// Rejects a stale or non-extending observation and an overlong interval.
    pub fn new(
        claim: LogicalMaterializationClaimFence,
        duration_ms: i64,
    ) -> Result<Self, LogicalMaterializationValueError> {
        if !(crate::MIN_LOGICAL_WORK_RENEWAL_REQUEST_MILLIS
            ..=MAX_LOGICAL_MATERIALIZATION_CLAIM_MILLIS)
            .contains(&duration_ms)
        {
            return Err(LogicalMaterializationValueError::InvalidRenewalInterval);
        }
        Ok(Self { claim, duration_ms })
    }

    /// Returns the exact current claim proof.
    #[must_use]
    pub const fn claim(&self) -> &LogicalMaterializationClaimFence {
        &self.claim
    }

    /// Returns the requested database-issued renewal duration.
    #[must_use]
    pub const fn duration_ms(&self) -> i64 {
        self.duration_ms
    }
}

/// Non-authorizing acknowledgement of one exact materialization renewal.
///
/// This value is immutable receipt evidence, not a current claim. Callers must
/// consume the retained work selection again before continuing with a fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenewedLogicalInstanceMaterialization {
    request: RenewLogicalInstanceMaterialization,
    successor_generation: LogicalMaterializationGeneration,
    successor_claimed_at: UnixMillis,
    successor_expires_at: UnixMillis,
    validated_at: UnixMillis,
}

impl RenewedLogicalInstanceMaterialization {
    /// Constructs exact, non-authorizing renewal acknowledgement evidence.
    ///
    /// # Errors
    ///
    /// Rejects a non-selector predecessor, a generation skip, or successor
    /// times that do not exactly describe the requested extending interval.
    pub fn new(
        request: RenewLogicalInstanceMaterialization,
        successor_generation: LogicalMaterializationGeneration,
        successor_claimed_at: UnixMillis,
        successor_expires_at: UnixMillis,
        validated_at: UnixMillis,
    ) -> Result<Self, LogicalMaterializationValueError> {
        let predecessor = request.claim();
        let expected_generation = predecessor
            .generation()
            .get()
            .checked_add(1)
            .and_then(|value| LogicalMaterializationGeneration::new(value).ok());
        if expected_generation != Some(successor_generation)
            || successor_claimed_at < predecessor.claimed_at()
            || successor_claimed_at >= predecessor.expires_at()
            || successor_expires_at <= predecessor.expires_at()
            || successor_expires_at
                .get()
                .checked_sub(successor_claimed_at.get())
                != Some(request.duration_ms())
            || validated_at < successor_claimed_at
            || validated_at >= successor_expires_at
        {
            return Err(LogicalMaterializationValueError::InvalidRenewalInterval);
        }
        Ok(Self {
            request,
            successor_generation,
            successor_claimed_at,
            successor_expires_at,
            validated_at,
        })
    }

    /// Returns the exact request acknowledged by this receipt.
    #[must_use]
    pub const fn request(&self) -> &RenewLogicalInstanceMaterialization {
        &self.request
    }

    /// Returns the immutable predecessor fence named by the request.
    #[must_use]
    pub const fn predecessor(&self) -> &LogicalMaterializationClaimFence {
        self.request.claim()
    }

    /// Returns the acknowledged successor generation.
    #[must_use]
    pub const fn successor_generation(&self) -> LogicalMaterializationGeneration {
        self.successor_generation
    }

    /// Returns the acknowledged successor claim start.
    #[must_use]
    pub const fn successor_claimed_at(&self) -> UnixMillis {
        self.successor_claimed_at
    }

    /// Returns the acknowledged successor expiration.
    #[must_use]
    pub const fn successor_expires_at(&self) -> UnixMillis {
        self.successor_expires_at
    }

    /// Returns the immutable database validation time stored with the receipt.
    #[must_use]
    pub const fn validated_at(&self) -> UnixMillis {
        self.validated_at
    }
}

/// Outcome of claiming one exact immutable instance.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)] // Claimed evidence is consumed immediately without boxing.
pub enum LogicalInstanceMaterializationClaimOutcome {
    /// The claim was acquired or exactly replayed.
    Claimed(ClaimedLogicalInstanceMaterialization),
    /// Another worker owns an unexpired claim.
    Busy,
    /// The exact instance already has a durable runnable job.
    Materialized(LogicalMaterializationReceipt),
}

/// Validated commit assembled only after exact `JobIR` blob loading and decode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitLogicalInstanceMaterialization {
    claim: LogicalMaterializationClaimFence,
    job_key: String,
    display_name: String,
    requirements: RunnerRequirements,
    authority_profile: JobAuthorityProfile,
    requirements_json: serde_json::Value,
    requirements_digest: Sha256Digest,
    commit_digest: Sha256Digest,
    committed_at: UnixMillis,
}

impl CommitLogicalInstanceMaterialization {
    /// Verifies decoded `JobIR` evidence and builds one fenced SQL commit.
    ///
    /// `encoded_job_ir` and `encoded_runtime_context` must be the exact
    /// immutable bytes named by the claimed descriptor. Decoding them into
    /// `envelope` and `runtime_context` occurs before this constructor and
    /// therefore outside every repository transaction.
    ///
    /// # Errors
    ///
    /// Rejects blob digest/size mismatch, invalid `JobIR`, any identity or
    /// execution-reference mismatch, or a commit outside the claim interval.
    pub fn new(
        claimed: &ClaimedLogicalInstanceMaterialization,
        encoded_job_ir: &[u8],
        envelope: &JobIrEnvelope,
        encoded_runtime_context: &[u8],
        runtime_context: &JobRuntimeContext,
        committed_at: UnixMillis,
    ) -> Result<Self, LogicalMaterializationValueError> {
        let descriptor = claimed.descriptor();
        let claim = claimed.claim().clone();
        if committed_at < claim.claimed_at() || committed_at >= claim.expires_at() {
            return Err(LogicalMaterializationValueError::CommitOutsideClaim);
        }
        let encoded_size = u64::try_from(encoded_job_ir.len())
            .map_err(|_| LogicalMaterializationValueError::JobIrBlobMismatch)?;
        let encoded_digest = Sha256Digest::from_bytes(Sha256::digest(encoded_job_ir).into());
        if encoded_size != descriptor.job_ir().encoded_size()
            || encoded_digest != descriptor.job_ir().digest()
        {
            return Err(LogicalMaterializationValueError::JobIrBlobMismatch);
        }
        envelope
            .validate()
            .map_err(|_| LogicalMaterializationValueError::InvalidJobIr)?;
        if envelope.schema_version() != JOB_IR_SCHEMA_VERSION {
            return Err(LogicalMaterializationValueError::InvalidJobIr);
        }
        if envelope.job().authority_profile() != descriptor.authority_profile() {
            return Err(LogicalMaterializationValueError::JobIrIdentityMismatch);
        }
        validate_envelope_identity(descriptor, envelope)?;
        validate_runtime_context(descriptor, encoded_runtime_context, runtime_context)?;

        let authority_profile = envelope.job().authority_profile();
        let requirements = envelope.job().requirements().clone();
        let requirements_json = serde_json::to_value(&requirements)
            .map_err(|_| LogicalMaterializationValueError::InvalidRequirements)?;
        let round_trip: RunnerRequirements = serde_json::from_value(requirements_json.clone())
            .map_err(|_| LogicalMaterializationValueError::InvalidRequirements)?;
        if round_trip != requirements {
            return Err(LogicalMaterializationValueError::InvalidRequirements);
        }
        let requirements_bytes = serde_json::to_vec(&requirements_json)
            .map_err(|_| LogicalMaterializationValueError::InvalidRequirements)?;
        let requirements_digest =
            Sha256Digest::from_bytes(Sha256::digest(&requirements_bytes).into());
        let display_name = envelope.job().name().to_owned();
        let job_key = descriptor.job_key().to_owned();
        let commit_digest = materialization_commit_digest(
            &claim,
            &job_key,
            &display_name,
            &requirements_bytes,
            authority_profile,
            committed_at,
        );
        Ok(Self {
            claim,
            job_key,
            display_name,
            requirements,
            authority_profile,
            requirements_json,
            requirements_digest,
            commit_digest,
            committed_at,
        })
    }

    /// Returns the exact live claim proof.
    #[must_use]
    pub const fn claim(&self) -> &LogicalMaterializationClaimFence {
        &self.claim
    }

    /// Returns the deterministic concrete job key.
    #[must_use]
    pub fn job_key(&self) -> &str {
        &self.job_key
    }

    /// Returns the display name decoded from `JobIR`.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Returns typed current runner requirements decoded from `JobIR`.
    #[must_use]
    pub const fn requirements(&self) -> &RunnerRequirements {
        &self.requirements
    }

    /// Returns the validated immutable job-visible authority profile.
    #[must_use]
    pub const fn authority_profile(&self) -> JobAuthorityProfile {
        self.authority_profile
    }

    pub(crate) const fn requirements_json(&self) -> &serde_json::Value {
        &self.requirements_json
    }

    /// Returns the canonical requirements digest.
    #[must_use]
    pub const fn requirements_digest(&self) -> Sha256Digest {
        self.requirements_digest
    }

    /// Returns the canonical exact-commit digest.
    #[must_use]
    pub const fn commit_digest(&self) -> Sha256Digest {
        self.commit_digest
    }

    /// Returns the trusted commit timestamp.
    #[must_use]
    pub const fn committed_at(&self) -> UnixMillis {
        self.committed_at
    }
}

/// Durable receipt for one concrete job and its initial queued attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalMaterializationReceipt {
    instance_id: LogicalWorkflowInstanceId,
    job_id: JobId,
    attempt_id: AttemptId,
    descriptor_digest: Sha256Digest,
    runtime_policy_revision: WorkflowRuntimePolicyRevision,
    runtime_policy_digest: Sha256Digest,
    requirements_digest: Sha256Digest,
    commit_digest: Sha256Digest,
    committed_at: UnixMillis,
    replayed: bool,
}

impl LogicalMaterializationReceipt {
    /// Constructs the exact receipt for a validated commit request.
    #[must_use]
    pub fn new(request: &CommitLogicalInstanceMaterialization, replayed: bool) -> Self {
        Self {
            instance_id: request.claim.target().instance_id(),
            job_id: request.claim.expected_job_id(),
            attempt_id: request.claim.expected_attempt_id(),
            descriptor_digest: request.claim.descriptor_digest(),
            runtime_policy_revision: request.claim.runtime_policy().revision(),
            runtime_policy_digest: request.claim.runtime_policy().digest(),
            requirements_digest: request.requirements_digest,
            commit_digest: request.commit_digest,
            committed_at: request.committed_at,
            replayed,
        }
    }

    /// Rehydrates a store-authenticated receipt.
    ///
    /// # Errors
    ///
    /// Rejects nil identities or a negative commit timestamp.
    #[allow(clippy::too_many_arguments)]
    pub fn from_durable(
        instance_id: LogicalWorkflowInstanceId,
        job_id: JobId,
        attempt_id: AttemptId,
        descriptor_digest: Sha256Digest,
        runtime_policy_revision: WorkflowRuntimePolicyRevision,
        runtime_policy_digest: Sha256Digest,
        requirements_digest: Sha256Digest,
        commit_digest: Sha256Digest,
        committed_at: UnixMillis,
        replayed: bool,
    ) -> Result<Self, LogicalMaterializationValueError> {
        if job_id.as_uuid().is_nil() {
            return Err(LogicalMaterializationValueError::NilUuid("concrete job ID"));
        }
        if attempt_id.as_uuid().is_nil() {
            return Err(LogicalMaterializationValueError::NilUuid(
                "initial attempt ID",
            ));
        }
        validate_timestamp(committed_at, "materialization commit time")?;
        Ok(Self {
            instance_id,
            job_id,
            attempt_id,
            descriptor_digest,
            runtime_policy_revision,
            runtime_policy_digest,
            requirements_digest,
            commit_digest,
            committed_at,
            replayed,
        })
    }

    /// Returns the activated-instance identity.
    #[must_use]
    pub const fn instance_id(&self) -> LogicalWorkflowInstanceId {
        self.instance_id
    }

    /// Returns the runnable concrete job identity.
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    /// Returns the initial queued-attempt identity.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the immutable instance-descriptor digest.
    #[must_use]
    pub const fn descriptor_digest(&self) -> Sha256Digest {
        self.descriptor_digest
    }

    /// Returns the immutable runtime-policy revision.
    #[must_use]
    pub const fn runtime_policy_revision(&self) -> WorkflowRuntimePolicyRevision {
        self.runtime_policy_revision
    }

    /// Returns the immutable runtime-policy digest.
    #[must_use]
    pub const fn runtime_policy_digest(&self) -> Sha256Digest {
        self.runtime_policy_digest
    }

    /// Returns the canonical runner-requirements digest.
    #[must_use]
    pub const fn requirements_digest(&self) -> Sha256Digest {
        self.requirements_digest
    }

    /// Returns the exact commit digest.
    #[must_use]
    pub const fn commit_digest(&self) -> Sha256Digest {
        self.commit_digest
    }

    /// Returns the durable commit timestamp.
    #[must_use]
    pub const fn committed_at(&self) -> UnixMillis {
        self.committed_at
    }

    /// Reports whether prior durable evidence was replayed.
    #[must_use]
    pub const fn is_replay(&self) -> bool {
        self.replayed
    }
}

/// Invalid concrete-job materialization value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LogicalMaterializationValueError {
    /// A durable UUID used the nil sentinel.
    #[error("{0} must not be the nil UUID")]
    NilUuid(&'static str),
    /// A trusted timestamp preceded the Unix epoch.
    #[error("{0} must not precede the Unix epoch")]
    NegativeTimestamp(&'static str),
    /// The claim interval was empty or exceeded its fixed bound.
    #[error("logical materialization claim interval is invalid or too long")]
    InvalidClaimInterval,
    /// The monotonic generation was zero or exceeded `PostgreSQL` `BIGINT`.
    #[error("logical materialization generation is invalid")]
    InvalidGeneration,
    /// A renewal did not extend the exact current live claim.
    #[error("logical materialization renewal interval is invalid")]
    InvalidRenewalInterval,
    /// Durable matrix coordinates were outside the current bound.
    #[error("logical materialization matrix identity is invalid")]
    InvalidMatrixIdentity,
    /// The durable workspace was not a canonical absolute target path.
    #[error("logical materialization workspace is invalid")]
    InvalidWorkspace,
    /// A content descriptor occupied the wrong semantic field.
    #[error("logical materialization object kind is invalid")]
    ObjectKindMismatch,
    /// The runtime-policy pin disagreed with the target tenant or durable chain.
    #[error("logical materialization runtime policy is invalid")]
    RuntimePolicyMismatch,
    /// A claim fence did not bind its immutable descriptor.
    #[error("logical materialization claim does not bind its descriptor")]
    ClaimDescriptorMismatch,
    /// Loaded `JobIR` bytes differed from the immutable blob descriptor.
    #[error("loaded JobIR bytes disagree with the activated descriptor")]
    JobIrBlobMismatch,
    /// Loaded runtime-context bytes differed from the immutable descriptor.
    #[error("loaded runtime-context bytes disagree with the activated descriptor")]
    RuntimeContextBlobMismatch,
    /// The decoded envelope was not valid current `JobIR`.
    #[error("decoded JobIR is invalid or not current schema")]
    InvalidJobIr,
    /// The decoded envelope disagreed with durable identity or content refs.
    #[error("decoded JobIR disagrees with its activated instance")]
    JobIrIdentityMismatch,
    /// The decoded runtime context was not exact current schema or disagreed
    /// with the activated matrix coordinates.
    #[error("decoded runtime context is invalid or disagrees with the activated instance")]
    InvalidRuntimeContext,
    /// Runner requirements failed exact current-schema round-trip validation.
    #[error("decoded runner requirements are invalid")]
    InvalidRequirements,
    /// The commit timestamp was outside the live claim.
    #[error("logical materialization commit falls outside its claim")]
    CommitOutsideClaim,
}

/// Durable materialization claim or commit failure.
#[derive(Debug, Error)]
pub enum LogicalMaterializationStoreError {
    /// The relational store failed or contained malformed current data.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The target is absent, cross-tenant, non-current, or not activated.
    #[error("logical materialization target is not an activated current instance")]
    InvalidTarget,
    /// The monotonic claim generation cannot advance.
    #[error("logical materialization claim generation is exhausted")]
    GenerationExhausted,
    /// Commit did not own the exact current live fence.
    #[error("logical materialization claim fence was rejected")]
    ClaimRejected,
    /// Commit disagreed with immutable durable materialization evidence.
    #[error("logical materialization commit conflicts with durable evidence")]
    CommitConflict,
}

/// Persistence boundary for current activated-instance materialization.
#[async_trait]
pub trait LogicalMaterializationRepository: std::fmt::Debug + Send + Sync {
    /// Replaces one exact live claim with its next generation while preserving
    /// its selector origin.
    async fn renew_logical_instance_materialization(
        &self,
        request: RenewLogicalInstanceMaterialization,
    ) -> Result<RenewedLogicalInstanceMaterialization, LogicalMaterializationStoreError>;

    /// Atomically inserts the deterministic `JobIR` job and its initial
    /// queued attempt under the exact live fence. No legacy dependency edge is
    /// written. Exact same-fence commits replay their receipt.
    async fn commit_logical_instance_materialization(
        &self,
        request: CommitLogicalInstanceMaterialization,
    ) -> Result<LogicalMaterializationReceipt, LogicalMaterializationStoreError>;
}

fn validate_envelope_identity(
    descriptor: &LogicalInstanceMaterializationDescriptor,
    envelope: &JobIrEnvelope,
) -> Result<(), LogicalMaterializationValueError> {
    let job = envelope.job();
    let identity = job.instance_identity();
    let execution = envelope.execution();
    let durable_execution = descriptor.execution();
    let exact = envelope.workflow_id() == durable_execution.workflow_id()
        && job.job_id() == descriptor.expected_job_id()
        && job.run_id() == descriptor.target().run_id()
        && identity.logical_job_key() == descriptor.logical_key().as_str()
        && identity.matrix_index() == descriptor.matrix_index()
        && identity.matrix_total() == descriptor.matrix_total()
        && identity.matrix_digest() == descriptor.matrix_digest()
        && execution.workspace() == descriptor.workspace()
        && execution.workflow_name() == durable_execution.workflow_name()
        && execution.git_ref() == durable_execution.git_ref()
        && execution.actor() == durable_execution.actor()
        && execution.run_id_alias() == Some(durable_execution.run_id_alias())
        && execution.run_number() == Some(durable_execution.run_number())
        && execution.run_attempt() == Some(durable_execution.run_attempt())
        && content_reference_matches_admission(execution.event(), descriptor.event())
        && content_reference_matches_activation(
            execution.runtime_context(),
            descriptor.runtime_context(),
        );
    if exact {
        Ok(())
    } else {
        Err(LogicalMaterializationValueError::JobIrIdentityMismatch)
    }
}

fn validate_runtime_context(
    descriptor: &LogicalInstanceMaterializationDescriptor,
    encoded_runtime_context: &[u8],
    runtime_context: &JobRuntimeContext,
) -> Result<(), LogicalMaterializationValueError> {
    let encoded_size = u64::try_from(encoded_runtime_context.len())
        .map_err(|_| LogicalMaterializationValueError::RuntimeContextBlobMismatch)?;
    let encoded_digest = Sha256Digest::from_bytes(Sha256::digest(encoded_runtime_context).into());
    if encoded_size != descriptor.runtime_context().encoded_size()
        || encoded_digest != descriptor.runtime_context().digest()
    {
        return Err(LogicalMaterializationValueError::RuntimeContextBlobMismatch);
    }
    runtime_context
        .validate()
        .map_err(|_| LogicalMaterializationValueError::InvalidRuntimeContext)?;
    let strategy = runtime_context.strategy();
    if runtime_context.schema_version() != JOB_RUNTIME_CONTEXT_SCHEMA_VERSION
        || strategy.job_index() != descriptor.matrix_index()
        || strategy.job_total() != descriptor.matrix_total()
    {
        return Err(LogicalMaterializationValueError::InvalidRuntimeContext);
    }
    Ok(())
}

fn content_reference_matches_admission(
    reference: &automata_ci_core::JobContentReference,
    object: &AdmissionObject,
) -> bool {
    reference.object_key() == object.object_key().as_str()
        && reference.digest() == object.digest()
        && reference.encoded_size() == object.encoded_size()
        && reference.media_type() == object.media_type()
}

fn content_reference_matches_activation(
    reference: &automata_ci_core::JobContentReference,
    object: &LogicalActivationObject,
) -> bool {
    reference.object_key() == object.object_key().as_str()
        && reference.digest() == object.digest()
        && reference.encoded_size() == object.encoded_size()
        && reference.media_type() == object.media_type()
}

#[allow(clippy::too_many_arguments)] // Canonical digest covers each independent durable field.
fn descriptor_digest(
    target: &LogicalInstanceMaterializationTarget,
    logical_key: &WorkflowJobKey,
    matrix_index: u32,
    matrix_total: u32,
    matrix_digest: Sha256Digest,
    workspace: &str,
    job_ir: &LogicalActivationObject,
    runtime_context: &LogicalActivationObject,
    event: &AdmissionObject,
    execution: &LogicalActivationExecutionContext,
    authority_profile: JobAuthorityProfile,
    runtime_policy: &WorkflowRuntimePolicyPin,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(DESCRIPTOR_DIGEST_DOMAIN);
    hasher.update(target.run_id().as_uuid().as_bytes());
    hasher.update(target.invocation_id().as_uuid().as_bytes());
    hasher.update(target.logical_job_id().as_uuid().as_bytes());
    hasher.update(target.instance_id().as_uuid().as_bytes());
    hash_text(&mut hasher, logical_key.as_str());
    hasher.update(matrix_index.to_be_bytes());
    hasher.update(matrix_total.to_be_bytes());
    hasher.update(matrix_digest.as_bytes());
    hash_text(&mut hasher, workspace);
    hash_activation_object(&mut hasher, job_ir);
    hash_activation_object(&mut hasher, runtime_context);
    hash_admission_object(&mut hasher, event);
    hasher.update(execution.workflow_id().as_uuid().as_bytes());
    hash_text(&mut hasher, execution.workflow_name());
    hash_text(&mut hasher, execution.git_ref());
    hash_optional_text(&mut hasher, execution.actor());
    hasher.update(execution.run_id_alias().get().to_be_bytes());
    hasher.update(execution.run_number().to_be_bytes());
    hasher.update(execution.run_attempt().to_be_bytes());
    hasher.update([authority_profile_code(authority_profile)]);
    hasher.update(runtime_policy.repository_id().as_uuid().as_bytes());
    hasher.update(runtime_policy.revision().get().to_be_bytes());
    hasher.update(runtime_policy.digest().as_bytes());
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn materialization_commit_digest(
    claim: &LogicalMaterializationClaimFence,
    job_key: &str,
    display_name: &str,
    requirements: &[u8],
    authority_profile: JobAuthorityProfile,
    committed_at: UnixMillis,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(COMMIT_DIGEST_DOMAIN);
    hasher.update(claim.target().instance_id().as_uuid().as_bytes());
    hasher.update(claim.owner().as_uuid().as_bytes());
    hasher.update(claim.generation().get().to_be_bytes());
    hasher.update(claim.descriptor_digest().as_bytes());
    hasher.update(claim.runtime_policy().repository_id().as_uuid().as_bytes());
    hasher.update(claim.runtime_policy().revision().get().to_be_bytes());
    hasher.update(claim.runtime_policy().digest().as_bytes());
    hasher.update(claim.expected_job_id().as_uuid().as_bytes());
    hasher.update(claim.expected_attempt_id().as_uuid().as_bytes());
    hash_text(&mut hasher, job_key);
    hash_text(&mut hasher, display_name);
    hash_bytes(&mut hasher, requirements);
    hasher.update([authority_profile_code(authority_profile)]);
    hasher.update(committed_at.get().to_be_bytes());
    Sha256Digest::from_bytes(hasher.finalize().into())
}

const fn authority_profile_code(value: JobAuthorityProfile) -> u8 {
    match value {
        JobAuthorityProfile::Standard => 1,
        JobAuthorityProfile::CredentialFree => 2,
    }
}

fn derive_job_id(
    target: &LogicalInstanceMaterializationTarget,
    matrix_index: u32,
    matrix_total: u32,
    matrix_digest: Sha256Digest,
) -> JobId {
    let mut hasher = Sha256::new();
    hasher.update(JOB_ID_DOMAIN);
    hasher.update(target.run_id().as_uuid().as_bytes());
    hasher.update(target.invocation_id().as_uuid().as_bytes());
    hasher.update(target.logical_job_id().as_uuid().as_bytes());
    hasher.update(matrix_index.to_be_bytes());
    hasher.update(matrix_total.to_be_bytes());
    hasher.update(matrix_digest.as_bytes());
    JobId::from_uuid(uuid_v8(hasher.finalize().into()))
}

fn derive_attempt_id(job_id: JobId) -> AttemptId {
    let mut hasher = Sha256::new();
    hasher.update(ATTEMPT_ID_DOMAIN);
    hasher.update(job_id.as_uuid().as_bytes());
    hasher.update(1_u32.to_be_bytes());
    AttemptId::from_uuid(uuid_v8(hasher.finalize().into()))
}

fn uuid_v8(digest: [u8; 32]) -> Uuid {
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn hash_activation_object(hasher: &mut Sha256, object: &LogicalActivationObject) {
    hasher.update(object.digest().as_bytes());
    hash_text(hasher, object.object_key().as_str());
    hasher.update(object.encoded_size().to_be_bytes());
    hash_text(hasher, object.media_type());
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
    hash_bytes(hasher, value.as_bytes());
}

fn hash_bytes(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn validate_claim_interval(
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
) -> Result<(), LogicalMaterializationValueError> {
    validate_timestamp(claimed_at, "materialization claim start")?;
    validate_timestamp(expires_at, "materialization claim expiration")?;
    expires_at
        .get()
        .checked_sub(claimed_at.get())
        .filter(|duration| *duration > 0 && *duration <= MAX_LOGICAL_MATERIALIZATION_CLAIM_MILLIS)
        .ok_or(LogicalMaterializationValueError::InvalidClaimInterval)?;
    Ok(())
}

fn validate_timestamp(
    value: UnixMillis,
    field: &'static str,
) -> Result<(), LogicalMaterializationValueError> {
    if value.get() < 0 {
        return Err(LogicalMaterializationValueError::NegativeTimestamp(field));
    }
    Ok(())
}

fn validate_workspace(value: &str) -> Result<(), LogicalMaterializationValueError> {
    if value.trim().is_empty() || value.len() > 1_024 || value.chars().any(char::is_control) {
        return Err(LogicalMaterializationValueError::InvalidWorkspace);
    }
    let unix = value.starts_with('/')
        && value != "/"
        && !value.contains("//")
        && value
            .split('/')
            .skip(1)
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."));
    let bytes = value.as_bytes();
    let windows = bytes.len() >= 4
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'\\'
        && !value.contains("\\\\")
        && value
            .split('\\')
            .skip(1)
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."));
    if unix || windows {
        Ok(())
    } else {
        Err(LogicalMaterializationValueError::InvalidWorkspace)
    }
}
