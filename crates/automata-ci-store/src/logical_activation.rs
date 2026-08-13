//! Fenced publication of current logical-job activation descriptors.
//!
//! Blob reads and writes deliberately remain outside this repository port.
//! A worker first claims one dependency-ready logical step job using a digest
//! of its exact immutable activation inputs, writes every resulting blob, and
//! finally publishes only their credential-free descriptors atomically.

use std::num::NonZeroU64;

use async_trait::async_trait;
use automata_ci_core::{
    JOB_IR_SCHEMA_VERSION, JOB_RUNTIME_CONTEXT_SCHEMA_VERSION, JobInstanceIdentity,
    MAX_MATRIX_EXPANSION, RunId, RunIdAlias, Sha256Digest, UnixMillis, WorkflowId, WorkflowJobKey,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    AdmissionObject, JobEnvironmentActivationEvidence, LogicalActivationPreparationReceipt,
    LogicalWorkflowInvocationId, LogicalWorkflowJobId, LogicalWorkflowJobKind, MAX_JOB_IR_BYTES,
    ObjectKey, ReusableWorkflowPermissionSnapshot, StoreError, TenantScope,
    WorkflowRuntimePolicyPin,
};

/// Maximum duration of one logical-job activation claim.
pub const MAX_LOGICAL_ACTIVATION_CLAIM_MILLIS: i64 = 15 * 60 * 1_000;
/// Maximum concrete descriptors published by one matrix activation.
pub const MAX_LOGICAL_ACTIVATED_INSTANCES: usize = MAX_MATRIX_EXPANSION;
/// Exact media type accepted for current `JobIR` blobs.
pub const LOGICAL_ACTIVATION_JOB_IR_MEDIA_TYPE: &str = "application/vnd.automata.job-ir.protobuf";
/// Exact media type accepted for current runtime-context blobs.
pub const LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE: &str =
    "application/vnd.automata.job-runtime-context.protobuf";

const INSTANCE_ID_DOMAIN: &[u8] = b"automata.store.logical-instance-id.v1\0";
const PUBLICATION_DIGEST_DOMAIN: &[u8] = b"automata.store.logical-activation-output.v1\0";

/// Non-nil durable identity of an activation worker.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalActivationWorkerId(Uuid);

impl LogicalActivationWorkerId {
    /// Constructs a non-nil worker identity.
    ///
    /// # Errors
    ///
    /// Rejects the nil UUID sentinel.
    pub fn from_uuid(value: Uuid) -> Result<Self, LogicalActivationValueError> {
        if value.is_nil() {
            return Err(LogicalActivationValueError::NilUuid(
                "logical activation worker ID",
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

/// Positive monotonic generation of one logical-job activation claim.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalActivationGeneration(NonZeroU64);

impl LogicalActivationGeneration {
    /// Constructs a positive generation representable by `PostgreSQL` `BIGINT`.
    ///
    /// # Errors
    ///
    /// Rejects zero and values larger than `i64::MAX`.
    pub fn new(value: u64) -> Result<Self, LogicalActivationValueError> {
        let value = NonZeroU64::new(value)
            .filter(|value| i64::try_from(value.get()).is_ok())
            .ok_or(LogicalActivationValueError::InvalidGeneration)?;
        Ok(Self(value))
    }

    /// Returns the numeric generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    pub(crate) fn as_i64(self) -> i64 {
        i64::try_from(self.get()).expect("validated activation generation fits in i64")
    }
}

/// Deterministic identity of one expanded logical-job instance descriptor.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalWorkflowInstanceId(Uuid);

impl LogicalWorkflowInstanceId {
    /// Rehydrates a non-nil deterministic instance identity.
    ///
    /// # Errors
    ///
    /// Rejects the nil UUID sentinel.
    pub fn from_uuid(value: Uuid) -> Result<Self, LogicalActivationValueError> {
        if value.is_nil() {
            return Err(LogicalActivationValueError::NilUuid(
                "logical workflow instance ID",
            ));
        }
        Ok(Self(value))
    }

    fn derive(
        run_id: RunId,
        invocation_id: LogicalWorkflowInvocationId,
        logical_job_id: LogicalWorkflowJobId,
        identity: &JobInstanceIdentity,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(INSTANCE_ID_DOMAIN);
        hasher.update(run_id.as_uuid().as_bytes());
        hasher.update(invocation_id.as_uuid().as_bytes());
        hasher.update(logical_job_id.as_uuid().as_bytes());
        hasher.update(identity.matrix_index().to_be_bytes());
        hasher.update(identity.matrix_total().to_be_bytes());
        hasher.update(identity.matrix_digest().as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        // RFC 9562 version 8 is reserved for application-defined UUID layouts.
        bytes[6] = (bytes[6] & 0x0f) | 0x80;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Self(Uuid::from_bytes(bytes))
    }

    /// Returns the deterministic UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

/// Request to acquire or take over one exact logical step-job activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimLogicalJobActivation {
    tenant: TenantScope,
    run_id: RunId,
    invocation_id: LogicalWorkflowInvocationId,
    logical_job_id: LogicalWorkflowJobId,
    owner: LogicalActivationWorkerId,
    runtime_policy: WorkflowRuntimePolicyPin,
    input_digest: Sha256Digest,
    observed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl ClaimLogicalJobActivation {
    /// Constructs a bounded exact-target claim request.
    ///
    /// `input_digest` is the caller's domain-separated digest of the exact
    /// immutable plan, event, prerequisite results, public outputs, inputs,
    /// variables, secret bindings, and aggregate status used by activation.
    /// A takeover must present the same digest.
    ///
    /// # Errors
    ///
    /// Rejects nil run identities, negative time, an empty interval, or an
    /// interval longer than [`MAX_LOGICAL_ACTIVATION_CLAIM_MILLIS`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: TenantScope,
        run_id: RunId,
        invocation_id: LogicalWorkflowInvocationId,
        logical_job_id: LogicalWorkflowJobId,
        owner: LogicalActivationWorkerId,
        runtime_policy: WorkflowRuntimePolicyPin,
        input_digest: Sha256Digest,
        observed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, LogicalActivationValueError> {
        if run_id.as_uuid().is_nil() {
            return Err(LogicalActivationValueError::NilUuid("workflow run ID"));
        }
        if runtime_policy.tenant() != &tenant {
            return Err(LogicalActivationValueError::RuntimePolicyMismatch);
        }
        validate_timestamp(observed_at, "activation claim observation")?;
        validate_timestamp(expires_at, "activation claim expiration")?;
        expires_at
            .get()
            .checked_sub(observed_at.get())
            .filter(|duration| *duration > 0 && *duration <= MAX_LOGICAL_ACTIVATION_CLAIM_MILLIS)
            .ok_or(LogicalActivationValueError::InvalidClaimInterval)?;
        Ok(Self {
            tenant,
            run_id,
            invocation_id,
            logical_job_id,
            owner,
            runtime_policy,
            input_digest,
            observed_at,
            expires_at,
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

    /// Returns the worker identity.
    #[must_use]
    pub const fn owner(&self) -> LogicalActivationWorkerId {
        self.owner
    }

    /// Returns the exact immutable runtime policy pinned to this run.
    #[must_use]
    pub const fn runtime_policy(&self) -> &WorkflowRuntimePolicyPin {
        &self.runtime_policy
    }

    /// Returns the exact activation-input digest.
    #[must_use]
    pub const fn input_digest(&self) -> Sha256Digest {
        self.input_digest
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

/// Exact owner/generation/input proof required for publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalActivationClaimFence {
    tenant: TenantScope,
    run_id: RunId,
    invocation_id: LogicalWorkflowInvocationId,
    logical_job_id: LogicalWorkflowJobId,
    owner: LogicalActivationWorkerId,
    runtime_policy: WorkflowRuntimePolicyPin,
    generation: LogicalActivationGeneration,
    input_digest: Sha256Digest,
    selection_origin: crate::LogicalWorkSelectionId,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl LogicalActivationClaimFence {
    /// Rehydrates inert selector-origin fence evidence for a repository adapter.
    ///
    /// Construction does not confer durable authority. Renew, publish, and
    /// quarantine operations still compare every field under repository locks.
    ///
    /// # Errors
    ///
    /// Rejects invalid identities, policy binding, or claim interval.
    #[allow(clippy::too_many_arguments)]
    pub fn new_for_selection(
        tenant: TenantScope,
        run_id: RunId,
        invocation_id: LogicalWorkflowInvocationId,
        logical_job_id: LogicalWorkflowJobId,
        owner: LogicalActivationWorkerId,
        runtime_policy: WorkflowRuntimePolicyPin,
        generation: LogicalActivationGeneration,
        input_digest: Sha256Digest,
        claimed_at: UnixMillis,
        expires_at: UnixMillis,
        selection_origin: crate::LogicalWorkSelectionId,
    ) -> Result<Self, LogicalActivationValueError> {
        if run_id.as_uuid().is_nil() {
            return Err(LogicalActivationValueError::NilUuid("workflow run ID"));
        }
        if runtime_policy.tenant() != &tenant {
            return Err(LogicalActivationValueError::RuntimePolicyMismatch);
        }
        validate_timestamp(claimed_at, "activation claim start")?;
        validate_timestamp(expires_at, "activation claim expiration")?;
        expires_at
            .get()
            .checked_sub(claimed_at.get())
            .filter(|duration| *duration > 0 && *duration <= MAX_LOGICAL_ACTIVATION_CLAIM_MILLIS)
            .ok_or(LogicalActivationValueError::InvalidClaimInterval)?;
        Ok(Self {
            tenant,
            run_id,
            invocation_id,
            logical_job_id,
            owner,
            runtime_policy,
            generation,
            input_digest,
            selection_origin,
            claimed_at,
            expires_at,
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

    /// Returns the claim owner.
    #[must_use]
    pub const fn owner(&self) -> LogicalActivationWorkerId {
        self.owner
    }

    /// Returns the exact immutable runtime policy pinned to this run.
    #[must_use]
    pub const fn runtime_policy(&self) -> &WorkflowRuntimePolicyPin {
        &self.runtime_policy
    }

    /// Returns the monotonic claim generation.
    #[must_use]
    pub const fn generation(&self) -> LogicalActivationGeneration {
        self.generation
    }

    /// Returns the exact immutable activation-input digest.
    #[must_use]
    pub const fn input_digest(&self) -> Sha256Digest {
        self.input_digest
    }

    /// Returns the mandatory exact selector origin.
    #[must_use]
    pub const fn selection_origin(&self) -> crate::LogicalWorkSelectionId {
        self.selection_origin
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

/// Request to renew one exact live activation claim without holding a
/// transaction across blob reads or writes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenewLogicalJobActivation {
    claim: LogicalActivationClaimFence,
    duration_ms: i64,
}

impl RenewLogicalJobActivation {
    /// Constructs a bounded extension of a currently live claim.
    ///
    /// Renewal advances the durable generation. `observed_at` must be within
    /// the current claim and `expires_at` must extend its prior expiration by
    /// no more than one claim interval from the new observation.
    ///
    /// # Errors
    ///
    /// Rejects negative time, stale observations, non-extending expiration,
    /// or an interval longer than [`MAX_LOGICAL_ACTIVATION_CLAIM_MILLIS`].
    pub fn new(
        claim: LogicalActivationClaimFence,
        duration_ms: i64,
    ) -> Result<Self, LogicalActivationValueError> {
        if !(crate::MIN_LOGICAL_WORK_RENEWAL_REQUEST_MILLIS..=MAX_LOGICAL_ACTIVATION_CLAIM_MILLIS)
            .contains(&duration_ms)
        {
            return Err(LogicalActivationValueError::InvalidRenewalInterval);
        }
        Ok(Self { claim, duration_ms })
    }

    /// Returns the exact current claim proof.
    #[must_use]
    pub const fn claim(&self) -> &LogicalActivationClaimFence {
        &self.claim
    }

    /// Returns the requested database-issued renewal duration.
    #[must_use]
    pub const fn duration_ms(&self) -> i64 {
        self.duration_ms
    }
}

/// Non-authorizing acknowledgement of one exact activation renewal.
///
/// This value is immutable receipt evidence, not a current claim. Callers must
/// consume the retained work selection again before continuing with a fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenewedLogicalJobActivation {
    request: RenewLogicalJobActivation,
    successor_generation: LogicalActivationGeneration,
    successor_claimed_at: UnixMillis,
    successor_expires_at: UnixMillis,
    validated_at: UnixMillis,
}

impl RenewedLogicalJobActivation {
    /// Constructs exact, non-authorizing renewal acknowledgement evidence.
    ///
    /// # Errors
    ///
    /// Rejects a non-selector predecessor, a generation skip, or successor
    /// times that do not exactly describe the requested extending interval.
    pub fn new(
        request: RenewLogicalJobActivation,
        successor_generation: LogicalActivationGeneration,
        successor_claimed_at: UnixMillis,
        successor_expires_at: UnixMillis,
        validated_at: UnixMillis,
    ) -> Result<Self, LogicalActivationValueError> {
        let predecessor = request.claim();
        let expected_generation = predecessor
            .generation()
            .get()
            .checked_add(1)
            .and_then(|value| LogicalActivationGeneration::new(value).ok());
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
            return Err(LogicalActivationValueError::InvalidRenewalInterval);
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
    pub const fn request(&self) -> &RenewLogicalJobActivation {
        &self.request
    }

    /// Returns the immutable predecessor fence named by the request.
    #[must_use]
    pub const fn predecessor(&self) -> &LogicalActivationClaimFence {
        self.request.claim()
    }

    /// Returns the acknowledged successor generation.
    #[must_use]
    pub const fn successor_generation(&self) -> LogicalActivationGeneration {
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

/// Immutable current-plan evidence returned under a logical activation claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedLogicalJobActivation {
    claim: LogicalActivationClaimFence,
    logical_key: WorkflowJobKey,
    source_order: u16,
    kind: LogicalWorkflowJobKind,
    execution: LogicalActivationExecutionContext,
    plan: AdmissionObject,
    event: AdmissionObject,
    preparation: Option<LogicalActivationPreparationReceipt>,
    replayed: bool,
}

impl ClaimedLogicalJobActivation {
    /// Rehydrates validated evidence returned by a repository adapter or
    /// synthetic repository implementation.
    ///
    /// # Errors
    ///
    /// Rejects non-step jobs and source orders outside the current logical
    /// plan bound.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        claim: LogicalActivationClaimFence,
        logical_key: WorkflowJobKey,
        source_order: u16,
        kind: LogicalWorkflowJobKind,
        execution: LogicalActivationExecutionContext,
        plan: AdmissionObject,
        event: AdmissionObject,
        replayed: bool,
    ) -> Result<Self, LogicalActivationValueError> {
        Self::new_inner(
            claim,
            logical_key,
            source_order,
            kind,
            execution,
            plan,
            event,
            None,
            replayed,
        )
    }

    /// Rehydrates activation evidence with its exact immutable preparation
    /// binding.
    ///
    /// This constructor remains non-authorizing. Durable renewal and
    /// publication still validate the claim and its selector origin in the
    /// repository transaction.
    ///
    /// # Errors
    ///
    /// Rejects a preparation for another target, policy pin, or activation
    /// input digest.
    pub fn new_with_preparation(
        claim: LogicalActivationClaimFence,
        preparation: LogicalActivationPreparationReceipt,
        replayed: bool,
    ) -> Result<Self, LogicalActivationValueError> {
        let descriptor = preparation.descriptor();
        let target = descriptor.target();
        if target.tenant() != claim.tenant()
            || target.run_id() != claim.run_id()
            || target.invocation_id() != claim.invocation_id()
            || target.logical_job_id() != claim.logical_job_id()
            || descriptor.runtime_policy().pin() != claim.runtime_policy()
            || preparation.input_digest() != claim.input_digest()
        {
            return Err(LogicalActivationValueError::PreparationClaimMismatch);
        }
        Self::new_inner(
            claim,
            descriptor.logical_key().clone(),
            descriptor.source_order(),
            LogicalWorkflowJobKind::Steps,
            descriptor.execution().clone(),
            descriptor.plan().clone(),
            descriptor.event().clone(),
            Some(preparation),
            replayed,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_inner(
        claim: LogicalActivationClaimFence,
        logical_key: WorkflowJobKey,
        source_order: u16,
        kind: LogicalWorkflowJobKind,
        execution: LogicalActivationExecutionContext,
        plan: AdmissionObject,
        event: AdmissionObject,
        preparation: Option<LogicalActivationPreparationReceipt>,
        replayed: bool,
    ) -> Result<Self, LogicalActivationValueError> {
        if kind != LogicalWorkflowJobKind::Steps {
            return Err(LogicalActivationValueError::UnsupportedJobKind);
        }
        if source_order > 1_023 {
            return Err(LogicalActivationValueError::InvalidSourceOrder);
        }
        Ok(Self {
            claim,
            logical_key,
            source_order,
            kind,
            execution,
            plan,
            event,
            preparation,
            replayed,
        })
    }

    /// Returns the exact publication fence.
    #[must_use]
    pub const fn claim(&self) -> &LogicalActivationClaimFence {
        &self.claim
    }

    /// Returns the stable source-level job key.
    #[must_use]
    pub const fn logical_key(&self) -> &WorkflowJobKey {
        &self.logical_key
    }

    /// Returns the canonical source order.
    #[must_use]
    pub const fn source_order(&self) -> u16 {
        self.source_order
    }

    /// Returns the admitted execution kind.
    #[must_use]
    pub const fn kind(&self) -> LogicalWorkflowJobKind {
        self.kind
    }

    /// Returns store-authenticated immutable workflow execution metadata.
    #[must_use]
    pub const fn execution(&self) -> &LogicalActivationExecutionContext {
        &self.execution
    }

    /// Returns the immutable logical workflow descriptor.
    #[must_use]
    pub const fn plan(&self) -> &AdmissionObject {
        &self.plan
    }

    /// Returns the immutable event descriptor.
    #[must_use]
    pub const fn event(&self) -> &AdmissionObject {
        &self.event
    }

    /// Returns the exact immutable preparation binding when the repository
    /// loaded it as part of the current activation authority.
    #[must_use]
    pub const fn preparation(&self) -> Option<&LogicalActivationPreparationReceipt> {
        self.preparation.as_ref()
    }

    /// Reports whether this was an exact replay of the same claim request.
    #[must_use]
    pub const fn is_replay(&self) -> bool {
        self.replayed
    }
}

/// Store-authenticated workflow metadata needed to project current `JobIR`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalActivationExecutionContext {
    workflow_id: WorkflowId,
    workflow_name: String,
    git_ref: String,
    root_event_name: String,
    actor: Option<String>,
    triggering_actor: Option<String>,
    run_id_alias: RunIdAlias,
    run_number: u64,
    run_attempt: u32,
}

impl LogicalActivationExecutionContext {
    /// Constructs expected current execution metadata for exact comparison
    /// with the store-issued claim context.
    ///
    /// This constructor does not confer claim authority; only a
    /// [`ClaimedLogicalJobActivation`] returned by the repository does so.
    ///
    /// # Errors
    ///
    /// Rejects nil workflow identity, invalid execution text or Git ref, and
    /// zero run-number/attempt sentinels.
    #[allow(clippy::too_many_arguments)] // Mirrors immutable workflow-run execution evidence.
    pub fn new(
        workflow_id: WorkflowId,
        workflow_name: String,
        git_ref: String,
        root_event_name: String,
        actor: Option<String>,
        run_id_alias: RunIdAlias,
        run_number: u64,
        run_attempt: u32,
    ) -> Result<Self, LogicalActivationValueError> {
        if workflow_id.as_uuid().is_nil() {
            return Err(LogicalActivationValueError::NilUuid("workflow ID"));
        }
        validate_bounded_text(&workflow_name, "workflow name")?;
        validate_bounded_text(&git_ref, "Git ref")?;
        validate_bounded_text(&root_event_name, "root event name")?;
        if !git_ref.starts_with("refs/") || git_ref == "refs/" {
            return Err(LogicalActivationValueError::InvalidGitRef);
        }
        if let Some(actor) = actor.as_deref() {
            validate_bounded_text(actor, "actor")?;
        }
        if run_number == 0 {
            return Err(LogicalActivationValueError::InvalidRunNumber);
        }
        if run_attempt == 0 {
            return Err(LogicalActivationValueError::InvalidRunAttempt);
        }
        Ok(Self {
            workflow_id,
            workflow_name,
            git_ref,
            root_event_name,
            actor,
            triggering_actor: None,
            run_id_alias,
            run_number,
            run_attempt,
        })
    }

    /// Returns the workflow definition identity.
    #[must_use]
    pub const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }

    /// Returns the admitted workflow display name.
    #[must_use]
    pub fn workflow_name(&self) -> &str {
        &self.workflow_name
    }

    /// Returns the canonical full Git reference.
    #[must_use]
    pub fn git_ref(&self) -> &str {
        &self.git_ref
    }

    /// Returns the immutable authenticated event name admitted for the root run.
    ///
    /// Reusable-workflow plans use the synthetic `workflow_call` trigger, so
    /// security policy must use this run-level provenance rather than the
    /// child plan trigger when classifying fork and automation trust.
    #[must_use]
    pub fn root_event_name(&self) -> &str {
        &self.root_event_name
    }

    /// Returns the authenticated event actor when one was admitted.
    #[must_use]
    pub fn actor(&self) -> Option<&str> {
        self.actor.as_deref()
    }

    /// Returns the current physical-attempt initiator when this is a rerun.
    #[must_use]
    pub fn triggering_actor(&self) -> Option<&str> {
        self.triggering_actor.as_deref()
    }

    /// Attaches the store-authenticated current physical-attempt initiator.
    ///
    /// # Errors
    ///
    /// Rejects blank, oversized, or control-bearing actor identities.
    pub fn with_triggering_actor(
        mut self,
        triggering_actor: impl Into<String>,
    ) -> Result<Self, LogicalActivationValueError> {
        let triggering_actor = triggering_actor.into();
        validate_bounded_text(&triggering_actor, "triggering actor")?;
        self.triggering_actor = Some(triggering_actor);
        Ok(self)
    }

    /// Returns the stable positive numeric alias for the internal run ID.
    #[must_use]
    pub const fn run_id_alias(&self) -> RunIdAlias {
        self.run_id_alias
    }

    /// Returns the one-based workflow run number.
    #[must_use]
    pub const fn run_number(&self) -> u64 {
        self.run_number
    }

    /// Returns the one-based run attempt.
    #[must_use]
    pub const fn run_attempt(&self) -> u32 {
        self.run_attempt
    }
}

/// Kind of an immutable activation-produced blob.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LogicalActivationObjectKind {
    JobIr,
    RuntimeContext,
}

/// Immutable credential-free blob descriptor produced before publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalActivationObject {
    kind: LogicalActivationObjectKind,
    digest: Sha256Digest,
    object_key: ObjectKey,
    encoded_size: u64,
}

impl LogicalActivationObject {
    /// Constructs an exact current `JobIR` descriptor.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized blob.
    pub fn job_ir(
        digest: Sha256Digest,
        object_key: ObjectKey,
        encoded_size: u64,
    ) -> Result<Self, LogicalActivationValueError> {
        Self::new(
            LogicalActivationObjectKind::JobIr,
            digest,
            object_key,
            encoded_size,
        )
    }

    /// Constructs an exact current runtime-context descriptor.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized blob.
    pub fn runtime_context(
        digest: Sha256Digest,
        object_key: ObjectKey,
        encoded_size: u64,
    ) -> Result<Self, LogicalActivationValueError> {
        Self::new(
            LogicalActivationObjectKind::RuntimeContext,
            digest,
            object_key,
            encoded_size,
        )
    }

    fn new(
        kind: LogicalActivationObjectKind,
        digest: Sha256Digest,
        object_key: ObjectKey,
        encoded_size: u64,
    ) -> Result<Self, LogicalActivationValueError> {
        if encoded_size == 0 || encoded_size > MAX_JOB_IR_BYTES {
            return Err(LogicalActivationValueError::InvalidObjectSize);
        }
        Ok(Self {
            kind,
            digest,
            object_key,
            encoded_size,
        })
    }

    /// Returns the exact object digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Returns the logical immutable object key.
    #[must_use]
    pub const fn object_key(&self) -> &ObjectKey {
        &self.object_key
    }

    /// Returns the exact encoded byte length.
    #[must_use]
    pub const fn encoded_size(&self) -> u64 {
        self.encoded_size
    }

    /// Returns the exact current media type.
    #[must_use]
    pub const fn media_type(&self) -> &'static str {
        match self.kind {
            LogicalActivationObjectKind::JobIr => LOGICAL_ACTIVATION_JOB_IR_MEDIA_TYPE,
            LogicalActivationObjectKind::RuntimeContext => {
                LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE
            }
        }
    }

    pub(crate) const fn is_job_ir(&self) -> bool {
        matches!(self.kind, LogicalActivationObjectKind::JobIr)
    }

    pub(crate) const fn is_runtime_context(&self) -> bool {
        matches!(self.kind, LogicalActivationObjectKind::RuntimeContext)
    }
}

/// One deterministic immutable matrix-instance publication descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivatedLogicalInstanceDescriptor {
    id: LogicalWorkflowInstanceId,
    run_id: RunId,
    invocation_id: LogicalWorkflowInvocationId,
    logical_job_id: LogicalWorkflowJobId,
    matrix_index: u32,
    matrix_total: u32,
    matrix_digest: Sha256Digest,
    workspace: String,
    job_ir: LogicalActivationObject,
    runtime_context: LogicalActivationObject,
    environment_gate: Option<JobEnvironmentActivationEvidence>,
}

impl ActivatedLogicalInstanceDescriptor {
    /// Constructs a descriptor bound to the claimed job and derives its stable
    /// UUID from immutable run/job/matrix identity. The UUID intentionally
    /// excludes claim generation so crash takeover reproduces it exactly.
    ///
    /// # Errors
    ///
    /// Rejects a logical key that does not match the claimed job or object
    /// descriptors of the wrong kind. Value-free environment-gate evidence is
    /// mandatory for every newly constructed instance; only historical durable
    /// decoding may represent a pre-evidence row.
    pub fn new(
        claimed: &ClaimedLogicalJobActivation,
        identity: &JobInstanceIdentity,
        workspace: impl Into<String>,
        job_ir: LogicalActivationObject,
        runtime_context: LogicalActivationObject,
        environment_gate: JobEnvironmentActivationEvidence,
    ) -> Result<Self, LogicalActivationValueError> {
        if identity.logical_job_key() != claimed.logical_key().as_str() {
            return Err(LogicalActivationValueError::LogicalKeyMismatch);
        }
        if !job_ir.is_job_ir() || !runtime_context.is_runtime_context() {
            return Err(LogicalActivationValueError::ObjectKindMismatch);
        }
        let workspace = workspace.into();
        validate_workspace(&workspace)?;
        let claim = claimed.claim();
        Ok(Self {
            id: LogicalWorkflowInstanceId::derive(
                claim.run_id(),
                claim.invocation_id(),
                claim.logical_job_id(),
                identity,
            ),
            run_id: claim.run_id(),
            invocation_id: claim.invocation_id(),
            logical_job_id: claim.logical_job_id(),
            matrix_index: identity.matrix_index(),
            matrix_total: identity.matrix_total(),
            matrix_digest: identity.matrix_digest(),
            workspace,
            job_ir,
            runtime_context,
            environment_gate: Some(environment_gate),
        })
    }

    /// Replaces the value-free evidence while constructing a divergent test or
    /// retry candidate. A descriptor can never transition back to no evidence.
    #[must_use]
    pub fn with_environment_gate(mut self, evidence: JobEnvironmentActivationEvidence) -> Self {
        self.environment_gate = Some(evidence);
        self
    }

    /// Decodes either a current instance or retained pre-evidence history.
    ///
    /// `None` is accepted only on this internal durable path so terminal rows
    /// written before the evidence migration remain readable.
    #[allow(clippy::too_many_arguments)] // Mirrors one immutable durable descriptor row exactly.
    pub(crate) fn from_durable(
        id: LogicalWorkflowInstanceId,
        run_id: RunId,
        invocation_id: LogicalWorkflowInvocationId,
        logical_job_id: LogicalWorkflowJobId,
        matrix_index: u32,
        matrix_total: u32,
        matrix_digest: Sha256Digest,
        workspace: String,
        job_ir: LogicalActivationObject,
        runtime_context: LogicalActivationObject,
        environment_gate: Option<JobEnvironmentActivationEvidence>,
    ) -> Result<Self, LogicalActivationValueError> {
        let maximum_instances = u32::try_from(MAX_LOGICAL_ACTIVATED_INSTANCES)
            .map_err(|_| LogicalActivationValueError::NoncanonicalMatrixInstances)?;
        if matrix_total == 0
            || matrix_total > maximum_instances
            || matrix_index >= matrix_total
            || !job_ir.is_job_ir()
            || !runtime_context.is_runtime_context()
        {
            return Err(LogicalActivationValueError::NoncanonicalMatrixInstances);
        }
        validate_workspace(&workspace)?;
        Ok(Self {
            id,
            run_id,
            invocation_id,
            logical_job_id,
            matrix_index,
            matrix_total,
            matrix_digest,
            workspace,
            job_ir,
            runtime_context,
            environment_gate,
        })
    }

    /// Returns the deterministic instance identity.
    #[must_use]
    pub const fn id(&self) -> LogicalWorkflowInstanceId {
        self.id
    }

    /// Returns the zero-based matrix index.
    #[must_use]
    pub const fn matrix_index(&self) -> u32 {
        self.matrix_index
    }

    /// Returns the total expansion count.
    #[must_use]
    pub const fn matrix_total(&self) -> u32 {
        self.matrix_total
    }

    /// Returns the exact matrix-value digest.
    #[must_use]
    pub const fn matrix_digest(&self) -> Sha256Digest {
        self.matrix_digest
    }

    /// Returns the server-selected canonical workspace for this instance.
    #[must_use]
    pub fn workspace(&self) -> &str {
        &self.workspace
    }

    /// Returns the current `JobIR` object descriptor.
    #[must_use]
    pub const fn job_ir(&self) -> &LogicalActivationObject {
        &self.job_ir
    }

    /// Returns the current runtime-context object descriptor.
    #[must_use]
    pub const fn runtime_context(&self) -> &LogicalActivationObject {
        &self.runtime_context
    }

    /// Returns value-free activation evidence retained outside `JobIR`.
    #[must_use]
    pub const fn environment_gate(&self) -> Option<&JobEnvironmentActivationEvidence> {
        self.environment_gate.as_ref()
    }
}

/// Atomic publication of zero or more already-written instance blobs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishLogicalJobActivation {
    claim: LogicalActivationClaimFence,
    condition_matched: bool,
    instances: Vec<ActivatedLogicalInstanceDescriptor>,
    output_digest: Sha256Digest,
    published_at: UnixMillis,
}

impl PublishLogicalJobActivation {
    /// Constructs and hashes one canonical activation result.
    ///
    /// A false condition requires zero instances. A matched condition may also
    /// produce zero instances when a dynamic matrix expands to the empty set.
    /// Non-empty matrices must be in exact zero-based index order and carry the
    /// same total equal to the descriptor count.
    ///
    /// # Errors
    ///
    /// Rejects descriptors for another claim, noncanonical matrix identity,
    /// too many instances, or publication outside the live claim interval.
    pub fn new(
        claim: LogicalActivationClaimFence,
        condition_matched: bool,
        instances: Vec<ActivatedLogicalInstanceDescriptor>,
        published_at: UnixMillis,
    ) -> Result<Self, LogicalActivationValueError> {
        validate_timestamp(published_at, "activation publication time")?;
        if published_at < claim.claimed_at() || published_at >= claim.expires_at() {
            return Err(LogicalActivationValueError::PublicationOutsideClaim);
        }
        if instances.len() > MAX_LOGICAL_ACTIVATED_INSTANCES {
            return Err(LogicalActivationValueError::TooManyInstances);
        }
        if !condition_matched && !instances.is_empty() {
            return Err(LogicalActivationValueError::UnmatchedConditionHasInstances);
        }
        let total = u32::try_from(instances.len())
            .map_err(|_| LogicalActivationValueError::TooManyInstances)?;
        for (index, instance) in instances.iter().enumerate() {
            let index =
                u32::try_from(index).map_err(|_| LogicalActivationValueError::TooManyInstances)?;
            if instance.run_id != claim.run_id()
                || instance.invocation_id != claim.invocation_id()
                || instance.logical_job_id != claim.logical_job_id()
            {
                return Err(LogicalActivationValueError::DescriptorClaimMismatch);
            }
            if instance.matrix_index() != index || instance.matrix_total() != total {
                return Err(LogicalActivationValueError::NoncanonicalMatrixInstances);
            }
        }
        let output_digest = publication_digest(&claim, condition_matched, &instances);
        Ok(Self {
            claim,
            condition_matched,
            instances,
            output_digest,
            published_at,
        })
    }

    /// Returns the exact claim fence.
    #[must_use]
    pub const fn claim(&self) -> &LogicalActivationClaimFence {
        &self.claim
    }

    /// Reports whether the job condition matched.
    #[must_use]
    pub const fn condition_matched(&self) -> bool {
        self.condition_matched
    }

    /// Returns canonical matrix-instance descriptors.
    #[must_use]
    pub fn instances(&self) -> &[ActivatedLogicalInstanceDescriptor] {
        &self.instances
    }

    /// Returns the canonical activation-output digest.
    #[must_use]
    pub const fn output_digest(&self) -> Sha256Digest {
        self.output_digest
    }

    /// Returns the trusted publication timestamp.
    #[must_use]
    pub const fn published_at(&self) -> UnixMillis {
        self.published_at
    }
}

/// Receipt for an initial or exactly replayed activation publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalActivationPublicationReceipt {
    claim: LogicalActivationClaimFence,
    condition_matched: bool,
    output_digest: Sha256Digest,
    instance_count: u16,
    published_at: UnixMillis,
    replayed: bool,
}

impl LogicalActivationPublicationReceipt {
    /// Constructs the exact receipt for a validated publication request in a
    /// repository adapter or synthetic repository implementation.
    #[must_use]
    pub fn new(request: &PublishLogicalJobActivation, replayed: bool) -> Self {
        Self {
            claim: request.claim.clone(),
            condition_matched: request.condition_matched,
            output_digest: request.output_digest,
            instance_count: u16::try_from(request.instances.len()).unwrap_or(u16::MAX),
            published_at: request.published_at,
            replayed,
        }
    }

    /// Returns the terminal claim proof.
    #[must_use]
    pub const fn claim(&self) -> &LogicalActivationClaimFence {
        &self.claim
    }

    /// Reports whether the job condition matched.
    #[must_use]
    pub const fn condition_matched(&self) -> bool {
        self.condition_matched
    }

    /// Returns the canonical output digest.
    #[must_use]
    pub const fn output_digest(&self) -> Sha256Digest {
        self.output_digest
    }

    /// Returns the immutable instance count.
    #[must_use]
    pub const fn instance_count(&self) -> u16 {
        self.instance_count
    }

    /// Returns the durable publication time.
    #[must_use]
    pub const fn published_at(&self) -> UnixMillis {
        self.published_at
    }

    /// Reports whether exact prior publication evidence was replayed.
    #[must_use]
    pub const fn is_replay(&self) -> bool {
        self.replayed
    }
}

/// Invalid activation persistence value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LogicalActivationValueError {
    /// A durable UUID was the nil sentinel.
    #[error("{0} must not be the nil UUID")]
    NilUuid(&'static str),
    /// A trusted timestamp preceded the Unix epoch.
    #[error("{0} must not precede the Unix epoch")]
    NegativeTimestamp(&'static str),
    /// The claim interval was empty or exceeded its fixed bound.
    #[error("logical activation claim interval is invalid or too long")]
    InvalidClaimInterval,
    /// Renewal did not extend a live claim within the fixed duration bound.
    #[error("logical activation renewal interval is invalid or does not extend the live claim")]
    InvalidRenewalInterval,
    /// The durable generation did not fit a positive `PostgreSQL` `BIGINT`.
    #[error("logical activation generation must be positive and fit PostgreSQL BIGINT")]
    InvalidGeneration,
    /// An object was empty or exceeded the current blob bound.
    #[error("logical activation object size is outside the current bound")]
    InvalidObjectSize,
    /// Store-authenticated execution text violated its current bound.
    #[error("{0} is empty, oversized, or contains a control character")]
    InvalidExecutionText(&'static str),
    /// The admitted Git reference was not a canonical full reference.
    #[error("logical activation Git ref must be a canonical full refs/... name")]
    InvalidGitRef,
    /// The durable run number was not positive.
    #[error("logical activation run number must be positive")]
    InvalidRunNumber,
    /// The durable run attempt was not positive.
    #[error("logical activation run attempt must be positive")]
    InvalidRunAttempt,
    /// A repository adapter attempted to issue a non-step activation claim.
    #[error("logical activation currently supports step jobs only")]
    UnsupportedJobKind,
    /// A durable logical-job source order exceeded the current plan bound.
    #[error("logical activation source order is outside the current plan bound")]
    InvalidSourceOrder,
    /// The server-selected workspace was not a canonical absolute target path.
    #[error("logical activation workspace is not a canonical absolute target path")]
    InvalidWorkspace,
    /// An instance identity named a different logical job.
    #[error("matrix identity logical key does not match the claimed job")]
    LogicalKeyMismatch,
    /// A blob descriptor occupied the wrong semantic field.
    #[error("logical activation object kind does not match its descriptor field")]
    ObjectKindMismatch,
    /// A descriptor was constructed for another claim target.
    #[error("logical instance descriptor belongs to another activation claim")]
    DescriptorClaimMismatch,
    /// Immutable preparation evidence belongs to another activation claim.
    #[error("logical activation preparation does not match its claim")]
    PreparationClaimMismatch,
    /// A typed runtime policy disagreed with its tenant or propagation chain.
    #[error("logical activation runtime policy does not match its target")]
    RuntimePolicyMismatch,
    /// Matrix descriptors were not the exact canonical expansion sequence.
    #[error("logical instance descriptors are not in canonical matrix order")]
    NoncanonicalMatrixInstances,
    /// The activation result exceeded the current matrix-expansion bound.
    #[error("logical activation exceeds its instance limit")]
    TooManyInstances,
    /// A false condition incorrectly carried runnable instances.
    #[error("an unmatched logical-job condition cannot publish instances")]
    UnmatchedConditionHasInstances,
    /// Publication time did not fall within the claimed interval.
    #[error("logical activation publication falls outside its claim interval")]
    PublicationOutsideClaim,
}

/// Durable activation-claim or publication failure.
#[derive(Debug, Error)]
pub enum LogicalActivationStoreError {
    /// The relational store failed or contained malformed current data.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The target is absent, cross-tenant, non-current, or not a step job.
    #[error("logical activation target is not an admitted current step job")]
    InvalidTarget,
    /// A takeover supplied different canonical activation inputs.
    #[error("logical activation input digest conflicts with the durable claim")]
    InputConflict,
    /// The monotonic generation cannot advance.
    #[error("logical activation claim generation is exhausted")]
    GenerationExhausted,
    /// Publication did not own the exact current live fence.
    #[error("logical activation claim fence was rejected")]
    ClaimRejected,
    /// The job already has different immutable publication evidence.
    #[error("logical activation publication conflicts with durable evidence")]
    PublicationConflict,
}

/// Persistence boundary for current logical-job activation descriptors.
#[async_trait]
pub trait LogicalActivationRepository: std::fmt::Debug + Send + Sync {
    /// Loads the immutable permission ceiling for one sealed reusable child.
    /// Root invocations and unpublished children return no snapshot.
    async fn reusable_workflow_permission_snapshot(
        &self,
        _tenant: &TenantScope,
        _run_id: RunId,
        _invocation_id: LogicalWorkflowInvocationId,
    ) -> Result<Option<ReusableWorkflowPermissionSnapshot>, LogicalActivationStoreError> {
        Ok(None)
    }

    /// Replaces an exact live claim with the next generation and a new bounded
    /// interval. Concurrent exact retries replay the replacement fence; stale
    /// or divergent renewals fail closed.
    async fn renew_logical_job_activation(
        &self,
        request: RenewLogicalJobActivation,
    ) -> Result<RenewedLogicalJobActivation, LogicalActivationStoreError>;

    /// Atomically publishes already-written immutable instance descriptors.
    /// An exact same-fence replay returns the prior receipt; any changed output
    /// or stale/taken-over fence fails closed.
    async fn publish_logical_job_activation(
        &self,
        request: PublishLogicalJobActivation,
    ) -> Result<LogicalActivationPublicationReceipt, LogicalActivationStoreError>;
}

fn publication_digest(
    claim: &LogicalActivationClaimFence,
    condition_matched: bool,
    instances: &[ActivatedLogicalInstanceDescriptor],
) -> Sha256Digest {
    rederive_publication_digest(
        claim.run_id(),
        claim.invocation_id(),
        claim.logical_job_id(),
        claim.input_digest(),
        condition_matched,
        instances,
    )
}

pub(crate) fn rederive_publication_digest(
    run_id: RunId,
    invocation_id: LogicalWorkflowInvocationId,
    logical_job_id: LogicalWorkflowJobId,
    input_digest: Sha256Digest,
    condition_matched: bool,
    instances: &[ActivatedLogicalInstanceDescriptor],
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(PUBLICATION_DIGEST_DOMAIN);
    hasher.update(run_id.as_uuid().as_bytes());
    hasher.update(invocation_id.as_uuid().as_bytes());
    hasher.update(logical_job_id.as_uuid().as_bytes());
    hasher.update(input_digest.as_bytes());
    hasher.update([u8::from(condition_matched)]);
    hasher.update(
        u32::try_from(instances.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for instance in instances {
        hasher.update(instance.id().as_uuid().as_bytes());
        hasher.update(instance.matrix_index().to_be_bytes());
        hasher.update(instance.matrix_total().to_be_bytes());
        hasher.update(instance.matrix_digest().as_bytes());
        let workspace = instance.workspace().as_bytes();
        hasher.update(
            u64::try_from(workspace.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hasher.update(workspace);
        hash_object(&mut hasher, instance.job_ir());
        hash_object(&mut hasher, instance.runtime_context());
        hash_environment_gate(&mut hasher, instance.environment_gate());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn hash_environment_gate(hasher: &mut Sha256, evidence: Option<&JobEnvironmentActivationEvidence>) {
    let Some(evidence) = evidence else {
        return;
    };
    hasher.update(b"automata.store.logical-activation-environment-gate.v1\0");
    match evidence.environment() {
        Some(environment) => {
            hasher.update([1]);
            let value = environment.normalized().as_bytes();
            hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
            hasher.update(value);
        }
        None => hasher.update([0]),
    }
    hasher.update([match evidence.event_trust() {
        crate::JobEventTrust::Trusted => 1,
        crate::JobEventTrust::Untrusted => 2,
    }]);
    hasher.update([match evidence.source_kind() {
        crate::JobSourceKind::SameRepository => 1,
        crate::JobSourceKind::Fork => 2,
        crate::JobSourceKind::Dependabot => 3,
    }]);
    hasher.update([match evidence.reusable_secret_permission() {
        crate::ReusableSecretPermission::None => 1,
        crate::ReusableSecretPermission::Explicit => 2,
    }]);
}

fn hash_object(hasher: &mut Sha256, object: &LogicalActivationObject) {
    let key = object.object_key().as_str().as_bytes();
    hasher.update(u64::try_from(key.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(key);
    hasher.update(object.digest().as_bytes());
    hasher.update(object.encoded_size().to_be_bytes());
    let media_type = object.media_type().as_bytes();
    hasher.update(
        u64::try_from(media_type.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(media_type);
    let schema = if object.is_job_ir() {
        JOB_IR_SCHEMA_VERSION
    } else {
        JOB_RUNTIME_CONTEXT_SCHEMA_VERSION
    };
    hasher.update(schema.to_be_bytes());
}

fn validate_timestamp(
    value: UnixMillis,
    field: &'static str,
) -> Result<(), LogicalActivationValueError> {
    if value.get() < 0 {
        return Err(LogicalActivationValueError::NegativeTimestamp(field));
    }
    Ok(())
}

fn validate_bounded_text(
    value: &str,
    field: &'static str,
) -> Result<(), LogicalActivationValueError> {
    if value.trim().is_empty() || value.len() > 1_024 || value.chars().any(char::is_control) {
        return Err(LogicalActivationValueError::InvalidExecutionText(field));
    }
    Ok(())
}

fn validate_workspace(value: &str) -> Result<(), LogicalActivationValueError> {
    validate_bounded_text(value, "workspace")?;
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
    if !unix && !windows {
        return Err(LogicalActivationValueError::InvalidWorkspace);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DeploymentEnvironmentName, JobEventTrust, JobSourceKind, ReusableSecretPermission,
    };

    fn activation_evidence(
        event_trust: JobEventTrust,
        source_kind: JobSourceKind,
        reusable_secret_permission: ReusableSecretPermission,
    ) -> JobEnvironmentActivationEvidence {
        JobEnvironmentActivationEvidence::new(
            Some(DeploymentEnvironmentName::new("Production").expect("environment")),
            event_trust,
            source_kind,
            reusable_secret_permission,
        )
    }

    fn instance(
        evidence: Option<JobEnvironmentActivationEvidence>,
    ) -> ActivatedLogicalInstanceDescriptor {
        ActivatedLogicalInstanceDescriptor::from_durable(
            LogicalWorkflowInstanceId::from_uuid(Uuid::from_u128(4)).expect("instance"),
            RunId::from_uuid(Uuid::from_u128(1)),
            LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(2)).expect("invocation"),
            LogicalWorkflowJobId::from_uuid(Uuid::from_u128(3)).expect("job"),
            0,
            1,
            Sha256Digest::from_bytes([4; 32]),
            "/work/job".to_owned(),
            LogicalActivationObject::job_ir(
                Sha256Digest::from_bytes([5; 32]),
                ObjectKey::new("jobs/ir").expect("job IR key"),
                1,
            )
            .expect("job IR"),
            LogicalActivationObject::runtime_context(
                Sha256Digest::from_bytes([6; 32]),
                ObjectKey::new("jobs/context").expect("runtime-context key"),
                1,
            )
            .expect("runtime context"),
            evidence,
        )
        .expect("instance")
    }

    fn digest(instance: ActivatedLogicalInstanceDescriptor) -> Sha256Digest {
        rederive_publication_digest(
            RunId::from_uuid(Uuid::from_u128(1)),
            LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(2)).expect("invocation"),
            LogicalWorkflowJobId::from_uuid(Uuid::from_u128(3)).expect("job"),
            Sha256Digest::from_bytes([7; 32]),
            true,
            &[instance],
        )
    }

    #[test]
    fn activation_gate_evidence_is_retry_stable_and_digest_bound() {
        let trusted = activation_evidence(
            JobEventTrust::Trusted,
            JobSourceKind::SameRepository,
            ReusableSecretPermission::None,
        );
        let expected = digest(instance(Some(trusted.clone())));
        assert_eq!(expected, digest(instance(Some(trusted))));

        for substitution in [
            Some(activation_evidence(
                JobEventTrust::Untrusted,
                JobSourceKind::SameRepository,
                ReusableSecretPermission::None,
            )),
            Some(activation_evidence(
                JobEventTrust::Trusted,
                JobSourceKind::Fork,
                ReusableSecretPermission::None,
            )),
            Some(activation_evidence(
                JobEventTrust::Trusted,
                JobSourceKind::SameRepository,
                ReusableSecretPermission::Explicit,
            )),
            None,
        ] {
            assert_ne!(expected, digest(instance(substitution)));
        }
    }

    #[test]
    fn evidence_free_descriptor_has_canonical_publication_digest() {
        assert_eq!(
            digest(instance(None)).to_string(),
            "9e354947a483da281cf6bde73e5a0b4e066237228e83c8879a9a2f75b4029b84"
        );
    }
}
