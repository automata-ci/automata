//! Fenced projection of terminal concrete attempts into logical-instance results.
//!
//! A repository claim authenticates only immutable, credential-free object
//! descriptors. Callers load and decode the exact terminal `JobResult` and
//! `JobIR` objects outside the repository transaction, then submit a commit
//! whose constructor validates current schemas, identities, output
//! classifications, and job-level `continue-on-error` semantics.

use std::{fmt, num::NonZeroU64};

use async_trait::async_trait;
use automata_ci_core::{
    AttemptId, CORE_SCHEMA_VERSION, JOB_IR_SCHEMA_VERSION, JobConclusion, JobId, JobIrEnvelope,
    JobResult, JobSecretExposure, OperationId, OutputSensitivity, RunId, Sha256Digest, UnixMillis,
    WorkflowJobKey,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    LogicalActivationObject, LogicalWorkflowInstanceId, LogicalWorkflowInvocationId,
    LogicalWorkflowJobId, ObjectKey, StoreError, TenantScope,
    value::terminal_result_bytes_rejection,
};

/// Exact media type of the current runner terminal-result object.
pub const LOGICAL_INSTANCE_RESULT_MEDIA_TYPE: &str = "application/vnd.automata.job-result+json";
/// Maximum duration of one logical-instance result claim.
pub const MAX_LOGICAL_INSTANCE_RESULT_CLAIM_MILLIS: i64 = 15 * 60 * 1_000;

const DESCRIPTOR_DIGEST_DOMAIN: &[u8] = b"automata.store.logical-instance-result-descriptor.v1\0";
const SERVER_CANCELLATION_DESCRIPTOR_DOMAIN: &[u8] =
    b"automata.store.logical-instance-result.server-cancellation.v1\0";
const OUTPUTS_DIGEST_DOMAIN: &[u8] = b"automata.store.logical-instance-result-outputs.v1\0";
const COMMIT_DIGEST_DOMAIN: &[u8] = b"automata.store.logical-instance-result-commit.v1\0";

/// Positive server-assigned completion order within one logical job.
///
/// The repository assigns this value transactionally when the terminal attempt
/// is inserted. It is therefore suitable for deterministic matrix-output
/// selection without trusting runner clocks.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalInstanceTerminalOrdinal(NonZeroU64);

impl LogicalInstanceTerminalOrdinal {
    /// Rehydrates a positive ordinal within the signed 64-bit storage boundary.
    ///
    /// # Errors
    ///
    /// Rejects zero and values larger than `i64::MAX`.
    pub fn new(value: u64) -> Result<Self, LogicalInstanceResultValueError> {
        let value = NonZeroU64::new(value)
            .filter(|value| i64::try_from(value.get()).is_ok())
            .ok_or(LogicalInstanceResultValueError::InvalidTerminalOrdinal)?;
        Ok(Self(value))
    }

    /// Returns the server-assigned ordinal.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Non-nil durable identity of one instance-result worker.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalInstanceResultWorkerId(Uuid);

impl LogicalInstanceResultWorkerId {
    /// Constructs a non-nil worker identity.
    ///
    /// # Errors
    ///
    /// Rejects the nil UUID sentinel.
    pub fn from_uuid(value: Uuid) -> Result<Self, LogicalInstanceResultValueError> {
        if value.is_nil() {
            return Err(LogicalInstanceResultValueError::NilUuid(
                "logical instance-result worker ID",
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

/// Non-nil idempotency key for one autonomous claim-next operation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalInstanceResultSelectionId(Uuid);

impl LogicalInstanceResultSelectionId {
    /// Constructs a non-nil selection identity.
    ///
    /// # Errors
    ///
    /// Rejects the nil UUID sentinel.
    pub fn from_uuid(value: Uuid) -> Result<Self, LogicalInstanceResultValueError> {
        if value.is_nil() {
            return Err(LogicalInstanceResultValueError::NilUuid(
                "logical instance-result selection ID",
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

/// Positive monotonic generation of one instance-result claim.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalInstanceResultGeneration(NonZeroU64);

impl LogicalInstanceResultGeneration {
    /// Constructs a positive generation within the signed 64-bit storage boundary.
    ///
    /// # Errors
    ///
    /// Rejects zero and values larger than `i64::MAX`.
    pub fn new(value: u64) -> Result<Self, LogicalInstanceResultValueError> {
        let value = NonZeroU64::new(value)
            .filter(|value| i64::try_from(value.get()).is_ok())
            .ok_or(LogicalInstanceResultValueError::InvalidGeneration)?;
        Ok(Self(value))
    }

    /// Returns the numeric generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Tenant-scoped terminal-attempt target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalInstanceResultTarget {
    tenant: TenantScope,
    attempt_id: AttemptId,
}

impl LogicalInstanceResultTarget {
    /// Constructs an exact tenant-scoped target.
    ///
    /// # Errors
    ///
    /// Rejects the nil attempt sentinel.
    pub fn new(
        tenant: TenantScope,
        attempt_id: AttemptId,
    ) -> Result<Self, LogicalInstanceResultValueError> {
        if attempt_id.as_uuid().is_nil() {
            return Err(LogicalInstanceResultValueError::NilUuid("attempt ID"));
        }
        Ok(Self { tenant, attempt_id })
    }

    /// Returns the authenticated tenant scope.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }

    /// Returns the exact terminal-attempt identity.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }
}

/// Request to acquire or take over one instance-result claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimLogicalInstanceResult {
    target: LogicalInstanceResultTarget,
    owner: LogicalInstanceResultWorkerId,
    observed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl ClaimLogicalInstanceResult {
    /// Constructs one bounded claim request.
    ///
    /// # Errors
    ///
    /// Rejects negative time, an empty interval, or an interval longer than
    /// [`MAX_LOGICAL_INSTANCE_RESULT_CLAIM_MILLIS`].
    pub fn new(
        target: LogicalInstanceResultTarget,
        owner: LogicalInstanceResultWorkerId,
        observed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, LogicalInstanceResultValueError> {
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
    pub const fn target(&self) -> &LogicalInstanceResultTarget {
        &self.target
    }

    /// Returns the claim owner.
    #[must_use]
    pub const fn owner(&self) -> LogicalInstanceResultWorkerId {
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

/// Bounded request to select and claim the next due terminal attempt globally.
///
/// The stable selection identity makes a lost response replayable without a
/// caller guessing which tenant or attempt the repository selected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimNextLogicalInstanceResult {
    selection_id: LogicalInstanceResultSelectionId,
    owner: LogicalInstanceResultWorkerId,
    observed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl ClaimNextLogicalInstanceResult {
    /// Constructs one globally bounded claim-next request.
    ///
    /// # Errors
    ///
    /// Rejects negative time, an empty interval, or an interval longer than
    /// [`MAX_LOGICAL_INSTANCE_RESULT_CLAIM_MILLIS`].
    pub fn new(
        selection_id: LogicalInstanceResultSelectionId,
        owner: LogicalInstanceResultWorkerId,
        observed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, LogicalInstanceResultValueError> {
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
    pub const fn selection_id(&self) -> LogicalInstanceResultSelectionId {
        self.selection_id
    }

    /// Returns the claim owner.
    #[must_use]
    pub const fn owner(&self) -> LogicalInstanceResultWorkerId {
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

/// Immutable descriptor of one current terminal-result object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalTerminalResultObject {
    digest: Sha256Digest,
    object_key: ObjectKey,
    encoded_size: u64,
}

impl LogicalTerminalResultObject {
    /// Constructs an exact current terminal-result descriptor.
    ///
    /// # Errors
    ///
    /// Rejects a non-current schema or an empty/oversized object.
    pub fn new(
        digest: Sha256Digest,
        object_key: ObjectKey,
        encoded_size: u64,
        schema: u16,
    ) -> Result<Self, LogicalInstanceResultValueError> {
        if schema != CORE_SCHEMA_VERSION {
            return Err(LogicalInstanceResultValueError::InvalidResultObject);
        }
        if encoded_size == 0 || terminal_result_bytes_rejection(encoded_size).is_some() {
            return Err(LogicalInstanceResultValueError::InvalidResultObject);
        }
        Ok(Self {
            digest,
            object_key,
            encoded_size,
        })
    }

    /// Returns the SHA-256 digest of the exact encoded bytes.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Returns the credential-free immutable object key.
    #[must_use]
    pub const fn object_key(&self) -> &ObjectKey {
        &self.object_key
    }

    /// Returns the exact encoded byte length.
    #[must_use]
    pub const fn encoded_size(&self) -> u64 {
        self.encoded_size
    }

    /// Returns the exact current schema.
    #[must_use]
    pub const fn schema(&self) -> u16 {
        CORE_SCHEMA_VERSION
    }

    /// Returns the fixed current media type.
    #[must_use]
    pub const fn media_type(&self) -> &'static str {
        LOGICAL_INSTANCE_RESULT_MEDIA_TYPE
    }
}

/// Immutable server authority for a queued attempt that never reached a runner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalServerCancellationTerminal {
    operation_id: OperationId,
    digest: Sha256Digest,
}

impl LogicalServerCancellationTerminal {
    /// Rehydrates exact cancellation-intent authority already validated by the store.
    #[must_use]
    pub const fn new(operation_id: OperationId, digest: Sha256Digest) -> Self {
        Self {
            operation_id,
            digest,
        }
    }

    /// Returns the immutable cancellation operation.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the domain-separated server evidence digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

/// Closed authority that made a concrete attempt terminal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LogicalInstanceTerminalAuthority {
    /// A runner committed one exact immutable `JobResult` object.
    Runner(LogicalTerminalResultObject),
    /// The server cancelled an exact queued attempt before runner assignment.
    ServerCancellation(LogicalServerCancellationTerminal),
}

/// Store-authenticated terminal attempt and immutable object descriptors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalInstanceResultDescriptor {
    target: LogicalInstanceResultTarget,
    run_id: RunId,
    invocation_id: LogicalWorkflowInvocationId,
    logical_job_id: LogicalWorkflowJobId,
    instance_id: LogicalWorkflowInstanceId,
    job_id: JobId,
    logical_key: WorkflowJobKey,
    matrix_index: u32,
    matrix_total: u32,
    matrix_digest: Sha256Digest,
    terminal_ordinal: LogicalInstanceTerminalOrdinal,
    terminal_authority: LogicalInstanceTerminalAuthority,
    job_ir: LogicalActivationObject,
    maximum_secret_exposure: JobSecretExposure,
    raw_conclusion: JobConclusion,
    result_completed_at: UnixMillis,
    result_committed_at: UnixMillis,
    descriptor_digest: Sha256Digest,
}

impl LogicalInstanceResultDescriptor {
    /// Rehydrates one exact current terminal attempt without performing blob I/O.
    ///
    /// # Errors
    ///
    /// Rejects nil identities, invalid matrix coordinates, a non-JobIR object,
    /// or impossible terminal timestamps.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target: LogicalInstanceResultTarget,
        run_id: RunId,
        invocation_id: LogicalWorkflowInvocationId,
        logical_job_id: LogicalWorkflowJobId,
        instance_id: LogicalWorkflowInstanceId,
        job_id: JobId,
        logical_key: WorkflowJobKey,
        matrix_index: u32,
        matrix_total: u32,
        matrix_digest: Sha256Digest,
        terminal_ordinal: LogicalInstanceTerminalOrdinal,
        terminal_result: LogicalTerminalResultObject,
        job_ir_object: LogicalActivationObject,
        maximum_secret_exposure: JobSecretExposure,
        raw_conclusion: JobConclusion,
        result_completed_at: UnixMillis,
        result_committed_at: UnixMillis,
    ) -> Result<Self, LogicalInstanceResultValueError> {
        Self::new_with_authority(
            target,
            run_id,
            invocation_id,
            logical_job_id,
            instance_id,
            job_id,
            logical_key,
            matrix_index,
            matrix_total,
            matrix_digest,
            terminal_ordinal,
            LogicalInstanceTerminalAuthority::Runner(terminal_result),
            job_ir_object,
            maximum_secret_exposure,
            raw_conclusion,
            result_completed_at,
            result_committed_at,
        )
    }

    /// Rehydrates exact queued-cancellation authority without a result blob.
    ///
    /// # Errors
    ///
    /// Rejects nil identities, invalid matrix coordinates, a non-JobIR object,
    /// or impossible terminal timestamps.
    #[allow(clippy::too_many_arguments)]
    pub fn new_server_cancellation(
        target: LogicalInstanceResultTarget,
        run_id: RunId,
        invocation_id: LogicalWorkflowInvocationId,
        logical_job_id: LogicalWorkflowJobId,
        instance_id: LogicalWorkflowInstanceId,
        job_id: JobId,
        logical_key: WorkflowJobKey,
        matrix_index: u32,
        matrix_total: u32,
        matrix_digest: Sha256Digest,
        terminal_ordinal: LogicalInstanceTerminalOrdinal,
        server_cancellation: LogicalServerCancellationTerminal,
        job_ir_object: LogicalActivationObject,
        maximum_secret_exposure: JobSecretExposure,
        result_completed_at: UnixMillis,
        result_committed_at: UnixMillis,
    ) -> Result<Self, LogicalInstanceResultValueError> {
        Self::new_with_authority(
            target,
            run_id,
            invocation_id,
            logical_job_id,
            instance_id,
            job_id,
            logical_key,
            matrix_index,
            matrix_total,
            matrix_digest,
            terminal_ordinal,
            LogicalInstanceTerminalAuthority::ServerCancellation(server_cancellation),
            job_ir_object,
            maximum_secret_exposure,
            JobConclusion::Cancelled,
            result_completed_at,
            result_committed_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_authority(
        target: LogicalInstanceResultTarget,
        run_id: RunId,
        invocation_id: LogicalWorkflowInvocationId,
        logical_job_id: LogicalWorkflowJobId,
        instance_id: LogicalWorkflowInstanceId,
        job_id: JobId,
        logical_key: WorkflowJobKey,
        matrix_index: u32,
        matrix_total: u32,
        matrix_digest: Sha256Digest,
        terminal_ordinal: LogicalInstanceTerminalOrdinal,
        terminal_authority: LogicalInstanceTerminalAuthority,
        job_ir_object: LogicalActivationObject,
        maximum_secret_exposure: JobSecretExposure,
        raw_conclusion: JobConclusion,
        result_completed_at: UnixMillis,
        result_committed_at: UnixMillis,
    ) -> Result<Self, LogicalInstanceResultValueError> {
        if run_id.as_uuid().is_nil() {
            return Err(LogicalInstanceResultValueError::NilUuid("workflow run ID"));
        }
        if job_id.as_uuid().is_nil() {
            return Err(LogicalInstanceResultValueError::NilUuid("concrete job ID"));
        }
        if matrix_total == 0 || matrix_total > 256 || matrix_index >= matrix_total {
            return Err(LogicalInstanceResultValueError::InvalidMatrixIdentity);
        }
        if !job_ir_object.is_job_ir() {
            return Err(LogicalInstanceResultValueError::InvalidJobIrObject);
        }
        validate_timestamp(result_completed_at, "terminal-result completion time")?;
        validate_timestamp(result_committed_at, "terminal-result commit time")?;
        if result_committed_at < result_completed_at {
            return Err(LogicalInstanceResultValueError::InvalidResultTimestamps);
        }
        let descriptor_digest = descriptor_digest(
            &target,
            run_id,
            invocation_id,
            logical_job_id,
            instance_id,
            job_id,
            &logical_key,
            matrix_index,
            matrix_total,
            matrix_digest,
            terminal_ordinal,
            &terminal_authority,
            &job_ir_object,
            maximum_secret_exposure,
            raw_conclusion,
            result_completed_at,
            result_committed_at,
        );
        Ok(Self {
            target,
            run_id,
            invocation_id,
            logical_job_id,
            instance_id,
            job_id,
            logical_key,
            matrix_index,
            matrix_total,
            matrix_digest,
            terminal_ordinal,
            terminal_authority,
            job_ir: job_ir_object,
            maximum_secret_exposure,
            raw_conclusion,
            result_completed_at,
            result_committed_at,
            descriptor_digest,
        })
    }

    /// Returns the tenant-scoped attempt target.
    #[must_use]
    pub const fn target(&self) -> &LogicalInstanceResultTarget {
        &self.target
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

    /// Returns the immutable matrix-instance identity.
    #[must_use]
    pub const fn instance_id(&self) -> LogicalWorkflowInstanceId {
        self.instance_id
    }

    /// Returns the concrete job identity.
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
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

    /// Returns the matrix expansion size.
    #[must_use]
    pub const fn matrix_total(&self) -> u32 {
        self.matrix_total
    }

    /// Returns the exact matrix-values digest.
    #[must_use]
    pub const fn matrix_digest(&self) -> Sha256Digest {
        self.matrix_digest
    }

    /// Returns the server-assigned terminal order within the logical job.
    #[must_use]
    pub const fn terminal_ordinal(&self) -> LogicalInstanceTerminalOrdinal {
        self.terminal_ordinal
    }

    /// Returns the closed terminal authority.
    #[must_use]
    pub const fn terminal_authority(&self) -> &LogicalInstanceTerminalAuthority {
        &self.terminal_authority
    }

    /// Returns the terminal `JobResult` object only for runner authority.
    #[must_use]
    pub const fn terminal_result(&self) -> Option<&LogicalTerminalResultObject> {
        match &self.terminal_authority {
            LogicalInstanceTerminalAuthority::Runner(result) => Some(result),
            LogicalInstanceTerminalAuthority::ServerCancellation(_) => None,
        }
    }

    /// Returns queued server-cancellation authority when present.
    #[must_use]
    pub const fn server_cancellation(&self) -> Option<&LogicalServerCancellationTerminal> {
        match &self.terminal_authority {
            LogicalInstanceTerminalAuthority::Runner(_) => None,
            LogicalInstanceTerminalAuthority::ServerCancellation(cancellation) => {
                Some(cancellation)
            }
        }
    }

    /// Returns the immutable `JobIR` object descriptor.
    #[must_use]
    pub const fn job_ir(&self) -> &LogicalActivationObject {
        &self.job_ir
    }

    /// Returns the immutable maximum exposure admitted for this attempt.
    #[must_use]
    pub const fn maximum_secret_exposure(&self) -> JobSecretExposure {
        self.maximum_secret_exposure
    }

    pub(crate) const fn accepts_terminal_secret_exposure(
        &self,
        observed: JobSecretExposure,
    ) -> bool {
        match self.maximum_secret_exposure {
            // Once raw-secret authority is admitted, runner-controlled result
            // metadata cannot downgrade the publication safety boundary.
            JobSecretExposure::ReadableSecret => {
                matches!(observed, JobSecretExposure::ReadableSecret)
            }
            maximum => maximum.permits(observed),
        }
    }

    /// Returns the unmodified terminal-authority conclusion.
    #[must_use]
    pub const fn raw_conclusion(&self) -> JobConclusion {
        self.raw_conclusion
    }

    /// Returns the runner-declared job completion time.
    #[must_use]
    pub const fn result_completed_at(&self) -> UnixMillis {
        self.result_completed_at
    }

    /// Returns the durable terminal-result commit time.
    #[must_use]
    pub const fn result_committed_at(&self) -> UnixMillis {
        self.result_committed_at
    }

    /// Returns the canonical digest of every immutable descriptor field.
    #[must_use]
    pub const fn descriptor_digest(&self) -> Sha256Digest {
        self.descriptor_digest
    }
}

/// Exact live proof required to finalize one instance result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalInstanceResultClaimFence {
    target: LogicalInstanceResultTarget,
    owner: LogicalInstanceResultWorkerId,
    generation: LogicalInstanceResultGeneration,
    descriptor_digest: Sha256Digest,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl LogicalInstanceResultClaimFence {
    /// Rehydrates repository-issued claim evidence.
    ///
    /// Construction grants no durable authority; adapters compare every field
    /// again under lock before committing.
    ///
    /// # Errors
    ///
    /// Rejects an invalid claim interval.
    pub fn new(
        target: LogicalInstanceResultTarget,
        owner: LogicalInstanceResultWorkerId,
        generation: LogicalInstanceResultGeneration,
        descriptor_digest: Sha256Digest,
        claimed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, LogicalInstanceResultValueError> {
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
    pub const fn target(&self) -> &LogicalInstanceResultTarget {
        &self.target
    }

    /// Returns the claim owner.
    #[must_use]
    pub const fn owner(&self) -> LogicalInstanceResultWorkerId {
        self.owner
    }

    /// Returns the monotonic claim generation.
    #[must_use]
    pub const fn generation(&self) -> LogicalInstanceResultGeneration {
        self.generation
    }

    /// Returns the immutable descriptor digest.
    #[must_use]
    pub const fn descriptor_digest(&self) -> Sha256Digest {
        self.descriptor_digest
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
pub struct ClaimedLogicalInstanceResult {
    descriptor: LogicalInstanceResultDescriptor,
    claim: LogicalInstanceResultClaimFence,
    replayed: bool,
}

impl ClaimedLogicalInstanceResult {
    /// Constructs a repository result after exact descriptor/fence checks.
    ///
    /// # Errors
    ///
    /// Rejects a fence that does not bind the supplied descriptor or starts
    /// before the terminal result was durably committed.
    pub fn new(
        descriptor: LogicalInstanceResultDescriptor,
        claim: LogicalInstanceResultClaimFence,
        replayed: bool,
    ) -> Result<Self, LogicalInstanceResultValueError> {
        if claim.target() != descriptor.target()
            || claim.descriptor_digest() != descriptor.descriptor_digest()
        {
            return Err(LogicalInstanceResultValueError::ClaimDescriptorMismatch);
        }
        if claim.claimed_at() < descriptor.result_committed_at() {
            return Err(LogicalInstanceResultValueError::ClaimBeforeTerminalCommit);
        }
        Ok(Self {
            descriptor,
            claim,
            replayed,
        })
    }

    /// Returns the exact terminal-attempt descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &LogicalInstanceResultDescriptor {
        &self.descriptor
    }

    /// Returns the live commit fence.
    #[must_use]
    pub const fn claim(&self) -> &LogicalInstanceResultClaimFence {
        &self.claim
    }

    /// Reports whether the exact same claim request was replayed.
    #[must_use]
    pub const fn is_replay(&self) -> bool {
        self.replayed
    }
}

/// Outcome of claiming one exact terminal attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum LogicalInstanceResultClaimOutcome {
    /// The claim was acquired or exactly replayed.
    Claimed(ClaimedLogicalInstanceResult),
    /// Another worker owns an unexpired claim.
    Busy,
    /// The exact attempt already has a durable logical-instance result.
    Finalized(LogicalInstanceResultReceipt),
}

/// Outcome of one idempotent global instance-result selection.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum LogicalInstanceResultClaimNextOutcome {
    /// One due attempt was claimed, or the exact selection was replayed.
    Claimed(ClaimedLogicalInstanceResult),
    /// The selected attempt was finalized before this selection was replayed.
    Finalized(LogicalInstanceResultReceipt),
    /// Deterministically corrupt target-local durable evidence was isolated.
    Quarantined,
    /// No due terminal attempt was available without waiting on another worker.
    Idle,
}

/// Closed, value-free reason for isolating one logical-instance result target.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LogicalInstanceResultQuarantineKind {
    /// Durable evidence was internally inconsistent.
    RelationalEvidence,
    /// An immutable object could not be loaded with its exact descriptor.
    ObjectEvidence,
    /// Loaded bytes were malformed or disagreed with current payload semantics.
    PayloadEvidence,
}

/// Exact live fence authorizing isolation of one claimed result target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantineLogicalInstanceResult {
    descriptor: LogicalInstanceResultDescriptor,
    claim: LogicalInstanceResultClaimFence,
    kind: LogicalInstanceResultQuarantineKind,
}

impl QuarantineLogicalInstanceResult {
    /// Binds a value-free failure classification to an already validated claim.
    #[must_use]
    pub fn new(
        claimed: &ClaimedLogicalInstanceResult,
        kind: LogicalInstanceResultQuarantineKind,
    ) -> Self {
        Self {
            descriptor: claimed.descriptor().clone(),
            claim: claimed.claim().clone(),
            kind,
        }
    }

    /// Returns the exact store-authenticated target descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &LogicalInstanceResultDescriptor {
        &self.descriptor
    }

    /// Returns the exact current claim fence.
    #[must_use]
    pub const fn claim(&self) -> &LogicalInstanceResultClaimFence {
        &self.claim
    }

    /// Returns the closed value-free failure classification.
    #[must_use]
    pub const fn kind(&self) -> LogicalInstanceResultQuarantineKind {
        self.kind
    }
}

/// Result of idempotently isolating one claimed logical-instance result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogicalInstanceResultQuarantineOutcome {
    /// The exact live target and fence were isolated.
    Quarantined,
    /// The target was already durably isolated.
    AlreadyQuarantined,
    /// The target no longer has the submitted exact live fence and due snapshot.
    FenceRejected,
}

/// One sensitivity-safe output record persisted for a logical instance.
#[derive(Clone, Eq, PartialEq)]
pub struct LogicalInstanceResultOutput {
    name: String,
    sensitivity: OutputSensitivity,
    public_value: Option<String>,
}

impl fmt::Debug for LogicalInstanceResultOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LogicalInstanceResultOutput")
            .field("name", &self.name)
            .field("sensitivity", &self.sensitivity)
            .field(
                "public_value",
                &self.public_value.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl LogicalInstanceResultOutput {
    /// Returns the canonical output name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the persisted sensitivity classification.
    #[must_use]
    pub const fn sensitivity(&self) -> OutputSensitivity {
        self.sensitivity
    }

    /// Returns a value only for a public output.
    #[must_use]
    pub fn public_value(&self) -> Option<&str> {
        self.public_value.as_deref()
    }

    #[cfg(feature = "adapter-spi")]
    pub(crate) fn from_durable(
        name: String,
        sensitivity: OutputSensitivity,
        public_value: Option<String>,
    ) -> Result<Self, LogicalInstanceResultValueError> {
        let valid_name = !name.is_empty()
            && name.len() <= 256
            && name.trim() == name
            && !name.chars().any(char::is_control);
        let valid_value = match (sensitivity, public_value.as_deref()) {
            (OutputSensitivity::Public, Some(value)) => {
                !value.is_empty() && value.len() <= 2 * 1024 * 1024
            }
            (OutputSensitivity::SecretDerived, None) => true,
            _ => false,
        };
        if !valid_name || !valid_value {
            return Err(LogicalInstanceResultValueError::InvalidOutputSet);
        }
        Ok(Self {
            name,
            sensitivity,
            public_value,
        })
    }
}

/// Validated commit assembled after exact terminal-result and `JobIR` loading.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitLogicalInstanceResult {
    claim: LogicalInstanceResultClaimFence,
    raw_conclusion: JobConclusion,
    effective_conclusion: JobConclusion,
    continue_on_error: bool,
    secret_exposure: JobSecretExposure,
    outputs: Vec<LogicalInstanceResultOutput>,
    outputs_digest: Sha256Digest,
    commit_digest: Sha256Digest,
    finalized_at: UnixMillis,
}

impl CommitLogicalInstanceResult {
    /// Validates exact decoded current `JobResult` and `JobIR` evidence.
    ///
    /// Result output names must be declared by `JobIR`. A statically
    /// secret-derived definition must remain secret-derived; a public
    /// definition may be upgraded to a secret-derived marker at runtime but
    /// never carries plaintext in that form. Missing/empty outputs remain
    /// omitted. A raw failure maps to effective success only when the decoded
    /// job-level `continue-on-error` value is true.
    ///
    /// # Errors
    ///
    /// Rejects blob mismatches, non-current/invalid decoded values, identity,
    /// conclusion, timestamp, or output disagreements, and expired claims.
    pub fn new(
        claimed: &ClaimedLogicalInstanceResult,
        encoded_result: &[u8],
        result: &JobResult,
        encoded_job_ir: &[u8],
        envelope: &JobIrEnvelope,
        finalized_at: UnixMillis,
    ) -> Result<Self, LogicalInstanceResultValueError> {
        let descriptor = claimed.descriptor();
        let claim = claimed.claim().clone();
        if finalized_at < claim.claimed_at() || finalized_at >= claim.expires_at() {
            return Err(LogicalInstanceResultValueError::CommitOutsideClaim);
        }
        let terminal_result = descriptor
            .terminal_result()
            .ok_or(LogicalInstanceResultValueError::TerminalAuthorityMismatch)?;
        validate_blob(
            encoded_result,
            terminal_result.encoded_size(),
            terminal_result.digest(),
            LogicalInstanceResultValueError::ResultBlobMismatch,
        )?;
        let canonical_result = serde_json::to_vec(result)
            .map_err(|_| LogicalInstanceResultValueError::InvalidJobResult)?;
        if canonical_result != encoded_result {
            return Err(LogicalInstanceResultValueError::InvalidJobResult);
        }
        result
            .validate()
            .map_err(|_| LogicalInstanceResultValueError::InvalidJobResult)?;
        if result.schema_version() != CORE_SCHEMA_VERSION
            || result.attempt_id() != descriptor.target().attempt_id()
            || result.conclusion() != descriptor.raw_conclusion()
            || result.completed_at() != descriptor.result_completed_at()
        {
            return Err(LogicalInstanceResultValueError::JobResultIdentityMismatch);
        }
        if !descriptor.accepts_terminal_secret_exposure(result.secret_exposure()) {
            return Err(LogicalInstanceResultValueError::SecretExposureDisagreesWithAdmission);
        }

        validate_blob(
            encoded_job_ir,
            descriptor.job_ir().encoded_size(),
            descriptor.job_ir().digest(),
            LogicalInstanceResultValueError::JobIrBlobMismatch,
        )?;
        envelope
            .validate()
            .map_err(|_| LogicalInstanceResultValueError::InvalidJobIr)?;
        if envelope.schema_version() != JOB_IR_SCHEMA_VERSION {
            return Err(LogicalInstanceResultValueError::InvalidJobIr);
        }
        validate_job_ir_identity(descriptor, envelope)?;
        let outputs = validate_outputs(result, envelope)?;
        let outputs_digest = output_set_digest(&outputs);
        let continue_on_error = envelope.job().continue_on_error();
        let effective_conclusion =
            effective_conclusion(descriptor.raw_conclusion(), continue_on_error);
        let commit_digest = result_commit_digest(
            &claim,
            descriptor,
            effective_conclusion,
            continue_on_error,
            result.secret_exposure(),
            outputs_digest,
            finalized_at,
        );
        Ok(Self {
            claim,
            raw_conclusion: descriptor.raw_conclusion(),
            effective_conclusion,
            continue_on_error,
            secret_exposure: result.secret_exposure(),
            outputs,
            outputs_digest,
            commit_digest,
            finalized_at,
        })
    }

    /// Builds a zero-output cancellation from exact server authority and `JobIR`.
    ///
    /// No runner result bytes are accepted or synthesized. The decoded `JobIR`
    /// still supplies the exact identity and `continue-on-error` setting; that
    /// setting does not reinterpret cancellation as success.
    ///
    /// # Errors
    ///
    /// Rejects a runner-authority descriptor, invalid `JobIR`, identity drift,
    /// or a commit outside the live claim.
    pub fn new_server_cancellation(
        claimed: &ClaimedLogicalInstanceResult,
        encoded_job_ir: &[u8],
        envelope: &JobIrEnvelope,
        finalized_at: UnixMillis,
    ) -> Result<Self, LogicalInstanceResultValueError> {
        let descriptor = claimed.descriptor();
        let claim = claimed.claim().clone();
        if descriptor.server_cancellation().is_none()
            || descriptor.raw_conclusion() != JobConclusion::Cancelled
        {
            return Err(LogicalInstanceResultValueError::TerminalAuthorityMismatch);
        }
        if finalized_at < claim.claimed_at() || finalized_at >= claim.expires_at() {
            return Err(LogicalInstanceResultValueError::CommitOutsideClaim);
        }
        validate_blob(
            encoded_job_ir,
            descriptor.job_ir().encoded_size(),
            descriptor.job_ir().digest(),
            LogicalInstanceResultValueError::JobIrBlobMismatch,
        )?;
        envelope
            .validate()
            .map_err(|_| LogicalInstanceResultValueError::InvalidJobIr)?;
        if envelope.schema_version() != JOB_IR_SCHEMA_VERSION {
            return Err(LogicalInstanceResultValueError::InvalidJobIr);
        }
        validate_job_ir_identity(descriptor, envelope)?;
        let outputs = Vec::new();
        let outputs_digest = output_set_digest(&outputs);
        let continue_on_error = envelope.job().continue_on_error();
        let effective_conclusion =
            effective_conclusion(JobConclusion::Cancelled, continue_on_error);
        let secret_exposure = JobSecretExposure::Secretless;
        let commit_digest = result_commit_digest(
            &claim,
            descriptor,
            effective_conclusion,
            continue_on_error,
            secret_exposure,
            outputs_digest,
            finalized_at,
        );
        Ok(Self {
            claim,
            raw_conclusion: JobConclusion::Cancelled,
            effective_conclusion,
            continue_on_error,
            secret_exposure,
            outputs,
            outputs_digest,
            commit_digest,
            finalized_at,
        })
    }

    /// Returns the exact live claim proof.
    #[must_use]
    pub const fn claim(&self) -> &LogicalInstanceResultClaimFence {
        &self.claim
    }

    /// Returns the unmodified runner conclusion.
    #[must_use]
    pub const fn raw_conclusion(&self) -> JobConclusion {
        self.raw_conclusion
    }

    /// Returns the job-level `continue-on-error` mapped conclusion.
    #[must_use]
    pub const fn effective_conclusion(&self) -> JobConclusion {
        self.effective_conclusion
    }

    /// Returns the decoded job-level `continue-on-error` value.
    #[must_use]
    pub const fn continue_on_error(&self) -> bool {
        self.continue_on_error
    }

    /// Returns the runner-observed terminal secret exposure.
    #[must_use]
    pub const fn secret_exposure(&self) -> JobSecretExposure {
        self.secret_exposure
    }

    /// Returns canonical name-sorted sensitivity-safe output records.
    #[must_use]
    pub fn outputs(&self) -> &[LogicalInstanceResultOutput] {
        &self.outputs
    }

    /// Returns the canonical digest of the complete output set.
    #[must_use]
    pub const fn outputs_digest(&self) -> Sha256Digest {
        self.outputs_digest
    }

    /// Returns the canonical exact-commit digest.
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

/// Durable receipt for one immutable logical-instance result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalInstanceResultReceipt {
    instance_id: LogicalWorkflowInstanceId,
    job_id: JobId,
    attempt_id: AttemptId,
    terminal_ordinal: LogicalInstanceTerminalOrdinal,
    descriptor_digest: Sha256Digest,
    raw_conclusion: JobConclusion,
    effective_conclusion: JobConclusion,
    secret_exposure: JobSecretExposure,
    output_count: u32,
    outputs_digest: Sha256Digest,
    commit_digest: Sha256Digest,
    finalized_at: UnixMillis,
    replayed: bool,
}

impl LogicalInstanceResultReceipt {
    /// Constructs the exact receipt for a validated commit.
    #[must_use]
    pub fn new(
        request: &CommitLogicalInstanceResult,
        descriptor: &LogicalInstanceResultDescriptor,
        replayed: bool,
    ) -> Self {
        Self {
            instance_id: descriptor.instance_id(),
            job_id: descriptor.job_id(),
            attempt_id: descriptor.target().attempt_id(),
            terminal_ordinal: descriptor.terminal_ordinal(),
            descriptor_digest: descriptor.descriptor_digest(),
            raw_conclusion: request.raw_conclusion(),
            effective_conclusion: request.effective_conclusion(),
            secret_exposure: request.secret_exposure(),
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
    /// Rejects nil identities, excessive output counts, or negative time.
    #[allow(clippy::too_many_arguments)]
    pub fn from_durable(
        instance_id: LogicalWorkflowInstanceId,
        job_id: JobId,
        attempt_id: AttemptId,
        terminal_ordinal: LogicalInstanceTerminalOrdinal,
        descriptor_digest: Sha256Digest,
        raw_conclusion: JobConclusion,
        effective_conclusion: JobConclusion,
        secret_exposure: JobSecretExposure,
        output_count: u32,
        outputs_digest: Sha256Digest,
        commit_digest: Sha256Digest,
        finalized_at: UnixMillis,
        replayed: bool,
    ) -> Result<Self, LogicalInstanceResultValueError> {
        if job_id.as_uuid().is_nil() {
            return Err(LogicalInstanceResultValueError::NilUuid("concrete job ID"));
        }
        if attempt_id.as_uuid().is_nil() {
            return Err(LogicalInstanceResultValueError::NilUuid("attempt ID"));
        }
        if usize::try_from(output_count).unwrap_or(usize::MAX)
            > automata_ci_core::MAX_JOB_OUTPUT_DEFINITIONS
        {
            return Err(LogicalInstanceResultValueError::InvalidOutputSet);
        }
        validate_timestamp(finalized_at, "instance-result finalization time")?;
        Ok(Self {
            instance_id,
            job_id,
            attempt_id,
            terminal_ordinal,
            descriptor_digest,
            raw_conclusion,
            effective_conclusion,
            secret_exposure,
            output_count,
            outputs_digest,
            commit_digest,
            finalized_at,
            replayed,
        })
    }

    /// Returns the immutable matrix-instance identity.
    #[must_use]
    pub const fn instance_id(&self) -> LogicalWorkflowInstanceId {
        self.instance_id
    }

    /// Returns the concrete job identity.
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    /// Returns the terminal attempt identity.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the server-assigned terminal order within the logical job.
    #[must_use]
    pub const fn terminal_ordinal(&self) -> LogicalInstanceTerminalOrdinal {
        self.terminal_ordinal
    }

    /// Returns the immutable descriptor digest.
    #[must_use]
    pub const fn descriptor_digest(&self) -> Sha256Digest {
        self.descriptor_digest
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

    /// Returns the runner-observed secret exposure bound to the result.
    #[must_use]
    pub const fn secret_exposure(&self) -> JobSecretExposure {
        self.secret_exposure
    }

    /// Returns the number of persisted sensitivity-safe outputs.
    #[must_use]
    pub const fn output_count(&self) -> u32 {
        self.output_count
    }

    /// Returns the canonical output-set digest.
    #[must_use]
    pub const fn outputs_digest(&self) -> Sha256Digest {
        self.outputs_digest
    }

    /// Returns the exact commit digest.
    #[must_use]
    pub const fn commit_digest(&self) -> Sha256Digest {
        self.commit_digest
    }

    /// Returns the durable finalization timestamp.
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

/// Invalid instance-result projection value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LogicalInstanceResultValueError {
    /// A durable UUID used the nil sentinel.
    #[error("{0} must not be the nil UUID")]
    NilUuid(&'static str),
    /// A trusted timestamp preceded the Unix epoch.
    #[error("{0} must not precede the Unix epoch")]
    NegativeTimestamp(&'static str),
    /// The claim interval was empty or exceeded its fixed bound.
    #[error("logical instance-result claim interval is invalid or too long")]
    InvalidClaimInterval,
    /// The monotonic generation was zero or exceeded the signed 64-bit storage boundary.
    #[error("logical instance-result generation is invalid")]
    InvalidGeneration,
    /// The server terminal ordinal was zero or exceeded the signed 64-bit storage boundary.
    #[error("logical instance-result terminal ordinal is invalid")]
    InvalidTerminalOrdinal,
    /// Durable matrix coordinates were outside the current bound.
    #[error("logical instance-result matrix identity is invalid")]
    InvalidMatrixIdentity,
    /// The terminal-result object was empty, oversized, or non-current.
    #[error("logical terminal-result object descriptor is invalid")]
    InvalidResultObject,
    /// A runner commit and server terminal authority were mixed.
    #[error("logical terminal authority does not match the requested projection")]
    TerminalAuthorityMismatch,
    /// The `JobIR` descriptor occupied the wrong semantic field.
    #[error("logical instance-result JobIR object descriptor is invalid")]
    InvalidJobIrObject,
    /// Durable terminal-result timestamps were impossible.
    #[error("logical terminal-result timestamps are invalid")]
    InvalidResultTimestamps,
    /// A claim fence did not bind its immutable descriptor.
    #[error("logical instance-result claim does not bind its descriptor")]
    ClaimDescriptorMismatch,
    /// A claim started before the runner result was durably committed.
    #[error("logical instance-result claim precedes the terminal-result commit")]
    ClaimBeforeTerminalCommit,
    /// Loaded terminal-result bytes differed from the immutable descriptor.
    #[error("loaded terminal-result bytes disagree with the durable descriptor")]
    ResultBlobMismatch,
    /// The decoded terminal result was invalid or non-current.
    #[error("decoded terminal result is invalid or not current")]
    InvalidJobResult,
    /// The decoded terminal result disagreed with the durable attempt.
    #[error("decoded terminal result disagrees with the durable attempt")]
    JobResultIdentityMismatch,
    /// Runner-observed exposure disagreed with the immutable admission boundary.
    #[error("terminal-result secret exposure disagrees with admitted attempt safety")]
    SecretExposureDisagreesWithAdmission,
    /// Loaded `JobIR` bytes differed from the immutable descriptor.
    #[error("loaded JobIR bytes disagree with the durable descriptor")]
    JobIrBlobMismatch,
    /// The decoded envelope was not valid current `JobIR`.
    #[error("decoded JobIR is invalid or not current schema")]
    InvalidJobIr,
    /// The decoded envelope disagreed with the durable concrete instance.
    #[error("decoded JobIR disagrees with the durable concrete instance")]
    JobIrIdentityMismatch,
    /// Result output names or sensitivity classifications disagreed with `JobIR`.
    #[error("terminal-result outputs disagree with JobIR definitions")]
    InvalidOutputSet,
    /// The commit timestamp was outside the live claim.
    #[error("logical instance-result commit falls outside its claim")]
    CommitOutsideClaim,
}

/// Durable claim or finalization failure.
#[derive(Debug, Error)]
pub enum LogicalInstanceResultStoreError {
    /// The repository failed or contained malformed current data.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The target is absent, cross-tenant, non-current, or nonterminal.
    #[error("logical instance-result target is not a current terminal attempt")]
    InvalidTarget,
    /// The monotonic claim generation cannot advance.
    #[error("logical instance-result claim generation is exhausted")]
    GenerationExhausted,
    /// Commit did not own the exact current live fence.
    #[error("logical instance-result claim fence was rejected")]
    ClaimRejected,
    /// A new targeted claim was not corroborated by authoritative repository time.
    #[error("logical instance-result claim time exceeds the allowed database clock skew")]
    ClaimClockSkew,
    /// A targeted claim request or exact projecting fence has expired.
    #[error("logical instance-result claim has expired")]
    ClaimExpired,
    /// Commit disagreed with immutable durable finalization evidence.
    #[error("logical instance-result commit conflicts with durable evidence")]
    CommitConflict,
    /// A selection identity was replayed with different owner or time bounds.
    #[error("logical instance-result selection identity was reused inconsistently")]
    SelectionConflict,
    /// The bounded replay horizon has closed for this selection request.
    #[error("logical instance-result selection replay horizon has closed")]
    SelectionExpired,
    /// The caller observation is not corroborated by authoritative repository time.
    #[error("logical instance-result selection time exceeds the allowed database clock skew")]
    SelectionClockSkew,
}

/// Persistence boundary for current terminal-attempt projection.
#[async_trait]
pub trait LogicalInstanceResultRepository: fmt::Debug + Send + Sync {
    /// Globally selects at most one due attempt using nonblocking record locking.
    async fn claim_next_logical_instance_result(
        &self,
        request: ClaimNextLogicalInstanceResult,
    ) -> Result<LogicalInstanceResultClaimNextOutcome, LogicalInstanceResultStoreError>;

    /// Claims one exact current terminal attempt without blob I/O.
    async fn claim_logical_instance_result(
        &self,
        request: ClaimLogicalInstanceResult,
    ) -> Result<LogicalInstanceResultClaimOutcome, LogicalInstanceResultStoreError>;

    /// Atomically persists the immutable instance result and classified outputs.
    async fn commit_logical_instance_result(
        &self,
        request: CommitLogicalInstanceResult,
    ) -> Result<LogicalInstanceResultReceipt, LogicalInstanceResultStoreError>;

    /// Idempotently isolates one exact claimed target after deterministic failure.
    async fn quarantine_logical_instance_result(
        &self,
        request: QuarantineLogicalInstanceResult,
    ) -> Result<LogicalInstanceResultQuarantineOutcome, LogicalInstanceResultStoreError>;
}

fn validate_blob(
    encoded: &[u8],
    expected_size: u64,
    expected_digest: Sha256Digest,
    error: LogicalInstanceResultValueError,
) -> Result<(), LogicalInstanceResultValueError> {
    let size = u64::try_from(encoded.len()).map_err(|_| error)?;
    let digest = Sha256Digest::from_bytes(Sha256::digest(encoded).into());
    if size == expected_size && digest == expected_digest {
        Ok(())
    } else {
        Err(error)
    }
}

fn validate_job_ir_identity(
    descriptor: &LogicalInstanceResultDescriptor,
    envelope: &JobIrEnvelope,
) -> Result<(), LogicalInstanceResultValueError> {
    let job = envelope.job();
    let identity = job.instance_identity();
    if job.job_id() == descriptor.job_id()
        && job.run_id() == descriptor.run_id()
        && identity.logical_job_key() == descriptor.logical_key().as_str()
        && identity.matrix_index() == descriptor.matrix_index()
        && identity.matrix_total() == descriptor.matrix_total()
        && identity.matrix_digest() == descriptor.matrix_digest()
    {
        Ok(())
    } else {
        Err(LogicalInstanceResultValueError::JobIrIdentityMismatch)
    }
}

fn validate_outputs(
    result: &JobResult,
    envelope: &JobIrEnvelope,
) -> Result<Vec<LogicalInstanceResultOutput>, LogicalInstanceResultValueError> {
    let definitions = envelope.job().output_definitions();
    let mut outputs = Vec::with_capacity(result.outputs().len());
    for (name, output) in result.outputs() {
        let definition = definitions
            .binary_search_by(|definition| definition.name().cmp(name))
            .ok()
            .map(|index| &definitions[index])
            .ok_or(LogicalInstanceResultValueError::InvalidOutputSet)?;
        if definition.sensitivity() == OutputSensitivity::SecretDerived
            && output.sensitivity() != OutputSensitivity::SecretDerived
        {
            return Err(LogicalInstanceResultValueError::InvalidOutputSet);
        }
        outputs.push(LogicalInstanceResultOutput {
            name: name.clone(),
            sensitivity: output.sensitivity(),
            public_value: output.public_value().map(str::to_owned),
        });
    }
    Ok(outputs)
}

const fn effective_conclusion(raw: JobConclusion, continue_on_error: bool) -> JobConclusion {
    if continue_on_error && matches!(raw, JobConclusion::Failure) {
        JobConclusion::Success
    } else {
        raw
    }
}

#[allow(clippy::too_many_arguments)]
fn descriptor_digest(
    target: &LogicalInstanceResultTarget,
    run_id: RunId,
    invocation_id: LogicalWorkflowInvocationId,
    logical_job_id: LogicalWorkflowJobId,
    instance_id: LogicalWorkflowInstanceId,
    job_id: JobId,
    logical_key: &WorkflowJobKey,
    matrix_index: u32,
    matrix_total: u32,
    matrix_digest: Sha256Digest,
    terminal_ordinal: LogicalInstanceTerminalOrdinal,
    terminal_authority: &LogicalInstanceTerminalAuthority,
    job_ir_object: &LogicalActivationObject,
    maximum_secret_exposure: JobSecretExposure,
    raw_conclusion: JobConclusion,
    result_completed_at: UnixMillis,
    result_committed_at: UnixMillis,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(DESCRIPTOR_DIGEST_DOMAIN);
    hasher.update(run_id.as_uuid().as_bytes());
    hasher.update(invocation_id.as_uuid().as_bytes());
    hasher.update(logical_job_id.as_uuid().as_bytes());
    hasher.update(instance_id.as_uuid().as_bytes());
    hasher.update(job_id.as_uuid().as_bytes());
    hasher.update(target.attempt_id().as_uuid().as_bytes());
    hash_text(&mut hasher, logical_key.as_str());
    hasher.update(matrix_index.to_be_bytes());
    hasher.update(matrix_total.to_be_bytes());
    hasher.update(matrix_digest.as_bytes());
    hasher.update(terminal_ordinal.get().to_be_bytes());
    match terminal_authority {
        // Preserve the current runner descriptor bytes exactly.
        LogicalInstanceTerminalAuthority::Runner(terminal_result) => {
            hash_result_object(&mut hasher, terminal_result);
        }
        LogicalInstanceTerminalAuthority::ServerCancellation(cancellation) => {
            hasher.update(SERVER_CANCELLATION_DESCRIPTOR_DOMAIN);
            hasher.update(cancellation.operation_id().as_uuid().as_bytes());
            hasher.update(cancellation.digest().as_bytes());
        }
    }
    hash_job_ir_object(&mut hasher, job_ir_object);
    hasher.update([secret_exposure_code(maximum_secret_exposure)]);
    hasher.update([conclusion_code(raw_conclusion)]);
    hasher.update(result_completed_at.get().to_be_bytes());
    hasher.update(result_committed_at.get().to_be_bytes());
    Sha256Digest::from_bytes(hasher.finalize().into())
}

pub(crate) fn output_set_digest(outputs: &[LogicalInstanceResultOutput]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(OUTPUTS_DIGEST_DOMAIN);
    hasher.update(
        u64::try_from(outputs.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for output in outputs {
        hash_text(&mut hasher, output.name());
        hasher.update([sensitivity_code(output.sensitivity())]);
        match output.public_value() {
            Some(value) => {
                hasher.update([1]);
                hash_text(&mut hasher, value);
            }
            None => hasher.update([0]),
        }
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn result_commit_digest(
    claim: &LogicalInstanceResultClaimFence,
    descriptor: &LogicalInstanceResultDescriptor,
    effective_conclusion: JobConclusion,
    continue_on_error: bool,
    secret_exposure: JobSecretExposure,
    outputs_digest: Sha256Digest,
    finalized_at: UnixMillis,
) -> Sha256Digest {
    rederive_commit_digest(
        descriptor.instance_id(),
        descriptor.job_id(),
        descriptor.target().attempt_id(),
        descriptor.terminal_ordinal(),
        claim.owner(),
        claim.generation(),
        claim.descriptor_digest(),
        descriptor.raw_conclusion(),
        effective_conclusion,
        continue_on_error,
        secret_exposure,
        outputs_digest,
        finalized_at,
    )
}

#[allow(clippy::too_many_arguments)] // Mirrors the complete immutable result root and fence.
pub(crate) fn rederive_commit_digest(
    instance_id: LogicalWorkflowInstanceId,
    job_id: JobId,
    attempt_id: AttemptId,
    terminal_ordinal: LogicalInstanceTerminalOrdinal,
    owner: LogicalInstanceResultWorkerId,
    generation: LogicalInstanceResultGeneration,
    descriptor_digest: Sha256Digest,
    raw_conclusion: JobConclusion,
    effective_conclusion: JobConclusion,
    continue_on_error: bool,
    secret_exposure: JobSecretExposure,
    outputs_digest: Sha256Digest,
    finalized_at: UnixMillis,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(COMMIT_DIGEST_DOMAIN);
    hasher.update(instance_id.as_uuid().as_bytes());
    hasher.update(job_id.as_uuid().as_bytes());
    hasher.update(attempt_id.as_uuid().as_bytes());
    hasher.update(terminal_ordinal.get().to_be_bytes());
    hasher.update(owner.as_uuid().as_bytes());
    hasher.update(generation.get().to_be_bytes());
    hasher.update(descriptor_digest.as_bytes());
    hasher.update([conclusion_code(raw_conclusion)]);
    hasher.update([conclusion_code(effective_conclusion)]);
    hasher.update([u8::from(continue_on_error)]);
    hasher.update([secret_exposure_code(secret_exposure)]);
    hasher.update(outputs_digest.as_bytes());
    hasher.update(finalized_at.get().to_be_bytes());
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn hash_result_object(hasher: &mut Sha256, object: &LogicalTerminalResultObject) {
    hasher.update(object.digest().as_bytes());
    hash_text(hasher, object.object_key().as_str());
    hasher.update(object.encoded_size().to_be_bytes());
    hasher.update(object.schema().to_be_bytes());
    hash_text(hasher, object.media_type());
}

fn hash_job_ir_object(hasher: &mut Sha256, object: &LogicalActivationObject) {
    hasher.update(object.digest().as_bytes());
    hash_text(hasher, object.object_key().as_str());
    hasher.update(object.encoded_size().to_be_bytes());
    hash_text(hasher, object.media_type());
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

const fn secret_exposure_code(value: JobSecretExposure) -> u8 {
    match value {
        JobSecretExposure::Secretless => 1,
        JobSecretExposure::CapabilityOnly => 2,
        JobSecretExposure::ReadableSecret => 3,
    }
}

fn hash_text(hasher: &mut Sha256, value: &str) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn validate_claim_interval(
    observed_at: UnixMillis,
    expires_at: UnixMillis,
) -> Result<(), LogicalInstanceResultValueError> {
    validate_timestamp(observed_at, "instance-result claim start")?;
    validate_timestamp(expires_at, "instance-result claim expiration")?;
    expires_at
        .get()
        .checked_sub(observed_at.get())
        .filter(|duration| *duration > 0 && *duration <= MAX_LOGICAL_INSTANCE_RESULT_CLAIM_MILLIS)
        .ok_or(LogicalInstanceResultValueError::InvalidClaimInterval)?;
    Ok(())
}

fn validate_timestamp(
    value: UnixMillis,
    field: &'static str,
) -> Result<(), LogicalInstanceResultValueError> {
    if value.get() < 0 {
        return Err(LogicalInstanceResultValueError::NegativeTimestamp(field));
    }
    Ok(())
}
