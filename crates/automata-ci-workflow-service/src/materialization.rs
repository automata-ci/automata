//! Verified blob-to-store materialization of one activated logical instance.

use std::sync::Arc;

use automata_ci_blob::{
    BlobDescriptor, BlobKey, BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore, MediaType,
};
use automata_ci_core::{JobIrEnvelope, JobRuntimeContext, UnixMillis};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_store::{
    ClaimedLogicalInstanceMaterialization, CommitLogicalInstanceMaterialization,
    LogicalActivationObject, LogicalMaterializationReceipt, LogicalMaterializationRepository,
    LogicalMaterializationStoreError, LogicalWorkQuarantineKind, StoreError,
};
use bytes::Bytes;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::{
    AdmissionClock, AutonomousMaterializationLease, AutonomousWorkflowExecutionOutcome,
    AutonomousWorkflowLeaseError,
};

/// Current-only service joining immutable activation blobs to runnable jobs.
#[derive(Clone, Debug)]
pub(crate) struct LogicalInstanceMaterializationService {
    blobs: Arc<dyn ImmutableBlobStore>,
    repository: Arc<dyn LogicalMaterializationRepository>,
    clock: Arc<dyn AdmissionClock>,
    limits: ProtocolLimits,
}

/// Opaque exact materialization commit built under one selected authority.
///
/// Queue-local worker custody retains this value before the Store operation is
/// first polled. Its debug representation intentionally excludes all tenant and
/// immutable-object evidence.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ReadyLogicalInstanceMaterialization {
    authority: ClaimedLogicalInstanceMaterialization,
    request: CommitLogicalInstanceMaterialization,
}

impl std::fmt::Debug for ReadyLogicalInstanceMaterialization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ReadyLogicalInstanceMaterialization([REDACTED])")
    }
}

impl ReadyLogicalInstanceMaterialization {
    fn new(
        authority: ClaimedLogicalInstanceMaterialization,
        request: CommitLogicalInstanceMaterialization,
    ) -> Result<Self, AutonomousWorkflowLeaseError> {
        if request.claim() != authority.claim() {
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        Ok(Self { authority, request })
    }

    pub(crate) fn matches_authority(
        &self,
        authority: &ClaimedLogicalInstanceMaterialization,
    ) -> bool {
        &self.authority == authority && self.request.claim() == authority.claim()
    }

    pub(crate) const fn request(&self) -> &CommitLogicalInstanceMaterialization {
        &self.request
    }
}

impl LogicalInstanceMaterializationService {
    pub(crate) fn with_limits(
        blobs: Arc<dyn ImmutableBlobStore>,
        repository: Arc<dyn LogicalMaterializationRepository>,
        clock: Arc<dyn AdmissionClock>,
        limits: ProtocolLimits,
    ) -> Self {
        Self {
            blobs,
            repository,
            clock,
            limits,
        }
    }

    /// Materializes one already-selected instance without acquiring a second claim.
    pub(crate) async fn materialize_selected(
        &self,
        lease: &mut AutonomousMaterializationLease,
        shutdown: &CancellationToken,
    ) -> Result<AutonomousWorkflowExecutionOutcome, AutonomousWorkflowLeaseError> {
        let descriptor = lease.authority().descriptor().clone();
        lease.before_io(shutdown)?;
        let job_bytes = match self.load(descriptor.job_ir()).await {
            Ok(bytes) => bytes,
            Err(error) => return Ok(classify_materialization_load_failure(&error)),
        };
        lease.before_io(shutdown)?;
        let runtime_bytes = match self.load(descriptor.runtime_context()).await {
            Ok(bytes) => bytes,
            Err(error) => return Ok(classify_materialization_load_failure(&error)),
        };
        let Ok(envelope) = decode_job_ir(&job_bytes, &self.limits) else {
            return Ok(materialization_payload_failure());
        };
        let Ok(runtime_context) = decode_runtime_context(&runtime_bytes, &self.limits) else {
            return Ok(materialization_payload_failure());
        };

        lease.renew(shutdown).await?;
        if lease.authority().descriptor() != &descriptor {
            return Ok(materialization_relational_failure());
        }
        let claim = lease.authority().claim();
        let mut committed_at = trusted_now(self.clock.as_ref())
            .map_err(|_| AutonomousWorkflowLeaseError::AuthorityRejected)?;
        if committed_at < claim.claimed_at() {
            committed_at = claim.claimed_at();
        }
        if committed_at >= claim.expires_at() {
            return Err(AutonomousWorkflowLeaseError::DeadlineElapsed);
        }
        let Ok(commit) = CommitLogicalInstanceMaterialization::new(
            lease.authority(),
            &job_bytes,
            &envelope,
            &runtime_bytes,
            &runtime_context,
            committed_at,
        ) else {
            return Ok(materialization_payload_failure());
        };
        let ready = ReadyLogicalInstanceMaterialization::new(lease.authority().clone(), commit)?;
        lease.retain_ready_final(ready)?;
        Ok(AutonomousWorkflowExecutionOutcome::FinalRequestReady)
    }

    pub(crate) async fn submit_ready_commit(
        &self,
        lease: &AutonomousMaterializationLease,
    ) -> Result<AutonomousWorkflowExecutionOutcome, AutonomousWorkflowLeaseError> {
        let ready = lease.pending_final_request()?;
        if !ready.matches_authority(lease.authority()) {
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        let commit = ready.request();
        match self
            .repository
            .commit_logical_instance_materialization(commit.clone())
            .await
        {
            Err(LogicalMaterializationStoreError::Store(StoreError::Operation(_))) => {
                Ok(AutonomousWorkflowExecutionOutcome::FinalRequestOperation)
            }
            Ok(receipt)
                if receipt == LogicalMaterializationReceipt::new(commit, receipt.is_replay()) =>
            {
                Ok(AutonomousWorkflowExecutionOutcome::Completed)
            }
            Ok(_) => Ok(materialization_relational_failure()),
            Err(error) => classify_materialization_store_failure(&error),
        }
    }

    async fn load(
        &self,
        object: &LogicalActivationObject,
    ) -> Result<Bytes, LogicalInstanceMaterializationError> {
        let protocol_maximum = u64::try_from(self.limits.max_frame_bytes())
            .map_err(|_| LogicalInstanceMaterializationError::InvalidObject)?;
        if object.encoded_size() > protocol_maximum {
            return Err(LogicalInstanceMaterializationError::InvalidObject);
        }
        let key = BlobKey::new(object.object_key().as_str().to_owned())
            .map_err(|_| LogicalInstanceMaterializationError::InvalidObject)?;
        let media_type = MediaType::new(object.media_type())
            .map_err(|_| LogicalInstanceMaterializationError::InvalidObject)?;
        let descriptor =
            BlobDescriptor::new(key, object.digest(), object.encoded_size(), media_type);
        self.blobs
            .get_verified(&descriptor, protocol_maximum)
            .await
            .map(automata_ci_blob::VerifiedBlob::into_bytes)
            .map_err(LogicalInstanceMaterializationError::Blob)
    }
}

#[derive(Debug, Error)]
enum LogicalInstanceMaterializationError {
    /// The trusted clock returned an invalid or overflowing interval.
    #[error("logical instance materialization time is invalid")]
    InvalidTimestamp,
    /// A durable activation object cannot fit the configured protocol budget.
    #[error("logical instance materialization object is invalid")]
    InvalidObject,
    /// The `JobIR` object is malformed, unsupported, or noncanonical.
    #[error("logical instance JobIR object is invalid")]
    InvalidJobIr,
    /// The runtime-context object is malformed, unsupported, or noncanonical.
    #[error("logical instance runtime context object is invalid")]
    InvalidRuntimeContext,
    /// Immutable object storage failed.
    #[error(transparent)]
    Blob(#[from] BlobStoreError),
}

fn trusted_now(
    clock: &dyn AdmissionClock,
) -> Result<UnixMillis, LogicalInstanceMaterializationError> {
    let value = clock.now();
    if value.get() < 0 {
        return Err(LogicalInstanceMaterializationError::InvalidTimestamp);
    }
    Ok(value)
}

fn decode_job_ir(
    encoded: &[u8],
    limits: &ProtocolLimits,
) -> Result<JobIrEnvelope, LogicalInstanceMaterializationError> {
    let envelope = automata_ci_protocol_protobuf::decode_job_ir(encoded, limits)
        .map_err(|_| LogicalInstanceMaterializationError::InvalidJobIr)?;
    let canonical = automata_ci_protocol_protobuf::encode_job_ir(&envelope, limits)
        .map_err(|_| LogicalInstanceMaterializationError::InvalidJobIr)?;
    if canonical != encoded {
        return Err(LogicalInstanceMaterializationError::InvalidJobIr);
    }
    Ok(envelope)
}

fn decode_runtime_context(
    encoded: &[u8],
    limits: &ProtocolLimits,
) -> Result<JobRuntimeContext, LogicalInstanceMaterializationError> {
    let context = automata_ci_protocol_protobuf::decode_job_runtime_context(encoded, limits)
        .map_err(|_| LogicalInstanceMaterializationError::InvalidRuntimeContext)?;
    let canonical = automata_ci_protocol_protobuf::encode_job_runtime_context(&context, limits)
        .map_err(|_| LogicalInstanceMaterializationError::InvalidRuntimeContext)?;
    if canonical != encoded {
        return Err(LogicalInstanceMaterializationError::InvalidRuntimeContext);
    }
    Ok(context)
}

const fn materialization_relational_failure() -> AutonomousWorkflowExecutionOutcome {
    AutonomousWorkflowExecutionOutcome::EvidenceFailure(
        LogicalWorkQuarantineKind::RelationalEvidence,
    )
}

const fn materialization_payload_failure() -> AutonomousWorkflowExecutionOutcome {
    AutonomousWorkflowExecutionOutcome::EvidenceFailure(LogicalWorkQuarantineKind::PayloadEvidence)
}

fn classify_materialization_load_failure(
    error: &LogicalInstanceMaterializationError,
) -> AutonomousWorkflowExecutionOutcome {
    match error {
        LogicalInstanceMaterializationError::Blob(error) => match error.kind() {
            BlobStoreErrorKind::Unavailable
            | BlobStoreErrorKind::Unauthorized
            | BlobStoreErrorKind::InvalidResponse => AutonomousWorkflowExecutionOutcome::Retryable,
            BlobStoreErrorKind::NotFound
            | BlobStoreErrorKind::Conflict
            | BlobStoreErrorKind::Integrity
            | BlobStoreErrorKind::TooLarge => AutonomousWorkflowExecutionOutcome::EvidenceFailure(
                LogicalWorkQuarantineKind::ObjectEvidence,
            ),
        },
        LogicalInstanceMaterializationError::InvalidJobIr
        | LogicalInstanceMaterializationError::InvalidRuntimeContext => {
            materialization_payload_failure()
        }
        LogicalInstanceMaterializationError::InvalidTimestamp
        | LogicalInstanceMaterializationError::InvalidObject => {
            materialization_relational_failure()
        }
    }
}

fn classify_materialization_store_failure(
    error: &LogicalMaterializationStoreError,
) -> Result<AutonomousWorkflowExecutionOutcome, AutonomousWorkflowLeaseError> {
    match error {
        LogicalMaterializationStoreError::Store(StoreError::Operation(_)) => {
            Ok(AutonomousWorkflowExecutionOutcome::Retryable)
        }
        LogicalMaterializationStoreError::InvalidTarget
        | LogicalMaterializationStoreError::ClaimRejected => {
            Err(AutonomousWorkflowLeaseError::AuthorityRejected)
        }
        LogicalMaterializationStoreError::Store(_)
        | LogicalMaterializationStoreError::GenerationExhausted
        | LogicalMaterializationStoreError::CommitConflict => {
            Ok(materialization_relational_failure())
        }
    }
}
