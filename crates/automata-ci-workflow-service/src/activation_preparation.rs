//! Blob-first adapter for durable logical activation preparation.

use std::{collections::BTreeMap, fmt, sync::Arc};

use crate::{
    ActivationStatus, AdmissionClock, AutonomousPreparationLease,
    AutonomousWorkflowExecutionOutcome, AutonomousWorkflowLeaseError,
    JOB_RUNTIME_CONTEXT_MEDIA_TYPE,
    orchestration::{
        LogicalActivationPreparationError, LogicalJobOrchestrationTarget,
        PreparedLogicalJobActivation,
    },
};
use automata_ci_blob::{
    BlobDescriptor, BlobKey, BlobPayload, BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore,
    MediaType,
};
use automata_ci_core::{
    ContextValue, JobRuntimeContext, NeedContext, NeedOutput, OutputSensitivity, StrategyContext,
    UnixMillis,
};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_store::{
    AdmissionObject, BindLogicalActivationPreparation, ClaimedLogicalActivationPreparation,
    LogicalActivationAggregateStatus, LogicalActivationBaseContextKind,
    LogicalActivationPreparationDescriptor, LogicalActivationPreparationReceipt,
    LogicalActivationPreparationStore, LogicalActivationPreparationStoreError,
    LogicalWorkQuarantineKind, ObjectKey, StoreError,
};
use bytes::Bytes;
use tokio_util::sync::CancellationToken;

/// Store-backed implementation of the trusted preparation repository.
#[derive(Clone)]
pub(crate) struct StoreBackedLogicalActivationPreparationRepository {
    store: Arc<dyn LogicalActivationPreparationStore>,
    blobs: Arc<dyn ImmutableBlobStore>,
    clock: Arc<dyn AdmissionClock>,
    limits: ProtocolLimits,
}

/// Opaque exact preparation binding built under one selected authority.
///
/// Queue-local worker custody retains this value before the Store operation is
/// first polled. Its debug representation intentionally excludes all tenant and
/// immutable-object evidence.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ReadyLogicalActivationPreparation {
    authority: ClaimedLogicalActivationPreparation,
    request: BindLogicalActivationPreparation,
}

impl fmt::Debug for ReadyLogicalActivationPreparation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReadyLogicalActivationPreparation([REDACTED])")
    }
}

impl ReadyLogicalActivationPreparation {
    fn new(
        authority: ClaimedLogicalActivationPreparation,
        request: BindLogicalActivationPreparation,
    ) -> Result<Self, AutonomousWorkflowLeaseError> {
        if request.claim() != authority.claim() || request.descriptor() != authority.descriptor() {
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        Ok(Self { authority, request })
    }

    pub(crate) fn matches_authority(
        &self,
        authority: &ClaimedLogicalActivationPreparation,
    ) -> bool {
        &self.authority == authority
            && self.request.claim() == authority.claim()
            && self.request.descriptor() == authority.descriptor()
    }

    pub(crate) const fn request(&self) -> &BindLogicalActivationPreparation {
        &self.request
    }
}

impl fmt::Debug for StoreBackedLogicalActivationPreparationRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoreBackedLogicalActivationPreparationRepository")
            .field("store", &"[CONFIGURED]")
            .field("blobs", &"[CONFIGURED]")
            .field("clock", &"[CONFIGURED]")
            .field("limits", &self.limits)
            .finish()
    }
}

impl StoreBackedLogicalActivationPreparationRepository {
    pub(crate) fn with_limits(
        store: Arc<dyn LogicalActivationPreparationStore>,
        blobs: Arc<dyn ImmutableBlobStore>,
        clock: Arc<dyn AdmissionClock>,
        limits: ProtocolLimits,
    ) -> Self {
        Self {
            store,
            blobs,
            clock,
            limits,
        }
    }

    /// Completes one already-selected preparation without acquiring a second claim.
    ///
    /// Every external operation is preceded by the worker-owned lease checkpoint,
    /// and the final binding uses only the exact fence recovered after renewal.
    pub(crate) async fn prepare_selected(
        &self,
        lease: &mut AutonomousPreparationLease,
        shutdown: &CancellationToken,
    ) -> Result<AutonomousWorkflowExecutionOutcome, AutonomousWorkflowLeaseError> {
        let descriptor = lease.authority().descriptor().clone();
        if descriptor.base_context_kind() != LogicalActivationBaseContextKind::AdmissionV2 {
            return Ok(relational_evidence_failure());
        }
        let Ok(base_descriptor) = admission_blob_descriptor(descriptor.base_context()) else {
            return Ok(relational_evidence_failure());
        };
        lease.before_io(shutdown)?;
        let base_bytes = match self
            .blobs
            .get_verified(&base_descriptor, descriptor.base_context().encoded_size())
            .await
        {
            Ok(blob) => blob.into_bytes(),
            Err(error) => return Ok(classify_blob_failure(error)),
        };
        let Ok(_base) = decode_base_context(&base_bytes, &self.limits) else {
            return Ok(payload_evidence_failure());
        };
        let Ok(prerequisites) = prerequisite_context(&descriptor) else {
            return Ok(relational_evidence_failure());
        };
        let Ok(prerequisite_payload) = context_payload(
            &descriptor,
            "prerequisite-context.pb",
            &prerequisites,
            &self.limits,
        ) else {
            return Ok(payload_evidence_failure());
        };
        let base_object = descriptor.base_context().clone();
        let Ok(prerequisite_object) = admission_object(prerequisite_payload.descriptor()) else {
            return Ok(relational_evidence_failure());
        };

        lease.before_io(shutdown)?;
        if let Err(error) = self.blobs.put_if_absent(prerequisite_payload).await {
            return Ok(classify_blob_failure(error));
        }

        lease.renew(shutdown).await?;
        let current = lease.authority();
        if current.descriptor() != &descriptor {
            return Ok(relational_evidence_failure());
        }
        let fence = current.claim().clone();
        let mut bound_at = trusted_now(self.clock.as_ref())
            .map_err(|_| AutonomousWorkflowLeaseError::AuthorityRejected)?;
        if bound_at < fence.claimed_at() {
            bound_at = fence.claimed_at();
        }
        if bound_at >= fence.expires_at() {
            return Err(AutonomousWorkflowLeaseError::DeadlineElapsed);
        }
        let Ok(binding) = BindLogicalActivationPreparation::new(
            descriptor,
            fence,
            base_object,
            prerequisite_object,
            bound_at,
        ) else {
            return Ok(relational_evidence_failure());
        };
        let ready = ReadyLogicalActivationPreparation::new(lease.authority().clone(), binding)?;
        lease.retain_ready_final(ready)?;
        Ok(AutonomousWorkflowExecutionOutcome::FinalRequestReady)
    }

    pub(crate) async fn submit_ready_binding(
        &self,
        lease: &AutonomousPreparationLease,
    ) -> Result<AutonomousWorkflowExecutionOutcome, AutonomousWorkflowLeaseError> {
        let ready = lease.pending_final_request()?;
        if !ready.matches_authority(lease.authority()) {
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        let binding = ready.request();
        match self
            .store
            .bind_logical_activation_preparation(binding.clone())
            .await
        {
            Err(LogicalActivationPreparationStoreError::Store(StoreError::Operation(_))) => {
                Ok(AutonomousWorkflowExecutionOutcome::FinalRequestOperation)
            }
            Ok(receipt) => {
                let exact = receipt.descriptor() == binding.descriptor()
                    && receipt.claim() == binding.claim()
                    && receipt.base_context() == binding.base_context()
                    && receipt.prerequisite_context() == binding.prerequisite_context()
                    && receipt.input_digest() == binding.input_digest()
                    && receipt.bound_at() == binding.bound_at();
                if !exact || prepared_from_receipt(&receipt).is_err() {
                    Ok(relational_evidence_failure())
                } else {
                    Ok(AutonomousWorkflowExecutionOutcome::Completed)
                }
            }
            Err(error) => classify_preparation_store_failure(&error),
        }
    }
}

fn decode_base_context(
    bytes: &[u8],
    limits: &ProtocolLimits,
) -> Result<JobRuntimeContext, LogicalActivationPreparationError> {
    let context = automata_ci_protocol_protobuf::decode_job_runtime_context(bytes, limits)
        .map_err(|_| LogicalActivationPreparationError::Corrupt)?;
    let canonical = automata_ci_protocol_protobuf::encode_job_runtime_context(&context, limits)
        .map_err(|_| LogicalActivationPreparationError::Corrupt)?;
    if canonical != bytes || !valid_base_context_shape(&context) {
        return Err(LogicalActivationPreparationError::Corrupt);
    }
    Ok(context)
}

fn valid_base_context_shape(context: &JobRuntimeContext) -> bool {
    let strategy = context.strategy();
    context.matrix().as_object().is_some_and(BTreeMap::is_empty)
        && context.needs().is_empty()
        && strategy.fail_fast()
        && strategy.job_index() == 0
        && strategy.job_total() == 1
        && strategy.max_parallel() == 1
}

fn admission_blob_descriptor(
    object: &AdmissionObject,
) -> Result<BlobDescriptor, LogicalActivationPreparationError> {
    let key = BlobKey::new(object.object_key().as_str().to_owned())
        .map_err(|_| LogicalActivationPreparationError::Corrupt)?;
    let media_type = MediaType::new(object.media_type().to_owned())
        .map_err(|_| LogicalActivationPreparationError::Corrupt)?;
    Ok(BlobDescriptor::new(
        key,
        object.digest(),
        object.encoded_size(),
        media_type,
    ))
}

fn prerequisite_context(
    descriptor: &LogicalActivationPreparationDescriptor,
) -> Result<JobRuntimeContext, LogicalActivationPreparationError> {
    let strategy = StrategyContext::new(true, 0, 1, 1)
        .map_err(|_| LogicalActivationPreparationError::Corrupt)?;
    let empty = ContextValue::empty_object();

    let mut needs = BTreeMap::new();
    for prerequisite in descriptor.prerequisites() {
        let mut outputs = BTreeMap::new();
        for output in prerequisite.outputs() {
            let value = match output.sensitivity() {
                OutputSensitivity::Public => output
                    .public_value()
                    .ok_or(LogicalActivationPreparationError::Corrupt)?,
                OutputSensitivity::SecretDerived => "",
            };
            outputs.insert(
                output.name().as_str().to_owned(),
                NeedOutput::new(value, output.sensitivity())
                    .map_err(|_| LogicalActivationPreparationError::Corrupt)?,
            );
        }
        needs.insert(
            prerequisite.logical_key().as_str().to_owned(),
            NeedContext::new(prerequisite.effective_conclusion(), outputs)
                .map_err(|_| LogicalActivationPreparationError::Corrupt)?,
        );
    }
    JobRuntimeContext::new(
        empty.clone(),
        empty.clone(),
        empty,
        strategy,
        needs,
        BTreeMap::new(),
    )
    .map_err(|_| LogicalActivationPreparationError::Corrupt)
}

fn context_payload(
    descriptor: &LogicalActivationPreparationDescriptor,
    filename: &str,
    context: &JobRuntimeContext,
    limits: &ProtocolLimits,
) -> Result<BlobPayload, LogicalActivationPreparationError> {
    let bytes = automata_ci_protocol_protobuf::encode_job_runtime_context(context, limits)
        .map_err(|_| LogicalActivationPreparationError::Corrupt)?;
    let key = BlobKey::new(format!(
        "workflow-plan-v2/activation-preparations/{}/{}/{}/{}/{filename}",
        descriptor.target().run_id().as_uuid(),
        descriptor.target().invocation_id().as_uuid(),
        descriptor.target().logical_job_id().as_uuid(),
        digest_hex(descriptor.descriptor_digest().as_bytes()),
    ))
    .map_err(|_| LogicalActivationPreparationError::Corrupt)?;
    let media_type = MediaType::new(JOB_RUNTIME_CONTEXT_MEDIA_TYPE)
        .map_err(|_| LogicalActivationPreparationError::Corrupt)?;
    Ok(BlobPayload::from_bytes(key, media_type, Bytes::from(bytes)))
}

pub(crate) fn prepared_from_receipt(
    receipt: &LogicalActivationPreparationReceipt,
) -> Result<PreparedLogicalJobActivation, LogicalActivationPreparationError> {
    let descriptor = receipt.descriptor();
    let target = LogicalJobOrchestrationTarget::new(
        descriptor.target().tenant().clone(),
        descriptor.target().run_id(),
        descriptor.target().invocation_id(),
        descriptor.target().logical_job_id(),
    )
    .map_err(|_| LogicalActivationPreparationError::Corrupt)?;
    let prepared = PreparedLogicalJobActivation::new(
        target,
        descriptor.logical_key().clone(),
        descriptor.source_order(),
        descriptor.execution().clone(),
        descriptor.authority_profile(),
        descriptor.runner_policy().clone(),
        descriptor.runtime_policy().clone(),
        descriptor.plan().clone(),
        descriptor.event().clone(),
        receipt.base_context().clone(),
        receipt.prerequisite_context().clone(),
        activation_status(descriptor.status()),
    )
    .map_err(|_| LogicalActivationPreparationError::Corrupt)?;
    if prepared.input_digest() != receipt.input_digest() {
        return Err(LogicalActivationPreparationError::Corrupt);
    }
    Ok(prepared)
}

fn admission_object(
    descriptor: &BlobDescriptor,
) -> Result<AdmissionObject, LogicalActivationPreparationError> {
    AdmissionObject::new(
        descriptor.digest(),
        ObjectKey::new(descriptor.key().as_str().to_owned())
            .map_err(|_| LogicalActivationPreparationError::Corrupt)?,
        descriptor.size(),
        descriptor.media_type().as_str(),
    )
    .map_err(|_| LogicalActivationPreparationError::Corrupt)
}

const fn activation_status(value: LogicalActivationAggregateStatus) -> ActivationStatus {
    match value {
        LogicalActivationAggregateStatus::Success => ActivationStatus::Success,
        LogicalActivationAggregateStatus::Failure => ActivationStatus::Failure,
        LogicalActivationAggregateStatus::Cancelled => ActivationStatus::Cancelled,
        LogicalActivationAggregateStatus::Skipped => ActivationStatus::Skipped,
    }
}

fn trusted_now(
    clock: &dyn AdmissionClock,
) -> Result<UnixMillis, LogicalActivationPreparationError> {
    let now = clock.now();
    if now.get() < 0 {
        Err(LogicalActivationPreparationError::Corrupt)
    } else {
        Ok(now)
    }
}

const fn relational_evidence_failure() -> AutonomousWorkflowExecutionOutcome {
    AutonomousWorkflowExecutionOutcome::EvidenceFailure(
        LogicalWorkQuarantineKind::RelationalEvidence,
    )
}

const fn payload_evidence_failure() -> AutonomousWorkflowExecutionOutcome {
    AutonomousWorkflowExecutionOutcome::EvidenceFailure(LogicalWorkQuarantineKind::PayloadEvidence)
}

const fn classify_blob_failure(error: BlobStoreError) -> AutonomousWorkflowExecutionOutcome {
    match error.kind() {
        BlobStoreErrorKind::Unavailable
        | BlobStoreErrorKind::Unauthorized
        | BlobStoreErrorKind::InvalidResponse => AutonomousWorkflowExecutionOutcome::Retryable,
        BlobStoreErrorKind::NotFound
        | BlobStoreErrorKind::Conflict
        | BlobStoreErrorKind::Integrity
        | BlobStoreErrorKind::TooLarge => AutonomousWorkflowExecutionOutcome::EvidenceFailure(
            LogicalWorkQuarantineKind::ObjectEvidence,
        ),
    }
}

fn classify_preparation_store_failure(
    error: &LogicalActivationPreparationStoreError,
) -> Result<AutonomousWorkflowExecutionOutcome, AutonomousWorkflowLeaseError> {
    match error {
        LogicalActivationPreparationStoreError::Store(StoreError::Operation(_)) => {
            Ok(AutonomousWorkflowExecutionOutcome::Retryable)
        }
        LogicalActivationPreparationStoreError::InvalidTarget
        | LogicalActivationPreparationStoreError::ClaimRejected => {
            Err(AutonomousWorkflowLeaseError::AuthorityRejected)
        }
        LogicalActivationPreparationStoreError::Store(_)
        | LogicalActivationPreparationStoreError::PreparationConflict
        | LogicalActivationPreparationStoreError::GenerationExhausted
        | LogicalActivationPreparationStoreError::BindConflict => Ok(relational_evidence_failure()),
    }
}

fn digest_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(64);
    for byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}
