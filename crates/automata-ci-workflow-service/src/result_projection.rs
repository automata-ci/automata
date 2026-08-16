//! Autonomous projection of exact immutable execution results.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use automata_ci_blob::{
    BlobDescriptor, BlobKey, BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore, MediaType,
    VerifiedBlob,
};
use automata_ci_core::{JobResult, Sha256Digest, UnixMillis, WorkflowPlan};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_protocol_protobuf::decode_job_ir;
use automata_ci_store::{
    AdmissionObject, ClaimNextLogicalInstanceResult, ClaimNextLogicalJobResult,
    ClaimedLogicalInstanceResult, ClaimedLogicalJobResult, CommitLogicalInstanceResult,
    CommitLogicalJobResult, LogicalActivationObject, LogicalInstanceResultClaimNextOutcome,
    LogicalInstanceResultQuarantineKind, LogicalInstanceResultQuarantineOutcome,
    LogicalInstanceResultReceipt, LogicalInstanceResultRepository,
    LogicalInstanceResultSelectionId, LogicalInstanceResultStoreError,
    LogicalInstanceResultValueError, LogicalInstanceResultWorkerId,
    LogicalInstanceTerminalAuthority, LogicalJobResultClaimNextOutcome,
    LogicalJobResultQuarantineKind, LogicalJobResultQuarantineOutcome, LogicalJobResultReceipt,
    LogicalJobResultRepository, LogicalJobResultSelectionId, LogicalJobResultStoreError,
    LogicalJobResultValueError, LogicalJobResultWorkerId, QuarantineLogicalInstanceResult,
    QuarantineLogicalJobResult, StoreError,
};
use thiserror::Error;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::AdmissionClock;

/// Duration of one autonomous result-projection claim.
pub const LOGICAL_RESULT_PROJECTION_CLAIM_MILLIS: i64 = 5 * 60 * 1_000;
const IDLE_POLL_MILLIS: u64 = 250;

/// One unit of autonomous projection work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LogicalResultProjectionOutcome {
    /// A terminal attempt became an immutable logical-instance result.
    Instance(LogicalInstanceResultReceipt),
    /// A ready logical job became terminal and can unlock dependents.
    Job(LogicalJobResultReceipt),
    /// One corrupt terminal-attempt target was durably isolated.
    InstanceQuarantined,
    /// One corrupt logical-job target was durably isolated.
    JobQuarantined,
    /// No unlocked due work was available in either projection stage.
    Idle,
}

/// Cancellation-aware worker for instance and logical-job result projection.
#[derive(Debug)]
pub struct LogicalResultProjectionService {
    blobs: Arc<dyn ImmutableBlobStore>,
    instance_results: Arc<dyn LogicalInstanceResultRepository>,
    job_results: Arc<dyn LogicalJobResultRepository>,
    clock: Arc<dyn AdmissionClock>,
    instance_worker: LogicalInstanceResultWorkerId,
    job_worker: LogicalJobResultWorkerId,
    protocol_limits: ProtocolLimits,
    prefer_job: AtomicBool,
}

impl LogicalResultProjectionService {
    /// Creates one worker over credential-free blob and repository ports.
    #[must_use]
    pub fn new(
        blobs: Arc<dyn ImmutableBlobStore>,
        instance_results: Arc<dyn LogicalInstanceResultRepository>,
        job_results: Arc<dyn LogicalJobResultRepository>,
        clock: Arc<dyn AdmissionClock>,
        instance_worker: LogicalInstanceResultWorkerId,
        job_worker: LogicalJobResultWorkerId,
        protocol_limits: ProtocolLimits,
    ) -> Self {
        Self {
            blobs,
            instance_results,
            job_results,
            clock,
            instance_worker,
            job_worker,
            protocol_limits,
            prefer_job: AtomicBool::new(false),
        }
    }

    /// Claims and projects at most one result, alternating the first stage.
    ///
    /// # Errors
    ///
    /// Returns a sanitized clock, storage, decoding, validation, persistence,
    /// or cancellation failure.
    pub async fn run_once(
        &self,
        shutdown: CancellationToken,
    ) -> Result<LogicalResultProjectionOutcome, LogicalResultProjectionError> {
        if shutdown.is_cancelled() {
            return Err(LogicalResultProjectionError::Shutdown);
        }
        let job_first = self.prefer_job.fetch_xor(true, Ordering::Relaxed);
        if job_first {
            if let Some(outcome) = self.try_job(&shutdown).await? {
                return Ok(outcome);
            }
            if let Some(outcome) = self.try_instance(&shutdown).await? {
                return Ok(outcome);
            }
        } else {
            if let Some(outcome) = self.try_instance(&shutdown).await? {
                return Ok(outcome);
            }
            if let Some(outcome) = self.try_job(&shutdown).await? {
                return Ok(outcome);
            }
        }
        Ok(LogicalResultProjectionOutcome::Idle)
    }

    /// Polls until local cancellation or the first non-cancellation failure.
    ///
    /// # Errors
    ///
    /// Returns the first sanitized projection failure. Cancellation completes
    /// normally after interrupting any in-flight claim, load, or commit.
    pub async fn run(
        &self,
        shutdown: CancellationToken,
    ) -> Result<(), LogicalResultProjectionError> {
        loop {
            if shutdown.is_cancelled() {
                return Ok(());
            }
            match self.run_once(shutdown.child_token()).await {
                Ok(LogicalResultProjectionOutcome::Idle) => {
                    tokio::select! {
                        () = shutdown.cancelled() => return Ok(()),
                        () = sleep(Duration::from_millis(IDLE_POLL_MILLIS)) => {}
                    }
                }
                Ok(_) => {}
                Err(LogicalResultProjectionError::Shutdown) if shutdown.is_cancelled() => {
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn try_instance(
        &self,
        shutdown: &CancellationToken,
    ) -> Result<Option<LogicalResultProjectionOutcome>, LogicalResultProjectionError> {
        let (observed_at, expires_at) = self.claim_interval()?;
        let selection_id = LogicalInstanceResultSelectionId::from_uuid(Uuid::new_v4())
            .map_err(LogicalResultProjectionError::InstanceValue)?;
        let request = ClaimNextLogicalInstanceResult::new(
            selection_id,
            self.instance_worker,
            observed_at,
            expires_at,
        )
        .map_err(LogicalResultProjectionError::InstanceValue)?;
        let outcome = tokio::select! {
            () = shutdown.cancelled() => return Err(LogicalResultProjectionError::Shutdown),
            outcome = self.instance_results.claim_next_logical_instance_result(request) => outcome?,
        };
        match outcome {
            LogicalInstanceResultClaimNextOutcome::Claimed(claimed) => {
                self.project_instance(claimed, shutdown).await
            }
            LogicalInstanceResultClaimNextOutcome::Quarantined => {
                Ok(Some(LogicalResultProjectionOutcome::InstanceQuarantined))
            }
            LogicalInstanceResultClaimNextOutcome::Finalized(_)
            | LogicalInstanceResultClaimNextOutcome::Idle => Ok(None),
        }
    }

    #[allow(clippy::too_many_lines)] // Keeps the three closed terminal-authority paths together.
    async fn project_instance(
        &self,
        claimed: ClaimedLogicalInstanceResult,
        shutdown: &CancellationToken,
    ) -> Result<Option<LogicalResultProjectionOutcome>, LogicalResultProjectionError> {
        let runner_result = match claimed.descriptor().terminal_authority() {
            LogicalInstanceTerminalAuthority::Runner(result_object) => {
                let encoded_result = match self
                    .load(
                        result_object.object_key().as_str(),
                        result_object.digest(),
                        result_object.encoded_size(),
                        result_object.media_type(),
                        shutdown,
                    )
                    .await
                {
                    Ok(encoded) => encoded,
                    Err(error) => {
                        let Some(kind) = instance_load_quarantine_kind(&error) else {
                            return Err(error);
                        };
                        return self.quarantine_instance(&claimed, kind, shutdown).await;
                    }
                };
                let result: JobResult = match serde_json::from_slice(&encoded_result) {
                    Ok(result) => result,
                    Err(_) => {
                        return self
                            .quarantine_instance(
                                &claimed,
                                LogicalInstanceResultQuarantineKind::PayloadEvidence,
                                shutdown,
                            )
                            .await;
                    }
                };
                Some((encoded_result, result))
            }
            LogicalInstanceTerminalAuthority::ServerCancellation(_)
            | LogicalInstanceTerminalAuthority::ServerLeaseExpiry => None,
        };
        let job_ir_object = claimed.descriptor().job_ir();
        let protocol_maximum = u64::try_from(self.protocol_limits.max_frame_bytes())
            .map_err(|_| LogicalResultProjectionError::InvalidObject)?;
        if job_ir_object.encoded_size() > protocol_maximum {
            return self
                .quarantine_instance(
                    &claimed,
                    LogicalInstanceResultQuarantineKind::ObjectEvidence,
                    shutdown,
                )
                .await;
        }
        let encoded_job_ir = match self.load_activation(job_ir_object, shutdown).await {
            Ok(encoded) => encoded,
            Err(error) => {
                let Some(kind) = instance_load_quarantine_kind(&error) else {
                    return Err(error);
                };
                return self.quarantine_instance(&claimed, kind, shutdown).await;
            }
        };
        let Ok(job_ir) = decode_job_ir(&encoded_job_ir, &self.protocol_limits) else {
            return self
                .quarantine_instance(
                    &claimed,
                    LogicalInstanceResultQuarantineKind::PayloadEvidence,
                    shutdown,
                )
                .await;
        };
        let finalized_at = self.clock.now();
        let commit_result = match (runner_result, claimed.descriptor().terminal_authority()) {
            (Some((encoded_result, result)), LogicalInstanceTerminalAuthority::Runner(_)) => {
                CommitLogicalInstanceResult::new(
                    &claimed,
                    &encoded_result,
                    &result,
                    &encoded_job_ir,
                    &job_ir,
                    finalized_at,
                )
            }
            (None, LogicalInstanceTerminalAuthority::ServerCancellation(_)) => {
                CommitLogicalInstanceResult::new_server_cancellation(
                    &claimed,
                    &encoded_job_ir,
                    &job_ir,
                    finalized_at,
                )
            }
            (None, LogicalInstanceTerminalAuthority::ServerLeaseExpiry) => {
                CommitLogicalInstanceResult::new_server_lease_expiry(
                    &claimed,
                    &encoded_job_ir,
                    &job_ir,
                    finalized_at,
                )
            }
            _ => Err(LogicalInstanceResultValueError::TerminalAuthorityMismatch),
        };
        let commit = match commit_result {
            Ok(commit) => commit,
            Err(error) if instance_value_is_target_corruption(error) => {
                return self
                    .quarantine_instance(
                        &claimed,
                        LogicalInstanceResultQuarantineKind::PayloadEvidence,
                        shutdown,
                    )
                    .await;
            }
            Err(error) => return Err(LogicalResultProjectionError::InstanceValue(error)),
        };
        self.persist_instance(&claimed, commit, shutdown).await
    }

    async fn persist_instance(
        &self,
        claimed: &ClaimedLogicalInstanceResult,
        commit: CommitLogicalInstanceResult,
        shutdown: &CancellationToken,
    ) -> Result<Option<LogicalResultProjectionOutcome>, LogicalResultProjectionError> {
        let receipt = tokio::select! {
            () = shutdown.cancelled() => return Err(LogicalResultProjectionError::Shutdown),
            receipt = self.instance_results.commit_logical_instance_result(commit) => receipt,
        };
        match receipt {
            Ok(receipt) => Ok(Some(LogicalResultProjectionOutcome::Instance(receipt))),
            Err(error) if instance_store_is_target_corruption(&error) => {
                self.quarantine_instance(
                    claimed,
                    LogicalInstanceResultQuarantineKind::RelationalEvidence,
                    shutdown,
                )
                .await
            }
            Err(error) => Err(LogicalResultProjectionError::InstanceStore(error)),
        }
    }

    async fn try_job(
        &self,
        shutdown: &CancellationToken,
    ) -> Result<Option<LogicalResultProjectionOutcome>, LogicalResultProjectionError> {
        let (observed_at, expires_at) = self.claim_interval()?;
        let selection_id = LogicalJobResultSelectionId::from_uuid(Uuid::new_v4())
            .map_err(LogicalResultProjectionError::JobValue)?;
        let request =
            ClaimNextLogicalJobResult::new(selection_id, self.job_worker, observed_at, expires_at)
                .map_err(LogicalResultProjectionError::JobValue)?;
        let outcome = tokio::select! {
            () = shutdown.cancelled() => return Err(LogicalResultProjectionError::Shutdown),
            outcome = self.job_results.claim_next_logical_job_result(request) => outcome?,
        };
        match outcome {
            LogicalJobResultClaimNextOutcome::Claimed(claimed) => {
                self.project_job(claimed, shutdown).await
            }
            LogicalJobResultClaimNextOutcome::Quarantined => {
                Ok(Some(LogicalResultProjectionOutcome::JobQuarantined))
            }
            LogicalJobResultClaimNextOutcome::Finalized(_)
            | LogicalJobResultClaimNextOutcome::Idle => Ok(None),
        }
    }

    async fn project_job(
        &self,
        claimed: ClaimedLogicalJobResult,
        shutdown: &CancellationToken,
    ) -> Result<Option<LogicalResultProjectionOutcome>, LogicalResultProjectionError> {
        let plan_object = claimed.descriptor().plan();
        let encoded_plan = match self.load_admission(plan_object, shutdown).await {
            Ok(encoded) => encoded,
            Err(error) => {
                let Some(kind) = job_load_quarantine_kind(&error) else {
                    return Err(error);
                };
                return self.quarantine_job(&claimed, kind, shutdown).await;
            }
        };
        let plan: WorkflowPlan = match serde_json::from_slice(&encoded_plan) {
            Ok(plan) => plan,
            Err(_) => {
                return self
                    .quarantine_job(
                        &claimed,
                        LogicalJobResultQuarantineKind::PayloadEvidence,
                        shutdown,
                    )
                    .await;
            }
        };
        let finalized_at = self.clock.now();
        let commit = match CommitLogicalJobResult::new(&claimed, &encoded_plan, &plan, finalized_at)
        {
            Ok(commit) => commit,
            Err(error) if job_value_is_target_corruption(error) => {
                return self
                    .quarantine_job(
                        &claimed,
                        LogicalJobResultQuarantineKind::PayloadEvidence,
                        shutdown,
                    )
                    .await;
            }
            Err(error) => return Err(LogicalResultProjectionError::JobValue(error)),
        };
        self.persist_job(&claimed, commit, shutdown).await
    }

    async fn persist_job(
        &self,
        claimed: &ClaimedLogicalJobResult,
        commit: CommitLogicalJobResult,
        shutdown: &CancellationToken,
    ) -> Result<Option<LogicalResultProjectionOutcome>, LogicalResultProjectionError> {
        let receipt = tokio::select! {
            () = shutdown.cancelled() => return Err(LogicalResultProjectionError::Shutdown),
            receipt = self.job_results.commit_logical_job_result(commit) => receipt,
        };
        match receipt {
            Ok(receipt) => Ok(Some(LogicalResultProjectionOutcome::Job(receipt))),
            Err(error) if job_store_is_target_corruption(&error) => {
                self.quarantine_job(
                    claimed,
                    LogicalJobResultQuarantineKind::RelationalEvidence,
                    shutdown,
                )
                .await
            }
            Err(error) => Err(LogicalResultProjectionError::JobStore(error)),
        }
    }

    fn claim_interval(&self) -> Result<(UnixMillis, UnixMillis), LogicalResultProjectionError> {
        let observed_at = self.clock.now();
        let expires_at = observed_at
            .get()
            .checked_add(LOGICAL_RESULT_PROJECTION_CLAIM_MILLIS)
            .map(UnixMillis::new)
            .ok_or(LogicalResultProjectionError::InvalidTimestamp)?;
        Ok((observed_at, expires_at))
    }

    async fn quarantine_instance(
        &self,
        claimed: &ClaimedLogicalInstanceResult,
        kind: LogicalInstanceResultQuarantineKind,
        shutdown: &CancellationToken,
    ) -> Result<Option<LogicalResultProjectionOutcome>, LogicalResultProjectionError> {
        let request = QuarantineLogicalInstanceResult::new(claimed, kind);
        let outcome = tokio::select! {
            () = shutdown.cancelled() => return Err(LogicalResultProjectionError::Shutdown),
            outcome = self.instance_results.quarantine_logical_instance_result(request) => outcome?,
        };
        Ok(match outcome {
            LogicalInstanceResultQuarantineOutcome::Quarantined
            | LogicalInstanceResultQuarantineOutcome::AlreadyQuarantined => {
                Some(LogicalResultProjectionOutcome::InstanceQuarantined)
            }
            LogicalInstanceResultQuarantineOutcome::FenceRejected => None,
        })
    }

    async fn quarantine_job(
        &self,
        claimed: &ClaimedLogicalJobResult,
        kind: LogicalJobResultQuarantineKind,
        shutdown: &CancellationToken,
    ) -> Result<Option<LogicalResultProjectionOutcome>, LogicalResultProjectionError> {
        let request = QuarantineLogicalJobResult::new(claimed, kind);
        let outcome = tokio::select! {
            () = shutdown.cancelled() => return Err(LogicalResultProjectionError::Shutdown),
            outcome = self.job_results.quarantine_logical_job_result(request) => outcome?,
        };
        Ok(match outcome {
            LogicalJobResultQuarantineOutcome::Quarantined
            | LogicalJobResultQuarantineOutcome::AlreadyQuarantined => {
                Some(LogicalResultProjectionOutcome::JobQuarantined)
            }
            LogicalJobResultQuarantineOutcome::FenceRejected => None,
        })
    }

    async fn load_activation(
        &self,
        object: &LogicalActivationObject,
        shutdown: &CancellationToken,
    ) -> Result<bytes::Bytes, LogicalResultProjectionError> {
        self.load(
            object.object_key().as_str(),
            object.digest(),
            object.encoded_size(),
            object.media_type(),
            shutdown,
        )
        .await
    }

    async fn load_admission(
        &self,
        object: &AdmissionObject,
        shutdown: &CancellationToken,
    ) -> Result<bytes::Bytes, LogicalResultProjectionError> {
        self.load(
            object.object_key().as_str(),
            object.digest(),
            object.encoded_size(),
            object.media_type(),
            shutdown,
        )
        .await
    }

    async fn load(
        &self,
        key: &str,
        digest: Sha256Digest,
        size: u64,
        media_type: &str,
        shutdown: &CancellationToken,
    ) -> Result<bytes::Bytes, LogicalResultProjectionError> {
        load_verified(self.blobs.as_ref(), key, digest, size, media_type, shutdown).await
    }
}

fn instance_load_quarantine_kind(
    error: &LogicalResultProjectionError,
) -> Option<LogicalInstanceResultQuarantineKind> {
    match error {
        LogicalResultProjectionError::InvalidObject => {
            Some(LogicalInstanceResultQuarantineKind::ObjectEvidence)
        }
        LogicalResultProjectionError::Blob(error)
            if matches!(
                error.kind(),
                BlobStoreErrorKind::NotFound
                    | BlobStoreErrorKind::Conflict
                    | BlobStoreErrorKind::Integrity
                    | BlobStoreErrorKind::TooLarge
            ) =>
        {
            Some(LogicalInstanceResultQuarantineKind::ObjectEvidence)
        }
        _ => None,
    }
}

fn job_load_quarantine_kind(
    error: &LogicalResultProjectionError,
) -> Option<LogicalJobResultQuarantineKind> {
    match error {
        LogicalResultProjectionError::InvalidObject => {
            Some(LogicalJobResultQuarantineKind::ObjectEvidence)
        }
        LogicalResultProjectionError::Blob(error)
            if matches!(
                error.kind(),
                BlobStoreErrorKind::NotFound
                    | BlobStoreErrorKind::Conflict
                    | BlobStoreErrorKind::Integrity
                    | BlobStoreErrorKind::TooLarge
            ) =>
        {
            Some(LogicalJobResultQuarantineKind::ObjectEvidence)
        }
        _ => None,
    }
}

const fn instance_value_is_target_corruption(error: LogicalInstanceResultValueError) -> bool {
    !matches!(
        error,
        LogicalInstanceResultValueError::NegativeTimestamp(_)
            | LogicalInstanceResultValueError::CommitOutsideClaim
    )
}

const fn job_value_is_target_corruption(error: LogicalJobResultValueError) -> bool {
    !matches!(
        error,
        LogicalJobResultValueError::NegativeTimestamp(_)
            | LogicalJobResultValueError::CommitOutsideClaim
    )
}

fn instance_store_is_target_corruption(error: &LogicalInstanceResultStoreError) -> bool {
    matches!(
        error,
        LogicalInstanceResultStoreError::CommitConflict
            | LogicalInstanceResultStoreError::Store(StoreError::CorruptData(_))
    )
}

fn job_store_is_target_corruption(error: &LogicalJobResultStoreError) -> bool {
    matches!(
        error,
        LogicalJobResultStoreError::CommitConflict
            | LogicalJobResultStoreError::Store(StoreError::CorruptData(_))
    )
}

async fn load_verified(
    blobs: &dyn ImmutableBlobStore,
    key: &str,
    digest: Sha256Digest,
    size: u64,
    media_type: &str,
    shutdown: &CancellationToken,
) -> Result<bytes::Bytes, LogicalResultProjectionError> {
    let descriptor = BlobDescriptor::new(
        BlobKey::new(key.to_owned()).map_err(|_| LogicalResultProjectionError::InvalidObject)?,
        digest,
        size,
        MediaType::new(media_type.to_owned())
            .map_err(|_| LogicalResultProjectionError::InvalidObject)?,
    );
    tokio::select! {
        () = shutdown.cancelled() => Err(LogicalResultProjectionError::Shutdown),
        blob = blobs.get_verified(&descriptor, size) => {
            blob.map(VerifiedBlob::into_bytes).map_err(LogicalResultProjectionError::Blob)
        }
    }
}

/// Sanitized autonomous result-projection failure.
#[derive(Debug, Error)]
pub enum LogicalResultProjectionError {
    /// Local shutdown interrupted an in-flight operation.
    #[error("logical result projection was cancelled")]
    Shutdown,
    /// The trusted clock produced an invalid claim interval.
    #[error("logical result projection timestamp is invalid")]
    InvalidTimestamp,
    /// A store-authenticated immutable object descriptor is invalid.
    #[error("logical result projection object descriptor is invalid")]
    InvalidObject,
    /// Immutable object storage failed.
    #[error(transparent)]
    Blob(#[from] BlobStoreError),
    /// Instance-result persistence failed.
    #[error(transparent)]
    InstanceStore(#[from] LogicalInstanceResultStoreError),
    /// Logical-job result persistence failed.
    #[error(transparent)]
    JobStore(#[from] LogicalJobResultStoreError),
    /// Terminal result or `JobIR` disagreed with store-authenticated evidence.
    #[error(transparent)]
    InstanceValue(LogicalInstanceResultValueError),
    /// Workflow plan disagreed with store-authenticated aggregation evidence.
    #[error(transparent)]
    JobValue(LogicalJobResultValueError),
}

#[cfg(test)]
mod tests {
    use automata_ci_blob::{BlobPayload, ImmutableBlobStore as _, MemoryBlobStore};
    use bytes::Bytes;

    use super::*;

    #[tokio::test]
    async fn exact_blob_reader_rejects_digest_corruption() {
        let store = MemoryBlobStore::default();
        let payload = BlobPayload::from_bytes(
            BlobKey::new("results/exact.json").expect("key"),
            MediaType::new("application/json").expect("media type"),
            Bytes::from_static(b"exact"),
        );
        store
            .put_if_absent(payload.clone())
            .await
            .expect("seed object");

        let error = load_verified(
            &store,
            payload.descriptor().key().as_str(),
            Sha256Digest::from_bytes([0x55; 32]),
            payload.descriptor().size(),
            payload.descriptor().media_type().as_str(),
            &CancellationToken::new(),
        )
        .await
        .expect_err("wrong digest must fail closed");
        assert!(matches!(error, LogicalResultProjectionError::Blob(_)));
    }

    #[test]
    fn only_target_local_blob_failures_are_quarantinable() {
        for kind in [
            BlobStoreErrorKind::NotFound,
            BlobStoreErrorKind::Conflict,
            BlobStoreErrorKind::Integrity,
            BlobStoreErrorKind::TooLarge,
        ] {
            let error = LogicalResultProjectionError::Blob(BlobStoreError::new(kind));
            assert_eq!(
                instance_load_quarantine_kind(&error),
                Some(LogicalInstanceResultQuarantineKind::ObjectEvidence)
            );
            assert_eq!(
                job_load_quarantine_kind(&error),
                Some(LogicalJobResultQuarantineKind::ObjectEvidence)
            );
        }

        for kind in [
            BlobStoreErrorKind::Unauthorized,
            BlobStoreErrorKind::Unavailable,
            BlobStoreErrorKind::InvalidResponse,
        ] {
            let error = LogicalResultProjectionError::Blob(BlobStoreError::new(kind));
            assert_eq!(instance_load_quarantine_kind(&error), None);
            assert_eq!(job_load_quarantine_kind(&error), None);
        }
    }
}
