use std::collections::BTreeSet;

use async_trait::async_trait;
use automata_ci_auth::{authorization::SecretExposureClass, human::TenantId};
use automata_ci_control::{
    adapter_spi::{
        BlockedAttempt, BlockedAttemptRepository, BlockedConclusion, ConcludeBlockedAttempt,
    },
    attempt::RenewLease,
    cancellation::{
        CANCEL_JOB_COMMAND_KIND, CANCEL_JOB_COMMAND_SCHEMA, CancelJobCommandPayload,
        CancellationActor, CancellationIntent, CancellationReason, CancellationRepository,
        DEFAULT_CANCELLATION_REASON, RequestCancellation,
    },
    lease::{
        BeginLeaseRequest, BegunLeaseRequest, ClaimRejection, ClaimedAttempt, CompleteLeaseRequest,
        LeaseRequestCompletion, LeaseRequestKey, NoWorkLeaseRequest, RevokedLeaseOfferFallback,
        RunnableAttempt, RunnableQueueKey, RunnableScanLimit, RunnableScanPage,
        RunnableScanRequest, TryClaimAttempt, TryClaimOutcome, TryClaimReceipt,
        repository::{
            RunnableAttemptRepository, RunnerClaimRepository, RunnerLeaseRequestRepository,
        },
        routing::{
            RunnerGroupId, RunnerRoutingRepository, RunnerRoutingSnapshot, RunnerSlotAvailability,
            RunnerSlotAvailabilityRepository,
        },
    },
    runner_control::{
        INITIAL_RUNTIME_AUTHORITY_GENERATION, RuntimeAuthorityDeliveryBinding,
        durable::{
            AcceptedRuntimeAuthorityOffer, AcknowledgeRuntimeAuthorityDelivery,
            AuthorizeRuntimeAuthorityDelivery, CommitCommandAcknowledgement, CommitLeaseHeartbeat,
            CommitLeaseResponse, CommitRunnerLogSegment, CommitRunnerTerminalResult,
            CommitRuntimeAuthorityDelivery, CurrentRunnerSession, CurrentRunnerSessionRepository,
            LeaseOfferClaim, LeaseOfferClaimStatus, LeaseResponseAction, PublishLeaseOffer,
            PublishedLeaseOffer, RawLogDisposition, RunnerControlTransactionRepository,
            RunnerLeaseOfferRepository, RunnerLogAdmission, RunnerLogAdmissionRequest,
            RuntimeAuthorityDeliveryAdmission, RuntimeAuthorityDeliveryDisposition,
            RuntimeAuthorityDeliveryRepository, RuntimeAuthorityOfferCommand,
        },
        repository::{
            RunnerCommandOutbox, RunnerOperationReceiptRepository, RunnerSessionRepository,
        },
    },
};
use automata_ci_core::{
    AttemptId, FencingToken, JobConclusion, JobId, JobIrVersion, JobLifecycle, Lease, LeaseGuard,
    LeaseId, LogSequence, OperationId, RUNNER_REQUIREMENTS_SCHEMA_VERSION, RunId,
    RunnerCapabilities, RunnerGroup, RunnerId, RunnerRequirements, RunnerSessionId, Sha256Digest,
    UnixMillis,
};
use automata_ci_key_management::{
    ENVELOPE_NONCE_BYTES, EncryptedEnvelope, EnvelopeError, KeyEncryptionContext,
    KeyEncryptionError, KeyId, KeyPurpose, SecretBytes, WrappedDataKey,
};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row as _, Transaction};
use uuid::Uuid;

use super::{
    PostgresStore, RunnerPayloadEncryption, lifecycle_name,
    log_notifications::publish_log_commit_notification, parse_lifecycle,
};
use automata_ci_store::{
    AcknowledgeRunnerCommands, AttemptAssignment, AttemptStoreError, CloseRunnerSession,
    CommandCursor, CommandReplayDisposition, CommandReplayLimit, CommandReplayPage,
    CommandSequence, DocumentSchema, DurableRunnerCommand, EnqueueRunnerCommand,
    HeartbeatRunnerSession, HumanLogCommitHint, JobDependency, JobIrMetadata,
    LeaseOfferCommandIdentity, MAX_COMMAND_REPLAY_BYTES, MAX_COMMAND_REPLAY_LIMIT, ObjectKey,
    OpenRunnerSession, ResumeRunnerSession, RoutingDocument, RoutingLabel, RunnerCommandPayload,
    RunnerGeneration, RunnerOperationKind, RunnerOperationReceipt, RunnerOperationRequest,
    RunnerOperationResponse, RunnerPayloadTombstone, RunnerPayloadTombstoneReason,
    RunnerProtocolVersion, RunnerSessionFence, RunnerSessionSnapshot, RunnerSlotCount,
    SessionEpoch, StableRunnerSlot, StoreError, WORKFLOW_ADMISSION_EPOCH, WorkflowPlanRepository,
};

const LEASE_OPERATION_KIND: &str = "automata.lease-request.v1";
const LEASE_RPC_OPERATION_KIND: &str = "automata.runner.lease-request.v1";
const LEASE_OFFER_COMMAND_KIND: &str = "automata.runner.lease-offer.v2";
const LEASE_OFFER_COMMAND_SCHEMA: u16 = 2;
const RUNTIME_AUTHORITY_REQUEST_KIND: &str = "automata.runner.runtime-authority-request.v2";
const RUNTIME_AUTHORITY_ACK_KIND: &str = "automata.runner.runtime-authority-ack.v2";
const COMMAND_ENVELOPE_METADATA_DOMAIN: &[u8] =
    b"automata-ci/control-plane/runner-command-metadata:v1";
const RESPONSE_ENVELOPE_METADATA_DOMAIN: &[u8] =
    b"automata-ci/control-plane/runner-rpc-response-metadata:v1";

fn is_lease_offer_command_kind(kind: &str) -> bool {
    kind == LEASE_OFFER_COMMAND_KIND
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RunnerCommandEnvelopeMetadata {
    session_id: Uuid,
    sequence: i64,
    operation_id: Uuid,
    runner_id: Uuid,
    session_epoch: i64,
    runner_generation: i64,
    kind: String,
    schema: i32,
    digest: Sha256Digest,
    plaintext_size_bytes: i64,
    created_at_ms: i64,
}

impl RunnerCommandEnvelopeMetadata {
    fn from_command(
        command: &EnqueueRunnerCommand,
        sequence: CommandSequence,
        plaintext_size_bytes: i64,
    ) -> Result<Self, StoreError> {
        Ok(Self {
            session_id: command.session().session_id().as_uuid(),
            sequence: sequence_i64(sequence)?,
            operation_id: command.operation_id().as_uuid(),
            runner_id: command.session().runner_id().as_uuid(),
            session_epoch: epoch_i64(command.session().session_epoch())?,
            runner_generation: generation_i64(command.session().runner_generation())?,
            kind: command.kind().as_str().to_owned(),
            schema: i32::from(command.payload().schema().get()),
            digest: command.payload().digest(),
            plaintext_size_bytes,
            created_at_ms: command.created_at().get(),
        })
    }

    fn from_row(row: &sqlx::postgres::PgRow) -> Result<Self, StoreError> {
        let metadata = Self {
            session_id: row
                .try_get("command_runner_session_id")
                .map_err(operation_error)?,
            sequence: row.try_get("command_sequence").map_err(operation_error)?,
            operation_id: row
                .try_get("command_operation_id")
                .map_err(operation_error)?,
            runner_id: row.try_get("command_runner_id").map_err(operation_error)?,
            session_epoch: row
                .try_get("command_runner_session_epoch")
                .map_err(operation_error)?,
            runner_generation: row
                .try_get("command_runner_generation")
                .map_err(operation_error)?,
            kind: row.try_get("command_kind").map_err(operation_error)?,
            schema: row.try_get("command_schema").map_err(operation_error)?,
            digest: decode_sha256_digest(row.try_get("command_digest").map_err(operation_error)?)
                .map_err(|error| StoreError::corrupt_data(error.clone()))?,
            plaintext_size_bytes: row
                .try_get("command_plaintext_size_bytes")
                .map_err(operation_error)?,
            created_at_ms: row
                .try_get("command_created_at_ms")
                .map_err(operation_error)?,
        };
        metadata.validate()?;
        Ok(metadata)
    }

    fn validate(&self) -> Result<(), StoreError> {
        decode_sequence(self.sequence)?;
        decode_epoch(self.session_epoch)?;
        decode_generation(self.runner_generation)?;
        RunnerOperationKind::new(self.kind.clone())
            .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
        decode_schema(self.schema)?;
        self.plaintext_size()?;
        Ok(())
    }

    fn plaintext_size(&self) -> Result<usize, StoreError> {
        usize::try_from(self.plaintext_size_bytes)
            .ok()
            .filter(|size| *size > 0)
            .ok_or_else(|| StoreError::corrupt_data("invalid runner command plaintext size"))
    }

    fn fence(&self) -> Result<RunnerSessionFence, StoreError> {
        Ok(RunnerSessionFence::new(
            RunnerSessionId::from_uuid(self.session_id),
            RunnerId::from_uuid(self.runner_id),
            decode_generation(self.runner_generation)?,
            decode_epoch(self.session_epoch)?,
        ))
    }

    fn sequence(&self) -> Result<CommandSequence, StoreError> {
        decode_sequence(self.sequence)
    }

    fn metadata_digest(&self) -> Sha256Digest {
        metadata_digest(
            COMMAND_ENVELOPE_METADATA_DOMAIN,
            [
                self.session_id.as_bytes().as_slice(),
                self.sequence.to_be_bytes().as_slice(),
                self.operation_id.as_bytes().as_slice(),
                self.runner_id.as_bytes().as_slice(),
                self.session_epoch.to_be_bytes().as_slice(),
                self.runner_generation.to_be_bytes().as_slice(),
                self.kind.as_bytes(),
                self.schema.to_be_bytes().as_slice(),
                self.digest.as_bytes().as_slice(),
                self.plaintext_size_bytes.to_be_bytes().as_slice(),
                self.created_at_ms.to_be_bytes().as_slice(),
            ],
        )
    }

    fn record_id(&self) -> String {
        format!(
            "{}/command/{}/metadata/{}",
            self.session_id,
            self.sequence,
            self.metadata_digest()
        )
    }
}

#[derive(Clone, Debug)]
struct RunnerResponseEnvelopeMetadata {
    session_id: Uuid,
    operation_id: Uuid,
    runner_id: Uuid,
    session_epoch: i64,
    runner_generation: i64,
    operation_kind: String,
    request_digest: Sha256Digest,
    response_schema: i32,
    response_digest: Sha256Digest,
    plaintext_size_bytes: i64,
    committed_at_ms: i64,
}

impl RunnerResponseEnvelopeMetadata {
    fn from_values(
        request: &RunnerOperationRequest,
        response: &RunnerOperationResponse,
        plaintext_size_bytes: i64,
        committed_at: UnixMillis,
    ) -> Result<Self, StoreError> {
        Ok(Self {
            session_id: request.session().session_id().as_uuid(),
            operation_id: request.operation_id().as_uuid(),
            runner_id: request.session().runner_id().as_uuid(),
            session_epoch: epoch_i64(request.session().session_epoch())?,
            runner_generation: generation_i64(request.session().runner_generation())?,
            operation_kind: request.kind().as_str().to_owned(),
            request_digest: request.request_digest(),
            response_schema: i32::from(response.schema().get()),
            response_digest: response.digest(),
            plaintext_size_bytes,
            committed_at_ms: committed_at.get(),
        })
    }

    fn from_row(row: &sqlx::postgres::PgRow) -> Result<Self, StoreError> {
        let metadata = Self {
            session_id: row
                .try_get("response_runner_session_id")
                .map_err(operation_error)?,
            operation_id: row
                .try_get("response_operation_id")
                .map_err(operation_error)?,
            runner_id: row.try_get("response_runner_id").map_err(operation_error)?,
            session_epoch: row
                .try_get("response_runner_session_epoch")
                .map_err(operation_error)?,
            runner_generation: row
                .try_get("response_runner_generation")
                .map_err(operation_error)?,
            operation_kind: row
                .try_get("response_operation_kind")
                .map_err(operation_error)?,
            request_digest: decode_sha256_digest(
                row.try_get("response_request_digest")
                    .map_err(operation_error)?,
            )
            .map_err(|error| StoreError::corrupt_data(error.clone()))?,
            response_schema: row.try_get("response_schema").map_err(operation_error)?,
            response_digest: decode_sha256_digest(
                row.try_get("response_digest").map_err(operation_error)?,
            )
            .map_err(|error| StoreError::corrupt_data(error.clone()))?,
            plaintext_size_bytes: row
                .try_get("response_plaintext_size_bytes")
                .map_err(operation_error)?,
            committed_at_ms: row
                .try_get("response_committed_at_ms")
                .map_err(operation_error)?,
        };
        metadata.validate()?;
        Ok(metadata)
    }

    fn validate(&self) -> Result<(), StoreError> {
        decode_epoch(self.session_epoch)?;
        decode_generation(self.runner_generation)?;
        RunnerOperationKind::new(self.operation_kind.clone())
            .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
        decode_schema(self.response_schema)?;
        self.plaintext_size()?;
        Ok(())
    }

    fn plaintext_size(&self) -> Result<usize, StoreError> {
        usize::try_from(self.plaintext_size_bytes)
            .ok()
            .filter(|size| *size > 0)
            .ok_or_else(|| StoreError::corrupt_data("invalid runner response plaintext size"))
    }

    fn fence(&self) -> Result<RunnerSessionFence, StoreError> {
        Ok(RunnerSessionFence::new(
            RunnerSessionId::from_uuid(self.session_id),
            RunnerId::from_uuid(self.runner_id),
            decode_generation(self.runner_generation)?,
            decode_epoch(self.session_epoch)?,
        ))
    }

    fn metadata_digest(&self) -> Sha256Digest {
        metadata_digest(
            RESPONSE_ENVELOPE_METADATA_DOMAIN,
            [
                self.session_id.as_bytes().as_slice(),
                self.operation_id.as_bytes().as_slice(),
                self.runner_id.as_bytes().as_slice(),
                self.session_epoch.to_be_bytes().as_slice(),
                self.runner_generation.to_be_bytes().as_slice(),
                self.operation_kind.as_bytes(),
                self.request_digest.as_bytes().as_slice(),
                self.response_schema.to_be_bytes().as_slice(),
                self.response_digest.as_bytes().as_slice(),
                self.plaintext_size_bytes.to_be_bytes().as_slice(),
                self.committed_at_ms.to_be_bytes().as_slice(),
            ],
        )
    }

    fn record_id(&self) -> String {
        format!(
            "{}/operation/{}/metadata/{}",
            self.session_id,
            self.operation_id,
            self.metadata_digest()
        )
    }
}

fn metadata_digest<'a>(domain: &[u8], fields: impl IntoIterator<Item = &'a [u8]>) -> Sha256Digest {
    let mut digest = Sha256::new();
    metadata_digest_field(&mut digest, domain);
    for field in fields {
        metadata_digest_field(&mut digest, field);
    }
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn metadata_digest_field(digest: &mut Sha256, value: &[u8]) {
    // A fixed-width big-endian length precedes every field, including the
    // versioned domain, so concatenated metadata has one canonical framing.
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

struct RunnerPayloadEnvelopeParameters {
    plaintext_size_bytes: i64,
    schema: i32,
    wrapping_key_id: String,
    wrapped_data_key: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl RunnerPayloadEnvelopeParameters {
    fn from_envelope(
        plaintext_size: usize,
        envelope: EncryptedEnvelope,
    ) -> Result<Self, StoreError> {
        let (schema, wrapped_data_key, nonce, ciphertext) = envelope.into_parts();
        let (wrapping_key_id, wrapped_data_key) = wrapped_data_key.into_parts();
        Ok(Self {
            plaintext_size_bytes: i64::try_from(plaintext_size).map_err(|_| {
                StoreError::corrupt_data("runner payload size exceeds PostgreSQL BIGINT")
            })?,
            schema: i32::from(schema),
            wrapping_key_id: wrapping_key_id.as_str().to_owned(),
            wrapped_data_key,
            nonce: nonce.to_vec(),
            ciphertext,
        })
    }
}

async fn seal_runner_payload(
    encryption: &RunnerPayloadEncryption,
    tenant_id: &str,
    purpose: &KeyPurpose,
    record_id: String,
    payload: &[u8],
) -> Result<RunnerPayloadEnvelopeParameters, StoreError> {
    let context = KeyEncryptionContext::new(tenant_id, purpose.clone(), record_id)
        .map_err(|_| StoreError::corrupt_data("invalid runner payload encryption context"))?;
    let plaintext = SecretBytes::new(payload.to_vec())
        .map_err(|_| StoreError::corrupt_data("invalid runner payload plaintext size"))?;
    let plaintext_size = plaintext.len();
    let envelope = encryption
        .codec
        .seal(&context, plaintext)
        .await
        .map_err(map_runner_payload_envelope_error)?;
    RunnerPayloadEnvelopeParameters::from_envelope(plaintext_size, envelope)
}

async fn open_runner_payload(
    encryption: &RunnerPayloadEncryption,
    row: &sqlx::postgres::PgRow,
    plaintext_size: usize,
    purpose: &KeyPurpose,
    record_id: String,
) -> Result<Vec<u8>, StoreError> {
    let tenant_id: String = row.try_get("tenant_id").map_err(operation_error)?;
    let envelope = runner_payload_envelope_from_row(row)?;
    let context = KeyEncryptionContext::new(tenant_id, purpose.clone(), record_id)
        .map_err(|_| StoreError::corrupt_data("invalid runner payload encryption context"))?;
    let plaintext = encryption
        .codec
        .open(&context, &envelope)
        .await
        .map_err(map_runner_payload_envelope_error)?;
    if plaintext.len() != plaintext_size {
        return Err(StoreError::corrupt_data(
            "runner payload plaintext length mismatch",
        ));
    }
    let payload = plaintext.expose_secret().to_vec();
    drop(plaintext);
    Ok(payload)
}

fn map_runner_payload_envelope_error(error: EnvelopeError) -> StoreError {
    if matches!(
        error,
        EnvelopeError::KeyEncryption(KeyEncryptionError::Unavailable)
    ) {
        StoreError::operation(error)
    } else {
        StoreError::corrupt_data("runner payload envelope failed integrity validation")
    }
}

fn runner_payload_envelope_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<EncryptedEnvelope, StoreError> {
    let schema = u16::try_from(
        row.try_get::<i32, _>("envelope_schema")
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("invalid runner payload envelope schema"))?;
    let key_id = KeyId::new(
        row.try_get::<String, _>("wrapping_key_id")
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("invalid runner payload wrapping key ID"))?;
    let wrapped_data_key = WrappedDataKey::new(
        key_id,
        row.try_get("wrapped_data_key").map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("invalid wrapped runner payload data key"))?;
    let nonce: [u8; ENVELOPE_NONCE_BYTES] = row
        .try_get::<Vec<u8>, _>("nonce")
        .map_err(operation_error)?
        .try_into()
        .map_err(|_| StoreError::corrupt_data("invalid runner payload envelope nonce"))?;
    let ciphertext = row.try_get("ciphertext").map_err(operation_error)?;
    EncryptedEnvelope::from_parts(schema, wrapped_data_key, nonce, ciphertext)
        .map_err(|_| StoreError::corrupt_data("invalid runner payload envelope"))
}

fn decode_runner_payload_tombstone(
    row: &sqlx::postgres::PgRow,
) -> Result<Option<RunnerPayloadTombstone>, StoreError> {
    let reason: Option<String> = row
        .try_get("payload_tombstone_reason")
        .map_err(operation_error)?;
    let tombstoned_at: Option<i64> = row
        .try_get("payload_tombstoned_at_ms")
        .map_err(operation_error)?;
    match (reason, tombstoned_at) {
        (None, None) => Ok(None),
        (Some(reason), Some(tombstoned_at)) => {
            let reason = decode_runner_payload_tombstone_reason(&reason).ok_or_else(|| {
                StoreError::corrupt_data("invalid runner payload tombstone reason")
            })?;
            Ok(Some(RunnerPayloadTombstone::new(
                reason,
                UnixMillis::new(tombstoned_at),
            )))
        }
        _ => Err(StoreError::corrupt_data(
            "incomplete runner payload tombstone",
        )),
    }
}

pub(super) fn session_epoch_to_i64(value: SessionEpoch) -> Result<i64, AttemptStoreError> {
    i64::try_from(value.get())
        .map_err(|_| AttemptStoreError::corrupt_data("session epoch exceeds PostgreSQL BIGINT"))
}

pub(super) fn runner_generation_to_i64(value: RunnerGeneration) -> Result<i64, AttemptStoreError> {
    i64::try_from(value.get())
        .map_err(|_| AttemptStoreError::corrupt_data("runner generation exceeds PostgreSQL BIGINT"))
}

#[async_trait]
impl RunnerSessionRepository for PostgresStore {
    #[allow(clippy::too_many_lines)]
    async fn open_session(
        &self,
        request: OpenRunnerSession,
    ) -> Result<RunnerSessionSnapshot, StoreError> {
        validate_observed_capabilities(
            request.runner_id(),
            request.capability_snapshot().as_str(),
        )?;
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::pin_runner_attempt_read_committed(&mut transaction).await?;
        let runner = sqlx::query(
            r"
            SELECT generation, session_epoch, desired_state, updated_at_ms
            FROM runners
            WHERE id = $1
            FOR UPDATE
            ",
        )
        .bind(request.runner_id().as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?
        .ok_or(StoreError::RunnerNotFound(request.runner_id()))?;

        let generation = decode_generation(runner.try_get("generation").map_err(operation_error)?)?;
        if generation != request.expected_generation() {
            return Err(generation_mismatch(
                request.runner_id(),
                request.expected_generation(),
                generation,
            ));
        }
        let desired_state =
            decode_desired_runner_state(runner.try_get("desired_state").map_err(operation_error)?)?;
        match desired_state {
            DurableDesiredRunnerState::Active => {}
            DurableDesiredRunnerState::Draining => {
                return Err(StoreError::RunnerNotAcceptingWork(request.runner_id()));
            }
            DurableDesiredRunnerState::Disabled => {
                return Err(StoreError::RunnerDisabled(request.runner_id()));
            }
        }
        let runner_changed_at =
            UnixMillis::new(runner.try_get("updated_at_ms").map_err(operation_error)?);

        let live_heartbeats: Vec<i64> = sqlx::query_scalar(
            r"
            SELECT heartbeat_at_ms
            FROM runner_sessions
            WHERE runner_id = $1 AND disconnected_at_ms IS NULL
            FOR UPDATE
            ",
        )
        .bind(request.runner_id().as_uuid())
        .fetch_all(&mut *transaction)
        .await
        .map_err(operation_error)?;
        let database_now = super::runner_attempt_database_now(&mut transaction).await?;
        let decision_at = database_session_decision_at(
            database_now,
            std::iter::once(runner_changed_at)
                .chain(live_heartbeats.into_iter().map(UnixMillis::new)),
        )?;

        let prior_epoch: i64 = runner.try_get("session_epoch").map_err(operation_error)?;
        let next_epoch = prior_epoch
            .checked_add(1)
            .and_then(|value| u64::try_from(value).ok())
            .and_then(|value| SessionEpoch::new(value).ok())
            .ok_or_else(|| StoreError::SessionEpochExhausted(request.runner_id()))?;

        sqlx::query(
            r"
            UPDATE runner_sessions
            SET disconnected_at_ms = $2
            WHERE runner_id = $1 AND disconnected_at_ms IS NULL
            ",
        )
        .bind(request.runner_id().as_uuid())
        .bind(decision_at.get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
        cleanup_disconnected_runner_lease_request_state(&mut transaction, request.runner_id())
            .await?;

        sqlx::query(
            r"
            UPDATE runners
            SET session_epoch = $2,
                status = CASE WHEN status = 'offline' THEN 'online' ELSE status END,
                last_seen_at_ms = $3,
                updated_at_ms = $3
            WHERE id = $1
            ",
        )
        .bind(request.runner_id().as_uuid())
        .bind(epoch_i64(next_epoch)?)
        .bind(decision_at.get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
        tombstone_disconnected_runner_payloads(
            &mut transaction,
            request.runner_id(),
            RunnerPayloadTombstoneReason::SessionSuperseded,
            decision_at,
        )
        .await?;

        sqlx::query(
            r"
            INSERT INTO runner_sessions (
                id, runner_id, protocol_version, job_ir_schema,
                capability_snapshot, connected_at_ms, heartbeat_at_ms,
                runner_generation, session_epoch
            )
            VALUES ($1, $2, $3, $4, $5::jsonb, $6, $6, $7, $8)
            ",
        )
        .bind(request.session_id().as_uuid())
        .bind(request.runner_id().as_uuid())
        .bind(protocol_i32(request.protocol_version()))
        .bind(i32::from(request.job_ir_version().get()))
        .bind(request.capability_snapshot().as_str())
        .bind(decision_at.get())
        .bind(generation_i64(generation)?)
        .bind(epoch_i64(next_epoch)?)
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;

        let snapshot = RunnerSessionSnapshot::try_new(
            RunnerSessionFence::new(
                request.session_id(),
                request.runner_id(),
                generation,
                next_epoch,
            ),
            request.protocol_version(),
            request.job_ir_version(),
            request.capability_snapshot().clone(),
            decision_at,
            decision_at,
            None,
            CommandCursor::initial(),
        )
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(snapshot)
    }

    async fn close_session(&self, request: CloseRunnerSession) -> Result<(), StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::pin_runner_attempt_read_committed(&mut transaction).await?;
        lock_runner_fence(&mut transaction, request.fence()).await?;
        close_session_in_transaction(&mut transaction, request.fence()).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(())
    }

    async fn heartbeat_session(
        &self,
        request: HeartbeatRunnerSession,
    ) -> Result<RunnerSessionSnapshot, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::pin_runner_attempt_read_committed(&mut transaction).await?;
        lock_existing_session_authority(&mut transaction, request.fence()).await?;
        let current = locked_session(&mut transaction, request.fence()).await?;
        if current.disconnected_at().is_some() {
            return Err(StoreError::SessionClosed(request.fence().session_id()));
        }
        let database_now = super::runner_attempt_database_now(&mut transaction).await?;
        // Concurrent authenticated calls can acquire this durable fence in a
        // different order from their database-clock samples. Liveness must
        // never regress even when the later lock holder sampled first.
        let observed_at = database_session_decision_at(database_now, [current.heartbeat_at()])?;
        update_session_liveness(
            &mut transaction,
            request.fence(),
            request.command_cursor(),
            observed_at,
            &current,
        )
        .await?;
        let snapshot = locked_session(&mut transaction, request.fence()).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(snapshot)
    }

    async fn resume_session(
        &self,
        request: ResumeRunnerSession,
    ) -> Result<RunnerSessionSnapshot, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::pin_runner_attempt_read_committed(&mut transaction).await?;
        let runner = sqlx::query(
            "SELECT generation, session_epoch, status, desired_state FROM runners WHERE id = $1 FOR UPDATE",
        )
            .bind(request.runner_id().as_uuid())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(operation_error)?
            .ok_or(StoreError::RunnerNotFound(request.runner_id()))?;
        let actual = decode_generation(runner.try_get("generation").map_err(operation_error)?)?;
        if actual != request.expected_generation() {
            return Err(generation_mismatch(
                request.runner_id(),
                request.expected_generation(),
                actual,
            ));
        }
        let desired_state =
            decode_desired_runner_state(runner.try_get("desired_state").map_err(operation_error)?)?;
        if desired_state == DurableDesiredRunnerState::Disabled {
            return Err(StoreError::RunnerDisabled(request.runner_id()));
        }
        let status: &str = runner.try_get("status").map_err(operation_error)?;
        if status != "online" {
            return Err(StoreError::SessionClosed(request.session_id()));
        }
        let identity = sqlx::query(
            r"
            SELECT session_epoch, runner_generation, disconnected_at_ms
            FROM runner_sessions
            WHERE id = $1 AND runner_id = $2
            FOR UPDATE
            ",
        )
        .bind(request.session_id().as_uuid())
        .bind(request.runner_id().as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?
        .ok_or(StoreError::SessionNotFound(request.session_id()))?;
        if identity
            .try_get::<Option<i64>, _>("disconnected_at_ms")
            .map_err(operation_error)?
            .is_some()
        {
            return Err(StoreError::SessionClosed(request.session_id()));
        }
        let stored_generation = decode_generation(
            identity
                .try_get("runner_generation")
                .map_err(operation_error)?,
        )?;
        if stored_generation != actual {
            return Err(StoreError::SessionFenceRejected(request.session_id()));
        }
        let epoch = decode_epoch(identity.try_get("session_epoch").map_err(operation_error)?)?;
        let current_epoch =
            decode_epoch(runner.try_get("session_epoch").map_err(operation_error)?)?;
        if current_epoch != epoch {
            return Err(StoreError::SessionFenceRejected(request.session_id()));
        }
        let fence =
            RunnerSessionFence::new(request.session_id(), request.runner_id(), actual, epoch);
        let current = locked_session(&mut transaction, fence).await?;
        if request.command_cursor().durable_value() < current.command_cursor().durable_value() {
            return Err(StoreError::CommandCursorBehind {
                session_id: request.session_id(),
                requested: request.command_cursor(),
                durable: current.command_cursor(),
            });
        }
        let database_now = super::runner_attempt_database_now(&mut transaction).await?;
        let observed_at = database_session_decision_at(database_now, [current.heartbeat_at()])?;
        update_session_liveness(
            &mut transaction,
            fence,
            request.command_cursor(),
            observed_at,
            &current,
        )
        .await?;
        let snapshot = locked_session(&mut transaction, fence).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(snapshot)
    }

    async fn get_session(
        &self,
        fence: RunnerSessionFence,
    ) -> Result<RunnerSessionSnapshot, StoreError> {
        let row = session_query(fence)
            .fetch_optional(&self.pool)
            .await
            .map_err(operation_error)?
            .ok_or(StoreError::SessionNotFound(fence.session_id()))?;
        decode_session(&row, fence)
    }
}

#[async_trait]
impl CurrentRunnerSessionRepository for PostgresStore {
    async fn resolve_current_session(
        &self,
        request: CurrentRunnerSession,
    ) -> Result<Option<RunnerSessionFence>, StoreError> {
        let epoch = sqlx::query_scalar::<_, i64>(
            r"
            SELECT session.session_epoch
            FROM runners AS runner
            JOIN runner_sessions AS session ON session.runner_id = runner.id
            WHERE runner.id = $1
              AND runner.generation = $2
              AND runner.status = 'online'
              AND runner.desired_state IN ('active', 'draining')
              AND runner.session_epoch = session.session_epoch
              AND session.id = $3
              AND session.runner_generation = runner.generation
              AND session.disconnected_at_ms IS NULL
            ",
        )
        .bind(request.runner_id().as_uuid())
        .bind(generation_i64(request.generation())?)
        .bind(request.session_id().as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(operation_error)?;
        epoch.map(decode_epoch).transpose().map(|epoch| {
            epoch.map(|epoch| {
                RunnerSessionFence::new(
                    request.session_id(),
                    request.runner_id(),
                    request.generation(),
                    epoch,
                )
            })
        })
    }
}

#[async_trait]
impl RunnerRoutingRepository for PostgresStore {
    async fn routing_for_session(
        &self,
        fence: RunnerSessionFence,
    ) -> Result<RunnerRoutingSnapshot, StoreError> {
        let row = sqlx::query(
            r"
            SELECT runner.group_id, runner_group.name AS group_name,
                   runner.labels, runner.capabilities::text AS registered_capabilities,
                   session.capability_snapshot::text AS negotiated_capabilities,
                   runner.slots, session.job_ir_schema
            FROM runner_sessions AS session
            JOIN runners AS runner ON runner.id = session.runner_id
            LEFT JOIN runner_groups AS runner_group ON runner_group.id = runner.group_id
            WHERE session.id = $1
              AND runner.id = $2
              AND runner.generation = $3
              AND session.runner_generation = $3
              AND runner.session_epoch = session.session_epoch
              AND session.session_epoch = $4
              AND session.disconnected_at_ms IS NULL
            ",
        )
        .bind(fence.session_id().as_uuid())
        .bind(fence.runner_id().as_uuid())
        .bind(generation_i64(fence.runner_generation())?)
        .bind(epoch_i64(fence.session_epoch())?)
        .fetch_optional(&self.pool)
        .await
        .map_err(operation_error)?
        .ok_or_else(|| StoreError::SessionFenceRejected(fence.session_id()))?;
        decode_routing(&row, fence)
    }
}

#[async_trait]
impl RunnerSlotAvailabilityRepository for PostgresStore {
    async fn slot_availability(
        &self,
        fence: RunnerSessionFence,
        slot: StableRunnerSlot,
        _observed_at: UnixMillis,
    ) -> Result<RunnerSlotAvailability, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let routing = lock_live_routing(&mut transaction, fence).await?;
        if !routing.online || !routing.accepts_new_work {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(RunnerSlotAvailability::RunnerUnavailable);
        }
        if !routing.slots.contains(slot) {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(RunnerSlotAvailability::OutOfRange);
        }

        let occupied = sqlx::query_scalar::<_, Uuid>(
            r"
            SELECT id
            FROM job_attempts
            WHERE runner_id = $1 AND runner_slot = $2 AND lease_id IS NOT NULL
            LIMIT 1
            ",
        )
        .bind(fence.runner_id().as_uuid())
        .bind(i32::from(slot.ordinal()))
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?;
        let availability = occupied.map_or(RunnerSlotAvailability::Available, |attempt_id| {
            RunnerSlotAvailability::Occupied {
                attempt_id: AttemptId::from_uuid(attempt_id),
            }
        });
        transaction.commit().await.map_err(operation_error)?;
        Ok(availability)
    }
}

#[async_trait]
impl RunnerCommandOutbox for PostgresStore {
    async fn enqueue_command(
        &self,
        command: EnqueueRunnerCommand,
    ) -> Result<DurableRunnerCommand, StoreError> {
        let encryption = self.require_runner_payload_encryption()?;
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let durable = enqueue_command_in_transaction(&mut transaction, encryption, command).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(durable)
    }

    async fn replay_commands(
        &self,
        session: RunnerSessionFence,
        after: CommandCursor,
        limit: CommandReplayLimit,
    ) -> Result<CommandReplayPage, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::pin_runner_attempt_read_committed(&mut transaction).await?;
        reject_tombstoned_session_payload_access(&mut transaction, session).await?;
        let encryption = self.require_runner_payload_encryption()?;
        lock_live_routing(&mut transaction, session)
            .await?
            .require_online(session)?;
        let current = locked_session(&mut transaction, session).await?;
        let scan_after = i64::try_from(
            after
                .durable_value()
                .max(current.command_cursor().durable_value()),
        )
        .map_err(|_| StoreError::corrupt_data("command cursor exceeds PostgreSQL BIGINT"))?;
        let sequences =
            select_replay_candidate_sequences(&mut transaction, session, scan_after).await?;
        let page =
            inspect_replay_candidates(&mut transaction, encryption, session, limit, sequences)
                .await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(page)
    }

    async fn acknowledge_commands(
        &self,
        acknowledgement: AcknowledgeRunnerCommands,
    ) -> Result<CommandCursor, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::pin_runner_attempt_read_committed(&mut transaction).await?;
        lock_existing_session_authority(&mut transaction, acknowledgement.session()).await?;
        let current = locked_session(&mut transaction, acknowledgement.session()).await?;
        if current.disconnected_at().is_some() {
            return Err(StoreError::SessionClosed(
                acknowledgement.session().session_id(),
            ));
        }
        let database_now = super::runner_attempt_database_now(&mut transaction).await?;
        let decision_at = database_session_decision_at(database_now, [current.heartbeat_at()])?;
        update_session_liveness(
            &mut transaction,
            acknowledgement.session(),
            acknowledgement.cursor(),
            decision_at,
            &current,
        )
        .await?;
        let updated = locked_session(&mut transaction, acknowledgement.session()).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(updated.command_cursor())
    }
}

#[async_trait]
impl RunnerOperationReceiptRepository for PostgresStore {
    async fn lookup_operation(
        &self,
        request: &RunnerOperationRequest,
    ) -> Result<Option<RunnerOperationReceipt>, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::pin_runner_attempt_read_committed(&mut transaction).await?;
        reject_tombstoned_session_payload_access(&mut transaction, request.session()).await?;
        let encryption = self.require_runner_payload_encryption()?;
        lock_live_routing(&mut transaction, request.session())
            .await?
            .require_online(request.session())?;
        let receipt = match load_generic_receipt(
            &mut transaction,
            encryption,
            request,
            true,
            ReceiptOfferExpectation::Any,
        )
        .await?
        {
            Some(LoadedGenericReceipt::Live { receipt, .. }) => Some(receipt),
            Some(LoadedGenericReceipt::RevokedLeaseOffer { .. }) | None => None,
        };
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }

    async fn record_operation(
        &self,
        request: RunnerOperationRequest,
        response: RunnerOperationResponse,
        committed_at: UnixMillis,
    ) -> Result<RunnerOperationReceipt, StoreError> {
        let encryption = self.require_runner_payload_encryption()?;
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        lock_live_routing(&mut transaction, request.session())
            .await?
            .require_online(request.session())?;
        if request.kind().as_str() == LEASE_RPC_OPERATION_KIND {
            lock_current_lease_rpc_operation(&mut transaction, &request).await?;
            return Err(StoreError::corrupt_data(
                "lease-request receipts require the typed completion repository",
            ));
        }
        let receipt = insert_generic_receipt(
            &mut transaction,
            encryption,
            request,
            response,
            committed_at,
            None,
            None,
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }
}

#[async_trait]
impl RunnerLeaseRequestRepository for PostgresStore {
    #[allow(clippy::too_many_lines)]
    async fn begin_lease_request(
        &self,
        request: BeginLeaseRequest,
    ) -> Result<BegunLeaseRequest, StoreError> {
        let encryption = self.require_runner_payload_encryption()?;
        let key = request.request_key();
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::pin_runner_attempt_read_committed(&mut transaction).await?;
        let routing = lock_live_routing(&mut transaction, key.session()).await?;
        routing.require_online(key.session())?;
        if !routing.slots.contains(key.slot()) {
            return Err(StoreError::SlotOutOfRange {
                session_id: key.session().session_id(),
                slot: key.slot(),
            });
        }

        let current = sqlx::query(
            r"
            SELECT operation_id, request_digest, acknowledges_operation_id
            FROM runner_lease_request_heads
            WHERE runner_session_id = $1 AND runner_slot = $2
            FOR UPDATE
            ",
        )
        .bind(key.session().session_id().as_uuid())
        .bind(i32::from(key.slot().ordinal()))
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?;

        let completed_response = if let Some(current) = current {
            let current_operation =
                OperationId::from_uuid(current.try_get("operation_id").map_err(operation_error)?);
            let current_digest =
                decode_sha256_digest(current.try_get("request_digest").map_err(operation_error)?)
                    .map_err(|error| StoreError::corrupt_data(error.clone()))?;
            let current_predecessor = current
                .try_get::<Option<Uuid>, _>("acknowledges_operation_id")
                .map_err(operation_error)?
                .map(OperationId::from_uuid);

            if current_operation == key.operation_id() {
                if current_digest != request.request_digest()
                    || current_predecessor != key.acknowledges_operation_id()
                {
                    return Err(lease_request_conflict(key));
                }
                load_lease_rpc_response(&mut transaction, encryption, request, true).await?
            } else {
                if key.acknowledges_operation_id() != Some(current_operation) {
                    return Err(lease_request_conflict(key));
                }
                let current_key = if let Some(predecessor) = current_predecessor {
                    LeaseRequestKey::successor(
                        key.session(),
                        current_operation,
                        key.slot(),
                        predecessor,
                    )
                    .map_err(|error| StoreError::corrupt_data(error.to_string()))?
                } else {
                    LeaseRequestKey::first(key.session(), current_operation, key.slot())
                };
                let current_request = BeginLeaseRequest::new(current_key, current_digest);
                if matches!(
                    load_lease_rpc_response(&mut transaction, encryption, current_request, false,)
                        .await?,
                    LoadedLeaseRpcResponse::Missing
                ) {
                    return Err(lease_request_conflict(key));
                }

                sqlx::query(
                    r"
                    DELETE FROM runner_operation_receipts
                    WHERE runner_session_id = $1 AND operation_id = $2
                    ",
                )
                .bind(key.session().session_id().as_uuid())
                .bind(current_operation.as_uuid())
                .execute(&mut *transaction)
                .await
                .map_err(operation_error)?;
                let deleted = sqlx::query(
                    r"
                    DELETE FROM runner_rpc_receipts
                    WHERE runner_session_id = $1 AND operation_id = $2
                      AND operation_kind = $3
                    ",
                )
                .bind(key.session().session_id().as_uuid())
                .bind(current_operation.as_uuid())
                .bind(LEASE_RPC_OPERATION_KIND)
                .execute(&mut *transaction)
                .await
                .map_err(operation_error)?;
                if deleted.rows_affected() != 1 {
                    return Err(invalid_operation_receipt(
                        "completed lease-request predecessor disappeared",
                    ));
                }
                let updated = sqlx::query(
                    r"
                    UPDATE runner_lease_request_heads
                    SET operation_id = $3, request_digest = $4,
                        acknowledges_operation_id = $5
                    WHERE runner_session_id = $1 AND runner_slot = $2
                      AND operation_id = $6
                    ",
                )
                .bind(key.session().session_id().as_uuid())
                .bind(i32::from(key.slot().ordinal()))
                .bind(key.operation_id().as_uuid())
                .bind(request.request_digest().as_bytes().as_slice())
                .bind(key.acknowledges_operation_id().map(OperationId::as_uuid))
                .bind(current_operation.as_uuid())
                .execute(&mut *transaction)
                .await
                .map_err(|error| map_lease_head_write_error(error, key))?;
                if updated.rows_affected() != 1 {
                    return Err(lease_request_conflict(key));
                }
                LoadedLeaseRpcResponse::Missing
            }
        } else {
            if key.acknowledges_operation_id().is_some() {
                return Err(lease_request_conflict(key));
            }
            sqlx::query(
                r"
                INSERT INTO runner_lease_request_heads (
                    runner_session_id, runner_slot, runner_id,
                    runner_session_epoch, runner_generation, operation_id,
                    request_digest, acknowledges_operation_id
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, NULL)
                ",
            )
            .bind(key.session().session_id().as_uuid())
            .bind(i32::from(key.slot().ordinal()))
            .bind(key.session().runner_id().as_uuid())
            .bind(epoch_i64(key.session().session_epoch())?)
            .bind(generation_i64(key.session().runner_generation())?)
            .bind(key.operation_id().as_uuid())
            .bind(request.request_digest().as_bytes().as_slice())
            .execute(&mut *transaction)
            .await
            .map_err(|error| map_lease_head_write_error(error, key))?;
            LoadedLeaseRpcResponse::Missing
        };

        transaction.commit().await.map_err(operation_error)?;
        Ok(match completed_response {
            LoadedLeaseRpcResponse::Missing => BegunLeaseRequest::new(request, None),
            LoadedLeaseRpcResponse::Completed(completion) => {
                BegunLeaseRequest::completed(request, completion)
            }
        })
    }

    #[allow(clippy::too_many_lines)] // Keep the receipt/publication locks and post-KMS fallback in one auditable transaction.
    async fn complete_lease_request(
        &self,
        request: CompleteLeaseRequest,
    ) -> Result<LeaseRequestCompletion, StoreError> {
        let encryption = self.require_runner_payload_encryption()?;
        let requested_fallback = if request.lease_offer_command().is_some() {
            Some(request.revoked_lease_offer_fallback().ok_or_else(|| {
                StoreError::corrupt_data(
                    "lease-offer completion is missing its typed revocation fallback",
                )
            })?)
        } else {
            if request.revoked_lease_offer_fallback().is_some() {
                return Err(StoreError::corrupt_data(
                    "non-offer completion carries a lease-offer revocation fallback",
                ));
            }
            None
        };
        let begin = request.request();
        let key = begin.request_key();
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::pin_runner_attempt_read_committed(&mut transaction).await?;
        lock_live_routing(&mut transaction, key.session())
            .await?
            .require_online(key.session())?;
        lock_current_lease_request_head(&mut transaction, key, Some(begin.request_digest()))
            .await?;
        let operation = lease_rpc_operation_request(begin)?;
        let offer_expectation = ReceiptOfferExpectation::Exact(request.lease_offer_command());
        if let Some(existing) = load_generic_receipt(
            &mut transaction,
            encryption,
            &operation,
            true,
            offer_expectation,
        )
        .await?
        {
            let completion = match existing {
                LoadedGenericReceipt::Live {
                    receipt,
                    lease_offer_fallback,
                } => {
                    if request.lease_offer_command().is_some() {
                        if receipt.response() != request.response() {
                            return Err(StoreError::corrupt_data(
                                "lease-offer completion replayed a different primary response",
                            ));
                        }
                        let fallback = lease_offer_fallback.ok_or_else(|| {
                            StoreError::corrupt_data(
                                "live lease-offer receipt lost its revocation fallback",
                            )
                        })?;
                        LeaseRequestCompletion::LiveLeaseOffer {
                            response: receipt.response().clone(),
                            fallback,
                        }
                    } else if lease_offer_fallback.is_some() {
                        return Err(StoreError::corrupt_data(
                            "non-offer receipt carries lease-offer fallback metadata",
                        ));
                    } else {
                        LeaseRequestCompletion::Response(receipt.response().clone())
                    }
                }
                LoadedGenericReceipt::RevokedLeaseOffer {
                    operation_id,
                    primary_response_schema,
                    primary_response_digest,
                    fallback,
                    ..
                } => {
                    let identity = request.lease_offer_command().ok_or_else(|| {
                        StoreError::corrupt_data(
                            "non-offer completion resolved a revoked lease offer",
                        )
                    })?;
                    if identity.operation_id() != operation_id {
                        return Err(StoreError::corrupt_data(
                            "lease-offer completion resolved a different revoked command",
                        ));
                    }
                    if request.response().schema() != primary_response_schema
                        || request.response().digest() != primary_response_digest
                    {
                        return Err(StoreError::corrupt_data(
                            "lease-offer completion replayed a different primary response",
                        ));
                    }
                    LeaseRequestCompletion::RevokedLeaseOffer {
                        offer_operation_id: operation_id,
                        fallback,
                    }
                }
            };
            transaction.commit().await.map_err(operation_error)?;
            return Ok(completion);
        }
        let publication = if let Some(identity) = request.lease_offer_command() {
            if let Some(delivery) = lock_lease_offer_command_delivery(
                &mut transaction,
                identity.session(),
                identity.sequence(),
                Some(identity.operation_id()),
                Some(operation.operation_id()),
            )
            .await?
                && let LockedLeaseOfferDeliveryStatus::Revoked(revocation) = delivery.status
            {
                let receipt_binding = ReceiptLeaseOfferBinding {
                    request_operation_id: OperationId::from_uuid(
                        delivery.publication.request_operation_id,
                    ),
                    sequence: delivery.command.sequence()?,
                };
                mark_replay_publication_revoked(
                    &mut transaction,
                    &delivery.command,
                    delivery.publication,
                    revocation,
                )
                .await?;
                let completion = persist_revoked_lease_offer_response(
                    &mut transaction,
                    encryption,
                    &operation,
                    &request,
                    receipt_binding,
                )
                .await?;
                transaction.commit().await.map_err(operation_error)?;
                return Ok(completion);
            }
            let publication =
                load_lease_offer_publication_by_command(&mut transaction, encryption, identity)
                    .await?
                    .ok_or_else(|| {
                        StoreError::corrupt_data(
                            "lease-request response references an orphaned offer command",
                        )
                    })?;
            let delivery =
                classify_locked_published_lease_offer(&mut transaction, &publication).await?;
            if publication.request() != &operation {
                return Err(StoreError::corrupt_data(
                    "lease-request response resolved a different offer publication",
                ));
            }
            if let LockedLeaseOfferDeliveryStatus::Revoked(revocation) = delivery {
                mark_published_lease_offer_revoked(&mut transaction, &publication, revocation)
                    .await?;
                let receipt_binding = lease_offer_receipt_binding(&publication);
                let completion = persist_revoked_lease_offer_response(
                    &mut transaction,
                    encryption,
                    &operation,
                    &request,
                    receipt_binding,
                )
                .await?;
                transaction.commit().await.map_err(operation_error)?;
                return Ok(completion);
            }
            Some(publication)
        } else {
            None
        };
        let receipt = insert_generic_receipt(
            &mut transaction,
            encryption,
            operation.clone(),
            request.response().clone(),
            request.completed_at(),
            publication.as_ref(),
            request.revoked_lease_offer_fallback(),
        )
        .await;
        let completion = match receipt {
            Ok(receipt) => match requested_fallback {
                Some(fallback) => LeaseRequestCompletion::LiveLeaseOffer {
                    response: receipt.response().clone(),
                    fallback,
                },
                None => LeaseRequestCompletion::Response(receipt.response().clone()),
            },
            Err(StoreError::AttemptFenceRejected(attempt_id)) => {
                let publication = publication
                    .as_ref()
                    .ok_or_else(|| StoreError::AttemptFenceRejected(attempt_id))?;
                if publication.lease().attempt_id() != attempt_id {
                    return Err(StoreError::AttemptFenceRejected(attempt_id));
                }
                let LockedLeaseOfferDeliveryStatus::Revoked(revocation) =
                    classify_locked_published_lease_offer(&mut transaction, publication).await?
                else {
                    return Err(StoreError::AttemptFenceRejected(attempt_id));
                };
                mark_published_lease_offer_revoked(&mut transaction, publication, revocation)
                    .await?;
                let receipt_binding = lease_offer_receipt_binding(publication);
                persist_revoked_lease_offer_response(
                    &mut transaction,
                    encryption,
                    &operation,
                    &request,
                    receipt_binding,
                )
                .await?
            }
            Err(error) => return Err(error),
        };
        transaction.commit().await.map_err(operation_error)?;
        Ok(completion)
    }
}

async fn persist_revoked_lease_offer_response(
    transaction: &mut Transaction<'_, Postgres>,
    encryption: &RunnerPayloadEncryption,
    operation: &RunnerOperationRequest,
    completion: &CompleteLeaseRequest,
    receipt_binding: ReceiptLeaseOfferBinding,
) -> Result<LeaseRequestCompletion, StoreError> {
    if receipt_binding.request_operation_id != operation.operation_id() {
        return Err(StoreError::corrupt_data(
            "revoked lease-offer receipt references a different request",
        ));
    }
    let response = completion
        .revoked_lease_offer_response()
        .ok_or_else(|| {
            StoreError::corrupt_data("lease-offer completion is missing its revocation response")
        })?
        .clone();
    let fallback = completion.revoked_lease_offer_fallback().ok_or_else(|| {
        StoreError::corrupt_data("lease-offer completion is missing its typed revocation fallback")
    })?;
    if response.schema() != fallback.response_schema()
        || response.digest() != fallback.response_digest()
    {
        return Err(StoreError::corrupt_data(
            "lease-offer completion fallback metadata mismatches its response",
        ));
    }
    let offer_operation_id = completion
        .lease_offer_command()
        .ok_or_else(|| {
            StoreError::corrupt_data("revoked receipt completion has no lease-offer command")
        })?
        .operation_id();
    let tenant_id = runner_payload_tenant(transaction, operation.session()).await?;
    let plaintext_size_bytes = i64::try_from(response.payload().len())
        .map_err(|_| StoreError::corrupt_data("runner response size exceeds PostgreSQL BIGINT"))?;
    let metadata = RunnerResponseEnvelopeMetadata::from_values(
        operation,
        &response,
        plaintext_size_bytes,
        completion.completed_at(),
    )?;
    let envelope = seal_runner_payload(
        encryption,
        &tenant_id,
        &encryption.response_purpose,
        metadata.record_id(),
        response.payload(),
    )
    .await?;
    if envelope.plaintext_size_bytes != metadata.plaintext_size_bytes {
        return Err(StoreError::corrupt_data(
            "sealed runner response size changed unexpectedly",
        ));
    }
    require_persisted_revoked_receipt_binding(transaction, operation, receipt_binding).await?;
    let lease_offer_completion = ReceiptLeaseOfferCompletion::new(
        receipt_binding,
        ReceiptLeaseOfferResponseDisposition::RevokedFallback,
        completion.response(),
        fallback,
    );
    let inserted = insert_generic_receipt_row(
        transaction,
        &metadata,
        &tenant_id,
        &envelope,
        Some(lease_offer_completion),
    )
    .await?;
    if inserted != 1 {
        return Err(StoreError::corrupt_data(
            "revoked lease-offer receipt conflicted after its exact head was locked",
        ));
    }
    Ok(LeaseRequestCompletion::RevokedLeaseOffer {
        offer_operation_id,
        fallback,
    })
}

fn lease_offer_receipt_binding(publication: &PublishedLeaseOffer) -> ReceiptLeaseOfferBinding {
    ReceiptLeaseOfferBinding {
        request_operation_id: publication.request().operation_id(),
        sequence: publication.command().sequence(),
    }
}

async fn require_persisted_revoked_receipt_binding(
    transaction: &mut Transaction<'_, Postgres>,
    operation: &RunnerOperationRequest,
    binding: ReceiptLeaseOfferBinding,
) -> Result<(), StoreError> {
    let evidence: Option<(i64, i64, Option<i64>, Option<String>)> = sqlx::query_as(
        r"
        SELECT created_at_ms, offer_valid_until_ms,
               delivery_revoked_at_ms, delivery_revocation_reason
        FROM runner_lease_offer_publications
        WHERE runner_session_id = $1
          AND request_operation_id = $2
          AND command_sequence = $3
        FOR UPDATE
        ",
    )
    .bind(operation.session().session_id().as_uuid())
    .bind(binding.request_operation_id.as_uuid())
    .bind(sequence_i64(binding.sequence)?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some((created_at, offer_valid_until, Some(revoked_at), Some(reason))) = evidence else {
        return Err(StoreError::corrupt_data(
            "revoked lease-offer receipt lost its durable publication marker",
        ));
    };
    let reason = decode_lease_offer_delivery_revocation_reason(&reason)?;
    if revoked_at < created_at
        || (reason == LeaseOfferDeliveryRevocationReason::AuthorityExpired
            && revoked_at < offer_valid_until)
    {
        return Err(StoreError::corrupt_data(
            "revoked lease-offer receipt has invalid publication evidence",
        ));
    }
    Ok(())
}

#[async_trait]
impl RunnerLeaseOfferRepository for PostgresStore {
    async fn inspect_lease_offer_claim(
        &self,
        request: LeaseOfferClaim,
    ) -> Result<LeaseOfferClaimStatus, StoreError> {
        let encryption = self.require_runner_payload_encryption()?;
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::pin_runner_attempt_read_committed(&mut transaction).await?;
        super::admission::lock_attempt_concurrency(&mut transaction, request.lease().attempt_id())
            .await?;
        let routing = lock_live_routing(&mut transaction, request.request().session()).await?;
        routing.require_online(request.request().session())?;
        if let Some(publication) =
            load_lease_offer_publication(&mut transaction, encryption, &request, None, None, true)
                .await?
        {
            if !matches!(
                classify_locked_published_lease_offer(&mut transaction, &publication).await?,
                LockedLeaseOfferDeliveryStatus::Live
            ) {
                transaction.commit().await.map_err(operation_error)?;
                return Ok(LeaseOfferClaimStatus::ClaimSuperseded);
            }
            transaction.commit().await.map_err(operation_error)?;
            return Ok(LeaseOfferClaimStatus::Published(Box::new(publication)));
        }
        lock_exact_lease_offer_claim(&mut transaction, &request, &routing).await?;
        let current = lock_publishable_lease_offer_attempt(&mut transaction, &request).await?;
        if current && !routing.accepts_new_work {
            return Err(StoreError::RunnerNotAcceptingWork(
                request.request().session().runner_id(),
            ));
        }
        transaction.commit().await.map_err(operation_error)?;
        Ok(if current {
            LeaseOfferClaimStatus::Current
        } else {
            LeaseOfferClaimStatus::ClaimSuperseded
        })
    }

    async fn resolve_lease_offer_command(
        &self,
        identity: LeaseOfferCommandIdentity,
    ) -> Result<Option<PublishedLeaseOffer>, StoreError> {
        let encryption = self.require_runner_payload_encryption()?;
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::pin_runner_attempt_read_committed(&mut transaction).await?;
        lock_live_routing(&mut transaction, identity.session())
            .await?
            .require_online(identity.session())?;
        if let Some(delivery) = lock_lease_offer_command_delivery(
            &mut transaction,
            identity.session(),
            identity.sequence(),
            Some(identity.operation_id()),
            None,
        )
        .await?
            && let LockedLeaseOfferDeliveryStatus::Revoked(revocation) = delivery.status
        {
            mark_replay_publication_revoked(
                &mut transaction,
                &delivery.command,
                delivery.publication,
                revocation,
            )
            .await?;
            let attempt_id = delivery.publication.attempt_id;
            transaction.commit().await.map_err(operation_error)?;
            return Err(StoreError::AttemptFenceRejected(attempt_id));
        }
        let publication =
            load_lease_offer_publication_by_command(&mut transaction, encryption, identity).await?;
        if let Some(publication) = publication.as_ref() {
            match classify_locked_published_lease_offer(&mut transaction, publication).await? {
                LockedLeaseOfferDeliveryStatus::Live => {}
                LockedLeaseOfferDeliveryStatus::Revoked(revocation) => {
                    mark_published_lease_offer_revoked(&mut transaction, publication, revocation)
                        .await?;
                    let attempt_id = publication.lease().attempt_id();
                    transaction.commit().await.map_err(operation_error)?;
                    return Err(StoreError::AttemptFenceRejected(attempt_id));
                }
            }
        }
        transaction.commit().await.map_err(operation_error)?;
        Ok(publication)
    }

    async fn publish_lease_offer(
        &self,
        request: PublishLeaseOffer,
    ) -> Result<PublishedLeaseOffer, StoreError> {
        let encryption = self.require_runner_payload_encryption()?;
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::pin_runner_attempt_read_committed(&mut transaction).await?;
        super::admission::lock_attempt_concurrency(&mut transaction, request.lease().attempt_id())
            .await?;
        let routing = lock_live_routing(&mut transaction, request.request().session()).await?;
        routing.require_online(request.request().session())?;
        if let Some(publication) = load_lease_offer_publication(
            &mut transaction,
            encryption,
            request.claim(),
            Some(request.command()),
            Some(request.offer_valid_until()),
            true,
        )
        .await?
        {
            if !matches!(
                classify_locked_published_lease_offer(&mut transaction, &publication).await?,
                LockedLeaseOfferDeliveryStatus::Live
            ) {
                return Err(StoreError::AttemptFenceRejected(
                    publication.lease().attempt_id(),
                ));
            }
            transaction.commit().await.map_err(operation_error)?;
            return Ok(publication);
        }
        lock_exact_lease_offer_claim(&mut transaction, request.claim(), &routing).await?;
        if !lock_publishable_lease_offer_attempt(&mut transaction, request.claim()).await? {
            return Err(StoreError::AttemptFenceRejected(
                request.lease().attempt_id(),
            ));
        }
        let database_now = super::runner_attempt_database_now(&mut transaction).await?;
        if database_now < request.command().created_at()
            || database_now >= request.offer_valid_until()
        {
            return Err(StoreError::AttemptFenceRejected(
                request.lease().attempt_id(),
            ));
        }
        if !routing.accepts_new_work {
            return Err(StoreError::RunnerNotAcceptingWork(
                request.request().session().runner_id(),
            ));
        }
        let command =
            enqueue_command_in_transaction(&mut transaction, encryption, request.command().clone())
                .await?;
        let post_encryption_now = super::runner_attempt_database_now(&mut transaction).await?;
        if post_encryption_now < request.command().created_at()
            || post_encryption_now >= request.offer_valid_until()
        {
            return Err(StoreError::AttemptFenceRejected(
                request.lease().attempt_id(),
            ));
        }
        insert_lease_offer_publication(&mut transaction, &request, command.sequence()).await?;
        let publication = PublishedLeaseOffer::new(
            request.request().clone(),
            request.protocol_version(),
            request.slot(),
            request.lease().clone(),
            request.job_ir().clone(),
            request.offer_valid_until(),
            command,
        )
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(publication)
    }
}

#[async_trait]
impl RuntimeAuthorityDeliveryRepository for PostgresStore {
    async fn authorize_runtime_authority_delivery(
        &self,
        request: AuthorizeRuntimeAuthorityDelivery,
    ) -> Result<RuntimeAuthorityDeliveryAdmission, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::pin_runner_attempt_read_committed(&mut transaction).await?;
        super::admission::lock_attempt_concurrency(
            &mut transaction,
            request.binding().attempt_id(),
        )
        .await?;
        let Some((offer, delivery)) = lock_runtime_authority_delivery_admission(
            &mut transaction,
            request.request().session(),
            request.protocol_version(),
            request.binding(),
        )
        .await?
        else {
            transaction.commit().await.map_err(operation_error)?;
            return Err(StoreError::SessionClosed(
                request.request().session().session_id(),
            ));
        };
        if request.request().kind().as_str() != RUNTIME_AUTHORITY_REQUEST_KIND {
            return Err(StoreError::OperationConflict {
                session_id: request.request().session().session_id(),
                operation_id: request.request().operation_id(),
            });
        }
        if let Some(delivery) = delivery.as_ref()
            && (delivery.request_operation_id != request.request().operation_id()
                || delivery.request_digest != request.request().request_digest())
        {
            return Err(StoreError::OperationConflict {
                session_id: request.request().session().session_id(),
                operation_id: request.request().operation_id(),
            });
        }
        let admission = RuntimeAuthorityDeliveryAdmission::new(
            request,
            offer,
            delivery.map(|delivery| delivery.bundle_digest),
        )
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(admission)
    }

    async fn commit_runtime_authority_delivery(
        &self,
        request: CommitRuntimeAuthorityDelivery,
    ) -> Result<RuntimeAuthorityDeliveryDisposition, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::pin_runner_attempt_read_committed(&mut transaction).await?;
        let requested = request.admission().request();
        super::admission::lock_attempt_concurrency(
            &mut transaction,
            requested.binding().attempt_id(),
        )
        .await?;
        let Some((offer, delivery)) = lock_runtime_authority_delivery_admission(
            &mut transaction,
            requested.request().session(),
            requested.protocol_version(),
            requested.binding(),
        )
        .await?
        else {
            transaction.commit().await.map_err(operation_error)?;
            return Err(StoreError::SessionClosed(
                requested.request().session().session_id(),
            ));
        };
        if requested.request().kind().as_str() != RUNTIME_AUTHORITY_REQUEST_KIND
            || &offer != request.admission().offer()
        {
            return Err(StoreError::OperationConflict {
                session_id: requested.request().session().session_id(),
                operation_id: requested.request().operation_id(),
            });
        }
        if let Some(delivery) = delivery {
            if delivery.request_operation_id != requested.request().operation_id()
                || delivery.request_digest != requested.request().request_digest()
                || delivery.bundle_digest != request.bundle_digest()
            {
                return Err(StoreError::OperationConflict {
                    session_id: requested.request().session().session_id(),
                    operation_id: requested.request().operation_id(),
                });
            }
            transaction.commit().await.map_err(operation_error)?;
            return Ok(RuntimeAuthorityDeliveryDisposition::Replayed);
        }
        let database_now = super::runner_attempt_database_now(&mut transaction).await?;
        if database_now >= offer.offer_valid_until() {
            return Err(StoreError::AttemptFenceRejected(offer.lease().attempt_id()));
        }
        insert_runtime_authority_delivery(
            &mut transaction,
            request.admission(),
            request.bundle_digest(),
            database_now,
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(RuntimeAuthorityDeliveryDisposition::Committed)
    }

    async fn acknowledge_runtime_authority_delivery(
        &self,
        request: AcknowledgeRuntimeAuthorityDelivery,
    ) -> Result<RuntimeAuthorityDeliveryDisposition, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::pin_runner_attempt_read_committed(&mut transaction).await?;
        super::admission::lock_attempt_concurrency(
            &mut transaction,
            request.binding().attempt_id(),
        )
        .await?;
        let Some((_offer, delivery)) = lock_runtime_authority_delivery_admission(
            &mut transaction,
            request.request().session(),
            request.protocol_version(),
            request.binding(),
        )
        .await?
        else {
            transaction.commit().await.map_err(operation_error)?;
            return Err(StoreError::SessionClosed(
                request.request().session().session_id(),
            ));
        };
        if request.request().kind().as_str() != RUNTIME_AUTHORITY_ACK_KIND {
            return Err(StoreError::OperationConflict {
                session_id: request.request().session().session_id(),
                operation_id: request.request().operation_id(),
            });
        }
        let delivery = delivery.ok_or_else(|| {
            StoreError::corrupt_data("runtime-authority acknowledgement has no committed delivery")
        })?;
        if delivery.bundle_digest != request.bundle_digest() {
            return Err(StoreError::OperationConflict {
                session_id: request.request().session().session_id(),
                operation_id: request.request().operation_id(),
            });
        }
        match (
            delivery.acknowledgement_operation_id,
            delivery.acknowledgement_digest,
            delivery.acknowledged_at,
        ) {
            (Some(operation_id), Some(digest), Some(_)) => {
                if operation_id != request.request().operation_id()
                    || digest != request.request().request_digest()
                {
                    return Err(StoreError::OperationConflict {
                        session_id: request.request().session().session_id(),
                        operation_id: request.request().operation_id(),
                    });
                }
                transaction.commit().await.map_err(operation_error)?;
                Ok(RuntimeAuthorityDeliveryDisposition::Replayed)
            }
            (None, None, None) => {
                let database_now = super::runner_attempt_database_now(&mut transaction).await?;
                acknowledge_runtime_authority_delivery_row(
                    &mut transaction,
                    &request,
                    database_now,
                )
                .await?;
                transaction.commit().await.map_err(operation_error)?;
                Ok(RuntimeAuthorityDeliveryDisposition::Committed)
            }
            _ => Err(StoreError::corrupt_data(
                "runtime-authority delivery has partial acknowledgement evidence",
            )),
        }
    }
}

#[async_trait]
impl RunnerControlTransactionRepository for PostgresStore {
    async fn admit_runner_log_segment(
        &self,
        request: RunnerLogAdmissionRequest,
    ) -> Result<RunnerLogAdmission, StoreError> {
        self.require_runner_payload_encryption()?;
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::pin_runner_attempt_read_committed(&mut transaction).await?;
        let fence = request.request().session();
        super::admission::lock_attempt_concurrency(&mut transaction, request.attempt_id()).await?;
        let routing = lock_live_routing(&mut transaction, fence).await?;
        routing.require_online(fence)?;
        let locked = lock_exact_active_attempt(
            &mut transaction,
            request.attempt_id(),
            fence,
            request.guard(),
            request.observed_at(),
        )
        .await?;
        let admission = lock_runner_log_admission(
            &mut transaction,
            request,
            locked.slot,
            routing.tenant_id.as_str(),
        )
        .await?
        .admission;
        transaction.rollback().await.map_err(operation_error)?;
        Ok(admission)
    }

    async fn authorize_lease_renewal(
        &self,
        request: RenewLease,
        reported_lifecycle: JobLifecycle,
    ) -> Result<RenewLease, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::pin_runner_attempt_read_committed(&mut transaction).await?;
        let authorized = super::authorize_lease_renewal_in_transaction(
            &mut transaction,
            request,
            reported_lifecycle,
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(authorized)
    }

    async fn commit_lease_response(
        &self,
        request: CommitLeaseResponse,
    ) -> Result<RunnerOperationReceipt, StoreError> {
        let encryption = self.require_runner_payload_encryption()?;
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::pin_runner_attempt_read_committed(&mut transaction).await?;
        let fence = request.request().session();
        super::admission::lock_attempt_concurrency(&mut transaction, request.attempt_id()).await?;
        let routing = lock_live_routing(&mut transaction, fence).await?;
        routing.require_online(fence)?;
        let current = locked_session(&mut transaction, fence).await?;
        if !current.is_live() {
            return Err(StoreError::SessionClosed(fence.session_id()));
        }
        if let Some(receipt) = load_generic_receipt(
            &mut transaction,
            encryption,
            request.request(),
            true,
            ReceiptOfferExpectation::Exact(None),
        )
        .await?
        {
            // The exact receipt closes this operation; later attempt state cannot
            // reinterpret an already-committed response.
            let receipt = receipt.into_live()?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(receipt);
        }
        let decision_now = verify_exact_published_offer(&mut transaction, &request).await?;
        update_session_liveness(
            &mut transaction,
            fence,
            request.command_cursor(),
            decision_now,
            &current,
        )
        .await?;
        apply_lease_response(&mut transaction, &request, decision_now).await?;
        super::admission::reconcile_attempt_run(
            &mut transaction,
            request.attempt_id(),
            decision_now,
        )
        .await?;
        let receipt = insert_generic_receipt(
            &mut transaction,
            encryption,
            request.request().clone(),
            request.response().clone(),
            decision_now,
            None,
            None,
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }

    async fn commit_lease_heartbeat(
        &self,
        request: CommitLeaseHeartbeat,
    ) -> Result<RunnerOperationReceipt, StoreError> {
        let encryption = self.require_runner_payload_encryption()?;
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::pin_runner_attempt_read_committed(&mut transaction).await?;
        let fence = request.request().session();
        super::admission::lock_attempt_concurrency(
            &mut transaction,
            request.renewal().attempt_id(),
        )
        .await?;
        let routing = lock_live_routing(&mut transaction, fence).await?;
        if !routing.online {
            return Err(StoreError::SessionClosed(fence.session_id()));
        }
        let current = locked_session(&mut transaction, fence).await?;
        if !current.is_live() {
            return Err(StoreError::SessionClosed(fence.session_id()));
        }
        if let Some(receipt) = load_generic_receipt(
            &mut transaction,
            encryption,
            request.request(),
            true,
            ReceiptOfferExpectation::Exact(None),
        )
        .await?
        {
            let receipt = receipt.into_live()?;
            require_live_renewal_attempt(&mut transaction, request.renewal()).await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(receipt);
        }
        let decision_now =
            require_live_renewal_attempt(&mut transaction, request.renewal()).await?;
        super::validate_runner_attempt_caller_clock(request.renewal().observed_at(), decision_now)?;
        update_session_liveness(
            &mut transaction,
            fence,
            request.command_cursor(),
            decision_now,
            &current,
        )
        .await?;
        if let Some(lifecycle) = request.reported_lifecycle() {
            commit_reported_lifecycle(&mut transaction, request.renewal(), lifecycle, decision_now)
                .await?;
        }
        let lease = super::commit_database_issued_lease_renewal_in_transaction(
            &mut transaction,
            request.renewal(),
        )
        .await?;
        if lease.expires_at() != request.renewal().expires_at()
            || lease.guard() != request.renewal().guard()
            || lease.attempt_id() != request.renewal().attempt_id()
        {
            return Err(StoreError::corrupt_data(
                "atomic heartbeat renewal returned mismatched lease",
            ));
        }
        let receipt_now = super::runner_attempt_database_now(&mut transaction).await?;
        if receipt_now >= lease.expires_at() {
            return Err(StoreError::Attempt(AttemptStoreError::LeaseExpired(
                lease.attempt_id(),
            )));
        }
        let receipt = insert_generic_receipt(
            &mut transaction,
            encryption,
            request.request().clone(),
            request.response().clone(),
            receipt_now,
            None,
            None,
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }

    async fn commit_command_acknowledgement(
        &self,
        request: CommitCommandAcknowledgement,
    ) -> Result<RunnerOperationReceipt, StoreError> {
        let encryption = self.require_runner_payload_encryption()?;
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::pin_runner_attempt_read_committed(&mut transaction).await?;
        let fence = request.request().session();
        let routing = lock_live_routing(&mut transaction, fence).await?;
        if !routing.online {
            return Err(StoreError::SessionClosed(fence.session_id()));
        }
        let current = locked_session(&mut transaction, fence).await?;
        if !current.is_live() {
            return Err(StoreError::SessionClosed(fence.session_id()));
        }
        if let Some(receipt) = load_generic_receipt(
            &mut transaction,
            encryption,
            request.request(),
            true,
            ReceiptOfferExpectation::Exact(None),
        )
        .await?
        {
            let receipt = receipt.into_live()?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(receipt);
        }
        let acknowledgement = request.acknowledgement();
        let database_now = super::runner_attempt_database_now(&mut transaction).await?;
        let decision_at = database_session_decision_at(database_now, [current.heartbeat_at()])?;
        update_session_liveness(
            &mut transaction,
            fence,
            acknowledgement.cursor(),
            decision_at,
            &current,
        )
        .await?;
        let receipt = insert_generic_receipt(
            &mut transaction,
            encryption,
            request.request().clone(),
            request.response().clone(),
            decision_at,
            None,
            None,
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }

    async fn commit_runner_terminal_result(
        &self,
        request: CommitRunnerTerminalResult,
    ) -> Result<RunnerOperationReceipt, StoreError> {
        let encryption = self.require_runner_payload_encryption()?;
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::pin_runner_attempt_read_committed(&mut transaction).await?;
        let fence = request.request().session();
        super::admission::lock_attempt_concurrency(&mut transaction, request.attempt_id()).await?;
        lock_live_routing(&mut transaction, fence)
            .await?
            .require_online(fence)?;
        if let Some(receipt) = load_generic_receipt(
            &mut transaction,
            encryption,
            request.request(),
            true,
            ReceiptOfferExpectation::Exact(None),
        )
        .await?
        {
            let receipt = receipt.into_live()?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(receipt);
        }
        let locked = lock_exact_active_attempt(
            &mut transaction,
            request.attempt_id(),
            fence,
            request.guard(),
            request.committed_at(),
        )
        .await?;
        insert_terminal_result(&mut transaction, &request, locked.slot).await?;
        let decision_at = require_locked_attempt_database_live(
            &mut transaction,
            request.attempt_id(),
            locked.expires_at,
        )
        .await?;
        conclude_terminal_attempt(&mut transaction, &request, decision_at).await?;
        close_cancellation_from_result(&mut transaction, request.attempt_id(), decision_at).await?;
        super::admission::reconcile_attempt_run(
            &mut transaction,
            request.attempt_id(),
            decision_at,
        )
        .await?;
        let receipt = insert_generic_receipt(
            &mut transaction,
            encryption,
            request.request().clone(),
            request.response().clone(),
            decision_at,
            None,
            None,
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }

    async fn commit_runner_log_segment(
        &self,
        request: CommitRunnerLogSegment,
    ) -> Result<RunnerOperationReceipt, StoreError> {
        let encryption = self.require_runner_payload_encryption()?;
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::pin_runner_attempt_read_committed(&mut transaction).await?;
        let fence = request.request().session();
        super::admission::lock_attempt_concurrency(&mut transaction, request.attempt_id()).await?;
        let routing = lock_live_routing(&mut transaction, fence).await?;
        routing.require_online(fence)?;
        if let Some(receipt) = load_generic_receipt(
            &mut transaction,
            encryption,
            request.request(),
            true,
            ReceiptOfferExpectation::Exact(None),
        )
        .await?
        {
            let receipt = receipt.into_live()?;
            verify_replayed_runner_log_admission(
                &mut transaction,
                &request,
                routing.tenant_id.as_str(),
            )
            .await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(receipt);
        }
        let active = lock_exact_active_attempt(
            &mut transaction,
            request.attempt_id(),
            fence,
            request.guard(),
            request.stored_at(),
        )
        .await?;
        let locked = lock_runner_log_admission(
            &mut transaction,
            request.admission().request().clone(),
            active.slot,
            routing.tenant_id.as_str(),
        )
        .await?;
        if locked.admission != *request.admission() {
            return Err(StoreError::AttemptFenceRejected(request.attempt_id()));
        }
        append_runner_log_segment(
            &mut transaction,
            &request,
            locked.admission.slot(),
            &locked.safety,
        )
        .await?;
        let decision_at = require_locked_attempt_database_live(
            &mut transaction,
            request.attempt_id(),
            active.expires_at,
        )
        .await?;
        let receipt = insert_generic_receipt(
            &mut transaction,
            encryption,
            request.request().clone(),
            request.response().clone(),
            decision_at,
            None,
            None,
        )
        .await?;
        publish_log_commit_notification(
            &mut transaction,
            HumanLogCommitHint::new(
                request.stream_id(),
                request.last_sequence(),
                request.is_end_of_stream(),
            ),
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }
}

fn decode_fencing(value: i64) -> Result<FencingToken, StoreError> {
    u64::try_from(value)
        .ok()
        .and_then(|value| FencingToken::new(value).ok())
        .ok_or_else(|| StoreError::corrupt_data("invalid log-stream fencing token"))
}

async fn verify_exact_published_offer(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitLeaseResponse,
) -> Result<UnixMillis, StoreError> {
    let fence = request.request().session();
    let row = sqlx::query(
        r"
        SELECT attempt.lifecycle, attempt.changed_at_ms, attempt.lease_expires_at_ms,
               publication.lease_issued_at_ms AS publication_lease_issued_at_ms,
               publication.lease_expires_at_ms AS publication_lease_expires_at_ms,
               publication.offer_valid_until_ms, publication.created_at_ms
        FROM runner_lease_offer_publications AS publication
        JOIN runner_command_outbox AS command
          ON command.runner_session_id = publication.runner_session_id
         AND command.command_sequence = publication.command_sequence
        JOIN job_attempts AS attempt ON attempt.id = publication.attempt_id
        WHERE publication.runner_session_id = $1
          AND publication.attempt_id = $2
          AND publication.runner_id = $3
          AND publication.runner_session_epoch = $4
          AND publication.runner_generation = $5
          AND publication.runner_slot = $6
          AND publication.lease_id = $7
          AND publication.fencing_token = $8
          AND attempt.runner_session_id = publication.runner_session_id
          AND attempt.runner_id = publication.runner_id
          AND attempt.runner_session_epoch = publication.runner_session_epoch
          AND attempt.runner_generation = publication.runner_generation
          AND attempt.runner_slot = publication.runner_slot
          AND attempt.lease_id = publication.lease_id
          AND attempt.fencing_token = publication.fencing_token
          AND attempt.lease_issued_at_ms = publication.lease_issued_at_ms
          AND attempt.lease_expires_at_ms >= publication.lease_expires_at_ms
        FOR UPDATE OF publication, attempt
        ",
    )
    .bind(fence.session_id().as_uuid())
    .bind(request.attempt_id().as_uuid())
    .bind(fence.runner_id().as_uuid())
    .bind(epoch_i64(fence.session_epoch())?)
    .bind(generation_i64(fence.runner_generation())?)
    .bind(i32::from(request.slot().ordinal()))
    .bind(request.guard().lease_id().as_uuid())
    .bind(fencing_i64(request.guard().fencing_token())?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(StoreError::AttemptFenceRejected(request.attempt_id()))?;
    let lifecycle = parse_lifecycle(row.try_get("lifecycle").map_err(operation_error)?)
        .map_err(StoreError::from)?;
    if lifecycle != JobLifecycle::Leased {
        return Err(StoreError::AttemptFenceRejected(request.attempt_id()));
    }
    let database_now = super::runner_attempt_database_now(transaction).await?;
    let publication_created_at =
        UnixMillis::new(row.try_get("created_at_ms").map_err(operation_error)?);
    if database_now < publication_created_at {
        return Err(StoreError::AttemptFenceRejected(request.attempt_id()));
    }
    super::validate_runner_attempt_caller_clock(request.observed_at(), database_now)?;
    let current_lease_expires_at = UnixMillis::new(
        row.try_get("lease_expires_at_ms")
            .map_err(operation_error)?,
    );
    if database_now >= current_lease_expires_at {
        return Err(StoreError::Attempt(AttemptStoreError::LeaseExpired(
            request.attempt_id(),
        )));
    }
    let acceptance_expires_at = UnixMillis::new(
        row.try_get("offer_valid_until_ms")
            .map_err(operation_error)?,
    );
    if request.action() == LeaseResponseAction::Accept && database_now >= acceptance_expires_at {
        return Err(StoreError::Attempt(AttemptStoreError::LeaseExpired(
            request.attempt_id(),
        )));
    }
    Ok(database_now)
}

async fn apply_lease_response(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitLeaseResponse,
    decision_now: UnixMillis,
) -> Result<(), StoreError> {
    let next = match request.action() {
        LeaseResponseAction::Accept => "preparing",
        LeaseResponseAction::Requeue => "queued",
        LeaseResponseAction::Fail => "failed",
    };
    let retain_lease = request.action() == LeaseResponseAction::Accept;
    let requeue = request.action() == LeaseResponseAction::Requeue;
    let fence = request.request().session();
    let rows = sqlx::query(
        r"
        UPDATE job_attempts
        SET lifecycle = $9,
            lease_id = CASE WHEN $10 THEN lease_id ELSE NULL END,
            runner_id = CASE WHEN $10 THEN runner_id ELSE NULL END,
            lease_issued_at_ms = CASE WHEN $10 THEN lease_issued_at_ms ELSE NULL END,
            lease_expires_at_ms = CASE WHEN $10 THEN lease_expires_at_ms ELSE NULL END,
            runner_session_id = CASE WHEN $10 THEN runner_session_id ELSE NULL END,
            runner_session_epoch = CASE WHEN $10 THEN runner_session_epoch ELSE NULL END,
            runner_generation = CASE WHEN $10 THEN runner_generation ELSE NULL END,
            runner_slot = CASE WHEN $10 THEN runner_slot ELSE NULL END,
            lease_failures = lease_failures + CASE WHEN $11 THEN 1 ELSE 0 END,
            queued_at_ms = CASE WHEN $11 THEN $12 ELSE queued_at_ms END,
            changed_at_ms = $12
        WHERE id = $1 AND lifecycle = 'leased'
          AND lease_id = $2 AND fencing_token = $3
          AND runner_id = $4 AND runner_session_id = $5
          AND runner_session_epoch = $6 AND runner_generation = $7
          AND runner_slot = $8 AND changed_at_ms <= $12
          AND lease_expires_at_ms > $12
        ",
    )
    .bind(request.attempt_id().as_uuid())
    .bind(request.guard().lease_id().as_uuid())
    .bind(fencing_i64(request.guard().fencing_token())?)
    .bind(fence.runner_id().as_uuid())
    .bind(fence.session_id().as_uuid())
    .bind(epoch_i64(fence.session_epoch())?)
    .bind(generation_i64(fence.runner_generation())?)
    .bind(i32::from(request.slot().ordinal()))
    .bind(next)
    .bind(retain_lease)
    .bind(requeue)
    .bind(decision_now.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if rows != 1 {
        return Err(StoreError::AttemptFenceRejected(request.attempt_id()));
    }
    Ok(())
}

async fn require_live_renewal_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    renewal: RenewLease,
) -> Result<UnixMillis, StoreError> {
    let session = renewal.session();
    let row = sqlx::query(
        r"
        SELECT lifecycle IN ('leased', 'preparing', 'running', 'cancelling', 'finalizing')
                   AS lifecycle_is_active,
               lease_expires_at_ms
        FROM job_attempts
        WHERE id = $1
          AND lease_id = $2
          AND fencing_token = $3
          AND runner_id = $4
          AND runner_session_id = $5
          AND runner_session_epoch = $6
          AND runner_generation = $7
        FOR UPDATE
        ",
    )
    .bind(renewal.attempt_id().as_uuid())
    .bind(renewal.guard().lease_id().as_uuid())
    .bind(fencing_i64(renewal.guard().fencing_token())?)
    .bind(session.runner_id().as_uuid())
    .bind(session.session_id().as_uuid())
    .bind(epoch_i64(session.session_epoch())?)
    .bind(generation_i64(session.runner_generation())?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(StoreError::AttemptFenceRejected(renewal.attempt_id()))?;
    let lifecycle_is_active: bool = row
        .try_get("lifecycle_is_active")
        .map_err(operation_error)?;
    if !lifecycle_is_active {
        return Err(StoreError::AttemptFenceRejected(renewal.attempt_id()));
    }
    let current_expires_at = UnixMillis::new(
        row.try_get("lease_expires_at_ms")
            .map_err(operation_error)?,
    );
    let database_now = super::runner_attempt_database_now(transaction).await?;
    if database_now >= current_expires_at {
        return Err(StoreError::Attempt(AttemptStoreError::LeaseExpired(
            renewal.attempt_id(),
        )));
    }
    Ok(database_now)
}

async fn commit_reported_lifecycle(
    transaction: &mut Transaction<'_, Postgres>,
    renewal: RenewLease,
    reported: JobLifecycle,
    decision_now: UnixMillis,
) -> Result<(), StoreError> {
    let snapshot = super::locked_snapshot(transaction, renewal.attempt_id()).await?;
    super::verify_guard(renewal.attempt_id(), renewal.guard(), &snapshot)?;
    super::verify_assignment(renewal.attempt_id(), renewal.session(), &snapshot)?;
    if snapshot.lifecycle() == reported {
        return Ok(());
    }
    snapshot
        .lifecycle()
        .validate_transition(reported)
        .map_err(|_| {
            StoreError::Attempt(AttemptStoreError::InvalidTransition {
                attempt_id: renewal.attempt_id(),
                from: snapshot.lifecycle(),
                to: reported,
            })
        })?;
    let rows = sqlx::query(
        r"
        UPDATE job_attempts
        SET lifecycle = $4, changed_at_ms = $5
        WHERE id = $1 AND lease_id = $2 AND fencing_token = $3
          AND runner_id = $6 AND runner_session_id = $7
          AND runner_session_epoch = $8 AND runner_generation = $9
          AND changed_at_ms <= $5 AND lease_expires_at_ms > $5
        ",
    )
    .bind(renewal.attempt_id().as_uuid())
    .bind(renewal.guard().lease_id().as_uuid())
    .bind(fencing_i64(renewal.guard().fencing_token())?)
    .bind(lifecycle_name(reported))
    .bind(decision_now.get())
    .bind(renewal.session().runner_id().as_uuid())
    .bind(renewal.session().session_id().as_uuid())
    .bind(epoch_i64(renewal.session().session_epoch())?)
    .bind(generation_i64(renewal.session().runner_generation())?)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if rows != 1 {
        return Err(StoreError::AttemptFenceRejected(renewal.attempt_id()));
    }
    Ok(())
}

async fn lock_exact_active_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    attempt_id: AttemptId,
    fence: RunnerSessionFence,
    guard: LeaseGuard,
    observed_at: UnixMillis,
) -> Result<LockedActiveAttempt, StoreError> {
    let row = sqlx::query(
        r"
        SELECT lifecycle, runner_slot, changed_at_ms, lease_expires_at_ms
        FROM job_attempts
        WHERE id = $1 AND lease_id = $2 AND fencing_token = $3
          AND runner_id = $4 AND runner_session_id = $5
          AND runner_session_epoch = $6 AND runner_generation = $7
        FOR UPDATE
        ",
    )
    .bind(attempt_id.as_uuid())
    .bind(guard.lease_id().as_uuid())
    .bind(fencing_i64(guard.fencing_token())?)
    .bind(fence.runner_id().as_uuid())
    .bind(fence.session_id().as_uuid())
    .bind(epoch_i64(fence.session_epoch())?)
    .bind(generation_i64(fence.runner_generation())?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(StoreError::AttemptFenceRejected(attempt_id))?;
    let lifecycle = parse_lifecycle(row.try_get("lifecycle").map_err(operation_error)?)
        .map_err(StoreError::from)?;
    if !matches!(
        lifecycle,
        JobLifecycle::Leased
            | JobLifecycle::Preparing
            | JobLifecycle::Running
            | JobLifecycle::Cancelling
            | JobLifecycle::Finalizing
    ) {
        return Err(StoreError::AttemptFenceRejected(attempt_id));
    }
    let changed_at = UnixMillis::new(row.try_get("changed_at_ms").map_err(operation_error)?);
    if observed_at < changed_at {
        return Err(StoreError::AttemptTimeRegression {
            attempt_id,
            observed_at,
            changed_at,
        });
    }
    let expires_at = UnixMillis::new(
        row.try_get("lease_expires_at_ms")
            .map_err(operation_error)?,
    );
    let decision_at = super::runner_attempt_database_now(transaction).await?;
    super::validate_runner_attempt_caller_clock(observed_at, decision_at)?;
    if observed_at >= expires_at || decision_at >= expires_at {
        return Err(StoreError::Attempt(AttemptStoreError::LeaseExpired(
            attempt_id,
        )));
    }
    let slot = u16::try_from(
        row.try_get::<i32, _>("runner_slot")
            .map_err(operation_error)?,
    )
    .ok()
    .and_then(|value| StableRunnerSlot::new(value).ok())
    .ok_or_else(|| StoreError::corrupt_data("invalid active runner slot"))?;
    Ok(LockedActiveAttempt { slot, expires_at })
}

#[derive(Clone, Copy)]
struct LockedActiveAttempt {
    slot: StableRunnerSlot,
    expires_at: UnixMillis,
}

async fn require_locked_attempt_database_live(
    transaction: &mut Transaction<'_, Postgres>,
    attempt_id: AttemptId,
    expires_at: UnixMillis,
) -> Result<UnixMillis, StoreError> {
    let decision_at = super::runner_attempt_database_now(transaction).await?;
    if decision_at >= expires_at {
        return Err(StoreError::Attempt(AttemptStoreError::LeaseExpired(
            attempt_id,
        )));
    }
    Ok(decision_at)
}

async fn insert_terminal_result(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitRunnerTerminalResult,
    slot: StableRunnerSlot,
) -> Result<(), StoreError> {
    let fence = request.request().session();
    let rows = sqlx::query(
        r"
        INSERT INTO attempt_terminal_results (
            attempt_id, terminal_authority,
            runner_session_id, operation_id, runner_id,
            runner_session_epoch, runner_generation, runner_slot,
            lease_id, fencing_token, result_schema, result_size_bytes,
            result_digest, result_object_key, conclusion, completed_at_ms, committed_at_ms
        ) VALUES ($1,'runner',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
        ON CONFLICT DO NOTHING
        ",
    )
    .bind(request.attempt_id().as_uuid())
    .bind(fence.session_id().as_uuid())
    .bind(request.request().operation_id().as_uuid())
    .bind(fence.runner_id().as_uuid())
    .bind(epoch_i64(fence.session_epoch())?)
    .bind(generation_i64(fence.runner_generation())?)
    .bind(i32::from(slot.ordinal()))
    .bind(request.guard().lease_id().as_uuid())
    .bind(fencing_i64(request.guard().fencing_token())?)
    .bind(i32::from(request.schema().get()))
    .bind(size_i64(request.encoded_size(), "terminal result")?)
    .bind(request.digest().as_bytes().as_slice())
    .bind(request.object_key().as_str())
    .bind(conclusion_name(request.conclusion()))
    .bind(request.completed_at().get())
    .bind(request.committed_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if rows != 1 {
        return Err(StoreError::ImmutableConflict("terminal result"));
    }
    Ok(())
}

async fn conclude_terminal_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitRunnerTerminalResult,
    decision_at: UnixMillis,
) -> Result<(), StoreError> {
    let fence = request.request().session();
    let lifecycle = terminal_lifecycle(request.conclusion());
    let rows = sqlx::query(
        r"
        UPDATE job_attempts
        SET lifecycle = $8, lease_id = NULL, runner_id = NULL,
            lease_issued_at_ms = NULL, lease_expires_at_ms = NULL,
            runner_session_id = NULL, runner_session_epoch = NULL,
            runner_generation = NULL, runner_slot = NULL, changed_at_ms = $9
        WHERE id = $1 AND lease_id = $2 AND fencing_token = $3
          AND runner_id = $4 AND runner_session_id = $5
          AND runner_session_epoch = $6 AND runner_generation = $7
          AND lifecycle IN ('leased','preparing','running','cancelling','finalizing')
          AND runner_slot IS NOT NULL AND changed_at_ms <= $9
          AND lease_expires_at_ms > $9
        ",
    )
    .bind(request.attempt_id().as_uuid())
    .bind(request.guard().lease_id().as_uuid())
    .bind(fencing_i64(request.guard().fencing_token())?)
    .bind(fence.runner_id().as_uuid())
    .bind(fence.session_id().as_uuid())
    .bind(epoch_i64(fence.session_epoch())?)
    .bind(generation_i64(fence.runner_generation())?)
    .bind(lifecycle_name(lifecycle))
    .bind(decision_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if rows != 1 {
        return Err(StoreError::AttemptFenceRejected(request.attempt_id()));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DurableRunnerLogSafety {
    tenant_id: TenantId,
    secret_exposure: SecretExposureClass,
    raw_log_disposition: RawLogDisposition,
    requested_visibility: String,
    effective_visibility: String,
    reason: String,
    schema: i32,
}

#[derive(Debug)]
struct LockedRunnerLogAdmission {
    admission: RunnerLogAdmission,
    safety: DurableRunnerLogSafety,
}

async fn lock_runner_log_admission(
    transaction: &mut Transaction<'_, Postgres>,
    request: RunnerLogAdmissionRequest,
    slot: StableRunnerSlot,
    runner_tenant: &str,
) -> Result<LockedRunnerLogAdmission, StoreError> {
    let safety = load_runner_log_safety(transaction, request.attempt_id(), runner_tenant).await?;
    let admission = RunnerLogAdmission::new(
        request,
        safety.tenant_id.clone(),
        slot,
        safety.secret_exposure,
        safety.raw_log_disposition,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    lock_runner_log_position(transaction, &admission, &safety).await?;
    Ok(LockedRunnerLogAdmission { admission, safety })
}

async fn load_runner_log_safety(
    transaction: &mut Transaction<'_, Postgres>,
    attempt_id: AttemptId,
    runner_tenant: &str,
) -> Result<DurableRunnerLogSafety, StoreError> {
    let row = sqlx::query(
        r"
        SELECT repository.tenant_id, attempt.secret_exposure_class,
               attempt.raw_log_disposition, attempt.requested_log_visibility,
               attempt.effective_log_visibility, attempt.output_safety_reason,
               attempt.output_safety_schema
        FROM job_attempts AS attempt
        JOIN jobs AS job ON job.id = attempt.job_id
        JOIN workflow_runs AS run ON run.id = job.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        WHERE attempt.id = $1
        FOR KEY SHARE OF repository
        ",
    )
    .bind(attempt_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(StoreError::AttemptFenceRejected(attempt_id))?;
    decode_runner_log_safety(&row, runner_tenant)
}

fn decode_runner_log_safety(
    row: &sqlx::postgres::PgRow,
    runner_tenant: &str,
) -> Result<DurableRunnerLogSafety, StoreError> {
    let tenant_text: String = row.try_get("tenant_id").map_err(operation_error)?;
    if tenant_text != runner_tenant {
        return Err(StoreError::corrupt_data(
            "active attempt crosses the runner tenant boundary",
        ));
    }
    let secret_exposure = match row
        .try_get::<String, _>("secret_exposure_class")
        .map_err(operation_error)?
        .as_str()
    {
        "secretless" => SecretExposureClass::Secretless,
        "capability_only" => SecretExposureClass::CapabilityOnly,
        "readable_secret" => SecretExposureClass::ReadableSecret,
        _ => {
            return Err(StoreError::corrupt_data(
                "invalid runner log secret exposure",
            ));
        }
    };
    let raw_log_disposition = match row
        .try_get::<String, _>("raw_log_disposition")
        .map_err(operation_error)?
        .as_str()
    {
        "persist" => RawLogDisposition::Persist,
        _ => return Err(StoreError::corrupt_data("invalid raw log disposition")),
    };
    let requested_visibility: String = row
        .try_get("requested_log_visibility")
        .map_err(operation_error)?;
    let effective_visibility: String = row
        .try_get("effective_log_visibility")
        .map_err(operation_error)?;
    let reason: String = row
        .try_get("output_safety_reason")
        .map_err(operation_error)?;
    let schema: i32 = row
        .try_get("output_safety_schema")
        .map_err(operation_error)?;
    if !matches!(
        requested_visibility.as_str(),
        "private" | "authenticated" | "public"
    ) || !matches!(
        effective_visibility.as_str(),
        "private" | "authenticated" | "public"
    ) || !matches!(reason.as_str(), "repository_policy" | "secret_exposure")
        || !automata_ci_store::human_output_publication_safety_schema_is_current(schema)
    {
        return Err(StoreError::corrupt_data(
            "invalid runner log output-safety snapshot",
        ));
    }
    let tenant_id = TenantId::new(tenant_text)
        .map_err(|_| StoreError::corrupt_data("invalid runner log tenant identity"))?;
    let safety = DurableRunnerLogSafety {
        tenant_id,
        secret_exposure,
        raw_log_disposition,
        requested_visibility,
        effective_visibility,
        reason,
        schema,
    };
    if !runner_log_safety_is_consistent(&safety) {
        return Err(StoreError::corrupt_data(
            "inconsistent runner log output-safety snapshot",
        ));
    }
    Ok(safety)
}

fn runner_log_safety_is_consistent(safety: &DurableRunnerLogSafety) -> bool {
    let raw_policy_is_consistent =
        automata_ci_store::human_output_publication_safety_schema_is_current(safety.schema)
            && safety.raw_log_disposition == RawLogDisposition::Persist;
    raw_policy_is_consistent
        && matches!(
            (
                safety.requested_visibility.as_str(),
                safety.effective_visibility.as_str(),
            ),
            ("private", "private") | ("authenticated", "authenticated") | ("public", "public")
        )
        && safety.reason == "repository_policy"
}

#[cfg(test)]
mod runner_log_safety_tests {
    use super::*;

    #[test]
    fn runner_log_reader_rejects_noncurrent_publication_safety_schema() {
        let mut safety = DurableRunnerLogSafety {
            tenant_id: TenantId::new("tenant-1").expect("tenant ID"),
            secret_exposure: SecretExposureClass::Secretless,
            raw_log_disposition: RawLogDisposition::Persist,
            requested_visibility: "private".to_owned(),
            effective_visibility: "private".to_owned(),
            reason: "repository_policy".to_owned(),
            schema: automata_ci_store::HUMAN_OUTPUT_PUBLICATION_SAFETY_SCHEMA,
        };
        assert!(runner_log_safety_is_consistent(&safety));
        for schema in [0, 1, 3] {
            safety.schema = schema;
            assert!(!runner_log_safety_is_consistent(&safety));
        }
    }
}

async fn lock_runner_log_position(
    transaction: &mut Transaction<'_, Postgres>,
    admission: &RunnerLogAdmission,
    safety: &DurableRunnerLogSafety,
) -> Result<(), StoreError> {
    let request = admission.request();
    let stream = sqlx::query(
        r"
        SELECT attempt_id, runner_session_id, runner_id, runner_session_epoch,
               runner_generation, runner_slot, lease_id, fencing_token,
               log_schema, closed_at_ms, secret_exposure_class,
               raw_log_disposition, requested_visibility, effective_visibility,
               output_safety_reason, output_safety_schema
        FROM attempt_log_streams WHERE id = $1 FOR UPDATE
        ",
    )
    .bind(request.stream_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if let Some(row) = stream {
        if !runner_log_stream_matches(&row, admission, safety, true)? {
            return Err(StoreError::ImmutableConflict("log stream"));
        }
        let prior: Option<i64> = sqlx::query_scalar(
            "SELECT max(last_sequence) FROM attempt_log_segments WHERE stream_id = $1",
        )
        .bind(request.stream_id().as_uuid())
        .fetch_one(&mut **transaction)
        .await
        .map_err(operation_error)?;
        let expected = prior.map_or(0, |value| value.saturating_add(1));
        if log_sequence_i64(request.first_sequence())? != expected {
            return Err(StoreError::ImmutableConflict("log sequence"));
        }
    } else if request.first_sequence() != LogSequence::new(0) {
        return Err(StoreError::ImmutableConflict("log sequence"));
    }
    Ok(())
}

fn runner_log_stream_matches(
    row: &sqlx::postgres::PgRow,
    admission: &RunnerLogAdmission,
    safety: &DurableRunnerLogSafety,
    require_open: bool,
) -> Result<bool, StoreError> {
    let request = admission.request();
    let fence = request.request().session();
    Ok(row
        .try_get::<Uuid, _>("attempt_id")
        .map_err(operation_error)?
        == request.attempt_id().as_uuid()
        && row
            .try_get::<Uuid, _>("runner_session_id")
            .map_err(operation_error)?
            == fence.session_id().as_uuid()
        && row
            .try_get::<Uuid, _>("runner_id")
            .map_err(operation_error)?
            == fence.runner_id().as_uuid()
        && row
            .try_get::<i64, _>("runner_session_epoch")
            .map_err(operation_error)?
            == epoch_i64(fence.session_epoch())?
        && row
            .try_get::<i64, _>("runner_generation")
            .map_err(operation_error)?
            == generation_i64(fence.runner_generation())?
        && row
            .try_get::<i32, _>("runner_slot")
            .map_err(operation_error)?
            == i32::from(admission.slot().ordinal())
        && row
            .try_get::<Uuid, _>("lease_id")
            .map_err(operation_error)?
            == request.guard().lease_id().as_uuid()
        && row
            .try_get::<i64, _>("fencing_token")
            .map_err(operation_error)?
            == fencing_i64(request.guard().fencing_token())?
        && row
            .try_get::<i32, _>("log_schema")
            .map_err(operation_error)?
            == i32::from(request.schema().get())
        && (!require_open
            || row
                .try_get::<Option<i64>, _>("closed_at_ms")
                .map_err(operation_error)?
                .is_none())
        && row
            .try_get::<String, _>("secret_exposure_class")
            .map_err(operation_error)?
            == secret_exposure_name(safety.secret_exposure)
        && row
            .try_get::<String, _>("raw_log_disposition")
            .map_err(operation_error)?
            == raw_log_disposition_name(safety.raw_log_disposition)
        && row
            .try_get::<String, _>("requested_visibility")
            .map_err(operation_error)?
            == safety.requested_visibility
        && row
            .try_get::<String, _>("effective_visibility")
            .map_err(operation_error)?
            == safety.effective_visibility
        && row
            .try_get::<String, _>("output_safety_reason")
            .map_err(operation_error)?
            == safety.reason
        && row
            .try_get::<i32, _>("output_safety_schema")
            .map_err(operation_error)?
            == safety.schema)
}

const fn secret_exposure_name(value: SecretExposureClass) -> &'static str {
    match value {
        SecretExposureClass::Secretless => "secretless",
        SecretExposureClass::CapabilityOnly => "capability_only",
        SecretExposureClass::ReadableSecret => "readable_secret",
    }
}

const fn raw_log_disposition_name(value: RawLogDisposition) -> &'static str {
    match value {
        RawLogDisposition::Persist => "persist",
    }
}

async fn verify_replayed_runner_log_admission(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitRunnerLogSegment,
    runner_tenant: &str,
) -> Result<(), StoreError> {
    let safety = load_runner_log_safety(transaction, request.attempt_id(), runner_tenant).await?;
    let row = sqlx::query(
        r"
        SELECT stream.attempt_id, stream.runner_session_id, stream.runner_id,
               stream.runner_session_epoch, stream.runner_generation,
               stream.runner_slot, stream.lease_id, stream.fencing_token,
               stream.log_schema, stream.closed_at_ms,
               stream.secret_exposure_class, stream.raw_log_disposition,
               stream.requested_visibility, stream.effective_visibility,
               stream.output_safety_reason, stream.output_safety_schema,
               segment.first_sequence, segment.last_sequence,
               segment.object_key, segment.object_digest,
               segment.encoded_size_bytes, segment.uncompressed_size_bytes,
               segment.stored_at_ms, segment.end_of_stream
        FROM attempt_log_segments AS segment
        JOIN attempt_log_streams AS stream ON stream.id = segment.stream_id
        WHERE segment.stream_id = $1 AND segment.operation_id = $2
        FOR SHARE OF stream, segment
        ",
    )
    .bind(request.stream_id().as_uuid())
    .bind(request.request().operation_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(StoreError::ImmutableConflict("log segment replay"))?;
    let slot = u16::try_from(
        row.try_get::<i32, _>("runner_slot")
            .map_err(operation_error)?,
    )
    .ok()
    .and_then(|value| StableRunnerSlot::new(value).ok())
    .ok_or_else(|| StoreError::corrupt_data("invalid log-stream runner slot"))?;
    let durable_admission = RunnerLogAdmission::new(
        request.admission().request().clone(),
        safety.tenant_id.clone(),
        slot,
        safety.secret_exposure,
        safety.raw_log_disposition,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let digest = decode_sha256_digest(row.try_get("object_digest").map_err(operation_error)?)
        .map_err(|error| StoreError::corrupt_data(error.clone()))?;
    let exact = durable_admission == *request.admission()
        && runner_log_stream_matches(&row, &durable_admission, &safety, false)?
        && row
            .try_get::<i64, _>("first_sequence")
            .map_err(operation_error)?
            == log_sequence_i64(request.first_sequence())?
        && row
            .try_get::<i64, _>("last_sequence")
            .map_err(operation_error)?
            == log_sequence_i64(request.last_sequence())?
        && row
            .try_get::<String, _>("object_key")
            .map_err(operation_error)?
            == request.object_key().as_str()
        && digest == request.digest()
        && row
            .try_get::<i64, _>("encoded_size_bytes")
            .map_err(operation_error)?
            == size_i64(request.encoded_size(), "log segment")?
        && row
            .try_get::<i64, _>("uncompressed_size_bytes")
            .map_err(operation_error)?
            == size_i64(request.uncompressed_size(), "log segment")?
        && row
            .try_get::<i64, _>("stored_at_ms")
            .map_err(operation_error)?
            == request.stored_at().get()
        && row
            .try_get::<bool, _>("end_of_stream")
            .map_err(operation_error)?
            == request.is_end_of_stream();
    if !exact {
        return Err(StoreError::ImmutableConflict("log segment replay"));
    }
    Ok(())
}

async fn append_runner_log_segment(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitRunnerLogSegment,
    slot: StableRunnerSlot,
    safety: &DurableRunnerLogSafety,
) -> Result<(), StoreError> {
    ensure_runner_log_stream(transaction, request, slot, safety).await?;
    let prior: Option<i64> = sqlx::query_scalar(
        "SELECT max(last_sequence) FROM attempt_log_segments WHERE stream_id = $1",
    )
    .bind(request.stream_id().as_uuid())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let expected = prior.map_or(0, |value| value.saturating_add(1));
    if log_sequence_i64(request.first_sequence())? != expected {
        return Err(StoreError::ImmutableConflict("log sequence"));
    }
    sqlx::query(
        r"
        INSERT INTO attempt_log_segments (
            stream_id, operation_id, first_sequence, last_sequence, object_key,
            object_digest, encoded_size_bytes, uncompressed_size_bytes,
            stored_at_ms, end_of_stream
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        ",
    )
    .bind(request.stream_id().as_uuid())
    .bind(request.request().operation_id().as_uuid())
    .bind(log_sequence_i64(request.first_sequence())?)
    .bind(log_sequence_i64(request.last_sequence())?)
    .bind(request.object_key().as_str())
    .bind(request.digest().as_bytes().as_slice())
    .bind(size_i64(request.encoded_size(), "log segment")?)
    .bind(size_i64(request.uncompressed_size(), "log segment")?)
    .bind(request.stored_at().get())
    .bind(request.is_end_of_stream())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if request.is_end_of_stream() {
        sqlx::query("UPDATE attempt_log_streams SET closed_at_ms = $2 WHERE id = $1")
            .bind(request.stream_id().as_uuid())
            .bind(request.stored_at().get())
            .execute(&mut **transaction)
            .await
            .map_err(operation_error)?;
    }
    Ok(())
}

async fn ensure_runner_log_stream(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitRunnerLogSegment,
    slot: StableRunnerSlot,
    safety: &DurableRunnerLogSafety,
) -> Result<(), StoreError> {
    let fence = request.request().session();
    if slot != request.admission().slot() {
        return Err(StoreError::AttemptFenceRejected(request.attempt_id()));
    }
    let stream = sqlx::query(
        r"
        SELECT attempt_id, runner_session_id, runner_id, runner_session_epoch,
               runner_generation, runner_slot, lease_id, fencing_token,
               log_schema, closed_at_ms, secret_exposure_class,
               raw_log_disposition, requested_visibility, effective_visibility,
               output_safety_reason, output_safety_schema
        FROM attempt_log_streams WHERE id = $1 FOR UPDATE
        ",
    )
    .bind(request.stream_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if let Some(row) = stream {
        if !runner_log_stream_matches(&row, request.admission(), safety, true)? {
            return Err(StoreError::ImmutableConflict("log stream"));
        }
    } else {
        if request.first_sequence() != LogSequence::new(0) {
            return Err(StoreError::ImmutableConflict("log sequence"));
        }
        sqlx::query(
            r"
            INSERT INTO attempt_log_streams (
                id, attempt_id, runner_session_id, operation_id, runner_id,
                runner_session_epoch, runner_generation, runner_slot, lease_id,
                fencing_token, log_schema, opened_at_ms, secret_exposure_class,
                raw_log_disposition, requested_visibility, effective_visibility,
                output_safety_reason, output_safety_schema
            ) VALUES (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,
                $13,$14,$15,$16,$17,$18
            )
            ",
        )
        .bind(request.stream_id().as_uuid())
        .bind(request.attempt_id().as_uuid())
        .bind(fence.session_id().as_uuid())
        .bind(request.request().operation_id().as_uuid())
        .bind(fence.runner_id().as_uuid())
        .bind(epoch_i64(fence.session_epoch())?)
        .bind(generation_i64(fence.runner_generation())?)
        .bind(i32::from(slot.ordinal()))
        .bind(request.guard().lease_id().as_uuid())
        .bind(fencing_i64(request.guard().fencing_token())?)
        .bind(i32::from(request.schema().get()))
        .bind(request.stored_at().get())
        .bind(secret_exposure_name(safety.secret_exposure))
        .bind(raw_log_disposition_name(safety.raw_log_disposition))
        .bind(&safety.requested_visibility)
        .bind(&safety.effective_visibility)
        .bind(&safety.reason)
        .bind(safety.schema)
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    }
    Ok(())
}

const fn conclusion_name(conclusion: JobConclusion) -> &'static str {
    match conclusion {
        JobConclusion::Success => "success",
        JobConclusion::Failure => "failure",
        JobConclusion::Cancelled => "cancelled",
        JobConclusion::TimedOut => "timed_out",
        JobConclusion::Skipped => "skipped",
    }
}

const fn terminal_lifecycle(conclusion: JobConclusion) -> JobLifecycle {
    match conclusion {
        JobConclusion::Success => JobLifecycle::Succeeded,
        JobConclusion::Failure => JobLifecycle::Failed,
        JobConclusion::Cancelled => JobLifecycle::Cancelled,
        JobConclusion::TimedOut => JobLifecycle::TimedOut,
        JobConclusion::Skipped => JobLifecycle::Skipped,
    }
}

fn fencing_i64(value: FencingToken) -> Result<i64, StoreError> {
    i64::try_from(value.get())
        .map_err(|_| StoreError::corrupt_data("fencing token exceeds PostgreSQL BIGINT"))
}

fn log_sequence_i64(value: LogSequence) -> Result<i64, StoreError> {
    i64::try_from(value.get())
        .map_err(|_| StoreError::corrupt_data("log sequence exceeds PostgreSQL BIGINT"))
}

fn size_i64(value: u64, kind: &'static str) -> Result<i64, StoreError> {
    i64::try_from(value)
        .map_err(|_| StoreError::corrupt_data(format!("{kind} size exceeds PostgreSQL BIGINT")))
}

async fn enqueue_command_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    encryption: &RunnerPayloadEncryption,
    command: EnqueueRunnerCommand,
) -> Result<DurableRunnerCommand, StoreError> {
    lock_live_routing(transaction, command.session())
        .await?
        .require_online(command.session())?;
    enqueue_locked_command_in_transaction(transaction, encryption, command).await
}

/// Enqueues a cancellation against the exact session recorded on an active
/// attempt, including a session that disconnected after receiving the lease.
/// The caller must hold the attempt's concurrency lock before entering this
/// function, preserving the global group -> session -> attempt lock order.
pub(super) async fn enqueue_cancellation_command_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    encryption: &RunnerPayloadEncryption,
    command: EnqueueRunnerCommand,
) -> Result<DurableRunnerCommand, StoreError> {
    let session = command.session();
    let disconnected_at = lock_exact_command_session(transaction, session).await?;
    let durable = enqueue_locked_command_in_transaction(transaction, encryption, command).await?;
    if let Some(disconnected_at) = disconnected_at {
        let reason = disconnected_session_tombstone_reason(transaction, session).await?;
        let tombstoned_at = disconnected_at.max(durable.request().created_at());
        tombstone_exact_command_payload(
            transaction,
            session.session_id(),
            durable.sequence(),
            reason,
            tombstoned_at,
        )
        .await?;
    }
    Ok(durable)
}

async fn lock_exact_command_session(
    transaction: &mut Transaction<'_, Postgres>,
    session: RunnerSessionFence,
) -> Result<Option<UnixMillis>, StoreError> {
    let disconnected_at = sqlx::query_scalar::<_, Option<i64>>(
        r"
        SELECT disconnected_at_ms
        FROM runner_sessions
        WHERE id = $1 AND runner_id = $2
          AND runner_generation = $3 AND session_epoch = $4
        FOR UPDATE
        ",
    )
    .bind(session.session_id().as_uuid())
    .bind(session.runner_id().as_uuid())
    .bind(generation_i64(session.runner_generation())?)
    .bind(epoch_i64(session.session_epoch())?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or_else(|| StoreError::SessionFenceRejected(session.session_id()))?;
    Ok(disconnected_at.map(UnixMillis::new))
}

async fn disconnected_session_tombstone_reason(
    transaction: &mut Transaction<'_, Postgres>,
    session: RunnerSessionFence,
) -> Result<RunnerPayloadTombstoneReason, StoreError> {
    let row = sqlx::query("SELECT generation, session_epoch FROM runners WHERE id = $1")
        .bind(session.runner_id().as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?
        .ok_or(StoreError::RunnerNotFound(session.runner_id()))?;
    let generation = decode_generation(row.try_get("generation").map_err(operation_error)?)?;
    let epoch = decode_epoch(row.try_get("session_epoch").map_err(operation_error)?)?;
    Ok(
        if generation == session.runner_generation() && epoch == session.session_epoch() {
            RunnerPayloadTombstoneReason::SessionClosed
        } else {
            RunnerPayloadTombstoneReason::SessionSuperseded
        },
    )
}

async fn enqueue_locked_command_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    encryption: &RunnerPayloadEncryption,
    command: EnqueueRunnerCommand,
) -> Result<DurableRunnerCommand, StoreError> {
    let existing = sqlx::query(
        r"
        SELECT tenant_id, runner_session_id AS command_runner_session_id,
               command_sequence, operation_id AS command_operation_id,
               runner_id AS command_runner_id,
               runner_session_epoch AS command_runner_session_epoch,
               runner_generation AS command_runner_generation,
               command_kind, command_schema, command_digest,
               command_plaintext_size_bytes,
               envelope_schema, wrapping_key_id, wrapped_data_key, nonce,
               ciphertext, payload_tombstone_reason,
               payload_tombstoned_at_ms,
               created_at_ms AS command_created_at_ms
        FROM runner_command_outbox
        WHERE runner_session_id = $1 AND operation_id = $2
        FOR UPDATE
        ",
    )
    .bind(command.session().session_id().as_uuid())
    .bind(command.operation_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if let Some(row) = existing {
        if let Some(tombstone) = decode_runner_payload_tombstone(&row)? {
            let stored = RunnerCommandEnvelopeMetadata::from_row(&row)?;
            let expected_size = i64::try_from(command.payload().bytes().len()).map_err(|_| {
                StoreError::corrupt_data("runner command size exceeds PostgreSQL BIGINT")
            })?;
            let expected = RunnerCommandEnvelopeMetadata::from_command(
                &command,
                stored.sequence()?,
                expected_size,
            )?;
            if stored != expected {
                return Err(StoreError::OperationConflict {
                    session_id: command.session().session_id(),
                    operation_id: command.operation_id(),
                });
            }
            return Err(StoreError::RunnerPayloadUnavailable {
                session_id: command.session().session_id(),
                tombstone,
            });
        }
        let durable = decode_outbox_command(encryption, &row, command.session(), true).await?;
        if durable.request() != &command {
            return Err(StoreError::OperationConflict {
                session_id: command.session().session_id(),
                operation_id: command.operation_id(),
            });
        }
        return Ok(durable);
    }
    let sequence_value: Option<i64> = sqlx::query_scalar(
        r"
        UPDATE runner_sessions
        SET last_command_sequence = last_command_sequence + 1
        WHERE id = $1 AND runner_id = $2
          AND runner_generation = $3 AND session_epoch = $4
          AND last_command_sequence < 9223372036854775807
        RETURNING last_command_sequence
        ",
    )
    .bind(command.session().session_id().as_uuid())
    .bind(command.session().runner_id().as_uuid())
    .bind(generation_i64(command.session().runner_generation())?)
    .bind(epoch_i64(command.session().session_epoch())?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let sequence_value = sequence_value.ok_or(StoreError::CommandSequenceExhausted(
        command.session().session_id(),
    ))?;
    let sequence = decode_sequence(sequence_value)?;
    let tenant_id = runner_payload_tenant(transaction, command.session()).await?;
    let plaintext_size_bytes = i64::try_from(command.payload().bytes().len())
        .map_err(|_| StoreError::corrupt_data("runner command size exceeds PostgreSQL BIGINT"))?;
    let metadata =
        RunnerCommandEnvelopeMetadata::from_command(&command, sequence, plaintext_size_bytes)?;
    let envelope = seal_runner_payload(
        encryption,
        &tenant_id,
        &encryption.command_purpose,
        metadata.record_id(),
        command.payload().bytes(),
    )
    .await?;
    if envelope.plaintext_size_bytes != metadata.plaintext_size_bytes {
        return Err(StoreError::corrupt_data(
            "sealed runner command size changed unexpectedly",
        ));
    }
    insert_encrypted_command_row(transaction, &metadata, &tenant_id, &envelope).await?;
    Ok(DurableRunnerCommand::new(command, sequence, false))
}

async fn insert_encrypted_command_row(
    transaction: &mut Transaction<'_, Postgres>,
    metadata: &RunnerCommandEnvelopeMetadata,
    tenant_id: &str,
    envelope: &RunnerPayloadEnvelopeParameters,
) -> Result<(), StoreError> {
    sqlx::query(
        r"
        INSERT INTO runner_command_outbox (
            runner_session_id, command_sequence, operation_id, runner_id,
            runner_session_epoch, runner_generation, command_kind,
            command_schema, command_digest, tenant_id,
            command_plaintext_size_bytes, envelope_schema, wrapping_key_id,
            wrapped_data_key, nonce, ciphertext, created_at_ms
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
            $14, $15, $16, $17
        )
        ",
    )
    .bind(metadata.session_id)
    .bind(metadata.sequence)
    .bind(metadata.operation_id)
    .bind(metadata.runner_id)
    .bind(metadata.session_epoch)
    .bind(metadata.runner_generation)
    .bind(&metadata.kind)
    .bind(metadata.schema)
    .bind(metadata.digest.as_bytes().as_slice())
    .bind(tenant_id)
    .bind(metadata.plaintext_size_bytes)
    .bind(envelope.schema)
    .bind(&envelope.wrapping_key_id)
    .bind(&envelope.wrapped_data_key)
    .bind(&envelope.nonce)
    .bind(&envelope.ciphertext)
    .bind(metadata.created_at_ms)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn lock_replay_command_row(
    transaction: &mut Transaction<'_, Postgres>,
    session: RunnerSessionFence,
    sequence: CommandSequence,
) -> Result<Option<sqlx::postgres::PgRow>, StoreError> {
    sqlx::query(
        r"
        SELECT tenant_id,
               runner_session_id AS command_runner_session_id,
               command_sequence, operation_id AS command_operation_id,
               runner_id AS command_runner_id,
               runner_session_epoch AS command_runner_session_epoch,
               runner_generation AS command_runner_generation,
               command_kind, command_schema, command_digest,
               command_plaintext_size_bytes, envelope_schema,
               wrapping_key_id, wrapped_data_key, nonce, ciphertext,
               payload_tombstone_reason, payload_tombstoned_at_ms,
               created_at_ms AS command_created_at_ms
        FROM runner_command_outbox
        WHERE runner_session_id = $1
          AND command_sequence = $2
        FOR UPDATE
        ",
    )
    .bind(session.session_id().as_uuid())
    .bind(sequence_i64(sequence)?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn select_replay_candidate_sequences(
    transaction: &mut Transaction<'_, Postgres>,
    session: RunnerSessionFence,
    scan_after: i64,
) -> Result<Vec<i64>, StoreError> {
    sqlx::query_scalar(
        r"
        SELECT command.command_sequence
        FROM runner_command_outbox AS command
        WHERE command.runner_session_id = $1
          AND command.payload_tombstone_reason IS NULL
          AND command.command_sequence > $2
          AND NOT EXISTS (
              SELECT 1
              FROM runner_lease_offer_publications AS publication
              WHERE publication.runner_session_id = command.runner_session_id
                AND publication.command_sequence = command.command_sequence
                AND publication.delivery_revoked_at_ms IS NOT NULL
          )
        ORDER BY command.command_sequence
        LIMIT $3
        ",
    )
    .bind(session.session_id().as_uuid())
    .bind(scan_after)
    .bind(i64::from(MAX_COMMAND_REPLAY_LIMIT))
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn inspect_replay_candidates(
    transaction: &mut Transaction<'_, Postgres>,
    encryption: &RunnerPayloadEncryption,
    session: RunnerSessionFence,
    limit: CommandReplayLimit,
    sequences: Vec<i64>,
) -> Result<CommandReplayPage, StoreError> {
    let mut commands = Vec::with_capacity(usize::from(limit.get()));
    let mut replay_bytes = 0_usize;
    let candidate_count = sequences.len();
    let candidate_ceiling_reached = candidate_count == usize::from(MAX_COMMAND_REPLAY_LIMIT);
    let mut disposition = if candidate_ceiling_reached {
        CommandReplayDisposition::Saturated
    } else {
        CommandReplayDisposition::Exhausted
    };
    let mut wrote_revocation = false;
    for (index, raw_sequence) in sequences.into_iter().enumerate() {
        let sequence = decode_sequence(raw_sequence)?;
        let row = lock_replay_command_row(transaction, session, sequence)
            .await?
            .ok_or_else(|| {
                StoreError::corrupt_data("pending runner command disappeared during replay")
            })?;
        let metadata = RunnerCommandEnvelopeMetadata::from_row(&row)?;
        if metadata.fence()? != session || metadata.sequence()? != sequence {
            return Err(StoreError::corrupt_data(
                "runner replay locked a different command identity",
            ));
        }
        let publication = lock_replay_publication_evidence(transaction, &metadata).await?;
        if let Some(publication) = publication {
            let database_now = super::runner_attempt_database_now(transaction).await?;
            if let LockedLeaseOfferDeliveryStatus::Revoked(revocation) =
                publication.classify(&metadata, database_now)?
            {
                wrote_revocation |= !revocation.persisted;
                mark_replay_publication_revoked(transaction, &metadata, publication, revocation)
                    .await?;
                continue;
            }
        }
        if wrote_revocation {
            // Commit every monotonic marker discovered in this transaction before
            // opening an unrelated later command. Otherwise a dependency or
            // corruption failure while opening that command would roll back the
            // stale-prefix progress and poison every retry from the same cursor.
            disposition = CommandReplayDisposition::Saturated;
            break;
        }
        let payload_size = metadata.plaintext_size()?;
        let Some(next_replay_bytes) = replay_bytes.checked_add(payload_size) else {
            return Err(StoreError::corrupt_data(
                "runner command replay byte count overflowed",
            ));
        };
        if next_replay_bytes > MAX_COMMAND_REPLAY_BYTES {
            disposition = CommandReplayDisposition::Saturated;
            break;
        }
        let command = decode_outbox_command(encryption, &row, session, true).await?;
        if let Some(publication) = publication {
            let database_now = super::runner_attempt_database_now(transaction).await?;
            if let LockedLeaseOfferDeliveryStatus::Revoked(revocation) =
                publication.classify(&metadata, database_now)?
            {
                wrote_revocation |= !revocation.persisted;
                mark_replay_publication_revoked(transaction, &metadata, publication, revocation)
                    .await?;
                continue;
            }
        }
        replay_bytes = next_replay_bytes;
        commands.push(command);
        if commands.len() == usize::from(limit.get()) {
            if index + 1 < candidate_count || candidate_ceiling_reached {
                disposition = CommandReplayDisposition::Saturated;
            }
            break;
        }
    }
    Ok(CommandReplayPage::new(commands, disposition))
}

#[derive(Clone, Copy, Debug)]
struct LockedReplayPublicationEvidence {
    request_operation_id: Uuid,
    attempt_id: AttemptId,
    runner_id: Uuid,
    runner_session_epoch: i64,
    runner_generation: i64,
    request_kind_is_lease_request: bool,
    created_at: UnixMillis,
    offer_valid_until: UnixMillis,
    delivery_revoked_at: Option<UnixMillis>,
    delivery_revocation_reason: Option<LeaseOfferDeliveryRevocationReason>,
    exact_active_attempt: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LeaseOfferDeliveryRevocationReason {
    AttemptSuperseded,
    AuthorityExpired,
}

impl LeaseOfferDeliveryRevocationReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AttemptSuperseded => "attempt_superseded",
            Self::AuthorityExpired => "authority_expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LeaseOfferDeliveryRevocation {
    reason: LeaseOfferDeliveryRevocationReason,
    observed_at: UnixMillis,
    persisted: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LockedLeaseOfferDeliveryStatus {
    Live,
    Revoked(LeaseOfferDeliveryRevocation),
}

impl LockedReplayPublicationEvidence {
    fn classify(
        self,
        command: &RunnerCommandEnvelopeMetadata,
        database_now: UnixMillis,
    ) -> Result<LockedLeaseOfferDeliveryStatus, StoreError> {
        if self.runner_id != command.runner_id
            || self.runner_session_epoch != command.session_epoch
            || self.runner_generation != command.runner_generation
        {
            return Err(StoreError::corrupt_data(
                "lease-offer publication has a mismatched command fence",
            ));
        }
        if !self.request_kind_is_lease_request || !is_lease_offer_command_kind(&command.kind) {
            return Err(StoreError::corrupt_data(
                "lease-offer publication has mismatched command authority metadata",
            ));
        }
        if self.created_at.get() != command.created_at_ms
            || self.offer_valid_until <= self.created_at
        {
            return Err(StoreError::corrupt_data(
                "lease-offer publication has invalid command-time evidence",
            ));
        }
        match (self.delivery_revoked_at, self.delivery_revocation_reason) {
            (Some(observed_at), Some(reason)) => {
                if observed_at < self.created_at
                    || (reason == LeaseOfferDeliveryRevocationReason::AuthorityExpired
                        && observed_at < self.offer_valid_until)
                {
                    return Err(StoreError::corrupt_data(
                        "lease-offer publication has invalid delivery revocation evidence",
                    ));
                }
                return Ok(LockedLeaseOfferDeliveryStatus::Revoked(
                    LeaseOfferDeliveryRevocation {
                        reason,
                        observed_at,
                        persisted: true,
                    },
                ));
            }
            (None, None) => {}
            _ => {
                return Err(StoreError::corrupt_data(
                    "lease-offer publication has partial delivery revocation evidence",
                ));
            }
        }
        if database_now < self.created_at {
            return Err(StoreError::corrupt_data(
                "lease-offer publication was observed before its creation time",
            ));
        }
        if !self.exact_active_attempt {
            return Ok(LockedLeaseOfferDeliveryStatus::Revoked(
                LeaseOfferDeliveryRevocation {
                    reason: LeaseOfferDeliveryRevocationReason::AttemptSuperseded,
                    observed_at: database_now,
                    persisted: false,
                },
            ));
        }
        if database_now >= self.offer_valid_until {
            return Ok(LockedLeaseOfferDeliveryStatus::Revoked(
                LeaseOfferDeliveryRevocation {
                    reason: LeaseOfferDeliveryRevocationReason::AuthorityExpired,
                    observed_at: database_now,
                    persisted: false,
                },
            ));
        }
        Ok(LockedLeaseOfferDeliveryStatus::Live)
    }
}

async fn lock_replay_publication_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    command: &RunnerCommandEnvelopeMetadata,
) -> Result<Option<LockedReplayPublicationEvidence>, StoreError> {
    let rows = sqlx::query(
        r"
        SELECT publication.request_operation_id, publication.attempt_id,
               publication.runner_id,
               publication.runner_session_epoch,
               publication.runner_generation,
               publication.operation_kind = 'automata.runner.lease-request.v1'
                   AS request_kind_is_lease_request,
               publication.created_at_ms,
               publication.offer_valid_until_ms,
               publication.delivery_revoked_at_ms,
               publication.delivery_revocation_reason,
               COALESCE(
                   attempt.lifecycle IN (
                       'leased', 'preparing', 'running', 'cancelling', 'finalizing'
                   )
                   AND attempt.job_id = publication.job_id
                   AND attempt.runner_id = publication.runner_id
                   AND attempt.runner_session_id = publication.runner_session_id
                   AND attempt.runner_session_epoch = publication.runner_session_epoch
                   AND attempt.runner_generation = publication.runner_generation
                   AND attempt.runner_slot = publication.runner_slot
                   AND attempt.lease_id = publication.lease_id
                   AND attempt.fencing_token = publication.fencing_token
                   AND attempt.lease_issued_at_ms = publication.lease_issued_at_ms
                   AND attempt.lease_expires_at_ms >= publication.lease_expires_at_ms,
                   FALSE
               ) AS exact_active_attempt
        FROM runner_lease_offer_publications AS publication
        JOIN job_attempts AS attempt ON attempt.id = publication.attempt_id
        WHERE publication.runner_session_id = $1
          AND publication.command_sequence = $2
        ORDER BY publication.request_operation_id
        LIMIT 2
        FOR UPDATE OF publication, attempt
        ",
    )
    .bind(command.session_id)
    .bind(command.sequence)
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let [row] = rows.as_slice() else {
        return if rows.is_empty() {
            Ok(None)
        } else {
            Err(StoreError::corrupt_data(
                "multiple lease-offer publications reference one command",
            ))
        };
    };
    let delivery_revoked_at = row
        .try_get::<Option<i64>, _>("delivery_revoked_at_ms")
        .map_err(operation_error)?
        .map(UnixMillis::new);
    let delivery_revocation_reason = row
        .try_get::<Option<String>, _>("delivery_revocation_reason")
        .map_err(operation_error)?
        .as_deref()
        .map(decode_lease_offer_delivery_revocation_reason)
        .transpose()?;
    Ok(Some(LockedReplayPublicationEvidence {
        request_operation_id: row
            .try_get("request_operation_id")
            .map_err(operation_error)?,
        attempt_id: AttemptId::from_uuid(row.try_get("attempt_id").map_err(operation_error)?),
        runner_id: row.try_get("runner_id").map_err(operation_error)?,
        runner_session_epoch: row
            .try_get("runner_session_epoch")
            .map_err(operation_error)?,
        runner_generation: row.try_get("runner_generation").map_err(operation_error)?,
        request_kind_is_lease_request: row
            .try_get("request_kind_is_lease_request")
            .map_err(operation_error)?,
        created_at: UnixMillis::new(row.try_get("created_at_ms").map_err(operation_error)?),
        offer_valid_until: UnixMillis::new(
            row.try_get("offer_valid_until_ms")
                .map_err(operation_error)?,
        ),
        delivery_revoked_at,
        delivery_revocation_reason,
        exact_active_attempt: row
            .try_get("exact_active_attempt")
            .map_err(operation_error)?,
    }))
}

#[derive(Debug)]
struct LockedLeaseOfferCommandDelivery {
    command: RunnerCommandEnvelopeMetadata,
    publication: LockedReplayPublicationEvidence,
    status: LockedLeaseOfferDeliveryStatus,
}

async fn lock_lease_offer_command_delivery(
    transaction: &mut Transaction<'_, Postgres>,
    session: RunnerSessionFence,
    sequence: CommandSequence,
    expected_command_operation_id: Option<OperationId>,
    expected_request_operation_id: Option<OperationId>,
) -> Result<Option<LockedLeaseOfferCommandDelivery>, StoreError> {
    let Some(row) = lock_replay_command_row(transaction, session, sequence).await? else {
        return Ok(None);
    };
    let command = RunnerCommandEnvelopeMetadata::from_row(&row)?;
    if command.fence()? != session || command.sequence()? != sequence {
        return Err(StoreError::corrupt_data(
            "lease-offer delivery preflight locked a different command identity",
        ));
    }
    if expected_command_operation_id
        .is_some_and(|expected| expected.as_uuid() != command.operation_id)
    {
        return Err(StoreError::corrupt_data(
            "lease-offer publication resolved a different command identity",
        ));
    }
    let Some(publication) = lock_replay_publication_evidence(transaction, &command).await? else {
        return Ok(None);
    };
    if expected_request_operation_id
        .is_some_and(|expected| expected.as_uuid() != publication.request_operation_id)
    {
        return Err(StoreError::corrupt_data(
            "lease-request receipt resolved a different offer publication",
        ));
    }
    let database_now = super::runner_attempt_database_now(transaction).await?;
    let status = publication.classify(&command, database_now)?;
    Ok(Some(LockedLeaseOfferCommandDelivery {
        command,
        publication,
        status,
    }))
}

async fn mark_replay_publication_revoked(
    transaction: &mut Transaction<'_, Postgres>,
    command: &RunnerCommandEnvelopeMetadata,
    publication: LockedReplayPublicationEvidence,
    revocation: LeaseOfferDeliveryRevocation,
) -> Result<(), StoreError> {
    if revocation.persisted {
        return Ok(());
    }
    let updated = sqlx::query(
        r"
        UPDATE runner_lease_offer_publications
        SET delivery_revoked_at_ms = $4,
            delivery_revocation_reason = $5
        WHERE runner_session_id = $1
          AND request_operation_id = $2
          AND command_sequence = $3
          AND delivery_revoked_at_ms IS NULL
          AND delivery_revocation_reason IS NULL
        ",
    )
    .bind(command.session_id)
    .bind(publication.request_operation_id)
    .bind(command.sequence)
    .bind(revocation.observed_at.get())
    .bind(revocation.reason.as_str())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if updated.rows_affected() != 1 {
        return Err(StoreError::corrupt_data(
            "lease-offer replay revocation lost its exact publication",
        ));
    }
    Ok(())
}

async fn decode_outbox_command(
    encryption: &RunnerPayloadEncryption,
    row: &sqlx::postgres::PgRow,
    session: RunnerSessionFence,
    replayed: bool,
) -> Result<DurableRunnerCommand, StoreError> {
    let metadata = RunnerCommandEnvelopeMetadata::from_row(row)?;
    let sequence = metadata.sequence()?;
    if let Some(tombstone) = decode_runner_payload_tombstone(row)? {
        return Err(StoreError::RunnerPayloadUnavailable {
            session_id: session.session_id(),
            tombstone,
        });
    }
    let bytes = open_runner_payload(
        encryption,
        row,
        metadata.plaintext_size()?,
        &encryption.command_purpose,
        metadata.record_id(),
    )
    .await?;
    if metadata.fence()? != session {
        return Err(StoreError::corrupt_data(
            "runner command has a mismatched session fence",
        ));
    }
    let operation_id = OperationId::from_uuid(metadata.operation_id);
    let kind = RunnerOperationKind::new(metadata.kind)
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let schema = decode_schema(metadata.schema)?;
    let payload = RunnerCommandPayload::new(schema, bytes)
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    if metadata.digest != payload.digest() {
        return Err(StoreError::corrupt_data("runner command digest mismatch"));
    }
    let created_at = UnixMillis::new(metadata.created_at_ms);
    Ok(DurableRunnerCommand::new(
        EnqueueRunnerCommand::new(session, operation_id, kind, payload, created_at),
        sequence,
        replayed,
    ))
}

async fn runner_payload_tenant(
    transaction: &mut Transaction<'_, Postgres>,
    session: RunnerSessionFence,
) -> Result<String, StoreError> {
    sqlx::query_scalar(
        r"
        SELECT runner.tenant_id
        FROM runner_sessions AS session
        JOIN runners AS runner ON runner.id = session.runner_id
        WHERE session.id = $1 AND session.runner_id = $2
          AND session.runner_generation = $3 AND session.session_epoch = $4
        ",
    )
    .bind(session.session_id().as_uuid())
    .bind(session.runner_id().as_uuid())
    .bind(generation_i64(session.runner_generation())?)
    .bind(epoch_i64(session.session_epoch())?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or_else(|| StoreError::SessionFenceRejected(session.session_id()))
}

#[derive(Clone, Copy, Debug)]
struct ReceiptLeaseOfferBinding {
    request_operation_id: OperationId,
    sequence: CommandSequence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiptLeaseOfferResponseDisposition {
    Primary,
    RevokedFallback,
}

impl ReceiptLeaseOfferResponseDisposition {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::RevokedFallback => "revoked_fallback",
        }
    }

    fn decode(value: &str) -> Result<Self, StoreError> {
        match value {
            "primary" => Ok(Self::Primary),
            "revoked_fallback" => Ok(Self::RevokedFallback),
            _ => Err(StoreError::corrupt_data(
                "runner RPC receipt has an invalid lease-offer response disposition",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ReceiptLeaseOfferCompletion {
    binding: ReceiptLeaseOfferBinding,
    disposition: ReceiptLeaseOfferResponseDisposition,
    primary_response_schema: DocumentSchema,
    primary_response_digest: Sha256Digest,
    fallback: RevokedLeaseOfferFallback,
}

impl ReceiptLeaseOfferCompletion {
    fn new(
        binding: ReceiptLeaseOfferBinding,
        disposition: ReceiptLeaseOfferResponseDisposition,
        primary_response: &RunnerOperationResponse,
        fallback: RevokedLeaseOfferFallback,
    ) -> Self {
        Self {
            binding,
            disposition,
            primary_response_schema: primary_response.schema(),
            primary_response_digest: primary_response.digest(),
            fallback,
        }
    }

    fn validate_actual_response(
        self,
        response: &RunnerResponseEnvelopeMetadata,
    ) -> Result<(), StoreError> {
        let expected = match self.disposition {
            ReceiptLeaseOfferResponseDisposition::Primary => {
                (self.primary_response_schema, self.primary_response_digest)
            }
            ReceiptLeaseOfferResponseDisposition::RevokedFallback => (
                self.fallback.response_schema(),
                self.fallback.response_digest(),
            ),
        };
        if i32::from(expected.0.get()) != response.response_schema
            || expected.1 != response.response_digest
        {
            return Err(StoreError::corrupt_data(
                "runner RPC receipt lease-offer disposition mismatches its stored response",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
enum ReceiptOfferExpectation {
    Any,
    Exact(Option<LeaseOfferCommandIdentity>),
}

enum LoadedGenericReceipt {
    Live {
        receipt: RunnerOperationReceipt,
        lease_offer_fallback: Option<RevokedLeaseOfferFallback>,
    },
    RevokedLeaseOffer {
        operation_id: OperationId,
        attempt_id: AttemptId,
        primary_response_schema: DocumentSchema,
        primary_response_digest: Sha256Digest,
        fallback: RevokedLeaseOfferFallback,
    },
}

impl LoadedGenericReceipt {
    fn into_live(self) -> Result<RunnerOperationReceipt, StoreError> {
        match self {
            Self::Live { receipt, .. } => Ok(receipt),
            Self::RevokedLeaseOffer { attempt_id, .. } => {
                Err(StoreError::AttemptFenceRejected(attempt_id))
            }
        }
    }
}

async fn classify_bound_receipt_before_decrypt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RunnerOperationRequest,
    completion: ReceiptLeaseOfferCompletion,
    expectation: ReceiptOfferExpectation,
) -> Result<Option<LoadedGenericReceipt>, StoreError> {
    let expected_command_operation_id = match expectation {
        ReceiptOfferExpectation::Exact(Some(expected)) => {
            if expected.session() != request.session()
                || expected.sequence() != completion.binding.sequence
            {
                return Err(StoreError::corrupt_data(
                    "lease-request receipt resolved a different lease-offer command identity",
                ));
            }
            Some(expected.operation_id())
        }
        ReceiptOfferExpectation::Any | ReceiptOfferExpectation::Exact(None) => None,
    };
    let Some(delivery) = lock_lease_offer_command_delivery(
        transaction,
        request.session(),
        completion.binding.sequence,
        expected_command_operation_id,
        Some(completion.binding.request_operation_id),
    )
    .await?
    else {
        return Ok(None);
    };
    let LockedLeaseOfferDeliveryStatus::Revoked(revocation) = delivery.status else {
        return Ok(None);
    };
    mark_replay_publication_revoked(
        transaction,
        &delivery.command,
        delivery.publication,
        revocation,
    )
    .await?;
    Ok(Some(LoadedGenericReceipt::RevokedLeaseOffer {
        operation_id: OperationId::from_uuid(delivery.command.operation_id),
        attempt_id: delivery.publication.attempt_id,
        primary_response_schema: completion.primary_response_schema,
        primary_response_digest: completion.primary_response_digest,
        fallback: completion.fallback,
    }))
}

#[allow(
    clippy::too_many_lines,
    reason = "keep receipt identity, publication locks, pre-KMS revocation, and post-KMS revalidation in one auditable flow"
)]
async fn load_generic_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    encryption: &RunnerPayloadEncryption,
    request: &RunnerOperationRequest,
    replayed: bool,
    expectation: ReceiptOfferExpectation,
) -> Result<Option<LoadedGenericReceipt>, StoreError> {
    let row = sqlx::query(
        r"
        SELECT tenant_id,
               runner_session_id AS response_runner_session_id,
               operation_id AS response_operation_id,
               runner_id AS response_runner_id,
               runner_session_epoch AS response_runner_session_epoch,
               runner_generation AS response_runner_generation,
               operation_kind AS response_operation_kind,
               request_digest AS response_request_digest, response_schema,
               response_digest, response_plaintext_size_bytes,
               envelope_schema, wrapping_key_id, wrapped_data_key, nonce,
               ciphertext, payload_tombstone_reason,
               payload_tombstoned_at_ms,
               committed_at_ms AS response_committed_at_ms,
               lease_offer_request_operation_id,
               lease_offer_command_sequence,
               lease_offer_response_disposition,
               lease_offer_primary_response_schema,
               lease_offer_primary_response_digest,
               lease_offer_fallback_version,
               lease_offer_fallback_operation_id,
               lease_offer_fallback_retry_after_millis,
               lease_offer_fallback_response_schema,
               lease_offer_fallback_response_digest
        FROM runner_rpc_receipts
        WHERE runner_session_id = $1 AND operation_id = $2
        FOR UPDATE
        ",
    )
    .bind(request.session().session_id().as_uuid())
    .bind(request.operation_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(row) = row.as_ref() else {
        return Ok(None);
    };
    let response_metadata = RunnerResponseEnvelopeMetadata::from_row(row)?;
    validate_response_receipt_request(&response_metadata, request)?;
    let lease_offer_completion = decode_receipt_lease_offer_completion(row)?;
    if let Some(completion) = lease_offer_completion {
        completion.validate_actual_response(&response_metadata)?;
    }
    let binding = lease_offer_completion.map(|completion| completion.binding);
    if binding.is_some_and(|binding| binding.request_operation_id != request.operation_id()) {
        return Err(StoreError::corrupt_data(
            "runner RPC receipt binds a different lease-request publication",
        ));
    }
    let binding_matches = match expectation {
        ReceiptOfferExpectation::Any => true,
        ReceiptOfferExpectation::Exact(None) => binding.is_none(),
        ReceiptOfferExpectation::Exact(Some(_)) => binding.is_some(),
    };
    if !binding_matches {
        return Err(StoreError::corrupt_data(
            "runner RPC receipt has a mismatched lease-offer binding",
        ));
    }
    let publication = if let Some(completion) = lease_offer_completion {
        if let Some(revoked) =
            classify_bound_receipt_before_decrypt(transaction, request, completion, expectation)
                .await?
        {
            return Ok(Some(revoked));
        }
        if completion.disposition != ReceiptLeaseOfferResponseDisposition::Primary {
            return Err(StoreError::corrupt_data(
                "live lease-offer publication has a revoked-fallback receipt disposition",
            ));
        }
        let publication = load_lease_offer_publication_by_receipt_binding(
            transaction,
            encryption,
            request.session(),
            completion.binding,
        )
        .await?
        .ok_or_else(|| {
            StoreError::corrupt_data("lease-request receipt lost its offer publication")
        })?;
        if publication.request() != request
            || !is_lease_offer_command_kind(publication.command().request().kind().as_str())
            || matches!(expectation,
                ReceiptOfferExpectation::Exact(Some(expected))
                if expected.session() != publication.command().request().session()
                    || expected.operation_id()
                        != publication.command().request().operation_id()
                    || expected.sequence() != publication.command().sequence())
        {
            return Err(StoreError::corrupt_data(
                "lease-request receipt resolved a mismatched offer publication",
            ));
        }
        if let LockedLeaseOfferDeliveryStatus::Revoked(revocation) =
            classify_locked_published_lease_offer(transaction, &publication).await?
        {
            mark_published_lease_offer_revoked(transaction, &publication, revocation).await?;
            return Ok(Some(LoadedGenericReceipt::RevokedLeaseOffer {
                operation_id: publication.command().request().operation_id(),
                attempt_id: publication.lease().attempt_id(),
                primary_response_schema: completion.primary_response_schema,
                primary_response_digest: completion.primary_response_digest,
                fallback: completion.fallback,
            }));
        }
        Some(publication)
    } else {
        None
    };
    let receipt = decode_generic_receipt(encryption, row, request, replayed).await?;
    if let Some(publication) = publication.as_ref()
        && let LockedLeaseOfferDeliveryStatus::Revoked(revocation) =
            classify_locked_published_lease_offer(transaction, publication).await?
    {
        mark_published_lease_offer_revoked(transaction, publication, revocation).await?;
        let completion = lease_offer_completion.ok_or_else(|| {
            StoreError::corrupt_data("lease-offer publication has no typed receipt completion")
        })?;
        return Ok(Some(LoadedGenericReceipt::RevokedLeaseOffer {
            operation_id: publication.command().request().operation_id(),
            attempt_id: publication.lease().attempt_id(),
            primary_response_schema: completion.primary_response_schema,
            primary_response_digest: completion.primary_response_digest,
            fallback: completion.fallback,
        }));
    }
    Ok(Some(LoadedGenericReceipt::Live {
        receipt,
        lease_offer_fallback: lease_offer_completion.map(|completion| completion.fallback),
    }))
}

async fn insert_generic_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    encryption: &RunnerPayloadEncryption,
    request: RunnerOperationRequest,
    response: RunnerOperationResponse,
    committed_at: UnixMillis,
    lease_offer_publication: Option<&PublishedLeaseOffer>,
    lease_offer_fallback: Option<RevokedLeaseOfferFallback>,
) -> Result<RunnerOperationReceipt, StoreError> {
    let lease_offer_completion = match (lease_offer_publication, lease_offer_fallback) {
        (Some(publication), Some(fallback)) => {
            if publication.request() != &request
                || !is_lease_offer_command_kind(publication.command().request().kind().as_str())
            {
                return Err(StoreError::corrupt_data(
                    "lease-request response has a mismatched offer publication",
                ));
            }
            Some(ReceiptLeaseOfferCompletion::new(
                lease_offer_receipt_binding(publication),
                ReceiptLeaseOfferResponseDisposition::Primary,
                &response,
                fallback,
            ))
        }
        (None, None) => None,
        (Some(_), None) | (None, Some(_)) => {
            return Err(StoreError::corrupt_data(
                "lease-offer receipt is missing its typed revocation fallback",
            ));
        }
    };
    let tenant_id = runner_payload_tenant(transaction, request.session()).await?;
    let plaintext_size_bytes = i64::try_from(response.payload().len())
        .map_err(|_| StoreError::corrupt_data("runner response size exceeds PostgreSQL BIGINT"))?;
    let metadata = RunnerResponseEnvelopeMetadata::from_values(
        &request,
        &response,
        plaintext_size_bytes,
        committed_at,
    )?;
    let envelope = seal_runner_payload(
        encryption,
        &tenant_id,
        &encryption.response_purpose,
        metadata.record_id(),
        response.payload(),
    )
    .await?;
    if envelope.plaintext_size_bytes != metadata.plaintext_size_bytes {
        return Err(StoreError::corrupt_data(
            "sealed runner response size changed unexpectedly",
        ));
    }
    if let Some(publication) = lease_offer_publication
        && !matches!(
            classify_locked_published_lease_offer(transaction, publication).await?,
            LockedLeaseOfferDeliveryStatus::Live
        )
    {
        return Err(StoreError::AttemptFenceRejected(
            publication.lease().attempt_id(),
        ));
    }
    let inserted = insert_generic_receipt_row(
        transaction,
        &metadata,
        &tenant_id,
        &envelope,
        lease_offer_completion,
    )
    .await?;
    if inserted == 1 {
        return Ok(RunnerOperationReceipt::new(
            request,
            response,
            committed_at,
            false,
        ));
    }
    let expected = lease_offer_publication.map(|publication| {
        LeaseOfferCommandIdentity::new(
            publication.command().request().session(),
            publication.command().request().operation_id(),
            publication.command().sequence(),
        )
    });
    load_generic_receipt(
        transaction,
        encryption,
        &request,
        true,
        ReceiptOfferExpectation::Exact(expected),
    )
    .await?
    .ok_or_else(|| StoreError::corrupt_data("conflicting receipt disappeared"))?
    .into_live()
}

async fn insert_generic_receipt_row(
    transaction: &mut Transaction<'_, Postgres>,
    metadata: &RunnerResponseEnvelopeMetadata,
    tenant_id: &str,
    envelope: &RunnerPayloadEnvelopeParameters,
    lease_offer_completion: Option<ReceiptLeaseOfferCompletion>,
) -> Result<u64, StoreError> {
    let lease_offer_request_operation_id =
        lease_offer_completion.map(|completion| completion.binding.request_operation_id.as_uuid());
    let lease_offer_command_sequence = lease_offer_completion
        .map(|completion| sequence_i64(completion.binding.sequence))
        .transpose()?;
    let lease_offer_response_disposition =
        lease_offer_completion.map(|completion| completion.disposition.as_str());
    let lease_offer_primary_response_schema = lease_offer_completion
        .map(|completion| i32::from(completion.primary_response_schema.get()));
    let lease_offer_primary_response_digest =
        lease_offer_completion.map(|completion| completion.primary_response_digest);
    let lease_offer_fallback_version = lease_offer_completion
        .map(|completion| i32::from(completion.fallback.representation_version()));
    let lease_offer_fallback_operation_id = lease_offer_completion
        .map(|completion| completion.fallback.response_operation_id().as_uuid());
    let lease_offer_fallback_retry_after_millis = lease_offer_completion
        .map(|completion| i64::from(completion.fallback.retry_after_millis()));
    let lease_offer_fallback_response_schema = lease_offer_completion
        .map(|completion| i32::from(completion.fallback.response_schema().get()));
    let lease_offer_fallback_response_digest =
        lease_offer_completion.map(|completion| completion.fallback.response_digest());
    Ok(sqlx::query(
        r"
        INSERT INTO runner_rpc_receipts (
            runner_session_id, operation_id, runner_id,
            runner_session_epoch, runner_generation, operation_kind,
            request_digest, response_schema, response_digest,
            tenant_id, response_plaintext_size_bytes, envelope_schema,
            wrapping_key_id, wrapped_data_key, nonce, ciphertext,
            committed_at_ms, lease_offer_request_operation_id,
            lease_offer_command_sequence, lease_offer_response_disposition,
            lease_offer_primary_response_schema, lease_offer_primary_response_digest,
            lease_offer_fallback_version, lease_offer_fallback_operation_id,
            lease_offer_fallback_retry_after_millis,
            lease_offer_fallback_response_schema, lease_offer_fallback_response_digest
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
            $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24,
            $25, $26, $27
        )
        ON CONFLICT (runner_session_id, operation_id) DO NOTHING
        ",
    )
    .bind(metadata.session_id)
    .bind(metadata.operation_id)
    .bind(metadata.runner_id)
    .bind(metadata.session_epoch)
    .bind(metadata.runner_generation)
    .bind(&metadata.operation_kind)
    .bind(metadata.request_digest.as_bytes().as_slice())
    .bind(metadata.response_schema)
    .bind(metadata.response_digest.as_bytes().as_slice())
    .bind(tenant_id)
    .bind(metadata.plaintext_size_bytes)
    .bind(envelope.schema)
    .bind(&envelope.wrapping_key_id)
    .bind(&envelope.wrapped_data_key)
    .bind(&envelope.nonce)
    .bind(&envelope.ciphertext)
    .bind(metadata.committed_at_ms)
    .bind(lease_offer_request_operation_id)
    .bind(lease_offer_command_sequence)
    .bind(lease_offer_response_disposition)
    .bind(lease_offer_primary_response_schema)
    .bind(lease_offer_primary_response_digest.map(|digest| digest.as_bytes().to_vec()))
    .bind(lease_offer_fallback_version)
    .bind(lease_offer_fallback_operation_id)
    .bind(lease_offer_fallback_retry_after_millis)
    .bind(lease_offer_fallback_response_schema)
    .bind(lease_offer_fallback_response_digest.map(|digest| digest.as_bytes().to_vec()))
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected())
}

fn decode_receipt_lease_offer_completion(
    row: &sqlx::postgres::PgRow,
) -> Result<Option<ReceiptLeaseOfferCompletion>, StoreError> {
    let request_operation_id = row
        .try_get::<Option<Uuid>, _>("lease_offer_request_operation_id")
        .map_err(operation_error)?;
    let sequence = row
        .try_get::<Option<i64>, _>("lease_offer_command_sequence")
        .map_err(operation_error)?;
    let disposition = row
        .try_get::<Option<String>, _>("lease_offer_response_disposition")
        .map_err(operation_error)?;
    let primary_schema = row
        .try_get::<Option<i32>, _>("lease_offer_primary_response_schema")
        .map_err(operation_error)?;
    let primary_digest = row
        .try_get::<Option<Vec<u8>>, _>("lease_offer_primary_response_digest")
        .map_err(operation_error)?;
    let fallback_version = row
        .try_get::<Option<i32>, _>("lease_offer_fallback_version")
        .map_err(operation_error)?;
    let fallback_operation_id = row
        .try_get::<Option<Uuid>, _>("lease_offer_fallback_operation_id")
        .map_err(operation_error)?;
    let fallback_retry_after_millis = row
        .try_get::<Option<i64>, _>("lease_offer_fallback_retry_after_millis")
        .map_err(operation_error)?;
    let fallback_schema = row
        .try_get::<Option<i32>, _>("lease_offer_fallback_response_schema")
        .map_err(operation_error)?;
    let fallback_digest = row
        .try_get::<Option<Vec<u8>>, _>("lease_offer_fallback_response_digest")
        .map_err(operation_error)?;
    match (
        request_operation_id,
        sequence,
        disposition,
        primary_schema,
        primary_digest,
        fallback_version,
        fallback_operation_id,
        fallback_retry_after_millis,
        fallback_schema,
        fallback_digest,
    ) {
        (None, None, None, None, None, None, None, None, None, None) => Ok(None),
        (
            Some(request_operation_id),
            Some(sequence),
            Some(disposition),
            Some(primary_schema),
            Some(primary_digest),
            Some(fallback_version),
            Some(fallback_operation_id),
            Some(fallback_retry_after_millis),
            Some(fallback_schema),
            Some(fallback_digest),
        ) => {
            let fallback = automata_ci_control::adapter_spi::revoked_lease_offer_fallback(
                u16::try_from(fallback_version).map_err(|_| {
                    StoreError::corrupt_data(
                        "runner RPC receipt fallback version is outside the durable range",
                    )
                })?,
                OperationId::from_uuid(fallback_operation_id),
                u32::try_from(fallback_retry_after_millis).map_err(|_| {
                    StoreError::corrupt_data(
                        "runner RPC receipt fallback retry is outside the durable range",
                    )
                })?,
                decode_schema(fallback_schema)?,
                decode_sha256_digest(fallback_digest)
                    .map_err(|error| StoreError::corrupt_data(error.clone()))?,
            )
            .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
            Ok(Some(ReceiptLeaseOfferCompletion {
                binding: ReceiptLeaseOfferBinding {
                    request_operation_id: OperationId::from_uuid(request_operation_id),
                    sequence: decode_sequence(sequence)?,
                },
                disposition: ReceiptLeaseOfferResponseDisposition::decode(&disposition)?,
                primary_response_schema: decode_schema(primary_schema)?,
                primary_response_digest: decode_sha256_digest(primary_digest)
                    .map_err(|error| StoreError::corrupt_data(error.clone()))?,
                fallback,
            }))
        }
        _ => Err(StoreError::corrupt_data(
            "runner RPC receipt has a partial lease-offer completion",
        )),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LockedRuntimeAuthorityDelivery {
    request_operation_id: OperationId,
    request_digest: Sha256Digest,
    bundle_digest: Sha256Digest,
    committed_at: UnixMillis,
    acknowledgement_operation_id: Option<OperationId>,
    acknowledgement_digest: Option<Sha256Digest>,
    acknowledged_at: Option<UnixMillis>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeAuthorityAttemptStatus {
    Accepted,
    AwaitingAcceptance,
    Rejected,
    Stale,
}

async fn close_session_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    fence: RunnerSessionFence,
) -> Result<(), StoreError> {
    let snapshot = locked_session(transaction, fence).await?;
    let decision_at = if let Some(disconnected_at) = snapshot.disconnected_at() {
        disconnected_at
    } else {
        let database_now = super::runner_attempt_database_now(transaction).await?;
        let decision_at = database_session_decision_at(database_now, [snapshot.heartbeat_at()])?;
        let updated = sqlx::query(
            r"
            UPDATE runner_sessions
            SET disconnected_at_ms = $5
            WHERE id = $1 AND runner_id = $2
              AND runner_generation = $3 AND session_epoch = $4
              AND disconnected_at_ms IS NULL
            ",
        )
        .bind(fence.session_id().as_uuid())
        .bind(fence.runner_id().as_uuid())
        .bind(generation_i64(fence.runner_generation())?)
        .bind(epoch_i64(fence.session_epoch())?)
        .bind(decision_at.get())
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
        if updated.rows_affected() != 1 {
            return Err(StoreError::SessionFenceRejected(fence.session_id()));
        }
        decision_at
    };
    cleanup_session_lease_request_state(transaction, fence.session_id()).await?;
    tombstone_session_runner_payloads(
        transaction,
        fence.session_id(),
        RunnerPayloadTombstoneReason::SessionClosed,
        decision_at,
    )
    .await?;
    mark_runner_offline(transaction, fence, decision_at).await
}

async fn lock_runtime_authority_delivery_admission(
    transaction: &mut Transaction<'_, Postgres>,
    session: RunnerSessionFence,
    protocol_version: RunnerProtocolVersion,
    binding: RuntimeAuthorityDeliveryBinding,
) -> Result<
    Option<(
        AcceptedRuntimeAuthorityOffer,
        Option<LockedRuntimeAuthorityDelivery>,
    )>,
    StoreError,
> {
    let routing = lock_live_routing(transaction, session).await?;
    routing.require_online(session)?;
    if routing.protocol_version != protocol_version {
        return Err(StoreError::OperationConflict {
            session_id: session.session_id(),
            operation_id: binding.offer_operation_id(),
        });
    }
    let sequence = CommandSequence::new(binding.offer_sequence().get())
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let identity = LeaseOfferCommandIdentity::new(session, binding.offer_operation_id(), sequence);
    let offer = load_runtime_authority_offer_by_command(transaction, identity)
        .await?
        .ok_or_else(|| StoreError::OperationConflict {
            session_id: session.session_id(),
            operation_id: binding.offer_operation_id(),
        })?;
    if !runtime_authority_binding_matches_offer(binding, protocol_version, &offer) {
        return Err(StoreError::OperationConflict {
            session_id: session.session_id(),
            operation_id: binding.offer_operation_id(),
        });
    }
    match lock_runtime_authority_attempt(transaction, &offer).await? {
        RuntimeAuthorityAttemptStatus::Accepted => {}
        RuntimeAuthorityAttemptStatus::AwaitingAcceptance
        | RuntimeAuthorityAttemptStatus::Rejected => {
            return Err(StoreError::AttemptFenceRejected(offer.lease().attempt_id()));
        }
        RuntimeAuthorityAttemptStatus::Stale => {
            close_session_in_transaction(transaction, session).await?;
            return Ok(None);
        }
    }
    let delivery = lock_runtime_authority_delivery_row(transaction, &offer, binding).await?;
    Ok(Some((offer, delivery)))
}

fn runtime_authority_binding_matches_offer(
    binding: RuntimeAuthorityDeliveryBinding,
    protocol_version: RunnerProtocolVersion,
    offer: &AcceptedRuntimeAuthorityOffer,
) -> bool {
    binding.generation() == INITIAL_RUNTIME_AUTHORITY_GENERATION
        && offer.protocol_version() == protocol_version
        && binding.attempt_id() == offer.lease().attempt_id()
        && binding.slot().get() == offer.slot().ordinal()
        && binding.guard() == offer.lease().guard()
        && binding.offer_operation_id() == offer.command().operation_id()
        && binding.offer_sequence().get() == offer.command().sequence().get()
        && binding.job_ir_digest() == offer.job_ir().digest()
}

async fn lock_runtime_authority_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    offer: &AcceptedRuntimeAuthorityOffer,
) -> Result<RuntimeAuthorityAttemptStatus, StoreError> {
    let session = offer.request().session();
    let row = sqlx::query(
        r"
        SELECT attempt.lifecycle IN ('preparing', 'running') AS lifecycle_accepted,
               attempt.lifecycle = 'leased' AS lifecycle_awaiting_acceptance,
               COALESCE(attempt.lease_id = $2
                   AND attempt.fencing_token = $3
                   AND attempt.runner_id = $4
                   AND attempt.runner_session_id = $5
                   AND attempt.runner_session_epoch = $6
                   AND attempt.runner_generation = $7
                   AND attempt.runner_slot = $8
                   AND attempt.lease_issued_at_ms = $9
                   AND attempt.lease_expires_at_ms >= $10, FALSE) AS exact_fence,
               COALESCE(attempt.job_id = $11
                   AND job.run_id = $12
                   AND job.job_ir_schema = $13
                   AND job.job_ir_size_bytes = $14
                   AND job.job_ir_digest = $15
                   AND job.job_ir_object_key = $16, FALSE) AS exact_job_ir
        FROM job_attempts AS attempt
        LEFT JOIN jobs AS job ON job.id = attempt.job_id
        WHERE attempt.id = $1
        FOR UPDATE OF attempt
        ",
    )
    .bind(offer.lease().attempt_id().as_uuid())
    .bind(offer.lease().lease_id().as_uuid())
    .bind(fencing_i64(offer.lease().fencing_token())?)
    .bind(session.runner_id().as_uuid())
    .bind(session.session_id().as_uuid())
    .bind(epoch_i64(session.session_epoch())?)
    .bind(generation_i64(session.runner_generation())?)
    .bind(i32::from(offer.slot().ordinal()))
    .bind(offer.lease().issued_at().get())
    .bind(offer.offer_valid_until().get())
    .bind(offer.job_ir().job_id().as_uuid())
    .bind(offer.job_ir().run_id().as_uuid())
    .bind(i32::from(offer.job_ir().version().get()))
    .bind(i64::try_from(offer.job_ir().encoded_size()).map_err(|_| {
        StoreError::corrupt_data("runtime-authority JobIR size exceeds PostgreSQL BIGINT")
    })?)
    .bind(offer.job_ir().digest().as_bytes().as_slice())
    .bind(offer.job_ir().object_key().as_str())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(row) = row else {
        return Ok(RuntimeAuthorityAttemptStatus::Stale);
    };
    if !row
        .try_get::<bool, _>("exact_job_ir")
        .map_err(operation_error)?
    {
        return Err(StoreError::corrupt_data(
            "accepted runtime-authority attempt disagrees with immutable JobIR",
        ));
    }
    let lifecycle_accepted = row
        .try_get::<bool, _>("lifecycle_accepted")
        .map_err(operation_error)?;
    let lifecycle_awaiting_acceptance = row
        .try_get::<bool, _>("lifecycle_awaiting_acceptance")
        .map_err(operation_error)?;
    let exact_fence = row
        .try_get::<bool, _>("exact_fence")
        .map_err(operation_error)?;
    let database_now = super::runner_attempt_database_now(transaction).await?;
    if database_now < offer.command().created_at() || database_now >= offer.offer_valid_until() {
        return Ok(RuntimeAuthorityAttemptStatus::Stale);
    }
    if lifecycle_accepted && exact_fence {
        return Ok(RuntimeAuthorityAttemptStatus::Accepted);
    }
    if lifecycle_awaiting_acceptance && exact_fence {
        return Ok(RuntimeAuthorityAttemptStatus::AwaitingAcceptance);
    }
    if exact_fence {
        return Ok(RuntimeAuthorityAttemptStatus::Rejected);
    }
    Ok(RuntimeAuthorityAttemptStatus::Stale)
}

async fn lock_runtime_authority_delivery_row(
    transaction: &mut Transaction<'_, Postgres>,
    offer: &AcceptedRuntimeAuthorityOffer,
    binding: RuntimeAuthorityDeliveryBinding,
) -> Result<Option<LockedRuntimeAuthorityDelivery>, StoreError> {
    let row = sqlx::query(
        r"
        SELECT attempt_id, fencing_token, delivery_generation,
               runner_id, runner_session_id, runner_session_epoch,
               runner_generation, protocol_version, runner_slot, lease_id,
               offer_operation_id, offer_command_sequence,
               job_id, run_id, job_ir_schema, job_ir_size_bytes,
               job_ir_digest, job_ir_object_key,
               request_operation_id, request_digest, bundle_digest,
               committed_at_ms, acknowledgement_operation_id,
               acknowledgement_digest, acknowledged_at_ms
        FROM runner_runtime_authority_deliveries
        WHERE attempt_id = $1
          AND fencing_token = $2
          AND delivery_generation = $3
        FOR UPDATE
        ",
    )
    .bind(binding.attempt_id().as_uuid())
    .bind(fencing_i64(binding.guard().fencing_token())?)
    .bind(i32::try_from(binding.generation().get()).map_err(|_| {
        StoreError::corrupt_data("runtime-authority generation exceeds PostgreSQL INTEGER")
    })?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    validate_locked_runtime_authority_delivery_identity(&row, offer, binding)?;
    decode_locked_runtime_authority_delivery(&row, offer).map(Some)
}

fn validate_locked_runtime_authority_delivery_identity(
    row: &sqlx::postgres::PgRow,
    offer: &AcceptedRuntimeAuthorityOffer,
    binding: RuntimeAuthorityDeliveryBinding,
) -> Result<(), StoreError> {
    let session = offer.request().session();
    let attempt_id = AttemptId::from_uuid(row.try_get("attempt_id").map_err(operation_error)?);
    let fencing_token = u64::try_from(
        row.try_get::<i64, _>("fencing_token")
            .map_err(operation_error)?,
    )
    .ok()
    .and_then(|value| FencingToken::new(value).ok())
    .ok_or_else(|| StoreError::corrupt_data("invalid runtime-authority fencing token"))?;
    let delivery_generation = u32::try_from(
        row.try_get::<i32, _>("delivery_generation")
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("invalid runtime-authority generation"))?;
    let runner_id = RunnerId::from_uuid(row.try_get("runner_id").map_err(operation_error)?);
    let runner_session_id =
        RunnerSessionId::from_uuid(row.try_get("runner_session_id").map_err(operation_error)?);
    let runner_session_epoch = decode_epoch(
        row.try_get("runner_session_epoch")
            .map_err(operation_error)?,
    )?;
    let runner_generation =
        decode_generation(row.try_get("runner_generation").map_err(operation_error)?)?;
    let protocol_version =
        decode_protocol(row.try_get("protocol_version").map_err(operation_error)?)?;
    let runner_slot = u16::try_from(
        row.try_get::<i32, _>("runner_slot")
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("invalid runtime-authority runner slot"))?;
    let lease_id = LeaseId::from_uuid(row.try_get("lease_id").map_err(operation_error)?);
    let offer_operation_id =
        OperationId::from_uuid(row.try_get("offer_operation_id").map_err(operation_error)?);
    let offer_sequence = decode_sequence(
        row.try_get("offer_command_sequence")
            .map_err(operation_error)?,
    )?;
    let job_id = JobId::from_uuid(row.try_get("job_id").map_err(operation_error)?);
    let run_id = RunId::from_uuid(row.try_get("run_id").map_err(operation_error)?);
    let job_ir_version =
        decode_job_ir_version(row.try_get("job_ir_schema").map_err(operation_error)?)?;
    let job_ir_size = u64::try_from(
        row.try_get::<i64, _>("job_ir_size_bytes")
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("invalid runtime-authority JobIR size"))?;
    let job_ir_digest =
        decode_sha256_digest(row.try_get("job_ir_digest").map_err(operation_error)?)
            .map_err(|error| StoreError::corrupt_data(error.clone()))?;
    let job_ir_object_key: String = row.try_get("job_ir_object_key").map_err(operation_error)?;
    if attempt_id != offer.lease().attempt_id()
        || fencing_token != offer.lease().fencing_token()
        || delivery_generation != binding.generation().get()
        || runner_id != session.runner_id()
        || runner_session_id != session.session_id()
        || runner_session_epoch != session.session_epoch()
        || runner_generation != session.runner_generation()
        || protocol_version != offer.protocol_version()
        || runner_slot != offer.slot().ordinal()
        || lease_id != offer.lease().lease_id()
        || offer_operation_id != offer.command().operation_id()
        || offer_sequence != offer.command().sequence()
        || job_id != offer.job_ir().job_id()
        || run_id != offer.job_ir().run_id()
        || job_ir_version != offer.job_ir().version()
        || job_ir_size != offer.job_ir().encoded_size()
        || job_ir_digest != offer.job_ir().digest()
        || job_ir_object_key != offer.job_ir().object_key().as_str()
    {
        return Err(StoreError::corrupt_data(
            "runtime-authority delivery row disagrees with its accepted offer",
        ));
    }
    Ok(())
}

fn decode_locked_runtime_authority_delivery(
    row: &sqlx::postgres::PgRow,
    offer: &AcceptedRuntimeAuthorityOffer,
) -> Result<LockedRuntimeAuthorityDelivery, StoreError> {
    let committed_at = UnixMillis::new(row.try_get("committed_at_ms").map_err(operation_error)?);
    if committed_at < offer.command().created_at() || committed_at >= offer.offer_valid_until() {
        return Err(StoreError::corrupt_data(
            "runtime-authority delivery commit is outside its offer horizon",
        ));
    }
    let acknowledgement_operation_id = row
        .try_get::<Option<Uuid>, _>("acknowledgement_operation_id")
        .map_err(operation_error)?
        .map(OperationId::from_uuid);
    let acknowledgement_digest = row
        .try_get::<Option<Vec<u8>>, _>("acknowledgement_digest")
        .map_err(operation_error)?
        .map(decode_sha256_digest)
        .transpose()
        .map_err(|error| StoreError::corrupt_data(error.clone()))?;
    let acknowledged_at = row
        .try_get::<Option<i64>, _>("acknowledged_at_ms")
        .map_err(operation_error)?
        .map(UnixMillis::new);
    if acknowledged_at.is_some_and(|acknowledged| acknowledged < committed_at) {
        return Err(StoreError::corrupt_data(
            "runtime-authority acknowledgement predates delivery commit",
        ));
    }
    Ok(LockedRuntimeAuthorityDelivery {
        request_operation_id: OperationId::from_uuid(
            row.try_get("request_operation_id")
                .map_err(operation_error)?,
        ),
        request_digest: decode_sha256_digest(
            row.try_get("request_digest").map_err(operation_error)?,
        )
        .map_err(|error| StoreError::corrupt_data(error.clone()))?,
        bundle_digest: decode_sha256_digest(row.try_get("bundle_digest").map_err(operation_error)?)
            .map_err(|error| StoreError::corrupt_data(error.clone()))?,
        committed_at,
        acknowledgement_operation_id,
        acknowledgement_digest,
        acknowledged_at,
    })
}

async fn insert_runtime_authority_delivery(
    transaction: &mut Transaction<'_, Postgres>,
    admission: &RuntimeAuthorityDeliveryAdmission,
    bundle_digest: Sha256Digest,
    committed_at: UnixMillis,
) -> Result<(), StoreError> {
    let request = admission.request();
    let binding = request.binding();
    let offer = admission.offer();
    let session = request.request().session();
    let inserted = sqlx::query(
        r"
        INSERT INTO runner_runtime_authority_deliveries (
            attempt_id, fencing_token, delivery_generation,
            runner_id, runner_session_id, runner_session_epoch,
            runner_generation, protocol_version, runner_slot, lease_id,
            offer_operation_id, offer_command_sequence,
            job_id, run_id, job_ir_schema, job_ir_size_bytes,
            job_ir_digest, job_ir_object_key,
            request_operation_id, request_digest, bundle_digest, committed_at_ms
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
            $14, $15, $16, $17, $18, $19, $20, $21, $22
        )
        ",
    )
    .bind(binding.attempt_id().as_uuid())
    .bind(fencing_i64(binding.guard().fencing_token())?)
    .bind(i32::try_from(binding.generation().get()).map_err(|_| {
        StoreError::corrupt_data("runtime-authority generation exceeds PostgreSQL INTEGER")
    })?)
    .bind(session.runner_id().as_uuid())
    .bind(session.session_id().as_uuid())
    .bind(epoch_i64(session.session_epoch())?)
    .bind(generation_i64(session.runner_generation())?)
    .bind(protocol_i32(request.protocol_version()))
    .bind(i32::from(offer.slot().ordinal()))
    .bind(offer.lease().lease_id().as_uuid())
    .bind(binding.offer_operation_id().as_uuid())
    .bind(sequence_i64(offer.command().sequence())?)
    .bind(offer.job_ir().job_id().as_uuid())
    .bind(offer.job_ir().run_id().as_uuid())
    .bind(i32::from(offer.job_ir().version().get()))
    .bind(i64::try_from(offer.job_ir().encoded_size()).map_err(|_| {
        StoreError::corrupt_data("runtime-authority JobIR size exceeds PostgreSQL BIGINT")
    })?)
    .bind(binding.job_ir_digest().as_bytes().as_slice())
    .bind(offer.job_ir().object_key().as_str())
    .bind(request.request().operation_id().as_uuid())
    .bind(request.request().request_digest().as_bytes().as_slice())
    .bind(bundle_digest.as_bytes().as_slice())
    .bind(committed_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if inserted != 1 {
        return Err(StoreError::corrupt_data(
            "runtime-authority delivery insert affected an unexpected row count",
        ));
    }
    Ok(())
}

async fn acknowledge_runtime_authority_delivery_row(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AcknowledgeRuntimeAuthorityDelivery,
    acknowledged_at: UnixMillis,
) -> Result<(), StoreError> {
    let binding = request.binding();
    let updated = sqlx::query(
        r"
        UPDATE runner_runtime_authority_deliveries
        SET acknowledgement_operation_id = $4,
            acknowledgement_digest = $5,
            acknowledged_at_ms = $6
        WHERE attempt_id = $1
          AND fencing_token = $2
          AND delivery_generation = $3
          AND runner_session_id = $7
          AND offer_operation_id = $8
          AND offer_command_sequence = $9
          AND job_ir_digest = $10
          AND bundle_digest = $11
          AND acknowledgement_operation_id IS NULL
          AND acknowledgement_digest IS NULL
          AND acknowledged_at_ms IS NULL
        ",
    )
    .bind(binding.attempt_id().as_uuid())
    .bind(fencing_i64(binding.guard().fencing_token())?)
    .bind(i32::try_from(binding.generation().get()).map_err(|_| {
        StoreError::corrupt_data("runtime-authority generation exceeds PostgreSQL INTEGER")
    })?)
    .bind(request.request().operation_id().as_uuid())
    .bind(request.request().request_digest().as_bytes().as_slice())
    .bind(acknowledged_at.get())
    .bind(request.request().session().session_id().as_uuid())
    .bind(binding.offer_operation_id().as_uuid())
    .bind(i64::try_from(binding.offer_sequence().get()).map_err(|_| {
        StoreError::corrupt_data("runtime-authority offer sequence exceeds PostgreSQL BIGINT")
    })?)
    .bind(binding.job_ir_digest().as_bytes().as_slice())
    .bind(request.bundle_digest().as_bytes().as_slice())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if updated.rows_affected() != 1 {
        return Err(StoreError::OperationConflict {
            session_id: request.request().session().session_id(),
            operation_id: request.request().operation_id(),
        });
    }
    Ok(())
}

async fn load_lease_offer_publication(
    transaction: &mut Transaction<'_, Postgres>,
    encryption: &RunnerPayloadEncryption,
    expected: &LeaseOfferClaim,
    expected_command: Option<&EnqueueRunnerCommand>,
    expected_offer_valid_until: Option<UnixMillis>,
    replayed: bool,
) -> Result<Option<PublishedLeaseOffer>, StoreError> {
    let row = sqlx::query(
        r"
        SELECT publication.request_operation_id, publication.runner_id,
               publication.runner_session_epoch, publication.runner_generation,
               publication.operation_kind, publication.request_digest,
               publication.protocol_version, publication.runner_slot,
               publication.attempt_id, publication.lease_id,
               publication.fencing_token, publication.lease_issued_at_ms,
               publication.lease_expires_at_ms, publication.offer_valid_until_ms,
               publication.job_id,
               publication.run_id, publication.job_ir_schema,
               publication.job_ir_size_bytes, publication.job_ir_digest,
               publication.job_ir_object_key,
               publication.created_at_ms AS publication_created_at_ms,
               command.runner_session_id AS command_runner_session_id,
               command.command_sequence,
               command.operation_id AS command_operation_id,
               command.runner_id AS command_runner_id,
               command.runner_session_epoch AS command_runner_session_epoch,
               command.runner_generation AS command_runner_generation,
               command.command_kind, command.command_schema,
               command.command_digest, command.tenant_id AS tenant_id,
               command.command_plaintext_size_bytes,
               command.envelope_schema, command.wrapping_key_id,
               command.wrapped_data_key, command.nonce, command.ciphertext,
               command.payload_tombstone_reason,
               command.payload_tombstoned_at_ms,
               command.created_at_ms AS command_created_at_ms
        FROM runner_lease_offer_publications AS publication
        JOIN runner_command_outbox AS command
          ON command.runner_session_id = publication.runner_session_id
         AND command.command_sequence = publication.command_sequence
        WHERE publication.runner_session_id = $1
          AND publication.request_operation_id = $2
        FOR UPDATE OF publication, command
        ",
    )
    .bind(expected.request().session().session_id().as_uuid())
    .bind(expected.request().operation_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    decode_lease_offer_publication(
        encryption,
        &row,
        expected,
        expected_command,
        expected_offer_valid_until,
        replayed,
    )
    .await
    .map(Some)
}

async fn load_lease_offer_publication_by_command(
    transaction: &mut Transaction<'_, Postgres>,
    encryption: &RunnerPayloadEncryption,
    identity: LeaseOfferCommandIdentity,
) -> Result<Option<PublishedLeaseOffer>, StoreError> {
    let publication = load_lease_offer_publication_by_coordinates(
        transaction,
        encryption,
        identity.session(),
        None,
        identity.sequence(),
    )
    .await?;
    if let Some(publication) = publication.as_ref()
        && publication.command().request().operation_id() != identity.operation_id()
    {
        return Err(StoreError::corrupt_data(
            "lease-offer publication resolved a different command identity",
        ));
    }
    Ok(publication)
}

#[allow(clippy::too_many_lines)] // One snapshot query closes every offer field under the same lock.
async fn load_runtime_authority_offer_by_command(
    transaction: &mut Transaction<'_, Postgres>,
    identity: LeaseOfferCommandIdentity,
) -> Result<Option<AcceptedRuntimeAuthorityOffer>, StoreError> {
    let session = identity.session();
    let rows = sqlx::query(
        r"
        SELECT publication.request_operation_id, publication.runner_id,
               publication.runner_session_epoch, publication.runner_generation,
               publication.operation_kind, publication.request_digest,
               publication.protocol_version, publication.runner_slot,
               publication.attempt_id, publication.lease_id,
               publication.fencing_token, publication.lease_issued_at_ms,
               publication.lease_expires_at_ms, publication.offer_valid_until_ms,
               publication.job_id, publication.run_id, publication.job_ir_schema,
               publication.job_ir_size_bytes, publication.job_ir_digest,
               publication.job_ir_object_key,
               publication.created_at_ms AS publication_created_at_ms,
               command.runner_session_id AS command_runner_session_id,
               command.command_sequence, command.operation_id AS command_operation_id,
               command.runner_id AS command_runner_id,
               command.runner_session_epoch AS command_runner_session_epoch,
               command.runner_generation AS command_runner_generation,
               command.command_kind, command.command_schema, command.command_digest,
               command.created_at_ms AS command_created_at_ms
        FROM runner_lease_offer_publications AS publication
        JOIN runner_command_outbox AS command
          ON command.runner_session_id = publication.runner_session_id
         AND command.command_sequence = publication.command_sequence
        WHERE publication.runner_session_id = $1
          AND publication.command_sequence = $2
        LIMIT 2
        FOR UPDATE OF publication, command
        ",
    )
    .bind(session.session_id().as_uuid())
    .bind(sequence_i64(identity.sequence())?)
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let [row] = rows.as_slice() else {
        return if rows.is_empty() {
            Ok(None)
        } else {
            Err(StoreError::corrupt_data(
                "multiple runtime-authority offers reference one command",
            ))
        };
    };

    let publication_runner_id =
        RunnerId::from_uuid(row.try_get("runner_id").map_err(operation_error)?);
    let publication_epoch = decode_epoch(
        row.try_get("runner_session_epoch")
            .map_err(operation_error)?,
    )?;
    let publication_generation =
        decode_generation(row.try_get("runner_generation").map_err(operation_error)?)?;
    let command_session_id: Uuid = row
        .try_get("command_runner_session_id")
        .map_err(operation_error)?;
    let command_runner_id =
        RunnerId::from_uuid(row.try_get("command_runner_id").map_err(operation_error)?);
    let command_epoch = decode_epoch(
        row.try_get("command_runner_session_epoch")
            .map_err(operation_error)?,
    )?;
    let command_generation = decode_generation(
        row.try_get("command_runner_generation")
            .map_err(operation_error)?,
    )?;
    if publication_runner_id != session.runner_id()
        || publication_epoch != session.session_epoch()
        || publication_generation != session.runner_generation()
        || command_session_id != session.session_id().as_uuid()
        || command_runner_id != session.runner_id()
        || command_epoch != session.session_epoch()
        || command_generation != session.runner_generation()
    {
        return Err(StoreError::corrupt_data(
            "runtime-authority offer has a mismatched session fence",
        ));
    }

    let request_kind = RunnerOperationKind::new(
        row.try_get::<String, _>("operation_kind")
            .map_err(operation_error)?,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let command_kind: String = row.try_get("command_kind").map_err(operation_error)?;
    let command_schema = decode_schema(row.try_get("command_schema").map_err(operation_error)?)?;
    let _command_digest =
        decode_sha256_digest(row.try_get("command_digest").map_err(operation_error)?)
            .map_err(|error| StoreError::corrupt_data(error.clone()))?;
    if request_kind.as_str() != LEASE_RPC_OPERATION_KIND
        || !is_lease_offer_command_kind(&command_kind)
    {
        return Err(StoreError::corrupt_data(
            "runtime-authority offer has invalid command metadata",
        ));
    }

    let command_operation_id = OperationId::from_uuid(
        row.try_get("command_operation_id")
            .map_err(operation_error)?,
    );
    let command_sequence =
        decode_sequence(row.try_get("command_sequence").map_err(operation_error)?)?;
    if command_operation_id != identity.operation_id() || command_sequence != identity.sequence() {
        return Err(StoreError::corrupt_data(
            "runtime-authority offer resolved a different command identity",
        ));
    }
    let command_created_at = UnixMillis::new(
        row.try_get("command_created_at_ms")
            .map_err(operation_error)?,
    );
    let publication_created_at = UnixMillis::new(
        row.try_get("publication_created_at_ms")
            .map_err(operation_error)?,
    );
    if command_created_at != publication_created_at {
        return Err(StoreError::corrupt_data(
            "runtime-authority publication and command creation times disagree",
        ));
    }

    let request_operation_id = OperationId::from_uuid(
        row.try_get("request_operation_id")
            .map_err(operation_error)?,
    );
    let request_digest =
        decode_sha256_digest(row.try_get("request_digest").map_err(operation_error)?)
            .map_err(|error| StoreError::corrupt_data(error.clone()))?;
    let request =
        RunnerOperationRequest::new(session, request_operation_id, request_kind, request_digest);
    let protocol_version =
        decode_protocol(row.try_get("protocol_version").map_err(operation_error)?)?;
    if command_schema.get() != LEASE_OFFER_COMMAND_SCHEMA
        || protocol_version.get() != LEASE_OFFER_COMMAND_SCHEMA
    {
        return Err(StoreError::corrupt_data(
            "runtime-authority offer has invalid protocol metadata",
        ));
    }
    let slot = u16::try_from(
        row.try_get::<i32, _>("runner_slot")
            .map_err(operation_error)?,
    )
    .ok()
    .and_then(|value| StableRunnerSlot::new(value).ok())
    .ok_or_else(|| StoreError::corrupt_data("invalid runtime-authority runner slot"))?;
    let fencing = u64::try_from(
        row.try_get::<i64, _>("fencing_token")
            .map_err(operation_error)?,
    )
    .ok()
    .and_then(|value| FencingToken::new(value).ok())
    .ok_or_else(|| StoreError::corrupt_data("invalid runtime-authority fencing token"))?;
    let lease = decode_lease_offer_lease(row, session.runner_id(), fencing)?;
    let job_ir = decode_lease_offer_job_ir(row)?;
    let offer_valid_until = UnixMillis::new(
        row.try_get("offer_valid_until_ms")
            .map_err(operation_error)?,
    );
    AcceptedRuntimeAuthorityOffer::new(
        request,
        protocol_version,
        slot,
        lease,
        job_ir,
        offer_valid_until,
        RuntimeAuthorityOfferCommand::new(
            command_operation_id,
            command_sequence,
            command_created_at,
        ),
    )
    .map(Some)
    .map_err(|error| StoreError::corrupt_data(error.to_string()))
}

async fn load_lease_offer_publication_by_receipt_binding(
    transaction: &mut Transaction<'_, Postgres>,
    encryption: &RunnerPayloadEncryption,
    session: RunnerSessionFence,
    binding: ReceiptLeaseOfferBinding,
) -> Result<Option<PublishedLeaseOffer>, StoreError> {
    let publication = load_lease_offer_publication_by_coordinates(
        transaction,
        encryption,
        session,
        Some(binding.request_operation_id),
        binding.sequence,
    )
    .await?;
    if let Some(publication) = publication.as_ref()
        && publication.request().operation_id() != binding.request_operation_id
    {
        return Err(StoreError::corrupt_data(
            "lease-request receipt resolved a different offer publication",
        ));
    }
    Ok(publication)
}

async fn load_lease_offer_publication_by_coordinates(
    transaction: &mut Transaction<'_, Postgres>,
    encryption: &RunnerPayloadEncryption,
    session: RunnerSessionFence,
    request_operation_id: Option<OperationId>,
    sequence: CommandSequence,
) -> Result<Option<PublishedLeaseOffer>, StoreError> {
    let rows = sqlx::query(
        r"
        SELECT publication.request_operation_id, publication.runner_id,
               publication.runner_session_epoch, publication.runner_generation,
               publication.operation_kind, publication.request_digest,
               publication.protocol_version, publication.runner_slot,
               publication.attempt_id, publication.lease_id,
               publication.fencing_token, publication.lease_issued_at_ms,
               publication.lease_expires_at_ms, publication.offer_valid_until_ms,
               publication.job_id,
               publication.run_id, publication.job_ir_schema,
               publication.job_ir_size_bytes, publication.job_ir_digest,
               publication.job_ir_object_key,
               publication.created_at_ms AS publication_created_at_ms,
               command.runner_session_id AS command_runner_session_id,
               command.command_sequence,
               command.operation_id AS command_operation_id,
               command.runner_id AS command_runner_id,
               command.runner_session_epoch AS command_runner_session_epoch,
               command.runner_generation AS command_runner_generation,
               command.command_kind, command.command_schema,
               command.command_digest, command.tenant_id AS tenant_id,
               command.command_plaintext_size_bytes,
               command.envelope_schema, command.wrapping_key_id,
               command.wrapped_data_key, command.nonce, command.ciphertext,
               command.payload_tombstone_reason,
               command.payload_tombstoned_at_ms,
               command.created_at_ms AS command_created_at_ms
        FROM runner_lease_offer_publications AS publication
        JOIN runner_command_outbox AS command
          ON command.runner_session_id = publication.runner_session_id
         AND command.command_sequence = publication.command_sequence
        WHERE publication.runner_session_id = $1
          AND publication.command_sequence = $2
          AND ($3::UUID IS NULL OR publication.request_operation_id = $3)
        LIMIT 2
        FOR UPDATE OF publication, command
        ",
    )
    .bind(session.session_id().as_uuid())
    .bind(sequence_i64(sequence)?)
    .bind(request_operation_id.map(OperationId::as_uuid))
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let [row] = rows.as_slice() else {
        return if rows.is_empty() {
            Ok(None)
        } else {
            Err(StoreError::corrupt_data(
                "multiple lease-offer publications reference one command",
            ))
        };
    };
    let publication = decode_lease_offer_publication_row(encryption, row, session, true).await?;
    if publication.command().sequence() != sequence {
        return Err(StoreError::corrupt_data(
            "lease-offer publication resolved a different command identity",
        ));
    }
    Ok(Some(publication))
}

async fn decode_lease_offer_publication(
    encryption: &RunnerPayloadEncryption,
    row: &sqlx::postgres::PgRow,
    expected: &LeaseOfferClaim,
    expected_command: Option<&EnqueueRunnerCommand>,
    expected_offer_valid_until: Option<UnixMillis>,
    replayed: bool,
) -> Result<PublishedLeaseOffer, StoreError> {
    let publication =
        decode_lease_offer_publication_row(encryption, row, expected.request().session(), replayed)
            .await?;
    let stable_command_matches = expected_command.is_none_or(|expected_command| {
        publication.command().request().session() == expected_command.session()
            && publication.command().request().kind() == expected_command.kind()
            && publication.command().request().payload() == expected_command.payload()
            && publication.command().request().created_at() == expected_command.created_at()
    });
    if publication.request() != expected.request()
        || publication.protocol_version() != expected.protocol_version()
        || publication.slot() != expected.slot()
        || publication.lease() != expected.lease()
        || publication.job_ir() != expected.job_ir()
        || expected_offer_valid_until
            .is_some_and(|horizon| publication.offer_valid_until() != horizon)
        || !stable_command_matches
    {
        return Err(StoreError::OperationConflict {
            session_id: expected.request().session().session_id(),
            operation_id: expected.request().operation_id(),
        });
    }
    Ok(publication)
}

async fn decode_lease_offer_publication_row(
    encryption: &RunnerPayloadEncryption,
    row: &sqlx::postgres::PgRow,
    session: RunnerSessionFence,
    replayed: bool,
) -> Result<PublishedLeaseOffer, StoreError> {
    let publication_runner_id =
        RunnerId::from_uuid(row.try_get("runner_id").map_err(operation_error)?);
    let publication_epoch = decode_epoch(
        row.try_get("runner_session_epoch")
            .map_err(operation_error)?,
    )?;
    let publication_generation =
        decode_generation(row.try_get("runner_generation").map_err(operation_error)?)?;
    if publication_runner_id != session.runner_id()
        || publication_epoch != session.session_epoch()
        || publication_generation != session.runner_generation()
    {
        return Err(StoreError::corrupt_data(
            "lease-offer publication has a mismatched session fence",
        ));
    }
    let request_operation_id = OperationId::from_uuid(
        row.try_get("request_operation_id")
            .map_err(operation_error)?,
    );
    let kind = RunnerOperationKind::new(
        row.try_get::<String, _>("operation_kind")
            .map_err(operation_error)?,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    if kind.as_str() != LEASE_RPC_OPERATION_KIND {
        return Err(StoreError::corrupt_data(
            "lease-offer publication has an invalid request kind",
        ));
    }
    let digest = decode_sha256_digest(row.try_get("request_digest").map_err(operation_error)?)
        .map_err(|error| StoreError::corrupt_data(error.clone()))?;
    let request = RunnerOperationRequest::new(session, request_operation_id, kind, digest);
    let protocol = decode_protocol(row.try_get("protocol_version").map_err(operation_error)?)?;
    let slot = u16::try_from(
        row.try_get::<i32, _>("runner_slot")
            .map_err(operation_error)?,
    )
    .ok()
    .and_then(|value| StableRunnerSlot::new(value).ok())
    .ok_or_else(|| StoreError::corrupt_data("invalid lease-offer runner slot"))?;
    let fencing = u64::try_from(
        row.try_get::<i64, _>("fencing_token")
            .map_err(operation_error)?,
    )
    .ok()
    .and_then(|value| FencingToken::new(value).ok())
    .ok_or_else(|| StoreError::corrupt_data("invalid lease-offer fencing token"))?;
    let lease = decode_lease_offer_lease(row, request.session().runner_id(), fencing)?;
    let job_ir = decode_lease_offer_job_ir(row)?;
    let command = decode_outbox_command(encryption, row, request.session(), replayed).await?;
    let publication_created_at = UnixMillis::new(
        row.try_get("publication_created_at_ms")
            .map_err(operation_error)?,
    );
    if publication_created_at != command.request().created_at() {
        return Err(StoreError::corrupt_data(
            "lease-offer publication and command creation times disagree",
        ));
    }
    let offer_valid_until = UnixMillis::new(
        row.try_get("offer_valid_until_ms")
            .map_err(operation_error)?,
    );
    PublishedLeaseOffer::new(
        request,
        protocol,
        slot,
        lease,
        job_ir,
        offer_valid_until,
        command,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))
}

fn decode_lease_offer_lease(
    row: &sqlx::postgres::PgRow,
    runner_id: RunnerId,
    fencing: FencingToken,
) -> Result<Lease, StoreError> {
    Lease::new(
        automata_ci_core::LeaseId::from_uuid(row.try_get("lease_id").map_err(operation_error)?),
        AttemptId::from_uuid(row.try_get("attempt_id").map_err(operation_error)?),
        runner_id,
        fencing,
        UnixMillis::new(row.try_get("lease_issued_at_ms").map_err(operation_error)?),
        UnixMillis::new(
            row.try_get("lease_expires_at_ms")
                .map_err(operation_error)?,
        ),
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))
}

fn decode_lease_offer_job_ir(row: &sqlx::postgres::PgRow) -> Result<JobIrMetadata, StoreError> {
    JobIrMetadata::new(
        JobId::from_uuid(row.try_get("job_id").map_err(operation_error)?),
        RunId::from_uuid(row.try_get("run_id").map_err(operation_error)?),
        decode_job_ir_version(row.try_get("job_ir_schema").map_err(operation_error)?)?,
        u64::try_from(
            row.try_get::<i64, _>("job_ir_size_bytes")
                .map_err(operation_error)?,
        )
        .map_err(|_| StoreError::corrupt_data("negative lease-offer JobIR size"))?,
        decode_sha256_digest(row.try_get("job_ir_digest").map_err(operation_error)?)
            .map_err(|error| StoreError::corrupt_data(error.clone()))?,
        ObjectKey::new(
            row.try_get::<String, _>("job_ir_object_key")
                .map_err(operation_error)?,
        )
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))
}

async fn lock_exact_lease_offer_claim(
    transaction: &mut Transaction<'_, Postgres>,
    request: &LeaseOfferClaim,
    routing: &LockedRouting,
) -> Result<(), StoreError> {
    let conflict = || StoreError::OperationConflict {
        session_id: request.request().session().session_id(),
        operation_id: request.request().operation_id(),
    };
    if request.request().kind().as_str() != LEASE_RPC_OPERATION_KIND
        || request.protocol_version() != routing.protocol_version
        || request.job_ir().version() != routing.job_ir_version
        || !routing.slots.contains(request.slot())
    {
        return Err(conflict());
    }
    let head = sqlx::query(
        r"
        SELECT operation_id, request_digest, acknowledges_operation_id
        FROM runner_lease_request_heads
        WHERE runner_session_id = $1 AND runner_slot = $2
        FOR UPDATE
        ",
    )
    .bind(request.request().session().session_id().as_uuid())
    .bind(i32::from(request.slot().ordinal()))
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or_else(conflict)?;
    let operation_id =
        OperationId::from_uuid(head.try_get("operation_id").map_err(operation_error)?);
    let request_digest =
        decode_sha256_digest(head.try_get("request_digest").map_err(operation_error)?)
            .map_err(|error| StoreError::corrupt_data(error.clone()))?;
    let predecessor = head
        .try_get::<Option<Uuid>, _>("acknowledges_operation_id")
        .map_err(operation_error)?
        .map(OperationId::from_uuid);
    if operation_id != request.request().operation_id()
        || request_digest != request.request().request_digest()
    {
        return Err(conflict());
    }
    let key = if let Some(predecessor) = predecessor {
        LeaseRequestKey::successor(
            request.request().session(),
            operation_id,
            request.slot(),
            predecessor,
        )
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?
    } else {
        LeaseRequestKey::first(request.request().session(), operation_id, request.slot())
    };
    let receipt = claim_receipt_row(transaction, key)
        .await?
        .ok_or_else(conflict)
        .and_then(|row| decode_claim_receipt(&row, key, true))?;
    let TryClaimOutcome::Claimed(claimed) = receipt.outcome() else {
        return Err(conflict());
    };
    if claimed.assignment() != AttemptAssignment::new(request.request().session(), request.slot())
        || claimed.lease() != request.lease()
        || claimed.job_ir() != request.job_ir()
    {
        return Err(conflict());
    }
    Ok(())
}

/// Locks the attempt row even when the repository-level concurrency advisory is absent.
async fn lock_publishable_lease_offer_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &LeaseOfferClaim,
) -> Result<bool, StoreError> {
    let row = sqlx::query(
        r"
        SELECT attempt.lifecycle IN (
                   'leased', 'preparing', 'running', 'cancelling', 'finalizing'
               ) AS lifecycle_publishable,
               COALESCE(attempt.lease_id = $4
           AND attempt.fencing_token = $5
           AND attempt.runner_id = $6
           AND attempt.runner_session_id = $7
           AND attempt.runner_session_epoch = $8
           AND attempt.runner_generation = $9
           AND attempt.runner_slot = $10
           AND attempt.lease_issued_at_ms = $11
           AND attempt.lease_expires_at_ms >= $12, FALSE) AS fence_matches,
               COALESCE(attempt.job_id = $2
           AND job.run_id = $3
           AND job.job_ir_schema = $13
           AND job.job_ir_size_bytes = $14
           AND job.job_ir_digest = $15
           AND job.job_ir_object_key = $16, FALSE)
               AS metadata_matches
        FROM job_attempts AS attempt
        LEFT JOIN jobs AS job ON job.id = attempt.job_id
        WHERE attempt.id = $1
        FOR UPDATE OF attempt
        ",
    )
    .bind(request.lease().attempt_id().as_uuid())
    .bind(request.job_ir().job_id().as_uuid())
    .bind(request.job_ir().run_id().as_uuid())
    .bind(request.lease().lease_id().as_uuid())
    .bind(
        i64::try_from(request.lease().fencing_token().get()).map_err(|_| {
            StoreError::corrupt_data("lease-offer fencing token exceeds PostgreSQL BIGINT")
        })?,
    )
    .bind(request.request().session().runner_id().as_uuid())
    .bind(request.request().session().session_id().as_uuid())
    .bind(epoch_i64(request.request().session().session_epoch())?)
    .bind(generation_i64(
        request.request().session().runner_generation(),
    )?)
    .bind(i32::from(request.slot().ordinal()))
    .bind(request.lease().issued_at().get())
    .bind(request.lease().expires_at().get())
    .bind(i32::from(request.job_ir().version().get()))
    .bind(i64::try_from(request.job_ir().encoded_size()).map_err(|_| {
        StoreError::corrupt_data("lease-offer JobIR size exceeds PostgreSQL BIGINT")
    })?)
    .bind(request.job_ir().digest().as_bytes().as_slice())
    .bind(request.job_ir().object_key().as_str())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(row) = row else {
        return Ok(false);
    };
    let lifecycle_publishable = row
        .try_get::<bool, _>("lifecycle_publishable")
        .map_err(operation_error)?;
    let fence_matches = row
        .try_get::<bool, _>("fence_matches")
        .map_err(operation_error)?;
    if !lifecycle_publishable || !fence_matches {
        return Ok(false);
    }
    let metadata_matches = row
        .try_get::<bool, _>("metadata_matches")
        .map_err(operation_error)?;
    if !metadata_matches {
        return Err(StoreError::corrupt_data(
            "live lease-offer fence disagrees with immutable JobIR metadata",
        ));
    }
    let database_now = super::runner_attempt_database_now(transaction).await?;
    Ok(database_now < request.lease().expires_at())
}

#[derive(Debug, Eq, PartialEq)]
struct LockedLeaseOfferDeliveryEvidence {
    revoked_at: Option<i64>,
    revocation_reason: Option<String>,
    lifecycle_is_active: bool,
    exact_live_fence: bool,
}

async fn lock_lease_offer_delivery_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    publication: &PublishedLeaseOffer,
) -> Result<LockedLeaseOfferDeliveryEvidence, StoreError> {
    let fence = publication.request().session();
    let row = sqlx::query(
        r"
        SELECT publication.delivery_revoked_at_ms,
               publication.delivery_revocation_reason,
               attempt.lifecycle IN (
                   'leased', 'preparing', 'running', 'cancelling', 'finalizing'
               )
                   AS lifecycle_is_active,
               COALESCE(attempt.lease_id = $2
                   AND attempt.fencing_token = $3
                   AND attempt.runner_id = $4
                   AND attempt.runner_session_id = $5
                   AND attempt.runner_session_epoch = $6
                   AND attempt.runner_generation = $7
                   AND attempt.runner_slot = $8
                   AND attempt.lease_issued_at_ms = $9
                   AND attempt.lease_expires_at_ms >= $10, FALSE) AS exact_live_fence
        FROM runner_lease_offer_publications AS publication
        JOIN job_attempts AS attempt ON attempt.id = publication.attempt_id
        WHERE attempt.id = $1
          AND publication.runner_session_id = $11
          AND publication.request_operation_id = $12
          AND publication.command_sequence = $13
        FOR UPDATE OF publication, attempt
        ",
    )
    .bind(publication.lease().attempt_id().as_uuid())
    .bind(publication.lease().lease_id().as_uuid())
    .bind(fencing_i64(publication.lease().fencing_token())?)
    .bind(fence.runner_id().as_uuid())
    .bind(fence.session_id().as_uuid())
    .bind(epoch_i64(fence.session_epoch())?)
    .bind(generation_i64(fence.runner_generation())?)
    .bind(i32::from(publication.slot().ordinal()))
    .bind(publication.lease().issued_at().get())
    .bind(publication.lease().expires_at().get())
    .bind(fence.session_id().as_uuid())
    .bind(publication.request().operation_id().as_uuid())
    .bind(sequence_i64(publication.command().sequence())?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(row) = row else {
        return Err(StoreError::corrupt_data(
            "lease-offer publication disappeared during delivery classification",
        ));
    };
    Ok(LockedLeaseOfferDeliveryEvidence {
        revoked_at: row
            .try_get("delivery_revoked_at_ms")
            .map_err(operation_error)?,
        revocation_reason: row
            .try_get("delivery_revocation_reason")
            .map_err(operation_error)?,
        lifecycle_is_active: row
            .try_get("lifecycle_is_active")
            .map_err(operation_error)?,
        exact_live_fence: row.try_get("exact_live_fence").map_err(operation_error)?,
    })
}

async fn classify_locked_published_lease_offer(
    transaction: &mut Transaction<'_, Postgres>,
    publication: &PublishedLeaseOffer,
) -> Result<LockedLeaseOfferDeliveryStatus, StoreError> {
    let LockedLeaseOfferDeliveryEvidence {
        revoked_at,
        revocation_reason,
        lifecycle_is_active,
        exact_live_fence,
    } = lock_lease_offer_delivery_evidence(transaction, publication).await?;
    if let (Some(revoked_at), Some(revocation_reason)) = (revoked_at, revocation_reason.as_deref())
    {
        let reason = decode_lease_offer_delivery_revocation_reason(revocation_reason)?;
        let observed_at = UnixMillis::new(revoked_at);
        if observed_at < publication.command().request().created_at()
            || (reason == LeaseOfferDeliveryRevocationReason::AuthorityExpired
                && observed_at < publication.offer_valid_until())
        {
            return Err(StoreError::corrupt_data(
                "lease-offer publication has invalid delivery revocation evidence",
            ));
        }
        return Ok(LockedLeaseOfferDeliveryStatus::Revoked(
            LeaseOfferDeliveryRevocation {
                reason,
                observed_at,
                persisted: true,
            },
        ));
    }
    if revoked_at.is_some() || revocation_reason.is_some() {
        return Err(StoreError::corrupt_data(
            "lease-offer publication has partial delivery revocation evidence",
        ));
    }
    let database_now = super::runner_attempt_database_now(transaction).await?;
    if database_now < publication.command().request().created_at() {
        return Err(StoreError::corrupt_data(
            "lease-offer publication was observed before its creation time",
        ));
    }
    if !lifecycle_is_active || !exact_live_fence {
        return Ok(LockedLeaseOfferDeliveryStatus::Revoked(
            LeaseOfferDeliveryRevocation {
                reason: LeaseOfferDeliveryRevocationReason::AttemptSuperseded,
                observed_at: database_now,
                persisted: false,
            },
        ));
    }
    if database_now >= publication.offer_valid_until() {
        return Ok(LockedLeaseOfferDeliveryStatus::Revoked(
            LeaseOfferDeliveryRevocation {
                reason: LeaseOfferDeliveryRevocationReason::AuthorityExpired,
                observed_at: database_now,
                persisted: false,
            },
        ));
    }
    Ok(LockedLeaseOfferDeliveryStatus::Live)
}

fn decode_lease_offer_delivery_revocation_reason(
    reason: &str,
) -> Result<LeaseOfferDeliveryRevocationReason, StoreError> {
    match reason {
        "attempt_superseded" => Ok(LeaseOfferDeliveryRevocationReason::AttemptSuperseded),
        "authority_expired" => Ok(LeaseOfferDeliveryRevocationReason::AuthorityExpired),
        _ => Err(StoreError::corrupt_data(
            "lease-offer publication has an invalid delivery revocation reason",
        )),
    }
}

async fn mark_published_lease_offer_revoked(
    transaction: &mut Transaction<'_, Postgres>,
    publication: &PublishedLeaseOffer,
    revocation: LeaseOfferDeliveryRevocation,
) -> Result<(), StoreError> {
    if revocation.persisted {
        return Ok(());
    }
    let updated = sqlx::query(
        r"
        UPDATE runner_lease_offer_publications
        SET delivery_revoked_at_ms = $4,
            delivery_revocation_reason = $5
        WHERE runner_session_id = $1
          AND request_operation_id = $2
          AND command_sequence = $3
          AND delivery_revoked_at_ms IS NULL
          AND delivery_revocation_reason IS NULL
        ",
    )
    .bind(publication.request().session().session_id().as_uuid())
    .bind(publication.request().operation_id().as_uuid())
    .bind(sequence_i64(publication.command().sequence())?)
    .bind(revocation.observed_at.get())
    .bind(revocation.reason.as_str())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if updated.rows_affected() != 1 {
        return Err(StoreError::corrupt_data(
            "lease-offer delivery revocation lost its exact publication",
        ));
    }
    Ok(())
}

async fn insert_lease_offer_publication(
    transaction: &mut Transaction<'_, Postgres>,
    request: &PublishLeaseOffer,
    sequence: CommandSequence,
) -> Result<(), StoreError> {
    let inserted = sqlx::query(
        r"
        INSERT INTO runner_lease_offer_publications (
            runner_session_id, request_operation_id, runner_id,
            runner_session_epoch, runner_generation, operation_kind,
            request_digest, protocol_version, runner_slot,
            attempt_id, lease_id, fencing_token, lease_issued_at_ms,
            lease_expires_at_ms, offer_valid_until_ms, job_id, run_id, job_ir_schema,
            job_ir_size_bytes, job_ir_digest, job_ir_object_key,
            command_sequence, created_at_ms
        )
        SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
               $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23
        WHERE floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint >= $23
          AND floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint < $15
        ",
    )
    .bind(request.request().session().session_id().as_uuid())
    .bind(request.request().operation_id().as_uuid())
    .bind(request.request().session().runner_id().as_uuid())
    .bind(epoch_i64(request.request().session().session_epoch())?)
    .bind(generation_i64(
        request.request().session().runner_generation(),
    )?)
    .bind(request.request().kind().as_str())
    .bind(request.request().request_digest().as_bytes().as_slice())
    .bind(protocol_i32(request.protocol_version()))
    .bind(i32::from(request.slot().ordinal()))
    .bind(request.lease().attempt_id().as_uuid())
    .bind(request.lease().lease_id().as_uuid())
    .bind(
        i64::try_from(request.lease().fencing_token().get()).map_err(|_| {
            StoreError::corrupt_data("lease-offer fencing token exceeds PostgreSQL BIGINT")
        })?,
    )
    .bind(request.lease().issued_at().get())
    .bind(request.lease().expires_at().get())
    .bind(request.offer_valid_until().get())
    .bind(request.job_ir().job_id().as_uuid())
    .bind(request.job_ir().run_id().as_uuid())
    .bind(i32::from(request.job_ir().version().get()))
    .bind(i64::try_from(request.job_ir().encoded_size()).map_err(|_| {
        StoreError::corrupt_data("lease-offer JobIR size exceeds PostgreSQL BIGINT")
    })?)
    .bind(request.job_ir().digest().as_bytes().as_slice())
    .bind(request.job_ir().object_key().as_str())
    .bind(sequence_i64(sequence)?)
    .bind(request.command().created_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if inserted != 1 {
        return Err(StoreError::AttemptFenceRejected(
            request.lease().attempt_id(),
        ));
    }
    Ok(())
}

async fn decode_generic_receipt(
    encryption: &RunnerPayloadEncryption,
    row: &sqlx::postgres::PgRow,
    expected: &RunnerOperationRequest,
    replayed: bool,
) -> Result<RunnerOperationReceipt, StoreError> {
    let metadata = RunnerResponseEnvelopeMetadata::from_row(row)?;
    validate_response_receipt_request(&metadata, expected)?;
    if let Some(tombstone) = decode_runner_payload_tombstone(row)? {
        return Err(StoreError::RunnerPayloadUnavailable {
            session_id: expected.session().session_id(),
            tombstone,
        });
    }
    let payload = open_runner_payload(
        encryption,
        row,
        metadata.plaintext_size()?,
        &encryption.response_purpose,
        metadata.record_id(),
    )
    .await?;
    let schema = decode_schema(metadata.response_schema)?;
    let response = RunnerOperationResponse::new(schema, payload)
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    if metadata.response_digest != response.digest() {
        return Err(StoreError::corrupt_data(
            "runner operation response digest mismatch",
        ));
    }
    Ok(RunnerOperationReceipt::new(
        expected.clone(),
        response,
        UnixMillis::new(metadata.committed_at_ms),
        replayed,
    ))
}

fn validate_response_receipt_request(
    metadata: &RunnerResponseEnvelopeMetadata,
    expected: &RunnerOperationRequest,
) -> Result<(), StoreError> {
    if metadata.fence()? != expected.session()
        || metadata.operation_id != expected.operation_id().as_uuid()
        || metadata.operation_kind != expected.kind().as_str()
        || metadata.request_digest != expected.request_digest()
    {
        return Err(StoreError::OperationConflict {
            session_id: expected.session().session_id(),
            operation_id: expected.operation_id(),
        });
    }
    Ok(())
}

fn lease_request_conflict(request: LeaseRequestKey) -> StoreError {
    StoreError::OperationConflict {
        session_id: request.session().session_id(),
        operation_id: request.operation_id(),
    }
}

fn map_lease_head_write_error(error: sqlx::Error, request: LeaseRequestKey) -> StoreError {
    if matches!(&error, sqlx::Error::Database(database) if database.is_unique_violation()) {
        lease_request_conflict(request)
    } else {
        operation_error(error)
    }
}

fn lease_rpc_operation_request(
    request: BeginLeaseRequest,
) -> Result<RunnerOperationRequest, StoreError> {
    let key = request.request_key();
    let kind = RunnerOperationKind::new(LEASE_RPC_OPERATION_KIND)
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    Ok(RunnerOperationRequest::new(
        key.session(),
        key.operation_id(),
        kind,
        request.request_digest(),
    ))
}

enum LoadedLeaseRpcResponse {
    Missing,
    Completed(LeaseRequestCompletion),
}

async fn load_lease_rpc_response(
    transaction: &mut Transaction<'_, Postgres>,
    encryption: &RunnerPayloadEncryption,
    request: BeginLeaseRequest,
    replayed: bool,
) -> Result<LoadedLeaseRpcResponse, StoreError> {
    let operation = lease_rpc_operation_request(request)?;
    Ok(
        match load_generic_receipt(
            transaction,
            encryption,
            &operation,
            replayed,
            ReceiptOfferExpectation::Any,
        )
        .await?
        {
            None => LoadedLeaseRpcResponse::Missing,
            Some(LoadedGenericReceipt::Live {
                receipt,
                lease_offer_fallback,
            }) => {
                let completion = match lease_offer_fallback {
                    Some(fallback) => LeaseRequestCompletion::LiveLeaseOffer {
                        response: receipt.response().clone(),
                        fallback,
                    },
                    None => LeaseRequestCompletion::Response(receipt.response().clone()),
                };
                LoadedLeaseRpcResponse::Completed(completion)
            }
            Some(LoadedGenericReceipt::RevokedLeaseOffer {
                operation_id,
                fallback,
                ..
            }) => LoadedLeaseRpcResponse::Completed(LeaseRequestCompletion::RevokedLeaseOffer {
                offer_operation_id: operation_id,
                fallback,
            }),
        },
    )
}

async fn lock_current_lease_request_head(
    transaction: &mut Transaction<'_, Postgres>,
    request: LeaseRequestKey,
    expected_rpc_digest: Option<Sha256Digest>,
) -> Result<(), StoreError> {
    let row = sqlx::query(
        r"
        SELECT operation_id, request_digest, acknowledges_operation_id
        FROM runner_lease_request_heads
        WHERE runner_session_id = $1 AND runner_slot = $2
        FOR UPDATE
        ",
    )
    .bind(request.session().session_id().as_uuid())
    .bind(i32::from(request.slot().ordinal()))
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or_else(|| lease_request_conflict(request))?;
    let operation_id =
        OperationId::from_uuid(row.try_get("operation_id").map_err(operation_error)?);
    let predecessor = row
        .try_get::<Option<Uuid>, _>("acknowledges_operation_id")
        .map_err(operation_error)?
        .map(OperationId::from_uuid);
    let digest = decode_sha256_digest(row.try_get("request_digest").map_err(operation_error)?)
        .map_err(|error| StoreError::corrupt_data(error.clone()))?;
    if operation_id != request.operation_id()
        || predecessor != request.acknowledges_operation_id()
        || expected_rpc_digest.is_some_and(|expected| expected != digest)
    {
        return Err(lease_request_conflict(request));
    }
    Ok(())
}

async fn lock_current_lease_rpc_operation(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RunnerOperationRequest,
) -> Result<(), StoreError> {
    let row = sqlx::query(
        r"
        SELECT request_digest
        FROM runner_lease_request_heads
        WHERE runner_session_id = $1 AND operation_id = $2
        FOR UPDATE
        ",
    )
    .bind(request.session().session_id().as_uuid())
    .bind(request.operation_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(StoreError::OperationConflict {
        session_id: request.session().session_id(),
        operation_id: request.operation_id(),
    })?;
    let digest = decode_sha256_digest(row.try_get("request_digest").map_err(operation_error)?)
        .map_err(|error| StoreError::corrupt_data(error.clone()))?;
    if digest != request.request_digest() {
        return Err(StoreError::OperationConflict {
            session_id: request.session().session_id(),
            operation_id: request.operation_id(),
        });
    }
    Ok(())
}

async fn load_cancellation(
    transaction: &mut Transaction<'_, Postgres>,
    encryption: Option<&RunnerPayloadEncryption>,
    attempt_id: AttemptId,
) -> Result<Option<CancellationIntent>, StoreError> {
    let row = sqlx::query(
        r"
        SELECT cancellation.operation_id AS cancellation_operation_id,
               cancellation.requested_by, cancellation.reason,
               cancellation.requested_at_ms, cancellation.acknowledged_at_ms,
               cancellation.delivery_session_id,
               cancellation.delivery_command_sequence,
               command.runner_session_id AS command_runner_session_id,
               command.operation_id AS command_operation_id,
               command.runner_id AS command_runner_id,
               command.runner_session_epoch AS command_runner_session_epoch,
               command.runner_generation AS command_runner_generation,
               command.command_kind, command.command_schema,
               command.command_digest, command.tenant_id AS tenant_id,
               command.command_plaintext_size_bytes,
               command.envelope_schema, command.wrapping_key_id,
               command.wrapped_data_key, command.nonce, command.ciphertext,
               command.payload_tombstone_reason,
               command.payload_tombstoned_at_ms,
               command.created_at_ms AS command_created_at_ms,
               session.runner_id, session.runner_generation, session.session_epoch,
               session.protocol_version AS delivery_protocol_version,
               command.command_sequence
        FROM attempt_cancellation_intents AS cancellation
        LEFT JOIN runner_command_outbox AS command
          ON command.runner_session_id = cancellation.delivery_session_id
         AND command.command_sequence = cancellation.delivery_command_sequence
        LEFT JOIN runner_sessions AS session ON session.id = command.runner_session_id
        WHERE cancellation.attempt_id = $1
        ",
    )
    .bind(attempt_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let operation_id = OperationId::from_uuid(
        row.try_get("cancellation_operation_id")
            .map_err(operation_error)?,
    );
    let actor = CancellationActor::new(
        row.try_get::<String, _>("requested_by")
            .map_err(operation_error)?,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let reason = row
        .try_get::<Option<String>, _>("reason")
        .map_err(operation_error)?
        .map(CancellationReason::new)
        .transpose()
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let requested_at = UnixMillis::new(row.try_get("requested_at_ms").map_err(operation_error)?);
    let acknowledged_at = row
        .try_get::<Option<i64>, _>("acknowledged_at_ms")
        .map_err(operation_error)?
        .map(UnixMillis::new);
    let delivery = decode_loaded_cancellation_delivery(
        encryption,
        &row,
        attempt_id,
        reason.as_ref(),
        requested_at,
    )
    .await?;
    let mut request =
        RequestCancellation::new(operation_id, attempt_id, actor, reason, requested_at);
    if let Some(delivery) = &delivery {
        request = request.with_delivery(delivery.request().clone());
    }
    CancellationIntent::try_new(request, acknowledged_at, false, delivery)
        .map(Some)
        .map_err(|error| StoreError::corrupt_data(error.to_string()))
}

async fn decode_loaded_cancellation_delivery(
    encryption: Option<&RunnerPayloadEncryption>,
    row: &sqlx::postgres::PgRow,
    attempt_id: AttemptId,
    reason: Option<&CancellationReason>,
    requested_at: UnixMillis,
) -> Result<Option<DurableRunnerCommand>, StoreError> {
    let Some(session_id) = row
        .try_get::<Option<Uuid>, _>("delivery_session_id")
        .map_err(operation_error)?
    else {
        return Ok(None);
    };
    let runner_id = RunnerId::from_uuid(
        row.try_get::<Option<Uuid>, _>("runner_id")
            .map_err(operation_error)?
            .ok_or_else(|| StoreError::corrupt_data("cancellation delivery runner missing"))?,
    );
    let generation = decode_generation(
        row.try_get::<Option<i64>, _>("runner_generation")
            .map_err(operation_error)?
            .ok_or_else(|| StoreError::corrupt_data("cancellation delivery generation missing"))?,
    )?;
    let epoch = decode_epoch(
        row.try_get::<Option<i64>, _>("session_epoch")
            .map_err(operation_error)?
            .ok_or_else(|| StoreError::corrupt_data("cancellation delivery epoch missing"))?,
    )?;
    let fence = RunnerSessionFence::new(
        RunnerSessionId::from_uuid(session_id),
        runner_id,
        generation,
        epoch,
    );
    let encryption = encryption.ok_or(StoreError::RunnerPayloadEncryptionUnavailable)?;
    let durable = decode_outbox_command(encryption, row, fence, false).await?;
    let protocol = decode_protocol(
        row.try_get::<Option<i32>, _>("delivery_protocol_version")
            .map_err(operation_error)?
            .ok_or_else(|| StoreError::corrupt_data("cancellation delivery protocol missing"))?,
    )?;
    validate_loaded_cancel_job(&durable, attempt_id, reason, requested_at, protocol)?;
    Ok(Some(durable))
}

fn validate_loaded_cancel_job(
    delivery: &DurableRunnerCommand,
    attempt_id: AttemptId,
    reason: Option<&CancellationReason>,
    requested_at: UnixMillis,
    protocol: RunnerProtocolVersion,
) -> Result<(), StoreError> {
    let request = delivery.request();
    let payload = CancelJobCommandPayload::decode_json(request.payload().bytes())
        .map_err(|_| StoreError::corrupt_data("invalid durable cancellation command"))?;
    let expected_reason = reason.map_or(DEFAULT_CANCELLATION_REASON, CancellationReason::as_str);
    if request.kind().as_str() != CANCEL_JOB_COMMAND_KIND
        || request.payload().schema().get() != CANCEL_JOB_COMMAND_SCHEMA
        || request.created_at() != requested_at
        || payload.attempt_id() != attempt_id
        || payload.protocol_version() != protocol.get()
        || payload.reason() != expected_reason
        || payload.requested_at() != requested_at
    {
        return Err(StoreError::corrupt_data(
            "durable cancellation command does not match its intent",
        ));
    }
    Ok(())
}

fn same_cancellation_request(left: &RequestCancellation, right: &RequestCancellation) -> bool {
    left.operation_id() == right.operation_id()
        && left.attempt_id() == right.attempt_id()
        && left.actor() == right.actor()
        && left.reason() == right.reason()
        && left.requested_at() == right.requested_at()
        && left.delivery() == right.delivery()
}

fn lifecycle_is_active(lifecycle: JobLifecycle) -> bool {
    matches!(
        lifecycle,
        JobLifecycle::Leased
            | JobLifecycle::Preparing
            | JobLifecycle::Running
            | JobLifecycle::Cancelling
            | JobLifecycle::Finalizing
    )
}

async fn acknowledge_cancellations_through(
    transaction: &mut Transaction<'_, Postgres>,
    session: RunnerSessionFence,
    cursor: CommandCursor,
    acknowledged_at: UnixMillis,
) -> Result<(), StoreError> {
    let Some(sequence) = cursor.acknowledged_through() else {
        return Ok(());
    };
    sqlx::query(
        r"
        UPDATE attempt_cancellation_intents
        SET acknowledged_at_ms = $3
        WHERE delivery_session_id = $1
          AND delivery_command_sequence <= $2
          AND acknowledged_at_ms IS NULL
          AND requested_at_ms <= $3
        ",
    )
    .bind(session.session_id().as_uuid())
    .bind(sequence_i64(sequence)?)
    .bind(acknowledged_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn close_cancellation_from_result(
    transaction: &mut Transaction<'_, Postgres>,
    attempt_id: AttemptId,
    acknowledged_at: UnixMillis,
) -> Result<(), StoreError> {
    let delivery: Option<(Option<Uuid>, Option<i64>)> = sqlx::query_as(
        r"
        UPDATE attempt_cancellation_intents
        SET acknowledged_at_ms = $2
        WHERE attempt_id = $1 AND acknowledged_at_ms IS NULL
          AND requested_at_ms <= $2
        RETURNING delivery_session_id, delivery_command_sequence
        ",
    )
    .bind(attempt_id.as_uuid())
    .bind(acknowledged_at.get())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if let Some((Some(session_id), Some(sequence))) = delivery {
        tombstone_exact_command_payload(
            transaction,
            RunnerSessionId::from_uuid(session_id),
            decode_sequence(sequence)?,
            RunnerPayloadTombstoneReason::Acknowledged,
            acknowledged_at,
        )
        .await?;
    }
    Ok(())
}

fn decode_optional_attempt_session(
    row: &sqlx::postgres::PgRow,
) -> Result<Option<RunnerSessionFence>, StoreError> {
    let runner_id: Option<Uuid> = row.try_get("runner_id").map_err(operation_error)?;
    let session_id: Option<Uuid> = row.try_get("runner_session_id").map_err(operation_error)?;
    let epoch: Option<i64> = row
        .try_get("runner_session_epoch")
        .map_err(operation_error)?;
    let generation: Option<i64> = row.try_get("runner_generation").map_err(operation_error)?;
    let slot: Option<i32> = row.try_get("runner_slot").map_err(operation_error)?;
    match (runner_id, session_id, epoch, generation, slot) {
        (None, None, None, None, None) => Ok(None),
        (Some(runner_id), Some(session_id), Some(epoch), Some(generation), Some(slot)) => {
            let slot = u16::try_from(slot)
                .ok()
                .and_then(|value| StableRunnerSlot::new(value).ok())
                .ok_or_else(|| StoreError::corrupt_data("invalid attempt runner slot"))?;
            let _ = slot;
            Ok(Some(RunnerSessionFence::new(
                RunnerSessionId::from_uuid(session_id),
                RunnerId::from_uuid(runner_id),
                decode_generation(generation)?,
                decode_epoch(epoch)?,
            )))
        }
        _ => Err(StoreError::corrupt_data(
            "partial active attempt session assignment",
        )),
    }
}

#[async_trait]
impl RunnerClaimRepository for PostgresStore {
    async fn lookup_lease_request(
        &self,
        request: LeaseRequestKey,
    ) -> Result<Option<TryClaimReceipt>, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::pin_runner_attempt_read_committed(&mut transaction).await?;
        lock_live_routing(&mut transaction, request.session())
            .await?
            .require_online(request.session())?;
        lock_current_lease_request_head(&mut transaction, request, None).await?;
        let row = claim_receipt_row(&mut transaction, request).await?;
        let receipt = if let Some(row) = row.as_ref() {
            let receipt = decode_claim_receipt(row, request, true)?;
            Some(resolve_claim_receipt(&mut transaction, receipt).await?)
        } else {
            None
        };
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }

    async fn try_claim(&self, mut request: TryClaimAttempt) -> Result<TryClaimReceipt, StoreError> {
        let caller_observed_at = request.observed_at();
        let cursor = automata_ci_control::adapter_spi::try_claim_attempt_cursor(&request);
        let requested_duration =
            super::runner_attempt_requested_duration(request.observed_at(), request.expires_at())?;
        let digest = request.request_digest();
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::pin_runner_attempt_read_committed(&mut transaction).await?;
        super::admission::lock_attempt_concurrency(&mut transaction, request.attempt_id()).await?;
        let routing = lock_live_routing(&mut transaction, request.session()).await?;
        routing.require_online(request.session())?;
        lock_current_lease_request_head(&mut transaction, request.request_key(), None).await?;

        let inserted = sqlx::query(
            r"
            INSERT INTO runner_operation_receipts (
                runner_session_id, operation_id, runner_id,
                runner_session_epoch, runner_generation, operation_kind,
                selection_kind,
                request_digest, requested_attempt_id, requested_lease_id,
                runner_slot, scan_cursor_version, observed_at_ms,
                lease_expires_at_ms, outcome
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, 'claim', $7, $8, $9, $10, $11, $12, $13,
                'pending'
            )
            ON CONFLICT (runner_session_id, operation_id) DO NOTHING
            ",
        )
        .bind(request.session().session_id().as_uuid())
        .bind(request.operation_id().as_uuid())
        .bind(request.session().runner_id().as_uuid())
        .bind(epoch_i64(request.session().session_epoch())?)
        .bind(generation_i64(request.session().runner_generation())?)
        .bind(LEASE_OPERATION_KIND)
        .bind(digest.as_bytes().as_slice())
        .bind(request.attempt_id().as_uuid())
        .bind(request.lease_id().as_uuid())
        .bind(i32::from(request.slot().ordinal()))
        .bind(cursor_version_i64(cursor.expected_version())?)
        .bind(request.observed_at().get())
        .bind(request.expires_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?
        .rows_affected();

        if inserted == 0 {
            let receipt = replay_claim(&mut transaction, request.request_key()).await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(receipt);
        }

        let admission_now = super::runner_attempt_database_now(&mut transaction).await?;
        super::validate_runner_attempt_caller_clock(caller_observed_at, admission_now)?;
        rebase_claim_request(&mut request, admission_now, requested_duration)?;

        let (outcome, committed_cursor) = if routing.online && routing.accepts_new_work {
            let committed_cursor =
                advance_scan_cursor(&mut transaction, cursor, &routing, request.observed_at())
                    .await?;
            let outcome = if committed_cursor.is_some() {
                evaluate_claim(
                    &mut transaction,
                    &mut request,
                    &routing,
                    caller_observed_at,
                    requested_duration,
                )
                .await?
            } else {
                TryClaimOutcome::Rejected(ClaimRejection::ScanSuperseded)
            };
            (outcome, committed_cursor)
        } else {
            (TryClaimOutcome::Rejected(ClaimRejection::NotRoutable), None)
        };
        complete_claim_receipt(&mut transaction, &request, &outcome, committed_cursor).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(TryClaimReceipt::new(request.request_key(), outcome, false))
    }

    async fn record_no_work(
        &self,
        request: NoWorkLeaseRequest,
    ) -> Result<TryClaimReceipt, StoreError> {
        let request_key = request.request_key();
        let cursor = automata_ci_control::adapter_spi::no_work_lease_request_cursor(&request);
        let digest = request_key.request_digest();
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::pin_runner_attempt_read_committed(&mut transaction).await?;
        let routing = lock_live_routing(&mut transaction, request_key.session()).await?;
        routing.require_online(request_key.session())?;
        lock_current_lease_request_head(&mut transaction, request_key, None).await?;
        let inserted = sqlx::query(
            r"
            INSERT INTO runner_operation_receipts (
                runner_session_id, operation_id, runner_id,
                runner_session_epoch, runner_generation, operation_kind,
                selection_kind, request_digest, runner_slot,
                scan_cursor_version, observed_at_ms, outcome
            )
            VALUES ($1, $2, $3, $4, $5, $6, 'no_work', $7, $8, $9, $10, 'pending')
            ON CONFLICT (runner_session_id, operation_id) DO NOTHING
            ",
        )
        .bind(request_key.session().session_id().as_uuid())
        .bind(request_key.operation_id().as_uuid())
        .bind(request_key.session().runner_id().as_uuid())
        .bind(epoch_i64(request_key.session().session_epoch())?)
        .bind(generation_i64(request_key.session().runner_generation())?)
        .bind(LEASE_OPERATION_KIND)
        .bind(digest.as_bytes().as_slice())
        .bind(i32::from(request_key.slot().ordinal()))
        .bind(cursor_version_i64(cursor.expected_version())?)
        .bind(request.observed_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?
        .rows_affected();
        let receipt = if inserted == 1 {
            let (outcome, committed_cursor) = if routing.online && routing.accepts_new_work {
                let committed_cursor =
                    advance_scan_cursor(&mut transaction, cursor, &routing, request.observed_at())
                        .await?;
                let outcome = if committed_cursor.is_some() {
                    TryClaimOutcome::NoWork
                } else {
                    TryClaimOutcome::Rejected(ClaimRejection::ScanSuperseded)
                };
                (outcome, committed_cursor)
            } else {
                (TryClaimOutcome::Rejected(ClaimRejection::NotRoutable), None)
            };
            complete_no_work_receipt(&mut transaction, &request, &outcome, committed_cursor)
                .await?;
            TryClaimReceipt::new(request_key, outcome, false)
        } else {
            replay_claim(&mut transaction, request_key).await?
        };
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }
}

#[async_trait]
impl WorkflowPlanRepository for PostgresStore {
    async fn get_job_ir_metadata(&self, job_id: JobId) -> Result<JobIrMetadata, StoreError> {
        let row = sqlx::query(
            r"
            SELECT run_id, job_ir_schema, job_ir_size_bytes,
                   job_ir_digest, job_ir_object_key
            FROM jobs
            WHERE id = $1
            ",
        )
        .bind(job_id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(operation_error)?
        .ok_or(StoreError::JobNotFound(job_id))?;
        let run_id = RunId::from_uuid(row.try_get("run_id").map_err(operation_error)?);
        let version =
            decode_job_ir_version(row.try_get("job_ir_schema").map_err(operation_error)?)?;
        let size = u64::try_from(
            row.try_get::<i64, _>("job_ir_size_bytes")
                .map_err(operation_error)?,
        )
        .map_err(|_| StoreError::corrupt_data("negative JobIR size"))?;
        let digest = decode_sha256_digest(row.try_get("job_ir_digest").map_err(operation_error)?)
            .map_err(|error| StoreError::corrupt_data(error.clone()))?;
        let key = ObjectKey::new(
            row.try_get::<String, _>("job_ir_object_key")
                .map_err(operation_error)?,
        )
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
        JobIrMetadata::new(job_id, run_id, version, size, digest, key)
            .map_err(|error| StoreError::corrupt_data(error.to_string()))
    }

    async fn insert_dependency(&self, dependency: JobDependency) -> Result<(), StoreError> {
        sqlx::query(
            r"
            INSERT INTO job_dependencies (run_id, job_id, prerequisite_job_id)
            VALUES ($1, $2, $3)
            ON CONFLICT (run_id, job_id, prerequisite_job_id) DO NOTHING
            ",
        )
        .bind(dependency.run_id().as_uuid())
        .bind(dependency.job_id().as_uuid())
        .bind(dependency.prerequisite_job_id().as_uuid())
        .execute(&self.pool)
        .await
        .map_err(operation_error)?;
        Ok(())
    }
}

#[async_trait]
impl CancellationRepository for PostgresStore {
    async fn request_cancellation(
        &self,
        request: RequestCancellation,
    ) -> Result<CancellationIntent, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let intent = request_cancellation_in_transaction(
            &mut transaction,
            self.runner_payload_encryption.as_ref(),
            request,
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(intent)
    }

    async fn cancellation_for_attempt(
        &self,
        attempt_id: AttemptId,
    ) -> Result<Option<CancellationIntent>, StoreError> {
        let encryption = self.runner_payload_encryption.as_ref();
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let intent = load_cancellation(&mut transaction, encryption, attempt_id).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(intent)
    }
}

/// Runs the canonical cancellation state machine inside a caller-owned
/// transaction. Gate-like schedulability authorities use this to make their
/// terminal transition atomic with the cancellation intent, queued terminal
/// result, attempt transition, and run reconciliation.
pub(super) async fn request_cancellation_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    encryption: Option<&RunnerPayloadEncryption>,
    request: RequestCancellation,
) -> Result<CancellationIntent, StoreError> {
    super::admission::lock_attempt_concurrency(transaction, request.attempt_id()).await?;
    lock_cancellation_routing(transaction, &request).await?;
    let attempt = lock_cancellation_attempt(transaction, request.attempt_id()).await?;
    if let Some(existing) = load_cancellation(transaction, encryption, request.attempt_id()).await?
    {
        if same_cancellation_request(existing.request(), &request) {
            if super::server_cancellation_terminal::server_cancellation_terminal_exists(
                transaction,
                request.attempt_id(),
            )
            .await?
            {
                super::server_cancellation_terminal::verify_queued_server_cancellation_terminal(
                    transaction,
                    existing.request(),
                )
                .await?;
            }
            return CancellationIntent::try_new(
                existing.request().clone(),
                existing.acknowledged_at(),
                true,
                existing.delivery().cloned(),
            )
            .map_err(|error| StoreError::corrupt_data(error.to_string()));
        }
        return Err(StoreError::ImmutableConflict("cancellation intent"));
    }
    if request.requested_at() < attempt.changed_at {
        return Err(StoreError::AttemptTimeRegression {
            attempt_id: request.attempt_id(),
            observed_at: request.requested_at(),
            changed_at: attempt.changed_at,
        });
    }
    let durable_delivery =
        prepare_cancellation_delivery(transaction, encryption, &request, &attempt).await?;
    insert_cancellation_intent(transaction, &request, durable_delivery.as_ref()).await?;
    if attempt.lifecycle == JobLifecycle::Queued {
        super::server_cancellation_terminal::insert_queued_server_cancellation_terminal(
            transaction,
            &request,
        )
        .await?;
    }
    transition_cancelled_attempt(transaction, &request, attempt.lifecycle).await?;
    super::admission::reconcile_attempt_run(
        transaction,
        request.attempt_id(),
        request.requested_at(),
    )
    .await?;
    CancellationIntent::try_new(request, None, false, durable_delivery)
        .map_err(|error| StoreError::corrupt_data(error.to_string()))
}

#[derive(Clone, Copy, Debug)]
struct LockedCancellationAttempt {
    lifecycle: JobLifecycle,
    changed_at: UnixMillis,
    lease_expires_at: Option<UnixMillis>,
    session: Option<RunnerSessionFence>,
    guard: Option<LeaseGuard>,
    protocol_version: Option<RunnerProtocolVersion>,
}

async fn lock_cancellation_routing(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RequestCancellation,
) -> Result<(), StoreError> {
    let row = sqlx::query(
        r"
        SELECT lifecycle, runner_id, runner_session_id,
               runner_session_epoch, runner_generation, runner_slot
        FROM job_attempts
        WHERE id = $1
        ",
    )
    .bind(request.attempt_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(StoreError::AttemptNotFound(request.attempt_id()))?;
    let lifecycle = parse_lifecycle_store(row.try_get("lifecycle").map_err(operation_error)?)?;
    if !lifecycle_is_active(lifecycle) {
        return Ok(());
    }
    let delivery = request
        .delivery()
        .ok_or(StoreError::CancellationDeliveryRequired(
            request.attempt_id(),
        ))?;
    if decode_optional_attempt_session(&row)? != Some(delivery.session()) {
        return Err(StoreError::CancellationDeliveryMismatch(
            request.attempt_id(),
        ));
    }
    lock_live_routing(transaction, delivery.session())
        .await?
        .require_online(delivery.session())
}

async fn lock_cancellation_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    attempt_id: AttemptId,
) -> Result<LockedCancellationAttempt, StoreError> {
    let row = sqlx::query(
        r"
        SELECT attempt.lifecycle, attempt.changed_at_ms, attempt.lease_expires_at_ms,
               attempt.lease_id, attempt.fencing_token, attempt.runner_id,
               attempt.runner_session_id, attempt.runner_session_epoch,
               attempt.runner_generation, attempt.runner_slot, session.protocol_version
        FROM job_attempts AS attempt
        LEFT JOIN runner_sessions AS session
          ON session.id = attempt.runner_session_id
         AND session.runner_id = attempt.runner_id
         AND session.runner_generation = attempt.runner_generation
         AND session.session_epoch = attempt.runner_session_epoch
        WHERE attempt.id = $1
        FOR UPDATE OF attempt
        ",
    )
    .bind(attempt_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(StoreError::AttemptNotFound(attempt_id))?;
    decode_cancellation_attempt(&row)
}

fn decode_cancellation_attempt(
    row: &sqlx::postgres::PgRow,
) -> Result<LockedCancellationAttempt, StoreError> {
    let lifecycle = parse_lifecycle_store(row.try_get("lifecycle").map_err(operation_error)?)?;
    let lease_id = row
        .try_get::<Option<Uuid>, _>("lease_id")
        .map_err(operation_error)?
        .map(LeaseId::from_uuid);
    let raw_fence: i64 = row.try_get("fencing_token").map_err(operation_error)?;
    let guard = lease_id
        .map(|lease_id| decode_fencing(raw_fence).map(|fence| LeaseGuard::new(lease_id, fence)))
        .transpose()?;
    let protocol_version = row
        .try_get::<Option<i32>, _>("protocol_version")
        .map_err(operation_error)?
        .map(decode_protocol)
        .transpose()?;
    Ok(LockedCancellationAttempt {
        lifecycle,
        changed_at: UnixMillis::new(row.try_get("changed_at_ms").map_err(operation_error)?),
        lease_expires_at: row
            .try_get::<Option<i64>, _>("lease_expires_at_ms")
            .map_err(operation_error)?
            .map(UnixMillis::new),
        session: decode_optional_attempt_session(row)?,
        guard,
        protocol_version,
    })
}

async fn prepare_cancellation_delivery(
    transaction: &mut Transaction<'_, Postgres>,
    encryption: Option<&RunnerPayloadEncryption>,
    request: &RequestCancellation,
    attempt: &LockedCancellationAttempt,
) -> Result<Option<DurableRunnerCommand>, StoreError> {
    if !lifecycle_is_active(attempt.lifecycle) {
        if request.delivery().is_some() {
            return Err(StoreError::CancellationDeliveryMismatch(
                request.attempt_id(),
            ));
        }
        return Ok(None);
    }
    let delivery = request
        .delivery()
        .ok_or(StoreError::CancellationDeliveryRequired(
            request.attempt_id(),
        ))?;
    validate_cancel_job_delivery(request, attempt, delivery)?;
    let expires_at = attempt
        .lease_expires_at
        .ok_or_else(|| StoreError::corrupt_data("active attempt lacks lease expiry"))?;
    if request.requested_at() >= expires_at {
        return Err(StoreError::AttemptFenceRejected(request.attempt_id()));
    }
    let encryption = encryption.ok_or(StoreError::RunnerPayloadEncryptionUnavailable)?;
    enqueue_cancellation_command_in_transaction(transaction, encryption, delivery.clone())
        .await
        .map(Some)
}

fn validate_cancel_job_delivery(
    request: &RequestCancellation,
    attempt: &LockedCancellationAttempt,
    delivery: &EnqueueRunnerCommand,
) -> Result<(), StoreError> {
    let expected_reason = request
        .reason()
        .map_or(DEFAULT_CANCELLATION_REASON, CancellationReason::as_str);
    let payload = CancelJobCommandPayload::decode_json(delivery.payload().bytes())
        .map_err(|_| StoreError::CancellationDeliveryMismatch(request.attempt_id()))?;
    let exact = delivery.kind().as_str() == CANCEL_JOB_COMMAND_KIND
        && delivery.payload().schema().get() == CANCEL_JOB_COMMAND_SCHEMA
        && delivery.created_at() == request.requested_at()
        && attempt.session == Some(delivery.session())
        && Some(payload.guard()) == attempt.guard
        && Some(payload.protocol_version())
            == attempt.protocol_version.map(RunnerProtocolVersion::get)
        && payload.attempt_id() == request.attempt_id()
        && payload.requested_at() == request.requested_at()
        && payload.reason() == expected_reason;
    if exact {
        Ok(())
    } else {
        Err(StoreError::CancellationDeliveryMismatch(
            request.attempt_id(),
        ))
    }
}

async fn insert_cancellation_intent(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RequestCancellation,
    delivery: Option<&DurableRunnerCommand>,
) -> Result<(), StoreError> {
    sqlx::query(
        r"
        INSERT INTO attempt_cancellation_intents (
            attempt_id, operation_id, requested_by, reason, requested_at_ms,
            delivery_session_id, delivery_command_sequence
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        ",
    )
    .bind(request.attempt_id().as_uuid())
    .bind(request.operation_id().as_uuid())
    .bind(request.actor().as_str())
    .bind(request.reason().map(CancellationReason::as_str))
    .bind(request.requested_at().get())
    .bind(delivery.map(|value| value.request().session().session_id().as_uuid()))
    .bind(
        delivery
            .map(DurableRunnerCommand::sequence)
            .map(sequence_i64)
            .transpose()?,
    )
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn transition_cancelled_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RequestCancellation,
    lifecycle: JobLifecycle,
) -> Result<(), StoreError> {
    let next = if lifecycle == JobLifecycle::Queued {
        Some("cancelled")
    } else if lifecycle_is_active(lifecycle) && lifecycle != JobLifecycle::Cancelling {
        Some("cancelling")
    } else {
        None
    };
    let Some(next) = next else {
        return Ok(());
    };
    sqlx::query(
        r"
        UPDATE job_attempts
        SET lifecycle = $2, changed_at_ms = $3
        WHERE id = $1 AND changed_at_ms <= $3
        ",
    )
    .bind(request.attempt_id().as_uuid())
    .bind(next)
    .bind(request.requested_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

#[async_trait]
impl BlockedAttemptRepository for PostgresStore {
    async fn scan_blocked(
        &self,
        limit: RunnableScanLimit,
        observed_at: UnixMillis,
    ) -> Result<Vec<BlockedAttempt>, StoreError> {
        let rows = sqlx::query(
            r"
            SELECT attempt.id AS attempt_id, attempt.job_id,
                   job.run_id, attempt.queued_at_ms
            FROM job_attempts AS attempt
            JOIN jobs AS job ON job.id = attempt.job_id
            JOIN workflow_runs AS run ON run.id = job.run_id
            WHERE attempt.lifecycle = 'queued'
              AND attempt.queued_at_ms <= $1
              AND run.status IN ('queued', 'in_progress')
              AND NOT EXISTS (
                  SELECT 1 FROM attempt_cancellation_intents AS cancellation
                  WHERE cancellation.attempt_id = attempt.id
              )
              AND EXISTS (
                  SELECT 1
                  FROM job_dependencies AS dependency
                  WHERE dependency.run_id = job.run_id
                    AND dependency.job_id = job.id
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM job_dependencies AS dependency
                  WHERE dependency.run_id = job.run_id
                    AND dependency.job_id = job.id
                    AND coalesce((
                        SELECT prerequisite_attempt.lifecycle
                        FROM job_attempts AS prerequisite_attempt
                        WHERE prerequisite_attempt.job_id = dependency.prerequisite_job_id
                        ORDER BY prerequisite_attempt.attempt_number DESC
                        LIMIT 1
                    ), '') NOT IN (
                        'succeeded', 'failed', 'cancelled', 'timed_out',
                        'skipped', 'lost'
                    )
              )
              AND EXISTS (
                  SELECT 1
                  FROM job_dependencies AS dependency
                  WHERE dependency.run_id = job.run_id
                    AND dependency.job_id = job.id
                    AND (
                        SELECT prerequisite_attempt.lifecycle
                        FROM job_attempts AS prerequisite_attempt
                        WHERE prerequisite_attempt.job_id = dependency.prerequisite_job_id
                        ORDER BY prerequisite_attempt.attempt_number DESC
                        LIMIT 1
                    ) IN ('failed', 'cancelled', 'timed_out', 'skipped', 'lost')
              )
            ORDER BY attempt.queued_at_ms, attempt.id
            LIMIT $2
            ",
        )
        .bind(observed_at.get())
        .bind(i64::from(limit.get()))
        .fetch_all(&self.pool)
        .await
        .map_err(operation_error)?;
        rows.iter()
            .map(|row| {
                Ok(BlockedAttempt::new(
                    AttemptId::from_uuid(row.try_get("attempt_id").map_err(operation_error)?),
                    JobId::from_uuid(row.try_get("job_id").map_err(operation_error)?),
                    RunId::from_uuid(row.try_get("run_id").map_err(operation_error)?),
                    UnixMillis::new(row.try_get("queued_at_ms").map_err(operation_error)?),
                ))
            })
            .collect()
    }

    #[allow(clippy::too_many_lines)]
    async fn conclude_blocked(
        &self,
        request: ConcludeBlockedAttempt,
    ) -> Result<BlockedConclusion, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::admission::lock_attempt_concurrency(&mut transaction, request.attempt_id()).await?;
        let row = sqlx::query(
            r"
            SELECT attempt.lifecycle, attempt.changed_at_ms, job.id AS job_id,
                   job.run_id, run.status AS run_status,
                   EXISTS (
                       SELECT 1 FROM attempt_cancellation_intents AS cancellation
                       WHERE cancellation.attempt_id = attempt.id
                   ) AS has_cancellation
            FROM job_attempts AS attempt
            JOIN jobs AS job ON job.id = attempt.job_id
            JOIN workflow_runs AS run ON run.id = job.run_id
            WHERE attempt.id = $1
            FOR UPDATE OF attempt, run
            ",
        )
        .bind(request.attempt_id().as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?
        .ok_or(StoreError::AttemptNotFound(request.attempt_id()))?;
        let lifecycle = parse_lifecycle_store(row.try_get("lifecycle").map_err(operation_error)?)?;
        if lifecycle == JobLifecycle::Skipped {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(BlockedConclusion::AlreadySkipped);
        }
        if lifecycle != JobLifecycle::Queued {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(BlockedConclusion::NotQueued(lifecycle));
        }
        let changed_at = UnixMillis::new(row.try_get("changed_at_ms").map_err(operation_error)?);
        if request.observed_at() < changed_at {
            return Err(StoreError::AttemptTimeRegression {
                attempt_id: request.attempt_id(),
                observed_at: request.observed_at(),
                changed_at,
            });
        }
        let run_status: &str = row.try_get("run_status").map_err(operation_error)?;
        let has_cancellation: bool = row.try_get("has_cancellation").map_err(operation_error)?;
        if !matches!(run_status, "queued" | "in_progress") || has_cancellation {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(BlockedConclusion::NoLongerBlocked);
        }
        let job_id: Uuid = row.try_get("job_id").map_err(operation_error)?;
        let run_id: Uuid = row.try_get("run_id").map_err(operation_error)?;
        let prerequisite_jobs = sqlx::query_scalar::<_, Uuid>(
            r"
            SELECT prerequisite.id
            FROM job_dependencies AS dependency
            JOIN jobs AS prerequisite
              ON prerequisite.run_id = dependency.run_id
             AND prerequisite.id = dependency.prerequisite_job_id
            WHERE dependency.run_id = $1 AND dependency.job_id = $2
            ORDER BY prerequisite.id
            FOR UPDATE OF prerequisite
            ",
        )
        .bind(run_id)
        .bind(job_id)
        .fetch_all(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if prerequisite_jobs.is_empty() {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(BlockedConclusion::NoLongerBlocked);
        }
        let latest_rows = sqlx::query(
            r"
            SELECT dependency.prerequisite_job_id, latest.lifecycle
            FROM job_dependencies AS dependency
            LEFT JOIN LATERAL (
                SELECT prerequisite_attempt.lifecycle
                FROM job_attempts AS prerequisite_attempt
                WHERE prerequisite_attempt.job_id = dependency.prerequisite_job_id
                ORDER BY prerequisite_attempt.attempt_number DESC
                LIMIT 1
                FOR UPDATE
            ) AS latest ON TRUE
            WHERE dependency.run_id = $1 AND dependency.job_id = $2
            ORDER BY dependency.prerequisite_job_id
            ",
        )
        .bind(run_id)
        .bind(job_id)
        .fetch_all(&mut *transaction)
        .await
        .map_err(operation_error)?;
        let mut has_non_success = false;
        for latest in latest_rows {
            let lifecycle = latest
                .try_get::<Option<&str>, _>("lifecycle")
                .map_err(operation_error)?
                .map(parse_lifecycle_store)
                .transpose()?;
            let Some(lifecycle) = lifecycle else {
                transaction.commit().await.map_err(operation_error)?;
                return Ok(BlockedConclusion::NoLongerBlocked);
            };
            if !lifecycle.is_terminal() {
                transaction.commit().await.map_err(operation_error)?;
                return Ok(BlockedConclusion::NoLongerBlocked);
            }
            has_non_success |= lifecycle != JobLifecycle::Succeeded;
        }
        if !has_non_success {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(BlockedConclusion::NoLongerBlocked);
        }
        let updated = sqlx::query(
            r"
            UPDATE job_attempts
            SET lifecycle = 'skipped', changed_at_ms = $2
            WHERE id = $1 AND lifecycle = 'queued' AND changed_at_ms <= $2
            ",
        )
        .bind(request.attempt_id().as_uuid())
        .bind(request.observed_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if updated.rows_affected() != 1 {
            return Err(StoreError::corrupt_data(
                "locked blocked conclusion did not update exactly one attempt",
            ));
        }
        super::admission::reconcile_attempt_run(
            &mut transaction,
            request.attempt_id(),
            request.observed_at(),
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(BlockedConclusion::Skipped)
    }
}

#[async_trait]
impl RunnableAttemptRepository for PostgresStore {
    async fn scan_runnable(
        &self,
        request: RunnableScanRequest,
    ) -> Result<RunnableScanPage, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let routing = lock_live_routing(&mut transaction, request.session()).await?;
        routing.require_online(request.session())?;
        if !routing.slots.contains(request.slot()) {
            return Err(StoreError::SlotOutOfRange {
                session_id: request.session().session_id(),
                slot: request.slot(),
            });
        }

        let fingerprint = routing_fingerprint(&routing, request.session().runner_generation())?;
        if !routing.accepts_new_work {
            let page = RunnableScanPage::try_new(
                request.session(),
                request.slot(),
                fingerprint,
                0,
                None,
                Vec::new(),
            )
            .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(page);
        }
        let stored = load_scan_cursor(&mut transaction, request.session(), request.slot()).await?;
        let expected_version = stored.as_ref().map_or(0, |cursor| cursor.version);
        let (after, upper) = stored
            .filter(|cursor| {
                cursor.routing_fingerprint == fingerprint
                    && cursor.runner_generation == request.session().runner_generation()
            })
            .map_or((None, None), |cursor| (cursor.after, cursor.cycle_upper));

        let mut cycle_upper = upper;
        let mut rows = if let Some(upper) = cycle_upper {
            if after.is_none_or(|after| after < upper) {
                scan_page_rows(&mut transaction, &routing, after, upper, request).await?
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // An exhausted finite cycle wraps exactly once. Capturing the new
        // high-water mark before reading the page prevents continuous arrivals
        // from keeping the scan in one non-terminating cycle.
        if rows.is_empty() {
            cycle_upper = scan_cycle_upper(&mut transaction, &routing, request).await?;
            rows = if let Some(upper) = cycle_upper {
                scan_page_rows(&mut transaction, &routing, None, upper, request).await?
            } else {
                Vec::new()
            };
        }

        let candidates = rows
            .iter()
            .map(decode_runnable_attempt)
            .collect::<Result<Vec<_>, _>>()?;
        let page = RunnableScanPage::try_new(
            request.session(),
            request.slot(),
            fingerprint,
            expected_version,
            cycle_upper,
            candidates,
        )
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(page)
    }
}

#[derive(Clone, Debug)]
struct StoredScanCursor {
    runner_generation: RunnerGeneration,
    routing_fingerprint: Sha256Digest,
    version: u64,
    after: Option<RunnableQueueKey>,
    cycle_upper: Option<RunnableQueueKey>,
}

async fn load_scan_cursor(
    transaction: &mut Transaction<'_, Postgres>,
    session: RunnerSessionFence,
    slot: StableRunnerSlot,
) -> Result<Option<StoredScanCursor>, StoreError> {
    let row = sqlx::query(
        r"
        SELECT runner_generation, routing_fingerprint, cursor_version,
               after_queued_at_ms, after_attempt_id,
               cycle_upper_queued_at_ms, cycle_upper_attempt_id
        FROM runner_queue_cursors
        WHERE runner_id = $1 AND runner_slot = $2
        FOR UPDATE
        ",
    )
    .bind(session.runner_id().as_uuid())
    .bind(i32::from(slot.ordinal()))
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    row.as_ref().map(decode_scan_cursor).transpose()
}

fn decode_scan_cursor(row: &sqlx::postgres::PgRow) -> Result<StoredScanCursor, StoreError> {
    let version = u64::try_from(
        row.try_get::<i64, _>("cursor_version")
            .map_err(operation_error)?,
    )
    .ok()
    .filter(|version| *version > 0)
    .ok_or_else(|| StoreError::corrupt_data("invalid runnable cursor version"))?;
    Ok(StoredScanCursor {
        runner_generation: decode_generation(
            row.try_get("runner_generation").map_err(operation_error)?,
        )?,
        routing_fingerprint: decode_sha256_digest(
            row.try_get("routing_fingerprint")
                .map_err(operation_error)?,
        )
        .map_err(|error| StoreError::corrupt_data(error.clone()))?,
        version,
        after: decode_queue_key(row, "after_queued_at_ms", "after_attempt_id")?,
        cycle_upper: decode_queue_key(row, "cycle_upper_queued_at_ms", "cycle_upper_attempt_id")?,
    })
}

fn decode_queue_key(
    row: &sqlx::postgres::PgRow,
    time_column: &str,
    id_column: &str,
) -> Result<Option<RunnableQueueKey>, StoreError> {
    let queued_at = row
        .try_get::<Option<i64>, _>(time_column)
        .map_err(operation_error)?;
    let attempt_id = row
        .try_get::<Option<Uuid>, _>(id_column)
        .map_err(operation_error)?;
    match (queued_at, attempt_id) {
        (None, None) => Ok(None),
        (Some(time), Some(id)) => Ok(Some(RunnableQueueKey::new(
            UnixMillis::new(time),
            AttemptId::from_uuid(id),
        ))),
        _ => Err(StoreError::corrupt_data(
            "partial runnable queue cursor key",
        )),
    }
}

async fn scan_cycle_upper(
    transaction: &mut Transaction<'_, Postgres>,
    routing: &LockedRouting,
    request: RunnableScanRequest,
) -> Result<Option<RunnableQueueKey>, StoreError> {
    let row = sqlx::query(
        r"
        SELECT attempt.queued_at_ms, attempt.id AS attempt_id
        FROM job_attempts AS attempt
        JOIN jobs AS job ON job.id = attempt.job_id
        JOIN workflow_runs AS run ON run.id = job.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        WHERE repository.tenant_id = $1
          AND job.admission_epoch = $4
          AND job.job_ir_schema = $2
          AND attempt.lifecycle = 'queued'
          AND attempt.queued_at_ms <= $3
          AND run.status IN ('queued', 'in_progress')
          AND NOT EXISTS (
              SELECT 1 FROM attempt_cancellation_intents AS cancellation
              WHERE cancellation.attempt_id = attempt.id
          )
          AND (
              run.concurrency_group_key IS NULL
              OR EXISTS (
                  SELECT 1 FROM concurrency_groups AS concurrency
                  WHERE concurrency.repository_id = run.repository_id
                    AND concurrency.normalized_key = run.concurrency_group_key
                    AND concurrency.running_run_id = run.id
              )
          )
          AND NOT EXISTS (
              SELECT 1
              FROM job_dependencies AS dependency
              WHERE dependency.run_id = job.run_id
                AND dependency.job_id = job.id
                AND coalesce((
                    SELECT prerequisite_attempt.lifecycle
                    FROM job_attempts AS prerequisite_attempt
                    WHERE prerequisite_attempt.job_id = dependency.prerequisite_job_id
                    ORDER BY prerequisite_attempt.attempt_number DESC
                    LIMIT 1
                ), '') <> 'succeeded'
          )
        ORDER BY attempt.queued_at_ms DESC, attempt.id DESC
        LIMIT 1
        ",
    )
    .bind(&routing.tenant_id)
    .bind(i32::from(routing.job_ir_version.get()))
    .bind(request.observed_at().get())
    .bind(i32::from(WORKFLOW_ADMISSION_EPOCH))
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    row.as_ref()
        .map(|row| {
            Ok(RunnableQueueKey::new(
                UnixMillis::new(row.try_get("queued_at_ms").map_err(operation_error)?),
                AttemptId::from_uuid(row.try_get("attempt_id").map_err(operation_error)?),
            ))
        })
        .transpose()
}

async fn scan_page_rows(
    transaction: &mut Transaction<'_, Postgres>,
    routing: &LockedRouting,
    after: Option<RunnableQueueKey>,
    upper: RunnableQueueKey,
    request: RunnableScanRequest,
) -> Result<Vec<sqlx::postgres::PgRow>, StoreError> {
    sqlx::query(
        r"
        SELECT attempt.id AS attempt_id, attempt.job_id, attempt.queued_at_ms,
               job.run_id, job.requirements, job.job_ir_schema,
               job.job_ir_size_bytes, job.job_ir_digest, job.job_ir_object_key
        FROM job_attempts AS attempt
        JOIN jobs AS job ON job.id = attempt.job_id
        JOIN workflow_runs AS run ON run.id = job.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        WHERE repository.tenant_id = $1
          AND job.admission_epoch = $9
          AND job.job_ir_schema = $2
          AND attempt.lifecycle = 'queued'
          AND attempt.queued_at_ms <= $3
          AND (
              $4::BIGINT IS NULL
              OR (attempt.queued_at_ms, attempt.id) > ($4, $5::UUID)
          )
          AND (attempt.queued_at_ms, attempt.id) <= ($6, $7)
          AND run.status IN ('queued', 'in_progress')
          AND NOT EXISTS (
              SELECT 1 FROM attempt_cancellation_intents AS cancellation
              WHERE cancellation.attempt_id = attempt.id
          )
          AND (
              run.concurrency_group_key IS NULL
              OR EXISTS (
                  SELECT 1 FROM concurrency_groups AS concurrency
                  WHERE concurrency.repository_id = run.repository_id
                    AND concurrency.normalized_key = run.concurrency_group_key
                    AND concurrency.running_run_id = run.id
              )
          )
          AND NOT EXISTS (
              SELECT 1
              FROM job_dependencies AS dependency
              WHERE dependency.run_id = job.run_id
                AND dependency.job_id = job.id
                AND coalesce((
                    SELECT prerequisite_attempt.lifecycle
                    FROM job_attempts AS prerequisite_attempt
                    WHERE prerequisite_attempt.job_id = dependency.prerequisite_job_id
                    ORDER BY prerequisite_attempt.attempt_number DESC
                    LIMIT 1
                ), '') <> 'succeeded'
          )
        ORDER BY attempt.queued_at_ms, attempt.id
        LIMIT $8
        ",
    )
    .bind(&routing.tenant_id)
    .bind(i32::from(routing.job_ir_version.get()))
    .bind(request.observed_at().get())
    .bind(after.map(|key| key.queued_at().get()))
    .bind(after.map(|key| key.attempt_id().as_uuid()))
    .bind(upper.queued_at().get())
    .bind(upper.attempt_id().as_uuid())
    .bind(i64::from(request.limit().get()))
    .bind(i32::from(WORKFLOW_ADMISSION_EPOCH))
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DurableDesiredRunnerState {
    Active,
    Draining,
    Disabled,
}

#[derive(Debug)]
struct LockedRouting {
    tenant_id: String,
    group_name: Option<String>,
    labels: BTreeSet<RoutingLabel>,
    slots: RunnerSlotCount,
    protocol_version: RunnerProtocolVersion,
    job_ir_version: JobIrVersion,
    registered_capabilities: RunnerCapabilities,
    observed_capabilities: RunnerCapabilities,
    online: bool,
    accepts_new_work: bool,
}

impl LockedRouting {
    fn require_online(&self, fence: RunnerSessionFence) -> Result<(), StoreError> {
        if self.online {
            Ok(())
        } else {
            Err(StoreError::SessionClosed(fence.session_id()))
        }
    }
}

fn decode_desired_runner_state(value: &str) -> Result<DurableDesiredRunnerState, StoreError> {
    match value {
        "active" => Ok(DurableDesiredRunnerState::Active),
        "draining" => Ok(DurableDesiredRunnerState::Draining),
        "disabled" => Ok(DurableDesiredRunnerState::Disabled),
        _ => Err(StoreError::corrupt_data("invalid runner desired state")),
    }
}

fn routing_fingerprint(
    routing: &LockedRouting,
    generation: RunnerGeneration,
) -> Result<Sha256Digest, StoreError> {
    fn field(digest: &mut Sha256, value: &[u8]) {
        digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(value);
    }

    let mut digest = Sha256::new();
    digest.update(b"automata.store.runner-routing-fingerprint.v1\0");
    digest.update(generation.get().to_be_bytes());
    digest.update(routing.job_ir_version.get().to_be_bytes());
    field(&mut digest, routing.tenant_id.as_bytes());
    field(
        &mut digest,
        routing.group_name.as_deref().unwrap_or_default().as_bytes(),
    );
    for label in &routing.labels {
        field(&mut digest, label.as_str().as_bytes());
    }
    let registered = serde_json::to_vec(&routing.registered_capabilities)
        .map_err(|_| StoreError::corrupt_data("registered capabilities are not canonical"))?;
    let observed = serde_json::to_vec(&routing.observed_capabilities)
        .map_err(|_| StoreError::corrupt_data("observed capabilities are not canonical"))?;
    field(&mut digest, &registered);
    field(&mut digest, &observed);
    Ok(Sha256Digest::from_bytes(digest.finalize().into()))
}

async fn reject_tombstoned_session_payload_access(
    transaction: &mut Transaction<'_, Postgres>,
    fence: RunnerSessionFence,
) -> Result<(), StoreError> {
    let runner =
        sqlx::query("SELECT generation, session_epoch FROM runners WHERE id = $1 FOR UPDATE")
            .bind(fence.runner_id().as_uuid())
            .fetch_optional(&mut **transaction)
            .await
            .map_err(operation_error)?
            .ok_or(StoreError::RunnerNotFound(fence.runner_id()))?;
    let current_generation =
        decode_generation(runner.try_get("generation").map_err(operation_error)?)?;
    let current_epoch = decode_epoch(runner.try_get("session_epoch").map_err(operation_error)?)?;

    let session = sqlx::query(
        r"
        SELECT runner_generation, session_epoch, disconnected_at_ms
        FROM runner_sessions
        WHERE id = $1 AND runner_id = $2
        FOR UPDATE
        ",
    )
    .bind(fence.session_id().as_uuid())
    .bind(fence.runner_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(StoreError::SessionNotFound(fence.session_id()))?;
    let stored_generation = decode_generation(
        session
            .try_get("runner_generation")
            .map_err(operation_error)?,
    )?;
    let stored_epoch = decode_epoch(session.try_get("session_epoch").map_err(operation_error)?)?;
    if stored_generation != fence.runner_generation() || stored_epoch != fence.session_epoch() {
        return Err(StoreError::SessionFenceRejected(fence.session_id()));
    }
    if let Some(disconnected_at) = session
        .try_get::<Option<i64>, _>("disconnected_at_ms")
        .map_err(operation_error)?
    {
        let reason = if stored_generation == current_generation && stored_epoch == current_epoch {
            RunnerPayloadTombstoneReason::SessionClosed
        } else {
            RunnerPayloadTombstoneReason::SessionSuperseded
        };
        return Err(StoreError::RunnerPayloadUnavailable {
            session_id: fence.session_id(),
            tombstone: RunnerPayloadTombstone::new(reason, UnixMillis::new(disconnected_at)),
        });
    }
    if current_generation != fence.runner_generation() || current_epoch != fence.session_epoch() {
        return Err(StoreError::SessionFenceRejected(fence.session_id()));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn lock_live_routing(
    transaction: &mut Transaction<'_, Postgres>,
    fence: RunnerSessionFence,
) -> Result<LockedRouting, StoreError> {
    let runner_id: Uuid = sqlx::query_scalar("SELECT runner_id FROM runner_sessions WHERE id = $1")
        .bind(fence.session_id().as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?
        .ok_or(StoreError::SessionNotFound(fence.session_id()))?;
    if runner_id != fence.runner_id().as_uuid() {
        return Err(StoreError::SessionFenceRejected(fence.session_id()));
    }

    let runner = sqlx::query(
        r"
        SELECT runner.tenant_id, runner.generation, runner.session_epoch, runner.group_id,
               runner_group.normalized_name AS group_name,
               runner.labels, runner.slots, runner.status, runner.desired_state,
               runner.capabilities
        FROM runners AS runner
        LEFT JOIN runner_groups AS runner_group ON runner_group.id = runner.group_id
        WHERE runner.id = $1
        FOR UPDATE OF runner
        ",
    )
    .bind(fence.runner_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(StoreError::RunnerNotFound(fence.runner_id()))?;
    let actual_generation =
        decode_generation(runner.try_get("generation").map_err(operation_error)?)?;
    if actual_generation != fence.runner_generation() {
        return Err(generation_mismatch(
            fence.runner_id(),
            fence.runner_generation(),
            actual_generation,
        ));
    }
    let current_epoch = decode_epoch(runner.try_get("session_epoch").map_err(operation_error)?)?;
    if current_epoch != fence.session_epoch() {
        return Err(StoreError::SessionFenceRejected(fence.session_id()));
    }
    let status: &str = runner.try_get("status").map_err(operation_error)?;
    let desired_state =
        decode_desired_runner_state(runner.try_get("desired_state").map_err(operation_error)?)?;
    if desired_state == DurableDesiredRunnerState::Disabled {
        return Err(StoreError::RunnerDisabled(fence.runner_id()));
    }

    let session = sqlx::query(
        r"
        SELECT runner_generation, session_epoch, protocol_version, job_ir_schema,
               capability_snapshot, disconnected_at_ms
        FROM runner_sessions
        WHERE id = $1
        FOR UPDATE
        ",
    )
    .bind(fence.session_id().as_uuid())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let stored_generation = decode_generation(
        session
            .try_get("runner_generation")
            .map_err(operation_error)?,
    )?;
    let stored_epoch = decode_epoch(session.try_get("session_epoch").map_err(operation_error)?)?;
    let disconnected: Option<i64> = session
        .try_get("disconnected_at_ms")
        .map_err(operation_error)?;
    if stored_generation != fence.runner_generation() || stored_epoch != fence.session_epoch() {
        return Err(StoreError::SessionFenceRejected(fence.session_id()));
    }
    if disconnected.is_some() {
        return Err(StoreError::SessionClosed(fence.session_id()));
    }

    let slots = u16::try_from(runner.try_get::<i32, _>("slots").map_err(operation_error)?)
        .ok()
        .and_then(|value| RunnerSlotCount::new(value).ok())
        .ok_or_else(|| StoreError::corrupt_data("invalid registered runner slots"))?;
    let registered_capabilities: RunnerCapabilities = serde_json::from_value(
        runner
            .try_get::<serde_json::Value, _>("capabilities")
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("invalid registered runner capabilities"))?;
    registered_capabilities
        .validate()
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    if registered_capabilities.runner_id() != fence.runner_id() {
        return Err(StoreError::corrupt_data(
            "registered capabilities identify a different runner",
        ));
    }
    let observed_capabilities: RunnerCapabilities = serde_json::from_value(
        session
            .try_get::<serde_json::Value, _>("capability_snapshot")
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("invalid observed runner capabilities"))?;
    observed_capabilities
        .validate()
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    if observed_capabilities.runner_id() != fence.runner_id() {
        return Err(StoreError::corrupt_data(
            "observed capabilities identify a different runner",
        ));
    }
    Ok(LockedRouting {
        tenant_id: runner.try_get("tenant_id").map_err(operation_error)?,
        group_name: runner.try_get("group_name").map_err(operation_error)?,
        labels: decode_routing_labels(
            runner
                .try_get::<Vec<String>, _>("labels")
                .map_err(operation_error)?,
            "durable runner routing labels contain case-folded duplicates",
        )?,
        slots,
        protocol_version: decode_protocol(
            session
                .try_get("protocol_version")
                .map_err(operation_error)?,
        )?,
        job_ir_version: decode_job_ir_version(
            session.try_get("job_ir_schema").map_err(operation_error)?,
        )?,
        registered_capabilities,
        observed_capabilities,
        online: status == "online",
        accepts_new_work: desired_state == DurableDesiredRunnerState::Active,
    })
}

async fn lock_existing_session_authority(
    transaction: &mut Transaction<'_, Postgres>,
    fence: RunnerSessionFence,
) -> Result<(), StoreError> {
    let runner = sqlx::query(
        r"
        SELECT generation, session_epoch, status, desired_state
        FROM runners
        WHERE id = $1
        FOR UPDATE
        ",
    )
    .bind(fence.runner_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(StoreError::RunnerNotFound(fence.runner_id()))?;
    let generation = decode_generation(runner.try_get("generation").map_err(operation_error)?)?;
    if generation != fence.runner_generation() {
        return Err(generation_mismatch(
            fence.runner_id(),
            fence.runner_generation(),
            generation,
        ));
    }
    let epoch = decode_epoch(runner.try_get("session_epoch").map_err(operation_error)?)?;
    if epoch != fence.session_epoch() {
        return Err(StoreError::SessionFenceRejected(fence.session_id()));
    }
    if decode_desired_runner_state(runner.try_get("desired_state").map_err(operation_error)?)?
        == DurableDesiredRunnerState::Disabled
    {
        return Err(StoreError::RunnerDisabled(fence.runner_id()));
    }
    match runner
        .try_get::<&str, _>("status")
        .map_err(operation_error)?
    {
        "online" => Ok(()),
        "offline" => Err(StoreError::SessionClosed(fence.session_id())),
        _ => Err(StoreError::corrupt_data("invalid observed runner status")),
    }
}

async fn lock_runner_fence(
    transaction: &mut Transaction<'_, Postgres>,
    fence: RunnerSessionFence,
) -> Result<(), StoreError> {
    let runner = sqlx::query(
        r"
        SELECT generation, session_epoch
        FROM runners
        WHERE id = $1
        FOR UPDATE
        ",
    )
    .bind(fence.runner_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(StoreError::RunnerNotFound(fence.runner_id()))?;
    let generation = decode_generation(runner.try_get("generation").map_err(operation_error)?)?;
    let epoch = decode_epoch(runner.try_get("session_epoch").map_err(operation_error)?)?;
    if generation != fence.runner_generation() || epoch != fence.session_epoch() {
        return Err(StoreError::SessionFenceRejected(fence.session_id()));
    }
    Ok(())
}

async fn mark_runner_offline(
    transaction: &mut Transaction<'_, Postgres>,
    fence: RunnerSessionFence,
    observed_at: UnixMillis,
) -> Result<(), StoreError> {
    let updated = sqlx::query(
        r"
        UPDATE runners
        SET status = 'offline',
            last_seen_at_ms = greatest(coalesce(last_seen_at_ms, $4), $4),
            updated_at_ms = greatest(updated_at_ms, $4)
        WHERE id = $1 AND generation = $2 AND session_epoch = $3
        ",
    )
    .bind(fence.runner_id().as_uuid())
    .bind(generation_i64(fence.runner_generation())?)
    .bind(epoch_i64(fence.session_epoch())?)
    .bind(observed_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if updated.rows_affected() != 1 {
        return Err(StoreError::SessionFenceRejected(fence.session_id()));
    }
    Ok(())
}

pub(super) async fn cleanup_session_lease_request_state(
    transaction: &mut Transaction<'_, Postgres>,
    session_id: RunnerSessionId,
) -> Result<(), StoreError> {
    cleanup_session_lease_request_state_uuid(transaction, session_id.as_uuid()).await
}

pub(super) async fn cleanup_session_lease_request_state_uuid(
    transaction: &mut Transaction<'_, Postgres>,
    session_id: Uuid,
) -> Result<(), StoreError> {
    sqlx::query("DELETE FROM runner_operation_receipts WHERE runner_session_id = $1")
        .bind(session_id)
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    sqlx::query(
        r"
        DELETE FROM runner_rpc_receipts
        WHERE runner_session_id = $1 AND operation_kind = $2
        ",
    )
    .bind(session_id)
    .bind(LEASE_RPC_OPERATION_KIND)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    sqlx::query("DELETE FROM runner_lease_request_heads WHERE runner_session_id = $1")
        .bind(session_id)
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    Ok(())
}

async fn tombstone_session_runner_payloads(
    transaction: &mut Transaction<'_, Postgres>,
    session_id: RunnerSessionId,
    reason: RunnerPayloadTombstoneReason,
    tombstoned_at: UnixMillis,
) -> Result<(), StoreError> {
    tombstone_session_runner_payloads_uuid(transaction, session_id.as_uuid(), reason, tombstoned_at)
        .await
}

pub(super) async fn tombstone_session_runner_payloads_uuid(
    transaction: &mut Transaction<'_, Postgres>,
    session_id: Uuid,
    reason: RunnerPayloadTombstoneReason,
    tombstoned_at: UnixMillis,
) -> Result<(), StoreError> {
    sqlx::query(
        r"
        UPDATE runner_command_outbox
        SET envelope_schema = NULL,
            wrapping_key_id = NULL,
            wrapped_data_key = NULL,
            nonce = NULL,
            ciphertext = NULL,
            payload_tombstone_reason = $2,
            payload_tombstoned_at_ms = greatest($3, created_at_ms)
        WHERE runner_session_id = $1
          AND payload_tombstone_reason IS NULL
        ",
    )
    .bind(session_id)
    .bind(reason.as_str())
    .bind(tombstoned_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    sqlx::query(
        r"
        UPDATE runner_rpc_receipts
        SET envelope_schema = NULL,
            wrapping_key_id = NULL,
            wrapped_data_key = NULL,
            nonce = NULL,
            ciphertext = NULL,
            payload_tombstone_reason = $2,
            payload_tombstoned_at_ms = greatest($3, committed_at_ms)
        WHERE runner_session_id = $1
          AND payload_tombstone_reason IS NULL
        ",
    )
    .bind(session_id)
    .bind(reason.as_str())
    .bind(tombstoned_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn tombstone_disconnected_runner_payloads(
    transaction: &mut Transaction<'_, Postgres>,
    runner_id: RunnerId,
    reason: RunnerPayloadTombstoneReason,
    tombstoned_at: UnixMillis,
) -> Result<(), StoreError> {
    sqlx::query(
        r"
        UPDATE runner_command_outbox AS command
        SET envelope_schema = NULL,
            wrapping_key_id = NULL,
            wrapped_data_key = NULL,
            nonce = NULL,
            ciphertext = NULL,
            payload_tombstone_reason = $2,
            payload_tombstoned_at_ms = greatest($3, command.created_at_ms)
        FROM runner_sessions AS session
        WHERE command.runner_session_id = session.id
          AND session.runner_id = $1
          AND session.disconnected_at_ms IS NOT NULL
          AND command.payload_tombstone_reason IS NULL
        ",
    )
    .bind(runner_id.as_uuid())
    .bind(reason.as_str())
    .bind(tombstoned_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    sqlx::query(
        r"
        UPDATE runner_rpc_receipts AS receipt
        SET envelope_schema = NULL,
            wrapping_key_id = NULL,
            wrapped_data_key = NULL,
            nonce = NULL,
            ciphertext = NULL,
            payload_tombstone_reason = $2,
            payload_tombstoned_at_ms = greatest($3, receipt.committed_at_ms)
        FROM runner_sessions AS session
        WHERE receipt.runner_session_id = session.id
          AND session.runner_id = $1
          AND session.disconnected_at_ms IS NOT NULL
          AND receipt.payload_tombstone_reason IS NULL
        ",
    )
    .bind(runner_id.as_uuid())
    .bind(reason.as_str())
    .bind(tombstoned_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn tombstone_acknowledged_command_payloads(
    transaction: &mut Transaction<'_, Postgres>,
    session_id: RunnerSessionId,
    through: CommandCursor,
    tombstoned_at: UnixMillis,
) -> Result<(), StoreError> {
    sqlx::query(
        r"
        UPDATE runner_command_outbox
        SET envelope_schema = NULL,
            wrapping_key_id = NULL,
            wrapped_data_key = NULL,
            nonce = NULL,
            ciphertext = NULL,
            payload_tombstone_reason = 'acknowledged',
            payload_tombstoned_at_ms = greatest($3, created_at_ms)
        WHERE runner_session_id = $1
          AND command_sequence <= $2
          AND payload_tombstone_reason IS NULL
        ",
    )
    .bind(session_id.as_uuid())
    .bind(cursor_i64(through)?)
    .bind(tombstoned_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn tombstone_exact_command_payload(
    transaction: &mut Transaction<'_, Postgres>,
    session_id: RunnerSessionId,
    sequence: CommandSequence,
    reason: RunnerPayloadTombstoneReason,
    tombstoned_at: UnixMillis,
) -> Result<(), StoreError> {
    sqlx::query(
        r"
        UPDATE runner_command_outbox
        SET envelope_schema = NULL,
            wrapping_key_id = NULL,
            wrapped_data_key = NULL,
            nonce = NULL,
            ciphertext = NULL,
            payload_tombstone_reason = $3,
            payload_tombstoned_at_ms = greatest($4, created_at_ms)
        WHERE runner_session_id = $1
          AND command_sequence = $2
          AND payload_tombstone_reason IS NULL
        ",
    )
    .bind(session_id.as_uuid())
    .bind(sequence_i64(sequence)?)
    .bind(reason.as_str())
    .bind(tombstoned_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn cleanup_disconnected_runner_lease_request_state(
    transaction: &mut Transaction<'_, Postgres>,
    runner_id: RunnerId,
) -> Result<(), StoreError> {
    sqlx::query(
        r"
        DELETE FROM runner_operation_receipts AS receipt
        USING runner_sessions AS session
        WHERE receipt.runner_session_id = session.id
          AND session.runner_id = $1
          AND session.disconnected_at_ms IS NOT NULL
        ",
    )
    .bind(runner_id.as_uuid())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    sqlx::query(
        r"
        DELETE FROM runner_rpc_receipts AS receipt
        USING runner_sessions AS session
        WHERE receipt.runner_session_id = session.id
          AND receipt.operation_kind = $2
          AND session.runner_id = $1
          AND session.disconnected_at_ms IS NOT NULL
        ",
    )
    .bind(runner_id.as_uuid())
    .bind(LEASE_RPC_OPERATION_KIND)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    sqlx::query(
        r"
        DELETE FROM runner_lease_request_heads AS head
        USING runner_sessions AS session
        WHERE head.runner_session_id = session.id
          AND session.runner_id = $1
          AND session.disconnected_at_ms IS NOT NULL
        ",
    )
    .bind(runner_id.as_uuid())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn advance_scan_cursor(
    transaction: &mut Transaction<'_, Postgres>,
    cursor: automata_ci_control::adapter_spi::RunnableCursorView,
    routing: &LockedRouting,
    observed_at: UnixMillis,
) -> Result<Option<u64>, StoreError> {
    if cursor.routing_fingerprint()
        != routing_fingerprint(routing, cursor.session().runner_generation())?
    {
        return Ok(None);
    }
    let next_version = cursor
        .expected_version()
        .checked_add(1)
        .filter(|version| i64::try_from(*version).is_ok())
        .ok_or_else(|| StoreError::corrupt_data("runnable cursor version exhausted"))?;
    let through = cursor.through();
    let upper = cursor.cycle_upper();
    if through.is_some_and(|key| upper.is_none_or(|upper| key > upper)) {
        return Err(StoreError::corrupt_data(
            "runnable cursor advancement exceeds cycle high-water mark",
        ));
    }
    let rows = if cursor.expected_version() == 0 {
        sqlx::query(
            r"
            INSERT INTO runner_queue_cursors (
                runner_id, runner_slot, runner_generation, routing_fingerprint,
                cursor_version, after_queued_at_ms, after_attempt_id,
                cycle_upper_queued_at_ms, cycle_upper_attempt_id, updated_at_ms
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (runner_id, runner_slot) DO NOTHING
            ",
        )
        .bind(cursor.session().runner_id().as_uuid())
        .bind(i32::from(cursor.slot().ordinal()))
        .bind(generation_i64(cursor.session().runner_generation())?)
        .bind(cursor.routing_fingerprint().as_bytes().as_slice())
        .bind(cursor_version_i64(next_version)?)
        .bind(through.map(|key| key.queued_at().get()))
        .bind(through.map(|key| key.attempt_id().as_uuid()))
        .bind(upper.map(|key| key.queued_at().get()))
        .bind(upper.map(|key| key.attempt_id().as_uuid()))
        .bind(observed_at.get())
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?
        .rows_affected()
    } else {
        sqlx::query(
            r"
            UPDATE runner_queue_cursors
            SET runner_generation = $3,
                routing_fingerprint = $4,
                cursor_version = $5,
                after_queued_at_ms = $6,
                after_attempt_id = $7,
                cycle_upper_queued_at_ms = $8,
                cycle_upper_attempt_id = $9,
                updated_at_ms = $10
            WHERE runner_id = $1 AND runner_slot = $2 AND cursor_version = $11
            ",
        )
        .bind(cursor.session().runner_id().as_uuid())
        .bind(i32::from(cursor.slot().ordinal()))
        .bind(generation_i64(cursor.session().runner_generation())?)
        .bind(cursor.routing_fingerprint().as_bytes().as_slice())
        .bind(cursor_version_i64(next_version)?)
        .bind(through.map(|key| key.queued_at().get()))
        .bind(through.map(|key| key.attempt_id().as_uuid()))
        .bind(upper.map(|key| key.queued_at().get()))
        .bind(upper.map(|key| key.attempt_id().as_uuid()))
        .bind(observed_at.get())
        .bind(cursor_version_i64(cursor.expected_version())?)
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?
        .rows_affected()
    };
    Ok((rows == 1).then_some(next_version))
}

fn rebase_claim_request(
    request: &mut TryClaimAttempt,
    database_now: UnixMillis,
    requested_duration: i64,
) -> Result<(), StoreError> {
    let database_expires_at =
        super::runner_attempt_database_expiry(database_now, requested_duration)?;
    *request = automata_ci_control::adapter_spi::rebase_try_claim_attempt(
        request,
        database_now,
        database_expires_at,
    )
    .map_err(|error| {
        StoreError::corrupt_data(format!("database-issued attempt claim is invalid: {error}"))
    })?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn evaluate_claim(
    transaction: &mut Transaction<'_, Postgres>,
    request: &mut TryClaimAttempt,
    routing: &LockedRouting,
    caller_observed_at: UnixMillis,
    requested_duration: i64,
) -> Result<TryClaimOutcome, StoreError> {
    if !routing.online || !routing.accepts_new_work {
        return Ok(TryClaimOutcome::Rejected(ClaimRejection::NotRoutable));
    }
    if !routing.slots.contains(request.slot()) {
        return Ok(TryClaimOutcome::Rejected(ClaimRejection::SlotOutOfRange));
    }
    let occupied = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT id
        FROM job_attempts
        WHERE runner_id = $1 AND runner_slot = $2 AND lease_id IS NOT NULL
        LIMIT 1
        ",
    )
    .bind(request.session().runner_id().as_uuid())
    .bind(i32::from(request.slot().ordinal()))
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if let Some(attempt_id) = occupied {
        return Ok(TryClaimOutcome::Rejected(ClaimRejection::SlotOccupied {
            attempt_id: AttemptId::from_uuid(attempt_id),
        }));
    }

    let row = sqlx::query(
        r"
        SELECT attempt.lifecycle, attempt.fencing_token, attempt.changed_at_ms,
               job.id AS job_id, job.admission_epoch, job.job_ir_schema,
               job.job_ir_size_bytes, job.job_ir_digest, job.job_ir_object_key,
               job.requirements,
               repository.tenant_id, run.id AS run_id, run.repository_id,
               run.status AS run_status, run.concurrency_group_key,
               EXISTS (
                   SELECT 1 FROM attempt_cancellation_intents AS cancellation
                   WHERE cancellation.attempt_id = attempt.id
               ) AS has_cancellation,
               NOT EXISTS (
                   SELECT 1
                   FROM job_dependencies AS dependency
                   WHERE dependency.run_id = job.run_id
                     AND dependency.job_id = job.id
                     AND coalesce((
                         SELECT prerequisite_attempt.lifecycle
                         FROM job_attempts AS prerequisite_attempt
                         WHERE prerequisite_attempt.job_id = dependency.prerequisite_job_id
                         ORDER BY prerequisite_attempt.attempt_number DESC
                         LIMIT 1
                     ), '') <> 'succeeded'
               ) AS dependencies_succeeded
        FROM job_attempts AS attempt
        JOIN jobs AS job ON job.id = attempt.job_id
        JOIN workflow_runs AS run ON run.id = job.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        WHERE attempt.id = $1
        FOR UPDATE OF attempt, run
        ",
    )
    .bind(request.attempt_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(row) = row else {
        return Ok(TryClaimOutcome::Rejected(ClaimRejection::AttemptNotFound));
    };
    let lifecycle = parse_lifecycle_store(row.try_get("lifecycle").map_err(operation_error)?)?;
    if lifecycle != JobLifecycle::Queued {
        return Ok(TryClaimOutcome::Rejected(ClaimRejection::AttemptNotQueued(
            lifecycle,
        )));
    }
    let run_status: &str = row.try_get("run_status").map_err(operation_error)?;
    let has_cancellation: bool = row.try_get("has_cancellation").map_err(operation_error)?;
    let dependencies_succeeded: bool = row
        .try_get("dependencies_succeeded")
        .map_err(operation_error)?;
    let concurrency_key: Option<String> = row
        .try_get("concurrency_group_key")
        .map_err(operation_error)?;
    let run_id: Uuid = row.try_get("run_id").map_err(operation_error)?;
    if !matches!(run_status, "queued" | "in_progress")
        || has_cancellation
        || !dependencies_succeeded
    {
        return Ok(TryClaimOutcome::Rejected(ClaimRejection::NoLongerRunnable));
    }
    if let Some(concurrency_key) = concurrency_key {
        let repository_id: Uuid = row.try_get("repository_id").map_err(operation_error)?;
        let running_run_id: Option<Uuid> = sqlx::query_scalar(
            r"
            SELECT running_run_id
            FROM concurrency_groups
            WHERE repository_id = $1 AND normalized_key = $2
            FOR UPDATE
            ",
        )
        .bind(repository_id)
        .bind(concurrency_key)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?
        .flatten();
        if running_run_id != Some(run_id) {
            return Ok(TryClaimOutcome::Rejected(ClaimRejection::NoLongerRunnable));
        }
    }
    let database_now = super::runner_attempt_database_now(transaction).await?;
    super::validate_runner_attempt_caller_clock(caller_observed_at, database_now)?;
    rebase_claim_request(request, database_now, requested_duration)?;
    let changed_at = UnixMillis::new(row.try_get("changed_at_ms").map_err(operation_error)?);
    if request.observed_at() < changed_at {
        return Err(StoreError::AttemptTimeRegression {
            attempt_id: request.attempt_id(),
            observed_at: request.observed_at(),
            changed_at,
        });
    }

    let tenant_id: String = row.try_get("tenant_id").map_err(operation_error)?;
    let admission_epoch: i32 = row.try_get("admission_epoch").map_err(operation_error)?;
    let job_version =
        decode_job_ir_version(row.try_get("job_ir_schema").map_err(operation_error)?)?;
    let requirements: RunnerRequirements = serde_json::from_value(
        row.try_get::<serde_json::Value, _>("requirements")
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("invalid durable runner requirements"))?;
    let machine_requirements = requirements
        .clone()
        .with_labels(std::iter::empty::<automata_ci_core::RunnerLabel>())
        .with_eligible_groups(std::iter::empty::<automata_ci_core::RunnerGroup>());
    let capabilities_match = routing
        .registered_capabilities
        .satisfies(&machine_requirements)
        .is_ok()
        && routing
            .observed_capabilities
            .satisfies(&machine_requirements)
            .is_ok();
    let labels_match = requirements.labels().iter().all(|label| {
        RoutingLabel::new(label.as_str())
            .ok()
            .is_some_and(|label| routing.labels.contains(&label))
    });
    let group_matches = requirements.eligible_groups().is_empty()
        || routing.group_name.as_ref().is_some_and(|name| {
            RunnerGroup::new(name)
                .ok()
                .is_some_and(|group| requirements.eligible_groups().contains(&group))
        });
    if tenant_id != routing.tenant_id
        || admission_epoch != i32::from(WORKFLOW_ADMISSION_EPOCH)
        || !labels_match
        || !group_matches
        || !capabilities_match
        || job_version != routing.job_ir_version
    {
        return Ok(TryClaimOutcome::Rejected(ClaimRejection::NotRoutable));
    }

    let raw_fence: i64 = row.try_get("fencing_token").map_err(operation_error)?;
    let fencing_token = if raw_fence == 0 {
        FencingToken::new(1)
    } else {
        let current = decode_fencing_token(raw_fence)?;
        current.checked_next()
    }
    .map_err(|_| StoreError::FencingTokenExhausted {
        attempt_id: request.attempt_id(),
    })?;

    let updated = sqlx::query(
        r"
        UPDATE job_attempts
        SET lifecycle = 'leased', fencing_token = $2, lease_id = $3,
            runner_id = $4, lease_issued_at_ms = $5, lease_expires_at_ms = $6,
            runner_session_id = $7, runner_session_epoch = $8,
            runner_generation = $9, runner_slot = $10, changed_at_ms = $5
        WHERE id = $1 AND lifecycle = 'queued' AND changed_at_ms <= $5
        ",
    )
    .bind(request.attempt_id().as_uuid())
    .bind(fence_i64(fencing_token)?)
    .bind(request.lease_id().as_uuid())
    .bind(request.session().runner_id().as_uuid())
    .bind(request.observed_at().get())
    .bind(request.expires_at().get())
    .bind(request.session().session_id().as_uuid())
    .bind(epoch_i64(request.session().session_epoch())?)
    .bind(generation_i64(request.session().runner_generation())?)
    .bind(i32::from(request.slot().ordinal()))
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if updated.rows_affected() != 1 {
        return Err(StoreError::corrupt_data(
            "locked claim update did not affect exactly one attempt",
        ));
    }
    super::admission::reconcile_attempt_run(
        transaction,
        request.attempt_id(),
        request.observed_at(),
    )
    .await?;
    let lease = Lease::new(
        request.lease_id(),
        request.attempt_id(),
        request.session().runner_id(),
        fencing_token,
        request.observed_at(),
        request.expires_at(),
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let assignment = AttemptAssignment::new(request.session(), request.slot());
    let job_id = JobId::from_uuid(row.try_get("job_id").map_err(operation_error)?);
    let run_id = RunId::from_uuid(row.try_get("run_id").map_err(operation_error)?);
    let size = u64::try_from(
        row.try_get::<i64, _>("job_ir_size_bytes")
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("negative JobIR size"))?;
    let digest = decode_sha256_digest(row.try_get("job_ir_digest").map_err(operation_error)?)
        .map_err(|error| StoreError::corrupt_data(error.clone()))?;
    let object_key = ObjectKey::new(
        row.try_get::<String, _>("job_ir_object_key")
            .map_err(operation_error)?,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let metadata = JobIrMetadata::new(job_id, run_id, job_version, size, digest, object_key)
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let claimed = ClaimedAttempt::try_new(lease, assignment, metadata)
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    Ok(TryClaimOutcome::Claimed(Box::new(claimed)))
}

#[allow(clippy::too_many_lines)]
async fn complete_claim_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &TryClaimAttempt,
    outcome: &TryClaimOutcome,
    committed_cursor: Option<u64>,
) -> Result<(), StoreError> {
    let (name, fencing_token, lifecycle, occupied_attempt) = match outcome {
        TryClaimOutcome::Claimed(claimed) => (
            "claimed",
            Some(fence_i64(claimed.lease().fencing_token())?),
            None,
            None,
        ),
        TryClaimOutcome::Rejected(ClaimRejection::AttemptNotFound) => {
            ("attempt_not_found", None, None, None)
        }
        TryClaimOutcome::Rejected(ClaimRejection::ClaimExpired) => {
            return Err(invalid_operation_receipt(
                "a fresh claim cannot complete as an expired claim",
            ));
        }
        TryClaimOutcome::Rejected(ClaimRejection::ClaimSuperseded) => {
            return Err(invalid_operation_receipt(
                "a fresh claim cannot complete as a superseded claim",
            ));
        }
        TryClaimOutcome::Rejected(ClaimRejection::AttemptNotQueued(lifecycle)) => {
            ("not_queued", None, Some(lifecycle_name(*lifecycle)), None)
        }
        TryClaimOutcome::Rejected(ClaimRejection::NoLongerRunnable) => {
            ("not_runnable", None, None, None)
        }
        TryClaimOutcome::Rejected(ClaimRejection::NotRoutable) => {
            if committed_cursor.is_some() {
                ("not_routable", None, None, None)
            } else {
                ("authority_rejected", None, None, None)
            }
        }
        TryClaimOutcome::Rejected(ClaimRejection::SlotOutOfRange) => {
            ("slot_out_of_range", None, None, None)
        }
        TryClaimOutcome::Rejected(ClaimRejection::SlotOccupied { attempt_id }) => {
            ("slot_occupied", None, None, Some(attempt_id.as_uuid()))
        }
        TryClaimOutcome::Rejected(ClaimRejection::ScanSuperseded) => {
            ("scan_superseded", None, None, None)
        }
        TryClaimOutcome::NoWork => {
            return Err(invalid_operation_receipt(
                "claim completion received a no-work outcome",
            ));
        }
    };
    let result = sqlx::query(
        r"
        UPDATE runner_operation_receipts
        SET outcome = $3, claimed_fencing_token = $4,
            rejection_lifecycle = $5, occupied_attempt_id = $6,
            committed_cursor_version = $7,
            claimed_job_id = $8, claimed_run_id = $9,
            claimed_job_ir_schema = $10, claimed_job_ir_size_bytes = $11,
            claimed_job_ir_digest = $12, claimed_job_ir_object_key = $13,
            observed_at_ms = $14, lease_expires_at_ms = $15,
            completed_at_ms = $14
        WHERE runner_session_id = $1 AND operation_id = $2 AND outcome = 'pending'
        ",
    )
    .bind(request.session().session_id().as_uuid())
    .bind(request.operation_id().as_uuid())
    .bind(name)
    .bind(fencing_token)
    .bind(lifecycle)
    .bind(occupied_attempt)
    .bind(committed_cursor.map(cursor_version_i64).transpose()?)
    .bind(
        outcome
            .claimed_job_ir()
            .map(|metadata| metadata.job_id().as_uuid()),
    )
    .bind(
        outcome
            .claimed_job_ir()
            .map(|metadata| metadata.run_id().as_uuid()),
    )
    .bind(
        outcome
            .claimed_job_ir()
            .map(|metadata| i32::from(metadata.version().get())),
    )
    .bind(
        outcome
            .claimed_job_ir()
            .map(|metadata| i64::try_from(metadata.encoded_size()))
            .transpose()
            .map_err(|_| StoreError::corrupt_data("JobIR size exceeds PostgreSQL BIGINT"))?,
    )
    .bind(
        outcome
            .claimed_job_ir()
            .map(|metadata| metadata.digest().as_bytes().to_vec()),
    )
    .bind(
        outcome
            .claimed_job_ir()
            .map(|metadata| metadata.object_key().as_str()),
    )
    .bind(request.observed_at().get())
    .bind(request.expires_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if result.rows_affected() != 1 {
        return Err(invalid_operation_receipt(
            "pending receipt could not be completed",
        ));
    }
    Ok(())
}

async fn complete_no_work_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &NoWorkLeaseRequest,
    outcome: &TryClaimOutcome,
    committed_cursor: Option<u64>,
) -> Result<(), StoreError> {
    let name = match outcome {
        TryClaimOutcome::NoWork => "no_work",
        TryClaimOutcome::Rejected(ClaimRejection::ScanSuperseded) => "scan_superseded",
        TryClaimOutcome::Rejected(ClaimRejection::NotRoutable) if committed_cursor.is_none() => {
            "authority_rejected"
        }
        _ => {
            return Err(invalid_operation_receipt(
                "no-work completion received an invalid outcome",
            ));
        }
    };
    let result = sqlx::query(
        r"
        UPDATE runner_operation_receipts
        SET outcome = $3, committed_cursor_version = $4, completed_at_ms = $5
        WHERE runner_session_id = $1 AND operation_id = $2 AND outcome = 'pending'
        ",
    )
    .bind(request.request_key().session().session_id().as_uuid())
    .bind(request.request_key().operation_id().as_uuid())
    .bind(name)
    .bind(committed_cursor.map(cursor_version_i64).transpose()?)
    .bind(request.observed_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if result.rows_affected() != 1 {
        return Err(invalid_operation_receipt(
            "pending no-work receipt could not be completed",
        ));
    }
    Ok(())
}

async fn replay_claim(
    transaction: &mut Transaction<'_, Postgres>,
    request: LeaseRequestKey,
) -> Result<TryClaimReceipt, StoreError> {
    let row = claim_receipt_row(transaction, request)
        .await?
        .ok_or_else(|| invalid_operation_receipt("conflicting receipt disappeared"))?;
    let receipt = decode_claim_receipt(&row, request, true)?;
    resolve_claim_receipt(transaction, receipt).await
}

/// Resolves the provisional claim phase of an admitted lease request.
///
/// A successful claim is replayable only while its exact attempt fence and
/// lease remain live. An expired or superseded unpublished selection is
/// atomically finalized as a durable negative outcome. The control layer can
/// then complete one canonical no-work response, so an exact retry can never
/// become trapped behind an undeliverable claim.
async fn resolve_claim_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    receipt: TryClaimReceipt,
) -> Result<TryClaimReceipt, StoreError> {
    let TryClaimOutcome::Claimed(claimed) = receipt.outcome() else {
        return Ok(receipt);
    };
    let lease = claimed.lease();
    let database_now = super::runner_attempt_database_now(transaction).await?;
    let rejection = if database_now >= lease.expires_at() {
        Some(ClaimRejection::ClaimExpired)
    } else {
        let assignment = claimed.assignment();
        let session = assignment.session();
        let live: bool = sqlx::query_scalar(
            r"
            SELECT EXISTS (
                SELECT 1
                FROM job_attempts
                WHERE id = $1
                  AND lifecycle IN ('leased', 'preparing', 'running', 'cancelling', 'finalizing')
                  AND lease_id = $2
                  AND fencing_token = $3
                  AND runner_id = $4
                  AND runner_session_id = $5
                  AND runner_session_epoch = $6
                  AND runner_generation = $7
                  AND runner_slot = $8
                  AND lease_issued_at_ms = $9
                  AND lease_expires_at_ms >= $10
            )
            ",
        )
        .bind(lease.attempt_id().as_uuid())
        .bind(lease.lease_id().as_uuid())
        .bind(fencing_i64(lease.fencing_token())?)
        .bind(session.runner_id().as_uuid())
        .bind(session.session_id().as_uuid())
        .bind(epoch_i64(session.session_epoch())?)
        .bind(generation_i64(session.runner_generation())?)
        .bind(i32::from(assignment.slot().ordinal()))
        .bind(lease.issued_at().get())
        .bind(lease.expires_at().get())
        .fetch_one(&mut **transaction)
        .await
        .map_err(operation_error)?;
        (!live).then_some(ClaimRejection::ClaimSuperseded)
    };
    let Some(rejection) = rejection else {
        return Ok(receipt);
    };
    let outcome = match rejection {
        ClaimRejection::ClaimExpired => "claim_expired",
        ClaimRejection::ClaimSuperseded => "claim_superseded",
        _ => {
            return Err(invalid_operation_receipt(
                "live claim resolved to an invalid terminal reason",
            ));
        }
    };

    let updated = sqlx::query(
        r"
        UPDATE runner_operation_receipts
        SET outcome = $3,
            claimed_fencing_token = NULL,
            rejection_lifecycle = NULL,
            occupied_attempt_id = NULL,
            claimed_job_id = NULL,
            claimed_run_id = NULL,
            claimed_job_ir_schema = NULL,
            claimed_job_ir_size_bytes = NULL,
            claimed_job_ir_digest = NULL,
            claimed_job_ir_object_key = NULL,
            completed_at_ms = $4
        WHERE runner_session_id = $1
          AND operation_id = $2
          AND outcome = 'claimed'
        ",
    )
    .bind(receipt.session_id().as_uuid())
    .bind(receipt.operation_id().as_uuid())
    .bind(outcome)
    .bind(database_now.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if updated.rows_affected() != 1 {
        return Err(invalid_operation_receipt(
            "terminal claim did not finalize exactly once",
        ));
    }
    Ok(TryClaimReceipt::new(
        receipt.request_key(),
        TryClaimOutcome::Rejected(rejection),
        true,
    ))
}

async fn claim_receipt_row(
    transaction: &mut Transaction<'_, Postgres>,
    request: LeaseRequestKey,
) -> Result<Option<sqlx::postgres::PgRow>, StoreError> {
    sqlx::query(
        r"
        SELECT operation_kind, selection_kind, request_digest, outcome,
               scan_cursor_version, committed_cursor_version, claimed_fencing_token,
               rejection_lifecycle, occupied_attempt_id, requested_attempt_id,
               requested_lease_id, runner_slot, observed_at_ms, lease_expires_at_ms,
               claimed_job_id, claimed_run_id, claimed_job_ir_schema,
               claimed_job_ir_size_bytes, claimed_job_ir_digest,
               claimed_job_ir_object_key
        FROM runner_operation_receipts
        WHERE runner_session_id = $1 AND operation_id = $2
        FOR UPDATE
        ",
    )
    .bind(request.session().session_id().as_uuid())
    .bind(request.operation_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

fn decode_claim_receipt(
    row: &sqlx::postgres::PgRow,
    request: LeaseRequestKey,
    replayed: bool,
) -> Result<TryClaimReceipt, StoreError> {
    let kind: &str = row.try_get("operation_kind").map_err(operation_error)?;
    let stored_digest =
        decode_sha256_digest(row.try_get("request_digest").map_err(operation_error)?)
            .map_err(|error| invalid_operation_receipt(error.clone()))?;
    let raw_slot: i32 = row.try_get("runner_slot").map_err(operation_error)?;
    let stored_slot = u16::try_from(raw_slot)
        .ok()
        .and_then(|value| StableRunnerSlot::new(value).ok())
        .ok_or_else(|| invalid_operation_receipt("invalid runner slot"))?;
    if kind != LEASE_OPERATION_KIND
        || stored_digest != request.request_digest()
        || stored_slot != request.slot()
    {
        return Err(StoreError::OperationConflict {
            session_id: request.session().session_id(),
            operation_id: request.operation_id(),
        });
    }
    let name: &str = row.try_get("outcome").map_err(operation_error)?;
    let outcome = match name {
        "claim_expired" => TryClaimOutcome::Rejected(ClaimRejection::ClaimExpired),
        "claim_superseded" => TryClaimOutcome::Rejected(ClaimRejection::ClaimSuperseded),
        "claimed" => {
            let attempt_id = receipt_attempt_id(row)?;
            let lease_id = receipt_lease_id(row)?;
            let observed_at = receipt_observed_at(row)?;
            let expires_at = receipt_expires_at(row)?;
            let raw_fence: i64 = row
                .try_get::<Option<i64>, _>("claimed_fencing_token")
                .map_err(operation_error)?
                .ok_or_else(|| invalid_operation_receipt("claimed fence missing"))?;
            let fencing_token = decode_fencing_token(raw_fence)?;
            let lease = Lease::new(
                lease_id,
                attempt_id,
                request.session().runner_id(),
                fencing_token,
                observed_at,
                expires_at,
            )
            .map_err(|error| invalid_operation_receipt(error.to_string()))?;
            let claimed = ClaimedAttempt::try_new(
                lease,
                AttemptAssignment::new(request.session(), stored_slot),
                decode_receipt_job_ir(row)?,
            )
            .map_err(|error| invalid_operation_receipt(error.to_string()))?;
            TryClaimOutcome::Claimed(Box::new(claimed))
        }
        "attempt_not_found" => TryClaimOutcome::Rejected(ClaimRejection::AttemptNotFound),
        "not_queued" => {
            let lifecycle: &str = row
                .try_get::<Option<&str>, _>("rejection_lifecycle")
                .map_err(operation_error)?
                .ok_or_else(|| invalid_operation_receipt("lifecycle missing"))?;
            TryClaimOutcome::Rejected(ClaimRejection::AttemptNotQueued(parse_lifecycle_store(
                lifecycle,
            )?))
        }
        "not_routable" | "authority_rejected" => {
            TryClaimOutcome::Rejected(ClaimRejection::NotRoutable)
        }
        "not_runnable" => TryClaimOutcome::Rejected(ClaimRejection::NoLongerRunnable),
        "slot_out_of_range" => TryClaimOutcome::Rejected(ClaimRejection::SlotOutOfRange),
        "slot_occupied" => {
            let attempt_id: Uuid = row
                .try_get::<Option<Uuid>, _>("occupied_attempt_id")
                .map_err(operation_error)?
                .ok_or_else(|| invalid_operation_receipt("occupied attempt missing"))?;
            TryClaimOutcome::Rejected(ClaimRejection::SlotOccupied {
                attempt_id: AttemptId::from_uuid(attempt_id),
            })
        }
        "scan_superseded" => TryClaimOutcome::Rejected(ClaimRejection::ScanSuperseded),
        "no_work" => TryClaimOutcome::NoWork,
        "pending" => {
            return Err(invalid_operation_receipt(
                "pending receipt escaped its transaction",
            ));
        }
        other => {
            return Err(invalid_operation_receipt(format!(
                "unknown outcome {other:?}"
            )));
        }
    };
    Ok(TryClaimReceipt::new(request, outcome, replayed))
}

fn decode_receipt_job_ir(row: &sqlx::postgres::PgRow) -> Result<JobIrMetadata, StoreError> {
    let job_id = row
        .try_get::<Option<Uuid>, _>("claimed_job_id")
        .map_err(operation_error)?
        .map(JobId::from_uuid)
        .ok_or_else(|| invalid_operation_receipt("claimed job missing"))?;
    let run_id = row
        .try_get::<Option<Uuid>, _>("claimed_run_id")
        .map_err(operation_error)?
        .map(RunId::from_uuid)
        .ok_or_else(|| invalid_operation_receipt("claimed run missing"))?;
    let version = row
        .try_get::<Option<i32>, _>("claimed_job_ir_schema")
        .map_err(operation_error)?
        .ok_or_else(|| invalid_operation_receipt("claimed JobIR version missing"))
        .and_then(decode_job_ir_version)?;
    let size = row
        .try_get::<Option<i64>, _>("claimed_job_ir_size_bytes")
        .map_err(operation_error)?
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| invalid_operation_receipt("claimed JobIR size missing"))?;
    let digest = row
        .try_get::<Option<Vec<u8>>, _>("claimed_job_ir_digest")
        .map_err(operation_error)?
        .ok_or_else(|| invalid_operation_receipt("claimed JobIR digest missing"))
        .and_then(|value| {
            decode_sha256_digest(value).map_err(|error| invalid_operation_receipt(error.clone()))
        })?;
    let object_key = row
        .try_get::<Option<String>, _>("claimed_job_ir_object_key")
        .map_err(operation_error)?
        .ok_or_else(|| invalid_operation_receipt("claimed JobIR key missing"))
        .and_then(|value| {
            ObjectKey::new(value).map_err(|error| invalid_operation_receipt(error.to_string()))
        })?;
    JobIrMetadata::new(job_id, run_id, version, size, digest, object_key)
        .map_err(|error| invalid_operation_receipt(error.to_string()))
}

fn receipt_attempt_id(row: &sqlx::postgres::PgRow) -> Result<AttemptId, StoreError> {
    row.try_get::<Option<Uuid>, _>("requested_attempt_id")
        .map_err(operation_error)?
        .map(AttemptId::from_uuid)
        .ok_or_else(|| invalid_operation_receipt("selected attempt missing"))
}

fn receipt_lease_id(row: &sqlx::postgres::PgRow) -> Result<automata_ci_core::LeaseId, StoreError> {
    row.try_get::<Option<Uuid>, _>("requested_lease_id")
        .map_err(operation_error)?
        .map(automata_ci_core::LeaseId::from_uuid)
        .ok_or_else(|| invalid_operation_receipt("selected lease missing"))
}

fn receipt_observed_at(row: &sqlx::postgres::PgRow) -> Result<UnixMillis, StoreError> {
    Ok(UnixMillis::new(
        row.try_get("observed_at_ms").map_err(operation_error)?,
    ))
}

fn receipt_expires_at(row: &sqlx::postgres::PgRow) -> Result<UnixMillis, StoreError> {
    row.try_get::<Option<i64>, _>("lease_expires_at_ms")
        .map_err(operation_error)?
        .map(UnixMillis::new)
        .ok_or_else(|| invalid_operation_receipt("selected lease expiry missing"))
}

fn session_query(
    fence: RunnerSessionFence,
) -> sqlx::query::Query<'static, Postgres, sqlx::postgres::PgArguments> {
    sqlx::query(
        r"
        SELECT protocol_version, job_ir_schema, capability_snapshot::text AS capability_snapshot,
               connected_at_ms, heartbeat_at_ms, disconnected_at_ms,
               acknowledged_command_sequence
        FROM runner_sessions
        WHERE id = $1 AND runner_id = $2
          AND runner_generation = $3 AND session_epoch = $4
        ",
    )
    .bind(fence.session_id().as_uuid())
    .bind(fence.runner_id().as_uuid())
    .bind(generation_i64(fence.runner_generation()).unwrap_or_default())
    .bind(epoch_i64(fence.session_epoch()).unwrap_or_default())
}

async fn locked_session(
    transaction: &mut Transaction<'_, Postgres>,
    fence: RunnerSessionFence,
) -> Result<RunnerSessionSnapshot, StoreError> {
    let row = sqlx::query(
        r"
        SELECT protocol_version, job_ir_schema, capability_snapshot::text AS capability_snapshot,
               connected_at_ms, heartbeat_at_ms, disconnected_at_ms,
               acknowledged_command_sequence
        FROM runner_sessions
        WHERE id = $1 AND runner_id = $2
          AND runner_generation = $3 AND session_epoch = $4
        FOR UPDATE
        ",
    )
    .bind(fence.session_id().as_uuid())
    .bind(fence.runner_id().as_uuid())
    .bind(generation_i64(fence.runner_generation())?)
    .bind(epoch_i64(fence.session_epoch())?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or_else(|| StoreError::SessionFenceRejected(fence.session_id()))?;
    decode_session(&row, fence)
}

async fn update_session_liveness(
    transaction: &mut Transaction<'_, Postgres>,
    fence: RunnerSessionFence,
    requested_cursor: CommandCursor,
    observed_at: UnixMillis,
    current: &RunnerSessionSnapshot,
) -> Result<(), StoreError> {
    if observed_at < current.heartbeat_at() {
        return Err(StoreError::SessionTimeRegression {
            session_id: fence.session_id(),
            observed_at,
            durable_at: current.heartbeat_at(),
        });
    }
    let last_sequence: i64 = sqlx::query_scalar(
        r"
        SELECT last_command_sequence
        FROM runner_sessions
        WHERE id = $1 AND runner_id = $2
          AND runner_generation = $3 AND session_epoch = $4
        ",
    )
    .bind(fence.session_id().as_uuid())
    .bind(fence.runner_id().as_uuid())
    .bind(generation_i64(fence.runner_generation())?)
    .bind(epoch_i64(fence.session_epoch())?)
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let available = decode_cursor(last_sequence)?;
    if requested_cursor.durable_value() > available.durable_value() {
        return Err(StoreError::CommandCursorAhead {
            session_id: fence.session_id(),
            requested: requested_cursor,
            available,
        });
    }
    let durable_cursor =
        if requested_cursor.durable_value() < current.command_cursor().durable_value() {
            current.command_cursor()
        } else {
            requested_cursor
        };
    sqlx::query(
        r"
        UPDATE runner_sessions
        SET heartbeat_at_ms = $5,
            acknowledged_command_sequence = greatest(
                acknowledged_command_sequence, $6
            )
        WHERE id = $1 AND runner_id = $2
          AND runner_generation = $3 AND session_epoch = $4
          AND disconnected_at_ms IS NULL
        ",
    )
    .bind(fence.session_id().as_uuid())
    .bind(fence.runner_id().as_uuid())
    .bind(generation_i64(fence.runner_generation())?)
    .bind(epoch_i64(fence.session_epoch())?)
    .bind(observed_at.get())
    .bind(cursor_i64(durable_cursor)?)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    sqlx::query(
        r"
        UPDATE runners
        SET last_seen_at_ms = greatest(coalesce(last_seen_at_ms, $2), $2),
            updated_at_ms = greatest(updated_at_ms, $2)
        WHERE id = $1 AND generation = $3
        ",
    )
    .bind(fence.runner_id().as_uuid())
    .bind(observed_at.get())
    .bind(generation_i64(fence.runner_generation())?)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    acknowledge_cancellations_through(transaction, fence, durable_cursor, observed_at).await?;
    tombstone_acknowledged_command_payloads(
        transaction,
        fence.session_id(),
        durable_cursor,
        observed_at,
    )
    .await?;
    Ok(())
}

fn database_session_decision_at(
    database_now: UnixMillis,
    durable_times: impl IntoIterator<Item = UnixMillis>,
) -> Result<UnixMillis, StoreError> {
    let mut decision_at = database_now;
    for durable_at in durable_times {
        if durable_at > database_now
            && durable_at.get().abs_diff(database_now.get())
                > super::MAX_RUNNER_ATTEMPT_CALLER_CLOCK_SKEW_MILLIS
        {
            return Err(StoreError::corrupt_data(
                "runner session timestamp is ahead of authoritative database time",
            ));
        }
        decision_at = decision_at.max(durable_at);
    }
    Ok(decision_at)
}

fn decode_session(
    row: &sqlx::postgres::PgRow,
    fence: RunnerSessionFence,
) -> Result<RunnerSessionSnapshot, StoreError> {
    let protocol = u16::try_from(
        row.try_get::<i32, _>("protocol_version")
            .map_err(operation_error)?,
    )
    .ok()
    .and_then(|value| RunnerProtocolVersion::new(value).ok())
    .ok_or_else(|| StoreError::corrupt_data("invalid runner protocol version"))?;
    let version = decode_job_ir_version(row.try_get("job_ir_schema").map_err(operation_error)?)?;
    let capabilities = RoutingDocument::new(
        row.try_get::<String, _>("capability_snapshot")
            .map_err(operation_error)?,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let connected_at = UnixMillis::new(row.try_get("connected_at_ms").map_err(operation_error)?);
    let heartbeat_at = UnixMillis::new(row.try_get("heartbeat_at_ms").map_err(operation_error)?);
    let disconnected_at = row
        .try_get::<Option<i64>, _>("disconnected_at_ms")
        .map_err(operation_error)?
        .map(UnixMillis::new);
    let command_cursor = decode_cursor(
        row.try_get("acknowledged_command_sequence")
            .map_err(operation_error)?,
    )?;
    RunnerSessionSnapshot::try_new(
        fence,
        protocol,
        version,
        capabilities,
        connected_at,
        heartbeat_at,
        disconnected_at,
        command_cursor,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))
}

fn decode_routing(
    row: &sqlx::postgres::PgRow,
    fence: RunnerSessionFence,
) -> Result<RunnerRoutingSnapshot, StoreError> {
    let group_id = row
        .try_get::<Option<Uuid>, _>("group_id")
        .map_err(operation_error)?
        .map(RunnerGroupId::from_uuid);
    let group_name: Option<String> = row.try_get("group_name").map_err(operation_error)?;
    let group = match (group_id, group_name) {
        (None, None) => None,
        (Some(id), Some(name)) => Some((id, name)),
        _ => {
            return Err(StoreError::corrupt_data(
                "partial runner group routing identity",
            ));
        }
    };
    let labels = row
        .try_get::<Vec<String>, _>("labels")
        .map_err(operation_error)?
        .into_iter()
        .map(|label| {
            RoutingLabel::new(label).map_err(|error| StoreError::corrupt_data(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let registered = RoutingDocument::new(
        row.try_get::<String, _>("registered_capabilities")
            .map_err(operation_error)?,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let negotiated = RoutingDocument::new(
        row.try_get::<String, _>("negotiated_capabilities")
            .map_err(operation_error)?,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let slots = u16::try_from(row.try_get::<i32, _>("slots").map_err(operation_error)?)
        .ok()
        .and_then(|value| RunnerSlotCount::new(value).ok())
        .ok_or_else(|| StoreError::corrupt_data("invalid registered runner slots"))?;
    let job_ir_version =
        decode_job_ir_version(row.try_get("job_ir_schema").map_err(operation_error)?)?;
    RunnerRoutingSnapshot::try_new(
        fence,
        group,
        labels,
        registered,
        negotiated,
        slots,
        job_ir_version,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))
}

fn decode_routing_labels(
    raw: Vec<String>,
    duplicate_message: &'static str,
) -> Result<BTreeSet<RoutingLabel>, StoreError> {
    let raw_len = raw.len();
    let labels = raw
        .into_iter()
        .map(|label| {
            RoutingLabel::new(label).map_err(|error| StoreError::corrupt_data(error.to_string()))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if labels.len() != raw_len {
        return Err(StoreError::corrupt_data(duplicate_message));
    }
    Ok(labels)
}

fn decode_runnable_attempt(row: &sqlx::postgres::PgRow) -> Result<RunnableAttempt, StoreError> {
    let attempt_id = AttemptId::from_uuid(row.try_get("attempt_id").map_err(operation_error)?);
    let job_id = JobId::from_uuid(row.try_get("job_id").map_err(operation_error)?);
    let run_id = RunId::from_uuid(row.try_get("run_id").map_err(operation_error)?);
    let queued_at = UnixMillis::new(row.try_get("queued_at_ms").map_err(operation_error)?);
    let requirements_value: serde_json::Value =
        row.try_get("requirements").map_err(operation_error)?;
    let requirements: RunnerRequirements = serde_json::from_value(requirements_value)
        .map_err(|_| StoreError::corrupt_data("invalid durable runner requirements"))?;
    if requirements.schema_version() != RUNNER_REQUIREMENTS_SCHEMA_VERSION {
        return Err(StoreError::corrupt_data(format!(
            "unsupported runner requirements schema {}",
            requirements.schema_version()
        )));
    }
    let version = decode_job_ir_version(row.try_get("job_ir_schema").map_err(operation_error)?)?;
    let size = u64::try_from(
        row.try_get::<i64, _>("job_ir_size_bytes")
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("negative JobIR size"))?;
    let digest = decode_sha256_digest(row.try_get("job_ir_digest").map_err(operation_error)?)
        .map_err(|error| StoreError::corrupt_data(error.clone()))?;
    let key = ObjectKey::new(
        row.try_get::<String, _>("job_ir_object_key")
            .map_err(operation_error)?,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let ir_metadata = JobIrMetadata::new(job_id, run_id, version, size, digest, key)
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    RunnableAttempt::try_new(
        attempt_id,
        job_id,
        run_id,
        queued_at,
        requirements,
        ir_metadata,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))
}

fn operation_error(error: sqlx::Error) -> StoreError {
    StoreError::operation(error)
}

fn decode_sha256_digest(bytes: Vec<u8>) -> Result<Sha256Digest, String> {
    let length = bytes.len();
    let bytes = bytes
        .try_into()
        .map_err(|_| format!("SHA-256 digest has {length} bytes; expected 32"))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn decode_fencing_token(value: i64) -> Result<FencingToken, StoreError> {
    let value = u64::try_from(value)
        .map_err(|_| StoreError::corrupt_data("negative fencing token in claim receipt"))?;
    FencingToken::new(value)
        .map_err(|error| StoreError::corrupt_data(format!("invalid fencing token: {error}")))
}

fn decode_runner_payload_tombstone_reason(value: &str) -> Option<RunnerPayloadTombstoneReason> {
    match value {
        "acknowledged" => Some(RunnerPayloadTombstoneReason::Acknowledged),
        "session_closed" => Some(RunnerPayloadTombstoneReason::SessionClosed),
        "session_superseded" => Some(RunnerPayloadTombstoneReason::SessionSuperseded),
        _ => None,
    }
}

fn generation_mismatch(
    runner_id: RunnerId,
    expected: RunnerGeneration,
    actual: RunnerGeneration,
) -> StoreError {
    StoreError::RunnerGenerationMismatch {
        runner_id,
        expected,
        actual,
    }
}

fn invalid_operation_receipt(message: impl Into<String>) -> StoreError {
    StoreError::corrupt_data(format!(
        "invalid runner operation receipt: {}",
        message.into()
    ))
}

fn invalid_generation(value: i64) -> StoreError {
    StoreError::corrupt_data(format!("invalid runner generation {value}"))
}

fn invalid_session_epoch(value: i64) -> StoreError {
    StoreError::corrupt_data(format!("invalid runner session epoch {value}"))
}

fn validate_observed_capabilities(
    runner_id: RunnerId,
    document: &str,
) -> Result<RunnerCapabilities, StoreError> {
    let capabilities: RunnerCapabilities = serde_json::from_str(document)
        .map_err(|_| StoreError::InvalidCapabilitySnapshot(runner_id))?;
    capabilities
        .validate()
        .map_err(|_| StoreError::InvalidCapabilitySnapshot(runner_id))?;
    if capabilities.runner_id() != runner_id {
        return Err(StoreError::InvalidCapabilitySnapshot(runner_id));
    }
    Ok(capabilities)
}

fn decode_generation(value: i64) -> Result<RunnerGeneration, StoreError> {
    u64::try_from(value)
        .ok()
        .and_then(|value| RunnerGeneration::new(value).ok())
        .ok_or_else(|| invalid_generation(value))
}

fn decode_epoch(value: i64) -> Result<SessionEpoch, StoreError> {
    u64::try_from(value)
        .ok()
        .and_then(|value| SessionEpoch::new(value).ok())
        .ok_or_else(|| invalid_session_epoch(value))
}

fn decode_cursor(value: i64) -> Result<CommandCursor, StoreError> {
    if value == 0 {
        return Ok(CommandCursor::initial());
    }
    let value =
        u64::try_from(value).map_err(|_| StoreError::corrupt_data("negative command cursor"))?;
    let sequence =
        CommandSequence::new(value).map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    Ok(CommandCursor::through(sequence))
}

fn decode_sequence(value: i64) -> Result<CommandSequence, StoreError> {
    let value = u64::try_from(value)
        .map_err(|_| StoreError::corrupt_data("negative server command sequence"))?;
    CommandSequence::new(value).map_err(|error| StoreError::corrupt_data(error.to_string()))
}

fn sequence_i64(value: CommandSequence) -> Result<i64, StoreError> {
    i64::try_from(value.get())
        .map_err(|_| StoreError::corrupt_data("command sequence exceeds PostgreSQL BIGINT"))
}

fn cursor_i64(value: CommandCursor) -> Result<i64, StoreError> {
    i64::try_from(value.durable_value())
        .map_err(|_| StoreError::corrupt_data("command cursor exceeds PostgreSQL BIGINT"))
}

fn decode_schema(value: i32) -> Result<DocumentSchema, StoreError> {
    u16::try_from(value)
        .ok()
        .and_then(|value| DocumentSchema::new(value).ok())
        .ok_or_else(|| StoreError::corrupt_data(format!("invalid document schema {value}")))
}

fn decode_job_ir_version(value: i32) -> Result<JobIrVersion, StoreError> {
    u16::try_from(value)
        .ok()
        .and_then(|value| JobIrVersion::new(value).ok())
        .ok_or_else(|| StoreError::corrupt_data("invalid JobIR version"))
}

fn cursor_version_i64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value)
        .map_err(|_| StoreError::corrupt_data("runnable cursor version exceeds PostgreSQL BIGINT"))
}

fn generation_i64(value: RunnerGeneration) -> Result<i64, StoreError> {
    i64::try_from(value.get()).map_err(|_| invalid_generation(i64::MAX))
}

fn epoch_i64(value: SessionEpoch) -> Result<i64, StoreError> {
    i64::try_from(value.get()).map_err(|_| invalid_session_epoch(i64::MAX))
}

fn protocol_i32(value: RunnerProtocolVersion) -> i32 {
    i32::from(value.get())
}

fn decode_protocol(value: i32) -> Result<RunnerProtocolVersion, StoreError> {
    u16::try_from(value)
        .ok()
        .and_then(|value| RunnerProtocolVersion::new(value).ok())
        .ok_or_else(|| StoreError::corrupt_data("invalid runner protocol version"))
}

fn fence_i64(value: FencingToken) -> Result<i64, StoreError> {
    i64::try_from(value.get())
        .map_err(|_| StoreError::corrupt_data("fencing token exceeds PostgreSQL BIGINT"))
}

fn parse_lifecycle_store(value: &str) -> Result<JobLifecycle, StoreError> {
    parse_lifecycle(value).map_err(|error| StoreError::corrupt_data(error.to_string()))
}

#[cfg(test)]
mod runner_payload_encryption_tests {
    use std::sync::Arc;

    use automata_ci_key_management::{
        EnvelopeCodec, KeyEncryptionProvider, KeyPurpose, WrappedDataKey,
    };

    use super::*;

    #[derive(Debug)]
    struct FailingKeyProvider(KeyEncryptionError);

    #[test]
    fn command_metadata_digest_binds_every_clear_field() {
        let metadata = RunnerCommandEnvelopeMetadata {
            session_id: Uuid::from_u128(1),
            sequence: 1,
            operation_id: Uuid::from_u128(2),
            runner_id: Uuid::from_u128(3),
            session_epoch: 4,
            runner_generation: 5,
            kind: "automata.test-command.v1".to_owned(),
            schema: 6,
            digest: Sha256Digest::from_bytes([7; 32]),
            plaintext_size_bytes: 8,
            created_at_ms: 9,
        };
        let expected = metadata.metadata_digest();
        macro_rules! assert_bound {
            ($field:ident, $value:expr) => {{
                let mut changed = metadata.clone();
                changed.$field = $value;
                assert_ne!(changed.metadata_digest(), expected, stringify!($field));
            }};
        }
        assert_bound!(session_id, Uuid::from_u128(10));
        assert_bound!(sequence, 10);
        assert_bound!(operation_id, Uuid::from_u128(10));
        assert_bound!(runner_id, Uuid::from_u128(10));
        assert_bound!(session_epoch, 10);
        assert_bound!(runner_generation, 10);
        assert_bound!(kind, "automata.changed-command.v1".to_owned());
        assert_bound!(schema, 10);
        assert_bound!(digest, Sha256Digest::from_bytes([10; 32]));
        assert_bound!(plaintext_size_bytes, 10);
        assert_bound!(created_at_ms, 10);
    }

    #[test]
    fn response_metadata_digest_binds_every_clear_field() {
        let metadata = RunnerResponseEnvelopeMetadata {
            session_id: Uuid::from_u128(1),
            operation_id: Uuid::from_u128(2),
            runner_id: Uuid::from_u128(3),
            session_epoch: 4,
            runner_generation: 5,
            operation_kind: "automata.test-response.v1".to_owned(),
            request_digest: Sha256Digest::from_bytes([6; 32]),
            response_schema: 7,
            response_digest: Sha256Digest::from_bytes([8; 32]),
            plaintext_size_bytes: 9,
            committed_at_ms: 10,
        };
        let expected = metadata.metadata_digest();
        macro_rules! assert_bound {
            ($field:ident, $value:expr) => {{
                let mut changed = metadata.clone();
                changed.$field = $value;
                assert_ne!(changed.metadata_digest(), expected, stringify!($field));
            }};
        }
        assert_bound!(session_id, Uuid::from_u128(11));
        assert_bound!(operation_id, Uuid::from_u128(11));
        assert_bound!(runner_id, Uuid::from_u128(11));
        assert_bound!(session_epoch, 11);
        assert_bound!(runner_generation, 11);
        assert_bound!(operation_kind, "automata.changed-response.v1".to_owned());
        assert_bound!(request_digest, Sha256Digest::from_bytes([11; 32]));
        assert_bound!(response_schema, 11);
        assert_bound!(response_digest, Sha256Digest::from_bytes([11; 32]));
        assert_bound!(plaintext_size_bytes, 11);
        assert_bound!(committed_at_ms, 11);
    }

    #[async_trait::async_trait]
    impl KeyEncryptionProvider for FailingKeyProvider {
        async fn wrap_data_key(
            &self,
            _plaintext_key: &SecretBytes,
            _context: &KeyEncryptionContext,
        ) -> Result<WrappedDataKey, KeyEncryptionError> {
            Err(self.0)
        }

        async fn unwrap_data_key(
            &self,
            _wrapped_key: &WrappedDataKey,
            _context: &KeyEncryptionContext,
        ) -> Result<SecretBytes, KeyEncryptionError> {
            Err(self.0)
        }
    }

    async fn mapped_provider_open_error(provider_error: KeyEncryptionError) -> StoreError {
        let codec = EnvelopeCodec::new(Arc::new(FailingKeyProvider(provider_error)));
        let context = KeyEncryptionContext::new(
            "tenant-test",
            KeyPurpose::new("control-plane/runner-command:v1").expect("canonical purpose"),
            "00000000-0000-0000-0000-000000000001/command/1/metadata/test",
        )
        .expect("valid context");
        let wrapped_data_key = WrappedDataKey::new(
            KeyId::new("test-key-v1").expect("canonical key ID"),
            vec![1],
        )
        .expect("structurally valid wrapped key");
        let envelope = EncryptedEnvelope::from_parts(
            1,
            wrapped_data_key,
            [0; ENVELOPE_NONCE_BYTES],
            vec![0; 17],
        )
        .expect("structurally valid envelope");
        let error = codec
            .open(&context, &envelope)
            .await
            .expect_err("provider must fail");
        map_runner_payload_envelope_error(error)
    }

    #[tokio::test]
    async fn provider_unavailability_remains_a_retryable_operation() {
        assert!(matches!(
            mapped_provider_open_error(KeyEncryptionError::Unavailable).await,
            StoreError::Operation(_)
        ));
    }

    #[tokio::test]
    async fn non_retryable_provider_open_failures_are_sanitized_corruption() {
        for error in [
            KeyEncryptionError::InvalidDataKey,
            KeyEncryptionError::InvalidCiphertext,
            KeyEncryptionError::AuthenticationFailed,
            KeyEncryptionError::UnknownKey,
            KeyEncryptionError::RetiredKey,
            KeyEncryptionError::RandomnessUnavailable,
        ] {
            assert!(matches!(
                mapped_provider_open_error(error).await,
                StoreError::CorruptData(message)
                    if message == "runner payload envelope failed integrity validation"
            ));
        }
    }

    #[test]
    fn local_envelope_open_failures_are_sanitized_corruption() {
        for error in [
            EnvelopeError::InvalidEnvelope,
            EnvelopeError::UnsupportedSchema,
            EnvelopeError::RandomnessUnavailable,
            EnvelopeError::AuthenticationFailed,
            EnvelopeError::CryptographicFailure,
        ] {
            assert!(matches!(
                map_runner_payload_envelope_error(error),
                StoreError::CorruptData(message)
                    if message == "runner payload envelope failed integrity validation"
            ));
        }
    }
}
