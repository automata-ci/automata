use automata_ci_blob::{BlobDescriptor, BlobKey, MediaType};
use automata_ci_core::{GitObjectId, Sha256Digest, UnixMillis};
use automata_ci_provider::{
    AcceptProviderDelivery, BindProviderProcessingSource, ClaimProviderProcessing,
    ClaimedProviderProcessing, CompleteProviderProcessing, ExternalDeliveryId,
    ExternalDeliveryIdentity, ExternalRepositoryId, ExternalRepositoryIdentity, ExternalSubjectId,
    ExternalSubjectIdentity, ExternalSubjectKind, FailProviderProcessing,
    MAX_PROVIDER_PROCESSING_ATTEMPTS, ProviderConfigurationRevision, ProviderConnectionId,
    ProviderConnectionRevision, ProviderControl, ProviderControlDocument, ProviderControlKind,
    ProviderDelivery, ProviderDeliveryAcceptOutcome, ProviderDeliveryEvidence, ProviderDeliveryId,
    ProviderDeliveryObservations, ProviderDeliveryReceipt, ProviderDeliveryRejection,
    ProviderDeliveryRepositoryError, ProviderEventName, ProviderInstanceId,
    ProviderProcessingClaimFence, ProviderProcessingFailure, ProviderProcessingInvocationId,
    ProviderProcessingReceipt, ProviderProcessingRepositoryError, ProviderProcessingState,
    ProviderSchemaVersion, ProviderSecretGeneration, ProviderSecretName, ProviderTypeId,
    ProviderWebhookEndpointId, ProviderWebhookEndpointRevision, ProviderWebhookSecretReference,
    ProviderWebhookSignatureEvidence, RejectedProviderDelivery, RenewProviderProcessing,
    RetryProviderProcessing, SealedNormalizedTrigger, VerifiedProviderControlDelivery,
    VerifiedProviderTriggerDelivery,
};
use sqlx::{FromRow, Postgres, Transaction};

use crate::PostgresProviderManifestRepository;

#[derive(FromRow)]
struct DeliveryRow {
    delivery_id: uuid::Uuid,
    provider_instance_id: uuid::Uuid,
    external_delivery_id: String,
    replay_fingerprint: Vec<u8>,
    endpoint_id: uuid::Uuid,
    endpoint_revision: i64,
    provider_type: String,
    provider_revision: i64,
    connection_id: uuid::Uuid,
    connection_revision: i64,
    event_type: String,
    received_at_ms: i64,
    raw_object_key: String,
    raw_body_digest: Vec<u8>,
    raw_body_size: i64,
    raw_media_type: String,
    raw_retain_until_ms: i64,
    signature_scheme: String,
    signature_configuration_revision: i64,
    signature_secret_name: String,
    signature_secret_generation: i64,
    disposition: String,
    repository_external_id: Option<String>,
    normalized_payload: Option<Vec<u8>>,
    normalized_payload_digest: Option<Vec<u8>>,
    control_kind: Option<String>,
    control_object_id: Option<Vec<u8>>,
    control_actor_kind: Option<String>,
    control_actor_external_id: Option<String>,
    control_document_schema: Option<i64>,
    rejection_reason: Option<String>,
    observations: Vec<u8>,
    observations_digest: Vec<u8>,
    accepted_at_ms: i64,
}

#[derive(FromRow)]
struct ProcessingRow {
    invocation_id: uuid::Uuid,
    cause_delivery_id: uuid::Uuid,
    source_delivery_id: Option<uuid::Uuid>,
    attempts: i16,
    created_at_ms: i64,
    claim_fence: Option<i64>,
}

#[derive(FromRow)]
struct ReceiptRow {
    invocation_id: uuid::Uuid,
    cause_delivery_id: uuid::Uuid,
    source_delivery_id: Option<uuid::Uuid>,
    state: String,
    attempts: i16,
    created_at_ms: i64,
}

impl PostgresProviderManifestRepository {
    pub(crate) async fn accept_delivery_inner(
        &self,
        request: AcceptProviderDelivery,
    ) -> Result<ProviderDeliveryAcceptOutcome, ProviderDeliveryRepositoryError> {
        let (delivery, invocation_id, accepted_at) = request.into_parts();
        let fingerprint = delivery.replay_fingerprint();
        let mut transaction = self.pool.begin().await.map_err(unavailable)?;
        let inserted = insert_delivery(
            &mut transaction,
            &delivery,
            accepted_at,
            fingerprint.digest(),
        )
        .await?;
        if inserted {
            if let Some(invocation_id) = invocation_id {
                insert_initial_invocation(
                    &mut transaction,
                    invocation_id,
                    delivery.delivery_id(),
                    matches!(delivery, ProviderDelivery::Trigger(_)),
                    accepted_at,
                )
                .await?;
            }
            transaction.commit().await.map_err(unavailable)?;
            let receipt =
                ProviderDeliveryReceipt::new(delivery.delivery_id(), invocation_id, accepted_at)
                    .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?;
            return Ok(ProviderDeliveryAcceptOutcome::Inserted(receipt));
        }

        let row = sqlx::query_as::<_, ReceiptReplayRow>(
            r"
            SELECT delivery.delivery_id, delivery.accepted_at_ms,
                   delivery.replay_fingerprint, invocation.invocation_id
            FROM provider_deliveries AS delivery
            LEFT JOIN provider_processing_invocations AS invocation
              ON invocation.cause_delivery_id = delivery.delivery_id
            WHERE delivery.provider_instance_id = $1
              AND delivery.external_delivery_id = $2
            ",
        )
        .bind(delivery.external_delivery().instance_id().as_uuid())
        .bind(delivery.external_delivery().external_id().as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?;
        transaction.rollback().await.map_err(unavailable)?;
        let Some(row) = row else {
            return Err(ProviderDeliveryRepositoryError::ReplayConflict);
        };
        if digest(row.replay_fingerprint)? != fingerprint.digest() {
            return Err(ProviderDeliveryRepositoryError::ReplayConflict);
        }
        let invocation_id = row
            .invocation_id
            .map(ProviderProcessingInvocationId::from_uuid)
            .transpose()
            .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?;
        let receipt = ProviderDeliveryReceipt::new(
            ProviderDeliveryId::from_uuid(row.delivery_id)
                .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?,
            invocation_id,
            UnixMillis::new(row.accepted_at_ms),
        )
        .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?;
        Ok(ProviderDeliveryAcceptOutcome::Duplicate(receipt))
    }

    pub(crate) async fn load_delivery_inner(
        &self,
        delivery_id: ProviderDeliveryId,
    ) -> Result<Option<ProviderDelivery>, ProviderDeliveryRepositoryError> {
        sqlx::query_as::<_, DeliveryRow>("SELECT * FROM provider_deliveries WHERE delivery_id = $1")
            .bind(delivery_id.as_uuid())
            .fetch_optional(&self.pool)
            .await
            .map_err(unavailable)?
            .map(decode_delivery)
            .transpose()
    }

    pub(crate) async fn claim_processing_inner(
        &self,
        request: ClaimProviderProcessing,
    ) -> Result<Option<ClaimedProviderProcessing>, ProviderProcessingRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(processing_unavailable)?;
        let row = sqlx::query_as::<_, ProcessingRow>(
            r"
            SELECT invocation_id, cause_delivery_id, source_delivery_id,
                   attempts, created_at_ms, claim_fence
            FROM provider_processing_invocations
            WHERE attempts < 16
              AND (
                (state IN ('pending', 'retry-pending') AND available_at_ms <= $1)
                OR (state = 'claimed' AND claim_expires_at_ms <= $1)
              )
            ORDER BY available_at_ms, created_at_ms, invocation_id
            FOR UPDATE SKIP LOCKED
            LIMIT 1
            ",
        )
        .bind(request.claimed_at().get())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(processing_unavailable)?;
        let Some(row) = row else {
            transaction.commit().await.map_err(processing_unavailable)?;
            return Ok(None);
        };
        let next_attempt = processing_positive_u16(row.attempts)?
            .checked_add(1)
            .ok_or(ProviderProcessingRepositoryError::AttemptLimitReached)?;
        if next_attempt > MAX_PROVIDER_PROCESSING_ATTEMPTS {
            return Err(ProviderProcessingRepositoryError::AttemptLimitReached);
        }
        let next_fence = match row.claim_fence {
            Some(value) => processing_positive_u64(value)?
                .checked_add(1)
                .ok_or(ProviderProcessingRepositoryError::Corrupt)?,
            None => 1,
        };
        let expires_at = request
            .claimed_at()
            .get()
            .checked_add(
                i64::try_from(request.lease_millis())
                    .map_err(|_| ProviderProcessingRepositoryError::Corrupt)?,
            )
            .ok_or(ProviderProcessingRepositoryError::Corrupt)?;
        sqlx::query(
            r"
            UPDATE provider_processing_invocations
            SET state = 'claimed', attempts = $2, claim_worker_id = $3,
                claim_fence = $4, claim_started_at_ms = $6,
                claim_expires_at_ms = $5, failure_kind = NULL
            WHERE invocation_id = $1
            ",
        )
        .bind(row.invocation_id)
        .bind(i16::try_from(next_attempt).map_err(|_| ProviderProcessingRepositoryError::Corrupt)?)
        .bind(request.worker_id().as_uuid())
        .bind(processing_durable_u64(next_fence)?)
        .bind(expires_at)
        .bind(request.claimed_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(processing_unavailable)?;
        let delivery_row = sqlx::query_as::<_, DeliveryRow>(
            "SELECT * FROM provider_deliveries WHERE delivery_id = $1",
        )
        .bind(row.source_delivery_id.unwrap_or(row.cause_delivery_id))
        .fetch_one(&mut *transaction)
        .await
        .map_err(processing_unavailable)?;
        transaction.commit().await.map_err(processing_unavailable)?;
        decode_claim(
            &row,
            delivery_row,
            request,
            next_attempt,
            next_fence,
            expires_at,
        )
        .map(Some)
    }

    pub(crate) async fn complete_processing_inner(
        &self,
        request: CompleteProviderProcessing,
    ) -> Result<ProviderProcessingReceipt, ProviderProcessingRepositoryError> {
        mutate_claim(
            &self.pool,
            request.fence(),
            request.completed_at(),
            "completed",
            request.completed_at(),
            None,
        )
        .await
    }

    pub(crate) async fn renew_processing_inner(
        &self,
        request: RenewProviderProcessing,
    ) -> Result<ProviderProcessingClaimFence, ProviderProcessingRepositoryError> {
        let fence = request.fence();
        let extension = i64::try_from(request.lease_millis())
            .map_err(|_| ProviderProcessingRepositoryError::Corrupt)?;
        let expires_at = request
            .renewed_at()
            .get()
            .checked_add(extension)
            .ok_or(ProviderProcessingRepositoryError::Corrupt)?;
        let renewed = sqlx::query_scalar::<_, i64>(
            r"
            UPDATE provider_processing_invocations
            SET claim_expires_at_ms = $5
            WHERE invocation_id = $1 AND state = 'claimed'
              AND claim_worker_id = $2 AND claim_fence = $3
              AND claim_started_at_ms <= $4
              AND claim_expires_at_ms > $4
              AND claim_expires_at_ms = $6
              AND claim_expires_at_ms < $5
            RETURNING claim_expires_at_ms
            ",
        )
        .bind(fence.invocation_id().as_uuid())
        .bind(fence.worker_id().as_uuid())
        .bind(processing_durable_u64(fence.token())?)
        .bind(request.renewed_at().get())
        .bind(expires_at)
        .bind(fence.expires_at().get())
        .fetch_optional(&self.pool)
        .await
        .map_err(processing_unavailable)?
        .ok_or(ProviderProcessingRepositoryError::ClaimRejected)?;
        ProviderProcessingClaimFence::new(
            fence.invocation_id(),
            fence.worker_id(),
            fence.token(),
            fence.claimed_at(),
            UnixMillis::new(renewed),
        )
        .map_err(|_| ProviderProcessingRepositoryError::Corrupt)
    }

    pub(crate) async fn retry_processing_inner(
        &self,
        request: RetryProviderProcessing,
    ) -> Result<ProviderProcessingReceipt, ProviderProcessingRepositoryError> {
        mutate_claim(
            &self.pool,
            request.fence(),
            request.failed_at(),
            "retry-pending",
            request.retry_at(),
            Some(request.failure()),
        )
        .await
    }

    pub(crate) async fn fail_processing_inner(
        &self,
        request: FailProviderProcessing,
    ) -> Result<ProviderProcessingReceipt, ProviderProcessingRepositoryError> {
        mutate_claim(
            &self.pool,
            request.fence(),
            request.failed_at(),
            "failed",
            request.failed_at(),
            Some(request.failure()),
        )
        .await
    }

    pub(crate) async fn bind_processing_source_inner(
        &self,
        request: BindProviderProcessingSource,
    ) -> Result<ClaimedProviderProcessing, ProviderProcessingRepositoryError> {
        let fence = request.fence();
        let row = sqlx::query_as::<_, ReceiptRow>(
            r"
            UPDATE provider_processing_invocations AS invocation
            SET source_delivery_id = source.delivery_id,
                source_disposition = source.disposition
            FROM provider_deliveries AS source
            WHERE invocation.invocation_id = $1
              AND invocation.state = 'claimed'
              AND invocation.claim_worker_id = $2
              AND invocation.claim_fence = $3
              AND invocation.claim_started_at_ms <= $4
              AND invocation.claim_expires_at_ms > $4
              AND invocation.source_delivery_id IS NULL
              AND source.delivery_id = $5
              AND source.disposition = 'trigger'
            RETURNING invocation.invocation_id, invocation.cause_delivery_id,
                      invocation.source_delivery_id, invocation.state,
                      invocation.attempts, invocation.created_at_ms
            ",
        )
        .bind(fence.invocation_id().as_uuid())
        .bind(fence.worker_id().as_uuid())
        .bind(processing_durable_u64(fence.token())?)
        .bind(request.bound_at().get())
        .bind(request.source_delivery_id().as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(processing_unavailable)?
        .ok_or(ProviderProcessingRepositoryError::ClaimRejected)?;
        let receipt = decode_receipt(row)?;
        let input = match self
            .load_delivery_inner(request.source_delivery_id())
            .await
            .map_err(processing_from_delivery)?
            .ok_or(ProviderProcessingRepositoryError::NotFound)?
        {
            ProviderDelivery::Trigger(delivery) => {
                automata_ci_provider::ProviderProcessingInput::Trigger(delivery)
            }
            ProviderDelivery::Control(_) | ProviderDelivery::Rejected(_) => {
                return Err(ProviderProcessingRepositoryError::Corrupt);
            }
        };
        ClaimedProviderProcessing::new(receipt, input, fence)
            .map_err(|_| ProviderProcessingRepositoryError::Corrupt)
    }
}

fn decode_claim(
    row: &ProcessingRow,
    delivery_row: DeliveryRow,
    request: ClaimProviderProcessing,
    attempt: u16,
    fence_token: u64,
    expires_at: i64,
) -> Result<ClaimedProviderProcessing, ProviderProcessingRepositoryError> {
    let input = match decode_delivery(delivery_row).map_err(processing_from_delivery)? {
        ProviderDelivery::Trigger(value) => {
            automata_ci_provider::ProviderProcessingInput::Trigger(value)
        }
        ProviderDelivery::Control(value) => {
            automata_ci_provider::ProviderProcessingInput::Control(value)
        }
        ProviderDelivery::Rejected(_) => {
            return Err(ProviderProcessingRepositoryError::Corrupt);
        }
    };
    let invocation_id = ProviderProcessingInvocationId::from_uuid(row.invocation_id)
        .map_err(|_| ProviderProcessingRepositoryError::Corrupt)?;
    let receipt = ProviderProcessingReceipt::new(
        invocation_id,
        ProviderDeliveryId::from_uuid(row.cause_delivery_id)
            .map_err(|_| ProviderProcessingRepositoryError::Corrupt)?,
        row.source_delivery_id
            .map(ProviderDeliveryId::from_uuid)
            .transpose()
            .map_err(|_| ProviderProcessingRepositoryError::Corrupt)?,
        ProviderProcessingState::Claimed,
        attempt,
        UnixMillis::new(row.created_at_ms),
    )
    .map_err(|_| ProviderProcessingRepositoryError::Corrupt)?;
    let fence = ProviderProcessingClaimFence::new(
        invocation_id,
        request.worker_id(),
        fence_token,
        request.claimed_at(),
        UnixMillis::new(expires_at),
    )
    .map_err(|_| ProviderProcessingRepositoryError::Corrupt)?;
    ClaimedProviderProcessing::new(receipt, input, fence)
        .map_err(|_| ProviderProcessingRepositoryError::Corrupt)
}

#[derive(FromRow)]
struct ReceiptReplayRow {
    delivery_id: uuid::Uuid,
    accepted_at_ms: i64,
    replay_fingerprint: Vec<u8>,
    invocation_id: Option<uuid::Uuid>,
}

#[allow(clippy::too_many_lines)] // Ordered bindings mirror one immutable delivery record.
async fn insert_delivery(
    transaction: &mut Transaction<'_, Postgres>,
    delivery: &ProviderDelivery,
    accepted_at: UnixMillis,
    fingerprint: Sha256Digest,
) -> Result<bool, ProviderDeliveryRepositoryError> {
    let evidence = match delivery {
        ProviderDelivery::Trigger(value) => value.evidence(),
        ProviderDelivery::Control(value) => value.evidence(),
        ProviderDelivery::Rejected(value) => value.evidence(),
    };
    let (
        disposition,
        repository_id,
        normalized_bytes,
        normalized_digest,
        control_kind,
        control_object_id,
        control_actor_kind,
        control_actor_id,
        control_document_schema,
        rejection,
    ) = match delivery {
        ProviderDelivery::Trigger(value) => (
            "trigger",
            Some(
                value
                    .trigger()
                    .trigger()
                    .target_repository()
                    .identity()
                    .external_id()
                    .as_str(),
            ),
            Some(value.trigger().canonical_bytes()),
            Some(value.trigger().digest()),
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        ProviderDelivery::Control(value) => (
            "control",
            Some(value.control().repository().external_id().as_str()),
            Some(value.control().document().bytes()),
            Some(value.control().document().digest()),
            Some(control_kind(value.control().kind())),
            Some(value.control().object().as_bytes().to_vec()),
            value
                .control()
                .actor()
                .map(|actor| subject_kind(actor.kind())),
            value
                .control()
                .actor()
                .map(|actor| actor.external_id().as_str()),
            Some(i64::from(value.control().document().schema().get())),
            None,
        ),
        ProviderDelivery::Rejected(value) => (
            "rejected",
            value
                .repository()
                .map(|identity| identity.external_id().as_str()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(rejection_text(value.reason())),
        ),
    };
    let result = sqlx::query(
        r"
        INSERT INTO provider_deliveries (
            delivery_id, provider_instance_id, external_delivery_id,
            replay_fingerprint, endpoint_id, endpoint_revision, provider_type,
            provider_revision, connection_id, connection_revision, event_type,
            received_at_ms, raw_object_key, raw_body_digest, raw_body_size,
            raw_media_type, raw_retain_until_ms, signature_scheme,
            signature_configuration_revision,
            signature_secret_name, signature_secret_generation, disposition,
            repository_external_id, normalized_payload, normalized_payload_digest,
            control_kind, control_object_id, control_actor_kind,
            control_actor_external_id, control_document_schema,
            rejection_reason, observations, observations_digest, accepted_at_ms
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
            $18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,
            $33,$34
        ) ON CONFLICT DO NOTHING
        ",
    )
    .bind(evidence.delivery_id().as_uuid())
    .bind(evidence.instance_id().as_uuid())
    .bind(evidence.external_delivery().external_id().as_str())
    .bind(fingerprint.as_bytes().as_slice())
    .bind(evidence.endpoint_id().as_uuid())
    .bind(durable_u64(evidence.endpoint_revision().get())?)
    .bind(evidence.provider_type().as_str())
    .bind(durable_u64(evidence.provider_revision().get())?)
    .bind(evidence.connection_id().as_uuid())
    .bind(durable_u64(evidence.connection_revision().get())?)
    .bind(evidence.event_type().as_str())
    .bind(evidence.received_at().get())
    .bind(evidence.raw_body().key().as_str())
    .bind(evidence.raw_body().digest().as_bytes().as_slice())
    .bind(durable_u64(evidence.raw_body().size())?)
    .bind(evidence.raw_body().media_type().as_str())
    .bind(evidence.raw_retain_until().get())
    .bind(evidence.signature().scheme())
    .bind(durable_u64(
        evidence.signature().secret().configuration_revision().get(),
    )?)
    .bind(evidence.signature().secret().name().as_str())
    .bind(durable_u64(
        evidence.signature().secret().generation().get(),
    )?)
    .bind(disposition)
    .bind(repository_id)
    .bind(normalized_bytes)
    .bind(normalized_digest.map(|value| value.as_bytes().to_vec()))
    .bind(control_kind)
    .bind(control_object_id)
    .bind(control_actor_kind)
    .bind(control_actor_id)
    .bind(control_document_schema)
    .bind(rejection)
    .bind(evidence.observations().canonical_bytes())
    .bind(evidence.observations().digest().as_bytes().as_slice())
    .bind(accepted_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(unavailable)?;
    Ok(result.rows_affected() == 1)
}

async fn insert_initial_invocation(
    transaction: &mut Transaction<'_, Postgres>,
    invocation_id: ProviderProcessingInvocationId,
    delivery_id: ProviderDeliveryId,
    has_source: bool,
    created_at: UnixMillis,
) -> Result<(), ProviderDeliveryRepositoryError> {
    let inserted = sqlx::query(
        r"
        INSERT INTO provider_processing_invocations (
            invocation_id, cause_delivery_id, source_delivery_id,
            source_disposition, state, attempts, available_at_ms, created_at_ms
        ) VALUES ($1, $2, $3, $4, 'pending', 0, $5, $5)
        ",
    )
    .bind(invocation_id.as_uuid())
    .bind(delivery_id.as_uuid())
    .bind(has_source.then(|| delivery_id.as_uuid()))
    .bind(has_source.then_some("trigger"))
    .bind(created_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(unavailable)?;
    if inserted.rows_affected() != 1 {
        return Err(ProviderDeliveryRepositoryError::Corrupt);
    }
    Ok(())
}

async fn mutate_claim(
    pool: &sqlx::PgPool,
    fence: ProviderProcessingClaimFence,
    mutation_at: UnixMillis,
    state: &'static str,
    available_or_completed_at: UnixMillis,
    failure: Option<ProviderProcessingFailure>,
) -> Result<ProviderProcessingReceipt, ProviderProcessingRepositoryError> {
    let completed_at =
        matches!(state, "completed" | "failed").then_some(available_or_completed_at.get());
    let row = sqlx::query_as::<_, ReceiptRow>(
        r"
        UPDATE provider_processing_invocations
        SET state = $5, available_at_ms = $6, claim_worker_id = NULL,
            claim_started_at_ms = NULL, claim_expires_at_ms = NULL,
            completed_at_ms = $7, failure_kind = $8
        WHERE invocation_id = $1 AND state = 'claimed'
          AND claim_worker_id = $2 AND claim_fence = $3
          AND claim_started_at_ms <= $4
          AND claim_expires_at_ms > $4
        RETURNING invocation_id, cause_delivery_id, source_delivery_id,
                  state, attempts, created_at_ms
        ",
    )
    .bind(fence.invocation_id().as_uuid())
    .bind(fence.worker_id().as_uuid())
    .bind(processing_durable_u64(fence.token())?)
    .bind(mutation_at.get())
    .bind(state)
    .bind(available_or_completed_at.get())
    .bind(completed_at)
    .bind(failure.map(failure_text))
    .fetch_optional(pool)
    .await
    .map_err(processing_unavailable)?
    .ok_or(ProviderProcessingRepositoryError::ClaimRejected)?;
    decode_receipt(row)
}

#[allow(clippy::too_many_lines)] // Strict decoding validates every durable evidence field.
fn decode_delivery(row: DeliveryRow) -> Result<ProviderDelivery, ProviderDeliveryRepositoryError> {
    let _ = (&row.replay_fingerprint, row.accepted_at_ms);
    let instance_id = ProviderInstanceId::from_uuid(row.provider_instance_id)
        .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?;
    let external_delivery = ExternalDeliveryIdentity::new(
        instance_id,
        ExternalDeliveryId::new(row.external_delivery_id)
            .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?,
    );
    let raw_body = BlobDescriptor::new(
        BlobKey::new(row.raw_object_key).map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?,
        digest(row.raw_body_digest)?,
        positive_u64(row.raw_body_size)?,
        MediaType::new(row.raw_media_type).map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?,
    );
    let signature = ProviderWebhookSignatureEvidence::new(
        row.signature_scheme,
        ProviderWebhookSecretReference::new(
            ProviderConfigurationRevision::new(positive_u64(row.signature_configuration_revision)?)
                .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?,
            ProviderSecretName::new(row.signature_secret_name)
                .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?,
            ProviderSecretGeneration::new(positive_u64(row.signature_secret_generation)?)
                .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?,
        ),
    )
    .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?;
    let observations = ProviderDeliveryObservations::new(row.observations)
        .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?;
    if observations.digest() != digest(row.observations_digest)? {
        return Err(ProviderDeliveryRepositoryError::Corrupt);
    }
    let delivery_id = ProviderDeliveryId::from_uuid(row.delivery_id)
        .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?;
    let endpoint_id = ProviderWebhookEndpointId::from_uuid(row.endpoint_id)
        .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?;
    let endpoint_revision =
        ProviderWebhookEndpointRevision::new(positive_u64(row.endpoint_revision)?)
            .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?;
    let provider_type = ProviderTypeId::new(row.provider_type)
        .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?;
    let provider_revision =
        ProviderConfigurationRevision::new(positive_u64(row.provider_revision)?)
            .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?;
    let connection_id = ProviderConnectionId::from_uuid(row.connection_id)
        .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?;
    let connection_revision =
        ProviderConnectionRevision::new(positive_u64(row.connection_revision)?)
            .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?;
    let event_type = ProviderEventName::new(row.event_type)
        .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?;
    let evidence = ProviderDeliveryEvidence::rehydrate(
        delivery_id,
        endpoint_id,
        endpoint_revision,
        provider_type,
        instance_id,
        provider_revision,
        connection_id,
        connection_revision,
        external_delivery,
        event_type,
        UnixMillis::new(row.received_at_ms),
        raw_body,
        UnixMillis::new(row.raw_retain_until_ms),
        signature,
        observations,
    )
    .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?;
    match row.disposition.as_str() {
        "trigger" => {
            let trigger = SealedNormalizedTrigger::from_canonical_bytes(
                row.normalized_payload
                    .ok_or(ProviderDeliveryRepositoryError::Corrupt)?,
            )
            .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?;
            if Some(trigger.digest()) != row.normalized_payload_digest.map(digest).transpose()? {
                return Err(ProviderDeliveryRepositoryError::Corrupt);
            }
            VerifiedProviderTriggerDelivery::rehydrate(evidence, trigger)
                .map(Box::new)
                .map(ProviderDelivery::Trigger)
                .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)
        }
        "control" => {
            let repository = ExternalRepositoryIdentity::new(
                instance_id,
                ExternalRepositoryId::new(
                    row.repository_external_id
                        .ok_or(ProviderDeliveryRepositoryError::Corrupt)?,
                )
                .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?,
            );
            if row.control_kind.as_deref() != Some("rerun") {
                return Err(ProviderDeliveryRepositoryError::Corrupt);
            }
            let document = ProviderControlDocument::new(
                ProviderSchemaVersion::new(
                    u16::try_from(
                        row.control_document_schema
                            .ok_or(ProviderDeliveryRepositoryError::Corrupt)?,
                    )
                    .ok()
                    .filter(|value| *value > 0)
                    .ok_or(ProviderDeliveryRepositoryError::Corrupt)?,
                )
                .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?,
                row.normalized_payload
                    .ok_or(ProviderDeliveryRepositoryError::Corrupt)?,
            )
            .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?;
            if Some(document.digest()) != row.normalized_payload_digest.map(digest).transpose()? {
                return Err(ProviderDeliveryRepositoryError::Corrupt);
            }
            let actor = match (row.control_actor_kind, row.control_actor_external_id) {
                (Some(kind), Some(external_id)) => Some(ExternalSubjectIdentity::new(
                    instance_id,
                    decode_subject_kind(&kind)?,
                    ExternalSubjectId::new(external_id)
                        .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?,
                )),
                (None, None) => None,
                _ => return Err(ProviderDeliveryRepositoryError::Corrupt),
            };
            let control = ProviderControl::new(
                ProviderControlKind::Rerun,
                repository,
                GitObjectId::from_durable_bytes(
                    &row.control_object_id
                        .ok_or(ProviderDeliveryRepositoryError::Corrupt)?,
                )
                .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?,
                actor,
                document,
            )
            .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?;
            VerifiedProviderControlDelivery::rehydrate(evidence, control)
                .map(Box::new)
                .map(ProviderDelivery::Control)
                .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)
        }
        "rejected" => {
            let repository = row
                .repository_external_id
                .map(|value| {
                    ExternalRepositoryId::new(value).map(|external_id| {
                        ExternalRepositoryIdentity::new(instance_id, external_id)
                    })
                })
                .transpose()
                .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?;
            let reason = rejection(
                row.rejection_reason
                    .as_deref()
                    .ok_or(ProviderDeliveryRepositoryError::Corrupt)?,
            )?;
            RejectedProviderDelivery::rehydrate(evidence, repository, reason)
                .map(Box::new)
                .map(ProviderDelivery::Rejected)
                .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)
        }
        _ => Err(ProviderDeliveryRepositoryError::Corrupt),
    }
}

fn decode_receipt(
    row: ReceiptRow,
) -> Result<ProviderProcessingReceipt, ProviderProcessingRepositoryError> {
    let ReceiptRow {
        invocation_id,
        cause_delivery_id,
        source_delivery_id,
        state: durable_state,
        attempts,
        created_at_ms,
    } = row;
    ProviderProcessingReceipt::new(
        ProviderProcessingInvocationId::from_uuid(invocation_id)
            .map_err(|_| ProviderProcessingRepositoryError::Corrupt)?,
        ProviderDeliveryId::from_uuid(cause_delivery_id)
            .map_err(|_| ProviderProcessingRepositoryError::Corrupt)?,
        source_delivery_id
            .map(ProviderDeliveryId::from_uuid)
            .transpose()
            .map_err(|_| ProviderProcessingRepositoryError::Corrupt)?,
        state(&durable_state)?,
        processing_positive_u16(attempts)?,
        UnixMillis::new(created_at_ms),
    )
    .map_err(|_| ProviderProcessingRepositoryError::Corrupt)
}

fn digest(value: Vec<u8>) -> Result<Sha256Digest, ProviderDeliveryRepositoryError> {
    value
        .try_into()
        .map(Sha256Digest::from_bytes)
        .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)
}

fn state(value: &str) -> Result<ProviderProcessingState, ProviderProcessingRepositoryError> {
    match value {
        "pending" => Ok(ProviderProcessingState::Pending),
        "retry-pending" => Ok(ProviderProcessingState::RetryPending),
        "claimed" => Ok(ProviderProcessingState::Claimed),
        "completed" => Ok(ProviderProcessingState::Completed),
        "failed" => Ok(ProviderProcessingState::Failed),
        _ => Err(ProviderProcessingRepositoryError::Corrupt),
    }
}

const fn rejection_text(value: ProviderDeliveryRejection) -> &'static str {
    match value {
        ProviderDeliveryRejection::UnknownEvent => "unknown-event",
        ProviderDeliveryRejection::UnsupportedEvent => "unsupported-event",
        ProviderDeliveryRejection::IncompleteEvent => "incomplete-event",
        ProviderDeliveryRejection::PayloadIdentityMismatch => "payload-identity-mismatch",
        ProviderDeliveryRejection::InvalidPayload => "invalid-payload",
    }
}

const fn control_kind(value: ProviderControlKind) -> &'static str {
    match value {
        ProviderControlKind::Rerun => "rerun",
    }
}

const fn subject_kind(value: ExternalSubjectKind) -> &'static str {
    match value {
        ExternalSubjectKind::User => "user",
        ExternalSubjectKind::Organization => "organization",
        ExternalSubjectKind::Team => "team",
        ExternalSubjectKind::ServiceAccount => "service-account",
    }
}

fn decode_subject_kind(
    value: &str,
) -> Result<ExternalSubjectKind, ProviderDeliveryRepositoryError> {
    match value {
        "user" => Ok(ExternalSubjectKind::User),
        "organization" => Ok(ExternalSubjectKind::Organization),
        "team" => Ok(ExternalSubjectKind::Team),
        "service-account" => Ok(ExternalSubjectKind::ServiceAccount),
        _ => Err(ProviderDeliveryRepositoryError::Corrupt),
    }
}

fn rejection(value: &str) -> Result<ProviderDeliveryRejection, ProviderDeliveryRepositoryError> {
    match value {
        "unknown-event" => Ok(ProviderDeliveryRejection::UnknownEvent),
        "unsupported-event" => Ok(ProviderDeliveryRejection::UnsupportedEvent),
        "incomplete-event" => Ok(ProviderDeliveryRejection::IncompleteEvent),
        "payload-identity-mismatch" => Ok(ProviderDeliveryRejection::PayloadIdentityMismatch),
        "invalid-payload" => Ok(ProviderDeliveryRejection::InvalidPayload),
        _ => Err(ProviderDeliveryRepositoryError::Corrupt),
    }
}

const fn failure_text(value: ProviderProcessingFailure) -> &'static str {
    match value {
        ProviderProcessingFailure::DependencyUnavailable => "dependency-unavailable",
        ProviderProcessingFailure::PolicyRejected => "policy-rejected",
        ProviderProcessingFailure::InvalidEvidence => "invalid-evidence",
    }
}

fn durable_u64(value: u64) -> Result<i64, ProviderDeliveryRepositoryError> {
    i64::try_from(value).map_err(|_| ProviderDeliveryRepositoryError::Corrupt)
}

fn positive_u64(value: i64) -> Result<u64, ProviderDeliveryRepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(ProviderDeliveryRepositoryError::Corrupt)
}

fn unavailable(_: sqlx::Error) -> ProviderDeliveryRepositoryError {
    ProviderDeliveryRepositoryError::Unavailable
}

fn processing_durable_u64(value: u64) -> Result<i64, ProviderProcessingRepositoryError> {
    i64::try_from(value).map_err(|_| ProviderProcessingRepositoryError::Corrupt)
}

fn processing_positive_u64(value: i64) -> Result<u64, ProviderProcessingRepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(ProviderProcessingRepositoryError::Corrupt)
}

fn processing_positive_u16(value: i16) -> Result<u16, ProviderProcessingRepositoryError> {
    u16::try_from(value).map_err(|_| ProviderProcessingRepositoryError::Corrupt)
}

const fn processing_from_delivery(
    error: ProviderDeliveryRepositoryError,
) -> ProviderProcessingRepositoryError {
    match error {
        ProviderDeliveryRepositoryError::NotFound => ProviderProcessingRepositoryError::NotFound,
        ProviderDeliveryRepositoryError::Unavailable => {
            ProviderProcessingRepositoryError::Unavailable
        }
        ProviderDeliveryRepositoryError::EndpointConflict
        | ProviderDeliveryRepositoryError::ReplayConflict
        | ProviderDeliveryRepositoryError::Corrupt => ProviderProcessingRepositoryError::Corrupt,
    }
}

fn processing_unavailable(_: sqlx::Error) -> ProviderProcessingRepositoryError {
    ProviderProcessingRepositoryError::Unavailable
}
