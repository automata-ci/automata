use automata_ci_blob::{BlobDescriptor, BlobKey, MediaType};
use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_provider::{
    AcceptProviderDelivery, ClaimProviderDelivery, ClaimedProviderDelivery,
    CompleteProviderDelivery, ExternalDeliveryId, ExternalDeliveryIdentity, ExternalRepositoryId,
    ExternalRepositoryIdentity, FailProviderDelivery, MAX_PROVIDER_DELIVERY_ATTEMPTS,
    ProviderConfigurationRevision, ProviderConnectionId, ProviderConnectionRevision,
    ProviderDelivery, ProviderDeliveryAcceptOutcome, ProviderDeliveryClaimFence,
    ProviderDeliveryFailure, ProviderDeliveryId, ProviderDeliveryObservations,
    ProviderDeliveryReceipt, ProviderDeliveryRejection, ProviderDeliveryRepositoryError,
    ProviderDeliveryState, ProviderEventName, ProviderInstanceId, ProviderSecretGeneration,
    ProviderSecretName, ProviderTypeId, ProviderWebhookEndpointId, ProviderWebhookEndpointRevision,
    ProviderWebhookSecretReference, ProviderWebhookSignatureEvidence, RejectedProviderDelivery,
    RenewProviderDelivery, RetryProviderDelivery, SealedNormalizedTrigger,
    VerifiedProviderDelivery,
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
    normalized_trigger: Option<Vec<u8>>,
    normalized_trigger_digest: Option<Vec<u8>>,
    rejection_reason: Option<String>,
    observations: Vec<u8>,
    observations_digest: Vec<u8>,
    state: String,
    attempts: i16,
    available_at_ms: i64,
    accepted_at_ms: i64,
    claim_worker_id: Option<uuid::Uuid>,
    claim_fence: Option<i64>,
    claim_started_at_ms: Option<i64>,
    claim_expires_at_ms: Option<i64>,
    completed_at_ms: Option<i64>,
    failure_kind: Option<String>,
}

#[derive(FromRow)]
struct ReceiptRow {
    delivery_id: uuid::Uuid,
    state: String,
    attempts: i16,
    accepted_at_ms: i64,
}

impl PostgresProviderManifestRepository {
    pub(crate) async fn accept_delivery_inner(
        &self,
        request: AcceptProviderDelivery,
    ) -> Result<ProviderDeliveryAcceptOutcome, ProviderDeliveryRepositoryError> {
        let (delivery, accepted_at) = request.into_parts();
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
            transaction.commit().await.map_err(unavailable)?;
            let receipt = ProviderDeliveryReceipt::new(
                delivery.delivery_id(),
                match delivery {
                    ProviderDelivery::Trigger(_) => ProviderDeliveryState::Pending,
                    ProviderDelivery::Rejected(_) => ProviderDeliveryState::Discarded,
                },
                0,
                accepted_at,
            )
            .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?;
            return Ok(ProviderDeliveryAcceptOutcome::Inserted(receipt));
        }

        let row = sqlx::query_as::<_, ReceiptReplayRow>(
            r"
            SELECT delivery_id, state, attempts, accepted_at_ms, replay_fingerprint
            FROM provider_delivery_records
            WHERE provider_instance_id = $1 AND external_delivery_id = $2
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
        Ok(ProviderDeliveryAcceptOutcome::Duplicate(decode_receipt(
            ReceiptRow {
                delivery_id: row.delivery_id,
                state: row.state,
                attempts: row.attempts,
                accepted_at_ms: row.accepted_at_ms,
            },
        )?))
    }

    pub(crate) async fn load_delivery_inner(
        &self,
        delivery_id: ProviderDeliveryId,
    ) -> Result<Option<ProviderDelivery>, ProviderDeliveryRepositoryError> {
        sqlx::query_as::<_, DeliveryRow>(
            "SELECT * FROM provider_delivery_records WHERE delivery_id = $1",
        )
        .bind(delivery_id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable)?
        .map(decode_delivery)
        .transpose()
    }

    pub(crate) async fn claim_delivery_inner(
        &self,
        request: ClaimProviderDelivery,
    ) -> Result<Option<ClaimedProviderDelivery>, ProviderDeliveryRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(unavailable)?;
        let row = sqlx::query_as::<_, DeliveryRow>(
            r"
            SELECT * FROM provider_delivery_records
            WHERE disposition = 'trigger'
              AND attempts < 16
              AND (
                (state IN ('pending', 'retry-pending') AND available_at_ms <= $1)
                OR (state = 'claimed' AND claim_expires_at_ms <= $1)
              )
            ORDER BY available_at_ms, accepted_at_ms, delivery_id
            FOR UPDATE SKIP LOCKED
            LIMIT 1
            ",
        )
        .bind(request.claimed_at().get())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let Some(row) = row else {
            transaction.commit().await.map_err(unavailable)?;
            return Ok(None);
        };
        let next_attempt = positive_u16(row.attempts)?
            .checked_add(1)
            .ok_or(ProviderDeliveryRepositoryError::AttemptLimitReached)?;
        if next_attempt > MAX_PROVIDER_DELIVERY_ATTEMPTS {
            return Err(ProviderDeliveryRepositoryError::AttemptLimitReached);
        }
        let next_fence = match row.claim_fence {
            Some(value) => positive_u64(value)?
                .checked_add(1)
                .ok_or(ProviderDeliveryRepositoryError::Corrupt)?,
            None => 1,
        };
        let expires_at = request
            .claimed_at()
            .get()
            .checked_add(
                i64::try_from(request.lease_millis())
                    .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?,
            )
            .ok_or(ProviderDeliveryRepositoryError::Corrupt)?;
        sqlx::query(
            r"
            UPDATE provider_delivery_records
            SET state = 'claimed', attempts = $2, claim_worker_id = $3,
                claim_fence = $4, claim_started_at_ms = $6,
                claim_expires_at_ms = $5, failure_kind = NULL
            WHERE delivery_id = $1
            ",
        )
        .bind(row.delivery_id)
        .bind(i16::try_from(next_attempt).map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?)
        .bind(request.worker_id().as_uuid())
        .bind(durable_u64(next_fence)?)
        .bind(expires_at)
        .bind(request.claimed_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(unavailable)?;
        transaction.commit().await.map_err(unavailable)?;

        let accepted_at = row.accepted_at_ms;
        let delivery = match decode_delivery(row)? {
            ProviderDelivery::Trigger(value) => *value,
            ProviderDelivery::Rejected(_) => return Err(ProviderDeliveryRepositoryError::Corrupt),
        };
        let receipt = ProviderDeliveryReceipt::new(
            delivery.delivery_id(),
            ProviderDeliveryState::Claimed,
            next_attempt,
            UnixMillis::new(accepted_at),
        )
        .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?;
        let fence = ProviderDeliveryClaimFence::new(
            delivery.delivery_id(),
            request.worker_id(),
            next_fence,
            request.claimed_at(),
            UnixMillis::new(expires_at),
        )
        .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?;
        ClaimedProviderDelivery::new(receipt, delivery, fence)
            .map(Some)
            .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)
    }

    pub(crate) async fn complete_delivery_inner(
        &self,
        request: CompleteProviderDelivery,
    ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryRepositoryError> {
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

    pub(crate) async fn renew_delivery_inner(
        &self,
        request: RenewProviderDelivery,
    ) -> Result<ProviderDeliveryClaimFence, ProviderDeliveryRepositoryError> {
        let fence = request.fence();
        let extension = i64::try_from(request.lease_millis())
            .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?;
        let expires_at = request
            .renewed_at()
            .get()
            .checked_add(extension)
            .ok_or(ProviderDeliveryRepositoryError::Corrupt)?;
        let renewed = sqlx::query_scalar::<_, i64>(
            r"
            UPDATE provider_delivery_records
            SET claim_expires_at_ms = $5
            WHERE delivery_id = $1 AND state = 'claimed'
              AND claim_worker_id = $2 AND claim_fence = $3
              AND claim_started_at_ms <= $4
              AND claim_expires_at_ms > $4
              AND claim_expires_at_ms = $6
              AND claim_expires_at_ms < $5
            RETURNING claim_expires_at_ms
            ",
        )
        .bind(fence.delivery_id().as_uuid())
        .bind(fence.worker_id().as_uuid())
        .bind(durable_u64(fence.token())?)
        .bind(request.renewed_at().get())
        .bind(expires_at)
        .bind(fence.expires_at().get())
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable)?
        .ok_or(ProviderDeliveryRepositoryError::ClaimRejected)?;
        ProviderDeliveryClaimFence::new(
            fence.delivery_id(),
            fence.worker_id(),
            fence.token(),
            fence.claimed_at(),
            UnixMillis::new(renewed),
        )
        .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)
    }

    pub(crate) async fn retry_delivery_inner(
        &self,
        request: RetryProviderDelivery,
    ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryRepositoryError> {
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

    pub(crate) async fn fail_delivery_inner(
        &self,
        request: FailProviderDelivery,
    ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryRepositoryError> {
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
}

#[derive(FromRow)]
struct ReceiptReplayRow {
    delivery_id: uuid::Uuid,
    state: String,
    attempts: i16,
    accepted_at_ms: i64,
    replay_fingerprint: Vec<u8>,
}

#[allow(clippy::too_many_lines)] // Ordered bindings mirror one immutable delivery record.
async fn insert_delivery(
    transaction: &mut Transaction<'_, Postgres>,
    delivery: &ProviderDelivery,
    accepted_at: UnixMillis,
    fingerprint: Sha256Digest,
) -> Result<bool, ProviderDeliveryRepositoryError> {
    let (
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
        received_at,
        raw_body,
        raw_retain_until,
        signature,
        disposition,
        repository_id,
        trigger_bytes,
        trigger_digest,
        rejection,
        observations,
        state,
    ) = match delivery {
        ProviderDelivery::Trigger(value) => (
            value.delivery_id(),
            value.endpoint_id(),
            value.endpoint_revision(),
            value.provider_type(),
            value.instance_id(),
            value.provider_revision(),
            value.connection_id(),
            value.connection_revision(),
            value.external_delivery(),
            value.event_type(),
            value.received_at(),
            value.raw_body(),
            value.raw_retain_until(),
            value.signature(),
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
            value.observations(),
            "pending",
        ),
        ProviderDelivery::Rejected(value) => (
            value.delivery_id(),
            value.endpoint_id(),
            value.endpoint_revision(),
            value.provider_type(),
            value.instance_id(),
            value.provider_revision(),
            value.connection_id(),
            value.connection_revision(),
            value.external_delivery(),
            value.event_type(),
            value.received_at(),
            value.raw_body(),
            value.raw_retain_until(),
            value.signature(),
            "rejected",
            value
                .repository()
                .map(|identity| identity.external_id().as_str()),
            None,
            None,
            Some(rejection_text(value.reason())),
            value.observations(),
            "discarded",
        ),
    };
    let result = sqlx::query(
        r"
        INSERT INTO provider_delivery_records (
            delivery_id, provider_instance_id, external_delivery_id,
            replay_fingerprint, endpoint_id, endpoint_revision, provider_type,
            provider_revision, connection_id, connection_revision, event_type,
            received_at_ms, raw_object_key, raw_body_digest, raw_body_size,
            raw_media_type, raw_retain_until_ms, signature_scheme,
            signature_configuration_revision,
            signature_secret_name, signature_secret_generation, disposition,
            repository_external_id, normalized_trigger, normalized_trigger_digest,
            rejection_reason, observations, observations_digest, state, attempts,
            available_at_ms, accepted_at_ms
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
            $18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,0,$30,$30
        ) ON CONFLICT DO NOTHING
        ",
    )
    .bind(delivery_id.as_uuid())
    .bind(instance_id.as_uuid())
    .bind(external_delivery.external_id().as_str())
    .bind(fingerprint.as_bytes().as_slice())
    .bind(endpoint_id.as_uuid())
    .bind(durable_u64(endpoint_revision.get())?)
    .bind(provider_type.as_str())
    .bind(durable_u64(provider_revision.get())?)
    .bind(connection_id.as_uuid())
    .bind(durable_u64(connection_revision.get())?)
    .bind(event_type.as_str())
    .bind(received_at.get())
    .bind(raw_body.key().as_str())
    .bind(raw_body.digest().as_bytes().as_slice())
    .bind(durable_u64(raw_body.size())?)
    .bind(raw_body.media_type().as_str())
    .bind(raw_retain_until.get())
    .bind(signature.scheme())
    .bind(durable_u64(
        signature.secret().configuration_revision().get(),
    )?)
    .bind(signature.secret().name().as_str())
    .bind(durable_u64(signature.secret().generation().get())?)
    .bind(disposition)
    .bind(repository_id)
    .bind(trigger_bytes)
    .bind(trigger_digest.map(|value| value.as_bytes().to_vec()))
    .bind(rejection)
    .bind(observations.canonical_bytes())
    .bind(observations.digest().as_bytes().as_slice())
    .bind(state)
    .bind(accepted_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(unavailable)?;
    Ok(result.rows_affected() == 1)
}

async fn mutate_claim(
    pool: &sqlx::PgPool,
    fence: ProviderDeliveryClaimFence,
    mutation_at: UnixMillis,
    state: &'static str,
    available_or_completed_at: UnixMillis,
    failure: Option<ProviderDeliveryFailure>,
) -> Result<ProviderDeliveryReceipt, ProviderDeliveryRepositoryError> {
    let completed_at =
        matches!(state, "completed" | "failed").then_some(available_or_completed_at.get());
    let row = sqlx::query_as::<_, ReceiptRow>(
        r"
        UPDATE provider_delivery_records
        SET state = $5, available_at_ms = $6, claim_worker_id = NULL,
            claim_started_at_ms = NULL, claim_expires_at_ms = NULL,
            completed_at_ms = $7, failure_kind = $8
        WHERE delivery_id = $1 AND state = 'claimed'
          AND claim_worker_id = $2 AND claim_fence = $3
          AND claim_started_at_ms <= $4
          AND claim_expires_at_ms > $4
        RETURNING delivery_id, state, attempts, accepted_at_ms
        ",
    )
    .bind(fence.delivery_id().as_uuid())
    .bind(fence.worker_id().as_uuid())
    .bind(durable_u64(fence.token())?)
    .bind(mutation_at.get())
    .bind(state)
    .bind(available_or_completed_at.get())
    .bind(completed_at)
    .bind(failure.map(failure_text))
    .fetch_optional(pool)
    .await
    .map_err(unavailable)?
    .ok_or(ProviderDeliveryRepositoryError::ClaimRejected)?;
    decode_receipt(row)
}

#[allow(clippy::too_many_lines)] // Strict decoding validates every durable evidence field.
fn decode_delivery(row: DeliveryRow) -> Result<ProviderDelivery, ProviderDeliveryRepositoryError> {
    // Lifecycle-only columns are decoded separately by receipt operations.
    let _ = (
        &row.replay_fingerprint,
        &row.state,
        row.attempts,
        row.available_at_ms,
        row.accepted_at_ms,
        row.claim_worker_id,
        row.claim_fence,
        row.claim_started_at_ms,
        row.claim_expires_at_ms,
        row.completed_at_ms,
        &row.failure_kind,
    );
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
    match row.disposition.as_str() {
        "trigger" => {
            let trigger = SealedNormalizedTrigger::from_canonical_bytes(
                row.normalized_trigger
                    .ok_or(ProviderDeliveryRepositoryError::Corrupt)?,
            )
            .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?;
            if Some(trigger.digest()) != row.normalized_trigger_digest.map(digest).transpose()? {
                return Err(ProviderDeliveryRepositoryError::Corrupt);
            }
            VerifiedProviderDelivery::rehydrate(
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
                trigger,
                observations,
            )
            .map(Box::new)
            .map(ProviderDelivery::Trigger)
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
            RejectedProviderDelivery::rehydrate(
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
                repository,
                reason,
                observations,
            )
            .map(Box::new)
            .map(ProviderDelivery::Rejected)
            .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)
        }
        _ => Err(ProviderDeliveryRepositoryError::Corrupt),
    }
}

fn decode_receipt(
    row: ReceiptRow,
) -> Result<ProviderDeliveryReceipt, ProviderDeliveryRepositoryError> {
    let ReceiptRow {
        delivery_id,
        state: durable_state,
        attempts,
        accepted_at_ms,
    } = row;
    ProviderDeliveryReceipt::new(
        ProviderDeliveryId::from_uuid(delivery_id)
            .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?,
        state(&durable_state)?,
        positive_u16(attempts)?,
        UnixMillis::new(accepted_at_ms),
    )
    .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)
}

fn digest(value: Vec<u8>) -> Result<Sha256Digest, ProviderDeliveryRepositoryError> {
    value
        .try_into()
        .map(Sha256Digest::from_bytes)
        .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)
}

fn state(value: &str) -> Result<ProviderDeliveryState, ProviderDeliveryRepositoryError> {
    match value {
        "pending" => Ok(ProviderDeliveryState::Pending),
        "retry-pending" => Ok(ProviderDeliveryState::RetryPending),
        "claimed" => Ok(ProviderDeliveryState::Claimed),
        "completed" => Ok(ProviderDeliveryState::Completed),
        "failed" => Ok(ProviderDeliveryState::Failed),
        "discarded" => Ok(ProviderDeliveryState::Discarded),
        _ => Err(ProviderDeliveryRepositoryError::Corrupt),
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

const fn failure_text(value: ProviderDeliveryFailure) -> &'static str {
    match value {
        ProviderDeliveryFailure::DependencyUnavailable => "dependency-unavailable",
        ProviderDeliveryFailure::PolicyRejected => "policy-rejected",
        ProviderDeliveryFailure::InvalidEvidence => "invalid-evidence",
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

fn positive_u16(value: i16) -> Result<u16, ProviderDeliveryRepositoryError> {
    u16::try_from(value).map_err(|_| ProviderDeliveryRepositoryError::Corrupt)
}

fn unavailable(_: sqlx::Error) -> ProviderDeliveryRepositoryError {
    ProviderDeliveryRepositoryError::Unavailable
}
