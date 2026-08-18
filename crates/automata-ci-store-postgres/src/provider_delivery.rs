use async_trait::async_trait;
use automata_ci_core::{RunId, UnixMillis};
use sqlx::{PgPool, Postgres, Row as _, Transaction, postgres::PgRow};
use tokio::time::{Instant, timeout_at};
use uuid::Uuid;

use automata_ci_provider::ProviderConnectionId;
use automata_ci_store::{
    AcceptProviderDelivery, AdmissionObject, ClaimProviderDelivery, ClaimedProviderDelivery,
    CompleteProviderDelivery, GithubCheckTerminalCause, MAX_PROVIDER_DELIVERY_ATTEMPTS,
    MAX_PROVIDER_DELIVERY_CLAIM_MILLIS, MAX_PROVIDER_DELIVERY_TOTAL_CLAIM_MILLIS, ObjectKey,
    ProviderDeliveryClaimFence, ProviderDeliveryClaimRenewalRepository,
    ProviderDeliveryEventEnvelope, ProviderDeliveryId, ProviderDeliveryIdentity,
    ProviderDeliveryReceipt, ProviderDeliveryRepository, ProviderDeliveryState,
    ProviderDeliveryStoreError, ProviderDeliveryWorkflowConclusion,
    ProviderDeliveryWorkflowInventory, ProviderDeliveryWorkflowInventoryEntry,
    ProviderDeliveryWorkflowInventoryReceipt, ProviderDeliveryWorkflowOutcome,
    ProviderDeliveryWorkflowSourceState, ProviderInstallationId, ProviderProcessingWorkerId,
    ProviderRepositoryCoordinates, ProviderRepositoryId, ProviderRepositoryVisibility,
    RecordProviderDeliveryWorkflowProgress, RegisterProviderDeliveryWorkflowInventory,
    RejectProviderDelivery, RenewProviderDeliveryClaim, RenewedProviderDeliveryClaim,
    RetryProviderDelivery, Sha256Digest, TenantScope,
};

use super::{
    PostgresStore,
    github_check_aggregation::{GithubCheckAggregationError, reconcile_all_direct_check},
    github_checks::{github_check_conclusion_name, github_check_terminal_cause_name},
    pg_bigint,
};

const MAX_CALLER_DATABASE_SKEW_MILLIS: u64 = 60_000;
const LEGACY_UNSEALED_FAILURE_KIND: &str = "provider_delivery.legacy_unsealed";
const LEGACY_UNSEALED_QUARANTINE_BATCH: i64 = 64;

#[allow(clippy::too_many_lines)]
#[async_trait]
impl ProviderDeliveryRepository for PostgresStore {
    async fn accept_provider_delivery(
        &self,
        request: AcceptProviderDelivery,
    ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError> {
        let proposed_id = Uuid::new_v4();
        let row = sqlx::query(
            r"
            INSERT INTO provider_delivery_inbox (
                id, tenant_id, provider, connection_id, installation_id,
                provider_repository_id, repository_visibility,
                repository_identity, delivery_id,
                request_digest, raw_event_digest, raw_event_object_key,
                raw_event_size_bytes, raw_event_media_type,
                event_envelope_schema, event_registry_schema,
                event_envelope_digest, event_envelope_bytes,
                event_envelope_media_type,
                accepted_at_ms, state_updated_at_ms
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9,
                $10, $11, $12, $13, $14, $15, $16, $17,
                $18, $19, $20, $20
            )
            ON CONFLICT (provider, connection_id, delivery_id) DO NOTHING
            RETURNING
                id, tenant_id, provider, connection_id, installation_id,
                provider_repository_id, repository_visibility,
                repository_identity, delivery_id,
                request_digest, raw_event_digest, raw_event_object_key,
                raw_event_size_bytes, raw_event_media_type,
                event_envelope_schema, event_registry_schema,
                event_envelope_digest, event_envelope_bytes,
                event_envelope_media_type, state,
                attempt_count, accepted_at_ms
            ",
        )
        .bind(proposed_id)
        .bind(request.identity().tenant().as_str())
        .bind(request.identity().provider())
        .bind(request.identity().connection_id().as_uuid())
        .bind(pg_bigint(request.identity().installation_id().get()))
        .bind(pg_bigint(request.identity().repository_id().get()))
        .bind(provider_repository_visibility_name(
            request.identity().repository_visibility(),
        ))
        .bind(request.identity().repository_identity())
        .bind(request.identity().delivery_id())
        .bind(request.request_digest().as_bytes().as_slice())
        .bind(request.raw_event().digest().as_bytes().as_slice())
        .bind(request.raw_event().object_key().as_str())
        .bind(object_size_i64(request.raw_event())?)
        .bind(request.raw_event().media_type())
        .bind(i16::try_from(request.event_envelope().schema()).expect("validated schema fits"))
        .bind(
            i16::try_from(request.event_envelope().registry_schema())
                .expect("validated registry schema fits"),
        )
        .bind(request.event_envelope().digest().as_bytes().as_slice())
        .bind(request.event_envelope().canonical_bytes())
        .bind(request.event_envelope().media_type())
        .bind(request.accepted_at().get())
        .fetch_optional(&self.pool)
        .await
        .map_err(operation_error)?;

        let row = match row {
            Some(row) => row,
            None => sqlx::query(
                r"
                    SELECT
                        id, tenant_id, provider, connection_id, installation_id,
                        provider_repository_id, repository_visibility,
                        repository_identity, delivery_id,
                        request_digest, raw_event_digest, raw_event_object_key,
                        raw_event_size_bytes, raw_event_media_type,
                        event_envelope_schema, event_registry_schema,
                        event_envelope_digest, event_envelope_bytes,
                        event_envelope_media_type, state,
                        attempt_count, accepted_at_ms
                    FROM provider_delivery_inbox
                    WHERE provider = $1
                      AND connection_id = $2
                      AND delivery_id = $3
                    ",
            )
            .bind(request.identity().provider())
            .bind(request.identity().connection_id().as_uuid())
            .bind(request.identity().delivery_id())
            .fetch_optional(&self.pool)
            .await
            .map_err(operation_error)?
            .ok_or(ProviderDeliveryStoreError::CorruptData)?,
        };
        let durable = decode_delivery(&row)?;
        if durable.identity != *request.identity()
            || durable.request_digest != request.request_digest()
            || durable.raw_event != *request.raw_event()
            || durable.event_envelope != *request.event_envelope()
        {
            return Err(ProviderDeliveryStoreError::ReplayConflict);
        }
        Ok(durable.receipt)
    }

    async fn claim_provider_delivery(
        &self,
        request: ClaimProviderDelivery,
    ) -> Result<Option<ClaimedProviderDelivery>, ProviderDeliveryStoreError> {
        let claim_duration = request
            .expires_at()
            .get()
            .checked_sub(request.observed_at().get())
            .ok_or(ProviderDeliveryStoreError::CorruptData)?;
        let mut transaction = begin_read_committed_transaction(&self.pool).await?;
        let admission_time = database_time(&mut transaction).await?;
        if !caller_time_is_admissible(request.observed_at(), admission_time) {
            return Err(ProviderDeliveryStoreError::ClaimRejected);
        }
        quarantine_legacy_unsealed_deliveries(&mut transaction, request.owner(), admission_time)
            .await?;

        let candidate: Option<(Uuid, i64)> = sqlx::query_as(
            r"
            WITH database_time AS MATERIALIZED (
                SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms
            )
            SELECT inbox.id, database_time.now_ms
            FROM provider_delivery_inbox AS inbox
            CROSS JOIN database_time
            WHERE inbox.event_envelope_schema IS NOT NULL
              AND inbox.state_updated_at_ms <= database_time.now_ms
              AND inbox.claim_fence < 9223372036854775807
              AND (
                inbox.state = 'pending'
                OR (
                    inbox.state = 'retry'
                    AND inbox.next_attempt_at_ms <= database_time.now_ms
                )
                OR (
                    inbox.state = 'claimed'
                    AND inbox.claim_expires_at_ms <= database_time.now_ms
                )
              )
              AND (inbox.state = 'claimed' OR inbox.attempt_count < 16)
            ORDER BY
                CASE inbox.state
                    WHEN 'pending' THEN inbox.accepted_at_ms
                    WHEN 'retry' THEN inbox.next_attempt_at_ms
                    ELSE inbox.claim_expires_at_ms
                END,
                inbox.accepted_at_ms,
                inbox.id
            FOR UPDATE OF inbox SKIP LOCKED
            LIMIT 1
            ",
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?;

        let Some((candidate, selection_time)) = candidate else {
            let exhausted_at = database_time(&mut transaction).await?;
            let fence_exhausted = eligible_exhausted_fence(&mut transaction, exhausted_at).await?;
            transaction.commit().await.map_err(operation_error)?;
            return if fence_exhausted {
                Err(ProviderDeliveryStoreError::FenceExhausted)
            } else {
                Ok(None)
            };
        };

        // Eligibility and the issued horizon are re-evaluated after the row is
        // locked. Caller time is never persisted as claim authority.
        let claimed_at = database_time(&mut transaction).await?;
        if claimed_at < admission_time || claimed_at.get() < selection_time {
            return Err(ProviderDeliveryStoreError::CorruptData);
        }
        let expires_at = claimed_at
            .get()
            .checked_add(claim_duration)
            .map(UnixMillis::new)
            .ok_or(ProviderDeliveryStoreError::CorruptData)?;
        let row = sqlx::query(
            r"
            UPDATE provider_delivery_inbox AS inbox
            SET state = 'claimed',
                attempt_count = CASE
                    WHEN inbox.state = 'claimed' THEN inbox.attempt_count
                    ELSE inbox.attempt_count + 1
                END,
                claim_fence = inbox.claim_fence + 1,
                claim_owner_id = $2,
                claimed_at_ms = $3,
                claim_expires_at_ms = $4,
                renewal_predecessor_expires_at_ms = NULL,
                next_attempt_at_ms = NULL,
                terminal_claim_owner_id = NULL,
                terminal_claim_fence = NULL,
                completion_digest = NULL,
                completion_outcome_count = NULL,
                completed_at_ms = NULL,
                rejected_at_ms = NULL,
                state_updated_at_ms = $3
            WHERE inbox.id = $1
              AND inbox.event_envelope_schema IS NOT NULL
              AND inbox.state_updated_at_ms <= $3
              AND inbox.claim_fence < 9223372036854775807
              AND (
                inbox.state = 'pending'
                OR (inbox.state = 'retry' AND inbox.next_attempt_at_ms <= $3)
                OR (inbox.state = 'claimed' AND inbox.claim_expires_at_ms <= $3)
              )
              AND (inbox.state = 'claimed' OR inbox.attempt_count < 16)
            RETURNING
                inbox.id, inbox.tenant_id, inbox.provider,
                inbox.connection_id, inbox.installation_id,
                inbox.provider_repository_id, inbox.repository_visibility,
                inbox.repository_identity,
                inbox.delivery_id, inbox.request_digest,
                inbox.raw_event_digest, inbox.raw_event_object_key,
                inbox.raw_event_size_bytes, inbox.raw_event_media_type,
                inbox.event_envelope_schema, inbox.event_registry_schema,
                inbox.event_envelope_digest, inbox.event_envelope_bytes,
                inbox.event_envelope_media_type,
                inbox.state, inbox.attempt_count, inbox.accepted_at_ms,
                inbox.claim_owner_id, inbox.claim_fence,
                inbox.claimed_at_ms, inbox.claim_expires_at_ms
            ",
        )
        .bind(candidate)
        .bind(request.owner().as_uuid())
        .bind(claimed_at.get())
        .bind(expires_at.get())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?;

        if let Some(row) = row {
            let claimed = decode_claimed_delivery(&row)?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(Some(claimed));
        }

        let fence_exhausted = eligible_exhausted_fence(&mut transaction, claimed_at).await?;
        transaction.commit().await.map_err(operation_error)?;
        if fence_exhausted {
            return Err(ProviderDeliveryStoreError::FenceExhausted);
        }
        Ok(None)
    }

    async fn complete_provider_delivery(
        &self,
        request: CompleteProviderDelivery,
    ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let row = sqlx::query(
            r"
            UPDATE provider_delivery_inbox
            SET state = 'completed',
                claim_owner_id = NULL,
                claimed_at_ms = NULL,
                claim_expires_at_ms = NULL,
                renewal_predecessor_expires_at_ms = NULL,
                terminal_claim_owner_id = $2,
                terminal_claim_fence = $3,
                completion_digest = $4,
                completion_outcome_count = $5,
                completed_at_ms = $6,
                state_updated_at_ms = $6
            WHERE id = $1
              AND state = 'claimed'
              AND claim_owner_id = $2
              AND claim_fence = $3
              AND claimed_at_ms <= $6
              AND state_updated_at_ms <= $6
              AND claim_expires_at_ms > $6
            RETURNING id, tenant_id, state, attempt_count, accepted_at_ms
            ",
        )
        .bind(request.claim().delivery_id().as_uuid())
        .bind(request.claim().owner().as_uuid())
        .bind(pg_bigint(request.claim().fence()))
        .bind(request.completion_digest().as_bytes().as_slice())
        .bind(outcome_count_i16(request.outcomes())?)
        .bind(request.completed_at().get())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?;

        let receipt = if let Some(row) = row {
            let receipt = decode_receipt(&row)?;
            let tenant_id: String = row.try_get("tenant_id").map_err(operation_error)?;
            TenantScope::from_authenticated_tenant_id(tenant_id.clone())
                .map_err(|_| ProviderDeliveryStoreError::CorruptData)?;
            insert_outcomes(&mut transaction, receipt.id(), &tenant_id, &request).await?;
            receipt
        } else {
            verify_exact_completion(&mut transaction, &request).await?
        };
        let all_direct = delivery_uses_all_direct_workflow_selection(
            &mut transaction,
            request.claim().delivery_id(),
        )
        .await?;
        if all_direct {
            reconcile_all_direct_check(
                &mut transaction,
                request.claim().delivery_id().as_uuid(),
                request.completed_at().get(),
            )
            .await
            .map_err(provider_delivery_aggregation_error)?;
        } else if let Some(cause) = completion_check_terminal_cause(request.outcomes()) {
            terminalize_pre_admission_check(
                &mut transaction,
                request.claim().delivery_id(),
                cause,
                request.completed_at(),
            )
            .await?;
        }
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }

    async fn register_provider_delivery_workflow_inventory(
        &self,
        request: RegisterProviderDeliveryWorkflowInventory,
    ) -> Result<ProviderDeliveryWorkflowInventoryReceipt, ProviderDeliveryStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let inventory = request.inventory();
        let inserted = sqlx::query(
            r"
            INSERT INTO provider_delivery_workflow_inventories (
                inbox_id, tenant_id, manifest_digest, source_revision,
                repository_source_digest, inventory_digest, workflow_count,
                registered_at_ms
            )
            SELECT inbox.id, inbox.tenant_id, $4, $5, $6, $7, $8, $9
            FROM provider_delivery_inbox AS inbox
            JOIN github_provider_delivery_evidence AS evidence
              ON evidence.provider_delivery_id = inbox.id
             AND evidence.tenant_id = inbox.tenant_id
             AND evidence.provider_manifest_digest = $4
            WHERE inbox.id = $1
              AND inbox.state = 'claimed'
              AND inbox.claim_owner_id = $2
              AND inbox.claim_fence = $3
              AND inbox.claimed_at_ms <= $9
              AND inbox.claim_expires_at_ms > $9
            ON CONFLICT (inbox_id) DO NOTHING
            ",
        )
        .bind(request.claim().delivery_id().as_uuid())
        .bind(request.claim().owner().as_uuid())
        .bind(pg_bigint(request.claim().fence()))
        .bind(inventory.manifest_digest().as_bytes().as_slice())
        .bind(inventory.source_revision().as_bytes())
        .bind(inventory.repository_source_digest().as_bytes().as_slice())
        .bind(inventory.digest().as_bytes().as_slice())
        .bind(
            i16::try_from(inventory.entries().len())
                .map_err(|_| ProviderDeliveryStoreError::CorruptData)?,
        )
        .bind(request.observed_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;

        if inserted.rows_affected() == 1 {
            insert_workflow_inventory_entries(
                &mut transaction,
                request.claim().delivery_id(),
                inventory,
            )
            .await?;
        }
        require_live_inventory_claim(&mut transaction, &request).await?;
        let receipt =
            load_workflow_inventory_receipt(&mut transaction, request.claim().delivery_id())
                .await?
                .ok_or(ProviderDeliveryStoreError::WorkflowProgressRejected)?;
        if receipt.inventory() != inventory {
            return Err(ProviderDeliveryStoreError::WorkflowProgressRejected);
        }
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }

    async fn record_provider_delivery_workflow_progress(
        &self,
        request: RecordProviderDeliveryWorkflowProgress,
    ) -> Result<ProviderDeliveryWorkflowOutcome, ProviderDeliveryStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        require_live_progress_claim(&mut transaction, &request).await?;
        insert_workflow_progress(&mut transaction, &request).await?;
        if matches!(
            request.outcome().conclusion(),
            ProviderDeliveryWorkflowConclusion::Failed { .. }
        ) {
            terminalize_failed_workflow_check(&mut transaction, &request).await?;
        }
        let outcome = load_workflow_progress(
            &mut transaction,
            request.claim().delivery_id(),
            request.outcome().workflow_path(),
        )
        .await?
        .ok_or(ProviderDeliveryStoreError::WorkflowProgressRejected)?;
        if &outcome != request.outcome() {
            return Err(ProviderDeliveryStoreError::WorkflowProgressRejected);
        }
        transaction.commit().await.map_err(operation_error)?;
        Ok(outcome)
    }

    async fn retry_provider_delivery(
        &self,
        request: RetryProviderDelivery,
    ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError> {
        let row = sqlx::query(
            r"
            UPDATE provider_delivery_inbox
            SET state = 'retry',
                claim_owner_id = NULL,
                claimed_at_ms = NULL,
                claim_expires_at_ms = NULL,
                renewal_predecessor_expires_at_ms = NULL,
                next_attempt_at_ms = $4,
                last_failure_kind = $5,
                state_updated_at_ms = $6
            WHERE id = $1
              AND state = 'claimed'
              AND claim_owner_id = $2
              AND claim_fence = $3
              AND claimed_at_ms <= $6
              AND state_updated_at_ms <= $6
              AND claim_expires_at_ms > $6
              AND attempt_count < 16
            RETURNING id, state, attempt_count, accepted_at_ms
            ",
        )
        .bind(request.claim().delivery_id().as_uuid())
        .bind(request.claim().owner().as_uuid())
        .bind(pg_bigint(request.claim().fence()))
        .bind(request.retry_at().get())
        .bind(request.failure_kind().as_str())
        .bind(request.observed_at().get())
        .fetch_optional(&self.pool)
        .await
        .map_err(operation_error)?;
        if let Some(row) = row {
            return decode_receipt(&row);
        }
        if live_claim_attempts(&self.pool, request.claim(), request.observed_at()).await?
            == Some(MAX_PROVIDER_DELIVERY_ATTEMPTS)
        {
            return Err(ProviderDeliveryStoreError::RetryLimitReached);
        }
        Err(ProviderDeliveryStoreError::ClaimRejected)
    }

    async fn reject_provider_delivery(
        &self,
        request: RejectProviderDelivery,
    ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let row = sqlx::query(
            r"
            UPDATE provider_delivery_inbox
            SET state = 'rejected',
                claim_owner_id = NULL,
                claimed_at_ms = NULL,
                claim_expires_at_ms = NULL,
                renewal_predecessor_expires_at_ms = NULL,
                next_attempt_at_ms = NULL,
                last_failure_kind = $4,
                terminal_claim_owner_id = $2,
                terminal_claim_fence = $3,
                rejected_at_ms = $5,
                state_updated_at_ms = $5
            WHERE id = $1
              AND state = 'claimed'
              AND claim_owner_id = $2
              AND claim_fence = $3
              AND claimed_at_ms <= $5
              AND state_updated_at_ms <= $5
              AND claim_expires_at_ms > $5
            RETURNING id, state, attempt_count, accepted_at_ms
            ",
        )
        .bind(request.claim().delivery_id().as_uuid())
        .bind(request.claim().owner().as_uuid())
        .bind(pg_bigint(request.claim().fence()))
        .bind(request.failure_kind().as_str())
        .bind(request.rejected_at().get())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?;
        let receipt = row
            .as_ref()
            .map(decode_receipt)
            .transpose()?
            .ok_or(ProviderDeliveryStoreError::ClaimRejected)?;
        terminalize_pre_admission_check(
            &mut transaction,
            request.claim().delivery_id(),
            GithubCheckTerminalCause::SystemUnknown,
            request.rejected_at(),
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }
}

fn completion_check_terminal_cause(
    outcomes: &[ProviderDeliveryWorkflowOutcome],
) -> Option<GithubCheckTerminalCause> {
    if outcomes.iter().any(|outcome| {
        matches!(
            outcome.conclusion(),
            ProviderDeliveryWorkflowConclusion::Admitted { .. }
        )
    }) {
        None
    } else if outcomes.iter().any(|outcome| {
        matches!(
            outcome.conclusion(),
            ProviderDeliveryWorkflowConclusion::Failed { .. }
        )
    }) {
        Some(GithubCheckTerminalCause::WorkflowFailure)
    } else {
        Some(GithubCheckTerminalCause::WorkflowSkipped)
    }
}

async fn delivery_uses_all_direct_workflow_selection(
    transaction: &mut Transaction<'_, Postgres>,
    delivery_id: ProviderDeliveryId,
) -> Result<bool, ProviderDeliveryStoreError> {
    sqlx::query_scalar::<_, bool>(
        r"
        SELECT manifest.workflow_selection_kind = 'all_direct'
        FROM github_provider_delivery_evidence AS evidence
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = evidence.tenant_id
         AND manifest.repository_id = evidence.repository_id
         AND manifest.provider_connection_id = evidence.provider_connection_id
         AND manifest.manifest_revision = evidence.provider_manifest_revision
         AND manifest.manifest_digest = evidence.provider_manifest_digest
        WHERE evidence.provider_delivery_id = $1
        FOR SHARE OF evidence, manifest
        ",
    )
    .bind(delivery_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
    .map(Option::unwrap_or_default)
}

async fn terminalize_pre_admission_check(
    transaction: &mut Transaction<'_, Postgres>,
    delivery_id: ProviderDeliveryId,
    cause: GithubCheckTerminalCause,
    terminal_at: UnixMillis,
) -> Result<(), ProviderDeliveryStoreError> {
    let row = sqlx::query(
        r"
        SELECT id, workflow_run_id, desired_state, desired_conclusion,
               terminal_cause, desired_revision, desired_updated_at_ms
        FROM github_check_subjects AS subject
        JOIN github_provider_delivery_evidence AS evidence
          ON evidence.github_check_subject_id = subject.id
         AND evidence.provider_delivery_id = subject.provider_delivery_id
         AND evidence.tenant_id = subject.tenant_id
        WHERE evidence.provider_delivery_id = $1
        FOR UPDATE OF subject
        ",
    )
    .bind(delivery_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(row) = row else {
        return if provider_delivery_evidence_exists(transaction, delivery_id).await? {
            Err(ProviderDeliveryStoreError::CorruptData)
        } else {
            Ok(())
        };
    };
    let subject_id: Uuid = row.try_get("id").map_err(operation_error)?;
    let workflow_run_id: Option<Uuid> = row.try_get("workflow_run_id").map_err(operation_error)?;
    let desired_state: String = row.try_get("desired_state").map_err(operation_error)?;
    let desired_conclusion: Option<String> =
        row.try_get("desired_conclusion").map_err(operation_error)?;
    let terminal_cause: Option<String> = row.try_get("terminal_cause").map_err(operation_error)?;
    let desired_revision: i64 = row.try_get("desired_revision").map_err(operation_error)?;
    let desired_updated_at: i64 = row
        .try_get("desired_updated_at_ms")
        .map_err(operation_error)?;
    if desired_updated_at < 0 {
        return Err(ProviderDeliveryStoreError::CorruptData);
    }
    if workflow_run_id.is_some() {
        return Ok(());
    }
    let expected_conclusion = github_check_conclusion_name(cause.conclusion());
    let expected_cause = github_check_terminal_cause_name(cause);
    if desired_state == "completed" {
        return if desired_conclusion.as_deref() == Some(expected_conclusion)
            && terminal_cause.as_deref() == Some(expected_cause)
            && desired_revision == 2
            && desired_updated_at == terminal_at.get()
        {
            Ok(())
        } else {
            Err(ProviderDeliveryStoreError::CorruptData)
        };
    }
    if desired_state != "queued"
        || desired_conclusion.is_some()
        || terminal_cause.is_some()
        || desired_revision != 1
        || desired_updated_at > terminal_at.get()
    {
        return Err(ProviderDeliveryStoreError::CorruptData);
    }
    let updated = sqlx::query_scalar::<_, Uuid>(
        r"
        UPDATE github_check_subjects
        SET desired_state = 'completed',
            desired_conclusion = $2,
            terminal_cause = $3,
            desired_revision = desired_revision + 1,
            desired_updated_at_ms = $4
        WHERE id = $1
          AND workflow_run_id IS NULL
          AND desired_state = 'queued'
          AND desired_conclusion IS NULL
          AND terminal_cause IS NULL
          AND desired_revision = 1
          AND desired_updated_at_ms <= $4
        RETURNING id
        ",
    )
    .bind(subject_id)
    .bind(expected_conclusion)
    .bind(expected_cause)
    .bind(terminal_at.get())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if updated == Some(subject_id) {
        Ok(())
    } else {
        Err(ProviderDeliveryStoreError::CorruptData)
    }
}

async fn provider_delivery_evidence_exists(
    transaction: &mut Transaction<'_, Postgres>,
    delivery_id: ProviderDeliveryId,
) -> Result<bool, ProviderDeliveryStoreError> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM github_provider_delivery_evidence \
         WHERE provider_delivery_id = $1)",
    )
    .bind(delivery_id.as_uuid())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn database_time(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<UnixMillis, ProviderDeliveryStoreError> {
    let milliseconds: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(&mut **transaction)
            .await
            .map_err(operation_error)?;
    if milliseconds < 0 {
        return Err(ProviderDeliveryStoreError::CorruptData);
    }
    Ok(UnixMillis::new(milliseconds))
}

fn caller_time_is_admissible(observed_at: UnixMillis, database_time: UnixMillis) -> bool {
    observed_at.get().abs_diff(database_time.get()) <= MAX_CALLER_DATABASE_SKEW_MILLIS
}

/// Terminally isolates rows accepted before sealed envelopes became mandatory.
///
/// A bounded, lock-skipping pass prevents legacy evidence from blocking newer
/// work while ensuring it can never be claimed and interpreted from raw JSON.
async fn quarantine_legacy_unsealed_deliveries(
    transaction: &mut Transaction<'_, Postgres>,
    owner: ProviderProcessingWorkerId,
    observed_at: UnixMillis,
) -> Result<(), ProviderDeliveryStoreError> {
    sqlx::query(
        r"
        WITH candidates AS MATERIALIZED (
            SELECT inbox.id
            FROM provider_delivery_inbox AS inbox
            WHERE inbox.event_envelope_schema IS NULL
              AND inbox.state_updated_at_ms <= $2
              AND inbox.claim_fence < 9223372036854775807
              AND (
                inbox.state = 'pending'
                OR (
                    inbox.state = 'retry'
                    AND inbox.next_attempt_at_ms <= $2
                )
                OR (
                    inbox.state = 'claimed'
                    AND inbox.claim_expires_at_ms <= $2
                )
              )
              AND (inbox.state = 'claimed' OR inbox.attempt_count < 16)
            ORDER BY inbox.accepted_at_ms, inbox.id
            FOR UPDATE OF inbox SKIP LOCKED
            LIMIT $3
        )
        UPDATE provider_delivery_inbox AS inbox
        SET state = 'rejected',
            attempt_count = GREATEST(inbox.attempt_count, 1),
            claim_fence = inbox.claim_fence + 1,
            claim_owner_id = NULL,
            claimed_at_ms = NULL,
            claim_expires_at_ms = NULL,
            renewal_predecessor_expires_at_ms = NULL,
            next_attempt_at_ms = NULL,
            last_failure_kind = $4,
            terminal_claim_owner_id = $1,
            terminal_claim_fence = inbox.claim_fence + 1,
            completion_digest = NULL,
            completion_outcome_count = NULL,
            completed_at_ms = NULL,
            rejected_at_ms = $2,
            state_updated_at_ms = $2
        FROM candidates
        WHERE inbox.id = candidates.id
        ",
    )
    .bind(owner.as_uuid())
    .bind(observed_at.get())
    .bind(LEGACY_UNSEALED_QUARANTINE_BATCH)
    .bind(LEGACY_UNSEALED_FAILURE_KIND)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn eligible_exhausted_fence(
    transaction: &mut Transaction<'_, Postgres>,
    database_time: UnixMillis,
) -> Result<bool, ProviderDeliveryStoreError> {
    sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM provider_delivery_inbox
            WHERE event_envelope_schema IS NOT NULL
              AND state_updated_at_ms <= $1
              AND claim_fence = 9223372036854775807
              AND (
                state = 'pending'
                OR (state = 'retry' AND next_attempt_at_ms <= $1)
                OR (state = 'claimed' AND claim_expires_at_ms <= $1)
              )
              AND (state = 'claimed' OR attempt_count < 16)
        )
        ",
    )
    .bind(database_time.get())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)
}

#[derive(Clone, Copy)]
struct RenewalSqlEvidence {
    request: RenewProviderDeliveryClaim,
    renewed_fence: u64,
    renewed_fence_i64: i64,
    attempt_i16: i16,
    duration_millis: i64,
}

impl RenewalSqlEvidence {
    fn new(request: RenewProviderDeliveryClaim) -> Result<Self, ProviderDeliveryStoreError> {
        let renewed_fence = request
            .claim()
            .fence()
            .checked_add(1)
            .filter(|fence| i64::try_from(*fence).is_ok())
            .ok_or(ProviderDeliveryStoreError::FenceExhausted)?;
        Ok(Self {
            request,
            renewed_fence,
            renewed_fence_i64: i64::try_from(renewed_fence)
                .map_err(|_| ProviderDeliveryStoreError::FenceExhausted)?,
            attempt_i16: i16::try_from(request.attempt())
                .map_err(|_| ProviderDeliveryStoreError::CorruptData)?,
            duration_millis: request
                .expires_at()
                .get()
                .checked_sub(request.observed_at().get())
                .ok_or(ProviderDeliveryStoreError::CorruptData)?,
        })
    }
}

async fn begin_read_committed_transaction(
    pool: &PgPool,
) -> Result<Transaction<'_, Postgres>, ProviderDeliveryStoreError> {
    let mut transaction = pool.begin().await.map_err(operation_error)?;
    // A waiter must re-evaluate the row after a concurrent predecessor wins.
    // Do not inherit a mutable pool/session default that can turn that exact
    // successor replay into a serialization failure.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
    Ok(transaction)
}

async fn lock_exact_renewal_predecessor(
    transaction: &mut Transaction<'_, Postgres>,
    evidence: RenewalSqlEvidence,
) -> Result<Option<PgRow>, ProviderDeliveryStoreError> {
    let request = evidence.request;
    sqlx::query(
        r"
        SELECT id, claim_owner_id, claim_fence, attempt_count, claimed_at_ms,
               state_updated_at_ms, claim_expires_at_ms,
               renewal_predecessor_expires_at_ms
        FROM provider_delivery_inbox
        WHERE id = $1
          AND state = 'claimed'
          AND claim_owner_id = $2
          AND attempt_count = $3
          AND claimed_at_ms = $4
          AND (
              (
                  claim_fence = $5
                  AND claim_expires_at_ms = $6
              ) OR (
                  claim_fence = $7
                  AND renewal_predecessor_expires_at_ms = $6
                  AND claim_expires_at_ms - state_updated_at_ms = $8
              )
          )
        FOR UPDATE
        ",
    )
    .bind(request.claim().delivery_id().as_uuid())
    .bind(request.claim().owner().as_uuid())
    .bind(evidence.attempt_i16)
    .bind(request.claimed_at().get())
    .bind(pg_bigint(request.claim().fence()))
    .bind(request.predecessor_expires_at().get())
    .bind(evidence.renewed_fence_i64)
    .bind(evidence.duration_millis)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn update_locked_renewal_predecessor(
    transaction: &mut Transaction<'_, Postgres>,
    evidence: RenewalSqlEvidence,
    renewed_at: UnixMillis,
    expires_at: UnixMillis,
) -> Result<Option<PgRow>, ProviderDeliveryStoreError> {
    let request = evidence.request;
    sqlx::query(
        r"
        UPDATE provider_delivery_inbox
        SET claim_fence = $8,
            claim_expires_at_ms = $5,
            state_updated_at_ms = $4,
            renewal_predecessor_expires_at_ms = $11
        WHERE id = $1
          AND state = 'claimed'
          AND claim_owner_id = $2
          AND claim_fence = $3
          AND attempt_count = $9
          AND claimed_at_ms = $10
          AND claimed_at_ms < $4
          AND state_updated_at_ms < $4
          AND claim_expires_at_ms = $11
          AND claim_expires_at_ms > $4
          AND $5 > claim_expires_at_ms
          AND $5 - $4 BETWEEN 1 AND $6
          AND $5 - claimed_at_ms BETWEEN 1 AND $7
        RETURNING id, claim_owner_id, claim_fence, attempt_count, claimed_at_ms,
                  state_updated_at_ms, claim_expires_at_ms,
                  renewal_predecessor_expires_at_ms
        ",
    )
    .bind(request.claim().delivery_id().as_uuid())
    .bind(request.claim().owner().as_uuid())
    .bind(pg_bigint(request.claim().fence()))
    .bind(renewed_at.get())
    .bind(expires_at.get())
    .bind(MAX_PROVIDER_DELIVERY_CLAIM_MILLIS)
    .bind(MAX_PROVIDER_DELIVERY_TOTAL_CLAIM_MILLIS)
    .bind(evidence.renewed_fence_i64)
    .bind(evidence.attempt_i16)
    .bind(request.claimed_at().get())
    .bind(request.predecessor_expires_at().get())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn load_exact_renewal_replay(
    pool: &PgPool,
    evidence: RenewalSqlEvidence,
) -> Result<RenewedProviderDeliveryClaim, ProviderDeliveryStoreError> {
    let mut transaction = begin_read_committed_transaction(pool).await?;
    // Lock through the same predecessor-or-successor predicate as the initial
    // attempt. A successor-only MVCC query can filter an uncommitted winner's
    // still-visible predecessor before it ever waits on the row lock.
    let row = lock_exact_renewal_predecessor(&mut transaction, evidence)
        .await?
        .ok_or(ProviderDeliveryStoreError::ClaimRejected)?;
    let locked_fence: i64 = row.try_get("claim_fence").map_err(operation_error)?;
    if locked_fence != evidence.renewed_fence_i64 {
        return Err(ProviderDeliveryStoreError::ClaimRejected);
    }
    let renewed = decode_exact_renewal(&row, evidence)?;
    transaction.commit().await.map_err(operation_error)?;
    Ok(renewed)
}

fn decode_exact_renewal(
    row: &PgRow,
    evidence: RenewalSqlEvidence,
) -> Result<RenewedProviderDeliveryClaim, ProviderDeliveryStoreError> {
    let request = evidence.request;
    let returned_owner: Uuid = row.try_get("claim_owner_id").map_err(operation_error)?;
    let returned_fence: i64 = row.try_get("claim_fence").map_err(operation_error)?;
    let returned_predecessor_expiry: i64 = row
        .try_get("renewal_predecessor_expires_at_ms")
        .map_err(operation_error)?;
    let claim = ProviderDeliveryClaimFence::from_durable_parts(
        request.claim().delivery_id(),
        ProviderProcessingWorkerId::from_uuid(returned_owner)
            .map_err(|_| ProviderDeliveryStoreError::CorruptData)?,
        u64::try_from(returned_fence).map_err(|_| ProviderDeliveryStoreError::CorruptData)?,
    )
    .map_err(|_| ProviderDeliveryStoreError::CorruptData)?;
    if claim.owner() != request.claim().owner() || claim.fence() != evidence.renewed_fence {
        return Err(ProviderDeliveryStoreError::CorruptData);
    }
    let renewed = RenewedProviderDeliveryClaim::from_durable_parts(
        claim,
        u16::try_from(
            row.try_get::<i16, _>("attempt_count")
                .map_err(operation_error)?,
        )
        .map_err(|_| ProviderDeliveryStoreError::CorruptData)?,
        UnixMillis::new(row.try_get("claimed_at_ms").map_err(operation_error)?),
        UnixMillis::new(
            row.try_get("state_updated_at_ms")
                .map_err(operation_error)?,
        ),
        UnixMillis::new(
            row.try_get("claim_expires_at_ms")
                .map_err(operation_error)?,
        ),
    )
    .map_err(|_| ProviderDeliveryStoreError::CorruptData)?;
    if renewed.attempt() != request.attempt()
        || renewed.claimed_at() != request.claimed_at()
        || renewed
            .expires_at()
            .get()
            .checked_sub(renewed.renewed_at().get())
            != Some(evidence.duration_millis)
        || returned_predecessor_expiry != request.predecessor_expires_at().get()
    {
        return Err(ProviderDeliveryStoreError::CorruptData);
    }
    Ok(renewed)
}

#[async_trait]
impl ProviderDeliveryClaimRenewalRepository for PostgresStore {
    async fn renew_provider_delivery_claim(
        &self,
        request: RenewProviderDeliveryClaim,
    ) -> Result<RenewedProviderDeliveryClaim, ProviderDeliveryStoreError> {
        let evidence = RenewalSqlEvidence::new(request)?;
        if Instant::now() >= request.deadline() {
            return load_exact_renewal_replay(&self.pool, evidence).await;
        }
        let mut transaction = match timeout_at(
            request.deadline(),
            begin_read_committed_transaction(&self.pool),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => return load_exact_renewal_replay(&self.pool, evidence).await,
        };
        let row = if let Ok(result) = timeout_at(
            request.deadline(),
            lock_exact_renewal_predecessor(&mut transaction, evidence),
        )
        .await
        {
            result?
        } else {
            drop(transaction);
            return load_exact_renewal_replay(&self.pool, evidence).await;
        }
        .ok_or(ProviderDeliveryStoreError::ClaimRejected)?;
        let locked_fence: i64 = row.try_get("claim_fence").map_err(operation_error)?;
        let row = if locked_fence == pg_bigint(request.claim().fence()) {
            if Instant::now() >= request.deadline() {
                return Err(ProviderDeliveryStoreError::ClaimRejected);
            }
            let renewed_at = database_time(&mut transaction).await?;
            if !caller_time_is_admissible(request.observed_at(), renewed_at) {
                return Err(ProviderDeliveryStoreError::ClaimRejected);
            }
            let expires_at = renewed_at
                .get()
                .checked_add(evidence.duration_millis)
                .map(UnixMillis::new)
                .ok_or(ProviderDeliveryStoreError::CorruptData)?;
            update_locked_renewal_predecessor(&mut transaction, evidence, renewed_at, expires_at)
                .await?
                .ok_or(ProviderDeliveryStoreError::ClaimRejected)?
        } else if locked_fence == evidence.renewed_fence_i64 {
            row
        } else {
            return Err(ProviderDeliveryStoreError::CorruptData);
        };
        let renewed = decode_exact_renewal(&row, evidence)?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(renewed)
    }
}

#[derive(Debug)]
struct DurableDelivery {
    receipt: ProviderDeliveryReceipt,
    identity: ProviderDeliveryIdentity,
    request_digest: Sha256Digest,
    raw_event: AdmissionObject,
    event_envelope: ProviderDeliveryEventEnvelope,
}

fn decode_delivery(
    row: &sqlx::postgres::PgRow,
) -> Result<DurableDelivery, ProviderDeliveryStoreError> {
    let receipt = decode_receipt(row)?;
    let tenant_id: String = row.try_get("tenant_id").map_err(operation_error)?;
    let provider: String = row.try_get("provider").map_err(operation_error)?;
    let connection_id: Uuid = row.try_get("connection_id").map_err(operation_error)?;
    let installation_id: i64 = row.try_get("installation_id").map_err(operation_error)?;
    let repository_id: i64 = row
        .try_get("provider_repository_id")
        .map_err(operation_error)?;
    let repository_visibility: String = row
        .try_get("repository_visibility")
        .map_err(operation_error)?;
    let repository_identity: String = row
        .try_get("repository_identity")
        .map_err(operation_error)?;
    let delivery_id: String = row.try_get("delivery_id").map_err(operation_error)?;
    let repository = ProviderRepositoryCoordinates::new(
        ProviderRepositoryId::new(
            u64::try_from(repository_id).map_err(|_| ProviderDeliveryStoreError::CorruptData)?,
        )
        .map_err(|_| ProviderDeliveryStoreError::CorruptData)?,
        decode_provider_repository_visibility(&repository_visibility)
            .ok_or(ProviderDeliveryStoreError::CorruptData)?,
        repository_identity,
    )
    .map_err(|_| ProviderDeliveryStoreError::CorruptData)?;
    let identity = ProviderDeliveryIdentity::new(
        TenantScope::from_authenticated_tenant_id(tenant_id)
            .map_err(|_| ProviderDeliveryStoreError::CorruptData)?,
        provider,
        ProviderConnectionId::from_uuid(connection_id)
            .map_err(|_| ProviderDeliveryStoreError::CorruptData)?,
        ProviderInstallationId::new(
            u64::try_from(installation_id).map_err(|_| ProviderDeliveryStoreError::CorruptData)?,
        )
        .map_err(|_| ProviderDeliveryStoreError::CorruptData)?,
        repository,
        delivery_id,
    )
    .map_err(|_| ProviderDeliveryStoreError::CorruptData)?;
    let request_digest = decode_digest(row, "request_digest")?;
    let raw_digest = decode_digest(row, "raw_event_digest")?;
    let raw_object_key: String = row
        .try_get("raw_event_object_key")
        .map_err(operation_error)?;
    let raw_size: i64 = row
        .try_get("raw_event_size_bytes")
        .map_err(operation_error)?;
    let raw_media_type: String = row
        .try_get("raw_event_media_type")
        .map_err(operation_error)?;
    let raw_event = AdmissionObject::new_event(
        raw_digest,
        ObjectKey::new(raw_object_key).map_err(|_| ProviderDeliveryStoreError::CorruptData)?,
        u64::try_from(raw_size).map_err(|_| ProviderDeliveryStoreError::CorruptData)?,
        raw_media_type,
    )
    .map_err(|_| ProviderDeliveryStoreError::CorruptData)?;
    let envelope_schema: i16 = row
        .try_get("event_envelope_schema")
        .map_err(operation_error)?;
    let registry_schema: i16 = row
        .try_get("event_registry_schema")
        .map_err(operation_error)?;
    let envelope_digest = decode_digest(row, "event_envelope_digest")?;
    let envelope_bytes: Vec<u8> = row
        .try_get("event_envelope_bytes")
        .map_err(operation_error)?;
    let envelope_media_type: String = row
        .try_get("event_envelope_media_type")
        .map_err(operation_error)?;
    let event_envelope = ProviderDeliveryEventEnvelope::new(
        u16::try_from(envelope_schema).map_err(|_| ProviderDeliveryStoreError::CorruptData)?,
        u16::try_from(registry_schema).map_err(|_| ProviderDeliveryStoreError::CorruptData)?,
        envelope_digest,
        envelope_bytes,
        envelope_media_type,
    )
    .map_err(|_| ProviderDeliveryStoreError::CorruptData)?;
    Ok(DurableDelivery {
        receipt,
        identity,
        request_digest,
        raw_event,
        event_envelope,
    })
}

fn decode_claimed_delivery(
    row: &sqlx::postgres::PgRow,
) -> Result<ClaimedProviderDelivery, ProviderDeliveryStoreError> {
    let durable = decode_delivery(row)?;
    if durable.receipt.state() != ProviderDeliveryState::Claimed {
        return Err(ProviderDeliveryStoreError::CorruptData);
    }
    let owner: Uuid = row.try_get("claim_owner_id").map_err(operation_error)?;
    let fence: i64 = row.try_get("claim_fence").map_err(operation_error)?;
    let claimed_at: i64 = row.try_get("claimed_at_ms").map_err(operation_error)?;
    let expires_at: i64 = row
        .try_get("claim_expires_at_ms")
        .map_err(operation_error)?;
    let owner = ProviderProcessingWorkerId::from_uuid(owner)
        .map_err(|_| ProviderDeliveryStoreError::CorruptData)?;
    let claim = ProviderDeliveryClaimFence::from_durable_parts(
        durable.receipt.id(),
        owner,
        u64::try_from(fence).map_err(|_| ProviderDeliveryStoreError::CorruptData)?,
    )
    .map_err(|_| ProviderDeliveryStoreError::CorruptData)?;
    ClaimedProviderDelivery::from_durable_parts(
        durable.receipt,
        durable.identity,
        durable.request_digest,
        durable.raw_event,
        durable.event_envelope,
        claim,
        UnixMillis::new(claimed_at),
        UnixMillis::new(expires_at),
    )
    .map_err(|_| ProviderDeliveryStoreError::CorruptData)
}

fn decode_receipt(
    row: &sqlx::postgres::PgRow,
) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError> {
    let id: Uuid = row.try_get("id").map_err(operation_error)?;
    let state: String = row.try_get("state").map_err(operation_error)?;
    let attempts: i16 = row.try_get("attempt_count").map_err(operation_error)?;
    let accepted_at: i64 = row.try_get("accepted_at_ms").map_err(operation_error)?;
    let id =
        ProviderDeliveryId::from_uuid(id).map_err(|_| ProviderDeliveryStoreError::CorruptData)?;
    let state = decode_state(&state)?;
    let attempts = u16::try_from(attempts).map_err(|_| ProviderDeliveryStoreError::CorruptData)?;
    ProviderDeliveryReceipt::from_durable_parts(id, state, attempts, UnixMillis::new(accepted_at))
        .map_err(|_| ProviderDeliveryStoreError::CorruptData)
}

fn decode_state(value: &str) -> Result<ProviderDeliveryState, ProviderDeliveryStoreError> {
    match value {
        "pending" => Ok(ProviderDeliveryState::Pending),
        "claimed" => Ok(ProviderDeliveryState::Claimed),
        "retry" => Ok(ProviderDeliveryState::RetryPending),
        "completed" => Ok(ProviderDeliveryState::Completed),
        "rejected" => Ok(ProviderDeliveryState::Rejected),
        _ => Err(ProviderDeliveryStoreError::CorruptData),
    }
}

async fn insert_workflow_inventory_entries(
    transaction: &mut Transaction<'_, Postgres>,
    delivery_id: ProviderDeliveryId,
    inventory: &ProviderDeliveryWorkflowInventory,
) -> Result<(), ProviderDeliveryStoreError> {
    for (ordinal, entry) in inventory.entries().iter().enumerate() {
        let (source_state, source_digest) = match entry.source_state() {
            ProviderDeliveryWorkflowSourceState::Ready(digest) => {
                ("ready", Some(digest.as_bytes().as_slice()))
            }
            ProviderDeliveryWorkflowSourceState::Empty => ("empty", None),
            ProviderDeliveryWorkflowSourceState::Oversized => ("oversized", None),
            ProviderDeliveryWorkflowSourceState::Missing => ("missing", None),
        };
        let inserted = sqlx::query(
            r"
            INSERT INTO provider_delivery_workflow_inventory_entries (
                inbox_id, tenant_id, ordinal, workflow_path,
                source_state, source_digest
            )
            SELECT inventory.inbox_id, inventory.tenant_id, $2, $3, $4, $5
            FROM provider_delivery_workflow_inventories AS inventory
            WHERE inventory.inbox_id = $1
              AND inventory.inventory_digest = $6
            ",
        )
        .bind(delivery_id.as_uuid())
        .bind(i16::try_from(ordinal).map_err(|_| ProviderDeliveryStoreError::CorruptData)?)
        .bind(entry.workflow_path())
        .bind(source_state)
        .bind(source_digest)
        .bind(inventory.digest().as_bytes().as_slice())
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
        if inserted.rows_affected() != 1 {
            return Err(ProviderDeliveryStoreError::WorkflowProgressRejected);
        }
    }
    Ok(())
}

async fn require_live_inventory_claim(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RegisterProviderDeliveryWorkflowInventory,
) -> Result<(), ProviderDeliveryStoreError> {
    let valid: bool = sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM provider_delivery_inbox AS inbox
            JOIN provider_delivery_workflow_inventories AS inventory
              ON inventory.inbox_id = inbox.id
             AND inventory.tenant_id = inbox.tenant_id
            WHERE inbox.id = $1
              AND inbox.state = 'claimed'
              AND inbox.claim_owner_id = $2
              AND inbox.claim_fence = $3
              AND inbox.claimed_at_ms <= $4
              AND inbox.claim_expires_at_ms > $4
              AND inventory.inventory_digest = $5
        )
        ",
    )
    .bind(request.claim().delivery_id().as_uuid())
    .bind(request.claim().owner().as_uuid())
    .bind(pg_bigint(request.claim().fence()))
    .bind(request.observed_at().get())
    .bind(request.inventory().digest().as_bytes().as_slice())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if !valid {
        return Err(ProviderDeliveryStoreError::WorkflowProgressRejected);
    }
    Ok(())
}

async fn require_live_progress_claim(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RecordProviderDeliveryWorkflowProgress,
) -> Result<(), ProviderDeliveryStoreError> {
    let valid: bool = sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM provider_delivery_inbox AS inbox
            JOIN provider_delivery_workflow_inventories AS inventory
              ON inventory.inbox_id = inbox.id
             AND inventory.tenant_id = inbox.tenant_id
            JOIN provider_delivery_workflow_inventory_entries AS entry
              ON entry.inbox_id = inventory.inbox_id
             AND entry.tenant_id = inventory.tenant_id
             AND entry.workflow_path = $6
            WHERE inbox.id = $1
              AND inbox.state = 'claimed'
              AND inbox.claim_owner_id = $2
              AND inbox.claim_fence = $3
              AND inbox.claimed_at_ms <= $4
              AND inbox.claim_expires_at_ms > $4
              AND inventory.inventory_digest = $5
        )
        ",
    )
    .bind(request.claim().delivery_id().as_uuid())
    .bind(request.claim().owner().as_uuid())
    .bind(pg_bigint(request.claim().fence()))
    .bind(request.observed_at().get())
    .bind(request.inventory_digest().as_bytes().as_slice())
    .bind(request.outcome().workflow_path())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if !valid {
        return Err(ProviderDeliveryStoreError::WorkflowProgressRejected);
    }
    Ok(())
}

async fn insert_workflow_progress(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RecordProviderDeliveryWorkflowProgress,
) -> Result<(), ProviderDeliveryStoreError> {
    let outcome = request.outcome();
    match outcome.conclusion() {
        ProviderDeliveryWorkflowConclusion::Admitted { run_id } => {
            sqlx::query(
                r"
                INSERT INTO provider_delivery_workflow_progress (
                    inbox_id, tenant_id, workflow_path, inventory_digest,
                    outcome_kind, run_id, failure_kind, recorded_at_ms
                )
                SELECT inventory.inbox_id, inventory.tenant_id, entry.workflow_path,
                       inventory.inventory_digest, 'admitted', run.id, NULL, $5
                FROM provider_delivery_workflow_inventories AS inventory
                JOIN provider_delivery_workflow_inventory_entries AS entry
                  ON entry.inbox_id = inventory.inbox_id
                 AND entry.tenant_id = inventory.tenant_id
                 AND entry.workflow_path = $2
                JOIN github_provider_delivery_evidence AS evidence
                  ON evidence.provider_delivery_id = inventory.inbox_id
                 AND evidence.tenant_id = inventory.tenant_id
                JOIN workflow_runs AS run
                  ON run.repository_id = evidence.repository_id
                 AND run.id = $4
                JOIN workflow_definitions AS workflow
                  ON workflow.repository_id = run.repository_id
                 AND workflow.id = run.workflow_id
                 AND workflow.path = entry.workflow_path
                WHERE inventory.inbox_id = $1
                  AND inventory.inventory_digest = $3
                ON CONFLICT (inbox_id, workflow_path) DO NOTHING
                ",
            )
            .bind(request.claim().delivery_id().as_uuid())
            .bind(outcome.workflow_path())
            .bind(request.inventory_digest().as_bytes().as_slice())
            .bind(run_id.as_uuid())
            .bind(request.observed_at().get())
            .execute(&mut **transaction)
            .await
            .map_err(operation_error)?;
        }
        ProviderDeliveryWorkflowConclusion::Skipped { reason } => {
            insert_non_admitted_workflow_progress(transaction, request, "skipped", reason.as_str())
                .await?;
        }
        ProviderDeliveryWorkflowConclusion::Failed { failure_kind } => {
            insert_non_admitted_workflow_progress(
                transaction,
                request,
                "failed",
                failure_kind.as_str(),
            )
            .await?;
        }
    }
    Ok(())
}

async fn terminalize_failed_workflow_check(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RecordProviderDeliveryWorkflowProgress,
) -> Result<(), ProviderDeliveryStoreError> {
    insert_failed_workflow_check(transaction, request).await?;
    transition_failed_workflow_check(transaction, request).await
}

async fn insert_failed_workflow_check(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RecordProviderDeliveryWorkflowProgress,
) -> Result<(), ProviderDeliveryStoreError> {
    let candidate_id = Uuid::new_v4();
    let external_id = format!("automata-check:{candidate_id}");
    sqlx::query(
        r"
        INSERT INTO github_check_subjects (
            id, tenant_id, repository_id, provider_delivery_id, subject_key,
            provider_connection_id, provider_installation_id,
            github_repository_id, github_app_id, head_sha, check_name,
            external_id, created_at_ms, desired_updated_at_ms
        )
        SELECT $1, evidence.tenant_id, evidence.repository_id,
               evidence.provider_delivery_id, progress.workflow_path,
               evidence.provider_connection_id, evidence.provider_installation_id,
               evidence.github_repository_id, manifest.github_app_id,
               evidence.github_check_head_sha,
               automata_github_workflow_check_name(
                   manifest.check_name, progress.workflow_path
               ), $2,
               inbox.accepted_at_ms, inbox.accepted_at_ms
        FROM provider_delivery_workflow_progress AS progress
        JOIN provider_delivery_workflow_inventories AS inventory
          ON inventory.inbox_id = progress.inbox_id
         AND inventory.tenant_id = progress.tenant_id
         AND inventory.inventory_digest = progress.inventory_digest
        JOIN github_provider_delivery_evidence AS evidence
          ON evidence.provider_delivery_id = inventory.inbox_id
         AND evidence.tenant_id = inventory.tenant_id
        JOIN provider_delivery_inbox AS inbox
          ON inbox.id = evidence.provider_delivery_id
         AND inbox.tenant_id = evidence.tenant_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = evidence.tenant_id
         AND manifest.repository_id = evidence.repository_id
         AND manifest.provider_connection_id = evidence.provider_connection_id
         AND manifest.manifest_revision = evidence.provider_manifest_revision
         AND manifest.manifest_digest = evidence.provider_manifest_digest
        WHERE progress.inbox_id = $3
          AND progress.workflow_path = $4
          AND progress.inventory_digest = $5
          AND progress.outcome_kind = 'failed'
          AND manifest.workflow_selection_kind = 'all_direct'
          AND inbox.state = 'claimed'
          AND inbox.claim_owner_id = $6
          AND inbox.claim_fence = $7
          AND inbox.claimed_at_ms <= $8
          AND inbox.claim_expires_at_ms > $8
        ON CONFLICT (provider_delivery_id, subject_key) DO NOTHING
        ",
    )
    .bind(candidate_id)
    .bind(external_id)
    .bind(request.claim().delivery_id().as_uuid())
    .bind(request.outcome().workflow_path())
    .bind(request.inventory_digest().as_bytes().as_slice())
    .bind(request.claim().owner().as_uuid())
    .bind(pg_bigint(request.claim().fence()))
    .bind(request.observed_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn transition_failed_workflow_check(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RecordProviderDeliveryWorkflowProgress,
) -> Result<(), ProviderDeliveryStoreError> {
    let row = sqlx::query(
        r"
        SELECT subject.id, subject.workflow_run_id, subject.desired_state,
               subject.desired_conclusion, subject.terminal_cause,
               subject.desired_revision, subject.desired_updated_at_ms
        FROM github_check_subjects AS subject
        JOIN github_provider_delivery_evidence AS evidence
          ON evidence.provider_delivery_id = subject.provider_delivery_id
         AND evidence.tenant_id = subject.tenant_id
         AND evidence.repository_id = subject.repository_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = evidence.tenant_id
         AND manifest.repository_id = evidence.repository_id
         AND manifest.provider_connection_id = evidence.provider_connection_id
         AND manifest.manifest_revision = evidence.provider_manifest_revision
         AND manifest.manifest_digest = evidence.provider_manifest_digest
        JOIN provider_delivery_workflow_progress AS progress
          ON progress.inbox_id = evidence.provider_delivery_id
         AND progress.tenant_id = evidence.tenant_id
         AND progress.workflow_path = subject.subject_key
        WHERE evidence.provider_delivery_id = $1
          AND subject.subject_key = $2
          AND progress.inventory_digest = $3
          AND progress.outcome_kind = 'failed'
          AND manifest.workflow_selection_kind = 'all_direct'
        FOR UPDATE OF subject
        ",
    )
    .bind(request.claim().delivery_id().as_uuid())
    .bind(request.outcome().workflow_path())
    .bind(request.inventory_digest().as_bytes().as_slice())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(ProviderDeliveryStoreError::WorkflowProgressRejected)?;
    let subject_id: Uuid = row.try_get("id").map_err(operation_error)?;
    let run_id: Option<Uuid> = row.try_get("workflow_run_id").map_err(operation_error)?;
    let state: String = row.try_get("desired_state").map_err(operation_error)?;
    let conclusion: Option<String> = row.try_get("desired_conclusion").map_err(operation_error)?;
    let cause: Option<String> = row.try_get("terminal_cause").map_err(operation_error)?;
    let revision: i64 = row.try_get("desired_revision").map_err(operation_error)?;
    let updated_at: i64 = row
        .try_get("desired_updated_at_ms")
        .map_err(operation_error)?;
    if run_id.is_some() {
        return Err(ProviderDeliveryStoreError::WorkflowProgressRejected);
    }
    if state == "completed" {
        return if conclusion.as_deref() == Some("failure")
            && cause.as_deref() == Some("workflow_failure")
            && revision == 2
            && updated_at >= 0
        {
            Ok(())
        } else {
            Err(ProviderDeliveryStoreError::WorkflowProgressRejected)
        };
    }
    if state != "queued"
        || conclusion.is_some()
        || cause.is_some()
        || revision != 1
        || updated_at > request.observed_at().get()
    {
        return Err(ProviderDeliveryStoreError::WorkflowProgressRejected);
    }
    let updated = sqlx::query_scalar::<_, Uuid>(
        r"
        UPDATE github_check_subjects
        SET desired_state = 'completed', desired_conclusion = 'failure',
            terminal_cause = 'workflow_failure',
            desired_revision = desired_revision + 1,
            desired_updated_at_ms = $2
        WHERE id = $1
          AND workflow_run_id IS NULL
          AND desired_state = 'queued'
          AND desired_conclusion IS NULL
          AND terminal_cause IS NULL
          AND desired_revision = 1
          AND desired_updated_at_ms <= $2
        RETURNING id
        ",
    )
    .bind(subject_id)
    .bind(request.observed_at().get())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if updated == Some(subject_id) {
        Ok(())
    } else {
        Err(ProviderDeliveryStoreError::WorkflowProgressRejected)
    }
}

async fn insert_non_admitted_workflow_progress(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RecordProviderDeliveryWorkflowProgress,
    outcome_kind: &'static str,
    failure_kind: &str,
) -> Result<(), ProviderDeliveryStoreError> {
    sqlx::query(
        r"
        INSERT INTO provider_delivery_workflow_progress (
            inbox_id, tenant_id, workflow_path, inventory_digest,
            outcome_kind, run_id, failure_kind, recorded_at_ms
        )
        SELECT inventory.inbox_id, inventory.tenant_id, entry.workflow_path,
               inventory.inventory_digest, $4, NULL, $5, $6
        FROM provider_delivery_workflow_inventories AS inventory
        JOIN provider_delivery_workflow_inventory_entries AS entry
          ON entry.inbox_id = inventory.inbox_id
         AND entry.tenant_id = inventory.tenant_id
         AND entry.workflow_path = $2
        WHERE inventory.inbox_id = $1
          AND inventory.inventory_digest = $3
        ON CONFLICT (inbox_id, workflow_path) DO NOTHING
        ",
    )
    .bind(request.claim().delivery_id().as_uuid())
    .bind(request.outcome().workflow_path())
    .bind(request.inventory_digest().as_bytes().as_slice())
    .bind(outcome_kind)
    .bind(failure_kind)
    .bind(request.observed_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn load_workflow_inventory_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    delivery_id: ProviderDeliveryId,
) -> Result<Option<ProviderDeliveryWorkflowInventoryReceipt>, ProviderDeliveryStoreError> {
    let header = sqlx::query(
        r"
        SELECT manifest_digest, source_revision, repository_source_digest,
               inventory_digest, workflow_count
        FROM provider_delivery_workflow_inventories
        WHERE inbox_id = $1
        ",
    )
    .bind(delivery_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(header) = header else {
        return Ok(None);
    };
    let rows = sqlx::query(
        r"
        SELECT workflow_path, source_state, source_digest
        FROM provider_delivery_workflow_inventory_entries
        WHERE inbox_id = $1
        ORDER BY ordinal
        ",
    )
    .bind(delivery_id.as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        let source_state = match row
            .try_get::<String, _>("source_state")
            .map_err(operation_error)?
            .as_str()
        {
            "ready" => {
                ProviderDeliveryWorkflowSourceState::Ready(decode_digest(&row, "source_digest")?)
            }
            "empty" => ProviderDeliveryWorkflowSourceState::Empty,
            "oversized" => ProviderDeliveryWorkflowSourceState::Oversized,
            "missing" => ProviderDeliveryWorkflowSourceState::Missing,
            _ => return Err(ProviderDeliveryStoreError::CorruptData),
        };
        entries.push(
            ProviderDeliveryWorkflowInventoryEntry::new(
                row.try_get::<String, _>("workflow_path")
                    .map_err(operation_error)?,
                source_state,
            )
            .map_err(|_| ProviderDeliveryStoreError::CorruptData)?,
        );
    }
    let expected_count: i16 = header.try_get("workflow_count").map_err(operation_error)?;
    if usize::try_from(expected_count).ok() != Some(entries.len()) {
        return Err(ProviderDeliveryStoreError::CorruptData);
    }
    let inventory = ProviderDeliveryWorkflowInventory::new(
        decode_digest(&header, "manifest_digest")?,
        automata_ci_core::GitObjectId::from_durable_bytes(
            &header
                .try_get::<Vec<u8>, _>("source_revision")
                .map_err(operation_error)?,
        )
        .map_err(|_| ProviderDeliveryStoreError::CorruptData)?,
        decode_digest(&header, "repository_source_digest")?,
        entries,
    )
    .map_err(|_| ProviderDeliveryStoreError::CorruptData)?;
    if inventory.digest() != decode_digest(&header, "inventory_digest")? {
        return Err(ProviderDeliveryStoreError::CorruptData);
    }
    let progress = load_all_workflow_progress(transaction, delivery_id).await?;
    ProviderDeliveryWorkflowInventoryReceipt::new(inventory, progress)
        .map(Some)
        .map_err(|_| ProviderDeliveryStoreError::CorruptData)
}

async fn load_all_workflow_progress(
    transaction: &mut Transaction<'_, Postgres>,
    delivery_id: ProviderDeliveryId,
) -> Result<Vec<ProviderDeliveryWorkflowOutcome>, ProviderDeliveryStoreError> {
    let rows = sqlx::query(
        r"
        SELECT workflow_path, outcome_kind, run_id, failure_kind
        FROM provider_delivery_workflow_progress
        WHERE inbox_id = $1
        ORDER BY workflow_path
        ",
    )
    .bind(delivery_id.as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    rows.iter().map(decode_workflow_progress).collect()
}

async fn load_workflow_progress(
    transaction: &mut Transaction<'_, Postgres>,
    delivery_id: ProviderDeliveryId,
    workflow_path: &str,
) -> Result<Option<ProviderDeliveryWorkflowOutcome>, ProviderDeliveryStoreError> {
    sqlx::query(
        r"
        SELECT workflow_path, outcome_kind, run_id, failure_kind
        FROM provider_delivery_workflow_progress
        WHERE inbox_id = $1 AND workflow_path = $2
        ",
    )
    .bind(delivery_id.as_uuid())
    .bind(workflow_path)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .as_ref()
    .map(decode_workflow_progress)
    .transpose()
}

fn decode_workflow_progress(
    row: &PgRow,
) -> Result<ProviderDeliveryWorkflowOutcome, ProviderDeliveryStoreError> {
    let conclusion = match row
        .try_get::<String, _>("outcome_kind")
        .map_err(operation_error)?
        .as_str()
    {
        "admitted" => {
            let run_id: Uuid = row.try_get("run_id").map_err(operation_error)?;
            ProviderDeliveryWorkflowConclusion::Admitted {
                run_id: RunId::from_uuid(run_id),
            }
        }
        "skipped" => ProviderDeliveryWorkflowConclusion::Skipped {
            reason: automata_ci_store::ProviderDeliveryFailureKind::new(
                row.try_get::<String, _>("failure_kind")
                    .map_err(operation_error)?,
            )
            .map_err(|_| ProviderDeliveryStoreError::CorruptData)?,
        },
        "failed" => ProviderDeliveryWorkflowConclusion::Failed {
            failure_kind: automata_ci_store::ProviderDeliveryFailureKind::new(
                row.try_get::<String, _>("failure_kind")
                    .map_err(operation_error)?,
            )
            .map_err(|_| ProviderDeliveryStoreError::CorruptData)?,
        },
        _ => return Err(ProviderDeliveryStoreError::CorruptData),
    };
    ProviderDeliveryWorkflowOutcome::new(
        row.try_get::<String, _>("workflow_path")
            .map_err(operation_error)?,
        conclusion,
    )
    .map_err(|_| ProviderDeliveryStoreError::CorruptData)
}

fn decode_digest(
    row: &sqlx::postgres::PgRow,
    column: &str,
) -> Result<Sha256Digest, ProviderDeliveryStoreError> {
    let value: Vec<u8> = row.try_get(column).map_err(operation_error)?;
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| ProviderDeliveryStoreError::CorruptData)?;
    Ok(Sha256Digest::from_bytes(bytes))
}

async fn insert_outcomes(
    transaction: &mut Transaction<'_, Postgres>,
    delivery_id: ProviderDeliveryId,
    tenant_id: &str,
    request: &CompleteProviderDelivery,
) -> Result<(), ProviderDeliveryStoreError> {
    for (ordinal, outcome) in request.outcomes().iter().enumerate() {
        let ordinal =
            i16::try_from(ordinal).map_err(|_| ProviderDeliveryStoreError::CorruptData)?;
        match outcome.conclusion() {
            ProviderDeliveryWorkflowConclusion::Admitted { run_id } => {
                let result = sqlx::query(
                    r"
                    INSERT INTO provider_delivery_workflow_outcomes (
                        inbox_id, tenant_id, ordinal, workflow_path,
                        outcome_kind, repository_id, run_id, failure_kind,
                        created_at_ms
                    )
                    SELECT $1, $2, $3, $4, 'admitted', run.repository_id,
                           run.id, NULL, $6
                    FROM workflow_runs AS run
                    JOIN repositories AS repository
                      ON repository.id = run.repository_id
                     AND repository.tenant_id = $2
                    JOIN provider_delivery_inbox AS inbox
                      ON inbox.id = $1
                     AND inbox.tenant_id = $2
                     AND inbox.provider = repository.scm_provider
                     AND inbox.provider_repository_id::text =
                         repository.provider_repository_id
                    WHERE run.id = $5
                    ",
                )
                .bind(delivery_id.as_uuid())
                .bind(tenant_id)
                .bind(ordinal)
                .bind(outcome.workflow_path())
                .bind(run_id.as_uuid())
                .bind(request.completed_at().get())
                .execute(&mut **transaction)
                .await
                .map_err(operation_error)?;
                if result.rows_affected() != 1 {
                    return Err(ProviderDeliveryStoreError::OutcomeRunRejected);
                }
            }
            ProviderDeliveryWorkflowConclusion::Skipped { reason } => {
                insert_non_admitted_outcome(
                    transaction,
                    delivery_id,
                    tenant_id,
                    ordinal,
                    outcome.workflow_path(),
                    "skipped",
                    reason.as_str(),
                    request.completed_at(),
                )
                .await?;
            }
            ProviderDeliveryWorkflowConclusion::Failed { failure_kind } => {
                insert_non_admitted_outcome(
                    transaction,
                    delivery_id,
                    tenant_id,
                    ordinal,
                    outcome.workflow_path(),
                    "failed",
                    failure_kind.as_str(),
                    request.completed_at(),
                )
                .await?;
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert_non_admitted_outcome(
    transaction: &mut Transaction<'_, Postgres>,
    delivery_id: ProviderDeliveryId,
    tenant_id: &str,
    ordinal: i16,
    workflow_path: &str,
    outcome_kind: &'static str,
    failure_kind: &str,
    completed_at: UnixMillis,
) -> Result<(), ProviderDeliveryStoreError> {
    sqlx::query(
        r"
        INSERT INTO provider_delivery_workflow_outcomes (
            inbox_id, tenant_id, ordinal, workflow_path, outcome_kind,
            repository_id, run_id, failure_kind, created_at_ms
        )
        VALUES ($1, $2, $3, $4, $5, NULL, NULL, $6, $7)
        ",
    )
    .bind(delivery_id.as_uuid())
    .bind(tenant_id)
    .bind(ordinal)
    .bind(workflow_path)
    .bind(outcome_kind)
    .bind(failure_kind)
    .bind(completed_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

fn outcome_columns(
    outcome: &ProviderDeliveryWorkflowOutcome,
) -> (&'static str, Option<Uuid>, Option<&str>) {
    match outcome.conclusion() {
        ProviderDeliveryWorkflowConclusion::Admitted { run_id } => {
            ("admitted", Some(run_id.as_uuid()), None)
        }
        ProviderDeliveryWorkflowConclusion::Skipped { reason } => {
            ("skipped", None, Some(reason.as_str()))
        }
        ProviderDeliveryWorkflowConclusion::Failed { failure_kind } => {
            ("failed", None, Some(failure_kind.as_str()))
        }
    }
}

async fn verify_exact_completion(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CompleteProviderDelivery,
) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError> {
    let row = sqlx::query(
        r"
        SELECT id, tenant_id, state, attempt_count, accepted_at_ms,
               terminal_claim_owner_id, terminal_claim_fence,
               completion_digest, completion_outcome_count, completed_at_ms
        FROM provider_delivery_inbox
        WHERE id = $1
        FOR UPDATE
        ",
    )
    .bind(request.claim().delivery_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(ProviderDeliveryStoreError::ClaimRejected)?;
    let receipt = decode_receipt(&row)?;
    let terminal_tenant: String = row.try_get("tenant_id").map_err(operation_error)?;
    TenantScope::from_authenticated_tenant_id(terminal_tenant.clone())
        .map_err(|_| ProviderDeliveryStoreError::CorruptData)?;
    let terminal_owner: Option<Uuid> = row
        .try_get("terminal_claim_owner_id")
        .map_err(operation_error)?;
    let terminal_fence: Option<i64> = row
        .try_get("terminal_claim_fence")
        .map_err(operation_error)?;
    let completion_digest: Option<Vec<u8>> =
        row.try_get("completion_digest").map_err(operation_error)?;
    let outcome_count: Option<i16> = row
        .try_get("completion_outcome_count")
        .map_err(operation_error)?;
    let completed_at: Option<i64> = row.try_get("completed_at_ms").map_err(operation_error)?;
    let exact_header = receipt.state() == ProviderDeliveryState::Completed
        && terminal_owner == Some(request.claim().owner().as_uuid())
        && terminal_fence == Some(pg_bigint(request.claim().fence()))
        && completion_digest.as_deref() == Some(request.completion_digest().as_bytes().as_slice())
        && outcome_count == Some(outcome_count_i16(request.outcomes())?)
        && completed_at == Some(request.completed_at().get());
    if !exact_header {
        return Err(ProviderDeliveryStoreError::ClaimRejected);
    }

    let rows = sqlx::query(
        r"
        SELECT outcome.ordinal, outcome.tenant_id, outcome.workflow_path,
               outcome.outcome_kind, outcome.repository_id, outcome.run_id,
               outcome.failure_kind, outcome.created_at_ms,
               (
                   outcome.outcome_kind <> 'admitted'
                   OR EXISTS (
                       SELECT 1
                       FROM repositories AS repository
                       JOIN workflow_runs AS run
                         ON run.repository_id = repository.id
                        AND run.id = outcome.run_id
                       WHERE repository.id = outcome.repository_id
                         AND repository.tenant_id = outcome.tenant_id
                   )
               ) AS run_authority_valid
        FROM provider_delivery_workflow_outcomes AS outcome
        WHERE outcome.inbox_id = $1
        ORDER BY ordinal
        ",
    )
    .bind(request.claim().delivery_id().as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if rows.len() != request.outcomes().len() {
        return Err(ProviderDeliveryStoreError::CorruptData);
    }
    for (expected_ordinal, (row, expected)) in rows.iter().zip(request.outcomes()).enumerate() {
        let ordinal: i16 = row.try_get("ordinal").map_err(operation_error)?;
        let tenant_id: String = row.try_get("tenant_id").map_err(operation_error)?;
        let path: String = row.try_get("workflow_path").map_err(operation_error)?;
        let kind: String = row.try_get("outcome_kind").map_err(operation_error)?;
        let repository_id: Option<Uuid> = row.try_get("repository_id").map_err(operation_error)?;
        let run_id: Option<Uuid> = row.try_get("run_id").map_err(operation_error)?;
        let failure_kind: Option<String> = row.try_get("failure_kind").map_err(operation_error)?;
        let created_at: i64 = row.try_get("created_at_ms").map_err(operation_error)?;
        let run_authority_valid: bool = row
            .try_get("run_authority_valid")
            .map_err(operation_error)?;
        let expected_columns = outcome_columns(expected);
        if usize::try_from(ordinal).ok() != Some(expected_ordinal)
            || tenant_id != terminal_tenant
            || path != expected.workflow_path()
            || kind != expected_columns.0
            || repository_id.is_some() != (expected_columns.0 == "admitted")
            || run_id != expected_columns.1
            || failure_kind.as_deref() != expected_columns.2
            || created_at != request.completed_at().get()
            || !run_authority_valid
        {
            return Err(ProviderDeliveryStoreError::CorruptData);
        }
    }
    Ok(receipt)
}

async fn live_claim_attempts(
    pool: &sqlx::PgPool,
    claim: ProviderDeliveryClaimFence,
    observed_at: UnixMillis,
) -> Result<Option<u16>, ProviderDeliveryStoreError> {
    let attempts: Option<i16> = sqlx::query_scalar(
        r"
        SELECT attempt_count
        FROM provider_delivery_inbox
        WHERE id = $1
          AND state = 'claimed'
          AND claim_owner_id = $2
          AND claim_fence = $3
          AND claimed_at_ms <= $4
          AND state_updated_at_ms <= $4
          AND claim_expires_at_ms > $4
        ",
    )
    .bind(claim.delivery_id().as_uuid())
    .bind(claim.owner().as_uuid())
    .bind(pg_bigint(claim.fence()))
    .bind(observed_at.get())
    .fetch_optional(pool)
    .await
    .map_err(operation_error)?;
    attempts
        .map(|value| {
            u16::try_from(value)
                .ok()
                .filter(|value| (1..=MAX_PROVIDER_DELIVERY_ATTEMPTS).contains(value))
                .ok_or(ProviderDeliveryStoreError::CorruptData)
        })
        .transpose()
}

fn object_size_i64(object: &AdmissionObject) -> Result<i64, ProviderDeliveryStoreError> {
    i64::try_from(object.encoded_size()).map_err(|_| ProviderDeliveryStoreError::CorruptData)
}

const fn provider_repository_visibility_name(
    visibility: ProviderRepositoryVisibility,
) -> &'static str {
    match visibility {
        ProviderRepositoryVisibility::Public => "public",
        ProviderRepositoryVisibility::Private => "private",
    }
}

fn decode_provider_repository_visibility(value: &str) -> Option<ProviderRepositoryVisibility> {
    match value {
        "public" => Some(ProviderRepositoryVisibility::Public),
        "private" => Some(ProviderRepositoryVisibility::Private),
        _ => None,
    }
}

fn outcome_count_i16(
    outcomes: &[ProviderDeliveryWorkflowOutcome],
) -> Result<i16, ProviderDeliveryStoreError> {
    i16::try_from(outcomes.len()).map_err(|_| ProviderDeliveryStoreError::CorruptData)
}

fn operation_error(error: sqlx::Error) -> ProviderDeliveryStoreError {
    ProviderDeliveryStoreError::operation(error)
}

fn provider_delivery_aggregation_error(
    error: GithubCheckAggregationError,
) -> ProviderDeliveryStoreError {
    match error {
        GithubCheckAggregationError::Operation(error) => operation_error(error),
        GithubCheckAggregationError::CorruptData => ProviderDeliveryStoreError::CorruptData,
    }
}
