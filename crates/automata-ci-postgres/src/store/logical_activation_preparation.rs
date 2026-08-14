use std::collections::BTreeMap;

use async_trait::async_trait;
use automata_ci_core::{
    JobAuthorityProfile, JobConclusion, OutputSensitivity, RunId, RunIdAlias, Sha256Digest,
    UnixMillis, WorkflowId, WorkflowJobKey, WorkflowOutputKey,
};
use sqlx::{Postgres, Row as _, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::{
    PostgresStore, durable_schema::current_durable_schemas, pg_bigint,
    workflow_runtime_policy::load_pinned_runtime_policy_for_run,
};
use automata_ci_store::{
    AdmissionObject, BindLogicalActivationPreparation, ClaimLogicalActivationPreparation,
    ClaimedLogicalActivationPreparation, LOGICAL_ACTIVATION_PREPARATION_EVENT_MEDIA_TYPE,
    LOGICAL_ACTIVATION_PREPARATION_PLAN_MEDIA_TYPE, LogicalActivationAggregateStatus,
    LogicalActivationBaseContextKind, LogicalActivationExecutionContext,
    LogicalActivationPreparationClaimFence, LogicalActivationPreparationClaimOutcome,
    LogicalActivationPreparationDescriptor, LogicalActivationPreparationGeneration,
    LogicalActivationPreparationReceipt, LogicalActivationPreparationStore,
    LogicalActivationPreparationStoreError, LogicalActivationPreparationTarget,
    LogicalActivationPrerequisiteEvidence, LogicalActivationPrerequisiteOutput,
    LogicalActivationWorkerId, LogicalWorkflowJobId, MIN_LOGICAL_WORK_SELECTION_HANDOFF_MILLIS,
    ObjectKey, PinnedWorkflowRuntimePolicy, RenewLogicalActivationPreparation,
    RenewedLogicalActivationPreparation, SelectedLogicalJobOrchestration, StoreError,
    WORKFLOW_PLAN_SCHEMA, WorkflowRuntimePolicyStoreError,
};

#[allow(clippy::too_many_lines)] // The trait transaction keeps its security-relevant lock order visible.
#[async_trait]
impl LogicalActivationPreparationStore for PostgresStore {
    async fn renew_logical_activation_preparation(
        &self,
        request: RenewLogicalActivationPreparation,
    ) -> Result<RenewedLogicalActivationPreparation, LogicalActivationPreparationStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let selection_is_claimed =
            lock_preparation_renewal_selection_custody(&mut transaction, request.claim()).await?;
        let next_generation = request
            .claim()
            .generation()
            .get()
            .checked_add(1)
            .ok_or(LogicalActivationPreparationStoreError::GenerationExhausted)?;
        let origin_selection_id = request.claim().selection_origin();
        let (runtime_policy_revision, runtime_policy_digest) =
            load_preparation_renewal_policy(&mut transaction, request.claim()).await?;
        if let Some((
            receipt_generation,
            receipt_claimed_at,
            receipt_expires_at,
            receipt_validated_at,
        )) = load_exact_preparation_renewal_receipt(
            &mut transaction,
            &request,
            runtime_policy_revision,
            runtime_policy_digest,
        )
        .await?
        {
            let acknowledgement = RenewedLogicalActivationPreparation::new(
                request,
                LogicalActivationPreparationGeneration::new(receipt_generation)
                    .map_err(corrupt_value)?,
                UnixMillis::new(receipt_claimed_at),
                UnixMillis::new(receipt_expires_at),
                UnixMillis::new(receipt_validated_at),
            )
            .map_err(corrupt_value)?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(acknowledgement);
        }
        if !selection_is_claimed {
            return Err(LogicalActivationPreparationStoreError::ClaimRejected);
        }
        lock_preparation_quarantine_custody(&mut transaction, request.claim()).await?;
        if !lock_active_preparation_graph(&mut transaction, request.claim().target()).await? {
            return Err(LogicalActivationPreparationStoreError::ClaimRejected);
        }
        let row = lock_target(&mut transaction, request.claim().target())
            .await?
            .ok_or(LogicalActivationPreparationStoreError::InvalidTarget)?;
        let durable = DurablePreparationClaim::decode(&row)?
            .ok_or(LogicalActivationPreparationStoreError::ClaimRejected)?;
        let descriptor = load_pinned_descriptor(
            &mut transaction,
            request.claim().target().clone(),
            &row,
            &durable,
        )
        .await?;
        durable.verify_descriptor(&descriptor)?;
        if durable.state != "preparing" {
            return Err(LogicalActivationPreparationStoreError::ClaimRejected);
        }
        let database_now: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT",
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if !durable.matches_fence(request.claim()) {
            return Err(LogicalActivationPreparationStoreError::ClaimRejected);
        }
        if database_now < durable.claimed_at || database_now >= durable.expires_at {
            return Err(LogicalActivationPreparationStoreError::ClaimRejected);
        }
        let expires_at = database_now
            .checked_add(request.duration_ms())
            .filter(|expires_at| *expires_at > durable.expires_at)
            .ok_or(LogicalActivationPreparationStoreError::ClaimRejected)?;

        let rows = sqlx::query(
            r"
            UPDATE logical_workflow_activation_preparation_claims
            SET generation = $2, claimed_at_ms = $3,
                expires_at_ms = $4, updated_at_ms = $3
            WHERE logical_job_id = $1 AND state = 'preparing'
              AND owner_id = $5 AND generation = $6
              AND descriptor_digest = $7
              AND claimed_at_ms = $8 AND expires_at_ms = $9
            ",
        )
        .bind(request.claim().target().logical_job_id().as_uuid())
        .bind(generation_i64(next_generation)?)
        .bind(database_now)
        .bind(expires_at)
        .bind(request.claim().owner().as_uuid())
        .bind(pg_bigint(request.claim().generation().get()))
        .bind(request.claim().descriptor_digest().as_bytes().as_slice())
        .bind(request.claim().claimed_at().get())
        .bind(request.claim().expires_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?
        .rows_affected();
        if rows != 1 {
            return Err(LogicalActivationPreparationStoreError::ClaimRejected);
        }
        let validated_at = insert_preparation_renewal_receipt(
            &mut transaction,
            &request,
            descriptor.runtime_policy().pin(),
            generation_i64(next_generation)?,
            database_now,
            expires_at,
            origin_selection_id.as_uuid(),
        )
        .await?;
        let acknowledgement = RenewedLogicalActivationPreparation::new(
            request,
            LogicalActivationPreparationGeneration::new(next_generation).map_err(corrupt_value)?,
            UnixMillis::new(database_now),
            UnixMillis::new(expires_at),
            UnixMillis::new(validated_at),
        )
        .map_err(corrupt_value)?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(acknowledgement)
    }

    async fn bind_logical_activation_preparation(
        &self,
        request: BindLogicalActivationPreparation,
    ) -> Result<LogicalActivationPreparationReceipt, LogicalActivationPreparationStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        lock_preparation_continuation_custody(&mut transaction, request.claim()).await?;
        if !lock_active_preparation_graph(&mut transaction, request.claim().target()).await? {
            return Err(LogicalActivationPreparationStoreError::ClaimRejected);
        }
        let row = lock_target(&mut transaction, request.claim().target())
            .await?
            .ok_or(LogicalActivationPreparationStoreError::InvalidTarget)?;
        let durable = DurablePreparationClaim::decode(&row)?
            .ok_or(LogicalActivationPreparationStoreError::ClaimRejected)?;
        let descriptor = load_pinned_descriptor(
            &mut transaction,
            request.claim().target().clone(),
            &row,
            &durable,
        )
        .await?;
        durable.verify_descriptor(&descriptor)?;
        if request.descriptor() != &descriptor {
            return Err(LogicalActivationPreparationStoreError::BindConflict);
        }
        if durable.state == "prepared" {
            let receipt = load_receipt(&mut transaction, descriptor, true).await?;
            let exact = receipt.claim() == request.claim()
                && receipt.base_context() == request.base_context()
                && receipt.prerequisite_context() == request.prerequisite_context()
                && receipt.input_digest() == request.input_digest()
                && receipt.bound_at() == request.bound_at();
            if !exact {
                return Err(LogicalActivationPreparationStoreError::BindConflict);
            }
            transaction.commit().await.map_err(operation_error)?;
            return Ok(receipt);
        }
        if durable.state != "preparing" || !durable.matches_fence(request.claim()) {
            return Err(LogicalActivationPreparationStoreError::ClaimRejected);
        }
        let database_now: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT",
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if database_now < durable.claimed_at || database_now >= durable.expires_at {
            return Err(LogicalActivationPreparationStoreError::ClaimRejected);
        }

        insert_binding(&mut transaction, &request).await?;
        let rows = sqlx::query(
            r"
            UPDATE logical_workflow_activation_preparation_claims
            SET state = 'prepared', updated_at_ms = $8
            WHERE logical_job_id = $1 AND run_id = $2 AND invocation_id = $3
              AND state = 'preparing' AND owner_id = $4
              AND generation = $5 AND descriptor_digest = $6
              AND claimed_at_ms = $7 AND expires_at_ms = $9
            ",
        )
        .bind(request.claim().target().logical_job_id().as_uuid())
        .bind(request.claim().target().run_id().as_uuid())
        .bind(request.claim().target().invocation_id().as_uuid())
        .bind(request.claim().owner().as_uuid())
        .bind(pg_bigint(request.claim().generation().get()))
        .bind(request.claim().descriptor_digest().as_bytes().as_slice())
        .bind(request.claim().claimed_at().get())
        .bind(request.bound_at().get())
        .bind(request.claim().expires_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?
        .rows_affected();
        if rows != 1 {
            return Err(StoreError::corrupt_data(
                "logical activation preparation binding lost its locked claim",
            )
            .into());
        }
        transaction.commit().await.map_err(operation_error)?;
        Ok(LogicalActivationPreparationReceipt::new(&request, false))
    }
}

async fn load_exact_preparation_renewal_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RenewLogicalActivationPreparation,
    runtime_policy_revision: i64,
    runtime_policy_digest: Sha256Digest,
) -> Result<Option<(u64, i64, i64, i64)>, LogicalActivationPreparationStoreError> {
    let selection_id = request.claim().selection_origin();
    let row = sqlx::query(
        r"
        SELECT successor_generation, successor_claimed_at_ms,
               successor_expires_at_ms, validated_at_ms
        FROM logical_workflow_activation_renewal_receipts
        WHERE logical_job_id = $1
          AND authority_kind = 'preparation'
          AND predecessor_generation = $2
          AND selection_id = $3
          AND tenant_id = $4
          AND run_id = $5
          AND invocation_id = $6
          AND owner_id = $7
          AND runtime_policy_revision = $8
          AND runtime_policy_digest = $9
          AND authority_digest = $10
          AND predecessor_claimed_at_ms = $11
          AND predecessor_expires_at_ms = $12
          AND requested_duration_ms = $13
        FOR UPDATE
        ",
    )
    .bind(request.claim().target().logical_job_id().as_uuid())
    .bind(pg_bigint(request.claim().generation().get()))
    .bind(selection_id.as_uuid())
    .bind(request.claim().target().tenant().as_str())
    .bind(request.claim().target().run_id().as_uuid())
    .bind(request.claim().target().invocation_id().as_uuid())
    .bind(request.claim().owner().as_uuid())
    .bind(runtime_policy_revision)
    .bind(runtime_policy_digest.as_bytes().as_slice())
    .bind(request.claim().descriptor_digest().as_bytes().as_slice())
    .bind(request.claim().claimed_at().get())
    .bind(request.claim().expires_at().get())
    .bind(request.duration_ms())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    row.map(|row| {
        let generation: i64 = row
            .try_get("successor_generation")
            .map_err(operation_error)?;
        let generation = u64::try_from(generation).map_err(|_| {
            LogicalActivationPreparationStoreError::Store(StoreError::corrupt_data(
                "invalid preparation renewal receipt generation",
            ))
        })?;
        let claimed_at = row
            .try_get("successor_claimed_at_ms")
            .map_err(operation_error)?;
        let expires_at = row
            .try_get("successor_expires_at_ms")
            .map_err(operation_error)?;
        let validated_at = row.try_get("validated_at_ms").map_err(operation_error)?;
        Ok((generation, claimed_at, expires_at, validated_at))
    })
    .transpose()
}

async fn load_preparation_renewal_policy(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &LogicalActivationPreparationClaimFence,
) -> Result<(i64, Sha256Digest), LogicalActivationPreparationStoreError> {
    let row = sqlx::query(
        r"
        SELECT policy_revision, policy_digest
        FROM logical_workflow_runtime_policy_pins
        WHERE run_id = $1 AND tenant_id = $2
        FOR SHARE
        ",
    )
    .bind(claim.target().run_id().as_uuid())
    .bind(claim.target().tenant().as_str())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(LogicalActivationPreparationStoreError::ClaimRejected)?;
    Ok((
        row.try_get("policy_revision").map_err(operation_error)?,
        decode_digest(&row, "policy_digest")?,
    ))
}

#[allow(clippy::too_many_lines)] // One bounded proof follows the complete immutable renewal chain.
async fn verify_selected_preparation_renewal_lineage(
    transaction: &mut Transaction<'_, Postgres>,
    selected: &SelectedLogicalJobOrchestration,
    durable: &DurablePreparationClaim,
) -> Result<(), LogicalActivationPreparationStoreError> {
    const MAX_RENEWAL_CHAIN_EDGES: usize = 64;

    let selection_id = selected.selection_id();
    let mut generation = pg_bigint(selected.generation().get());
    let mut claimed_at = selected.claimed_at().get();
    let mut expires_at = selected.expires_at().get();
    for _ in 0..MAX_RENEWAL_CHAIN_EDGES {
        if generation == durable.generation {
            break;
        }
        if generation > durable.generation {
            return Err(LogicalActivationPreparationStoreError::ClaimRejected);
        }
        let edge = sqlx::query(
            r"
            SELECT successor_generation, successor_claimed_at_ms,
                   successor_expires_at_ms
            FROM logical_workflow_activation_renewal_receipts
            WHERE logical_job_id = $1
              AND authority_kind = 'preparation'
              AND predecessor_generation = $2
              AND selection_id = $3
              AND tenant_id = $4
              AND run_id = $5
              AND invocation_id = $6
              AND owner_id = $7
              AND runtime_policy_revision = $8
              AND runtime_policy_digest = $9
              AND authority_digest = $10
              AND predecessor_claimed_at_ms = $11
              AND predecessor_expires_at_ms = $12
            FOR UPDATE
            ",
        )
        .bind(selected.target().logical_job_id().as_uuid())
        .bind(generation)
        .bind(selection_id.as_uuid())
        .bind(selected.target().tenant().as_str())
        .bind(selected.target().run_id().as_uuid())
        .bind(selected.target().invocation_id().as_uuid())
        .bind(selected.owner().as_uuid())
        .bind(durable.runtime_policy_revision)
        .bind(durable.runtime_policy_digest.as_bytes().as_slice())
        .bind(selected.authority_digest().as_bytes().as_slice())
        .bind(claimed_at)
        .bind(expires_at)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?
        .ok_or(LogicalActivationPreparationStoreError::ClaimRejected)?;
        let next_generation: i64 = edge
            .try_get("successor_generation")
            .map_err(operation_error)?;
        let next_claimed_at: i64 = edge
            .try_get("successor_claimed_at_ms")
            .map_err(operation_error)?;
        let next_expires_at: i64 = edge
            .try_get("successor_expires_at_ms")
            .map_err(operation_error)?;
        if generation.checked_add(1) != Some(next_generation)
            || next_claimed_at < claimed_at
            || next_claimed_at >= expires_at
            || next_expires_at <= expires_at
        {
            return Err(StoreError::corrupt_data(
                "logical preparation renewal receipt chain is invalid",
            )
            .into());
        }
        generation = next_generation;
        claimed_at = next_claimed_at;
        expires_at = next_expires_at;
    }
    if generation != durable.generation
        || claimed_at != durable.claimed_at
        || expires_at != durable.expires_at
    {
        return Err(LogicalActivationPreparationStoreError::ClaimRejected);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert_preparation_renewal_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RenewLogicalActivationPreparation,
    runtime_policy: &automata_ci_store::WorkflowRuntimePolicyPin,
    successor_generation: i64,
    successor_claimed_at: i64,
    successor_expires_at: i64,
    selection_id: Uuid,
) -> Result<i64, LogicalActivationPreparationStoreError> {
    sqlx::query_scalar(
        r"
        INSERT INTO logical_workflow_activation_renewal_receipts (
            logical_job_id, authority_kind, selection_id, tenant_id, run_id,
            invocation_id, owner_id, runtime_policy_revision,
            runtime_policy_digest, authority_digest, predecessor_generation,
            predecessor_claimed_at_ms, predecessor_expires_at_ms,
            requested_duration_ms, successor_generation,
            successor_claimed_at_ms, successor_expires_at_ms, validated_at_ms
        ) VALUES (
            $1, 'preparation', $2, $3, $4, $5, $6, $7, $8, $9,
            $10, $11, $12, $13, $14, $15, $16, $15
        )
        RETURNING validated_at_ms
        ",
    )
    .bind(request.claim().target().logical_job_id().as_uuid())
    .bind(selection_id)
    .bind(request.claim().target().tenant().as_str())
    .bind(request.claim().target().run_id().as_uuid())
    .bind(request.claim().target().invocation_id().as_uuid())
    .bind(request.claim().owner().as_uuid())
    .bind(pg_bigint(runtime_policy.revision().get()))
    .bind(runtime_policy.digest().as_bytes().as_slice())
    .bind(request.claim().descriptor_digest().as_bytes().as_slice())
    .bind(pg_bigint(request.claim().generation().get()))
    .bind(request.claim().claimed_at().get())
    .bind(request.claim().expires_at().get())
    .bind(request.duration_ms())
    .bind(successor_generation)
    .bind(successor_claimed_at)
    .bind(successor_expires_at)
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)
}

pub(super) async fn claim_logical_activation_preparation_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimLogicalActivationPreparation,
    origin_selection_id: Uuid,
) -> Result<LogicalActivationPreparationClaimOutcome, LogicalActivationPreparationStoreError> {
    if !lock_active_preparation_graph(transaction, request.target()).await? {
        return Ok(LogicalActivationPreparationClaimOutcome::NotReady);
    }
    let row = lock_target(transaction, request.target())
        .await?
        .ok_or(LogicalActivationPreparationStoreError::InvalidTarget)?;
    reject_quarantined_preparation(transaction, request.target().logical_job_id()).await?;
    let durable = DurablePreparationClaim::decode(&row)?;

    if let Some(durable) = durable {
        let descriptor =
            load_pinned_descriptor(transaction, request.target().clone(), &row, &durable).await?;
        return resolve_durable_claim(
            transaction,
            request,
            descriptor,
            durable,
            origin_selection_id,
        )
        .await;
    }

    let Some(descriptor) =
        load_current_descriptor(transaction, request.target().clone(), &row).await?
    else {
        return Ok(LogicalActivationPreparationClaimOutcome::NotReady);
    };
    if request.observed_at() < descriptor.evidence_ready_at() {
        return Ok(LogicalActivationPreparationClaimOutcome::NotReady);
    }

    if !insert_claim(transaction, request, &descriptor, origin_selection_id).await? {
        let refreshed = lock_target(transaction, request.target())
            .await?
            .ok_or(LogicalActivationPreparationStoreError::InvalidTarget)?;
        let durable = DurablePreparationClaim::decode(&refreshed)?.ok_or_else(|| {
            StoreError::corrupt_data("conflicting logical preparation insert has no durable winner")
        })?;
        let descriptor =
            load_pinned_descriptor(transaction, request.target().clone(), &refreshed, &durable)
                .await?;
        return resolve_durable_claim(
            transaction,
            request,
            descriptor,
            durable,
            origin_selection_id,
        )
        .await;
    }
    bind_logical_job_execution_policy(transaction, &descriptor).await?;
    insert_prerequisite_pins(transaction, &descriptor).await?;
    let fence = make_fence(
        request.target().clone(),
        request.owner(),
        1,
        descriptor.descriptor_digest(),
        request.observed_at(),
        request.expires_at(),
        origin_selection_id,
    )?;
    let claimed = ClaimedLogicalActivationPreparation::new(descriptor, fence, false)
        .map_err(corrupt_value)?;
    Ok(LogicalActivationPreparationClaimOutcome::Claimed(claimed))
}

pub(super) async fn consume_selected_preparation_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    selected: &SelectedLogicalJobOrchestration,
) -> Result<Option<ClaimedLogicalActivationPreparation>, LogicalActivationPreparationStoreError> {
    let row = lock_target(transaction, selected.target()).await?;
    let Some(row) = row else {
        return Ok(None);
    };
    reject_quarantined_preparation(transaction, selected.target().logical_job_id()).await?;
    let Some(durable) = DurablePreparationClaim::decode(&row)? else {
        return Ok(None);
    };
    if durable.state != "preparing"
        || durable.origin_selection_id != Some(selected.selection_id().as_uuid())
        || durable.owner != selected.owner().as_uuid()
        || durable.generation < pg_bigint(selected.generation().get())
        || durable.descriptor_digest != selected.authority_digest()
    {
        return Ok(None);
    }
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(&mut **transaction)
            .await
            .map_err(operation_error)?;
    if now < durable.claimed_at
        || durable.expires_at.saturating_sub(now) < MIN_LOGICAL_WORK_SELECTION_HANDOFF_MILLIS
    {
        return Ok(None);
    }
    let descriptor =
        load_pinned_descriptor(transaction, selected.target().clone(), &row, &durable).await?;
    durable.verify_descriptor(&descriptor)?;
    verify_selected_preparation_renewal_lineage(transaction, selected, &durable).await?;
    let fence = make_fence(
        selected.target().clone(),
        selected.owner(),
        durable.generation_u64()?,
        durable.descriptor_digest,
        UnixMillis::new(durable.claimed_at),
        UnixMillis::new(durable.expires_at),
        selected.selection_id().as_uuid(),
    )?;
    ClaimedLogicalActivationPreparation::new(descriptor, fence, true)
        .map(Some)
        .map_err(corrupt_value)
}

/// Loads the immutable preparation binding after the caller has locked the
/// active run graph and logical job in the canonical order.
pub(super) async fn load_bound_preparation_for_activation_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalActivationPreparationTarget,
) -> Result<LogicalActivationPreparationReceipt, LogicalActivationPreparationStoreError> {
    let row = lock_target(transaction, target)
        .await?
        .ok_or(LogicalActivationPreparationStoreError::InvalidTarget)?;
    let durable = DurablePreparationClaim::decode(&row)?
        .ok_or(LogicalActivationPreparationStoreError::InvalidTarget)?;
    if durable.state != "prepared" {
        return Err(LogicalActivationPreparationStoreError::InvalidTarget);
    }
    let descriptor = load_pinned_descriptor(transaction, target.clone(), &row, &durable).await?;
    durable.verify_descriptor(&descriptor)?;
    load_receipt(transaction, descriptor, true).await
}

async fn resolve_durable_claim(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimLogicalActivationPreparation,
    descriptor: LogicalActivationPreparationDescriptor,
    durable: DurablePreparationClaim,
    origin_selection_id: Uuid,
) -> Result<LogicalActivationPreparationClaimOutcome, LogicalActivationPreparationStoreError> {
    durable.verify_descriptor(&descriptor)?;
    let origin_mismatch = durable.origin_selection_id != Some(origin_selection_id);
    if durable.state == "prepared" {
        if origin_mismatch {
            return Err(LogicalActivationPreparationStoreError::ClaimRejected);
        }
        return load_receipt(transaction, descriptor, true)
            .await
            .map(LogicalActivationPreparationClaimOutcome::Prepared);
    }
    if durable.state != "preparing" {
        return Err(StoreError::corrupt_data("unknown logical preparation claim state").into());
    }
    if !origin_mismatch && durable.is_exact_replay(request) {
        let fence = make_fence(
            request.target().clone(),
            request.owner(),
            durable.generation_u64()?,
            descriptor.descriptor_digest(),
            request.observed_at(),
            request.expires_at(),
            origin_selection_id,
        )?;
        let claimed = ClaimedLogicalActivationPreparation::new(descriptor, fence, true)
            .map_err(corrupt_value)?;
        return Ok(LogicalActivationPreparationClaimOutcome::Claimed(claimed));
    }
    if durable.expires_at > request.observed_at().get() {
        return Ok(LogicalActivationPreparationClaimOutcome::Busy);
    }

    let next_generation = durable
        .generation_u64()?
        .checked_add(1)
        .ok_or(LogicalActivationPreparationStoreError::GenerationExhausted)?;
    let rows = sqlx::query(
        r"
        UPDATE logical_workflow_activation_preparation_claims
        SET owner_id = $3, generation = $4, claimed_at_ms = $5,
            expires_at_ms = $6, updated_at_ms = $5,
            origin_selection_id = $7
        WHERE logical_job_id = $1 AND state = 'preparing'
          AND generation = $2
        ",
    )
    .bind(request.target().logical_job_id().as_uuid())
    .bind(durable.generation)
    .bind(request.owner().as_uuid())
    .bind(generation_i64(next_generation)?)
    .bind(request.observed_at().get())
    .bind(request.expires_at().get())
    .bind(origin_selection_id)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if rows != 1 {
        return Err(StoreError::corrupt_data(
            "locked logical preparation claim disappeared during takeover",
        )
        .into());
    }
    let fence = make_fence(
        request.target().clone(),
        request.owner(),
        next_generation,
        descriptor.descriptor_digest(),
        request.observed_at(),
        request.expires_at(),
        origin_selection_id,
    )?;
    let claimed = ClaimedLogicalActivationPreparation::new(descriptor, fence, false)
        .map_err(corrupt_value)?;
    Ok(LogicalActivationPreparationClaimOutcome::Claimed(claimed))
}

async fn lock_preparation_selection_custody(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &LogicalActivationPreparationClaimFence,
) -> Result<(), LogicalActivationPreparationStoreError> {
    let outcome = lock_preparation_selection_evidence(transaction, claim).await?;
    if outcome != "claimed" {
        return Err(LogicalActivationPreparationStoreError::ClaimRejected);
    }
    Ok(())
}

async fn lock_preparation_renewal_selection_custody(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &LogicalActivationPreparationClaimFence,
) -> Result<bool, LogicalActivationPreparationStoreError> {
    match lock_preparation_selection_evidence(transaction, claim)
        .await?
        .as_str()
    {
        "claimed" => Ok(true),
        "quarantined" => Ok(false),
        _ => Err(LogicalActivationPreparationStoreError::ClaimRejected),
    }
}

async fn lock_preparation_selection_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &LogicalActivationPreparationClaimFence,
) -> Result<String, LogicalActivationPreparationStoreError> {
    let selection_id = claim.selection_origin();
    let row = sqlx::query(
        r"
        SELECT outcome,
               COALESCE(owner_id = $2
               AND tenant_id = $3
               AND run_id = $4
               AND invocation_id = $5
               AND logical_job_id = $6
               AND authority_kind = 'preparation'
               AND authority_digest = $7, FALSE) AS exact
        FROM logical_workflow_activation_work_selections
        WHERE selection_id = $1
        FOR UPDATE
        ",
    )
    .bind(selection_id.as_uuid())
    .bind(claim.owner().as_uuid())
    .bind(claim.target().tenant().as_str())
    .bind(claim.target().run_id().as_uuid())
    .bind(claim.target().invocation_id().as_uuid())
    .bind(claim.target().logical_job_id().as_uuid())
    .bind(claim.descriptor_digest().as_bytes().as_slice())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let row = row.ok_or(LogicalActivationPreparationStoreError::ClaimRejected)?;
    let exact: bool = row.try_get("exact").map_err(operation_error)?;
    if !exact {
        return Err(LogicalActivationPreparationStoreError::ClaimRejected);
    }
    let outcome: String = row.try_get("outcome").map_err(operation_error)?;
    let horizon: Option<String> = sqlx::query_scalar(
        r"
        SELECT queue_name
        FROM logical_workflow_work_selection_replay_horizons
        WHERE queue_name = 'activation'
        FOR UPDATE
        ",
    )
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if horizon.as_deref() != Some("activation") {
        return Err(
            StoreError::corrupt_data("activation selection replay horizon is absent").into(),
        );
    }
    Ok(outcome)
}

async fn lock_preparation_quarantine_custody(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &LogicalActivationPreparationClaimFence,
) -> Result<(), LogicalActivationPreparationStoreError> {
    let quarantine: Option<Uuid> = sqlx::query_scalar(
        r"
        SELECT logical_job_id
        FROM logical_workflow_activation_work_quarantines
        WHERE logical_job_id = $1
        FOR UPDATE
        ",
    )
    .bind(claim.target().logical_job_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if quarantine.is_some() {
        return Err(LogicalActivationPreparationStoreError::ClaimRejected);
    }
    Ok(())
}

async fn lock_preparation_continuation_custody(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &LogicalActivationPreparationClaimFence,
) -> Result<(), LogicalActivationPreparationStoreError> {
    lock_preparation_selection_custody(transaction, claim).await?;
    lock_preparation_quarantine_custody(transaction, claim).await
}

async fn lock_active_preparation_graph(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalActivationPreparationTarget,
) -> Result<bool, LogicalActivationPreparationStoreError> {
    let schemas = current_durable_schemas();
    let run_active: Option<bool> = sqlx::query_scalar(
        r"
        SELECT run.status IN ('queued', 'in_progress')
               AND run.admission_epoch = $4 AND run.plan_schema = $3
        FROM workflow_runs AS run
        JOIN repositories AS repository ON repository.id = run.repository_id
        WHERE repository.tenant_id = $1 AND run.id = $2
        FOR SHARE OF run
        ",
    )
    .bind(target.tenant().as_str())
    .bind(target.run_id().as_uuid())
    .bind(schemas.workflow_plan_i32)
    .bind(schemas.admission_epoch_i32)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if run_active != Some(true) {
        return Ok(false);
    }
    let marker_active: Option<bool> = sqlx::query_scalar(
        r"
        SELECT marker.state IN ('pending', 'active')
               AND marker.orchestration_schema = $3
               AND marker.admission_graph_sealed_at_ms IS NOT NULL
               AND automata_logical_workflow_invocation_published(
                   marker.run_id, $2
               )
        FROM logical_workflow_runs AS marker
        WHERE marker.run_id = $1
        FOR SHARE OF marker
        ",
    )
    .bind(target.run_id().as_uuid())
    .bind(target.invocation_id().as_uuid())
    .bind(schemas.logical_orchestration_i16)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if marker_active != Some(true) {
        return Ok(false);
    }
    let invocation_active: Option<bool> = sqlx::query_scalar(
        r"
        SELECT invocation.state IN ('pending', 'active')
               AND invocation.plan_schema = $3
        FROM logical_workflow_invocations AS invocation
        WHERE invocation.run_id = $1 AND invocation.id = $2
        FOR SHARE OF invocation
        ",
    )
    .bind(target.run_id().as_uuid())
    .bind(target.invocation_id().as_uuid())
    .bind(schemas.workflow_plan_i16)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(invocation_active == Some(true))
}

async fn reject_quarantined_preparation(
    transaction: &mut Transaction<'_, Postgres>,
    logical_job_id: LogicalWorkflowJobId,
) -> Result<(), LogicalActivationPreparationStoreError> {
    let quarantined: bool = sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM logical_workflow_activation_work_quarantines
            WHERE logical_job_id = $1
        )
        ",
    )
    .bind(logical_job_id.as_uuid())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if quarantined {
        Err(LogicalActivationPreparationStoreError::ClaimRejected)
    } else {
        Ok(())
    }
}

async fn lock_target(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalActivationPreparationTarget,
) -> Result<Option<PgRow>, LogicalActivationPreparationStoreError> {
    let row = fetch_locked_target(transaction, target).await?;
    let Some(row) = row else {
        return Ok(None);
    };
    if let Some(logical_job_id) = row
        .try_get::<Option<Uuid>, _>("durable_logical_job_id")
        .map_err(operation_error)?
    {
        sqlx::query(
            r"
            SELECT logical_job_id
            FROM logical_workflow_activation_preparation_claims
            WHERE logical_job_id = $1
            FOR UPDATE
            ",
        )
        .bind(logical_job_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?
        .ok_or_else(|| {
            StoreError::corrupt_data("logical preparation claim disappeared while locking")
        })?;
        return fetch_locked_target(transaction, target).await;
    }
    Ok(Some(row))
}

async fn fetch_locked_target(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalActivationPreparationTarget,
) -> Result<Option<PgRow>, LogicalActivationPreparationStoreError> {
    fetch_locked_target_kind(transaction, target, "steps").await
}

async fn fetch_locked_target_kind(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalActivationPreparationTarget,
    execution_kind: &str,
) -> Result<Option<PgRow>, LogicalActivationPreparationStoreError> {
    let schemas = current_durable_schemas();
    sqlx::query(include_str!(
        "sql/logical_activation_preparation_locked_target.sql"
    ))
    .bind(target.tenant().as_str())
    .bind(target.run_id().as_uuid())
    .bind(target.invocation_id().as_uuid())
    .bind(target.logical_job_id().as_uuid())
    .bind(execution_kind)
    .bind(schemas.workflow_plan_i16)
    .bind(LOGICAL_ACTIVATION_PREPARATION_PLAN_MEDIA_TYPE)
    .bind(schemas.logical_orchestration_i16)
    .bind(schemas.runtime_context_i16)
    .bind(schemas.admission_epoch_i32)
    .bind(schemas.workflow_plan_i32)
    .bind(LOGICAL_ACTIVATION_PREPARATION_EVENT_MEDIA_TYPE)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

pub(super) async fn load_ready_reusable_preparation_descriptor(
    transaction: &mut Transaction<'_, Postgres>,
    target: LogicalActivationPreparationTarget,
) -> Result<Option<LogicalActivationPreparationDescriptor>, LogicalActivationPreparationStoreError>
{
    let Some(row) = fetch_locked_target_kind(transaction, &target, "reusable_workflow").await?
    else {
        return Ok(None);
    };
    load_current_descriptor(transaction, target, &row).await
}

async fn load_current_descriptor(
    transaction: &mut Transaction<'_, Postgres>,
    target: LogicalActivationPreparationTarget,
    row: &PgRow,
) -> Result<Option<LogicalActivationPreparationDescriptor>, LogicalActivationPreparationStoreError>
{
    let prerequisite_rows = sqlx::query(
        r"
        SELECT dependency.prerequisite_job_id,
               prerequisite.logical_key, prerequisite.source_order,
               result.descriptor_digest AS result_descriptor_digest,
               result.outputs_digest, result.commit_digest,
               result.effective_conclusion, result.closure_has_failure,
               result.closure_has_cancelled, result.closure_has_skipped,
               result.output_count, result.finalized_at_ms,
               result.claim_state AS result_claim_state
        FROM logical_workflow_dependencies AS dependency
        JOIN logical_workflow_jobs AS prerequisite
          ON prerequisite.run_id = dependency.run_id
         AND prerequisite.invocation_id = dependency.invocation_id
         AND prerequisite.id = dependency.prerequisite_job_id
        LEFT JOIN logical_workflow_effective_job_results AS result
          ON result.run_id = dependency.run_id
         AND result.invocation_id = dependency.invocation_id
         AND result.logical_job_id = dependency.prerequisite_job_id
        WHERE dependency.run_id = $1 AND dependency.invocation_id = $2
          AND dependency.logical_job_id = $3
        ORDER BY prerequisite.source_order, prerequisite.id
        ",
    )
    .bind(target.run_id().as_uuid())
    .bind(target.invocation_id().as_uuid())
    .bind(target.logical_job_id().as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if prerequisite_rows.iter().any(|row| {
        row.try_get::<Option<String>, _>("result_claim_state")
            .ok()
            .flatten()
            .as_deref()
            != Some("finalized")
    }) {
        return Ok(None);
    }
    let output_rows = load_current_outputs(transaction, &target).await?;
    let prerequisites = decode_prerequisites(&prerequisite_rows, &output_rows)?;
    let runtime_policy = load_runtime_policy(transaction, target.run_id()).await?;
    build_descriptor(target, runtime_policy, row, "", prerequisites).map(Some)
}

async fn load_pinned_descriptor(
    transaction: &mut Transaction<'_, Postgres>,
    target: LogicalActivationPreparationTarget,
    row: &PgRow,
    durable: &DurablePreparationClaim,
) -> Result<LogicalActivationPreparationDescriptor, LogicalActivationPreparationStoreError> {
    let prerequisite_rows = sqlx::query(
        r"
        SELECT prerequisite_job_id, logical_key, source_order,
               result_descriptor_digest, outputs_digest, commit_digest,
               effective_conclusion, closure_has_failure,
               closure_has_cancelled, closure_has_skipped,
               output_count, finalized_at_ms
        FROM logical_workflow_activation_preparation_prerequisites
        WHERE logical_job_id = $1
        ORDER BY source_order, prerequisite_job_id
        ",
    )
    .bind(target.logical_job_id().as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let output_rows = sqlx::query(
        r#"
        SELECT prerequisite_job_id, output_name, sensitivity, public_value
        FROM logical_workflow_activation_preparation_outputs
        WHERE logical_job_id = $1
        ORDER BY prerequisite_job_id, output_name COLLATE "C"
        "#,
    )
    .bind(target.logical_job_id().as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let prerequisites = decode_prerequisites(&prerequisite_rows, &output_rows)?;
    let runtime_policy = load_runtime_policy(transaction, target.run_id()).await?;
    let descriptor = build_descriptor(target, runtime_policy, row, "durable_", prerequisites)?;
    durable.verify_descriptor(&descriptor)?;
    Ok(descriptor)
}

async fn load_current_outputs(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalActivationPreparationTarget,
) -> Result<Vec<PgRow>, LogicalActivationPreparationStoreError> {
    sqlx::query(
        r#"
        SELECT dependency.prerequisite_job_id, output.output_name,
               output.sensitivity, output.public_value
        FROM logical_workflow_dependencies AS dependency
        JOIN logical_workflow_effective_job_results AS result
          ON result.run_id = dependency.run_id
         AND result.invocation_id = dependency.invocation_id
         AND result.logical_job_id = dependency.prerequisite_job_id
         AND result.claim_state = 'finalized'
        JOIN logical_workflow_effective_job_result_outputs AS output
          ON output.logical_job_id = result.logical_job_id
        WHERE dependency.run_id = $1 AND dependency.invocation_id = $2
          AND dependency.logical_job_id = $3
        ORDER BY dependency.prerequisite_job_id, output.output_name COLLATE "C"
        "#,
    )
    .bind(target.run_id().as_uuid())
    .bind(target.invocation_id().as_uuid())
    .bind(target.logical_job_id().as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)
}

fn decode_prerequisites(
    prerequisite_rows: &[PgRow],
    output_rows: &[PgRow],
) -> Result<Vec<LogicalActivationPrerequisiteEvidence>, LogicalActivationPreparationStoreError> {
    let mut outputs = BTreeMap::<Uuid, Vec<LogicalActivationPrerequisiteOutput>>::new();
    for row in output_rows {
        let prerequisite_id = row
            .try_get::<Uuid, _>("prerequisite_job_id")
            .map_err(operation_error)?;
        let output = LogicalActivationPrerequisiteOutput::new(
            WorkflowOutputKey::new(
                row.try_get::<String, _>("output_name")
                    .map_err(operation_error)?,
            )
            .map_err(corrupt_value)?,
            parse_sensitivity(
                &row.try_get::<String, _>("sensitivity")
                    .map_err(operation_error)?,
            )?,
            row.try_get("public_value").map_err(operation_error)?,
        )
        .map_err(corrupt_value)?;
        outputs.entry(prerequisite_id).or_default().push(output);
    }

    let mut prerequisites = Vec::with_capacity(prerequisite_rows.len());
    for row in prerequisite_rows {
        let prerequisite_uuid = row
            .try_get::<Uuid, _>("prerequisite_job_id")
            .map_err(operation_error)?;
        let expected_output_count = usize::try_from(
            row.try_get::<i32, _>("output_count")
                .map_err(operation_error)?,
        )
        .map_err(|_| StoreError::corrupt_data("negative prerequisite output count"))?;
        let prerequisite_outputs = outputs.remove(&prerequisite_uuid).unwrap_or_default();
        if prerequisite_outputs.len() != expected_output_count {
            return Err(
                StoreError::corrupt_data("logical prerequisite output set is incomplete").into(),
            );
        }
        prerequisites.push(
            LogicalActivationPrerequisiteEvidence::new(
                LogicalWorkflowJobId::from_uuid(prerequisite_uuid).map_err(corrupt_value)?,
                WorkflowJobKey::new(
                    row.try_get::<String, _>("logical_key")
                        .map_err(operation_error)?,
                )
                .map_err(corrupt_value)?,
                u16::try_from(
                    row.try_get::<i32, _>("source_order")
                        .map_err(operation_error)?,
                )
                .map_err(|_| StoreError::corrupt_data("invalid prerequisite source order"))?,
                decode_digest(row, "result_descriptor_digest")?,
                decode_digest(row, "outputs_digest")?,
                decode_digest(row, "commit_digest")?,
                parse_conclusion(
                    &row.try_get::<String, _>("effective_conclusion")
                        .map_err(operation_error)?,
                )?,
                row.try_get("closure_has_failure")
                    .map_err(operation_error)?,
                row.try_get("closure_has_cancelled")
                    .map_err(operation_error)?,
                row.try_get("closure_has_skipped")
                    .map_err(operation_error)?,
                prerequisite_outputs,
                UnixMillis::new(row.try_get("finalized_at_ms").map_err(operation_error)?),
            )
            .map_err(corrupt_value)?,
        );
    }
    if !outputs.is_empty() {
        return Err(StoreError::corrupt_data("orphan logical prerequisite output pin").into());
    }
    Ok(prerequisites)
}

async fn load_runtime_policy(
    transaction: &mut Transaction<'_, Postgres>,
    run_id: RunId,
) -> Result<PinnedWorkflowRuntimePolicy, LogicalActivationPreparationStoreError> {
    load_pinned_runtime_policy_for_run(transaction, run_id)
        .await
        .map_err(|error| match error {
            WorkflowRuntimePolicyStoreError::Store(error) => error.into(),
            WorkflowRuntimePolicyStoreError::InvalidTarget => {
                LogicalActivationPreparationStoreError::InvalidTarget
            }
            WorkflowRuntimePolicyStoreError::Conflict => StoreError::corrupt_data(
                "logical activation runtime policy has conflicting durable state",
            )
            .into(),
        })
}

fn build_descriptor(
    target: LogicalActivationPreparationTarget,
    runtime_policy: PinnedWorkflowRuntimePolicy,
    row: &PgRow,
    prefix: &str,
    prerequisites: Vec<LogicalActivationPrerequisiteEvidence>,
) -> Result<LogicalActivationPreparationDescriptor, LogicalActivationPreparationStoreError> {
    let schemas = current_durable_schemas();
    let logical_key =
        WorkflowJobKey::new(get_string(row, prefix, "logical_key")?).map_err(corrupt_value)?;
    let source_order = u16::try_from(get_i32(row, prefix, "source_order")?)
        .map_err(|_| StoreError::corrupt_data("invalid preparation source order"))?;
    let mut execution = LogicalActivationExecutionContext::new(
        WorkflowId::from_uuid(get_uuid(row, prefix, "workflow_id")?),
        get_string(row, prefix, "workflow_name")?,
        get_string(row, prefix, "git_ref")?,
        get_string(row, prefix, "event_name")?,
        get_optional_string(row, prefix, "actor")?,
        RunIdAlias::new(
            u64::try_from(get_i64(row, prefix, "run_id_alias")?)
                .map_err(|_| StoreError::corrupt_data("invalid preparation run ID alias"))?,
        )
        .map_err(|_| StoreError::corrupt_data("invalid preparation run ID alias"))?,
        u64::try_from(get_i64(row, prefix, "run_number")?)
            .map_err(|_| StoreError::corrupt_data("invalid preparation run number"))?,
        u32::try_from(get_i32(row, prefix, "run_attempt")?)
            .map_err(|_| StoreError::corrupt_data("invalid preparation run attempt"))?,
    )
    .map_err(corrupt_value)?;
    if let Some(triggering_actor) = get_optional_string(row, prefix, "triggering_actor")? {
        execution = execution
            .with_triggering_actor(triggering_actor)
            .map_err(corrupt_value)?;
    }
    let authority_profile =
        parse_authority_profile(&get_string(row, prefix, "authority_profile")?)?;
    let runner_policy =
        decode_admission_object(row, prefix, "runner_policy", AdmissionObjectLimit::Standard)?;
    let plan = decode_admission_object(row, prefix, "plan", AdmissionObjectLimit::Standard)?;
    let event = decode_admission_object(row, prefix, "event", AdmissionObjectLimit::ProviderEvent)?;
    let base_context =
        decode_admission_object(row, prefix, "base_context", AdmissionObjectLimit::Standard)?;
    let ready_at = if prefix.is_empty() {
        UnixMillis::new(row.try_get("created_at_ms").map_err(operation_error)?)
    } else {
        UnixMillis::new(get_i64(row, prefix, "evidence_ready_at_ms")?)
    };
    let descriptor = LogicalActivationPreparationDescriptor::new(
        target,
        logical_key,
        source_order,
        execution,
        authority_profile,
        runner_policy,
        runtime_policy,
        plan,
        event,
        LogicalActivationBaseContextKind::Admission,
        base_context,
        prerequisites,
        ready_at,
    )
    .map_err(corrupt_value)?;
    if !prefix.is_empty() {
        let exact = get_string(row, prefix, "base_context_kind")? == "admission"
            && get_i16(row, prefix, "base_context_schema")? == schemas.runtime_context_i16
            && usize::try_from(get_i32(row, prefix, "prerequisite_count")?).ok()
                == Some(descriptor.prerequisites().len())
            && decode_prefixed_digest(row, prefix, "prerequisites_digest")?
                == descriptor.prerequisites_digest()
            && parse_status(&get_string(row, prefix, "aggregate_status")?)? == descriptor.status()
            && decode_prefixed_digest(row, prefix, "descriptor_digest")?
                == descriptor.descriptor_digest();
        if !exact {
            return Err(StoreError::corrupt_data(
                "durable logical preparation descriptor is inconsistent",
            )
            .into());
        }
    }
    Ok(descriptor)
}

async fn insert_claim(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimLogicalActivationPreparation,
    descriptor: &LogicalActivationPreparationDescriptor,
    origin_selection_id: Uuid,
) -> Result<bool, LogicalActivationPreparationStoreError> {
    let schemas = current_durable_schemas();
    let rows = sqlx::query(
        r"
        INSERT INTO logical_workflow_activation_preparation_claims (
            logical_job_id, run_id, invocation_id, descriptor_digest,
            logical_key, source_order, workflow_id, workflow_name, git_ref,
            authority_profile, runner_policy_digest, runner_policy_object_key,
            runner_policy_size_bytes, runner_policy_media_type,
            actor, run_number, run_attempt, plan_digest, plan_object_key,
            plan_size_bytes, plan_media_type, plan_schema, event_digest,
            event_object_key, event_size_bytes, event_media_type,
            base_context_kind, base_context_digest, base_context_object_key,
            base_context_size_bytes, base_context_media_type, base_context_schema,
            workspace, prerequisite_count,
            prerequisites_digest, aggregate_status, evidence_ready_at_ms,
            runtime_policy_revision, runtime_policy_digest,
            state, owner_id, generation, claimed_at_ms, expires_at_ms,
            created_at_ms, updated_at_ms, origin_selection_id
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
            $15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,
            'admission',$27,$28,$29,$30,$42,$31,$32,$33,$34,$35,
            $36,$37,'preparing',$38,1,$39,$40,$39,$39,$41
        )
        ON CONFLICT (logical_job_id) DO NOTHING
        ",
    )
    .bind(descriptor.target().logical_job_id().as_uuid())
    .bind(descriptor.target().run_id().as_uuid())
    .bind(descriptor.target().invocation_id().as_uuid())
    .bind(descriptor.descriptor_digest().as_bytes().as_slice())
    .bind(descriptor.logical_key().as_str())
    .bind(i32::from(descriptor.source_order()))
    .bind(descriptor.execution().workflow_id().as_uuid())
    .bind(descriptor.execution().workflow_name())
    .bind(descriptor.execution().git_ref())
    .bind(authority_profile_name(descriptor.authority_profile()))
    .bind(descriptor.runner_policy().digest().as_bytes().as_slice())
    .bind(descriptor.runner_policy().object_key().as_str())
    .bind(size_i64(descriptor.runner_policy().encoded_size())?)
    .bind(descriptor.runner_policy().media_type())
    .bind(descriptor.execution().actor())
    .bind(run_number_i64(descriptor.execution().run_number())?)
    .bind(run_attempt_i32(descriptor.execution().run_attempt())?)
    .bind(descriptor.plan().digest().as_bytes().as_slice())
    .bind(descriptor.plan().object_key().as_str())
    .bind(size_i64(descriptor.plan().encoded_size())?)
    .bind(descriptor.plan().media_type())
    .bind(i16::try_from(WORKFLOW_PLAN_SCHEMA).unwrap_or(i16::MAX))
    .bind(descriptor.event().digest().as_bytes().as_slice())
    .bind(descriptor.event().object_key().as_str())
    .bind(size_i64(descriptor.event().encoded_size())?)
    .bind(descriptor.event().media_type())
    .bind(descriptor.base_context().digest().as_bytes().as_slice())
    .bind(descriptor.base_context().object_key().as_str())
    .bind(size_i64(descriptor.base_context().encoded_size())?)
    .bind(descriptor.base_context().media_type())
    .bind(descriptor.workspace().as_str())
    .bind(count_i32(descriptor.prerequisites().len())?)
    .bind(descriptor.prerequisites_digest().as_bytes().as_slice())
    .bind(status_name(descriptor.status()))
    .bind(descriptor.evidence_ready_at().get())
    .bind(pg_bigint(
        descriptor.runtime_policy().pin().revision().get(),
    ))
    .bind(
        descriptor
            .runtime_policy()
            .pin()
            .digest()
            .as_bytes()
            .as_slice(),
    )
    .bind(request.owner().as_uuid())
    .bind(request.observed_at().get())
    .bind(request.expires_at().get())
    .bind(origin_selection_id)
    .bind(schemas.runtime_context_i16)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    Ok(rows == 1)
}

async fn bind_logical_job_execution_policy(
    transaction: &mut Transaction<'_, Postgres>,
    descriptor: &LogicalActivationPreparationDescriptor,
) -> Result<(), LogicalActivationPreparationStoreError> {
    let rows = sqlx::query(
        r"
        UPDATE logical_workflow_jobs
        SET authority_profile = $2
        WHERE id = $1 AND authority_profile IS NULL
          AND runtime_policy_revision = $3
          AND runtime_policy_digest = $4
        ",
    )
    .bind(descriptor.target().logical_job_id().as_uuid())
    .bind(authority_profile_name(descriptor.authority_profile()))
    .bind(pg_bigint(
        descriptor.runtime_policy().pin().revision().get(),
    ))
    .bind(
        descriptor
            .runtime_policy()
            .pin()
            .digest()
            .as_bytes()
            .as_slice(),
    )
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if rows != 1 {
        return Err(StoreError::corrupt_data(
            "logical job execution policy was already bound inconsistently",
        )
        .into());
    }
    Ok(())
}

async fn insert_prerequisite_pins(
    transaction: &mut Transaction<'_, Postgres>,
    descriptor: &LogicalActivationPreparationDescriptor,
) -> Result<(), LogicalActivationPreparationStoreError> {
    for prerequisite in descriptor.prerequisites() {
        sqlx::query(
            r"
            INSERT INTO logical_workflow_activation_preparation_prerequisites (
                logical_job_id, prerequisite_job_id, logical_key, source_order,
                result_descriptor_digest, outputs_digest, commit_digest,
                effective_conclusion, closure_has_failure,
                closure_has_cancelled, closure_has_skipped, output_count,
                finalized_at_ms
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
            ",
        )
        .bind(descriptor.target().logical_job_id().as_uuid())
        .bind(prerequisite.logical_job_id().as_uuid())
        .bind(prerequisite.logical_key().as_str())
        .bind(i32::from(prerequisite.source_order()))
        .bind(
            prerequisite
                .result_descriptor_digest()
                .as_bytes()
                .as_slice(),
        )
        .bind(prerequisite.outputs_digest().as_bytes().as_slice())
        .bind(prerequisite.commit_digest().as_bytes().as_slice())
        .bind(conclusion_name(prerequisite.effective_conclusion()))
        .bind(prerequisite.closure_has_failure())
        .bind(prerequisite.closure_has_cancelled())
        .bind(prerequisite.closure_has_skipped())
        .bind(count_i32(prerequisite.outputs().len())?)
        .bind(prerequisite.finalized_at().get())
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
        for output in prerequisite.outputs() {
            sqlx::query(
                r"
                INSERT INTO logical_workflow_activation_preparation_outputs (
                    logical_job_id, prerequisite_job_id, output_name,
                    sensitivity, public_value
                ) VALUES ($1,$2,$3,$4,$5)
                ",
            )
            .bind(descriptor.target().logical_job_id().as_uuid())
            .bind(prerequisite.logical_job_id().as_uuid())
            .bind(output.name().as_str())
            .bind(sensitivity_name(output.sensitivity()))
            .bind(output.public_value())
            .execute(&mut **transaction)
            .await
            .map_err(operation_error)?;
        }
    }
    Ok(())
}

async fn insert_binding(
    transaction: &mut Transaction<'_, Postgres>,
    request: &BindLogicalActivationPreparation,
) -> Result<(), LogicalActivationPreparationStoreError> {
    let claim_origin_selection_id = request.claim().selection_origin();
    let schemas = current_durable_schemas();
    sqlx::query(
        r"
        INSERT INTO logical_workflow_activation_preparations (
            logical_job_id, run_id, invocation_id, descriptor_digest,
            authority_profile,
            base_context_digest, base_context_object_key,
            base_context_size_bytes, base_context_media_type,
            base_context_schema, prerequisite_context_digest,
            prerequisite_context_object_key, prerequisite_context_size_bytes,
            prerequisite_context_media_type, prerequisite_context_schema,
            activation_input_digest, claim_owner_id, claim_generation,
            claim_started_at_ms, claim_expires_at_ms, bound_at_ms,
            runtime_policy_revision, runtime_policy_digest,
            claim_origin_selection_id
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$23,$10,$11,$12,$13,$23,
            $14,$15,$16,$17,$18,$19,$20,$21,$22
        )
        ",
    )
    .bind(request.claim().target().logical_job_id().as_uuid())
    .bind(request.claim().target().run_id().as_uuid())
    .bind(request.claim().target().invocation_id().as_uuid())
    .bind(
        request
            .descriptor()
            .descriptor_digest()
            .as_bytes()
            .as_slice(),
    )
    .bind(authority_profile_name(
        request.descriptor().authority_profile(),
    ))
    .bind(request.base_context().digest().as_bytes().as_slice())
    .bind(request.base_context().object_key().as_str())
    .bind(size_i64(request.base_context().encoded_size())?)
    .bind(request.base_context().media_type())
    .bind(
        request
            .prerequisite_context()
            .digest()
            .as_bytes()
            .as_slice(),
    )
    .bind(request.prerequisite_context().object_key().as_str())
    .bind(size_i64(request.prerequisite_context().encoded_size())?)
    .bind(request.prerequisite_context().media_type())
    .bind(request.input_digest().as_bytes().as_slice())
    .bind(request.claim().owner().as_uuid())
    .bind(pg_bigint(request.claim().generation().get()))
    .bind(request.claim().claimed_at().get())
    .bind(request.claim().expires_at().get())
    .bind(request.bound_at().get())
    .bind(pg_bigint(
        request.descriptor().runtime_policy().pin().revision().get(),
    ))
    .bind(
        request
            .descriptor()
            .runtime_policy()
            .pin()
            .digest()
            .as_bytes()
            .as_slice(),
    )
    .bind(claim_origin_selection_id.as_uuid())
    .bind(schemas.runtime_context_i16)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

#[allow(clippy::too_many_lines)] // Rehydration validates the complete authenticated receipt tuple.
async fn load_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    descriptor: LogicalActivationPreparationDescriptor,
    replayed: bool,
) -> Result<LogicalActivationPreparationReceipt, LogicalActivationPreparationStoreError> {
    let row = sqlx::query(
        r"
        SELECT descriptor_digest,
               authority_profile,
               base_context_digest, base_context_object_key,
               base_context_size_bytes, base_context_media_type,
               prerequisite_context_digest, prerequisite_context_object_key,
               prerequisite_context_size_bytes, prerequisite_context_media_type,
               activation_input_digest, claim_owner_id, claim_generation,
               claim_started_at_ms, claim_expires_at_ms, bound_at_ms,
               runtime_policy_revision, runtime_policy_digest,
               claim_origin_selection_id
        FROM logical_workflow_activation_preparations
        WHERE logical_job_id = $1 AND run_id = $2 AND invocation_id = $3
        ",
    )
    .bind(descriptor.target().logical_job_id().as_uuid())
    .bind(descriptor.target().run_id().as_uuid())
    .bind(descriptor.target().invocation_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or_else(|| StoreError::corrupt_data("prepared claim lacks immutable binding"))?;
    if decode_digest(&row, "descriptor_digest")? != descriptor.descriptor_digest() {
        return Err(StoreError::corrupt_data(
            "logical preparation receipt descriptor disagrees with claim",
        )
        .into());
    }
    if parse_authority_profile(
        &row.try_get::<String, _>("authority_profile")
            .map_err(operation_error)?,
    )? != descriptor.authority_profile()
    {
        return Err(StoreError::corrupt_data(
            "logical preparation receipt authority profile disagrees with claim",
        )
        .into());
    }
    let runtime_revision: i64 = row
        .try_get("runtime_policy_revision")
        .map_err(operation_error)?;
    if u64::try_from(runtime_revision).ok()
        != Some(descriptor.runtime_policy().pin().revision().get())
        || decode_digest(&row, "runtime_policy_digest")?
            != descriptor.runtime_policy().pin().digest()
    {
        return Err(StoreError::corrupt_data(
            "logical preparation receipt runtime policy disagrees with claim",
        )
        .into());
    }
    let owner = LogicalActivationWorkerId::from_uuid(
        row.try_get("claim_owner_id").map_err(operation_error)?,
    )
    .map_err(corrupt_value)?;
    let generation = LogicalActivationPreparationGeneration::new(
        u64::try_from(
            row.try_get::<i64, _>("claim_generation")
                .map_err(operation_error)?,
        )
        .map_err(|_| StoreError::corrupt_data("invalid preparation receipt generation"))?,
    )
    .map_err(corrupt_value)?;
    let selection_origin = automata_ci_store::LogicalWorkSelectionId::from_uuid(
        row.try_get("claim_origin_selection_id")
            .map_err(operation_error)?,
    )
    .map_err(corrupt_value)?;
    let claim = LogicalActivationPreparationClaimFence::new_for_selection(
        descriptor.target().clone(),
        owner,
        generation,
        descriptor.descriptor_digest(),
        UnixMillis::new(
            row.try_get("claim_started_at_ms")
                .map_err(operation_error)?,
        ),
        UnixMillis::new(
            row.try_get("claim_expires_at_ms")
                .map_err(operation_error)?,
        ),
        selection_origin,
    )
    .map_err(corrupt_value)?;
    LogicalActivationPreparationReceipt::from_durable(
        descriptor,
        claim,
        decode_admission_object(&row, "", "base_context", AdmissionObjectLimit::Standard)?,
        decode_admission_object(
            &row,
            "",
            "prerequisite_context",
            AdmissionObjectLimit::Standard,
        )?,
        decode_digest(&row, "activation_input_digest")?,
        UnixMillis::new(row.try_get("bound_at_ms").map_err(operation_error)?),
        replayed,
    )
    .map_err(corrupt_value)
}

#[derive(Debug)]
struct DurablePreparationClaim {
    state: String,
    owner: Uuid,
    generation: i64,
    descriptor_digest: Sha256Digest,
    runtime_policy_revision: i64,
    runtime_policy_digest: Sha256Digest,
    workspace: String,
    claimed_at: i64,
    expires_at: i64,
    origin_selection_id: Option<Uuid>,
}

impl DurablePreparationClaim {
    fn decode(row: &PgRow) -> Result<Option<Self>, LogicalActivationPreparationStoreError> {
        if row
            .try_get::<Option<Uuid>, _>("durable_logical_job_id")
            .map_err(operation_error)?
            .is_none()
        {
            return Ok(None);
        }
        let owner: Uuid = required_optional(row, "durable_owner_id")?;
        if owner.is_nil() {
            return Err(StoreError::corrupt_data("nil logical preparation owner").into());
        }
        Ok(Some(Self {
            state: required_optional(row, "durable_state")?,
            owner,
            generation: required_optional(row, "durable_generation")?,
            descriptor_digest: decode_optional_digest(row, "durable_descriptor_digest")?,
            runtime_policy_revision: required_optional(row, "durable_runtime_policy_revision")?,
            runtime_policy_digest: decode_optional_digest(row, "durable_runtime_policy_digest")?,
            workspace: required_optional(row, "durable_workspace")?,
            claimed_at: required_optional(row, "durable_claimed_at_ms")?,
            expires_at: required_optional(row, "durable_expires_at_ms")?,
            origin_selection_id: row
                .try_get("durable_origin_selection_id")
                .map_err(operation_error)?,
        }))
    }

    fn generation_u64(&self) -> Result<u64, LogicalActivationPreparationStoreError> {
        u64::try_from(self.generation)
            .ok()
            .filter(|value| *value > 0)
            .ok_or(LogicalActivationPreparationStoreError::GenerationExhausted)
    }

    fn verify_descriptor(
        &self,
        descriptor: &LogicalActivationPreparationDescriptor,
    ) -> Result<(), LogicalActivationPreparationStoreError> {
        if self.descriptor_digest != descriptor.descriptor_digest()
            || self.workspace != descriptor.workspace().as_str()
            || u64::try_from(self.runtime_policy_revision).ok()
                != Some(descriptor.runtime_policy().pin().revision().get())
            || self.runtime_policy_digest != descriptor.runtime_policy().pin().digest()
        {
            return Err(StoreError::corrupt_data(
                "durable logical preparation claim disagrees with pinned descriptor",
            )
            .into());
        }
        Ok(())
    }

    fn is_exact_replay(&self, request: &ClaimLogicalActivationPreparation) -> bool {
        self.owner == request.owner().as_uuid()
            && self.claimed_at == request.observed_at().get()
            && self.expires_at == request.expires_at().get()
    }

    fn matches_fence(&self, claim: &LogicalActivationPreparationClaimFence) -> bool {
        self.owner == claim.owner().as_uuid()
            && self.generation == pg_bigint(claim.generation().get())
            && self.descriptor_digest == claim.descriptor_digest()
            && self.origin_selection_id == Some(claim.selection_origin().as_uuid())
            && self.claimed_at == claim.claimed_at().get()
            && self.expires_at == claim.expires_at().get()
    }
}

fn make_fence(
    target: LogicalActivationPreparationTarget,
    owner: LogicalActivationWorkerId,
    generation: u64,
    descriptor_digest: Sha256Digest,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
    origin_selection_id: Uuid,
) -> Result<LogicalActivationPreparationClaimFence, LogicalActivationPreparationStoreError> {
    let selection_origin =
        automata_ci_store::LogicalWorkSelectionId::from_uuid(origin_selection_id)
            .map_err(corrupt_value)?;
    LogicalActivationPreparationClaimFence::new_for_selection(
        target,
        owner,
        LogicalActivationPreparationGeneration::new(generation).map_err(corrupt_value)?,
        descriptor_digest,
        claimed_at,
        expires_at,
        selection_origin,
    )
    .map_err(corrupt_value)
}

fn decode_admission_object(
    row: &PgRow,
    prefix: &str,
    name: &str,
    limit: AdmissionObjectLimit,
) -> Result<AdmissionObject, LogicalActivationPreparationStoreError> {
    let digest = decode_prefixed_digest(row, prefix, &format!("{name}_digest"))?;
    let object_key = ObjectKey::new(get_string(row, prefix, &format!("{name}_object_key"))?)
        .map_err(corrupt_value)?;
    let encoded_size = u64::try_from(get_i64(row, prefix, &format!("{name}_size_bytes"))?)
        .map_err(|_| StoreError::corrupt_data("invalid preparation object size"))?;
    let media_type = get_string(row, prefix, &format!("{name}_media_type"))?;
    match limit {
        AdmissionObjectLimit::Standard => {
            AdmissionObject::new(digest, object_key, encoded_size, media_type)
        }
        AdmissionObjectLimit::ProviderEvent => {
            AdmissionObject::new_event(digest, object_key, encoded_size, media_type)
        }
    }
    .map_err(corrupt_value)
}

#[derive(Clone, Copy)]
enum AdmissionObjectLimit {
    Standard,
    ProviderEvent,
}

fn decode_prefixed_digest(
    row: &PgRow,
    prefix: &str,
    name: &str,
) -> Result<Sha256Digest, LogicalActivationPreparationStoreError> {
    decode_digest(row, &format!("{prefix}{name}"))
}

fn decode_digest(
    row: &PgRow,
    column: &str,
) -> Result<Sha256Digest, LogicalActivationPreparationStoreError> {
    digest_from_vec(row.try_get(column).map_err(operation_error)?, column)
}

fn decode_optional_digest(
    row: &PgRow,
    column: &str,
) -> Result<Sha256Digest, LogicalActivationPreparationStoreError> {
    digest_from_vec(required_optional(row, column)?, column)
}

fn digest_from_vec(
    value: Vec<u8>,
    column: &str,
) -> Result<Sha256Digest, LogicalActivationPreparationStoreError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| StoreError::corrupt_data(format!("{column} is not SHA-256")))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn get_string(
    row: &PgRow,
    prefix: &str,
    name: &str,
) -> Result<String, LogicalActivationPreparationStoreError> {
    row.try_get(format!("{prefix}{name}").as_str())
        .map_err(operation_error)
}

fn get_optional_string(
    row: &PgRow,
    prefix: &str,
    name: &str,
) -> Result<Option<String>, LogicalActivationPreparationStoreError> {
    row.try_get(format!("{prefix}{name}").as_str())
        .map_err(operation_error)
}

fn get_uuid(
    row: &PgRow,
    prefix: &str,
    name: &str,
) -> Result<Uuid, LogicalActivationPreparationStoreError> {
    row.try_get(format!("{prefix}{name}").as_str())
        .map_err(operation_error)
}

fn get_i64(
    row: &PgRow,
    prefix: &str,
    name: &str,
) -> Result<i64, LogicalActivationPreparationStoreError> {
    row.try_get(format!("{prefix}{name}").as_str())
        .map_err(operation_error)
}

fn get_i32(
    row: &PgRow,
    prefix: &str,
    name: &str,
) -> Result<i32, LogicalActivationPreparationStoreError> {
    row.try_get(format!("{prefix}{name}").as_str())
        .map_err(operation_error)
}

fn get_i16(
    row: &PgRow,
    prefix: &str,
    name: &str,
) -> Result<i16, LogicalActivationPreparationStoreError> {
    row.try_get(format!("{prefix}{name}").as_str())
        .map_err(operation_error)
}

fn required_optional<T>(
    row: &PgRow,
    column: &str,
) -> Result<T, LogicalActivationPreparationStoreError>
where
    for<'value> T: sqlx::Decode<'value, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get::<Option<T>, _>(column)
        .map_err(operation_error)?
        .ok_or_else(|| {
            StoreError::corrupt_data(format!("logical preparation lacks {column}")).into()
        })
}

fn parse_conclusion(value: &str) -> Result<JobConclusion, LogicalActivationPreparationStoreError> {
    match value {
        "success" => Ok(JobConclusion::Success),
        "failure" => Ok(JobConclusion::Failure),
        "cancelled" => Ok(JobConclusion::Cancelled),
        "timed_out" => Ok(JobConclusion::TimedOut),
        "skipped" => Ok(JobConclusion::Skipped),
        _ => Err(StoreError::corrupt_data("unknown logical conclusion").into()),
    }
}

fn parse_sensitivity(
    value: &str,
) -> Result<OutputSensitivity, LogicalActivationPreparationStoreError> {
    match value {
        "public" => Ok(OutputSensitivity::Public),
        "secret_derived" => Ok(OutputSensitivity::SecretDerived),
        _ => Err(StoreError::corrupt_data("unknown logical output sensitivity").into()),
    }
}

fn parse_status(
    value: &str,
) -> Result<LogicalActivationAggregateStatus, LogicalActivationPreparationStoreError> {
    match value {
        "success" => Ok(LogicalActivationAggregateStatus::Success),
        "failure" => Ok(LogicalActivationAggregateStatus::Failure),
        "cancelled" => Ok(LogicalActivationAggregateStatus::Cancelled),
        "skipped" => Ok(LogicalActivationAggregateStatus::Skipped),
        _ => Err(StoreError::corrupt_data("unknown logical activation status").into()),
    }
}

fn parse_authority_profile(
    value: &str,
) -> Result<JobAuthorityProfile, LogicalActivationPreparationStoreError> {
    match value {
        "standard" => Ok(JobAuthorityProfile::Standard),
        "credential_free" => Ok(JobAuthorityProfile::CredentialFree),
        _ => Err(StoreError::corrupt_data("unknown logical authority profile").into()),
    }
}

const fn authority_profile_name(value: JobAuthorityProfile) -> &'static str {
    match value {
        JobAuthorityProfile::Standard => "standard",
        JobAuthorityProfile::CredentialFree => "credential_free",
    }
}

const fn conclusion_name(value: JobConclusion) -> &'static str {
    match value {
        JobConclusion::Success => "success",
        JobConclusion::Failure => "failure",
        JobConclusion::Cancelled => "cancelled",
        JobConclusion::TimedOut => "timed_out",
        JobConclusion::Skipped => "skipped",
    }
}

const fn sensitivity_name(value: OutputSensitivity) -> &'static str {
    match value {
        OutputSensitivity::Public => "public",
        OutputSensitivity::SecretDerived => "secret_derived",
    }
}

const fn status_name(value: LogicalActivationAggregateStatus) -> &'static str {
    match value {
        LogicalActivationAggregateStatus::Success => "success",
        LogicalActivationAggregateStatus::Failure => "failure",
        LogicalActivationAggregateStatus::Cancelled => "cancelled",
        LogicalActivationAggregateStatus::Skipped => "skipped",
    }
}

fn size_i64(value: u64) -> Result<i64, LogicalActivationPreparationStoreError> {
    i64::try_from(value)
        .map_err(|_| StoreError::corrupt_data("logical preparation object exceeds BIGINT").into())
}

fn run_number_i64(value: u64) -> Result<i64, LogicalActivationPreparationStoreError> {
    i64::try_from(value).map_err(|_| {
        StoreError::corrupt_data("logical preparation run number exceeds BIGINT").into()
    })
}

fn run_attempt_i32(value: u32) -> Result<i32, LogicalActivationPreparationStoreError> {
    i32::try_from(value).map_err(|_| {
        StoreError::corrupt_data("logical preparation run attempt exceeds INTEGER").into()
    })
}

fn count_i32(value: usize) -> Result<i32, LogicalActivationPreparationStoreError> {
    i32::try_from(value)
        .map_err(|_| StoreError::corrupt_data("logical preparation count exceeds INTEGER").into())
}

fn generation_i64(value: u64) -> Result<i64, LogicalActivationPreparationStoreError> {
    i64::try_from(value).map_err(|_| LogicalActivationPreparationStoreError::GenerationExhausted)
}

fn corrupt_value(error: impl std::fmt::Display) -> LogicalActivationPreparationStoreError {
    StoreError::corrupt_data(format!(
        "invalid logical activation preparation value: {error}"
    ))
    .into()
}

fn operation_error(error: sqlx::Error) -> LogicalActivationPreparationStoreError {
    StoreError::operation(error).into()
}
