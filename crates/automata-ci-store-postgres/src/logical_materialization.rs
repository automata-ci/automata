use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use automata_ci_core::{
    AttemptId, JOB_IR_SCHEMA_VERSION, JOB_RUNTIME_CONTEXT_SCHEMA_VERSION, JobAuthorityProfile,
    JobConclusion, JobId, JobSecretExposure, MAX_LOGICAL_JOBS, OutputSensitivity, RunIdAlias,
    Sha256Digest, UnixMillis, WorkflowId, WorkflowJobKey, WorkflowOutputKey,
};
use sha2::{Digest as _, Sha256};
use sqlx::{PgPool, Postgres, Row as _, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::{
    CurrentAttemptOutputSafety, PostgresStore,
    durable_schema::current_durable_schemas,
    github_checks::{GithubJobCheckInsertError, insert_github_job_check_subject},
    logical_activation::decode_scheduling_policy,
    pg_bigint,
};
use automata_ci_store::{
    ActivatedLogicalInstanceDescriptor, AdmissionObject, ClaimLogicalInstanceMaterialization,
    ClaimedLogicalInstanceMaterialization, ClaimedLogicalRunFinalization,
    CommitLogicalInstanceMaterialization, CommitLogicalRunFinalization,
    LOGICAL_ACTIVATION_JOB_IR_MEDIA_TYPE, LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE,
    LOGICAL_INSTANCE_RESULT_MEDIA_TYPE, LOGICAL_JOB_RESULT_PLAN_MEDIA_TYPE,
    LogicalActivationExecutionContext, LogicalActivationObject,
    LogicalInstanceMaterializationClaimOutcome, LogicalInstanceMaterializationDescriptor,
    LogicalInstanceMaterializationTarget, LogicalInstanceResultDescriptor,
    LogicalInstanceResultGeneration, LogicalInstanceResultTarget, LogicalInstanceResultWorkerId,
    LogicalInstanceTerminalOrdinal, LogicalJobInstanceOutput, LogicalJobInstanceResultEvidence,
    LogicalJobPrerequisiteEvidence, LogicalJobResultDescriptor, LogicalJobResultGeneration,
    LogicalJobResultOutput, LogicalJobResultTarget, LogicalJobResultWorkerId,
    LogicalJobSchedulingPolicyScope, LogicalMaterializationClaimFence,
    LogicalMaterializationGeneration, LogicalMaterializationReceipt,
    LogicalMaterializationRepository, LogicalMaterializationStoreError,
    LogicalRunFinalizationClaimFence, LogicalRunFinalizationDescriptor,
    LogicalRunFinalizationGeneration, LogicalRunFinalizationOpenState,
    LogicalRunFinalizationTarget, LogicalRunFinalizationWorkerId,
    LogicalRunFinalizationWorkflowStatus, LogicalRunJobResultEvidence, LogicalTerminalResultObject,
    LogicalWorkflowInstanceId, LogicalWorkflowInvocationId, LogicalWorkflowJobId,
    MIN_LOGICAL_WORK_SELECTION_HANDOFF_MILLIS, ObjectKey, RenewLogicalInstanceMaterialization,
    RenewedLogicalInstanceMaterialization, RepositoryId, ResolvedLogicalJobSchedulingPolicy,
    SelectedLogicalInstanceMaterialization, StoreError, WORKFLOW_PLAN_SCHEMA,
    WorkflowRuntimePolicyPin, WorkflowRuntimePolicyRevision,
};

const MATERIALIZATION_COMMIT_DIGEST_DOMAIN: &[u8] =
    b"automata.store.logical-materialization-commit.v3\0";

#[allow(clippy::too_many_lines)] // The trait transaction keeps its security-relevant lock order visible.
#[async_trait]
impl LogicalMaterializationRepository for PostgresStore {
    async fn renew_logical_instance_materialization(
        &self,
        request: RenewLogicalInstanceMaterialization,
    ) -> Result<RenewedLogicalInstanceMaterialization, LogicalMaterializationStoreError> {
        let mut transaction = begin_materialization_transaction(&self.pool).await?;
        let selection_is_claimed =
            lock_materialization_renewal_selection_custody(&mut transaction, request.claim())
                .await?;
        let next_generation = request
            .claim()
            .generation()
            .get()
            .checked_add(1)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or(LogicalMaterializationStoreError::GenerationExhausted)?;
        let selection_id = request.claim().selection_origin();
        if let Some((
            receipt_generation,
            receipt_claimed_at,
            receipt_expires_at,
            receipt_validated_at,
        )) = load_exact_materialization_renewal_receipt(&mut transaction, &request).await?
        {
            let acknowledgement = RenewedLogicalInstanceMaterialization::new(
                request,
                LogicalMaterializationGeneration::new(
                    u64::try_from(receipt_generation)
                        .map_err(|_| LogicalMaterializationStoreError::GenerationExhausted)?,
                )
                .map_err(|_| LogicalMaterializationStoreError::GenerationExhausted)?,
                UnixMillis::new(receipt_claimed_at),
                UnixMillis::new(receipt_expires_at),
                UnixMillis::new(receipt_validated_at),
            )
            .map_err(|_| StoreError::corrupt_data("invalid materialization renewal receipt"))?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(acknowledgement);
        }
        if !selection_is_claimed {
            return Err(LogicalMaterializationStoreError::ClaimRejected);
        }
        lock_materialization_quarantine_custody(&mut transaction, request.claim()).await?;
        let run_state = lock_run(&mut transaction, request.claim().target())
            .await?
            .ok_or(LogicalMaterializationStoreError::InvalidTarget)?;
        if !run_state.is_active() {
            return Err(LogicalMaterializationStoreError::ClaimRejected);
        }
        let row = lock_fresh_target(&mut transaction, request.claim().target())
            .await?
            .ok_or(LogicalMaterializationStoreError::InvalidTarget)?;
        let descriptor = decode_descriptor(request.claim().target().clone(), &row)?;
        let durable = DurableMaterializationClaim::decode(&row)?
            .ok_or(LogicalMaterializationStoreError::ClaimRejected)?;
        durable.verify_descriptor(&descriptor)?;
        if durable.state != "materializing" {
            return Err(LogicalMaterializationStoreError::ClaimRejected);
        }
        let database_now: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT",
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if !durable.matches_fence(request.claim()) {
            return Err(LogicalMaterializationStoreError::ClaimRejected);
        }
        if database_now < durable.claimed_at || database_now >= durable.expires_at {
            return Err(LogicalMaterializationStoreError::ClaimRejected);
        }
        let expires_at = database_now
            .checked_add(request.duration_ms())
            .filter(|expires_at| *expires_at > durable.expires_at)
            .ok_or(LogicalMaterializationStoreError::ClaimRejected)?;

        let rows = sqlx::query(
            r"
            UPDATE logical_workflow_materialization_claims
            SET generation = $6,
                claimed_at_ms = $7,
                expires_at_ms = $8,
                updated_at_ms = $7
            WHERE instance_id = $1
              AND run_id = $2
              AND invocation_id = $3
              AND logical_job_id = $4
              AND state = 'materializing'
              AND generation = $5
              AND owner_id = $9
              AND descriptor_digest = $10
              AND claimed_at_ms = $11
              AND expires_at_ms = $12
              AND origin_selection_id IS NOT DISTINCT FROM $13
            ",
        )
        .bind(request.claim().target().instance_id().as_uuid())
        .bind(request.claim().target().run_id().as_uuid())
        .bind(request.claim().target().invocation_id().as_uuid())
        .bind(request.claim().target().logical_job_id().as_uuid())
        .bind(pg_bigint(request.claim().generation().get()))
        .bind(next_generation)
        .bind(database_now)
        .bind(expires_at)
        .bind(request.claim().owner().as_uuid())
        .bind(request.claim().descriptor_digest().as_bytes().as_slice())
        .bind(request.claim().claimed_at().get())
        .bind(request.claim().expires_at().get())
        .bind(selection_id.as_uuid())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?
        .rows_affected();
        if rows != 1 {
            return Err(LogicalMaterializationStoreError::ClaimRejected);
        }
        let validated_at = insert_materialization_renewal_receipt(
            &mut transaction,
            &request,
            next_generation,
            database_now,
            expires_at,
            selection_id.as_uuid(),
        )
        .await?;
        let acknowledgement = RenewedLogicalInstanceMaterialization::new(
            request,
            LogicalMaterializationGeneration::new(
                u64::try_from(next_generation)
                    .map_err(|_| LogicalMaterializationStoreError::GenerationExhausted)?,
            )
            .map_err(|_| LogicalMaterializationStoreError::GenerationExhausted)?,
            UnixMillis::new(database_now),
            UnixMillis::new(expires_at),
            UnixMillis::new(validated_at),
        )
        .map_err(|_| StoreError::corrupt_data("invalid materialization renewal receipt"))?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(acknowledgement)
    }

    async fn commit_logical_instance_materialization(
        &self,
        request: CommitLogicalInstanceMaterialization,
    ) -> Result<LogicalMaterializationReceipt, LogicalMaterializationStoreError> {
        let mut transaction = begin_materialization_transaction(&self.pool).await?;
        lock_materialization_continuation_custody(&mut transaction, request.claim()).await?;
        let run_state = lock_run(&mut transaction, request.claim().target())
            .await?
            .ok_or(LogicalMaterializationStoreError::InvalidTarget)?;
        let row = lock_fresh_target(&mut transaction, request.claim().target())
            .await?
            .ok_or(LogicalMaterializationStoreError::InvalidTarget)?;
        let descriptor = decode_descriptor(request.claim().target().clone(), &row)?;
        if request.authority_profile() != descriptor.authority_profile() {
            return Err(LogicalMaterializationStoreError::CommitConflict);
        }
        let requested_log_visibility =
            decode_requested_log_visibility(&row, "requested_log_visibility")?;
        let attempt_safety = CurrentAttemptOutputSafety::for_authority_profile(
            request.authority_profile(),
            &requested_log_visibility,
        )
        .ok_or_else(|| {
            StoreError::corrupt_data("workflow run log publication snapshot is malformed")
        })?;
        let durable = DurableMaterializationClaim::decode(&row)?
            .ok_or(LogicalMaterializationStoreError::ClaimRejected)?;
        durable.verify_descriptor(&descriptor)?;

        if durable.state == "materialized" {
            verify_exact_materialized_commit(&mut transaction, &request, &descriptor, &durable)
                .await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(LogicalMaterializationReceipt::new(&request, true));
        }
        if !run_state.is_active() {
            return Err(LogicalMaterializationStoreError::ClaimRejected);
        }
        if !durable.matches_fence(request.claim())
            || request.committed_at().get() < durable.claimed_at
            || request.committed_at().get() >= durable.expires_at
        {
            return Err(LogicalMaterializationStoreError::ClaimRejected);
        }
        let database_now: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT",
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if database_now < durable.claimed_at || database_now >= durable.expires_at {
            return Err(LogicalMaterializationStoreError::ClaimRejected);
        }

        insert_job(&mut transaction, &request, &descriptor).await?;
        insert_initial_attempt(&mut transaction, &request, attempt_safety).await?;
        insert_materialization_receipt(&mut transaction, &request, &descriptor).await?;
        insert_github_job_check_subject(
            &mut transaction,
            request.claim().expected_job_id(),
            request.claim().expected_attempt_id(),
            request.committed_at(),
        )
        .await
        .map_err(GithubJobCheckInsertError::into_store_error)?;
        let rows = sqlx::query(
            r"
            UPDATE logical_workflow_materialization_claims
            SET state = 'materialized', updated_at_ms = $9
            WHERE instance_id = $1
              AND run_id = $2
              AND invocation_id = $3
              AND logical_job_id = $4
              AND state = 'materializing'
              AND owner_id = $5
              AND generation = $6
              AND claimed_at_ms = $7
              AND expires_at_ms = $8
            ",
        )
        .bind(request.claim().target().instance_id().as_uuid())
        .bind(request.claim().target().run_id().as_uuid())
        .bind(request.claim().target().invocation_id().as_uuid())
        .bind(request.claim().target().logical_job_id().as_uuid())
        .bind(request.claim().owner().as_uuid())
        .bind(pg_bigint(request.claim().generation().get()))
        .bind(request.claim().claimed_at().get())
        .bind(request.claim().expires_at().get())
        .bind(request.committed_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?
        .rows_affected();
        if rows != 1 {
            return Err(StoreError::corrupt_data(
                "locked logical materialization claim disappeared during commit",
            )
            .into());
        }
        transaction.commit().await.map_err(operation_error)?;
        Ok(LogicalMaterializationReceipt::new(&request, false))
    }
}

async fn lock_materialization_selection_custody(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &LogicalMaterializationClaimFence,
) -> Result<(), LogicalMaterializationStoreError> {
    let outcome = lock_materialization_selection_evidence(transaction, claim).await?;
    if outcome != "claimed" {
        return Err(LogicalMaterializationStoreError::ClaimRejected);
    }
    Ok(())
}

async fn lock_materialization_renewal_selection_custody(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &LogicalMaterializationClaimFence,
) -> Result<bool, LogicalMaterializationStoreError> {
    match lock_materialization_selection_evidence(transaction, claim)
        .await?
        .as_str()
    {
        "claimed" => Ok(true),
        "quarantined" => Ok(false),
        _ => Err(LogicalMaterializationStoreError::ClaimRejected),
    }
}

async fn lock_materialization_selection_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &LogicalMaterializationClaimFence,
) -> Result<String, LogicalMaterializationStoreError> {
    let selection_id = claim.selection_origin();
    let row = sqlx::query(
        r"
        SELECT outcome,
               COALESCE(owner_id = $2
               AND tenant_id = $3
               AND run_id = $4
               AND invocation_id = $5
               AND logical_job_id = $6
               AND instance_id = $7
               AND authority_digest = $8, FALSE) AS exact
        FROM logical_workflow_materialization_work_selections
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
    .bind(claim.target().instance_id().as_uuid())
    .bind(claim.descriptor_digest().as_bytes().as_slice())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let row = row.ok_or(LogicalMaterializationStoreError::ClaimRejected)?;
    let exact: bool = row.try_get("exact").map_err(operation_error)?;
    if !exact {
        return Err(LogicalMaterializationStoreError::ClaimRejected);
    }
    let outcome: String = row.try_get("outcome").map_err(operation_error)?;
    let horizon: Option<String> = sqlx::query_scalar(
        r"
        SELECT queue_name
        FROM logical_workflow_work_selection_replay_horizons
        WHERE queue_name = 'materialization'
        FOR UPDATE
        ",
    )
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if horizon.as_deref() != Some("materialization") {
        return Err(
            StoreError::corrupt_data("materialization selection replay horizon is absent").into(),
        );
    }
    Ok(outcome)
}

async fn lock_materialization_quarantine_custody(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &LogicalMaterializationClaimFence,
) -> Result<(), LogicalMaterializationStoreError> {
    let quarantine: Option<Uuid> = sqlx::query_scalar(
        r"
        SELECT instance_id
        FROM logical_workflow_materialization_work_quarantines
        WHERE instance_id = $1
        FOR UPDATE
        ",
    )
    .bind(claim.target().instance_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if quarantine.is_some() {
        return Err(LogicalMaterializationStoreError::ClaimRejected);
    }
    Ok(())
}

async fn lock_materialization_continuation_custody(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &LogicalMaterializationClaimFence,
) -> Result<(), LogicalMaterializationStoreError> {
    lock_materialization_selection_custody(transaction, claim).await?;
    lock_materialization_quarantine_custody(transaction, claim).await
}

async fn load_exact_materialization_renewal_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RenewLogicalInstanceMaterialization,
) -> Result<Option<(i64, i64, i64, i64)>, LogicalMaterializationStoreError> {
    let selection_id = request.claim().selection_origin();
    let row = sqlx::query(
        r"
        SELECT successor_generation, successor_claimed_at_ms,
               successor_expires_at_ms, validated_at_ms
        FROM logical_workflow_materialization_renewal_receipts
        WHERE instance_id = $1
          AND predecessor_generation = $2
          AND selection_id = $3
          AND tenant_id = $4
          AND run_id = $5
          AND invocation_id = $6
          AND logical_job_id = $7
          AND owner_id = $8
          AND runtime_policy_revision = $9
          AND runtime_policy_digest = $10
          AND authority_digest = $11
          AND expected_job_id = $12
          AND expected_attempt_id = $13
          AND predecessor_claimed_at_ms = $14
          AND predecessor_expires_at_ms = $15
          AND requested_duration_ms = $16
        FOR UPDATE
        ",
    )
    .bind(request.claim().target().instance_id().as_uuid())
    .bind(pg_bigint(request.claim().generation().get()))
    .bind(selection_id.as_uuid())
    .bind(request.claim().target().tenant().as_str())
    .bind(request.claim().target().run_id().as_uuid())
    .bind(request.claim().target().invocation_id().as_uuid())
    .bind(request.claim().target().logical_job_id().as_uuid())
    .bind(request.claim().owner().as_uuid())
    .bind(pg_bigint(request.claim().runtime_policy().revision().get()))
    .bind(
        request
            .claim()
            .runtime_policy()
            .digest()
            .as_bytes()
            .as_slice(),
    )
    .bind(request.claim().descriptor_digest().as_bytes().as_slice())
    .bind(request.claim().expected_job_id().as_uuid())
    .bind(request.claim().expected_attempt_id().as_uuid())
    .bind(request.claim().claimed_at().get())
    .bind(request.claim().expires_at().get())
    .bind(request.duration_ms())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    row.map(|row| {
        Ok((
            row.try_get("successor_generation")
                .map_err(operation_error)?,
            row.try_get("successor_claimed_at_ms")
                .map_err(operation_error)?,
            row.try_get("successor_expires_at_ms")
                .map_err(operation_error)?,
            row.try_get("validated_at_ms").map_err(operation_error)?,
        ))
    })
    .transpose()
}

#[allow(clippy::too_many_lines)] // One bounded proof follows the complete immutable renewal chain.
async fn verify_selected_materialization_renewal_lineage(
    transaction: &mut Transaction<'_, Postgres>,
    selected: &SelectedLogicalInstanceMaterialization,
    durable: &DurableMaterializationClaim,
) -> Result<(), LogicalMaterializationStoreError> {
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
            return Err(LogicalMaterializationStoreError::ClaimRejected);
        }
        let edge = sqlx::query(
            r"
            SELECT successor_generation, successor_claimed_at_ms,
                   successor_expires_at_ms
            FROM logical_workflow_materialization_renewal_receipts
            WHERE instance_id = $1
              AND predecessor_generation = $2
              AND selection_id = $3
              AND tenant_id = $4
              AND run_id = $5
              AND invocation_id = $6
              AND logical_job_id = $7
              AND owner_id = $8
              AND runtime_policy_revision = $9
              AND runtime_policy_digest = $10
              AND authority_digest = $11
              AND expected_job_id = $12
              AND expected_attempt_id = $13
              AND predecessor_claimed_at_ms = $14
              AND predecessor_expires_at_ms = $15
            FOR UPDATE
            ",
        )
        .bind(selected.target().instance_id().as_uuid())
        .bind(generation)
        .bind(selection_id.as_uuid())
        .bind(selected.target().tenant().as_str())
        .bind(selected.target().run_id().as_uuid())
        .bind(selected.target().invocation_id().as_uuid())
        .bind(selected.target().logical_job_id().as_uuid())
        .bind(selected.owner().as_uuid())
        .bind(pg_bigint(durable.runtime_policy_revision.get()))
        .bind(durable.runtime_policy_digest.as_bytes().as_slice())
        .bind(selected.authority_digest().as_bytes().as_slice())
        .bind(durable.expected_job_id.as_uuid())
        .bind(durable.expected_attempt_id.as_uuid())
        .bind(claimed_at)
        .bind(expires_at)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?
        .ok_or(LogicalMaterializationStoreError::ClaimRejected)?;
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
                "logical materialization renewal receipt chain is invalid",
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
        return Err(LogicalMaterializationStoreError::ClaimRejected);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert_materialization_renewal_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RenewLogicalInstanceMaterialization,
    successor_generation: i64,
    successor_claimed_at: i64,
    successor_expires_at: i64,
    selection_id: Uuid,
) -> Result<i64, LogicalMaterializationStoreError> {
    sqlx::query_scalar(
        r"
        INSERT INTO logical_workflow_materialization_renewal_receipts (
            instance_id, selection_id, tenant_id, run_id, invocation_id,
            logical_job_id, owner_id, runtime_policy_revision,
            runtime_policy_digest, authority_digest, expected_job_id,
            expected_attempt_id, predecessor_generation,
            predecessor_claimed_at_ms, predecessor_expires_at_ms,
            requested_duration_ms, successor_generation,
            successor_claimed_at_ms, successor_expires_at_ms, validated_at_ms
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            $11, $12, $13, $14, $15, $16, $17, $18, $19, $18
        )
        RETURNING validated_at_ms
        ",
    )
    .bind(request.claim().target().instance_id().as_uuid())
    .bind(selection_id)
    .bind(request.claim().target().tenant().as_str())
    .bind(request.claim().target().run_id().as_uuid())
    .bind(request.claim().target().invocation_id().as_uuid())
    .bind(request.claim().target().logical_job_id().as_uuid())
    .bind(request.claim().owner().as_uuid())
    .bind(pg_bigint(request.claim().runtime_policy().revision().get()))
    .bind(
        request
            .claim()
            .runtime_policy()
            .digest()
            .as_bytes()
            .as_slice(),
    )
    .bind(request.claim().descriptor_digest().as_bytes().as_slice())
    .bind(request.claim().expected_job_id().as_uuid())
    .bind(request.claim().expected_attempt_id().as_uuid())
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

pub(super) async fn claim_logical_instance_materialization_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimLogicalInstanceMaterialization,
    origin_selection_id: Uuid,
) -> Result<LogicalInstanceMaterializationClaimOutcome, LogicalMaterializationStoreError> {
    let run_state = lock_run(transaction, request.target())
        .await?
        .ok_or(LogicalMaterializationStoreError::InvalidTarget)?;
    let row = lock_fresh_target(transaction, request.target())
        .await?
        .ok_or(LogicalMaterializationStoreError::InvalidTarget)?;
    reject_quarantined_materialization(transaction, request.target().instance_id()).await?;
    let descriptor = decode_descriptor(request.target().clone(), &row)?;
    let durable = DurableMaterializationClaim::decode(&row)?;

    if let Some(durable) = durable {
        if !durable.is_materialized() && !run_state.is_active() {
            return Err(LogicalMaterializationStoreError::InvalidTarget);
        }
        return resolve_durable_claim(
            transaction,
            request,
            descriptor,
            durable,
            origin_selection_id,
        )
        .await;
    }
    if !run_state.is_active() {
        return Err(LogicalMaterializationStoreError::InvalidTarget);
    }

    let inserted = sqlx::query(
        r"
        INSERT INTO logical_workflow_materialization_claims (
            instance_id, run_id, invocation_id, logical_job_id,
            descriptor_digest, expected_job_id, expected_attempt_id,
            authority_profile, state, owner_id, generation, claimed_at_ms, expires_at_ms,
            runtime_policy_revision, runtime_policy_digest,
            created_at_ms, updated_at_ms, origin_selection_id
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'materializing',$9,1,$10,$11,$12,$13,$10,$10,$14)
        ON CONFLICT (instance_id) DO NOTHING
        ",
    )
    .bind(request.target().instance_id().as_uuid())
    .bind(request.target().run_id().as_uuid())
    .bind(request.target().invocation_id().as_uuid())
    .bind(request.target().logical_job_id().as_uuid())
    .bind(descriptor.descriptor_digest().as_bytes().as_slice())
    .bind(descriptor.expected_job_id().as_uuid())
    .bind(descriptor.expected_attempt_id().as_uuid())
    .bind(authority_profile_name(descriptor.authority_profile()))
    .bind(request.owner().as_uuid())
    .bind(request.observed_at().get())
    .bind(request.expires_at().get())
    .bind(pg_bigint(descriptor.runtime_policy().revision().get()))
    .bind(descriptor.runtime_policy().digest().as_bytes().as_slice())
    .bind(origin_selection_id)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if inserted == 0 {
        let row = lock_fresh_target(transaction, request.target())
            .await?
            .ok_or(LogicalMaterializationStoreError::InvalidTarget)?;
        let descriptor = decode_descriptor(request.target().clone(), &row)?;
        let durable = DurableMaterializationClaim::decode(&row)?.ok_or_else(|| {
            StoreError::corrupt_data("logical materialization claim conflict has no durable owner")
        })?;
        return resolve_durable_claim(
            transaction,
            request,
            descriptor,
            durable,
            origin_selection_id,
        )
        .await;
    }
    if inserted != 1 {
        return Err(StoreError::corrupt_data(
            "logical materialization claim inserted an invalid row count",
        )
        .into());
    }
    let claim = make_fence(
        request.target().clone(),
        request.owner(),
        1,
        &descriptor,
        request.observed_at(),
        request.expires_at(),
        origin_selection_id,
    )?;
    let claimed = ClaimedLogicalInstanceMaterialization::new(descriptor, claim, false)
        .map_err(corrupt_value)?;
    Ok(LogicalInstanceMaterializationClaimOutcome::Claimed(claimed))
}

pub(super) async fn consume_selected_materialization_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    selected: &SelectedLogicalInstanceMaterialization,
) -> Result<Option<ClaimedLogicalInstanceMaterialization>, LogicalMaterializationStoreError> {
    let row = lock_fresh_target(transaction, selected.target()).await?;
    let Some(row) = row else {
        return Ok(None);
    };
    reject_quarantined_materialization(transaction, selected.target().instance_id()).await?;
    let descriptor = decode_descriptor(selected.target().clone(), &row)?;
    let Some(durable) = DurableMaterializationClaim::decode(&row)? else {
        return Ok(None);
    };
    if durable.state != "materializing"
        || durable.origin_selection_id != Some(selected.selection_id().as_uuid())
        || durable.owner_id != selected.owner().as_uuid()
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
    durable.verify_descriptor(&descriptor)?;
    verify_selected_materialization_renewal_lineage(transaction, selected, &durable).await?;
    claimed_from_durable(descriptor, &durable, true).map(Some)
}

async fn begin_materialization_transaction(
    pool: &PgPool,
) -> Result<Transaction<'_, Postgres>, LogicalMaterializationStoreError> {
    let mut transaction = pool.begin().await.map_err(operation_error)?;
    // Run cancellation and materialization deliberately wait on one another's
    // workflow-run row lock. Pin READ COMMITTED so a waiter decodes the
    // predecessor's committed row version and later statements stay fresh.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
    Ok(transaction)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LockedRunState {
    Active,
    Inactive,
}

impl LockedRunState {
    const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    fn decode(row: &PgRow) -> Result<Self, LogicalMaterializationStoreError> {
        let status: String = row.try_get("status").map_err(operation_error)?;
        match status.as_str() {
            "queued" | "in_progress" => Ok(Self::Active),
            "completed" | "cancelled" => Ok(Self::Inactive),
            _ => Err(StoreError::corrupt_data(
                "logical materialization workflow-run status is unknown",
            )
            .into()),
        }
    }
}

async fn lock_run(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalInstanceMaterializationTarget,
) -> Result<Option<LockedRunState>, LogicalMaterializationStoreError> {
    let schemas = current_durable_schemas();
    let row = sqlx::query(
        r"
        SELECT run.status
        FROM workflow_runs AS run
        JOIN repositories AS repository ON repository.id = run.repository_id
        WHERE repository.tenant_id = $1
          AND run.id = $2
        FOR SHARE OF run
        ",
    )
    .bind(target.tenant().as_str())
    .bind(target.run_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let state = LockedRunState::decode(&row)?;
    if !state.is_active() {
        return Ok(Some(state));
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
        return Ok(Some(LockedRunState::Inactive));
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
    Ok(Some(if invocation_active == Some(true) {
        LockedRunState::Active
    } else {
        LockedRunState::Inactive
    }))
}

async fn resolve_durable_claim(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimLogicalInstanceMaterialization,
    descriptor: LogicalInstanceMaterializationDescriptor,
    durable: DurableMaterializationClaim,
    origin_selection_id: Uuid,
) -> Result<LogicalInstanceMaterializationClaimOutcome, LogicalMaterializationStoreError> {
    durable.verify_descriptor(&descriptor)?;
    let origin_mismatch = durable.origin_selection_id != Some(origin_selection_id);
    if durable.state == "materialized" {
        if origin_mismatch {
            return Err(LogicalMaterializationStoreError::ClaimRejected);
        }
        let receipt = load_materialized_receipt(
            transaction,
            request.target().instance_id(),
            &descriptor,
            &durable,
            true,
        )
        .await?;
        return Ok(LogicalInstanceMaterializationClaimOutcome::Materialized(
            receipt,
        ));
    }
    if !origin_mismatch && durable.is_exact_replay(request) {
        return claimed_from_durable(descriptor, &durable, true)
            .map(LogicalInstanceMaterializationClaimOutcome::Claimed);
    }
    if durable.expires_at > request.observed_at().get() {
        return Ok(LogicalInstanceMaterializationClaimOutcome::Busy);
    }
    let next_generation = durable
        .generation
        .checked_add(1)
        .filter(|value| *value > 0)
        .ok_or(LogicalMaterializationStoreError::GenerationExhausted)?;
    let rows = sqlx::query(
        r"
        UPDATE logical_workflow_materialization_claims
        SET owner_id = $6,
            generation = $7,
            claimed_at_ms = $8,
            expires_at_ms = $9,
            origin_selection_id = $10,
            updated_at_ms = $8
        WHERE instance_id = $1
          AND run_id = $2
          AND invocation_id = $3
          AND logical_job_id = $4
          AND state = 'materializing'
          AND generation = $5
        ",
    )
    .bind(request.target().instance_id().as_uuid())
    .bind(request.target().run_id().as_uuid())
    .bind(request.target().invocation_id().as_uuid())
    .bind(request.target().logical_job_id().as_uuid())
    .bind(durable.generation)
    .bind(request.owner().as_uuid())
    .bind(next_generation)
    .bind(request.observed_at().get())
    .bind(request.expires_at().get())
    .bind(origin_selection_id)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if rows != 1 {
        return Err(StoreError::corrupt_data(
            "locked logical materialization claim disappeared during takeover",
        )
        .into());
    }
    let claim = make_fence(
        request.target().clone(),
        request.owner(),
        next_generation,
        &descriptor,
        request.observed_at(),
        request.expires_at(),
        origin_selection_id,
    )?;
    let claimed = ClaimedLogicalInstanceMaterialization::new(descriptor, claim, false)
        .map_err(corrupt_value)?;
    Ok(LogicalInstanceMaterializationClaimOutcome::Claimed(claimed))
}

async fn reject_quarantined_materialization(
    transaction: &mut Transaction<'_, Postgres>,
    instance_id: LogicalWorkflowInstanceId,
) -> Result<(), LogicalMaterializationStoreError> {
    let quarantined: bool = sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM logical_workflow_materialization_work_quarantines
            WHERE instance_id = $1
        )
        ",
    )
    .bind(instance_id.as_uuid())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if quarantined {
        Err(LogicalMaterializationStoreError::ClaimRejected)
    } else {
        Ok(())
    }
}

async fn lock_instance(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalInstanceMaterializationTarget,
) -> Result<Option<PgRow>, LogicalMaterializationStoreError> {
    let schemas = current_durable_schemas();
    sqlx::query(instance_query())
        .bind(target.tenant().as_str())
        .bind(target.run_id().as_uuid())
        .bind(target.invocation_id().as_uuid())
        .bind(target.logical_job_id().as_uuid())
        .bind(target.instance_id().as_uuid())
        .bind(schemas.job_ir_i16)
        .bind(schemas.runtime_context_i16)
        .bind(schemas.workflow_plan_i16)
        .bind(schemas.logical_orchestration_i16)
        .bind(schemas.workflow_plan_i32)
        .bind(LOGICAL_ACTIVATION_JOB_IR_MEDIA_TYPE)
        .bind(LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE)
        .bind(schemas.admission_epoch_i32)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)
}

async fn lock_claim_target(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalInstanceMaterializationTarget,
) -> Result<Option<PgRow>, LogicalMaterializationStoreError> {
    if let Some(row) = lock_instance(transaction, target).await? {
        return Ok(Some(row));
    }
    lock_terminal_materialized_instance(transaction, target).await
}

async fn lock_terminal_materialized_instance(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalInstanceMaterializationTarget,
) -> Result<Option<PgRow>, LogicalMaterializationStoreError> {
    let schemas = current_durable_schemas();
    let row = sqlx::query(TERMINAL_MATERIALIZED_INSTANCE_QUERY)
        .bind(target.tenant().as_str())
        .bind(target.run_id().as_uuid())
        .bind(target.invocation_id().as_uuid())
        .bind(target.logical_job_id().as_uuid())
        .bind(target.instance_id().as_uuid())
        .bind(schemas.job_ir_i16)
        .bind(schemas.runtime_context_i16)
        .bind(schemas.workflow_plan_i16)
        .bind(schemas.logical_orchestration_i16)
        .bind(schemas.workflow_plan_i32)
        .bind(schemas.job_ir_i32)
        .bind(schemas.core_i32)
        .bind(LOGICAL_ACTIVATION_JOB_IR_MEDIA_TYPE)
        .bind(LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE)
        .bind(schemas.admission_epoch_i32)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?;
    if let Some(row) = row {
        verify_terminal_materialized_graph(transaction, target).await?;
        return Ok(Some(row));
    }
    if terminal_materialized_base_exists(transaction, target).await? {
        return Err(StoreError::corrupt_data(
            "materialized logical target has malformed terminal aggregate evidence",
        )
        .into());
    }
    Ok(None)
}

async fn terminal_materialized_base_exists(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalInstanceMaterializationTarget,
) -> Result<bool, LogicalMaterializationStoreError> {
    sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM logical_workflow_instances AS instance
            JOIN logical_workflow_jobs AS logical_job
              ON logical_job.run_id = instance.run_id
             AND logical_job.invocation_id = instance.invocation_id
             AND logical_job.id = instance.logical_job_id
            JOIN logical_workflow_runs AS marker ON marker.run_id = instance.run_id
            JOIN workflow_runs AS run ON run.id = marker.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            JOIN logical_workflow_materialization_claims AS claim
              ON claim.instance_id = instance.id
            WHERE repository.tenant_id = $1
              AND instance.run_id = $2
              AND instance.invocation_id = $3
              AND instance.logical_job_id = $4
              AND instance.id = $5
              AND claim.state = 'materialized'
        )
        ",
    )
    .bind(target.tenant().as_str())
    .bind(target.run_id().as_uuid())
    .bind(target.invocation_id().as_uuid())
    .bind(target.logical_job_id().as_uuid())
    .bind(target.instance_id().as_uuid())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn lock_fresh_target(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalInstanceMaterializationTarget,
) -> Result<Option<PgRow>, LogicalMaterializationStoreError> {
    let row = lock_claim_target(transaction, target).await?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row
        .try_get::<Option<i64>, _>("materialization_generation")
        .map_err(operation_error)?
        .is_some()
    {
        sqlx::query(
            "SELECT instance_id FROM logical_workflow_materialization_claims WHERE instance_id = $1 FOR UPDATE",
        )
        .bind(target.instance_id().as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?
        .ok_or_else(|| StoreError::corrupt_data("materialization claim disappeared while locking"))?;
    }
    // A concurrent commit may have held the immutable instance row while the
    // first statement acquired its READ COMMITTED snapshot. Re-read in a new
    // statement after owning that row lock so claim/receipt state is current.
    lock_claim_target(transaction, target).await
}

#[allow(clippy::too_many_lines)] // Keep the complete immutable instance projection auditable.
fn instance_query() -> &'static str {
    r"
    SELECT instance.matrix_index, instance.matrix_total,
           instance.matrix_digest, instance.workspace,
           instance.runtime_policy_revision, instance.runtime_policy_digest,
           instance.job_ir_digest, instance.job_ir_object_key,
           instance.job_ir_size_bytes, instance.job_ir_media_type,
           instance.job_ir_version,
           instance.runtime_context_digest,
           instance.runtime_context_object_key,
           instance.runtime_context_size_bytes,
           instance.runtime_context_media_type,
           instance.runtime_context_schema,
           publication.authority_profile,
           logical_job.logical_key,
           repository.id AS runtime_policy_repository_id,
           run.workflow_id, run.workflow_name, run.git_ref, run.event_name,
           run.actor,
           run.triggering_actor,
           run.public_run_id_alias AS run_id_alias,
           run.run_number, run.run_attempt,
           run.requested_log_visibility,
           run.event_digest, run.event_object_key, run.event_size_bytes,
           run.event_media_type,
           claim.run_id AS materialization_run_id,
           claim.invocation_id AS materialization_invocation_id,
           claim.logical_job_id AS materialization_logical_job_id,
           claim.state AS materialization_state,
           claim.descriptor_digest AS materialization_descriptor_digest,
           claim.authority_profile AS materialization_authority_profile,
           claim.runtime_policy_revision AS materialization_runtime_policy_revision,
           claim.runtime_policy_digest AS materialization_runtime_policy_digest,
           claim.expected_job_id, claim.expected_attempt_id,
           claim.owner_id AS materialization_owner_id,
           claim.generation AS materialization_generation,
           claim.claimed_at_ms AS materialization_claimed_at_ms,
           claim.expires_at_ms AS materialization_expires_at_ms,
           claim.created_at_ms AS materialization_created_at_ms,
           claim.updated_at_ms AS materialization_updated_at_ms,
           claim.origin_selection_id AS materialization_origin_selection_id
    FROM logical_workflow_instances AS instance
    JOIN logical_workflow_activation_publications AS publication
      ON publication.run_id = instance.run_id
     AND publication.invocation_id = instance.invocation_id
     AND publication.logical_job_id = instance.logical_job_id
    JOIN logical_workflow_jobs AS logical_job
      ON logical_job.run_id = instance.run_id
     AND logical_job.invocation_id = instance.invocation_id
     AND logical_job.id = instance.logical_job_id
    JOIN logical_workflow_invocations AS invocation
      ON invocation.run_id = logical_job.run_id
     AND invocation.id = logical_job.invocation_id
    JOIN logical_workflow_runs AS marker ON marker.run_id = instance.run_id
    JOIN workflow_runs AS run ON run.id = marker.run_id
    JOIN repositories AS repository ON repository.id = run.repository_id
    LEFT JOIN logical_workflow_materialization_claims AS claim
      ON claim.instance_id = instance.id
     AND claim.run_id = instance.run_id
     AND claim.invocation_id = instance.invocation_id
     AND claim.logical_job_id = instance.logical_job_id
    WHERE repository.tenant_id = $1
      AND instance.run_id = $2
      AND instance.invocation_id = $3
      AND instance.logical_job_id = $4
      AND instance.id = $5
      AND instance.job_ir_version = $6
      AND instance.job_ir_media_type = $11
      AND instance.runtime_context_schema = $7
      AND instance.runtime_context_media_type = $12
      AND publication.condition_matched
      AND publication.instance_count > 0
      AND logical_job.execution_kind = 'steps'
      AND invocation.plan_schema = $8
      AND marker.orchestration_schema = $9
      AND (
          (
              logical_job.state = 'activated'
              AND invocation.state IN ('pending', 'active')
              AND marker.state IN ('pending', 'active')
          ) OR (
              logical_job.state = 'cancelled'
              AND invocation.state = 'cancelled'
              AND marker.state = 'cancelled'
              AND run.status = 'cancelled'
              AND EXISTS (
                  SELECT 1
                  FROM logical_workflow_concurrency_cancellations AS cancellation
                  WHERE cancellation.run_id = run.id
                    AND cancellation.root_invocation_id = invocation.id
                    AND cancellation.cancelled_at_ms = logical_job.updated_at_ms
                    AND cancellation.cancelled_at_ms = invocation.updated_at_ms
                    AND cancellation.cancelled_at_ms = marker.updated_at_ms
                    AND cancellation.cancelled_at_ms = run.updated_at_ms
              )
          )
      )
      AND run.admission_epoch = $13
      AND run.plan_schema = $10
    FOR UPDATE OF instance
    "
}

const TERMINAL_MATERIALIZED_INSTANCE_QUERY: &str = r"
    SELECT instance.matrix_index, instance.matrix_total,
           instance.matrix_digest, instance.workspace,
           instance.runtime_policy_revision, instance.runtime_policy_digest,
           instance.job_ir_digest, instance.job_ir_object_key,
           instance.job_ir_size_bytes, instance.job_ir_media_type,
           instance.job_ir_version,
           instance.runtime_context_digest,
           instance.runtime_context_object_key,
           instance.runtime_context_size_bytes,
           instance.runtime_context_media_type,
           instance.runtime_context_schema,
           publication.authority_profile,
           logical_job.logical_key,
           repository.id AS runtime_policy_repository_id,
           run.workflow_id, run.workflow_name, run.git_ref, run.event_name,
           run.actor,
           run.triggering_actor,
           run.public_run_id_alias AS run_id_alias,
           run.run_number, run.run_attempt,
           run.requested_log_visibility,
           run.event_digest, run.event_object_key, run.event_size_bytes,
           run.event_media_type,
           claim.run_id AS materialization_run_id,
           claim.invocation_id AS materialization_invocation_id,
           claim.logical_job_id AS materialization_logical_job_id,
           claim.state AS materialization_state,
           claim.descriptor_digest AS materialization_descriptor_digest,
           claim.authority_profile AS materialization_authority_profile,
           claim.runtime_policy_revision AS materialization_runtime_policy_revision,
           claim.runtime_policy_digest AS materialization_runtime_policy_digest,
           claim.expected_job_id, claim.expected_attempt_id,
           claim.owner_id AS materialization_owner_id,
           claim.generation AS materialization_generation,
           claim.claimed_at_ms AS materialization_claimed_at_ms,
           claim.expires_at_ms AS materialization_expires_at_ms,
           claim.created_at_ms AS materialization_created_at_ms,
           claim.updated_at_ms AS materialization_updated_at_ms,
           claim.origin_selection_id AS materialization_origin_selection_id
    FROM logical_workflow_instances AS instance
    JOIN logical_workflow_activation_publications AS publication
      ON publication.run_id = instance.run_id
     AND publication.invocation_id = instance.invocation_id
     AND publication.logical_job_id = instance.logical_job_id
    JOIN logical_workflow_jobs AS logical_job
      ON logical_job.run_id = instance.run_id
     AND logical_job.invocation_id = instance.invocation_id
     AND logical_job.id = instance.logical_job_id
    JOIN logical_workflow_invocations AS invocation
      ON invocation.run_id = logical_job.run_id
     AND invocation.id = logical_job.invocation_id
    JOIN logical_workflow_runs AS marker ON marker.run_id = instance.run_id
    JOIN workflow_runs AS run ON run.id = marker.run_id
    JOIN repositories AS repository ON repository.id = run.repository_id
    JOIN logical_workflow_materialization_claims AS claim
      ON claim.instance_id = instance.id
     AND claim.run_id = instance.run_id
     AND claim.invocation_id = instance.invocation_id
     AND claim.logical_job_id = instance.logical_job_id
    JOIN logical_workflow_concrete_jobs AS concrete
      ON concrete.instance_id = claim.instance_id
     AND concrete.run_id = claim.run_id
     AND concrete.invocation_id = claim.invocation_id
     AND concrete.logical_job_id = claim.logical_job_id
    JOIN jobs AS job ON job.id = concrete.job_id
    JOIN job_attempts AS attempt ON attempt.id = concrete.initial_attempt_id
    JOIN attempt_terminal_results AS terminal
      ON terminal.attempt_id = attempt.id
    JOIN logical_workflow_instance_result_claims AS instance_claim
      ON instance_claim.attempt_id = terminal.attempt_id
     AND instance_claim.run_id = concrete.run_id
     AND instance_claim.invocation_id = concrete.invocation_id
     AND instance_claim.logical_job_id = concrete.logical_job_id
     AND instance_claim.instance_id = concrete.instance_id
     AND instance_claim.job_id = concrete.job_id
    JOIN logical_workflow_instance_results AS instance_result
      ON instance_result.instance_id = instance_claim.instance_id
     AND instance_result.run_id = instance_claim.run_id
     AND instance_result.invocation_id = instance_claim.invocation_id
     AND instance_result.logical_job_id = instance_claim.logical_job_id
     AND instance_result.job_id = instance_claim.job_id
     AND instance_result.attempt_id = instance_claim.attempt_id
    JOIN logical_workflow_job_result_claims AS job_claim
      ON job_claim.run_id = logical_job.run_id
     AND job_claim.invocation_id = logical_job.invocation_id
     AND job_claim.logical_job_id = logical_job.id
    JOIN logical_workflow_job_results AS job_result
      ON job_result.run_id = job_claim.run_id
     AND job_result.invocation_id = job_claim.invocation_id
     AND job_result.logical_job_id = job_claim.logical_job_id
    JOIN logical_workflow_job_result_instances AS job_instance
      ON job_instance.logical_job_id = job_result.logical_job_id
     AND job_instance.instance_id = instance_result.instance_id
    LEFT JOIN logical_workflow_run_result_claims AS run_claim
      ON run_claim.run_id = marker.run_id
     AND run_claim.root_invocation_id = marker.root_invocation_id
    LEFT JOIN logical_workflow_run_results AS run_result
      ON run_result.run_id = run_claim.run_id
     AND run_result.root_invocation_id = run_claim.root_invocation_id
    LEFT JOIN logical_workflow_run_result_jobs AS run_job
      ON run_job.run_id = run_result.run_id
     AND run_job.root_invocation_id = run_result.root_invocation_id
     AND run_job.logical_job_id = logical_job.id
    WHERE repository.tenant_id = $1
      AND instance.run_id = $2
      AND instance.invocation_id = $3
      AND instance.logical_job_id = $4
      AND instance.id = $5
      AND instance.job_ir_version = $6
      AND instance.job_ir_media_type = $13
      AND instance.runtime_context_schema = $7
      AND instance.runtime_context_media_type = $14
      AND publication.condition_matched
      AND publication.instance_count > 0
      AND logical_job.execution_kind = 'steps'
      AND invocation.plan_schema = $8
      AND marker.root_invocation_id = invocation.id
      AND marker.orchestration_schema = $9
      AND run.admission_epoch = $15
      AND run.plan_schema = $10
      AND claim.state = 'materialized'
      AND concrete.descriptor_digest = claim.descriptor_digest
      AND concrete.job_id = claim.expected_job_id
      AND concrete.initial_attempt_id = claim.expected_attempt_id
      AND concrete.claim_owner_id = claim.owner_id
      AND concrete.claim_generation = claim.generation
      AND concrete.claim_started_at_ms = claim.claimed_at_ms
      AND concrete.claim_expires_at_ms = claim.expires_at_ms
      AND concrete.committed_at_ms = claim.updated_at_ms
      AND job.run_id = concrete.run_id
      AND job.admission_epoch = $15
      AND job.job_ir_schema = $11
      AND job.job_ir_digest = instance.job_ir_digest
      AND job.job_ir_object_key = instance.job_ir_object_key
      AND job.job_ir_size_bytes = instance.job_ir_size_bytes
      AND attempt.job_id = job.id
      AND attempt.attempt_number = 1
      AND terminal.result_schema = $12
      AND terminal.logical_workflow_logical_job_id = logical_job.id
      AND terminal.logical_workflow_terminal_ordinal > 0
      AND terminal.completed_at_ms >= 0
      AND terminal.committed_at_ms >= terminal.completed_at_ms
      AND (
          (terminal.conclusion = 'success' AND attempt.lifecycle = 'succeeded')
          OR (terminal.conclusion = 'failure' AND attempt.lifecycle = 'failed')
          OR (terminal.conclusion = 'cancelled' AND attempt.lifecycle = 'cancelled')
          OR (terminal.conclusion = 'timed_out' AND attempt.lifecycle = 'timed_out')
          OR (terminal.conclusion = 'skipped' AND attempt.lifecycle = 'skipped')
      )
      AND instance_claim.state = 'finalized'
      AND instance_result.descriptor_digest = instance_claim.descriptor_digest
      AND instance_result.claim_owner_id = instance_claim.owner_id
      AND instance_result.claim_generation = instance_claim.generation
      AND instance_result.claim_started_at_ms = instance_claim.claimed_at_ms
      AND instance_result.claim_expires_at_ms = instance_claim.expires_at_ms
      AND instance_result.finalized_at_ms = instance_claim.updated_at_ms
      AND instance_result.result_digest = terminal.result_digest
      AND instance_result.result_object_key = terminal.result_object_key
      AND instance_result.result_size_bytes = terminal.result_size_bytes
      AND instance_result.result_schema = terminal.result_schema
      AND instance_result.raw_conclusion = terminal.conclusion
      AND instance_result.terminal_ordinal = terminal.logical_workflow_terminal_ordinal
      AND instance_result.result_completed_at_ms = terminal.completed_at_ms
      AND instance_result.result_committed_at_ms = terminal.committed_at_ms
      AND instance_result.job_ir_digest = instance.job_ir_digest
      AND instance_result.job_ir_object_key = instance.job_ir_object_key
      AND instance_result.job_ir_size_bytes = instance.job_ir_size_bytes
      AND instance_result.job_ir_schema = instance.job_ir_version
      AND instance_result.secret_exposure_class = attempt.secret_exposure_class
      AND job_claim.state = 'finalized'
      AND job_result.descriptor_digest = job_claim.descriptor_digest
      AND job_result.claim_owner_id = job_claim.owner_id
      AND job_result.claim_generation = job_claim.generation
      AND job_result.claim_started_at_ms = job_claim.claimed_at_ms
      AND job_result.claim_expires_at_ms = job_claim.expires_at_ms
      AND job_result.finalized_at_ms = job_claim.updated_at_ms
      AND job_result.logical_key = logical_job.logical_key
      AND job_result.source_order = logical_job.source_order
      AND job_result.activation_output_digest = publication.activation_output_digest
      AND job_result.condition_matched = publication.condition_matched
      AND job_result.instance_count = publication.instance_count
      AND job_result.instance_count = (
          SELECT count(*)::INTEGER
          FROM logical_workflow_instances AS expected_instance
          WHERE expected_instance.run_id = logical_job.run_id
            AND expected_instance.invocation_id = logical_job.invocation_id
            AND expected_instance.logical_job_id = logical_job.id
      )
      AND job_result.instance_count = (
          SELECT count(*)::INTEGER
          FROM logical_workflow_job_result_instances AS result_instance
          WHERE result_instance.logical_job_id = logical_job.id
      )
      AND job_instance.matrix_index = instance.matrix_index
      AND job_instance.terminal_ordinal = terminal.logical_workflow_terminal_ordinal
      AND job_instance.instance_descriptor_digest = instance_result.descriptor_digest
      AND job_instance.instance_outputs_digest = instance_result.outputs_digest
      AND job_instance.instance_commit_digest = instance_result.commit_digest
      AND job_instance.raw_conclusion = instance_result.raw_conclusion
      AND job_instance.effective_conclusion = instance_result.effective_conclusion
      AND logical_job.state = CASE job_result.effective_conclusion
          WHEN 'success' THEN 'completed'
          WHEN 'failure' THEN 'failed'
          WHEN 'timed_out' THEN 'failed'
          WHEN 'cancelled' THEN 'cancelled'
          WHEN 'skipped' THEN 'skipped'
      END
      AND logical_job.updated_at_ms = job_result.finalized_at_ms
      AND (
          (
              invocation.state IN ('pending', 'active')
              AND marker.state IN ('pending', 'active')
              AND run.status IN ('queued', 'in_progress', 'cancelled')
          ) OR (
              run_claim.state = 'finalized'
              AND run_result.descriptor_digest = run_claim.descriptor_digest
              AND run_result.claim_owner_id = run_claim.owner_id
              AND run_result.claim_generation = run_claim.generation
              AND run_result.claim_started_at_ms = run_claim.claimed_at_ms
              AND run_result.claim_expires_at_ms = run_claim.expires_at_ms
              AND run_result.finalized_at_ms = run_claim.updated_at_ms
              AND run_result.admission_digest = marker.admission_digest
              AND run_result.job_count = (
                  SELECT count(*)::INTEGER
                  FROM logical_workflow_jobs AS expected_job
                  WHERE expected_job.run_id = marker.run_id
                    AND expected_job.invocation_id = marker.root_invocation_id
              )
              AND run_result.job_count = (
                  SELECT count(*)::INTEGER
                  FROM logical_workflow_run_result_jobs AS result_job
                  WHERE result_job.run_id = marker.run_id
                    AND result_job.root_invocation_id = marker.root_invocation_id
              )
              AND run_job.logical_key = job_result.logical_key
              AND run_job.source_order = job_result.source_order
              AND run_job.descriptor_digest = job_result.descriptor_digest
              AND run_job.effective_conclusion = job_result.effective_conclusion
              AND run_job.closure_has_failure = job_result.closure_has_failure
              AND run_job.closure_has_cancelled = job_result.closure_has_cancelled
              AND run_job.closure_has_skipped = job_result.closure_has_skipped
              AND run_job.instance_count = job_result.instance_count
              AND run_job.instances_digest = job_result.instances_digest
              AND run_job.prerequisite_count = job_result.prerequisite_count
              AND run_job.prerequisites_digest = job_result.prerequisites_digest
              AND run_job.output_count = job_result.output_count
              AND run_job.outputs_digest = job_result.outputs_digest
              AND run_job.job_commit_digest = job_result.commit_digest
              AND run_job.job_finalized_at_ms = job_result.finalized_at_ms
              AND invocation.state = CASE run_result.effective_conclusion
                  WHEN 'success' THEN 'completed'
                  WHEN 'skipped' THEN 'completed'
                  WHEN 'cancelled' THEN 'cancelled'
                  ELSE 'failed'
              END
              AND invocation.revision = run_result.invocation_revision + 1
              AND invocation.updated_at_ms = run_result.finalized_at_ms
              AND marker.state = CASE run_result.effective_conclusion
                  WHEN 'success' THEN 'completed'
                  WHEN 'skipped' THEN 'completed'
                  WHEN 'cancelled' THEN 'cancelled'
                  ELSE 'failed'
              END
              AND marker.revision = run_result.marker_revision + 1
              AND marker.updated_at_ms = run_result.finalized_at_ms
              AND run.status = CASE run_result.effective_conclusion
                  WHEN 'cancelled' THEN 'cancelled'
                  ELSE 'completed'
              END
              AND run.updated_at_ms = run_result.finalized_at_ms
          )
      )
    FOR UPDATE OF instance
    ";

struct ReauthenticatedTerminalJob {
    evidence: LogicalRunJobResultEvidence,
}

async fn verify_terminal_materialized_graph(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalInstanceMaterializationTarget,
) -> Result<(), LogicalMaterializationStoreError> {
    let run_root = load_terminal_run_root(transaction, target).await?;
    let finalized_run = run_root
        .as_ref()
        .is_some_and(|row| row.get::<Option<Uuid>, _>("result_run_id").is_some());
    if run_root
        .as_ref()
        .is_some_and(|row| row.get::<String, _>("run_claim_state") == "finalized" && !finalized_run)
    {
        return Err(StoreError::corrupt_data(
            "finalized logical run claim has no immutable result",
        )
        .into());
    }
    let jobs = reauthenticate_terminal_jobs(transaction, target, finalized_run).await?;
    if !jobs
        .iter()
        .any(|job| job.evidence.logical_job_id() == target.logical_job_id())
    {
        return Err(StoreError::corrupt_data(
            "terminal materialization target is absent from its logical job graph",
        )
        .into());
    }
    if let Some(run_root) = run_root.filter(|_| finalized_run) {
        verify_terminal_run_result(transaction, target, &run_root, &jobs).await?;
    }
    Ok(())
}

async fn load_terminal_run_root(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalInstanceMaterializationTarget,
) -> Result<Option<PgRow>, LogicalMaterializationStoreError> {
    sqlx::query(
        r"
        SELECT claim.state AS run_claim_state,
               claim.root_invocation_id AS claim_root_invocation_id,
               claim.descriptor_digest AS run_claim_descriptor_digest,
               claim.owner_id AS run_claim_owner_id,
               claim.generation AS run_claim_generation,
               claim.claimed_at_ms AS run_claim_claimed_at_ms,
               claim.expires_at_ms AS run_claim_expires_at_ms,
               claim.updated_at_ms AS run_claim_updated_at_ms,
               result.run_id AS result_run_id, result.root_invocation_id,
               result.descriptor_digest, result.admission_digest,
               result.marker_state, result.marker_revision,
               result.marker_updated_at_ms, result.invocation_state,
               result.invocation_revision, result.invocation_updated_at_ms,
               result.workflow_status, result.workflow_updated_at_ms,
               result.job_count, result.evidence_digest,
               result.effective_conclusion, result.commit_digest,
               result.claim_owner_id, result.claim_generation,
               result.claim_started_at_ms, result.claim_expires_at_ms,
               result.finalized_at_ms,
               marker.root_invocation_id AS current_root_invocation_id,
               marker.admission_digest AS current_admission_digest,
               marker.state AS current_marker_state,
               marker.revision AS current_marker_revision,
               marker.updated_at_ms AS current_marker_updated_at_ms,
               invocation.state AS current_invocation_state,
               invocation.revision AS current_invocation_revision,
               invocation.updated_at_ms AS current_invocation_updated_at_ms,
               run.status AS current_workflow_status,
               run.updated_at_ms AS current_workflow_updated_at_ms
        FROM logical_workflow_run_result_claims AS claim
        JOIN logical_workflow_runs AS marker ON marker.run_id = claim.run_id
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = marker.run_id
         AND invocation.id = marker.root_invocation_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        LEFT JOIN logical_workflow_run_results AS result
          ON result.run_id = claim.run_id
        WHERE repository.tenant_id = $1
          AND claim.run_id = $2
        ",
    )
    .bind(target.tenant().as_str())
    .bind(target.run_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

#[allow(clippy::too_many_lines)] // Reauthenticates every immutable terminal edge in one snapshot.
async fn reauthenticate_terminal_jobs(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalInstanceMaterializationTarget,
    require_all: bool,
) -> Result<Vec<ReauthenticatedTerminalJob>, LogicalMaterializationStoreError> {
    let mut base_rows = load_terminal_job_base_rows(transaction, target).await?;
    if base_rows.is_empty() || base_rows.len() > MAX_LOGICAL_JOBS {
        return Err(StoreError::corrupt_data("invalid terminal logical-job graph size").into());
    }
    let expected_job_count = sqlx::query_scalar::<_, i64>(
        r"
        SELECT count(*)
        FROM logical_workflow_jobs
        WHERE run_id = $1 AND invocation_id = $2
        ",
    )
    .bind(target.run_id().as_uuid())
    .bind(target.invocation_id().as_uuid())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if require_all && usize::try_from(expected_job_count).ok() != Some(base_rows.len()) {
        return Err(StoreError::corrupt_data(
            "finalized run contains a malformed logical-job base row",
        )
        .into());
    }

    let dependency_rows = sqlx::query(
        r"
        SELECT logical_job_id, prerequisite_job_id
        FROM logical_workflow_dependencies
        WHERE run_id = $1 AND invocation_id = $2
        ORDER BY logical_job_id, prerequisite_job_id
        ",
    )
    .bind(target.run_id().as_uuid())
    .bind(target.invocation_id().as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let mut dependencies: BTreeMap<Uuid, Vec<Uuid>> = BTreeMap::new();
    for row in dependency_rows {
        dependencies
            .entry(row.try_get("logical_job_id").map_err(operation_error)?)
            .or_default()
            .push(
                row.try_get("prerequisite_job_id")
                    .map_err(operation_error)?,
            );
    }

    let all_ids: BTreeSet<Uuid> = base_rows.keys().copied().collect();
    let mut required = if require_all {
        all_ids.clone()
    } else {
        BTreeSet::from([target.logical_job_id().as_uuid()])
    };
    if !require_all {
        let mut frontier = vec![target.logical_job_id().as_uuid()];
        while let Some(job_id) = frontier.pop() {
            for prerequisite_id in dependencies.get(&job_id).into_iter().flatten() {
                if required.insert(*prerequisite_id) {
                    frontier.push(*prerequisite_id);
                }
            }
            if required.len() > MAX_LOGICAL_JOBS {
                return Err(StoreError::corrupt_data(
                    "terminal logical-job dependency closure is oversized",
                )
                .into());
            }
        }
    }
    if !required.is_subset(&all_ids)
        || (require_all
            && dependencies.iter().any(|(job_id, prerequisite_ids)| {
                !all_ids.contains(job_id) || prerequisite_ids.iter().any(|id| !all_ids.contains(id))
            }))
    {
        return Err(StoreError::corrupt_data(
            "terminal logical-job graph references an unknown job",
        )
        .into());
    }

    let mut verified: BTreeMap<Uuid, ReauthenticatedTerminalJob> = BTreeMap::new();
    while verified.len() < required.len() {
        let mut ready: Vec<(i32, Uuid)> = required
            .iter()
            .filter(|id| !verified.contains_key(id))
            .filter_map(|id| {
                let row = base_rows.get(id)?;
                let source_order = row.try_get::<i32, _>("source_order").ok()?;
                let ready = dependencies
                    .get(id)
                    .into_iter()
                    .flatten()
                    .all(|dependency| verified.contains_key(dependency));
                ready.then_some((source_order, *id))
            })
            .collect();
        ready.sort_unstable();
        if ready.is_empty() {
            return Err(StoreError::corrupt_data(
                "terminal logical-job dependency graph is cyclic or malformed",
            )
            .into());
        }
        for (_, job_id) in ready {
            let row = base_rows.remove(&job_id).ok_or_else(|| {
                StoreError::corrupt_data("terminal logical-job base row disappeared")
            })?;
            let job_target = LogicalJobResultTarget::new(
                target.tenant().clone(),
                target.run_id(),
                target.invocation_id(),
                LogicalWorkflowJobId::from_uuid(job_id).map_err(corrupt_value)?,
            )
            .map_err(corrupt_value)?;
            let prerequisites = dependencies
                .get(&job_id)
                .into_iter()
                .flatten()
                .map(|id| {
                    verified.get(id).ok_or_else(|| {
                        StoreError::corrupt_data(
                            "terminal logical-job prerequisite was not reauthenticated",
                        )
                        .into()
                    })
                })
                .collect::<Result<Vec<_>, LogicalMaterializationStoreError>>()?;
            let job =
                reauthenticate_terminal_job(transaction, job_target, &row, &prerequisites).await?;
            verified.insert(job_id, job);
        }
    }

    let mut jobs: Vec<_> = verified.into_values().collect();
    jobs.sort_by_key(|job| job.evidence.source_order());
    Ok(jobs)
}

async fn load_terminal_job_base_rows(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalInstanceMaterializationTarget,
) -> Result<BTreeMap<Uuid, PgRow>, LogicalMaterializationStoreError> {
    let schemas = current_durable_schemas();
    let rows = sqlx::query(
        r"
        SELECT job.id AS logical_job_id, job.logical_key, job.source_order,
               job.execution_kind, job.state AS logical_job_state,
               job.updated_at_ms AS logical_job_updated_at_ms,
               invocation.plan_digest, invocation.plan_object_key,
               invocation.plan_size_bytes, invocation.plan_media_type,
               invocation.plan_schema,
               publication.activation_input_digest,
               publication.activation_output_digest,
               publication.condition_matched, publication.instance_count,
               publication.published_at_ms,
               publication.scheduling_policy_schema,
               publication.requested_max_parallel,
               publication.effective_max_parallel
        FROM logical_workflow_jobs AS job
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = job.run_id AND invocation.id = job.invocation_id
        JOIN logical_workflow_runs AS marker ON marker.run_id = job.run_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        JOIN logical_workflow_activation_publications AS publication
          ON publication.run_id = job.run_id
         AND publication.invocation_id = job.invocation_id
         AND publication.logical_job_id = job.id
        WHERE repository.tenant_id = $1
          AND job.run_id = $2 AND job.invocation_id = $3
          AND marker.root_invocation_id = job.invocation_id
          AND marker.orchestration_schema = $4
          AND invocation.plan_schema = $5
          AND invocation.plan_media_type = $7
          AND run.admission_epoch = $8 AND run.plan_schema = $6
        ORDER BY job.source_order, job.id
        ",
    )
    .bind(target.tenant().as_str())
    .bind(target.run_id().as_uuid())
    .bind(target.invocation_id().as_uuid())
    .bind(schemas.logical_orchestration_i16)
    .bind(schemas.workflow_plan_i16)
    .bind(schemas.workflow_plan_i32)
    .bind(LOGICAL_JOB_RESULT_PLAN_MEDIA_TYPE)
    .bind(schemas.admission_epoch_i32)
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let mut by_id = BTreeMap::new();
    for row in rows {
        let id = row
            .try_get::<Uuid, _>("logical_job_id")
            .map_err(operation_error)?;
        if by_id.insert(id, row).is_some() {
            return Err(StoreError::corrupt_data("duplicate terminal logical-job row").into());
        }
    }
    Ok(by_id)
}

#[allow(clippy::too_many_lines)] // Exact terminal replay checks every retained job/result field.
async fn reauthenticate_terminal_job(
    transaction: &mut Transaction<'_, Postgres>,
    target: LogicalJobResultTarget,
    base: &PgRow,
    prerequisite_jobs: &[&ReauthenticatedTerminalJob],
) -> Result<ReauthenticatedTerminalJob, LogicalMaterializationStoreError> {
    if base
        .try_get::<String, _>("execution_kind")
        .map_err(operation_error)?
        != "steps"
    {
        return Err(StoreError::corrupt_data(
            "terminal logical-job evidence uses an unsupported execution kind",
        )
        .into());
    }
    let logical_key = WorkflowJobKey::new(
        base.try_get::<String, _>("logical_key")
            .map_err(operation_error)?,
    )
    .map_err(corrupt_value)?;
    let source_order = u16::try_from(
        base.try_get::<i32, _>("source_order")
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("invalid terminal logical-job source order"))?;
    let plan = decode_terminal_admission_object(
        base,
        "plan_digest",
        "plan_object_key",
        "plan_size_bytes",
        "plan_media_type",
    )?;
    if base
        .try_get::<i16, _>("plan_schema")
        .map_err(operation_error)?
        != i16::try_from(WORKFLOW_PLAN_SCHEMA).unwrap_or(i16::MAX)
        || plan.media_type() != LOGICAL_JOB_RESULT_PLAN_MEDIA_TYPE
    {
        return Err(StoreError::corrupt_data(
            "terminal logical-job plan descriptor is not current",
        )
        .into());
    }
    let instance_count = decode_terminal_count(base, "instance_count", 256)?;
    let condition_matched = base
        .try_get::<bool, _>("condition_matched")
        .map_err(operation_error)?;
    let activation_input_digest = decode_digest(base, "activation_input_digest")?;
    let activation_output_digest = decode_digest(base, "activation_output_digest")?;
    let scheduling_scope = LogicalJobSchedulingPolicyScope::new(
        target.tenant().clone(),
        target.run_id(),
        target.invocation_id(),
        target.logical_job_id(),
    )
    .map_err(corrupt_value)?;
    let scheduling_policy = decode_scheduling_policy(base, &scheduling_scope)
        .map_err(LogicalMaterializationStoreError::from)?;
    let activation_publication = ActivationPublicationDigestEvidence {
        input_digest: activation_input_digest,
        output_digest: activation_output_digest,
        condition_matched,
        scheduling_policy: &scheduling_policy,
    };
    let instances = load_terminal_instance_evidence(
        transaction,
        &target,
        &logical_key,
        instance_count,
        &activation_publication,
    )
    .await?;
    let prerequisites = prerequisite_jobs
        .iter()
        .map(|job| {
            let evidence = &job.evidence;
            LogicalJobPrerequisiteEvidence::new(
                evidence.logical_job_id(),
                evidence.logical_key().clone(),
                evidence.source_order(),
                evidence.commit_digest(),
                evidence.outputs_digest(),
                evidence.effective_conclusion(),
                evidence.closure_has_failure(),
                evidence.closure_has_cancelled(),
                evidence.closure_has_skipped(),
                evidence.finalized_at(),
            )
            .map_err(corrupt_value)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let descriptor = LogicalJobResultDescriptor::new(
        target,
        logical_key,
        source_order,
        plan,
        activation_output_digest,
        condition_matched,
        instance_count,
        instances,
        prerequisites,
        UnixMillis::new(base.try_get("published_at_ms").map_err(operation_error)?),
    )
    .map_err(corrupt_value)?;
    let root = load_terminal_job_result_root(transaction, descriptor.target()).await?;
    let outputs = load_terminal_job_outputs(transaction, descriptor.target()).await?;
    let output_count = decode_terminal_count(&root, "output_count", 256)?;
    let stored_outputs_digest = decode_digest(&root, "outputs_digest")?;
    if usize::try_from(output_count).ok() != Some(outputs.len())
        || automata_ci_store::adapter_spi::logical_job_outputs_digest(&outputs)
            != stored_outputs_digest
    {
        return Err(StoreError::corrupt_data(
            "terminal logical-job output root disagrees with child rows",
        )
        .into());
    }
    let effective_conclusion = aggregate_terminal_job_conclusion(descriptor.instances());
    let closure_has_failure = matches!(
        effective_conclusion,
        JobConclusion::Failure | JobConclusion::TimedOut
    ) || descriptor
        .prerequisites()
        .iter()
        .any(LogicalJobPrerequisiteEvidence::closure_has_failure);
    let closure_has_cancelled = effective_conclusion == JobConclusion::Cancelled
        || descriptor
            .prerequisites()
            .iter()
            .any(LogicalJobPrerequisiteEvidence::closure_has_cancelled);
    let closure_has_skipped = effective_conclusion == JobConclusion::Skipped
        || descriptor
            .prerequisites()
            .iter()
            .any(LogicalJobPrerequisiteEvidence::closure_has_skipped);
    let claim_owner_id = root
        .try_get::<Uuid, _>("claim_owner_id")
        .map_err(operation_error)?;
    let claim_owner = LogicalJobResultWorkerId::from_uuid(claim_owner_id).map_err(corrupt_value)?;
    let claim_generation_i64 = root
        .try_get::<i64, _>("claim_generation")
        .map_err(operation_error)?;
    let claim_generation = LogicalJobResultGeneration::new(
        u64::try_from(claim_generation_i64)
            .map_err(|_| StoreError::corrupt_data("invalid terminal job claim generation"))?,
    )
    .map_err(corrupt_value)?;
    let finalized_at = UnixMillis::new(root.try_get("finalized_at_ms").map_err(operation_error)?);
    let expected_commit = automata_ci_store::adapter_spi::logical_job_result_commit_digest(
        descriptor.target(),
        claim_owner,
        claim_generation,
        descriptor.descriptor_digest(),
        descriptor.instances_digest(),
        descriptor.prerequisites_digest(),
        effective_conclusion,
        closure_has_failure,
        closure_has_cancelled,
        closure_has_skipped,
        stored_outputs_digest,
        finalized_at,
    );
    verify_terminal_job_root(
        base,
        &root,
        &descriptor,
        output_count,
        stored_outputs_digest,
        expected_commit,
        effective_conclusion,
        closure_has_failure,
        closure_has_cancelled,
        closure_has_skipped,
    )?;
    if !terminal_job_instance_children_match(transaction, &descriptor).await?
        || !terminal_job_prerequisite_children_match(transaction, &descriptor).await?
    {
        return Err(StoreError::corrupt_data(
            "terminal logical-job child snapshots failed reauthentication",
        )
        .into());
    }
    let evidence = LogicalRunJobResultEvidence::new(
        descriptor.target().logical_job_id(),
        descriptor.logical_key().clone(),
        descriptor.source_order(),
        descriptor.descriptor_digest(),
        effective_conclusion,
        closure_has_failure,
        closure_has_cancelled,
        closure_has_skipped,
        descriptor.instance_count(),
        descriptor.instances_digest(),
        u32::try_from(descriptor.prerequisites().len()).unwrap_or(u32::MAX),
        descriptor.prerequisites_digest(),
        output_count,
        stored_outputs_digest,
        expected_commit,
        finalized_at,
    )
    .map_err(corrupt_value)?;
    Ok(ReauthenticatedTerminalJob { evidence })
}

async fn load_terminal_job_result_root(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalJobResultTarget,
) -> Result<PgRow, LogicalMaterializationStoreError> {
    sqlx::query(
        r"
        SELECT result.*,
               claim.state AS receipt_claim_state,
               claim.run_id AS receipt_claim_run_id,
               claim.invocation_id AS receipt_claim_invocation_id,
               claim.descriptor_digest AS receipt_claim_descriptor_digest,
               claim.owner_id AS receipt_claim_owner_id,
               claim.generation AS receipt_claim_generation,
               claim.claimed_at_ms AS receipt_claim_claimed_at_ms,
               claim.expires_at_ms AS receipt_claim_expires_at_ms,
               claim.updated_at_ms AS receipt_claim_updated_at_ms,
               (SELECT count(*) FROM logical_workflow_job_result_instances AS child
                WHERE child.logical_job_id = result.logical_job_id) AS actual_instance_count,
               (SELECT count(*) FROM logical_workflow_job_result_prerequisites AS child
                WHERE child.logical_job_id = result.logical_job_id) AS actual_prerequisite_count,
               (SELECT count(*) FROM logical_workflow_job_result_outputs AS child
                WHERE child.logical_job_id = result.logical_job_id) AS actual_output_count
        FROM logical_workflow_job_results AS result
        JOIN logical_workflow_job_result_claims AS claim
          ON claim.logical_job_id = result.logical_job_id
        WHERE result.logical_job_id = $1
        ",
    )
    .bind(target.logical_job_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or_else(|| StoreError::corrupt_data("terminal logical job has no immutable result").into())
}

async fn load_terminal_job_outputs(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalJobResultTarget,
) -> Result<Vec<LogicalJobResultOutput>, LogicalMaterializationStoreError> {
    let rows = sqlx::query(
        r#"
        SELECT output_name, sensitivity, public_value
        FROM logical_workflow_job_result_outputs
        WHERE logical_job_id = $1
        ORDER BY output_name COLLATE "C"
        "#,
    )
    .bind(target.logical_job_id().as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    rows.into_iter()
        .map(|row| {
            automata_ci_store::adapter_spi::logical_job_result_output(
                WorkflowOutputKey::new(
                    row.try_get::<String, _>("output_name")
                        .map_err(operation_error)?,
                )
                .map_err(corrupt_value)?,
                parse_terminal_sensitivity(
                    &row.try_get::<String, _>("sensitivity")
                        .map_err(operation_error)?,
                )?,
                row.try_get("public_value").map_err(operation_error)?,
            )
            .map_err(corrupt_value)
        })
        .collect()
}

struct ActivationPublicationDigestEvidence<'a> {
    input_digest: Sha256Digest,
    output_digest: Sha256Digest,
    condition_matched: bool,
    scheduling_policy: &'a ResolvedLogicalJobSchedulingPolicy,
}

#[allow(clippy::too_many_lines)]
async fn load_terminal_instance_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalJobResultTarget,
    logical_key: &WorkflowJobKey,
    expected_count: u32,
    activation_publication: &ActivationPublicationDigestEvidence<'_>,
) -> Result<Vec<LogicalJobInstanceResultEvidence>, LogicalMaterializationStoreError> {
    let rows = sqlx::query(
        r"
        SELECT instance.id AS instance_id, instance.matrix_index,
               instance.matrix_total, instance.matrix_digest,
               instance.workspace, instance.job_ir_digest,
               instance.job_ir_object_key, instance.job_ir_size_bytes,
               instance.job_ir_media_type, instance.job_ir_version,
               instance.runtime_context_digest,
               instance.runtime_context_object_key,
               instance.runtime_context_size_bytes,
               instance.runtime_context_media_type,
               instance.runtime_context_schema,
               evidence.environment_normalized_name AS gate_environment,
               evidence.event_trust AS gate_event_trust,
               evidence.source_kind AS gate_source_kind,
               evidence.reusable_secret_permission AS gate_reusable_permission,
               result.run_id AS result_run_id,
               result.invocation_id AS result_invocation_id,
               result.logical_job_id AS result_logical_job_id,
               result.job_id, result.attempt_id,
               result.terminal_ordinal AS result_terminal_ordinal,
               result.descriptor_digest, result.result_digest,
               result.result_object_key, result.result_size_bytes,
               result.result_media_type, result.result_schema,
               result.job_ir_digest AS result_job_ir_digest,
               result.job_ir_object_key AS result_job_ir_object_key,
               result.job_ir_size_bytes AS result_job_ir_size_bytes,
               result.job_ir_media_type AS result_job_ir_media_type,
               result.job_ir_schema AS result_job_ir_schema,
               result.raw_conclusion, result.effective_conclusion,
               result.continue_on_error, result.secret_exposure_class,
               result.result_completed_at_ms, result.result_committed_at_ms,
               result.output_count, result.outputs_digest,
               result.commit_digest, result.claim_owner_id,
               result.claim_generation, result.claim_started_at_ms,
               result.claim_expires_at_ms, result.finalized_at_ms,
               claim.state AS instance_claim_state,
               claim.run_id AS instance_claim_run_id,
               claim.invocation_id AS instance_claim_invocation_id,
               claim.logical_job_id AS instance_claim_logical_job_id,
               claim.instance_id AS instance_claim_instance_id,
               claim.job_id AS instance_claim_job_id,
               claim.attempt_id AS instance_claim_attempt_id,
               claim.descriptor_digest AS instance_claim_descriptor_digest,
               claim.owner_id AS instance_claim_owner_id,
               claim.generation AS instance_claim_generation,
               claim.claimed_at_ms AS instance_claim_claimed_at_ms,
               claim.expires_at_ms AS instance_claim_expires_at_ms,
               claim.updated_at_ms AS instance_claim_updated_at_ms,
               concrete.run_id AS concrete_run_id,
               concrete.invocation_id AS concrete_invocation_id,
               concrete.logical_job_id AS concrete_logical_job_id,
               concrete.job_id AS concrete_job_id,
               concrete.initial_attempt_id AS concrete_attempt_id,
               materialization.state AS materialization_state,
               attempt.secret_exposure_class AS maximum_secret_exposure_class,
               attempt.lifecycle AS attempt_lifecycle,
               terminal.result_digest AS terminal_result_digest,
               terminal.result_object_key AS terminal_result_object_key,
               terminal.result_size_bytes AS terminal_result_size_bytes,
               terminal.result_schema AS terminal_result_schema,
               terminal.conclusion AS terminal_conclusion,
               terminal.completed_at_ms AS terminal_completed_at_ms,
               terminal.committed_at_ms AS terminal_committed_at_ms,
               terminal.logical_workflow_logical_job_id AS terminal_logical_job_id,
               terminal.logical_workflow_terminal_ordinal AS terminal_ordinal
        FROM logical_workflow_instances AS instance
        LEFT JOIN logical_workflow_instance_results AS result
          ON result.instance_id = instance.id
        LEFT JOIN logical_workflow_instance_result_claims AS claim
          ON claim.instance_id = instance.id
        LEFT JOIN logical_workflow_job_environment_evidence AS evidence
          ON evidence.instance_id = instance.id
        LEFT JOIN logical_workflow_concrete_jobs AS concrete
          ON concrete.instance_id = instance.id
        LEFT JOIN logical_workflow_materialization_claims AS materialization
          ON materialization.instance_id = instance.id
        LEFT JOIN job_attempts AS attempt ON attempt.id = result.attempt_id
        LEFT JOIN attempt_terminal_results AS terminal
          ON terminal.attempt_id = result.attempt_id
        WHERE instance.run_id = $1 AND instance.invocation_id = $2
          AND instance.logical_job_id = $3
        ORDER BY instance.matrix_index
        ",
    )
    .bind(target.run_id().as_uuid())
    .bind(target.invocation_id().as_uuid())
    .bind(target.logical_job_id().as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if rows.len() != usize::try_from(expected_count).unwrap_or(usize::MAX) {
        return Err(StoreError::corrupt_data(
            "terminal logical-job instance count disagrees with activation",
        )
        .into());
    }
    let mut activation_instances = Vec::with_capacity(rows.len());
    for row in &rows {
        activation_instances.push(decode_terminal_activation_instance(target, row)?);
    }
    if automata_ci_store::adapter_spi::logical_activation_publication_digest(
        target.run_id(),
        target.invocation_id(),
        target.logical_job_id(),
        activation_publication.input_digest,
        activation_publication.condition_matched,
        &activation_instances,
        activation_publication.scheduling_policy,
    ) != activation_publication.output_digest
    {
        return Err(StoreError::corrupt_data(
            "terminal activation publication digest failed reauthentication",
        )
        .into());
    }
    if expected_count == 0 {
        return Ok(Vec::new());
    }
    let mut outputs = load_terminal_instance_outputs(transaction, target).await?;
    let mut evidence = Vec::with_capacity(rows.len());
    for row in rows {
        let instance_uuid = row
            .try_get::<Uuid, _>("instance_id")
            .map_err(operation_error)?;
        let instance_outputs = outputs.remove(&instance_uuid).unwrap_or_default();
        evidence.push(decode_terminal_instance_evidence(
            target,
            logical_key,
            &row,
            instance_uuid,
            instance_outputs,
        )?);
    }
    if !outputs.is_empty() {
        return Err(StoreError::corrupt_data("orphan terminal logical-instance outputs").into());
    }
    Ok(evidence)
}

async fn load_terminal_instance_outputs(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalJobResultTarget,
) -> Result<BTreeMap<Uuid, Vec<LogicalJobInstanceOutput>>, LogicalMaterializationStoreError> {
    let rows = sqlx::query(
        r#"
        SELECT output.instance_id, output.output_name,
               output.sensitivity, output.public_value
        FROM logical_workflow_instance_result_outputs AS output
        JOIN logical_workflow_instance_results AS result
          ON result.instance_id = output.instance_id
        WHERE result.run_id = $1 AND result.invocation_id = $2
          AND result.logical_job_id = $3
        ORDER BY output.instance_id, output.output_name COLLATE "C"
        "#,
    )
    .bind(target.run_id().as_uuid())
    .bind(target.invocation_id().as_uuid())
    .bind(target.logical_job_id().as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let mut outputs: BTreeMap<Uuid, Vec<LogicalJobInstanceOutput>> = BTreeMap::new();
    for row in rows {
        let instance_id = row
            .try_get::<Uuid, _>("instance_id")
            .map_err(operation_error)?;
        outputs.entry(instance_id).or_default().push(
            LogicalJobInstanceOutput::new(
                WorkflowOutputKey::new(
                    row.try_get::<String, _>("output_name")
                        .map_err(operation_error)?,
                )
                .map_err(corrupt_value)?,
                parse_terminal_sensitivity(
                    &row.try_get::<String, _>("sensitivity")
                        .map_err(operation_error)?,
                )?,
                row.try_get("public_value").map_err(operation_error)?,
            )
            .map_err(corrupt_value)?,
        );
    }
    Ok(outputs)
}

fn decode_terminal_activation_instance(
    target: &LogicalJobResultTarget,
    row: &PgRow,
) -> Result<ActivatedLogicalInstanceDescriptor, LogicalMaterializationStoreError> {
    if row
        .try_get::<String, _>("job_ir_media_type")
        .map_err(operation_error)?
        != LOGICAL_ACTIVATION_JOB_IR_MEDIA_TYPE
        || row
            .try_get::<i16, _>("job_ir_version")
            .map_err(operation_error)?
            != i16::try_from(JOB_IR_SCHEMA_VERSION).unwrap_or(i16::MAX)
        || row
            .try_get::<String, _>("runtime_context_media_type")
            .map_err(operation_error)?
            != LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE
        || row
            .try_get::<i16, _>("runtime_context_schema")
            .map_err(operation_error)?
            != i16::try_from(JOB_RUNTIME_CONTEXT_SCHEMA_VERSION).unwrap_or(i16::MAX)
    {
        return Err(StoreError::corrupt_data(
            "terminal activation instance object contract is not current",
        )
        .into());
    }
    let job_ir_object = LogicalActivationObject::job_ir(
        decode_digest(row, "job_ir_digest")?,
        ObjectKey::new(
            row.try_get::<String, _>("job_ir_object_key")
                .map_err(operation_error)?,
        )
        .map_err(corrupt_value)?,
        decode_terminal_size(row, "job_ir_size_bytes")?,
    )
    .map_err(corrupt_value)?;
    let runtime_context = LogicalActivationObject::runtime_context(
        decode_digest(row, "runtime_context_digest")?,
        ObjectKey::new(
            row.try_get::<String, _>("runtime_context_object_key")
                .map_err(operation_error)?,
        )
        .map_err(corrupt_value)?,
        decode_terminal_size(row, "runtime_context_size_bytes")?,
    )
    .map_err(corrupt_value)?;
    automata_ci_store::adapter_spi::activated_logical_instance_descriptor(
        LogicalWorkflowInstanceId::from_uuid(row.try_get("instance_id").map_err(operation_error)?)
            .map_err(corrupt_value)?,
        target.run_id(),
        target.invocation_id(),
        target.logical_job_id(),
        u32::try_from(
            row.try_get::<i32, _>("matrix_index")
                .map_err(operation_error)?,
        )
        .map_err(|_| StoreError::corrupt_data("negative terminal matrix index"))?,
        u32::try_from(
            row.try_get::<i32, _>("matrix_total")
                .map_err(operation_error)?,
        )
        .map_err(|_| StoreError::corrupt_data("negative terminal matrix total"))?,
        decode_digest(row, "matrix_digest")?,
        row.try_get("workspace").map_err(operation_error)?,
        job_ir_object,
        runtime_context,
        super::protected_environment::decode_job_environment_activation_evidence(row)?,
    )
    .map_err(corrupt_value)
}

#[allow(clippy::too_many_lines)]
fn decode_terminal_instance_evidence(
    target: &LogicalJobResultTarget,
    logical_key: &WorkflowJobKey,
    row: &PgRow,
    instance_uuid: Uuid,
    outputs: Vec<LogicalJobInstanceOutput>,
) -> Result<LogicalJobInstanceResultEvidence, LogicalMaterializationStoreError> {
    let instance_id = LogicalWorkflowInstanceId::from_uuid(instance_uuid).map_err(corrupt_value)?;
    let job_id = JobId::from_uuid(required_terminal(row, "job_id")?);
    let attempt_id = AttemptId::from_uuid(required_terminal(row, "attempt_id")?);
    let terminal_ordinal = LogicalInstanceTerminalOrdinal::new(
        u64::try_from(required_terminal::<i64>(row, "result_terminal_ordinal")?)
            .map_err(|_| StoreError::corrupt_data("invalid terminal instance ordinal"))?,
    )
    .map_err(corrupt_value)?;
    let terminal_result_schema =
        u16::try_from(required_terminal::<i32>(row, "terminal_result_schema")?)
            .map_err(|_| StoreError::corrupt_data("invalid terminal result schema"))?;
    let terminal_result = LogicalTerminalResultObject::new(
        decode_terminal_required_digest(row, "terminal_result_digest")?,
        ObjectKey::new(required_terminal::<String>(
            row,
            "terminal_result_object_key",
        )?)
        .map_err(corrupt_value)?,
        u64::try_from(required_terminal::<i64>(row, "terminal_result_size_bytes")?)
            .map_err(|_| StoreError::corrupt_data("negative terminal result size"))?,
        terminal_result_schema,
    )
    .map_err(corrupt_value)?;
    let job_ir_object = LogicalActivationObject::job_ir(
        decode_digest(row, "job_ir_digest")?,
        ObjectKey::new(
            row.try_get::<String, _>("job_ir_object_key")
                .map_err(operation_error)?,
        )
        .map_err(corrupt_value)?,
        decode_terminal_size(row, "job_ir_size_bytes")?,
    )
    .map_err(corrupt_value)?;
    let maximum_secret_exposure = parse_terminal_secret_exposure(&required_terminal::<String>(
        row,
        "maximum_secret_exposure_class",
    )?)?;
    if maximum_secret_exposure == JobSecretExposure::CapabilityOnly {
        return Err(StoreError::corrupt_data(
            "materialized logical attempt has unsupported capability-only authority",
        )
        .into());
    }
    let raw_conclusion =
        parse_terminal_conclusion(&required_terminal::<String>(row, "terminal_conclusion")?)?;
    let result_completed_at = UnixMillis::new(required_terminal(row, "terminal_completed_at_ms")?);
    let result_committed_at = UnixMillis::new(required_terminal(row, "terminal_committed_at_ms")?);
    let descriptor = LogicalInstanceResultDescriptor::new(
        LogicalInstanceResultTarget::new(target.tenant().clone(), attempt_id)
            .map_err(corrupt_value)?,
        target.run_id(),
        target.invocation_id(),
        target.logical_job_id(),
        instance_id,
        job_id,
        logical_key.clone(),
        u32::try_from(
            row.try_get::<i32, _>("matrix_index")
                .map_err(operation_error)?,
        )
        .map_err(|_| StoreError::corrupt_data("negative terminal matrix index"))?,
        u32::try_from(
            row.try_get::<i32, _>("matrix_total")
                .map_err(operation_error)?,
        )
        .map_err(|_| StoreError::corrupt_data("negative terminal matrix total"))?,
        decode_digest(row, "matrix_digest")?,
        terminal_ordinal,
        terminal_result,
        job_ir_object,
        maximum_secret_exposure,
        raw_conclusion,
        result_completed_at,
        result_committed_at,
    )
    .map_err(corrupt_value)?;
    let stored_descriptor_digest = decode_terminal_required_digest(row, "descriptor_digest")?;
    let continue_on_error = required_terminal::<bool>(row, "continue_on_error")?;
    let effective_conclusion = if continue_on_error && raw_conclusion == JobConclusion::Failure {
        JobConclusion::Success
    } else {
        raw_conclusion
    };
    let secret_exposure = parse_terminal_secret_exposure(&required_terminal::<String>(
        row,
        "secret_exposure_class",
    )?)?;
    let stored_outputs_digest = decode_terminal_required_digest(row, "outputs_digest")?;
    let finalized_at = UnixMillis::new(required_terminal(row, "finalized_at_ms")?);
    let owner_id = required_terminal::<Uuid>(row, "claim_owner_id")?;
    let generation_i64 = required_terminal::<i64>(row, "claim_generation")?;
    let generation = LogicalInstanceResultGeneration::new(
        u64::try_from(generation_i64)
            .map_err(|_| StoreError::corrupt_data("invalid terminal instance generation"))?,
    )
    .map_err(corrupt_value)?;
    let expected_commit = automata_ci_store::adapter_spi::logical_instance_result_commit_digest(
        instance_id,
        job_id,
        attempt_id,
        terminal_ordinal,
        LogicalInstanceResultWorkerId::from_uuid(owner_id).map_err(corrupt_value)?,
        generation,
        stored_descriptor_digest,
        raw_conclusion,
        effective_conclusion,
        continue_on_error,
        secret_exposure,
        stored_outputs_digest,
        finalized_at,
    );
    let output_count = usize::try_from(required_terminal::<i32>(row, "output_count")?)
        .map_err(|_| StoreError::corrupt_data("negative terminal instance output count"))?;
    let instance_result_schema = u16::try_from(required_terminal::<i16>(row, "result_schema")?)
        .map_err(|_| StoreError::corrupt_data("invalid logical instance result schema"))?;
    let claim_started_at = required_terminal::<i64>(row, "claim_started_at_ms")?;
    let claim_expires_at = required_terminal::<i64>(row, "claim_expires_at_ms")?;
    let exact = stored_descriptor_digest == descriptor.descriptor_digest()
        && required_terminal::<Uuid>(row, "result_run_id")? == target.run_id().as_uuid()
        && required_terminal::<Uuid>(row, "result_invocation_id")?
            == target.invocation_id().as_uuid()
        && required_terminal::<Uuid>(row, "result_logical_job_id")?
            == target.logical_job_id().as_uuid()
        && required_terminal::<String>(row, "instance_claim_state")? == "finalized"
        && required_terminal::<Uuid>(row, "instance_claim_run_id")? == target.run_id().as_uuid()
        && required_terminal::<Uuid>(row, "instance_claim_invocation_id")?
            == target.invocation_id().as_uuid()
        && required_terminal::<Uuid>(row, "instance_claim_logical_job_id")?
            == target.logical_job_id().as_uuid()
        && required_terminal::<Uuid>(row, "instance_claim_instance_id")? == instance_uuid
        && required_terminal::<Uuid>(row, "instance_claim_job_id")? == job_id.as_uuid()
        && required_terminal::<Uuid>(row, "instance_claim_attempt_id")? == attempt_id.as_uuid()
        && decode_terminal_required_digest(row, "instance_claim_descriptor_digest")?
            == stored_descriptor_digest
        && required_terminal::<Uuid>(row, "instance_claim_owner_id")? == owner_id
        && required_terminal::<i64>(row, "instance_claim_generation")? == generation_i64
        && required_terminal::<i64>(row, "instance_claim_claimed_at_ms")? == claim_started_at
        && required_terminal::<i64>(row, "instance_claim_expires_at_ms")? == claim_expires_at
        && required_terminal::<i64>(row, "instance_claim_updated_at_ms")? == finalized_at.get()
        && claim_started_at >= result_committed_at.get()
        && claim_expires_at > claim_started_at
        && claim_expires_at - claim_started_at <= 900_000
        && finalized_at.get() >= claim_started_at
        && finalized_at.get() < claim_expires_at
        && required_terminal::<Uuid>(row, "concrete_run_id")? == target.run_id().as_uuid()
        && required_terminal::<Uuid>(row, "concrete_invocation_id")?
            == target.invocation_id().as_uuid()
        && required_terminal::<Uuid>(row, "concrete_logical_job_id")?
            == target.logical_job_id().as_uuid()
        && required_terminal::<Uuid>(row, "concrete_job_id")? == job_id.as_uuid()
        && required_terminal::<Uuid>(row, "concrete_attempt_id")? == attempt_id.as_uuid()
        && required_terminal::<String>(row, "materialization_state")? == "materialized"
        && required_terminal::<Uuid>(row, "terminal_logical_job_id")?
            == target.logical_job_id().as_uuid()
        && required_terminal::<i64>(row, "terminal_ordinal")? == pg_bigint(terminal_ordinal.get())
        && required_terminal::<String>(row, "attempt_lifecycle")?
            == terminal_lifecycle_name(raw_conclusion)
        && secret_exposure == maximum_secret_exposure
        && parse_terminal_conclusion(&required_terminal::<String>(row, "raw_conclusion")?)?
            == raw_conclusion
        && parse_terminal_conclusion(&required_terminal::<String>(row, "effective_conclusion")?)?
            == effective_conclusion
        && decode_terminal_required_digest(row, "result_digest")?
            == decode_terminal_required_digest(row, "terminal_result_digest")?
        && required_terminal::<String>(row, "result_object_key")?
            == required_terminal::<String>(row, "terminal_result_object_key")?
        && required_terminal::<i64>(row, "result_size_bytes")?
            == required_terminal::<i64>(row, "terminal_result_size_bytes")?
        && instance_result_schema == terminal_result_schema
        && required_terminal::<String>(row, "result_media_type")?
            == LOGICAL_INSTANCE_RESULT_MEDIA_TYPE
        && decode_terminal_required_digest(row, "result_job_ir_digest")?
            == decode_digest(row, "job_ir_digest")?
        && required_terminal::<String>(row, "result_job_ir_object_key")?
            == row
                .try_get::<String, _>("job_ir_object_key")
                .map_err(operation_error)?
        && required_terminal::<i64>(row, "result_job_ir_size_bytes")?
            == row
                .try_get::<i64, _>("job_ir_size_bytes")
                .map_err(operation_error)?
        && required_terminal::<String>(row, "result_job_ir_media_type")?
            == LOGICAL_ACTIVATION_JOB_IR_MEDIA_TYPE
        && required_terminal::<i16>(row, "result_job_ir_schema")?
            == i16::try_from(JOB_IR_SCHEMA_VERSION).unwrap_or(i16::MAX)
        && required_terminal::<i64>(row, "result_completed_at_ms")? == result_completed_at.get()
        && required_terminal::<i64>(row, "result_committed_at_ms")? == result_committed_at.get()
        && output_count == outputs.len()
        && decode_terminal_required_digest(row, "commit_digest")? == expected_commit;
    if !exact {
        return Err(StoreError::corrupt_data(
            "terminal logical-instance root failed complete reauthentication",
        )
        .into());
    }
    let evidence = LogicalJobInstanceResultEvidence::new(
        instance_id,
        descriptor.matrix_index(),
        terminal_ordinal,
        stored_descriptor_digest,
        expected_commit,
        raw_conclusion,
        effective_conclusion,
        outputs,
        finalized_at,
    )
    .map_err(corrupt_value)?;
    if evidence.outputs_digest() != stored_outputs_digest {
        return Err(StoreError::corrupt_data(
            "terminal logical-instance output digest failed reauthentication",
        )
        .into());
    }
    Ok(evidence)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn verify_terminal_job_root(
    base: &PgRow,
    root: &PgRow,
    descriptor: &LogicalJobResultDescriptor,
    output_count: u32,
    outputs_digest: Sha256Digest,
    expected_commit: Sha256Digest,
    effective_conclusion: JobConclusion,
    closure_has_failure: bool,
    closure_has_cancelled: bool,
    closure_has_skipped: bool,
) -> Result<(), LogicalMaterializationStoreError> {
    let finalized_at = root
        .try_get::<i64, _>("finalized_at_ms")
        .map_err(operation_error)?;
    let claim_started_at = root
        .try_get::<i64, _>("claim_started_at_ms")
        .map_err(operation_error)?;
    let claim_expires_at = root
        .try_get::<i64, _>("claim_expires_at_ms")
        .map_err(operation_error)?;
    let expected_state = terminal_logical_job_state(effective_conclusion);
    let instance_count = decode_terminal_count(root, "instance_count", 256)?;
    let prerequisite_count = decode_terminal_count(root, "prerequisite_count", 128)?;
    let exact = root
        .try_get::<Uuid, _>("logical_job_id")
        .map_err(operation_error)?
        == descriptor.target().logical_job_id().as_uuid()
        && root.try_get::<Uuid, _>("run_id").map_err(operation_error)?
            == descriptor.target().run_id().as_uuid()
        && root
            .try_get::<Uuid, _>("invocation_id")
            .map_err(operation_error)?
            == descriptor.target().invocation_id().as_uuid()
        && decode_digest(root, "descriptor_digest")? == descriptor.descriptor_digest()
        && root
            .try_get::<String, _>("logical_key")
            .map_err(operation_error)?
            == descriptor.logical_key().as_str()
        && root
            .try_get::<i32, _>("source_order")
            .map_err(operation_error)?
            == i32::from(descriptor.source_order())
        && decode_digest(root, "plan_digest")? == descriptor.plan().digest()
        && root
            .try_get::<String, _>("plan_object_key")
            .map_err(operation_error)?
            == descriptor.plan().object_key().as_str()
        && root
            .try_get::<i64, _>("plan_size_bytes")
            .map_err(operation_error)?
            == i64::try_from(descriptor.plan().encoded_size()).unwrap_or(i64::MAX)
        && root
            .try_get::<String, _>("plan_media_type")
            .map_err(operation_error)?
            == descriptor.plan().media_type()
        && root
            .try_get::<i16, _>("plan_schema")
            .map_err(operation_error)?
            == i16::try_from(WORKFLOW_PLAN_SCHEMA).unwrap_or(i16::MAX)
        && decode_digest(root, "activation_output_digest")?
            == descriptor.activation_output_digest()
        && root
            .try_get::<bool, _>("condition_matched")
            .map_err(operation_error)?
            == descriptor.condition_matched()
        && instance_count == descriptor.instance_count()
        && decode_digest(root, "instances_digest")? == descriptor.instances_digest()
        && usize::try_from(prerequisite_count).ok() == Some(descriptor.prerequisites().len())
        && decode_digest(root, "prerequisites_digest")? == descriptor.prerequisites_digest()
        && parse_terminal_conclusion(
            &root
                .try_get::<String, _>("effective_conclusion")
                .map_err(operation_error)?,
        )? == effective_conclusion
        && root
            .try_get::<bool, _>("closure_has_failure")
            .map_err(operation_error)?
            == closure_has_failure
        && root
            .try_get::<bool, _>("closure_has_cancelled")
            .map_err(operation_error)?
            == closure_has_cancelled
        && root
            .try_get::<bool, _>("closure_has_skipped")
            .map_err(operation_error)?
            == closure_has_skipped
        && decode_terminal_count(root, "output_count", 256)? == output_count
        && decode_digest(root, "outputs_digest")? == outputs_digest
        && decode_digest(root, "commit_digest")? == expected_commit
        && root
            .try_get::<String, _>("receipt_claim_state")
            .map_err(operation_error)?
            == "finalized"
        && root
            .try_get::<Uuid, _>("receipt_claim_run_id")
            .map_err(operation_error)?
            == descriptor.target().run_id().as_uuid()
        && root
            .try_get::<Uuid, _>("receipt_claim_invocation_id")
            .map_err(operation_error)?
            == descriptor.target().invocation_id().as_uuid()
        && decode_digest(root, "receipt_claim_descriptor_digest")?
            == descriptor.descriptor_digest()
        && root
            .try_get::<Uuid, _>("receipt_claim_owner_id")
            .map_err(operation_error)?
            == root
                .try_get::<Uuid, _>("claim_owner_id")
                .map_err(operation_error)?
        && root
            .try_get::<i64, _>("receipt_claim_generation")
            .map_err(operation_error)?
            == root
                .try_get::<i64, _>("claim_generation")
                .map_err(operation_error)?
        && root
            .try_get::<i64, _>("receipt_claim_claimed_at_ms")
            .map_err(operation_error)?
            == claim_started_at
        && root
            .try_get::<i64, _>("receipt_claim_expires_at_ms")
            .map_err(operation_error)?
            == claim_expires_at
        && root
            .try_get::<i64, _>("receipt_claim_updated_at_ms")
            .map_err(operation_error)?
            == finalized_at
        && claim_started_at >= descriptor.evidence_ready_at().get()
        && claim_expires_at > claim_started_at
        && claim_expires_at - claim_started_at <= 900_000
        && finalized_at >= claim_started_at
        && finalized_at < claim_expires_at
        && root
            .try_get::<i64, _>("actual_instance_count")
            .map_err(operation_error)?
            == i64::from(instance_count)
        && root
            .try_get::<i64, _>("actual_prerequisite_count")
            .map_err(operation_error)?
            == i64::from(prerequisite_count)
        && root
            .try_get::<i64, _>("actual_output_count")
            .map_err(operation_error)?
            == i64::from(output_count)
        && base
            .try_get::<String, _>("logical_job_state")
            .map_err(operation_error)?
            == expected_state
        && base
            .try_get::<i64, _>("logical_job_updated_at_ms")
            .map_err(operation_error)?
            == finalized_at;
    if exact {
        Ok(())
    } else {
        Err(
            StoreError::corrupt_data("terminal logical-job root failed complete reauthentication")
                .into(),
        )
    }
}

async fn terminal_job_instance_children_match(
    transaction: &mut Transaction<'_, Postgres>,
    descriptor: &LogicalJobResultDescriptor,
) -> Result<bool, LogicalMaterializationStoreError> {
    let rows = sqlx::query(
        r"
        SELECT instance_id, matrix_index, terminal_ordinal,
               instance_descriptor_digest, instance_outputs_digest,
               instance_commit_digest, raw_conclusion, effective_conclusion
        FROM logical_workflow_job_result_instances
        WHERE logical_job_id = $1
        ORDER BY matrix_index
        ",
    )
    .bind(descriptor.target().logical_job_id().as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if rows.len() != descriptor.instances().len() {
        return Ok(false);
    }
    for (row, expected) in rows.iter().zip(descriptor.instances()) {
        if row
            .try_get::<Uuid, _>("instance_id")
            .map_err(operation_error)?
            != expected.instance_id().as_uuid()
            || row
                .try_get::<i32, _>("matrix_index")
                .map_err(operation_error)?
                != i32::try_from(expected.matrix_index()).unwrap_or(i32::MAX)
            || row
                .try_get::<i64, _>("terminal_ordinal")
                .map_err(operation_error)?
                != pg_bigint(expected.terminal_ordinal().get())
            || decode_digest(row, "instance_descriptor_digest")? != expected.descriptor_digest()
            || decode_digest(row, "instance_outputs_digest")? != expected.outputs_digest()
            || decode_digest(row, "instance_commit_digest")? != expected.commit_digest()
            || parse_terminal_conclusion(
                &row.try_get::<String, _>("raw_conclusion")
                    .map_err(operation_error)?,
            )? != expected.raw_conclusion()
            || parse_terminal_conclusion(
                &row.try_get::<String, _>("effective_conclusion")
                    .map_err(operation_error)?,
            )? != expected.effective_conclusion()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn terminal_job_prerequisite_children_match(
    transaction: &mut Transaction<'_, Postgres>,
    descriptor: &LogicalJobResultDescriptor,
) -> Result<bool, LogicalMaterializationStoreError> {
    let rows = sqlx::query(
        r"
        SELECT prerequisite_job_id, prerequisite_source_order,
               prerequisite_commit_digest, prerequisite_outputs_digest,
               effective_conclusion, closure_has_failure,
               closure_has_cancelled, closure_has_skipped
        FROM logical_workflow_job_result_prerequisites
        WHERE logical_job_id = $1
        ORDER BY prerequisite_source_order, prerequisite_job_id
        ",
    )
    .bind(descriptor.target().logical_job_id().as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if rows.len() != descriptor.prerequisites().len() {
        return Ok(false);
    }
    for (row, expected) in rows.iter().zip(descriptor.prerequisites()) {
        if row
            .try_get::<Uuid, _>("prerequisite_job_id")
            .map_err(operation_error)?
            != expected.logical_job_id().as_uuid()
            || row
                .try_get::<i32, _>("prerequisite_source_order")
                .map_err(operation_error)?
                != i32::from(expected.source_order())
            || decode_digest(row, "prerequisite_commit_digest")? != expected.commit_digest()
            || decode_digest(row, "prerequisite_outputs_digest")? != expected.outputs_digest()
            || parse_terminal_conclusion(
                &row.try_get::<String, _>("effective_conclusion")
                    .map_err(operation_error)?,
            )? != expected.effective_conclusion()
            || row
                .try_get::<bool, _>("closure_has_failure")
                .map_err(operation_error)?
                != expected.closure_has_failure()
            || row
                .try_get::<bool, _>("closure_has_cancelled")
                .map_err(operation_error)?
                != expected.closure_has_cancelled()
            || row
                .try_get::<bool, _>("closure_has_skipped")
                .map_err(operation_error)?
                != expected.closure_has_skipped()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn aggregate_terminal_job_conclusion(
    instances: &[LogicalJobInstanceResultEvidence],
) -> JobConclusion {
    if instances.is_empty() {
        JobConclusion::Skipped
    } else if instances
        .iter()
        .any(|instance| instance.effective_conclusion() == JobConclusion::Failure)
    {
        JobConclusion::Failure
    } else if instances
        .iter()
        .any(|instance| instance.effective_conclusion() == JobConclusion::TimedOut)
    {
        JobConclusion::TimedOut
    } else if instances
        .iter()
        .any(|instance| instance.effective_conclusion() == JobConclusion::Cancelled)
    {
        JobConclusion::Cancelled
    } else if instances
        .iter()
        .any(|instance| instance.effective_conclusion() == JobConclusion::Success)
    {
        JobConclusion::Success
    } else {
        JobConclusion::Skipped
    }
}

#[allow(clippy::too_many_lines)] // Run-result replay compares the full transitive terminal graph.
async fn verify_terminal_run_result(
    transaction: &mut Transaction<'_, Postgres>,
    materialization_target: &LogicalInstanceMaterializationTarget,
    root: &PgRow,
    jobs: &[ReauthenticatedTerminalJob],
) -> Result<(), LogicalMaterializationStoreError> {
    if jobs.is_empty() || jobs.len() > MAX_LOGICAL_JOBS {
        return Err(StoreError::corrupt_data("invalid terminal run job evidence size").into());
    }
    let root_invocation_id =
        LogicalWorkflowInvocationId::from_uuid(required_terminal(root, "root_invocation_id")?)
            .map_err(corrupt_value)?;
    let target = LogicalRunFinalizationTarget::new(
        materialization_target.tenant().clone(),
        materialization_target.run_id(),
        root_invocation_id,
    )
    .map_err(corrupt_value)?;
    let job_evidence = jobs.iter().map(|job| job.evidence.clone()).collect();
    let descriptor = LogicalRunFinalizationDescriptor::new(
        target,
        decode_terminal_required_digest(root, "admission_digest")?,
        parse_terminal_open_state(&required_terminal::<String>(root, "marker_state")?)?,
        decode_terminal_revision(root, "marker_revision")?,
        UnixMillis::new(required_terminal(root, "marker_updated_at_ms")?),
        parse_terminal_open_state(&required_terminal::<String>(root, "invocation_state")?)?,
        decode_terminal_revision(root, "invocation_revision")?,
        UnixMillis::new(required_terminal(root, "invocation_updated_at_ms")?),
        parse_terminal_workflow_status(&required_terminal::<String>(root, "workflow_status")?)?,
        UnixMillis::new(required_terminal(root, "workflow_updated_at_ms")?),
        job_evidence,
    )
    .map_err(corrupt_value)?;
    let descriptor_digest = decode_terminal_required_digest(root, "descriptor_digest")?;
    let owner_id = required_terminal::<Uuid>(root, "claim_owner_id")?;
    let generation_i64 = required_terminal::<i64>(root, "claim_generation")?;
    let generation = LogicalRunFinalizationGeneration::new(
        u64::try_from(generation_i64)
            .map_err(|_| StoreError::corrupt_data("invalid terminal run generation"))?,
    )
    .map_err(corrupt_value)?;
    let claimed_at = UnixMillis::new(required_terminal(root, "claim_started_at_ms")?);
    let expires_at = UnixMillis::new(required_terminal(root, "claim_expires_at_ms")?);
    let fence = LogicalRunFinalizationClaimFence::new(
        descriptor.target().clone(),
        LogicalRunFinalizationWorkerId::from_uuid(owner_id).map_err(corrupt_value)?,
        generation,
        descriptor_digest,
        claimed_at,
        expires_at,
    )
    .map_err(corrupt_value)?;
    let claimed =
        ClaimedLogicalRunFinalization::new(descriptor.clone(), fence).map_err(corrupt_value)?;
    let finalized_at = UnixMillis::new(required_terminal(root, "finalized_at_ms")?);
    let commit =
        CommitLogicalRunFinalization::new(&claimed, finalized_at).map_err(corrupt_value)?;
    let expected_terminal_state = terminal_run_logical_state(commit.conclusion());
    let expected_workflow_status = if commit.conclusion() == JobConclusion::Cancelled {
        "cancelled"
    } else {
        "completed"
    };
    let stored_marker_revision = required_terminal::<i64>(root, "marker_revision")?;
    let stored_invocation_revision = required_terminal::<i64>(root, "invocation_revision")?;
    let exact = required_terminal::<Uuid>(root, "result_run_id")?
        == materialization_target.run_id().as_uuid()
        && root_invocation_id == materialization_target.invocation_id()
        && required_terminal::<Uuid>(root, "current_root_invocation_id")?
            == root_invocation_id.as_uuid()
        && required_terminal::<Uuid>(root, "claim_root_invocation_id")?
            == root_invocation_id.as_uuid()
        && required_terminal::<String>(root, "run_claim_state")? == "finalized"
        && decode_terminal_required_digest(root, "run_claim_descriptor_digest")?
            == descriptor_digest
        && required_terminal::<Uuid>(root, "run_claim_owner_id")? == owner_id
        && required_terminal::<i64>(root, "run_claim_generation")? == generation_i64
        && required_terminal::<i64>(root, "run_claim_claimed_at_ms")? == claimed_at.get()
        && required_terminal::<i64>(root, "run_claim_expires_at_ms")? == expires_at.get()
        && required_terminal::<i64>(root, "run_claim_updated_at_ms")? == finalized_at.get()
        && descriptor_digest == descriptor.descriptor_digest()
        && decode_terminal_required_digest(root, "current_admission_digest")?
            == descriptor.admission_digest()
        && decode_terminal_count(
            root,
            "job_count",
            u32::try_from(MAX_LOGICAL_JOBS).unwrap_or(u32::MAX),
        )? == descriptor.job_count()
        && decode_terminal_required_digest(root, "evidence_digest")?
            == descriptor.evidence_digest()
        && parse_terminal_conclusion(&required_terminal::<String>(root, "effective_conclusion")?)?
            == commit.conclusion()
        && decode_terminal_required_digest(root, "commit_digest")? == commit.commit_digest()
        && required_terminal::<Uuid>(root, "claim_owner_id")?
            == required_terminal::<Uuid>(root, "run_claim_owner_id")?
        && required_terminal::<i64>(root, "claim_generation")?
            == required_terminal::<i64>(root, "run_claim_generation")?
        && required_terminal::<i64>(root, "claim_started_at_ms")?
            == required_terminal::<i64>(root, "run_claim_claimed_at_ms")?
        && required_terminal::<i64>(root, "claim_expires_at_ms")?
            == required_terminal::<i64>(root, "run_claim_expires_at_ms")?
        && required_terminal::<String>(root, "current_marker_state")? == expected_terminal_state
        && required_terminal::<String>(root, "current_invocation_state")?
            == expected_terminal_state
        && required_terminal::<String>(root, "current_workflow_status")?
            == expected_workflow_status
        && required_terminal::<i64>(root, "current_marker_revision")?
            == stored_marker_revision.checked_add(1).unwrap_or(i64::MIN)
        && required_terminal::<i64>(root, "current_invocation_revision")?
            == stored_invocation_revision
                .checked_add(1)
                .unwrap_or(i64::MIN)
        && required_terminal::<i64>(root, "current_marker_updated_at_ms")? == finalized_at.get()
        && required_terminal::<i64>(root, "current_invocation_updated_at_ms")?
            == finalized_at.get()
        && required_terminal::<i64>(root, "current_workflow_updated_at_ms")? == finalized_at.get();
    if !exact || !terminal_run_job_children_match(transaction, &descriptor).await? {
        return Err(StoreError::corrupt_data(
            "terminal logical-run aggregate failed complete reauthentication",
        )
        .into());
    }
    Ok(())
}

async fn terminal_run_job_children_match(
    transaction: &mut Transaction<'_, Postgres>,
    descriptor: &LogicalRunFinalizationDescriptor,
) -> Result<bool, LogicalMaterializationStoreError> {
    let rows = sqlx::query(
        r#"
        SELECT logical_job_id, logical_key, source_order, descriptor_digest,
               effective_conclusion, closure_has_failure,
               closure_has_cancelled, closure_has_skipped, instance_count,
               instances_digest, prerequisite_count, prerequisites_digest,
               output_count, outputs_digest, job_commit_digest,
               job_finalized_at_ms
        FROM logical_workflow_run_result_jobs
        WHERE run_id = $1 AND root_invocation_id = $2
        ORDER BY source_order, logical_key COLLATE "C", logical_job_id
        "#,
    )
    .bind(descriptor.target().run_id().as_uuid())
    .bind(descriptor.target().root_invocation_id().as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if rows.len() != descriptor.jobs().len() {
        return Ok(false);
    }
    for (row, expected) in rows.iter().zip(descriptor.jobs()) {
        if row
            .try_get::<Uuid, _>("logical_job_id")
            .map_err(operation_error)?
            != expected.logical_job_id().as_uuid()
            || row
                .try_get::<String, _>("logical_key")
                .map_err(operation_error)?
                != expected.logical_key().as_str()
            || row
                .try_get::<i32, _>("source_order")
                .map_err(operation_error)?
                != i32::from(expected.source_order())
            || decode_digest(row, "descriptor_digest")? != expected.descriptor_digest()
            || parse_terminal_conclusion(
                &row.try_get::<String, _>("effective_conclusion")
                    .map_err(operation_error)?,
            )? != expected.effective_conclusion()
            || row
                .try_get::<bool, _>("closure_has_failure")
                .map_err(operation_error)?
                != expected.closure_has_failure()
            || row
                .try_get::<bool, _>("closure_has_cancelled")
                .map_err(operation_error)?
                != expected.closure_has_cancelled()
            || row
                .try_get::<bool, _>("closure_has_skipped")
                .map_err(operation_error)?
                != expected.closure_has_skipped()
            || decode_terminal_count(row, "instance_count", 256)? != expected.instance_count()
            || decode_digest(row, "instances_digest")? != expected.instances_digest()
            || decode_terminal_count(row, "prerequisite_count", 128)?
                != expected.prerequisite_count()
            || decode_digest(row, "prerequisites_digest")? != expected.prerequisites_digest()
            || decode_terminal_count(row, "output_count", 256)? != expected.output_count()
            || decode_digest(row, "outputs_digest")? != expected.outputs_digest()
            || decode_digest(row, "job_commit_digest")? != expected.commit_digest()
            || row
                .try_get::<i64, _>("job_finalized_at_ms")
                .map_err(operation_error)?
                != expected.finalized_at().get()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn decode_terminal_admission_object(
    row: &PgRow,
    digest_column: &str,
    key_column: &str,
    size_column: &str,
    media_column: &str,
) -> Result<AdmissionObject, LogicalMaterializationStoreError> {
    AdmissionObject::new(
        decode_digest(row, digest_column)?,
        ObjectKey::new(
            row.try_get::<String, _>(key_column)
                .map_err(operation_error)?,
        )
        .map_err(corrupt_value)?,
        decode_terminal_size(row, size_column)?,
        row.try_get::<String, _>(media_column)
            .map_err(operation_error)?,
    )
    .map_err(corrupt_value)
}

fn decode_terminal_size(
    row: &PgRow,
    column: &str,
) -> Result<u64, LogicalMaterializationStoreError> {
    u64::try_from(row.try_get::<i64, _>(column).map_err(operation_error)?)
        .map_err(|_| StoreError::corrupt_data(format!("negative terminal {column}")).into())
}

fn decode_terminal_count(
    row: &PgRow,
    column: &str,
    maximum: u32,
) -> Result<u32, LogicalMaterializationStoreError> {
    u32::try_from(row.try_get::<i32, _>(column).map_err(operation_error)?)
        .ok()
        .filter(|value| *value <= maximum)
        .ok_or_else(|| StoreError::corrupt_data(format!("invalid terminal {column}")).into())
}

fn decode_terminal_revision(
    row: &PgRow,
    column: &str,
) -> Result<u64, LogicalMaterializationStoreError> {
    u64::try_from(required_terminal::<i64>(row, column)?)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| StoreError::corrupt_data(format!("invalid terminal {column}")).into())
}

fn required_terminal<T>(row: &PgRow, column: &str) -> Result<T, LogicalMaterializationStoreError>
where
    for<'value> T: sqlx::Decode<'value, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get::<Option<T>, _>(column)
        .map_err(operation_error)?
        .ok_or_else(|| {
            StoreError::corrupt_data(format!("terminal aggregate lacks {column}")).into()
        })
}

fn decode_terminal_required_digest(
    row: &PgRow,
    column: &str,
) -> Result<Sha256Digest, LogicalMaterializationStoreError> {
    let value = required_terminal::<Vec<u8>>(row, column)?;
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| StoreError::corrupt_data(format!("{column} is not SHA-256")))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn parse_terminal_conclusion(
    value: &str,
) -> Result<JobConclusion, LogicalMaterializationStoreError> {
    match value {
        "success" => Ok(JobConclusion::Success),
        "failure" => Ok(JobConclusion::Failure),
        "cancelled" => Ok(JobConclusion::Cancelled),
        "timed_out" => Ok(JobConclusion::TimedOut),
        "skipped" => Ok(JobConclusion::Skipped),
        _ => Err(StoreError::corrupt_data("unknown terminal conclusion").into()),
    }
}

fn parse_terminal_secret_exposure(
    value: &str,
) -> Result<JobSecretExposure, LogicalMaterializationStoreError> {
    match value {
        "secretless" => Ok(JobSecretExposure::Secretless),
        "capability_only" => Ok(JobSecretExposure::CapabilityOnly),
        "readable_secret" => Ok(JobSecretExposure::ReadableSecret),
        _ => Err(StoreError::corrupt_data("unknown terminal secret exposure").into()),
    }
}

fn parse_terminal_sensitivity(
    value: &str,
) -> Result<OutputSensitivity, LogicalMaterializationStoreError> {
    match value {
        "public" => Ok(OutputSensitivity::Public),
        "secret_derived" => Ok(OutputSensitivity::SecretDerived),
        _ => Err(StoreError::corrupt_data("unknown terminal output sensitivity").into()),
    }
}

fn parse_terminal_open_state(
    value: &str,
) -> Result<LogicalRunFinalizationOpenState, LogicalMaterializationStoreError> {
    match value {
        "pending" => Ok(LogicalRunFinalizationOpenState::Pending),
        "active" => Ok(LogicalRunFinalizationOpenState::Active),
        _ => Err(StoreError::corrupt_data("unknown terminal open lifecycle state").into()),
    }
}

fn parse_terminal_workflow_status(
    value: &str,
) -> Result<LogicalRunFinalizationWorkflowStatus, LogicalMaterializationStoreError> {
    match value {
        "queued" => Ok(LogicalRunFinalizationWorkflowStatus::Queued),
        "in_progress" => Ok(LogicalRunFinalizationWorkflowStatus::InProgress),
        "cancelled" => Ok(LogicalRunFinalizationWorkflowStatus::Cancelled),
        _ => Err(StoreError::corrupt_data("unknown terminal workflow status").into()),
    }
}

const fn terminal_lifecycle_name(conclusion: JobConclusion) -> &'static str {
    match conclusion {
        JobConclusion::Success => "succeeded",
        JobConclusion::Failure => "failed",
        JobConclusion::Cancelled => "cancelled",
        JobConclusion::TimedOut => "timed_out",
        JobConclusion::Skipped => "skipped",
    }
}

const fn terminal_logical_job_state(conclusion: JobConclusion) -> &'static str {
    match conclusion {
        JobConclusion::Success => "completed",
        JobConclusion::Failure | JobConclusion::TimedOut => "failed",
        JobConclusion::Cancelled => "cancelled",
        JobConclusion::Skipped => "skipped",
    }
}

const fn terminal_run_logical_state(conclusion: JobConclusion) -> &'static str {
    match conclusion {
        JobConclusion::Success | JobConclusion::Skipped => "completed",
        JobConclusion::Cancelled => "cancelled",
        JobConclusion::Failure | JobConclusion::TimedOut => "failed",
    }
}

fn parse_authority_profile(
    value: &str,
) -> Result<JobAuthorityProfile, LogicalMaterializationStoreError> {
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

#[derive(Debug)]
struct DurableMaterializationClaim {
    run_id: Uuid,
    invocation_id: Uuid,
    logical_job_id: Uuid,
    state: String,
    descriptor_digest: Sha256Digest,
    expected_job_id: JobId,
    expected_attempt_id: AttemptId,
    authority_profile: JobAuthorityProfile,
    runtime_policy_revision: WorkflowRuntimePolicyRevision,
    runtime_policy_digest: Sha256Digest,
    owner_id: Uuid,
    generation: i64,
    claimed_at: i64,
    expires_at: i64,
    updated_at: i64,
    origin_selection_id: Option<Uuid>,
}

impl DurableMaterializationClaim {
    fn is_materialized(&self) -> bool {
        self.state == "materialized"
    }

    fn decode(row: &PgRow) -> Result<Option<Self>, LogicalMaterializationStoreError> {
        let generation: Option<i64> = row
            .try_get("materialization_generation")
            .map_err(operation_error)?;
        let Some(generation) = generation else {
            return Ok(None);
        };
        let run_id: Uuid = row
            .try_get("materialization_run_id")
            .map_err(operation_error)?;
        let invocation_id: Uuid = row
            .try_get("materialization_invocation_id")
            .map_err(operation_error)?;
        let logical_job_id: Uuid = row
            .try_get("materialization_logical_job_id")
            .map_err(operation_error)?;
        let state: String = row
            .try_get("materialization_state")
            .map_err(operation_error)?;
        let descriptor_digest = decode_digest(row, "materialization_descriptor_digest")?;
        let expected_job_id =
            JobId::from_uuid(row.try_get("expected_job_id").map_err(operation_error)?);
        let expected_attempt_id = AttemptId::from_uuid(
            row.try_get("expected_attempt_id")
                .map_err(operation_error)?,
        );
        let authority_profile = parse_authority_profile(
            &row.try_get::<String, _>("materialization_authority_profile")
                .map_err(operation_error)?,
        )?;
        let runtime_policy_revision =
            decode_runtime_policy_revision(row, "materialization_runtime_policy_revision")?;
        let runtime_policy_digest = decode_digest(row, "materialization_runtime_policy_digest")?;
        let owner_id: Uuid = row
            .try_get("materialization_owner_id")
            .map_err(operation_error)?;
        let claimed_at: i64 = row
            .try_get("materialization_claimed_at_ms")
            .map_err(operation_error)?;
        let expires_at: i64 = row
            .try_get("materialization_expires_at_ms")
            .map_err(operation_error)?;
        let created_at: i64 = row
            .try_get("materialization_created_at_ms")
            .map_err(operation_error)?;
        let updated_at: i64 = row
            .try_get("materialization_updated_at_ms")
            .map_err(operation_error)?;
        let origin_selection_id: Option<Uuid> = row
            .try_get("materialization_origin_selection_id")
            .map_err(operation_error)?;
        if !matches!(state.as_str(), "materializing" | "materialized")
            || generation <= 0
            || owner_id.is_nil()
            || expected_job_id.as_uuid().is_nil()
            || expected_attempt_id.as_uuid().is_nil()
            || claimed_at < created_at
            || expires_at <= claimed_at
            || expires_at - claimed_at > 900_000
            || updated_at < claimed_at
            || (state == "materializing" && updated_at != claimed_at)
            || (state == "materialized" && updated_at >= expires_at)
        {
            return Err(StoreError::corrupt_data(
                "logical materialization claim columns are inconsistent",
            )
            .into());
        }
        Ok(Some(Self {
            run_id,
            invocation_id,
            logical_job_id,
            state,
            descriptor_digest,
            expected_job_id,
            expected_attempt_id,
            authority_profile,
            runtime_policy_revision,
            runtime_policy_digest,
            owner_id,
            generation,
            claimed_at,
            expires_at,
            updated_at,
            origin_selection_id,
        }))
    }

    fn verify_descriptor(
        &self,
        descriptor: &LogicalInstanceMaterializationDescriptor,
    ) -> Result<(), LogicalMaterializationStoreError> {
        if self.run_id != descriptor.target().run_id().as_uuid()
            || self.invocation_id != descriptor.target().invocation_id().as_uuid()
            || self.logical_job_id != descriptor.target().logical_job_id().as_uuid()
            || self.descriptor_digest != descriptor.descriptor_digest()
            || self.expected_job_id != descriptor.expected_job_id()
            || self.expected_attempt_id != descriptor.expected_attempt_id()
            || self.authority_profile != descriptor.authority_profile()
            || self.runtime_policy_revision != descriptor.runtime_policy().revision()
            || self.runtime_policy_digest != descriptor.runtime_policy().digest()
        {
            return Err(StoreError::corrupt_data(
                "logical materialization claim disagrees with immutable instance",
            )
            .into());
        }
        Ok(())
    }

    fn is_exact_replay(&self, request: &ClaimLogicalInstanceMaterialization) -> bool {
        self.state == "materializing"
            && self.owner_id == request.owner().as_uuid()
            && self.claimed_at == request.observed_at().get()
            && self.expires_at == request.expires_at().get()
    }

    fn matches_fence(&self, claim: &LogicalMaterializationClaimFence) -> bool {
        self.state == "materializing"
            && self.owner_id == claim.owner().as_uuid()
            && self.generation == pg_bigint(claim.generation().get())
            && self.descriptor_digest == claim.descriptor_digest()
            && self.runtime_policy_revision == claim.runtime_policy().revision()
            && self.runtime_policy_digest == claim.runtime_policy().digest()
            && self.expected_job_id == claim.expected_job_id()
            && self.expected_attempt_id == claim.expected_attempt_id()
            && self.origin_selection_id == Some(claim.selection_origin().as_uuid())
            && self.claimed_at == claim.claimed_at().get()
            && self.expires_at == claim.expires_at().get()
    }
}

fn claimed_from_durable(
    descriptor: LogicalInstanceMaterializationDescriptor,
    durable: &DurableMaterializationClaim,
    replayed: bool,
) -> Result<ClaimedLogicalInstanceMaterialization, LogicalMaterializationStoreError> {
    let generation = LogicalMaterializationGeneration::new(
        u64::try_from(durable.generation)
            .map_err(|_| LogicalMaterializationStoreError::GenerationExhausted)?,
    )
    .map_err(|_| LogicalMaterializationStoreError::GenerationExhausted)?;
    let selection_origin = durable
        .origin_selection_id
        .ok_or(LogicalMaterializationStoreError::ClaimRejected)
        .and_then(|value| {
            automata_ci_store::LogicalWorkSelectionId::from_uuid(value).map_err(corrupt_value)
        })?;
    let claim = LogicalMaterializationClaimFence::new_for_selection(
        descriptor.target().clone(),
        automata_ci_store::LogicalMaterializationWorkerId::from_uuid(durable.owner_id)
            .map_err(corrupt_value)?,
        generation,
        durable.descriptor_digest,
        descriptor.runtime_policy().clone(),
        durable.expected_job_id,
        durable.expected_attempt_id,
        UnixMillis::new(durable.claimed_at),
        UnixMillis::new(durable.expires_at),
        selection_origin,
    )
    .map_err(corrupt_value)?;
    ClaimedLogicalInstanceMaterialization::new(descriptor, claim, replayed).map_err(corrupt_value)
}

fn make_fence(
    target: LogicalInstanceMaterializationTarget,
    owner: automata_ci_store::LogicalMaterializationWorkerId,
    generation: i64,
    descriptor: &LogicalInstanceMaterializationDescriptor,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
    origin_selection_id: Uuid,
) -> Result<LogicalMaterializationClaimFence, LogicalMaterializationStoreError> {
    let generation = LogicalMaterializationGeneration::new(
        u64::try_from(generation)
            .map_err(|_| LogicalMaterializationStoreError::GenerationExhausted)?,
    )
    .map_err(|_| LogicalMaterializationStoreError::GenerationExhausted)?;
    let selection_origin =
        automata_ci_store::LogicalWorkSelectionId::from_uuid(origin_selection_id)
            .map_err(corrupt_value)?;
    LogicalMaterializationClaimFence::new_for_selection(
        target,
        owner,
        generation,
        descriptor.descriptor_digest(),
        descriptor.runtime_policy().clone(),
        descriptor.expected_job_id(),
        descriptor.expected_attempt_id(),
        claimed_at,
        expires_at,
        selection_origin,
    )
    .map_err(corrupt_value)
}

fn decode_descriptor(
    target: LogicalInstanceMaterializationTarget,
    row: &PgRow,
) -> Result<LogicalInstanceMaterializationDescriptor, LogicalMaterializationStoreError> {
    let logical_key = WorkflowJobKey::new(
        row.try_get::<String, _>("logical_key")
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("invalid durable logical key"))?;
    let matrix_index = u32::try_from(
        row.try_get::<i32, _>("matrix_index")
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("invalid durable matrix index"))?;
    let matrix_total = u32::try_from(
        row.try_get::<i32, _>("matrix_total")
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("invalid durable matrix total"))?;
    let matrix_digest = decode_digest(row, "matrix_digest")?;
    let workspace: String = row.try_get("workspace").map_err(operation_error)?;
    verify_exact_schema(row)?;
    let job_ir = decode_activation_object(
        row,
        "job_ir_digest",
        "job_ir_object_key",
        "job_ir_size_bytes",
        true,
    )?;
    let runtime_context = decode_activation_object(
        row,
        "runtime_context_digest",
        "runtime_context_object_key",
        "runtime_context_size_bytes",
        false,
    )?;
    let event = decode_admission_object(row)?;
    let mut execution = LogicalActivationExecutionContext::new(
        WorkflowId::from_uuid(row.try_get("workflow_id").map_err(operation_error)?),
        row.try_get("workflow_name").map_err(operation_error)?,
        row.try_get("git_ref").map_err(operation_error)?,
        row.try_get("event_name").map_err(operation_error)?,
        row.try_get("actor").map_err(operation_error)?,
        RunIdAlias::new(
            u64::try_from(
                row.try_get::<i64, _>("run_id_alias")
                    .map_err(operation_error)?,
            )
            .map_err(|_| StoreError::corrupt_data("invalid durable run ID alias"))?,
        )
        .map_err(|_| StoreError::corrupt_data("invalid durable run ID alias"))?,
        u64::try_from(
            row.try_get::<i64, _>("run_number")
                .map_err(operation_error)?,
        )
        .map_err(|_| StoreError::corrupt_data("invalid durable run number"))?,
        u32::try_from(
            row.try_get::<i32, _>("run_attempt")
                .map_err(operation_error)?,
        )
        .map_err(|_| StoreError::corrupt_data("invalid durable run attempt"))?,
    )
    .map_err(|_| StoreError::corrupt_data("invalid materialization execution metadata"))?;
    if let Some(triggering_actor) = row
        .try_get::<Option<String>, _>("triggering_actor")
        .map_err(operation_error)?
    {
        execution = execution
            .with_triggering_actor(triggering_actor)
            .map_err(|_| StoreError::corrupt_data("invalid durable triggering actor"))?;
    }
    let authority_profile = parse_authority_profile(
        &row.try_get::<String, _>("authority_profile")
            .map_err(operation_error)?,
    )?;
    let runtime_policy = WorkflowRuntimePolicyPin::new(
        target.tenant().clone(),
        RepositoryId::from_uuid(
            row.try_get("runtime_policy_repository_id")
                .map_err(operation_error)?,
        ),
        decode_runtime_policy_revision(row, "runtime_policy_revision")?,
        decode_digest(row, "runtime_policy_digest")?,
    );
    LogicalInstanceMaterializationDescriptor::new(
        target,
        logical_key,
        matrix_index,
        matrix_total,
        matrix_digest,
        workspace,
        job_ir,
        runtime_context,
        event,
        execution,
        authority_profile,
        runtime_policy,
    )
    .map_err(corrupt_value)
}

fn verify_exact_schema(row: &PgRow) -> Result<(), LogicalMaterializationStoreError> {
    let job_ir_version: i16 = row.try_get("job_ir_version").map_err(operation_error)?;
    let runtime_context_schema: i16 = row
        .try_get("runtime_context_schema")
        .map_err(operation_error)?;
    let job_ir_media: String = row.try_get("job_ir_media_type").map_err(operation_error)?;
    let runtime_media: String = row
        .try_get("runtime_context_media_type")
        .map_err(operation_error)?;
    if job_ir_version != i16::try_from(JOB_IR_SCHEMA_VERSION).unwrap_or(i16::MAX)
        || runtime_context_schema
            != i16::try_from(JOB_RUNTIME_CONTEXT_SCHEMA_VERSION).unwrap_or(i16::MAX)
        || job_ir_media != LOGICAL_ACTIVATION_JOB_IR_MEDIA_TYPE
        || runtime_media != LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE
    {
        return Err(StoreError::corrupt_data(
            "logical materialization instance uses a non-current schema",
        )
        .into());
    }
    Ok(())
}

fn decode_requested_log_visibility(
    row: &PgRow,
    requested_visibility_column: &'static str,
) -> Result<String, LogicalMaterializationStoreError> {
    let requested_log_visibility: String = row
        .try_get(requested_visibility_column)
        .map_err(operation_error)?;
    CurrentAttemptOutputSafety::readable(&requested_log_visibility)
        .map(|_| requested_log_visibility)
        .ok_or_else(|| {
            StoreError::corrupt_data("workflow run log publication snapshot is malformed").into()
        })
}

fn decode_activation_object(
    row: &PgRow,
    digest_column: &str,
    key_column: &str,
    size_column: &str,
    job_ir: bool,
) -> Result<LogicalActivationObject, LogicalMaterializationStoreError> {
    let digest = decode_digest(row, digest_column)?;
    let key = ObjectKey::new(
        row.try_get::<String, _>(key_column)
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("invalid materialization object key"))?;
    let size = u64::try_from(
        row.try_get::<i64, _>(size_column)
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("invalid materialization object size"))?;
    let value = if job_ir {
        LogicalActivationObject::job_ir(digest, key, size)
    } else {
        LogicalActivationObject::runtime_context(digest, key, size)
    };
    value.map_err(|_| StoreError::corrupt_data("invalid materialization object descriptor").into())
}

fn decode_admission_object(
    row: &PgRow,
) -> Result<AdmissionObject, LogicalMaterializationStoreError> {
    let digest = decode_digest(row, "event_digest")?;
    let key = ObjectKey::new(
        row.try_get::<String, _>("event_object_key")
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("invalid durable event object key"))?;
    let size = u64::try_from(
        row.try_get::<i64, _>("event_size_bytes")
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("invalid durable event object size"))?;
    let media: String = row.try_get("event_media_type").map_err(operation_error)?;
    AdmissionObject::new_event(digest, key, size, media)
        .map_err(|_| StoreError::corrupt_data("invalid durable event descriptor").into())
}

async fn insert_job(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitLogicalInstanceMaterialization,
    descriptor: &LogicalInstanceMaterializationDescriptor,
) -> Result<(), LogicalMaterializationStoreError> {
    let schemas = current_durable_schemas();
    sqlx::query(
        r"
        INSERT INTO jobs (
            id, run_id, job_key, display_name, job_ir_digest,
            job_ir_object_key, requirements, created_at_ms,
            admission_epoch, job_ir_schema, job_ir_size_bytes
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$10,$11,$9)
        ",
    )
    .bind(request.claim().expected_job_id().as_uuid())
    .bind(request.claim().target().run_id().as_uuid())
    .bind(request.job_key())
    .bind(request.display_name())
    .bind(descriptor.job_ir().digest().as_bytes().as_slice())
    .bind(descriptor.job_ir().object_key().as_str())
    .bind(automata_ci_store::adapter_spi::logical_materialization_requirements_json(request))
    .bind(request.committed_at().get())
    .bind(
        i64::try_from(descriptor.job_ir().encoded_size()).map_err(|_| {
            StoreError::corrupt_data("logical JobIR size does not fit PostgreSQL BIGINT")
        })?,
    )
    .bind(schemas.admission_epoch_i32)
    .bind(schemas.job_ir_i32)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn insert_initial_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitLogicalInstanceMaterialization,
    safety: CurrentAttemptOutputSafety,
) -> Result<(), LogicalMaterializationStoreError> {
    sqlx::query(
        r"
        INSERT INTO job_attempts (
            id, job_id, attempt_number, lifecycle, fencing_token,
            lease_failures, queued_at_ms, changed_at_ms,
            secret_exposure_class, raw_log_disposition,
            requested_log_visibility, effective_log_visibility,
            output_safety_reason, output_safety_schema, classified_at_ms
        ) VALUES (
            $1,$2,1,'queued',0,0,$3,$3,$4,$5,$6,$7,$8,$9,$3
        )
        ",
    )
    .bind(request.claim().expected_attempt_id().as_uuid())
    .bind(request.claim().expected_job_id().as_uuid())
    .bind(request.committed_at().get())
    .bind(safety.secret_exposure_class())
    .bind(safety.raw_log_disposition())
    .bind(safety.requested_log_visibility())
    .bind(safety.effective_log_visibility())
    .bind(safety.output_safety_reason())
    .bind(safety.output_safety_schema())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn insert_materialization_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitLogicalInstanceMaterialization,
    descriptor: &LogicalInstanceMaterializationDescriptor,
) -> Result<(), LogicalMaterializationStoreError> {
    let schemas = current_durable_schemas();
    sqlx::query(
        r"
        INSERT INTO logical_workflow_concrete_jobs (
            instance_id, run_id, invocation_id, logical_job_id,
            descriptor_digest, job_id, initial_attempt_id, job_key,
            display_name, requirements, authority_profile,
            requirements_digest, commit_digest,
            event_digest, event_object_key, event_size_bytes, event_media_type,
            runtime_context_digest, runtime_context_object_key,
            runtime_context_size_bytes, runtime_context_media_type,
            runtime_context_schema, claim_owner_id, claim_generation,
            claim_started_at_ms, claim_expires_at_ms, committed_at_ms,
            runtime_policy_revision, runtime_policy_digest
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
            $18,$19,$20,$21,$29,$22,$23,$24,$25,$26,$27,$28
        )
        ",
    )
    .bind(request.claim().target().instance_id().as_uuid())
    .bind(request.claim().target().run_id().as_uuid())
    .bind(request.claim().target().invocation_id().as_uuid())
    .bind(request.claim().target().logical_job_id().as_uuid())
    .bind(request.claim().descriptor_digest().as_bytes().as_slice())
    .bind(request.claim().expected_job_id().as_uuid())
    .bind(request.claim().expected_attempt_id().as_uuid())
    .bind(request.job_key())
    .bind(request.display_name())
    .bind(automata_ci_store::adapter_spi::logical_materialization_requirements_json(request))
    .bind(authority_profile_name(request.authority_profile()))
    .bind(request.requirements_digest().as_bytes().as_slice())
    .bind(request.commit_digest().as_bytes().as_slice())
    .bind(descriptor.event().digest().as_bytes().as_slice())
    .bind(descriptor.event().object_key().as_str())
    .bind(
        i64::try_from(descriptor.event().encoded_size()).map_err(|_| {
            StoreError::corrupt_data("logical event size does not fit PostgreSQL BIGINT")
        })?,
    )
    .bind(descriptor.event().media_type())
    .bind(descriptor.runtime_context().digest().as_bytes().as_slice())
    .bind(descriptor.runtime_context().object_key().as_str())
    .bind(
        i64::try_from(descriptor.runtime_context().encoded_size()).map_err(|_| {
            StoreError::corrupt_data("logical runtime-context size does not fit PostgreSQL BIGINT")
        })?,
    )
    .bind(descriptor.runtime_context().media_type())
    .bind(request.claim().owner().as_uuid())
    .bind(pg_bigint(request.claim().generation().get()))
    .bind(request.claim().claimed_at().get())
    .bind(request.claim().expires_at().get())
    .bind(request.committed_at().get())
    .bind(pg_bigint(request.claim().runtime_policy().revision().get()))
    .bind(
        request
            .claim()
            .runtime_policy()
            .digest()
            .as_bytes()
            .as_slice(),
    )
    .bind(schemas.runtime_context_i16)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn load_materialized_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    instance_id: LogicalWorkflowInstanceId,
    descriptor: &LogicalInstanceMaterializationDescriptor,
    durable: &DurableMaterializationClaim,
    replayed: bool,
) -> Result<LogicalMaterializationReceipt, LogicalMaterializationStoreError> {
    let row = sqlx::query(receipt_query())
        .bind(instance_id.as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?
        .ok_or_else(|| {
            StoreError::corrupt_data("materialized logical claim has no concrete-job receipt")
        })?;
    decode_receipt(&row, descriptor, durable, None, replayed)
}

async fn verify_exact_materialized_commit(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitLogicalInstanceMaterialization,
    descriptor: &LogicalInstanceMaterializationDescriptor,
    durable: &DurableMaterializationClaim,
) -> Result<(), LogicalMaterializationStoreError> {
    let exact_fence = durable.owner_id == request.claim().owner().as_uuid()
        && durable.generation == pg_bigint(request.claim().generation().get())
        && durable.claimed_at == request.claim().claimed_at().get()
        && durable.expires_at == request.claim().expires_at().get()
        && durable.descriptor_digest == request.claim().descriptor_digest()
        && durable.runtime_policy_revision == request.claim().runtime_policy().revision()
        && durable.runtime_policy_digest == request.claim().runtime_policy().digest()
        && durable.expected_job_id == request.claim().expected_job_id()
        && durable.expected_attempt_id == request.claim().expected_attempt_id();
    if !exact_fence {
        return Err(LogicalMaterializationStoreError::ClaimRejected);
    }
    let row = sqlx::query(receipt_query())
        .bind(request.claim().target().instance_id().as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?
        .ok_or_else(|| {
            StoreError::corrupt_data("materialized logical claim has no concrete-job receipt")
        })?;
    let requested_log_visibility =
        decode_requested_log_visibility(&row, "run_requested_log_visibility")?;
    let expected_safety = CurrentAttemptOutputSafety::for_authority_profile(
        request.authority_profile(),
        &requested_log_visibility,
    )
    .ok_or_else(|| {
        StoreError::corrupt_data("workflow run log publication snapshot is malformed")
    })?;
    let _ = decode_receipt(&row, descriptor, durable, Some(expected_safety), true)?;
    let exact = decode_digest(&row, "commit_digest")? == request.commit_digest()
        && decode_digest(&row, "requirements_digest")? == request.requirements_digest()
        && row
            .try_get::<String, _>("job_key")
            .map_err(operation_error)?
            == request.job_key()
        && row
            .try_get::<String, _>("display_name")
            .map_err(operation_error)?
            == request.display_name()
        && row
            .try_get::<serde_json::Value, _>("requirements")
            .map_err(operation_error)?
            == *automata_ci_store::adapter_spi::logical_materialization_requirements_json(request)
        && row
            .try_get::<i64, _>("committed_at_ms")
            .map_err(operation_error)?
            == request.committed_at().get();
    if exact {
        Ok(())
    } else {
        Err(LogicalMaterializationStoreError::CommitConflict)
    }
}

fn receipt_query() -> &'static str {
    r"
    SELECT concrete.instance_id, concrete.run_id AS receipt_run_id,
           concrete.invocation_id AS receipt_invocation_id,
           concrete.logical_job_id AS receipt_logical_job_id,
           concrete.job_id, concrete.initial_attempt_id,
           concrete.descriptor_digest, concrete.requirements_digest,
           concrete.commit_digest, concrete.job_key, concrete.display_name,
           concrete.requirements, concrete.authority_profile,
           concrete.event_digest,
           concrete.event_object_key, concrete.event_size_bytes,
           concrete.event_media_type, concrete.runtime_context_digest,
           concrete.runtime_context_object_key,
           concrete.runtime_context_size_bytes,
           concrete.runtime_context_media_type,
           concrete.runtime_context_schema, concrete.claim_owner_id,
           concrete.claim_generation, concrete.claim_started_at_ms,
           concrete.claim_expires_at_ms, concrete.committed_at_ms,
           concrete.runtime_policy_revision,
           concrete.runtime_policy_digest,
           job.run_id AS concrete_run_id, job.job_ir_digest,
           job.job_ir_object_key, job.job_ir_size_bytes, job.job_ir_schema,
           job.admission_epoch, job.job_key AS runnable_job_key,
           job.display_name AS runnable_display_name,
           job.requirements AS job_requirements,
           run.requested_log_visibility AS run_requested_log_visibility,
           attempt.job_id AS attempt_job_id,
           attempt.attempt_number, attempt.lifecycle,
           attempt.queued_at_ms, attempt.changed_at_ms,
           attempt.secret_exposure_class, attempt.raw_log_disposition,
           attempt.requested_log_visibility, attempt.effective_log_visibility,
           attempt.output_safety_reason, attempt.output_safety_schema,
           attempt.classified_at_ms
    FROM logical_workflow_concrete_jobs AS concrete
    JOIN jobs AS job ON job.id = concrete.job_id
    JOIN workflow_runs AS run ON run.id = job.run_id
    JOIN job_attempts AS attempt ON attempt.id = concrete.initial_attempt_id
    WHERE concrete.instance_id = $1
    "
}

#[allow(clippy::too_many_lines)] // One exact relational receipt comparison is intentionally atomic.
fn decode_receipt(
    row: &PgRow,
    descriptor: &LogicalInstanceMaterializationDescriptor,
    durable: &DurableMaterializationClaim,
    expected_safety: Option<CurrentAttemptOutputSafety>,
    replayed: bool,
) -> Result<LogicalMaterializationReceipt, LogicalMaterializationStoreError> {
    let instance_id =
        LogicalWorkflowInstanceId::from_uuid(row.try_get("instance_id").map_err(operation_error)?)
            .map_err(corrupt_value)?;
    let job_id = JobId::from_uuid(row.try_get("job_id").map_err(operation_error)?);
    let attempt_id =
        AttemptId::from_uuid(row.try_get("initial_attempt_id").map_err(operation_error)?);
    let descriptor_digest = decode_digest(row, "descriptor_digest")?;
    let runtime_policy_revision = decode_runtime_policy_revision(row, "runtime_policy_revision")?;
    let runtime_policy_digest = decode_digest(row, "runtime_policy_digest")?;
    let requirements_digest = decode_digest(row, "requirements_digest")?;
    let commit_digest = decode_digest(row, "commit_digest")?;
    let committed_at = UnixMillis::new(row.try_get("committed_at_ms").map_err(operation_error)?);
    let run_requested_log_visibility =
        decode_requested_log_visibility(row, "run_requested_log_visibility")?;
    let attempt_safety = CurrentAttemptOutputSafety::from_durable(
        &row.try_get::<String, _>("secret_exposure_class")
            .map_err(operation_error)?,
        &row.try_get::<String, _>("raw_log_disposition")
            .map_err(operation_error)?,
        &row.try_get::<String, _>("requested_log_visibility")
            .map_err(operation_error)?,
        &row.try_get::<String, _>("effective_log_visibility")
            .map_err(operation_error)?,
        &row.try_get::<String, _>("output_safety_reason")
            .map_err(operation_error)?,
        row.try_get("output_safety_schema")
            .map_err(operation_error)?,
    )
    .filter(|safety| {
        safety.requested_log_visibility() == run_requested_log_visibility.as_str()
            && safety.supports_current_authority_profile()
            && expected_safety.is_none_or(|expected| expected == *safety)
    })
    .ok_or_else(|| {
        StoreError::corrupt_data("logical attempt output-safety snapshot is inconsistent")
    })?;
    let authority_profile = match attempt_safety.secret_exposure_class() {
        "readable_secret" => JobAuthorityProfile::Standard,
        "secretless" => JobAuthorityProfile::CredentialFree,
        _ => {
            return Err(StoreError::corrupt_data(
                "logical attempt safety has no materialization authority profile",
            )
            .into());
        }
    };
    let durable_authority_profile = parse_authority_profile(
        &row.try_get::<String, _>("authority_profile")
            .map_err(operation_error)?,
    )?;
    let requirements: serde_json::Value = row.try_get("requirements").map_err(operation_error)?;
    let requirements_bytes = serde_json::to_vec(&requirements).map_err(|_| {
        StoreError::corrupt_data("logical materialization requirements are not canonical JSON")
    })?;
    let expected_requirements_digest =
        Sha256Digest::from_bytes(Sha256::digest(&requirements_bytes).into());
    let job_key: String = row.try_get("job_key").map_err(operation_error)?;
    let display_name: String = row.try_get("display_name").map_err(operation_error)?;
    let expected_commit_digest = rederive_materialization_commit_digest(
        descriptor,
        durable,
        &job_key,
        &display_name,
        &requirements_bytes,
        authority_profile,
        committed_at,
    )?;
    let lifecycle: String = row.try_get("lifecycle").map_err(operation_error)?;
    let changed_at = UnixMillis::new(row.try_get("changed_at_ms").map_err(operation_error)?);
    let exact = instance_id == descriptor.target().instance_id()
        && authority_profile == descriptor.authority_profile()
        && durable_authority_profile == descriptor.authority_profile()
        && job_id == descriptor.expected_job_id()
        && attempt_id == descriptor.expected_attempt_id()
        && descriptor_digest == descriptor.descriptor_digest()
        && runtime_policy_revision == descriptor.runtime_policy().revision()
        && runtime_policy_revision == durable.runtime_policy_revision
        && runtime_policy_digest == descriptor.runtime_policy().digest()
        && runtime_policy_digest == durable.runtime_policy_digest
        && job_key == descriptor.job_key()
        && requirements_digest == expected_requirements_digest
        && commit_digest == expected_commit_digest
        && row
            .try_get::<Uuid, _>("receipt_run_id")
            .map_err(operation_error)?
            == descriptor.target().run_id().as_uuid()
        && row
            .try_get::<Uuid, _>("receipt_invocation_id")
            .map_err(operation_error)?
            == descriptor.target().invocation_id().as_uuid()
        && row
            .try_get::<Uuid, _>("receipt_logical_job_id")
            .map_err(operation_error)?
            == descriptor.target().logical_job_id().as_uuid()
        && row
            .try_get::<Uuid, _>("claim_owner_id")
            .map_err(operation_error)?
            == durable.owner_id
        && row
            .try_get::<i64, _>("claim_generation")
            .map_err(operation_error)?
            == durable.generation
        && row
            .try_get::<i64, _>("claim_started_at_ms")
            .map_err(operation_error)?
            == durable.claimed_at
        && row
            .try_get::<i64, _>("claim_expires_at_ms")
            .map_err(operation_error)?
            == durable.expires_at
        && committed_at.get() == durable.updated_at
        && row
            .try_get::<Uuid, _>("concrete_run_id")
            .map_err(operation_error)?
            == descriptor.target().run_id().as_uuid()
        && decode_digest(row, "job_ir_digest")? == descriptor.job_ir().digest()
        && row
            .try_get::<String, _>("job_ir_object_key")
            .map_err(operation_error)?
            == descriptor.job_ir().object_key().as_str()
        && row
            .try_get::<i64, _>("job_ir_size_bytes")
            .map_err(operation_error)?
            == i64::try_from(descriptor.job_ir().encoded_size()).unwrap_or(i64::MAX)
        && row
            .try_get::<i32, _>("job_ir_schema")
            .map_err(operation_error)?
            == i32::from(JOB_IR_SCHEMA_VERSION)
        && row
            .try_get::<i32, _>("admission_epoch")
            .map_err(operation_error)?
            == 1
        && row
            .try_get::<serde_json::Value, _>("job_requirements")
            .map_err(operation_error)?
            == requirements
        && row
            .try_get::<String, _>("runnable_job_key")
            .map_err(operation_error)?
            == job_key
        && row
            .try_get::<String, _>("runnable_display_name")
            .map_err(operation_error)?
            == display_name
        && decode_digest(row, "event_digest")? == descriptor.event().digest()
        && row
            .try_get::<String, _>("event_object_key")
            .map_err(operation_error)?
            == descriptor.event().object_key().as_str()
        && row
            .try_get::<i64, _>("event_size_bytes")
            .map_err(operation_error)?
            == i64::try_from(descriptor.event().encoded_size()).unwrap_or(i64::MAX)
        && row
            .try_get::<String, _>("event_media_type")
            .map_err(operation_error)?
            == descriptor.event().media_type()
        && decode_digest(row, "runtime_context_digest")? == descriptor.runtime_context().digest()
        && row
            .try_get::<String, _>("runtime_context_object_key")
            .map_err(operation_error)?
            == descriptor.runtime_context().object_key().as_str()
        && row
            .try_get::<i64, _>("runtime_context_size_bytes")
            .map_err(operation_error)?
            == i64::try_from(descriptor.runtime_context().encoded_size()).unwrap_or(i64::MAX)
        && row
            .try_get::<String, _>("runtime_context_media_type")
            .map_err(operation_error)?
            == descriptor.runtime_context().media_type()
        && row
            .try_get::<i16, _>("runtime_context_schema")
            .map_err(operation_error)?
            == i16::try_from(JOB_RUNTIME_CONTEXT_SCHEMA_VERSION).unwrap_or(i16::MAX)
        && row
            .try_get::<Uuid, _>("attempt_job_id")
            .map_err(operation_error)?
            == job_id.as_uuid()
        && row
            .try_get::<i32, _>("attempt_number")
            .map_err(operation_error)?
            == 1
        && is_current_attempt_lifecycle(&lifecycle)
        && row
            .try_get::<i64, _>("queued_at_ms")
            .map_err(operation_error)?
            == committed_at.get()
        && changed_at >= committed_at
        && row
            .try_get::<i64, _>("classified_at_ms")
            .map_err(operation_error)?
            == committed_at.get();
    if !exact {
        return Err(StoreError::corrupt_data(
            "concrete logical job receipt disagrees with durable execution state",
        )
        .into());
    }
    LogicalMaterializationReceipt::from_durable(
        instance_id,
        job_id,
        attempt_id,
        descriptor_digest,
        runtime_policy_revision,
        runtime_policy_digest,
        requirements_digest,
        commit_digest,
        committed_at,
        replayed,
    )
    .map_err(corrupt_value)
}

#[allow(clippy::too_many_arguments)] // The digest authenticates each independent receipt field.
fn rederive_materialization_commit_digest(
    descriptor: &LogicalInstanceMaterializationDescriptor,
    durable: &DurableMaterializationClaim,
    job_key: &str,
    display_name: &str,
    requirements: &[u8],
    authority_profile: JobAuthorityProfile,
    committed_at: UnixMillis,
) -> Result<Sha256Digest, LogicalMaterializationStoreError> {
    let generation = u64::try_from(durable.generation).map_err(|_| {
        StoreError::corrupt_data("logical materialization generation does not fit u64")
    })?;
    let mut hasher = Sha256::new();
    hasher.update(MATERIALIZATION_COMMIT_DIGEST_DOMAIN);
    hasher.update(descriptor.target().instance_id().as_uuid().as_bytes());
    hasher.update(durable.owner_id.as_bytes());
    hasher.update(generation.to_be_bytes());
    hasher.update(descriptor.descriptor_digest().as_bytes());
    hasher.update(
        descriptor
            .runtime_policy()
            .repository_id()
            .as_uuid()
            .as_bytes(),
    );
    hasher.update(descriptor.runtime_policy().revision().get().to_be_bytes());
    hasher.update(descriptor.runtime_policy().digest().as_bytes());
    hasher.update(descriptor.expected_job_id().as_uuid().as_bytes());
    hasher.update(descriptor.expected_attempt_id().as_uuid().as_bytes());
    hash_materialization_text(&mut hasher, job_key);
    hash_materialization_text(&mut hasher, display_name);
    hash_materialization_bytes(&mut hasher, requirements);
    hasher.update([match authority_profile {
        JobAuthorityProfile::Standard => 1,
        JobAuthorityProfile::CredentialFree => 2,
    }]);
    hasher.update(committed_at.get().to_be_bytes());
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

fn hash_materialization_text(hasher: &mut Sha256, value: &str) {
    hash_materialization_bytes(hasher, value.as_bytes());
}

fn hash_materialization_bytes(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn is_current_attempt_lifecycle(value: &str) -> bool {
    matches!(
        value,
        "queued"
            | "leased"
            | "preparing"
            | "running"
            | "cancelling"
            | "finalizing"
            | "succeeded"
            | "failed"
            | "cancelled"
            | "timed_out"
            | "skipped"
            | "lost"
    )
}

fn decode_runtime_policy_revision(
    row: &PgRow,
    column: &str,
) -> Result<WorkflowRuntimePolicyRevision, LogicalMaterializationStoreError> {
    let value: i64 = row.try_get(column).map_err(operation_error)?;
    u64::try_from(value)
        .ok()
        .and_then(|value| WorkflowRuntimePolicyRevision::new(value).ok())
        .ok_or_else(|| StoreError::corrupt_data("invalid runtime-policy revision").into())
}

fn decode_digest(
    row: &PgRow,
    column: &str,
) -> Result<Sha256Digest, LogicalMaterializationStoreError> {
    let value: Vec<u8> = row.try_get(column).map_err(operation_error)?;
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| StoreError::corrupt_data(format!("{column} is not SHA-256")))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn corrupt_value(error: impl std::fmt::Display) -> LogicalMaterializationStoreError {
    StoreError::corrupt_data(format!("invalid logical materialization value: {error}")).into()
}

fn operation_error(error: sqlx::Error) -> LogicalMaterializationStoreError {
    StoreError::operation(error).into()
}
