use async_trait::async_trait;
use automata_ci_core::{
    AttemptId, CORE_SCHEMA_VERSION, JOB_IR_SCHEMA_VERSION, JobConclusion, JobId, JobSecretExposure,
    OperationId, OutputSensitivity, RunId, Sha256Digest, UnixMillis, WorkflowJobKey,
};
use sqlx::{PgPool, Postgres, Row as _, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::PostgresStore;
use crate::{
    ClaimLogicalInstanceResult, ClaimNextLogicalInstanceResult, ClaimedLogicalInstanceResult,
    CommitLogicalInstanceResult, LOGICAL_ACTIVATION_JOB_IR_MEDIA_TYPE,
    LOGICAL_INSTANCE_RESULT_MEDIA_TYPE, LogicalActivationObject, LogicalInstanceResultClaimFence,
    LogicalInstanceResultClaimNextOutcome, LogicalInstanceResultClaimOutcome,
    LogicalInstanceResultDescriptor, LogicalInstanceResultGeneration, LogicalInstanceResultOutput,
    LogicalInstanceResultQuarantineKind, LogicalInstanceResultQuarantineOutcome,
    LogicalInstanceResultReceipt, LogicalInstanceResultRepository, LogicalInstanceResultStoreError,
    LogicalInstanceResultTarget, LogicalInstanceResultWorkerId, LogicalInstanceTerminalOrdinal,
    LogicalServerCancellationTerminal, LogicalTerminalResultObject, LogicalWorkflowInstanceId,
    LogicalWorkflowInvocationId, LogicalWorkflowJobId, ObjectKey, QuarantineLogicalInstanceResult,
    StoreError, TenantScope,
    logical_instance_result::{output_set_digest, rederive_commit_digest},
};

const MAX_SELECTION_CLOCK_SKEW_MILLIS: i64 = 60_000;

#[async_trait]
impl LogicalInstanceResultRepository for PostgresStore {
    async fn claim_next_logical_instance_result(
        &self,
        request: ClaimNextLogicalInstanceResult,
    ) -> Result<LogicalInstanceResultClaimNextOutcome, LogicalInstanceResultStoreError> {
        reserve_selection_request(self, &request).await?;
        let mut transaction = begin_read_committed(&self.pool).await?;
        if let Some(outcome) = reserve_or_replay_selection(&mut transaction, &request).await? {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(outcome);
        }

        let database_now = database_now_ms(&mut transaction).await?;
        if request.expires_at().get() <= database_now {
            return Err(LogicalInstanceResultStoreError::SelectionExpired);
        }
        let eligible_at = request.observed_at().get().min(database_now);
        let Some(candidate) =
            lock_next_target(&mut transaction, UnixMillis::new(eligible_at)).await?
        else {
            finalize_idle_selection(&mut transaction, &request).await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(LogicalInstanceResultClaimNextOutcome::Idle);
        };
        let outcome = match claim_selected_target(&mut transaction, &request, &candidate).await {
            Ok(outcome) => outcome,
            Err(error) if is_quarantinable_relational_error(&error) => {
                quarantine_locked_candidate(&mut transaction, &candidate).await?;
                finalize_quarantined_selection(&mut transaction, &request, &candidate).await?;
                transaction.commit().await.map_err(operation_error)?;
                return Ok(LogicalInstanceResultClaimNextOutcome::Quarantined);
            }
            Err(error) => return Err(error),
        };
        let claimed = match outcome {
            LogicalInstanceResultClaimOutcome::Claimed(claimed) => claimed,
            LogicalInstanceResultClaimOutcome::Busy
            | LogicalInstanceResultClaimOutcome::Finalized(_) => {
                finalize_idle_selection(&mut transaction, &request).await?;
                transaction.commit().await.map_err(operation_error)?;
                return Ok(LogicalInstanceResultClaimNextOutcome::Idle);
            }
        };
        finalize_claimed_selection(&mut transaction, &request, &claimed).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(LogicalInstanceResultClaimNextOutcome::Claimed(claimed))
    }

    async fn claim_logical_instance_result(
        &self,
        request: ClaimLogicalInstanceResult,
    ) -> Result<LogicalInstanceResultClaimOutcome, LogicalInstanceResultStoreError> {
        let mut transaction = begin_read_committed(&self.pool).await?;
        lock_due_target(&mut transaction, request.target().attempt_id()).await?;
        let row = lock_target(&mut transaction, request.target())
            .await?
            .ok_or(LogicalInstanceResultStoreError::InvalidTarget)?;
        let descriptor = decode_descriptor(request.target().clone(), &row)?;
        let durable = load_durable_claim(&mut transaction, request.target()).await?;
        validate_target_state(&row, durable.as_ref())?;
        let database_now = database_now_ms(&mut transaction).await?;
        if let Some(durable) = durable {
            let outcome = resolve_durable_claim(
                &mut transaction,
                &request,
                descriptor,
                durable,
                database_now,
                ClaimClockAdmission::Required,
            )
            .await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(outcome);
        }
        validate_new_claim_time(&request, &descriptor, database_now)?;
        let outcome = insert_initial_claim(&mut transaction, &request, descriptor).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(outcome)
    }

    async fn commit_logical_instance_result(
        &self,
        request: CommitLogicalInstanceResult,
    ) -> Result<LogicalInstanceResultReceipt, LogicalInstanceResultStoreError> {
        let mut transaction = begin_read_committed(&self.pool).await?;
        lock_due_target(&mut transaction, request.claim().target().attempt_id()).await?;
        let row = lock_commit_target(&mut transaction, request.claim().target())
            .await?
            .ok_or(LogicalInstanceResultStoreError::InvalidTarget)?;
        let descriptor = decode_descriptor(request.claim().target().clone(), &row)?;
        let durable = load_durable_claim(&mut transaction, request.claim().target())
            .await?
            .ok_or(LogicalInstanceResultStoreError::ClaimRejected)?;
        validate_target_state(&row, Some(&durable))?;
        durable.verify_descriptor(&descriptor)?;
        let database_now = database_now_ms(&mut transaction).await?;

        if durable.state == "finalized" {
            verify_exact_finalized_commit(&mut transaction, &request, &descriptor, &durable)
                .await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(LogicalInstanceResultReceipt::new(
                &request,
                &descriptor,
                true,
            ));
        }
        if database_now >= durable.expires_at {
            return Err(LogicalInstanceResultStoreError::ClaimExpired);
        }
        if !durable.matches_fence(request.claim())
            || database_now < durable.claimed_at
            || request.finalized_at().get() < durable.claimed_at
            || request.finalized_at().get() >= durable.expires_at
        {
            return Err(LogicalInstanceResultStoreError::ClaimRejected);
        }

        insert_instance_result(&mut transaction, &request, &descriptor).await?;
        insert_outputs(&mut transaction, &request, &descriptor).await?;
        let rows = sqlx::query(
            r"
            UPDATE workflow_plan_v2_instance_result_claims
            SET state = 'finalized', updated_at_ms = $8
            WHERE attempt_id = $1
              AND state = 'projecting'
              AND owner_id = $2
              AND generation = $3
              AND descriptor_digest = $4
              AND claimed_at_ms = $5
              AND expires_at_ms = $6
              AND instance_id = $7
            ",
        )
        .bind(request.claim().target().attempt_id().as_uuid())
        .bind(request.claim().owner().as_uuid())
        .bind(request.claim().generation().as_i64())
        .bind(request.claim().descriptor_digest().as_bytes().as_slice())
        .bind(request.claim().claimed_at().get())
        .bind(request.claim().expires_at().get())
        .bind(descriptor.instance_id().as_uuid())
        .bind(request.finalized_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?
        .rows_affected();
        if rows != 1 {
            return Err(StoreError::corrupt_data(
                "locked logical instance-result claim disappeared during finalization",
            )
            .into());
        }
        transaction.commit().await.map_err(operation_error)?;
        Ok(LogicalInstanceResultReceipt::new(
            &request,
            &descriptor,
            false,
        ))
    }

    async fn quarantine_logical_instance_result(
        &self,
        request: QuarantineLogicalInstanceResult,
    ) -> Result<LogicalInstanceResultQuarantineOutcome, LogicalInstanceResultStoreError> {
        let mut transaction = begin_read_committed(&self.pool).await?;
        let outcome = quarantine_claimed_target(&mut transaction, &request).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(outcome)
    }
}

async fn begin_read_committed(
    pool: &PgPool,
) -> Result<Transaction<'_, Postgres>, LogicalInstanceResultStoreError> {
    let mut transaction = pool.begin().await.map_err(operation_error)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
    Ok(transaction)
}

async fn database_now_ms(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<i64, LogicalInstanceResultStoreError> {
    sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
        .fetch_one(&mut **transaction)
        .await
        .map_err(operation_error)
}

#[derive(Clone, Copy)]
enum ClaimClockAdmission {
    Required,
    PrevalidatedSelection,
}

fn validate_new_claim_time(
    request: &ClaimLogicalInstanceResult,
    descriptor: &LogicalInstanceResultDescriptor,
    database_now: i64,
) -> Result<(), LogicalInstanceResultStoreError> {
    if request.observed_at() < descriptor.result_committed_at() {
        return Err(LogicalInstanceResultStoreError::InvalidTarget);
    }
    if request.observed_at().get() < database_now.saturating_sub(MAX_SELECTION_CLOCK_SKEW_MILLIS)
        || request.observed_at().get()
            > database_now.saturating_add(MAX_SELECTION_CLOCK_SKEW_MILLIS)
    {
        return Err(LogicalInstanceResultStoreError::ClaimClockSkew);
    }
    if request.expires_at().get() <= database_now {
        return Err(LogicalInstanceResultStoreError::ClaimExpired);
    }
    Ok(())
}

fn validate_prevalidated_selection_time(
    request: &ClaimLogicalInstanceResult,
    descriptor: &LogicalInstanceResultDescriptor,
    database_now: i64,
) -> Result<(), LogicalInstanceResultStoreError> {
    if request.observed_at() < descriptor.result_committed_at() {
        return Err(LogicalInstanceResultStoreError::InvalidTarget);
    }
    if request.expires_at().get() <= database_now {
        return Err(LogicalInstanceResultStoreError::SelectionExpired);
    }
    Ok(())
}

async fn claim_selected_target(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalInstanceResult,
    candidate: &PgRow,
) -> Result<LogicalInstanceResultClaimOutcome, LogicalInstanceResultStoreError> {
    let tenant = TenantScope::from_authenticated_tenant_id(
        candidate
            .try_get::<String, _>("repository_tenant_id")
            .map_err(operation_error)?,
    )
    .map_err(corrupt_value)?;
    let target = LogicalInstanceResultTarget::new(
        tenant,
        AttemptId::from_uuid(
            candidate
                .try_get::<Uuid, _>("terminal_attempt_id")
                .map_err(operation_error)?,
        ),
    )
    .map_err(corrupt_value)?;
    let row = lock_target(transaction, &target)
        .await?
        .ok_or_else(|| StoreError::corrupt_data("locked due instance target disappeared"))?;
    let descriptor = decode_descriptor(target.clone(), &row)?;
    let targeted = ClaimLogicalInstanceResult::new(
        target,
        request.owner(),
        request.observed_at(),
        request.expires_at(),
    )
    .map_err(corrupt_value)?;
    let durable = load_durable_claim(transaction, targeted.target()).await?;
    validate_target_state(&row, durable.as_ref())?;
    let database_now = database_now_ms(transaction).await?;
    if let Some(durable) = durable {
        resolve_durable_claim(
            transaction,
            &targeted,
            descriptor,
            durable,
            database_now,
            ClaimClockAdmission::PrevalidatedSelection,
        )
        .await
    } else {
        validate_prevalidated_selection_time(&targeted, &descriptor, database_now)?;
        insert_initial_claim(transaction, &targeted, descriptor).await
    }
}

async fn insert_initial_claim(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimLogicalInstanceResult,
    descriptor: LogicalInstanceResultDescriptor,
) -> Result<LogicalInstanceResultClaimOutcome, LogicalInstanceResultStoreError> {
    let inserted = sqlx::query(
        r"
        INSERT INTO workflow_plan_v2_instance_result_claims (
            attempt_id, run_id, invocation_id, logical_job_id, instance_id,
            job_id, descriptor_digest, state, owner_id, generation,
            claimed_at_ms, expires_at_ms, created_at_ms, updated_at_ms
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,'projecting',$8,1,$9,$10,$9,$9)
        ON CONFLICT (attempt_id) DO NOTHING
        ",
    )
    .bind(descriptor.target().attempt_id().as_uuid())
    .bind(descriptor.run_id().as_uuid())
    .bind(descriptor.invocation_id().as_uuid())
    .bind(descriptor.logical_job_id().as_uuid())
    .bind(descriptor.instance_id().as_uuid())
    .bind(descriptor.job_id().as_uuid())
    .bind(descriptor.descriptor_digest().as_bytes().as_slice())
    .bind(request.owner().as_uuid())
    .bind(request.observed_at().get())
    .bind(request.expires_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if inserted != 1 {
        return Err(StoreError::corrupt_data(
            "locked logical instance-result target produced a claim conflict",
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
    )?;
    ClaimedLogicalInstanceResult::new(descriptor, claim, false)
        .map(LogicalInstanceResultClaimOutcome::Claimed)
        .map_err(corrupt_value)
}

#[allow(clippy::too_many_lines)]
async fn reserve_or_replay_selection(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalInstanceResult,
) -> Result<Option<LogicalInstanceResultClaimNextOutcome>, LogicalInstanceResultStoreError> {
    let selection = lock_selection_request(transaction, request).await?;
    let owner_id: Uuid = selection.try_get("owner_id").map_err(operation_error)?;
    let claimed_at: i64 = selection
        .try_get("claimed_at_ms")
        .map_err(operation_error)?;
    let expires_at: i64 = selection
        .try_get("expires_at_ms")
        .map_err(operation_error)?;
    if owner_id != request.owner().as_uuid()
        || claimed_at != request.observed_at().get()
        || expires_at != request.expires_at().get()
    {
        return Err(LogicalInstanceResultStoreError::SelectionConflict);
    }
    if expires_at <= database_now_ms(transaction).await? {
        return Err(LogicalInstanceResultStoreError::SelectionExpired);
    }
    let outcome: String = selection.try_get("outcome").map_err(operation_error)?;
    if outcome == "selecting" {
        return Ok(None);
    }
    if outcome == "idle" {
        return Ok(Some(LogicalInstanceResultClaimNextOutcome::Idle));
    }
    if outcome == "quarantined" {
        let tenant_id = selection
            .try_get::<Option<String>, _>("tenant_id")
            .map_err(operation_error)?
            .ok_or_else(|| StoreError::corrupt_data("quarantined selection lacks tenant"))?;
        let attempt_id = selection
            .try_get::<Option<Uuid>, _>("attempt_id")
            .map_err(operation_error)?
            .ok_or_else(|| StoreError::corrupt_data("quarantined selection lacks attempt"))?;
        if selection
            .try_get::<Option<i64>, _>("generation")
            .map_err(operation_error)?
            .is_some()
        {
            return Err(StoreError::corrupt_data(
                "quarantined selection unexpectedly carries a claim generation",
            )
            .into());
        }
        let exists: bool = sqlx::query_scalar(
            r"
            SELECT EXISTS (
                SELECT 1
                FROM workflow_plan_v2_instance_result_quarantines
                WHERE attempt_id = $1 AND tenant_id = $2
            )
            ",
        )
        .bind(attempt_id)
        .bind(tenant_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(operation_error)?;
        if !exists {
            return Err(StoreError::corrupt_data(
                "quarantined selection has no durable quarantine evidence",
            )
            .into());
        }
        return Ok(Some(LogicalInstanceResultClaimNextOutcome::Quarantined));
    }
    if outcome != "claimed" {
        return Err(StoreError::corrupt_data("invalid instance-result selection outcome").into());
    }
    let tenant = TenantScope::from_authenticated_tenant_id(
        selection
            .try_get::<Option<String>, _>("tenant_id")
            .map_err(operation_error)?
            .ok_or_else(|| StoreError::corrupt_data("claimed selection lacks tenant"))?,
    )
    .map_err(corrupt_value)?;
    let target = LogicalInstanceResultTarget::new(
        tenant,
        AttemptId::from_uuid(
            selection
                .try_get::<Option<Uuid>, _>("attempt_id")
                .map_err(operation_error)?
                .ok_or_else(|| StoreError::corrupt_data("claimed selection lacks attempt"))?,
        ),
    )
    .map_err(corrupt_value)?;
    let row = lock_target(transaction, &target)
        .await?
        .ok_or_else(|| StoreError::corrupt_data("instance selection target disappeared"))?;
    let descriptor = decode_descriptor(target.clone(), &row)?;
    let durable = load_durable_claim(transaction, &target)
        .await?
        .ok_or_else(|| StoreError::corrupt_data("instance selection has no durable claim"))?;
    validate_target_state(&row, Some(&durable))?;
    durable.verify_descriptor(&descriptor)?;
    let generation: i64 = selection
        .try_get::<Option<i64>, _>("generation")
        .map_err(operation_error)?
        .ok_or_else(|| StoreError::corrupt_data("claimed selection lacks generation"))?;
    if durable.generation != generation
        || durable.owner_id != owner_id
        || durable.claimed_at != claimed_at
        || durable.expires_at != expires_at
    {
        return Err(StoreError::corrupt_data(
            "instance selection disagrees with its claim generation",
        )
        .into());
    }
    if durable.state == "finalized" {
        return load_finalized_receipt(transaction, &descriptor, true)
            .await
            .map(LogicalInstanceResultClaimNextOutcome::Finalized)
            .map(Some);
    }
    claimed_from_durable(descriptor, &durable, true)
        .map(LogicalInstanceResultClaimNextOutcome::Claimed)
        .map(Some)
}

async fn lock_selection_request(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalInstanceResult,
) -> Result<PgRow, LogicalInstanceResultStoreError> {
    let selection = sqlx::query(
        r"
        SELECT owner_id, claimed_at_ms, expires_at_ms, outcome,
               tenant_id, attempt_id, generation
        FROM workflow_plan_v2_instance_result_selections
        WHERE selection_id = $1
        FOR UPDATE
        ",
    )
    .bind(request.selection_id().as_uuid())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(selection)
}

async fn lock_selection_request_optional(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalInstanceResult,
) -> Result<Option<PgRow>, LogicalInstanceResultStoreError> {
    sqlx::query(
        r"
        SELECT owner_id, claimed_at_ms, expires_at_ms, outcome,
               tenant_id, attempt_id, generation
        FROM workflow_plan_v2_instance_result_selections
        WHERE selection_id = $1
        FOR UPDATE
        ",
    )
    .bind(request.selection_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

fn verify_selection_identity(
    selection: &PgRow,
    request: &ClaimNextLogicalInstanceResult,
) -> Result<(), LogicalInstanceResultStoreError> {
    let owner_id: Uuid = selection.try_get("owner_id").map_err(operation_error)?;
    let claimed_at: i64 = selection
        .try_get("claimed_at_ms")
        .map_err(operation_error)?;
    let expires_at: i64 = selection
        .try_get("expires_at_ms")
        .map_err(operation_error)?;
    if owner_id == request.owner().as_uuid()
        && claimed_at == request.observed_at().get()
        && expires_at == request.expires_at().get()
    {
        Ok(())
    } else {
        Err(LogicalInstanceResultStoreError::SelectionConflict)
    }
}

async fn accept_live_selection_reservation_replay(
    transaction: &mut Transaction<'_, Postgres>,
    selection: &PgRow,
    request: &ClaimNextLogicalInstanceResult,
) -> Result<(), LogicalInstanceResultStoreError> {
    verify_selection_identity(selection, request)?;
    let database_now = database_now_ms(transaction).await?;
    if request.expires_at().get() <= database_now {
        return Err(LogicalInstanceResultStoreError::SelectionExpired);
    }
    Ok(())
}

async fn reserve_selection_request(
    store: &PostgresStore,
    request: &ClaimNextLogicalInstanceResult,
) -> Result<(), LogicalInstanceResultStoreError> {
    let mut transaction = begin_read_committed(&store.pool).await?;
    if let Some(selection) = lock_selection_request_optional(&mut transaction, request).await? {
        accept_live_selection_reservation_replay(&mut transaction, &selection, request).await?;
        transaction.commit().await.map_err(operation_error)?;
        return Ok(());
    }

    let floor: i64 = sqlx::query_scalar(
        r"
        SELECT replay_floor_ms
        FROM workflow_plan_v2_result_selection_replay_horizons
        WHERE queue_name = 'instance'
        FOR UPDATE
        ",
    )
    .fetch_one(&mut *transaction)
    .await
    .map_err(operation_error)?;
    let database_now = database_now_ms(&mut transaction).await?;
    if let Some(selection) = lock_selection_request_optional(&mut transaction, request).await? {
        accept_live_selection_reservation_replay(&mut transaction, &selection, request).await?;
        transaction.commit().await.map_err(operation_error)?;
        return Ok(());
    }
    if request.observed_at().get() < database_now.saturating_sub(MAX_SELECTION_CLOCK_SKEW_MILLIS)
        || request.observed_at().get()
            > database_now.saturating_add(MAX_SELECTION_CLOCK_SKEW_MILLIS)
    {
        return Err(LogicalInstanceResultStoreError::SelectionClockSkew);
    }
    if request.expires_at().get() <= floor || request.expires_at().get() <= database_now {
        return Err(LogicalInstanceResultStoreError::SelectionExpired);
    }
    let horizon_rows = sqlx::query(
        r"
        UPDATE workflow_plan_v2_result_selection_replay_horizons
        SET replay_floor_ms = $1, updated_at_ms = $1
        WHERE queue_name = 'instance'
        ",
    )
    .bind(database_now)
    .execute(&mut *transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if horizon_rows != 1 {
        return Err(StoreError::corrupt_data(
            "instance-result replay horizon disappeared while locked",
        )
        .into());
    }
    sqlx::query(
        r"
        WITH expired AS (
            SELECT selection_id
            FROM workflow_plan_v2_instance_result_selections
            WHERE expires_at_ms <= $1
            ORDER BY expires_at_ms, selection_id
            FOR UPDATE SKIP LOCKED
            LIMIT 1024
        )
        DELETE FROM workflow_plan_v2_instance_result_selections AS selection
        USING expired
        WHERE selection.selection_id = expired.selection_id
        ",
    )
    .bind(database_now)
    .execute(&mut *transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    let inserted = sqlx::query(
        r"
        INSERT INTO workflow_plan_v2_instance_result_selections (
            selection_id, owner_id, claimed_at_ms, expires_at_ms, outcome,
            created_at_ms, updated_at_ms
        ) VALUES ($1,$2,$3,$4,'selecting',$3,$3)
        ON CONFLICT (selection_id) DO NOTHING
        ",
    )
    .bind(request.selection_id().as_uuid())
    .bind(request.owner().as_uuid())
    .bind(request.observed_at().get())
    .bind(request.expires_at().get())
    .execute(&mut *transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if inserted != 1 {
        return Err(StoreError::corrupt_data(
            "locked result selection horizon produced a reservation conflict",
        )
        .into());
    }
    transaction.commit().await.map_err(operation_error)?;
    Ok(())
}

async fn finalize_idle_selection(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalInstanceResult,
) -> Result<(), LogicalInstanceResultStoreError> {
    let rows = sqlx::query(
        r"
        UPDATE workflow_plan_v2_instance_result_selections
        SET outcome = 'idle'
        WHERE selection_id = $1 AND outcome = 'selecting'
          AND owner_id = $2 AND claimed_at_ms = $3 AND expires_at_ms = $4
        ",
    )
    .bind(request.selection_id().as_uuid())
    .bind(request.owner().as_uuid())
    .bind(request.observed_at().get())
    .bind(request.expires_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if rows == 1 {
        Ok(())
    } else {
        Err(StoreError::corrupt_data("instance-result Idle selection lost its reservation").into())
    }
}

async fn finalize_claimed_selection(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalInstanceResult,
    claimed: &ClaimedLogicalInstanceResult,
) -> Result<(), LogicalInstanceResultStoreError> {
    let rows = sqlx::query(
        r"
        UPDATE workflow_plan_v2_instance_result_selections
        SET outcome = 'claimed', tenant_id = $2, attempt_id = $3,
            generation = $5
        WHERE selection_id = $1 AND outcome = 'selecting'
          AND owner_id = $4 AND claimed_at_ms = $6 AND expires_at_ms = $7
        ",
    )
    .bind(request.selection_id().as_uuid())
    .bind(claimed.claim().target().tenant().as_str())
    .bind(claimed.claim().target().attempt_id().as_uuid())
    .bind(claimed.claim().owner().as_uuid())
    .bind(claimed.claim().generation().as_i64())
    .bind(claimed.claim().claimed_at().get())
    .bind(claimed.claim().expires_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if rows == 1 {
        Ok(())
    } else {
        Err(StoreError::corrupt_data("instance-result claim selection lost its reservation").into())
    }
}

async fn finalize_quarantined_selection(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalInstanceResult,
    candidate: &PgRow,
) -> Result<(), LogicalInstanceResultStoreError> {
    let rows = sqlx::query(
        r"
        UPDATE workflow_plan_v2_instance_result_selections
        SET outcome = 'quarantined', tenant_id = $2, attempt_id = $3,
            generation = NULL
        WHERE selection_id = $1 AND outcome = 'selecting'
          AND owner_id = $4 AND claimed_at_ms = $5 AND expires_at_ms = $6
        ",
    )
    .bind(request.selection_id().as_uuid())
    .bind(
        candidate
            .try_get::<String, _>("repository_tenant_id")
            .map_err(operation_error)?,
    )
    .bind(
        candidate
            .try_get::<Uuid, _>("terminal_attempt_id")
            .map_err(operation_error)?,
    )
    .bind(request.owner().as_uuid())
    .bind(request.observed_at().get())
    .bind(request.expires_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if rows == 1 {
        Ok(())
    } else {
        Err(
            StoreError::corrupt_data("instance-result quarantine selection lost its reservation")
                .into(),
        )
    }
}

fn is_quarantinable_relational_error(error: &LogicalInstanceResultStoreError) -> bool {
    matches!(
        error,
        LogicalInstanceResultStoreError::Store(StoreError::CorruptData(_))
            | LogicalInstanceResultStoreError::InvalidTarget
    )
}

async fn quarantine_locked_candidate(
    transaction: &mut Transaction<'_, Postgres>,
    candidate: &PgRow,
) -> Result<(), LogicalInstanceResultStoreError> {
    let attempt_id = candidate
        .try_get::<Uuid, _>("terminal_attempt_id")
        .map_err(operation_error)?;
    let due = lock_due_snapshot(transaction, attempt_id)
        .await?
        .ok_or_else(|| StoreError::corrupt_data("locked instance-result due target disappeared"))?;
    let tenant_id = due
        .try_get::<String, _>("tenant_id")
        .map_err(operation_error)?;
    let target = optional_quarantine_target(tenant_id, attempt_id);
    let durable = match target.as_ref() {
        Some(target) => match load_durable_claim(transaction, target).await {
            Ok(Some(durable)) if durable.state == "projecting" => Some(durable),
            Ok(_) => None,
            Err(error) if is_quarantinable_relational_error(&error) => None,
            Err(error) => return Err(error),
        },
        None => None,
    };
    let database_now = database_now_ms(transaction).await?;
    let durable = durable
        .filter(|durable| durable.claimed_at <= database_now && database_now < durable.expires_at);
    let inserted = insert_quarantine(
        transaction,
        &due,
        LogicalInstanceResultQuarantineKind::RelationalEvidence,
        durable.as_ref(),
    )
    .await?;
    if inserted || quarantine_matches_due_snapshot(transaction, &due).await? {
        Ok(())
    } else {
        Err(StoreError::corrupt_data(
            "instance-result quarantine insert produced no durable evidence",
        )
        .into())
    }
}

fn optional_quarantine_target(
    tenant_id: String,
    attempt_id: Uuid,
) -> Option<LogicalInstanceResultTarget> {
    TenantScope::from_authenticated_tenant_id(tenant_id)
        .ok()
        .and_then(|tenant| {
            LogicalInstanceResultTarget::new(tenant, AttemptId::from_uuid(attempt_id)).ok()
        })
}

async fn quarantine_matches_due_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    due: &PgRow,
) -> Result<bool, LogicalInstanceResultStoreError> {
    sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_instance_result_quarantines
            WHERE attempt_id = $1 AND tenant_id = $2 AND run_id = $3
              AND invocation_id = $4 AND logical_job_id = $5
              AND source_order = $6 AND ready_at_ms = $7
              AND available_at_ms = $8
        )
        ",
    )
    .bind(
        due.try_get::<Uuid, _>("attempt_id")
            .map_err(operation_error)?,
    )
    .bind(
        due.try_get::<String, _>("tenant_id")
            .map_err(operation_error)?,
    )
    .bind(due.try_get::<Uuid, _>("run_id").map_err(operation_error)?)
    .bind(
        due.try_get::<Uuid, _>("invocation_id")
            .map_err(operation_error)?,
    )
    .bind(
        due.try_get::<Uuid, _>("logical_job_id")
            .map_err(operation_error)?,
    )
    .bind(
        due.try_get::<i32, _>("source_order")
            .map_err(operation_error)?,
    )
    .bind(
        due.try_get::<i64, _>("ready_at_ms")
            .map_err(operation_error)?,
    )
    .bind(
        due.try_get::<i64, _>("available_at_ms")
            .map_err(operation_error)?,
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn quarantine_claimed_target(
    transaction: &mut Transaction<'_, Postgres>,
    request: &QuarantineLogicalInstanceResult,
) -> Result<LogicalInstanceResultQuarantineOutcome, LogicalInstanceResultStoreError> {
    if quarantine_exists(transaction, request.claim().target()).await? {
        return Ok(LogicalInstanceResultQuarantineOutcome::AlreadyQuarantined);
    }
    let Some(due) =
        lock_due_snapshot(transaction, request.claim().target().attempt_id().as_uuid()).await?
    else {
        return Ok(LogicalInstanceResultQuarantineOutcome::FenceRejected);
    };
    let Some(row) = lock_target(transaction, request.claim().target()).await? else {
        return Ok(LogicalInstanceResultQuarantineOutcome::FenceRejected);
    };
    let Some(durable) = load_durable_claim(transaction, request.claim().target()).await? else {
        return Ok(LogicalInstanceResultQuarantineOutcome::FenceRejected);
    };
    let database_now = database_now_ms(transaction).await?;
    let descriptor = decode_descriptor(request.claim().target().clone(), &row)?;
    if &descriptor != request.descriptor()
        || !durable.matches_fence(request.claim())
        || database_now < durable.claimed_at
        || database_now >= durable.expires_at
        || durable.verify_descriptor(request.descriptor()).is_err()
        || validate_target_state(&row, Some(&durable)).is_err()
    {
        return Ok(LogicalInstanceResultQuarantineOutcome::FenceRejected);
    }
    let inserted = insert_quarantine(transaction, &due, request.kind(), Some(&durable)).await?;
    Ok(if inserted {
        LogicalInstanceResultQuarantineOutcome::Quarantined
    } else {
        LogicalInstanceResultQuarantineOutcome::AlreadyQuarantined
    })
}

async fn quarantine_exists(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalInstanceResultTarget,
) -> Result<bool, LogicalInstanceResultStoreError> {
    let tenant_id = sqlx::query_scalar::<_, String>(
        r"
        SELECT tenant_id
        FROM workflow_plan_v2_instance_result_quarantines
        WHERE attempt_id = $1
        ",
    )
    .bind(target.attempt_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(tenant_id) = tenant_id else {
        return Ok(false);
    };
    if tenant_id != target.tenant().as_str() {
        return Err(StoreError::corrupt_data(
            "logical instance-result quarantine target identity is inconsistent",
        )
        .into());
    }
    Ok(true)
}

async fn insert_quarantine(
    transaction: &mut Transaction<'_, Postgres>,
    due: &PgRow,
    kind: LogicalInstanceResultQuarantineKind,
    claim: Option<&DurableResultClaim>,
) -> Result<bool, LogicalInstanceResultStoreError> {
    let claim_owner_id = claim.map(|claim| claim.owner_id);
    let claim_generation = claim.map(|claim| claim.generation);
    let claim_claimed_at = claim.map(|claim| claim.claimed_at);
    let claim_expires_at = claim.map(|claim| claim.expires_at);
    let claim_descriptor_digest = claim.map(|claim| claim.descriptor_digest.as_bytes().to_vec());
    let inserted = sqlx::query_scalar::<_, i64>(
        r"
        INSERT INTO workflow_plan_v2_instance_result_quarantines (
            attempt_id, tenant_id, run_id, invocation_id, logical_job_id,
            source_order, ready_at_ms, available_at_ms, failure_kind,
            claim_owner_id, claim_generation, claim_claimed_at_ms,
            claim_expires_at_ms, claim_descriptor_digest
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
        ON CONFLICT (attempt_id) DO NOTHING
        RETURNING quarantined_at_ms
        ",
    )
    .bind(
        due.try_get::<Uuid, _>("attempt_id")
            .map_err(operation_error)?,
    )
    .bind(
        due.try_get::<String, _>("tenant_id")
            .map_err(operation_error)?,
    )
    .bind(due.try_get::<Uuid, _>("run_id").map_err(operation_error)?)
    .bind(
        due.try_get::<Uuid, _>("invocation_id")
            .map_err(operation_error)?,
    )
    .bind(
        due.try_get::<Uuid, _>("logical_job_id")
            .map_err(operation_error)?,
    )
    .bind(
        due.try_get::<i32, _>("source_order")
            .map_err(operation_error)?,
    )
    .bind(
        due.try_get::<i64, _>("ready_at_ms")
            .map_err(operation_error)?,
    )
    .bind(
        due.try_get::<i64, _>("available_at_ms")
            .map_err(operation_error)?,
    )
    .bind(quarantine_kind_name(kind))
    .bind(claim_owner_id)
    .bind(claim_generation)
    .bind(claim_claimed_at)
    .bind(claim_expires_at)
    .bind(claim_descriptor_digest)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(inserted.is_some())
}

async fn resolve_durable_claim(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimLogicalInstanceResult,
    descriptor: LogicalInstanceResultDescriptor,
    durable: DurableResultClaim,
    database_now: i64,
    clock_admission: ClaimClockAdmission,
) -> Result<LogicalInstanceResultClaimOutcome, LogicalInstanceResultStoreError> {
    durable.verify_descriptor(&descriptor)?;
    if durable.state == "finalized" {
        let receipt = load_finalized_receipt(transaction, &descriptor, true).await?;
        return Ok(LogicalInstanceResultClaimOutcome::Finalized(receipt));
    }
    if durable.is_exact_replay(request) {
        if durable.expires_at <= database_now {
            return Err(LogicalInstanceResultStoreError::ClaimExpired);
        }
        return claimed_from_durable(descriptor, &durable, true)
            .map(LogicalInstanceResultClaimOutcome::Claimed);
    }
    match clock_admission {
        ClaimClockAdmission::Required => {
            validate_new_claim_time(request, &descriptor, database_now)?;
        }
        ClaimClockAdmission::PrevalidatedSelection => {
            validate_prevalidated_selection_time(request, &descriptor, database_now)?;
        }
    }
    if durable.expires_at > database_now {
        return Ok(LogicalInstanceResultClaimOutcome::Busy);
    }
    let next_generation = durable
        .generation
        .checked_add(1)
        .filter(|value| *value > 0)
        .ok_or(LogicalInstanceResultStoreError::GenerationExhausted)?;
    let rows = sqlx::query(
        r"
        UPDATE workflow_plan_v2_instance_result_claims
        SET owner_id = $3, generation = $4, claimed_at_ms = $5,
            expires_at_ms = $6, updated_at_ms = $5
        WHERE attempt_id = $1
          AND state = 'projecting'
          AND generation = $2
        ",
    )
    .bind(request.target().attempt_id().as_uuid())
    .bind(durable.generation)
    .bind(request.owner().as_uuid())
    .bind(next_generation)
    .bind(request.observed_at().get())
    .bind(request.expires_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if rows != 1 {
        return Err(StoreError::corrupt_data(
            "locked logical instance-result claim disappeared during takeover",
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
    )?;
    let claimed =
        ClaimedLogicalInstanceResult::new(descriptor, claim, false).map_err(corrupt_value)?;
    Ok(LogicalInstanceResultClaimOutcome::Claimed(claimed))
}

async fn lock_target(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalInstanceResultTarget,
) -> Result<Option<PgRow>, LogicalInstanceResultStoreError> {
    sqlx::query(target_query())
        .bind(target.tenant().as_str())
        .bind(target.attempt_id().as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)
}

async fn load_durable_claim(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalInstanceResultTarget,
) -> Result<Option<DurableResultClaim>, LogicalInstanceResultStoreError> {
    let row = sqlx::query(
        r"
        SELECT run_id AS result_claim_run_id,
               invocation_id AS result_claim_invocation_id,
               logical_job_id AS result_claim_logical_job_id,
               instance_id AS result_claim_instance_id,
               job_id AS result_claim_job_id,
               descriptor_digest AS result_claim_descriptor_digest,
               state AS result_claim_state,
               owner_id AS result_claim_owner_id,
               generation AS result_claim_generation,
               claimed_at_ms AS result_claim_claimed_at_ms,
               expires_at_ms AS result_claim_expires_at_ms
        FROM workflow_plan_v2_instance_result_claims
        WHERE attempt_id = $1
        FOR UPDATE
        ",
    )
    .bind(target.attempt_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    match row {
        Some(row) => DurableResultClaim::decode(&row),
        None => Ok(None),
    }
}

fn validate_target_state(
    row: &PgRow,
    durable: Option<&DurableResultClaim>,
) -> Result<(), LogicalInstanceResultStoreError> {
    if durable.is_some_and(|claim| claim.state == "finalized") {
        return Ok(());
    }
    let logical_job_state: String = row.try_get("logical_job_state").map_err(operation_error)?;
    let invocation_state: String = row.try_get("invocation_state").map_err(operation_error)?;
    let marker_state: String = row.try_get("marker_state").map_err(operation_error)?;
    if logical_job_state == "activated"
        && matches!(invocation_state.as_str(), "pending" | "active")
        && matches!(marker_state.as_str(), "pending" | "active")
    {
        Ok(())
    } else {
        Err(LogicalInstanceResultStoreError::InvalidTarget)
    }
}

async fn lock_next_target(
    transaction: &mut Transaction<'_, Postgres>,
    observed_at: UnixMillis,
) -> Result<Option<PgRow>, LogicalInstanceResultStoreError> {
    sqlx::query(
        r"
        SELECT tenant_id AS repository_tenant_id,
               attempt_id AS terminal_attempt_id,
               run_id AS due_run_id,
               invocation_id AS due_invocation_id,
               logical_job_id AS due_logical_job_id,
               source_order AS due_source_order,
               ready_at_ms AS due_ready_at_ms,
               available_at_ms AS due_available_at_ms
        FROM workflow_plan_v2_instance_result_due
        WHERE available_at_ms <= $1
          AND NOT EXISTS (
              SELECT 1
              FROM workflow_plan_v2_instance_result_quarantines AS quarantine
              WHERE quarantine.attempt_id =
                    workflow_plan_v2_instance_result_due.attempt_id
          )
        ORDER BY available_at_ms, ready_at_ms, run_id, invocation_id,
                 source_order, logical_job_id, attempt_id
        FOR UPDATE SKIP LOCKED
        LIMIT 1
        ",
    )
    .bind(observed_at.get())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn lock_due_target(
    transaction: &mut Transaction<'_, Postgres>,
    attempt_id: AttemptId,
) -> Result<(), LogicalInstanceResultStoreError> {
    sqlx::query(
        r"
        SELECT attempt_id
        FROM workflow_plan_v2_instance_result_due
        WHERE attempt_id = $1
        FOR UPDATE
        ",
    )
    .bind(attempt_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn lock_due_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    attempt_id: Uuid,
) -> Result<Option<PgRow>, LogicalInstanceResultStoreError> {
    sqlx::query(
        r"
        SELECT attempt_id, tenant_id, run_id, invocation_id, logical_job_id,
               source_order, ready_at_ms, available_at_ms
        FROM workflow_plan_v2_instance_result_due
        WHERE attempt_id = $1
        FOR UPDATE
        ",
    )
    .bind(attempt_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn lock_commit_target(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalInstanceResultTarget,
) -> Result<Option<PgRow>, LogicalInstanceResultStoreError> {
    if lock_target(transaction, target).await?.is_none() {
        return Ok(None);
    }
    // Re-read after owning the terminal-row lock so a concurrent finalization
    // cannot leave this READ COMMITTED statement with stale claim state.
    lock_target(transaction, target).await
}

fn target_query() -> &'static str {
    r"
    SELECT concrete.run_id, concrete.invocation_id, concrete.logical_job_id,
           concrete.instance_id, concrete.job_id,
           logical_job.logical_key, logical_job.state AS logical_job_state,
           invocation.state AS invocation_state, marker.state AS marker_state,
           instance.matrix_index, instance.matrix_total, instance.matrix_digest,
           terminal.terminal_authority,
           terminal.result_digest, terminal.result_object_key,
           terminal.result_size_bytes, terminal.result_schema,
           terminal.server_cancellation_operation_id,
           terminal.server_cancellation_digest,
           terminal.conclusion, terminal.completed_at_ms,
           terminal.committed_at_ms,
           terminal.workflow_plan_v2_terminal_ordinal,
           attempt.secret_exposure_class AS maximum_secret_exposure_class,
           instance.job_ir_digest, instance.job_ir_object_key,
           instance.job_ir_size_bytes, instance.job_ir_media_type,
           instance.job_ir_version
    FROM attempt_terminal_results AS terminal
    JOIN job_attempts AS attempt ON attempt.id = terminal.attempt_id
    JOIN jobs AS job ON job.id = attempt.job_id
    JOIN workflow_plan_v2_concrete_jobs AS concrete
      ON concrete.job_id = job.id
     AND concrete.initial_attempt_id = attempt.id
    JOIN workflow_plan_v2_materialization_claims AS materialization
      ON materialization.instance_id = concrete.instance_id
    JOIN workflow_plan_v2_instances AS instance
      ON instance.id = concrete.instance_id
     AND instance.run_id = concrete.run_id
     AND instance.invocation_id = concrete.invocation_id
     AND instance.logical_job_id = concrete.logical_job_id
    JOIN workflow_plan_v2_jobs AS logical_job
      ON logical_job.run_id = concrete.run_id
     AND logical_job.invocation_id = concrete.invocation_id
     AND logical_job.id = concrete.logical_job_id
    JOIN workflow_plan_v2_invocations AS invocation
      ON invocation.run_id = logical_job.run_id
     AND invocation.id = logical_job.invocation_id
    JOIN workflow_plan_v2_runs AS marker ON marker.run_id = concrete.run_id
    JOIN workflow_runs AS run ON run.id = marker.run_id
    JOIN repositories AS repository ON repository.id = run.repository_id
    WHERE repository.tenant_id = $1
      AND terminal.attempt_id = $2
      AND materialization.state = 'materialized'
      AND job.run_id = concrete.run_id
      AND job.admission_epoch = 4
      AND job.job_ir_schema = 5
      AND job.job_ir_digest = instance.job_ir_digest
      AND job.job_ir_object_key = instance.job_ir_object_key
      AND job.job_ir_size_bytes = instance.job_ir_size_bytes
      AND instance.job_ir_version = 5
      AND instance.job_ir_media_type =
          'application/vnd.automata.job-ir.protobuf'
      AND (
          (terminal.terminal_authority = 'runner'
           AND terminal.result_schema = 1)
          OR terminal.terminal_authority = 'server_cancellation'
      )
      AND terminal.workflow_plan_v2_logical_job_id = concrete.logical_job_id
      AND terminal.workflow_plan_v2_terminal_ordinal > 0
      AND terminal.completed_at_ms >= 0
      AND terminal.committed_at_ms >= terminal.completed_at_ms
      AND (
          (terminal.conclusion = 'success' AND attempt.lifecycle = 'succeeded')
          OR (terminal.conclusion = 'failure' AND attempt.lifecycle = 'failed')
          OR (terminal.conclusion = 'cancelled' AND attempt.lifecycle = 'cancelled')
          OR (terminal.conclusion = 'timed_out' AND attempt.lifecycle = 'timed_out')
          OR (terminal.conclusion = 'skipped' AND attempt.lifecycle = 'skipped')
      )
      AND logical_job.execution_kind = 'steps'
      AND invocation.plan_schema = 2
      AND marker.orchestration_schema = 1
      AND run.admission_epoch = 4
      AND run.plan_schema = 2
      AND logical_job.state IN ('activated', 'completed', 'skipped', 'cancelled', 'failed')
      AND invocation.state IN ('pending', 'active', 'completed', 'cancelled', 'failed')
      AND marker.state IN ('pending', 'active', 'completed', 'cancelled', 'failed')
    FOR UPDATE OF terminal
    "
}

#[derive(Debug)]
struct DurableResultClaim {
    run_id: Uuid,
    invocation_id: Uuid,
    logical_job_id: Uuid,
    instance_id: Uuid,
    job_id: Uuid,
    descriptor_digest: Sha256Digest,
    state: String,
    owner_id: Uuid,
    generation: i64,
    claimed_at: i64,
    expires_at: i64,
}

impl DurableResultClaim {
    fn decode(row: &PgRow) -> Result<Option<Self>, LogicalInstanceResultStoreError> {
        let state: Option<String> = row.try_get("result_claim_state").map_err(operation_error)?;
        let Some(state) = state else {
            return Ok(None);
        };
        let claim = Self {
            run_id: required_claim(row, "result_claim_run_id")?,
            invocation_id: required_claim(row, "result_claim_invocation_id")?,
            logical_job_id: required_claim(row, "result_claim_logical_job_id")?,
            instance_id: required_claim(row, "result_claim_instance_id")?,
            job_id: required_claim(row, "result_claim_job_id")?,
            descriptor_digest: decode_optional_digest(row, "result_claim_descriptor_digest")?
                .ok_or_else(|| StoreError::corrupt_data("instance-result claim lacks digest"))?,
            state,
            owner_id: required_claim(row, "result_claim_owner_id")?,
            generation: required_claim(row, "result_claim_generation")?,
            claimed_at: required_claim(row, "result_claim_claimed_at_ms")?,
            expires_at: required_claim(row, "result_claim_expires_at_ms")?,
        };
        if !matches!(claim.state.as_str(), "projecting" | "finalized")
            || claim.owner_id.is_nil()
            || claim.generation <= 0
        {
            return Err(StoreError::corrupt_data("invalid durable instance-result claim").into());
        }
        Ok(Some(claim))
    }

    fn verify_descriptor(
        &self,
        descriptor: &LogicalInstanceResultDescriptor,
    ) -> Result<(), LogicalInstanceResultStoreError> {
        let exact = self.run_id == descriptor.run_id().as_uuid()
            && self.invocation_id == descriptor.invocation_id().as_uuid()
            && self.logical_job_id == descriptor.logical_job_id().as_uuid()
            && self.instance_id == descriptor.instance_id().as_uuid()
            && self.job_id == descriptor.job_id().as_uuid()
            && self.descriptor_digest == descriptor.descriptor_digest();
        if exact {
            Ok(())
        } else {
            Err(StoreError::corrupt_data(
                "instance-result claim disagrees with terminal descriptor",
            )
            .into())
        }
    }

    fn is_exact_replay(&self, request: &ClaimLogicalInstanceResult) -> bool {
        self.state == "projecting"
            && self.owner_id == request.owner().as_uuid()
            && self.claimed_at == request.observed_at().get()
            && self.expires_at == request.expires_at().get()
    }

    fn matches_fence(&self, fence: &LogicalInstanceResultClaimFence) -> bool {
        self.state == "projecting"
            && self.owner_id == fence.owner().as_uuid()
            && self.generation == fence.generation().as_i64()
            && self.descriptor_digest == fence.descriptor_digest()
            && self.claimed_at == fence.claimed_at().get()
            && self.expires_at == fence.expires_at().get()
    }
}

fn required_claim<T>(row: &PgRow, column: &str) -> Result<T, LogicalInstanceResultStoreError>
where
    for<'value> T: sqlx::Decode<'value, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get::<Option<T>, _>(column)
        .map_err(operation_error)?
        .ok_or_else(|| {
            StoreError::corrupt_data(format!("instance-result claim lacks {column}")).into()
        })
}

#[allow(clippy::too_many_lines)]
fn decode_descriptor(
    target: LogicalInstanceResultTarget,
    row: &PgRow,
) -> Result<LogicalInstanceResultDescriptor, LogicalInstanceResultStoreError> {
    let run_id = RunId::from_uuid(row.try_get("run_id").map_err(operation_error)?);
    let invocation_id = LogicalWorkflowInvocationId::from_uuid(
        row.try_get("invocation_id").map_err(operation_error)?,
    )
    .map_err(corrupt_value)?;
    let logical_job_id =
        LogicalWorkflowJobId::from_uuid(row.try_get("logical_job_id").map_err(operation_error)?)
            .map_err(corrupt_value)?;
    let instance_id =
        LogicalWorkflowInstanceId::from_uuid(row.try_get("instance_id").map_err(operation_error)?)
            .map_err(corrupt_value)?;
    let job_id = JobId::from_uuid(row.try_get("job_id").map_err(operation_error)?);
    let logical_key = WorkflowJobKey::new(
        row.try_get::<String, _>("logical_key")
            .map_err(operation_error)?,
    )
    .map_err(corrupt_value)?;
    let matrix_index = u32::try_from(
        row.try_get::<i32, _>("matrix_index")
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("negative logical matrix index"))?;
    let matrix_total = u32::try_from(
        row.try_get::<i32, _>("matrix_total")
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("negative logical matrix total"))?;
    let matrix_digest = decode_digest(row, "matrix_digest")?;
    let terminal_ordinal = LogicalInstanceTerminalOrdinal::new(
        u64::try_from(
            row.try_get::<i64, _>("workflow_plan_v2_terminal_ordinal")
                .map_err(operation_error)?,
        )
        .map_err(|_| StoreError::corrupt_data("invalid logical terminal ordinal"))?,
    )
    .map_err(corrupt_value)?;
    let job_ir_version: i16 = row.try_get("job_ir_version").map_err(operation_error)?;
    let job_ir_media: String = row.try_get("job_ir_media_type").map_err(operation_error)?;
    if job_ir_version != i16::try_from(JOB_IR_SCHEMA_VERSION).unwrap_or(i16::MAX)
        || job_ir_media != LOGICAL_ACTIVATION_JOB_IR_MEDIA_TYPE
    {
        return Err(StoreError::corrupt_data("non-current logical result JobIR descriptor").into());
    }
    let job_ir_object = LogicalActivationObject::job_ir(
        decode_digest(row, "job_ir_digest")?,
        ObjectKey::new(
            row.try_get::<String, _>("job_ir_object_key")
                .map_err(operation_error)?,
        )
        .map_err(corrupt_value)?,
        u64::try_from(
            row.try_get::<i64, _>("job_ir_size_bytes")
                .map_err(operation_error)?,
        )
        .map_err(|_| StoreError::corrupt_data("invalid JobIR size"))?,
    )
    .map_err(corrupt_value)?;
    let maximum_secret_exposure = parse_secret_exposure(
        &row.try_get::<String, _>("maximum_secret_exposure_class")
            .map_err(operation_error)?,
    )?;
    let raw_conclusion = parse_conclusion(
        &row.try_get::<String, _>("conclusion")
            .map_err(operation_error)?,
    )?;
    let result_completed_at =
        UnixMillis::new(row.try_get("completed_at_ms").map_err(operation_error)?);
    let result_committed_at =
        UnixMillis::new(row.try_get("committed_at_ms").map_err(operation_error)?);
    let terminal_authority: String = row.try_get("terminal_authority").map_err(operation_error)?;
    match terminal_authority.as_str() {
        "runner" => {
            if row
                .try_get::<Option<Uuid>, _>("server_cancellation_operation_id")
                .map_err(operation_error)?
                .is_some()
                || decode_optional_digest(row, "server_cancellation_digest")?.is_some()
            {
                return Err(StoreError::corrupt_data(
                    "runner terminal carries server cancellation evidence",
                )
                .into());
            }
            let result_schema = u16::try_from(
                row.try_get::<Option<i32>, _>("result_schema")
                    .map_err(operation_error)?
                    .ok_or_else(|| StoreError::corrupt_data("runner terminal lacks schema"))?,
            )
            .map_err(|_| StoreError::corrupt_data("invalid terminal-result schema"))?;
            let terminal_result = LogicalTerminalResultObject::new(
                decode_optional_digest(row, "result_digest")?.ok_or_else(|| {
                    StoreError::corrupt_data("runner terminal lacks result digest")
                })?,
                ObjectKey::new(
                    row.try_get::<Option<String>, _>("result_object_key")
                        .map_err(operation_error)?
                        .ok_or_else(|| {
                            StoreError::corrupt_data("runner terminal lacks result object key")
                        })?,
                )
                .map_err(corrupt_value)?,
                u64::try_from(
                    row.try_get::<Option<i64>, _>("result_size_bytes")
                        .map_err(operation_error)?
                        .ok_or_else(|| {
                            StoreError::corrupt_data("runner terminal lacks result size")
                        })?,
                )
                .map_err(|_| StoreError::corrupt_data("invalid terminal-result size"))?,
                result_schema,
            )
            .map_err(corrupt_value)?;
            LogicalInstanceResultDescriptor::new(
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
                terminal_result,
                job_ir_object,
                maximum_secret_exposure,
                raw_conclusion,
                result_completed_at,
                result_committed_at,
            )
            .map_err(corrupt_value)
        }
        "server_cancellation" => {
            let result_fields_absent = decode_optional_digest(row, "result_digest")?.is_none()
                && row
                    .try_get::<Option<String>, _>("result_object_key")
                    .map_err(operation_error)?
                    .is_none()
                && row
                    .try_get::<Option<i64>, _>("result_size_bytes")
                    .map_err(operation_error)?
                    .is_none()
                && row
                    .try_get::<Option<i32>, _>("result_schema")
                    .map_err(operation_error)?
                    .is_none();
            let operation_id = row
                .try_get::<Option<Uuid>, _>("server_cancellation_operation_id")
                .map_err(operation_error)?
                .ok_or_else(|| {
                    StoreError::corrupt_data("server cancellation lacks operation ID")
                })?;
            let digest = decode_optional_digest(row, "server_cancellation_digest")?
                .ok_or_else(|| StoreError::corrupt_data("server cancellation lacks digest"))?;
            if !result_fields_absent || raw_conclusion != JobConclusion::Cancelled {
                return Err(StoreError::corrupt_data(
                    "server cancellation terminal has an invalid tagged shape",
                )
                .into());
            }
            LogicalInstanceResultDescriptor::new_server_cancellation(
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
                LogicalServerCancellationTerminal::new(
                    OperationId::from_uuid(operation_id),
                    digest,
                ),
                job_ir_object,
                maximum_secret_exposure,
                result_completed_at,
                result_committed_at,
            )
            .map_err(corrupt_value)
        }
        _ => Err(StoreError::corrupt_data("unknown terminal authority").into()),
    }
}

fn make_fence(
    target: LogicalInstanceResultTarget,
    owner: LogicalInstanceResultWorkerId,
    generation: i64,
    descriptor: &LogicalInstanceResultDescriptor,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
) -> Result<LogicalInstanceResultClaimFence, LogicalInstanceResultStoreError> {
    let generation = u64::try_from(generation)
        .ok()
        .and_then(|value| LogicalInstanceResultGeneration::new(value).ok())
        .ok_or_else(|| StoreError::corrupt_data("invalid instance-result claim generation"))?;
    LogicalInstanceResultClaimFence::new(
        target,
        owner,
        generation,
        descriptor.descriptor_digest(),
        claimed_at,
        expires_at,
    )
    .map_err(corrupt_value)
}

fn claimed_from_durable(
    descriptor: LogicalInstanceResultDescriptor,
    durable: &DurableResultClaim,
    replayed: bool,
) -> Result<ClaimedLogicalInstanceResult, LogicalInstanceResultStoreError> {
    let owner =
        LogicalInstanceResultWorkerId::from_uuid(durable.owner_id).map_err(corrupt_value)?;
    let claim = make_fence(
        descriptor.target().clone(),
        owner,
        durable.generation,
        &descriptor,
        UnixMillis::new(durable.claimed_at),
        UnixMillis::new(durable.expires_at),
    )?;
    ClaimedLogicalInstanceResult::new(descriptor, claim, replayed).map_err(corrupt_value)
}

async fn insert_instance_result(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitLogicalInstanceResult,
    descriptor: &LogicalInstanceResultDescriptor,
) -> Result<(), LogicalInstanceResultStoreError> {
    let (
        terminal_authority,
        result_digest,
        result_object_key,
        result_size,
        result_media_type,
        result_schema,
        server_operation_id,
        server_digest,
    ) = match descriptor.terminal_authority() {
        crate::LogicalInstanceTerminalAuthority::Runner(result) => (
            "runner",
            Some(result.digest().as_bytes().to_vec()),
            Some(result.object_key().as_str()),
            Some(size_i64(result.encoded_size())?),
            Some(LOGICAL_INSTANCE_RESULT_MEDIA_TYPE),
            Some(i16::try_from(CORE_SCHEMA_VERSION).expect("current result schema fits SMALLINT")),
            None,
            None,
        ),
        crate::LogicalInstanceTerminalAuthority::ServerCancellation(cancellation) => (
            "server_cancellation",
            None,
            None,
            None,
            None,
            None,
            Some(cancellation.operation_id().as_uuid()),
            Some(cancellation.digest().as_bytes().to_vec()),
        ),
    };
    sqlx::query(
        r"
        INSERT INTO workflow_plan_v2_instance_results (
            instance_id, run_id, invocation_id, logical_job_id, job_id,
            attempt_id, descriptor_digest, terminal_authority,
            result_digest, result_object_key, result_size_bytes,
            result_media_type, result_schema,
            server_cancellation_operation_id, server_cancellation_digest,
            job_ir_digest, job_ir_object_key, job_ir_size_bytes,
            job_ir_media_type, job_ir_schema,
            raw_conclusion, effective_conclusion, continue_on_error,
            secret_exposure_class,
            result_completed_at_ms, result_committed_at_ms, terminal_ordinal,
            output_count, outputs_digest, commit_digest,
            claim_owner_id, claim_generation, claim_started_at_ms,
            claim_expires_at_ms, finalized_at_ms
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
            $18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,
            $33,$34,$35
        )
        ",
    )
    .bind(descriptor.instance_id().as_uuid())
    .bind(descriptor.run_id().as_uuid())
    .bind(descriptor.invocation_id().as_uuid())
    .bind(descriptor.logical_job_id().as_uuid())
    .bind(descriptor.job_id().as_uuid())
    .bind(descriptor.target().attempt_id().as_uuid())
    .bind(descriptor.descriptor_digest().as_bytes().as_slice())
    .bind(terminal_authority)
    .bind(result_digest)
    .bind(result_object_key)
    .bind(result_size)
    .bind(result_media_type)
    .bind(result_schema)
    .bind(server_operation_id)
    .bind(server_digest)
    .bind(descriptor.job_ir().digest().as_bytes().as_slice())
    .bind(descriptor.job_ir().object_key().as_str())
    .bind(size_i64(descriptor.job_ir().encoded_size())?)
    .bind(descriptor.job_ir().media_type())
    .bind(i16::try_from(JOB_IR_SCHEMA_VERSION).expect("current JobIR schema fits SMALLINT"))
    .bind(conclusion_name(request.raw_conclusion()))
    .bind(conclusion_name(request.effective_conclusion()))
    .bind(request.continue_on_error())
    .bind(secret_exposure_name(request.secret_exposure()))
    .bind(descriptor.result_completed_at().get())
    .bind(descriptor.result_committed_at().get())
    .bind(descriptor.terminal_ordinal().as_i64())
    .bind(i32::try_from(request.outputs().len()).map_err(|_| {
        StoreError::corrupt_data("logical instance-result output count exceeds INTEGER")
    })?)
    .bind(request.outputs_digest().as_bytes().as_slice())
    .bind(request.commit_digest().as_bytes().as_slice())
    .bind(request.claim().owner().as_uuid())
    .bind(request.claim().generation().as_i64())
    .bind(request.claim().claimed_at().get())
    .bind(request.claim().expires_at().get())
    .bind(request.finalized_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn insert_outputs(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitLogicalInstanceResult,
    descriptor: &LogicalInstanceResultDescriptor,
) -> Result<(), LogicalInstanceResultStoreError> {
    for output in request.outputs() {
        sqlx::query(
            r"
            INSERT INTO workflow_plan_v2_instance_result_outputs (
                instance_id, output_name, sensitivity, public_value
            ) VALUES ($1,$2,$3,$4)
            ",
        )
        .bind(descriptor.instance_id().as_uuid())
        .bind(output.name())
        .bind(sensitivity_name(output.sensitivity()))
        .bind(output.public_value())
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    }
    Ok(())
}

async fn load_finalized_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    descriptor: &LogicalInstanceResultDescriptor,
    replayed: bool,
) -> Result<LogicalInstanceResultReceipt, LogicalInstanceResultStoreError> {
    let row = sqlx::query(receipt_query())
        .bind(descriptor.target().attempt_id().as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?
        .ok_or_else(|| StoreError::corrupt_data("finalized claim has no instance result"))?;
    let receipt = decode_receipt(&row, descriptor, replayed)?;
    verify_finalized_result_evidence(transaction, descriptor, &row, &receipt).await?;
    Ok(receipt)
}

fn receipt_query() -> &'static str {
    r"
    SELECT result.instance_id, result.run_id, result.invocation_id,
           result.logical_job_id, result.job_id, result.attempt_id,
           result.descriptor_digest, result.terminal_authority,
           result.result_digest,
           result.result_object_key, result.result_size_bytes,
           result.result_media_type, result.result_schema,
           result.server_cancellation_operation_id,
           result.server_cancellation_digest,
           result.job_ir_digest, result.job_ir_object_key,
           result.job_ir_size_bytes, result.job_ir_media_type,
           result.job_ir_schema, result.raw_conclusion,
           result.effective_conclusion, result.continue_on_error,
           result.secret_exposure_class,
           result.result_completed_at_ms, result.result_committed_at_ms,
           result.terminal_ordinal,
           result.output_count, result.outputs_digest, result.commit_digest,
           result.claim_owner_id, result.claim_generation,
           result.claim_started_at_ms, result.claim_expires_at_ms,
           result.finalized_at_ms, claim.state AS receipt_claim_state,
           claim.run_id AS receipt_claim_run_id,
           claim.invocation_id AS receipt_claim_invocation_id,
           claim.logical_job_id AS receipt_claim_logical_job_id,
           claim.instance_id AS receipt_claim_instance_id,
           claim.job_id AS receipt_claim_job_id,
           claim.descriptor_digest AS receipt_claim_descriptor_digest,
           claim.owner_id AS receipt_claim_owner_id,
           claim.generation AS receipt_claim_generation,
           claim.claimed_at_ms AS receipt_claim_claimed_at_ms,
           claim.expires_at_ms AS receipt_claim_expires_at_ms,
           claim.updated_at_ms AS receipt_claim_updated_at_ms,
           (SELECT count(*) FROM workflow_plan_v2_instance_result_outputs AS output
            WHERE output.instance_id = result.instance_id) AS actual_output_count
    FROM workflow_plan_v2_instance_results AS result
    JOIN workflow_plan_v2_instance_result_claims AS claim
      ON claim.attempt_id = result.attempt_id
    WHERE result.attempt_id = $1
    "
}

fn terminal_projection_evidence_matches(
    row: &PgRow,
    descriptor: &LogicalInstanceResultDescriptor,
) -> Result<bool, LogicalInstanceResultStoreError> {
    let authority: String = row.try_get("terminal_authority").map_err(operation_error)?;
    match descriptor.terminal_authority() {
        crate::LogicalInstanceTerminalAuthority::Runner(result) => Ok(authority == "runner"
            && decode_optional_digest(row, "result_digest")? == Some(result.digest())
            && row
                .try_get::<Option<String>, _>("result_object_key")
                .map_err(operation_error)?
                .as_deref()
                == Some(result.object_key().as_str())
            && row
                .try_get::<Option<i64>, _>("result_size_bytes")
                .map_err(operation_error)?
                == Some(i64::try_from(result.encoded_size()).unwrap_or(i64::MAX))
            && row
                .try_get::<Option<String>, _>("result_media_type")
                .map_err(operation_error)?
                .as_deref()
                == Some(LOGICAL_INSTANCE_RESULT_MEDIA_TYPE)
            && row
                .try_get::<Option<i16>, _>("result_schema")
                .map_err(operation_error)?
                == Some(i16::try_from(CORE_SCHEMA_VERSION).unwrap_or(i16::MAX))
            && row
                .try_get::<Option<Uuid>, _>("server_cancellation_operation_id")
                .map_err(operation_error)?
                .is_none()
            && decode_optional_digest(row, "server_cancellation_digest")?.is_none()),
        crate::LogicalInstanceTerminalAuthority::ServerCancellation(cancellation) => Ok(authority
            == "server_cancellation"
            && decode_optional_digest(row, "result_digest")?.is_none()
            && row
                .try_get::<Option<String>, _>("result_object_key")
                .map_err(operation_error)?
                .is_none()
            && row
                .try_get::<Option<i64>, _>("result_size_bytes")
                .map_err(operation_error)?
                .is_none()
            && row
                .try_get::<Option<String>, _>("result_media_type")
                .map_err(operation_error)?
                .is_none()
            && row
                .try_get::<Option<i16>, _>("result_schema")
                .map_err(operation_error)?
                .is_none()
            && row
                .try_get::<Option<Uuid>, _>("server_cancellation_operation_id")
                .map_err(operation_error)?
                == Some(cancellation.operation_id().as_uuid())
            && decode_optional_digest(row, "server_cancellation_digest")?
                == Some(cancellation.digest())),
    }
}

#[allow(clippy::too_many_lines)]
fn decode_receipt(
    row: &PgRow,
    descriptor: &LogicalInstanceResultDescriptor,
    replayed: bool,
) -> Result<LogicalInstanceResultReceipt, LogicalInstanceResultStoreError> {
    let instance_id =
        LogicalWorkflowInstanceId::from_uuid(row.try_get("instance_id").map_err(operation_error)?)
            .map_err(corrupt_value)?;
    let job_id = JobId::from_uuid(row.try_get("job_id").map_err(operation_error)?);
    let attempt_id = AttemptId::from_uuid(row.try_get("attempt_id").map_err(operation_error)?);
    let descriptor_digest = decode_digest(row, "descriptor_digest")?;
    let raw_conclusion = parse_conclusion(
        &row.try_get::<String, _>("raw_conclusion")
            .map_err(operation_error)?,
    )?;
    let effective_conclusion = parse_conclusion(
        &row.try_get::<String, _>("effective_conclusion")
            .map_err(operation_error)?,
    )?;
    let secret_exposure = parse_secret_exposure(
        &row.try_get::<String, _>("secret_exposure_class")
            .map_err(operation_error)?,
    )?;
    let output_count_i32: i32 = row.try_get("output_count").map_err(operation_error)?;
    let output_count = u32::try_from(output_count_i32)
        .map_err(|_| StoreError::corrupt_data("negative instance-result output count"))?;
    let actual_output_count: i64 = row
        .try_get("actual_output_count")
        .map_err(operation_error)?;
    let exact = instance_id == descriptor.instance_id()
        && job_id == descriptor.job_id()
        && attempt_id == descriptor.target().attempt_id()
        && descriptor_digest == descriptor.descriptor_digest()
        && row.try_get::<Uuid, _>("run_id").map_err(operation_error)?
            == descriptor.run_id().as_uuid()
        && row
            .try_get::<Uuid, _>("invocation_id")
            .map_err(operation_error)?
            == descriptor.invocation_id().as_uuid()
        && row
            .try_get::<Uuid, _>("logical_job_id")
            .map_err(operation_error)?
            == descriptor.logical_job_id().as_uuid()
        && terminal_projection_evidence_matches(row, descriptor)?
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
            .try_get::<String, _>("job_ir_media_type")
            .map_err(operation_error)?
            == descriptor.job_ir().media_type()
        && row
            .try_get::<i16, _>("job_ir_schema")
            .map_err(operation_error)?
            == i16::try_from(JOB_IR_SCHEMA_VERSION).unwrap_or(i16::MAX)
        && raw_conclusion == descriptor.raw_conclusion()
        && match descriptor.terminal_authority() {
            crate::LogicalInstanceTerminalAuthority::Runner(_) => {
                descriptor.accepts_terminal_secret_exposure(secret_exposure)
            }
            crate::LogicalInstanceTerminalAuthority::ServerCancellation(_) => {
                secret_exposure == JobSecretExposure::Secretless && output_count == 0
            }
        }
        && row
            .try_get::<i64, _>("result_completed_at_ms")
            .map_err(operation_error)?
            == descriptor.result_completed_at().get()
        && row
            .try_get::<i64, _>("result_committed_at_ms")
            .map_err(operation_error)?
            == descriptor.result_committed_at().get()
        && row
            .try_get::<i64, _>("terminal_ordinal")
            .map_err(operation_error)?
            == descriptor.terminal_ordinal().as_i64()
        && actual_output_count == i64::from(output_count)
        && row
            .try_get::<String, _>("receipt_claim_state")
            .map_err(operation_error)?
            == "finalized"
        && row
            .try_get::<Uuid, _>("receipt_claim_run_id")
            .map_err(operation_error)?
            == descriptor.run_id().as_uuid()
        && row
            .try_get::<Uuid, _>("receipt_claim_invocation_id")
            .map_err(operation_error)?
            == descriptor.invocation_id().as_uuid()
        && row
            .try_get::<Uuid, _>("receipt_claim_logical_job_id")
            .map_err(operation_error)?
            == descriptor.logical_job_id().as_uuid()
        && row
            .try_get::<Uuid, _>("receipt_claim_instance_id")
            .map_err(operation_error)?
            == descriptor.instance_id().as_uuid()
        && row
            .try_get::<Uuid, _>("receipt_claim_job_id")
            .map_err(operation_error)?
            == descriptor.job_id().as_uuid()
        && decode_digest(row, "receipt_claim_descriptor_digest")? == descriptor_digest
        && row
            .try_get::<Uuid, _>("receipt_claim_owner_id")
            .map_err(operation_error)?
            == row
                .try_get::<Uuid, _>("claim_owner_id")
                .map_err(operation_error)?
        && row
            .try_get::<i64, _>("receipt_claim_generation")
            .map_err(operation_error)?
            == row
                .try_get::<i64, _>("claim_generation")
                .map_err(operation_error)?
        && row
            .try_get::<i64, _>("receipt_claim_claimed_at_ms")
            .map_err(operation_error)?
            == row
                .try_get::<i64, _>("claim_started_at_ms")
                .map_err(operation_error)?
        && row
            .try_get::<i64, _>("receipt_claim_expires_at_ms")
            .map_err(operation_error)?
            == row
                .try_get::<i64, _>("claim_expires_at_ms")
                .map_err(operation_error)?
        && row
            .try_get::<i64, _>("receipt_claim_updated_at_ms")
            .map_err(operation_error)?
            == row
                .try_get::<i64, _>("finalized_at_ms")
                .map_err(operation_error)?;
    if !exact {
        return Err(StoreError::corrupt_data(
            "logical instance-result receipt disagrees with durable terminal evidence",
        )
        .into());
    }
    LogicalInstanceResultReceipt::from_durable(
        instance_id,
        job_id,
        attempt_id,
        descriptor.terminal_ordinal(),
        descriptor_digest,
        raw_conclusion,
        effective_conclusion,
        secret_exposure,
        output_count,
        decode_digest(row, "outputs_digest")?,
        decode_digest(row, "commit_digest")?,
        UnixMillis::new(row.try_get("finalized_at_ms").map_err(operation_error)?),
        replayed,
    )
    .map_err(corrupt_value)
}

async fn verify_exact_finalized_commit(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitLogicalInstanceResult,
    descriptor: &LogicalInstanceResultDescriptor,
    durable: &DurableResultClaim,
) -> Result<(), LogicalInstanceResultStoreError> {
    if durable.owner_id != request.claim().owner().as_uuid()
        || durable.generation != request.claim().generation().as_i64()
        || durable.claimed_at != request.claim().claimed_at().get()
        || durable.expires_at != request.claim().expires_at().get()
        || durable.descriptor_digest != request.claim().descriptor_digest()
    {
        return Err(LogicalInstanceResultStoreError::ClaimRejected);
    }
    let receipt = load_finalized_receipt(transaction, descriptor, true).await?;
    let continue_on_error = sqlx::query_scalar::<_, bool>(
        r"
        SELECT continue_on_error
        FROM workflow_plan_v2_instance_results
        WHERE attempt_id = $1
        ",
    )
    .bind(descriptor.target().attempt_id().as_uuid())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let exact = receipt.raw_conclusion() == request.raw_conclusion()
        && receipt.effective_conclusion() == request.effective_conclusion()
        && receipt.secret_exposure() == request.secret_exposure()
        && receipt.output_count() == u32::try_from(request.outputs().len()).unwrap_or(u32::MAX)
        && receipt.outputs_digest() == request.outputs_digest()
        && receipt.commit_digest() == request.commit_digest()
        && receipt.finalized_at() == request.finalized_at()
        && continue_on_error == request.continue_on_error();
    if !exact || !outputs_match(transaction, request, descriptor).await? {
        return Err(LogicalInstanceResultStoreError::CommitConflict);
    }
    Ok(())
}

async fn verify_finalized_result_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    descriptor: &LogicalInstanceResultDescriptor,
    row: &PgRow,
    receipt: &LogicalInstanceResultReceipt,
) -> Result<(), LogicalInstanceResultStoreError> {
    let outputs = load_result_outputs(transaction, descriptor).await?;
    let owner = LogicalInstanceResultWorkerId::from_uuid(
        row.try_get::<Uuid, _>("claim_owner_id")
            .map_err(operation_error)?,
    )
    .map_err(corrupt_value)?;
    let generation = LogicalInstanceResultGeneration::new(
        u64::try_from(
            row.try_get::<i64, _>("claim_generation")
                .map_err(operation_error)?,
        )
        .map_err(|_| StoreError::corrupt_data("invalid finalized claim generation"))?,
    )
    .map_err(corrupt_value)?;
    let continue_on_error = row
        .try_get::<bool, _>("continue_on_error")
        .map_err(operation_error)?;
    let expected_effective_conclusion =
        if continue_on_error && matches!(receipt.raw_conclusion(), JobConclusion::Failure) {
            JobConclusion::Success
        } else {
            receipt.raw_conclusion()
        };
    let expected_commit = rederive_commit_digest(
        descriptor.instance_id(),
        descriptor.job_id(),
        descriptor.target().attempt_id(),
        descriptor.terminal_ordinal(),
        owner,
        generation,
        receipt.descriptor_digest(),
        receipt.raw_conclusion(),
        receipt.effective_conclusion(),
        continue_on_error,
        receipt.secret_exposure(),
        receipt.outputs_digest(),
        receipt.finalized_at(),
    );
    let claim_started_at = row
        .try_get::<i64, _>("claim_started_at_ms")
        .map_err(operation_error)?;
    let claim_expires_at = row
        .try_get::<i64, _>("claim_expires_at_ms")
        .map_err(operation_error)?;
    if u32::try_from(outputs.len()).unwrap_or(u32::MAX) != receipt.output_count()
        || output_set_digest(&outputs) != receipt.outputs_digest()
        || expected_commit != receipt.commit_digest()
        || expected_effective_conclusion != receipt.effective_conclusion()
        || claim_started_at < descriptor.result_committed_at().get()
        || receipt.finalized_at().get() < claim_started_at
        || receipt.finalized_at().get() >= claim_expires_at
    {
        return Err(StoreError::corrupt_data(
            "finalized logical instance-result evidence failed complete reauthentication",
        )
        .into());
    }
    Ok(())
}

async fn load_result_outputs(
    transaction: &mut Transaction<'_, Postgres>,
    descriptor: &LogicalInstanceResultDescriptor,
) -> Result<Vec<LogicalInstanceResultOutput>, LogicalInstanceResultStoreError> {
    let rows = sqlx::query(
        r#"
        SELECT output_name, sensitivity, public_value
        FROM workflow_plan_v2_instance_result_outputs
        WHERE instance_id = $1
        ORDER BY output_name COLLATE "C"
        "#,
    )
    .bind(descriptor.instance_id().as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    rows.into_iter()
        .map(|row| {
            LogicalInstanceResultOutput::from_durable(
                row.try_get::<String, _>("output_name")
                    .map_err(operation_error)?,
                parse_sensitivity(
                    &row.try_get::<String, _>("sensitivity")
                        .map_err(operation_error)?,
                )?,
                row.try_get("public_value").map_err(operation_error)?,
            )
            .map_err(corrupt_value)
        })
        .collect()
}

async fn outputs_match(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitLogicalInstanceResult,
    descriptor: &LogicalInstanceResultDescriptor,
) -> Result<bool, LogicalInstanceResultStoreError> {
    let rows = sqlx::query(
        r#"
        SELECT output_name, sensitivity, public_value
        FROM workflow_plan_v2_instance_result_outputs
        WHERE instance_id = $1
        ORDER BY output_name COLLATE "C"
        "#,
    )
    .bind(descriptor.instance_id().as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if rows.len() != request.outputs().len() {
        return Ok(false);
    }
    for (row, expected) in rows.iter().zip(request.outputs()) {
        if row
            .try_get::<String, _>("output_name")
            .map_err(operation_error)?
            != expected.name()
            || row
                .try_get::<String, _>("sensitivity")
                .map_err(operation_error)?
                != sensitivity_name(expected.sensitivity())
            || row
                .try_get::<Option<String>, _>("public_value")
                .map_err(operation_error)?
                .as_deref()
                != expected.public_value()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn decode_digest(
    row: &PgRow,
    column: &str,
) -> Result<Sha256Digest, LogicalInstanceResultStoreError> {
    let value: Vec<u8> = row.try_get(column).map_err(operation_error)?;
    digest_from_vec(value, column)
}

fn decode_optional_digest(
    row: &PgRow,
    column: &str,
) -> Result<Option<Sha256Digest>, LogicalInstanceResultStoreError> {
    let value: Option<Vec<u8>> = row.try_get(column).map_err(operation_error)?;
    value.map_or(Ok(None), |value| digest_from_vec(value, column).map(Some))
}

fn digest_from_vec(
    value: Vec<u8>,
    column: &str,
) -> Result<Sha256Digest, LogicalInstanceResultStoreError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| StoreError::corrupt_data(format!("{column} is not SHA-256")))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn size_i64(value: u64) -> Result<i64, LogicalInstanceResultStoreError> {
    i64::try_from(value).map_err(|_| {
        StoreError::corrupt_data("logical instance-result object size exceeds BIGINT").into()
    })
}

fn parse_conclusion(value: &str) -> Result<JobConclusion, LogicalInstanceResultStoreError> {
    match value {
        "success" => Ok(JobConclusion::Success),
        "failure" => Ok(JobConclusion::Failure),
        "cancelled" => Ok(JobConclusion::Cancelled),
        "timed_out" => Ok(JobConclusion::TimedOut),
        "skipped" => Ok(JobConclusion::Skipped),
        _ => Err(StoreError::corrupt_data("unknown terminal conclusion").into()),
    }
}

fn parse_secret_exposure(
    value: &str,
) -> Result<JobSecretExposure, LogicalInstanceResultStoreError> {
    match value {
        "secretless" => Ok(JobSecretExposure::Secretless),
        "capability_only" => Ok(JobSecretExposure::CapabilityOnly),
        "readable_secret" => Ok(JobSecretExposure::ReadableSecret),
        _ => Err(StoreError::corrupt_data("unknown job secret-exposure class").into()),
    }
}

fn parse_sensitivity(value: &str) -> Result<OutputSensitivity, LogicalInstanceResultStoreError> {
    match value {
        "public" => Ok(OutputSensitivity::Public),
        "secret_derived" => Ok(OutputSensitivity::SecretDerived),
        _ => Err(StoreError::corrupt_data("unknown logical output sensitivity").into()),
    }
}

const fn secret_exposure_name(value: JobSecretExposure) -> &'static str {
    match value {
        JobSecretExposure::Secretless => "secretless",
        JobSecretExposure::CapabilityOnly => "capability_only",
        JobSecretExposure::ReadableSecret => "readable_secret",
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

const fn sensitivity_name(value: automata_ci_core::OutputSensitivity) -> &'static str {
    match value {
        automata_ci_core::OutputSensitivity::Public => "public",
        automata_ci_core::OutputSensitivity::SecretDerived => "secret_derived",
    }
}

const fn quarantine_kind_name(value: LogicalInstanceResultQuarantineKind) -> &'static str {
    match value {
        LogicalInstanceResultQuarantineKind::RelationalEvidence => "relational_evidence",
        LogicalInstanceResultQuarantineKind::ObjectEvidence => "object_evidence",
        LogicalInstanceResultQuarantineKind::PayloadEvidence => "payload_evidence",
    }
}

fn corrupt_value(error: impl std::fmt::Display) -> LogicalInstanceResultStoreError {
    StoreError::corrupt_data(format!("invalid logical instance-result value: {error}")).into()
}

fn operation_error(error: sqlx::Error) -> LogicalInstanceResultStoreError {
    StoreError::operation(error).into()
}

#[cfg(test)]
mod tests {
    use super::optional_quarantine_target;
    use uuid::Uuid;

    #[test]
    fn raw_quarantine_fallback_does_not_require_a_typed_tenant_target() {
        assert!(optional_quarantine_target("\u{0085}".to_owned(), Uuid::from_u128(1)).is_none());
    }
}
