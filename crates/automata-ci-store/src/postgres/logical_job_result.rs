use std::collections::BTreeMap;

use async_trait::async_trait;
use automata_ci_core::{
    AttemptId, JOB_IR_SCHEMA_VERSION, JOB_RUNTIME_CONTEXT_SCHEMA_VERSION, JobConclusion, JobId,
    JobSecretExposure, OutputSensitivity, RunId, Sha256Digest, UnixMillis, WorkflowJobKey,
    WorkflowOutputKey,
};
use sqlx::{PgPool, Postgres, Row as _, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::PostgresStore;
use crate::{
    ActivatedLogicalInstanceDescriptor, AdmissionObject, ClaimLogicalJobResult,
    ClaimNextLogicalJobResult, ClaimedLogicalJobResult, CommitLogicalJobResult,
    LOGICAL_ACTIVATION_JOB_IR_MEDIA_TYPE, LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE,
    LOGICAL_JOB_RESULT_PLAN_MEDIA_TYPE, LogicalActivationObject, LogicalInstanceResultGeneration,
    LogicalInstanceResultWorkerId, LogicalInstanceTerminalOrdinal, LogicalJobInstanceOutput,
    LogicalJobInstanceResultEvidence, LogicalJobPrerequisiteEvidence, LogicalJobResultClaimFence,
    LogicalJobResultClaimNextOutcome, LogicalJobResultClaimOutcome, LogicalJobResultDescriptor,
    LogicalJobResultGeneration, LogicalJobResultOutput, LogicalJobResultQuarantineKind,
    LogicalJobResultQuarantineOutcome, LogicalJobResultReceipt, LogicalJobResultRepository,
    LogicalJobResultStoreError, LogicalJobResultTarget, LogicalJobResultWorkerId,
    LogicalWorkflowInstanceId, LogicalWorkflowInvocationId, LogicalWorkflowJobId, ObjectKey,
    QuarantineLogicalJobResult, StoreError, TenantScope, WORKFLOW_PLAN_SCHEMA,
    logical_activation::rederive_publication_digest,
    logical_instance_result::rederive_commit_digest as rederive_instance_commit_digest,
    logical_job_result::outputs_digest as derive_outputs_digest,
    logical_job_result::rederive_commit_digest,
};

const MAX_SELECTION_CLOCK_SKEW_MILLIS: i64 = 60_000;

async fn begin_read_committed(
    pool: &PgPool,
) -> Result<Transaction<'_, Postgres>, LogicalJobResultStoreError> {
    let mut transaction = pool.begin().await.map_err(operation_error)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
    Ok(transaction)
}

async fn database_now_ms(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<i64, LogicalJobResultStoreError> {
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

#[allow(clippy::too_many_lines)] // Claim paths keep the lock/validation order locally auditable.
#[async_trait]
impl LogicalJobResultRepository for PostgresStore {
    async fn claim_next_logical_job_result(
        &self,
        request: ClaimNextLogicalJobResult,
    ) -> Result<LogicalJobResultClaimNextOutcome, LogicalJobResultStoreError> {
        reserve_selection_request(self, &request).await?;
        let mut transaction = begin_read_committed(&self.pool).await?;
        if let Some(outcome) = reserve_or_replay_selection(&mut transaction, &request).await? {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(outcome);
        }
        let selection_now = database_now_ms(&mut transaction).await?;
        if request.expires_at().get() <= selection_now {
            return Err(LogicalJobResultStoreError::SelectionExpired);
        }
        let eligible_at = request.observed_at().get().min(selection_now);
        let Some(candidate) = lock_next_target(&mut transaction, eligible_at).await? else {
            finalize_idle_selection(&mut transaction, &request).await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(LogicalJobResultClaimNextOutcome::Idle);
        };
        let target = match decode_candidate_target(&candidate) {
            Ok(target) => target,
            Err(error) if is_target_local_relational_corruption(&error) => {
                quarantine_relational_selection(&mut transaction, &request, &candidate).await?;
                transaction.commit().await.map_err(operation_error)?;
                return Ok(LogicalJobResultClaimNextOutcome::Quarantined);
            }
            Err(error) => return Err(error),
        };
        let Some(row) = lock_target(&mut transaction, &target).await? else {
            quarantine_relational_selection(&mut transaction, &request, &candidate).await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(LogicalJobResultClaimNextOutcome::Quarantined);
        };
        let database_now = database_now_ms(&mut transaction).await?;
        let descriptor = match load_descriptor(&mut transaction, target.clone(), &row).await {
            Ok(Some(descriptor)) => descriptor,
            Ok(None) => {
                quarantine_relational_selection(&mut transaction, &request, &candidate).await?;
                transaction.commit().await.map_err(operation_error)?;
                return Ok(LogicalJobResultClaimNextOutcome::Quarantined);
            }
            Err(error) if is_target_local_relational_corruption(&error) => {
                quarantine_relational_selection(&mut transaction, &request, &candidate).await?;
                transaction.commit().await.map_err(operation_error)?;
                return Ok(LogicalJobResultClaimNextOutcome::Quarantined);
            }
            Err(error) => return Err(error),
        };
        if database_now < descriptor.evidence_ready_at().get() {
            quarantine_relational_selection(&mut transaction, &request, &candidate).await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(LogicalJobResultClaimNextOutcome::Quarantined);
        }
        let targeted = ClaimLogicalJobResult::new(
            target,
            request.owner(),
            request.observed_at(),
            request.expires_at(),
        )
        .map_err(corrupt_value)?;
        let durable = match load_durable_claim(&mut transaction, targeted.target()).await {
            Ok(durable) => durable,
            Err(error) if is_target_local_relational_corruption(&error) => {
                quarantine_relational_selection(&mut transaction, &request, &candidate).await?;
                transaction.commit().await.map_err(operation_error)?;
                return Ok(LogicalJobResultClaimNextOutcome::Quarantined);
            }
            Err(error) => return Err(error),
        };
        if let Err(error) = validate_target_state(&row, durable.as_ref()) {
            if is_target_local_relational_corruption(&error) {
                quarantine_relational_selection(&mut transaction, &request, &candidate).await?;
                transaction.commit().await.map_err(operation_error)?;
                return Ok(LogicalJobResultClaimNextOutcome::Quarantined);
            }
            return Err(error);
        }
        let outcome = if let Some(durable) = durable {
            match resolve_durable_claim(
                &mut transaction,
                &targeted,
                descriptor,
                durable,
                database_now,
                ClaimClockAdmission::PrevalidatedSelection,
            )
            .await
            {
                Ok(outcome) => outcome,
                Err(error) if is_target_local_relational_corruption(&error) => {
                    quarantine_relational_selection(&mut transaction, &request, &candidate).await?;
                    transaction.commit().await.map_err(operation_error)?;
                    return Ok(LogicalJobResultClaimNextOutcome::Quarantined);
                }
                Err(error) => return Err(error),
            }
        } else {
            validate_prevalidated_selection_time(&targeted, &descriptor, database_now)?;
            insert_initial_claim(&mut transaction, &targeted, descriptor).await?
        };
        let claimed = match outcome {
            LogicalJobResultClaimOutcome::Claimed(claimed) => claimed,
            LogicalJobResultClaimOutcome::Busy
            | LogicalJobResultClaimOutcome::Finalized(_)
            | LogicalJobResultClaimOutcome::NotReady => {
                finalize_idle_selection(&mut transaction, &request).await?;
                transaction.commit().await.map_err(operation_error)?;
                return Ok(LogicalJobResultClaimNextOutcome::Idle);
            }
        };
        finalize_claimed_selection(&mut transaction, &request, &claimed).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(LogicalJobResultClaimNextOutcome::Claimed(claimed))
    }

    async fn claim_logical_job_result(
        &self,
        request: ClaimLogicalJobResult,
    ) -> Result<LogicalJobResultClaimOutcome, LogicalJobResultStoreError> {
        let mut transaction = begin_read_committed(&self.pool).await?;
        let _ = lock_due_target(&mut transaction, request.target().logical_job_id()).await?;
        let row = lock_target(&mut transaction, request.target())
            .await?
            .ok_or(LogicalJobResultStoreError::InvalidTarget)?;
        let database_now = database_now_ms(&mut transaction).await?;
        let durable = load_durable_claim(&mut transaction, request.target()).await?;
        validate_target_state(&row, durable.as_ref())?;
        let Some(descriptor) =
            load_descriptor(&mut transaction, request.target().clone(), &row).await?
        else {
            if durable.is_some() {
                return Err(StoreError::corrupt_data(
                    "logical job-result claim exists without complete immutable evidence",
                )
                .into());
            }
            transaction.commit().await.map_err(operation_error)?;
            return Ok(LogicalJobResultClaimOutcome::NotReady);
        };
        if database_now < descriptor.evidence_ready_at().get() {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(LogicalJobResultClaimOutcome::NotReady);
        }
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

        let rows = sqlx::query(
            r"
            INSERT INTO workflow_plan_v2_job_result_claims (
                logical_job_id, run_id, invocation_id, descriptor_digest,
                state, owner_id, generation, claimed_at_ms, expires_at_ms,
                created_at_ms, updated_at_ms
            ) VALUES ($1,$2,$3,$4,'aggregating',$5,1,$6,$7,$6,$6)
            ON CONFLICT (logical_job_id) DO NOTHING
            ",
        )
        .bind(request.target().logical_job_id().as_uuid())
        .bind(request.target().run_id().as_uuid())
        .bind(request.target().invocation_id().as_uuid())
        .bind(descriptor.descriptor_digest().as_bytes().as_slice())
        .bind(request.owner().as_uuid())
        .bind(request.observed_at().get())
        .bind(request.expires_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?
        .rows_affected();
        if rows != 1 {
            return Err(StoreError::corrupt_data(
                "locked logical job-result target produced a claim conflict",
            )
            .into());
        }
        let fence = make_fence(
            request.target().clone(),
            request.owner(),
            1,
            &descriptor,
            request.observed_at(),
            request.expires_at(),
        )?;
        let claimed =
            ClaimedLogicalJobResult::new(descriptor, fence, false).map_err(corrupt_value)?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(LogicalJobResultClaimOutcome::Claimed(claimed))
    }

    async fn commit_logical_job_result(
        &self,
        request: CommitLogicalJobResult,
    ) -> Result<LogicalJobResultReceipt, LogicalJobResultStoreError> {
        let mut transaction = begin_read_committed(&self.pool).await?;
        let _ =
            lock_due_target(&mut transaction, request.claim().target().logical_job_id()).await?;
        let row = lock_target(&mut transaction, request.claim().target())
            .await?
            .ok_or(LogicalJobResultStoreError::InvalidTarget)?;
        let database_now = database_now_ms(&mut transaction).await?;
        let descriptor = load_descriptor(&mut transaction, request.claim().target().clone(), &row)
            .await?
            .ok_or_else(|| {
                StoreError::corrupt_data("claimed logical job lost immutable aggregation evidence")
            })?;
        let durable = load_durable_claim(&mut transaction, request.claim().target())
            .await?
            .ok_or(LogicalJobResultStoreError::ClaimRejected)?;
        validate_target_state(&row, Some(&durable))?;
        durable.verify_descriptor(&descriptor)?;
        if durable.state == "finalized" {
            verify_exact_finalized_commit(&mut transaction, &request, &descriptor, &durable)
                .await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(LogicalJobResultReceipt::new(&request, &descriptor, true));
        }
        if !durable.matches_fence(request.claim())
            || database_now < durable.claimed_at
            || database_now >= durable.expires_at
            || request.finalized_at().get() < durable.claimed_at
            || request.finalized_at().get() >= durable.expires_at
        {
            return Err(LogicalJobResultStoreError::ClaimRejected);
        }

        insert_result(&mut transaction, &request, &descriptor).await?;
        insert_instance_evidence(&mut transaction, &descriptor).await?;
        insert_prerequisite_evidence(&mut transaction, &descriptor).await?;
        insert_outputs(&mut transaction, &request, &descriptor).await?;
        let terminal_state = terminal_job_state(request.effective_conclusion());
        let updated = sqlx::query(
            r"
            UPDATE workflow_plan_v2_jobs
            SET state = $5, updated_at_ms = $6
            WHERE run_id = $1 AND invocation_id = $2 AND id = $3
              AND state IN ('activated', 'skipped')
              AND execution_kind = 'steps'
              AND updated_at_ms <= $6
              AND EXISTS (
                  SELECT 1
                  FROM workflow_plan_v2_job_results AS result
                  WHERE result.logical_job_id = $3
                    AND result.descriptor_digest = $4
                    AND result.finalized_at_ms = $6
              )
            ",
        )
        .bind(descriptor.target().run_id().as_uuid())
        .bind(descriptor.target().invocation_id().as_uuid())
        .bind(descriptor.target().logical_job_id().as_uuid())
        .bind(descriptor.descriptor_digest().as_bytes().as_slice())
        .bind(terminal_state)
        .bind(request.finalized_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?
        .rows_affected();
        if updated != 1 {
            return Err(StoreError::corrupt_data(
                "logical job terminal-state update lost its locked target",
            )
            .into());
        }
        let finalized = sqlx::query(
            r"
            UPDATE workflow_plan_v2_job_result_claims
            SET state = 'finalized', updated_at_ms = $8
            WHERE logical_job_id = $1 AND run_id = $2 AND invocation_id = $3
              AND state = 'aggregating' AND owner_id = $4
              AND generation = $5 AND descriptor_digest = $6
              AND claimed_at_ms = $7 AND expires_at_ms = $9
            ",
        )
        .bind(descriptor.target().logical_job_id().as_uuid())
        .bind(descriptor.target().run_id().as_uuid())
        .bind(descriptor.target().invocation_id().as_uuid())
        .bind(request.claim().owner().as_uuid())
        .bind(request.claim().generation().as_i64())
        .bind(request.claim().descriptor_digest().as_bytes().as_slice())
        .bind(request.claim().claimed_at().get())
        .bind(request.finalized_at().get())
        .bind(request.claim().expires_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?
        .rows_affected();
        if finalized != 1 {
            return Err(StoreError::corrupt_data(
                "logical job-result claim disappeared during finalization",
            )
            .into());
        }
        transaction.commit().await.map_err(operation_error)?;
        Ok(LogicalJobResultReceipt::new(&request, &descriptor, false))
    }

    async fn quarantine_logical_job_result(
        &self,
        request: QuarantineLogicalJobResult,
    ) -> Result<LogicalJobResultQuarantineOutcome, LogicalJobResultStoreError> {
        let mut transaction = begin_read_committed(&self.pool).await?;
        if quarantine_exists(&mut transaction, request.claim().target()).await? {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(LogicalJobResultQuarantineOutcome::AlreadyQuarantined);
        }
        let Some(due) =
            lock_due_target(&mut transaction, request.claim().target().logical_job_id()).await?
        else {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(LogicalJobResultQuarantineOutcome::FenceRejected);
        };
        let Some(row) = lock_target(&mut transaction, request.claim().target()).await? else {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(LogicalJobResultQuarantineOutcome::FenceRejected);
        };
        let Some(durable) = load_durable_claim(&mut transaction, request.claim().target()).await?
        else {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(LogicalJobResultQuarantineOutcome::FenceRejected);
        };
        let Some(descriptor) =
            load_descriptor(&mut transaction, request.claim().target().clone(), &row).await?
        else {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(LogicalJobResultQuarantineOutcome::FenceRejected);
        };
        let database_now = database_now_ms(&mut transaction).await?;
        if &descriptor != request.descriptor()
            || !durable.matches_fence(request.claim())
            || durable.verify_descriptor(request.descriptor()).is_err()
            || validate_target_state(&row, Some(&durable)).is_err()
            || database_now < durable.claimed_at
            || database_now >= durable.expires_at
        {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(LogicalJobResultQuarantineOutcome::FenceRejected);
        }
        let inserted =
            insert_quarantine(&mut transaction, &due, request.kind(), Some(&durable)).await?;
        if !inserted && !quarantine_exists(&mut transaction, request.claim().target()).await? {
            return Err(StoreError::corrupt_data(
                "logical job-result quarantine insert produced no durable evidence",
            )
            .into());
        }
        transaction.commit().await.map_err(operation_error)?;
        Ok(if inserted {
            LogicalJobResultQuarantineOutcome::Quarantined
        } else {
            LogicalJobResultQuarantineOutcome::AlreadyQuarantined
        })
    }
}

async fn insert_initial_claim(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimLogicalJobResult,
    descriptor: LogicalJobResultDescriptor,
) -> Result<LogicalJobResultClaimOutcome, LogicalJobResultStoreError> {
    let rows = sqlx::query(
        r"
        INSERT INTO workflow_plan_v2_job_result_claims (
            logical_job_id, run_id, invocation_id, descriptor_digest,
            state, owner_id, generation, claimed_at_ms, expires_at_ms,
            created_at_ms, updated_at_ms
        ) VALUES ($1,$2,$3,$4,'aggregating',$5,1,$6,$7,$6,$6)
        ON CONFLICT (logical_job_id) DO NOTHING
        ",
    )
    .bind(request.target().logical_job_id().as_uuid())
    .bind(request.target().run_id().as_uuid())
    .bind(request.target().invocation_id().as_uuid())
    .bind(descriptor.descriptor_digest().as_bytes().as_slice())
    .bind(request.owner().as_uuid())
    .bind(request.observed_at().get())
    .bind(request.expires_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if rows != 1 {
        return Err(StoreError::corrupt_data(
            "locked logical job-result target produced a claim conflict",
        )
        .into());
    }
    let fence = make_fence(
        request.target().clone(),
        request.owner(),
        1,
        &descriptor,
        request.observed_at(),
        request.expires_at(),
    )?;
    ClaimedLogicalJobResult::new(descriptor, fence, false)
        .map(LogicalJobResultClaimOutcome::Claimed)
        .map_err(corrupt_value)
}

async fn reserve_or_replay_selection(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalJobResult,
) -> Result<Option<LogicalJobResultClaimNextOutcome>, LogicalJobResultStoreError> {
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
        return Err(LogicalJobResultStoreError::SelectionConflict);
    }
    if expires_at <= database_now_ms(transaction).await? {
        return Err(LogicalJobResultStoreError::SelectionExpired);
    }
    let outcome: String = selection.try_get("outcome").map_err(operation_error)?;
    if outcome == "selecting" {
        return Ok(None);
    }
    if outcome == "idle" {
        return Ok(Some(LogicalJobResultClaimNextOutcome::Idle));
    }
    if outcome == "quarantined" {
        verify_quarantined_selection(transaction, &selection).await?;
        return Ok(Some(LogicalJobResultClaimNextOutcome::Quarantined));
    }
    if outcome != "claimed" {
        return Err(StoreError::corrupt_data("invalid job-result selection outcome").into());
    }
    let target = decode_candidate_target(&selection)?;
    let row = lock_target(transaction, &target)
        .await?
        .ok_or_else(|| StoreError::corrupt_data("job-result selection target disappeared"))?;
    let descriptor = load_descriptor(transaction, target.clone(), &row)
        .await?
        .ok_or_else(|| StoreError::corrupt_data("selected job lost immutable evidence"))?;
    let durable = load_durable_claim(transaction, &target)
        .await?
        .ok_or_else(|| StoreError::corrupt_data("job selection has no durable claim"))?;
    validate_target_state(&row, Some(&durable))?;
    durable.verify_descriptor(&descriptor)?;
    let generation: i64 = selection
        .try_get::<Option<i64>, _>("generation")
        .map_err(operation_error)?
        .ok_or_else(|| StoreError::corrupt_data("claimed job selection lacks generation"))?;
    if durable.generation != generation
        || durable.owner_id != owner_id
        || durable.claimed_at != claimed_at
        || durable.expires_at != expires_at
    {
        return Err(StoreError::corrupt_data(
            "job-result selection disagrees with its claim generation",
        )
        .into());
    }
    if durable.state == "finalized" {
        return load_receipt(transaction, &descriptor, true)
            .await
            .map(LogicalJobResultClaimNextOutcome::Finalized)
            .map(Some);
    }
    claimed_from_durable(descriptor, &durable, true)
        .map(LogicalJobResultClaimNextOutcome::Claimed)
        .map(Some)
}

async fn verify_quarantined_selection(
    transaction: &mut Transaction<'_, Postgres>,
    selection: &PgRow,
) -> Result<(), LogicalJobResultStoreError> {
    let tenant_id = required_optional::<String>(selection, "tenant_id")?;
    let run_id = required_optional::<Uuid>(selection, "run_id")?;
    let invocation_id = required_optional::<Uuid>(selection, "invocation_id")?;
    let logical_job_id = required_optional::<Uuid>(selection, "logical_job_id")?;
    if selection
        .try_get::<Option<i64>, _>("generation")
        .map_err(operation_error)?
        .is_some()
    {
        return Err(StoreError::corrupt_data(
            "quarantined job-result selection unexpectedly carries a generation",
        )
        .into());
    }
    let has_ledger: bool = sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_job_result_quarantines
            WHERE logical_job_id = $1 AND tenant_id = $2
              AND run_id = $3 AND invocation_id = $4
        )
        ",
    )
    .bind(logical_job_id)
    .bind(tenant_id)
    .bind(run_id)
    .bind(invocation_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if has_ledger {
        Ok(())
    } else {
        Err(StoreError::corrupt_data(
            "quarantined job-result selection lacks its quarantine ledger",
        )
        .into())
    }
}

async fn lock_selection_request(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalJobResult,
) -> Result<PgRow, LogicalJobResultStoreError> {
    lock_selection_request_optional(transaction, request)
        .await?
        .ok_or_else(|| StoreError::corrupt_data("reserved job-result selection disappeared").into())
}

async fn lock_selection_request_optional(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalJobResult,
) -> Result<Option<PgRow>, LogicalJobResultStoreError> {
    sqlx::query(
        r"
        SELECT owner_id, claimed_at_ms, expires_at_ms, outcome,
               tenant_id, run_id, invocation_id, logical_job_id, generation
        FROM workflow_plan_v2_job_result_selections
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
    request: &ClaimNextLogicalJobResult,
) -> Result<(), LogicalJobResultStoreError> {
    if selection
        .try_get::<Uuid, _>("owner_id")
        .map_err(operation_error)?
        == request.owner().as_uuid()
        && selection
            .try_get::<i64, _>("claimed_at_ms")
            .map_err(operation_error)?
            == request.observed_at().get()
        && selection
            .try_get::<i64, _>("expires_at_ms")
            .map_err(operation_error)?
            == request.expires_at().get()
    {
        Ok(())
    } else {
        Err(LogicalJobResultStoreError::SelectionConflict)
    }
}

async fn accept_live_selection_reservation_replay(
    transaction: &mut Transaction<'_, Postgres>,
    selection: &PgRow,
    request: &ClaimNextLogicalJobResult,
) -> Result<(), LogicalJobResultStoreError> {
    verify_selection_identity(selection, request)?;
    if request.expires_at().get() <= database_now_ms(transaction).await? {
        return Err(LogicalJobResultStoreError::SelectionExpired);
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // Replay admission and bounded cleanup share one horizon lock.
async fn reserve_selection_request(
    store: &PostgresStore,
    request: &ClaimNextLogicalJobResult,
) -> Result<(), LogicalJobResultStoreError> {
    let mut transaction = begin_read_committed(&store.pool).await?;
    if let Some(selection) = lock_selection_request_optional(&mut transaction, request).await? {
        accept_live_selection_reservation_replay(&mut transaction, &selection, request).await?;
        transaction.commit().await.map_err(operation_error)?;
        return Ok(());
    }
    let (floor, horizon_updated_at, database_now): (i64, i64, i64) = sqlx::query_as(
        r"
        SELECT replay_floor_ms, updated_at_ms,
               floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint
        FROM workflow_plan_v2_result_selection_replay_horizons
        WHERE queue_name = 'job'
        FOR UPDATE
        ",
    )
    .fetch_one(&mut *transaction)
    .await
    .map_err(operation_error)?;
    if let Some(selection) = lock_selection_request_optional(&mut transaction, request).await? {
        accept_live_selection_reservation_replay(&mut transaction, &selection, request).await?;
        transaction.commit().await.map_err(operation_error)?;
        return Ok(());
    }
    if floor > horizon_updated_at || horizon_updated_at > database_now {
        return Err(StoreError::corrupt_data(
            "job-result replay horizon disagrees with authoritative database time",
        )
        .into());
    }
    if request.observed_at().get() < database_now.saturating_sub(MAX_SELECTION_CLOCK_SKEW_MILLIS)
        || request.observed_at().get()
            > database_now.saturating_add(MAX_SELECTION_CLOCK_SKEW_MILLIS)
    {
        return Err(LogicalJobResultStoreError::SelectionClockSkew);
    }
    if request.expires_at().get() <= floor || request.expires_at().get() <= database_now {
        return Err(LogicalJobResultStoreError::SelectionExpired);
    }
    let advanced = sqlx::query(
        r"
        UPDATE workflow_plan_v2_result_selection_replay_horizons
        SET replay_floor_ms = $1, updated_at_ms = $1
        WHERE queue_name = 'job'
          AND replay_floor_ms = $2 AND updated_at_ms = $3
        ",
    )
    .bind(database_now)
    .bind(floor)
    .bind(horizon_updated_at)
    .execute(&mut *transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if advanced != 1 {
        return Err(
            StoreError::corrupt_data("locked job-result replay horizon disappeared").into(),
        );
    }
    sqlx::query(
        r"
        WITH expired AS (
            SELECT selection_id
            FROM workflow_plan_v2_job_result_selections
            WHERE expires_at_ms <= $1
            ORDER BY expires_at_ms, selection_id
            FOR UPDATE SKIP LOCKED
            LIMIT 1024
        )
        DELETE FROM workflow_plan_v2_job_result_selections AS selection
        USING expired
        WHERE selection.selection_id = expired.selection_id
        ",
    )
    .bind(database_now)
    .execute(&mut *transaction)
    .await
    .map_err(operation_error)?;
    let inserted = sqlx::query(
        r"
        INSERT INTO workflow_plan_v2_job_result_selections (
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
            "locked job-result replay horizon produced a reservation conflict",
        )
        .into());
    }
    transaction.commit().await.map_err(operation_error)?;
    Ok(())
}

async fn finalize_idle_selection(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalJobResult,
) -> Result<(), LogicalJobResultStoreError> {
    let rows = sqlx::query(
        r"
        UPDATE workflow_plan_v2_job_result_selections
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
        Err(StoreError::corrupt_data("job-result Idle selection lost its reservation").into())
    }
}

async fn finalize_claimed_selection(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalJobResult,
    claimed: &ClaimedLogicalJobResult,
) -> Result<(), LogicalJobResultStoreError> {
    let target = claimed.claim().target();
    let rows = sqlx::query(
        r"
        UPDATE workflow_plan_v2_job_result_selections
        SET outcome = 'claimed', tenant_id = $2, run_id = $3,
            invocation_id = $4, logical_job_id = $5, generation = $7
        WHERE selection_id = $1 AND outcome = 'selecting'
          AND owner_id = $6 AND claimed_at_ms = $8 AND expires_at_ms = $9
        ",
    )
    .bind(request.selection_id().as_uuid())
    .bind(target.tenant().as_str())
    .bind(target.run_id().as_uuid())
    .bind(target.invocation_id().as_uuid())
    .bind(target.logical_job_id().as_uuid())
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
        Err(StoreError::corrupt_data("job-result claim selection lost its reservation").into())
    }
}

async fn quarantine_relational_selection(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalJobResult,
    due: &PgRow,
) -> Result<(), LogicalJobResultStoreError> {
    let database_now = database_now_ms(transaction).await?;
    let durable = match decode_candidate_target(due) {
        Ok(target) => match load_durable_claim(transaction, &target).await {
            Ok(Some(durable))
                if durable.state == "aggregating"
                    && durable.claimed_at <= database_now
                    && database_now < durable.expires_at =>
            {
                Some(durable)
            }
            Ok(_) => None,
            Err(error) if is_target_local_relational_corruption(&error) => None,
            Err(error) => return Err(error),
        },
        Err(error) if is_target_local_relational_corruption(&error) => None,
        Err(error) => return Err(error),
    };
    let _ = insert_quarantine(
        transaction,
        due,
        LogicalJobResultQuarantineKind::RelationalEvidence,
        durable.as_ref(),
    )
    .await?;
    let rows = sqlx::query(
        r"
        UPDATE workflow_plan_v2_job_result_selections
        SET outcome = 'quarantined', tenant_id = $2, run_id = $3,
            invocation_id = $4, logical_job_id = $5, generation = NULL
        WHERE selection_id = $1 AND outcome = 'selecting'
          AND owner_id = $6 AND claimed_at_ms = $7 AND expires_at_ms = $8
        ",
    )
    .bind(request.selection_id().as_uuid())
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
    .bind(request.owner().as_uuid())
    .bind(request.observed_at().get())
    .bind(request.expires_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if rows != 1 {
        return Err(StoreError::corrupt_data(
            "job-result quarantine selection lost its reservation",
        )
        .into());
    }
    Ok(())
}

fn is_target_local_relational_corruption(error: &LogicalJobResultStoreError) -> bool {
    matches!(
        error,
        LogicalJobResultStoreError::Store(StoreError::CorruptData(_))
            | LogicalJobResultStoreError::InvalidTarget
    )
}

async fn resolve_durable_claim(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimLogicalJobResult,
    descriptor: LogicalJobResultDescriptor,
    durable: DurableJobResultClaim,
    database_now: i64,
    clock_admission: ClaimClockAdmission,
) -> Result<LogicalJobResultClaimOutcome, LogicalJobResultStoreError> {
    durable.verify_descriptor(&descriptor)?;
    if durable.state == "finalized" {
        return load_receipt(transaction, &descriptor, true)
            .await
            .map(LogicalJobResultClaimOutcome::Finalized);
    }
    if durable.is_exact_replay(request) {
        if database_now >= durable.expires_at {
            return Err(match clock_admission {
                ClaimClockAdmission::Required => LogicalJobResultStoreError::ClaimExpired,
                ClaimClockAdmission::PrevalidatedSelection => {
                    LogicalJobResultStoreError::SelectionExpired
                }
            });
        }
        return claimed_from_durable(descriptor, &durable, true)
            .map(LogicalJobResultClaimOutcome::Claimed);
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
        return Ok(LogicalJobResultClaimOutcome::Busy);
    }
    let next_generation = durable
        .generation
        .checked_add(1)
        .filter(|value| *value > 0)
        .ok_or(LogicalJobResultStoreError::GenerationExhausted)?;
    let rows = sqlx::query(
        r"
        UPDATE workflow_plan_v2_job_result_claims
        SET owner_id = $3, generation = $4, claimed_at_ms = $5,
            expires_at_ms = $6, updated_at_ms = $5
        WHERE logical_job_id = $1 AND state = 'aggregating'
          AND generation = $2
        ",
    )
    .bind(request.target().logical_job_id().as_uuid())
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
            "locked logical job-result claim disappeared during takeover",
        )
        .into());
    }
    let fence = make_fence(
        request.target().clone(),
        request.owner(),
        next_generation,
        &descriptor,
        request.observed_at(),
        request.expires_at(),
    )?;
    ClaimedLogicalJobResult::new(descriptor, fence, false)
        .map(LogicalJobResultClaimOutcome::Claimed)
        .map_err(corrupt_value)
}

fn validate_new_claim_time(
    request: &ClaimLogicalJobResult,
    descriptor: &LogicalJobResultDescriptor,
    database_now: i64,
) -> Result<(), LogicalJobResultStoreError> {
    if request.observed_at() < descriptor.evidence_ready_at() {
        return Err(LogicalJobResultStoreError::InvalidTarget);
    }
    if request.observed_at().get() < database_now.saturating_sub(MAX_SELECTION_CLOCK_SKEW_MILLIS)
        || request.observed_at().get()
            > database_now.saturating_add(MAX_SELECTION_CLOCK_SKEW_MILLIS)
    {
        return Err(LogicalJobResultStoreError::ClaimClockSkew);
    }
    if request.expires_at().get() <= database_now {
        return Err(LogicalJobResultStoreError::ClaimExpired);
    }
    Ok(())
}

fn validate_prevalidated_selection_time(
    request: &ClaimLogicalJobResult,
    descriptor: &LogicalJobResultDescriptor,
    database_now: i64,
) -> Result<(), LogicalJobResultStoreError> {
    if request.observed_at() < descriptor.evidence_ready_at() {
        return Err(LogicalJobResultStoreError::InvalidTarget);
    }
    if request.expires_at().get() <= database_now {
        return Err(LogicalJobResultStoreError::SelectionExpired);
    }
    Ok(())
}

async fn lock_target(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalJobResultTarget,
) -> Result<Option<PgRow>, LogicalJobResultStoreError> {
    sqlx::query(
        r"
        SELECT job.state AS logical_job_state,
               invocation.state AS invocation_state,
               marker.state AS marker_state, job.logical_key,
               job.source_order, job.execution_kind,
               invocation.plan_digest, invocation.plan_object_key,
               invocation.plan_size_bytes, invocation.plan_media_type,
               invocation.plan_schema,
               publication.activation_input_digest,
               publication.activation_output_digest,
               publication.condition_matched, publication.instance_count,
               publication.published_at_ms
        FROM workflow_plan_v2_jobs AS job
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = job.run_id AND invocation.id = job.invocation_id
        JOIN workflow_plan_v2_runs AS marker ON marker.run_id = job.run_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        JOIN workflow_plan_v2_activation_publications AS publication
          ON publication.run_id = job.run_id
         AND publication.invocation_id = job.invocation_id
         AND publication.logical_job_id = job.id
        WHERE repository.tenant_id = $1
          AND job.run_id = $2 AND job.invocation_id = $3 AND job.id = $4
          AND job.execution_kind = 'steps'
          AND invocation.plan_schema = 2
          AND invocation.plan_media_type =
              'application/vnd.automata.workflow-plan+json'
          AND marker.orchestration_schema = 1
          AND run.admission_epoch = 4 AND run.plan_schema = 2
          AND job.state IN ('activated', 'completed', 'skipped', 'cancelled', 'failed')
          AND invocation.state IN ('pending', 'active', 'completed', 'cancelled', 'failed')
          AND marker.state IN ('pending', 'active', 'completed', 'cancelled', 'failed')
        FOR UPDATE OF job
        ",
    )
    .bind(target.tenant().as_str())
    .bind(target.run_id().as_uuid())
    .bind(target.invocation_id().as_uuid())
    .bind(target.logical_job_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn load_durable_claim(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalJobResultTarget,
) -> Result<Option<DurableJobResultClaim>, LogicalJobResultStoreError> {
    let row = sqlx::query(
        r"
        SELECT run_id AS result_claim_run_id,
               invocation_id AS result_claim_invocation_id,
               descriptor_digest AS result_claim_descriptor_digest,
               state AS result_claim_state,
               owner_id AS result_claim_owner_id,
               generation AS result_claim_generation,
               claimed_at_ms AS result_claim_claimed_at_ms,
               expires_at_ms AS result_claim_expires_at_ms
        FROM workflow_plan_v2_job_result_claims
        WHERE logical_job_id = $1
        FOR UPDATE
        ",
    )
    .bind(target.logical_job_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    match row {
        Some(row) => DurableJobResultClaim::decode(&row),
        None => Ok(None),
    }
}

fn validate_target_state(
    row: &PgRow,
    durable: Option<&DurableJobResultClaim>,
) -> Result<(), LogicalJobResultStoreError> {
    if durable.is_some_and(|claim| claim.state == "finalized") {
        return Ok(());
    }
    let state: String = row.try_get("logical_job_state").map_err(operation_error)?;
    let invocation_state: String = row.try_get("invocation_state").map_err(operation_error)?;
    let marker_state: String = row.try_get("marker_state").map_err(operation_error)?;
    if matches!(state.as_str(), "activated" | "skipped")
        && matches!(invocation_state.as_str(), "pending" | "active")
        && matches!(marker_state.as_str(), "pending" | "active")
    {
        Ok(())
    } else {
        Err(LogicalJobResultStoreError::InvalidTarget)
    }
}

fn decode_candidate_target(
    row: &PgRow,
) -> Result<LogicalJobResultTarget, LogicalJobResultStoreError> {
    let tenant = TenantScope::from_authenticated_tenant_id(
        row.try_get::<String, _>("tenant_id")
            .map_err(operation_error)?,
    )
    .map_err(corrupt_value)?;
    LogicalJobResultTarget::new(
        tenant,
        RunId::from_uuid(row.try_get("run_id").map_err(operation_error)?),
        LogicalWorkflowInvocationId::from_uuid(
            row.try_get("invocation_id").map_err(operation_error)?,
        )
        .map_err(corrupt_value)?,
        LogicalWorkflowJobId::from_uuid(row.try_get("logical_job_id").map_err(operation_error)?)
            .map_err(corrupt_value)?,
    )
    .map_err(corrupt_value)
}

async fn lock_next_target(
    transaction: &mut Transaction<'_, Postgres>,
    eligible_at: i64,
) -> Result<Option<PgRow>, LogicalJobResultStoreError> {
    sqlx::query(
        r"
        SELECT tenant_id, run_id, invocation_id, logical_job_id,
               source_order, ready_at_ms, available_at_ms
        FROM workflow_plan_v2_job_result_due
        WHERE available_at_ms <= $1
          AND NOT EXISTS (
              SELECT 1
              FROM workflow_plan_v2_job_result_quarantines AS quarantine
              WHERE quarantine.logical_job_id =
                    workflow_plan_v2_job_result_due.logical_job_id
          )
        ORDER BY available_at_ms, ready_at_ms, run_id, invocation_id,
                 source_order, logical_job_id
        FOR UPDATE SKIP LOCKED
        LIMIT 1
        ",
    )
    .bind(eligible_at)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn lock_due_target(
    transaction: &mut Transaction<'_, Postgres>,
    logical_job_id: LogicalWorkflowJobId,
) -> Result<Option<PgRow>, LogicalJobResultStoreError> {
    sqlx::query(
        r"
        SELECT logical_job_id, tenant_id, run_id, invocation_id,
               source_order, ready_at_ms, available_at_ms
        FROM workflow_plan_v2_job_result_due
        WHERE logical_job_id = $1
        FOR UPDATE
        ",
    )
    .bind(logical_job_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn quarantine_exists(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalJobResultTarget,
) -> Result<bool, LogicalJobResultStoreError> {
    let row = sqlx::query(
        r"
        SELECT tenant_id, run_id, invocation_id
        FROM workflow_plan_v2_job_result_quarantines
        WHERE logical_job_id = $1
        ",
    )
    .bind(target.logical_job_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(row) = row else {
        return Ok(false);
    };
    if row
        .try_get::<String, _>("tenant_id")
        .map_err(operation_error)?
        != target.tenant().as_str()
        || row.try_get::<Uuid, _>("run_id").map_err(operation_error)? != target.run_id().as_uuid()
        || row
            .try_get::<Uuid, _>("invocation_id")
            .map_err(operation_error)?
            != target.invocation_id().as_uuid()
    {
        return Err(StoreError::corrupt_data(
            "logical job-result quarantine target identity is inconsistent",
        )
        .into());
    }
    Ok(true)
}

async fn insert_quarantine(
    transaction: &mut Transaction<'_, Postgres>,
    due: &PgRow,
    kind: LogicalJobResultQuarantineKind,
    claim: Option<&DurableJobResultClaim>,
) -> Result<bool, LogicalJobResultStoreError> {
    let claim_owner_id = claim.map(|claim| claim.owner_id);
    let claim_generation = claim.map(|claim| claim.generation);
    let claim_claimed_at = claim.map(|claim| claim.claimed_at);
    let claim_expires_at = claim.map(|claim| claim.expires_at);
    let claim_descriptor_digest = claim.map(|claim| claim.descriptor_digest.as_bytes().to_vec());
    let inserted = sqlx::query_scalar::<_, i64>(
        r"
        INSERT INTO workflow_plan_v2_job_result_quarantines (
            logical_job_id, tenant_id, run_id, invocation_id, source_order,
            ready_at_ms, available_at_ms, failure_kind,
            claim_owner_id, claim_generation, claim_claimed_at_ms,
            claim_expires_at_ms, claim_descriptor_digest
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
        ON CONFLICT (logical_job_id) DO NOTHING
        RETURNING quarantined_at_ms
        ",
    )
    .bind(
        due.try_get::<Uuid, _>("logical_job_id")
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

async fn load_descriptor(
    transaction: &mut Transaction<'_, Postgres>,
    target: LogicalJobResultTarget,
    row: &PgRow,
) -> Result<Option<LogicalJobResultDescriptor>, LogicalJobResultStoreError> {
    if row
        .try_get::<String, _>("execution_kind")
        .map_err(operation_error)?
        != "steps"
    {
        return Err(LogicalJobResultStoreError::InvalidTarget);
    }
    let logical_key = WorkflowJobKey::new(
        row.try_get::<String, _>("logical_key")
            .map_err(operation_error)?,
    )
    .map_err(corrupt_value)?;
    let source_order = u16::try_from(
        row.try_get::<i32, _>("source_order")
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("invalid logical job source order"))?;
    let plan_schema: i16 = row.try_get("plan_schema").map_err(operation_error)?;
    if plan_schema != i16::try_from(WORKFLOW_PLAN_SCHEMA).unwrap_or(i16::MAX) {
        return Err(StoreError::corrupt_data("non-current logical result plan schema").into());
    }
    let plan = decode_admission_object(
        row,
        "plan_digest",
        "plan_object_key",
        "plan_size_bytes",
        "plan_media_type",
    )?;
    if plan.media_type() != LOGICAL_JOB_RESULT_PLAN_MEDIA_TYPE {
        return Err(StoreError::corrupt_data("non-current logical result plan media type").into());
    }
    let instance_count = u32::try_from(
        row.try_get::<i32, _>("instance_count")
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("negative logical activation instance count"))?;
    let condition_matched = row.try_get("condition_matched").map_err(operation_error)?;
    let activation_input_digest = decode_digest(row, "activation_input_digest")?;
    let activation_output_digest = decode_digest(row, "activation_output_digest")?;
    let Some(instances) = load_instances(
        transaction,
        &target,
        instance_count,
        activation_input_digest,
        activation_output_digest,
        condition_matched,
    )
    .await?
    else {
        return Ok(None);
    };
    let Some(prerequisites) = load_prerequisites(transaction, &target).await? else {
        return Ok(None);
    };
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
        UnixMillis::new(row.try_get("published_at_ms").map_err(operation_error)?),
    )
    .map_err(corrupt_value)?;
    Ok(Some(descriptor))
}

#[allow(clippy::too_many_lines)]
async fn load_instances(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalJobResultTarget,
    expected_count: u32,
    activation_input_digest: Sha256Digest,
    activation_output_digest: Sha256Digest,
    condition_matched: bool,
) -> Result<Option<Vec<LogicalJobInstanceResultEvidence>>, LogicalJobResultStoreError> {
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
               result.terminal_ordinal, result.descriptor_digest,
               result.outputs_digest, result.commit_digest,
               result.raw_conclusion, result.effective_conclusion,
               result.continue_on_error, result.secret_exposure_class,
               result.output_count, result.finalized_at_ms,
               result.job_id, result.attempt_id,
               result.claim_owner_id, result.claim_generation,
               result.claim_started_at_ms, result.claim_expires_at_ms,
               claim.state AS instance_claim_state,
               claim.owner_id AS current_claim_owner_id,
               claim.generation AS current_claim_generation,
               claim.descriptor_digest AS current_claim_descriptor_digest,
               claim.claimed_at_ms AS current_claim_started_at_ms,
               claim.expires_at_ms AS current_claim_expires_at_ms
        FROM workflow_plan_v2_instances AS instance
        LEFT JOIN workflow_plan_v2_instance_results AS result
          ON result.instance_id = instance.id
         AND result.run_id = instance.run_id
         AND result.invocation_id = instance.invocation_id
         AND result.logical_job_id = instance.logical_job_id
        LEFT JOIN workflow_plan_v2_instance_result_claims AS claim
          ON claim.instance_id = result.instance_id
        LEFT JOIN workflow_plan_v2_job_environment_evidence AS evidence
          ON evidence.instance_id = instance.id
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
        return Ok(None);
    }
    let mut activation_instances = Vec::with_capacity(rows.len());
    for row in &rows {
        activation_instances.push(decode_activation_instance(target, row)?);
    }
    if rederive_publication_digest(
        target.run_id(),
        target.invocation_id(),
        target.logical_job_id(),
        activation_input_digest,
        condition_matched,
        &activation_instances,
    ) != activation_output_digest
    {
        return Err(StoreError::corrupt_data(
            "activation publication digest disagrees with immutable instance rows",
        )
        .into());
    }
    if expected_count == 0 {
        return Ok(Some(Vec::new()));
    }
    let mut outputs = load_instance_outputs(transaction, target).await?;
    let mut instances = Vec::with_capacity(rows.len());
    for row in rows {
        let instance_uuid: Uuid = row.try_get("instance_id").map_err(operation_error)?;
        let state: Option<String> = row
            .try_get("instance_claim_state")
            .map_err(operation_error)?;
        if state.as_deref() != Some("finalized") {
            return Ok(None);
        }
        let instance_outputs = outputs.remove(&instance_uuid).unwrap_or_default();
        instances.push(decode_instance_evidence(
            &row,
            instance_uuid,
            instance_outputs,
        )?);
    }
    if !outputs.is_empty() {
        return Err(StoreError::corrupt_data("orphan logical instance outputs").into());
    }
    Ok(Some(instances))
}

async fn load_instance_outputs(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalJobResultTarget,
) -> Result<BTreeMap<Uuid, Vec<LogicalJobInstanceOutput>>, LogicalJobResultStoreError> {
    let rows = sqlx::query(
        r#"
        SELECT output.instance_id, output.output_name,
               output.sensitivity, output.public_value
        FROM workflow_plan_v2_instance_result_outputs AS output
        JOIN workflow_plan_v2_instance_results AS result
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
    for output in rows {
        let instance_id: Uuid = output.try_get("instance_id").map_err(operation_error)?;
        let name = WorkflowOutputKey::new(
            output
                .try_get::<String, _>("output_name")
                .map_err(operation_error)?,
        )
        .map_err(corrupt_value)?;
        let sensitivity = parse_sensitivity(
            &output
                .try_get::<String, _>("sensitivity")
                .map_err(operation_error)?,
        )?;
        let public_value = output
            .try_get::<Option<String>, _>("public_value")
            .map_err(operation_error)?;
        outputs.entry(instance_id).or_default().push(
            LogicalJobInstanceOutput::new(name, sensitivity, public_value)
                .map_err(corrupt_value)?,
        );
    }
    Ok(outputs)
}

fn decode_instance_evidence(
    row: &PgRow,
    instance_uuid: Uuid,
    outputs: Vec<LogicalJobInstanceOutput>,
) -> Result<LogicalJobInstanceResultEvidence, LogicalJobResultStoreError> {
    let output_count = usize::try_from(required_optional::<i32>(row, "output_count")?)
        .map_err(|_| StoreError::corrupt_data("negative instance output count"))?;
    if output_count != outputs.len() {
        return Err(StoreError::corrupt_data(
            "instance output count disagrees with immutable rows",
        )
        .into());
    }
    let stored_outputs_digest = decode_optional_required_digest(row, "outputs_digest")?;
    let instance_id = LogicalWorkflowInstanceId::from_uuid(instance_uuid).map_err(corrupt_value)?;
    let terminal_ordinal = LogicalInstanceTerminalOrdinal::new(
        u64::try_from(required_optional::<i64>(row, "terminal_ordinal")?)
            .map_err(|_| StoreError::corrupt_data("invalid terminal ordinal"))?,
    )
    .map_err(corrupt_value)?;
    let descriptor_digest = decode_optional_required_digest(row, "descriptor_digest")?;
    let stored_commit_digest = decode_optional_required_digest(row, "commit_digest")?;
    let raw_conclusion = parse_conclusion(&required_optional::<String>(row, "raw_conclusion")?)?;
    let effective_conclusion =
        parse_conclusion(&required_optional::<String>(row, "effective_conclusion")?)?;
    let finalized_at = UnixMillis::new(required_optional::<i64>(row, "finalized_at_ms")?);
    let claim_owner: Uuid = required_optional(row, "claim_owner_id")?;
    let claim_generation: i64 = required_optional(row, "claim_generation")?;
    let claim_started_at: i64 = required_optional(row, "claim_started_at_ms")?;
    let claim_expires_at: i64 = required_optional(row, "claim_expires_at_ms")?;
    if claim_owner != required_optional::<Uuid>(row, "current_claim_owner_id")?
        || claim_generation != required_optional::<i64>(row, "current_claim_generation")?
        || descriptor_digest
            != decode_optional_required_digest(row, "current_claim_descriptor_digest")?
        || claim_started_at != required_optional::<i64>(row, "current_claim_started_at_ms")?
        || claim_expires_at != required_optional::<i64>(row, "current_claim_expires_at_ms")?
    {
        return Err(StoreError::corrupt_data(
            "instance result root disagrees with its finalized claim fence",
        )
        .into());
    }
    let expected_commit_digest = rederive_instance_commit_digest(
        instance_id,
        JobId::from_uuid(required_optional(row, "job_id")?),
        AttemptId::from_uuid(required_optional(row, "attempt_id")?),
        terminal_ordinal,
        LogicalInstanceResultWorkerId::from_uuid(claim_owner).map_err(corrupt_value)?,
        LogicalInstanceResultGeneration::new(
            u64::try_from(claim_generation)
                .map_err(|_| StoreError::corrupt_data("invalid instance claim generation"))?,
        )
        .map_err(corrupt_value)?,
        descriptor_digest,
        raw_conclusion,
        effective_conclusion,
        required_optional(row, "continue_on_error")?,
        parse_secret_exposure(&required_optional::<String>(row, "secret_exposure_class")?)?,
        stored_outputs_digest,
        finalized_at,
    );
    if expected_commit_digest != stored_commit_digest {
        return Err(StoreError::corrupt_data(
            "instance commit digest disagrees with immutable root evidence",
        )
        .into());
    }
    let evidence = LogicalJobInstanceResultEvidence::new(
        instance_id,
        u32::try_from(
            row.try_get::<i32, _>("matrix_index")
                .map_err(operation_error)?,
        )
        .map_err(|_| StoreError::corrupt_data("negative matrix index"))?,
        terminal_ordinal,
        descriptor_digest,
        stored_commit_digest,
        raw_conclusion,
        effective_conclusion,
        outputs,
        finalized_at,
    )
    .map_err(corrupt_value)?;
    if evidence.outputs_digest() != stored_outputs_digest {
        return Err(StoreError::corrupt_data(
            "instance output digest disagrees with immutable child rows",
        )
        .into());
    }
    Ok(evidence)
}

fn decode_activation_instance(
    target: &LogicalJobResultTarget,
    row: &PgRow,
) -> Result<ActivatedLogicalInstanceDescriptor, LogicalJobResultStoreError> {
    let job_ir_media: String = row.try_get("job_ir_media_type").map_err(operation_error)?;
    let job_ir_version: i16 = row.try_get("job_ir_version").map_err(operation_error)?;
    let runtime_media: String = row
        .try_get("runtime_context_media_type")
        .map_err(operation_error)?;
    let runtime_schema: i16 = row
        .try_get("runtime_context_schema")
        .map_err(operation_error)?;
    if job_ir_media != LOGICAL_ACTIVATION_JOB_IR_MEDIA_TYPE
        || job_ir_version != i16::try_from(JOB_IR_SCHEMA_VERSION).unwrap_or(-1)
        || runtime_media != LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE
        || runtime_schema != i16::try_from(JOB_RUNTIME_CONTEXT_SCHEMA_VERSION).unwrap_or(-1)
    {
        return Err(
            StoreError::corrupt_data("activation instance object contract is not current").into(),
        );
    }
    let job_ir = LogicalActivationObject::job_ir(
        decode_digest(row, "job_ir_digest")?,
        ObjectKey::new(
            row.try_get::<String, _>("job_ir_object_key")
                .map_err(operation_error)?,
        )
        .map_err(corrupt_value)?,
        decode_encoded_size(row, "job_ir_size_bytes")?,
    )
    .map_err(corrupt_value)?;
    let runtime_context = LogicalActivationObject::runtime_context(
        decode_digest(row, "runtime_context_digest")?,
        ObjectKey::new(
            row.try_get::<String, _>("runtime_context_object_key")
                .map_err(operation_error)?,
        )
        .map_err(corrupt_value)?,
        decode_encoded_size(row, "runtime_context_size_bytes")?,
    )
    .map_err(corrupt_value)?;
    ActivatedLogicalInstanceDescriptor::from_durable(
        LogicalWorkflowInstanceId::from_uuid(row.try_get("instance_id").map_err(operation_error)?)
            .map_err(corrupt_value)?,
        target.run_id(),
        target.invocation_id(),
        target.logical_job_id(),
        u32::try_from(
            row.try_get::<i32, _>("matrix_index")
                .map_err(operation_error)?,
        )
        .map_err(|_| StoreError::corrupt_data("negative activation matrix index"))?,
        u32::try_from(
            row.try_get::<i32, _>("matrix_total")
                .map_err(operation_error)?,
        )
        .map_err(|_| StoreError::corrupt_data("negative activation matrix total"))?,
        decode_digest(row, "matrix_digest")?,
        row.try_get("workspace").map_err(operation_error)?,
        job_ir,
        runtime_context,
        super::protected_environment::decode_job_environment_activation_evidence(row)?,
    )
    .map_err(corrupt_value)
}

fn decode_encoded_size(row: &PgRow, column: &str) -> Result<u64, LogicalJobResultStoreError> {
    u64::try_from(row.try_get::<i64, _>(column).map_err(operation_error)?)
        .map_err(|_| StoreError::corrupt_data("negative activation object size").into())
}

async fn load_prerequisites(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalJobResultTarget,
) -> Result<Option<Vec<LogicalJobPrerequisiteEvidence>>, LogicalJobResultStoreError> {
    let rows = sqlx::query(
        r"
        SELECT dependency.prerequisite_job_id,
               prerequisite_job.logical_key,
               prerequisite_job.source_order,
               result.descriptor_digest, result.instances_digest,
               result.prerequisites_digest, result.commit_digest,
               result.outputs_digest, result.output_count,
               result.effective_conclusion,
               result.closure_has_failure, result.closure_has_cancelled,
               result.closure_has_skipped, result.finalized_at_ms,
               result.claim_owner_id, result.claim_generation,
               result.claim_started_at_ms, result.claim_expires_at_ms,
               result.claim_state AS prerequisite_claim_state,
               result.run_id AS prerequisite_claim_run_id,
               result.invocation_id AS prerequisite_claim_invocation_id,
               result.descriptor_digest AS prerequisite_claim_descriptor_digest,
               result.claim_owner_id AS prerequisite_claim_owner_id,
               result.claim_generation AS prerequisite_claim_generation,
               result.claim_started_at_ms AS prerequisite_claim_claimed_at_ms,
               result.claim_expires_at_ms AS prerequisite_claim_expires_at_ms,
               result.carried
        FROM workflow_plan_v2_dependencies AS dependency
        JOIN workflow_plan_v2_jobs AS prerequisite_job
          ON prerequisite_job.run_id = dependency.run_id
         AND prerequisite_job.invocation_id = dependency.invocation_id
         AND prerequisite_job.id = dependency.prerequisite_job_id
        LEFT JOIN workflow_plan_v2_effective_job_results AS result
          ON result.run_id = dependency.run_id
         AND result.invocation_id = dependency.invocation_id
         AND result.logical_job_id = dependency.prerequisite_job_id
        WHERE dependency.run_id = $1 AND dependency.invocation_id = $2
          AND dependency.logical_job_id = $3
        ORDER BY prerequisite_job.source_order, dependency.prerequisite_job_id
        ",
    )
    .bind(target.run_id().as_uuid())
    .bind(target.invocation_id().as_uuid())
    .bind(target.logical_job_id().as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let mut outputs = load_prerequisite_outputs(transaction, target).await?;
    let mut prerequisites = Vec::with_capacity(rows.len());
    for row in rows {
        let state: Option<String> = row
            .try_get("prerequisite_claim_state")
            .map_err(operation_error)?;
        if state.as_deref() != Some("finalized") {
            return Ok(None);
        }
        let prerequisite_id: Uuid = row
            .try_get("prerequisite_job_id")
            .map_err(operation_error)?;
        let prerequisite_outputs = outputs.remove(&prerequisite_id).unwrap_or_default();
        let prerequisite =
            decode_prerequisite(target, &row, prerequisite_id, &prerequisite_outputs)?;
        if !row.try_get::<bool, _>("carried").map_err(operation_error)? {
            verify_prerequisite_descriptor(
                transaction,
                target,
                prerequisite_id,
                &row,
                &prerequisite,
            )
            .await?;
        }
        prerequisites.push(prerequisite);
    }
    if !outputs.is_empty() {
        return Err(StoreError::corrupt_data("orphan prerequisite outputs").into());
    }
    Ok(Some(prerequisites))
}

async fn load_prerequisite_outputs(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalJobResultTarget,
) -> Result<BTreeMap<Uuid, Vec<LogicalJobResultOutput>>, LogicalJobResultStoreError> {
    let rows = sqlx::query(
        r#"
        SELECT dependency.prerequisite_job_id, output.output_name,
               output.sensitivity, output.public_value
        FROM workflow_plan_v2_dependencies AS dependency
        JOIN workflow_plan_v2_effective_job_result_outputs AS output
          ON output.logical_job_id = dependency.prerequisite_job_id
        WHERE dependency.run_id = $1 AND dependency.invocation_id = $2
          AND dependency.logical_job_id = $3
        ORDER BY dependency.prerequisite_job_id,
                 output.output_name COLLATE "C"
        "#,
    )
    .bind(target.run_id().as_uuid())
    .bind(target.invocation_id().as_uuid())
    .bind(target.logical_job_id().as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let mut outputs: BTreeMap<Uuid, Vec<LogicalJobResultOutput>> = BTreeMap::new();
    for output in rows {
        let logical_job_id: Uuid = output
            .try_get("prerequisite_job_id")
            .map_err(operation_error)?;
        let name = WorkflowOutputKey::new(
            output
                .try_get::<String, _>("output_name")
                .map_err(operation_error)?,
        )
        .map_err(corrupt_value)?;
        let sensitivity = parse_sensitivity(
            &output
                .try_get::<String, _>("sensitivity")
                .map_err(operation_error)?,
        )?;
        let public_value = output
            .try_get::<Option<String>, _>("public_value")
            .map_err(operation_error)?;
        outputs.entry(logical_job_id).or_default().push(
            LogicalJobResultOutput::from_durable(name, sensitivity, public_value)
                .map_err(corrupt_value)?,
        );
    }
    Ok(outputs)
}

fn decode_prerequisite(
    target: &LogicalJobResultTarget,
    row: &PgRow,
    prerequisite_id: Uuid,
    outputs: &[LogicalJobResultOutput],
) -> Result<LogicalJobPrerequisiteEvidence, LogicalJobResultStoreError> {
    let output_count = usize::try_from(required_optional::<i32>(row, "output_count")?)
        .map_err(|_| StoreError::corrupt_data("negative prerequisite output count"))?;
    let outputs_digest = decode_optional_required_digest(row, "outputs_digest")?;
    if output_count != outputs.len() || derive_outputs_digest(outputs) != outputs_digest {
        return Err(StoreError::corrupt_data(
            "prerequisite output digest disagrees with immutable child rows",
        )
        .into());
    }
    let prerequisite_target = LogicalJobResultTarget::new(
        target.tenant().clone(),
        target.run_id(),
        target.invocation_id(),
        LogicalWorkflowJobId::from_uuid(prerequisite_id).map_err(corrupt_value)?,
    )
    .map_err(corrupt_value)?;
    let owner = LogicalJobResultWorkerId::from_uuid(required_optional(row, "claim_owner_id")?)
        .map_err(corrupt_value)?;
    let generation = LogicalJobResultGeneration::new(
        u64::try_from(required_optional::<i64>(row, "claim_generation")?)
            .map_err(|_| StoreError::corrupt_data("invalid prerequisite claim generation"))?,
    )
    .map_err(corrupt_value)?;
    let conclusion = parse_conclusion(&required_optional::<String>(row, "effective_conclusion")?)?;
    let has_failure = required_optional(row, "closure_has_failure")?;
    let has_cancelled = required_optional(row, "closure_has_cancelled")?;
    let has_skipped = required_optional(row, "closure_has_skipped")?;
    let finalized_at = UnixMillis::new(required_optional(row, "finalized_at_ms")?);
    if required_optional::<Uuid>(row, "claim_owner_id")?
        != required_optional::<Uuid>(row, "prerequisite_claim_owner_id")?
        || required_optional::<i64>(row, "claim_generation")?
            != required_optional::<i64>(row, "prerequisite_claim_generation")?
        || required_optional::<i64>(row, "claim_started_at_ms")?
            != required_optional::<i64>(row, "prerequisite_claim_claimed_at_ms")?
        || required_optional::<i64>(row, "claim_expires_at_ms")?
            != required_optional::<i64>(row, "prerequisite_claim_expires_at_ms")?
        || decode_optional_required_digest(row, "descriptor_digest")?
            != decode_optional_required_digest(row, "prerequisite_claim_descriptor_digest")?
        || required_optional::<Uuid>(row, "prerequisite_claim_run_id")? != target.run_id().as_uuid()
        || required_optional::<Uuid>(row, "prerequisite_claim_invocation_id")?
            != target.invocation_id().as_uuid()
    {
        return Err(StoreError::corrupt_data(
            "prerequisite result root disagrees with its finalized claim fence",
        )
        .into());
    }
    let stored_commit = decode_optional_required_digest(row, "commit_digest")?;
    let expected_commit = rederive_commit_digest(
        &prerequisite_target,
        owner,
        generation,
        decode_optional_required_digest(row, "descriptor_digest")?,
        decode_optional_required_digest(row, "instances_digest")?,
        decode_optional_required_digest(row, "prerequisites_digest")?,
        conclusion,
        has_failure,
        has_cancelled,
        has_skipped,
        outputs_digest,
        finalized_at,
    );
    let carried = row.try_get::<bool, _>("carried").map_err(operation_error)?;
    if !carried && expected_commit != stored_commit {
        return Err(StoreError::corrupt_data(
            "prerequisite commit digest disagrees with immutable root evidence",
        )
        .into());
    }
    LogicalJobPrerequisiteEvidence::new(
        prerequisite_target.logical_job_id(),
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
        stored_commit,
        outputs_digest,
        conclusion,
        has_failure,
        has_cancelled,
        has_skipped,
        finalized_at,
    )
    .map_err(corrupt_value)
}

async fn verify_prerequisite_descriptor(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalJobResultTarget,
    prerequisite_id: Uuid,
    root: &PgRow,
    evidence: &LogicalJobPrerequisiteEvidence,
) -> Result<(), LogicalJobResultStoreError> {
    let prerequisite_target = LogicalJobResultTarget::new(
        target.tenant().clone(),
        target.run_id(),
        target.invocation_id(),
        LogicalWorkflowJobId::from_uuid(prerequisite_id).map_err(corrupt_value)?,
    )
    .map_err(corrupt_value)?;
    let target_row = lock_target(transaction, &prerequisite_target)
        .await?
        .ok_or_else(|| StoreError::corrupt_data("prerequisite target disappeared"))?;
    let descriptor = Box::pin(load_descriptor(
        transaction,
        prerequisite_target,
        &target_row,
    ))
    .await?
    .ok_or_else(|| StoreError::corrupt_data("finalized prerequisite lost child evidence"))?;
    if descriptor.logical_key() != evidence.logical_key()
        || descriptor.source_order() != evidence.source_order()
        || descriptor.descriptor_digest()
            != decode_optional_required_digest(root, "descriptor_digest")?
        || descriptor.instances_digest()
            != decode_optional_required_digest(root, "instances_digest")?
        || descriptor.prerequisites_digest()
            != decode_optional_required_digest(root, "prerequisites_digest")?
        || !instance_evidence_matches(transaction, &descriptor).await?
        || !prerequisite_evidence_matches(transaction, &descriptor).await?
    {
        return Err(StoreError::corrupt_data(
            "prerequisite child-set digests disagree with rederived evidence",
        )
        .into());
    }
    Ok(())
}

#[derive(Debug)]
struct DurableJobResultClaim {
    run_id: Uuid,
    invocation_id: Uuid,
    descriptor_digest: Sha256Digest,
    state: String,
    owner_id: Uuid,
    generation: i64,
    claimed_at: i64,
    expires_at: i64,
}

impl DurableJobResultClaim {
    fn decode(row: &PgRow) -> Result<Option<Self>, LogicalJobResultStoreError> {
        let state: Option<String> = row.try_get("result_claim_state").map_err(operation_error)?;
        let Some(state) = state else {
            return Ok(None);
        };
        let claim = Self {
            run_id: required_optional(row, "result_claim_run_id")?,
            invocation_id: required_optional(row, "result_claim_invocation_id")?,
            descriptor_digest: decode_optional_required_digest(
                row,
                "result_claim_descriptor_digest",
            )?,
            state,
            owner_id: required_optional(row, "result_claim_owner_id")?,
            generation: required_optional(row, "result_claim_generation")?,
            claimed_at: required_optional(row, "result_claim_claimed_at_ms")?,
            expires_at: required_optional(row, "result_claim_expires_at_ms")?,
        };
        if !matches!(claim.state.as_str(), "aggregating" | "finalized")
            || claim.owner_id.is_nil()
            || claim.generation <= 0
            || claim.expires_at <= claim.claimed_at
        {
            return Err(
                StoreError::corrupt_data("invalid durable logical job-result claim").into(),
            );
        }
        Ok(Some(claim))
    }

    fn verify_descriptor(
        &self,
        descriptor: &LogicalJobResultDescriptor,
    ) -> Result<(), LogicalJobResultStoreError> {
        if self.run_id == descriptor.target().run_id().as_uuid()
            && self.invocation_id == descriptor.target().invocation_id().as_uuid()
            && self.descriptor_digest == descriptor.descriptor_digest()
        {
            Ok(())
        } else {
            Err(StoreError::corrupt_data(
                "logical job-result claim disagrees with immutable descriptor",
            )
            .into())
        }
    }

    fn is_exact_replay(&self, request: &ClaimLogicalJobResult) -> bool {
        self.state == "aggregating"
            && self.owner_id == request.owner().as_uuid()
            && self.claimed_at == request.observed_at().get()
            && self.expires_at == request.expires_at().get()
    }

    fn matches_fence(&self, fence: &LogicalJobResultClaimFence) -> bool {
        self.state == "aggregating"
            && self.owner_id == fence.owner().as_uuid()
            && self.generation == fence.generation().as_i64()
            && self.descriptor_digest == fence.descriptor_digest()
            && self.claimed_at == fence.claimed_at().get()
            && self.expires_at == fence.expires_at().get()
    }
}

fn make_fence(
    target: LogicalJobResultTarget,
    owner: LogicalJobResultWorkerId,
    generation: i64,
    descriptor: &LogicalJobResultDescriptor,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
) -> Result<LogicalJobResultClaimFence, LogicalJobResultStoreError> {
    let generation = u64::try_from(generation)
        .ok()
        .and_then(|value| LogicalJobResultGeneration::new(value).ok())
        .ok_or_else(|| StoreError::corrupt_data("invalid logical job-result generation"))?;
    LogicalJobResultClaimFence::new(
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
    descriptor: LogicalJobResultDescriptor,
    durable: &DurableJobResultClaim,
    replayed: bool,
) -> Result<ClaimedLogicalJobResult, LogicalJobResultStoreError> {
    let owner = LogicalJobResultWorkerId::from_uuid(durable.owner_id).map_err(corrupt_value)?;
    let fence = make_fence(
        descriptor.target().clone(),
        owner,
        durable.generation,
        &descriptor,
        UnixMillis::new(durable.claimed_at),
        UnixMillis::new(durable.expires_at),
    )?;
    ClaimedLogicalJobResult::new(descriptor, fence, replayed).map_err(corrupt_value)
}

async fn insert_result(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitLogicalJobResult,
    descriptor: &LogicalJobResultDescriptor,
) -> Result<(), LogicalJobResultStoreError> {
    sqlx::query(
        r"
        INSERT INTO workflow_plan_v2_job_results (
            logical_job_id, run_id, invocation_id, descriptor_digest,
            logical_key, source_order,
            plan_digest, plan_object_key, plan_size_bytes,
            plan_media_type, plan_schema,
            activation_output_digest, condition_matched,
            instance_count, instances_digest,
            prerequisite_count, prerequisites_digest,
            effective_conclusion,
            closure_has_failure, closure_has_cancelled, closure_has_skipped,
            output_count, outputs_digest, commit_digest,
            claim_owner_id, claim_generation, claim_started_at_ms,
            claim_expires_at_ms, finalized_at_ms
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
            $16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29
        )
        ",
    )
    .bind(descriptor.target().logical_job_id().as_uuid())
    .bind(descriptor.target().run_id().as_uuid())
    .bind(descriptor.target().invocation_id().as_uuid())
    .bind(descriptor.descriptor_digest().as_bytes().as_slice())
    .bind(descriptor.logical_key().as_str())
    .bind(i32::from(descriptor.source_order()))
    .bind(descriptor.plan().digest().as_bytes().as_slice())
    .bind(descriptor.plan().object_key().as_str())
    .bind(size_i64(descriptor.plan().encoded_size())?)
    .bind(descriptor.plan().media_type())
    .bind(i16::try_from(descriptor.plan_schema()).expect("current plan schema fits SMALLINT"))
    .bind(descriptor.activation_output_digest().as_bytes().as_slice())
    .bind(descriptor.condition_matched())
    .bind(i32::try_from(descriptor.instance_count()).expect("instance count fits INTEGER"))
    .bind(descriptor.instances_digest().as_bytes().as_slice())
    .bind(
        i32::try_from(descriptor.prerequisites().len())
            .map_err(|_| StoreError::corrupt_data("logical prerequisite count exceeds INTEGER"))?,
    )
    .bind(descriptor.prerequisites_digest().as_bytes().as_slice())
    .bind(conclusion_name(request.effective_conclusion()))
    .bind(request.closure_has_failure())
    .bind(request.closure_has_cancelled())
    .bind(request.closure_has_skipped())
    .bind(
        i32::try_from(request.outputs().len())
            .map_err(|_| StoreError::corrupt_data("logical output count exceeds INTEGER"))?,
    )
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

async fn insert_instance_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    descriptor: &LogicalJobResultDescriptor,
) -> Result<(), LogicalJobResultStoreError> {
    for instance in descriptor.instances() {
        sqlx::query(
            r"
            INSERT INTO workflow_plan_v2_job_result_instances (
                logical_job_id, instance_id, matrix_index, terminal_ordinal,
                instance_descriptor_digest, instance_outputs_digest,
                instance_commit_digest, raw_conclusion, effective_conclusion
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
            ",
        )
        .bind(descriptor.target().logical_job_id().as_uuid())
        .bind(instance.instance_id().as_uuid())
        .bind(i32::try_from(instance.matrix_index()).expect("matrix index fits INTEGER"))
        .bind(instance.terminal_ordinal().as_i64())
        .bind(instance.descriptor_digest().as_bytes().as_slice())
        .bind(instance.outputs_digest().as_bytes().as_slice())
        .bind(instance.commit_digest().as_bytes().as_slice())
        .bind(conclusion_name(instance.raw_conclusion()))
        .bind(conclusion_name(instance.effective_conclusion()))
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    }
    Ok(())
}

async fn insert_prerequisite_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    descriptor: &LogicalJobResultDescriptor,
) -> Result<(), LogicalJobResultStoreError> {
    for prerequisite in descriptor.prerequisites() {
        sqlx::query(
            r"
            INSERT INTO workflow_plan_v2_job_result_prerequisites (
                logical_job_id, prerequisite_job_id, prerequisite_source_order,
                prerequisite_commit_digest, prerequisite_outputs_digest,
                effective_conclusion, closure_has_failure,
                closure_has_cancelled, closure_has_skipped
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
            ",
        )
        .bind(descriptor.target().logical_job_id().as_uuid())
        .bind(prerequisite.logical_job_id().as_uuid())
        .bind(i32::from(prerequisite.source_order()))
        .bind(prerequisite.commit_digest().as_bytes().as_slice())
        .bind(prerequisite.outputs_digest().as_bytes().as_slice())
        .bind(conclusion_name(prerequisite.effective_conclusion()))
        .bind(prerequisite.closure_has_failure())
        .bind(prerequisite.closure_has_cancelled())
        .bind(prerequisite.closure_has_skipped())
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    }
    Ok(())
}

async fn insert_outputs(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitLogicalJobResult,
    descriptor: &LogicalJobResultDescriptor,
) -> Result<(), LogicalJobResultStoreError> {
    for output in request.outputs() {
        sqlx::query(
            r"
            INSERT INTO workflow_plan_v2_job_result_outputs (
                logical_job_id, output_name, sensitivity, public_value
            ) VALUES ($1,$2,$3,$4)
            ",
        )
        .bind(descriptor.target().logical_job_id().as_uuid())
        .bind(output.name().as_str())
        .bind(sensitivity_name(output.sensitivity()))
        .bind(output.public_value())
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    }
    Ok(())
}

async fn load_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    descriptor: &LogicalJobResultDescriptor,
    replayed: bool,
) -> Result<LogicalJobResultReceipt, LogicalJobResultStoreError> {
    let row = sqlx::query(receipt_query())
        .bind(descriptor.target().logical_job_id().as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?
        .ok_or_else(|| StoreError::corrupt_data("finalized logical claim has no result"))?;
    let receipt = decode_receipt(&row, descriptor, replayed)?;
    verify_finalized_result_evidence(transaction, descriptor, &receipt).await?;
    Ok(receipt)
}

fn receipt_query() -> &'static str {
    r"
    SELECT result.*, claim.state AS receipt_claim_state,
           claim.run_id AS receipt_claim_run_id,
           claim.invocation_id AS receipt_claim_invocation_id,
           claim.descriptor_digest AS receipt_claim_descriptor_digest,
           claim.owner_id AS receipt_claim_owner_id,
           claim.generation AS receipt_claim_generation,
           claim.claimed_at_ms AS receipt_claim_claimed_at_ms,
           claim.expires_at_ms AS receipt_claim_expires_at_ms,
           (SELECT count(*) FROM workflow_plan_v2_job_result_instances AS instance
            WHERE instance.logical_job_id = result.logical_job_id) AS actual_instance_count,
           (SELECT count(*) FROM workflow_plan_v2_job_result_prerequisites AS prerequisite
            WHERE prerequisite.logical_job_id = result.logical_job_id) AS actual_prerequisite_count,
           (SELECT count(*) FROM workflow_plan_v2_job_result_outputs AS output
            WHERE output.logical_job_id = result.logical_job_id) AS actual_output_count
    FROM workflow_plan_v2_job_results AS result
    JOIN workflow_plan_v2_job_result_claims AS claim
      ON claim.logical_job_id = result.logical_job_id
    WHERE result.logical_job_id = $1
    "
}

#[allow(clippy::too_many_lines)]
fn decode_receipt(
    row: &PgRow,
    descriptor: &LogicalJobResultDescriptor,
    replayed: bool,
) -> Result<LogicalJobResultReceipt, LogicalJobResultStoreError> {
    let logical_job_id =
        LogicalWorkflowJobId::from_uuid(row.try_get("logical_job_id").map_err(operation_error)?)
            .map_err(corrupt_value)?;
    let descriptor_digest = decode_digest(row, "descriptor_digest")?;
    let effective_conclusion = parse_conclusion(
        &row.try_get::<String, _>("effective_conclusion")
            .map_err(operation_error)?,
    )?;
    let closure_has_failure = row
        .try_get("closure_has_failure")
        .map_err(operation_error)?;
    let closure_has_cancelled = row
        .try_get("closure_has_cancelled")
        .map_err(operation_error)?;
    let closure_has_skipped = row
        .try_get("closure_has_skipped")
        .map_err(operation_error)?;
    let instance_count = decode_count(row, "instance_count", 256)?;
    let prerequisite_count = decode_count(row, "prerequisite_count", 128)?;
    let output_count = decode_count(row, "output_count", 256)?;
    let exact = logical_job_id == descriptor.target().logical_job_id()
        && descriptor_digest == descriptor.descriptor_digest()
        && row.try_get::<Uuid, _>("run_id").map_err(operation_error)?
            == descriptor.target().run_id().as_uuid()
        && row
            .try_get::<Uuid, _>("invocation_id")
            .map_err(operation_error)?
            == descriptor.target().invocation_id().as_uuid()
        && row
            .try_get::<String, _>("logical_key")
            .map_err(operation_error)?
            == descriptor.logical_key().as_str()
        && row
            .try_get::<i32, _>("source_order")
            .map_err(operation_error)?
            == i32::from(descriptor.source_order())
        && decode_digest(row, "plan_digest")? == descriptor.plan().digest()
        && row
            .try_get::<String, _>("plan_object_key")
            .map_err(operation_error)?
            == descriptor.plan().object_key().as_str()
        && row
            .try_get::<i64, _>("plan_size_bytes")
            .map_err(operation_error)?
            == i64::try_from(descriptor.plan().encoded_size()).unwrap_or(i64::MAX)
        && row
            .try_get::<String, _>("plan_media_type")
            .map_err(operation_error)?
            == descriptor.plan().media_type()
        && row
            .try_get::<i16, _>("plan_schema")
            .map_err(operation_error)?
            == i16::try_from(WORKFLOW_PLAN_SCHEMA).unwrap_or(i16::MAX)
        && decode_digest(row, "activation_output_digest")? == descriptor.activation_output_digest()
        && row
            .try_get::<bool, _>("condition_matched")
            .map_err(operation_error)?
            == descriptor.condition_matched()
        && instance_count == descriptor.instance_count()
        && decode_digest(row, "instances_digest")? == descriptor.instances_digest()
        && prerequisite_count
            == u32::try_from(descriptor.prerequisites().len()).unwrap_or(u32::MAX)
        && decode_digest(row, "prerequisites_digest")? == descriptor.prerequisites_digest()
        && row
            .try_get::<i64, _>("actual_instance_count")
            .map_err(operation_error)?
            == i64::from(instance_count)
        && row
            .try_get::<i64, _>("actual_prerequisite_count")
            .map_err(operation_error)?
            == i64::from(prerequisite_count)
        && row
            .try_get::<i64, _>("actual_output_count")
            .map_err(operation_error)?
            == i64::from(output_count)
        && row
            .try_get::<String, _>("receipt_claim_state")
            .map_err(operation_error)?
            == "finalized"
        && row
            .try_get::<Uuid, _>("receipt_claim_run_id")
            .map_err(operation_error)?
            == descriptor.target().run_id().as_uuid()
        && row
            .try_get::<Uuid, _>("receipt_claim_invocation_id")
            .map_err(operation_error)?
            == descriptor.target().invocation_id().as_uuid()
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
                .map_err(operation_error)?;
    if !exact {
        return Err(StoreError::corrupt_data(
            "logical job-result receipt disagrees with immutable descriptor",
        )
        .into());
    }
    LogicalJobResultReceipt::from_durable(
        logical_job_id,
        descriptor_digest,
        effective_conclusion,
        closure_has_failure,
        closure_has_cancelled,
        closure_has_skipped,
        instance_count,
        decode_digest(row, "instances_digest")?,
        prerequisite_count,
        decode_digest(row, "prerequisites_digest")?,
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
    request: &CommitLogicalJobResult,
    descriptor: &LogicalJobResultDescriptor,
    durable: &DurableJobResultClaim,
) -> Result<(), LogicalJobResultStoreError> {
    if durable.owner_id != request.claim().owner().as_uuid()
        || durable.generation != request.claim().generation().as_i64()
        || durable.claimed_at != request.claim().claimed_at().get()
        || durable.expires_at != request.claim().expires_at().get()
        || durable.descriptor_digest != request.claim().descriptor_digest()
    {
        return Err(LogicalJobResultStoreError::ClaimRejected);
    }
    let receipt = load_receipt(transaction, descriptor, true).await?;
    let exact = receipt.effective_conclusion() == request.effective_conclusion()
        && receipt.closure_has_failure() == request.closure_has_failure()
        && receipt.closure_has_cancelled() == request.closure_has_cancelled()
        && receipt.closure_has_skipped() == request.closure_has_skipped()
        && receipt.output_count() == u32::try_from(request.outputs().len()).unwrap_or(u32::MAX)
        && receipt.outputs_digest() == request.outputs_digest()
        && receipt.commit_digest() == request.commit_digest()
        && receipt.finalized_at() == request.finalized_at();
    if !exact || !outputs_match(transaction, request, descriptor).await? {
        return Err(LogicalJobResultStoreError::CommitConflict);
    }
    Ok(())
}

async fn verify_finalized_result_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    descriptor: &LogicalJobResultDescriptor,
    receipt: &LogicalJobResultReceipt,
) -> Result<(), LogicalJobResultStoreError> {
    let outputs = load_result_outputs(transaction, descriptor).await?;
    let owner = sqlx::query_scalar::<_, Uuid>(
        "SELECT claim_owner_id FROM workflow_plan_v2_job_results WHERE logical_job_id = $1",
    )
    .bind(descriptor.target().logical_job_id().as_uuid())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let generation = sqlx::query_scalar::<_, i64>(
        "SELECT claim_generation FROM workflow_plan_v2_job_results WHERE logical_job_id = $1",
    )
    .bind(descriptor.target().logical_job_id().as_uuid())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let owner = LogicalJobResultWorkerId::from_uuid(owner).map_err(corrupt_value)?;
    let generation = LogicalJobResultGeneration::new(
        u64::try_from(generation)
            .map_err(|_| StoreError::corrupt_data("invalid finalized claim generation"))?,
    )
    .map_err(corrupt_value)?;
    let expected_commit = rederive_commit_digest(
        descriptor.target(),
        owner,
        generation,
        receipt.descriptor_digest(),
        receipt.instances_digest(),
        receipt.prerequisites_digest(),
        receipt.effective_conclusion(),
        receipt.closure_has_failure(),
        receipt.closure_has_cancelled(),
        receipt.closure_has_skipped(),
        receipt.outputs_digest(),
        receipt.finalized_at(),
    );
    if u32::try_from(outputs.len()).unwrap_or(u32::MAX) != receipt.output_count()
        || derive_outputs_digest(&outputs) != receipt.outputs_digest()
        || expected_commit != receipt.commit_digest()
        || !instance_evidence_matches(transaction, descriptor).await?
        || !prerequisite_evidence_matches(transaction, descriptor).await?
    {
        return Err(StoreError::corrupt_data(
            "finalized logical job-result evidence failed complete reauthentication",
        )
        .into());
    }
    Ok(())
}

async fn load_result_outputs(
    transaction: &mut Transaction<'_, Postgres>,
    descriptor: &LogicalJobResultDescriptor,
) -> Result<Vec<LogicalJobResultOutput>, LogicalJobResultStoreError> {
    let rows = sqlx::query(
        r#"
        SELECT output_name, sensitivity, public_value
        FROM workflow_plan_v2_job_result_outputs
        WHERE logical_job_id = $1
        ORDER BY output_name COLLATE "C"
        "#,
    )
    .bind(descriptor.target().logical_job_id().as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    rows.into_iter()
        .map(|row| {
            LogicalJobResultOutput::from_durable(
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
            .map_err(corrupt_value)
        })
        .collect()
}

async fn outputs_match(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitLogicalJobResult,
    descriptor: &LogicalJobResultDescriptor,
) -> Result<bool, LogicalJobResultStoreError> {
    Ok(load_result_outputs(transaction, descriptor).await? == request.outputs())
}

async fn instance_evidence_matches(
    transaction: &mut Transaction<'_, Postgres>,
    descriptor: &LogicalJobResultDescriptor,
) -> Result<bool, LogicalJobResultStoreError> {
    let rows = sqlx::query(
        r"
        SELECT instance_id, matrix_index, terminal_ordinal,
               instance_descriptor_digest, instance_outputs_digest,
               instance_commit_digest, raw_conclusion, effective_conclusion
        FROM workflow_plan_v2_job_result_instances
        WHERE logical_job_id = $1 ORDER BY matrix_index
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
                != expected.terminal_ordinal().as_i64()
            || decode_digest(row, "instance_descriptor_digest")? != expected.descriptor_digest()
            || decode_digest(row, "instance_outputs_digest")? != expected.outputs_digest()
            || decode_digest(row, "instance_commit_digest")? != expected.commit_digest()
            || row
                .try_get::<String, _>("raw_conclusion")
                .map_err(operation_error)?
                != conclusion_name(expected.raw_conclusion())
            || row
                .try_get::<String, _>("effective_conclusion")
                .map_err(operation_error)?
                != conclusion_name(expected.effective_conclusion())
        {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn prerequisite_evidence_matches(
    transaction: &mut Transaction<'_, Postgres>,
    descriptor: &LogicalJobResultDescriptor,
) -> Result<bool, LogicalJobResultStoreError> {
    let rows = sqlx::query(
        r"
        SELECT prerequisite_job_id, prerequisite_source_order,
               prerequisite_commit_digest, prerequisite_outputs_digest,
               effective_conclusion, closure_has_failure,
               closure_has_cancelled, closure_has_skipped
        FROM workflow_plan_v2_job_result_prerequisites
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
            || row
                .try_get::<String, _>("effective_conclusion")
                .map_err(operation_error)?
                != conclusion_name(expected.effective_conclusion())
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

fn decode_admission_object(
    row: &PgRow,
    digest_column: &str,
    key_column: &str,
    size_column: &str,
    media_column: &str,
) -> Result<AdmissionObject, LogicalJobResultStoreError> {
    AdmissionObject::new(
        decode_digest(row, digest_column)?,
        ObjectKey::new(
            row.try_get::<String, _>(key_column)
                .map_err(operation_error)?,
        )
        .map_err(corrupt_value)?,
        u64::try_from(
            row.try_get::<i64, _>(size_column)
                .map_err(operation_error)?,
        )
        .map_err(|_| StoreError::corrupt_data("invalid admission object size"))?,
        row.try_get::<String, _>(media_column)
            .map_err(operation_error)?,
    )
    .map_err(corrupt_value)
}

fn required_optional<T>(row: &PgRow, column: &str) -> Result<T, LogicalJobResultStoreError>
where
    for<'value> T: sqlx::Decode<'value, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get::<Option<T>, _>(column)
        .map_err(operation_error)?
        .ok_or_else(|| StoreError::corrupt_data(format!("logical evidence lacks {column}")).into())
}

fn decode_count(
    row: &PgRow,
    column: &str,
    maximum: u32,
) -> Result<u32, LogicalJobResultStoreError> {
    let value = u32::try_from(row.try_get::<i32, _>(column).map_err(operation_error)?)
        .map_err(|_| StoreError::corrupt_data(format!("negative {column}")))?;
    if value > maximum {
        return Err(StoreError::corrupt_data(format!("oversized {column}")).into());
    }
    Ok(value)
}

fn decode_digest(row: &PgRow, column: &str) -> Result<Sha256Digest, LogicalJobResultStoreError> {
    let value: Vec<u8> = row.try_get(column).map_err(operation_error)?;
    digest_from_vec(value, column)
}

fn decode_optional_required_digest(
    row: &PgRow,
    column: &str,
) -> Result<Sha256Digest, LogicalJobResultStoreError> {
    let value: Vec<u8> = required_optional(row, column)?;
    digest_from_vec(value, column)
}

fn digest_from_vec(
    value: Vec<u8>,
    column: &str,
) -> Result<Sha256Digest, LogicalJobResultStoreError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| StoreError::corrupt_data(format!("{column} is not SHA-256")))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn size_i64(value: u64) -> Result<i64, LogicalJobResultStoreError> {
    i64::try_from(value)
        .map_err(|_| StoreError::corrupt_data("logical plan size exceeds BIGINT").into())
}

fn parse_conclusion(value: &str) -> Result<JobConclusion, LogicalJobResultStoreError> {
    match value {
        "success" => Ok(JobConclusion::Success),
        "failure" => Ok(JobConclusion::Failure),
        "cancelled" => Ok(JobConclusion::Cancelled),
        "timed_out" => Ok(JobConclusion::TimedOut),
        "skipped" => Ok(JobConclusion::Skipped),
        _ => Err(StoreError::corrupt_data("unknown logical conclusion").into()),
    }
}

fn parse_secret_exposure(value: &str) -> Result<JobSecretExposure, LogicalJobResultStoreError> {
    match value {
        "secretless" => Ok(JobSecretExposure::Secretless),
        "capability_only" => Ok(JobSecretExposure::CapabilityOnly),
        "readable_secret" => Ok(JobSecretExposure::ReadableSecret),
        _ => Err(StoreError::corrupt_data("unknown job secret-exposure class").into()),
    }
}

fn parse_sensitivity(value: &str) -> Result<OutputSensitivity, LogicalJobResultStoreError> {
    match value {
        "public" => Ok(OutputSensitivity::Public),
        "secret_derived" => Ok(OutputSensitivity::SecretDerived),
        _ => Err(StoreError::corrupt_data("unknown logical output sensitivity").into()),
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

const fn quarantine_kind_name(value: LogicalJobResultQuarantineKind) -> &'static str {
    match value {
        LogicalJobResultQuarantineKind::RelationalEvidence => "relational_evidence",
        LogicalJobResultQuarantineKind::ObjectEvidence => "object_evidence",
        LogicalJobResultQuarantineKind::PayloadEvidence => "payload_evidence",
    }
}

const fn terminal_job_state(value: JobConclusion) -> &'static str {
    match value {
        JobConclusion::Success => "completed",
        JobConclusion::Failure | JobConclusion::TimedOut => "failed",
        JobConclusion::Cancelled => "cancelled",
        JobConclusion::Skipped => "skipped",
    }
}

fn corrupt_value(error: impl std::fmt::Display) -> LogicalJobResultStoreError {
    StoreError::corrupt_data(format!("invalid logical job-result value: {error}")).into()
}

fn operation_error(error: sqlx::Error) -> LogicalJobResultStoreError {
    StoreError::operation(error).into()
}
