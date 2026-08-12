use async_trait::async_trait;
use automata_ci_core::{
    JobConclusion, MAX_LOGICAL_JOB_NEEDS, MAX_LOGICAL_JOB_OUTPUTS, MAX_LOGICAL_JOBS, RunId,
    Sha256Digest, UnixMillis, WorkflowJobKey,
};
use sqlx::{PgPool, Postgres, Row as _, Transaction, postgres::PgRow};

use super::PostgresStore;
use crate::{
    ClaimLogicalRunFinalization, ClaimedLogicalRunFinalization, CommitLogicalRunFinalization,
    LogicalRunFinalizationClaimFence, LogicalRunFinalizationDescriptor,
    LogicalRunFinalizationGeneration, LogicalRunFinalizationOpenState,
    LogicalRunFinalizationReceipt, LogicalRunFinalizationRepository,
    LogicalRunFinalizationStoreError, LogicalRunFinalizationTarget, LogicalRunFinalizationWorkerId,
    LogicalRunFinalizationWorkflowStatus, LogicalRunJobResultEvidence, LogicalWorkflowInvocationId,
    LogicalWorkflowJobId, StoreError, TenantScope,
};

const MAX_LOGICAL_RUN_FINALIZATION_CLOCK_SKEW_MILLIS: i64 = 60_000;

const LOCK_READY_CANDIDATE_QUERY: &str = r"
        SELECT repository.tenant_id, marker.run_id, marker.root_invocation_id,
               marker.admission_digest, marker.state AS marker_state,
               marker.revision AS marker_revision,
               marker.updated_at_ms AS marker_updated_at_ms,
               invocation.state AS invocation_state,
               invocation.revision AS invocation_revision,
               invocation.updated_at_ms AS invocation_updated_at_ms,
               run.status AS workflow_status,
               run.updated_at_ms AS workflow_updated_at_ms,
               claim.state AS claim_state, claim.owner_id AS claim_owner_id,
               claim.generation AS claim_generation,
               claim.claimed_at_ms AS claim_claimed_at_ms,
               claim.expires_at_ms AS claim_expires_at_ms
        FROM logical_workflow_runs AS marker
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = marker.run_id
         AND invocation.id = marker.root_invocation_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        LEFT JOIN logical_workflow_run_result_claims AS claim
          ON claim.run_id = marker.run_id
        WHERE marker.orchestration_schema = 1
          AND marker.state IN ('pending', 'active')
          AND marker.revision < 9223372036854775807
          AND invocation.plan_schema = 1
          AND invocation.state IN ('pending', 'active')
          AND invocation.revision < 9223372036854775807
          AND run.admission_epoch = 1 AND run.plan_schema = 1
          AND run.status IN ('queued', 'in_progress', 'cancelled')
          AND (
              claim.run_id IS NULL
              OR (claim.state = 'aggregating'
                  AND claim.expires_at_ms <= $1
                  AND claim.generation < 9223372036854775807)
          )
          AND (SELECT count(*)
               FROM logical_workflow_jobs AS job
               WHERE job.run_id = marker.run_id
                 AND job.invocation_id = marker.root_invocation_id)
              BETWEEN 1 AND 1024
          AND NOT EXISTS (
              SELECT 1
              FROM logical_workflow_jobs AS job
              LEFT JOIN logical_workflow_effective_job_results AS result
                ON result.run_id = job.run_id
               AND result.invocation_id = job.invocation_id
               AND result.logical_job_id = job.id
              WHERE job.run_id = marker.run_id
                AND job.invocation_id = marker.root_invocation_id
                AND (
                    result.logical_job_id IS NULL
                    OR result.claim_state IS DISTINCT FROM 'finalized'
                    OR result.logical_key IS DISTINCT FROM job.logical_key
                    OR result.source_order IS DISTINCT FROM job.source_order
                    OR job.state IS DISTINCT FROM CASE result.effective_conclusion
                        WHEN 'success' THEN 'completed'
                        WHEN 'failure' THEN 'failed'
                        WHEN 'timed_out' THEN 'failed'
                        WHEN 'cancelled' THEN 'cancelled'
                        WHEN 'skipped' THEN 'skipped'
                    END
                    OR result.prerequisite_count IS DISTINCT FROM (
                        SELECT count(*)::INTEGER
                        FROM logical_workflow_dependencies AS dependency
                        WHERE dependency.run_id = job.run_id
                          AND dependency.invocation_id = job.invocation_id
                          AND dependency.logical_job_id = job.id
                    )
                )
          )
          AND NOT EXISTS (
              SELECT 1
              FROM (
                  SELECT job.source_order,
                         row_number() OVER (ORDER BY job.source_order) - 1 AS expected_order
                  FROM logical_workflow_jobs AS job
                  WHERE job.run_id = marker.run_id
                    AND job.invocation_id = marker.root_invocation_id
              ) AS ordered
              WHERE ordered.source_order <> ordered.expected_order
          )
          AND $1 >= greatest(
              marker.updated_at_ms,
              invocation.updated_at_ms,
              run.updated_at_ms,
              COALESCE((
                  SELECT max(result.finalized_at_ms)
                  FROM logical_workflow_effective_job_results AS result
                  WHERE result.run_id = marker.run_id
                    AND result.invocation_id = marker.root_invocation_id
              ), 0)
          )
        ORDER BY marker.admitted_at_ms, marker.run_id
        FOR UPDATE OF marker SKIP LOCKED
        LIMIT 1
        ";

const EXACT_FINALIZED_COMMIT_QUERY: &str = r"
        SELECT result.root_invocation_id, result.descriptor_digest,
               result.job_count, result.evidence_digest,
               result.effective_conclusion, result.commit_digest,
               result.claim_owner_id, result.claim_generation,
               result.claim_started_at_ms, result.claim_expires_at_ms,
               result.finalized_at_ms, marker.state AS marker_state,
               marker.revision AS marker_revision,
               marker.updated_at_ms AS marker_updated_at_ms,
               invocation.state AS invocation_state,
               invocation.revision AS invocation_revision,
               invocation.updated_at_ms AS invocation_updated_at_ms,
               run.status AS workflow_status,
               run.updated_at_ms AS workflow_updated_at_ms
        FROM logical_workflow_run_results AS result
        JOIN logical_workflow_runs AS marker ON marker.run_id = result.run_id
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = result.run_id
         AND invocation.id = result.root_invocation_id
        JOIN workflow_runs AS run ON run.id = result.run_id
        WHERE result.run_id = $1
        ";

#[async_trait]
impl LogicalRunFinalizationRepository for PostgresStore {
    async fn claim_logical_run_finalization(
        &self,
        request: ClaimLogicalRunFinalization,
    ) -> Result<Option<ClaimedLogicalRunFinalization>, LogicalRunFinalizationStoreError> {
        let mut transaction = begin_read_committed(&self.pool).await?;
        let selection_now = database_now_ms(&mut transaction).await?;
        validate_caller_clock(request.observed_at(), selection_now)?;
        // Caller wall time is admission evidence only. It cannot select a due
        // row or expire an existing fence.
        let Some(row) = lock_ready_candidate(&mut transaction, selection_now).await? else {
            if has_exhausted_ready_candidate(&mut transaction, selection_now).await? {
                return Err(LogicalRunFinalizationStoreError::GenerationExhausted);
            }
            transaction.commit().await.map_err(operation_error)?;
            return Ok(None);
        };
        let descriptor = load_descriptor(&mut transaction, &row).await?;
        let claimed_at = database_now_ms(&mut transaction).await?;
        if claimed_at < selection_now || claimed_at < descriptor.evidence_ready_at().get() {
            return Err(StoreError::corrupt_data(
                "database time regressed behind ready run-finalization evidence",
            )
            .into());
        }
        let duration = request
            .expires_at()
            .get()
            .checked_sub(request.observed_at().get())
            .ok_or_else(|| StoreError::corrupt_data("invalid run-finalization claim duration"))?;
        // Preserve only the validated requested duration; issue both absolute
        // fence timestamps from the database clock while the marker is locked.
        let expires_at = claimed_at.checked_add(duration).ok_or_else(|| {
            StoreError::corrupt_data("run-finalization database claim time overflowed")
        })?;

        let claim_row = sqlx::query(
            r"
            INSERT INTO logical_workflow_run_result_claims (
                run_id, root_invocation_id, descriptor_digest, state,
                owner_id, generation, claimed_at_ms, expires_at_ms,
                created_at_ms, updated_at_ms
            ) VALUES ($1,$2,$3,'aggregating',$4,1,$5,$6,$5,$5)
            ON CONFLICT (run_id) DO UPDATE
            SET owner_id = EXCLUDED.owner_id,
                generation = logical_workflow_run_result_claims.generation + 1,
                claimed_at_ms = EXCLUDED.claimed_at_ms,
                expires_at_ms = EXCLUDED.expires_at_ms,
                updated_at_ms = EXCLUDED.claimed_at_ms
            WHERE logical_workflow_run_result_claims.state = 'aggregating'
              AND logical_workflow_run_result_claims.expires_at_ms <= $5
              AND logical_workflow_run_result_claims.generation < 9223372036854775807
              AND logical_workflow_run_result_claims.descriptor_digest = EXCLUDED.descriptor_digest
              AND logical_workflow_run_result_claims.root_invocation_id = EXCLUDED.root_invocation_id
            RETURNING owner_id, generation, claimed_at_ms, expires_at_ms
            ",
        )
        .bind(descriptor.target().run_id().as_uuid())
        .bind(descriptor.target().root_invocation_id().as_uuid())
        .bind(descriptor.descriptor_digest().as_bytes().as_slice())
        .bind(request.owner().as_uuid())
        .bind(claimed_at)
        .bind(expires_at)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?
        .ok_or_else(|| {
            StoreError::corrupt_data(
                "locked ready run-finalization candidate rejected its exact claim",
            )
        })?;
        let fence = decode_fence(
            descriptor.target().clone(),
            &claim_row,
            descriptor.descriptor_digest(),
        )?;
        let claimed =
            ClaimedLogicalRunFinalization::new(descriptor, fence).map_err(corrupt_value)?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(Some(claimed))
    }

    async fn commit_logical_run_finalization(
        &self,
        request: CommitLogicalRunFinalization,
    ) -> Result<LogicalRunFinalizationReceipt, LogicalRunFinalizationStoreError> {
        let mut transaction = begin_read_committed(&self.pool).await?;
        let (repository_id, concurrency_key) = super::admission::lock_run_concurrency(
            &mut transaction,
            request.claim().target().run_id(),
        )
        .await?;
        let row = lock_commit_target(&mut transaction, request.claim().target())
            .await?
            .ok_or(LogicalRunFinalizationStoreError::ClaimRejected)?;
        let state: String = row.try_get("claim_state").map_err(operation_error)?;
        if state == "finalized" {
            verify_exact_finalized_commit(&mut transaction, &request).await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(LogicalRunFinalizationReceipt::new(&request, true));
        }
        if state != "aggregating" {
            return Err(StoreError::corrupt_data("unknown run-finalization claim state").into());
        }
        let descriptor = load_descriptor(&mut transaction, &row).await?;
        let database_now = database_now_ms(&mut transaction).await?;
        // The repository-issued claim start is the aggregate decision time.
        // A fresh commit may not substitute a caller-issued timestamp, while
        // the post-lock database observation alone decides fence liveness.
        if descriptor != *request.descriptor()
            || !row_matches_fence(&row, request.claim())?
            || database_now < request.claim().claimed_at().get()
            || database_now >= request.claim().expires_at().get()
            || request.finalized_at() != request.claim().claimed_at()
            || request.finalized_at() < descriptor.evidence_ready_at()
            || request.finalized_at() < request.claim().claimed_at()
            || request.finalized_at() >= request.claim().expires_at()
        {
            return Err(LogicalRunFinalizationStoreError::ClaimRejected);
        }

        insert_result(&mut transaction, &request).await?;
        insert_job_evidence(&mut transaction, request.descriptor()).await?;
        transition_invocation(&mut transaction, &request).await?;
        transition_marker(&mut transaction, &request).await?;
        transition_workflow_run(&mut transaction, &request).await?;
        transition_linked_github_check(&mut transaction, &request).await?;
        super::admission::reconcile_terminal_concurrency(
            &mut transaction,
            repository_id,
            concurrency_key.as_deref(),
            request.claim().target().run_id(),
            request.finalized_at(),
        )
        .await?;
        let finalized = sqlx::query(
            r"
            UPDATE logical_workflow_run_result_claims
            SET state = 'finalized', updated_at_ms = $8
            WHERE run_id = $1 AND root_invocation_id = $2
              AND state = 'aggregating' AND owner_id = $3
              AND generation = $4 AND descriptor_digest = $5
              AND claimed_at_ms = $6 AND expires_at_ms = $7
            ",
        )
        .bind(request.claim().target().run_id().as_uuid())
        .bind(request.claim().target().root_invocation_id().as_uuid())
        .bind(request.claim().owner().as_uuid())
        .bind(request.claim().generation().as_i64())
        .bind(request.claim().descriptor_digest().as_bytes().as_slice())
        .bind(request.claim().claimed_at().get())
        .bind(request.claim().expires_at().get())
        .bind(request.finalized_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?
        .rows_affected();
        if finalized != 1 {
            return Err(StoreError::corrupt_data(
                "run-finalization claim disappeared during exact commit",
            )
            .into());
        }
        transaction.commit().await.map_err(operation_error)?;
        Ok(LogicalRunFinalizationReceipt::new(&request, false))
    }
}

async fn begin_read_committed(
    pool: &PgPool,
) -> Result<Transaction<'_, Postgres>, LogicalRunFinalizationStoreError> {
    let mut transaction = pool.begin().await.map_err(operation_error)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
    Ok(transaction)
}

async fn database_now_ms(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<i64, LogicalRunFinalizationStoreError> {
    let value: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(&mut **transaction)
            .await
            .map_err(operation_error)?;
    if value < 0 {
        return Err(StoreError::corrupt_data("database time precedes the Unix epoch").into());
    }
    Ok(value)
}

fn validate_caller_clock(
    observed_at: UnixMillis,
    database_now: i64,
) -> Result<(), LogicalRunFinalizationStoreError> {
    if caller_clock_is_bounded(observed_at, database_now) {
        Ok(())
    } else {
        Err(LogicalRunFinalizationStoreError::ClaimRejected)
    }
}

const fn caller_clock_is_bounded(observed_at: UnixMillis, database_now: i64) -> bool {
    observed_at.get() >= database_now.saturating_sub(MAX_LOGICAL_RUN_FINALIZATION_CLOCK_SKEW_MILLIS)
        && observed_at.get()
            <= database_now.saturating_add(MAX_LOGICAL_RUN_FINALIZATION_CLOCK_SKEW_MILLIS)
}

async fn lock_ready_candidate(
    transaction: &mut Transaction<'_, Postgres>,
    database_now: i64,
) -> Result<Option<PgRow>, LogicalRunFinalizationStoreError> {
    sqlx::query(LOCK_READY_CANDIDATE_QUERY)
        .bind(database_now)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)
}

async fn has_exhausted_ready_candidate(
    transaction: &mut Transaction<'_, Postgres>,
    database_now: i64,
) -> Result<bool, LogicalRunFinalizationStoreError> {
    sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM logical_workflow_run_result_claims AS claim
            JOIN logical_workflow_runs AS marker ON marker.run_id = claim.run_id
            JOIN logical_workflow_invocations AS invocation
              ON invocation.run_id = marker.run_id
             AND invocation.id = marker.root_invocation_id
            JOIN workflow_runs AS run ON run.id = marker.run_id
            WHERE claim.state = 'aggregating'
              AND claim.generation = 9223372036854775807
              AND claim.expires_at_ms <= $1
              AND marker.state IN ('pending', 'active')
              AND invocation.state IN ('pending', 'active')
              AND run.status IN ('queued', 'in_progress', 'cancelled')
              AND NOT EXISTS (
                  SELECT 1
                  FROM logical_workflow_jobs AS job
                  LEFT JOIN logical_workflow_effective_job_results AS result
                    ON result.run_id = job.run_id
                   AND result.invocation_id = job.invocation_id
                   AND result.logical_job_id = job.id
                  WHERE job.run_id = marker.run_id
                    AND job.invocation_id = marker.root_invocation_id
                    AND (result.logical_job_id IS NULL
                         OR result.claim_state IS DISTINCT FROM 'finalized')
              )
        )
        ",
    )
    .bind(database_now)
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn lock_commit_target(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalRunFinalizationTarget,
) -> Result<Option<PgRow>, LogicalRunFinalizationStoreError> {
    sqlx::query(
        r"
        SELECT repository.tenant_id, marker.run_id, marker.root_invocation_id,
               marker.admission_digest, marker.state AS marker_state,
               marker.revision AS marker_revision,
               marker.updated_at_ms AS marker_updated_at_ms,
               invocation.state AS invocation_state,
               invocation.revision AS invocation_revision,
               invocation.updated_at_ms AS invocation_updated_at_ms,
               run.status AS workflow_status,
               run.updated_at_ms AS workflow_updated_at_ms,
               claim.state AS claim_state, claim.owner_id AS claim_owner_id,
               claim.generation AS claim_generation,
               claim.claimed_at_ms AS claim_claimed_at_ms,
               claim.expires_at_ms AS claim_expires_at_ms
        FROM logical_workflow_run_result_claims AS claim
        JOIN logical_workflow_runs AS marker ON marker.run_id = claim.run_id
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = marker.run_id
         AND invocation.id = marker.root_invocation_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        WHERE repository.tenant_id = $1
          AND marker.run_id = $2
          AND marker.root_invocation_id = $3
          AND marker.orchestration_schema = 1
          AND invocation.plan_schema = 1
          AND run.admission_epoch = 1 AND run.plan_schema = 1
        FOR UPDATE OF marker, invocation, run, claim
        ",
    )
    .bind(target.tenant().as_str())
    .bind(target.run_id().as_uuid())
    .bind(target.root_invocation_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn load_descriptor(
    transaction: &mut Transaction<'_, Postgres>,
    row: &PgRow,
) -> Result<LogicalRunFinalizationDescriptor, LogicalRunFinalizationStoreError> {
    let target = LogicalRunFinalizationTarget::new(
        TenantScope::from_authenticated_tenant_id(
            row.try_get::<String, _>("tenant_id")
                .map_err(operation_error)?,
        )
        .map_err(corrupt_value)?,
        RunId::from_uuid(row.try_get("run_id").map_err(operation_error)?),
        LogicalWorkflowInvocationId::from_uuid(
            row.try_get("root_invocation_id").map_err(operation_error)?,
        )
        .map_err(corrupt_value)?,
    )
    .map_err(corrupt_value)?;
    let jobs = load_job_evidence(transaction, &target).await?;
    LogicalRunFinalizationDescriptor::new(
        target,
        decode_digest(row, "admission_digest")?,
        parse_open_state(
            &row.try_get::<String, _>("marker_state")
                .map_err(operation_error)?,
        )?,
        decode_revision(row, "marker_revision")?,
        UnixMillis::new(
            row.try_get("marker_updated_at_ms")
                .map_err(operation_error)?,
        ),
        parse_open_state(
            &row.try_get::<String, _>("invocation_state")
                .map_err(operation_error)?,
        )?,
        decode_revision(row, "invocation_revision")?,
        UnixMillis::new(
            row.try_get("invocation_updated_at_ms")
                .map_err(operation_error)?,
        ),
        parse_workflow_status(
            &row.try_get::<String, _>("workflow_status")
                .map_err(operation_error)?,
        )?,
        UnixMillis::new(
            row.try_get("workflow_updated_at_ms")
                .map_err(operation_error)?,
        ),
        jobs,
    )
    .map_err(corrupt_value)
}

async fn load_job_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalRunFinalizationTarget,
) -> Result<Vec<LogicalRunJobResultEvidence>, LogicalRunFinalizationStoreError> {
    let rows = sqlx::query(
        r#"
        SELECT job.id AS logical_job_id, job.logical_key, job.source_order,
               result.descriptor_digest, result.effective_conclusion,
               result.closure_has_failure, result.closure_has_cancelled,
               result.closure_has_skipped, result.instance_count,
               result.instances_digest, result.prerequisite_count,
               result.prerequisites_digest, result.output_count,
               result.outputs_digest, result.commit_digest,
               result.finalized_at_ms, result.claim_state AS result_claim_state
        FROM logical_workflow_jobs AS job
        LEFT JOIN logical_workflow_effective_job_results AS result
          ON result.run_id = job.run_id
         AND result.invocation_id = job.invocation_id
         AND result.logical_job_id = job.id
        WHERE job.run_id = $1 AND job.invocation_id = $2
        ORDER BY job.source_order, job.logical_key COLLATE "C", job.id
        "#,
    )
    .bind(target.run_id().as_uuid())
    .bind(target.root_invocation_id().as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if rows.is_empty() || rows.len() > MAX_LOGICAL_JOBS {
        return Err(StoreError::corrupt_data("invalid logical run-finalization job count").into());
    }
    let mut jobs = Vec::with_capacity(rows.len());
    for row in rows {
        if row
            .try_get::<Option<String>, _>("result_claim_state")
            .map_err(operation_error)?
            .as_deref()
            != Some("finalized")
        {
            return Err(StoreError::corrupt_data(
                "ready run-finalization descriptor has an unfinished logical job",
            )
            .into());
        }
        jobs.push(
            LogicalRunJobResultEvidence::new(
                LogicalWorkflowJobId::from_uuid(
                    row.try_get("logical_job_id").map_err(operation_error)?,
                )
                .map_err(corrupt_value)?,
                WorkflowJobKey::new(
                    row.try_get::<String, _>("logical_key")
                        .map_err(operation_error)?,
                )
                .map_err(corrupt_value)?,
                u16::try_from(
                    row.try_get::<i32, _>("source_order")
                        .map_err(operation_error)?,
                )
                .map_err(|_| StoreError::corrupt_data("invalid logical-job source order"))?,
                decode_digest(&row, "descriptor_digest")?,
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
                decode_count(&row, "instance_count", 256)?,
                decode_digest(&row, "instances_digest")?,
                decode_count(
                    &row,
                    "prerequisite_count",
                    u32::try_from(MAX_LOGICAL_JOB_NEEDS).unwrap_or(u32::MAX),
                )?,
                decode_digest(&row, "prerequisites_digest")?,
                decode_count(
                    &row,
                    "output_count",
                    u32::try_from(MAX_LOGICAL_JOB_OUTPUTS).unwrap_or(u32::MAX),
                )?,
                decode_digest(&row, "outputs_digest")?,
                decode_digest(&row, "commit_digest")?,
                UnixMillis::new(row.try_get("finalized_at_ms").map_err(operation_error)?),
            )
            .map_err(corrupt_value)?,
        );
    }
    Ok(jobs)
}

fn decode_fence(
    target: LogicalRunFinalizationTarget,
    row: &PgRow,
    descriptor_digest: Sha256Digest,
) -> Result<LogicalRunFinalizationClaimFence, LogicalRunFinalizationStoreError> {
    LogicalRunFinalizationClaimFence::new(
        target,
        LogicalRunFinalizationWorkerId::from_uuid(
            row.try_get("owner_id").map_err(operation_error)?,
        )
        .map_err(corrupt_value)?,
        LogicalRunFinalizationGeneration::new(
            u64::try_from(
                row.try_get::<i64, _>("generation")
                    .map_err(operation_error)?,
            )
            .map_err(|_| StoreError::corrupt_data("negative run-finalization generation"))?,
        )
        .map_err(corrupt_value)?,
        descriptor_digest,
        UnixMillis::new(row.try_get("claimed_at_ms").map_err(operation_error)?),
        UnixMillis::new(row.try_get("expires_at_ms").map_err(operation_error)?),
    )
    .map_err(corrupt_value)
}

fn row_matches_fence(
    row: &PgRow,
    fence: &LogicalRunFinalizationClaimFence,
) -> Result<bool, LogicalRunFinalizationStoreError> {
    Ok(row
        .try_get::<uuid::Uuid, _>("claim_owner_id")
        .map_err(operation_error)?
        == fence.owner().as_uuid()
        && row
            .try_get::<i64, _>("claim_generation")
            .map_err(operation_error)?
            == fence.generation().as_i64()
        && row
            .try_get::<i64, _>("claim_claimed_at_ms")
            .map_err(operation_error)?
            == fence.claimed_at().get()
        && row
            .try_get::<i64, _>("claim_expires_at_ms")
            .map_err(operation_error)?
            == fence.expires_at().get())
}

async fn insert_result(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitLogicalRunFinalization,
) -> Result<(), LogicalRunFinalizationStoreError> {
    let descriptor = request.descriptor();
    sqlx::query(
        r"
        INSERT INTO logical_workflow_run_results (
            run_id, root_invocation_id, descriptor_digest, admission_digest,
            marker_state, marker_revision, marker_updated_at_ms,
            invocation_state, invocation_revision, invocation_updated_at_ms,
            workflow_status, workflow_updated_at_ms, job_count,
            evidence_digest, effective_conclusion, commit_digest,
            claim_owner_id, claim_generation, claim_started_at_ms,
            claim_expires_at_ms, finalized_at_ms
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
            $17,$18,$19,$20,$21
        )
        ",
    )
    .bind(descriptor.target().run_id().as_uuid())
    .bind(descriptor.target().root_invocation_id().as_uuid())
    .bind(descriptor.descriptor_digest().as_bytes().as_slice())
    .bind(descriptor.admission_digest().as_bytes().as_slice())
    .bind(descriptor.marker_state().as_str())
    .bind(revision_i64(descriptor.marker_revision())?)
    .bind(descriptor.marker_updated_at().get())
    .bind(descriptor.invocation_state().as_str())
    .bind(revision_i64(descriptor.invocation_revision())?)
    .bind(descriptor.invocation_updated_at().get())
    .bind(descriptor.workflow_status().as_str())
    .bind(descriptor.workflow_updated_at().get())
    .bind(
        i32::try_from(descriptor.job_count())
            .map_err(|_| StoreError::corrupt_data("run job count exceeds INTEGER"))?,
    )
    .bind(descriptor.evidence_digest().as_bytes().as_slice())
    .bind(conclusion_name(request.conclusion()))
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

async fn insert_job_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    descriptor: &LogicalRunFinalizationDescriptor,
) -> Result<(), LogicalRunFinalizationStoreError> {
    for job in descriptor.jobs() {
        sqlx::query(
            r"
            INSERT INTO logical_workflow_run_result_jobs (
                run_id, root_invocation_id, logical_job_id, logical_key,
                source_order, descriptor_digest, effective_conclusion,
                closure_has_failure, closure_has_cancelled, closure_has_skipped,
                instance_count, instances_digest, prerequisite_count,
                prerequisites_digest, output_count, outputs_digest,
                job_commit_digest, job_finalized_at_ms
            ) VALUES (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18
            )
            ",
        )
        .bind(descriptor.target().run_id().as_uuid())
        .bind(descriptor.target().root_invocation_id().as_uuid())
        .bind(job.logical_job_id().as_uuid())
        .bind(job.logical_key().as_str())
        .bind(i32::from(job.source_order()))
        .bind(job.descriptor_digest().as_bytes().as_slice())
        .bind(conclusion_name(job.effective_conclusion()))
        .bind(job.closure_has_failure())
        .bind(job.closure_has_cancelled())
        .bind(job.closure_has_skipped())
        .bind(
            i32::try_from(job.instance_count())
                .map_err(|_| StoreError::corrupt_data("instance count exceeds INTEGER"))?,
        )
        .bind(job.instances_digest().as_bytes().as_slice())
        .bind(
            i32::try_from(job.prerequisite_count())
                .map_err(|_| StoreError::corrupt_data("prerequisite count exceeds INTEGER"))?,
        )
        .bind(job.prerequisites_digest().as_bytes().as_slice())
        .bind(
            i32::try_from(job.output_count())
                .map_err(|_| StoreError::corrupt_data("output count exceeds INTEGER"))?,
        )
        .bind(job.outputs_digest().as_bytes().as_slice())
        .bind(job.commit_digest().as_bytes().as_slice())
        .bind(job.finalized_at().get())
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    }
    Ok(())
}

async fn transition_invocation(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitLogicalRunFinalization,
) -> Result<(), LogicalRunFinalizationStoreError> {
    let descriptor = request.descriptor();
    let rows = sqlx::query(
        r"
        UPDATE logical_workflow_invocations
        SET state = $6, revision = revision + 1, updated_at_ms = $7
        WHERE run_id = $1 AND id = $2
          AND state = $3 AND revision = $4 AND updated_at_ms = $5
        ",
    )
    .bind(descriptor.target().run_id().as_uuid())
    .bind(descriptor.target().root_invocation_id().as_uuid())
    .bind(descriptor.invocation_state().as_str())
    .bind(revision_i64(descriptor.invocation_revision())?)
    .bind(descriptor.invocation_updated_at().get())
    .bind(orchestration_terminal_state(request.conclusion()))
    .bind(request.finalized_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    require_one_transition(rows, "root invocation")
}

async fn transition_marker(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitLogicalRunFinalization,
) -> Result<(), LogicalRunFinalizationStoreError> {
    let descriptor = request.descriptor();
    let rows = sqlx::query(
        r"
        UPDATE logical_workflow_runs
        SET state = $5, revision = revision + 1, updated_at_ms = $6
        WHERE run_id = $1 AND state = $2 AND revision = $3 AND updated_at_ms = $4
        ",
    )
    .bind(descriptor.target().run_id().as_uuid())
    .bind(descriptor.marker_state().as_str())
    .bind(revision_i64(descriptor.marker_revision())?)
    .bind(descriptor.marker_updated_at().get())
    .bind(orchestration_terminal_state(request.conclusion()))
    .bind(request.finalized_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    require_one_transition(rows, "orchestration marker")
}

async fn transition_workflow_run(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitLogicalRunFinalization,
) -> Result<(), LogicalRunFinalizationStoreError> {
    let descriptor = request.descriptor();
    let rows = sqlx::query(
        r"
        UPDATE workflow_runs
        SET status = $4, updated_at_ms = $5
        WHERE id = $1 AND status = $2 AND updated_at_ms = $3
        ",
    )
    .bind(descriptor.target().run_id().as_uuid())
    .bind(descriptor.workflow_status().as_str())
    .bind(descriptor.workflow_updated_at().get())
    .bind(workflow_terminal_status(request.conclusion()))
    .bind(request.finalized_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    require_one_transition(rows, "workflow run")
}

async fn transition_linked_github_check(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitLogicalRunFinalization,
) -> Result<(), LogicalRunFinalizationStoreError> {
    let (linked, updated): (i64, i64) = sqlx::query_as(
        r"
        WITH linked AS MATERIALIZED (
            SELECT id
            FROM github_check_subjects
            WHERE workflow_run_id = $1
            FOR UPDATE
        ), updated AS (
            UPDATE github_check_subjects AS subject
            SET desired_state = 'completed',
                desired_conclusion = $2,
                terminal_cause = $3,
                desired_revision = desired_revision + 1,
                desired_updated_at_ms = $4
            FROM linked
            WHERE subject.id = linked.id
              AND subject.desired_state = 'in_progress'
              AND subject.desired_conclusion IS NULL
              AND subject.terminal_cause IS NULL
              AND subject.desired_revision = 2
              AND subject.desired_updated_at_ms <= $4
            RETURNING subject.id
        )
        SELECT (SELECT count(*) FROM linked),
               (SELECT count(*) FROM updated)
        ",
    )
    .bind(request.claim().target().run_id().as_uuid())
    .bind(conclusion_name(request.conclusion()))
    .bind(check_terminal_cause(request.conclusion()))
    .bind(request.finalized_at().get())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if (linked, updated) == (0, 0) || (linked, updated) == (1, 1) {
        Ok(())
    } else {
        Err(StoreError::corrupt_data(
            "linked GitHub Check did not match the exact run-finalization transition",
        )
        .into())
    }
}

fn require_one_transition(
    rows: u64,
    target: &'static str,
) -> Result<(), LogicalRunFinalizationStoreError> {
    if rows == 1 {
        Ok(())
    } else {
        Err(StoreError::corrupt_data(format!(
            "run-finalization {target} transition lost its locked target"
        ))
        .into())
    }
}

async fn verify_exact_finalized_commit(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitLogicalRunFinalization,
) -> Result<(), LogicalRunFinalizationStoreError> {
    let row = sqlx::query(EXACT_FINALIZED_COMMIT_QUERY)
        .bind(request.claim().target().run_id().as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?
        .ok_or(LogicalRunFinalizationStoreError::CommitConflict)?;
    let descriptor = request.descriptor();
    let exact = row
        .try_get::<uuid::Uuid, _>("root_invocation_id")
        .map_err(operation_error)?
        == descriptor.target().root_invocation_id().as_uuid()
        && decode_digest(&row, "descriptor_digest")? == descriptor.descriptor_digest()
        && decode_count(
            &row,
            "job_count",
            u32::try_from(MAX_LOGICAL_JOBS).unwrap_or(u32::MAX),
        )? == descriptor.job_count()
        && decode_digest(&row, "evidence_digest")? == descriptor.evidence_digest()
        && parse_conclusion(
            &row.try_get::<String, _>("effective_conclusion")
                .map_err(operation_error)?,
        )? == request.conclusion()
        && decode_digest(&row, "commit_digest")? == request.commit_digest()
        && row
            .try_get::<uuid::Uuid, _>("claim_owner_id")
            .map_err(operation_error)?
            == request.claim().owner().as_uuid()
        && row
            .try_get::<i64, _>("claim_generation")
            .map_err(operation_error)?
            == request.claim().generation().as_i64()
        && row
            .try_get::<i64, _>("claim_started_at_ms")
            .map_err(operation_error)?
            == request.claim().claimed_at().get()
        && row
            .try_get::<i64, _>("claim_expires_at_ms")
            .map_err(operation_error)?
            == request.claim().expires_at().get()
        && row
            .try_get::<i64, _>("finalized_at_ms")
            .map_err(operation_error)?
            == request.finalized_at().get()
        && row
            .try_get::<String, _>("marker_state")
            .map_err(operation_error)?
            == orchestration_terminal_state(request.conclusion())
        && row
            .try_get::<i64, _>("marker_revision")
            .map_err(operation_error)?
            == revision_i64(descriptor.marker_revision())? + 1
        && row
            .try_get::<i64, _>("marker_updated_at_ms")
            .map_err(operation_error)?
            == request.finalized_at().get()
        && row
            .try_get::<String, _>("invocation_state")
            .map_err(operation_error)?
            == orchestration_terminal_state(request.conclusion())
        && row
            .try_get::<i64, _>("invocation_revision")
            .map_err(operation_error)?
            == revision_i64(descriptor.invocation_revision())? + 1
        && row
            .try_get::<i64, _>("invocation_updated_at_ms")
            .map_err(operation_error)?
            == request.finalized_at().get()
        && row
            .try_get::<String, _>("workflow_status")
            .map_err(operation_error)?
            == workflow_terminal_status(request.conclusion())
        && row
            .try_get::<i64, _>("workflow_updated_at_ms")
            .map_err(operation_error)?
            == request.finalized_at().get();
    if !exact
        || !stored_job_evidence_matches(transaction, descriptor).await?
        || !linked_github_check_matches(transaction, request).await?
    {
        return Err(LogicalRunFinalizationStoreError::CommitConflict);
    }
    Ok(())
}

async fn linked_github_check_matches(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitLogicalRunFinalization,
) -> Result<bool, LogicalRunFinalizationStoreError> {
    let (linked, exact): (i64, i64) = sqlx::query_as(
        r"
        WITH linked AS MATERIALIZED (
            SELECT desired_state, desired_conclusion, terminal_cause,
                   desired_revision, desired_updated_at_ms
            FROM github_check_subjects
            WHERE workflow_run_id = $1
            FOR SHARE
        )
        SELECT count(*), count(*) FILTER (
            WHERE desired_state = 'completed'
              AND desired_conclusion = $2
              AND terminal_cause = $3
              AND desired_revision = 3
              AND desired_updated_at_ms = $4
        )
        FROM linked
        ",
    )
    .bind(request.claim().target().run_id().as_uuid())
    .bind(conclusion_name(request.conclusion()))
    .bind(check_terminal_cause(request.conclusion()))
    .bind(request.finalized_at().get())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok((linked, exact) == (0, 0) || (linked, exact) == (1, 1))
}

async fn stored_job_evidence_matches(
    transaction: &mut Transaction<'_, Postgres>,
    descriptor: &LogicalRunFinalizationDescriptor,
) -> Result<bool, LogicalRunFinalizationStoreError> {
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
            .try_get::<uuid::Uuid, _>("logical_job_id")
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
            || parse_conclusion(
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
            || decode_count(row, "instance_count", 256)? != expected.instance_count()
            || decode_digest(row, "instances_digest")? != expected.instances_digest()
            || decode_count(
                row,
                "prerequisite_count",
                u32::try_from(MAX_LOGICAL_JOB_NEEDS).unwrap_or(u32::MAX),
            )? != expected.prerequisite_count()
            || decode_digest(row, "prerequisites_digest")? != expected.prerequisites_digest()
            || decode_count(
                row,
                "output_count",
                u32::try_from(MAX_LOGICAL_JOB_OUTPUTS).unwrap_or(u32::MAX),
            )? != expected.output_count()
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

fn decode_revision(row: &PgRow, column: &str) -> Result<u64, LogicalRunFinalizationStoreError> {
    let value = row.try_get::<i64, _>(column).map_err(operation_error)?;
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| StoreError::corrupt_data(format!("invalid {column}")).into())
}

fn revision_i64(value: u64) -> Result<i64, LogicalRunFinalizationStoreError> {
    i64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| StoreError::corrupt_data("invalid run-finalization revision").into())
}

fn decode_count(
    row: &PgRow,
    column: &str,
    maximum: u32,
) -> Result<u32, LogicalRunFinalizationStoreError> {
    let value = u32::try_from(row.try_get::<i32, _>(column).map_err(operation_error)?)
        .map_err(|_| StoreError::corrupt_data(format!("negative {column}")))?;
    if value > maximum {
        return Err(StoreError::corrupt_data(format!("oversized {column}")).into());
    }
    Ok(value)
}

fn decode_digest(
    row: &PgRow,
    column: &str,
) -> Result<Sha256Digest, LogicalRunFinalizationStoreError> {
    let value: Vec<u8> = row.try_get(column).map_err(operation_error)?;
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| StoreError::corrupt_data(format!("{column} is not SHA-256")))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn parse_open_state(
    value: &str,
) -> Result<LogicalRunFinalizationOpenState, LogicalRunFinalizationStoreError> {
    match value {
        "pending" => Ok(LogicalRunFinalizationOpenState::Pending),
        "active" => Ok(LogicalRunFinalizationOpenState::Active),
        _ => Err(StoreError::corrupt_data("run-finalization state is not open").into()),
    }
}

fn parse_workflow_status(
    value: &str,
) -> Result<LogicalRunFinalizationWorkflowStatus, LogicalRunFinalizationStoreError> {
    match value {
        "queued" => Ok(LogicalRunFinalizationWorkflowStatus::Queued),
        "in_progress" => Ok(LogicalRunFinalizationWorkflowStatus::InProgress),
        "cancelled" => Ok(LogicalRunFinalizationWorkflowStatus::Cancelled),
        _ => Err(
            StoreError::corrupt_data("run-finalization workflow status cannot be finalized").into(),
        ),
    }
}

fn parse_conclusion(value: &str) -> Result<JobConclusion, LogicalRunFinalizationStoreError> {
    match value {
        "success" => Ok(JobConclusion::Success),
        "failure" => Ok(JobConclusion::Failure),
        "cancelled" => Ok(JobConclusion::Cancelled),
        "timed_out" => Ok(JobConclusion::TimedOut),
        "skipped" => Ok(JobConclusion::Skipped),
        _ => Err(StoreError::corrupt_data("unknown logical run conclusion").into()),
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

const fn check_terminal_cause(value: JobConclusion) -> &'static str {
    match value {
        JobConclusion::Success => "workflow_success",
        JobConclusion::Failure => "workflow_failure",
        JobConclusion::Cancelled => "workflow_cancelled",
        JobConclusion::TimedOut => "workflow_timed_out",
        JobConclusion::Skipped => "workflow_skipped",
    }
}

const fn orchestration_terminal_state(value: JobConclusion) -> &'static str {
    match value {
        JobConclusion::Success | JobConclusion::Skipped => "completed",
        JobConclusion::Failure | JobConclusion::TimedOut => "failed",
        JobConclusion::Cancelled => "cancelled",
    }
}

const fn workflow_terminal_status(value: JobConclusion) -> &'static str {
    match value {
        JobConclusion::Cancelled => "cancelled",
        JobConclusion::Success
        | JobConclusion::Failure
        | JobConclusion::TimedOut
        | JobConclusion::Skipped => "completed",
    }
}

fn corrupt_value(error: impl std::fmt::Display) -> LogicalRunFinalizationStoreError {
    StoreError::corrupt_data(format!("invalid logical run-finalization value: {error}")).into()
}

fn operation_error(error: sqlx::Error) -> LogicalRunFinalizationStoreError {
    StoreError::operation(error).into()
}
