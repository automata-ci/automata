//! `PostgreSQL` adapter for durable workflow reruns.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use async_trait::async_trait;
use automata_ci_core::{QueuePolicy, RunId, UnixMillis};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row as _, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::{
    PostgresStore,
    secret_management::{AuthorizedHumanRepositoryAction, authorize_human_repository_action},
};
use crate::{
    MAX_WORKFLOW_RERUN_AGE_MILLIS, MAX_WORKFLOW_RERUN_ATTEMPTS, RerunWorkflow, StoreError,
    WorkflowConcurrency, WorkflowRerunReceipt, WorkflowRerunRepository, WorkflowRerunSelection,
    WorkflowRerunStoreError,
};

const RERUN_PERMISSION: &str = "runs:rerun";
const RERUN_IDEMPOTENCY_PREFIX: &str = "workflow-rerun:";
const RERUN_REQUEST_DIGEST_DOMAIN: &[u8] = b"automata.workflow-rerun.request.v1\0";
const RERUN_RUN_ID_DOMAIN: &[u8] = b"automata.workflow-rerun.run-id.v1\0";
const RERUN_INVOCATION_ID_DOMAIN: &[u8] = b"automata.workflow-rerun.invocation-id.v1\0";
const RERUN_JOB_ID_DOMAIN: &[u8] = b"automata.workflow-rerun.job-id.v1\0";
const RERUN_AUDIT_ID_DOMAIN: &[u8] = b"automata.workflow-rerun.audit.v1\0";

#[derive(Debug)]
struct SourceRun {
    source_run_id: Uuid,
    root_run_id: Uuid,
    root_invocation_id: Uuid,
    run_number: u64,
    public_run_id: u64,
    source_admission_digest: Vec<u8>,
    source_plan_digest: Vec<u8>,
    source_event_digest: Vec<u8>,
    source_created_at_ms: i64,
    concurrency: Option<WorkflowConcurrency>,
}

#[derive(Debug)]
struct SourceJob {
    id: Uuid,
    logical_key: String,
    source_order: i32,
    state: String,
    activation_fence: i64,
    activation_input_digest: Option<Vec<u8>>,
    authority_profile: Option<String>,
    runtime_policy_revision: i64,
    runtime_policy_digest: Vec<u8>,
    activation_origin_selection_id: Option<Uuid>,
    environment_requirement_kind: String,
    environment_template_digest: Option<Vec<u8>>,
    secret_reference_names: Vec<String>,
    variable_reference_names: Vec<String>,
    credential_requirements_schema: i16,
    conclusion: String,
    instance_count: i32,
}

#[async_trait]
impl WorkflowRerunRepository for PostgresStore {
    async fn rerun_workflow(
        &self,
        request: RerunWorkflow,
    ) -> Result<WorkflowRerunReceipt, WorkflowRerunStoreError> {
        rerun_workflow_transaction(self, request).await
    }
}

async fn rerun_workflow_transaction(
    store: &PostgresStore,
    request: RerunWorkflow,
) -> Result<WorkflowRerunReceipt, WorkflowRerunStoreError> {
    let mut transaction = store.pool.begin().await.map_err(operation_error)?;
    let actor = authorize_human_repository_action(
        &mut transaction,
        request.actor(),
        RERUN_PERMISSION,
        request.repository_id().as_uuid(),
    )
    .await
    .map_err(WorkflowRerunStoreError::Store)?
    .ok_or(WorkflowRerunStoreError::AuthorityRejected)?;
    require_exact_actor(&request, &actor)?;

    let request_digest = rerun_request_digest(&request, &actor);
    let idempotency_key = format!("{RERUN_IDEMPOTENCY_PREFIX}{}", request.operation_id());
    if !claim_idempotency_receipt(&mut transaction, &request, request_digest, &idempotency_key)
        .await?
    {
        let receipt =
            replay_receipt(&mut transaction, &request, request_digest, &idempotency_key).await?;
        transaction.commit().await.map_err(operation_error)?;
        return Ok(receipt);
    }

    let database_now = database_now_ms(&mut transaction).await?;
    let source = lock_source_run(&mut transaction, &request, database_now).await?;
    lock_rerun_group(&mut transaction, source.root_run_id).await?;
    ensure_root_attempt(&mut transaction, &source).await?;
    let next_attempt = next_attempt(&mut transaction, &source).await?;
    let triggering_actor = load_triggering_actor(&mut transaction, &actor).await?;
    let jobs = load_source_jobs(&mut transaction, &source).await?;
    let dependencies = load_source_dependencies(&mut transaction, &source).await?;
    let selected = select_jobs(&request, &jobs, &dependencies)?;

    if let Some(concurrency) = source.concurrency.as_ref() {
        super::admission::lock_concurrency_group(
            &mut transaction,
            request.repository_id(),
            UnixMillis::new(database_now),
            concurrency,
        )
        .await
        .map_err(map_concurrency_error)?;
    }

    let run_id = derived_uuid(RERUN_RUN_ID_DOMAIN, &request_digest, &[]);
    let invocation_id = derived_uuid(RERUN_INVOCATION_ID_DOMAIN, &request_digest, &[]);
    let job_ids = jobs
        .iter()
        .map(|job| {
            (
                job.id,
                derived_uuid(RERUN_JOB_ID_DOMAIN, &request_digest, job.id.as_bytes()),
            )
        })
        .collect::<BTreeMap<_, _>>();

    insert_run(
        &mut transaction,
        &source,
        run_id,
        next_attempt,
        database_now,
        &triggering_actor,
    )
    .await?;
    insert_marker_and_invocation(
        &mut transaction,
        &source,
        run_id,
        invocation_id,
        request_digest,
        database_now,
    )
    .await?;
    insert_attempt_and_request(
        &mut transaction,
        &request,
        &actor,
        &source,
        run_id,
        next_attempt,
        request_digest,
        database_now,
    )
    .await?;
    finalize_admission_receipt(
        &mut transaction,
        &request,
        run_id,
        request_digest,
        &idempotency_key,
        database_now,
    )
    .await?;
    copy_runtime_policy_pin(&mut transaction, &source, run_id, database_now).await?;
    insert_jobs_and_dependencies(
        &mut transaction,
        &source,
        run_id,
        invocation_id,
        &jobs,
        &dependencies,
        &selected,
        &job_ids,
    )
    .await?;
    seal_graph(&mut transaction, run_id).await?;
    record_audit_event(
        &mut transaction,
        &request,
        &actor,
        run_id,
        request_digest,
        database_now,
    )
    .await?;

    if let Some(concurrency) = source.concurrency.as_ref() {
        super::admission::assign_concurrency_slot(
            &mut transaction,
            store.runner_payload_encryption.as_ref(),
            request.repository_id(),
            RunId::from_uuid(run_id),
            UnixMillis::new(database_now),
            concurrency,
        )
        .await
        .map_err(map_concurrency_error)?;
    }
    transaction.commit().await.map_err(operation_error)?;

    WorkflowRerunReceipt::new(
        request.source_run_id(),
        RunId::from_uuid(run_id),
        source.public_run_id,
        source.run_number,
        next_attempt,
        false,
    )
    .map_err(corrupt_value)
}

fn require_exact_actor(
    request: &RerunWorkflow,
    actor: &AuthorizedHumanRepositoryAction,
) -> Result<(), WorkflowRerunStoreError> {
    let expected_revision =
        i64::try_from(request.actor().authorization_revision().value()).unwrap_or(i64::MAX);
    if actor.tenant_id != request.actor().tenant_id().as_str()
        || actor.principal_id.hyphenated().to_string() != request.actor().principal_id().as_str()
        || actor.session_id.hyphenated().to_string() != request.actor().session_id().as_str()
        || actor.authorization_revision != expected_revision
    {
        return Err(StoreError::corrupt_data(
            "reauthorized workflow rerun actor disagrees with its request",
        )
        .into());
    }
    Ok(())
}

async fn claim_idempotency_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RerunWorkflow,
    request_digest: [u8; 32],
    idempotency_key: &str,
) -> Result<bool, WorkflowRerunStoreError> {
    let rows = sqlx::query(
        r"
        INSERT INTO workflow_admission_receipts (
            tenant_id, idempotency_kind, idempotency_key, request_digest,
            github_subject_evidence_required
        ) VALUES ($1, 'operation', $2, $3, TRUE)
        ON CONFLICT DO NOTHING
        ",
    )
    .bind(request.actor().tenant_id().as_str())
    .bind(idempotency_key)
    .bind(request_digest.as_slice())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    Ok(rows == 1)
}

async fn replay_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RerunWorkflow,
    request_digest: [u8; 32],
    idempotency_key: &str,
) -> Result<WorkflowRerunReceipt, WorkflowRerunStoreError> {
    let row = sqlx::query(
        r"
        SELECT receipt.request_digest, receipt.repository_id, receipt.run_id,
               receipt.committed_at_ms, receipt.github_subject_evidence_required,
               rerun.source_run_id, rerun.rerun_run_id,
               run.public_run_id_alias, run.run_number, run.run_attempt
        FROM workflow_admission_receipts AS receipt
        LEFT JOIN workflow_rerun_requests AS rerun
          ON rerun.tenant_id = receipt.tenant_id
         AND ('workflow-rerun:' || rerun.operation_id::TEXT) = receipt.idempotency_key
        LEFT JOIN workflow_runs AS run ON run.id = receipt.run_id
        WHERE receipt.tenant_id = $1
          AND receipt.idempotency_kind = 'operation'
          AND receipt.idempotency_key = $2
        FOR UPDATE OF receipt
        ",
    )
    .bind(request.actor().tenant_id().as_str())
    .bind(idempotency_key)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or_else(|| StoreError::corrupt_data("workflow rerun receipt disappeared"))?;
    let durable_digest: Vec<u8> = row.try_get("request_digest").map_err(operation_error)?;
    if durable_digest.as_slice() != request_digest
        || row
            .try_get::<Option<Uuid>, _>("repository_id")
            .map_err(operation_error)?
            != Some(request.repository_id().as_uuid())
        || row
            .try_get::<Option<Uuid>, _>("source_run_id")
            .map_err(operation_error)?
            != Some(request.source_run_id().as_uuid())
        || row
            .try_get::<bool, _>("github_subject_evidence_required")
            .map_err(operation_error)?
            != true
    {
        return Err(WorkflowRerunStoreError::IdempotencyConflict);
    }
    let run_id = row
        .try_get::<Option<Uuid>, _>("run_id")
        .map_err(operation_error)?
        .ok_or_else(|| StoreError::corrupt_data("workflow rerun receipt is incomplete"))?;
    if row
        .try_get::<Option<Uuid>, _>("rerun_run_id")
        .map_err(operation_error)?
        != Some(run_id)
        || row
            .try_get::<Option<i64>, _>("committed_at_ms")
            .map_err(operation_error)?
            .is_none()
    {
        return Err(
            StoreError::corrupt_data("workflow rerun replay lacks committed evidence").into(),
        );
    }
    WorkflowRerunReceipt::new(
        request.source_run_id(),
        RunId::from_uuid(run_id),
        positive_u64(&row, "public_run_id_alias")?,
        positive_u64(&row, "run_number")?,
        positive_u32(&row, "run_attempt")?,
        true,
    )
    .map_err(corrupt_value)
}

async fn lock_source_run(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RerunWorkflow,
    database_now: i64,
) -> Result<SourceRun, WorkflowRerunStoreError> {
    let row = sqlx::query(
        r"
        SELECT run.run_attempt, run.run_number, run.public_run_id_alias,
               run.created_at_ms, run.status, run.admission_epoch, run.plan_schema,
               run.plan_digest, run.event_digest, run.concurrency_group_key,
               run.concurrency_queue_policy, run.concurrency_cancel_in_progress,
               concurrency.display_key AS concurrency_display_key,
               marker.root_invocation_id, marker.admission_digest,
               marker.state AS marker_state, invocation.state AS invocation_state,
               claim.state AS result_claim_state, result.finalized_at_ms,
               attempt.root_run_id, attempt.attempt AS durable_attempt
        FROM workflow_runs AS run
        JOIN repositories AS repository ON repository.id = run.repository_id
        LEFT JOIN workflow_plan_v2_runs AS marker ON marker.run_id = run.id
        LEFT JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = marker.run_id
         AND invocation.id = marker.root_invocation_id
        LEFT JOIN workflow_plan_v2_run_result_claims AS claim ON claim.run_id = run.id
        LEFT JOIN workflow_plan_v2_run_results AS result ON result.run_id = run.id
        LEFT JOIN workflow_rerun_attempts AS attempt ON attempt.run_id = run.id
        LEFT JOIN concurrency_groups AS concurrency
          ON concurrency.repository_id = run.repository_id
         AND concurrency.normalized_key = run.concurrency_group_key
        WHERE repository.tenant_id = $1
          AND run.repository_id = $2
          AND run.id = $3
        FOR UPDATE OF run
        ",
    )
    .bind(request.actor().tenant_id().as_str())
    .bind(request.repository_id().as_uuid())
    .bind(request.source_run_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(WorkflowRerunStoreError::NotFound)?;

    let source_attempt = positive_u32(&row, "run_attempt")?;
    let root_run_id = row
        .try_get::<Option<Uuid>, _>("root_run_id")
        .map_err(operation_error)?
        .unwrap_or(request.source_run_id().as_uuid());
    let durable_attempt: Option<i32> = row.try_get("durable_attempt").map_err(operation_error)?;
    if durable_attempt.is_none() && source_attempt != 1
        || durable_attempt.and_then(|value| u32::try_from(value).ok())
            != durable_attempt.map(|_| source_attempt)
    {
        return Err(
            StoreError::corrupt_data("workflow rerun attempt lineage is inconsistent").into(),
        );
    }
    let terminal = matches!(
        row.try_get::<String, _>("status")
            .map_err(operation_error)?
            .as_str(),
        "completed" | "cancelled"
    ) && matches!(
        row.try_get::<Option<String>, _>("marker_state")
            .map_err(operation_error)?
            .as_deref(),
        Some("completed" | "cancelled" | "failed")
    ) && matches!(
        row.try_get::<Option<String>, _>("invocation_state")
            .map_err(operation_error)?
            .as_deref(),
        Some("completed" | "cancelled" | "failed")
    ) && row
        .try_get::<Option<String>, _>("result_claim_state")
        .map_err(operation_error)?
        .as_deref()
        == Some("finalized");
    let finalized_at_ms = row
        .try_get::<Option<i64>, _>("finalized_at_ms")
        .map_err(operation_error)?
        .ok_or(WorkflowRerunStoreError::SourceNotTerminal)?;
    if !terminal {
        return Err(WorkflowRerunStoreError::SourceNotTerminal);
    }
    if finalized_at_ms > database_now
        || database_now.saturating_sub(finalized_at_ms) > MAX_WORKFLOW_RERUN_AGE_MILLIS
    {
        return Err(WorkflowRerunStoreError::SourceExpired);
    }
    if row
        .try_get::<i32, _>("admission_epoch")
        .map_err(operation_error)?
        != 4
        || row
            .try_get::<Option<i32>, _>("plan_schema")
            .map_err(operation_error)?
            != Some(2)
    {
        return Err(WorkflowRerunStoreError::UnsupportedSelection);
    }

    let concurrency = decode_concurrency(&row)?;
    Ok(SourceRun {
        source_run_id: request.source_run_id().as_uuid(),
        root_run_id,
        root_invocation_id: row
            .try_get::<Option<Uuid>, _>("root_invocation_id")
            .map_err(operation_error)?
            .ok_or(WorkflowRerunStoreError::SourceNotTerminal)?,
        run_number: positive_u64(&row, "run_number")?,
        public_run_id: positive_u64(&row, "public_run_id_alias")?,
        source_admission_digest: required_digest(&row, "admission_digest")?,
        source_plan_digest: required_digest(&row, "plan_digest")?,
        source_event_digest: required_digest(&row, "event_digest")?,
        source_created_at_ms: row.try_get("created_at_ms").map_err(operation_error)?,
        concurrency,
    })
}

fn decode_concurrency(row: &PgRow) -> Result<Option<WorkflowConcurrency>, WorkflowRerunStoreError> {
    let normalized: Option<String> = row
        .try_get("concurrency_group_key")
        .map_err(operation_error)?;
    let Some(normalized) = normalized else {
        return Ok(None);
    };
    let display: Option<String> = row
        .try_get("concurrency_display_key")
        .map_err(operation_error)?;
    let cancel: Option<bool> = row
        .try_get("concurrency_cancel_in_progress")
        .map_err(operation_error)?;
    let policy: Option<String> = row
        .try_get("concurrency_queue_policy")
        .map_err(operation_error)?;
    let (Some(display), Some(cancel), Some(policy)) = (display, cancel, policy) else {
        return Err(WorkflowRerunStoreError::UnsupportedSelection);
    };
    let queue_policy = match policy.as_str() {
        "single" => QueuePolicy::Single,
        "max" => QueuePolicy::Max,
        _ => return Err(StoreError::corrupt_data("workflow rerun queue policy is invalid").into()),
    };
    let concurrency = WorkflowConcurrency::new(display, cancel)
        .map_err(corrupt_value)?
        .with_queue_policy(queue_policy);
    if concurrency.normalized_key() != normalized {
        return Err(
            StoreError::corrupt_data("workflow rerun concurrency key is inconsistent").into(),
        );
    }
    Ok(Some(concurrency))
}

async fn lock_rerun_group(
    transaction: &mut Transaction<'_, Postgres>,
    root_run_id: Uuid,
) -> Result<(), WorkflowRerunStoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 0))")
        .bind(root_run_id)
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    Ok(())
}

async fn ensure_root_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    source: &SourceRun,
) -> Result<(), WorkflowRerunStoreError> {
    if source.root_run_id != source.source_run_id {
        return Ok(());
    }
    let rows = sqlx::query(
        r"
        INSERT INTO workflow_rerun_attempts (
            run_id, root_run_id, source_run_id, attempt,
            source_admission_digest, source_plan_digest, source_event_digest,
            created_at_ms
        ) VALUES ($1,$1,NULL,1,$2,$3,$4,$5)
        ON CONFLICT (run_id) DO NOTHING
        ",
    )
    .bind(source.root_run_id)
    .bind(&source.source_admission_digest)
    .bind(&source.source_plan_digest)
    .bind(&source.source_event_digest)
    .bind(source.source_created_at_ms)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if rows == 0 {
        let exact: bool = sqlx::query_scalar(
            r"
            SELECT EXISTS (
                SELECT 1 FROM workflow_rerun_attempts
                WHERE run_id = $1 AND root_run_id = $1
                  AND source_run_id IS NULL AND attempt = 1
                  AND source_admission_digest = $2
                  AND source_plan_digest = $3
                  AND source_event_digest = $4
            )
            ",
        )
        .bind(source.root_run_id)
        .bind(&source.source_admission_digest)
        .bind(&source.source_plan_digest)
        .bind(&source.source_event_digest)
        .fetch_one(&mut **transaction)
        .await
        .map_err(operation_error)?;
        if !exact {
            return Err(StoreError::corrupt_data("workflow rerun root lineage conflicts").into());
        }
    }
    Ok(())
}

async fn next_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    source: &SourceRun,
) -> Result<u32, WorkflowRerunStoreError> {
    let attempts = sqlx::query(
        r"
        SELECT attempt
        FROM workflow_rerun_attempts
        WHERE root_run_id = $1
        ORDER BY attempt
        FOR UPDATE
        ",
    )
    .bind(source.root_run_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if attempts.is_empty() || attempts.len() > MAX_WORKFLOW_RERUN_ATTEMPTS as usize {
        return Err(StoreError::corrupt_data("workflow rerun attempt ledger is malformed").into());
    }
    let maximum = attempts
        .last()
        .map(|row| row.try_get::<i32, _>("attempt"))
        .transpose()
        .map_err(operation_error)?
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| StoreError::corrupt_data("workflow rerun attempt is invalid"))?;
    if maximum >= MAX_WORKFLOW_RERUN_ATTEMPTS {
        return Err(WorkflowRerunStoreError::AttemptLimitReached);
    }
    maximum
        .checked_add(1)
        .ok_or(WorkflowRerunStoreError::AttemptLimitReached)
}

async fn load_triggering_actor(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &AuthorizedHumanRepositoryAction,
) -> Result<String, WorkflowRerunStoreError> {
    let login = sqlx::query_scalar::<_, String>(
        r"
        SELECT identity.provider_login
        FROM human_sessions AS session
        JOIN human_provider_identities AS identity
          ON identity.principal_id = session.principal_id
         AND identity.provider_id = session.provider_id
         AND identity.provider_subject = session.provider_subject
        WHERE session.tenant_id = $1
          AND session.principal_id = $2
          AND session.id = $3
        ",
    )
    .bind(&actor.tenant_id)
    .bind(actor.principal_id)
    .bind(actor.session_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or_else(|| StoreError::corrupt_data("workflow rerun actor has no provider login"))?;
    if login.is_empty() || login.len() > 1_024 || login.chars().any(char::is_control) {
        return Err(StoreError::corrupt_data("workflow rerun actor login is invalid").into());
    }
    Ok(login)
}

async fn load_source_jobs(
    transaction: &mut Transaction<'_, Postgres>,
    source: &SourceRun,
) -> Result<Vec<SourceJob>, WorkflowRerunStoreError> {
    let rows = sqlx::query(
        r"
        SELECT job.id, job.logical_key, job.source_order, job.execution_kind,
               job.state, job.activation_fence, job.activation_input_digest,
               job.authority_profile, job.runtime_policy_revision,
               job.runtime_policy_digest, job.activation_origin_selection_id,
               job.environment_requirement_kind, job.environment_template_digest,
               job.secret_reference_names, job.variable_reference_names,
               job.credential_requirements_schema,
               result.effective_conclusion, result.instance_count
        FROM workflow_plan_v2_jobs AS job
        JOIN workflow_plan_v2_job_result_claims AS claim
          ON claim.logical_job_id = job.id AND claim.state = 'finalized'
        JOIN workflow_plan_v2_job_results AS result ON result.logical_job_id = job.id
        JOIN workflow_plan_v2_run_result_jobs AS aggregate
          ON aggregate.run_id = job.run_id
         AND aggregate.root_invocation_id = job.invocation_id
         AND aggregate.logical_job_id = job.id
         AND aggregate.descriptor_digest = result.descriptor_digest
         AND aggregate.job_commit_digest = result.commit_digest
        WHERE job.run_id = $1 AND job.invocation_id = $2
        ORDER BY job.source_order
        ",
    )
    .bind(source.source_run_id)
    .bind(source.root_invocation_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if rows.is_empty() || rows.len() > 1_024 {
        return Err(WorkflowRerunStoreError::UnsupportedSelection);
    }
    let invocation_count: i64 = sqlx::query_scalar(
        "SELECT count(*)::BIGINT FROM workflow_plan_v2_invocations WHERE run_id = $1",
    )
    .bind(source.source_run_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if invocation_count != 1 {
        return Err(WorkflowRerunStoreError::UnsupportedSelection);
    }
    rows.into_iter().map(decode_source_job).collect()
}

fn decode_source_job(row: PgRow) -> Result<SourceJob, WorkflowRerunStoreError> {
    let execution_kind: String = row.try_get("execution_kind").map_err(operation_error)?;
    if execution_kind != "steps" {
        return Err(WorkflowRerunStoreError::UnsupportedSelection);
    }
    let state: String = row.try_get("state").map_err(operation_error)?;
    if !matches!(
        state.as_str(),
        "completed" | "skipped" | "cancelled" | "failed"
    ) {
        return Err(StoreError::corrupt_data("terminal rerun source contains a live job").into());
    }
    Ok(SourceJob {
        id: row.try_get("id").map_err(operation_error)?,
        logical_key: row.try_get("logical_key").map_err(operation_error)?,
        source_order: row.try_get("source_order").map_err(operation_error)?,
        state,
        activation_fence: row.try_get("activation_fence").map_err(operation_error)?,
        activation_input_digest: row
            .try_get("activation_input_digest")
            .map_err(operation_error)?,
        authority_profile: row.try_get("authority_profile").map_err(operation_error)?,
        runtime_policy_revision: row
            .try_get("runtime_policy_revision")
            .map_err(operation_error)?,
        runtime_policy_digest: required_digest(&row, "runtime_policy_digest")?,
        activation_origin_selection_id: row
            .try_get("activation_origin_selection_id")
            .map_err(operation_error)?,
        environment_requirement_kind: row
            .try_get("environment_requirement_kind")
            .map_err(operation_error)?,
        environment_template_digest: row
            .try_get("environment_template_digest")
            .map_err(operation_error)?,
        secret_reference_names: row
            .try_get("secret_reference_names")
            .map_err(operation_error)?,
        variable_reference_names: row
            .try_get("variable_reference_names")
            .map_err(operation_error)?,
        credential_requirements_schema: row
            .try_get("credential_requirements_schema")
            .map_err(operation_error)?,
        conclusion: row
            .try_get("effective_conclusion")
            .map_err(operation_error)?,
        instance_count: row.try_get("instance_count").map_err(operation_error)?,
    })
}

async fn load_source_dependencies(
    transaction: &mut Transaction<'_, Postgres>,
    source: &SourceRun,
) -> Result<Vec<(Uuid, Uuid)>, WorkflowRerunStoreError> {
    sqlx::query_as(
        r"
        SELECT logical_job_id, prerequisite_job_id
        FROM workflow_plan_v2_dependencies
        WHERE run_id = $1 AND invocation_id = $2
        ORDER BY logical_job_id, prerequisite_job_id
        ",
    )
    .bind(source.source_run_id)
    .bind(source.root_invocation_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)
}

fn select_jobs(
    request: &RerunWorkflow,
    jobs: &[SourceJob],
    dependencies: &[(Uuid, Uuid)],
) -> Result<BTreeSet<Uuid>, WorkflowRerunStoreError> {
    if request.selection() != WorkflowRerunSelection::EntireWorkflow
        && jobs.iter().any(|job| job.instance_count > 1)
    {
        return Err(WorkflowRerunStoreError::UnsupportedSelection);
    }
    let known = jobs.iter().map(|job| job.id).collect::<BTreeSet<_>>();
    if dependencies
        .iter()
        .any(|(job, prerequisite)| !known.contains(job) || !known.contains(prerequisite))
    {
        return Err(
            StoreError::corrupt_data("workflow rerun dependency leaves its root graph").into(),
        );
    }
    if request.selection() == WorkflowRerunSelection::EntireWorkflow {
        return Ok(known);
    }

    let mut selected = BTreeSet::new();
    let mut queue = VecDeque::new();
    match request.selection() {
        WorkflowRerunSelection::EntireWorkflow => unreachable!(),
        WorkflowRerunSelection::FailedJobsAndDependents => {
            for job in jobs.iter().filter(|job| {
                matches!(
                    job.conclusion.as_str(),
                    "failure" | "timed_out" | "cancelled"
                )
            }) {
                selected.insert(job.id);
                queue.push_back(job.id);
            }
        }
        WorkflowRerunSelection::JobAndDependents(job_id) => {
            if !known.contains(&job_id.as_uuid()) {
                return Err(WorkflowRerunStoreError::UnsupportedSelection);
            }
            selected.insert(job_id.as_uuid());
            queue.push_back(job_id.as_uuid());
        }
    }
    if selected.is_empty() {
        return Err(WorkflowRerunStoreError::UnsupportedSelection);
    }
    while let Some(prerequisite) = queue.pop_front() {
        for (dependent, candidate) in dependencies {
            if *candidate == prerequisite && selected.insert(*dependent) {
                queue.push_back(*dependent);
            }
        }
    }
    Ok(selected)
}

#[allow(clippy::too_many_arguments)]
async fn insert_run(
    transaction: &mut Transaction<'_, Postgres>,
    source: &SourceRun,
    run_id: Uuid,
    run_attempt: u32,
    admitted_at_ms: i64,
    triggering_actor: &str,
) -> Result<(), WorkflowRerunStoreError> {
    let run_attempt = i32::try_from(run_attempt)
        .map_err(|_| StoreError::corrupt_data("workflow rerun attempt exceeds INTEGER"))?;
    let rows = sqlx::query(
        r"
        INSERT INTO workflow_runs (
            id, repository_id, workflow_id, snapshot_id, run_number, run_attempt,
            event_name, event_object_key, head_sha, status, created_at_ms, updated_at_ms,
            concurrency_group_key, admission_epoch, event_digest, event_size_bytes,
            event_media_type, plan_digest, plan_object_key, plan_size_bytes,
            plan_media_type, plan_schema, workflow_name, git_ref, actor,
            display_title, commit_subject, publication_policy_revision,
            requested_dashboard_visibility, effective_dashboard_visibility,
            requested_log_visibility, requested_artifact_visibility,
            publication_safety_reason, publication_safety_schema,
            concurrency_queue_policy, public_run_id_alias, triggering_actor,
            concurrency_cancel_in_progress
        )
        SELECT $2, repository_id, workflow_id, snapshot_id, run_number, $3,
               event_name, event_object_key, head_sha, 'queued', $4, $4,
               concurrency_group_key, admission_epoch, event_digest, event_size_bytes,
               event_media_type, plan_digest, plan_object_key, plan_size_bytes,
               plan_media_type, plan_schema, workflow_name, git_ref, actor,
               display_title, commit_subject, publication_policy_revision,
               requested_dashboard_visibility, effective_dashboard_visibility,
               requested_log_visibility, requested_artifact_visibility,
               publication_safety_reason, publication_safety_schema,
               concurrency_queue_policy, public_run_id_alias, $5,
               concurrency_cancel_in_progress
        FROM workflow_runs
        WHERE id = $1
        ",
    )
    .bind(source.source_run_id)
    .bind(run_id)
    .bind(run_attempt)
    .bind(admitted_at_ms)
    .bind(triggering_actor)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    exact_one(rows, "workflow rerun source run disappeared")
}

async fn insert_marker_and_invocation(
    transaction: &mut Transaction<'_, Postgres>,
    source: &SourceRun,
    run_id: Uuid,
    invocation_id: Uuid,
    request_digest: [u8; 32],
    admitted_at_ms: i64,
) -> Result<(), WorkflowRerunStoreError> {
    let marker_rows = sqlx::query(
        r"
        INSERT INTO workflow_plan_v2_runs (
            run_id, root_invocation_id, orchestration_schema, admission_digest,
            state, revision, admitted_at_ms, updated_at_ms,
            base_context_digest, base_context_object_key,
            base_context_size_bytes, base_context_media_type, base_context_schema
        )
        SELECT $2, $3, orchestration_schema, $4, 'pending', 1, $5, $5,
               base_context_digest, base_context_object_key,
               base_context_size_bytes, base_context_media_type, base_context_schema
        FROM workflow_plan_v2_runs WHERE run_id = $1
        ",
    )
    .bind(source.source_run_id)
    .bind(run_id)
    .bind(invocation_id)
    .bind(request_digest.as_slice())
    .bind(admitted_at_ms)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    exact_one(marker_rows, "workflow rerun source marker disappeared")?;

    let invocation_rows = sqlx::query(
        r"
        INSERT INTO workflow_plan_v2_invocations (
            id, run_id, plan_digest, plan_object_key, plan_size_bytes,
            plan_media_type, plan_schema, state, revision,
            created_at_ms, updated_at_ms, invocation_kind
        )
        SELECT $3, $2, plan_digest, plan_object_key, plan_size_bytes,
               plan_media_type, plan_schema, 'pending', 1, $4, $4, 'root'
        FROM workflow_plan_v2_invocations
        WHERE run_id = $1 AND id = $5 AND invocation_kind = 'root'
        ",
    )
    .bind(source.source_run_id)
    .bind(run_id)
    .bind(invocation_id)
    .bind(admitted_at_ms)
    .bind(source.root_invocation_id)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    exact_one(
        invocation_rows,
        "workflow rerun source invocation disappeared",
    )
}

#[allow(clippy::too_many_arguments)]
async fn insert_attempt_and_request(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RerunWorkflow,
    actor: &AuthorizedHumanRepositoryAction,
    source: &SourceRun,
    run_id: Uuid,
    run_attempt: u32,
    request_digest: [u8; 32],
    admitted_at_ms: i64,
) -> Result<(), WorkflowRerunStoreError> {
    sqlx::query(
        r"
        INSERT INTO workflow_rerun_attempts (
            run_id, root_run_id, source_run_id, attempt,
            source_admission_digest, source_plan_digest, source_event_digest,
            created_at_ms
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        ",
    )
    .bind(run_id)
    .bind(source.root_run_id)
    .bind(source.source_run_id)
    .bind(
        i32::try_from(run_attempt)
            .map_err(|_| StoreError::corrupt_data("workflow rerun attempt exceeds INTEGER"))?,
    )
    .bind(&source.source_admission_digest)
    .bind(&source.source_plan_digest)
    .bind(&source.source_event_digest)
    .bind(admitted_at_ms)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;

    let (selection_kind, selected_job_id) = selection_columns(request.selection());
    sqlx::query(
        r"
        INSERT INTO workflow_rerun_requests (
            tenant_id, operation_id, request_digest, repository_id, source_run_id,
            selection_kind, selected_source_job_id, actor_principal_id,
            actor_session_id, authorization_revision, rerun_run_id, committed_at_ms
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
        ",
    )
    .bind(&actor.tenant_id)
    .bind(request.operation_id().as_uuid())
    .bind(request_digest.as_slice())
    .bind(request.repository_id().as_uuid())
    .bind(source.source_run_id)
    .bind(selection_kind)
    .bind(selected_job_id)
    .bind(actor.principal_id)
    .bind(actor.session_id)
    .bind(actor.authorization_revision)
    .bind(run_id)
    .bind(admitted_at_ms)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

fn selection_columns(selection: WorkflowRerunSelection) -> (&'static str, Option<Uuid>) {
    match selection {
        WorkflowRerunSelection::EntireWorkflow => ("entire_workflow", None),
        WorkflowRerunSelection::FailedJobsAndDependents => ("failed_jobs_and_dependents", None),
        WorkflowRerunSelection::JobAndDependents(job_id) => {
            ("job_and_dependents", Some(job_id.as_uuid()))
        }
    }
}

async fn finalize_admission_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RerunWorkflow,
    run_id: Uuid,
    request_digest: [u8; 32],
    idempotency_key: &str,
    admitted_at_ms: i64,
) -> Result<(), WorkflowRerunStoreError> {
    let rows = sqlx::query(
        r"
        UPDATE workflow_admission_receipts
        SET repository_id = $3, run_id = $4, committed_at_ms = $5
        WHERE tenant_id = $1 AND idempotency_kind = 'operation'
          AND idempotency_key = $2 AND request_digest = $6
          AND repository_id IS NULL AND run_id IS NULL AND committed_at_ms IS NULL
          AND github_subject_evidence_required
        ",
    )
    .bind(request.actor().tenant_id().as_str())
    .bind(idempotency_key)
    .bind(request.repository_id().as_uuid())
    .bind(run_id)
    .bind(admitted_at_ms)
    .bind(request_digest.as_slice())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    exact_one(rows, "workflow rerun admission receipt lost ownership")
}

async fn copy_runtime_policy_pin(
    transaction: &mut Transaction<'_, Postgres>,
    source: &SourceRun,
    run_id: Uuid,
    admitted_at_ms: i64,
) -> Result<(), WorkflowRerunStoreError> {
    let rows = sqlx::query(
        r"
        INSERT INTO workflow_plan_v2_runtime_policy_pins (
            run_id, tenant_id, repository_id, policy_revision,
            policy_digest, pinned_at_ms
        )
        SELECT $2, tenant_id, repository_id, policy_revision,
               policy_digest, $3
        FROM workflow_plan_v2_runtime_policy_pins
        WHERE run_id = $1
        ",
    )
    .bind(source.source_run_id)
    .bind(run_id)
    .bind(admitted_at_ms)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    exact_one(rows, "workflow rerun source runtime policy pin disappeared")
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn insert_jobs_and_dependencies(
    transaction: &mut Transaction<'_, Postgres>,
    source: &SourceRun,
    run_id: Uuid,
    invocation_id: Uuid,
    jobs: &[SourceJob],
    dependencies: &[(Uuid, Uuid)],
    selected: &BTreeSet<Uuid>,
    job_ids: &BTreeMap<Uuid, Uuid>,
) -> Result<(), WorkflowRerunStoreError> {
    for job in jobs {
        let new_job_id = job_ids[&job.id];
        let is_selected = selected.contains(&job.id);
        sqlx::query(
            r"
            INSERT INTO workflow_plan_v2_jobs (
                id, run_id, invocation_id, logical_key, source_order,
                execution_kind, state, activation_fence,
                activation_owner_id, activation_claimed_at_ms,
                activation_expires_at_ms, created_at_ms, updated_at_ms,
                activation_input_digest, authority_profile,
                runtime_policy_revision, runtime_policy_digest,
                activation_origin_selection_id, environment_requirement_kind,
                environment_template_digest, secret_reference_names,
                variable_reference_names, credential_requirements_schema,
                rerun_carried
            ) VALUES (
                $1,$2,$3,$4,$5,'steps',$6,$7,NULL,NULL,NULL,$8,$8,
                $9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19
            )
            ",
        )
        .bind(new_job_id)
        .bind(run_id)
        .bind(invocation_id)
        .bind(&job.logical_key)
        .bind(job.source_order)
        .bind(if is_selected { "pending" } else { &job.state })
        .bind(if is_selected { 0 } else { job.activation_fence })
        .bind(if is_selected {
            None
        } else {
            job.activation_input_digest.as_deref()
        })
        .bind(if is_selected {
            None
        } else {
            job.authority_profile.as_deref()
        })
        .bind(job.runtime_policy_revision)
        .bind(&job.runtime_policy_digest)
        .bind(if is_selected {
            None
        } else {
            job.activation_origin_selection_id
        })
        .bind(&job.environment_requirement_kind)
        .bind(job.environment_template_digest.as_deref())
        .bind(&job.secret_reference_names)
        .bind(&job.variable_reference_names)
        .bind(job.credential_requirements_schema)
        .bind(!is_selected)
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;

        sqlx::query(
            r"
            INSERT INTO workflow_rerun_attempt_jobs (
                run_id, source_run_id, logical_job_id,
                source_logical_job_id, selected
            ) VALUES ($1,$2,$3,$4,$5)
            ",
        )
        .bind(run_id)
        .bind(source.source_run_id)
        .bind(new_job_id)
        .bind(job.id)
        .bind(is_selected)
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;

        if !is_selected {
            copy_carried_result(
                transaction,
                source,
                run_id,
                invocation_id,
                new_job_id,
                job.id,
            )
            .await?;
        }
    }
    for (source_job, source_prerequisite) in dependencies {
        sqlx::query(
            r"
            INSERT INTO workflow_plan_v2_dependencies (
                run_id, invocation_id, logical_job_id, prerequisite_job_id
            ) VALUES ($1,$2,$3,$4)
            ",
        )
        .bind(run_id)
        .bind(invocation_id)
        .bind(job_ids[source_job])
        .bind(job_ids[source_prerequisite])
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    }
    Ok(())
}

async fn copy_carried_result(
    transaction: &mut Transaction<'_, Postgres>,
    source: &SourceRun,
    run_id: Uuid,
    invocation_id: Uuid,
    logical_job_id: Uuid,
    source_logical_job_id: Uuid,
) -> Result<(), WorkflowRerunStoreError> {
    let rows = sqlx::query(
        r"
        INSERT INTO workflow_rerun_carried_job_results (
            logical_job_id, run_id, invocation_id, source_run_id,
            source_logical_job_id, result_descriptor_digest, logical_key,
            source_order, plan_digest, plan_object_key, plan_size_bytes,
            plan_media_type, plan_schema, activation_output_digest,
            condition_matched, instance_count, instances_digest,
            prerequisite_count, prerequisites_digest, effective_conclusion,
            closure_has_failure, closure_has_cancelled, closure_has_skipped,
            output_count, outputs_digest, commit_digest, claim_owner_id,
            claim_generation, claim_started_at_ms, claim_expires_at_ms,
            finalized_at_ms
        )
        SELECT $3,$4,$5,$1,result.logical_job_id,result.descriptor_digest,
               result.logical_key,result.source_order,result.plan_digest,
               result.plan_object_key,result.plan_size_bytes,result.plan_media_type,
               result.plan_schema,result.activation_output_digest,
               result.condition_matched,result.instance_count,result.instances_digest,
               result.prerequisite_count,result.prerequisites_digest,
               result.effective_conclusion,result.closure_has_failure,
               result.closure_has_cancelled,result.closure_has_skipped,
               result.output_count,result.outputs_digest,result.commit_digest,
               result.claim_owner_id,result.claim_generation,
               result.claim_started_at_ms,result.claim_expires_at_ms,
               result.finalized_at_ms
        FROM workflow_plan_v2_job_results AS result
        JOIN workflow_plan_v2_job_result_claims AS claim
          ON claim.logical_job_id = result.logical_job_id
         AND claim.state = 'finalized'
        WHERE result.run_id = $1 AND result.logical_job_id = $2
        ",
    )
    .bind(source.source_run_id)
    .bind(source_logical_job_id)
    .bind(logical_job_id)
    .bind(run_id)
    .bind(invocation_id)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    exact_one(rows, "workflow rerun carried result disappeared")?;

    sqlx::query(
        r#"
        INSERT INTO workflow_rerun_carried_job_outputs (
            logical_job_id, output_name, sensitivity, public_value
        )
        SELECT $2, output_name, sensitivity, public_value
        FROM workflow_plan_v2_job_result_outputs
        WHERE logical_job_id = $1
        ORDER BY output_name COLLATE "C"
        "#,
    )
    .bind(source_logical_job_id)
    .bind(logical_job_id)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn seal_graph(
    transaction: &mut Transaction<'_, Postgres>,
    run_id: Uuid,
) -> Result<(), WorkflowRerunStoreError> {
    let rows = sqlx::query(
        r"
        UPDATE workflow_plan_v2_runs
        SET admission_graph_sealed_at_ms = database_clock.now_ms,
            updated_at_ms = database_clock.now_ms
        FROM (
            SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT AS now_ms
        ) AS database_clock
        WHERE run_id = $1 AND admission_graph_sealed_at_ms IS NULL
        ",
    )
    .bind(run_id)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    exact_one(rows, "workflow rerun graph did not seal")
}

async fn record_audit_event(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RerunWorkflow,
    actor: &AuthorizedHumanRepositoryAction,
    run_id: Uuid,
    request_digest: [u8; 32],
    occurred_at_ms: i64,
) -> Result<(), WorkflowRerunStoreError> {
    let event_id = derived_uuid(RERUN_AUDIT_ID_DOMAIN, &request_digest, &[]);
    sqlx::query(
        r"
        INSERT INTO security_audit_events (
            event_id, tenant_id, occurred_at_ms, actor_kind,
            actor_principal_id, actor_session_id, authorization_revision,
            action, outcome, resource_kind, resource_id, request_id
        ) VALUES ($1,$2,$3,'human',$4,$5,$6,'workflow.rerun','succeeded',
                  'workflow_run',$7,$8)
        ",
    )
    .bind(event_id)
    .bind(&actor.tenant_id)
    .bind(occurred_at_ms)
    .bind(actor.principal_id)
    .bind(actor.session_id)
    .bind(actor.authorization_revision)
    .bind(run_id.hyphenated().to_string())
    .bind(actor.request_id.as_deref())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let _ = request;
    Ok(())
}

fn rerun_request_digest(
    request: &RerunWorkflow,
    actor: &AuthorizedHumanRepositoryAction,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RERUN_REQUEST_DIGEST_DOMAIN);
    update_part(&mut hasher, actor.tenant_id.as_bytes());
    update_part(&mut hasher, request.repository_id().as_uuid().as_bytes());
    update_part(&mut hasher, request.source_run_id().as_uuid().as_bytes());
    update_part(&mut hasher, request.operation_id().as_uuid().as_bytes());
    update_part(&mut hasher, actor.principal_id.as_bytes());
    update_part(&mut hasher, actor.session_id.as_bytes());
    update_part(&mut hasher, &actor.authorization_revision.to_be_bytes());
    match request.selection() {
        WorkflowRerunSelection::EntireWorkflow => update_part(&mut hasher, b"entire_workflow"),
        WorkflowRerunSelection::FailedJobsAndDependents => {
            update_part(&mut hasher, b"failed_jobs_and_dependents");
        }
        WorkflowRerunSelection::JobAndDependents(job_id) => {
            update_part(&mut hasher, b"job_and_dependents");
            update_part(&mut hasher, job_id.as_uuid().as_bytes());
        }
    }
    hasher.finalize().into()
}

fn update_part(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn derived_uuid(domain: &[u8], request_digest: &[u8; 32], suffix: &[u8]) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(request_digest);
    hasher.update(suffix);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

async fn database_now_ms(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<i64, WorkflowRerunStoreError> {
    let value: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(&mut **transaction)
            .await
            .map_err(operation_error)?;
    if value < 0 {
        return Err(StoreError::corrupt_data("database clock precedes the Unix epoch").into());
    }
    Ok(value)
}

fn positive_u64(row: &PgRow, field: &'static str) -> Result<u64, WorkflowRerunStoreError> {
    u64::try_from(row.try_get::<i64, _>(field).map_err(operation_error)?)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| StoreError::corrupt_data("workflow rerun identity is not positive").into())
}

fn positive_u32(row: &PgRow, field: &'static str) -> Result<u32, WorkflowRerunStoreError> {
    u32::try_from(row.try_get::<i32, _>(field).map_err(operation_error)?)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| StoreError::corrupt_data("workflow rerun attempt is not positive").into())
}

fn required_digest(row: &PgRow, field: &'static str) -> Result<Vec<u8>, WorkflowRerunStoreError> {
    let digest: Option<Vec<u8>> = row.try_get(field).map_err(operation_error)?;
    match digest {
        Some(digest) if digest.len() == 32 => Ok(digest),
        _ => Err(StoreError::corrupt_data("workflow rerun digest is malformed").into()),
    }
}

fn exact_one(rows: u64, message: &'static str) -> Result<(), WorkflowRerunStoreError> {
    if rows == 1 {
        Ok(())
    } else {
        Err(StoreError::corrupt_data(message).into())
    }
}

fn map_concurrency_error(error: crate::WorkflowAdmissionStoreError) -> WorkflowRerunStoreError {
    match error {
        crate::WorkflowAdmissionStoreError::Store(error) => error.into(),
        crate::WorkflowAdmissionStoreError::ConcurrencyQueueFull => {
            StoreError::operation(error).into()
        }
        crate::WorkflowAdmissionStoreError::IdempotencyConflict
        | crate::WorkflowAdmissionStoreError::IdentityConflict(_)
        | crate::WorkflowAdmissionStoreError::RunNumberExhausted => StoreError::corrupt_data(
            "workflow rerun concurrency returned an unrelated admission error",
        )
        .into(),
    }
}

fn corrupt_value(error: impl std::fmt::Display) -> WorkflowRerunStoreError {
    StoreError::corrupt_data(error.to_string()).into()
}

fn operation_error(error: sqlx::Error) -> WorkflowRerunStoreError {
    StoreError::operation(error).into()
}
