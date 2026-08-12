//! `PostgreSQL` adapter for durable workflow reruns.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use async_trait::async_trait;
use automata_ci_core::RunId;
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row as _, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::{
    PostgresStore,
    secret_management::{AuthorizedHumanRepositoryAction, authorize_human_repository_action},
};
use crate::{
    MAX_WORKFLOW_RERUN_AGE_MILLIS, MAX_WORKFLOW_RERUN_ATTEMPTS, RepositoryId, RerunWorkflow,
    RerunWorkflowByName, StoreError, WorkflowConcurrency, WorkflowRerunReceipt,
    WorkflowRerunRepository, WorkflowRerunSelection, WorkflowRerunStoreError,
};

const RERUN_PERMISSION: &str = "runs:rerun";
const RERUN_IDEMPOTENCY_PREFIX: &str = "workflow-rerun:";
const RERUN_REQUEST_DIGEST_DOMAIN: &[u8] = b"automata.workflow-rerun.request.v1\0";
const RERUN_RUN_ID_DOMAIN: &[u8] = b"automata.workflow-rerun.run-id.v1\0";
const RERUN_INVOCATION_ID_DOMAIN: &[u8] = b"automata.workflow-rerun.invocation-id.v1\0";
const RERUN_JOB_ID_DOMAIN: &[u8] = b"automata.workflow-rerun.job-id.v1\0";
const RERUN_CHECK_SUBJECT_ID_DOMAIN: &[u8] = b"automata.workflow-rerun.check-subject-id.v1\0";
const RERUN_AUDIT_ID_DOMAIN: &[u8] = b"automata.workflow-rerun.audit.v1\0";

const REPLAY_RECEIPT_SQL: &str = r"
    SELECT receipt.request_digest, receipt.repository_id, receipt.run_id,
           receipt.committed_at_ms, receipt.github_subject_evidence_required,
           rerun.operation_id, rerun.source_run_id, rerun.rerun_run_id,
           run.public_run_id_alias, run.run_number, run.run_attempt,
           check_evidence.run_id AS check_evidence_run_id,
           check_evidence.source_run_id AS check_evidence_source_run_id,
           check_evidence.github_check_subject_id,
           check_evidence.github_check_head_sha AS check_evidence_head_sha,
           check_evidence.recorded_at_ms AS check_evidence_recorded_at_ms,
           subject.origin_kind AS check_origin_kind,
           subject.workflow_rerun_run_id AS check_origin_run_id,
           subject.workflow_run_id AS check_workflow_run_id,
           subject.head_sha AS check_subject_head_sha,
           outbox.subject_id AS outbox_subject_id,
           run_evidence.run_id AS run_evidence_run_id,
           run_evidence.github_check_subject_id AS run_evidence_subject_id,
           run_evidence.github_check_head_sha AS run_evidence_head_sha,
           run_evidence.subject_evidence_sha256 AS run_evidence_digest,
           run_evidence.admitted_at_ms AS run_evidence_admitted_at_ms,
           audit_evidence.run_id AS audit_evidence_run_id,
           audit_evidence.request_digest AS audit_request_digest,
           audit_evidence.recorded_at_ms AS audit_recorded_at_ms,
           audit.tenant_id AS audit_tenant_id,
           audit.occurred_at_ms AS audit_occurred_at_ms,
           audit.actor_kind AS audit_actor_kind,
           audit.actor_principal_id AS audit_actor_principal_id,
           audit.actor_session_id AS audit_actor_session_id,
           audit.authorization_revision AS audit_authorization_revision,
           audit.action AS audit_action, audit.outcome AS audit_outcome,
           audit.resource_kind AS audit_resource_kind,
           audit.resource_id AS audit_resource_id
    FROM workflow_admission_receipts AS receipt
    LEFT JOIN workflow_rerun_requests AS rerun
      ON rerun.tenant_id = receipt.tenant_id
     AND ('workflow-rerun:' || rerun.operation_id::TEXT) = receipt.idempotency_key
    LEFT JOIN workflow_runs AS run ON run.id = receipt.run_id
    LEFT JOIN workflow_rerun_check_evidence AS check_evidence
      ON check_evidence.tenant_id = rerun.tenant_id
     AND check_evidence.operation_id = rerun.operation_id
     AND check_evidence.run_id = rerun.rerun_run_id
     AND check_evidence.source_run_id = rerun.source_run_id
    LEFT JOIN github_check_subjects AS subject
      ON subject.tenant_id = check_evidence.tenant_id
     AND subject.id = check_evidence.github_check_subject_id
    LEFT JOIN github_check_projection_outbox AS outbox
      ON outbox.subject_id = subject.id
    LEFT JOIN github_workflow_rerun_subject_evidence AS run_evidence
      ON run_evidence.tenant_id = check_evidence.tenant_id
     AND run_evidence.operation_id = check_evidence.operation_id
     AND run_evidence.run_id = check_evidence.run_id
     AND run_evidence.github_check_subject_id =
         check_evidence.github_check_subject_id
    LEFT JOIN workflow_rerun_audit_evidence AS audit_evidence
      ON audit_evidence.tenant_id = rerun.tenant_id
     AND audit_evidence.operation_id = rerun.operation_id
     AND audit_evidence.run_id = rerun.rerun_run_id
    LEFT JOIN security_audit_events AS audit
      ON audit.event_id = audit_evidence.event_id
    WHERE receipt.tenant_id = $1
      AND receipt.idempotency_kind = 'operation'
      AND receipt.idempotency_key = $2
    FOR UPDATE OF receipt
";

#[derive(Debug)]
struct SourceRun {
    run_id: Uuid,
    root_run_id: Uuid,
    root_invocation_id: Uuid,
    run_number: u64,
    public_run_id: u64,
    admission_digest: Vec<u8>,
    plan_digest: Vec<u8>,
    event_digest: Vec<u8>,
    created_at_ms: i64,
    root_created_at_ms: i64,
    check_subject_id: Uuid,
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

#[derive(Debug)]
struct PrivateSourceAuthorityEvidence {
    id: Uuid,
    identity_digest: Vec<u8>,
    app_configuration_revision: i64,
    policy_revision: i64,
}

struct RerunWrite<'a> {
    request: &'a RerunWorkflow,
    actor: &'a AuthorizedHumanRepositoryAction,
    source: &'a SourceRun,
    private_source_authority: Option<&'a PrivateSourceAuthorityEvidence>,
    request_digest: [u8; 32],
    idempotency_key: &'a str,
    admitted_at_ms: i64,
    attempt: u32,
    triggering_actor: &'a str,
    jobs: &'a [SourceJob],
    dependencies: &'a [(Uuid, Uuid)],
    selected_jobs: &'a BTreeSet<Uuid>,
    job_ids: &'a BTreeMap<Uuid, Uuid>,
    run_id: Uuid,
    invocation_id: Uuid,
}

#[async_trait]
impl WorkflowRerunRepository for PostgresStore {
    async fn rerun_workflow(
        &self,
        request: RerunWorkflow,
    ) -> Result<WorkflowRerunReceipt, WorkflowRerunStoreError> {
        rerun_workflow_transaction(self, request).await
    }

    async fn rerun_workflow_by_name(
        &self,
        request: RerunWorkflowByName,
    ) -> Result<WorkflowRerunReceipt, WorkflowRerunStoreError> {
        rerun_workflow_by_name_transaction(self, request).await
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

    admit_authorized_rerun(transaction, request, actor).await
}

async fn rerun_workflow_by_name_transaction(
    store: &PostgresStore,
    request: RerunWorkflowByName,
) -> Result<WorkflowRerunReceipt, WorkflowRerunStoreError> {
    let mut transaction = store.pool.begin().await.map_err(operation_error)?;
    // Resolve an authorization target without taking the repository lock, then
    // acquire the normal actor/permission locks before locking and rechecking
    // the name. This preserves the established authorization lock order while
    // preventing a concurrent rename from retargeting admission.
    let repository_id = resolve_named_repository(&mut transaction, &request).await?;
    let authorization_target = repository_id.unwrap_or(Uuid::nil());
    let actor = authorize_human_repository_action(
        &mut transaction,
        request.actor(),
        RERUN_PERMISSION,
        authorization_target,
    )
    .await
    .map_err(WorkflowRerunStoreError::Store)?;
    let (Some(repository_id), Some(actor)) = (repository_id, actor) else {
        return Err(WorkflowRerunStoreError::AuthorityRejected);
    };
    if repository_id.is_nil() {
        return Err(
            StoreError::corrupt_data("named workflow rerun resolved a nil repository").into(),
        );
    }
    if lock_named_repository(&mut transaction, &request).await? != Some(repository_id) {
        return Err(WorkflowRerunStoreError::AuthorityRejected);
    }
    let request = request
        .into_resolved(RepositoryId::from_uuid(repository_id))
        .map_err(corrupt_value)?;
    require_exact_actor(&request, &actor)?;

    admit_authorized_rerun(transaction, request, actor).await
}

async fn resolve_named_repository(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RerunWorkflowByName,
) -> Result<Option<Uuid>, WorkflowRerunStoreError> {
    sqlx::query_scalar(
        r"
        SELECT id
        FROM repositories
        WHERE tenant_id = $1
          AND scm_provider = 'github'
          AND lower(owner) = lower($2)
          AND lower(name) = lower($3)
        ",
    )
    .bind(request.actor().tenant_id().as_str())
    .bind(request.repository_owner())
    .bind(request.repository_name())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn lock_named_repository(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RerunWorkflowByName,
) -> Result<Option<Uuid>, WorkflowRerunStoreError> {
    sqlx::query_scalar(
        r"
        SELECT id
        FROM repositories
        WHERE tenant_id = $1
          AND scm_provider = 'github'
          AND lower(owner) = lower($2)
          AND lower(name) = lower($3)
        FOR SHARE
        ",
    )
    .bind(request.actor().tenant_id().as_str())
    .bind(request.repository_owner())
    .bind(request.repository_name())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn admit_authorized_rerun(
    mut transaction: Transaction<'_, Postgres>,
    request: RerunWorkflow,
    actor: AuthorizedHumanRepositoryAction,
) -> Result<WorkflowRerunReceipt, WorkflowRerunStoreError> {
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

    // Every member of a rerun lineage must take the group advisory lock before
    // locking its selected source row. Otherwise a root-source request can own
    // the root row while a nested-source request owns the group lock, and the
    // nested attempt's root foreign key completes a row/advisory lock cycle.
    let root_run_id_hint = resolve_rerun_root_hint(&mut transaction, &request).await?;
    lock_rerun_group(&mut transaction, root_run_id_hint).await?;
    let source = lock_source_run(&mut transaction, &request).await?;
    if source.root_run_id != root_run_id_hint {
        return Err(StoreError::corrupt_data(
            "workflow rerun root changed while acquiring its group lock",
        )
        .into());
    }
    let database_now = database_now_ms(&mut transaction).await?;
    if source.root_created_at_ms > database_now
        || database_now.saturating_sub(source.root_created_at_ms) > MAX_WORKFLOW_RERUN_AGE_MILLIS
    {
        return Err(WorkflowRerunStoreError::SourceExpired);
    }
    let private_source_authority =
        lock_private_source_authority(&mut transaction, &request, &source, database_now).await?;
    ensure_root_attempt(&mut transaction, &source).await?;
    let next_attempt = next_attempt(&mut transaction, &source).await?;
    let triggering_actor = load_triggering_actor(&mut transaction, &actor).await?;
    let jobs = load_source_jobs(&mut transaction, &source).await?;
    let dependencies = load_source_dependencies(&mut transaction, &source).await?;
    let selected = select_jobs(&request, &jobs, &dependencies)?;
    if source.concurrency.is_some() {
        return Err(WorkflowRerunStoreError::UnsupportedSelection);
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

    let write = RerunWrite {
        request: &request,
        actor: &actor,
        source: &source,
        private_source_authority: private_source_authority.as_ref(),
        request_digest,
        idempotency_key: &idempotency_key,
        admitted_at_ms: database_now,
        attempt: next_attempt,
        triggering_actor: &triggering_actor,
        jobs: &jobs,
        dependencies: &dependencies,
        selected_jobs: &selected,
        job_ids: &job_ids,
        run_id,
        invocation_id,
    };
    persist_rerun(&mut transaction, &write).await?;
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

async fn persist_rerun(
    transaction: &mut Transaction<'_, Postgres>,
    write: &RerunWrite<'_>,
) -> Result<(), WorkflowRerunStoreError> {
    insert_run(
        transaction,
        write.source,
        write.run_id,
        write.attempt,
        write.admitted_at_ms,
        write.triggering_actor,
    )
    .await?;
    insert_marker_and_invocation(
        transaction,
        write.source,
        write.run_id,
        write.invocation_id,
        write.request_digest,
        write.admitted_at_ms,
    )
    .await?;
    insert_attempt_and_request(transaction, write).await?;
    finalize_admission_receipt(
        transaction,
        write.request,
        write.run_id,
        write.request_digest,
        write.idempotency_key,
        write.admitted_at_ms,
    )
    .await?;
    insert_rerun_check_projection(transaction, write).await?;
    copy_runtime_policy_pin(
        transaction,
        write.source,
        write.run_id,
        write.admitted_at_ms,
    )
    .await?;
    insert_jobs_and_dependencies(transaction, write).await?;
    seal_graph(transaction, write.run_id).await?;
    record_audit_event(
        transaction,
        write.request,
        write.actor,
        write.run_id,
        write.request_digest,
        write.admitted_at_ms,
    )
    .await?;

    Ok(())
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
    let row = sqlx::query(REPLAY_RECEIPT_SQL)
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
        || !row
            .try_get::<bool, _>("github_subject_evidence_required")
            .map_err(operation_error)?
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
    validate_replay_evidence(&row, request, request_digest, run_id)?;
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

fn validate_replay_evidence(
    row: &PgRow,
    request: &RerunWorkflow,
    request_digest: [u8; 32],
    run_id: Uuid,
) -> Result<(), WorkflowRerunStoreError> {
    let subject_id = row
        .try_get("github_check_subject_id")
        .map_err(operation_error)?;
    let check_head = row
        .try_get("check_evidence_head_sha")
        .map_err(operation_error)?;
    let subject_head = row
        .try_get("check_subject_head_sha")
        .map_err(operation_error)?;
    let run_head = row
        .try_get("run_evidence_head_sha")
        .map_err(operation_error)?;
    let run_digest = row
        .try_get("run_evidence_digest")
        .map_err(operation_error)?;
    let committed_at_ms = row.try_get("committed_at_ms").map_err(operation_error)?;
    let principal_id = Uuid::parse_str(request.actor().principal_id().as_str())
        .map_err(|_| StoreError::corrupt_data("workflow rerun actor principal is invalid"))?;
    let session_id = Uuid::parse_str(request.actor().session_id().as_str())
        .map_err(|_| StoreError::corrupt_data("workflow rerun actor session is invalid"))?;
    let evidence = ReplayEvidence {
        request,
        request_digest,
        run_id,
        subject_id,
        check_head,
        subject_head,
        run_head,
        run_digest,
        committed_at_ms,
        principal_id,
        session_id,
        resource_id: run_id.hyphenated().to_string(),
    };
    validate_replay_check_evidence(row, &evidence)?;
    validate_replay_audit_evidence(row, &evidence)
}

struct ReplayEvidence<'a> {
    request: &'a RerunWorkflow,
    request_digest: [u8; 32],
    run_id: Uuid,
    subject_id: Option<Uuid>,
    check_head: Option<Vec<u8>>,
    subject_head: Option<Vec<u8>>,
    run_head: Option<Vec<u8>>,
    run_digest: Option<Vec<u8>>,
    committed_at_ms: Option<i64>,
    principal_id: Uuid,
    session_id: Uuid,
    resource_id: String,
}

fn validate_replay_check_evidence(
    row: &PgRow,
    evidence: &ReplayEvidence<'_>,
) -> Result<(), WorkflowRerunStoreError> {
    if row
        .try_get::<Option<Uuid>, _>("operation_id")
        .map_err(operation_error)?
        != Some(evidence.request.operation_id().as_uuid())
        || row
            .try_get::<Option<Uuid>, _>("check_evidence_run_id")
            .map_err(operation_error)?
            != Some(evidence.run_id)
        || row
            .try_get::<Option<Uuid>, _>("check_evidence_source_run_id")
            .map_err(operation_error)?
            != Some(evidence.request.source_run_id().as_uuid())
        || evidence.subject_id.is_none()
        || row
            .try_get::<Option<String>, _>("check_origin_kind")
            .map_err(operation_error)?
            .as_deref()
            != Some("workflow_rerun")
        || row
            .try_get::<Option<Uuid>, _>("check_origin_run_id")
            .map_err(operation_error)?
            != Some(evidence.run_id)
        || row
            .try_get::<Option<Uuid>, _>("check_workflow_run_id")
            .map_err(operation_error)?
            != Some(evidence.run_id)
        || row
            .try_get::<Option<Uuid>, _>("outbox_subject_id")
            .map_err(operation_error)?
            != evidence.subject_id
        || row
            .try_get::<Option<Uuid>, _>("run_evidence_run_id")
            .map_err(operation_error)?
            != Some(evidence.run_id)
        || row
            .try_get::<Option<Uuid>, _>("run_evidence_subject_id")
            .map_err(operation_error)?
            != evidence.subject_id
        || evidence.check_head.is_none()
        || evidence.check_head != evidence.subject_head
        || evidence.check_head != evidence.run_head
        || evidence
            .run_digest
            .as_deref()
            .is_none_or(|digest| digest.len() != 32)
        || row
            .try_get::<Option<i64>, _>("check_evidence_recorded_at_ms")
            .map_err(operation_error)?
            != evidence.committed_at_ms
        || row
            .try_get::<Option<i64>, _>("run_evidence_admitted_at_ms")
            .map_err(operation_error)?
            != evidence.committed_at_ms
    {
        return Err(replay_evidence_error());
    }
    Ok(())
}

fn validate_replay_audit_evidence(
    row: &PgRow,
    evidence: &ReplayEvidence<'_>,
) -> Result<(), WorkflowRerunStoreError> {
    if row
        .try_get::<Option<Uuid>, _>("audit_evidence_run_id")
        .map_err(operation_error)?
        != Some(evidence.run_id)
        || row
            .try_get::<Option<Vec<u8>>, _>("audit_request_digest")
            .map_err(operation_error)?
            .as_deref()
            != Some(evidence.request_digest.as_slice())
        || row
            .try_get::<Option<i64>, _>("audit_recorded_at_ms")
            .map_err(operation_error)?
            != evidence.committed_at_ms
        || row
            .try_get::<Option<String>, _>("audit_tenant_id")
            .map_err(operation_error)?
            .as_deref()
            != Some(evidence.request.actor().tenant_id().as_str())
        || row
            .try_get::<Option<i64>, _>("audit_occurred_at_ms")
            .map_err(operation_error)?
            != evidence.committed_at_ms
        || row
            .try_get::<Option<String>, _>("audit_actor_kind")
            .map_err(operation_error)?
            .as_deref()
            != Some("human")
        || row
            .try_get::<Option<Uuid>, _>("audit_actor_principal_id")
            .map_err(operation_error)?
            != Some(evidence.principal_id)
        || row
            .try_get::<Option<Uuid>, _>("audit_actor_session_id")
            .map_err(operation_error)?
            != Some(evidence.session_id)
        || row
            .try_get::<Option<i64>, _>("audit_authorization_revision")
            .map_err(operation_error)?
            != i64::try_from(evidence.request.actor().authorization_revision().value()).ok()
        || row
            .try_get::<Option<String>, _>("audit_action")
            .map_err(operation_error)?
            .as_deref()
            != Some("workflow.rerun")
        || row
            .try_get::<Option<String>, _>("audit_outcome")
            .map_err(operation_error)?
            .as_deref()
            != Some("succeeded")
        || row
            .try_get::<Option<String>, _>("audit_resource_kind")
            .map_err(operation_error)?
            .as_deref()
            != Some("workflow_run")
        || row
            .try_get::<Option<String>, _>("audit_resource_id")
            .map_err(operation_error)?
            .as_deref()
            != Some(evidence.resource_id.as_str())
    {
        return Err(replay_evidence_error());
    }
    Ok(())
}

fn replay_evidence_error() -> WorkflowRerunStoreError {
    StoreError::corrupt_data("workflow rerun replay lacks exact durable evidence").into()
}

async fn resolve_rerun_root_hint(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RerunWorkflow,
) -> Result<Uuid, WorkflowRerunStoreError> {
    // This is deliberately an unlocked hint. Rerun-attempt lineage is
    // immutable, and an attempt-one source always resolves to itself. The
    // locked source query below rechecks the value after the group lock is held.
    let root_run_id: Uuid = sqlx::query_scalar(
        r"
        SELECT COALESCE(attempt.root_run_id, run.id)
        FROM workflow_runs AS run
        JOIN repositories AS repository ON repository.id = run.repository_id
        LEFT JOIN workflow_rerun_attempts AS attempt ON attempt.run_id = run.id
        WHERE repository.tenant_id = $1
          AND run.repository_id = $2
          AND run.id = $3
        ",
    )
    .bind(request.actor().tenant_id().as_str())
    .bind(request.repository_id().as_uuid())
    .bind(request.source_run_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(WorkflowRerunStoreError::NotFound)?;
    if root_run_id.is_nil() {
        return Err(StoreError::corrupt_data("workflow rerun root hint is nil").into());
    }
    Ok(root_run_id)
}

async fn lock_source_run(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RerunWorkflow,
) -> Result<SourceRun, WorkflowRerunStoreError> {
    let row = sqlx::query(
        r"
        SELECT run.run_attempt, root_run.run_number, root_run.public_run_id_alias,
               run.created_at_ms AS source_created_at_ms,
               root_run.created_at_ms AS root_created_at_ms,
               run.status, run.admission_epoch, run.plan_schema,
               run.plan_digest, run.event_digest, run.concurrency_group_key,
               run.concurrency_queue_policy, run.concurrency_cancel_in_progress,
               concurrency.display_key AS concurrency_display_key,
               marker.root_invocation_id, marker.admission_digest,
               marker.base_context_schema,
               marker.state AS marker_state, invocation.state AS invocation_state,
               claim.state AS result_claim_state, result.finalized_at_ms,
               root_run.id AS root_run_id, attempt.attempt AS durable_attempt,
               check_projection.subject_count AS check_subject_count,
               check_projection.subject_id AS check_subject_id,
               check_projection.terminal_count AS terminal_check_subject_count
        FROM workflow_runs AS run
        JOIN repositories AS repository ON repository.id = run.repository_id
        LEFT JOIN workflow_plan_v2_runs AS marker ON marker.run_id = run.id
        LEFT JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = marker.run_id
         AND invocation.id = marker.root_invocation_id
        LEFT JOIN workflow_plan_v2_run_result_claims AS claim ON claim.run_id = run.id
        LEFT JOIN workflow_plan_v2_run_results AS result ON result.run_id = run.id
        LEFT JOIN workflow_rerun_attempts AS attempt ON attempt.run_id = run.id
        LEFT JOIN workflow_runs AS root_run
          ON root_run.id = COALESCE(attempt.root_run_id, run.id)
         AND root_run.workflow_id = run.workflow_id
         AND root_run.public_run_id_alias = run.public_run_id_alias
         AND root_run.run_attempt = 1
        LEFT JOIN concurrency_groups AS concurrency
          ON concurrency.repository_id = run.repository_id
         AND concurrency.normalized_key = run.concurrency_group_key
        LEFT JOIN LATERAL (
            SELECT count(*)::BIGINT AS subject_count,
                   (array_agg(subject.id ORDER BY subject.id))[1] AS subject_id,
                   count(*) FILTER (
                       WHERE subject.desired_state = 'completed'
                         AND subject.desired_conclusion IS NOT NULL
                         AND subject.terminal_cause IS NOT NULL
                         AND subject.desired_revision = 3
                   )::BIGINT AS terminal_count
            FROM github_check_subjects AS subject
            WHERE subject.workflow_run_id = run.id
        ) AS check_projection ON TRUE
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

    let root_run_id = validate_source_row(&row)?;
    let concurrency = decode_concurrency(&row)?;
    Ok(SourceRun {
        run_id: request.source_run_id().as_uuid(),
        root_run_id,
        root_invocation_id: row
            .try_get::<Option<Uuid>, _>("root_invocation_id")
            .map_err(operation_error)?
            .ok_or(WorkflowRerunStoreError::SourceNotTerminal)?,
        run_number: positive_u64(&row, "run_number")?,
        public_run_id: positive_u64(&row, "public_run_id_alias")?,
        admission_digest: required_digest(&row, "admission_digest")?,
        plan_digest: required_digest(&row, "plan_digest")?,
        event_digest: required_digest(&row, "event_digest")?,
        created_at_ms: row
            .try_get("source_created_at_ms")
            .map_err(operation_error)?,
        root_created_at_ms: row.try_get("root_created_at_ms").map_err(operation_error)?,
        check_subject_id: row
            .try_get::<Option<Uuid>, _>("check_subject_id")
            .map_err(operation_error)?
            .ok_or(WorkflowRerunStoreError::UnsupportedSelection)?,
        concurrency,
    })
}

async fn lock_private_source_authority(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RerunWorkflow,
    source: &SourceRun,
    admitted_at_ms: i64,
) -> Result<Option<PrivateSourceAuthorityEvidence>, WorkflowRerunStoreError> {
    let visibility = sqlx::query_scalar::<_, String>(
        r"
        SELECT origin.repository_visibility
        FROM github_workflow_run_base_manifest_origins AS origin
        WHERE origin.tenant_id = $1
          AND origin.repository_id = $2
          AND origin.run_id = $3
        ",
    )
    .bind(request.actor().tenant_id().as_str())
    .bind(request.repository_id().as_uuid())
    .bind(source.root_run_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(WorkflowRerunStoreError::UnsupportedSelection)?;
    if visibility == "public" {
        return Ok(None);
    }
    if visibility != "private" {
        return Err(
            StoreError::corrupt_data("workflow rerun repository visibility is invalid").into(),
        );
    }

    let rows = sqlx::query(
        r"
        SELECT authority.id, authority.identity_digest,
               authority.app_configuration_revision, authority.policy_revision
        FROM github_workflow_run_base_manifest_origins AS origin
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = origin.tenant_id
         AND manifest.repository_id = origin.repository_id
         AND manifest.provider_connection_id = origin.provider_connection_id
         AND manifest.manifest_revision = origin.provider_manifest_revision
         AND manifest.manifest_digest = origin.provider_manifest_digest
        JOIN github_server_service_authorities AS authority
          ON authority.tenant_id = origin.tenant_id
         AND authority.id = origin.private_source_authority_id
         AND authority.repository_id = origin.repository_id
         AND authority.provider_connection_id = origin.provider_connection_id
         AND authority.provider_installation_id = origin.provider_installation_id
         AND authority.github_app_id = manifest.github_app_id
         AND authority.github_repository_id = origin.github_repository_id
         AND authority.github_repository_name = origin.github_repository_name
         AND authority.service_scope = 'private_repository_source_read'
         AND authority.github_app_client_id = manifest.github_app_client_id
         AND authority.github_app_jwt_issuer_kind =
             manifest.github_app_jwt_issuer_kind
         AND authority.app_key_spki_sha256 = manifest.app_key_spki_sha256
         AND authority.app_configuration_revision =
             origin.private_source_authority_app_configuration_revision
         AND authority.policy_revision =
             origin.private_source_authority_policy_revision
         AND authority.identity_digest =
             origin.private_source_authority_identity_digest
         AND authority.state = 'active'
         AND authority.created_at_ms <= $4
         AND authority.state_updated_at_ms <= $4
        WHERE origin.tenant_id = $1
          AND origin.repository_id = $2
          AND origin.run_id = $3
          AND origin.repository_visibility = 'private'
        FOR SHARE OF manifest, authority
        ",
    )
    .bind(request.actor().tenant_id().as_str())
    .bind(request.repository_id().as_uuid())
    .bind(source.root_run_id)
    .bind(admitted_at_ms)
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    match rows.as_slice() {
        [row] => Ok(Some(PrivateSourceAuthorityEvidence {
            id: row.try_get("id").map_err(operation_error)?,
            identity_digest: row.try_get("identity_digest").map_err(operation_error)?,
            app_configuration_revision: row
                .try_get("app_configuration_revision")
                .map_err(operation_error)?,
            policy_revision: row.try_get("policy_revision").map_err(operation_error)?,
        })),
        [] => Err(WorkflowRerunStoreError::UnsupportedSelection),
        _ => Err(
            StoreError::corrupt_data("workflow rerun private source authority is ambiguous").into(),
        ),
    }
}

fn validate_source_row(row: &PgRow) -> Result<Uuid, WorkflowRerunStoreError> {
    let source_attempt = positive_u32(row, "run_attempt")?;
    let durable_attempt: Option<i32> = row.try_get("durable_attempt").map_err(operation_error)?;
    if durable_attempt.is_none() && source_attempt != 1 {
        return Err(WorkflowRerunStoreError::UnsupportedSelection);
    }
    if durable_attempt.is_some()
        && durable_attempt.and_then(|value| u32::try_from(value).ok()) != Some(source_attempt)
    {
        return Err(
            StoreError::corrupt_data("workflow rerun attempt lineage is inconsistent").into(),
        );
    }
    let root_run_id = row
        .try_get::<Option<Uuid>, _>("root_run_id")
        .map_err(operation_error)?
        .ok_or_else(|| StoreError::corrupt_data("workflow rerun root lineage is missing"))?;
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
    row.try_get::<Option<i64>, _>("finalized_at_ms")
        .map_err(operation_error)?
        .ok_or(WorkflowRerunStoreError::SourceNotTerminal)?;
    if !terminal {
        return Err(WorkflowRerunStoreError::SourceNotTerminal);
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
    if row
        .try_get::<Option<i16>, _>("base_context_schema")
        .map_err(operation_error)?
        != Some(2)
    {
        return Err(WorkflowRerunStoreError::UnsupportedSelection);
    }
    if row
        .try_get::<i64, _>("check_subject_count")
        .map_err(operation_error)?
        != 1
        || row
            .try_get::<i64, _>("terminal_check_subject_count")
            .map_err(operation_error)?
            != 1
    {
        return Err(WorkflowRerunStoreError::UnsupportedSelection);
    }

    Ok(root_run_id)
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
        "single" => automata_ci_core::QueuePolicy::Single,
        "max" => automata_ci_core::QueuePolicy::Max,
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
    if source.root_run_id != source.run_id {
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
    .bind(&source.admission_digest)
    .bind(&source.plan_digest)
    .bind(&source.event_digest)
    .bind(source.created_at_ms)
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
        .bind(&source.admission_digest)
        .bind(&source.plan_digest)
        .bind(&source.event_digest)
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
    for (index, row) in attempts.iter().enumerate() {
        let durable = row
            .try_get::<i32, _>("attempt")
            .map_err(operation_error)
            .and_then(|value| {
                u32::try_from(value).map_err(|_| {
                    StoreError::corrupt_data("workflow rerun attempt is invalid").into()
                })
            })?;
        let expected = u32::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| StoreError::corrupt_data("workflow rerun attempt ledger overflowed"))?;
        if durable != expected {
            return Err(StoreError::corrupt_data(
                "workflow rerun attempt ledger is not contiguous",
            )
            .into());
        }
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
        JOIN workflow_plan_v2_effective_job_results AS result
          ON result.logical_job_id = job.id
         AND result.run_id = job.run_id
         AND result.invocation_id = job.invocation_id
         AND result.claim_state = 'finalized'
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
    .bind(source.run_id)
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
    .bind(source.run_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if invocation_count != 1 {
        return Err(WorkflowRerunStoreError::UnsupportedSelection);
    }
    rows.iter().map(decode_source_job).collect()
}

fn decode_source_job(row: &PgRow) -> Result<SourceJob, WorkflowRerunStoreError> {
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
        runtime_policy_digest: required_digest(row, "runtime_policy_digest")?,
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
    .bind(source.run_id)
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
            for job in jobs
                .iter()
                .filter(|job| matches!(job.conclusion.as_str(), "failure" | "timed_out"))
            {
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
    .bind(source.run_id)
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
    .bind(source.run_id)
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
    .bind(source.run_id)
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

async fn insert_attempt_and_request(
    transaction: &mut Transaction<'_, Postgres>,
    write: &RerunWrite<'_>,
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
    .bind(write.run_id)
    .bind(write.source.root_run_id)
    .bind(write.source.run_id)
    .bind(
        i32::try_from(write.attempt)
            .map_err(|_| StoreError::corrupt_data("workflow rerun attempt exceeds INTEGER"))?,
    )
    .bind(&write.source.admission_digest)
    .bind(&write.source.plan_digest)
    .bind(&write.source.event_digest)
    .bind(write.admitted_at_ms)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;

    let (selection_kind, selected_job_id) = selection_columns(write.request.selection());
    sqlx::query(
        r"
        INSERT INTO workflow_rerun_requests (
            tenant_id, operation_id, request_digest, repository_id, source_run_id,
            selection_kind, selected_source_job_id, actor_principal_id,
            actor_session_id, authorization_revision, rerun_run_id, committed_at_ms
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
        ",
    )
    .bind(&write.actor.tenant_id)
    .bind(write.request.operation_id().as_uuid())
    .bind(write.request_digest.as_slice())
    .bind(write.request.repository_id().as_uuid())
    .bind(write.source.run_id)
    .bind(selection_kind)
    .bind(selected_job_id)
    .bind(write.actor.principal_id)
    .bind(write.actor.session_id)
    .bind(write.actor.authorization_revision)
    .bind(write.run_id)
    .bind(write.admitted_at_ms)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn insert_rerun_check_projection(
    transaction: &mut Transaction<'_, Postgres>,
    write: &RerunWrite<'_>,
) -> Result<(), WorkflowRerunStoreError> {
    let subject_id = derived_uuid(RERUN_CHECK_SUBJECT_ID_DOMAIN, &write.request_digest, &[]);
    let external_id = format!("automata-check:{subject_id}");
    insert_rerun_check_subject(transaction, write, subject_id, &external_id).await?;
    link_rerun_check_subject(transaction, write, subject_id).await?;
    insert_rerun_check_evidence(transaction, write, subject_id).await?;
    insert_rerun_run_subject_evidence(transaction, write, subject_id).await
}

async fn insert_rerun_check_subject(
    transaction: &mut Transaction<'_, Postgres>,
    write: &RerunWrite<'_>,
    subject_id: Uuid,
    external_id: &str,
) -> Result<(), WorkflowRerunStoreError> {
    let inserted = sqlx::query(
        r"
        INSERT INTO github_check_subjects (
            id, tenant_id, repository_id, origin_kind,
            provider_delivery_id, schedule_fire_id, workflow_rerun_run_id,
            subject_key, provider_connection_id, provider_installation_id,
            github_repository_id, github_app_id, head_sha, check_name,
            external_id, created_at_ms, desired_updated_at_ms
        )
        SELECT $1, source.tenant_id, source.repository_id, 'workflow_rerun',
               NULL, NULL, $2, source.subject_key, source.provider_connection_id,
               source.provider_installation_id, source.github_repository_id,
               source.github_app_id, source.head_sha, source.check_name,
               $3, $4, $4
        FROM github_check_subjects AS source
        JOIN workflow_rerun_attempts AS attempt
          ON attempt.run_id = $2
         AND attempt.source_run_id = $5
        WHERE source.id = $6
          AND source.workflow_run_id = attempt.source_run_id
          AND source.desired_state = 'completed'
          AND source.desired_conclusion IS NOT NULL
          AND source.terminal_cause IS NOT NULL
          AND source.desired_revision = 3
        ",
    )
    .bind(subject_id)
    .bind(write.run_id)
    .bind(external_id)
    .bind(write.admitted_at_ms)
    .bind(write.source.run_id)
    .bind(write.source.check_subject_id)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    exact_one(inserted, "workflow rerun Check subject was not created")
}

async fn link_rerun_check_subject(
    transaction: &mut Transaction<'_, Postgres>,
    write: &RerunWrite<'_>,
    subject_id: Uuid,
) -> Result<(), WorkflowRerunStoreError> {
    let linked = sqlx::query(
        r"
        UPDATE github_check_subjects AS subject
        SET workflow_run_id = $2,
            linked_at_ms = $3,
            desired_state = 'in_progress',
            desired_revision = 2,
            desired_updated_at_ms = $3
        WHERE subject.id = $1
          AND subject.origin_kind = 'workflow_rerun'
          AND subject.workflow_rerun_run_id = $2
          AND subject.workflow_run_id IS NULL
          AND subject.linked_at_ms IS NULL
          AND subject.desired_state = 'queued'
          AND subject.desired_revision = 1
        ",
    )
    .bind(subject_id)
    .bind(write.run_id)
    .bind(write.admitted_at_ms)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    exact_one(
        linked,
        "workflow rerun Check subject did not link and start",
    )
}

async fn insert_rerun_check_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    write: &RerunWrite<'_>,
    subject_id: Uuid,
) -> Result<(), WorkflowRerunStoreError> {
    let evidence = sqlx::query(
        r"
        INSERT INTO workflow_rerun_check_evidence (
            run_id, source_run_id, tenant_id, operation_id, repository_id,
            provider_connection_id, provider_manifest_revision,
            provider_manifest_digest, source_github_check_subject_id,
            github_check_subject_id, github_check_head_sha, checks_authority_id,
            checks_authority_identity_digest,
            checks_authority_app_configuration_revision,
            checks_authority_policy_revision,
            private_source_authority_id,
            private_source_authority_identity_digest,
            private_source_authority_app_configuration_revision,
            private_source_authority_policy_revision, recorded_at_ms
        )
        SELECT $1, $2, origin.tenant_id, request.operation_id,
               origin.repository_id, origin.provider_connection_id,
               origin.provider_manifest_revision, origin.provider_manifest_digest,
               $3, $4, origin.github_check_head_sha, authority.id,
               authority.identity_digest, authority.app_configuration_revision,
               authority.policy_revision, $8, $9, $10, $11, $5
        FROM workflow_rerun_attempts AS attempt
        JOIN workflow_rerun_requests AS request
          ON request.tenant_id = $6
         AND request.operation_id = $7
         AND request.rerun_run_id = attempt.run_id
         AND request.source_run_id = attempt.source_run_id
        JOIN github_workflow_run_base_manifest_origins AS origin
          ON origin.tenant_id = request.tenant_id
         AND origin.repository_id = request.repository_id
         AND origin.run_id = attempt.root_run_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = origin.tenant_id
         AND manifest.repository_id = origin.repository_id
         AND manifest.provider_connection_id = origin.provider_connection_id
         AND manifest.manifest_revision = origin.provider_manifest_revision
         AND manifest.manifest_digest = origin.provider_manifest_digest
        JOIN github_server_service_authorities AS authority
          ON authority.tenant_id = origin.tenant_id
         AND authority.repository_id = origin.repository_id
         AND authority.provider_connection_id = origin.provider_connection_id
         AND authority.provider_installation_id = origin.provider_installation_id
         AND authority.github_app_id = manifest.github_app_id
         AND authority.github_repository_id = origin.github_repository_id
         AND authority.github_repository_name = origin.github_repository_name
         AND authority.service_scope = 'checks_write'
         AND authority.github_app_client_id = manifest.github_app_client_id
         AND authority.github_app_jwt_issuer_kind =
             manifest.github_app_jwt_issuer_kind
         AND authority.app_key_spki_sha256 = manifest.app_key_spki_sha256
         AND authority.app_configuration_revision =
             manifest.app_configuration_revision
         AND authority.policy_revision = manifest.policy_revision
         AND authority.state = 'active'
         AND authority.created_at_ms <= $5
         AND authority.state_updated_at_ms <= $5
        WHERE attempt.run_id = $1
          AND attempt.source_run_id = $2
        FOR SHARE OF manifest, authority
        ",
    )
    .bind(write.run_id)
    .bind(write.source.run_id)
    .bind(write.source.check_subject_id)
    .bind(subject_id)
    .bind(write.admitted_at_ms)
    .bind(write.request.actor().tenant_id().as_str())
    .bind(write.request.operation_id().as_uuid())
    .bind(write.private_source_authority.map(|evidence| evidence.id))
    .bind(
        write
            .private_source_authority
            .map(|evidence| evidence.identity_digest.as_slice()),
    )
    .bind(
        write
            .private_source_authority
            .map(|evidence| evidence.app_configuration_revision),
    )
    .bind(
        write
            .private_source_authority
            .map(|evidence| evidence.policy_revision),
    )
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    match evidence {
        1 => Ok(()),
        0 => Err(WorkflowRerunStoreError::UnsupportedSelection),
        _ => Err(
            StoreError::corrupt_data("workflow rerun Check evidence authority is ambiguous").into(),
        ),
    }
}

async fn insert_rerun_run_subject_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    write: &RerunWrite<'_>,
    subject_id: Uuid,
) -> Result<(), WorkflowRerunStoreError> {
    let rows = sqlx::query(
        r"
        INSERT INTO github_workflow_rerun_subject_evidence (
            operation_id, tenant_id, repository_id, workflow_id, snapshot_id,
            run_id, source_run_id, root_invocation_id,
            github_repository_owner_id, github_check_subject_id,
            github_check_head_sha, workflow_path, source_digest,
            event_name, event_digest, git_ref, workflow_plan_schema,
            plan_digest, logical_admission_digest, admitted_at_ms
        )
        SELECT request.operation_id, origin.tenant_id, origin.repository_id,
               run.workflow_id, run.snapshot_id, attempt.run_id,
               attempt.source_run_id, marker.root_invocation_id,
               origin.github_repository_owner_id, $2,
               origin.github_check_head_sha, origin.workflow_path,
               origin.source_digest, origin.event_name, origin.event_digest,
               origin.git_ref, origin.workflow_plan_schema, origin.plan_digest,
               marker.admission_digest, $3
        FROM workflow_rerun_attempts AS attempt
        JOIN workflow_rerun_requests AS request
          ON request.tenant_id = $4
         AND request.operation_id = $5
         AND request.rerun_run_id = attempt.run_id
         AND request.source_run_id = attempt.source_run_id
        JOIN workflow_runs AS run ON run.id = attempt.run_id
        JOIN workflow_plan_v2_runs AS marker ON marker.run_id = attempt.run_id
        JOIN workflow_rerun_check_evidence AS check_evidence
          ON check_evidence.tenant_id = request.tenant_id
         AND check_evidence.operation_id = request.operation_id
         AND check_evidence.run_id = attempt.run_id
         AND check_evidence.github_check_subject_id = $2
        JOIN github_workflow_run_base_manifest_origins AS origin
          ON origin.tenant_id = request.tenant_id
         AND origin.repository_id = request.repository_id
         AND origin.run_id = attempt.root_run_id
         AND origin.provider_connection_id =
             check_evidence.provider_connection_id
         AND origin.provider_manifest_revision =
             check_evidence.provider_manifest_revision
         AND origin.provider_manifest_digest =
             check_evidence.provider_manifest_digest
        WHERE attempt.run_id = $1
          AND attempt.source_run_id = $6
        ",
    )
    .bind(write.run_id)
    .bind(subject_id)
    .bind(write.admitted_at_ms)
    .bind(write.request.actor().tenant_id().as_str())
    .bind(write.request.operation_id().as_uuid())
    .bind(write.source.run_id)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    exact_one(rows, "workflow rerun run-subject evidence was not sealed")
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
    .bind(source.run_id)
    .bind(run_id)
    .bind(admitted_at_ms)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    exact_one(rows, "workflow rerun source runtime policy pin disappeared")
}

async fn insert_jobs_and_dependencies(
    transaction: &mut Transaction<'_, Postgres>,
    write: &RerunWrite<'_>,
) -> Result<(), WorkflowRerunStoreError> {
    insert_jobs(transaction, write).await?;
    insert_dependencies(transaction, write).await
}

async fn insert_jobs(
    transaction: &mut Transaction<'_, Postgres>,
    write: &RerunWrite<'_>,
) -> Result<(), WorkflowRerunStoreError> {
    for job in write.jobs {
        let new_job_id = write.job_ids[&job.id];
        let is_selected = write.selected_jobs.contains(&job.id);
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
        .bind(write.run_id)
        .bind(write.invocation_id)
        .bind(&job.logical_key)
        .bind(job.source_order)
        .bind(if is_selected { "pending" } else { &job.state })
        .bind(if is_selected { 0 } else { job.activation_fence })
        .bind(write.admitted_at_ms)
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
        .bind(write.run_id)
        .bind(write.source.run_id)
        .bind(new_job_id)
        .bind(job.id)
        .bind(is_selected)
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;

        if !is_selected {
            copy_carried_result(
                transaction,
                write.source,
                write.run_id,
                write.invocation_id,
                new_job_id,
                job.id,
            )
            .await?;
        }
    }
    Ok(())
}

async fn insert_dependencies(
    transaction: &mut Transaction<'_, Postgres>,
    write: &RerunWrite<'_>,
) -> Result<(), WorkflowRerunStoreError> {
    for (source_job, source_prerequisite) in write.dependencies {
        sqlx::query(
            r"
            INSERT INTO workflow_plan_v2_dependencies (
                run_id, invocation_id, logical_job_id, prerequisite_job_id
            ) VALUES ($1,$2,$3,$4)
            ",
        )
        .bind(write.run_id)
        .bind(write.invocation_id)
        .bind(write.job_ids[source_job])
        .bind(write.job_ids[source_prerequisite])
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
        FROM workflow_plan_v2_effective_job_results AS result
        WHERE result.run_id = $1 AND result.logical_job_id = $2
          AND result.claim_state = 'finalized'
        ",
    )
    .bind(source.run_id)
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
        FROM workflow_plan_v2_effective_job_result_outputs
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
    let rows = sqlx::query(
        r"
        INSERT INTO workflow_rerun_audit_evidence (
            run_id, tenant_id, operation_id, event_id,
            request_digest, recorded_at_ms
        ) VALUES ($1,$2,$3,$4,$5,$6)
        ",
    )
    .bind(run_id)
    .bind(&actor.tenant_id)
    .bind(request.operation_id().as_uuid())
    .bind(event_id)
    .bind(request_digest.as_slice())
    .bind(occurred_at_ms)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    exact_one(rows, "workflow rerun audit evidence was not sealed")?;
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
    let value: i64 = sqlx::query_scalar("SELECT automata_workflow_rerun_now_ms()")
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

fn corrupt_value(error: impl std::fmt::Display) -> WorkflowRerunStoreError {
    StoreError::corrupt_data(error.to_string()).into()
}

fn operation_error(error: sqlx::Error) -> WorkflowRerunStoreError {
    StoreError::operation(error).into()
}
