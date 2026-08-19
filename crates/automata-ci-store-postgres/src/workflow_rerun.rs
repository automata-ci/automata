//! `PostgreSQL` adapter for durable workflow reruns.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use async_trait::async_trait;
use automata_ci_auth::{
    human::{PrincipalId, TenantId},
    management::{ManagementActor, ManagementRevision},
    session::SessionId,
    time::UnixTimestamp,
};
use automata_ci_core::{
    JOB_RUNTIME_CONTEXT_SCHEMA_VERSION, OperationId, RUNNER_REQUIREMENTS_SCHEMA_VERSION, RunId,
};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row as _, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::{
    PostgresStore, pg_bigint,
    secret_management::{AuthorizedHumanRepositoryAction, authorize_human_repository_action},
};
use automata_ci_store::{
    GithubCheckRerunAction, GithubCheckRerunRepository, GithubCheckRerunRequest,
    GithubCheckRerunStoreError, GithubCheckRerunTarget, MAX_WORKFLOW_RERUN_ATTEMPTS, RepositoryId,
    RerunWorkflow, RerunWorkflowByName, StoreError, WORKFLOW_ADMISSION_EPOCH, WORKFLOW_PLAN_SCHEMA,
    WorkflowAdmissionStoreError, WorkflowConcurrency, WorkflowRerunReceipt,
    WorkflowRerunRepository, WorkflowRerunSelection, WorkflowRerunStoreError,
    next_workflow_rerun_attempt,
};

const RERUN_PERMISSION: &str = "runs:rerun";
const RERUN_IDEMPOTENCY_PREFIX: &str = "workflow-rerun:";
const RERUN_REQUEST_DIGEST_DOMAIN: &[u8] = b"automata.workflow-rerun.request.v1\0";
const RERUN_RUN_ID_DOMAIN: &[u8] = b"automata.workflow-rerun.run-id.v1\0";
const RERUN_INVOCATION_ID_DOMAIN: &[u8] = b"automata.workflow-rerun.invocation-id.v1\0";
const RERUN_JOB_ID_DOMAIN: &[u8] = b"automata.workflow-rerun.job-id.v1\0";
const RERUN_AUDIT_ID_DOMAIN: &[u8] = b"automata.workflow-rerun.audit.v1\0";
const GITHUB_CHECK_RERUN_OPERATION_ID_DOMAIN: &[u8] =
    b"automata.github-check-rerun.operation-id.v1\0";

const REPLAY_RECEIPT_SQL: &str = r"
    SELECT receipt.request_digest, receipt.repository_id, receipt.run_id,
           receipt.committed_at_ms, receipt.github_subject_evidence_required,
           rerun.operation_id, rerun.source_run_id, rerun.rerun_run_id,
           run.public_run_id_alias, run.run_number, run.run_attempt,
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

struct RerunWrite<'a> {
    request: &'a RerunWorkflow,
    actor: &'a AuthorizedHumanRepositoryAction,
    source: &'a SourceRun,
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

#[derive(Debug)]
struct GithubCheckRerunResolution {
    repository_id: Uuid,
    source_run_id: Uuid,
    subject_kind: String,
    logical_job_id: Option<Uuid>,
}

#[derive(Debug)]
struct GithubCheckRerunActor {
    principal_id: Uuid,
    session_id: Uuid,
    authorization_revision: i64,
}

#[async_trait]
impl GithubCheckRerunRepository for PostgresStore {
    async fn rerun_github_check(
        &self,
        request: GithubCheckRerunRequest,
    ) -> Result<Vec<WorkflowRerunReceipt>, GithubCheckRerunStoreError> {
        rerun_from_github_check(self, request).await
    }
}

async fn rerun_from_github_check(
    store: &PostgresStore,
    request: GithubCheckRerunRequest,
) -> Result<Vec<WorkflowRerunReceipt>, GithubCheckRerunStoreError> {
    let mut transaction = store
        .pool
        .begin()
        .await
        .map_err(github_check_operation_error)?;
    let actor = resolve_github_check_actor(&mut transaction, &request).await?;
    let targets = resolve_github_check_targets(&mut transaction, &request).await?;
    transaction
        .commit()
        .await
        .map_err(github_check_operation_error)?;

    if targets.is_empty() {
        return Err(GithubCheckRerunStoreError::AuthorityRejected);
    }
    let actor = management_actor(&request, &actor)?;
    let mut receipts = Vec::with_capacity(targets.len());
    for target in targets {
        let selection = github_check_selection(&request, &target)?;
        let operation_id = github_check_operation_id(&request, target.source_run_id);
        let rerun = RerunWorkflow::new(
            actor.clone(),
            RepositoryId::from_uuid(target.repository_id),
            RunId::from_uuid(target.source_run_id),
            selection,
            OperationId::from_uuid(operation_id),
        )
        .map_err(|_| StoreError::corrupt_data("GitHub Check rerun resolution was invalid"))?;
        let receipt = rerun_workflow_transaction(store, rerun)
            .await
            .map_err(map_github_check_rerun_error)?;
        receipts.push(receipt);
    }
    Ok(receipts)
}

async fn resolve_github_check_actor(
    transaction: &mut Transaction<'_, Postgres>,
    request: &GithubCheckRerunRequest,
) -> Result<GithubCheckRerunActor, GithubCheckRerunStoreError> {
    let sender_id = request.sender_id().to_string();
    sqlx::query_as::<_, (Uuid, Uuid, i64)>(
        r"
        SELECT session.principal_id, session.id, session.authorization_revision
        FROM human_provider_identities AS identity
        JOIN human_principals AS principal ON principal.id = identity.principal_id
        JOIN human_sessions AS session
          ON session.tenant_id = $1
         AND session.principal_id = identity.principal_id
         AND session.provider_id = identity.provider_id
         AND session.provider_subject = identity.provider_subject
        JOIN tenant_human_memberships AS membership
          ON membership.tenant_id = session.tenant_id
         AND membership.principal_id = session.principal_id
        WHERE identity.provider_id = 'github'
          AND identity.provider_subject = $2
          AND principal.status = 'active'
          AND membership.status = 'active'
          AND session.lifecycle_status = 'active'
          AND session.revoked_at_ms IS NULL
          AND session.idle_expires_at_ms > automata_workflow_rerun_now_ms()
          AND session.expires_at_ms > automata_workflow_rerun_now_ms()
          AND session.authorization_revision = membership.authorization_revision
        ORDER BY session.last_seen_at_ms DESC, session.id
        LIMIT 1
        ",
    )
    .bind(request.tenant().as_str())
    .bind(sender_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(github_check_operation_error)?
    .map(
        |(principal_id, session_id, authorization_revision)| GithubCheckRerunActor {
            principal_id,
            session_id,
            authorization_revision,
        },
    )
    .ok_or(GithubCheckRerunStoreError::AuthorityRejected)
}

#[allow(clippy::too_many_lines)]
async fn resolve_github_check_targets(
    transaction: &mut Transaction<'_, Postgres>,
    request: &GithubCheckRerunRequest,
) -> Result<Vec<GithubCheckRerunResolution>, GithubCheckRerunStoreError> {
    let repository_id = request.github_repository_id().to_string();
    let head_sha = request.head_sha().as_bytes().to_vec();
    match request.target() {
        GithubCheckRerunTarget::Run {
            run_id,
            suite_id,
            external_id,
            ..
        } => sqlx::query_as::<_, (Uuid, Uuid, String, Option<Uuid>)>(
            r"
            SELECT run.repository_id, subject.run_id,
                   'workflow'::TEXT, NULL::UUID
            FROM provider_result_subjects AS subject
            JOIN provider_result_outbox AS outbox
              ON outbox.subject_id = subject.subject_id
            JOIN provider_connection_revisions AS connection
              ON connection.connection_id = subject.connection_id
             AND connection.revision = subject.connection_revision
            JOIN workflow_runs AS run ON run.id = subject.run_id
            WHERE connection.workspace_id = $1
              AND connection.connection_id = $2
              AND connection.external_repository_id = $3
              AND subject.object_algorithm = 'sha1'
              AND subject.object_bytes = $4
              AND subject.subject_kind = 'workflow-run'
              AND ('automata-result:' || subject.subject_id::TEXT) = $5
              AND outbox.phase = 'completed'
              AND outbox.state = 'completed'
              AND COALESCE(
                    outbox.external_result_id,
                    outbox.binding_external_result_id
                  ) = ('github-check:' || $6::TEXT || ':' || $7::TEXT)
            ",
        )
        .bind(request.tenant().as_str())
        .bind(request.connection_id().as_uuid())
        .bind(repository_id)
        .bind(head_sha)
        .bind(external_id)
        .bind(pg_bigint(suite_id.get()))
        .bind(pg_bigint(run_id.get()))
        .fetch_optional(&mut **transaction)
        .await
        .map_err(github_check_operation_error)?
        .map(
            |(repository_id, source_run_id, subject_kind, logical_job_id)| {
                vec![GithubCheckRerunResolution {
                    repository_id,
                    source_run_id,
                    subject_kind,
                    logical_job_id,
                }]
            },
        )
        .ok_or(GithubCheckRerunStoreError::AuthorityRejected),
        GithubCheckRerunTarget::Suite { suite_id } => {
            let rows = sqlx::query_as::<_, (Uuid, Uuid, String, Option<Uuid>)>(
                r"
                SELECT DISTINCT run.repository_id, subject.run_id,
                                'workflow'::TEXT, NULL::UUID
                FROM provider_result_subjects AS subject
                JOIN provider_result_outbox AS outbox
                  ON outbox.subject_id = subject.subject_id
                JOIN provider_connection_revisions AS connection
                  ON connection.connection_id = subject.connection_id
                 AND connection.revision = subject.connection_revision
                JOIN workflow_runs AS run ON run.id = subject.run_id
                WHERE connection.workspace_id = $1
                  AND connection.connection_id = $2
                  AND connection.external_repository_id = $3
                  AND subject.object_algorithm = 'sha1'
                  AND subject.object_bytes = $4
                  AND subject.subject_kind = 'workflow-run'
                  AND outbox.phase = 'completed'
                  AND outbox.state = 'completed'
                  AND split_part(
                        COALESCE(
                          outbox.external_result_id,
                          outbox.binding_external_result_id
                        ),
                        ':',
                        2
                      ) = $5::TEXT
                ORDER BY subject.run_id
                ",
            )
            .bind(request.tenant().as_str())
            .bind(request.connection_id().as_uuid())
            .bind(repository_id)
            .bind(head_sha)
            .bind(pg_bigint(suite_id.get()))
            .fetch_all(&mut **transaction)
            .await
            .map_err(github_check_operation_error)?;
            Ok(rows
                .into_iter()
                .map(
                    |(repository_id, source_run_id, subject_kind, logical_job_id)| {
                        GithubCheckRerunResolution {
                            repository_id,
                            source_run_id,
                            subject_kind,
                            logical_job_id,
                        }
                    },
                )
                .collect())
        }
    }
}

fn management_actor(
    request: &GithubCheckRerunRequest,
    actor: &GithubCheckRerunActor,
) -> Result<ManagementActor, GithubCheckRerunStoreError> {
    let revision = u64::try_from(actor.authorization_revision)
        .ok()
        .and_then(|value| ManagementRevision::new(value).ok())
        .ok_or_else(|| StoreError::corrupt_data("GitHub Check actor revision was invalid"))?;
    Ok(ManagementActor::new(
        TenantId::new(request.tenant().as_str().to_owned())
            .map_err(|_| StoreError::corrupt_data("GitHub Check tenant was invalid"))?,
        PrincipalId::new(actor.principal_id.hyphenated().to_string())
            .map_err(|_| StoreError::corrupt_data("GitHub Check principal was invalid"))?,
        SessionId::new(actor.session_id.hyphenated().to_string())
            .map_err(|_| StoreError::corrupt_data("GitHub Check session was invalid"))?,
        revision,
        None,
        UnixTimestamp::from_seconds(0),
    ))
}

fn github_check_selection(
    request: &GithubCheckRerunRequest,
    target: &GithubCheckRerunResolution,
) -> Result<WorkflowRerunSelection, GithubCheckRerunStoreError> {
    let action = match request.target() {
        GithubCheckRerunTarget::Run { action, .. } => Some(*action),
        GithubCheckRerunTarget::Suite { .. } => None,
    };
    match (action, target.subject_kind.as_str(), target.logical_job_id) {
        (None | Some(GithubCheckRerunAction::RerunAll), "workflow" | "job", _)
        | (Some(GithubCheckRerunAction::Rerequested), "workflow", None) => {
            Ok(WorkflowRerunSelection::EntireWorkflow)
        }
        (Some(GithubCheckRerunAction::RerunFailed), "workflow" | "job", _) => {
            Ok(WorkflowRerunSelection::FailedJobsAndDependents)
        }
        (
            Some(GithubCheckRerunAction::Rerequested | GithubCheckRerunAction::RerunJob),
            "job",
            Some(logical_job_id),
        ) => Ok(WorkflowRerunSelection::JobAndDependents(
            automata_ci_store::LogicalWorkflowJobId::from_uuid(logical_job_id)
                .map_err(|_| StoreError::corrupt_data("GitHub Check logical job was invalid"))?,
        )),
        _ => Err(GithubCheckRerunStoreError::Conflict),
    }
}

fn github_check_operation_id(request: &GithubCheckRerunRequest, source_run_id: Uuid) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(GITHUB_CHECK_RERUN_OPERATION_ID_DOMAIN);
    update_part(&mut hasher, request.delivery_id().as_bytes());
    update_part(&mut hasher, request.body_sha256().as_bytes());
    update_part(&mut hasher, source_run_id.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn map_github_check_rerun_error(error: WorkflowRerunStoreError) -> GithubCheckRerunStoreError {
    match error {
        WorkflowRerunStoreError::Store(error) => GithubCheckRerunStoreError::Store(error),
        WorkflowRerunStoreError::AuthorityRejected => GithubCheckRerunStoreError::AuthorityRejected,
        WorkflowRerunStoreError::NotFound
        | WorkflowRerunStoreError::SourceNotTerminal
        | WorkflowRerunStoreError::SourceExpired
        | WorkflowRerunStoreError::AttemptLimitReached
        | WorkflowRerunStoreError::UnsupportedSelection
        | WorkflowRerunStoreError::ConcurrencyQueueFull
        | WorkflowRerunStoreError::IdempotencyConflict => GithubCheckRerunStoreError::Conflict,
    }
}

fn github_check_operation_error(error: sqlx::Error) -> GithubCheckRerunStoreError {
    GithubCheckRerunStoreError::Store(StoreError::operation(error))
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

    admit_authorized_rerun(store, transaction, request, actor).await
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
    let request = automata_ci_store::adapter_spi::resolve_workflow_rerun(
        request,
        RepositoryId::from_uuid(repository_id),
    )
    .map_err(corrupt_value)?;
    require_exact_actor(&request, &actor)?;

    admit_authorized_rerun(store, transaction, request, actor).await
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
    store: &PostgresStore,
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
        validate_copied_trust_snapshot(
            &mut transaction,
            request.source_run_id().as_uuid(),
            receipt.run_id().as_uuid(),
        )
        .await?;
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
        || automata_ci_store::adapter_spi::workflow_rerun_age_is_rejected(
            database_now.saturating_sub(source.root_created_at_ms),
        )
    {
        return Err(WorkflowRerunStoreError::SourceExpired);
    }
    ensure_root_attempt(&mut transaction, &source).await?;
    let next_attempt = next_attempt(&mut transaction, &source).await?;
    let triggering_actor = load_triggering_actor(&mut transaction, &actor).await?;
    let jobs = load_source_jobs(&mut transaction, &source).await?;
    let dependencies = load_source_dependencies(&mut transaction, &source).await?;
    let selected = select_jobs(&request, &jobs, &dependencies)?;
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
    if let Some(concurrency) = write.source.concurrency.as_ref() {
        super::admission::assign_concurrency_slot(
            &mut transaction,
            store.runner_payload_encryption.as_ref(),
            request.repository_id(),
            RunId::from_uuid(write.run_id),
            automata_ci_core::UnixMillis::new(write.admitted_at_ms),
            concurrency,
        )
        .await
        .map_err(map_concurrency_admission_error)?;
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

fn map_concurrency_admission_error(error: WorkflowAdmissionStoreError) -> WorkflowRerunStoreError {
    match error {
        WorkflowAdmissionStoreError::Store(error) => WorkflowRerunStoreError::Store(error),
        WorkflowAdmissionStoreError::ConcurrencyQueueFull => {
            WorkflowRerunStoreError::ConcurrencyQueueFull
        }
        WorkflowAdmissionStoreError::IdempotencyConflict
        | WorkflowAdmissionStoreError::IdentityConflict(_)
        | WorkflowAdmissionStoreError::RunNumberExhausted => WorkflowRerunStoreError::Store(
            StoreError::corrupt_data("workflow rerun concurrency returned an unrelated error"),
        ),
    }
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
    copy_trust_snapshot(transaction, write.source, write.run_id).await?;
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
    record_audit_event(
        transaction,
        write.request,
        write.actor,
        write.run_id,
        write.request_digest,
        write.admitted_at_ms,
    )
    .await?;
    copy_runtime_policy_pin(
        transaction,
        write.source,
        write.run_id,
        write.admitted_at_ms,
    )
    .await?;
    insert_jobs_and_dependencies(transaction, write).await?;
    seal_graph(transaction, write.run_id).await?;
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
        ) VALUES ($1, 'operation', $2, $3, FALSE)
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
        || row
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
    let committed_at_ms = row.try_get("committed_at_ms").map_err(operation_error)?;
    let principal_id = Uuid::parse_str(request.actor().principal_id().as_str())
        .map_err(|_| StoreError::corrupt_data("workflow rerun actor principal is invalid"))?;
    let session_id = Uuid::parse_str(request.actor().session_id().as_str())
        .map_err(|_| StoreError::corrupt_data("workflow rerun actor session is invalid"))?;
    let evidence = ReplayEvidence {
        request,
        request_digest,
        run_id,
        committed_at_ms,
        principal_id,
        session_id,
        resource_id: run_id.hyphenated().to_string(),
    };
    validate_replay_audit_evidence(row, &evidence)
}

struct ReplayEvidence<'a> {
    request: &'a RerunWorkflow,
    request_digest: [u8; 32],
    run_id: Uuid,
    committed_at_ms: Option<i64>,
    principal_id: Uuid,
    session_id: Uuid,
    resource_id: String,
}

fn validate_replay_audit_evidence(
    row: &PgRow,
    evidence: &ReplayEvidence<'_>,
) -> Result<(), WorkflowRerunStoreError> {
    if row
        .try_get::<Option<Uuid>, _>("operation_id")
        .map_err(operation_error)?
        != Some(evidence.request.operation_id().as_uuid())
        || row
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
               marker.runner_requirements_schema AS marker_requirements_schema,
               run.runner_requirements_schema AS run_requirements_schema,
               marker.state AS marker_state, invocation.state AS invocation_state,
               claim.state AS result_claim_state, result.finalized_at_ms,
               root_run.id AS root_run_id, attempt.attempt AS durable_attempt,
               result_projection.subject_count AS result_subject_count,
               result_projection.terminal_count AS terminal_result_subject_count
        FROM workflow_runs AS run
        JOIN repositories AS repository ON repository.id = run.repository_id
        LEFT JOIN logical_workflow_runs AS marker ON marker.run_id = run.id
        LEFT JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = marker.run_id
         AND invocation.id = marker.root_invocation_id
        LEFT JOIN logical_workflow_run_result_claims AS claim ON claim.run_id = run.id
        LEFT JOIN logical_workflow_run_results AS result ON result.run_id = run.id
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
                   count(*) FILTER (
                       WHERE outbox.phase = 'completed'
                         AND outbox.conclusion IS NOT NULL
                         AND outbox.state = 'completed'
                   )::BIGINT AS terminal_count
            FROM provider_result_subjects AS subject
            JOIN provider_result_outbox AS outbox
              ON outbox.subject_id = subject.subject_id
            WHERE subject.subject_kind = 'workflow-run'
              AND subject.run_id = run.id
        ) AS result_projection ON TRUE
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
    if row
        .try_get::<Option<i16>, _>("marker_requirements_schema")
        .map_err(operation_error)?
        != Some(i16::try_from(RUNNER_REQUIREMENTS_SCHEMA_VERSION).unwrap_or(i16::MAX))
        || row
            .try_get::<i16, _>("run_requirements_schema")
            .map_err(operation_error)?
            != i16::try_from(RUNNER_REQUIREMENTS_SCHEMA_VERSION).unwrap_or(i16::MAX)
    {
        return Err(WorkflowRerunStoreError::UnsupportedSelection);
    }
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
        concurrency,
    })
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
    validate_current_source_contract(
        row.try_get("admission_epoch").map_err(operation_error)?,
        row.try_get("plan_schema").map_err(operation_error)?,
        row.try_get("base_context_schema")
            .map_err(operation_error)?,
    )?;
    if row
        .try_get::<i64, _>("result_subject_count")
        .map_err(operation_error)?
        != 1
        || row
            .try_get::<i64, _>("terminal_result_subject_count")
            .map_err(operation_error)?
            != 1
    {
        return Err(WorkflowRerunStoreError::UnsupportedSelection);
    }

    Ok(root_run_id)
}

fn validate_current_source_contract(
    admission_epoch: i32,
    plan_schema: Option<i32>,
    base_context_schema: Option<i16>,
) -> Result<(), WorkflowRerunStoreError> {
    let runtime_context_schema = i16::try_from(JOB_RUNTIME_CONTEXT_SCHEMA_VERSION)
        .map_err(|_| StoreError::corrupt_data("current runtime context schema exceeds SMALLINT"))?;
    if admission_epoch != i32::from(WORKFLOW_ADMISSION_EPOCH)
        || plan_schema != Some(i32::from(WORKFLOW_PLAN_SCHEMA))
        || base_context_schema != Some(runtime_context_schema)
    {
        return Err(WorkflowRerunStoreError::UnsupportedSelection);
    }
    Ok(())
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
        .with_queue_policy(queue_policy)
        .map_err(corrupt_value)?;
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
    next_workflow_rerun_attempt(maximum).ok_or(WorkflowRerunStoreError::AttemptLimitReached)
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
        FROM logical_workflow_jobs AS job
        JOIN logical_workflow_effective_job_results AS result
          ON result.logical_job_id = job.id
         AND result.run_id = job.run_id
         AND result.invocation_id = job.invocation_id
         AND result.claim_state = 'finalized'
        JOIN logical_workflow_run_result_jobs AS aggregate
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
        "SELECT count(*)::BIGINT FROM logical_workflow_invocations WHERE run_id = $1",
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
        FROM logical_workflow_dependencies
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
            concurrency_cancel_in_progress, runner_requirements_schema
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
               concurrency_cancel_in_progress, runner_requirements_schema
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
        INSERT INTO logical_workflow_runs (
            run_id, root_invocation_id, orchestration_schema, admission_digest,
            state, revision, admitted_at_ms, updated_at_ms,
            base_context_digest, base_context_object_key,
            base_context_size_bytes, base_context_media_type, base_context_schema,
            runner_requirements_schema
        )
        SELECT $2, $3, orchestration_schema, $4, 'pending', 1, $5, $5,
               base_context_digest, base_context_object_key,
               base_context_size_bytes, base_context_media_type, base_context_schema,
               runner_requirements_schema
        FROM logical_workflow_runs WHERE run_id = $1
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
        INSERT INTO logical_workflow_invocations (
            id, run_id, plan_digest, plan_object_key, plan_size_bytes,
            plan_media_type, plan_schema, state, revision,
            created_at_ms, updated_at_ms, invocation_kind
        )
        SELECT $3, $2, plan_digest, plan_object_key, plan_size_bytes,
               plan_media_type, plan_schema, 'pending', 1, $4, $4, 'root'
        FROM logical_workflow_invocations
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

async fn copy_trust_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    source: &SourceRun,
    run_id: Uuid,
) -> Result<(), WorkflowRerunStoreError> {
    let rows = sqlx::query(
        r"
        INSERT INTO workflow_run_trust_snapshots (
            run_id, snapshot_schema, policy_revision, policy_digest,
            snapshot_digest, snapshot_bytes, media_type, created_at_ms
        )
        SELECT $2, snapshot_schema, policy_revision, policy_digest,
               snapshot_digest, snapshot_bytes, media_type, created_at_ms
        FROM workflow_run_trust_snapshots
        WHERE run_id = $1
        ",
    )
    .bind(source.run_id)
    .bind(run_id)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    exact_one(rows, "workflow rerun source trust snapshot disappeared")
}

async fn validate_copied_trust_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    source_run_id: Uuid,
    rerun_id: Uuid,
) -> Result<(), WorkflowRerunStoreError> {
    let exact: Option<bool> = sqlx::query_scalar(
        r"
        SELECT ROW(
                   rerun.snapshot_schema, rerun.policy_revision,
                   rerun.policy_digest, rerun.snapshot_digest,
                   rerun.snapshot_bytes, rerun.media_type, rerun.created_at_ms
               ) = ROW(
                   source.snapshot_schema, source.policy_revision,
                   source.policy_digest, source.snapshot_digest,
                   source.snapshot_bytes, source.media_type, source.created_at_ms
               )
        FROM workflow_run_trust_snapshots AS source
        JOIN workflow_run_trust_snapshots AS rerun ON rerun.run_id = $2
        WHERE source.run_id = $1
        FOR KEY SHARE OF source, rerun
        ",
    )
    .bind(source_run_id)
    .bind(rerun_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if exact == Some(true) {
        Ok(())
    } else {
        Err(StoreError::corrupt_data("workflow rerun trust snapshot is not an exact copy").into())
    }
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
          AND NOT github_subject_evidence_required
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
        INSERT INTO logical_workflow_runtime_policy_pins (
            run_id, tenant_id, repository_id, policy_revision,
            policy_digest, pinned_at_ms
        )
        SELECT $2, tenant_id, repository_id, policy_revision,
               policy_digest, $3
        FROM logical_workflow_runtime_policy_pins
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
            INSERT INTO logical_workflow_jobs (
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
            INSERT INTO logical_workflow_dependencies (
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
        FROM logical_workflow_effective_job_results AS result
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
        FROM logical_workflow_effective_job_result_outputs
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
        UPDATE logical_workflow_runs
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

#[cfg(test)]
mod tests {
    use automata_ci_core::JOB_RUNTIME_CONTEXT_SCHEMA_VERSION;

    use automata_ci_store::{
        WORKFLOW_ADMISSION_EPOCH, WORKFLOW_PLAN_SCHEMA, WorkflowAdmissionStoreError,
        WorkflowRerunStoreError,
    };

    use super::{map_concurrency_admission_error, validate_current_source_contract};

    #[test]
    fn rerun_concurrency_preserves_the_queue_full_contract() {
        assert!(matches!(
            map_concurrency_admission_error(WorkflowAdmissionStoreError::ConcurrencyQueueFull),
            WorkflowRerunStoreError::ConcurrencyQueueFull
        ));
    }

    #[test]
    fn post_terminal_source_contract_accepts_current_schema_and_rejects_skew() {
        let admission_epoch = i32::from(WORKFLOW_ADMISSION_EPOCH);
        let plan_schema = i32::from(WORKFLOW_PLAN_SCHEMA);
        let context_schema =
            i16::try_from(JOB_RUNTIME_CONTEXT_SCHEMA_VERSION).expect("current context schema");

        assert!(
            validate_current_source_contract(
                admission_epoch,
                Some(plan_schema),
                Some(context_schema),
            )
            .is_ok()
        );
        for candidate in [
            (admission_epoch + 1, Some(plan_schema), Some(context_schema)),
            (admission_epoch, None, Some(context_schema)),
            (admission_epoch, Some(plan_schema + 1), Some(context_schema)),
            (admission_epoch, Some(plan_schema), None),
            (admission_epoch, Some(plan_schema), Some(context_schema + 1)),
        ] {
            assert!(matches!(
                validate_current_source_contract(candidate.0, candidate.1, candidate.2),
                Err(WorkflowRerunStoreError::UnsupportedSelection)
            ));
        }
    }
}
