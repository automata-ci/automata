use async_trait::async_trait;
use automata_ci_core::{
    AttemptId, FencingToken, JOB_IR_SCHEMA_VERSION, LeaseGuard, LeaseId, OperationId,
    RUNNER_REQUIREMENTS_SCHEMA_VERSION, RunId, RunnerId, RunnerSessionId, UnixMillis, WorkflowId,
};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row as _, Transaction};
use uuid::Uuid;

use super::{CurrentAttemptOutputSafety, PostgresStore, RunnerPayloadEncryption};
use crate::{
    AdmissionObject, AdmitWorkflowRun, CANCEL_JOB_COMMAND_KIND, CANCEL_JOB_COMMAND_SCHEMA,
    CancelJobCommandPayload, CancellationActor, CancellationReason, DocumentSchema,
    EnqueueRunnerCommand, RepositoryId, RequestCancellation, RunReconciliation,
    RunReconciliationRepository, RunnerCommandPayload, RunnerGeneration, RunnerOperationKind,
    RunnerProtocolVersion, RunnerSessionFence, SessionEpoch, StoreError, WORKFLOW_ADMISSION_EPOCH,
    WORKFLOW_PLAN_SCHEMA, WorkflowAdmissionReceipt, WorkflowAdmissionRepository,
    WorkflowAdmissionStoreError, WorkflowConcurrency, WorkflowRunStatus, WorkflowSnapshotId,
};

const CONCURRENCY_CANCELLATION_ACTOR: &str = "automata.concurrency";
const CONCURRENCY_CANCELLATION_REASON: &str = "superseded by a newer workflow run";
const CANCELLATION_INTENT_ID_DOMAIN: &[u8] = b"automata.concurrency.cancel-intent.v1";
const CANCELLATION_COMMAND_ID_DOMAIN: &[u8] = b"automata.concurrency.cancel-command.v1";
const PUBLICATION_SAFETY_REASON: &str = "repository_policy";
const PUBLICATION_SAFETY_SCHEMA: i32 = 1;
pub(super) const MAX_PENDING_RUNS_PER_CONCURRENCY_GROUP: i64 = 4_096;

pub(super) const fn queue_policy_name(policy: automata_ci_core::QueuePolicy) -> &'static str {
    match policy {
        automata_ci_core::QueuePolicy::Single => "single",
        automata_ci_core::QueuePolicy::Max => "max",
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct RunPublicationSnapshot {
    revision: i64,
    dashboard: String,
    logs: String,
    artifacts: String,
}

impl RunPublicationSnapshot {
    fn new(
        revision: i64,
        dashboard: String,
        logs: String,
        artifacts: String,
    ) -> Result<Self, StoreError> {
        if revision <= 0
            || !is_publication_audience(&dashboard)
            || !is_publication_audience(&logs)
            || !is_publication_audience(&artifacts)
        {
            return Err(StoreError::corrupt_data(
                "repository publication policy is malformed",
            ));
        }
        Ok(Self {
            revision,
            dashboard,
            logs,
            artifacts,
        })
    }

    pub(super) fn from_durable_run(
        revision: Option<i64>,
        dashboard: Option<String>,
        effective_dashboard: Option<&str>,
        logs: Option<String>,
        artifacts: Option<String>,
        safety_reason: Option<&str>,
        safety_schema: Option<i32>,
    ) -> Result<Self, StoreError> {
        let snapshot = Self::new(
            revision.ok_or_else(|| {
                StoreError::corrupt_data("workflow run publication snapshot is incomplete")
            })?,
            dashboard.ok_or_else(|| {
                StoreError::corrupt_data("workflow run publication snapshot is incomplete")
            })?,
            logs.ok_or_else(|| {
                StoreError::corrupt_data("workflow run publication snapshot is incomplete")
            })?,
            artifacts.ok_or_else(|| {
                StoreError::corrupt_data("workflow run publication snapshot is incomplete")
            })?,
        )?;
        if effective_dashboard != Some(snapshot.dashboard())
            || safety_reason != Some(PUBLICATION_SAFETY_REASON)
            || safety_schema != Some(PUBLICATION_SAFETY_SCHEMA)
        {
            return Err(StoreError::corrupt_data(
                "workflow run publication snapshot is malformed",
            ));
        }
        Ok(snapshot)
    }

    pub(super) fn revalidate_against_current(&self, current: &Self) -> Result<(), StoreError> {
        // The immutable workflow-run row is the authority after the repository
        // advances. While both rows name the same revision, require their exact
        // values to agree; a newer current policy must never reinterpret the
        // already-admitted snapshot.
        if current.revision < self.revision
            || (current.revision == self.revision && current != self)
        {
            return Err(StoreError::corrupt_data(
                "workflow run publication snapshot disagrees with repository policy evidence",
            ));
        }
        Ok(())
    }

    pub(super) const fn revision(&self) -> i64 {
        self.revision
    }

    pub(super) fn dashboard(&self) -> &str {
        &self.dashboard
    }

    pub(super) fn logs(&self) -> &str {
        &self.logs
    }

    pub(super) fn artifacts(&self) -> &str {
        &self.artifacts
    }
}

fn is_publication_audience(value: &str) -> bool {
    matches!(value, "private" | "authenticated" | "public")
}

pub(super) async fn lock_repository_publication_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    repository_id: Uuid,
) -> Result<RunPublicationSnapshot, StoreError> {
    let row = sqlx::query(
        r"
        SELECT revision, dashboard_audience, log_audience, artifact_audience
        FROM repository_publication_policies
        WHERE tenant_id = $1 AND repository_id = $2
        FOR SHARE
        ",
    )
    .bind(tenant_id)
    .bind(repository_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(StoreError::operation)?
    .ok_or_else(|| StoreError::corrupt_data("repository publication policy is missing"))?;
    RunPublicationSnapshot::new(
        row.try_get("revision").map_err(StoreError::operation)?,
        row.try_get("dashboard_audience")
            .map_err(StoreError::operation)?,
        row.try_get("log_audience").map_err(StoreError::operation)?,
        row.try_get("artifact_audience")
            .map_err(StoreError::operation)?,
    )
}

#[async_trait]
impl WorkflowAdmissionRepository for PostgresStore {
    async fn admit_workflow(
        &self,
        command: AdmitWorkflowRun,
    ) -> Result<WorkflowAdmissionReceipt, WorkflowAdmissionStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        // Cancellation deliberately locks the run before reading its attempt
        // set in a later statement. Pin READ COMMITTED so a waiter observes a
        // materialization that committed while it was acquiring that lock,
        // regardless of the pool/session default.
        sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            .execute(&mut *transaction)
            .await
            .map_err(operation_error)?;
        verify_cluster_compatibility(&mut transaction).await?;

        if !claim_idempotency_receipt(&mut transaction, &command).await? {
            let receipt = replay_receipt(&mut transaction, &command).await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(receipt);
        }

        resolve_repository(&mut transaction, &command).await?;
        let publication = lock_repository_publication_snapshot(
            &mut transaction,
            command.tenant().as_str(),
            command.repository().id().as_uuid(),
        )
        .await?;
        resolve_workflow(&mut transaction, &command).await?;
        resolve_snapshot(&mut transaction, &command).await?;
        let run_number = allocate_run_number(&mut transaction, command.workflow_id()).await?;

        if let Some(concurrency) = command.concurrency() {
            lock_concurrency_group(
                &mut transaction,
                command.repository().id(),
                command.admitted_at(),
                concurrency,
            )
            .await?;
        }
        insert_run(&mut transaction, &command, run_number, &publication).await?;
        insert_jobs_and_dag(&mut transaction, &command, &publication).await?;
        if let Some(concurrency) = command.concurrency() {
            assign_concurrency_slot(
                &mut transaction,
                self.runner_payload_encryption.as_ref(),
                command.repository().id(),
                command.run_id(),
                command.admitted_at(),
                concurrency,
            )
            .await?;
        }
        finalize_receipt(&mut transaction, &command).await?;
        transaction.commit().await.map_err(operation_error)?;

        Ok(WorkflowAdmissionReceipt::new(
            command.repository().id(),
            command.workflow_id(),
            command.snapshot_id(),
            command.run_id(),
            run_number,
            false,
        ))
    }
}

async fn verify_cluster_compatibility(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), WorkflowAdmissionStoreError> {
    let row = sqlx::query(
        r"
        SELECT minimum_admission_epoch, job_ir_schema, runner_requirements_schema
        FROM automata_cluster_compatibility
        WHERE singleton
        FOR SHARE
        ",
    )
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or_else(|| StoreError::corrupt_data("missing cluster compatibility record"))?;
    let actual: (i32, i32, i32) = (
        row.try_get("minimum_admission_epoch")
            .map_err(operation_error)?,
        row.try_get("job_ir_schema").map_err(operation_error)?,
        row.try_get("runner_requirements_schema")
            .map_err(operation_error)?,
    );
    if actual
        != (
            i32::from(WORKFLOW_ADMISSION_EPOCH),
            i32::from(JOB_IR_SCHEMA_VERSION),
            i32::from(RUNNER_REQUIREMENTS_SCHEMA_VERSION),
        )
    {
        return Err(StoreError::corrupt_data("unsupported cluster compatibility epoch").into());
    }
    Ok(())
}

async fn claim_idempotency_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitWorkflowRun,
) -> Result<bool, WorkflowAdmissionStoreError> {
    let rows = sqlx::query(
        r"
        INSERT INTO workflow_admission_receipts (
            tenant_id, idempotency_kind, idempotency_key, request_digest
        ) VALUES ($1, $2, $3, $4)
        ON CONFLICT DO NOTHING
        ",
    )
    .bind(command.tenant().as_str())
    .bind(command.idempotency().kind())
    .bind(command.idempotency().key())
    .bind(command.request_digest().as_bytes().as_slice())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    Ok(rows == 1)
}

#[allow(clippy::too_many_lines)] // Exact replay decodes and checks every current run descriptor.
async fn replay_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitWorkflowRun,
) -> Result<WorkflowAdmissionReceipt, WorkflowAdmissionStoreError> {
    let row = sqlx::query(
        r"
        SELECT receipt.request_digest,
               receipt.repository_id AS receipt_repository_id, receipt.run_id,
               run.repository_id AS run_repository_id,
               run.workflow_id, run.snapshot_id, run.run_number,
               run.publication_policy_revision,
               run.requested_dashboard_visibility,
               run.effective_dashboard_visibility,
               run.requested_log_visibility,
               run.requested_artifact_visibility,
               run.publication_safety_reason, run.publication_safety_schema,
               receipt.committed_at_ms
        FROM workflow_admission_receipts AS receipt
        LEFT JOIN workflow_runs AS run ON run.id = receipt.run_id
        WHERE receipt.tenant_id = $1
          AND receipt.idempotency_kind = $2
          AND receipt.idempotency_key = $3
        FOR UPDATE OF receipt
        ",
    )
    .bind(command.tenant().as_str())
    .bind(command.idempotency().kind())
    .bind(command.idempotency().key())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or_else(|| StoreError::corrupt_data("idempotency conflict lost its durable receipt"))?;
    let request_digest: Vec<u8> = row.try_get("request_digest").map_err(operation_error)?;
    if request_digest.as_slice() != command.request_digest().as_bytes() {
        return Err(WorkflowAdmissionStoreError::IdempotencyConflict);
    }
    let repository_id = row
        .try_get::<Option<Uuid>, _>("receipt_repository_id")
        .map_err(operation_error)?;
    let run_repository_id = row
        .try_get::<Option<Uuid>, _>("run_repository_id")
        .map_err(operation_error)?;
    let run_id = row
        .try_get::<Option<Uuid>, _>("run_id")
        .map_err(operation_error)?;
    let workflow_id = row
        .try_get::<Option<Uuid>, _>("workflow_id")
        .map_err(operation_error)?;
    let snapshot_id = row
        .try_get::<Option<Uuid>, _>("snapshot_id")
        .map_err(operation_error)?;
    let run_number = row
        .try_get::<Option<i64>, _>("run_number")
        .map_err(operation_error)?;
    let committed_at = row
        .try_get::<Option<i64>, _>("committed_at_ms")
        .map_err(operation_error)?;
    let (
        Some(repository_id),
        Some(run_repository_id),
        Some(run_id),
        Some(workflow_id),
        Some(snapshot_id),
        Some(run_number),
        Some(_),
    ) = (
        repository_id,
        run_repository_id,
        run_id,
        workflow_id,
        snapshot_id,
        run_number,
        committed_at,
    )
    else {
        return Err(StoreError::corrupt_data("committed admission receipt is incomplete").into());
    };
    if repository_id != command.repository().id().as_uuid()
        || run_repository_id != repository_id
        || run_id != command.run_id().as_uuid()
        || workflow_id != command.workflow_id().as_uuid()
        || snapshot_id != command.snapshot_id().as_uuid()
    {
        return Err(StoreError::corrupt_data(
            "workflow admission receipt disagrees with immutable run evidence",
        )
        .into());
    }
    let publication = RunPublicationSnapshot::from_durable_run(
        row.try_get("publication_policy_revision")
            .map_err(operation_error)?,
        row.try_get("requested_dashboard_visibility")
            .map_err(operation_error)?,
        row.try_get::<Option<String>, _>("effective_dashboard_visibility")
            .map_err(operation_error)?
            .as_deref(),
        row.try_get("requested_log_visibility")
            .map_err(operation_error)?,
        row.try_get("requested_artifact_visibility")
            .map_err(operation_error)?,
        row.try_get::<Option<String>, _>("publication_safety_reason")
            .map_err(operation_error)?
            .as_deref(),
        row.try_get("publication_safety_schema")
            .map_err(operation_error)?,
    )?;
    let current = lock_repository_publication_snapshot(
        transaction,
        command.tenant().as_str(),
        command.repository().id().as_uuid(),
    )
    .await?;
    publication.revalidate_against_current(&current)?;
    let run_number = u64::try_from(run_number)
        .ok()
        .filter(|number| *number > 0)
        .ok_or_else(|| StoreError::corrupt_data("invalid durable workflow run number"))?;
    Ok(WorkflowAdmissionReceipt::new(
        RepositoryId::from_uuid(repository_id),
        WorkflowId::from_uuid(workflow_id),
        WorkflowSnapshotId::from_uuid(snapshot_id),
        RunId::from_uuid(run_id),
        run_number,
        true,
    ))
}

async fn resolve_repository(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitWorkflowRun,
) -> Result<(), WorkflowAdmissionStoreError> {
    let repository = command.repository();
    let id: Uuid = sqlx::query_scalar(
        r"
        INSERT INTO repositories (
            id, tenant_id, scm_provider, provider_repository_id, owner, name,
            created_at_ms, updated_at_ms
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$7)
        ON CONFLICT (tenant_id, scm_provider, provider_repository_id)
        DO UPDATE SET owner = EXCLUDED.owner, name = EXCLUDED.name,
                      updated_at_ms = EXCLUDED.updated_at_ms
        RETURNING id
        ",
    )
    .bind(repository.id().as_uuid())
    .bind(command.tenant().as_str())
    .bind(repository.provider())
    .bind(repository.provider_repository_id())
    .bind(repository.owner())
    .bind(repository.name())
    .bind(command.admitted_at().get())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if id != repository.id().as_uuid() {
        return Err(WorkflowAdmissionStoreError::IdentityConflict("repository"));
    }
    Ok(())
}

async fn resolve_workflow(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitWorkflowRun,
) -> Result<(), WorkflowAdmissionStoreError> {
    let id: Uuid = sqlx::query_scalar(
        r"
        INSERT INTO workflow_definitions (
            id, repository_id, path, created_at_ms, updated_at_ms
        ) VALUES ($1,$2,$3,$4,$4)
        ON CONFLICT (repository_id, path)
        DO UPDATE SET updated_at_ms = EXCLUDED.updated_at_ms
        RETURNING id
        ",
    )
    .bind(command.workflow_id().as_uuid())
    .bind(command.repository().id().as_uuid())
    .bind(command.workflow_path())
    .bind(command.admitted_at().get())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if id != command.workflow_id().as_uuid() {
        return Err(WorkflowAdmissionStoreError::IdentityConflict("workflow"));
    }
    Ok(())
}

async fn resolve_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitWorkflowRun,
) -> Result<(), WorkflowAdmissionStoreError> {
    let source = command.source();
    sqlx::query(
        r"
        INSERT INTO workflow_snapshots (
            id, workflow_id, source_digest, source_object_key, frontend_schema,
            created_at_ms, admission_epoch, source_size_bytes, source_media_type
        ) VALUES ($1,$2,$3,$4,1,$5,$6,$7,$8)
        ON CONFLICT (workflow_id, source_digest) DO NOTHING
        ",
    )
    .bind(command.snapshot_id().as_uuid())
    .bind(command.workflow_id().as_uuid())
    .bind(source.digest().as_bytes().as_slice())
    .bind(source.object_key().as_str())
    .bind(command.admitted_at().get())
    .bind(i32::from(WORKFLOW_ADMISSION_EPOCH))
    .bind(size_i64(source)?)
    .bind(source.media_type())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;

    let row = sqlx::query(
        r"
        SELECT id, source_object_key, frontend_schema, admission_epoch,
               source_size_bytes, source_media_type
        FROM workflow_snapshots
        WHERE workflow_id = $1 AND source_digest = $2
        FOR UPDATE
        ",
    )
    .bind(command.workflow_id().as_uuid())
    .bind(source.digest().as_bytes().as_slice())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let exact = row.try_get::<Uuid, _>("id").map_err(operation_error)?
        == command.snapshot_id().as_uuid()
        && row
            .try_get::<String, _>("source_object_key")
            .map_err(operation_error)?
            == source.object_key().as_str()
        && row
            .try_get::<i16, _>("frontend_schema")
            .map_err(operation_error)?
            == 1
        && row
            .try_get::<i32, _>("admission_epoch")
            .map_err(operation_error)?
            == i32::from(WORKFLOW_ADMISSION_EPOCH)
        && row
            .try_get::<Option<i64>, _>("source_size_bytes")
            .map_err(operation_error)?
            == Some(size_i64(source)?)
        && row
            .try_get::<Option<String>, _>("source_media_type")
            .map_err(operation_error)?
            .as_deref()
            == Some(source.media_type());
    if !exact {
        return Err(WorkflowAdmissionStoreError::IdentityConflict(
            "workflow snapshot",
        ));
    }
    Ok(())
}

async fn allocate_run_number(
    transaction: &mut Transaction<'_, Postgres>,
    workflow_id: WorkflowId,
) -> Result<u64, WorkflowAdmissionStoreError> {
    let number: Option<i64> = sqlx::query_scalar(
        r"
        INSERT INTO workflow_run_number_counters (workflow_id, next_run_number)
        VALUES ($1, 2)
        ON CONFLICT (workflow_id) DO UPDATE
        SET next_run_number = workflow_run_number_counters.next_run_number + 1
        WHERE workflow_run_number_counters.next_run_number < 9223372036854775807
        RETURNING next_run_number - 1
        ",
    )
    .bind(workflow_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let number = number.ok_or(WorkflowAdmissionStoreError::RunNumberExhausted)?;
    u64::try_from(number)
        .ok()
        .filter(|number| *number > 0)
        .ok_or(WorkflowAdmissionStoreError::RunNumberExhausted)
}

pub(super) async fn lock_concurrency_group(
    transaction: &mut Transaction<'_, Postgres>,
    repository_id: RepositoryId,
    admitted_at: UnixMillis,
    concurrency: &WorkflowConcurrency,
) -> Result<(), WorkflowAdmissionStoreError> {
    lock_concurrency_advisory(
        transaction,
        repository_id.as_uuid(),
        concurrency.normalized_key(),
    )
    .await
    .map_err(WorkflowAdmissionStoreError::from)?;
    sqlx::query(
        r"
        INSERT INTO concurrency_groups (
            repository_id, normalized_key, display_key, updated_at_ms
        ) VALUES ($1,$2,$3,$4)
        ON CONFLICT (repository_id, normalized_key) DO NOTHING
        ",
    )
    .bind(repository_id.as_uuid())
    .bind(concurrency.normalized_key())
    .bind(concurrency.display_key())
    .bind(admitted_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    sqlx::query(
        r"
        SELECT running_run_id
        FROM concurrency_groups
        WHERE repository_id = $1 AND normalized_key = $2
        FOR UPDATE
        ",
    )
    .bind(repository_id.as_uuid())
    .bind(concurrency.normalized_key())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn insert_run(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitWorkflowRun,
    run_number: u64,
    publication: &RunPublicationSnapshot,
) -> Result<(), WorkflowAdmissionStoreError> {
    let event = command.event();
    let plan = command.plan();
    let run_number =
        i64::try_from(run_number).map_err(|_| WorkflowAdmissionStoreError::RunNumberExhausted)?;
    let run_attempt = i32::try_from(command.run_attempt())
        .map_err(|_| StoreError::corrupt_data("workflow run attempt exceeds INTEGER"))?;
    sqlx::query(
        r"
        INSERT INTO workflow_runs (
            id, repository_id, workflow_id, snapshot_id, run_number, run_attempt,
            event_name, event_object_key, head_sha, status, workflow_name,
            git_ref, actor, display_title, commit_subject,
            created_at_ms, updated_at_ms, concurrency_group_key,
            concurrency_queue_policy,
            admission_epoch, event_digest, event_size_bytes, event_media_type,
            plan_digest, plan_object_key, plan_size_bytes, plan_media_type, plan_schema,
            publication_policy_revision, requested_dashboard_visibility,
            effective_dashboard_visibility, requested_log_visibility,
            requested_artifact_visibility, publication_safety_reason,
            publication_safety_schema
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,'queued',$10,
            $11,$12,$13,$14,$15,$15,$16,$17,
            $18,$19,$20,$21,$22,$23,$24,$25,$26,
            $27,$28,$28,$29,$30,$31,$32
        )
        ",
    )
    .bind(command.run_id().as_uuid())
    .bind(command.repository().id().as_uuid())
    .bind(command.workflow_id().as_uuid())
    .bind(command.snapshot_id().as_uuid())
    .bind(run_number)
    .bind(run_attempt)
    .bind(command.event_name())
    .bind(event.object_key().as_str())
    .bind(command.head_sha())
    .bind(command.workflow_name())
    .bind(command.git_ref())
    .bind(command.actor())
    .bind(command.display_title())
    .bind(command.commit_subject())
    .bind(command.admitted_at().get())
    .bind(
        command
            .concurrency()
            .map(WorkflowConcurrency::normalized_key),
    )
    .bind(
        command
            .concurrency()
            .map(|concurrency| queue_policy_name(concurrency.queue_policy())),
    )
    .bind(i32::from(WORKFLOW_ADMISSION_EPOCH))
    .bind(event.digest().as_bytes().as_slice())
    .bind(size_i64(event)?)
    .bind(event.media_type())
    .bind(plan.digest().as_bytes().as_slice())
    .bind(plan.object_key().as_str())
    .bind(size_i64(plan)?)
    .bind(plan.media_type())
    .bind(i32::from(WORKFLOW_PLAN_SCHEMA))
    .bind(publication.revision())
    .bind(publication.dashboard())
    .bind(publication.logs())
    .bind(publication.artifacts())
    .bind(PUBLICATION_SAFETY_REASON)
    .bind(PUBLICATION_SAFETY_SCHEMA)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn insert_jobs_and_dag(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitWorkflowRun,
    publication: &RunPublicationSnapshot,
) -> Result<(), WorkflowAdmissionStoreError> {
    let attempt_safety =
        CurrentAttemptOutputSafety::readable(publication.logs()).ok_or_else(|| {
            StoreError::corrupt_data("workflow run log publication snapshot is malformed")
        })?;
    for job in command.jobs() {
        let requirements: serde_json::Value = serde_json::from_str(job.requirements().as_str())
            .map_err(|_| StoreError::corrupt_data("invalid admitted runner requirements"))?;
        sqlx::query(
            r"
            INSERT INTO jobs (
                id, run_id, job_key, display_name, job_ir_digest,
                job_ir_object_key, requirements, created_at_ms,
                admission_epoch, job_ir_schema, job_ir_size_bytes
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
            ",
        )
        .bind(job.job_id().as_uuid())
        .bind(command.run_id().as_uuid())
        .bind(job.key())
        .bind(job.display_name())
        .bind(job.job_ir().digest().as_bytes().as_slice())
        .bind(job.job_ir().object_key().as_str())
        .bind(requirements)
        .bind(command.admitted_at().get())
        .bind(i32::from(WORKFLOW_ADMISSION_EPOCH))
        .bind(i32::from(JOB_IR_SCHEMA_VERSION))
        .bind(size_i64(job.job_ir())?)
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
        sqlx::query(
            r"
            INSERT INTO job_attempts (
                id, job_id, attempt_number, lifecycle, queued_at_ms, changed_at_ms,
                secret_exposure_class, raw_log_disposition,
                requested_log_visibility, effective_log_visibility,
                output_safety_reason, output_safety_schema, classified_at_ms
            ) VALUES (
                $1,$2,1,'queued',$3,$3,$4,$5,$6,$7,$8,$9,$3
            )
            ",
        )
        .bind(job.attempt_id().as_uuid())
        .bind(job.job_id().as_uuid())
        .bind(command.admitted_at().get())
        .bind(attempt_safety.secret_exposure_class())
        .bind(attempt_safety.raw_log_disposition())
        .bind(attempt_safety.requested_log_visibility())
        .bind(attempt_safety.effective_log_visibility())
        .bind(attempt_safety.output_safety_reason())
        .bind(attempt_safety.output_safety_schema())
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    }
    for job in command.jobs() {
        for prerequisite in job.prerequisites() {
            sqlx::query(
                r"
                INSERT INTO job_dependencies (run_id, job_id, prerequisite_job_id)
                VALUES ($1,$2,$3)
                ",
            )
            .bind(command.run_id().as_uuid())
            .bind(job.job_id().as_uuid())
            .bind(prerequisite.as_uuid())
            .execute(&mut **transaction)
            .await
            .map_err(operation_error)?;
        }
    }
    Ok(())
}

pub(super) async fn assign_concurrency_slot(
    transaction: &mut Transaction<'_, Postgres>,
    encryption: Option<&RunnerPayloadEncryption>,
    repository_id: RepositoryId,
    run_id: RunId,
    admitted_at: UnixMillis,
    concurrency: &WorkflowConcurrency,
) -> Result<(), WorkflowAdmissionStoreError> {
    let row = sqlx::query(
        r"
        SELECT running_run_id
        FROM concurrency_groups
        WHERE repository_id = $1 AND normalized_key = $2
        FOR UPDATE
        ",
    )
    .bind(repository_id.as_uuid())
    .bind(concurrency.normalized_key())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let mut running = row
        .try_get::<Option<Uuid>, _>("running_run_id")
        .map_err(operation_error)?;

    running = discard_terminal_slot(transaction, running).await?;
    delete_terminal_pending_runs(transaction, repository_id, concurrency).await?;
    if concurrency.queue_policy() == automata_ci_core::QueuePolicy::Single {
        let old_pending = active_pending_runs(transaction, repository_id, concurrency).await?;
        for old_pending in old_pending {
            cancel_run(transaction, encryption, old_pending, run_id, admitted_at).await?;
        }
        delete_pending_runs(transaction, repository_id, concurrency).await?;
    }

    let mut enqueue = false;
    if concurrency.cancel_in_progress() {
        if let Some(old_running) = running.take() {
            cancel_run(transaction, encryption, old_running, run_id, admitted_at).await?;
        }
        running = Some(run_id.as_uuid());
    } else if running.is_some() {
        enqueue = true;
    } else {
        running = Some(run_id.as_uuid());
    }

    if enqueue {
        let count = pending_run_count(transaction, repository_id, concurrency).await?;
        if count >= MAX_PENDING_RUNS_PER_CONCURRENCY_GROUP {
            return Err(WorkflowAdmissionStoreError::ConcurrencyQueueFull);
        }
        sqlx::query(
            r"
            INSERT INTO concurrency_group_pending_runs (
                repository_id, normalized_key, run_id, enqueued_at_ms
            ) VALUES ($1,$2,$3,$4)
            ",
        )
        .bind(repository_id.as_uuid())
        .bind(concurrency.normalized_key())
        .bind(run_id.as_uuid())
        .bind(admitted_at.get())
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    }

    let rows = sqlx::query(
        r"
        UPDATE concurrency_groups
        SET display_key = $3, running_run_id = $4,
            generation = generation + 1, updated_at_ms = $5
        WHERE repository_id = $1 AND normalized_key = $2
          AND generation < 9223372036854775807
        ",
    )
    .bind(repository_id.as_uuid())
    .bind(concurrency.normalized_key())
    .bind(concurrency.display_key())
    .bind(running)
    .bind(admitted_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if rows != 1 {
        return Err(StoreError::corrupt_data("concurrency generation is exhausted").into());
    }
    Ok(())
}

async fn active_pending_runs(
    transaction: &mut Transaction<'_, Postgres>,
    repository_id: RepositoryId,
    concurrency: &WorkflowConcurrency,
) -> Result<Vec<Uuid>, WorkflowAdmissionStoreError> {
    sqlx::query_scalar(
        r"
        SELECT pending.run_id
        FROM concurrency_group_pending_runs AS pending
        JOIN workflow_runs AS run ON run.id = pending.run_id
        WHERE pending.repository_id = $1 AND pending.normalized_key = $2
          AND run.status IN ('queued', 'in_progress')
        ORDER BY pending.enqueued_at_ms, pending.run_id
        ",
    )
    .bind(repository_id.as_uuid())
    .bind(concurrency.normalized_key())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn delete_terminal_pending_runs(
    transaction: &mut Transaction<'_, Postgres>,
    repository_id: RepositoryId,
    concurrency: &WorkflowConcurrency,
) -> Result<(), WorkflowAdmissionStoreError> {
    sqlx::query(
        r"
        DELETE FROM concurrency_group_pending_runs AS pending
        USING workflow_runs AS run
        WHERE pending.repository_id = $1 AND pending.normalized_key = $2
          AND run.id = pending.run_id
          AND run.status NOT IN ('queued', 'in_progress')
        ",
    )
    .bind(repository_id.as_uuid())
    .bind(concurrency.normalized_key())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn delete_pending_runs(
    transaction: &mut Transaction<'_, Postgres>,
    repository_id: RepositoryId,
    concurrency: &WorkflowConcurrency,
) -> Result<(), WorkflowAdmissionStoreError> {
    sqlx::query(
        r"
        DELETE FROM concurrency_group_pending_runs
        WHERE repository_id = $1 AND normalized_key = $2
        ",
    )
    .bind(repository_id.as_uuid())
    .bind(concurrency.normalized_key())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn pending_run_count(
    transaction: &mut Transaction<'_, Postgres>,
    repository_id: RepositoryId,
    concurrency: &WorkflowConcurrency,
) -> Result<i64, WorkflowAdmissionStoreError> {
    sqlx::query_scalar(
        r"
        SELECT count(*)
        FROM concurrency_group_pending_runs
        WHERE repository_id = $1 AND normalized_key = $2
        ",
    )
    .bind(repository_id.as_uuid())
    .bind(concurrency.normalized_key())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn discard_terminal_slot(
    transaction: &mut Transaction<'_, Postgres>,
    run_id: Option<Uuid>,
) -> Result<Option<Uuid>, WorkflowAdmissionStoreError> {
    let Some(run_id) = run_id else {
        return Ok(None);
    };
    let status: String = sqlx::query_scalar("SELECT status FROM workflow_runs WHERE id = $1")
        .bind(run_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(operation_error)?;
    Ok(matches!(status.as_str(), "queued" | "in_progress").then_some(run_id))
}

#[derive(Debug)]
struct PreemptedAttempt {
    attempt_id: AttemptId,
    lifecycle: String,
    changed_at: UnixMillis,
    has_cancellation: bool,
    lease_id: Option<LeaseId>,
    fencing_token: Option<FencingToken>,
    session: Option<RunnerSessionFence>,
    protocol_version: Option<RunnerProtocolVersion>,
}

async fn cancel_run(
    transaction: &mut Transaction<'_, Postgres>,
    encryption: Option<&RunnerPayloadEncryption>,
    run_id: Uuid,
    preempting_run_id: RunId,
    observed_at: UnixMillis,
) -> Result<(), WorkflowAdmissionStoreError> {
    let status: String = sqlx::query_scalar(
        r"
        SELECT status
        FROM workflow_runs
        WHERE id = $1
        FOR UPDATE
        ",
    )
    .bind(run_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    match status.as_str() {
        "queued" | "in_progress" => {}
        "completed" | "cancelled" => return Ok(()),
        _ => {
            return Err(StoreError::corrupt_data(
                "workflow run has an invalid cancellation status",
            )
            .into());
        }
    }

    // Keep this as a distinct READ COMMITTED statement after acquiring the
    // run lock. A materializer that owned a compatible run lock first may
    // have committed a new attempt while this transaction waited.
    let rows = sqlx::query(
        r"
        SELECT attempt.id, attempt.lifecycle, attempt.changed_at_ms,
               attempt.lease_id, attempt.fencing_token, attempt.runner_id,
               attempt.runner_session_id, attempt.runner_generation,
               attempt.runner_session_epoch, session.protocol_version,
               EXISTS (
                   SELECT 1 FROM attempt_cancellation_intents AS cancellation
                   WHERE cancellation.attempt_id = attempt.id
               ) AS has_cancellation
        FROM job_attempts AS attempt
        JOIN jobs AS job ON job.id = attempt.job_id
        LEFT JOIN runner_sessions AS session
          ON session.id = attempt.runner_session_id
         AND session.runner_id = attempt.runner_id
         AND session.runner_generation = attempt.runner_generation
         AND session.session_epoch = attempt.runner_session_epoch
        WHERE job.run_id = $1
          AND attempt.lifecycle IN (
              'queued','leased','preparing','running','cancelling','finalizing'
          )
        ORDER BY attempt.runner_id NULLS LAST,
                 attempt.runner_session_id NULLS LAST, attempt.id
        ",
    )
    .bind(run_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let attempts = rows
        .iter()
        .map(decode_preempted_attempt)
        .collect::<Result<Vec<_>, _>>()?;
    for attempt in attempts {
        cancel_attempt(
            transaction,
            encryption,
            preempting_run_id,
            observed_at,
            attempt,
        )
        .await?;
    }
    let updated = sqlx::query(
        r"
        UPDATE workflow_runs
        SET status = 'cancelled', updated_at_ms = greatest(updated_at_ms, $2)
        WHERE id = $1 AND status IN ('queued','in_progress')
        ",
    )
    .bind(run_id)
    .bind(observed_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if updated != 1 {
        return Err(StoreError::corrupt_data(
            "locked active workflow run disappeared during cancellation",
        )
        .into());
    }
    Ok(())
}

async fn cancel_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    encryption: Option<&RunnerPayloadEncryption>,
    preempting_run_id: RunId,
    observed_at: UnixMillis,
    attempt: PreemptedAttempt,
) -> Result<(), WorkflowAdmissionStoreError> {
    let requested_at = UnixMillis::new(observed_at.get().max(attempt.changed_at.get()));
    if attempt.has_cancellation {
        if attempt.lifecycle == "queued" {
            return Err(StoreError::corrupt_data(
                "queued attempt has cancellation intent without terminal authority",
            )
            .into());
        }
        return ensure_cancelled_lifecycle(transaction, &attempt, requested_at).await;
    }
    let (request, delivery) = prepare_preemption_cancellation(
        transaction,
        encryption,
        preempting_run_id,
        requested_at,
        &attempt,
    )
    .await?;
    insert_preemption_intent(transaction, &request, delivery.as_ref()).await?;
    if attempt.lifecycle == "queued" {
        super::server_cancellation_terminal::insert_queued_server_cancellation_terminal(
            transaction,
            &request,
        )
        .await?;
    }
    ensure_cancelled_lifecycle(transaction, &attempt, requested_at).await
}

async fn insert_preemption_intent(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RequestCancellation,
    delivery: Option<&crate::DurableRunnerCommand>,
) -> Result<(), WorkflowAdmissionStoreError> {
    let inserted = sqlx::query(
        r"
        INSERT INTO attempt_cancellation_intents (
            attempt_id, operation_id, requested_by, reason, requested_at_ms,
            delivery_session_id, delivery_command_sequence
        ) VALUES ($1,$2,$3,$4,$5,$6,$7)
        ON CONFLICT (attempt_id) DO NOTHING
        ",
    )
    .bind(request.attempt_id().as_uuid())
    .bind(request.operation_id().as_uuid())
    .bind(request.actor().as_str())
    .bind(request.reason().map(CancellationReason::as_str))
    .bind(request.requested_at().get())
    .bind(delivery.map(|delivery| delivery.request().session().session_id().as_uuid()))
    .bind(
        delivery
            .map(|delivery| i64::try_from(delivery.sequence().get()))
            .transpose()
            .map_err(|_| StoreError::corrupt_data("cancellation sequence exceeds BIGINT"))?,
    )
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if inserted != 1 {
        return Err(StoreError::corrupt_data(
            "preempted attempt acquired an unexpected cancellation intent",
        )
        .into());
    }
    Ok(())
}

async fn prepare_preemption_cancellation(
    transaction: &mut Transaction<'_, Postgres>,
    encryption: Option<&RunnerPayloadEncryption>,
    preempting_run_id: RunId,
    requested_at: UnixMillis,
    attempt: &PreemptedAttempt,
) -> Result<(RequestCancellation, Option<crate::DurableRunnerCommand>), WorkflowAdmissionStoreError>
{
    let actor = CancellationActor::new(CONCURRENCY_CANCELLATION_ACTOR)
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let reason = CancellationReason::new(CONCURRENCY_CANCELLATION_REASON)
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let request = RequestCancellation::new(
        stable_cancellation_operation_id(
            CANCELLATION_INTENT_ID_DOMAIN,
            preempting_run_id,
            attempt.attempt_id,
        ),
        attempt.attempt_id,
        actor,
        Some(reason.clone()),
        requested_at,
    );
    if attempt.lifecycle == "queued" {
        return Ok((request, None));
    }
    let delivery = build_preemption_delivery(preempting_run_id, requested_at, attempt, &reason)?;
    let encryption = encryption.ok_or(StoreError::RunnerPayloadEncryptionUnavailable)?;
    let durable = super::g1::enqueue_cancellation_command_in_transaction(
        transaction,
        encryption,
        delivery.clone(),
    )
    .await?;
    Ok((request.with_delivery(delivery), Some(durable)))
}

fn build_preemption_delivery(
    preempting_run_id: RunId,
    requested_at: UnixMillis,
    attempt: &PreemptedAttempt,
    reason: &CancellationReason,
) -> Result<EnqueueRunnerCommand, WorkflowAdmissionStoreError> {
    let session = attempt.session.ok_or_else(|| {
        StoreError::corrupt_data("active preempted attempt lacks a complete session fence")
    })?;
    let guard = LeaseGuard::new(
        attempt
            .lease_id
            .ok_or_else(|| StoreError::corrupt_data("active preempted attempt lacks a lease ID"))?,
        attempt.fencing_token.ok_or_else(|| {
            StoreError::corrupt_data("active preempted attempt lacks a fencing token")
        })?,
    );
    let protocol_version = attempt.protocol_version.ok_or_else(|| {
        StoreError::corrupt_data("active preempted attempt lacks a durable protocol version")
    })?;
    let encoded = CancelJobCommandPayload::new(
        attempt.attempt_id,
        guard,
        protocol_version,
        reason.as_str(),
        requested_at,
    )
    .and_then(|payload| payload.encode_json())
    .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let payload = RunnerCommandPayload::new(
        DocumentSchema::new(CANCEL_JOB_COMMAND_SCHEMA)
            .map_err(|error| StoreError::corrupt_data(error.to_string()))?,
        encoded,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let kind = RunnerOperationKind::new(CANCEL_JOB_COMMAND_KIND)
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    Ok(EnqueueRunnerCommand::new(
        session,
        stable_cancellation_operation_id(
            CANCELLATION_COMMAND_ID_DOMAIN,
            preempting_run_id,
            attempt.attempt_id,
        ),
        kind,
        payload,
        requested_at,
    ))
}

async fn ensure_cancelled_lifecycle(
    transaction: &mut Transaction<'_, Postgres>,
    attempt: &PreemptedAttempt,
    requested_at: UnixMillis,
) -> Result<(), WorkflowAdmissionStoreError> {
    let next = if attempt.lifecycle == "queued" {
        "cancelled"
    } else {
        "cancelling"
    };
    let rows = sqlx::query(
        r"
        UPDATE job_attempts
        SET lifecycle = $2, changed_at_ms = greatest(changed_at_ms, $3)
        WHERE id = $1
          AND lifecycle IN (
              'queued','leased','preparing','running','cancelling','finalizing'
          )
        ",
    )
    .bind(attempt.attempt_id.as_uuid())
    .bind(next)
    .bind(requested_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if rows != 1 {
        return Err(StoreError::corrupt_data(
            "preempted attempt changed outside the concurrency lock",
        )
        .into());
    }
    Ok(())
}

fn decode_preempted_attempt(
    row: &sqlx::postgres::PgRow,
) -> Result<PreemptedAttempt, WorkflowAdmissionStoreError> {
    let attempt_id = AttemptId::from_uuid(row.try_get("id").map_err(operation_error)?);
    let lease_id = row
        .try_get::<Option<Uuid>, _>("lease_id")
        .map_err(operation_error)?
        .map(LeaseId::from_uuid);
    let fencing_token = row
        .try_get::<i64, _>("fencing_token")
        .map_err(operation_error)?;
    let fencing_token = if fencing_token == 0 {
        None
    } else {
        Some(
            u64::try_from(fencing_token)
                .ok()
                .and_then(|value| FencingToken::new(value).ok())
                .ok_or_else(|| StoreError::corrupt_data("invalid cancellation fencing token"))?,
        )
    };
    let runner_id = row
        .try_get::<Option<Uuid>, _>("runner_id")
        .map_err(operation_error)?;
    let session_id = row
        .try_get::<Option<Uuid>, _>("runner_session_id")
        .map_err(operation_error)?;
    let generation = row
        .try_get::<Option<i64>, _>("runner_generation")
        .map_err(operation_error)?;
    let epoch = row
        .try_get::<Option<i64>, _>("runner_session_epoch")
        .map_err(operation_error)?;
    let session = match (runner_id, session_id, generation, epoch) {
        (None, None, None, None) => None,
        (Some(runner_id), Some(session_id), Some(generation), Some(epoch)) => {
            Some(RunnerSessionFence::new(
                RunnerSessionId::from_uuid(session_id),
                RunnerId::from_uuid(runner_id),
                RunnerGeneration::new(
                    u64::try_from(generation)
                        .map_err(|_| StoreError::corrupt_data("negative runner generation"))?,
                )
                .map_err(|error| StoreError::corrupt_data(error.to_string()))?,
                SessionEpoch::new(
                    u64::try_from(epoch)
                        .map_err(|_| StoreError::corrupt_data("negative session epoch"))?,
                )
                .map_err(|error| StoreError::corrupt_data(error.to_string()))?,
            ))
        }
        _ => {
            return Err(StoreError::corrupt_data(
                "preempted attempt has a partial runner session fence",
            )
            .into());
        }
    };
    let protocol_version = row
        .try_get::<Option<i32>, _>("protocol_version")
        .map_err(operation_error)?
        .map(|version| {
            u16::try_from(version)
                .ok()
                .and_then(|value| RunnerProtocolVersion::new(value).ok())
                .ok_or_else(|| StoreError::corrupt_data("invalid cancellation protocol version"))
        })
        .transpose()?;
    Ok(PreemptedAttempt {
        attempt_id,
        lifecycle: row.try_get("lifecycle").map_err(operation_error)?,
        changed_at: UnixMillis::new(row.try_get("changed_at_ms").map_err(operation_error)?),
        has_cancellation: row.try_get("has_cancellation").map_err(operation_error)?,
        lease_id,
        fencing_token,
        session,
        protocol_version,
    })
}

fn stable_cancellation_operation_id(
    domain: &[u8],
    preempting_run_id: RunId,
    attempt_id: AttemptId,
) -> OperationId {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update([0]);
    digest.update(preempting_run_id.as_uuid().as_bytes());
    digest.update(attempt_id.as_uuid().as_bytes());
    let output: [u8; 32] = digest.finalize().into();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&output[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    OperationId::from_uuid(Uuid::from_bytes(bytes))
}

async fn finalize_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitWorkflowRun,
) -> Result<(), WorkflowAdmissionStoreError> {
    let rows = sqlx::query(
        r"
        UPDATE workflow_admission_receipts
        SET repository_id = $4, run_id = $5, committed_at_ms = $6
        WHERE tenant_id = $1 AND idempotency_kind = $2 AND idempotency_key = $3
          AND request_digest = $7 AND run_id IS NULL
        ",
    )
    .bind(command.tenant().as_str())
    .bind(command.idempotency().kind())
    .bind(command.idempotency().key())
    .bind(command.repository().id().as_uuid())
    .bind(command.run_id().as_uuid())
    .bind(command.admitted_at().get())
    .bind(command.request_digest().as_bytes().as_slice())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if rows != 1 {
        return Err(
            StoreError::corrupt_data("admission receipt finalization lost ownership").into(),
        );
    }
    Ok(())
}

fn size_i64(object: &AdmissionObject) -> Result<i64, WorkflowAdmissionStoreError> {
    i64::try_from(object.encoded_size()).map_err(|_| {
        StoreError::corrupt_data("immutable object size exceeds PostgreSQL BIGINT").into()
    })
}

fn operation_error(error: sqlx::Error) -> WorkflowAdmissionStoreError {
    StoreError::operation(error).into()
}

#[async_trait]
impl RunReconciliationRepository for PostgresStore {
    async fn reconcile_run(
        &self,
        run_id: RunId,
        observed_at: UnixMillis,
    ) -> Result<RunReconciliation, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(StoreError::operation)?;
        let result = reconcile_run_in_transaction(&mut transaction, run_id, observed_at).await?;
        transaction.commit().await.map_err(StoreError::operation)?;
        Ok(result)
    }
}

/// Acquires the repository/concurrency serialization lock before an attempt is
/// locked, preventing inversion with run admission and slot promotion.
pub(super) async fn lock_attempt_concurrency(
    transaction: &mut Transaction<'_, Postgres>,
    attempt_id: AttemptId,
) -> Result<(), StoreError> {
    let row = sqlx::query(
        r"
        SELECT run.repository_id, run.concurrency_group_key
        FROM job_attempts AS attempt
        JOIN jobs AS job ON job.id = attempt.job_id
        JOIN workflow_runs AS run ON run.id = job.run_id
        WHERE attempt.id = $1
        ",
    )
    .bind(attempt_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(StoreError::operation)?;
    if let Some(row) = row {
        let repository_id: Uuid = row
            .try_get("repository_id")
            .map_err(StoreError::operation)?;
        let key: Option<String> = row
            .try_get("concurrency_group_key")
            .map_err(StoreError::operation)?;
        if let Some(key) = key {
            lock_concurrency_advisory(transaction, repository_id, &key).await?;
        }
    }
    Ok(())
}

/// Acquires one run's repository concurrency lock before any run-owned row.
pub(super) async fn lock_run_concurrency(
    transaction: &mut Transaction<'_, Postgres>,
    run_id: RunId,
) -> Result<(Uuid, Option<String>), StoreError> {
    let row = sqlx::query(
        r"
        SELECT repository_id, concurrency_group_key
        FROM workflow_runs
        WHERE id = $1
        ",
    )
    .bind(run_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(StoreError::operation)?
    .ok_or(StoreError::RunNotFound(run_id))?;
    let repository_id: Uuid = row
        .try_get("repository_id")
        .map_err(StoreError::operation)?;
    let key: Option<String> = row
        .try_get("concurrency_group_key")
        .map_err(StoreError::operation)?;
    if let Some(key) = key.as_deref() {
        lock_concurrency_advisory(transaction, repository_id, key).await?;
    }
    Ok((repository_id, key))
}

pub(super) async fn reconcile_attempt_run(
    transaction: &mut Transaction<'_, Postgres>,
    attempt_id: AttemptId,
    observed_at: UnixMillis,
) -> Result<RunReconciliation, StoreError> {
    let run_id = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT job.run_id
        FROM job_attempts AS attempt
        JOIN jobs AS job ON job.id = attempt.job_id
        WHERE attempt.id = $1
        ",
    )
    .bind(attempt_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(StoreError::operation)?
    .ok_or(StoreError::AttemptNotFound(attempt_id))?;
    reconcile_run_in_transaction(transaction, RunId::from_uuid(run_id), observed_at).await
}

pub(super) async fn reconcile_run_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    run_id: RunId,
    observed_at: UnixMillis,
) -> Result<RunReconciliation, StoreError> {
    let identity = sqlx::query(
        r"
        SELECT run.repository_id, run.concurrency_group_key,
               marker.state AS logical_orchestration_state
        FROM workflow_runs AS run
        LEFT JOIN workflow_plan_v2_runs AS marker ON marker.run_id = run.id
        WHERE run.id = $1
        ",
    )
    .bind(run_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(StoreError::operation)?
    .ok_or(StoreError::RunNotFound(run_id))?;
    let repository_id: Uuid = identity
        .try_get("repository_id")
        .map_err(StoreError::operation)?;
    let concurrency_key: Option<String> = identity
        .try_get("concurrency_group_key")
        .map_err(StoreError::operation)?;
    let logical_orchestration_state: Option<String> = identity
        .try_get("logical_orchestration_state")
        .map_err(StoreError::operation)?;
    let logical_orchestration_finalized =
        decode_logical_orchestration_finalization(logical_orchestration_state.as_deref())?;
    if let Some(key) = concurrency_key.as_deref() {
        lock_concurrency_advisory(transaction, repository_id, key).await?;
    }

    let run =
        sqlx::query("SELECT status, updated_at_ms FROM workflow_runs WHERE id = $1 FOR UPDATE")
            .bind(run_id.as_uuid())
            .fetch_one(&mut **transaction)
            .await
            .map_err(StoreError::operation)?;
    let current = parse_run_status(run.try_get("status").map_err(StoreError::operation)?)?;
    let updated_at = UnixMillis::new(
        run.try_get("updated_at_ms")
            .map_err(StoreError::operation)?,
    );
    if observed_at < updated_at {
        return Err(StoreError::RunTimeRegression {
            run_id,
            observed_at,
            updated_at,
        });
    }
    let (job_count, durable_all_terminal, any_started) =
        latest_attempt_aggregate(transaction, run_id).await?;
    if job_count == 0 && logical_orchestration_finalized.is_none() {
        return Err(StoreError::corrupt_data("workflow run has no durable jobs"));
    }
    let all_terminal = match logical_orchestration_finalized {
        Some(true) if job_count == 0 => true,
        Some(true) | None => durable_all_terminal,
        Some(false) => false,
    };
    let desired = match current {
        WorkflowRunStatus::Cancelled => WorkflowRunStatus::Cancelled,
        WorkflowRunStatus::Completed if !all_terminal => {
            return Err(StoreError::corrupt_data(
                "completed workflow run lacks terminal execution and orchestration state",
            ));
        }
        WorkflowRunStatus::Completed => WorkflowRunStatus::Completed,
        WorkflowRunStatus::Queued | WorkflowRunStatus::InProgress if all_terminal => {
            WorkflowRunStatus::Completed
        }
        WorkflowRunStatus::Queued if any_started => WorkflowRunStatus::InProgress,
        WorkflowRunStatus::Queued | WorkflowRunStatus::InProgress => current,
    };
    if desired != current {
        sqlx::query("UPDATE workflow_runs SET status = $2, updated_at_ms = $3 WHERE id = $1")
            .bind(run_id.as_uuid())
            .bind(run_status_name(desired))
            .bind(observed_at.get())
            .execute(&mut **transaction)
            .await
            .map_err(StoreError::operation)?;
    }
    let promoted = if matches!(
        desired,
        WorkflowRunStatus::Completed | WorkflowRunStatus::Cancelled
    ) {
        reconcile_terminal_concurrency(
            transaction,
            repository_id,
            concurrency_key.as_deref(),
            run_id,
            observed_at,
        )
        .await?
    } else {
        None
    };
    Ok(RunReconciliation::new(run_id, desired, promoted))
}

fn decode_logical_orchestration_finalization(
    state: Option<&str>,
) -> Result<Option<bool>, StoreError> {
    match state {
        None => Ok(None),
        Some("completed" | "failed") => Ok(Some(true)),
        Some("pending" | "active" | "cancelled") => Ok(Some(false)),
        Some(_) => Err(StoreError::corrupt_data(
            "workflow run has an invalid logical orchestration state",
        )),
    }
}

async fn latest_attempt_aggregate(
    transaction: &mut Transaction<'_, Postgres>,
    run_id: RunId,
) -> Result<(i64, bool, bool), StoreError> {
    let row = sqlx::query(
        r"
        SELECT count(*) AS job_count,
               coalesce(bool_and(coalesce(latest.lifecycle IN (
                   'succeeded','failed','cancelled','timed_out','skipped','lost'
               ), false)), false) AS all_terminal,
               coalesce(bool_or(coalesce(latest.lifecycle <> 'queued', false)), false)
                   AS any_started
        FROM jobs AS job
        LEFT JOIN LATERAL (
            SELECT attempt.lifecycle
            FROM job_attempts AS attempt
            WHERE attempt.job_id = job.id
            ORDER BY attempt.attempt_number DESC
            LIMIT 1
        ) AS latest ON TRUE
        WHERE job.run_id = $1
        ",
    )
    .bind(run_id.as_uuid())
    .fetch_one(&mut **transaction)
    .await
    .map_err(StoreError::operation)?;
    Ok((
        row.try_get("job_count").map_err(StoreError::operation)?,
        row.try_get("all_terminal").map_err(StoreError::operation)?,
        row.try_get("any_started").map_err(StoreError::operation)?,
    ))
}

pub(super) async fn reconcile_terminal_concurrency(
    transaction: &mut Transaction<'_, Postgres>,
    repository_id: Uuid,
    concurrency_key: Option<&str>,
    run_id: RunId,
    observed_at: UnixMillis,
) -> Result<Option<RunId>, StoreError> {
    let Some(concurrency_key) = concurrency_key else {
        return Ok(None);
    };
    let row = sqlx::query(
        r"
        SELECT running_run_id
        FROM concurrency_groups
        WHERE repository_id = $1 AND normalized_key = $2
        FOR UPDATE
        ",
    )
    .bind(repository_id)
    .bind(concurrency_key)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(StoreError::operation)?
    .ok_or_else(|| StoreError::corrupt_data("run references a missing concurrency group"))?;
    let running: Option<Uuid> = row
        .try_get("running_run_id")
        .map_err(StoreError::operation)?;
    sqlx::query(
        r"
        DELETE FROM concurrency_group_pending_runs AS pending
        USING workflow_runs AS queued
        WHERE pending.repository_id = $1 AND pending.normalized_key = $2
          AND queued.id = pending.run_id
          AND queued.status NOT IN ('queued', 'in_progress')
        ",
    )
    .bind(repository_id)
    .bind(concurrency_key)
    .execute(&mut **transaction)
    .await
    .map_err(StoreError::operation)?;

    let pending_member: bool = sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1 FROM concurrency_group_pending_runs
            WHERE repository_id = $1 AND normalized_key = $2 AND run_id = $3
        )
        ",
    )
    .bind(repository_id)
    .bind(concurrency_key)
    .bind(run_id.as_uuid())
    .fetch_one(&mut **transaction)
    .await
    .map_err(StoreError::operation)?;
    if pending_member {
        sqlx::query(
            r"
            DELETE FROM concurrency_group_pending_runs
            WHERE repository_id = $1 AND normalized_key = $2 AND run_id = $3
            ",
        )
        .bind(repository_id)
        .bind(concurrency_key)
        .bind(run_id.as_uuid())
        .execute(&mut **transaction)
        .await
        .map_err(StoreError::operation)?;
    }
    if running != Some(run_id.as_uuid()) {
        if pending_member {
            let rows = sqlx::query(
                r"
                UPDATE concurrency_groups
                SET generation = generation + 1,
                    updated_at_ms = greatest(updated_at_ms, $3)
                WHERE repository_id = $1 AND normalized_key = $2
                  AND generation < 9223372036854775807
                ",
            )
            .bind(repository_id)
            .bind(concurrency_key)
            .bind(observed_at.get())
            .execute(&mut **transaction)
            .await
            .map_err(StoreError::operation)?
            .rows_affected();
            if rows != 1 {
                return Err(StoreError::corrupt_data(
                    "concurrency generation is exhausted",
                ));
            }
        }
        return Ok(None);
    }

    let promotable: Option<Uuid> = sqlx::query_scalar(
        r"
        SELECT pending.run_id
        FROM concurrency_group_pending_runs AS pending
        JOIN workflow_runs AS queued ON queued.id = pending.run_id
        WHERE pending.repository_id = $1 AND pending.normalized_key = $2
          AND queued.status IN ('queued', 'in_progress')
        ORDER BY pending.enqueued_at_ms, pending.run_id
        LIMIT 1
        FOR UPDATE OF pending, queued
        ",
    )
    .bind(repository_id)
    .bind(concurrency_key)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(StoreError::operation)?;
    if let Some(promoted) = promotable {
        sqlx::query(
            r"
            DELETE FROM concurrency_group_pending_runs
            WHERE repository_id = $1 AND normalized_key = $2 AND run_id = $3
            ",
        )
        .bind(repository_id)
        .bind(concurrency_key)
        .bind(promoted)
        .execute(&mut **transaction)
        .await
        .map_err(StoreError::operation)?;
    }
    let rows = sqlx::query(
        r"
        UPDATE concurrency_groups
        SET running_run_id = $3,
            generation = generation + 1,
            updated_at_ms = greatest(updated_at_ms, $4)
        WHERE repository_id = $1 AND normalized_key = $2
          AND generation < 9223372036854775807
        ",
    )
    .bind(repository_id)
    .bind(concurrency_key)
    .bind(promotable)
    .bind(observed_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(StoreError::operation)?
    .rows_affected();
    if rows != 1 {
        return Err(StoreError::corrupt_data(
            "concurrency generation is exhausted",
        ));
    }
    Ok(promotable.map(RunId::from_uuid))
}

async fn lock_concurrency_advisory(
    transaction: &mut Transaction<'_, Postgres>,
    repository_id: Uuid,
    normalized_key: &str,
) -> Result<(), StoreError> {
    let lock_identity = format!("{repository_id}:{normalized_key}");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 6840335614489014273))")
        .bind(lock_identity)
        .execute(&mut **transaction)
        .await
        .map_err(StoreError::operation)?;
    Ok(())
}

fn parse_run_status(value: &str) -> Result<WorkflowRunStatus, StoreError> {
    match value {
        "queued" => Ok(WorkflowRunStatus::Queued),
        "in_progress" => Ok(WorkflowRunStatus::InProgress),
        "completed" => Ok(WorkflowRunStatus::Completed),
        "cancelled" => Ok(WorkflowRunStatus::Cancelled),
        other => Err(StoreError::corrupt_data(format!(
            "unknown workflow run status {other:?}"
        ))),
    }
}

const fn run_status_name(status: WorkflowRunStatus) -> &'static str {
    match status {
        WorkflowRunStatus::Queued => "queued",
        WorkflowRunStatus::InProgress => "in_progress",
        WorkflowRunStatus::Completed => "completed",
        WorkflowRunStatus::Cancelled => "cancelled",
    }
}
