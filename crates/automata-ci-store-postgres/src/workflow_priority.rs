use async_trait::async_trait;
use automata_ci_auth::authorization::repository_mutation_permissions;
use automata_ci_store::{
    StoreError, UpdateWorkflowRunPriority, UpdateWorkflowRunPriorityOutcome,
    WorkflowPriorityRepository, WorkflowPriorityRepositoryError, WorkflowRunPriority,
};
use sqlx::Row as _;
use uuid::Uuid;

use super::{PostgresStore, secret_management::authorize_human_repository_action};

const AUDIT_ACTION: &str = "workflow-run.priority.update";
const AUDIT_RESOURCE_KIND: &str = "workflow-run";

#[async_trait]
impl WorkflowPriorityRepository for PostgresStore {
    async fn update_workflow_run_priority(
        &self,
        request: UpdateWorkflowRunPriority,
    ) -> Result<UpdateWorkflowRunPriorityOutcome, WorkflowPriorityRepositoryError> {
        if request.priority().is_merge_queue() {
            return Err(WorkflowPriorityRepositoryError::InvalidRequest);
        }
        let mut transaction = self.pool.begin().await.map_err(sql_error)?;
        let actor = authorize_human_repository_action(
            &mut transaction,
            request.actor(),
            repository_mutation_permissions::RUN_PRIORITY_UPDATE,
            request.repository_id().as_uuid(),
        )
        .await
        .map_err(|error| store_error(&error))?;
        let Some(actor) = actor else {
            transaction.commit().await.map_err(sql_error)?;
            return Ok(UpdateWorkflowRunPriorityOutcome::AuthorityRejected);
        };
        if actor.tenant_id != request.actor().tenant_id().as_str()
            || actor.principal_id.hyphenated().to_string()
                != request.actor().principal_id().as_str()
            || actor.session_id.hyphenated().to_string() != request.actor().session_id().as_str()
        {
            return Err(WorkflowPriorityRepositoryError::CorruptData);
        }

        let row = sqlx::query(
            r"
            SELECT run.status, run.scheduling_priority
            FROM repositories AS repository
            JOIN workflow_runs AS run ON run.repository_id = repository.id
            WHERE repository.tenant_id = $1
              AND repository.id = $2
              AND run.id = $3
            FOR UPDATE OF run
            ",
        )
        .bind(&actor.tenant_id)
        .bind(request.repository_id().as_uuid())
        .bind(request.run_id().as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(sql_error)?;
        let Some(row) = row else {
            transaction.commit().await.map_err(sql_error)?;
            return Ok(UpdateWorkflowRunPriorityOutcome::NotFound);
        };
        let status: String = row.try_get("status").map_err(sql_error)?;
        let current = WorkflowRunPriority::from_storage(
            row.try_get("scheduling_priority").map_err(sql_error)?,
        )
        .ok_or(WorkflowPriorityRepositoryError::CorruptData)?;
        let outcome = if current.is_merge_queue() {
            UpdateWorkflowRunPriorityOutcome::MergeQueueManaged
        } else if !matches!(status.as_str(), "queued" | "in_progress") {
            UpdateWorkflowRunPriorityOutcome::RunNotQueued
        } else if current == request.priority() {
            UpdateWorkflowRunPriorityOutcome::Applied(current)
        } else {
            persist_priority_change(&mut transaction, &request, current, &actor.tenant_id).await?;
            UpdateWorkflowRunPriorityOutcome::Applied(request.priority())
        };
        append_audit(
            &mut transaction,
            &actor,
            request.run_id().as_uuid(),
            outcome,
        )
        .await?;
        transaction.commit().await.map_err(sql_error)?;
        Ok(outcome)
    }
}

async fn persist_priority_change(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request: &UpdateWorkflowRunPriority,
    current: WorkflowRunPriority,
    tenant_id: &str,
) -> Result<(), WorkflowPriorityRepositoryError> {
    sqlx::query(
        r"
        UPDATE workflow_runs
        SET scheduling_priority = $4
        WHERE repository_id = $1 AND id = $2
          AND scheduling_priority = $3
        ",
    )
    .bind(request.repository_id().as_uuid())
    .bind(request.run_id().as_uuid())
    .bind(current.storage_value())
    .bind(request.priority().storage_value())
    .execute(&mut **transaction)
    .await
    .map_err(sql_error)
    .and_then(|result| {
        if result.rows_affected() == 1 {
            Ok(())
        } else {
            Err(WorkflowPriorityRepositoryError::CorruptData)
        }
    })?;
    // A priority change can move an attempt before a runner's current keyset
    // position. Drop the tenant's durable scan cursors so the next poll starts
    // from the new ordering rather than skipping the explicitly reprioritized
    // work until a later cycle.
    sqlx::query(
        r"
        DELETE FROM runner_queue_cursors AS cursor
        USING runners AS runner
        WHERE cursor.runner_id = runner.id
          AND runner.tenant_id = $1
        ",
    )
    .bind(tenant_id)
    .execute(&mut **transaction)
    .await
    .map_err(sql_error)?;
    Ok(())
}

async fn append_audit(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor: &super::secret_management::AuthorizedHumanRepositoryAction,
    run_id: Uuid,
    outcome: UpdateWorkflowRunPriorityOutcome,
) -> Result<(), WorkflowPriorityRepositoryError> {
    let outcome = match outcome {
        UpdateWorkflowRunPriorityOutcome::Applied(_) => "succeeded",
        UpdateWorkflowRunPriorityOutcome::RunNotQueued
        | UpdateWorkflowRunPriorityOutcome::MergeQueueManaged => "failed",
        UpdateWorkflowRunPriorityOutcome::AuthorityRejected
        | UpdateWorkflowRunPriorityOutcome::NotFound => {
            return Err(WorkflowPriorityRepositoryError::CorruptData);
        }
    };
    sqlx::query(
        r"
        INSERT INTO security_audit_events (
            event_id, tenant_id, occurred_at_ms, actor_kind,
            actor_principal_id, actor_session_id, authorization_revision,
            action, outcome, resource_kind, resource_id, request_id
        ) VALUES (
            $1, $2,
            floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT,
            'human', $3, $4, $5, $6, $7, $8, $9, $10
        )
        ",
    )
    .bind(Uuid::new_v4())
    .bind(&actor.tenant_id)
    .bind(actor.principal_id)
    .bind(actor.session_id)
    .bind(actor.authorization_revision)
    .bind(AUDIT_ACTION)
    .bind(outcome)
    .bind(AUDIT_RESOURCE_KIND)
    .bind(run_id.hyphenated().to_string())
    .bind(actor.request_id.as_deref())
    .execute(&mut **transaction)
    .await
    .map_err(sql_error)?;
    Ok(())
}

fn store_error(error: &StoreError) -> WorkflowPriorityRepositoryError {
    match error {
        StoreError::Operation(_) => WorkflowPriorityRepositoryError::Unavailable,
        _ => WorkflowPriorityRepositoryError::CorruptData,
    }
}

fn sql_error(_: sqlx::Error) -> WorkflowPriorityRepositoryError {
    WorkflowPriorityRepositoryError::Unavailable
}
