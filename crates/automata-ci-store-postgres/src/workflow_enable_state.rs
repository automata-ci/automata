use async_trait::async_trait;
use automata_ci_core::{UnixMillis, WorkflowId};
use sqlx::{Row as _, postgres::PgRow};

use automata_ci_store::{
    RepositoryId, SetWorkflowEnableState, TenantScope, WorkflowEnableState,
    WorkflowEnableStateReceipt, WorkflowEnableStateRecord, WorkflowEnableStateRepository,
    WorkflowEnableStateRevision, WorkflowEnableStateStoreError,
};

use super::{PostgresStore, pg_bigint};

#[async_trait]
impl WorkflowEnableStateRepository for PostgresStore {
    #[allow(clippy::too_many_lines)] // One fenced CAS transaction handles first write, replay, and successor.
    async fn set_workflow_enable_state(
        &self,
        request: SetWorkflowEnableState,
    ) -> Result<WorkflowEnableStateReceipt, WorkflowEnableStateStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            .execute(&mut *transaction)
            .await
            .map_err(operation_error)?;
        let current = load_current_for_update(&mut transaction, request.next()).await?;

        if let Some(durable) = current {
            if durable == *request.next() {
                transaction.commit().await.map_err(operation_error)?;
                return Ok(
                    automata_ci_store::adapter_spi::workflow_enable_state_receipt(durable, true),
                );
            }
            if request.expected_current_revision() != Some(durable.revision())
                || durable.tenant() != request.next().tenant()
                || durable.repository_id() != request.next().repository_id()
                || durable.workflow_id() != request.next().workflow_id()
                || durable.workflow_path() != request.next().workflow_path()
                || durable.state() == request.next().state()
            {
                return Err(WorkflowEnableStateStoreError::Conflict);
            }
        } else if request.expected_current_revision().is_some()
            || request.next().revision().get() != 1
        {
            return Err(WorkflowEnableStateStoreError::Conflict);
        }

        let inserted = sqlx::query(
            r"
            INSERT INTO workflow_enable_state_revisions (
                tenant_id, repository_id, workflow_id, workflow_path,
                state_revision, enable_state, changed_at_ms
            )
            SELECT $1,$2,$3,$4,$5,$6,$7
            FROM workflow_definitions AS workflow
            JOIN repositories AS repository
              ON repository.id = workflow.repository_id
             AND repository.tenant_id = $1
            WHERE workflow.repository_id = $2
              AND workflow.id = $3
              AND workflow.path = $4
            ON CONFLICT DO NOTHING
            ",
        )
        .bind(request.next().tenant().as_str())
        .bind(request.next().repository_id().as_uuid())
        .bind(request.next().workflow_id().as_uuid())
        .bind(request.next().workflow_path())
        .bind(pg_bigint(request.next().revision().get()))
        .bind(request.next().state().as_durable_str())
        .bind(request.next().changed_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if inserted.rows_affected() != 1 {
            if load_current_for_update(&mut transaction, request.next())
                .await?
                .as_ref()
                == Some(request.next())
            {
                transaction.commit().await.map_err(operation_error)?;
                return Ok(
                    automata_ci_store::adapter_spi::workflow_enable_state_receipt(
                        request.next().clone(),
                        true,
                    ),
                );
            }
            return Err(WorkflowEnableStateStoreError::Conflict);
        }

        let selected = match request.expected_current_revision() {
            Some(expected) => sqlx::query(
                r"
                    UPDATE workflow_enable_state_current
                    SET state_revision = $4
                    WHERE tenant_id = $1 AND repository_id = $2
                      AND workflow_id = $3 AND state_revision = $5
                    ",
            )
            .bind(request.next().tenant().as_str())
            .bind(request.next().repository_id().as_uuid())
            .bind(request.next().workflow_id().as_uuid())
            .bind(pg_bigint(request.next().revision().get()))
            .bind(pg_bigint(expected.get()))
            .execute(&mut *transaction)
            .await
            .map_err(operation_error)?,
            None => sqlx::query(
                r"
                    INSERT INTO workflow_enable_state_current (
                        tenant_id, repository_id, workflow_id, state_revision
                    ) VALUES ($1,$2,$3,$4)
                    ON CONFLICT DO NOTHING
                    ",
            )
            .bind(request.next().tenant().as_str())
            .bind(request.next().repository_id().as_uuid())
            .bind(request.next().workflow_id().as_uuid())
            .bind(pg_bigint(request.next().revision().get()))
            .execute(&mut *transaction)
            .await
            .map_err(operation_error)?,
        };
        if selected.rows_affected() != 1 {
            return Err(WorkflowEnableStateStoreError::Conflict);
        }
        let projected = sqlx::query(
            r"
            UPDATE workflow_definitions
               SET enabled = $4,
                   updated_at_ms = $5
             WHERE repository_id = $1
               AND id = $2
               AND path = $3
            ",
        )
        .bind(request.next().repository_id().as_uuid())
        .bind(request.next().workflow_id().as_uuid())
        .bind(request.next().workflow_path())
        .bind(matches!(
            request.next().state(),
            WorkflowEnableState::Enabled
        ))
        .bind(request.next().changed_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if projected.rows_affected() != 1 {
            return Err(WorkflowEnableStateStoreError::Conflict);
        }
        transaction.commit().await.map_err(operation_error)?;
        Ok(
            automata_ci_store::adapter_spi::workflow_enable_state_receipt(
                request.next().clone(),
                false,
            ),
        )
    }

    async fn load_workflow_enable_state(
        &self,
        tenant: &TenantScope,
        repository_id: RepositoryId,
        workflow_id: WorkflowId,
    ) -> Result<WorkflowEnableStateRecord, WorkflowEnableStateStoreError> {
        let row = sqlx::query(
            r"
            SELECT revision.tenant_id, revision.repository_id,
                   revision.workflow_id, revision.workflow_path,
                   revision.state_revision, revision.enable_state,
                   revision.changed_at_ms
            FROM workflow_enable_state_current AS current
            JOIN workflow_enable_state_revisions AS revision
              ON revision.tenant_id = current.tenant_id
             AND revision.repository_id = current.repository_id
             AND revision.workflow_id = current.workflow_id
             AND revision.state_revision = current.state_revision
            WHERE current.tenant_id = $1
              AND current.repository_id = $2
              AND current.workflow_id = $3
            ",
        )
        .bind(tenant.as_str())
        .bind(repository_id.as_uuid())
        .bind(workflow_id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(operation_error)?
        .ok_or(WorkflowEnableStateStoreError::NotFound)?;
        decode_record(&row)
    }
}

async fn load_current_for_update(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    expected: &WorkflowEnableStateRecord,
) -> Result<Option<WorkflowEnableStateRecord>, WorkflowEnableStateStoreError> {
    let row = sqlx::query(
        r"
        SELECT revision.tenant_id, revision.repository_id,
               revision.workflow_id, revision.workflow_path,
               revision.state_revision, revision.enable_state,
               revision.changed_at_ms
        FROM workflow_enable_state_current AS current
        JOIN workflow_enable_state_revisions AS revision
          ON revision.tenant_id = current.tenant_id
         AND revision.repository_id = current.repository_id
         AND revision.workflow_id = current.workflow_id
         AND revision.state_revision = current.state_revision
        WHERE current.tenant_id = $1
          AND current.repository_id = $2
          AND current.workflow_id = $3
        FOR UPDATE OF current
        ",
    )
    .bind(expected.tenant().as_str())
    .bind(expected.repository_id().as_uuid())
    .bind(expected.workflow_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    row.as_ref().map(decode_record).transpose()
}

fn decode_record(row: &PgRow) -> Result<WorkflowEnableStateRecord, WorkflowEnableStateStoreError> {
    let tenant = TenantScope::from_authenticated_tenant_id(
        row.try_get::<String, _>("tenant_id")
            .map_err(operation_error)?,
    )
    .map_err(|_| WorkflowEnableStateStoreError::CorruptData)?;
    let repository_id =
        RepositoryId::from_uuid(row.try_get("repository_id").map_err(operation_error)?);
    let workflow_id = WorkflowId::from_uuid(row.try_get("workflow_id").map_err(operation_error)?);
    let revision = u64::try_from(
        row.try_get::<i64, _>("state_revision")
            .map_err(operation_error)?,
    )
    .ok()
    .and_then(|value| WorkflowEnableStateRevision::new(value).ok())
    .ok_or(WorkflowEnableStateStoreError::CorruptData)?;
    let state = match row
        .try_get::<String, _>("enable_state")
        .map_err(operation_error)?
        .as_str()
    {
        "enabled" => WorkflowEnableState::Enabled,
        "disabled" => WorkflowEnableState::Disabled,
        _ => return Err(WorkflowEnableStateStoreError::CorruptData),
    };
    WorkflowEnableStateRecord::new(
        tenant,
        repository_id,
        workflow_id,
        row.try_get::<String, _>("workflow_path")
            .map_err(operation_error)?,
        revision,
        state,
        UnixMillis::new(row.try_get("changed_at_ms").map_err(operation_error)?),
    )
    .map_err(|_| WorkflowEnableStateStoreError::CorruptData)
}

fn operation_error(error: sqlx::Error) -> WorkflowEnableStateStoreError {
    WorkflowEnableStateStoreError::Operation(
        automata_ci_store::RepositoryOperationError::from_source(error),
    )
}
