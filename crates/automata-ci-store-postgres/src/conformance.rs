use async_trait::async_trait;
use automata_ci_core::{RunId, UnixMillis};
use sqlx::{PgPool, Postgres, Row as _, Transaction, postgres::PgRow};
use uuid::Uuid;

use automata_ci_store::{
    ConformanceDelivery, ConformanceDeliveryQuery, ConformanceDeliveryState,
    ConformanceReadRepository, ConformanceRepositoryQuery, ConformanceWorkflowResult,
    ProviderDeliveryId, RepositoryId, StoreError,
};

use super::PostgresStore;

#[async_trait]
impl ConformanceReadRepository for PostgresStore {
    async fn resolve_conformance_repository(
        &self,
        query: &ConformanceRepositoryQuery,
    ) -> Result<Option<RepositoryId>, StoreError> {
        resolve_repository(self.postgres_pool(), query).await
    }

    async fn get_conformance_delivery(
        &self,
        query: &ConformanceDeliveryQuery,
    ) -> Result<Option<ConformanceDelivery>, StoreError> {
        get_conformance_delivery(self, query).await
    }
}

async fn resolve_repository(
    pool: &PgPool,
    query: &ConformanceRepositoryQuery,
) -> Result<Option<RepositoryId>, StoreError> {
    let rows = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT id
        FROM repositories
        WHERE tenant_id = $1
          AND scm_provider = $2
          AND provider_repository_id = $3
        LIMIT 2
        ",
    )
    .bind(query.tenant().as_str())
    .bind(query.provider())
    .bind(query.external_repository_id())
    .fetch_all(pool)
    .await
    .map_err(StoreError::operation)?;
    match rows.as_slice() {
        [] => Ok(None),
        [id] if !id.is_nil() => Ok(Some(RepositoryId::from_uuid(*id))),
        [_] => Err(StoreError::corrupt_data(
            "conformance repository identity is nil",
        )),
        _ => Err(StoreError::corrupt_data(
            "provider repository coordinate is not unique",
        )),
    }
}

async fn get_conformance_delivery(
    store: &PostgresStore,
    query: &ConformanceDeliveryQuery,
) -> Result<Option<ConformanceDelivery>, StoreError> {
    let mut transaction = begin_read(store).await?;
    let row = sqlx::query(
        r"
        SELECT delivery.delivery_id, delivery.external_delivery_id,
               delivery.disposition, delivery.accepted_at_ms,
               invocation.state, invocation.attempts, invocation.completed_at_ms
        FROM provider_deliveries AS delivery
        JOIN provider_connection_revisions AS connection
          ON connection.connection_id = delivery.connection_id
         AND connection.revision = delivery.connection_revision
         AND connection.provider_instance_id = delivery.provider_instance_id
         AND connection.provider_revision = delivery.provider_revision
         AND connection.external_repository_id = delivery.repository_external_id
        JOIN provider_instance_revisions AS provider
          ON provider.instance_id = delivery.provider_instance_id
         AND provider.revision = delivery.provider_revision
         AND provider.provider_type = delivery.provider_type
         AND provider.configuration_digest = connection.provider_configuration_digest
         AND provider.capability_digest = connection.capability_digest
        JOIN repositories AS repository
          ON repository.id = $2
         AND repository.tenant_id = connection.workspace_id
         AND repository.scm_provider = provider.provider_type
         AND repository.provider_repository_id = connection.external_repository_id
        LEFT JOIN provider_processing_invocations AS invocation
          ON invocation.cause_delivery_id = delivery.delivery_id
        WHERE connection.workspace_id = $1
          AND provider.provider_type = $3
          AND connection.external_repository_id = $4
          AND delivery.external_delivery_id = $5
        ",
    )
    .bind(query.tenant().as_str())
    .bind(query.repository_id().as_uuid())
    .bind(query.provider())
    .bind(query.external_repository_id())
    .bind(query.delivery_id())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(StoreError::operation)?;
    let Some(row) = row else {
        transaction.commit().await.map_err(StoreError::operation)?;
        return Ok(None);
    };
    let header = decode_delivery_header(&row, query)?;
    let workflow_rows = sqlx::query(
        r"
        SELECT workflow_path, run_id
        FROM provider_workflow_admission_evidence
        WHERE delivery_id = $1
          AND tenant_id = $2
          AND repository_id = $3
        ORDER BY workflow_path, run_id
        ",
    )
    .bind(header.id.as_uuid())
    .bind(query.tenant().as_str())
    .bind(query.repository_id().as_uuid())
    .fetch_all(&mut *transaction)
    .await
    .map_err(StoreError::operation)?;
    transaction.commit().await.map_err(StoreError::operation)?;

    let workflows = decode_workflows(&workflow_rows)?;
    Ok(Some(automata_ci_store::adapter_spi::conformance_delivery(
        header.id,
        header.external_delivery_id,
        header.state,
        header.attempts,
        header.accepted_at,
        header.completed_at,
        workflows,
    )))
}

struct DeliveryHeader {
    id: ProviderDeliveryId,
    external_delivery_id: String,
    state: ConformanceDeliveryState,
    attempts: u16,
    accepted_at: UnixMillis,
    completed_at: Option<UnixMillis>,
}

fn decode_delivery_header(
    row: &PgRow,
    query: &ConformanceDeliveryQuery,
) -> Result<DeliveryHeader, StoreError> {
    let id =
        ProviderDeliveryId::from_uuid(row.try_get("delivery_id").map_err(StoreError::operation)?)
            .map_err(|_| StoreError::corrupt_data("provider delivery ID is nil"))?;
    let external_delivery_id: String = row
        .try_get("external_delivery_id")
        .map_err(StoreError::operation)?;
    if external_delivery_id != query.delivery_id() {
        return Err(StoreError::corrupt_data(
            "provider delivery lookup changed its external identity",
        ));
    }
    let disposition: String = row.try_get("disposition").map_err(StoreError::operation)?;
    let processing_state: Option<String> = row.try_get("state").map_err(StoreError::operation)?;
    let attempts = row
        .try_get::<Option<i16>, _>("attempts")
        .map_err(StoreError::operation)?
        .map(u16::try_from)
        .transpose()
        .map_err(|_| StoreError::corrupt_data("provider processing attempts are negative"))?;
    let completed_at = row
        .try_get::<Option<i64>, _>("completed_at_ms")
        .map_err(StoreError::operation)?
        .map(UnixMillis::new);
    let (state, attempts) = delivery_state(&disposition, processing_state.as_deref(), attempts)?;
    let accepted_at = UnixMillis::new(
        row.try_get("accepted_at_ms")
            .map_err(StoreError::operation)?,
    );
    validate_header(state, attempts, accepted_at, completed_at)?;
    Ok(DeliveryHeader {
        id,
        external_delivery_id,
        state,
        attempts,
        accepted_at,
        completed_at,
    })
}

fn delivery_state(
    disposition: &str,
    processing_state: Option<&str>,
    attempts: Option<u16>,
) -> Result<(ConformanceDeliveryState, u16), StoreError> {
    match (disposition, processing_state, attempts) {
        ("rejected", None, None) => Ok((ConformanceDeliveryState::Rejected, 0)),
        ("trigger" | "control", Some("pending"), Some(attempts)) => {
            Ok((ConformanceDeliveryState::Pending, attempts))
        }
        ("trigger" | "control", Some("claimed"), Some(attempts)) => {
            Ok((ConformanceDeliveryState::Claimed, attempts))
        }
        ("trigger" | "control", Some("retry-pending"), Some(attempts)) => {
            Ok((ConformanceDeliveryState::RetryPending, attempts))
        }
        ("trigger" | "control", Some("completed"), Some(attempts)) => {
            Ok((ConformanceDeliveryState::Completed, attempts))
        }
        ("trigger" | "control", Some("failed"), Some(attempts)) => {
            Ok((ConformanceDeliveryState::Failed, attempts))
        }
        _ => Err(StoreError::corrupt_data(
            "provider delivery and processing states disagree",
        )),
    }
}

fn validate_header(
    state: ConformanceDeliveryState,
    attempts: u16,
    accepted_at: UnixMillis,
    completed_at: Option<UnixMillis>,
) -> Result<(), StoreError> {
    let attempt_shape = match state {
        ConformanceDeliveryState::Pending | ConformanceDeliveryState::Rejected => attempts == 0,
        ConformanceDeliveryState::Claimed
        | ConformanceDeliveryState::RetryPending
        | ConformanceDeliveryState::Completed
        | ConformanceDeliveryState::Failed => (1..=16).contains(&attempts),
    };
    let terminal = matches!(
        state,
        ConformanceDeliveryState::Completed | ConformanceDeliveryState::Failed
    );
    if !attempt_shape
        || accepted_at.get() < 0
        || terminal != completed_at.is_some()
        || completed_at.is_some_and(|completed| completed < accepted_at)
    {
        return Err(StoreError::corrupt_data(
            "provider delivery conformance header is inconsistent",
        ));
    }
    Ok(())
}

fn decode_workflows(rows: &[PgRow]) -> Result<Vec<ConformanceWorkflowResult>, StoreError> {
    let mut workflows = Vec::with_capacity(rows.len());
    let mut previous_path: Option<String> = None;
    for row in rows {
        let workflow_path: String = row
            .try_get("workflow_path")
            .map_err(StoreError::operation)?;
        if previous_path
            .as_ref()
            .is_some_and(|previous| previous >= &workflow_path)
        {
            return Err(StoreError::corrupt_data(
                "provider delivery admitted duplicate or unordered workflows",
            ));
        }
        let run_id: Uuid = row.try_get("run_id").map_err(StoreError::operation)?;
        if run_id.is_nil() {
            return Err(StoreError::corrupt_data(
                "provider delivery admitted a nil workflow run",
            ));
        }
        previous_path = Some(workflow_path.clone());
        workflows.push(automata_ci_store::adapter_spi::conformance_workflow_result(
            workflow_path,
            RunId::from_uuid(run_id),
        ));
    }
    Ok(workflows)
}

async fn begin_read(store: &PostgresStore) -> Result<Transaction<'_, Postgres>, StoreError> {
    let mut transaction = store
        .postgres_pool()
        .begin()
        .await
        .map_err(StoreError::operation)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await
        .map_err(StoreError::operation)?;
    Ok(transaction)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_delivery_headers_fail_closed_across_terminal_shapes() {
        let accepted = UnixMillis::new(100);
        assert!(
            validate_header(
                ConformanceDeliveryState::Completed,
                1,
                accepted,
                Some(UnixMillis::new(200)),
            )
            .is_ok()
        );
        assert!(validate_header(ConformanceDeliveryState::Completed, 1, accepted, None,).is_err());
        assert!(validate_header(ConformanceDeliveryState::Pending, 1, accepted, None).is_err());
        assert!(
            delivery_state("rejected", Some("failed"), Some(1)).is_err(),
            "normalization rejection cannot acquire a processing lifecycle"
        );
    }
}
