use async_trait::async_trait;
use automata_ci_core::{RunId, UnixMillis};
use sqlx::{Postgres, Row as _, Transaction, postgres::PgRow};
use uuid::Uuid;

use crate::{
    ConformanceDelivery, ConformanceDeliveryQuery, ConformanceDeliveryState,
    ConformanceReadRepository, ConformanceWorkflowOutcome, ConformanceWorkflowResult,
    ProviderDeliveryId, StoreError,
};

use super::PostgresStore;

#[async_trait]
impl ConformanceReadRepository for PostgresStore {
    async fn get_conformance_delivery(
        &self,
        query: &ConformanceDeliveryQuery,
    ) -> Result<Option<ConformanceDelivery>, StoreError> {
        get_conformance_delivery(self, query).await
    }
}

async fn get_conformance_delivery(
    store: &PostgresStore,
    query: &ConformanceDeliveryQuery,
) -> Result<Option<ConformanceDelivery>, StoreError> {
    let mut transaction = begin_read(store).await?;
    let row = sqlx::query(
        r"
        SELECT inbox.id, inbox.delivery_id, inbox.state, inbox.attempt_count,
               inbox.accepted_at_ms, inbox.completed_at_ms,
               inbox.completion_outcome_count
        FROM provider_delivery_inbox AS inbox
        JOIN repositories AS repository
          ON repository.tenant_id = inbox.tenant_id
         AND repository.id = $2
         AND repository.scm_provider = inbox.provider
         AND repository.provider_repository_id = inbox.provider_repository_id::text
        WHERE inbox.tenant_id = $1
          AND inbox.provider = $3
          AND inbox.delivery_id = $4
        ",
    )
    .bind(query.tenant().as_str())
    .bind(query.repository_id().as_uuid())
    .bind(query.provider())
    .bind(query.delivery_id())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(StoreError::operation)?;
    let Some(row) = row else {
        transaction.commit().await.map_err(StoreError::operation)?;
        return Ok(None);
    };

    let header = decode_delivery_header(&row, query)?;

    let outcome_rows = sqlx::query(
        r"
        SELECT outcome.ordinal, outcome.workflow_path, outcome.outcome_kind,
               outcome.repository_id, outcome.run_id, outcome.failure_kind
        FROM provider_delivery_workflow_outcomes AS outcome
        WHERE outcome.inbox_id = $1
          AND outcome.tenant_id = $2
        ORDER BY outcome.ordinal
        ",
    )
    .bind(header.delivery_uuid)
    .bind(query.tenant().as_str())
    .fetch_all(&mut *transaction)
    .await
    .map_err(StoreError::operation)?;
    transaction.commit().await.map_err(StoreError::operation)?;

    validate_header_shape(
        header.state,
        header.attempts,
        header.accepted_at,
        header.completed_at,
        header.expected_outcomes,
    )?;
    let expected_outcomes = header
        .expected_outcomes
        .map_or(0, |count| usize::try_from(count).unwrap_or(usize::MAX));
    if outcome_rows.len() != expected_outcomes {
        return Err(StoreError::corrupt_data(
            "provider delivery outcome count contradicts its terminal header",
        ));
    }
    let workflows = decode_workflow_results(&outcome_rows, query.repository_id().as_uuid())?;

    Ok(Some(ConformanceDelivery::new(
        header.delivery_id,
        header.external_delivery_id,
        header.state,
        header.attempts,
        header.accepted_at,
        header.completed_at,
        workflows,
    )))
}

fn decode_workflow_results(
    rows: &[PgRow],
    repository_id: Uuid,
) -> Result<Vec<ConformanceWorkflowResult>, StoreError> {
    let mut workflows = Vec::with_capacity(rows.len());
    let mut previous_path: Option<String> = None;
    for (expected_ordinal, row) in rows.iter().enumerate() {
        let ordinal: i16 = row.try_get("ordinal").map_err(StoreError::operation)?;
        if usize::try_from(ordinal).ok() != Some(expected_ordinal) {
            return Err(StoreError::corrupt_data(
                "provider delivery outcome ordinal is not contiguous",
            ));
        }
        let workflow_path: String = row
            .try_get("workflow_path")
            .map_err(StoreError::operation)?;
        if previous_path
            .as_ref()
            .is_some_and(|path| path >= &workflow_path)
        {
            return Err(StoreError::corrupt_data(
                "provider delivery workflow outcomes are not path sorted",
            ));
        }
        previous_path = Some(workflow_path.clone());
        workflows.push(ConformanceWorkflowResult::new(
            workflow_path,
            decode_outcome(row, repository_id)?,
        ));
    }
    Ok(workflows)
}

struct DeliveryHeader {
    delivery_uuid: Uuid,
    delivery_id: ProviderDeliveryId,
    external_delivery_id: String,
    state: ConformanceDeliveryState,
    attempts: u16,
    accepted_at: UnixMillis,
    completed_at: Option<UnixMillis>,
    expected_outcomes: Option<i16>,
}

fn decode_delivery_header(
    row: &PgRow,
    query: &ConformanceDeliveryQuery,
) -> Result<DeliveryHeader, StoreError> {
    let delivery_uuid: Uuid = row.try_get("id").map_err(StoreError::operation)?;
    let delivery_id = ProviderDeliveryId::from_uuid(delivery_uuid)
        .map_err(|_| StoreError::corrupt_data("provider delivery ID is nil"))?;
    let external_delivery_id: String = row.try_get("delivery_id").map_err(StoreError::operation)?;
    if external_delivery_id != query.delivery_id() {
        return Err(StoreError::corrupt_data(
            "provider delivery lookup changed its external identity",
        ));
    }
    let state = delivery_state(
        &row.try_get::<String, _>("state")
            .map_err(StoreError::operation)?,
    )?;
    let attempts = u16::try_from(
        row.try_get::<i16, _>("attempt_count")
            .map_err(StoreError::operation)?,
    )
    .map_err(|_| StoreError::corrupt_data("provider delivery attempt count is negative"))?;
    let accepted_at = UnixMillis::new(
        row.try_get("accepted_at_ms")
            .map_err(StoreError::operation)?,
    );
    let completed_at = row
        .try_get::<Option<i64>, _>("completed_at_ms")
        .map_err(StoreError::operation)?
        .map(UnixMillis::new);
    let expected_outcomes = row
        .try_get("completion_outcome_count")
        .map_err(StoreError::operation)?;
    Ok(DeliveryHeader {
        delivery_uuid,
        delivery_id,
        external_delivery_id,
        state,
        attempts,
        accepted_at,
        completed_at,
        expected_outcomes,
    })
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

fn delivery_state(value: &str) -> Result<ConformanceDeliveryState, StoreError> {
    match value {
        "pending" => Ok(ConformanceDeliveryState::Pending),
        "claimed" => Ok(ConformanceDeliveryState::Claimed),
        "retry" => Ok(ConformanceDeliveryState::RetryPending),
        "completed" => Ok(ConformanceDeliveryState::Completed),
        "rejected" => Ok(ConformanceDeliveryState::Rejected),
        _ => Err(StoreError::corrupt_data(
            "provider delivery state is outside the closed lifecycle",
        )),
    }
}

fn validate_header_shape(
    state: ConformanceDeliveryState,
    attempts: u16,
    accepted_at: UnixMillis,
    completed_at: Option<UnixMillis>,
    expected_outcomes: Option<i16>,
) -> Result<(), StoreError> {
    const MAX_ATTEMPTS: u16 = 16;
    let terminal_shape = match state {
        ConformanceDeliveryState::Completed => {
            completed_at.is_some() && expected_outcomes.is_some()
        }
        ConformanceDeliveryState::Rejected => completed_at.is_none() && expected_outcomes.is_none(),
        ConformanceDeliveryState::Pending
        | ConformanceDeliveryState::Claimed
        | ConformanceDeliveryState::RetryPending => {
            completed_at.is_none() && expected_outcomes.is_none()
        }
    };
    let attempts_valid = match state {
        ConformanceDeliveryState::Pending => attempts == 0,
        ConformanceDeliveryState::RetryPending => (1..MAX_ATTEMPTS).contains(&attempts),
        ConformanceDeliveryState::Claimed
        | ConformanceDeliveryState::Completed
        | ConformanceDeliveryState::Rejected => (1..=MAX_ATTEMPTS).contains(&attempts),
    };
    if !terminal_shape
        || !attempts_valid
        || accepted_at.get() < 0
        || completed_at.is_some_and(|completed| completed < accepted_at)
        || expected_outcomes.is_some_and(|count| !(0..=256).contains(&count))
    {
        return Err(StoreError::corrupt_data(
            "provider delivery conformance header is inconsistent",
        ));
    }
    Ok(())
}

fn decode_outcome(
    row: &sqlx::postgres::PgRow,
    expected_repository_id: Uuid,
) -> Result<ConformanceWorkflowOutcome, StoreError> {
    let kind: String = row.try_get("outcome_kind").map_err(StoreError::operation)?;
    let repository_id: Option<Uuid> = row
        .try_get("repository_id")
        .map_err(StoreError::operation)?;
    let run_id: Option<Uuid> = row.try_get("run_id").map_err(StoreError::operation)?;
    let failure_kind: Option<String> =
        row.try_get("failure_kind").map_err(StoreError::operation)?;
    match (kind.as_str(), repository_id, run_id, failure_kind) {
        ("admitted", Some(repository_id), Some(run_id), None)
            if repository_id == expected_repository_id && !run_id.is_nil() =>
        {
            Ok(ConformanceWorkflowOutcome::Admitted {
                run_id: RunId::from_uuid(run_id),
            })
        }
        ("skipped", None, None, Some(reason)) => Ok(ConformanceWorkflowOutcome::Skipped { reason }),
        ("failed", None, None, Some(failure_kind)) => {
            Ok(ConformanceWorkflowOutcome::Failed { failure_kind })
        }
        _ => Err(StoreError::corrupt_data(
            "provider delivery workflow outcome is inconsistent",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_headers_fail_closed_across_terminal_shapes() {
        let accepted = UnixMillis::new(100);
        assert!(
            validate_header_shape(
                ConformanceDeliveryState::Completed,
                1,
                accepted,
                Some(UnixMillis::new(200)),
                Some(1),
            )
            .is_ok()
        );
        assert!(
            validate_header_shape(
                ConformanceDeliveryState::Completed,
                1,
                accepted,
                None,
                Some(1),
            )
            .is_err()
        );
        assert!(
            validate_header_shape(ConformanceDeliveryState::Pending, 1, accepted, None, None,)
                .is_err()
        );
    }
}
