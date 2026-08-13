use sqlx::{Postgres, Row as _, Transaction};

use automata_ci_core::AttemptId;

use crate::{RequestCancellation, StoreError};

pub(super) async fn server_cancellation_terminal_exists(
    transaction: &mut Transaction<'_, Postgres>,
    attempt_id: AttemptId,
) -> Result<bool, StoreError> {
    sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM attempt_terminal_results
            WHERE attempt_id = $1
              AND terminal_authority = 'server_cancellation'
        )
        ",
    )
    .bind(attempt_id.as_uuid())
    .fetch_one(&mut **transaction)
    .await
    .map_err(StoreError::operation)
}

pub(super) async fn insert_queued_server_cancellation_terminal(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RequestCancellation,
) -> Result<(), StoreError> {
    let inserted = sqlx::query(
        r"
        INSERT INTO attempt_terminal_results (
            attempt_id, terminal_authority,
            server_cancellation_operation_id, server_cancellation_digest,
            conclusion, completed_at_ms, committed_at_ms
        )
        SELECT cancellation.attempt_id, 'server_cancellation',
               cancellation.operation_id,
               automata_server_cancellation_terminal_digest(
                   cancellation.attempt_id, cancellation.operation_id,
                   cancellation.requested_by, cancellation.reason,
                   cancellation.requested_at_ms
               ),
               'cancelled', cancellation.requested_at_ms,
               cancellation.requested_at_ms
        FROM attempt_cancellation_intents AS cancellation
        WHERE cancellation.attempt_id = $1
          AND cancellation.operation_id = $2
          AND cancellation.requested_by = $3
          AND cancellation.reason IS NOT DISTINCT FROM $4
          AND cancellation.requested_at_ms = $5
          AND cancellation.acknowledged_at_ms IS NULL
          AND cancellation.delivery_session_id IS NULL
          AND cancellation.delivery_command_sequence IS NULL
        ON CONFLICT DO NOTHING
        ",
    )
    .bind(request.attempt_id().as_uuid())
    .bind(request.operation_id().as_uuid())
    .bind(request.actor().as_str())
    .bind(request.reason().map(crate::CancellationReason::as_str))
    .bind(request.requested_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(StoreError::operation)?
    .rows_affected();
    if inserted != 1 {
        return Err(StoreError::ImmutableConflict(
            "server cancellation terminal authority",
        ));
    }
    verify_queued_server_cancellation_terminal(transaction, request).await
}

pub(super) async fn verify_queued_server_cancellation_terminal(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RequestCancellation,
) -> Result<(), StoreError> {
    let row = sqlx::query(
        r"
        SELECT terminal.terminal_authority,
               terminal.server_cancellation_operation_id,
               terminal.server_cancellation_digest,
               terminal.conclusion, terminal.completed_at_ms,
               terminal.committed_at_ms,
               terminal.logical_workflow_logical_job_id,
               terminal.logical_workflow_terminal_ordinal,
               terminal.server_cancellation_digest =
                   automata_server_cancellation_terminal_digest(
                       cancellation.attempt_id, cancellation.operation_id,
                       cancellation.requested_by, cancellation.reason,
                       cancellation.requested_at_ms
                   ) AS digest_valid,
               concrete.logical_job_id AS concrete_logical_job_id
        FROM attempt_cancellation_intents AS cancellation
        JOIN attempt_terminal_results AS terminal
          ON terminal.attempt_id = cancellation.attempt_id
         AND terminal.server_cancellation_operation_id =
             cancellation.operation_id
        LEFT JOIN logical_workflow_concrete_jobs AS concrete
          ON concrete.initial_attempt_id = terminal.attempt_id
        WHERE cancellation.attempt_id = $1
          AND cancellation.operation_id = $2
          AND cancellation.requested_by = $3
          AND cancellation.reason IS NOT DISTINCT FROM $4
          AND cancellation.requested_at_ms = $5
          AND cancellation.acknowledged_at_ms IS NULL
          AND cancellation.delivery_session_id IS NULL
          AND cancellation.delivery_command_sequence IS NULL
        ",
    )
    .bind(request.attempt_id().as_uuid())
    .bind(request.operation_id().as_uuid())
    .bind(request.actor().as_str())
    .bind(request.reason().map(crate::CancellationReason::as_str))
    .bind(request.requested_at().get())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(StoreError::operation)?
    .ok_or_else(|| {
        StoreError::corrupt_data("queued cancellation lacks server terminal authority")
    })?;

    let logical_job_id = row
        .try_get::<Option<uuid::Uuid>, _>("logical_workflow_logical_job_id")
        .map_err(StoreError::operation)?;
    let terminal_ordinal = row
        .try_get::<Option<i64>, _>("logical_workflow_terminal_ordinal")
        .map_err(StoreError::operation)?;
    let concrete_logical_job_id = row
        .try_get::<Option<uuid::Uuid>, _>("concrete_logical_job_id")
        .map_err(StoreError::operation)?;
    let logical_order_exact = match concrete_logical_job_id {
        Some(concrete) => {
            logical_job_id == Some(concrete) && terminal_ordinal.is_some_and(|v| v > 0)
        }
        None => logical_job_id.is_none() && terminal_ordinal.is_none(),
    };
    let digest = row
        .try_get::<Vec<u8>, _>("server_cancellation_digest")
        .map_err(StoreError::operation)?;
    let exact = row
        .try_get::<String, _>("terminal_authority")
        .map_err(StoreError::operation)?
        == "server_cancellation"
        && row
            .try_get::<uuid::Uuid, _>("server_cancellation_operation_id")
            .map_err(StoreError::operation)?
            == request.operation_id().as_uuid()
        && digest.len() == 32
        && row
            .try_get::<bool, _>("digest_valid")
            .map_err(StoreError::operation)?
        && row
            .try_get::<String, _>("conclusion")
            .map_err(StoreError::operation)?
            == "cancelled"
        && row
            .try_get::<i64, _>("completed_at_ms")
            .map_err(StoreError::operation)?
            == request.requested_at().get()
        && row
            .try_get::<i64, _>("committed_at_ms")
            .map_err(StoreError::operation)?
            == request.requested_at().get()
        && logical_order_exact;
    if exact {
        Ok(())
    } else {
        Err(StoreError::corrupt_data(
            "queued cancellation terminal authority is inconsistent",
        ))
    }
}
