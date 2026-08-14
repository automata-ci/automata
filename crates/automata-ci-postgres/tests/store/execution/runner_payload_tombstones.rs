use std::sync::Arc;

use automata_ci_core::{JobIrVersion, OperationId, RunnerSessionId, Sha256Digest, UnixMillis};
use automata_ci_postgres::store::PostgresStore;
use automata_ci_store::{
    AcknowledgeRunnerCommands, CloseRunnerSession, CommandCursor, CommandReplayLimit,
    ControlPlaneMaintenanceRepository as _, ControlPlaneMaintenanceRequest, DocumentSchema,
    EnqueueRunnerCommand, LeaseFailureLimit, MaintenanceBatchSize, OpenRunnerSession,
    RunnerCommandOutbox as _, RunnerCommandPayload, RunnerGeneration, RunnerOperationKind,
    RunnerOperationReceiptRepository as _, RunnerOperationRequest, RunnerOperationResponse,
    RunnerPayloadTombstoneReason, RunnerProtocolVersion, RunnerSessionFence,
    RunnerSessionRepository as _, StaleSessionTimeoutMillis, StoreError,
};

use crate::support::{
    TestDatabase, TestResult, run_with_database, runner_capability_document, seed_control_plane,
    test_runner_payload_key_provider,
};

#[derive(Debug, sqlx::FromRow)]
struct PayloadState {
    envelope_columns_are_null: bool,
    payload_tombstone_reason: Option<String>,
    payload_tombstoned_at_ms: Option<i64>,
    authenticated_at_ms: i64,
    digest: Vec<u8>,
    plaintext_size_bytes: i64,
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn acknowledgement_erases_only_envelopes_and_makes_exact_retry_typed() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let operation_id = OperationId::new();
        let command_created_at = database_now(&database).await?;
        let original = command(
            fence,
            operation_id,
            command_created_at,
            b"ephemeral-command",
        )?;
        let digest = original.payload().digest();
        let durable = database.store().enqueue_command(original.clone()).await?;
        assert_rejects_non_newer_supersession(database.as_ref(), fence, durable.sequence().get())
            .await?;
        assert_retention_constraint_rejects_ack_without_erasure(
            database.as_ref(),
            fence,
            durable.sequence().get(),
        )
        .await?;

        let acknowledgement_started_at = database_now(&database).await?;
        database
            .store()
            .acknowledge_commands(AcknowledgeRunnerCommands::new(
                fence,
                CommandCursor::through(durable.sequence()),
                acknowledgement_started_at,
            ))
            .await?;
        let acknowledgement_finished_at = database_now(&database).await?;

        let state = command_state(&database, fence, durable.sequence().get()).await?;
        let heartbeat_at = session_heartbeat_at(&database, fence).await?;
        assert!(heartbeat_at >= acknowledgement_started_at.get());
        assert!(heartbeat_at <= acknowledgement_finished_at.get());
        let tombstoned_at = assert_erased_for_decision(&state, "acknowledged", heartbeat_at);
        assert_eq!(state.digest, digest.as_bytes());
        assert_eq!(state.plaintext_size_bytes, 17);
        let conflicting = command(
            fence,
            operation_id,
            command_created_at,
            b"different-command",
        )?;
        assert!(matches!(
            database.store().enqueue_command(conflicting).await,
            Err(StoreError::OperationConflict {
                session_id,
                operation_id: conflicting_operation,
            }) if session_id == fence.session_id() && conflicting_operation == operation_id
        ));
        assert!(matches!(
            database.store().enqueue_command(original).await,
            Err(StoreError::RunnerPayloadUnavailable { session_id, tombstone })
                if session_id == fence.session_id()
                    && tombstone.reason() == RunnerPayloadTombstoneReason::Acknowledged
                    && tombstone.tombstoned_at() == tombstoned_at
        ));

        assert_rejects_tombstone_mutation(database.as_ref(), fence, durable.sequence().get()).await;
        assert_delivery_foreign_keys_remain(database.as_ref()).await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn explicit_close_and_supersession_erase_commands_and_receipts() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 2).await?;
        let close_fence = seed.session_fences[0];
        let superseded_fence = seed.session_fences[1];

        let close_command_created_at = database_now(&database).await?;
        let close_command = database
            .store()
            .enqueue_command(command(
                close_fence,
                OperationId::new(),
                close_command_created_at,
                b"close-command-secret",
            )?)
            .await?;
        let close_receipt = receipt_request(close_fence, OperationId::new())?;
        let close_receipt_committed_at = database_now(&database).await?;
        database
            .store()
            .record_operation(
                close_receipt.clone(),
                response(b"close-receipt-secret")?,
                close_receipt_committed_at,
            )
            .await?;
        assert_retention_constraint_rejects_close_without_erasure(database.as_ref(), close_fence)
            .await?;
        let close_started_at = database_now(&database).await?;
        database
            .store()
            .close_session(CloseRunnerSession::new(close_fence, close_started_at))
            .await?;
        let close_finished_at = database_now(&database).await?;
        let close_decision_at = session_disconnected_at(&database, close_fence).await?;
        assert!(close_decision_at >= close_started_at.get());
        assert!(close_decision_at <= close_finished_at.get());

        let close_command_tombstoned_at = assert_erased_for_decision(
            &command_state(&database, close_fence, close_command.sequence().get()).await?,
            "session_closed",
            close_decision_at,
        );
        let close_receipt_tombstoned_at = assert_erased_for_decision(
            &receipt_state(&database, &close_receipt).await?,
            "session_closed",
            close_decision_at,
        );
        assert_rejects_receipt_tombstone_mutation(database.as_ref(), &close_receipt).await;
        assert_unavailable(
            &database
                .store()
                .replay_commands(
                    close_fence,
                    CommandCursor::initial(),
                    CommandReplayLimit::new(1)?,
                )
                .await,
            close_fence,
            RunnerPayloadTombstoneReason::SessionClosed,
            close_command_tombstoned_at,
        );
        assert_unavailable(
            &database.store().lookup_operation(&close_receipt).await,
            close_fence,
            RunnerPayloadTombstoneReason::SessionClosed,
            close_receipt_tombstoned_at,
        );

        let superseded_command_created_at = database_now(&database).await?;
        let superseded_command = database
            .store()
            .enqueue_command(command(
                superseded_fence,
                OperationId::new(),
                superseded_command_created_at,
                b"superseded-command-secret",
            )?)
            .await?;
        let superseded_receipt = receipt_request(superseded_fence, OperationId::new())?;
        let superseded_receipt_committed_at = database_now(&database).await?;
        database
            .store()
            .record_operation(
                superseded_receipt.clone(),
                response(b"superseded-receipt-secret")?,
                superseded_receipt_committed_at,
            )
            .await?;
        let supersession_started_at = database_now(&database).await?;
        let replacement = database
            .store()
            .open_session(OpenRunnerSession::new(
                RunnerSessionId::new(),
                superseded_fence.runner_id(),
                RunnerGeneration::new(1)?,
                RunnerProtocolVersion::new(1)?,
                JobIrVersion::current(),
                runner_capability_document(database.pool(), superseded_fence.runner_id()).await?,
                supersession_started_at,
            ))
            .await?;
        let supersession_finished_at = database_now(&database).await?;
        assert_ne!(replacement.fence(), superseded_fence);
        let supersession_decision_at = session_disconnected_at(&database, superseded_fence).await?;
        assert!(supersession_decision_at >= supersession_started_at.get());
        assert!(supersession_decision_at <= supersession_finished_at.get());
        let superseded_command_tombstoned_at = assert_erased_for_decision(
            &command_state(
                &database,
                superseded_fence,
                superseded_command.sequence().get(),
            )
            .await?,
            "session_superseded",
            supersession_decision_at,
        );
        let superseded_receipt_tombstoned_at = assert_erased_for_decision(
            &receipt_state(&database, &superseded_receipt).await?,
            "session_superseded",
            supersession_decision_at,
        );
        assert_unavailable(
            &database
                .store()
                .replay_commands(
                    superseded_fence,
                    CommandCursor::initial(),
                    CommandReplayLimit::new(1)?,
                )
                .await,
            superseded_fence,
            RunnerPayloadTombstoneReason::SessionSuperseded,
            superseded_command_tombstoned_at,
        );
        assert_unavailable(
            &database.store().lookup_operation(&superseded_receipt).await,
            superseded_fence,
            RunnerPayloadTombstoneReason::SessionSuperseded,
            superseded_receipt_tombstoned_at,
        );
        let pending: (i64, Option<i64>) = sqlx::query_as(
            r"
            SELECT count(*)::BIGINT, min(command.created_at_ms)::BIGINT
            FROM runner_command_outbox AS command
            JOIN runner_sessions AS session ON session.id = command.runner_session_id
            WHERE command.payload_tombstone_reason IS NULL
              AND command.command_sequence > session.acknowledged_command_sequence
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(pending, (0, None));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn erasure_time_never_precedes_authenticated_payload_metadata() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 2).await?;
        let acknowledged_fence = seed.session_fences[0];
        let closed_fence = seed.session_fences[1];
        let baseline = database_now(&database).await?;
        let future_ack_command_at = timestamp_after(baseline, 30_000)?;

        let acknowledged = database
            .store()
            .enqueue_command(command(
                acknowledged_fence,
                OperationId::new(),
                future_ack_command_at,
                b"future-ack-command",
            )?)
            .await?;
        let acknowledgement_started_at = database_now(&database).await?;
        database
            .store()
            .acknowledge_commands(AcknowledgeRunnerCommands::new(
                acknowledged_fence,
                CommandCursor::through(acknowledged.sequence()),
                acknowledgement_started_at,
            ))
            .await?;
        let acknowledgement_finished_at = database_now(&database).await?;
        let acknowledgement_decision_at =
            session_heartbeat_at(&database, acknowledged_fence).await?;
        assert!(acknowledgement_decision_at >= acknowledgement_started_at.get());
        assert!(acknowledgement_decision_at <= acknowledgement_finished_at.get());
        assert_erased_for_decision(
            &command_state(&database, acknowledged_fence, acknowledged.sequence().get()).await?,
            "acknowledged",
            acknowledgement_decision_at,
        );

        let future_close_command_at = timestamp_after(baseline, 40_000)?;
        let closed = database
            .store()
            .enqueue_command(command(
                closed_fence,
                OperationId::new(),
                future_close_command_at,
                b"future-close-command",
            )?)
            .await?;
        let receipt = receipt_request(closed_fence, OperationId::new())?;
        let future_close_receipt_at = timestamp_after(baseline, 50_000)?;
        database
            .store()
            .record_operation(
                receipt.clone(),
                response(b"future-close-receipt")?,
                future_close_receipt_at,
            )
            .await?;
        let close_started_at = database_now(&database).await?;
        database
            .store()
            .close_session(CloseRunnerSession::new(closed_fence, close_started_at))
            .await?;
        let close_finished_at = database_now(&database).await?;
        let close_decision_at = session_disconnected_at(&database, closed_fence).await?;
        assert!(close_decision_at >= close_started_at.get());
        assert!(close_decision_at <= close_finished_at.get());
        assert_erased_for_decision(
            &command_state(&database, closed_fence, closed.sequence().get()).await?,
            "session_closed",
            close_decision_at,
        );
        assert_erased_for_decision(
            &receipt_state(&database, &receipt).await?,
            "session_closed",
            close_decision_at,
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn acknowledgement_and_close_race_has_one_erased_terminal_state() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let command_created_at = database_now(&database).await?;
        let durable = database
            .store()
            .enqueue_command(command(
                fence,
                OperationId::new(),
                command_created_at,
                b"race-command-secret",
            )?)
            .await?;
        let request = receipt_request(fence, OperationId::new())?;
        let receipt_committed_at = database_now(&database).await?;
        database
            .store()
            .record_operation(
                request.clone(),
                response(b"race-receipt-secret")?,
                receipt_committed_at,
            )
            .await?;

        let ack_store = PostgresStore::from_postgres_pool(database.pool().clone())
            .with_runner_payload_encryption(test_runner_payload_key_provider());
        let close_store = PostgresStore::from_postgres_pool(database.pool().clone())
            .with_runner_payload_encryption(test_runner_payload_key_provider());
        let race_started_at = database_now(&database).await?;
        let acknowledgement = AcknowledgeRunnerCommands::new(
            fence,
            CommandCursor::through(durable.sequence()),
            race_started_at,
        );
        let (acknowledged, closed) = tokio::join!(
            ack_store.acknowledge_commands(acknowledgement),
            close_store.close_session(CloseRunnerSession::new(fence, race_started_at)),
        );
        closed?;
        let race_finished_at = database_now(&database).await?;
        assert!(
            acknowledged.is_ok()
                || matches!(acknowledged, Err(StoreError::SessionClosed(id)) if id == fence.session_id())
        );

        let command = command_state(&database, fence, durable.sequence().get()).await?;
        let command_reason = command
            .payload_tombstone_reason
            .as_deref()
            .filter(|reason| matches!(*reason, "acknowledged" | "session_closed"))
            .expect("race command has one authorized tombstone reason");
        assert_erased_between(
            &command,
            command_reason,
            race_started_at,
            race_finished_at,
        );
        let close_decision_at = session_disconnected_at(&database, fence).await?;
        assert!(close_decision_at >= race_started_at.get());
        assert!(close_decision_at <= race_finished_at.get());
        assert_erased_for_decision(
            &receipt_state(&database, &request).await?,
            "session_closed",
            close_decision_at,
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn stale_session_maintenance_erases_remaining_envelopes() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let command_created_at = database_now(&database).await?;
        let durable = database
            .store()
            .enqueue_command(command(
                fence,
                OperationId::new(),
                command_created_at,
                b"stale-command-secret",
            )?)
            .await?;
        let request = receipt_request(fence, OperationId::new())?;
        let receipt_committed_at = database_now(&database).await?;
        database
            .store()
            .record_operation(
                request.clone(),
                response(b"stale-receipt-secret")?,
                receipt_committed_at,
            )
            .await?;

        let maintenance_started_at = database_now(&database).await?;
        let stale_at = maintenance_started_at
            .get()
            .checked_sub(10_000)
            .ok_or("test stale-session timestamp underflowed")?;
        let backdated = sqlx::query(
            r"
            UPDATE runner_sessions
            SET connected_at_ms = $2, heartbeat_at_ms = $2
            WHERE id = $1
            ",
        )
        .bind(fence.session_id().as_uuid())
        .bind(stale_at)
        .execute(database.pool())
        .await?;
        assert_eq!(backdated.rows_affected(), 1);
        let report = database
            .store()
            .maintain_control_plane(ControlPlaneMaintenanceRequest::new(
                maintenance_started_at,
                LeaseFailureLimit::new(3)?,
                MaintenanceBatchSize::new(10)?,
                StaleSessionTimeoutMillis::new(1_000)?,
            )?)
            .await?;
        let maintenance_finished_at = database_now(&database).await?;
        assert_eq!(report.closed_stale_sessions(), 1);
        let maintenance_decision_at = session_disconnected_at(&database, fence).await?;
        assert!(maintenance_decision_at >= maintenance_started_at.get());
        assert!(maintenance_decision_at <= maintenance_finished_at.get());
        assert_erased_for_decision(
            &command_state(&database, fence, durable.sequence().get()).await?,
            "session_closed",
            maintenance_decision_at,
        );
        assert_erased_for_decision(
            &receipt_state(&database, &request).await?,
            "session_closed",
            maintenance_decision_at,
        );
        Ok(())
    })
    .await
}

fn command(
    fence: RunnerSessionFence,
    operation_id: OperationId,
    created_at: UnixMillis,
    payload: &[u8],
) -> TestResult<EnqueueRunnerCommand> {
    Ok(EnqueueRunnerCommand::new(
        fence,
        operation_id,
        RunnerOperationKind::new("automata.test.runner-payload.v1")?,
        RunnerCommandPayload::new(DocumentSchema::new(1)?, payload.to_vec())?,
        created_at,
    ))
}

fn receipt_request(
    fence: RunnerSessionFence,
    operation_id: OperationId,
) -> TestResult<RunnerOperationRequest> {
    Ok(RunnerOperationRequest::new(
        fence,
        operation_id,
        RunnerOperationKind::new("automata.test.runner-receipt.v1")?,
        Sha256Digest::from_bytes([0x31; 32]),
    ))
}

fn response(payload: &[u8]) -> TestResult<RunnerOperationResponse> {
    Ok(RunnerOperationResponse::new(
        DocumentSchema::new(1)?,
        payload.to_vec(),
    )?)
}

async fn database_now(database: &TestDatabase) -> TestResult<UnixMillis> {
    Ok(UnixMillis::new(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(database.pool())
            .await?,
    ))
}

fn timestamp_after(timestamp: UnixMillis, delta_millis: i64) -> TestResult<UnixMillis> {
    Ok(UnixMillis::new(
        timestamp
            .get()
            .checked_add(delta_millis)
            .ok_or("test timestamp overflowed")?,
    ))
}

async fn session_heartbeat_at(
    database: &TestDatabase,
    fence: RunnerSessionFence,
) -> TestResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT heartbeat_at_ms FROM runner_sessions WHERE id = $1")
            .bind(fence.session_id().as_uuid())
            .fetch_one(database.pool())
            .await?,
    )
}

async fn session_disconnected_at(
    database: &TestDatabase,
    fence: RunnerSessionFence,
) -> TestResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT disconnected_at_ms FROM runner_sessions WHERE id = $1")
            .bind(fence.session_id().as_uuid())
            .fetch_one(database.pool())
            .await?,
    )
}

async fn command_state(
    database: &Arc<TestDatabase>,
    fence: RunnerSessionFence,
    sequence: u64,
) -> TestResult<PayloadState> {
    Ok(sqlx::query_as(
        r"
        SELECT envelope_schema IS NULL
                   AND wrapping_key_id IS NULL
                   AND wrapped_data_key IS NULL
                   AND nonce IS NULL
                   AND ciphertext IS NULL AS envelope_columns_are_null,
               payload_tombstone_reason, payload_tombstoned_at_ms,
               created_at_ms AS authenticated_at_ms,
               command_digest AS digest,
               command_plaintext_size_bytes AS plaintext_size_bytes
        FROM runner_command_outbox
        WHERE runner_session_id = $1 AND command_sequence = $2
        ",
    )
    .bind(fence.session_id().as_uuid())
    .bind(i64::try_from(sequence)?)
    .fetch_one(database.pool())
    .await?)
}

async fn receipt_state(
    database: &Arc<TestDatabase>,
    request: &RunnerOperationRequest,
) -> TestResult<PayloadState> {
    Ok(sqlx::query_as(
        r"
        SELECT envelope_schema IS NULL
                   AND wrapping_key_id IS NULL
                   AND wrapped_data_key IS NULL
                   AND nonce IS NULL
                   AND ciphertext IS NULL AS envelope_columns_are_null,
               payload_tombstone_reason, payload_tombstoned_at_ms,
               committed_at_ms AS authenticated_at_ms,
               response_digest AS digest,
               response_plaintext_size_bytes AS plaintext_size_bytes
        FROM runner_rpc_receipts
        WHERE runner_session_id = $1 AND operation_id = $2
        ",
    )
    .bind(request.session().session_id().as_uuid())
    .bind(request.operation_id().as_uuid())
    .fetch_one(database.pool())
    .await?)
}

fn assert_erased(state: &PayloadState, reason: &str) -> UnixMillis {
    assert!(all_envelope_columns_are_null(state));
    assert_eq!(state.payload_tombstone_reason.as_deref(), Some(reason));
    let tombstoned_at = state
        .payload_tombstoned_at_ms
        .expect("erased payload retains its tombstone timestamp");
    assert!(tombstoned_at >= state.authenticated_at_ms);
    assert_eq!(state.digest.len(), 32);
    assert!(state.plaintext_size_bytes > 0);
    UnixMillis::new(tombstoned_at)
}

fn assert_erased_for_decision(state: &PayloadState, reason: &str, decision_at: i64) -> UnixMillis {
    let tombstoned_at = assert_erased(state, reason);
    assert_eq!(
        tombstoned_at.get(),
        decision_at.max(state.authenticated_at_ms)
    );
    tombstoned_at
}

fn assert_erased_between(
    state: &PayloadState,
    reason: &str,
    started_at: UnixMillis,
    finished_at: UnixMillis,
) -> UnixMillis {
    let tombstoned_at = assert_erased(state, reason);
    assert!(tombstoned_at >= started_at);
    assert!(tombstoned_at <= finished_at);
    tombstoned_at
}

const fn all_envelope_columns_are_null(state: &PayloadState) -> bool {
    state.envelope_columns_are_null
}

fn assert_unavailable<T>(
    result: &Result<T, StoreError>,
    fence: RunnerSessionFence,
    reason: RunnerPayloadTombstoneReason,
    tombstoned_at: UnixMillis,
) {
    match result {
        Err(StoreError::RunnerPayloadUnavailable {
            session_id,
            tombstone,
        }) if *session_id == fence.session_id()
            && tombstone.reason() == reason
            && tombstone.tombstoned_at() == tombstoned_at => {}
        Err(error) => panic!("expected the exact typed runner payload tombstone, got {error:?}"),
        Ok(_) => panic!("expected runner payload lookup to be unavailable"),
    }
}

async fn assert_rejects_tombstone_mutation(
    database: &TestDatabase,
    fence: RunnerSessionFence,
    sequence: u64,
) {
    let sequence = i64::try_from(sequence).expect("bounded sequence");
    for statement in [
        "UPDATE runner_command_outbox SET command_kind = 'automata.test.changed.v1' WHERE runner_session_id = $1 AND command_sequence = $2",
        "UPDATE runner_command_outbox SET payload_tombstoned_at_ms = payload_tombstoned_at_ms + 1 WHERE runner_session_id = $1 AND command_sequence = $2",
        "UPDATE runner_command_outbox SET ciphertext = decode('00', 'hex') WHERE runner_session_id = $1 AND command_sequence = $2",
        "DELETE FROM runner_command_outbox WHERE runner_session_id = $1 AND command_sequence = $2",
    ] {
        sqlx::query(statement)
            .bind(fence.session_id().as_uuid())
            .bind(sequence)
            .execute(database.pool())
            .await
            .expect_err("tombstoned command state must be immutable and retained");
    }
}

async fn assert_retention_constraint_rejects_ack_without_erasure(
    database: &TestDatabase,
    fence: RunnerSessionFence,
    sequence: u64,
) -> TestResult {
    let mut transaction = database.pool().begin().await?;
    sqlx::query("UPDATE runner_sessions SET acknowledged_command_sequence = $2 WHERE id = $1")
        .bind(fence.session_id().as_uuid())
        .bind(i64::try_from(sequence)?)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SET CONSTRAINTS runner_session_payload_retention IMMEDIATE")
        .execute(&mut *transaction)
        .await
        .expect_err("an ACK cannot commit while its envelope remains live");
    transaction.rollback().await?;
    Ok(())
}

async fn assert_rejects_non_newer_supersession(
    database: &TestDatabase,
    fence: RunnerSessionFence,
    sequence: u64,
) -> TestResult {
    let tombstoned_at = database_now(database).await?;
    let mut transaction = database.pool().begin().await?;
    sqlx::query("UPDATE runner_sessions SET disconnected_at_ms = $2 WHERE id = $1")
        .bind(fence.session_id().as_uuid())
        .bind(tombstoned_at.get())
        .execute(&mut *transaction)
        .await?;
    sqlx::query("UPDATE runners SET session_epoch = 0 WHERE id = $1")
        .bind(fence.runner_id().as_uuid())
        .execute(&mut *transaction)
        .await?;
    let error = sqlx::query(
        r"
        UPDATE runner_command_outbox
        SET envelope_schema = NULL, wrapping_key_id = NULL,
            wrapped_data_key = NULL, nonce = NULL, ciphertext = NULL,
            payload_tombstone_reason = 'session_superseded',
            payload_tombstoned_at_ms = $3
        WHERE runner_session_id = $1 AND command_sequence = $2
        ",
    )
    .bind(fence.session_id().as_uuid())
    .bind(i64::try_from(sequence)?)
    .bind(tombstoned_at.get())
    .execute(&mut *transaction)
    .await
    .expect_err("an older runner epoch cannot authorize payload supersession");
    assert_eq!(
        error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::constraint),
        Some("runner_command_outbox_superseded_tombstone_authority")
    );
    transaction.rollback().await?;
    Ok(())
}

async fn assert_retention_constraint_rejects_close_without_erasure(
    database: &TestDatabase,
    fence: RunnerSessionFence,
) -> TestResult {
    let disconnected_at = database_now(database).await?;
    let mut transaction = database.pool().begin().await?;
    sqlx::query("UPDATE runner_sessions SET disconnected_at_ms = $2 WHERE id = $1")
        .bind(fence.session_id().as_uuid())
        .bind(disconnected_at.get())
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SET CONSTRAINTS runner_session_payload_retention IMMEDIATE")
        .execute(&mut *transaction)
        .await
        .expect_err("a session close cannot commit while any payload envelope remains live");
    transaction.rollback().await?;
    Ok(())
}

async fn assert_rejects_receipt_tombstone_mutation(
    database: &TestDatabase,
    request: &RunnerOperationRequest,
) {
    for statement in [
        "UPDATE runner_rpc_receipts SET operation_kind = 'automata.test.changed.v1' WHERE runner_session_id = $1 AND operation_id = $2",
        "UPDATE runner_rpc_receipts SET payload_tombstoned_at_ms = payload_tombstoned_at_ms + 1 WHERE runner_session_id = $1 AND operation_id = $2",
        "UPDATE runner_rpc_receipts SET ciphertext = decode('00', 'hex') WHERE runner_session_id = $1 AND operation_id = $2",
        "DELETE FROM runner_rpc_receipts WHERE runner_session_id = $1 AND operation_id = $2",
    ] {
        sqlx::query(statement)
            .bind(request.session().session_id().as_uuid())
            .bind(request.operation_id().as_uuid())
            .execute(database.pool())
            .await
            .expect_err("tombstoned receipt state must be immutable and retained");
    }
}

async fn assert_delivery_foreign_keys_remain(database: &TestDatabase) -> TestResult {
    let constraints: Vec<String> = sqlx::query_scalar(
        r"
        SELECT conname
        FROM pg_constraint
        WHERE connamespace = current_schema()::regnamespace
          AND conname IN (
            'attempt_cancellation_delivery_command',
            'runner_lease_offer_publications_command'
        )
        ORDER BY conname
        ",
    )
    .fetch_all(database.pool())
    .await?;
    assert_eq!(
        constraints,
        vec![
            "attempt_cancellation_delivery_command".to_owned(),
            "runner_lease_offer_publications_command".to_owned(),
        ]
    );
    Ok(())
}
