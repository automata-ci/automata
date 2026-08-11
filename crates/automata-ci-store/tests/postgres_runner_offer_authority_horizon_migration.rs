#[allow(dead_code)]
mod common;

use automata_ci_core::{AttemptId, AttemptNumber, JobId, LeaseId, OperationId, UnixMillis};
use automata_ci_store::{
    AcknowledgeRunnerCommands, AcquireLease, CommandCursor, CommandSequence, DocumentSchema,
    EnqueueRunnerCommand, InternalAttemptRepository as _, RunnerCommandOutbox as _,
    RunnerCommandPayload, RunnerOperationKind, RunnerSessionFence, StableRunnerSlot,
};
use sqlx::migrate::Migrate as _;

use common::{TestDatabase, TestResult, run_with_unmigrated_database, seed_control_plane};

const MIGRATION_VERSION: i64 = 45;
const LEASE_OFFER_COMMAND_KIND: &str = "automata.runner.lease-offer.v2";
const LEASE_REQUEST_KIND: &str = "automata.runner.lease-request.v1";

type RolledBack0045Catalog = (
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    Option<String>,
    Option<String>,
    Option<String>,
);

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Clone, Copy)]
struct LegacyOfferFixture {
    attempt_id: AttemptId,
    fence: RunnerSessionFence,
    command_sequence: CommandSequence,
    request_operation_id: OperationId,
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn legacy_offer_state_blocks_0045_atomically_then_reconciled_upgrade_applies() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_before_0045(&database).await?;
        let fixture = insert_pre_horizon_offer_publication(&database).await?;
        insert_live_lease_request_receipt(&database, fixture).await?;

        let migration = MIGRATOR
            .iter()
            .find(|migration| migration.version == MIGRATION_VERSION)
            .expect("migration 0045 is embedded");
        let mut connection = database.pool().acquire().await?;
        let error = connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await
            .expect_err("a pre-horizon offer publication must fail closed");
        assert_migration_refusal(error, "runner_lease_offer_authority_horizon_upgrade");
        drop(connection);

        assert_0045_rolled_back(&database, 1).await?;

        let deleted = sqlx::query("DELETE FROM runner_lease_offer_publications")
            .execute(database.pool())
            .await?;
        assert_eq!(deleted.rows_affected(), 1);

        let mut connection = database.pool().acquire().await?;
        let error = connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await
            .expect_err("an orphaned live lease-offer command must fail closed");
        assert_migration_refusal(
            error,
            "runner_lease_offer_command_authority_horizon_upgrade",
        );
        drop(connection);

        assert_0045_rolled_back(&database, 0).await?;
        tombstone_legacy_offer_command(&database, fixture).await?;

        let mut connection = database.pool().acquire().await?;
        let error = connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await
            .expect_err("a live lease-request receipt must fail closed");
        assert_migration_refusal(
            error,
            "runner_lease_request_receipt_authority_horizon_upgrade",
        );
        drop(connection);

        assert_0045_rolled_back(&database, 0).await?;
        tombstone_legacy_lease_request_receipt(&database, fixture).await?;

        let mut connection = database.pool().acquire().await?;
        let error = connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await
            .expect_err("an active pre-database-time lease must fail closed");
        assert_migration_refusal(error, "runner_active_lease_database_time_upgrade");
        drop(connection);

        assert_0045_rolled_back(&database, 0).await?;
        reconcile_active_attempt(&database, fixture.attempt_id).await?;

        let mut connection = database.pool().acquire().await?;
        connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await?;
        drop(connection);

        assert_0045_applied(&database).await?;
        assert_reconciled_offer_history_retained(&database, fixture).await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn future_session_heartbeat_blocks_0045_atomically_then_reconciled_upgrade_applies()
-> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_before_0045(&database).await?;
        let seed = seed_control_plane(database.pool(), 1).await?;
        let session_id = seed.session_fences[0].session_id();
        let future_heartbeat: i64 = sqlx::query_scalar(
            r"
            UPDATE runner_sessions
            SET heartbeat_at_ms =
                floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT + 120000
            WHERE id = $1
            RETURNING heartbeat_at_ms
            ",
        )
        .bind(session_id.as_uuid())
        .fetch_one(database.pool())
        .await?;

        let migration = MIGRATOR
            .iter()
            .find(|migration| migration.version == MIGRATION_VERSION)
            .expect("migration 0045 is embedded");
        let mut connection = database.pool().acquire().await?;
        let error = connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await
            .expect_err("a future durable runner heartbeat must fail closed");
        assert_migration_refusal(error, "runner_database_time_upgrade");
        drop(connection);

        assert_0045_rolled_back(&database, 0).await?;
        let retained_future: bool = sqlx::query_scalar(
            r"
            SELECT heartbeat_at_ms = $2
               AND heartbeat_at_ms >
                   floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT + 60000
            FROM runner_sessions
            WHERE id = $1
            ",
        )
        .bind(session_id.as_uuid())
        .bind(future_heartbeat)
        .fetch_one(database.pool())
        .await?;
        assert!(
            retained_future,
            "the refused migration must not rewrite durable time"
        );

        let reconciled = sqlx::query(
            r"
            UPDATE runner_sessions
            SET heartbeat_at_ms = greatest(
                connected_at_ms,
                floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT
            )
            WHERE id = $1
            ",
        )
        .bind(session_id.as_uuid())
        .execute(database.pool())
        .await?;
        assert_eq!(reconciled.rows_affected(), 1);

        let mut connection = database.pool().acquire().await?;
        connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await?;
        drop(connection);

        assert_0045_applied(&database).await?;
        Ok(())
    })
    .await
}

async fn apply_before_0045(database: &TestDatabase) -> TestResult {
    let mut connection = database.pool().acquire().await?;
    connection
        .ensure_migrations_table(MIGRATOR.table_name.as_ref())
        .await?;
    for migration in MIGRATOR
        .iter()
        .filter(|migration| migration.version < MIGRATION_VERSION)
    {
        connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await?;
    }
    Ok(())
}

fn assert_migration_refusal(error: sqlx::migrate::MigrateError, expected_constraint: &str) {
    match error {
        sqlx::migrate::MigrateError::ExecuteMigration(error, MIGRATION_VERSION) => {
            let database_error = error
                .as_database_error()
                .expect("migration refusal is a PostgreSQL error");
            assert_eq!(database_error.code().as_deref(), Some("23514"));
            assert_eq!(database_error.constraint(), Some(expected_constraint));
        }
        other => panic!("unexpected migration error: {other}"),
    }
}

async fn assert_0045_rolled_back(
    database: &TestDatabase,
    expected_publications: i64,
) -> TestResult {
    let rolled_back: RolledBack0045Catalog = sqlx::query_as(
        r"
        SELECT
            (SELECT count(*) FROM runner_lease_offer_publications),
            (SELECT count(*) FROM information_schema.columns
             WHERE table_schema = current_schema()
               AND table_name = 'runner_lease_offer_publications'
               AND column_name = 'offer_valid_until_ms'),
            (SELECT count(*) FROM _sqlx_migrations
             WHERE version = 45 AND success),
            (SELECT count(*) FROM information_schema.columns
             WHERE table_schema = current_schema()
               AND table_name = 'runner_rpc_receipts'
               AND column_name IN (
                   'lease_offer_request_operation_id',
                   'lease_offer_command_sequence',
                   'lease_offer_response_disposition',
                   'lease_offer_primary_response_schema',
                   'lease_offer_primary_response_digest',
                   'lease_offer_fallback_version',
                   'lease_offer_fallback_operation_id',
                   'lease_offer_fallback_retry_after_millis',
                   'lease_offer_fallback_response_schema',
                   'lease_offer_fallback_response_digest'
               )),
            (SELECT count(*) FROM pg_constraint
             WHERE connamespace = current_schema()::regnamespace
               AND conname IN (
                   'runner_rpc_receipts_lease_offer_binding_shape',
                   'runner_rpc_receipts_lease_offer_completion_shape',
                   'runner_rpc_receipts_lease_offer_publication'
               )),
            (SELECT count(*) FROM pg_trigger
             WHERE tgrelid = 'runner_rpc_receipts'::regclass
               AND tgname = 'runner_rpc_receipt_lease_offer_binding_guard'),
            (SELECT count(*) FROM information_schema.columns
             WHERE table_schema = current_schema()
               AND table_name = 'runner_lease_offer_publications'
               AND column_name IN (
                   'delivery_revoked_at_ms', 'delivery_revocation_reason'
               )),
            to_regprocedure(
                'automata_enforce_runner_lease_offer_authority_horizon()'
            )::TEXT,
            to_regprocedure(
                'automata_enforce_runner_lease_offer_delivery_revocation()'
            )::TEXT,
            to_regprocedure(
                'automata_enforce_runner_rpc_receipt_lease_offer_binding()'
            )::TEXT
        ",
    )
    .fetch_one(database.pool())
    .await?;
    assert_eq!(
        rolled_back,
        (expected_publications, 0, 0, 0, 0, 0, 0, None, None, None,)
    );
    Ok(())
}

async fn assert_0045_applied(database: &TestDatabase) -> TestResult {
    let applied: (
        i64,
        Option<String>,
        i64,
        i64,
        i64,
        i64,
        i64,
        Option<String>,
        i64,
    ) = sqlx::query_as(
        r"
        SELECT
            (SELECT count(*) FROM information_schema.columns
             WHERE table_schema = current_schema()
               AND table_name = 'runner_lease_offer_publications'
               AND column_name IN (
                   'offer_valid_until_ms', 'delivery_revoked_at_ms',
                   'delivery_revocation_reason'
               )),
            (SELECT is_nullable FROM information_schema.columns
             WHERE table_schema = current_schema()
               AND table_name = 'runner_lease_offer_publications'
               AND column_name = 'offer_valid_until_ms'),
            (SELECT count(*) FROM pg_constraint
             WHERE connamespace = current_schema()::regnamespace
               AND conname IN (
                   'runner_lease_offer_publications_receipt_binding_unique',
                   'runner_lease_offer_publications_command_unique',
                   'runner_lease_offer_publications_authority_horizon',
                   'runner_lease_offer_publications_delivery_revocation'
               )),
            (SELECT count(*) FROM pg_trigger
             WHERE tgrelid = 'runner_lease_offer_publications'::regclass
               AND tgname IN (
                   'runner_lease_offer_authority_horizon_guard',
                   'runner_lease_offer_delivery_revocation_guard'
               )),
            (SELECT count(*) FROM information_schema.columns
             WHERE table_schema = current_schema()
               AND table_name = 'runner_rpc_receipts'
               AND column_name IN (
                   'lease_offer_request_operation_id',
                   'lease_offer_command_sequence',
                   'lease_offer_response_disposition',
                   'lease_offer_primary_response_schema',
                   'lease_offer_primary_response_digest',
                   'lease_offer_fallback_version',
                   'lease_offer_fallback_operation_id',
                   'lease_offer_fallback_retry_after_millis',
                   'lease_offer_fallback_response_schema',
                   'lease_offer_fallback_response_digest'
               )),
            (SELECT count(*) FROM pg_constraint
             WHERE connamespace = current_schema()::regnamespace
               AND conname IN (
                   'runner_rpc_receipts_lease_offer_binding_shape',
                   'runner_rpc_receipts_lease_offer_completion_shape',
                   'runner_rpc_receipts_lease_offer_publication'
               )),
            (SELECT count(*) FROM pg_trigger
             WHERE tgrelid = 'runner_rpc_receipts'::regclass
               AND tgname = 'runner_rpc_receipt_lease_offer_binding_guard'),
            to_regprocedure(
                'automata_enforce_runner_rpc_receipt_lease_offer_binding()'
            )::TEXT,
            (SELECT count(*) FROM _sqlx_migrations
             WHERE version = 45 AND success)
        ",
    )
    .fetch_one(database.pool())
    .await?;
    assert_eq!(
        applied,
        (
            3,
            Some("NO".to_owned()),
            4,
            2,
            10,
            3,
            1,
            Some("automata_enforce_runner_rpc_receipt_lease_offer_binding()".to_owned()),
            1,
        )
    );
    Ok(())
}

async fn insert_pre_horizon_offer_publication(
    database: &TestDatabase,
) -> TestResult<LegacyOfferFixture> {
    let seed = seed_control_plane(database.pool(), 1).await?;
    let fence = seed.session_fences[0];
    let database_now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(database.pool())
            .await?;
    let lease_expires_at = database_now
        .checked_add(120_000)
        .ok_or("test lease expiry overflowed PostgreSQL BIGINT")?;
    let attempt_id = AttemptId::new();
    insert_legacy_queued_attempt(database, attempt_id, seed.job_id, database_now).await?;
    let lease = database
        .store()
        .acquire_lease(AcquireLease::new(
            attempt_id,
            LeaseId::new(),
            fence,
            StableRunnerSlot::new(1)?,
            UnixMillis::new(database_now),
            UnixMillis::new(lease_expires_at),
        )?)
        .await?;

    let command = database
        .store()
        .enqueue_command(EnqueueRunnerCommand::new(
            fence,
            OperationId::new(),
            RunnerOperationKind::new(LEASE_OFFER_COMMAND_KIND)?,
            RunnerCommandPayload::new(
                DocumentSchema::new(1)?,
                b"pre-horizon lease offer".to_vec(),
            )?,
            lease.issued_at(),
        ))
        .await?;
    let request_operation_id = OperationId::new();

    let inserted = sqlx::query(
        r"
        INSERT INTO runner_lease_offer_publications (
            runner_session_id, request_operation_id, runner_id,
            runner_session_epoch, runner_generation, operation_kind,
            request_digest, protocol_version, runner_slot,
            attempt_id, lease_id, fencing_token, lease_issued_at_ms,
            lease_expires_at_ms, job_id, run_id, job_ir_schema,
            job_ir_size_bytes, job_ir_digest, job_ir_object_key,
            command_sequence, created_at_ms
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, 4, 1,
            $8, $9, $10, $11, $12, $13, $14, 5,
            128, $15, 'test/job-ir', $16, $11
        )
        ",
    )
    .bind(fence.session_id().as_uuid())
    .bind(request_operation_id.as_uuid())
    .bind(fence.runner_id().as_uuid())
    .bind(i64::try_from(fence.session_epoch().get())?)
    .bind(i64::try_from(fence.runner_generation().get())?)
    .bind(LEASE_REQUEST_KIND)
    .bind(vec![0x45_u8; 32])
    .bind(lease.attempt_id().as_uuid())
    .bind(lease.lease_id().as_uuid())
    .bind(i64::try_from(lease.fencing_token().get())?)
    .bind(lease.issued_at().get())
    .bind(lease.expires_at().get())
    .bind(seed.job_id.as_uuid())
    .bind(seed.run_id.as_uuid())
    .bind(vec![11_u8; 32])
    .bind(i64::try_from(command.sequence().get())?)
    .execute(database.pool())
    .await?;
    assert_eq!(inserted.rows_affected(), 1);
    Ok(LegacyOfferFixture {
        attempt_id,
        fence,
        command_sequence: command.sequence(),
        request_operation_id,
    })
}

async fn insert_legacy_queued_attempt(
    database: &TestDatabase,
    attempt_id: AttemptId,
    job_id: JobId,
    queued_at_ms: i64,
) -> TestResult {
    let inserted = sqlx::query(
        r"
        INSERT INTO job_attempts (
            id, job_id, attempt_number, lifecycle, fencing_token,
            lease_failures, queued_at_ms, changed_at_ms,
            secret_exposure_class, raw_log_disposition,
            requested_log_visibility, effective_log_visibility,
            output_safety_reason, output_safety_schema, classified_at_ms
        ) VALUES (
            $1, $2, $3, 'queued', 0, 0, $4, $4,
            'readable_secret', 'suppress_user_output',
            'private', 'private', 'repository_policy', 1, $4
        )
        ",
    )
    .bind(attempt_id.as_uuid())
    .bind(job_id.as_uuid())
    .bind(i32::try_from(AttemptNumber::new(1)?.get())?)
    .bind(queued_at_ms)
    .execute(database.pool())
    .await?;
    assert_eq!(inserted.rows_affected(), 1);
    Ok(())
}

async fn tombstone_legacy_offer_command(
    database: &TestDatabase,
    fixture: LegacyOfferFixture,
) -> TestResult {
    let observed_at = UnixMillis::new(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(database.pool())
            .await?,
    );
    let acknowledged = database
        .store()
        .acknowledge_commands(AcknowledgeRunnerCommands::new(
            fixture.fence,
            CommandCursor::through(fixture.command_sequence),
            observed_at,
        ))
        .await?;
    assert_eq!(
        acknowledged,
        CommandCursor::through(fixture.command_sequence)
    );
    let tombstone: Option<String> = sqlx::query_scalar(
        r"
        SELECT payload_tombstone_reason
        FROM runner_command_outbox
        WHERE runner_session_id = $1 AND command_sequence = $2
        ",
    )
    .bind(fixture.fence.session_id().as_uuid())
    .bind(i64::try_from(fixture.command_sequence.get())?)
    .fetch_one(database.pool())
    .await?;
    assert_eq!(tombstone.as_deref(), Some("acknowledged"));
    Ok(())
}

async fn insert_live_lease_request_receipt(
    database: &TestDatabase,
    fixture: LegacyOfferFixture,
) -> TestResult {
    let inserted = sqlx::query(
        r"
        INSERT INTO runner_rpc_receipts (
            runner_session_id, operation_id, runner_id,
            runner_session_epoch, runner_generation, operation_kind,
            request_digest, response_schema, response_digest, committed_at_ms,
            tenant_id, response_plaintext_size_bytes, envelope_schema,
            wrapping_key_id, wrapped_data_key, nonce, ciphertext
        )
        SELECT $1, $2, $3, $4, $5, $6, $7, 1, $8,
               floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT,
               runner.tenant_id, 1, 1, 'fixture-key', $9, $10, $11
        FROM runners AS runner
        WHERE runner.id = $3
        ",
    )
    .bind(fixture.fence.session_id().as_uuid())
    .bind(fixture.request_operation_id.as_uuid())
    .bind(fixture.fence.runner_id().as_uuid())
    .bind(i64::try_from(fixture.fence.session_epoch().get())?)
    .bind(i64::try_from(fixture.fence.runner_generation().get())?)
    .bind(LEASE_REQUEST_KIND)
    .bind(vec![0x45_u8; 32])
    .bind(vec![0x47_u8; 32])
    .bind(vec![0x48_u8])
    .bind(vec![0x49_u8; 12])
    .bind(vec![0x4a_u8; 17])
    .execute(database.pool())
    .await?;
    assert_eq!(inserted.rows_affected(), 1);
    Ok(())
}

async fn tombstone_legacy_lease_request_receipt(
    database: &TestDatabase,
    fixture: LegacyOfferFixture,
) -> TestResult {
    let mut transaction = database.pool().begin().await?;
    let decision_at: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(&mut *transaction)
            .await?;
    let disconnected = sqlx::query(
        r"
        UPDATE runner_sessions
        SET disconnected_at_ms = $2
        WHERE id = $1 AND disconnected_at_ms IS NULL
        ",
    )
    .bind(fixture.fence.session_id().as_uuid())
    .bind(decision_at)
    .execute(&mut *transaction)
    .await?;
    assert_eq!(disconnected.rows_affected(), 1);
    let tombstoned = sqlx::query(
        r"
        UPDATE runner_rpc_receipts
        SET envelope_schema = NULL,
            wrapping_key_id = NULL,
            wrapped_data_key = NULL,
            nonce = NULL,
            ciphertext = NULL,
            payload_tombstone_reason = 'session_closed',
            payload_tombstoned_at_ms = $3
        WHERE runner_session_id = $1 AND operation_id = $2
          AND operation_kind = $4
          AND payload_tombstone_reason IS NULL
        ",
    )
    .bind(fixture.fence.session_id().as_uuid())
    .bind(fixture.request_operation_id.as_uuid())
    .bind(decision_at)
    .bind(LEASE_REQUEST_KIND)
    .execute(&mut *transaction)
    .await?;
    assert_eq!(tombstoned.rows_affected(), 1);
    transaction.commit().await?;

    let retained: (i64, Option<String>) = sqlx::query_as(
        r"
        SELECT count(*), max(payload_tombstone_reason)
        FROM runner_rpc_receipts
        WHERE runner_session_id = $1 AND operation_id = $2
        ",
    )
    .bind(fixture.fence.session_id().as_uuid())
    .bind(fixture.request_operation_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(retained, (1, Some("session_closed".to_owned())));
    Ok(())
}

async fn reconcile_active_attempt(database: &TestDatabase, attempt_id: AttemptId) -> TestResult {
    let reconciled = sqlx::query(
        r"
        UPDATE job_attempts
        SET lifecycle = 'lost',
            lease_id = NULL,
            runner_id = NULL,
            lease_issued_at_ms = NULL,
            lease_expires_at_ms = NULL,
            runner_session_id = NULL,
            runner_session_epoch = NULL,
            runner_generation = NULL,
            runner_slot = NULL,
            lease_failures = lease_failures + 1,
            changed_at_ms = greatest(
                changed_at_ms,
                floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT
            )
        WHERE id = $1
        ",
    )
    .bind(attempt_id.as_uuid())
    .execute(database.pool())
    .await?;
    assert_eq!(reconciled.rows_affected(), 1);
    Ok(())
}

async fn assert_reconciled_offer_history_retained(
    database: &TestDatabase,
    fixture: LegacyOfferFixture,
) -> TestResult {
    let history: (
        Option<String>,
        Option<String>,
        Option<uuid::Uuid>,
        Option<i64>,
    ) = sqlx::query_as(
        r"
            SELECT command.payload_tombstone_reason,
                   receipt.payload_tombstone_reason,
                   receipt.lease_offer_request_operation_id,
                   receipt.lease_offer_command_sequence
            FROM runner_command_outbox AS command
            JOIN runner_rpc_receipts AS receipt
              ON receipt.runner_session_id = command.runner_session_id
             AND receipt.operation_id = $3
            WHERE command.runner_session_id = $1
              AND command.command_sequence = $2
            ",
    )
    .bind(fixture.fence.session_id().as_uuid())
    .bind(i64::try_from(fixture.command_sequence.get())?)
    .bind(fixture.request_operation_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(
        history,
        (
            Some("acknowledged".to_owned()),
            Some("session_closed".to_owned()),
            None,
            None,
        ),
        "0045 must retain non-replayable command and receipt history without inventing a binding"
    );
    Ok(())
}
