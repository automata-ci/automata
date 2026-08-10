#[allow(dead_code)]
mod common;

use uuid::Uuid;

use automata_ci_core::{AttemptId, OperationId, UnixMillis};
use automata_ci_store::{
    CancellationActor, CancellationReason, CancellationRepository as _, RequestCancellation,
};

use common::{TestResult, run_with_database, run_with_unmigrated_database, seed_control_plane};

const MIGRATION: &str =
    include_str!("../migrations/0040_server_cancellation_terminal_authority.sql");
const ADMISSION_ADAPTER: &str = include_str!("../src/postgres/admission.rs");
const CANCELLATION_ADAPTER: &str = include_str!("../src/postgres/g1.rs");
const RESULT_ADAPTER: &str = include_str!("../src/postgres/logical_instance_result.rs");
const RESULT_PROJECTOR: &str =
    include_str!("../../automata-ci-workflow-service/src/result_projection.rs");

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn migration_0040_is_tagged_exact_and_current_only() {
    let migration = MIGRATOR
        .iter()
        .find(|migration| migration.version == 40)
        .expect("migration 0040 is embedded");
    assert_eq!(
        migration.description.as_ref(),
        "server cancellation terminal authority"
    );
    for required in [
        "terminal_authority TEXT NOT NULL DEFAULT 'runner'",
        "terminal_authority = 'runner'",
        "terminal_authority = 'server_cancellation'",
        "server_cancellation_operation_id UUID",
        "server_cancellation_digest BYTEA",
        "attempt_terminal_results_server_cancellation_intent_fk",
        "FOREIGN KEY (attempt_id, server_cancellation_operation_id)",
        "REFERENCES attempt_cancellation_intents (attempt_id, operation_id)",
        "conclusion = 'cancelled'",
        "runner_session_id IS NULL",
        "result_digest IS NULL",
        "result_object_key IS NULL",
        "automata_server_cancellation_terminal_digest",
        "server cancellation terminal lacks exact queued intent authority",
        "queued cancellation state must be recreated before terminal authority",
        "unmatched logical cancellation must be recreated",
        "attempt terminal result evidence is immutable",
        "WorkflowPlan-v2 instance result lacks exact terminal authority/fence evidence",
        "secret_exposure_class = 'secretless'",
        "output_count = 0",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing invariant: {required}"
        );
    }
    for prohibited in [
        "CREATE EXTENSION",
        "legacy",
        "result_object_key = ''",
        "result_size_bytes = 0",
    ] {
        assert!(
            !MIGRATION.contains(prohibited),
            "unexpected compatibility or forged-object surface: {prohibited}"
        );
    }
}

#[test]
fn cancellation_write_order_and_projection_never_forge_runner_evidence() {
    for adapter in [ADMISSION_ADAPTER, CANCELLATION_ADAPTER] {
        let intent = adapter
            .find("insert_cancellation_intent")
            .or_else(|| adapter.find("insert_preemption_intent"))
            .expect("cancellation intent insert");
        let terminal = adapter
            .find("insert_queued_server_cancellation_terminal")
            .expect("server terminal insert");
        assert!(
            intent < terminal,
            "the immutable intent must exist before its exact terminal authority"
        );
    }
    for required in [
        "LogicalInstanceTerminalAuthority::ServerCancellation",
        "server_cancellation_operation_id",
        "server_cancellation_digest",
        "decode_optional_digest(row, \"result_digest\")?.is_none()",
        "try_get::<Option<String>, _>(\"result_object_key\")",
    ] {
        assert!(
            RESULT_ADAPTER.contains(required),
            "result adapter lost server-authority handling: {required}"
        );
    }
    let instance_projection = RESULT_PROJECTOR
        .split_once("async fn project_instance(")
        .expect("instance projection")
        .1
        .split_once("async fn persist_instance(")
        .expect("bounded instance projection")
        .0;
    assert!(instance_projection.contains("CommitLogicalInstanceResult::new_server_cancellation"));
    assert!(instance_projection.contains("self.load_activation(job_ir_object, shutdown)"));
    assert!(!instance_projection.contains("JobResult::new("));
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn queued_cancellation_request_replays_one_exact_terminal_receipt() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 0).await?;
        let attempt_id = AttemptId::new();
        sqlx::query(
            r"
            INSERT INTO job_attempts (
                id, job_id, attempt_number, lifecycle, fencing_token,
                queued_at_ms, changed_at_ms
            ) VALUES ($1, $2, 1, 'queued', 0, 10, 10)
            ",
        )
        .bind(attempt_id.as_uuid())
        .bind(seed.job_id.as_uuid())
        .execute(database.pool())
        .await?;
        let request = RequestCancellation::new(
            OperationId::new(),
            attempt_id,
            CancellationActor::new("scheduler")?,
            Some(CancellationReason::new("run cancelled")?),
            UnixMillis::new(40),
        );
        let first = database
            .store()
            .request_cancellation(request.clone())
            .await?;
        let terminal_before: (Uuid, Vec<u8>, Option<i64>, i64) = sqlx::query_as(
            r"
            SELECT server_cancellation_operation_id,
                   server_cancellation_digest,
                   workflow_plan_v2_terminal_ordinal,
                   committed_at_ms
            FROM attempt_terminal_results
            WHERE attempt_id = $1
            ",
        )
        .bind(attempt_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        let replay = database.store().request_cancellation(request).await?;
        let terminal_after: (Uuid, Vec<u8>, Option<i64>, i64) = sqlx::query_as(
            r"
            SELECT server_cancellation_operation_id,
                   server_cancellation_digest,
                   workflow_plan_v2_terminal_ordinal,
                   committed_at_ms
            FROM attempt_terminal_results
            WHERE attempt_id = $1
            ",
        )
        .bind(attempt_id.as_uuid())
        .fetch_one(database.pool())
        .await?;

        assert!(!first.was_replayed());
        assert!(replay.was_replayed());
        assert_eq!(replay.request(), first.request());
        assert_eq!(terminal_after, terminal_before);
        assert_eq!(terminal_after.0, first.request().operation_id().as_uuid());
        assert_eq!(terminal_after.1.len(), 32);
        assert_eq!(terminal_after.2, None);
        assert_eq!(terminal_after.3, 40);
        let lifecycle: String =
            sqlx::query_scalar("SELECT lifecycle FROM job_attempts WHERE id = $1")
                .bind(attempt_id.as_uuid())
                .fetch_one(database.pool())
                .await?;
        assert_eq!(lifecycle, "cancelled");
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn migration_backfills_only_provable_queued_cancellation_evidence() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        MIGRATOR.run_to(39, database.pool()).await?;
        let seed = seed_control_plane(database.pool(), 0).await?;
        let attempt_id = Uuid::new_v4();
        let operation_id = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO job_attempts (
                id, job_id, attempt_number, lifecycle, fencing_token,
                queued_at_ms, changed_at_ms
            ) VALUES ($1, $2, 1, 'cancelled', 0, 10, 40)
            ",
        )
        .bind(attempt_id)
        .bind(seed.job_id.as_uuid())
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO attempt_cancellation_intents (
                attempt_id, operation_id, requested_by, reason, requested_at_ms
            ) VALUES ($1, $2, 'scheduler', 'no longer needed', 40)
            ",
        )
        .bind(attempt_id)
        .bind(operation_id)
        .execute(database.pool())
        .await?;

        MIGRATOR.run_to(40, database.pool()).await?;
        let row: (String, Uuid, bool, bool, String, i64, i64) = sqlx::query_as(
            r"
            SELECT terminal_authority, server_cancellation_operation_id,
                   server_cancellation_digest =
                       automata_server_cancellation_terminal_digest(
                           $1, $2, 'scheduler', 'no longer needed', 40
                       ),
                   num_nonnulls(
                       runner_session_id, operation_id, runner_id,
                       runner_session_epoch, runner_generation, runner_slot,
                       lease_id, fencing_token, result_schema,
                       result_size_bytes, result_digest, result_object_key
                   ) = 0,
                   conclusion, completed_at_ms, committed_at_ms
            FROM attempt_terminal_results
            WHERE attempt_id = $1
            ",
        )
        .bind(attempt_id)
        .bind(operation_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            row,
            (
                "server_cancellation".to_owned(),
                operation_id,
                true,
                true,
                "cancelled".to_owned(),
                40,
                40,
            )
        );
        assert!(
            sqlx::query(
                "UPDATE attempt_cancellation_intents SET reason = 'changed' WHERE attempt_id = $1",
            )
            .bind(attempt_id)
            .execute(database.pool())
            .await
            .is_err(),
            "terminal authority must freeze its exact cancellation intent"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn migration_refuses_non_atomic_queued_cancellation_state() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        MIGRATOR.run_to(39, database.pool()).await?;
        let seed = seed_control_plane(database.pool(), 0).await?;
        let attempt_id = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO job_attempts (
                id, job_id, attempt_number, lifecycle, fencing_token,
                queued_at_ms, changed_at_ms
            ) VALUES ($1, $2, 1, 'queued', 0, 10, 40)
            ",
        )
        .bind(attempt_id)
        .bind(seed.job_id.as_uuid())
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO attempt_cancellation_intents (
                attempt_id, operation_id, requested_by, requested_at_ms
            ) VALUES ($1, $2, 'scheduler', 40)
            ",
        )
        .bind(attempt_id)
        .bind(Uuid::new_v4())
        .execute(database.pool())
        .await?;

        let error = MIGRATOR
            .run_to(40, database.pool())
            .await
            .expect_err("current-only migration must reject split queued cancellation state");
        assert!(
            error
                .to_string()
                .contains("queued cancellation state must be recreated before terminal authority"),
            "unexpected migration rejection: {error}"
        );
        Ok(())
    })
    .await
}
