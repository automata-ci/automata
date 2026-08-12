#[allow(dead_code)]
mod common;

use sha2::{Digest as _, Sha256};
use sqlx::migrate::Migrate as _;

use common::{TestResult, run_with_unmigrated_database, seed_control_plane};

const ACTIVATION_MIGRATION: &str =
    include_str!("../migrations/0020_logical_activation_publication.sql");
const MATERIALIZATION_MIGRATION: &str =
    include_str!("../migrations/0021_workflow_plan_v2_concrete_jobs.sql");
const UPGRADE_MIGRATION: &str =
    include_str!("../migrations/0054_runner_requirements_schema_v3.sql");

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn released_job_ir_v5_foundation_retains_runner_requirements_v2() {
    let activation: [u8; 32] = Sha256::digest(ACTIVATION_MIGRATION.as_bytes()).into();
    let materialization: [u8; 32] = Sha256::digest(MATERIALIZATION_MIGRATION.as_bytes()).into();
    assert_eq!(
        activation,
        decode_hex("cb355c160d0b7373c86400d6d35a22596d9e9a4ff7e2170d236680494d7cbcbc")
    );
    assert_eq!(
        materialization,
        decode_hex("88a80c735c76d8be84c8f89a057b4a4c6df959ff70bc1246f71bfab008c8d382")
    );
    for required in [
        "runner_requirements_schema = 2",
        "requirements @> '{\"schema_version\": 2}'::jsonb",
    ] {
        assert!(
            ACTIVATION_MIGRATION.contains(required),
            "released JobIR-v5 foundation changed: {required}"
        );
    }
    assert!(
        MATERIALIZATION_MIGRATION.contains("requirements @> '{\"schema_version\": 2}'::jsonb"),
        "released logical materialization must retain requirements v2"
    );
}

#[test]
fn migration_0054_drains_v2_and_requires_v3_for_new_work() {
    let migration = MIGRATOR
        .iter()
        .find(|migration| migration.version == 54)
        .expect("migration 0054 is embedded");
    assert_eq!(
        migration.description.as_ref(),
        "runner requirements schema v3"
    );
    for required in [
        "runner_requirements_v3_live_attempts_refused",
        "runner_requirements_v3_live_runs_refused",
        "runner_requirements_v3_live_sessions_refused",
        "runner_sessions_live_protocol_v5",
        "SET runner_requirements_schema = 3",
        "requirements @> '{\"schema_version\": 3}'::jsonb",
        "requirements ? 'resource_allocation'",
        "jobs_00_require_runner_requirements_v3",
        "workflow_plan_v2_concrete_jobs_00_require_runner_requirements_v3",
        "job_attempts_00_require_runner_requirements_v3",
        "workflow_runs_00_require_runner_requirements_v3",
        "workflow_plan_v2_runs_00_require_runner_requirements_v3",
    ] {
        assert!(
            UPGRADE_MIGRATION.contains(required),
            "requirements-v3 upgrade is missing: {required}"
        );
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn terminal_v2_history_is_retained_but_cannot_be_resurrected() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        let mut connection = database.pool().acquire().await?;
        connection
            .ensure_migrations_table(MIGRATOR.table_name.as_ref())
            .await?;
        for migration in MIGRATOR.iter().filter(|migration| migration.version <= 53) {
            connection
                .apply(MIGRATOR.table_name.as_ref(), migration)
                .await?;
        }
        drop(connection);

        let seed = seed_control_plane(database.pool(), 1).await?;
        let migration = MIGRATOR
            .iter()
            .find(|migration| migration.version == 54)
            .expect("migration 0054");
        let mut connection = database.pool().acquire().await?;
        let live_run = connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await
            .expect_err("schema-v2 queued workflow runs must be drained");
        assert_migration_constraint(
            live_run,
            "runner_requirements_v3_live_runs_refused",
        );
        drop(connection);

        sqlx::query("ALTER TABLE workflow_runs DISABLE TRIGGER USER")
            .execute(database.pool())
            .await?;
        let terminal = sqlx::query(
            "UPDATE workflow_runs SET status = 'completed', updated_at_ms = 2 WHERE id = $1",
        )
        .bind(seed.run_id.as_uuid())
        .execute(database.pool())
        .await;
        let restored = sqlx::query("ALTER TABLE workflow_runs ENABLE TRIGGER USER")
            .execute(database.pool())
            .await;
        assert_eq!(terminal?.rows_affected(), 1);
        restored?;

        let mut connection = database.pool().acquire().await?;
        let live_session = connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await
            .expect_err("live protocol-v4 sessions must be drained");
        assert_migration_constraint(
            live_session,
            "runner_requirements_v3_live_sessions_refused",
        );
        drop(connection);

        sqlx::query(
            "UPDATE runner_sessions SET disconnected_at_ms = heartbeat_at_ms WHERE disconnected_at_ms IS NULL",
        )
        .execute(database.pool())
        .await?;

        let mut connection = database.pool().acquire().await?;
        connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await?;
        drop(connection);

        let compatibility: (i32, i32, i32) = sqlx::query_as(
            "SELECT minimum_admission_epoch, job_ir_schema, runner_requirements_schema FROM automata_cluster_compatibility WHERE singleton",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(compatibility, (4, 5, 3));
        let retained: (i16, i32) = sqlx::query_as(
            r"
            SELECT run.runner_requirements_schema,
                   (job.requirements->>'schema_version')::INTEGER
            FROM workflow_runs AS run
            JOIN jobs AS job ON job.run_id = run.id
            WHERE run.id = $1
            ",
        )
        .bind(seed.run_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(retained, (2, 2));

        let resurrection = sqlx::query(
            r"
            INSERT INTO job_attempts (
                id, job_id, attempt_number, lifecycle, queued_at_ms, changed_at_ms
            ) VALUES ($1,$2,1,'queued',3,3)
            ",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(seed.job_id.as_uuid())
        .execute(database.pool())
        .await
        .expect_err("terminal runner-requirements v2 history must not become runnable again");
        let database_error = resurrection
            .as_database_error()
            .expect("resurrection rejection is a PostgreSQL error");
        assert_eq!(
            database_error.constraint(),
            Some("job_attempts_runner_requirements_v3_new_only")
        );
        Ok(())
    })
    .await
}

fn decode_hex(value: &str) -> [u8; 32] {
    let mut digest = [0_u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).expect("hex digest");
    }
    digest
}

fn assert_migration_constraint(error: sqlx::migrate::MigrateError, expected: &str) {
    match error {
        sqlx::migrate::MigrateError::ExecuteMigration(error, 54) => {
            let database_error = error
                .as_database_error()
                .expect("migration refusal is a PostgreSQL error");
            assert_eq!(database_error.constraint(), Some(expected));
        }
        other => panic!("unexpected migration error: {other}"),
    }
}
