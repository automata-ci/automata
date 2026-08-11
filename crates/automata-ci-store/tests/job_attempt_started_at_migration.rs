#[allow(dead_code)]
mod common;

use automata_ci_core::{AttemptId, AttemptNumber, LeaseId, UnixMillis};
use automata_ci_store::{
    AcquireLease, InternalAttemptRepository as _, QueuedAttempt, StableRunnerSlot,
};
use sqlx::migrate::Migrate as _;

use common::{TestResult, run_with_unmigrated_database, seed_control_plane};

const MIGRATION: &str = include_str!("../migrations/0042_job_attempt_started_at.sql");

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn migration_0042_preserves_one_immutable_first_lease_start() {
    let migration = MIGRATOR
        .iter()
        .find(|migration| migration.version == 42)
        .expect("migration 0042 is embedded");
    assert_eq!(migration.description.as_ref(), "job attempt started at");
    for required in [
        "ADD COLUMN started_at_ms BIGINT",
        "SET started_at_ms = lease_issued_at_ms",
        "job_attempts_started_at_shape",
        "job_attempts_lease_after_start",
        "automata_job_attempt_started_at_guard",
        "job attempt start is immutable",
        "job attempt start requires an issued lease",
        "NEW.started_at_ms := NEW.lease_issued_at_ms",
        "BEFORE INSERT OR UPDATE ON job_attempts",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing invariant: {required}"
        );
    }
    for prohibited in ["COALESCE", "completed_at_ms", "legacy", "DEFAULT 0"] {
        assert!(
            !MIGRATION.contains(prohibited),
            "migration must not fabricate historical execution time: {prohibited}"
        );
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn live_lease_is_backfilled_and_start_survives_custody_release() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        let mut connection = database.pool().acquire().await?;
        let table_name = MIGRATOR.table_name.as_ref();
        connection.ensure_migrations_table(table_name).await?;
        for migration in MIGRATOR.iter().filter(|migration| migration.version <= 41) {
            connection.apply(table_name, migration).await?;
        }
        drop(connection);

        let seed = seed_control_plane(database.pool(), 1).await?;
        let attempt_id = AttemptId::new();
        let queued_at = database_now(database.pool()).await?;
        database
            .store()
            .insert_queued(QueuedAttempt::new(
                attempt_id,
                seed.job_id,
                AttemptNumber::new(1)?,
                queued_at,
            ))
            .await?;
        let lease_observed_at = database_now(database.pool()).await?;
        let lease = database
            .store()
            .acquire_lease(AcquireLease::new(
                attempt_id,
                LeaseId::new(),
                seed.session_fences[0],
                StableRunnerSlot::new(1)?,
                lease_observed_at,
                checked_add_millis(lease_observed_at, 60_000)?,
            )?)
            .await?;
        let started_at_ms = lease.issued_at().get();

        let mut connection = database.pool().acquire().await?;
        let migration = MIGRATOR
            .iter()
            .find(|migration| migration.version == 42)
            .expect("migration 0042");
        connection.apply(table_name, migration).await?;
        drop(connection);

        assert_eq!(
            started_at(database.pool(), attempt_id).await?,
            Some(started_at_ms)
        );

        let requeued_at = checked_add_millis(lease.issued_at(), 1)?;

        sqlx::query(
            r"
            UPDATE job_attempts
            SET lifecycle = 'queued', lease_id = NULL, runner_id = NULL,
                lease_issued_at_ms = NULL, lease_expires_at_ms = NULL,
                runner_session_id = NULL, runner_session_epoch = NULL,
                runner_generation = NULL, runner_slot = NULL,
                lease_failures = lease_failures + 1, queued_at_ms = $2,
                changed_at_ms = $2
            WHERE id = $1
            ",
        )
        .bind(attempt_id.as_uuid())
        .bind(requeued_at.get())
        .execute(database.pool())
        .await?;
        assert_eq!(
            started_at(database.pool(), attempt_id).await?,
            Some(started_at_ms)
        );

        let rewritten_start = checked_add_millis(lease.issued_at(), 1)?;
        let rewrite = sqlx::query("UPDATE job_attempts SET started_at_ms = $2 WHERE id = $1")
            .bind(attempt_id.as_uuid())
            .bind(rewritten_start.get())
            .execute(database.pool())
            .await
            .expect_err("the first execution start is immutable");
        assert_eq!(
            rewrite
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("job_attempts_started_at_immutable")
        );

        let never_leased = AttemptId::new();
        let never_leased_queued_at = checked_add_millis(requeued_at, 1)?;
        database
            .store()
            .insert_queued(QueuedAttempt::new(
                never_leased,
                seed.job_id,
                AttemptNumber::new(2)?,
                never_leased_queued_at,
            ))
            .await?;
        assert_eq!(started_at(database.pool(), never_leased).await?, None);
        Ok(())
    })
    .await
}

async fn database_now(pool: &sqlx::PgPool) -> TestResult<UnixMillis> {
    Ok(UnixMillis::new(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(pool)
            .await?,
    ))
}

fn checked_add_millis(base: UnixMillis, duration_millis: i64) -> TestResult<UnixMillis> {
    Ok(UnixMillis::new(
        base.get()
            .checked_add(duration_millis)
            .ok_or("test timestamp overflow")?,
    ))
}

async fn started_at(pool: &sqlx::PgPool, attempt_id: AttemptId) -> TestResult<Option<i64>> {
    Ok(
        sqlx::query_scalar("SELECT started_at_ms FROM job_attempts WHERE id = $1")
            .bind(attempt_id.as_uuid())
            .fetch_one(pool)
            .await?,
    )
}
