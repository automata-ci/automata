#[allow(dead_code)]
mod common;

use sqlx::migrate::Migrate as _;

use common::{TestDatabase, TestResult, run_with_unmigrated_database};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn liveness_0069_upgrades_forward_without_checksum_or_trigger_drift() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_through(&database, 69).await?;

        let released_checksum: Vec<u8> = sqlx::query_scalar(
            "SELECT checksum FROM _sqlx_migrations WHERE version = 69 AND success",
        )
        .fetch_one(database.pool())
        .await?;
        let old_trigger_exists: bool = sqlx::query_scalar(
            r"
            SELECT EXISTS (
                SELECT 1 FROM pg_trigger
                WHERE tgrelid = 'job_attempts'::regclass
                  AND tgname = 'job_attempts_require_current_secret_precedence_before_lease'
                  AND NOT tgisinternal
            )
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert!(old_trigger_exists);

        apply_range(&database, 70, 70).await?;

        let upgraded_checksum: Vec<u8> = sqlx::query_scalar(
            "SELECT checksum FROM _sqlx_migrations WHERE version = 69 AND success",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(upgraded_checksum, released_checksum);

        let versions: Vec<i64> = sqlx::query_scalar(
            "SELECT version FROM _sqlx_migrations \
             WHERE version BETWEEN 69 AND 70 AND success ORDER BY version",
        )
        .fetch_all(database.pool())
        .await?;
        assert_eq!(versions, [69, 70]);

        let functions: (bool, bool, bool) = sqlx::query_as(
            r"
            SELECT
                to_regprocedure(
                    'automata_require_current_secret_precedence_before_lease()'
                ) IS NULL,
                to_regprocedure(
                    'automata_job_environment_gate_ready_authority_is_current(uuid,bigint)'
                ) IS NOT NULL,
                to_regprocedure(
                    'automata_require_current_job_environment_gate_before_lease()'
                ) IS NOT NULL
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(functions, (true, true, true));

        let triggers: Vec<String> = sqlx::query_scalar(
            r"
            SELECT tgname FROM pg_trigger
            WHERE tgrelid = 'job_attempts'::regclass
              AND tgname IN (
                  'job_attempts_require_current_secret_precedence_before_lease',
                  'job_attempts_01_require_current_environment_gate_before_lease'
              )
              AND NOT tgisinternal
            ORDER BY tgname
            ",
        )
        .fetch_all(database.pool())
        .await?;
        assert_eq!(
            triggers,
            ["job_attempts_01_require_current_environment_gate_before_lease"]
        );
        Ok(())
    })
    .await
}

async fn apply_through(database: &TestDatabase, maximum: i64) -> TestResult {
    let mut connection = database.pool().acquire().await?;
    connection
        .ensure_migrations_table(MIGRATOR.table_name.as_ref())
        .await?;
    for migration in MIGRATOR
        .iter()
        .filter(|migration| migration.version <= maximum)
    {
        connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await?;
    }
    Ok(())
}

async fn apply_range(database: &TestDatabase, first: i64, last: i64) -> TestResult {
    let mut connection = database.pool().acquire().await?;
    for migration in MIGRATOR
        .iter()
        .filter(|migration| (first..=last).contains(&migration.version))
    {
        connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await?;
    }
    Ok(())
}
