#[allow(dead_code)]
mod common;

use sqlx::migrate::Migrate as _;
use uuid::Uuid;

use common::{TestDatabase, TestResult, run_with_unmigrated_database, seed_control_plane};

const MIGRATION_VERSION: i64 = 62;
const MIGRATION: &str = include_str!("../migrations/0062_managed_secret_delivery.sql");

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn migration_0062_is_value_free_append_only_and_revision_pinned() {
    let migration = MIGRATOR
        .iter()
        .find(|migration| migration.version == MIGRATION_VERSION)
        .expect("migration 0062 is embedded");
    assert_eq!(migration.description.as_ref(), "managed secret delivery");
    for required in [
        "protected_environment_approval_revision_backfill_refused",
        "protected_environment_approval_revision_guard",
        "protected_environment_approval_resolution_current",
        "protected_environment_approval_stale_resolution",
        "protected_environment_approval_decisions_current_policy",
        "protected_environment_approval_decisions_lifetime",
        "protected_environment_approval_decisions_no_truncate",
        "secret_workload_grants_environment_current",
        "managed_secret_delivery_operations",
        "credential_sha256 BYTEA NOT NULL",
        "managed_secret_delivery_operations_no_delete",
        "managed_secret_delivery_operations_operation_unique",
        "ON DELETE RESTRICT",
        "job_attempts_expire_managed_secret_delivery",
        "runner_sessions_expire_managed_secret_delivery",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing invariant: {required}"
        );
    }
    for prohibited in [
        "credential TEXT",
        "bearer TEXT",
        "plaintext TEXT",
        "ON DELETE CASCADE",
        "SET environment_revision = environment.revision",
    ] {
        assert!(
            !MIGRATION.contains(prohibited),
            "delivery migration must not persist or guess sensitive authority: {prohibited}"
        );
    }
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn migration_refuses_to_guess_revision_for_existing_approval_evidence() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_before_0062(&database).await?;
        let seed = seed_control_plane(database.pool(), 0).await?;
        let attempt_id = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO job_attempts (
                id, job_id, attempt_number, lifecycle, fencing_token,
                queued_at_ms, changed_at_ms
            ) VALUES ($1, $2, 1, 'succeeded', 1, 1, 2)
            ",
        )
        .bind(attempt_id)
        .bind(seed.job_id.as_uuid())
        .execute(database.pool())
        .await?;
        let environment_id = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO repository_environments (
                tenant_id, repository_id, id, name, normalized_name,
                protection_mode, required_approvals, prevent_self_review,
                created_by_principal_id, created_at_ms, updated_at_ms
            ) VALUES (
                $1, $2, $3, 'Protected', 'protected',
                'required_approvals', 1, FALSE, NULL, 1, 1
            )
            ",
        )
        .bind(&seed.tenant_id)
        .bind(seed.repository_id)
        .bind(environment_id)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO protected_environment_approval_requests (
                tenant_id, repository_id, environment_id, run_id, job_id,
                attempt_id, id, required_approvals, prevent_self_review,
                requested_by_principal_id, created_at_ms, expires_at_ms
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, 1, FALSE, NULL, 2, 100)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(seed.repository_id)
        .bind(environment_id)
        .bind(seed.run_id.as_uuid())
        .bind(seed.job_id.as_uuid())
        .bind(attempt_id)
        .bind(Uuid::new_v4())
        .execute(database.pool())
        .await?;

        let migration = MIGRATOR
            .iter()
            .find(|migration| migration.version == MIGRATION_VERSION)
            .expect("migration 0062");
        let mut connection = database.pool().acquire().await?;
        let error = connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await
            .expect_err("existing approval evidence must require an explicit drain");
        match error {
            sqlx::migrate::MigrateError::ExecuteMigration(error, MIGRATION_VERSION) => {
                let database_error = error
                    .as_database_error()
                    .expect("migration refusal is a PostgreSQL error");
                assert_eq!(database_error.code().as_deref(), Some("23514"));
                assert_eq!(
                    database_error.constraint(),
                    Some("protected_environment_approval_revision_backfill_refused")
                );
            }
            other => panic!("unexpected migration error: {other}"),
        }
        drop(connection);

        let revision_column_exists: bool = sqlx::query_scalar(
            r"
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = 'protected_environment_approval_requests'
                  AND column_name = 'environment_revision'
            )
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert!(!revision_column_exists, "0062 must roll back atomically");
        Ok(())
    })
    .await
}

async fn apply_before_0062(database: &TestDatabase) -> TestResult {
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
