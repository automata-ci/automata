#[allow(dead_code)]
mod common;

use std::time::Duration;

use sqlx::migrate::Migrate as _;
use uuid::Uuid;

use common::{TestDatabase, TestResult, run_with_database, run_with_unmigrated_database};

const MIGRATION: &str = include_str!("../migrations/0035_github_provider_manifest.sql");
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn migration_is_current_only_immutable_exact_and_value_free() {
    for required in [
        "github_provider_manifest_current_only",
        "CREATE TABLE github_provider_manifest_revisions",
        "CREATE TABLE github_provider_manifest_current",
        "github_provider_manifest_current_repository_unique",
        "manifest_revision <> 1",
        "NEW.manifest_revision <> OLD.manifest_revision + 1",
        "github_provider_manifest_revisions_immutable",
        "github_provider_manifest_current_removal_forbidden",
        "github_provider_manifest_repository_exact",
        "github_provider_manifest_repository_identity_immutable",
        "repository_visibility IN ('public', 'private')",
        "repository_visibility = 'public'",
        "repository_visibility = 'private'",
        "github_app_installation_token",
        "workflow_path = '.ci/workflows/ci.yml'",
        "event_name = 'push'",
        "git_ref = 'refs/heads/main'",
        "github_web_origin = 'https://github.com/'",
        "github_api_origin = 'https://api.github.com/'",
        "github_archive_origin = 'https://codeload.github.com/'",
        "github_rest_api_version = '2026-03-10'",
        "github_rest_accept = 'application/vnd.github+json'",
        "github_archive_accept = 'application/octet-stream'",
        "github_app_client_id ~ '^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$'",
        "webhook_max_body_bytes = 26214400",
        "webhook_accept_timeout_ms = 7000",
        "push_webhook_max_commits = 2048",
        "path_filter_max_commits = 1000",
        "path_filter_max_changed_files = 3000",
        "archive_max_compressed_bytes = 268435456",
        "archive_max_decompressed_bytes = 2147483648",
        "archive_max_entries = 100000",
        "archive_max_expanded_bytes = 1073741824",
        "archive_max_entry_path_bytes = 4096",
        "archive_max_workflows = 256",
        "workflow_max_bytes = 1048576",
        "app_evidence_changed OR verifier_evidence_changed OR policy_evidence_changed",
        "webhook_verifier_fingerprint_sha256",
        "webhook_verifier_revision",
        "LOCK TABLE provider_delivery_inbox IN SHARE ROW EXCLUSIVE MODE",
        "LOCK TABLE github_check_subjects IN SHARE ROW EXCLUSIVE MODE",
        "github_provider_manifest_unpinned_delivery_forbidden",
        "github_provider_manifest_unpinned_check_forbidden",
        "replace only with mandatory atomic manifest pinning",
        "automata_github_provider_repository_id",
        "automata_github_provider_manifest_digest",
        "github_provider_manifest_revisions_repository_id_canonical",
        "github_provider_manifest_revisions_digest_canonical",
        "pg_catalog.sha256",
        "provider_delivery_inbox",
        "github_check_subjects",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing invariant: {required}"
        );
    }
    for prohibited in [
        "access_token",
        "webhook_secret",
        "private_key",
        "credential_bytes",
        "CREATE EXTENSION",
        "UPDATE provider_delivery_inbox",
        "UPDATE github_check_subjects",
        "DELETE FROM provider_delivery_inbox",
        "DELETE FROM github_check_subjects",
    ] {
        assert!(
            !MIGRATION.contains(prohibited),
            "forbidden value/backfill surface: {prohibited}"
        );
    }
}

#[test]
fn repository_name_constraint_has_exact_component_bounds() {
    for exact in [
        "BETWEEN 1 AND 39",
        "BETWEEN 1 AND 100",
        "array_length(string_to_array(github_repository_name, '/'), 1) = 2",
        "!~ '--'",
        "NOT IN ('.', '..')",
        "!~* '[.]git$'",
    ] {
        assert!(MIGRATION.contains(exact), "missing name bound: {exact}");
    }
    assert!(!MIGRATION.contains("BETWEEN 3 AND 140"));
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn pre_manifest_delivery_and_check_state_fail_without_backfill() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_before_0035(&database).await?;
        insert_ambiguous_github_state(&database).await?;

        let mut connection = database.pool().acquire().await?;
        let migration = MIGRATOR
            .iter()
            .find(|migration| migration.version == 35)
            .expect("migration 0035");
        let error = connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await
            .expect_err("unmanifested provider state must fail closed");
        match error {
            sqlx::migrate::MigrateError::ExecuteMigration(error, 35) => {
                assert_constraint(&error, "github_provider_manifest_current_only");
            }
            other => panic!("unexpected migration error: {other}"),
        }
        drop(connection);

        let rollback: (i64, i64, Option<String>, Option<String>, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM provider_delivery_inbox),
                (SELECT count(*) FROM github_check_subjects),
                to_regclass('github_provider_manifest_revisions')::TEXT,
                to_regclass('github_provider_manifest_current')::TEXT,
                (SELECT count(*) FROM _sqlx_migrations WHERE success)
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(rollback, (1, 1, None, None, 34));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn post_migration_direct_unpinned_delivery_and_check_inserts_fail_closed() -> TestResult {
    run_with_database(|database| async move {
        sqlx::query(
            "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) \
             VALUES ('unmanifested', 'Unmanifested', 1, 1)",
        )
        .execute(database.pool())
        .await?;
        let delivery = Uuid::new_v4();
        let connection = Uuid::new_v4();
        let repository = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO repositories (
                id, tenant_id, scm_provider, provider_repository_id,
                owner, name, created_at_ms, updated_at_ms
            ) VALUES (
                $1, 'unmanifested', 'github', '202',
                'automata-ci', 'automata', 1, 1
            )
            ",
        )
        .bind(repository)
        .execute(database.pool())
        .await?;
        assert_direct_unpinned_delivery_is_guarded(&database, delivery, connection).await?;

        let subject = Uuid::new_v4();
        let check_delivery = Uuid::new_v4();
        let mut transaction = database.pool().begin().await?;
        sqlx::query(
            r"
            INSERT INTO provider_delivery_inbox (
                id, tenant_id, provider, connection_id, installation_id,
                provider_repository_id, repository_visibility,
                repository_identity, delivery_id, request_digest,
                raw_event_digest, raw_event_object_key, raw_event_size_bytes,
                raw_event_media_type, accepted_at_ms, state_updated_at_ms
            ) VALUES (
                $1, 'unmanifested', 'github', $2, 101, 202, 'public',
                'automata-ci/automata', 'post-migration-check-delivery', $3, $4,
                'guard/check-event', 128, 'application/json', 11, 11
            )
            ",
        )
        .bind(check_delivery)
        .bind(connection)
        .bind(vec![3_u8; 32])
        .bind(vec![4_u8; 32])
        .execute(&mut *transaction)
        .await?;
        let check_error = sqlx::query(
            r"
            INSERT INTO github_check_subjects (
                id, tenant_id, repository_id, provider_delivery_id, subject_key,
                provider_connection_id, provider_installation_id,
                github_repository_id, github_app_id, head_sha, check_name,
                external_id, created_at_ms, desired_updated_at_ms,
                github_repository_name
            ) VALUES (
                $1, 'unmanifested', $2, $3, '.ci/workflows/ci.yml',
                $4, 101, 202, 303, $5, 'Automata CI',
                'automata-check:' || $1::TEXT, 11, 11,
                'automata-ci/automata'
            )
            ",
        )
        .bind(subject)
        .bind(repository)
        .bind(check_delivery)
        .bind(connection)
        .bind(vec![9_u8; 20])
        .execute(&mut *transaction)
        .await
        .expect_err("post-migration direct Check insert must be guarded");
        assert_constraint(
            &check_error,
            "github_check_subjects_delivery_evidence_exact",
        );
        transaction.rollback().await?;
        Ok(())
    })
    .await
}

async fn assert_direct_unpinned_delivery_is_guarded(
    database: &TestDatabase,
    delivery: Uuid,
    connection: Uuid,
) -> TestResult {
    let delivery_error = sqlx::query(
        r"
        INSERT INTO provider_delivery_inbox (
            id, tenant_id, provider, connection_id, installation_id,
            provider_repository_id, repository_visibility,
            repository_identity, delivery_id, request_digest,
            raw_event_digest, raw_event_object_key, raw_event_size_bytes,
            raw_event_media_type, accepted_at_ms, state_updated_at_ms
        ) VALUES (
            $1, 'unmanifested', 'github', $2, 101, 202, 'public',
            'automata-ci/automata', 'post-migration-delivery', $3, $4,
            'guard/event', 128, 'application/json', 10, 10
        )
        ",
    )
    .bind(delivery)
    .bind(connection)
    .bind(vec![1_u8; 32])
    .bind(vec![2_u8; 32])
    .execute(database.pool())
    .await
    .expect_err("post-migration direct GitHub delivery insert must be guarded");
    assert_constraint(&delivery_error, "github_delivery_atomic_evidence_required");
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn concurrent_pre_manifest_writer_is_serialized_before_the_audit() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_before_0035(&database).await?;
        let tenant = format!("manifest-race-{}", Uuid::new_v4().simple());
        sqlx::query(
            "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) \
             VALUES ($1, 'Manifest race', 1, 1)",
        )
        .bind(&tenant)
        .execute(database.pool())
        .await?;

        let mut writer = database.pool().begin().await?;
        sqlx::query(
            r"
            INSERT INTO provider_delivery_inbox (
                id, tenant_id, provider, connection_id, installation_id,
                provider_repository_id, repository_visibility,
                repository_identity, delivery_id, request_digest,
                raw_event_digest, raw_event_object_key, raw_event_size_bytes,
                raw_event_media_type, accepted_at_ms, state_updated_at_ms
            ) VALUES (
                $1, $2, 'github', $3, 101, 202, 'public',
                'automata-ci/automata', 'racing-delivery', $4, $5,
                'race/event', 128, 'application/json', 10, 10
            )
            ",
        )
        .bind(Uuid::new_v4())
        .bind(&tenant)
        .bind(Uuid::new_v4())
        .bind(vec![1_u8; 32])
        .bind(vec![2_u8; 32])
        .execute(&mut *writer)
        .await?;

        let mut migration_connection = database.pool().acquire().await?;
        let migration_backend_pid: i32 = sqlx::query_scalar("SELECT pg_catalog.pg_backend_pid()")
            .fetch_one(&mut *migration_connection)
            .await?;
        let migration = MIGRATOR
            .iter()
            .find(|migration| migration.version == 35)
            .expect("migration 0035");
        let apply = tokio::spawn(async move {
            migration_connection
                .apply(MIGRATOR.table_name.as_ref(), migration)
                .await
        });

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let waiting: bool = sqlx::query_scalar(
                    r"
                    SELECT EXISTS (
                        SELECT 1
                        FROM pg_catalog.pg_locks
                        WHERE pid = $1
                          AND relation = 'provider_delivery_inbox'::regclass
                          AND mode = 'ShareRowExclusiveLock'
                          AND NOT granted
                    )
                    ",
                )
                .bind(migration_backend_pid)
                .fetch_one(database.pool())
                .await
                .expect("lock observation");
                if waiting {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("migration must wait behind the preexisting writer");

        writer.commit().await?;
        let error = apply
            .await?
            .expect_err("the serialized audit must observe the committed racing row");
        match error {
            sqlx::migrate::MigrateError::ExecuteMigration(error, 35) => {
                assert_constraint(&error, "github_provider_manifest_current_only");
            }
            other => panic!("unexpected migration error: {other}"),
        }
        let migrated: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 35 AND success)",
        )
        .fetch_one(database.pool())
        .await?;
        assert!(!migrated);
        Ok(())
    })
    .await
}

async fn apply_before_0035(database: &TestDatabase) -> TestResult {
    let mut connection = database.pool().acquire().await?;
    connection
        .ensure_migrations_table(MIGRATOR.table_name.as_ref())
        .await?;
    for migration in MIGRATOR.iter().filter(|migration| migration.version < 35) {
        connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // One fixture establishes both ambiguous durable surfaces.
async fn insert_ambiguous_github_state(database: &TestDatabase) -> TestResult {
    let tenant = format!("manifest-upgrade-{}", Uuid::new_v4().simple());
    let repository = Uuid::new_v4();
    let delivery = Uuid::new_v4();
    let connection = Uuid::new_v4();
    let subject = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms)
        VALUES ($1, 'Manifest upgrade', 1, 1)
        ",
    )
    .bind(&tenant)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO repositories (
            id, tenant_id, scm_provider, provider_repository_id,
            owner, name, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, 'github', '202', 'automata-ci', 'automata', 1, 1)
        ",
    )
    .bind(repository)
    .bind(&tenant)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO provider_delivery_inbox (
            id, tenant_id, provider, connection_id, installation_id,
            provider_repository_id, repository_visibility,
            repository_identity, delivery_id, request_digest,
            raw_event_digest, raw_event_object_key, raw_event_size_bytes,
            raw_event_media_type, accepted_at_ms, state_updated_at_ms
        ) VALUES (
            $1, $2, 'github', $3, 101, 202, 'public',
            'automata-ci/automata', 'unmanifested-delivery', $4, $5,
            'upgrade/event', 128, 'application/json', 10, 10
        )
        ",
    )
    .bind(delivery)
    .bind(&tenant)
    .bind(connection)
    .bind(vec![1_u8; 32])
    .bind(vec![2_u8; 32])
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO github_check_subjects (
            id, tenant_id, repository_id, provider_delivery_id, subject_key,
            provider_connection_id, provider_installation_id,
            github_repository_id, github_app_id, head_sha, check_name,
            external_id, created_at_ms, desired_updated_at_ms
        ) VALUES (
            $1, $2, $3, $4, '.ci/workflows/ci.yml',
            $5, 101, 202, 303, $6, 'Automata CI',
            'automata-check:' || $1::TEXT, 11, 11
        )
        ",
    )
    .bind(subject)
    .bind(&tenant)
    .bind(repository)
    .bind(delivery)
    .bind(connection)
    .bind(vec![9_u8; 20])
    .execute(database.pool())
    .await?;
    Ok(())
}

fn assert_constraint(error: &sqlx::Error, expected: &str) {
    let actual = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint);
    assert_eq!(actual, Some(expected), "unexpected database error: {error}");
}
