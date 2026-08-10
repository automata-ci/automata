#[allow(dead_code)]
mod common;

use sqlx::migrate::Migrate as _;
use uuid::Uuid;

use common::{TestDatabase, TestResult, run_with_unmigrated_database};

const MIGRATION: &str = include_str!("../migrations/0032_github_server_service_authorities.sql");
const POSTGRES_ADAPTER: &str = include_str!("../src/postgres/github_service_authority.rs");
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn migration_is_current_only_value_free_and_policy_disjoint() {
    for required in [
        "github_check_subjects_canonical_name_current_only",
        "ADD COLUMN github_repository_name TEXT COLLATE \"C\" NOT NULL",
        "CREATE TABLE github_server_service_authorities",
        "github_server_service_authorities_one_active_scope",
        "CREATE TABLE github_server_service_authority_issuances",
        "CREATE TABLE github_server_service_authority_handoffs",
        "github_app_jwt_issuer_kind IN ('app_client_id', 'app_id')",
        "'{\"checks\":\"write\"}'::JSONB",
        "private_repository_source_read",
        "'{\"contents\":\"read\"}'::JSONB",
        "fetch_private_repository_revision",
        "fetch_private_repository_changed_files",
        "plaintext_size_bytes BETWEEN 1 AND 16384",
        "github_server_service_issuances_state_shape",
        "github_server_service_issuances_mint_retry_claim_exact",
        "github_server_service_issuances_mint_retry_failure_exact",
        "github_server_service_issuances_mint_start_exact",
        "github_server_service_issuances_mint_started_immutable",
        "github_server_service_issuances_mint_result_claim_exact",
        "github_server_service_issuances_ready_expiry_exact",
        "github_server_service_issuances_revoke_only_exact",
        "github_server_service_authorities_next_generation_exact",
        "failure_budget_rearm_at_ms",
        "NEW.consecutive_generation_failures = 31",
        "OLD.failure_budget_rearm_at_ms <= NEW.state_updated_at_ms",
        "github_server_service_authorities_same_state_exact",
        "github_server_service_authorities_retired_terminal_exact",
        "github_server_service_issuances_authority_pointer_exact",
        "DEFERRABLE INITIALLY DEFERRED",
        "github_server_service_issuances_revoke_result_claim_exact",
        "github_server_service_issuances_provider_revocation_exact",
        "github_server_service_issuances_protected_immutable",
        "github_server_service_issuances_provider_expiry_immutable",
        "github_server_service_issuances_safe_erase_horizon",
        "github_server_service_handoffs_checks_claim_exact",
        "github_server_service_handoffs_exact_consumer_unique",
        "check_outbox.claimed_at_ms > NEW.granted_at_ms",
        "> check_outbox.claim_expires_at_ms::NUMERIC",
        "WHEN 'publish_check_run' THEN 600000",
        "ELSE 300000",
        "delivery.claimed_at_ms > NEW.granted_at_ms",
        "delivery.state_updated_at_ms > NEW.granted_at_ms",
        "> delivery.claim_expires_at_ms::NUMERIC + 300000",
        "github_server_service_authorities_bootstrap_due",
        "github_server_service_issuances_revoke_pending_due",
        "github_server_service_handoffs_live_issuance",
        "github_server_service_authority_removal_forbidden",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing invariant: {required}"
        );
    }
    for prohibited in [
        "access_token TEXT",
        "credential TEXT",
        "token_plaintext",
        "{\"checks\":\"write\",\"contents\":\"read\"}",
        "UPDATE github_check_subjects SET github_repository_name",
        "DELETE FROM github_server_service",
    ] {
        assert!(
            !MIGRATION.contains(prohibited),
            "forbidden compatibility/value surface: {prohibited}"
        );
    }
}

#[test]
fn fixed_policy_digests_match_the_rust_domain_contract() {
    use automata_ci_store::GithubServerServiceScope;

    let checks = GithubServerServiceScope::ChecksWrite
        .policy_digest()
        .to_string();
    let source = GithubServerServiceScope::PrivateRepositorySourceRead
        .policy_digest()
        .to_string();
    assert!(MIGRATION.contains(checks.as_str()));
    assert!(MIGRATION.contains(source.as_str()));
    assert_ne!(checks, source);
}

#[test]
fn maintenance_discovery_materializes_each_indexed_due_head_before_filtering() {
    for head in [
        "erase_head AS MATERIALIZED",
        "mint_claim_head AS MATERIALIZED",
        "mint_retry_deadline_head AS MATERIALIZED",
        "mint_retry_head AS MATERIALIZED",
        "revoke_pending_head AS MATERIALIZED",
        "revoke_retry_head AS MATERIALIZED",
        "revoke_claim_head AS MATERIALIZED",
        "bootstrap_head AS MATERIALIZED",
        "refresh_head AS MATERIALIZED",
    ] {
        assert!(
            POSTGRES_ADAPTER.contains(head),
            "maintenance scan lacks bounded head: {head}"
        );
    }
    assert!(
        POSTGRES_ADAPTER.matches("LIMIT 64").count() >= 9,
        "every maintenance head must have its own planner-visible row bound"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn existing_check_state_fails_closed_without_backfill() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_before_0032(&database).await?;
        insert_precanonical_check(&database).await?;

        let mut connection = database.pool().acquire().await?;
        let migration = MIGRATOR
            .iter()
            .find(|migration| migration.version == 32)
            .expect("migration 0032");
        let error = connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await
            .expect_err("precanonical Check state must fail closed");
        match error {
            sqlx::migrate::MigrateError::ExecuteMigration(error, 32) => {
                assert_constraint(&error, "github_check_subjects_canonical_name_current_only");
            }
            other => panic!("unexpected migration error: {other}"),
        }
        drop(connection);

        let rollback: (i64, i64, Option<String>, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM github_check_subjects),
                (SELECT count(*) FROM information_schema.columns
                 WHERE table_schema = current_schema()
                   AND table_name = 'github_check_subjects'
                   AND column_name = 'github_repository_name'),
                to_regclass('github_server_service_authorities')::TEXT,
                (SELECT count(*) FROM _sqlx_migrations WHERE success)
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(rollback, (1, 0, None, 31));
        Ok(())
    })
    .await
}

async fn apply_before_0032(database: &TestDatabase) -> TestResult {
    let mut connection = database.pool().acquire().await?;
    connection
        .ensure_migrations_table(MIGRATOR.table_name.as_ref())
        .await?;
    for migration in MIGRATOR.iter().filter(|migration| migration.version < 32) {
        connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await?;
    }
    Ok(())
}

async fn insert_precanonical_check(database: &TestDatabase) -> TestResult {
    let tenant = format!("authority-upgrade-{}", Uuid::new_v4().simple());
    let repository = Uuid::new_v4();
    let delivery = Uuid::new_v4();
    let connection = Uuid::new_v4();
    let subject = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms)
        VALUES ($1, 'Authority upgrade', 1, 1)
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
            $1, $2, 'github', $3, 101, 202, 'private',
            'automata-ci/automata', 'upgrade-delivery', $4, $5,
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
            $1, $2, $3, $4, '.github/workflows/ci.yml',
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
