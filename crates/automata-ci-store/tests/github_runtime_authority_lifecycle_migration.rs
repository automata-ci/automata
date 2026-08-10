#[allow(dead_code)]
mod common;

use sqlx::migrate::Migrate as _;
use uuid::Uuid;

use common::{TestDatabase, TestResult, run_with_unmigrated_database, seed_control_plane};

const MIGRATION: &str = include_str!("../migrations/0023_github_runtime_authority_lifecycle.sql");
const DATABASE_TIME_MIGRATION: &str =
    include_str!("../migrations/0044_github_runtime_authority_database_time.sql");
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn successor_is_current_only_ciphertext_custody() {
    for required in [
        "github_runtime_authority_current_only_empty_upgrade",
        "provider_connection_id UUID NOT NULL",
        "provider_installation_id BIGINT NOT NULL",
        "provider_expires_at_ms IS NULL",
        "commit_disposition IN ('deliverable', 'revoke_only')",
        "state = 'mint_retry_pending'",
        "state = 'rejected'",
        "state = 'quarantined'",
        "conservative_expiry_at_ms::NUMERIC",
        "request_deadline_at_ms::NUMERIC + 3780000",
        "safe_erase_after_ms = conservative_expiry_at_ms",
        "provider_expires_at_ms::NUMERIC + 120000",
        "state_updated_at_ms::NUMERIC + 60000",
        "OLD.state = 'mint_retry_pending' AND NEW.state = 'claimed'",
        "OLD.state IN ('ready', 'revoke_pending') AND NEW.state = 'quarantined'",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing lifecycle guard: {required}"
        );
    }
    for forbidden in [
        "access_token TEXT",
        "token_plaintext",
        "UPDATE github_runtime_authority_issuances SET provider_connection_id",
        "COALESCE(provider_expires_at_ms",
    ] {
        assert!(
            !MIGRATION.contains(forbidden),
            "migration must not convert or persist plaintext: {forbidden}"
        );
    }
}

#[test]
fn database_time_successor_has_permanent_reciprocal_operation_evidence() {
    for required in [
        "github_runtime_authority_v3_current_only_empty_upgrade",
        "github_runtime_authority_operation_transitions",
        "automata_capture_github_runtime_authority_operation_transition",
        "github_runtime_authority_operation_transition_receipt",
        "DEFERRABLE INITIALLY DEFERRED",
        "github_runtime_authority_operation_receipt_transition_exact",
        "github_runtime_authority_operation_transition_receipt_exact",
        "github_runtime_authority_operation_receipt_immutable",
        "github_runtime_authority_operation_transition_immutable",
        "github_runtime_authority_operation_receipts_reject_truncate",
        "github_runtime_authority_operation_transitions_reject_truncate",
        "automata_github_runtime_authority_operation_digest",
        "NEW.operation_digest := automata_github_runtime_authority_operation_digest",
        "github_runtime_authority_operation_digest_exact",
        "github_runtime_authority_mint_begins",
        "mint_provider_request_millis",
        "authority.mint_provider_request_millis =",
        "preparation_selection_id UUID NOT NULL",
        "activation_selection_id UUID NOT NULL",
        "materialization_selection_id UUID NOT NULL",
        "JOIN workflow_plan_v2_activation_preparations AS preparation",
        "preparation_claim.descriptor_digest = preparation.descriptor_digest",
    ] {
        assert!(
            DATABASE_TIME_MIGRATION.contains(required),
            "missing permanent operation closure: {required}"
        );
    }
    for forbidden in [
        "retain_until_ms",
        "86400000",
        "compact_operation_receipt",
        "SET disposition = 'terminal_erasable'",
        "DELETE FROM github_runtime_authority_operation_receipts",
        "preparation_claim.descriptor_digest = concrete.descriptor_digest",
    ] {
        assert!(
            !DATABASE_TIME_MIGRATION.contains(forbidden),
            "operation evidence must not have an age-based mutation path: {forbidden}"
        );
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn obsolete_nonempty_issuance_fails_closed_and_rolls_back() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        require_postgres_18(&database).await?;
        apply_before_lifecycle_migration(&database).await?;
        insert_obsolete_issuance(&database).await?;

        let mut connection = database.pool().acquire().await?;
        let migration = MIGRATOR
            .iter()
            .find(|migration| migration.version == 23)
            .expect("migration 0023");
        let error = connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await
            .expect_err("nonempty obsolete authority state must fail closed");
        match error {
            sqlx::migrate::MigrateError::ExecuteMigration(error, 23) => assert_constraint(
                &error,
                "github_runtime_authority_current_only_empty_upgrade",
            ),
            other => panic!("unexpected migration error: {other}"),
        }
        drop(connection);

        let rollback: (i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM github_runtime_authority_issuances),
                (SELECT count(*) FROM information_schema.columns
                 WHERE table_schema = current_schema()
                   AND table_name = 'github_runtime_authority_issuances'
                   AND column_name IN (
                       'provider_connection_id', 'provider_installation_id',
                       'commit_disposition', 'next_mint_at_ms', 'quarantine_kind'
                   )),
                (SELECT count(*) FROM _sqlx_migrations WHERE success)
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(rollback, (1, 0, 22));
        Ok(())
    })
    .await
}

async fn require_postgres_18(database: &TestDatabase) -> TestResult {
    let version: i32 =
        sqlx::query_scalar("SELECT pg_catalog.current_setting('server_version_num')::INTEGER")
            .fetch_one(database.pool())
            .await?;
    if version < 180_000 {
        return Err("runtime-authority lifecycle migration test requires PostgreSQL 18".into());
    }
    Ok(())
}

async fn apply_before_lifecycle_migration(database: &TestDatabase) -> TestResult {
    let mut connection = database.pool().acquire().await?;
    let table_name = MIGRATOR.table_name.as_ref();
    connection.ensure_migrations_table(table_name).await?;
    for migration in MIGRATOR.iter().filter(|migration| migration.version < 23) {
        connection.apply(table_name, migration).await?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn insert_obsolete_issuance(database: &TestDatabase) -> TestResult {
    let seed = seed_control_plane(database.pool(), 0).await?;
    sqlx::query(
        r"
        UPDATE repositories
        SET scm_provider = 'github', provider_repository_id = '4242',
            owner = 'automata-ci', name = 'automata', updated_at_ms = 2
        WHERE id = $1 AND tenant_id = $2
        ",
    )
    .bind(seed.repository_id)
    .bind(&seed.tenant_id)
    .execute(database.pool())
    .await?;

    let runner_id = Uuid::new_v4();
    let runner_session_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO runners (
            id, tenant_id, name, normalized_name, capabilities, slots, status,
            generation, session_epoch, desired_state, created_at_ms, updated_at_ms
        ) VALUES (
            $1, $2, 'migration-runner', 'migration-runner', '{}', 1, 'online',
            1, 1, 'active', 1, 1
        )
        ",
    )
    .bind(runner_id)
    .bind(&seed.tenant_id)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO runner_sessions (
            id, runner_id, protocol_version, job_ir_schema, capability_snapshot,
            connected_at_ms, heartbeat_at_ms, runner_generation, session_epoch
        ) VALUES ($1, $2, 4, 5, '{}', 2, 2, 1, 1)
        ",
    )
    .bind(runner_session_id)
    .bind(runner_id)
    .execute(database.pool())
    .await?;

    let attempt_id = Uuid::new_v4();
    let lease_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO job_attempts (
            id, job_id, attempt_number, lifecycle, fencing_token,
            lease_id, runner_id, lease_issued_at_ms, lease_expires_at_ms,
            lease_failures, queued_at_ms, changed_at_ms,
            runner_session_id, runner_session_epoch, runner_generation,
            runner_slot
        ) VALUES (
            $1, $2, 1, 'leased', 7, $3, $4, 10, 200000,
            0, 3, 10, $5, $6, $7, 1
        )
        ",
    )
    .bind(attempt_id)
    .bind(seed.job_id.as_uuid())
    .bind(lease_id)
    .bind(runner_id)
    .bind(runner_session_id)
    .bind(1_i64)
    .bind(1_i64)
    .execute(database.pool())
    .await?;

    sqlx::query(
        r"
        INSERT INTO github_runtime_authority_issuances (
            tenant_id, attempt_id, fencing_token, lease_id,
            lease_issued_at_ms, lease_expires_at_ms, run_id, job_id,
            runner_id, runner_session_id, runner_session_epoch,
            runner_generation, runner_slot, job_ir_schema,
            job_ir_size_bytes, job_ir_digest, repository_id,
            github_repository_id, github_repository_name,
            authority_namespace, policy_digest, issuer_fingerprint,
            configuration_fingerprint, requested_at_ms,
            request_deadline_at_ms, conservative_expiry_at_ms,
            mint_claim_owner_id, mint_claimed_at_ms,
            mint_claim_expires_at_ms, state_updated_at_ms
        ) VALUES (
            $1, $2, 7, $3, 10, 200000, $4, $5, $6, $7, $8, $9,
            1, 5, 128, $10, $11, 4242, 'automata-ci/automata',
            'github.actions.runtime', $12, $13, $14, 20, 1000, 3721000,
            $15, 20, 100, 20
        )
        ",
    )
    .bind(&seed.tenant_id)
    .bind(attempt_id)
    .bind(lease_id)
    .bind(seed.run_id.as_uuid())
    .bind(seed.job_id.as_uuid())
    .bind(runner_id)
    .bind(runner_session_id)
    .bind(1_i64)
    .bind(1_i64)
    .bind(vec![11_u8; 32])
    .bind(seed.repository_id)
    .bind(vec![0x51_u8; 32])
    .bind(vec![0x52_u8; 32])
    .bind(vec![0x53_u8; 32])
    .bind(Uuid::new_v4())
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
