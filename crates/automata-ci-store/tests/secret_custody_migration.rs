#[allow(dead_code)]
mod common;

use common::{TestResult, run_with_database, run_with_unmigrated_database};

const MIGRATION: &str = include_str!("../migrations/0036_secret_custody_readiness.sql");
const ADAPTER: &str = include_str!("../src/postgres/secret_custody.rs");
const DOMAIN: &str = include_str!("../src/secret_custody.rs");

#[test]
fn migration_is_an_exact_immutable_authenticated_canary_shape() {
    for required in [
        "secret_custody_pre_canary_builtin_state",
        "CREATE TABLE secret_custody_key_canaries",
        "wrapping_key_id TEXT COLLATE \"C\" PRIMARY KEY",
        "canary_generation = 1",
        "canary_schema = 1",
        "octet_length(ciphertext) = 52",
        "octet_length(nonce) = 12",
        "octet_length(wrapped_data_key) BETWEEN 1 AND 4096",
        "envelope_schema = 1",
        "secret_custody_key_canaries_update_forbidden",
        "secret_custody_key_canaries_delete_forbidden",
        "secret_custody_key_canaries_truncate_forbidden",
        "secret_custody_key_canaries_fresh_key",
        "secret_custody_canary_require_fresh_key",
        "referenced secret custody keys require a prior canary",
        "secret_custody_key_canaries_immutable",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing invariant: {required}"
        );
    }
    assert!(MIGRATION.contains("BETWEEN 1 AND 64"));
    assert!(MIGRATION.contains("^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$"));

    for required in [
        "ALTER TABLE secret_version_envelopes",
        "DROP CONSTRAINT secret_version_envelopes_key_id_shape",
        "ALTER COLUMN wrapping_key_id TYPE TEXT COLLATE \"C\"",
        "ADD CONSTRAINT secret_version_envelopes_custody_canary",
        "FOREIGN KEY (wrapping_key_id)",
        "REFERENCES secret_custody_key_canaries(wrapping_key_id)",
        "ON DELETE RESTRICT",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing built-in schema boundary: {required}"
        );
    }
}

#[test]
fn readiness_receipt_is_adapter_issued_and_does_not_claim_write_composition() {
    for required in [
        "pub struct VerifiedSecretCustody",
        "pub(crate) fn from_verified_parts",
        "configured_key_set_digest",
        "requirements_digest",
        "canaries: Vec<SecretCustodyCanaryBinding>",
        "composition must require a freshly verified receipt",
        "Possessing this foundation receipt alone does not yet",
    ] {
        assert!(
            DOMAIN.contains(required),
            "missing receipt boundary: {required}"
        );
    }
    assert!(!DOMAIN.contains("pub fn from_verified_parts"));
}

#[test]
fn requirement_query_covers_every_current_secret_custody_surface() {
    for required in [
        "EnvelopeCodec",
        "actions/secrets/custody-canary:v1",
        "automata-ci-secret-custody-canary-v1",
        ".seal(&context, plaintext)",
        ".open(&context, &canary.envelope)",
        "candidate.wrapping_key_id() != active_key_id",
        "KEY_ID_IS_FRESH_QUERY",
        "WHERE from_wrapping_key_id = $1 OR to_wrapping_key_id = $1",
        "MAX_SECRET_CUSTODY_CONFIGURED_KEYS == 32",
        "REQUIRED_KEY_QUERY_BOUND: i64 = 33",
    ] {
        assert!(
            ADAPTER.contains(required),
            "missing attestation: {required}"
        );
    }
    for required in [
        "secret_providers WHERE status = 'active'",
        "secret_provider_configuration_envelopes",
        "secret_provider_configuration_envelope_heads",
        "secret_provider_locator_envelopes",
        "secret_provider_locator_envelope_heads",
        "secret_provider_version_envelopes",
        "secret_provider_version_envelope_heads",
        "secret_version_envelopes",
        "secret_version_envelope_heads",
        "secret_provider_lease_envelopes",
        "secret_provider_lease_envelope_heads",
        "secret_version_mutations WHERE state = 'reserved'",
        "secret_provider_leases",
        "status IN ('active', 'revocation_pending')",
        "status IN ('pending', 'in_progress', 'dead_letter')",
        "secret_mutation_recovery_outbox",
        "status IN ('pending', 'in_progress')",
        "status IN ('pending', 'running', 'failed')",
        "status IN ('pending', 'failed')",
        "from_wrapping_key_id COLLATE \"C\" AS wrapping_key_id",
        "to_wrapping_key_id COLLATE \"C\" AS wrapping_key_id",
        "ORDER BY wrapping_key_id COLLATE \"C\"",
        "LIMIT $1",
    ] {
        assert!(
            ADAPTER.contains(required),
            "missing state query: {required}"
        );
    }
    assert!(
        ADAPTER.matches("LIMIT $1").count() >= 8,
        "every source and the final union must be independently bounded"
    );
}

#[test]
fn migration_provides_planner_visible_bounded_scan_paths() {
    for required in [
        "secret_custody_configuration_key_scan",
        "secret_custody_configuration_head_scan",
        "secret_custody_locator_key_scan",
        "secret_custody_locator_head_scan",
        "secret_custody_provider_version_key_scan",
        "secret_custody_provider_version_head_scan",
        "secret_custody_builtin_version_key_scan",
        "secret_custody_builtin_version_head_scan",
        "secret_custody_lease_key_scan",
        "secret_custody_lease_head_scan",
        "secret_custody_rotation_from_key_scan",
        "secret_custody_rotation_to_key_scan",
        "secret_custody_active_provider_scan",
        "WHERE status = 'active'",
        "secret_custody_open_mutation_scan",
        "WHERE state = 'reserved'",
        "secret_custody_open_lease_scan",
        "WHERE status IN ('active', 'revocation_pending')",
        "secret_custody_open_cleanup_scan",
        "WHERE status IN ('pending', 'in_progress', 'dead_letter')",
        "secret_custody_open_recovery_scan",
        "WHERE status IN ('pending', 'in_progress')",
        "secret_custody_open_rotation_scan",
        "WHERE status IN ('pending', 'running', 'failed')",
        "secret_custody_open_rotation_item_scan",
        "WHERE status IN ('pending', 'failed')",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing scan path: {required}"
        );
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn migration_refuses_pre_canary_built_in_envelopes() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        let migration_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        let migrator = sqlx::migrate::Migrator::new(migration_path.as_path()).await?;
        migrator.run_to(35, database.pool()).await?;

        // This isolated fixture deliberately removes only the old compound FK
        // so it can represent otherwise-impossible pre-canary ciphertext.
        sqlx::query(
            "ALTER TABLE secret_version_envelopes \
             DROP CONSTRAINT secret_version_envelopes_builtin_version",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO secret_version_envelopes (
                tenant_id, secret_version_id, secret_id, version_number,
                storage_kind, envelope_generation, ciphertext, nonce,
                wrapped_data_key, wrapping_key_id, envelope_schema,
                created_at_ms
            ) VALUES (
                'custody-pre-canary',
                '10000000-0000-0000-0000-000000000001'::UUID,
                '10000000-0000-0000-0000-000000000002'::UUID,
                1, 'built_in_ciphertext', 1, $1, $2, $3,
                'legacy-key', 1, 1
            )
            ",
        )
        .bind(vec![1_u8; 17])
        .bind(vec![2_u8; 12])
        .bind(vec![3_u8; 48])
        .execute(database.pool())
        .await?;

        let error = migrator
            .run_to(36, database.pool())
            .await
            .expect_err("current-only migration must reject pre-canary built-in state");
        let (source, version) = match &error {
            sqlx::migrate::MigrateError::ExecuteMigration(source, version) => {
                (source, Some(*version))
            }
            sqlx::migrate::MigrateError::Execute(source) => (source, None),
            _ => panic!("unexpected migration failure: {error}"),
        };
        assert!(version.is_none_or(|version| version == 36));
        assert_eq!(
            source
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("secret_custody_pre_canary_builtin_state")
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn built_in_envelopes_are_canonical_and_validated_canary_references() -> TestResult {
    run_with_database(|database| async move {
        let collation: Option<String> = sqlx::query_scalar(
            r"
            SELECT collation_name::TEXT
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'secret_version_envelopes'
              AND column_name = 'wrapping_key_id'
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(collation.as_deref(), Some("C"));

        let (definition, delete_action, validated): (String, String, bool) = sqlx::query_as(
            r"
            SELECT pg_get_constraintdef(oid),
                   CASE confdeltype WHEN 'r' THEN 'restrict' ELSE 'other' END,
                   convalidated
            FROM pg_constraint
            WHERE conrelid = 'secret_version_envelopes'::regclass
              AND conname = 'secret_version_envelopes_custody_canary'
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert!(definition.contains("FOREIGN KEY (wrapping_key_id)"));
        assert!(definition.contains("secret_custody_key_canaries(wrapping_key_id)"));
        assert_eq!(delete_action, "restrict");
        assert!(validated);

        // Remove only the unrelated version FK in this isolated schema so a
        // direct insert reaches the new declarative canary boundary.
        sqlx::query(
            "ALTER TABLE secret_version_envelopes \
             DROP CONSTRAINT secret_version_envelopes_builtin_version",
        )
        .execute(database.pool())
        .await?;
        let error = sqlx::query(
            r"
            INSERT INTO secret_version_envelopes (
                tenant_id, secret_version_id, secret_id, version_number,
                storage_kind, envelope_generation, ciphertext, nonce,
                wrapped_data_key, wrapping_key_id, envelope_schema,
                created_at_ms
            ) VALUES (
                'custody-fk',
                '20000000-0000-0000-0000-000000000001'::UUID,
                '20000000-0000-0000-0000-000000000002'::UUID,
                1, 'built_in_ciphertext', 1, $1, $2, $3,
                'missing-canary', 1, 1
            )
            ",
        )
        .bind(vec![1_u8; 17])
        .bind(vec![2_u8; 12])
        .bind(vec![3_u8; 48])
        .execute(database.pool())
        .await
        .expect_err("built-in ciphertext must reference an existing canary");
        assert_eq!(
            error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("secret_version_envelopes_custody_canary")
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn canaries_reject_rewrite_removal_and_truncation() -> TestResult {
    run_with_database(|database| async move {
        sqlx::query(
            r"
            INSERT INTO secret_custody_key_canaries (
                wrapping_key_id, canary_generation, canary_schema,
                ciphertext, nonce, wrapped_data_key, envelope_schema,
                created_at_ms
            ) VALUES ('key-a', 1, 1, $1, $2, $3, 1, 1)
            ",
        )
        .bind(vec![7_u8; 52])
        .bind(vec![8_u8; 12])
        .bind(vec![9_u8; 48])
        .execute(database.pool())
        .await?;

        for statement in [
            "UPDATE secret_custody_key_canaries SET created_at_ms = created_at_ms",
            "DELETE FROM secret_custody_key_canaries",
            "TRUNCATE secret_custody_key_canaries CASCADE",
        ] {
            let error = sqlx::query(statement)
                .execute(database.pool())
                .await
                .expect_err("immutable canary mutation must fail");
            assert_eq!(
                error
                    .as_database_error()
                    .and_then(sqlx::error::DatabaseError::constraint),
                Some("secret_custody_key_canaries_immutable")
            );
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn preexisting_envelope_rejects_first_writer_attestation() -> TestResult {
    run_with_database(|database| async move {
        sqlx::query(
            r"
            INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms)
            VALUES ('custody-legacy', 'Custody legacy', 1, 1)
            ",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO secret_providers (
                tenant_id, provider_id, adapter_kind, display_name,
                supports_create_version, supports_destroy_version,
                supports_dynamic_leases, supports_renew_leases,
                supports_revoke_leases, is_default, status, health,
                created_at_ms, updated_at_ms
            ) VALUES (
                'custody-legacy', 'legacy', 'custody_test', 'Custody legacy',
                TRUE, TRUE, FALSE, FALSE, FALSE, FALSE,
                'unconfigured', 'unknown', 1, 1
            )
            ",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO secret_provider_configuration_envelopes (
                tenant_id, provider_id, envelope_generation, ciphertext,
                nonce, wrapped_data_key, wrapping_key_id, envelope_schema,
                created_at_ms
            ) VALUES (
                'custody-legacy', 'legacy', 1, $1, $2, $3, 'legacy-key', 1, 1
            )
            ",
        )
        .bind(vec![1_u8; 17])
        .bind(vec![2_u8; 12])
        .bind(vec![3_u8; 48])
        .execute(database.pool())
        .await?;

        let error = sqlx::query(
            r"
            INSERT INTO secret_custody_key_canaries (
                wrapping_key_id, canary_generation, canary_schema,
                ciphertext, nonce, wrapped_data_key, envelope_schema,
                created_at_ms
            ) VALUES ('legacy-key', 1, 1, $1, $2, $3, 1, 1)
            ",
        )
        .bind(vec![7_u8; 52])
        .bind(vec![8_u8; 12])
        .bind(vec![9_u8; 48])
        .execute(database.pool())
        .await
        .expect_err("referenced key ID must not establish trust on first use");
        assert_eq!(
            error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("secret_custody_key_canaries_fresh_key")
        );
        Ok(())
    })
    .await
}
