mod common;

use sqlx::{PgPool, Postgres, Transaction, migrate::Migrate as _};
use uuid::Uuid;

use common::{
    SeedData, TestDatabase, TestResult, run_with_database, run_with_unmigrated_database,
    seed_control_plane,
};

const SECRETS_MIGRATION: &str = include_str!("../migrations/0012_secrets_output_safety.sql");
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn secrets_migration_is_ciphertext_only_and_fail_private() {
    for table in [
        "secret_providers",
        "secret_provider_configuration_envelopes",
        "repository_environments",
        "protected_environment_approval_requests",
        "secrets",
        "secret_versions",
        "secret_provider_locator_envelopes",
        "secret_provider_version_envelopes",
        "secret_version_envelopes",
        "secret_policies",
        "secret_repository_access",
        "secret_workload_grants",
        "secret_provider_leases",
        "secret_provider_lease_envelopes",
        "secret_cleanup_outbox",
        "secret_key_rotations",
    ] {
        assert!(
            SECRETS_MIGRATION.contains(&format!("CREATE TABLE {table}")),
            "missing durable table {table}"
        );
    }
    assert!(SECRETS_MIGRATION.contains("octet_length(nonce) = 12"));
    assert!(SECRETS_MIGRATION.contains("wrapped_data_key BYTEA NOT NULL"));
    assert!(SECRETS_MIGRATION.contains("DEFAULT 'readable_secret'"));
    assert!(SECRETS_MIGRATION.contains("DEFAULT 'suppress_user_output'"));
    assert!(!SECRETS_MIGRATION.contains("value_hash"));
    assert!(!SECRETS_MIGRATION.contains("value_digest"));
    assert!(!SECRETS_MIGRATION.contains("provider_locator TEXT"));
    assert!(!SECRETS_MIGRATION.contains("provider_version_id TEXT"));
    assert!(!SECRETS_MIGRATION.contains("provider_lease_id TEXT"));
    assert!(!SECRETS_MIGRATION.contains("public_configuration JSONB"));
    assert!(!SECRETS_MIGRATION.contains("credential_source_label TEXT"));
    assert!(!SECRETS_MIGRATION.contains("octet_length(resolution_reason)"));
    assert!(!SECRETS_MIGRATION.contains("octet_length(revocation_reason)"));
    assert!(!SECRETS_MIGRATION.contains("failure_kind ~"));
    assert!(SECRETS_MIGRATION.contains("resolution_reason IN ("));
    assert!(SECRETS_MIGRATION.contains("revocation_reason IN ("));
    assert!(SECRETS_MIGRATION.contains("failure_kind IN ("));
    assert!(SECRETS_MIGRATION.contains("create_request_id TEXT NOT NULL"));
    assert!(SECRETS_MIGRATION.contains("secret_version_id UUID NOT NULL"));
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn secrets_upgrade_backfills_outputs_private_and_seeds_builtin_provider() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_before_secrets_migration(&database).await?;
        let seed = seed_control_plane(database.pool(), 1).await?;
        let attempt = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO job_attempts (
                id, job_id, attempt_number, lifecycle, fencing_token,
                queued_at_ms, changed_at_ms
            ) VALUES ($1, $2, 1, 'succeeded', 7, 1, 2)
            ",
        )
        .bind(attempt)
        .bind(seed.job_id.as_uuid())
        .execute(database.pool())
        .await?;

        let stream = Uuid::new_v4();
        let fence = seed.session_fences[0];
        sqlx::query(
            r"
            INSERT INTO attempt_log_streams (
                id, attempt_id, runner_session_id, operation_id, runner_id,
                runner_session_epoch, runner_generation, runner_slot, lease_id,
                fencing_token, log_schema, opened_at_ms
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, 1, $8, 7, 1, 2)
            ",
        )
        .bind(stream)
        .bind(attempt)
        .bind(fence.session_id().as_uuid())
        .bind(Uuid::new_v4())
        .bind(fence.runner_id().as_uuid())
        .bind(i64::try_from(fence.session_epoch().get())?)
        .bind(i64::try_from(fence.runner_generation().get())?)
        .bind(Uuid::new_v4())
        .execute(database.pool())
        .await?;

        let artifact: i64 = sqlx::query_scalar(
            r"
            INSERT INTO workflow_artifacts (
                upload_id, tenant_id, repository_id, run_id, job_id, attempt_id,
                fencing_token, name, protocol_version, mime_type, created_at_seconds
            ) VALUES (
                $1, $2, $3, $4, $5, $6, 7, 'legacy-output', 7,
                'application/octet-stream', 1
            ) RETURNING id
            ",
        )
        .bind(Uuid::new_v4())
        .bind(&seed.tenant_id)
        .bind(seed.repository_id)
        .bind(seed.run_id.as_uuid())
        .bind(seed.job_id.as_uuid())
        .bind(attempt)
        .fetch_one(database.pool())
        .await?;

        let mut connection = database.pool().acquire().await?;
        let table_name = MIGRATOR.table_name.as_ref();
        let migration = MIGRATOR
            .iter()
            .find(|migration| migration.version == 12)
            .expect("migration 0012");
        connection.apply(table_name, migration).await?;
        drop(connection);

        let repository_policy: (String, String, String) = sqlx::query_as(
            r"
            SELECT dashboard_audience, log_audience, artifact_audience
            FROM repository_publication_policies
            WHERE repository_id = $1
            ",
        )
        .bind(seed.repository_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            repository_policy,
            ("private".into(), "private".into(), "private".into())
        );

        let run_policy: (String, String, String, String) = sqlx::query_as(
            r"
            SELECT requested_dashboard_visibility, effective_dashboard_visibility,
                   requested_log_visibility, requested_artifact_visibility
            FROM workflow_runs WHERE id = $1
            ",
        )
        .bind(seed.run_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            run_policy,
            (
                "private".into(),
                "private".into(),
                "private".into(),
                "private".into()
            )
        );

        let attempt_policy: (String, String, String) = sqlx::query_as(
            r"
            SELECT secret_exposure_class, raw_log_disposition, effective_log_visibility
            FROM job_attempts WHERE id = $1
            ",
        )
        .bind(attempt)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            attempt_policy,
            (
                "readable_secret".into(),
                "suppress_user_output".into(),
                "private".into()
            )
        );
        let stream_policy: (String, String, String) = sqlx::query_as(
            r"
            SELECT secret_exposure_class, raw_log_disposition, effective_visibility
            FROM attempt_log_streams WHERE id = $1
            ",
        )
        .bind(stream)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(stream_policy, attempt_policy);
        let artifact_policy: (String, String, String) = sqlx::query_as(
            r"
            SELECT secret_exposure_class, requested_visibility, effective_visibility
            FROM workflow_artifacts WHERE id = $1
            ",
        )
        .bind(artifact)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            artifact_policy,
            ("readable_secret".into(), "private".into(), "private".into())
        );

        let builtin: (String, String, bool, String) = sqlx::query_as(
            r"
            SELECT provider_id, adapter_kind, is_default, status
            FROM secret_providers WHERE tenant_id = $1
            ",
        )
        .bind(&seed.tenant_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            builtin,
            (
                "builtin".into(),
                "builtin_postgres".into(),
                true,
                "unconfigured".into()
            )
        );

        sqlx::query("DELETE FROM workflow_artifacts WHERE id = $1")
            .bind(artifact)
            .execute(database.pool())
            .await?;
        sqlx::query("DELETE FROM jobs WHERE id = $1")
            .bind(seed.job_id.as_uuid())
            .execute(database.pool())
            .await?;
        database.store().migrate().await?;
        let compatibility: (i32, i32) = sqlx::query_as(
            "SELECT minimum_admission_epoch, job_ir_schema FROM automata_cluster_compatibility WHERE singleton",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(compatibility, (4, 5));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn secret_scopes_envelopes_and_versions_are_strict_and_ciphertext_only() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 0).await?;
        let principal = seed_human(database.pool(), &seed.tenant_id, "301", "cipher").await?;
        activate_builtin(database.pool(), &seed.tenant_id).await?;
        let plaintext_provider_configuration = sqlx::query(
            r#"
            UPDATE secret_providers
            SET public_configuration = '{"token":"sentinel-credential"}'::jsonb
            WHERE tenant_id = $1 AND provider_id = 'builtin'
            "#,
        )
        .bind(&seed.tenant_id)
        .execute(database.pool())
        .await
        .expect_err("provider configuration has no arbitrary plaintext JSON surface");
        assert_sqlstate(&plaintext_provider_configuration, "42703");
        insert_provider_configuration_envelope(database.pool(), &seed.tenant_id).await?;

        let environment = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO repository_environments (
                tenant_id, repository_id, id, name, normalized_name,
                created_by_principal_id, created_at_ms, updated_at_ms
            ) VALUES ($1, $2, $3, 'Production', 'production', $4, 1, 1)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(seed.repository_id)
        .bind(environment)
        .bind(principal)
        .execute(database.pool())
        .await?;

        let secret = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO secrets (
                tenant_id, id, canonical_name, scope_kind, repository_id,
                provider_id, created_by_principal_id,
                created_at_ms, updated_at_ms
            ) VALUES ($1, $2, 'RELEASE_TOKEN', 'repository', $3,
                      'builtin', $4, 1, 1)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(secret)
        .bind(seed.repository_id)
        .bind(principal)
        .execute(database.pool())
        .await?;
        let invalid_provider_reference_nonce = sqlx::query(
            r"
            INSERT INTO secret_provider_locator_envelopes (
                tenant_id, secret_id, provider_id, envelope_generation,
                ciphertext, nonce, wrapped_data_key, wrapping_key_id,
                envelope_schema, created_at_ms
            ) VALUES ($1, $2, 'builtin', 1, $3, $4, $5,
                      'provider-reference-kek-v1', 1, 1)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(secret)
        .bind(vec![41_u8; 64])
        .bind(vec![42_u8; 11])
        .bind(vec![43_u8; 48])
        .execute(database.pool())
        .await
        .expect_err("provider references require an exact 12-byte AEAD nonce");
        assert_constraint(
            &invalid_provider_reference_nonce,
            "secret_provider_locator_envelopes_nonce_shape",
        );
        insert_provider_locator_envelope(database.pool(), &seed.tenant_id, secret).await?;
        let policy: (String, String, bool, bool) = sqlx::query_as(
            r"
            SELECT tenant_repository_access_mode, minimum_event_trust,
                   allow_fork_pull_requests, allow_dependabot
            FROM secret_policies WHERE tenant_id = $1 AND secret_id = $2
            ",
        )
        .bind(&seed.tenant_id)
        .bind(secret)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            policy,
            ("scope_only".into(), "trusted".into(), false, false)
        );

        let managed_secret = Uuid::new_v4();
        let mutation = Uuid::new_v4();
        let version = Uuid::new_v4();
        let create_request = format!("secret-version:{mutation}");
        sqlx::query(
            r"
            INSERT INTO secrets (
                tenant_id, id, canonical_name, scope_kind, repository_id,
                environment_id, provider_id, created_by_principal_id,
                updated_by_principal_id, created_at_ms, updated_at_ms
            ) VALUES (
                $1, $2, 'BUILTIN_VALUE', 'environment', $3,
                $4, 'builtin', $5, $5, 2, 2
            )
            ",
        )
        .bind(&seed.tenant_id)
        .bind(managed_secret)
        .bind(seed.repository_id)
        .bind(environment)
        .bind(principal)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO secret_version_mutations (
                tenant_id, mutation_id, secret_id, scope_kind,
                repository_id, environment_id, canonical_name,
                provider_id, mutation_kind,
                reserved_secret_revision, provider_create_request_id,
                reserved_by_principal_id, reserved_at_ms
            ) VALUES (
                $1, $2, $3, 'environment', $4, $5,
                'BUILTIN_VALUE', 'builtin', 'create', 1, $6, $7, 2
            )
            ",
        )
        .bind(&seed.tenant_id)
        .bind(mutation)
        .bind(managed_secret)
        .bind(seed.repository_id)
        .bind(environment)
        .bind(&create_request)
        .bind(principal)
        .execute(database.pool())
        .await?;
        let mut invalid_stage = database.pool().begin().await?;
        insert_builtin_version(
            &mut invalid_stage,
            &seed.tenant_id,
            principal,
            managed_secret,
            version,
            1,
            &create_request,
        )
        .await?;
        let invalid_nonce = sqlx::query(
            r"
            INSERT INTO secret_version_envelopes (
                tenant_id, secret_version_id, secret_id, version_number,
                envelope_generation,
                ciphertext, nonce, wrapped_data_key, wrapping_key_id,
                envelope_schema, created_at_ms
            ) VALUES ($1, $2, $3, 1, 1, $4, $5, $6,
                      'secret-kek-v1', 1, 2)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(version)
        .bind(managed_secret)
        .bind(vec![7_u8; 64])
        .bind(vec![8_u8; 11])
        .bind(vec![9_u8; 48])
        .execute(&mut *invalid_stage)
        .await
        .expect_err("built-in secret envelopes require an exact 12-byte AEAD nonce");
        assert_constraint(&invalid_nonce, "secret_version_envelopes_nonce_shape");
        invalid_stage.rollback().await?;

        let mut staging = database.pool().begin().await?;
        insert_builtin_version(
            &mut staging,
            &seed.tenant_id,
            principal,
            managed_secret,
            version,
            1,
            &create_request,
        )
        .await?;
        insert_envelope(
            &mut staging,
            &seed.tenant_id,
            managed_secret,
            version,
            1,
            1,
            "secret-kek-v1",
        )
        .await?;
        sqlx::query(
            r"
            INSERT INTO secret_version_envelope_heads (
                tenant_id, secret_version_id, envelope_generation, updated_at_ms
            ) VALUES ($1, $2, 1, 2)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(version)
        .execute(&mut *staging)
        .await?;
        sqlx::query(
            r"
            INSERT INTO secret_version_lifecycle (
                tenant_id, secret_version_id, secret_id, version_number,
                provider_id, mutation_id, status, revision,
                changed_by_principal_id, changed_at_ms
            ) VALUES ($1, $2, $3, 1, 'builtin', $4, 'staged', 1, $5, 2)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(version)
        .bind(managed_secret)
        .bind(mutation)
        .bind(principal)
        .execute(&mut *staging)
        .await?;
        staging.commit().await?;
        let mut confirmation = database.pool().begin().await?;
        sqlx::query(
            r"
            UPDATE secret_version_lifecycle
            SET status = 'active', revision = 2,
                changed_by_principal_id = $3, changed_at_ms = 2
            WHERE tenant_id = $1 AND secret_version_id = $2
              AND status = 'staged' AND revision = 1
            ",
        )
        .bind(&seed.tenant_id)
        .bind(version)
        .bind(principal)
        .execute(&mut *confirmation)
        .await?;
        sqlx::query(
            r"
            UPDATE secrets
            SET status = 'active', current_version_id = $3,
                current_version_number = 1,
                updated_by_principal_id = $4, updated_at_ms = 2, revision = 2
            WHERE tenant_id = $1 AND id = $2
              AND status = 'provisioning' AND revision = 1
            ",
        )
        .bind(&seed.tenant_id)
        .bind(managed_secret)
        .bind(version)
        .bind(principal)
        .execute(&mut *confirmation)
        .await?;
        sqlx::query(
            r"
            UPDATE secret_version_mutations
            SET state = 'confirmed', completion_kind = 'builtin_created',
                committed_version_id = $3, committed_version_number = 1,
                confirmed_secret_revision = 2,
                confirmed_by_principal_id = $4, confirmed_at_ms = 2,
                revision = 2
            WHERE tenant_id = $1 AND mutation_id = $2
              AND state = 'reserved' AND revision = 1
            ",
        )
        .bind(&seed.tenant_id)
        .bind(mutation)
        .bind(version)
        .bind(principal)
        .execute(&mut *confirmation)
        .await?;
        confirmation.commit().await?;

        let mutate_version = sqlx::query(
            "UPDATE secret_versions SET created_at_ms = 3 WHERE tenant_id = $1 AND id = $2",
        )
        .bind(&seed.tenant_id)
        .bind(version)
        .execute(database.pool())
        .await
        .expect_err("logical secret versions are immutable");
        assert_constraint(&mutate_version, "secret_versions_immutable");
        let mutate_envelope = sqlx::query(
            "UPDATE secret_version_envelopes SET ciphertext = $3 WHERE tenant_id = $1 AND secret_version_id = $2",
        )
        .bind(&seed.tenant_id)
        .bind(version)
        .bind(vec![1_u8; 64])
        .execute(database.pool())
        .await
        .expect_err("authenticated ciphertext envelope rows are immutable");
        assert_constraint(
            &mutate_envelope,
            "secret_version_envelopes_immutable",
        );
        let mutate_provider_reference = sqlx::query(
            "UPDATE secret_provider_locator_envelopes SET ciphertext = $3 WHERE tenant_id = $1 AND secret_id = $2",
        )
        .bind(&seed.tenant_id)
        .bind(secret)
        .bind(vec![1_u8; 64])
        .execute(database.pool())
        .await
        .expect_err("encrypted external-provider handles are immutable");
        assert_constraint(
            &mutate_provider_reference,
            "secret_provider_reference_envelopes_immutable",
        );

        let duplicate_create_request = sqlx::query(
            r"
            INSERT INTO secret_versions (
                tenant_id, id, secret_id, version_number, provider_id,
                create_request_id, storage_kind, created_by_principal_id,
                created_at_ms
            ) VALUES ($1, $2, $3, 2, 'builtin', $4,
                      'built_in_ciphertext', $5, 3)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(Uuid::new_v4())
        .bind(managed_secret)
        .bind(&create_request)
        .bind(principal)
        .execute(database.pool())
        .await
        .expect_err("create retries must replay one tenant/provider request winner");
        assert_constraint(
            &duplicate_create_request,
            "secret_versions_create_request_unique",
        );

        sqlx::query(
            r"
            UPDATE secrets
            SET status = 'deleted', revision = 3,
                updated_by_principal_id = $3,
                updated_at_ms = 3, deleted_at_ms = 3
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(&seed.tenant_id)
        .bind(managed_secret)
        .bind(principal)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            UPDATE secret_version_lifecycle
            SET status = 'destroy_pending', destroy_request_id = 'destroy-release-token-v1',
                revision = 3, changed_by_principal_id = $3, changed_at_ms = 3
            WHERE tenant_id = $1 AND secret_version_id = $2
            ",
        )
        .bind(&seed.tenant_id)
        .bind(version)
        .bind(principal)
        .execute(database.pool())
        .await?;
        let destroy_before_crypto_erasure = sqlx::query(
            r"
            UPDATE secret_version_lifecycle
            SET status = 'destroyed', revision = 4,
                changed_at_ms = 4, destroyed_at_ms = 4
            WHERE tenant_id = $1 AND secret_version_id = $2
            ",
        )
        .bind(&seed.tenant_id)
        .bind(version)
        .execute(database.pool())
        .await
        .expect_err("logical destruction cannot precede cryptographic erasure");
        assert_constraint(
            &destroy_before_crypto_erasure,
            "secret_version_lifecycle_crypto_destroyed",
        );
        sqlx::query(
            "DELETE FROM secret_provider_version_envelope_heads WHERE tenant_id = $1 AND secret_version_id = $2",
        )
        .bind(&seed.tenant_id)
        .bind(version)
        .execute(database.pool())
        .await?;
        sqlx::query(
            "DELETE FROM secret_provider_version_envelopes WHERE tenant_id = $1 AND secret_version_id = $2",
        )
        .bind(&seed.tenant_id)
        .bind(version)
        .execute(database.pool())
        .await?;
        sqlx::query(
            "DELETE FROM secret_version_envelope_heads WHERE tenant_id = $1 AND secret_version_id = $2",
        )
        .bind(&seed.tenant_id)
        .bind(version)
        .execute(database.pool())
        .await?;
        sqlx::query(
            "DELETE FROM secret_version_envelopes WHERE tenant_id = $1 AND secret_version_id = $2",
        )
        .bind(&seed.tenant_id)
        .bind(version)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            UPDATE secret_version_lifecycle
            SET status = 'destroyed', revision = 4,
                changed_at_ms = 4, destroyed_at_ms = 4
            WHERE tenant_id = $1 AND secret_version_id = $2
            ",
        )
        .bind(&seed.tenant_id)
        .bind(version)
        .execute(database.pool())
        .await?;

        let other_tenant = format!("secret-other-{}", Uuid::new_v4().simple());
        sqlx::query(
            "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Other', 1, 1)",
        )
        .bind(&other_tenant)
        .execute(database.pool())
        .await?;
        let other_repository = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO repositories (
                id, tenant_id, scm_provider, provider_repository_id, owner, name,
                created_at_ms, updated_at_ms
            ) VALUES ($1, $2, 'test', $3, 'automata-ci', 'other-secret', 1, 1)
            ",
        )
        .bind(other_repository)
        .bind(&other_tenant)
        .bind(other_repository.to_string())
        .execute(database.pool())
        .await?;
        let cross_tenant_reference = sqlx::query(
            r"
            INSERT INTO secret_provider_locator_envelopes (
                tenant_id, secret_id, provider_id, envelope_generation,
                ciphertext, nonce, wrapped_data_key, wrapping_key_id,
                envelope_schema, created_at_ms
            ) VALUES ($1, $2, 'builtin', 2, $3, $4, $5,
                      'provider-reference-kek-v1', 1, 3)
            ",
        )
        .bind(&other_tenant)
        .bind(secret)
        .bind(vec![51_u8; 64])
        .bind(vec![52_u8; 12])
        .bind(vec![53_u8; 48])
        .execute(database.pool())
        .await
        .expect_err("provider reference envelopes cannot cross tenant boundaries");
        assert_constraint(
            &cross_tenant_reference,
            "secret_provider_locator_envelopes_secret",
        );
        let cross_tenant_scope = sqlx::query(
            r"
            INSERT INTO secrets (
                tenant_id, id, canonical_name, scope_kind, repository_id,
                provider_id, created_at_ms, updated_at_ms
            ) VALUES ($1, $2, 'CROSS_TENANT', 'repository', $3,
                      'builtin', 1, 1)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(Uuid::new_v4())
        .bind(other_repository)
        .execute(database.pool())
        .await
        .expect_err("a repository-scoped secret cannot cross tenant boundaries");
        assert_constraint(&cross_tenant_scope, "secrets_repository");

        let reserved_name = sqlx::query(
            r"
            INSERT INTO secrets (
                tenant_id, id, canonical_name, scope_kind, repository_id,
                environment_id, provider_id,
                created_at_ms, updated_at_ms
            ) VALUES ($1, $2, 'GITHUB_TOKEN', 'environment', $3, $4,
                      'builtin', 1, 1)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(Uuid::new_v4())
        .bind(seed.repository_id)
        .bind(environment)
        .execute(database.pool())
        .await
        .expect_err("platform-owned secret namespaces are reserved");
        assert_constraint(&reserved_name, "secrets_name_shape");

        let forbidden_value_columns: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name LIKE 'secret%'
              AND column_name IN (
                  'plaintext', 'value', 'secret_value', 'value_hash', 'value_digest',
                  'raw_value', 'raw_secret', 'bearer', 'bearer_token',
                  'access_token', 'refresh_token', 'password',
                  'provider_locator', 'external_locator',
                  'provider_version_id', 'external_version_id',
                  'provider_lease_id', 'lease_handle',
                  'public_configuration', 'credential_source_label'
              )
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(forbidden_value_columns, 0);
        let arbitrary_json_columns: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND (
                  table_name LIKE 'secret%'
                  OR table_name LIKE 'protected_environment%'
              )
              AND data_type IN ('json', 'jsonb')
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(arbitrary_json_columns, 0);
        let encrypted_envelope_columns: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name IN (
                  'secret_provider_configuration_envelopes',
                  'secret_provider_locator_envelopes',
                  'secret_provider_version_envelopes',
                  'secret_provider_lease_envelopes',
                  'secret_version_envelopes'
              )
              AND column_name IN ('ciphertext', 'nonce', 'wrapped_data_key')
              AND data_type = 'bytea'
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(encrypted_envelope_columns, 15);
        let unexpected_binary_columns: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name LIKE 'secret%'
              AND data_type = 'bytea'
              AND NOT (
                  (
                      table_name IN (
                          'secret_provider_configuration_envelopes',
                          'secret_provider_locator_envelopes',
                          'secret_provider_version_envelopes',
                          'secret_provider_lease_envelopes',
                          'secret_version_envelopes'
                      )
                      AND column_name IN ('ciphertext', 'nonce', 'wrapped_data_key')
                  ) OR (
                      table_name = 'secret_workload_grants'
                      AND column_name = 'authority_digest'
                  )
              )
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(unexpected_binary_columns, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn public_output_is_allowed_only_with_a_compatible_safety_snapshot() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        sqlx::query(
            r"
            UPDATE repository_publication_policies
            SET dashboard_audience = 'public', log_audience = 'public',
                artifact_audience = 'public', revision = 2, updated_at_ms = 2
            WHERE tenant_id = $1 AND repository_id = $2
            ",
        )
        .bind(&seed.tenant_id)
        .bind(seed.repository_id)
        .execute(database.pool())
        .await?;
        let (public_run, public_job) = create_public_run_and_job(database.pool(), &seed).await?;

        let freeform_output_reason = sqlx::query(
            r"
            INSERT INTO job_attempts (
                id, job_id, attempt_number, lifecycle, fencing_token,
                queued_at_ms, changed_at_ms, secret_exposure_class,
                raw_log_disposition, requested_log_visibility,
                effective_log_visibility, output_safety_reason, classified_at_ms
            ) VALUES (
                $1, $2, 1, 'succeeded', 6, 1, 2, 'secretless',
                'persist', 'public', 'public', 'password=sentinel-secret', 1
            )
            ",
        )
        .bind(Uuid::new_v4())
        .bind(public_job)
        .execute(database.pool())
        .await
        .expect_err("output safety snapshots accept only closed nonsecret reason codes");
        assert_constraint(
            &freeform_output_reason,
            "job_attempts_output_safety_reason_code",
        );

        let mutate_historical_run = sqlx::query(
            r"
            UPDATE workflow_runs
            SET publication_policy_revision = 2,
                requested_dashboard_visibility = 'public',
                effective_dashboard_visibility = 'public',
                publication_safety_reason = 'repository_policy'
            WHERE id = $1
            ",
        )
        .bind(seed.run_id.as_uuid())
        .execute(database.pool())
        .await
        .expect_err("a historical run cannot inherit a later public repository policy");
        assert_constraint(
            &mutate_historical_run,
            "workflow_runs_publication_snapshot_immutable",
        );

        let unsafe_attempt = sqlx::query(
            r"
            INSERT INTO job_attempts (
                id, job_id, attempt_number, lifecycle, fencing_token,
                queued_at_ms, changed_at_ms, secret_exposure_class,
                raw_log_disposition, requested_log_visibility,
                effective_log_visibility, output_safety_reason, classified_at_ms
            ) VALUES (
                $1, $2, 1, 'succeeded', 7, 1, 2, 'readable_secret',
                'suppress_user_output', 'public', 'public',
                'repository_policy', 1
            )
            ",
        )
        .bind(Uuid::new_v4())
        .bind(public_job)
        .execute(database.pool())
        .await
        .expect_err("readable-secret attempts can never publish raw logs");
        assert_constraint(&unsafe_attempt, "job_attempts_exposure_safety");

        let attempt = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO job_attempts (
                id, job_id, attempt_number, lifecycle, fencing_token,
                queued_at_ms, changed_at_ms, secret_exposure_class,
                raw_log_disposition, requested_log_visibility,
                effective_log_visibility, output_safety_reason, classified_at_ms
            ) VALUES (
                $1, $2, 1, 'succeeded', 7, 1, 2, 'secretless',
                'persist', 'public', 'public', 'repository_policy', 1
            )
            ",
        )
        .bind(attempt)
        .bind(public_job)
        .execute(database.pool())
        .await?;

        let readable_attempt = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO job_attempts (
                id, job_id, attempt_number, lifecycle, fencing_token,
                queued_at_ms, changed_at_ms, secret_exposure_class,
                raw_log_disposition, requested_log_visibility,
                effective_log_visibility, output_safety_reason, classified_at_ms
            ) VALUES (
                $1, $2, 2, 'succeeded', 8, 1, 2, 'readable_secret',
                'suppress_user_output', 'public', 'private',
                'secret_exposure', 1
            )
            ",
        )
        .bind(readable_attempt)
        .bind(public_job)
        .execute(database.pool())
        .await?;

        let unsafe_artifact = sqlx::query(
            r"
            INSERT INTO workflow_artifacts (
                upload_id, tenant_id, repository_id, run_id, job_id, attempt_id,
                fencing_token, name, protocol_version, mime_type,
                created_at_seconds, secret_exposure_class,
                requested_visibility, effective_visibility,
                publication_safety_reason
            ) VALUES (
                $1, $2, $3, $4, $5, $6, 7, 'unsafe-artifact', 7,
                'application/octet-stream', 1, 'readable_secret',
                'public', 'public', 'secret_exposure'
            )
            ",
        )
        .bind(Uuid::new_v4())
        .bind(&seed.tenant_id)
        .bind(seed.repository_id)
        .bind(public_run)
        .bind(public_job)
        .bind(readable_attempt)
        .execute(database.pool())
        .await
        .expect_err("readable-secret artifacts are capped private");
        assert_constraint(&unsafe_artifact, "workflow_artifacts_exposure_safety");

        let forged_safe_artifact = sqlx::query(
            r"
            INSERT INTO workflow_artifacts (
                upload_id, tenant_id, repository_id, run_id, job_id, attempt_id,
                fencing_token, name, protocol_version, mime_type,
                created_at_seconds, secret_exposure_class,
                requested_visibility, effective_visibility,
                publication_safety_reason
            ) VALUES (
                $1, $2, $3, $4, $5, $6, 8, 'forged-safe-artifact', 7,
                'application/octet-stream', 1, 'secretless',
                'public', 'public', 'repository_policy'
            )
            ",
        )
        .bind(Uuid::new_v4())
        .bind(&seed.tenant_id)
        .bind(seed.repository_id)
        .bind(public_run)
        .bind(public_job)
        .bind(readable_attempt)
        .execute(database.pool())
        .await
        .expect_err("an artifact cannot claim a safer class than its attempt");
        assert_constraint(
            &forged_safe_artifact,
            "workflow_artifacts_attempt_exposure_snapshot",
        );

        let artifact: i64 = sqlx::query_scalar(
            r"
            INSERT INTO workflow_artifacts (
                upload_id, tenant_id, repository_id, run_id, job_id, attempt_id,
                fencing_token, name, protocol_version, mime_type,
                created_at_seconds, secret_exposure_class,
                requested_visibility, effective_visibility,
                publication_safety_reason
            ) VALUES (
                $1, $2, $3, $4, $5, $6, 7, 'public-artifact', 7,
                'application/octet-stream', 1, 'secretless',
                'public', 'public', 'repository_policy'
            ) RETURNING id
            ",
        )
        .bind(Uuid::new_v4())
        .bind(&seed.tenant_id)
        .bind(seed.repository_id)
        .bind(public_run)
        .bind(public_job)
        .bind(attempt)
        .fetch_one(database.pool())
        .await?;
        let broaden_artifact = sqlx::query(
            "UPDATE workflow_artifacts SET effective_visibility = 'private' WHERE id = $1",
        )
        .bind(artifact)
        .execute(database.pool())
        .await
        .expect_err("artifact publication safety is an immutable admission snapshot");
        assert_constraint(
            &broaden_artifact,
            "workflow_artifacts_output_safety_immutable",
        );

        let fence = seed.session_fences[0];
        let forged_safe_stream = sqlx::query(
            r"
            INSERT INTO attempt_log_streams (
                id, attempt_id, runner_session_id, operation_id, runner_id,
                runner_session_epoch, runner_generation, runner_slot, lease_id,
                fencing_token, log_schema, opened_at_ms, secret_exposure_class,
                raw_log_disposition, requested_visibility, effective_visibility,
                output_safety_reason
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, 1, $8, 8, 1, 2,
                'secretless', 'persist', 'public', 'public', 'repository_policy'
            )
            ",
        )
        .bind(Uuid::new_v4())
        .bind(readable_attempt)
        .bind(fence.session_id().as_uuid())
        .bind(Uuid::new_v4())
        .bind(fence.runner_id().as_uuid())
        .bind(i64::try_from(fence.session_epoch().get())?)
        .bind(i64::try_from(fence.runner_generation().get())?)
        .bind(Uuid::new_v4())
        .execute(database.pool())
        .await
        .expect_err("a log stream cannot claim a safer class than its attempt");
        assert_constraint(
            &forged_safe_stream,
            "attempt_log_streams_attempt_safety_snapshot",
        );

        let stream = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO attempt_log_streams (
                id, attempt_id, runner_session_id, operation_id, runner_id,
                runner_session_epoch, runner_generation, runner_slot, lease_id,
                fencing_token, log_schema, opened_at_ms, secret_exposure_class,
                raw_log_disposition, requested_visibility, effective_visibility,
                output_safety_reason
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, 1, $8, 7, 1, 2,
                'secretless', 'persist', 'public', 'public', 'repository_policy'
            )
            ",
        )
        .bind(stream)
        .bind(attempt)
        .bind(fence.session_id().as_uuid())
        .bind(Uuid::new_v4())
        .bind(fence.runner_id().as_uuid())
        .bind(i64::try_from(fence.session_epoch().get())?)
        .bind(i64::try_from(fence.runner_generation().get())?)
        .bind(Uuid::new_v4())
        .execute(database.pool())
        .await?;
        let mutate_stream = sqlx::query(
            "UPDATE attempt_log_streams SET effective_visibility = 'private' WHERE id = $1",
        )
        .bind(stream)
        .execute(database.pool())
        .await
        .expect_err("log publication safety is an immutable stream snapshot");
        assert_constraint(
            &mutate_stream,
            "attempt_log_streams_output_safety_immutable",
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn workload_grants_require_scope_access_and_protected_environment_approval() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 0).await?;
        let principal = seed_human(database.pool(), &seed.tenant_id, "401", "approver").await?;
        let second_principal =
            seed_human(database.pool(), &seed.tenant_id, "402", "reviewer").await?;
        activate_builtin(database.pool(), &seed.tenant_id).await?;
        let attempt = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO job_attempts (
                id, job_id, attempt_number, lifecycle, fencing_token,
                queued_at_ms, changed_at_ms
            ) VALUES ($1, $2, 1, 'succeeded', 9, 1, 2)
            ",
        )
        .bind(attempt)
        .bind(seed.job_id.as_uuid())
        .execute(database.pool())
        .await?;

        let environment = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO repository_environments (
                tenant_id, repository_id, id, name, normalized_name,
                protection_mode, required_approvals, prevent_self_review,
                created_by_principal_id, created_at_ms, updated_at_ms
            ) VALUES (
                $1, $2, $3, 'Release', 'release', 'required_approvals', 1,
                TRUE, $4, 1, 1
            )
            ",
        )
        .bind(&seed.tenant_id)
        .bind(seed.repository_id)
        .bind(environment)
        .bind(principal)
        .execute(database.pool())
        .await?;

        let (secret, version) =
            create_tenant_secret(database.pool(), &seed.tenant_id, principal, "DEPLOY_TOKEN")
                .await?;

        let without_repository_access = insert_workload_grant(
            database.pool(),
            &seed,
            attempt,
            secret,
            version,
            environment,
            None,
            vec![21_u8; 32],
        )
        .await
        .expect_err("tenant secrets default to no repository access");
        assert_constraint(&without_repository_access, "secret_workload_grants_scope");

        sqlx::query(
            r"
            INSERT INTO secret_repository_access (
                tenant_id, secret_id, repository_id,
                granted_by_principal_id, granted_at_ms
            ) VALUES ($1, $2, $3, $4, 3)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(secret)
        .bind(seed.repository_id)
        .bind(principal)
        .execute(database.pool())
        .await?;

        let without_approval = insert_workload_grant(
            database.pool(),
            &seed,
            attempt,
            secret,
            version,
            environment,
            None,
            vec![22_u8; 32],
        )
        .await
        .expect_err("protected environments require an approved exact workload request");
        assert_constraint(
            &without_approval,
            "secret_workload_grants_environment_approval",
        );

        let freeform_resolution = sqlx::query(
            r"
            INSERT INTO protected_environment_approval_requests (
                tenant_id, repository_id, environment_id, run_id, job_id,
                attempt_id, id, required_approvals, prevent_self_review,
                requested_by_principal_id, status, created_at_ms, expires_at_ms,
                resolved_at_ms, resolution_reason
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, 1, TRUE, $8,
                'approved', 2, 100, 3, 'token=sentinel-secret'
            )
            ",
        )
        .bind(&seed.tenant_id)
        .bind(seed.repository_id)
        .bind(environment)
        .bind(seed.run_id.as_uuid())
        .bind(seed.job_id.as_uuid())
        .bind(attempt)
        .bind(Uuid::new_v4())
        .bind(principal)
        .execute(database.pool())
        .await
        .expect_err("approval resolution persists only a closed nonsecret code");
        assert_constraint(
            &freeform_resolution,
            "protected_environment_approval_requests_status_shape",
        );

        let approval = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO protected_environment_approval_requests (
                tenant_id, repository_id, environment_id, run_id, job_id,
                attempt_id, id, required_approvals, prevent_self_review,
                requested_by_principal_id, status, created_at_ms, expires_at_ms,
                resolved_at_ms, resolution_reason
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, 1, TRUE, $8,
                'approved', 2, 100, 3, 'approval_threshold_met'
            )
            ",
        )
        .bind(&seed.tenant_id)
        .bind(seed.repository_id)
        .bind(environment)
        .bind(seed.run_id.as_uuid())
        .bind(seed.job_id.as_uuid())
        .bind(attempt)
        .bind(approval)
        .bind(principal)
        .execute(database.pool())
        .await?;

        let grant = insert_workload_grant(
            database.pool(),
            &seed,
            attempt,
            secret,
            version,
            environment,
            Some(approval),
            vec![23_u8; 32],
        )
        .await?;

        let freeform_grant_revocation = sqlx::query(
            r"
            UPDATE secret_workload_grants
            SET status = 'revoked', revoked_at_ms = 4,
                revocation_reason = 'password=sentinel-secret'
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(&seed.tenant_id)
        .bind(grant)
        .execute(database.pool())
        .await
        .expect_err("grant lifecycle persists only closed revocation codes");
        assert_constraint(
            &freeform_grant_revocation,
            "secret_workload_grants_revocation_shape",
        );

        let reclassify_granted_attempt = sqlx::query(
            r"
            UPDATE job_attempts
            SET secret_exposure_class = 'secretless',
                raw_log_disposition = 'persist',
                requested_log_visibility = 'public',
                effective_log_visibility = 'public',
                output_safety_reason = 'repository_policy',
                classified_at_ms = 3
            WHERE id = $1
            ",
        )
        .bind(attempt)
        .execute(database.pool())
        .await
        .expect_err("a readable-secret attempt cannot be relabelled public after a grant");
        assert_constraint(
            &reclassify_granted_attempt,
            "job_attempts_output_safety_immutable",
        );

        let lease = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO secret_provider_leases (
                tenant_id, id, provider_id, workload_grant_id,
                issued_at_seconds, expires_at_seconds
            ) VALUES ($1, $2, 'builtin', $3, 10, 20)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(lease)
        .bind(grant)
        .execute(database.pool())
        .await?;
        let freeform_lease_revocation = sqlx::query(
            r"
            UPDATE secret_provider_leases
            SET status = 'revoked', revoked_at_seconds = 11,
                revocation_reason = 'token=sentinel-secret'
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(&seed.tenant_id)
        .bind(lease)
        .execute(database.pool())
        .await
        .expect_err("provider lease lifecycle persists only closed revocation codes");
        assert_constraint(
            &freeform_lease_revocation,
            "secret_provider_leases_revocation_shape",
        );
        insert_provider_lease_envelope(database.pool(), &seed.tenant_id, lease).await?;
        let cleanup_operation = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO secret_cleanup_outbox (
                operation_id, tenant_id, provider_id, cleanup_kind,
                provider_lease_record_id, next_attempt_at_ms, created_at_ms
            ) VALUES ($1, $2, 'builtin', 'revoke_provider_lease', $3, 4, 4)
            ",
        )
        .bind(cleanup_operation)
        .bind(&seed.tenant_id)
        .bind(lease)
        .execute(database.pool())
        .await?;
        let freeform_cleanup_failure = sqlx::query(
            r"
            UPDATE secret_cleanup_outbox
            SET last_failure_kind = 'password=sentinel-secret'
            WHERE operation_id = $1
            ",
        )
        .bind(cleanup_operation)
        .execute(database.pool())
        .await
        .expect_err("cleanup persistence accepts only closed provider error codes");
        assert_constraint(
            &freeform_cleanup_failure,
            "secret_cleanup_outbox_failure_kind",
        );

        let pending_approval = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO protected_environment_approval_requests (
                tenant_id, repository_id, environment_id, run_id, job_id,
                attempt_id, id, required_approvals, prevent_self_review,
                requested_by_principal_id, created_at_ms, expires_at_ms
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, 1, TRUE, $8, 4, 100)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(seed.repository_id)
        .bind(environment)
        .bind(seed.run_id.as_uuid())
        .bind(seed.job_id.as_uuid())
        .bind(attempt)
        .bind(pending_approval)
        .bind(principal)
        .execute(database.pool())
        .await?;
        let freeform_decision_reason = sqlx::query(
            r"
            INSERT INTO protected_environment_approval_decisions (
                tenant_id, request_id, principal_id, decision, reason, decided_at_ms
            ) VALUES ($1, $2, $3, 'approve', 'password=sentinel-secret', 5)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(pending_approval)
        .bind(second_principal)
        .execute(database.pool())
        .await
        .expect_err("approval decisions persist only closed nonsecret reason codes");
        assert_constraint(
            &freeform_decision_reason,
            "protected_environment_approval_decisions_reason_code",
        );
        let self_review = sqlx::query(
            r"
            INSERT INTO protected_environment_approval_decisions (
                tenant_id, request_id, principal_id, decision, decided_at_ms
            ) VALUES ($1, $2, $3, 'approve', 5)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(pending_approval)
        .bind(principal)
        .execute(database.pool())
        .await
        .expect_err("protected environments can prevent self-review");
        assert_constraint(
            &self_review,
            "protected_environment_approval_decisions_self_review",
        );

        let rotation = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO secret_key_rotations (
                tenant_id, id, provider_id, from_wrapping_key_id,
                to_wrapping_key_id, discovered_versions,
                initiated_by_principal_id, created_at_ms
            ) VALUES ($1, $2, 'builtin', 'secret-kek-v1', 'secret-kek-v2', 1, $3, 5)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(rotation)
        .bind(principal)
        .execute(database.pool())
        .await?;
        let freeform_rotation_failure = sqlx::query(
            r"
            UPDATE secret_key_rotations
            SET status = 'failed', started_at_ms = 6, completed_at_ms = 7,
                failure_kind = 'token=sentinel-secret', revision = 2
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(&seed.tenant_id)
        .bind(rotation)
        .execute(database.pool())
        .await
        .expect_err("key rotation persistence accepts only closed failure codes");
        assert_constraint(
            &freeform_rotation_failure,
            "secret_key_rotations_status_shape",
        );
        sqlx::query(
            r"
            INSERT INTO secret_key_rotation_items (
                tenant_id, rotation_id, secret_version_id,
                secret_id, version_number,
                previous_envelope_generation, created_at_ms
            ) VALUES ($1, $2, $3, $4, 1, 1, 5)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(rotation)
        .bind(version)
        .bind(secret)
        .execute(database.pool())
        .await?;
        Ok(())
    })
    .await
}

async fn apply_before_secrets_migration(database: &TestDatabase) -> TestResult {
    let mut connection = database.pool().acquire().await?;
    let table_name = MIGRATOR.table_name.as_ref();
    connection.ensure_migrations_table(table_name).await?;
    for migration in MIGRATOR.iter().filter(|migration| migration.version < 12) {
        connection.apply(table_name, migration).await?;
    }
    Ok(())
}

async fn seed_human(
    pool: &PgPool,
    tenant_id: &str,
    provider_subject: &str,
    provider_login: &str,
) -> TestResult<Uuid> {
    let principal = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO human_principals (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Secret test human', 1, 1)",
    )
    .bind(principal)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO human_provider_identities (
            principal_id, provider_id, provider_subject, provider_login,
            normalized_login, first_authenticated_at_ms, last_authenticated_at_ms,
            last_observed_at_ms, created_at_ms, updated_at_ms
        ) VALUES ($1, 'github', $2, $3, $3, 1, 1, 1, 1, 1)
        ",
    )
    .bind(principal)
    .bind(provider_subject)
    .bind(provider_login)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO tenant_human_memberships (
            tenant_id, principal_id, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, 1, 1)
        ",
    )
    .bind(tenant_id)
    .bind(principal)
    .execute(pool)
    .await?;
    Ok(principal)
}

async fn create_public_run_and_job(pool: &PgPool, seed: &SeedData) -> TestResult<(Uuid, Uuid)> {
    let run_id = Uuid::new_v4();
    let job_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO workflow_runs (
            id, repository_id, workflow_id, snapshot_id, run_number,
            event_name, event_object_key, head_sha, status,
            created_at_ms, updated_at_ms, publication_policy_revision,
            requested_dashboard_visibility, effective_dashboard_visibility,
            requested_log_visibility, requested_artifact_visibility,
            publication_safety_reason, publication_safety_schema
        )
        SELECT
            $1, repository_id, workflow_id, snapshot_id, run_number + 1,
            event_name, 'test/public-event', head_sha, status,
            2, 2, 2, 'public', 'public', 'public', 'public',
            'repository_policy', 1
        FROM workflow_runs
        WHERE id = $2
        ",
    )
    .bind(run_id)
    .bind(seed.run_id.as_uuid())
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO jobs (
            id, run_id, job_key, display_name, job_ir_digest,
            job_ir_object_key, requirements, admission_epoch,
            job_ir_schema, job_ir_size_bytes, created_at_ms
        )
        SELECT
            $1, $2, 'public-output', display_name, job_ir_digest,
            job_ir_object_key, requirements, admission_epoch,
            job_ir_schema, job_ir_size_bytes, 2
        FROM jobs
        WHERE id = $3
        ",
    )
    .bind(job_id)
    .bind(run_id)
    .bind(seed.job_id.as_uuid())
    .execute(pool)
    .await?;
    Ok((run_id, job_id))
}

async fn activate_builtin(pool: &PgPool, tenant_id: &str) -> TestResult {
    sqlx::query(
        r"
        UPDATE secret_providers
        SET status = 'active', health = 'healthy', revision = 2, updated_at_ms = 2
        WHERE tenant_id = $1 AND provider_id = 'builtin'
        ",
    )
    .bind(tenant_id)
    .execute(pool)
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert_builtin_version(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    principal: Uuid,
    secret_id: Uuid,
    secret_version_id: Uuid,
    version_number: i64,
    create_request_id: &str,
) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO secret_versions (
            tenant_id, id, secret_id, version_number, provider_id,
            create_request_id, storage_kind, created_by_principal_id,
            created_at_ms
        ) VALUES ($1, $2, $3, $4, 'builtin', $5,
                  'built_in_ciphertext', $6, 2)
        ",
    )
    .bind(tenant_id)
    .bind(secret_version_id)
    .bind(secret_id)
    .bind(version_number)
    .bind(create_request_id)
    .bind(principal)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn insert_envelope(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    secret_id: Uuid,
    secret_version_id: Uuid,
    version_number: i64,
    generation: i64,
    key_id: &str,
) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO secret_version_envelopes (
            tenant_id, secret_version_id, secret_id, version_number,
            envelope_generation,
            ciphertext, nonce, wrapped_data_key, wrapping_key_id,
            envelope_schema, created_at_ms
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 1, 2)
        ",
    )
    .bind(tenant_id)
    .bind(secret_version_id)
    .bind(secret_id)
    .bind(version_number)
    .bind(generation)
    .bind(vec![31_u8; 64])
    .bind(vec![32_u8; 12])
    .bind(vec![33_u8; 48])
    .bind(key_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn insert_provider_configuration_envelope(pool: &PgPool, tenant_id: &str) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO secret_provider_configuration_envelopes (
            tenant_id, provider_id, envelope_generation, ciphertext, nonce,
            wrapped_data_key, wrapping_key_id, envelope_schema, created_at_ms
        ) VALUES ($1, 'builtin', 1, $2, $3, $4,
                  'provider-configuration-kek-v1', 1, 2)
        ",
    )
    .bind(tenant_id)
    .bind(vec![34_u8; 64])
    .bind(vec![35_u8; 12])
    .bind(vec![36_u8; 48])
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO secret_provider_configuration_envelope_heads (
            tenant_id, provider_id, envelope_generation, updated_at_ms
        ) VALUES ($1, 'builtin', 1, 2)
        ",
    )
    .bind(tenant_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn insert_provider_locator_envelope(
    pool: &PgPool,
    tenant_id: &str,
    secret_id: Uuid,
) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO secret_provider_locator_envelopes (
            tenant_id, secret_id, provider_id, envelope_generation,
            ciphertext, nonce, wrapped_data_key, wrapping_key_id,
            envelope_schema, created_at_ms
        ) VALUES ($1, $2, 'builtin', 1, $3, $4, $5,
                  'provider-reference-kek-v1', 1, 2)
        ",
    )
    .bind(tenant_id)
    .bind(secret_id)
    .bind(vec![41_u8; 64])
    .bind(vec![42_u8; 12])
    .bind(vec![43_u8; 48])
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO secret_provider_locator_envelope_heads (
            tenant_id, secret_id, envelope_generation, updated_at_ms
        ) VALUES ($1, $2, 1, 2)
        ",
    )
    .bind(tenant_id)
    .bind(secret_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn insert_provider_lease_envelope(
    pool: &PgPool,
    tenant_id: &str,
    lease_id: Uuid,
) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO secret_provider_lease_envelopes (
            tenant_id, provider_lease_record_id, provider_id,
            envelope_generation, ciphertext, nonce, wrapped_data_key,
            wrapping_key_id, envelope_schema, created_at_ms
        ) VALUES ($1, $2, 'builtin', 1, $3, $4, $5,
                  'provider-reference-kek-v1', 1, 4)
        ",
    )
    .bind(tenant_id)
    .bind(lease_id)
    .bind(vec![47_u8; 64])
    .bind(vec![48_u8; 12])
    .bind(vec![49_u8; 48])
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO secret_provider_lease_envelope_heads (
            tenant_id, provider_lease_record_id,
            envelope_generation, updated_at_ms
        ) VALUES ($1, $2, 1, 4)
        ",
    )
    .bind(tenant_id)
    .bind(lease_id)
    .execute(pool)
    .await?;
    Ok(())
}

#[allow(clippy::too_many_lines)] // Trusted fixture spells out the complete stage/confirm authority.
async fn create_tenant_secret(
    pool: &PgPool,
    tenant_id: &str,
    principal: Uuid,
    canonical_name: &str,
) -> TestResult<(Uuid, Uuid)> {
    let secret = Uuid::new_v4();
    let mutation = Uuid::new_v4();
    let version = Uuid::new_v4();
    let create_request = format!("secret-version:{mutation}");
    sqlx::query(
        r"
        INSERT INTO secrets (
            tenant_id, id, canonical_name, scope_kind, provider_id,
            created_by_principal_id, updated_by_principal_id,
            created_at_ms, updated_at_ms
        ) VALUES ($1, $2, $3, 'tenant', 'builtin', $4, $4, 1, 1)
        ",
    )
    .bind(tenant_id)
    .bind(secret)
    .bind(canonical_name)
    .bind(principal)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO secret_version_mutations (
            tenant_id, mutation_id, secret_id, scope_kind,
            canonical_name, provider_id, mutation_kind,
            reserved_secret_revision, provider_create_request_id,
            reserved_by_principal_id, reserved_at_ms
        ) VALUES (
            $1, $2, $3, 'tenant', $4, 'builtin', 'create',
            1, $5, $6, 2
        )
        ",
    )
    .bind(tenant_id)
    .bind(mutation)
    .bind(secret)
    .bind(canonical_name)
    .bind(&create_request)
    .bind(principal)
    .execute(pool)
    .await?;
    let mut staging = pool.begin().await?;
    insert_builtin_version(
        &mut staging,
        tenant_id,
        principal,
        secret,
        version,
        1,
        &create_request,
    )
    .await?;
    insert_envelope(
        &mut staging,
        tenant_id,
        secret,
        version,
        1,
        1,
        "secret-kek-v1",
    )
    .await?;
    sqlx::query(
        r"
        INSERT INTO secret_version_envelope_heads (
            tenant_id, secret_version_id, envelope_generation, updated_at_ms
        ) VALUES ($1, $2, 1, 2)
        ",
    )
    .bind(tenant_id)
    .bind(version)
    .execute(&mut *staging)
    .await?;
    sqlx::query(
        r"
        INSERT INTO secret_version_lifecycle (
            tenant_id, secret_version_id, secret_id, version_number,
            provider_id, mutation_id, status, revision,
            changed_by_principal_id, changed_at_ms
        ) VALUES ($1, $2, $3, 1, 'builtin', $4, 'staged', 1, $5, 2)
        ",
    )
    .bind(tenant_id)
    .bind(version)
    .bind(secret)
    .bind(mutation)
    .bind(principal)
    .execute(&mut *staging)
    .await?;
    staging.commit().await?;
    let mut confirmation = pool.begin().await?;
    sqlx::query(
        r"
        UPDATE secret_version_lifecycle
        SET status = 'active', revision = 2,
            changed_by_principal_id = $3, changed_at_ms = 3
        WHERE tenant_id = $1 AND secret_version_id = $2
          AND status = 'staged' AND revision = 1
        ",
    )
    .bind(tenant_id)
    .bind(version)
    .bind(principal)
    .execute(&mut *confirmation)
    .await?;
    sqlx::query(
        r"
        UPDATE secrets
        SET status = 'active', current_version_id = $3,
            current_version_number = 1,
            updated_by_principal_id = $4, updated_at_ms = 3, revision = 2
        WHERE tenant_id = $1 AND id = $2
          AND status = 'provisioning' AND revision = 1
        ",
    )
    .bind(tenant_id)
    .bind(secret)
    .bind(version)
    .bind(principal)
    .execute(&mut *confirmation)
    .await?;
    sqlx::query(
        r"
        UPDATE secret_version_mutations
        SET state = 'confirmed', completion_kind = 'builtin_created',
            committed_version_id = $3, committed_version_number = 1,
            confirmed_secret_revision = 2,
            confirmed_by_principal_id = $4, confirmed_at_ms = 3,
            revision = 2
        WHERE tenant_id = $1 AND mutation_id = $2
          AND state = 'reserved' AND revision = 1
        ",
    )
    .bind(tenant_id)
    .bind(mutation)
    .bind(version)
    .bind(principal)
    .execute(&mut *confirmation)
    .await?;
    confirmation.commit().await?;
    Ok((secret, version))
}

#[allow(clippy::too_many_arguments)]
async fn insert_workload_grant(
    pool: &PgPool,
    seed: &SeedData,
    attempt_id: Uuid,
    secret_id: Uuid,
    secret_version_id: Uuid,
    environment_id: Uuid,
    approval_id: Option<Uuid>,
    authority_digest: Vec<u8>,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar(
        r"
        INSERT INTO secret_workload_grants (
            tenant_id, repository_id, run_id, job_id, attempt_id, id,
            fencing_token, secret_id, secret_version_id,
            secret_version_number, provider_id,
            environment_id, environment_approval_request_id, grant_mode,
            event_trust, source_kind, authority_digest, authority_digest_key_id,
            issued_at_ms, expires_at_ms
        ) VALUES (
            $1, $2, $3, $4, $5, $6, 9, $7, $8, 1, 'builtin', $9, $10,
            'readable_secret', 'trusted', 'same_repository', $11,
            'workload-authority-v1', 3, 100
        ) RETURNING id
        ",
    )
    .bind(&seed.tenant_id)
    .bind(seed.repository_id)
    .bind(seed.run_id.as_uuid())
    .bind(seed.job_id.as_uuid())
    .bind(attempt_id)
    .bind(Uuid::new_v4())
    .bind(secret_id)
    .bind(secret_version_id)
    .bind(environment_id)
    .bind(approval_id)
    .bind(authority_digest)
    .fetch_one(pool)
    .await
}

fn assert_constraint(error: &sqlx::Error, expected: &str) {
    let actual = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint);
    assert_eq!(actual, Some(expected), "unexpected database error: {error}");
}

fn assert_sqlstate(error: &sqlx::Error, expected: &str) {
    let actual = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code);
    assert_eq!(
        actual.as_deref(),
        Some(expected),
        "unexpected database error: {error}"
    );
}
