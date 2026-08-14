use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::support::{SeedData, TestResult, run_with_database, seed_control_plane};

#[derive(Clone, Copy)]
struct SeededHuman {
    principal_id: Uuid,
    session_id: Uuid,
    authorization_revision: i64,
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn secret_scopes_envelopes_and_versions_are_strict_and_ciphertext_only() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 0).await?;
        let actor = seed_human(database.pool(), &seed.tenant_id, "301", "cipher").await?;
        let principal = actor.principal_id;
        activate_builtin(database.pool(), &seed.tenant_id).await?;
        insert_custody_canary(database.pool(), "secret-kek-v1").await?;
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
        let mut reservation = database.pool().begin().await?;
        sqlx::query(
            r"
            INSERT INTO secret_version_mutations (
                tenant_id, mutation_id, secret_id, scope_kind,
                repository_id, environment_id, canonical_name,
                provider_id, mutation_kind,
                reserved_secret_revision, reserved_version_number,
                confirmation_deadline_ms, provider_create_request_id,
                reserved_by_principal_id, reserved_by_session_id,
                reserved_authorization_revision, reserved_at_ms
            ) VALUES (
                $1, $2, $3, 'environment', $4, $5,
                'BUILTIN_VALUE', 'builtin', 'create', 1, 1, 600002,
                $6, $7, $8, $9, 2
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
        .bind(actor.session_id)
        .bind(actor.authorization_revision)
        .execute(&mut *reservation)
        .await?;
        sqlx::query(
            r"
            INSERT INTO secret_mutation_recovery_outbox (
                operation_id, tenant_id, mutation_id,
                next_attempt_at_ms, created_at_ms
            ) VALUES (
                automata_secret_mutation_recovery_operation_id($1, $2),
                $1, $2, 600002, 2
            )
            ",
        )
        .bind(&seed.tenant_id)
        .bind(mutation)
        .execute(&mut *reservation)
        .await?;
        reservation.commit().await?;
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
                confirmed_by_principal_id = $4, confirmed_by_session_id = $5,
                confirmed_authorization_revision = $6, confirmed_at_ms = 2,
                terminal_actor_kind = 'human',
                revision = 2
            WHERE tenant_id = $1 AND mutation_id = $2
              AND state = 'reserved' AND revision = 1
            ",
        )
        .bind(&seed.tenant_id)
        .bind(mutation)
        .bind(version)
        .bind(principal)
        .bind(actor.session_id)
        .bind(actor.authorization_revision)
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
                  'secret_version_envelopes',
                  'secret_custody_key_canaries'
              )
              AND column_name IN ('ciphertext', 'nonce', 'wrapped_data_key')
              AND data_type = 'bytea'
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(encrypted_envelope_columns, 18);
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
                          'secret_custody_key_canaries',
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
                'persist', 'public', 'public',
                'repository_policy', 1
            )
            ",
        )
        .bind(Uuid::new_v4())
        .bind(public_job)
        .execute(database.pool())
        .await
        .expect_err("readable-secret attempt resources remain private");
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
                'persist', 'public', 'private',
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
                $1, $2, $3, $4, $5, $6, 7, 'unsafe-artifact', 1,
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
                $1, $2, $3, $4, $5, $6, 8, 'forged-safe-artifact', 1,
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
                $1, $2, $3, $4, $5, $6, 7, 'public-artifact', 1,
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
        let actor = seed_human(database.pool(), &seed.tenant_id, "401", "approver").await?;
        let actor = grant_environment_review_authority(
            database.pool(),
            &seed.tenant_id,
            seed.repository_id,
            actor,
        )
        .await?;
        let principal = actor.principal_id;
        let reviewer = seed_human(database.pool(), &seed.tenant_id, "402", "reviewer").await?;
        let reviewer = grant_environment_review_authority(
            database.pool(),
            &seed.tenant_id,
            seed.repository_id,
            reviewer,
        )
        .await?;
        let second_principal = reviewer.principal_id;
        activate_builtin(database.pool(), &seed.tenant_id).await?;
        insert_custody_canary(database.pool(), "secret-kek-v1").await?;
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
        let database_now_ms: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT",
        )
        .fetch_one(database.pool())
        .await?;
        let approval_created_at = database_now_ms - 1_000;
        let approval_expires_at = database_now_ms + 60_000;
        sqlx::query(
            r"
            INSERT INTO repository_environment_reviewers (
                tenant_id, repository_id, environment_id, environment_revision,
                principal_id, principal_authorization_revision,
                granted_by_principal_id, grantor_authorization_revision, granted_at_ms
            ) VALUES
                ($1, $2, $3, 1, $4, $5, $4, $5, $6),
                ($1, $2, $3, 1, $7, $8, $7, $8, $6)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(seed.repository_id)
        .bind(environment)
        .bind(principal)
        .bind(actor.authorization_revision)
        .bind(database_now_ms)
        .bind(second_principal)
        .bind(reviewer.authorization_revision)
        .execute(database.pool())
        .await?;

        let (secret, version) =
            create_tenant_secret(database.pool(), &seed.tenant_id, actor, "DEPLOY_TOKEN").await?;

        let without_repository_access = insert_workload_grant(
            database.pool(),
            &seed,
            attempt,
            secret,
            version,
            None,
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
            Some(environment),
            None,
            vec![22_u8; 32],
        )
        .await
        .expect_err("protected environments require an approved exact workload request");
        assert_constraint(
            &without_approval,
            "secret_workload_grants_environment_current",
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
            "protected_environment_approval_snapshot",
        );

        let approval = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO protected_environment_approval_requests (
                tenant_id, repository_id, environment_id, run_id, job_id,
                attempt_id, id, required_approvals, prevent_self_review,
                requested_by_principal_id, status, created_at_ms, expires_at_ms,
                resolved_at_ms, resolution_reason, revision
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, 1, TRUE, $8,
                'pending', $9, $10, NULL, NULL, 1
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
        .bind(approval_created_at)
        .bind(approval_expires_at)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO protected_environment_approval_decisions (
                tenant_id, request_id, principal_id, decision, reason, decided_at_ms
            ) VALUES ($1, $2, $3, 'approve', 'policy_reviewed', $4)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(approval)
        .bind(second_principal)
        .bind(database_now_ms)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            UPDATE protected_environment_approval_requests
            SET status = 'approved', resolved_at_ms = $3,
                resolution_reason = 'approval_threshold_met', revision = 2
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(&seed.tenant_id)
        .bind(approval)
        .bind(database_now_ms)
        .execute(database.pool())
        .await?;

        let grant = insert_workload_grant(
            database.pool(),
            &seed,
            attempt,
            secret,
            version,
            Some(environment),
            Some(approval),
            vec![23_u8; 32],
        )
        .await?;

        let short_attempt =
            insert_succeeded_attempt(database.pool(), seed.job_id.as_uuid(), 2).await?;
        let short_approval = Uuid::new_v4();
        let short_created_at: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT",
        )
        .fetch_one(database.pool())
        .await?;
        let short_expires_at = short_created_at + 1_000;
        sqlx::query(
            r"
            INSERT INTO protected_environment_approval_requests (
                tenant_id, repository_id, environment_id, run_id, job_id,
                attempt_id, id, required_approvals, prevent_self_review,
                requested_by_principal_id, created_at_ms, expires_at_ms
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, 1, TRUE, $8, $9, $10)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(seed.repository_id)
        .bind(environment)
        .bind(seed.run_id.as_uuid())
        .bind(seed.job_id.as_uuid())
        .bind(short_attempt)
        .bind(short_approval)
        .bind(principal)
        .bind(short_created_at - 1)
        .bind(short_expires_at)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO protected_environment_approval_decisions (
                tenant_id, request_id, principal_id, decision, decided_at_ms
            ) VALUES ($1, $2, $3, 'approve', $4)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(short_approval)
        .bind(second_principal)
        .bind(short_created_at)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            UPDATE protected_environment_approval_requests
            SET status = 'approved', resolved_at_ms = $3,
                resolution_reason = 'approval_threshold_met', revision = 2
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(&seed.tenant_id)
        .bind(short_approval)
        .bind(short_created_at)
        .execute(database.pool())
        .await?;
        loop {
            let current: i64 = sqlx::query_scalar(
                "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT",
            )
            .fetch_one(database.pool())
            .await?;
            if current >= short_expires_at {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let backdated_grant = sqlx::query(
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
                'backdated-workload-authority-v1', $12,
                floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT + 60000
            )
            ",
        )
        .bind(&seed.tenant_id)
        .bind(seed.repository_id)
        .bind(seed.run_id.as_uuid())
        .bind(seed.job_id.as_uuid())
        .bind(short_attempt)
        .bind(Uuid::new_v4())
        .bind(secret)
        .bind(version)
        .bind(environment)
        .bind(short_approval)
        .bind(vec![25_u8; 32])
        .bind(short_created_at)
        .execute(database.pool())
        .await
        .expect_err("an expired approval cannot issue a backdated workload grant");
        assert_constraint(
            &backdated_grant,
            "secret_workload_grants_environment_current",
        );

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
        sqlx::query(
            r"
            UPDATE secret_cleanup_outbox
            SET status = 'in_progress', attempts = 1, claim_generation = 1,
                locked_by = 'cleanup-worker', locked_at_ms = 4
            WHERE operation_id = $1
            ",
        )
        .bind(cleanup_operation)
        .execute(database.pool())
        .await?;
        let freeform_cleanup_failure = sqlx::query(
            r"
            UPDATE secret_cleanup_outbox
            SET status = 'pending', attempts = 1, claim_generation = 1,
                next_attempt_at_ms = 5,
                locked_by = NULL, locked_at_ms = NULL,
                last_failure_kind = 'password=sentinel-secret',
                completed_at_ms = NULL
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

        let pending_attempt =
            insert_succeeded_attempt(database.pool(), seed.job_id.as_uuid(), 3).await?;
        let pending_approval = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO protected_environment_approval_requests (
                tenant_id, repository_id, environment_id, run_id, job_id,
                attempt_id, id, required_approvals, prevent_self_review,
                requested_by_principal_id, created_at_ms, expires_at_ms
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, 1, TRUE, $8, $9, $10)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(seed.repository_id)
        .bind(environment)
        .bind(seed.run_id.as_uuid())
        .bind(seed.job_id.as_uuid())
        .bind(pending_attempt)
        .bind(pending_approval)
        .bind(principal)
        .bind(approval_created_at)
        .bind(approval_expires_at)
        .execute(database.pool())
        .await?;
        let mutate_pending_revision = sqlx::query(
            r"
            UPDATE protected_environment_approval_requests
            SET revision = revision + 1
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(&seed.tenant_id)
        .bind(pending_approval)
        .execute(database.pool())
        .await
        .expect_err("pending approval revisions are immutable");
        assert_constraint(
            &mutate_pending_revision,
            "protected_environment_approval_revision_guard",
        );
        let truncate_decisions = sqlx::query("TRUNCATE protected_environment_approval_decisions")
            .execute(database.pool())
            .await
            .expect_err("approval decisions are append-only under TRUNCATE");
        assert_constraint(
            &truncate_decisions,
            "protected_environment_approval_decisions_immutable",
        );
        let freeform_decision_reason = sqlx::query(
            r"
            INSERT INTO protected_environment_approval_decisions (
                tenant_id, request_id, principal_id, decision, reason, decided_at_ms
            ) VALUES ($1, $2, $3, 'approve', 'password=sentinel-secret', $4)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(pending_approval)
        .bind(second_principal)
        .bind(database_now_ms)
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
            ) VALUES ($1, $2, $3, 'approve', $4)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(pending_approval)
        .bind(principal)
        .bind(database_now_ms)
        .execute(database.pool())
        .await
        .expect_err("protected environments can prevent self-review");
        assert_constraint(
            &self_review,
            "protected_environment_approval_decisions_self_review",
        );

        let expired_attempt =
            insert_succeeded_attempt(database.pool(), seed.job_id.as_uuid(), 4).await?;
        let expired_approval = Uuid::new_v4();
        let expired_created_at: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT",
        )
        .fetch_one(database.pool())
        .await?;
        let expired_at = expired_created_at + 1_000;
        sqlx::query(
            r"
            INSERT INTO protected_environment_approval_requests (
                tenant_id, repository_id, environment_id, run_id, job_id,
                attempt_id, id, required_approvals, prevent_self_review,
                requested_by_principal_id, created_at_ms, expires_at_ms
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, 1, TRUE, $8, $9, $10)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(seed.repository_id)
        .bind(environment)
        .bind(seed.run_id.as_uuid())
        .bind(seed.job_id.as_uuid())
        .bind(expired_attempt)
        .bind(expired_approval)
        .bind(principal)
        .bind(expired_created_at)
        .bind(expired_at)
        .execute(database.pool())
        .await?;
        loop {
            let current: i64 = sqlx::query_scalar(
                "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT",
            )
            .fetch_one(database.pool())
            .await?;
            if current >= expired_at {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let expired_decision = sqlx::query(
            r"
            INSERT INTO protected_environment_approval_decisions (
                tenant_id, request_id, principal_id, decision, decided_at_ms
            ) VALUES ($1, $2, $3, 'approve', $4)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(expired_approval)
        .bind(second_principal)
        .bind(expired_created_at)
        .execute(database.pool())
        .await
        .expect_err("an expired request cannot accept a backdated decision");
        assert_constraint(
            &expired_decision,
            "protected_environment_approval_decisions_lifetime",
        );
        let expired_resolution = sqlx::query(
            r"
            UPDATE protected_environment_approval_requests
            SET status = 'approved', resolved_at_ms = $3,
                resolution_reason = 'approval_threshold_met', revision = 2
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(&seed.tenant_id)
        .bind(expired_approval)
        .bind(expired_created_at)
        .execute(database.pool())
        .await
        .expect_err("an expired request cannot be approved with a backdated resolution");
        assert_constraint(
            &expired_resolution,
            "protected_environment_approval_resolution_current",
        );

        sqlx::query(
            r"
            UPDATE repository_environments
            SET required_approvals = 2, revision = 2, updated_at_ms = 6
            WHERE tenant_id = $1 AND repository_id = $2 AND id = $3
            ",
        )
        .bind(&seed.tenant_id)
        .bind(seed.repository_id)
        .bind(environment)
        .execute(database.pool())
        .await?;
        let stale_decision = sqlx::query(
            r"
            INSERT INTO protected_environment_approval_decisions (
                tenant_id, request_id, principal_id, decision, decided_at_ms
            ) VALUES ($1, $2, $3, 'approve', 6)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(pending_approval)
        .bind(second_principal)
        .execute(database.pool())
        .await
        .expect_err("a policy revision invalidates pending review evidence");
        assert_constraint(
            &stale_decision,
            "protected_environment_approval_decisions_current_policy",
        );
        let stale_resolution = sqlx::query(
            r"
            UPDATE protected_environment_approval_requests
            SET status = 'approved', resolved_at_ms = $3,
                resolution_reason = 'approval_threshold_met', revision = 2
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(&seed.tenant_id)
        .bind(pending_approval)
        .bind(database_now_ms)
        .execute(database.pool())
        .await
        .expect_err("stale policy evidence cannot become approved");
        assert_constraint(
            &stale_resolution,
            "protected_environment_approval_resolution_current",
        );
        let stale_approved_grant = insert_workload_grant(
            database.pool(),
            &seed,
            attempt,
            secret,
            version,
            Some(environment),
            Some(approval),
            vec![24_u8; 32],
        )
        .await
        .expect_err("a previously approved request cannot survive a policy revision");
        assert_constraint(
            &stale_approved_grant,
            "secret_workload_grants_environment_current",
        );

        sqlx::query(
            r"
            UPDATE repository_environments
            SET required_approvals = 1, revision = 3, updated_at_ms = 7
            WHERE tenant_id = $1 AND repository_id = $2 AND id = $3
            ",
        )
        .bind(&seed.tenant_id)
        .bind(seed.repository_id)
        .bind(environment)
        .execute(database.pool())
        .await?;
        let aba_decision = sqlx::query(
            r"
            INSERT INTO protected_environment_approval_decisions (
                tenant_id, request_id, principal_id, decision, decided_at_ms
            ) VALUES ($1, $2, $3, 'approve', 7)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(pending_approval)
        .bind(second_principal)
        .execute(database.pool())
        .await
        .expect_err("restoring visible policy settings does not restore an old revision");
        assert_constraint(
            &aba_decision,
            "protected_environment_approval_decisions_current_policy",
        );

        sqlx::query(
            r"
            UPDATE repository_environments
            SET status = 'disabled', revision = 4, updated_at_ms = 8
            WHERE tenant_id = $1 AND repository_id = $2 AND id = $3
            ",
        )
        .bind(&seed.tenant_id)
        .bind(seed.repository_id)
        .bind(environment)
        .execute(database.pool())
        .await?;
        let disabled_decision = sqlx::query(
            r"
            INSERT INTO protected_environment_approval_decisions (
                tenant_id, request_id, principal_id, decision, decided_at_ms
            ) VALUES ($1, $2, $3, 'approve', 8)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(pending_approval)
        .bind(second_principal)
        .execute(database.pool())
        .await
        .expect_err("disabled environments cannot accept review decisions");
        assert_constraint(
            &disabled_decision,
            "protected_environment_approval_decisions_current_policy",
        );
        let mistyped_stale_cancellation = sqlx::query(
            r"
            UPDATE protected_environment_approval_requests
            SET status = 'cancelled', resolved_at_ms = $3,
                resolution_reason = 'policy_changed', revision = 2
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(&seed.tenant_id)
        .bind(pending_approval)
        .bind(database_now_ms)
        .execute(database.pool())
        .await
        .expect_err("disabled policy evidence requires the exact cancellation code");
        assert_constraint(
            &mistyped_stale_cancellation,
            "protected_environment_approval_stale_resolution",
        );
        sqlx::query(
            r"
            UPDATE protected_environment_approval_requests
            SET status = 'cancelled', resolved_at_ms = $3,
                resolution_reason = 'environment_disabled', revision = 2
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(&seed.tenant_id)
        .bind(pending_approval)
        .bind(database_now_ms)
        .execute(database.pool())
        .await?;

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

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)] // One transaction preserves the full grantor-revision proof.
async fn protected_environment_approval_rechecks_reviewer_grantor_authorization_revision()
-> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 0).await?;
        let grantor = grant_environment_review_authority(
            database.pool(),
            &seed.tenant_id,
            seed.repository_id,
            seed_human(
                database.pool(),
                &seed.tenant_id,
                "review-grantor",
                "grantor",
            )
            .await?,
        )
        .await?;
        let reviewer = grant_environment_review_authority(
            database.pool(),
            &seed.tenant_id,
            seed.repository_id,
            seed_human(
                database.pool(),
                &seed.tenant_id,
                "review-reviewer",
                "reviewer",
            )
            .await?,
        )
        .await?;
        let attempt = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO job_attempts (
                id, job_id, attempt_number, lifecycle, fencing_token,
                queued_at_ms, changed_at_ms
            ) VALUES ($1, $2, 1, 'succeeded', 1, 1, 1)
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
        .bind(grantor.principal_id)
        .execute(database.pool())
        .await?;
        let now: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT",
        )
        .fetch_one(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO repository_environment_reviewers (
                tenant_id, repository_id, environment_id, environment_revision,
                principal_id, principal_authorization_revision,
                granted_by_principal_id, grantor_authorization_revision, granted_at_ms
            ) VALUES ($1, $2, $3, 1, $4, $5, $6, $7, $8)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(seed.repository_id)
        .bind(environment)
        .bind(reviewer.principal_id)
        .bind(reviewer.authorization_revision)
        .bind(grantor.principal_id)
        .bind(grantor.authorization_revision)
        .bind(now)
        .execute(database.pool())
        .await?;
        let approval = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO protected_environment_approval_requests (
                tenant_id, repository_id, environment_id, run_id, job_id,
                attempt_id, id, required_approvals, prevent_self_review,
                requested_by_principal_id, status, created_at_ms, expires_at_ms,
                resolved_at_ms, resolution_reason, revision
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, 1, TRUE,
                $8, 'pending', $9, $10, NULL, NULL, 1
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
        .bind(grantor.principal_id)
        .bind(now)
        .bind(now + 60_000)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO protected_environment_approval_decisions (
                tenant_id, request_id, principal_id, decision, decided_at_ms
            ) VALUES ($1, $2, $3, 'approve', $4)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(approval)
        .bind(reviewer.principal_id)
        .bind(now)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            UPDATE protected_environment_approval_requests
            SET status = 'approved', resolved_at_ms = $3,
                resolution_reason = 'approval_threshold_met', revision = 2
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(&seed.tenant_id)
        .bind(approval)
        .bind(now)
        .execute(database.pool())
        .await?;
        let current: bool = sqlx::query_scalar(
            "SELECT automata_protected_environment_approval_is_current($1, $2, $3)",
        )
        .bind(&seed.tenant_id)
        .bind(approval)
        .bind(now)
        .fetch_one(database.pool())
        .await?;
        assert!(current, "the exact reviewer/grantor proof starts current");

        sqlx::query(
            r"
            UPDATE tenant_human_memberships
            SET authorization_revision = authorization_revision + 1
            WHERE tenant_id = $1 AND principal_id = $2
            ",
        )
        .bind(&seed.tenant_id)
        .bind(grantor.principal_id)
        .execute(database.pool())
        .await?;
        let current_after_grantor_aba: bool = sqlx::query_scalar(
            "SELECT automata_protected_environment_approval_is_current($1, $2, $3)",
        )
        .bind(&seed.tenant_id)
        .bind(approval)
        .bind(now)
        .fetch_one(database.pool())
        .await?;
        assert!(
            !current_after_grantor_aba,
            "grantor authorization ABA invalidates prior reviewer assignment evidence",
        );
        Ok(())
    })
    .await
}

async fn seed_human(
    pool: &PgPool,
    tenant_id: &str,
    provider_subject: &str,
    provider_login: &str,
) -> TestResult<SeededHuman> {
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
    let authorization_revision: i64 = sqlx::query_scalar(
        r"
        SELECT authorization_revision
        FROM tenant_human_memberships
        WHERE tenant_id = $1 AND principal_id = $2
        ",
    )
    .bind(tenant_id)
    .bind(principal)
    .fetch_one(pool)
    .await?;
    let session_id = Uuid::new_v4();
    let mut token_hash = [0_u8; 32];
    token_hash[..16].copy_from_slice(session_id.as_bytes());
    token_hash[16..].copy_from_slice(session_id.as_bytes());
    sqlx::query(
        r"
        INSERT INTO human_sessions (
            id, tenant_id, principal_id, provider_id, provider_subject,
            session_kind, audience, token_hash, token_hash_key_id,
            authorization_revision, issued_at_ms, last_seen_at_ms,
            idle_expires_at_ms, expires_at_ms
        ) VALUES (
            $1, $2, $3, 'github', $4, 'browser', 'automata.web',
            $5, 'secret-output-session-v1', $6, 1, 1, 700000, 750000
        )
        ",
    )
    .bind(session_id)
    .bind(tenant_id)
    .bind(principal)
    .bind(provider_subject)
    .bind(token_hash.as_slice())
    .bind(authorization_revision)
    .execute(pool)
    .await?;
    Ok(SeededHuman {
        principal_id: principal,
        session_id,
        authorization_revision,
    })
}

async fn grant_environment_review_authority(
    pool: &PgPool,
    tenant_id: &str,
    repository_id: Uuid,
    actor: SeededHuman,
) -> TestResult<SeededHuman> {
    let role_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO rbac_roles (
            tenant_id, id, name, display_name, role_kind, immutable,
            created_by_principal_id, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, $3, 'Environment reviewer', 'custom', FALSE, $4, 1, 1)
        ",
    )
    .bind(tenant_id)
    .bind(role_id)
    .bind(format!("environment-reviewer-{}", role_id.simple()))
    .bind(actor.principal_id)
    .execute(pool)
    .await?;
    for permission in ["environments:approve", "environments:manage"] {
        sqlx::query(
            r"
            INSERT INTO rbac_role_permissions (
                tenant_id, role_id, permission_name,
                granted_by_principal_id, granted_at_ms
            ) VALUES ($1, $2, $3, $4, 1)
            ",
        )
        .bind(tenant_id)
        .bind(role_id)
        .bind(permission)
        .bind(actor.principal_id)
        .execute(pool)
        .await?;
    }
    sqlx::query(
        r"
        INSERT INTO rbac_role_bindings (
            tenant_id, id, principal_id, role_id, scope_kind, repository_id,
            assignment_source, created_by_principal_id, created_at_ms
        ) VALUES ($1, $2, $3, $4, 'repository', $5, 'manual', $3, 1)
        ",
    )
    .bind(tenant_id)
    .bind(Uuid::new_v4())
    .bind(actor.principal_id)
    .bind(role_id)
    .bind(repository_id)
    .execute(pool)
    .await?;
    let authorization_revision: i64 = sqlx::query_scalar(
        "SELECT authorization_revision FROM tenant_human_memberships WHERE tenant_id = $1 AND principal_id = $2",
    )
    .bind(tenant_id)
    .bind(actor.principal_id)
    .fetch_one(pool)
    .await?;
    // Role bindings advance the durable authorization revision.  Issue a
    // fresh browser session rather than mutating the historical session, so
    // later fixture writes carry current authorization evidence.
    let provider_subject: String =
        sqlx::query_scalar("SELECT provider_subject FROM human_sessions WHERE id = $1")
            .bind(actor.session_id)
            .fetch_one(pool)
            .await?;
    let session_id = Uuid::new_v4();
    let mut token_hash = [0_u8; 32];
    token_hash[..16].copy_from_slice(session_id.as_bytes());
    token_hash[16..].copy_from_slice(session_id.as_bytes());
    sqlx::query(
        r"
        INSERT INTO human_sessions (
            id, tenant_id, principal_id, provider_id, provider_subject,
            session_kind, audience, token_hash, token_hash_key_id,
            authorization_revision, issued_at_ms, last_seen_at_ms,
            idle_expires_at_ms, expires_at_ms
        ) VALUES (
            $1, $2, $3, 'github', $4, 'browser', 'automata.web',
            $5, 'secret-output-session-v1', $6, 1, 1, 700000, 750000
        )
        ",
    )
    .bind(session_id)
    .bind(tenant_id)
    .bind(actor.principal_id)
    .bind(provider_subject)
    .bind(token_hash.as_slice())
    .bind(authorization_revision)
    .execute(pool)
    .await?;
    Ok(SeededHuman {
        session_id,
        authorization_revision,
        ..actor
    })
}

async fn create_public_run_and_job(pool: &PgPool, seed: &SeedData) -> TestResult<(Uuid, Uuid)> {
    let run_id = Uuid::new_v4();
    let job_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO workflow_runs (
            id, repository_id, workflow_id, snapshot_id, run_number,
            event_name, event_object_key, event_digest, event_size_bytes,
            event_media_type, plan_digest, plan_object_key, plan_size_bytes,
            plan_media_type, plan_schema, workflow_name, head_sha, status,
            created_at_ms, updated_at_ms, publication_policy_revision,
            requested_dashboard_visibility, effective_dashboard_visibility,
            requested_log_visibility, requested_artifact_visibility,
            publication_safety_reason, publication_safety_schema,
            runner_requirements_schema
        )
        SELECT
            $1, repository_id, workflow_id, snapshot_id, run_number + 1,
            event_name, 'test/public-event', event_digest, event_size_bytes,
            event_media_type, plan_digest, plan_object_key, plan_size_bytes,
            plan_media_type, plan_schema, workflow_name, head_sha, status,
            2, 2, 2, 'public', 'public', 'public', 'public',
            'repository_policy', 1, runner_requirements_schema
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

async fn insert_custody_canary(pool: &PgPool, wrapping_key_id: &str) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO secret_custody_key_canaries (
            wrapping_key_id, canary_generation, canary_schema,
            ciphertext, nonce, wrapped_data_key, envelope_schema,
            created_at_ms
        ) VALUES ($1, 1, 1, $2, $3, $4, 1, 2)
        ",
    )
    .bind(wrapping_key_id)
    .bind(vec![51_u8; 52])
    .bind(vec![52_u8; 12])
    .bind(vec![53_u8; 48])
    .execute(pool)
    .await?;
    Ok(())
}

#[allow(clippy::too_many_lines)] // Trusted fixture spells out the complete stage/confirm authority.
async fn create_tenant_secret(
    pool: &PgPool,
    tenant_id: &str,
    actor: SeededHuman,
    canonical_name: &str,
) -> TestResult<(Uuid, Uuid)> {
    let principal = actor.principal_id;
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
    let mut reservation = pool.begin().await?;
    sqlx::query(
        r"
        INSERT INTO secret_version_mutations (
            tenant_id, mutation_id, secret_id, scope_kind,
            canonical_name, provider_id, mutation_kind,
            reserved_secret_revision, reserved_version_number,
            confirmation_deadline_ms, provider_create_request_id,
            reserved_by_principal_id, reserved_by_session_id,
            reserved_authorization_revision, reserved_at_ms
        ) VALUES (
            $1, $2, $3, 'tenant', $4, 'builtin', 'create',
            1, 1, 600002, $5, $6, $7, $8, 2
        )
        ",
    )
    .bind(tenant_id)
    .bind(mutation)
    .bind(secret)
    .bind(canonical_name)
    .bind(&create_request)
    .bind(principal)
    .bind(actor.session_id)
    .bind(actor.authorization_revision)
    .execute(&mut *reservation)
    .await?;
    sqlx::query(
        r"
        INSERT INTO secret_mutation_recovery_outbox (
            operation_id, tenant_id, mutation_id,
            next_attempt_at_ms, created_at_ms
        ) VALUES (
            automata_secret_mutation_recovery_operation_id($1, $2),
            $1, $2, 600002, 2
        )
        ",
    )
    .bind(tenant_id)
    .bind(mutation)
    .execute(&mut *reservation)
    .await?;
    reservation.commit().await?;
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
            confirmed_by_principal_id = $4, confirmed_by_session_id = $5,
            confirmed_authorization_revision = $6, confirmed_at_ms = 3,
            terminal_actor_kind = 'human',
            revision = 2
        WHERE tenant_id = $1 AND mutation_id = $2
          AND state = 'reserved' AND revision = 1
        ",
    )
    .bind(tenant_id)
    .bind(mutation)
    .bind(version)
    .bind(principal)
    .bind(actor.session_id)
    .bind(actor.authorization_revision)
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
    environment_id: Option<Uuid>,
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
            'workload-authority-v1',
            floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT,
            floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT + 60000
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

async fn insert_succeeded_attempt(
    pool: &PgPool,
    job_id: Uuid,
    attempt_number: i32,
) -> Result<Uuid, sqlx::Error> {
    let attempt_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO job_attempts (
            id, job_id, attempt_number, lifecycle, fencing_token,
            queued_at_ms, changed_at_ms
        ) VALUES ($1, $2, $3, 'succeeded', 9, 1, 2)
        ",
    )
    .bind(attempt_id)
    .bind(job_id)
    .bind(attempt_number)
    .execute(pool)
    .await?;
    Ok(attempt_id)
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
