#[allow(dead_code)]
use crate::common;

use sqlx::PgPool;
use uuid::Uuid;

use common::{TestResult, run_with_database, seed_control_plane};

const HUMAN_AUTH_MIGRATION: &str = include_str!("../migrations/0001_initial_schema.sql");

#[test]
fn human_auth_migration_keeps_publication_private_and_never_names_value_read() {
    assert!(HUMAN_AUTH_MIGRATION.contains("dashboard_audience TEXT NOT NULL DEFAULT 'private'"));
    assert!(HUMAN_AUTH_MIGRATION.contains("log_audience TEXT NOT NULL DEFAULT 'private'"));
    assert!(HUMAN_AUTH_MIGRATION.contains("artifact_audience TEXT NOT NULL DEFAULT 'private'"));
    assert!(HUMAN_AUTH_MIGRATION.contains("public_if_safe"));
    assert!(HUMAN_AUTH_MIGRATION.contains("octet_length(token_hash) = 32"));
    assert!(HUMAN_AUTH_MIGRATION.contains("security_audit_events_append_only"));
    assert!(!HUMAN_AUTH_MIGRATION.contains("secrets.value.read"));
    assert!(HUMAN_AUTH_MIGRATION.contains("('runs:read'"));
    assert!(HUMAN_AUTH_MIGRATION.contains("('repositories:read'"));
    assert!(!HUMAN_AUTH_MIGRATION.contains("('runs.read'"));
    assert!(!HUMAN_AUTH_MIGRATION.contains("('repositories.read'"));
    assert!(!HUMAN_AUTH_MIGRATION.contains("device_user_code TEXT"));
    assert!(!HUMAN_AUTH_MIGRATION.contains("verification_uri TEXT"));
    assert!(!HUMAN_AUTH_MIGRATION.contains("access_token TEXT"));
    assert!(!HUMAN_AUTH_MIGRATION.contains("refresh_token TEXT"));
    assert!(!HUMAN_AUTH_MIGRATION.contains("metadata JSONB"));
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn auth_schema_enforces_encrypted_credentials_and_tenant_scopes() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let principal = seed_human(database.pool(), &seed.tenant_id, "101", "octocat").await?;

        let short_session_hash = sqlx::query(
            r"
            INSERT INTO human_sessions (
                id, tenant_id, principal_id, provider_id, provider_subject,
                session_kind, audience, token_hash, token_hash_key_id,
                authorization_revision, issued_at_ms, last_seen_at_ms,
                idle_expires_at_ms, expires_at_ms
            ) VALUES (
                $1, $2, $3, 'github', '101', 'browser', 'automata.web',
                $4, 'session-hmac-v1', 1, 10, 10, 20, 30
            )
            ",
        )
        .bind(Uuid::new_v4())
        .bind(&seed.tenant_id)
        .bind(principal)
        .bind(vec![1_u8; 31])
        .execute(database.pool())
        .await
        .expect_err("session bearer digests must contain exactly 32 bytes");
        assert_constraint(&short_session_hash, "human_sessions_token_hash");

        let invalid_token_envelope = sqlx::query(
            r"
            INSERT INTO human_provider_tokens (
                envelope_record_id, tenant_id, principal_id, provider_id,
                provider_subject, version, grant_kind, token_type,
                encrypted_payload, payload_nonce, wrapped_data_key,
                encryption_key_id, encryption_schema, issued_at_ms,
                access_expires_at_ms, refresh_expires_at_ms, created_at_ms, updated_at_ms
            ) VALUES (
                $1, $2, $3, 'github', '101', 1,
                'browser_authorization_code', 'bearer',
                $4, $5, $6, 'auth-kek-v1', 1, 10, 20, 30, 10, 10
            )
            ",
        )
        .bind(Uuid::new_v4())
        .bind(&seed.tenant_id)
        .bind(principal)
        .bind(vec![2_u8; 64])
        .bind(vec![3_u8; 11])
        .bind(vec![4_u8; 48])
        .execute(database.pool())
        .await
        .expect_err("provider token envelopes must carry the exact AEAD nonce shape");
        assert_constraint(
            &invalid_token_envelope,
            "human_provider_tokens_envelope_shape",
        );

        let invalid_browser_transaction = sqlx::query(
            r"
            INSERT INTO human_login_transactions (
                id, tenant_id, purpose, flow_kind, provider_id, return_path,
                state_hash, encrypted_payload, payload_nonce, wrapped_data_key,
                encryption_key_id, encryption_schema, created_at_ms, updated_at_ms,
                expires_at_ms
            ) VALUES (
                $1, $2, 'sign_in', 'browser', 'github', '/runs', $3,
                $4, $5, $6, 'login-kek-v1', 1, 10, 10, 20
            )
            ",
        )
        .bind(Uuid::new_v4())
        .bind(&seed.tenant_id)
        .bind(vec![5_u8; 32])
        .bind(vec![6_u8; 64])
        .bind(vec![7_u8; 12])
        .bind(vec![8_u8; 48])
        .execute(database.pool())
        .await
        .expect_err("browser login state must be bound to the initiating browser");
        assert_constraint(
            &invalid_browser_transaction,
            "human_login_transactions_flow_shape",
        );

        let other_tenant = format!("auth-other-{}", Uuid::new_v4().simple());
        sqlx::query(
            "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Other tenant', 1, 1)",
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
            ) VALUES ($1, $2, 'test', $3, 'automata-ci', 'other', 1, 1)
            ",
        )
        .bind(other_repository)
        .bind(&other_tenant)
        .bind(other_repository.to_string())
        .execute(database.pool())
        .await?;

        let role = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO rbac_roles (
                tenant_id, id, name, display_name, created_at_ms, updated_at_ms
            ) VALUES ($1, $2, 'viewer', 'Viewer', 1, 1)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(role)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO rbac_role_bindings (
                tenant_id, id, principal_id, role_id, scope_kind, created_at_ms
            ) VALUES ($1, $2, $3, $4, 'tenant', 10)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(Uuid::new_v4())
        .bind(principal)
        .bind(role)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO rbac_role_permissions (
                tenant_id, role_id, permission_name, granted_at_ms
            ) VALUES ($1, $2, 'runs:read', 10)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(role)
        .execute(database.pool())
        .await?;
        let authorization_revision: i64 = sqlx::query_scalar(
            "SELECT authorization_revision FROM tenant_human_memberships WHERE tenant_id=$1 AND principal_id=$2",
        )
        .bind(&seed.tenant_id)
        .bind(principal)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(authorization_revision, 3);
        sqlx::query(
            r"
            UPDATE tenant_human_memberships
            SET status='suspended', suspended_at_ms=20,
                suspended_reason='security review', revision=revision+1,
                updated_at_ms=20
            WHERE tenant_id=$1 AND principal_id=$2
            ",
        )
        .bind(&seed.tenant_id)
        .bind(principal)
        .execute(database.pool())
        .await?;
        let suspended_revision: i64 = sqlx::query_scalar(
            "SELECT authorization_revision FROM tenant_human_memberships WHERE tenant_id=$1 AND principal_id=$2",
        )
        .bind(&seed.tenant_id)
        .bind(principal)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(suspended_revision, 4);
        let cross_tenant_binding = sqlx::query(
            r"
            INSERT INTO rbac_role_bindings (
                tenant_id, id, principal_id, role_id, scope_kind, repository_id,
                created_at_ms
            ) VALUES ($1, $2, $3, $4, 'repository', $5, 10)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(Uuid::new_v4())
        .bind(principal)
        .bind(role)
        .bind(other_repository)
        .execute(database.pool())
        .await
        .expect_err("repository role bindings must match the binding tenant");
        assert_constraint(&cross_tenant_binding, "rbac_role_bindings_repository");

        let forbidden_plaintext_columns: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name IN (
                  'human_login_transactions', 'human_provider_tokens', 'human_sessions',
                  'security_audit_events'
              )
              AND column_name IN (
                  'access_token', 'refresh_token', 'session_token', 'plaintext',
                  'pkce_verifier', 'oauth_state', 'browser_binding', 'poll_proof',
                  'device_code', 'device_user_code', 'verification_uri', 'metadata'
              )
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(forbidden_plaintext_columns, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn github_membership_uses_numeric_identity_and_audit_is_append_only() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 0).await?;
        let principal = seed_human(database.pool(), &seed.tenant_id, "202", "hubot").await?;
        let role = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO rbac_roles (
                tenant_id, id, name, display_name, created_at_ms, updated_at_ms
            ) VALUES ($1, $2, 'maintainer', 'Maintainer', 1, 1)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(role)
        .execute(database.pool())
        .await?;

        sqlx::query(
            r"
            INSERT INTO github_role_mappings (
                tenant_id, id, organization_id, organization_login, role_id,
                scope_kind, created_at_ms, updated_at_ms
            ) VALUES ($1, $2, 4242, 'old-name', $3, 'tenant', 1, 1)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(Uuid::new_v4())
        .bind(role)
        .execute(database.pool())
        .await?;
        let renamed_duplicate = sqlx::query(
            r"
            INSERT INTO github_role_mappings (
                tenant_id, id, organization_id, organization_login, role_id,
                scope_kind, created_at_ms, updated_at_ms
            ) VALUES ($1, $2, 4242, 'new-name', $3, 'tenant', 2, 2)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(Uuid::new_v4())
        .bind(role)
        .execute(database.pool())
        .await
        .expect_err("renaming an organization cannot create a second stable-ID mapping");
        assert_constraint(
            &renamed_duplicate,
            "github_role_mappings_active_organization_tenant",
        );

        let snapshot = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO github_membership_snapshots (
                tenant_id, id, principal_id, provider_subject,
                provider_token_version, observed_at_ms, valid_until_ms
            ) VALUES ($1, $2, $3, '202', 1, 10, 20)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(snapshot)
        .bind(principal)
        .execute(database.pool())
        .await?;
        let team_without_organization = sqlx::query(
            r"
            INSERT INTO github_team_membership_observations (
                tenant_id, snapshot_id, organization_id, team_id, team_slug
            ) VALUES ($1, $2, 4242, 5151, 'security')
            ",
        )
        .bind(&seed.tenant_id)
        .bind(snapshot)
        .execute(database.pool())
        .await
        .expect_err("a team observation requires its stable organization observation");
        assert_constraint(
            &team_without_organization,
            "github_team_membership_observations_organization",
        );

        let event_id = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO security_audit_events (
                event_id, tenant_id, occurred_at_ms, actor_kind, action, outcome,
                resource_kind, resource_id
            ) VALUES (
                $1, $2, 10, 'system', 'auth.installation.created', 'succeeded',
                'installation', 'singleton'
            )
            ",
        )
        .bind(event_id)
        .bind(&seed.tenant_id)
        .execute(database.pool())
        .await?;
        let audit_update =
            sqlx::query("UPDATE security_audit_events SET outcome = 'failed' WHERE event_id = $1")
                .bind(event_id)
                .execute(database.pool())
                .await
                .expect_err("security audit events must reject updates");
        assert_constraint(&audit_update, "security_audit_events_append_only");

        let audit_delete = sqlx::query("DELETE FROM security_audit_events WHERE event_id = $1")
            .bind(event_id)
            .execute(database.pool())
            .await
            .expect_err("security audit events must reject deletes");
        assert_constraint(&audit_delete, "security_audit_events_append_only");

        let audit_truncate = sqlx::query("TRUNCATE security_audit_events CASCADE")
            .execute(database.pool())
            .await
            .expect_err("security audit events must reject truncation");
        assert_constraint(&audit_truncate, "security_audit_events_append_only");
        Ok(())
    })
    .await
}

async fn seed_human(
    pool: &PgPool,
    tenant_id: &str,
    provider_subject: &str,
    provider_login: &str,
) -> TestResult<Uuid> {
    let principal = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO human_principals (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Test human', 1, 1)",
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

fn assert_constraint(error: &sqlx::Error, expected: &str) {
    let actual = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint);
    assert_eq!(actual, Some(expected), "unexpected database error: {error}");
}
