use std::{collections::BTreeSet, sync::Arc};

use automata_ci_auth::{
    human::{ProviderId, ProviderSubject, TenantId},
    secret::SecretString,
    time::UnixTimestamp,
    vault::{
        ProviderAccessToken, ProviderGrantKind, ProviderRefreshToken, ProviderTokenKey,
        ProviderTokenMetadata, ProviderTokenRevocationReason, ProviderTokenSet, ProviderTokenVault,
        ProviderTokenVaultError, TokenVersion,
    },
};
use automata_ci_key_management::{KeyId, LocalAes256GcmKeyring, LocalKeyMaterial, SecretBytes};
use automata_ci_postgres::auth::PostgresProviderTokenVault;
use sqlx::PgPool;
use uuid::Uuid;

use crate::support::{TestResult, run_with_database};

fn key_material(id: &str, byte: u8) -> LocalKeyMaterial {
    LocalKeyMaterial::new(
        KeyId::new(id).expect("canonical key ID"),
        SecretBytes::new(vec![byte; 32]).expect("exact key bytes"),
    )
    .expect("valid local key material")
}

fn keyring(
    active_id: &str,
    active_byte: u8,
    decrypt_only: Vec<LocalKeyMaterial>,
) -> Arc<LocalAes256GcmKeyring> {
    Arc::new(
        LocalAes256GcmKeyring::new(key_material(active_id, active_byte), decrypt_only, [])
            .expect("valid keyring"),
    )
}

fn token_key(tenant: &str, subject: &str) -> ProviderTokenKey {
    ProviderTokenKey::new(
        TenantId::new(tenant).expect("tenant ID"),
        ProviderId::new("github").expect("provider ID"),
        ProviderSubject::new(subject).expect("provider subject"),
    )
}

fn token_set(key: &ProviderTokenKey, access: &str, refresh: &str) -> ProviderTokenSet {
    let metadata = ProviderTokenMetadata::builder(
        key.provider_id().clone(),
        ProviderGrantKind::BrowserAuthorizationCode,
        "Bearer",
        UnixTimestamp::from_seconds(100),
    )
    .provider_subject(Some(key.provider_subject().clone()))
    .scopes(BTreeSet::from(["read:org".to_owned(), "repo".to_owned()]))
    .refresh_expires_at(Some(UnixTimestamp::from_seconds(10_000)))
    .build()
    .expect("valid provider-token metadata");
    ProviderTokenSet::new(
        ProviderAccessToken::new(SecretString::new(access).expect("access token")),
        Some(ProviderRefreshToken::new(
            SecretString::new(refresh).expect("refresh token"),
        )),
        metadata,
    )
    .expect("consistent provider tokens")
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn provider_tokens_are_encrypted_cas_rotated_tenant_bound_and_crypto_erased() -> TestResult {
    run_with_database(|database| async move {
        seed_human(database.pool(), "tenant-a", "42").await?;
        seed_human(database.pool(), "tenant-b", "43").await?;
        let key_a = token_key("tenant-a", "42");
        let key_b = token_key("tenant-b", "43");
        let old_keyring = keyring("provider-kek-old", 0x31, Vec::new());
        let old_vault = Arc::new(PostgresProviderTokenVault::new(
            database.pool().clone(),
            old_keyring,
        ));
        let access_sentinel = "provider-access-sentinel-v1";
        let refresh_sentinel = "provider-refresh-sentinel-v1";
        assert_eq!(
            old_vault
                .insert_if_absent(
                    &key_a,
                    token_set(&key_a, access_sentinel, refresh_sentinel),
                )
                .await?,
            TokenVersion::new(1).expect("version")
        );

        let stored: (Uuid, String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = sqlx::query_as(
            r"
            SELECT envelope_record_id, encryption_key_id, encrypted_payload,
                   payload_nonce, wrapped_data_key,
                   convert_to(array_to_string(scopes, ','), 'UTF8')
            FROM human_provider_tokens
            WHERE tenant_id='tenant-a' AND provider_subject='42'
              AND revoked_at_ms IS NULL
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(stored.1, "provider-kek-old");
        for durable_bytes in [&stored.2, &stored.3, &stored.4, &stored.5] {
            assert!(!durable_bytes.windows(access_sentinel.len()).any(|window| {
                window == access_sentinel.as_bytes()
            }));
            assert!(!durable_bytes.windows(refresh_sentinel.len()).any(|window| {
                window == refresh_sentinel.as_bytes()
            }));
        }

        let loaded = old_vault.load(&key_a).await?;
        assert_eq!(loaded.version(), TokenVersion::new(1).expect("version"));
        assert_eq!(
            loaded.tokens().access_token().expose_secret(),
            access_sentinel
        );
        assert_eq!(
            loaded
                .tokens()
                .refresh_token()
                .expect("refresh token")
                .expose_secret(),
            refresh_sentinel
        );

        let rotated_vault = Arc::new(PostgresProviderTokenVault::new(
            database.pool().clone(),
            keyring(
                "provider-kek-current",
                0x32,
                vec![key_material("provider-kek-old", 0x31)],
            ),
        ));
        assert_eq!(
            rotated_vault.load(&key_a).await?.version(),
            TokenVersion::new(1).expect("version")
        );

        let first = Arc::clone(&rotated_vault);
        let second = Arc::clone(&rotated_vault);
        let first_key = key_a.clone();
        let second_key = key_a.clone();
        let expected = TokenVersion::new(1).expect("version");
        let (first_result, second_result) = tokio::join!(
            first.replace_if_version(
                &first_key,
                expected,
                token_set(&first_key, "rotated-access-a", "rotated-refresh-a"),
            ),
            second.replace_if_version(
                &second_key,
                expected,
                token_set(&second_key, "rotated-access-b", "rotated-refresh-b"),
            )
        );
        let outcomes = [first_result, second_result];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| outcome.as_ref().is_ok_and(|version| {
                    *version == TokenVersion::new(2).expect("version")
                }))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, Err(ProviderTokenVaultError::VersionConflict)))
                .count(),
            1
        );
        let active_key_id: String = sqlx::query_scalar(
            "SELECT encryption_key_id FROM human_provider_tokens WHERE envelope_record_id=$1",
        )
        .bind(stored.0)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(active_key_id, "provider-kek-current");

        rotated_vault
            .insert_if_absent(
                &key_b,
                token_set(&key_b, "tenant-b-access", "tenant-b-refresh"),
            )
            .await?;
        sqlx::query("ALTER TABLE human_provider_tokens DISABLE TRIGGER human_provider_tokens_lifecycle_guard")
            .execute(database.pool())
            .await?;
        sqlx::query(
            r"
            UPDATE human_provider_tokens AS target
            SET (encrypted_payload, payload_nonce, wrapped_data_key,
                 encryption_key_id, encryption_schema) = (
                SELECT encrypted_payload, payload_nonce, wrapped_data_key,
                       encryption_key_id, encryption_schema
                FROM human_provider_tokens
                WHERE tenant_id='tenant-a' AND provider_subject='42'
                  AND revoked_at_ms IS NULL
            )
            WHERE target.tenant_id='tenant-b' AND target.provider_subject='43'
              AND target.revoked_at_ms IS NULL
            ",
        )
        .execute(database.pool())
        .await?;
        sqlx::query("ALTER TABLE human_provider_tokens ENABLE TRIGGER human_provider_tokens_lifecycle_guard")
            .execute(database.pool())
            .await?;
        assert_eq!(
            rotated_vault
                .load(&key_b)
                .await
                .expect_err("copied tenant/row ciphertext must not authenticate"),
            ProviderTokenVaultError::IntegrityFailure
        );

        rotated_vault
            .revoke(&key_a, ProviderTokenRevocationReason::Explicit)
            .await?;
        rotated_vault
            .revoke(&key_a, ProviderTokenRevocationReason::Explicit)
            .await?;
        assert_eq!(
            rotated_vault
                .load(&key_a)
                .await
                .expect_err("revoked credentials must not load"),
            ProviderTokenVaultError::Revoked
        );
        let erased: (bool, bool, bool, bool, bool, String) = sqlx::query_as(
            r"
            SELECT encrypted_payload IS NULL, payload_nonce IS NULL,
                   wrapped_data_key IS NULL, encryption_key_id IS NULL,
                   encryption_schema IS NULL, revocation_reason
            FROM human_provider_tokens WHERE envelope_record_id=$1
            ",
        )
        .bind(stored.0)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(erased, (true, true, true, true, true, "explicit".to_owned()));

        assert_eq!(
            rotated_vault
                .insert_if_absent(
                    &key_a,
                    token_set(&key_a, "reauthorized-access", "reauthorized-refresh"),
                )
                .await?,
            TokenVersion::new(1).expect("new record version")
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM human_provider_tokens WHERE tenant_id='tenant-a' AND provider_subject='42'",
            )
            .fetch_one(database.pool())
            .await?,
            2
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM human_provider_tokens WHERE tenant_id='tenant-a' AND provider_subject='42' AND revoked_at_ms IS NULL",
            )
            .fetch_one(database.pool())
            .await?,
            1
        );
        Ok(())
    })
    .await
}

async fn seed_human(pool: &PgPool, tenant: &str, subject: &str) -> TestResult {
    sqlx::query(
        "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) VALUES ($1,$1,100000,100000)",
    )
    .bind(tenant)
    .execute(pool)
    .await?;
    let principal = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO human_principals (id, created_at_ms, updated_at_ms) VALUES ($1,100000,100000)",
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
        ) VALUES ($1,'github',$2,$2,$2,100000,100000,100000,100000,100000)
        ",
    )
    .bind(principal)
    .bind(subject)
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO tenant_human_memberships (tenant_id, principal_id, created_at_ms, updated_at_ms) VALUES ($1,$2,100000,100000)",
    )
    .bind(tenant)
    .bind(principal)
    .execute(pool)
    .await?;
    Ok(())
}
