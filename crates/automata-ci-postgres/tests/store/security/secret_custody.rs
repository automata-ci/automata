use std::sync::Arc;

use automata_ci_key_management::{
    KeyEncryptionProvider, KeyId, LocalAes256GcmKeyring, LocalKeyMaterial, SecretBytes,
};
use automata_ci_postgres::store::PostgresSecretCustodyRepository;
use automata_ci_store::{
    SECRET_CUSTODY_CANARY_GENERATION, SecretCustodyKeySet, SecretCustodyRepository as _,
    SecretCustodyRepositoryError, VerifySecretCustody, VerifySecretCustodyOutcome,
};

use crate::support::{TestDatabase, TestResult, run_with_database};

fn key_id(value: &str) -> KeyId {
    KeyId::new(value).expect("canonical test key ID")
}

fn key_material(id: &str, byte: u8) -> LocalKeyMaterial {
    LocalKeyMaterial::new(
        key_id(id),
        SecretBytes::new(vec![byte; 32]).expect("exact key bytes"),
    )
    .expect("valid local key material")
}

fn key_provider(active: (&str, u8), decrypt_only: &[(&str, u8)]) -> Arc<dyn KeyEncryptionProvider> {
    let decrypt_only = decrypt_only
        .iter()
        .map(|(id, byte)| key_material(id, *byte))
        .collect();
    Arc::new(
        LocalAes256GcmKeyring::new(
            key_material(active.0, active.1),
            decrypt_only,
            Vec::<KeyId>::new(),
        )
        .expect("valid local keyring"),
    )
}

fn configured(active: &str, decrypt_only: &[&str]) -> SecretCustodyKeySet {
    SecretCustodyKeySet::new(
        key_id(active),
        decrypt_only.iter().map(|id| key_id(id)).collect(),
    )
    .expect("valid configured key set")
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn absent_configuration_is_allowed_only_for_empty_durable_state() -> TestResult {
    run_with_database(|database| async move {
        let repository = PostgresSecretCustodyRepository::new(database.pool().clone());
        let empty = repository.inspect_secret_custody_requirements().await?;
        assert!(!empty.configuration_required());
        assert!(matches!(
            repository
                .verify_or_create_secret_custody(VerifySecretCustody::absent())
                .await?,
            VerifySecretCustodyOutcome::NotRequired
        ));
        assert!(matches!(
            repository
                .verify_or_create_secret_custody(VerifySecretCustody::configured(configured(
                    "key-a",
                    &[],
                )))
                .await,
            Err(SecretCustodyRepositoryError::ConfigurationUnavailable)
        ));

        insert_provider(&database, "tenant-active", "builtin", "active").await?;
        let required = repository.inspect_secret_custody_requirements().await?;
        assert!(required.configuration_required());
        assert!(required.has_active_provider());
        assert!(required.required_key_ids().is_empty());
        assert!(matches!(
            repository
                .verify_or_create_secret_custody(VerifySecretCustody::absent())
                .await,
            Err(SecretCustodyRepositoryError::ConfigurationRequired)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn restart_authenticates_material_and_wrong_bytes_for_same_id_fail() -> TestResult {
    run_with_database(|database| async move {
        let keys = configured("key-a", &[]);
        let repository = PostgresSecretCustodyRepository::new(database.pool().clone())
            .with_key_encryption_provider(key_provider(("key-a", 0x11), &[]));
        let created = repository
            .verify_or_create_secret_custody(VerifySecretCustody::configured(keys.clone()))
            .await?;
        let VerifySecretCustodyOutcome::Verified(created) = created else {
            panic!("configured custody must be verified");
        };
        assert_eq!(created.active_key_id(), &key_id("key-a"));
        assert_eq!(created.configured_key_set_digest(), keys.digest());
        assert_eq!(created.canaries().len(), 1);
        assert_eq!(
            created.canaries()[0].generation().get(),
            SECRET_CUSTODY_CANARY_GENERATION
        );

        let before: (Vec<u8>, Vec<u8>, Vec<u8>, i64) = sqlx::query_as(
            r"
            SELECT ciphertext, nonce, wrapped_data_key, created_at_ms
            FROM secret_custody_key_canaries
            WHERE wrapping_key_id = 'key-a'
            ",
        )
        .fetch_one(database.pool())
        .await?;
        let restarted = PostgresSecretCustodyRepository::new(database.pool().clone())
            .with_key_encryption_provider(key_provider(("key-a", 0x11), &[]));
        assert!(matches!(
            restarted
                .verify_or_create_secret_custody(VerifySecretCustody::configured(keys.clone()))
                .await?,
            VerifySecretCustodyOutcome::Verified(_)
        ));
        let after: (Vec<u8>, Vec<u8>, Vec<u8>, i64) = sqlx::query_as(
            r"
            SELECT ciphertext, nonce, wrapped_data_key, created_at_ms
            FROM secret_custody_key_canaries
            WHERE wrapping_key_id = 'key-a'
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            after, before,
            "replay must retain the first envelope exactly"
        );

        // The active provider is probed on every verification. An existing
        // canary must not let a differently active provider identity pass.
        let mismatched_active = PostgresSecretCustodyRepository::new(database.pool().clone())
            .with_key_encryption_provider(key_provider(("key-b", 0x33), &[("key-a", 0x11)]));
        assert!(matches!(
            mismatched_active
                .verify_or_create_secret_custody(VerifySecretCustody::configured(keys.clone()))
                .await,
            Err(SecretCustodyRepositoryError::ActiveKeyMismatch)
        ));

        let wrong = PostgresSecretCustodyRepository::new(database.pool().clone())
            .with_key_encryption_provider(key_provider(("key-a", 0x22), &[]));
        let error = wrong
            .verify_or_create_secret_custody(VerifySecretCustody::configured(keys))
            .await
            .expect_err("same ID with different bytes must fail authentication");
        assert_eq!(error, SecretCustodyRepositoryError::VerificationFailed);
        let diagnostic = format!("{error:?}: {error}");
        assert!(!diagnostic.contains("key-a"));
        assert!(!diagnostic.contains("ciphertext"));
        assert!(!diagnostic.contains("plaintext"));

        // An orphan canary authenticates only the fixed public marker. Once
        // no protected state remains, absent configuration is still safe.
        let requirement_only = PostgresSecretCustodyRepository::new(database.pool().clone());
        assert!(matches!(
            requirement_only
                .verify_or_create_secret_custody(VerifySecretCustody::absent())
                .await?,
            VerifySecretCustodyOutcome::NotRequired
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn noncurrent_canary_schema_fails_closed() -> TestResult {
    run_with_database(|database| async move {
        let keys = configured("key-schema", &[]);
        let repository = PostgresSecretCustodyRepository::new(database.pool().clone())
            .with_key_encryption_provider(key_provider(("key-schema", 0x19), &[]));
        assert!(matches!(
            repository
                .verify_or_create_secret_custody(VerifySecretCustody::configured(keys.clone()))
                .await?,
            VerifySecretCustodyOutcome::Verified(_)
        ));

        sqlx::query(
            "UPDATE secret_custody_key_canaries \
             SET canary_schema = 2 \
             WHERE wrapping_key_id = 'key-schema'",
        )
        .execute(database.pool())
        .await?;

        let restarted = PostgresSecretCustodyRepository::new(database.pool().clone())
            .with_key_encryption_provider(key_provider(("key-schema", 0x19), &[]));
        assert!(matches!(
            restarted
                .verify_or_create_secret_custody(VerifySecretCustody::configured(keys))
                .await,
            Err(SecretCustodyRepositoryError::CorruptData)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn concurrent_first_writers_converge_on_one_authenticated_canary() -> TestResult {
    run_with_database(|database| async move {
        let first = PostgresSecretCustodyRepository::new(database.pool().clone())
            .with_key_encryption_provider(key_provider(("key-race", 0x27), &[]));
        let second = PostgresSecretCustodyRepository::new(database.pool().clone())
            .with_key_encryption_provider(key_provider(("key-race", 0x27), &[]));
        let (first_result, second_result) = tokio::join!(
            first.verify_or_create_secret_custody(VerifySecretCustody::configured(configured(
                "key-race",
                &[],
            ))),
            second.verify_or_create_secret_custody(VerifySecretCustody::configured(configured(
                "key-race",
                &[],
            ))),
        );
        assert!(matches!(
            first_result?,
            VerifySecretCustodyOutcome::Verified(_)
        ));
        assert!(matches!(
            second_result?,
            VerifySecretCustodyOutcome::Verified(_)
        ));
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM secret_custody_key_canaries \
             WHERE wrapping_key_id = 'key-race'",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(count, 1);

        let first = PostgresSecretCustodyRepository::new(database.pool().clone())
            .with_key_encryption_provider(key_provider(("key-race-mismatch", 0x37), &[]));
        let second = PostgresSecretCustodyRepository::new(database.pool().clone())
            .with_key_encryption_provider(key_provider(("key-race-mismatch", 0x38), &[]));
        let (first_result, second_result) = tokio::join!(
            first.verify_or_create_secret_custody(VerifySecretCustody::configured(configured(
                "key-race-mismatch",
                &[],
            ))),
            second.verify_or_create_secret_custody(VerifySecretCustody::configured(configured(
                "key-race-mismatch",
                &[],
            ))),
        );
        let mut verified = 0;
        let mut rejected = 0;
        for outcome in [&first_result, &second_result] {
            match outcome {
                Ok(VerifySecretCustodyOutcome::Verified(_)) => verified += 1,
                Err(SecretCustodyRepositoryError::VerificationFailed) => rejected += 1,
                _ => panic!("different-material first writers must converge or fail closed"),
            }
        }
        assert_eq!((verified, rejected), (1, 1));
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM secret_custody_key_canaries \
             WHERE wrapping_key_id = 'key-race-mismatch'",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(count, 1);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn already_required_key_cannot_establish_a_first_writer_canary() -> TestResult {
    run_with_database(|database| async move {
        insert_provider(&database, "tenant-legacy", "legacy", "unconfigured").await?;
        insert_configuration_envelope(&database, "tenant-legacy", "legacy", "legacy-key").await?;
        let repository = PostgresSecretCustodyRepository::new(database.pool().clone())
            .with_key_encryption_provider(key_provider(("legacy-key", 0x51), &[]));
        assert!(matches!(
            repository
                .verify_or_create_secret_custody(VerifySecretCustody::configured(configured(
                    "legacy-key",
                    &[],
                )))
                .await,
            Err(SecretCustodyRepositoryError::CanaryUnavailable)
        ));
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM secret_custody_key_canaries \
             WHERE wrapping_key_id = 'legacy-key'",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(count, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn active_key_rotation_verifies_old_material_and_required_identity() -> TestResult {
    run_with_database(|database| async move {
        let first = PostgresSecretCustodyRepository::new(database.pool().clone())
            .with_key_encryption_provider(key_provider(("key-a", 0x31), &[]));
        first
            .verify_or_create_secret_custody(VerifySecretCustody::configured(configured(
                "key-a",
                &[],
            )))
            .await?;

        let uninitialized_old = PostgresSecretCustodyRepository::new(database.pool().clone())
            .with_key_encryption_provider(key_provider(("key-a", 0x31), &[("key-b", 0x32)]));
        let VerifySecretCustodyOutcome::Verified(prestaged) = uninitialized_old
            .verify_or_create_secret_custody(VerifySecretCustody::configured(configured(
                "key-a",
                &["key-b"],
            )))
            .await?
        else {
            panic!("a fresh decrypt-only successor may be prestaged")
        };
        assert_eq!(
            prestaged
                .canaries()
                .iter()
                .map(|binding| binding.key_id().as_str())
                .collect::<Vec<_>>(),
            ["key-a"]
        );
        let prestaged_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM secret_custody_key_canaries \
             WHERE wrapping_key_id = 'key-b'",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(prestaged_count, 0);

        let rotated_keys = configured("key-b", &["key-a"]);
        let rotated = PostgresSecretCustodyRepository::new(database.pool().clone())
            .with_key_encryption_provider(key_provider(("key-b", 0x32), &[("key-a", 0x31)]));
        let VerifySecretCustodyOutcome::Verified(receipt) = rotated
            .verify_or_create_secret_custody(VerifySecretCustody::configured(rotated_keys.clone()))
            .await?
        else {
            panic!("rotated keyring must authenticate both generations");
        };
        assert_eq!(
            receipt
                .canaries()
                .iter()
                .map(|binding| binding.key_id().as_str())
                .collect::<Vec<_>>(),
            ["key-a", "key-b"]
        );

        let wrong_old = PostgresSecretCustodyRepository::new(database.pool().clone())
            .with_key_encryption_provider(key_provider(("key-b", 0x32), &[("key-a", 0x41)]));
        assert!(matches!(
            wrong_old
                .verify_or_create_secret_custody(VerifySecretCustody::configured(rotated_keys))
                .await,
            Err(SecretCustodyRepositoryError::VerificationFailed)
        ));

        insert_provider(&database, "tenant-envelope", "secondary", "unconfigured").await?;
        insert_configuration_envelope(&database, "tenant-envelope", "secondary", "key-a").await?;
        let requirements = rotated.inspect_secret_custody_requirements().await?;
        assert!(requirements.has_encrypted_envelopes());
        assert_eq!(requirements.required_key_ids(), &[key_id("key-a")]);

        let before: i64 = sqlx::query_scalar("SELECT count(*) FROM secret_custody_key_canaries")
            .fetch_one(database.pool())
            .await?;
        let missing_old = PostgresSecretCustodyRepository::new(database.pool().clone())
            .with_key_encryption_provider(key_provider(("key-b", 0x32), &[]));
        assert!(matches!(
            missing_old
                .verify_or_create_secret_custody(VerifySecretCustody::configured(configured(
                    "key-b",
                    &[],
                )))
                .await,
            Err(SecretCustodyRepositoryError::RequiredKeyUnavailable)
        ));
        let after: i64 = sqlx::query_scalar("SELECT count(*) FROM secret_custody_key_canaries")
            .fetch_one(database.pool())
            .await?;
        assert_eq!(
            after, before,
            "missing required config must not write a canary"
        );
        Ok(())
    })
    .await
}

async fn insert_provider(
    database: &TestDatabase,
    tenant_id: &str,
    provider_id: &str,
    status: &str,
) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms)
        VALUES ($1, 'Custody test', 1, 1)
        ",
    )
    .bind(tenant_id)
    .execute(database.pool())
    .await?;

    if provider_id == "builtin" {
        sqlx::query(
            r"
            UPDATE secret_providers
            SET status = $2, revision = 2, updated_at_ms = 2
            WHERE tenant_id = $1 AND provider_id = 'builtin'
            ",
        )
        .bind(tenant_id)
        .bind(status)
        .execute(database.pool())
        .await?;
        return Ok(());
    }

    sqlx::query(
        r"
        INSERT INTO secret_providers (
            tenant_id, provider_id, adapter_kind, display_name,
            supports_create_version, supports_destroy_version,
            supports_dynamic_leases, supports_renew_leases,
            supports_revoke_leases, is_default, status, health,
            created_at_ms, updated_at_ms
        ) VALUES (
            $1, $2, 'custody_test', 'Custody test',
            TRUE, TRUE, FALSE, FALSE, FALSE, FALSE, $3, 'unknown', 1, 1
        )
        ",
    )
    .bind(tenant_id)
    .bind(provider_id)
    .bind(status)
    .execute(database.pool())
    .await?;
    Ok(())
}

async fn insert_configuration_envelope(
    database: &TestDatabase,
    tenant_id: &str,
    provider_id: &str,
    wrapping_key_id: &str,
) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO secret_provider_configuration_envelopes (
            tenant_id, provider_id, envelope_generation, ciphertext, nonce,
            wrapped_data_key, wrapping_key_id, envelope_schema, created_at_ms
        ) VALUES ($1, $2, 1, $3, $4, $5, $6, 1, 1)
        ",
    )
    .bind(tenant_id)
    .bind(provider_id)
    .bind(vec![1_u8; 17])
    .bind(vec![2_u8; 12])
    .bind(vec![3_u8; 48])
    .bind(wrapping_key_id)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO secret_provider_configuration_envelope_heads (
            tenant_id, provider_id, envelope_generation, revision, updated_at_ms
        ) VALUES ($1, $2, 1, 1, 1)
        ",
    )
    .bind(tenant_id)
    .bind(provider_id)
    .execute(database.pool())
    .await?;
    Ok(())
}
