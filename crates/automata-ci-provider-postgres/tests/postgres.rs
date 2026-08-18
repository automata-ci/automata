use std::sync::Arc;

use automata_ci_core::{GitObjectAlgorithm, Sha256Digest, UnixMillis, WorkspaceId};
use automata_ci_key_management::{KeyId, LocalAes256GcmKeyring, LocalKeyMaterial, SecretBytes};
use automata_ci_postgres::test_support::{TestResult, run_with_database};
use automata_ci_provider::{
    ExternalRepositoryId, ExternalRepositoryIdentity, ProviderArchiveLimits, ProviderCapabilities,
    ProviderCapability, ProviderConfigurationDocument, ProviderConfigurationRevision,
    ProviderConnectionConfiguration, ProviderConnectionId, ProviderConnectionManifest,
    ProviderConnectionPolicyDocument, ProviderConnectionRevision, ProviderDefaultBranch,
    ProviderInstanceId, ProviderInstanceManifest, ProviderInstanceRecord, ProviderLifecycleState,
    ProviderManifestRepository as _, ProviderOrigins, ProviderRepositoryError,
    ProviderRepositoryPath, ProviderRunnerPolicyBinding, ProviderSaveOutcome,
    ProviderSchemaVersion, ProviderSecret, ProviderSecretBinding, ProviderSecretBindings,
    ProviderSecretGeneration, ProviderSecretName, ProviderSecretSet, ProviderTypeId,
    ProviderWorkflowSource, RepositoryVisibility, SourceReadCapability, provider_capability_digest,
};
use automata_ci_provider_postgres::PostgresProviderManifestRepository;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

const TOKEN: &[u8] = b"forgejo-control-token-that-must-stay-encrypted";

fn repository(pool: sqlx::PgPool) -> PostgresProviderManifestRepository {
    let material = LocalKeyMaterial::new(
        KeyId::new("provider-test-key-v1").expect("key ID"),
        SecretBytes::new(vec![7; 32]).expect("key bytes"),
    )
    .expect("key material");
    let keys = LocalAes256GcmKeyring::new(material, Vec::new(), []).expect("local keyring");
    PostgresProviderManifestRepository::new(pool, Arc::new(keys))
}

fn capability_digest() -> Sha256Digest {
    let capabilities = ProviderCapabilities::new([ProviderCapability::SourceRead(
        SourceReadCapability::new([GitObjectAlgorithm::Sha1]).expect("source capability"),
    )])
    .expect("capabilities");
    provider_capability_digest(&capabilities).expect("capability digest")
}

fn secret_digest(value: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(value).into())
}

fn instance_record(
    instance_id: ProviderInstanceId,
    provider_type: &str,
    revision: u64,
    value: &[u8],
    generation: u64,
    state: ProviderLifecycleState,
    activated_at: Option<UnixMillis>,
) -> ProviderInstanceRecord {
    let name = ProviderSecretName::new("control-token").expect("secret name");
    let generation = ProviderSecretGeneration::new(generation).expect("secret generation");
    let bindings = ProviderSecretBindings::new([ProviderSecretBinding::new(
        name.clone(),
        generation,
        secret_digest(value),
    )])
    .expect("bindings");
    let secrets = ProviderSecretSet::new(
        &bindings,
        [ProviderSecret::new(
            name,
            generation,
            SecretBytes::new(value.to_vec()).expect("secret"),
        )],
    )
    .expect("secret set");
    let manifest = ProviderInstanceManifest::new(
        instance_id,
        ProviderTypeId::new(provider_type).expect("provider type"),
        ProviderConfigurationRevision::new(revision).expect("revision"),
        state,
        ProviderOrigins::new("https://code.example/", "https://code.example/api/v1/")
            .expect("origins"),
        ProviderConfigurationDocument::new(
            ProviderSchemaVersion::new(1).expect("schema"),
            format!(r#"{{"provider":"{provider_type}"}}"#).into_bytes(),
        )
        .expect("configuration"),
        bindings,
        capability_digest(),
        UnixMillis::new(1_000),
        activated_at,
        None,
    )
    .expect("manifest");
    ProviderInstanceRecord::new(manifest, secrets).expect("record")
}

fn connection(
    workspace_id: WorkspaceId,
    instance: &ProviderInstanceManifest,
) -> ProviderConnectionManifest {
    let configuration = ProviderConnectionConfiguration::new(
        workspace_id,
        ExternalRepositoryIdentity::new(
            instance.instance_id(),
            ExternalRepositoryId::new("42").expect("repository"),
        ),
        instance.revision(),
        instance.configuration().digest(),
        instance.capability_digest(),
        RepositoryVisibility::Private,
        ProviderDefaultBranch::new("main").expect("branch"),
        ProviderWorkflowSource::Directory(
            ProviderRepositoryPath::new(".forgejo/workflows").expect("workflow path"),
        ),
        ProviderRunnerPolicyBinding::new(
            ProviderSchemaVersion::new(2).expect("runner policy schema"),
            Sha256Digest::from_bytes([8; 32]),
        ),
        ProviderArchiveLimits::new(
            1_024 * 1_024,
            8 * 1_024 * 1_024,
            1_000,
            1_024,
            64,
            512 * 1_024,
        )
        .expect("archive limits"),
        ProviderConnectionPolicyDocument::new(
            ProviderSchemaVersion::new(1).expect("policy schema"),
            br#"{"installation_id":99}"#.to_vec(),
        )
        .expect("adapter policy"),
    );
    ProviderConnectionManifest::new(
        ProviderConnectionId::from_uuid(Uuid::from_u128(99)).expect("connection"),
        ProviderConnectionRevision::new(1).expect("revision"),
        ProviderLifecycleState::Active,
        configuration,
        UnixMillis::new(2_000),
        Some(UnixMillis::new(2_000)),
        None,
    )
    .expect("connection manifest")
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 via AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)] // One sequence proves immutable history, rotation, and references.
async fn instance_and_connection_revisions_are_atomic_encrypted_and_exact() -> TestResult {
    run_with_database(|database| async move {
        let repository = repository(database.pool().clone());
        let instance_id = ProviderInstanceId::from_uuid(Uuid::from_u128(7))?;
        assert_eq!(
            repository
                .save_instance(instance_record(
                    instance_id,
                    "forgejo",
                    1,
                    TOKEN,
                    1,
                    ProviderLifecycleState::Disabled,
                    None,
                ))
                .await?,
            ProviderSaveOutcome::Inserted
        );
        assert_eq!(
            repository
                .save_instance(instance_record(
                    instance_id,
                    "forgejo",
                    1,
                    TOKEN,
                    1,
                    ProviderLifecycleState::Disabled,
                    None,
                ))
                .await?,
            ProviderSaveOutcome::Unchanged
        );

        let stored_ciphertext: Vec<u8> = sqlx::query_scalar(
            "SELECT ciphertext FROM provider_instance_secret_bindings WHERE instance_id = $1 AND revision = 1",
        )
        .bind(instance_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert!(!stored_ciphertext.windows(TOKEN.len()).any(|window| window == TOKEN));

        let first_loaded = repository
            .current_instance(instance_id)
            .await?
            .expect("current instance");
        let name = ProviderSecretName::new("control-token")?;
        assert_eq!(
            first_loaded
                .secrets()
                .get(&name)
                .expect("control token")
                .expose_secret(),
            TOKEN
        );

        let second_value = b"rotated-forgejo-control-token";
        assert_eq!(
            repository
                .save_instance(instance_record(
                    instance_id,
                    "forgejo",
                    2,
                    second_value,
                    2,
                    ProviderLifecycleState::Active,
                    Some(UnixMillis::new(2_000)),
                ))
                .await?,
            ProviderSaveOutcome::Inserted
        );
        let current = repository
            .current_instance(instance_id)
            .await?
            .expect("current instance");
        assert_eq!(current.manifest().revision().get(), 2);
        assert_eq!(
            current
                .secrets()
                .get(&name)
                .expect("rotated token")
                .expose_secret(),
            second_value
        );
        assert_eq!(
            repository
                .load_instance(
                    instance_id,
                    ProviderConfigurationRevision::new(1).expect("revision"),
                )
                .await?
                .expect("historical instance")
                .secrets()
                .get(&name)
                .expect("historical token")
                .expose_secret(),
            TOKEN
        );

        let workspace = WorkspaceId::parse("11111111-1111-4111-8111-111111111111")?;
        assert_eq!(
            repository
                .save_connection(connection(workspace, current.manifest()))
                .await,
            Err(ProviderRepositoryError::NotFound)
        );
        sqlx::query(
            "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Provider test', 1, 1)",
        )
        .bind(workspace.to_string())
        .execute(database.pool())
        .await?;
        let first_connection = connection(workspace, current.manifest());
        assert_eq!(
            repository.save_connection(first_connection).await?,
            ProviderSaveOutcome::Inserted
        );
        assert_eq!(
            repository
                .save_connection(connection(workspace, current.manifest()))
                .await?,
            ProviderSaveOutcome::Unchanged
        );
        let loaded_connection = repository
            .current_connection(
                ProviderConnectionId::from_uuid(Uuid::from_u128(99)).expect("connection"),
            )
            .await?
            .expect("current connection");
        assert_eq!(loaded_connection.configuration().workspace_id(), workspace);
        assert_eq!(
            loaded_connection
                .configuration()
                .repository()
                .external_id()
                .as_str(),
            "42"
        );
        assert_eq!(
            loaded_connection
                .configuration()
                .provider_revision()
                .get(),
            2
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 via AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)] // One sequence proves relational and ciphertext tamper rejection.
async fn stale_missing_and_tampered_state_fail_closed() -> TestResult {
    run_with_database(|database| async move {
        let repository = repository(database.pool().clone());
        let instance_id = ProviderInstanceId::from_uuid(Uuid::from_u128(17))?;
        assert_eq!(
            repository
                .save_instance(instance_record(
                    instance_id,
                    "github",
                    2,
                    TOKEN,
                    1,
                    ProviderLifecycleState::Active,
                    Some(UnixMillis::new(1_000)),
                ))
                .await,
            Err(ProviderRepositoryError::Conflict)
        );

        repository
            .save_instance(instance_record(
                instance_id,
                "github",
                1,
                TOKEN,
                1,
                ProviderLifecycleState::Active,
                Some(UnixMillis::new(1_000)),
            ))
            .await?;
        sqlx::query(
            "UPDATE provider_instance_revisions SET configuration_bytes = $1 WHERE instance_id = $2 AND revision = 1",
        )
        .bind(br#"{"provider":"tampered"}"#.as_slice())
        .bind(instance_id.as_uuid())
        .execute(database.pool())
        .await?;
        assert!(matches!(
            repository
                .load_instance(
                    instance_id,
                    ProviderConfigurationRevision::new(1).expect("revision"),
                )
                .await,
            Err(ProviderRepositoryError::Corrupt)
        ));

        let encrypted_instance = ProviderInstanceId::from_uuid(Uuid::from_u128(18))?;
        repository
            .save_instance(instance_record(
                encrypted_instance,
                "github",
                1,
                TOKEN,
                1,
                ProviderLifecycleState::Active,
                Some(UnixMillis::new(1_000)),
            ))
            .await?;
        sqlx::query(
            r"
            UPDATE provider_instance_secret_bindings
            SET ciphertext = set_byte(ciphertext, 0, get_byte(ciphertext, 0) # 1)
            WHERE instance_id = $1 AND revision = 1
            ",
        )
        .bind(encrypted_instance.as_uuid())
        .execute(database.pool())
        .await?;
        assert!(matches!(
            repository
                .load_instance(
                    encrypted_instance,
                    ProviderConfigurationRevision::new(1).expect("revision"),
                )
                .await,
            Err(ProviderRepositoryError::SecretCustody)
        ));
        Ok(())
    })
    .await
}
