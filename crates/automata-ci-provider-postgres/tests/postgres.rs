use std::sync::Arc;

use automata_ci_core::{
    GitObjectAlgorithm, GitObjectId, RunId, Sha256Digest, UnixMillis, WorkspaceId,
};
use automata_ci_key_management::{KeyId, LocalAes256GcmKeyring, LocalKeyMaterial, SecretBytes};
use automata_ci_postgres::test_support::{TestResult, run_with_database};
use automata_ci_provider::{
    AcceptProviderDelivery, BindProviderProcessingSource, ClaimProviderProcessing,
    ClaimProviderResult, CompleteProviderProcessing, CompleteProviderResult, DesiredProviderResult,
    ExternalDeliveryId, ExternalDeliveryIdentity, ExternalRepositoryId, ExternalRepositoryIdentity,
    ExternalSubjectId, ExternalSubjectIdentity, ExternalSubjectKind, NormalizedTrigger,
    ProviderArchiveLimits, ProviderCapabilities, ProviderCapability, ProviderConfigurationDocument,
    ProviderConfigurationRevision, ProviderConnectionConfiguration, ProviderConnectionId,
    ProviderConnectionManifest, ProviderConnectionPolicyDocument, ProviderConnectionRevision,
    ProviderControl, ProviderControlDocument, ProviderControlKind, ProviderDefaultBranch,
    ProviderDelivery, ProviderDeliveryAcceptOutcome, ProviderDeliveryEvidence, ProviderDeliveryId,
    ProviderDeliveryObservations, ProviderDeliveryRepository as _, ProviderDeliveryRepositoryError,
    ProviderEventName, ProviderGitRef, ProviderGitRefKind, ProviderInstanceId,
    ProviderInstanceManifest, ProviderInstanceRecord, ProviderLifecycleState,
    ProviderManifestRepository as _, ProviderOrigins, ProviderProcessingFailure,
    ProviderProcessingInput, ProviderProcessingRepository as _, ProviderProcessingRepositoryError,
    ProviderProcessingState, ProviderProcessingWorkerId, ProviderRepository,
    ProviderRepositoryError, ProviderRepositoryPath, ProviderResultDetailsUrl, ProviderResultPhase,
    ProviderResultPublicationEvidence, ProviderResultPublicationModel,
    ProviderResultRepository as _, ProviderResultRepositoryError, ProviderResultSaveOutcome,
    ProviderResultSubject, ProviderResultSubjectId, ProviderResultSubjectKind,
    ProviderResultSummary, ProviderResultTitle, ProviderResultWorkerId,
    ProviderRunnerPolicyBinding, ProviderSaveOutcome, ProviderSchemaVersion, ProviderSecret,
    ProviderSecretBinding, ProviderSecretBindings, ProviderSecretGeneration, ProviderSecretName,
    ProviderSecretSet, ProviderTypeId, ProviderWebhookEndpointId, ProviderWebhookEndpointManifest,
    ProviderWebhookEndpointRepository as _, ProviderWebhookEndpointRevision,
    ProviderWebhookEndpointState, ProviderWebhookSecretReference, ProviderWebhookSignatureEvidence,
    ProviderWorkflowSource, PushCommitEvidence, PushTrigger, RepositoryVisibility,
    RetryProviderProcessing, RetryProviderResult, SaveDesiredProviderResult, SourceReadCapability,
    VerifiedProviderControlDelivery, VerifiedProviderTriggerDelivery, provider_capability_digest,
    provider_raw_webhook_descriptor,
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
#[allow(clippy::too_many_lines)] // One lifecycle proves every durable result transition and fence.
async fn provider_results_are_contiguous_fenced_and_rehydratable() -> TestResult {
    run_with_database(|database| async move {
        let repository = repository(database.pool().clone());
        let workspace = WorkspaceId::from_uuid(Uuid::from_u128(0x5900))?;
        sqlx::query(
            "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Provider results', 1, 1)",
        )
        .bind(workspace.to_string())
        .execute(database.pool())
        .await?;
        let instance_id = ProviderInstanceId::from_uuid(Uuid::from_u128(0x5901))?;
        repository
            .save_instance(instance_record(
                instance_id,
                "forgejo",
                1,
                TOKEN,
                1,
                ProviderLifecycleState::Active,
                Some(UnixMillis::new(1_001)),
            ))
            .await?;
        let instance = repository
            .current_instance(instance_id)
            .await?
            .expect("provider instance");
        let connection = connection(workspace, instance.manifest());
        repository.save_connection(connection.clone()).await?;

        let subject = ProviderResultSubject::new(
            ProviderResultSubjectId::from_uuid(Uuid::from_u128(0x5902))?,
            &connection,
            GitObjectId::from_provider_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?,
            ProviderResultSubjectKind::WorkflowRun {
                run_id: RunId::from_uuid(Uuid::from_u128(0x5903)),
            },
            1,
            UnixMillis::new(3_000),
        )?;
        let desired = |generation, updated_at, summary| {
            DesiredProviderResult::new(
                generation,
                ProviderResultPhase::Running,
                None,
                ProviderResultTitle::new("Automata CI")?,
                ProviderResultSummary::new(summary)?,
                ProviderResultDetailsUrl::new(
                    "https://ci.example/runs/5903"
                        .parse()
                        .expect("fixed provider result URL"),
                )?,
                Vec::new(),
                UnixMillis::new(updated_at),
            )
        };
        let first_desired = desired(1, 3_001, "queued")?;
        assert_eq!(
            repository
                .save_desired(SaveDesiredProviderResult::new(
                    subject.clone(),
                    first_desired.clone(),
                )?)
                .await?,
            ProviderResultSaveOutcome::Inserted
        );
        assert_eq!(
            repository
                .save_desired(SaveDesiredProviderResult::new(
                    subject.clone(),
                    first_desired,
                )?)
                .await?,
            ProviderResultSaveOutcome::Unchanged
        );

        let worker = ProviderResultWorkerId::from_uuid(Uuid::from_u128(0x5904))?;
        let first_claim = repository
            .claim_result(ClaimProviderResult::new(
                connection.connection_id(),
                worker,
                UnixMillis::new(3_002),
                1_000,
            )?)
            .await?
            .expect("first result claim");
        assert_eq!(first_claim.subject(), &subject);
        assert_eq!(first_claim.attempts(), 1);

        let second_desired = desired(2, 3_003, "running")?;
        assert_eq!(
            repository
                .save_desired(SaveDesiredProviderResult::new(
                    subject.clone(),
                    second_desired.clone(),
                )?)
                .await?,
            ProviderResultSaveOutcome::Superseded
        );
        let stale_evidence = ProviderResultPublicationEvidence::new(
            &first_claim,
            ProviderResultPublicationModel::AppendOnlyCommitStatus,
            None,
            first_claim.desired().digest(),
            UnixMillis::new(3_002),
        )?;
        assert_eq!(
            repository
                .complete_result(CompleteProviderResult::new(
                    first_claim.claim(),
                    stale_evidence,
                )?)
                .await,
            Err(ProviderResultRepositoryError::StaleClaim)
        );

        let second_claim = repository
            .claim_result(ClaimProviderResult::new(
                connection.connection_id(),
                worker,
                UnixMillis::new(3_004),
                1_000,
            )?)
            .await?
            .expect("second result claim");
        assert_eq!(second_claim.desired(), &second_desired);
        assert!(second_claim.claim().fence() > first_claim.claim().fence());
        repository
            .retry_result(RetryProviderResult::new(
                second_claim.claim(),
                UnixMillis::new(3_005),
                UnixMillis::new(3_100),
            )?)
            .await?;
        assert!(
            repository
                .claim_result(ClaimProviderResult::new(
                    connection.connection_id(),
                    worker,
                    UnixMillis::new(3_099),
                    1_000,
                )?)
                .await?
                .is_none()
        );
        let final_claim = repository
            .claim_result(ClaimProviderResult::new(
                connection.connection_id(),
                worker,
                UnixMillis::new(3_100),
                1_000,
            )?)
            .await?
            .expect("retried result claim");
        assert_eq!(final_claim.attempts(), 2);
        let evidence = ProviderResultPublicationEvidence::new(
            &final_claim,
            ProviderResultPublicationModel::AppendOnlyCommitStatus,
            None,
            final_claim.desired().digest(),
            UnixMillis::new(3_101),
        )?;
        repository
            .complete_result(CompleteProviderResult::new(final_claim.claim(), evidence)?)
            .await?;
        let state: String = sqlx::query_scalar(
            "SELECT state FROM provider_result_outbox WHERE subject_id = $1",
        )
        .bind(subject.subject_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(state, "completed");
        assert!(
            repository
                .claim_result(ClaimProviderResult::new(
                    connection.connection_id(),
                    worker,
                    UnixMillis::new(4_000),
                    1_000,
                )?)
                .await?
                .is_none()
        );
        let third_desired = desired(3, 4_001, "still running")?;
        repository
            .save_desired(SaveDesiredProviderResult::new(
                subject.clone(),
                third_desired,
            )?)
            .await?;
        let exhausted_claim = repository
            .claim_result(ClaimProviderResult::new(
                connection.connection_id(),
                worker,
                UnixMillis::new(4_002),
                1_000,
            )?)
            .await?
            .expect("exhaustion fixture claim");
        sqlx::query(
            "UPDATE provider_result_outbox SET attempts = 64, next_fence = 64, claim_fence = 64, claim_expires_at_ms = 4003 WHERE subject_id = $1",
        )
        .bind(subject.subject_id().as_uuid())
        .execute(database.pool())
        .await?;
        assert!(
            repository
                .claim_result(ClaimProviderResult::new(
                    connection.connection_id(),
                    worker,
                    UnixMillis::new(4_003),
                    1_000,
                )?)
                .await?
                .is_none()
        );
        let exhausted: (String, Option<String>) = sqlx::query_as(
            "SELECT state, failure_kind FROM provider_result_outbox WHERE subject_id = $1",
        )
        .bind(exhausted_claim.subject().subject_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(exhausted, ("failed".to_owned(), Some("attempt-limit".to_owned())));
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

fn verified_delivery(
    endpoint: &ProviderWebhookEndpointManifest,
    delivery_id: ProviderDeliveryId,
    raw_body: &[u8],
) -> VerifiedProviderTriggerDelivery {
    let digest = secret_digest(raw_body);
    let raw =
        provider_raw_webhook_descriptor(digest, raw_body.len() as u64).expect("raw descriptor");
    let repository = ProviderRepository::new(
        ExternalRepositoryIdentity::new(
            endpoint.instance_id(),
            ExternalRepositoryId::new("42").expect("repository ID"),
        ),
        automata_ci_provider::ExternalSubjectId::new("7").expect("owner ID"),
        ProviderRepositoryPath::new("owner/repository").expect("repository path"),
        RepositoryVisibility::Private,
    );
    let before = automata_ci_core::GitObjectId::from_hex(GitObjectAlgorithm::Sha1, &"a".repeat(40))
        .expect("before object");
    let after = automata_ci_core::GitObjectId::from_hex(GitObjectAlgorithm::Sha1, &"b".repeat(40))
        .expect("after object");
    let trigger = NormalizedTrigger::Push(
        PushTrigger::new(
            repository,
            ProviderGitRef::new("refs/heads/main", ProviderGitRefKind::Branch).expect("branch"),
            Some(before),
            Some(after),
            PushCommitEvidence::complete([after]).expect("commit evidence"),
            false,
            None,
        )
        .expect("push"),
    )
    .seal()
    .expect("sealed trigger");
    let evidence = ProviderDeliveryEvidence::rehydrate(
        delivery_id,
        endpoint.endpoint_id(),
        endpoint.revision(),
        endpoint.provider_type().clone(),
        endpoint.instance_id(),
        endpoint.provider_revision(),
        endpoint.connection_id(),
        endpoint.connection_revision(),
        ExternalDeliveryIdentity::new(
            endpoint.instance_id(),
            ExternalDeliveryId::new("delivery-100").expect("external delivery"),
        ),
        ProviderEventName::new("push").expect("event type"),
        UnixMillis::new(4_000),
        raw,
        UnixMillis::new(
            4_000
                + i64::try_from(endpoint.raw_retention_millis())
                    .expect("retention is in signed range"),
        ),
        ProviderWebhookSignatureEvidence::new(
            "fake-sha256",
            endpoint.secret_references()[0].clone(),
        )
        .expect("signature evidence"),
        ProviderDeliveryObservations::new(br#"{"fixture":"postgres"}"#.to_vec())
            .expect("observations"),
    )
    .expect("delivery evidence");
    VerifiedProviderTriggerDelivery::rehydrate(evidence, trigger).expect("verified delivery")
}

fn verified_control(
    endpoint: &ProviderWebhookEndpointManifest,
    delivery_id: ProviderDeliveryId,
    external_delivery_id: &str,
    raw_body: &[u8],
) -> VerifiedProviderControlDelivery {
    let raw = provider_raw_webhook_descriptor(secret_digest(raw_body), raw_body.len() as u64)
        .expect("raw descriptor");
    let evidence = ProviderDeliveryEvidence::rehydrate(
        delivery_id,
        endpoint.endpoint_id(),
        endpoint.revision(),
        endpoint.provider_type().clone(),
        endpoint.instance_id(),
        endpoint.provider_revision(),
        endpoint.connection_id(),
        endpoint.connection_revision(),
        ExternalDeliveryIdentity::new(
            endpoint.instance_id(),
            ExternalDeliveryId::new(external_delivery_id).expect("external delivery"),
        ),
        ProviderEventName::new("check_run").expect("event type"),
        UnixMillis::new(8_000),
        raw,
        UnixMillis::new(
            8_000
                + i64::try_from(endpoint.raw_retention_millis())
                    .expect("retention is in signed range"),
        ),
        ProviderWebhookSignatureEvidence::new(
            "fake-sha256",
            endpoint.secret_references()[0].clone(),
        )
        .expect("signature evidence"),
        ProviderDeliveryObservations::new(br#"{"fixture":"control"}"#.to_vec())
            .expect("observations"),
    )
    .expect("delivery evidence");
    let control = ProviderControl::new(
        ProviderControlKind::Rerun,
        ExternalRepositoryIdentity::new(
            endpoint.instance_id(),
            ExternalRepositoryId::new("42").expect("repository ID"),
        ),
        automata_ci_core::GitObjectId::from_hex(GitObjectAlgorithm::Sha1, &"b".repeat(40))
            .expect("object"),
        Some(ExternalSubjectIdentity::new(
            endpoint.instance_id(),
            ExternalSubjectKind::User,
            ExternalSubjectId::new("301").expect("actor"),
        )),
        ProviderControlDocument::new(
            ProviderSchemaVersion::new(1).expect("schema"),
            br#"{"schema":1,"target":{"kind":"check_run","run_id":601}}"#.to_vec(),
        )
        .expect("control document"),
    )
    .expect("control");
    VerifiedProviderControlDelivery::rehydrate(evidence, control).expect("verified control")
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 via AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn endpoint_secrets_replay_conflicts_and_worker_fences_are_exact() -> TestResult {
    run_with_database(|database| async move {
        let repository = repository(database.pool().clone());
        let instance_id = ProviderInstanceId::from_uuid(Uuid::from_u128(101))?;
        repository
            .save_instance(instance_record(
                instance_id,
                "forgejo",
                1,
                TOKEN,
                1,
                ProviderLifecycleState::Active,
                Some(UnixMillis::new(1_000)),
            ))
            .await?;
        let instance = repository
            .current_instance(instance_id)
            .await?
            .expect("instance");
        let workspace = WorkspaceId::parse("22222222-2222-4222-8222-222222222222")?;
        sqlx::query(
            "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Delivery test', 1, 1)",
        )
        .bind(workspace.to_string())
        .execute(database.pool())
        .await?;
        let connection = connection(workspace, instance.manifest());
        repository.save_connection(connection.clone()).await?;

        let endpoint = ProviderWebhookEndpointManifest::new(
            ProviderWebhookEndpointId::from_uuid(Uuid::from_u128(102))?,
            ProviderWebhookEndpointRevision::new(1)?,
            ProviderWebhookEndpointState::Active,
            ProviderTypeId::new("forgejo")?,
            instance_id,
            instance.manifest().revision(),
            connection.connection_id(),
            connection.revision(),
            1_024,
            30 * 24 * 60 * 60 * 1_000,
            vec![ProviderWebhookSecretReference::new(
                instance.manifest().revision(),
                ProviderSecretName::new("control-token")?,
                ProviderSecretGeneration::new(1)?,
            )],
            UnixMillis::new(3_000),
            None,
        )?;
        assert_eq!(
            repository.save_endpoint(endpoint.clone()).await?,
            ProviderSaveOutcome::Inserted
        );
        let resolved = repository
            .resolve_endpoint(endpoint.endpoint_id())
            .await?
            .expect("resolved endpoint");
        assert_eq!(resolved.connection(), &connection);
        assert_eq!(
            resolved
                .secrets()
                .iter()
                .next()
                .expect("candidate")
                .expose_secret(),
            TOKEN
        );

        let first_id = ProviderDeliveryId::from_uuid(Uuid::from_u128(103))?;
        let first = ProviderDelivery::Trigger(Box::new(verified_delivery(
            &endpoint,
            first_id,
            b"body-one",
        )));
        let acceptance = AcceptProviderDelivery::new(first, UnixMillis::new(4_100))?;
        assert!(matches!(
            repository.accept_delivery(acceptance).await?,
            ProviderDeliveryAcceptOutcome::Inserted(receipt)
                if receipt.delivery_id() == first_id
                    && receipt.invocation_id().is_some()
        ));
        let immutable_update = sqlx::query(
            "UPDATE provider_deliveries SET event_type = 'tampered' WHERE delivery_id = $1",
        )
        .bind(first_id.as_uuid())
        .execute(database.pool())
        .await;
        assert!(immutable_update.is_err(), "raw delivery evidence is immutable");

        let duplicate = ProviderDelivery::Trigger(Box::new(verified_delivery(
            &endpoint,
            ProviderDeliveryId::from_uuid(Uuid::from_u128(104))?,
            b"body-one",
        )));
        assert!(matches!(
            repository
                .accept_delivery(AcceptProviderDelivery::new(
                    duplicate,
                    UnixMillis::new(4_200),
                )?)
                .await?,
            ProviderDeliveryAcceptOutcome::Duplicate(receipt)
                if receipt.delivery_id() == first_id
        ));

        let conflict = ProviderDelivery::Trigger(Box::new(verified_delivery(
            &endpoint,
            ProviderDeliveryId::from_uuid(Uuid::from_u128(105))?,
            b"different-body",
        )));
        assert_eq!(
            repository
                .accept_delivery(AcceptProviderDelivery::new(
                    conflict,
                    UnixMillis::new(4_300),
                )?)
                .await,
            Err(ProviderDeliveryRepositoryError::ReplayConflict)
        );

        let worker = ProviderProcessingWorkerId::from_uuid(Uuid::from_u128(106))?;
        let first_claim = repository
            .claim_processing(ClaimProviderProcessing::new(
                worker,
                UnixMillis::new(5_000),
                1_000,
            )?)
            .await?
            .expect("first claim");
        let retry = repository
            .retry_processing(RetryProviderProcessing::new(
                first_claim.fence(),
                UnixMillis::new(5_500),
                UnixMillis::new(7_000),
                ProviderProcessingFailure::DependencyUnavailable,
            )?)
            .await?;
        assert_eq!(retry.state(), ProviderProcessingState::RetryPending);
        assert!(
            repository
                .claim_processing(ClaimProviderProcessing::new(
                    worker,
                    UnixMillis::new(6_999),
                    1_000,
                )?)
                .await?
                .is_none()
        );
        let second_claim = repository
            .claim_processing(ClaimProviderProcessing::new(
                worker,
                UnixMillis::new(7_000),
                1_000,
            )?)
            .await?
            .expect("second claim");
        assert!(second_claim.fence().token() > first_claim.fence().token());
        let completed = repository
            .complete_processing(CompleteProviderProcessing::new(
                second_claim.fence(),
                UnixMillis::new(7_500),
            )?)
            .await?;
        assert_eq!(completed.state(), ProviderProcessingState::Completed);

        let control_id = ProviderDeliveryId::from_uuid(Uuid::from_u128(107))?;
        let control = ProviderDelivery::Control(Box::new(verified_control(
            &endpoint,
            control_id,
            "control-100",
            b"control-body",
        )));
        let ProviderDeliveryAcceptOutcome::Inserted(control_receipt) = repository
            .accept_delivery(AcceptProviderDelivery::new(
                control,
                UnixMillis::new(8_100),
            )?)
            .await?
        else {
            panic!("new control was not inserted");
        };
        assert_eq!(control_receipt.delivery_id(), control_id);
        assert!(control_receipt.invocation_id().is_some());
        let replay = ProviderDelivery::Control(Box::new(verified_control(
            &endpoint,
            ProviderDeliveryId::from_uuid(Uuid::from_u128(108))?,
            "control-100",
            b"control-body",
        )));
        assert!(matches!(
            repository
                .accept_delivery(AcceptProviderDelivery::new(
                    replay,
                    UnixMillis::new(8_150),
                )?)
                .await?,
            ProviderDeliveryAcceptOutcome::Duplicate(receipt)
                if receipt.delivery_id() == control_id
                    && receipt.invocation_id() == control_receipt.invocation_id()
        ));
        let control_claim = repository
            .claim_processing(ClaimProviderProcessing::new(
                worker,
                UnixMillis::new(8_200),
                1_000,
            )?)
            .await?
            .expect("control claim");
        assert!(matches!(
            control_claim.input(),
            ProviderProcessingInput::Control(delivery)
                if delivery.evidence().delivery_id() == control_id
        ));
        assert!(control_claim.receipt().source_delivery_id().is_none());
        let bound = repository
            .bind_processing_source(BindProviderProcessingSource::new(
                control_claim.fence(),
                first_id,
                UnixMillis::new(8_300),
            )?)
            .await?;
        assert_eq!(bound.receipt().source_delivery_id(), Some(first_id));
        assert_eq!(
            repository
                .bind_processing_source(BindProviderProcessingSource::new(
                    control_claim.fence(),
                    first_id,
                    UnixMillis::new(8_400),
                )?)
                .await,
            Err(ProviderProcessingRepositoryError::ClaimRejected),
            "a control source can only be bound once"
        );
        assert_eq!(
            repository
                .complete_processing(CompleteProviderProcessing::new(
                    control_claim.fence(),
                    UnixMillis::new(8_500),
                )?)
                .await?
                .state(),
            ProviderProcessingState::Completed
        );

        let unbound_control_id = ProviderDeliveryId::from_uuid(Uuid::from_u128(109))?;
        let unbound_control = ProviderDelivery::Control(Box::new(verified_control(
            &endpoint,
            unbound_control_id,
            "control-without-trigger-source",
            b"schedule-control-body",
        )));
        repository
            .accept_delivery(AcceptProviderDelivery::new(
                unbound_control,
                UnixMillis::new(8_600),
            )?)
            .await?;
        let unbound_claim = repository
            .claim_processing(ClaimProviderProcessing::new(
                worker,
                UnixMillis::new(8_700),
                1_000,
            )?)
            .await?
            .expect("unbound control claim");
        assert_eq!(unbound_claim.receipt().source_delivery_id(), None);
        let unbound_completed = repository
            .complete_processing(CompleteProviderProcessing::new(
                unbound_claim.fence(),
                UnixMillis::new(8_800),
            )?)
            .await?;
        assert_eq!(unbound_completed.state(), ProviderProcessingState::Completed);
        assert_eq!(unbound_completed.source_delivery_id(), None);

        let disabled_connection = ProviderConnectionManifest::new(
            connection.connection_id(),
            ProviderConnectionRevision::new(2)?,
            ProviderLifecycleState::Disabled,
            connection.configuration().clone(),
            connection.created_at(),
            connection.activated_at(),
            None,
        )?;
        repository.save_connection(disabled_connection).await?;
        assert!(
            repository
                .resolve_endpoint(endpoint.endpoint_id())
                .await?
                .is_none(),
            "connection disablement closes ingress without a fallback revision"
        );
        Ok(())
    })
    .await
}
