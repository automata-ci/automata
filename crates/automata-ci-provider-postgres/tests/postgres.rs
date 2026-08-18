use std::sync::Arc;

use automata_ci_core::{
    GitObjectAlgorithm, GitObjectId, RunId, Sha256Digest, TrustEventKind, TrustEvidence,
    TrustOriginKind, TrustPolicy, TrustRepositoryEvidence, TrustTokenRecursion, UnixMillis,
    WorkflowId, WorkflowJobKey, WorkspaceId,
};
use automata_ci_key_management::{KeyId, LocalAes256GcmKeyring, LocalKeyMaterial, SecretBytes};
use automata_ci_postgres::test_support::{TestResult, run_with_database};
use automata_ci_provider::{
    AcceptProviderDelivery, BindProviderProcessingSource, ClaimProviderProcessing,
    ClaimProviderResult, CompleteProviderProcessing, CompleteProviderResult, DesiredProviderResult,
    ExternalDeliveryId, ExternalDeliveryIdentity, ExternalRepositoryId, ExternalRepositoryIdentity,
    ExternalResultId, ExternalSubjectId, ExternalSubjectIdentity, ExternalSubjectKind,
    NormalizedTrigger, ProviderArchiveLimits, ProviderCapabilities, ProviderCapability,
    ProviderConfigurationDocument, ProviderConfigurationRevision, ProviderConnectionConfiguration,
    ProviderConnectionId, ProviderConnectionManifest, ProviderConnectionPolicyDocument,
    ProviderConnectionRevision, ProviderControl, ProviderControlDocument, ProviderControlKind,
    ProviderDefaultBranch, ProviderDelivery, ProviderDeliveryAcceptOutcome,
    ProviderDeliveryEvidence, ProviderDeliveryId, ProviderDeliveryObservations,
    ProviderDeliveryRepository as _, ProviderDeliveryRepositoryError, ProviderEventName,
    ProviderGitRef, ProviderGitRefKind, ProviderInstanceId, ProviderInstanceManifest,
    ProviderInstanceRecord, ProviderLifecycleState, ProviderManifestRepository as _,
    ProviderOrigins, ProviderProcessingFailure, ProviderProcessingInput,
    ProviderProcessingRepository as _, ProviderProcessingRepositoryError, ProviderProcessingState,
    ProviderProcessingWorkerId, ProviderRepository, ProviderRepositoryError,
    ProviderRepositoryPath, ProviderResultContinuation, ProviderResultDetailsUrl,
    ProviderResultName, ProviderResultPhase, ProviderResultProjection,
    ProviderResultPublicationEvidence, ProviderResultPublicationModel,
    ProviderResultRepository as _, ProviderResultRepositoryError, ProviderResultSaveOutcome,
    ProviderResultSubject, ProviderResultSubjectId, ProviderResultSubjectKind,
    ProviderResultSummary, ProviderResultTitle, ProviderResultWorkerId,
    ProviderRunnerPolicyBinding, ProviderSaveOutcome, ProviderSchemaVersion, ProviderSecret,
    ProviderSecretBinding, ProviderSecretBindings, ProviderSecretGeneration, ProviderSecretName,
    ProviderSecretSet, ProviderTypeId, ProviderWebhookEndpointId, ProviderWebhookEndpointManifest,
    ProviderWebhookEndpointRepository as _, ProviderWebhookEndpointRevision,
    ProviderWebhookEndpointState, ProviderWebhookSecretReference, ProviderWebhookSignatureEvidence,
    ProviderWorkflowSource, PushCommitEvidence, PushTrigger, RenewProviderResult,
    RepositoryVisibility, RetryProviderProcessing, RetryProviderResult, SaveDesiredProviderResult,
    SourceReadCapability, VerifiedProviderControlDelivery, VerifiedProviderTriggerDelivery,
    provider_capability_digest, provider_raw_webhook_descriptor,
};
use automata_ci_provider_postgres::PostgresProviderManifestRepository;
use automata_ci_store::{
    AdmissionObject, AdmissionRepository, AdmitLogicalWorkflowRun, AdmittedLogicalWorkflowJob,
    AuthenticatedProviderDeliveryClaim, LogicalWorkflowAdmissionRepository as _,
    LogicalWorkflowInvocationId, LogicalWorkflowJobId, LogicalWorkflowJobKind, ObjectKey,
    RepositoryId, TenantScope, WorkflowAdmissionIdempotency, WorkflowRuntimePolicy,
    WorkflowSnapshotId,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

const TOKEN: &[u8] = b"forgejo-control-token-that-must-stay-encrypted";
const RUNTIME_POLICY: &[u8] = br#"{
  "workspace":{"derivation":1,"root":"/__w","schema":1},
  "mappings":[{
    "runner_features":{"schema":1,"supported":["automata.core/bash-shell@v1","automata.core/default-posix-shell@v1","automata.core/shell-steps@v1"]},
    "container_features":[],"architecture":"x86_64","operating_system":"linux",
    "environment_profile":{"manifest_sha256":"1111111111111111111111111111111111111111111111111111111111111111","id":"automata.example/ubuntu-24-04"},
    "selector":"Ubuntu-24.04"
  }],
  "permissions":{"provider_default":{"contents":"read","packages":"read"},"read_all":{"actions":"read","artifact-metadata":"read","attestations":"read","checks":"read","code-quality":"read","contents":"read","deployments":"read","discussions":"read","issues":"read","models":"read","packages":"read","pages":"read","pull-requests":"read","security-events":"read","statuses":"read","vulnerability-alerts":"read"},"write_all":{"actions":"write","artifact-metadata":"write","attestations":"write","checks":"write","code-quality":"write","contents":"write","deployments":"write","discussions":"write","id-token":"write","issues":"write","models":"read","packages":"write","pages":"write","pull-requests":"write","security-events":"write","statuses":"write","vulnerability-alerts":"read"}},
  "resources":{"defaults":{"requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"limits":{"cpu_millis":1000,"memory_bytes":1073741824,"ephemeral_disk_bytes":0,"gpu_count":0}},"minimum_requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"maximum_limits":{"cpu_millis":4000,"memory_bytes":8589934592,"ephemeral_disk_bytes":0,"gpu_count":0}},
  "schema":2
}"#;

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

fn connection_with_runner_policy(
    workspace_id: WorkspaceId,
    instance: &ProviderInstanceManifest,
    runner_policy: ProviderRunnerPolicyBinding,
) -> ProviderConnectionManifest {
    let mut connection = connection(workspace_id, instance);
    let configuration = ProviderConnectionConfiguration::new(
        workspace_id,
        connection.configuration().repository().clone(),
        instance.revision(),
        instance.configuration().digest(),
        instance.capability_digest(),
        RepositoryVisibility::Private,
        ProviderDefaultBranch::new("main").expect("branch"),
        ProviderWorkflowSource::Directory(
            ProviderRepositoryPath::new(".forgejo/workflows").expect("workflow path"),
        ),
        runner_policy,
        connection.configuration().archive_limits(),
        connection.configuration().adapter_policy().clone(),
    );
    connection = ProviderConnectionManifest::new(
        connection.connection_id(),
        connection.revision(),
        ProviderLifecycleState::Active,
        configuration,
        UnixMillis::new(2_000),
        Some(UnixMillis::new(2_000)),
        None,
    )
    .expect("connection manifest");
    connection
}

async fn seed_provider_runtime_policy(
    pool: &sqlx::PgPool,
    tenant: &str,
    repository_id: RepositoryId,
    policy: &WorkflowRuntimePolicy,
) -> TestResult {
    let canonical = policy.canonical_bytes()?;
    let mapping = &policy.mappings()[0];
    let mut transaction = pool.begin().await?;
    sqlx::query(
        r"
        INSERT INTO repositories (
            id, tenant_id, scm_provider, provider_repository_id,
            owner, name, created_at_ms, updated_at_ms
        ) VALUES ($1,$2,'forgejo','42','owner','repository',1,1)
        ",
    )
    .bind(repository_id.as_uuid())
    .bind(tenant)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_runtime_policy_revisions (
            tenant_id, repository_id, policy_revision, policy_digest,
            canonical_policy, permission_policy_canonical,
            resource_policy_canonical, policy_schema, workspace_root,
            workspace_derivation_version, mapping_count, state,
            registered_at_ms, sealed_at_ms
        ) VALUES ($1,$2,1,$3,$4,$5,$6,$7,'/__w',1,1,'staging',2,NULL)
        ",
    )
    .bind(tenant)
    .bind(repository_id.as_uuid())
    .bind(policy.digest().as_bytes().as_slice())
    .bind(&canonical)
    .bind(policy.permission_policy().canonical_bytes()?)
    .bind(serde_json::to_vec(&policy.resource_policy())?)
    .bind(i16::try_from(policy.schema())?)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_runtime_policy_mappings (
            tenant_id, repository_id, policy_revision, selector,
            environment_profile_id, environment_profile_digest,
            operating_system, architecture, feature_count,
            runner_feature_schema, runner_feature_count
        ) VALUES ($1,$2,1,$3,$4,$5,'linux','x86_64',0,1,$6)
        ",
    )
    .bind(tenant)
    .bind(repository_id.as_uuid())
    .bind(mapping.selector().as_str())
    .bind(mapping.environment().id().as_str())
    .bind(mapping.environment().digest().as_bytes().as_slice())
    .bind(i32::try_from(
        mapping
            .runner_feature_policy()
            .expect("current policy runner features")
            .supported()
            .len(),
    )?)
    .execute(&mut *transaction)
    .await?;
    for feature in mapping
        .runner_feature_policy()
        .expect("current policy runner features")
        .supported()
    {
        sqlx::query(
            r"
            INSERT INTO workflow_runtime_policy_runner_features (
                tenant_id, repository_id, policy_revision, selector, feature
            ) VALUES ($1,$2,1,$3,$4)
            ",
        )
        .bind(tenant)
        .bind(repository_id.as_uuid())
        .bind(mapping.selector().as_str())
        .bind(feature.as_str())
        .execute(&mut *transaction)
        .await?;
    }
    sqlx::query(
        "UPDATE workflow_runtime_policy_revisions SET state='sealed', sealed_at_ms=registered_at_ms WHERE tenant_id=$1 AND repository_id=$2 AND policy_revision=1",
    )
    .bind(tenant)
    .bind(repository_id.as_uuid())
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO workflow_runtime_policy_current (tenant_id, repository_id, policy_revision, policy_digest, activated_at_ms) VALUES ($1,$2,1,$3,2)",
    )
    .bind(tenant)
    .bind(repository_id.as_uuid())
    .bind(policy.digest().as_bytes().as_slice())
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
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
            ProviderResultName::new("Automata CI")?,
            ProviderResultDetailsUrl::new(
                "https://ci.example/runs/5903"
                    .parse()
                    .expect("fixed provider result URL"),
            )?,
            ProviderResultSubjectKind::WorkflowRun {
                run_id: RunId::from_uuid(Uuid::from_u128(0x5903)),
            },
            1,
            UnixMillis::new(3_000),
        )?;
        let desired = |generation, updated_at, summary| {
            DesiredProviderResult::new(
                generation,
                ProviderResultProjection::new(
                    ProviderResultPhase::Running,
                    None,
                    ProviderResultTitle::new("Automata CI")?,
                    ProviderResultSummary::new(summary)?,
                    Vec::new(),
                    UnixMillis::new(updated_at),
                )?,
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

        let mut second_claim = repository
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
        let continuation = ProviderResultContinuation::new(
            ProviderSchemaVersion::new(1)?,
            br#"{"state":"reconcile-create"}"#.to_vec(),
        )?;
        let stale_second_fence = second_claim.claim();
        let renewed = repository
            .renew_result(RenewProviderResult::new(
                stale_second_fence,
                UnixMillis::new(3_500),
                1_000,
            )?)
            .await?;
        second_claim.renew_claim(renewed)?;
        assert_eq!(renewed.expires_at(), UnixMillis::new(4_500));
        assert_eq!(
            repository
                .retry_result(RetryProviderResult::new(
                    stale_second_fence,
                    UnixMillis::new(3_501),
                    UnixMillis::new(3_600),
                    None,
                )?)
                .await,
            Err(ProviderResultRepositoryError::StaleClaim)
        );
        assert!(
            repository
                .claim_result(ClaimProviderResult::new(
                    connection.connection_id(),
                    worker,
                    UnixMillis::new(4_004),
                    1_000,
                )?)
                .await?
                .is_none(),
            "the renewed claim must exclude a concurrent reclaim"
        );
        repository
            .retry_result(RetryProviderResult::new(
                second_claim.claim(),
                UnixMillis::new(3_502),
                UnixMillis::new(3_600),
                Some(continuation.clone()),
            )?)
            .await?;
        assert!(
            repository
                .claim_result(ClaimProviderResult::new(
                    connection.connection_id(),
                    worker,
                    UnixMillis::new(3_599),
                    1_000,
                )?)
                .await?
                .is_none()
        );
        let final_claim = repository
            .claim_result(ClaimProviderResult::new(
                connection.connection_id(),
                worker,
                UnixMillis::new(3_600),
                1_000,
            )?)
            .await?
            .expect("retried result claim");
        assert_eq!(final_claim.attempts(), 2);
        assert_eq!(final_claim.continuation(), Some(&continuation));
        let evidence = ProviderResultPublicationEvidence::new(
            &final_claim,
            ProviderResultPublicationModel::MutableRichCheck,
            Some(ExternalResultId::new("github-check-5903")?),
            final_claim.desired().digest(),
            UnixMillis::new(3_601),
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
        assert_eq!(
            exhausted_claim
                .binding()
                .expect("mutable provider binding")
                .external_id()
                .as_str(),
            "github-check-5903"
        );
        assert!(exhausted_claim.continuation().is_none());
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

fn admission_object(name: &str, digest: Sha256Digest, media_type: &str) -> AdmissionObject {
    AdmissionObject::new(
        digest,
        ObjectKey::new(format!("provider-admission/{name}")).expect("object key"),
        128,
        media_type,
    )
    .expect("admission object")
}

#[allow(clippy::too_many_arguments)]
fn provider_admission_command(
    tenant: &str,
    delivery_id: ProviderDeliveryId,
    repository_id: RepositoryId,
    workflow_id: WorkflowId,
    workflow_path: &str,
    git_ref: &str,
    event_name: &str,
    head_sha: GitObjectId,
    actor: Option<&str>,
    event_digest: Sha256Digest,
    request_digest: Sha256Digest,
    admitted_at: UnixMillis,
) -> AdmitLogicalWorkflowRun {
    let trust_repository =
        TrustRepositoryEvidence::new("42", "7").expect("trust repository evidence");
    let revision = head_sha.to_string();
    let trust = TrustPolicy::current()
        .evaluate(
            TrustEvidence::new(TrustOriginKind::ProviderWebhook, TrustEventKind::Push)
                .with_repositories(trust_repository.clone(), trust_repository)
                .with_refs(git_ref, git_ref, git_ref)
                .with_revisions(revision.clone(), revision.clone(), revision)
                .with_fork(false)
                .with_token_recursion(TrustTokenRecursion::Suppressed),
        )
        .expect("trust snapshot");
    let job = AdmittedLogicalWorkflowJob::new(
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(0x5147)).expect("job ID"),
        WorkflowJobKey::new("verify").expect("job key"),
        0,
        LogicalWorkflowJobKind::Steps,
        Vec::new(),
    )
    .expect("logical job");
    let mut builder = AdmitLogicalWorkflowRun::builder(
        TenantScope::from_authenticated_tenant_id(tenant).expect("tenant"),
        WorkflowAdmissionIdempotency::provider_delivery(delivery_id.to_string())
            .expect("provider delivery idempotency"),
        request_digest,
        AdmissionRepository::new(repository_id, "forgejo", "42", "owner/repository")
            .expect("admission repository"),
        workflow_id,
        workflow_path,
        "Provider admission",
        git_ref,
        WorkflowSnapshotId::from_uuid(Uuid::from_u128(0x5144)),
        admission_object(
            "source",
            Sha256Digest::from_bytes([0x51; 32]),
            "application/yaml",
        ),
        admission_object(
            "plan",
            Sha256Digest::from_bytes([0x52; 32]),
            "application/vnd.automata.workflow-plan.protobuf",
        ),
        RunId::from_uuid(Uuid::from_u128(0x5145)),
        1,
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(0x5146)).expect("root invocation"),
        event_name,
        admission_object("event", event_digest, "application/json"),
        head_sha,
        vec![job],
        admitted_at,
    )
    .trust_snapshot(trust);
    if let Some(actor) = actor {
        builder = builder.actor(actor);
    }
    builder.build().expect("provider admission command")
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
async fn provider_admission_binds_normalized_trigger_and_replays_after_claim_rotation() -> TestResult
{
    run_with_database(|database| async move {
        let repository = repository(database.pool().clone());
        let instance_id = ProviderInstanceId::from_uuid(Uuid::from_u128(0x5141))?;
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
            .expect("provider instance");
        let workspace = WorkspaceId::parse("00000000-0000-4000-8000-000000005142")?;
        let tenant = workspace.to_string();
        let repository_id = RepositoryId::from_uuid(Uuid::from_u128(0x5149));
        sqlx::query(
            "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Provider admission test', 1, 1)",
        )
        .bind(workspace.to_string())
        .execute(database.pool())
        .await?;
        let runtime_policy = WorkflowRuntimePolicy::decode_configuration(RUNTIME_POLICY)?;
        let runner_policy = ProviderRunnerPolicyBinding::new(
            ProviderSchemaVersion::new(runtime_policy.schema())?,
            runtime_policy.canonical_digest(),
        );
        let connection = connection_with_runner_policy(workspace, instance.manifest(), runner_policy);
        repository.save_connection(connection.clone()).await?;
        seed_provider_runtime_policy(
            database.pool(),
            &tenant,
            repository_id,
            &runtime_policy,
        )
        .await?;
        let endpoint = ProviderWebhookEndpointManifest::new(
            ProviderWebhookEndpointId::from_uuid(Uuid::from_u128(0x5142))?,
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
        repository.save_endpoint(endpoint.clone()).await?;

        let delivery_id = ProviderDeliveryId::from_uuid(Uuid::from_u128(0x5143))?;
        let raw_body = b"provider-admission-body";
        let event_digest = secret_digest(raw_body);
        let delivery = ProviderDelivery::Trigger(Box::new(verified_delivery(
            &endpoint,
            delivery_id,
            raw_body,
        )));
        let ProviderDeliveryAcceptOutcome::Inserted(delivery_receipt) = repository
            .accept_delivery(AcceptProviderDelivery::new(
                delivery,
                UnixMillis::new(4_100),
            )?)
            .await?
        else {
            panic!("provider delivery was not inserted");
        };
        let worker = ProviderProcessingWorkerId::from_uuid(Uuid::from_u128(0x5148))?;
        let first_claim = repository
            .claim_processing(ClaimProviderProcessing::new(
                worker,
                UnixMillis::new(5_000),
                1_000,
            )?)
            .await?
            .expect("first processing claim");
        assert_eq!(
            delivery_receipt.invocation_id(),
            Some(first_claim.receipt().invocation_id())
        );
        let first_authority = AuthenticatedProviderDeliveryClaim::new(
            delivery_id,
            first_claim.receipt(),
            first_claim.fence(),
        )?;
        let workflow_id = WorkflowId::from_uuid(Uuid::from_u128(0x514a));
        let expected_head = GitObjectId::from_hex(GitObjectAlgorithm::Sha1, &"b".repeat(40))?;
        let request_digest = Sha256Digest::from_bytes([0x53; 32]);
        let command = |workflow_path: &str,
                       git_ref: &str,
                       event_name: &str,
                       head_sha: GitObjectId,
                       actor: Option<&str>,
                       digest: Sha256Digest,
                       admitted_at: UnixMillis| {
            provider_admission_command(
                &tenant,
                delivery_id,
                repository_id,
                workflow_id,
                workflow_path,
                git_ref,
                event_name,
                head_sha,
                actor,
                event_digest,
                digest,
                admitted_at,
            )
        };

        for invalid in [
            command(
                ".forgejo/workflows/ci.yml",
                "refs/heads/main",
                "push",
                GitObjectId::from_hex(GitObjectAlgorithm::Sha1, &"c".repeat(40))?,
                None,
                request_digest,
                UnixMillis::new(5_500),
            ),
            command(
                ".forgejo/workflows/ci.yml",
                "refs/heads/other",
                "push",
                expected_head,
                None,
                request_digest,
                UnixMillis::new(5_500),
            ),
            command(
                ".forgejo/workflows/ci.yml",
                "refs/heads/main",
                "pull_request",
                expected_head,
                None,
                request_digest,
                UnixMillis::new(5_500),
            ),
            command(
                ".forgejo/workflows/ci.yml",
                "refs/heads/main",
                "push",
                expected_head,
                Some("different-actor"),
                request_digest,
                UnixMillis::new(5_500),
            ),
        ] {
            database
                .store()
                .admit_authenticated_provider_delivery(
                    invalid,
                    first_authority,
                    UnixMillis::new(5_500),
                )
                .await
                .expect_err("changed normalized trigger coordinate must be rejected");
        }

        let initial = command(
            ".forgejo/workflows/ci.yml",
            "refs/heads/main",
            "push",
            expected_head,
            None,
            request_digest,
            UnixMillis::new(5_500),
        );
        let receipt = database
            .store()
            .admit_authenticated_provider_delivery(
                initial,
                first_authority,
                UnixMillis::new(5_500),
            )
            .await?;
        assert!(!receipt.is_replay());
        let (evidence_schema, evidence_digest, pin_revision, pin_digest):
            (i16, Vec<u8>, i64, Vec<u8>) = sqlx::query_as(
                r"
                SELECT evidence.runner_policy_schema, evidence.runner_policy_digest,
                       pin.policy_revision, pin.policy_digest
                FROM provider_workflow_admission_evidence AS evidence
                JOIN logical_workflow_runtime_policy_pins AS pin
                  ON pin.run_id = evidence.run_id
                WHERE evidence.delivery_id = $1
                ",
            )
            .bind(delivery_id.as_uuid())
            .fetch_one(database.pool())
            .await?;
        assert_eq!(evidence_schema, i16::try_from(runtime_policy.schema())?);
        assert_eq!(
            evidence_digest.as_slice(),
            runtime_policy.canonical_digest().as_bytes()
        );
        assert_eq!(pin_revision, 1);
        assert_eq!(pin_digest.as_slice(), runtime_policy.digest().as_bytes());

        repository
            .retry_processing(RetryProviderProcessing::new(
                first_claim.fence(),
                UnixMillis::new(5_600),
                UnixMillis::new(7_000),
                ProviderProcessingFailure::DependencyUnavailable,
            )?)
            .await?;
        let second_claim = repository
            .claim_processing(ClaimProviderProcessing::new(
                worker,
                UnixMillis::new(7_000),
                1_000,
            )?)
            .await?
            .expect("reclaimed processing invocation");
        assert!(second_claim.fence().token() > first_claim.fence().token());
        let second_authority = AuthenticatedProviderDeliveryClaim::new(
            delivery_id,
            second_claim.receipt(),
            second_claim.fence(),
        )?;
        let replay = command(
            ".forgejo/workflows/ci.yml",
            "refs/heads/main",
            "push",
            expected_head,
            None,
            request_digest,
            UnixMillis::new(7_500),
        );
        assert!(
            database
                .store()
                .admit_authenticated_provider_delivery(
                    replay,
                    second_authority,
                    UnixMillis::new(7_500),
                )
                .await?
                .is_replay()
        );

        for changed in [
            command(
                ".forgejo/workflows/other.yml",
                "refs/heads/main",
                "push",
                expected_head,
                None,
                request_digest,
                UnixMillis::new(7_600),
            ),
            command(
                ".forgejo/workflows/ci.yml",
                "refs/heads/main",
                "push",
                expected_head,
                None,
                Sha256Digest::from_bytes([0x54; 32]),
                UnixMillis::new(7_600),
            ),
        ] {
            database
                .store()
                .admit_authenticated_provider_delivery(
                    changed,
                    second_authority,
                    UnixMillis::new(7_600),
                )
                .await
                .expect_err("replay must retain the original workflow evidence");
        }

        let (count, original_fence): (i64, i64) = sqlx::query_as(
            "SELECT count(*), min(original_fence) FROM provider_workflow_admission_evidence WHERE delivery_id = $1",
        )
        .bind(delivery_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(count, 1);
        assert_eq!(original_fence, i64::try_from(first_claim.fence().token())?);
        assert!(
            sqlx::query(
                "UPDATE provider_workflow_admission_evidence SET workflow_path = '.forgejo/workflows/tampered.yml' WHERE delivery_id = $1",
            )
            .bind(delivery_id.as_uuid())
            .execute(database.pool())
            .await
            .is_err(),
            "provider admission evidence must be immutable",
        );
        Ok(())
    })
    .await
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
