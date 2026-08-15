use std::sync::Arc;

use automata_ci_core::JobAuthorityProfile;
use automata_ci_key_management::KeyEncryptionProvider;
use automata_ci_postgres::provisioning::{
    PostgresGithubProviderConfigurationApplier, PostgresGithubProviderDesiredStateReader,
    PostgresWorkspaceGithubRepositoriesApplier, PostgresWorkspaceProvisioner,
};
use automata_ci_provisioning::{
    ApplyGithubProviderConfigurationCommand, ApplyWorkspaceGithubRepositoriesCommand,
    AuthorizedApplyGithubProviderConfiguration, AuthorizedApplyWorkspaceGithubRepositories,
    AuthorizedProvisionWorkspace, DelegatedActorIssuer, DisplayName, ExternalAccountSubject,
    GithubProviderConfiguration, GithubProviderConfigurationApplier,
    GithubProviderConfigurationFailureKind, GithubProviderConfigurationRevision,
    GithubProviderDesiredStateFailureKind, GithubProviderDesiredStateReader,
    GithubProviderRepositorySelection, GithubProviderSchedulePolicy, GithubProviderSecret,
    OperationId, ProvisionWorkspaceCommand, ProvisioningAuthority, ProvisioningAuthorityId,
    ShardId, WorkspaceGithubRepositoriesApplier, WorkspaceGithubRepositoriesFailureKind,
    WorkspaceGithubRepositoriesRevision, WorkspaceId, WorkspaceProvisioner,
};
use automata_ci_store::{
    GithubCheckName, GithubRepositoryName, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceJwtIssuer, ProviderInstallationId,
    ProviderRepositoryId, ProviderRepositoryOwnerId, ProviderRepositoryVisibility,
};
use automata_ci_workflow_service::GithubRunnerPolicy;
use url::Url;
use uuid::Uuid;

use crate::support::{TestResult, run_with_database, test_runner_payload_key_provider};

const AUTHORITY: &str = "automata-cloud-production";
const ISSUER: &str = "https://cloud.automata.example";
const SHARD: &str = "prod-us-east-1-001";
const PRIVATE_KEY: &[u8] = b"test GitHub App private key material";
const WEBHOOK_SECRET: &[u8] = b"test GitHub webhook secret";
const RUNNER_POLICY: &[u8] = br#"{
  "workspace":{"derivation":1,"root":"/__w","schema":1},
  "mappings":[{"container_features":["automata.core/job-containers@v1"],"architecture":"x86_64","operating_system":"linux","environment_profile":{"manifest_sha256":"1111111111111111111111111111111111111111111111111111111111111111","id":"automata.example/ubuntu-24-04"},"selector":"Ubuntu-24.04"}],
  "permissions":{"provider_default":{"contents":"read","packages":"read"},"read_all":{"actions":"read","artifact-metadata":"read","attestations":"read","checks":"read","code-quality":"read","contents":"read","deployments":"read","discussions":"read","issues":"read","models":"read","packages":"read","pages":"read","pull-requests":"read","security-events":"read","statuses":"read","vulnerability-alerts":"read"},"write_all":{"actions":"write","artifact-metadata":"write","attestations":"write","checks":"write","code-quality":"write","contents":"write","deployments":"write","discussions":"write","id-token":"write","issues":"write","models":"read","packages":"write","pages":"write","pull-requests":"write","security-events":"write","statuses":"write","vulnerability-alerts":"read"}},
  "resources":{"defaults":{"requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"limits":{"cpu_millis":1000,"memory_bytes":1073741824,"ephemeral_disk_bytes":0,"gpu_count":0}},"minimum_requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"maximum_limits":{"cpu_millis":4000,"memory_bytes":8589934592,"ephemeral_disk_bytes":0,"gpu_count":0}},
  "schema":1
}"#;

#[derive(sqlx::FromRow)]
struct StoredProviderRevision {
    revision: i64,
    app_configuration_revision: i64,
    app_private_key_ciphertext: Vec<u8>,
    webhook_secret_ciphertext: Vec<u8>,
    app_private_key_sha256: Vec<u8>,
}

fn authority(authority_id: &str) -> ProvisioningAuthority {
    ProvisioningAuthority::new(
        ProvisioningAuthorityId::new(authority_id).expect("authority"),
        ShardId::new(SHARD).expect("shard"),
        DelegatedActorIssuer::new(ISSUER).expect("issuer"),
    )
}

fn provider_request(
    operation_id: Uuid,
    revision: u64,
    private_key: &[u8],
) -> AuthorizedApplyGithubProviderConfiguration {
    let configuration = GithubProviderConfiguration::new(
        Url::parse("https://cloud.automata.example/").expect("dashboard URL"),
        GithubServerServiceAppId::new(42).expect("App ID"),
        GithubServerServiceAppClientId::new("Iv1.automata-provider").expect("client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        GithubProviderSecret::private_key(private_key.to_vec()).expect("private key"),
        GithubProviderSecret::webhook(WEBHOOK_SECRET.to_vec()).expect("webhook secret"),
        GithubCheckName::new("Automata CI").expect("check name"),
        GithubRunnerPolicy::decode_configuration(RUNNER_POLICY).expect("runner policy"),
        GithubProviderSchedulePolicy::default(),
    )
    .expect("provider configuration");
    let command = ApplyGithubProviderConfigurationCommand::new(
        OperationId::from_uuid(operation_id).expect("operation ID"),
        ShardId::new(SHARD).expect("shard"),
        GithubProviderConfigurationRevision::new(revision).expect("revision"),
        configuration,
    );
    AuthorizedApplyGithubProviderConfiguration::authorize(authority(AUTHORITY), command)
        .expect("authorized provider configuration")
}

fn workspace_provisioning(workspace_id: Uuid) -> AuthorizedProvisionWorkspace {
    AuthorizedProvisionWorkspace::authorize(
        authority(AUTHORITY),
        ProvisionWorkspaceCommand::new(
            OperationId::from_uuid(Uuid::new_v4()).expect("operation ID"),
            ShardId::new(SHARD).expect("shard"),
            WorkspaceId::from_uuid(workspace_id).expect("workspace ID"),
            DisplayName::new("Acme Engineering").expect("workspace name"),
            DelegatedActorIssuer::new(ISSUER).expect("issuer"),
            ExternalAccountSubject::from_uuid(Uuid::new_v4()).expect("subject"),
            DisplayName::new("The Octocat").expect("owner name"),
        ),
    )
    .expect("authorized provisioning")
}

fn selected_repository(id: u64, name: &str) -> GithubProviderRepositorySelection {
    GithubProviderRepositorySelection::new(
        ProviderInstallationId::new(100).expect("installation"),
        ProviderRepositoryId::new(id).expect("repository ID"),
        ProviderRepositoryOwnerId::new(200).expect("owner ID"),
        GithubRepositoryName::new(name).expect("repository name"),
        "main",
        ProviderRepositoryVisibility::Public,
        JobAuthorityProfile::CredentialFree,
    )
    .expect("repository selection")
}

fn workspace_request(
    authority_id: &str,
    operation_id: Uuid,
    workspace_id: Uuid,
    revision: u64,
    repositories: Vec<GithubProviderRepositorySelection>,
) -> AuthorizedApplyWorkspaceGithubRepositories {
    let command = ApplyWorkspaceGithubRepositoriesCommand::new(
        OperationId::from_uuid(operation_id).expect("operation ID"),
        ShardId::new(SHARD).expect("shard"),
        WorkspaceId::from_uuid(workspace_id).expect("workspace ID"),
        WorkspaceGithubRepositoriesRevision::new(revision).expect("revision"),
        repositories,
    )
    .expect("workspace desired set");
    AuthorizedApplyWorkspaceGithubRepositories::authorize(authority(authority_id), command)
        .expect("authorized workspace desired set")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn provider_credentials_are_encrypted_and_revisions_are_idempotent() -> TestResult {
    run_with_database(|database| async move {
        let key_provider: Arc<dyn KeyEncryptionProvider> = test_runner_payload_key_provider();
        let reader = PostgresGithubProviderDesiredStateReader::new(
            database.pool().clone(),
            Arc::clone(&key_provider),
        );
        assert!(reader.load().await?.is_none());
        let applier =
            PostgresGithubProviderConfigurationApplier::new(database.pool().clone(), key_provider);
        let operation_id = Uuid::new_v4();
        let first = applier
            .apply(provider_request(operation_id, 1, PRIVATE_KEY))
            .await?;
        let replay = applier
            .apply(provider_request(operation_id, 1, PRIVATE_KEY))
            .await?;
        assert_eq!(replay, first);

        let conflict = applier
            .apply(provider_request(operation_id, 1, b"changed private key"))
            .await
            .expect_err("operation semantic drift must conflict");
        assert_eq!(
            conflict.kind(),
            GithubProviderConfigurationFailureKind::OperationConflict
        );
        let stale = applier
            .apply(provider_request(Uuid::new_v4(), 1, PRIVATE_KEY))
            .await
            .expect_err("another operation cannot reuse the current revision");
        assert_eq!(
            stale.kind(),
            GithubProviderConfigurationFailureKind::StaleRevision
        );
        applier
            .apply(provider_request(Uuid::new_v4(), 3, b"rotated private key"))
            .await?;

        let rows: Vec<StoredProviderRevision> = sqlx::query_as(
            r"
            SELECT revision, app_configuration_revision,
                   app_private_key_ciphertext, webhook_secret_ciphertext,
                   app_private_key_sha256
            FROM github_provider_configuration_revisions ORDER BY revision
            ",
        )
        .fetch_all(database.pool())
        .await?;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].revision, 1);
        assert_eq!(rows[0].app_configuration_revision, 1);
        assert_eq!(rows[1].revision, 3);
        assert_eq!(rows[1].app_configuration_revision, 2);
        assert_ne!(rows[0].app_private_key_ciphertext.as_slice(), PRIVATE_KEY);
        assert_ne!(rows[0].webhook_secret_ciphertext.as_slice(), WEBHOOK_SECRET);
        assert_eq!(rows[0].app_private_key_sha256.len(), 32);

        let desired = reader.load().await?.expect("provider desired state");
        assert_eq!(desired.shard_id().as_str(), SHARD);
        assert_eq!(desired.configuration_revision().get(), 3);
        assert_eq!(desired.app_configuration_revision(), 2);
        assert_eq!(desired.webhook_verifier_revision(), 1);
        assert_eq!(
            desired.configuration().private_key().expose_secret(),
            b"rotated private key"
        );
        assert_eq!(
            desired.configuration().webhook_secret().expose_secret(),
            WEBHOOK_SECRET
        );
        assert!(desired.workspaces().is_empty());

        sqlx::query(
            r"
            UPDATE github_provider_configuration_revisions
            SET webhook_secret_ciphertext=set_byte(
                webhook_secret_ciphertext,
                0,
                get_byte(webhook_secret_ciphertext, 0) # 1
            )
            WHERE revision=3
            ",
        )
        .execute(database.pool())
        .await?;
        let corrupt = reader
            .load()
            .await
            .expect_err("tampered provider credentials must fail closed");
        assert_eq!(
            corrupt.kind(),
            GithubProviderDesiredStateFailureKind::CorruptState
        );
        Ok(())
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(
    clippy::too_many_lines,
    reason = "one live schema proves replacement, replay, and authority boundaries"
)]
async fn workspace_repository_omission_is_an_authoritative_revision() -> TestResult {
    run_with_database(|database| async move {
        let key_provider: Arc<dyn KeyEncryptionProvider> = test_runner_payload_key_provider();
        PostgresGithubProviderConfigurationApplier::new(
            database.pool().clone(),
            Arc::clone(&key_provider),
        )
        .apply(provider_request(Uuid::new_v4(), 1, PRIVATE_KEY))
        .await?;
        let workspace_id = Uuid::new_v4();
        PostgresWorkspaceProvisioner::new(database.pool().clone())
            .provision(workspace_provisioning(workspace_id))
            .await?;
        let applier = PostgresWorkspaceGithubRepositoriesApplier::new(database.pool().clone());
        let operation_id = Uuid::new_v4();
        let selected = vec![
            selected_repository(301, "octo/one"),
            selected_repository(302, "octo/two"),
        ];
        let first = applier
            .apply(workspace_request(
                AUTHORITY,
                operation_id,
                workspace_id,
                1,
                selected.clone(),
            ))
            .await?;
        let reader =
            PostgresGithubProviderDesiredStateReader::new(database.pool().clone(), key_provider);
        let desired = reader.load().await?.expect("provider desired state");
        assert_eq!(desired.workspaces().len(), 1);
        assert_eq!(
            desired.workspaces()[0].workspace_id().as_uuid(),
            workspace_id
        );
        assert_eq!(desired.workspaces()[0].revision().get(), 1);
        assert_eq!(desired.workspaces()[0].repositories().len(), 2);
        let replay = applier
            .apply(workspace_request(
                AUTHORITY,
                operation_id,
                workspace_id,
                1,
                selected,
            ))
            .await?;
        assert_eq!(replay, first);

        let foreign = applier
            .apply(workspace_request(
                "other-authority",
                Uuid::new_v4(),
                workspace_id,
                2,
                Vec::new(),
            ))
            .await
            .expect_err("foreign authority must not replace workspace state");
        assert_eq!(
            foreign.kind(),
            WorkspaceGithubRepositoriesFailureKind::WorkspaceUnavailable
        );
        applier
            .apply(workspace_request(
                AUTHORITY,
                Uuid::new_v4(),
                workspace_id,
                2,
                Vec::new(),
            ))
            .await?;

        let workspace_text = workspace_id.hyphenated().to_string();
        let current_count: i64 = sqlx::query_scalar(
            r"
            SELECT count(*) FROM workspace_github_repository_selections AS selection
            JOIN workspace_github_repository_heads AS head
              ON head.workspace_id=selection.workspace_id
             AND head.revision=selection.revision
            WHERE head.workspace_id=$1
            ",
        )
        .bind(&workspace_text)
        .fetch_one(database.pool())
        .await?;
        let historical_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM workspace_github_repository_selections WHERE workspace_id=$1",
        )
        .bind(&workspace_text)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            current_count, 0,
            "empty revision disconnects every repository"
        );
        assert_eq!(
            historical_count, 2,
            "prior desired evidence remains immutable"
        );
        let desired = reader.load().await?.expect("provider desired state");
        assert!(desired.workspaces()[0].repositories().is_empty());
        assert_eq!(desired.workspaces()[0].revision().get(), 2);
        Ok(())
    })
    .await
}
