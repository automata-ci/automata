use std::sync::Arc;

use automata_ci_core::RunnerLabel;
use automata_ci_key_management::{KeyId, LocalAes256GcmKeyring, LocalKeyMaterial, SecretBytes};
use automata_ci_postgres::test_support::{TestResult, run_with_database};
use automata_ci_provisioning::{
    ApplyGithubProviderConfigurationCommand, ApplyGithubProviderRunnerPolicyCommand,
    AuthorizedApplyGithubProviderConfiguration, AuthorizedApplyGithubProviderRunnerPolicy,
    DelegatedActorIssuer, GithubProviderConfiguration, GithubProviderConfigurationApplier as _,
    GithubProviderConfigurationRevision, GithubProviderDesiredStateReader as _,
    GithubProviderRunnerPolicyApplier as _, GithubProviderRunnerPolicyFailureKind,
    GithubProviderSchedulePolicy, GithubProviderSecret, OperationId, ProvisioningAuthority,
    ProvisioningAuthorityId, ShardId,
};
use automata_ci_provisioning_postgres::{
    PostgresGithubProviderConfigurationApplier, PostgresGithubProviderDesiredStateReader,
    PostgresGithubProviderRunnerPolicyApplier,
};
use automata_ci_store::{
    GithubCheckName, GithubServerServiceAppClientId, GithubServerServiceAppId,
    GithubServerServiceJwtIssuer,
};
use automata_ci_workflow_service::GithubRunnerPolicy;
use serde_json::Value;
use sqlx::{FromRow, PgPool};
use url::Url;

const PRIVATE_KEY: &[u8] = b"integration-test App private key";
const WEBHOOK_SECRET: &[u8] = b"integration-test webhook secret";
const RUNNER_POLICY: &[u8] = br#"{
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

fn key_provider() -> Arc<LocalAes256GcmKeyring> {
    let material = LocalKeyMaterial::new(
        KeyId::new("provider-policy-test-v1").expect("key ID"),
        SecretBytes::new(vec![0x42; 32]).expect("key bytes"),
    )
    .expect("key material");
    Arc::new(LocalAes256GcmKeyring::new(material, Vec::new(), []).expect("test keyring"))
}

fn authority() -> ProvisioningAuthority {
    ProvisioningAuthority::new(
        ProvisioningAuthorityId::new("policy-test").expect("authority ID"),
        ShardId::new("local").expect("shard ID"),
        DelegatedActorIssuer::new("https://cloud.example").expect("issuer"),
    )
}

fn policy(selector: &str) -> GithubRunnerPolicy {
    let mut value: Value = serde_json::from_slice(RUNNER_POLICY).expect("policy fixture");
    value["mappings"][0]["selector"] = Value::String(selector.to_owned());
    GithubRunnerPolicy::decode_configuration(
        &serde_json::to_vec(&value).expect("encode policy fixture"),
    )
    .expect("valid policy fixture")
}

fn configuration() -> GithubProviderConfiguration {
    GithubProviderConfiguration::new(
        Url::parse("https://ci.example/").expect("dashboard URL"),
        GithubServerServiceAppId::new(42).expect("App ID"),
        GithubServerServiceAppClientId::new("Iv1.policy-test").expect("client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        GithubProviderSecret::private_key(PRIVATE_KEY.to_vec()).expect("private key"),
        GithubProviderSecret::webhook(WEBHOOK_SECRET.to_vec()).expect("webhook secret"),
        GithubCheckName::new("Automata CI").expect("check name"),
        policy("Ubuntu-24.04"),
        GithubProviderSchedulePolicy::default(),
    )
    .expect("provider configuration")
}

#[derive(Debug, Eq, FromRow, PartialEq)]
struct CredentialEvidence {
    app_configuration_revision: i64,
    app_private_key_envelope_revision: i64,
    app_private_key_sha256: Vec<u8>,
    app_private_key_envelope_schema: i16,
    app_private_key_wrapping_key_id: String,
    app_private_key_wrapped_data_key: Vec<u8>,
    app_private_key_nonce: Vec<u8>,
    app_private_key_ciphertext: Vec<u8>,
    webhook_verifier_revision: i64,
    webhook_secret_envelope_revision: i64,
    webhook_secret_sha256: Vec<u8>,
    webhook_secret_envelope_schema: i16,
    webhook_secret_wrapping_key_id: String,
    webhook_secret_wrapped_data_key: Vec<u8>,
    webhook_secret_nonce: Vec<u8>,
    webhook_secret_ciphertext: Vec<u8>,
}

async fn credential_evidence(pool: &PgPool) -> TestResult<CredentialEvidence> {
    Ok(sqlx::query_as(
        r"
        SELECT app_configuration_revision, app_private_key_envelope_revision,
               app_private_key_sha256, app_private_key_envelope_schema,
               app_private_key_wrapping_key_id, app_private_key_wrapped_data_key,
               app_private_key_nonce, app_private_key_ciphertext,
               webhook_verifier_revision, webhook_secret_envelope_revision,
               webhook_secret_sha256, webhook_secret_envelope_schema,
               webhook_secret_wrapping_key_id, webhook_secret_wrapped_data_key,
               webhook_secret_nonce, webhook_secret_ciphertext
        FROM github_provider_configuration_current WHERE singleton=true
        ",
    )
    .fetch_one(pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires PostgreSQL configured by the integration-test harness"]
async fn runner_policy_update_retains_authenticated_provider_credentials() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool().clone();
        let keys = key_provider();
        let configuration_applier =
            PostgresGithubProviderConfigurationApplier::new(pool.clone(), keys.clone());
        let initial = ApplyGithubProviderConfigurationCommand::new(
            OperationId::parse("11111111-1111-4111-8111-111111111111")?,
            ShardId::new("local")?,
            GithubProviderConfigurationRevision::new(1)?,
            configuration(),
        );
        configuration_applier
            .apply(AuthorizedApplyGithubProviderConfiguration::authorize(
                authority(),
                initial,
            )?)
            .await?;
        let before = credential_evidence(&pool).await?;

        let operation_id = OperationId::parse("22222222-2222-4222-8222-222222222222")?;
        let update = || {
            ApplyGithubProviderRunnerPolicyCommand::new(
                operation_id,
                ShardId::new("local").expect("shard"),
                GithubProviderConfigurationRevision::new(2).expect("revision"),
                policy("macos-15"),
            )
        };
        let applier = PostgresGithubProviderRunnerPolicyApplier::new(pool.clone());
        let first = applier
            .apply(AuthorizedApplyGithubProviderRunnerPolicy::authorize(
                authority(),
                update(),
            )?)
            .await?;
        let replay = applier
            .apply(AuthorizedApplyGithubProviderRunnerPolicy::authorize(
                authority(),
                update(),
            )?)
            .await?;
        assert_eq!(first, replay);
        assert_eq!(before, credential_evidence(&pool).await?);

        let desired = PostgresGithubProviderDesiredStateReader::new(pool, keys)
            .load()
            .await?
            .expect("provider remains configured");
        assert_eq!(desired.configuration_revision().get(), 2);
        assert_eq!(desired.app_configuration_revision(), 1);
        assert_eq!(desired.webhook_verifier_revision(), 1);
        assert_eq!(desired.runner_policy_revision(), 2);
        assert_eq!(
            desired.configuration().private_key().expose_secret(),
            PRIVATE_KEY
        );
        assert_eq!(
            desired.configuration().webhook_secret().expose_secret(),
            WEBHOOK_SECRET
        );
        assert_eq!(
            desired
                .configuration()
                .runner_policy()
                .catalog()
                .get(&RunnerLabel::new("macos-15").expect("selector"))
                .expect("updated mapping")
                .selector()
                .as_str(),
            "macos-15"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL configured by the integration-test harness"]
async fn runner_policy_update_requires_an_existing_provider() -> TestResult {
    run_with_database(|database| async move {
        let command = ApplyGithubProviderRunnerPolicyCommand::new(
            OperationId::parse("33333333-3333-4333-8333-333333333333")?,
            ShardId::new("local")?,
            GithubProviderConfigurationRevision::new(1)?,
            policy("macos-15"),
        );
        let error = PostgresGithubProviderRunnerPolicyApplier::new(database.pool().clone())
            .apply(AuthorizedApplyGithubProviderRunnerPolicy::authorize(
                authority(),
                command,
            )?)
            .await
            .expect_err("an absent provider must fail closed");
        assert_eq!(
            error.kind(),
            GithubProviderRunnerPolicyFailureKind::ProviderUnavailable
        );
        Ok(())
    })
    .await
}
