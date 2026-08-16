use std::{collections::BTreeMap, fs, path::PathBuf, sync::Mutex};

use serde_json::{Value, json};

use super::*;

fn uuid(value: u128) -> String {
    let encoded = format!("{value:032x}");
    format!(
        "{}-{}-{}-{}-{}",
        &encoded[0..8],
        &encoded[8..12],
        &encoded[12..16],
        &encoded[16..20],
        &encoded[20..32]
    )
}

fn authority(id: u128, revision: u64) -> Value {
    json!({
        "authority_id": uuid(id),
        "policy_revision": revision
    })
}

fn runner_policy() -> Value {
    json!({
        "workspace": {"derivation": 1, "root": "/__w", "schema": 1},
        "mappings": [{
            "container_features": ["automata.core/job-containers@v1"],
            "architecture": "x86_64",
            "operating_system": "linux",
            "environment_profile": {
                "manifest_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
                "id": "automata.example/ubuntu-24-04"
            },
            "selector": "Ubuntu-24.04"
        }],
        "permissions": {
            "provider_default": {"contents": "read", "packages": "read"},
            "read_all": {"actions":"read","artifact-metadata":"read","attestations":"read","checks":"read","code-quality":"read","contents":"read","deployments":"read","discussions":"read","issues":"read","models":"read","packages":"read","pages":"read","pull-requests":"read","security-events":"read","statuses":"read","vulnerability-alerts":"read"},
            "write_all": {"actions":"write","artifact-metadata":"write","attestations":"write","checks":"write","code-quality":"write","contents":"write","deployments":"write","discussions":"write","id-token":"write","issues":"write","models":"read","packages":"write","pages":"write","pull-requests":"write","security-events":"write","statuses":"write","vulnerability-alerts":"read"}
        },
        "resources": resource_policy(),
        "schema": 1
    })
}

fn resource_policy() -> Value {
    json!({
        "defaults": {
            "requests": {"cpu_millis": 100, "memory_bytes": 268_435_456, "ephemeral_disk_bytes": 0, "gpu_count": 0},
            "limits": {"cpu_millis": 1000, "memory_bytes": 1_073_741_824, "ephemeral_disk_bytes": 0, "gpu_count": 0}
        },
        "minimum_requests": {"cpu_millis": 100, "memory_bytes": 268_435_456, "ephemeral_disk_bytes": 0, "gpu_count": 0},
        "maximum_limits": {"cpu_millis": 4000, "memory_bytes": 8_589_934_592_u64, "ephemeral_disk_bytes": 0, "gpu_count": 0}
    })
}

#[allow(clippy::too_many_arguments)]
fn repository(
    tenant: &str,
    connection: u128,
    installation: u64,
    repository_id: u64,
    owner_id: u64,
    name: &str,
    default_branch: &str,
    visibility: &str,
    checks_authority: u128,
    private_authority: Option<u128>,
) -> Value {
    json!({
        "tenant_id": tenant,
        "connection_id": uuid(connection),
        "installation_id": installation,
        "installation_binding_generation": 1,
        "repository_id": repository_id,
        "repository_owner_id": owner_id,
        "repository": name,
        "default_branch": default_branch,
        "visibility": visibility,
        "manifest_revision": 1,
        "policy_revision": 7,
        "runtime_policy_revision": 1,
        "authority_profile": "standard",
        "runner_policy": runner_policy(),
        "check_name": "Automata CI",
        "authorities": {
            "checks_write": authority(checks_authority, 7),
            "workflow_permissions_read": authority(checks_authority + 0x1000_0000, 7),
            "private_repository_source_read": private_authority
                .map_or(Value::Null, |id| authority(id, 7)),
            "private_pull_request_files_read": private_authority
                .map_or(Value::Null, |id| authority(id + 0x10_0000, 7))
        }
    })
}

fn mixed_document() -> Value {
    let public = repository(
        "tenant-public",
        0x201,
        202,
        302,
        402,
        "octo/public-repository",
        "refs/release",
        "public",
        0x501,
        None,
    );
    json!({
        "schema": 4,
        "transport": {"mode": "github_dot_com"},
        "dashboard_url": "https://ci.automata.example/",
        "app": {
            "id": 42,
            "client_id": "Iv1.automata-provider",
            "jwt_issuer": "app_client_id",
            "private_key_source": "env:AUTOMATA_PROVIDER_TEST_APP_KEY",
            "configuration_revision": 5
        },
        "webhook": {
            "hmac_secret_source": "env:AUTOMATA_PROVIDER_TEST_WEBHOOK_KEY",
            "verifier_revision": 11
        },
        "repositories": [
            public,
            repository(
                "tenant-private",
                0x202,
                101,
                301,
                401,
                "octo/private-repository",
                "release/stable",
                "private",
                0x502,
                Some(0x602),
            )
        ]
    })
}

fn config_file(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "automata-github-provider-bootstrap-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("temporary configuration directory");
    directory.join(name)
}

fn load_config(
    name: &str,
    document: &Value,
) -> Result<GithubProviderConfig, super::super::GithubProviderConfigError> {
    let path = config_file(name);
    fs::write(
        &path,
        serde_json::to_vec(document).expect("configuration JSON"),
    )
    .expect("write configuration");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("owner-only configuration");
    }
    GithubProviderConfig::load_test_fixture(&super::super::SecretSource::File(path))
}

fn fixed_evidence_plan(
    config: &GithubProviderConfig,
    broker_policy_byte: u8,
) -> GithubProviderBootstrapPlan {
    GithubProviderBootstrapPlan::from_derived_evidence(
        config,
        Sha256Digest::from_bytes([0x51; 32]),
        GithubProviderWebhookVerifierFingerprint::from_sha256(Sha256Digest::from_bytes([0x61; 32]))
            .expect("fixture verifier fingerprint"),
        Sha256Digest::from_bytes([broker_policy_byte; 32]),
    )
    .expect("fixed-evidence plan")
}

type RuntimePolicyKey = (TenantScope, RepositoryId, WorkflowRuntimePolicyRevision);

#[derive(Default)]
struct MemoryBootstrapTarget {
    manifests: Mutex<BTreeMap<ProviderConnectionId, GithubProviderManifest>>,
    runtime_policies: Mutex<BTreeMap<RuntimePolicyKey, RuntimePolicyBootstrap>>,
    authorities:
        Mutex<BTreeMap<GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity>>,
}

impl MemoryBootstrapTarget {
    fn insert_manifest(&self, manifest: GithubProviderManifest) {
        self.manifests
            .lock()
            .expect("manifest lock")
            .insert(manifest.connection_id(), manifest);
    }

    fn insert_runtime_policy(&self, policy: RuntimePolicyBootstrap) {
        self.runtime_policies
            .lock()
            .expect("runtime-policy lock")
            .insert(runtime_policy_key(&policy), policy);
    }

    fn insert_authority(&self, identity: GithubServerServiceAuthorityIdentity) {
        self.authorities
            .lock()
            .expect("authority lock")
            .insert(identity.authority_id(), identity);
    }
}

fn runtime_policy_key(policy: &RuntimePolicyBootstrap) -> RuntimePolicyKey {
    (policy.tenant.clone(), policy.repository_id, policy.revision)
}

#[async_trait]
impl GithubProviderBootstrapTarget for MemoryBootstrapTarget {
    async fn bootstrap_repository(
        &self,
        repository: &RepositoryBootstrap,
        _applied_at: UnixMillis,
    ) -> Result<(bool, bool), GithubProviderBootstrapError> {
        let policy = &repository.runtime_policy;
        let key = runtime_policy_key(policy);
        let mut policies = self.runtime_policies.lock().expect("runtime-policy lock");
        let mut manifests = self.manifests.lock().expect("manifest lock");
        let policy_replay = match policies.get(&key) {
            None => false,
            Some(current) if current == policy => true,
            Some(_) => return Err(GithubProviderBootstrapError::ConfigurationDrift),
        };
        let manifest_replay = match manifests.get(&repository.manifest.connection_id()) {
            None => false,
            Some(current) if current == &repository.manifest => true,
            Some(_) => return Err(GithubProviderBootstrapError::ConfigurationDrift),
        };
        if !policy_replay {
            policies.insert(key, policy.clone());
        }
        if !manifest_replay {
            manifests.insert(
                repository.manifest.connection_id(),
                repository.manifest.clone(),
            );
        }
        Ok((policy_replay, manifest_replay))
    }

    async fn inspect_authority(
        &self,
        identity: &GithubServerServiceAuthorityIdentity,
    ) -> Result<bool, GithubProviderBootstrapError> {
        let authorities = self.authorities.lock().expect("authority lock");
        match authorities.get(&identity.authority_id()) {
            None => Ok(false),
            Some(current) if current == identity => Ok(true),
            Some(_) => Err(GithubProviderBootstrapError::ConfigurationDrift),
        }
    }

    async fn ensure_authority(
        &self,
        identity: &GithubServerServiceAuthorityIdentity,
        _applied_at: UnixMillis,
    ) -> Result<bool, GithubProviderBootstrapError> {
        let mut authorities = self.authorities.lock().expect("authority lock");
        match authorities.get(&identity.authority_id()) {
            None => {
                authorities.insert(identity.authority_id(), identity.clone());
                Ok(false)
            }
            Some(current) if current == identity => Ok(true),
            Some(_) => Err(GithubProviderBootstrapError::ConfigurationDrift),
        }
    }
}

#[test]
fn mixed_public_private_projection_has_exact_visibility_dependent_shape() {
    let config = load_config("mixed-shape.json", &mixed_document()).expect("mixed config");
    let plan = fixed_evidence_plan(&config, 0x70);

    assert_eq!(plan.manifests().len(), 2);
    assert_eq!(plan.authorities().len(), 6);
    assert_eq!(plan.connections().len(), 2);
    assert!(
        plan.manifests()
            .iter()
            .all(|manifest| manifest.installation_binding_generation().get() == 1)
    );
    assert_eq!(plan.manifests()[1].workflow_path(), ".ci/workflows");
    assert_eq!(plan.manifests()[0].git_ref(), "refs/heads/release/stable");
    assert_eq!(plan.manifests()[1].git_ref(), "refs/heads/refs/release");
    assert_eq!(
        plan.manifests()[0].repository_visibility(),
        ProviderRepositoryVisibility::Private
    );
    assert_eq!(
        plan.manifests()[1].repository_visibility(),
        ProviderRepositoryVisibility::Public
    );
    assert_eq!(plan.connections()[0].repository_owner(), "octo");
    assert_eq!(
        plan.connections()[0].repository_name(),
        "private-repository"
    );
    assert_eq!(plan.connections()[1].repository_name(), "public-repository");
    assert_eq!(
        plan.connections()[1].default_branch_ref(),
        Some("refs/heads/refs/release")
    );

    let ordered_authorities = plan
        .authorities()
        .iter()
        .map(|identity| (identity.installation_id().get(), identity.scope()))
        .collect::<Vec<_>>();
    assert_eq!(
        ordered_authorities,
        [
            (101, GithubServerServiceScope::ChecksWrite),
            (101, GithubServerServiceScope::WorkflowPermissionsRead),
            (101, GithubServerServiceScope::PrivateRepositorySourceRead),
            (101, GithubServerServiceScope::PrivatePullRequestFilesRead),
            (202, GithubServerServiceScope::ChecksWrite),
            (202, GithubServerServiceScope::WorkflowPermissionsRead),
        ]
    );

    let public_connection = plan.manifests()[1].connection_id();
    let public_authorities = plan
        .authorities()
        .iter()
        .filter(|identity| identity.connection_id() == public_connection)
        .collect::<Vec<_>>();
    assert_eq!(public_authorities.len(), 2);
    assert_eq!(
        public_authorities[0].scope(),
        GithubServerServiceScope::ChecksWrite
    );
    assert_eq!(
        public_authorities[1].scope(),
        GithubServerServiceScope::WorkflowPermissionsRead
    );
    assert!(plan.authorities().iter().any(|identity| {
        identity.scope() == GithubServerServiceScope::PrivateRepositorySourceRead
            && identity.connection_id() == plan.manifests()[0].connection_id()
    }));
    assert!(plan.authorities().iter().any(|identity| {
        identity.scope() == GithubServerServiceScope::PrivatePullRequestFilesRead
            && identity.connection_id() == plan.manifests()[0].connection_id()
    }));

    let checks_fingerprints = plan
        .authorities()
        .iter()
        .filter(|identity| identity.scope() == GithubServerServiceScope::ChecksWrite)
        .map(GithubServerServiceAuthorityIdentity::configuration_fingerprint)
        .collect::<Vec<_>>();
    assert_eq!(checks_fingerprints[0], checks_fingerprints[1]);
    let private_fingerprint = plan
        .authorities()
        .iter()
        .find(|identity| identity.scope() == GithubServerServiceScope::PrivateRepositorySourceRead)
        .expect("private authority")
        .configuration_fingerprint();
    assert_ne!(checks_fingerprints[0], private_fingerprint);
    let pull_request_files_fingerprint = plan
        .authorities()
        .iter()
        .find(|identity| identity.scope() == GithubServerServiceScope::PrivatePullRequestFilesRead)
        .expect("private pull-request-files authority")
        .configuration_fingerprint();
    assert_ne!(private_fingerprint, pull_request_files_fingerprint);
}

#[test]
fn configured_installation_generation_reaches_manifest_and_delivery_connection() {
    let mut document = mixed_document();
    document["repositories"][0]["installation_id"] = json!(303);
    document["repositories"][0]["installation_binding_generation"] = json!(2);
    document["repositories"][0]["manifest_revision"] = json!(2);
    let config = load_config("installation-generation.json", &document)
        .expect("rotated installation configuration");
    let plan = fixed_evidence_plan(&config, 0x70);
    let manifest = plan
        .manifests()
        .iter()
        .find(|manifest| manifest.installation_id().get() == 303)
        .expect("rotated manifest");
    assert_eq!(manifest.installation_binding_generation().get(), 2);
    assert!(plan.connections().iter().any(|connection| {
        connection.installation_id().get() == 303
            && connection.repository_id() == manifest.github_repository_id()
    }));
}

#[tokio::test]
async fn exact_bootstrap_replays_and_only_then_exposes_the_resolver() {
    let config = load_config("exact-replay.json", &mixed_document()).expect("mixed config");
    let plan = fixed_evidence_plan(&config, 0x71);
    let target = MemoryBootstrapTarget::default();

    let first = plan
        .bootstrap_with_target(&target, UnixMillis::new(1_000))
        .await
        .expect("first bootstrap");
    assert_eq!(first.manifest_count(), 2);
    assert_eq!(first.manifest_replay_count(), 0);
    assert_eq!(first.runtime_policy_count(), 2);
    assert_eq!(first.runtime_policy_replay_count(), 0);
    assert_eq!(first.authority_count(), 6);
    assert_eq!(first.authority_replay_count(), 0);

    let replay = plan
        .bootstrap_with_target(&target, UnixMillis::new(2_000))
        .await
        .expect("exact replay");
    assert_eq!(replay.manifest_replay_count(), 2);
    assert_eq!(replay.runtime_policy_count(), 2);
    assert_eq!(replay.runtime_policy_replay_count(), 2);
    assert_eq!(replay.authority_replay_count(), 6);
    let resolver = replay.credential_request_resolver();
    assert_eq!(resolver.len(), 6);
    for identity in plan.authorities() {
        let resolution = resolver
            .resolve_github_server_service_credential_request(identity)
            .await
            .expect("in-memory resolution")
            .expect("configured identity");
        assert_eq!(resolution.identity(), identity);
        assert_eq!(
            resolution.request(),
            &github_server_service_credential_request(identity).expect("canonical request")
        );
    }
}

#[tokio::test]
async fn runtime_policy_drift_fails_before_manifest_or_authority_writes() {
    const DRIFTED_POLICY: &[u8] = br#"{
      "workspace":{"derivation":1,"root":"/__w","schema":1},
      "mappings":[{
        "container_features":["automata.core/job-containers@v1"],
        "architecture":"x86_64","operating_system":"linux",
        "environment_profile":{"manifest_sha256":"2222222222222222222222222222222222222222222222222222222222222222","id":"automata.example/ubuntu-24-04"},
        "selector":"Ubuntu-24.04"
      }],"permissions":{"provider_default":{"contents":"read","packages":"read"},"read_all":{"actions":"read","artifact-metadata":"read","attestations":"read","checks":"read","code-quality":"read","contents":"read","deployments":"read","discussions":"read","issues":"read","models":"read","packages":"read","pages":"read","pull-requests":"read","security-events":"read","statuses":"read","vulnerability-alerts":"read"},"write_all":{"actions":"write","artifact-metadata":"write","attestations":"write","checks":"write","code-quality":"write","contents":"write","deployments":"write","discussions":"write","id-token":"write","issues":"write","models":"read","packages":"write","pages":"write","pull-requests":"write","security-events":"write","statuses":"write","vulnerability-alerts":"read"}},"resources":{"defaults":{"requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"limits":{"cpu_millis":1000,"memory_bytes":1073741824,"ephemeral_disk_bytes":0,"gpu_count":0}},"minimum_requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"maximum_limits":{"cpu_millis":4000,"memory_bytes":8589934592,"ephemeral_disk_bytes":0,"gpu_count":0}},"schema":1
    }"#;

    let config = load_config("runtime-policy-drift.json", &mixed_document()).expect("mixed config");
    let plan = fixed_evidence_plan(&config, 0x72);
    let mut drifted = plan.repositories[0].runtime_policy.clone();
    drifted.policy =
        WorkflowRuntimePolicy::decode_configuration(DRIFTED_POLICY).expect("drifted policy");
    let target = MemoryBootstrapTarget::default();
    target.insert_runtime_policy(drifted);

    assert!(matches!(
        plan.bootstrap_with_target(&target, UnixMillis::new(3_000))
            .await,
        Err(GithubProviderBootstrapError::ConfigurationDrift)
    ));
    assert!(target.manifests.lock().expect("manifest lock").is_empty());
    assert!(
        target
            .authorities
            .lock()
            .expect("authority lock")
            .is_empty()
    );
}

#[tokio::test]
async fn configuration_fingerprint_drift_is_not_resolved_or_declared_ready() {
    let config = load_config("resolver-drift.json", &mixed_document()).expect("mixed config");
    let plan = fixed_evidence_plan(&config, 0x72);
    let drifted = fixed_evidence_plan(&config, 0x73);
    let target = MemoryBootstrapTarget::default();
    let ready = plan
        .bootstrap_with_target(&target, UnixMillis::new(3_000))
        .await
        .expect("initial bootstrap");
    let resolver = ready.credential_request_resolver();

    assert!(
        resolver
            .resolve_github_server_service_credential_request(&drifted.authorities()[0])
            .await
            .expect("exact in-memory lookup")
            .is_none()
    );

    let authority_drift = MemoryBootstrapTarget::default();
    authority_drift.insert_authority(drifted.authorities()[0].clone());
    assert!(matches!(
        plan.bootstrap_with_target(&authority_drift, UnixMillis::new(4_000))
            .await,
        Err(GithubProviderBootstrapError::ConfigurationDrift)
    ));
    assert!(
        authority_drift
            .manifests
            .lock()
            .expect("manifest lock")
            .is_empty(),
        "authority preflight must fail before manifest convergence"
    );
}

#[tokio::test]
async fn duplicate_config_and_durable_manifest_selector_drift_fail_closed() {
    let mut duplicate = mixed_document();
    duplicate["repositories"][1]["installation_id"] =
        duplicate["repositories"][0]["installation_id"].clone();
    duplicate["repositories"][1]["repository_id"] =
        duplicate["repositories"][0]["repository_id"].clone();
    assert_eq!(
        load_config("duplicate-selector.json", &duplicate),
        Err(super::super::GithubProviderConfigError)
    );

    let config =
        load_config("manifest-selector-base.json", &mixed_document()).expect("base configuration");
    let plan = fixed_evidence_plan(&config, 0x74);
    let mut changed_document = mixed_document();
    changed_document["repositories"][1]["check_name"] = json!("Changed Check");
    let changed_config = load_config("manifest-selector-changed.json", &changed_document)
        .expect("changed configuration");
    let changed_plan = fixed_evidence_plan(&changed_config, 0x74);
    let target = MemoryBootstrapTarget::default();
    target.insert_manifest(changed_plan.manifests()[0].clone());

    assert!(matches!(
        plan.bootstrap_with_target(&target, UnixMillis::new(5_000))
            .await,
        Err(GithubProviderBootstrapError::ConfigurationDrift)
    ));
    assert!(
        target
            .runtime_policies
            .lock()
            .expect("runtime-policy lock")
            .is_empty(),
        "manifest drift must not partially register its runtime policy"
    );
}

fn database_desired_state(
    configuration_revision: u64,
    workspace_revision: u64,
) -> automata_ci_provisioning::GithubProviderDesiredState {
    use automata_ci_core::JobAuthorityProfile;
    use automata_ci_provisioning::{
        GithubProviderConfiguration, GithubProviderConfigurationRevision,
        GithubProviderRepositorySelection, GithubProviderSchedulePolicy, GithubProviderSecret,
        ShardId, WorkspaceGithubRepositoriesDesiredState, WorkspaceGithubRepositoriesRevision,
        WorkspaceId,
    };
    use automata_ci_store::{
        GithubCheckName, GithubRepositoryName, GithubServerServiceAppClientId,
        GithubServerServiceAppId, GithubServerServiceJwtIssuer, ProviderInstallationId,
        ProviderRepositoryId, ProviderRepositoryOwnerId, ProviderRepositoryVisibility,
    };
    use automata_ci_workflow_service::GithubRunnerPolicy;
    use url::Url;

    let policy = serde_json::to_vec(&runner_policy()).expect("runner policy JSON");
    let configuration = GithubProviderConfiguration::new(
        Url::parse("https://ci.automata.example/").expect("dashboard URL"),
        GithubServerServiceAppId::new(42).expect("App ID"),
        GithubServerServiceAppClientId::new("Iv1.automata-provider").expect("client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        GithubProviderSecret::private_key(b"database-app-key".to_vec()).expect("App key"),
        GithubProviderSecret::webhook(b"database-webhook-secret".to_vec()).expect("webhook secret"),
        GithubCheckName::new("Automata CI").expect("Check name"),
        GithubRunnerPolicy::decode_configuration(&policy).expect("runner policy"),
        GithubProviderSchedulePolicy::default(),
    )
    .expect("provider configuration");
    let workspace_id =
        WorkspaceId::parse("11111111-1111-4111-8111-111111111111").expect("workspace ID");
    let repository = GithubProviderRepositorySelection::new(
        ProviderInstallationId::new(101).expect("installation ID"),
        ProviderRepositoryId::new(301).expect("repository ID"),
        ProviderRepositoryOwnerId::new(401).expect("owner ID"),
        GithubRepositoryName::new("octo/database-repository").expect("repository name"),
        "main",
        ProviderRepositoryVisibility::Public,
        JobAuthorityProfile::CredentialFree,
    )
    .expect("repository selection");
    automata_ci_provisioning::GithubProviderDesiredState::new(
        ShardId::new("prod-us-east-1-001").expect("shard ID"),
        GithubProviderConfigurationRevision::new(configuration_revision)
            .expect("configuration revision"),
        3,
        4,
        configuration,
        vec![
            WorkspaceGithubRepositoriesDesiredState::new(
                workspace_id,
                WorkspaceGithubRepositoriesRevision::new(workspace_revision)
                    .expect("workspace revision"),
                vec![repository],
            )
            .expect("workspace desired state"),
        ],
    )
    .expect("provider desired state")
}

#[test]
fn database_desired_state_derives_stable_runtime_identities_and_revisions() {
    let first = GithubProviderConfig::from_desired_state(database_desired_state(5, 5))
        .expect("database projection");
    let second = GithubProviderConfig::from_desired_state(database_desired_state(5, 5))
        .expect("stable database projection");
    let first_repository = &first.config().repositories()[0];
    let second_repository = &second.config().repositories()[0];

    assert_eq!(
        first_repository.tenant().as_str(),
        "11111111-1111-4111-8111-111111111111"
    );
    assert_eq!(first_repository.manifest_revision().get(), 5);
    assert_eq!(first_repository.policy_revision().get(), 5);
    assert_eq!(first_repository.runtime_policy_revision().get(), 5);
    assert_eq!(
        first_repository.connection_id(),
        second_repository.connection_id()
    );
    assert_eq!(
        first_repository.checks_write_authority().authority_id(),
        second_repository.checks_write_authority().authority_id()
    );
    assert_ne!(
        first_repository.checks_write_authority().authority_id(),
        first_repository
            .workflow_permissions_authority()
            .authority_id()
    );
    let debug = format!("{first:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("database-app-key"));
    assert!(!debug.contains("database-webhook-secret"));
}

#[test]
fn database_desired_state_rejects_mixed_runtime_generations() {
    assert!(GithubProviderConfig::from_desired_state(database_desired_state(5, 4)).is_err());
}
