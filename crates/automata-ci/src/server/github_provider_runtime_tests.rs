use std::{
    collections::VecDeque,
    fs,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use automata_ci_core::{
    AttemptId, FencingToken, JobId, JobIrVersion, LeaseId, RunId, RunnerId, RunnerSessionId,
};
use automata_ci_credential_github::{
    GithubInstallationTokenRevocationCandidate, GithubInstallationTokenRevocationFailureKind,
    GithubInstallationTokenRevocationOutcome,
};
use automata_ci_store::{
    GithubRepositoryId, GithubRuntimeAuthorityActivationSelectionTail,
    GithubRuntimeAuthorityIdentity, GithubRuntimeAuthorityMaterializationSelectionTail,
    GithubRuntimeAuthorityNamespace, GithubRuntimeAuthorityPreparationSelectionTail,
    GithubServerServiceAuthorityIdentity, LogicalActivationGeneration,
    LogicalActivationPreparationGeneration, LogicalActivationWorkerId,
    LogicalMaterializationGeneration, LogicalMaterializationWorkerId, LogicalWorkSelectionId,
    RunnerGeneration, SessionEpoch, StableRunnerSlot,
};
use serde_json::{Value, json};
use url::Url;

use super::*;

static CONFIG_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

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

fn authority(id: u128) -> Value {
    json!({
        "authority_id": uuid(id),
        "policy_revision": 7
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
        "default_branch": "main",
        "visibility": visibility,
        "manifest_revision": 1,
        "policy_revision": 7,
        "runtime_policy_revision": 1,
        "authority_profile": "standard",
        "runner_policy": {
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
                "provider_default": {"contents": "read"},
                "read_all": {"contents": "read"},
                "write_all": {"contents": "write"}
            },
            "resources": {
                "defaults": {
                    "requests": {"cpu_millis": 100, "memory_bytes": 268_435_456, "ephemeral_disk_bytes": 0, "gpu_count": 0},
                    "limits": {"cpu_millis": 1000, "memory_bytes": 1_073_741_824, "ephemeral_disk_bytes": 0, "gpu_count": 0}
                },
                "minimum_requests": {"cpu_millis": 100, "memory_bytes": 268_435_456, "ephemeral_disk_bytes": 0, "gpu_count": 0},
                "maximum_limits": {"cpu_millis": 4000, "memory_bytes": 8_589_934_592_u64, "ephemeral_disk_bytes": 0, "gpu_count": 0}
            },
            "schema": 1
        },
        "check_name": "Automata CI",
        "authorities": {
            "checks_write": authority(checks_authority),
            "private_repository_source_read": private_authority
                .map_or(Value::Null, authority)
        }
    })
}

fn document(repositories: &[Value]) -> Value {
    json!({
        "schema": 2,
        "transport": {"mode": "github_dot_com"},
        "dashboard_url": "https://ci.automata.example/",
        "app": {
            "id": 42,
            "client_id": "Iv1.automata-provider-runtime",
            "jwt_issuer": "app_client_id",
            "private_key_source": "env:AUTOMATA_PROVIDER_RUNTIME_TEST_APP_KEY",
            "configuration_revision": 5
        },
        "webhook": {
            "hmac_secret_source": "env:AUTOMATA_PROVIDER_RUNTIME_TEST_WEBHOOK_KEY",
            "verifier_revision": 11
        },
        "repositories": repositories
    })
}

#[test]
fn loopback_transport_builds_one_exact_emulator_origin() {
    let api_base =
        Url::parse("http://automata-git.localhost:18088/api/v3/").expect("emulator API base");
    let job_runtime_origin =
        Url::parse("http://automata-git.invalid:18088/").expect("job runtime origin");
    let transport = GithubProviderTransport::LoopbackEmulator {
        api_base: api_base.clone(),
        job_runtime_origin: job_runtime_origin.clone(),
    };

    let endpoint = provider_http_endpoint(&transport).expect("provider HTTP endpoint");
    assert_eq!(endpoint.trusted_origins().api_base(), &api_base);
    assert_eq!(
        endpoint.trusted_origins().oauth_origin().as_str(),
        "http://automata-git.localhost:18088/"
    );
    let credential = provider_credential_config(
        &transport,
        GithubAppIssuer::new("Iv1.isolated-emulator").expect("issuer"),
        GithubInstallationId::new(10).expect("installation"),
    );
    assert!(credential.is_ok());
    let authority =
        provider_runtime_authority_endpoint(&transport).expect("provider authority endpoint");
    assert_eq!(authority.as_url(), &job_runtime_origin);
    assert_eq!(
        authority.security(),
        automata_ci_protocol::RuntimeAuthorityEndpointSecurity::TrustedPrivateDevelopment
    );
}

fn config_file() -> PathBuf {
    let sequence = CONFIG_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "automata-github-provider-runtime-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("temporary configuration directory");
    directory.join("provider.json")
}

fn load_config(document: &Value) -> GithubProviderConfig {
    let path = config_file();
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
    GithubProviderConfig::load(&super::super::SecretSource::File(path))
        .expect("valid provider configuration")
}

fn set_repository_revisions(repository: &mut Value, manifest: u64, policy: u64) {
    repository["manifest_revision"] = json!(manifest);
    repository["policy_revision"] = json!(policy);
    repository["authorities"]["checks_write"]["policy_revision"] = json!(policy);
}

fn live_test_broker(
    config: &GithubProviderConfig,
    installation_id: u64,
) -> Arc<GithubAppCredentialBroker> {
    const PKCS8_DER: &[u8] = include_bytes!(
        "../../../automata-ci-credential-github/tests/fixtures/rsa2048-test-key.pkcs8.der"
    );

    let pem = pem_rfc7468::encode_string("PRIVATE KEY", pem_rfc7468::LineEnding::LF, PKCS8_DER)
        .expect("published RSA fixture encodes as PEM");
    let private_key = SecretString::new(pem).expect("published RSA fixture is nonempty");
    let broker_config = GithubAppCredentialConfig::github_dot_com(
        github_app_issuer(config).expect("validated App issuer"),
        GithubInstallationId::new(installation_id).expect("installation"),
        GITHUB_HTTP_USER_AGENT,
    )
    .expect("GitHub.com broker configuration");
    Arc::new(
        GithubAppCredentialBroker::new(broker_config, &private_key)
            .expect("published RSA fixture constructs a live broker"),
    )
}

fn checks_authority(
    plan: &GithubProviderBootstrapPlan,
    repository_id: u64,
) -> GithubServerServiceAuthorityIdentity {
    plan.authorities()
        .iter()
        .find(|authority| {
            authority.scope() == GithubServerServiceScope::ChecksWrite
                && authority.github_repository_id().get() == repository_id
        })
        .cloned()
        .expect("checks authority for configured repository")
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimeRouteEvidence {
    github_app_id: GithubServerServiceAppId,
    github_app_client_id: GithubServerServiceAppClientId,
    github_app_jwt_issuer_kind: GithubServerServiceJwtIssuer,
    app_key_spki_sha256: Sha256Digest,
    configuration_fingerprint: Sha256Digest,
}

impl RuntimeRouteEvidence {
    fn from_authority(authority: &GithubServerServiceAuthorityIdentity) -> Self {
        Self {
            github_app_id: authority.github_app_id(),
            github_app_client_id: authority.app_client_id().clone(),
            github_app_jwt_issuer_kind: authority.jwt_issuer(),
            app_key_spki_sha256: authority.app_key_spki_sha256(),
            configuration_fingerprint: authority.configuration_fingerprint(),
        }
    }
}

fn runtime_identity(
    authority: &GithubServerServiceAuthorityIdentity,
    route: &RuntimeRouteEvidence,
    seed: u128,
    policy_digest_byte: u8,
) -> GithubRuntimeAuthorityIdentity {
    let identifier = |offset| Uuid::from_u128(seed + offset);
    let policy_digest = Sha256Digest::from_bytes([policy_digest_byte; 32]);
    GithubRuntimeAuthorityIdentity::new(
        authority.tenant().clone(),
        AttemptId::from_uuid(identifier(1)),
        FencingToken::new(1).expect("fence"),
        LeaseId::from_uuid(identifier(2)),
        UnixMillis::new(1_000),
        UnixMillis::new(10_000),
        RunId::from_uuid(identifier(3)),
        JobId::from_uuid(identifier(4)),
        RunnerId::from_uuid(identifier(5)),
        RunnerSessionId::from_uuid(identifier(6)),
        SessionEpoch::new(1).expect("session epoch"),
        RunnerGeneration::new(1).expect("runner generation"),
        StableRunnerSlot::new(1).expect("runner slot"),
        JobIrVersion::current(),
        1_024,
        policy_digest,
        authority.repository_id(),
        authority.connection_id(),
        authority.installation_id(),
        route.github_app_id,
        route.github_app_client_id.clone(),
        route.github_app_jwt_issuer_kind,
        GithubRepositoryId::new(authority.github_repository_id().get()).expect("repository ID"),
        authority.github_repository_name().clone(),
        GithubRuntimeAuthorityNamespace::new("github.actions.runtime").expect("namespace"),
        policy_digest,
        route.app_key_spki_sha256,
        route.configuration_fingerprint,
        GithubRuntimeAuthorityPreparationSelectionTail::new(
            LogicalWorkSelectionId::from_uuid(identifier(7)).expect("preparation selection"),
            LogicalActivationWorkerId::from_uuid(identifier(8)).expect("preparation owner"),
            LogicalActivationPreparationGeneration::new(1).expect("preparation generation"),
            Sha256Digest::from_bytes([0x31; 32]),
            UnixMillis::new(1_100),
            UnixMillis::new(1_200),
        )
        .expect("preparation tail"),
        GithubRuntimeAuthorityActivationSelectionTail::new(
            LogicalWorkSelectionId::from_uuid(identifier(9)).expect("activation selection"),
            LogicalActivationWorkerId::from_uuid(identifier(10)).expect("activation owner"),
            LogicalActivationGeneration::new(1).expect("activation generation"),
            Sha256Digest::from_bytes([0x32; 32]),
            UnixMillis::new(1_200),
            UnixMillis::new(1_300),
        )
        .expect("activation tail"),
        GithubRuntimeAuthorityMaterializationSelectionTail::new(
            LogicalWorkSelectionId::from_uuid(identifier(11)).expect("materialization selection"),
            LogicalMaterializationWorkerId::from_uuid(identifier(12))
                .expect("materialization owner"),
            LogicalMaterializationGeneration::new(1).expect("materialization generation"),
            Sha256Digest::from_bytes([0x33; 32]),
            UnixMillis::new(1_300),
            UnixMillis::new(1_400),
        )
        .expect("materialization tail"),
        UnixMillis::new(2_000),
        UnixMillis::new(3_000),
    )
    .expect("runtime identity")
}

fn changed_digest(digest: Sha256Digest) -> Sha256Digest {
    let mut bytes = *digest.as_bytes();
    bytes[0] ^= 0xff;
    Sha256Digest::from_bytes(bytes)
}

struct RevisionRoutingFixture {
    broker: Arc<GithubAppCredentialBroker>,
    pin: JobAuthorityBrokerPin,
    current: GithubServerServiceAuthorityIdentity,
    current_peer: GithubServerServiceAuthorityIdentity,
}

fn revision_routing_fixture() -> RevisionRoutingFixture {
    const INSTALLATION_ID: u64 = 202;
    const REPOSITORY_ID: u64 = 302;

    let mut current_repository = repository(
        "tenant-current",
        0x211,
        INSTALLATION_ID,
        REPOSITORY_ID,
        402,
        "octo/current-repository",
        "public",
        0x811,
        None,
    );
    set_repository_revisions(&mut current_repository, 2, 8);
    let mut current_peer = repository(
        "tenant-peer",
        0x212,
        INSTALLATION_ID,
        303,
        403,
        "octo/peer-repository",
        "public",
        0x911,
        None,
    );
    set_repository_revisions(&mut current_peer, 3, 9);
    let mut current_document = document(&[current_repository, current_peer]);
    current_document["app"]["configuration_revision"] = json!(8);
    let current_config = load_config(&current_document);
    let broker = live_test_broker(&current_config, INSTALLATION_ID);
    let verifier =
        GithubWebhookVerifier::new(b"runtime revision routing verifier").expect("webhook verifier");
    let current_plan = GithubProviderBootstrapPlan::new(&current_config, &broker, &verifier)
        .expect("same-installation current registry builds");
    let pins = job_authority_broker_pins(&current_plan)
        .expect("different policy revisions share one exact broker pin");
    assert_eq!(pins.len(), 1);
    let pin = pins
        .get(&INSTALLATION_ID)
        .cloned()
        .expect("one same-installation route");

    RevisionRoutingFixture {
        broker,
        pin,
        current: checks_authority(&current_plan, REPOSITORY_ID),
        current_peer: checks_authority(&current_plan, 303),
    }
}

#[test]
fn same_installation_current_policy_revisions_share_one_configuration_pin() {
    let fixture = revision_routing_fixture();

    assert_eq!(fixture.current.app_configuration_revision().get(), 8);
    assert_eq!(fixture.current_peer.app_configuration_revision().get(), 8);
    assert_eq!(fixture.current.policy_revision().get(), 8);
    assert_eq!(fixture.current_peer.policy_revision().get(), 9);
    assert_ne!(
        fixture.current.identity_digest(),
        fixture.current_peer.identity_digest()
    );
    assert_eq!(
        fixture.current.configuration_fingerprint(),
        fixture.current_peer.configuration_fingerprint()
    );
    assert_eq!(
        fixture.pin.configuration_fingerprint,
        fixture.current.configuration_fingerprint()
    );
    assert_eq!(
        fixture.broker.app_key_spki_sha256(),
        fixture.pin.app_key_spki_sha256
    );
}

#[tokio::test]
async fn current_identity_uses_the_exact_live_route_and_mismatches_close() {
    let fixture = revision_routing_fixture();
    let current_route = RuntimeRouteEvidence::from_authority(&fixture.current);

    let current = runtime_identity(&fixture.current, &current_route, 0x2_000, 0x81);

    // Runtime construction feeds this one pin into both provider-operation paths.
    let mint_route = PinnedGithubRuntimeAuthorityMintBroker::new(
        fixture.broker.clone(),
        fixture.pin.github_app_id,
        fixture.pin.github_app_client_id.clone(),
        fixture.pin.github_app_jwt_issuer_kind,
        fixture.pin.configuration_fingerprint,
    )
    .expect("the live mint route consumes the converged pin");
    let lifecycle_route = GithubRuntimeAuthorityLifecycleBrokerRouter::new([(
        fixture.broker,
        fixture.pin.github_app_id,
        fixture.pin.github_app_client_id,
        fixture.pin.github_app_jwt_issuer_kind,
        fixture.pin.configuration_fingerprint,
    )])
    .expect("the live lifecycle route consumes the same converged pin");
    assert_eq!(
        mint_route.installation_id(),
        current.provider_installation_id().get()
    );
    assert_eq!(mint_route.github_app_id(), current.github_app_id());
    assert_eq!(
        mint_route.github_app_client_id(),
        current.github_app_client_id()
    );
    assert_eq!(
        mint_route.github_app_jwt_issuer_kind(),
        current.github_app_jwt_issuer_kind()
    );
    assert_eq!(
        mint_route.github_app_jwt_issuer_value(),
        current.github_app_jwt_issuer_value()
    );
    assert_eq!(
        mint_route.app_key_spki_sha256(),
        current.app_key_spki_sha256()
    );
    assert_eq!(
        mint_route.configuration_fingerprint(),
        current.configuration_fingerprint()
    );
    assert_eq!(
        lifecycle_route.maximum_request_duration(&current),
        Some(mint_route.maximum_mint_duration())
    );

    let mut wrong_key = current_route.clone();
    wrong_key.app_key_spki_sha256 = changed_digest(wrong_key.app_key_spki_sha256);
    let mut wrong_issuer = current_route.clone();
    wrong_issuer.github_app_jwt_issuer_kind = match wrong_issuer.github_app_jwt_issuer_kind {
        GithubServerServiceJwtIssuer::AppClientId => GithubServerServiceJwtIssuer::AppId,
        GithubServerServiceJwtIssuer::AppId => GithubServerServiceJwtIssuer::AppClientId,
    };
    let mut wrong_fingerprint = current_route;
    wrong_fingerprint.configuration_fingerprint =
        changed_digest(wrong_fingerprint.configuration_fingerprint);
    let candidate = GithubInstallationTokenRevocationCandidate::from_protected_secret(
        SecretString::new("routing-mismatch-token").expect("candidate"),
    )
    .expect("bounded protected candidate");

    for (label, route) in [
        ("App key", wrong_key),
        ("JWT issuer", wrong_issuer),
        ("configuration fingerprint", wrong_fingerprint),
    ] {
        let mismatch = runtime_identity(&fixture.current, &route, 0x3_000, 0x81);
        assert_eq!(lifecycle_route.maximum_request_duration(&mismatch), None);
        let outcome = tokio::time::timeout(
            Duration::from_millis(50),
            lifecycle_route.revoke(&mismatch, &candidate),
        )
        .await
        .unwrap_or_else(|_| panic!("{label} mismatch reached the live provider"));
        assert!(
            matches!(
                outcome,
                GithubInstallationTokenRevocationOutcome::Unconfirmed(failure)
                    if failure.kind()
                        == GithubInstallationTokenRevocationFailureKind::InvalidResponse
            ),
            "{label} mismatch must fail at the exact route"
        );
    }
}

#[test]
fn non_regressing_clock_clamps_backward_observations() {
    let clock = NonRegressingGithubProviderClock::default();

    assert_eq!(clock.observe(41).get(), 41);
    assert_eq!(clock.observe(9).get(), 41);
    assert_eq!(clock.observe(-1).get(), 41);
    assert_eq!(clock.observe(73).get(), 73);
}

#[test]
fn public_only_and_mixed_registries_select_closed_source_modes() {
    let public = load_config(&document(&[repository(
        "tenant-public",
        0x201,
        202,
        302,
        402,
        "octo/public-repository",
        "public",
        0x501,
        None,
    )]));
    let public_shape = GithubProviderRuntimeShape::from_config(&public);
    assert_eq!(public_shape.repository_count(), 1);
    assert_eq!(public_shape.installation_count(), 1);
    assert_eq!(public_shape.tenant_count(), 1);
    assert_eq!(
        public_shape.source_mode(),
        GithubProviderSourceMode::PublicOnly
    );

    let mixed = load_config(&document(&[
        repository(
            "tenant-public",
            0x211,
            202,
            312,
            412,
            "octo/public-repository",
            "public",
            0x511,
            None,
        ),
        repository(
            "tenant-private",
            0x212,
            101,
            311,
            411,
            "octo/private-repository",
            "private",
            0x512,
            Some(0x612),
        ),
    ]));
    let mixed_shape = GithubProviderRuntimeShape::from_config(&mixed);
    assert_eq!(mixed_shape.repository_count(), 2);
    assert_eq!(mixed_shape.installation_count(), 2);
    assert_eq!(mixed_shape.tenant_count(), 2);
    assert_eq!(
        mixed_shape.source_mode(),
        GithubProviderSourceMode::PublicAndPrivate
    );
}

#[test]
fn fair_sweep_visits_every_stable_item_before_idle_delay() {
    let mut sweep = FairSweep::new(Arc::<[u8]>::from([1, 2, 3]));

    assert_eq!(sweep.next(), 1);
    assert!(!sweep.observe(true));
    assert_eq!(sweep.next(), 2);
    assert!(!sweep.observe(true));
    assert_eq!(sweep.next(), 3);
    assert!(sweep.observe(true));
    assert_eq!(sweep.next(), 1);
    assert!(!sweep.observe(true));
    assert_eq!(sweep.next(), 2);
    assert!(!sweep.observe(false));
    assert_eq!(sweep.next(), 3);
    assert!(!sweep.observe(true));
    assert_eq!(sweep.next(), 1);
}

#[test]
fn runtime_policy_rejects_unbounded_values() {
    assert_eq!(
        GithubProviderRuntimePolicy::new(
            Duration::ZERO,
            MAX_GITHUB_PROVIDER_SUPERVISED_RELEASES,
            Duration::from_secs(1),
            Duration::from_secs(1),
        ),
        Err(GithubProviderRuntimePolicyError)
    );
    assert_eq!(
        GithubProviderRuntimePolicy::new(
            Duration::from_secs(1),
            MAX_GITHUB_PROVIDER_SUPERVISED_RELEASES + 1,
            Duration::from_secs(1),
            Duration::from_secs(1),
        ),
        Err(GithubProviderRuntimePolicyError)
    );
    assert_eq!(
        GithubProviderRuntimePolicy::new(
            Duration::from_secs(1),
            1,
            Duration::from_mins(1) + Duration::from_millis(1),
            Duration::from_secs(1),
        ),
        Err(GithubProviderRuntimePolicyError)
    );
    assert_eq!(
        GithubProviderRuntimePolicy::new(
            Duration::from_secs(1),
            1,
            Duration::from_secs(1),
            Duration::ZERO,
        ),
        Err(GithubProviderRuntimePolicyError)
    );
    assert_eq!(
        GithubProviderRuntimePolicy::new(
            Duration::from_secs(1),
            1,
            Duration::from_secs(1),
            MAX_DRAIN_TIMEOUT + Duration::from_millis(1),
        ),
        Err(GithubProviderRuntimePolicyError)
    );
}

#[derive(Debug)]
struct FakePendingCommit {
    log: Arc<Mutex<Vec<String>>>,
    failures_remaining: AtomicUsize,
}

#[async_trait]
impl PendingCredentialCommit for FakePendingCommit {
    async fn replay(&self) -> bool {
        self.log.lock().expect("log lock").push("replay".to_owned());
        self.failures_remaining
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(1)
            })
            .is_err()
    }
}

enum FakeMaintenanceStep {
    Pending {
        replay_failures: usize,
        cancel: bool,
    },
    Worked {
        cancel: bool,
    },
}

struct FakeCredentialMaintenance {
    log: Arc<Mutex<Vec<String>>>,
    steps: Mutex<VecDeque<FakeMaintenanceStep>>,
    stop: CancellationToken,
}

impl fmt::Debug for FakeCredentialMaintenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FakeCredentialMaintenance")
    }
}

#[async_trait]
impl CredentialMaintenancePort for FakeCredentialMaintenance {
    async fn coordinate_next(
        &self,
        tenant: TenantScope,
        custody: CredentialMaintenanceCustody,
    ) -> Result<CredentialMaintenanceOutcome, GithubServerServiceCoordinatorError> {
        self.log
            .lock()
            .expect("log lock")
            .push(format!("coordinate:{}", tenant.as_str()));
        let step = self
            .steps
            .lock()
            .expect("step lock")
            .pop_front()
            .expect("scripted maintenance step");
        Ok(match step {
            FakeMaintenanceStep::Pending {
                replay_failures,
                cancel,
            } => {
                if cancel {
                    self.stop.cancel();
                }
                CredentialMaintenanceOutcome::Pending(custody.supervise(Box::new(
                    FakePendingCommit {
                        log: self.log.clone(),
                        failures_remaining: AtomicUsize::new(replay_failures),
                    },
                )))
            }
            FakeMaintenanceStep::Worked { cancel } => {
                if cancel {
                    self.stop.cancel();
                }
                CredentialMaintenanceOutcome::Worked
            }
        })
    }
}

fn tenants() -> Arc<[TenantScope]> {
    vec![
        TenantScope::from_authenticated_tenant_id("tenant-a").expect("tenant"),
        TenantScope::from_authenticated_tenant_id("tenant-b").expect("tenant"),
    ]
    .into()
}

fn credential_commit_supervisor() -> Arc<CredentialMaintenanceCommitSupervisor> {
    Arc::new(CredentialMaintenanceCommitSupervisor::new(
        tokio::runtime::Handle::current(),
        Duration::from_millis(1),
    ))
}

#[tokio::test]
async fn pending_commit_replays_exactly_before_more_fair_maintenance() {
    let stop = CancellationToken::new();
    let log = Arc::new(Mutex::new(Vec::new()));
    let maintenance: Arc<dyn CredentialMaintenancePort> = Arc::new(FakeCredentialMaintenance {
        log: log.clone(),
        steps: Mutex::new(VecDeque::from([
            FakeMaintenanceStep::Pending {
                replay_failures: 1,
                cancel: false,
            },
            FakeMaintenanceStep::Worked { cancel: true },
        ])),
        stop: stop.clone(),
    });

    run_credential_maintenance_loop(
        maintenance,
        credential_commit_supervisor(),
        tenants(),
        Duration::from_millis(1),
        stop,
    )
    .await
    .expect("maintenance stops cleanly");

    assert_eq!(
        *log.lock().expect("log lock"),
        [
            "coordinate:tenant-a",
            "replay",
            "replay",
            "coordinate:tenant-b"
        ]
    );
}

#[tokio::test]
async fn shutdown_replays_a_closed_commit_before_maintenance_stops() {
    let stop = CancellationToken::new();
    let supervisor = credential_commit_supervisor();
    let log = Arc::new(Mutex::new(Vec::new()));
    let maintenance: Arc<dyn CredentialMaintenancePort> = Arc::new(FakeCredentialMaintenance {
        log: log.clone(),
        steps: Mutex::new(VecDeque::from([FakeMaintenanceStep::Pending {
            replay_failures: 0,
            cancel: true,
        }])),
        stop: stop.clone(),
    });

    run_credential_maintenance_loop(
        maintenance,
        supervisor.clone(),
        tenants(),
        Duration::from_millis(1),
        stop,
    )
    .await
    .expect("pending commit moves under independent custody during shutdown");
    assert!(supervisor.drain(Duration::from_secs(1)).await);

    assert_eq!(
        *log.lock().expect("log lock"),
        ["coordinate:tenant-a", "replay"]
    );
}

#[derive(Debug)]
struct GatedPendingCommit {
    confirmed: Arc<AtomicBool>,
}

#[async_trait]
impl PendingCredentialCommit for GatedPendingCommit {
    async fn replay(&self) -> bool {
        self.confirmed.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
struct ParkAfterCommitPending {
    attempts: Arc<AtomicUsize>,
    replay_started: CancellationToken,
    release_replay: CancellationToken,
}

#[async_trait]
impl PendingCredentialCommit for ParkAfterCommitPending {
    async fn replay(&self) -> bool {
        let attempt = self.attempts.fetch_add(1, Ordering::SeqCst);
        assert_ne!(attempt, 0, "scripted ParkAfterCommit task loss");
        self.replay_started.cancel();
        self.release_replay.cancelled().await;
        true
    }
}

#[tokio::test]
async fn park_after_commit_task_loss_replays_exactly_and_reuses_permit() {
    let supervisor = credential_commit_supervisor();
    let reservation = supervisor.try_reserve().expect("initial reservation");
    let attempts = Arc::new(AtomicUsize::new(0));
    let replay_started = CancellationToken::new();
    let release_replay = CancellationToken::new();
    let completion = supervisor.supervise(
        reservation,
        Box::new(ParkAfterCommitPending {
            attempts: Arc::clone(&attempts),
            replay_started: replay_started.clone(),
            release_replay: release_replay.clone(),
        }),
    );

    assert!(
        completion.await.is_err(),
        "repository panic must be visible without detaching its Store future"
    );
    assert!(!supervisor.drain(Duration::from_millis(5)).await);
    replay_started.cancelled().await;
    assert!(
        supervisor.try_reserve().is_none(),
        "panicked Finish custody retains the sole bounded permit"
    );
    release_replay.cancel();
    assert!(supervisor.drain(Duration::from_secs(1)).await);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert!(
        supervisor.try_reserve().is_some(),
        "task cancellation must not strand bounded capacity"
    );
}

#[derive(Debug)]
struct ParkOuterCommitTaskPending {
    started: CancellationToken,
    release: CancellationToken,
    attempts: Arc<AtomicUsize>,
}

#[async_trait]
impl PendingCredentialCommit for ParkOuterCommitTaskPending {
    async fn replay(&self) -> bool {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        self.started.cancel();
        self.release.cancelled().await;
        true
    }
}

async fn assert_concrete_commit_wrapper_re_drives_after_outer_task_loss(
    wrap: impl FnOnce(Box<dyn PendingCredentialCommit>) -> Box<dyn PendingCredentialCommit>,
) {
    let supervisor = credential_commit_supervisor();
    let reservation = supervisor.try_reserve().expect("initial reservation");
    let started = CancellationToken::new();
    let release = CancellationToken::new();
    let attempts = Arc::new(AtomicUsize::new(0));
    let completion = supervisor.supervise(
        reservation,
        wrap(Box::new(ParkOuterCommitTaskPending {
            started: started.clone(),
            release: release.clone(),
            attempts: Arc::clone(&attempts),
        })),
    );
    started.cancelled().await;
    assert_eq!(attempts.load(Ordering::SeqCst), 1);

    assert!(supervisor.abort_pending_task(), "pending outer task exists");
    assert!(
        completion.await.is_err(),
        "task loss must become visible to the maintenance caller"
    );
    assert!(
        !supervisor.drain(Duration::from_millis(5)).await,
        "supervisor-owned exact custody must prevent a false idle result"
    );
    assert!(
        supervisor.try_reserve().is_none(),
        "lost-task custody must retain its bounded permit"
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while attempts.load(Ordering::SeqCst) != 2 {
            supervisor.redrive_retained();
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the exact retained Finish operation was re-driven");
    for _ in 0..32 {
        supervisor.redrive_retained();
        tokio::task::yield_now().await;
    }
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        2,
        "one active driver must serialize concurrent recovery attempts"
    );
    let hammer_started = CancellationToken::new();
    let stop_hammer = CancellationToken::new();
    let hammer = tokio::spawn({
        let supervisor = Arc::clone(&supervisor);
        let hammer_started = hammer_started.clone();
        let stop_hammer = stop_hammer.clone();
        async move {
            hammer_started.cancel();
            while !stop_hammer.is_cancelled() {
                supervisor.redrive_retained();
                tokio::task::yield_now().await;
            }
        }
    });
    hammer_started.cancelled().await;
    release.cancel();
    assert!(supervisor.drain(Duration::from_secs(1)).await);
    stop_hammer.cancel();
    hammer.await.expect("Finish redrive hammer");
    assert!(
        supervisor.try_reserve().is_some(),
        "exact re-drive confirmation releases bounded capacity"
    );
    for _ in 0..32 {
        supervisor.redrive_retained();
        tokio::task::yield_now().await;
    }
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        2,
        "confirmed Finish custody must never restart after removal"
    );
}

#[tokio::test]
async fn mint_finish_wrapper_re_drives_after_outer_task_loss() {
    assert_concrete_commit_wrapper_re_drives_after_outer_task_loss(|pending| {
        Box::new(PendingMintCommit { pending })
    })
    .await;
}

#[tokio::test]
async fn revocation_finish_wrapper_re_drives_after_outer_task_loss() {
    assert_concrete_commit_wrapper_re_drives_after_outer_task_loss(|pending| {
        Box::new(PendingRevocationCommit { pending })
    })
    .await;
}

#[tokio::test]
async fn removed_finish_custody_rejects_its_exact_stale_driver() {
    let supervisor = credential_commit_supervisor();
    let reservation = supervisor.try_reserve().expect("initial reservation");
    let started = CancellationToken::new();
    let release = CancellationToken::new();
    let attempts = Arc::new(AtomicUsize::new(0));
    let completion = supervisor.supervise(
        reservation,
        Box::new(PendingMintCommit {
            pending: Box::new(ParkOuterCommitTaskPending {
                started: started.clone(),
                release: release.clone(),
                attempts: Arc::clone(&attempts),
            }),
        }),
    );

    started.cancelled().await;
    let stale_custody = supervisor
        .custody
        .lock()
        .expect("service-credential custody lock")
        .clone()
        .expect("Finish custody retained before confirmation");
    release.cancel();
    completion.await.expect("confirmed Finish commit");
    tokio::time::timeout(Duration::from_secs(1), async {
        while !stale_custody.removed.load(Ordering::Acquire)
            || stale_custody.driver_active.load(Ordering::Acquire)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Finish custody removed with no active driver");

    let confirmed_calls = attempts.load(Ordering::SeqCst);
    assert_eq!(confirmed_calls, 1);
    assert!(!supervisor.start_driver(&stale_custody, None));
    tokio::task::yield_now().await;
    assert_eq!(attempts.load(Ordering::SeqCst), confirmed_calls);
    assert!(!supervisor.drain(Duration::from_millis(5)).await);

    drop(stale_custody);
    assert!(supervisor.drain(Duration::from_secs(1)).await);
    assert!(supervisor.try_reserve().is_some());
}

struct PanicAfterCredentialHandoffMaintenance {
    confirmed: Arc<AtomicBool>,
    handed_off: CancellationToken,
}

impl fmt::Debug for PanicAfterCredentialHandoffMaintenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PanicAfterCredentialHandoffMaintenance")
    }
}

#[async_trait]
impl CredentialMaintenancePort for PanicAfterCredentialHandoffMaintenance {
    async fn coordinate_next(
        &self,
        _tenant: TenantScope,
        custody: CredentialMaintenanceCustody,
    ) -> Result<CredentialMaintenanceOutcome, GithubServerServiceCoordinatorError> {
        let _completion = custody.supervise(Box::new(GatedPendingCommit {
            confirmed: self.confirmed.clone(),
        }));
        self.handed_off.cancel();
        panic!("scripted credential-maintenance caller task loss after custody handoff")
    }
}

#[tokio::test]
async fn caller_task_loss_after_handoff_preserves_exact_commit_and_reuses_permit() {
    let stop = CancellationToken::new();
    let confirmed = Arc::new(AtomicBool::new(false));
    let handed_off = CancellationToken::new();
    let supervisor = credential_commit_supervisor();
    let maintenance: Arc<dyn CredentialMaintenancePort> =
        Arc::new(PanicAfterCredentialHandoffMaintenance {
            confirmed: confirmed.clone(),
            handed_off: handed_off.clone(),
        });
    let run = tokio::spawn(run_credential_maintenance_loop(
        maintenance,
        supervisor.clone(),
        tenants(),
        Duration::from_millis(1),
        stop,
    ));

    handed_off.cancelled().await;
    assert!(run.await.expect_err("caller task must be lost").is_panic());
    assert!(
        !supervisor.drain(Duration::from_millis(5)).await,
        "the watchdog must retain an unconfirmed exact commit"
    );
    confirmed.store(true, Ordering::Release);
    assert!(supervisor.drain(Duration::from_secs(1)).await);
    assert!(
        supervisor.try_reserve().is_some(),
        "caller task loss must not strand bounded capacity"
    );
}

struct GatedPendingMaintenance {
    confirmed: Arc<AtomicBool>,
    stop: CancellationToken,
}

struct FatalPendingMaintenance {
    confirmed: Arc<AtomicBool>,
    pending_started: CancellationToken,
}

impl fmt::Debug for FatalPendingMaintenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FatalPendingMaintenance")
    }
}

#[async_trait]
impl CredentialMaintenancePort for FatalPendingMaintenance {
    async fn coordinate_next(
        &self,
        _tenant: TenantScope,
        custody: CredentialMaintenanceCustody,
    ) -> Result<CredentialMaintenanceOutcome, GithubServerServiceCoordinatorError> {
        self.pending_started.cancel();
        Ok(CredentialMaintenanceOutcome::Pending(custody.supervise(
            Box::new(GatedPendingCommit {
                confirmed: self.confirmed.clone(),
            }),
        )))
    }
}

impl fmt::Debug for GatedPendingMaintenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GatedPendingMaintenance")
    }
}

#[async_trait]
impl CredentialMaintenancePort for GatedPendingMaintenance {
    async fn coordinate_next(
        &self,
        _tenant: TenantScope,
        custody: CredentialMaintenanceCustody,
    ) -> Result<CredentialMaintenanceOutcome, GithubServerServiceCoordinatorError> {
        self.stop.cancel();
        Ok(CredentialMaintenanceOutcome::Pending(custody.supervise(
            Box::new(GatedPendingCommit {
                confirmed: self.confirmed.clone(),
            }),
        )))
    }
}

#[tokio::test]
async fn shutdown_hands_an_unconfirmed_exact_commit_to_independent_custody() {
    let stop = CancellationToken::new();
    let confirmed = Arc::new(AtomicBool::new(false));
    let supervisor = credential_commit_supervisor();
    let maintenance: Arc<dyn CredentialMaintenancePort> = Arc::new(GatedPendingMaintenance {
        confirmed: confirmed.clone(),
        stop: stop.clone(),
    });
    let run = run_credential_maintenance_loop(
        maintenance,
        supervisor.clone(),
        tenants(),
        Duration::from_millis(1),
        stop,
    );
    tokio::time::timeout(Duration::from_secs(1), run)
        .await
        .expect("maintenance observes stop after handing off custody")
        .expect("maintenance stops cleanly");
    assert!(!supervisor.drain(Duration::from_millis(5)).await);
    confirmed.store(true, Ordering::Release);
    assert!(supervisor.drain(Duration::from_secs(1)).await);
    assert!(
        supervisor.try_reserve().is_some(),
        "the bounded permit is reusable after independent confirmation"
    );
}

struct FakeReleaseDrain {
    log: Arc<Mutex<Vec<String>>>,
}

struct GatedReleaseDrain {
    entered: CancellationToken,
    release: CancellationToken,
}

struct FakeJobRuntimeAuthorityDrain {
    log: Arc<Mutex<Vec<String>>>,
}

struct ServiceCredentialJobRuntimeAuthorityDrain {
    log: Arc<Mutex<Vec<String>>>,
    service_credentials: Arc<CredentialMaintenanceCommitSupervisor>,
}

struct TimedOutJobRuntimeAuthorityDrain;

impl fmt::Debug for FakeJobRuntimeAuthorityDrain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FakeJobRuntimeAuthorityDrain")
    }
}

impl fmt::Debug for ServiceCredentialJobRuntimeAuthorityDrain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServiceCredentialJobRuntimeAuthorityDrain")
    }
}

impl fmt::Debug for TimedOutJobRuntimeAuthorityDrain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TimedOutJobRuntimeAuthorityDrain")
    }
}

#[async_trait]
impl JobRuntimeAuthorityDrainPort for FakeJobRuntimeAuthorityDrain {
    fn close(&self) {
        self.log
            .lock()
            .expect("log lock")
            .push("job-authority-close".to_owned());
    }

    async fn drain(&self, _timeout: Duration) -> bool {
        self.log
            .lock()
            .expect("log lock")
            .push("job-authority-drain".to_owned());
        true
    }
}

#[async_trait]
impl JobRuntimeAuthorityDrainPort for ServiceCredentialJobRuntimeAuthorityDrain {
    fn close(&self) {
        self.log
            .lock()
            .expect("log lock")
            .push("job-authority-close".to_owned());
        self.service_credentials.close();
    }

    async fn drain(&self, timeout: Duration) -> bool {
        self.log
            .lock()
            .expect("log lock")
            .push("job-authority-drain".to_owned());
        self.service_credentials.drain(timeout).await
    }
}

#[async_trait]
impl JobRuntimeAuthorityDrainPort for TimedOutJobRuntimeAuthorityDrain {
    fn close(&self) {}

    async fn drain(&self, _timeout: Duration) -> bool {
        false
    }
}

impl fmt::Debug for FakeReleaseDrain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FakeReleaseDrain")
    }
}

#[async_trait]
impl ReleaseDrainPort for FakeReleaseDrain {
    async fn drain(&self, _timeout: Duration) -> bool {
        self.log
            .lock()
            .expect("log lock")
            .push("release-drain".to_owned());
        true
    }
}

impl fmt::Debug for GatedReleaseDrain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GatedReleaseDrain")
    }
}

#[async_trait]
impl ReleaseDrainPort for GatedReleaseDrain {
    async fn drain(&self, timeout: Duration) -> bool {
        self.entered.cancel();
        tokio::time::timeout(timeout, self.release.cancelled())
            .await
            .is_ok()
    }
}

fn stopped_loop(
    name: &'static str,
    stop: CancellationToken,
    log: Arc<Mutex<Vec<String>>>,
    exit: fn(Result<(), GithubDeliveryServiceError>) -> RuntimeLoopExit,
) -> RuntimeLoopFuture<'static> {
    runtime_loop(async move {
        stop.cancelled().await;
        log.lock().expect("log lock").push(name.to_owned());
        exit(Ok(()))
    })
}

#[tokio::test]
async fn shutdown_stops_all_consumers_before_release_drain() {
    let shutdown = CancellationToken::new();
    shutdown.cancel();
    let stop = CancellationToken::new();
    let log = Arc::new(Mutex::new(Vec::new()));
    let loops = FuturesUnordered::new();
    loops.push(stopped_loop(
        "delivery-stop",
        stop.clone(),
        log.clone(),
        RuntimeLoopExit::Delivery,
    ));
    loops.push(runtime_loop({
        let stop = stop.clone();
        let log = log.clone();
        async move {
            stop.cancelled().await;
            log.lock().expect("log lock").push("checks-stop".to_owned());
            RuntimeLoopExit::Checks(Ok(()))
        }
    }));
    loops.push(runtime_loop({
        let stop = stop.clone();
        let log = log.clone();
        async move {
            stop.cancelled().await;
            log.lock()
                .expect("log lock")
                .push("maintenance-stop".to_owned());
            RuntimeLoopExit::Credentials(Ok(()))
        }
    }));
    let job_authority_drain: Arc<dyn JobRuntimeAuthorityDrainPort> =
        Arc::new(FakeJobRuntimeAuthorityDrain { log: log.clone() });
    let release_drain: Arc<dyn ReleaseDrainPort> = Arc::new(FakeReleaseDrain { log: log.clone() });
    let (fatal_notification, fatal_signal) = oneshot::channel();

    supervise_runtime_loops(
        loops,
        shutdown,
        stop,
        job_authority_drain,
        release_drain,
        Duration::from_secs(1),
        Some(fatal_notification),
    )
    .await
    .expect("ordered shutdown");
    assert!(
        fatal_signal.await.is_err(),
        "operator shutdown must not send a provider-fatal notification"
    );

    let log = log.lock().expect("log lock");
    assert_eq!(log.last().map(String::as_str), Some("release-drain"));
    let job_drain = log
        .iter()
        .position(|entry| entry == "job-authority-drain")
        .expect("job-authority drain");
    let release_drain = log
        .iter()
        .position(|entry| entry == "release-drain")
        .expect("release drain");
    assert!(job_drain < release_drain);
    let stopped = &log[..job_drain];
    assert!(stopped.iter().any(|entry| entry == "delivery-stop"));
    assert!(stopped.iter().any(|entry| entry == "checks-stop"));
    assert!(stopped.iter().any(|entry| entry == "maintenance-stop"));
}

#[tokio::test]
async fn job_authority_drain_timeout_is_visible_and_blocks_release_drain() {
    let shutdown = CancellationToken::new();
    shutdown.cancel();
    let stop = CancellationToken::new();
    let log = Arc::new(Mutex::new(Vec::new()));
    let loops = FuturesUnordered::new();
    loops.push(stopped_loop(
        "delivery-stop",
        stop.clone(),
        log.clone(),
        RuntimeLoopExit::Delivery,
    ));
    let release_drain: Arc<dyn ReleaseDrainPort> = Arc::new(FakeReleaseDrain { log: log.clone() });

    let result = supervise_runtime_loops(
        loops,
        shutdown,
        stop,
        Arc::new(TimedOutJobRuntimeAuthorityDrain),
        release_drain,
        Duration::from_secs(1),
        None,
    )
    .await;

    assert!(matches!(
        result,
        Err(GithubProviderRuntimeError::DrainTimeout)
    ));
    assert!(
        !log.lock()
            .expect("log lock")
            .iter()
            .any(|entry| entry == "release-drain"),
        "service-credential releases remain ordered behind job-authority custody"
    );
}

#[tokio::test]
async fn loop_timeout_closes_custody_and_never_starts_release_drain() {
    let shutdown = CancellationToken::new();
    shutdown.cancel();
    let stop = CancellationToken::new();
    let log = Arc::new(Mutex::new(Vec::new()));
    let loops = FuturesUnordered::new();
    loops.push(runtime_loop(async move {
        std::future::pending::<()>().await;
        RuntimeLoopExit::Checks(Ok(()))
    }));
    let job_authority_drain: Arc<dyn JobRuntimeAuthorityDrainPort> =
        Arc::new(FakeJobRuntimeAuthorityDrain { log: log.clone() });
    let release_drain: Arc<dyn ReleaseDrainPort> = Arc::new(FakeReleaseDrain { log: log.clone() });

    let result = supervise_runtime_loops(
        loops,
        shutdown,
        stop,
        job_authority_drain,
        release_drain,
        Duration::from_millis(20),
        None,
    )
    .await;

    assert!(matches!(
        result,
        Err(GithubProviderRuntimeError::DrainTimeout)
    ));
    let log = log.lock().expect("log lock");
    assert!(log.iter().any(|entry| entry == "job-authority-close"));
    assert!(!log.iter().any(|entry| entry == "job-authority-drain"));
    assert!(!log.iter().any(|entry| entry == "release-drain"));
}

#[tokio::test]
async fn service_credential_release_drain_timeout_is_visible() {
    let shutdown = CancellationToken::new();
    shutdown.cancel();
    let stop = CancellationToken::new();
    let log = Arc::new(Mutex::new(Vec::new()));
    let loops = FuturesUnordered::new();
    loops.push(stopped_loop(
        "delivery-stop",
        stop.clone(),
        log.clone(),
        RuntimeLoopExit::Delivery,
    ));
    let job_authority_drain: Arc<dyn JobRuntimeAuthorityDrainPort> =
        Arc::new(FakeJobRuntimeAuthorityDrain { log });
    let release_entered = CancellationToken::new();
    let release_drain: Arc<dyn ReleaseDrainPort> = Arc::new(GatedReleaseDrain {
        entered: release_entered.clone(),
        release: CancellationToken::new(),
    });

    let result = supervise_runtime_loops(
        loops,
        shutdown,
        stop,
        job_authority_drain,
        release_drain,
        Duration::from_millis(20),
        None,
    )
    .await;

    assert!(release_entered.is_cancelled());
    assert!(matches!(
        result,
        Err(GithubProviderRuntimeError::DrainTimeout)
    ));
}

#[tokio::test]
async fn first_fatal_exit_notifies_before_pending_commit_and_release_drain_finish() {
    let shutdown = CancellationToken::new();
    let stop = CancellationToken::new();
    let pending_started = CancellationToken::new();
    let confirmed = Arc::new(AtomicBool::new(false));
    let maintenance: Arc<dyn CredentialMaintenancePort> = Arc::new(FatalPendingMaintenance {
        confirmed: confirmed.clone(),
        pending_started: pending_started.clone(),
    });
    let commit_supervisor = credential_commit_supervisor();
    let loop_commit_supervisor = commit_supervisor.clone();
    let loops = FuturesUnordered::new();
    loops.push(runtime_loop({
        let stop = stop.clone();
        async move {
            RuntimeLoopExit::Credentials(
                run_credential_maintenance_loop(
                    maintenance,
                    loop_commit_supervisor,
                    tenants(),
                    Duration::from_millis(1),
                    stop,
                )
                .await,
            )
        }
    }));
    loops.push(runtime_loop(async move {
        pending_started.cancelled().await;
        RuntimeLoopExit::Checks(Ok(()))
    }));
    let log = Arc::new(Mutex::new(Vec::new()));
    let job_authority_drain: Arc<dyn JobRuntimeAuthorityDrainPort> =
        Arc::new(ServiceCredentialJobRuntimeAuthorityDrain {
            log,
            service_credentials: commit_supervisor,
        });
    let release_entered = CancellationToken::new();
    let release = CancellationToken::new();
    let release_drain: Arc<dyn ReleaseDrainPort> = Arc::new(GatedReleaseDrain {
        entered: release_entered.clone(),
        release: release.clone(),
    });
    let (fatal_notification, fatal_signal) = oneshot::channel();
    let runtime = tokio::spawn(supervise_runtime_loops(
        loops,
        shutdown,
        stop,
        job_authority_drain,
        release_drain,
        Duration::from_secs(1),
        Some(fatal_notification),
    ));

    tokio::time::timeout(Duration::from_secs(1), fatal_signal)
        .await
        .expect("first fatal exit must notify before drain")
        .expect("fatal notifier must remain owned");
    assert!(
        !runtime.is_finished(),
        "fatal notification must not detach the pending commit"
    );
    assert!(
        !release_entered.is_cancelled(),
        "credential release waits behind the pending commit"
    );

    confirmed.store(true, Ordering::Release);
    tokio::time::timeout(Duration::from_secs(1), release_entered.cancelled())
        .await
        .expect("credential release drain must remain awaited");
    assert!(
        !runtime.is_finished(),
        "provider service remains owned through credential release"
    );
    release.cancel();
    assert!(matches!(
        runtime.await.expect("runtime supervisor joins"),
        Err(GithubProviderRuntimeError::UnexpectedStop)
    ));
}

#[tokio::test]
async fn shutdown_timeout_is_visible_for_an_unconfirmed_service_credential_commit() {
    let shutdown = CancellationToken::new();
    let shutdown_signal = shutdown.clone();
    let stop = CancellationToken::new();
    let pending_started = CancellationToken::new();
    let maintenance: Arc<dyn CredentialMaintenancePort> = Arc::new(FatalPendingMaintenance {
        confirmed: Arc::new(AtomicBool::new(false)),
        pending_started: pending_started.clone(),
    });
    let commit_supervisor = credential_commit_supervisor();
    let loop_commit_supervisor = commit_supervisor.clone();
    let loops = FuturesUnordered::new();
    loops.push(runtime_loop({
        let stop = stop.clone();
        async move {
            RuntimeLoopExit::Credentials(
                run_credential_maintenance_loop(
                    maintenance,
                    loop_commit_supervisor,
                    tenants(),
                    Duration::from_millis(1),
                    stop,
                )
                .await,
            )
        }
    }));
    let log = Arc::new(Mutex::new(Vec::new()));
    let job_authority_drain: Arc<dyn JobRuntimeAuthorityDrainPort> =
        Arc::new(ServiceCredentialJobRuntimeAuthorityDrain {
            log: log.clone(),
            service_credentials: commit_supervisor,
        });
    let release_drain: Arc<dyn ReleaseDrainPort> = Arc::new(FakeReleaseDrain { log });
    let runtime = tokio::spawn(supervise_runtime_loops(
        loops,
        shutdown,
        stop,
        job_authority_drain,
        release_drain,
        Duration::from_millis(20),
        None,
    ));

    tokio::time::timeout(Duration::from_secs(1), pending_started.cancelled())
        .await
        .expect("maintenance produced an exact pending commit");
    shutdown_signal.cancel();
    let result = tokio::time::timeout(Duration::from_secs(1), runtime)
        .await
        .expect("the whole-provider drain is bounded")
        .expect("runtime supervisor joins");
    assert!(matches!(
        result,
        Err(GithubProviderRuntimeError::DrainTimeout)
    ));
}
