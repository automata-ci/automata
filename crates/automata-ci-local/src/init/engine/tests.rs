use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::PermissionsExt as _,
    path::PathBuf,
    process::Command,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use crate::init::catalog::{
    CandidateBinding, LiveImageEvidence, Release, candidate_replay_test_catalog,
};
use crate::{Installation, InstallationId, InstallationName};
use zeroize::Zeroizing;

use super::*;

fn installation() -> Installation {
    Installation::verified(InstallationName::default(), InstallationId::new())
}

fn fingerprint() -> Sha256Digest {
    Sha256Digest::from_bytes([0x5a; 32])
}

const CONTAINER_ID: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const CANDIDATE_CONFIG_ID: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CANDIDATE_MANIFEST_ID: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[tokio::test]
async fn image_batch_starts_no_later_role_after_a_settled_operation_cancels() {
    let cancellation = CancellationToken::new();
    let started = Mutex::new(Vec::new());
    let cancellation_ref = &cancellation;
    let started_ref = &started;

    let result = cancellation_checkpointed(
        &cancellation,
        ["automata", "runner", "postgres"],
        move |role| async move {
            started_ref.lock().unwrap().push(role);
            if role == "automata" {
                cancellation_ref.cancel();
            }
            Ok(())
        },
    )
    .await;

    assert_eq!(result.unwrap_err().code(), LocalInitErrorCode::Cancelled);
    assert_eq!(*started.lock().unwrap(), ["automata"]);
}

#[tokio::test]
async fn registry_pull_starts_no_mutation_after_the_last_preflight_observes_cancellation() {
    let cancellation = CancellationToken::new();
    let mutations = Mutex::new(Vec::new());
    cancellation.cancel();

    let result = mutation_after_cancellation_checkpoint(&cancellation, || async {
        mutations.lock().unwrap().push("pull");
        Ok(())
    })
    .await;

    assert_eq!(result.unwrap_err().code(), LocalInitErrorCode::Cancelled);
    assert!(mutations.lock().unwrap().is_empty());
}

#[tokio::test]
async fn volume_batch_starts_no_later_create_after_a_settled_operation_cancels() {
    let cancellation = CancellationToken::new();
    let started = Mutex::new(Vec::new());
    let cancellation_ref = &cancellation;
    let started_ref = &started;

    let result = cancellation_checkpointed(
        &cancellation,
        [
            VolumeRole::BootstrapState,
            VolumeRole::ControlMaterial,
            VolumeRole::EngineRelay,
        ],
        move |role| async move {
            started_ref.lock().unwrap().push(role);
            if role == VolumeRole::BootstrapState {
                cancellation_ref.cancel();
            }
            Ok(())
        },
    )
    .await;

    assert_eq!(result.unwrap_err().code(), LocalInitErrorCode::Cancelled);
    assert_eq!(*started.lock().unwrap(), [VolumeRole::BootstrapState]);
}

fn candidate_fixture() -> (
    VerifiedCatalog,
    CandidateBinding,
    bollard::models::ImageInspect,
) {
    let release = Release {
        commit: "1".repeat(40),
        created: "2026-08-17T12:34:56Z".to_owned(),
        prerelease: false,
        source_date_epoch: 1_786_970_096,
        tag: "v1.0.0".to_owned(),
        tag_object: "2".repeat(40),
        version: "1.0.0".to_owned(),
    };
    let binding = CandidateBinding {
        reference: format!("ghcr.io/automata-ci/automata-service-proxy@{CANDIDATE_MANIFEST_ID}"),
        candidate_provenance_sha256: "3".repeat(64),
        config_digest: CANDIDATE_CONFIG_ID.to_owned(),
        image_digest: CANDIDATE_MANIFEST_ID.to_owned(),
        image_name: "ghcr.io/automata-ci/automata-service-proxy".to_owned(),
        oci_archive_sha256: "4".repeat(64),
        sha256: "5".repeat(64),
        source_provenance_sha256: "6".repeat(64),
    };
    let path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    let expected = serde_json::json!({
        "command": ["true"],
        "entrypoint": [],
        "required_environment": {"PATH": path},
        "required_labels": {},
        "user": "",
        "working_directory": "/"
    });
    let image: bollard::models::ImageInspect = serde_json::from_value(serde_json::json!({
        "Id": CANDIDATE_CONFIG_ID,
        "RepoTags": [],
        "RepoDigests": [],
        "Os": "linux",
        "Architecture": "amd64",
        "Config": {
            "Cmd": ["true"],
            "Entrypoint": null,
            "Env": [format!("PATH={path}")],
            "Labels": {
                "org.opencontainers.image.created": &release.created,
                "org.opencontainers.image.revision": &release.commit,
                "org.opencontainers.image.version": &release.version
            },
            "User": "",
            "WorkingDir": "/"
        }
    }))
    .unwrap();
    let catalog = candidate_replay_test_catalog(release, binding.clone(), expected);
    (catalog, binding, image)
}

#[derive(Default)]
struct FakeCandidateState {
    config: Option<bollard::models::ImageInspect>,
    manifest: Option<bollard::models::ImageInspect>,
    digest: Option<bollard::models::ImageInspect>,
    tagged: Option<bollard::models::ImageInspect>,
    imports: usize,
    cancel_on_verify: Option<CancellationToken>,
    cancel_on_import: Option<CancellationToken>,
}

struct FakeCandidateDriver {
    binding: CandidateBinding,
    template: bollard::models::ImageInspect,
    state: Mutex<FakeCandidateState>,
}

#[async_trait::async_trait]
impl CandidateLoadDriver for FakeCandidateDriver {
    async fn candidate_verify(&self) -> Result<(), LocalInitError> {
        if let Some(cancellation) = self.state.lock().unwrap().cancel_on_verify.take() {
            cancellation.cancel();
        }
        Ok(())
    }

    async fn candidate_inspect(
        &self,
        reference: &str,
    ) -> Result<Option<bollard::models::ImageInspect>, LocalInitError> {
        let state = self.state.lock().unwrap();
        if reference == self.binding.config_digest {
            Ok(state.config.clone())
        } else if reference == self.binding.image_digest {
            Ok(state.manifest.clone())
        } else {
            Ok(state.digest.clone())
        }
    }

    async fn candidate_import_untrusted(&self, _archive: &[u8]) -> Result<(), LocalInitError> {
        let mut state = self.state.lock().unwrap();
        state.imports += 1;
        if state.imports == 1 {
            state.config = Some(self.template.clone());
        } else {
            let mut tagged = self.template.clone();
            tagged.repo_tags = Some(vec![
                self.binding
                    .local_reference("automata.local/automata-ci-service-proxy"),
            ]);
            state.tagged = Some(tagged);
        }
        if let Some(cancellation) = state.cancel_on_import.take() {
            cancellation.cancel();
        }
        Ok(())
    }
}

#[tokio::test]
async fn candidate_load_retry_adopts_one_exact_partial_ingest_and_replays_the_verified_archive() {
    let (catalog, binding, template) = candidate_fixture();
    let driver = FakeCandidateDriver {
        binding: binding.clone(),
        template,
        state: Mutex::new(FakeCandidateState::default()),
    };
    let image = catalog.image("service-proxy");
    let cancellation = CancellationToken::new();

    replay_candidate_load(
        &driver,
        &catalog,
        "service-proxy",
        image,
        b"verified",
        &cancellation,
    )
    .await
    .unwrap();
    assert!(driver.state.lock().unwrap().tagged.is_none());
    replay_candidate_load(
        &driver,
        &catalog,
        "service-proxy",
        image,
        b"verified",
        &cancellation,
    )
    .await
    .unwrap();

    let state = driver.state.lock().unwrap();
    assert_eq!(state.imports, 2);
    let tagged = state.tagged.as_ref().unwrap();
    let config = serde_json::to_value(tagged.config.as_ref().unwrap()).unwrap();
    catalog
        .validate_live_image(
            "service-proxy",
            &LiveImageEvidence {
                image_id: tagged.id.as_deref().unwrap(),
                operating_system: tagged.os.as_deref().unwrap(),
                architecture: tagged.architecture.as_deref().unwrap(),
                config: &config,
                repository_tags: tagged.repo_tags.as_deref(),
                repository_digests: tagged.repo_digests.as_deref(),
            },
        )
        .unwrap();
}

#[tokio::test]
async fn candidate_partial_ingest_with_an_unexpected_reference_is_never_replayed() {
    let (catalog, binding, mut template) = candidate_fixture();
    template.repo_tags = Some(vec!["foreign.invalid/image:tag".to_owned()]);
    let driver = FakeCandidateDriver {
        binding,
        template: template.clone(),
        state: Mutex::new(FakeCandidateState {
            config: Some(template),
            ..Default::default()
        }),
    };
    let cancellation = CancellationToken::new();
    let result = replay_candidate_load(
        &driver,
        &catalog,
        "service-proxy",
        catalog.image("service-proxy"),
        b"verified",
        &cancellation,
    )
    .await;
    assert_eq!(
        result.unwrap_err().code(),
        LocalInitErrorCode::EngineResourceMismatch
    );
    assert_eq!(driver.state.lock().unwrap().imports, 0);
}

#[tokio::test]
async fn candidate_import_starts_no_mutation_after_the_last_verify_observes_cancellation() {
    let (catalog, binding, template) = candidate_fixture();
    let cancellation = CancellationToken::new();
    let driver = FakeCandidateDriver {
        binding,
        template,
        state: Mutex::new(FakeCandidateState {
            cancel_on_verify: Some(cancellation.clone()),
            ..Default::default()
        }),
    };

    let result = replay_candidate_load(
        &driver,
        &catalog,
        "service-proxy",
        catalog.image("service-proxy"),
        b"verified",
        &cancellation,
    )
    .await;

    assert_eq!(result.unwrap_err().code(), LocalInitErrorCode::Cancelled);
    assert_eq!(driver.state.lock().unwrap().imports, 0);
}

#[tokio::test]
async fn cancellation_during_candidate_import_settles_to_an_exact_replayable_partial() {
    let (catalog, binding, template) = candidate_fixture();
    let cancellation = CancellationToken::new();
    let driver = FakeCandidateDriver {
        binding,
        template,
        state: Mutex::new(FakeCandidateState {
            cancel_on_import: Some(cancellation.clone()),
            ..Default::default()
        }),
    };

    assert_eq!(
        replay_candidate_load(
            &driver,
            &catalog,
            "service-proxy",
            catalog.image("service-proxy"),
            b"verified",
            &cancellation,
        )
        .await
        .unwrap_err()
        .code(),
        LocalInitErrorCode::Cancelled
    );
    {
        let state = driver.state.lock().unwrap();
        assert_eq!(state.imports, 1);
        assert!(state.config.is_some());
        assert!(state.tagged.is_none());
    }

    let replay = CancellationToken::new();
    replay_candidate_load(
        &driver,
        &catalog,
        "service-proxy",
        catalog.image("service-proxy"),
        b"verified",
        &replay,
    )
    .await
    .unwrap();
    let state = driver.state.lock().unwrap();
    assert_eq!(state.imports, 2);
    assert!(state.tagged.is_some());
}

#[derive(Default)]
struct FakeGuardState {
    guard: Option<bollard::models::Volume>,
    attachments: Vec<String>,
    creates: Vec<String>,
    next_mutations: usize,
    helper_removals: usize,
    cancel_on_verify: Option<CancellationToken>,
    cancel_on_create: Option<CancellationToken>,
}

#[derive(Default)]
struct FakeGuardDriver {
    state: Mutex<FakeGuardState>,
}

fn fake_volume(name: &str, labels: &BTreeMap<String, String>) -> bollard::models::Volume {
    serde_json::from_value(serde_json::json!({
        "CreatedAt": "",
        "Driver": "local",
        "Labels": labels,
        "Mountpoint": "",
        "Name": name,
        "Options": {},
        "Scope": "local"
    }))
    .unwrap()
}

#[async_trait::async_trait]
impl VolumeGuardDriver for FakeGuardDriver {
    async fn guard_verify(&self) -> Result<(), LocalInitError> {
        if let Some(cancellation) = self.state.lock().unwrap().cancel_on_verify.take() {
            cancellation.cancel();
        }
        Ok(())
    }

    async fn guard_inspect(
        &self,
        _name: &str,
    ) -> Result<Option<bollard::models::Volume>, LocalInitError> {
        let guard = self.state.lock().unwrap().guard.clone();
        tokio::task::yield_now().await;
        Ok(guard)
    }

    async fn guard_attachments(&self, _name: &str) -> Result<Vec<String>, LocalInitError> {
        Ok(self.state.lock().unwrap().attachments.clone())
    }

    async fn guard_create_untrusted(
        &self,
        name: &str,
        labels: &BTreeMap<String, String>,
    ) -> Result<(), LocalInitError> {
        let mut state = self.state.lock().unwrap();
        state.creates.push(name.to_owned());
        if state.guard.is_none() {
            state.guard = Some(fake_volume(name, labels));
        }
        if let Some(cancellation) = state.cancel_on_create.take() {
            cancellation.cancel();
        }
        Ok(())
    }
}

async fn elect_then_reach_next_mutation(
    driver: &FakeGuardDriver,
    name: &str,
    labels: &BTreeMap<String, String>,
) -> Result<(), LocalInitError> {
    let cancellation = CancellationToken::new();
    elect_desired_guard_with_driver(driver, name, labels, None, true, &cancellation).await?;
    driver.state.lock().unwrap().next_mutations += 1;
    Ok(())
}

#[tokio::test]
async fn desired_guard_elects_one_fresh_state_before_any_later_mutation() {
    let installation = installation();
    let name = volume_name(installation.compose_project().as_str(), VolumeRole::Desired);
    let first = volume_labels(
        &installation,
        Sha256Digest::from_bytes([0x11; 32]),
        VolumeRole::Desired,
    );
    let second = volume_labels(
        &installation,
        Sha256Digest::from_bytes([0x22; 32]),
        VolumeRole::Desired,
    );
    let driver = FakeGuardDriver::default();

    let (first_result, second_result) = tokio::join!(
        elect_then_reach_next_mutation(&driver, &name, &first),
        elect_then_reach_next_mutation(&driver, &name, &second),
    );
    assert_ne!(first_result.is_ok(), second_result.is_ok());
    let failure = if let Err(error) = first_result {
        error
    } else {
        second_result.unwrap_err()
    };
    assert_eq!(failure.code(), LocalInitErrorCode::EngineResourceMismatch);

    let state = driver.state.lock().unwrap();
    assert_eq!(state.next_mutations, 1);
    assert_eq!(state.helper_removals, 0);
    assert!(!state.creates.is_empty());
    assert!(state.creates.iter().all(|created| created == &name));
}

#[tokio::test]
async fn desired_guard_replays_after_a_crash_without_another_create() {
    let installation = installation();
    let name = volume_name(installation.compose_project().as_str(), VolumeRole::Desired);
    let labels = volume_labels(&installation, fingerprint(), VolumeRole::Desired);
    let driver = FakeGuardDriver::default();
    let cancellation = CancellationToken::new();

    elect_desired_guard_with_driver(&driver, &name, &labels, None, true, &cancellation)
        .await
        .unwrap();
    elect_desired_guard_with_driver(&driver, &name, &labels, None, true, &cancellation)
        .await
        .unwrap();

    let state = driver.state.lock().unwrap();
    assert_eq!(state.creates, [name]);
    assert!(state.guard.is_some());
}

#[tokio::test]
async fn cancelled_guard_create_is_reconciled_before_return_and_replays_exactly() {
    let installation = installation();
    let name = volume_name(installation.compose_project().as_str(), VolumeRole::Desired);
    let labels = volume_labels(&installation, fingerprint(), VolumeRole::Desired);
    let driver = FakeGuardDriver::default();
    let cancellation = CancellationToken::new();
    driver.state.lock().unwrap().cancel_on_create = Some(cancellation.clone());

    assert_eq!(
        elect_desired_guard_with_driver(&driver, &name, &labels, None, true, &cancellation)
            .await
            .unwrap_err()
            .code(),
        LocalInitErrorCode::Cancelled
    );
    {
        let state = driver.state.lock().unwrap();
        assert_eq!(state.creates.as_slice(), std::slice::from_ref(&name));
        assert!(state.guard.is_some());
    }

    let replay = CancellationToken::new();
    elect_desired_guard_with_driver(&driver, &name, &labels, None, true, &replay)
        .await
        .unwrap();
    assert_eq!(driver.state.lock().unwrap().creates, [name]);
}

#[tokio::test]
async fn volume_create_starts_no_mutation_after_the_last_verify_observes_cancellation() {
    let installation = installation();
    let name = volume_name(
        installation.compose_project().as_str(),
        VolumeRole::BootstrapState,
    );
    let labels = volume_labels(&installation, fingerprint(), VolumeRole::BootstrapState);
    let driver = FakeGuardDriver::default();
    let cancellation = CancellationToken::new();
    driver.state.lock().unwrap().cancel_on_verify = Some(cancellation.clone());

    assert_eq!(
        create_volume_after_preflight(&driver, &name, &labels, &cancellation)
            .await
            .unwrap_err()
            .code(),
        LocalInitErrorCode::Cancelled
    );
    let state = driver.state.lock().unwrap();
    assert!(state.creates.is_empty());
    assert!(state.guard.is_none());
}

#[tokio::test]
async fn desired_guard_requires_zero_running_or_stopped_attachments() {
    let installation = installation();
    let name = volume_name(installation.compose_project().as_str(), VolumeRole::Desired);
    let labels = volume_labels(&installation, fingerprint(), VolumeRole::Desired);
    let driver = FakeGuardDriver::default();
    {
        let mut state = driver.state.lock().unwrap();
        state.guard = Some(fake_volume(&name, &labels));
        state.attachments.push(CONTAINER_ID.to_owned());
    }

    assert_eq!(
        elect_desired_guard_with_driver(
            &driver,
            &name,
            &labels,
            None,
            true,
            &CancellationToken::new(),
        )
        .await
        .unwrap_err()
        .code(),
        LocalInitErrorCode::EngineResourceMismatch
    );
    assert!(driver.state.lock().unwrap().creates.is_empty());
}

#[tokio::test]
async fn desired_guard_adopts_only_the_preflight_pinned_stale_helper_attachment() {
    let installation = installation();
    let name = volume_name(installation.compose_project().as_str(), VolumeRole::Desired);
    let labels = volume_labels(&installation, fingerprint(), VolumeRole::Desired);
    let driver = FakeGuardDriver::default();
    {
        let mut state = driver.state.lock().unwrap();
        state.guard = Some(fake_volume(&name, &labels));
        state.attachments.push(CONTAINER_ID.to_owned());
    }
    elect_desired_guard_with_driver(
        &driver,
        &name,
        &labels,
        Some(CONTAINER_ID),
        true,
        &CancellationToken::new(),
    )
    .await
    .unwrap();

    assert_eq!(
        elect_desired_guard_with_driver(
            &driver,
            &name,
            &labels,
            Some("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
            true,
            &CancellationToken::new(),
        )
        .await
        .unwrap_err()
        .code(),
        LocalInitErrorCode::EngineResourceMismatch
    );

    let absent = FakeGuardDriver::default();
    assert_eq!(
        elect_desired_guard_with_driver(
            &absent,
            &name,
            &labels,
            Some(CONTAINER_ID),
            true,
            &CancellationToken::new(),
        )
        .await
        .unwrap_err()
        .code(),
        LocalInitErrorCode::EngineResourceMismatch
    );
    assert!(absent.state.lock().unwrap().creates.is_empty());
}

#[tokio::test]
async fn helper_recovery_is_not_invoked_until_desired_guard_attestation_succeeds() {
    let failed_state = Mutex::new((true, Vec::new()));
    let result = guard_then_recover(
        async {
            failed_state.lock().unwrap().1.push("guard");
            Err(engine_resource_mismatch())
        },
        || async {
            let mut state = failed_state.lock().unwrap();
            state.1.push("cleanup");
            state.0 = false;
            Ok(())
        },
    )
    .await;
    assert_eq!(
        result.unwrap_err().code(),
        LocalInitErrorCode::EngineResourceMismatch
    );
    assert_eq!(*failed_state.lock().unwrap(), (true, vec!["guard"]));

    let success_state = Mutex::new((true, Vec::new()));
    guard_then_recover(
        async {
            success_state.lock().unwrap().1.push("guard");
            Ok(())
        },
        || async {
            let mut state = success_state.lock().unwrap();
            state.1.push("cleanup");
            state.0 = false;
            Ok(())
        },
    )
    .await
    .unwrap();
    assert_eq!(
        *success_state.lock().unwrap(),
        (false, vec!["guard", "cleanup"])
    );
}

fn contract(installation: &Installation) -> HelperContract<'static> {
    let volumes = Box::leak(Box::new(volume_names(installation)));
    HelperContract {
        name: helper_name(installation),
        image: "registry.example.invalid/automata@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        image_id: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        volumes,
        labels: helper_labels(installation, fingerprint()),
        volume_labels: expected_volume_labels(installation, fingerprint()),
        baseline_attachments: BTreeMap::new(),
        mode: HelperMode::Mutating,
    }
}

fn valid_helper_inspect(
    contract: &HelperContract<'_>,
    container_id: &str,
) -> bollard::models::ContainerInspectResponse {
    let body = helper_body(
        contract.image,
        contract.volumes,
        &contract.labels,
        contract.mode,
    );
    let mut config: bollard::models::ContainerConfig =
        serde_json::from_value(serde_json::to_value(&body).unwrap()).unwrap();
    config.exposed_ports = Some(vec![HELPER_EXPOSED_PORT.to_owned()]);
    let mounts = contract
        .volumes
        .iter()
        .map(|(role, volume)| bollard::models::MountPoint {
            typ: Some("volume".to_owned()),
            name: Some(volume.clone()),
            destination: Some(role.mount_target()),
            driver: Some("local".to_owned()),
            rw: Some(true),
            ..Default::default()
        })
        .collect();
    bollard::models::ContainerInspectResponse {
        id: Some(container_id.to_owned()),
        name: Some(format!("/{}", contract.name)),
        image: Some(contract.image_id.to_owned()),
        platform: Some("linux".to_owned()),
        config: Some(config),
        host_config: body.host_config,
        mounts: Some(mounts),
        network_settings: Some(bollard::models::NetworkSettings {
            sandbox_id: Some(String::new()),
            sandbox_key: Some(String::new()),
            ports: Some(std::collections::HashMap::new()),
            networks: Some(std::collections::HashMap::new()),
        }),
        state: Some(bollard::models::ContainerState {
            running: Some(false),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn request(installation: &Installation) -> MaterializeRequest {
    let material_root = [7_u8; 32];
    let epoch = crate::init::epoch::certificate_test_epoch(installation, &material_root);
    let deriver = crate::init::epoch::MaterialDeriver::new(material_root, installation, &epoch);
    let certificates = crate::init::certificates::CertificateMaterial {
        ca_pem: "ca".to_owned(),
        ca_key_pem: Zeroizing::new("ca-key".to_owned()),
        postgres_chain_pem: "postgres-chain".to_owned(),
        postgres_key_pem: Zeroizing::new("postgres-key".to_owned()),
        object_chain_pem: "object-chain".to_owned(),
        object_key_pem: Zeroizing::new("object-key".to_owned()),
        runner_chain_pem: "runner-chain".to_owned(),
        runner_key_pem: Zeroizing::new("runner-key".to_owned()),
    };
    MaterializeRequest::build(&epoch, &deriver, &certificates, b"{}\n", true)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InjectedStage {
    Create,
    Attach,
    StoppedAttestation,
    Start,
    RunningAttestation,
    Request,
    Wait,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InjectedAction {
    Fail(InjectedStage),
    Cancel(InjectedStage),
    FailAndCancel(InjectedStage),
    None,
}

struct FakeHelperState {
    by_id: Option<bollard::models::ContainerInspectResponse>,
    by_name: Option<bollard::models::ContainerInspectResponse>,
    removed: Vec<String>,
    requests: Vec<Vec<u8>>,
    events: Vec<&'static str>,
    volumes: BTreeMap<String, bollard::models::Volume>,
    extra_attachment: bool,
    exit_on_request: bool,
    cleanup: CleanupBehavior,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanupBehavior {
    Succeeds,
    FailsBeforeApply,
    AppliesThenFails,
}

struct FakeHelperDriver {
    action: InjectedAction,
    cancellation: CancellationToken,
    response: Vec<u8>,
    template: bollard::models::ContainerInspectResponse,
    state: Mutex<FakeHelperState>,
}

struct LiveStdinHelperDriver {
    docker: Docker,
    truncate_request: bool,
    observed_stdout: Mutex<Vec<u8>>,
}

impl LiveStdinHelperDriver {
    async fn logs(&self, id: &str) -> Result<(Vec<u8>, Vec<u8>), LocalInitError> {
        let options = LogsOptionsBuilder::default()
            .follow(false)
            .stdout(true)
            .stderr(true)
            .timestamps(false)
            .tail("all")
            .build();
        let mut frames = self.docker.logs(id, Some(options));
        tokio::time::timeout(ENGINE_TIMEOUT, async {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            while let Some(frame) = frames.next().await {
                let frame = frame.map_err(|_| materialization_failed())?;
                let destination = match frame {
                    LogOutput::StdOut { .. } => &mut stdout,
                    LogOutput::StdErr { .. } => &mut stderr,
                    _ => return Err(materialization_failed()),
                };
                if frame.as_ref().len() > MAX_HELPER_LOG_BYTES.saturating_sub(destination.len()) {
                    return Err(materialization_failed());
                }
                destination.extend_from_slice(frame.as_ref());
            }
            Ok((stdout, stderr))
        })
        .await
        .map_err(|_| materialization_failed())?
    }
}

#[async_trait::async_trait]
impl HelperDriver for LiveStdinHelperDriver {
    async fn driver_verify(&self) -> Result<(), LocalInitError> {
        tokio::time::timeout(ENGINE_TIMEOUT, self.docker.ping())
            .await
            .map_err(|_| engine_unavailable())?
            .map(|_| ())
            .map_err(|_| engine_unavailable())
    }

    async fn driver_create(
        &self,
        name: &str,
        body: ContainerCreateBody,
    ) -> Result<HelperCreateResult, LocalInitError> {
        let options = CreateContainerOptionsBuilder::default()
            .name(name)
            .platform("linux/amd64")
            .build();
        let created = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.create_container(Some(options), body),
        )
        .await
        .map_err(|_| materialization_failed())?
        .map_err(|_| materialization_failed())?;
        Ok(HelperCreateResult {
            id: created.id,
            warnings: created.warnings,
        })
    }

    async fn driver_inspect(
        &self,
        target: &str,
    ) -> Result<Option<bollard::models::ContainerInspectResponse>, LocalInitError> {
        match tokio::time::timeout(ENGINE_TIMEOUT, self.docker.inspect_container(target, None))
            .await
        {
            Ok(Ok(container)) => Ok(Some(container)),
            Ok(Err(error)) if not_found(&error) => Ok(None),
            _ => Err(materialization_failed()),
        }
    }

    async fn driver_inspect_volume(
        &self,
        name: &str,
    ) -> Result<Option<bollard::models::Volume>, LocalInitError> {
        match tokio::time::timeout(ENGINE_TIMEOUT, self.docker.inspect_volume(name)).await {
            Ok(Ok(volume)) => Ok(Some(volume)),
            Ok(Err(error)) if not_found(&error) => Ok(None),
            _ => Err(materialization_failed()),
        }
    }

    async fn driver_attach(&self, id: &str) -> Result<HelperInput, LocalInitError> {
        let options = AttachContainerOptionsBuilder::default()
            .stdin(true)
            .stdout(false)
            .stderr(false)
            .stream(true)
            .logs(false)
            .build();
        let AttachContainerResults {
            output: _output,
            input,
        } = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.attach_container(id, Some(options)),
        )
        .await
        .map_err(|_| materialization_failed())?
        .map_err(|_| materialization_failed())?;
        Ok(input)
    }

    async fn driver_start(&self, id: &str) -> Result<(), LocalInitError> {
        tokio::time::timeout(ENGINE_TIMEOUT, self.docker.start_container(id, None))
            .await
            .map_err(|_| materialization_failed())?
            .map_err(|_| materialization_failed())
    }

    async fn driver_send_request(
        &self,
        input: &mut HelperInput,
        request: &[u8],
    ) -> Result<(), LocalInitError> {
        let request = if self.truncate_request {
            &request[..request.len() / 2]
        } else {
            request
        };
        tokio::time::timeout(ENGINE_TIMEOUT, async {
            input.write_all(request).await?;
            input.flush().await?;
            input.shutdown().await
        })
        .await
        .map_err(|_| materialization_failed())?
        .map_err(|_| materialization_failed())
    }

    async fn driver_wait(&self, id: &str) -> Result<HelperWaitResult, LocalInitError> {
        let mut wait_stream = self.docker.wait_container(
            id,
            Some(
                WaitContainerOptionsBuilder::default()
                    .condition("not-running")
                    .build(),
            ),
        );
        let result = tokio::time::timeout(HELPER_TIMEOUT, async {
            let result = wait_stream
                .next()
                .await
                .ok_or_else(materialization_failed)?
                .map_err(|_| materialization_failed())?;
            if wait_stream.next().await.is_some() {
                return Err(materialization_failed());
            }
            Ok(result)
        })
        .await
        .map_err(|_| materialization_failed())??;
        if self.truncate_request {
            let (stdout, _stderr) = self.logs(id).await?;
            *self.observed_stdout.lock().unwrap() = stdout;
        }
        Ok(HelperWaitResult {
            status_code: result.status_code,
            has_error: result.error.is_some(),
        })
    }

    async fn driver_logs(&self, id: &str) -> Result<(Vec<u8>, Vec<u8>), LocalInitError> {
        self.logs(id).await
    }

    async fn driver_force_remove(&self, id: &str) -> Result<(), LocalInitError> {
        let options = RemoveContainerOptionsBuilder::default()
            .force(true)
            .v(false)
            .link(false)
            .build();
        match tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.remove_container(id, Some(options)),
        )
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) if not_found(&error) => Ok(()),
            _ => Err(materialization_failed()),
        }
    }

    async fn driver_volume_attachments(&self, name: &str) -> Result<Vec<String>, LocalInitError> {
        let filters = HashMap::from([("volume", vec![name])]);
        let options = ListContainersOptionsBuilder::default()
            .all(true)
            .filters(&filters)
            .build();
        let containers =
            tokio::time::timeout(ENGINE_TIMEOUT, self.docker.list_containers(Some(options)))
                .await
                .map_err(|_| materialization_failed())?
                .map_err(|_| materialization_failed())?;
        containers
            .into_iter()
            .map(|container| container.id.ok_or_else(materialization_failed))
            .collect()
    }
}

struct LiveStdinCleanup {
    docker_command: String,
    container: Option<String>,
    volumes: Vec<String>,
    state_directory: PathBuf,
}

impl LiveStdinCleanup {
    fn remove(&mut self) {
        if let Some(container) = self.container.take() {
            let _ = Command::new(&self.docker_command)
                .args([
                    "--host",
                    "unix:///var/run/docker.sock",
                    "container",
                    "rm",
                    "--force",
                    &container,
                ])
                .output();
        }
        for volume in &self.volumes {
            let _ = Command::new(&self.docker_command)
                .args([
                    "--host",
                    "unix:///var/run/docker.sock",
                    "volume",
                    "rm",
                    "--force",
                    volume,
                ])
                .output();
        }
        self.volumes.clear();
        let _ = fs::remove_dir_all(&self.state_directory);
    }
}

impl Drop for LiveStdinCleanup {
    fn drop(&mut self) {
        self.remove();
    }
}

impl FakeHelperDriver {
    fn new(
        action: InjectedAction,
        cancellation: CancellationToken,
        contract: &HelperContract<'_>,
    ) -> Self {
        let response = MaterializeResponse {
            schema: RESPONSE_SCHEMA.to_owned(),
            epoch_fingerprint: fingerprint(),
            sealed_static_volumes: 4,
        };
        let mut response = serde_json::to_vec(&response).unwrap();
        response.push(b'\n');
        let volumes = contract
            .volumes
            .iter()
            .map(|(role, name)| {
                (
                    name.clone(),
                    fake_volume(name, contract.volume_labels.get(role).unwrap()),
                )
            })
            .collect();
        Self {
            action,
            cancellation,
            response,
            template: valid_helper_inspect(contract, CONTAINER_ID),
            state: Mutex::new(FakeHelperState {
                by_id: None,
                by_name: None,
                removed: Vec::new(),
                requests: Vec::new(),
                events: Vec::new(),
                volumes,
                extra_attachment: false,
                exit_on_request: false,
                cleanup: CleanupBehavior::Succeeds,
            }),
        }
    }

    async fn inject(&self, stage: InjectedStage) -> Result<(), LocalInitError> {
        match self.action {
            InjectedAction::Fail(expected) if expected == stage => Err(materialization_failed()),
            InjectedAction::Cancel(expected) if expected == stage => {
                self.cancellation.cancel();
                tokio::task::yield_now().await;
                Ok(())
            }
            InjectedAction::FailAndCancel(expected) if expected == stage => {
                self.cancellation.cancel();
                tokio::task::yield_now().await;
                Err(materialization_failed())
            }
            _ => Ok(()),
        }
    }

    fn assert_cleaned(&self) {
        let state = self.state.lock().unwrap();
        assert!(state.by_id.is_none());
        assert!(state.by_name.is_none());
        assert_eq!(state.removed, [CONTAINER_ID]);
    }
}

#[tokio::test]
async fn operation_error_survives_latched_cancellation_after_exact_cleanup() {
    let installation = installation();
    let contract = contract(&installation);
    let request = request(&installation);
    let cancellation = CancellationToken::new();
    let driver = FakeHelperDriver::new(
        InjectedAction::FailAndCancel(InjectedStage::Request),
        cancellation.clone(),
        &contract,
    );
    let result = super::super::cancellation_bounded(
        &cancellation,
        run_materializer_with_driver(&driver, &contract, &request, fingerprint(), &cancellation),
    )
    .await;
    assert_eq!(
        result.unwrap_err().code(),
        LocalInitErrorCode::MaterializationFailed
    );
    driver.assert_cleaned();
}

#[async_trait::async_trait]
impl HelperDriver for FakeHelperDriver {
    async fn driver_verify(&self) -> Result<(), LocalInitError> {
        Ok(())
    }

    async fn driver_create(
        &self,
        _name: &str,
        _body: ContainerCreateBody,
    ) -> Result<HelperCreateResult, LocalInitError> {
        {
            let mut state = self.state.lock().unwrap();
            state.events.push("create");
            state.by_id = Some(self.template.clone());
            state.by_name = Some(self.template.clone());
        }
        self.inject(InjectedStage::Create).await?;
        Ok(HelperCreateResult {
            id: CONTAINER_ID.to_owned(),
            warnings: Vec::new(),
        })
    }

    async fn driver_inspect(
        &self,
        target: &str,
    ) -> Result<Option<bollard::models::ContainerInspectResponse>, LocalInitError> {
        let state = self.state.lock().unwrap();
        if target == CONTAINER_ID {
            Ok(state.by_id.clone())
        } else {
            Ok(state.by_name.clone())
        }
    }

    async fn driver_attach(&self, id: &str) -> Result<HelperInput, LocalInitError> {
        assert_eq!(id, CONTAINER_ID);
        self.state.lock().unwrap().events.push("attach");
        self.inject(InjectedStage::Attach).await?;
        Ok(Box::pin(tokio::io::sink()))
    }

    async fn driver_inspect_volume(
        &self,
        name: &str,
    ) -> Result<Option<bollard::models::Volume>, LocalInitError> {
        let (volume, injected_stage) = {
            let state = self.state.lock().unwrap();
            let injected_stage = if state.events.contains(&"start")
                && !state.events.contains(&"write-flush-shutdown")
            {
                Some(InjectedStage::RunningAttestation)
            } else if state.events.contains(&"attach") && !state.events.contains(&"start") {
                Some(InjectedStage::StoppedAttestation)
            } else {
                None
            };
            (state.volumes.get(name).cloned(), injected_stage)
        };
        if let Some(injected_stage) = injected_stage {
            self.inject(injected_stage).await?;
        }
        Ok(volume)
    }

    async fn driver_start(&self, id: &str) -> Result<(), LocalInitError> {
        assert_eq!(id, CONTAINER_ID);
        self.state.lock().unwrap().events.push("start");
        self.inject(InjectedStage::Start).await?;
        let mut state = self.state.lock().unwrap();
        if let Some(container) = state.by_id.as_mut() {
            container.state.as_mut().unwrap().running = Some(true);
        }
        if let Some(container) = state.by_name.as_mut() {
            container.state.as_mut().unwrap().running = Some(true);
        }
        Ok(())
    }

    async fn driver_send_request(
        &self,
        _input: &mut HelperInput,
        request: &[u8],
    ) -> Result<(), LocalInitError> {
        assert!(!request.is_empty());
        {
            let mut state = self.state.lock().unwrap();
            state.events.push("write-flush-shutdown");
            state.requests.push(request.to_vec());
        }
        self.inject(InjectedStage::Request).await?;
        let mut state = self.state.lock().unwrap();
        if state.exit_on_request {
            if let Some(container) = state.by_id.as_mut() {
                container.state.as_mut().unwrap().running = Some(false);
            }
            if let Some(container) = state.by_name.as_mut() {
                container.state.as_mut().unwrap().running = Some(false);
            }
        }
        Ok(())
    }

    async fn driver_wait(&self, id: &str) -> Result<HelperWaitResult, LocalInitError> {
        assert_eq!(id, CONTAINER_ID);
        self.state.lock().unwrap().events.push("wait");
        self.inject(InjectedStage::Wait).await?;
        let mut state = self.state.lock().unwrap();
        if let Some(container) = state.by_id.as_mut() {
            container.state.as_mut().unwrap().running = Some(false);
        }
        if let Some(container) = state.by_name.as_mut() {
            container.state.as_mut().unwrap().running = Some(false);
        }
        Ok(HelperWaitResult {
            status_code: 0,
            has_error: false,
        })
    }

    async fn driver_logs(&self, id: &str) -> Result<(Vec<u8>, Vec<u8>), LocalInitError> {
        assert_eq!(id, CONTAINER_ID);
        Ok((self.response.clone(), Vec::new()))
    }

    async fn driver_force_remove(&self, id: &str) -> Result<(), LocalInitError> {
        let mut state = self.state.lock().unwrap();
        state.events.push("remove");
        if state.cleanup == CleanupBehavior::FailsBeforeApply {
            return Err(materialization_failed());
        }
        assert_eq!(id, CONTAINER_ID);
        state.removed.push(id.to_owned());
        state.by_id = None;
        if state
            .by_name
            .as_ref()
            .and_then(|container| container.id.as_deref())
            == Some(id)
        {
            state.by_name = None;
        }
        if state.cleanup == CleanupBehavior::AppliesThenFails {
            Err(materialization_failed())
        } else {
            Ok(())
        }
    }

    async fn driver_volume_attachments(&self, _name: &str) -> Result<Vec<String>, LocalInitError> {
        let state = self.state.lock().unwrap();
        let mut attachments = Vec::new();
        if state.by_id.is_some() {
            attachments.push(CONTAINER_ID.to_owned());
        }
        if state.extra_attachment {
            attachments.push(
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_owned(),
            );
        }
        Ok(attachments)
    }
}

#[tokio::test]
async fn helper_request_transport_is_attach_then_start_then_eof_before_wait_and_cleanup() {
    let installation = installation();
    let contract = contract(&installation);
    let request = request(&installation);
    let expected_request = request.canonical_bytes().unwrap();
    let cancellation = CancellationToken::new();
    let driver = FakeHelperDriver::new(InjectedAction::None, cancellation.clone(), &contract);

    run_materializer_with_driver(&driver, &contract, &request, fingerprint(), &cancellation)
        .await
        .unwrap();

    let state = driver.state.lock().unwrap();
    assert_eq!(
        state.events,
        [
            "create",
            "attach",
            "start",
            "write-flush-shutdown",
            "wait",
            "remove"
        ]
    );
    assert_eq!(state.requests, [expected_request]);
    assert!(state.by_id.is_none());
    assert!(state.by_name.is_none());
}

#[tokio::test]
async fn lifecycle_attestation_preserves_exact_preexisting_volume_attachments() {
    let installation = installation();
    let mut contract = contract(&installation);
    let existing = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_owned();
    contract.baseline_attachments = VolumeRole::ALL
        .into_iter()
        .map(|role| (role, BTreeSet::from([existing.clone()])))
        .collect();
    let request = request(&installation);
    let cancellation = CancellationToken::new();
    let driver = FakeHelperDriver::new(InjectedAction::None, cancellation.clone(), &contract);
    driver.state.lock().unwrap().extra_attachment = true;

    run_materializer_with_driver(&driver, &contract, &request, fingerprint(), &cancellation)
        .await
        .unwrap();

    let state = driver.state.lock().unwrap();
    assert!(state.by_id.is_none());
    assert!(state.by_name.is_none());
    assert!(state.extra_attachment);
    assert_eq!(state.removed, [CONTAINER_ID]);
}

#[tokio::test]
async fn helper_may_exit_immediately_after_request_eof_before_wait_observes_it() {
    let installation = installation();
    let contract = contract(&installation);
    let request = request(&installation);
    let cancellation = CancellationToken::new();
    let driver = FakeHelperDriver::new(InjectedAction::None, cancellation.clone(), &contract);
    driver.state.lock().unwrap().exit_on_request = true;

    run_materializer_with_driver(&driver, &contract, &request, fingerprint(), &cancellation)
        .await
        .unwrap();

    let state = driver.state.lock().unwrap();
    assert_eq!(
        state.events,
        [
            "create",
            "attach",
            "start",
            "write-flush-shutdown",
            "wait",
            "remove"
        ]
    );
    assert!(state.by_id.is_none());
    assert!(state.by_name.is_none());
}

#[tokio::test]
async fn cancellation_during_helper_reattestation_starts_no_later_mutation() {
    for (stage, expected_events) in [
        (
            InjectedStage::StoppedAttestation,
            vec!["create", "attach", "remove"],
        ),
        (
            InjectedStage::RunningAttestation,
            vec!["create", "attach", "start", "remove"],
        ),
    ] {
        let installation = installation();
        let contract = contract(&installation);
        let request = request(&installation);
        let cancellation = CancellationToken::new();
        let driver = FakeHelperDriver::new(
            InjectedAction::Cancel(stage),
            cancellation.clone(),
            &contract,
        );

        let result = run_materializer_with_driver(
            &driver,
            &contract,
            &request,
            fingerprint(),
            &cancellation,
        )
        .await;

        assert_eq!(result.unwrap_err().code(), LocalInitErrorCode::Cancelled);
        let state = driver.state.lock().unwrap();
        assert_eq!(
            state.events, expected_events,
            "unexpected trace for {stage:?}"
        );
        assert!(state.requests.is_empty());
        assert!(state.by_id.is_none());
        assert!(state.by_name.is_none());
    }
}

#[tokio::test]
#[ignore = "requires an explicitly supplied digest-pinned Automata image and rootful Docker at the fixed init socket"]
#[allow(clippy::too_many_lines)]
async fn live_read_only_helper_consumes_stdin_eof_and_rejects_a_truncated_prefix_before_sealing() {
    use sha2::{Digest as _, Sha256};

    let image = std::env::var("AUTOMATA_LOCAL_INIT_TEST_MATERIALIZER_IMAGE")
        .expect("set the exact digest-pinned local Automata materializer image");
    let digest = image
        .rsplit_once("@sha256:")
        .map(|(_, digest)| digest)
        .expect("the live materializer image must be digest pinned");
    assert!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    let docker = Docker::connect_with_unix(
        "unix:///var/run/docker.sock",
        ENGINE_TIMEOUT.as_secs(),
        bollard::API_DEFAULT_VERSION,
    )
    .expect("the fixed init Docker socket must be available");
    docker
        .ping()
        .await
        .expect("the fixed init Docker daemon must answer");
    let image_id = docker
        .inspect_image(&image)
        .await
        .expect("the authorized materializer image must already be present")
        .id
        .expect("the authorized materializer image must expose its exact ID");

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let installation_name: InstallationName = format!("stdin-live-{}-{nonce}", std::process::id())
        .parse()
        .unwrap();
    let installation = Installation::verified(installation_name, InstallationId::new());
    let names = volume_names(&installation);
    let helper_name = helper_name(&installation);
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap();
    let scratch = workspace.join("target/task-tmp/automata-ci-local");
    fs::create_dir_all(&scratch).unwrap();
    let state_directory = scratch.join(format!("stdin-live-{}-{nonce}", std::process::id()));
    fs::create_dir(&state_directory).unwrap();
    fs::set_permissions(&state_directory, fs::Permissions::from_mode(0o700)).unwrap();
    let mut cleanup = LiveStdinCleanup {
        docker_command: std::env::var("AUTOMATA_LOCAL_INIT_TEST_DOCKER")
            .unwrap_or_else(|_| "docker".to_owned()),
        container: None,
        volumes: Vec::new(),
        state_directory: state_directory.clone(),
    };

    assert!(
        matches!(
            docker.inspect_container(&helper_name, None).await,
            Err(ref error) if not_found(error)
        ),
        "the unique live helper fixture must not preexist"
    );
    cleanup.container = Some(helper_name.clone());

    let desired = b"{}\n";
    let desired_sha256 = Sha256Digest::from_bytes(Sha256::digest(desired).into());
    let material_root = [0x42; 32];
    let state = super::super::state::StateRoot::acquire(&state_directory.join("state")).unwrap();
    let (catalog, _, _) = candidate_fixture();
    let epoch = super::super::epoch::ImmutableEpoch::new(
        &catalog,
        &installation,
        1,
        state.authority_sha256(),
        &material_root,
        desired_sha256,
        Sha256Digest::from_bytes([0x51; 32]),
    );
    for (role, name) in &names {
        assert!(
            matches!(
                docker.inspect_volume(name).await,
                Err(ref error) if not_found(error)
            ),
            "the unique live volume fixture must not preexist"
        );
        cleanup.volumes.push(name.clone());
        let labels = volume_labels(&installation, epoch.fingerprint(), *role);
        docker
            .create_volume(VolumeCreateRequest {
                name: Some(name.clone()),
                driver: Some("local".to_owned()),
                driver_opts: Some(HashMap::new()),
                labels: Some(labels.clone().into_iter().collect()),
                cluster_volume_spec: None,
            })
            .await
            .unwrap();
        let volume = docker.inspect_volume(name).await.unwrap();
        validate_volume(&volume, name, &labels).unwrap();
    }

    let deriver = super::super::epoch::MaterialDeriver::new(material_root, &installation, &epoch);
    let certificates =
        super::super::certificates::load_or_issue(&state, &deriver, &epoch, false).unwrap();
    let request = MaterializeRequest::build(&epoch, &deriver, &certificates, desired, true);
    let contract = HelperContract {
        name: helper_name.clone(),
        image: &image,
        image_id: &image_id,
        volumes: &names,
        labels: helper_labels(&installation, epoch.fingerprint()),
        volume_labels: expected_volume_labels(&installation, epoch.fingerprint()),
        baseline_attachments: BTreeMap::new(),
        mode: HelperMode::Mutating,
    };
    let cancellation = CancellationToken::new();

    let truncated = LiveStdinHelperDriver {
        docker: docker.clone(),
        truncate_request: true,
        observed_stdout: Mutex::new(Vec::new()),
    };
    let result = run_materializer_with_driver(
        &truncated,
        &contract,
        &request,
        epoch.fingerprint(),
        &cancellation,
    )
    .await;
    assert_eq!(
        result.unwrap_err().code(),
        LocalInitErrorCode::MaterializationFailed
    );
    assert!(truncated.observed_stdout.lock().unwrap().is_empty());
    assert!(
        truncated
            .driver_inspect(&helper_name)
            .await
            .unwrap()
            .is_none()
    );
    for name in names.values() {
        assert!(
            truncated
                .driver_volume_attachments(name)
                .await
                .unwrap()
                .is_empty()
        );
    }

    // Exact success on the same fresh roots proves that the rejected prefix did
    // not leave conflicting target-volume evidence before canonical parsing.
    let complete = LiveStdinHelperDriver {
        docker,
        truncate_request: false,
        observed_stdout: Mutex::new(Vec::new()),
    };
    run_materializer_with_driver(
        &complete,
        &contract,
        &request,
        epoch.fingerprint(),
        &cancellation,
    )
    .await
    .unwrap();
    assert!(
        complete
            .driver_inspect(&helper_name)
            .await
            .unwrap()
            .is_none()
    );
    for name in names.values() {
        assert!(
            complete
                .driver_volume_attachments(name)
                .await
                .unwrap()
                .is_empty()
        );
    }

    drop(state);
    cleanup.remove();
}

#[tokio::test]
async fn replaced_volume_or_foreign_attachment_blocks_secrets_and_cleans_the_pinned_helper() {
    for foreign_attachment in [false, true] {
        let installation = installation();
        let contract = contract(&installation);
        let request = request(&installation);
        let cancellation = CancellationToken::new();
        let driver = FakeHelperDriver::new(InjectedAction::None, cancellation.clone(), &contract);
        {
            let mut state = driver.state.lock().unwrap();
            if foreign_attachment {
                state.extra_attachment = true;
            } else {
                let desired = contract.volumes.get(&VolumeRole::Desired).unwrap();
                state.volumes.get_mut(desired).unwrap().labels.insert(
                    "io.automata.local.volume-role".to_owned(),
                    "replacement".to_owned(),
                );
            }
        }

        let result = run_materializer_with_driver(
            &driver,
            &contract,
            &request,
            fingerprint(),
            &cancellation,
        )
        .await;
        assert_eq!(
            result.unwrap_err().code(),
            LocalInitErrorCode::MaterializationFailed
        );
        let state = driver.state.lock().unwrap();
        assert!(!state.events.contains(&"write-flush-shutdown"));
        assert_eq!(state.removed, [CONTAINER_ID]);
        assert!(state.by_id.is_none());
    }
}

#[tokio::test]
async fn every_mutating_stage_failure_and_cancellation_exactly_cleans_the_pinned_helper() {
    for stage in [
        InjectedStage::Create,
        InjectedStage::Attach,
        InjectedStage::Start,
        InjectedStage::Request,
        InjectedStage::Wait,
    ] {
        for cancellation_case in [false, true] {
            let installation = installation();
            let contract = contract(&installation);
            let request = request(&installation);
            let cancellation = CancellationToken::new();
            let action = if cancellation_case {
                InjectedAction::Cancel(stage)
            } else {
                InjectedAction::Fail(stage)
            };
            let driver = FakeHelperDriver::new(action, cancellation.clone(), &contract);
            let result = super::super::cancellation_bounded(
                &cancellation,
                run_materializer_with_driver(
                    &driver,
                    &contract,
                    &request,
                    fingerprint(),
                    &cancellation,
                ),
            )
            .await;
            assert_eq!(
                result.unwrap_err().code(),
                if cancellation_case {
                    LocalInitErrorCode::Cancelled
                } else {
                    LocalInitErrorCode::MaterializationFailed
                },
                "unexpected result for {action:?}"
            );
            driver.assert_cleaned();
        }
    }
}

#[tokio::test]
async fn cleanup_failure_dominates_latched_cancellation() {
    let installation = installation();
    let contract = contract(&installation);
    let request = request(&installation);
    let cancellation = CancellationToken::new();
    let driver = FakeHelperDriver::new(
        InjectedAction::Cancel(InjectedStage::Start),
        cancellation.clone(),
        &contract,
    );
    driver.state.lock().unwrap().cleanup = CleanupBehavior::FailsBeforeApply;
    let result = super::super::cancellation_bounded(
        &cancellation,
        run_materializer_with_driver(&driver, &contract, &request, fingerprint(), &cancellation),
    )
    .await;
    assert_eq!(
        result.unwrap_err().code(),
        LocalInitErrorCode::MaterializationFailed
    );
    let state = driver.state.lock().unwrap();
    assert!(state.by_id.is_some());
    assert!(state.by_name.is_some());
    assert!(state.removed.is_empty());
}

#[tokio::test]
async fn reset_helper_cleanup_accepts_an_applied_ambiguous_remove_after_exact_absence_proof() {
    let installation = installation();
    let contract = contract(&installation);
    let driver = FakeHelperDriver::new(InjectedAction::None, CancellationToken::new(), &contract);
    {
        let mut state = driver.state.lock().unwrap();
        state.by_id = Some(driver.template.clone());
        state.by_name = Some(driver.template.clone());
        state.cleanup = CleanupBehavior::AppliesThenFails;
    }

    cleanup_reset_helper_with_driver(&driver, &contract, CONTAINER_ID)
        .await
        .unwrap();
    driver.assert_cleaned();
}

#[tokio::test]
async fn divergent_name_and_id_custody_removes_only_the_pinned_helper_and_fails_closed() {
    let installation = installation();
    let contract = contract(&installation);
    let cancellation = CancellationToken::new();
    let driver = FakeHelperDriver::new(InjectedAction::None, cancellation, &contract);
    let replacement_id = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let mut replacement = valid_helper_inspect(&contract, replacement_id);
    replacement.id = Some(replacement_id.to_owned());
    {
        let mut state = driver.state.lock().unwrap();
        state.by_id = Some(valid_helper_inspect(&contract, CONTAINER_ID));
        state.by_name = Some(replacement);
    }

    assert_eq!(
        cleanup_helper(&driver, &contract, Some(CONTAINER_ID))
            .await
            .unwrap_err()
            .code(),
        LocalInitErrorCode::MaterializationFailed
    );
    let state = driver.state.lock().unwrap();
    assert_eq!(state.removed, [CONTAINER_ID]);
    assert!(state.by_id.is_none());
    assert_eq!(
        state.by_name.as_ref().unwrap().id.as_deref(),
        Some(replacement_id)
    );
}

#[test]
fn helper_container_ids_are_exact_lowercase_full_hex() {
    assert!(exact_container_id_text(CONTAINER_ID));
    for invalid in [
        "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
    ] {
        assert!(!exact_container_id_text(invalid));
    }
}

#[test]
fn persistent_volume_contract_has_twelve_owner_specific_roles_and_no_plan_binding() {
    let installation = installation();
    let names = volume_names(&installation);
    assert_eq!(names.len(), 12);
    assert_eq!(names.keys().copied().collect::<Vec<_>>(), VolumeRole::ALL);
    assert_eq!(
        INIT_VOLUME_ORDER,
        [
            VolumeRole::Desired,
            VolumeRole::BootstrapState,
            VolumeRole::ControlMaterial,
            VolumeRole::EngineRelay,
            VolumeRole::ObjectData,
            VolumeRole::PostgresConfig,
            VolumeRole::PostgresData,
            VolumeRole::RelayBinding,
            VolumeRole::RunnerConfig,
            VolumeRole::RunnerData,
            VolumeRole::RunnerSecrets,
            VolumeRole::RustfsConfig,
        ]
    );

    for role in VolumeRole::ALL {
        let name = names.get(&role).unwrap();
        assert_eq!(
            name,
            &volume_name(installation.compose_project().as_str(), role)
        );
        let labels = volume_labels(&installation, fingerprint(), role);
        assert_eq!(labels.len(), 9);
        assert_eq!(labels["io.automata.local.volume-role"], role.name());
        assert_eq!(
            labels["io.automata.local.epoch-fingerprint"],
            fingerprint().to_string()
        );
        assert!(!labels.keys().any(|key| key.contains("plan")));
        assert!(!labels.keys().any(|key| key.contains("desired")));
    }
}

#[test]
fn fixed_helper_body_has_no_ambient_authority_or_extensible_inputs() {
    let installation = installation();
    let names = volume_names(&installation);
    let labels = helper_labels(&installation, fingerprint());
    let image = "registry.example.invalid/automata@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let body = helper_body(image, &names, &labels, HelperMode::Mutating);
    let request_bytes = request(&installation).canonical_bytes().unwrap();
    assert!(
        request_bytes
            .windows(b"ca-key".len())
            .any(|part| part == b"ca-key")
    );
    let body_bytes = serde_json::to_vec(&body).unwrap();
    assert!(
        !body_bytes
            .windows(b"ca-key".len())
            .any(|part| part == b"ca-key")
    );
    assert_eq!(body.user.as_deref(), Some("0:0"));
    assert_eq!(body.attach_stdin, Some(true));
    assert_eq!(body.open_stdin, Some(true));
    assert_eq!(body.stdin_once, Some(true));
    assert_eq!(body.image.as_deref(), Some(image));
    assert_eq!(body.working_dir.as_deref(), Some("/"));
    assert_eq!(
        body.entrypoint.as_deref(),
        Some(["/usr/local/bin/automata".to_owned()].as_slice())
    );
    assert_eq!(
        body.cmd.as_deref(),
        Some(
            [
                "internal".to_owned(),
                "local".to_owned(),
                "materialize".to_owned(),
            ]
            .as_slice()
        )
    );
    assert_eq!(body.env.as_deref(), Some([].as_slice()));
    assert_eq!(body.network_disabled, Some(true));
    assert_eq!(body.attach_stdout, Some(false));
    assert_eq!(body.attach_stderr, Some(false));
    assert_eq!(body.tty, Some(false));

    let host = body.host_config.unwrap();
    assert_eq!(host.network_mode.as_deref(), Some("none"));
    assert_eq!(host.readonly_rootfs, Some(true));
    assert_eq!(host.privileged, None);
    assert_eq!(host.auto_remove, Some(false));
    assert_eq!(
        host.cap_drop.as_deref(),
        Some(["ALL".to_owned()].as_slice())
    );
    assert_eq!(
        host.cap_add.as_deref(),
        Some(["CHOWN".to_owned(), "DAC_OVERRIDE".to_owned()].as_slice())
    );
    assert_eq!(host.security_opt, Some(helper_security_options()));
    assert!(host.tmpfs.as_ref().is_none_or(HashMap::is_empty));
    assert!(host.binds.as_ref().is_none_or(Vec::is_empty));

    let mounts = host.mounts.unwrap();
    assert_eq!(mounts.len(), 12);
    let targets = mounts
        .iter()
        .map(|mount| mount.target.as_deref().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(targets.len(), 12);
    assert_eq!(
        targets,
        VolumeRole::ALL
            .into_iter()
            .map(VolumeRole::mount_target)
            .collect::<BTreeSet<_>>()
            .iter()
            .map(String::as_str)
            .collect()
    );
    for mount in mounts {
        assert_eq!(mount.typ, Some(MountType::VOLUME));
        assert_eq!(mount.read_only, Some(false));
        assert_eq!(mount.volume_options.unwrap().no_copy, Some(true));
        assert!(
            names
                .values()
                .any(|name| Some(name) == mount.source.as_ref())
        );
    }
}

#[test]
fn materializer_response_is_canonical_bounded_and_epoch_bound() {
    let response = MaterializeResponse {
        schema: RESPONSE_SCHEMA.to_owned(),
        epoch_fingerprint: fingerprint(),
        sealed_static_volumes: 4,
    };
    let mut bytes = serde_json::to_vec(&response).unwrap();
    bytes.push(b'\n');
    validate_response(&bytes, b"", fingerprint()).unwrap();

    assert_eq!(
        validate_response(&bytes, b"warning", fingerprint())
            .unwrap_err()
            .code(),
        LocalInitErrorCode::MaterializationFailed
    );
    let other = Sha256Digest::from_bytes([0xa5; 32]);
    assert_eq!(
        validate_response(&bytes, b"", other).unwrap_err().code(),
        LocalInitErrorCode::MaterializationFailed
    );
    let mut noncanonical = bytes.clone();
    noncanonical.insert(0, b' ');
    assert_eq!(
        validate_response(&noncanonical, b"", fingerprint())
            .unwrap_err()
            .code(),
        LocalInitErrorCode::MaterializationFailed
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn helper_inspect_recovery_rejects_ambient_authority_and_realized_networks() {
    let installation = installation();
    let names = volume_names(&installation);
    let labels = helper_labels(&installation, fingerprint());
    let image = "registry.example.invalid/automata@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let image_id = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let name = helper_name(&installation);
    let body = helper_body(image, &names, &labels, HelperMode::Mutating);
    let mut config: bollard::models::ContainerConfig =
        serde_json::from_value(serde_json::to_value(&body).unwrap()).unwrap();
    config.exposed_ports = Some(vec![HELPER_EXPOSED_PORT.to_owned()]);
    let mounts = names
        .iter()
        .map(|(role, volume)| bollard::models::MountPoint {
            typ: Some("volume".to_owned()),
            name: Some(volume.clone()),
            destination: Some(role.mount_target()),
            driver: Some("local".to_owned()),
            rw: Some(true),
            ..Default::default()
        })
        .collect();
    let mut inspect = bollard::models::ContainerInspectResponse {
        id: Some("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned()),
        name: Some(format!("/{name}")),
        image: Some(image_id.to_owned()),
        platform: Some("linux".to_owned()),
        config: Some(config),
        host_config: body.host_config,
        mounts: Some(mounts),
        network_settings: Some(bollard::models::NetworkSettings {
            sandbox_id: Some(String::new()),
            sandbox_key: Some(String::new()),
            ports: Some(std::collections::HashMap::new()),
            networks: Some(std::collections::HashMap::new()),
        }),
        ..Default::default()
    };
    let container_id = inspect.id.as_deref().unwrap();
    validate_helper(
        &inspect,
        container_id,
        &name,
        image,
        image_id,
        &names,
        &labels,
    )
    .unwrap();

    inspect
        .config
        .as_mut()
        .unwrap()
        .labels
        .as_mut()
        .unwrap()
        .insert(
            COMPOSE_PROJECT_LABEL.to_owned(),
            installation.compose_project().to_string(),
        );
    validate_helper(
        &inspect,
        container_id,
        &name,
        image,
        image_id,
        &names,
        &labels,
    )
    .unwrap();
    inspect
        .config
        .as_mut()
        .unwrap()
        .labels
        .as_mut()
        .unwrap()
        .insert(
            COMPOSE_PROJECT_LABEL.to_owned(),
            "some-other-project".to_owned(),
        );
    assert_eq!(
        validate_helper(
            &inspect,
            container_id,
            &name,
            image,
            image_id,
            &names,
            &labels,
        )
        .unwrap_err()
        .code(),
        LocalInitErrorCode::MaterializationFailed
    );
    inspect
        .config
        .as_mut()
        .unwrap()
        .labels
        .as_mut()
        .unwrap()
        .remove(COMPOSE_PROJECT_LABEL);

    inspect.host_config.as_mut().unwrap().pid_mode = Some("host".to_owned());
    assert_eq!(
        validate_helper(
            &inspect,
            container_id,
            &name,
            image,
            image_id,
            &names,
            &labels,
        )
        .unwrap_err()
        .code(),
        LocalInitErrorCode::MaterializationFailed
    );
    inspect.host_config.as_mut().unwrap().pid_mode = None;
    inspect
        .network_settings
        .as_mut()
        .unwrap()
        .networks
        .as_mut()
        .unwrap()
        .insert(
            "bridge".to_owned(),
            bollard::models::EndpointSettings::default(),
        );
    assert_eq!(
        validate_helper(
            &inspect,
            container_id,
            &name,
            image,
            image_id,
            &names,
            &labels,
        )
        .unwrap_err()
        .code(),
        LocalInitErrorCode::MaterializationFailed
    );
}

#[derive(Default)]
struct FakeOwnedUnionDriver {
    warnings: bool,
    volumes: Vec<bollard::models::Volume>,
    second_volume_list: Option<Vec<bollard::models::Volume>>,
    volume_list_calls: AtomicUsize,
    containers: Vec<bollard::models::ContainerSummary>,
    networks: Vec<bollard::models::Network>,
    inspected_volumes: Option<HashMap<String, bollard::models::Volume>>,
    attachments: HashMap<String, Vec<String>>,
    later_mutations: Mutex<usize>,
}

#[async_trait::async_trait]
impl OwnedUnionDriver for FakeOwnedUnionDriver {
    async fn list_owned_union_volumes(&self) -> Result<OwnedUnionVolumes, LocalInitError> {
        let list_call = self.volume_list_calls.fetch_add(1, Ordering::SeqCst);
        let volumes = if list_call == 0 {
            &self.volumes
        } else {
            self.second_volume_list.as_ref().unwrap_or(&self.volumes)
        };
        Ok(OwnedUnionVolumes {
            warnings: self.warnings,
            volumes: volumes.clone(),
        })
    }

    async fn list_owned_union_containers(
        &self,
    ) -> Result<Vec<bollard::models::ContainerSummary>, LocalInitError> {
        Ok(self.containers.clone())
    }

    async fn list_owned_union_networks(
        &self,
    ) -> Result<Vec<bollard::models::Network>, LocalInitError> {
        Ok(self.networks.clone())
    }
}

#[async_trait::async_trait]
impl OwnedVolumeDriver for FakeOwnedUnionDriver {
    async fn inspect_owned_volume(
        &self,
        name: &str,
    ) -> Result<Option<bollard::models::Volume>, LocalInitError> {
        if let Some(volumes) = self.inspected_volumes.as_ref() {
            return Ok(volumes.get(name).cloned());
        }
        Ok(self
            .volumes
            .iter()
            .find(|volume| volume.name == name)
            .cloned())
    }

    async fn owned_volume_attachments(&self, name: &str) -> Result<Vec<String>, LocalInitError> {
        Ok(self.attachments.get(name).cloned().unwrap_or_default())
    }
}

fn owned_union_prefix(
    installation: &Installation,
    anchor: bool,
    volume_count: usize,
) -> FakeOwnedUnionDriver {
    let mut volumes = Vec::new();
    if anchor {
        volumes.push(fake_volume(
            installation.anchor_volume_name(),
            &BTreeMap::new(),
        ));
    }
    volumes.extend(
        INIT_VOLUME_ORDER
            .into_iter()
            .take(volume_count)
            .map(|role| {
                fake_volume(
                    &volume_name(installation.compose_project().as_str(), role),
                    &BTreeMap::new(),
                )
            }),
    );
    FakeOwnedUnionDriver {
        volumes,
        ..Default::default()
    }
}

async fn discover_then_reach_later_mutation(
    driver: &FakeOwnedUnionDriver,
    installation: &Installation,
) -> Result<InitOwnedUnion, LocalInitError> {
    let expected = Installation::expected(installation.name());
    let result =
        inspect_init_owned_union_with_driver(driver, &expected, Some(installation)).await?;
    *driver.later_mutations.lock().unwrap() += 1;
    Ok(result)
}

#[tokio::test]
async fn owned_union_accepts_only_desired_led_creation_prefixes_and_exact_final_union() {
    let installation = installation();
    for (anchor, count) in std::iter::once((false, 0))
        .chain(std::iter::once((true, 0)))
        .chain((1..=INIT_VOLUME_ORDER.len()).map(|count| (true, count)))
    {
        let driver = owned_union_prefix(&installation, anchor, count);
        let observed = discover_then_reach_later_mutation(&driver, &installation)
            .await
            .unwrap();
        assert_eq!(observed.anchor_present, anchor);
        assert_eq!(observed.roles.len(), count);
        assert_eq!(*driver.later_mutations.lock().unwrap(), 1);
    }

    let mut non_desired = owned_union_prefix(&installation, true, 0);
    non_desired.volumes.push(fake_volume(
        &volume_name(
            installation.compose_project().as_str(),
            VolumeRole::BootstrapState,
        ),
        &BTreeMap::new(),
    ));
    assert!(
        discover_then_reach_later_mutation(&non_desired, &installation)
            .await
            .is_err()
    );
    assert_eq!(*non_desired.later_mutations.lock().unwrap(), 0);

    let without_anchor = owned_union_prefix(&installation, false, 1);
    assert!(
        discover_then_reach_later_mutation(&without_anchor, &installation)
            .await
            .is_err()
    );
    assert_eq!(*without_anchor.later_mutations.lock().unwrap(), 0);

    let mut gap = owned_union_prefix(&installation, true, 1);
    gap.volumes.push(fake_volume(
        &volume_name(
            installation.compose_project().as_str(),
            VolumeRole::ControlMaterial,
        ),
        &BTreeMap::new(),
    ));
    assert!(
        discover_then_reach_later_mutation(&gap, &installation)
            .await
            .is_err()
    );
    assert_eq!(*gap.later_mutations.lock().unwrap(), 0);
}

#[tokio::test]
async fn fresh_union_transitions_from_empty_to_anchor_before_desired_can_exist() {
    let installation = installation();
    let expected = Installation::expected(installation.name());
    let empty = inspect_init_owned_union_with_driver(
        &owned_union_prefix(&installation, false, 0),
        &expected,
        None,
    )
    .await
    .unwrap();
    assert!(!empty.anchor_present);
    assert!(empty.roles.is_empty());

    let anchor = inspect_init_owned_union_with_driver(
        &owned_union_prefix(&installation, true, 0),
        &expected,
        Some(&installation),
    )
    .await
    .unwrap();
    validate_post_identity_transition(&empty, &anchor).unwrap();

    let desired_name = volume_name(installation.compose_project().as_str(), VolumeRole::Desired);
    let desired_labels = volume_labels(&installation, fingerprint(), VolumeRole::Desired);
    let guard = FakeGuardDriver::default();
    elect_desired_guard_with_driver(
        &guard,
        &desired_name,
        &desired_labels,
        None,
        true,
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(guard.state.lock().unwrap().creates, [desired_name]);

    let desired = inspect_init_owned_union_with_driver(
        &owned_union_prefix(&installation, true, 1),
        &expected,
        Some(&installation),
    )
    .await
    .unwrap();
    assert_eq!(desired, expected_post_desired_union(&empty));
    assert_eq!(
        validate_post_identity_transition(&empty, &desired)
            .unwrap_err()
            .code(),
        LocalInitErrorCode::EngineResourceMismatch
    );
    assert_eq!(desired.roles, BTreeSet::from([VolumeRole::Desired]));
}

#[tokio::test]
async fn owned_union_rejects_unknown_associated_resources_before_any_later_mutation() {
    let installation = installation();
    let related_labels = HashMap::from([(
        "io.automata.local.installation-id".to_owned(),
        installation.id().to_string(),
    )]);

    let mut unknown_volume = owned_union_prefix(&installation, true, 0);
    unknown_volume.volumes.push(fake_volume(
        &format!("{}-unknown", installation.compose_project()),
        &BTreeMap::new(),
    ));
    assert!(
        discover_then_reach_later_mutation(&unknown_volume, &installation)
            .await
            .is_err()
    );
    assert_eq!(*unknown_volume.later_mutations.lock().unwrap(), 0);

    let mut contradictory_volume = owned_union_prefix(&installation, true, 1);
    contradictory_volume.volumes[1].labels.insert(
        COMPOSE_PROJECT_LABEL.to_owned(),
        "some-other-project".to_owned(),
    );
    assert!(
        discover_then_reach_later_mutation(&contradictory_volume, &installation)
            .await
            .is_err()
    );
    assert_eq!(*contradictory_volume.later_mutations.lock().unwrap(), 0);

    let mut unknown_container = owned_union_prefix(&installation, true, 0);
    unknown_container
        .containers
        .push(bollard::models::ContainerSummary {
            id: Some(CONTAINER_ID.to_owned()),
            names: Some(vec!["/unknown".to_owned()]),
            labels: Some(related_labels.clone()),
            ..Default::default()
        });
    assert!(
        discover_then_reach_later_mutation(&unknown_container, &installation)
            .await
            .is_err()
    );
    assert_eq!(*unknown_container.later_mutations.lock().unwrap(), 0);

    let mut unknown_network = owned_union_prefix(&installation, true, 0);
    unknown_network.networks.push(bollard::models::Network {
        name: Some("unrecognized".to_owned()),
        labels: Some(related_labels),
        ..Default::default()
    });
    assert!(
        discover_then_reach_later_mutation(&unknown_network, &installation)
            .await
            .is_err()
    );
    assert_eq!(*unknown_network.later_mutations.lock().unwrap(), 0);
}

#[test]
fn owned_union_association_covers_the_name_prefix_and_every_identity_label() {
    let installation = installation();
    let expected = Installation::expected(installation.name());
    assert!(resource_related(
        &format!("{}-unknown", installation.compose_project()),
        &HashMap::new(),
        &expected,
        Some(&installation),
    ));
    assert!(!resource_related(
        "somebody-else",
        &HashMap::new(),
        &expected,
        Some(&installation),
    ));

    for (key, value) in [
        (
            "io.automata.local.installation-id",
            installation.id().to_string(),
        ),
        (
            "io.automata.local.installation-key",
            installation.selector_key().to_string(),
        ),
        (
            "io.automata.local.compose-project",
            installation.compose_project().to_string(),
        ),
        (
            "com.docker.compose.project",
            installation.compose_project().to_string(),
        ),
    ] {
        assert!(resource_related(
            "arbitrary-name",
            &HashMap::from([(key.to_owned(), value)]),
            &expected,
            Some(&installation),
        ));
    }
}

#[tokio::test]
async fn owned_union_admits_only_the_exact_stale_helper_after_all_twelve_volumes() {
    let installation = installation();
    let helper = bollard::models::ContainerSummary {
        id: Some(CONTAINER_ID.to_owned()),
        names: Some(vec![format!("/{}", helper_name(&installation))]),
        labels: Some(HashMap::new()),
        ..Default::default()
    };

    let mut partial = owned_union_prefix(&installation, true, INIT_VOLUME_ORDER.len() - 1);
    partial.containers.push(helper.clone());
    assert!(
        discover_then_reach_later_mutation(&partial, &installation)
            .await
            .is_err()
    );
    assert_eq!(*partial.later_mutations.lock().unwrap(), 0);

    let mut complete = owned_union_prefix(&installation, true, INIT_VOLUME_ORDER.len());
    complete.containers.push(helper);
    let observed = discover_then_reach_later_mutation(&complete, &installation)
        .await
        .unwrap();
    assert_eq!(observed.helper_id.as_deref(), Some(CONTAINER_ID));
    assert_eq!(*complete.later_mutations.lock().unwrap(), 1);

    for mutate in ["invalid-id", "extra-name", "wrong-project", "duplicate"] {
        let mut invalid = owned_union_prefix(&installation, true, INIT_VOLUME_ORDER.len());
        let mut helper = bollard::models::ContainerSummary {
            id: Some(CONTAINER_ID.to_owned()),
            names: Some(vec![format!("/{}", helper_name(&installation))]),
            labels: Some(HashMap::new()),
            ..Default::default()
        };
        match mutate {
            "invalid-id" => helper.id = Some("short".to_owned()),
            "extra-name" => helper.names.as_mut().unwrap().push("/alias".to_owned()),
            "wrong-project" => {
                helper.labels.as_mut().unwrap().insert(
                    COMPOSE_PROJECT_LABEL.to_owned(),
                    "some-other-project".to_owned(),
                );
            }
            "duplicate" => invalid.containers.push(helper.clone()),
            _ => unreachable!(),
        }
        invalid.containers.push(helper);
        assert!(
            discover_then_reach_later_mutation(&invalid, &installation)
                .await
                .is_err(),
            "helper mutation {mutate} must fail closed"
        );
        assert_eq!(*invalid.later_mutations.lock().unwrap(), 0);
    }
}

struct FakeOwnedVolumeDriver {
    volumes: HashMap<String, bollard::models::Volume>,
    attachments: HashMap<String, Vec<String>>,
}

#[async_trait::async_trait]
impl OwnedVolumeDriver for FakeOwnedVolumeDriver {
    async fn inspect_owned_volume(
        &self,
        name: &str,
    ) -> Result<Option<bollard::models::Volume>, LocalInitError> {
        Ok(self.volumes.get(name).cloned())
    }

    async fn owned_volume_attachments(&self, name: &str) -> Result<Vec<String>, LocalInitError> {
        Ok(self.attachments.get(name).cloned().unwrap_or_default())
    }
}

fn exact_owned_volume_driver(
    installation: &Installation,
    helper_id: Option<&str>,
) -> (InitOwnedUnion, FakeOwnedVolumeDriver) {
    let roles = INIT_VOLUME_ORDER.into_iter().collect::<BTreeSet<_>>();
    let owned = InitOwnedUnion {
        anchor_present: true,
        roles,
        helper_id: helper_id.map(str::to_owned),
    };
    let volumes = INIT_VOLUME_ORDER
        .into_iter()
        .map(|role| {
            let name = volume_name(installation.compose_project().as_str(), role);
            let labels = volume_labels(installation, fingerprint(), role);
            (name.clone(), fake_volume(&name, &labels))
        })
        .collect();
    let attachments = helper_id.map_or_else(HashMap::new, |helper_id| {
        INIT_VOLUME_ORDER
            .into_iter()
            .map(|role| {
                (
                    volume_name(installation.compose_project().as_str(), role),
                    vec![helper_id.to_owned()],
                )
            })
            .collect()
    });
    (
        owned,
        FakeOwnedVolumeDriver {
            volumes,
            attachments,
        },
    )
}

#[tokio::test]
async fn every_present_owned_volume_requires_exact_metadata_labels_and_attachments() {
    let installation = installation();
    for helper in [None, Some(CONTAINER_ID)] {
        let (owned, mut driver) = exact_owned_volume_driver(&installation, helper);
        for volume in driver.volumes.values_mut() {
            volume.labels.insert(
                "com.docker.compose.project".to_owned(),
                installation.compose_project().to_string(),
            );
            volume
                .labels
                .insert("com.example.note".to_owned(), "tolerated".to_owned());
        }
        validate_owned_volumes_with_driver(&driver, &installation, fingerprint(), &owned)
            .await
            .unwrap();
    }

    for role in INIT_VOLUME_ORDER {
        let name = volume_name(installation.compose_project().as_str(), role);
        for drift in [
            "missing",
            "name",
            "driver",
            "scope",
            "options",
            "extra-label",
            "missing-label",
            "wrong-label",
            "wrong-compose-project",
        ] {
            let (owned, mut driver) = exact_owned_volume_driver(&installation, None);
            if drift == "missing" {
                driver.volumes.remove(&name);
            } else {
                let volume = driver.volumes.get_mut(&name).unwrap();
                match drift {
                    "name" => volume.name.push_str("-replacement"),
                    "driver" => volume.driver = "foreign".to_owned(),
                    "scope" => volume.scope = None,
                    "options" => {
                        volume.options.insert("type".to_owned(), "tmpfs".to_owned());
                    }
                    "extra-label" => {
                        volume
                            .labels
                            .insert("io.automata.local.extra".to_owned(), "true".to_owned());
                    }
                    "missing-label" => {
                        volume.labels.remove("io.automata.local.volume-role");
                    }
                    "wrong-label" => {
                        volume.labels.insert(
                            "io.automata.local.volume-role".to_owned(),
                            "replacement".to_owned(),
                        );
                    }
                    "wrong-compose-project" => {
                        volume.labels.insert(
                            "com.docker.compose.project".to_owned(),
                            "some-other-project".to_owned(),
                        );
                    }
                    _ => unreachable!(),
                }
            }
            assert!(
                validate_owned_volumes_with_driver(&driver, &installation, fingerprint(), &owned,)
                    .await
                    .is_err(),
                "role {role:?} drift field {drift} must fail closed"
            );
        }

        let (owned, mut driver) = exact_owned_volume_driver(&installation, None);
        driver
            .attachments
            .insert(name.clone(), vec![CONTAINER_ID.to_owned()]);
        assert!(
            validate_owned_volumes_with_driver(&driver, &installation, fingerprint(), &owned)
                .await
                .is_err()
        );

        for attachments in [
            Vec::new(),
            vec!["dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned()],
            vec![CONTAINER_ID.to_owned(), CONTAINER_ID.to_owned()],
        ] {
            let (owned, mut driver) = exact_owned_volume_driver(&installation, Some(CONTAINER_ID));
            driver.attachments.insert(name.clone(), attachments);
            assert!(
                validate_owned_volumes_with_driver(&driver, &installation, fingerprint(), &owned,)
                    .await
                    .is_err()
            );
        }
    }
}

fn exact_final_owned_union_driver(installation: &Installation) -> FakeOwnedUnionDriver {
    let mut driver = owned_union_prefix(installation, true, 0);
    driver
        .volumes
        .extend(INIT_VOLUME_ORDER.into_iter().map(|role| {
            let name = volume_name(installation.compose_project().as_str(), role);
            fake_volume(&name, &volume_labels(installation, fingerprint(), role))
        }));
    driver
}

#[tokio::test]
async fn final_owned_union_census_rejects_every_absence_helper_and_drift_class() {
    let installation = installation();
    validate_final_owned_union_with_driver(
        &exact_final_owned_union_driver(&installation),
        &installation,
        fingerprint(),
    )
    .await
    .unwrap();

    let mut absent_anchor = exact_final_owned_union_driver(&installation);
    absent_anchor
        .volumes
        .retain(|volume| volume.name != installation.anchor_volume_name());
    assert!(
        validate_final_owned_union_with_driver(&absent_anchor, &installation, fingerprint(),)
            .await
            .is_err()
    );

    let mut partial = exact_final_owned_union_driver(&installation);
    let last = volume_name(
        installation.compose_project().as_str(),
        *INIT_VOLUME_ORDER.last().unwrap(),
    );
    partial.volumes.retain(|volume| volume.name != last);
    assert!(
        validate_final_owned_union_with_driver(&partial, &installation, fingerprint())
            .await
            .is_err()
    );

    let mut helper = exact_final_owned_union_driver(&installation);
    helper.containers.push(bollard::models::ContainerSummary {
        id: Some(CONTAINER_ID.to_owned()),
        names: Some(vec![format!("/{}", helper_name(&installation))]),
        labels: Some(HashMap::new()),
        ..Default::default()
    });
    assert!(
        validate_final_owned_union_with_driver(&helper, &installation, fingerprint())
            .await
            .is_err()
    );

    let desired = volume_name(installation.compose_project().as_str(), VolumeRole::Desired);
    let mut metadata_drift = exact_final_owned_union_driver(&installation);
    metadata_drift
        .volumes
        .iter_mut()
        .find(|volume| volume.name == desired)
        .unwrap()
        .driver = "foreign".to_owned();
    assert!(
        validate_final_owned_union_with_driver(&metadata_drift, &installation, fingerprint())
            .await
            .is_err()
    );

    let mut replacement_drift = exact_final_owned_union_driver(&installation);
    let mut inspected = replacement_drift
        .volumes
        .iter()
        .filter(|volume| volume.name != installation.anchor_volume_name())
        .map(|volume| (volume.name.clone(), volume.clone()))
        .collect::<HashMap<_, _>>();
    inspected.get_mut(&desired).unwrap().labels.insert(
        "io.automata.local.volume-role".to_owned(),
        "replacement".to_owned(),
    );
    replacement_drift.inspected_volumes = Some(inspected);
    assert!(
        validate_final_owned_union_with_driver(&replacement_drift, &installation, fingerprint())
            .await
            .is_err()
    );

    let mut attachment_drift = exact_final_owned_union_driver(&installation);
    attachment_drift
        .attachments
        .insert(desired, vec![CONTAINER_ID.to_owned()]);
    assert!(
        validate_final_owned_union_with_driver(&attachment_drift, &installation, fingerprint())
            .await
            .is_err()
    );

    let mut warning = exact_final_owned_union_driver(&installation);
    warning.warnings = true;
    assert!(
        validate_final_owned_union_with_driver(&warning, &installation, fingerprint())
            .await
            .is_err()
    );

    let mut union_drift = exact_final_owned_union_driver(&installation);
    let mut second = union_drift.volumes.clone();
    second.retain(|volume| volume.name != last);
    union_drift.second_volume_list = Some(second);
    assert!(
        validate_final_owned_union_with_driver(&union_drift, &installation, fingerprint())
            .await
            .is_err()
    );
}

#[test]
fn reset_preflight_allows_only_the_exact_helper_as_a_volume_attachment() {
    let helper = ResetHelperBinding {
        reference: "registry.invalid/automata@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        image_id: CANDIDATE_CONFIG_ID.to_owned(),
        container_id: CONTAINER_ID.to_owned(),
    };
    validate_reset_attachments(std::slice::from_ref(&helper.container_id), Some(&helper)).unwrap();
    validate_reset_attachments(&[], None).unwrap();
    for attachments in [
        vec!["d".repeat(64)],
        vec![helper.container_id.clone(), "d".repeat(64)],
    ] {
        assert_eq!(
            validate_reset_attachments(&attachments, Some(&helper))
                .unwrap_err()
                .code(),
            LocalInitErrorCode::EngineResourceMismatch
        );
    }
    assert!(validate_reset_attachments(&["d".repeat(64)], None).is_err());
}

#[test]
fn reset_order_is_complete_unique_and_keeps_desired_last() {
    let order = reset_volume_order();
    assert_eq!(order.len(), INIT_VOLUME_ORDER.len());
    assert_eq!(order.last(), Some(&VolumeRole::Desired));
    assert_eq!(
        order.into_iter().collect::<BTreeSet<_>>(),
        INIT_VOLUME_ORDER.into_iter().collect::<BTreeSet<_>>()
    );
}

#[test]
fn reset_progress_accepts_only_an_absent_prefix_and_anchor_last() {
    for deleted in 0..=12 {
        let mut presence = [true; 12];
        presence[..deleted].fill(false);
        assert_eq!(
            reset_progress_from_presence(&presence, true).unwrap(),
            deleted
        );
    }
    assert_eq!(
        reset_progress_from_presence(&[false; 12], false).unwrap(),
        13
    );

    let mut hole = [true; 12];
    hole[3] = false;
    assert_eq!(
        reset_progress_from_presence(&hole, true)
            .unwrap_err()
            .code(),
        LocalInitErrorCode::EngineResourceMismatch
    );
    assert_eq!(
        reset_progress_from_presence(&[true; 12], false)
            .unwrap_err()
            .code(),
        LocalInitErrorCode::EngineResourceMismatch
    );
}

#[tokio::test]
async fn raw_union_supports_reset_suffixes_without_weakening_init_prefixes() {
    let installation = installation();
    let expected = Installation::expected(installation.name());
    let reset_order = reset_volume_order();
    for deleted in 0..=reset_order.len() {
        let mut volumes = vec![fake_volume(
            installation.anchor_volume_name(),
            &BTreeMap::new(),
        )];
        volumes.extend(reset_order[deleted..].iter().map(|role| {
            let name = volume_name(installation.compose_project().as_str(), *role);
            let mut volume = fake_volume(&name, &BTreeMap::new());
            volume
                .labels
                .insert("com.example.note".to_owned(), "tolerated".to_owned());
            volume
        }));
        let driver = FakeOwnedUnionDriver {
            volumes,
            ..Default::default()
        };
        let observed =
            inspect_owned_union_census_with_driver(&driver, &expected, Some(&installation))
                .await
                .unwrap();
        let presence = reset_order.map(|role| observed.roles.contains(&role));
        assert_eq!(
            reset_progress_from_presence(&presence, observed.anchor_present).unwrap(),
            deleted
        );
        if (1..reset_order.len() - 1).contains(&deleted) {
            assert_eq!(
                validate_init_owned_union(&observed).unwrap_err().code(),
                LocalInitErrorCode::EngineResourceMismatch
            );
        }
    }

    let mut contradictory = owned_union_prefix(&installation, true, 1);
    contradictory.volumes[1].labels.insert(
        COMPOSE_PROJECT_LABEL.to_owned(),
        "some-other-project".to_owned(),
    );
    assert_eq!(
        inspect_owned_union_census_with_driver(&contradictory, &expected, Some(&installation),)
            .await
            .unwrap_err()
            .code(),
        LocalInitErrorCode::EngineResourceMismatch
    );
}

struct FakeExactDeleteDriver {
    outcome: DeleteAttemptOutcome,
    present_after: bool,
    trace: Mutex<Vec<&'static str>>,
}

#[async_trait::async_trait]
impl ExactVolumeDeleteDriver for FakeExactDeleteDriver {
    async fn delete_volume_untrusted(&self, _name: &str) -> DeleteAttemptOutcome {
        self.trace.lock().unwrap().push("delete");
        self.outcome
    }

    async fn inspect_volume_present(&self, _name: &str) -> Result<bool, LocalInitError> {
        self.trace.lock().unwrap().push("inspect");
        Ok(self.present_after)
    }

    async fn verify_after_volume_delete(&self) -> Result<(), LocalInitError> {
        self.trace.lock().unwrap().push("verify");
        Ok(())
    }
}

#[tokio::test]
async fn exact_volume_delete_reconciles_success_error_and_timeout_from_observed_absence() {
    for outcome in [
        DeleteAttemptOutcome::Completed,
        DeleteAttemptOutcome::Failed,
        DeleteAttemptOutcome::TimedOut,
    ] {
        let absent = FakeExactDeleteDriver {
            outcome,
            present_after: false,
            trace: Mutex::new(Vec::new()),
        };
        remove_volume_and_prove_absent_with_driver(&absent, "owned")
            .await
            .unwrap();
        assert_eq!(
            *absent.trace.lock().unwrap(),
            ["delete", "inspect", "verify"]
        );

        let present = FakeExactDeleteDriver {
            outcome,
            present_after: true,
            trace: Mutex::new(Vec::new()),
        };
        assert_eq!(
            remove_volume_and_prove_absent_with_driver(&present, "owned")
                .await
                .unwrap_err()
                .code(),
            LocalInitErrorCode::ResetFailed
        );
        assert_eq!(*present.trace.lock().unwrap(), ["delete", "inspect"]);
    }
}

#[test]
fn reset_helper_contract_accepts_sealed_config_or_manifest_id_without_live_image_lookup() {
    let installation = installation();
    let contract = contract(&installation);
    let alternate = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let mut inspect = valid_helper_inspect(&contract, CONTAINER_ID);
    inspect.image = Some(alternate.to_owned());
    validate_helper_image_ids(
        &inspect,
        CONTAINER_ID,
        &contract.name,
        contract.image,
        &[contract.image_id, alternate],
        contract.volumes,
        &contract.labels,
    )
    .unwrap();

    inspect.image =
        Some("sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_owned());
    assert_eq!(
        validate_helper_image_ids(
            &inspect,
            CONTAINER_ID,
            &contract.name,
            contract.image,
            &[contract.image_id, alternate],
            contract.volumes,
            &contract.labels,
        )
        .unwrap_err()
        .code(),
        LocalInitErrorCode::MaterializationFailed
    );
}
