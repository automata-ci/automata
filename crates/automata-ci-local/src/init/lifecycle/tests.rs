use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    str::FromStr as _,
    sync::atomic::{AtomicU64, Ordering},
};

use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use super::*;
use crate::init::{certificates::CertificateMaterial, epoch::authority_test_epoch};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("crate is inside the workspace");
        let scratch = workspace.join("target/task-tmp/automata-ci-local");
        fs::create_dir_all(&scratch).unwrap();
        let path = scratch.join(format!(
            "automata-ci-local-lifecycle-test-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn state_path(&self) -> PathBuf {
        self.0.join("state")
    }

    fn stage(&self, bytes: &[u8]) {
        self.write_state_file(".lifecycle-operation.json.automata-write", bytes);
    }

    fn write_state_file(&self, name: &str, bytes: &[u8]) {
        let path = self.state_path().join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }
}

#[tokio::test]
async fn any_reset_intent_poison_precedes_lifecycle_stage_recovery() {
    for reset_name in ["reset-intent.json", ".reset-intent.json.automata-write"] {
        for lifecycle_bytes in [
            b"".as_slice(),
            b"{\"schema\":".as_slice(),
            b"not canonical json\n".as_slice(),
        ] {
            let (directory, state, _established) = fixture();
            directory.stage(lifecycle_bytes);
            directory.write_state_file(reset_name, b"reset authority poison\n");
            drop(state);

            let error = up_local(LocalUpRequest::new(
                directory.state_path(),
                CancellationToken::new(),
            ))
            .await
            .unwrap_err();
            assert_eq!(error.code(), LocalInitErrorCode::ResetRequired);
            assert_eq!(
                fs::read(
                    directory
                        .state_path()
                        .join(".lifecycle-operation.json.automata-write")
                )
                .unwrap(),
                lifecycle_bytes
            );
            assert_eq!(
                fs::read(directory.state_path().join(reset_name)).unwrap(),
                b"reset authority poison\n"
            );
        }
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn fixture() -> (TestDirectory, StateRoot, EstablishedLifecycle) {
    let directory = TestDirectory::new();
    let state = StateRoot::acquire(&directory.state_path()).unwrap();
    let installation = Installation::verified(
        InstallationName::new("lifecycle-test").unwrap(),
        InstallationId::from_str("11111111-2222-4333-8444-555555555555").unwrap(),
    );
    let material_root = [0x51; 32];
    let epoch = authority_test_epoch(&installation, &material_root, state.authority_sha256());
    let certificates = CertificateMaterial {
        ca_pem: "ca\n".to_owned(),
        ca_key_pem: Zeroizing::new("ca-key\n".to_owned()),
        postgres_chain_pem: "postgres\n".to_owned(),
        postgres_key_pem: Zeroizing::new("postgres-key\n".to_owned()),
        object_chain_pem: "object\n".to_owned(),
        object_key_pem: Zeroizing::new("object-key\n".to_owned()),
        runner_chain_pem: "runner\n".to_owned(),
        runner_key_pem: Zeroizing::new("runner-key\n".to_owned()),
    };
    (
        directory,
        state,
        EstablishedLifecycle {
            installation,
            epoch,
            material_root: Zeroizing::new(material_root),
            certificates,
        },
    )
}

fn resolve(
    state: &StateRoot,
    established: &EstablishedLifecycle,
) -> Result<(LifecycleIntent, bool), LocalInitError> {
    let observed = observe_reconciled_lifecycle_intent(state)?;
    resolve_lifecycle_intent(state, &observed, established, LifecycleOperationKind::Up)
}

#[test]
fn bootstrap_identity_uses_the_installation_uuid_and_material_root_identifier() {
    let (_directory, _state, established) = fixture();
    let artifacts = derive_bootstrap_artifacts(&established).unwrap();
    let request: serde_json::Value = serde_json::from_slice(&artifacts.request).unwrap();

    assert_eq!(
        request["tenant"]["tenant_id"],
        format!("local-{}", established.installation.id().as_uuid().simple())
    );
    assert_eq!(
        request["installation_authority_source_sha256"],
        established.epoch.material_root_sha256().to_string()
    );
}

#[test]
fn safe_empty_and_partial_lifecycle_stages_are_discarded_before_replay() {
    for malformed in [b"".as_slice(), b"{\"schema\":".as_slice()] {
        let (directory, state, established) = fixture();
        directory.stage(malformed);
        let (intent, resumed) = resolve(&state, &established).unwrap();
        assert_eq!(intent.phase(), LifecyclePhase::Prepared);
        assert!(!resumed);
        assert!(
            !state
                .observe_lifecycle_operation()
                .unwrap()
                .staged_present()
        );

        drop(state);
        let (directory, state, established) = fixture();
        let (intent, _) = resolve(&state, &established).unwrap();
        directory.stage(malformed);
        let (replayed, resumed) = resolve(&state, &established).unwrap();
        assert_eq!(replayed, intent);
        assert!(resumed);
        assert!(
            !state
                .observe_lifecycle_operation()
                .unwrap()
                .staged_present()
        );
    }
}

#[test]
fn fresh_and_staged_initial_publication_reconcile_to_one_prepared_intent() {
    let (_directory, state, established) = fixture();
    let (fresh, resumed) = resolve(&state, &established).unwrap();
    assert_eq!(fresh.phase(), LifecyclePhase::Prepared);
    assert!(!resumed);
    drop(state);

    let (directory, state, established) = fixture();
    let prepared = LifecycleIntent::new(
        &state,
        &established.installation,
        &established.epoch,
        LifecycleOperationKind::Up,
    )
    .unwrap();
    directory.stage(&prepared.canonical_bytes().unwrap());
    let (recovered, resumed) = resolve(&state, &established).unwrap();
    assert_eq!(recovered, prepared);
    assert!(resumed);
    let observation = state.observe_lifecycle_operation().unwrap();
    assert!(observation.completed_present());
    assert!(!observation.staged_present());
}

#[test]
fn every_up_phase_transition_recovers_a_durable_staged_successor() {
    let transitions = [
        LifecyclePhase::ResultsTransitReady,
        LifecyclePhase::DependenciesReady,
        LifecyclePhase::BootstrapReady,
        LifecyclePhase::RunnerConfigurationReady,
        LifecyclePhase::Running,
        LifecyclePhase::Complete,
    ];
    let (directory, state, established) = fixture();
    let mut current = LifecycleIntent::new(
        &state,
        &established.installation,
        &established.epoch,
        LifecycleOperationKind::Up,
    )
    .unwrap();
    state
        .store_lifecycle_operation(&current.canonical_bytes().unwrap())
        .unwrap();
    for next_phase in transitions {
        let next = current.advance(next_phase).unwrap();
        directory.stage(&next.canonical_bytes().unwrap());
        let (recovered, resumed) = resolve(&state, &established).unwrap();
        assert!(resumed);
        assert_eq!(recovered, next);
        assert!(
            !state
                .observe_lifecycle_operation()
                .unwrap()
                .staged_present()
        );
        current = recovered;
    }
}

#[test]
fn equal_staged_bytes_are_cleaned_without_changing_the_final_intent() {
    let (directory, state, established) = fixture();
    let (intent, _) = resolve(&state, &established).unwrap();
    directory.stage(&intent.canonical_bytes().unwrap());
    let (recovered, resumed) = resolve(&state, &established).unwrap();
    assert_eq!(recovered, intent);
    assert!(resumed);
    assert!(
        !state
            .observe_lifecycle_operation()
            .unwrap()
            .staged_present()
    );
}

#[test]
fn skipped_and_conflicting_canonical_staged_intents_are_never_published() {
    let (directory, state, established) = fixture();
    let (prepared, _) = resolve(&state, &established).unwrap();
    let skipped = prepared
        .advance(LifecyclePhase::ResultsTransitReady)
        .unwrap()
        .advance(LifecyclePhase::DependenciesReady)
        .unwrap();
    directory.stage(&skipped.canonical_bytes().unwrap());
    assert_eq!(
        resolve(&state, &established).unwrap_err().code(),
        LocalInitErrorCode::ResetRequired
    );
    assert!(
        state
            .observe_lifecycle_operation()
            .unwrap()
            .staged_present()
    );

    drop(state);
    let (directory, state, established) = fixture();
    let _ = resolve(&state, &established).unwrap();
    let conflicting = LifecycleIntent::new(
        &state,
        &established.installation,
        &established.epoch,
        LifecycleOperationKind::Up,
    )
    .unwrap()
    .advance(LifecyclePhase::ResultsTransitReady)
    .unwrap();
    directory.stage(&conflicting.canonical_bytes().unwrap());
    assert_eq!(
        resolve(&state, &established).unwrap_err().code(),
        LocalInitErrorCode::ResetRequired
    );
}

#[test]
fn a_completed_intent_is_a_finalization_latch_not_a_valid_mutation_phase() {
    let (_directory, state, established) = fixture();
    let (mut intent, _) = resolve(&state, &established).unwrap();
    for phase in [
        LifecyclePhase::ResultsTransitReady,
        LifecyclePhase::DependenciesReady,
        LifecyclePhase::BootstrapReady,
        LifecyclePhase::RunnerConfigurationReady,
        LifecyclePhase::Running,
        LifecyclePhase::Complete,
    ] {
        intent = intent.advance(phase).unwrap();
    }
    assert!(intent.completed());
    assert!(intent.advance(LifecyclePhase::Complete).is_err());
}
