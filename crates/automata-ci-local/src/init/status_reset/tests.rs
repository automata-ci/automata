#![allow(clippy::large_futures)]

use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use super::*;
use crate::InstallationId;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap();
        let scratch = workspace.join("target/task-tmp/automata-ci-local");
        fs::create_dir_all(&scratch).unwrap();
        let path = scratch.join(format!(
            "automata-ci-local-status-reset-test-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn state_path(&self) -> PathBuf {
        self.0.join("state")
    }

    fn private_file(&self, name: &str, bytes: &[u8]) {
        self.private_file_mode(name, bytes, 0o600);
    }

    fn private_file_mode(&self, name: &str, bytes: &[u8], mode: u32) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(self.state_path().join(name))
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        fs::set_permissions(
            self.state_path().join(name),
            fs::Permissions::from_mode(mode),
        )
        .unwrap();
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

struct FakeResetDriver {
    state: Mutex<FakeResetState>,
    cancellation: CancellationToken,
    holder_lost: CancellationToken,
}

struct FakeResetState {
    progress: usize,
    phase: FakeResetPhase,
    failure: Option<FakeResetFailure>,
    inspect_count: usize,
    cancel_at: Option<usize>,
    lose_holder_at: Option<usize>,
    trace: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FakeResetPhase {
    Topology,
    Volumes,
    AnchorRemoved,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FakeResetFailure {
    Topology,
    Inspect(usize),
    Volume(usize),
    Anchor,
    Lock,
}

impl FakeResetDriver {
    fn new(progress: usize, topology_present: bool) -> Self {
        assert!(progress <= 12);
        Self {
            state: Mutex::new(FakeResetState {
                progress,
                phase: if topology_present {
                    FakeResetPhase::Topology
                } else {
                    FakeResetPhase::Volumes
                },
                failure: None,
                inspect_count: 0,
                cancel_at: None,
                lose_holder_at: None,
                trace: Vec::new(),
            }),
            cancellation: CancellationToken::new(),
            holder_lost: CancellationToken::new(),
        }
    }

    fn trace(&self) -> Vec<String> {
        self.state.lock().unwrap().trace.clone()
    }
}

#[async_trait::async_trait(?Send)]
impl ResetMutationDriver for FakeResetDriver {
    fn holder_lost(&self) -> CancellationToken {
        self.holder_lost.clone()
    }

    async fn remove_topology(&mut self) -> Result<(), LocalInitError> {
        if self.holder_lost.is_cancelled() {
            return Err(reset_required());
        }
        let mut state = self.state.lock().unwrap();
        assert_eq!(state.phase, FakeResetPhase::Topology);
        state.trace.push("topology".to_owned());
        if state.failure == Some(FakeResetFailure::Topology) {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetFailed));
        }
        state.phase = FakeResetPhase::Volumes;
        Ok(())
    }

    async fn inspect_progress(&mut self) -> Result<usize, LocalInitError> {
        if self.holder_lost.is_cancelled() {
            return Err(reset_required());
        }
        let mut state = self.state.lock().unwrap();
        assert_eq!(state.phase, FakeResetPhase::Volumes);
        let progress = state.progress;
        state.trace.push(format!("inspect:{progress}"));
        let inspection = state.inspect_count;
        state.inspect_count += 1;
        if state.failure == Some(FakeResetFailure::Inspect(inspection)) {
            return Err(LocalInitError::new(
                LocalInitErrorCode::EngineResourceMismatch,
            ));
        }
        Ok(progress)
    }

    async fn remove_volume(
        &mut self,
        role: super::super::materializer::VolumeRole,
    ) -> Result<(), LocalInitError> {
        if self.holder_lost.is_cancelled() {
            return Err(reset_required());
        }
        let mut state = self.state.lock().unwrap();
        assert_eq!(state.phase, FakeResetPhase::Volumes);
        let index = state.progress;
        assert_eq!(reset_volume_order()[index], role);
        state.trace.push(format!("volume:{}", role.name()));
        if state.cancel_at == Some(index) {
            self.cancellation.cancel();
        }
        if state.lose_holder_at == Some(index) {
            self.holder_lost.cancel();
        }
        if state.failure == Some(FakeResetFailure::Volume(index)) {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetFailed));
        }
        state.progress += 1;
        Ok(())
    }

    async fn remove_anchor_and_release_lock(&mut self) -> Result<(), LocalInitError> {
        if self.holder_lost.is_cancelled() {
            return Err(reset_required());
        }
        let mut state = self.state.lock().unwrap();
        assert_eq!(state.phase, FakeResetPhase::Volumes);
        assert_eq!(state.progress, 12);
        state.trace.push("anchor".to_owned());
        if state.failure == Some(FakeResetFailure::Anchor) {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetFailed));
        }
        state.phase = FakeResetPhase::AnchorRemoved;
        state.trace.push("lock".to_owned());
        if state.failure == Some(FakeResetFailure::Lock) {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetFailed));
        }
        state.phase = FakeResetPhase::Complete;
        Ok(())
    }
}

fn installation() -> Installation {
    Installation::verified(InstallationName::default(), InstallationId::new())
}

fn helper() -> ResetHelperBinding {
    ResetHelperBinding {
        reference: "example.invalid/automata@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        image_id: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        container_id: "c".repeat(64),
    }
}

#[tokio::test]
async fn destructive_reset_is_topology_first_desired_twelfth_anchor_then_lock_and_latched() {
    let mut driver = FakeResetDriver::new(0, true);
    driver.state.lock().unwrap().cancel_at = Some(0);
    let cancellation = driver.cancellation.clone();
    let completed_after_cancellation = drive_engine_reset(&mut driver, false, &cancellation)
        .await
        .unwrap();

    assert!(completed_after_cancellation);
    let trace = driver.trace();
    assert_eq!(trace.first().map(String::as_str), Some("topology"));
    assert_eq!(
        trace
            .iter()
            .rfind(|event| event.starts_with("volume:"))
            .map(String::as_str),
        Some("volume:desired")
    );
    assert_eq!(
        trace.iter().rposition(|event| event == "anchor"),
        Some(trace.len() - 2),
        "the lifecycle lock is the only mutation after anchor deletion"
    );
    assert_eq!(trace.last().map(String::as_str), Some("lock"));
}

#[tokio::test]
async fn pre_cancelled_destructive_replay_still_completes_and_reports_the_latch() {
    let mut driver = FakeResetDriver::new(7, false);
    driver.cancellation.cancel();
    let cancellation = driver.cancellation.clone();

    let completed_after_cancellation = drive_engine_reset(&mut driver, true, &cancellation)
        .await
        .unwrap();

    assert!(completed_after_cancellation);
    assert_eq!(
        driver
            .trace()
            .iter()
            .filter(|event| event.starts_with("volume:"))
            .count(),
        5
    );
    assert_eq!(driver.trace().last().map(String::as_str), Some("lock"));
}

#[tokio::test]
async fn reset_replay_resumes_at_the_exact_absent_prefix() {
    for progress in 0..=12 {
        let mut driver = FakeResetDriver::new(progress, false);
        let cancellation = driver.cancellation.clone();
        drive_engine_reset(&mut driver, true, &cancellation)
            .await
            .unwrap();

        let trace = driver.trace();
        let removed = trace
            .iter()
            .filter(|event| event.starts_with("volume:"))
            .cloned()
            .collect::<Vec<_>>();
        let expected = reset_volume_order()[progress..]
            .iter()
            .map(|role| format!("volume:{}", role.name()))
            .collect::<Vec<_>>();
        assert_eq!(removed, expected, "replay prefix {progress}");
        assert_eq!(
            trace
                .iter()
                .filter(|event| event.as_str() == "anchor")
                .count(),
            1,
            "anchor replay prefix {progress}"
        );
        assert_eq!(trace.last().map(String::as_str), Some("lock"));
    }
}

#[tokio::test]
async fn reset_failure_dominates_latched_cancellation_and_stops_later_mutations() {
    let mut driver = FakeResetDriver::new(0, false);
    {
        let mut state = driver.state.lock().unwrap();
        state.cancel_at = Some(2);
        state.failure = Some(FakeResetFailure::Volume(2));
    }
    let cancellation = driver.cancellation.clone();
    let error = drive_engine_reset(&mut driver, true, &cancellation)
        .await
        .unwrap_err();
    assert_eq!(error.code(), LocalInitErrorCode::ResetFailed);
    assert!(driver.cancellation.is_cancelled());
    assert_eq!(
        driver
            .trace()
            .iter()
            .filter(|event| event.starts_with("volume:"))
            .count(),
        3
    );
    assert!(!driver.trace().iter().any(|event| event == "anchor"));
}

#[tokio::test]
async fn every_last_preflight_or_ordered_delete_failure_stops_later_mutation() {
    let mut preflight = FakeResetDriver::new(0, false);
    preflight.state.lock().unwrap().failure = Some(FakeResetFailure::Inspect(0));
    let cancellation = preflight.cancellation.clone();
    assert_eq!(
        drive_engine_reset(&mut preflight, true, &cancellation)
            .await
            .unwrap_err()
            .code(),
        LocalInitErrorCode::EngineResourceMismatch
    );
    assert_eq!(preflight.trace(), ["inspect:0"]);

    let mut topology_failure = FakeResetDriver::new(0, true);
    topology_failure.state.lock().unwrap().failure = Some(FakeResetFailure::Topology);
    let cancellation = topology_failure.cancellation.clone();
    assert!(
        drive_engine_reset(&mut topology_failure, false, &cancellation)
            .await
            .is_err()
    );
    assert_eq!(topology_failure.trace(), ["topology"]);

    let mut desired_failure = FakeResetDriver::new(0, false);
    desired_failure.state.lock().unwrap().failure = Some(FakeResetFailure::Volume(11));
    let cancellation = desired_failure.cancellation.clone();
    assert!(
        drive_engine_reset(&mut desired_failure, true, &cancellation)
            .await
            .is_err()
    );
    assert!(
        !desired_failure
            .trace()
            .iter()
            .any(|event| event == "anchor")
    );

    let mut anchor_failure = FakeResetDriver::new(0, false);
    anchor_failure.state.lock().unwrap().failure = Some(FakeResetFailure::Anchor);
    let cancellation = anchor_failure.cancellation.clone();
    assert!(
        drive_engine_reset(&mut anchor_failure, true, &cancellation)
            .await
            .is_err()
    );
    assert_eq!(
        anchor_failure.trace().last().map(String::as_str),
        Some("anchor")
    );

    let mut lock_failure = FakeResetDriver::new(12, false);
    lock_failure.state.lock().unwrap().failure = Some(FakeResetFailure::Lock);
    let cancellation = lock_failure.cancellation.clone();
    assert!(
        drive_engine_reset(&mut lock_failure, true, &cancellation)
            .await
            .is_err()
    );
    assert_eq!(lock_failure.trace(), ["inspect:12", "anchor", "lock"]);
}

#[tokio::test]
async fn holder_loss_stops_the_ordered_transaction_before_later_mutations() {
    let mut driver = FakeResetDriver::new(0, false);
    driver.state.lock().unwrap().lose_holder_at = Some(2);
    let cancellation = driver.cancellation.clone();

    let error = drive_engine_reset(&mut driver, true, &cancellation)
        .await
        .unwrap_err();

    assert_eq!(error.code(), LocalInitErrorCode::ResetRequired);
    assert_eq!(
        driver
            .trace()
            .iter()
            .filter(|event| event.starts_with("volume:"))
            .count(),
        3
    );
    assert!(!driver.trace().iter().any(|event| event == "anchor"));
}

struct FakeHostResetDriver {
    state: Mutex<FakeHostResetState>,
    cancellation: CancellationToken,
}

struct FakeHostResetState {
    present: Vec<StateRecord>,
    cancel_on: Option<StateRecord>,
    trace: Vec<StateRecord>,
}

impl FakeHostResetDriver {
    fn with_removed_prefix(prefix: usize) -> Self {
        let records = HOST_RESET_ORDER
            .into_iter()
            .chain(std::iter::once(StateRecord::ResetIntent))
            .collect::<Vec<_>>();
        Self {
            state: Mutex::new(FakeHostResetState {
                present: records[prefix..].to_vec(),
                cancel_on: None,
                trace: Vec::new(),
            }),
            cancellation: CancellationToken::new(),
        }
    }
}

impl ResetHostDriver for FakeHostResetDriver {
    fn validate_remaining(&self) -> Result<(), LocalInitError> {
        if self
            .state
            .lock()
            .unwrap()
            .present
            .contains(&StateRecord::ResetIntent)
        {
            Ok(())
        } else {
            Err(LocalInitError::new(LocalInitErrorCode::ResetRequired))
        }
    }

    fn remove_record(&self, record: StateRecord) -> Result<(), LocalInitError> {
        let mut state = self.state.lock().unwrap();
        state.trace.push(record);
        state.present.retain(|present| *present != record);
        if state.cancel_on == Some(record) {
            self.cancellation.cancel();
        }
        Ok(())
    }

    fn verify_empty(&self) -> Result<(), LocalInitError> {
        if self.state.lock().unwrap().present.is_empty() {
            Ok(())
        } else {
            Err(LocalInitError::new(LocalInitErrorCode::ResetFailed))
        }
    }
}

#[test]
fn host_record_replay_is_fixed_order_intent_last_and_samples_final_cancellation() {
    for prefix in 0..=HOST_RESET_ORDER.len() {
        let driver = FakeHostResetDriver::with_removed_prefix(prefix);
        if prefix == 0 {
            driver.state.lock().unwrap().cancel_on = Some(StateRecord::ResetIntent);
        }
        let cancelled = erase_host_records(&driver, &driver.cancellation, false).unwrap();
        assert_eq!(cancelled, prefix == 0);
        assert_eq!(
            driver.state.lock().unwrap().trace,
            HOST_RESET_ORDER
                .into_iter()
                .chain(std::iter::once(StateRecord::ResetIntent))
                .collect::<Vec<_>>()
        );
        assert!(driver.state.lock().unwrap().present.is_empty());
    }
}

#[test]
fn reset_authority_survives_missing_or_safe_malformed_non_authority_records() {
    let directory = TestDirectory::new();
    let state = StateRoot::acquire(&directory.state_path()).unwrap();
    let installation = installation();
    let epoch = super::super::epoch::authority_test_epoch(
        &installation,
        &[0x51; 32],
        state.authority_sha256(),
    );
    directory.private_file("epoch.json", &epoch.canonical_bytes());
    fs::set_permissions(
        directory.state_path().join("epoch.json"),
        fs::Permissions::from_mode(0o400),
    )
    .unwrap();

    let missing = validate_reset_host_state(&state, &state.snapshot_for_reset().unwrap()).unwrap();
    assert_eq!(missing.installation, installation);
    assert_eq!(missing.epoch, epoch);

    directory.private_file("material-root", &[0x99; 32]);
    directory.private_file("certificates.json", &vec![b'x'; 128 * 1024 + 1]);
    let selection = StateInstallationSelection::new(installation.name())
        .canonical_bytes()
        .unwrap();
    directory.private_file("installation-selection.json", &selection);
    directory.private_file(".installation-selection.json.automata-write", &selection);
    directory.private_file("materialization.json", b"{malformed}\n");
    directory.private_file(".materialization.json.automata-write", b"{malformed}\n");
    directory.private_file(".epoch.json.automata-write", &epoch.canonical_bytes());
    let malformed =
        validate_reset_host_state(&state, &state.snapshot_for_reset().unwrap()).unwrap();
    assert_eq!(malformed.installation, installation);
    assert_eq!(malformed.epoch, epoch);
}

#[test]
fn unreadable_or_temp_only_epoch_cannot_authorize_a_fresh_reset() {
    let directory = TestDirectory::new();
    let state = StateRoot::acquire(&directory.state_path()).unwrap();
    let installation = installation();
    let epoch = super::super::epoch::authority_test_epoch(
        &installation,
        &[0x54; 32],
        state.authority_sha256(),
    );
    directory.private_file("epoch.json", &epoch.canonical_bytes());
    fs::set_permissions(
        directory.state_path().join("epoch.json"),
        fs::Permissions::from_mode(0o000),
    )
    .unwrap();

    assert_eq!(
        validate_reset_host_state(&state, &state.snapshot_for_reset().unwrap())
            .err()
            .unwrap()
            .code(),
        LocalInitErrorCode::ResetRequired
    );

    let staged_directory = TestDirectory::new();
    let staged_state = StateRoot::acquire(&staged_directory.state_path()).unwrap();
    let staged_epoch = super::super::epoch::authority_test_epoch(
        &installation,
        &[0x55; 32],
        staged_state.authority_sha256(),
    );
    staged_directory.private_file(
        ".epoch.json.automata-write",
        &staged_epoch.canonical_bytes(),
    );
    assert_eq!(
        validate_reset_host_state(&staged_state, &staged_state.snapshot_for_reset().unwrap())
            .err()
            .unwrap()
            .code(),
        LocalInitErrorCode::ResetRequired
    );
}

#[test]
fn valid_conflicting_final_or_staged_authority_evidence_blocks_before_engine_preflight() {
    for conflict in [
        "selection-final",
        "selection-staged",
        "materialization-final",
        "materialization-staged",
        "epoch-staged",
    ] {
        let directory = TestDirectory::new();
        let state = StateRoot::acquire(&directory.state_path()).unwrap();
        let installation = installation();
        let epoch = super::super::epoch::authority_test_epoch(
            &installation,
            &[0x52; 32],
            state.authority_sha256(),
        );
        directory.private_file("epoch.json", &epoch.canonical_bytes());
        if conflict.starts_with("selection") {
            let other = InstallationName::new("other").unwrap();
            let bytes = StateInstallationSelection::new(&other)
                .canonical_bytes()
                .unwrap();
            if conflict.ends_with("final") {
                directory.private_file("installation-selection.json", &bytes);
            } else {
                directory.private_file(".installation-selection.json.automata-write", &bytes);
            }
        } else if conflict.starts_with("materialization") {
            let bytes = StateMaterialization::new(Sha256Digest::from_bytes([0x53; 32]))
                .canonical_bytes()
                .unwrap();
            if conflict.ends_with("final") {
                directory.private_file("materialization.json", &bytes);
            } else {
                directory.private_file(".materialization.json.automata-write", &bytes);
            }
        } else {
            let conflicting = super::super::epoch::authority_test_epoch(
                &installation,
                &[0x55; 32],
                state.authority_sha256(),
            );
            directory.private_file(".epoch.json.automata-write", &conflicting.canonical_bytes());
        }

        assert_eq!(
            validate_reset_host_state(&state, &state.snapshot_for_reset().unwrap())
                .err()
                .unwrap()
                .code(),
            LocalInitErrorCode::ResetRequired,
            "valid conflicting {conflict} must fail before the Engine is connected"
        );
    }
}

#[test]
fn reset_intent_is_canonical_self_contained_and_binds_the_closed_topology() {
    let installation = installation();
    let root = [0x5a; 32];
    let epoch = super::super::epoch::certificate_test_epoch(&installation, &root);
    let established = EstablishedState {
        installation,
        epoch,
        material_root: Some(root),
    };
    let authority = Sha256Digest::from_bytes([0x22; 32]);
    let intent = ResetIntent::new(authority, &established, Some(helper()));
    let bytes = intent.canonical_bytes().unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    for secret in [
        "ZZZZZZZZ",
        "certificate-record-private-marker",
        "materialization-record",
        "certificates_sha256",
        "material_root_sha256",
    ] {
        assert!(!text.contains(secret));
    }
    assert!(text.contains("\"role_set_sha256\""));

    let validated = ResetIntent::from_canonical_bytes(&bytes, authority).unwrap();
    validated.validate_intent_bytes(Some(&bytes)).unwrap();
    assert_eq!(
        validated
            .validate_intent_bytes(Some(b"different\n"))
            .unwrap_err()
            .code(),
        LocalInitErrorCode::ResetRequired
    );
    assert_eq!(
        ResetIntent::from_canonical_bytes(&bytes, Sha256Digest::from_bytes([0x23; 32]))
            .err()
            .unwrap()
            .code(),
        LocalInitErrorCode::ResetRequired
    );

    let mut wrong_topology: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    wrong_topology["role_set_sha256"] =
        serde_json::Value::String(Sha256Digest::from_bytes([0x99; 32]).to_string());
    let mut wrong_topology = serde_json::to_vec(&wrong_topology).unwrap();
    wrong_topology.push(b'\n');
    assert_eq!(
        ResetIntent::from_canonical_bytes(&wrong_topology, authority)
            .err()
            .unwrap()
            .code(),
        LocalInitErrorCode::ResetRequired
    );
}

#[test]
fn published_reset_intent_remains_authoritative_after_host_record_loss_or_corruption() {
    let directory = TestDirectory::new();
    let state = StateRoot::acquire(&directory.state_path()).unwrap();
    let installation = installation();
    let epoch = super::super::epoch::authority_test_epoch(
        &installation,
        &[0x61; 32],
        state.authority_sha256(),
    );
    directory.private_file("epoch.json", &epoch.canonical_bytes());
    let intent = ResetIntent::new(
        state.authority_sha256(),
        &EstablishedState {
            installation,
            epoch,
            material_root: Some([0x61; 32]),
        },
        None,
    );
    let bytes = intent.canonical_bytes().unwrap();
    state.store_reset_intent(&bytes).unwrap();
    fs::set_permissions(
        directory.state_path().join("reset-intent.json"),
        fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    assert_eq!(
        state.reconcile_validated_reset_intent(&bytes).unwrap(),
        bytes
    );
    state.remove_record(StateRecord::Epoch).unwrap();
    directory.private_file("material-root", b"");
    directory.private_file("certificates.json", &vec![b'x'; 128 * 1024 + 1]);
    directory.private_file("epoch.json", b"{malformed}\n");
    directory.private_file(".epoch.json.automata-write", b"{malformed}\n");
    directory.private_file("installation-selection.json", b"{malformed}\n");
    directory.private_file(
        ".installation-selection.json.automata-write",
        b"{malformed}\n",
    );
    directory.private_file("materialization.json", b"{malformed}\n");
    directory.private_file(".materialization.json.automata-write", b"{malformed}\n");

    let validated = ResetIntent::from_canonical_bytes(&bytes, state.authority_sha256()).unwrap();
    validated
        .validate_reset_snapshot(&state.snapshot_for_reset().unwrap())
        .unwrap();
}

#[test]
fn every_replay_phase_rejects_any_unreadable_staged_intent_evidence() {
    let directory = TestDirectory::new();
    let state = StateRoot::acquire(&directory.state_path()).unwrap();
    let installation = installation();
    let epoch = super::super::epoch::authority_test_epoch(
        &installation,
        &[0x62; 32],
        state.authority_sha256(),
    );
    let intent = ResetIntent::new(
        state.authority_sha256(),
        &EstablishedState {
            installation,
            epoch,
            material_root: Some([0x62; 32]),
        },
        None,
    );
    let bytes = intent.canonical_bytes().unwrap();
    state.store_reset_intent(&bytes).unwrap();
    directory.private_file_mode(".reset-intent.json.automata-write", b"opaque", 0o000);

    let snapshot = state.snapshot_for_reset().unwrap();
    assert!(snapshot.reset_intent.staged_present());
    assert_eq!(snapshot.reset_intent.staged(), None);
    let validated = ResetIntent::from_canonical_bytes(&bytes, state.authority_sha256()).unwrap();
    assert_eq!(
        validated
            .validate_reset_snapshot(&snapshot)
            .unwrap_err()
            .code(),
        LocalInitErrorCode::ResetRequired
    );
}

#[test]
fn restored_old_intent_rejects_new_generation_final_and_staged_evidence_before_engine_mutation() {
    for conflict in [
        "epoch-name-final",
        "epoch-name-staged",
        "epoch-fingerprint-final",
        "epoch-fingerprint-staged",
        "selection-final",
        "selection-staged",
        "materialization-final",
        "materialization-staged",
    ] {
        let directory = TestDirectory::new();
        let state = StateRoot::acquire(&directory.state_path()).unwrap();
        let old_installation = installation();
        let old_epoch = super::super::epoch::authority_test_epoch(
            &old_installation,
            &[0x71; 32],
            state.authority_sha256(),
        );
        let old_intent = ResetIntent::new(
            state.authority_sha256(),
            &EstablishedState {
                installation: old_installation.clone(),
                epoch: old_epoch,
                material_root: Some([0x71; 32]),
            },
            None,
        );
        let old_intent_bytes = old_intent.canonical_bytes().unwrap();
        state.store_reset_intent(&old_intent_bytes).unwrap();
        let validated =
            ResetIntent::from_canonical_bytes(&old_intent_bytes, state.authority_sha256()).unwrap();

        let new_installation = Installation::verified(
            InstallationName::new("replacement").unwrap(),
            InstallationId::new(),
        );
        let candidate_installation = if conflict.starts_with("epoch-fingerprint") {
            &old_installation
        } else {
            &new_installation
        };
        let new_epoch = super::super::epoch::authority_test_epoch(
            candidate_installation,
            &[0x72; 32],
            state.authority_sha256(),
        );
        match conflict {
            "epoch-name-final" | "epoch-fingerprint-final" => {
                directory.private_file("epoch.json", &new_epoch.canonical_bytes());
            }
            "epoch-name-staged" | "epoch-fingerprint-staged" => {
                directory.private_file(".epoch.json.automata-write", &new_epoch.canonical_bytes());
            }
            "selection-final" => directory.private_file(
                "installation-selection.json",
                &StateInstallationSelection::new(new_installation.name())
                    .canonical_bytes()
                    .unwrap(),
            ),
            "selection-staged" => directory.private_file(
                ".installation-selection.json.automata-write",
                &StateInstallationSelection::new(new_installation.name())
                    .canonical_bytes()
                    .unwrap(),
            ),
            "materialization-final" => directory.private_file(
                "materialization.json",
                &StateMaterialization::new(new_epoch.fingerprint())
                    .canonical_bytes()
                    .unwrap(),
            ),
            "materialization-staged" => directory.private_file(
                ".materialization.json.automata-write",
                &StateMaterialization::new(new_epoch.fingerprint())
                    .canonical_bytes()
                    .unwrap(),
            ),
            _ => unreachable!(),
        }

        assert_eq!(
            validated
                .validate_reset_snapshot(&state.snapshot_for_reset().unwrap())
                .unwrap_err()
                .code(),
            LocalInitErrorCode::ResetRequired,
            "restored intent must not reach the Engine with conflicting {conflict} evidence"
        );
    }
}

fn staged_intent_rejection_fixture(case: &str) -> TestDirectory {
    let directory = TestDirectory::new();
    let state = StateRoot::acquire(&directory.state_path()).unwrap();
    let bytes = if case.starts_with("stale") {
        let old_installation = installation();
        let old_epoch = super::super::epoch::authority_test_epoch(
            &old_installation,
            &[0x81; 32],
            state.authority_sha256(),
        );
        let old_intent = ResetIntent::new(
            state.authority_sha256(),
            &EstablishedState {
                installation: old_installation,
                epoch: old_epoch,
                material_root: Some([0x81; 32]),
            },
            None,
        );
        let new_installation = Installation::verified(
            InstallationName::new("replacement").unwrap(),
            InstallationId::new(),
        );
        let new_epoch = super::super::epoch::authority_test_epoch(
            &new_installation,
            &[0x82; 32],
            state.authority_sha256(),
        );
        directory.private_file("epoch.json", &new_epoch.canonical_bytes());
        directory.private_file(
            "installation-selection.json",
            &StateInstallationSelection::new(new_installation.name())
                .canonical_bytes()
                .unwrap(),
        );
        directory.private_file(
            "materialization.json",
            &StateMaterialization::new(new_epoch.fingerprint())
                .canonical_bytes()
                .unwrap(),
        );
        old_intent.canonical_bytes().unwrap()
    } else if case.starts_with("unreadable") {
        let installation = installation();
        let epoch = super::super::epoch::authority_test_epoch(
            &installation,
            &[0x86; 32],
            state.authority_sha256(),
        );
        directory.private_file("epoch.json", &epoch.canonical_bytes());
        ResetIntent::new(
            state.authority_sha256(),
            &EstablishedState {
                installation,
                epoch,
                material_root: Some([0x86; 32]),
            },
            None,
        )
        .canonical_bytes()
        .unwrap()
    } else {
        b"{malformed}\n".to_vec()
    };
    if case.ends_with("final-and-temp") {
        state.store_reset_intent(&bytes).unwrap();
    }
    if case.starts_with("unreadable") {
        directory.private_file_mode(".reset-intent.json.automata-write", &bytes, 0o000);
    } else {
        directory.private_file(".reset-intent.json.automata-write", &bytes);
    }
    drop(state);
    directory
}

#[tokio::test]
async fn reset_api_validates_staged_intent_before_publication_or_engine_connection() {
    for case in [
        "stale-temp",
        "stale-final-and-temp",
        "malformed-temp",
        "malformed-final-and-temp",
        "unreadable-temp",
        "unreadable-final-and-temp",
    ] {
        let directory = staged_intent_rejection_fixture(case);

        let engine_connections = AtomicU64::new(0);
        let error = reset_local_with_connector(
            LocalResetRequest::new(directory.state_path(), true, CancellationToken::new()),
            || {
                engine_connections.fetch_add(1, Ordering::Relaxed);
                std::future::ready(Err(LocalInitError::new(
                    LocalInitErrorCode::EngineUnavailable,
                )))
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), LocalInitErrorCode::ResetRequired, "{case}");
        assert_eq!(engine_connections.load(Ordering::Relaxed), 0, "{case}");
        assert!(
            directory
                .state_path()
                .join(".reset-intent.json.automata-write")
                .is_file(),
            "{case} must retain staged evidence"
        );
        assert_eq!(
            directory.state_path().join("reset-intent.json").is_file(),
            case.ends_with("final-and-temp"),
            "{case} must perform no publication or unlink"
        );
    }
}

#[tokio::test]
async fn valid_staged_reset_intent_is_published_and_bypasses_entry_cancellation() {
    let directory = TestDirectory::new();
    let state = StateRoot::acquire(&directory.state_path()).unwrap();
    let installation = installation();
    let epoch = super::super::epoch::authority_test_epoch(
        &installation,
        &[0x83; 32],
        state.authority_sha256(),
    );
    directory.private_file("epoch.json", &epoch.canonical_bytes());
    let intent = ResetIntent::new(
        state.authority_sha256(),
        &EstablishedState {
            installation,
            epoch,
            material_root: Some([0x83; 32]),
        },
        None,
    );
    let bytes = intent.canonical_bytes().unwrap();
    directory.private_file(".reset-intent.json.automata-write", &bytes);
    drop(state);

    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let engine_connections = AtomicU64::new(0);
    let error = reset_local_with_connector(
        LocalResetRequest::new(directory.state_path(), true, cancellation),
        || {
            engine_connections.fetch_add(1, Ordering::Relaxed);
            std::future::ready(Err(LocalInitError::new(
                LocalInitErrorCode::EngineUnavailable,
            )))
        },
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), LocalInitErrorCode::EngineUnavailable);
    assert_eq!(engine_connections.load(Ordering::Relaxed), 1);
    assert_eq!(
        fs::read(directory.state_path().join("reset-intent.json")).unwrap(),
        bytes
    );
    assert!(
        !directory
            .state_path()
            .join(".reset-intent.json.automata-write")
            .exists()
    );
}

#[tokio::test]
async fn status_reports_init_frontier_stage_as_incomplete_without_repair() {
    let directory = TestDirectory::new();
    let state = StateRoot::acquire(&directory.state_path()).unwrap();
    drop(state);
    let staged = b"partially-written-selection";
    directory.private_file(".installation-selection.json.automata-write", staged);

    let report = inspect_local_status(LocalStatusRequest::new(
        directory.state_path(),
        CancellationToken::new(),
    ))
    .await
    .unwrap();

    assert_eq!(report.status(), LocalInstallationStatus::Incomplete);
    assert_eq!(report.installation(), None);
    assert!(report.records.installation_selection.0);
    assert_eq!(
        fs::read(
            directory
                .state_path()
                .join(".installation-selection.json.automata-write")
        )
        .unwrap(),
        staged
    );
}

#[tokio::test]
async fn status_accepts_empty_exact_stage_but_rejects_mode_drift() {
    let empty = TestDirectory::new();
    drop(StateRoot::acquire(&empty.state_path()).unwrap());
    empty.private_file(".installation-selection.json.automata-write", b"");
    let report = inspect_local_status(LocalStatusRequest::new(
        empty.state_path(),
        CancellationToken::new(),
    ))
    .await
    .unwrap();
    assert_eq!(report.status(), LocalInstallationStatus::Incomplete);

    let unreadable = TestDirectory::new();
    drop(StateRoot::acquire(&unreadable.state_path()).unwrap());
    unreadable.private_file_mode(
        ".installation-selection.json.automata-write",
        b"partial",
        0o000,
    );
    let error = inspect_local_status(LocalStatusRequest::new(
        unreadable.state_path(),
        CancellationToken::new(),
    ))
    .await
    .unwrap_err();
    assert_eq!(error.code(), LocalInitErrorCode::ResetRequired);

    let empty_final = TestDirectory::new();
    drop(StateRoot::acquire(&empty_final.state_path()).unwrap());
    empty_final.private_file("installation-selection.json", b"");
    let error = inspect_local_status(LocalStatusRequest::new(
        empty_final.state_path(),
        CancellationToken::new(),
    ))
    .await
    .unwrap_err();
    assert_eq!(error.code(), LocalInitErrorCode::ResetRequired);
}

#[tokio::test]
async fn status_reports_valid_staged_reset_intent_without_publishing_it() {
    let directory = TestDirectory::new();
    let state = StateRoot::acquire(&directory.state_path()).unwrap();
    let installation = installation();
    let epoch = super::super::epoch::authority_test_epoch(
        &installation,
        &[0x8b; 32],
        state.authority_sha256(),
    );
    let bytes = ResetIntent::new(
        state.authority_sha256(),
        &EstablishedState {
            installation: installation.clone(),
            epoch: epoch.clone(),
            material_root: Some([0x8b; 32]),
        },
        None,
    )
    .canonical_bytes()
    .unwrap();
    directory.private_file("epoch.json", &epoch.canonical_bytes());
    directory.private_file(".reset-intent.json.automata-write", &bytes);
    drop(state);

    let report = inspect_local_status(LocalStatusRequest::new(
        directory.state_path(),
        CancellationToken::new(),
    ))
    .await
    .unwrap();

    assert_eq!(report.status(), LocalInstallationStatus::ResetInProgress);
    assert_eq!(report.installation(), Some(installation.name().as_str()));
    assert!(report.records.reset_intent.0);
    assert!(report.reset.is_none());
    assert!(!directory.state_path().join("reset-intent.json").exists());
    assert_eq!(
        fs::read(
            directory
                .state_path()
                .join(".reset-intent.json.automata-write")
        )
        .unwrap(),
        bytes
    );
}

#[tokio::test]
async fn pre_cancelled_fresh_reset_precedes_unrelated_corrupt_state() {
    let directory = TestDirectory::new();
    let state = StateRoot::acquire(&directory.state_path()).unwrap();
    directory.private_file("unknown-record", b"corrupt\n");
    drop(state);
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let engine_connections = AtomicU64::new(0);
    let error = reset_local_with_connector(
        LocalResetRequest::new(directory.state_path(), true, cancellation),
        || {
            engine_connections.fetch_add(1, Ordering::Relaxed);
            std::future::ready(Err(LocalInitError::new(
                LocalInitErrorCode::EngineUnavailable,
            )))
        },
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), LocalInitErrorCode::Cancelled);
    assert_eq!(engine_connections.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn status_api_rejects_a_restored_old_intent_against_new_canonical_custody() {
    let directory = TestDirectory::new();
    let state = StateRoot::acquire(&directory.state_path()).unwrap();
    let old_installation = installation();
    let old_epoch = super::super::epoch::authority_test_epoch(
        &old_installation,
        &[0x84; 32],
        state.authority_sha256(),
    );
    let old_intent = ResetIntent::new(
        state.authority_sha256(),
        &EstablishedState {
            installation: old_installation,
            epoch: old_epoch,
            material_root: Some([0x84; 32]),
        },
        None,
    );
    state
        .store_reset_intent(&old_intent.canonical_bytes().unwrap())
        .unwrap();
    let new_installation = Installation::verified(
        InstallationName::new("replacement").unwrap(),
        InstallationId::new(),
    );
    let new_epoch = super::super::epoch::authority_test_epoch(
        &new_installation,
        &[0x85; 32],
        state.authority_sha256(),
    );
    directory.private_file("epoch.json", &new_epoch.canonical_bytes());
    directory.private_file(
        "installation-selection.json",
        &StateInstallationSelection::new(new_installation.name())
            .canonical_bytes()
            .unwrap(),
    );
    directory.private_file(
        "materialization.json",
        &StateMaterialization::new(new_epoch.fingerprint())
            .canonical_bytes()
            .unwrap(),
    );
    drop(state);

    let error = inspect_local_status(LocalStatusRequest::new(
        directory.state_path(),
        CancellationToken::new(),
    ))
    .await
    .unwrap_err();
    assert_eq!(error.code(), LocalInitErrorCode::ResetRequired);
}

fn public_status_reports() -> (
    Sha256Digest,
    [LocalStatusReport; 5],
    LocalStatusReport,
    LocalStatusReport,
) {
    let installation = Installation::verified(
        InstallationName::default(),
        InstallationId::parse_canonical("11111111-1111-4111-8111-111111111111").unwrap(),
    );
    let epoch = super::super::epoch::authority_test_epoch(
        &installation,
        &[0x34; 32],
        Sha256Digest::from_bytes([0x35; 32]),
    );
    let fingerprint = epoch.fingerprint();
    let established = EstablishedState {
        installation,
        epoch,
        material_root: Some([0x34; 32]),
    };
    let records = StatusRecords {
        installation_selection: true.into(),
        material_root: true.into(),
        epoch: true.into(),
        certificates: true.into(),
        materialization: true.into(),
        reset_intent: false.into(),
    };
    let engine = SealedEngineStatus {
        images: Vec::new(),
        volumes: Vec::new(),
    };
    let lifecycle = [
        lifecycle_report(
            records.clone(),
            &established,
            LocalInstallationStatus::RecordedSealed,
            LifecycleReportEvidence::Engine {
                custody: engine.clone(),
                attachments: "absent",
            },
        ),
        lifecycle_report(
            records.clone(),
            &established,
            LocalInstallationStatus::Running,
            LifecycleReportEvidence::Engine {
                custody: engine.clone(),
                attachments: "exact_running_topology",
            },
        ),
        lifecycle_report(
            records.clone(),
            &established,
            LocalInstallationStatus::LifecycleInProgress,
            LifecycleReportEvidence::Guarded {
                volume_contents: "indeterminate_while_busy",
            },
        ),
        lifecycle_report(
            records.clone(),
            &established,
            LocalInstallationStatus::LifecycleRecoveryRequired,
            LifecycleReportEvidence::Guarded {
                volume_contents: "stopped_lock_recovery_required",
            },
        ),
        lifecycle_report(
            records,
            &established,
            LocalInstallationStatus::Degraded,
            LifecycleReportEvidence::Engine {
                custody: engine,
                attachments: "exact_partial_topology",
            },
        ),
    ];
    let incomplete = LocalStatusReport {
        schema: STATUS_SCHEMA,
        status: LocalInstallationStatus::Incomplete,
        installation: Some("default".to_owned()),
        installation_id: None,
        workers: None,
        epoch_fingerprint: None,
        records: StatusRecords {
            installation_selection: true.into(),
            material_root: false.into(),
            epoch: false.into(),
            certificates: false.into(),
            materialization: false.into(),
            reset_intent: false.into(),
        },
        engine: None,
        volume_contents: "not_inspected",
        reset: None,
    };
    let resetting = LocalStatusReport {
        schema: STATUS_SCHEMA,
        status: LocalInstallationStatus::ResetInProgress,
        installation: Some("default".to_owned()),
        installation_id: Some("11111111-1111-4111-8111-111111111111".to_owned()),
        workers: None,
        epoch_fingerprint: Some(fingerprint),
        records: StatusRecords {
            installation_selection: false.into(),
            material_root: false.into(),
            epoch: true.into(),
            certificates: false.into(),
            materialization: false.into(),
            reset_intent: true.into(),
        },
        engine: None,
        volume_contents: "not_inspected",
        reset: Some(StatusReset {
            removed_resources: 7,
            total_resources: 13,
        }),
    };
    (fingerprint, lifecycle, incomplete, resetting)
}

#[test]
fn lifecycle_status_classifier_preserves_lock_dominance_and_topology() {
    let operation_id = OperationId::new();
    let absent = LifecycleLockObservation::Absent;
    let live = LifecycleLockObservation::Live {
        id: "a".repeat(64),
        operation_id,
    };
    let stopped = LifecycleLockObservation::Stopped {
        id: "b".repeat(64),
        operation_id,
    };
    let topologies = [
        (
            LifecycleTopology::Empty,
            LocalInstallationStatus::RecordedSealed,
        ),
        (
            LifecycleTopology::Running {
                transit_id: "c".repeat(64),
            },
            LocalInstallationStatus::Running,
        ),
        (
            LifecycleTopology::Partial,
            LocalInstallationStatus::Degraded,
        ),
    ];

    for (topology, expected) in &topologies {
        assert_eq!(classify_lifecycle_status(&absent, topology), *expected);
        assert_eq!(
            classify_lifecycle_status(&live, topology),
            LocalInstallationStatus::LifecycleInProgress,
        );
        assert_eq!(
            classify_lifecycle_status(&stopped, topology),
            LocalInstallationStatus::LifecycleRecoveryRequired,
        );
    }
}

#[test]
fn stable_status_json_is_exact_and_redacted_for_every_public_state() {
    let (
        fingerprint,
        [
            recorded,
            running,
            lifecycle_in_progress,
            lifecycle_recovery_required,
            degraded,
        ],
        incomplete,
        resetting,
    ) = public_status_reports();

    let recorded_json = serde_json::json!({
        "schema": "automata.local/status/v1",
        "status": "recorded_sealed",
        "installation": "default",
        "installation_id": "11111111-1111-4111-8111-111111111111",
        "workers": 1,
        "epoch_fingerprint": fingerprint.to_string(),
        "records": {
            "installation_selection": true,
            "material_root": true,
            "epoch": true,
            "certificates": true,
            "materialization": true,
            "reset_intent": false
        },
        "engine": {
            "identity": "exact",
            "image_representations": "exact",
            "images": [],
            "owned_union": "exact",
            "volumes": [],
            "attachments": "absent",
            "unknown_managed_resources": "absent"
        },
        "volume_contents": "not_inspected",
        "reset": null
    });
    let lifecycle_json = |status: &str, attachments: &str| {
        let mut value = recorded_json.clone();
        value["status"] = serde_json::json!(status);
        value["engine"]["attachments"] = serde_json::json!(attachments);
        value
    };
    let guarded_json = |status: &str, volume_contents: &str| {
        let mut value = recorded_json.clone();
        value["status"] = serde_json::json!(status);
        value["engine"] = serde_json::Value::Null;
        value["volume_contents"] = serde_json::json!(volume_contents);
        value
    };

    let cases = [
        (
            incomplete,
            serde_json::json!({
                "schema": "automata.local/status/v1",
                "status": "incomplete",
                "installation": "default",
                "installation_id": null,
                "workers": null,
                "epoch_fingerprint": null,
                "records": {
                    "installation_selection": true,
                    "material_root": false,
                    "epoch": false,
                    "certificates": false,
                    "materialization": false,
                    "reset_intent": false
                },
                "engine": null,
                "volume_contents": "not_inspected",
                "reset": null
            }),
        ),
        (recorded, recorded_json.clone()),
        (running, lifecycle_json("running", "exact_running_topology")),
        (
            lifecycle_in_progress,
            guarded_json("lifecycle_in_progress", "indeterminate_while_busy"),
        ),
        (
            lifecycle_recovery_required,
            guarded_json(
                "lifecycle_recovery_required",
                "stopped_lock_recovery_required",
            ),
        ),
        (
            degraded,
            lifecycle_json("degraded", "exact_partial_topology"),
        ),
        (
            resetting,
            serde_json::json!({
                "schema": "automata.local/status/v1",
                "status": "reset_in_progress",
                "installation": "default",
                "installation_id": "11111111-1111-4111-8111-111111111111",
                "workers": null,
                "epoch_fingerprint": fingerprint.to_string(),
                "records": {
                    "installation_selection": false,
                    "material_root": false,
                    "epoch": true,
                    "certificates": false,
                    "materialization": false,
                    "reset_intent": true
                },
                "engine": null,
                "volume_contents": "not_inspected",
                "reset": {"removed_resources": 7, "total_resources": 13}
            }),
        ),
    ];

    for (report, expected) in cases {
        assert_eq!(serde_json::to_value(&report).unwrap(), expected);
        let json = serde_json::to_string(&report).unwrap();
        for forbidden in ["password", "private-key", "secret-key", "material-root"] {
            assert!(!json.contains(forbidden));
        }
    }
}
