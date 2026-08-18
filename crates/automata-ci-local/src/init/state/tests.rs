use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::ffi::OsStringExt as _,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _, symlink},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use super::*;

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
            "automata-ci-local-init-state-test-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn private_file(&self, name: &str, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.join(name))
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn relative_state_paths_are_rejected_before_io() {
    assert_eq!(
        validate_absolute_path(Path::new("relative"), true)
            .unwrap_err()
            .code(),
        LocalInitErrorCode::InvalidStateDirectory
    );
}

#[test]
fn state_namespace_accepts_only_one_strict_record_frontier() {
    let set = |names: &[&str]| {
        names
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<BTreeSet<_>>()
    };
    for valid in [
        set(&[OPERATION_LOCK]),
        set(&[OPERATION_LOCK, &temporary_name(INSTALLATION_SELECTION)]),
        set(&[OPERATION_LOCK, INSTALLATION_SELECTION]),
        set(&[
            OPERATION_LOCK,
            INSTALLATION_SELECTION,
            &temporary_name(MATERIAL_ROOT),
        ]),
        set(&[
            OPERATION_LOCK,
            INSTALLATION_SELECTION,
            MATERIAL_ROOT,
            &temporary_name(MATERIAL_ROOT),
        ]),
    ] {
        validate_init_record_layout(&valid, None).unwrap();
    }

    for invalid in [
        set(&[OPERATION_LOCK, EPOCH_RECORD]),
        set(&[OPERATION_LOCK, MATERIAL_ROOT]),
        set(&[
            OPERATION_LOCK,
            &temporary_name(INSTALLATION_SELECTION),
            &temporary_name(MATERIAL_ROOT),
        ]),
        set(&[
            OPERATION_LOCK,
            INSTALLATION_SELECTION,
            &temporary_name(EPOCH_RECORD),
        ]),
        set(&[OPERATION_LOCK, "unknown-private-state"]),
    ] {
        assert_eq!(
            validate_init_record_layout(&invalid, None)
                .unwrap_err()
                .code(),
            LocalInitErrorCode::ResetRequired
        );
    }
}

#[test]
fn unknown_and_non_utf8_state_entries_are_rejected_at_acquisition() {
    for name in [
        OsString::from("unknown-private-state"),
        OsString::from_vec(vec![b'n', b'o', b'n', 0xff]),
    ] {
        let parent = TestDirectory::new();
        let path = parent.join("state");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path.join(name))
            .unwrap();
        file.write_all(b"opaque\n").unwrap();
        file.sync_all().unwrap();

        assert_eq!(
            StateRoot::acquire(&path).err().unwrap().code(),
            LocalInitErrorCode::ResetRequired
        );
    }
}

#[test]
fn successful_state_layout_has_four_then_five_exact_records_without_temporaries() {
    let parent = TestDirectory::new();
    let path = parent.join("state");
    let state = StateRoot::acquire(&path).unwrap();
    state.store_installation_selection(b"selection\n").unwrap();
    state.create_material_root().unwrap();
    state.store_epoch(b"epoch\n").unwrap();
    state.store_certificates(b"certificates\n").unwrap();
    state.validate_before_materialization().unwrap();
    assert_eq!(
        state.validate_complete().unwrap_err().code(),
        LocalInitErrorCode::ResetRequired
    );
    state.store_materialization(b"materialization\n").unwrap();
    state.validate_complete().unwrap();

    let names = fs::read_dir(&path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        names,
        [
            OPERATION_LOCK,
            INSTALLATION_SELECTION,
            MATERIAL_ROOT,
            EPOCH_RECORD,
            CERTIFICATE_RECORD,
            MATERIALIZATION_RECORD,
        ]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect()
    );
}

#[test]
fn record_publication_apis_enforce_the_exact_durable_prefix() {
    let parent = TestDirectory::new();
    let path = parent.join("state");
    let state = StateRoot::acquire(&path).unwrap();

    let future_temporary = temporary_name(EPOCH_RECORD);
    parent.private_file(&format!("state/{future_temporary}"), b"epoch\n");
    assert_eq!(
        state.load_epoch().unwrap_err().code(),
        LocalInitErrorCode::ResetRequired
    );
    assert!(path.join(&future_temporary).exists());
    fs::remove_file(path.join(&future_temporary)).unwrap();

    parent.private_file("state/unknown-private-state", b"opaque\n");
    assert_eq!(
        state.load_installation_selection().unwrap_err().code(),
        LocalInitErrorCode::ResetRequired
    );
    fs::remove_file(path.join("unknown-private-state")).unwrap();

    assert_eq!(
        state.create_material_root().unwrap_err().code(),
        LocalInitErrorCode::ResetRequired
    );
    for result in [
        state.store_epoch(b"epoch\n"),
        state.store_certificates(b"certificates\n"),
        state.store_materialization(b"materialization\n"),
    ] {
        assert_eq!(
            result.unwrap_err().code(),
            LocalInitErrorCode::ResetRequired
        );
    }

    state.store_installation_selection(b"selection\n").unwrap();
    assert_eq!(
        state.store_epoch(b"epoch\n").unwrap_err().code(),
        LocalInitErrorCode::ResetRequired
    );
    let material_root = state.create_material_root().unwrap();
    assert_eq!(state.create_material_root().unwrap(), material_root);
    assert_eq!(
        state
            .store_certificates(b"certificates\n")
            .unwrap_err()
            .code(),
        LocalInitErrorCode::ResetRequired
    );
    state.store_epoch(b"epoch\n").unwrap();
    assert_eq!(
        state
            .store_materialization(b"materialization\n")
            .unwrap_err()
            .code(),
        LocalInitErrorCode::ResetRequired
    );
    state.store_certificates(b"certificates\n").unwrap();
    state.store_materialization(b"materialization\n").unwrap();

    state.store_installation_selection(b"selection\n").unwrap();
    state.store_epoch(b"epoch\n").unwrap();
    state.store_certificates(b"certificates\n").unwrap();
    state.store_materialization(b"materialization\n").unwrap();
    state.validate_complete().unwrap();
}

#[test]
fn state_root_exact_replay_locking_and_tamper_are_fail_closed() {
    let parent = TestDirectory::new();
    let path = parent.join("state");
    let state = StateRoot::acquire(&path).unwrap();

    assert_eq!(state.load_material_root().unwrap(), None);
    state
        .store_installation_selection(b"installation-selection\n")
        .unwrap();
    let material_root = state.create_material_root().unwrap();
    assert_eq!(material_root.len(), 32);
    assert_eq!(state.load_material_root().unwrap(), Some(material_root));
    state.store_epoch(b"epoch-one\n").unwrap();
    state.store_epoch(b"epoch-one\n").unwrap();
    assert_eq!(state.load_epoch().unwrap().unwrap(), b"epoch-one\n");
    assert_eq!(
        state.store_epoch(b"epoch-two\n").unwrap_err().code(),
        LocalInitErrorCode::ResetRequired
    );

    let metadata = fs::metadata(&path).unwrap();
    assert_eq!(metadata.mode() & 0o7777, 0o700);
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    for name in [
        OPERATION_LOCK,
        INSTALLATION_SELECTION,
        MATERIAL_ROOT,
        EPOCH_RECORD,
    ] {
        let metadata = fs::metadata(path.join(name)).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(metadata.nlink(), 1);
    }

    assert_eq!(
        StateRoot::acquire(&path).err().unwrap().code(),
        LocalInitErrorCode::OperationInProgress
    );
    drop(state);

    fs::set_permissions(path.join(MATERIAL_ROOT), fs::Permissions::from_mode(0o644)).unwrap();
    let state = StateRoot::acquire(&path).unwrap();
    assert_eq!(
        state.load_material_root().unwrap_err().code(),
        LocalInitErrorCode::ResetRequired
    );
}

#[test]
fn interrupted_private_file_publication_is_recovered_exactly_once() {
    let parent = TestDirectory::new();
    let path = parent.join("state");
    let state = StateRoot::acquire(&path).unwrap();

    let selection = b"installation-selection\n";
    let temporary = format!(".{INSTALLATION_SELECTION}.automata-write");
    parent.private_file(&format!("state/{temporary}"), selection);
    assert_eq!(
        state.load_installation_selection().unwrap().as_deref(),
        Some(selection.as_slice())
    );
    assert!(!path.join(&temporary).exists());

    let root = [0x5a_u8; 32];
    let temporary = format!(".{MATERIAL_ROOT}.automata-write");
    parent.private_file(&format!("state/{temporary}"), &root);
    assert_eq!(state.load_material_root().unwrap(), Some(root));
    assert!(!path.join(&temporary).exists());

    let epoch = b"canonical-epoch\n";
    let temporary = format!(".{EPOCH_RECORD}.automata-write");
    parent.private_file(&format!("state/{temporary}"), epoch);

    state.store_epoch(epoch).unwrap();
    assert_eq!(
        state.load_epoch().unwrap().as_deref(),
        Some(epoch.as_slice())
    );
    assert!(!path.join(&temporary).exists());

    let certificates = b"one-time-certificate-record\n";
    let temporary = format!(".{CERTIFICATE_RECORD}.automata-write");
    parent.private_file(&format!("state/{temporary}"), certificates);
    assert_eq!(
        state.load_certificates().unwrap().as_deref(),
        Some(certificates.as_slice())
    );
    assert!(!path.join(&temporary).exists());
}

#[test]
fn replay_frontier_must_be_recovered_and_reenumerated_before_engine_work() {
    let parent = TestDirectory::new();
    let path = parent.join("state");
    let state = StateRoot::acquire(&path).unwrap();
    state
        .store_installation_selection(b"installation-selection\n")
        .unwrap();
    state.create_material_root().unwrap();
    let temporary = format!(".{EPOCH_RECORD}.automata-write");
    parent.private_file(&format!("state/{temporary}"), b"epoch\n");

    assert_eq!(
        state.validate_recovered_layout().unwrap_err().code(),
        LocalInitErrorCode::ResetRequired
    );
    assert_eq!(
        state.load_epoch().unwrap().as_deref(),
        Some(b"epoch\n".as_slice())
    );
    state.validate_recovered_layout().unwrap();
    assert!(!path.join(temporary).exists());
}

#[test]
fn existing_operation_lock_metadata_is_verified_without_repair() {
    let parent = TestDirectory::new();
    let path = parent.join("state");
    drop(StateRoot::acquire(&path).unwrap());
    let lock = path.join(OPERATION_LOCK);
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o640)).unwrap();

    assert_eq!(
        StateRoot::acquire(&path).err().unwrap().code(),
        LocalInitErrorCode::ResetRequired
    );
    assert_eq!(fs::metadata(lock).unwrap().mode() & 0o7777, 0o640);
}

#[test]
fn copied_state_tree_and_replaced_lock_have_distinct_authority() {
    let parent = TestDirectory::new();
    let original_path = parent.join("original");
    let original = StateRoot::acquire(&original_path).unwrap();
    let original_authority = original.authority_sha256();
    original
        .store_installation_selection(b"installation-selection\n")
        .unwrap();
    original.create_material_root().unwrap();
    original.store_epoch(b"epoch\n").unwrap();
    drop(original);

    let copied_path = parent.join("copied");
    fs::create_dir(&copied_path).unwrap();
    fs::set_permissions(&copied_path, fs::Permissions::from_mode(0o700)).unwrap();
    for name in [
        OPERATION_LOCK,
        INSTALLATION_SELECTION,
        MATERIAL_ROOT,
        EPOCH_RECORD,
    ] {
        fs::copy(original_path.join(name), copied_path.join(name)).unwrap();
        fs::set_permissions(copied_path.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    let copied = StateRoot::acquire(&copied_path).unwrap();
    assert_ne!(copied.authority_sha256(), original_authority);
    drop(copied);

    let held = StateRoot::acquire(&original_path).unwrap();
    assert_eq!(held.authority_sha256(), original_authority);
    fs::remove_file(original_path.join(OPERATION_LOCK)).unwrap();
    parent.private_file("original/operation.lock", b"");
    let replacement = StateRoot::acquire(&original_path).unwrap();
    assert_ne!(replacement.authority_sha256(), held.authority_sha256());
}

#[test]
fn conflicting_completed_and_temporary_records_require_reset() {
    let parent = TestDirectory::new();
    let path = parent.join("state");
    let state = StateRoot::acquire(&path).unwrap();
    state
        .store_installation_selection(b"installation-selection\n")
        .unwrap();
    state.create_material_root().unwrap();
    state.store_epoch(b"completed\n").unwrap();
    parent.private_file(
        &format!("state/.{EPOCH_RECORD}.automata-write"),
        b"different\n",
    );

    assert_eq!(
        state.load_epoch().unwrap_err().code(),
        LocalInitErrorCode::ResetRequired
    );

    fs::remove_file(path.join(format!(".{EPOCH_RECORD}.automata-write"))).unwrap();
    parent.private_file(
        &format!("state/.{EPOCH_RECORD}.automata-write"),
        b"completed\n",
    );
    assert_eq!(state.load_epoch().unwrap().unwrap(), b"completed\n");
    assert!(
        !path
            .join(format!(".{EPOCH_RECORD}.automata-write"))
            .exists()
    );
}

#[test]
fn symlink_state_and_evidence_paths_are_never_followed() {
    let parent = TestDirectory::new();
    let real_state = parent.join("real-state");
    fs::create_dir(&real_state).unwrap();
    fs::set_permissions(&real_state, fs::Permissions::from_mode(0o700)).unwrap();
    let state_link = parent.join("state-link");
    symlink(&real_state, &state_link).unwrap();
    assert_eq!(
        StateRoot::acquire(&state_link).err().unwrap().code(),
        LocalInitErrorCode::InvalidStateDirectory
    );

    parent.private_file("catalog.json", b"{}\n");
    parent.private_file("candidate.tar", b"candidate");
    symlink(
        parent.join("candidate.tar"),
        parent.join("candidate-link.tar"),
    )
    .unwrap();
    let evidence =
        EvidenceDirectory::open(&format!("file:{}", parent.join("catalog.json").display()))
            .unwrap();
    assert_eq!(evidence.catalog(), b"{}\n");
    assert_eq!(
        evidence
            .read_candidate("candidate-link.tar")
            .unwrap_err()
            .code(),
        LocalInitErrorCode::InvalidCatalogPayload
    );
    assert_eq!(
        evidence
            .read_candidate("../candidate.tar")
            .unwrap_err()
            .code(),
        LocalInitErrorCode::InvalidCatalogPayload
    );
}

#[test]
fn evidence_files_must_be_regular_single_link_owned_immutable_siblings() {
    let parent = TestDirectory::new();
    parent.private_file("catalog.json", b"{}\n");
    fs::hard_link(
        parent.join("catalog.json"),
        parent.join("catalog-copy.json"),
    )
    .unwrap();
    assert_eq!(
        EvidenceDirectory::open(&format!("file:{}", parent.join("catalog.json").display()))
            .err()
            .unwrap()
            .code(),
        LocalInitErrorCode::InvalidCatalogSource
    );

    fs::remove_file(parent.join("catalog-copy.json")).unwrap();
    fs::set_permissions(
        parent.join("catalog.json"),
        fs::Permissions::from_mode(0o620),
    )
    .unwrap();
    assert_eq!(
        EvidenceDirectory::open(&format!("file:{}", parent.join("catalog.json").display()))
            .err()
            .unwrap()
            .code(),
        LocalInitErrorCode::InvalidCatalogSource
    );
}

#[test]
fn noncanonical_absolute_paths_are_rejected() {
    for path in ["/", "/tmp/", "/tmp//state", "/tmp/./state", "/tmp/../state"] {
        assert_eq!(
            validate_absolute_path(Path::new(path), true)
                .unwrap_err()
                .code(),
            LocalInitErrorCode::InvalidStateDirectory,
            "{path}"
        );
    }
}
