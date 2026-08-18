use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
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
            "automata-ci-local-materializer-test-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn descriptor(&self) -> OwnedFd {
        rustix::fs::open(
            &self.0,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap()
    }

    fn file(&self, name: &str, bytes: &[u8], mode: u32) {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(mode)
            .open(self.0.join(name))
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        fs::set_permissions(self.0.join(name), fs::Permissions::from_mode(mode)).unwrap();
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn exact_file_publication_replays_and_recovers_a_fsynced_temporary() {
    let directory = TestDirectory::new();
    let descriptor = directory.descriptor();
    let owner = rustix::process::geteuid().as_raw();
    let group = rustix::process::getegid().as_raw();

    ensure_exact_file(&descriptor, "first", b"one", owner, group, 0o400).unwrap();
    ensure_exact_file(&descriptor, "first", b"one", owner, group, 0o400).unwrap();
    assert_eq!(
        ensure_exact_file(&descriptor, "first", b"two", owner, group, 0o400)
            .unwrap_err()
            .code(),
        LocalInitErrorCode::MaterializationFailed
    );

    directory.file(&temporary_name("second"), b"two", 0o400);
    ensure_exact_file(&descriptor, "second", b"two", owner, group, 0o400).unwrap();
    assert_eq!(
        read_exact_file(&descriptor, "second", 3, owner, group, 0o400).unwrap(),
        b"two"
    );
    assert!(!directory.0.join(temporary_name("second")).exists());
}

#[test]
fn preseal_allows_only_fixed_temps_and_manifest_while_final_seal_is_exact() {
    let directory = TestDirectory::new();
    let descriptor = directory.descriptor();
    directory.file("value", b"v", 0o400);
    directory.file(MANIFEST_FILE, b"m", 0o400);
    let expected = BTreeSet::from(["value".to_owned()]);
    verify_no_extra_entries(&descriptor, &expected, false).unwrap();
    verify_no_extra_entries(&descriptor, &expected, true).unwrap();

    directory.file("foreign", b"x", 0o400);
    assert_eq!(
        verify_no_extra_entries(&descriptor, &expected, false)
            .unwrap_err()
            .code(),
        LocalInitErrorCode::MaterializationFailed
    );
}

#[test]
fn established_tls_directory_metadata_is_exact() {
    let directory = TestDirectory::new();
    let descriptor = directory.descriptor();
    let owner = rustix::process::geteuid().as_raw();
    let group = rustix::process::getegid().as_raw();
    let stat = fstat(&descriptor).unwrap();
    assert!(exact_directory_metadata(&stat, owner, group, 0o700));

    rustix::fs::fchmod(&descriptor, Mode::from_raw_mode(0o755)).unwrap();
    let stat = fstat(&descriptor).unwrap();
    assert!(!exact_directory_metadata(&stat, owner, group, 0o700));
}

#[test]
fn fresh_dynamic_roots_must_be_empty() {
    let directory = TestDirectory::new();
    let descriptor = directory.descriptor();
    verify_empty_directory(&descriptor).unwrap();
    directory.file("stale", b"x", 0o600);
    assert_eq!(
        verify_empty_directory(&descriptor).unwrap_err().code(),
        LocalInitErrorCode::MaterializationFailed
    );
}

#[test]
fn completed_materialization_never_repairs_drifted_root_metadata() {
    let directory = TestDirectory::new();
    let descriptor = directory.descriptor();
    let before = fstat(&descriptor).unwrap();
    assert_eq!(before.st_mode & 0o7777, 0o700);
    assert_eq!(
        prepare_volume_root(&descriptor, VolumeRole::RelayBinding, false)
            .unwrap_err()
            .code(),
        LocalInitErrorCode::MaterializationFailed
    );
    let after = fstat(&descriptor).unwrap();
    assert_eq!(after.st_uid, before.st_uid);
    assert_eq!(after.st_gid, before.st_gid);
    assert_eq!(after.st_mode, before.st_mode);
}

#[test]
fn generated_dynamic_roots_have_closed_namespaces() {
    let directory = TestDirectory::new();
    let descriptor = directory.descriptor();
    directory.file("binding.json", b"{}\n", 0o444);
    directory.file(".binding.json.automata-write", b"{}\n", 0o444);
    verify_dynamic_root_shape(&descriptor, VolumeRole::RelayBinding).unwrap();
    directory.file("foreign", b"x", 0o444);
    assert_eq!(
        verify_dynamic_root_shape(&descriptor, VolumeRole::RelayBinding)
            .unwrap_err()
            .code(),
        LocalInitErrorCode::MaterializationFailed
    );

    let bootstrap = TestDirectory::new();
    let bootstrap_descriptor = bootstrap.descriptor();
    bootstrap.file("request.json", b"{}\n", 0o400);
    bootstrap.file(
        ".automata-bootstrap-receipt-123e4567-e89b-12d3-a456-426614174000.tmp",
        b"{}\n",
        0o400,
    );
    verify_dynamic_root_shape(&bootstrap_descriptor, VolumeRole::BootstrapState).unwrap();
}

#[test]
fn volume_roots_and_static_files_match_the_exact_consumer_role_table() {
    let expected = [
        (VolumeRole::BootstrapState, 65_532, 65_532, 0o700, false),
        (VolumeRole::ControlMaterial, 65_532, 65_532, 0o700, true),
        (VolumeRole::Desired, 0, 0, 0o555, true),
        (VolumeRole::EngineRelay, 65_532, 65_532, 0o700, false),
        (VolumeRole::ObjectData, 10_001, 10_001, 0o750, false),
        (VolumeRole::PostgresConfig, 999, 999, 0o700, true),
        (VolumeRole::PostgresData, 999, 999, 0o700, false),
        (VolumeRole::RelayBinding, 0, 0, 0o555, false),
        (VolumeRole::RunnerConfig, 0, 0, 0o555, false),
        (VolumeRole::RunnerData, 65_532, 65_532, 0o700, false),
        (VolumeRole::RunnerSecrets, 65_532, 65_532, 0o700, false),
        (VolumeRole::RustfsConfig, 10_001, 10_001, 0o700, true),
    ];
    assert_eq!(expected.map(|entry| entry.0), VolumeRole::ALL);
    for (role, uid, gid, mode, static_material) in expected {
        assert_eq!(role.uid(), uid, "{role:?} uid");
        assert_eq!(role.gid(), gid, "{role:?} gid");
        assert_eq!(role.directory_mode(), mode, "{role:?} root mode");
        assert_eq!(role.is_static(), static_material, "{role:?} static flag");
        assert_eq!(
            manifest_mode(role),
            if role == VolumeRole::Desired {
                0o444
            } else {
                0o400
            },
            "{role:?} manifest mode"
        );
    }

    for id in FileId::ALL {
        let file = plan(id, b"x");
        assert_eq!(file.uid, id.volume().uid(), "{id:?} uid");
        assert_eq!(file.gid, id.volume().gid(), "{id:?} gid");
        assert_eq!(
            file.mode,
            if id == FileId::Desired { 0o444 } else { 0o400 },
            "{id:?} mode"
        );
    }
}

#[test]
fn encryption_key_files_are_exact_raw_bytes_not_base64url_text() {
    let installation = crate::desired_spec::tests::installation();
    let material_root = [7_u8; 32];
    let epoch = crate::init::epoch::certificate_test_epoch(&installation, &material_root);
    let deriver = MaterialDeriver::new(material_root, &installation, &epoch);

    for (id, purpose) in [
        (
            FileId::ControlEncryptionKey,
            b"control/encryption-key".as_slice(),
        ),
        (
            FileId::ControlSecretEncryptionKey,
            b"control/secret-encryption-key".as_slice(),
        ),
    ] {
        let plan = derived_key_plan(id, &deriver, purpose);
        let raw = decode_file(&plan).unwrap();
        let encoded = deriver.text(purpose, 32);
        assert_eq!(plan.size, 32);
        assert_eq!(raw.len(), 32);
        assert_eq!(encoded.len(), 43);
        assert_ne!(raw, encoded.as_bytes());
    }
}

#[test]
fn object_store_credentials_and_sse_key_match_the_pinned_scalar_contracts() {
    let installation = crate::desired_spec::tests::installation();
    let material_root = [8_u8; 32];
    let epoch = crate::init::epoch::certificate_test_epoch(&installation, &material_root);
    let deriver = MaterialDeriver::new(material_root, &installation, &epoch);

    let access = s3_access_key(&deriver);
    let secret = s3_secret_key(&deriver);
    let sse = sse_master_key(&deriver);
    assert_eq!(access.len(), 20);
    assert!(
        access
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    );
    assert_eq!(secret.len(), 40);
    assert!(
        secret
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    );
    assert_eq!(sse.len(), 44);
    assert_eq!(STANDARD.decode(sse.as_bytes()).unwrap().len(), 32);

    let control_access = plan(FileId::ControlS3AccessKey, access.as_bytes());
    let rustfs_access = plan(FileId::RustfsAccessKey, access.as_bytes());
    let control_secret = plan(FileId::ControlS3SecretKey, secret.as_bytes());
    let rustfs_secret = plan(FileId::RustfsSecretKey, secret.as_bytes());
    let plans = BTreeMap::from([
        (control_access.id, &control_access),
        (rustfs_access.id, &rustfs_access),
        (control_secret.id, &control_secret),
        (rustfs_secret.id, &rustfs_secret),
    ]);
    exact_equal(&plans, FileId::ControlS3AccessKey, FileId::RustfsAccessKey).unwrap();
    exact_equal(&plans, FileId::ControlS3SecretKey, FileId::RustfsSecretKey).unwrap();
}

#[test]
fn database_url_has_the_exact_query_free_consumer_shape() {
    let url = database_url("URL_safe-password_123");
    assert_eq!(
        url,
        "postgresql://automata:URL_safe-password_123@postgres.automata.invalid:5432/automata\n"
    );
    assert!(url.ends_with('\n'));
    assert!(!url.contains('?'));
    assert!(!url.contains('#'));
}

#[test]
fn stdin_request_framing_rejects_empty_oversize_partial_and_noncanonical_input() {
    assert_eq!(
        read_fixed_request_from(&b""[..]).unwrap_err().code(),
        LocalInitErrorCode::MaterializationFailed
    );
    let oversized = vec![b'x'; MAX_REQUEST_BYTES + 1];
    assert_eq!(
        read_fixed_request_from(oversized.as_slice())
            .unwrap_err()
            .code(),
        LocalInitErrorCode::MaterializationFailed
    );
    let partial = read_fixed_request_from(&b"{"[..]).unwrap();
    assert_eq!(
        parse_fixed_request(&partial).err().unwrap().code(),
        LocalInitErrorCode::MaterializationFailed
    );

    let request = MaterializeRequest {
        schema: REQUEST_SCHEMA.to_owned(),
        epoch_fingerprint: Sha256Digest::from_bytes([0x11; 32]),
        initial_desired_sha256: Sha256Digest::from_bytes([0x22; 32]),
        fresh_dynamic_roots: true,
        volumes: Vec::new(),
        files: Vec::new(),
    };
    let canonical = request.canonical_bytes().unwrap();
    assert!(parse_fixed_request(&canonical).is_ok());
    let mut noncanonical = b" ".to_vec();
    noncanonical.extend_from_slice(&canonical);
    assert_eq!(
        parse_fixed_request(&noncanonical).err().unwrap().code(),
        LocalInitErrorCode::MaterializationFailed
    );
}

#[test]
fn established_desired_manifest_is_bound_to_initial_epoch_provenance() {
    let epoch = Sha256Digest::from_bytes([1; 32]);
    let desired = Sha256Digest::from_bytes([3; 32]);
    let manifest = StaticManifest {
        schema: MANIFEST_SCHEMA.to_owned(),
        epoch_fingerprint: epoch,
        volume: VolumeRole::Desired,
        files: vec![ManifestFile {
            id: FileId::Desired,
            path: FileId::Desired.path().to_owned(),
            sha256: desired,
            size: 456,
            uid: VolumeRole::Desired.uid(),
            gid: VolumeRole::Desired.gid(),
            mode: FileId::Desired.mode(),
        }],
    };
    let mut stored = serde_json::to_vec(&manifest).unwrap();
    stored.push(b'\n');
    validate_stored_desired_manifest_descriptor(&stored, &manifest, epoch, desired).unwrap();

    let current_desired_digest = Sha256Digest::from_bytes([4; 32]);
    assert_ne!(current_desired_digest, desired);
    assert_eq!(
        validate_stored_desired_manifest_descriptor(
            &stored,
            &manifest,
            epoch,
            current_desired_digest,
        )
        .unwrap_err()
        .code(),
        LocalInitErrorCode::MaterializationFailed
    );
}
