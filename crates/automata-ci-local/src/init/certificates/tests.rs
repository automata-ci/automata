use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{Installation, InstallationId, InstallationName};

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
            "automata-ci-local-certificates-test-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn certificate_roles_and_hosts_are_closed() {
    assert_eq!(POSTGRES_HOST, "postgres.automata.invalid");
    assert_eq!(OBJECT_HOST, "objects.automata.invalid");
    assert_eq!(RUNNER_HOST, "runner.automata.invalid");
    assert_ne!(CA_ROLE, RUNNER_ROLE);
}

#[test]
fn certificate_serial_is_a_positive_nonzero_canonical_der_magnitude() {
    let mut leading_zero = [0xa5; 20];
    leading_zero[0] = 0;
    let serial = canonical_serial_bytes(leading_zero);
    assert_eq!(serial[0], 1);
    assert_ne!(serial[0], 0);
    assert_eq!(serial[0] & 0x80, 0);

    let mut high_bit = [0x5a; 20];
    high_bit[0] = 0xfe;
    let serial = canonical_serial_bytes(high_bit);
    assert_eq!(serial[0], 0x7f);
    assert_eq!(serial.len(), 20);
}

#[test]
fn one_time_certificate_record_round_trips_and_tampering_fails_closed() {
    let directory = TestDirectory::new();
    let state = StateRoot::acquire(&directory.0.join("state")).unwrap();
    let installation = Installation::verified(InstallationName::default(), InstallationId::new());
    state
        .store_installation_selection(b"installation-selection\n")
        .unwrap();
    let root = state.create_material_root().unwrap();
    let epoch = super::super::epoch::certificate_test_epoch(&installation, &root);
    state.store_epoch(&epoch.canonical_bytes()).unwrap();
    let deriver = MaterialDeriver::new(root, &installation, &epoch);

    let issued = load_or_issue(&state, &deriver, &epoch, false).unwrap();
    let replayed = load_or_issue(&state, &deriver, &epoch, true).unwrap();
    assert_eq!(issued.ca_pem, replayed.ca_pem);
    assert_eq!(issued.postgres_chain_pem, replayed.postgres_chain_pem);
    assert_eq!(issued.object_chain_pem, replayed.object_chain_pem);
    assert_eq!(issued.runner_chain_pem, replayed.runner_chain_pem);

    let bytes = state.load_certificates().unwrap().unwrap();
    let mut record: CertificateRecord = serde_json::from_slice(&bytes).unwrap();
    record
        .certificates
        .get_mut(POSTGRES_ROLE)
        .unwrap()
        .serial_hex = "01".to_owned();
    assert_eq!(
        validate_record(
            &canonical_bytes(&record).unwrap(),
            &DerivedKeys::new(&deriver).unwrap(),
            &epoch
        )
        .err()
        .unwrap()
        .code(),
        LocalInitErrorCode::ResetRequired
    );

    let mut record: CertificateRecord = serde_json::from_slice(&bytes).unwrap();
    let postgres = record.certificates.get_mut(POSTGRES_ROLE).unwrap();
    postgres.chain_pem = postgres.leaf_pem.clone();
    postgres.chain_sha256 = digest(postgres.chain_pem.as_bytes());
    assert_eq!(
        validate_record(
            &canonical_bytes(&record).unwrap(),
            &DerivedKeys::new(&deriver).unwrap(),
            &epoch
        )
        .err()
        .unwrap()
        .code(),
        LocalInitErrorCode::ResetRequired
    );
}
