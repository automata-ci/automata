use crate::support;

use std::sync::Arc;

use automata_ci_core::Sha256Digest;
use automata_ci_runner_spool::{
    ContentCommitmentDomain, ContentKind, ContentProtectionError, ContentProtector,
    DurableContentRef, DurableContentStore, FileSpool, ProtectionId, SpoolError,
};
use sha2::{Digest as _, Sha256};
use support::{Scratch, StaticRetainSet, TestProtector, adopt};

struct TestKeyring {
    active: TestProtector,
    decrypt_only: Vec<TestProtector>,
}

impl TestKeyring {
    fn new(active: (&str, u8), decrypt_only: &[(&str, u8)]) -> Self {
        Self {
            active: TestProtector::new(active.0, active.1),
            decrypt_only: decrypt_only
                .iter()
                .map(|(id, marker)| TestProtector::new(id, *marker))
                .collect(),
        }
    }

    fn exact(&self, id: &ProtectionId) -> Option<&TestProtector> {
        if self.active.protection_id() == id {
            return Some(&self.active);
        }
        self.decrypt_only
            .iter()
            .find(|protector| protector.protection_id() == id)
    }
}

impl ContentProtector for TestKeyring {
    fn protection_id(&self) -> &ProtectionId {
        self.active.protection_id()
    }

    fn supports_protection_id(&self, protection_id: &ProtectionId) -> bool {
        self.exact(protection_id).is_some()
    }

    fn keyed_commitment(
        &self,
        protection_id: &ProtectionId,
        domain: ContentCommitmentDomain,
        material_digest: &[u8; 32],
    ) -> Result<[u8; 32], ContentProtectionError> {
        self.exact(protection_id)
            .ok_or(ContentProtectionError::KeyUnavailable)?
            .keyed_commitment(protection_id, domain, material_digest)
    }

    fn endpoint_result_protected_bytes(
        &self,
        plaintext_bytes: u64,
    ) -> Result<u64, ContentProtectionError> {
        self.active.endpoint_result_protected_bytes(plaintext_bytes)
    }

    fn protect(
        &self,
        reference: &DurableContentRef,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ContentProtectionError> {
        self.active.protect(reference, plaintext)
    }

    fn unprotect(
        &self,
        reference: &DurableContentRef,
        protected: &[u8],
    ) -> Result<Vec<u8>, ContentProtectionError> {
        self.exact(reference.protection_id())
            .ok_or(ContentProtectionError::KeyUnavailable)?
            .unprotect(reference, protected)
    }
}

fn keyring(active: (&str, u8), decrypt_only: &[(&str, u8)]) -> Arc<TestKeyring> {
    Arc::new(TestKeyring::new(active, decrypt_only))
}

#[test]
fn keyed_commitments_replay_with_the_exact_old_key_and_rotate_for_new_requests() {
    let scratch = Scratch::new("keyed-commitment-rotation");
    let root = scratch.spool_root();
    let digest = [0x31; 32];
    let before =
        FileSpool::open(root.clone(), keyring(("spool-v1", 0x11), &[])).expect("open old spool");
    let old = before
        .create_keyed_commitment(ContentCommitmentDomain::EndpointRequest, &digest)
        .expect("old commitment");
    drop(before);

    let rotated = FileSpool::open(root, keyring(("spool-v2", 0x22), &[("spool-v1", 0x11)]))
        .expect("open rotated spool");
    let replay = rotated
        .recreate_keyed_commitment(
            old.protection_id(),
            ContentCommitmentDomain::EndpointRequest,
            &digest,
        )
        .expect("recreate old commitment");
    let current = rotated
        .create_keyed_commitment(ContentCommitmentDomain::EndpointRequest, &digest)
        .expect("create current commitment");
    assert_eq!(replay, old);
    assert_ne!(current, old);
    assert_eq!(current.protection_id().as_str(), "spool-v2");
}

fn reference(id: &str, plaintext: &[u8]) -> DurableContentRef {
    DurableContentRef::after_public_commit(
        ContentKind::JobIr,
        u64::try_from(plaintext.len()).expect("fixture size"),
        Sha256Digest::from_bytes(Sha256::digest(plaintext).into()),
        ProtectionId::new(id).expect("valid protection ID"),
    )
    .expect("valid reference")
}

#[test]
fn rotation_preserves_old_reads_and_uses_exact_ids_for_remove_and_reconcile() {
    let scratch = Scratch::new("key-rotation");
    let root = scratch.spool_root();
    let before_rotation =
        FileSpool::open(root.clone(), keyring(("spool-v1", 0x11), &[])).expect("open old spool");
    let old_to_remove = adopt(
        before_rotation
            .persist(ContentKind::RuntimeAuthority, b"old authority")
            .expect("persist old removable object"),
    );
    let old_to_retain = adopt(
        before_rotation
            .persist(ContentKind::JobIr, b"old retained JobIR")
            .expect("persist old retained object"),
    );
    drop(before_rotation);

    let rotated = FileSpool::open(root, keyring(("spool-v2", 0x22), &[("spool-v1", 0x11)]))
        .expect("open rotated spool");
    assert_eq!(
        rotated.load(&old_to_remove).expect("load exact old key"),
        b"old authority"
    );
    let new_reference = adopt(
        rotated
            .persist(ContentKind::JobIr, b"old retained JobIR")
            .expect("re-persist identical plaintext with active key"),
    );
    assert_eq!(new_reference.protection_id().as_str(), "spool-v2");
    assert_eq!(old_to_retain.protection_id().as_str(), "spool-v1");
    assert_ne!(
        new_reference, old_to_retain,
        "rotation must not deduplicate a new publication onto an old key ID"
    );

    assert!(
        rotated
            .remove(&old_to_remove)
            .expect("old object is authenticated with its exact old key")
    );
    assert_eq!(
        rotated.load(&new_reference).expect("new object remains"),
        b"old retained JobIR"
    );

    rotated
        .reconcile(&StaticRetainSet::new([old_to_retain.clone()]))
        .expect("old retained reference authenticates during reconciliation");
    assert_eq!(
        rotated.load(&old_to_retain).expect("old object retained"),
        b"old retained JobIR"
    );
    assert!(matches!(
        rotated.load(&new_reference),
        Err(SpoolError::ContentMissing)
    ));
}

#[test]
fn endpoint_result_opaque_identity_rotates_and_old_exact_key_remains_readable() {
    let scratch = Scratch::new("endpoint-result-key-rotation");
    let root = scratch.spool_root();
    let plaintext = b"low entropy result: 0427";
    let before =
        FileSpool::open(root.clone(), keyring(("spool-v1", 0x11), &[])).expect("old spool");
    let old = adopt(
        before
            .reserve_endpoint_result(64)
            .expect("old reservation")
            .persist(plaintext)
            .expect("old result"),
    );
    drop(before);

    let rotated = FileSpool::open(root, keyring(("spool-v2", 0x22), &[("spool-v1", 0x11)]))
        .expect("rotated spool");
    assert_eq!(rotated.load(&old).expect("old exact key opens"), plaintext);
    let current = adopt(
        rotated
            .reserve_endpoint_result(64)
            .expect("new reservation")
            .persist(plaintext)
            .expect("new result"),
    );
    assert_ne!(
        current.endpoint_result_identity(),
        old.endpoint_result_identity()
    );
    assert_ne!(current.cache_key(), old.cache_key());
    assert_eq!(current.protection_id().as_str(), "spool-v2");
    assert_eq!(old.protection_id().as_str(), "spool-v1");
}

#[test]
fn unknown_key_ids_fail_before_missing_or_idempotent_filesystem_results() {
    let scratch = Scratch::new("unknown-rotation-key");
    let spool = FileSpool::open(
        scratch.spool_root(),
        keyring(("spool-v2", 0x22), &[("spool-v1", 0x11)]),
    )
    .expect("open rotated spool");
    let unknown = reference("spool-retired", b"referenced by durable journal");

    for result in [
        spool.load(&unknown),
        spool.remove(&unknown).map(|_| Vec::new()),
    ] {
        assert!(matches!(
            result,
            Err(SpoolError::Protection(
                ContentProtectionError::KeyUnavailable
            ))
        ));
    }
    assert!(matches!(
        spool.reconcile(&StaticRetainSet::new([unknown])),
        Err(SpoolError::Protection(
            ContentProtectionError::KeyUnavailable
        ))
    ));
}
