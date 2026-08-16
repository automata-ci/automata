use crate::support;

use std::{fs, sync::Arc};

use automata_ci_core::Sha256Digest;
use automata_ci_runner_spool::{
    ContentCommitmentDomain, ContentKind, ContentProtectionError, ContentProtector,
    DurableContentRef, DurableContentStore, FileSpool, FileSpoolOptions, OpaqueContentIdentity,
    ProtectionId, SpoolError, SpoolInvariantError, SpoolLimits, endpoint_result_allocation,
};
use sha2::{Digest as _, Sha256};
use support::{Scratch, TestProtector, adopt, content_path};

fn protector(marker: u8) -> Arc<TestProtector> {
    Arc::new(TestProtector::new("endpoint-key", marker))
}

fn bounded_spool(label: &str, limits: SpoolLimits) -> (Scratch, FileSpool) {
    let scratch = Scratch::new(label);
    let spool = FileSpool::open_with_options(
        scratch.spool_root(),
        protector(0x71),
        FileSpoolOptions::new().with_limits(limits),
    )
    .expect("open bounded spool");
    (scratch, spool)
}

enum PreflightFailure {
    WrongSize,
    Unavailable,
}

struct PreflightProtector {
    inner: TestProtector,
    failure: PreflightFailure,
}

impl ContentProtector for PreflightProtector {
    fn protection_id(&self) -> &ProtectionId {
        self.inner.protection_id()
    }

    fn keyed_commitment(
        &self,
        protection_id: &ProtectionId,
        domain: ContentCommitmentDomain,
        material_digest: &[u8; 32],
    ) -> Result<[u8; 32], ContentProtectionError> {
        self.inner
            .keyed_commitment(protection_id, domain, material_digest)
    }

    fn endpoint_result_protected_bytes(
        &self,
        plaintext_bytes: u64,
    ) -> Result<u64, ContentProtectionError> {
        match self.failure {
            PreflightFailure::WrongSize => endpoint_result_allocation(plaintext_bytes)
                .map(|bytes| bytes + 1)
                .map_err(|_| ContentProtectionError::Failed),
            PreflightFailure::Unavailable => Err(ContentProtectionError::KeyUnavailable),
        }
    }

    fn protect(
        &self,
        reference: &DurableContentRef,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ContentProtectionError> {
        self.inner.protect(reference, plaintext)
    }

    fn unprotect(
        &self,
        reference: &DurableContentRef,
        protected: &[u8],
    ) -> Result<Vec<u8>, ContentProtectionError> {
        self.inner.unprotect(reference, protected)
    }
}

#[test]
fn allocation_classes_are_deterministic_and_hide_exact_lengths() {
    assert_eq!(endpoint_result_allocation(0).expect("zero"), 64 * 1024);
    assert_eq!(endpoint_result_allocation(1).expect("one"), 64 * 1024);
    assert_eq!(
        endpoint_result_allocation(65_460).expect("last first-class payload"),
        64 * 1024
    );
    assert_eq!(
        endpoint_result_allocation(65_461).expect("first second-class payload"),
        128 * 1024
    );
    assert!(
        automata_ci_runner_spool::DurableContentRef::after_endpoint_result_commit(
            65_537,
            OpaqueContentIdentity::from_bytes([0x55; 32]),
            ProtectionId::new("endpoint-key").expect("key ID"),
        )
        .is_err()
    );
}

#[test]
fn endpoint_result_reference_has_no_plaintext_digest_or_exact_size_oracle() {
    let scratch = Scratch::new("endpoint-opaque-identity");
    let spool = FileSpool::open(scratch.spool_root(), protector(0x51)).expect("open spool");
    let plaintext = b"0427";
    let reference = adopt(
        spool
            .reserve_endpoint_result(plaintext.len().try_into().expect("size"))
            .expect("reserve")
            .persist(plaintext)
            .expect("persist reserved result"),
    );

    assert_eq!(reference.public_plaintext_bytes(), None);
    assert_eq!(reference.public_plaintext_sha256(), None);
    assert_eq!(
        reference.endpoint_result_allocation_bytes(),
        Some(64 * 1024)
    );
    assert_eq!(reference.accounted_bytes(), 64 * 1024);
    assert_eq!(spool.load(&reference).expect("open result"), plaintext);

    let plaintext_digest = Sha256Digest::from_bytes(Sha256::digest(plaintext).into()).to_string();
    let serialized = serde_json::to_string(&reference).expect("serialize current ref");
    let decoded: automata_ci_runner_spool::DurableContentRef =
        serde_json::from_str(&serialized).expect("current ref decodes");
    assert_eq!(decoded, reference);
    let debug = format!("{reference:?}");
    for exposed in [&serialized, &debug, reference.cache_key().as_str()] {
        assert!(!exposed.contains(&plaintext_digest));
        assert!(!exposed.contains("plaintext_bytes"));
        assert!(!exposed.contains("plaintext_sha256"));
    }
    assert!(!serialized.contains(":4,"));

    for candidate in [b"0000".as_slice(), b"0427", b"9999"] {
        let digest = Sha256Digest::from_bytes(Sha256::digest(candidate).into()).to_string();
        assert!(!reference.cache_key().as_str().contains(&digest));
        assert!(!serialized.contains(&digest));
    }

    let old_shape = format!(
        r#"{{"kind":"endpoint_result","size":4,"sha256":"{plaintext_digest}","cache_key":"endpoint-result-old","protection_id":"endpoint-key"}}"#
    );
    assert!(
        serde_json::from_str::<automata_ci_runner_spool::DurableContentRef>(&old_shape).is_err()
    );
}

#[test]
fn same_class_results_have_identical_file_allocation_not_exact_length() {
    let scratch = Scratch::new("endpoint-padding-class");
    let root = scratch.spool_root();
    let spool = FileSpool::open(root.clone(), protector(0x53)).expect("open spool");
    let short = adopt(
        spool
            .reserve_endpoint_result(128)
            .expect("short reserve")
            .persist(b"x")
            .expect("short persist"),
    );
    let longer = adopt(
        spool
            .reserve_endpoint_result(128)
            .expect("long reserve")
            .persist(&[b'y'; 127])
            .expect("long persist"),
    );
    let short_file = fs::metadata(content_path(&root, &short))
        .expect("short metadata")
        .len();
    let longer_file = fs::metadata(content_path(&root, &longer))
        .expect("long metadata")
        .len();
    assert_eq!(short_file, 64 * 1024);
    assert_eq!(longer_file, short_file);
    assert_eq!(short.accounted_bytes(), longer.accounted_bytes());
    assert_ne!(
        short.endpoint_result_identity(),
        longer.endpoint_result_identity()
    );
}

#[test]
fn ordinary_persist_cannot_bypass_endpoint_result_reservation() {
    let scratch = Scratch::new("endpoint-reservation-required");
    let spool = FileSpool::open(scratch.spool_root(), protector(0x52)).expect("open spool");
    assert!(matches!(
        spool.persist(ContentKind::EndpointResult, b"result"),
        Err(SpoolError::Invariant(
            SpoolInvariantError::EndpointResultReservationRequired
        ))
    ));
}

#[test]
fn reservation_preflights_the_active_protector_size_and_availability() {
    for (label, failure) in [
        ("endpoint-preflight-size", PreflightFailure::WrongSize),
        (
            "endpoint-preflight-unavailable",
            PreflightFailure::Unavailable,
        ),
    ] {
        let scratch = Scratch::new(label);
        let spool = FileSpool::open(
            scratch.spool_root(),
            Arc::new(PreflightProtector {
                inner: TestProtector::new("endpoint-preflight", 0x43),
                failure,
            }),
        )
        .expect("open spool");
        let Err(error) = spool.reserve_endpoint_result(1) else {
            panic!("incoherent protection preflight must reject reservation");
        };
        assert!(matches!(
            error,
            SpoolError::Invariant(SpoolInvariantError::ProtectionOverheadExceeded)
                | SpoolError::Protection(ContentProtectionError::KeyUnavailable)
        ));
        assert_eq!(spool.usage().expect("unchanged usage"), (0, 0));
    }
}

#[test]
fn reservation_blocks_competing_publishers_and_reservations_until_drop() {
    let limits = SpoolLimits::new(1024, 66_559, 2, 65_535).expect("coherent limits");
    let (_scratch, spool) = bounded_spool("endpoint-reservation-global", limits);
    let reservation = spool
        .reserve_endpoint_result(1)
        .expect("reserve full byte budget");

    assert!(matches!(
        spool.persist(ContentKind::JobIr, &[0x42; 1024]),
        Err(SpoolError::CapacityExhausted)
    ));
    assert!(matches!(
        spool.reserve_endpoint_result(1),
        Err(SpoolError::CapacityExhausted)
    ));

    drop(reservation);
    spool
        .persist(ContentKind::JobIr, &[0x42; 1024])
        .expect("drop releases all reserved capacity")
        .abort();
}

#[test]
fn consuming_smaller_class_relinquishes_unused_bytes_atomically() {
    let limits = SpoolLimits::new(65_536, 131_147, 2, 65_611).expect("coherent limits");
    let (_scratch, spool) = bounded_spool("endpoint-reservation-consume", limits);
    let reservation = spool
        .reserve_endpoint_result(65_461)
        .expect("reserve second allocation class");
    let reference = adopt(
        reservation
            .persist(b"small actual result")
            .expect("consume first allocation class"),
    );
    assert_eq!(reference.accounted_bytes(), 65_536);
    assert_eq!(spool.usage().expect("actual usage"), (1, 65_536));

    spool
        .persist(
            ContentKind::JobIr,
            b"fits only after unused reservation is released",
        )
        .expect("ordinary publication uses relinquished bytes")
        .abort();
}

#[test]
fn failed_reserved_persist_releases_capacity() {
    let limits = SpoolLimits::new(1024, 66_559, 1, 65_535).expect("coherent limits");
    let (_scratch, spool) = bounded_spool("endpoint-reservation-failure", limits);
    let reservation = spool.reserve_endpoint_result(1).expect("reserve");
    assert!(matches!(
        reservation.persist(b"too large"),
        Err(SpoolError::Invariant(SpoolInvariantError::ObjectTooLarge))
    ));
    drop(
        spool
            .reserve_endpoint_result(1)
            .expect("failure releases reservation"),
    );
}
