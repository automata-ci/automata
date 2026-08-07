use automata_core::Sha256Digest;
use automata_runner_crypto::{AES_256_GCM_KEY_BYTES, Aes256GcmContentProtector};
use automata_runner_spool::{
    ContentKind, ContentProtectionError, ContentProtector, DurableContentRef, ProtectionId,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

fn make_protector(id: &str, marker: u8) -> Aes256GcmContentProtector {
    Aes256GcmContentProtector::new(id, Zeroizing::new(vec![marker; AES_256_GCM_KEY_BYTES]))
        .expect("valid protector")
}

fn make_reference(id: &str, kind: ContentKind, plaintext: &[u8]) -> DurableContentRef {
    DurableContentRef::after_commit(
        kind,
        u64::try_from(plaintext.len()).expect("fixture size"),
        Sha256Digest::from_bytes(Sha256::digest(plaintext).into()),
        ProtectionId::new(id).expect("valid ID"),
    )
    .expect("valid reference")
}

#[test]
fn round_trips_with_fresh_nonces_and_no_plaintext_debug() {
    let plaintext = b"runner recovery payload with sensitive material";
    let reference = make_reference("key-2026-08", ContentKind::JobIr, plaintext);
    let protector = make_protector("key-2026-08", 0x42);

    let first = protector.protect(&reference, plaintext).expect("protect");
    let second = protector
        .protect(&reference, plaintext)
        .expect("protect again");
    assert_ne!(first, second, "each object protection uses a fresh nonce");
    assert_eq!(first.len(), plaintext.len() + 32);
    assert_eq!(&first[..4], b"ASP1");
    assert!(
        !first
            .windows(plaintext.len())
            .any(|window| window == plaintext)
    );
    assert_eq!(
        protector
            .unprotect(&reference, &first)
            .expect("authenticate"),
        plaintext
    );
    let debug = format!("{protector:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("424242"));
}

#[test]
fn authenticates_every_byte_and_complete_content_identity() {
    let plaintext = b"payload";
    let reference = make_reference("key-a", ContentKind::TerminalResult, plaintext);
    let protector = make_protector("key-a", 1);
    let protected = protector.protect(&reference, plaintext).expect("protect");

    for index in [0, 5, protected.len() - 1] {
        let mut altered = protected.clone();
        altered[index] ^= 0x80;
        assert_eq!(
            protector
                .unprotect(&reference, &altered)
                .expect_err("tampering rejected"),
            ContentProtectionError::AuthenticationFailed
        );
    }

    let other_kind = make_reference("key-a", ContentKind::LogSpool, plaintext);
    assert_eq!(
        protector
            .unprotect(&other_kind, &protected)
            .expect_err("cross-kind substitution rejected"),
        ContentProtectionError::AuthenticationFailed
    );
    let other_key = make_protector("key-a", 2);
    assert_eq!(
        other_key
            .unprotect(&reference, &protected)
            .expect_err("wrong key rejected"),
        ContentProtectionError::AuthenticationFailed
    );
}

#[test]
fn runtime_authority_has_a_distinct_authenticated_domain() {
    let plaintext = b"short-lived per-attempt bearer";
    let protector = make_protector("key-a", 0x31);
    let authority = make_reference("key-a", ContentKind::RuntimeAuthority, plaintext);
    let job_ir = make_reference("key-a", ContentKind::JobIr, plaintext);

    let protected = protector
        .protect(&authority, plaintext)
        .expect("protect runtime authority");
    assert_eq!(
        protector
            .unprotect(&job_ir, &protected)
            .expect_err("cross-kind substitution rejected"),
        ContentProtectionError::AuthenticationFailed
    );
    assert_eq!(
        protector
            .unprotect(&authority, &protected)
            .expect("authority kind authenticates"),
        plaintext
    );
}

#[test]
fn rejects_wrong_identity_and_plaintext_before_encryption() {
    let plaintext = b"payload";
    let reference = make_reference("key-a", ContentKind::JobIr, plaintext);
    let protector = make_protector("key-b", 1);
    assert_eq!(
        protector
            .protect(&reference, plaintext)
            .expect_err("wrong key ID rejected"),
        ContentProtectionError::KeyUnavailable
    );

    let matching = make_protector("key-a", 1);
    assert_eq!(
        matching
            .protect(&reference, b"different")
            .expect_err("content identity mismatch rejected"),
        ContentProtectionError::Failed
    );
}

#[test]
fn public_protector_port_remains_object_safe() {
    static_assertions::assert_obj_safe!(ContentProtector);
    let protector: Box<dyn ContentProtector> = Box::new(make_protector("key-a", 1));
    assert_eq!(protector.protection_id().as_str(), "key-a");
}
