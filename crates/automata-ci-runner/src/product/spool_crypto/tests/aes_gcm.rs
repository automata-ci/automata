use automata_ci_core::Sha256Digest;
use automata_ci_runner_spool::{
    ContentCommitmentDomain, ContentKind, ContentProtectionError, ContentProtector,
    DurableContentRef, ProtectionId,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::super::{AES_256_GCM_KEY_BYTES, Aes256GcmContentProtector};

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
fn endpoint_commitment_is_a_domain_separated_keyed_prf_and_debug_is_redacted() {
    let digest = [0x09; 32];
    let first = make_protector("key-a", 0x42);
    let same = make_protector("key-a", 0x42);
    let other = make_protector("key-b", 0x43);
    let id_a = ProtectionId::new("key-a").expect("key id");
    let id_b = ProtectionId::new("key-b").expect("key id");
    let commitment = first
        .keyed_commitment(&id_a, ContentCommitmentDomain::EndpointRequest, &digest)
        .expect("commitment");
    assert_eq!(
        commitment,
        same.keyed_commitment(&id_a, ContentCommitmentDomain::EndpointRequest, &digest)
            .expect("same key commitment")
    );
    assert_ne!(
        commitment,
        other
            .keyed_commitment(&id_b, ContentCommitmentDomain::EndpointRequest, &digest)
            .expect("other key commitment")
    );
    assert_ne!(commitment, digest);
    assert_eq!(
        first
            .keyed_commitment(&id_b, ContentCommitmentDomain::EndpointRequest, &digest)
            .expect_err("wrong key id"),
        ContentProtectionError::KeyUnavailable
    );
    assert!(!format!("{first:?}").contains("090909"));
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
fn decrypts_fixed_legacy_asp1_ciphertext() {
    // Models the former standalone adapter's ASP1 output for nonce
    // 000102030405060708090a0b. The vector was independently generated with
    // Python cryptography and cross-checked with Node/OpenSSL AES-GCM.
    const LEGACY_PROTECTED: [u8; 79] = [
        0x41, 0x53, 0x50, 0x31, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x77, 0xab, 0xff, 0xb3, 0xd4, 0x5e, 0xd2, 0x79, 0xf8, 0x65, 0x2b, 0x65, 0xb4, 0xaf,
        0x22, 0x1b, 0x42, 0xfc, 0xb7, 0x06, 0xcf, 0x28, 0x86, 0xc9, 0x64, 0xf0, 0x54, 0x4f, 0xba,
        0x67, 0xd8, 0x91, 0x27, 0xd2, 0xfd, 0xcb, 0x07, 0x55, 0x02, 0x94, 0x8b, 0x01, 0x63, 0x61,
        0x66, 0xe0, 0xb9, 0xb0, 0x6e, 0x74, 0x03, 0x51, 0x5f, 0x1f, 0xa4, 0x1a, 0x22, 0x11, 0xc7,
        0x47, 0x95, 0x18, 0xb6,
    ];

    let plaintext = b"runner recovery payload with sensitive material";
    let reference = make_reference("key-2026-08", ContentKind::JobIr, plaintext);
    let protector = make_protector("key-2026-08", 0x42);

    assert_eq!(
        protector
            .unprotect(&reference, &LEGACY_PROTECTED)
            .expect("legacy ciphertext authenticates"),
        plaintext
    );
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
fn rejects_encoded_length_mismatch_before_ciphertext_processing() {
    let plaintext = b"payload";
    let reference = make_reference("key-a", ContentKind::JobIr, plaintext);
    let protector = make_protector("key-a", 1);
    let protected = protector.protect(&reference, plaintext).expect("protect");

    for mismatched in [protected[..protected.len() - 1].to_vec(), {
        let mut oversized = protected.clone();
        oversized.extend_from_slice(&vec![0_u8; 1024 * 1024]);
        oversized
    }] {
        assert_eq!(
            protector
                .unprotect(&reference, &mismatched)
                .expect_err("encoded length mismatch rejected"),
            ContentProtectionError::AuthenticationFailed
        );
    }
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
fn endpoint_request_and_result_have_distinct_authenticated_domains() {
    let plaintext = b"endpoint replay bytes";
    let protector = make_protector("key-a", 0x32);
    let request = make_reference("key-a", ContentKind::EndpointRequest, plaintext);
    let result = make_reference("key-a", ContentKind::EndpointResult, plaintext);

    let protected = protector
        .protect(&request, plaintext)
        .expect("protect endpoint request");
    assert_eq!(
        protector
            .unprotect(&result, &protected)
            .expect_err("request/result substitution rejected"),
        ContentProtectionError::AuthenticationFailed
    );
    assert_eq!(
        protector
            .unprotect(&request, &protected)
            .expect("endpoint request authenticates"),
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
