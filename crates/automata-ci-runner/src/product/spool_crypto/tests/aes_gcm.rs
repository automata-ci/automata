use automata_ci_core::Sha256Digest;
use automata_ci_runner_spool::{
    ContentCommitmentDomain, ContentKind, ContentProtectionError, ContentProtector,
    DurableContentRef, OpaqueContentIdentity, ProtectionId, endpoint_result_allocation,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::super::{AES_256_GCM_KEY_BYTES, Aes256GcmContentProtector};

fn make_protector(id: &str, marker: u8) -> Aes256GcmContentProtector {
    Aes256GcmContentProtector::new(id, Zeroizing::new(vec![marker; AES_256_GCM_KEY_BYTES]))
        .expect("valid protector")
}

fn make_reference(id: &str, kind: ContentKind, plaintext: &[u8]) -> DurableContentRef {
    DurableContentRef::after_public_commit(
        kind,
        u64::try_from(plaintext.len()).expect("fixture size"),
        Sha256Digest::from_bytes(Sha256::digest(plaintext).into()),
        ProtectionId::new(id).expect("valid ID"),
    )
    .expect("valid reference")
}

fn make_endpoint_reference(
    protector: &Aes256GcmContentProtector,
    plaintext: &[u8],
) -> DurableContentRef {
    const MATERIAL_DOMAIN: &[u8] = b"automata.runner.endpoint-result.material.v1\0";
    let plaintext_bytes = u64::try_from(plaintext.len()).expect("fixture size");
    let mut material = Sha256::new();
    material.update(MATERIAL_DOMAIN);
    material.update(plaintext_bytes.to_be_bytes());
    material.update(Sha256::digest(plaintext));
    let material_digest: [u8; 32] = material.finalize().into();
    let opaque = protector
        .keyed_commitment(
            protector.protection_id(),
            ContentCommitmentDomain::EndpointResultIdentity,
            &material_digest,
        )
        .expect("opaque identity");
    DurableContentRef::after_endpoint_result_commit(
        endpoint_result_allocation(plaintext_bytes).expect("allocation"),
        OpaqueContentIdentity::from_bytes(opaque),
        protector.protection_id().clone(),
    )
    .expect("endpoint reference")
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
    let result_identity = first
        .keyed_commitment(
            &id_a,
            ContentCommitmentDomain::EndpointResultIdentity,
            &digest,
        )
        .expect("result identity");
    assert_ne!(result_identity, commitment);
    assert_ne!(result_identity, digest);
    assert_eq!(
        first
            .keyed_commitment(&id_b, ContentCommitmentDomain::EndpointRequest, &digest)
            .expect_err("wrong key id"),
        ContentProtectionError::KeyUnavailable
    );
    assert!(!format!("{first:?}").contains("090909"));
}

#[test]
fn endpoint_results_round_trip_with_authenticated_padding_classes() {
    let protector = make_protector("key-a", 0x5a);
    let short = b"x";
    let longer = [b'y'; 127];
    let short_ref = make_endpoint_reference(&protector, short);
    let longer_ref = make_endpoint_reference(&protector, &longer);
    let short_protected = protector.protect(&short_ref, short).expect("protect short");
    let longer_protected = protector
        .protect(&longer_ref, &longer)
        .expect("protect longer");

    assert_eq!(
        protector
            .endpoint_result_protected_bytes(short.len().try_into().expect("short length"))
            .expect("preflight short result"),
        u64::try_from(short_protected.len()).expect("protected length")
    );
    assert_eq!(
        protector
            .endpoint_result_protected_bytes(longer.len().try_into().expect("longer length"))
            .expect("preflight longer result"),
        u64::try_from(longer_protected.len()).expect("protected length")
    );
    assert_eq!(short_protected.len(), 64 * 1024);
    assert_eq!(longer_protected.len(), short_protected.len());
    assert_eq!(&short_protected[..4], b"ASP2");
    assert_eq!(
        protector
            .unprotect(&short_ref, &short_protected)
            .expect("open short"),
        short
    );
    assert_eq!(
        protector
            .unprotect(&longer_ref, &longer_protected)
            .expect("open longer"),
        longer
    );

    let mut obsolete_header = short_protected.clone();
    obsolete_header[..4].copy_from_slice(b"ASP1");
    assert_eq!(
        protector
            .unprotect(&short_ref, &obsolete_header)
            .expect_err("obsolete protection schema must fail closed"),
        ContentProtectionError::AuthenticationFailed
    );

    let mut tampered = short_protected;
    let last = tampered.len() - 1;
    tampered[last] ^= 0x80;
    assert_eq!(
        protector
            .unprotect(&short_ref, &tampered)
            .expect_err("authenticated padding rejects tampering"),
        ContentProtectionError::AuthenticationFailed
    );
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
    assert_eq!(&first[..4], b"ASP2");
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
    let result = make_endpoint_reference(&protector, plaintext);

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
