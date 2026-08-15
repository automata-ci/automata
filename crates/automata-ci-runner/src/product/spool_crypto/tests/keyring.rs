use automata_ci_core::Sha256Digest;
use automata_ci_runner_spool::{
    ContentKind, ContentProtectionError, ContentProtector, DurableContentRef, ProtectionId,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::super::{
    AES_256_GCM_KEY_BYTES, Aes256GcmContentKeyring, Aes256GcmContentProtector,
    MAX_DECRYPT_ONLY_CONTENT_KEYS, error::ContentProtectorConfigurationError,
};

fn protector(id: &str, marker: u8) -> Aes256GcmContentProtector {
    Aes256GcmContentProtector::new(id, Zeroizing::new(vec![marker; AES_256_GCM_KEY_BYTES]))
        .expect("valid protector")
}

fn reference(id: &str, plaintext: &[u8]) -> DurableContentRef {
    DurableContentRef::after_commit(
        ContentKind::RuntimeAuthority,
        u64::try_from(plaintext.len()).expect("fixture size"),
        Sha256Digest::from_bytes(Sha256::digest(plaintext).into()),
        ProtectionId::new(id).expect("valid protection ID"),
    )
    .expect("valid reference")
}

#[test]
fn rotation_reads_exact_old_id_but_all_new_writes_use_active_id() {
    let old_plaintext = b"authority issued before spool-key rotation";
    let old_reference = reference("spool-v1", old_plaintext);
    let old_ciphertext = protector("spool-v1", 0x11)
        .protect(&old_reference, old_plaintext)
        .expect("protect old object");

    let keyring = Aes256GcmContentKeyring::new(
        protector("spool-v2", 0x22),
        vec![protector("spool-v1", 0x11)],
    )
    .expect("rotation keyring");
    assert_eq!(keyring.protection_id().as_str(), "spool-v2");
    assert!(keyring.supports_protection_id(old_reference.protection_id()));
    assert_eq!(
        keyring
            .unprotect(&old_reference, &old_ciphertext)
            .expect("old key remains readable"),
        old_plaintext
    );
    assert_eq!(
        keyring
            .protect(&old_reference, old_plaintext)
            .expect_err("decrypt-only key must never protect a new write"),
        ContentProtectionError::KeyUnavailable
    );

    let new_plaintext = b"authority issued after spool-key rotation";
    let new_reference = reference(keyring.protection_id().as_str(), new_plaintext);
    let new_ciphertext = keyring
        .protect(&new_reference, new_plaintext)
        .expect("active key protects new object");
    assert_eq!(
        keyring
            .unprotect(&new_reference, &new_ciphertext)
            .expect("active object opens"),
        new_plaintext
    );
    assert_eq!(
        protector("spool-v1", 0x11)
            .unprotect(&new_reference, &new_ciphertext)
            .expect_err("old-only process cannot open new object"),
        ContentProtectionError::KeyUnavailable
    );
}

#[test]
fn unknown_ids_wrong_material_and_tampering_fail_closed() {
    let plaintext = b"sensitive recovery object";
    let old_reference = reference("spool-v1", plaintext);
    let ciphertext = protector("spool-v1", 0x31)
        .protect(&old_reference, plaintext)
        .expect("protect old object");
    let keyring = Aes256GcmContentKeyring::new(
        protector("spool-v2", 0x32),
        vec![protector("spool-v1", 0x31)],
    )
    .expect("rotation keyring");

    let unknown = reference("spool-retired", plaintext);
    assert!(!keyring.supports_protection_id(unknown.protection_id()));
    assert_eq!(
        keyring
            .unprotect(&unknown, &ciphertext)
            .expect_err("unknown key ID rejected before trial decryption"),
        ContentProtectionError::KeyUnavailable
    );

    let wrong_keyring = Aes256GcmContentKeyring::new(
        protector("spool-v2", 0x32),
        vec![protector("spool-v1", 0x7f)],
    )
    .expect("wrong old material is still structurally valid");
    assert_eq!(
        wrong_keyring
            .unprotect(&old_reference, &ciphertext)
            .expect_err("wrong exact-ID key fails authentication"),
        ContentProtectionError::AuthenticationFailed
    );

    let mut tampered = ciphertext;
    let last = tampered.len() - 1;
    tampered[last] ^= 0x80;
    assert_eq!(
        keyring
            .unprotect(&old_reference, &tampered)
            .expect_err("tampered old ciphertext rejected"),
        ContentProtectionError::AuthenticationFailed
    );
}

#[test]
fn duplicate_active_as_old_and_oversized_keyrings_are_rejected() {
    let active_as_old = Aes256GcmContentKeyring::new(
        protector("spool-v2", 0x41),
        vec![protector("spool-v2", 0x42)],
    );
    assert_eq!(
        active_as_old.expect_err("active ID cannot be decrypt-only"),
        ContentProtectorConfigurationError::DuplicateProtectionId
    );

    let duplicate_old = Aes256GcmContentKeyring::new(
        protector("spool-v3", 0x43),
        vec![protector("spool-v1", 0x44), protector("spool-v1", 0x45)],
    );
    assert_eq!(
        duplicate_old.expect_err("old IDs must be unique"),
        ContentProtectorConfigurationError::DuplicateProtectionId
    );

    let maximum = (0..MAX_DECRYPT_ONLY_CONTENT_KEYS)
        .map(|index| {
            protector(
                &format!("old-{index}"),
                u8::try_from(index).expect("small keyring index"),
            )
        })
        .collect();
    let keyring = Aes256GcmContentKeyring::new(protector("active", 0x51), maximum)
        .expect("the documented old-key bound is accepted");
    assert_eq!(
        keyring.decrypt_only_ids().len(),
        MAX_DECRYPT_ONLY_CONTENT_KEYS
    );

    let oversized = (0..=MAX_DECRYPT_ONLY_CONTENT_KEYS)
        .map(|index| {
            protector(
                &format!("old-{index}"),
                u8::try_from(index).expect("small keyring index"),
            )
        })
        .collect();
    assert_eq!(
        Aes256GcmContentKeyring::new(protector("active", 0x52), oversized)
            .expect_err("keyring must be bounded"),
        ContentProtectorConfigurationError::TooManyDecryptOnlyKeys
    );
}

#[test]
fn debug_exposes_ids_but_never_key_material() {
    let keyring = Aes256GcmContentKeyring::new(
        protector("active-id", 0xaa),
        vec![protector("old-id", 0xbb)],
    )
    .expect("keyring");
    let debug = format!("{keyring:?}");
    assert!(debug.contains("active-id"));
    assert!(debug.contains("old-id"));
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("aaaaaaaa"));
    assert!(!debug.contains("bbbbbbbb"));
}
