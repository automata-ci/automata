use automata_ci_key_management::{
    KeyEncryptionContext, KeyEncryptionContextError, KeyId, KeyPurpose,
    MAX_ENVELOPE_PLAINTEXT_BYTES, SecretBytes, SecretBytesError, WrappedDataKey,
};

#[test]
fn key_ids_and_purposes_are_canonical_and_serde_validated() {
    let key_id = KeyId::new("local-2026_08.1").expect("key ID");
    assert_eq!(key_id.as_str(), "local-2026_08.1");
    assert_eq!(
        serde_json::to_string(&key_id).expect("serialize key ID"),
        "\"local-2026_08.1\""
    );
    assert_eq!(
        serde_json::from_str::<KeyId>("\"local-2026_08.1\"").expect("deserialize key ID"),
        key_id
    );
    for invalid in ["", "UPPER", "key/one", "key-", ".key"] {
        assert!(KeyId::new(invalid).is_err(), "accepted key ID {invalid:?}");
    }

    let purpose = KeyPurpose::new("auth/provider-tokens:v1").expect("purpose");
    assert_eq!(purpose.as_str(), "auth/provider-tokens:v1");
    assert_eq!(
        serde_json::from_str::<KeyPurpose>("\"auth/provider-tokens:v1\"")
            .expect("deserialize purpose"),
        purpose
    );
    for invalid in ["", "Auth/tokens:v1", "/auth", "auth/", "auth tokens"] {
        assert!(
            KeyPurpose::new(invalid).is_err(),
            "accepted purpose {invalid:?}"
        );
    }
    assert!(serde_json::from_str::<KeyId>("\"KEY\"").is_err());
    assert!(serde_json::from_str::<KeyPurpose>("\"bad purpose\"").is_err());
}

#[test]
fn authenticated_context_has_an_unambiguous_golden_encoding() {
    let context = KeyEncryptionContext::new("t", KeyPurpose::new("p:v1").expect("purpose"), "row")
        .expect("context");
    assert_eq!(
        context.canonical_authenticated_bytes(),
        b"AKC1\x00\x00\x00\x01t\x00\x00\x00\x04p:v1\x00\x00\x00\x03row"
    );

    let split_one = KeyEncryptionContext::new("a", KeyPurpose::new("p:v1").expect("purpose"), "bc")
        .expect("context");
    let split_two = KeyEncryptionContext::new("ab", KeyPurpose::new("p:v1").expect("purpose"), "c")
        .expect("context");
    assert_ne!(
        split_one.canonical_authenticated_bytes(),
        split_two.canonical_authenticated_bytes()
    );
}

#[test]
fn authenticated_context_rejects_unsafe_bindings() {
    let purpose = || KeyPurpose::new("actions/secrets:v1").expect("purpose");
    assert_eq!(
        KeyEncryptionContext::new("", purpose(), "row"),
        Err(KeyEncryptionContextError::InvalidTenantId)
    );
    assert_eq!(
        KeyEncryptionContext::new("tenant", purpose(), "row\nother"),
        Err(KeyEncryptionContextError::InvalidRecordId)
    );
    assert_eq!(
        KeyEncryptionContext::new("t".repeat(513), purpose(), "row"),
        Err(KeyEncryptionContextError::InvalidTenantId)
    );
}

#[test]
fn secret_and_wrapped_key_diagnostics_never_expose_bytes() {
    let secret = SecretBytes::new(b"plaintext-key-material".to_vec()).expect("secret");
    let rendered = format!("{secret:?}");
    assert_eq!(rendered, "SecretBytes([REDACTED])");
    assert!(!rendered.contains("plaintext-key-material"));

    let wrapped = WrappedDataKey::new(
        KeyId::new("key-a").expect("key ID"),
        b"opaque-wrapped-key-ciphertext".to_vec(),
    )
    .expect("wrapped key");
    let rendered = format!("{wrapped:?}");
    assert!(rendered.contains("[OPAQUE]"));
    assert!(!rendered.contains("opaque-wrapped-key-ciphertext"));

    assert!(SecretBytes::new(Vec::new()).is_err());
    assert_eq!(
        SecretBytes::new(vec![0x5a; MAX_ENVELOPE_PLAINTEXT_BYTES + 1]).unwrap_err(),
        SecretBytesError::TooLong {
            maximum: MAX_ENVELOPE_PLAINTEXT_BYTES,
        }
    );
    let error = SecretBytesError::TooLong {
        maximum: MAX_ENVELOPE_PLAINTEXT_BYTES,
    };
    assert!(!error.to_string().contains("5a5a5a"));
}
