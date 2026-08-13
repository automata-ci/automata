use automata_ci_key_management::KeyId;
use automata_ci_store::{
    MAX_SECRET_CUSTODY_CONFIGURED_KEYS, SecretCustodyKeySet, SecretCustodyRepositoryError,
    SecretCustodyValueError, VerifySecretCustody,
};

fn key_id(value: &str) -> KeyId {
    KeyId::new(value).expect("canonical key ID")
}

#[test]
fn configured_key_sets_are_bounded_unique_and_active_bound() {
    assert_eq!(MAX_SECRET_CUSTODY_CONFIGURED_KEYS, 32);
    let first =
        SecretCustodyKeySet::new(key_id("key-a"), vec![key_id("key-b")]).expect("valid key set");
    assert_eq!(
        first
            .key_ids()
            .iter()
            .map(KeyId::as_str)
            .collect::<Vec<_>>(),
        ["key-a", "key-b"]
    );
    let different_active = SecretCustodyKeySet::new(key_id("key-b"), vec![key_id("key-a")])
        .expect("valid rotated key set");
    assert_ne!(first.digest(), different_active.digest());

    assert!(matches!(
        SecretCustodyKeySet::new(key_id("key-a"), vec![key_id("key-a")]),
        Err(SecretCustodyValueError::DuplicateConfiguredKey)
    ));
    let at_limit = (0..MAX_SECRET_CUSTODY_CONFIGURED_KEYS - 1)
        .map(|index| key_id(&format!("key-{index}")))
        .collect();
    assert_eq!(
        SecretCustodyKeySet::new(key_id("active-key"), at_limit)
            .expect("the exact configured-key bound is accepted")
            .key_ids()
            .len(),
        MAX_SECRET_CUSTODY_CONFIGURED_KEYS
    );
    let oversized = (0..MAX_SECRET_CUSTODY_CONFIGURED_KEYS)
        .map(|index| key_id(&format!("key-{index}")))
        .collect();
    assert!(matches!(
        SecretCustodyKeySet::new(key_id("active-key"), oversized),
        Err(SecretCustodyValueError::TooManyConfiguredKeys)
    ));
}

#[test]
fn request_and_errors_are_safe_for_public_diagnostics() {
    let key = "sensitive-infrastructure-key-id";
    let keys = SecretCustodyKeySet::new(key_id(key), Vec::new()).expect("valid key set");
    let request = VerifySecretCustody::configured(keys.clone());
    for debug in [format!("{keys:?}"), format!("{request:?}")] {
        assert!(!debug.contains(key));
        assert!(!debug.contains("plaintext"));
        assert!(!debug.contains("ciphertext"));
    }

    for error in [
        SecretCustodyRepositoryError::ConfigurationRequired,
        SecretCustodyRepositoryError::ConfigurationUnavailable,
        SecretCustodyRepositoryError::RequiredKeyUnavailable,
        SecretCustodyRepositoryError::CanaryUnavailable,
        SecretCustodyRepositoryError::VerificationFailed,
        SecretCustodyRepositoryError::ActiveKeyMismatch,
        SecretCustodyRepositoryError::Unavailable,
        SecretCustodyRepositoryError::CorruptData,
    ] {
        let diagnostic = format!("{error:?}: {error}");
        assert!(!diagnostic.contains(key));
        assert!(!diagnostic.contains("plaintext"));
        assert!(!diagnostic.contains("ciphertext"));
    }
}
