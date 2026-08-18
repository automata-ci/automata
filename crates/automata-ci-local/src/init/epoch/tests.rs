use super::*;

#[test]
fn epoch_domains_are_versioned_and_distinct() {
    assert_ne!(EPOCH_FINGERPRINT_DOMAIN, MATERIAL_KDF_DOMAIN);
    assert!(EPOCH_FINGERPRINT_DOMAIN.ends_with(&[0]));
    assert!(MATERIAL_KDF_DOMAIN.ends_with(&[0]));
}

#[test]
fn initial_desired_and_state_authority_are_exact_replay_predicates() {
    let installation = crate::Installation::verified(
        crate::InstallationName::default(),
        crate::InstallationId::new(),
    );
    let epoch = certificate_test_epoch(&installation, &[7; 32]);
    let mut current_desired = epoch.clone();
    current_desired.initial_desired_sha256 = Sha256Digest::from_bytes([8; 32]);
    current_desired.epoch_fingerprint = current_desired.recompute_fingerprint();

    assert_eq!(
        ImmutableEpoch::from_canonical_bytes(&epoch.canonical_bytes(), &current_desired)
            .unwrap_err()
            .code(),
        LocalInitErrorCode::ResetRequired
    );

    let mut relocated_state = epoch.clone();
    relocated_state.state_authority_sha256 = Sha256Digest::from_bytes([9; 32]);
    relocated_state.epoch_fingerprint = relocated_state.recompute_fingerprint();
    assert_eq!(
        ImmutableEpoch::from_canonical_bytes(&epoch.canonical_bytes(), &relocated_state)
            .unwrap_err()
            .code(),
        LocalInitErrorCode::ResetRequired
    );

    let mut tampered = epoch.clone();
    tampered.initial_desired_sha256 = Sha256Digest::from_bytes([10; 32]);
    assert_eq!(
        ImmutableEpoch::from_canonical_bytes(&tampered.canonical_bytes(), &epoch)
            .unwrap_err()
            .code(),
        LocalInitErrorCode::ResetRequired
    );
}
