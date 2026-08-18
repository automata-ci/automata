use super::*;

#[test]
fn epoch_domains_are_versioned_and_distinct() {
    assert_ne!(EPOCH_FINGERPRINT_DOMAIN_V1, MATERIAL_KDF_DOMAIN);
    assert_ne!(EPOCH_FINGERPRINT_DOMAIN_V2, MATERIAL_KDF_DOMAIN);
    assert_ne!(EPOCH_FINGERPRINT_DOMAIN_V1, EPOCH_FINGERPRINT_DOMAIN_V2);
    assert!(EPOCH_FINGERPRINT_DOMAIN_V1.ends_with(&[0]));
    assert!(EPOCH_FINGERPRINT_DOMAIN_V2.ends_with(&[0]));
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

fn standalone_epoch() -> (ImmutableEpoch, [u8; 32]) {
    let root = [7; 32];
    let installation = crate::Installation::verified(
        crate::InstallationName::default(),
        crate::InstallationId::new(),
    );
    let epoch = authority_test_epoch(&installation, &root, Sha256Digest::from_bytes([5; 32]));
    (epoch, root)
}

#[test]
fn standalone_epoch_decode_recomputes_authority_material_and_identity() {
    let (epoch, root) = standalone_epoch();
    assert_eq!(
        ImmutableEpoch::from_authority_bound_bytes(
            &epoch.canonical_bytes(),
            Sha256Digest::from_bytes([5; 32]),
        )
        .unwrap(),
        epoch
    );
    let decoded = ImmutableEpoch::from_sealed_bytes(
        &epoch.canonical_bytes(),
        Sha256Digest::from_bytes([5; 32]),
        &root,
    )
    .unwrap();
    assert_eq!(decoded, epoch);
    assert_eq!(decoded.workers(), 1);
    assert_eq!(decoded.image_expectations().count(), 7);

    assert_eq!(
        ImmutableEpoch::from_authority_bound_bytes(
            &epoch.canonical_bytes(),
            Sha256Digest::from_bytes([6; 32]),
        )
        .unwrap_err()
        .code(),
        LocalInitErrorCode::ResetRequired
    );

    assert_eq!(
        ImmutableEpoch::from_sealed_bytes(
            &epoch.canonical_bytes(),
            Sha256Digest::from_bytes([6; 32]),
            &root,
        )
        .unwrap_err()
        .code(),
        LocalInitErrorCode::ResetRequired
    );
    assert_eq!(
        ImmutableEpoch::from_sealed_bytes(
            &epoch.canonical_bytes(),
            Sha256Digest::from_bytes([5; 32]),
            &[8; 32],
        )
        .unwrap_err()
        .code(),
        LocalInitErrorCode::ResetRequired
    );

    let mut copied = epoch.clone();
    copied.installation.selector_key = "0".repeat(64);
    copied.epoch_fingerprint = copied.recompute_fingerprint();
    assert_eq!(
        ImmutableEpoch::from_sealed_bytes(
            &copied.canonical_bytes(),
            Sha256Digest::from_bytes([5; 32]),
            &root,
        )
        .unwrap_err()
        .code(),
        LocalInitErrorCode::ResetRequired
    );
}

#[test]
fn exact_parent_v1_golden_remains_status_and_reset_decodable_but_not_lifecycle_current() {
    let installation = crate::Installation::verified(
        crate::InstallationName::default(),
        "11111111-1111-4111-8111-111111111111"
            .parse()
            .expect("fixed UUIDv4"),
    );
    let epoch = legacy_test_epoch(&installation, &[7; 32], Sha256Digest::from_bytes([5; 32]));
    let golden = include_bytes!("immutable-epoch-v1.golden.json");
    let actual = epoch.canonical_bytes();
    assert_eq!(
        actual.as_slice(),
        golden,
        "lengths actual={} golden={}; first difference={:?}",
        actual.len(),
        golden.len(),
        actual
            .iter()
            .zip(golden)
            .position(|(actual, golden)| actual != golden)
    );
    assert_eq!(
        epoch.fingerprint().to_string(),
        "86a6bc41fb7135a6d8dd7deee397f5149b73b75d56d23903162c29d1ce7c7b05"
    );
    let decoded =
        ImmutableEpoch::from_authority_bound_bytes(golden, Sha256Digest::from_bytes([5; 32]))
            .expect("status/reset decoder preserves exact v1 custody");
    assert_eq!(decoded, epoch);
    assert_eq!(
        decoded
            .require_current_lifecycle_contract()
            .unwrap_err()
            .code(),
        LocalInitErrorCode::ResetRequired
    );
}

#[test]
fn v2_binds_current_source_and_desired_plan_across_replay() {
    let (epoch, _) = standalone_epoch();
    epoch
        .require_current_lifecycle_contract()
        .expect("exact v2 contract is current");

    let mut wrong_source = epoch.clone();
    wrong_source.catalog.source_contract_sha256 = Some(Sha256Digest::from_bytes([0x91; 32]));
    wrong_source.epoch_fingerprint = wrong_source.recompute_fingerprint();
    assert_eq!(
        wrong_source
            .require_current_lifecycle_contract()
            .unwrap_err()
            .code(),
        LocalInitErrorCode::ResetRequired
    );

    let mut changed_plan = epoch.clone();
    changed_plan.desired_plan_sha256 = Some(Sha256Digest::from_bytes([0x92; 32]));
    assert_eq!(
        ImmutableEpoch::from_authority_bound_bytes(
            &changed_plan.canonical_bytes(),
            Sha256Digest::from_bytes([5; 32]),
        )
        .unwrap_err()
        .code(),
        LocalInitErrorCode::ResetRequired
    );
    changed_plan.epoch_fingerprint = changed_plan.recompute_fingerprint();
    assert_eq!(
        ImmutableEpoch::from_canonical_bytes(&changed_plan.canonical_bytes(), &epoch)
            .unwrap_err()
            .code(),
        LocalInitErrorCode::ResetRequired
    );

    let installation = epoch.installation().unwrap();
    let legacy = legacy_test_epoch(&installation, &[7; 32], Sha256Digest::from_bytes([5; 32]));
    assert_eq!(
        ImmutableEpoch::from_canonical_bytes(&legacy.canonical_bytes(), &epoch)
            .unwrap_err()
            .code(),
        LocalInitErrorCode::ResetRequired
    );
}
