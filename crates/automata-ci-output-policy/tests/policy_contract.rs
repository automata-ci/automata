use automata_ci_output_policy::{
    OutputKind, OutputVisibility, RawLogDisposition, RepositoryPublicationPolicy,
    SecretExposureClass,
};

#[test]
fn visibility_is_a_bounded_lattice() {
    let values = [
        OutputVisibility::Private,
        OutputVisibility::Authenticated,
        OutputVisibility::Public,
    ];

    for left in values {
        assert_eq!(left.meet(left), left);
        assert_eq!(left.join(left), left);
        for right in values {
            assert_eq!(left.meet(right), right.meet(left));
            assert_eq!(left.join(right), right.join(left));
            assert_eq!(left.meet(left.join(right)), left);
            assert_eq!(left.join(left.meet(right)), left);
            for third in values {
                assert_eq!(left.meet(right).meet(third), left.meet(right.meet(third)));
                assert_eq!(left.join(right).join(third), left.join(right.join(third)));
            }
        }
    }
}

#[test]
fn default_constructor_is_private_but_snapshots_require_every_audience() {
    let private = RepositoryPublicationPolicy::new(
        OutputVisibility::Private,
        OutputVisibility::Private,
        OutputVisibility::Private,
    );
    assert_eq!(RepositoryPublicationPolicy::default(), private);
    assert!(serde_json::from_str::<RepositoryPublicationPolicy>("{}").is_err());
    assert!(
        serde_json::from_str::<RepositoryPublicationPolicy>(r#"{"dashboard":"public"}"#).is_err()
    );
    assert!(
        serde_json::from_str::<RepositoryPublicationPolicy>(
            r#"{"dashboard":"public","logs":"private"}"#,
        )
        .is_err()
    );
}

#[test]
fn publication_settings_are_independent_but_secret_safety_is_a_hard_ceiling() {
    let policy = RepositoryPublicationPolicy::new(
        OutputVisibility::Public,
        OutputVisibility::Public,
        OutputVisibility::Authenticated,
    );

    assert_eq!(
        policy.effective_visibility(OutputKind::Dashboard, SecretExposureClass::ReadableSecret),
        OutputVisibility::Public
    );
    assert_eq!(
        policy.effective_visibility(OutputKind::Logs, SecretExposureClass::Secretless),
        OutputVisibility::Public
    );
    assert_eq!(
        policy.effective_visibility(OutputKind::Logs, SecretExposureClass::CapabilityOnly),
        OutputVisibility::Public
    );
    assert_eq!(
        policy.effective_visibility(OutputKind::Logs, SecretExposureClass::ReadableSecret),
        OutputVisibility::Private
    );
    assert_eq!(
        policy.effective_visibility(OutputKind::Artifacts, SecretExposureClass::Secretless),
        OutputVisibility::Authenticated
    );
    assert_eq!(
        SecretExposureClass::ReadableSecret.raw_log_disposition(),
        RawLogDisposition::Persist
    );
    assert_eq!(
        SecretExposureClass::CapabilityOnly.raw_log_disposition(),
        RawLogDisposition::Persist
    );
}

#[test]
fn durable_policy_and_safety_snapshots_round_trip_canonically() {
    let policy = RepositoryPublicationPolicy::new(
        OutputVisibility::Public,
        OutputVisibility::Authenticated,
        OutputVisibility::Private,
    );
    let encoded = serde_json::to_string(&policy).expect("serialize policy");
    assert_eq!(
        encoded,
        r#"{"dashboard":"public","logs":"authenticated","artifacts":"private"}"#
    );
    assert_eq!(
        serde_json::from_str::<RepositoryPublicationPolicy>(&encoded).expect("deserialize policy"),
        policy
    );

    for (value, snapshot) in [
        (SecretExposureClass::Secretless, "\"secretless\""),
        (SecretExposureClass::CapabilityOnly, "\"capability_only\""),
        (SecretExposureClass::ReadableSecret, "\"readable_secret\""),
    ] {
        assert_eq!(
            serde_json::to_string(&value).expect("serialize exposure"),
            snapshot
        );
        assert_eq!(
            serde_json::from_str::<SecretExposureClass>(snapshot).expect("deserialize exposure"),
            value
        );
    }

    assert_eq!(
        serde_json::to_string(&RawLogDisposition::Persist).expect("serialize disposition"),
        "\"persist\""
    );
}

#[test]
fn snapshots_reject_unknown_security_fields_and_variants() {
    assert!(
        serde_json::from_str::<RepositoryPublicationPolicy>(
            r#"{"dashboard":"private","future_policy":"public"}"#,
        )
        .is_err()
    );
    assert!(serde_json::from_str::<OutputVisibility>("\"everyone\"").is_err());
    assert!(serde_json::from_str::<SecretExposureClass>("\"masked_secret\"").is_err());
}
