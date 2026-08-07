use automata_core::{JOB_IR_SCHEMA_VERSION, JobIrVersion, JobIrVersionError, JobIrVersionRange};

#[test]
fn current_version_and_range_are_explicit() {
    let current = JobIrVersion::current();
    let range = JobIrVersionRange::current();

    assert_eq!(current.get(), 4);
    assert_eq!(current.get(), JOB_IR_SCHEMA_VERSION);
    assert_eq!(range.minimum(), current);
    assert_eq!(range.maximum(), current);
    assert!(range.supports(current));
}

#[test]
fn version_and_range_round_trip_as_numbers() {
    let range = JobIrVersionRange::new(
        JobIrVersion::new(1).expect("positive"),
        JobIrVersion::new(3).expect("positive"),
    )
    .expect("ordered");
    let encoded = serde_json::to_string(&range).expect("serialize");
    assert_eq!(encoded, r#"{"minimum":1,"maximum":3}"#);
    assert_eq!(
        serde_json::from_str::<JobIrVersionRange>(&encoded).expect("deserialize"),
        range
    );
}

#[test]
fn serde_rejects_zero_and_inverted_ranges() {
    assert!(serde_json::from_str::<JobIrVersion>("0").is_err());
    assert!(serde_json::from_str::<JobIrVersionRange>(r#"{"minimum":3,"maximum":1}"#).is_err());
    assert_eq!(JobIrVersion::new(0), Err(JobIrVersionError::Zero));
}
