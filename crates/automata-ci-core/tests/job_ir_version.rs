use automata_ci_core::{JobIrVersion, JobIrVersionError, JobIrVersionRange};

#[test]
fn exact_current_range_round_trips_as_numbers() {
    let range = JobIrVersionRange::new(JobIrVersion::current(), JobIrVersion::current())
        .expect("exact current range");
    let encoded = serde_json::to_string(&range).expect("serialize");
    assert_eq!(encoded, r#"{"minimum":1,"maximum":1}"#);
    assert_eq!(
        serde_json::from_str::<JobIrVersionRange>(&encoded).expect("deserialize"),
        range
    );
}

#[test]
fn serde_rejects_zero_and_any_noncurrent_range() {
    assert!(serde_json::from_str::<JobIrVersion>("0").is_err());
    assert!(serde_json::from_str::<JobIrVersionRange>(r#"{"minimum":1,"maximum":2}"#).is_err());
    assert!(serde_json::from_str::<JobIrVersionRange>(r#"{"minimum":2,"maximum":2}"#).is_err());
    assert_eq!(JobIrVersion::new(0), Err(JobIrVersionError::Zero));
    assert_eq!(
        JobIrVersionRange::new(
            JobIrVersion::new(2).expect("positive"),
            JobIrVersion::current(),
        ),
        Err(JobIrVersionError::UnsupportedRange {
            minimum: JobIrVersion::new(2).expect("positive"),
            maximum: JobIrVersion::current(),
        })
    );
}
