use automata_ci_core::{JOB_IR_SCHEMA_VERSION, JobIrVersion, JobIrVersionError, JobIrVersionRange};

#[test]
fn current_version_and_range_are_explicit() {
    let current = JobIrVersion::current();
    let range = JobIrVersionRange::current();

    assert_eq!(current.get(), 5);
    assert_eq!(current.get(), JOB_IR_SCHEMA_VERSION);
    assert_eq!(range.minimum(), current);
    assert_eq!(range.maximum(), current);
    assert!(range.supports(current));
    assert!(!range.supports(JobIrVersion::new(4).expect("positive")));
}

#[test]
fn exact_current_range_round_trips_as_numbers() {
    let range = JobIrVersionRange::new(JobIrVersion::current(), JobIrVersion::current())
        .expect("exact current range");
    let encoded = serde_json::to_string(&range).expect("serialize");
    assert_eq!(encoded, r#"{"minimum":5,"maximum":5}"#);
    assert_eq!(
        serde_json::from_str::<JobIrVersionRange>(&encoded).expect("deserialize"),
        range
    );
}

#[test]
fn serde_rejects_zero_and_any_noncurrent_range() {
    assert!(serde_json::from_str::<JobIrVersion>("0").is_err());
    assert!(serde_json::from_str::<JobIrVersionRange>(r#"{"minimum":4,"maximum":5}"#).is_err());
    assert!(serde_json::from_str::<JobIrVersionRange>(r#"{"minimum":5,"maximum":6}"#).is_err());
    assert_eq!(JobIrVersion::new(0), Err(JobIrVersionError::Zero));
    assert_eq!(
        JobIrVersionRange::new(
            JobIrVersion::new(4).expect("positive"),
            JobIrVersion::current(),
        ),
        Err(JobIrVersionError::UnsupportedRange {
            minimum: JobIrVersion::new(4).expect("positive"),
            maximum: JobIrVersion::current(),
        })
    );
}
