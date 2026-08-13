use std::collections::BTreeMap;

use automata_ci_core::{
    AttemptId, JobConclusion, JobResult, JobResultOutput, JobResultValidationError,
    JobSecretExposure, MAX_JOB_OUTPUT_DEFINITIONS, MAX_JOB_RESULT_OUTPUT_UTF16_BYTES,
    OutputSensitivity, StepAnnotation, StepAnnotationLevel, StepAnnotationProperty, StepId,
    StepResult, UnixMillis,
};

fn step(id: &str, started_at: i64, completed_at: i64) -> StepResult {
    StepResult::new(
        StepId::new(id).expect("valid step ID"),
        JobConclusion::Success,
        JobConclusion::Success,
        UnixMillis::new(started_at),
        UnixMillis::new(completed_at),
    )
}

#[test]
fn valid_result_has_monotonic_unique_step_history() {
    let result = JobResult::new(
        AttemptId::new(),
        JobConclusion::Success,
        JobSecretExposure::Secretless,
        UnixMillis::new(30),
    )
    .with_steps(vec![step("build", 10, 20), step("test", 20, 30)]);

    assert_eq!(result.validate(), Ok(()));
}

#[test]
fn step_summaries_and_annotations_are_bounded_redacted_and_schema_complete() {
    let sensitive = "masked-attachment-value";
    let attached = step("build", 10, 20)
        .with_summary_markdown(format!("## Result\n{sensitive}\n"))
        .with_annotations(vec![StepAnnotation::new(
            StepAnnotationLevel::Warning,
            sensitive,
            vec![StepAnnotationProperty::new("file", sensitive)],
        )]);
    let result = JobResult::new(
        AttemptId::new(),
        JobConclusion::Success,
        JobSecretExposure::Secretless,
        UnixMillis::new(30),
    )
    .with_steps(vec![attached]);

    result.validate().expect("bounded attachments");
    assert_eq!(
        result.steps()[0].summary_markdown(),
        Some("## Result\nmasked-attachment-value\n")
    );
    assert_eq!(
        result.steps()[0].annotations()[0].level(),
        StepAnnotationLevel::Warning
    );
    assert!(!format!("{result:?}").contains(sensitive));

    let encoded = serde_json::to_value(&result).expect("serialize attachments");
    let decoded: JobResult = serde_json::from_value(encoded).expect("decode attachments");
    assert_eq!(decoded, result);

    let empty = serde_json::to_value(step("empty", 20, 30)).expect("serialize empty attachment");
    assert_eq!(empty["summary_markdown"], serde_json::Value::Null);
    assert_eq!(empty["annotations"], serde_json::json!([]));
    let decoded: StepResult = serde_json::from_value(empty.clone()).expect("decode current step");
    assert_eq!(decoded.summary_markdown(), None);
    assert!(decoded.annotations().is_empty());

    for required in ["summary_markdown", "annotations"] {
        let mut incomplete = empty.clone();
        incomplete
            .as_object_mut()
            .expect("step object")
            .remove(required);
        assert!(serde_json::from_value::<StepResult>(incomplete).is_err());
    }
}

#[test]
fn malformed_annotation_properties_fail_closed() {
    let result = JobResult::new(
        AttemptId::new(),
        JobConclusion::Failure,
        JobSecretExposure::Secretless,
        UnixMillis::new(30),
    )
    .with_steps(vec![step("build", 10, 20).with_annotations(vec![
        StepAnnotation::new(
            StepAnnotationLevel::Error,
            "failure",
            vec![
                StepAnnotationProperty::new("file", "one"),
                StepAnnotationProperty::new("FILE", "two"),
            ],
        ),
    ])]);

    assert_eq!(
        result.validate(),
        Err(JobResultValidationError::InvalidStepAnnotationProperty)
    );
}

#[test]
fn invalid_step_timestamps_and_duplicates_are_rejected() {
    let completed_before_start = JobResult::new(
        AttemptId::new(),
        JobConclusion::Failure,
        JobSecretExposure::Secretless,
        UnixMillis::new(30),
    )
    .with_steps(vec![step("build", 20, 10)]);
    assert!(matches!(
        completed_before_start.validate(),
        Err(JobResultValidationError::StepCompletedBeforeStart(_))
    ));

    let completed_after_job = JobResult::new(
        AttemptId::new(),
        JobConclusion::Failure,
        JobSecretExposure::Secretless,
        UnixMillis::new(15),
    )
    .with_steps(vec![step("build", 10, 20)]);
    assert!(matches!(
        completed_after_job.validate(),
        Err(JobResultValidationError::StepCompletedAfterJob(_))
    ));

    let duplicate = JobResult::new(
        AttemptId::new(),
        JobConclusion::Success,
        JobSecretExposure::Secretless,
        UnixMillis::new(30),
    )
    .with_steps(vec![step("build", 10, 20), step("build", 20, 30)]);
    assert!(matches!(
        duplicate.validate(),
        Err(JobResultValidationError::DuplicateStepId(_))
    ));
}

#[test]
fn deserialized_foreign_schema_is_rejected() {
    let result = JobResult::new(
        AttemptId::new(),
        JobConclusion::Success,
        JobSecretExposure::Secretless,
        UnixMillis::new(1),
    );
    let mut json = serde_json::to_value(result).expect("serialize result");
    json["schema_version"] = serde_json::json!(u16::MAX);
    let decoded: JobResult = serde_json::from_value(json).expect("decode wire-shaped result");

    assert!(matches!(
        decoded.validate(),
        Err(JobResultValidationError::UnsupportedSchema { .. })
    ));
}

#[test]
fn classified_outputs_keep_secret_plaintext_out_of_the_result() {
    let public = JobResultOutput::public("artifact-123").expect("bounded public output");
    let secret = JobResultOutput::secret_derived();
    let result = JobResult::new(
        AttemptId::new(),
        JobConclusion::Success,
        JobSecretExposure::Secretless,
        UnixMillis::new(1),
    )
    .with_outputs(BTreeMap::from([
        ("artifact".to_owned(), public),
        ("credential".to_owned(), secret),
    ]));

    result.validate().expect("classified result");
    assert_eq!(
        result.outputs()["artifact"].sensitivity(),
        OutputSensitivity::Public
    );
    assert_eq!(
        result.outputs()["artifact"].public_value(),
        Some("artifact-123")
    );
    assert_eq!(
        result.outputs()["credential"].sensitivity(),
        OutputSensitivity::SecretDerived
    );
    assert_eq!(result.outputs()["credential"].public_value(), None);

    let encoded = serde_json::to_value(&result).expect("serialize result");
    assert_eq!(
        encoded["outputs"]["credential"],
        serde_json::json!({"sensitivity": "secret_derived"})
    );
}

#[test]
fn output_debug_and_validation_errors_do_not_disclose_values() {
    let sensitive_text = "public-but-sensitive-test-value";
    let output = JobResultOutput::public(sensitive_text).expect("bounded public output");
    assert!(!format!("{output:?}").contains(sensitive_text));

    let mut encoded = serde_json::to_value(JobResultOutput::secret_derived()).expect("serialize");
    encoded["value"] = serde_json::json!(sensitive_text);
    let error = serde_json::from_value::<JobResultOutput>(encoded)
        .expect_err("secret-derived plaintext must fail closed");
    assert!(!error.to_string().contains(sensitive_text));
}

#[test]
fn malformed_output_classifications_fail_closed() {
    let missing_public = serde_json::json!({"sensitivity": "public"});
    assert!(serde_json::from_value::<JobResultOutput>(missing_public).is_err());

    let empty_public = serde_json::json!({"sensitivity": "public", "value": ""});
    assert!(serde_json::from_value::<JobResultOutput>(empty_public).is_err());

    let classified_secret = serde_json::json!({
        "sensitivity": "secret_derived",
        "value": "must-not-survive"
    });
    assert!(serde_json::from_value::<JobResultOutput>(classified_secret).is_err());
}

#[test]
fn output_names_counts_and_utf16_budget_are_validated() {
    let output = JobResultOutput::public("value").expect("bounded public output");
    let invalid_name = JobResult::new(
        AttemptId::new(),
        JobConclusion::Success,
        JobSecretExposure::Secretless,
        UnixMillis::new(1),
    )
    .with_outputs(BTreeMap::from([(" padded ".to_owned(), output.clone())]));
    assert_eq!(
        invalid_name.validate(),
        Err(JobResultValidationError::InvalidOutputName)
    );

    let too_many = JobResult::new(
        AttemptId::new(),
        JobConclusion::Success,
        JobSecretExposure::Secretless,
        UnixMillis::new(1),
    )
    .with_outputs(
        (0..=MAX_JOB_OUTPUT_DEFINITIONS)
            .map(|index| (format!("output-{index}"), output.clone()))
            .collect(),
    );
    assert!(matches!(
        too_many.validate(),
        Err(JobResultValidationError::TooManyOutputs { .. })
    ));

    let half_budget = MAX_JOB_RESULT_OUTPUT_UTF16_BYTES / 4 + 1;
    let aggregate = JobResult::new(
        AttemptId::new(),
        JobConclusion::Success,
        JobSecretExposure::Secretless,
        UnixMillis::new(1),
    )
    .with_outputs(BTreeMap::from([
        (
            "first".to_owned(),
            JobResultOutput::public("a".repeat(half_budget)).expect("individual output fits"),
        ),
        (
            "second".to_owned(),
            JobResultOutput::public("b".repeat(half_budget)).expect("individual output fits"),
        ),
    ]));
    assert!(matches!(
        aggregate.validate(),
        Err(JobResultValidationError::OutputValuesTooLarge { .. })
    ));

    assert!(matches!(
        JobResultOutput::public("x".repeat(MAX_JOB_RESULT_OUTPUT_UTF16_BYTES / 2 + 1)),
        Err(JobResultValidationError::OutputValueTooLarge { .. })
    ));
}

#[test]
fn readable_secret_exposure_and_output_sensitivity_are_independent() {
    let public = JobResultOutput::public("derived-value").expect("bounded output");
    let result = JobResult::new(
        AttemptId::new(),
        JobConclusion::Success,
        JobSecretExposure::ReadableSecret,
        UnixMillis::new(1),
    )
    .with_outputs(BTreeMap::from([("value".to_owned(), public)]));

    assert_eq!(result.validate(), Ok(()));

    let safe = JobResult::new(
        AttemptId::new(),
        JobConclusion::Success,
        JobSecretExposure::ReadableSecret,
        UnixMillis::new(1),
    )
    .with_outputs(BTreeMap::from([(
        "value".to_owned(),
        JobResultOutput::secret_derived(),
    )]));
    assert_eq!(safe.validate(), Ok(()));
}

#[test]
fn exposure_is_required_and_unknown_result_fields_fail_closed() {
    let result = JobResult::new(
        AttemptId::new(),
        JobConclusion::Success,
        JobSecretExposure::CapabilityOnly,
        UnixMillis::new(1),
    );
    let mut json = serde_json::to_value(result).expect("serialize result");
    json.as_object_mut()
        .expect("job result object")
        .remove("secret_exposure");
    assert!(serde_json::from_value::<JobResult>(json).is_err());

    let result = JobResult::new(
        AttemptId::new(),
        JobConclusion::Success,
        JobSecretExposure::Secretless,
        UnixMillis::new(1),
    );
    let mut json = serde_json::to_value(result).expect("serialize result");
    json["future_field"] = serde_json::json!(true);
    assert!(serde_json::from_value::<JobResult>(json).is_err());

    assert!(JobSecretExposure::ReadableSecret.permits(JobSecretExposure::CapabilityOnly));
    assert!(!JobSecretExposure::Secretless.permits(JobSecretExposure::CapabilityOnly));
}
