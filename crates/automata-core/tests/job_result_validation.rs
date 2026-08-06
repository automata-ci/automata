use automata_core::{
    AttemptId, JobConclusion, JobResult, JobResultValidationError, StepId, StepResult, UnixMillis,
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
        UnixMillis::new(30),
    )
    .with_steps(vec![step("build", 10, 20), step("test", 20, 30)]);

    assert_eq!(result.validate(), Ok(()));
}

#[test]
fn invalid_step_timestamps_and_duplicates_are_rejected() {
    let completed_before_start = JobResult::new(
        AttemptId::new(),
        JobConclusion::Failure,
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
    let result = JobResult::new(AttemptId::new(), JobConclusion::Success, UnixMillis::new(1));
    let mut json = serde_json::to_value(result).expect("serialize result");
    json["schema_version"] = serde_json::json!(u16::MAX);
    let decoded: JobResult = serde_json::from_value(json).expect("decode wire-shaped result");

    assert!(matches!(
        decoded.validate(),
        Err(JobResultValidationError::UnsupportedSchema { .. })
    ));
}
