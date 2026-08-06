use automata_core::{
    JobId, JobIr, JobIrEnvelope, JobSource, JobValidationError, RunId, RunnerRequirements,
    SemanticStep, ShellSpec, StepId, StepIr, WorkflowId,
};

fn test_step() -> StepIr {
    StepIr::new(
        StepId::new("tests").expect("valid step ID"),
        "Run tests",
        SemanticStep::run("cargo test --workspace", ShellSpec::Default),
    )
}

fn envelope_with_steps(steps: Vec<StepIr>) -> JobIrEnvelope {
    JobIrEnvelope::new(
        WorkflowId::new(),
        JobSource::new(
            "github",
            "owner/repository",
            "0123456789abcdef",
            ".github/workflows/ci.yml",
            "push",
        ),
        JobIr::new(
            JobId::new(),
            RunId::new(),
            "test",
            RunnerRequirements::default(),
            steps,
        )
        .with_timeout_seconds(600),
    )
}

#[test]
fn valid_job_ir_round_trips_through_json() {
    let envelope = envelope_with_steps(vec![test_step()]);
    envelope.validate().expect("valid envelope");
    let encoded = serde_json::to_string(&envelope).expect("serialize envelope");
    let decoded: JobIrEnvelope = serde_json::from_str(&encoded).expect("deserialize envelope");
    assert_eq!(decoded, envelope);
    assert!(encoded.contains("\"schema_version\":1"));
}

#[test]
fn validation_rejects_duplicate_step_ids() {
    let step = test_step();
    let envelope = envelope_with_steps(vec![step.clone(), step]);
    assert!(matches!(
        envelope.validate(),
        Err(JobValidationError::DuplicateStepId(_)),
    ));
}
