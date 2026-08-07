use automata_core::{
    JOB_IR_SCHEMA_VERSION, JobContentReference, JobExecutionContext, JobId, JobIr, JobIrEnvelope,
    JobSource, JobValidationError, RunId, RunnerRequirements, SemanticStep, Sha256Digest,
    ShellSpec, StepId, StepIr, WorkflowId,
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
        JobExecutionContext::new(
            "CI",
            "refs/heads/main",
            "/__w/repository/repository",
            JobContentReference::new(
                "events/push.json",
                Sha256Digest::from_bytes([0x42; 32]),
                2,
                "application/json",
            ),
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
    let shape: serde_json::Value = serde_json::from_str(&encoded).expect("JSON shape");
    assert_eq!(shape["schema_version"], serde_json::json!(4));
    assert_eq!(
        shape["job"]["requirements"]["schema_version"],
        serde_json::json!(2)
    );
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

#[test]
fn job_ir_version_deserialization_rejects_zero_and_validation_rejects_future_schemas() {
    let envelope = envelope_with_steps(vec![test_step()]);
    let mut encoded = serde_json::to_value(&envelope).expect("serialize envelope");
    encoded["schema_version"] = serde_json::json!(0);
    assert!(serde_json::from_value::<JobIrEnvelope>(encoded).is_err());

    let mut encoded = serde_json::to_value(&envelope).expect("serialize envelope");
    encoded["schema_version"] = serde_json::json!(5);
    let future: JobIrEnvelope = serde_json::from_value(encoded).expect("positive version");
    assert!(matches!(
        future.validate(),
        Err(JobValidationError::UnsupportedSchema {
            supported: JOB_IR_SCHEMA_VERSION,
            received: 5,
        })
    ));
}

#[test]
fn runner_requirements_v2_rejects_v1_and_unknown_required_fields() {
    let mut encoded =
        serde_json::to_value(RunnerRequirements::default()).expect("serialize requirements");
    encoded["schema_version"] = serde_json::json!(1);
    encoded
        .as_object_mut()
        .expect("requirements object")
        .remove("environment_profile");

    assert!(serde_json::from_value::<RunnerRequirements>(encoded).is_err());

    let mut encoded =
        serde_json::to_value(RunnerRequirements::default()).expect("serialize requirements");
    encoded
        .as_object_mut()
        .expect("requirements object")
        .insert(
            "future_required_constraint".to_owned(),
            serde_json::json!(true),
        );
    assert!(serde_json::from_value::<RunnerRequirements>(encoded).is_err());
}

#[test]
fn execution_context_rejects_noncanonical_ref_workspace_and_event_identity() {
    let envelope = envelope_with_steps(vec![test_step()]);
    for (path, value, expected) in [
        (
            "/execution/git_ref",
            serde_json::json!("refs/heads/feature..lock"),
            JobValidationError::InvalidGitRef,
        ),
        (
            "/execution/workspace",
            serde_json::json!("/__w//repository"),
            JobValidationError::InvalidWorkspace,
        ),
        (
            "/execution/event/object_key",
            serde_json::json!("events/../push.json"),
            JobValidationError::InvalidContentReference,
        ),
        (
            "/execution/event/media_type",
            serde_json::json!("application/json/extra"),
            JobValidationError::InvalidContentReference,
        ),
    ] {
        let mut encoded = serde_json::to_value(&envelope).expect("serialize envelope");
        *encoded.pointer_mut(path).expect("fixture field") = value;
        let malformed: JobIrEnvelope =
            serde_json::from_value(encoded).expect("structurally valid envelope");
        assert_eq!(malformed.validate(), Err(expected));
    }
}
