use std::collections::BTreeMap;

use automata_ci_core::{
    ContainerPort, ContainerSpec, JOB_IR_SCHEMA_VERSION, JobContentReference, JobExecutionContext,
    JobId, JobInstanceIdentity, JobIr, JobIrEnvelope, JobSource, JobValidationError,
    RUNNER_REQUIREMENTS_SCHEMA_VERSION, RunId, RunValueTemplates, RunnerRequirements,
    RuntimeBoolean, SemanticStep, Sha256Digest, ShellTemplate, StepId, StepIr, TransportProtocol,
    TrustActorEvidence, TrustActorKind, TrustAutomationKind, TrustEventKind, TrustEvidence,
    TrustOriginKind, TrustPolicy, TrustRepositoryEvidence, TrustSnapshot, TrustTokenRecursion,
    ValueTemplate, WorkflowId,
};

fn test_step() -> StepIr {
    StepIr::new_literal_name(
        StepId::new("tests").expect("valid step ID"),
        "Run tests",
        RuntimeBoolean::literal(false),
        SemanticStep::run(RunValueTemplates::new(
            ValueTemplate::literal("cargo test --workspace").expect("command"),
            ShellTemplate::default_shell(),
        )),
    )
    .expect("step name")
}

fn envelope_with_steps(steps: Vec<StepIr>) -> JobIrEnvelope {
    envelope_with_job(base_job(steps))
}

fn base_job(steps: Vec<StepIr>) -> JobIr {
    JobIr::new(
        JobId::new(),
        RunId::new(),
        "test",
        RunnerRequirements::default(),
        JobInstanceIdentity::new("test", 0, 1, Sha256Digest::from_bytes([0x44; 32]))
            .expect("instance"),
        false,
        steps,
    )
    .with_trust_snapshot(trusted_push_snapshot())
    .with_timeout_seconds(600)
}

fn trusted_push_snapshot() -> TrustSnapshot {
    let repository =
        TrustRepositoryEvidence::new("100", "10").expect("stable repository trust evidence");
    TrustPolicy::current()
        .evaluate(
            TrustEvidence::new(TrustOriginKind::ProviderWebhook, TrustEventKind::Push)
                .with_original_actor(
                    TrustActorEvidence::new("200", TrustActorKind::User, TrustAutomationKind::None)
                        .expect("stable actor trust evidence"),
                )
                .with_repositories(repository.clone(), repository)
                .with_refs("refs/heads/main", "refs/heads/main", "refs/heads/main")
                .with_revisions("0123456789abcdef", "0123456789abcdef", "0123456789abcdef")
                .with_fork(false)
                .with_token_recursion(TrustTokenRecursion::Suppressed),
        )
        .expect("complete same-repository trust snapshot")
}

fn envelope_with_job(job: JobIr) -> JobIrEnvelope {
    JobIrEnvelope::new(
        WorkflowId::new(),
        JobSource::new(
            "github",
            "owner/repository",
            "0123456789abcdef",
            ".ci/workflows/ci.yml",
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
            JobContentReference::new(
                "contexts/job.pb",
                Sha256Digest::from_bytes([0x43; 32]),
                2,
                "application/x-protobuf",
            ),
        ),
        job,
    )
}

#[test]
fn container_ports_require_nonzero_unique_container_and_requested_endpoints() {
    let service =
        |ports| ContainerSpec::new("registry.example/service@sha256:synthetic").with_ports(ports);
    let envelope = |service| {
        envelope_with_job(
            base_job(vec![test_step()])
                .with_services(BTreeMap::from([("service".to_owned(), service)])),
        )
    };

    let valid = envelope(service(vec![
        ContainerPort::new(5432, Some(15432), TransportProtocol::Tcp),
        ContainerPort::new(5353, None, TransportProtocol::Udp),
    ]));
    valid.validate().expect("valid service ports");
    let encoded = serde_json::to_string(&valid).expect("serialize service ports");
    let decoded: JobIrEnvelope = serde_json::from_str(&encoded).expect("deserialize service ports");
    assert_eq!(decoded, valid);

    for ports in [
        vec![ContainerPort::new(0, None, TransportProtocol::Tcp)],
        vec![
            ContainerPort::new(53, None, TransportProtocol::Tcp),
            ContainerPort::new(53, None, TransportProtocol::Udp),
        ],
        vec![
            ContainerPort::new(53, Some(1053), TransportProtocol::Tcp),
            ContainerPort::new(54, Some(1053), TransportProtocol::Tcp),
        ],
    ] {
        assert_eq!(
            envelope(service(ports)).validate(),
            Err(JobValidationError::InvalidContainerPorts)
        );
    }
}

#[test]
fn valid_job_ir_round_trips_through_json() {
    let envelope = envelope_with_steps(vec![test_step()]);
    envelope.validate().expect("valid envelope");
    let encoded = serde_json::to_string(&envelope).expect("serialize envelope");
    let decoded: JobIrEnvelope = serde_json::from_str(&encoded).expect("deserialize envelope");
    assert_eq!(decoded, envelope);
    let shape: serde_json::Value = serde_json::from_str(&encoded).expect("JSON shape");
    assert_eq!(shape["schema_version"], serde_json::json!(1));
    assert_eq!(
        shape["job"]["requirements"]["schema_version"],
        serde_json::json!(RUNNER_REQUIREMENTS_SCHEMA_VERSION)
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
    encoded["schema_version"] = serde_json::json!(6);
    let future: JobIrEnvelope = serde_json::from_value(encoded).expect("positive version");
    assert!(matches!(
        future.validate(),
        Err(JobValidationError::UnsupportedSchema {
            supported: JOB_IR_SCHEMA_VERSION,
            received: 6,
        })
    ));
}

#[test]
fn current_runner_requirements_reject_unknown_required_fields() {
    let encoded =
        serde_json::to_value(RunnerRequirements::default()).expect("serialize requirements");
    assert_eq!(encoded["environment_profile"], serde_json::Value::Null);
    assert_eq!(
        encoded["schema_version"],
        serde_json::json!(RUNNER_REQUIREMENTS_SCHEMA_VERSION)
    );

    let mut missing_profile = encoded.clone();
    missing_profile
        .as_object_mut()
        .expect("requirements object")
        .remove("environment_profile");
    assert!(serde_json::from_value::<RunnerRequirements>(missing_profile).is_err());

    let mut unknown_resource = encoded.clone();
    unknown_resource["minimum_resources"]["future_required_resource"] = serde_json::json!(1);
    assert!(serde_json::from_value::<RunnerRequirements>(unknown_resource).is_err());

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
