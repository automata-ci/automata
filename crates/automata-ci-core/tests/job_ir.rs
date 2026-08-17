use std::collections::BTreeMap;

use automata_ci_core::{
    ActionReference, ExpressionDialect, ExpressionInstruction, ExpressionProgram, GitObjectId,
    JobAuthorityProfile, JobContentReference, JobExecutionContext, JobId, JobInstanceIdentity,
    JobIr, JobIrEnvelope, JobOutputDefinition, JobPermissionGrant, JobPermissionRequest, JobSource,
    JobValidationError, OutputSensitivity, PermissionLevel, RunId, RunValueTemplates,
    RunnerRequirements, RuntimeBoolean, RuntimePositiveInteger, RuntimeTimeoutTemplate,
    SemanticStep, Sha256Digest, ShellTemplate, StepId, StepIr, ValueSource, ValueTemplate,
    WorkflowId,
};

use crate::support::trusted_push_snapshot;

fn expression(source: &str, root: &str) -> ExpressionProgram {
    ExpressionProgram::new(
        ExpressionDialect::new("github-actions", 1).expect("dialect"),
        source,
        vec![ExpressionInstruction::NamedValue {
            name: root.to_owned(),
        }],
    )
    .expect("expression")
}

fn source() -> JobSource {
    JobSource::new(
        "github",
        "example/project",
        GitObjectId::from_provider_hex("0123456789abcdef0123456789abcdef01234567")
            .expect("revision"),
        ".ci/workflows/ci.yml",
        "push",
    )
}

fn content(key: &str, byte: u8) -> JobContentReference {
    JobContentReference::new(
        key,
        Sha256Digest::from_bytes([byte; 32]),
        128,
        "application/json",
    )
}

fn templated_step() -> StepIr {
    let name = ValueTemplate::new(vec![
        automata_ci_core::ValueTemplateSegment::literal("Test "),
        automata_ci_core::ValueTemplateSegment::expression(expression("matrix.target", "matrix")),
    ])
    .expect("step-name template");
    let command = ValueTemplate::new(vec![
        automata_ci_core::ValueTemplateSegment::literal("cargo test --target "),
        automata_ci_core::ValueTemplateSegment::expression(expression("matrix.target", "matrix")),
    ])
    .expect("command template");
    let working_directory = ValueTemplate::new(vec![
        automata_ci_core::ValueTemplateSegment::literal("crates/"),
        automata_ci_core::ValueTemplateSegment::expression(expression("inputs.package", "inputs")),
    ])
    .expect("working-directory template");
    let dynamic_shell = ValueTemplate::expression(expression("inputs.shell", "inputs"))
        .expect("dynamic shell template");
    let values = RunValueTemplates::new(command, ShellTemplate::dynamic(dynamic_shell))
        .with_working_directory(working_directory);
    StepIr::new(
        StepId::new("test").expect("step ID"),
        name,
        RuntimeBoolean::expression(expression("matrix.experimental", "matrix")),
        SemanticStep::run(values),
    )
    .with_timeout(RuntimeTimeoutTemplate::minutes(
        RuntimePositiveInteger::expression(expression("inputs.timeout", "inputs")),
    ))
    .with_environment(BTreeMap::from([(
        "TARGET".to_owned(),
        ValueSource::Template(
            ValueTemplate::expression(expression("matrix.target", "matrix"))
                .expect("environment template"),
        ),
    )]))
}

fn current_job(outputs: Vec<JobOutputDefinition>) -> JobIr {
    JobIr::new(
        JobId::new(),
        RunId::new(),
        "test",
        RunnerRequirements::default(),
        JobInstanceIdentity::new("test", 1, 3, Sha256Digest::from_bytes([0x33; 32]))
            .expect("instance"),
        false,
        vec![templated_step()],
    )
    .with_trust_snapshot(trusted_push_snapshot())
    .with_output_definitions(outputs)
    .with_working_directory(
        ValueTemplate::new(vec![
            automata_ci_core::ValueTemplateSegment::literal("workspaces/"),
            automata_ci_core::ValueTemplateSegment::expression(expression(
                "matrix.target",
                "matrix",
            )),
        ])
        .expect("job working-directory template"),
    )
}

fn current_envelope(outputs: Vec<JobOutputDefinition>) -> JobIrEnvelope {
    JobIrEnvelope::new(
        WorkflowId::new(),
        source(),
        JobExecutionContext::new(
            "CI",
            "refs/heads/main",
            "/__w/project/project",
            content("events/push.json", 0x11),
            content("contexts/job-1.pb", 0x22),
        ),
        current_job(outputs),
    )
}

fn permission_envelope(permission_request: JobPermissionRequest) -> JobIrEnvelope {
    JobIrEnvelope::new(
        WorkflowId::new(),
        source(),
        JobExecutionContext::new(
            "CI",
            "refs/heads/main",
            "/__w/project/project",
            content("events/push.json", 0x11),
            content("contexts/job-1.pb", 0x22),
        ),
        current_job(Vec::new()).with_permission_request(permission_request),
    )
}

fn output(name: &str) -> JobOutputDefinition {
    JobOutputDefinition::new(
        name,
        ValueTemplate::expression(expression("steps.test.outputs.value", "steps"))
            .expect("output template"),
        OutputSensitivity::Public,
    )
    .expect("output definition")
}

#[test]
fn current_instance_templates_and_outputs_round_trip_without_legacy_sentinels() {
    let envelope = current_envelope(vec![output("zeta"), output("alpha")]);
    envelope.validate().expect("valid current JobIR");
    assert_eq!(envelope.schema_version(), 1);
    assert_eq!(envelope.job().instance_identity().matrix_index(), 1);
    assert!(!envelope.job().continue_on_error());
    assert_eq!(
        envelope.job().authority_profile(),
        JobAuthorityProfile::Standard
    );
    assert_eq!(
        envelope.job().permission_request(),
        &JobPermissionRequest::ProviderDefault
    );
    assert_eq!(envelope.job().output_definitions()[0].name(), "alpha");
    assert_eq!(
        envelope.job().output_definitions()[0].sensitivity(),
        OutputSensitivity::Public
    );
    assert_eq!(
        envelope.job().steps()[0]
            .continue_on_error()
            .expression_program()
            .expect("deferred expression")
            .source(),
        "matrix.experimental"
    );
    assert_eq!(
        envelope.job().steps()[0].name_template().segments().len(),
        2
    );
    let timeout = envelope.job().steps()[0].timeout().expect("step timeout");
    assert_eq!(timeout.unit().seconds_multiplier(), 60);
    assert_eq!(
        timeout
            .value()
            .expression_program()
            .expect("deferred timeout")
            .source(),
        "inputs.timeout"
    );
    assert_eq!(
        envelope
            .job()
            .working_directory_template()
            .expect("job working directory")
            .segments()
            .len(),
        2
    );
    let SemanticStep::Run { values } = envelope.job().steps()[0].kind() else {
        panic!("run step")
    };
    assert!(matches!(values.shell(), ShellTemplate::Dynamic { .. }));

    let encoded = serde_json::to_value(&envelope).expect("serialize current JobIR");
    let run = &encoded["job"]["steps"][0]["kind"];
    assert_eq!(run["kind"], serde_json::json!("run"));
    assert!(run.get("values").is_some());
    assert!(run.get("command").is_none());
    assert!(run.get("shell").is_none());
    assert!(run.get("working_directory").is_none());
    assert!(encoded["job"].get("condition").is_none());
    assert_eq!(
        encoded["job"]["permission_request"],
        serde_json::json!({"mode": "provider_default"})
    );
    assert_eq!(
        encoded["job"]["authority_profile"],
        serde_json::json!("standard")
    );
    assert!(
        encoded["job"]["steps"][0]
            .get("deferred_continue_on_error")
            .is_none()
    );
    assert!(
        encoded["job"]["steps"][0]
            .get("run_value_templates")
            .is_none()
    );

    let decoded: JobIrEnvelope = serde_json::from_value(encoded).expect("decode current JobIR");
    decoded.validate().expect("decoded current JobIR");
    assert_eq!(decoded, envelope);
}

#[test]
fn output_sensitivity_is_required_and_round_trips() {
    let secret = JobOutputDefinition::new(
        "receipt",
        ValueTemplate::expression(expression("steps.test.outputs.receipt", "steps"))
            .expect("output template"),
        OutputSensitivity::SecretDerived,
    )
    .expect("secret-derived output definition");
    let envelope = current_envelope(vec![secret]);
    let encoded = serde_json::to_value(&envelope).expect("serialize current JobIR");
    assert_eq!(
        encoded["job"]["outputs"][0]["sensitivity"],
        serde_json::json!("secret_derived")
    );
    let decoded: JobIrEnvelope = serde_json::from_value(encoded.clone()).expect("decode JobIR");
    assert_eq!(decoded, envelope);

    let mut unclassified = encoded;
    unclassified["job"]["outputs"][0]
        .as_object_mut()
        .expect("output object")
        .remove("sensitivity");
    assert!(serde_json::from_value::<JobIrEnvelope>(unclassified).is_err());

    let direct_secret = ValueTemplate::expression(expression("secrets.token", "secrets"))
        .expect("secret output template");
    assert_eq!(
        JobOutputDefinition::new("receipt", direct_secret.clone(), OutputSensitivity::Public,),
        Err(JobValidationError::PublicOutputReferencesSecrets)
    );
    assert!(
        JobOutputDefinition::new("receipt", direct_secret, OutputSensitivity::SecretDerived,)
            .is_ok()
    );

    let secret = JobOutputDefinition::new(
        "credential",
        ValueTemplate::expression(expression("secrets.token", "secrets"))
            .expect("secret output template"),
        OutputSensitivity::SecretDerived,
    )
    .expect("classified secret output");
    let mut relabeled =
        serde_json::to_value(current_envelope(vec![secret])).expect("serialize JobIR");
    relabeled["job"]["outputs"][0]["sensitivity"] = serde_json::json!("public");
    assert!(serde_json::from_value::<JobIrEnvelope>(relabeled).is_err());
}

#[test]
fn current_json_requires_and_emits_the_output_definition_list() {
    let envelope = current_envelope(Vec::new());
    let mut encoded = serde_json::to_value(&envelope).expect("serialize current JobIR");
    assert_eq!(encoded["job"]["outputs"], serde_json::json!([]));

    encoded["job"]
        .as_object_mut()
        .expect("job object")
        .remove("outputs");
    assert!(serde_json::from_value::<JobIrEnvelope>(encoded).is_err());
}

#[test]
fn resolved_permission_modes_are_required_closed_and_round_trip() {
    let mapping = JobPermissionRequest::mapping([
        JobPermissionGrant::new("statuses", PermissionLevel::Write),
        JobPermissionGrant::new("contents", PermissionLevel::Read),
        JobPermissionGrant::new("id-token", PermissionLevel::Write),
    ]);
    assert_eq!(
        mapping
            .grants()
            .expect("mapping")
            .iter()
            .map(JobPermissionGrant::name)
            .collect::<Vec<_>>(),
        ["contents", "id-token", "statuses"]
    );

    for request in [
        JobPermissionRequest::ProviderDefault,
        JobPermissionRequest::ReadAll,
        JobPermissionRequest::WriteAll,
        mapping,
    ] {
        let envelope = JobIrEnvelope::new(
            WorkflowId::new(),
            source(),
            JobExecutionContext::new(
                "CI",
                "refs/heads/main",
                "/__w/project/project",
                content("events/push.json", 0x11),
                content("contexts/job-1.pb", 0x22),
            ),
            current_job(Vec::new()).with_permission_request(request),
        );
        envelope.validate().expect("valid permission mode");
        let encoded = serde_json::to_value(&envelope).expect("serialize permission mode");
        let decoded: JobIrEnvelope =
            serde_json::from_value(encoded).expect("decode permission mode");
        assert_eq!(decoded, envelope);
    }

    let mut missing = serde_json::to_value(current_envelope(Vec::new())).expect("serialize");
    missing["job"]
        .as_object_mut()
        .expect("job object")
        .remove("permission_request");
    assert!(serde_json::from_value::<JobIrEnvelope>(missing).is_err());

    for malformed in [
        serde_json::json!({"mode": "future"}),
        serde_json::json!({"mode": "provider_default", "future": true}),
        serde_json::json!({
            "mode": "mapping",
            "permissions": [{"name": "contents", "level": "future"}]
        }),
    ] {
        let mut encoded = serde_json::to_value(current_envelope(Vec::new())).expect("serialize");
        encoded["job"]["permission_request"] = malformed;
        assert!(serde_json::from_value::<JobIrEnvelope>(encoded).is_err());
    }
}

#[test]
fn permission_mapping_validation_is_bounded_canonical_and_oidc_safe() {
    let exact_count =
        JobPermissionRequest::mapping((0..automata_ci_core::MAX_JOB_PERMISSION_GRANTS).map(
            |index| JobPermissionGrant::new(format!("permission{index:02}"), PermissionLevel::None),
        ));
    permission_envelope(exact_count)
        .validate()
        .expect("exact grant-count boundary");
    permission_envelope(JobPermissionRequest::mapping([JobPermissionGrant::new(
        "a".repeat(automata_ci_core::MAX_JOB_PERMISSION_NAME_BYTES),
        PermissionLevel::None,
    )]))
    .validate()
    .expect("exact permission-name boundary");

    for (request, expected) in [
        (
            JobPermissionRequest::Mapping(vec![
                JobPermissionGrant::new("statuses", PermissionLevel::Write),
                JobPermissionGrant::new("contents", PermissionLevel::Read),
            ]),
            JobValidationError::NonCanonicalPermissionMapping,
        ),
        (
            JobPermissionRequest::Mapping(vec![
                JobPermissionGrant::new("contents", PermissionLevel::Read),
                JobPermissionGrant::new("contents", PermissionLevel::Write),
            ]),
            JobValidationError::NonCanonicalPermissionMapping,
        ),
        (
            JobPermissionRequest::Mapping(vec![JobPermissionGrant::new(
                "Invalid_Name",
                PermissionLevel::Read,
            )]),
            JobValidationError::InvalidPermissionName,
        ),
        (
            JobPermissionRequest::Mapping(vec![JobPermissionGrant::new(
                "a".repeat(automata_ci_core::MAX_JOB_PERMISSION_NAME_BYTES + 1),
                PermissionLevel::Read,
            )]),
            JobValidationError::InvalidPermissionName,
        ),
        (
            JobPermissionRequest::Mapping(vec![JobPermissionGrant::new(
                "id-token",
                PermissionLevel::Read,
            )]),
            JobValidationError::IdTokenReadPermission,
        ),
    ] {
        let envelope = permission_envelope(request);
        assert_eq!(envelope.validate(), Err(expected));
    }

    let excessive =
        JobPermissionRequest::mapping((0..=automata_ci_core::MAX_JOB_PERMISSION_GRANTS).map(
            |index| JobPermissionGrant::new(format!("permission{index:02}"), PermissionLevel::None),
        ));
    let envelope = permission_envelope(excessive);
    assert_eq!(
        envelope.validate(),
        Err(JobValidationError::TooManyPermissionGrants {
            maximum: automata_ci_core::MAX_JOB_PERMISSION_GRANTS,
        })
    );
}

#[test]
fn credential_free_profile_is_explicit_deny_all_and_rejects_secret_or_results_paths() {
    let credential_free = || {
        current_job(Vec::new())
            .with_authority_profile(JobAuthorityProfile::CredentialFree)
            .with_permission_request(JobPermissionRequest::Mapping(Vec::new()))
    };
    let envelope = JobIrEnvelope::new(
        WorkflowId::new(),
        source(),
        JobExecutionContext::new(
            "CI",
            "refs/heads/main",
            "/__w/project/project",
            content("events/push.json", 0x11),
            content("contexts/job-1.pb", 0x22),
        ),
        credential_free(),
    );
    envelope.validate().expect("credential-free shell job");
    let encoded = serde_json::to_value(&envelope).expect("serialize credential-free JobIR");
    assert_eq!(
        encoded["job"]["authority_profile"],
        serde_json::json!("credential_free")
    );
    assert_eq!(
        serde_json::from_value::<JobIrEnvelope>(encoded).expect("decode credential-free JobIR"),
        envelope
    );

    let provider_default = JobIrEnvelope::new(
        WorkflowId::new(),
        source(),
        envelope.execution().clone(),
        current_job(Vec::new()).with_authority_profile(JobAuthorityProfile::CredentialFree),
    );
    assert_eq!(
        provider_default.validate(),
        Err(JobValidationError::CredentialFreePermissions)
    );

    let secret_reference = JobIrEnvelope::new(
        WorkflowId::new(),
        source(),
        envelope.execution().clone(),
        credential_free().with_environment(BTreeMap::from([(
            "TOKEN".to_owned(),
            ValueSource::SecretReference("repository-token".to_owned()),
        )])),
    );
    assert_eq!(
        secret_reference.validate(),
        Err(JobValidationError::CredentialFreeSecretDependency)
    );

    for repository in ["actions/cache", "actions/upload-artifact"] {
        let results_step = StepIr::new(
            StepId::new("results").expect("step ID"),
            ValueTemplate::literal("Results").expect("step name"),
            RuntimeBoolean::literal(false),
            SemanticStep::action(
                ActionReference::Repository {
                    repository: repository.to_owned(),
                    selector: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                    subpath: None,
                },
                BTreeMap::new(),
            ),
        );
        let results_action = JobIrEnvelope::new(
            WorkflowId::new(),
            source(),
            envelope.execution().clone(),
            JobIr::new(
                envelope.job().job_id(),
                envelope.job().run_id(),
                envelope.job().name(),
                envelope.job().requirements().clone(),
                envelope.job().instance_identity().clone(),
                false,
                vec![results_step],
            )
            .with_authority_profile(JobAuthorityProfile::CredentialFree)
            .with_permission_request(JobPermissionRequest::Mapping(Vec::new())),
        );
        assert_eq!(
            results_action.validate(),
            Err(JobValidationError::CredentialFreeResultsAction)
        );
    }
}

#[test]
fn noncurrent_versions_fail_closed() {
    for version in [4, 6] {
        let mut encoded = serde_json::to_value(current_envelope(Vec::new())).expect("serialize");
        encoded["schema_version"] = serde_json::json!(version);
        let envelope: JobIrEnvelope = serde_json::from_value(encoded).expect("typed version");
        assert_eq!(
            envelope.validate(),
            Err(JobValidationError::UnsupportedSchema {
                supported: 1,
                received: version,
            })
        );
    }
}

#[test]
fn current_required_fields_and_removed_legacy_fields_fail_structural_decode() {
    for pointer in [
        "/execution/runtime_context",
        "/job/instance",
        "/job/continue_on_error",
        "/job/authority_profile",
        "/job/permission_request",
        "/job/steps/0/continue_on_error",
        "/job/steps/0/kind/values",
    ] {
        let mut encoded = serde_json::to_value(current_envelope(Vec::new())).expect("serialize");
        let (parent, key) = pointer.rsplit_once('/').expect("nested pointer");
        encoded
            .pointer_mut(parent)
            .expect("parent")
            .as_object_mut()
            .expect("object")
            .remove(key);
        assert!(serde_json::from_value::<JobIrEnvelope>(encoded).is_err());
    }

    for (pointer, value) in [
        ("/job/condition", serde_json::json!({})),
        (
            "/job/steps/0/deferred_continue_on_error",
            serde_json::json!({}),
        ),
        ("/job/steps/0/run_value_templates", serde_json::json!({})),
        ("/job/steps/0/kind/command", serde_json::json!("legacy")),
    ] {
        let mut encoded = serde_json::to_value(current_envelope(Vec::new())).expect("serialize");
        let (parent, key) = pointer.rsplit_once('/').expect("nested pointer");
        encoded
            .pointer_mut(parent)
            .expect("parent")
            .as_object_mut()
            .expect("object")
            .insert(key.to_owned(), value);
        assert!(serde_json::from_value::<JobIrEnvelope>(encoded).is_err());
    }
}

#[test]
fn duplicate_outputs_and_impossible_instance_coordinates_are_rejected() {
    let duplicated = current_envelope(vec![output("same"), output("same")]);
    assert_eq!(
        duplicated.validate(),
        Err(JobValidationError::NonCanonicalJobOutput("same".to_owned()))
    );
    assert_eq!(
        JobInstanceIdentity::new("test", 0, 0, Sha256Digest::from_bytes([0; 32])),
        Err(JobValidationError::ZeroMatrixTotal)
    );
    assert_eq!(
        JobInstanceIdentity::new("test", 2, 2, Sha256Digest::from_bytes([0; 32])),
        Err(JobValidationError::MatrixIndexOutOfRange { index: 2, total: 2 })
    );
}

#[test]
fn deferred_step_timeout_rejects_zero_and_scaled_overflow() {
    let zero = templated_step().with_timeout(RuntimeTimeoutTemplate::seconds(
        RuntimePositiveInteger::literal(0),
    ));
    assert!(matches!(
        envelope_with_replaced_step(zero).validate(),
        Err(JobValidationError::ZeroStepTimeout(_))
    ));

    let overflow = templated_step().with_timeout(RuntimeTimeoutTemplate::minutes(
        RuntimePositiveInteger::literal(u32::MAX),
    ));
    assert!(matches!(
        envelope_with_replaced_step(overflow).validate(),
        Err(JobValidationError::StepTimeoutScaleOverflow(_))
    ));
}

fn envelope_with_replaced_step(step: StepIr) -> JobIrEnvelope {
    let mut envelope = current_envelope(Vec::new());
    let job = JobIr::new(
        envelope.job().job_id(),
        envelope.job().run_id(),
        envelope.job().name(),
        envelope.job().requirements().clone(),
        envelope.job().instance_identity().clone(),
        envelope.job().continue_on_error(),
        vec![step],
    );
    envelope = JobIrEnvelope::new(
        envelope.workflow_id(),
        envelope.source().clone(),
        envelope.execution().clone(),
        job,
    );
    envelope
}
