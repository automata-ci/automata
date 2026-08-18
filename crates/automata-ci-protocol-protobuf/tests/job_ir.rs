use std::collections::BTreeMap;

use automata_ci_core::{
    ActionReference, AttemptId, ExpressionDialect, ExpressionInstruction, ExpressionProgram,
    FencingToken, GitObjectId, JobAuthorityProfile, JobContentReference, JobExecutionContext,
    JobId, JobInstanceIdentity, JobIr, JobIrEnvelope, JobOutputDefinition, JobPermissionGrant,
    JobPermissionRequest, JobSource, Lease, LeaseId, OperationId, OutputSensitivity,
    PermissionLevel, RunId, RunIdAlias, RunValueTemplates, RunnerId, RunnerRequirements,
    RunnerSessionId, RuntimeBoolean, RuntimePositiveInteger, RuntimeTimeoutTemplate, SemanticStep,
    Sha256Digest, ShellTemplate, StepId, StepIr, TrustActorEvidence, TrustActorKind,
    TrustAutomationKind, TrustEventKind, TrustEvidence, TrustOriginKind, TrustPolicy,
    TrustRepositoryEvidence, TrustSnapshot, TrustTokenRecursion, UnixMillis, ValueSource,
    ValueTemplate, ValueTemplateSegment, WorkflowId,
};
use automata_ci_protocol::{
    CommandSequence, JobRuntimeAuthorities, LeaseOffer, MessageValidationError, ProtocolLimits,
    RunnerSlotOrdinal, SUPPORTED_PROTOCOL_RANGE, ServerCommandHeader, ServerToRunner,
};
use automata_ci_protocol_protobuf::{
    DecodeError, EncodeError, decode_job_ir, decode_server_frame, encode_job_ir,
    encode_server_frame,
};
use prost::Message as _;
use uuid::Uuid;

#[allow(clippy::all, clippy::pedantic, dead_code)]
mod fixture_wire {
    include!("../src/generated/automata.runner.v1.rs");
}

#[derive(Clone, PartialEq, prost::Message)]
struct DeletedJobSourceEncoding {
    #[prost(string, tag = "1")]
    provider: String,
    #[prost(string, tag = "2")]
    repository: String,
    #[prost(string, tag = "3")]
    revision: String,
    #[prost(string, tag = "4")]
    workflow_path: String,
    #[prost(string, tag = "5")]
    event_name: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct DeletedJobIrEncoding {
    #[prost(uint32, tag = "1")]
    schema_version: u32,
    #[prost(bytes = "vec", tag = "2")]
    workflow_id: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    source: Option<DeletedJobSourceEncoding>,
    #[prost(message, optional, tag = "4")]
    job: Option<fixture_wire::JobIr>,
    #[prost(message, optional, tag = "5")]
    execution: Option<fixture_wire::JobExecutionContext>,
}

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

fn content(key: &str, byte: u8, media_type: &str) -> JobContentReference {
    JobContentReference::new(key, Sha256Digest::from_bytes([byte; 32]), 128, media_type)
}

fn template(prefix: &str, source: &str, root: &str) -> ValueTemplate {
    ValueTemplate::new(vec![
        ValueTemplateSegment::literal(prefix),
        ValueTemplateSegment::expression(expression(source, root)),
    ])
    .expect("value template")
}

fn current_envelope_with_permission(permission_request: JobPermissionRequest) -> JobIrEnvelope {
    current_envelope_with_profile(permission_request, JobAuthorityProfile::Standard)
}

fn trusted_snapshot() -> TrustSnapshot {
    TrustPolicy::current()
        .evaluate(
            TrustEvidence::new(TrustOriginKind::ProviderWebhook, TrustEventKind::Push)
                .with_original_actor(
                    TrustActorEvidence::new(
                        "actor-1",
                        TrustActorKind::User,
                        TrustAutomationKind::None,
                    )
                    .expect("actor evidence"),
                )
                .with_repositories(
                    TrustRepositoryEvidence::new("42", "7").expect("source repository"),
                    TrustRepositoryEvidence::new("42", "7").expect("target repository"),
                )
                .with_refs("refs/heads/main", "refs/heads/main", "refs/heads/main")
                .with_revisions("source-sha", "target-sha", "execution-sha")
                .with_fork(false)
                .with_token_recursion(TrustTokenRecursion::Suppressed),
        )
        .expect("trusted snapshot")
}

fn current_envelope_with_profile(
    permission_request: JobPermissionRequest,
    authority_profile: JobAuthorityProfile,
) -> JobIrEnvelope {
    let run = StepIr::new(
        StepId::new("build").expect("step ID"),
        template("Build ", "matrix.target", "matrix"),
        RuntimeBoolean::expression(expression("matrix.experimental", "matrix")),
        SemanticStep::run(
            RunValueTemplates::new(
                template("cargo build --target ", "matrix.target", "matrix"),
                ShellTemplate::dynamic(
                    ValueTemplate::expression(expression("inputs.shell", "inputs"))
                        .expect("dynamic shell template"),
                ),
            )
            .with_working_directory(template("crates/", "inputs.package", "inputs")),
        ),
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
    )]));
    let action = StepIr::new(
        StepId::new("collect").expect("step ID"),
        ValueTemplate::literal("Collect").expect("action name"),
        RuntimeBoolean::literal(false),
        SemanticStep::action(
            ActionReference::Local {
                path: ".github/actions/collect".to_owned(),
            },
            BTreeMap::from([(
                "artifact".to_owned(),
                ValueSource::Template(template("build-", "matrix.target", "matrix")),
            )]),
        ),
    );
    let output = JobOutputDefinition::new(
        "digest",
        ValueTemplate::expression(expression("steps.collect.outputs.digest", "steps"))
            .expect("output template"),
        OutputSensitivity::Public,
    )
    .expect("job output");
    let job = JobIr::new(
        JobId::from_uuid(Uuid::from_u128(0x21)),
        RunId::from_uuid(Uuid::from_u128(0x20)),
        "build",
        RunnerRequirements::default(),
        JobInstanceIdentity::new("build", 1, 3, Sha256Digest::from_bytes([0x33; 32]))
            .expect("instance identity"),
        false,
        vec![run, action],
    )
    .with_authority_profile(authority_profile)
    .with_permission_request(permission_request)
    .with_trust_snapshot(trusted_snapshot())
    .with_environment(BTreeMap::from([(
        "CHANNEL".to_owned(),
        ValueSource::Template(template("channel-", "vars.channel", "vars")),
    )]))
    .with_working_directory(template("workspaces/", "matrix.target", "matrix"))
    .with_output_definitions([output]);

    JobIrEnvelope::new(
        WorkflowId::from_uuid(Uuid::from_u128(0x19)),
        JobSource::new(
            "github",
            "example/project",
            GitObjectId::from_provider_hex("0123456789abcdef0123456789abcdef01234567")
                .expect("revision"),
            ".github/workflows/ci.yml",
            "push",
        ),
        JobExecutionContext::new(
            "CI",
            "refs/heads/main",
            "/__w/project/project",
            content("events/push.json", 0x11, "application/json"),
            content(
                "contexts/build-1.pb",
                0x22,
                "application/vnd.automata.job-runtime-context.protobuf",
            ),
        )
        .with_run_id_alias(RunIdAlias::new(42).expect("run ID alias")),
        job,
    )
}

fn current_envelope() -> JobIrEnvelope {
    current_envelope_with_permission(JobPermissionRequest::Mapping(vec![
        JobPermissionGrant::new("actions", PermissionLevel::Read),
        JobPermissionGrant::new("contents", PermissionLevel::None),
        JobPermissionGrant::new("id-token", PermissionLevel::Write),
    ]))
}

fn wire() -> fixture_wire::JobIrEnvelope {
    let encoded = encode_job_ir(&current_envelope(), &ProtocolLimits::default())
        .expect("encode current JobIR");
    fixture_wire::JobIrEnvelope::decode(encoded.as_slice()).expect("wire current JobIR")
}

fn wire_permission_mapping(
    value: &mut fixture_wire::JobIrEnvelope,
) -> &mut fixture_wire::JobPermissionMapping {
    let request = value
        .job
        .as_mut()
        .expect("job")
        .permission_request
        .as_mut()
        .expect("permission request")
        .request
        .as_mut()
        .expect("permission request mode");
    match request {
        fixture_wire::job_permission_request::Request::Mapping(mapping) => mapping,
        fixture_wire::job_permission_request::Request::ProviderDefault(_)
        | fixture_wire::job_permission_request::Request::ReadAll(_)
        | fixture_wire::job_permission_request::Request::WriteAll(_) => {
            panic!("fixture permission request must be an explicit mapping")
        }
    }
}

#[test]
fn standalone_job_ir_current_is_deterministic_and_round_trips() {
    let envelope = current_envelope();
    let limits = ProtocolLimits::default();
    let first = encode_job_ir(&envelope, &limits).expect("encode current JobIR");
    let second = encode_job_ir(&envelope, &limits).expect("encode current JobIR again");
    assert_eq!(first, second);
    assert_eq!(
        decode_job_ir(&first, &limits).expect("decode current JobIR"),
        envelope
    );

    let wire = fixture_wire::JobIrEnvelope::decode(first.as_slice()).expect("wire current JobIR");
    assert_eq!(wire.schema_version, 1);
    let execution = wire.execution.expect("execution");
    assert!(execution.runtime_context.is_some());
    assert_eq!(execution.run_id_alias, Some(42));
    let job = wire.job.expect("job");
    assert!(job.instance.is_some());
    assert_eq!(
        job.authority_profile,
        Some(fixture_wire::JobAuthorityProfile::Standard as i32)
    );
    assert!(!job.continue_on_error);
    assert!(job.working_directory.is_some());
    assert_eq!(job.outputs.len(), 1);
    assert_eq!(
        job.outputs[0].sensitivity,
        fixture_wire::OutputSensitivity::Public as i32
    );
    let permission_request = job.permission_request.expect("permission request");
    let Some(fixture_wire::job_permission_request::Request::Mapping(permission_mapping)) =
        permission_request.request
    else {
        panic!("permission request must remain an explicit mapping");
    };
    assert_eq!(
        permission_mapping
            .grants
            .iter()
            .map(|grant| (grant.name.as_str(), grant.level))
            .collect::<Vec<_>>(),
        [
            ("actions", fixture_wire::PermissionLevel::Read as i32),
            ("contents", fixture_wire::PermissionLevel::None as i32),
            ("id-token", fixture_wire::PermissionLevel::Write as i32),
        ]
    );
    assert!(
        job.steps
            .iter()
            .all(|step| step.continue_on_error.is_some())
    );
    let run = &job.steps[0];
    assert!(run.name.is_some());
    let timeout = run.timeout.as_ref().expect("deferred timeout");
    assert_eq!(
        timeout.unit,
        fixture_wire::RuntimeTimeoutUnit::Minutes as i32
    );
    assert!(matches!(
        timeout
            .value
            .as_ref()
            .and_then(|value| value.value.as_ref()),
        Some(fixture_wire::runtime_positive_integer::Value::Expression(_))
    ));
    let shell = run
        .kind
        .as_ref()
        .and_then(|kind| kind.value.as_ref())
        .and_then(|kind| match kind {
            fixture_wire::semantic_step::Value::Run(run) => run.shell.as_ref(),
            fixture_wire::semantic_step::Value::Action(_) => None,
        })
        .and_then(|shell| shell.value.as_ref());
    assert!(matches!(
        shell,
        Some(fixture_wire::shell_template::Value::Dynamic(_))
    ));
}

#[test]
fn run_id_alias_rejects_non_positive_or_inexact_wire_values() {
    let limits = ProtocolLimits::default();
    for value in [0, RunIdAlias::MAX + 1] {
        let mut wire = wire();
        wire.execution.as_mut().expect("execution").run_id_alias = Some(value);
        assert!(matches!(
            decode_job_ir(&wire.encode_to_vec(), &limits),
            Err(DecodeError::InvalidValue {
                field: "job_execution_context.run_id_alias"
            })
        ));
    }
}

#[test]
fn git_object_ids_round_trip_both_algorithms_and_reject_malformed_wire_values() {
    let limits = ProtocolLimits::default();
    for (algorithm, digest) in [
        (fixture_wire::GitObjectAlgorithm::Sha1, vec![0x11; 20]),
        (fixture_wire::GitObjectAlgorithm::Sha256, vec![0x22; 32]),
    ] {
        let mut value = wire();
        value
            .source
            .as_mut()
            .expect("source")
            .revision
            .as_mut()
            .expect("revision")
            .algorithm = algorithm as i32;
        value
            .source
            .as_mut()
            .expect("source")
            .revision
            .as_mut()
            .expect("revision")
            .digest = digest.clone();
        let decoded = decode_job_ir(&value.encode_to_vec(), &limits).expect("decode object ID");
        assert_eq!(decoded.source().revision().as_bytes(), digest);
    }

    for (algorithm, digest) in [
        (
            fixture_wire::GitObjectAlgorithm::Unspecified as i32,
            vec![1; 20],
        ),
        (i32::MAX, vec![1; 20]),
        (fixture_wire::GitObjectAlgorithm::Sha1 as i32, vec![1; 32]),
        (fixture_wire::GitObjectAlgorithm::Sha256 as i32, vec![1; 20]),
        (fixture_wire::GitObjectAlgorithm::Sha1 as i32, vec![0; 20]),
    ] {
        let mut value = wire();
        value.source.as_mut().expect("source").revision =
            Some(fixture_wire::GitObjectId { algorithm, digest });
        assert!(decode_job_ir(&value.encode_to_vec(), &limits).is_err());
    }
}

#[test]
fn deleted_string_revision_wire_is_rejected() {
    let current = wire();
    let source = current.source.expect("source");
    let deleted_encoding = DeletedJobIrEncoding {
        schema_version: current.schema_version,
        workflow_id: current.workflow_id,
        source: Some(DeletedJobSourceEncoding {
            provider: source.provider,
            repository: source.repository,
            revision: "0123456789abcdef0123456789abcdef01234567".into(),
            workflow_path: source.workflow_path,
            event_name: source.event_name,
        }),
        job: current.job,
        execution: current.execution,
    };
    assert!(
        decode_job_ir(
            &deleted_encoding.encode_to_vec(),
            &ProtocolLimits::default()
        )
        .is_err()
    );
}

#[test]
fn every_closed_permission_request_mode_round_trips_without_defaulting() {
    let limits = ProtocolLimits::default();
    for request in [
        JobPermissionRequest::ProviderDefault,
        JobPermissionRequest::ReadAll,
        JobPermissionRequest::WriteAll,
        JobPermissionRequest::Mapping(Vec::new()),
    ] {
        let envelope = current_envelope_with_permission(request);
        let encoded = encode_job_ir(&envelope, &limits).expect("encode permission request");
        assert_eq!(
            decode_job_ir(&encoded, &limits).expect("decode permission request"),
            envelope
        );
    }
}

#[test]
fn authority_profile_is_required_closed_and_round_trips_without_defaulting() {
    let limits = ProtocolLimits::default();
    for (profile, permissions) in [
        (
            JobAuthorityProfile::Standard,
            JobPermissionRequest::ProviderDefault,
        ),
        (
            JobAuthorityProfile::CredentialFree,
            JobPermissionRequest::Mapping(Vec::new()),
        ),
    ] {
        let envelope = current_envelope_with_profile(permissions, profile);
        let encoded = encode_job_ir(&envelope, &limits).expect("encode authority profile");
        assert_eq!(
            decode_job_ir(&encoded, &limits).expect("decode authority profile"),
            envelope
        );
    }

    let mut missing = wire();
    missing.job.as_mut().expect("job").authority_profile = None;
    assert!(matches!(
        decode_job_ir(&missing.encode_to_vec(), &limits),
        Err(DecodeError::MissingField {
            field: "job_ir.authority_profile"
        })
    ));

    for value in [
        fixture_wire::JobAuthorityProfile::Unspecified as i32,
        i32::MAX,
    ] {
        let mut unknown = wire();
        unknown.job.as_mut().expect("job").authority_profile = Some(value);
        assert!(matches!(
            decode_job_ir(&unknown.encode_to_vec(), &limits),
            Err(DecodeError::InvalidValue {
                field: "job_ir.authority_profile"
            })
        ));
    }
}

#[test]
fn credential_free_offer_round_trips_without_pre_accept_authority_material() {
    let limits = ProtocolLimits::default();
    let job = current_envelope_with_profile(
        JobPermissionRequest::Mapping(Vec::new()),
        JobAuthorityProfile::CredentialFree,
    );
    let lease = Lease::new(
        LeaseId::new(),
        AttemptId::new(),
        RunnerId::new(),
        FencingToken::new(7).expect("fencing token"),
        UnixMillis::new(1_000),
        UnixMillis::new(10_000),
    )
    .expect("lease");
    JobRuntimeAuthorities::new(Vec::new(), &job, &lease).expect("empty authority bundle");
    let message = ServerToRunner::LeaseOffer(Box::new(LeaseOffer::new(
        ServerCommandHeader::new(
            SUPPORTED_PROTOCOL_RANGE.max(),
            RunnerSessionId::new(),
            OperationId::new(),
            CommandSequence::new(1).expect("command sequence"),
        ),
        RunnerSlotOrdinal::new(1).expect("runner slot"),
        lease,
        job,
    )));

    let encoded = encode_server_frame(&message, &limits).expect("encode credential-free offer");
    let decoded = decode_server_frame(&encoded, &limits)
        .expect("decode credential-free offer")
        .into_message();
    assert_eq!(decoded, message);
    let ServerToRunner::LeaseOffer(offer) = decoded else {
        panic!("expected credential-free lease offer")
    };
    assert_eq!(
        offer.job().job().authority_profile(),
        JobAuthorityProfile::CredentialFree
    );
}

#[test]
fn permission_requests_obey_identical_encode_and_decode_resource_limits() {
    let limits = ProtocolLimits::new(16 * 1024, 2, 63, 1, 1).expect("tight limits");
    let exact = current_envelope_with_permission(JobPermissionRequest::mapping([
        JobPermissionGrant::new("actions", PermissionLevel::Read),
        JobPermissionGrant::new("contents", PermissionLevel::None),
    ]));
    let encoded = encode_job_ir(&exact, &limits).expect("encode exact permission budget");
    assert_eq!(
        decode_job_ir(&encoded, &limits).expect("decode exact permission budget"),
        exact
    );

    let excessive = current_envelope_with_permission(JobPermissionRequest::mapping([
        JobPermissionGrant::new("actions", PermissionLevel::Read),
        JobPermissionGrant::new("contents", PermissionLevel::Read),
        JobPermissionGrant::new("statuses", PermissionLevel::Write),
    ]));
    assert!(matches!(
        encode_job_ir(&excessive, &limits),
        Err(EncodeError::InvalidMessage(
            MessageValidationError::CollectionTooLarge {
                field: "job permission grants",
                length: 3,
                maximum: 2,
            }
        ))
    ));

    let excessive_name =
        current_envelope_with_permission(JobPermissionRequest::mapping([JobPermissionGrant::new(
            "a".repeat(automata_ci_core::MAX_JOB_PERMISSION_NAME_BYTES),
            PermissionLevel::None,
        )]));
    assert!(matches!(
        encode_job_ir(&excessive_name, &limits),
        Err(EncodeError::InvalidMessage(
            MessageValidationError::TextTooLong {
                field: "job permission name",
                length: 64,
                maximum: 63,
            }
        ))
    ));
}

#[test]
fn current_decode_requires_the_single_run_shape_and_canonical_outputs() {
    let limits = ProtocolLimits::default();
    let mut missing_command = wire();
    missing_command
        .job
        .as_mut()
        .expect("job")
        .steps
        .first_mut()
        .expect("run step")
        .kind
        .as_mut()
        .and_then(|kind| kind.value.as_mut())
        .and_then(|kind| match kind {
            fixture_wire::semantic_step::Value::Run(run) => Some(run),
            fixture_wire::semantic_step::Value::Action(_) => None,
        })
        .expect("run")
        .command = None;
    assert!(matches!(
        decode_job_ir(&missing_command.encode_to_vec(), &limits),
        Err(DecodeError::MissingField {
            field: "run_step.command"
        })
    ));

    let mut outputs = wire();
    let job = outputs.job.as_mut().expect("job");
    let value = job.outputs[0].value.clone();
    let sensitivity = job.outputs[0].sensitivity;
    job.outputs = vec![
        fixture_wire::JobOutputDefinition {
            name: "z".to_owned(),
            value: value.clone(),
            sensitivity,
        },
        fixture_wire::JobOutputDefinition {
            name: "a".to_owned(),
            value,
            sensitivity,
        },
    ];
    assert!(matches!(
        decode_job_ir(&outputs.encode_to_vec(), &limits),
        Err(DecodeError::NonCanonicalOrder {
            field: "job_ir.outputs"
        })
    ));

    for sensitivity in [
        fixture_wire::OutputSensitivity::Unspecified as i32,
        i32::MAX,
    ] {
        let mut unclassified = wire();
        unclassified.job.as_mut().expect("job").outputs[0].sensitivity = sensitivity;
        assert!(matches!(
            decode_job_ir(&unclassified.encode_to_vec(), &limits),
            Err(DecodeError::UnknownEnum {
                field: "job_output_definition.sensitivity",
                value,
            }) if value == sensitivity
        ));
    }
}

#[test]
fn current_decode_requires_runtime_context_instance_and_step_boolean() {
    let limits = ProtocolLimits::default();
    let mut missing_context = wire();
    missing_context
        .execution
        .as_mut()
        .expect("execution")
        .runtime_context = None;
    assert!(matches!(
        decode_job_ir(&missing_context.encode_to_vec(), &limits),
        Err(DecodeError::MissingField {
            field: "job_execution_context.runtime_context"
        })
    ));

    let mut missing_instance = wire();
    missing_instance.job.as_mut().expect("job").instance = None;
    assert!(matches!(
        decode_job_ir(&missing_instance.encode_to_vec(), &limits),
        Err(DecodeError::MissingField {
            field: "job_ir.instance"
        })
    ));

    let mut missing_boolean = wire();
    missing_boolean
        .job
        .as_mut()
        .expect("job")
        .steps
        .first_mut()
        .expect("step")
        .continue_on_error = None;
    assert!(matches!(
        decode_job_ir(&missing_boolean.encode_to_vec(), &limits),
        Err(DecodeError::MissingField {
            field: "step_ir.continue_on_error"
        })
    ));

    let mut missing_name = wire();
    missing_name
        .job
        .as_mut()
        .expect("job")
        .steps
        .first_mut()
        .expect("step")
        .name = None;
    assert!(matches!(
        decode_job_ir(&missing_name.encode_to_vec(), &limits),
        Err(DecodeError::MissingField {
            field: "step_ir.name"
        })
    ));

    let mut unknown_timeout_unit = wire();
    unknown_timeout_unit
        .job
        .as_mut()
        .expect("job")
        .steps
        .first_mut()
        .expect("step")
        .timeout
        .as_mut()
        .expect("timeout")
        .unit = i32::MAX;
    assert!(matches!(
        decode_job_ir(&unknown_timeout_unit.encode_to_vec(), &limits),
        Err(DecodeError::UnknownEnum {
            field: "runtime_timeout_template.unit",
            value: i32::MAX,
        })
    ));
}

#[test]
fn current_permission_request_decode_is_required_closed_and_canonical() {
    let limits = ProtocolLimits::default();

    let mut missing_request = wire();
    missing_request
        .job
        .as_mut()
        .expect("job")
        .permission_request = None;
    assert!(matches!(
        decode_job_ir(&missing_request.encode_to_vec(), &limits),
        Err(DecodeError::MissingField {
            field: "job_ir.permission_request"
        })
    ));

    let mut missing_mode = wire();
    missing_mode
        .job
        .as_mut()
        .expect("job")
        .permission_request
        .as_mut()
        .expect("permission request")
        .request = None;
    assert!(matches!(
        decode_job_ir(&missing_mode.encode_to_vec(), &limits),
        Err(DecodeError::MissingVariant {
            field: "job_permission_request.request"
        })
    ));

    let mut noncanonical = wire();
    wire_permission_mapping(&mut noncanonical).grants.swap(0, 1);
    assert!(matches!(
        decode_job_ir(&noncanonical.encode_to_vec(), &limits),
        Err(DecodeError::NonCanonicalOrder {
            field: "job_permission_mapping.grants"
        })
    ));

    let mut duplicate = wire();
    let mapping = wire_permission_mapping(&mut duplicate);
    let duplicate_name = mapping.grants[0].name.clone();
    mapping.grants[1].name = duplicate_name;
    assert!(matches!(
        decode_job_ir(&duplicate.encode_to_vec(), &limits),
        Err(DecodeError::DuplicateEntry {
            field: "job_permission_mapping.grants"
        })
    ));

    for level in [fixture_wire::PermissionLevel::Unspecified as i32, i32::MAX] {
        let mut unknown = wire();
        wire_permission_mapping(&mut unknown).grants[0].level = level;
        assert!(matches!(
            decode_job_ir(&unknown.encode_to_vec(), &limits),
            Err(DecodeError::UnknownEnum {
                field: "job_permission_grant.level",
                value,
            }) if value == level
        ));
    }

    let mut oversized = wire();
    wire_permission_mapping(&mut oversized).grants = (0..=64)
        .map(|index| fixture_wire::JobPermissionGrant {
            name: format!("p{index:02}"),
            level: fixture_wire::PermissionLevel::Read as i32,
        })
        .collect();
    assert!(matches!(
        decode_job_ir(&oversized.encode_to_vec(), &limits),
        Err(DecodeError::CollectionTooLarge {
            field: "job_permission_mapping.grants",
            length: 65,
            maximum: 64,
        })
    ));
}

#[test]
fn id_token_read_is_rejected_on_both_job_ir_wire_directions() {
    let limits = ProtocolLimits::default();
    let invalid = current_envelope_with_permission(JobPermissionRequest::Mapping(vec![
        JobPermissionGrant::new("id-token", PermissionLevel::Read),
    ]));
    assert!(matches!(
        encode_job_ir(&invalid, &limits),
        Err(EncodeError::InvalidMessage(_))
    ));

    let mut invalid_wire = wire();
    let id_token = wire_permission_mapping(&mut invalid_wire)
        .grants
        .iter_mut()
        .find(|grant| grant.name == "id-token")
        .expect("id-token grant");
    id_token.level = fixture_wire::PermissionLevel::Read as i32;
    assert!(matches!(
        decode_job_ir(&invalid_wire.encode_to_vec(), &limits),
        Err(DecodeError::InvalidMessage(_))
    ));
}
