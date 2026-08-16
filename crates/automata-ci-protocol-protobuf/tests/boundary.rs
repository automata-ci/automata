use crate::common;

use automata_ci_core::{
    AttemptId, JobIrVersion, Lease, OperationId, RUNNER_REQUIREMENTS_SCHEMA_VERSION,
    RunnerSessionId,
};
use automata_ci_protocol::{
    CommandAck, CommandCursor, LeaseAuthorityPollContributions, LeaseOffer, LeaseRequest,
    MessageHeader, MessageValidationError, ProtocolLimits, RunnerToServer,
    SUPPORTED_PROTOCOL_RANGE, ServerToRunner,
};
use automata_ci_protocol_protobuf::{
    DecodeError, EncodeError, decode_job_ir, decode_runner_frame, decode_server_frame,
    encode_job_ir, encode_runner_frame, encode_server_frame,
};
use prost::Message as _;
use sha2::{Digest as _, Sha256};
use static_assertions::assert_impl_all;
use uuid::Uuid;

#[allow(clippy::all, clippy::pedantic, dead_code)]
mod fixture_wire {
    include!("../src/generated/automata.runner.v1.rs");
}

fn wire_header(reply: bool) -> fixture_wire::MessageHeader {
    fixture_wire::MessageHeader {
        message_schema_version: u32::from(automata_ci_protocol::MESSAGE_SCHEMA_VERSION),
        protocol_version: u32::from(SUPPORTED_PROTOCOL_RANGE.max().get()),
        session_id: Uuid::from_u128(1).as_bytes().to_vec(),
        operation_id: Uuid::from_u128(2).as_bytes().to_vec(),
        in_reply_to: reply.then(|| Uuid::from_u128(3).as_bytes().to_vec()),
    }
}

fn wire_guard() -> fixture_wire::LeaseGuard {
    fixture_wire::LeaseGuard {
        lease_id: Uuid::from_u128(4).as_bytes().to_vec(),
        fencing_token: 1,
    }
}

fn wire_empty_authority_contributions() -> fixture_wire::LeaseAuthorityPollContributions {
    let empty = LeaseAuthorityPollContributions::default();
    fixture_wire::LeaseAuthorityPollContributions {
        schema_version: u32::from(empty.schema_version()),
        contributions: Vec::new(),
        sha256_digest: empty.sha256_digest().as_bytes().to_vec(),
    }
}

fn encode<M: prost::Message>(message: &M) -> Vec<u8> {
    message.encode_to_vec()
}

fn fixture_lease_offer() -> fixture_wire::ServerFrame {
    let message = common::server_messages()
        .into_iter()
        .find_map(|(name, message)| (name == "lease_offer").then_some(message))
        .expect("lease offer fixture");
    let encoded =
        encode_server_frame(&message, &ProtocolLimits::default()).expect("encode fixture");
    fixture_wire::ServerFrame::decode(encoded.as_slice()).expect("decode private test DTO")
}

fn fixture_runtime_authority_grant() -> fixture_wire::ServerFrame {
    let message = common::server_messages()
        .into_iter()
        .find_map(|(name, message)| (name == "runtime_authority_grant").then_some(message))
        .expect("runtime-authority grant fixture");
    let encoded =
        encode_server_frame(&message, &ProtocolLimits::default()).expect("encode fixture");
    fixture_wire::ServerFrame::decode(encoded.as_slice()).expect("decode private test DTO")
}

fn fixture_lease_offer_with_managed_overlay() -> fixture_wire::ServerFrame {
    let offer = common::lease_offer_with_job(common::rich_job());
    let overlay = common::managed_secret_overlay(offer.lease());
    let offer = offer
        .with_managed_secret_bindings(overlay)
        .expect("lease-bound overlay");
    let encoded = encode_server_frame(
        &ServerToRunner::LeaseOffer(Box::new(offer)),
        &ProtocolLimits::default(),
    )
    .expect("encode managed-overlay fixture");
    fixture_wire::ServerFrame::decode(encoded.as_slice()).expect("decode private test DTO")
}

fn lease_offer_payload(frame: &mut fixture_wire::ServerFrame) -> &mut fixture_wire::LeaseOffer {
    let Some(fixture_wire::server_frame::Payload::LeaseOffer(offer)) = frame.payload.as_mut()
    else {
        panic!("lease offer fixture shape");
    };
    offer
}

fn managed_secret_overlay_digest(overlay: &fixture_wire::ManagedSecretBindingOverlay) -> Vec<u8> {
    fn update_text(hasher: &mut Sha256, value: &str) {
        hasher.update(
            u32::try_from(value.len())
                .expect("fixture text length")
                .to_be_bytes(),
        );
        hasher.update(value.as_bytes());
    }

    let mut hasher = Sha256::new();
    hasher.update(b"automata.managed-secret-binding-overlay.v1\0");
    hasher.update(
        u16::try_from(overlay.schema_version)
            .expect("fixture schema")
            .to_be_bytes(),
    );
    hasher.update(&overlay.attempt_id);
    hasher.update(&overlay.lease_id);
    hasher.update(overlay.fencing_token.to_be_bytes());
    hasher.update(
        u32::try_from(overlay.bindings.len())
            .expect("fixture binding count")
            .to_be_bytes(),
    );
    for binding in &overlay.bindings {
        update_text(&mut hasher, &binding.canonical_name);
        update_text(&mut hasher, &binding.grant_id);
        update_text(&mut hasher, &binding.version_id);
    }
    hasher.finalize().to_vec()
}

fn runner_requirements(
    frame: &mut fixture_wire::ServerFrame,
) -> &mut fixture_wire::RunnerRequirements {
    lease_offer_payload(frame)
        .job
        .as_mut()
        .expect("job envelope")
        .job
        .as_mut()
        .expect("job")
        .requirements
        .as_mut()
        .expect("runner requirements")
}

fn attach_valid_resource_allocation(frame: &mut fixture_wire::ServerFrame) {
    let requirements = runner_requirements(frame);
    let requests = requirements.minimum_resources.expect("minimum resources");
    let mut limits = requests;
    limits.cpu_millis *= 2;
    limits.memory_bytes *= 2;
    limits.ephemeral_disk_bytes *= 2;
    requirements.resource_allocation = Some(fixture_wire::JobResourceAllocation {
        requests: Some(requests),
        limits: Some(limits),
    });
}

fn fixture_runner_hello() -> fixture_wire::RunnerFrame {
    let message = common::runner_messages()
        .into_iter()
        .find_map(|(name, message)| (name == "hello").then_some(message))
        .expect("runner hello fixture");
    let encoded =
        encode_runner_frame(&message, &ProtocolLimits::default()).expect("encode fixture");
    fixture_wire::RunnerFrame::decode(encoded.as_slice()).expect("decode private test DTO")
}

fn fixture_server_hello() -> fixture_wire::ServerFrame {
    let message = common::server_messages()
        .into_iter()
        .find_map(|(name, message)| (name == "hello").then_some(message))
        .expect("server hello fixture");
    let encoded =
        encode_server_frame(&message, &ProtocolLimits::default()).expect("encode fixture");
    fixture_wire::ServerFrame::decode(encoded.as_slice()).expect("decode private test DTO")
}

fn fixture_job_result() -> fixture_wire::RunnerFrame {
    let message = common::runner_messages()
        .into_iter()
        .find_map(|(name, message)| (name == "job_result").then_some(message))
        .expect("job result fixture");
    let encoded =
        encode_runner_frame(&message, &ProtocolLimits::default()).expect("encode fixture");
    fixture_wire::RunnerFrame::decode(encoded.as_slice()).expect("decode private test DTO")
}

fn job_result_payload(frame: &mut fixture_wire::RunnerFrame) -> &mut fixture_wire::JobResult {
    let Some(fixture_wire::runner_frame::Payload::JobResult(message)) = frame.payload.as_mut()
    else {
        panic!("job result fixture shape");
    };
    message.result.as_mut().expect("job result payload")
}

fn fixture_job_ir() -> fixture_wire::JobIrEnvelope {
    let encoded = encode_job_ir(&common::rich_job(), &ProtocolLimits::default())
        .expect("encode JobIR fixture");
    fixture_wire::JobIrEnvelope::decode(encoded.as_slice()).expect("decode private test DTO")
}

fn job_ir_runner_requirements(
    envelope: &mut fixture_wire::JobIrEnvelope,
) -> &mut fixture_wire::RunnerRequirements {
    envelope
        .job
        .as_mut()
        .expect("job")
        .requirements
        .as_mut()
        .expect("runner requirements")
}

#[test]
fn job_ir_round_trips_exact_trust_snapshot_and_rejects_tampering() {
    let original = common::rich_job();
    let encoded = encode_job_ir(&original, &ProtocolLimits::default()).expect("encode JobIR");
    let decoded = decode_job_ir(&encoded, &ProtocolLimits::default()).expect("decode JobIR");
    assert_eq!(
        decoded.job().trust_snapshot().canonical_bytes(),
        original.job().trust_snapshot().canonical_bytes()
    );
    assert_eq!(
        decoded.job().trust_snapshot().digest(),
        original.job().trust_snapshot().digest()
    );

    let mut tampered = fixture_job_ir();
    let trust_digest = &mut tampered.job.as_mut().expect("job").trust_snapshot_digest;
    trust_digest[0] ^= 1;
    assert!(matches!(
        decode_job_ir(&encode(&tampered), &ProtocolLimits::default()),
        Err(DecodeError::InvalidValue {
            field: "job_ir.trust_snapshot"
        })
    ));

    let mut missing_digest = fixture_job_ir();
    missing_digest
        .job
        .as_mut()
        .expect("job")
        .trust_snapshot_digest
        .clear();
    assert!(matches!(
        decode_job_ir(&encode(&missing_digest), &ProtocolLimits::default()),
        Err(DecodeError::InvalidValue {
            field: "job_ir.trust_snapshot_digest"
        })
    ));
}

#[test]
fn standalone_job_ir_rejects_schema_and_expression_program_skew() {
    for version in [2, u32::from(JobIrVersion::current().get()) + 1] {
        let mut noncurrent_job = fixture_job_ir();
        noncurrent_job.schema_version = version;
        assert!(matches!(
            decode_job_ir(&encode(&noncurrent_job), &ProtocolLimits::default()),
            Err(DecodeError::UnsupportedSchema {
                field: "job_ir_envelope.schema_version",
                received,
                supported: 1,
            }) if received == version
        ));
    }

    let mut future_expression = fixture_job_ir();
    future_expression
        .job
        .as_mut()
        .expect("job")
        .steps
        .first_mut()
        .expect("step")
        .condition
        .as_mut()
        .expect("condition")
        .schema_version += 1;
    assert!(matches!(
        decode_job_ir(&encode(&future_expression), &ProtocolLimits::default()),
        Err(DecodeError::UnsupportedSchema {
            field: "expression_program.schema_version",
            ..
        })
    ));
}

#[test]
fn windows_hyperv_requirement_wire_shape_fails_closed() {
    let exact = common::rich_job_with_requirements(
        automata_ci_core::RunnerRequirements::default().with_windows_hyperv_container(),
    );
    let encoded = encode_job_ir(&exact, &ProtocolLimits::default()).expect("encode exact shape");
    let fixture = fixture_wire::JobIrEnvelope::decode(encoded.as_slice())
        .expect("decode private exact-shape DTO");
    decode_job_ir(&encode(&fixture), &ProtocolLimits::default()).expect("decode exact shape");

    let mut missing_launch = fixture.clone();
    job_ir_runner_requirements(&mut missing_launch)
        .sandbox_features
        .clear();
    assert!(matches!(
        decode_job_ir(&encode(&missing_launch), &ProtocolLimits::default()),
        Err(DecodeError::InvalidValue {
            field: "runner_requirements.sandbox_features"
        })
    ));

    let mut weak_isolation = fixture.clone();
    job_ir_runner_requirements(&mut weak_isolation).minimum_isolation =
        fixture_wire::IsolationLevel::SharedKernel as i32;
    assert!(matches!(
        decode_job_ir(&encode(&weak_isolation), &ProtocolLimits::default()),
        Err(DecodeError::InvalidValue {
            field: "runner_requirements.minimum_isolation"
        })
    ));

    let mut wrong_platform = fixture;
    job_ir_runner_requirements(&mut wrong_platform).operating_system =
        Some(fixture_wire::OperatingSystem {
            value: Some(fixture_wire::operating_system::Value::Linux(
                fixture_wire::Unit {},
            )),
        });
    assert!(matches!(
        decode_job_ir(&encode(&wrong_platform), &ProtocolLimits::default()),
        Err(DecodeError::InvalidValue {
            field: "runner_requirements.sandbox_features"
        })
    ));
}

#[test]
fn handshake_rejects_every_noncurrent_job_ir_endpoint() {
    for version in [2, 3] {
        let mut hello = fixture_runner_hello();
        let Some(fixture_wire::runner_frame::Payload::Hello(payload)) = hello.payload.as_mut()
        else {
            panic!("runner hello fixture shape");
        };
        payload
            .supported_job_ir
            .as_mut()
            .expect("JobIR contract")
            .minimum = version;
        assert!(matches!(
            decode_runner_frame(&encode(&hello), &ProtocolLimits::default()),
            Err(DecodeError::UnsupportedSchema {
                field: "job_ir_version_range.minimum",
                received,
                supported: 1,
            }) if received == version
        ));

        let mut hello = fixture_server_hello();
        let Some(fixture_wire::server_frame::Payload::Hello(payload)) = hello.payload.as_mut()
        else {
            panic!("server hello fixture shape");
        };
        payload
            .session
            .as_mut()
            .expect("negotiated session")
            .selected_job_ir = version;
        assert!(matches!(
            decode_server_frame(&encode(&hello), &ProtocolLimits::default()),
            Err(DecodeError::UnsupportedSchema {
                field: "negotiated_session.selected_job_ir",
                received,
                supported: 1,
            }) if received == version
        ));
    }
}

#[test]
fn standalone_job_ir_rejects_malformed_expression_programs() {
    let mut missing_instruction = fixture_job_ir();
    missing_instruction
        .job
        .as_mut()
        .expect("job")
        .steps
        .first_mut()
        .expect("step")
        .condition
        .as_mut()
        .expect("condition")
        .instructions
        .push(fixture_wire::ExpressionInstruction { value: None });
    assert!(matches!(
        decode_job_ir(&encode(&missing_instruction), &ProtocolLimits::default()),
        Err(DecodeError::MissingVariant {
            field: "expression_instruction.value"
        })
    ));

    let mut invalid_stack = fixture_job_ir();
    let condition = invalid_stack
        .job
        .as_mut()
        .expect("job")
        .steps
        .first_mut()
        .expect("step")
        .condition
        .as_mut()
        .expect("condition");
    condition.instructions = vec![fixture_wire::ExpressionInstruction {
        value: Some(fixture_wire::expression_instruction::Value::Not(
            fixture_wire::Unit {},
        )),
    }];
    assert!(matches!(
        decode_job_ir(&encode(&invalid_stack), &ProtocolLimits::default()),
        Err(DecodeError::InvalidValue {
            field: "expression_program"
        })
    ));
}

#[test]
fn standalone_job_ir_rejects_unknown_expression_enums_and_instruction_floods() {
    let mut unknown_enum = fixture_job_ir();
    let condition = unknown_enum
        .job
        .as_mut()
        .expect("job")
        .steps
        .first_mut()
        .expect("step")
        .condition
        .as_mut()
        .expect("condition");
    condition.instructions = vec![
        fixture_wire::ExpressionInstruction {
            value: Some(fixture_wire::expression_instruction::Value::Literal(
                fixture_wire::ExpressionLiteral {
                    value: Some(fixture_wire::expression_literal::Value::Boolean(true)),
                },
            )),
        },
        fixture_wire::ExpressionInstruction {
            value: Some(fixture_wire::expression_instruction::Value::Literal(
                fixture_wire::ExpressionLiteral {
                    value: Some(fixture_wire::expression_literal::Value::Boolean(false)),
                },
            )),
        },
        fixture_wire::ExpressionInstruction {
            value: Some(fixture_wire::expression_instruction::Value::Logical(
                fixture_wire::ExpressionLogicalInstruction {
                    operator: 777,
                    operand_count: 2,
                },
            )),
        },
    ];
    let Some(fixture_wire::expression_instruction::Value::Logical(logical)) = condition
        .instructions
        .last_mut()
        .and_then(|instruction| instruction.value.as_mut())
    else {
        panic!("logical instruction fixture");
    };
    assert_eq!(logical.operator, 777);
    assert!(matches!(
        decode_job_ir(&encode(&unknown_enum), &ProtocolLimits::default()),
        Err(DecodeError::UnknownEnum {
            field: "expression_logical_instruction.operator",
            value: 777
        })
    ));

    let mut flooded = fixture_job_ir();
    let condition = flooded
        .job
        .as_mut()
        .expect("job")
        .steps
        .first_mut()
        .expect("step")
        .condition
        .as_mut()
        .expect("condition");
    condition.instructions = (0..=automata_ci_core::MAX_EXPRESSION_INSTRUCTIONS)
        .map(|_| fixture_wire::ExpressionInstruction {
            value: Some(fixture_wire::expression_instruction::Value::Literal(
                fixture_wire::ExpressionLiteral {
                    value: Some(fixture_wire::expression_literal::Value::Boolean(true)),
                },
            )),
        })
        .collect();
    assert!(matches!(
        decode_job_ir(&encode(&flooded), &ProtocolLimits::default()),
        Err(DecodeError::CollectionTooLarge {
            field: "expression_program.instructions",
            length,
            maximum: automata_ci_core::MAX_EXPRESSION_INSTRUCTIONS,
        }) if length == automata_ci_core::MAX_EXPRESSION_INSTRUCTIONS + 1
    ));
}

#[test]
fn decode_is_size_first_and_rejects_empty_or_malformed_frames() {
    let limits = ProtocolLimits::new(128, 8, 64, 4, 64).expect("coherent limits");
    let oversized = vec![0xff; 129];
    assert!(matches!(
        decode_runner_frame(&oversized, &limits),
        Err(DecodeError::FrameTooLarge {
            size: 129,
            maximum: 128
        })
    ));
    assert!(matches!(
        decode_server_frame(&[], &limits),
        Err(DecodeError::EmptyFrame)
    ));
    assert!(matches!(
        decode_server_frame(&[0xff], &limits),
        Err(DecodeError::MalformedProtobuf(_))
    ));
}

#[test]
fn missing_or_unknown_required_oneofs_are_rejected() {
    let unknown_top_level_field = [0xa0, 0x06, 0x01];
    assert!(matches!(
        decode_runner_frame(&unknown_top_level_field, &ProtocolLimits::default()),
        Err(DecodeError::MissingVariant {
            field: "runner_frame.payload"
        })
    ));

    let frame = fixture_wire::RunnerFrame {
        payload: Some(fixture_wire::runner_frame::Payload::LeaseRequest(
            fixture_wire::LeaseRequest {
                header: None,
                slot: 1,
                acknowledges_operation_id: None,
                authority_contributions: Some(wire_empty_authority_contributions()),
            },
        )),
    };
    assert!(matches!(
        decode_runner_frame(&encode(&frame), &ProtocolLimits::default()),
        Err(DecodeError::MissingField {
            field: "lease_request.header"
        })
    ));

    let mut frame = fixture_runtime_authority_grant();
    let Some(fixture_wire::server_frame::Payload::RuntimeAuthorityGrant(grant)) =
        frame.payload.as_mut()
    else {
        panic!("runtime-authority grant fixture shape");
    };
    grant.authorities = None;
    assert!(matches!(
        decode_server_frame(&encode(&frame), &ProtocolLimits::default()),
        Err(DecodeError::MissingField {
            field: "runtime_authority_grant.authorities"
        })
    ));

    let message = common::runner_messages()
        .into_iter()
        .find_map(|(name, message)| (name == "lease_request").then_some(message))
        .expect("lease request fixture");
    let encoded =
        encode_runner_frame(&message, &ProtocolLimits::default()).expect("encode fixture");
    let mut frame = fixture_wire::RunnerFrame::decode(encoded.as_slice()).expect("wire fixture");
    let Some(fixture_wire::runner_frame::Payload::LeaseRequest(request)) = frame.payload.as_mut()
    else {
        panic!("lease request fixture shape");
    };
    request.authority_contributions = None;
    assert!(matches!(
        decode_runner_frame(&encode(&frame), &ProtocolLimits::default()),
        Err(DecodeError::MissingField {
            field: "lease_request.authority_contributions"
        })
    ));
}

#[test]
fn protected_authority_bundle_requires_provider_neutral_sandbox_authorizations() {
    let mut frame = fixture_runtime_authority_grant();
    let Some(fixture_wire::server_frame::Payload::RuntimeAuthorityGrant(grant)) =
        frame.payload.as_mut()
    else {
        panic!("runtime-authority grant fixture shape");
    };
    grant
        .authorities
        .as_mut()
        .expect("authorities")
        .sandbox_authorizations = None;

    assert!(matches!(
        decode_server_frame(&encode(&frame), &ProtocolLimits::default()),
        Err(DecodeError::MissingField {
            field: "runtime_authorities.sandbox_authorizations"
        })
    ));
}

#[test]
fn uuid_fields_require_exactly_sixteen_bytes_without_echoing_contents() {
    let mut header = wire_header(false);
    header.session_id = vec![0x5a; 15];
    let frame = fixture_wire::RunnerFrame {
        payload: Some(fixture_wire::runner_frame::Payload::LeaseRequest(
            fixture_wire::LeaseRequest {
                header: Some(header),
                slot: 1,
                acknowledges_operation_id: None,
                authority_contributions: Some(wire_empty_authority_contributions()),
            },
        )),
    };
    let error = decode_runner_frame(&encode(&frame), &ProtocolLimits::default())
        .expect_err("short UUID must fail");
    assert!(matches!(
        error,
        DecodeError::InvalidUuidLength {
            field: "message_header.session_id",
            received: 15
        }
    ));
    let displayed = error.to_string();
    assert!(!displayed.contains("5a5a"));

    let acknowledgement = vec![0x6b; 15];
    let frame = fixture_wire::RunnerFrame {
        payload: Some(fixture_wire::runner_frame::Payload::LeaseRequest(
            fixture_wire::LeaseRequest {
                header: Some(wire_header(false)),
                slot: 1,
                acknowledges_operation_id: Some(acknowledgement),
                authority_contributions: Some(wire_empty_authority_contributions()),
            },
        )),
    };
    let error = decode_runner_frame(&encode(&frame), &ProtocolLimits::default())
        .expect_err("short acknowledged operation UUID must fail");
    assert!(matches!(
        error,
        DecodeError::InvalidUuidLength {
            field: "lease_request.acknowledges_operation_id",
            received: 15
        }
    ));
    assert!(!error.to_string().contains("6b6b"));
}

#[test]
fn lease_request_self_acknowledgement_is_rejected_after_wire_conversion() {
    let header = wire_header(false);
    let operation_id = header.operation_id.clone();
    let frame = fixture_wire::RunnerFrame {
        payload: Some(fixture_wire::runner_frame::Payload::LeaseRequest(
            fixture_wire::LeaseRequest {
                header: Some(header),
                slot: 1,
                acknowledges_operation_id: Some(operation_id),
                authority_contributions: Some(wire_empty_authority_contributions()),
            },
        )),
    };
    assert!(matches!(
        decode_runner_frame(&encode(&frame), &ProtocolLimits::default()),
        Err(DecodeError::InvalidMessage(
            MessageValidationError::LeaseRequestSelfAcknowledgement { .. }
        ))
    ));
}

#[test]
fn unknown_and_zero_required_enums_are_typed_errors() {
    for lifecycle in [0, 777] {
        let frame = fixture_wire::RunnerFrame {
            payload: Some(fixture_wire::runner_frame::Payload::Heartbeat(
                fixture_wire::LeaseHeartbeat {
                    header: Some(wire_header(false)),
                    attempt_id: Uuid::from_u128(5).as_bytes().to_vec(),
                    guard: Some(wire_guard()),
                    lifecycle,
                    sent_at_unix_millis: 10,
                },
            )),
        };
        assert!(matches!(
            decode_runner_frame(&encode(&frame), &ProtocolLimits::default()),
            Err(DecodeError::UnknownEnum {
                field: "lease_heartbeat.lifecycle",
                value
            }) if value == lifecycle
        ));
    }

    for endpoint_security in [0, 777] {
        let mut frame = fixture_runtime_authority_grant();
        let Some(fixture_wire::server_frame::Payload::RuntimeAuthorityGrant(grant)) =
            frame.payload.as_mut()
        else {
            panic!("runtime-authority grant fixture shape");
        };
        grant
            .authorities
            .as_mut()
            .expect("runtime authorities")
            .authorities
            .first_mut()
            .expect("runtime authority")
            .endpoint_security = endpoint_security;
        assert!(matches!(
            decode_server_frame(&encode(&frame), &ProtocolLimits::default()),
            Err(DecodeError::UnknownEnum {
                field: "runtime_authority.endpoint_security",
                value
            }) if value == endpoint_security
        ));
    }
}

#[test]
fn classified_job_result_outputs_reject_plaintext_and_wire_tampering() {
    let mut baseline = fixture_job_result();
    assert_eq!(
        job_result_payload(&mut baseline).secret_exposure,
        fixture_wire::JobSecretExposure::Secretless as i32
    );
    let outputs = &job_result_payload(&mut baseline).outputs;
    let public = outputs
        .iter()
        .find(|entry| entry.key == "artifact-digest")
        .and_then(|entry| entry.value.as_ref())
        .expect("public output");
    assert_eq!(
        public.sensitivity,
        fixture_wire::OutputSensitivity::Public as i32
    );
    assert_eq!(public.value.as_deref(), Some("abc123"));
    let secret = outputs
        .iter()
        .find(|entry| entry.key == "receipt")
        .and_then(|entry| entry.value.as_ref())
        .expect("secret-derived output");
    assert_eq!(
        secret.sensitivity,
        fixture_wire::OutputSensitivity::SecretDerived as i32
    );
    assert_eq!(secret.value, None);

    let sensitive_text = "must-never-enter-the-domain-result";
    let mut secret_with_plaintext = fixture_job_result();
    job_result_payload(&mut secret_with_plaintext)
        .outputs
        .iter_mut()
        .find(|entry| entry.key == "receipt")
        .and_then(|entry| entry.value.as_mut())
        .expect("secret-derived output")
        .value = Some(sensitive_text.to_owned());
    let error = decode_runner_frame(&encode(&secret_with_plaintext), &ProtocolLimits::default())
        .expect_err("secret-derived plaintext must fail closed");
    assert!(matches!(
        &error,
        DecodeError::InvalidValue {
            field: "job_result_output.value"
        }
    ));
    assert!(!error.to_string().contains(sensitive_text));

    let mut missing_public = fixture_job_result();
    job_result_payload(&mut missing_public)
        .outputs
        .iter_mut()
        .find(|entry| entry.key == "artifact-digest")
        .and_then(|entry| entry.value.as_mut())
        .expect("public output")
        .value = None;
    assert!(matches!(
        decode_runner_frame(&encode(&missing_public), &ProtocolLimits::default()),
        Err(DecodeError::MissingField {
            field: "job_result_output.value"
        })
    ));

    assert_unclassified_job_result_fields_fail_closed();
    assert_readable_secret_result_accepts_classified_public_output();
}

fn assert_unclassified_job_result_fields_fail_closed() {
    for sensitivity in [
        fixture_wire::OutputSensitivity::Unspecified as i32,
        i32::MAX,
    ] {
        let mut unclassified = fixture_job_result();
        job_result_payload(&mut unclassified).outputs[0]
            .value
            .as_mut()
            .expect("output")
            .sensitivity = sensitivity;
        assert!(matches!(
            decode_runner_frame(&encode(&unclassified), &ProtocolLimits::default()),
            Err(DecodeError::UnknownEnum {
                field: "job_result_output.sensitivity",
                value,
            }) if value == sensitivity
        ));
    }

    let mut absent_entry = fixture_job_result();
    job_result_payload(&mut absent_entry).outputs[0].value = None;
    assert!(matches!(
        decode_runner_frame(&encode(&absent_entry), &ProtocolLimits::default()),
        Err(DecodeError::MissingField {
            field: "job_result_output_entry.value"
        })
    ));

    for exposure in [
        fixture_wire::JobSecretExposure::Unspecified as i32,
        i32::MAX,
    ] {
        let mut unclassified = fixture_job_result();
        job_result_payload(&mut unclassified).secret_exposure = exposure;
        assert!(matches!(
            decode_runner_frame(&encode(&unclassified), &ProtocolLimits::default()),
            Err(DecodeError::UnknownEnum {
                field: "job_result.secret_exposure",
                value,
            }) if value == exposure
        ));
    }
}

fn assert_readable_secret_result_accepts_classified_public_output() {
    let mut readable_with_public = fixture_job_result();
    job_result_payload(&mut readable_with_public).secret_exposure =
        fixture_wire::JobSecretExposure::ReadableSecret as i32;
    decode_runner_frame(&encode(&readable_with_public), &ProtocolLimits::default())
        .expect("job exposure does not override value-level output sensitivity");
}

#[test]
fn canonical_maps_reject_duplicates_and_descending_keys() {
    for (keys, duplicate) in [(["alpha", "alpha"], true), (["zulu", "alpha"], false)] {
        let frame = fixture_wire::ServerFrame {
            payload: Some(fixture_wire::server_frame::Payload::Error(
                fixture_wire::ErrorMessage {
                    header: Some(wire_header(true)),
                    code: fixture_wire::RemoteErrorCode::RetryLater as i32,
                    message: "retry".to_owned(),
                    retryable: true,
                    details: keys
                        .into_iter()
                        .map(|key| fixture_wire::StringEntry {
                            key: key.to_owned(),
                            value: "value".to_owned(),
                        })
                        .collect(),
                },
            )),
        };
        let result = decode_server_frame(&encode(&frame), &ProtocolLimits::default());
        if duplicate {
            assert!(matches!(
                result,
                Err(DecodeError::DuplicateEntry {
                    field: "error_message.details"
                })
            ));
        } else {
            assert!(matches!(
                result,
                Err(DecodeError::NonCanonicalOrder {
                    field: "error_message.details"
                })
            ));
        }
    }
}

#[test]
fn canonical_sets_reject_duplicates_ordering_and_normalization_aliases() {
    let cases = [
        (vec!["linux", "linux"], "duplicate"),
        (vec!["x64", "linux"], "order"),
        (vec!["Linux", "self-hosted"], "normalization"),
    ];
    for (labels, expected) in cases {
        let mut frame = fixture_runner_hello();
        let Some(fixture_wire::runner_frame::Payload::Hello(hello)) = frame.payload.as_mut() else {
            panic!("runner hello fixture shape");
        };
        hello.runner.as_mut().expect("runner capabilities").labels =
            labels.into_iter().map(str::to_owned).collect();
        let result = decode_runner_frame(&encode(&frame), &ProtocolLimits::default());
        match expected {
            "duplicate" => assert!(matches!(
                result,
                Err(DecodeError::DuplicateEntry {
                    field: "runner_capabilities.labels"
                })
            )),
            "order" => assert!(matches!(
                result,
                Err(DecodeError::NonCanonicalOrder {
                    field: "runner_capabilities.labels"
                })
            )),
            "normalization" => assert!(matches!(
                result,
                Err(DecodeError::NonCanonicalValue {
                    field: "runner_capabilities.labels"
                })
            )),
            _ => unreachable!("closed fixture cases"),
        }
    }
}

#[test]
fn environment_profiles_require_canonical_exact_attestations() {
    let mut duplicate = fixture_runner_hello();
    let Some(fixture_wire::runner_frame::Payload::Hello(hello)) = duplicate.payload.as_mut() else {
        panic!("runner hello fixture shape");
    };
    let profiles = &mut hello
        .runner
        .as_mut()
        .expect("runner capabilities")
        .environment_profiles;
    profiles.push(profiles[0].clone());
    assert!(matches!(
        decode_runner_frame(&encode(&duplicate), &ProtocolLimits::default()),
        Err(DecodeError::DuplicateEntry {
            field: "runner_capabilities.environment_profiles"
        })
    ));

    let mut descending = fixture_runner_hello();
    let Some(fixture_wire::runner_frame::Payload::Hello(hello)) = descending.payload.as_mut()
    else {
        panic!("runner hello fixture shape");
    };
    hello
        .runner
        .as_mut()
        .expect("runner capabilities")
        .environment_profiles
        .push(fixture_wire::EnvironmentProfile {
            id: "example.com/earlier".to_owned(),
            sha256_digest: vec![0x11; 32],
        });
    assert!(matches!(
        decode_runner_frame(&encode(&descending), &ProtocolLimits::default()),
        Err(DecodeError::NonCanonicalOrder {
            field: "runner_capabilities.environment_profiles"
        })
    ));

    let mut malformed = fixture_runner_hello();
    let Some(fixture_wire::runner_frame::Payload::Hello(hello)) = malformed.payload.as_mut() else {
        panic!("runner hello fixture shape");
    };
    hello
        .runner
        .as_mut()
        .expect("runner capabilities")
        .environment_profiles[0]
        .sha256_digest = vec![0x11; 31];
    assert!(matches!(
        decode_runner_frame(&encode(&malformed), &ProtocolLimits::default()),
        Err(DecodeError::InvalidValue {
            field: "environment_profile.sha256_digest"
        })
    ));
}

#[test]
fn required_environment_profile_digest_is_validated_at_the_job_boundary() {
    let mut frame = fixture_lease_offer();
    let Some(fixture_wire::server_frame::Payload::LeaseOffer(offer)) = frame.payload.as_mut()
    else {
        panic!("lease offer fixture shape");
    };
    offer
        .job
        .as_mut()
        .expect("job envelope")
        .job
        .as_mut()
        .expect("job")
        .requirements
        .as_mut()
        .expect("requirements")
        .environment_profile
        .as_mut()
        .expect("required profile")
        .sha256_digest = vec![0x44; 33];
    assert!(matches!(
        decode_server_frame(&encode(&frame), &ProtocolLimits::default()),
        Err(DecodeError::InvalidValue {
            field: "environment_profile.sha256_digest"
        })
    ));
}

#[test]
fn resource_allocation_requires_exact_placement_request_evidence() {
    let mut frame = fixture_lease_offer();
    attach_valid_resource_allocation(&mut frame);
    runner_requirements(&mut frame)
        .minimum_resources
        .as_mut()
        .expect("minimum resources")
        .cpu_millis += 1;

    assert!(matches!(
        decode_server_frame(&encode(&frame), &ProtocolLimits::default()),
        Err(DecodeError::InvalidValue {
            field: "runner_requirements.minimum_resources"
        })
    ));
}

#[test]
fn resource_allocation_rejects_one_limit_below_its_request() {
    let mut frame = fixture_lease_offer();
    attach_valid_resource_allocation(&mut frame);
    let allocation = runner_requirements(&mut frame)
        .resource_allocation
        .as_mut()
        .expect("resource allocation");
    let requested_cpu = allocation.requests.as_ref().expect("requests").cpu_millis;
    allocation.limits.as_mut().expect("limits").cpu_millis = requested_cpu - 1;

    assert!(matches!(
        decode_server_frame(&encode(&frame), &ProtocolLimits::default()),
        Err(DecodeError::InvalidValue {
            field: "job_resource_allocation"
        })
    ));
}

#[test]
fn managed_secret_overlay_rejects_a_lease_attempt_mismatch_with_a_valid_digest() {
    let mut frame = fixture_lease_offer_with_managed_overlay();
    let template = common::lease_offer_with_job(common::rich_job());
    let original_lease = template.lease();
    let changed_lease = Lease::new(
        original_lease.lease_id(),
        AttemptId::new(),
        original_lease.runner_id(),
        original_lease.fencing_token(),
        original_lease.issued_at(),
        original_lease.expires_at(),
    )
    .expect("changed attempt lease");
    let job = template.job().clone();
    let changed_offer = LeaseOffer::new(
        template.header(),
        template.slot(),
        changed_lease.clone(),
        job,
    )
    .with_managed_secret_bindings(common::managed_secret_overlay(&changed_lease))
    .expect("internally valid changed-attempt overlay");
    let encoded = encode_server_frame(
        &ServerToRunner::LeaseOffer(Box::new(changed_offer)),
        &ProtocolLimits::default(),
    )
    .expect("encode changed-attempt fixture");
    let mut changed_frame = fixture_wire::ServerFrame::decode(encoded.as_slice())
        .expect("decode changed-attempt fixture");
    let changed_overlay = lease_offer_payload(&mut changed_frame)
        .managed_secret_bindings
        .take()
        .expect("managed-secret overlay");
    lease_offer_payload(&mut frame).managed_secret_bindings = Some(changed_overlay);

    assert!(matches!(
        decode_server_frame(&encode(&frame), &ProtocolLimits::default()),
        Err(DecodeError::InvalidValue {
            field: "managed_secret_binding_overlay.lease_binding"
        })
    ));
}

#[test]
fn managed_secret_overlay_rejects_noncanonical_order_with_a_matching_digest() {
    let mut frame = fixture_lease_offer_with_managed_overlay();
    let overlay = lease_offer_payload(&mut frame)
        .managed_secret_bindings
        .as_mut()
        .expect("managed-secret overlay");
    assert_eq!(
        overlay.sha256_digest,
        managed_secret_overlay_digest(overlay),
        "the test digest helper must reproduce a canonical production digest"
    );
    overlay.bindings.reverse();
    overlay.sha256_digest = managed_secret_overlay_digest(overlay);

    assert!(matches!(
        decode_server_frame(&encode(&frame), &ProtocolLimits::default()),
        Err(DecodeError::NonCanonicalOrder {
            field: "managed_secret_binding_overlay.bindings"
        })
    ));
}

#[test]
fn managed_secret_overlay_rejects_digest_substitution() {
    let mut frame = fixture_lease_offer_with_managed_overlay();
    lease_offer_payload(&mut frame)
        .managed_secret_bindings
        .as_mut()
        .expect("managed-secret overlay")
        .sha256_digest = vec![0x5a; 32];

    assert!(matches!(
        decode_server_frame(&encode(&frame), &ProtocolLimits::default()),
        Err(DecodeError::InvalidValue {
            field: "managed_secret_binding_overlay.sha256_digest"
        })
    ));
}

#[test]
fn nested_collection_and_log_payload_limits_apply_before_domain_allocation() {
    let hello = fixture_runner_hello();
    let collection_limits =
        ProtocolLimits::new(1024 * 1024, 2, 4096, 2, 4096).expect("coherent limits");
    assert!(matches!(
        decode_runner_frame(&encode(&hello), &collection_limits),
        Err(DecodeError::CollectionTooLarge {
            field: "runner_capabilities.labels",
            length: 3,
            maximum: 2
        })
    ));

    let log_message = common::runner_messages()
        .into_iter()
        .find_map(|(name, message)| (name == "log_batch").then_some(message))
        .expect("log fixture");
    let encoded =
        encode_runner_frame(&log_message, &ProtocolLimits::default()).expect("encode log fixture");
    let log_limits = ProtocolLimits::new(1024 * 1024, 32, 4096, 16, 1).expect("coherent limits");
    assert!(matches!(
        decode_runner_frame(&encoded, &log_limits),
        Err(DecodeError::LogPayloadTooLarge {
            size: 10,
            maximum: 1
        })
    ));
}

#[test]
fn future_unknown_optional_fields_are_ignored() {
    let message = common::runner_messages()
        .into_iter()
        .find_map(|(name, message)| (name == "lease_request").then_some(message))
        .expect("lease request fixture");
    let mut encoded =
        encode_runner_frame(&message, &ProtocolLimits::default()).expect("encode fixture");
    encoded.extend_from_slice(&[0xa0, 0x06, 0x01]);
    let decoded = decode_runner_frame(&encoded, &ProtocolLimits::default())
        .expect("unknown protobuf field must be ignored");
    assert_eq!(decoded.into_message(), message);
}

#[test]
fn only_the_current_protocol_is_accepted() {
    let current = fixture_wire::RunnerFrame {
        payload: Some(fixture_wire::runner_frame::Payload::LeaseRequest(
            fixture_wire::LeaseRequest {
                header: Some(wire_header(false)),
                slot: 1,
                acknowledges_operation_id: None,
                authority_contributions: Some(wire_empty_authority_contributions()),
            },
        )),
    };
    decode_runner_frame(&encode(&current), &ProtocolLimits::default()).expect("current protocol");

    let mut zero = current.clone();
    let Some(fixture_wire::runner_frame::Payload::LeaseRequest(request)) = zero.payload.as_mut()
    else {
        panic!("lease request fixture shape");
    };
    request.header.as_mut().expect("header").protocol_version -= 1;
    assert!(decode_runner_frame(&encode(&zero), &ProtocolLimits::default()).is_err());

    let mut future = current;
    let Some(fixture_wire::runner_frame::Payload::LeaseRequest(request)) = future.payload.as_mut()
    else {
        panic!("lease request fixture shape");
    };
    request.header.as_mut().expect("header").protocol_version += 1;
    assert!(matches!(
        decode_runner_frame(&encode(&future), &ProtocolLimits::default()),
        Err(DecodeError::InvalidMessage(_))
    ));
}

#[test]
fn message_job_ir_and_requirements_schema_skew_are_rejected_without_reconstruction() {
    let mut request = fixture_wire::RunnerFrame {
        payload: Some(fixture_wire::runner_frame::Payload::LeaseRequest(
            fixture_wire::LeaseRequest {
                header: Some(wire_header(false)),
                slot: 1,
                acknowledges_operation_id: None,
                authority_contributions: Some(wire_empty_authority_contributions()),
            },
        )),
    };
    let Some(fixture_wire::runner_frame::Payload::LeaseRequest(payload)) = request.payload.as_mut()
    else {
        panic!("lease request fixture shape");
    };
    payload
        .header
        .as_mut()
        .expect("header")
        .message_schema_version += 1;
    assert!(matches!(
        decode_runner_frame(&encode(&request), &ProtocolLimits::default()),
        Err(DecodeError::UnsupportedSchema {
            field: "message_header.message_schema_version",
            ..
        })
    ));

    let mut offer = fixture_lease_offer();
    let Some(fixture_wire::server_frame::Payload::LeaseOffer(payload)) = offer.payload.as_mut()
    else {
        panic!("lease offer fixture shape");
    };
    payload.job.as_mut().expect("JobIR envelope").schema_version =
        u32::from(JobIrVersion::current().get()) + 1;
    assert!(matches!(
        decode_server_frame(&encode(&offer), &ProtocolLimits::default()),
        Err(DecodeError::UnsupportedSchema {
            field: "job_ir_envelope.schema_version",
            ..
        })
    ));

    let mut noncurrent_requirements = fixture_lease_offer();
    let Some(fixture_wire::server_frame::Payload::LeaseOffer(payload)) =
        noncurrent_requirements.payload.as_mut()
    else {
        panic!("lease offer fixture shape");
    };
    payload
        .job
        .as_mut()
        .expect("JobIR envelope")
        .job
        .as_mut()
        .expect("job")
        .requirements
        .as_mut()
        .expect("runner requirements")
        .schema_version = 2;
    assert!(matches!(
        decode_server_frame(&encode(&noncurrent_requirements), &ProtocolLimits::default()),
        Err(DecodeError::UnsupportedSchema {
            field: "runner_requirements.schema_version",
            supported,
            received: 2,
        }) if supported == u32::from(RUNNER_REQUIREMENTS_SCHEMA_VERSION)
    ));
}

#[test]
fn encoding_applies_domain_validation_and_size_budget() {
    let invalid = RunnerToServer::CommandAck(CommandAck::new(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            RunnerSessionId::from_uuid(Uuid::from_u128(10)),
            OperationId::from_uuid(Uuid::from_u128(11)),
        ),
        CommandCursor::initial(),
    ));
    assert!(matches!(
        encode_runner_frame(&invalid, &ProtocolLimits::default()),
        Err(EncodeError::InvalidMessage(_))
    ));

    let valid = RunnerToServer::LeaseRequest(LeaseRequest::first(
        common::request_header(90),
        common::slot(),
        LeaseAuthorityPollContributions::default(),
    ));
    let tiny = ProtocolLimits::new(1, 1, 1, 1, 1).expect("coherent tiny limits");
    assert!(matches!(
        encode_runner_frame(&valid, &tiny),
        Err(EncodeError::FrameTooLarge { maximum: 1, .. })
    ));
}

#[test]
fn public_error_types_are_thread_safe_and_have_sanitized_displays() {
    assert_impl_all!(DecodeError: Send, Sync);
    assert_impl_all!(EncodeError: Send, Sync);
}
