mod common;

use automata_core::{OperationId, RUNNER_REQUIREMENTS_SCHEMA_VERSION, RunnerSessionId};
use automata_protocol::{
    CommandAck, CommandCursor, LeaseRequest, MessageHeader, MessageValidationError, ProtocolLimits,
    RunnerToServer, SUPPORTED_PROTOCOL_RANGE,
};
use automata_protocol_protobuf::{
    DecodeError, EncodeError, decode_job_ir, decode_runner_frame, decode_server_frame,
    encode_job_ir, encode_runner_frame, encode_server_frame,
};
use prost::Message as _;
use static_assertions::assert_impl_all;
use uuid::Uuid;

#[allow(clippy::all, clippy::pedantic, dead_code)]
mod fixture_wire {
    include!("../src/generated/automata.runner.v1.rs");
}

fn wire_header(reply: bool) -> fixture_wire::MessageHeader {
    fixture_wire::MessageHeader {
        message_schema_version: u32::from(automata_protocol::MESSAGE_SCHEMA_VERSION),
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

fn fixture_runner_hello() -> fixture_wire::RunnerFrame {
    let message = common::runner_messages()
        .into_iter()
        .find_map(|(name, message)| (name == "hello").then_some(message))
        .expect("runner hello fixture");
    let encoded =
        encode_runner_frame(&message, &ProtocolLimits::default()).expect("encode fixture");
    fixture_wire::RunnerFrame::decode(encoded.as_slice()).expect("decode private test DTO")
}

fn fixture_job_ir() -> fixture_wire::JobIrEnvelope {
    let encoded = encode_job_ir(&common::rich_job(), &ProtocolLimits::default())
        .expect("encode JobIR fixture");
    fixture_wire::JobIrEnvelope::decode(encoded.as_slice()).expect("decode private test DTO")
}

#[test]
fn standalone_job_ir_rejects_schema_and_expression_program_skew() {
    let mut future_job = fixture_job_ir();
    future_job.schema_version += 1;
    assert!(matches!(
        decode_job_ir(&encode(&future_job), &ProtocolLimits::default()),
        Err(DecodeError::UnsupportedSchema {
            field: "job_ir_envelope.schema_version",
            ..
        })
    ));

    let mut future_expression = fixture_job_ir();
    future_expression
        .job
        .as_mut()
        .expect("job")
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
fn standalone_job_ir_rejects_malformed_expression_programs() {
    let mut missing_instruction = fixture_job_ir();
    missing_instruction
        .job
        .as_mut()
        .expect("job")
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
        .condition
        .as_mut()
        .expect("condition");
    let Some(fixture_wire::expression_instruction::Value::Logical(logical)) = condition
        .instructions
        .last_mut()
        .and_then(|instruction| instruction.value.as_mut())
    else {
        panic!("logical instruction fixture");
    };
    logical.operator = 777;
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
        .condition
        .as_mut()
        .expect("condition");
    condition.instructions = (0..=automata_core::MAX_EXPRESSION_INSTRUCTIONS)
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
            maximum: automata_core::MAX_EXPRESSION_INSTRUCTIONS,
        }) if length == automata_core::MAX_EXPRESSION_INSTRUCTIONS + 1
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
            },
        )),
    };
    assert!(matches!(
        decode_runner_frame(&encode(&frame), &ProtocolLimits::default()),
        Err(DecodeError::MissingField {
            field: "lease_request.header"
        })
    ));

    let mut frame = fixture_lease_offer();
    let Some(fixture_wire::server_frame::Payload::LeaseOffer(offer)) = frame.payload.as_mut()
    else {
        panic!("lease offer fixture shape");
    };
    offer.runtime_authorities = None;
    assert!(matches!(
        decode_server_frame(&encode(&frame), &ProtocolLimits::default()),
        Err(DecodeError::MissingField {
            field: "lease_offer.runtime_authorities"
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
        let mut frame = fixture_lease_offer();
        let Some(fixture_wire::server_frame::Payload::LeaseOffer(offer)) = frame.payload.as_mut()
        else {
            panic!("lease offer fixture shape");
        };
        offer
            .runtime_authorities
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
fn only_current_protocol_v4_is_accepted() {
    let current = fixture_wire::RunnerFrame {
        payload: Some(fixture_wire::runner_frame::Payload::LeaseRequest(
            fixture_wire::LeaseRequest {
                header: Some(wire_header(false)),
                slot: 1,
                acknowledges_operation_id: None,
            },
        )),
    };
    decode_runner_frame(&encode(&current), &ProtocolLimits::default())
        .expect("current protocol v4");

    let mut legacy = current.clone();
    let Some(fixture_wire::runner_frame::Payload::LeaseRequest(request)) = legacy.payload.as_mut()
    else {
        panic!("lease request fixture shape");
    };
    request.header.as_mut().expect("header").protocol_version -= 1;
    assert!(matches!(
        decode_runner_frame(&encode(&legacy), &ProtocolLimits::default()),
        Err(DecodeError::InvalidMessage(_))
    ));

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
    payload.job.as_mut().expect("JobIR envelope").schema_version += 1;
    assert!(matches!(
        decode_server_frame(&encode(&offer), &ProtocolLimits::default()),
        Err(DecodeError::UnsupportedSchema {
            field: "job_ir_envelope.schema_version",
            ..
        })
    ));

    let mut legacy_requirements = fixture_lease_offer();
    let Some(fixture_wire::server_frame::Payload::LeaseOffer(payload)) =
        legacy_requirements.payload.as_mut()
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
        .schema_version = 1;
    assert!(matches!(
        decode_server_frame(&encode(&legacy_requirements), &ProtocolLimits::default()),
        Err(DecodeError::UnsupportedSchema {
            field: "runner_requirements.schema_version",
            supported,
            received: 1,
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
