mod common;

use automata_ci_protocol::ProtocolLimits;
use automata_ci_protocol_protobuf::{DecodeError, decode_job_ir, encode_job_ir};
use prost::Message as _;

#[allow(clippy::all, clippy::pedantic, dead_code)]
mod fixture_wire {
    include!("../src/generated/automata.runner.v1.rs");
}

#[test]
fn standalone_decode_is_size_first() {
    let limits = ProtocolLimits::new(128, 8, 64, 4, 64).expect("coherent limits");
    assert!(matches!(
        decode_job_ir(&[], &limits),
        Err(DecodeError::EmptyFrame)
    ));
    assert!(matches!(
        decode_job_ir(&[0xff; 129], &limits),
        Err(DecodeError::FrameTooLarge {
            size: 129,
            maximum: 128
        })
    ));
    assert!(matches!(
        decode_job_ir(&[0xff], &limits),
        Err(DecodeError::MalformedProtobuf(_))
    ));
}

#[test]
fn standalone_decode_requires_current_execution_content_descriptors() {
    let encoded =
        encode_job_ir(&common::rich_job(), &ProtocolLimits::default()).expect("encode JobIR");
    let mut wire = fixture_wire::JobIrEnvelope::decode(encoded.as_slice()).expect("wire JobIR");
    wire.execution = None;
    assert!(matches!(
        decode_job_ir(&wire.encode_to_vec(), &ProtocolLimits::default()),
        Err(DecodeError::MissingField {
            field: "job_ir_envelope.execution"
        })
    ));

    let mut wire = fixture_wire::JobIrEnvelope::decode(encoded.as_slice()).expect("wire JobIR");
    wire.execution.as_mut().expect("execution").event = None;
    assert!(matches!(
        decode_job_ir(&wire.encode_to_vec(), &ProtocolLimits::default()),
        Err(DecodeError::MissingField {
            field: "job_execution_context.event"
        })
    ));

    let mut wire = fixture_wire::JobIrEnvelope::decode(encoded.as_slice()).expect("wire JobIR");
    wire.execution.as_mut().expect("execution").runtime_context = None;
    assert!(matches!(
        decode_job_ir(&wire.encode_to_vec(), &ProtocolLimits::default()),
        Err(DecodeError::MissingField {
            field: "job_execution_context.runtime_context"
        })
    ));
}
