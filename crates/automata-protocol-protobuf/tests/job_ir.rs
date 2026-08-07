mod common;

use std::fmt::Write as _;

use automata_protocol::ProtocolLimits;
use automata_protocol_protobuf::{DecodeError, decode_job_ir, encode_job_ir};
use prost::Message as _;
use sha2::{Digest as _, Sha256};

const JOB_IR_GOLDEN: &str = include_str!("fixtures/job-ir-v4.sha256");

#[allow(clippy::all, clippy::pedantic, dead_code)]
mod fixture_wire {
    include!("../src/generated/automata.runner.v1.rs");
}

fn sha256(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(output, "{byte:02x}").expect("writing to a String is infallible");
    }
    output
}

#[test]
fn standalone_job_ir_v4_is_deterministic_and_round_trips() {
    let envelope = common::rich_job();
    let limits = ProtocolLimits::default();
    let first = encode_job_ir(&envelope, &limits).expect("encode JobIR");
    let second = encode_job_ir(&envelope, &limits).expect("encode JobIR again");
    assert_eq!(first, second);
    assert_eq!(
        decode_job_ir(&first, &limits).expect("decode JobIR"),
        envelope
    );
}

#[test]
fn standalone_job_ir_v4_matches_exact_wire_digest() {
    let encoded = encode_job_ir(&common::rich_job(), &ProtocolLimits::default())
        .expect("encode golden JobIR");
    assert_eq!(
        format!("{}  job-ir-v4.pb\n", sha256(&encoded)),
        JOB_IR_GOLDEN
    );
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
fn standalone_v4_decode_requires_execution_context_and_event_descriptor() {
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
}
