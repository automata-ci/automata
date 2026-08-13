use automata_ci_core::{
    AttemptId, LogAck, LogChannel, LogFrame, LogSequence, LogStreamId, LogValidationError,
    UnixMillis,
};

#[test]
fn log_frame_and_ack_schemas_reject_noncurrent_versions() {
    let stream = LogStreamId::new();
    let frame = LogFrame::new(
        stream,
        AttemptId::new(),
        LogSequence::new(0),
        UnixMillis::new(1),
        LogChannel::Stdout,
        b"log".to_vec(),
        false,
    )
    .expect("frame");
    let mut encoded_frame = serde_json::to_value(frame).expect("serialize frame");
    encoded_frame["schema_version"] = serde_json::json!(u16::MAX);
    let decoded_frame: LogFrame =
        serde_json::from_value(encoded_frame).expect("decode structurally valid frame");
    assert_eq!(
        decoded_frame.validate(),
        Err(LogValidationError::UnsupportedSchema {
            supported: 1,
            received: u16::MAX,
        })
    );

    let mut encoded_ack = serde_json::to_value(LogAck::new(stream, None)).expect("serialize ack");
    encoded_ack["schema_version"] = serde_json::json!(u16::MAX);
    let decoded_ack: LogAck =
        serde_json::from_value(encoded_ack).expect("decode structurally valid ack");
    assert_eq!(
        decoded_ack.validate(),
        Err(LogValidationError::UnsupportedSchema {
            supported: 1,
            received: u16::MAX,
        })
    );
}

#[test]
fn ack_is_exclusive_at_zero_and_advances_contiguously() {
    let stream = LogStreamId::new();
    assert_eq!(
        LogAck::new(stream, None).next_expected(),
        Ok(LogSequence::new(0)),
    );
    assert_eq!(
        LogAck::new(stream, Some(LogSequence::new(41))).next_expected(),
        Ok(LogSequence::new(42)),
    );
}

#[test]
fn log_frame_json_round_trip_preserves_arbitrary_bytes() {
    let frame = LogFrame::new(
        LogStreamId::new(),
        AttemptId::new(),
        LogSequence::new(0),
        UnixMillis::new(10),
        LogChannel::Stdout,
        vec![0, 0xff, b'\n'],
        false,
    )
    .expect("valid frame");
    let json = serde_json::to_string(&frame).expect("serialize frame");
    assert_eq!(
        serde_json::from_str::<LogFrame>(&json).expect("deserialize frame"),
        frame,
    );
}
