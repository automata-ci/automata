use automata_ci_core::{
    AttemptId, LOG_SCHEMA_VERSION, LogAck, LogChannel, LogFrame, LogGroup, LogGroupId,
    LogGroupKind, LogSequence, LogStreamId, LogValidationError, UnixMillis,
};

#[test]
fn log_frame_and_ack_schemas_reject_noncurrent_versions() {
    let stream = LogStreamId::new();
    let frame = LogFrame::output(
        stream,
        AttemptId::new(),
        LogSequence::new(0),
        UnixMillis::new(1),
        LogGroupId::new("test").expect("group ID"),
        LogChannel::Stdout,
        b"log".to_vec(),
    )
    .expect("frame");
    let mut encoded_frame = serde_json::to_value(frame).expect("serialize frame");
    encoded_frame["schema_version"] = serde_json::json!(u16::MAX);
    let decoded_frame: LogFrame =
        serde_json::from_value(encoded_frame).expect("decode structurally valid frame");
    assert_eq!(
        decoded_frame.validate(),
        Err(LogValidationError::UnsupportedSchema {
            supported: LOG_SCHEMA_VERSION,
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
            supported: LOG_SCHEMA_VERSION,
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
    let frame = LogFrame::output(
        LogStreamId::new(),
        AttemptId::new(),
        LogSequence::new(0),
        UnixMillis::new(10),
        LogGroupId::new("test").expect("group ID"),
        LogChannel::Stdout,
        vec![0, 0xff, b'\n'],
    )
    .expect("valid frame");
    let json = serde_json::to_string(&frame).expect("serialize frame");
    assert_eq!(
        serde_json::from_str::<LogFrame>(&json).expect("deserialize frame"),
        frame,
    );
}

#[test]
fn deserialized_group_metadata_is_validated_at_the_frame_boundary() {
    let frame = LogFrame::group_started(
        LogStreamId::new(),
        AttemptId::new(),
        LogSequence::new(0),
        UnixMillis::new(10),
        LogGroup::new(
            LogGroupId::new("step/build").expect("group ID"),
            None,
            "Build",
            LogGroupKind::Step,
            1,
        )
        .expect("group"),
    )
    .expect("frame");
    let mut encoded = serde_json::to_value(frame).expect("serialize frame");
    encoded["record"]["group"]["name"] = serde_json::json!("\n");

    let decoded: LogFrame = serde_json::from_value(encoded).expect("decode wire-shaped frame");

    assert_eq!(decoded.validate(), Err(LogValidationError::EmptyGroupName),);
}

#[test]
fn log_group_names_reject_control_and_directional_formatting() {
    for name in ["Build\tstep", "Build\u{202e}step"] {
        assert_eq!(
            LogGroup::new(
                LogGroupId::new("step/build").expect("group ID"),
                None,
                name,
                LogGroupKind::Step,
                1,
            ),
            Err(LogValidationError::InvalidGroupName),
        );
    }
}
