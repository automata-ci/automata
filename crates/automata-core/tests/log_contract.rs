use automata_core::{
    AttemptId, LogAck, LogChannel, LogFrame, LogSequence, LogStreamId, UnixMillis,
};

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
