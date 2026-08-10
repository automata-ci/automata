use automata_ci_core::{AttemptId, LeaseGuard, LogFrame, LogStreamId};
use automata_ci_protocol::{NegotiatedSession, ProtocolLimits, RunnerToServer};
use automata_ci_runner_journal::LogSegment;
use automata_ci_runner_transport::PreparedRequest;

use crate::RunnerRuntimeError;

const LENGTH_PREFIX_BYTES: usize = 4;

pub(crate) fn append_record(existing: &[u8], record: &[u8]) -> Result<Vec<u8>, RunnerRuntimeError> {
    let capacity = existing
        .len()
        .checked_add(LENGTH_PREFIX_BYTES)
        .and_then(|value| value.checked_add(record.len()))
        .ok_or(RunnerRuntimeError::InvalidDurablePayload)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| RunnerRuntimeError::InvalidDurablePayload)?;
    output.extend_from_slice(existing);
    append_record_in_place(&mut output, record)?;
    Ok(output)
}

pub(crate) fn append_record_in_place(
    output: &mut Vec<u8>,
    record: &[u8],
) -> Result<(), RunnerRuntimeError> {
    let record_len =
        u32::try_from(record.len()).map_err(|_| RunnerRuntimeError::InvalidDurablePayload)?;
    let additional = LENGTH_PREFIX_BYTES
        .checked_add(record.len())
        .ok_or(RunnerRuntimeError::InvalidDurablePayload)?;
    output
        .len()
        .checked_add(additional)
        .ok_or(RunnerRuntimeError::InvalidDurablePayload)?;
    output
        .try_reserve(additional)
        .map_err(|_| RunnerRuntimeError::InvalidDurablePayload)?;
    output.extend_from_slice(&record_len.to_be_bytes());
    output.extend_from_slice(record);
    Ok(())
}

pub(crate) struct DecodedRecord {
    pub(crate) message: RunnerToServer,
    pub(crate) canonical_bytes: Vec<u8>,
}

pub(crate) fn decode_records(
    encoded: &[u8],
    limits: &ProtocolLimits,
) -> Result<Vec<DecodedRecord>, RunnerRuntimeError> {
    let mut messages = Vec::new();
    let mut remaining = encoded;
    while !remaining.is_empty() {
        let prefix = remaining
            .get(..LENGTH_PREFIX_BYTES)
            .ok_or(RunnerRuntimeError::InvalidDurablePayload)?;
        let length = usize::try_from(u32::from_be_bytes(
            prefix
                .try_into()
                .map_err(|_| RunnerRuntimeError::InvalidDurablePayload)?,
        ))
        .map_err(|_| RunnerRuntimeError::InvalidDurablePayload)?;
        if length == 0 || length > limits.max_frame_bytes() {
            return Err(RunnerRuntimeError::InvalidDurablePayload);
        }
        remaining = remaining
            .get(LENGTH_PREFIX_BYTES..)
            .ok_or(RunnerRuntimeError::InvalidDurablePayload)?;
        let record = remaining
            .get(..length)
            .ok_or(RunnerRuntimeError::InvalidDurablePayload)?;
        let decoded = automata_ci_protocol_protobuf::decode_runner_frame(record, limits)
            .map_err(|_| RunnerRuntimeError::InvalidDurablePayload)?;
        messages.push(DecodedRecord {
            message: decoded.into_message(),
            canonical_bytes: record.to_vec(),
        });
        remaining = remaining
            .get(length..)
            .ok_or(RunnerRuntimeError::InvalidDurablePayload)?;
    }
    Ok(messages)
}

/// Decodes and verifies the complete immutable segment against its durable
/// metadata before any frame can reach the network.
pub(crate) fn validate_log_segment_records(
    encoded: &[u8],
    segment: &LogSegment,
    session: NegotiatedSession,
    guard: LeaseGuard,
    attempt_id: AttemptId,
    stream_id: LogStreamId,
    limits: &ProtocolLimits,
) -> Result<Vec<LogFrame>, RunnerRuntimeError> {
    let records = decode_records(encoded, limits)?;
    if records.len() != usize::try_from(segment.frame_count()).unwrap_or(usize::MAX) {
        return Err(RunnerRuntimeError::InvalidDurablePayload);
    }
    let mut frames: Vec<LogFrame> = Vec::new();
    frames
        .try_reserve_exact(records.len())
        .map_err(|_| RunnerRuntimeError::InvalidDurablePayload)?;
    let mut payload_bytes = 0_u64;
    for record in records {
        let RunnerToServer::LogBatch(batch) = &record.message else {
            return Err(RunnerRuntimeError::InvalidDurablePayload);
        };
        let [frame] = batch.frames() else {
            return Err(RunnerRuntimeError::InvalidDurablePayload);
        };
        if batch.guard() != guard
            || frame.stream_id() != stream_id
            || frame.attempt_id() != attempt_id
        {
            return Err(RunnerRuntimeError::InvalidDurablePayload);
        }
        let expected = match frames.last() {
            Some(previous) => previous
                .sequence()
                .checked_next()
                .map_err(|_| RunnerRuntimeError::InvalidDurablePayload)?,
            None => segment.first_sequence(),
        };
        if frame.sequence() != expected
            || frame.is_end_of_stream()
                != (segment.ends_stream() && frame.sequence() == segment.last_sequence())
        {
            return Err(RunnerRuntimeError::InvalidDurablePayload);
        }
        payload_bytes = payload_bytes
            .checked_add(u64::try_from(frame.payload().len()).unwrap_or(u64::MAX))
            .ok_or(RunnerRuntimeError::InvalidDurablePayload)?;
        let frame = frame.clone();
        let canonical = PreparedRequest::for_session(record.message, session, limits)?;
        if canonical.canonical_bytes().as_ref() != record.canonical_bytes {
            return Err(RunnerRuntimeError::InvalidDurablePayload);
        }
        frames.push(frame);
    }
    if frames.first().map(LogFrame::sequence) != Some(segment.first_sequence())
        || frames.last().map(LogFrame::sequence) != Some(segment.last_sequence())
        || payload_bytes != segment.payload_bytes()
    {
        return Err(RunnerRuntimeError::InvalidDurablePayload);
    }
    Ok(frames)
}

#[cfg(test)]
mod tests {
    use automata_ci_core::{
        AttemptId, FencingToken, JobIrVersion, LeaseGuard, LeaseId, LogChannel, LogFrame,
        LogSequence, LogStreamId, OperationId, RunnerSessionId, Sha256Digest, UnixMillis,
    };
    use automata_ci_protocol::{
        CommandCursor, LogBatch, MessageHeader, NegotiatedSession, ProtocolLimits, RunnerToServer,
        SUPPORTED_PROTOCOL_RANGE, SessionDisposition,
    };
    use automata_ci_runner_journal::{ContentKind, DurableContentRef, LogSegment};
    use automata_ci_runner_spool::ProtectionId;
    use automata_ci_runner_transport::PreparedRequest;

    use super::{
        LENGTH_PREFIX_BYTES, append_record, append_record_in_place, validate_log_segment_records,
    };

    struct LogFixture {
        attempt_id: AttemptId,
        stream_id: LogStreamId,
        guard: LeaseGuard,
        session: NegotiatedSession,
        limits: ProtocolLimits,
    }

    impl LogFixture {
        fn new() -> Self {
            Self {
                attempt_id: AttemptId::new(),
                stream_id: LogStreamId::new(),
                guard: LeaseGuard::new(
                    LeaseId::new(),
                    FencingToken::new(1).expect("fencing token"),
                ),
                session: NegotiatedSession::new(
                    SUPPORTED_PROTOCOL_RANGE.max(),
                    JobIrVersion::current(),
                    RunnerSessionId::new(),
                    SessionDisposition::Opened,
                    CommandCursor::initial(),
                ),
                limits: ProtocolLimits::default(),
            }
        }

        fn record(&self, sequence: u64, end_of_stream: bool) -> Vec<u8> {
            let frame = LogFrame::new(
                self.stream_id,
                self.attempt_id,
                LogSequence::new(sequence),
                UnixMillis::new(10_000),
                LogChannel::Stdout,
                b"x".to_vec(),
                end_of_stream,
            )
            .expect("log frame");
            let message = RunnerToServer::LogBatch(LogBatch::new(
                MessageHeader::request(
                    self.session.selected_protocol(),
                    self.session.session_id(),
                    OperationId::new(),
                ),
                self.guard,
                vec![frame],
            ));
            let prepared = PreparedRequest::for_session(message, self.session, &self.limits)
                .expect("canonical one-frame record");
            let mut encoded = Vec::new();
            append_record_in_place(&mut encoded, prepared.canonical_bytes()).expect("frame record");
            encoded
        }

        fn segment(encoded: &[u8], last: u64, frame_count: u32, end_of_stream: bool) -> LogSegment {
            let content = DurableContentRef::after_commit(
                ContentKind::LogSpool,
                u64::try_from(encoded.len()).expect("encoded size"),
                Sha256Digest::from_bytes([0xa5; 32]),
                ProtectionId::new("outbox-unit-key").expect("protection ID"),
            )
            .expect("content reference");
            LogSegment::new(
                LogSequence::new(0),
                LogSequence::new(last),
                frame_count,
                u64::from(frame_count),
                content,
                true,
                end_of_stream,
            )
            .expect("segment metadata")
        }
    }

    #[test]
    fn in_place_append_reuses_one_preallocated_many_record_buffer() {
        const RECORDS: usize = 10_000;
        const RECORD_BYTES: usize = 37;

        let record = vec![0xa5; RECORD_BYTES];
        let encoded_record_bytes = LENGTH_PREFIX_BYTES + RECORD_BYTES;
        let total_bytes = RECORDS
            .checked_mul(encoded_record_bytes)
            .expect("bounded test payload");
        let mut output = Vec::new();
        output
            .try_reserve_exact(total_bytes)
            .expect("bounded test allocation");
        let initial_capacity = output.capacity();
        let initial_pointer = output.as_ptr();

        for _ in 0..RECORDS {
            append_record_in_place(&mut output, &record).expect("append record");
        }

        assert_eq!(output.len(), total_bytes);
        assert_eq!(output.capacity(), initial_capacity);
        assert_eq!(output.as_ptr(), initial_pointer);
        for encoded in output.chunks_exact(encoded_record_bytes) {
            assert_eq!(
                &encoded[..LENGTH_PREFIX_BYTES],
                &(u32::try_from(RECORD_BYTES).expect("record length")).to_be_bytes()
            );
            assert_eq!(&encoded[LENGTH_PREFIX_BYTES..], record.as_slice());
        }
    }

    #[test]
    fn fixed_batch_segmentation_keeps_many_frame_copy_work_linear() {
        const BATCH_FRAMES: usize = 16;
        const RECORD_BYTES: usize = 257;

        fn persisted_work(frame_count: usize) -> (usize, usize) {
            let record = vec![0x5a; RECORD_BYTES];
            let mut segment = Vec::new();
            let mut work = 0_usize;
            let mut largest = 0_usize;
            for index in 0..frame_count {
                if index % BATCH_FRAMES == 0 {
                    segment.clear();
                }
                segment = append_record(&segment, &record).expect("bounded append");
                work = work.checked_add(segment.len()).expect("bounded work");
                largest = largest.max(segment.len());
            }
            (work, largest)
        }

        let one_batch = persisted_work(BATCH_FRAMES);
        let ten_batches = persisted_work(BATCH_FRAMES * 10);
        assert_eq!(ten_batches.0, one_batch.0 * 10);
        assert_eq!(ten_batches.1, one_batch.1);
        assert_eq!(
            one_batch.1,
            BATCH_FRAMES * (LENGTH_PREFIX_BYTES + RECORD_BYTES)
        );
    }

    #[test]
    fn full_segment_validation_rejects_eos_mismatch_before_delivery() {
        let fixture = LogFixture::new();
        let encoded = fixture.record(0, false);
        let segment = LogFixture::segment(&encoded, 0, 1, true);

        assert!(
            validate_log_segment_records(
                &encoded,
                &segment,
                fixture.session,
                fixture.guard,
                fixture.attempt_id,
                fixture.stream_id,
                &fixture.limits,
            )
            .is_err()
        );
    }

    #[test]
    fn full_segment_validation_rejects_unrecorded_extra_tail_before_delivery() {
        let fixture = LogFixture::new();
        let mut encoded = fixture.record(0, false);
        encoded.extend_from_slice(&fixture.record(1, false));
        let segment = LogFixture::segment(&encoded, 0, 1, false);

        assert!(
            validate_log_segment_records(
                &encoded,
                &segment,
                fixture.session,
                fixture.guard,
                fixture.attempt_id,
                fixture.stream_id,
                &fixture.limits,
            )
            .is_err()
        );
    }
}
