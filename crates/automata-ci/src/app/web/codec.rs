use std::io::{Cursor, Read as _, Write as _};

use automata_ci_blob::VerifiedBlob;
use automata_ci_control::runner_control::LOG_SEGMENT_MEDIA_TYPE;
use automata_ci_core::{AttemptId, LogFrame, LogSequence, LogStreamId};
use automata_ci_store::MAX_LOG_SEGMENT_BYTES;
use thiserror::Error;

pub(crate) const MAX_LOG_SEGMENT_UNCOMPRESSED_BYTES: usize =
    automata_ci_protocol::MAX_CONFIGURABLE_FRAME_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LogSegmentExpectation {
    attempt_id: AttemptId,
    stream_id: LogStreamId,
    first_sequence: LogSequence,
    last_sequence: LogSequence,
    uncompressed_size: u64,
    end_of_stream: bool,
}

impl LogSegmentExpectation {
    pub(crate) const fn new(
        attempt_id: AttemptId,
        stream_id: LogStreamId,
        first_sequence: LogSequence,
        last_sequence: LogSequence,
        uncompressed_size: u64,
        end_of_stream: bool,
    ) -> Self {
        Self {
            attempt_id,
            stream_id,
            first_sequence,
            last_sequence,
            uncompressed_size,
            end_of_stream,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum BlobDecodeError {
    #[error("immutable blob has an unexpected media type")]
    UnexpectedMediaType,
    #[error("immutable blob encoded size is outside the supported bounds")]
    EncodedSizeOutOfBounds,
    #[error("immutable blob bytes contradict the verified descriptor")]
    DescriptorMismatch,
    #[error("immutable blob contains invalid JSON")]
    InvalidJson,
    #[error("immutable blob contains an invalid domain document")]
    InvalidDocument,
    #[error("immutable blob is not in its canonical representation")]
    NonCanonicalEncoding,
    #[error("immutable blob belongs to another attempt")]
    AttemptMismatch,
    #[error("log segment belongs to another stream")]
    StreamMismatch,
    #[error("log segment has an invalid expected sequence range")]
    InvalidSequenceRange,
    #[error("log segment does not contain its exact expected sequence range")]
    SequenceRangeMismatch,
    #[error("log segment contains a noncontiguous sequence")]
    NonContiguousSequence,
    #[error("log segment contains a frame after its end marker")]
    FrameAfterEndOfStream,
    #[error("log segment end marker contradicts durable metadata")]
    EndOfStreamMismatch,
    #[error("log segment uncompressed size is outside the supported bounds")]
    UncompressedSizeOutOfBounds,
    #[error("log segment is not a valid single gzip member")]
    InvalidGzip,
    #[error("log segment expands to a different byte count than durable metadata")]
    UncompressedSizeMismatch,
    #[error("log segment has bytes after its gzip member")]
    TrailingGzipData,
    #[error("log segment is empty")]
    EmptyLogSegment,
}

/// Decodes one durable segment without removing its terminal frame.
///
/// Callers must explicitly decide whether an end marker's payload is rendered.
pub(crate) fn decode_log_segment(
    blob: &VerifiedBlob,
    expected: LogSegmentExpectation,
) -> Result<Vec<LogFrame>, BlobDecodeError> {
    let compressed = verified_bytes(blob, LOG_SEGMENT_MEDIA_TYPE, MAX_LOG_SEGMENT_BYTES)?;
    if expected.first_sequence > expected.last_sequence {
        return Err(BlobDecodeError::InvalidSequenceRange);
    }
    let uncompressed_size = usize::try_from(expected.uncompressed_size)
        .map_err(|_| BlobDecodeError::UncompressedSizeOutOfBounds)?;
    if uncompressed_size == 0 || uncompressed_size > MAX_LOG_SEGMENT_UNCOMPRESSED_BYTES {
        return Err(BlobDecodeError::UncompressedSizeOutOfBounds);
    }

    let uncompressed = decompress_exact_single_member(compressed, uncompressed_size)?;
    let frames: Vec<LogFrame> =
        serde_json::from_slice(&uncompressed).map_err(|_| BlobDecodeError::InvalidJson)?;
    if frames.is_empty() {
        return Err(BlobDecodeError::EmptyLogSegment);
    }

    validate_frames(&frames, expected)?;

    let canonical = serde_json::to_vec(&frames).map_err(|_| BlobDecodeError::InvalidDocument)?;
    if canonical != uncompressed || deterministic_gzip(&canonical)? != compressed {
        return Err(BlobDecodeError::NonCanonicalEncoding);
    }
    Ok(frames)
}

fn verified_bytes<'a>(
    blob: &'a VerifiedBlob,
    expected_media_type: &str,
    maximum_size: u64,
) -> Result<&'a [u8], BlobDecodeError> {
    let descriptor = blob.descriptor();
    if descriptor.media_type().as_str() != expected_media_type {
        return Err(BlobDecodeError::UnexpectedMediaType);
    }
    if descriptor.size() == 0 || descriptor.size() > maximum_size {
        return Err(BlobDecodeError::EncodedSizeOutOfBounds);
    }
    if u64::try_from(blob.bytes().len()) != Ok(descriptor.size()) {
        return Err(BlobDecodeError::DescriptorMismatch);
    }
    Ok(blob.bytes())
}

fn decompress_exact_single_member(
    compressed: &[u8],
    expected_size: usize,
) -> Result<Vec<u8>, BlobDecodeError> {
    let cursor = Cursor::new(compressed);
    let mut decoder = flate2::bufread::GzDecoder::new(cursor);
    let read_limit = u64::try_from(expected_size)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(BlobDecodeError::UncompressedSizeOutOfBounds)?;
    let mut uncompressed = Vec::with_capacity(expected_size.min(1024 * 1024));
    decoder
        .by_ref()
        .take(read_limit)
        .read_to_end(&mut uncompressed)
        .map_err(|_| BlobDecodeError::InvalidGzip)?;
    if uncompressed.len() != expected_size {
        return Err(BlobDecodeError::UncompressedSizeMismatch);
    }
    let consumed = usize::try_from(decoder.into_inner().position())
        .map_err(|_| BlobDecodeError::TrailingGzipData)?;
    if consumed != compressed.len() {
        return Err(BlobDecodeError::TrailingGzipData);
    }
    Ok(uncompressed)
}

fn validate_frames(
    frames: &[LogFrame],
    expected: LogSegmentExpectation,
) -> Result<(), BlobDecodeError> {
    let first = frames.first().ok_or(BlobDecodeError::EmptyLogSegment)?;
    let last = frames.last().ok_or(BlobDecodeError::EmptyLogSegment)?;
    if first.sequence() != expected.first_sequence || last.sequence() != expected.last_sequence {
        return Err(BlobDecodeError::SequenceRangeMismatch);
    }

    let mut previous: Option<&LogFrame> = None;
    for frame in frames {
        frame
            .validate()
            .map_err(|_| BlobDecodeError::InvalidDocument)?;
        if frame.attempt_id() != expected.attempt_id {
            return Err(BlobDecodeError::AttemptMismatch);
        }
        if frame.stream_id() != expected.stream_id {
            return Err(BlobDecodeError::StreamMismatch);
        }
        if let Some(previous_frame) = previous {
            if previous_frame.is_end_of_stream() {
                return Err(BlobDecodeError::FrameAfterEndOfStream);
            }
            if previous_frame.sequence().checked_next().ok() != Some(frame.sequence()) {
                return Err(BlobDecodeError::NonContiguousSequence);
            }
        }
        previous = Some(frame);
    }

    if last.is_end_of_stream() != expected.end_of_stream {
        return Err(BlobDecodeError::EndOfStreamMismatch);
    }
    Ok(())
}

fn deterministic_gzip(bytes: &[u8]) -> Result<Vec<u8>, BlobDecodeError> {
    let mut encoder = flate2::GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), flate2::Compression::new(6));
    encoder
        .write_all(bytes)
        .map_err(|_| BlobDecodeError::InvalidGzip)?;
    encoder.finish().map_err(|_| BlobDecodeError::InvalidGzip)
}

#[cfg(test)]
mod tests {
    use automata_ci_blob::{BlobKey, BlobPayload, MediaType, VerifiedBlob};
    use automata_ci_core::{AttemptId, LogChannel, LogFrame, LogSequence, LogStreamId, UnixMillis};

    use super::{
        BlobDecodeError, LogSegmentExpectation, MAX_LOG_SEGMENT_UNCOMPRESSED_BYTES,
        decode_log_segment, deterministic_gzip,
    };

    #[test]
    fn decodes_frames_without_stringifying_or_omitting_terminal_payload() {
        let attempt = AttemptId::new();
        let stream = LogStreamId::new();
        let frames = vec![
            frame(attempt, stream, 7, vec![0xff, 0xfe], false),
            frame(attempt, stream, 8, b"done".to_vec(), true),
        ];
        let (blob, expectation) = log_blob(&frames, attempt, stream, 7, 8, true);

        let decoded = decode_log_segment(&blob, expectation).expect("decode log segment");
        assert_eq!(decoded, frames);
        assert_eq!(decoded[0].payload(), &[0xff, 0xfe]);
        assert!(decoded[1].is_end_of_stream());
        assert_eq!(decoded[1].payload(), b"done");
    }

    #[test]
    fn rejects_a_log_segment_with_the_wrong_media_type() {
        let attempt = AttemptId::new();
        let stream = LogStreamId::new();
        let frames = vec![frame(attempt, stream, 0, b"ok".to_vec(), false)];
        let (valid_blob, expectation) = log_blob(&frames, attempt, stream, 0, 0, false);
        let wrong_media_type = blob("application/json", valid_blob.bytes().to_vec());

        assert_eq!(
            decode_log_segment(&wrong_media_type, expectation),
            Err(BlobDecodeError::UnexpectedMediaType)
        );
    }

    #[test]
    fn rejects_corrupt_gzip_and_bounded_expansion() {
        let attempt = AttemptId::new();
        let stream = LogStreamId::new();
        let frames = vec![frame(attempt, stream, 0, b"ok".to_vec(), false)];
        let uncompressed = serde_json::to_vec(&frames).expect("serialize frames");
        let mut compressed = deterministic_gzip(&uncompressed).expect("compress frames");
        let last = compressed.last_mut().expect("gzip trailer");
        *last ^= 0xff;
        let corrupt = blob(super::LOG_SEGMENT_MEDIA_TYPE, compressed);
        let expected = LogSegmentExpectation::new(
            attempt,
            stream,
            LogSequence::new(0),
            LogSequence::new(0),
            u64::try_from(uncompressed.len()).expect("size"),
            false,
        );
        assert_eq!(
            decode_log_segment(&corrupt, expected),
            Err(BlobDecodeError::InvalidGzip)
        );

        let expansion = vec![b'x'; 1024 * 1024];
        let compressed = deterministic_gzip(&expansion).expect("compress expansion");
        let expansion = blob(super::LOG_SEGMENT_MEDIA_TYPE, compressed);
        let bounded = LogSegmentExpectation::new(
            attempt,
            stream,
            LogSequence::new(0),
            LogSequence::new(0),
            16,
            false,
        );
        assert_eq!(
            decode_log_segment(&expansion, bounded),
            Err(BlobDecodeError::UncompressedSizeMismatch)
        );
    }

    #[test]
    fn rejects_oversized_uncompressed_metadata_before_decoding() {
        let attempt = AttemptId::new();
        let stream = LogStreamId::new();
        let bytes = deterministic_gzip(b"[]").expect("compress empty list");
        let blob = blob(super::LOG_SEGMENT_MEDIA_TYPE, bytes);
        let expected = LogSegmentExpectation::new(
            attempt,
            stream,
            LogSequence::new(0),
            LogSequence::new(0),
            u64::try_from(MAX_LOG_SEGMENT_UNCOMPRESSED_BYTES).expect("limit") + 1,
            false,
        );
        assert_eq!(
            decode_log_segment(&blob, expected),
            Err(BlobDecodeError::UncompressedSizeOutOfBounds)
        );
    }

    #[test]
    fn rejects_wrong_log_identity() {
        let attempt = AttemptId::new();
        let stream = LogStreamId::new();
        let frames = vec![frame(attempt, stream, 0, b"ok".to_vec(), false)];
        let (blob, _) = log_blob(&frames, attempt, stream, 0, 0, false);
        let expected = expectation(&frames, AttemptId::new(), stream, 0, 0, false);
        assert_eq!(
            decode_log_segment(&blob, expected),
            Err(BlobDecodeError::AttemptMismatch)
        );

        let expected = expectation(&frames, attempt, LogStreamId::new(), 0, 0, false);
        assert_eq!(
            decode_log_segment(&blob, expected),
            Err(BlobDecodeError::StreamMismatch)
        );
    }

    #[test]
    fn rejects_noncontiguous_sequences() {
        let attempt = AttemptId::new();
        let stream = LogStreamId::new();
        let frames = vec![
            frame(attempt, stream, 2, b"a".to_vec(), false),
            frame(attempt, stream, 4, b"b".to_vec(), false),
        ];
        let (blob, expectation) = log_blob(&frames, attempt, stream, 2, 4, false);
        assert_eq!(
            decode_log_segment(&blob, expectation),
            Err(BlobDecodeError::NonContiguousSequence)
        );
    }

    #[test]
    fn rejects_a_trailing_gzip_member() {
        let attempt = AttemptId::new();
        let stream = LogStreamId::new();
        let frames = vec![frame(attempt, stream, 0, b"ok".to_vec(), false)];
        let uncompressed = serde_json::to_vec(&frames).expect("serialize frames");
        let mut compressed = deterministic_gzip(&uncompressed).expect("compress frames");
        compressed.extend(deterministic_gzip(b"[]").expect("compress trailing member"));
        let blob = blob(super::LOG_SEGMENT_MEDIA_TYPE, compressed);
        let expected = expectation(&frames, attempt, stream, 0, 0, false);
        assert_eq!(
            decode_log_segment(&blob, expected),
            Err(BlobDecodeError::TrailingGzipData)
        );
    }

    fn frame(
        attempt: AttemptId,
        stream: LogStreamId,
        sequence: u64,
        payload: Vec<u8>,
        end_of_stream: bool,
    ) -> LogFrame {
        LogFrame::new(
            stream,
            attempt,
            LogSequence::new(sequence),
            UnixMillis::new(10),
            LogChannel::Stdout,
            payload,
            end_of_stream,
        )
        .expect("valid log frame")
    }

    fn log_blob(
        frames: &[LogFrame],
        attempt: AttemptId,
        stream: LogStreamId,
        first: u64,
        last: u64,
        end_of_stream: bool,
    ) -> (VerifiedBlob, LogSegmentExpectation) {
        let uncompressed = serde_json::to_vec(frames).expect("serialize frames");
        let compressed = deterministic_gzip(&uncompressed).expect("compress frames");
        let expectation = LogSegmentExpectation::new(
            attempt,
            stream,
            LogSequence::new(first),
            LogSequence::new(last),
            u64::try_from(uncompressed.len()).expect("size"),
            end_of_stream,
        );
        (blob(super::LOG_SEGMENT_MEDIA_TYPE, compressed), expectation)
    }

    fn expectation(
        frames: &[LogFrame],
        attempt: AttemptId,
        stream: LogStreamId,
        first: u64,
        last: u64,
        end_of_stream: bool,
    ) -> LogSegmentExpectation {
        let size = serde_json::to_vec(frames).expect("serialize frames").len();
        LogSegmentExpectation::new(
            attempt,
            stream,
            LogSequence::new(first),
            LogSequence::new(last),
            u64::try_from(size).expect("size"),
            end_of_stream,
        )
    }

    fn blob(media_type: &str, bytes: Vec<u8>) -> VerifiedBlob {
        let key = BlobKey::new("web/codec/test").expect("key");
        let media_type = MediaType::new(media_type).expect("media type");
        VerifiedBlob::from_payload(BlobPayload::from_bytes(key, media_type, bytes.into()))
    }
}
