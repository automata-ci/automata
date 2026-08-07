use async_trait::async_trait;
use automata_core::{AttemptId, LeaseGuard, LogSequence, LogStreamId, OperationId, UnixMillis};
use thiserror::Error;

use crate::{
    AttemptAssignment, DocumentSchema, MAX_LOG_SEGMENT_BYTES, ObjectKey, Sha256Digest, StoreError,
};

const MAX_UNCOMPRESSED_LOG_SEGMENT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_POSTGRES_SEQUENCE: u64 = 9_223_372_036_854_775_807;

/// Durable identity and fence for one attempt log stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogStreamMetadata {
    operation_id: OperationId,
    stream_id: LogStreamId,
    attempt_id: AttemptId,
    assignment: AttemptAssignment,
    guard: LeaseGuard,
    schema: DocumentSchema,
    opened_at: UnixMillis,
}

impl LogStreamMetadata {
    #[must_use]
    pub const fn new(
        operation_id: OperationId,
        stream_id: LogStreamId,
        attempt_id: AttemptId,
        assignment: AttemptAssignment,
        guard: LeaseGuard,
        schema: DocumentSchema,
        opened_at: UnixMillis,
    ) -> Self {
        Self {
            operation_id,
            stream_id,
            attempt_id,
            assignment,
            guard,
            schema,
            opened_at,
        }
    }

    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn stream_id(&self) -> LogStreamId {
        self.stream_id
    }

    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    #[must_use]
    pub const fn assignment(&self) -> AttemptAssignment {
        self.assignment
    }

    #[must_use]
    pub const fn guard(&self) -> LeaseGuard {
        self.guard
    }

    #[must_use]
    pub const fn schema(&self) -> DocumentSchema {
        self.schema
    }

    #[must_use]
    pub const fn opened_at(&self) -> UnixMillis {
        self.opened_at
    }
}

/// Immutable S3-compatible segment covering an inclusive log sequence range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogSegmentMetadata {
    operation_id: OperationId,
    stream_id: LogStreamId,
    first_sequence: LogSequence,
    last_sequence: LogSequence,
    object_key: ObjectKey,
    digest: Sha256Digest,
    encoded_size: u64,
    uncompressed_size: u64,
    stored_at: UnixMillis,
    end_of_stream: bool,
}

impl LogSegmentMetadata {
    /// Creates bounded, ordered segment metadata.
    ///
    /// # Errors
    ///
    /// Rejects inverted/unrepresentable sequences and invalid object sizes.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_id: OperationId,
        stream_id: LogStreamId,
        first_sequence: LogSequence,
        last_sequence: LogSequence,
        object_key: ObjectKey,
        digest: Sha256Digest,
        encoded_size: u64,
        uncompressed_size: u64,
        stored_at: UnixMillis,
        end_of_stream: bool,
    ) -> Result<Self, LogSegmentMetadataError> {
        if first_sequence > last_sequence {
            return Err(LogSegmentMetadataError::InvertedSequenceRange);
        }
        if last_sequence.get() > MAX_POSTGRES_SEQUENCE {
            return Err(LogSegmentMetadataError::SequenceOutOfRange);
        }
        if encoded_size == 0 || encoded_size > MAX_LOG_SEGMENT_BYTES {
            return Err(LogSegmentMetadataError::InvalidEncodedSize {
                size: encoded_size,
                maximum: MAX_LOG_SEGMENT_BYTES,
            });
        }
        if uncompressed_size == 0 || uncompressed_size > MAX_UNCOMPRESSED_LOG_SEGMENT_BYTES {
            return Err(LogSegmentMetadataError::InvalidUncompressedSize {
                size: uncompressed_size,
                maximum: MAX_UNCOMPRESSED_LOG_SEGMENT_BYTES,
            });
        }
        Ok(Self {
            operation_id,
            stream_id,
            first_sequence,
            last_sequence,
            object_key,
            digest,
            encoded_size,
            uncompressed_size,
            stored_at,
            end_of_stream,
        })
    }

    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn stream_id(&self) -> LogStreamId {
        self.stream_id
    }

    #[must_use]
    pub const fn first_sequence(&self) -> LogSequence {
        self.first_sequence
    }

    #[must_use]
    pub const fn last_sequence(&self) -> LogSequence {
        self.last_sequence
    }

    #[must_use]
    pub const fn object_key(&self) -> &ObjectKey {
        &self.object_key
    }

    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    #[must_use]
    pub const fn encoded_size(&self) -> u64 {
        self.encoded_size
    }

    #[must_use]
    pub const fn uncompressed_size(&self) -> u64 {
        self.uncompressed_size
    }

    #[must_use]
    pub const fn stored_at(&self) -> UnixMillis {
        self.stored_at
    }

    #[must_use]
    pub const fn is_end_of_stream(&self) -> bool {
        self.end_of_stream
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LogSegmentMetadataError {
    #[error("log segment sequence range is inverted")]
    InvertedSequenceRange,
    #[error("log segment sequence cannot be represented by the durable backend")]
    SequenceOutOfRange,
    #[error("log segment encoded size {size} is outside 1..={maximum}")]
    InvalidEncodedSize { size: u64, maximum: u64 },
    #[error("log segment uncompressed size {size} is outside 1..={maximum}")]
    InvalidUncompressedSize { size: u64, maximum: u64 },
}

/// Result of an immutable log metadata write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogMetadataReceipt {
    replayed: bool,
}

impl LogMetadataReceipt {
    #[must_use]
    pub const fn new(replayed: bool) -> Self {
        Self { replayed }
    }

    #[must_use]
    pub const fn was_replayed(self) -> bool {
        self.replayed
    }
}

/// Fenced log stream and immutable segment metadata port.
#[async_trait]
pub trait LogMetadataRepository: Send + Sync {
    /// Creates the first fenced stream for an attempt. Exact retries replay;
    /// key reuse with different immutable contents conflicts.
    async fn create_log_stream(
        &self,
        metadata: LogStreamMetadata,
    ) -> Result<LogMetadataReceipt, StoreError>;

    /// Appends immutable object metadata. Implementations must serialize
    /// writers per stream, reject gaps/overlaps, and replay an exact operation.
    async fn append_log_segment(
        &self,
        metadata: LogSegmentMetadata,
    ) -> Result<LogMetadataReceipt, StoreError>;
}
