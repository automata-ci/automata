//! Durable, ordered log frames and contiguous acknowledgements.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{AttemptId, CORE_SCHEMA_VERSION, LogStreamId, UnixMillis};

/// Defensive maximum for one wire frame; larger writes must be chunked.
pub const MAX_LOG_FRAME_BYTES: usize = 1024 * 1024;

/// Zero-based sequence number within one log stream.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct LogSequence(u64);

impl LogSequence {
    /// Creates a zero-based log sequence.
    #[must_use]
    pub const fn new(sequence: u64) -> Self {
        Self(sequence)
    }

    /// Returns the numeric sequence.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the following sequence without wrapping.
    ///
    /// # Errors
    ///
    /// Returns [`LogValidationError::SequenceExhausted`] at `u64::MAX`.
    pub fn checked_next(self) -> Result<Self, LogValidationError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(LogValidationError::SequenceExhausted)
    }
}

/// Logical source channel for bytes in a log stream.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogChannel {
    Stdout,
    Stderr,
    System,
}

/// Independently retryable frame of log bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LogFrame {
    schema_version: u16,
    stream_id: LogStreamId,
    attempt_id: AttemptId,
    sequence: LogSequence,
    emitted_at: UnixMillis,
    channel: LogChannel,
    /// Raw bytes. In canonical JSON this is an integer array, avoiding an
    /// implicit or implementation-specific binary codec.
    payload: Vec<u8>,
    end_of_stream: bool,
}

impl LogFrame {
    /// Creates and validates a current-schema frame.
    ///
    /// # Errors
    ///
    /// Returns [`LogValidationError`] when the payload is empty without an
    /// end marker or exceeds [`MAX_LOG_FRAME_BYTES`].
    pub fn new(
        stream_id: LogStreamId,
        attempt_id: AttemptId,
        sequence: LogSequence,
        emitted_at: UnixMillis,
        channel: LogChannel,
        payload: Vec<u8>,
        end_of_stream: bool,
    ) -> Result<Self, LogValidationError> {
        let frame = Self {
            schema_version: CORE_SCHEMA_VERSION,
            stream_id,
            attempt_id,
            sequence,
            emitted_at,
            channel,
            payload,
            end_of_stream,
        };
        frame.validate()?;
        Ok(frame)
    }

    /// Validates a frame read from an interchange boundary.
    ///
    /// # Errors
    ///
    /// Returns [`LogValidationError`] for an unsupported schema or invalid
    /// payload size.
    pub fn validate(&self) -> Result<(), LogValidationError> {
        if self.schema_version != CORE_SCHEMA_VERSION {
            return Err(LogValidationError::UnsupportedSchema {
                supported: CORE_SCHEMA_VERSION,
                received: self.schema_version,
            });
        }
        if self.payload.is_empty() && !self.end_of_stream {
            return Err(LogValidationError::EmptyNonTerminalFrame);
        }
        if self.payload.len() > MAX_LOG_FRAME_BYTES {
            return Err(LogValidationError::FrameTooLarge {
                size: self.payload.len(),
                maximum: MAX_LOG_FRAME_BYTES,
            });
        }
        Ok(())
    }

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
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
    pub const fn sequence(&self) -> LogSequence {
        self.sequence
    }

    #[must_use]
    pub const fn emitted_at(&self) -> UnixMillis {
        self.emitted_at
    }

    #[must_use]
    pub const fn channel(&self) -> LogChannel {
        self.channel
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    #[must_use]
    pub const fn is_end_of_stream(&self) -> bool {
        self.end_of_stream
    }

    #[must_use]
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }
}

/// Acknowledges every sequence from zero through `contiguous_through`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LogAck {
    schema_version: u16,
    stream_id: LogStreamId,
    /// `None` means no frame has yet been durably accepted.
    contiguous_through: Option<LogSequence>,
}

impl LogAck {
    /// Creates a current-schema acknowledgement.
    #[must_use]
    pub const fn new(stream_id: LogStreamId, contiguous_through: Option<LogSequence>) -> Self {
        Self {
            schema_version: CORE_SCHEMA_VERSION,
            stream_id,
            contiguous_through,
        }
    }

    /// First frame sequence the receiver has not acknowledged.
    ///
    /// # Errors
    ///
    /// Returns [`LogValidationError::SequenceExhausted`] when the acknowledgement
    /// already contains the maximum sequence.
    pub fn next_expected(&self) -> Result<LogSequence, LogValidationError> {
        match self.contiguous_through {
            Some(sequence) => sequence.checked_next(),
            None => Ok(LogSequence::new(0)),
        }
    }

    /// Validates a durable acknowledgement's schema.
    ///
    /// # Errors
    ///
    /// Returns [`LogValidationError::UnsupportedSchema`] for another schema.
    pub fn validate(&self) -> Result<(), LogValidationError> {
        if self.schema_version == CORE_SCHEMA_VERSION {
            Ok(())
        } else {
            Err(LogValidationError::UnsupportedSchema {
                supported: CORE_SCHEMA_VERSION,
                received: self.schema_version,
            })
        }
    }

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub const fn stream_id(&self) -> LogStreamId {
        self.stream_id
    }

    #[must_use]
    pub const fn contiguous_through(&self) -> Option<LogSequence> {
        self.contiguous_through
    }
}

/// Log schema and sequencing failures.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum LogValidationError {
    #[error("unsupported log schema {received}; this build supports {supported}")]
    UnsupportedSchema { supported: u16, received: u16 },
    #[error("a non-terminal log frame cannot have an empty payload")]
    EmptyNonTerminalFrame,
    #[error("log frame has {size} bytes; maximum is {maximum}")]
    FrameTooLarge { size: usize, maximum: usize },
    #[error("log sequence is exhausted")]
    SequenceExhausted,
}
