//! Durable, ordered log frames and contiguous acknowledgements.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{AttemptId, JobConclusion, LogStreamId, UnixMillis};

/// Current durable execution-log document schema.
pub const LOG_SCHEMA_VERSION: u16 = 2;

/// Defensive maximum for one wire frame; larger writes must be chunked.
pub const MAX_LOG_FRAME_BYTES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LogLimitRejection {
    Frame,
    GroupId,
    GroupName,
}

const MAX_LOG_GROUP_ID_BYTES: usize = 256;
const MAX_LOG_GROUP_NAME_BYTES: usize = 512;

const fn log_frame_byte_rejection(observed: usize) -> Option<LogLimitRejection> {
    if observed > MAX_LOG_FRAME_BYTES {
        return Some(LogLimitRejection::Frame);
    }
    None
}

const fn log_group_id_byte_rejection(observed: usize) -> Option<LogLimitRejection> {
    if observed > MAX_LOG_GROUP_ID_BYTES {
        return Some(LogLimitRejection::GroupId);
    }
    None
}

const fn log_group_name_byte_rejection(observed: usize) -> Option<LogLimitRejection> {
    if observed > MAX_LOG_GROUP_NAME_BYTES {
        return Some(LogLimitRejection::GroupName);
    }
    None
}

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
    /// Bytes captured from the attempt's standard output stream.
    Stdout,
    /// Bytes captured from the attempt's standard error stream.
    Stderr,
    /// Trusted runner or control-plane diagnostics, distinct from job output.
    System,
}

/// Stable identity of one execution-log disclosure group.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct LogGroupId(String);

impl LogGroupId {
    /// Creates a bounded portable group identity.
    ///
    /// # Errors
    ///
    /// Returns [`LogValidationError`] when the identity is empty, too large, or
    /// contains characters outside the portable group-identity alphabet.
    pub fn new(value: impl Into<String>) -> Result<Self, LogValidationError> {
        let value = value.into();
        if value.is_empty() {
            return Err(LogValidationError::EmptyGroupId);
        }
        if log_group_id_byte_rejection(value.len()).is_some() {
            return Err(LogValidationError::GroupIdTooLarge {
                maximum: MAX_LOG_GROUP_ID_BYTES,
            });
        }
        if !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'.' | b'_' | b'-' | b'/')
        }) {
            return Err(LogValidationError::InvalidGroupId);
        }
        Ok(Self(value))
    }

    /// Returns the exact case-sensitive group identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for LogGroupId {
    type Error = LogValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<LogGroupId> for String {
    fn from(value: LogGroupId) -> Self {
        value.0
    }
}

/// Presentation kind for one execution-log group.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogGroupKind {
    /// Runner and sandbox preparation before workflow steps execute.
    Setup,
    /// A workflow-authored run or action step.
    Step,
    /// An action's pre-entrypoint.
    ActionPre,
    /// An action's registered post-entrypoint.
    ActionPost,
    /// Job-level service and sandbox cleanup.
    Cleanup,
}

/// Immutable metadata announced before a group can own log lines.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LogGroup {
    id: LogGroupId,
    parent_id: Option<LogGroupId>,
    name: String,
    kind: LogGroupKind,
    ordinal: u32,
}

impl LogGroup {
    /// Creates a bounded execution-log group descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`LogValidationError`] for an empty or unsafe name, or when a
    /// group names itself as its parent.
    pub fn new(
        id: LogGroupId,
        parent_id: Option<LogGroupId>,
        name: impl Into<String>,
        kind: LogGroupKind,
        ordinal: u32,
    ) -> Result<Self, LogValidationError> {
        let group = Self {
            id,
            parent_id,
            name: name.into(),
            kind,
            ordinal,
        };
        group.validate()?;
        Ok(group)
    }

    fn validate(&self) -> Result<(), LogValidationError> {
        if self.name.trim().is_empty() {
            return Err(LogValidationError::EmptyGroupName);
        }
        if log_group_name_byte_rejection(self.name.len()).is_some() {
            return Err(LogValidationError::GroupNameTooLarge {
                maximum: MAX_LOG_GROUP_NAME_BYTES,
            });
        }
        if self.name.chars().any(invalid_log_group_name_character) {
            return Err(LogValidationError::InvalidGroupName);
        }
        if self.parent_id.as_ref() == Some(&self.id) {
            return Err(LogValidationError::SelfParentGroup);
        }
        Ok(())
    }

    /// Returns the stable group identity.
    #[must_use]
    pub const fn id(&self) -> &LogGroupId {
        &self.id
    }

    /// Returns the optional containing group.
    #[must_use]
    pub const fn parent_id(&self) -> Option<&LogGroupId> {
        self.parent_id.as_ref()
    }

    /// Returns the redaction-safe display name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the presentation kind.
    #[must_use]
    pub const fn kind(&self) -> LogGroupKind {
        self.kind
    }

    /// Returns the stable display ordinal within the attempt.
    #[must_use]
    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }
}

fn invalid_log_group_name_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

/// Typed payload of one ordered execution-log record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LogRecord {
    /// Announces immutable metadata before the group owns any lines.
    GroupStarted {
        /// Immutable metadata for the newly active group.
        group: LogGroup,
    },
    /// One output payload explicitly owned by a previously announced group.
    Line {
        /// Group that owns the output bytes.
        group_id: LogGroupId,
        /// Logical source of the output bytes.
        channel: LogChannel,
        /// Raw bytes; canonical JSON uses an integer array.
        payload: Vec<u8>,
    },
    /// Marks one announced group terminal.
    GroupFinished {
        /// Group reaching its terminal state.
        group_id: LogGroupId,
        /// Effective terminal conclusion.
        conclusion: JobConclusion,
    },
    /// Closes the complete attempt log stream.
    StreamFinished,
}

/// Independently retryable frame of log bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LogFrame {
    schema_version: u16,
    stream_id: LogStreamId,
    attempt_id: AttemptId,
    sequence: LogSequence,
    emitted_at: UnixMillis,
    record: LogRecord,
}

impl LogFrame {
    /// Announces one execution-log group.
    ///
    /// # Errors
    ///
    /// Returns [`LogValidationError`] when the group metadata is invalid.
    pub fn group_started(
        stream_id: LogStreamId,
        attempt_id: AttemptId,
        sequence: LogSequence,
        emitted_at: UnixMillis,
        group: LogGroup,
    ) -> Result<Self, LogValidationError> {
        Self::new(
            stream_id,
            attempt_id,
            sequence,
            emitted_at,
            LogRecord::GroupStarted { group },
        )
    }

    /// Creates one group-owned output line record.
    ///
    /// # Errors
    ///
    /// Returns [`LogValidationError`] when the payload is empty or exceeds
    /// [`MAX_LOG_FRAME_BYTES`].
    pub fn line(
        stream_id: LogStreamId,
        attempt_id: AttemptId,
        sequence: LogSequence,
        emitted_at: UnixMillis,
        group_id: LogGroupId,
        channel: LogChannel,
        payload: Vec<u8>,
    ) -> Result<Self, LogValidationError> {
        Self::new(
            stream_id,
            attempt_id,
            sequence,
            emitted_at,
            LogRecord::Line {
                group_id,
                channel,
                payload,
            },
        )
    }

    /// Marks one execution-log group terminal.
    ///
    /// # Errors
    ///
    /// Returns [`LogValidationError`] if the assembled record is invalid.
    pub fn group_finished(
        stream_id: LogStreamId,
        attempt_id: AttemptId,
        sequence: LogSequence,
        emitted_at: UnixMillis,
        group_id: LogGroupId,
        conclusion: JobConclusion,
    ) -> Result<Self, LogValidationError> {
        Self::new(
            stream_id,
            attempt_id,
            sequence,
            emitted_at,
            LogRecord::GroupFinished {
                group_id,
                conclusion,
            },
        )
    }

    /// Creates the unique terminal stream record.
    ///
    /// # Errors
    ///
    /// Returns [`LogValidationError`] if the assembled record is invalid.
    pub fn stream_finished(
        stream_id: LogStreamId,
        attempt_id: AttemptId,
        sequence: LogSequence,
        emitted_at: UnixMillis,
    ) -> Result<Self, LogValidationError> {
        Self::new(
            stream_id,
            attempt_id,
            sequence,
            emitted_at,
            LogRecord::StreamFinished,
        )
    }

    fn new(
        stream_id: LogStreamId,
        attempt_id: AttemptId,
        sequence: LogSequence,
        emitted_at: UnixMillis,
        record: LogRecord,
    ) -> Result<Self, LogValidationError> {
        let frame = Self {
            schema_version: LOG_SCHEMA_VERSION,
            stream_id,
            attempt_id,
            sequence,
            emitted_at,
            record,
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
        if self.schema_version != LOG_SCHEMA_VERSION {
            return Err(LogValidationError::UnsupportedSchema {
                supported: LOG_SCHEMA_VERSION,
                received: self.schema_version,
            });
        }
        match &self.record {
            LogRecord::GroupStarted { group } => group.validate()?,
            LogRecord::Line { payload, .. } => {
                if payload.is_empty() {
                    return Err(LogValidationError::EmptyLine);
                }
                if log_frame_byte_rejection(payload.len()).is_some() {
                    return Err(LogValidationError::FrameTooLarge {
                        size: payload.len(),
                        maximum: MAX_LOG_FRAME_BYTES,
                    });
                }
            }
            LogRecord::GroupFinished { .. } | LogRecord::StreamFinished => {}
        }
        Ok(())
    }

    /// Returns the durable schema carried by this frame.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the durable stream identity used for ordering and replay.
    #[must_use]
    pub const fn stream_id(&self) -> LogStreamId {
        self.stream_id
    }

    /// Returns the attempt to which this frame is immutably bound.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the zero-based sequence within the stream.
    #[must_use]
    pub const fn sequence(&self) -> LogSequence {
        self.sequence
    }

    /// Returns the runner-recorded emission time.
    #[must_use]
    pub const fn emitted_at(&self) -> UnixMillis {
        self.emitted_at
    }

    /// Returns the typed record payload.
    #[must_use]
    pub const fn record(&self) -> &LogRecord {
        &self.record
    }

    /// Returns the logical source when this record contains output bytes.
    #[must_use]
    pub const fn channel(&self) -> Option<LogChannel> {
        match self.record {
            LogRecord::Line { channel, .. } => Some(channel),
            LogRecord::GroupStarted { .. }
            | LogRecord::GroupFinished { .. }
            | LogRecord::StreamFinished => None,
        }
    }

    /// Borrows the raw, codec-independent frame payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        match &self.record {
            LogRecord::Line { payload, .. } => payload,
            LogRecord::GroupStarted { .. }
            | LogRecord::GroupFinished { .. }
            | LogRecord::StreamFinished => &[],
        }
    }

    /// Reports whether this frame closes its stream.
    #[must_use]
    pub const fn is_end_of_stream(&self) -> bool {
        matches!(self.record, LogRecord::StreamFinished)
    }
}

#[cfg(test)]
mod limit_contract_tests {
    use super::{
        LogLimitRejection, MAX_LOG_FRAME_BYTES, MAX_LOG_GROUP_ID_BYTES, MAX_LOG_GROUP_NAME_BYTES,
        log_frame_byte_rejection, log_group_id_byte_rejection, log_group_name_byte_rejection,
    };

    #[test]
    fn log_frame_byte_limit_has_exact_boundaries() {
        assert_eq!(log_frame_byte_rejection(MAX_LOG_FRAME_BYTES - 1), None);
        assert_eq!(log_frame_byte_rejection(MAX_LOG_FRAME_BYTES), None);
        assert_eq!(
            log_frame_byte_rejection(MAX_LOG_FRAME_BYTES + 1),
            Some(LogLimitRejection::Frame)
        );
    }

    #[test]
    fn log_group_limits_have_exact_boundaries() {
        assert_eq!(log_group_id_byte_rejection(MAX_LOG_GROUP_ID_BYTES), None);
        assert_eq!(
            log_group_id_byte_rejection(MAX_LOG_GROUP_ID_BYTES + 1),
            Some(LogLimitRejection::GroupId)
        );
        assert_eq!(
            log_group_name_byte_rejection(MAX_LOG_GROUP_NAME_BYTES),
            None
        );
        assert_eq!(
            log_group_name_byte_rejection(MAX_LOG_GROUP_NAME_BYTES + 1),
            Some(LogLimitRejection::GroupName)
        );
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
            schema_version: LOG_SCHEMA_VERSION,
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
        if self.schema_version == LOG_SCHEMA_VERSION {
            Ok(())
        } else {
            Err(LogValidationError::UnsupportedSchema {
                supported: LOG_SCHEMA_VERSION,
                received: self.schema_version,
            })
        }
    }

    /// Returns the durable schema carried by this acknowledgement.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the stream whose contiguous prefix was acknowledged.
    #[must_use]
    pub const fn stream_id(&self) -> LogStreamId {
        self.stream_id
    }

    /// Returns the greatest durably accepted sequence, or `None` before any frame.
    #[must_use]
    pub const fn contiguous_through(&self) -> Option<LogSequence> {
        self.contiguous_through
    }
}

/// Log schema and sequencing failures.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum LogValidationError {
    /// A durable frame or acknowledgement used a schema this build cannot interpret.
    #[error("unsupported log schema {received}; this build supports {supported}")]
    UnsupportedSchema {
        /// Schema version understood by this build.
        supported: u16,
        /// Schema version found at the interchange boundary.
        received: u16,
    },
    /// A line record carried no bytes.
    #[error("a log line cannot have an empty payload")]
    EmptyLine,
    /// A group identity was empty.
    #[error("a log group identity cannot be empty")]
    EmptyGroupId,
    /// A group identity exceeded the bounded wire limit.
    #[error("log group identity exceeds {maximum} bytes")]
    GroupIdTooLarge {
        /// Maximum accepted group identity size.
        maximum: usize,
    },
    /// A group identity used an unsafe or non-portable character.
    #[error("log group identity is not portable")]
    InvalidGroupId,
    /// A group display name was empty.
    #[error("a log group display name cannot be empty")]
    EmptyGroupName,
    /// A group display name exceeded the bounded wire limit.
    #[error("log group display name exceeds {maximum} bytes")]
    GroupNameTooLarge {
        /// Maximum accepted display-name size.
        maximum: usize,
    },
    /// A group display name contained a control or directional formatting character.
    #[error("log group display name contains a control or directional formatting character")]
    InvalidGroupName,
    /// A group named itself as its parent.
    #[error("a log group cannot contain itself")]
    SelfParentGroup,
    /// A single frame exceeded the defensive wire limit and must be chunked.
    #[error("log frame has {size} bytes; maximum is {maximum}")]
    FrameTooLarge {
        /// Actual payload size in bytes.
        size: usize,
        /// Maximum payload size accepted by the current contract.
        maximum: usize,
    },
    /// Advancing the sequence would wrap its `u64` representation.
    #[error("log sequence is exhausted")]
    SequenceExhausted,
}
