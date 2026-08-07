//! Stable runner slots and durable server-command cursors.

use std::num::{NonZeroU16, NonZeroU64};

use automata_core::{OperationId, RunnerSessionId};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use super::validation::{MessageValidationError, validate_schema};
use crate::{MESSAGE_SCHEMA_VERSION, ProtocolVersion, SUPPORTED_PROTOCOL_RANGE};

/// Stable, one-based execution slot owned by one runner registration.
///
/// Slot identity does not grant capacity. The control plane validates it
/// against the authenticated registration and active session before assigning
/// work.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RunnerSlotOrdinal(NonZeroU16);

impl RunnerSlotOrdinal {
    /// Creates a stable one-based slot ordinal.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerSlotOrdinalError`] when `ordinal` is zero.
    pub fn new(ordinal: u16) -> Result<Self, RunnerSlotOrdinalError> {
        NonZeroU16::new(ordinal)
            .map(Self)
            .ok_or(RunnerSlotOrdinalError::Zero)
    }

    /// Returns the one-based slot ordinal.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

impl<'de> Deserialize<'de> for RunnerSlotOrdinal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// One-based sequence assigned to a durable server command.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CommandSequence(NonZeroU64);

impl CommandSequence {
    /// Largest sequence representable by the durable `PostgreSQL` `BIGINT`
    /// column.
    pub const MAX: u64 = i64::MAX as u64;

    /// Creates a one-based durable command sequence.
    ///
    /// # Errors
    ///
    /// Returns [`CommandSequenceError`] for zero or a value outside the
    /// durable signed 64-bit range.
    pub fn new(value: u64) -> Result<Self, CommandSequenceError> {
        if value > Self::MAX {
            return Err(CommandSequenceError::OutOfRange);
        }
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(CommandSequenceError::Zero)
    }

    /// Returns the one-based integer value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the next sequence without wrapping.
    ///
    /// # Errors
    ///
    /// Returns [`CommandSequenceError::Exhausted`] at [`Self::MAX`].
    pub fn checked_next(self) -> Result<Self, CommandSequenceError> {
        if self.get() == Self::MAX {
            return Err(CommandSequenceError::Exhausted);
        }
        Self::new(self.get() + 1).map_err(|_| CommandSequenceError::Exhausted)
    }
}

impl<'de> Deserialize<'de> for CommandSequence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Highest contiguous durable server command recorded by a runner.
///
/// `None` represents the initial cursor before command sequence one.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandCursor {
    acknowledged_through: Option<CommandSequence>,
}

impl CommandCursor {
    /// Returns the initial cursor before any server command is durable locally.
    #[must_use]
    pub const fn initial() -> Self {
        Self {
            acknowledged_through: None,
        }
    }

    /// Creates a cursor through an already durable command.
    #[must_use]
    pub const fn through(sequence: CommandSequence) -> Self {
        Self {
            acknowledged_through: Some(sequence),
        }
    }

    /// Returns the highest contiguous durable command, if any.
    #[must_use]
    pub const fn acknowledged_through(self) -> Option<CommandSequence> {
        self.acknowledged_through
    }

    /// Advances the cursor by exactly one command.
    ///
    /// # Errors
    ///
    /// Returns [`CommandCursorError`] for a gap, duplicate, or regression.
    pub fn advance(self, sequence: CommandSequence) -> Result<Self, CommandCursorError> {
        let expected = match self.acknowledged_through {
            Some(current) => current
                .checked_next()
                .map_err(|_| CommandCursorError::Exhausted)?,
            None => CommandSequence(NonZeroU64::MIN),
        };
        if sequence != expected {
            return Err(CommandCursorError::NonContiguous {
                expected,
                received: sequence,
            });
        }
        Ok(Self::through(sequence))
    }
}

/// Runner request to resume a previously journaled control-plane session.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionResume {
    session_id: RunnerSessionId,
    command_cursor: CommandCursor,
}

impl SessionResume {
    /// Creates a resume claim. Authentication and server state still decide
    /// whether the session can actually be resumed.
    #[must_use]
    pub const fn new(session_id: RunnerSessionId, command_cursor: CommandCursor) -> Self {
        Self {
            session_id,
            command_cursor,
        }
    }

    #[must_use]
    pub const fn session_id(self) -> RunnerSessionId {
        self.session_id
    }

    #[must_use]
    pub const fn command_cursor(self) -> CommandCursor {
        self.command_cursor
    }
}

/// Whether a successful handshake opened a new session or resumed the claimed
/// one.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionDisposition {
    Opened,
    Resumed,
}

/// Header for a durable, replayable server-to-runner command.
///
/// Unlike a request/reply header, this identity is stable when the command is
/// replayed through a later long poll or another control-plane replica.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServerCommandHeader {
    message_schema_version: u16,
    protocol_version: ProtocolVersion,
    session_id: RunnerSessionId,
    operation_id: OperationId,
    sequence: CommandSequence,
}

impl ServerCommandHeader {
    /// Creates a durable command header for an authenticated session.
    #[must_use]
    pub const fn new(
        protocol_version: ProtocolVersion,
        session_id: RunnerSessionId,
        operation_id: OperationId,
        sequence: CommandSequence,
    ) -> Self {
        Self {
            message_schema_version: MESSAGE_SCHEMA_VERSION,
            protocol_version,
            session_id,
            operation_id,
            sequence,
        }
    }

    #[must_use]
    pub const fn message_schema_version(self) -> u16 {
        self.message_schema_version
    }

    #[must_use]
    pub const fn protocol_version(self) -> ProtocolVersion {
        self.protocol_version
    }

    #[must_use]
    pub const fn session_id(self) -> RunnerSessionId {
        self.session_id
    }

    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn sequence(self) -> CommandSequence {
        self.sequence
    }

    /// Validates message schema and locally supported protocol.
    ///
    /// # Errors
    ///
    /// Returns [`MessageValidationError`] when this build cannot consume the
    /// command header.
    pub fn validate(self) -> Result<(), MessageValidationError> {
        validate_schema(self.message_schema_version)?;
        if !SUPPORTED_PROTOCOL_RANGE.contains(self.protocol_version) {
            return Err(MessageValidationError::UnsupportedProtocol {
                received: self.protocol_version,
                supported: SUPPORTED_PROTOCOL_RANGE,
            });
        }
        Ok(())
    }

    /// Validates that this command belongs to the negotiated session.
    ///
    /// # Errors
    ///
    /// Returns [`MessageValidationError`] for schema, protocol, or session
    /// mismatches.
    pub fn validate_for(
        self,
        protocol_version: ProtocolVersion,
        session_id: RunnerSessionId,
    ) -> Result<(), MessageValidationError> {
        self.validate()?;
        if self.protocol_version != protocol_version {
            return Err(MessageValidationError::ResponseProtocolMismatch {
                expected: protocol_version,
                received: self.protocol_version,
            });
        }
        if self.session_id != session_id {
            return Err(MessageValidationError::ResponseSessionMismatch {
                expected: session_id,
                received: self.session_id,
            });
        }
        Ok(())
    }
}

/// Invalid durable command sequence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CommandSequenceError {
    #[error("server command sequences are one-based and cannot be zero")]
    Zero,
    #[error("server command sequences must fit the durable signed 64-bit representation")]
    OutOfRange,
    #[error("the durable server command sequence is exhausted")]
    Exhausted,
}

/// Invalid cursor advancement.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CommandCursorError {
    #[error("expected command sequence {expected:?}, received {received:?}")]
    NonContiguous {
        expected: CommandSequence,
        received: CommandSequence,
    },
    #[error("the durable server command cursor is exhausted")]
    Exhausted,
}

/// Invalid stable runner slot ordinal.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RunnerSlotOrdinalError {
    #[error("runner slot ordinals are one-based and cannot be zero")]
    Zero,
}
