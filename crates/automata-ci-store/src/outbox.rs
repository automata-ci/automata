use std::{
    fmt,
    num::{NonZeroU16, NonZeroU64},
};

use automata_ci_core::{OperationId, Sha256Digest, UnixMillis};
use thiserror::Error;
use zeroize::Zeroize as _;

use crate::{DocumentSchema, RunnerOperationKind, RunnerSessionFence, value::sha256_digest};

const MAX_COMMAND_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
/// Maximum commands returned by one bounded outbox replay.
pub const MAX_COMMAND_REPLAY_LIMIT: u16 = 256;
/// Maximum aggregate command payload bytes returned by one outbox replay.
pub const MAX_COMMAND_REPLAY_BYTES: usize = 16 * 1024 * 1024;

/// Exact server-command identity used to resolve a replay to one typed offer publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseOfferCommandIdentity {
    session: RunnerSessionFence,
    operation_id: OperationId,
    sequence: CommandSequence,
}

impl LeaseOfferCommandIdentity {
    #[must_use]
    pub const fn new(
        session: RunnerSessionFence,
        operation_id: OperationId,
        sequence: CommandSequence,
    ) -> Self {
        Self {
            session,
            operation_id,
            sequence,
        }
    }

    #[must_use]
    pub const fn session(self) -> RunnerSessionFence {
        self.session
    }

    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn sequence(self) -> CommandSequence {
        self.sequence
    }
}

/// Whether one fixed-total replay transaction proved that no later candidate exists.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CommandReplayDisposition {
    /// Every candidate visible after the durable cursor was inspected.
    #[default]
    Exhausted,
    /// A fixed record or byte ceiling stopped inspection before exhaustion was proven.
    Saturated,
}

/// Positive, defensively bounded command replay record count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandReplayLimit(NonZeroU16);

impl CommandReplayLimit {
    /// Creates a replay limit in `1..=256`.
    ///
    /// # Errors
    ///
    /// Rejects zero and unbounded replay requests.
    pub fn new(value: u16) -> Result<Self, CommandValueError> {
        if value > MAX_COMMAND_REPLAY_LIMIT {
            return Err(CommandValueError::InvalidReplayLimit {
                maximum: MAX_COMMAND_REPLAY_LIMIT,
            });
        }
        NonZeroU16::new(value)
            .map(Self)
            .ok_or(CommandValueError::InvalidReplayLimit {
                maximum: MAX_COMMAND_REPLAY_LIMIT,
            })
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

/// One-based durable server-command sequence.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CommandSequence(NonZeroU64);

impl CommandSequence {
    /// Creates a positive sequence within the signed 64-bit storage boundary.
    ///
    /// # Errors
    ///
    /// Rejects zero and values larger than `i64::MAX`.
    pub fn new(value: u64) -> Result<Self, CommandValueError> {
        if value > 9_223_372_036_854_775_807 {
            return Err(CommandValueError::SequenceOutOfRange);
        }
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(CommandValueError::SequenceOutOfRange)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Highest cumulative server command durably acknowledged by a runner.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CommandCursor(Option<CommandSequence>);

impl CommandCursor {
    #[must_use]
    pub const fn initial() -> Self {
        Self(None)
    }

    #[must_use]
    pub const fn through(sequence: CommandSequence) -> Self {
        Self(Some(sequence))
    }

    #[must_use]
    pub const fn acknowledged_through(self) -> Option<CommandSequence> {
        self.0
    }

    #[must_use]
    pub const fn durable_value(self) -> u64 {
        match self.0 {
            Some(sequence) => sequence.get(),
            None => 0,
        }
    }
}

/// Exact bounded command bytes to replay after reconnect.
#[derive(Clone, Eq, PartialEq)]
pub struct RunnerCommandPayload {
    schema: DocumentSchema,
    digest: Sha256Digest,
    bytes: Vec<u8>,
}

impl fmt::Debug for RunnerCommandPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunnerCommandPayload")
            .field("schema", &self.schema)
            .field("digest", &self.digest)
            .field("size", &self.bytes.len())
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl Drop for RunnerCommandPayload {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl RunnerCommandPayload {
    /// Creates a nonempty command payload and computes its digest.
    ///
    /// # Errors
    ///
    /// Rejects payloads over 16 MiB.
    pub fn new(schema: DocumentSchema, mut bytes: Vec<u8>) -> Result<Self, CommandValueError> {
        if bytes.is_empty() || bytes.len() > MAX_COMMAND_PAYLOAD_BYTES {
            let size = bytes.len();
            bytes.zeroize();
            return Err(CommandValueError::InvalidPayloadSize {
                size,
                maximum: MAX_COMMAND_PAYLOAD_BYTES,
            });
        }
        let digest = sha256_digest(&bytes);
        Ok(Self {
            schema,
            digest,
            bytes,
        })
    }

    #[must_use]
    pub const fn schema(&self) -> DocumentSchema {
        self.schema
    }

    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// New durable command for exactly one live runner session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnqueueRunnerCommand {
    session: RunnerSessionFence,
    operation_id: OperationId,
    kind: RunnerOperationKind,
    payload: RunnerCommandPayload,
    created_at: UnixMillis,
}

impl EnqueueRunnerCommand {
    #[must_use]
    pub const fn new(
        session: RunnerSessionFence,
        operation_id: OperationId,
        kind: RunnerOperationKind,
        payload: RunnerCommandPayload,
        created_at: UnixMillis,
    ) -> Self {
        Self {
            session,
            operation_id,
            kind,
            payload,
            created_at,
        }
    }

    #[must_use]
    pub const fn session(&self) -> RunnerSessionFence {
        self.session
    }

    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn kind(&self) -> &RunnerOperationKind {
        &self.kind
    }

    #[must_use]
    pub const fn payload(&self) -> &RunnerCommandPayload {
        &self.payload
    }

    #[must_use]
    pub const fn created_at(&self) -> UnixMillis {
        self.created_at
    }
}

/// Immutable command read from the session outbox.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableRunnerCommand {
    request: EnqueueRunnerCommand,
    sequence: CommandSequence,
    replayed: bool,
}

/// Commands returned by one fixed-total outbox replay transaction.
///
/// A caller must not interpret an empty saturated page as an empty outbox. It
/// must retry from the same durable acknowledgement cursor after the Store has
/// committed any monotonic invalid-offer revocations discovered by the scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandReplayPage {
    commands: Vec<DurableRunnerCommand>,
    disposition: CommandReplayDisposition,
}

impl CommandReplayPage {
    #[must_use]
    pub const fn new(
        commands: Vec<DurableRunnerCommand>,
        disposition: CommandReplayDisposition,
    ) -> Self {
        Self {
            commands,
            disposition,
        }
    }

    #[must_use]
    pub const fn disposition(&self) -> CommandReplayDisposition {
        self.disposition
    }

    #[must_use]
    pub fn commands(&self) -> &[DurableRunnerCommand] {
        &self.commands
    }

    #[must_use]
    pub fn into_commands(self) -> Vec<DurableRunnerCommand> {
        self.commands
    }

    pub fn pop(&mut self) -> Option<DurableRunnerCommand> {
        self.commands.pop()
    }
}

impl std::ops::Deref for CommandReplayPage {
    type Target = [DurableRunnerCommand];

    fn deref(&self) -> &Self::Target {
        self.commands()
    }
}

impl DurableRunnerCommand {
    #[must_use]
    pub const fn new(
        request: EnqueueRunnerCommand,
        sequence: CommandSequence,
        replayed: bool,
    ) -> Self {
        Self {
            request,
            sequence,
            replayed,
        }
    }

    #[must_use]
    pub const fn request(&self) -> &EnqueueRunnerCommand {
        &self.request
    }

    #[must_use]
    pub const fn sequence(&self) -> CommandSequence {
        self.sequence
    }

    #[must_use]
    pub const fn was_replayed(&self) -> bool {
        self.replayed
    }
}

/// Cumulative acknowledgement observed for an exact live session fence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcknowledgeRunnerCommands {
    session: RunnerSessionFence,
    cursor: CommandCursor,
    observed_at: UnixMillis,
}

impl AcknowledgeRunnerCommands {
    #[must_use]
    pub const fn new(
        session: RunnerSessionFence,
        cursor: CommandCursor,
        observed_at: UnixMillis,
    ) -> Self {
        Self {
            session,
            cursor,
            observed_at,
        }
    }

    #[must_use]
    pub const fn session(self) -> RunnerSessionFence {
        self.session
    }

    #[must_use]
    pub const fn cursor(self) -> CommandCursor {
        self.cursor
    }

    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CommandValueError {
    #[error("server command sequence must be in 1..=i64::MAX")]
    SequenceOutOfRange,
    #[error("server command payload has {size} bytes; expected 1..={maximum}")]
    InvalidPayloadSize { size: usize, maximum: usize },
    #[error("server command replay limit must be in 1..={maximum}")]
    InvalidReplayLimit { maximum: u16 },
}
