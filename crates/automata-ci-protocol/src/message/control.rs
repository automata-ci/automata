//! Idempotent operation and durable-command acknowledgements.

use serde::{Deserialize, Serialize};

use super::{CommandCursor, MessageHeader};

/// Runner acknowledgement after every command through the cursor is durable
/// in its local journal.
///
/// The control plane may delete acknowledged outbox entries only after this
/// idempotent operation commits.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandAck {
    header: MessageHeader,
    command_cursor: CommandCursor,
}

impl CommandAck {
    /// Creates an acknowledgement for a non-initial durable command cursor.
    ///
    /// Call [`super::RunnerToServer::validate`] before acting on the value;
    /// validation rejects a cursor that acknowledges no command.
    #[must_use]
    pub const fn new(header: MessageHeader, command_cursor: CommandCursor) -> Self {
        Self {
            header,
            command_cursor,
        }
    }

    #[must_use]
    /// Returns the idempotent runner-operation header.
    pub const fn header(self) -> MessageHeader {
        self.header
    }

    #[must_use]
    /// Returns the highest contiguous command made durable by the runner.
    pub const fn command_cursor(self) -> CommandCursor {
        self.command_cursor
    }
}

/// Exact replayable success response for an idempotent runner operation that
/// has no richer result.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperationAck {
    header: MessageHeader,
}

impl OperationAck {
    /// Creates a replayable success acknowledgement for one request.
    #[must_use]
    pub const fn new(header: MessageHeader) -> Self {
        Self { header }
    }

    #[must_use]
    /// Returns the response header that correlates this acknowledgement.
    pub const fn header(self) -> MessageHeader {
        self.header
    }
}
