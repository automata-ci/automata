//! Retryable log delivery and durable acknowledgements.

use automata_core::{LeaseGuard, LogAck, LogFrame};
use serde::{Deserialize, Serialize};

use super::MessageHeader;

/// Retryable ordered log batch for one fenced attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LogBatch {
    header: MessageHeader,
    guard: LeaseGuard,
    frames: Vec<LogFrame>,
}

impl LogBatch {
    #[must_use]
    pub const fn new(header: MessageHeader, guard: LeaseGuard, frames: Vec<LogFrame>) -> Self {
        Self {
            header,
            guard,
            frames,
        }
    }

    #[must_use]
    pub const fn header(&self) -> MessageHeader {
        self.header
    }

    #[must_use]
    pub const fn guard(&self) -> LeaseGuard {
        self.guard
    }

    #[must_use]
    pub fn frames(&self) -> &[LogFrame] {
        &self.frames
    }
}

/// Server's durable log acknowledgement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LogAckMessage {
    header: MessageHeader,
    ack: LogAck,
}

impl LogAckMessage {
    #[must_use]
    pub const fn new(header: MessageHeader, ack: LogAck) -> Self {
        Self { header, ack }
    }

    #[must_use]
    pub const fn header(&self) -> MessageHeader {
        self.header
    }

    #[must_use]
    pub const fn ack(&self) -> &LogAck {
        &self.ack
    }
}
