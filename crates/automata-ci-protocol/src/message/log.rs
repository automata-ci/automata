//! Retryable log delivery and durable acknowledgements.

use automata_ci_core::{LeaseGuard, LogAck, LogFrame};
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
    /// Creates a retryable batch of ordered log frames under a lease fence.
    ///
    /// Envelope validation enforces one attempt, one stream, contiguous
    /// sequence numbers, end-of-stream finality, and configured size limits.
    #[must_use]
    pub const fn new(header: MessageHeader, guard: LeaseGuard, frames: Vec<LogFrame>) -> Self {
        Self {
            header,
            guard,
            frames,
        }
    }

    #[must_use]
    /// Returns the runner request identity used for replay detection.
    pub const fn header(&self) -> MessageHeader {
        self.header
    }

    #[must_use]
    /// Returns the lease identity and fencing token authorizing delivery.
    pub const fn guard(&self) -> LeaseGuard {
        self.guard
    }

    #[must_use]
    /// Returns the ordered frames in this batch.
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
    /// Creates a response confirming the server's durable log prefix.
    #[must_use]
    pub const fn new(header: MessageHeader, ack: LogAck) -> Self {
        Self { header, ack }
    }

    #[must_use]
    /// Returns the response header correlated to a log-batch request.
    pub const fn header(&self) -> MessageHeader {
        self.header
    }

    #[must_use]
    /// Returns the durable per-stream acknowledgement.
    pub const fn ack(&self) -> &LogAck {
        &self.ack
    }
}
