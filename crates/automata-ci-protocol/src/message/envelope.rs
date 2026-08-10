//! Directional envelopes for complete owned protocol messages.

use serde::{Deserialize, Serialize};

use super::{
    CancelJob, CommandAck, ErrorMessage, HandshakeRejected, JobResultMessage, JobStateUpdate,
    LeaseHeartbeat, LeaseOffer, LeaseRenewal, LeaseRequest, LeaseResponse, LogAckMessage, LogBatch,
    NoWork, OperationAck, ProtocolLimits, RunnerHello, ServerHello,
    validation::{validate_runner_message, validate_server_message},
};

/// Complete owned messages sent by a runner.
///
/// This is the construction and serialization shape. A transport adapter must
/// enforce its byte-level limits, decode into this type, and construct
/// [`super::ValidatedRunnerToServer`] before handing the message to a handler.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum RunnerToServer {
    /// Opens or attempts to resume an authenticated protocol session.
    Hello(RunnerHello),
    /// Polls for at most one lease on a stable runner slot.
    LeaseRequest(LeaseRequest),
    /// Accepts or rejects a previously offered lease.
    LeaseResponse(LeaseResponse),
    /// Reports liveness and progress under an active lease fence.
    Heartbeat(LeaseHeartbeat),
    /// Reports a fenced non-terminal job lifecycle transition.
    JobState(JobStateUpdate),
    /// Commits a fenced terminal job result idempotently.
    JobResult(JobResultMessage),
    /// Delivers a bounded contiguous batch of attempt log frames.
    LogBatch(LogBatch),
    /// Confirms that a contiguous prefix of server commands is durable.
    CommandAck(CommandAck),
}

impl RunnerToServer {
    /// Validates every nested value before the message reaches a handler.
    ///
    /// # Errors
    ///
    /// Returns a typed error for invalid schemas, domain invariants, or
    /// configured resource budgets.
    pub fn validate(&self, limits: &ProtocolLimits) -> Result<(), super::MessageValidationError> {
        validate_runner_message(self, limits)
    }
}

/// Complete owned messages sent by a server.
///
/// This is the construction and serialization shape. A transport adapter must
/// enforce its byte-level limits, decode into this type, and construct
/// [`super::ValidatedServerToRunner`] before handing the message to a handler.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum ServerToRunner {
    /// Selects protocol and `JobIR` versions and establishes session state.
    Hello(ServerHello),
    /// Rejects a pre-negotiation hello with a stable reason code.
    HandshakeRejected(HandshakeRejected),
    /// Offers one immutable job, lease fence, and authority bundle.
    LeaseOffer(Box<LeaseOffer>),
    /// Extends the lease associated with a correlated heartbeat.
    LeaseRenewal(LeaseRenewal),
    /// Requests cancellation through the durable command stream.
    CancelJob(CancelJob),
    /// Confirms the durable log prefix accepted by the server.
    LogAck(LogAckMessage),
    /// Confirms an idempotent runner operation with no richer response.
    OperationAck(OperationAck),
    /// Directs an idle slot to back off before polling again.
    NoWork(NoWork),
    /// Reports a typed, sanitized remote failure.
    Error(ErrorMessage),
}

impl ServerToRunner {
    /// Validates every nested value before the message reaches a handler.
    ///
    /// # Errors
    ///
    /// Returns a typed error for invalid schemas, domain invariants, or
    /// configured resource budgets.
    pub fn validate(&self, limits: &ProtocolLimits) -> Result<(), super::MessageValidationError> {
        validate_server_message(self, limits)
    }
}
