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
/// This is the construction and serialization shape. Untrusted transport bytes
/// must enter through [`super::decode_runner_frame`], which applies the hard
/// frame ceiling and returns a validated wrapper.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum RunnerToServer {
    Hello(RunnerHello),
    LeaseRequest(LeaseRequest),
    LeaseResponse(LeaseResponse),
    Heartbeat(LeaseHeartbeat),
    JobState(JobStateUpdate),
    JobResult(JobResultMessage),
    LogBatch(LogBatch),
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
/// This is the construction and serialization shape. Untrusted transport bytes
/// must enter through [`super::decode_server_frame`], which applies the hard
/// frame ceiling and returns a validated wrapper.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum ServerToRunner {
    Hello(ServerHello),
    HandshakeRejected(HandshakeRejected),
    LeaseOffer(Box<LeaseOffer>),
    LeaseRenewal(LeaseRenewal),
    CancelJob(CancelJob),
    LogAck(LogAckMessage),
    OperationAck(OperationAck),
    NoWork(NoWork),
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
