use std::fmt;

use automata_ci_core::OperationId;
use automata_ci_protocol::{
    MessageHeader, NegotiatedSession, ProtocolLimits, RunnerHello, RunnerToServer,
};
use bytes::Bytes;
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{ControlRoute, MAX_EPHEMERAL_REQUEST_BYTES, SessionBinding};

/// Failure while preparing a deterministic outbound runner request.
#[derive(Debug, Error)]
pub enum PrepareError {
    /// Domain validation or canonical protobuf encoding failed.
    #[error("runner request cannot be encoded")]
    InvalidMessage(#[source] automata_ci_protocol_protobuf::EncodeError),
    /// A handshake constructor received a post-handshake message or vice versa.
    #[error("runner request does not match the selected control route")]
    WrongRoute,
    /// The request header does not match the explicitly negotiated session.
    #[error("runner request does not match the negotiated session")]
    SessionMismatch,
}

/// Invalid bounded payload for the private ephemeral-value route.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("ephemeral runner request is empty or exceeds its byte bound")]
pub struct PrepareEphemeralError;

/// Retry-stable application payload for the private mTLS value route.
///
/// The encoded operation identity and bearer remain in an application-owned
/// zeroizing aggregate. This type is intentionally non-cloneable so retries
/// cannot silently diverge from the caller's one prepared operation.
pub struct PreparedEphemeralRequest {
    body: Zeroizing<Vec<u8>>,
}

impl PreparedEphemeralRequest {
    /// Takes ownership of one non-empty request within the route ceiling.
    ///
    /// The transport treats these bytes as opaque and may classify an ambiguous
    /// loss as safe to retry with the exact same prepared value. Callers must
    /// therefore validate their application envelope before construction: it
    /// must carry a stable operation identity, and the server-side handler must
    /// deduplicate identical replays by that identity before committing side
    /// effects. Reusing identical bytes alone does not make an arbitrary
    /// operation safe. A new operation must be represented by a newly prepared
    /// value.
    ///
    /// # Errors
    ///
    /// Rejects and zeroizes empty or oversized input.
    pub fn new(mut body: Vec<u8>) -> Result<Self, PrepareEphemeralError> {
        if body.is_empty() || body.len() > MAX_EPHEMERAL_REQUEST_BYTES {
            body.zeroize();
            return Err(PrepareEphemeralError);
        }
        Ok(Self {
            body: Zeroizing::new(body),
        })
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }
}

impl fmt::Debug for PreparedEphemeralRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedEphemeralRequest")
            .field("body", &"[REDACTED]")
            .field("byte_count", &self.body.len())
            .finish()
    }
}

/// Immutable request whose operation identity and canonical bytes survive retries.
///
/// Callers create this value once and reuse it for every transport retry. The
/// transport never re-runs message construction, so it cannot accidentally mint
/// a replacement [`OperationId`].
#[derive(Clone)]
pub struct PreparedRequest {
    route: ControlRoute,
    operation_id: OperationId,
    message: RunnerToServer,
    canonical_bytes: Bytes,
    session: Option<SessionBinding>,
}

impl PreparedRequest {
    /// Validates and canonically encodes a pre-negotiation hello once.
    ///
    /// # Errors
    ///
    /// Returns [`PrepareError`] if validation or encoding fails.
    pub fn handshake(
        hello: RunnerHello,
        protocol_limits: &ProtocolLimits,
    ) -> Result<Self, PrepareError> {
        Self::prepare(
            RunnerToServer::Hello(hello),
            ControlRoute::Handshake,
            None,
            protocol_limits,
        )
    }

    /// Validates and canonically encodes a post-handshake request once.
    ///
    /// The explicit negotiated session is retained with the canonical bytes so
    /// every response can be rejected before journaling if its protocol,
    /// session, or offered `JobIR` version crosses that binding.
    ///
    /// # Errors
    ///
    /// Returns [`PrepareError`] if `message` is a hello, if its request header
    /// does not match `session`, or if validation/encoding fails.
    pub fn for_session(
        message: RunnerToServer,
        session: NegotiatedSession,
        protocol_limits: &ProtocolLimits,
    ) -> Result<Self, PrepareError> {
        let binding = SessionBinding::from_negotiated(session);
        let header = sync_header(&message).ok_or(PrepareError::WrongRoute)?;
        header
            .validate_request()
            .map_err(|_| PrepareError::SessionMismatch)?;
        if header.protocol_version() != binding.protocol_version()
            || header.session_id() != binding.session_id()
            || !automata_ci_core::JobIrVersionRange::current().supports(binding.job_ir_version())
        {
            return Err(PrepareError::SessionMismatch);
        }
        Self::prepare(message, ControlRoute::Sync, Some(binding), protocol_limits)
    }

    fn prepare(
        message: RunnerToServer,
        route: ControlRoute,
        session: Option<SessionBinding>,
        protocol_limits: &ProtocolLimits,
    ) -> Result<Self, PrepareError> {
        let operation_id = operation_id(&message);
        let canonical_bytes =
            automata_ci_protocol_protobuf::encode_runner_frame(&message, protocol_limits)
                .map(Bytes::from)
                .map_err(PrepareError::InvalidMessage)?;
        Ok(Self {
            route,
            operation_id,
            message,
            canonical_bytes,
            session,
        })
    }

    /// Returns the fixed route selected from the message kind.
    #[must_use]
    pub const fn route(&self) -> ControlRoute {
        self.route
    }

    /// Returns the operation identifier retained across retries.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the validated construction shape used to create the bytes.
    #[must_use]
    pub const fn message(&self) -> &RunnerToServer {
        &self.message
    }

    /// Returns the exact canonical bytes reused by every retry.
    #[must_use]
    pub const fn canonical_bytes(&self) -> &Bytes {
        &self.canonical_bytes
    }

    /// Returns the negotiated binding required by sync requests.
    #[must_use]
    pub const fn session_binding(&self) -> Option<SessionBinding> {
        self.session
    }
}

fn sync_header(message: &RunnerToServer) -> Option<MessageHeader> {
    match message {
        RunnerToServer::Hello(_) => None,
        RunnerToServer::LeaseRequest(value) => Some(value.header()),
        RunnerToServer::LeaseResponse(value) => Some(value.header()),
        RunnerToServer::Heartbeat(value) => Some(value.header()),
        RunnerToServer::JobState(value) => Some(value.header()),
        RunnerToServer::JobResult(value) => Some(value.header()),
        RunnerToServer::LogBatch(value) => Some(value.header()),
        RunnerToServer::CommandAck(value) => Some(value.header()),
    }
}

impl fmt::Debug for PreparedRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedRequest")
            .field("route", &self.route)
            .field("operation_id", &self.operation_id)
            .field("canonical_byte_count", &self.canonical_bytes.len())
            .finish_non_exhaustive()
    }
}

fn operation_id(message: &RunnerToServer) -> OperationId {
    match message {
        RunnerToServer::Hello(value) => value.operation_id(),
        RunnerToServer::LeaseRequest(value) => value.header().operation_id(),
        RunnerToServer::LeaseResponse(value) => value.header().operation_id(),
        RunnerToServer::Heartbeat(value) => value.header().operation_id(),
        RunnerToServer::JobState(value) => value.header().operation_id(),
        RunnerToServer::JobResult(value) => value.header().operation_id(),
        RunnerToServer::LogBatch(value) => value.header().operation_id(),
        RunnerToServer::CommandAck(value) => value.header().operation_id(),
    }
}
