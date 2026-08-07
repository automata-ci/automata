use std::{fmt, future::Future, pin::Pin};

use automata_auth::machine::AuthenticatedMachine;
use automata_core::{JobIrVersion, RunnerSessionId};
use automata_protocol::{
    NegotiatedSession, ProtocolVersion, ValidatedRunnerToServer, ValidatedServerToRunner,
};
use bytes::Bytes;
use tokio_util::sync::CancellationToken;

use crate::{ApplicationError, ClientError, PreparedRequest};

/// Immutable protocol, `JobIR`, and session identity selected by a successful handshake.
///
/// This binding is carried into every prepared sync request and is checked again
/// on every response. It contains no replica-local connection identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionBinding {
    protocol_version: ProtocolVersion,
    job_ir_version: JobIrVersion,
    session_id: RunnerSessionId,
}

impl SessionBinding {
    /// Derives a transport binding from a validated negotiated session.
    #[must_use]
    pub const fn from_negotiated(session: NegotiatedSession) -> Self {
        Self {
            protocol_version: session.selected_protocol(),
            job_ir_version: session.selected_job_ir(),
            session_id: session.session_id(),
        }
    }

    /// Returns the exact negotiated runner protocol version.
    #[must_use]
    pub const fn protocol_version(self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns the exact negotiated `JobIR` version.
    #[must_use]
    pub const fn job_ir_version(self) -> JobIrVersion {
        self.job_ir_version
    }

    /// Returns the exact durable runner session identifier.
    #[must_use]
    pub const fn session_id(self) -> RunnerSessionId {
        self.session_id
    }
}

/// Stable route selected from a validated runner request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlRoute {
    /// Pre-negotiation `RunnerHello` exchange.
    Handshake,
    /// Post-negotiation request/reply or long poll.
    Sync,
}

impl ControlRoute {
    pub(crate) const fn path(self) -> &'static str {
        match self {
            Self::Handshake => crate::HANDSHAKE_PATH,
            Self::Sync => crate::SYNC_PATH,
        }
    }
}

/// Fully authenticated and decoded input passed to application code.
///
/// Application implementations must use the authenticated machine to map the
/// durable runner and must fence every post-handshake session claim against
/// shared state. The transport keeps no connection-affine authorization cache.
pub struct AuthenticatedRunnerRequest {
    machine: AuthenticatedMachine,
    message: ValidatedRunnerToServer,
    canonical_bytes: Bytes,
    cancellation: CancellationToken,
}

impl AuthenticatedRunnerRequest {
    pub(crate) const fn new(
        machine: AuthenticatedMachine,
        message: ValidatedRunnerToServer,
        canonical_bytes: Bytes,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            machine,
            message,
            canonical_bytes,
            cancellation,
        }
    }

    /// Returns the independently authenticated machine assertion for this request.
    #[must_use]
    pub const fn machine(&self) -> &AuthenticatedMachine {
        &self.machine
    }

    /// Returns the validated domain message, including runner and session claims.
    #[must_use]
    pub const fn message(&self) -> &ValidatedRunnerToServer {
        &self.message
    }

    /// Returns the deterministic canonical protobuf used for receipt hashing.
    #[must_use]
    pub const fn canonical_bytes(&self) -> &Bytes {
        &self.canonical_bytes
    }

    /// Returns a cancellation token that fires if the request future is dropped,
    /// its connection is shut down, or the listener begins shutdown.
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    /// Decomposes the authenticated request into owned parts.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        AuthenticatedMachine,
        ValidatedRunnerToServer,
        Bytes,
        CancellationToken,
    ) {
        (
            self.machine,
            self.message,
            self.canonical_bytes,
            self.cancellation,
        )
    }
}

impl fmt::Debug for AuthenticatedRunnerRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedRunnerRequest")
            .field("machine", &self.machine)
            .field("canonical_byte_count", &self.canonical_bytes.len())
            .field("cancelled", &self.cancellation.is_cancelled())
            .finish_non_exhaustive()
    }
}

/// Boxed future returned by [`RunnerControlHandler`].
pub type HandlerFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<automata_protocol::ServerToRunner, ApplicationError>>
            + Send
            + 'a,
    >,
>;

/// Replica-neutral application port for runner control operations.
///
/// Both methods receive a fresh machine authentication result. Implementations
/// must authorize and fence the advertised runner/session against shared state
/// inside each call; a previous call or TLS connection is not an authorization.
pub trait RunnerControlHandler: fmt::Debug + Send + Sync {
    /// Handles one decoded pre-negotiation hello.
    fn handshake(&self, request: AuthenticatedRunnerRequest) -> HandlerFuture<'_>;

    /// Handles one decoded post-handshake operation or long poll.
    fn sync(&self, request: AuthenticatedRunnerRequest) -> HandlerFuture<'_>;
}

/// Validated server response together with its canonical protobuf bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct ControlReply {
    message: ValidatedServerToRunner,
    canonical_bytes: Bytes,
}

impl fmt::Debug for ControlReply {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlReply")
            .field("canonical_byte_count", &self.canonical_bytes.len())
            .finish_non_exhaustive()
    }
}

impl ControlReply {
    pub(crate) const fn new(message: ValidatedServerToRunner, canonical_bytes: Bytes) -> Self {
        Self {
            message,
            canonical_bytes,
        }
    }

    /// Returns the validated server message.
    #[must_use]
    pub const fn message(&self) -> &ValidatedServerToRunner {
        &self.message
    }

    /// Returns deterministic canonical protobuf response bytes.
    #[must_use]
    pub const fn canonical_bytes(&self) -> &Bytes {
        &self.canonical_bytes
    }

    /// Decomposes the reply into its validated message and canonical bytes.
    #[must_use]
    pub fn into_parts(self) -> (ValidatedServerToRunner, Bytes) {
        (self.message, self.canonical_bytes)
    }
}

/// Boxed future returned by [`RunnerControlClient`].
pub type ClientFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ControlReply, ClientError>> + Send + 'a>>;

/// Object-safe outbound runner-control client port.
pub trait RunnerControlClient: fmt::Debug + Send + Sync {
    /// Exchanges one already-prepared request.
    ///
    /// Retries must call this method again with the same `PreparedRequest` so
    /// the operation identifier and canonical protobuf bytes cannot change.
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        cancellation: CancellationToken,
    ) -> ClientFuture<'a>;
}
