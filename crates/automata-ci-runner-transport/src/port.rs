use std::{fmt, future::Future, pin::Pin};

use automata_ci_auth::machine::AuthenticatedMachine;
use automata_ci_core::{JobIrVersion, RunnerSessionId};
use automata_ci_protocol::{
    NegotiatedSession, ProtocolVersion, ValidatedRunnerToServer, ValidatedServerToRunner,
};
use bytes::Bytes;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::{
    ApplicationError, ClientError, PreparedCertificateRenewalRequest, PreparedEphemeralRequest,
    PreparedRequest,
};

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
        dyn Future<Output = Result<automata_ci_protocol::ServerToRunner, ApplicationError>>
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

/// Freshly authenticated request on the private ephemeral-value route.
///
/// The body aggregate is bounded by the transport before construction and
/// zeroized when dropped. This type is intentionally non-cloneable and its
/// diagnostics never expose body bytes or authenticated identities. Network
/// framing remains owned by the TLS/HTTP implementation and is outside this
/// application's zeroization guarantee.
pub struct AuthenticatedRunnerEphemeralRequest {
    machine: AuthenticatedMachine,
    body: Zeroizing<Vec<u8>>,
    cancellation: CancellationToken,
}

impl AuthenticatedRunnerEphemeralRequest {
    pub(crate) const fn new(
        machine: AuthenticatedMachine,
        body: Zeroizing<Vec<u8>>,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            machine,
            body,
            cancellation,
        }
    }

    /// Returns the independently authenticated runner machine.
    #[must_use]
    pub const fn machine(&self) -> &AuthenticatedMachine {
        &self.machine
    }

    /// Exposes the bounded request only to the application decoder.
    #[must_use]
    pub fn expose_body(&self) -> &[u8] {
        &self.body
    }

    /// Returns request-scoped cancellation.
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }
}

impl fmt::Debug for AuthenticatedRunnerEphemeralRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedRunnerEphemeralRequest")
            .field("body", &"[REDACTED]")
            .field("cancelled", &self.cancellation.is_cancelled())
            .finish_non_exhaustive()
    }
}

/// Bounded value-bearing application reply owned in zeroizing memory until it
/// is transferred to the HTTP response boundary.
pub struct RunnerEphemeralReply(Zeroizing<Vec<u8>>);

impl RunnerEphemeralReply {
    /// Creates a non-empty reply within the private response ceiling.
    ///
    /// # Errors
    ///
    /// Rejects empty or oversized bytes and zeroizes rejected input.
    pub fn new(mut body: Vec<u8>) -> Result<Self, ApplicationError> {
        if body.is_empty() || body.len() > crate::MAX_EPHEMERAL_RESPONSE_BYTES {
            use zeroize::Zeroize as _;
            body.zeroize();
            return Err(ApplicationError::new(crate::ApplicationErrorKind::Internal));
        }
        Ok(Self(Zeroizing::new(body)))
    }

    pub(crate) fn into_body(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(std::mem::take(&mut *self.0))
    }
}

impl fmt::Debug for RunnerEphemeralReply {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RunnerEphemeralReply([REDACTED])")
    }
}

/// Boxed future returned by [`RunnerEphemeralHandler`].
pub type EphemeralHandlerFuture<'a> =
    Pin<Box<dyn Future<Output = Result<RunnerEphemeralReply, ApplicationError>> + Send + 'a>>;

/// Private mTLS application port for ephemeral runner values.
pub trait RunnerEphemeralHandler: fmt::Debug + Send + Sync {
    /// Handles one freshly authenticated bounded request.
    fn handle(&self, request: AuthenticatedRunnerEphemeralRequest) -> EphemeralHandlerFuture<'_>;
}

/// Bounded application-owned response from the private ephemeral route.
///
/// The aggregate is non-cloneable, redacted in diagnostics, and zeroized on
/// drop. TLS and HTTP frame buffers remain outside this guarantee.
pub struct RunnerEphemeralResponse(Zeroizing<Vec<u8>>);

impl RunnerEphemeralResponse {
    pub(crate) const fn new(body: Zeroizing<Vec<u8>>) -> Self {
        Self(body)
    }

    /// Creates a bounded response for alternate client adapters and tests.
    ///
    /// # Errors
    ///
    /// Rejects and zeroizes an empty or oversized aggregate.
    pub fn from_body(mut body: Vec<u8>) -> Result<Self, crate::PrepareEphemeralError> {
        if body.is_empty() || body.len() > crate::MAX_EPHEMERAL_RESPONSE_BYTES {
            use zeroize::Zeroize as _;
            body.zeroize();
            return Err(crate::PrepareEphemeralError);
        }
        Ok(Self(Zeroizing::new(body)))
    }

    /// Exposes the response only to the caller's private wire decoder.
    #[must_use]
    pub fn expose_body(&self) -> &[u8] {
        &self.0
    }

    /// Transfers the aggregate into the next zeroizing custody boundary.
    #[must_use]
    pub fn into_body(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(std::mem::take(&mut *self.0))
    }
}

impl fmt::Debug for RunnerEphemeralResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RunnerEphemeralResponse([REDACTED])")
    }
}

/// Boxed future returned by [`RunnerEphemeralClient`].
pub type EphemeralClientFuture<'a> =
    Pin<Box<dyn Future<Output = Result<RunnerEphemeralResponse, ClientError>> + Send + 'a>>;

/// Object-safe outbound client for the dedicated mTLS ephemeral-value route.
pub trait RunnerEphemeralClient: fmt::Debug + Send + Sync {
    /// Exchanges the exact same prepared bytes across ambiguous transport loss.
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedEphemeralRequest,
        cancellation: CancellationToken,
    ) -> EphemeralClientFuture<'a>;
}

/// Freshly authenticated request on the certificate-renewal route.
///
/// The bounded body is zeroized on drop and diagnostics expose neither its
/// contents nor the authenticated machine identity.
pub struct AuthenticatedRunnerCertificateRenewalRequest {
    machine: AuthenticatedMachine,
    body: Zeroizing<Vec<u8>>,
    cancellation: CancellationToken,
}

impl AuthenticatedRunnerCertificateRenewalRequest {
    pub(crate) const fn new(
        machine: AuthenticatedMachine,
        body: Zeroizing<Vec<u8>>,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            machine,
            body,
            cancellation,
        }
    }

    /// Decomposes the request without copying authenticated or body state.
    #[must_use]
    pub fn into_parts(self) -> (AuthenticatedMachine, Zeroizing<Vec<u8>>, CancellationToken) {
        (self.machine, self.body, self.cancellation)
    }
}

impl fmt::Debug for AuthenticatedRunnerCertificateRenewalRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedRunnerCertificateRenewalRequest")
            .field("body", &"[REDACTED]")
            .field("cancelled", &self.cancellation.is_cancelled())
            .finish_non_exhaustive()
    }
}

/// Bounded exact certificate-renewal response retained in zeroizing memory.
pub struct RunnerCertificateRenewalReply(Zeroizing<Vec<u8>>);

impl RunnerCertificateRenewalReply {
    /// Creates one non-empty response inside the fixed route ceiling.
    ///
    /// # Errors
    ///
    /// Rejects and zeroizes empty or oversized bytes.
    pub fn new(mut body: Vec<u8>) -> Result<Self, ApplicationError> {
        if body.is_empty() || body.len() > crate::MAX_CERTIFICATE_RENEWAL_RESPONSE_BYTES {
            use zeroize::Zeroize as _;
            body.zeroize();
            return Err(ApplicationError::new(crate::ApplicationErrorKind::Internal));
        }
        Ok(Self(Zeroizing::new(body)))
    }

    pub(crate) fn into_body(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(std::mem::take(&mut *self.0))
    }
}

impl fmt::Debug for RunnerCertificateRenewalReply {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RunnerCertificateRenewalReply([REDACTED])")
    }
}

/// Boxed future returned by [`RunnerCertificateRenewalHandler`].
pub type CertificateRenewalHandlerFuture<'a> = Pin<
    Box<dyn Future<Output = Result<RunnerCertificateRenewalReply, ApplicationError>> + Send + 'a>,
>;

/// Application port for the authenticated certificate-renewal route.
pub trait RunnerCertificateRenewalHandler: fmt::Debug + Send + Sync {
    /// Handles one freshly authenticated, bounded, opaque request.
    fn handle(
        &self,
        request: AuthenticatedRunnerCertificateRenewalRequest,
    ) -> CertificateRenewalHandlerFuture<'_>;
}

/// Bounded response returned by the certificate-renewal client.
pub struct RunnerCertificateRenewalResponse(Zeroizing<Vec<u8>>);

impl RunnerCertificateRenewalResponse {
    pub(crate) const fn new(body: Zeroizing<Vec<u8>>) -> Self {
        Self(body)
    }

    /// Transfers the response into the next zeroizing custody boundary.
    #[must_use]
    pub fn into_body(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(std::mem::take(&mut *self.0))
    }
}

impl fmt::Debug for RunnerCertificateRenewalResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RunnerCertificateRenewalResponse([REDACTED])")
    }
}

/// Boxed future returned by [`RunnerCertificateRenewalClient`].
pub type CertificateRenewalClientFuture<'a> = Pin<
    Box<dyn Future<Output = Result<RunnerCertificateRenewalResponse, ClientError>> + Send + 'a>,
>;

/// Object-safe client for exact certificate-renewal retries.
pub trait RunnerCertificateRenewalClient: fmt::Debug + Send + Sync {
    /// Exchanges the same durably prepared request bytes until one outcome is known.
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedCertificateRenewalRequest,
        cancellation: CancellationToken,
    ) -> CertificateRenewalClientFuture<'a>;
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
