use http::StatusCode;
use thiserror::Error;

/// Sanitized startup configuration failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ConfigurationError {
    /// A configured size, concurrency, or duration limit was zero or unrepresentable.
    #[error("a transport limit is invalid")]
    InvalidLimit,
    /// Related resource or time limits contradict one another.
    #[error("transport limits are incoherent")]
    IncoherentLimits,
    /// The supplied root set was empty or contained an invalid certificate.
    #[error("a TLS trust store is invalid")]
    InvalidTrustStore,
    /// The certificate chain or private key could not form an identity.
    #[error("a TLS identity is invalid")]
    InvalidIdentity,
    /// The selected TLS versions are unavailable from the reviewed provider.
    #[error("the TLS version policy is unavailable")]
    InvalidTlsPolicy,
    /// The control endpoint was not a simple HTTPS origin.
    #[error("the runner control endpoint is invalid")]
    InvalidEndpoint,
    /// Transport body limits exceed the protocol decoder's hard frame budget.
    #[error("transport body limits exceed protocol limits")]
    ProtocolLimitMismatch,
}

/// Error category returned by the application handler port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationErrorKind {
    /// The authenticated runner is not authorized for the claimed operation.
    Forbidden,
    /// The claimed durable session is absent or no longer current.
    StaleSession,
    /// Durable state rejected a conflicting operation or fencing token.
    Conflict,
    /// Shared application state is temporarily unavailable.
    Unavailable,
    /// An internal failure occurred without exposing implementation detail.
    Internal,
}

/// Sanitized failure from the application handler.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("runner control handling failed")]
pub struct ApplicationError {
    kind: ApplicationErrorKind,
}

impl ApplicationError {
    /// Creates a sanitized application failure with a stable category.
    #[must_use]
    pub const fn new(kind: ApplicationErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(self) -> ApplicationErrorKind {
        self.kind
    }
}

/// Whether the identical prepared request may be retried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryClass {
    /// The exact same canonical bytes may be submitted again.
    RetrySameRequest,
    /// The failure is semantic or violates the transport contract and must not be retried.
    Never,
}

/// Sanitized runner-client failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientErrorKind {
    /// Admission or transport I/O failed before a valid response arrived.
    Transport,
    /// The configured total or body-read deadline expired.
    Timeout,
    /// The operation was explicitly cancelled.
    Cancelled,
    /// The peer returned a non-success HTTP status.
    HttpStatus(StatusCode),
    /// The successful response violated required HTTP framing.
    InvalidResponse,
    /// The successful response exceeded the configured byte ceiling.
    ResponseTooLarge,
    /// The successful response was not a valid server protobuf frame.
    InvalidProtobuf,
}

/// Sanitized error from the outbound runner client.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("runner control request failed")]
pub struct ClientError {
    kind: ClientErrorKind,
    retry: RetryClass,
}

impl ClientError {
    pub(crate) const fn new(kind: ClientErrorKind, retry: RetryClass) -> Self {
        Self { kind, retry }
    }

    /// Returns the stable failure category without a URL, certificate, or secret.
    #[must_use]
    pub const fn kind(self) -> ClientErrorKind {
        self.kind
    }

    /// Returns whether only the identical [`crate::PreparedRequest`] is safe to retry.
    #[must_use]
    pub const fn retry_class(self) -> RetryClass {
        self.retry
    }
}

/// Fatal failure of the listener accept loop.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ServeError {
    /// Accepting a TCP connection failed.
    #[error("runner transport listener failed")]
    Listener,
}
