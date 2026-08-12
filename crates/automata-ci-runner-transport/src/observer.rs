use std::{fmt, time::Duration};

/// Direction of canonical body bytes at the outbound client boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerControlClientByteDirection {
    /// A validated request was admitted and dispatched to the HTTP transport.
    Request,
    /// A correlated response was fully validated and accepted by the client.
    Response,
}

/// Provider-neutral, infallible observation seam for the physical client.
///
/// Implementations must be non-blocking, must not panic, and must not retain
/// request, response, runner, session, operation, or endpoint identities.
pub trait RunnerControlClientObserver: fmt::Debug + Send + Sync {
    /// Records canonical bytes at a bounded outbound transport boundary.
    ///
    /// Request bytes are emitted only after request-size and client-admission
    /// checks, immediately before dispatch to the HTTP client. Response bytes
    /// are emitted only after framing, protobuf, and correlation validation.
    fn observe_bytes(&self, _direction: RunnerControlClientByteDirection, _bytes: u64) {}
}

/// Allocation-free observer used when outbound client metrics are not composed.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopRunnerControlClientObserver;

impl RunnerControlClientObserver for NoopRunnerControlClientObserver {}

/// Stable route known at the point a transport request finishes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerTransportRoute {
    /// Admission failed before a route could be trusted.
    Unknown,
    /// Pre-negotiation runner handshake.
    Handshake,
    /// Post-negotiation runner synchronization.
    Sync,
}

/// Bounded connection-lifecycle events emitted by the server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerTransportConnectionEvent {
    /// A TCP connection entered the bounded TLS task set.
    Admitted,
    /// The bounded connection task set was full.
    Overloaded,
    /// The HTTP/2 connection ended without a transport error.
    Http2Closed,
    /// The HTTP/2 connection ended with a transport error.
    Http2Error,
    /// Listener shutdown ended the connection.
    Shutdown,
    /// The listener drain deadline forcibly aborted a still-running connection
    /// task; this does not classify its TLS or HTTP/2 state.
    DrainAborted,
    /// The fixed connection lifetime ended the connection.
    LifetimeExpired,
}

/// Final outcome of one bounded TLS and peer-evidence admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerTransportTlsOutcome {
    /// TLS, HTTP/2 ALPN, and peer-certificate evidence were accepted.
    Accepted,
    /// The TLS handshake deadline elapsed.
    Timeout,
    /// Rustls rejected the peer or handshake.
    Rejected,
    /// The negotiated application protocol was not HTTP/2.
    InvalidProtocol,
    /// The authenticated TLS stream did not contain bounded peer evidence.
    InvalidPeerIdentity,
}

/// Closed request-head rejection categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerTransportHeadRejection {
    /// The request was not HTTP/2.
    HttpVersion,
    /// The request method was not `POST`.
    Method,
    /// The path or query did not name an exact control route.
    NotFound,
    /// The media type or content encoding was unsupported.
    UnsupportedMediaType,
    /// A content length was required.
    LengthRequired,
    /// The content length was ambiguous or non-canonical.
    InvalidContentLength,
    /// The declared request body exceeded the configured ceiling.
    BodyTooLarge,
}

/// Closed machine-authentication rejection categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerTransportAuthenticationRejection {
    /// The peer identity was not trusted.
    Untrusted,
    /// The peer identity had expired.
    Expired,
    /// The identity verifier was unavailable.
    Unavailable,
    /// The identity-verification deadline elapsed.
    Timeout,
}

/// Closed request-body rejection categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerTransportBodyRejection {
    /// Actual body bytes exceeded the declared or configured ceiling.
    TooLarge,
    /// Body framing or the declared length was invalid.
    Invalid,
    /// The HTTP body stream failed.
    Transport,
    /// The body-read deadline elapsed.
    Timeout,
}

/// Closed protobuf admission rejection categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerTransportDecodeRejection {
    /// The body was not a valid bounded runner protobuf frame.
    InvalidProtobuf,
    /// The decoded message kind did not match the fixed route.
    RouteMismatch,
    /// The validated request could not be encoded canonically.
    Canonicalization,
}

/// Closed application-boundary rejection categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerTransportApplicationRejection {
    /// The authenticated runner was forbidden.
    Forbidden,
    /// The application rejected a stale session or durable conflict.
    Conflict,
    /// Shared application state was unavailable.
    Unavailable,
    /// The application returned an internal failure.
    Internal,
    /// The bounded handler deadline elapsed.
    Timeout,
}

/// Closed response-boundary rejection categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerTransportResponseRejection {
    /// The application response did not correlate to the request.
    InvalidCorrelation,
    /// The validated response could not be encoded.
    Encoding,
    /// The encoded response exceeded the configured ceiling.
    TooLarge,
}

/// Final disposition of one physical HTTP/2 runner-control request.
///
/// Each request produces exactly one value. Variants encode the stage at which
/// processing stopped, so implementations cannot invent identifier-bearing or
/// unbounded labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerTransportRequestObservation {
    /// The request future was dropped before a response disposition completed.
    Cancelled {
        /// Route known before cancellation, if any.
        route: RunnerTransportRoute,
    },
    /// Bounded request admission timed out before the request head was read.
    AdmissionOverloaded,
    /// The request head failed validation.
    HeadRejected {
        /// Route known before the rejection, if any.
        route: RunnerTransportRoute,
        /// Stable rejection category.
        reason: RunnerTransportHeadRejection,
    },
    /// Fresh machine authentication failed.
    AuthenticationRejected {
        /// Validated fixed route.
        route: RunnerTransportRoute,
        /// Stable rejection category.
        reason: RunnerTransportAuthenticationRejection,
    },
    /// Bounded request-body collection failed.
    BodyRejected {
        /// Validated fixed route.
        route: RunnerTransportRoute,
        /// Stable rejection category.
        reason: RunnerTransportBodyRejection,
    },
    /// Protobuf validation or canonicalization failed.
    DecodeRejected {
        /// Validated fixed route.
        route: RunnerTransportRoute,
        /// Stable rejection category.
        reason: RunnerTransportDecodeRejection,
    },
    /// The application boundary rejected the request.
    ApplicationRejected {
        /// Validated fixed route.
        route: RunnerTransportRoute,
        /// Stable rejection category.
        reason: RunnerTransportApplicationRejection,
    },
    /// Response validation or encoding failed.
    ResponseRejected {
        /// Validated fixed route.
        route: RunnerTransportRoute,
        /// Stable rejection category.
        reason: RunnerTransportResponseRejection,
    },
    /// A correlated protobuf response was returned.
    Succeeded {
        /// Validated fixed route.
        route: RunnerTransportRoute,
    },
}

/// Direction of canonical HTTP body bytes at the transport boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerTransportByteDirection {
    /// Request body bytes read from a runner.
    Request,
    /// Response body bytes returned to a runner.
    Response,
}

/// Provider-neutral, infallible observation seam for the physical server.
///
/// Implementations must be non-blocking, must not panic, and must not retain
/// request, connection, certificate, runner, session, or operation identities.
pub trait RunnerTransportObserver: fmt::Debug + Send + Sync {
    /// Records one connection admission or terminal lifecycle event.
    fn observe_connection(&self, _event: RunnerTransportConnectionEvent) {}

    /// Records one final TLS/peer-evidence admission and its monotonic duration.
    fn observe_tls(&self, _outcome: RunnerTransportTlsOutcome, _duration: Duration) {}

    /// Records one final physical request disposition and total duration.
    fn observe_request(
        &self,
        _observation: RunnerTransportRequestObservation,
        _duration: Duration,
    ) {
    }

    /// Marks entry to the route-known in-flight request set.
    fn request_started(&self, _route: RunnerTransportRoute) {}

    /// Marks exit from the route-known in-flight request set.
    fn request_finished(&self, _route: RunnerTransportRoute) {}

    /// Records bounded physical request or response body bytes.
    fn observe_bytes(
        &self,
        _route: RunnerTransportRoute,
        _direction: RunnerTransportByteDirection,
        _bytes: u64,
    ) {
    }
}

/// Allocation-free observer used when transport metrics are not composed.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopRunnerTransportObserver;

impl RunnerTransportObserver for NoopRunnerTransportObserver {}
