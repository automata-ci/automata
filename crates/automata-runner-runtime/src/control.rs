use std::{fmt, future::Future, pin::Pin, sync::Arc};

use automata_protocol::{ProtocolLimits, ServerToRunner, ValidatedServerToRunner};
use automata_runner_transport::{
    ClientErrorKind, PreparedRequest, RetryClass, RunnerControlClient,
};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

/// Validated server response and its canonical protobuf representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeControlReply {
    message: ValidatedServerToRunner,
    canonical_bytes: Vec<u8>,
}

impl RuntimeControlReply {
    /// Builds a canonical reply for deterministic adapters and tests.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeControlReplyError`] if the message violates domain or
    /// resource limits.
    pub fn from_message(
        message: ServerToRunner,
        limits: &ProtocolLimits,
    ) -> Result<Self, RuntimeControlReplyError> {
        let canonical_bytes = automata_protocol_protobuf::encode_server_frame(&message, limits)
            .map_err(RuntimeControlReplyError::Encode)?;
        let message = ValidatedServerToRunner::new(message, limits)
            .map_err(RuntimeControlReplyError::Validation)?;
        Ok(Self {
            message,
            canonical_bytes,
        })
    }

    pub(crate) fn from_transport(reply: automata_runner_transport::ControlReply) -> Self {
        let (message, canonical_bytes) = reply.into_parts();
        Self {
            message,
            canonical_bytes: canonical_bytes.to_vec(),
        }
    }

    /// Returns the validated domain message.
    #[must_use]
    pub const fn message(&self) -> &ValidatedServerToRunner {
        &self.message
    }

    /// Returns the exact canonical server protobuf bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

/// Failure while constructing a scripted canonical control reply.
#[derive(Debug, Error)]
pub enum RuntimeControlReplyError {
    /// Canonical protobuf conversion failed.
    #[error("runtime control reply encoding failed")]
    Encode(#[source] automata_protocol_protobuf::EncodeError),
    /// Domain validation failed.
    #[error("runtime control reply validation failed")]
    Validation(#[source] automata_protocol::MessageValidationError),
}

/// Retry disposition returned by the runtime-level control port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeControlRetry {
    /// The identical [`PreparedRequest`] may be submitted again.
    SamePreparedRequest,
    /// The failure is terminal for this request.
    Never,
}

/// Sanitized runtime control-client failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeControlErrorKind {
    /// Transport or peer availability failed.
    Unavailable,
    /// A bounded request deadline elapsed.
    TimedOut,
    /// The caller cancelled the exchange.
    Cancelled,
    /// The peer response violated the transport/protobuf contract.
    InvalidResponse,
}

/// Constructible, secret-free failure for runtime transport adapters.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("runner runtime control exchange failed")]
pub struct RuntimeControlError {
    kind: RuntimeControlErrorKind,
    retry: RuntimeControlRetry,
}

impl RuntimeControlError {
    /// Creates a sanitized failure with an explicit exact-request retry policy.
    #[must_use]
    pub const fn new(kind: RuntimeControlErrorKind, retry: RuntimeControlRetry) -> Self {
        Self { kind, retry }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(self) -> RuntimeControlErrorKind {
        self.kind
    }

    /// Returns the exact-request retry disposition.
    #[must_use]
    pub const fn retry(self) -> RuntimeControlRetry {
        self.retry
    }
}

/// Boxed future returned by [`RunnerRuntimeControlClient`].
pub type RuntimeControlFuture<'a> =
    Pin<Box<dyn Future<Output = Result<RuntimeControlReply, RuntimeControlError>> + Send + 'a>>;

/// Testable object-safe runner control boundary.
pub trait RunnerRuntimeControlClient: fmt::Debug + Send + Sync {
    /// Exchanges an immutable prepared request.
    ///
    /// Retrying callers always pass the same borrowed object, preserving its
    /// operation ID and canonical bytes exactly. Implementations are a trusted
    /// server-authentication boundary: production adapters must authenticate
    /// the control-plane peer before returning a reply. The bundled transport
    /// adapter does so with explicitly configured rustls roots and mTLS.
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a>;
}

/// Production adapter over the mTLS/HTTP2 [`RunnerControlClient`].
pub struct TransportControlClientAdapter {
    inner: Arc<dyn RunnerControlClient>,
}

impl TransportControlClientAdapter {
    /// Wraps a configured transport client.
    #[must_use]
    pub const fn new(inner: Arc<dyn RunnerControlClient>) -> Self {
        Self { inner }
    }
}

impl fmt::Debug for TransportControlClientAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportControlClientAdapter")
            .field("inner", &"configured")
            .finish()
    }
}

impl RunnerRuntimeControlClient for TransportControlClientAdapter {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            self.inner
                .exchange(request, cancellation)
                .await
                .map(RuntimeControlReply::from_transport)
                .map_err(|error| {
                    let kind = match error.kind() {
                        ClientErrorKind::Timeout => RuntimeControlErrorKind::TimedOut,
                        ClientErrorKind::Cancelled => RuntimeControlErrorKind::Cancelled,
                        ClientErrorKind::InvalidResponse
                        | ClientErrorKind::ResponseTooLarge
                        | ClientErrorKind::InvalidProtobuf => {
                            RuntimeControlErrorKind::InvalidResponse
                        }
                        ClientErrorKind::Transport | ClientErrorKind::HttpStatus(_) => {
                            RuntimeControlErrorKind::Unavailable
                        }
                    };
                    let retry = match error.retry_class() {
                        RetryClass::RetrySameRequest => RuntimeControlRetry::SamePreparedRequest,
                        RetryClass::Never => RuntimeControlRetry::Never,
                    };
                    RuntimeControlError::new(kind, retry)
                })
        })
    }
}
