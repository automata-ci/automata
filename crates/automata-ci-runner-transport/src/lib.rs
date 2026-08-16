#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Dedicated mTLS and HTTP/2 transport for `automata.runner.v1`.
//!
//! This crate is deliberately transport-only. It does not import a database
//! adapter and it retains no replica-local runner session state. Every request
//! is authenticated from the certificate chain on its rustls connection and
//! is passed to the application port with the claimed runner/session fields so
//! shared durable state can fence it independently.
//!
//! The listener must be separate from any human-facing HTTP listener. A reverse
//! proxy cannot terminate runner mTLS for this implementation: certificate
//! forwarding headers are ordinary untrusted request data and are never read.
//! Supporting proxy termination in the future requires a distinct authenticated
//! transport adapter and an explicit cryptographic trust contract.

mod client;
mod error;
mod limits;
mod managed_secret_delivery;
mod observer;
mod port;
mod prepared;
mod server;
mod tls;

pub use client::{
    HyperRunnerCertificateRenewalClient, HyperRunnerControlClient, HyperRunnerEphemeralClient,
};
pub use error::{
    ApplicationError, ApplicationErrorKind, ClientError, ClientErrorKind, ConfigurationError,
    RetryClass, ServeError,
};
pub use limits::TransportLimits;
pub use managed_secret_delivery::{
    ManagedSecretDeliveryBinding, ManagedSecretDeliveryCoordinates, ManagedSecretDeliveryOperation,
    ManagedSecretDeliveryRequest, ManagedSecretDeliveryResponse, ManagedSecretDeliveryValue,
    ManagedSecretDeliveryWireError,
};
pub use observer::{
    NoopRunnerControlClientObserver, NoopRunnerTransportObserver, RunnerControlClientByteDirection,
    RunnerControlClientObserver, RunnerTransportApplicationRejection,
    RunnerTransportAuthenticationRejection, RunnerTransportBodyRejection,
    RunnerTransportByteDirection, RunnerTransportConnectionEvent, RunnerTransportDecodeRejection,
    RunnerTransportHeadRejection, RunnerTransportObserver, RunnerTransportRequestObservation,
    RunnerTransportResponseRejection, RunnerTransportRoute, RunnerTransportTlsOutcome,
};
pub use port::{
    AuthenticatedRunnerCertificateRenewalRequest, AuthenticatedRunnerEphemeralRequest,
    AuthenticatedRunnerRequest, CertificateRenewalClientFuture, CertificateRenewalHandlerFuture,
    ClientFuture, ControlReply, ControlRoute, EphemeralClientFuture, EphemeralHandlerFuture,
    HandlerFuture, RunnerCertificateRenewalClient, RunnerCertificateRenewalHandler,
    RunnerCertificateRenewalReply, RunnerCertificateRenewalResponse, RunnerControlClient,
    RunnerControlHandler, RunnerEphemeralClient, RunnerEphemeralHandler, RunnerEphemeralReply,
    RunnerEphemeralResponse, SessionBinding,
};
pub use prepared::{
    PrepareCertificateRenewalError, PrepareEphemeralError, PrepareError,
    PreparedCertificateRenewalRequest, PreparedEphemeralRequest, PreparedRequest,
};
pub use server::RunnerControlServer;
pub use tls::{ClientTlsConfig, ServerTlsConfig};

/// Exact protobuf media type accepted on runner-control routes.
pub const PROTOBUF_CONTENT_TYPE: &str = "application/protobuf";

/// Pre-negotiation runner handshake endpoint.
pub const HANDSHAKE_PATH: &str = "/automata.runner.v1.RunnerControl/Handshake";

/// Post-handshake request/reply and long-poll endpoint.
pub const SYNC_PATH: &str = "/automata.runner.v1.RunnerControl/Sync";

/// Private value-bearing route on the dedicated mTLS runner listener.
pub const EPHEMERAL_SECRETS_PATH: &str = "/automata.runner.v1.RunnerEphemeralSecrets/Exchange";

/// Exact media type for the bounded ephemeral-secret binary contract.
pub const EPHEMERAL_SECRETS_CONTENT_TYPE: &str =
    "application/vnd.automata.runner-ephemeral-secrets.v1";

/// Maximum request bytes admitted on the ephemeral-secret route.
pub const MAX_EPHEMERAL_REQUEST_BYTES: usize = 128 * 1024;

/// Maximum response bytes admitted on the ephemeral-secret route.
pub const MAX_EPHEMERAL_RESPONSE_BYTES: usize = 1024 * 1024;

/// Certificate-renewal route on the dedicated runner mTLS listener.
pub const CERTIFICATE_RENEWAL_PATH: &str = "/automata.runner.v1.RunnerCertificateRenewal/Renew";

/// Exact media type for the current bounded renewal document.
pub const CERTIFICATE_RENEWAL_CONTENT_TYPE: &str =
    "application/vnd.automata.runner-certificate-renewal.v1+json";

/// Maximum CSR-bearing renewal request bytes.
pub const MAX_CERTIFICATE_RENEWAL_REQUEST_BYTES: usize = 64 * 1024;

/// Maximum PEM-bearing exact renewal response bytes.
pub const MAX_CERTIFICATE_RENEWAL_RESPONSE_BYTES: usize = 512 * 1024;

/// Stable verifier-key identity for managed-secret delivery bearer digests.
pub const MANAGED_SECRET_DELIVERY_CREDENTIAL_KEY_ID: &str = "managed-secret-delivery-v1";
