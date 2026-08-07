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
mod port;
mod prepared;
mod server;
mod tls;

pub use client::HyperRunnerControlClient;
pub use error::{
    ApplicationError, ApplicationErrorKind, ClientError, ClientErrorKind, ConfigurationError,
    RetryClass, ServeError,
};
pub use limits::TransportLimits;
pub use port::{
    AuthenticatedRunnerRequest, ClientFuture, ControlReply, ControlRoute, HandlerFuture,
    RunnerControlClient, RunnerControlHandler, SessionBinding,
};
pub use prepared::{PrepareError, PreparedRequest};
pub use server::RunnerControlServer;
pub use tls::{ClientTlsConfig, ServerTlsConfig, TlsVersionPolicy};

/// Exact protobuf media type accepted on runner-control routes.
pub const PROTOBUF_CONTENT_TYPE: &str = "application/protobuf";

/// Pre-negotiation runner handshake endpoint.
pub const HANDSHAKE_PATH: &str = "/automata.runner.v1.RunnerControl/Handshake";

/// Post-handshake request/reply and long-poll endpoint.
pub const SYNC_PATH: &str = "/automata.runner.v1.RunnerControl/Sync";
