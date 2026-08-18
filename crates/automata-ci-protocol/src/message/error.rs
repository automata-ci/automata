//! Backoff and typed remote error responses.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::MessageHeader;

/// Stable remote error codes; callers must not parse the human message.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteErrorCode {
    /// The decoded request violates schema or validation invariants.
    InvalidMessage,
    /// The requested protocol version is not supported.
    UnsupportedProtocol,
    /// The requested `JobIR` schema is not supported.
    UnsupportedJobIr,
    /// The peer could not be authenticated.
    Unauthenticated,
    /// The authenticated peer lacks authority for the operation.
    Unauthorized,
    /// The referenced runner session does not exist.
    SessionNotFound,
    /// The referenced session has been superseded or invalidated.
    StaleSession,
    /// The stable slot is outside the authenticated registration.
    InvalidSlot,
    /// An idempotency key was reused for different request content.
    OperationKeyReused,
    /// The runner and server disagree about durable command progress.
    CommandCursorConflict,
    /// The referenced lease or attempt does not exist.
    LeaseNotFound,
    /// The request carries a superseded lease fencing token.
    StaleFencingToken,
    /// Current durable state conflicts with the requested transition.
    Conflict,
    /// A transient condition requires a later retry.
    RetryLater,
    /// The server failed without a safe, more specific public classification.
    Internal,
}

/// Typed error response with optional machine-readable details.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ErrorMessage {
    header: MessageHeader,
    code: RemoteErrorCode,
    message: String,
    retryable: bool,
    details: BTreeMap<String, String>,
}

impl ErrorMessage {
    /// Creates a typed remote error with no detail entries.
    ///
    /// Human messages cross a trust boundary and must already be sanitized;
    /// callers must not include credentials, identifiers, or raw backend
    /// error text.
    #[must_use]
    pub fn new(
        header: MessageHeader,
        code: RemoteErrorCode,
        message: impl Into<String>,
        retryable: bool,
    ) -> Self {
        Self {
            header,
            code,
            message: message.into(),
            retryable,
            details: BTreeMap::new(),
        }
    }

    #[must_use]
    /// Returns the response header and its request correlation.
    pub const fn header(&self) -> MessageHeader {
        self.header
    }

    #[must_use]
    /// Returns the stable machine-readable error classification.
    pub const fn code(&self) -> RemoteErrorCode {
        self.code
    }

    #[must_use]
    /// Returns the sanitized human-readable explanation.
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    /// Returns whether the server considers replay safe after backoff.
    pub const fn is_retryable(&self) -> bool {
        self.retryable
    }

    #[must_use]
    /// Returns bounded machine-readable diagnostic fields.
    ///
    /// Consumers must treat keys as optional and must not parse
    /// [`Self::message`] for control flow.
    pub const fn details(&self) -> &BTreeMap<String, String> {
        &self.details
    }

    #[must_use]
    /// Replaces the machine-readable details carried with the error.
    ///
    /// Envelope validation applies collection and text ceilings. Producers
    /// remain responsible for excluding secrets and raw backend diagnostics.
    pub fn with_details(mut self, details: BTreeMap<String, String>) -> Self {
        self.details = details;
        self
    }
}
