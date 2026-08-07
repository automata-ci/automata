//! Backoff and typed remote error responses.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::MessageHeader;

/// Poll response indicating that no compatible work is currently available.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NoWork {
    header: MessageHeader,
    retry_after_millis: u32,
}

impl NoWork {
    #[must_use]
    pub const fn new(header: MessageHeader, retry_after_millis: u32) -> Self {
        Self {
            header,
            retry_after_millis,
        }
    }

    #[must_use]
    pub const fn header(&self) -> MessageHeader {
        self.header
    }

    #[must_use]
    pub const fn retry_after_millis(&self) -> u32 {
        self.retry_after_millis
    }
}

/// Stable remote error codes; callers must not parse the human message.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteErrorCode {
    InvalidMessage,
    UnsupportedProtocol,
    UnsupportedJobIr,
    Unauthenticated,
    Unauthorized,
    SessionNotFound,
    StaleSession,
    InvalidSlot,
    OperationKeyReused,
    CommandCursorConflict,
    LeaseNotFound,
    StaleFencingToken,
    Conflict,
    RetryLater,
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
    pub const fn header(&self) -> MessageHeader {
        self.header
    }

    #[must_use]
    pub const fn code(&self) -> RemoteErrorCode {
        self.code
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        self.retryable
    }

    #[must_use]
    pub const fn details(&self) -> &BTreeMap<String, String> {
        &self.details
    }

    #[must_use]
    pub fn with_details(mut self, details: BTreeMap<String, String>) -> Self {
        self.details = details;
        self
    }
}
