use std::fmt;

use automata_ci_core::{OperationId, Sha256Digest, UnixMillis};
use thiserror::Error;
use zeroize::Zeroize as _;

use crate::{DocumentSchema, RunnerSessionFence, value::sha256_digest};

const MAX_OPERATION_KIND_BYTES: usize = 128;
const MAX_RECEIPT_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Stable, namespaced kind for a retryable runner mutation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RunnerOperationKind(String);

impl RunnerOperationKind {
    /// Creates a lowercase namespaced operation kind.
    ///
    /// # Errors
    ///
    /// Rejects empty/oversized values and characters outside
    /// `[a-z0-9._/-]`.
    pub fn new(value: impl Into<String>) -> Result<Self, RunnerReceiptValueError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_OPERATION_KIND_BYTES {
            return Err(RunnerReceiptValueError::InvalidOperationKind);
        }
        if !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'_' | b'/' | b'-'))
        }) {
            return Err(RunnerReceiptValueError::InvalidOperationKind);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Identity of a generic retryable runner operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerOperationRequest {
    session: RunnerSessionFence,
    operation_id: OperationId,
    kind: RunnerOperationKind,
    request_digest: Sha256Digest,
}

impl RunnerOperationRequest {
    #[must_use]
    pub const fn new(
        session: RunnerSessionFence,
        operation_id: OperationId,
        kind: RunnerOperationKind,
        request_digest: Sha256Digest,
    ) -> Self {
        Self {
            session,
            operation_id,
            kind,
            request_digest,
        }
    }

    #[must_use]
    pub const fn session(&self) -> RunnerSessionFence {
        self.session
    }

    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn kind(&self) -> &RunnerOperationKind {
        &self.kind
    }

    #[must_use]
    pub const fn request_digest(&self) -> Sha256Digest {
        self.request_digest
    }
}

/// Exact bounded response retained for retry replay.
#[derive(Clone, Eq, PartialEq)]
pub struct RunnerOperationResponse {
    schema: DocumentSchema,
    digest: Sha256Digest,
    payload: Vec<u8>,
}

impl fmt::Debug for RunnerOperationResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunnerOperationResponse")
            .field("schema", &self.schema)
            .field("digest", &self.digest)
            .field("size", &self.payload.len())
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

impl Drop for RunnerOperationResponse {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}

impl RunnerOperationResponse {
    /// Creates an exact response and computes its content digest.
    ///
    /// # Errors
    ///
    /// Rejects empty responses and responses over 16 MiB.
    pub fn new(
        schema: DocumentSchema,
        mut payload: Vec<u8>,
    ) -> Result<Self, RunnerReceiptValueError> {
        if payload.is_empty() || payload.len() > MAX_RECEIPT_RESPONSE_BYTES {
            let size = payload.len();
            payload.zeroize();
            return Err(RunnerReceiptValueError::InvalidResponseSize {
                size,
                maximum: MAX_RECEIPT_RESPONSE_BYTES,
            });
        }
        let digest = sha256_digest(&payload);
        Ok(Self {
            schema,
            digest,
            payload,
        })
    }

    #[must_use]
    pub const fn schema(&self) -> DocumentSchema {
        self.schema
    }

    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Exact generic operation receipt loaded on a retry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerOperationReceipt {
    request: RunnerOperationRequest,
    response: RunnerOperationResponse,
    committed_at: UnixMillis,
    replayed: bool,
}

impl RunnerOperationReceipt {
    #[must_use]
    pub const fn new(
        request: RunnerOperationRequest,
        response: RunnerOperationResponse,
        committed_at: UnixMillis,
        replayed: bool,
    ) -> Self {
        Self {
            request,
            response,
            committed_at,
            replayed,
        }
    }

    #[must_use]
    pub const fn request(&self) -> &RunnerOperationRequest {
        &self.request
    }

    #[must_use]
    pub const fn response(&self) -> &RunnerOperationResponse {
        &self.response
    }

    #[must_use]
    pub const fn committed_at(&self) -> UnixMillis {
        self.committed_at
    }

    #[must_use]
    pub const fn was_replayed(&self) -> bool {
        self.replayed
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RunnerReceiptValueError {
    #[error("runner operation kind must be 1..=128 lowercase namespaced bytes")]
    InvalidOperationKind,
    #[error("runner operation response has {size} bytes; expected 1..={maximum}")]
    InvalidResponseSize { size: usize, maximum: usize },
}
