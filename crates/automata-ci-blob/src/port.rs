use async_trait::async_trait;
use thiserror::Error;

use crate::{BlobDescriptor, BlobPayload, PutBlobOutcome, VerifiedBlob};

/// Provider-neutral class of a blob operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobStoreErrorKind {
    /// The requested immutable key does not exist.
    NotFound,
    /// Existing content or metadata contradicts the requested descriptor.
    Conflict,
    /// Provider content failed local size or digest verification.
    Integrity,
    /// A provider response exceeded the exact expected size or caller ceiling.
    TooLarge,
    /// Credentials do not authorize the operation.
    Unauthorized,
    /// The provider is temporarily unavailable.
    Unavailable,
    /// The provider returned an invalid or unsupported response.
    InvalidResponse,
}

/// Sanitized blob-store failure that never includes credentials, endpoints, or keys.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("immutable blob operation failed: {kind:?}")]
pub struct BlobStoreError {
    kind: BlobStoreErrorKind,
}

impl BlobStoreError {
    /// Creates a sanitized provider-boundary error.
    #[must_use]
    pub const fn new(kind: BlobStoreErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable error class.
    #[must_use]
    pub const fn kind(self) -> BlobStoreErrorKind {
        self.kind
    }
}

/// Immutable, content-addressed object operations.
///
/// Implementations must never overwrite an existing key. `AlreadyPresent` is
/// valid only after proving that bytes and immutable metadata match exactly.
/// Reads must enforce `maximum_bytes` incrementally before buffering and verify
/// both size and SHA-256 before returning.
#[async_trait]
pub trait ImmutableBlobStore: std::fmt::Debug + Send + Sync {
    /// Creates an object exactly once or verifies the existing object.
    async fn put_if_absent(&self, payload: BlobPayload) -> Result<PutBlobOutcome, BlobStoreError>;

    /// Loads and verifies one exact immutable object.
    async fn get_verified(
        &self,
        descriptor: &BlobDescriptor,
        maximum_bytes: u64,
    ) -> Result<VerifiedBlob, BlobStoreError>;
}

/// Explicit reclamation capability for immutable objects whose durable
/// references have been retired.
///
/// Publication remains immutable: implementations must never overwrite an
/// object. Deletion is idempotent and is permitted only after the coordination
/// store has durably made the descriptor unreachable.
#[async_trait]
pub trait ReclaimableBlobStore: ImmutableBlobStore {
    /// Deletes one exact unreachable object, succeeding when it is already
    /// absent.
    async fn delete_if_present(&self, descriptor: &BlobDescriptor) -> Result<(), BlobStoreError>;
}
