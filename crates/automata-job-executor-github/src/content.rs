use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_blob::{BlobDescriptor, BlobKey, BlobStoreErrorKind, ImmutableBlobStore, MediaType};
use automata_core::JobContentReference;
use bytes::Bytes;

use crate::{JobContentPort, PortError, PortErrorKind};

/// Verified immutable-object adapter for execution-time job content.
///
/// The supplied store must address the same bucket and provider prefix as the
/// admission publisher. [`JobContentReference::object_key`] is passed through
/// as the logical [`BlobKey`] without adding an executor-specific namespace.
/// A configuration mismatch therefore returns `NotFound` and execution fails
/// closed instead of searching a fallback prefix.
pub struct ImmutableJobContent {
    blobs: Arc<dyn ImmutableBlobStore>,
    maximum_bytes: u64,
}

impl ImmutableJobContent {
    /// Creates a bounded content reader.
    ///
    /// # Errors
    ///
    /// Rejects a zero bound or a bound above the execution copy ceiling.
    pub fn new(blobs: Arc<dyn ImmutableBlobStore>, maximum_bytes: u64) -> Result<Self, PortError> {
        if maximum_bytes == 0 || maximum_bytes > automata_execution::MAX_COPY_BYTES as u64 {
            return Err(PortError::new(PortErrorKind::ResourceExhausted));
        }
        Ok(Self {
            blobs,
            maximum_bytes,
        })
    }
}

impl fmt::Debug for ImmutableJobContent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImmutableJobContent")
            .field("blobs", &self.blobs)
            .field("maximum_bytes", &self.maximum_bytes)
            .finish()
    }
}

#[async_trait]
impl JobContentPort for ImmutableJobContent {
    async fn load(&self, reference: &JobContentReference) -> Result<Bytes, PortError> {
        if reference.encoded_size() > self.maximum_bytes {
            return Err(PortError::new(PortErrorKind::ResourceExhausted));
        }
        let key = BlobKey::new(reference.object_key()).map_err(|_| invalid_data())?;
        let media_type = MediaType::new(reference.media_type()).map_err(|_| invalid_data())?;
        let descriptor = BlobDescriptor::new(
            key,
            reference.digest(),
            reference.encoded_size(),
            media_type,
        );
        self.blobs
            .get_verified(&descriptor, self.maximum_bytes)
            .await
            .map(automata_blob::VerifiedBlob::into_bytes)
            .map_err(|error| {
                let kind = match error.kind() {
                    BlobStoreErrorKind::NotFound => PortErrorKind::NotFound,
                    BlobStoreErrorKind::Unauthorized => PortErrorKind::PermissionDenied,
                    BlobStoreErrorKind::TooLarge => PortErrorKind::ResourceExhausted,
                    BlobStoreErrorKind::Unavailable => PortErrorKind::Unavailable,
                    BlobStoreErrorKind::Conflict
                    | BlobStoreErrorKind::Integrity
                    | BlobStoreErrorKind::InvalidResponse => PortErrorKind::InvalidData,
                };
                PortError::new(kind)
            })
    }
}

const fn invalid_data() -> PortError {
    PortError::new(PortErrorKind::InvalidData)
}
