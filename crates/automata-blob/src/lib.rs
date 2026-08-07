#![forbid(unsafe_code)]
//! Provider-neutral immutable blob storage.
//!
//! Coordination and publication remain in `PostgreSQL`. This crate deliberately
//! exposes only content-addressed, read-after-write object operations; provider
//! adapters cannot turn S3 listing or mutable object state into coordination.

mod memory;
mod model;
mod port;

pub use memory::MemoryBlobStore;
pub use model::{
    BlobDescriptor, BlobKey, BlobKeyError, BlobPayload, BlobPayloadError, MediaType,
    MediaTypeError, PutBlobOutcome, VerifiedBlob,
};
pub use port::{BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore};
