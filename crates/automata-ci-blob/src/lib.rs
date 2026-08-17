#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Provider-neutral immutable blob and manifest storage.
//!
//! Coordination and publication remain in `PostgreSQL`. This crate deliberately
//! exposes content-addressed reads plus exact-key discovery for bounded
//! immutable records; provider adapters cannot turn S3 listing or mutable
//! object state into coordination.

mod memory;
mod model;
mod port;

pub use memory::MemoryBlobStore;
pub use model::{
    BlobDescriptor, BlobKey, BlobKeyError, BlobPayload, BlobPayloadError, MediaType,
    MediaTypeError, PutBlobOutcome, VerifiedBlob,
};
pub use port::{
    BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore, ImmutableRecordStore,
    ReclaimableBlobStore,
};
