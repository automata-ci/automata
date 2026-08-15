#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! S3-compatible adapter for Automata's immutable blob port.
//!
//! The adapter uses conditional creation and then reads content back through
//! the same size/SHA-256 verification path. It does not list objects or use S3
//! as a coordination primitive.

mod adapter;
mod config;

pub use adapter::{EnsureBucketError, EnsureBucketOutcome, S3BlobStore};
pub use config::{
    MAX_S3_PRIVATE_CA_PEM_BYTES, S3AtRestEncryption, S3BlobStoreConfig, S3BlobStoreConfigError,
    S3TlsTrust, StaticS3Credentials,
};
