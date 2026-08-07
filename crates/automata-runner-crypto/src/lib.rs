#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Authenticated at-rest protection for crash-durable runner content.
//!
//! This crate is an adapter: the spool owns persistence and recovery semantics,
//! while key acquisition/rotation remains product configuration. The initial
//! implementation is a static-binary-friendly AES-256-GCM protector backed by
//! `ring`; no OpenSSL or platform service is required.

mod aes_gcm;
mod error;

pub use aes_gcm::{AES_256_GCM_KEY_BYTES, Aes256GcmContentProtector};
pub use error::ContentProtectorConfigurationError;
