#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Private authenticated at-rest protection for crash-durable runner content.
//!
//! This module is an adapter: the spool owns persistence and recovery semantics,
//! while key acquisition/rotation remains product configuration. The
//! implementation is a static-binary-friendly AES-256-GCM protector backed by
//! `ring`; no OpenSSL or platform service is required.

mod aes_gcm;
mod error;
mod keyring;
#[cfg(test)]
mod tests;

pub(super) use aes_gcm::{AES_256_GCM_KEY_BYTES, Aes256GcmContentProtector};
pub(super) use keyring::{Aes256GcmContentKeyring, MAX_DECRYPT_ONLY_CONTENT_KEYS};
