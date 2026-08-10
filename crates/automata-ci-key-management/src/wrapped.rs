use std::fmt;

use thiserror::Error;

use crate::KeyId;

/// Largest provider-owned wrapped DEK representation accepted at the boundary.
pub const MAX_WRAPPED_DATA_KEY_BYTES: usize = 64 * 1024;

/// Opaque provider ciphertext for one data-encryption key.
///
/// The wrapping key ID is durable metadata and participates in authenticated
/// data. Ciphertext bytes are deliberately omitted from debug output.
pub struct WrappedDataKey {
    key_id: KeyId,
    ciphertext: Vec<u8>,
}

impl WrappedDataKey {
    /// Creates a bounded, non-empty opaque wrapped key.
    ///
    /// # Errors
    ///
    /// Rejects empty and oversized provider ciphertext.
    pub fn new(key_id: KeyId, ciphertext: Vec<u8>) -> Result<Self, WrappedDataKeyError> {
        if ciphertext.is_empty() || ciphertext.len() > MAX_WRAPPED_DATA_KEY_BYTES {
            return Err(WrappedDataKeyError);
        }
        Ok(Self { key_id, ciphertext })
    }

    /// Returns the exact wrapping key version.
    #[must_use]
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// Borrows opaque provider ciphertext for persistence or provider use.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Consumes the wrapper into persistence-safe parts.
    #[must_use]
    pub fn into_parts(self) -> (KeyId, Vec<u8>) {
        (self.key_id, self.ciphertext)
    }
}

impl fmt::Debug for WrappedDataKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WrappedDataKey")
            .field("key_id", &self.key_id)
            .field("ciphertext", &"[OPAQUE]")
            .field("ciphertext_length", &self.ciphertext.len())
            .finish()
    }
}

/// Invalid wrapped data-key ciphertext.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("wrapped data key is invalid")]
pub struct WrappedDataKeyError;
