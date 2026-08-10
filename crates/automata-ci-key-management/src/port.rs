use std::fmt;

use async_trait::async_trait;
use thiserror::Error;

use crate::{KeyEncryptionContext, SecretBytes, WrappedDataKey};

/// Sanitized failure at a KMS, HSM, transit, or local-keyring boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum KeyEncryptionError {
    /// The supplied plaintext DEK has an invalid length.
    #[error("data-encryption key is invalid")]
    InvalidDataKey,
    /// Wrapped ciphertext has an invalid durable representation.
    #[error("wrapped data-key ciphertext is invalid")]
    InvalidCiphertext,
    /// Ciphertext, nonce, key identity, or authenticated context did not verify.
    #[error("wrapped data-key authentication failed")]
    AuthenticationFailed,
    /// The referenced key ID was never configured by this provider.
    #[error("wrapping key is unknown")]
    UnknownKey,
    /// The key ID is an explicit cryptographic-shredding tombstone.
    #[error("wrapping key is retired")]
    RetiredKey,
    /// Cryptographically secure random bytes were unavailable.
    #[error("secure randomness is unavailable")]
    RandomnessUnavailable,
    /// The key-encryption provider could not complete the operation.
    #[error("key-encryption provider is unavailable")]
    Unavailable,
}

/// Object-safe asynchronous DEK wrapping boundary.
///
/// Implementations must bind both operations to the complete authenticated
/// context, return the exact wrapping key ID, and return only sanitized errors.
/// They must never retain, log, or serialize the plaintext DEK.
#[async_trait]
pub trait KeyEncryptionProvider: fmt::Debug + Send + Sync {
    /// Wraps one plaintext data-encryption key using the active wrapping key.
    async fn wrap_data_key(
        &self,
        plaintext_key: &SecretBytes,
        context: &KeyEncryptionContext,
    ) -> Result<WrappedDataKey, KeyEncryptionError>;

    /// Unwraps one DEK using the key ID carried by the opaque wrapped key.
    async fn unwrap_data_key(
        &self,
        wrapped_key: &WrappedDataKey,
        context: &KeyEncryptionContext,
    ) -> Result<SecretBytes, KeyEncryptionError>;
}
