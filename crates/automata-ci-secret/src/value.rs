use std::fmt;

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum plaintext bytes accepted by the provider-neutral boundary: 64 KiB.
pub const MAX_SECRET_VALUE_BYTES: usize = 64 * 1_024;

/// Owned secret material redacted from diagnostics and zeroized on drop.
///
/// This type intentionally does not implement `Clone`, `Display`, `Serialize`,
/// or `Deserialize`. [`SecretValue::expose_secret`] is the explicit trust-boundary
/// crossing used by a provider adapter or isolated workload injector.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretValue(Vec<u8>);

impl SecretValue {
    /// Creates a bounded, non-empty secret value.
    ///
    /// # Errors
    ///
    /// Rejects empty values and values larger than 64 KiB.
    pub fn new(mut value: Vec<u8>) -> Result<Self, SecretValueError> {
        if value.is_empty() {
            value.zeroize();
            return Err(SecretValueError::Empty);
        }
        if value.len() > MAX_SECRET_VALUE_BYTES {
            value.zeroize();
            return Err(SecretValueError::TooLong {
                maximum: MAX_SECRET_VALUE_BYTES,
            });
        }
        Ok(Self(value))
    }

    /// Creates a value from UTF-8 text without retaining an extra copy here.
    ///
    /// # Errors
    ///
    /// Rejects empty or oversized values.
    pub fn from_utf8(value: String) -> Result<Self, SecretValueError> {
        Self::new(value.into_bytes())
    }

    /// Explicitly exposes the plaintext bytes at a trusted provider or
    /// workload-injection boundary.
    ///
    /// The returned slice must not be logged, formatted, persisted outside an
    /// approved encrypted store, or retained beyond the operation that needs
    /// it.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}

/// Closed construction failures for bounded plaintext secret material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SecretValueError {
    /// No plaintext bytes were supplied.
    #[error("a secret value must not be empty")]
    Empty,
    /// The plaintext exceeds [`MAX_SECRET_VALUE_BYTES`].
    #[error("a secret value exceeds the maximum length of {maximum} bytes")]
    TooLong {
        /// Maximum number of bytes accepted by this crate version.
        maximum: usize,
    },
}
