use std::{fmt, mem};

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Inclusive maximum plaintext length accepted by the generic envelope boundary.
///
/// This matches Automata's bounded 16 MiB durable command and receipt payload
/// contract. Domain-specific secret types may enforce smaller limits before
/// constructing this generic transport value.
pub const MAX_ENVELOPE_PLAINTEXT_BYTES: usize = 16 * 1024 * 1024;

/// Owned binary secret redacted from diagnostics and zeroized on drop.
///
/// This type intentionally does not implement `Clone`, `Display`, `Serialize`,
/// or `Deserialize`. [`SecretBytes::expose_secret`] is an explicit boundary
/// crossing.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Creates bounded, non-empty secret material.
    ///
    /// Rejected buffers are zeroized before returning.
    ///
    /// # Errors
    ///
    /// Rejects empty values and values larger than
    /// [`MAX_ENVELOPE_PLAINTEXT_BYTES`].
    pub fn new(mut value: Vec<u8>) -> Result<Self, SecretBytesError> {
        validate_length(&mut value)?;
        Ok(Self(value))
    }

    /// Creates secret bytes from owned UTF-8 text.
    ///
    /// # Errors
    ///
    /// Rejects empty and oversized values.
    pub fn from_utf8(value: String) -> Result<Self, SecretBytesError> {
        Self::new(value.into_bytes())
    }

    /// Explicitly exposes the plaintext bytes.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }

    /// Returns the plaintext byte count without exposing its contents.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether no secret bytes are present.
    ///
    /// Valid constructed values are never empty; this completes the standard
    /// collection inspection contract for callers handling borrowed values.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn expose_secret_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    pub(crate) fn take_for_encryption(&mut self) -> Vec<u8> {
        mem::take(&mut self.0)
    }
}

fn validate_length(value: &mut Vec<u8>) -> Result<(), SecretBytesError> {
    if value.is_empty() {
        value.zeroize();
        return Err(SecretBytesError::Empty);
    }
    if value.len() > MAX_ENVELOPE_PLAINTEXT_BYTES {
        value.zeroize();
        return Err(SecretBytesError::TooLong {
            maximum: MAX_ENVELOPE_PLAINTEXT_BYTES,
        });
    }
    Ok(())
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

/// Validation failure for owned secret material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SecretBytesError {
    /// Secret material is empty.
    #[error("secret bytes must not be empty")]
    Empty,
    /// Secret material exceeds the hard memory bound.
    #[error("secret bytes exceed the maximum length of {maximum} bytes")]
    TooLong {
        /// Inclusive maximum byte length.
        maximum: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_rejection_zeroizes_the_owned_input_buffer() {
        let mut rejected = vec![0xa5; MAX_ENVELOPE_PLAINTEXT_BYTES + 1];

        assert_eq!(
            validate_length(&mut rejected),
            Err(SecretBytesError::TooLong {
                maximum: MAX_ENVELOPE_PLAINTEXT_BYTES,
            })
        );
        assert!(rejected.iter().all(|byte| *byte == 0));
    }
}
