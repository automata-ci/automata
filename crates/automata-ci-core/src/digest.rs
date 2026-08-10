//! Opaque content-addressing digests shared across storage and protocol adapters.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use thiserror::Error;

/// Exact byte length of a SHA-256 digest.
pub const SHA256_DIGEST_BYTES: usize = 32;
/// Exact lowercase hexadecimal length of a SHA-256 digest.
pub const SHA256_DIGEST_HEX_LENGTH: usize = SHA256_DIGEST_BYTES * 2;

/// An opaque, exactly 256-bit SHA-256 digest.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha256Digest([u8; SHA256_DIGEST_BYTES]);

impl Sha256Digest {
    /// Wraps an already-computed SHA-256 digest.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SHA256_DIGEST_BYTES]) -> Self {
        Self(bytes)
    }

    /// Borrows the exact digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SHA256_DIGEST_BYTES] {
        &self.0
    }

    /// Returns the exact digest bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; SHA256_DIGEST_BYTES] {
        self.0
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Sha256Digest")
            .field(&format_args!("{self}"))
            .finish()
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for Sha256Digest {
    type Err = Sha256DigestError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != SHA256_DIGEST_HEX_LENGTH {
            return Err(Sha256DigestError::InvalidLength {
                expected: SHA256_DIGEST_HEX_LENGTH,
                received: value.len(),
            });
        }
        let mut bytes = [0; SHA256_DIGEST_BYTES];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let high =
                hex_nibble(pair[0]).ok_or(Sha256DigestError::InvalidHex { index: index * 2 })?;
            let low = hex_nibble(pair[1]).ok_or(Sha256DigestError::InvalidHex {
                index: index * 2 + 1,
            })?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(D::Error::custom)
    }
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Malformed textual SHA-256 digest.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum Sha256DigestError {
    /// The textual digest did not contain exactly 64 hexadecimal characters.
    #[error(
        "SHA-256 digest must contain exactly {expected} hexadecimal characters; received {received}"
    )]
    InvalidLength {
        /// Required encoded length for a SHA-256 digest.
        expected: usize,
        /// Length of the rejected input.
        received: usize,
    },
    /// A byte at the reported zero-based position was not hexadecimal.
    #[error("SHA-256 digest contains a non-hexadecimal byte at index {index}")]
    InvalidHex {
        /// Zero-based byte index in the rejected textual digest.
        index: usize,
    },
}
