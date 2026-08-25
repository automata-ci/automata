//! Exact Git object identities shared across provider, storage, and protocol boundaries.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeStruct as _};
use thiserror::Error;

/// Byte length of a Git SHA-1 object identity.
pub const GIT_SHA1_BYTES: usize = 20;
/// Byte length of a Git SHA-256 object identity.
pub const GIT_SHA256_BYTES: usize = 32;

/// Hash algorithm used by one exact Git object identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GitObjectAlgorithm {
    /// The original 160-bit Git object format.
    Sha1,
    /// The 256-bit Git object format.
    Sha256,
}

impl GitObjectAlgorithm {
    /// Returns the exact raw object-ID length for this algorithm.
    #[must_use]
    pub const fn byte_length(self) -> usize {
        match self {
            Self::Sha1 => GIT_SHA1_BYTES,
            Self::Sha256 => GIT_SHA256_BYTES,
        }
    }

    /// Returns the canonical hexadecimal object-ID length for this algorithm.
    #[must_use]
    pub const fn hex_length(self) -> usize {
        self.byte_length() * 2
    }
}

/// One full, immutable Git object identity with its hash algorithm.
///
/// All-zero values, abbreviated hashes, uppercase hexadecimal, and algorithm
/// mismatches are rejected. Provider deletion sentinels must be represented as
/// absence rather than as a [`GitObjectId`].
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GitObjectId {
    algorithm: GitObjectAlgorithm,
    bytes: [u8; GIT_SHA256_BYTES],
}

impl GitObjectId {
    /// Constructs an object identity from exact raw bytes and an explicit algorithm.
    ///
    /// # Errors
    ///
    /// Rejects a length that disagrees with `algorithm` or an all-zero identity.
    pub fn from_bytes(
        algorithm: GitObjectAlgorithm,
        value: &[u8],
    ) -> Result<Self, GitObjectIdError> {
        if value.len() != algorithm.byte_length() {
            return Err(GitObjectIdError::InvalidLength {
                algorithm,
                expected: algorithm.byte_length(),
                received: value.len(),
            });
        }
        if value.iter().all(|byte| *byte == 0) {
            return Err(GitObjectIdError::ZeroIdentity);
        }
        let mut bytes = [0; GIT_SHA256_BYTES];
        bytes[..value.len()].copy_from_slice(value);
        Ok(Self { algorithm, bytes })
    }

    /// Rehydrates a canonical raw identity whose length defines its Git object format.
    ///
    /// This is the durable binary representation used by storage boundaries:
    /// exactly 20 bytes means SHA-1 and exactly 32 bytes means SHA-256.
    ///
    /// # Errors
    ///
    /// Rejects any other length or an all-zero identity.
    pub fn from_durable_bytes(value: &[u8]) -> Result<Self, GitObjectIdError> {
        let algorithm = match value.len() {
            GIT_SHA1_BYTES => GitObjectAlgorithm::Sha1,
            GIT_SHA256_BYTES => GitObjectAlgorithm::Sha256,
            received => return Err(GitObjectIdError::UnsupportedByteLength { received }),
        };
        Self::from_bytes(algorithm, value)
    }

    /// Parses a full canonical lowercase hexadecimal identity for an explicit algorithm.
    ///
    /// # Errors
    ///
    /// Rejects the wrong encoded length, non-lowercase hexadecimal, or an all-zero identity.
    pub fn from_hex(algorithm: GitObjectAlgorithm, value: &str) -> Result<Self, GitObjectIdError> {
        if value.len() != algorithm.hex_length() {
            return Err(GitObjectIdError::InvalidLength {
                algorithm,
                expected: algorithm.hex_length(),
                received: value.len(),
            });
        }
        let mut bytes = [0; GIT_SHA256_BYTES];
        for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let high = lowercase_hex_nibble(pair[0])
                .ok_or(GitObjectIdError::InvalidHex { index: index * 2 })?;
            let low = lowercase_hex_nibble(pair[1]).ok_or(GitObjectIdError::InvalidHex {
                index: index * 2 + 1,
            })?;
            bytes[index] = (high << 4) | low;
        }
        Self::from_bytes(algorithm, &bytes[..algorithm.byte_length()])
    }

    /// Parses a full canonical lowercase identity and infers its algorithm from length.
    ///
    /// This is intended for provider APIs whose object-ID field does not carry a
    /// separate algorithm discriminator. Durable and protocol decoders use
    /// [`Self::from_hex`] with an explicit algorithm instead.
    ///
    /// # Errors
    ///
    /// Rejects lengths other than 40 or 64, non-lowercase hexadecimal, or all-zero input.
    pub fn from_provider_hex(value: impl AsRef<str>) -> Result<Self, GitObjectIdError> {
        let value = value.as_ref();
        let algorithm = match value.len() {
            length if length == GitObjectAlgorithm::Sha1.hex_length() => GitObjectAlgorithm::Sha1,
            length if length == GitObjectAlgorithm::Sha256.hex_length() => {
                GitObjectAlgorithm::Sha256
            }
            received => return Err(GitObjectIdError::UnsupportedLength { received }),
        };
        Self::from_hex(algorithm, value)
    }

    /// Returns the hash algorithm carried by this identity.
    #[must_use]
    pub const fn algorithm(self) -> GitObjectAlgorithm {
        self.algorithm
    }

    /// Borrows the exact raw object-ID bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.algorithm.byte_length()]
    }
}

impl fmt::Debug for GitObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitObjectId")
            .field("algorithm", &self.algorithm)
            .field("hex", &format_args!("{self}"))
            .finish_non_exhaustive()
    }
}

impl fmt::Display for GitObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_bytes() {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for GitObjectId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("GitObjectId", 2)?;
        state.serialize_field("algorithm", &self.algorithm)?;
        state.serialize_field("hex", &format_args!("{self}"))?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for GitObjectId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct EncodedGitObjectId {
            algorithm: GitObjectAlgorithm,
            hex: String,
        }

        let encoded = EncodedGitObjectId::deserialize(deserializer)?;
        Self::from_hex(encoded.algorithm, &encoded.hex).map_err(serde::de::Error::custom)
    }
}

const fn lowercase_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Malformed or ambiguous exact Git object identity.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GitObjectIdError {
    /// An explicit algorithm disagreed with the supplied raw or hexadecimal length.
    #[error(
        "Git object ID for {algorithm:?} must contain exactly {expected} bytes or characters; received {received}"
    )]
    InvalidLength {
        /// Declared object algorithm.
        algorithm: GitObjectAlgorithm,
        /// Required length in the representation being decoded.
        expected: usize,
        /// Observed length.
        received: usize,
    },
    /// A provider object-ID field had neither a full SHA-1 nor SHA-256 length.
    #[error(
        "Git object ID must contain exactly 40 or 64 lowercase hexadecimal characters; received {received}"
    )]
    UnsupportedLength {
        /// Observed hexadecimal length.
        received: usize,
    },
    /// A durable binary object ID had neither a SHA-1 nor SHA-256 length.
    #[error("Git object ID must contain exactly 20 or 32 bytes; received {received}")]
    UnsupportedByteLength {
        /// Observed raw byte length.
        received: usize,
    },
    /// The hexadecimal form contained an uppercase or non-hexadecimal byte.
    #[error("Git object ID contains a non-lowercase-hexadecimal byte at index {index}")]
    InvalidHex {
        /// Zero-based byte index in the rejected textual form.
        index: usize,
    },
    /// The provider null sentinel is not an object identity.
    #[error("Git object ID must not be the all-zero sentinel")]
    ZeroIdentity,
}
