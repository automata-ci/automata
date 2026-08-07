//! Backend-neutral idempotency identity for control-plane commands.

use std::{fmt, str::FromStr};

use automata_core::OperationId;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Byte length of a SHA-256 operation request digest.
pub const OPERATION_REQUEST_DIGEST_BYTES: usize = 32;

/// Length of the canonical lower-case hexadecimal representation.
pub const OPERATION_REQUEST_DIGEST_HEX_LENGTH: usize = OPERATION_REQUEST_DIGEST_BYTES * 2;

/// SHA-256 digest of the canonical bytes for one mutating request.
///
/// Canonicalization belongs to the request adapter. This type deliberately
/// records the digest algorithm and representation without binding the domain
/// to JSON, protobuf, SQL, or an HTTP transport.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OperationRequestDigest([u8; OPERATION_REQUEST_DIGEST_BYTES]);

impl OperationRequestDigest {
    /// Hashes canonical request bytes with SHA-256.
    #[must_use]
    pub fn sha256(canonical_request: impl AsRef<[u8]>) -> Self {
        Self(Sha256::digest(canonical_request.as_ref()).into())
    }

    /// Wraps an already-computed SHA-256 digest.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; OPERATION_REQUEST_DIGEST_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the exact digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; OPERATION_REQUEST_DIGEST_BYTES] {
        &self.0
    }

    /// Consumes the digest and returns its bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; OPERATION_REQUEST_DIGEST_BYTES] {
        self.0
    }
}

impl fmt::Display for OperationRequestDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for OperationRequestDigest {
    type Err = OperationRequestDigestError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != OPERATION_REQUEST_DIGEST_HEX_LENGTH {
            return Err(OperationRequestDigestError::InvalidLength {
                expected: OPERATION_REQUEST_DIGEST_HEX_LENGTH,
                received: value.len(),
            });
        }

        let mut bytes = [0_u8; OPERATION_REQUEST_DIGEST_BYTES];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = decode_hex_nibble(pair[0])
                .ok_or(OperationRequestDigestError::InvalidHexCharacter { index: index * 2 })?;
            let low = decode_hex_nibble(pair[1]).ok_or(
                OperationRequestDigestError::InvalidHexCharacter {
                    index: index * 2 + 1,
                },
            )?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }
}

const fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

impl Serialize for OperationRequestDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for OperationRequestDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(D::Error::custom)
    }
}

/// A replay identity paired with the digest that detects key reuse for a
/// different request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct IdempotencyGuard {
    operation_id: OperationId,
    request_digest: OperationRequestDigest,
}

impl IdempotencyGuard {
    /// Creates an idempotency guard for canonical request content.
    #[must_use]
    pub const fn new(operation_id: OperationId, request_digest: OperationRequestDigest) -> Self {
        Self {
            operation_id,
            request_digest,
        }
    }

    /// Returns the caller-selected operation identity.
    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    /// Returns the content digest bound to the operation identity.
    #[must_use]
    pub const fn request_digest(self) -> OperationRequestDigest {
        self.request_digest
    }
}

/// Parsing errors for a canonical request digest.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OperationRequestDigestError {
    /// The representation was not exactly 64 ASCII bytes.
    #[error(
        "operation request digest must contain exactly {expected} hexadecimal bytes; received {received}"
    )]
    InvalidLength { expected: usize, received: usize },
    /// A byte was not a lower-case hexadecimal character.
    #[error(
        "operation request digest contains a non-canonical hexadecimal character at byte {index}"
    )]
    InvalidHexCharacter { index: usize },
}
