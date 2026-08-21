//! Service-owned custody contracts for Windows enrollment material.
//!
//! Concrete persistence is namespaced under [`mod@file`]. Callers receive only
//! opaque handles and authenticated value-free metadata.

use std::{fmt, str::FromStr as _};

use automata_ci_core::{Sha256Digest, UnixMillis};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

pub mod file;

const MAX_ADMISSION_RECEIPT_BYTES: usize = 256 * 1024;
const MAX_ENROLLMENT_SECRET_BYTES: usize = 64 * 1024;

/// Type of broker-custodied material.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsBrokerCustodyKind {
    /// Authenticated, short-lived pre-enrollment admission receipt.
    AdmissionReceipt,
    /// Runner enrollment secret that must never be written by the runner.
    EnrollmentSecret,
}

impl WindowsBrokerCustodyKind {
    const fn byte_limit(self) -> usize {
        match self {
            Self::AdmissionReceipt => MAX_ADMISSION_RECEIPT_BYTES,
            Self::EnrollmentSecret => MAX_ENROLLMENT_SECRET_BYTES,
        }
    }

    const fn domain_byte(self) -> u8 {
        match self {
            Self::AdmissionReceipt => 1,
            Self::EnrollmentSecret => 2,
        }
    }
}

/// Opaque random capability for one service-owned custody record.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WindowsBrokerCustodyHandle {
    token: String,
    digest: Sha256Digest,
}

impl WindowsBrokerCustodyHandle {
    /// Parses a fixed canonical custody token.
    ///
    /// # Errors
    ///
    /// Rejects unknown versions, path-like values, and non-canonical digests.
    pub fn parse(value: &str) -> Result<Self, WindowsBrokerCustodyError> {
        let digest_text = value
            .strip_prefix("bc1-")
            .ok_or(WindowsBrokerCustodyError::InvalidHandle)?;
        if digest_text.len() != 64
            || !digest_text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(WindowsBrokerCustodyError::InvalidHandle);
        }
        let digest = Sha256Digest::from_str(digest_text)
            .map_err(|_| WindowsBrokerCustodyError::InvalidHandle)?;
        if digest.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(WindowsBrokerCustodyError::InvalidHandle);
        }
        Ok(Self {
            token: value.to_owned(),
            digest,
        })
    }

    /// Returns the path-free broker token. Treat it as opaque.
    #[must_use]
    pub fn opaque(&self) -> &str {
        &self.token
    }

    /// Returns the stable value-free capability digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

impl fmt::Debug for WindowsBrokerCustodyHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsBrokerCustodyHandle([OPAQUE])")
    }
}

/// Reauthenticated metadata for one custody record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsBrokerCustodyMetadata {
    kind: WindowsBrokerCustodyKind,
    content_sha256: Sha256Digest,
    byte_len: usize,
    created_at: UnixMillis,
}

impl WindowsBrokerCustodyMetadata {
    /// Returns the material class.
    #[must_use]
    pub const fn kind(self) -> WindowsBrokerCustodyKind {
        self.kind
    }

    /// Returns SHA-256 of the authenticated plaintext.
    #[must_use]
    pub const fn content_sha256(self) -> Sha256Digest {
        self.content_sha256
    }

    /// Returns the exact plaintext byte length.
    #[must_use]
    pub const fn byte_len(self) -> usize {
        self.byte_len
    }

    /// Returns the trusted service creation time.
    #[must_use]
    pub const fn created_at(self) -> UnixMillis {
        self.created_at
    }
}

/// Safe sealing boundary used by the broker custody store.
///
/// The Windows service implementation uses same-account `CurrentUser` DPAPI
/// with UI forbidden. Tests use a deliberately non-production reversible fake.
pub trait WindowsBrokerCustodyProtector: fmt::Debug + Send + Sync {
    /// Seals one bounded value for durable service-only storage.
    ///
    /// # Errors
    ///
    /// Returns a value-free protector failure.
    fn seal(&self, plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, WindowsBrokerCustodyError>;

    /// Opens one sealed value under the same service identity.
    ///
    /// # Errors
    ///
    /// Returns a value-free protector failure or authentication failure.
    fn open(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, WindowsBrokerCustodyError>;
}

/// Narrow custody port required by the admission application state machine.
///
/// Implementations own durable material, handle generation, exact replay, and
/// completion tombstones. The application service never receives a path or a
/// generic plaintext lookup surface.
pub trait WindowsBrokerAdmissionCustody: fmt::Debug + Send + Sync {
    /// Reserves a new opaque handle without publishing authority.
    ///
    /// # Errors
    ///
    /// Fails closed on entropy, capacity, or backend availability failures.
    fn reserve_handle(
        &self,
        kind: WindowsBrokerCustodyKind,
    ) -> Result<WindowsBrokerCustodyHandle, WindowsBrokerCustodyError>;

    /// Publishes or exactly replays material at a reserved handle.
    ///
    /// # Errors
    ///
    /// Rejects substitution, completion reuse, capacity, and durability
    /// failures.
    fn put_reserved(
        &self,
        handle: &WindowsBrokerCustodyHandle,
        kind: WindowsBrokerCustodyKind,
        plaintext: &[u8],
        created_at: UnixMillis,
    ) -> Result<(), WindowsBrokerCustodyError>;

    /// Opens the exact live or completed admission receipt.
    ///
    /// # Errors
    ///
    /// Rejects absence, substitution, corruption, and backend failures.
    fn get_admission_receipt(
        &self,
        handle: &WindowsBrokerCustodyHandle,
        completed: bool,
    ) -> Result<Zeroizing<Vec<u8>>, WindowsBrokerCustodyError>;

    /// Atomically completes one exact admission receipt.
    ///
    /// # Errors
    ///
    /// Rejects absence, kind or digest substitution, corruption, and backend
    /// failures.
    fn complete_admission_receipt(
        &self,
        handle: &WindowsBrokerCustodyHandle,
        expected_content_sha256: Sha256Digest,
    ) -> Result<(), WindowsBrokerCustodyError>;
}

/// Closed custody failure without secret bytes or host paths.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WindowsBrokerCustodyError {
    /// A handle or store configuration is malformed.
    #[error("Windows broker custody input is invalid")]
    InvalidHandle,
    /// A service-owned path is not a regular non-reparse object.
    #[error("Windows broker custody path safety check failed")]
    UnsafePath,
    /// A bounded filesystem operation failed.
    #[error("Windows broker custody I/O failed")]
    Io,
    /// A record was modified, truncated, or schema-invalid.
    #[error("Windows broker custody record authentication failed")]
    Tampered,
    /// The configured bounded store or material limit was exceeded.
    #[error("Windows broker custody capacity was exceeded")]
    Capacity,
    /// The service-account sealing boundary failed.
    #[error("Windows broker custody protector failed")]
    Protector,
    /// No live record exists for the exact handle.
    #[error("Windows broker custody handle is absent")]
    Absent,
}
