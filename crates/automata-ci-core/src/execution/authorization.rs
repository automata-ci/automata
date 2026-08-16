//! Provider-neutral, job-bound sandbox authorizations.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::Sha256Digest;

/// Current schema for a job-bound sandbox-authorization bundle.
pub const SANDBOX_AUTHORIZATIONS_SCHEMA_VERSION: u16 = 1;
/// Maximum number of independent sandbox authorizations carried by one job.
pub const MAX_SANDBOX_AUTHORIZATIONS: usize = 16;
/// Maximum UTF-8 bytes in one sandbox-authorization namespace.
pub const MAX_SANDBOX_AUTHORIZATION_NAME_BYTES: usize = 128;
/// Maximum bytes in one provider-owned sandbox-authorization payload.
pub const MAX_SANDBOX_AUTHORIZATION_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Canonical provider-owned namespace for one sandbox authorization.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct SandboxAuthorizationName(String);

impl SandboxAuthorizationName {
    /// Validates a lowercase portable authorization namespace.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, path-like, or noncanonical names.
    pub fn new(value: impl Into<String>) -> Result<Self, SandboxAuthorizationError> {
        let value = value.into();
        let mut bytes = value.bytes();
        let valid_first = bytes.next().is_some_and(|byte| byte.is_ascii_lowercase());
        let valid_rest = bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        });
        if value.len() <= MAX_SANDBOX_AUTHORIZATION_NAME_BYTES && valid_first && valid_rest {
            Ok(Self(value))
        } else {
            Err(SandboxAuthorizationError::InvalidName)
        }
    }

    /// Returns the canonical provider namespace.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<SandboxAuthorizationName> for String {
    fn from(value: SandboxAuthorizationName) -> Self {
        value.0
    }
}

impl TryFrom<String> for SandboxAuthorizationName {
    type Error = SandboxAuthorizationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SandboxAuthorizationDocument {
    name: SandboxAuthorizationName,
    payload_schema_version: u16,
    payload_sha256: Sha256Digest,
    payload: Box<[u8]>,
}

/// One bounded provider-owned authorization carried through generic execution.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    try_from = "SandboxAuthorizationDocument",
    into = "SandboxAuthorizationDocument"
)]
pub struct SandboxAuthorization {
    name: SandboxAuthorizationName,
    payload_schema_version: u16,
    payload_sha256: Sha256Digest,
    payload: Box<[u8]>,
}

impl SandboxAuthorization {
    /// Creates an authorization and commits to its exact payload bytes.
    ///
    /// # Errors
    ///
    /// Rejects schema zero, an empty payload, or a payload above the hard bound.
    pub fn new(
        name: SandboxAuthorizationName,
        payload_schema_version: u16,
        payload: impl Into<Box<[u8]>>,
    ) -> Result<Self, SandboxAuthorizationError> {
        let payload = payload.into();
        let payload_sha256 = Sha256Digest::from_bytes(Sha256::digest(&payload).into());
        Self::from_parts(name, payload_schema_version, payload_sha256, payload)
    }

    /// Rehydrates an authorization at a durable or transport boundary.
    ///
    /// # Errors
    ///
    /// Rejects invalid bounds or a digest that does not match the exact payload.
    pub fn from_parts(
        name: SandboxAuthorizationName,
        payload_schema_version: u16,
        payload_sha256: Sha256Digest,
        payload: impl Into<Box<[u8]>>,
    ) -> Result<Self, SandboxAuthorizationError> {
        let payload = payload.into();
        if payload_schema_version == 0 {
            return Err(SandboxAuthorizationError::ZeroPayloadSchema);
        }
        if payload.is_empty() || payload.len() > MAX_SANDBOX_AUTHORIZATION_PAYLOAD_BYTES {
            return Err(SandboxAuthorizationError::InvalidPayloadSize);
        }
        let actual = Sha256Digest::from_bytes(Sha256::digest(&payload).into());
        if actual != payload_sha256 {
            return Err(SandboxAuthorizationError::PayloadDigestMismatch);
        }
        Ok(Self {
            name,
            payload_schema_version,
            payload_sha256,
            payload,
        })
    }

    /// Returns the provider-owned authorization namespace.
    #[must_use]
    pub const fn name(&self) -> &SandboxAuthorizationName {
        &self.name
    }

    /// Returns the provider-owned payload schema.
    #[must_use]
    pub const fn payload_schema_version(&self) -> u16 {
        self.payload_schema_version
    }

    /// Returns the digest of the exact payload bytes.
    #[must_use]
    pub const fn payload_sha256(&self) -> Sha256Digest {
        self.payload_sha256
    }

    /// Returns the exact provider-owned payload bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl fmt::Debug for SandboxAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SandboxAuthorization")
            .field("name", &self.name)
            .field("payload_schema_version", &self.payload_schema_version)
            .field("payload_sha256", &self.payload_sha256)
            .field("payload_bytes", &self.payload.len())
            .finish()
    }
}

impl From<SandboxAuthorization> for SandboxAuthorizationDocument {
    fn from(value: SandboxAuthorization) -> Self {
        Self {
            name: value.name,
            payload_schema_version: value.payload_schema_version,
            payload_sha256: value.payload_sha256,
            payload: value.payload,
        }
    }
}

impl TryFrom<SandboxAuthorizationDocument> for SandboxAuthorization {
    type Error = SandboxAuthorizationError;

    fn try_from(value: SandboxAuthorizationDocument) -> Result<Self, Self::Error> {
        Self::from_parts(
            value.name,
            value.payload_schema_version,
            value.payload_sha256,
            value.payload,
        )
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SandboxAuthorizationsDocument {
    schema_version: u16,
    authorizations: Vec<SandboxAuthorization>,
}

/// Canonically ordered provider-owned sandbox authorizations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    try_from = "SandboxAuthorizationsDocument",
    into = "SandboxAuthorizationsDocument"
)]
pub struct SandboxAuthorizations {
    schema_version: u16,
    authorizations: Vec<SandboxAuthorization>,
}

impl SandboxAuthorizations {
    /// Creates an explicit canonical authorization set.
    ///
    /// # Errors
    ///
    /// Rejects oversized, duplicate, or noncanonically ordered entries.
    pub fn new(
        authorizations: Vec<SandboxAuthorization>,
    ) -> Result<Self, SandboxAuthorizationError> {
        let authorizations = Self {
            schema_version: SANDBOX_AUTHORIZATIONS_SCHEMA_VERSION,
            authorizations,
        };
        authorizations.validate()?;
        Ok(authorizations)
    }

    /// Returns an explicit empty authorization set.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            schema_version: SANDBOX_AUTHORIZATIONS_SCHEMA_VERSION,
            authorizations: Vec::new(),
        }
    }

    /// Returns the bundle schema.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns entries in canonical namespace order.
    #[must_use]
    pub fn as_slice(&self) -> &[SandboxAuthorization] {
        &self.authorizations
    }

    /// Finds one exact authorization namespace.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&SandboxAuthorization> {
        self.authorizations
            .binary_search_by(|authorization| authorization.name().as_str().cmp(name))
            .ok()
            .map(|index| &self.authorizations[index])
    }

    /// Validates schema, bounds, and canonical ordering.
    ///
    /// # Errors
    ///
    /// Rejects an unsupported schema or invalid authorization structure.
    pub fn validate(&self) -> Result<(), SandboxAuthorizationError> {
        if self.schema_version != SANDBOX_AUTHORIZATIONS_SCHEMA_VERSION {
            return Err(SandboxAuthorizationError::UnsupportedSchema);
        }
        if self.authorizations.len() > MAX_SANDBOX_AUTHORIZATIONS {
            return Err(SandboxAuthorizationError::InvalidCount);
        }
        let mut previous: Option<&SandboxAuthorizationName> = None;
        for authorization in &self.authorizations {
            if previous.is_some_and(|name| name >= authorization.name()) {
                return Err(SandboxAuthorizationError::NonCanonicalOrder);
            }
            previous = Some(authorization.name());
        }
        Ok(())
    }
}

impl Default for SandboxAuthorizations {
    fn default() -> Self {
        Self::empty()
    }
}

impl From<SandboxAuthorizations> for SandboxAuthorizationsDocument {
    fn from(value: SandboxAuthorizations) -> Self {
        Self {
            schema_version: value.schema_version,
            authorizations: value.authorizations,
        }
    }
}

impl TryFrom<SandboxAuthorizationsDocument> for SandboxAuthorizations {
    type Error = SandboxAuthorizationError;

    fn try_from(value: SandboxAuthorizationsDocument) -> Result<Self, Self::Error> {
        if value.schema_version != SANDBOX_AUTHORIZATIONS_SCHEMA_VERSION {
            return Err(SandboxAuthorizationError::UnsupportedSchema);
        }
        Self::new(value.authorizations)
    }
}

/// Invalid provider-neutral sandbox-authorization material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SandboxAuthorizationError {
    /// The namespace is empty, oversized, path-like, or noncanonical.
    #[error("sandbox authorization name is invalid")]
    InvalidName,
    /// Payload schema zero is reserved.
    #[error("sandbox authorization payload schema must be nonzero")]
    ZeroPayloadSchema,
    /// Payload is empty or above the hard bound.
    #[error("sandbox authorization payload size is invalid")]
    InvalidPayloadSize,
    /// Payload bytes disagree with their claimed digest.
    #[error("sandbox authorization payload digest does not match")]
    PayloadDigestMismatch,
    /// The bundle schema is unsupported.
    #[error("sandbox authorization bundle schema is unsupported")]
    UnsupportedSchema,
    /// The bundle contains too many entries.
    #[error("sandbox authorization count is invalid")]
    InvalidCount,
    /// Entries are not strictly ordered by unique namespace.
    #[error("sandbox authorizations are not in canonical order")]
    NonCanonicalOrder,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn payload(name: &str, byte: u8) -> SandboxAuthorization {
        SandboxAuthorization::new(
            SandboxAuthorizationName::new(name).expect("name"),
            1,
            vec![byte; 32],
        )
        .expect("authorization")
    }

    #[test]
    fn authorization_rejects_payload_substitution_and_redacts_debug() {
        let exact = payload("example.authorization", 0x5a);
        let debug = format!("{exact:?}");
        assert!(!debug.contains(&"5a".repeat(16)));
        assert!(matches!(
            SandboxAuthorization::from_parts(
                exact.name().clone(),
                exact.payload_schema_version(),
                exact.payload_sha256(),
                vec![0x6b; 32]
            ),
            Err(SandboxAuthorizationError::PayloadDigestMismatch)
        ));
    }

    #[test]
    fn bundle_rejects_noncanonical_entries_and_defaults_to_explicit_empty() {
        assert!(matches!(
            SandboxAuthorizations::new(vec![payload("zulu", 1), payload("alpha", 2)]),
            Err(SandboxAuthorizationError::NonCanonicalOrder)
        ));
        assert!(SandboxAuthorizations::default().as_slice().is_empty());
    }
}
