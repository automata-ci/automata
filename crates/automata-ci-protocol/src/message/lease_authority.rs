//! Provider-neutral authority contributions attached to a lease poll.

use std::fmt;

use automata_ci_core::Sha256Digest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Current schema of the canonical lease-authority contribution bundle.
pub const LEASE_AUTHORITY_POLL_CONTRIBUTIONS_SCHEMA_VERSION: u16 = 1;
/// Maximum number of independent extensions contributing to one poll.
pub const MAX_LEASE_AUTHORITY_POLL_CONTRIBUTIONS: usize = 16;
/// Maximum UTF-8 bytes in one lease-authority namespace.
pub const MAX_LEASE_AUTHORITY_NAME_BYTES: usize = 128;
/// Maximum bytes in one provider-owned contribution payload.
pub const MAX_LEASE_AUTHORITY_POLL_PAYLOAD_BYTES: usize = 1024 * 1024;

const CONTRIBUTIONS_DIGEST_DOMAIN: &[u8] = b"automata.lease-authority-poll-contributions.v1\0";

/// Canonical namespace owned by one lease-authority extension.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct LeaseAuthorityName(String);

impl LeaseAuthorityName {
    /// Validates a lowercase portable extension namespace.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, path-like, or noncanonical names.
    pub fn new(value: impl Into<String>) -> Result<Self, LeaseAuthorityPollContributionError> {
        let value = value.into();
        let mut bytes = value.bytes();
        let valid_first = bytes.next().is_some_and(|byte| byte.is_ascii_lowercase());
        let valid_rest = bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        });
        if value.len() <= MAX_LEASE_AUTHORITY_NAME_BYTES && valid_first && valid_rest {
            Ok(Self(value))
        } else {
            Err(LeaseAuthorityPollContributionError::InvalidName)
        }
    }

    /// Returns the canonical extension namespace.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<LeaseAuthorityName> for String {
    fn from(value: LeaseAuthorityName) -> Self {
        value.0
    }
}

impl TryFrom<String> for LeaseAuthorityName {
    type Error = LeaseAuthorityPollContributionError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LeaseAuthorityPollContributionDocument {
    name: LeaseAuthorityName,
    payload_schema_version: u16,
    payload_sha256: Sha256Digest,
    payload: Box<[u8]>,
}

/// One bounded, provider-owned lease-poll contribution.
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(
    try_from = "LeaseAuthorityPollContributionDocument",
    into = "LeaseAuthorityPollContributionDocument"
)]
pub struct LeaseAuthorityPollContribution {
    name: LeaseAuthorityName,
    payload_schema_version: u16,
    payload_sha256: Sha256Digest,
    payload: Box<[u8]>,
}

impl LeaseAuthorityPollContribution {
    /// Creates a contribution and commits to its exact payload bytes.
    ///
    /// # Errors
    ///
    /// Rejects schema zero, an empty payload, or a payload above the hard bound.
    pub fn new(
        name: LeaseAuthorityName,
        payload_schema_version: u16,
        payload: impl Into<Box<[u8]>>,
    ) -> Result<Self, LeaseAuthorityPollContributionError> {
        let payload = payload.into();
        let payload_sha256 = Sha256Digest::from_bytes(Sha256::digest(&payload).into());
        Self::from_parts(name, payload_schema_version, payload_sha256, payload)
    }

    /// Rehydrates one contribution at a transport boundary.
    ///
    /// # Errors
    ///
    /// Rejects invalid bounds or a digest that does not match the payload.
    pub fn from_parts(
        name: LeaseAuthorityName,
        payload_schema_version: u16,
        payload_sha256: Sha256Digest,
        payload: impl Into<Box<[u8]>>,
    ) -> Result<Self, LeaseAuthorityPollContributionError> {
        let payload = payload.into();
        if payload_schema_version == 0 {
            return Err(LeaseAuthorityPollContributionError::ZeroPayloadSchema);
        }
        if payload.is_empty() || payload.len() > MAX_LEASE_AUTHORITY_POLL_PAYLOAD_BYTES {
            return Err(LeaseAuthorityPollContributionError::InvalidPayloadSize);
        }
        let actual = Sha256Digest::from_bytes(Sha256::digest(&payload).into());
        if actual != payload_sha256 {
            return Err(LeaseAuthorityPollContributionError::PayloadDigestMismatch);
        }
        Ok(Self {
            name,
            payload_schema_version,
            payload_sha256,
            payload,
        })
    }

    /// Returns the extension namespace.
    #[must_use]
    pub const fn name(&self) -> &LeaseAuthorityName {
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

    /// Returns the exact provider-owned payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl fmt::Debug for LeaseAuthorityPollContribution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeaseAuthorityPollContribution")
            .field("name", &self.name)
            .field("payload_schema_version", &self.payload_schema_version)
            .field("payload_sha256", &self.payload_sha256)
            .field("payload_bytes", &self.payload.len())
            .finish()
    }
}

impl From<LeaseAuthorityPollContribution> for LeaseAuthorityPollContributionDocument {
    fn from(value: LeaseAuthorityPollContribution) -> Self {
        Self {
            name: value.name,
            payload_schema_version: value.payload_schema_version,
            payload_sha256: value.payload_sha256,
            payload: value.payload,
        }
    }
}

impl TryFrom<LeaseAuthorityPollContributionDocument> for LeaseAuthorityPollContribution {
    type Error = LeaseAuthorityPollContributionError;

    fn try_from(value: LeaseAuthorityPollContributionDocument) -> Result<Self, Self::Error> {
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
struct LeaseAuthorityPollReceiptDocument {
    name: LeaseAuthorityName,
    payload_schema_version: u16,
    payload_sha256: Sha256Digest,
}

/// Value-free identity of one contribution durably accepted by control.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(
    try_from = "LeaseAuthorityPollReceiptDocument",
    into = "LeaseAuthorityPollReceiptDocument"
)]
pub struct LeaseAuthorityPollReceipt {
    name: LeaseAuthorityName,
    payload_schema_version: u16,
    payload_sha256: Sha256Digest,
}

impl LeaseAuthorityPollReceipt {
    /// Creates the exact acknowledgement identity for one accepted contribution.
    #[must_use]
    pub fn for_contribution(contribution: &LeaseAuthorityPollContribution) -> Self {
        Self {
            name: contribution.name().clone(),
            payload_schema_version: contribution.payload_schema_version(),
            payload_sha256: contribution.payload_sha256(),
        }
    }

    /// Rehydrates one value-free acknowledgement identity.
    ///
    /// # Errors
    ///
    /// Rejects reserved payload schema zero.
    pub fn from_parts(
        name: LeaseAuthorityName,
        payload_schema_version: u16,
        payload_sha256: Sha256Digest,
    ) -> Result<Self, LeaseAuthorityPollContributionError> {
        if payload_schema_version == 0 {
            return Err(LeaseAuthorityPollContributionError::ZeroPayloadSchema);
        }
        Ok(Self {
            name,
            payload_schema_version,
            payload_sha256,
        })
    }

    /// Returns the extension namespace.
    #[must_use]
    pub const fn name(&self) -> &LeaseAuthorityName {
        &self.name
    }

    /// Returns the accepted provider-owned payload schema.
    #[must_use]
    pub const fn payload_schema_version(&self) -> u16 {
        self.payload_schema_version
    }

    /// Returns the digest of the exact accepted payload bytes.
    #[must_use]
    pub const fn payload_sha256(&self) -> Sha256Digest {
        self.payload_sha256
    }
}

impl From<LeaseAuthorityPollReceipt> for LeaseAuthorityPollReceiptDocument {
    fn from(value: LeaseAuthorityPollReceipt) -> Self {
        Self {
            name: value.name,
            payload_schema_version: value.payload_schema_version,
            payload_sha256: value.payload_sha256,
        }
    }
}

impl TryFrom<LeaseAuthorityPollReceiptDocument> for LeaseAuthorityPollReceipt {
    type Error = LeaseAuthorityPollContributionError;

    fn try_from(value: LeaseAuthorityPollReceiptDocument) -> Result<Self, Self::Error> {
        Self::from_parts(
            value.name,
            value.payload_schema_version,
            value.payload_sha256,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LeaseAuthorityPollContributionsDocument {
    schema_version: u16,
    contributions: Vec<LeaseAuthorityPollContribution>,
    sha256_digest: Sha256Digest,
}

/// Canonical contribution bundle which a server must explicitly acknowledge.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(
    try_from = "LeaseAuthorityPollContributionsDocument",
    into = "LeaseAuthorityPollContributionsDocument"
)]
pub struct LeaseAuthorityPollContributions {
    schema_version: u16,
    contributions: Vec<LeaseAuthorityPollContribution>,
    sha256_digest: Sha256Digest,
}

impl LeaseAuthorityPollContributions {
    /// Creates a canonical contribution bundle.
    ///
    /// # Errors
    ///
    /// Rejects oversized, duplicate, or noncanonically ordered entries.
    pub fn new(
        contributions: Vec<LeaseAuthorityPollContribution>,
    ) -> Result<Self, LeaseAuthorityPollContributionError> {
        let sha256_digest = contributions_digest(
            LEASE_AUTHORITY_POLL_CONTRIBUTIONS_SCHEMA_VERSION,
            &contributions,
        );
        Self::from_parts(
            LEASE_AUTHORITY_POLL_CONTRIBUTIONS_SCHEMA_VERSION,
            contributions,
            sha256_digest,
        )
    }

    /// Creates the canonical empty contribution bundle.
    #[must_use]
    pub fn empty() -> Self {
        let contributions = Vec::new();
        let sha256_digest = contributions_digest(
            LEASE_AUTHORITY_POLL_CONTRIBUTIONS_SCHEMA_VERSION,
            &contributions,
        );
        Self {
            schema_version: LEASE_AUTHORITY_POLL_CONTRIBUTIONS_SCHEMA_VERSION,
            contributions,
            sha256_digest,
        }
    }

    /// Rehydrates a bundle with its claimed canonical digest.
    ///
    /// # Errors
    ///
    /// Rejects unsupported schema, invalid ordering, or digest substitution.
    pub fn from_parts(
        schema_version: u16,
        contributions: Vec<LeaseAuthorityPollContribution>,
        sha256_digest: Sha256Digest,
    ) -> Result<Self, LeaseAuthorityPollContributionError> {
        if schema_version != LEASE_AUTHORITY_POLL_CONTRIBUTIONS_SCHEMA_VERSION {
            return Err(LeaseAuthorityPollContributionError::UnsupportedSchema);
        }
        if contributions.len() > MAX_LEASE_AUTHORITY_POLL_CONTRIBUTIONS {
            return Err(LeaseAuthorityPollContributionError::InvalidCount);
        }
        let mut previous: Option<&LeaseAuthorityName> = None;
        for contribution in &contributions {
            if previous.is_some_and(|name| name >= contribution.name()) {
                return Err(LeaseAuthorityPollContributionError::NonCanonicalOrder);
            }
            previous = Some(contribution.name());
        }
        if contributions_digest(schema_version, &contributions) != sha256_digest {
            return Err(LeaseAuthorityPollContributionError::BundleDigestMismatch);
        }
        Ok(Self {
            schema_version,
            contributions,
            sha256_digest,
        })
    }

    /// Returns the bundle schema.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns contributions in canonical namespace order.
    #[must_use]
    pub fn as_slice(&self) -> &[LeaseAuthorityPollContribution] {
        &self.contributions
    }

    /// Finds one exact extension namespace.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&LeaseAuthorityPollContribution> {
        self.contributions
            .binary_search_by(|contribution| contribution.name().as_str().cmp(name))
            .ok()
            .map(|index| &self.contributions[index])
    }

    /// Returns the canonical digest a successful poll response must echo.
    #[must_use]
    pub const fn sha256_digest(&self) -> Sha256Digest {
        self.sha256_digest
    }
}

impl Default for LeaseAuthorityPollContributions {
    fn default() -> Self {
        Self::empty()
    }
}

impl From<LeaseAuthorityPollContributions> for LeaseAuthorityPollContributionsDocument {
    fn from(value: LeaseAuthorityPollContributions) -> Self {
        Self {
            schema_version: value.schema_version,
            contributions: value.contributions,
            sha256_digest: value.sha256_digest,
        }
    }
}

impl TryFrom<LeaseAuthorityPollContributionsDocument> for LeaseAuthorityPollContributions {
    type Error = LeaseAuthorityPollContributionError;

    fn try_from(value: LeaseAuthorityPollContributionsDocument) -> Result<Self, Self::Error> {
        Self::from_parts(
            value.schema_version,
            value.contributions,
            value.sha256_digest,
        )
    }
}

fn contributions_digest(
    schema_version: u16,
    contributions: &[LeaseAuthorityPollContribution],
) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(CONTRIBUTIONS_DIGEST_DOMAIN);
    digest.update(schema_version.to_be_bytes());
    digest.update(
        u32::try_from(contributions.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for contribution in contributions {
        update_bytes(&mut digest, contribution.name().as_str().as_bytes());
        digest.update(contribution.payload_schema_version().to_be_bytes());
        digest.update(contribution.payload_sha256().as_bytes());
        update_bytes(&mut digest, contribution.payload());
    }
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn update_bytes(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

/// Invalid provider-neutral lease-authority contribution material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LeaseAuthorityPollContributionError {
    /// The extension namespace is empty, oversized, path-like, or noncanonical.
    #[error("lease authority name is invalid")]
    InvalidName,
    /// Payload schema zero is reserved.
    #[error("lease authority payload schema must be nonzero")]
    ZeroPayloadSchema,
    /// Payload is empty or above the hard bound.
    #[error("lease authority contribution payload size is invalid")]
    InvalidPayloadSize,
    /// Payload bytes disagree with their claimed digest.
    #[error("lease authority contribution payload digest does not match")]
    PayloadDigestMismatch,
    /// The contribution bundle schema is unsupported.
    #[error("lease authority contribution bundle schema is unsupported")]
    UnsupportedSchema,
    /// The contribution bundle contains too many entries.
    #[error("lease authority contribution count is invalid")]
    InvalidCount,
    /// Contributions are not strictly ordered by unique namespace.
    #[error("lease authority contributions are not in canonical order")]
    NonCanonicalOrder,
    /// The claimed canonical bundle digest is incorrect.
    #[error("lease authority contribution bundle digest does not match")]
    BundleDigestMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contribution(name: &str, byte: u8) -> LeaseAuthorityPollContribution {
        LeaseAuthorityPollContribution::new(
            LeaseAuthorityName::new(name).expect("name"),
            1,
            vec![byte; 32],
        )
        .expect("contribution")
    }

    #[test]
    fn exact_bundle_digest_commits_to_payload_and_order() {
        let first = contribution("alpha", 1);
        let second = contribution("zulu", 2);
        let bundle = LeaseAuthorityPollContributions::new(vec![first.clone(), second.clone()])
            .expect("bundle");
        assert_eq!(
            bundle.sha256_digest().to_string(),
            "77cbaccb7a406d175fe88ff86e4efa43ab63ab597d7ee1196d7602388eb6687e"
        );
        assert_ne!(
            bundle.sha256_digest(),
            LeaseAuthorityPollContributions::empty().sha256_digest()
        );
        assert!(matches!(
            LeaseAuthorityPollContributions::from_parts(
                bundle.schema_version(),
                vec![second, first],
                bundle.sha256_digest(),
            ),
            Err(LeaseAuthorityPollContributionError::NonCanonicalOrder)
        ));
    }

    #[test]
    fn payload_and_bundle_digest_substitution_fail_closed() {
        let exact = contribution("alpha", 1);
        assert!(matches!(
            LeaseAuthorityPollContribution::from_parts(
                exact.name().clone(),
                exact.payload_schema_version(),
                exact.payload_sha256(),
                vec![2; 32],
            ),
            Err(LeaseAuthorityPollContributionError::PayloadDigestMismatch)
        ));
        assert!(matches!(
            LeaseAuthorityPollContributions::from_parts(
                LEASE_AUTHORITY_POLL_CONTRIBUTIONS_SCHEMA_VERSION,
                vec![exact],
                Sha256Digest::from_bytes([0x5a; 32]),
            ),
            Err(LeaseAuthorityPollContributionError::BundleDigestMismatch)
        ));
    }

    #[test]
    fn receipt_identity_includes_payload_schema() {
        let exact = contribution("alpha", 1);
        let receipt = LeaseAuthorityPollReceipt::for_contribution(&exact);
        let another_schema = LeaseAuthorityPollReceipt::from_parts(
            exact.name().clone(),
            exact.payload_schema_version() + 1,
            exact.payload_sha256(),
        )
        .expect("receipt");
        assert_ne!(receipt, another_schema);
    }
}
