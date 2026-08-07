//! Content-attested execution-environment profiles.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use thiserror::Error;

use crate::Sha256Digest;

const MAX_ENVIRONMENT_PROFILE_ID_LENGTH: usize = 128;

/// Stable, provider-namespaced identity for an execution-environment profile.
///
/// The identity deliberately does not imply mutable image contents. An
/// [`EnvironmentProfile`] pairs it with a content attestation digest.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EnvironmentProfileId(String);

impl EnvironmentProfileId {
    /// Validates a `<provider-namespace>/<profile-name>` identity.
    /// Reverse-DNS namespaces are recommended for third-party providers.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentProfileError`] when the value is not canonical.
    pub fn new(value: impl Into<String>) -> Result<Self, EnvironmentProfileError> {
        let value = value.into();
        validate_profile_id(&value)?;
        Ok(Self(value))
    }

    /// Returns the canonical profile identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EnvironmentProfileId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for EnvironmentProfileId {
    type Err = EnvironmentProfileError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for EnvironmentProfileId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for EnvironmentProfileId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

/// Exact, content-attested execution environment understood by a runner.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentProfile {
    id: EnvironmentProfileId,
    digest: Sha256Digest,
}

impl EnvironmentProfile {
    /// Creates an immutable environment-profile reference.
    #[must_use]
    pub const fn new(id: EnvironmentProfileId, digest: Sha256Digest) -> Self {
        Self { id, digest }
    }

    /// Returns the stable, namespaced profile identity.
    #[must_use]
    pub const fn id(&self) -> &EnvironmentProfileId {
        &self.id
    }

    /// Returns the digest of the server-attested profile manifest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

fn validate_profile_id(value: &str) -> Result<(), EnvironmentProfileError> {
    if value.is_empty() {
        return Err(EnvironmentProfileError::Empty);
    }
    if value.len() > MAX_ENVIRONMENT_PROFILE_ID_LENGTH {
        return Err(EnvironmentProfileError::TooLong {
            maximum: MAX_ENVIRONMENT_PROFILE_ID_LENGTH,
        });
    }
    if !value.is_ascii() {
        return Err(EnvironmentProfileError::NonAscii);
    }
    let (namespace, name) = value
        .split_once('/')
        .ok_or(EnvironmentProfileError::MissingNamespace)?;
    if namespace.is_empty()
        || namespace
            .split('.')
            .any(|part| !valid_component(part, false))
    {
        return Err(EnvironmentProfileError::InvalidNamespace);
    }
    if name.is_empty()
        || name.contains('/')
        || name.split('.').any(|part| !valid_component(part, true))
    {
        return Err(EnvironmentProfileError::InvalidName);
    }
    Ok(())
}

fn valid_component(value: &str, allow_leading_digit: bool) -> bool {
    let bytes = value.as_bytes();
    let Some(first) = bytes.first() else {
        return false;
    };
    let Some(last) = bytes.last() else {
        return false;
    };
    (first.is_ascii_lowercase() || (allow_leading_digit && first.is_ascii_digit()))
        && (last.is_ascii_lowercase() || last.is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// Invalid stable environment-profile identity.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EnvironmentProfileError {
    #[error("environment profile identity cannot be empty")]
    Empty,
    #[error("environment profile identity exceeds {maximum} bytes")]
    TooLong { maximum: usize },
    #[error("environment profile identity must contain only ASCII characters")]
    NonAscii,
    #[error("environment profile identity must be namespaced as `<namespace>/<name>`")]
    MissingNamespace,
    #[error("environment profile namespace must be canonical provider text")]
    InvalidNamespace,
    #[error("environment profile name must be canonical lower-case text")]
    InvalidName,
}
