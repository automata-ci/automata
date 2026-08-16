//! Stable local-installation identity derived from an explicit selector.

use std::{fmt, str::FromStr};

use automata_ci_core::Sha256Digest;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::{Uuid, Version};

const DEFAULT_INSTALLATION_NAME: &str = "default";
const MAX_INSTALLATION_NAME_BYTES: usize = 64;
const SELECTOR_KEY_DOMAIN: &[u8] = b"automata/local/installation-selector/v1\0";
const ENGINE_NAME_KEY_HEX_LENGTH: usize = 32;
const ENGINE_NAME_PREFIX: &str = "automata-local-";

/// Canonical user-facing selector for one local control-plane installation.
///
/// An installation is a deployment and runner-capacity domain. It is not bound
/// to one source repository; repository identity belongs to workflow admission.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InstallationName(String);

impl InstallationName {
    /// Validates a canonical installation selector.
    ///
    /// # Errors
    ///
    /// Returns [`InstallationNameError`] when `value` is empty, exceeds 64
    /// bytes, or is not lower-case ASCII alphanumeric text separated by single
    /// hyphens.
    pub fn new(value: impl Into<String>) -> Result<Self, InstallationNameError> {
        let value = value.into();
        if value.is_empty() {
            return Err(InstallationNameError::Empty);
        }
        if value.len() > MAX_INSTALLATION_NAME_BYTES {
            return Err(InstallationNameError::TooLong);
        }
        let bytes = value.as_bytes();
        if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
            return Err(InstallationNameError::InvalidSyntax);
        }
        if !bytes[bytes.len() - 1].is_ascii_lowercase() && !bytes[bytes.len() - 1].is_ascii_digit()
        {
            return Err(InstallationNameError::InvalidSyntax);
        }
        if bytes
            .iter()
            .any(|byte| !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && *byte != b'-')
            || bytes.windows(2).any(|pair| pair == b"--")
        {
            return Err(InstallationNameError::InvalidSyntax);
        }
        Ok(Self(value))
    }

    /// Returns the canonical selector text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for InstallationName {
    fn default() -> Self {
        Self(DEFAULT_INSTALLATION_NAME.to_owned())
    }
}

impl fmt::Display for InstallationName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for InstallationName {
    type Err = InstallationNameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// Rejected local-installation selector.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum InstallationNameError {
    /// The selector was empty.
    #[error("installation name cannot be empty")]
    Empty,
    /// The selector exceeded the bounded input length.
    #[error("installation name cannot exceed 64 bytes")]
    TooLong,
    /// The selector was not canonical lower-case ASCII text.
    #[error(
        "installation name must use lowercase ASCII letters, digits, and single interior hyphens"
    )]
    InvalidSyntax,
}

/// Full domain-separated digest identifying an installation selector.
///
/// Version 1 is SHA-256 over the literal bytes
/// `automata/local/installation-selector/v1\0`, the canonical selector byte
/// length as one unsigned big-endian 16-bit integer, and the selector's ASCII
/// bytes, in that order. Docker names use the leading 128 bits; every adoption
/// also compares this full 256-bit value from the managed label.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InstallationSelectorKey(Sha256Digest);

impl InstallationSelectorKey {
    pub(crate) fn for_name(name: &InstallationName) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(SELECTOR_KEY_DOMAIN);
        hasher.update(
            u16::try_from(name.as_str().len())
                .expect("validated installation names fit in u16")
                .to_be_bytes(),
        );
        hasher.update(name.as_str().as_bytes());
        Self(Sha256Digest::from_bytes(hasher.finalize().into()))
    }

    /// Returns the full 256-bit selector digest.
    pub const fn digest(self) -> Sha256Digest {
        self.0
    }

    fn engine_name_component(self) -> String {
        self.to_string()[..ENGINE_NAME_KEY_HEX_LENGTH].to_owned()
    }
}

impl fmt::Display for InstallationSelectorKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Deterministic Docker Compose project name for one installation selector.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ComposeProjectName(String);

impl ComposeProjectName {
    fn for_key(key: InstallationSelectorKey) -> Self {
        Self(format!(
            "{ENGINE_NAME_PREFIX}{}",
            key.engine_name_component()
        ))
    }

    /// Returns the engine-safe project name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ComposeProjectName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Random immutable identity stored on one installation anchor.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InstallationId(Uuid);

impl InstallationId {
    pub(crate) fn parse_canonical(value: &str) -> Option<Self> {
        let parsed = Uuid::parse_str(value).ok()?;
        (parsed.to_string() == value && parsed.get_version() == Some(Version::Random))
            .then_some(Self(parsed))
    }

    /// Returns the immutable UUID.
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for InstallationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for InstallationId {
    type Err = InstallationIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse_canonical(value).ok_or(InstallationIdError)
    }
}

/// Rejected noncanonical or non-random installation UUID.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("installation identity must be a canonical UUIDv4")]
pub struct InstallationIdError;

/// Verified identity of one engine-owned local installation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Installation {
    name: InstallationName,
    id: InstallationId,
    selector_key: InstallationSelectorKey,
    compose_project: ComposeProjectName,
    anchor_volume_name: String,
}

impl Installation {
    /// Constructs the exact expected installation binding.
    ///
    /// Provider connection still verifies this name and UUID against the
    /// immutable Engine-owned installation anchor before use.
    #[must_use]
    pub fn new(name: InstallationName, id: InstallationId) -> Self {
        let selector_key = InstallationSelectorKey::for_name(&name);
        let compose_project = ComposeProjectName::for_key(selector_key);
        let anchor_volume_name = format!("{compose_project}-identity");
        Self {
            name,
            id,
            selector_key,
            compose_project,
            anchor_volume_name,
        }
    }

    #[cfg(unix)]
    pub(crate) fn expected(name: &InstallationName) -> ExpectedInstallation {
        let selector_key = InstallationSelectorKey::for_name(name);
        let compose_project = ComposeProjectName::for_key(selector_key);
        let anchor_volume_name = format!("{compose_project}-identity");
        ExpectedInstallation {
            selector_key,
            compose_project,
            anchor_volume_name,
        }
    }

    /// Returns the user-facing installation selector.
    pub const fn name(&self) -> &InstallationName {
        &self.name
    }

    /// Returns the immutable installation UUID.
    pub const fn id(&self) -> InstallationId {
        self.id
    }

    /// Returns the full selector key verified from the anchor labels.
    pub const fn selector_key(&self) -> InstallationSelectorKey {
        self.selector_key
    }

    /// Returns the deterministic Compose project name.
    pub const fn compose_project(&self) -> &ComposeProjectName {
        &self.compose_project
    }

    /// Returns the deterministic external identity-volume name.
    pub fn anchor_volume_name(&self) -> &str {
        &self.anchor_volume_name
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(unix)]
pub(crate) struct ExpectedInstallation {
    pub(crate) selector_key: InstallationSelectorKey,
    pub(crate) compose_project: ComposeProjectName,
    pub(crate) anchor_volume_name: String,
}

#[cfg(test)]
mod tests {
    use super::{
        ComposeProjectName, Installation, InstallationId, InstallationName, InstallationNameError,
        InstallationSelectorKey,
    };

    #[test]
    fn installation_names_are_canonical_and_bounded() {
        for valid in ["default", "team-2", "0", &"a".repeat(64)] {
            assert_eq!(
                InstallationName::new(valid).expect("valid installation name"),
                valid.parse().expect("same parsed installation name")
            );
        }
        for (invalid, expected) in [
            ("", InstallationNameError::Empty),
            (&"a".repeat(65), InstallationNameError::TooLong),
            ("Team", InstallationNameError::InvalidSyntax),
            ("team_1", InstallationNameError::InvalidSyntax),
            ("-team", InstallationNameError::InvalidSyntax),
            ("team-", InstallationNameError::InvalidSyntax),
            ("team--1", InstallationNameError::InvalidSyntax),
        ] {
            assert_eq!(InstallationName::new(invalid), Err(expected));
        }
    }

    #[test]
    fn selector_preimage_and_engine_names_are_stable() {
        let name = InstallationName::default();
        let key = InstallationSelectorKey::for_name(&name);
        assert_eq!(
            key.to_string(),
            "df06ebed0fcba9b2d00b0476426924f354f73d0d7c6cd4ed2844b52787ccd120"
        );
        assert_eq!(
            ComposeProjectName::for_key(key).as_str(),
            "automata-local-df06ebed0fcba9b2d00b0476426924f3"
        );
        let expected = Installation::new(
            name,
            InstallationId::parse_canonical("00000000-0000-4000-8000-000000000001")
                .expect("canonical test installation ID"),
        );
        assert_eq!(
            expected.anchor_volume_name(),
            "automata-local-df06ebed0fcba9b2d00b0476426924f3-identity"
        );
    }
}
