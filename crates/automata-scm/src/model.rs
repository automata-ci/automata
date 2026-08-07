use std::fmt;

use automata_auth::secret::SecretString;
use automata_core::Sha256Digest;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const MAX_PROVIDER_ID_BYTES: usize = 64;
const MAX_REPOSITORY_ID_BYTES: usize = 512;
const MAX_REVISION_BYTES: usize = 1_024;
const MAX_ARCHIVE_BYTES: u64 = 4 * 1_024 * 1_024 * 1_024;
const DEFAULT_ARCHIVE_BYTES: u64 = 256 * 1_024 * 1_024;

/// Canonical identifier selecting one compiled SCM adapter.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct ScmProviderId(String);

impl ScmProviderId {
    /// Creates a lowercase provider identifier.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, non-ASCII, or noncanonical identifiers.
    pub fn new(value: impl Into<String>) -> Result<Self, ScmProviderIdError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_PROVIDER_ID_BYTES {
            return Err(ScmProviderIdError);
        }
        if !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'-'))
        }) || value.ends_with(['.', '-'])
        {
            return Err(ScmProviderIdError);
        }
        Ok(Self(value))
    }

    /// Returns the canonical provider identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ScmProviderId {
    type Error = ScmProviderIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ScmProviderId> for String {
    fn from(value: ScmProviderId) -> Self {
        value.0
    }
}

/// Provider-native repository identity without credentials or a URL.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct RepositoryId(String);

impl RepositoryId {
    /// Creates an opaque, bounded repository identifier.
    ///
    /// Individual providers apply their stricter naming rules before network
    /// access.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, control-containing, absolute, or path-aliased
    /// values.
    pub fn new(value: impl Into<String>) -> Result<Self, RepositoryIdError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_REPOSITORY_ID_BYTES {
            return Err(RepositoryIdError::InvalidLength);
        }
        if value.starts_with('/') || value.contains('\\') || value.chars().any(char::is_control) {
            return Err(RepositoryIdError::UnsafeCharacter);
        }
        if value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
        {
            return Err(RepositoryIdError::InvalidComponent);
        }
        Ok(Self(value))
    }

    /// Returns the provider-native identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RepositoryId {
    type Error = RepositoryIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<RepositoryId> for String {
    fn from(value: RepositoryId) -> Self {
        value.0
    }
}

macro_rules! revision_type {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Creates a bounded provider-native revision.
            ///
            /// # Errors
            ///
            /// Rejects empty, oversized, or control-containing values.
            pub fn new(value: impl Into<String>) -> Result<Self, RevisionError> {
                let value = value.into();
                if value.is_empty() || value.len() > MAX_REVISION_BYTES {
                    return Err(RevisionError::InvalidLength);
                }
                if value.chars().any(char::is_control) {
                    return Err(RevisionError::ControlCharacter);
                }
                Ok(Self(value))
            }

            /// Returns the provider-native revision text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = RevisionError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

revision_type!(
    RevisionSpec,
    "A user-facing branch, tag, or immutable revision request."
);
revision_type!(
    ResolvedRevision,
    "The immutable revision proven by an SCM provider."
);

/// Archive encoding returned by a provider.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveFormat {
    TarGzip,
}

/// Caller-controlled archive resource ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveLimits {
    maximum_bytes: u64,
}

impl ArchiveLimits {
    /// Creates a nonzero archive ceiling no larger than four GiB.
    ///
    /// # Errors
    ///
    /// Rejects zero and unreasonably large in-memory archive limits.
    pub const fn new(maximum_bytes: u64) -> Result<Self, ArchiveLimitsError> {
        if maximum_bytes == 0 || maximum_bytes > MAX_ARCHIVE_BYTES {
            return Err(ArchiveLimitsError);
        }
        Ok(Self { maximum_bytes })
    }

    /// Returns the inclusive archive byte ceiling.
    #[must_use]
    pub const fn maximum_bytes(self) -> u64 {
        self.maximum_bytes
    }
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            maximum_bytes: DEFAULT_ARCHIVE_BYTES,
        }
    }
}

/// One credential-scoped repository snapshot request.
pub struct SnapshotRequest<'a> {
    repository: &'a RepositoryId,
    revision: &'a RevisionSpec,
    credential: Option<&'a SecretString>,
    limits: ArchiveLimits,
}

impl<'a> SnapshotRequest<'a> {
    /// Creates a public-repository request without credentials.
    #[must_use]
    pub const fn public(
        repository: &'a RepositoryId,
        revision: &'a RevisionSpec,
        limits: ArchiveLimits,
    ) -> Self {
        Self {
            repository,
            revision,
            credential: None,
            limits,
        }
    }

    /// Creates a private-repository request with a scoped provider credential.
    #[must_use]
    pub const fn authenticated(
        repository: &'a RepositoryId,
        revision: &'a RevisionSpec,
        credential: &'a SecretString,
        limits: ArchiveLimits,
    ) -> Self {
        Self {
            repository,
            revision,
            credential: Some(credential),
            limits,
        }
    }

    #[must_use]
    pub const fn repository(&self) -> &RepositoryId {
        self.repository
    }

    #[must_use]
    pub const fn revision(&self) -> &RevisionSpec {
        self.revision
    }

    #[must_use]
    pub const fn credential(&self) -> Option<&SecretString> {
        self.credential
    }

    #[must_use]
    pub const fn limits(&self) -> ArchiveLimits {
        self.limits
    }
}

impl fmt::Debug for SnapshotRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnapshotRequest")
            .field("repository", &self.repository)
            .field("revision", &self.revision)
            .field("credential", &self.credential.map(|_| "[redacted]"))
            .field("limits", &self.limits)
            .finish()
    }
}

/// Immutable, content-addressed repository archive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositorySnapshot {
    provider: ScmProviderId,
    repository: RepositoryId,
    requested_revision: RevisionSpec,
    resolved_revision: ResolvedRevision,
    format: ArchiveFormat,
    digest: Sha256Digest,
    bytes: Bytes,
}

impl RepositorySnapshot {
    /// Hashes bounded bytes returned by a provider adapter.
    #[must_use]
    pub fn from_bytes(
        provider: ScmProviderId,
        repository: RepositoryId,
        requested_revision: RevisionSpec,
        resolved_revision: ResolvedRevision,
        format: ArchiveFormat,
        bytes: Bytes,
    ) -> Self {
        let digest = Sha256Digest::from_bytes(Sha256::digest(&bytes).into());
        Self {
            provider,
            repository,
            requested_revision,
            resolved_revision,
            format,
            digest,
            bytes,
        }
    }

    #[must_use]
    pub const fn provider(&self) -> &ScmProviderId {
        &self.provider
    }

    #[must_use]
    pub const fn repository(&self) -> &RepositoryId {
        &self.repository
    }

    #[must_use]
    pub const fn requested_revision(&self) -> &RevisionSpec {
        &self.requested_revision
    }

    #[must_use]
    pub const fn resolved_revision(&self) -> &ResolvedRevision {
        &self.resolved_revision
    }

    #[must_use]
    pub const fn format(&self) -> ArchiveFormat {
        self.format
    }

    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    #[must_use]
    pub fn size(&self) -> u64 {
        u64::try_from(self.bytes.len()).unwrap_or(u64::MAX)
    }

    #[must_use]
    pub const fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("SCM provider ID is not canonical")]
pub struct ScmProviderIdError;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RepositoryIdError {
    #[error("repository ID length is invalid")]
    InvalidLength,
    #[error("repository ID contains an unsafe character")]
    UnsafeCharacter,
    #[error("repository ID contains an empty or traversal component")]
    InvalidComponent,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RevisionError {
    #[error("revision length is invalid")]
    InvalidLength,
    #[error("revision contains a control character")]
    ControlCharacter,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("archive byte limit must be in 1..=4294967296")]
pub struct ArchiveLimitsError;
