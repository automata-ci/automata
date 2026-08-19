use std::fmt;

use automata_ci_auth::secret::SecretStringRef;
use automata_ci_core::{GitObjectId, Sha256Digest};
use automata_ci_provider::{ExternalRepositoryId, ProviderConnectionId};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const MAX_PROVIDER_ID_BYTES: usize = 64;
const MAX_REPOSITORY_ID_BYTES: usize = 512;
const MAX_REVISION_BYTES: usize = 1_024;
const MAX_ARCHIVE_BYTES: u64 = 4 * 1_024 * 1_024 * 1_024;
const DEFAULT_ARCHIVE_BYTES: u64 = 256 * 1_024 * 1_024;

/// Canonical identifier selecting one configured SCM provider adapter.
///
/// Provider IDs are stable policy and routing keys, not network locations or
/// credentials. Their restricted syntax keeps serialized identities portable
/// across adapters and durable storage.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct ScmProviderId(String);

impl ScmProviderId {
    /// Creates a canonical lowercase provider identifier.
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

    /// Returns the canonical provider identifier used for routing and storage.
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
///
/// This value is an opaque routing identity. It deliberately cannot encode an
/// absolute path, platform-specific path, or authentication material.
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

    /// Returns the validated provider-native repository identity.
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
    "A user-facing branch, tag, or immutable revision selector. The provider must treat this value as mutable until it resolves the request."
);
/// Archive encoding returned by a provider.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveFormat {
    /// A tar archive compressed with gzip.
    TarGzip,
}

/// Caller-controlled ceiling on downloaded compressed archive bytes.
///
/// Providers must enforce this limit incrementally rather than trusting a
/// response's declared content length. The default is 256 MiB.
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

/// One borrowed, credential-scoped repository snapshot request.
///
/// The requested [`RevisionSpec`] may name mutable provider state. A provider
/// resolves it to a distinct [`GitObjectId`] before returning a snapshot.
/// Any credential is borrowed for this request only and is redacted by the
/// [`Debug`](fmt::Debug) implementation.
pub struct SnapshotRequest<'a> {
    repository: &'a RepositoryId,
    revision: &'a RevisionSpec,
    credential: Option<SecretStringRef<'a>>,
    limits: ArchiveLimits,
}

impl<'a> SnapshotRequest<'a> {
    /// Creates a repository request without an explicit credential.
    ///
    /// Providers must not substitute ambient process, filesystem, or host
    /// credentials when this request is used.
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

    /// Creates a request with one explicitly scoped provider credential.
    ///
    /// The credential may be presented only to the selected provider during
    /// this operation. It must not be copied into the returned snapshot,
    /// retained by an adapter, sent to a redirected origin, or included in an
    /// error or diagnostic.
    #[must_use]
    pub const fn authenticated(
        repository: &'a RepositoryId,
        revision: &'a RevisionSpec,
        credential: SecretStringRef<'a>,
        limits: ArchiveLimits,
    ) -> Self {
        Self {
            repository,
            revision,
            credential: Some(credential),
            limits,
        }
    }

    /// Returns the exact provider-native repository requested by the caller.
    #[must_use]
    pub const fn repository(&self) -> &RepositoryId {
        self.repository
    }

    /// Returns the caller's unresolved, potentially mutable revision selector.
    #[must_use]
    pub const fn revision(&self) -> &RevisionSpec {
        self.revision
    }

    /// Returns the explicitly supplied request credential, when present.
    ///
    /// The returned reference remains tied to this request's borrow and must
    /// not be retained after the operation.
    #[must_use]
    pub const fn credential(&self) -> Option<SecretStringRef<'a>> {
        self.credential
    }

    /// Returns the compressed archive byte ceiling for this request.
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

/// Provider-neutral routing evidence for one repository connection.
///
/// The provider-native ID is authoritative identity. `repository` is the
/// provider-owned route authenticated for that identity by the caller's
/// admission boundary. Adapters must preserve both values in returned source
/// and prove the requested exact revision through the provider's trusted
/// archive boundary. The configured provider instance is supplied by the
/// selected [`RepositorySource`](crate::RepositorySource) adapter, so callers
/// cannot route a request to an arbitrary instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositorySourceConnection {
    connection_id: ProviderConnectionId,
    external_repository_id: ExternalRepositoryId,
    repository: RepositoryId,
}

impl RepositorySourceConnection {
    /// Binds one Automata connection to its provider-native identity and route.
    #[must_use]
    pub const fn new(
        connection_id: ProviderConnectionId,
        external_repository_id: ExternalRepositoryId,
        repository: RepositoryId,
    ) -> Self {
        Self {
            connection_id,
            external_repository_id,
            repository,
        }
    }

    /// Returns the stable Automata connection identity.
    #[must_use]
    pub const fn connection_id(&self) -> ProviderConnectionId {
        self.connection_id
    }

    /// Returns the provider-native repository identity.
    #[must_use]
    pub const fn external_repository_id(&self) -> &ExternalRepositoryId {
        &self.external_repository_id
    }

    /// Returns the provider-owned repository route.
    #[must_use]
    pub const fn repository(&self) -> &RepositoryId {
        &self.repository
    }
}

/// Redirect authority for one source-archive request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositorySourceRedirectPolicy {
    /// Reject every provider redirect.
    Deny,
    /// Permit one credential-free redirect to the adapter's configured archive origin.
    ConfiguredArchiveOrigin,
}

/// One borrowed request for source at an already known exact revision.
///
/// The connection coordinates must have been authenticated by the caller's
/// admission boundary. The revision is an immutable [`GitObjectId`], so an
/// implementation must prove that the provider returned source for that
/// byte-exact commit. Any credential is borrowed for this request only and is
/// redacted by the [`Debug`](fmt::Debug) implementation.
pub struct RepositorySourceRequest<'a> {
    connection: &'a RepositorySourceConnection,
    revision: &'a GitObjectId,
    credential: Option<SecretStringRef<'a>>,
    limits: ArchiveLimits,
    redirect_policy: RepositorySourceRedirectPolicy,
}

impl<'a> RepositorySourceRequest<'a> {
    /// Creates an exact-revision source request without an explicit credential.
    ///
    /// The caller must have authenticated `connection` before constructing the
    /// request. Providers must not substitute ambient process, filesystem, or
    /// host credentials when this request is used.
    #[must_use]
    pub const fn public(
        connection: &'a RepositorySourceConnection,
        revision: &'a GitObjectId,
        limits: ArchiveLimits,
        redirect_policy: RepositorySourceRedirectPolicy,
    ) -> Self {
        Self {
            connection,
            revision,
            credential: None,
            limits,
            redirect_policy,
        }
    }

    /// Creates an exact-revision request with one provider credential.
    ///
    /// The caller must have authenticated `connection` before constructing the
    /// request. The credential may be presented only to the selected provider
    /// during this operation. It must not be retained, forwarded to an archive
    /// origin, or included in returned source, errors, or diagnostics.
    #[must_use]
    pub const fn authenticated(
        connection: &'a RepositorySourceConnection,
        revision: &'a GitObjectId,
        credential: SecretStringRef<'a>,
        limits: ArchiveLimits,
        redirect_policy: RepositorySourceRedirectPolicy,
    ) -> Self {
        Self {
            connection,
            revision,
            credential: Some(credential),
            limits,
            redirect_policy,
        }
    }

    /// Returns the exact repository connection requested by the caller.
    #[must_use]
    pub const fn connection(&self) -> &RepositorySourceConnection {
        self.connection
    }

    /// Returns the provider-owned repository route requested by the caller.
    #[must_use]
    pub const fn repository(&self) -> &RepositoryId {
        self.connection.repository()
    }

    /// Returns the exact immutable revision requested by the caller.
    #[must_use]
    pub const fn revision(&self) -> &GitObjectId {
        self.revision
    }

    /// Returns the explicitly supplied request credential, when present.
    ///
    /// The returned reference remains tied to this request's borrow and must
    /// not be retained after the operation.
    #[must_use]
    pub const fn credential(&self) -> Option<SecretStringRef<'a>> {
        self.credential
    }

    /// Returns the compressed source-archive byte ceiling for this request.
    #[must_use]
    pub const fn limits(&self) -> ArchiveLimits {
        self.limits
    }

    /// Returns the redirect authority granted for this operation.
    #[must_use]
    pub const fn redirect_policy(&self) -> RepositorySourceRedirectPolicy {
        self.redirect_policy
    }
}

impl fmt::Debug for RepositorySourceRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepositorySourceRequest")
            .field("connection", &self.connection)
            .field("revision", &self.revision)
            .field("credential", &self.credential.map(|_| "[redacted]"))
            .field("limits", &self.limits)
            .field("redirect_policy", &self.redirect_policy)
            .finish()
    }
}

/// Immutable, content-addressed repository archive.
///
/// A snapshot binds the caller's original selector to the immutable revision
/// resolved by the provider and retains the exact downloaded archive bytes.
/// It contains no credential material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositorySnapshot {
    provider: ScmProviderId,
    repository: RepositoryId,
    requested_revision: RevisionSpec,
    resolved_revision: GitObjectId,
    format: ArchiveFormat,
    digest: Sha256Digest,
    bytes: Bytes,
}

impl RepositorySnapshot {
    /// Builds a snapshot and hashes the exact supplied archive bytes.
    ///
    /// The digest is SHA-256 over `bytes`, without decoding or normalization.
    /// Provider adapters are responsible for resolving `resolved_revision` to
    /// immutable state and enforcing [`ArchiveLimits`] before calling this
    /// constructor.
    #[must_use]
    pub fn from_bytes(
        provider: ScmProviderId,
        repository: RepositoryId,
        requested_revision: RevisionSpec,
        resolved_revision: GitObjectId,
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

    /// Returns the stable identifier of the provider that produced the bytes.
    #[must_use]
    pub const fn provider(&self) -> &ScmProviderId {
        &self.provider
    }

    /// Returns the provider-native repository represented by this snapshot.
    #[must_use]
    pub const fn repository(&self) -> &RepositoryId {
        &self.repository
    }

    /// Returns the original selector supplied by the caller.
    ///
    /// This value may be a mutable branch or tag and is retained for provenance;
    /// consumers should use [`Self::resolved_revision`] for immutable identity.
    #[must_use]
    pub const fn requested_revision(&self) -> &RevisionSpec {
        &self.requested_revision
    }

    /// Returns the immutable provider revision resolved for the request.
    #[must_use]
    pub const fn resolved_revision(&self) -> GitObjectId {
        self.resolved_revision
    }

    /// Returns the encoding of the retained archive bytes.
    #[must_use]
    pub const fn format(&self) -> ArchiveFormat {
        self.format
    }

    /// Returns the SHA-256 digest of the exact retained archive bytes.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Returns the retained archive length in bytes.
    ///
    /// The result saturates at [`u64::MAX`] on platforms whose address space
    /// could represent a larger byte buffer.
    #[must_use]
    pub fn size(&self) -> u64 {
        u64::try_from(self.bytes.len()).unwrap_or(u64::MAX)
    }

    /// Borrows the exact downloaded archive bytes.
    #[must_use]
    pub const fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// Consumes the snapshot and returns the exact downloaded archive bytes.
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }
}

/// Immutable source archive for one caller-supplied exact revision.
///
/// A provider adapter may construct this value only after proving that the
/// provider resolved the request to the same byte-exact [`GitObjectId`]. It
/// retains the exact bounded archive bytes and their local SHA-256 digest, and
/// contains no credential material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositorySourceArchive {
    connection_id: ProviderConnectionId,
    external_repository_id: ExternalRepositoryId,
    repository: RepositoryId,
    revision: GitObjectId,
    format: ArchiveFormat,
    digest: Sha256Digest,
    bytes: Bytes,
}

impl RepositorySourceArchive {
    /// Builds exact-revision source and hashes the exact supplied archive bytes.
    ///
    /// The digest is SHA-256 over `bytes`, without decoding or normalization.
    /// Provider adapters are responsible for proving `revision`, enforcing
    /// [`ArchiveLimits`], and validating the archive media type before calling
    /// this constructor.
    #[must_use]
    pub fn from_bytes(
        connection: RepositorySourceConnection,
        revision: GitObjectId,
        format: ArchiveFormat,
        bytes: Bytes,
    ) -> Self {
        let digest = Sha256Digest::from_bytes(Sha256::digest(&bytes).into());
        Self {
            connection_id: connection.connection_id,
            external_repository_id: connection.external_repository_id,
            repository: connection.repository,
            revision,
            format,
            digest,
            bytes,
        }
    }

    /// Returns the stable Automata connection that authorized the read.
    #[must_use]
    pub const fn connection_id(&self) -> ProviderConnectionId {
        self.connection_id
    }

    /// Returns the provider-native repository identity proven by the adapter.
    #[must_use]
    pub const fn external_repository_id(&self) -> &ExternalRepositoryId {
        &self.external_repository_id
    }

    /// Returns the provider-native repository represented by this source.
    #[must_use]
    pub const fn repository(&self) -> &RepositoryId {
        &self.repository
    }

    /// Returns the exact immutable revision represented by this source.
    #[must_use]
    pub const fn revision(&self) -> &GitObjectId {
        &self.revision
    }

    /// Returns the encoding of the retained source-archive bytes.
    #[must_use]
    pub const fn format(&self) -> ArchiveFormat {
        self.format
    }

    /// Returns the SHA-256 digest of the exact retained source-archive bytes.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Returns the retained source-archive length in bytes.
    ///
    /// The result saturates at [`u64::MAX`] on platforms whose address space
    /// could represent a larger byte buffer.
    #[must_use]
    pub fn size(&self) -> u64 {
        u64::try_from(self.bytes.len()).unwrap_or(u64::MAX)
    }

    /// Borrows the exact downloaded source-archive bytes.
    #[must_use]
    pub const fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// Consumes this value and returns the exact downloaded source-archive bytes.
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }
}

/// Error returned when an SCM provider identifier is not canonical.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("SCM provider ID is not canonical")]
pub struct ScmProviderIdError;

/// Reason a provider-native repository identity was rejected.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RepositoryIdError {
    /// The identity is empty or exceeds the repository-ID byte limit.
    #[error("repository ID length is invalid")]
    InvalidLength,
    /// The identity contains an absolute-path marker, backslash, or control character.
    #[error("repository ID contains an unsafe character")]
    UnsafeCharacter,
    /// A slash-delimited component is empty, `.` or `..`.
    #[error("repository ID contains an empty or traversal component")]
    InvalidComponent,
}

/// Reason a requested or resolved provider revision was rejected.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RevisionError {
    /// The revision is empty or exceeds the revision byte limit.
    #[error("revision length is invalid")]
    InvalidLength,
    /// The revision contains a Unicode control character.
    #[error("revision contains a control character")]
    ControlCharacter,
}

/// Error returned when an archive byte ceiling is zero or exceeds four GiB.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("archive byte limit must be in 1..=4294967296")]
pub struct ArchiveLimitsError;
