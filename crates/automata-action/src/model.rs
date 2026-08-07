use std::fmt;

use automata_auth::secret::SecretString;
use automata_blob::BlobDescriptor;
use automata_core::Sha256Digest;
use automata_scm::{
    ArchiveLimits, RepositoryId, ResolvedRevision, RevisionSpec, ScmProviderId, SnapshotRequest,
};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const MAX_SUBPATH_BYTES: usize = 1_024;
const MAX_ENTRY_COUNT: usize = 1_000_000;
const MAX_EXPANDED_BYTES: u64 = 16 * 1_024 * 1_024 * 1_024;
const MAX_DEFINITION_BYTES: u64 = 16 * 1_024 * 1_024;
const MAX_ENTRY_PATH_BYTES: usize = 16 * 1_024;

/// Canonical repository-relative directory containing an action definition.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ActionSubpath(String);

impl ActionSubpath {
    /// Selects an action at the repository root.
    #[must_use]
    pub const fn root() -> Self {
        Self(String::new())
    }

    /// Creates a canonical non-root action directory.
    ///
    /// # Errors
    ///
    /// Rejects absolute, empty-component, traversal, control-containing,
    /// backslash-containing, trailing-slash, and oversized paths.
    pub fn new(value: impl Into<String>) -> Result<Self, ActionSubpathError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_SUBPATH_BYTES {
            return Err(ActionSubpathError::InvalidLength);
        }
        if value.starts_with('/')
            || value.ends_with('/')
            || value.contains('\\')
            || value.chars().any(char::is_control)
        {
            return Err(ActionSubpathError::UnsafeCharacter);
        }
        if value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
        {
            return Err(ActionSubpathError::InvalidComponent);
        }
        Ok(Self(value))
    }

    /// Returns an empty string for the repository root, otherwise a canonical
    /// repository-relative directory.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn components(&self) -> impl Iterator<Item = &[u8]> {
        self.0
            .split('/')
            .filter(|component| !component.is_empty())
            .map(str::as_bytes)
    }
}

/// Independent compressed and expanded archive ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionBundleLimits {
    compressed: ArchiveLimits,
    maximum_entries: usize,
    maximum_expanded_bytes: u64,
    maximum_definition_bytes: u64,
    maximum_entry_path_bytes: usize,
}

impl ActionBundleLimits {
    /// Creates bounded archive validation policy.
    ///
    /// # Errors
    ///
    /// Rejects zero or excessive values and definition limits larger than the
    /// aggregate expanded limit.
    pub const fn new(
        compressed: ArchiveLimits,
        maximum_entries: usize,
        maximum_expanded_bytes: u64,
        maximum_definition_bytes: u64,
        maximum_entry_path_bytes: usize,
    ) -> Result<Self, ActionBundleLimitsError> {
        if maximum_entries == 0
            || maximum_entries > MAX_ENTRY_COUNT
            || maximum_expanded_bytes == 0
            || maximum_expanded_bytes > MAX_EXPANDED_BYTES
            || maximum_definition_bytes == 0
            || maximum_definition_bytes > MAX_DEFINITION_BYTES
            || maximum_definition_bytes > maximum_expanded_bytes
            || maximum_entry_path_bytes == 0
            || maximum_entry_path_bytes > MAX_ENTRY_PATH_BYTES
        {
            return Err(ActionBundleLimitsError);
        }
        Ok(Self {
            compressed,
            maximum_entries,
            maximum_expanded_bytes,
            maximum_definition_bytes,
            maximum_entry_path_bytes,
        })
    }

    #[must_use]
    pub const fn compressed(self) -> ArchiveLimits {
        self.compressed
    }

    #[must_use]
    pub const fn maximum_entries(self) -> usize {
        self.maximum_entries
    }

    #[must_use]
    pub const fn maximum_expanded_bytes(self) -> u64 {
        self.maximum_expanded_bytes
    }

    #[must_use]
    pub const fn maximum_definition_bytes(self) -> u64 {
        self.maximum_definition_bytes
    }

    #[must_use]
    pub const fn maximum_entry_path_bytes(self) -> usize {
        self.maximum_entry_path_bytes
    }
}

impl Default for ActionBundleLimits {
    fn default() -> Self {
        Self {
            compressed: ArchiveLimits::default(),
            maximum_entries: 100_000,
            maximum_expanded_bytes: 2 * 1_024 * 1_024 * 1_024,
            maximum_definition_bytes: 1_024 * 1_024,
            maximum_entry_path_bytes: 4 * 1_024,
        }
    }
}

/// Credential-scoped request to resolve one repository action.
pub struct RepositoryActionRequest<'a> {
    repository: &'a RepositoryId,
    revision: &'a RevisionSpec,
    subpath: &'a ActionSubpath,
    credential: Option<&'a SecretString>,
    limits: ActionBundleLimits,
}

impl<'a> RepositoryActionRequest<'a> {
    #[must_use]
    pub const fn public(
        repository: &'a RepositoryId,
        revision: &'a RevisionSpec,
        subpath: &'a ActionSubpath,
        limits: ActionBundleLimits,
    ) -> Self {
        Self {
            repository,
            revision,
            subpath,
            credential: None,
            limits,
        }
    }

    #[must_use]
    pub const fn authenticated(
        repository: &'a RepositoryId,
        revision: &'a RevisionSpec,
        subpath: &'a ActionSubpath,
        credential: &'a SecretString,
        limits: ActionBundleLimits,
    ) -> Self {
        Self {
            repository,
            revision,
            subpath,
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
    pub const fn subpath(&self) -> &ActionSubpath {
        self.subpath
    }

    #[must_use]
    pub const fn limits(&self) -> ActionBundleLimits {
        self.limits
    }

    pub(crate) const fn snapshot_request(&self) -> SnapshotRequest<'_> {
        if let Some(credential) = self.credential {
            SnapshotRequest::authenticated(
                self.repository,
                self.revision,
                credential,
                self.limits.compressed,
            )
        } else {
            SnapshotRequest::public(self.repository, self.revision, self.limits.compressed)
        }
    }
}

impl fmt::Debug for RepositoryActionRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepositoryActionRequest")
            .field("repository", &self.repository)
            .field("revision", &self.revision)
            .field("subpath", &self.subpath)
            .field("credential", &self.credential.map(|_| "[redacted]"))
            .field("limits", &self.limits)
            .finish()
    }
}

/// Definition selected using GitHub-compatible filename precedence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionDefinitionKind {
    MetadataYaml,
    Dockerfile,
}

/// Bounded action definition bytes extracted without materializing the archive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionDefinitionDocument {
    kind: ActionDefinitionKind,
    path: String,
    digest: Sha256Digest,
    bytes: Bytes,
}

impl ActionDefinitionDocument {
    pub(crate) fn new(kind: ActionDefinitionKind, path: String, bytes: Bytes) -> Self {
        let digest = Sha256Digest::from_bytes(Sha256::digest(&bytes).into());
        Self {
            kind,
            path,
            digest,
            bytes,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> ActionDefinitionKind {
        self.kind
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    #[must_use]
    pub const fn bytes(&self) -> &Bytes {
        &self.bytes
    }
}

/// Immutable action bundle ready for semantic metadata compilation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedActionBundle {
    provider: ScmProviderId,
    repository: RepositoryId,
    requested_revision: RevisionSpec,
    resolved_revision: ResolvedRevision,
    subpath: ActionSubpath,
    archive: BlobDescriptor,
    definition: ActionDefinitionDocument,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedActionIdentity {
    provider: ScmProviderId,
    repository: RepositoryId,
    requested_revision: RevisionSpec,
    resolved_revision: ResolvedRevision,
    subpath: ActionSubpath,
}

impl ResolvedActionIdentity {
    pub(crate) fn new(
        provider: ScmProviderId,
        repository: RepositoryId,
        requested_revision: RevisionSpec,
        resolved_revision: ResolvedRevision,
        subpath: ActionSubpath,
    ) -> Self {
        Self {
            provider,
            repository,
            requested_revision,
            resolved_revision,
            subpath,
        }
    }
}

impl ResolvedActionBundle {
    pub(crate) fn new(
        identity: ResolvedActionIdentity,
        archive: BlobDescriptor,
        definition: ActionDefinitionDocument,
    ) -> Self {
        let ResolvedActionIdentity {
            provider,
            repository,
            requested_revision,
            resolved_revision,
            subpath,
        } = identity;
        Self {
            provider,
            repository,
            requested_revision,
            resolved_revision,
            subpath,
            archive,
            definition,
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
    pub const fn subpath(&self) -> &ActionSubpath {
        &self.subpath
    }

    #[must_use]
    pub const fn archive(&self) -> &BlobDescriptor {
        &self.archive
    }

    #[must_use]
    pub const fn definition(&self) -> &ActionDefinitionDocument {
        &self.definition
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ActionSubpathError {
    #[error("action subpath length is invalid")]
    InvalidLength,
    #[error("action subpath contains an unsafe character")]
    UnsafeCharacter,
    #[error("action subpath contains an empty or traversal component")]
    InvalidComponent,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("action bundle limit is zero, inconsistent, or excessive")]
pub struct ActionBundleLimitsError;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ActionArchiveError {
    #[error("action archive is malformed")]
    Malformed,
    #[error("action archive exceeds a configured resource limit")]
    ResourceLimit,
    #[error("action archive contains an unsafe path or link")]
    UnsafePath,
    #[error("action archive contains a duplicate path")]
    DuplicatePath,
    #[error("action archive contains an unsupported entry type")]
    UnsupportedEntry,
    #[error("action definition is missing")]
    MissingDefinition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionResolveErrorKind {
    Scm,
    Archive,
    BlobStore,
    ReferenceCache,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("action resolution failed: {kind:?}")]
pub struct ActionResolveError {
    kind: ActionResolveErrorKind,
}

impl ActionResolveError {
    #[must_use]
    pub const fn new(kind: ActionResolveErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> ActionResolveErrorKind {
        self.kind
    }
}
