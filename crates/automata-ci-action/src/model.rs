use std::fmt;

use automata_ci_auth::secret::SecretString;
use automata_ci_blob::BlobDescriptor;
use automata_ci_core::{
    MAX_WINDOWS_ACTION_ARCHIVE_DEFINITION_BYTES, MAX_WINDOWS_ACTION_ARCHIVE_ENTRIES,
    MAX_WINDOWS_ACTION_ARCHIVE_EXPANDED_BYTES, MAX_WINDOWS_ACTION_ARCHIVE_PATH_BYTES,
    MAX_WINDOWS_ACTION_ARCHIVE_PATH_INDEX_BYTES, MAX_WINDOWS_ACTION_GRAPH_COMPRESSED_BYTES,
    MAX_WINDOWS_ACTION_SUBPATH_BYTES, Sha256Digest,
};
use automata_ci_scm::{
    ArchiveLimits, RepositoryId, ResolvedRevision, RevisionSpec, ScmProviderId, SnapshotRequest,
};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const MAX_SUBPATH_BYTES: usize = MAX_WINDOWS_ACTION_SUBPATH_BYTES;
const MAX_COMPRESSED_BYTES: u64 = MAX_WINDOWS_ACTION_GRAPH_COMPRESSED_BYTES;
const MAX_ENTRY_COUNT: usize = MAX_WINDOWS_ACTION_ARCHIVE_ENTRIES as usize;
const MAX_EXPANDED_BYTES: u64 = MAX_WINDOWS_ACTION_ARCHIVE_EXPANDED_BYTES;
const MAX_DEFINITION_BYTES: u64 = MAX_WINDOWS_ACTION_ARCHIVE_DEFINITION_BYTES;
const MAX_ENTRY_PATH_BYTES: usize = MAX_WINDOWS_ACTION_ARCHIVE_PATH_BYTES as usize;
const MAX_PATH_INDEX_BYTES: usize = MAX_WINDOWS_ACTION_ARCHIVE_PATH_INDEX_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActionModelLimitRejection {
    SubpathBytes,
    CompressedBytes,
    EntryCount,
    ExpandedBytes,
    DefinitionBytes,
    EntryPathBytes,
    PathIndexBytes,
}

const fn action_subpath_byte_rejection(observed: usize) -> Option<ActionModelLimitRejection> {
    if observed > MAX_SUBPATH_BYTES {
        return Some(ActionModelLimitRejection::SubpathBytes);
    }
    None
}

const fn action_bundle_limit_rejection(
    compressed_bytes: u64,
    entries: usize,
    expanded_bytes: u64,
    definition_bytes: u64,
    entry_path_bytes: usize,
    path_index_bytes: usize,
) -> Option<ActionModelLimitRejection> {
    if compressed_bytes > MAX_COMPRESSED_BYTES {
        return Some(ActionModelLimitRejection::CompressedBytes);
    }
    if entries > MAX_ENTRY_COUNT {
        return Some(ActionModelLimitRejection::EntryCount);
    }
    if expanded_bytes > MAX_EXPANDED_BYTES {
        return Some(ActionModelLimitRejection::ExpandedBytes);
    }
    if definition_bytes > MAX_DEFINITION_BYTES {
        return Some(ActionModelLimitRejection::DefinitionBytes);
    }
    if entry_path_bytes > MAX_ENTRY_PATH_BYTES {
        return Some(ActionModelLimitRejection::EntryPathBytes);
    }
    if path_index_bytes > MAX_PATH_INDEX_BYTES {
        return Some(ActionModelLimitRejection::PathIndexBytes);
    }
    None
}

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
        if value.is_empty() || action_subpath_byte_rejection(value.len()).is_some() {
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

/// Independent compressed-transfer and expanded-archive ceilings.
///
/// The resolver applies [`Self::compressed`] while fetching or loading raw
/// bytes. Archive inspection separately applies the entry-count, total
/// expanded-byte, selected-definition, and entry-path ceilings so a small
/// compressed payload cannot expand without bound. The aggregate canonical
/// path-index ceiling additionally bounds metadata retained for zero-byte
/// entries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionBundleLimits {
    compressed: ArchiveLimits,
    maximum_entries: usize,
    maximum_expanded_bytes: u64,
    maximum_definition_bytes: u64,
    maximum_entry_path_bytes: usize,
    maximum_path_index_bytes: usize,
}

impl ActionBundleLimits {
    /// Creates bounded archive validation policy.
    ///
    /// # Errors
    ///
    /// Rejects zero or excessive values, compressed inputs above the supported
    /// execution-copy ceiling, and definition limits larger than the aggregate
    /// expanded limit.
    pub const fn new(
        compressed: ArchiveLimits,
        maximum_entries: usize,
        maximum_expanded_bytes: u64,
        maximum_definition_bytes: u64,
        maximum_entry_path_bytes: usize,
        maximum_path_index_bytes: usize,
    ) -> Result<Self, ActionBundleLimitsError> {
        if maximum_entries == 0
            || maximum_expanded_bytes == 0
            || maximum_definition_bytes == 0
            || maximum_definition_bytes > maximum_expanded_bytes
            || maximum_entry_path_bytes == 0
            || maximum_path_index_bytes == 0
            || action_bundle_limit_rejection(
                compressed.maximum_bytes(),
                maximum_entries,
                maximum_expanded_bytes,
                maximum_definition_bytes,
                maximum_entry_path_bytes,
                maximum_path_index_bytes,
            )
            .is_some()
        {
            return Err(ActionBundleLimitsError);
        }
        Ok(Self {
            compressed,
            maximum_entries,
            maximum_expanded_bytes,
            maximum_definition_bytes,
            maximum_entry_path_bytes,
            maximum_path_index_bytes,
        })
    }

    /// Returns the raw compressed snapshot or blob-read limit.
    ///
    /// This limit belongs at the SCM or blob I/O boundary; the standalone
    /// archive inspection functions do not use it to truncate their input.
    #[must_use]
    pub const fn compressed(self) -> ArchiveLimits {
        self.compressed
    }

    /// Returns the maximum number of tar entries, including metadata entries.
    #[must_use]
    pub const fn maximum_entries(self) -> usize {
        self.maximum_entries
    }

    /// Returns the maximum sum of declared expanded entry bytes.
    #[must_use]
    pub const fn maximum_expanded_bytes(self) -> u64 {
        self.maximum_expanded_bytes
    }

    /// Returns the maximum bytes retained for the selected action definition.
    #[must_use]
    pub const fn maximum_definition_bytes(self) -> u64 {
        self.maximum_definition_bytes
    }

    /// Returns the maximum encoded path or link-target length for one entry.
    #[must_use]
    pub const fn maximum_entry_path_bytes(self) -> usize {
        self.maximum_entry_path_bytes
    }

    /// Returns the maximum aggregate bytes retained by the canonical path index.
    #[must_use]
    pub const fn maximum_path_index_bytes(self) -> usize {
        self.maximum_path_index_bytes
    }
}

impl Default for ActionBundleLimits {
    fn default() -> Self {
        Self {
            compressed: ArchiveLimits::new(MAX_COMPRESSED_BYTES)
                .expect("the action archive ceiling is valid"),
            maximum_entries: MAX_ENTRY_COUNT,
            maximum_expanded_bytes: MAX_EXPANDED_BYTES,
            maximum_definition_bytes: MAX_DEFINITION_BYTES,
            maximum_entry_path_bytes: MAX_ENTRY_PATH_BYTES,
            maximum_path_index_bytes: MAX_PATH_INDEX_BYTES,
        }
    }
}

#[cfg(test)]
mod limit_contract_tests {
    use super::{
        ActionModelLimitRejection, MAX_COMPRESSED_BYTES, MAX_DEFINITION_BYTES, MAX_ENTRY_COUNT,
        MAX_ENTRY_PATH_BYTES, MAX_EXPANDED_BYTES, MAX_PATH_INDEX_BYTES, MAX_SUBPATH_BYTES,
        action_bundle_limit_rejection, action_subpath_byte_rejection,
    };

    #[test]
    fn action_subpath_byte_limit_has_exact_boundaries() {
        assert_eq!(action_subpath_byte_rejection(MAX_SUBPATH_BYTES - 1), None);
        assert_eq!(action_subpath_byte_rejection(MAX_SUBPATH_BYTES), None);
        assert_eq!(
            action_subpath_byte_rejection(MAX_SUBPATH_BYTES + 1),
            Some(ActionModelLimitRejection::SubpathBytes)
        );
    }

    #[test]
    fn action_bundle_compressed_byte_limit_has_exact_boundaries() {
        assert_eq!(
            action_bundle_limit_rejection(MAX_COMPRESSED_BYTES - 1, 1, 1, 1, 1, 1),
            None
        );
        assert_eq!(
            action_bundle_limit_rejection(MAX_COMPRESSED_BYTES, 1, 1, 1, 1, 1),
            None
        );
        assert_eq!(
            action_bundle_limit_rejection(MAX_COMPRESSED_BYTES + 1, 1, 1, 1, 1, 1),
            Some(ActionModelLimitRejection::CompressedBytes)
        );
    }

    #[test]
    fn action_bundle_entry_count_limit_has_exact_boundaries() {
        assert_eq!(
            action_bundle_limit_rejection(1, MAX_ENTRY_COUNT - 1, 1, 1, 1, 1),
            None
        );
        assert_eq!(
            action_bundle_limit_rejection(1, MAX_ENTRY_COUNT, 1, 1, 1, 1),
            None
        );
        assert_eq!(
            action_bundle_limit_rejection(1, MAX_ENTRY_COUNT + 1, 1, 1, 1, 1),
            Some(ActionModelLimitRejection::EntryCount)
        );
    }

    #[test]
    fn action_bundle_expanded_byte_limit_has_exact_boundaries() {
        assert_eq!(
            action_bundle_limit_rejection(1, 1, MAX_EXPANDED_BYTES - 1, 1, 1, 1),
            None
        );
        assert_eq!(
            action_bundle_limit_rejection(1, 1, MAX_EXPANDED_BYTES, 1, 1, 1),
            None
        );
        assert_eq!(
            action_bundle_limit_rejection(1, 1, MAX_EXPANDED_BYTES + 1, 1, 1, 1),
            Some(ActionModelLimitRejection::ExpandedBytes)
        );
    }

    #[test]
    fn action_bundle_definition_byte_limit_has_exact_boundaries() {
        assert_eq!(
            action_bundle_limit_rejection(1, 1, MAX_EXPANDED_BYTES, MAX_DEFINITION_BYTES - 1, 1, 1),
            None
        );
        assert_eq!(
            action_bundle_limit_rejection(1, 1, MAX_EXPANDED_BYTES, MAX_DEFINITION_BYTES, 1, 1),
            None
        );
        assert_eq!(
            action_bundle_limit_rejection(1, 1, MAX_EXPANDED_BYTES, MAX_DEFINITION_BYTES + 1, 1, 1),
            Some(ActionModelLimitRejection::DefinitionBytes)
        );
    }

    #[test]
    fn action_bundle_entry_path_byte_limit_has_exact_boundaries() {
        assert_eq!(
            action_bundle_limit_rejection(1, 1, 1, 1, MAX_ENTRY_PATH_BYTES - 1, 1),
            None
        );
        assert_eq!(
            action_bundle_limit_rejection(1, 1, 1, 1, MAX_ENTRY_PATH_BYTES, 1),
            None
        );
        assert_eq!(
            action_bundle_limit_rejection(1, 1, 1, 1, MAX_ENTRY_PATH_BYTES + 1, 1),
            Some(ActionModelLimitRejection::EntryPathBytes)
        );
    }

    #[test]
    fn action_bundle_path_index_byte_limit_has_exact_boundaries() {
        assert_eq!(
            action_bundle_limit_rejection(1, 1, 1, 1, 1, MAX_PATH_INDEX_BYTES - 1),
            None
        );
        assert_eq!(
            action_bundle_limit_rejection(1, 1, 1, 1, 1, MAX_PATH_INDEX_BYTES),
            None
        );
        assert_eq!(
            action_bundle_limit_rejection(1, 1, 1, 1, 1, MAX_PATH_INDEX_BYTES + 1),
            Some(ActionModelLimitRejection::PathIndexBytes)
        );
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
    /// Creates an unauthenticated repository snapshot request.
    ///
    /// The request borrows all identity inputs and carries explicit resource
    /// limits through both the provider and archive-validation boundaries.
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

    /// Creates a repository snapshot request using a borrowed provider secret.
    ///
    /// The credential is forwarded only to the SCM snapshot request. It is not
    /// copied into the resolved bundle, immutable blob descriptor, or reference
    /// index, and debug formatting replaces it with a redaction marker.
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

    /// Returns the exact repository requested from the SCM provider.
    #[must_use]
    pub const fn repository(&self) -> &RepositoryId {
        self.repository
    }

    /// Returns the requested revision before provider resolution.
    #[must_use]
    pub const fn revision(&self) -> &RevisionSpec {
        self.revision
    }

    /// Returns the canonical action directory selected within the repository.
    #[must_use]
    pub const fn subpath(&self) -> &ActionSubpath {
        self.subpath
    }

    /// Returns the resource policy applied throughout resolution.
    #[must_use]
    pub const fn limits(&self) -> ActionBundleLimits {
        self.limits
    }

    /// Reports whether this request carries no repository credential.
    ///
    /// Only credential-free requests may use the public immutable-action
    /// cache. Authenticated requests must always re-authorize through SCM.
    #[must_use]
    pub const fn is_public(&self) -> bool {
        self.credential.is_none()
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
    /// An `action.yml` or `action.yaml` metadata document.
    MetadataYaml,
    /// A `Dockerfile` or lowercase `dockerfile` container-action definition.
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

    /// Creates a metadata document from bytes read through another bounded,
    /// trusted content boundary.
    ///
    /// This constructor is intended for checked-out local actions, whose
    /// `action.yml` or `action.yaml` file lives in an already-created job
    /// sandbox rather than an immutable repository-action archive. Callers
    /// remain responsible for validating and containing `path`; the metadata
    /// decoder treats it as provenance and never opens it.
    #[must_use]
    pub fn metadata_yaml(path: impl Into<String>, bytes: Bytes) -> Self {
        Self::new(ActionDefinitionKind::MetadataYaml, path.into(), bytes)
    }

    /// Returns the selected definition format.
    #[must_use]
    pub const fn kind(&self) -> ActionDefinitionKind {
        self.kind
    }

    /// Returns the repository-relative provenance path for the definition.
    ///
    /// The value is descriptive provenance only; accessors never open it as a
    /// control-plane filesystem path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the SHA-256 digest of [`Self::bytes`], not of the full archive.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Returns the bounded definition bytes retained during inspection.
    #[must_use]
    pub const fn bytes(&self) -> &Bytes {
        &self.bytes
    }
}

/// Immutable action bundle ready for semantic metadata compilation.
///
/// The value keeps requested and resolved revisions distinct and binds them to
/// the provider, repository, action subpath, raw archive descriptor, and
/// selected definition. It contains no provider credential or backend error
/// detail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedActionBundle {
    provider: ScmProviderId,
    repository: RepositoryId,
    requested_revision: RevisionSpec,
    resolved_revision: ResolvedRevision,
    subpath: ActionSubpath,
    archive: BlobDescriptor,
    archive_bytes: Bytes,
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
        archive_bytes: Bytes,
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
            archive_bytes,
            definition,
        }
    }

    /// Returns the provider that supplied the repository snapshot.
    #[must_use]
    pub const fn provider(&self) -> &ScmProviderId {
        &self.provider
    }

    /// Returns the exact repository supplied to and confirmed by the provider.
    #[must_use]
    pub const fn repository(&self) -> &RepositoryId {
        &self.repository
    }

    /// Returns the caller's revision spelling before provider resolution.
    #[must_use]
    pub const fn requested_revision(&self) -> &RevisionSpec {
        &self.requested_revision
    }

    /// Returns the immutable revision confirmed by the SCM provider.
    #[must_use]
    pub const fn resolved_revision(&self) -> &ResolvedRevision {
        &self.resolved_revision
    }

    /// Returns the canonical repository-relative action directory.
    #[must_use]
    pub const fn subpath(&self) -> &ActionSubpath {
        &self.subpath
    }

    /// Returns the content-addressed descriptor of the complete raw archive.
    #[must_use]
    pub const fn archive(&self) -> &BlobDescriptor {
        &self.archive
    }

    /// Returns the verified archive bytes selected by the resolver.
    ///
    /// Cache hits retain the already-verified local or shared-cache payload so
    /// downstream preparation does not repeat an object-store read.
    #[must_use]
    pub const fn archive_bytes(&self) -> &Bytes {
        &self.archive_bytes
    }

    /// Returns the bounded, inspected definition selected from the archive.
    #[must_use]
    pub const fn definition(&self) -> &ActionDefinitionDocument {
        &self.definition
    }
}

/// Reason an action directory is not a safe canonical repository subpath.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ActionSubpathError {
    /// The path is empty or exceeds the accepted byte length.
    #[error("action subpath length is invalid")]
    InvalidLength,
    /// The path is absolute or contains a control character or backslash.
    #[error("action subpath contains an unsafe character")]
    UnsafeCharacter,
    /// A slash-separated component is empty, current-directory, or traversal.
    #[error("action subpath contains an empty or traversal component")]
    InvalidComponent,
}

/// A configured action-bundle resource policy is invalid.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("action bundle limit is zero, inconsistent, or excessive")]
pub struct ActionBundleLimitsError;

/// Stable fail-closed archive-inspection failure class.
///
/// Variants intentionally omit archive bytes, member paths, and decoder error
/// text so errors are safe to propagate across an untrusted provider boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ActionArchiveError {
    /// Gzip, tar, header, size, or supported global-PAX encoding is malformed.
    #[error("action archive is malformed")]
    Malformed,
    /// An entry-count, expanded-byte, definition-byte, or path-byte bound failed.
    #[error("action archive exceeds a configured resource limit")]
    ResourceLimit,
    /// A member path, symbolic-link target, archive root, or PAX field is unsafe.
    #[error("action archive contains an unsafe path or link")]
    UnsafePath,
    /// Two archive entries normalize to the same repository-relative path.
    #[error("action archive contains a duplicate path")]
    DuplicatePath,
    /// An entry type or path-extension mechanism is outside the accepted subset.
    #[error("action archive contains an unsupported entry type")]
    UnsupportedEntry,
    /// No supported action metadata file or Dockerfile exists at the subpath.
    #[error("action definition is missing")]
    MissingDefinition,
}

/// Sanitized stage at which action resolution failed.
///
/// This classification deliberately does not carry provider responses,
/// repository identities, member paths, credentials, or backend error text.
/// Retryability is an orchestration policy and is not implied by these variants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionResolveErrorKind {
    /// The SCM provider did not complete the bounded snapshot request.
    Scm,
    /// The fetched bytes failed bounded semantic archive inspection.
    Archive,
    /// Immutable blob verification or publication failed.
    BlobStore,
    /// The local immutable-reference index failed or contradicted provenance.
    ReferenceCache,
    /// A provider result or locally constructed identity violated an invariant.
    Internal,
}

/// Sanitized action-resolution error exposing only a stable failure stage.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("action resolution failed: {kind:?}")]
pub struct ActionResolveError {
    kind: ActionResolveErrorKind,
}

impl ActionResolveError {
    /// Creates an error from a stable stage without attaching sensitive detail.
    #[must_use]
    pub const fn new(kind: ActionResolveErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure stage available to caller policy.
    #[must_use]
    pub const fn kind(self) -> ActionResolveErrorKind {
        self.kind
    }
}
