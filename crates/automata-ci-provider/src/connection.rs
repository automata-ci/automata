//! Provider-neutral repository connection configuration.

use std::{fmt, num::NonZeroU64};

use automata_ci_core::{Sha256Digest, UnixMillis, WorkspaceId};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    ExternalRepositoryId, ExternalRepositoryIdentity, ProviderConfigurationRevision,
    ProviderConnectionId, ProviderInstanceManifest, ProviderLifecycleState, ProviderSchemaVersion,
    configuration::validate_lifecycle,
};

/// Maximum bytes in a repository-relative workflow path.
pub const MAX_PROVIDER_REPOSITORY_PATH_BYTES: usize = 1_024;
/// Maximum bytes in an adapter-owned connection-policy document.
pub const MAX_PROVIDER_CONNECTION_POLICY_BYTES: usize = 64 * 1_024;
/// Maximum accepted compressed repository archive size.
pub const MAX_PROVIDER_ARCHIVE_COMPRESSED_BYTES: u64 = 4 * 1_024 * 1_024 * 1_024;
/// Maximum accepted expanded repository archive size.
pub const MAX_PROVIDER_ARCHIVE_EXPANDED_BYTES: u64 = 16 * 1_024 * 1_024 * 1_024;
/// Maximum accepted repository archive entries.
pub const MAX_PROVIDER_ARCHIVE_ENTRIES: u64 = 1_000_000;
/// Maximum accepted bytes in one repository archive path.
pub const MAX_PROVIDER_ARCHIVE_ENTRY_PATH_BYTES: u64 = 16 * 1_024;
/// Maximum workflow files discovered in one repository archive.
pub const MAX_PROVIDER_ARCHIVE_WORKFLOWS: u64 = 4_096;
/// Maximum bytes in one workflow source file.
pub const MAX_PROVIDER_WORKFLOW_BYTES: u64 = 4 * 1_024 * 1_024;

const CONNECTION_POLICY_DIGEST_DOMAIN: &[u8] = b"automata.provider.connection-policy.v1\0";
const CONNECTION_CONFIGURATION_DIGEST_DOMAIN: &[u8] =
    b"automata.provider.connection-configuration.v1\0";
const CONNECTION_MANIFEST_DIGEST_DOMAIN: &[u8] = b"automata.provider.connection-manifest.v1\0";

/// Monotonic revision of one provider repository connection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "u64", into = "u64")]
pub struct ProviderConnectionRevision(NonZeroU64);

impl ProviderConnectionRevision {
    /// Creates a positive revision representable by a `PostgreSQL BIGINT`.
    ///
    /// # Errors
    ///
    /// Rejects zero or values beyond the signed durable range.
    pub const fn new(value: u64) -> Result<Self, ProviderConnectionError> {
        match NonZeroU64::new(value) {
            Some(value) if value.get() <= i64::MAX as u64 => Ok(Self(value)),
            _ => Err(ProviderConnectionError::InvalidRevision),
        }
    }

    /// Returns the positive revision.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl TryFrom<u64> for ProviderConnectionRevision {
    type Error = ProviderConnectionError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ProviderConnectionRevision> for u64 {
    fn from(value: ProviderConnectionRevision) -> Self {
        value.get()
    }
}

/// Authenticated visibility of one provider repository.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryVisibility {
    /// Repository contents are available without authentication.
    Public,
    /// Repository contents are visible inside a provider-defined internal scope.
    Internal,
    /// Repository contents require explicit authorization.
    Private,
}

/// Canonical default branch name without the `refs/heads/` prefix.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProviderDefaultBranch(String);

impl ProviderDefaultBranch {
    /// Validates a complete provider branch name.
    ///
    /// # Errors
    ///
    /// Rejects empty, ambiguous, unsafe, or oversized Git branch names.
    pub fn new(value: impl Into<String>) -> Result<Self, ProviderConnectionError> {
        let value = value.into();
        if !valid_branch_name(&value) {
            return Err(ProviderConnectionError::InvalidDefaultBranch);
        }
        Ok(Self(value))
    }

    /// Returns the branch name without `refs/heads/`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ProviderDefaultBranch {
    type Error = ProviderConnectionError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ProviderDefaultBranch> for String {
    fn from(value: ProviderDefaultBranch) -> Self {
        value.0
    }
}

#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn valid_branch_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value != "@"
        && !value.starts_with("refs/")
        && !value.starts_with(['-', '/', '.'])
        && !value.ends_with(['/', '.'])
        && !value.ends_with(".lock")
        && !value.contains("//")
        && !value.contains("..")
        && !value.contains("@{")
        && !value.chars().any(|character| {
            character.is_control()
                || character.is_whitespace()
                || matches!(character, '~' | '^' | ':' | '?' | '*' | '[' | '\\')
        })
}

/// Canonical repository-relative path used for workflow discovery.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProviderRepositoryPath(String);

impl ProviderRepositoryPath {
    /// Validates a normalized repository-relative path.
    ///
    /// # Errors
    ///
    /// Rejects absolute paths, empty segments, dot segments, backslashes,
    /// control characters, and oversized values.
    pub fn new(value: impl Into<String>) -> Result<Self, ProviderConnectionError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_PROVIDER_REPOSITORY_PATH_BYTES
            || value.starts_with('/')
            || value.ends_with('/')
            || value.contains('\\')
            || value.chars().any(char::is_control)
            || value
                .split('/')
                .any(|component| component.is_empty() || component == "." || component == "..")
        {
            return Err(ProviderConnectionError::InvalidRepositoryPath);
        }
        Ok(Self(value))
    }

    /// Returns the normalized repository-relative path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ProviderRepositoryPath {
    type Error = ProviderConnectionError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ProviderRepositoryPath> for String {
    fn from(value: ProviderRepositoryPath) -> Self {
        value.0
    }
}

/// Common workflow source selection shape.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "path", rename_all = "snake_case")]
pub enum ProviderWorkflowSource {
    /// Discover all supported workflow files below one exact directory.
    Directory(ProviderRepositoryPath),
    /// Load one exact workflow file.
    File(ProviderRepositoryPath),
}

impl ProviderWorkflowSource {
    /// Returns the selected repository-relative path.
    #[must_use]
    pub const fn path(&self) -> &ProviderRepositoryPath {
        match self {
            Self::Directory(path) | Self::File(path) => path,
        }
    }
}

/// Immutable reference to one already-validated common runner policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRunnerPolicyBinding {
    schema_version: ProviderSchemaVersion,
    digest: Sha256Digest,
}

impl ProviderRunnerPolicyBinding {
    /// Pins one runner policy schema and content digest.
    #[must_use]
    pub const fn new(schema_version: ProviderSchemaVersion, digest: Sha256Digest) -> Self {
        Self {
            schema_version,
            digest,
        }
    }

    /// Returns the common runner-policy schema.
    #[must_use]
    pub const fn schema_version(self) -> ProviderSchemaVersion {
        self.schema_version
    }

    /// Returns the exact canonical runner-policy digest.
    #[must_use]
    pub const fn digest(self) -> Sha256Digest {
        self.digest
    }
}

/// Hard repository archive and workflow-discovery bounds.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedProviderArchiveLimits")]
pub struct ProviderArchiveLimits {
    compressed_bytes: u64,
    expanded_bytes: u64,
    entries: u64,
    entry_path_bytes: u64,
    workflows: u64,
    workflow_bytes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedProviderArchiveLimits {
    compressed_bytes: u64,
    expanded_bytes: u64,
    entries: u64,
    entry_path_bytes: u64,
    workflows: u64,
    workflow_bytes: u64,
}

impl ProviderArchiveLimits {
    /// Creates internally consistent, bounded archive limits.
    ///
    /// # Errors
    ///
    /// Rejects zero, excessive, or internally impossible limits.
    pub const fn new(
        compressed_bytes: u64,
        expanded_bytes: u64,
        entries: u64,
        entry_path_bytes: u64,
        workflows: u64,
        workflow_bytes: u64,
    ) -> Result<Self, ProviderConnectionError> {
        if compressed_bytes == 0
            || compressed_bytes > MAX_PROVIDER_ARCHIVE_COMPRESSED_BYTES
            || expanded_bytes < compressed_bytes
            || expanded_bytes > MAX_PROVIDER_ARCHIVE_EXPANDED_BYTES
            || entries == 0
            || entries > MAX_PROVIDER_ARCHIVE_ENTRIES
            || entry_path_bytes == 0
            || entry_path_bytes > MAX_PROVIDER_ARCHIVE_ENTRY_PATH_BYTES
            || workflows == 0
            || workflows > MAX_PROVIDER_ARCHIVE_WORKFLOWS
            || workflows > entries
            || workflow_bytes == 0
            || workflow_bytes > MAX_PROVIDER_WORKFLOW_BYTES
            || workflow_bytes > expanded_bytes
        {
            return Err(ProviderConnectionError::InvalidArchiveLimits);
        }
        Ok(Self {
            compressed_bytes,
            expanded_bytes,
            entries,
            entry_path_bytes,
            workflows,
            workflow_bytes,
        })
    }

    /// Returns the maximum compressed download bytes.
    #[must_use]
    pub const fn compressed_bytes(self) -> u64 {
        self.compressed_bytes
    }

    /// Returns the maximum total expanded entry bytes.
    #[must_use]
    pub const fn expanded_bytes(self) -> u64 {
        self.expanded_bytes
    }

    /// Returns the maximum entry count.
    #[must_use]
    pub const fn entries(self) -> u64 {
        self.entries
    }

    /// Returns the maximum encoded bytes in one entry path.
    #[must_use]
    pub const fn entry_path_bytes(self) -> u64 {
        self.entry_path_bytes
    }

    /// Returns the maximum discovered workflow count.
    #[must_use]
    pub const fn workflows(self) -> u64 {
        self.workflows
    }

    /// Returns the maximum bytes in one workflow source.
    #[must_use]
    pub const fn workflow_bytes(self) -> u64 {
        self.workflow_bytes
    }
}

impl TryFrom<UncheckedProviderArchiveLimits> for ProviderArchiveLimits {
    type Error = ProviderConnectionError;

    fn try_from(value: UncheckedProviderArchiveLimits) -> Result<Self, Self::Error> {
        Self::new(
            value.compressed_bytes,
            value.expanded_bytes,
            value.entries,
            value.entry_path_bytes,
            value.workflows,
            value.workflow_bytes,
        )
    }
}

/// Bounded canonical adapter-owned connection policy.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderConnectionPolicyDocument {
    schema_version: ProviderSchemaVersion,
    bytes: Vec<u8>,
    digest: Sha256Digest,
}

impl fmt::Debug for ProviderConnectionPolicyDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderConnectionPolicyDocument")
            .field("schema_version", &self.schema_version)
            .field("bytes", &"[CANONICAL]")
            .field("byte_length", &self.bytes.len())
            .field("digest", &self.digest)
            .finish()
    }
}

impl ProviderConnectionPolicyDocument {
    /// Creates one nonempty bounded adapter policy document.
    ///
    /// The owning adapter must decode and exactly re-encode the document before
    /// accepting it.
    ///
    /// # Errors
    ///
    /// Rejects empty or oversized bytes.
    pub fn new(
        schema_version: ProviderSchemaVersion,
        bytes: Vec<u8>,
    ) -> Result<Self, ProviderConnectionError> {
        if bytes.is_empty() || bytes.len() > MAX_PROVIDER_CONNECTION_POLICY_BYTES {
            return Err(ProviderConnectionError::InvalidPolicyDocument);
        }
        let mut hash = Sha256::new();
        hash.update(CONNECTION_POLICY_DIGEST_DOMAIN);
        hash.update(schema_version.get().to_be_bytes());
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(&bytes);
        Ok(Self {
            schema_version,
            bytes,
            digest: Sha256Digest::from_bytes(hash.finalize().into()),
        })
    }

    /// Returns the adapter policy schema.
    #[must_use]
    pub const fn schema_version(&self) -> ProviderSchemaVersion {
        self.schema_version
    }

    /// Returns exact canonical adapter policy bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the domain-separated policy digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

/// Complete provider-neutral configuration of one repository connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderConnectionConfiguration {
    workspace_id: WorkspaceId,
    repository: ExternalRepositoryIdentity,
    provider_revision: ProviderConfigurationRevision,
    provider_configuration_digest: Sha256Digest,
    capability_digest: Sha256Digest,
    visibility: RepositoryVisibility,
    default_branch: ProviderDefaultBranch,
    workflow_source: ProviderWorkflowSource,
    runner_policy: ProviderRunnerPolicyBinding,
    archive_limits: ProviderArchiveLimits,
    adapter_policy: ProviderConnectionPolicyDocument,
    digest: Sha256Digest,
}

impl ProviderConnectionConfiguration {
    /// Constructs the immutable common and adapter-owned connection policy.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        workspace_id: WorkspaceId,
        repository: ExternalRepositoryIdentity,
        provider_revision: ProviderConfigurationRevision,
        provider_configuration_digest: Sha256Digest,
        capability_digest: Sha256Digest,
        visibility: RepositoryVisibility,
        default_branch: ProviderDefaultBranch,
        workflow_source: ProviderWorkflowSource,
        runner_policy: ProviderRunnerPolicyBinding,
        archive_limits: ProviderArchiveLimits,
        adapter_policy: ProviderConnectionPolicyDocument,
    ) -> Self {
        let mut value = Self {
            workspace_id,
            repository,
            provider_revision,
            provider_configuration_digest,
            capability_digest,
            visibility,
            default_branch,
            workflow_source,
            runner_policy,
            archive_limits,
            adapter_policy,
            digest: Sha256Digest::from_bytes([0; 32]),
        };
        value.digest = value.compute_digest();
        value
    }

    /// Returns the owning workspace.
    #[must_use]
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    /// Returns the instance-scoped provider repository identity.
    #[must_use]
    pub const fn repository(&self) -> &ExternalRepositoryIdentity {
        &self.repository
    }

    /// Returns the pinned provider configuration revision.
    #[must_use]
    pub const fn provider_revision(&self) -> ProviderConfigurationRevision {
        self.provider_revision
    }

    /// Returns the pinned provider configuration digest.
    #[must_use]
    pub const fn provider_configuration_digest(&self) -> Sha256Digest {
        self.provider_configuration_digest
    }

    /// Returns the pinned provider capability digest.
    #[must_use]
    pub const fn capability_digest(&self) -> Sha256Digest {
        self.capability_digest
    }

    /// Returns authenticated repository visibility.
    #[must_use]
    pub const fn visibility(&self) -> RepositoryVisibility {
        self.visibility
    }

    /// Returns the selected default branch.
    #[must_use]
    pub const fn default_branch(&self) -> &ProviderDefaultBranch {
        &self.default_branch
    }

    /// Returns the workflow source selection.
    #[must_use]
    pub const fn workflow_source(&self) -> &ProviderWorkflowSource {
        &self.workflow_source
    }

    /// Returns the pinned common runner policy.
    #[must_use]
    pub const fn runner_policy(&self) -> ProviderRunnerPolicyBinding {
        self.runner_policy
    }

    /// Returns hard archive and workflow-discovery limits.
    #[must_use]
    pub const fn archive_limits(&self) -> ProviderArchiveLimits {
        self.archive_limits
    }

    /// Returns adapter-owned connection policy.
    #[must_use]
    pub const fn adapter_policy(&self) -> &ProviderConnectionPolicyDocument {
        &self.adapter_policy
    }

    /// Returns the complete connection-configuration digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    fn compute_digest(&self) -> Sha256Digest {
        let mut hash = Sha256::new();
        hash.update(CONNECTION_CONFIGURATION_DIGEST_DOMAIN);
        part(&mut hash, self.workspace_id.as_uuid().as_bytes());
        part(
            &mut hash,
            self.repository.instance_id().as_uuid().as_bytes(),
        );
        part(&mut hash, self.repository.external_id().as_str().as_bytes());
        part(&mut hash, &self.provider_revision.get().to_be_bytes());
        part(&mut hash, self.provider_configuration_digest.as_bytes());
        part(&mut hash, self.capability_digest.as_bytes());
        part(
            &mut hash,
            match self.visibility {
                RepositoryVisibility::Public => b"public",
                RepositoryVisibility::Internal => b"internal",
                RepositoryVisibility::Private => b"private",
            },
        );
        part(&mut hash, self.default_branch.as_str().as_bytes());
        match &self.workflow_source {
            ProviderWorkflowSource::Directory(path) => {
                part(&mut hash, b"directory");
                part(&mut hash, path.as_str().as_bytes());
            }
            ProviderWorkflowSource::File(path) => {
                part(&mut hash, b"file");
                part(&mut hash, path.as_str().as_bytes());
            }
        }
        part(
            &mut hash,
            &self.runner_policy.schema_version().get().to_be_bytes(),
        );
        part(&mut hash, self.runner_policy.digest().as_bytes());
        for limit in [
            self.archive_limits.compressed_bytes(),
            self.archive_limits.expanded_bytes(),
            self.archive_limits.entries(),
            self.archive_limits.entry_path_bytes(),
            self.archive_limits.workflows(),
            self.archive_limits.workflow_bytes(),
        ] {
            part(&mut hash, &limit.to_be_bytes());
        }
        part(&mut hash, self.adapter_policy.digest().as_bytes());
        Sha256Digest::from_bytes(hash.finalize().into())
    }
}

/// Complete repository-connection revision awaiting provider binding and adapter validation.
pub struct ProviderConnectionDraft {
    connection_id: ProviderConnectionId,
    revision: ProviderConnectionRevision,
    state: ProviderLifecycleState,
    workspace_id: WorkspaceId,
    external_repository_id: ExternalRepositoryId,
    visibility: RepositoryVisibility,
    default_branch: ProviderDefaultBranch,
    workflow_source: ProviderWorkflowSource,
    runner_policy: ProviderRunnerPolicyBinding,
    archive_limits: ProviderArchiveLimits,
    adapter_policy: ProviderConnectionPolicyDocument,
    created_at: UnixMillis,
    activated_at: Option<UnixMillis>,
    retired_at: Option<UnixMillis>,
}

impl ProviderConnectionDraft {
    /// Creates a connection revision without caller-supplied provider digests.
    ///
    /// # Errors
    ///
    /// Rejects inconsistent lifecycle timestamps.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        connection_id: ProviderConnectionId,
        revision: ProviderConnectionRevision,
        state: ProviderLifecycleState,
        workspace_id: WorkspaceId,
        external_repository_id: ExternalRepositoryId,
        visibility: RepositoryVisibility,
        default_branch: ProviderDefaultBranch,
        workflow_source: ProviderWorkflowSource,
        runner_policy: ProviderRunnerPolicyBinding,
        archive_limits: ProviderArchiveLimits,
        adapter_policy: ProviderConnectionPolicyDocument,
        created_at: UnixMillis,
        activated_at: Option<UnixMillis>,
        retired_at: Option<UnixMillis>,
    ) -> Result<Self, ProviderConnectionError> {
        validate_lifecycle(state, created_at, activated_at, retired_at)
            .map_err(|_| ProviderConnectionError::InvalidLifecycle)?;
        Ok(Self {
            connection_id,
            revision,
            state,
            workspace_id,
            external_repository_id,
            visibility,
            default_branch,
            workflow_source,
            runner_policy,
            archive_limits,
            adapter_policy,
            created_at,
            activated_at,
            retired_at,
        })
    }

    pub(crate) fn into_manifest(
        self,
        provider: &ProviderInstanceManifest,
    ) -> Result<ProviderConnectionManifest, ProviderConnectionError> {
        let configuration = ProviderConnectionConfiguration::new(
            self.workspace_id,
            ExternalRepositoryIdentity::new(provider.instance_id(), self.external_repository_id),
            provider.revision(),
            provider.configuration().digest(),
            provider.capability_digest(),
            self.visibility,
            self.default_branch,
            self.workflow_source,
            self.runner_policy,
            self.archive_limits,
            self.adapter_policy,
        );
        ProviderConnectionManifest::new(
            self.connection_id,
            self.revision,
            self.state,
            configuration,
            self.created_at,
            self.activated_at,
            self.retired_at,
        )
    }
}

impl fmt::Debug for ProviderConnectionDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderConnectionDraft")
            .field("connection_id", &self.connection_id)
            .field("revision", &self.revision)
            .field("state", &self.state)
            .field("workspace_id", &self.workspace_id)
            .field("external_repository_id", &self.external_repository_id)
            .field("visibility", &self.visibility)
            .field("default_branch", &self.default_branch)
            .field("workflow_source", &self.workflow_source)
            .field("runner_policy", &self.runner_policy)
            .field("archive_limits", &self.archive_limits)
            .field("adapter_policy", &self.adapter_policy)
            .field("created_at", &self.created_at)
            .field("activated_at", &self.activated_at)
            .field("retired_at", &self.retired_at)
            .finish()
    }
}

/// Immutable lifecycle revision of one provider repository connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderConnectionManifest {
    connection_id: ProviderConnectionId,
    revision: ProviderConnectionRevision,
    state: ProviderLifecycleState,
    configuration: ProviderConnectionConfiguration,
    created_at: UnixMillis,
    activated_at: Option<UnixMillis>,
    retired_at: Option<UnixMillis>,
    digest: Sha256Digest,
}

impl ProviderConnectionManifest {
    /// Constructs one complete immutable connection revision.
    ///
    /// # Errors
    ///
    /// Rejects inconsistent lifecycle evidence.
    pub fn new(
        connection_id: ProviderConnectionId,
        revision: ProviderConnectionRevision,
        state: ProviderLifecycleState,
        configuration: ProviderConnectionConfiguration,
        created_at: UnixMillis,
        activated_at: Option<UnixMillis>,
        retired_at: Option<UnixMillis>,
    ) -> Result<Self, ProviderConnectionError> {
        validate_lifecycle(state, created_at, activated_at, retired_at)
            .map_err(|_| ProviderConnectionError::InvalidLifecycle)?;
        let mut value = Self {
            connection_id,
            revision,
            state,
            configuration,
            created_at,
            activated_at,
            retired_at,
            digest: Sha256Digest::from_bytes([0; 32]),
        };
        value.digest = value.compute_digest();
        Ok(value)
    }

    /// Returns the server-owned connection identity.
    #[must_use]
    pub const fn connection_id(&self) -> ProviderConnectionId {
        self.connection_id
    }

    /// Returns the monotonic connection revision.
    #[must_use]
    pub const fn revision(&self) -> ProviderConnectionRevision {
        self.revision
    }

    /// Returns lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ProviderLifecycleState {
        self.state
    }

    /// Returns common and adapter-owned repository configuration.
    #[must_use]
    pub const fn configuration(&self) -> &ProviderConnectionConfiguration {
        &self.configuration
    }

    /// Returns original creation evidence.
    #[must_use]
    pub const fn created_at(&self) -> UnixMillis {
        self.created_at
    }

    /// Returns first activation evidence.
    #[must_use]
    pub const fn activated_at(&self) -> Option<UnixMillis> {
        self.activated_at
    }

    /// Returns terminal retirement evidence.
    #[must_use]
    pub const fn retired_at(&self) -> Option<UnixMillis> {
        self.retired_at
    }

    /// Returns the complete connection manifest digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Validates a contiguous, changed successor revision.
    ///
    /// # Errors
    ///
    /// Rejects identity changes, no-op revisions, lifecycle regression, and
    /// noncontiguous revisions.
    pub fn validate_successor(&self, prior: &Self) -> Result<(), ProviderConnectionError> {
        let next = prior
            .revision
            .get()
            .checked_add(1)
            .ok_or(ProviderConnectionError::InvalidSuccessor)?;
        if self.connection_id != prior.connection_id
            || self.revision.get() != next
            || self.created_at != prior.created_at
            || prior.state == ProviderLifecycleState::Retired
            || (prior.activated_at.is_some() && self.activated_at != prior.activated_at)
            || (prior.activated_at.is_none()
                && self.state != ProviderLifecycleState::Active
                && self.activated_at.is_some())
            || (self.state == prior.state
                && self.configuration == prior.configuration
                && self.activated_at == prior.activated_at
                && self.retired_at == prior.retired_at)
        {
            return Err(ProviderConnectionError::InvalidSuccessor);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Sha256Digest {
        let mut hash = Sha256::new();
        hash.update(CONNECTION_MANIFEST_DIGEST_DOMAIN);
        part(&mut hash, self.connection_id.as_uuid().as_bytes());
        part(&mut hash, &self.revision.get().to_be_bytes());
        part(
            &mut hash,
            match self.state {
                ProviderLifecycleState::Disabled => b"disabled",
                ProviderLifecycleState::Active => b"active",
                ProviderLifecycleState::Retired => b"retired",
            },
        );
        part(&mut hash, self.configuration.digest().as_bytes());
        part(&mut hash, &self.created_at.get().to_be_bytes());
        optional_time(&mut hash, self.activated_at);
        optional_time(&mut hash, self.retired_at);
        Sha256Digest::from_bytes(hash.finalize().into())
    }
}

fn part(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

fn optional_time(hash: &mut Sha256, value: Option<UnixMillis>) {
    match value {
        Some(value) => {
            hash.update([1]);
            hash.update(value.get().to_be_bytes());
        }
        None => hash.update([0]),
    }
}

impl fmt::Display for ProviderDefaultBranch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(formatter)
    }
}

impl fmt::Display for ProviderRepositoryPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(formatter)
    }
}

/// Invalid common provider connection configuration or lifecycle evidence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderConnectionError {
    /// Connection revisions must be positive signed 64-bit values.
    #[error("provider connection revision is invalid")]
    InvalidRevision,
    /// The default branch was not a canonical complete Git branch name.
    #[error("provider default branch is invalid")]
    InvalidDefaultBranch,
    /// A workflow selection path was not normalized and repository-relative.
    #[error("provider repository path is invalid")]
    InvalidRepositoryPath,
    /// Archive or workflow-discovery limits were unsafe or inconsistent.
    #[error("provider archive limits are invalid")]
    InvalidArchiveLimits,
    /// The adapter policy document was empty or excessive.
    #[error("provider connection policy document is invalid")]
    InvalidPolicyDocument,
    /// Lifecycle state and timestamps were inconsistent.
    #[error("provider connection lifecycle is invalid")]
    InvalidLifecycle,
    /// A revision did not strictly succeed its predecessor.
    #[error("provider connection successor is invalid")]
    InvalidSuccessor,
}
