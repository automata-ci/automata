use async_trait::async_trait;
use automata_ci_auth::management::{ManagementActor, ManagementRevision};
use automata_ci_core::UnixMillis;
use thiserror::Error;
use uuid::Uuid;

use crate::{GithubRepositoryName, RepositoryId, TenantScope};

/// Stable identifier reserved for the built-in encrypted secret provider.
pub const BUILTIN_SECRET_PROVIDER_ID: &str = "builtin";
/// Maximum number of secret metadata records returned by one management read.
pub const MAX_SECRET_METADATA_PAGE_SIZE: u16 = 100;
/// Maximum number of attempts retained by the durable cleanup outbox.
pub const MAX_SECRET_CLEANUP_ATTEMPTS: u16 = 100;
/// Maximum duration of one built-in secret cleanup claim before safe replay.
pub const MAX_SECRET_CLEANUP_CLAIM_MILLIS: u64 = 15 * 60 * 1_000;
/// Maximum delay before a failed built-in cleanup becomes eligible again.
pub const MAX_SECRET_CLEANUP_RETRY_BACKOFF_MILLIS: u64 = 24 * 60 * 60 * 1_000;
/// Fixed current-contract lifetime of a provider mutation reservation.
pub const SECRET_MUTATION_CONFIRMATION_TTL_MILLIS: u64 = 10 * 60 * 1_000;
/// Maximum duration of one stale-mutation recovery claim before safe takeover.
pub const MAX_SECRET_MUTATION_RECOVERY_CLAIM_MILLIS: u64 = 15 * 60 * 1_000;

const MAX_SECRET_NAME_BYTES: usize = 255;
const MAX_PROVIDER_ID_BYTES: usize = 64;
const MAX_WORKER_ID_BYTES: usize = 255;

/// Durable identity of one logical secret.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RepositorySecretId(Uuid);

impl RepositorySecretId {
    /// Constructs a non-nil logical secret identity selected by trusted ingress.
    ///
    /// # Errors
    ///
    /// Rejects the nil UUID sentinel.
    pub fn from_uuid(value: Uuid) -> Result<Self, SecretManagementValueError> {
        if value.is_nil() {
            return Err(SecretManagementValueError::NilSecretId);
        }
        Ok(Self(value))
    }

    /// Returns the durable UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

/// Canonical, case-insensitive secret name safe to expose as metadata.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RepositorySecretName(String);

impl RepositorySecretName {
    /// Validates and canonicalizes the GitHub-compatible secret name grammar.
    ///
    /// Platform-owned prefixes are reserved so a user secret cannot impersonate
    /// an injected Automata, Actions, GitHub, or runner value.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, non-ASCII, malformed, or reserved names.
    pub fn new(value: impl AsRef<str>) -> Result<Self, SecretManagementValueError> {
        let value = value.as_ref();
        if value.is_empty() || value.len() > MAX_SECRET_NAME_BYTES || !value.is_ascii() {
            return Err(SecretManagementValueError::InvalidSecretName);
        }
        let mut bytes = value.bytes();
        let first = bytes
            .next()
            .ok_or(SecretManagementValueError::InvalidSecretName)?;
        if !(first.is_ascii_alphabetic() || first == b'_')
            || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(SecretManagementValueError::InvalidSecretName);
        }
        let canonical = value.to_ascii_uppercase();
        if ["GITHUB_", "ACTIONS_", "RUNNER_", "AUTOMATA_"]
            .iter()
            .any(|prefix| canonical.starts_with(prefix))
        {
            return Err(SecretManagementValueError::ReservedSecretName);
        }
        Ok(Self(canonical))
    }

    /// Returns the canonical uppercase name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Canonical identifier of one configured provider adapter.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ManagedSecretProviderId(String);

impl ManagedSecretProviderId {
    /// Creates a lowercase portable provider identifier.
    ///
    /// # Errors
    ///
    /// Rejects an empty, oversized, or noncanonical identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, SecretManagementValueError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_PROVIDER_ID_BYTES
            && value.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || (index > 0 && matches!(byte, b'.' | b'-'))
            })
            && !value.ends_with(['.', '-']);
        if !valid {
            return Err(SecretManagementValueError::InvalidProviderId);
        }
        Ok(Self(value))
    }

    /// Returns the canonical provider identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Positive bounded page size for secret metadata reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretMetadataPageSize(u16);

impl SecretMetadataPageSize {
    /// Constructs a page size in the inclusive range `1..=100`.
    ///
    /// # Errors
    ///
    /// Rejects zero and oversized pages.
    pub const fn new(value: u16) -> Result<Self, SecretManagementValueError> {
        if value == 0 || value > MAX_SECRET_METADATA_PAGE_SIZE {
            return Err(SecretManagementValueError::InvalidPageSize);
        }
        Ok(Self(value))
    }

    /// Returns the requested record count.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Durable logical secret lifecycle visible to metadata readers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositorySecretState {
    /// The logical descriptor exists but no provider version is confirmed yet.
    Provisioning,
    /// The current immutable provider version is eligible for policy checks.
    Active,
    /// The logical secret is retained but unavailable to new workloads.
    Disabled,
}

/// Sanitized metadata for one repository-scoped secret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositorySecretMetadata {
    id: RepositorySecretId,
    repository_id: RepositoryId,
    name: RepositorySecretName,
    provider_id: ManagedSecretProviderId,
    state: RepositorySecretState,
    current_version_number: Option<u64>,
    revision: ManagementRevision,
    created_at: UnixMillis,
    updated_at: UnixMillis,
}

impl RepositorySecretMetadata {
    /// Rehydrates sanitized metadata after an adapter has validated all durable
    /// relationships and lifecycle invariants.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn from_durable_parts(
        id: RepositorySecretId,
        repository_id: RepositoryId,
        name: RepositorySecretName,
        provider_id: ManagedSecretProviderId,
        state: RepositorySecretState,
        current_version_number: Option<u64>,
        revision: ManagementRevision,
        created_at: UnixMillis,
        updated_at: UnixMillis,
    ) -> Self {
        Self {
            id,
            repository_id,
            name,
            provider_id,
            state,
            current_version_number,
            revision,
            created_at,
            updated_at,
        }
    }

    /// Returns the logical secret identity.
    #[must_use]
    pub const fn id(&self) -> RepositorySecretId {
        self.id
    }

    /// Returns the exact repository exposure ceiling.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Returns the canonical non-value metadata name.
    #[must_use]
    pub const fn name(&self) -> &RepositorySecretName {
        &self.name
    }

    /// Returns the configured provider identifier, never an opaque provider handle.
    #[must_use]
    pub const fn provider_id(&self) -> &ManagedSecretProviderId {
        &self.provider_id
    }

    /// Returns the current logical lifecycle.
    #[must_use]
    pub const fn state(&self) -> RepositorySecretState {
        self.state
    }

    /// Returns the display-only monotonic version number when one is current.
    #[must_use]
    pub const fn current_version_number(&self) -> Option<u64> {
        self.current_version_number
    }

    /// Returns the logical descriptor lifecycle revision.
    #[must_use]
    pub const fn revision(&self) -> ManagementRevision {
        self.revision
    }

    /// Returns the durable creation time.
    #[must_use]
    pub const fn created_at(&self) -> UnixMillis {
        self.created_at
    }

    /// Returns the latest durable metadata change time.
    #[must_use]
    pub const fn updated_at(&self) -> UnixMillis {
        self.updated_at
    }
}

/// One stable page of secret metadata ordered by logical UUID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositorySecretMetadataPage {
    records: Vec<RepositorySecretMetadata>,
    next_after: Option<RepositorySecretId>,
}

impl RepositorySecretMetadataPage {
    /// Constructs a validated adapter result.
    #[must_use]
    pub const fn new(
        records: Vec<RepositorySecretMetadata>,
        next_after: Option<RepositorySecretId>,
    ) -> Self {
        Self {
            records,
            next_after,
        }
    }

    /// Returns metadata records; values and provider handles can never be present.
    #[must_use]
    pub fn records(&self) -> &[RepositorySecretMetadata] {
        &self.records
    }

    /// Returns the exclusive UUID cursor for the next page.
    #[must_use]
    pub const fn next_after(&self) -> Option<RepositorySecretId> {
        self.next_after
    }
}

/// Sanitized built-in provider lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuiltinSecretProviderState {
    /// The seeded provider has not yet been enabled by an authorized manager.
    Unconfigured,
    /// The provider is available for new operations.
    Active,
    /// New operations are administratively disabled.
    Disabled,
}

/// Sanitized durable health of the built-in provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuiltinSecretProviderHealth {
    /// No successful provider health observation has been retained yet.
    Unknown,
    /// The provider can currently serve operations normally.
    Healthy,
    /// The provider is available with reduced reliability or functionality.
    Degraded,
    /// The provider cannot currently serve operations.
    Unavailable,
}

/// Revision evidence authorizing an activation attempt through `If-Match`.
///
/// This value contains no provider configuration, key material, or credential.
/// Activation still reauthorizes the actor and compares the revision inside the
/// mutation transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuiltinSecretProviderActivationEvidence {
    expected_revision: ManagementRevision,
}

impl BuiltinSecretProviderActivationEvidence {
    const fn new(expected_revision: ManagementRevision) -> Self {
        Self { expected_revision }
    }

    /// Returns the exact provider revision to send as the activation precondition.
    #[must_use]
    pub const fn expected_revision(self) -> ManagementRevision {
        self.expected_revision
    }
}

/// Atomic, value-free built-in provider inspection for management clients.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltinSecretProviderInspection {
    state: BuiltinSecretProviderState,
    health: BuiltinSecretProviderHealth,
    revision: ManagementRevision,
    activation: Option<BuiltinSecretProviderActivationEvidence>,
}

impl BuiltinSecretProviderInspection {
    /// Rehydrates one validated durable provider record and its authorization
    /// decision. Activation evidence is derived rather than supplied, so it is
    /// impossible to attach a mismatched revision or expose it for active state.
    #[must_use]
    pub const fn from_durable_parts(
        state: BuiltinSecretProviderState,
        health: BuiltinSecretProviderHealth,
        revision: ManagementRevision,
        actor_can_manage: bool,
    ) -> Self {
        let activation = if actor_can_manage && !matches!(state, BuiltinSecretProviderState::Active)
        {
            Some(BuiltinSecretProviderActivationEvidence::new(revision))
        } else {
            None
        };
        Self {
            state,
            health,
            revision,
            activation,
        }
    }

    /// Returns the durable provider lifecycle.
    #[must_use]
    pub const fn state(&self) -> BuiltinSecretProviderState {
        self.state
    }

    /// Returns the latest sanitized durable health classification.
    #[must_use]
    pub const fn health(&self) -> BuiltinSecretProviderHealth {
        self.health
    }

    /// Returns the provider configuration revision observed atomically.
    #[must_use]
    pub const fn revision(&self) -> ManagementRevision {
        self.revision
    }

    /// Returns revision evidence only when this actor may activate the current
    /// non-active provider state.
    #[must_use]
    pub const fn activation(&self) -> Option<BuiltinSecretProviderActivationEvidence> {
        self.activation
    }
}

/// Sanitized metadata for the built-in provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltinSecretProviderMetadata {
    state: BuiltinSecretProviderState,
    revision: ManagementRevision,
    updated_at: UnixMillis,
}

impl BuiltinSecretProviderMetadata {
    /// Rehydrates a validated built-in provider record.
    #[must_use]
    pub const fn new(
        state: BuiltinSecretProviderState,
        revision: ManagementRevision,
        updated_at: UnixMillis,
    ) -> Self {
        Self {
            state,
            revision,
            updated_at,
        }
    }

    /// Returns the configured lifecycle.
    #[must_use]
    pub const fn state(&self) -> BuiltinSecretProviderState {
        self.state
    }

    /// Returns the provider configuration revision.
    #[must_use]
    pub const fn revision(&self) -> ManagementRevision {
        self.revision
    }

    /// Returns the latest durable provider change time.
    #[must_use]
    pub const fn updated_at(&self) -> UnixMillis {
        self.updated_at
    }
}

/// Enables the seeded built-in provider after runtime key/capability validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivateBuiltinSecretProvider {
    actor: ManagementActor,
    expected_revision: ManagementRevision,
}

impl ActivateBuiltinSecretProvider {
    /// Constructs a revision-guarded activation request.
    #[must_use]
    pub const fn new(actor: ManagementActor, expected_revision: ManagementRevision) -> Self {
        Self {
            actor,
            expected_revision,
        }
    }

    /// Returns the exact authenticated actor evidence to reauthorize durably.
    #[must_use]
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    /// Returns the provider revision observed by the caller.
    #[must_use]
    pub const fn expected_revision(&self) -> ManagementRevision {
        self.expected_revision
    }
}

/// Closed activation result without configuration or key material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActivateBuiltinSecretProviderOutcome {
    /// The provider was enabled at the returned revision.
    Activated(BuiltinSecretProviderMetadata),
    /// The provider was already active at the expected revision.
    AlreadyActive(BuiltinSecretProviderMetadata),
    /// The actor is active but lacks tenant-wide provider management authority.
    Forbidden,
    /// The exact session authorization generation is no longer current.
    SessionStale,
    /// The required seeded provider record does not exist.
    NotFound,
    /// The provider revision changed since it was read.
    RevisionConflict { current: ManagementRevision },
}

/// Transactionally authorized inspection of the built-in provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectBuiltinSecretProvider {
    actor: ManagementActor,
}

impl InspectBuiltinSecretProvider {
    /// Constructs an inspection using exact authenticated actor evidence.
    #[must_use]
    pub const fn new(actor: ManagementActor) -> Self {
        Self { actor }
    }

    /// Returns the actor evidence to reauthorize durably.
    #[must_use]
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }
}

/// Closed built-in provider inspection result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InspectBuiltinSecretProviderOutcome {
    /// The authorized atomic provider inspection.
    Found(BuiltinSecretProviderInspection),
    /// The actor lacks tenant-wide redacted provider-read authority.
    Forbidden,
    /// The exact session authorization generation is no longer current.
    SessionStale,
    /// The seeded built-in provider record is absent.
    NotFound,
}

/// Resolves one exact GitHub repository name for secret metadata operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolveGithubRepositorySecretMetadata {
    actor: ManagementActor,
    repository: GithubRepositoryName,
}

impl ResolveGithubRepositorySecretMetadata {
    /// Constructs an exact, validated GitHub repository resolution request.
    #[must_use]
    pub const fn new(actor: ManagementActor, repository: GithubRepositoryName) -> Self {
        Self { actor, repository }
    }

    /// Returns the actor evidence to reauthorize durably.
    #[must_use]
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    /// Returns the canonical GitHub `owner/repository` coordinate.
    #[must_use]
    pub const fn repository(&self) -> &GithubRepositoryName {
        &self.repository
    }
}

/// Non-enumerating exact GitHub repository resolution result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolveGithubRepositorySecretMetadataOutcome {
    /// The current actor may read secret metadata for this repository.
    Found(RepositoryId),
    /// The session authorization generation is no longer current.
    SessionStale,
    /// The repository is absent or the actor lacks metadata-read authority.
    NotFound,
}

/// Authorized lookup of one exact repository secret's value-free metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetRepositorySecretMetadata {
    actor: ManagementActor,
    repository_id: RepositoryId,
    name: RepositorySecretName,
}

impl GetRepositorySecretMetadata {
    /// Constructs an exact repository-and-canonical-name metadata lookup.
    ///
    /// # Errors
    ///
    /// Rejects the nil repository UUID.
    pub fn new(
        actor: ManagementActor,
        repository_id: RepositoryId,
        name: RepositorySecretName,
    ) -> Result<Self, SecretManagementValueError> {
        require_repository(repository_id)?;
        Ok(Self {
            actor,
            repository_id,
            name,
        })
    }

    /// Returns the actor evidence to reauthorize durably.
    #[must_use]
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    /// Returns the exact repository exposure ceiling.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Returns the exact canonical metadata name.
    #[must_use]
    pub const fn name(&self) -> &RepositorySecretName {
        &self.name
    }
}

/// Non-enumerating exact secret metadata lookup result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GetRepositorySecretMetadataOutcome {
    /// The exact value-free logical secret metadata.
    Found(RepositorySecretMetadata),
    /// The session authorization generation is no longer current.
    SessionStale,
    /// The repository/secret is absent or the actor lacks metadata-read authority.
    NotFound,
}

/// Authorized repository-scoped metadata read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListRepositorySecrets {
    actor: ManagementActor,
    repository_id: RepositoryId,
    after: Option<RepositorySecretId>,
    limit: SecretMetadataPageSize,
}

impl ListRepositorySecrets {
    /// Constructs a bounded exact-repository metadata read.
    ///
    /// # Errors
    ///
    /// Rejects the nil repository UUID.
    pub fn new(
        actor: ManagementActor,
        repository_id: RepositoryId,
        after: Option<RepositorySecretId>,
        limit: SecretMetadataPageSize,
    ) -> Result<Self, SecretManagementValueError> {
        require_repository(repository_id)?;
        Ok(Self {
            actor,
            repository_id,
            after,
            limit,
        })
    }

    /// Returns the exact actor evidence to reauthorize.
    #[must_use]
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    /// Returns the repository exposure ceiling.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Returns the exclusive UUID cursor.
    #[must_use]
    pub const fn after(&self) -> Option<RepositorySecretId> {
        self.after
    }

    /// Returns the requested page bound.
    #[must_use]
    pub const fn limit(&self) -> SecretMetadataPageSize {
        self.limit
    }
}

/// Closed metadata-read result with cross-tenant resources hidden.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ListRepositorySecretsOutcome {
    /// The authorized metadata page.
    Found(RepositorySecretMetadataPage),
    /// The actor is current but lacks metadata-read authority for the repository.
    Forbidden,
    /// The exact session authorization generation is no longer current.
    SessionStale,
    /// The repository does not exist in the actor tenant.
    NotFound,
}

/// Durable identity of one crash-safe secret-version mutation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RepositorySecretMutationId(Uuid);

impl RepositorySecretMutationId {
    /// Constructs a non-nil mutation identity distinct from the logical secret.
    ///
    /// # Errors
    ///
    /// Rejects the nil UUID sentinel or reuse of the logical secret UUID.
    pub fn from_uuid(
        value: Uuid,
        secret_id: RepositorySecretId,
    ) -> Result<Self, SecretManagementValueError> {
        if value.is_nil() {
            return Err(SecretManagementValueError::NilMutationId);
        }
        if value == secret_id.as_uuid() {
            return Err(SecretManagementValueError::MutationIdReusesSecretId);
        }
        Ok(Self(value))
    }

    /// Returns the durable UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

/// Canonical built-in provider version identity safe to return without a handle.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RepositorySecretVersionId(Uuid);

impl RepositorySecretVersionId {
    /// Constructs a non-nil built-in version UUID.
    ///
    /// # Errors
    ///
    /// Rejects the nil UUID sentinel.
    pub fn from_uuid(value: Uuid) -> Result<Self, SecretManagementValueError> {
        if value.is_nil() {
            return Err(SecretManagementValueError::NilVersionId);
        }
        Ok(Self(value))
    }

    /// Returns the canonical built-in version UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

/// Redacted built-in provider target containing canonical UUIDs only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuiltinRepositorySecretVersion {
    secret_id: RepositorySecretId,
    version_id: RepositorySecretVersionId,
    version_number: u64,
}

impl BuiltinRepositorySecretVersion {
    /// Constructs a canonical built-in provider target.
    ///
    /// # Errors
    ///
    /// Rejects version number zero.
    pub const fn new(
        secret_id: RepositorySecretId,
        version_id: RepositorySecretVersionId,
        version_number: u64,
    ) -> Result<Self, SecretManagementValueError> {
        if version_number == 0 {
            return Err(SecretManagementValueError::InvalidVersionNumber);
        }
        Ok(Self {
            secret_id,
            version_id,
            version_number,
        })
    }

    /// Returns the canonical logical locator used by the built-in provider.
    #[must_use]
    pub const fn secret_id(self) -> RepositorySecretId {
        self.secret_id
    }

    /// Returns the canonical immutable built-in version UUID.
    #[must_use]
    pub const fn version_id(self) -> RepositorySecretVersionId {
        self.version_id
    }

    /// Returns the display-only monotonic version number.
    #[must_use]
    pub const fn version_number(self) -> u64 {
        self.version_number
    }
}

/// Closed kind of immutable version mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositorySecretMutationKind {
    /// Creates the logical descriptor and its first immutable version.
    Create,
    /// Replaces one exact current immutable version.
    Replace,
}

/// Reserves a repository-scoped create or replacement before any provider call.
///
/// Deliberately absent is the secret value. The application retains the
/// move-only plaintext, invokes the exact returned built-in target outside the
/// repository transaction, and then confirms the provider result with
/// [`ConfirmRepositorySecretVersionMutation`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReserveRepositorySecretVersionMutation {
    actor: ManagementActor,
    mutation_id: RepositorySecretMutationId,
    secret_id: RepositorySecretId,
    repository_id: RepositoryId,
    name: RepositorySecretName,
    provider_id: Option<ManagedSecretProviderId>,
    kind: RepositorySecretMutationKind,
    expected_revision: Option<ManagementRevision>,
}

impl ReserveRepositorySecretVersionMutation {
    /// Constructs one create reservation with independent idempotency identity.
    ///
    /// A missing provider selects the exact active durable default; adapters
    /// must never fall back when an explicit provider is unavailable.
    ///
    /// # Errors
    ///
    /// Rejects the nil repository UUID or a mutation UUID equal to the actual
    /// logical secret UUID.
    pub fn create(
        actor: ManagementActor,
        mutation_id: RepositorySecretMutationId,
        secret_id: RepositorySecretId,
        repository_id: RepositoryId,
        name: RepositorySecretName,
        provider_id: Option<ManagedSecretProviderId>,
    ) -> Result<Self, SecretManagementValueError> {
        require_repository(repository_id)?;
        require_mutation_for_secret(mutation_id, secret_id)?;
        Ok(Self {
            actor,
            mutation_id,
            secret_id,
            repository_id,
            name,
            provider_id,
            kind: RepositorySecretMutationKind::Create,
            expected_revision: None,
        })
    }

    /// Constructs one revision-guarded replacement reservation.
    ///
    /// The adapter binds the exact current built-in predecessor under lock and
    /// returns it in the durable reservation. Provider selection is immutable
    /// for the lifetime of a logical secret.
    ///
    /// # Errors
    ///
    /// Rejects the nil repository UUID or a mutation UUID equal to the actual
    /// logical secret UUID.
    pub fn replace(
        actor: ManagementActor,
        mutation_id: RepositorySecretMutationId,
        secret_id: RepositorySecretId,
        repository_id: RepositoryId,
        name: RepositorySecretName,
        expected_revision: ManagementRevision,
    ) -> Result<Self, SecretManagementValueError> {
        require_repository(repository_id)?;
        require_mutation_for_secret(mutation_id, secret_id)?;
        Ok(Self {
            actor,
            mutation_id,
            secret_id,
            repository_id,
            name,
            provider_id: None,
            kind: RepositorySecretMutationKind::Replace,
            expected_revision: Some(expected_revision),
        })
    }

    /// Returns the exact actor evidence to reauthorize.
    #[must_use]
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    /// Returns the independent mutation identity.
    #[must_use]
    pub const fn mutation_id(&self) -> RepositorySecretMutationId {
        self.mutation_id
    }

    /// Returns the client-selected stable logical identity.
    #[must_use]
    pub const fn secret_id(&self) -> RepositorySecretId {
        self.secret_id
    }

    /// Returns the immutable repository exposure ceiling.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Returns the canonical metadata name.
    #[must_use]
    pub const fn name(&self) -> &RepositorySecretName {
        &self.name
    }

    /// Returns an explicit provider, or `None` to select the durable default.
    #[must_use]
    pub const fn provider_id(&self) -> Option<&ManagedSecretProviderId> {
        self.provider_id.as_ref()
    }

    /// Returns whether this creates or replaces an immutable version.
    #[must_use]
    pub const fn kind(&self) -> RepositorySecretMutationKind {
        self.kind
    }

    /// Returns the exact logical revision expected by a replacement.
    #[must_use]
    pub const fn expected_revision(&self) -> Option<ManagementRevision> {
        self.expected_revision
    }
}

/// Sanitized handoff from one durable mutation to the built-in provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositorySecretVersionMutationReservation {
    mutation_id: RepositorySecretMutationId,
    secret_id: RepositorySecretId,
    repository_id: RepositoryId,
    name: RepositorySecretName,
    provider_id: ManagedSecretProviderId,
    kind: RepositorySecretMutationKind,
    reserved_revision: ManagementRevision,
    reserved_version_number: u64,
    confirmation_deadline: UnixMillis,
    expected_predecessor: Option<BuiltinRepositorySecretVersion>,
    provider_create_request_id: String,
}

impl RepositorySecretVersionMutationReservation {
    /// Constructs an immutable, value-free provider handoff.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        mutation_id: RepositorySecretMutationId,
        secret_id: RepositorySecretId,
        repository_id: RepositoryId,
        name: RepositorySecretName,
        provider_id: ManagedSecretProviderId,
        kind: RepositorySecretMutationKind,
        reserved_revision: ManagementRevision,
        reserved_version_number: u64,
        confirmation_deadline: UnixMillis,
        expected_predecessor: Option<BuiltinRepositorySecretVersion>,
        provider_create_request_id: String,
    ) -> Self {
        Self {
            mutation_id,
            secret_id,
            repository_id,
            name,
            provider_id,
            kind,
            reserved_revision,
            reserved_version_number,
            confirmation_deadline,
            expected_predecessor,
            provider_create_request_id,
        }
    }

    /// Returns the independent durable mutation identity.
    #[must_use]
    pub const fn mutation_id(&self) -> RepositorySecretMutationId {
        self.mutation_id
    }

    /// Returns the logical secret identity used as the built-in locator.
    #[must_use]
    pub const fn secret_id(&self) -> RepositorySecretId {
        self.secret_id
    }

    /// Returns the immutable repository exposure ceiling.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Returns the canonical descriptor name.
    #[must_use]
    pub const fn name(&self) -> &RepositorySecretName {
        &self.name
    }

    /// Returns the exact built-in provider identity.
    #[must_use]
    pub const fn provider_id(&self) -> &ManagedSecretProviderId {
        &self.provider_id
    }

    /// Returns whether this mutation creates or replaces a version.
    #[must_use]
    pub const fn kind(&self) -> RepositorySecretMutationKind {
        self.kind
    }

    /// Returns the logical revision locked when the mutation was reserved.
    #[must_use]
    pub const fn reserved_revision(&self) -> ManagementRevision {
        self.reserved_revision
    }

    /// Returns the immutable attempt ordinal allocated before provider I/O.
    #[must_use]
    pub const fn reserved_version_number(&self) -> u64 {
        self.reserved_version_number
    }

    /// Returns the absolute last instant at which human confirmation may apply.
    #[must_use]
    pub const fn confirmation_deadline(&self) -> UnixMillis {
        self.confirmation_deadline
    }

    /// Returns the exact built-in predecessor for a replacement.
    #[must_use]
    pub const fn expected_predecessor(&self) -> Option<BuiltinRepositorySecretVersion> {
        self.expected_predecessor
    }

    /// Returns the stable, non-secret provider idempotency key.
    #[must_use]
    pub fn provider_create_request_id(&self) -> &str {
        &self.provider_create_request_id
    }
}

/// Sanitized receipt for a provider result durably bound to one mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepositorySecretVersionMutationReceipt {
    mutation_id: RepositorySecretMutationId,
    committed: BuiltinRepositorySecretVersion,
}

impl RepositorySecretVersionMutationReceipt {
    /// Constructs a value-free built-in provider receipt.
    #[must_use]
    pub const fn new(
        mutation_id: RepositorySecretMutationId,
        committed: BuiltinRepositorySecretVersion,
    ) -> Self {
        Self {
            mutation_id,
            committed,
        }
    }

    /// Returns the mutation identity.
    #[must_use]
    pub const fn mutation_id(self) -> RepositorySecretMutationId {
        self.mutation_id
    }

    /// Returns the exact committed built-in version.
    #[must_use]
    pub const fn committed(self) -> BuiltinRepositorySecretVersion {
        self.committed
    }
}

/// Closed logical mutation reservation result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReserveRepositorySecretVersionMutationOutcome {
    /// A newly committed intent authorizes its sole provider create call.
    FreshReservation(RepositorySecretVersionMutationReservation),
    /// An exact live replay may only reconcile the original provider create.
    ReconcileRequired(RepositorySecretVersionMutationReservation),
    /// Exact replay of a mutation whose provider version remains current.
    Applied(RepositorySecretVersionMutationReceipt),
    /// Exact replay of a mutation that applied and was later superseded.
    AppliedThenSuperseded(RepositorySecretVersionMutationReceipt),
    /// Exact replay of a mutation whose provider commit preceded deletion.
    AppliedThenDeleted(RepositorySecretVersionMutationReceipt),
    /// Exact replay of a mutation that definitively lost predecessor CAS.
    CasLost,
    /// Exact replay of an intent cancelled by logical deletion.
    Cancelled,
    /// Exact replay of an abandoned reservation cancelled at its hard deadline.
    Expired,
    /// The actor is current but lacks create authority for the repository.
    Forbidden,
    /// The exact session authorization generation is no longer current.
    SessionStale,
    /// The repository is absent from the actor tenant.
    NotFound,
    /// The UUID, name, or immutable descriptor conflicts with existing state.
    Conflict,
    /// The replacement observed a different logical descriptor revision.
    RevisionConflict {
        /// Current logical descriptor revision.
        current: ManagementRevision,
    },
    /// The exact configured provider is absent, disabled, external, or unsupported.
    ProviderUnavailable,
}

/// Closed result of the out-of-transaction provider operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositorySecretProviderMutationResult {
    /// The built-in provider returned this canonical logical/version UUID pair.
    BuiltinCreated(BuiltinRepositorySecretVersion),
    /// The provider definitively rejected the exact predecessor CAS.
    CasLost,
}

/// Reauthorizes and verifies one exact provider result after the provider call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfirmRepositorySecretVersionMutation {
    actor: ManagementActor,
    mutation_id: RepositorySecretMutationId,
    provider_result: RepositorySecretProviderMutationResult,
}

impl ConfirmRepositorySecretVersionMutation {
    /// Constructs a value-free confirmation for a typed built-in provider result.
    #[must_use]
    pub const fn new(
        actor: ManagementActor,
        mutation_id: RepositorySecretMutationId,
        provider_result: RepositorySecretProviderMutationResult,
    ) -> Self {
        Self {
            actor,
            mutation_id,
            provider_result,
        }
    }

    /// Returns the exact actor evidence to reauthorize after the provider call.
    #[must_use]
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    /// Returns the independent reserved mutation identity.
    #[must_use]
    pub const fn mutation_id(&self) -> RepositorySecretMutationId {
        self.mutation_id
    }

    /// Returns the closed, value-free provider result to reconcile.
    #[must_use]
    pub const fn provider_result(&self) -> RepositorySecretProviderMutationResult {
        self.provider_result
    }
}

/// Closed confirmation result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfirmRepositorySecretVersionMutationOutcome {
    /// The exact encrypted provider version is durable and remains current.
    Applied(RepositorySecretVersionMutationReceipt),
    /// The exact encrypted provider version applied and was later superseded.
    AppliedThenSuperseded(RepositorySecretVersionMutationReceipt),
    /// The exact encrypted provider version applied before logical deletion.
    AppliedThenDeleted(RepositorySecretVersionMutationReceipt),
    /// The exact provider request definitively lost predecessor CAS.
    CasLost,
    /// Logical deletion cancelled the reserved intent.
    Cancelled,
    /// The hard confirmation deadline elapsed and the reservation was cancelled.
    Expired,
    /// The actor is current but lacks create authority for the repository.
    Forbidden,
    /// The exact session authorization generation is no longer current.
    SessionStale,
    /// The mutation is absent from the actor tenant.
    NotFound,
    /// The confirmation differs from the durable intent or terminal receipt.
    Conflict,
    /// The reserved provider cannot be safely reconciled by this adapter.
    ProviderUnavailable,
}

/// Revision-guarded logical deletion and cryptographic-erasure enqueue request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeleteRepositorySecret {
    actor: ManagementActor,
    repository_id: RepositoryId,
    secret_id: RepositorySecretId,
    expected_revision: ManagementRevision,
}

impl DeleteRepositorySecret {
    /// Constructs a deletion request for one exact repository and descriptor revision.
    ///
    /// # Errors
    ///
    /// Rejects the nil repository UUID.
    pub fn new(
        actor: ManagementActor,
        repository_id: RepositoryId,
        secret_id: RepositorySecretId,
        expected_revision: ManagementRevision,
    ) -> Result<Self, SecretManagementValueError> {
        require_repository(repository_id)?;
        Ok(Self {
            actor,
            repository_id,
            secret_id,
            expected_revision,
        })
    }

    /// Returns the exact actor evidence to reauthorize.
    #[must_use]
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    /// Returns the exact repository parent supplied by the caller.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Returns the logical secret identity.
    #[must_use]
    pub const fn secret_id(&self) -> RepositorySecretId {
        self.secret_id
    }

    /// Returns the descriptor revision observed by the caller.
    #[must_use]
    pub const fn expected_revision(&self) -> ManagementRevision {
        self.expected_revision
    }
}

/// Sanitized deletion receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepositorySecretDeletionReceipt {
    secret_id: RepositorySecretId,
    cleanup_operations: u16,
}

impl RepositorySecretDeletionReceipt {
    /// Constructs a receipt for atomically enqueued erasure operations.
    #[must_use]
    pub const fn new(secret_id: RepositorySecretId, cleanup_operations: u16) -> Self {
        Self {
            secret_id,
            cleanup_operations,
        }
    }

    /// Returns the logically deleted secret.
    #[must_use]
    pub const fn secret_id(self) -> RepositorySecretId {
        self.secret_id
    }

    /// Returns the number of exact immutable versions scheduled for erasure.
    #[must_use]
    pub const fn cleanup_operations(self) -> u16 {
        self.cleanup_operations
    }
}

/// Closed logical deletion result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeleteRepositorySecretOutcome {
    /// Workload access was revoked and all retained versions were atomically enqueued.
    Deleted(RepositorySecretDeletionReceipt),
    /// The descriptor was already logically deleted.
    AlreadyDeleted,
    /// The actor is current but lacks delete authority for the repository.
    Forbidden,
    /// The exact session authorization generation is no longer current.
    SessionStale,
    /// The repository-scoped descriptor is absent from the actor tenant.
    NotFound,
    /// The descriptor revision changed since it was read.
    RevisionConflict { current: ManagementRevision },
}

/// Stable identity of one cleanup worker process.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretCleanupWorkerId(String);

impl SecretCleanupWorkerId {
    /// Creates a bounded identifier that is safe for persistence and diagnostics.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or control-containing values.
    pub fn new(value: impl Into<String>) -> Result<Self, SecretManagementValueError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_WORKER_ID_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(SecretManagementValueError::InvalidCleanupWorkerId);
        }
        Ok(Self(value))
    }

    /// Returns the validated worker identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact optimistic fence for one claimed cleanup operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretCleanupFence {
    operation_id: Uuid,
    worker_id: SecretCleanupWorkerId,
    claim_generation: u64,
    locked_at: UnixMillis,
}

impl SecretCleanupFence {
    /// Rehydrates a validated claim fence.
    #[must_use]
    pub const fn new(
        operation_id: Uuid,
        worker_id: SecretCleanupWorkerId,
        claim_generation: u64,
        locked_at: UnixMillis,
    ) -> Self {
        Self {
            operation_id,
            worker_id,
            claim_generation,
            locked_at,
        }
    }

    /// Returns the stable outbox operation UUID.
    #[must_use]
    pub const fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    /// Returns the exact claiming worker.
    #[must_use]
    pub const fn worker_id(&self) -> &SecretCleanupWorkerId {
        &self.worker_id
    }

    /// Returns the positive monotonic claim generation.
    #[must_use]
    pub const fn claim_generation(&self) -> u64 {
        self.claim_generation
    }

    /// Returns the lock generation timestamp used to reject stale completions.
    #[must_use]
    pub const fn locked_at(&self) -> UnixMillis {
        self.locked_at
    }
}

/// Built-in provider erasure work without a value or opaque provider handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltinSecretCleanupTask {
    fence: SecretCleanupFence,
    tenant: TenantScope,
    provider_id: ManagedSecretProviderId,
    secret_id: RepositorySecretId,
    repository_id: RepositoryId,
    name: RepositorySecretName,
    secret_version_id: Uuid,
    version_number: u64,
    provider_destroy_request_id: String,
    attempts: u16,
}

impl BuiltinSecretCleanupTask {
    /// Rehydrates an exact built-in destruction task from validated durable records.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        fence: SecretCleanupFence,
        tenant: TenantScope,
        provider_id: ManagedSecretProviderId,
        secret_id: RepositorySecretId,
        repository_id: RepositoryId,
        name: RepositorySecretName,
        secret_version_id: Uuid,
        version_number: u64,
        provider_destroy_request_id: String,
        attempts: u16,
    ) -> Self {
        Self {
            fence,
            tenant,
            provider_id,
            secret_id,
            repository_id,
            name,
            secret_version_id,
            version_number,
            provider_destroy_request_id,
            attempts,
        }
    }

    /// Returns the exact claim fence.
    #[must_use]
    pub const fn fence(&self) -> &SecretCleanupFence {
        &self.fence
    }

    /// Returns the authenticated tenant authority required by the provider descriptor.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }

    /// Returns the exact durable provider selected by the cleanup outbox.
    #[must_use]
    pub const fn provider_id(&self) -> &ManagedSecretProviderId {
        &self.provider_id
    }

    /// Returns the logical secret UUID, which is also the built-in locator.
    #[must_use]
    pub const fn secret_id(&self) -> RepositorySecretId {
        self.secret_id
    }

    /// Returns the immutable repository scope needed to build the provider descriptor.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Returns the sanitized logical name needed to build the provider descriptor.
    #[must_use]
    pub const fn name(&self) -> &RepositorySecretName {
        &self.name
    }

    /// Returns the immutable built-in provider version UUID.
    #[must_use]
    pub const fn secret_version_id(&self) -> Uuid {
        self.secret_version_id
    }

    /// Returns the display-only monotonic version number.
    #[must_use]
    pub const fn version_number(&self) -> u64 {
        self.version_number
    }

    /// Returns the stable, non-secret provider destruction idempotency key.
    #[must_use]
    pub fn provider_destroy_request_id(&self) -> &str {
        &self.provider_destroy_request_id
    }

    /// Returns the durable attempt count including this claim.
    #[must_use]
    pub const fn attempts(&self) -> u16 {
        self.attempts
    }
}

/// Claims one ready built-in cryptographic-erasure operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimBuiltinSecretCleanup {
    worker_id: SecretCleanupWorkerId,
    now: UnixMillis,
    stale_after_millis: u64,
}

impl ClaimBuiltinSecretCleanup {
    /// Constructs a claim and stale-lock takeover policy.
    ///
    /// # Errors
    ///
    /// Rejects a pre-epoch time, zero timeout, or a timeout above the public
    /// cleanup claim bound.
    pub fn new(
        worker_id: SecretCleanupWorkerId,
        now: UnixMillis,
        stale_after_millis: u64,
    ) -> Result<Self, SecretManagementValueError> {
        if now.get() < 0
            || stale_after_millis == 0
            || stale_after_millis > MAX_SECRET_CLEANUP_CLAIM_MILLIS
        {
            return Err(SecretManagementValueError::InvalidCleanupTime);
        }
        Ok(Self {
            worker_id,
            now,
            stale_after_millis,
        })
    }

    /// Returns the worker identity.
    #[must_use]
    pub const fn worker_id(&self) -> &SecretCleanupWorkerId {
        &self.worker_id
    }

    /// Returns the claim time.
    #[must_use]
    pub const fn now(&self) -> UnixMillis {
        self.now
    }

    /// Returns the bounded stale-lock takeover duration.
    #[must_use]
    pub const fn stale_after_millis(&self) -> u64 {
        self.stale_after_millis
    }
}

/// Value-free durable work item for one due mutation reservation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretMutationRecoveryTask {
    fence: SecretMutationRecoveryFence,
    tenant: TenantScope,
    mutation_id: RepositorySecretMutationId,
    secret_id: RepositorySecretId,
    provider_id: ManagedSecretProviderId,
    repository_id: RepositoryId,
    name: RepositorySecretName,
    kind: RepositorySecretMutationKind,
    reserved_version_number: u64,
    expected_predecessor: Option<BuiltinRepositorySecretVersion>,
    provider_create_request_id: String,
    confirmation_deadline: UnixMillis,
}

impl SecretMutationRecoveryTask {
    /// Rehydrates a validated recovery task from durable state.
    #[allow(clippy::too_many_arguments)] // Every durable create-intent pin is explicit.
    #[must_use]
    pub const fn new(
        fence: SecretMutationRecoveryFence,
        tenant: TenantScope,
        mutation_id: RepositorySecretMutationId,
        secret_id: RepositorySecretId,
        provider_id: ManagedSecretProviderId,
        repository_id: RepositoryId,
        name: RepositorySecretName,
        kind: RepositorySecretMutationKind,
        reserved_version_number: u64,
        expected_predecessor: Option<BuiltinRepositorySecretVersion>,
        provider_create_request_id: String,
        confirmation_deadline: UnixMillis,
    ) -> Self {
        Self {
            fence,
            tenant,
            mutation_id,
            secret_id,
            provider_id,
            repository_id,
            name,
            kind,
            reserved_version_number,
            expected_predecessor,
            provider_create_request_id,
            confirmation_deadline,
        }
    }

    /// Returns the exact recovery fence.
    #[must_use]
    pub const fn fence(&self) -> &SecretMutationRecoveryFence {
        &self.fence
    }

    /// Returns the authenticated tenant boundary.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }

    /// Returns the immutable mutation identity.
    #[must_use]
    pub const fn mutation_id(&self) -> RepositorySecretMutationId {
        self.mutation_id
    }

    /// Returns the immutable logical secret identity.
    #[must_use]
    pub const fn secret_id(&self) -> RepositorySecretId {
        self.secret_id
    }

    /// Returns the exact durable provider that owns the original create intent.
    #[must_use]
    pub const fn provider_id(&self) -> &ManagedSecretProviderId {
        &self.provider_id
    }

    /// Returns the immutable repository scope in the provider descriptor.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Returns the canonical name in the provider descriptor.
    #[must_use]
    pub const fn name(&self) -> &RepositorySecretName {
        &self.name
    }

    /// Returns the persisted mutation kind.
    #[must_use]
    pub const fn kind(&self) -> RepositorySecretMutationKind {
        self.kind
    }

    /// Returns the immutable version ordinal reserved before provider I/O.
    #[must_use]
    pub const fn reserved_version_number(&self) -> u64 {
        self.reserved_version_number
    }

    /// Returns the exact optional predecessor of the original create intent.
    #[must_use]
    pub const fn expected_predecessor(&self) -> Option<BuiltinRepositorySecretVersion> {
        self.expected_predecessor
    }

    /// Returns the original provider idempotency request identifier.
    #[must_use]
    pub fn provider_create_request_id(&self) -> &str {
        &self.provider_create_request_id
    }

    /// Returns the immutable hard confirmation deadline.
    #[must_use]
    pub const fn confirmation_deadline(&self) -> UnixMillis {
        self.confirmation_deadline
    }
}

/// Exact monotonic fence for one stale-reservation recovery claim.
///
/// Every takeover increments the durable generation, so an older replica can
/// never complete after ownership moves. Lock time is timeout evidence only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretMutationRecoveryFence {
    operation_id: Uuid,
    worker_id: SecretCleanupWorkerId,
    claim_generation: u64,
    locked_at: UnixMillis,
}

impl SecretMutationRecoveryFence {
    /// Rehydrates one exact durable recovery fence.
    ///
    /// # Errors
    ///
    /// Rejects a nil operation, zero generation, or pre-epoch lock observation.
    pub fn new(
        operation_id: Uuid,
        worker_id: SecretCleanupWorkerId,
        claim_generation: u64,
        locked_at: UnixMillis,
    ) -> Result<Self, SecretManagementValueError> {
        if operation_id.is_nil() || claim_generation == 0 || locked_at.get() < 0 {
            return Err(SecretManagementValueError::InvalidRecoveryTime);
        }
        Ok(Self {
            operation_id,
            worker_id,
            claim_generation,
            locked_at,
        })
    }

    /// Returns the stable recovery operation UUID.
    #[must_use]
    pub const fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    /// Returns the exact claiming worker.
    #[must_use]
    pub const fn worker_id(&self) -> &SecretCleanupWorkerId {
        &self.worker_id
    }

    /// Returns the positive monotonic ownership generation.
    #[must_use]
    pub const fn claim_generation(&self) -> u64 {
        self.claim_generation
    }

    /// Returns the strictly monotonic durable lock observation.
    #[must_use]
    pub const fn locked_at(&self) -> UnixMillis {
        self.locked_at
    }
}

/// Claims one due reservation, including safe takeover of a stale replica.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimSecretMutationRecovery {
    worker_id: SecretCleanupWorkerId,
    now: UnixMillis,
    stale_after_millis: u64,
}

impl ClaimSecretMutationRecovery {
    /// Constructs a bounded due-reservation claim.
    ///
    /// # Errors
    ///
    /// Rejects invalid time or stale-takeover bounds.
    pub fn new(
        worker_id: SecretCleanupWorkerId,
        now: UnixMillis,
        stale_after_millis: u64,
    ) -> Result<Self, SecretManagementValueError> {
        if now.get() < 0
            || stale_after_millis == 0
            || stale_after_millis > MAX_SECRET_MUTATION_RECOVERY_CLAIM_MILLIS
        {
            return Err(SecretManagementValueError::InvalidRecoveryTime);
        }
        Ok(Self {
            worker_id,
            now,
            stale_after_millis,
        })
    }

    /// Returns the stable process identity.
    #[must_use]
    pub const fn worker_id(&self) -> &SecretCleanupWorkerId {
        &self.worker_id
    }

    /// Returns the trusted recovery observation time.
    #[must_use]
    pub const fn now(&self) -> UnixMillis {
        self.now
    }

    /// Returns the bounded stale-claim takeover duration.
    #[must_use]
    pub const fn stale_after_millis(&self) -> u64 {
        self.stale_after_millis
    }
}

/// Completes one expired reservation using exact value-free provider evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverSecretMutationReservation {
    fence: SecretMutationRecoveryFence,
    recovered_at: UnixMillis,
    reconciliation: SecretMutationRecoveryReconciliation,
}

impl RecoverSecretMutationReservation {
    /// Constructs a fenced recovery completion.
    ///
    /// # Errors
    ///
    /// Rejects an observation before the claim was acquired.
    pub fn new(
        fence: SecretMutationRecoveryFence,
        recovered_at: UnixMillis,
        reconciliation: SecretMutationRecoveryReconciliation,
    ) -> Result<Self, SecretManagementValueError> {
        if recovered_at < fence.locked_at() {
            return Err(SecretManagementValueError::InvalidRecoveryTime);
        }
        Ok(Self {
            fence,
            recovered_at,
            reconciliation,
        })
    }

    /// Returns the exact claim fence.
    #[must_use]
    pub const fn fence(&self) -> &SecretMutationRecoveryFence {
        &self.fence
    }

    /// Returns the trusted terminal observation time.
    #[must_use]
    pub const fn recovered_at(&self) -> UnixMillis {
        self.recovered_at
    }

    /// Returns the value-free exact-provider reconciliation evidence.
    #[must_use]
    pub const fn reconciliation(&self) -> SecretMutationRecoveryReconciliation {
        self.reconciliation
    }
}

/// Closed value-free evidence from reconciling an expired provider create.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretMutationRecoveryReconciliation {
    /// The exact original create committed this immutable built-in version.
    AlreadyCommitted(BuiltinRepositorySecretVersion),
    /// The provider proved that the original create cannot commit later.
    DefinitivelyNotCommitted,
}

/// Closed result of claiming one due mutation reservation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)] // The claimed task retains the full durable create intent.
pub enum ClaimSecretMutationRecoveryOutcome {
    /// One exact mutation is fenced to this worker claim.
    Claimed(SecretMutationRecoveryTask),
    /// No due or stale recovery operation is available.
    NoWork,
}

/// Closed expired-reservation recovery result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoverSecretMutationReservationOutcome {
    /// The mutation expired before a provider candidate was durable.
    ExpiredWithoutStage,
    /// The mutation expired and one exact staged candidate was handed to erasure.
    ExpiredWithCleanup,
    /// A human or deletion transition terminalized the mutation first.
    AlreadyTerminal,
    /// A different replica claim owns the operation.
    FenceRejected,
    /// The recovery target is absent.
    NotFound,
}

/// Closed sanitized provider failure retained by cleanup scheduling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretCleanupFailureKind {
    InvalidRequest,
    Unsupported,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    Unavailable,
    IntegrityFailure,
    InvalidResponse,
}

/// Completes an exact claimed operation after the provider has erased its bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteBuiltinSecretCleanup {
    fence: SecretCleanupFence,
    completed_at: UnixMillis,
}

impl CompleteBuiltinSecretCleanup {
    /// Constructs a fenced completion.
    ///
    /// # Errors
    ///
    /// Rejects completion before the claim time.
    pub fn new(
        fence: SecretCleanupFence,
        completed_at: UnixMillis,
    ) -> Result<Self, SecretManagementValueError> {
        if completed_at < fence.locked_at() {
            return Err(SecretManagementValueError::InvalidCleanupTime);
        }
        Ok(Self {
            fence,
            completed_at,
        })
    }

    /// Returns the exact claim fence.
    #[must_use]
    pub const fn fence(&self) -> &SecretCleanupFence {
        &self.fence
    }

    /// Returns the completion time.
    #[must_use]
    pub const fn completed_at(&self) -> UnixMillis {
        self.completed_at
    }
}

/// Reschedules or dead-letters a fenced cleanup after a sanitized failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryBuiltinSecretCleanup {
    fence: SecretCleanupFence,
    failed_at: UnixMillis,
    retry_at: UnixMillis,
    failure_kind: SecretCleanupFailureKind,
}

impl RetryBuiltinSecretCleanup {
    /// Constructs a bounded retry decision.
    ///
    /// # Errors
    ///
    /// Rejects time regression, a non-future retry time, or a delay above the
    /// public cleanup retry bound.
    pub fn new(
        fence: SecretCleanupFence,
        failed_at: UnixMillis,
        retry_at: UnixMillis,
        failure_kind: SecretCleanupFailureKind,
    ) -> Result<Self, SecretManagementValueError> {
        let retry_delay = retry_at.get().checked_sub(failed_at.get());
        if failed_at < fence.locked_at()
            || retry_at <= failed_at
            || retry_delay
                .and_then(|delay| u64::try_from(delay).ok())
                .is_none_or(|delay| delay > MAX_SECRET_CLEANUP_RETRY_BACKOFF_MILLIS)
        {
            return Err(SecretManagementValueError::InvalidCleanupTime);
        }
        Ok(Self {
            fence,
            failed_at,
            retry_at,
            failure_kind,
        })
    }

    /// Returns the exact claim fence.
    #[must_use]
    pub const fn fence(&self) -> &SecretCleanupFence {
        &self.fence
    }

    /// Returns the observed failure time.
    #[must_use]
    pub const fn failed_at(&self) -> UnixMillis {
        self.failed_at
    }

    /// Returns the next eligible claim time.
    #[must_use]
    pub const fn retry_at(&self) -> UnixMillis {
        self.retry_at
    }

    /// Returns the closed failure classification.
    #[must_use]
    pub const fn failure_kind(&self) -> SecretCleanupFailureKind {
        self.failure_kind
    }
}

/// Closed claim result for the built-in provider cleanup worker.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)] // The claimed task retains its exact provider routing evidence.
pub enum ClaimBuiltinSecretCleanupOutcome {
    /// One exact task is fenced to this worker and lock timestamp.
    Claimed(BuiltinSecretCleanupTask),
    /// No ready built-in cleanup operation exists.
    NoWork,
}

/// Closed completion result that rejects stale worker acknowledgements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompleteBuiltinSecretCleanupOutcome {
    Completed,
    FenceRejected,
    NotFound,
    ProviderErasureIncomplete,
}

/// Closed retry result that makes terminal retry exhaustion explicit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryBuiltinSecretCleanupOutcome {
    RetryScheduled,
    DeadLettered,
    FenceRejected,
    NotFound,
}

/// Value-free read boundary used by operational repository-secret clients.
///
/// Every operation reauthenticates the exact session and authorization
/// revision inside the same transaction as its durable read. Exact repository
/// and secret lookups deliberately collapse missing and forbidden results.
#[async_trait]
pub trait RepositorySecretManagementReadRepository: std::fmt::Debug + Send + Sync {
    /// Resolves one GitHub repository only when metadata-read authority is current.
    async fn resolve_github_repository_secret_metadata(
        &self,
        request: ResolveGithubRepositorySecretMetadata,
    ) -> Result<ResolveGithubRepositorySecretMetadataOutcome, SecretManagementRepositoryError>;

    /// Looks up one exact repository secret without a value or provider handle.
    async fn get_repository_secret_metadata(
        &self,
        request: GetRepositorySecretMetadata,
    ) -> Result<GetRepositorySecretMetadataOutcome, SecretManagementRepositoryError>;

    /// Inspects redacted built-in provider state and atomic activation evidence.
    async fn inspect_builtin_secret_provider(
        &self,
        request: InspectBuiltinSecretProvider,
    ) -> Result<InspectBuiltinSecretProviderOutcome, SecretManagementRepositoryError>;
}

/// Backend-neutral repository-scoped secret management boundary.
#[async_trait]
pub trait RepositorySecretManagementRepository: std::fmt::Debug + Send + Sync {
    async fn activate_builtin_secret_provider(
        &self,
        request: ActivateBuiltinSecretProvider,
    ) -> Result<ActivateBuiltinSecretProviderOutcome, SecretManagementRepositoryError>;

    async fn list_repository_secrets(
        &self,
        request: ListRepositorySecrets,
    ) -> Result<ListRepositorySecretsOutcome, SecretManagementRepositoryError>;

    async fn reserve_repository_secret_version_mutation(
        &self,
        request: ReserveRepositorySecretVersionMutation,
    ) -> Result<ReserveRepositorySecretVersionMutationOutcome, SecretManagementRepositoryError>;

    async fn confirm_repository_secret_version_mutation(
        &self,
        request: ConfirmRepositorySecretVersionMutation,
    ) -> Result<ConfirmRepositorySecretVersionMutationOutcome, SecretManagementRepositoryError>;

    async fn delete_repository_secret(
        &self,
        request: DeleteRepositorySecret,
    ) -> Result<DeleteRepositorySecretOutcome, SecretManagementRepositoryError>;
}

/// Built-in provider cleanup outbox boundary.
#[async_trait]
pub trait BuiltinSecretCleanupRepository: std::fmt::Debug + Send + Sync {
    async fn claim_builtin_secret_cleanup(
        &self,
        request: ClaimBuiltinSecretCleanup,
    ) -> Result<ClaimBuiltinSecretCleanupOutcome, SecretManagementRepositoryError>;

    async fn complete_builtin_secret_cleanup(
        &self,
        request: CompleteBuiltinSecretCleanup,
    ) -> Result<CompleteBuiltinSecretCleanupOutcome, SecretManagementRepositoryError>;

    async fn retry_builtin_secret_cleanup(
        &self,
        request: RetryBuiltinSecretCleanup,
    ) -> Result<RetryBuiltinSecretCleanupOutcome, SecretManagementRepositoryError>;
}

/// Durable value-free reconciliation boundary for abandoned reservations.
#[async_trait]
pub trait SecretMutationRecoveryRepository: std::fmt::Debug + Send + Sync {
    /// Claims one due reservation or stale recovery generation.
    async fn claim_secret_mutation_recovery(
        &self,
        request: ClaimSecretMutationRecovery,
    ) -> Result<ClaimSecretMutationRecoveryOutcome, SecretManagementRepositoryError>;

    /// Cross-checks provider evidence, cancels the exact reservation, and atomically hands any
    /// staged winner to erasure.
    async fn recover_secret_mutation_reservation(
        &self,
        request: RecoverSecretMutationReservation,
    ) -> Result<RecoverSecretMutationReservationOutcome, SecretManagementRepositoryError>;
}

/// Sanitized persistence failure with no backend query text, value, locator, or handle.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SecretManagementRepositoryError {
    #[error("secret management request is invalid")]
    InvalidRequest,
    #[error("secret management storage is unavailable")]
    Unavailable,
    #[error("durable secret management data violates an invariant")]
    CorruptData,
}

/// Closed local validation failure for secret management request values.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SecretManagementValueError {
    #[error("logical secret ID must be non-nil")]
    NilSecretId,
    #[error("secret mutation ID must be non-nil")]
    NilMutationId,
    #[error("secret mutation ID must differ from the logical secret ID")]
    MutationIdReusesSecretId,
    #[error("secret version ID must be non-nil")]
    NilVersionId,
    #[error("secret version number must be positive")]
    InvalidVersionNumber,
    #[error("repository ID must be non-nil")]
    NilRepositoryId,
    #[error("secret name is invalid")]
    InvalidSecretName,
    #[error("secret name uses a reserved platform prefix")]
    ReservedSecretName,
    #[error("secret provider ID is invalid")]
    InvalidProviderId,
    #[error("secret metadata page size is invalid")]
    InvalidPageSize,
    #[error("secret cleanup worker ID is invalid")]
    InvalidCleanupWorkerId,
    #[error("secret cleanup time is invalid")]
    InvalidCleanupTime,
    #[error("secret mutation recovery time is invalid")]
    InvalidRecoveryTime,
}

fn require_repository(repository_id: RepositoryId) -> Result<(), SecretManagementValueError> {
    if repository_id.as_uuid().is_nil() {
        return Err(SecretManagementValueError::NilRepositoryId);
    }
    Ok(())
}

fn require_mutation_for_secret(
    mutation_id: RepositorySecretMutationId,
    secret_id: RepositorySecretId,
) -> Result<(), SecretManagementValueError> {
    if mutation_id.as_uuid() == secret_id.as_uuid() {
        return Err(SecretManagementValueError::MutationIdReusesSecretId);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use automata_ci_auth::{
        human::{PrincipalId, TenantId},
        management::{ManagementActor, ManagementRevision},
        session::SessionId,
        time::UnixTimestamp,
    };

    use super::*;

    fn actor() -> ManagementActor {
        ManagementActor::new(
            TenantId::new("tenant-a").unwrap(),
            PrincipalId::new("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
            SessionId::new("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").unwrap(),
            ManagementRevision::new(1).unwrap(),
            None,
            UnixTimestamp::from_seconds(1),
        )
    }

    #[test]
    fn names_are_canonical_and_platform_names_are_reserved() {
        assert_eq!(
            RepositorySecretName::new("release_token").unwrap().as_str(),
            "RELEASE_TOKEN"
        );
        assert!(matches!(
            RepositorySecretName::new("github_token"),
            Err(SecretManagementValueError::ReservedSecretName)
        ));
        assert!(RepositorySecretName::new("9TOKEN").is_err());
        assert!(RepositorySecretName::new("TOKEN-DASH").is_err());
    }

    #[test]
    fn identifiers_and_page_bounds_fail_closed() {
        assert!(RepositorySecretId::from_uuid(Uuid::nil()).is_err());
        assert!(SecretMetadataPageSize::new(0).is_err());
        assert!(SecretMetadataPageSize::new(100).is_ok());
        assert!(SecretMetadataPageSize::new(101).is_err());
        assert!(ManagedSecretProviderId::new("vault.prod").is_ok());
        assert!(ManagedSecretProviderId::new("Vault").is_err());
        assert!(SecretCleanupWorkerId::new("worker\nvalue").is_err());
    }

    #[test]
    fn activation_evidence_is_revision_bound_and_only_for_non_active_managers() {
        let revision = ManagementRevision::new(7).unwrap();
        let available = BuiltinSecretProviderInspection::from_durable_parts(
            BuiltinSecretProviderState::Unconfigured,
            BuiltinSecretProviderHealth::Unknown,
            revision,
            true,
        );
        assert_eq!(available.revision(), revision);
        assert_eq!(
            available
                .activation()
                .expect("authorized non-active provider")
                .expected_revision(),
            revision
        );
        let active = BuiltinSecretProviderInspection::from_durable_parts(
            BuiltinSecretProviderState::Active,
            BuiltinSecretProviderHealth::Healthy,
            revision,
            true,
        );
        assert!(active.activation().is_none());
        let unauthorized = BuiltinSecretProviderInspection::from_durable_parts(
            BuiltinSecretProviderState::Disabled,
            BuiltinSecretProviderHealth::Unavailable,
            revision,
            false,
        );
        assert!(unauthorized.activation().is_none());
    }

    #[test]
    fn creation_boundary_has_no_plaintext_or_provider_handle() {
        let secret_id = RepositorySecretId::from_uuid(Uuid::new_v4()).unwrap();
        let repository_id = RepositoryId::from_uuid(Uuid::new_v4());
        let mutation_id = RepositorySecretMutationId::from_uuid(Uuid::new_v4(), secret_id).unwrap();
        let request = ReserveRepositorySecretVersionMutation::create(
            actor(),
            mutation_id,
            secret_id,
            repository_id,
            RepositorySecretName::new("DEPLOY_TOKEN").unwrap(),
            None,
        )
        .unwrap();
        let debug = format!("{request:?}");
        assert!(debug.contains("DEPLOY_TOKEN"));
        assert!(!debug.contains("value"));
        assert!(!debug.contains("locator"));
        assert!(!debug.contains("handle"));
    }

    #[test]
    fn cleanup_time_and_fence_are_monotonic() {
        let worker = SecretCleanupWorkerId::new("cleanup-a").unwrap();
        let fence = SecretCleanupFence::new(Uuid::new_v4(), worker.clone(), 1, UnixMillis::new(10));
        assert!(CompleteBuiltinSecretCleanup::new(fence.clone(), UnixMillis::new(9)).is_err());
        let maximum_retry_at = 10 + i64::try_from(MAX_SECRET_CLEANUP_RETRY_BACKOFF_MILLIS).unwrap();
        assert!(
            RetryBuiltinSecretCleanup::new(
                fence.clone(),
                UnixMillis::new(10),
                UnixMillis::new(maximum_retry_at),
                SecretCleanupFailureKind::Unavailable,
            )
            .is_ok()
        );
        assert!(
            RetryBuiltinSecretCleanup::new(
                fence,
                UnixMillis::new(10),
                UnixMillis::new(maximum_retry_at + 1),
                SecretCleanupFailureKind::Unavailable,
            )
            .is_err()
        );
        assert!(
            ClaimBuiltinSecretCleanup::new(
                worker.clone(),
                UnixMillis::new(0),
                MAX_SECRET_CLEANUP_CLAIM_MILLIS,
            )
            .is_ok()
        );
        assert!(
            ClaimBuiltinSecretCleanup::new(
                worker,
                UnixMillis::new(0),
                MAX_SECRET_CLEANUP_CLAIM_MILLIS + 1,
            )
            .is_err()
        );
    }

    #[test]
    fn repository_and_cleanup_ports_are_object_safe() {
        fn accepts_management(_: &dyn RepositorySecretManagementRepository) {}
        fn accepts_management_reads(_: &dyn RepositorySecretManagementReadRepository) {}
        fn accepts_cleanup(_: &dyn BuiltinSecretCleanupRepository) {}
        let _ = (
            accepts_management,
            accepts_management_reads,
            accepts_cleanup,
        );
    }
}
