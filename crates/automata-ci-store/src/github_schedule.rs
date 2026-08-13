//! Durable, revision-pinned scheduled-workflow discovery and fire fencing.

use std::fmt;

use async_trait::async_trait;
use automata_ci_core::{RunId, Sha256Digest, UnixMillis};
use automata_ci_schedule::{CronExpression, validate_iana_timezone};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    GithubCheckSubjectKey, GithubCheckSubjectReceipt, GithubProviderManifest,
    GithubServerServiceAuthoritySelector, ObjectKey, ProviderConnectionId,
    ProviderRepositoryOwnerId, ProviderRepositoryVisibility, RepositoryId, StoreError, TenantScope,
};

/// Exact media type retained for one immutable gzip repository archive.
pub const GITHUB_SCHEDULE_ARCHIVE_MEDIA_TYPE: &str =
    "application/vnd.automata.github-repository-archive+gzip";
/// Explicit Automata-owned actor for non-webhook scheduled invocations.
///
/// GitHub's last-modifier and suspended-user semantics cannot be proven from
/// the schedule registry. Automata therefore identifies its own scheduler and
/// never fabricates a provider user.
pub const GITHUB_SCHEDULE_SERVICE_ACTOR: &str = "automata-scheduler";
/// Terminal reason used when retained registry evidence cannot be evaluated.
pub const GITHUB_SCHEDULE_INVALID_REGISTRY_FAILURE: &str = "github.schedule.registry_invalid";
/// Terminal reason recorded after the final bounded fire attempt is exhausted.
pub const GITHUB_SCHEDULE_ATTEMPTS_EXHAUSTED_FAILURE: &str = "github.schedule.attempts_exhausted";
/// Maximum schedule entries retained by one registry revision.
pub const MAX_GITHUB_REGISTERED_SCHEDULES: usize = 256;
/// Maximum attempts for one due fire before terminal failure.
pub const MAX_GITHUB_SCHEDULE_FIRE_ATTEMPTS: u16 = 20;
/// Maximum lease interval requested when schedule work is claimed or renewed.
pub const MAX_GITHUB_SCHEDULE_CLAIM_MILLIS: i64 = 5 * 60 * 1_000;
/// Maximum retry delay for one fire.
pub const MAX_GITHUB_SCHEDULE_RETRY_MILLIS: i64 = 24 * 60 * 60 * 1_000;

// foundation-governance: derived-contract owner=store kind=digest-domain
const ENTRY_DIGEST_DOMAIN: &[u8] = b"automata.store.github-schedule-entry.v1\0";
// foundation-governance: derived-contract owner=store kind=digest-domain
const INVENTORY_DIGEST_DOMAIN: &[u8] = b"automata.store.github-schedule-inventory.v1\0";
const MAX_ARCHIVE_BYTES: u64 = 256 * 1_024 * 1_024;
const MAX_OBJECT_KEY_BYTES: usize = 1_024;
const MAX_FAILURE_KIND_BYTES: usize = 128;

macro_rules! uuid_identity {
    ($(#[$meta:meta])* $name:ident, $error:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            /// Constructs a non-nil durable identity.
            ///
            /// # Errors
            ///
            /// Rejects the nil UUID sentinel.
            pub fn from_uuid(value: Uuid) -> Result<Self, GithubScheduleValueError> {
                if value.is_nil() {
                    return Err(GithubScheduleValueError::$error);
                }
                Ok(Self(value))
            }

            /// Returns the underlying UUID.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }
    };
}

uuid_identity!(/// Immutable schedule registry revision identity.
    GithubScheduleRegistryId, InvalidRegistryId);
uuid_identity!(/// Durable identity of one exact due fire.
    GithubScheduleFireId, InvalidFireId);
uuid_identity!(/// Durable scheduler worker identity.
    GithubScheduleWorkerId, InvalidWorkerId);

/// Positive monotonically increasing claim fence for one fire.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubScheduleClaimFence(u64);

impl GithubScheduleClaimFence {
    /// Rehydrates a positive fence representable by `BIGINT`.
    ///
    /// # Errors
    ///
    /// Rejects zero or a value larger than `i64::MAX`.
    pub fn new(value: u64) -> Result<Self, GithubScheduleValueError> {
        if value == 0 || i64::try_from(value).is_err() {
            return Err(GithubScheduleValueError::InvalidClaimFence);
        }
        Ok(Self(value))
    }

    /// Returns the positive fence value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Bounded immutable archive descriptor used for registry replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubScheduleArchive {
    digest: Sha256Digest,
    object_key: ObjectKey,
    encoded_size: u64,
}

impl GithubScheduleArchive {
    /// Creates one exact repository archive descriptor.
    ///
    /// # Errors
    ///
    /// Rejects empty, excessive, or non-canonical object metadata.
    pub fn new(
        digest: Sha256Digest,
        object_key: ObjectKey,
        encoded_size: u64,
    ) -> Result<Self, GithubScheduleValueError> {
        if encoded_size == 0
            || encoded_size > MAX_ARCHIVE_BYTES
            || object_key.as_str().len() > MAX_OBJECT_KEY_BYTES
        {
            return Err(GithubScheduleValueError::InvalidArchive);
        }
        Ok(Self {
            digest,
            object_key,
            encoded_size,
        })
    }

    /// Returns the exact archive digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Returns the credential-free immutable object key.
    #[must_use]
    pub const fn object_key(&self) -> &ObjectKey {
        &self.object_key
    }

    /// Returns the encoded archive size.
    #[must_use]
    pub const fn encoded_size(&self) -> u64 {
        self.encoded_size
    }

    /// Returns the fixed archive media type.
    #[must_use]
    pub const fn media_type(&self) -> &'static str {
        GITHUB_SCHEDULE_ARCHIVE_MEDIA_TYPE
    }
}

/// One canonical validated schedule entry and its first due instant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubScheduleRegistryEntry {
    ordinal: u16,
    workflow_path: GithubCheckSubjectKey,
    workflow_source_digest: Sha256Digest,
    schedule_ordinal: u16,
    cron_expression: String,
    timezone: String,
    entry_digest: Sha256Digest,
    next_fire_at: UnixMillis,
}

/// Fenced discovery lease used to resolve one exact default-branch archive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubScheduleDiscoveryClaim {
    registry_id: GithubScheduleRegistryId,
    worker_id: GithubScheduleWorkerId,
    fence: GithubScheduleClaimFence,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl GithubScheduleDiscoveryClaim {
    /// Rehydrates one exact live discovery claim.
    ///
    /// # Errors
    ///
    /// Rejects a non-positive or excessive lease interval.
    pub fn from_durable_parts(
        registry_id: GithubScheduleRegistryId,
        worker_id: GithubScheduleWorkerId,
        fence: GithubScheduleClaimFence,
        claimed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, GithubScheduleValueError> {
        if claimed_at.get() < 0
            || expires_at <= claimed_at
            || expires_at.get() - claimed_at.get() > MAX_GITHUB_SCHEDULE_CLAIM_MILLIS
        {
            return Err(GithubScheduleValueError::InvalidClaim);
        }
        Ok(Self {
            registry_id,
            worker_id,
            fence,
            claimed_at,
            expires_at,
        })
    }

    /// Returns the proposed registry/discovery identity.
    #[must_use]
    pub const fn registry_id(self) -> GithubScheduleRegistryId {
        self.registry_id
    }

    /// Returns the owning scheduler worker.
    #[must_use]
    pub const fn worker_id(self) -> GithubScheduleWorkerId {
        self.worker_id
    }

    /// Returns the monotonic discovery fence.
    #[must_use]
    pub const fn fence(self) -> GithubScheduleClaimFence {
        self.fence
    }

    /// Returns the authoritative claim instant.
    #[must_use]
    pub const fn claimed_at(self) -> UnixMillis {
        self.claimed_at
    }

    /// Returns the exclusive discovery lease expiry.
    #[must_use]
    pub const fn expires_at(self) -> UnixMillis {
        self.expires_at
    }
}

/// Closed source-read authority retained with one discovered repository archive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GithubScheduleSourceAuthority {
    /// A public repository archive fetched without a provider credential.
    PublicAnonymous,
    /// An exact least-authority `contents:read` descriptor for a private repository.
    Private(GithubServerServiceAuthoritySelector),
}

impl GithubScheduleSourceAuthority {
    /// Returns the private source-authority selector when one is required.
    #[must_use]
    pub const fn private_selector(&self) -> Option<&GithubServerServiceAuthoritySelector> {
        match self {
            Self::PublicAnonymous => None,
            Self::Private(selector) => Some(selector),
        }
    }

    /// Returns the durable closed discriminator.
    #[must_use]
    pub const fn as_durable_str(&self) -> &'static str {
        match self {
            Self::PublicAnonymous => "public_anonymous",
            Self::Private(_) => "private_repository_source_read",
        }
    }

    // This is only the compatibility check possible from a value-free
    // selector. The repository resolves the selector and verifies its exact
    // repository, connection, installation, App, source-read scope, identity
    // digest, and lifecycle before admitting either discovery or registration.
    fn is_structurally_compatible_with(&self, manifest: &GithubProviderManifest) -> bool {
        match (manifest.repository_visibility(), self) {
            (ProviderRepositoryVisibility::Public, Self::PublicAnonymous) => true,
            (ProviderRepositoryVisibility::Private, Self::Private(selector)) => {
                selector.tenant() == manifest.tenant()
                    && selector.app_configuration_revision()
                        == manifest.app_configuration_revision()
                    && selector.policy_revision() == manifest.policy_revision()
            }
            _ => false,
        }
    }
}

/// Bounded request to claim one manifest-pinned schedule discovery session.
#[derive(Clone, Debug)]
pub struct ClaimGithubScheduleDiscovery {
    registry_id: GithubScheduleRegistryId,
    manifest: GithubProviderManifest,
    repository_owner_id: ProviderRepositoryOwnerId,
    source_authority: GithubScheduleSourceAuthority,
    worker_id: GithubScheduleWorkerId,
    lease_millis: i64,
}

impl ClaimGithubScheduleDiscovery {
    /// Creates one exact discovery claim request.
    ///
    /// # Errors
    ///
    /// Rejects an authority mode, tenant, or revision incompatible with the
    /// manifest, or an invalid lease. The repository additionally resolves a
    /// private selector and verifies its complete identity and source-read
    /// scope before issuing a claim.
    pub fn new(
        registry_id: GithubScheduleRegistryId,
        manifest: GithubProviderManifest,
        repository_owner_id: ProviderRepositoryOwnerId,
        source_authority: GithubScheduleSourceAuthority,
        worker_id: GithubScheduleWorkerId,
        lease_millis: i64,
    ) -> Result<Self, GithubScheduleValueError> {
        if manifest.github_repository_owner_id() != Some(repository_owner_id) {
            return Err(GithubScheduleValueError::RepositoryOwnerMismatch);
        }
        if !source_authority.is_structurally_compatible_with(&manifest) {
            return Err(GithubScheduleValueError::InvalidSourceAuthority);
        }
        if lease_millis <= 0 || lease_millis > MAX_GITHUB_SCHEDULE_CLAIM_MILLIS {
            return Err(GithubScheduleValueError::InvalidLease);
        }
        Ok(Self {
            registry_id,
            manifest,
            repository_owner_id,
            source_authority,
            worker_id,
            lease_millis,
        })
    }

    /// Returns the proposed registry/discovery identity.
    #[must_use]
    pub const fn registry_id(&self) -> GithubScheduleRegistryId {
        self.registry_id
    }

    /// Returns the exact current manifest to resolve.
    #[must_use]
    pub const fn manifest(&self) -> &GithubProviderManifest {
        &self.manifest
    }

    /// Returns the provider-stable numeric repository owner.
    #[must_use]
    pub const fn repository_owner_id(&self) -> ProviderRepositoryOwnerId {
        self.repository_owner_id
    }

    /// Returns the closed public/private source authority.
    #[must_use]
    pub const fn source_authority(&self) -> &GithubScheduleSourceAuthority {
        &self.source_authority
    }

    /// Returns the claiming worker.
    #[must_use]
    pub const fn worker_id(&self) -> GithubScheduleWorkerId {
        self.worker_id
    }

    /// Returns the bounded lease duration.
    #[must_use]
    pub const fn lease_millis(&self) -> i64 {
        self.lease_millis
    }
}

impl GithubScheduleRegistryEntry {
    /// Constructs one source-bound schedule entry.
    ///
    /// # Errors
    ///
    /// Rejects invalid bounds, text, or a negative next-fire instant.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ordinal: u16,
        workflow_path: GithubCheckSubjectKey,
        workflow_source_digest: Sha256Digest,
        schedule_ordinal: u16,
        cron_expression: impl Into<String>,
        timezone: impl Into<String>,
        next_fire_at: UnixMillis,
    ) -> Result<Self, GithubScheduleValueError> {
        let cron_expression = cron_expression.into();
        let timezone = timezone.into();
        if usize::from(ordinal) >= MAX_GITHUB_REGISTERED_SCHEDULES
            || schedule_ordinal >= 64
            || next_fire_at.get() < 0
            || CronExpression::parse(&cron_expression).is_err()
            || validate_iana_timezone(&timezone).is_err()
        {
            return Err(GithubScheduleValueError::InvalidEntry);
        }
        let entry_digest = schedule_entry_digest(
            workflow_path.as_str(),
            workflow_source_digest,
            schedule_ordinal,
            &cron_expression,
            &timezone,
        );
        Ok(Self {
            ordinal,
            workflow_path,
            workflow_source_digest,
            schedule_ordinal,
            cron_expression,
            timezone,
            entry_digest,
            next_fire_at,
        })
    }

    /// Returns the registry-wide canonical ordinal.
    #[must_use]
    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }

    /// Returns the canonical direct workflow path.
    #[must_use]
    pub fn workflow_path(&self) -> &str {
        self.workflow_path.as_str()
    }

    /// Returns the exact workflow source digest.
    #[must_use]
    pub const fn workflow_source_digest(&self) -> Sha256Digest {
        self.workflow_source_digest
    }

    /// Returns the zero-based schedule ordinal within the workflow.
    #[must_use]
    pub const fn schedule_ordinal(&self) -> u16 {
        self.schedule_ordinal
    }

    /// Returns the exact decoded cron expression.
    #[must_use]
    pub fn cron_expression(&self) -> &str {
        &self.cron_expression
    }

    /// Returns the exact validated IANA timezone.
    #[must_use]
    pub fn timezone(&self) -> &str {
        &self.timezone
    }

    /// Returns the domain-separated entry digest.
    #[must_use]
    pub const fn entry_digest(&self) -> Sha256Digest {
        self.entry_digest
    }

    /// Returns the first due instant strictly after discovery.
    #[must_use]
    pub const fn next_fire_at(&self) -> UnixMillis {
        self.next_fire_at
    }
}

/// Atomic registration of one exact default-branch schedule inventory.
#[derive(Clone, Debug)]
pub struct RegisterGithubScheduleRegistry {
    registry_id: GithubScheduleRegistryId,
    discovery_claim: GithubScheduleDiscoveryClaim,
    manifest: GithubProviderManifest,
    repository_owner_id: ProviderRepositoryOwnerId,
    source_authority: GithubScheduleSourceAuthority,
    source_revision: String,
    archive: GithubScheduleArchive,
    inventory_digest: Sha256Digest,
    entries: Vec<GithubScheduleRegistryEntry>,
}

impl RegisterGithubScheduleRegistry {
    /// Constructs a canonical registry revision.
    ///
    /// # Errors
    ///
    /// Rejects a source-authority mode, tenant, or revision incompatible with
    /// the pinned manifest, a non-SHA revision, excessive entries,
    /// non-contiguous ordinals, inconsistent source digests for one workflow,
    /// non-canonical ordering and duplicates, or any first-fire cursor that is
    /// not the exact first cron occurrence strictly after discovery. The
    /// repository resolves and fully verifies a private source-authority
    /// selector before persistence.
    pub fn new(
        discovery_claim: GithubScheduleDiscoveryClaim,
        manifest: GithubProviderManifest,
        source_authority: GithubScheduleSourceAuthority,
        source_revision: impl Into<String>,
        archive: GithubScheduleArchive,
        entries: Vec<GithubScheduleRegistryEntry>,
    ) -> Result<Self, GithubScheduleValueError> {
        let source_revision = source_revision.into();
        let Some(repository_owner_id) = manifest.github_repository_owner_id() else {
            return Err(GithubScheduleValueError::RepositoryOwnerMismatch);
        };
        if !valid_sha1(&source_revision)
            || !source_authority.is_structurally_compatible_with(&manifest)
            || entries.len() > MAX_GITHUB_REGISTERED_SCHEDULES
            || !entries_are_canonical(&entries)
            || !entries_match_discovery_first_fire(&entries, discovery_claim.claimed_at())
        {
            return Err(GithubScheduleValueError::InvalidRegistry);
        }
        let registry_id = discovery_claim.registry_id();
        let inventory_digest = schedule_inventory_digest(&entries);
        Ok(Self {
            registry_id,
            discovery_claim,
            manifest,
            repository_owner_id,
            source_authority,
            source_revision,
            archive,
            inventory_digest,
            entries,
        })
    }

    /// Returns the proposed immutable registry identity.
    #[must_use]
    pub const fn registry_id(&self) -> GithubScheduleRegistryId {
        self.registry_id
    }

    /// Returns the exact live discovery claim that must be consumed atomically.
    #[must_use]
    pub const fn discovery_claim(&self) -> GithubScheduleDiscoveryClaim {
        self.discovery_claim
    }

    /// Returns the exact historical provider manifest.
    #[must_use]
    pub const fn manifest(&self) -> &GithubProviderManifest {
        &self.manifest
    }

    /// Returns the provider-stable numeric owner resolved with the exact source revision.
    #[must_use]
    pub const fn repository_owner_id(&self) -> ProviderRepositoryOwnerId {
        self.repository_owner_id
    }

    /// Returns the exact public/private source-read authority used for discovery.
    #[must_use]
    pub const fn source_authority(&self) -> &GithubScheduleSourceAuthority {
        &self.source_authority
    }

    /// Returns the exact 40-character lowercase source SHA.
    #[must_use]
    pub fn source_revision(&self) -> &str {
        &self.source_revision
    }

    /// Returns the immutable repository archive descriptor.
    #[must_use]
    pub const fn archive(&self) -> &GithubScheduleArchive {
        &self.archive
    }

    /// Returns the canonical digest of the ordered schedule definitions.
    ///
    /// First-fire timestamps are runtime cursors and deliberately do not alter
    /// this source-inventory identity. The registry's manifest, source
    /// revision, archive, and authority remain separately exact evidence.
    #[must_use]
    pub const fn inventory_digest(&self) -> Sha256Digest {
        self.inventory_digest
    }

    /// Returns canonical entries in path and source order.
    #[must_use]
    pub fn entries(&self) -> &[GithubScheduleRegistryEntry] {
        &self.entries
    }
}

/// Stable receipt for registry activation or an exact replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubScheduleRegistryReceipt {
    registry_id: GithubScheduleRegistryId,
    registered_at: UnixMillis,
    replayed: bool,
}

impl GithubScheduleRegistryReceipt {
    /// Rehydrates a checked repository receipt.
    #[must_use]
    pub const fn from_durable_parts(
        registry_id: GithubScheduleRegistryId,
        registered_at: UnixMillis,
        replayed: bool,
    ) -> Self {
        Self {
            registry_id,
            registered_at,
            replayed,
        }
    }

    /// Returns the immutable registry identity.
    #[must_use]
    pub const fn registry_id(self) -> GithubScheduleRegistryId {
        self.registry_id
    }

    /// Returns the authoritative database registration time.
    #[must_use]
    pub const fn registered_at(self) -> UnixMillis {
        self.registered_at
    }

    /// Reports an exact durable replay.
    #[must_use]
    pub const fn is_replay(self) -> bool {
        self.replayed
    }
}

/// Bounded request to claim one due schedule fire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimDueGithubScheduleFire {
    worker_id: GithubScheduleWorkerId,
    lease_millis: i64,
}

impl ClaimDueGithubScheduleFire {
    /// Creates a due-fire claim policy.
    ///
    /// # Errors
    ///
    /// Rejects a non-positive or excessive lease.
    pub fn new(
        worker_id: GithubScheduleWorkerId,
        lease_millis: i64,
    ) -> Result<Self, GithubScheduleValueError> {
        if lease_millis <= 0 || lease_millis > MAX_GITHUB_SCHEDULE_CLAIM_MILLIS {
            return Err(GithubScheduleValueError::InvalidLease);
        }
        Ok(Self {
            worker_id,
            lease_millis,
        })
    }

    /// Returns the claiming worker.
    #[must_use]
    pub const fn worker_id(self) -> GithubScheduleWorkerId {
        self.worker_id
    }

    /// Returns the requested lease duration.
    #[must_use]
    pub const fn lease_millis(self) -> i64 {
        self.lease_millis
    }
}

/// Exact fenced claim snapshot used by every mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubScheduleFireClaim {
    fire_id: GithubScheduleFireId,
    worker_id: GithubScheduleWorkerId,
    attempt: u16,
    fence: GithubScheduleClaimFence,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl GithubScheduleFireClaim {
    /// Rehydrates a checked live claim.
    ///
    /// # Errors
    ///
    /// Rejects an invalid attempt, a negative original claim instant, or
    /// non-increasing lease timestamps. A renewed snapshot may legitimately
    /// extend more than one maximum lease interval beyond its original
    /// `claimed_at`; each renewal request is bounded by the repository.
    pub fn from_durable_parts(
        fire_id: GithubScheduleFireId,
        worker_id: GithubScheduleWorkerId,
        attempt: u16,
        fence: GithubScheduleClaimFence,
        claimed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, GithubScheduleValueError> {
        if attempt == 0
            || attempt > MAX_GITHUB_SCHEDULE_FIRE_ATTEMPTS
            || claimed_at.get() < 0
            || expires_at <= claimed_at
        {
            return Err(GithubScheduleValueError::InvalidClaim);
        }
        Ok(Self {
            fire_id,
            worker_id,
            attempt,
            fence,
            claimed_at,
            expires_at,
        })
    }

    /// Returns the exact fire identity.
    #[must_use]
    pub const fn fire_id(self) -> GithubScheduleFireId {
        self.fire_id
    }

    /// Returns the exact worker identity.
    #[must_use]
    pub const fn worker_id(self) -> GithubScheduleWorkerId {
        self.worker_id
    }

    /// Returns the positive attempt number.
    #[must_use]
    pub const fn attempt(self) -> u16 {
        self.attempt
    }

    /// Returns the monotonically increasing fence.
    #[must_use]
    pub const fn fence(self) -> GithubScheduleClaimFence {
        self.fence
    }

    /// Returns the authoritative claim time.
    #[must_use]
    pub const fn claimed_at(self) -> UnixMillis {
        self.claimed_at
    }

    /// Returns the current lease expiry.
    #[must_use]
    pub const fn expires_at(self) -> UnixMillis {
        self.expires_at
    }
}

/// Complete immutable evidence for one claimed due schedule fire.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedGithubScheduleFire {
    claim: GithubScheduleFireClaim,
    tenant: TenantScope,
    repository_id: RepositoryId,
    provider_repository_id: String,
    repository_owner: String,
    repository_name: String,
    connection_id: ProviderConnectionId,
    registry_id: GithubScheduleRegistryId,
    source_revision: String,
    default_branch_ref: String,
    archive: GithubScheduleArchive,
    entry: GithubScheduleRegistryEntry,
    scheduled_at: UnixMillis,
}

impl ClaimedGithubScheduleFire {
    /// Rehydrates a complete checked claim from durable rows.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn from_durable_parts(
        claim: GithubScheduleFireClaim,
        tenant: TenantScope,
        repository_id: RepositoryId,
        provider_repository_id: String,
        repository_owner: String,
        repository_name: String,
        connection_id: ProviderConnectionId,
        registry_id: GithubScheduleRegistryId,
        source_revision: String,
        default_branch_ref: String,
        archive: GithubScheduleArchive,
        entry: GithubScheduleRegistryEntry,
        scheduled_at: UnixMillis,
    ) -> Self {
        Self {
            claim,
            tenant,
            repository_id,
            provider_repository_id,
            repository_owner,
            repository_name,
            connection_id,
            registry_id,
            source_revision,
            default_branch_ref,
            archive,
            entry,
            scheduled_at,
        }
    }

    /// Returns the exact live claim.
    #[must_use]
    pub const fn claim(&self) -> GithubScheduleFireClaim {
        self.claim
    }

    /// Returns the tenant scope.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }

    /// Returns the server-owned repository identity.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Returns the stable provider repository identifier.
    #[must_use]
    pub fn provider_repository_id(&self) -> &str {
        &self.provider_repository_id
    }

    /// Returns the configured repository owner.
    #[must_use]
    pub fn repository_owner(&self) -> &str {
        &self.repository_owner
    }

    /// Returns the configured repository name.
    #[must_use]
    pub fn repository_name(&self) -> &str {
        &self.repository_name
    }

    /// Returns the provider connection identity.
    #[must_use]
    pub const fn connection_id(&self) -> ProviderConnectionId {
        self.connection_id
    }

    /// Returns the immutable registry revision.
    #[must_use]
    pub const fn registry_id(&self) -> GithubScheduleRegistryId {
        self.registry_id
    }

    /// Returns the exact immutable source SHA.
    #[must_use]
    pub fn source_revision(&self) -> &str {
        &self.source_revision
    }

    /// Returns the configured full default-branch ref.
    #[must_use]
    pub fn default_branch_ref(&self) -> &str {
        &self.default_branch_ref
    }

    /// Returns the immutable repository archive descriptor.
    #[must_use]
    pub const fn archive(&self) -> &GithubScheduleArchive {
        &self.archive
    }

    /// Returns the selected schedule entry.
    #[must_use]
    pub const fn entry(&self) -> &GithubScheduleRegistryEntry {
        &self.entry
    }

    /// Returns the exact due instant represented by this fire.
    #[must_use]
    pub const fn scheduled_at(&self) -> UnixMillis {
        self.scheduled_at
    }
}

/// Terminal outcome for one exact scheduled invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GithubScheduleFireConclusion {
    /// A workflow run was admitted or exactly replayed.
    Admitted(RunId),
    /// The pinned source no longer selected this exact cron entry.
    Skipped(String),
    /// A deterministic failure prevents this occurrence from running.
    Failed(String),
}

/// Fenced terminal completion that also advances the current entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteGithubScheduleFire {
    claim: GithubScheduleFireClaim,
    conclusion: GithubScheduleFireConclusion,
    next_fire_at: Option<UnixMillis>,
}

impl CompleteGithubScheduleFire {
    /// Constructs a terminal completion.
    ///
    /// # Errors
    ///
    /// Rejects an invalid failure kind or a negative next occurrence. The
    /// repository additionally checks that the occurrence is strictly later
    /// than the durable scheduled instant; that instant is intentionally not
    /// approximated with the claim timestamp because delayed fires may retain
    /// catch-up occurrences.
    pub fn new(
        claim: GithubScheduleFireClaim,
        conclusion: GithubScheduleFireConclusion,
        next_fire_at: UnixMillis,
    ) -> Result<Self, GithubScheduleValueError> {
        if next_fire_at.get() < 0
            || match &conclusion {
                GithubScheduleFireConclusion::Admitted(_) => false,
                GithubScheduleFireConclusion::Skipped(kind)
                | GithubScheduleFireConclusion::Failed(kind) => !valid_failure_kind(kind),
            }
        {
            return Err(GithubScheduleValueError::InvalidConclusion);
        }
        Ok(Self {
            claim,
            conclusion,
            next_fire_at: Some(next_fire_at),
        })
    }

    /// Constructs a fail-closed terminalization that disables this registry entry.
    ///
    /// This path is deliberately limited to malformed retained registry
    /// evidence. Ordinary workflow failures must advance to their next
    /// calendar occurrence through [`Self::new`].
    #[must_use]
    pub fn invalid_registry(claim: GithubScheduleFireClaim) -> Self {
        Self {
            claim,
            conclusion: GithubScheduleFireConclusion::Failed(
                GITHUB_SCHEDULE_INVALID_REGISTRY_FAILURE.to_owned(),
            ),
            next_fire_at: None,
        }
    }

    /// Returns the exact claim to fence.
    #[must_use]
    pub const fn claim(&self) -> GithubScheduleFireClaim {
        self.claim
    }

    /// Returns the terminal outcome.
    #[must_use]
    pub const fn conclusion(&self) -> &GithubScheduleFireConclusion {
        &self.conclusion
    }

    /// Returns the next occurrence, or `None` for fail-closed registry disablement.
    #[must_use]
    pub const fn next_fire_at(&self) -> Option<UnixMillis> {
        self.next_fire_at
    }
}

/// Fenced retry after a sanitized transient failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryGithubScheduleFire {
    claim: GithubScheduleFireClaim,
    retry_after_millis: i64,
    failure_kind: String,
}

impl RetryGithubScheduleFire {
    /// Constructs a bounded retry.
    ///
    /// # Errors
    ///
    /// Rejects a non-positive/excessive delay or invalid sanitized kind.
    pub fn new(
        claim: GithubScheduleFireClaim,
        retry_after_millis: i64,
        failure_kind: impl Into<String>,
    ) -> Result<Self, GithubScheduleValueError> {
        let failure_kind = failure_kind.into();
        if retry_after_millis <= 0
            || retry_after_millis > MAX_GITHUB_SCHEDULE_RETRY_MILLIS
            || !valid_failure_kind(&failure_kind)
        {
            return Err(GithubScheduleValueError::InvalidRetry);
        }
        Ok(Self {
            claim,
            retry_after_millis,
            failure_kind,
        })
    }

    /// Returns the claim to fence.
    #[must_use]
    pub const fn claim(&self) -> GithubScheduleFireClaim {
        self.claim
    }

    /// Returns the bounded retry delay.
    #[must_use]
    pub const fn retry_after_millis(&self) -> i64 {
        self.retry_after_millis
    }

    /// Returns the sanitized failure kind.
    #[must_use]
    pub fn failure_kind(&self) -> &str {
        &self.failure_kind
    }
}

/// Successful fenced mutation receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubScheduleFireReceipt {
    fire_id: GithubScheduleFireId,
    recorded_at: UnixMillis,
}

/// Typed request to create or replay the Check for one live scheduled fire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisterGithubScheduledCheckSubject {
    claim: GithubScheduleFireClaim,
}

impl RegisterGithubScheduledCheckSubject {
    /// Binds Check registration to one exact claim snapshot.
    #[must_use]
    pub const fn new(claim: GithubScheduleFireClaim) -> Self {
        Self { claim }
    }

    /// Returns the exact claim that must still be live.
    #[must_use]
    pub const fn claim(self) -> GithubScheduleFireClaim {
        self.claim
    }
}

impl GithubScheduleFireReceipt {
    /// Rehydrates a checked receipt.
    #[must_use]
    pub const fn from_durable_parts(
        fire_id: GithubScheduleFireId,
        recorded_at: UnixMillis,
    ) -> Self {
        Self {
            fire_id,
            recorded_at,
        }
    }

    /// Returns the exact fire identity.
    #[must_use]
    pub const fn fire_id(self) -> GithubScheduleFireId {
        self.fire_id
    }

    /// Returns the authoritative database observation.
    #[must_use]
    pub const fn recorded_at(self) -> UnixMillis {
        self.recorded_at
    }
}

/// Durable schedule registry and fire claim boundary.
#[async_trait]
pub trait GithubScheduleRepository: fmt::Debug + Send + Sync {
    /// Claims or exactly replays one manifest-pinned discovery session.
    async fn claim_github_schedule_discovery(
        &self,
        request: ClaimGithubScheduleDiscovery,
    ) -> Result<GithubScheduleDiscoveryClaim, GithubScheduleStoreError>;

    /// Registers and activates one exact source revision or returns its replay.
    async fn register_github_schedule_registry(
        &self,
        request: RegisterGithubScheduleRegistry,
    ) -> Result<GithubScheduleRegistryReceipt, GithubScheduleStoreError>;

    /// Claims at most one due fire using database time and lease fencing.
    async fn claim_due_github_schedule_fire(
        &self,
        request: ClaimDueGithubScheduleFire,
    ) -> Result<Option<ClaimedGithubScheduleFire>, GithubScheduleStoreError>;

    /// Renews the exact current claim and returns its new snapshot.
    async fn renew_github_schedule_fire(
        &self,
        claim: GithubScheduleFireClaim,
        lease_millis: i64,
    ) -> Result<GithubScheduleFireClaim, GithubScheduleStoreError>;

    /// Creates or exactly replays the queued Check and sealed schedule evidence.
    async fn register_github_scheduled_check_subject(
        &self,
        request: RegisterGithubScheduledCheckSubject,
    ) -> Result<GithubCheckSubjectReceipt, GithubScheduleStoreError>;

    /// Releases a live claim into a bounded durable retry.
    async fn retry_github_schedule_fire(
        &self,
        request: RetryGithubScheduleFire,
    ) -> Result<GithubScheduleFireReceipt, GithubScheduleStoreError>;

    /// Records a terminal outcome and advances the exact current runtime entry.
    async fn complete_github_schedule_fire(
        &self,
        request: CompleteGithubScheduleFire,
    ) -> Result<GithubScheduleFireReceipt, GithubScheduleStoreError>;
}

/// Invalid schedule domain input.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum GithubScheduleValueError {
    /// Registry UUID is nil.
    #[error("GitHub schedule registry ID is invalid")]
    InvalidRegistryId,
    /// Fire UUID is nil.
    #[error("GitHub schedule fire ID is invalid")]
    InvalidFireId,
    /// Worker UUID is nil.
    #[error("GitHub schedule worker ID is invalid")]
    InvalidWorkerId,
    /// Claim fence is not positive and bounded.
    #[error("GitHub schedule claim fence is invalid")]
    InvalidClaimFence,
    /// Archive descriptor is invalid.
    #[error("GitHub schedule archive descriptor is invalid")]
    InvalidArchive,
    /// Provider-resolved repository owner differs from pinned manifest evidence.
    #[error("GitHub schedule repository owner does not match the manifest")]
    RepositoryOwnerMismatch,
    /// Registry entry is invalid.
    #[error("GitHub schedule registry entry is invalid")]
    InvalidEntry,
    /// Registry aggregate is invalid.
    #[error("GitHub schedule registry is invalid")]
    InvalidRegistry,
    /// Claim lease is invalid.
    #[error("GitHub schedule claim lease is invalid")]
    InvalidLease,
    /// Source-read authority is structurally incompatible with the manifest.
    #[error("GitHub schedule source authority is invalid")]
    InvalidSourceAuthority,
    /// Durable claim snapshot is invalid.
    #[error("GitHub schedule fire claim is invalid")]
    InvalidClaim,
    /// Terminal conclusion is invalid.
    #[error("GitHub schedule conclusion is invalid")]
    InvalidConclusion,
    /// Retry policy is invalid.
    #[error("GitHub schedule retry is invalid")]
    InvalidRetry,
}

/// Sanitized durable schedule failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GithubScheduleStoreError {
    /// A different registry revision occupies the replay identity.
    #[error("GitHub schedule registry conflicts with durable evidence")]
    Conflict,
    /// The claim is stale, expired, or belongs to a different worker/fence.
    #[error("GitHub schedule fire claim was rejected")]
    ClaimRejected,
    /// Durable schedule rows violate a domain invariant.
    #[error("GitHub schedule durable evidence is corrupt")]
    CorruptData,
    /// Backend operation failed.
    #[error("GitHub schedule store operation failed")]
    Store(#[source] StoreError),
}

fn entries_are_canonical(entries: &[GithubScheduleRegistryEntry]) -> bool {
    let mut previous: Option<&GithubScheduleRegistryEntry> = None;
    for (index, entry) in entries.iter().enumerate() {
        if usize::from(entry.ordinal()) != index {
            return false;
        }
        let key = (entry.workflow_path(), entry.schedule_ordinal());
        if let Some(previous) = previous {
            let previous_key = (previous.workflow_path(), previous.schedule_ordinal());
            if previous_key >= key
                || previous.workflow_path() == entry.workflow_path()
                    && previous.workflow_source_digest() != entry.workflow_source_digest()
            {
                return false;
            }
        }
        previous = Some(entry);
    }
    true
}

fn entries_match_discovery_first_fire(
    entries: &[GithubScheduleRegistryEntry],
    discovered_at: UnixMillis,
) -> bool {
    entries.iter().all(|entry| {
        CronExpression::parse(entry.cron_expression())
            .ok()
            .and_then(|cron| cron.next_after(discovered_at, entry.timezone()).ok())
            == Some(entry.next_fire_at())
    })
}

fn schedule_inventory_digest(entries: &[GithubScheduleRegistryEntry]) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(INVENTORY_DIGEST_DOMAIN);
    digest.update(
        u64::try_from(entries.len())
            .expect("bounded schedule inventory count fits u64")
            .to_be_bytes(),
    );
    for entry in entries {
        digest.update(entry.entry_digest().as_bytes());
    }
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn valid_sha1(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_failure_kind(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_FAILURE_KIND_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'_' | b'.' | b':' | b'-')
        })
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .bytes()
            .next_back()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn schedule_entry_digest(
    workflow_path: &str,
    workflow_source_digest: Sha256Digest,
    schedule_ordinal: u16,
    cron_expression: &str,
    timezone: &str,
) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(ENTRY_DIGEST_DOMAIN);
    digest_part(&mut digest, workflow_path.as_bytes());
    digest_part(&mut digest, workflow_source_digest.as_bytes());
    digest_part(&mut digest, &schedule_ordinal.to_be_bytes());
    digest_part(&mut digest, cron_expression.as_bytes());
    digest_part(&mut digest, timezone.as_bytes());
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn digest_part(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}
