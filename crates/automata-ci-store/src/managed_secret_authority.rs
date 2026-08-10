//! Value-free managed-secret authority resolution for one current workload.

use std::{collections::BTreeMap, fmt};

use async_trait::async_trait;
use automata_ci_core::{
    JobId, JobRuntimeContext, Lease, RunId, SecretBinding, Sha256Digest, UnixMillis,
};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    ManagedSecretProviderId, RepositoryId, RepositorySecretId, RepositorySecretVersionId,
    RunnerSessionFence, StableRunnerSlot, TenantScope,
};

/// Current evidence schema for a value-free managed-secret authority receipt.
pub const MANAGED_SECRET_AUTHORITY_SCHEMA: u16 = 1;
/// Maximum exact-version managed-secret bindings accepted for one workload.
pub const MAX_MANAGED_SECRET_BINDINGS: usize = 256;

/// Durable identity of one exact workload grant.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretWorkloadGrantId(Uuid);

impl SecretWorkloadGrantId {
    /// Constructs a non-nil workload-grant identity.
    ///
    /// # Errors
    ///
    /// Rejects the nil UUID sentinel.
    pub fn from_uuid(value: Uuid) -> Result<Self, ManagedSecretAuthorityValueError> {
        if value.is_nil() {
            return Err(ManagedSecretAuthorityValueError::InvalidBinding);
        }
        Ok(Self(value))
    }

    /// Returns the durable UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

/// One exact grant/version pair decoded from a runtime-context secret binding.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ManagedSecretBinding {
    grant_id: SecretWorkloadGrantId,
    version_id: RepositorySecretVersionId,
}

impl ManagedSecretBinding {
    /// Constructs one exact value-free binding.
    #[must_use]
    pub const fn new(
        grant_id: SecretWorkloadGrantId,
        version_id: RepositorySecretVersionId,
    ) -> Self {
        Self {
            grant_id,
            version_id,
        }
    }

    /// Decodes the current managed-secret representation of a runtime binding.
    ///
    /// Managed bindings use the canonical lowercase hyphenated workload-grant
    /// UUID as `binding_id` and require the canonical immutable built-in
    /// version UUID in `version_id`. No secret name, value, locator, or provider
    /// handle crosses this boundary. External-provider versions remain closed
    /// until a genuinely provider-neutral public identity type exists.
    ///
    /// # Errors
    ///
    /// Rejects a missing version or a noncanonical/nil UUID.
    pub fn from_runtime_binding(
        binding: &SecretBinding,
    ) -> Result<Self, ManagedSecretAuthorityValueError> {
        let grant_id = canonical_uuid(binding.binding_id())
            .and_then(|value| SecretWorkloadGrantId::from_uuid(value).ok())
            .ok_or(ManagedSecretAuthorityValueError::InvalidBinding)?;
        let version_id = binding
            .version_id()
            .and_then(canonical_uuid)
            .and_then(|value| RepositorySecretVersionId::from_uuid(value).ok())
            .ok_or(ManagedSecretAuthorityValueError::InvalidBinding)?;
        Ok(Self::new(grant_id, version_id))
    }

    /// Returns the exact workload-grant identity used as the runtime binding ID.
    #[must_use]
    pub const fn grant_id(self) -> SecretWorkloadGrantId {
        self.grant_id
    }

    /// Returns the immutable version identity selected by the runtime context.
    #[must_use]
    pub const fn version_id(self) -> RepositorySecretVersionId {
        self.version_id
    }
}

/// Canonically ordered, bounded exact binding set from one verified runtime context.
#[derive(Clone, Eq, PartialEq)]
pub struct ManagedSecretBindingSet(BTreeMap<SecretWorkloadGrantId, RepositorySecretVersionId>);

impl ManagedSecretBindingSet {
    /// Extracts the value-free exact-version set from a validated runtime context.
    ///
    /// The caller remains responsible for verifying the encoded context bytes
    /// against their durable digest. The resolution request carries that digest,
    /// and the adapter rechecks it against the exact current concrete job.
    ///
    /// # Errors
    ///
    /// Rejects more than 256 bindings, duplicate grant IDs, missing versions, or
    /// noncanonical managed binding/version UUIDs.
    pub fn from_runtime_context(
        context: &JobRuntimeContext,
    ) -> Result<Self, ManagedSecretAuthorityValueError> {
        if context.secrets().len() > MAX_MANAGED_SECRET_BINDINGS {
            return Err(ManagedSecretAuthorityValueError::TooManyBindings);
        }
        let mut bindings = BTreeMap::new();
        for binding in context.secrets().values() {
            let binding = ManagedSecretBinding::from_runtime_binding(binding)?;
            if bindings
                .insert(binding.grant_id(), binding.version_id())
                .is_some()
            {
                return Err(ManagedSecretAuthorityValueError::DuplicateBinding);
            }
        }
        Ok(Self(bindings))
    }

    /// Builds a bounded exact set from already-decoded managed bindings.
    ///
    /// # Errors
    ///
    /// Rejects more than 256 entries or a duplicate grant identity.
    pub fn new(
        values: impl IntoIterator<Item = ManagedSecretBinding>,
    ) -> Result<Self, ManagedSecretAuthorityValueError> {
        let mut bindings = BTreeMap::new();
        for binding in values {
            if bindings.len() == MAX_MANAGED_SECRET_BINDINGS {
                return Err(ManagedSecretAuthorityValueError::TooManyBindings);
            }
            if bindings
                .insert(binding.grant_id(), binding.version_id())
                .is_some()
            {
                return Err(ManagedSecretAuthorityValueError::DuplicateBinding);
            }
        }
        Ok(Self(bindings))
    }

    /// Returns the exact number of requested bindings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether no managed-secret binding is requested.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn entries(
        &self,
    ) -> impl ExactSizeIterator<Item = (&SecretWorkloadGrantId, &RepositorySecretVersionId)> {
        self.0.iter()
    }
}

impl fmt::Debug for ManagedSecretBindingSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedSecretBindingSet")
            .field("binding_count", &self.len())
            .field("bindings", &"[REDACTED]")
            .finish()
    }
}

/// Exact current workload and verified runtime-context evidence to authorize.
#[derive(Clone)]
pub struct ResolveManagedSecretAuthority {
    tenant: TenantScope,
    repository_id: RepositoryId,
    run_id: RunId,
    job_id: JobId,
    lease: Lease,
    session: RunnerSessionFence,
    slot: StableRunnerSlot,
    runtime_context_digest: Sha256Digest,
    bindings: ManagedSecretBindingSet,
    observed_at: UnixMillis,
}

impl ResolveManagedSecretAuthority {
    /// Constructs one exact current execution authority request.
    ///
    /// `runtime_context_digest` must identify the verified encoded context from
    /// which `bindings` was decoded. The `PostgreSQL` adapter rechecks that digest
    /// against the immutable current concrete-job row before considering grants.
    ///
    /// # Errors
    ///
    /// Rejects nil/cross-bound execution identities, an invalid or expired lease,
    /// negative time, or numeric fences outside `PostgreSQL` `BIGINT`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: TenantScope,
        repository_id: RepositoryId,
        run_id: RunId,
        job_id: JobId,
        lease: Lease,
        session: RunnerSessionFence,
        slot: StableRunnerSlot,
        runtime_context_digest: Sha256Digest,
        bindings: ManagedSecretBindingSet,
        observed_at: UnixMillis,
    ) -> Result<Self, ManagedSecretAuthorityValueError> {
        lease
            .validate()
            .map_err(|_| ManagedSecretAuthorityValueError::InvalidExecution)?;
        let valid = !repository_id.as_uuid().is_nil()
            && !run_id.as_uuid().is_nil()
            && !job_id.as_uuid().is_nil()
            && !lease.attempt_id().as_uuid().is_nil()
            && !lease.lease_id().as_uuid().is_nil()
            && !lease.runner_id().as_uuid().is_nil()
            && !session.session_id().as_uuid().is_nil()
            && lease.runner_id() == session.runner_id()
            && lease.issued_at().get() >= 0
            && lease.expires_at().get() >= 0
            && observed_at.get() >= 0
            && observed_at >= lease.issued_at()
            && observed_at < lease.expires_at()
            && i64::try_from(lease.fencing_token().get()).is_ok()
            && i64::try_from(session.session_epoch().get()).is_ok()
            && i64::try_from(session.runner_generation().get()).is_ok();
        if !valid {
            return Err(ManagedSecretAuthorityValueError::InvalidExecution);
        }
        Ok(Self {
            tenant,
            repository_id,
            run_id,
            job_id,
            lease,
            session,
            slot,
            runtime_context_digest,
            bindings,
            observed_at,
        })
    }

    /// Returns the authenticated tenant scope.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }

    /// Returns the exact repository identity.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Returns the exact workflow-run identity.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Returns the exact concrete-job identity.
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    /// Returns the exact current lease.
    #[must_use]
    pub const fn lease(&self) -> &Lease {
        &self.lease
    }

    /// Returns the exact current runner-session fence.
    #[must_use]
    pub const fn session(&self) -> RunnerSessionFence {
        self.session
    }

    /// Returns the exact stable runner slot.
    #[must_use]
    pub const fn slot(&self) -> StableRunnerSlot {
        self.slot
    }

    /// Returns the verified immutable runtime-context digest.
    #[must_use]
    pub const fn runtime_context_digest(&self) -> Sha256Digest {
        self.runtime_context_digest
    }

    /// Returns the exact bounded binding set.
    #[must_use]
    pub const fn bindings(&self) -> &ManagedSecretBindingSet {
        &self.bindings
    }

    /// Returns the trusted authority observation time.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
}

impl fmt::Debug for ResolveManagedSecretAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolveManagedSecretAuthority")
            .field("binding_count", &self.bindings.len())
            .field("identities", &"[REDACTED]")
            .field("observed_at", &self.observed_at)
            .finish_non_exhaustive()
    }
}

/// Delivery behavior authorized for one immutable secret version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedSecretGrantMode {
    /// User code may receive the readable secret value.
    ReadableSecret,
    /// Only a separately brokered provider capability may cross to the job.
    CapabilityOnly,
}

impl ManagedSecretGrantMode {
    pub(crate) const fn from_durable(value: &str) -> Option<Self> {
        match value.as_bytes() {
            b"readable_secret" => Some(Self::ReadableSecret),
            b"capability_only" => Some(Self::CapabilityOnly),
            _ => None,
        }
    }
}

/// One value-free, exact-version provider target authorized for the workload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedSecretAuthorityBinding {
    grant_id: SecretWorkloadGrantId,
    provider_id: ManagedSecretProviderId,
    secret_id: RepositorySecretId,
    version_id: RepositorySecretVersionId,
    version_number: u64,
    mode: ManagedSecretGrantMode,
    provider_supports_dynamic_leases: bool,
}

impl ManagedSecretAuthorityBinding {
    pub(crate) const fn from_verified_parts(
        grant_id: SecretWorkloadGrantId,
        provider_id: ManagedSecretProviderId,
        secret_id: RepositorySecretId,
        version_id: RepositorySecretVersionId,
        version_number: u64,
        mode: ManagedSecretGrantMode,
        provider_supports_dynamic_leases: bool,
    ) -> Self {
        Self {
            grant_id,
            provider_id,
            secret_id,
            version_id,
            version_number,
            mode,
            provider_supports_dynamic_leases,
        }
    }

    /// Returns the exact workload-grant/binding identity.
    #[must_use]
    pub const fn grant_id(&self) -> SecretWorkloadGrantId {
        self.grant_id
    }

    /// Returns the exact provider registry identity.
    #[must_use]
    pub const fn provider_id(&self) -> &ManagedSecretProviderId {
        &self.provider_id
    }

    /// Returns the immutable logical secret identity.
    #[must_use]
    pub const fn secret_id(&self) -> RepositorySecretId {
        self.secret_id
    }

    /// Returns the immutable secret-version identity.
    #[must_use]
    pub const fn version_id(&self) -> RepositorySecretVersionId {
        self.version_id
    }

    /// Returns the positive version ordinal.
    #[must_use]
    pub const fn version_number(&self) -> u64 {
        self.version_number
    }

    /// Returns whether this target permits readable or capability-only delivery.
    #[must_use]
    pub const fn mode(&self) -> ManagedSecretGrantMode {
        self.mode
    }

    /// Returns the exact current dynamic-lease capability of the provider.
    ///
    /// Capability-only delivery can never be authorized when this is false.
    #[must_use]
    pub const fn provider_supports_dynamic_leases(&self) -> bool {
        self.provider_supports_dynamic_leases
    }
}

/// Non-constructible, value-free proof of one exact current binding resolution.
///
/// The current no-migration `PostgreSQL` foundation intentionally never issues
/// this receipt: durable grant and attempt terminality, a unique current
/// attempt, protected-environment freshness/threshold evidence, and caller
/// credential possession are not yet exactly provable. Delivery also lacks a
/// durable one-operation consumption fence after the resolving transaction
/// releases its locks. The type fixes the eventual value-free boundary without
/// weakening those prerequisites and remains non-constructible for now.
#[derive(Eq, PartialEq)]
pub struct ManagedSecretAuthorityReceipt {
    tenant: TenantScope,
    repository_id: RepositoryId,
    run_id: RunId,
    job_id: JobId,
    lease: Lease,
    session: RunnerSessionFence,
    slot: StableRunnerSlot,
    runtime_context_digest: Sha256Digest,
    bindings: Vec<ManagedSecretAuthorityBinding>,
    evidence_digest: Sha256Digest,
    observed_at: UnixMillis,
    usable_until: UnixMillis,
}

impl ManagedSecretAuthorityReceipt {
    /// Returns the current authority evidence schema.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        MANAGED_SECRET_AUTHORITY_SCHEMA
    }

    /// Returns the authenticated tenant scope.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }

    /// Returns the exact repository identity.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Returns the exact workflow-run identity.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Returns the exact concrete-job identity.
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    /// Returns the exact current lease authenticated by the adapter.
    #[must_use]
    pub const fn lease(&self) -> &Lease {
        &self.lease
    }

    /// Returns the exact current runner-session fence.
    #[must_use]
    pub const fn session(&self) -> RunnerSessionFence {
        self.session
    }

    /// Returns the exact stable runner slot.
    #[must_use]
    pub const fn slot(&self) -> StableRunnerSlot {
        self.slot
    }

    /// Returns the immutable runtime-context digest containing this exact set.
    #[must_use]
    pub const fn runtime_context_digest(&self) -> Sha256Digest {
        self.runtime_context_digest
    }

    /// Returns the canonically ordered provider/secret/version identities.
    #[must_use]
    pub fn bindings(&self) -> &[ManagedSecretAuthorityBinding] {
        &self.bindings
    }

    /// Returns the domain-separated digest binding every checked identity,
    /// revision, policy, grant digest, fence, and authority deadline.
    #[must_use]
    pub const fn evidence_digest(&self) -> Sha256Digest {
        self.evidence_digest
    }

    /// Returns the trusted time at which this authority was checked.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }

    /// Returns the earliest grant, approval, or lease deadline.
    #[must_use]
    pub const fn usable_until(&self) -> UnixMillis {
        self.usable_until
    }
}

impl fmt::Debug for ManagedSecretAuthorityReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedSecretAuthorityReceipt")
            .field("schema_version", &self.schema_version())
            .field("binding_count", &self.bindings.len())
            .field("identities", &"[REDACTED]")
            .field("evidence_digest", &self.evidence_digest)
            .field("observed_at", &self.observed_at)
            .field("usable_until", &self.usable_until)
            .finish_non_exhaustive()
    }
}

/// Sanitized failures from durable managed-secret authority resolution.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ManagedSecretAuthorityStoreError {
    /// No exact current workload authority permits the requested binding set.
    #[error("managed-secret workload authority is unavailable")]
    Unauthorized,
    /// An already-authenticated caller reached an unsupported authority state.
    ///
    /// The current schema permits terminal grant/attempt reactivation and does
    /// not pin protected approvals to an immutable approval-time environment
    /// revision, settings digest, or append-only threshold decision set. The
    /// request also carries no proof of possession for the grant credential
    /// verifier. Those cases remain closed instead of accepting replay,
    /// mutable-value equality across ABA, or public IDs as authentication. The
    /// current `PostgreSQL` adapter has no authenticated proof input and
    /// therefore collapses these cases to [`Self::Unauthorized`] instead of
    /// exposing this otherwise-distinguishable result as an oracle.
    #[error("managed-secret workload authority cannot be determined")]
    Indeterminate,
    /// The current exact-set cardinality exceeds the closed delivery bound.
    #[error("managed-secret workload authority capacity is exhausted")]
    ResourceExhausted,
    /// Persisted rows violate the current value-free authority contract.
    #[error("managed-secret durable authority state is corrupt")]
    CorruptData,
    /// The durable store is temporarily unavailable.
    #[error("managed-secret durable authority state is unavailable")]
    Unavailable,
}

/// Value-construction failures at the managed-secret authority boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ManagedSecretAuthorityValueError {
    /// Execution coordinates do not form one exact live lease/session identity.
    #[error("managed-secret execution identity is invalid")]
    InvalidExecution,
    /// A runtime binding is not one canonical grant UUID and exact version UUID.
    #[error("managed-secret runtime binding is invalid")]
    InvalidBinding,
    /// More than one runtime entry reused the same workload-grant identity.
    #[error("managed-secret runtime binding set contains a duplicate grant")]
    DuplicateBinding,
    /// The runtime context exceeded the closed per-workload binding ceiling.
    #[error("managed-secret runtime binding set exceeds its bound")]
    TooManyBindings,
}

/// Object-safe durable boundary for one exact managed-secret workload binding set.
#[async_trait]
pub trait ManagedSecretAuthorityRepository: fmt::Debug + Send + Sync {
    /// Atomically rechecks the current lease, exact runtime context, grants,
    /// policies, protected environments, providers, and immutable versions.
    /// The current `PostgreSQL` schema and request credential contract cannot
    /// prove replay-safe authority or one-shot downstream consumption and
    /// therefore issue no receipt. Because the request contains only public
    /// identities, that adapter returns the same
    /// [`ManagedSecretAuthorityStoreError::Unauthorized`] result for both a
    /// matching-but-unprovable state and every unauthorized target.
    async fn resolve_managed_secret_authority(
        &self,
        request: ResolveManagedSecretAuthority,
    ) -> Result<ManagedSecretAuthorityReceipt, ManagedSecretAuthorityStoreError>;
}

fn canonical_uuid(value: &str) -> Option<Uuid> {
    let parsed = Uuid::parse_str(value).ok()?;
    (!parsed.is_nil() && parsed.hyphenated().to_string() == value).then_some(parsed)
}
