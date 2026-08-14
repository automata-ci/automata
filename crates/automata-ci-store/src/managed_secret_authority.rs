//! Value-free managed-secret authority resolution for one current workload.

use std::{collections::BTreeMap, fmt};

use async_trait::async_trait;
use automata_ci_core::{
    JobId, JobRuntimeContext, Lease, RunId, RunnerSessionId, SecretBinding, Sha256Digest,
    UnixMillis,
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

/// mTLS-authenticated runner and claimed durable session used to derive the
/// current server-owned fence for private delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolveManagedSecretDeliverySession {
    session_id: RunnerSessionId,
    machine: ManagedSecretDeliveryMachine,
    observed_at: UnixMillis,
}

impl ResolveManagedSecretDeliverySession {
    /// Constructs an authenticated-machine/session claim.
    ///
    /// # Errors
    ///
    /// Rejects a nil session or negative observation time. The Store maps the
    /// independently authenticated machine to its internal runner and derives
    /// the current epoch and generation before any value-bearing work begins.
    pub fn new(
        session_id: RunnerSessionId,
        machine: ManagedSecretDeliveryMachine,
        observed_at: UnixMillis,
    ) -> Result<Self, ManagedSecretAuthorityValueError> {
        if session_id.as_uuid().is_nil() || observed_at.get() < 0 {
            return Err(ManagedSecretAuthorityValueError::InvalidExecution);
        }
        Ok(Self {
            session_id,
            machine,
            observed_at,
        })
    }

    /// Returns the claimed durable session identity.
    #[must_use]
    pub const fn session_id(&self) -> RunnerSessionId {
        self.session_id
    }

    /// Returns the independently authenticated machine evidence.
    #[must_use]
    pub const fn machine(&self) -> &ManagedSecretDeliveryMachine {
        &self.machine
    }

    /// Returns the trusted server observation time.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
}

/// Durable identity of one retry-safe, value-free delivery operation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ManagedSecretDeliveryOperationId(Uuid);

impl ManagedSecretDeliveryOperationId {
    /// Constructs a non-nil delivery operation identity.
    ///
    /// # Errors
    ///
    /// Rejects the nil UUID sentinel.
    pub fn from_uuid(value: Uuid) -> Result<Self, ManagedSecretAuthorityValueError> {
        if value.is_nil() {
            return Err(ManagedSecretAuthorityValueError::InvalidDelivery);
        }
        Ok(Self(value))
    }

    /// Returns the durable UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

/// Value-free verifier proposed for one exact delivery operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedSecretDeliveryProposal {
    operation_id: ManagedSecretDeliveryOperationId,
    credential_key_id: String,
    credential_sha256: Sha256Digest,
}

impl ManagedSecretDeliveryProposal {
    /// Builds one bounded credential verifier. The bearer itself must never be
    /// passed to this store boundary.
    ///
    /// # Errors
    ///
    /// Rejects a noncanonical or oversized verifier-key identifier.
    pub fn new(
        operation_id: ManagedSecretDeliveryOperationId,
        credential_key_id: impl Into<String>,
        credential_sha256: Sha256Digest,
    ) -> Result<Self, ManagedSecretAuthorityValueError> {
        let credential_key_id = credential_key_id.into();
        if !canonical_machine_id(&credential_key_id, 128) {
            return Err(ManagedSecretAuthorityValueError::InvalidDelivery);
        }
        Ok(Self {
            operation_id,
            credential_key_id,
            credential_sha256,
        })
    }

    /// Returns the durable operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> ManagedSecretDeliveryOperationId {
        self.operation_id
    }

    /// Returns the non-secret credential-verifier key identity.
    #[must_use]
    pub fn credential_key_id(&self) -> &str {
        &self.credential_key_id
    }

    /// Returns the SHA-256 verifier of the separately transported bearer.
    #[must_use]
    pub const fn credential_sha256(&self) -> Sha256Digest {
        self.credential_sha256
    }
}

/// Independently authenticated runner-machine evidence for a delivery read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedSecretDeliveryMachine {
    external_identity: String,
    certificate_sha256: Sha256Digest,
}

impl ManagedSecretDeliveryMachine {
    /// Builds bounded machine evidence obtained from the mTLS verifier.
    ///
    /// # Errors
    ///
    /// Rejects an empty, oversized, or control-bearing external identity.
    pub fn new(
        external_identity: impl Into<String>,
        certificate_sha256: Sha256Digest,
    ) -> Result<Self, ManagedSecretAuthorityValueError> {
        let external_identity = external_identity.into();
        if external_identity.is_empty()
            || external_identity.len() > 255
            || external_identity.chars().any(char::is_control)
        {
            return Err(ManagedSecretAuthorityValueError::InvalidDelivery);
        }
        Ok(Self {
            external_identity,
            certificate_sha256,
        })
    }

    /// Returns the trust-provider external identity.
    #[must_use]
    pub fn external_identity(&self) -> &str {
        &self.external_identity
    }

    /// Returns the authenticated leaf-certificate fingerprint.
    #[must_use]
    pub const fn certificate_sha256(&self) -> Sha256Digest {
        self.certificate_sha256
    }
}

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

    /// Iterates normalized exact grant/version pairs in canonical order.
    ///
    /// This exposes value-free binding identity only, for an adapter to derive
    /// a server-owned retry identity after it validates the same set.
    #[must_use]
    pub fn entries(
        &self,
    ) -> impl ExactSizeIterator<Item = (&SecretWorkloadGrantId, &RepositorySecretVersionId)> + '_
    {
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

/// Value-free execution coordinates used to recover server-owned repository scope.
///
/// Lease offers and private runner delivery requests do not carry a tenant or
/// internal repository UUID. This request lets the durable adapter derive those
/// values from one exact current execution before the full authority check.
#[derive(Clone)]
pub struct ResolveManagedSecretExecutionScope {
    run_id: RunId,
    job_id: JobId,
    lease: Lease,
    session: RunnerSessionFence,
    slot: StableRunnerSlot,
    runtime_context_digest: Sha256Digest,
    observed_at: UnixMillis,
}

impl ResolveManagedSecretExecutionScope {
    /// Constructs one exact current execution lookup.
    ///
    /// # Errors
    ///
    /// Rejects malformed, expired, cross-runner, or unrepresentable fences.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        run_id: RunId,
        job_id: JobId,
        lease: Lease,
        session: RunnerSessionFence,
        slot: StableRunnerSlot,
        runtime_context_digest: Sha256Digest,
        observed_at: UnixMillis,
    ) -> Result<Self, ManagedSecretAuthorityValueError> {
        lease
            .validate()
            .map_err(|_| ManagedSecretAuthorityValueError::InvalidExecution)?;
        let valid = !run_id.as_uuid().is_nil()
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
            run_id,
            job_id,
            lease,
            session,
            slot,
            runtime_context_digest,
            observed_at,
        })
    }

    /// Returns the exact workflow run.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Returns the exact concrete job.
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    /// Returns the current lease coordinates.
    #[must_use]
    pub const fn lease(&self) -> &Lease {
        &self.lease
    }

    /// Returns the current session fence.
    #[must_use]
    pub const fn session(&self) -> RunnerSessionFence {
        self.session
    }

    /// Returns the stable runner slot.
    #[must_use]
    pub const fn slot(&self) -> StableRunnerSlot {
        self.slot
    }

    /// Returns the immutable runtime-context digest.
    #[must_use]
    pub const fn runtime_context_digest(&self) -> Sha256Digest {
        self.runtime_context_digest
    }

    /// Returns the trusted lookup observation time.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
}

impl fmt::Debug for ResolveManagedSecretExecutionScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolveManagedSecretExecutionScope")
            .field("identities", &"[REDACTED]")
            .field("observed_at", &self.observed_at)
            .finish_non_exhaustive()
    }
}

/// Server-owned tenant/repository scope for one exact current execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedSecretExecutionScope {
    tenant: TenantScope,
    repository_id: RepositoryId,
}

impl ManagedSecretExecutionScope {
    #[cfg(feature = "adapter-spi")]
    pub(crate) const fn from_durable(tenant: TenantScope, repository_id: RepositoryId) -> Self {
        Self {
            tenant,
            repository_id,
        }
    }

    /// Returns the durable tenant scope.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }

    /// Returns the internal repository identity.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
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
    delivery: Option<ManagedSecretDeliveryProposal>,
    machine: Option<ManagedSecretDeliveryMachine>,
}

impl ResolveManagedSecretAuthority {
    /// Constructs one exact current execution authority request.
    ///
    /// `runtime_context_digest` must identify the verified encoded context from
    /// which `bindings` was decoded. The repository rechecks that digest against
    /// the immutable current concrete-job record before considering grants.
    ///
    /// # Errors
    ///
    /// Rejects nil/cross-bound execution identities, an invalid or expired lease,
    /// negative time, or numeric fences outside the signed 64-bit storage boundary.
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
            delivery: None,
            machine: None,
        })
    }

    /// Attaches the value-free operation and bearer verifier to reserve or
    /// replay. Reusing the same operation with different evidence fails closed.
    #[must_use]
    pub fn with_delivery(mut self, delivery: ManagedSecretDeliveryProposal) -> Self {
        self.delivery = Some(delivery);
        self
    }

    /// Attaches independently authenticated mTLS machine evidence. This must
    /// be present for a value-bearing delivery read and absent during offer-time
    /// reservation.
    #[must_use]
    pub fn with_authenticated_machine(mut self, machine: ManagedSecretDeliveryMachine) -> Self {
        self.machine = Some(machine);
        self
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

    /// Returns the proposed value-free delivery operation, when requested.
    #[must_use]
    pub const fn delivery(&self) -> Option<&ManagedSecretDeliveryProposal> {
        self.delivery.as_ref()
    }

    /// Returns independently authenticated mTLS evidence for a delivery read.
    #[must_use]
    pub const fn machine(&self) -> Option<&ManagedSecretDeliveryMachine> {
        self.machine.as_ref()
    }
}

impl fmt::Debug for ResolveManagedSecretAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolveManagedSecretAuthority")
            .field("binding_count", &self.bindings.len())
            .field("identities", &"[REDACTED]")
            .field("observed_at", &self.observed_at)
            .field("delivery", &self.delivery.as_ref().map(|_| "[REDACTED]"))
            .field("machine", &self.machine.as_ref().map(|_| "[REDACTED]"))
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

/// One value-free, exact-version provider target authorized for the workload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedSecretScope {
    /// Tenant-scoped secret admitted to this exact repository by policy.
    Tenant,
    /// Repository-scoped secret bound to the receipt repository.
    Repository,
    /// Protected or unprotected environment-scoped secret.
    Environment {
        /// Durable repository-environment identity.
        environment_id: Uuid,
    },
}

/// One value-free, exact-version provider target authorized for the workload.
#[derive(Clone, Eq, PartialEq)]
pub struct ManagedSecretAuthorityBinding {
    grant_id: SecretWorkloadGrantId,
    provider_id: ManagedSecretProviderId,
    secret_id: RepositorySecretId,
    version_id: RepositorySecretVersionId,
    version_number: u64,
    canonical_name: String,
    scope: ManagedSecretScope,
    mode: ManagedSecretGrantMode,
    provider_supports_dynamic_leases: bool,
}

#[cfg(feature = "adapter-spi")]
pub(crate) struct ManagedSecretAuthorityBindingParts {
    pub(crate) grant_id: SecretWorkloadGrantId,
    pub(crate) provider_id: ManagedSecretProviderId,
    pub(crate) secret_id: RepositorySecretId,
    pub(crate) version_id: RepositorySecretVersionId,
    pub(crate) version_number: u64,
    pub(crate) canonical_name: String,
    pub(crate) scope: ManagedSecretScope,
    pub(crate) mode: ManagedSecretGrantMode,
    pub(crate) provider_supports_dynamic_leases: bool,
}

impl ManagedSecretAuthorityBinding {
    #[cfg(feature = "adapter-spi")]
    pub(crate) fn from_verified_parts(parts: ManagedSecretAuthorityBindingParts) -> Self {
        Self {
            grant_id: parts.grant_id,
            provider_id: parts.provider_id,
            secret_id: parts.secret_id,
            version_id: parts.version_id,
            version_number: parts.version_number,
            canonical_name: parts.canonical_name,
            scope: parts.scope,
            mode: parts.mode,
            provider_supports_dynamic_leases: parts.provider_supports_dynamic_leases,
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

    /// Returns the canonical public name used by the exact runtime binding.
    #[must_use]
    pub fn canonical_name(&self) -> &str {
        &self.canonical_name
    }

    /// Returns the immutable logical scope authenticated for this workload.
    #[must_use]
    pub const fn scope(&self) -> ManagedSecretScope {
        self.scope
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

impl fmt::Debug for ManagedSecretAuthorityBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedSecretAuthorityBinding")
            .field("grant_id", &"[REDACTED]")
            .field("provider_id", &self.provider_id)
            .field("secret_id", &"[REDACTED]")
            .field("version_id", &"[REDACTED]")
            .field("version_number", &self.version_number)
            .field("canonical_name", &"[REDACTED]")
            .field("scope", &self.scope)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

/// Value-free proof that one exact delivery operation held current authority.
///
/// The receipt contains only durable identities, digests, fences, and deadlines.
/// It authorizes resolving the listed immutable versions while the operation is
/// pending; it never contains a secret value or bearer credential.
#[derive(Eq, PartialEq)]
pub struct ManagedSecretAuthorityReceipt {
    operation_id: ManagedSecretDeliveryOperationId,
    credential_key_id: String,
    credential_sha256: Sha256Digest,
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
    #[cfg(feature = "adapter-spi")]
    pub(crate) fn from_verified_parts(
        operation_id: ManagedSecretDeliveryOperationId,
        credential_key_id: String,
        credential_sha256: Sha256Digest,
        request: &ResolveManagedSecretAuthority,
        bindings: Vec<ManagedSecretAuthorityBinding>,
        evidence_digest: Sha256Digest,
        usable_until: UnixMillis,
    ) -> Self {
        Self {
            operation_id,
            credential_key_id,
            credential_sha256,
            tenant: request.tenant().clone(),
            repository_id: request.repository_id(),
            run_id: request.run_id(),
            job_id: request.job_id(),
            lease: request.lease().clone(),
            session: request.session(),
            slot: request.slot(),
            runtime_context_digest: request.runtime_context_digest(),
            bindings,
            evidence_digest,
            observed_at: request.observed_at(),
            usable_until,
        }
    }

    /// Returns the exact retry-safe delivery operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> ManagedSecretDeliveryOperationId {
        self.operation_id
    }

    /// Returns the durably pinned bearer issuance-key identity.
    #[must_use]
    pub fn credential_key_id(&self) -> &str {
        &self.credential_key_id
    }

    /// Returns the constant-time verifier for the separately reconstructed bearer.
    #[must_use]
    pub const fn credential_sha256(&self) -> Sha256Digest {
        self.credential_sha256
    }

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

/// Exact authenticated acknowledgement of successful ephemeral custody.
///
/// This wraps the same request used to resolve values so the durable adapter can
/// require the identical operation, bearer verifier, lease, session, slot,
/// runtime context, binding set, and independently authenticated runner machine.
pub struct AcknowledgeManagedSecretDelivery {
    authority: ResolveManagedSecretAuthority,
}

impl AcknowledgeManagedSecretDelivery {
    /// Builds an acknowledgement for one authenticated delivery request.
    ///
    /// # Errors
    ///
    /// Rejects requests without both a delivery operation and mTLS evidence.
    pub fn new(
        authority: ResolveManagedSecretAuthority,
    ) -> Result<Self, ManagedSecretAuthorityValueError> {
        if authority.delivery().is_none() || authority.machine().is_none() {
            return Err(ManagedSecretAuthorityValueError::InvalidDelivery);
        }
        Ok(Self { authority })
    }

    /// Returns the exact delivery authority coordinates to acknowledge.
    #[must_use]
    pub const fn authority(&self) -> &ResolveManagedSecretAuthority {
        &self.authority
    }
}

impl fmt::Debug for AcknowledgeManagedSecretDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcknowledgeManagedSecretDelivery")
            .field("authority", &"[REDACTED]")
            .finish()
    }
}

/// Value-free durable receipt for one delivery acknowledgement.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ManagedSecretDeliveryAcknowledgement {
    operation_id: ManagedSecretDeliveryOperationId,
    acknowledged_at: UnixMillis,
}

impl ManagedSecretDeliveryAcknowledgement {
    #[cfg(feature = "adapter-spi")]
    pub(crate) const fn from_durable(
        operation_id: ManagedSecretDeliveryOperationId,
        acknowledged_at: UnixMillis,
    ) -> Self {
        Self {
            operation_id,
            acknowledged_at,
        }
    }

    /// Returns the exact terminal delivery operation.
    #[must_use]
    pub const fn operation_id(self) -> ManagedSecretDeliveryOperationId {
        self.operation_id
    }

    /// Returns the trusted acknowledgement observation time.
    #[must_use]
    pub const fn acknowledged_at(self) -> UnixMillis {
        self.acknowledged_at
    }
}

impl fmt::Debug for ManagedSecretDeliveryAcknowledgement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedSecretDeliveryAcknowledgement")
            .field("operation_id", &"[REDACTED]")
            .field("acknowledged_at", &self.acknowledged_at)
            .finish()
    }
}

/// Sanitized failures from durable managed-secret authority resolution.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ManagedSecretAuthorityStoreError {
    /// No exact current workload authority permits the requested binding set.
    #[error("managed-secret workload authority is unavailable")]
    Unauthorized,
    /// An already-authenticated caller reached an unsupported authority state.
    #[error("managed-secret workload authority cannot be determined")]
    Indeterminate,
    /// The current exact-set cardinality exceeds the closed delivery bound.
    #[error("managed-secret workload authority capacity is exhausted")]
    ResourceExhausted,
    /// Persisted records violate the current value-free authority contract.
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
    /// Delivery operation or mTLS machine evidence is malformed.
    #[error("managed-secret delivery evidence is invalid")]
    InvalidDelivery,
}

/// Object-safe durable boundary for one exact managed-secret workload binding set.
#[async_trait]
pub trait ManagedSecretAuthorityRepository: fmt::Debug + Send + Sync {
    /// Maps an authenticated machine and claimed session to one live fence.
    ///
    /// This is intentionally server-owned: the private runner request carries
    /// no client-authoritative internal runner identity, epoch, or registration
    /// generation.
    async fn resolve_managed_secret_delivery_session(
        &self,
        request: ResolveManagedSecretDeliverySession,
    ) -> Result<Option<RunnerSessionFence>, ManagedSecretAuthorityStoreError>;

    /// Derives tenant and repository scope from an exact current execution.
    ///
    /// This lookup returns no authority receipt and never accepts client-owned
    /// tenant/repository claims. The caller must still perform the complete
    /// resolution before any immutable value is read.
    async fn resolve_managed_secret_execution_scope(
        &self,
        request: ResolveManagedSecretExecutionScope,
    ) -> Result<ManagedSecretExecutionScope, ManagedSecretAuthorityStoreError>;

    /// Atomically rechecks the current lease, exact runtime context, grants,
    /// policies, protected environments, providers, immutable versions, and
    /// retry-safe operation evidence before issuing a value-free receipt.
    async fn resolve_managed_secret_authority(
        &self,
        request: ResolveManagedSecretAuthority,
    ) -> Result<ManagedSecretAuthorityReceipt, ManagedSecretAuthorityStoreError>;

    /// Atomically terminalizes one exact operation after the runner has placed
    /// every resolved value into bounded ephemeral custody.
    ///
    /// Retrying the same authenticated acknowledgement returns the original
    /// receipt. Any cross-operation, cross-session, changed-binding, stale, or
    /// already-expired request fails closed.
    async fn acknowledge_managed_secret_delivery(
        &self,
        request: AcknowledgeManagedSecretDelivery,
    ) -> Result<ManagedSecretDeliveryAcknowledgement, ManagedSecretAuthorityStoreError>;
}

fn canonical_uuid(value: &str) -> Option<Uuid> {
    let parsed = Uuid::parse_str(value).ok()?;
    (!parsed.is_nil() && parsed.hyphenated().to_string() == value).then_some(parsed)
}

fn canonical_machine_id(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
}
