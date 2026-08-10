use std::{fmt, num::NonZeroU64};

use async_trait::async_trait;
use thiserror::Error;

use crate::{
    ModelError, ProviderRequestId, SecretDescriptor, SecretValue, TenantScopeId, WorkloadContext,
};

const MAX_PROVIDER_ID_BYTES: usize = 64;
const MAX_PROVIDER_OPAQUE_ID_BYTES: usize = 2_048;
const MAX_PROVIDER_CAPABILITIES: usize = 6;

/// Mandatory durable protection boundary for secret-provider values.
///
/// There is deliberately no plaintext, unknown, or unspecified variant. An
/// adapter may be composed only after it can attest that every durable copy of
/// a secret value is protected by one of these two encryption boundaries.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SecretAtRestProtection {
    /// Automata envelope-encrypts values before they cross durable storage.
    AutomataEnvelope,
    /// The provider encrypts values within its own authenticated storage boundary.
    ProviderManagedEncryption,
}

impl SecretAtRestProtection {
    /// Returns the stable management and persistence label for the protection mode.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AutomataEnvelope => "automata_envelope",
            Self::ProviderManagedEncryption => "provider_managed_encryption",
        }
    }
}

/// Canonical identifier selecting one configured secret-provider adapter.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretProviderId(String);

impl SecretProviderId {
    /// Creates a lowercase portable provider identifier.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, non-ASCII, or noncanonical identifiers.
    pub fn new(value: impl Into<String>) -> Result<Self, SecretProviderIdError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_PROVIDER_ID_BYTES
            && value.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || (index > 0 && matches!(byte, b'.' | b'-'))
            })
            && !value.ends_with(['.', '-']);
        valid.then_some(Self(value)).ok_or(SecretProviderIdError)
    }

    /// Returns the canonical, non-secret adapter identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A secret-provider adapter identifier violates the portable identifier
/// grammar or byte limit.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("secret provider ID is invalid")]
pub struct SecretProviderIdError;

fn valid_provider_opaque_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PROVIDER_OPAQUE_ID_BYTES
        && !value.chars().any(char::is_control)
}

macro_rules! provider_opaque_id {
    ($name:ident, $label:literal) => {
        #[doc = concat!("Provider-owned opaque ", $label, ".")]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Creates a bounded provider ", $label, ".")]
            ///
            /// # Errors
            ///
            /// Rejects empty, oversized, or control-containing values.
            pub fn new(value: impl Into<String>) -> Result<Self, ProviderOpaqueIdError> {
                let value = value.into();
                valid_provider_opaque_id(&value)
                    .then_some(Self(value))
                    .ok_or(ProviderOpaqueIdError)
            }

            /// Borrows the provider-owned value for adapter use.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([OPAQUE])"))
            }
        }
    };
}

provider_opaque_id!(ProviderSecretLocator, "secret locator");
provider_opaque_id!(ProviderVersionId, "version ID");
provider_opaque_id!(ProviderLeaseId, "lease ID");

/// A provider-owned locator, version, or lease identifier is empty, exceeds
/// its byte limit, or contains a control character.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("provider-owned opaque identifier is invalid")]
pub struct ProviderOpaqueIdError;

/// Optional behavior supported by one configured provider.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProviderCapability {
    /// Creates a new immutable version, and optionally its provider object.
    CreateVersion,
    /// Reconciles an ambiguous create through a strictly non-mutating lookup.
    ReconcileCreateVersion,
    /// Permanently destroys one exact immutable version.
    DestroyVersion,
    /// Resolving a version may produce a time-bounded dynamic lease.
    DynamicLeases,
    /// Extends a dynamic lease before it expires.
    RenewLeases,
    /// Explicitly revokes a dynamic lease.
    RevokeLeases,
}

/// Sorted, unique, internally consistent optional provider capabilities.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProviderCapabilities(Vec<ProviderCapability>);

impl ProviderCapabilities {
    /// Builds an explicit provider capability set.
    ///
    /// # Errors
    ///
    /// Rejects duplicates, oversized declarations, create reconciliation
    /// without create support, and lease renewal or revocation without dynamic
    /// lease support.
    pub fn new(
        values: impl IntoIterator<Item = ProviderCapability>,
    ) -> Result<Self, ProviderCapabilityError> {
        let mut values: Vec<_> = values.into_iter().collect();
        if values.len() > MAX_PROVIDER_CAPABILITIES {
            return Err(ProviderCapabilityError::TooMany);
        }
        values.sort_unstable();
        if values.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ProviderCapabilityError::Duplicate);
        }
        let has_create_version = values
            .binary_search(&ProviderCapability::CreateVersion)
            .is_ok();
        let has_create_reconciliation = values
            .binary_search(&ProviderCapability::ReconcileCreateVersion)
            .is_ok();
        if has_create_reconciliation && !has_create_version {
            return Err(ProviderCapabilityError::InvalidCreateReconciliation);
        }
        let has_dynamic_leases = values
            .binary_search(&ProviderCapability::DynamicLeases)
            .is_ok();
        if !has_dynamic_leases
            && (values
                .binary_search(&ProviderCapability::RenewLeases)
                .is_ok()
                || values
                    .binary_search(&ProviderCapability::RevokeLeases)
                    .is_ok())
        {
            return Err(ProviderCapabilityError::InvalidLeaseCapabilities);
        }
        Ok(Self(values))
    }

    /// Returns whether the adapter declared an optional capability.
    #[must_use]
    pub fn supports(&self, capability: ProviderCapability) -> bool {
        self.0.binary_search(&capability).is_ok()
    }

    /// Returns the adapter's sorted, duplicate-free capability declaration.
    #[must_use]
    pub fn values(&self) -> &[ProviderCapability] {
        &self.0
    }
}

/// Closed validation failures for a provider capability declaration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderCapabilityError {
    /// A capability was declared more than once.
    #[error("secret provider capability declaration contains a duplicate")]
    Duplicate,
    /// The declaration contains more entries than the closed capability set.
    #[error("secret provider capability declaration exceeds its bound")]
    TooMany,
    /// Create reconciliation was declared without immutable-version creation.
    #[error("create reconciliation requires create-version support")]
    InvalidCreateReconciliation,
    /// Renewal or revocation was declared without dynamic lease support.
    #[error("lease renewal and revocation require dynamic lease support")]
    InvalidLeaseCapabilities,
}

/// Sanitized health state suitable for readiness and management interfaces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderHealth {
    /// The adapter can currently serve operations normally.
    Healthy,
    /// The adapter is reachable but operating with reduced reliability or
    /// functionality.
    Degraded,
    /// The adapter cannot currently serve provider operations.
    Unavailable,
}

/// Stable failure classification at the provider trust boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderErrorKind {
    /// The request violates the adapter's validated input contract.
    InvalidRequest,
    /// The adapter does not implement the requested optional operation.
    Unsupported,
    /// Provider authentication is missing, expired, or rejected.
    Unauthorized,
    /// Provider authentication succeeded but lacks access to the target.
    Forbidden,
    /// The exact provider object, version, or lease does not exist.
    NotFound,
    /// Existing provider state prevents applying the requested operation.
    Conflict,
    /// The provider is throttling operations.
    RateLimited,
    /// The provider or its required dependency is temporarily unavailable.
    Unavailable,
    /// Stored bytes or cryptographic metadata failed integrity validation.
    IntegrityFailure,
    /// A provider response violates the adapter's expected schema or bounds.
    InvalidResponse,
}

/// Sanitized provider failure with optional bounded retry guidance.
///
/// Provider response bodies, storage paths, credentials, and secret values are
/// never retained in this error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("secret provider operation failed: {kind:?}")]
pub struct ProviderError {
    kind: ProviderErrorKind,
    retry_after_seconds: Option<u64>,
}

impl ProviderError {
    /// Creates a sanitized failure without retry timing.
    #[must_use]
    pub const fn new(kind: ProviderErrorKind) -> Self {
        Self {
            kind,
            retry_after_seconds: None,
        }
    }

    /// Creates a sanitized failure with optional provider-supplied backoff in
    /// seconds.
    ///
    /// The classification remains authoritative: callers must not retry a
    /// non-transient failure merely because timing guidance is present.
    #[must_use]
    pub const fn retryable(kind: ProviderErrorKind, retry_after_seconds: Option<u64>) -> Self {
        Self {
            kind,
            retry_after_seconds,
        }
    }

    /// Creates the standard failure returned by an unsupported optional trait
    /// operation.
    #[must_use]
    pub const fn unsupported() -> Self {
        Self::new(ProviderErrorKind::Unsupported)
    }

    /// Returns the stable failure classification.
    #[must_use]
    pub const fn kind(self) -> ProviderErrorKind {
        self.kind
    }

    /// Returns provider-supplied retry delay guidance in seconds, when known.
    #[must_use]
    pub const fn retry_after_seconds(self) -> Option<u64> {
        self.retry_after_seconds
    }
}

/// Tenant and idempotency/audit correlation shared by one provider operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderOperationContext {
    tenant: TenantScopeId,
    request_id: ProviderRequestId,
}

impl ProviderOperationContext {
    /// Binds a provider call to its owning tenant and stable idempotency/audit
    /// request identifier.
    #[must_use]
    pub const fn new(tenant: TenantScopeId, request_id: ProviderRequestId) -> Self {
        Self { tenant, request_id }
    }

    /// Returns the tenant on whose behalf the provider operation runs.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantScopeId {
        &self.tenant
    }

    /// Returns the stable idempotency and audit correlation identifier.
    #[must_use]
    pub const fn request_id(&self) -> &ProviderRequestId {
        &self.request_id
    }
}

fn validate_secret_context(
    context: &ProviderOperationContext,
    secret: &SecretDescriptor,
) -> Result<(), ModelError> {
    if context.tenant_id() != secret.scope().tenant_id() {
        return Err(ModelError::TenantMismatch);
    }
    Ok(())
}

/// Exact immutable provider version that a create request expects to replace.
///
/// Providers must compare both handles to their current version atomically
/// with creation. A mismatched locator or version is a closed conflict; it
/// must never be interpreted as permission to append to whichever object or
/// version is current.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExistingSecretVersion {
    locator: ProviderSecretLocator,
    version: ProviderVersionId,
}

impl ExistingSecretVersion {
    /// Names the exact provider object and immutable version expected to be
    /// current before replacement.
    #[must_use]
    pub const fn new(locator: ProviderSecretLocator, version: ProviderVersionId) -> Self {
        Self { locator, version }
    }

    /// Returns the opaque provider object expected to contain the version.
    #[must_use]
    pub const fn locator(&self) -> &ProviderSecretLocator {
        &self.locator
    }

    /// Returns the exact opaque immutable version expected to be current.
    #[must_use]
    pub const fn version(&self) -> &ProviderVersionId {
        &self.version
    }
}

/// Immutable-version creation request carrying plaintext across the provider
/// trust boundary exactly once.
#[derive(Debug)]
pub struct CreateSecretVersionRequest {
    context: ProviderOperationContext,
    secret: SecretDescriptor,
    expected_existing_version: Option<ExistingSecretVersion>,
    value: SecretValue,
}

impl CreateSecretVersionRequest {
    /// Creates a tenant-consistent version request.
    ///
    /// `expected_existing_version` is absent only for the first provider
    /// version. A replacement names the exact provider object and immutable
    /// version that must still be current when creation is committed.
    ///
    /// # Errors
    ///
    /// Rejects a provider context from another tenant.
    pub fn new(
        context: ProviderOperationContext,
        secret: SecretDescriptor,
        expected_existing_version: Option<ExistingSecretVersion>,
        value: SecretValue,
    ) -> Result<Self, ModelError> {
        validate_secret_context(&context, &secret)?;
        Ok(Self {
            context,
            secret,
            expected_existing_version,
            value,
        })
    }

    /// Returns the tenant and idempotency/audit correlation for the write.
    #[must_use]
    pub const fn context(&self) -> &ProviderOperationContext {
        &self.context
    }

    /// Returns the stable logical secret identity and exposure ceiling.
    #[must_use]
    pub const fn secret(&self) -> &SecretDescriptor {
        &self.secret
    }

    /// Returns the exact provider version that must still be current, or
    /// `None` when the adapter must create the first version.
    #[must_use]
    pub const fn expected_existing_version(&self) -> Option<&ExistingSecretVersion> {
        self.expected_existing_version.as_ref()
    }

    /// Returns the bounded plaintext for this new immutable version.
    ///
    /// Calling [`SecretValue::expose_secret`] crosses the plaintext trust
    /// boundary; adapters must not log or retain the exposed bytes.
    #[must_use]
    pub const fn value(&self) -> &SecretValue {
        &self.value
    }
}

/// Value-free intent used only to reconcile an ambiguous immutable-version
/// creation.
///
/// This request deliberately omits [`SecretValue`]. It repeats the original
/// create's tenant, durable request identifier, exact logical descriptor, and
/// exact optional predecessor so an adapter can look up that immutable intent
/// without receiving plaintext or authority to write. It is non-cloneable and
/// non-serializable so reconciliation has one explicit in-process owner. Every
/// retained identifier is independently bounded by its public value type.
#[derive(Debug, Eq, PartialEq)]
pub struct ReconcileCreateSecretVersionRequest {
    context: ProviderOperationContext,
    secret: SecretDescriptor,
    expected_existing_version: Option<ExistingSecretVersion>,
}

impl ReconcileCreateSecretVersionRequest {
    /// Creates a tenant-consistent reconciliation request for one original
    /// create intent.
    ///
    /// The context's request identifier must be the same durable identifier
    /// used by the original [`CreateSecretVersionRequest`]. `secret` and
    /// `expected_existing_version` must also be byte-for-byte the original
    /// logical identity and optional predecessor. A different intent under the
    /// same request identifier is a provider conflict or integrity failure,
    /// never a not-committed result.
    ///
    /// # Errors
    ///
    /// Rejects a provider context from another tenant.
    pub fn new(
        context: ProviderOperationContext,
        secret: SecretDescriptor,
        expected_existing_version: Option<ExistingSecretVersion>,
    ) -> Result<Self, ModelError> {
        validate_secret_context(&context, &secret)?;
        Ok(Self {
            context,
            secret,
            expected_existing_version,
        })
    }

    /// Returns the tenant and durable request identity of the original create.
    #[must_use]
    pub const fn context(&self) -> &ProviderOperationContext {
        &self.context
    }

    /// Returns the exact logical descriptor from the original create.
    #[must_use]
    pub const fn secret(&self) -> &SecretDescriptor {
        &self.secret
    }

    /// Returns the original create's exact optional predecessor identity.
    #[must_use]
    pub const fn expected_existing_version(&self) -> Option<&ExistingSecretVersion> {
        self.expected_existing_version.as_ref()
    }
}

/// Provider acknowledgement of one newly immutable version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreatedSecretVersion {
    locator: ProviderSecretLocator,
    version: ProviderVersionId,
}

impl CreatedSecretVersion {
    /// Records the provider object and exact immutable version acknowledged by
    /// a successful create operation.
    #[must_use]
    pub const fn new(locator: ProviderSecretLocator, version: ProviderVersionId) -> Self {
        Self { locator, version }
    }

    /// Returns the opaque provider object containing the new version.
    #[must_use]
    pub const fn locator(&self) -> &ProviderSecretLocator {
        &self.locator
    }

    /// Returns the opaque identity of the newly created immutable version.
    #[must_use]
    pub const fn version(&self) -> &ProviderVersionId {
        &self.version
    }
}

/// Closed, value-free result of reconciling one ambiguous create intent.
///
/// Reconciliation is strictly observational. Neither outcome authorizes a new
/// create attempt, and retrying reconciliation may only repeat the same exact
/// non-mutating lookup.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "create reconciliation must be handled without retrying creation"]
pub enum ReconcileCreateSecretVersionOutcome {
    /// The provider had already committed this exact create intent.
    ///
    /// The returned locator and version must come from the provider's durable
    /// record for the request's exact tenant, request identifier, logical
    /// descriptor, and optional predecessor. A provider must fail closed when
    /// any recorded intent field differs.
    AlreadyCommitted(CreatedSecretVersion),
    /// The provider proves the exact create neither committed nor can commit.
    ///
    /// This result requires the original operation to be quiescent and rules
    /// out a delayed provider write. It is terminal recovery evidence, not
    /// permission to invoke [`SecretProvider::create_version`] again.
    DefinitivelyNotCommitted,
}

impl ReconcileCreateSecretVersionOutcome {
    /// Returns the exact already-committed provider result, when present.
    #[must_use]
    pub const fn already_committed(&self) -> Option<&CreatedSecretVersion> {
        match self {
            Self::AlreadyCommitted(created) => Some(created),
            Self::DefinitivelyNotCommitted => None,
        }
    }
}

/// Exact-version workload resolution request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolveSecretVersionRequest {
    context: ProviderOperationContext,
    workload: WorkloadContext,
    secret: SecretDescriptor,
    locator: ProviderSecretLocator,
    version: ProviderVersionId,
}

impl ResolveSecretVersionRequest {
    /// Creates a tenant- and scope-consistent exact-version request.
    ///
    /// # Errors
    ///
    /// Rejects cross-tenant requests and secrets whose logical scope does not
    /// enclose the resolving workload.
    pub fn new(
        context: ProviderOperationContext,
        workload: WorkloadContext,
        secret: SecretDescriptor,
        locator: ProviderSecretLocator,
        version: ProviderVersionId,
    ) -> Result<Self, ModelError> {
        validate_secret_context(&context, &secret)?;
        if !secret.scope().encloses(workload.scope()) {
            return Err(ModelError::WorkloadScopeMismatch);
        }
        Ok(Self {
            context,
            workload,
            secret,
            locator,
            version,
        })
    }

    /// Returns the tenant and idempotency/audit correlation for the read.
    #[must_use]
    pub const fn context(&self) -> &ProviderOperationContext {
        &self.context
    }

    /// Returns the exact workload authorized to receive the value.
    #[must_use]
    pub const fn workload(&self) -> &WorkloadContext {
        &self.workload
    }

    /// Returns the logical secret and its enforced exposure ceiling.
    #[must_use]
    pub const fn secret(&self) -> &SecretDescriptor {
        &self.secret
    }

    /// Returns the opaque provider object to resolve.
    #[must_use]
    pub const fn locator(&self) -> &ProviderSecretLocator {
        &self.locator
    }

    /// Returns the exact immutable provider version to resolve.
    #[must_use]
    pub const fn version(&self) -> &ProviderVersionId {
        &self.version
    }
}

/// Provider lease attached to a dynamically resolved value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderLease {
    id: ProviderLeaseId,
    expires_at: ProviderLeaseExpiration,
}

impl ProviderLease {
    /// Associates a provider-owned lease identity with its absolute expiry.
    #[must_use]
    pub const fn new(id: ProviderLeaseId, expires_at: ProviderLeaseExpiration) -> Self {
        Self { id, expires_at }
    }

    /// Returns the opaque provider lease identity.
    #[must_use]
    pub const fn id(&self) -> &ProviderLeaseId {
        &self.id
    }

    /// Returns the lease's absolute expiration time.
    #[must_use]
    pub const fn expires_at(&self) -> ProviderLeaseExpiration {
        self.expires_at
    }
}

/// Positive Unix timestamp representable by a durable signed 64-bit column.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProviderLeaseExpiration(NonZeroU64);

impl ProviderLeaseExpiration {
    /// Creates a provider lease expiry from Unix seconds.
    ///
    /// # Errors
    ///
    /// Rejects zero and values larger than `i64::MAX`.
    pub fn from_unix_seconds(value: u64) -> Result<Self, ProviderLeaseExpirationError> {
        if value > i64::MAX as u64 {
            return Err(ProviderLeaseExpirationError);
        }
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(ProviderLeaseExpirationError)
    }

    /// Returns the positive Unix timestamp in seconds.
    #[must_use]
    pub const fn as_unix_seconds(self) -> u64 {
        self.0.get()
    }
}

/// A lease expiry is zero or cannot be represented by the durable signed
/// 64-bit timestamp contract.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("provider lease expiration is invalid")]
pub struct ProviderLeaseExpirationError;

/// Resolved exact version and optional dynamic provider lease.
///
/// This type is intentionally non-cloneable and non-serializable because it
/// owns plaintext secret material.
#[derive(Debug)]
pub struct ResolvedSecretVersion {
    value: SecretValue,
    version: ProviderVersionId,
    lease: Option<ProviderLease>,
}

impl ResolvedSecretVersion {
    /// Packages bounded plaintext from the requested exact version and its
    /// optional dynamic lease.
    #[must_use]
    pub const fn new(
        value: SecretValue,
        version: ProviderVersionId,
        lease: Option<ProviderLease>,
    ) -> Self {
        Self {
            value,
            version,
            lease,
        }
    }

    /// Returns the bounded plaintext resolved for the authorized workload.
    ///
    /// Calling [`SecretValue::expose_secret`] crosses the plaintext trust
    /// boundary; the caller must not log or retain the exposed bytes.
    #[must_use]
    pub const fn value(&self) -> &SecretValue {
        &self.value
    }

    /// Returns the provider's exact version identity for the plaintext.
    #[must_use]
    pub const fn version(&self) -> &ProviderVersionId {
        &self.version
    }

    /// Returns the dynamic lease that must be renewed or revoked, when the
    /// provider issued one.
    #[must_use]
    pub const fn lease(&self) -> Option<&ProviderLease> {
        self.lease.as_ref()
    }
}

/// Exact-version destruction request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestroySecretVersionRequest {
    context: ProviderOperationContext,
    secret: SecretDescriptor,
    locator: ProviderSecretLocator,
    version: ProviderVersionId,
}

impl DestroySecretVersionRequest {
    /// Creates a tenant-consistent destruction request.
    ///
    /// # Errors
    ///
    /// Rejects a provider context from another tenant.
    pub fn new(
        context: ProviderOperationContext,
        secret: SecretDescriptor,
        locator: ProviderSecretLocator,
        version: ProviderVersionId,
    ) -> Result<Self, ModelError> {
        validate_secret_context(&context, &secret)?;
        Ok(Self {
            context,
            secret,
            locator,
            version,
        })
    }

    /// Returns the tenant and idempotency/audit correlation for the destroy.
    #[must_use]
    pub const fn context(&self) -> &ProviderOperationContext {
        &self.context
    }

    /// Returns the stable logical secret whose provider version is destroyed.
    #[must_use]
    pub const fn secret(&self) -> &SecretDescriptor {
        &self.secret
    }

    /// Returns the opaque provider object containing the version.
    #[must_use]
    pub const fn locator(&self) -> &ProviderSecretLocator {
        &self.locator
    }

    /// Returns the exact immutable provider version to destroy.
    #[must_use]
    pub const fn version(&self) -> &ProviderVersionId {
        &self.version
    }
}

/// Dynamic lease renewal request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenewProviderLeaseRequest {
    context: ProviderOperationContext,
    workload: WorkloadContext,
    lease_id: ProviderLeaseId,
}

impl RenewProviderLeaseRequest {
    /// Creates a tenant-consistent lease renewal request.
    ///
    /// # Errors
    ///
    /// Rejects a provider context from another tenant than the workload.
    pub fn new(
        context: ProviderOperationContext,
        workload: WorkloadContext,
        lease_id: ProviderLeaseId,
    ) -> Result<Self, ModelError> {
        if context.tenant_id() != workload.scope().tenant_id() {
            return Err(ModelError::TenantMismatch);
        }
        Ok(Self {
            context,
            workload,
            lease_id,
        })
    }

    /// Returns the tenant and idempotency/audit correlation for the renewal.
    #[must_use]
    pub const fn context(&self) -> &ProviderOperationContext {
        &self.context
    }

    /// Returns the exact workload that still owns the dynamic lease.
    #[must_use]
    pub const fn workload(&self) -> &WorkloadContext {
        &self.workload
    }

    /// Returns the opaque provider lease to renew.
    #[must_use]
    pub const fn lease_id(&self) -> &ProviderLeaseId {
        &self.lease_id
    }
}

/// Dynamic lease revocation request used by durable cleanup workers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeProviderLeaseRequest {
    context: ProviderOperationContext,
    lease_id: ProviderLeaseId,
}

impl RevokeProviderLeaseRequest {
    /// Creates a revocation request for one exact provider lease.
    ///
    /// Durable cleanup may run after the originating workload context is no
    /// longer available, so this request retains only tenant/audit correlation
    /// and the provider-owned lease identity.
    #[must_use]
    pub const fn new(context: ProviderOperationContext, lease_id: ProviderLeaseId) -> Self {
        Self { context, lease_id }
    }

    /// Returns the tenant and idempotency/audit correlation for the revocation.
    #[must_use]
    pub const fn context(&self) -> &ProviderOperationContext {
        &self.context
    }

    /// Returns the exact opaque provider lease to revoke.
    #[must_use]
    pub const fn lease_id(&self) -> &ProviderLeaseId {
        &self.lease_id
    }
}

/// Runtime-pluggable immutable secret version provider.
///
/// Implementations operate only after a higher-level service has performed
/// authorization, policy evaluation, version pinning, and workload fencing.
/// They must return sanitized errors and must never cache one resolved value
/// across tenants, workloads, locators, or versions. Every durable value copy
/// must remain encrypted according to the adapter's mandatory
/// [`SecretAtRestProtection`] attestation; temporary plaintext must not be
/// written to durable staging, swap, crash dumps, or diagnostics.
#[async_trait]
pub trait SecretProvider: fmt::Debug + Send + Sync {
    /// Returns the canonical non-secret identity used to select this adapter.
    fn provider_id(&self) -> &SecretProviderId;

    /// Returns the adapter's validated optional-operation declaration.
    fn capabilities(&self) -> &ProviderCapabilities;

    /// Attests the mandatory encryption boundary used for every durable value.
    ///
    /// Implementations choosing provider-managed encryption are responsible
    /// for verifying that provider configuration before the adapter is made
    /// available. This declaration never permits plaintext persistence.
    fn at_rest_protection(&self) -> SecretAtRestProtection;

    /// Returns a sanitized health classification for readiness and management
    /// surfaces.
    ///
    /// # Errors
    ///
    /// Returns a sanitized provider failure if health cannot be determined.
    async fn health(
        &self,
        context: &ProviderOperationContext,
    ) -> Result<ProviderHealth, ProviderError>;

    /// Creates one immutable provider version from bounded plaintext.
    ///
    /// Implementations must advertise [`ProviderCapability::CreateVersion`]
    /// and use the request identifier for idempotency and audit correlation.
    /// Replacements must compare the exact expected locator and version to the
    /// current provider head atomically with creation; stale or mismatched
    /// expectations fail closed.
    ///
    /// # Errors
    ///
    /// Returns a sanitized provider failure; error diagnostics must never
    /// contain plaintext or provider response bodies.
    async fn create_version(
        &self,
        request: CreateSecretVersionRequest,
    ) -> Result<CreatedSecretVersion, ProviderError>;

    /// Reconciles one ambiguous create through an exact, non-mutating lookup.
    ///
    /// The default rejects the operation as unsupported. Implementations must
    /// advertise both [`ProviderCapability::CreateVersion`] and
    /// [`ProviderCapability::ReconcileCreateVersion`] before overriding it.
    /// They must bind the durable request identifier to the request's exact
    /// tenant, logical descriptor, and optional predecessor, and may return
    /// [`ReconcileCreateSecretVersionOutcome::AlreadyCommitted`] only for the
    /// immutable result that was committed by that original intent. A missing
    /// or mismatched record must never fall back to a logical-secret lookup.
    ///
    /// This method must not create, replace, repair, import, or otherwise
    /// mutate a provider version. Retrying it may only repeat the same lookup;
    /// neither an error nor a definitively-not-committed result authorizes a
    /// caller or adapter to invoke creation again.
    ///
    /// # Errors
    ///
    /// Returns a sanitized provider failure if reconciliation is unsupported,
    /// unavailable, ambiguous, or finds durable intent disagreement.
    async fn reconcile_create_version(
        &self,
        _request: ReconcileCreateSecretVersionRequest,
    ) -> Result<ReconcileCreateSecretVersionOutcome, ProviderError> {
        Err(ProviderError::unsupported())
    }

    /// Resolves one exact immutable version for one already-authorized and
    /// fenced workload.
    ///
    /// Implementations must not fall back to another locator or version, or
    /// cache the resulting plaintext across workload boundaries.
    ///
    /// # Errors
    ///
    /// Returns a sanitized provider failure; error diagnostics must never
    /// contain plaintext or provider response bodies.
    async fn resolve_version(
        &self,
        request: ResolveSecretVersionRequest,
    ) -> Result<ResolvedSecretVersion, ProviderError>;

    /// Permanently destroys one exact immutable version.
    ///
    /// Implementations must advertise [`ProviderCapability::DestroyVersion`]
    /// and must not interpret the request as destruction of every version at
    /// the locator.
    ///
    /// # Errors
    ///
    /// Returns a sanitized provider failure if exact-version destruction does
    /// not complete.
    async fn destroy_version(
        &self,
        request: DestroySecretVersionRequest,
    ) -> Result<(), ProviderError>;

    /// Renews one dynamic lease for its exact workload owner.
    ///
    /// The default rejects the operation as unsupported. Implementations must
    /// advertise both [`ProviderCapability::DynamicLeases`] and
    /// [`ProviderCapability::RenewLeases`] before overriding it.
    ///
    /// # Errors
    ///
    /// Returns a sanitized provider failure if renewal is unsupported or does
    /// not complete.
    async fn renew_lease(
        &self,
        _request: RenewProviderLeaseRequest,
    ) -> Result<ProviderLease, ProviderError> {
        Err(ProviderError::unsupported())
    }

    /// Revokes one exact dynamic lease during workload or recovery cleanup.
    ///
    /// The default rejects the operation as unsupported. Implementations must
    /// advertise both [`ProviderCapability::DynamicLeases`] and
    /// [`ProviderCapability::RevokeLeases`] before overriding it.
    ///
    /// # Errors
    ///
    /// Returns a sanitized provider failure if revocation is unsupported or
    /// does not complete.
    async fn revoke_lease(
        &self,
        _request: RevokeProviderLeaseRequest,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::unsupported())
    }
}
