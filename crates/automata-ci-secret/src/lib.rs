//! Provider-neutral secret management contracts for Automata.
//!
//! The crate separates a secret's stable logical [`SecretDescriptor`] from the
//! opaque [`ProviderSecretLocator`] and immutable [`ProviderVersionId`] owned by
//! a storage provider. Resolution always names an exact version and carries a
//! repository- or environment-scoped [`WorkloadContext`]; [`SecretScope`] is
//! the maximum exposure boundary that may enclose that workload.
//!
//! Plaintext is accepted only as a bounded [`SecretValue`]. It is zeroized on
//! drop, redacted from `Debug`, deliberately non-cloneable, and exposed only by
//! an explicit accessor at the provider or workload-injection trust boundary.
//! Provider failures retain a closed classification and optional retry timing,
//! never provider response bodies, credentials, storage paths, or secret
//! values. Provider operation contexts bind every request to a tenant and a
//! stable idempotency/audit correlation identifier.
//! Ambiguous creates have a separate value-free reconciliation request that
//! repeats the immutable original intent and permits only a non-mutating lookup
//! of its already-committed outcome; reconciliation never authorizes creation.
//!
//! This crate deliberately contains no persistence, authentication, HTTP, or
//! provider implementation. Callers must authorize access, select and pin the
//! exact version, enforce workload fencing, and audit the operation before
//! invoking a [`SecretProvider`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod model;
mod provider;
mod registry;
mod value;

pub use model::{
    EnvironmentScopeId, ModelError, ProviderRequestId, RepositoryScopeId, SecretDescriptor,
    SecretId, SecretName, SecretScope, TenantScopeId, WorkloadContext, WorkloadId,
};
pub use provider::{
    CreateSecretVersionRequest, CreatedSecretVersion, DestroySecretVersionRequest,
    ExistingSecretVersion, ProviderCapabilities, ProviderCapability, ProviderCapabilityError,
    ProviderError, ProviderErrorKind, ProviderHealth, ProviderLease, ProviderLeaseExpiration,
    ProviderLeaseExpirationError, ProviderLeaseId, ProviderOpaqueIdError, ProviderOperationContext,
    ProviderSecretLocator, ProviderVersionId, ReconcileCreateSecretVersionOutcome,
    ReconcileCreateSecretVersionRequest, RenewProviderLeaseRequest, ResolveSecretVersionRequest,
    ResolvedSecretVersion, RevokeProviderLeaseRequest, SecretAtRestProtection, SecretProvider,
    SecretProviderId, SecretProviderIdError,
};
pub use registry::{
    MAX_REGISTERED_SECRET_PROVIDERS, SecretProviderRegistry, SecretProviderRegistryError,
};
pub use value::{MAX_SECRET_VALUE_BYTES, SecretValue, SecretValueError};
