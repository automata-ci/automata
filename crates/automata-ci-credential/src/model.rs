use std::{collections::BTreeMap, fmt};

use automata_ci_auth::{secret::SecretString, time::UnixTimestamp};
use automata_ci_scm::{RepositoryId, ScmProviderId};
use thiserror::Error;

const MAX_OPAQUE_ID_BYTES: usize = 256;
const MAX_WORKLOAD_ID_BYTES: usize = 512;
const MAX_PERMISSION_NAME_BYTES: usize = 64;
const MAX_PERMISSIONS: usize = 64;
const MAX_MINIMUM_VALIDITY_SECONDS: u64 = 3_600;

/// Provider-native stable identifier for a resource such as a repository,
/// application, or installation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderResourceId(String);

impl ProviderResourceId {
    /// Creates a bounded printable ASCII identifier.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, whitespace-containing, or control-containing
    /// values.
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_OPAQUE_ID_BYTES {
            return Err(ModelError::InvalidProviderResourceId);
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'/' | b'\\'))
        {
            return Err(ModelError::InvalidProviderResourceId);
        }
        Ok(Self(value))
    }

    /// Returns the exact provider-native identifier.
    ///
    /// The identifier is intended for audit correlation rather than display and
    /// must never contain secret material.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable identity of one scheduled workload attempt.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkloadIdentity(String);

impl WorkloadIdentity {
    /// Creates a bounded identity suitable for audit correlation.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, whitespace-containing, or control-containing
    /// values. Provider credentials must never be embedded in this identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_WORKLOAD_ID_BYTES {
            return Err(ModelError::InvalidWorkloadIdentity);
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'\\')
        {
            return Err(ModelError::InvalidWorkloadIdentity);
        }
        Ok(Self(value))
    }

    /// Returns the exact workload-attempt identity.
    ///
    /// This value is an audit and isolation subject, not a bearer credential or
    /// an idempotency key for provider operations.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Provider-neutral access level ordered from least to most privileged.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PermissionLevel {
    /// Allows observation without repository mutation.
    Read,
    /// Allows repository mutation but does not imply administrative control.
    Write,
    /// Allows provider-defined administrative operations.
    Admin,
}

impl PermissionLevel {
    /// Returns the canonical lowercase wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Admin => "admin",
        }
    }

    /// Parses a canonical provider response level.
    ///
    /// # Errors
    ///
    /// Rejects unknown or noncanonical values.
    pub fn parse(value: &str) -> Result<Self, ModelError> {
        match value {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            "admin" => Ok(Self::Admin),
            _ => Err(ModelError::InvalidPermissionLevel),
        }
    }
}

/// Canonical provider permission name.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PermissionName(String);

impl PermissionName {
    /// Creates a lowercase snake-case permission identifier.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or noncanonical names.
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_PERMISSION_NAME_BYTES {
            return Err(ModelError::InvalidPermissionName);
        }
        if !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase() || (index > 0 && (byte.is_ascii_digit() || byte == b'_'))
        }) || value.ends_with('_')
            || value.contains("__")
        {
            return Err(ModelError::InvalidPermissionName);
        }
        Ok(Self(value))
    }

    /// Returns the canonical provider-neutral permission name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Bounded exact permission map.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionSet(BTreeMap<PermissionName, PermissionLevel>);

impl PermissionSet {
    /// Builds a non-empty, duplicate-free, bounded permission set.
    ///
    /// # Errors
    ///
    /// Rejects empty sets, duplicate names, or more than 64 permissions.
    pub fn new<I>(permissions: I) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = (PermissionName, PermissionLevel)>,
    {
        let mut values = BTreeMap::new();
        for (name, level) in permissions {
            if values.len() >= MAX_PERMISSIONS {
                return Err(ModelError::TooManyPermissions);
            }
            if values.insert(name, level).is_some() {
                return Err(ModelError::DuplicatePermission);
            }
        }
        if values.is_empty() {
            return Err(ModelError::EmptyPermissions);
        }
        Ok(Self(values))
    }

    /// Iterates over the complete map in canonical permission-name order.
    #[must_use]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&PermissionName, PermissionLevel)> {
        self.0.iter().map(|(name, level)| (name, *level))
    }

    /// Returns the number of exact permission grants.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Reports whether the set contains no grants.
    ///
    /// Values produced by [`Self::new`] are always non-empty; this method is
    /// provided for conventional collection inspection.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Exact repository selected for one credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryScope {
    provider: ScmProviderId,
    repository: RepositoryId,
    stable_id: ProviderResourceId,
}

impl RepositoryScope {
    /// Binds a provider, repository name, and provider-native stable ID.
    ///
    /// Together the fields identify the sole authorization audience; the stable
    /// ID prevents a repository rename from changing its identity. The caller
    /// must obtain the ID and name from the same trusted repository observation.
    /// Provider adapters must reject any response that does not match this exact
    /// scope.
    #[must_use]
    pub const fn new(
        provider: ScmProviderId,
        repository: RepositoryId,
        stable_id: ProviderResourceId,
    ) -> Self {
        Self {
            provider,
            repository,
            stable_id,
        }
    }

    /// Returns the source-control provider that owns the repository.
    #[must_use]
    pub const fn provider(&self) -> &ScmProviderId {
        &self.provider
    }

    /// Returns the provider-qualified repository name.
    #[must_use]
    pub const fn repository(&self) -> &RepositoryId {
        &self.repository
    }

    /// Returns the repository's provider-native stable identifier.
    #[must_use]
    pub const fn stable_id(&self) -> &ProviderResourceId {
        &self.stable_id
    }
}

/// Caller-required lifetime remaining after issuance completes.
///
/// The default validity floor is 300 seconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MinimumValidity(u64);

impl MinimumValidity {
    /// Creates a nonzero validity floor no greater than one hour.
    ///
    /// # Errors
    ///
    /// Rejects zero or values greater than 3,600 seconds.
    pub const fn from_seconds(seconds: u64) -> Result<Self, ModelError> {
        if seconds == 0 || seconds > MAX_MINIMUM_VALIDITY_SECONDS {
            return Err(ModelError::InvalidMinimumValidity);
        }
        Ok(Self(seconds))
    }

    /// Returns the required post-issuance lifetime in seconds.
    #[must_use]
    pub const fn as_seconds(self) -> u64 {
        self.0
    }
}

impl Default for MinimumValidity {
    fn default() -> Self {
        Self(300)
    }
}

/// Complete least-privilege credential request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryCredentialRequest {
    workload: WorkloadIdentity,
    repository: RepositoryScope,
    permissions: PermissionSet,
    minimum_validity: MinimumValidity,
}

impl RepositoryCredentialRequest {
    /// Creates one exact workload credential request.
    ///
    /// The request binds the workload identity, sole repository audience,
    /// complete permission map, and required remaining lease lifetime. It is
    /// immutable but is not an operation or idempotency identifier: repeated
    /// submission may cause separate provider-side issuance operations.
    #[must_use]
    pub const fn new(
        workload: WorkloadIdentity,
        repository: RepositoryScope,
        permissions: PermissionSet,
        minimum_validity: MinimumValidity,
    ) -> Self {
        Self {
            workload,
            repository,
            permissions,
            minimum_validity,
        }
    }

    /// Returns the workload attempt authorized to receive the credential.
    #[must_use]
    pub const fn workload(&self) -> &WorkloadIdentity {
        &self.workload
    }

    /// Returns the credential's sole repository audience.
    #[must_use]
    pub const fn repository(&self) -> &RepositoryScope {
        &self.repository
    }

    /// Returns the complete exact permission map requested from the provider.
    #[must_use]
    pub const fn permissions(&self) -> &PermissionSet {
        &self.permissions
    }

    /// Returns the minimum lifetime that must remain when issuance completes.
    #[must_use]
    pub const fn minimum_validity(&self) -> MinimumValidity {
        self.minimum_validity
    }
}

/// Non-secret provider attribution for audit records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialProvenance {
    provider: ScmProviderId,
    issuer: ProviderResourceId,
    subject: ProviderResourceId,
}

impl CredentialProvenance {
    /// Records verified non-secret attribution from a provider response.
    ///
    /// The issuer identifies the provider principal that minted the credential;
    /// the subject identifies the provider resource to which it was issued.
    /// Callers must construct this only from trusted provider data.
    #[must_use]
    pub const fn new(
        provider: ScmProviderId,
        issuer: ProviderResourceId,
        subject: ProviderResourceId,
    ) -> Self {
        Self {
            provider,
            issuer,
            subject,
        }
    }

    /// Returns the provider that issued the credential.
    #[must_use]
    pub const fn provider(&self) -> &ScmProviderId {
        &self.provider
    }

    /// Returns the provider-native identity of the issuing principal.
    #[must_use]
    pub const fn issuer(&self) -> &ProviderResourceId {
        &self.issuer
    }

    /// Returns the provider-native identity of the credential subject.
    #[must_use]
    pub const fn subject(&self) -> &ProviderResourceId {
        &self.subject
    }
}

/// Issued secret bound to one exact workload request.
///
/// This type intentionally does not implement `Clone`, `Display`, or
/// `Serialize`, so ownership of the credential must move across execution
/// boundaries. Debug output redacts the secret, and the underlying secret
/// storage is zeroized on drop. Consumers must enforce [`Self::expires_at`];
/// reaching that timestamp is not proof that the provider has revoked the
/// credential.
pub struct IssuedRepositoryCredential {
    secret: SecretString,
    workload: WorkloadIdentity,
    repository: RepositoryScope,
    permissions: PermissionSet,
    issued_at: UnixTimestamp,
    expires_at: UnixTimestamp,
    provenance: CredentialProvenance,
}

impl IssuedRepositoryCredential {
    /// Creates a credential after a provider adapter has verified its response.
    ///
    /// # Errors
    ///
    /// Rejects provider disagreement and credentials that do not satisfy the
    /// request's validity floor at `issued_at`.
    pub fn new(
        secret: SecretString,
        request: &RepositoryCredentialRequest,
        issued_at: UnixTimestamp,
        expires_at: UnixTimestamp,
        provenance: CredentialProvenance,
    ) -> Result<Self, ModelError> {
        if provenance.provider() != request.repository().provider() {
            return Err(ModelError::ProviderMismatch);
        }
        let required_expiry = issued_at
            .checked_add(request.minimum_validity().as_seconds())
            .map_err(|_| ModelError::InvalidExpiration)?;
        if expires_at < required_expiry {
            return Err(ModelError::InvalidExpiration);
        }
        Ok(Self {
            secret,
            workload: request.workload().clone(),
            repository: request.repository().clone(),
            permissions: request.permissions().clone(),
            issued_at,
            expires_at,
            provenance,
        })
    }

    /// Explicitly borrows the bearer secret across the redaction boundary.
    ///
    /// Keep the returned reference within the smallest possible scope. It must
    /// not be formatted, logged, serialized, or retained beyond the credential
    /// lease.
    #[must_use]
    pub const fn secret(&self) -> &SecretString {
        &self.secret
    }

    /// Returns the exact workload attempt that owns this credential.
    #[must_use]
    pub const fn workload(&self) -> &WorkloadIdentity {
        &self.workload
    }

    /// Returns the credential's sole repository audience.
    #[must_use]
    pub const fn repository(&self) -> &RepositoryScope {
        &self.repository
    }

    /// Returns the complete permission set verified at issuance.
    #[must_use]
    pub const fn permissions(&self) -> &PermissionSet {
        &self.permissions
    }

    /// Returns the timestamp used to evaluate the issued lease's validity.
    #[must_use]
    pub const fn issued_at(&self) -> UnixTimestamp {
        self.issued_at
    }

    /// Returns the hard upper bound on the credential's usable lifetime.
    ///
    /// Consumers must stop using and exposing the secret no later than this
    /// timestamp. Provider revocation, when supported, is a separate lifecycle
    /// operation.
    #[must_use]
    pub const fn expires_at(&self) -> UnixTimestamp {
        self.expires_at
    }

    /// Returns verified, non-secret provider attribution for audit records.
    #[must_use]
    pub const fn provenance(&self) -> &CredentialProvenance {
        &self.provenance
    }
}

impl fmt::Debug for IssuedRepositoryCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedRepositoryCredential")
            .field("secret", &"[redacted]")
            .field("workload", &self.workload)
            .field("repository", &self.repository)
            .field("permissions", &self.permissions)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("provenance", &self.provenance)
            .finish()
    }
}

/// Failure to construct a canonical credential-domain value.
///
/// Variants contain no rejected input, provider response, or secret material,
/// so the error is safe to include in diagnostics.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    /// A provider-native resource identifier was empty, oversized, or unsafe.
    #[error("provider resource identifier is invalid")]
    InvalidProviderResourceId,
    /// A workload identity was empty, oversized, or unsafe.
    #[error("workload identity is invalid")]
    InvalidWorkloadIdentity,
    /// A permission name was empty, oversized, or noncanonical.
    #[error("permission name is invalid")]
    InvalidPermissionName,
    /// A permission level was not a canonical provider-neutral value.
    #[error("permission level is invalid")]
    InvalidPermissionLevel,
    /// A request attempted to grant no permissions.
    #[error("permission set must not be empty")]
    EmptyPermissions,
    /// A permission name occurred more than once in the input.
    #[error("permission set contains a duplicate")]
    DuplicatePermission,
    /// A permission set exceeded the fixed cardinality bound.
    #[error("permission set exceeds its bound")]
    TooManyPermissions,
    /// A requested validity floor was zero or exceeded the fixed bound.
    #[error("minimum validity is invalid")]
    InvalidMinimumValidity,
    /// Issuance provenance named a provider different from the repository.
    #[error("credential provider does not match the repository provider")]
    ProviderMismatch,
    /// The issued lease could not satisfy the request's minimum validity.
    #[error("credential expiration is invalid")]
    InvalidExpiration,
}
