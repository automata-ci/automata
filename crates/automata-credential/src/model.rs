use std::{collections::BTreeMap, fmt};

use automata_auth::{secret::SecretString, time::UnixTimestamp};
use automata_scm::{RepositoryId, ScmProviderId};
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

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Provider-neutral access level ordered from least to most privileged.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PermissionLevel {
    Read,
    Write,
    Admin,
}

impl PermissionLevel {
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

    #[must_use]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&PermissionName, PermissionLevel)> {
        self.0.iter().map(|(name, level)| (name, *level))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

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

    #[must_use]
    pub const fn provider(&self) -> &ScmProviderId {
        &self.provider
    }

    #[must_use]
    pub const fn repository(&self) -> &RepositoryId {
        &self.repository
    }

    #[must_use]
    pub const fn stable_id(&self) -> &ProviderResourceId {
        &self.stable_id
    }
}

/// Caller-required lifetime remaining after issuance completes.
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

    #[must_use]
    pub const fn workload(&self) -> &WorkloadIdentity {
        &self.workload
    }

    #[must_use]
    pub const fn repository(&self) -> &RepositoryScope {
        &self.repository
    }

    #[must_use]
    pub const fn permissions(&self) -> &PermissionSet {
        &self.permissions
    }

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

    #[must_use]
    pub const fn provider(&self) -> &ScmProviderId {
        &self.provider
    }

    #[must_use]
    pub const fn issuer(&self) -> &ProviderResourceId {
        &self.issuer
    }

    #[must_use]
    pub const fn subject(&self) -> &ProviderResourceId {
        &self.subject
    }
}

/// Issued secret bound to one exact workload request.
///
/// This type intentionally does not implement `Clone`, `Display`, or `Serialize`.
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

    /// Explicitly crosses the secret boundary.
    #[must_use]
    pub const fn secret(&self) -> &SecretString {
        &self.secret
    }

    #[must_use]
    pub const fn workload(&self) -> &WorkloadIdentity {
        &self.workload
    }

    #[must_use]
    pub const fn repository(&self) -> &RepositoryScope {
        &self.repository
    }

    #[must_use]
    pub const fn permissions(&self) -> &PermissionSet {
        &self.permissions
    }

    #[must_use]
    pub const fn issued_at(&self) -> UnixTimestamp {
        self.issued_at
    }

    #[must_use]
    pub const fn expires_at(&self) -> UnixTimestamp {
        self.expires_at
    }

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

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("provider resource identifier is invalid")]
    InvalidProviderResourceId,
    #[error("workload identity is invalid")]
    InvalidWorkloadIdentity,
    #[error("permission name is invalid")]
    InvalidPermissionName,
    #[error("permission level is invalid")]
    InvalidPermissionLevel,
    #[error("permission set must not be empty")]
    EmptyPermissions,
    #[error("permission set contains a duplicate")]
    DuplicatePermission,
    #[error("permission set exceeds its bound")]
    TooManyPermissions,
    #[error("minimum validity is invalid")]
    InvalidMinimumValidity,
    #[error("credential provider does not match the repository provider")]
    ProviderMismatch,
    #[error("credential expiration is invalid")]
    InvalidExpiration,
}
