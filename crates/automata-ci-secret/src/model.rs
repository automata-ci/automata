use thiserror::Error;

const MAX_SCOPE_ID_BYTES: usize = 255;
const MAX_SECRET_NAME_BYTES: usize = 255;

fn valid_scope_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_SCOPE_ID_BYTES && !value.chars().any(char::is_control)
}

macro_rules! scope_identifier {
    ($name:ident, $error:ident, $label:literal) => {
        #[doc = concat!("Validated ", $label, " used by secret policy.")]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Creates a bounded ", $label, ".")]
            ///
            /// # Errors
            ///
            /// Rejects empty, oversized, or control-containing identifiers.
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                valid_scope_id(&value)
                    .then_some(Self(value))
                    .ok_or(ModelError::$error)
            }

            /// Returns the validated identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

scope_identifier!(TenantScopeId, InvalidTenantScopeId, "tenant scope ID");
scope_identifier!(
    RepositoryScopeId,
    InvalidRepositoryScopeId,
    "repository scope ID"
);
scope_identifier!(
    EnvironmentScopeId,
    InvalidEnvironmentScopeId,
    "environment scope ID"
);
scope_identifier!(SecretId, InvalidSecretId, "logical secret ID");
scope_identifier!(
    ProviderRequestId,
    InvalidProviderRequestId,
    "provider request ID"
);
scope_identifier!(WorkloadId, InvalidWorkloadId, "workload ID");

/// Canonical, case-insensitive logical secret name.
///
/// Names use GitHub-compatible ASCII syntax and are stored in uppercase. The
/// `GITHUB_`, `ACTIONS_`, `RUNNER_`, and `AUTOMATA_` namespaces are reserved so
/// user secrets cannot impersonate platform-owned values.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretName(String);

impl SecretName {
    /// Validates and canonicalizes a logical secret name.
    ///
    /// # Errors
    ///
    /// Rejects names that are empty, longer than 255 bytes, begin with a digit,
    /// contain characters other than ASCII letters, digits, or `_`, or use a
    /// platform-reserved prefix.
    pub fn new(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        if value.is_empty() || value.len() > MAX_SECRET_NAME_BYTES || !value.is_ascii() {
            return Err(ModelError::InvalidSecretName);
        }
        let mut bytes = value.bytes();
        let first = bytes.next().ok_or(ModelError::InvalidSecretName)?;
        if !(first.is_ascii_alphabetic() || first == b'_')
            || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(ModelError::InvalidSecretName);
        }

        let canonical = value.to_ascii_uppercase();
        if ["GITHUB_", "ACTIONS_", "RUNNER_", "AUTOMATA_"]
            .iter()
            .any(|prefix| canonical.starts_with(prefix))
        {
            return Err(ModelError::ReservedSecretName);
        }
        Ok(Self(canonical))
    }

    /// Returns the canonical uppercase name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Hierarchical logical scope of one secret.
///
/// A scope always carries its tenant and, for environments, its repository.
/// This prevents an environment or repository identifier from being resolved
/// without its durable parent relationship.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SecretScope {
    /// Every authorized workload in one tenant may be within the exposure
    /// ceiling.
    Tenant {
        /// Tenant that owns the secret.
        tenant: TenantScopeId,
    },
    /// Only workloads in one repository may be within the exposure ceiling.
    Repository {
        /// Tenant that owns the repository and secret.
        tenant: TenantScopeId,
        /// Repository whose workloads may receive the secret.
        repository: RepositoryScopeId,
    },
    /// Only workloads in one repository environment may receive the secret.
    Environment {
        /// Tenant that owns the repository and secret.
        tenant: TenantScopeId,
        /// Repository that owns the environment.
        repository: RepositoryScopeId,
        /// Environment whose workloads may receive the secret.
        environment: EnvironmentScopeId,
    },
}

impl SecretScope {
    /// Creates a tenant-wide exposure ceiling.
    #[must_use]
    pub const fn tenant(tenant: TenantScopeId) -> Self {
        Self::Tenant { tenant }
    }

    /// Creates a repository exposure ceiling under its exact tenant.
    #[must_use]
    pub const fn repository(tenant: TenantScopeId, repository: RepositoryScopeId) -> Self {
        Self::Repository { tenant, repository }
    }

    /// Creates an environment exposure ceiling under its exact repository and
    /// tenant.
    #[must_use]
    pub const fn environment(
        tenant: TenantScopeId,
        repository: RepositoryScopeId,
        environment: EnvironmentScopeId,
    ) -> Self {
        Self::Environment {
            tenant,
            repository,
            environment,
        }
    }

    /// Returns the tenant that owns this scope.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantScopeId {
        match self {
            Self::Tenant { tenant }
            | Self::Repository { tenant, .. }
            | Self::Environment { tenant, .. } => tenant,
        }
    }

    /// Returns the repository for repository and environment scopes.
    #[must_use]
    pub const fn repository_id(&self) -> Option<&RepositoryScopeId> {
        match self {
            Self::Tenant { .. } => None,
            Self::Repository { repository, .. } | Self::Environment { repository, .. } => {
                Some(repository)
            }
        }
    }

    /// Returns the environment for an environment scope.
    #[must_use]
    pub const fn environment_id(&self) -> Option<&EnvironmentScopeId> {
        match self {
            Self::Tenant { .. } | Self::Repository { .. } => None,
            Self::Environment { environment, .. } => Some(environment),
        }
    }

    /// Returns true when `candidate` is this scope or a child of it.
    #[must_use]
    pub fn encloses(&self, candidate: &Self) -> bool {
        if self.tenant_id() != candidate.tenant_id() {
            return false;
        }
        match self {
            Self::Tenant { .. } => true,
            Self::Repository { repository, .. } => {
                candidate.repository_id().is_some_and(|id| id == repository)
            }
            Self::Environment {
                repository,
                environment,
                ..
            } => {
                candidate.repository_id().is_some_and(|id| id == repository)
                    && candidate
                        .environment_id()
                        .is_some_and(|id| id == environment)
            }
        }
    }
}

/// Stable logical identity and policy placement of one secret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretDescriptor {
    id: SecretId,
    name: SecretName,
    scope: SecretScope,
}

impl SecretDescriptor {
    /// Associates a stable logical identity and canonical name with its
    /// immutable exposure ceiling.
    #[must_use]
    pub const fn new(id: SecretId, name: SecretName, scope: SecretScope) -> Self {
        Self { id, name, scope }
    }

    /// Returns the stable logical secret identity.
    #[must_use]
    pub const fn id(&self) -> &SecretId {
        &self.id
    }

    /// Returns the canonical logical name presented to authorized workloads.
    #[must_use]
    pub const fn name(&self) -> &SecretName {
        &self.name
    }

    /// Returns the secret's maximum workload exposure scope.
    #[must_use]
    pub const fn scope(&self) -> &SecretScope {
        &self.scope
    }
}

/// Exact workload identity and repository/environment scope for a resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkloadContext {
    id: WorkloadId,
    scope: SecretScope,
}

impl WorkloadContext {
    /// Creates a repository- or environment-scoped workload context.
    ///
    /// # Errors
    ///
    /// Tenant-only workloads are rejected because executable jobs must belong
    /// to one exact repository.
    pub fn new(id: WorkloadId, scope: SecretScope) -> Result<Self, ModelError> {
        if matches!(scope, SecretScope::Tenant { .. }) {
            return Err(ModelError::InvalidWorkloadScope);
        }
        Ok(Self { id, scope })
    }

    /// Returns the exact workload identity used for authorization, fencing,
    /// and audit correlation.
    #[must_use]
    pub const fn id(&self) -> &WorkloadId {
        &self.id
    }

    /// Returns the workload's exact repository or environment scope.
    #[must_use]
    pub const fn scope(&self) -> &SecretScope {
        &self.scope
    }
}

/// Closed validation failures for logical secret identities and access scope.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    /// A tenant scope identifier is empty, oversized, or contains a control
    /// character.
    #[error("tenant scope ID is invalid")]
    InvalidTenantScopeId,
    /// A repository scope identifier is empty, oversized, or contains a
    /// control character.
    #[error("repository scope ID is invalid")]
    InvalidRepositoryScopeId,
    /// An environment scope identifier is empty, oversized, or contains a
    /// control character.
    #[error("environment scope ID is invalid")]
    InvalidEnvironmentScopeId,
    /// A logical secret identifier is empty, oversized, or contains a control
    /// character.
    #[error("logical secret ID is invalid")]
    InvalidSecretId,
    /// A provider request correlation identifier is empty, oversized, or
    /// contains a control character.
    #[error("provider request ID is invalid")]
    InvalidProviderRequestId,
    /// A workload identifier is empty, oversized, or contains a control
    /// character.
    #[error("workload ID is invalid")]
    InvalidWorkloadId,
    /// A logical name does not satisfy the bounded ASCII secret-name grammar.
    #[error("secret name is invalid")]
    InvalidSecretName,
    /// A logical name occupies a namespace reserved for platform-owned
    /// values.
    #[error("secret name uses a reserved platform prefix")]
    ReservedSecretName,
    /// An executable workload was given a tenant-only scope instead of an
    /// exact repository or environment.
    #[error("workload secret scope must identify a repository")]
    InvalidWorkloadScope,
    /// A provider operation was correlated to a different tenant than the
    /// referenced secret or workload.
    #[error("provider operation tenant does not match the secret scope")]
    TenantMismatch,
    /// A workload falls outside the secret's immutable exposure ceiling.
    #[error("secret scope does not enclose the resolving workload")]
    WorkloadScopeMismatch,
}
