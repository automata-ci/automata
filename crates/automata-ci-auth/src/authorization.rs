use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::human::{PrincipalId, TenantId};

use crate::output_policy::OutputKind;
pub use crate::output_policy::{
    OutputVisibility, RepositoryPublicationPolicy, SecretExposureClass,
};

const MAX_NAME_LENGTH: usize = 128;

/// Canonical repository-read permissions eligible for publication.
///
/// Publication deliberately recognizes a closed set. A newly added permission is
/// private until this module explicitly classifies it as a read operation and maps
/// it to one publication surface.
pub mod repository_read_permissions {
    /// Allows reading repository dashboard metadata.
    pub const REPOSITORY_READ: &str = "repositories:read";
    /// Allows reading workflow dashboard metadata.
    pub const WORKFLOW_READ: &str = "workflows:read";
    /// Allows reading run dashboard metadata.
    pub const RUN_READ: &str = "runs:read";
    /// Allows reading job dashboard metadata.
    pub const JOB_READ: &str = "jobs:read";
    /// Allows reading an authorized job-log stream.
    pub const LOG_READ: &str = "logs:read";
    /// Allows reading authorized artifact metadata.
    pub const ARTIFACT_READ: &str = "artifacts:read";
    /// Allows downloading authorized artifact bytes.
    pub const ARTIFACT_DOWNLOAD: &str = "artifacts:download";
}

macro_rules! policy_name {
    ($name:ident, $label:literal) => {
        #[doc = concat!("A bounded, portable ", $label, " used by RBAC policy.")]
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Creates a validated policy identifier.
            ///
            /// # Errors
            ///
            /// Returns an error when the value is empty, too long, or contains a
            /// character outside the portable policy alphabet.
            pub fn new(value: impl Into<String>) -> Result<Self, PolicyNameError> {
                let value = value.into();
                validate_policy_name(&value, $label)?;
                Ok(Self(value))
            }

            /// Returns the validated policy name.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = PolicyNameError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

policy_name!(RoleName, "role name");
policy_name!(Permission, "permission");

fn validate_policy_name(value: &str, label: &'static str) -> Result<(), PolicyNameError> {
    if value.is_empty() {
        return Err(PolicyNameError::Empty { label });
    }
    if value.len() > MAX_NAME_LENGTH {
        return Err(PolicyNameError::TooLong {
            label,
            maximum: MAX_NAME_LENGTH,
        });
    }
    if !value.bytes().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, b'-' | b'_' | b':' | b'.')
    }) {
        return Err(PolicyNameError::InvalidCharacter { label });
    }
    Ok(())
}

/// Validation failures for role and permission names.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PolicyNameError {
    /// A required policy name was empty.
    #[error("{label} must not be empty")]
    Empty {
        /// Sanitized name of the invalid field.
        label: &'static str,
    },
    /// A policy name exceeded the portable byte limit.
    #[error("{label} must not exceed {maximum} bytes")]
    TooLong {
        /// Sanitized name of the invalid field.
        label: &'static str,
        /// Maximum accepted UTF-8 byte length.
        maximum: usize,
    },
    /// A policy name used a character outside the portable alphabet.
    #[error("{label} contains a character outside the portable policy-name alphabet")]
    InvalidCharacter {
        /// Sanitized name of the invalid field.
        label: &'static str,
    },
}

/// Explicit role-to-permission grants. There are no privileged role names and no
/// administrator bypass: even a role named `administrator` only receives grants
/// present in this policy.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RbacPolicy {
    grants: BTreeMap<RoleName, BTreeSet<Permission>>,
}

impl RbacPolicy {
    /// Creates an explicit role-to-permission policy without privileged aliases.
    pub fn new(grants: BTreeMap<RoleName, BTreeSet<Permission>>) -> Self {
        Self { grants }
    }

    /// Reports whether any supplied role explicitly grants a permission.
    pub fn allows<'a>(
        &'a self,
        roles: impl IntoIterator<Item = &'a RoleName>,
        permission: &Permission,
    ) -> bool {
        roles
            .into_iter()
            .filter_map(|role| self.grants.get(role))
            .any(|permissions| permissions.contains(permission))
    }
}

/// Durable repository identity used by the authorization layer.
///
/// This identifies Automata's repository row, rather than an SCM-native
/// `owner/name` coordinate. Nil and non-canonical UUID text are rejected so route,
/// store, and policy identities cannot compare differently.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RepositoryResourceId(Uuid);

impl RepositoryResourceId {
    /// Parses one canonical, non-nil, hyphenated lowercase UUID.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not a canonical repository UUID.
    pub fn new(value: impl AsRef<str>) -> Result<Self, ResourceIdentityError> {
        let value = value.as_ref();
        let parsed = Uuid::parse_str(value)
            .map_err(|_| ResourceIdentityError::InvalidRepositoryResourceId)?;
        if parsed.is_nil() || parsed.hyphenated().to_string() != value {
            return Err(ResourceIdentityError::InvalidRepositoryResourceId);
        }
        Ok(Self(parsed))
    }

    /// Constructs a repository identity from an already parsed UUID.
    ///
    /// # Errors
    ///
    /// Returns an error for the nil UUID.
    pub const fn from_uuid(value: Uuid) -> Result<Self, ResourceIdentityError> {
        if value.is_nil() {
            return Err(ResourceIdentityError::InvalidRepositoryResourceId);
        }
        Ok(Self(value))
    }

    #[must_use]
    /// Returns the durable repository UUID.
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for RepositoryResourceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for RepositoryResourceId {
    type Err = ResourceIdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for RepositoryResourceId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for RepositoryResourceId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Durable runner-group identity used by the authorization layer.
///
/// This is Automata's runner-group row identity rather than a mutable display
/// label. It follows the same canonical non-nil UUID contract as repository
/// resources so storage and policy comparisons cannot disagree.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RunnerGroupResourceId(Uuid);

impl RunnerGroupResourceId {
    /// Parses one canonical, non-nil, hyphenated lowercase UUID.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not a canonical runner-group UUID.
    pub fn new(value: impl AsRef<str>) -> Result<Self, ResourceIdentityError> {
        let value = value.as_ref();
        let parsed = Uuid::parse_str(value)
            .map_err(|_| ResourceIdentityError::InvalidRunnerGroupResourceId)?;
        if parsed.is_nil() || parsed.hyphenated().to_string() != value {
            return Err(ResourceIdentityError::InvalidRunnerGroupResourceId);
        }
        Ok(Self(parsed))
    }

    /// Constructs a runner-group identity from an already parsed UUID.
    ///
    /// # Errors
    ///
    /// Returns an error for the nil UUID.
    pub const fn from_uuid(value: Uuid) -> Result<Self, ResourceIdentityError> {
        if value.is_nil() {
            return Err(ResourceIdentityError::InvalidRunnerGroupResourceId);
        }
        Ok(Self(value))
    }

    #[must_use]
    /// Returns the durable runner-group UUID.
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for RunnerGroupResourceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for RunnerGroupResourceId {
    type Err = ResourceIdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for RunnerGroupResourceId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for RunnerGroupResourceId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Validation failures for canonical authorization resource identities.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ResourceIdentityError {
    /// A repository identity was nil or not canonical lowercase UUID text.
    #[error("repository resource ID must be a canonical non-nil UUID")]
    InvalidRepositoryResourceId,
    #[error("runner-group resource ID must be a canonical non-nil UUID")]
    /// A runner-group identity was nil or not canonical lowercase UUID text.
    InvalidRunnerGroupResourceId,
}

/// Exact tenant/repository pair resolved by trusted storage before authorization.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RepositoryResource {
    tenant_id: TenantId,
    repository_id: RepositoryResourceId,
}

impl RepositoryResource {
    /// Creates an exact tenant/repository authorization resource.
    #[must_use]
    pub const fn new(tenant_id: TenantId, repository_id: RepositoryResourceId) -> Self {
        Self {
            tenant_id,
            repository_id,
        }
    }

    /// Returns the tenant that owns the repository.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the durable repository identity.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryResourceId {
        self.repository_id
    }
}

/// Exact tenant/runner-group pair resolved by trusted storage before authorization.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RunnerGroupResource {
    tenant_id: TenantId,
    runner_group_id: RunnerGroupResourceId,
}

impl RunnerGroupResource {
    /// Creates an exact tenant/runner-group authorization resource.
    #[must_use]
    pub const fn new(tenant_id: TenantId, runner_group_id: RunnerGroupResourceId) -> Self {
        Self {
            tenant_id,
            runner_group_id,
        }
    }

    /// Returns the tenant that owns the runner group.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the durable runner-group identity.
    #[must_use]
    pub const fn runner_group_id(&self) -> RunnerGroupResourceId {
        self.runner_group_id
    }
}

/// Scope at which a permission is requested or a role is granted.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthorizationScope {
    /// Authority scoped to every resource owned by one tenant.
    Tenant {
        /// Tenant whose resources are in scope.
        tenant_id: TenantId,
    },
    /// Authority scoped to one exact repository.
    Repository {
        /// Exact tenant/repository resource in scope.
        repository: RepositoryResource,
    },
    /// Authority scoped to one exact runner group.
    RunnerGroup {
        /// Exact tenant/runner-group resource in scope.
        runner_group: RunnerGroupResource,
    },
}

impl AuthorizationScope {
    /// Creates a tenant-wide scope.
    #[must_use]
    pub const fn tenant(tenant_id: TenantId) -> Self {
        Self::Tenant { tenant_id }
    }

    /// Creates an exact repository scope.
    #[must_use]
    pub const fn repository(repository: RepositoryResource) -> Self {
        Self::Repository { repository }
    }

    /// Creates an exact runner-group scope.
    #[must_use]
    pub const fn runner_group(runner_group: RunnerGroupResource) -> Self {
        Self::RunnerGroup { runner_group }
    }

    /// Returns the tenant that bounds this scope.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        match self {
            Self::Tenant { tenant_id } => tenant_id,
            Self::Repository { repository } => repository.tenant_id(),
            Self::RunnerGroup { runner_group } => runner_group.tenant_id(),
        }
    }

    /// Returns the repository resource when this is repository-scoped.
    #[must_use]
    pub const fn repository_resource(&self) -> Option<&RepositoryResource> {
        match self {
            Self::Repository { repository } => Some(repository),
            Self::Tenant { .. } | Self::RunnerGroup { .. } => None,
        }
    }

    /// Returns the runner-group resource when this is runner-group-scoped.
    #[must_use]
    pub const fn runner_group_resource(&self) -> Option<&RunnerGroupResource> {
        match self {
            Self::RunnerGroup { runner_group } => Some(runner_group),
            Self::Tenant { .. } | Self::Repository { .. } => None,
        }
    }

    fn contains(&self, requested: &Self) -> bool {
        match (self, requested) {
            (Self::Tenant { tenant_id }, _) => tenant_id == requested.tenant_id(),
            (
                Self::Repository { repository: grant },
                Self::Repository {
                    repository: requested,
                },
            ) => grant == requested,
            (
                Self::RunnerGroup {
                    runner_group: grant,
                },
                Self::RunnerGroup {
                    runner_group: requested,
                },
            ) => grant == requested,
            (Self::Repository { .. } | Self::RunnerGroup { .. }, _) => false,
        }
    }
}

/// One explicit role assignment at a tenant or repository scope.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ScopedRoleGrant {
    scope: AuthorizationScope,
    role: RoleName,
}

impl ScopedRoleGrant {
    /// Assigns one role at one explicit authorization scope.
    #[must_use]
    pub const fn new(scope: AuthorizationScope, role: RoleName) -> Self {
        Self { scope, role }
    }

    /// Returns the resource scope at which the role was granted.
    #[must_use]
    pub const fn scope(&self) -> &AuthorizationScope {
        &self.scope
    }

    /// Returns the assigned role name.
    #[must_use]
    pub const fn role(&self) -> &RoleName {
        &self.role
    }
}

/// Authenticated or anonymous evidence supplied to resource authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizationContext {
    /// No authenticated principal or durable role grants are present.
    Anonymous,
    /// Current principal identity and its explicitly scoped durable roles.
    Authenticated {
        /// Tenant that bounds the authenticated principal.
        tenant_id: TenantId,
        /// Stable Automata-owned principal identity.
        principal_id: PrincipalId,
        /// Current explicit role assignments.
        role_grants: BTreeSet<ScopedRoleGrant>,
        /// Exact durable revision, when loaded from a session snapshot.
        authorization_revision: Option<u64>,
    },
}

impl AuthorizationContext {
    /// Creates a context with no authenticated authority.
    #[must_use]
    pub const fn anonymous() -> Self {
        Self::Anonymous
    }

    /// Creates tenant-bound authenticated authorization evidence.
    ///
    /// # Errors
    ///
    /// Rejects a role grant from another tenant instead of silently widening or
    /// partially applying a corrupt authorization snapshot.
    pub fn authenticated(
        tenant_id: TenantId,
        principal_id: PrincipalId,
        role_grants: BTreeSet<ScopedRoleGrant>,
    ) -> Result<Self, AuthorizationContextError> {
        Self::authenticated_with_revision(tenant_id, principal_id, role_grants, None)
    }

    /// Creates tenant-bound authenticated evidence at one exact durable
    /// authorization revision.
    ///
    /// Consumers that load role permissions after session resolution can use
    /// this revision to recheck membership in the same permission query and
    /// fail closed when authority changed between the two operations.
    ///
    /// # Errors
    ///
    /// Rejects revision zero and role grants from another tenant.
    pub fn authenticated_at_revision(
        tenant_id: TenantId,
        principal_id: PrincipalId,
        role_grants: BTreeSet<ScopedRoleGrant>,
        authorization_revision: u64,
    ) -> Result<Self, AuthorizationContextError> {
        if authorization_revision == 0 {
            return Err(AuthorizationContextError::InvalidAuthorizationRevision);
        }
        Self::authenticated_with_revision(
            tenant_id,
            principal_id,
            role_grants,
            Some(authorization_revision),
        )
    }

    fn authenticated_with_revision(
        tenant_id: TenantId,
        principal_id: PrincipalId,
        role_grants: BTreeSet<ScopedRoleGrant>,
        authorization_revision: Option<u64>,
    ) -> Result<Self, AuthorizationContextError> {
        if role_grants
            .iter()
            .any(|grant| grant.scope().tenant_id() != &tenant_id)
        {
            return Err(AuthorizationContextError::CrossTenantRoleGrant);
        }
        Ok(Self::Authenticated {
            tenant_id,
            principal_id,
            role_grants,
            authorization_revision,
        })
    }

    /// Returns the authenticated tenant, or `None` for anonymous contexts.
    #[must_use]
    pub const fn tenant_id(&self) -> Option<&TenantId> {
        match self {
            Self::Anonymous => None,
            Self::Authenticated { tenant_id, .. } => Some(tenant_id),
        }
    }

    /// Returns the authenticated principal, or `None` for anonymous contexts.
    #[must_use]
    pub const fn principal_id(&self) -> Option<&PrincipalId> {
        match self {
            Self::Anonymous => None,
            Self::Authenticated { principal_id, .. } => Some(principal_id),
        }
    }

    /// Returns current scoped roles, or `None` for anonymous contexts.
    #[must_use]
    pub const fn role_grants(&self) -> Option<&BTreeSet<ScopedRoleGrant>> {
        match self {
            Self::Anonymous => None,
            Self::Authenticated { role_grants, .. } => Some(role_grants),
        }
    }

    /// Returns the exact durable revision when the context came from session
    /// resolution rather than a trusted in-process authorization fixture.
    #[must_use]
    pub const fn authorization_revision(&self) -> Option<u64> {
        match self {
            Self::Anonymous => None,
            Self::Authenticated {
                authorization_revision,
                ..
            } => *authorization_revision,
        }
    }
}

/// Validation failures for assembled authorization snapshots.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AuthorizationContextError {
    /// A role assignment belongs to a tenant other than the principal's tenant.
    #[error("an authenticated authorization context cannot contain a cross-tenant role grant")]
    CrossTenantRoleGrant,
    #[error("an authenticated authorization revision must be positive")]
    /// A durable authorization revision was zero.
    InvalidAuthorizationRevision,
}

/// Exact permission and trusted resource scope being authorized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationRequest {
    scope: AuthorizationScope,
    permission: Permission,
    secret_exposure: SecretExposureClass,
}

impl AuthorizationRequest {
    /// Creates a request with the restrictive readable-secret publication ceiling.
    ///
    /// Dashboard metadata is unaffected by the ceiling. Callers authorizing an
    /// exact log or artifact may attach a less restrictive classification only
    /// after resolving trusted attempt/artifact safety evidence.
    #[must_use]
    pub const fn new(scope: AuthorizationScope, permission: Permission) -> Self {
        Self {
            scope,
            permission,
            secret_exposure: SecretExposureClass::ReadableSecret,
        }
    }

    /// Sets trusted secret-exposure evidence used to narrow publication.
    #[must_use]
    pub const fn with_secret_exposure(mut self, exposure: SecretExposureClass) -> Self {
        self.secret_exposure = exposure;
        self
    }

    /// Returns the exact resource scope being authorized.
    #[must_use]
    pub const fn scope(&self) -> &AuthorizationScope {
        &self.scope
    }

    /// Returns the requested permission.
    #[must_use]
    pub const fn permission(&self) -> &Permission {
        &self.permission
    }

    /// Returns trusted secret-exposure evidence for output publication.
    #[must_use]
    pub const fn secret_exposure(&self) -> SecretExposureClass {
        self.secret_exposure
    }
}

fn output_kind_for(permission: &Permission) -> Option<OutputKind> {
    use repository_read_permissions::{
        ARTIFACT_DOWNLOAD, ARTIFACT_READ, JOB_READ, LOG_READ, REPOSITORY_READ, RUN_READ,
        WORKFLOW_READ,
    };

    match permission.as_str() {
        REPOSITORY_READ | WORKFLOW_READ | RUN_READ | JOB_READ => Some(OutputKind::Dashboard),
        LOG_READ => Some(OutputKind::Logs),
        ARTIFACT_READ | ARTIFACT_DOWNLOAD => Some(OutputKind::Artifacts),
        _ => None,
    }
}

/// Default-deny composition of explicit RBAC and repository publication policy.
///
/// An authenticated tenant mismatch is rejected before either component runs.
/// Publication is restricted to the closed read-permission catalog above, so a
/// role name or a visibility setting can never grant a mutation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompositeAuthorizationPolicy {
    rbac: RbacPolicy,
    repository_publications: BTreeMap<RepositoryResource, RepositoryPublicationPolicy>,
}

impl CompositeAuthorizationPolicy {
    /// Composes explicit RBAC with exact-repository publication policies.
    #[must_use]
    pub const fn new(
        rbac: RbacPolicy,
        repository_publications: BTreeMap<RepositoryResource, RepositoryPublicationPolicy>,
    ) -> Self {
        Self {
            rbac,
            repository_publications,
        }
    }

    /// Applies tenant checks, scoped RBAC, and closed output publication policy.
    #[must_use]
    pub fn allows(&self, context: &AuthorizationContext, request: &AuthorizationRequest) -> bool {
        let authenticated = match context {
            AuthorizationContext::Anonymous => false,
            AuthorizationContext::Authenticated {
                tenant_id,
                role_grants,
                ..
            } => {
                if tenant_id != request.scope().tenant_id() {
                    return false;
                }
                if self.rbac.allows(
                    role_grants
                        .iter()
                        .filter(|grant| grant.scope().contains(request.scope()))
                        .map(ScopedRoleGrant::role),
                    request.permission(),
                ) {
                    return true;
                }
                true
            }
        };

        let Some(repository) = request.scope().repository_resource() else {
            return false;
        };
        self.repository_publications
            .get(repository)
            .copied()
            .and_then(|policy| {
                output_kind_for(request.permission())
                    .map(|kind| policy.effective_visibility(kind, request.secret_exposure()))
            })
            .is_some_and(|visibility| match visibility {
                OutputVisibility::Public => true,
                OutputVisibility::Authenticated => authenticated,
                OutputVisibility::Private => false,
            })
    }
}
