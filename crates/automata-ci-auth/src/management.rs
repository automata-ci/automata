//! Revision-safe tenant RBAC management contracts.
//!
//! Management adapters must reauthorize the actor from current durable state in
//! the same transaction as every mutation. Caller-supplied role claims are never
//! authority. Successful security mutations, authorization-revision changes, and
//! sanitized audit events must commit atomically.

use std::{collections::BTreeSet, fmt, future::Future, pin::Pin};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    authorization::{AuthorizationScope, Permission, RoleName},
    human::{PrincipalId, ProviderId, TenantId},
    session::SessionId,
    time::UnixTimestamp,
};

const MAX_DISPLAY_NAME_BYTES: usize = 255;
const MAX_REASON_BYTES: usize = 1_024;
const MAX_REQUEST_ID_BYTES: usize = 255;
const MAX_PAGE_SIZE: u16 = 100;
const MAX_PERMISSION_CATALOG_ENTRIES: usize = 256;
const MAX_PERMISSION_DESCRIPTION_BYTES: usize = 1_024;
/// Maximum complete choice count for each direct-binding grant-option kind.
pub const DIRECT_BINDING_GRANT_OPTION_LIMIT: usize = 500;
const PROVIDER_OBSERVED_BINDING_ID_DOMAIN: &[u8] =
    b"automata-ci/rbac/provider-observed-binding-id/v1\0";

/// Permissions required by the management operations in this module.
pub mod permissions {
    /// Allows reading tenant member projections.
    pub const MEMBERS_READ: &str = "members:read";
    /// Allows suspending or restoring tenant members.
    pub const MEMBERS_MANAGE: &str = "members:manage";
    /// Allows reading role definitions.
    pub const ROLES_READ: &str = "roles:read";
    /// Allows creating, changing, or deleting custom roles.
    pub const ROLES_MANAGE: &str = "roles:manage";
    /// Allows granting or revoking direct scoped role bindings.
    pub const ROLE_BINDINGS_MANAGE: &str = "role-bindings:manage";
}

macro_rules! uuid_id {
    ($name:ident, $error:ident, $label:literal) => {
        #[doc = concat!("A canonical durable ", $label, " UUID.")]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            /// Parses one canonical lowercase, hyphenated, non-nil UUID.
            ///
            /// # Errors
            ///
            /// Rejects nil, noncanonical, or malformed UUID text.
            pub fn new(value: impl AsRef<str>) -> Result<Self, ManagementValueError> {
                let value = value.as_ref();
                let parsed = Uuid::parse_str(value).map_err(|_| ManagementValueError::$error)?;
                if parsed.is_nil() || parsed.hyphenated().to_string() != value {
                    return Err(ManagementValueError::$error);
                }
                Ok(Self(parsed))
            }

            /// Constructs an ID from a parsed UUID.
            ///
            /// # Errors
            ///
            /// Rejects the nil UUID.
            pub const fn from_uuid(value: Uuid) -> Result<Self, ManagementValueError> {
                if value.is_nil() {
                    return Err(ManagementValueError::$error);
                }
                Ok(Self(value))
            }

            #[must_use]
            /// Returns the parsed durable UUID.
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

uuid_id!(RoleId, InvalidRoleId, "role");
uuid_id!(RoleBindingId, InvalidRoleBindingId, "role binding");
uuid_id!(
    ProviderRoleMappingId,
    InvalidProviderRoleMappingId,
    "provider role mapping"
);
uuid_id!(ManagedPrincipalId, InvalidPrincipalId, "principal");

impl RoleBindingId {
    /// Derives the stable `UUIDv8` presentation identity of one provider-observed
    /// principal/mapping pair.
    ///
    /// This identity is not mutation authority and cannot be passed to direct
    /// binding mutation commands. Its domain-separated construction gives the
    /// renderer one canonical UUID for a read-only effective assignment without
    /// inventing a durable direct-binding row.
    #[must_use]
    pub fn for_provider_observation(
        principal_id: ManagedPrincipalId,
        mapping_id: ProviderRoleMappingId,
    ) -> Self {
        let mut digest = Sha256::new();
        digest.update(PROVIDER_OBSERVED_BINDING_ID_DOMAIN);
        digest.update(principal_id.as_uuid().as_bytes());
        digest.update(mapping_id.as_uuid().as_bytes());
        let digest = digest.finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        // RFC 9562 UUIDv8 reserves these bits for application-defined names.
        bytes[6] = (bytes[6] & 0x0f) | 0x80;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Self(Uuid::from_bytes(bytes))
    }
}

/// Positive optimistic-concurrency revision representable by `PostgreSQL` BIGINT.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ManagementRevision(u64);

impl ManagementRevision {
    /// Creates a valid durable revision.
    ///
    /// # Errors
    ///
    /// Rejects zero or values outside `PostgreSQL` BIGINT.
    pub const fn new(value: u64) -> Result<Self, ManagementValueError> {
        if value == 0 || value > i64::MAX as u64 {
            return Err(ManagementValueError::InvalidRevision);
        }
        Ok(Self(value))
    }

    #[must_use]
    /// Returns the positive durable revision.
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Bounded request correlation ID eligible for sanitized audit storage.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct ManagementRequestId(String);

impl ManagementRequestId {
    /// Creates a portable, non-whitespace request ID.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, whitespace-bearing, or control-bearing values.
    pub fn new(value: impl Into<String>) -> Result<Self, ManagementValueError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_REQUEST_ID_BYTES
            || value.chars().any(char::is_whitespace)
        {
            return Err(ManagementValueError::InvalidRequestId);
        }
        Ok(Self(value))
    }

    #[must_use]
    /// Returns the validated audit correlation identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ManagementRequestId {
    type Error = ManagementValueError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ManagementRequestId> for String {
    fn from(value: ManagementRequestId) -> Self {
        value.0
    }
}

/// Current authenticated actor evidence used to reauthorize a management call.
///
/// This carries identities and the session revision only. It deliberately has no
/// caller-supplied roles or permissions.
#[derive(Clone, Eq, PartialEq)]
pub struct ManagementActor {
    tenant_id: TenantId,
    principal_id: PrincipalId,
    session_id: SessionId,
    authorization_revision: ManagementRevision,
    request_id: Option<ManagementRequestId>,
    now: UnixTimestamp,
}

impl ManagementActor {
    #[must_use]
    /// Creates identity and revision evidence for transactional reauthorization.
    pub const fn new(
        tenant_id: TenantId,
        principal_id: PrincipalId,
        session_id: SessionId,
        authorization_revision: ManagementRevision,
        request_id: Option<ManagementRequestId>,
        now: UnixTimestamp,
    ) -> Self {
        Self {
            tenant_id,
            principal_id,
            session_id,
            authorization_revision,
            request_id,
            now,
        }
    }

    #[must_use]
    /// Returns the tenant that bounds the management operation.
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    /// Returns the stable actor principal to reauthorize.
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    #[must_use]
    /// Returns the exact session that must still be active.
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    /// Returns the session's expected authorization revision.
    pub const fn authorization_revision(&self) -> ManagementRevision {
        self.authorization_revision
    }

    #[must_use]
    /// Returns optional sanitized request correlation metadata.
    pub const fn request_id(&self) -> Option<&ManagementRequestId> {
        self.request_id.as_ref()
    }

    #[must_use]
    /// Returns the timestamp used for lifecycle and expiry checks.
    pub const fn now(&self) -> UnixTimestamp {
        self.now
    }
}

impl fmt::Debug for ManagementActor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagementActor")
            .field("tenant_id", &self.tenant_id)
            .field("principal_id", &self.principal_id)
            .field("session_id", &self.session_id)
            .field("authorization_revision", &self.authorization_revision)
            .field("request_id", &self.request_id)
            .field("now", &self.now)
            .finish()
    }
}

/// Bounded list page size.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ManagementPageSize(u16);

impl ManagementPageSize {
    /// Creates a page size in the inclusive range 1..=100.
    ///
    /// # Errors
    ///
    /// Rejects zero or oversized pages.
    pub const fn new(value: u16) -> Result<Self, ManagementValueError> {
        if value == 0 || value > MAX_PAGE_SIZE {
            return Err(ManagementValueError::InvalidPageSize);
        }
        Ok(Self(value))
    }

    #[must_use]
    /// Returns the bounded result limit.
    pub const fn value(self) -> u16 {
        self.0
    }
}

/// One page of stable results. `next_cursor` is an opaque backend cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementPage<T> {
    items: Vec<T>,
    next_cursor: Option<String>,
    mutation_authorization_revision: Option<ManagementRevision>,
}

impl<T> ManagementPage<T> {
    /// Creates a bounded page.
    ///
    /// # Errors
    ///
    /// Rejects a result larger than the requested maximum or an invalid cursor.
    pub fn new(
        items: Vec<T>,
        next_cursor: Option<String>,
        limit: ManagementPageSize,
    ) -> Result<Self, ManagementValueError> {
        if items.len() > usize::from(limit.value()) {
            return Err(ManagementValueError::OversizedPage);
        }
        if next_cursor.as_ref().is_some_and(|cursor| {
            cursor.is_empty()
                || cursor.len() > MAX_REQUEST_ID_BYTES
                || cursor.chars().any(char::is_whitespace)
        }) {
            return Err(ManagementValueError::InvalidCursor);
        }
        Ok(Self {
            items,
            next_cursor,
            mutation_authorization_revision: None,
        })
    }

    /// Creates a bounded page tied to the actor revision reauthorized in the
    /// same repeatable-read snapshot.
    ///
    /// The revision is an equivalent mutation-authority fence, not a claim that
    /// every collection row shares one database counter. Create/grant commands
    /// still rely on fresh durable UUIDs, uniqueness constraints, and
    /// transactional actor reauthorization rather than overwriting collection
    /// state by this value.
    ///
    /// # Errors
    ///
    /// Rejects a result larger than the requested maximum or an invalid cursor.
    pub fn new_authorized(
        items: Vec<T>,
        next_cursor: Option<String>,
        limit: ManagementPageSize,
        mutation_authorization_revision: ManagementRevision,
    ) -> Result<Self, ManagementValueError> {
        let mut page = Self::new(items, next_cursor, limit)?;
        page.mutation_authorization_revision = Some(mutation_authorization_revision);
        Ok(page)
    }

    #[must_use]
    /// Returns the stable records in this page.
    pub fn items(&self) -> &[T] {
        &self.items
    }

    #[must_use]
    /// Returns the opaque cursor for the following page, when present.
    pub fn next_cursor(&self) -> Option<&str> {
        self.next_cursor.as_deref()
    }

    /// Returns the exact actor-authorization revision proven by the storage
    /// snapshot, when the page came from an authorization-aware adapter.
    #[must_use]
    pub const fn mutation_authorization_revision(&self) -> Option<ManagementRevision> {
        self.mutation_authorization_revision
    }
}

/// Member status within one tenant.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberStatus {
    /// The member may authenticate and exercise current grants.
    Active,
    /// The member is denied authentication and management authority.
    Suspended,
}

/// Redacted management projection of a tenant member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberRecord {
    principal_id: ManagedPrincipalId,
    provider_id: ProviderId,
    provider_login: String,
    display_name: Option<String>,
    status: MemberStatus,
    authorization_revision: ManagementRevision,
    revision: ManagementRevision,
}

impl MemberRecord {
    /// Constructs a validated member projection.
    ///
    /// # Errors
    ///
    /// Rejects invalid display metadata.
    pub fn new(
        principal_id: ManagedPrincipalId,
        provider_id: ProviderId,
        provider_login: impl Into<String>,
        display_name: Option<String>,
        status: MemberStatus,
        authorization_revision: ManagementRevision,
        revision: ManagementRevision,
    ) -> Result<Self, ManagementValueError> {
        let provider_login = provider_login.into();
        validate_provider_login(&provider_login)?;
        validate_optional_display_name(display_name.as_deref())?;
        Ok(Self {
            principal_id,
            provider_id,
            provider_login,
            display_name,
            status,
            authorization_revision,
            revision,
        })
    }

    #[must_use]
    /// Returns the Automata-owned durable principal UUID.
    pub const fn principal_id(&self) -> ManagedPrincipalId {
        self.principal_id
    }

    #[must_use]
    /// Returns the provider used by this member.
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    #[must_use]
    /// Returns provider login display metadata.
    pub fn provider_login(&self) -> &str {
        &self.provider_login
    }

    #[must_use]
    /// Returns optional non-authoritative display metadata.
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    #[must_use]
    /// Returns whether the membership is active or suspended.
    pub const fn status(&self) -> MemberStatus {
        self.status
    }

    #[must_use]
    /// Returns the current revision that sessions must match.
    pub const fn authorization_revision(&self) -> ManagementRevision {
        self.authorization_revision
    }

    #[must_use]
    /// Returns the member record's optimistic-concurrency revision.
    pub const fn revision(&self) -> ManagementRevision {
        self.revision
    }
}

/// Durable role category.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleKind {
    /// A release-defined role that cannot be mutated or deleted.
    BuiltIn,
    /// A tenant-defined role managed through this boundary.
    Custom,
}

/// Redacted role projection with its explicit permission grants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleRecord {
    id: RoleId,
    name: RoleName,
    display_name: String,
    kind: RoleKind,
    immutable: bool,
    revision: ManagementRevision,
    permissions: BTreeSet<Permission>,
}

impl RoleRecord {
    /// Constructs a validated role projection.
    ///
    /// # Errors
    ///
    /// Rejects invalid display metadata or a mutable built-in role.
    pub fn new(
        id: RoleId,
        name: RoleName,
        display_name: impl Into<String>,
        kind: RoleKind,
        immutable: bool,
        revision: ManagementRevision,
        permissions: BTreeSet<Permission>,
    ) -> Result<Self, ManagementValueError> {
        let display_name = display_name.into();
        validate_display_name(&display_name)?;
        if matches!(kind, RoleKind::BuiltIn) && !immutable {
            return Err(ManagementValueError::InvalidRoleKind);
        }
        Ok(Self {
            id,
            name,
            display_name,
            kind,
            immutable,
            revision,
            permissions,
        })
    }

    #[must_use]
    /// Returns the durable role UUID.
    pub const fn id(&self) -> RoleId {
        self.id
    }

    #[must_use]
    /// Returns the portable policy name used in grants.
    pub const fn name(&self) -> &RoleName {
        &self.name
    }

    #[must_use]
    /// Returns the bounded role display label.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    #[must_use]
    /// Returns whether the role is built in or tenant-defined.
    pub const fn kind(&self) -> RoleKind {
        self.kind
    }

    #[must_use]
    /// Reports whether the role definition is immutable.
    pub const fn immutable(&self) -> bool {
        self.immutable
    }

    #[must_use]
    /// Returns the role record's optimistic-concurrency revision.
    pub const fn revision(&self) -> ManagementRevision {
        self.revision
    }

    #[must_use]
    /// Returns permissions explicitly granted by this role.
    pub const fn permissions(&self) -> &BTreeSet<Permission> {
        &self.permissions
    }
}

/// Lifecycle of a direct role binding.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleBindingStatus {
    /// The direct scoped grant currently contributes authority.
    Active,
    /// The direct grant has been durably revoked.
    Revoked,
}

/// One direct, scoped role assignment. Provider-derived mappings are managed by
/// a separate, read-only membership-observation boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleBindingRecord {
    id: RoleBindingId,
    principal_id: ManagedPrincipalId,
    role_id: RoleId,
    scope: AuthorizationScope,
    status: RoleBindingStatus,
    valid_until: Option<UnixTimestamp>,
    revision: ManagementRevision,
}

impl RoleBindingRecord {
    #[must_use]
    /// Creates a redacted direct-role-binding projection.
    pub const fn new(
        id: RoleBindingId,
        principal_id: ManagedPrincipalId,
        role_id: RoleId,
        scope: AuthorizationScope,
        status: RoleBindingStatus,
        valid_until: Option<UnixTimestamp>,
        revision: ManagementRevision,
    ) -> Self {
        Self {
            id,
            principal_id,
            role_id,
            scope,
            status,
            valid_until,
            revision,
        }
    }

    #[must_use]
    /// Returns the durable binding UUID.
    pub const fn id(&self) -> RoleBindingId {
        self.id
    }

    #[must_use]
    /// Returns the principal receiving the role.
    pub const fn principal_id(&self) -> ManagedPrincipalId {
        self.principal_id
    }

    #[must_use]
    /// Returns the granted role UUID.
    pub const fn role_id(&self) -> RoleId {
        self.role_id
    }

    #[must_use]
    /// Returns the exact tenant or resource scope of the grant.
    pub const fn scope(&self) -> &AuthorizationScope {
        &self.scope
    }

    #[must_use]
    /// Returns whether the binding is active or revoked.
    pub const fn status(&self) -> RoleBindingStatus {
        self.status
    }

    #[must_use]
    /// Returns the optional immutable grant deadline.
    pub const fn valid_until(&self) -> Option<UnixTimestamp> {
        self.valid_until
    }

    #[must_use]
    /// Returns the binding's optimistic-concurrency revision.
    pub const fn revision(&self) -> ManagementRevision {
        self.revision
    }
}

/// Durable origin of a direct role assignment.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectRoleBindingSource {
    /// A management operation explicitly created the binding.
    Manual,
    /// Installation bootstrap created the binding.
    Bootstrap,
    /// An explicit recovery operation created the binding.
    Recovery,
}

/// Source of one management-visible role assignment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagementRoleBindingSource {
    /// A mutable durable direct binding and its exact assignment origin.
    Direct(DirectRoleBindingSource),
    /// A read-only effective GitHub organization/team mapping from the newest
    /// valid numeric membership snapshot.
    ProviderObserved {
        /// Durable provider-role-mapping UUID that contributed this assignment.
        mapping_id: ProviderRoleMappingId,
    },
}

impl ManagementRoleBindingSource {
    /// Reports whether this assignment is a directly mutable binding.
    #[must_use]
    pub const fn is_direct(self) -> bool {
        matches!(self, Self::Direct(_))
    }
}

/// Bounded display metadata joined to a binding's exact authorization scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementScopeRecord {
    scope: AuthorizationScope,
    display_name: String,
}

impl ManagementScopeRecord {
    /// Creates a scope projection with a bounded non-authoritative label.
    ///
    /// # Errors
    ///
    /// Rejects visually blank, oversized, control-bearing, or bidi-formatted labels.
    pub fn new(
        scope: AuthorizationScope,
        display_name: impl Into<String>,
    ) -> Result<Self, ManagementValueError> {
        let display_name = display_name.into();
        validate_display_name(&display_name)?;
        Ok(Self {
            scope,
            display_name,
        })
    }

    /// Returns the exact tenant or resource scope.
    #[must_use]
    pub const fn scope(&self) -> &AuthorizationScope {
        &self.scope
    }

    /// Returns the bounded presentation label for that exact resource.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
}

/// Joined role identity and display metadata for a binding projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementBindingRole {
    id: RoleId,
    name: RoleName,
    display_name: String,
}

impl ManagementBindingRole {
    /// Creates a validated joined role label.
    ///
    /// # Errors
    ///
    /// Rejects invalid display metadata.
    pub fn new(
        id: RoleId,
        name: RoleName,
        display_name: impl Into<String>,
    ) -> Result<Self, ManagementValueError> {
        let display_name = display_name.into();
        validate_display_name(&display_name)?;
        Ok(Self {
            id,
            name,
            display_name,
        })
    }

    /// Returns the exact durable role UUID.
    #[must_use]
    pub const fn id(&self) -> RoleId {
        self.id
    }

    /// Returns the portable role policy name.
    #[must_use]
    pub const fn name(&self) -> &RoleName {
        &self.name
    }

    /// Returns the bounded role display label.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
}

/// Joined principal, role, scope, lifecycle, and source metadata for one
/// management-visible assignment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementRoleBindingRecord {
    id: RoleBindingId,
    principal: MemberRecord,
    role: ManagementBindingRole,
    scope: ManagementScopeRecord,
    source: ManagementRoleBindingSource,
    status: RoleBindingStatus,
    valid_until: Option<UnixTimestamp>,
    revision: ManagementRevision,
}

impl ManagementRoleBindingRecord {
    /// Creates a complete assignment projection.
    ///
    /// # Errors
    ///
    /// Rejects a provider-observed mapping reported as revoked. Provider
    /// mappings are emitted only while their newest numeric evidence is active;
    /// disabled mappings are absent rather than presented as direct revocations.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: RoleBindingId,
        principal: MemberRecord,
        role: ManagementBindingRole,
        scope: ManagementScopeRecord,
        source: ManagementRoleBindingSource,
        status: RoleBindingStatus,
        valid_until: Option<UnixTimestamp>,
        revision: ManagementRevision,
    ) -> Result<Self, ManagementValueError> {
        if matches!(source, ManagementRoleBindingSource::ProviderObserved { .. })
            && status != RoleBindingStatus::Active
        {
            return Err(ManagementValueError::InvalidRoleBindingSource);
        }
        Ok(Self {
            id,
            principal,
            role,
            scope,
            source,
            status,
            valid_until,
            revision,
        })
    }

    /// Returns the direct UUID or stable read-only provider projection UUID.
    #[must_use]
    pub const fn id(&self) -> RoleBindingId {
        self.id
    }

    /// Returns exact joined member metadata.
    #[must_use]
    pub const fn principal(&self) -> &MemberRecord {
        &self.principal
    }

    /// Returns exact joined role metadata.
    #[must_use]
    pub const fn role(&self) -> &ManagementBindingRole {
        &self.role
    }

    /// Returns the exact scope and its bounded resource label.
    #[must_use]
    pub const fn scope(&self) -> &ManagementScopeRecord {
        &self.scope
    }

    /// Returns whether the assignment is direct or provider-observed.
    #[must_use]
    pub const fn source(&self) -> ManagementRoleBindingSource {
        self.source
    }

    /// Returns the assignment lifecycle.
    #[must_use]
    pub const fn status(&self) -> RoleBindingStatus {
        self.status
    }

    /// Returns the direct expiry or newest provider-observation validity bound.
    #[must_use]
    pub const fn valid_until(&self) -> Option<UnixTimestamp> {
        self.valid_until
    }

    /// Returns the direct-binding or provider-mapping durable revision.
    #[must_use]
    pub const fn revision(&self) -> ManagementRevision {
        self.revision
    }
}

/// One entry from the complete release-defined permission catalog, joined with
/// a role's explicit grant state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RolePermissionRecord {
    permission: Permission,
    description: String,
    critical: bool,
    granted: bool,
}

impl RolePermissionRecord {
    /// Creates a validated permission catalog entry.
    ///
    /// # Errors
    ///
    /// Rejects visually blank, oversized, control-bearing, or bidi-formatted descriptions.
    pub fn new(
        permission: Permission,
        description: impl Into<String>,
        critical: bool,
        granted: bool,
    ) -> Result<Self, ManagementValueError> {
        let description = description.into();
        if !is_safe_management_text(&description, MAX_PERMISSION_DESCRIPTION_BYTES) {
            return Err(ManagementValueError::InvalidPermissionDescription);
        }
        Ok(Self {
            permission,
            description,
            critical,
            granted,
        })
    }

    /// Returns the exact portable permission name.
    #[must_use]
    pub const fn permission(&self) -> &Permission {
        &self.permission
    }

    /// Returns the bounded release-defined description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Reports whether the permission catalog classifies this operation as
    /// security-critical.
    #[must_use]
    pub const fn critical(&self) -> bool {
        self.critical
    }

    /// Reports whether this role explicitly grants the permission.
    #[must_use]
    pub const fn granted(&self) -> bool {
        self.granted
    }
}

/// Exact role detail with the complete, ordered permission catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleDetailRecord {
    role: RoleRecord,
    permission_catalog: Vec<RolePermissionRecord>,
}

/// Current mutation permissions proven for one freshly reauthorized actor.
///
/// These booleans are presentation readiness only. Every mutation must still
/// reauthorize the actor and enforce its optimistic-concurrency guards in the
/// mutation transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagementMutationCapabilities {
    authorization_revision: ManagementRevision,
    members_manage: bool,
    roles_manage: bool,
    role_bindings_manage: bool,
}

impl ManagementMutationCapabilities {
    #[must_use]
    /// Creates capabilities tied to the exact reauthorized session revision.
    pub const fn new(
        authorization_revision: ManagementRevision,
        members_manage: bool,
        roles_manage: bool,
        role_bindings_manage: bool,
    ) -> Self {
        Self {
            authorization_revision,
            members_manage,
            roles_manage,
            role_bindings_manage,
        }
    }

    #[must_use]
    /// Returns the actor authorization revision proven by the read snapshot.
    pub const fn authorization_revision(self) -> ManagementRevision {
        self.authorization_revision
    }

    #[must_use]
    /// Reports current `members:manage` authority.
    pub const fn members_manage(self) -> bool {
        self.members_manage
    }

    #[must_use]
    /// Reports current `roles:manage` authority.
    pub const fn roles_manage(self) -> bool {
        self.roles_manage
    }

    #[must_use]
    /// Reports current `role-bindings:manage` authority.
    pub const fn role_bindings_manage(self) -> bool {
        self.role_bindings_manage
    }
}

/// Fresh actor evidence for a current mutation-capability read.
#[derive(Clone, Eq, PartialEq)]
pub struct ReadManagementMutationCapabilities {
    actor: ManagementActor,
}

impl ReadManagementMutationCapabilities {
    #[must_use]
    /// Creates a capability read that trusts no caller-supplied permission.
    pub const fn new(actor: ManagementActor) -> Self {
        Self { actor }
    }

    #[must_use]
    /// Returns actor evidence that must be reauthorized in the read snapshot.
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }
}

impl fmt::Debug for ReadManagementMutationCapabilities {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadManagementMutationCapabilities")
            .finish_non_exhaustive()
    }
}

/// One active tenant principal eligible to receive a direct role grant.
#[derive(Clone, Eq, PartialEq)]
pub struct DirectBindingPrincipalOption {
    principal_id: ManagedPrincipalId,
    display_name: String,
}

impl DirectBindingPrincipalOption {
    /// Creates a principal option with a bounded presentation label.
    ///
    /// # Errors
    ///
    /// Rejects a visually blank, oversized, control-bearing, or bidi-formatted label.
    pub fn new(
        principal_id: ManagedPrincipalId,
        display_name: impl Into<String>,
    ) -> Result<Self, ManagementValueError> {
        let display_name = display_name.into();
        validate_display_name(&display_name)?;
        Ok(Self {
            principal_id,
            display_name,
        })
    }

    #[must_use]
    /// Returns the stable Automata principal UUID used by grant commands.
    pub const fn principal_id(&self) -> ManagedPrincipalId {
        self.principal_id
    }

    #[must_use]
    /// Returns the bounded non-authoritative presentation label.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
}

impl fmt::Debug for DirectBindingPrincipalOption {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectBindingPrincipalOption")
            .field("principal_id", &self.principal_id)
            .finish_non_exhaustive()
    }
}

/// One current tenant role eligible for a direct grant.
#[derive(Clone, Eq, PartialEq)]
pub struct DirectBindingRoleOption {
    role_id: RoleId,
    name: RoleName,
    display_name: String,
    kind: RoleKind,
    immutable: bool,
}

impl DirectBindingRoleOption {
    /// Creates a role option with consistent kind and immutable state.
    ///
    /// # Errors
    ///
    /// Rejects invalid display metadata or a mutable built-in role.
    pub fn new(
        role_id: RoleId,
        name: RoleName,
        display_name: impl Into<String>,
        kind: RoleKind,
        immutable: bool,
    ) -> Result<Self, ManagementValueError> {
        let display_name = display_name.into();
        validate_display_name(&display_name)?;
        if matches!(kind, RoleKind::BuiltIn) && !immutable {
            return Err(ManagementValueError::InvalidRoleKind);
        }
        Ok(Self {
            role_id,
            name,
            display_name,
            kind,
            immutable,
        })
    }

    #[must_use]
    /// Returns the stable role UUID used by grant commands.
    pub const fn role_id(&self) -> RoleId {
        self.role_id
    }

    #[must_use]
    /// Returns the canonical portable role name.
    pub const fn name(&self) -> &RoleName {
        &self.name
    }

    #[must_use]
    /// Returns the bounded role presentation label.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    #[must_use]
    /// Returns the current role category.
    pub const fn kind(&self) -> RoleKind {
        self.kind
    }

    #[must_use]
    /// Reports whether the role definition itself is immutable.
    pub const fn immutable(&self) -> bool {
        self.immutable
    }
}

impl fmt::Debug for DirectBindingRoleOption {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectBindingRoleOption")
            .field("role_id", &self.role_id)
            .field("kind", &self.kind)
            .field("immutable", &self.immutable)
            .finish_non_exhaustive()
    }
}

/// One current tenant repository eligible as a direct-grant scope.
#[derive(Clone, Eq, PartialEq)]
pub struct DirectBindingRepositoryOption {
    repository_id: crate::authorization::RepositoryResourceId,
    display_name: String,
}

impl DirectBindingRepositoryOption {
    /// Creates a repository option with a bounded presentation label.
    ///
    /// # Errors
    ///
    /// Rejects a visually blank, oversized, control-bearing, or bidi-formatted label.
    pub fn new(
        repository_id: crate::authorization::RepositoryResourceId,
        display_name: impl Into<String>,
    ) -> Result<Self, ManagementValueError> {
        let display_name = display_name.into();
        validate_display_name(&display_name)?;
        Ok(Self {
            repository_id,
            display_name,
        })
    }

    #[must_use]
    /// Returns the stable repository UUID used to construct a grant scope.
    pub const fn repository_id(&self) -> crate::authorization::RepositoryResourceId {
        self.repository_id
    }

    #[must_use]
    /// Returns the bounded repository presentation label.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
}

impl fmt::Debug for DirectBindingRepositoryOption {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectBindingRepositoryOption")
            .field("repository_id", &self.repository_id)
            .finish_non_exhaustive()
    }
}

/// One current tenant runner group eligible as a direct-grant scope.
#[derive(Clone, Eq, PartialEq)]
pub struct DirectBindingRunnerGroupOption {
    runner_group_id: crate::authorization::RunnerGroupResourceId,
    display_name: String,
}

impl DirectBindingRunnerGroupOption {
    /// Creates a runner-group option with a bounded presentation label.
    ///
    /// # Errors
    ///
    /// Rejects a visually blank, oversized, control-bearing, or bidi-formatted label.
    pub fn new(
        runner_group_id: crate::authorization::RunnerGroupResourceId,
        display_name: impl Into<String>,
    ) -> Result<Self, ManagementValueError> {
        let display_name = display_name.into();
        validate_display_name(&display_name)?;
        Ok(Self {
            runner_group_id,
            display_name,
        })
    }

    #[must_use]
    /// Returns the stable runner-group UUID used to construct a grant scope.
    pub const fn runner_group_id(&self) -> crate::authorization::RunnerGroupResourceId {
        self.runner_group_id
    }

    #[must_use]
    /// Returns the bounded runner-group presentation label.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
}

impl fmt::Debug for DirectBindingRunnerGroupOption {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectBindingRunnerGroupOption")
            .field("runner_group_id", &self.runner_group_id)
            .finish_non_exhaustive()
    }
}

/// One coherent, bounded set of valid direct-binding grant choices.
#[derive(Clone, Eq, PartialEq)]
pub struct DirectBindingGrantOptions {
    authorization_revision: ManagementRevision,
    principals: Vec<DirectBindingPrincipalOption>,
    roles: Vec<DirectBindingRoleOption>,
    repositories: Vec<DirectBindingRepositoryOption>,
    runner_groups: Vec<DirectBindingRunnerGroupOption>,
}

impl DirectBindingGrantOptions {
    /// Creates one canonical set of choices tied to an actor revision.
    ///
    /// Every collection must contain at most 500 entries, have unique stable
    /// IDs, and be strictly ordered by display label then ID.
    ///
    /// # Errors
    ///
    /// Rejects oversized, duplicate, or noncanonical collections.
    pub fn new(
        authorization_revision: ManagementRevision,
        principals: Vec<DirectBindingPrincipalOption>,
        roles: Vec<DirectBindingRoleOption>,
        repositories: Vec<DirectBindingRepositoryOption>,
        runner_groups: Vec<DirectBindingRunnerGroupOption>,
    ) -> Result<Self, ManagementValueError> {
        validate_grant_option_order(
            &principals,
            DirectBindingPrincipalOption::principal_id,
            DirectBindingPrincipalOption::display_name,
        )?;
        validate_grant_option_order(
            &roles,
            DirectBindingRoleOption::role_id,
            DirectBindingRoleOption::display_name,
        )?;
        validate_grant_option_order(
            &repositories,
            DirectBindingRepositoryOption::repository_id,
            DirectBindingRepositoryOption::display_name,
        )?;
        validate_grant_option_order(
            &runner_groups,
            DirectBindingRunnerGroupOption::runner_group_id,
            DirectBindingRunnerGroupOption::display_name,
        )?;
        Ok(Self {
            authorization_revision,
            principals,
            roles,
            repositories,
            runner_groups,
        })
    }

    #[must_use]
    /// Returns the actor authorization revision proven by this snapshot.
    pub const fn authorization_revision(&self) -> ManagementRevision {
        self.authorization_revision
    }

    #[must_use]
    /// Returns active principals eligible to receive a grant.
    pub fn principals(&self) -> &[DirectBindingPrincipalOption] {
        &self.principals
    }

    #[must_use]
    /// Returns current tenant roles eligible to be granted.
    pub fn roles(&self) -> &[DirectBindingRoleOption] {
        &self.roles
    }

    #[must_use]
    /// Returns current tenant repositories eligible as scopes.
    pub fn repositories(&self) -> &[DirectBindingRepositoryOption] {
        &self.repositories
    }

    #[must_use]
    /// Returns current tenant runner groups eligible as scopes.
    pub fn runner_groups(&self) -> &[DirectBindingRunnerGroupOption] {
        &self.runner_groups
    }
}

impl fmt::Debug for DirectBindingGrantOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectBindingGrantOptions")
            .field("authorization_revision", &self.authorization_revision)
            .field("principal_count", &self.principals.len())
            .field("role_count", &self.roles.len())
            .field("repository_count", &self.repositories.len())
            .field("runner_group_count", &self.runner_groups.len())
            .finish()
    }
}

/// Collection whose complete direct-binding choice set exceeded its bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectBindingGrantOptionCollection {
    /// Active eligible principals exceeded 500.
    Principals,
    /// Current grantable roles exceeded 500.
    Roles,
    /// Current repositories exceeded 500.
    Repositories,
    /// Current runner groups exceeded 500.
    RunnerGroups,
}

/// Authorized grant-option state from one coherent storage snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectBindingGrantOptionsState {
    /// Every collection was complete and within its bound.
    Available(DirectBindingGrantOptions),
    /// One collection was larger than the safe browser-management bound.
    Overflow {
        /// Exact actor authorization revision proven before the bounded reads.
        authorization_revision: ManagementRevision,
        /// First collection in canonical evaluation order that exceeded 500.
        collection: DirectBindingGrantOptionCollection,
    },
}

/// Fresh actor evidence for a coherent direct-binding grant-options read.
#[derive(Clone, Eq, PartialEq)]
pub struct ReadDirectBindingGrantOptions {
    actor: ManagementActor,
}

impl ReadDirectBindingGrantOptions {
    #[must_use]
    /// Creates a bounded grant-options request.
    pub const fn new(actor: ManagementActor) -> Self {
        Self { actor }
    }

    #[must_use]
    /// Returns actor evidence that must be reauthorized before any option read.
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }
}

impl fmt::Debug for ReadDirectBindingGrantOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadDirectBindingGrantOptions")
            .finish_non_exhaustive()
    }
}

impl RoleDetailRecord {
    /// Creates a complete role detail projection.
    ///
    /// # Errors
    ///
    /// Rejects an empty, oversized, duplicate, unordered, or grant-inconsistent
    /// catalog. This prevents a partial catalog from being presented as full
    /// role authority.
    pub fn new(
        role: RoleRecord,
        permission_catalog: Vec<RolePermissionRecord>,
    ) -> Result<Self, ManagementValueError> {
        if permission_catalog.is_empty()
            || permission_catalog.len() > MAX_PERMISSION_CATALOG_ENTRIES
            || permission_catalog
                .windows(2)
                .any(|pair| pair[0].permission() >= pair[1].permission())
        {
            return Err(ManagementValueError::InvalidPermissionCatalog);
        }
        let granted = permission_catalog
            .iter()
            .filter(|entry| entry.granted())
            .map(|entry| entry.permission().clone())
            .collect::<BTreeSet<_>>();
        if &granted != role.permissions() {
            return Err(ManagementValueError::InvalidPermissionCatalog);
        }
        Ok(Self {
            role,
            permission_catalog,
        })
    }

    /// Returns the exact role metadata and revision.
    #[must_use]
    pub const fn role(&self) -> &RoleRecord {
        &self.role
    }

    /// Returns every permission catalog entry in canonical name order.
    #[must_use]
    pub fn permission_catalog(&self) -> &[RolePermissionRecord] {
        &self.permission_catalog
    }
}

/// Generic list request whose authorization is rechecked by the repository.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListManagementRecords {
    actor: ManagementActor,
    cursor: Option<String>,
    limit: ManagementPageSize,
}

impl ListManagementRecords {
    /// Creates a bounded list request.
    ///
    /// # Errors
    ///
    /// Rejects a malformed opaque cursor.
    pub fn new(
        actor: ManagementActor,
        cursor: Option<String>,
        limit: ManagementPageSize,
    ) -> Result<Self, ManagementValueError> {
        if cursor.as_ref().is_some_and(|cursor| {
            cursor.is_empty()
                || cursor.len() > MAX_REQUEST_ID_BYTES
                || cursor.chars().any(char::is_whitespace)
        }) {
            return Err(ManagementValueError::InvalidCursor);
        }
        Ok(Self {
            actor,
            cursor,
            limit,
        })
    }

    #[must_use]
    /// Returns actor evidence that must be reauthorized transactionally.
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    #[must_use]
    /// Returns the opaque backend cursor, when continuing a list.
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }

    #[must_use]
    /// Returns the bounded page size.
    pub const fn limit(&self) -> ManagementPageSize {
        self.limit
    }
}

/// Exact management detail lookup for one tenant member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadMemberDetail {
    actor: ManagementActor,
    principal_id: ManagedPrincipalId,
}

impl ReadMemberDetail {
    /// Creates a tenant-bounded member lookup.
    #[must_use]
    pub const fn new(actor: ManagementActor, principal_id: ManagedPrincipalId) -> Self {
        Self {
            actor,
            principal_id,
        }
    }

    /// Returns actor evidence that must be reauthorized before target lookup.
    #[must_use]
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    /// Returns the exact Automata-owned member UUID.
    #[must_use]
    pub const fn principal_id(&self) -> ManagedPrincipalId {
        self.principal_id
    }
}

/// Exact management detail lookup for one tenant role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadRoleDetail {
    actor: ManagementActor,
    role_id: RoleId,
}

impl ReadRoleDetail {
    /// Creates a tenant-bounded role lookup.
    #[must_use]
    pub const fn new(actor: ManagementActor, role_id: RoleId) -> Self {
        Self { actor, role_id }
    }

    /// Returns actor evidence that must be reauthorized before target lookup.
    #[must_use]
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    /// Returns the exact durable role UUID.
    #[must_use]
    pub const fn role_id(&self) -> RoleId {
        self.role_id
    }
}

/// Canonical continuation point for the mixed direct/provider-observed binding
/// projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagementRoleBindingCursor {
    /// Continue after one direct binding UUID.
    Direct(RoleBindingId),
    /// Continue after one principal/mapping pair in provider-observed order.
    ProviderObserved {
        /// Principal whose newest numeric GitHub observation produced the row.
        principal_id: ManagedPrincipalId,
        /// Durable provider role mapping that produced the row.
        mapping_id: ProviderRoleMappingId,
    },
}

impl ManagementRoleBindingCursor {
    /// Parses the exact current cursor grammar.
    ///
    /// Direct rows use `d:<binding UUID>` and provider rows use
    /// `g:<principal UUID>:<mapping UUID>`. No aliases or legacy forms are
    /// accepted.
    ///
    /// # Errors
    ///
    /// Rejects malformed, noncanonical, nil, or mixed-form cursors.
    pub fn new(value: impl AsRef<str>) -> Result<Self, ManagementValueError> {
        let value = value.as_ref();
        if let Some(binding_id) = value.strip_prefix("d:") {
            if binding_id.contains(':') {
                return Err(ManagementValueError::InvalidCursor);
            }
            return RoleBindingId::new(binding_id)
                .map(Self::Direct)
                .map_err(|_| ManagementValueError::InvalidCursor);
        }
        let Some(provider) = value.strip_prefix("g:") else {
            return Err(ManagementValueError::InvalidCursor);
        };
        let Some((principal_id, mapping_id)) = provider.split_once(':') else {
            return Err(ManagementValueError::InvalidCursor);
        };
        if mapping_id.contains(':') {
            return Err(ManagementValueError::InvalidCursor);
        }
        Ok(Self::ProviderObserved {
            principal_id: ManagedPrincipalId::new(principal_id)
                .map_err(|_| ManagementValueError::InvalidCursor)?,
            mapping_id: ProviderRoleMappingId::new(mapping_id)
                .map_err(|_| ManagementValueError::InvalidCursor)?,
        })
    }

    /// Encodes the canonical current cursor form.
    #[must_use]
    pub fn encode(self) -> String {
        match self {
            Self::Direct(binding_id) => format!("d:{binding_id}"),
            Self::ProviderObserved {
                principal_id,
                mapping_id,
            } => format!("g:{principal_id}:{mapping_id}"),
        }
    }
}

/// Bounded list request for rich direct and provider-observed role assignments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListManagementRoleBindings {
    actor: ManagementActor,
    cursor: Option<ManagementRoleBindingCursor>,
    limit: ManagementPageSize,
    principal_id: Option<ManagedPrincipalId>,
}

impl ListManagementRoleBindings {
    /// Creates a bounded canonical assignment-list request.
    ///
    /// When `principal_id` is present, the request supplies the role-assignment
    /// portion of an exact member detail without widening to sibling members.
    ///
    /// # Errors
    ///
    /// Rejects malformed cursors and provider cursors that belong to a different
    /// principal than an exact member filter.
    pub fn new(
        actor: ManagementActor,
        cursor: Option<&str>,
        limit: ManagementPageSize,
        principal_id: Option<ManagedPrincipalId>,
    ) -> Result<Self, ManagementValueError> {
        let cursor = cursor.map(ManagementRoleBindingCursor::new).transpose()?;
        if let (
            Some(ManagementRoleBindingCursor::ProviderObserved {
                principal_id: cursor_principal,
                ..
            }),
            Some(requested_principal),
        ) = (cursor, principal_id)
            && cursor_principal != requested_principal
        {
            return Err(ManagementValueError::InvalidCursor);
        }
        Ok(Self {
            actor,
            cursor,
            limit,
            principal_id,
        })
    }

    /// Returns actor evidence that must be reauthorized transactionally.
    #[must_use]
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    /// Returns the canonical continuation point, when present.
    #[must_use]
    pub const fn cursor(&self) -> Option<ManagementRoleBindingCursor> {
        self.cursor
    }

    /// Returns the bounded result limit.
    #[must_use]
    pub const fn limit(&self) -> ManagementPageSize {
        self.limit
    }

    /// Returns an exact member filter for detail reads, when present.
    #[must_use]
    pub const fn principal_id(&self) -> Option<ManagedPrincipalId> {
        self.principal_id
    }
}

/// Create one custom role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateRole {
    actor: ManagementActor,
    role_id: RoleId,
    name: RoleName,
    display_name: String,
}

impl CreateRole {
    /// Creates a validated role command.
    ///
    /// # Errors
    ///
    /// Rejects an invalid display name.
    pub fn new(
        actor: ManagementActor,
        role_id: RoleId,
        name: RoleName,
        display_name: impl Into<String>,
    ) -> Result<Self, ManagementValueError> {
        let display_name = display_name.into();
        validate_display_name(&display_name)?;
        Ok(Self {
            actor,
            role_id,
            name,
            display_name,
        })
    }

    #[must_use]
    /// Returns actor evidence that must authorize role creation.
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    #[must_use]
    /// Returns the proposed durable role UUID.
    pub const fn role_id(&self) -> RoleId {
        self.role_id
    }

    #[must_use]
    /// Returns the proposed portable role name.
    pub const fn name(&self) -> &RoleName {
        &self.name
    }

    #[must_use]
    /// Returns the proposed bounded display label.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
}

/// Update one custom role's display metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateRole {
    actor: ManagementActor,
    role_id: RoleId,
    expected_revision: ManagementRevision,
    display_name: String,
}

impl UpdateRole {
    /// Creates a revision-guarded update.
    ///
    /// # Errors
    ///
    /// Rejects an invalid display name.
    pub fn new(
        actor: ManagementActor,
        role_id: RoleId,
        expected_revision: ManagementRevision,
        display_name: impl Into<String>,
    ) -> Result<Self, ManagementValueError> {
        let display_name = display_name.into();
        validate_display_name(&display_name)?;
        Ok(Self {
            actor,
            role_id,
            expected_revision,
            display_name,
        })
    }

    #[must_use]
    /// Returns actor evidence that must authorize the update.
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    #[must_use]
    /// Returns the custom role being updated.
    pub const fn role_id(&self) -> RoleId {
        self.role_id
    }

    #[must_use]
    /// Returns the exact role revision required by the update.
    pub const fn expected_revision(&self) -> ManagementRevision {
        self.expected_revision
    }

    #[must_use]
    /// Returns the replacement bounded display label.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
}

/// Delete one custom role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeleteRole {
    actor: ManagementActor,
    role_id: RoleId,
    expected_revision: ManagementRevision,
}

impl DeleteRole {
    #[must_use]
    /// Creates a revision-guarded custom-role deletion command.
    pub const fn new(
        actor: ManagementActor,
        role_id: RoleId,
        expected_revision: ManagementRevision,
    ) -> Self {
        Self {
            actor,
            role_id,
            expected_revision,
        }
    }

    #[must_use]
    /// Returns actor evidence that must authorize deletion.
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    #[must_use]
    /// Returns the custom role being deleted.
    pub const fn role_id(&self) -> RoleId {
        self.role_id
    }

    #[must_use]
    /// Returns the exact role revision required by deletion.
    pub const fn expected_revision(&self) -> ManagementRevision {
        self.expected_revision
    }
}

/// Add or remove one explicit role permission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetRolePermission {
    actor: ManagementActor,
    role_id: RoleId,
    expected_revision: ManagementRevision,
    permission: Permission,
    present: bool,
}

impl SetRolePermission {
    #[must_use]
    /// Creates a revision-guarded command to add or remove one permission.
    pub const fn new(
        actor: ManagementActor,
        role_id: RoleId,
        expected_revision: ManagementRevision,
        permission: Permission,
        present: bool,
    ) -> Self {
        Self {
            actor,
            role_id,
            expected_revision,
            permission,
            present,
        }
    }

    #[must_use]
    /// Returns actor evidence that must authorize the permission change.
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    #[must_use]
    /// Returns the custom role being changed.
    pub const fn role_id(&self) -> RoleId {
        self.role_id
    }

    #[must_use]
    /// Returns the exact role revision required by the change.
    pub const fn expected_revision(&self) -> ManagementRevision {
        self.expected_revision
    }

    #[must_use]
    /// Returns the permission to add or remove.
    pub const fn permission(&self) -> &Permission {
        &self.permission
    }

    #[must_use]
    /// Reports whether the permission should be present after mutation.
    pub const fn present(&self) -> bool {
        self.present
    }
}

/// Grant one direct role at an exact scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantRole {
    actor: ManagementActor,
    binding_id: RoleBindingId,
    principal_id: ManagedPrincipalId,
    role_id: RoleId,
    scope: AuthorizationScope,
    valid_until: Option<UnixTimestamp>,
}

impl GrantRole {
    /// Creates a tenant-consistent role grant.
    ///
    /// # Errors
    ///
    /// Rejects a scope from a different tenant or a nonfuture expiry.
    pub fn new(
        actor: ManagementActor,
        binding_id: RoleBindingId,
        principal_id: ManagedPrincipalId,
        role_id: RoleId,
        scope: AuthorizationScope,
        valid_until: Option<UnixTimestamp>,
    ) -> Result<Self, ManagementValueError> {
        if scope.tenant_id() != actor.tenant_id() {
            return Err(ManagementValueError::CrossTenantScope);
        }
        if valid_until.is_some_and(|expiry| expiry <= actor.now()) {
            return Err(ManagementValueError::InvalidBindingLifetime);
        }
        Ok(Self {
            actor,
            binding_id,
            principal_id,
            role_id,
            scope,
            valid_until,
        })
    }

    #[must_use]
    /// Returns actor evidence that must authorize the direct grant.
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    #[must_use]
    /// Returns the proposed durable binding UUID.
    pub const fn binding_id(&self) -> RoleBindingId {
        self.binding_id
    }

    #[must_use]
    /// Returns the principal receiving the role.
    pub const fn principal_id(&self) -> ManagedPrincipalId {
        self.principal_id
    }

    #[must_use]
    /// Returns the role being granted.
    pub const fn role_id(&self) -> RoleId {
        self.role_id
    }

    #[must_use]
    /// Returns the exact scope of the direct grant.
    pub const fn scope(&self) -> &AuthorizationScope {
        &self.scope
    }

    #[must_use]
    /// Returns the optional future grant deadline.
    pub const fn valid_until(&self) -> Option<UnixTimestamp> {
        self.valid_until
    }
}

/// Revoke one direct role binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeRole {
    actor: ManagementActor,
    binding_id: RoleBindingId,
    expected_revision: ManagementRevision,
    reason: String,
}

impl RevokeRole {
    /// Creates a validated revocation command.
    ///
    /// # Errors
    ///
    /// Rejects visually blank, oversized, control-bearing, or bidi-formatted reasons.
    pub fn new(
        actor: ManagementActor,
        binding_id: RoleBindingId,
        expected_revision: ManagementRevision,
        reason: impl Into<String>,
    ) -> Result<Self, ManagementValueError> {
        let reason = reason.into();
        validate_reason(&reason)?;
        Ok(Self {
            actor,
            binding_id,
            expected_revision,
            reason,
        })
    }

    #[must_use]
    /// Returns actor evidence that must authorize revocation.
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    #[must_use]
    /// Returns the direct binding being revoked.
    pub const fn binding_id(&self) -> RoleBindingId {
        self.binding_id
    }

    #[must_use]
    /// Returns the exact binding revision required by revocation.
    pub const fn expected_revision(&self) -> ManagementRevision {
        self.expected_revision
    }

    #[must_use]
    /// Returns the bounded sanitized audit reason.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Suspend or restore one tenant membership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeMemberStatus {
    actor: ManagementActor,
    principal_id: ManagedPrincipalId,
    expected_revision: ManagementRevision,
    status: MemberStatus,
    reason: Option<String>,
}

impl ChangeMemberStatus {
    /// Creates a revision-guarded member status command.
    ///
    /// # Errors
    ///
    /// Suspension requires a valid reason; restoration forbids one.
    pub fn new(
        actor: ManagementActor,
        principal_id: ManagedPrincipalId,
        expected_revision: ManagementRevision,
        status: MemberStatus,
        reason: Option<String>,
    ) -> Result<Self, ManagementValueError> {
        match (status, reason.as_deref()) {
            (MemberStatus::Suspended, Some(reason)) => validate_reason(reason)?,
            (MemberStatus::Active, None) => {}
            _ => return Err(ManagementValueError::InvalidMemberStatusReason),
        }
        Ok(Self {
            actor,
            principal_id,
            expected_revision,
            status,
            reason,
        })
    }

    #[must_use]
    /// Returns actor evidence that must authorize the status change.
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    #[must_use]
    /// Returns the member whose status will change.
    pub const fn principal_id(&self) -> ManagedPrincipalId {
        self.principal_id
    }

    #[must_use]
    /// Returns the exact member revision required by the change.
    pub const fn expected_revision(&self) -> ManagementRevision {
        self.expected_revision
    }

    #[must_use]
    /// Returns the desired membership status.
    pub const fn status(&self) -> MemberStatus {
        self.status
    }

    #[must_use]
    /// Returns the required suspension reason, absent for restoration.
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }
}

/// Authorization-aware result of a management read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManagementReadOutcome<T> {
    /// The actor was current and authorized; the requested projection is returned.
    Authorized(T),
    /// Current durable grants do not authorize the read.
    Forbidden,
    /// The actor session or authorization revision is no longer current.
    SessionStale,
}

/// Closed authorization and existence result for an exact management detail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManagementDetailOutcome<T> {
    /// The actor was current and authorized; the exact detail is returned.
    Authorized(T),
    /// Current durable grants do not authorize the lookup.
    Forbidden,
    /// The actor session or authorization revision is no longer current.
    SessionStale,
    /// No target with that identity exists inside the actor's tenant.
    NotFound,
}

/// Closed result of a revision-guarded management mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManagementMutationOutcome<T> {
    /// The mutation and its audit event committed atomically.
    Applied(T),
    /// Current durable grants do not authorize the mutation.
    Forbidden,
    /// The actor session or authorization revision is no longer current.
    SessionStale,
    /// The exact target does not exist in the actor's tenant.
    NotFound,
    /// A resource with the requested durable identity or name already exists.
    AlreadyExists,
    /// The target changed from the caller's expected revision.
    RevisionConflict {
        /// Current durable target revision.
        current: ManagementRevision,
    },
    /// The target is a release-defined immutable resource.
    Immutable,
    /// Another live resource still depends on the target.
    ResourceInUse,
    /// The operation would alter the actor's own protected authority.
    SelfModificationForbidden,
    /// The operation would remove the tenant's final effective manager.
    LastManager,
}

/// A management read that returns only authorization-aware outcomes.
pub type ManagementReadFuture<'a, T> = Pin<
    Box<
        dyn Future<Output = Result<ManagementReadOutcome<T>, ManagementRepositoryError>>
            + Send
            + 'a,
    >,
>;

/// An exact management detail read with closed authorization and not-found
/// outcomes.
pub type ManagementDetailFuture<'a, T> = Pin<
    Box<
        dyn Future<Output = Result<ManagementDetailOutcome<T>, ManagementRepositoryError>>
            + Send
            + 'a,
    >,
>;

/// A management mutation that returns only revision- and authorization-aware outcomes.
pub type ManagementMutationFuture<'a, T> = Pin<
    Box<
        dyn Future<Output = Result<ManagementMutationOutcome<T>, ManagementRepositoryError>>
            + Send
            + 'a,
    >,
>;

/// Object-safe storage boundary for human/RBAC administration.
///
/// Implementations must use the permission named in each method's documentation,
/// resolving it from current durable tenant-scoped grants. They must never trust a
/// role name (including `admin`, `owner`, or `installation-owner`) as authority.
pub trait HumanRbacManagementRepository: fmt::Debug + Send + Sync {
    /// Reads the actor's exact current management mutation capabilities from one
    /// fresh authorization snapshot. The result does not itself authorize a
    /// later mutation.
    fn read_mutation_capabilities<'a>(
        &'a self,
        request: &'a ReadManagementMutationCapabilities,
    ) -> ManagementReadFuture<'a, ManagementMutationCapabilities>;

    /// Reads a complete bounded set of direct-binding grant choices after
    /// checking `role-bindings:manage`. Authorization is resolved before any
    /// tenant resource choices are loaded.
    fn read_direct_binding_grant_options<'a>(
        &'a self,
        request: &'a ReadDirectBindingGrantOptions,
    ) -> ManagementReadFuture<'a, DirectBindingGrantOptionsState>;

    /// Lists members after checking `members:read`.
    fn list_members<'a>(
        &'a self,
        request: &'a ListManagementRecords,
    ) -> ManagementReadFuture<'a, ManagementPage<MemberRecord>>;

    /// Lists roles after checking `roles:read`.
    fn list_roles<'a>(
        &'a self,
        request: &'a ListManagementRecords,
    ) -> ManagementReadFuture<'a, ManagementPage<RoleRecord>>;

    /// Lists direct bindings after checking both `members:read` and `roles:read`.
    fn list_role_bindings<'a>(
        &'a self,
        request: &'a ListManagementRecords,
    ) -> ManagementReadFuture<'a, ManagementPage<RoleBindingRecord>>;

    /// Reads one exact member after checking `members:read`. Authorization is
    /// resolved before target existence, so foreign and absent IDs have the
    /// same `NotFound` result only for an authorized actor.
    fn read_member_detail<'a>(
        &'a self,
        request: &'a ReadMemberDetail,
    ) -> ManagementDetailFuture<'a, MemberRecord>;

    /// Reads one exact role and the complete permission catalog after checking
    /// `roles:read`.
    fn read_role_detail<'a>(
        &'a self,
        request: &'a ReadRoleDetail,
    ) -> ManagementDetailFuture<'a, RoleDetailRecord>;

    /// Lists joined direct and newest-valid provider-observed assignments after
    /// checking both `members:read` and `roles:read`.
    fn list_management_role_bindings<'a>(
        &'a self,
        request: &'a ListManagementRoleBindings,
    ) -> ManagementReadFuture<'a, ManagementPage<ManagementRoleBindingRecord>>;

    /// Creates a custom role after checking `roles:manage`.
    fn create_role(&self, request: CreateRole) -> ManagementMutationFuture<'_, RoleRecord>;

    /// Updates a custom role after checking `roles:manage`.
    fn update_role(&self, request: UpdateRole) -> ManagementMutationFuture<'_, RoleRecord>;

    /// Deletes a custom role after checking `roles:manage` and the last-manager invariant.
    fn delete_role(&self, request: DeleteRole) -> ManagementMutationFuture<'_, ()>;

    /// Changes a permission after checking `roles:manage` and the last-manager invariant.
    fn set_role_permission(
        &self,
        request: SetRolePermission,
    ) -> ManagementMutationFuture<'_, RoleRecord>;

    /// Grants a direct role after checking `role-bindings:manage`.
    fn grant_role(&self, request: GrantRole) -> ManagementMutationFuture<'_, RoleBindingRecord>;

    /// Revokes a direct role after checking `role-bindings:manage` and the last-manager invariant.
    fn revoke_role(&self, request: RevokeRole) -> ManagementMutationFuture<'_, RoleBindingRecord>;

    /// Suspends/restores a member after checking `members:manage` and the last-manager invariant.
    fn change_member_status(
        &self,
        request: ChangeMemberStatus,
    ) -> ManagementMutationFuture<'_, MemberRecord>;
}

/// Sanitized failures at the durable RBAC-management boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ManagementRepositoryError {
    /// The bounded request violates the repository contract.
    #[error("RBAC management request is invalid")]
    InvalidRequest,
    #[error("RBAC management storage is unavailable")]
    /// Durable RBAC storage is temporarily unavailable.
    Unavailable,
    /// Durable member, role, binding, or audit state violates an invariant.
    #[error("durable RBAC management data violates an invariant")]
    CorruptData,
}

/// Validation failures for bounded RBAC-management values.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ManagementValueError {
    /// A role UUID was nil, malformed, or noncanonical.
    #[error("role ID must be a canonical non-nil UUID")]
    InvalidRoleId,
    #[error("role-binding ID must be a canonical non-nil UUID")]
    /// A role-binding UUID was nil, malformed, or noncanonical.
    InvalidRoleBindingId,
    /// A provider role-mapping UUID was nil, malformed, or noncanonical.
    #[error("provider role-mapping ID must be a canonical non-nil UUID")]
    InvalidProviderRoleMappingId,
    /// A principal UUID was nil, malformed, or noncanonical.
    #[error("principal ID must be a canonical non-nil UUID")]
    InvalidPrincipalId,
    #[error("management revision must be positive and fit PostgreSQL BIGINT")]
    /// A revision was zero or outside the signed storage range.
    InvalidRevision,
    /// A request correlation identifier was not portable and bounded.
    #[error("management request ID is invalid")]
    InvalidRequestId,
    #[error("management page size must be between 1 and 100")]
    /// A requested page size was zero or above the public maximum.
    InvalidPageSize,
    /// Storage returned more records than the request allowed.
    #[error("management page exceeds its requested limit")]
    OversizedPage,
    #[error("management cursor is invalid")]
    /// An opaque page cursor was empty, oversized, or whitespace-bearing.
    InvalidCursor,
    /// A display label was visually blank, oversized, control-bearing, or bidi-formatted.
    #[error("management display name is invalid")]
    InvalidDisplayName,
    #[error("provider login is invalid")]
    /// Provider login metadata was visually blank, oversized, control-bearing, or bidi-formatted.
    InvalidProviderLogin,
    /// Role origin and immutability flags disagree.
    #[error("role kind and immutability are inconsistent")]
    InvalidRoleKind,
    /// Provider-observed and direct binding source/lifecycle fields disagree.
    #[error("role-binding source and lifecycle are inconsistent")]
    InvalidRoleBindingSource,
    /// A permission description was visually blank, oversized, control-bearing, or bidi-formatted.
    #[error("permission description is invalid")]
    InvalidPermissionDescription,
    /// A role detail did not contain one exact, canonical permission catalog.
    #[error("role permission catalog is invalid")]
    InvalidPermissionCatalog,
    /// A direct-binding option collection exceeded the complete-read bound.
    #[error("direct-binding grant options exceed the bounded collection limit")]
    OversizedGrantOptions,
    /// Direct-binding options were duplicated or not in canonical order.
    #[error("direct-binding grant options are not canonical")]
    InvalidGrantOptionOrder,
    #[error("role grant scope belongs to another tenant")]
    /// A direct role grant names a resource in another tenant.
    CrossTenantScope,
    /// A role-binding deadline is not in the future.
    #[error("role binding must expire in the future")]
    InvalidBindingLifetime,
    #[error("management reason is invalid")]
    /// A required audit reason was visually blank, oversized, control-bearing, or bidi-formatted.
    InvalidReason,
    /// Suspension/restoration state and reason presence disagree.
    #[error("member status and reason are inconsistent")]
    InvalidMemberStatusReason,
}

fn validate_display_name(value: &str) -> Result<(), ManagementValueError> {
    if !is_safe_management_text(value, MAX_DISPLAY_NAME_BYTES) {
        return Err(ManagementValueError::InvalidDisplayName);
    }
    Ok(())
}

fn validate_grant_option_order<T, I>(
    options: &[T],
    id: impl Fn(&T) -> I,
    display_name: impl Fn(&T) -> &str,
) -> Result<(), ManagementValueError>
where
    I: Copy + Ord,
{
    if options.len() > DIRECT_BINDING_GRANT_OPTION_LIMIT {
        return Err(ManagementValueError::OversizedGrantOptions);
    }
    let mut ids = BTreeSet::new();
    let mut previous = None;
    for option in options {
        let option_id = id(option);
        let option_display_name = display_name(option);
        if !ids.insert(option_id)
            || previous.is_some_and(|(previous_display_name, previous_id)| {
                previous_display_name > option_display_name
                    || (previous_display_name == option_display_name && previous_id >= option_id)
            })
        {
            return Err(ManagementValueError::InvalidGrantOptionOrder);
        }
        previous = Some((option_display_name, option_id));
    }
    Ok(())
}

fn validate_optional_display_name(value: Option<&str>) -> Result<(), ManagementValueError> {
    if let Some(value) = value {
        validate_display_name(value)?;
    }
    Ok(())
}

fn validate_provider_login(value: &str) -> Result<(), ManagementValueError> {
    if !is_safe_management_text(value, MAX_DISPLAY_NAME_BYTES) {
        return Err(ManagementValueError::InvalidProviderLogin);
    }
    Ok(())
}

fn validate_reason(value: &str) -> Result<(), ManagementValueError> {
    if !is_safe_management_text(value, MAX_REASON_BYTES) {
        return Err(ManagementValueError::InvalidReason);
    }
    Ok(())
}

fn is_safe_management_text(value: &str, maximum_bytes: usize) -> bool {
    value.len() <= maximum_bytes
        && value
            .chars()
            .any(|character| !character.is_whitespace() && !is_default_ignorable(character))
        && !value.chars().any(is_forbidden_display_character)
}

const fn is_default_ignorable(character: char) -> bool {
    matches!(
        character,
        '\u{00ad}'
            | '\u{034f}'
            | '\u{061c}'
            | '\u{115f}'..='\u{1160}'
            | '\u{17b4}'..='\u{17b5}'
            | '\u{180b}'..='\u{180f}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{fff0}'..='\u{fff8}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0000}'..='\u{e0fff}'
    )
}

const fn is_forbidden_display_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}
