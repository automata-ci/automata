//! Revision-safe management contracts for numeric GitHub role mappings.
//!
//! Organization logins and team slugs are presentation metadata only. Stable
//! numeric GitHub identities, Automata-owned UUIDs, exact resource scopes, and
//! transactionally rechecked permissions are the sole authority boundary.

use std::{collections::BTreeSet, fmt, future::Future, pin::Pin};

use crate::{
    authorization::AuthorizationScope,
    github::{GithubOrganizationId, GithubOrganizationLogin, GithubTeamId, GithubTeamSlug},
    management::{
        DirectBindingRepositoryOption, DirectBindingRoleOption, DirectBindingRunnerGroupOption,
        ManagementActor, ManagementRepositoryError, ManagementRevision, ProviderRoleMappingId,
        RoleId,
    },
};

const DEFAULT_PAGE_SIZE: u16 = 50;
const MAX_PAGE_SIZE: u16 = 100;
/// Maximum complete choice count for each mapping-option collection.
pub const GITHUB_MAPPING_OPTION_LIMIT: usize = 500;

/// Permissions required by GitHub role-mapping management operations.
pub mod permissions {
    /// Allows reading durable GitHub role mappings.
    pub const AUTH_MAPPINGS_READ: &str = "auth-mappings:read";
    /// Allows reading mapping choices and creating or disabling mappings.
    pub const AUTH_MAPPINGS_MANAGE: &str = "auth-mappings:manage";
}

/// Bounded mapping page size with a default of 50 and a maximum of 100.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubMappingPageSize(u16);

impl GithubMappingPageSize {
    /// Creates a page size in the inclusive range `1..=100`.
    ///
    /// # Errors
    ///
    /// Rejects zero or a value above 100.
    pub const fn new(value: u16) -> Result<Self, GithubMappingValueError> {
        if value == 0 || value > MAX_PAGE_SIZE {
            return Err(GithubMappingValueError::InvalidPageSize);
        }
        Ok(Self(value))
    }

    /// Returns the bounded database result limit.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }
}

impl Default for GithubMappingPageSize {
    fn default() -> Self {
        Self(DEFAULT_PAGE_SIZE)
    }
}

/// Canonical UUID keyset continuation point for mapping lists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubMappingCursor(ProviderRoleMappingId);

impl GithubMappingCursor {
    /// Parses one canonical, lowercase, hyphenated, non-nil mapping UUID.
    ///
    /// # Errors
    ///
    /// Rejects malformed, noncanonical, or nil UUID text.
    pub fn new(value: impl AsRef<str>) -> Result<Self, GithubMappingValueError> {
        ProviderRoleMappingId::new(value)
            .map(Self)
            .map_err(|_| GithubMappingValueError::InvalidCursor)
    }

    /// Constructs a cursor from an already validated mapping identity.
    #[must_use]
    pub const fn from_mapping_id(mapping_id: ProviderRoleMappingId) -> Self {
        Self(mapping_id)
    }

    /// Returns the exact durable keyset identity.
    #[must_use]
    pub const fn mapping_id(self) -> ProviderRoleMappingId {
        self.0
    }

    /// Encodes the canonical cursor form.
    #[must_use]
    pub fn encode(self) -> String {
        self.0.to_string()
    }
}

/// Stable numeric GitHub membership source plus display-only metadata.
#[derive(Clone, Eq, PartialEq)]
pub enum ManagedGithubMappingSource {
    /// Membership in one exact numeric GitHub organization.
    Organization {
        /// Stable numeric organization identity.
        organization_id: GithubOrganizationId,
        /// Non-authoritative organization login for presentation.
        organization_login: GithubOrganizationLogin,
    },
    /// Membership in one exact numeric GitHub team and containing organization.
    Team {
        /// Stable numeric containing-organization identity.
        organization_id: GithubOrganizationId,
        /// Non-authoritative organization login for presentation.
        organization_login: GithubOrganizationLogin,
        /// Stable numeric team identity.
        team_id: GithubTeamId,
        /// Non-authoritative team slug for presentation.
        team_slug: GithubTeamSlug,
    },
}

impl ManagedGithubMappingSource {
    /// Creates an organization source from an unsigned GitHub ID.
    ///
    /// # Errors
    ///
    /// Rejects zero, a value above `PostgreSQL` `BIGINT`, or invalid display
    /// metadata.
    pub fn organization(
        organization_id: u64,
        organization_login: impl Into<String>,
    ) -> Result<Self, GithubMappingValueError> {
        Ok(Self::Organization {
            organization_id: github_organization_id(organization_id)?,
            organization_login: GithubOrganizationLogin::new(organization_login)
                .map_err(|_| GithubMappingValueError::InvalidOrganizationLogin)?,
        })
    }

    /// Creates a team source from unsigned GitHub organization and team IDs.
    ///
    /// # Errors
    ///
    /// Rejects zero, values above `PostgreSQL` `BIGINT`, or invalid display
    /// metadata.
    pub fn team(
        organization_id: u64,
        organization_login: impl Into<String>,
        team_id: u64,
        team_slug: impl Into<String>,
    ) -> Result<Self, GithubMappingValueError> {
        Ok(Self::Team {
            organization_id: github_organization_id(organization_id)?,
            organization_login: GithubOrganizationLogin::new(organization_login)
                .map_err(|_| GithubMappingValueError::InvalidOrganizationLogin)?,
            team_id: github_team_id(team_id)?,
            team_slug: GithubTeamSlug::new(team_slug)
                .map_err(|_| GithubMappingValueError::InvalidTeamSlug)?,
        })
    }

    /// Returns the stable containing-organization identity.
    #[must_use]
    pub const fn organization_id(&self) -> GithubOrganizationId {
        match self {
            Self::Organization {
                organization_id, ..
            }
            | Self::Team {
                organization_id, ..
            } => *organization_id,
        }
    }

    /// Returns the non-authoritative organization login.
    #[must_use]
    pub fn organization_login(&self) -> &str {
        match self {
            Self::Organization {
                organization_login, ..
            }
            | Self::Team {
                organization_login, ..
            } => organization_login.as_str(),
        }
    }

    /// Returns the stable team identity when this is a team source.
    #[must_use]
    pub const fn team_id(&self) -> Option<GithubTeamId> {
        match self {
            Self::Organization { .. } => None,
            Self::Team { team_id, .. } => Some(*team_id),
        }
    }

    /// Returns the non-authoritative team slug when this is a team source.
    #[must_use]
    pub fn team_slug(&self) -> Option<&str> {
        match self {
            Self::Organization { .. } => None,
            Self::Team { team_slug, .. } => Some(team_slug.as_str()),
        }
    }
}

impl fmt::Debug for ManagedGithubMappingSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Organization {
                organization_id, ..
            } => formatter
                .debug_struct("Organization")
                .field("organization_id", organization_id)
                .finish_non_exhaustive(),
            Self::Team {
                organization_id,
                team_id,
                ..
            } => formatter
                .debug_struct("Team")
                .field("organization_id", organization_id)
                .field("team_id", team_id)
                .finish_non_exhaustive(),
        }
    }
}

fn github_organization_id(value: u64) -> Result<GithubOrganizationId, GithubMappingValueError> {
    let value = i64::try_from(value).map_err(|_| GithubMappingValueError::InvalidGithubId)?;
    GithubOrganizationId::new(value).map_err(|_| GithubMappingValueError::InvalidGithubId)
}

fn github_team_id(value: u64) -> Result<GithubTeamId, GithubMappingValueError> {
    let value = i64::try_from(value).map_err(|_| GithubMappingValueError::InvalidGithubId)?;
    GithubTeamId::new(value).map_err(|_| GithubMappingValueError::InvalidGithubId)
}

/// Durable lifecycle of one GitHub role mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubMappingStatus {
    /// The mapping currently contributes authority for matching observations.
    Active,
    /// The mapping was irreversibly disabled and contributes no authority.
    Disabled,
}

/// Redacted durable GitHub role-mapping projection.
#[derive(Clone, Eq, PartialEq)]
pub struct GithubMappingRecord {
    mapping_id: ProviderRoleMappingId,
    source: ManagedGithubMappingSource,
    role_id: RoleId,
    scope: AuthorizationScope,
    status: GithubMappingStatus,
    revision: ManagementRevision,
}

impl GithubMappingRecord {
    /// Creates one validated mapping record.
    #[must_use]
    pub const fn new(
        mapping_id: ProviderRoleMappingId,
        source: ManagedGithubMappingSource,
        role_id: RoleId,
        scope: AuthorizationScope,
        status: GithubMappingStatus,
        revision: ManagementRevision,
    ) -> Self {
        Self {
            mapping_id,
            source,
            role_id,
            scope,
            status,
            revision,
        }
    }

    /// Returns the tenant-scoped durable mapping UUID.
    #[must_use]
    pub const fn mapping_id(&self) -> ProviderRoleMappingId {
        self.mapping_id
    }

    /// Returns stable numeric source identity and display-only metadata.
    #[must_use]
    pub const fn source(&self) -> &ManagedGithubMappingSource {
        &self.source
    }

    /// Returns the exact Automata-owned role UUID.
    #[must_use]
    pub const fn role_id(&self) -> RoleId {
        self.role_id
    }

    /// Returns the exact tenant, repository, or runner-group scope.
    #[must_use]
    pub const fn scope(&self) -> &AuthorizationScope {
        &self.scope
    }

    /// Returns the irreversible mapping lifecycle.
    #[must_use]
    pub const fn status(&self) -> GithubMappingStatus {
        self.status
    }

    /// Returns the positive optimistic-concurrency revision.
    #[must_use]
    pub const fn revision(&self) -> ManagementRevision {
        self.revision
    }
}

impl fmt::Debug for GithubMappingRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubMappingRecord")
            .field("mapping_id", &self.mapping_id)
            .field("source", &self.source)
            .field("role_id", &self.role_id)
            .field("scope", &self.scope)
            .field("status", &self.status)
            .field("revision", &self.revision)
            .finish()
    }
}

/// One authorization-aware UUID-keyset page of durable mappings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubMappingPage {
    items: Vec<GithubMappingRecord>,
    next_cursor: Option<GithubMappingCursor>,
    authorization_revision: ManagementRevision,
}

impl GithubMappingPage {
    /// Creates a bounded page tied to the reauthorized actor revision.
    ///
    /// # Errors
    ///
    /// Rejects more rows than the requested page size.
    pub fn new(
        items: Vec<GithubMappingRecord>,
        next_cursor: Option<GithubMappingCursor>,
        requested_limit: GithubMappingPageSize,
        authorization_revision: ManagementRevision,
    ) -> Result<Self, GithubMappingValueError> {
        if items.len() > usize::from(requested_limit.value()) {
            return Err(GithubMappingValueError::OversizedPage);
        }
        Ok(Self {
            items,
            next_cursor,
            authorization_revision,
        })
    }

    /// Returns durable active and disabled mapping rows in UUID order.
    #[must_use]
    pub fn items(&self) -> &[GithubMappingRecord] {
        &self.items
    }

    /// Returns the exact keyset continuation point when another row exists.
    #[must_use]
    pub const fn next_cursor(&self) -> Option<GithubMappingCursor> {
        self.next_cursor
    }

    /// Returns the actor authorization revision proven by the read snapshot.
    #[must_use]
    pub const fn authorization_revision(&self) -> ManagementRevision {
        self.authorization_revision
    }
}

/// Collection whose complete mapping choice set exceeded its safe bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubMappingOptionCollection {
    /// Current roles exceeded 500.
    Roles,
    /// Current repositories exceeded 500.
    Repositories,
    /// Current runner groups exceeded 500.
    RunnerGroups,
}

/// One coherent, bounded set of valid mapping role and scope choices.
#[derive(Clone, Eq, PartialEq)]
pub struct GithubMappingOptions {
    authorization_revision: ManagementRevision,
    roles: Vec<DirectBindingRoleOption>,
    repositories: Vec<DirectBindingRepositoryOption>,
    runner_groups: Vec<DirectBindingRunnerGroupOption>,
}

impl GithubMappingOptions {
    /// Creates canonical choices tied to one current actor revision.
    ///
    /// Every collection must contain at most 500 entries, have unique stable
    /// IDs, and be strictly ordered by display label then ID.
    ///
    /// # Errors
    ///
    /// Rejects oversized, duplicate, or noncanonical collections.
    pub fn new(
        authorization_revision: ManagementRevision,
        roles: Vec<DirectBindingRoleOption>,
        repositories: Vec<DirectBindingRepositoryOption>,
        runner_groups: Vec<DirectBindingRunnerGroupOption>,
    ) -> Result<Self, GithubMappingValueError> {
        validate_option_order(
            &roles,
            DirectBindingRoleOption::role_id,
            DirectBindingRoleOption::display_name,
        )?;
        validate_option_order(
            &repositories,
            DirectBindingRepositoryOption::repository_id,
            DirectBindingRepositoryOption::display_name,
        )?;
        validate_option_order(
            &runner_groups,
            DirectBindingRunnerGroupOption::runner_group_id,
            DirectBindingRunnerGroupOption::display_name,
        )?;
        Ok(Self {
            authorization_revision,
            roles,
            repositories,
            runner_groups,
        })
    }

    /// Returns the exact reauthorized actor revision.
    #[must_use]
    pub const fn authorization_revision(&self) -> ManagementRevision {
        self.authorization_revision
    }

    /// Returns current grantable tenant roles.
    #[must_use]
    pub fn roles(&self) -> &[DirectBindingRoleOption] {
        &self.roles
    }

    /// Returns current tenant repositories eligible as exact scopes.
    #[must_use]
    pub fn repositories(&self) -> &[DirectBindingRepositoryOption] {
        &self.repositories
    }

    /// Returns current tenant runner groups eligible as exact scopes.
    #[must_use]
    pub fn runner_groups(&self) -> &[DirectBindingRunnerGroupOption] {
        &self.runner_groups
    }
}

impl fmt::Debug for GithubMappingOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubMappingOptions")
            .field("authorization_revision", &self.authorization_revision)
            .field("role_count", &self.roles.len())
            .field("repository_count", &self.repositories.len())
            .field("runner_group_count", &self.runner_groups.len())
            .finish()
    }
}

fn validate_option_order<T, I>(
    values: &[T],
    id: impl Fn(&T) -> I,
    label: impl Fn(&T) -> &str,
) -> Result<(), GithubMappingValueError>
where
    I: Copy + Ord,
{
    if values.len() > GITHUB_MAPPING_OPTION_LIMIT {
        return Err(GithubMappingValueError::OversizedOptions);
    }
    let mut identities = BTreeSet::new();
    if values.iter().any(|value| !identities.insert(id(value)))
        || values.windows(2).any(|pair| {
            let left_label = label(&pair[0]);
            let right_label = label(&pair[1]);
            left_label > right_label || (left_label == right_label && id(&pair[0]) >= id(&pair[1]))
        })
    {
        return Err(GithubMappingValueError::InvalidOptionOrder);
    }
    Ok(())
}

/// Authorized mapping-option state from one coherent storage snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GithubMappingOptionsState {
    /// Every collection is complete and within its bound.
    Available(GithubMappingOptions),
    /// One collection exceeded 500 rows and no partial choices are returned.
    Overflow {
        /// Exact actor revision reauthorized before the bounded reads.
        authorization_revision: ManagementRevision,
        /// First overflowing collection in canonical evaluation order.
        collection: GithubMappingOptionCollection,
    },
}

/// Bounded UUID-keyset list request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListGithubMappings {
    actor: ManagementActor,
    cursor: Option<GithubMappingCursor>,
    limit: GithubMappingPageSize,
}

impl ListGithubMappings {
    /// Creates a list request, using the default page size when `limit` is absent.
    ///
    /// # Errors
    ///
    /// Rejects a malformed cursor.
    pub fn new(
        actor: ManagementActor,
        cursor: Option<&str>,
        limit: Option<GithubMappingPageSize>,
    ) -> Result<Self, GithubMappingValueError> {
        Ok(Self {
            actor,
            cursor: cursor.map(GithubMappingCursor::new).transpose()?,
            limit: limit.unwrap_or_default(),
        })
    }

    /// Returns actor evidence that must be reauthorized before mapping reads.
    #[must_use]
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    /// Returns the exact UUID keyset continuation point.
    #[must_use]
    pub const fn cursor(&self) -> Option<GithubMappingCursor> {
        self.cursor
    }

    /// Returns the bounded requested page size.
    #[must_use]
    pub const fn limit(&self) -> GithubMappingPageSize {
        self.limit
    }
}

/// Fresh actor evidence for a coherent mapping-options read.
#[derive(Clone, Eq, PartialEq)]
pub struct ReadGithubMappingOptions {
    actor: ManagementActor,
}

impl ReadGithubMappingOptions {
    /// Creates a mapping-options request.
    #[must_use]
    pub const fn new(actor: ManagementActor) -> Self {
        Self { actor }
    }

    /// Returns actor evidence that must be reauthorized before option reads.
    #[must_use]
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }
}

impl fmt::Debug for ReadGithubMappingOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadGithubMappingOptions")
            .finish_non_exhaustive()
    }
}

/// Create one stable numeric GitHub role mapping.
#[derive(Clone, Eq, PartialEq)]
pub struct CreateGithubMapping {
    actor: ManagementActor,
    mapping_id: ProviderRoleMappingId,
    source: ManagedGithubMappingSource,
    role_id: RoleId,
    scope: AuthorizationScope,
}

impl CreateGithubMapping {
    /// Creates a tenant-consistent mapping command with a caller-stable UUID.
    ///
    /// # Errors
    ///
    /// Rejects a scope owned by a different tenant.
    pub fn new(
        actor: ManagementActor,
        mapping_id: ProviderRoleMappingId,
        source: ManagedGithubMappingSource,
        role_id: RoleId,
        scope: AuthorizationScope,
    ) -> Result<Self, GithubMappingValueError> {
        if scope.tenant_id() != actor.tenant_id() {
            return Err(GithubMappingValueError::CrossTenantScope);
        }
        Ok(Self {
            actor,
            mapping_id,
            source,
            role_id,
            scope,
        })
    }

    /// Returns actor evidence that must authorize creation.
    #[must_use]
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    /// Returns the caller-stable durable mapping UUID.
    #[must_use]
    pub const fn mapping_id(&self) -> ProviderRoleMappingId {
        self.mapping_id
    }

    /// Returns stable numeric source identity and display-only metadata.
    #[must_use]
    pub const fn source(&self) -> &ManagedGithubMappingSource {
        &self.source
    }

    /// Returns the exact role UUID to grant.
    #[must_use]
    pub const fn role_id(&self) -> RoleId {
        self.role_id
    }

    /// Returns the exact tenant or resource scope.
    #[must_use]
    pub const fn scope(&self) -> &AuthorizationScope {
        &self.scope
    }
}

impl fmt::Debug for CreateGithubMapping {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreateGithubMapping")
            .field("mapping_id", &self.mapping_id)
            .field("source", &self.source)
            .field("role_id", &self.role_id)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

/// Irreversibly disable one exact mapping revision.
#[derive(Clone, Eq, PartialEq)]
pub struct DisableGithubMapping {
    actor: ManagementActor,
    mapping_id: ProviderRoleMappingId,
    expected_revision: ManagementRevision,
}

impl DisableGithubMapping {
    /// Creates a revision-guarded one-way disable command.
    #[must_use]
    pub const fn new(
        actor: ManagementActor,
        mapping_id: ProviderRoleMappingId,
        expected_revision: ManagementRevision,
    ) -> Self {
        Self {
            actor,
            mapping_id,
            expected_revision,
        }
    }

    /// Returns actor evidence that must authorize the disable.
    #[must_use]
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    /// Returns the exact tenant-scoped mapping UUID.
    #[must_use]
    pub const fn mapping_id(&self) -> ProviderRoleMappingId {
        self.mapping_id
    }

    /// Returns the exact optimistic-concurrency revision.
    #[must_use]
    pub const fn expected_revision(&self) -> ManagementRevision {
        self.expected_revision
    }
}

impl fmt::Debug for DisableGithubMapping {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DisableGithubMapping")
            .field("mapping_id", &self.mapping_id)
            .field("expected_revision", &self.expected_revision)
            .finish_non_exhaustive()
    }
}

/// Authorization-aware result of a mapping read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GithubMappingReadOutcome<T> {
    /// The actor is current and authorized; the requested projection is returned.
    Authorized(T),
    /// Current durable grants do not authorize the read.
    Forbidden,
    /// The actor session or authorization revision is no longer current.
    SessionStale,
}

/// Closed result of a revision-guarded mapping mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GithubMappingMutationOutcome<T> {
    /// The mutation and its sanitized audit event committed atomically.
    Applied(T),
    /// Current durable grants do not authorize the mutation.
    Forbidden,
    /// The actor session or authorization revision is no longer current.
    SessionStale,
    /// No mapping, role, or scope target exists inside the actor's tenant.
    NotFound,
    /// The proposed UUID or active numeric-role-scope tuple already exists.
    AlreadyExists,
    /// The target changed from the caller's expected revision.
    RevisionConflict {
        /// Current durable target revision.
        current: ManagementRevision,
    },
    /// The mapping was already irreversibly disabled.
    AlreadyDisabled,
}

/// A mapping read that returns only authorization-aware outcomes.
pub type GithubMappingReadFuture<'a, T> = Pin<
    Box<
        dyn Future<Output = Result<GithubMappingReadOutcome<T>, ManagementRepositoryError>>
            + Send
            + 'a,
    >,
>;

/// A mapping mutation with closed authorization and revision outcomes.
pub type GithubMappingMutationFuture<'a, T> = Pin<
    Box<
        dyn Future<Output = Result<GithubMappingMutationOutcome<T>, ManagementRepositoryError>>
            + Send
            + 'a,
    >,
>;

/// Object-safe durable boundary for numeric GitHub role mappings.
///
/// Implementations must resolve the documented permission from current durable
/// direct or newest-valid numeric GitHub authority. Role names, organization
/// logins, and team slugs never grant authority.
///
/// Lists use a UUID keyset and bounded result window. Option reads return at
/// most 501 rows per collection, but the current schema has neither supporting
/// label-order indexes nor tenant cardinality ceilings, so it does not yet prove
/// bounded underlying option-scan work. The current migration's security trigger
/// also deliberately invalidates every tenant membership after a successful
/// mutation. Production composition therefore needs the missing indexes and
/// durable cardinality ceilings, or separately proven bounded designs, without
/// weakening complete options or tenant-wide session invalidation.
pub trait GithubMappingManagementRepository: fmt::Debug + Send + Sync {
    /// Lists active and disabled rows after checking `auth-mappings:read`.
    fn list_mappings<'a>(
        &'a self,
        request: &'a ListGithubMappings,
    ) -> GithubMappingReadFuture<'a, GithubMappingPage>;

    /// Reads complete bounded choices after checking `auth-mappings:manage`.
    fn read_mapping_options<'a>(
        &'a self,
        request: &'a ReadGithubMappingOptions,
    ) -> GithubMappingReadFuture<'a, GithubMappingOptionsState>;

    /// Creates a mapping after checking `auth-mappings:manage` and exact targets.
    fn create_mapping(
        &self,
        request: CreateGithubMapping,
    ) -> GithubMappingMutationFuture<'_, GithubMappingRecord>;

    /// Irreversibly disables an exact mapping revision after checking
    /// `auth-mappings:manage`.
    fn disable_mapping(
        &self,
        request: DisableGithubMapping,
    ) -> GithubMappingMutationFuture<'_, GithubMappingRecord>;
}

/// Validation failures for bounded GitHub mapping-management values.
#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
pub enum GithubMappingValueError {
    /// A requested page size was zero or above 100.
    #[error("GitHub mapping page size must be between 1 and 100")]
    InvalidPageSize,
    /// A UUID keyset cursor was malformed, nil, or noncanonical.
    #[error("GitHub mapping cursor is invalid")]
    InvalidCursor,
    /// A GitHub numeric identity was zero or above `PostgreSQL` `BIGINT`.
    #[error("GitHub mapping numeric ID must be positive and fit PostgreSQL BIGINT")]
    InvalidGithubId,
    /// Organization display metadata was malformed or oversized.
    #[error("GitHub organization login is invalid")]
    InvalidOrganizationLogin,
    /// Team display metadata was malformed or oversized.
    #[error("GitHub team slug is invalid")]
    InvalidTeamSlug,
    /// A requested mapping scope belongs to another tenant.
    #[error("GitHub mapping scope belongs to another tenant")]
    CrossTenantScope,
    /// Storage returned more records than the requested page allowed.
    #[error("GitHub mapping page exceeds its requested limit")]
    OversizedPage,
    /// One complete option collection exceeded 500 values.
    #[error("GitHub mapping options exceed the bounded collection limit")]
    OversizedOptions,
    /// Mapping options were duplicated or not in canonical order.
    #[error("GitHub mapping options are not canonical")]
    InvalidOptionOrder,
}
