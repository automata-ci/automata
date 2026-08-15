use std::fmt;

use automata_ci_auth::{
    authorization::{
        AuthorizationScope, RepositoryResource, RepositoryResourceId, RoleName,
        RunnerGroupResource, RunnerGroupResourceId,
    },
    github_mapping_management::{
        CreateGithubMapping, DisableGithubMapping, GITHUB_MAPPING_OPTION_LIMIT,
        GithubMappingCursor, GithubMappingManagementRepository, GithubMappingMutationFuture,
        GithubMappingMutationOutcome, GithubMappingOptionCollection, GithubMappingOptions,
        GithubMappingOptionsState, GithubMappingPage, GithubMappingReadFuture,
        GithubMappingReadOutcome, GithubMappingRecord, GithubMappingStatus, ListGithubMappings,
        ManagedGithubMappingSource, ReadGithubMappingOptions, permissions,
    },
    human::TenantId,
    management::{
        DirectBindingRepositoryOption, DirectBindingRoleOption, DirectBindingRunnerGroupOption,
        ManagementActor, ManagementRepositoryError, ProviderRoleMappingId, RoleId, RoleKind,
    },
};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::{
    management_authority::{
        ActorAuthentication, AuditDescriptor, AuthorizedActor, MutationAuthorization,
        actor_has_permission, append_audit_event, authenticate_actor, authorize_mutation,
        reauthorize_actor, refresh_actor_time,
    },
    support::{
        is_integrity_violation, management_revision_from_i64 as revision_from_i64,
        management_revision_to_i64 as revision_to_i64, tenant_management_read_lock,
    },
};

const ACTION_MAPPING_CREATE: &str = "rbac.github_mapping.create";
const ACTION_MAPPING_DISABLE: &str = "rbac.github_mapping.disable";
const RESOURCE_MAPPING: &str = "github_role_mapping";

/// Transactional `PostgreSQL` adapter for numeric GitHub role mappings.
///
/// Every operation revalidates the exact actor session, principal, membership,
/// and current direct or newest-valid numeric GitHub permission. Mutations use
/// the same tenant RBAC mutex as the human management adapter and retain exact
/// row locks through the mapping write and immutable audit append.
///
/// Lists use the mapping primary-key keyset. Option result sets are capped by
/// `LIMIT 501`, but the current schema has no supporting label-order indexes or
/// tenant cardinality ceilings, so those scans are only output-bounded.
/// Successful mutations retain tenant-wide authorization-revision invalidation
/// and likewise have tenant-cardinality-wide work. Product composition remains
/// gated on the missing indexes/ceilings or equivalently fail-closed bounded
/// designs.
#[derive(Clone)]
pub struct PostgresGithubMappingManagementRepository {
    pool: PgPool,
}

impl PostgresGithubMappingManagementRepository {
    /// Creates a mapping-management repository backed by `pool`.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl fmt::Debug for PostgresGithubMappingManagementRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresGithubMappingManagementRepository")
            .finish_non_exhaustive()
    }
}

async fn authorize_read(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &ManagementActor,
    permission: &str,
) -> Result<GithubMappingReadOutcome<AuthorizedActor>, ManagementRepositoryError> {
    tenant_management_read_lock(transaction, actor.tenant_id().as_str())
        .await
        .map_err(map_database_error)?;
    match authenticate_actor(transaction, actor, false, map_database_error).await? {
        ActorAuthentication::Forbidden => Ok(GithubMappingReadOutcome::Forbidden),
        ActorAuthentication::Stale(_) => Ok(GithubMappingReadOutcome::SessionStale),
        ActorAuthentication::Active(current) => {
            if actor_has_permission(transaction, &current, permission, map_database_error).await? {
                Ok(GithubMappingReadOutcome::Authorized(current))
            } else {
                Ok(GithubMappingReadOutcome::Forbidden)
            }
        }
    }
}

fn closed_authorization<T>(
    authorization: &MutationAuthorization,
) -> GithubMappingMutationOutcome<T> {
    match authorization {
        MutationAuthorization::Forbidden => GithubMappingMutationOutcome::Forbidden,
        MutationAuthorization::SessionStale => GithubMappingMutationOutcome::SessionStale,
        MutationAuthorization::Authorized(_) => unreachable!("authorized outcome is not closed"),
    }
}

async fn finish_denied<T>(
    mut transaction: Transaction<'_, Postgres>,
    actor: AuthorizedActor,
    descriptor: AuditDescriptor<'_>,
    outcome: GithubMappingMutationOutcome<T>,
) -> Result<GithubMappingMutationOutcome<T>, ManagementRepositoryError> {
    append_audit_event(
        &mut transaction,
        &actor,
        descriptor,
        "denied",
        map_database_error,
    )
    .await?;
    commit(transaction).await?;
    Ok(outcome)
}

async fn finish_applied<T>(
    mut transaction: Transaction<'_, Postgres>,
    mut actor: AuthorizedActor,
    descriptor: AuditDescriptor<'_>,
    value: T,
) -> Result<GithubMappingMutationOutcome<T>, ManagementRepositoryError> {
    if !refresh_actor_time(&mut transaction, &mut actor, map_database_error).await? {
        return Ok(GithubMappingMutationOutcome::Forbidden);
    }
    append_audit_event(
        &mut transaction,
        &actor,
        descriptor,
        "succeeded",
        map_database_error,
    )
    .await?;
    commit(transaction).await?;
    Ok(GithubMappingMutationOutcome::Applied(value))
}

async fn begin_read(pool: &PgPool) -> Result<Transaction<'_, Postgres>, ManagementRepositoryError> {
    pool.begin().await.map_err(map_database_error)
}

async fn commit(transaction: Transaction<'_, Postgres>) -> Result<(), ManagementRepositoryError> {
    transaction.commit().await.map_err(map_database_error)
}

async fn lock_mapping_trigger_revisions(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
) -> Result<(), ManagementRepositoryError> {
    let revisions: Vec<i64> = sqlx::query_scalar(
        r"
        SELECT authorization_revision
        FROM tenant_human_memberships
        WHERE tenant_id=$1
        ORDER BY principal_id
        FOR UPDATE
        ",
    )
    .bind(tenant_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    if revisions.is_empty()
        || revisions
            .iter()
            .any(|revision| *revision <= 0 || *revision == i64::MAX)
    {
        return Err(ManagementRepositoryError::CorruptData);
    }
    Ok(())
}

fn map_database_error(error: sqlx::Error) -> ManagementRepositoryError {
    let numeric_out_of_range = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|code| code == "22003");
    let mapped = if is_integrity_violation(&error) || numeric_out_of_range {
        ManagementRepositoryError::CorruptData
    } else {
        ManagementRepositoryError::Unavailable
    };
    drop(error);
    mapped
}

fn scope_columns(scope: &AuthorizationScope) -> (&'static str, Option<Uuid>, Option<Uuid>) {
    match scope {
        AuthorizationScope::Tenant { .. } => ("tenant", None, None),
        AuthorizationScope::Repository { repository } => (
            "repository",
            Some(repository.repository_id().as_uuid()),
            None,
        ),
        AuthorizationScope::RunnerGroup { runner_group } => (
            "runner_group",
            None,
            Some(runner_group.runner_group_id().as_uuid()),
        ),
    }
}

async fn recheck_role_and_scope(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &AuthorizedActor,
    role_id: Uuid,
    scope: &AuthorizationScope,
) -> Result<bool, ManagementRepositoryError> {
    if scope.tenant_id().as_str() != actor.tenant_id {
        return Err(ManagementRepositoryError::InvalidRequest);
    }
    let role: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM rbac_roles WHERE tenant_id=$1 AND id=$2 FOR SHARE")
            .bind(&actor.tenant_id)
            .bind(role_id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(map_database_error)?;
    if role != Some(role_id) {
        return Ok(false);
    }
    match scope {
        AuthorizationScope::Tenant { .. } => Ok(true),
        AuthorizationScope::Repository { repository } => {
            let tenant: Option<String> = sqlx::query_scalar(
                "SELECT tenant_id FROM repositories WHERE tenant_id=$1 AND id=$2 FOR SHARE",
            )
            .bind(&actor.tenant_id)
            .bind(repository.repository_id().as_uuid())
            .fetch_optional(&mut **transaction)
            .await
            .map_err(map_database_error)?;
            Ok(tenant.as_deref() == Some(actor.tenant_id.as_str()))
        }
        AuthorizationScope::RunnerGroup { runner_group } => {
            let tenant: Option<String> = sqlx::query_scalar(
                "SELECT tenant_id FROM runner_groups WHERE tenant_id=$1 AND id=$2 FOR SHARE",
            )
            .bind(&actor.tenant_id)
            .bind(runner_group.runner_group_id().as_uuid())
            .fetch_optional(&mut **transaction)
            .await
            .map_err(map_database_error)?;
            Ok(tenant.as_deref() == Some(actor.tenant_id.as_str()))
        }
    }
}

#[derive(FromRow)]
struct MappingRow {
    tenant_id: String,
    id: Uuid,
    provider_id: String,
    organization_id: i64,
    organization_login: String,
    team_id: Option<i64>,
    team_slug: Option<String>,
    role_id: Uuid,
    role_tenant_id: Option<String>,
    scope_kind: String,
    repository_id: Option<Uuid>,
    repository_tenant_id: Option<String>,
    runner_group_id: Option<Uuid>,
    runner_group_tenant_id: Option<String>,
    status: String,
    disabled_by_principal_id: Option<Uuid>,
    disabled_membership_principal_id: Option<Uuid>,
    created_at_ms: i64,
    updated_at_ms: i64,
    disabled_at_ms: Option<i64>,
    revision: i64,
}

struct LoadedMapping {
    record: GithubMappingRecord,
    created_at_ms: i64,
}

impl MappingRow {
    #[allow(
        clippy::too_many_lines,
        reason = "one conversion validates every durable mapping shape before projection"
    )]
    fn into_loaded(
        self,
        expected_tenant_id: &str,
    ) -> Result<LoadedMapping, ManagementRepositoryError> {
        if self.tenant_id != expected_tenant_id
            || self.provider_id != "github"
            || self.role_tenant_id.as_deref() != Some(expected_tenant_id)
            || self.created_at_ms < 0
            || self.updated_at_ms < self.created_at_ms
        {
            return Err(ManagementRepositoryError::CorruptData);
        }
        let mapping_id = ProviderRoleMappingId::from_uuid(self.id)
            .map_err(|_| ManagementRepositoryError::CorruptData)?;
        let role_id =
            RoleId::from_uuid(self.role_id).map_err(|_| ManagementRepositoryError::CorruptData)?;
        let organization_id = u64::try_from(self.organization_id)
            .map_err(|_| ManagementRepositoryError::CorruptData)?;
        let source = match (self.team_id, self.team_slug.as_deref()) {
            (None, None) => ManagedGithubMappingSource::organization(
                organization_id,
                self.organization_login.clone(),
            ),
            (Some(team_id), Some(team_slug)) => ManagedGithubMappingSource::team(
                organization_id,
                self.organization_login.clone(),
                u64::try_from(team_id).map_err(|_| ManagementRepositoryError::CorruptData)?,
                team_slug.to_owned(),
            ),
            _ => return Err(ManagementRepositoryError::CorruptData),
        }
        .map_err(|_| ManagementRepositoryError::CorruptData)?;
        if source.organization_login() != self.organization_login
            || source.team_slug() != self.team_slug.as_deref()
        {
            return Err(ManagementRepositoryError::CorruptData);
        }
        let tenant_id = TenantId::new(self.tenant_id.clone())
            .map_err(|_| ManagementRepositoryError::CorruptData)?;
        let scope = match self.scope_kind.as_str() {
            "tenant"
                if self.repository_id.is_none()
                    && self.repository_tenant_id.is_none()
                    && self.runner_group_id.is_none()
                    && self.runner_group_tenant_id.is_none() =>
            {
                AuthorizationScope::tenant(tenant_id)
            }
            "repository"
                if self.runner_group_id.is_none()
                    && self.runner_group_tenant_id.is_none()
                    && self.repository_tenant_id.as_deref() == Some(expected_tenant_id) =>
            {
                AuthorizationScope::repository(RepositoryResource::new(
                    tenant_id,
                    RepositoryResourceId::from_uuid(
                        self.repository_id
                            .ok_or(ManagementRepositoryError::CorruptData)?,
                    )
                    .map_err(|_| ManagementRepositoryError::CorruptData)?,
                ))
            }
            "runner_group"
                if self.repository_id.is_none()
                    && self.repository_tenant_id.is_none()
                    && self.runner_group_tenant_id.as_deref() == Some(expected_tenant_id) =>
            {
                AuthorizationScope::runner_group(RunnerGroupResource::new(
                    tenant_id,
                    RunnerGroupResourceId::from_uuid(
                        self.runner_group_id
                            .ok_or(ManagementRepositoryError::CorruptData)?,
                    )
                    .map_err(|_| ManagementRepositoryError::CorruptData)?,
                ))
            }
            _ => return Err(ManagementRepositoryError::CorruptData),
        };
        let status = match self.status.as_str() {
            "active"
                if self.disabled_by_principal_id.is_none()
                    && self.disabled_membership_principal_id.is_none()
                    && self.disabled_at_ms.is_none() =>
            {
                GithubMappingStatus::Active
            }
            "disabled"
                if self.disabled_by_principal_id.is_some_and(|disabler| {
                    !disabler.is_nil() && self.disabled_membership_principal_id == Some(disabler)
                }) && self.disabled_at_ms.is_some_and(|disabled_at| {
                    disabled_at >= self.created_at_ms && disabled_at <= self.updated_at_ms
                }) =>
            {
                GithubMappingStatus::Disabled
            }
            _ => return Err(ManagementRepositoryError::CorruptData),
        };
        Ok(LoadedMapping {
            record: GithubMappingRecord::new(
                mapping_id,
                source,
                role_id,
                scope,
                status,
                revision_from_i64(self.revision)?,
            ),
            created_at_ms: self.created_at_ms,
        })
    }
}

const MAPPING_SELECT: &str = r"
    SELECT mapping.tenant_id,mapping.id,mapping.provider_id,
           mapping.organization_id,mapping.organization_login,
           mapping.team_id,mapping.team_slug,mapping.role_id,
           role.tenant_id AS role_tenant_id,
           mapping.scope_kind,mapping.repository_id,
           repository.tenant_id AS repository_tenant_id,
           mapping.runner_group_id,
           runner_group.tenant_id AS runner_group_tenant_id,
           mapping.status,mapping.disabled_by_principal_id,
           disabler.principal_id AS disabled_membership_principal_id,
           mapping.created_at_ms,mapping.updated_at_ms,
           mapping.disabled_at_ms,mapping.revision
    FROM github_role_mappings AS mapping
    LEFT JOIN rbac_roles AS role
      ON role.tenant_id=mapping.tenant_id AND role.id=mapping.role_id
    LEFT JOIN repositories AS repository
      ON repository.tenant_id=mapping.tenant_id AND repository.id=mapping.repository_id
    LEFT JOIN runner_groups AS runner_group
      ON runner_group.tenant_id=mapping.tenant_id AND runner_group.id=mapping.runner_group_id
    LEFT JOIN tenant_human_memberships AS disabler
      ON disabler.tenant_id=mapping.tenant_id
     AND disabler.principal_id=mapping.disabled_by_principal_id
    WHERE mapping.tenant_id=$1 AND mapping.id=$2
";

const MAPPING_LOCK_SELECT: &str = r"
    SELECT mapping.tenant_id,mapping.id,mapping.provider_id,
           mapping.organization_id,mapping.organization_login,
           mapping.team_id,mapping.team_slug,mapping.role_id,
           role.tenant_id AS role_tenant_id,
           mapping.scope_kind,mapping.repository_id,
           repository.tenant_id AS repository_tenant_id,
           mapping.runner_group_id,
           runner_group.tenant_id AS runner_group_tenant_id,
           mapping.status,mapping.disabled_by_principal_id,
           disabler.principal_id AS disabled_membership_principal_id,
           mapping.created_at_ms,mapping.updated_at_ms,
           mapping.disabled_at_ms,mapping.revision
    FROM github_role_mappings AS mapping
    LEFT JOIN rbac_roles AS role
      ON role.tenant_id=mapping.tenant_id AND role.id=mapping.role_id
    LEFT JOIN repositories AS repository
      ON repository.tenant_id=mapping.tenant_id AND repository.id=mapping.repository_id
    LEFT JOIN runner_groups AS runner_group
      ON runner_group.tenant_id=mapping.tenant_id AND runner_group.id=mapping.runner_group_id
    LEFT JOIN tenant_human_memberships AS disabler
      ON disabler.tenant_id=mapping.tenant_id
     AND disabler.principal_id=mapping.disabled_by_principal_id
    WHERE mapping.tenant_id=$1 AND mapping.id=$2
    FOR UPDATE OF mapping
";

async fn load_mapping(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    mapping_id: Uuid,
    lock: bool,
) -> Result<Option<LoadedMapping>, ManagementRepositoryError> {
    let row = sqlx::query_as::<_, MappingRow>(if lock {
        MAPPING_LOCK_SELECT
    } else {
        MAPPING_SELECT
    })
    .bind(tenant_id)
    .bind(mapping_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    row.map(|row| row.into_loaded(tenant_id)).transpose()
}

async fn list_mapping_rows(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    cursor: Option<Uuid>,
    limit: i64,
) -> Result<Vec<LoadedMapping>, ManagementRepositoryError> {
    let rows = sqlx::query_as::<_, MappingRow>(
        r"
        SELECT mapping.tenant_id,mapping.id,mapping.provider_id,
               mapping.organization_id,mapping.organization_login,
               mapping.team_id,mapping.team_slug,mapping.role_id,
               role.tenant_id AS role_tenant_id,
               mapping.scope_kind,mapping.repository_id,
               repository.tenant_id AS repository_tenant_id,
               mapping.runner_group_id,
               runner_group.tenant_id AS runner_group_tenant_id,
               mapping.status,mapping.disabled_by_principal_id,
               disabler.principal_id AS disabled_membership_principal_id,
               mapping.created_at_ms,mapping.updated_at_ms,
               mapping.disabled_at_ms,mapping.revision
        FROM github_role_mappings AS mapping
        LEFT JOIN rbac_roles AS role
          ON role.tenant_id=mapping.tenant_id AND role.id=mapping.role_id
        LEFT JOIN repositories AS repository
          ON repository.tenant_id=mapping.tenant_id AND repository.id=mapping.repository_id
        LEFT JOIN runner_groups AS runner_group
          ON runner_group.tenant_id=mapping.tenant_id AND runner_group.id=mapping.runner_group_id
        LEFT JOIN tenant_human_memberships AS disabler
          ON disabler.tenant_id=mapping.tenant_id
         AND disabler.principal_id=mapping.disabled_by_principal_id
        WHERE mapping.tenant_id=$1 AND ($2::uuid IS NULL OR mapping.id>$2)
        ORDER BY mapping.id
        LIMIT $3
        ",
    )
    .bind(tenant_id)
    .bind(cursor)
    .bind(limit)
    .fetch_all(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    rows.into_iter()
        .map(|row| row.into_loaded(tenant_id))
        .collect()
}

#[derive(FromRow)]
struct RoleOptionRow {
    role_id: Uuid,
    name: String,
    display_name: String,
    role_kind: String,
    immutable: bool,
}

impl RoleOptionRow {
    fn into_option(self) -> Result<DirectBindingRoleOption, ManagementRepositoryError> {
        let kind = match self.role_kind.as_str() {
            "built_in" if self.immutable => RoleKind::BuiltIn,
            "custom" => RoleKind::Custom,
            _ => return Err(ManagementRepositoryError::CorruptData),
        };
        DirectBindingRoleOption::new(
            RoleId::from_uuid(self.role_id).map_err(|_| ManagementRepositoryError::CorruptData)?,
            RoleName::new(self.name).map_err(|_| ManagementRepositoryError::CorruptData)?,
            self.display_name,
            kind,
            self.immutable,
        )
        .map_err(|_| ManagementRepositoryError::CorruptData)
    }
}

#[derive(FromRow)]
struct RepositoryOptionRow {
    repository_id: Uuid,
    display_name: String,
}

impl RepositoryOptionRow {
    fn into_option(self) -> Result<DirectBindingRepositoryOption, ManagementRepositoryError> {
        DirectBindingRepositoryOption::new(
            RepositoryResourceId::from_uuid(self.repository_id)
                .map_err(|_| ManagementRepositoryError::CorruptData)?,
            self.display_name,
        )
        .map_err(|_| ManagementRepositoryError::CorruptData)
    }
}

#[derive(FromRow)]
struct RunnerGroupOptionRow {
    runner_group_id: Uuid,
    display_name: String,
}

impl RunnerGroupOptionRow {
    fn into_option(self) -> Result<DirectBindingRunnerGroupOption, ManagementRepositoryError> {
        DirectBindingRunnerGroupOption::new(
            RunnerGroupResourceId::from_uuid(self.runner_group_id)
                .map_err(|_| ManagementRepositoryError::CorruptData)?,
            self.display_name,
        )
        .map_err(|_| ManagementRepositoryError::CorruptData)
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "three bounded option queries intentionally share one authorization snapshot"
)]
async fn load_mapping_options(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &AuthorizedActor,
) -> Result<GithubMappingOptionsState, ManagementRepositoryError> {
    let query_limit = i64::try_from(GITHUB_MAPPING_OPTION_LIMIT + 1)
        .map_err(|_| ManagementRepositoryError::CorruptData)?;
    let role_rows = sqlx::query_as::<_, RoleOptionRow>(
        r#"
        SELECT role.id AS role_id,role.name,role.display_name,
               role.role_kind,role.immutable
        FROM rbac_roles AS role
        WHERE role.tenant_id=$1
        ORDER BY role.display_name COLLATE "C",role.id
        LIMIT $2
        "#,
    )
    .bind(&actor.tenant_id)
    .bind(query_limit)
    .fetch_all(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    let repository_rows = sqlx::query_as::<_, RepositoryOptionRow>(
        r#"
        SELECT repository.id AS repository_id,
               repository.owner || '/' || repository.name AS display_name
        FROM repositories AS repository
        WHERE repository.tenant_id=$1
        ORDER BY (repository.owner || '/' || repository.name) COLLATE "C",repository.id
        LIMIT $2
        "#,
    )
    .bind(&actor.tenant_id)
    .bind(query_limit)
    .fetch_all(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    let runner_group_rows = sqlx::query_as::<_, RunnerGroupOptionRow>(
        r#"
        SELECT runner_group.id AS runner_group_id,runner_group.name AS display_name
        FROM runner_groups AS runner_group
        WHERE runner_group.tenant_id=$1
        ORDER BY runner_group.name COLLATE "C",runner_group.id
        LIMIT $2
        "#,
    )
    .bind(&actor.tenant_id)
    .bind(query_limit)
    .fetch_all(&mut **transaction)
    .await
    .map_err(map_database_error)?;

    let roles = role_rows
        .into_iter()
        .map(RoleOptionRow::into_option)
        .collect::<Result<Vec<_>, _>>()?;
    let repositories = repository_rows
        .into_iter()
        .map(RepositoryOptionRow::into_option)
        .collect::<Result<Vec<_>, _>>()?;
    let runner_groups = runner_group_rows
        .into_iter()
        .map(RunnerGroupOptionRow::into_option)
        .collect::<Result<Vec<_>, _>>()?;
    let authorization_revision = revision_from_i64(actor.authorization_revision)?;
    let overflow = [
        (roles.len(), GithubMappingOptionCollection::Roles),
        (
            repositories.len(),
            GithubMappingOptionCollection::Repositories,
        ),
        (
            runner_groups.len(),
            GithubMappingOptionCollection::RunnerGroups,
        ),
    ]
    .into_iter()
    .find_map(|(length, collection)| (length > GITHUB_MAPPING_OPTION_LIMIT).then_some(collection));
    if let Some(collection) = overflow {
        return Ok(GithubMappingOptionsState::Overflow {
            authorization_revision,
            collection,
        });
    }
    GithubMappingOptions::new(authorization_revision, roles, repositories, runner_groups)
        .map(GithubMappingOptionsState::Available)
        .map_err(|_| ManagementRepositoryError::CorruptData)
}

impl GithubMappingManagementRepository for PostgresGithubMappingManagementRepository {
    fn list_mappings<'a>(
        &'a self,
        request: &'a ListGithubMappings,
    ) -> GithubMappingReadFuture<'a, GithubMappingPage> {
        Box::pin(async move {
            let mut transaction = begin_read(&self.pool).await?;
            let authorized_actor = match authorize_read(
                &mut transaction,
                request.actor(),
                permissions::AUTH_MAPPINGS_READ,
            )
            .await?
            {
                GithubMappingReadOutcome::Forbidden => {
                    commit(transaction).await?;
                    return Ok(GithubMappingReadOutcome::Forbidden);
                }
                GithubMappingReadOutcome::SessionStale => {
                    commit(transaction).await?;
                    return Ok(GithubMappingReadOutcome::SessionStale);
                }
                GithubMappingReadOutcome::Authorized(actor) => actor,
            };
            let row_limit_usize = usize::from(request.limit().value()) + 1;
            let row_limit = i64::try_from(row_limit_usize)
                .map_err(|_| ManagementRepositoryError::CorruptData)?;
            let rows = list_mapping_rows(
                &mut transaction,
                &authorized_actor.tenant_id,
                request.cursor().map(|cursor| cursor.mapping_id().as_uuid()),
                row_limit,
            )
            .await?;
            let has_more = rows.len() > usize::from(request.limit().value());
            let mut records = rows
                .into_iter()
                .map(|loaded| loaded.record)
                .collect::<Vec<_>>();
            if has_more {
                records.pop();
            }
            let next_cursor = has_more
                .then(|| records.last().map(GithubMappingRecord::mapping_id))
                .flatten()
                .map(GithubMappingCursor::from_mapping_id);
            let page = GithubMappingPage::new(
                records,
                next_cursor,
                request.limit(),
                revision_from_i64(authorized_actor.authorization_revision)?,
            )
            .map_err(|_| ManagementRepositoryError::CorruptData)?;
            commit(transaction).await?;
            Ok(GithubMappingReadOutcome::Authorized(page))
        })
    }

    fn read_mapping_options<'a>(
        &'a self,
        request: &'a ReadGithubMappingOptions,
    ) -> GithubMappingReadFuture<'a, GithubMappingOptionsState> {
        Box::pin(async move {
            let mut transaction = begin_read(&self.pool).await?;
            let authorized_actor = match authorize_read(
                &mut transaction,
                request.actor(),
                permissions::AUTH_MAPPINGS_MANAGE,
            )
            .await?
            {
                GithubMappingReadOutcome::Forbidden => {
                    commit(transaction).await?;
                    return Ok(GithubMappingReadOutcome::Forbidden);
                }
                GithubMappingReadOutcome::SessionStale => {
                    commit(transaction).await?;
                    return Ok(GithubMappingReadOutcome::SessionStale);
                }
                GithubMappingReadOutcome::Authorized(actor) => actor,
            };
            let options = load_mapping_options(&mut transaction, &authorized_actor).await?;
            commit(transaction).await?;
            Ok(GithubMappingReadOutcome::Authorized(options))
        })
    }

    #[allow(clippy::too_many_lines)]
    fn create_mapping(
        &self,
        request: CreateGithubMapping,
    ) -> GithubMappingMutationFuture<'_, GithubMappingRecord> {
        Box::pin(async move {
            let resource_id = request.mapping_id().to_string();
            let descriptor = AuditDescriptor::new(
                ACTION_MAPPING_CREATE,
                RESOURCE_MAPPING,
                &resource_id,
                request.actor(),
            );
            let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
            let authorization = authorize_mutation(
                &mut transaction,
                request.actor(),
                &[permissions::AUTH_MAPPINGS_MANAGE],
                descriptor,
                map_database_error,
            )
            .await?;
            let mut actor = match authorization {
                MutationAuthorization::Authorized(actor) => actor,
                closed => {
                    commit(transaction).await?;
                    return Ok(closed_authorization(&closed));
                }
            };
            lock_mapping_trigger_revisions(&mut transaction, &actor.tenant_id).await?;
            if !recheck_role_and_scope(
                &mut transaction,
                &actor,
                request.role_id().as_uuid(),
                request.scope(),
            )
            .await?
            {
                return finish_denied(
                    transaction,
                    actor,
                    descriptor,
                    GithubMappingMutationOutcome::NotFound,
                )
                .await;
            }
            if !reauthorize_actor(
                &mut transaction,
                &mut actor,
                permissions::AUTH_MAPPINGS_MANAGE,
                map_database_error,
            )
            .await?
            {
                return Ok(GithubMappingMutationOutcome::Forbidden);
            }
            let (scope_kind, repository_id, runner_group_id) = scope_columns(request.scope());
            let source = request.source();
            let inserted = sqlx::query(
                r"
                INSERT INTO github_role_mappings (
                    tenant_id,id,provider_id,organization_id,organization_login,
                    team_id,team_slug,role_id,scope_kind,repository_id,
                    runner_group_id,status,created_by_principal_id,
                    created_at_ms,updated_at_ms,revision
                ) VALUES ($1,$2,'github',$3,$4,$5,$6,$7,$8,$9,$10,
                          'active',$11,$12,$12,1)
                ON CONFLICT DO NOTHING
                ",
            )
            .bind(&actor.tenant_id)
            .bind(request.mapping_id().as_uuid())
            .bind(source.organization_id().get())
            .bind(source.organization_login())
            .bind(
                source
                    .team_id()
                    .map(automata_ci_auth::github::GithubTeamId::get),
            )
            .bind(source.team_slug())
            .bind(request.role_id().as_uuid())
            .bind(scope_kind)
            .bind(repository_id)
            .bind(runner_group_id)
            .bind(actor.principal_id)
            .bind(actor.now_ms)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?
            .rows_affected();
            if inserted != 1 {
                return finish_denied(
                    transaction,
                    actor,
                    descriptor,
                    GithubMappingMutationOutcome::AlreadyExists,
                )
                .await;
            }
            let mapping = load_mapping(
                &mut transaction,
                &actor.tenant_id,
                request.mapping_id().as_uuid(),
                false,
            )
            .await?
            .ok_or(ManagementRepositoryError::CorruptData)?
            .record;
            finish_applied(transaction, actor, descriptor, mapping).await
        })
    }

    #[allow(clippy::too_many_lines)]
    fn disable_mapping(
        &self,
        request: DisableGithubMapping,
    ) -> GithubMappingMutationFuture<'_, GithubMappingRecord> {
        Box::pin(async move {
            let resource_id = request.mapping_id().to_string();
            let descriptor = AuditDescriptor::new(
                ACTION_MAPPING_DISABLE,
                RESOURCE_MAPPING,
                &resource_id,
                request.actor(),
            );
            let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
            let authorization = authorize_mutation(
                &mut transaction,
                request.actor(),
                &[permissions::AUTH_MAPPINGS_MANAGE],
                descriptor,
                map_database_error,
            )
            .await?;
            let mut actor = match authorization {
                MutationAuthorization::Authorized(actor) => actor,
                closed => {
                    commit(transaction).await?;
                    return Ok(closed_authorization(&closed));
                }
            };
            lock_mapping_trigger_revisions(&mut transaction, &actor.tenant_id).await?;
            let Some(current) = load_mapping(
                &mut transaction,
                &actor.tenant_id,
                request.mapping_id().as_uuid(),
                true,
            )
            .await?
            else {
                return finish_denied(
                    transaction,
                    actor,
                    descriptor,
                    GithubMappingMutationOutcome::NotFound,
                )
                .await;
            };
            if current.record.revision() != request.expected_revision() {
                let current_revision = current.record.revision();
                return finish_denied(
                    transaction,
                    actor,
                    descriptor,
                    GithubMappingMutationOutcome::RevisionConflict {
                        current: current_revision,
                    },
                )
                .await;
            }
            if current.record.status() == GithubMappingStatus::Disabled {
                return finish_denied(
                    transaction,
                    actor,
                    descriptor,
                    GithubMappingMutationOutcome::AlreadyDisabled,
                )
                .await;
            }
            if !reauthorize_actor(
                &mut transaction,
                &mut actor,
                permissions::AUTH_MAPPINGS_MANAGE,
                map_database_error,
            )
            .await?
            {
                return Ok(GithubMappingMutationOutcome::Forbidden);
            }
            if current.record.revision().value() == i64::MAX as u64
                || actor.now_ms < current.created_at_ms
            {
                return Err(ManagementRepositoryError::CorruptData);
            }
            let updated = sqlx::query(
                r"
                UPDATE github_role_mappings
                SET status='disabled',disabled_by_principal_id=$3,
                    disabled_at_ms=$4,updated_at_ms=GREATEST(updated_at_ms,$4),
                    revision=revision+1
                WHERE tenant_id=$1 AND id=$2 AND provider_id='github'
                  AND status='active' AND revision=$5
                ",
            )
            .bind(&actor.tenant_id)
            .bind(request.mapping_id().as_uuid())
            .bind(actor.principal_id)
            .bind(actor.now_ms)
            .bind(revision_to_i64(request.expected_revision())?)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?
            .rows_affected();
            if updated != 1 {
                return Err(ManagementRepositoryError::CorruptData);
            }
            let mapping = load_mapping(
                &mut transaction,
                &actor.tenant_id,
                request.mapping_id().as_uuid(),
                false,
            )
            .await?
            .ok_or(ManagementRepositoryError::CorruptData)?
            .record;
            finish_applied(transaction, actor, descriptor, mapping).await
        })
    }
}
