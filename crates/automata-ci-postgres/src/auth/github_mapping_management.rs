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
    session::CLI_SESSION_ACTIVATION_LIFETIME_SECONDS,
};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::{
    session::{database_time_milliseconds, validate_caller_time},
    support::{
        canonical_uuid, is_integrity_violation, management_revision_from_i64 as revision_from_i64,
        management_revision_to_i64 as revision_to_i64, tenant_management_lock,
        tenant_management_read_lock,
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

#[derive(Clone, Copy)]
struct ActorKeys<'a> {
    tenant_id: &'a str,
    principal_id: Uuid,
    session_id: Uuid,
    supplied_authorization_revision: i64,
    caller_now: automata_ci_auth::time::UnixTimestamp,
}

impl<'a> ActorKeys<'a> {
    fn parse(actor: &'a ManagementActor) -> Result<Self, ManagementRepositoryError> {
        Ok(Self {
            tenant_id: actor.tenant_id().as_str(),
            principal_id: canonical_uuid(actor.principal_id().as_str())
                .map_err(|()| ManagementRepositoryError::InvalidRequest)?,
            session_id: canonical_uuid(actor.session_id().as_str())
                .map_err(|()| ManagementRepositoryError::InvalidRequest)?,
            supplied_authorization_revision: revision_to_i64(actor.authorization_revision())?,
            caller_now: actor.now(),
        })
    }
}

#[derive(FromRow)]
struct ActorRow {
    session_authorization_revision: i64,
    session_provider_id: String,
    session_provider_subject: String,
    session_kind: String,
    session_audience: String,
    lifecycle_status: String,
    activation_deadline_ms: Option<i64>,
    activated_at_ms: Option<i64>,
    issued_at_ms: i64,
    idle_expires_at_ms: i64,
    expires_at_ms: i64,
    revoked_at_ms: Option<i64>,
    principal_status: String,
    membership_status: String,
    current_authorization_revision: i64,
}

const ACTOR_SELECT: &str = r"
    SELECT session.authorization_revision AS session_authorization_revision,
           session.provider_id AS session_provider_id,
           session.provider_subject AS session_provider_subject,
           session.session_kind,session.audience AS session_audience,
           session.lifecycle_status,session.activation_deadline_ms,
           session.activated_at_ms,
           session.issued_at_ms,session.idle_expires_at_ms,
           session.expires_at_ms,session.revoked_at_ms,
           principal.status AS principal_status,
           membership.status AS membership_status,
           membership.authorization_revision AS current_authorization_revision
    FROM human_sessions AS session
    JOIN human_principals AS principal ON principal.id=session.principal_id
    JOIN tenant_human_memberships AS membership
      ON membership.tenant_id=session.tenant_id
     AND membership.principal_id=session.principal_id
    WHERE session.tenant_id=$1 AND session.principal_id=$2 AND session.id=$3
";

#[derive(Clone)]
struct AuthorizedActor {
    tenant_id: String,
    principal_id: Uuid,
    session_id: Uuid,
    provider_id: String,
    provider_subject: String,
    authorization_revision: i64,
    caller_now: automata_ci_auth::time::UnixTimestamp,
    issued_at_ms: i64,
    idle_expires_at_ms: i64,
    expires_at_ms: i64,
    now_ms: i64,
}

enum ActorAuthentication {
    Active(AuthorizedActor),
    Stale(AuthorizedActor),
    Forbidden,
}

impl ActorRow {
    fn lifecycle_allows_authority(&self, now_ms: i64) -> Result<bool, ManagementRepositoryError> {
        let valid_cli_deadline = |deadline_ms: i64| {
            deadline_ms > self.issued_at_ms
                && deadline_ms <= self.expires_at_ms
                && deadline_ms
                    .checked_sub(self.issued_at_ms)
                    .is_some_and(|lifetime_ms| {
                        lifetime_ms
                            <= i64::try_from(CLI_SESSION_ACTIVATION_LIFETIME_SECONDS)
                                .expect("the CLI activation lifetime fits BIGINT")
                                * 1_000
                    })
        };
        match (
            self.session_kind.as_str(),
            self.session_audience.as_str(),
            self.lifecycle_status.as_str(),
            self.activation_deadline_ms,
            self.activated_at_ms,
        ) {
            ("browser", "automata.web", "active", None, None) => Ok(true),
            ("cli", "automata.cli", "pending_activation", Some(deadline_ms), None)
                if valid_cli_deadline(deadline_ms) =>
            {
                Ok(false)
            }
            ("cli", "automata.cli", "active", Some(deadline_ms), Some(activated_at_ms))
                if valid_cli_deadline(deadline_ms)
                    && activated_at_ms >= self.issued_at_ms
                    && activated_at_ms < deadline_ms =>
            {
                if activated_at_ms > now_ms {
                    Err(ManagementRepositoryError::CorruptData)
                } else {
                    Ok(true)
                }
            }
            _ => Err(ManagementRepositoryError::CorruptData),
        }
    }

    fn classify(
        self,
        keys: ActorKeys<'_>,
        now_ms: i64,
    ) -> Result<ActorAuthentication, ManagementRepositoryError> {
        if self.session_authorization_revision <= 0 || self.current_authorization_revision <= 0 {
            return Err(ManagementRepositoryError::CorruptData);
        }
        if !self.lifecycle_allows_authority(now_ms)? {
            return Ok(ActorAuthentication::Forbidden);
        }
        match self.principal_status.as_str() {
            "active" => {}
            "disabled" => return Ok(ActorAuthentication::Forbidden),
            _ => return Err(ManagementRepositoryError::CorruptData),
        }
        match self.membership_status.as_str() {
            "active" => {}
            "suspended" => return Ok(ActorAuthentication::Forbidden),
            _ => return Err(ManagementRepositoryError::CorruptData),
        }
        if self.revoked_at_ms.is_some()
            || self.issued_at_ms > now_ms
            || self.idle_expires_at_ms <= now_ms
            || self.expires_at_ms <= now_ms
        {
            return Ok(ActorAuthentication::Forbidden);
        }
        let actor = AuthorizedActor {
            tenant_id: keys.tenant_id.to_owned(),
            principal_id: keys.principal_id,
            session_id: keys.session_id,
            provider_id: self.session_provider_id,
            provider_subject: self.session_provider_subject,
            authorization_revision: self.current_authorization_revision,
            caller_now: keys.caller_now,
            issued_at_ms: self.issued_at_ms,
            idle_expires_at_ms: self.idle_expires_at_ms,
            expires_at_ms: self.expires_at_ms,
            now_ms,
        };
        if self.session_authorization_revision != self.current_authorization_revision
            || keys.supplied_authorization_revision != self.current_authorization_revision
        {
            return Ok(ActorAuthentication::Stale(actor));
        }
        Ok(ActorAuthentication::Active(actor))
    }
}

async fn authenticate_actor(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &ManagementActor,
    lock: bool,
) -> Result<ActorAuthentication, ManagementRepositoryError> {
    let keys = ActorKeys::parse(actor)?;
    let authority_locked = lock_actor_authority(transaction, &keys, lock).await?;
    let row = if authority_locked {
        sqlx::query_as::<_, ActorRow>(ACTOR_SELECT)
            .bind(keys.tenant_id)
            .bind(keys.principal_id)
            .bind(keys.session_id)
            .fetch_optional(&mut **transaction)
            .await
    } else {
        Ok(None)
    }
    .map_err(map_database_error)?;
    let database_time_ms = database_time_milliseconds(transaction)
        .await
        .map_err(map_database_error)?;
    validate_caller_time(keys.caller_now, database_time_ms)
        .map_err(|()| ManagementRepositoryError::InvalidRequest)?;
    row.map_or(Ok(ActorAuthentication::Forbidden), |row| {
        row.classify(keys, database_time_ms)
    })
}

async fn lock_actor_authority(
    transaction: &mut Transaction<'_, Postgres>,
    keys: &ActorKeys<'_>,
    exclusive: bool,
) -> Result<bool, ManagementRepositoryError> {
    // Canonical order after the tenant advisory lock: session, principal,
    // provider identity (when needed), membership, then mapping targets.
    let session: Option<Uuid> = if exclusive {
        sqlx::query_scalar(
            "SELECT principal_id FROM human_sessions WHERE tenant_id=$1 AND principal_id=$2 AND id=$3 FOR UPDATE",
        )
        .bind(keys.tenant_id)
        .bind(keys.principal_id)
        .bind(keys.session_id)
        .fetch_optional(&mut **transaction)
        .await
    } else {
        sqlx::query_scalar(
            "SELECT principal_id FROM human_sessions WHERE tenant_id=$1 AND principal_id=$2 AND id=$3 FOR SHARE",
        )
        .bind(keys.tenant_id)
        .bind(keys.principal_id)
        .bind(keys.session_id)
        .fetch_optional(&mut **transaction)
        .await
    }
    .map_err(map_database_error)?;
    if session != Some(keys.principal_id) {
        return Ok(false);
    }
    let principal: Option<Uuid> = if exclusive {
        sqlx::query_scalar("SELECT id FROM human_principals WHERE id=$1 FOR UPDATE")
            .bind(keys.principal_id)
            .fetch_optional(&mut **transaction)
            .await
    } else {
        sqlx::query_scalar("SELECT id FROM human_principals WHERE id=$1 FOR SHARE")
            .bind(keys.principal_id)
            .fetch_optional(&mut **transaction)
            .await
    }
    .map_err(map_database_error)?;
    if principal != Some(keys.principal_id) {
        return Ok(false);
    }
    let membership: Option<Uuid> = if exclusive {
        sqlx::query_scalar(
            "SELECT principal_id FROM tenant_human_memberships WHERE tenant_id=$1 AND principal_id=$2 FOR UPDATE",
        )
        .bind(keys.tenant_id)
        .bind(keys.principal_id)
        .fetch_optional(&mut **transaction)
        .await
    } else {
        sqlx::query_scalar(
            "SELECT principal_id FROM tenant_human_memberships WHERE tenant_id=$1 AND principal_id=$2 FOR SHARE",
        )
        .bind(keys.tenant_id)
        .bind(keys.principal_id)
        .fetch_optional(&mut **transaction)
        .await
    }
    .map_err(map_database_error)?;
    Ok(membership == Some(keys.principal_id))
}

async fn refresh_actor_time(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &mut AuthorizedActor,
) -> Result<bool, ManagementRepositoryError> {
    let database_time_ms = database_time_milliseconds(transaction)
        .await
        .map_err(map_database_error)?;
    validate_caller_time(actor.caller_now, database_time_ms)
        .map_err(|()| ManagementRepositoryError::InvalidRequest)?;
    if actor.issued_at_ms > database_time_ms
        || actor.idle_expires_at_ms <= database_time_ms
        || actor.expires_at_ms <= database_time_ms
    {
        return Ok(false);
    }
    actor.now_ms = database_time_ms;
    Ok(true)
}

async fn actor_has_permission(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &AuthorizedActor,
    permission: &str,
) -> Result<bool, ManagementRepositoryError> {
    let direct: bool = sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM rbac_role_bindings AS binding
            JOIN tenant_human_memberships AS membership
              ON membership.tenant_id=binding.tenant_id
             AND membership.principal_id=binding.principal_id
             AND membership.status='active'
            JOIN human_principals AS principal
              ON principal.id=binding.principal_id AND principal.status='active'
            JOIN rbac_role_permissions AS role_permission
              ON role_permission.tenant_id=binding.tenant_id
             AND role_permission.role_id=binding.role_id
            WHERE binding.tenant_id=$1 AND binding.principal_id=$2
              AND binding.scope_kind='tenant' AND binding.status='active'
              AND (binding.valid_until_ms IS NULL OR binding.valid_until_ms>$3)
              AND role_permission.permission_name=$4
        )
        ",
    )
    .bind(&actor.tenant_id)
    .bind(actor.principal_id)
    .bind(actor.now_ms)
    .bind(permission)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    if direct || actor.provider_id != "github" {
        return Ok(direct);
    }
    actor_has_github_mapping_permission(transaction, actor, permission).await
}

async fn reauthorize_actor_after_wait(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &mut AuthorizedActor,
) -> Result<bool, ManagementRepositoryError> {
    if !refresh_actor_time(transaction, actor).await? {
        return Ok(false);
    }
    actor_has_permission(transaction, actor, permissions::AUTH_MAPPINGS_MANAGE).await
}

#[derive(FromRow)]
struct GithubAuthoritySnapshotRow {
    id: Uuid,
    provider_token_version: i64,
    observed_at_ms: i64,
    valid_until_ms: i64,
    identity_principal_id: Option<Uuid>,
    identity_provider_subject: Option<String>,
}

#[allow(
    clippy::too_many_lines,
    reason = "the newest numeric GitHub authority proof is intentionally one closed helper"
)]
async fn actor_has_github_mapping_permission(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &AuthorizedActor,
    permission: &str,
) -> Result<bool, ManagementRepositoryError> {
    let snapshots = sqlx::query_as::<_, GithubAuthoritySnapshotRow>(
        r"
        SELECT snapshot.id,snapshot.provider_token_version,
               snapshot.observed_at_ms,snapshot.valid_until_ms,
               identity.principal_id AS identity_principal_id,
               identity.provider_subject AS identity_provider_subject
        FROM github_membership_snapshots AS snapshot
        LEFT JOIN human_provider_identities AS identity
          ON identity.principal_id=snapshot.principal_id
         AND identity.provider_id=snapshot.provider_id
         AND identity.provider_subject=snapshot.provider_subject
        WHERE snapshot.tenant_id=$1 AND snapshot.principal_id=$2
          AND snapshot.provider_id='github' AND snapshot.provider_subject=$3
          AND snapshot.observed_at_ms<=$4
        ORDER BY snapshot.observed_at_ms DESC,snapshot.id DESC
        LIMIT 2
        ",
    )
    .bind(&actor.tenant_id)
    .bind(actor.principal_id)
    .bind(&actor.provider_subject)
    .bind(actor.now_ms)
    .fetch_all(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    let Some(snapshot) = snapshots.first() else {
        return Ok(false);
    };
    let canonical_subject = actor
        .provider_subject
        .parse::<u64>()
        .ok()
        .filter(|subject| *subject > 0)
        .is_some_and(|subject| subject.to_string() == actor.provider_subject);
    if snapshot.id.is_nil()
        || snapshot.provider_token_version <= 0
        || snapshot.observed_at_ms < 0
        || snapshot.valid_until_ms <= snapshot.observed_at_ms
        || !canonical_subject
        || snapshot.identity_principal_id != Some(actor.principal_id)
        || snapshot.identity_provider_subject.as_deref() != Some(actor.provider_subject.as_str())
        || snapshots
            .get(1)
            .is_some_and(|other| other.observed_at_ms == snapshot.observed_at_ms)
    {
        return Err(ManagementRepositoryError::CorruptData);
    }
    if snapshot.valid_until_ms <= actor.now_ms {
        return Ok(false);
    }
    sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM github_role_mappings AS mapping
            JOIN rbac_role_permissions AS role_permission
              ON role_permission.tenant_id=mapping.tenant_id
             AND role_permission.role_id=mapping.role_id
            WHERE mapping.tenant_id=$1 AND mapping.provider_id='github'
              AND mapping.status='active' AND mapping.scope_kind='tenant'
              AND mapping.repository_id IS NULL AND mapping.runner_group_id IS NULL
              AND role_permission.permission_name=$3
              AND (
                  (
                      mapping.team_id IS NULL
                      AND EXISTS (
                          SELECT 1
                          FROM github_organization_membership_observations AS organization
                          WHERE organization.tenant_id=mapping.tenant_id
                            AND organization.snapshot_id=$2
                            AND organization.organization_id=mapping.organization_id
                      )
                  ) OR (
                      mapping.team_id IS NOT NULL
                      AND EXISTS (
                          SELECT 1
                          FROM github_team_membership_observations AS team
                          WHERE team.tenant_id=mapping.tenant_id
                            AND team.snapshot_id=$2
                            AND team.organization_id=mapping.organization_id
                            AND team.team_id=mapping.team_id
                      )
                  )
              )
        )
        ",
    )
    .bind(&actor.tenant_id)
    .bind(snapshot.id)
    .bind(permission)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_database_error)
}

async fn authorize_read(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &ManagementActor,
    permission: &str,
) -> Result<GithubMappingReadOutcome<AuthorizedActor>, ManagementRepositoryError> {
    tenant_management_read_lock(transaction, actor.tenant_id().as_str())
        .await
        .map_err(map_database_error)?;
    match authenticate_actor(transaction, actor, false).await? {
        ActorAuthentication::Forbidden => Ok(GithubMappingReadOutcome::Forbidden),
        ActorAuthentication::Stale(_) => Ok(GithubMappingReadOutcome::SessionStale),
        ActorAuthentication::Active(current) => {
            if actor_has_permission(transaction, &current, permission).await? {
                Ok(GithubMappingReadOutcome::Authorized(current))
            } else {
                Ok(GithubMappingReadOutcome::Forbidden)
            }
        }
    }
}

#[derive(Clone, Copy)]
struct AuditDescriptor<'a> {
    action: &'static str,
    resource_id: &'a str,
    request_id: Option<&'a str>,
}

impl<'a> AuditDescriptor<'a> {
    fn new(action: &'static str, resource_id: &'a str, actor: &'a ManagementActor) -> Self {
        Self {
            action,
            resource_id,
            request_id: actor
                .request_id()
                .map(automata_ci_auth::management::ManagementRequestId::as_str),
        }
    }
}

async fn append_audit_event(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &AuthorizedActor,
    descriptor: AuditDescriptor<'_>,
    outcome: &str,
) -> Result<(), ManagementRepositoryError> {
    sqlx::query(
        r"
        INSERT INTO security_audit_events (
            event_id,tenant_id,occurred_at_ms,actor_kind,
            actor_principal_id,actor_session_id,authorization_revision,
            action,outcome,resource_kind,resource_id,request_id
        ) VALUES ($1,$2,$3,'human',$4,$5,$6,$7,$8,$9,$10,$11)
        ",
    )
    .bind(Uuid::new_v4())
    .bind(&actor.tenant_id)
    .bind(actor.now_ms)
    .bind(actor.principal_id)
    .bind(actor.session_id)
    .bind(actor.authorization_revision)
    .bind(descriptor.action)
    .bind(outcome)
    .bind(RESOURCE_MAPPING)
    .bind(descriptor.resource_id)
    .bind(descriptor.request_id)
    .execute(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    Ok(())
}

enum MutationAuthorization {
    Authorized(AuthorizedActor),
    Forbidden,
    SessionStale,
}

async fn authorize_mutation(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &ManagementActor,
    descriptor: AuditDescriptor<'_>,
) -> Result<MutationAuthorization, ManagementRepositoryError> {
    tenant_management_lock(transaction, actor.tenant_id().as_str())
        .await
        .map_err(map_database_error)?;
    match authenticate_actor(transaction, actor, true).await? {
        ActorAuthentication::Forbidden => Ok(MutationAuthorization::Forbidden),
        ActorAuthentication::Stale(current) => {
            append_audit_event(transaction, &current, descriptor, "denied").await?;
            Ok(MutationAuthorization::SessionStale)
        }
        ActorAuthentication::Active(current) => {
            if actor_has_permission(transaction, &current, permissions::AUTH_MAPPINGS_MANAGE)
                .await?
            {
                Ok(MutationAuthorization::Authorized(current))
            } else {
                append_audit_event(transaction, &current, descriptor, "denied").await?;
                Ok(MutationAuthorization::Forbidden)
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
    append_audit_event(&mut transaction, &actor, descriptor, "denied").await?;
    commit(transaction).await?;
    Ok(outcome)
}

async fn finish_applied<T>(
    mut transaction: Transaction<'_, Postgres>,
    mut actor: AuthorizedActor,
    descriptor: AuditDescriptor<'_>,
    value: T,
) -> Result<GithubMappingMutationOutcome<T>, ManagementRepositoryError> {
    if !refresh_actor_time(&mut transaction, &mut actor).await? {
        return Ok(GithubMappingMutationOutcome::Forbidden);
    }
    append_audit_event(&mut transaction, &actor, descriptor, "succeeded").await?;
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

    fn create_mapping(
        &self,
        request: CreateGithubMapping,
    ) -> GithubMappingMutationFuture<'_, GithubMappingRecord> {
        Box::pin(async move {
            let resource_id = request.mapping_id().to_string();
            let descriptor =
                AuditDescriptor::new(ACTION_MAPPING_CREATE, &resource_id, request.actor());
            let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
            let authorization =
                authorize_mutation(&mut transaction, request.actor(), descriptor).await?;
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
            if !reauthorize_actor_after_wait(&mut transaction, &mut actor).await? {
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

    fn disable_mapping(
        &self,
        request: DisableGithubMapping,
    ) -> GithubMappingMutationFuture<'_, GithubMappingRecord> {
        Box::pin(async move {
            let resource_id = request.mapping_id().to_string();
            let descriptor =
                AuditDescriptor::new(ACTION_MAPPING_DISABLE, &resource_id, request.actor());
            let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
            let authorization =
                authorize_mutation(&mut transaction, request.actor(), descriptor).await?;
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
            if !reauthorize_actor_after_wait(&mut transaction, &mut actor).await? {
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
