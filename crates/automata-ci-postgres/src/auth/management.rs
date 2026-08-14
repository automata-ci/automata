use std::{collections::BTreeSet, fmt};

use automata_ci_auth::{
    authorization::{
        AuthorizationScope, Permission, RepositoryResource, RepositoryResourceId, RoleName,
        RunnerGroupResource, RunnerGroupResourceId,
    },
    human::{ProviderId, TenantId},
    management::{
        ChangeMemberStatus, CreateRole, DIRECT_BINDING_GRANT_OPTION_LIMIT, DeleteRole,
        DirectBindingGrantOptionCollection, DirectBindingGrantOptions,
        DirectBindingGrantOptionsState, DirectBindingPrincipalOption,
        DirectBindingRepositoryOption, DirectBindingRoleOption, DirectBindingRunnerGroupOption,
        DirectRoleBindingSource, GrantRole, HumanRbacManagementRepository, ListManagementRecords,
        ListManagementRoleBindings, ManagedPrincipalId, ManagementActor, ManagementBindingRole,
        ManagementDetailFuture, ManagementDetailOutcome, ManagementMutationCapabilities,
        ManagementMutationFuture, ManagementMutationOutcome, ManagementPage, ManagementReadFuture,
        ManagementReadOutcome, ManagementRepositoryError, ManagementRevision,
        ManagementRoleBindingCursor, ManagementRoleBindingRecord, ManagementRoleBindingSource,
        ManagementScopeRecord, MemberRecord, MemberStatus, ProviderRoleMappingId,
        ReadDirectBindingGrantOptions, ReadManagementMutationCapabilities, ReadMemberDetail,
        ReadRoleDetail, RevokeRole, RoleBindingId, RoleBindingRecord, RoleBindingStatus,
        RoleDetailRecord, RoleId, RoleKind, RolePermissionRecord, RoleRecord, SetRolePermission,
        UpdateRole, permissions,
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
        tenant_management_read_lock, timestamp_from_milliseconds, timestamp_to_milliseconds,
    },
};

mod runner_enrollment;

pub use runner_enrollment::{
    ConsumeRunnerEnrollment, CreateRunnerEnrollmentToken, MAX_RUNNER_CERTIFICATE_LIFETIME_SECONDS,
    MIN_RUNNER_CERTIFICATE_REMAINING_LIFETIME_SECONDS, PrepareRunnerEnrollment,
    PreparedRunnerEnrollment, RunnerEnrollmentConsumeOutcome, RunnerEnrollmentPrepareOutcome,
    RunnerEnrollmentTokenRecord,
};

const ACTION_ROLE_CREATE: &str = "rbac.role.create";
const ACTION_ROLE_UPDATE: &str = "rbac.role.update";
const ACTION_ROLE_DELETE: &str = "rbac.role.delete";
const ACTION_ROLE_PERMISSION_SET: &str = "rbac.role.permission.set";
const ACTION_BINDING_GRANT: &str = "rbac.role_binding.grant";
const ACTION_BINDING_REVOKE: &str = "rbac.role_binding.revoke";
const ACTION_MEMBER_STATUS_CHANGE: &str = "rbac.member.status.change";
const RESOURCE_ROLE: &str = "rbac_role";
const RESOURCE_BINDING: &str = "rbac_role_binding";
const RESOURCE_MEMBERSHIP: &str = "tenant_membership";

/// Transactional `PostgreSQL` adapter for the human RBAC management boundary.
///
/// Mutations serialize per tenant, lock and revalidate the exact actor session,
/// principal, and membership before checking current tenant-scoped permission
/// grants, and retain those row locks through the mutation and audit append.
#[derive(Clone)]
pub struct PostgresHumanRbacManagementRepository {
    pool: PgPool,
}

impl PostgresHumanRbacManagementRepository {
    /// Creates an RBAC management repository backed by `pool`.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl fmt::Debug for PostgresHumanRbacManagementRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresHumanRbacManagementRepository")
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
           session.session_kind, session.audience AS session_audience,
           session.lifecycle_status, session.activation_deadline_ms,
           session.activated_at_ms,
           session.issued_at_ms, session.idle_expires_at_ms,
           session.expires_at_ms, session.revoked_at_ms,
           principal.status AS principal_status,
           membership.status AS membership_status,
           membership.authorization_revision AS current_authorization_revision
    FROM human_sessions AS session
    JOIN human_principals AS principal ON principal.id = session.principal_id
    JOIN tenant_human_memberships AS membership
      ON membership.tenant_id = session.tenant_id
     AND membership.principal_id = session.principal_id
    WHERE session.tenant_id = $1
      AND session.principal_id = $2
      AND session.id = $3
";

#[derive(Clone)]
struct AuthorizedActor {
    tenant_id: String,
    principal_id: Uuid,
    session_id: Uuid,
    provider_id: String,
    provider_subject: String,
    authorization_revision: i64,
    liveness: ActorLiveness,
    now_ms: i64,
}

#[derive(Clone, Copy)]
struct ActorLiveness {
    caller_now: automata_ci_auth::time::UnixTimestamp,
    issued_at_ms: i64,
    idle_expires_at_ms: i64,
    expires_at_ms: i64,
}

impl AuthorizedActor {
    fn from_keys(
        keys: ActorKeys<'_>,
        authorization_revision: i64,
        provider_id: String,
        provider_subject: String,
        liveness: ActorLiveness,
        now_ms: i64,
    ) -> Self {
        Self {
            tenant_id: keys.tenant_id.to_owned(),
            principal_id: keys.principal_id,
            session_id: keys.session_id,
            provider_id,
            provider_subject,
            authorization_revision,
            liveness,
            now_ms,
        }
    }
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
        let actor = AuthorizedActor::from_keys(
            keys,
            self.current_authorization_revision,
            self.session_provider_id,
            self.session_provider_subject,
            ActorLiveness {
                caller_now: keys.caller_now,
                issued_at_ms: self.issued_at_ms,
                idle_expires_at_ms: self.idle_expires_at_ms,
                expires_at_ms: self.expires_at_ms,
            },
            now_ms,
        );
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
    // provider identity (when needed), membership, then mutation targets.
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
    validate_caller_time(actor.liveness.caller_now, database_time_ms)
        .map_err(|()| ManagementRepositoryError::InvalidRequest)?;
    if actor.liveness.issued_at_ms > database_time_ms
        || actor.liveness.idle_expires_at_ms <= database_time_ms
        || actor.liveness.expires_at_ms <= database_time_ms
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
              ON role_permission.tenant_id = binding.tenant_id
             AND role_permission.role_id = binding.role_id
            WHERE binding.tenant_id = $1
              AND binding.principal_id = $2
              AND binding.scope_kind = 'tenant'
              AND binding.status = 'active'
              AND (binding.valid_until_ms IS NULL OR binding.valid_until_ms > $3)
              AND role_permission.permission_name = $4
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

#[derive(FromRow)]
struct GithubAuthoritySnapshotRow {
    id: Uuid,
    provider_token_version: i64,
    observed_at_ms: i64,
    valid_until_ms: i64,
    identity_principal_id: Option<Uuid>,
    identity_provider_subject: Option<String>,
}

#[allow(clippy::too_many_lines)]
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
          AND snapshot.observed_at_ms <= $4
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
    let observed_at = timestamp_from_milliseconds(snapshot.observed_at_ms)
        .map_err(|()| ManagementRepositoryError::CorruptData)?;
    let valid_until = timestamp_from_milliseconds(snapshot.valid_until_ms)
        .map_err(|()| ManagementRepositoryError::CorruptData)?;
    if snapshot.id.is_nil()
        || snapshot.provider_token_version <= 0
        || !canonical_subject
        || valid_until <= observed_at
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
            WHERE mapping.tenant_id=$1
              AND mapping.provider_id='github'
              AND mapping.status='active'
              AND mapping.scope_kind='tenant'
              AND mapping.repository_id IS NULL
              AND mapping.runner_group_id IS NULL
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

async fn actor_has_permissions(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &AuthorizedActor,
    required: &[&str],
) -> Result<bool, ManagementRepositoryError> {
    for permission in required {
        if !actor_has_permission(transaction, actor, permission).await? {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn reauthorize_actor(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &mut AuthorizedActor,
    required: &str,
) -> Result<bool, ManagementRepositoryError> {
    if !refresh_actor_time(transaction, actor).await? {
        return Ok(false);
    }
    actor_has_permission(transaction, actor, required).await
}

#[derive(Clone, Copy)]
struct AuditDescriptor<'a> {
    action: &'static str,
    resource_kind: &'static str,
    resource_id: &'a str,
    request_id: Option<&'a str>,
}

impl<'a> AuditDescriptor<'a> {
    fn new(
        action: &'static str,
        resource_kind: &'static str,
        resource_id: &'a str,
        actor: &'a ManagementActor,
    ) -> Self {
        Self {
            action,
            resource_kind,
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
            event_id, tenant_id, occurred_at_ms, actor_kind,
            actor_principal_id, actor_session_id, authorization_revision,
            action, outcome, resource_kind, resource_id, request_id
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
    .bind(descriptor.resource_kind)
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
    required_permissions: &[&str],
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
            if actor_has_permissions(transaction, &current, required_permissions).await? {
                Ok(MutationAuthorization::Authorized(current))
            } else {
                append_audit_event(transaction, &current, descriptor, "denied").await?;
                Ok(MutationAuthorization::Forbidden)
            }
        }
    }
}

async fn authorize_read(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &ManagementActor,
    required_permissions: &[&str],
) -> Result<ManagementReadOutcome<AuthorizedActor>, ManagementRepositoryError> {
    tenant_management_read_lock(transaction, actor.tenant_id().as_str())
        .await
        .map_err(map_database_error)?;
    match authenticate_actor(transaction, actor, false).await? {
        ActorAuthentication::Forbidden => Ok(ManagementReadOutcome::Forbidden),
        ActorAuthentication::Stale(_) => Ok(ManagementReadOutcome::SessionStale),
        ActorAuthentication::Active(current) => {
            if actor_has_permissions(transaction, &current, required_permissions).await? {
                Ok(ManagementReadOutcome::Authorized(current))
            } else {
                Ok(ManagementReadOutcome::Forbidden)
            }
        }
    }
}

async fn begin_read(pool: &PgPool) -> Result<Transaction<'_, Postgres>, ManagementRepositoryError> {
    pool.begin().await.map_err(map_database_error)
}

async fn commit(transaction: Transaction<'_, Postgres>) -> Result<(), ManagementRepositoryError> {
    transaction.commit().await.map_err(map_database_error)
}

fn closed_authorization<T>(authorization: &MutationAuthorization) -> ManagementMutationOutcome<T> {
    match authorization {
        MutationAuthorization::Forbidden => ManagementMutationOutcome::Forbidden,
        MutationAuthorization::SessionStale => ManagementMutationOutcome::SessionStale,
        MutationAuthorization::Authorized(_) => unreachable!("authorized outcome is not closed"),
    }
}

async fn finish_denied<T>(
    mut transaction: Transaction<'_, Postgres>,
    actor: AuthorizedActor,
    descriptor: AuditDescriptor<'_>,
    outcome: ManagementMutationOutcome<T>,
) -> Result<ManagementMutationOutcome<T>, ManagementRepositoryError> {
    append_audit_event(&mut transaction, &actor, descriptor, "denied").await?;
    commit(transaction).await?;
    Ok(outcome)
}

async fn finish_applied<T>(
    mut transaction: Transaction<'_, Postgres>,
    mut actor: AuthorizedActor,
    descriptor: AuditDescriptor<'_>,
    value: T,
) -> Result<ManagementMutationOutcome<T>, ManagementRepositoryError> {
    if !refresh_actor_time(&mut transaction, &mut actor).await? {
        return Ok(ManagementMutationOutcome::Forbidden);
    }
    append_audit_event(&mut transaction, &actor, descriptor, "succeeded").await?;
    commit(transaction).await?;
    Ok(ManagementMutationOutcome::Applied(value))
}

async fn lock_tenant_memberships(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
) -> Result<(), ManagementRepositoryError> {
    let _: Vec<Uuid> = sqlx::query_scalar(
        r"
        SELECT principal_id
        FROM tenant_human_memberships
        WHERE tenant_id = $1
        ORDER BY principal_id
        FOR UPDATE
        ",
    )
    .bind(tenant_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    Ok(())
}

#[derive(Default)]
struct ManagerExclusion {
    principal_id: Option<Uuid>,
    binding_id: Option<Uuid>,
    role_id: Option<Uuid>,
    permission_role_id: Option<Uuid>,
    permission_name: Option<&'static str>,
}

async fn manager_remains(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &AuthorizedActor,
    exclusion: &ManagerExclusion,
) -> Result<bool, ManagementRepositoryError> {
    sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM tenant_human_memberships AS membership
            JOIN human_principals AS principal ON principal.id = membership.principal_id
            WHERE membership.tenant_id = $1
              AND membership.status = 'active'
              AND principal.status = 'active'
              AND ($3::uuid IS NULL OR membership.principal_id <> $3)
              AND EXISTS (
                  SELECT 1
                  FROM rbac_role_bindings AS binding
                  JOIN rbac_role_permissions AS role_permission
                    ON role_permission.tenant_id = binding.tenant_id
                   AND role_permission.role_id = binding.role_id
                  WHERE binding.tenant_id = membership.tenant_id
                    AND binding.principal_id = membership.principal_id
                    AND binding.scope_kind = 'tenant'
                    AND binding.status = 'active'
                    AND (binding.valid_until_ms IS NULL OR binding.valid_until_ms > $2)
                    AND ($4::uuid IS NULL OR binding.id <> $4)
                    AND ($5::uuid IS NULL OR binding.role_id <> $5)
                    AND NOT (
                        $6::uuid IS NOT NULL
                        AND binding.role_id = $6
                        AND role_permission.permission_name = $7
                    )
                    AND role_permission.permission_name = 'roles:manage'
              )
              AND EXISTS (
                  SELECT 1
                  FROM rbac_role_bindings AS binding
                  JOIN rbac_role_permissions AS role_permission
                    ON role_permission.tenant_id = binding.tenant_id
                   AND role_permission.role_id = binding.role_id
                  WHERE binding.tenant_id = membership.tenant_id
                    AND binding.principal_id = membership.principal_id
                    AND binding.scope_kind = 'tenant'
                    AND binding.status = 'active'
                    AND (binding.valid_until_ms IS NULL OR binding.valid_until_ms > $2)
                    AND ($4::uuid IS NULL OR binding.id <> $4)
                    AND ($5::uuid IS NULL OR binding.role_id <> $5)
                    AND NOT (
                        $6::uuid IS NOT NULL
                        AND binding.role_id = $6
                        AND role_permission.permission_name = $7
                    )
                    AND role_permission.permission_name = 'members:manage'
              )
        )
        ",
    )
    .bind(&actor.tenant_id)
    .bind(actor.now_ms)
    .bind(exclusion.principal_id)
    .bind(exclusion.binding_id)
    .bind(exclusion.role_id)
    .bind(exclusion.permission_role_id)
    .bind(exclusion.permission_name)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_database_error)
}

async fn principal_has_manager_capability(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &AuthorizedActor,
    principal_id: Uuid,
) -> Result<bool, ManagementRepositoryError> {
    sqlx::query_scalar(
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
            WHERE binding.tenant_id=$1
              AND binding.principal_id=$2
              AND binding.scope_kind='tenant'
              AND binding.status='active'
              AND (binding.valid_until_ms IS NULL OR binding.valid_until_ms > $3)
              AND role_permission.permission_name IN ('roles:manage','members:manage')
        )
        ",
    )
    .bind(&actor.tenant_id)
    .bind(principal_id)
    .bind(actor.now_ms)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_database_error)
}

fn ensure_revision_can_advance(
    revision: ManagementRevision,
) -> Result<(), ManagementRepositoryError> {
    if revision.value() == i64::MAX as u64 {
        return Err(ManagementRepositoryError::CorruptData);
    }
    Ok(())
}

fn map_database_error(error: sqlx::Error) -> ManagementRepositoryError {
    let mapped = if is_integrity_violation(&error) {
        ManagementRepositoryError::CorruptData
    } else {
        ManagementRepositoryError::Unavailable
    };
    drop(error);
    mapped
}

#[derive(FromRow)]
struct MemberRow {
    principal_id: Uuid,
    provider_id: Option<String>,
    provider_login: Option<String>,
    display_name: Option<String>,
    membership_status: String,
    authorization_revision: i64,
    membership_revision: i64,
}

impl MemberRow {
    fn into_record(self) -> Result<MemberRecord, ManagementRepositoryError> {
        let status = match self.membership_status.as_str() {
            "active" => MemberStatus::Active,
            "suspended" => MemberStatus::Suspended,
            _ => return Err(ManagementRepositoryError::CorruptData),
        };
        MemberRecord::new(
            ManagedPrincipalId::from_uuid(self.principal_id)
                .map_err(|_| ManagementRepositoryError::CorruptData)?,
            ProviderId::new(
                self.provider_id
                    .ok_or(ManagementRepositoryError::CorruptData)?,
            )
            .map_err(|_| ManagementRepositoryError::CorruptData)?,
            self.provider_login
                .ok_or(ManagementRepositoryError::CorruptData)?,
            self.display_name,
            status,
            revision_from_i64(self.authorization_revision)?,
            revision_from_i64(self.membership_revision)?,
        )
        .map_err(|_| ManagementRepositoryError::CorruptData)
    }
}

async fn load_member(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    principal_id: Uuid,
) -> Result<Option<MemberRecord>, ManagementRepositoryError> {
    let row = sqlx::query_as::<_, MemberRow>(
        r"
        SELECT membership.principal_id,
               identity.provider_id,
               identity.provider_login,
               COALESCE(principal.display_name, identity.display_name) AS display_name,
               membership.status AS membership_status,
               membership.authorization_revision,
               membership.revision AS membership_revision
        FROM tenant_human_memberships AS membership
        JOIN human_principals AS principal ON principal.id = membership.principal_id
        LEFT JOIN LATERAL (
            SELECT provider_id, provider_subject, provider_login, display_name
            FROM human_provider_identities
            WHERE principal_id = membership.principal_id
            ORDER BY provider_id, provider_subject
            LIMIT 1
        ) AS identity ON TRUE
        WHERE membership.tenant_id = $1 AND membership.principal_id = $2
        ",
    )
    .bind(tenant_id)
    .bind(principal_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    row.map(MemberRow::into_record).transpose()
}

#[derive(FromRow)]
struct RoleRow {
    id: Uuid,
    name: String,
    display_name: String,
    role_kind: String,
    immutable: bool,
    revision: i64,
    permissions: Vec<String>,
}

impl RoleRow {
    fn into_record(self) -> Result<RoleRecord, ManagementRepositoryError> {
        let kind = match self.role_kind.as_str() {
            "built_in" => RoleKind::BuiltIn,
            "custom" => RoleKind::Custom,
            _ => return Err(ManagementRepositoryError::CorruptData),
        };
        let mut permissions = BTreeSet::new();
        for permission in self.permissions {
            let permission =
                Permission::new(permission).map_err(|_| ManagementRepositoryError::CorruptData)?;
            if !permissions.insert(permission) {
                return Err(ManagementRepositoryError::CorruptData);
            }
        }
        RoleRecord::new(
            RoleId::from_uuid(self.id).map_err(|_| ManagementRepositoryError::CorruptData)?,
            RoleName::new(self.name).map_err(|_| ManagementRepositoryError::CorruptData)?,
            self.display_name,
            kind,
            self.immutable,
            revision_from_i64(self.revision)?,
            permissions,
        )
        .map_err(|_| ManagementRepositoryError::CorruptData)
    }
}

async fn load_role(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    role_id: Uuid,
    lock: bool,
) -> Result<Option<RoleRecord>, ManagementRepositoryError> {
    let row = if lock {
        sqlx::query_as::<_, RoleRow>(
            r"
            SELECT role.id, role.name, role.display_name, role.role_kind,
                   role.immutable, role.revision,
                   ARRAY(
                       SELECT role_permission.permission_name
                       FROM rbac_role_permissions AS role_permission
                       WHERE role_permission.tenant_id = role.tenant_id
                         AND role_permission.role_id = role.id
                       ORDER BY role_permission.permission_name
                   ) AS permissions
            FROM rbac_roles AS role
            WHERE role.tenant_id = $1 AND role.id = $2
            FOR UPDATE OF role
            ",
        )
        .bind(tenant_id)
        .bind(role_id)
        .fetch_optional(&mut **transaction)
        .await
    } else {
        sqlx::query_as::<_, RoleRow>(
            r"
            SELECT role.id, role.name, role.display_name, role.role_kind,
                   role.immutable, role.revision,
                   ARRAY(
                       SELECT role_permission.permission_name
                       FROM rbac_role_permissions AS role_permission
                       WHERE role_permission.tenant_id = role.tenant_id
                         AND role_permission.role_id = role.id
                       ORDER BY role_permission.permission_name
                   ) AS permissions
            FROM rbac_roles AS role
            WHERE role.tenant_id = $1 AND role.id = $2
            ",
        )
        .bind(tenant_id)
        .bind(role_id)
        .fetch_optional(&mut **transaction)
        .await
    }
    .map_err(map_database_error)?;
    row.map(RoleRow::into_record).transpose()
}

#[derive(FromRow)]
struct PermissionCatalogRow {
    permission_name: String,
    description: String,
    critical: bool,
    granted: bool,
}

async fn load_role_detail(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    role_id: Uuid,
) -> Result<Option<RoleDetailRecord>, ManagementRepositoryError> {
    let Some(role) = load_role(transaction, tenant_id, role_id, false).await? else {
        return Ok(None);
    };
    let rows = sqlx::query_as::<_, PermissionCatalogRow>(
        r#"
        SELECT permission.name AS permission_name,
               permission.description,
               permission.critical,
               (role_permission.permission_name IS NOT NULL) AS granted
        FROM rbac_permissions AS permission
        LEFT JOIN rbac_role_permissions AS role_permission
          ON role_permission.tenant_id=$1
         AND role_permission.role_id=$2
         AND role_permission.permission_name=permission.name
        ORDER BY permission.name COLLATE "C"
        LIMIT 257
        "#,
    )
    .bind(tenant_id)
    .bind(role_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    let catalog = rows
        .into_iter()
        .map(|row| {
            RolePermissionRecord::new(
                Permission::new(row.permission_name)
                    .map_err(|_| ManagementRepositoryError::CorruptData)?,
                row.description,
                row.critical,
                row.granted,
            )
            .map_err(|_| ManagementRepositoryError::CorruptData)
        })
        .collect::<Result<Vec<_>, _>>()?;
    RoleDetailRecord::new(role, catalog)
        .map(Some)
        .map_err(|_| ManagementRepositoryError::CorruptData)
}

#[derive(FromRow)]
struct BindingRow {
    tenant_id: String,
    id: Uuid,
    principal_id: Uuid,
    role_id: Uuid,
    scope_kind: String,
    repository_id: Option<Uuid>,
    repository_tenant_id: Option<String>,
    runner_group_id: Option<Uuid>,
    runner_group_tenant_id: Option<String>,
    status: String,
    valid_until_ms: Option<i64>,
    revision: i64,
}

impl BindingRow {
    fn into_record(
        self,
        expected_tenant_id: &str,
    ) -> Result<RoleBindingRecord, ManagementRepositoryError> {
        if self.tenant_id != expected_tenant_id {
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
                let repository_id = self
                    .repository_id
                    .ok_or(ManagementRepositoryError::CorruptData)?;
                AuthorizationScope::repository(RepositoryResource::new(
                    tenant_id,
                    RepositoryResourceId::from_uuid(repository_id)
                        .map_err(|_| ManagementRepositoryError::CorruptData)?,
                ))
            }
            "runner_group"
                if self.repository_id.is_none()
                    && self.repository_tenant_id.is_none()
                    && self.runner_group_tenant_id.as_deref() == Some(expected_tenant_id) =>
            {
                let runner_group_id = self
                    .runner_group_id
                    .ok_or(ManagementRepositoryError::CorruptData)?;
                AuthorizationScope::runner_group(RunnerGroupResource::new(
                    tenant_id,
                    RunnerGroupResourceId::from_uuid(runner_group_id)
                        .map_err(|_| ManagementRepositoryError::CorruptData)?,
                ))
            }
            _ => return Err(ManagementRepositoryError::CorruptData),
        };
        let status = match self.status.as_str() {
            "active" => RoleBindingStatus::Active,
            "revoked" => RoleBindingStatus::Revoked,
            _ => return Err(ManagementRepositoryError::CorruptData),
        };
        Ok(RoleBindingRecord::new(
            RoleBindingId::from_uuid(self.id)
                .map_err(|_| ManagementRepositoryError::CorruptData)?,
            ManagedPrincipalId::from_uuid(self.principal_id)
                .map_err(|_| ManagementRepositoryError::CorruptData)?,
            RoleId::from_uuid(self.role_id).map_err(|_| ManagementRepositoryError::CorruptData)?,
            scope,
            status,
            self.valid_until_ms
                .map(timestamp_from_milliseconds)
                .transpose()
                .map_err(|()| ManagementRepositoryError::CorruptData)?,
            revision_from_i64(self.revision)?,
        ))
    }
}

async fn load_binding(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    binding_id: Uuid,
    lock: bool,
) -> Result<Option<RoleBindingRecord>, ManagementRepositoryError> {
    let row = if lock {
        sqlx::query_as::<_, BindingRow>(
            r"
            SELECT binding.tenant_id, binding.id, binding.principal_id,
                   binding.role_id, binding.scope_kind, binding.repository_id,
                   repository.tenant_id AS repository_tenant_id,
                   binding.runner_group_id,
                   runner_group.tenant_id AS runner_group_tenant_id,
                   binding.status, binding.valid_until_ms, binding.revision
            FROM rbac_role_bindings AS binding
            LEFT JOIN repositories AS repository
              ON repository.tenant_id = binding.tenant_id
             AND repository.id = binding.repository_id
            LEFT JOIN runner_groups AS runner_group
              ON runner_group.tenant_id = binding.tenant_id
             AND runner_group.id = binding.runner_group_id
            WHERE binding.tenant_id = $1 AND binding.id = $2
            FOR UPDATE OF binding
            ",
        )
        .bind(tenant_id)
        .bind(binding_id)
        .fetch_optional(&mut **transaction)
        .await
    } else {
        sqlx::query_as::<_, BindingRow>(
            r"
            SELECT binding.tenant_id, binding.id, binding.principal_id,
                   binding.role_id, binding.scope_kind, binding.repository_id,
                   repository.tenant_id AS repository_tenant_id,
                   binding.runner_group_id,
                   runner_group.tenant_id AS runner_group_tenant_id,
                   binding.status, binding.valid_until_ms, binding.revision
            FROM rbac_role_bindings AS binding
            LEFT JOIN repositories AS repository
              ON repository.tenant_id = binding.tenant_id
             AND repository.id = binding.repository_id
            LEFT JOIN runner_groups AS runner_group
              ON runner_group.tenant_id = binding.tenant_id
             AND runner_group.id = binding.runner_group_id
            WHERE binding.tenant_id = $1 AND binding.id = $2
            ",
        )
        .bind(tenant_id)
        .bind(binding_id)
        .fetch_optional(&mut **transaction)
        .await
    }
    .map_err(map_database_error)?;
    row.map(|row| row.into_record(tenant_id)).transpose()
}

#[derive(FromRow)]
struct ManagementDirectBindingRow {
    tenant_id: String,
    id: Uuid,
    principal_id: Uuid,
    provider_id: Option<String>,
    provider_login: Option<String>,
    principal_display_name: Option<String>,
    membership_status: String,
    authorization_revision: i64,
    membership_revision: i64,
    role_id: Uuid,
    role_name: String,
    role_display_name: String,
    scope_kind: String,
    repository_id: Option<Uuid>,
    repository_tenant_id: Option<String>,
    runner_group_id: Option<Uuid>,
    runner_group_tenant_id: Option<String>,
    scope_display_name: Option<String>,
    assignment_source: String,
    status: String,
    valid_until_ms: Option<i64>,
    revision: i64,
}

#[derive(FromRow)]
struct ManagementProviderBindingRow {
    tenant_id: String,
    principal_id: Uuid,
    provider_id: Option<String>,
    provider_login: Option<String>,
    principal_display_name: Option<String>,
    membership_status: String,
    authorization_revision: i64,
    membership_revision: i64,
    role_id: Uuid,
    role_name: String,
    role_display_name: String,
    scope_kind: String,
    repository_id: Option<Uuid>,
    repository_tenant_id: Option<String>,
    runner_group_id: Option<Uuid>,
    runner_group_tenant_id: Option<String>,
    scope_display_name: Option<String>,
    mapping_id: Uuid,
    mapping_revision: i64,
    organization_id: i64,
    team_id: Option<i64>,
    snapshot_id: Uuid,
    provider_subject: String,
    provider_token_version: i64,
    observed_at_ms: i64,
    valid_until_ms: i64,
    observed_at_ties: i64,
}

#[allow(clippy::too_many_arguments)]
fn management_member_from_parts(
    principal_id: Uuid,
    provider_id: Option<String>,
    provider_login: Option<String>,
    display_name: Option<String>,
    membership_status: String,
    authorization_revision: i64,
    membership_revision: i64,
) -> Result<MemberRecord, ManagementRepositoryError> {
    MemberRow {
        principal_id,
        provider_id,
        provider_login,
        display_name,
        membership_status,
        authorization_revision,
        membership_revision,
    }
    .into_record()
}

#[allow(clippy::too_many_arguments)]
fn management_scope_from_parts(
    expected_tenant_id: &str,
    tenant_id: String,
    scope_kind: &str,
    repository_id: Option<Uuid>,
    repository_tenant_id: Option<&str>,
    runner_group_id: Option<Uuid>,
    runner_group_tenant_id: Option<&str>,
    display_name: Option<String>,
) -> Result<ManagementScopeRecord, ManagementRepositoryError> {
    if tenant_id != expected_tenant_id {
        return Err(ManagementRepositoryError::CorruptData);
    }
    let tenant_id = TenantId::new(tenant_id).map_err(|_| ManagementRepositoryError::CorruptData)?;
    let scope = match scope_kind {
        "tenant"
            if repository_id.is_none()
                && repository_tenant_id.is_none()
                && runner_group_id.is_none()
                && runner_group_tenant_id.is_none() =>
        {
            AuthorizationScope::tenant(tenant_id)
        }
        "repository"
            if runner_group_id.is_none()
                && runner_group_tenant_id.is_none()
                && repository_tenant_id == Some(expected_tenant_id) =>
        {
            AuthorizationScope::repository(RepositoryResource::new(
                tenant_id,
                RepositoryResourceId::from_uuid(
                    repository_id.ok_or(ManagementRepositoryError::CorruptData)?,
                )
                .map_err(|_| ManagementRepositoryError::CorruptData)?,
            ))
        }
        "runner_group"
            if repository_id.is_none()
                && repository_tenant_id.is_none()
                && runner_group_tenant_id == Some(expected_tenant_id) =>
        {
            AuthorizationScope::runner_group(RunnerGroupResource::new(
                tenant_id,
                RunnerGroupResourceId::from_uuid(
                    runner_group_id.ok_or(ManagementRepositoryError::CorruptData)?,
                )
                .map_err(|_| ManagementRepositoryError::CorruptData)?,
            ))
        }
        _ => return Err(ManagementRepositoryError::CorruptData),
    };
    ManagementScopeRecord::new(
        scope,
        display_name.ok_or(ManagementRepositoryError::CorruptData)?,
    )
    .map_err(|_| ManagementRepositoryError::CorruptData)
}

impl ManagementDirectBindingRow {
    fn into_record(
        self,
        expected_tenant_id: &str,
    ) -> Result<ManagementRoleBindingRecord, ManagementRepositoryError> {
        let source = match self.assignment_source.as_str() {
            "manual" => DirectRoleBindingSource::Manual,
            "bootstrap" => DirectRoleBindingSource::Bootstrap,
            "recovery" => DirectRoleBindingSource::Recovery,
            _ => return Err(ManagementRepositoryError::CorruptData),
        };
        let status = match self.status.as_str() {
            "active" => RoleBindingStatus::Active,
            "revoked" => RoleBindingStatus::Revoked,
            _ => return Err(ManagementRepositoryError::CorruptData),
        };
        let principal = management_member_from_parts(
            self.principal_id,
            self.provider_id,
            self.provider_login,
            self.principal_display_name,
            self.membership_status,
            self.authorization_revision,
            self.membership_revision,
        )?;
        let role = ManagementBindingRole::new(
            RoleId::from_uuid(self.role_id).map_err(|_| ManagementRepositoryError::CorruptData)?,
            RoleName::new(self.role_name).map_err(|_| ManagementRepositoryError::CorruptData)?,
            self.role_display_name,
        )
        .map_err(|_| ManagementRepositoryError::CorruptData)?;
        let scope = management_scope_from_parts(
            expected_tenant_id,
            self.tenant_id,
            &self.scope_kind,
            self.repository_id,
            self.repository_tenant_id.as_deref(),
            self.runner_group_id,
            self.runner_group_tenant_id.as_deref(),
            self.scope_display_name,
        )?;
        ManagementRoleBindingRecord::new(
            RoleBindingId::from_uuid(self.id)
                .map_err(|_| ManagementRepositoryError::CorruptData)?,
            principal,
            role,
            scope,
            ManagementRoleBindingSource::Direct(source),
            status,
            self.valid_until_ms
                .map(timestamp_from_milliseconds)
                .transpose()
                .map_err(|()| ManagementRepositoryError::CorruptData)?,
            revision_from_i64(self.revision)?,
        )
        .map_err(|_| ManagementRepositoryError::CorruptData)
    }
}

impl ManagementProviderBindingRow {
    fn into_record(
        self,
        expected_tenant_id: &str,
        now_ms: i64,
    ) -> Result<ManagementRoleBindingRecord, ManagementRepositoryError> {
        let canonical_subject = self
            .provider_subject
            .parse::<u64>()
            .ok()
            .filter(|subject| *subject > 0)
            .is_some_and(|subject| subject.to_string() == self.provider_subject);
        let observed_at = timestamp_from_milliseconds(self.observed_at_ms)
            .map_err(|()| ManagementRepositoryError::CorruptData)?;
        let valid_until = timestamp_from_milliseconds(self.valid_until_ms)
            .map_err(|()| ManagementRepositoryError::CorruptData)?;
        if self.snapshot_id.is_nil()
            || self.provider_token_version <= 0
            || !canonical_subject
            || self.organization_id <= 0
            || self.team_id.is_some_and(|team_id| team_id <= 0)
            || self.observed_at_ties != 1
            || valid_until <= observed_at
            || self.valid_until_ms <= now_ms
        {
            return Err(ManagementRepositoryError::CorruptData);
        }
        let principal = management_member_from_parts(
            self.principal_id,
            self.provider_id,
            self.provider_login,
            self.principal_display_name,
            self.membership_status,
            self.authorization_revision,
            self.membership_revision,
        )?;
        let role = ManagementBindingRole::new(
            RoleId::from_uuid(self.role_id).map_err(|_| ManagementRepositoryError::CorruptData)?,
            RoleName::new(self.role_name).map_err(|_| ManagementRepositoryError::CorruptData)?,
            self.role_display_name,
        )
        .map_err(|_| ManagementRepositoryError::CorruptData)?;
        let scope = management_scope_from_parts(
            expected_tenant_id,
            self.tenant_id,
            &self.scope_kind,
            self.repository_id,
            self.repository_tenant_id.as_deref(),
            self.runner_group_id,
            self.runner_group_tenant_id.as_deref(),
            self.scope_display_name,
        )?;
        let mapping_id = ProviderRoleMappingId::from_uuid(self.mapping_id)
            .map_err(|_| ManagementRepositoryError::CorruptData)?;
        let principal_id = principal.principal_id();
        ManagementRoleBindingRecord::new(
            RoleBindingId::for_provider_observation(principal_id, mapping_id),
            principal,
            role,
            scope,
            ManagementRoleBindingSource::ProviderObserved { mapping_id },
            RoleBindingStatus::Active,
            Some(valid_until),
            revision_from_i64(self.mapping_revision)?,
        )
        .map_err(|_| ManagementRepositoryError::CorruptData)
    }
}

struct ProjectedManagementBinding {
    record: ManagementRoleBindingRecord,
    cursor: ManagementRoleBindingCursor,
}

async fn load_management_direct_bindings(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    principal_id: Option<Uuid>,
    cursor: Option<Uuid>,
    limit: i64,
) -> Result<Vec<ProjectedManagementBinding>, ManagementRepositoryError> {
    let rows = sqlx::query_as::<_, ManagementDirectBindingRow>(
        r"
        SELECT binding.tenant_id,binding.id,binding.principal_id,
               identity.provider_id,identity.provider_login,
               COALESCE(principal.display_name,identity.display_name)
                   AS principal_display_name,
               membership.status AS membership_status,
               membership.authorization_revision,
               membership.revision AS membership_revision,
               role.id AS role_id,role.name AS role_name,
               role.display_name AS role_display_name,
               binding.scope_kind,binding.repository_id,
               repository.tenant_id AS repository_tenant_id,
               binding.runner_group_id,
               runner_group.tenant_id AS runner_group_tenant_id,
               CASE binding.scope_kind
                   WHEN 'tenant' THEN tenant.display_name
                   WHEN 'repository' THEN repository.owner || '/' || repository.name
                   WHEN 'runner_group' THEN runner_group.name
               END AS scope_display_name,
               binding.assignment_source,binding.status,
               binding.valid_until_ms,binding.revision
        FROM rbac_role_bindings AS binding
        JOIN tenant_human_memberships AS membership
          ON membership.tenant_id=binding.tenant_id
         AND membership.principal_id=binding.principal_id
        JOIN human_principals AS principal ON principal.id=binding.principal_id
        LEFT JOIN LATERAL (
            SELECT provider_id,provider_subject,provider_login,display_name
            FROM human_provider_identities
            WHERE principal_id=binding.principal_id
            ORDER BY provider_id,provider_subject
            LIMIT 1
        ) AS identity ON TRUE
        JOIN rbac_roles AS role
          ON role.tenant_id=binding.tenant_id AND role.id=binding.role_id
        JOIN tenants AS tenant ON tenant.id=binding.tenant_id
        LEFT JOIN repositories AS repository
          ON repository.tenant_id=binding.tenant_id
         AND repository.id=binding.repository_id
        LEFT JOIN runner_groups AS runner_group
          ON runner_group.tenant_id=binding.tenant_id
         AND runner_group.id=binding.runner_group_id
        WHERE binding.tenant_id=$1
          AND ($2::uuid IS NULL OR binding.principal_id=$2)
          AND ($3::uuid IS NULL OR binding.id>$3)
        ORDER BY binding.id
        LIMIT $4
        ",
    )
    .bind(tenant_id)
    .bind(principal_id)
    .bind(cursor)
    .bind(limit)
    .fetch_all(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    rows.into_iter()
        .map(|row| {
            let cursor = ManagementRoleBindingCursor::Direct(
                RoleBindingId::from_uuid(row.id)
                    .map_err(|_| ManagementRepositoryError::CorruptData)?,
            );
            Ok(ProjectedManagementBinding {
                record: row.into_record(tenant_id)?,
                cursor,
            })
        })
        .collect()
}

#[allow(
    clippy::too_many_lines,
    reason = "the single bounded SQL statement keeps newest snapshot selection and mapping joins atomic"
)]
async fn load_management_provider_bindings(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    now_ms: i64,
    principal_id: Option<Uuid>,
    cursor: Option<(Uuid, Uuid)>,
    limit: i64,
) -> Result<Vec<ProjectedManagementBinding>, ManagementRepositoryError> {
    let corrupt_snapshot: bool = sqlx::query_scalar(
        r#"
        WITH ranked_snapshots AS (
            SELECT snapshot.*,
                   ROW_NUMBER() OVER (
                       PARTITION BY snapshot.principal_id
                       ORDER BY snapshot.observed_at_ms DESC,snapshot.id DESC
                   ) AS snapshot_rank,
                   COUNT(*) OVER (
                       PARTITION BY snapshot.principal_id,snapshot.observed_at_ms
                   ) AS observed_at_ties
            FROM github_membership_snapshots AS snapshot
            WHERE snapshot.tenant_id=$1
              AND snapshot.provider_id='github'
              AND snapshot.observed_at_ms <= $2
              AND ($3::uuid IS NULL OR snapshot.principal_id=$3)
        )
        SELECT EXISTS (
            SELECT 1
            FROM ranked_snapshots AS snapshot
            WHERE snapshot.snapshot_rank=1
              AND (
                  snapshot.id='00000000-0000-0000-0000-000000000000'::uuid
                  OR snapshot.provider_token_version <= 0
                  OR snapshot.observed_at_ms < 0
                  OR snapshot.valid_until_ms <= snapshot.observed_at_ms
                  OR mod(snapshot.observed_at_ms,1000) <> 0
                  OR mod(snapshot.valid_until_ms,1000) <> 0
                  OR snapshot.observed_at_ties <> 1
                  OR snapshot.provider_subject !~ '^[1-9][0-9]{0,19}$'
                  OR (
                      length(snapshot.provider_subject)=20
                      AND snapshot.provider_subject COLLATE "C" > '18446744073709551615'
                  )
              )
        )
        "#,
    )
    .bind(tenant_id)
    .bind(now_ms)
    .bind(principal_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    if corrupt_snapshot {
        return Err(ManagementRepositoryError::CorruptData);
    }
    let (cursor_principal_id, cursor_mapping_id) = cursor.unzip();
    let rows = sqlx::query_as::<_, ManagementProviderBindingRow>(
        r"
        WITH ranked_snapshots AS (
            SELECT snapshot.*,
                   ROW_NUMBER() OVER (
                       PARTITION BY snapshot.principal_id
                       ORDER BY snapshot.observed_at_ms DESC,snapshot.id DESC
                   ) AS snapshot_rank,
                   COUNT(*) OVER (
                       PARTITION BY snapshot.principal_id,snapshot.observed_at_ms
                   ) AS observed_at_ties
            FROM github_membership_snapshots AS snapshot
            WHERE snapshot.tenant_id=$1
              AND snapshot.provider_id='github'
              AND snapshot.observed_at_ms <= $2
              AND ($3::uuid IS NULL OR snapshot.principal_id=$3)
        ), latest_snapshot AS (
            SELECT * FROM ranked_snapshots WHERE snapshot_rank=1
        )
        SELECT mapping.tenant_id,snapshot.principal_id,
               identity.provider_id,identity.provider_login,
               COALESCE(principal.display_name,identity.display_name)
                   AS principal_display_name,
               membership.status AS membership_status,
               membership.authorization_revision,
               membership.revision AS membership_revision,
               role.id AS role_id,role.name AS role_name,
               role.display_name AS role_display_name,
               mapping.scope_kind,mapping.repository_id,
               repository.tenant_id AS repository_tenant_id,
               mapping.runner_group_id,
               runner_group.tenant_id AS runner_group_tenant_id,
               CASE mapping.scope_kind
                   WHEN 'tenant' THEN tenant.display_name
                   WHEN 'repository' THEN repository.owner || '/' || repository.name
                   WHEN 'runner_group' THEN runner_group.name
               END AS scope_display_name,
               mapping.id AS mapping_id,mapping.revision AS mapping_revision,
               mapping.organization_id,mapping.team_id,
               snapshot.id AS snapshot_id,snapshot.provider_subject,
               snapshot.provider_token_version,snapshot.observed_at_ms,
               snapshot.valid_until_ms,snapshot.observed_at_ties
        FROM latest_snapshot AS snapshot
        JOIN tenant_human_memberships AS membership
          ON membership.tenant_id=snapshot.tenant_id
         AND membership.principal_id=snapshot.principal_id
        JOIN human_principals AS principal ON principal.id=snapshot.principal_id
        JOIN human_provider_identities AS identity
          ON identity.principal_id=snapshot.principal_id
         AND identity.provider_id=snapshot.provider_id
         AND identity.provider_subject=snapshot.provider_subject
        JOIN github_role_mappings AS mapping
          ON mapping.tenant_id=snapshot.tenant_id
         AND mapping.provider_id='github'
         AND mapping.status='active'
        JOIN rbac_roles AS role
          ON role.tenant_id=mapping.tenant_id AND role.id=mapping.role_id
        JOIN tenants AS tenant ON tenant.id=mapping.tenant_id
        LEFT JOIN repositories AS repository
          ON repository.tenant_id=mapping.tenant_id
         AND repository.id=mapping.repository_id
        LEFT JOIN runner_groups AS runner_group
          ON runner_group.tenant_id=mapping.tenant_id
         AND runner_group.id=mapping.runner_group_id
        WHERE snapshot.valid_until_ms>$2
          AND (
              $4::uuid IS NULL
              OR snapshot.principal_id>$4
              OR (snapshot.principal_id=$4 AND mapping.id>$5)
          )
          AND (
              (
                  mapping.team_id IS NULL
                  AND EXISTS (
                      SELECT 1
                      FROM github_organization_membership_observations AS organization
                      WHERE organization.tenant_id=mapping.tenant_id
                        AND organization.snapshot_id=snapshot.id
                        AND organization.organization_id=mapping.organization_id
                  )
              ) OR (
                  mapping.team_id IS NOT NULL
                  AND EXISTS (
                      SELECT 1
                      FROM github_team_membership_observations AS team
                      WHERE team.tenant_id=mapping.tenant_id
                        AND team.snapshot_id=snapshot.id
                        AND team.organization_id=mapping.organization_id
                        AND team.team_id=mapping.team_id
                  )
              )
          )
        ORDER BY snapshot.principal_id,mapping.id
        LIMIT $6
        ",
    )
    .bind(tenant_id)
    .bind(now_ms)
    .bind(principal_id)
    .bind(cursor_principal_id)
    .bind(cursor_mapping_id)
    .bind(limit)
    .fetch_all(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    rows.into_iter()
        .map(|row| {
            let principal_id = ManagedPrincipalId::from_uuid(row.principal_id)
                .map_err(|_| ManagementRepositoryError::CorruptData)?;
            let mapping_id = ProviderRoleMappingId::from_uuid(row.mapping_id)
                .map_err(|_| ManagementRepositoryError::CorruptData)?;
            Ok(ProjectedManagementBinding {
                record: row.into_record(tenant_id, now_ms)?,
                cursor: ManagementRoleBindingCursor::ProviderObserved {
                    principal_id,
                    mapping_id,
                },
            })
        })
        .collect()
}

fn parse_cursor(cursor: Option<&str>) -> Result<Option<Uuid>, ManagementRepositoryError> {
    cursor
        .map(canonical_uuid)
        .transpose()
        .map_err(|()| ManagementRepositoryError::InvalidRequest)
}

fn page_from_rows<T, F>(
    mut rows: Vec<T>,
    request: &ListManagementRecords,
    id: F,
) -> (Vec<T>, Option<String>)
where
    F: Fn(&T) -> Uuid,
{
    let has_more = rows.len() > usize::from(request.limit().value());
    if has_more {
        rows.pop();
    }
    let next_cursor = has_more
        .then(|| rows.last().map(id))
        .flatten()
        .map(|id| id.hyphenated().to_string());
    (rows, next_cursor)
}

fn role_scope_columns(scope: &AuthorizationScope) -> (&'static str, Option<Uuid>, Option<Uuid>) {
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

#[derive(FromRow)]
struct DirectBindingPrincipalOptionRow {
    principal_id: Uuid,
    display_name: String,
}

impl DirectBindingPrincipalOptionRow {
    fn into_option(self) -> Result<DirectBindingPrincipalOption, ManagementRepositoryError> {
        DirectBindingPrincipalOption::new(
            ManagedPrincipalId::from_uuid(self.principal_id)
                .map_err(|_| ManagementRepositoryError::CorruptData)?,
            self.display_name,
        )
        .map_err(|_| ManagementRepositoryError::CorruptData)
    }
}

#[derive(FromRow)]
struct DirectBindingRoleOptionRow {
    role_id: Uuid,
    name: String,
    display_name: String,
    role_kind: String,
    immutable: bool,
}

impl DirectBindingRoleOptionRow {
    fn into_option(self) -> Result<DirectBindingRoleOption, ManagementRepositoryError> {
        let kind = match self.role_kind.as_str() {
            "built_in" => RoleKind::BuiltIn,
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
struct DirectBindingRepositoryOptionRow {
    repository_id: Uuid,
    display_name: String,
}

impl DirectBindingRepositoryOptionRow {
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
struct DirectBindingRunnerGroupOptionRow {
    runner_group_id: Uuid,
    display_name: String,
}

impl DirectBindingRunnerGroupOptionRow {
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
    reason = "four bounded option queries intentionally share one authorization snapshot"
)]
async fn load_direct_binding_grant_options(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &AuthorizedActor,
) -> Result<DirectBindingGrantOptionsState, ManagementRepositoryError> {
    let query_limit = i64::try_from(DIRECT_BINDING_GRANT_OPTION_LIMIT + 1)
        .map_err(|_| ManagementRepositoryError::CorruptData)?;
    let principal_rows = sqlx::query_as::<_, DirectBindingPrincipalOptionRow>(
        r#"
        SELECT membership.principal_id,
               COALESCE(
                   principal.display_name,
                   identity.display_name,
                   identity.provider_login,
                   membership.principal_id::text
               ) AS display_name
        FROM tenant_human_memberships AS membership
        JOIN human_principals AS principal
          ON principal.id=membership.principal_id
        LEFT JOIN LATERAL (
            SELECT provider_id,provider_subject,provider_login,display_name
            FROM human_provider_identities
            WHERE principal_id=membership.principal_id
            ORDER BY provider_id COLLATE "C",provider_subject COLLATE "C"
            LIMIT 1
        ) AS identity ON TRUE
        WHERE membership.tenant_id=$1
          AND membership.status='active'
          AND principal.status='active'
        ORDER BY COALESCE(
                     principal.display_name,
                     identity.display_name,
                     identity.provider_login,
                     membership.principal_id::text
                 ) COLLATE "C",
                 membership.principal_id
        LIMIT $2
        "#,
    )
    .bind(&actor.tenant_id)
    .bind(query_limit)
    .fetch_all(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    let role_rows = sqlx::query_as::<_, DirectBindingRoleOptionRow>(
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
    let repository_rows = sqlx::query_as::<_, DirectBindingRepositoryOptionRow>(
        r#"
        SELECT repository.id AS repository_id,
               repository.owner || '/' || repository.name AS display_name
        FROM repositories AS repository
        WHERE repository.tenant_id=$1
        ORDER BY (repository.owner || '/' || repository.name) COLLATE "C",
                 repository.id
        LIMIT $2
        "#,
    )
    .bind(&actor.tenant_id)
    .bind(query_limit)
    .fetch_all(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    let runner_group_rows = sqlx::query_as::<_, DirectBindingRunnerGroupOptionRow>(
        r#"
        SELECT runner_group.id AS runner_group_id,
               runner_group.name AS display_name
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

    let principals = principal_rows
        .into_iter()
        .map(DirectBindingPrincipalOptionRow::into_option)
        .collect::<Result<Vec<_>, _>>()?;
    let roles = role_rows
        .into_iter()
        .map(DirectBindingRoleOptionRow::into_option)
        .collect::<Result<Vec<_>, _>>()?;
    let repositories = repository_rows
        .into_iter()
        .map(DirectBindingRepositoryOptionRow::into_option)
        .collect::<Result<Vec<_>, _>>()?;
    let runner_groups = runner_group_rows
        .into_iter()
        .map(DirectBindingRunnerGroupOptionRow::into_option)
        .collect::<Result<Vec<_>, _>>()?;
    let authorization_revision = revision_from_i64(actor.authorization_revision)?;
    let overflow = [
        (
            principals.len(),
            DirectBindingGrantOptionCollection::Principals,
        ),
        (roles.len(), DirectBindingGrantOptionCollection::Roles),
        (
            repositories.len(),
            DirectBindingGrantOptionCollection::Repositories,
        ),
        (
            runner_groups.len(),
            DirectBindingGrantOptionCollection::RunnerGroups,
        ),
    ]
    .into_iter()
    .find_map(|(len, collection)| (len > DIRECT_BINDING_GRANT_OPTION_LIMIT).then_some(collection));
    if let Some(collection) = overflow {
        return Ok(DirectBindingGrantOptionsState::Overflow {
            authorization_revision,
            collection,
        });
    }
    let options = DirectBindingGrantOptions::new(
        authorization_revision,
        principals,
        roles,
        repositories,
        runner_groups,
    )
    .map_err(|_| ManagementRepositoryError::CorruptData)?;
    Ok(DirectBindingGrantOptionsState::Available(options))
}

impl HumanRbacManagementRepository for PostgresHumanRbacManagementRepository {
    fn read_mutation_capabilities<'a>(
        &'a self,
        request: &'a ReadManagementMutationCapabilities,
    ) -> ManagementReadFuture<'a, ManagementMutationCapabilities> {
        Box::pin(async move {
            let mut transaction = begin_read(&self.pool).await?;
            let authorized_actor =
                match authorize_read(&mut transaction, request.actor(), &[]).await? {
                    ManagementReadOutcome::Forbidden => {
                        commit(transaction).await?;
                        return Ok(ManagementReadOutcome::Forbidden);
                    }
                    ManagementReadOutcome::SessionStale => {
                        commit(transaction).await?;
                        return Ok(ManagementReadOutcome::SessionStale);
                    }
                    ManagementReadOutcome::Authorized(actor) => actor,
                };
            let members_manage = actor_has_permission(
                &mut transaction,
                &authorized_actor,
                permissions::MEMBERS_MANAGE,
            )
            .await?;
            let roles_manage = actor_has_permission(
                &mut transaction,
                &authorized_actor,
                permissions::ROLES_MANAGE,
            )
            .await?;
            let role_bindings_manage = actor_has_permission(
                &mut transaction,
                &authorized_actor,
                permissions::ROLE_BINDINGS_MANAGE,
            )
            .await?;
            let capabilities = ManagementMutationCapabilities::new(
                revision_from_i64(authorized_actor.authorization_revision)?,
                members_manage,
                roles_manage,
                role_bindings_manage,
            );
            commit(transaction).await?;
            Ok(ManagementReadOutcome::Authorized(capabilities))
        })
    }

    fn read_direct_binding_grant_options<'a>(
        &'a self,
        request: &'a ReadDirectBindingGrantOptions,
    ) -> ManagementReadFuture<'a, DirectBindingGrantOptionsState> {
        Box::pin(async move {
            let mut transaction = begin_read(&self.pool).await?;
            let authorized_actor = match authorize_read(
                &mut transaction,
                request.actor(),
                &[permissions::ROLE_BINDINGS_MANAGE],
            )
            .await?
            {
                ManagementReadOutcome::Forbidden => {
                    commit(transaction).await?;
                    return Ok(ManagementReadOutcome::Forbidden);
                }
                ManagementReadOutcome::SessionStale => {
                    commit(transaction).await?;
                    return Ok(ManagementReadOutcome::SessionStale);
                }
                ManagementReadOutcome::Authorized(actor) => actor,
            };
            let options =
                load_direct_binding_grant_options(&mut transaction, &authorized_actor).await?;
            commit(transaction).await?;
            Ok(ManagementReadOutcome::Authorized(options))
        })
    }

    fn list_members<'a>(
        &'a self,
        request: &'a ListManagementRecords,
    ) -> ManagementReadFuture<'a, ManagementPage<MemberRecord>> {
        Box::pin(async move {
            let cursor = parse_cursor(request.cursor())?;
            let mut transaction = begin_read(&self.pool).await?;
            let authorized_actor = match authorize_read(
                &mut transaction,
                request.actor(),
                &[permissions::MEMBERS_READ],
            )
            .await?
            {
                ManagementReadOutcome::Forbidden => {
                    commit(transaction).await?;
                    return Ok(ManagementReadOutcome::Forbidden);
                }
                ManagementReadOutcome::SessionStale => {
                    commit(transaction).await?;
                    return Ok(ManagementReadOutcome::SessionStale);
                }
                ManagementReadOutcome::Authorized(actor) => actor,
            };
            let rows = sqlx::query_as::<_, MemberRow>(
                r"
                SELECT membership.principal_id,
                       identity.provider_id,
                       identity.provider_login,
                       COALESCE(principal.display_name, identity.display_name) AS display_name,
                       membership.status AS membership_status,
                       membership.authorization_revision,
                       membership.revision AS membership_revision
                FROM tenant_human_memberships AS membership
                JOIN human_principals AS principal ON principal.id = membership.principal_id
                LEFT JOIN LATERAL (
                    SELECT provider_id, provider_subject, provider_login, display_name
                    FROM human_provider_identities
                    WHERE principal_id = membership.principal_id
                    ORDER BY provider_id, provider_subject
                    LIMIT 1
                ) AS identity ON TRUE
                WHERE membership.tenant_id = $1
                  AND ($2::uuid IS NULL OR membership.principal_id > $2)
                ORDER BY membership.principal_id
                LIMIT $3
                ",
            )
            .bind(request.actor().tenant_id().as_str())
            .bind(cursor)
            .bind(i64::from(request.limit().value()) + 1)
            .fetch_all(&mut *transaction)
            .await
            .map_err(map_database_error)?;
            let (rows, next_cursor) = page_from_rows(rows, request, |row| row.principal_id);
            let items = rows
                .into_iter()
                .map(MemberRow::into_record)
                .collect::<Result<Vec<_>, _>>()?;
            let page = ManagementPage::new_authorized(
                items,
                next_cursor,
                request.limit(),
                revision_from_i64(authorized_actor.authorization_revision)?,
            )
            .map_err(|_| ManagementRepositoryError::CorruptData)?;
            commit(transaction).await?;
            Ok(ManagementReadOutcome::Authorized(page))
        })
    }

    fn list_roles<'a>(
        &'a self,
        request: &'a ListManagementRecords,
    ) -> ManagementReadFuture<'a, ManagementPage<RoleRecord>> {
        Box::pin(async move {
            let cursor = parse_cursor(request.cursor())?;
            let mut transaction = begin_read(&self.pool).await?;
            let authorized_actor = match authorize_read(
                &mut transaction,
                request.actor(),
                &[permissions::ROLES_READ],
            )
            .await?
            {
                ManagementReadOutcome::Forbidden => {
                    commit(transaction).await?;
                    return Ok(ManagementReadOutcome::Forbidden);
                }
                ManagementReadOutcome::SessionStale => {
                    commit(transaction).await?;
                    return Ok(ManagementReadOutcome::SessionStale);
                }
                ManagementReadOutcome::Authorized(actor) => actor,
            };
            let rows = sqlx::query_as::<_, RoleRow>(
                r"
                SELECT role.id, role.name, role.display_name, role.role_kind,
                       role.immutable, role.revision,
                       ARRAY(
                           SELECT role_permission.permission_name
                           FROM rbac_role_permissions AS role_permission
                           WHERE role_permission.tenant_id = role.tenant_id
                             AND role_permission.role_id = role.id
                           ORDER BY role_permission.permission_name
                       ) AS permissions
                FROM rbac_roles AS role
                WHERE role.tenant_id = $1
                  AND ($2::uuid IS NULL OR role.id > $2)
                ORDER BY role.id
                LIMIT $3
                ",
            )
            .bind(request.actor().tenant_id().as_str())
            .bind(cursor)
            .bind(i64::from(request.limit().value()) + 1)
            .fetch_all(&mut *transaction)
            .await
            .map_err(map_database_error)?;
            let (rows, next_cursor) = page_from_rows(rows, request, |row| row.id);
            let items = rows
                .into_iter()
                .map(RoleRow::into_record)
                .collect::<Result<Vec<_>, _>>()?;
            let page = ManagementPage::new_authorized(
                items,
                next_cursor,
                request.limit(),
                revision_from_i64(authorized_actor.authorization_revision)?,
            )
            .map_err(|_| ManagementRepositoryError::CorruptData)?;
            commit(transaction).await?;
            Ok(ManagementReadOutcome::Authorized(page))
        })
    }

    fn list_role_bindings<'a>(
        &'a self,
        request: &'a ListManagementRecords,
    ) -> ManagementReadFuture<'a, ManagementPage<RoleBindingRecord>> {
        Box::pin(async move {
            let cursor = parse_cursor(request.cursor())?;
            let mut transaction = begin_read(&self.pool).await?;
            let authorized_actor = match authorize_read(
                &mut transaction,
                request.actor(),
                &[permissions::MEMBERS_READ, permissions::ROLES_READ],
            )
            .await?
            {
                ManagementReadOutcome::Forbidden => {
                    commit(transaction).await?;
                    return Ok(ManagementReadOutcome::Forbidden);
                }
                ManagementReadOutcome::SessionStale => {
                    commit(transaction).await?;
                    return Ok(ManagementReadOutcome::SessionStale);
                }
                ManagementReadOutcome::Authorized(actor) => actor,
            };
            let rows = sqlx::query_as::<_, BindingRow>(
                r"
                SELECT binding.tenant_id, binding.id, binding.principal_id,
                       binding.role_id, binding.scope_kind, binding.repository_id,
                       repository.tenant_id AS repository_tenant_id,
                       binding.runner_group_id,
                       runner_group.tenant_id AS runner_group_tenant_id,
                       binding.status, binding.valid_until_ms, binding.revision
                FROM rbac_role_bindings AS binding
                LEFT JOIN repositories AS repository
                  ON repository.tenant_id = binding.tenant_id
                 AND repository.id = binding.repository_id
                LEFT JOIN runner_groups AS runner_group
                  ON runner_group.tenant_id = binding.tenant_id
                 AND runner_group.id = binding.runner_group_id
                WHERE binding.tenant_id = $1
                  AND ($2::uuid IS NULL OR binding.id > $2)
                ORDER BY binding.id
                LIMIT $3
                ",
            )
            .bind(request.actor().tenant_id().as_str())
            .bind(cursor)
            .bind(i64::from(request.limit().value()) + 1)
            .fetch_all(&mut *transaction)
            .await
            .map_err(map_database_error)?;
            let (rows, next_cursor) = page_from_rows(rows, request, |row| row.id);
            let tenant_id = request.actor().tenant_id().as_str();
            let items = rows
                .into_iter()
                .map(|row| row.into_record(tenant_id))
                .collect::<Result<Vec<_>, _>>()?;
            let page = ManagementPage::new_authorized(
                items,
                next_cursor,
                request.limit(),
                revision_from_i64(authorized_actor.authorization_revision)?,
            )
            .map_err(|_| ManagementRepositoryError::CorruptData)?;
            commit(transaction).await?;
            Ok(ManagementReadOutcome::Authorized(page))
        })
    }

    fn read_member_detail<'a>(
        &'a self,
        request: &'a ReadMemberDetail,
    ) -> ManagementDetailFuture<'a, MemberRecord> {
        Box::pin(async move {
            let mut transaction = begin_read(&self.pool).await?;
            match authorize_read(
                &mut transaction,
                request.actor(),
                &[permissions::MEMBERS_READ],
            )
            .await?
            {
                ManagementReadOutcome::Forbidden => {
                    commit(transaction).await?;
                    return Ok(ManagementDetailOutcome::Forbidden);
                }
                ManagementReadOutcome::SessionStale => {
                    commit(transaction).await?;
                    return Ok(ManagementDetailOutcome::SessionStale);
                }
                ManagementReadOutcome::Authorized(_) => {}
            }
            let member = load_member(
                &mut transaction,
                request.actor().tenant_id().as_str(),
                request.principal_id().as_uuid(),
            )
            .await?;
            commit(transaction).await?;
            Ok(member.map_or(
                ManagementDetailOutcome::NotFound,
                ManagementDetailOutcome::Authorized,
            ))
        })
    }

    fn read_role_detail<'a>(
        &'a self,
        request: &'a ReadRoleDetail,
    ) -> ManagementDetailFuture<'a, RoleDetailRecord> {
        Box::pin(async move {
            let mut transaction = begin_read(&self.pool).await?;
            match authorize_read(
                &mut transaction,
                request.actor(),
                &[permissions::ROLES_READ],
            )
            .await?
            {
                ManagementReadOutcome::Forbidden => {
                    commit(transaction).await?;
                    return Ok(ManagementDetailOutcome::Forbidden);
                }
                ManagementReadOutcome::SessionStale => {
                    commit(transaction).await?;
                    return Ok(ManagementDetailOutcome::SessionStale);
                }
                ManagementReadOutcome::Authorized(_) => {}
            }
            let role = load_role_detail(
                &mut transaction,
                request.actor().tenant_id().as_str(),
                request.role_id().as_uuid(),
            )
            .await?;
            commit(transaction).await?;
            Ok(role.map_or(
                ManagementDetailOutcome::NotFound,
                ManagementDetailOutcome::Authorized,
            ))
        })
    }

    fn list_management_role_bindings<'a>(
        &'a self,
        request: &'a ListManagementRoleBindings,
    ) -> ManagementReadFuture<'a, ManagementPage<ManagementRoleBindingRecord>> {
        Box::pin(async move {
            let mut transaction = begin_read(&self.pool).await?;
            let authorized_actor = match authorize_read(
                &mut transaction,
                request.actor(),
                &[permissions::MEMBERS_READ, permissions::ROLES_READ],
            )
            .await?
            {
                ManagementReadOutcome::Forbidden => {
                    commit(transaction).await?;
                    return Ok(ManagementReadOutcome::Forbidden);
                }
                ManagementReadOutcome::SessionStale => {
                    commit(transaction).await?;
                    return Ok(ManagementReadOutcome::SessionStale);
                }
                ManagementReadOutcome::Authorized(actor) => actor,
            };
            let tenant_id = request.actor().tenant_id().as_str();
            let principal_id = request.principal_id().map(ManagedPrincipalId::as_uuid);
            let row_limit_usize = usize::from(request.limit().value()) + 1;
            let row_limit = i64::try_from(row_limit_usize)
                .map_err(|_| ManagementRepositoryError::CorruptData)?;
            let mut rows = match request.cursor() {
                None => {
                    load_management_direct_bindings(
                        &mut transaction,
                        tenant_id,
                        principal_id,
                        None,
                        row_limit,
                    )
                    .await?
                }
                Some(ManagementRoleBindingCursor::Direct(binding_id)) => {
                    load_management_direct_bindings(
                        &mut transaction,
                        tenant_id,
                        principal_id,
                        Some(binding_id.as_uuid()),
                        row_limit,
                    )
                    .await?
                }
                Some(ManagementRoleBindingCursor::ProviderObserved {
                    principal_id: cursor_principal,
                    mapping_id,
                }) => {
                    load_management_provider_bindings(
                        &mut transaction,
                        tenant_id,
                        authorized_actor.now_ms,
                        principal_id,
                        Some((cursor_principal.as_uuid(), mapping_id.as_uuid())),
                        row_limit,
                    )
                    .await?
                }
            };
            if !matches!(
                request.cursor(),
                Some(ManagementRoleBindingCursor::ProviderObserved { .. })
            ) && rows.len() < row_limit_usize
            {
                let remaining = row_limit
                    - i64::try_from(rows.len())
                        .map_err(|_| ManagementRepositoryError::CorruptData)?;
                rows.extend(
                    load_management_provider_bindings(
                        &mut transaction,
                        tenant_id,
                        authorized_actor.now_ms,
                        principal_id,
                        None,
                        remaining,
                    )
                    .await?,
                );
            }
            let has_more = rows.len() > usize::from(request.limit().value());
            if has_more {
                rows.pop();
            }
            let next_cursor = has_more
                .then(|| rows.last().map(|row| row.cursor.encode()))
                .flatten();
            let items = rows.into_iter().map(|row| row.record).collect();
            let page = ManagementPage::new_authorized(
                items,
                next_cursor,
                request.limit(),
                revision_from_i64(authorized_actor.authorization_revision)?,
            )
            .map_err(|_| ManagementRepositoryError::CorruptData)?;
            commit(transaction).await?;
            Ok(ManagementReadOutcome::Authorized(page))
        })
    }

    fn create_role(&self, request: CreateRole) -> ManagementMutationFuture<'_, RoleRecord> {
        Box::pin(async move {
            let role_id = request.role_id().as_uuid();
            let resource_id = request.role_id().to_string();
            let descriptor = AuditDescriptor::new(
                ACTION_ROLE_CREATE,
                RESOURCE_ROLE,
                &resource_id,
                request.actor(),
            );
            let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
            let authorization = authorize_mutation(
                &mut transaction,
                request.actor(),
                &[permissions::ROLES_MANAGE],
                descriptor,
            )
            .await?;
            let mut actor = match authorization {
                MutationAuthorization::Authorized(actor) => actor,
                closed => {
                    commit(transaction).await?;
                    return Ok(closed_authorization(&closed));
                }
            };
            lock_tenant_memberships(&mut transaction, &actor.tenant_id).await?;
            if !reauthorize_actor(&mut transaction, &mut actor, permissions::ROLES_MANAGE).await? {
                return Ok(ManagementMutationOutcome::Forbidden);
            }
            let inserted = sqlx::query(
                r"
                INSERT INTO rbac_roles (
                    tenant_id, id, name, display_name, role_kind, immutable,
                    revision, created_by_principal_id, created_at_ms, updated_at_ms
                ) VALUES ($1,$2,$3,$4,'custom',FALSE,1,$5,$6,$6)
                ON CONFLICT DO NOTHING
                ",
            )
            .bind(&actor.tenant_id)
            .bind(role_id)
            .bind(request.name().as_str())
            .bind(request.display_name())
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
                    ManagementMutationOutcome::AlreadyExists,
                )
                .await;
            }
            let role = load_role(
                &mut transaction,
                request.actor().tenant_id().as_str(),
                role_id,
                false,
            )
            .await?
            .ok_or(ManagementRepositoryError::CorruptData)?;
            finish_applied(transaction, actor, descriptor, role).await
        })
    }

    fn update_role(&self, request: UpdateRole) -> ManagementMutationFuture<'_, RoleRecord> {
        Box::pin(async move {
            let role_id = request.role_id().as_uuid();
            let resource_id = request.role_id().to_string();
            let descriptor = AuditDescriptor::new(
                ACTION_ROLE_UPDATE,
                RESOURCE_ROLE,
                &resource_id,
                request.actor(),
            );
            let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
            let authorization = authorize_mutation(
                &mut transaction,
                request.actor(),
                &[permissions::ROLES_MANAGE],
                descriptor,
            )
            .await?;
            let mut actor = match authorization {
                MutationAuthorization::Authorized(actor) => actor,
                closed => {
                    commit(transaction).await?;
                    return Ok(closed_authorization(&closed));
                }
            };
            lock_tenant_memberships(&mut transaction, &actor.tenant_id).await?;
            let Some(current) =
                load_role(&mut transaction, &actor.tenant_id, role_id, true).await?
            else {
                return finish_denied(
                    transaction,
                    actor,
                    descriptor,
                    ManagementMutationOutcome::NotFound,
                )
                .await;
            };
            if current.revision() != request.expected_revision() {
                let revision = current.revision();
                return finish_denied(
                    transaction,
                    actor,
                    descriptor,
                    ManagementMutationOutcome::RevisionConflict { current: revision },
                )
                .await;
            }
            if current.immutable() {
                return finish_denied(
                    transaction,
                    actor,
                    descriptor,
                    ManagementMutationOutcome::Immutable,
                )
                .await;
            }
            ensure_revision_can_advance(current.revision())?;
            if !reauthorize_actor(&mut transaction, &mut actor, permissions::ROLES_MANAGE).await? {
                return Ok(ManagementMutationOutcome::Forbidden);
            }
            let updated = sqlx::query(
                r"
                UPDATE rbac_roles
                SET display_name = $3,
                    updated_at_ms = GREATEST(updated_at_ms, $4),
                    revision = revision + 1
                WHERE tenant_id = $1 AND id = $2 AND revision = $5
                ",
            )
            .bind(&actor.tenant_id)
            .bind(role_id)
            .bind(request.display_name())
            .bind(actor.now_ms)
            .bind(revision_to_i64(request.expected_revision())?)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?
            .rows_affected();
            if updated != 1 {
                return Err(ManagementRepositoryError::CorruptData);
            }
            let role = load_role(&mut transaction, &actor.tenant_id, role_id, false)
                .await?
                .ok_or(ManagementRepositoryError::CorruptData)?;
            finish_applied(transaction, actor, descriptor, role).await
        })
    }

    fn delete_role(&self, request: DeleteRole) -> ManagementMutationFuture<'_, ()> {
        Box::pin(async move {
            let role_id = request.role_id().as_uuid();
            let resource_id = request.role_id().to_string();
            let descriptor = AuditDescriptor::new(
                ACTION_ROLE_DELETE,
                RESOURCE_ROLE,
                &resource_id,
                request.actor(),
            );
            let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
            let authorization = authorize_mutation(
                &mut transaction,
                request.actor(),
                &[permissions::ROLES_MANAGE],
                descriptor,
            )
            .await?;
            let mut actor = match authorization {
                MutationAuthorization::Authorized(actor) => actor,
                closed => {
                    commit(transaction).await?;
                    return Ok(closed_authorization(&closed));
                }
            };
            lock_tenant_memberships(&mut transaction, &actor.tenant_id).await?;
            let Some(current) =
                load_role(&mut transaction, &actor.tenant_id, role_id, true).await?
            else {
                return finish_denied(
                    transaction,
                    actor,
                    descriptor,
                    ManagementMutationOutcome::NotFound,
                )
                .await;
            };
            if current.revision() != request.expected_revision() {
                let revision = current.revision();
                return finish_denied(
                    transaction,
                    actor,
                    descriptor,
                    ManagementMutationOutcome::RevisionConflict { current: revision },
                )
                .await;
            }
            if current.immutable() {
                return finish_denied(
                    transaction,
                    actor,
                    descriptor,
                    ManagementMutationOutcome::Immutable,
                )
                .await;
            }
            let referenced: bool = sqlx::query_scalar(
                r"
                SELECT EXISTS (
                    SELECT 1 FROM rbac_role_bindings
                    WHERE tenant_id = $1 AND role_id = $2
                ) OR EXISTS (
                    SELECT 1 FROM github_role_mappings
                    WHERE tenant_id = $1 AND role_id = $2
                )
                ",
            )
            .bind(&actor.tenant_id)
            .bind(role_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(map_database_error)?;
            if referenced {
                return finish_denied(
                    transaction,
                    actor,
                    descriptor,
                    ManagementMutationOutcome::ResourceInUse,
                )
                .await;
            }
            if !reauthorize_actor(&mut transaction, &mut actor, permissions::ROLES_MANAGE).await? {
                return Ok(ManagementMutationOutcome::Forbidden);
            }
            let deleted =
                sqlx::query("DELETE FROM rbac_roles WHERE tenant_id=$1 AND id=$2 AND revision=$3")
                    .bind(&actor.tenant_id)
                    .bind(role_id)
                    .bind(revision_to_i64(request.expected_revision())?)
                    .execute(&mut *transaction)
                    .await
                    .map_err(map_database_error)?
                    .rows_affected();
            if deleted != 1 {
                return Err(ManagementRepositoryError::CorruptData);
            }
            finish_applied(transaction, actor, descriptor, ()).await
        })
    }

    #[allow(clippy::too_many_lines)]
    fn set_role_permission(
        &self,
        request: SetRolePermission,
    ) -> ManagementMutationFuture<'_, RoleRecord> {
        Box::pin(async move {
            let role_id = request.role_id().as_uuid();
            let resource_id = request.role_id().to_string();
            let descriptor = AuditDescriptor::new(
                ACTION_ROLE_PERMISSION_SET,
                RESOURCE_ROLE,
                &resource_id,
                request.actor(),
            );
            let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
            let authorization = authorize_mutation(
                &mut transaction,
                request.actor(),
                &[permissions::ROLES_MANAGE],
                descriptor,
            )
            .await?;
            let mut actor = match authorization {
                MutationAuthorization::Authorized(actor) => actor,
                closed => {
                    commit(transaction).await?;
                    return Ok(closed_authorization(&closed));
                }
            };
            lock_tenant_memberships(&mut transaction, &actor.tenant_id).await?;
            let Some(current) =
                load_role(&mut transaction, &actor.tenant_id, role_id, true).await?
            else {
                return finish_denied(
                    transaction,
                    actor,
                    descriptor,
                    ManagementMutationOutcome::NotFound,
                )
                .await;
            };
            if current.revision() != request.expected_revision() {
                let revision = current.revision();
                return finish_denied(
                    transaction,
                    actor,
                    descriptor,
                    ManagementMutationOutcome::RevisionConflict { current: revision },
                )
                .await;
            }
            if current.immutable() {
                return finish_denied(
                    transaction,
                    actor,
                    descriptor,
                    ManagementMutationOutcome::Immutable,
                )
                .await;
            }
            let permission_exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM rbac_permissions WHERE name=$1)")
                    .bind(request.permission().as_str())
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(map_database_error)?;
            if !permission_exists {
                return finish_denied(
                    transaction,
                    actor,
                    descriptor,
                    ManagementMutationOutcome::NotFound,
                )
                .await;
            }
            let was_present = current.permissions().contains(request.permission());
            let removed_manager_permission = !request.present()
                && was_present
                && matches!(
                    request.permission().as_str(),
                    permissions::ROLES_MANAGE | permissions::MEMBERS_MANAGE
                );
            if removed_manager_permission {
                let permission_name = match request.permission().as_str() {
                    permissions::ROLES_MANAGE => permissions::ROLES_MANAGE,
                    permissions::MEMBERS_MANAGE => permissions::MEMBERS_MANAGE,
                    _ => unreachable!("guarded by manager permission match"),
                };
                let exclusion = ManagerExclusion {
                    permission_role_id: Some(role_id),
                    permission_name: Some(permission_name),
                    ..ManagerExclusion::default()
                };
                if !manager_remains(&mut transaction, &actor, &exclusion).await? {
                    return finish_denied(
                        transaction,
                        actor,
                        descriptor,
                        ManagementMutationOutcome::LastManager,
                    )
                    .await;
                }
            }
            ensure_revision_can_advance(current.revision())?;
            if !reauthorize_actor(&mut transaction, &mut actor, permissions::ROLES_MANAGE).await? {
                return Ok(ManagementMutationOutcome::Forbidden);
            }
            if request.present() {
                sqlx::query(
                    r"
                    INSERT INTO rbac_role_permissions (
                        tenant_id, role_id, permission_name,
                        granted_by_principal_id, granted_at_ms
                    ) VALUES ($1,$2,$3,$4,$5)
                    ON CONFLICT DO NOTHING
                    ",
                )
                .bind(&actor.tenant_id)
                .bind(role_id)
                .bind(request.permission().as_str())
                .bind(actor.principal_id)
                .bind(actor.now_ms)
                .execute(&mut *transaction)
                .await
                .map_err(map_database_error)?;
            } else {
                sqlx::query(
                    r"
                    DELETE FROM rbac_role_permissions
                    WHERE tenant_id=$1 AND role_id=$2 AND permission_name=$3
                    ",
                )
                .bind(&actor.tenant_id)
                .bind(role_id)
                .bind(request.permission().as_str())
                .execute(&mut *transaction)
                .await
                .map_err(map_database_error)?;
            }
            let updated = sqlx::query(
                r"
                UPDATE rbac_roles
                SET updated_at_ms=GREATEST(updated_at_ms,$3), revision=revision+1
                WHERE tenant_id=$1 AND id=$2 AND revision=$4
                ",
            )
            .bind(&actor.tenant_id)
            .bind(role_id)
            .bind(actor.now_ms)
            .bind(revision_to_i64(request.expected_revision())?)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?
            .rows_affected();
            if updated != 1 {
                return Err(ManagementRepositoryError::CorruptData);
            }
            let role = load_role(&mut transaction, &actor.tenant_id, role_id, false)
                .await?
                .ok_or(ManagementRepositoryError::CorruptData)?;
            finish_applied(transaction, actor, descriptor, role).await
        })
    }

    #[allow(clippy::too_many_lines)]
    fn grant_role(&self, request: GrantRole) -> ManagementMutationFuture<'_, RoleBindingRecord> {
        Box::pin(async move {
            let requested_lifetime = request
                .valid_until()
                .map(|valid_until| {
                    valid_until
                        .as_seconds()
                        .checked_sub(request.actor().now().as_seconds())
                        .filter(|lifetime| *lifetime > 0)
                        .ok_or(ManagementRepositoryError::InvalidRequest)
                })
                .transpose()?;
            let binding_id = request.binding_id().as_uuid();
            let resource_id = request.binding_id().to_string();
            let descriptor = AuditDescriptor::new(
                ACTION_BINDING_GRANT,
                RESOURCE_BINDING,
                &resource_id,
                request.actor(),
            );
            let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
            let authorization = authorize_mutation(
                &mut transaction,
                request.actor(),
                &[permissions::ROLE_BINDINGS_MANAGE],
                descriptor,
            )
            .await?;
            let mut actor = match authorization {
                MutationAuthorization::Authorized(actor) => actor,
                closed => {
                    commit(transaction).await?;
                    return Ok(closed_authorization(&closed));
                }
            };
            // Rebase the caller's requested duration once, immediately after
            // the tenant/session authority locks. Later target-lock waits
            // consume this lifetime; they must never extend it.
            let valid_until_ms = requested_lifetime
                .map(|lifetime| {
                    timestamp_from_milliseconds(actor.now_ms)
                        .and_then(|database_time| {
                            database_time.checked_add(lifetime).map_err(|_| ())
                        })
                        .and_then(timestamp_to_milliseconds)
                        .map_err(|()| ManagementRepositoryError::InvalidRequest)
                })
                .transpose()?;
            lock_tenant_memberships(&mut transaction, &actor.tenant_id).await?;
            if request.scope().tenant_id().as_str() != actor.tenant_id {
                return Err(ManagementRepositoryError::InvalidRequest);
            }
            let target_is_active = sqlx::query_scalar::<_, Uuid>(
                r"
                SELECT membership.principal_id
                FROM tenant_human_memberships AS membership
                JOIN human_principals AS principal
                  ON principal.id=membership.principal_id
                WHERE membership.tenant_id=$1
                  AND membership.principal_id=$2
                  AND membership.status='active'
                  AND principal.status='active'
                FOR SHARE OF principal
                ",
            )
            .bind(&actor.tenant_id)
            .bind(request.principal_id().as_uuid())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(map_database_error)?
            .is_some();
            if !target_is_active {
                return finish_denied(
                    transaction,
                    actor,
                    descriptor,
                    ManagementMutationOutcome::NotFound,
                )
                .await;
            }
            if load_role(
                &mut transaction,
                &actor.tenant_id,
                request.role_id().as_uuid(),
                true,
            )
            .await?
            .is_none()
            {
                return finish_denied(
                    transaction,
                    actor,
                    descriptor,
                    ManagementMutationOutcome::NotFound,
                )
                .await;
            }
            let (scope_kind, repository_id, runner_group_id) = role_scope_columns(request.scope());
            let resource_exists = match (repository_id, runner_group_id) {
                (Some(repository_id), None) => sqlx::query_scalar::<_, Uuid>(
                    r"
                        SELECT id FROM repositories
                        WHERE tenant_id=$1 AND id=$2
                        FOR KEY SHARE
                        ",
                )
                .bind(&actor.tenant_id)
                .bind(repository_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(map_database_error)?
                .is_some(),
                (None, Some(runner_group_id)) => sqlx::query_scalar::<_, Uuid>(
                    r"
                        SELECT id FROM runner_groups
                        WHERE tenant_id=$1 AND id=$2
                        FOR KEY SHARE
                        ",
                )
                .bind(&actor.tenant_id)
                .bind(runner_group_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(map_database_error)?
                .is_some(),
                (None, None) => true,
                (Some(_), Some(_)) => return Err(ManagementRepositoryError::InvalidRequest),
            };
            if !resource_exists {
                return finish_denied(
                    transaction,
                    actor,
                    descriptor,
                    ManagementMutationOutcome::NotFound,
                )
                .await;
            }
            if !reauthorize_actor(
                &mut transaction,
                &mut actor,
                permissions::ROLE_BINDINGS_MANAGE,
            )
            .await?
            {
                return Ok(ManagementMutationOutcome::Forbidden);
            }
            if valid_until_ms.is_some_and(|valid_until_ms| valid_until_ms <= actor.now_ms) {
                return Err(ManagementRepositoryError::InvalidRequest);
            }
            let inserted = sqlx::query(
                r"
                INSERT INTO rbac_role_bindings (
                    tenant_id,id,principal_id,role_id,scope_kind,
                    repository_id,runner_group_id,assignment_source,status,
                    created_by_principal_id,created_at_ms,valid_until_ms,revision
                )
                SELECT $1,$2,$3,$4,$5,$6,$7,'manual','active',$8,$9,$10,1
                WHERE $10::BIGINT IS NULL OR $10 >
                    floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000
                ON CONFLICT DO NOTHING
                ",
            )
            .bind(&actor.tenant_id)
            .bind(binding_id)
            .bind(request.principal_id().as_uuid())
            .bind(request.role_id().as_uuid())
            .bind(scope_kind)
            .bind(repository_id)
            .bind(runner_group_id)
            .bind(actor.principal_id)
            .bind(actor.now_ms)
            .bind(valid_until_ms)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?
            .rows_affected();
            if inserted != 1 {
                let final_now_ms = database_time_milliseconds(&mut transaction)
                    .await
                    .map_err(map_database_error)?;
                validate_caller_time(request.actor().now(), final_now_ms)
                    .map_err(|()| ManagementRepositoryError::InvalidRequest)?;
                if valid_until_ms.is_some_and(|valid_until_ms| valid_until_ms <= final_now_ms) {
                    return Err(ManagementRepositoryError::InvalidRequest);
                }
                return finish_denied(
                    transaction,
                    actor,
                    descriptor,
                    ManagementMutationOutcome::AlreadyExists,
                )
                .await;
            }
            let binding = load_binding(&mut transaction, &actor.tenant_id, binding_id, false)
                .await?
                .ok_or(ManagementRepositoryError::CorruptData)?;
            finish_applied(transaction, actor, descriptor, binding).await
        })
    }

    #[allow(clippy::too_many_lines)]
    fn revoke_role(&self, request: RevokeRole) -> ManagementMutationFuture<'_, RoleBindingRecord> {
        Box::pin(async move {
            let binding_id = request.binding_id().as_uuid();
            let resource_id = request.binding_id().to_string();
            let descriptor = AuditDescriptor::new(
                ACTION_BINDING_REVOKE,
                RESOURCE_BINDING,
                &resource_id,
                request.actor(),
            );
            let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
            let authorization = authorize_mutation(
                &mut transaction,
                request.actor(),
                &[permissions::ROLE_BINDINGS_MANAGE],
                descriptor,
            )
            .await?;
            let mut actor = match authorization {
                MutationAuthorization::Authorized(actor) => actor,
                closed => {
                    commit(transaction).await?;
                    return Ok(closed_authorization(&closed));
                }
            };
            lock_tenant_memberships(&mut transaction, &actor.tenant_id).await?;
            let Some(current) =
                load_binding(&mut transaction, &actor.tenant_id, binding_id, true).await?
            else {
                return finish_denied(
                    transaction,
                    actor,
                    descriptor,
                    ManagementMutationOutcome::NotFound,
                )
                .await;
            };
            if current.revision() != request.expected_revision() {
                let revision = current.revision();
                return finish_denied(
                    transaction,
                    actor,
                    descriptor,
                    ManagementMutationOutcome::RevisionConflict { current: revision },
                )
                .await;
            }
            if current.status() == RoleBindingStatus::Revoked {
                let revision = current.revision();
                return finish_denied(
                    transaction,
                    actor,
                    descriptor,
                    ManagementMutationOutcome::RevisionConflict { current: revision },
                )
                .await;
            }
            let role = load_role(
                &mut transaction,
                &actor.tenant_id,
                current.role_id().as_uuid(),
                true,
            )
            .await?
            .ok_or(ManagementRepositoryError::CorruptData)?;
            let database_time = timestamp_from_milliseconds(actor.now_ms)
                .map_err(|()| ManagementRepositoryError::CorruptData)?;
            let effective_tenant_binding =
                matches!(current.scope(), AuthorizationScope::Tenant { .. })
                    && current
                        .valid_until()
                        .is_none_or(|expiry| expiry > database_time);
            let affects_manager = effective_tenant_binding
                && role.permissions().iter().any(|permission| {
                    matches!(
                        permission.as_str(),
                        permissions::ROLES_MANAGE | permissions::MEMBERS_MANAGE
                    )
                })
                && principal_has_manager_capability(
                    &mut transaction,
                    &actor,
                    current.principal_id().as_uuid(),
                )
                .await?;
            if affects_manager {
                let exclusion = ManagerExclusion {
                    binding_id: Some(binding_id),
                    ..ManagerExclusion::default()
                };
                if !manager_remains(&mut transaction, &actor, &exclusion).await? {
                    return finish_denied(
                        transaction,
                        actor,
                        descriptor,
                        ManagementMutationOutcome::LastManager,
                    )
                    .await;
                }
            }
            ensure_revision_can_advance(current.revision())?;
            if !reauthorize_actor(
                &mut transaction,
                &mut actor,
                permissions::ROLE_BINDINGS_MANAGE,
            )
            .await?
            {
                return Ok(ManagementMutationOutcome::Forbidden);
            }
            let updated = sqlx::query(
                r"
                UPDATE rbac_role_bindings
                SET status='revoked', revoked_by_principal_id=$3,
                    revoked_at_ms=$4, revocation_reason=$5, revision=revision+1
                WHERE tenant_id=$1 AND id=$2 AND revision=$6 AND status='active'
                ",
            )
            .bind(&actor.tenant_id)
            .bind(binding_id)
            .bind(actor.principal_id)
            .bind(actor.now_ms)
            .bind(request.reason())
            .bind(revision_to_i64(request.expected_revision())?)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?
            .rows_affected();
            if updated != 1 {
                return Err(ManagementRepositoryError::CorruptData);
            }
            let binding = load_binding(&mut transaction, &actor.tenant_id, binding_id, false)
                .await?
                .ok_or(ManagementRepositoryError::CorruptData)?;
            finish_applied(transaction, actor, descriptor, binding).await
        })
    }

    #[allow(clippy::too_many_lines)]
    fn change_member_status(
        &self,
        request: ChangeMemberStatus,
    ) -> ManagementMutationFuture<'_, MemberRecord> {
        Box::pin(async move {
            let principal_id = request.principal_id().as_uuid();
            let resource_id = request.principal_id().to_string();
            let descriptor = AuditDescriptor::new(
                ACTION_MEMBER_STATUS_CHANGE,
                RESOURCE_MEMBERSHIP,
                &resource_id,
                request.actor(),
            );
            let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
            let authorization = authorize_mutation(
                &mut transaction,
                request.actor(),
                &[permissions::MEMBERS_MANAGE],
                descriptor,
            )
            .await?;
            let mut actor = match authorization {
                MutationAuthorization::Authorized(actor) => actor,
                closed => {
                    commit(transaction).await?;
                    return Ok(closed_authorization(&closed));
                }
            };
            lock_tenant_memberships(&mut transaction, &actor.tenant_id).await?;
            if request.status() == MemberStatus::Suspended && principal_id == actor.principal_id {
                return finish_denied(
                    transaction,
                    actor,
                    descriptor,
                    ManagementMutationOutcome::SelfModificationForbidden,
                )
                .await;
            }
            let Some(current) =
                load_member(&mut transaction, &actor.tenant_id, principal_id).await?
            else {
                return finish_denied(
                    transaction,
                    actor,
                    descriptor,
                    ManagementMutationOutcome::NotFound,
                )
                .await;
            };
            if current.revision() != request.expected_revision() {
                let revision = current.revision();
                return finish_denied(
                    transaction,
                    actor,
                    descriptor,
                    ManagementMutationOutcome::RevisionConflict { current: revision },
                )
                .await;
            }
            if request.status() == MemberStatus::Suspended
                && current.status() == MemberStatus::Active
                && principal_has_manager_capability(&mut transaction, &actor, principal_id).await?
            {
                let exclusion = ManagerExclusion {
                    principal_id: Some(principal_id),
                    ..ManagerExclusion::default()
                };
                if !manager_remains(&mut transaction, &actor, &exclusion).await? {
                    return finish_denied(
                        transaction,
                        actor,
                        descriptor,
                        ManagementMutationOutcome::LastManager,
                    )
                    .await;
                }
            }
            ensure_revision_can_advance(current.revision())?;
            if !reauthorize_actor(&mut transaction, &mut actor, permissions::MEMBERS_MANAGE).await?
            {
                return Ok(ManagementMutationOutcome::Forbidden);
            }
            let (status, suspended_at_ms, reason) = match request.status() {
                MemberStatus::Active => ("active", None, None),
                MemberStatus::Suspended => ("suspended", Some(actor.now_ms), request.reason()),
            };
            let updated = sqlx::query(
                r"
                UPDATE tenant_human_memberships
                SET status=$3, suspended_at_ms=$4, suspended_reason=$5,
                    updated_at_ms=GREATEST(updated_at_ms,$6), revision=revision+1
                WHERE tenant_id=$1 AND principal_id=$2 AND revision=$7
                ",
            )
            .bind(&actor.tenant_id)
            .bind(principal_id)
            .bind(status)
            .bind(suspended_at_ms)
            .bind(reason)
            .bind(actor.now_ms)
            .bind(revision_to_i64(request.expected_revision())?)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?
            .rows_affected();
            if updated != 1 {
                return Err(ManagementRepositoryError::CorruptData);
            }
            let member = load_member(&mut transaction, &actor.tenant_id, principal_id)
                .await?
                .ok_or(ManagementRepositoryError::CorruptData)?;
            finish_applied(transaction, actor, descriptor, member).await
        })
    }
}

#[cfg(test)]
mod tests {
    use automata_ci_auth::management::{HumanRbacManagementRepository, ManagementRepositoryError};
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use static_assertions::assert_impl_all;

    use super::*;

    assert_impl_all!(
        PostgresHumanRbacManagementRepository:
            HumanRbacManagementRepository,
            Clone,
            Send,
            Sync
    );

    #[tokio::test]
    async fn adapter_debug_output_omits_pool_configuration() {
        let pool = PgPoolOptions::new().connect_lazy_with(PgConnectOptions::new());
        let repository = PostgresHumanRbacManagementRepository::new(pool);
        assert_eq!(
            format!("{repository:?}"),
            "PostgresHumanRbacManagementRepository { .. }"
        );
    }

    #[test]
    fn errors_are_sanitized() {
        let rendered = [
            ManagementRepositoryError::InvalidRequest,
            ManagementRepositoryError::Unavailable,
            ManagementRepositoryError::CorruptData,
        ]
        .map(|error| error.to_string())
        .join(" ");
        assert!(!rendered.contains("SELECT"));
        assert!(!rendered.contains("postgres"));
        assert!(!rendered.contains("password"));
    }

    #[test]
    fn maximum_management_revision_cannot_advance() {
        let maximum = ManagementRevision::new(i64::MAX as u64).expect("maximum revision");
        let advanceable =
            ManagementRevision::new(i64::MAX as u64 - 1).expect("advanceable revision");

        assert_eq!(
            ensure_revision_can_advance(maximum),
            Err(ManagementRepositoryError::CorruptData)
        );
        assert_eq!(ensure_revision_can_advance(advanceable), Ok(()));
    }
}
