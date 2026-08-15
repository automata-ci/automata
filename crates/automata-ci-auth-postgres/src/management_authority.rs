use automata_ci_auth::{
    management::{ManagementActor, ManagementRepositoryError},
    session::CLI_SESSION_ACTIVATION_LIFETIME_SECONDS,
};
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

use super::{
    session::{database_time_milliseconds, validate_caller_time},
    support::{
        canonical_uuid, management_revision_to_i64 as revision_to_i64, tenant_management_lock,
        timestamp_from_milliseconds,
    },
};

type DatabaseErrorMapper = fn(sqlx::Error) -> ManagementRepositoryError;

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
pub(super) struct AuthorizedActor {
    pub(super) tenant_id: String,
    pub(super) principal_id: Uuid,
    pub(super) session_id: Uuid,
    provider_id: String,
    provider_subject: String,
    pub(super) authorization_revision: i64,
    liveness: ActorLiveness,
    pub(super) now_ms: i64,
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

pub(super) enum ActorAuthentication {
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

pub(super) async fn authenticate_actor(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &ManagementActor,
    lock: bool,
    map_database_error: DatabaseErrorMapper,
) -> Result<ActorAuthentication, ManagementRepositoryError> {
    let keys = ActorKeys::parse(actor)?;
    let authority_locked =
        lock_actor_authority(transaction, &keys, lock, map_database_error).await?;
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
    map_database_error: DatabaseErrorMapper,
) -> Result<bool, ManagementRepositoryError> {
    // Canonical order after the tenant advisory lock: session, principal,
    // membership. Adapters lock any additional authority and mutation targets
    // afterward.
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

pub(super) async fn refresh_actor_time(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &mut AuthorizedActor,
    map_database_error: DatabaseErrorMapper,
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

pub(super) async fn actor_has_permission(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &AuthorizedActor,
    permission: &str,
    map_database_error: DatabaseErrorMapper,
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
    actor_has_github_mapping_permission(transaction, actor, permission, map_database_error).await
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
    map_database_error: DatabaseErrorMapper,
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
    validate_timestamp_interval(snapshot.observed_at_ms, snapshot.valid_until_ms)?;
    if snapshot.id.is_nil()
        || snapshot.provider_token_version <= 0
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

fn validate_timestamp_interval(
    observed_at_ms: i64,
    valid_until_ms: i64,
) -> Result<(), ManagementRepositoryError> {
    let observed_at = timestamp_from_milliseconds(observed_at_ms)
        .map_err(|()| ManagementRepositoryError::CorruptData)?;
    let valid_until = timestamp_from_milliseconds(valid_until_ms)
        .map_err(|()| ManagementRepositoryError::CorruptData)?;
    if valid_until <= observed_at {
        return Err(ManagementRepositoryError::CorruptData);
    }
    Ok(())
}

pub(super) async fn actor_has_permissions(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &AuthorizedActor,
    required: &[&str],
    map_database_error: DatabaseErrorMapper,
) -> Result<bool, ManagementRepositoryError> {
    for permission in required {
        if !actor_has_permission(transaction, actor, permission, map_database_error).await? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) async fn reauthorize_actor(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &mut AuthorizedActor,
    required: &str,
    map_database_error: DatabaseErrorMapper,
) -> Result<bool, ManagementRepositoryError> {
    if !refresh_actor_time(transaction, actor, map_database_error).await? {
        return Ok(false);
    }
    actor_has_permission(transaction, actor, required, map_database_error).await
}

#[derive(Clone, Copy)]
pub(super) struct AuditDescriptor<'a> {
    action: &'static str,
    resource_kind: &'static str,
    resource_id: &'a str,
    request_id: Option<&'a str>,
}

impl<'a> AuditDescriptor<'a> {
    pub(super) fn new(
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

pub(super) async fn append_audit_event(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &AuthorizedActor,
    descriptor: AuditDescriptor<'_>,
    outcome: &str,
    map_database_error: DatabaseErrorMapper,
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

pub(super) enum MutationAuthorization {
    Authorized(AuthorizedActor),
    Forbidden,
    SessionStale,
}

pub(super) async fn authorize_mutation(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &ManagementActor,
    required_permissions: &[&str],
    descriptor: AuditDescriptor<'_>,
    map_database_error: DatabaseErrorMapper,
) -> Result<MutationAuthorization, ManagementRepositoryError> {
    tenant_management_lock(transaction, actor.tenant_id().as_str())
        .await
        .map_err(map_database_error)?;
    match authenticate_actor(transaction, actor, true, map_database_error).await? {
        ActorAuthentication::Forbidden => Ok(MutationAuthorization::Forbidden),
        ActorAuthentication::Stale(current) => {
            append_audit_event(
                transaction,
                &current,
                descriptor,
                "denied",
                map_database_error,
            )
            .await?;
            Ok(MutationAuthorization::SessionStale)
        }
        ActorAuthentication::Active(current) => {
            if actor_has_permissions(
                transaction,
                &current,
                required_permissions,
                map_database_error,
            )
            .await?
            {
                Ok(MutationAuthorization::Authorized(current))
            } else {
                append_audit_event(
                    transaction,
                    &current,
                    descriptor,
                    "denied",
                    map_database_error,
                )
                .await?;
                Ok(MutationAuthorization::Forbidden)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_interval_accepts_second_aligned_forward_bounds() {
        assert_eq!(validate_timestamp_interval(1_000, 2_000), Ok(()));
    }

    #[test]
    fn timestamp_interval_rejects_negative_bounds() {
        for interval in [(-1_000, 1_000), (0, -1_000)] {
            assert_eq!(
                validate_timestamp_interval(interval.0, interval.1),
                Err(ManagementRepositoryError::CorruptData)
            );
        }
    }

    #[test]
    fn timestamp_interval_rejects_misaligned_bounds() {
        for interval in [(1, 1_000), (0, 1_001)] {
            assert_eq!(
                validate_timestamp_interval(interval.0, interval.1),
                Err(ManagementRepositoryError::CorruptData)
            );
        }
    }

    #[test]
    fn timestamp_interval_rejects_equal_bounds() {
        assert_eq!(
            validate_timestamp_interval(1_000, 1_000),
            Err(ManagementRepositoryError::CorruptData)
        );
    }

    #[test]
    fn timestamp_interval_rejects_reversed_bounds() {
        assert_eq!(
            validate_timestamp_interval(2_000, 1_000),
            Err(ManagementRepositoryError::CorruptData)
        );
    }
}
