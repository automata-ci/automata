use async_trait::async_trait;
use automata_ci_auth::{
    authorization::{OutputVisibility, RepositoryPublicationPolicy},
    management::{ManagementActor, ManagementRevision},
};
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    PublicationRepositoryError, RepositoryPublicationRepository, RepositoryPublicationSettings,
    UpdateRepositoryPublication, UpdateRepositoryPublicationOutcome,
};

use super::PostgresStore;

const UPDATE_PERMISSION: &str = "repositories:visibility:update";
const UPDATE_ACTION: &str = "repository.publication.update";
const RESOURCE_KIND: &str = "repository-publication";
const TENANT_MANAGEMENT_LOCK_NAMESPACE: i64 = 731_662_009;

#[derive(FromRow)]
struct ActorRow {
    session_authorization_revision: i64,
    session_provider_id: String,
    session_provider_subject: String,
    issued_at_ms: i64,
    idle_expires_at_ms: i64,
    expires_at_ms: i64,
    revoked_at_ms: Option<i64>,
    session_kind: String,
    audience: String,
    principal_status: String,
    membership_status: String,
    current_authorization_revision: i64,
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

enum ActorAuthorization {
    Authorized {
        principal_id: Uuid,
        session_id: Uuid,
        authorization_revision: i64,
    },
    Forbidden {
        principal_id: Uuid,
        session_id: Uuid,
        authorization_revision: i64,
    },
    SessionStale,
}

#[derive(FromRow)]
struct PublicationRow {
    dashboard_audience: String,
    log_audience: String,
    artifact_audience: String,
    revision: i64,
}

impl PublicationRow {
    fn policy(&self) -> Result<RepositoryPublicationPolicy, PublicationRepositoryError> {
        Ok(RepositoryPublicationPolicy::new(
            parse_dashboard(&self.dashboard_audience)?,
            parse_safe_output(&self.log_audience)?,
            parse_safe_output(&self.artifact_audience)?,
        ))
    }

    fn revision(&self) -> Result<ManagementRevision, PublicationRepositoryError> {
        let value =
            u64::try_from(self.revision).map_err(|_| PublicationRepositoryError::CorruptData)?;
        ManagementRevision::new(value).map_err(|_| PublicationRepositoryError::CorruptData)
    }
}

#[async_trait]
impl RepositoryPublicationRepository for PostgresStore {
    #[allow(clippy::too_many_lines)] // One transaction owns authorization, mutation, and audit.
    async fn update_repository_publication(
        &self,
        request: UpdateRepositoryPublication,
    ) -> Result<UpdateRepositoryPublicationOutcome, PublicationRepositoryError> {
        let actor = request.actor();
        let now_ms = timestamp_milliseconds(actor.now())?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| PublicationRepositoryError::Unavailable)?;
        lock_tenant_authorization(&mut transaction, actor.tenant_id().as_str()).await?;

        let authorization = authorize_actor(
            &mut transaction,
            actor,
            request.repository_id().as_uuid(),
            now_ms,
        )
        .await?;
        let (principal_id, session_id, authorization_revision) = match authorization {
            ActorAuthorization::SessionStale => {
                transaction
                    .commit()
                    .await
                    .map_err(|_| PublicationRepositoryError::Unavailable)?;
                return Ok(UpdateRepositoryPublicationOutcome::SessionStale);
            }
            ActorAuthorization::Forbidden {
                principal_id,
                session_id,
                authorization_revision,
            } => {
                append_audit(
                    &mut transaction,
                    actor,
                    principal_id,
                    session_id,
                    authorization_revision,
                    request.repository_id().as_uuid(),
                    "denied",
                    now_ms,
                )
                .await?;
                transaction
                    .commit()
                    .await
                    .map_err(|_| PublicationRepositoryError::Unavailable)?;
                return Ok(UpdateRepositoryPublicationOutcome::Forbidden);
            }
            ActorAuthorization::Authorized {
                principal_id,
                session_id,
                authorization_revision,
            } => (principal_id, session_id, authorization_revision),
        };

        let current = sqlx::query_as::<_, PublicationRow>(
            r"
            SELECT policy.dashboard_audience, policy.log_audience,
                   policy.artifact_audience, policy.revision
            FROM repositories AS repository
            JOIN repository_publication_policies AS policy
              ON policy.tenant_id = repository.tenant_id
             AND policy.repository_id = repository.id
            WHERE repository.tenant_id = $1 AND repository.id = $2
            FOR UPDATE OF policy
            ",
        )
        .bind(actor.tenant_id().as_str())
        .bind(request.repository_id().as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sql_error)?;

        let Some(current) = current else {
            append_audit(
                &mut transaction,
                actor,
                principal_id,
                session_id,
                authorization_revision,
                request.repository_id().as_uuid(),
                "failed",
                now_ms,
            )
            .await?;
            transaction
                .commit()
                .await
                .map_err(|_| PublicationRepositoryError::Unavailable)?;
            return Ok(UpdateRepositoryPublicationOutcome::NotFound);
        };
        current.policy()?;
        let current_revision = current.revision()?;
        if current_revision != request.expected_revision() {
            append_audit(
                &mut transaction,
                actor,
                principal_id,
                session_id,
                authorization_revision,
                request.repository_id().as_uuid(),
                "failed",
                now_ms,
            )
            .await?;
            transaction
                .commit()
                .await
                .map_err(|_| PublicationRepositoryError::Unavailable)?;
            return Ok(UpdateRepositoryPublicationOutcome::RevisionConflict {
                current: current_revision,
            });
        }

        let policy = request.policy();
        let next_revision = sqlx::query_scalar::<_, i64>(
            r"
            UPDATE repository_publication_policies
            SET dashboard_audience = $3,
                log_audience = $4,
                artifact_audience = $5,
                revision = revision + 1,
                updated_by_principal_id = $6,
                updated_at_ms = $7
            WHERE tenant_id = $1 AND repository_id = $2 AND revision = $8
            RETURNING revision
            ",
        )
        .bind(actor.tenant_id().as_str())
        .bind(request.repository_id().as_uuid())
        .bind(encode_dashboard(policy.dashboard()))
        .bind(encode_safe_output(policy.logs()))
        .bind(encode_safe_output(policy.artifacts()))
        .bind(principal_id)
        .bind(now_ms)
        .bind(
            i64::try_from(current_revision.value())
                .map_err(|_| PublicationRepositoryError::InvalidRequest)?,
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sql_error)?
        .ok_or(PublicationRepositoryError::CorruptData)?;
        let next_revision = ManagementRevision::new(
            u64::try_from(next_revision).map_err(|_| PublicationRepositoryError::CorruptData)?,
        )
        .map_err(|_| PublicationRepositoryError::CorruptData)?;

        append_audit(
            &mut transaction,
            actor,
            principal_id,
            session_id,
            authorization_revision,
            request.repository_id().as_uuid(),
            "succeeded",
            now_ms,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| PublicationRepositoryError::Unavailable)?;

        Ok(UpdateRepositoryPublicationOutcome::Applied(
            RepositoryPublicationSettings::new(
                request.repository_id(),
                policy,
                next_revision,
                actor.now(),
            ),
        ))
    }
}

async fn lock_tenant_authorization(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
) -> Result<(), PublicationRepositoryError> {
    // This is the same transaction-scoped namespace used by durable RBAC
    // management mutations. The membership row lock below is the actor fence;
    // this tenant mutex also serializes role-permission changes whose mapped
    // GitHub beneficiaries cannot be enumerated by a database trigger.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, $2))")
        .bind(tenant_id)
        .bind(TENANT_MANAGEMENT_LOCK_NAMESPACE)
        .execute(&mut **transaction)
        .await
        .map_err(map_sql_error)?;
    Ok(())
}

async fn authorize_actor(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &ManagementActor,
    repository_id: Uuid,
    now_ms: i64,
) -> Result<ActorAuthorization, PublicationRepositoryError> {
    let principal_id = parse_canonical_uuid(actor.principal_id().as_str())?;
    let session_id = parse_canonical_uuid(actor.session_id().as_str())?;
    let row = sqlx::query_as::<_, ActorRow>(
        r"
        SELECT session.authorization_revision AS session_authorization_revision,
               session.provider_id AS session_provider_id,
               session.provider_subject AS session_provider_subject,
               session.issued_at_ms, session.idle_expires_at_ms,
               session.expires_at_ms, session.revoked_at_ms,
               session.session_kind, session.audience,
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
        FOR UPDATE OF session, membership, principal
        ",
    )
    .bind(actor.tenant_id().as_str())
    .bind(principal_id)
    .bind(session_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_sql_error)?;
    let Some(row) = row else {
        return Ok(ActorAuthorization::SessionStale);
    };
    let current_revision = positive_revision(row.current_authorization_revision)?;
    let session_revision = positive_revision(row.session_authorization_revision)?;
    let expected_revision = i64::try_from(actor.authorization_revision().value())
        .map_err(|_| PublicationRepositoryError::InvalidRequest)?;
    let kind_valid = matches!(
        (row.session_kind.as_str(), row.audience.as_str()),
        ("browser", "automata.web") | ("cli", "automata.cli")
    );
    if row.principal_status != "active"
        || row.membership_status != "active"
        || row.revoked_at_ms.is_some()
        || !kind_valid
        || row.issued_at_ms > now_ms
        || row.idle_expires_at_ms <= now_ms
        || row.expires_at_ms <= now_ms
        || session_revision != current_revision
        || expected_revision != current_revision
    {
        return Ok(ActorAuthorization::SessionStale);
    }

    let direct = actor_has_direct_permission(
        transaction,
        actor.tenant_id().as_str(),
        principal_id,
        repository_id,
        now_ms,
    )
    .await?;
    let allowed = if direct {
        true
    } else if row.session_provider_id == "github" {
        actor_has_github_mapping_permission(
            transaction,
            actor.tenant_id().as_str(),
            principal_id,
            &row.session_provider_subject,
            repository_id,
            now_ms,
        )
        .await?
    } else {
        false
    };
    if allowed {
        Ok(ActorAuthorization::Authorized {
            principal_id,
            session_id,
            authorization_revision: current_revision,
        })
    } else {
        Ok(ActorAuthorization::Forbidden {
            principal_id,
            session_id,
            authorization_revision: current_revision,
        })
    }
}

async fn actor_has_direct_permission(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    principal_id: Uuid,
    repository_id: Uuid,
    now_ms: i64,
) -> Result<bool, PublicationRepositoryError> {
    sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM rbac_role_bindings AS binding
            JOIN rbac_role_permissions AS permission_grant
              ON permission_grant.tenant_id = binding.tenant_id
             AND permission_grant.role_id = binding.role_id
            WHERE binding.tenant_id = $1
              AND binding.principal_id = $2
              AND binding.status = 'active'
              AND (binding.valid_until_ms IS NULL OR binding.valid_until_ms > $3)
              AND permission_grant.permission_name = $4
              AND (
                  (
                      binding.scope_kind = 'tenant'
                      AND binding.repository_id IS NULL
                      AND binding.runner_group_id IS NULL
                  ) OR (
                      binding.scope_kind = 'repository'
                      AND binding.repository_id = $5
                      AND binding.runner_group_id IS NULL
                  )
              )
        )
        ",
    )
    .bind(tenant_id)
    .bind(principal_id)
    .bind(now_ms)
    .bind(UPDATE_PERMISSION)
    .bind(repository_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_sql_error)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn actor_has_github_mapping_permission(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    principal_id: Uuid,
    provider_subject: &str,
    repository_id: Uuid,
    now_ms: i64,
) -> Result<bool, PublicationRepositoryError> {
    let snapshots = sqlx::query_as::<_, GithubAuthoritySnapshotRow>(
        r"
        SELECT snapshot.id, snapshot.provider_token_version,
               snapshot.observed_at_ms, snapshot.valid_until_ms,
               identity.principal_id AS identity_principal_id,
               identity.provider_subject AS identity_provider_subject
        FROM github_membership_snapshots AS snapshot
        LEFT JOIN human_provider_identities AS identity
          ON identity.principal_id = snapshot.principal_id
         AND identity.provider_id = snapshot.provider_id
         AND identity.provider_subject = snapshot.provider_subject
        WHERE snapshot.tenant_id = $1
          AND snapshot.principal_id = $2
          AND snapshot.provider_id = 'github'
          AND snapshot.provider_subject = $3
          AND snapshot.observed_at_ms <= $4
        ORDER BY snapshot.observed_at_ms DESC, snapshot.id DESC
        LIMIT 2
        ",
    )
    .bind(tenant_id)
    .bind(principal_id)
    .bind(provider_subject)
    .bind(now_ms)
    .fetch_all(&mut **transaction)
    .await
    .map_err(map_sql_error)?;
    let Some(snapshot) = snapshots.first() else {
        return Ok(false);
    };
    let canonical_subject = provider_subject
        .parse::<u64>()
        .ok()
        .filter(|subject| *subject > 0)
        .is_some_and(|subject| subject.to_string() == provider_subject);
    if snapshot.id.is_nil()
        || snapshot.provider_token_version <= 0
        || !canonical_subject
        || !durable_timestamp_is_canonical(snapshot.observed_at_ms)
        || !durable_timestamp_is_canonical(snapshot.valid_until_ms)
        || snapshot.valid_until_ms <= snapshot.observed_at_ms
        || snapshot.identity_principal_id != Some(principal_id)
        || snapshot.identity_provider_subject.as_deref() != Some(provider_subject)
        || snapshots
            .get(1)
            .is_some_and(|other| other.observed_at_ms == snapshot.observed_at_ms)
    {
        return Err(PublicationRepositoryError::CorruptData);
    }
    if snapshot.valid_until_ms <= now_ms {
        return Ok(false);
    }

    sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM github_role_mappings AS mapping
            JOIN rbac_role_permissions AS permission_grant
              ON permission_grant.tenant_id = mapping.tenant_id
             AND permission_grant.role_id = mapping.role_id
            WHERE mapping.tenant_id = $1
              AND mapping.provider_id = 'github'
              AND mapping.status = 'active'
              AND permission_grant.permission_name = $3
              AND (
                  (
                      mapping.scope_kind = 'tenant'
                      AND mapping.repository_id IS NULL
                      AND mapping.runner_group_id IS NULL
                  ) OR (
                      mapping.scope_kind = 'repository'
                      AND mapping.repository_id = $4
                      AND mapping.runner_group_id IS NULL
                  )
              )
              AND (
                  (
                      mapping.team_id IS NULL
                      AND EXISTS (
                          SELECT 1
                          FROM github_organization_membership_observations AS organization
                          WHERE organization.tenant_id = mapping.tenant_id
                            AND organization.snapshot_id = $2
                            AND organization.organization_id = mapping.organization_id
                      )
                  ) OR (
                      mapping.team_id IS NOT NULL
                      AND EXISTS (
                          SELECT 1
                          FROM github_team_membership_observations AS team
                          WHERE team.tenant_id = mapping.tenant_id
                            AND team.snapshot_id = $2
                            AND team.organization_id = mapping.organization_id
                            AND team.team_id = mapping.team_id
                      )
                  )
              )
        )
        ",
    )
    .bind(tenant_id)
    .bind(snapshot.id)
    .bind(UPDATE_PERMISSION)
    .bind(repository_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_sql_error)
}

#[allow(clippy::too_many_arguments)]
async fn append_audit(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &ManagementActor,
    principal_id: Uuid,
    session_id: Uuid,
    authorization_revision: i64,
    repository_id: Uuid,
    outcome: &'static str,
    occurred_at_ms: i64,
) -> Result<(), PublicationRepositoryError> {
    sqlx::query(
        r"
        INSERT INTO security_audit_events (
            event_id, tenant_id, occurred_at_ms, actor_kind,
            actor_principal_id, actor_session_id, authorization_revision,
            action, outcome, resource_kind, resource_id, request_id
        ) VALUES ($1, $2, $3, 'human', $4, $5, $6, $7, $8, $9, $10, $11)
        ",
    )
    .bind(Uuid::new_v4())
    .bind(actor.tenant_id().as_str())
    .bind(occurred_at_ms)
    .bind(principal_id)
    .bind(session_id)
    .bind(authorization_revision)
    .bind(UPDATE_ACTION)
    .bind(outcome)
    .bind(RESOURCE_KIND)
    .bind(repository_id.hyphenated().to_string())
    .bind(
        actor
            .request_id()
            .map(automata_ci_auth::management::ManagementRequestId::as_str),
    )
    .execute(&mut **transaction)
    .await
    .map_err(map_sql_error)?;
    Ok(())
}

fn encode_dashboard(visibility: OutputVisibility) -> &'static str {
    match visibility {
        OutputVisibility::Private => "private",
        OutputVisibility::Authenticated => "authenticated",
        OutputVisibility::Public => "public",
    }
}

fn encode_safe_output(visibility: OutputVisibility) -> &'static str {
    match visibility {
        OutputVisibility::Private => "private",
        OutputVisibility::Authenticated => "authenticated",
        OutputVisibility::Public => "public",
    }
}

fn parse_dashboard(value: &str) -> Result<OutputVisibility, PublicationRepositoryError> {
    match value {
        "private" => Ok(OutputVisibility::Private),
        "authenticated" => Ok(OutputVisibility::Authenticated),
        "public" => Ok(OutputVisibility::Public),
        _ => Err(PublicationRepositoryError::CorruptData),
    }
}

fn parse_safe_output(value: &str) -> Result<OutputVisibility, PublicationRepositoryError> {
    match value {
        "private" => Ok(OutputVisibility::Private),
        "authenticated" => Ok(OutputVisibility::Authenticated),
        "public" => Ok(OutputVisibility::Public),
        _ => Err(PublicationRepositoryError::CorruptData),
    }
}

fn timestamp_milliseconds(
    timestamp: automata_ci_auth::time::UnixTimestamp,
) -> Result<i64, PublicationRepositoryError> {
    let milliseconds = timestamp
        .as_seconds()
        .checked_mul(1_000)
        .ok_or(PublicationRepositoryError::InvalidRequest)?;
    i64::try_from(milliseconds).map_err(|_| PublicationRepositoryError::InvalidRequest)
}

fn durable_timestamp_is_canonical(value: i64) -> bool {
    value >= 0 && value % 1_000 == 0
}

fn parse_canonical_uuid(value: &str) -> Result<Uuid, PublicationRepositoryError> {
    let parsed = Uuid::parse_str(value).map_err(|_| PublicationRepositoryError::InvalidRequest)?;
    if parsed.is_nil() || parsed.hyphenated().to_string() != value {
        return Err(PublicationRepositoryError::InvalidRequest);
    }
    Ok(parsed)
}

fn positive_revision(value: i64) -> Result<i64, PublicationRepositoryError> {
    if value <= 0 {
        return Err(PublicationRepositoryError::CorruptData);
    }
    Ok(value)
}

#[allow(clippy::needless_pass_by_value)] // This signature is a direct `Result::map_err` adapter.
fn map_sql_error(error: sqlx::Error) -> PublicationRepositoryError {
    if error.as_database_error().is_some() {
        PublicationRepositoryError::CorruptData
    } else {
        PublicationRepositoryError::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_preferences_use_current_durable_values() {
        assert_eq!(encode_dashboard(OutputVisibility::Public), "public");
        assert_eq!(encode_safe_output(OutputVisibility::Public), "public");
        assert_eq!(
            parse_safe_output("public").expect("safe public preference"),
            OutputVisibility::Public
        );
        assert!(parse_safe_output("public_if_safe").is_err());
        assert!(parse_dashboard("public_if_safe").is_err());
    }
}
