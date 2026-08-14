use std::{collections::BTreeSet, fmt};

use automata_ci_auth::{
    github::{
        GithubMembershipObservation, GithubMembershipPersistenceFuture, GithubMembershipRepository,
        GithubMembershipRepositoryError, GithubMembershipSnapshot, GithubMembershipSnapshotId,
        GithubOrganizationId, GithubOrganizationLogin, GithubOrganizationMembership,
        GithubOrganizationMembershipRole, GithubTeam, GithubTeamId, GithubTeamSlug,
        MAX_GITHUB_MEMBERSHIP_OBSERVATIONS, PersistGithubMembershipSnapshot,
        PersistGithubMembershipSnapshotOutcome,
    },
    human::{PrincipalId, ProviderSubject, TenantId},
    vault::TokenVersion,
};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::support::{
    is_integrity_violation, timestamp_from_milliseconds, timestamp_to_milliseconds,
};

const GITHUB_PROVIDER_ID: &str = "github";

/// `PostgreSQL` durable GitHub membership authority.
#[derive(Clone)]
pub struct PostgresGithubMembershipRepository {
    pool: PgPool,
}

impl PostgresGithubMembershipRepository {
    /// Creates a membership repository backed by `pool`.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl fmt::Debug for PostgresGithubMembershipRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresGithubMembershipRepository")
            .finish_non_exhaustive()
    }
}

#[derive(FromRow)]
struct PrincipalRow {
    status: String,
}

#[derive(FromRow)]
struct IdentityRow {
    principal_id: Uuid,
    provider_id: String,
    provider_subject: String,
}

#[derive(FromRow)]
struct MembershipRow {
    tenant_id: String,
    principal_id: Uuid,
    status: String,
    authorization_revision: i64,
}

#[derive(FromRow)]
struct ProviderTokenRow {
    tenant_id: String,
    principal_id: Uuid,
    provider_id: String,
    provider_subject: String,
    version: i64,
    issued_at_ms: i64,
    access_expires_at_ms: Option<i64>,
    revoked_at_ms: Option<i64>,
}

#[derive(FromRow)]
struct SnapshotHeaderRow {
    tenant_id: String,
    id: Uuid,
    principal_id: Uuid,
    provider_id: String,
    provider_subject: String,
    provider_token_version: i64,
    observed_at_ms: i64,
    valid_until_ms: i64,
}

#[derive(FromRow)]
struct OrganizationObservationRow {
    tenant_id: String,
    snapshot_id: Uuid,
    organization_id: i64,
    organization_login: String,
    membership_role: String,
}

#[derive(FromRow)]
struct TeamObservationRow {
    tenant_id: String,
    snapshot_id: Uuid,
    organization_id: i64,
    team_id: i64,
    team_slug: String,
}

struct DurableSnapshot {
    request: PersistGithubMembershipSnapshot,
}

impl DurableSnapshot {
    fn effective_authority(&self) -> EffectiveMembershipAuthority {
        EffectiveMembershipAuthority::from_snapshot(self.request.memberships())
    }
}

#[derive(Default, Eq, PartialEq)]
struct EffectiveMembershipAuthority {
    organizations: BTreeSet<i64>,
    teams: BTreeSet<(i64, i64)>,
}

impl EffectiveMembershipAuthority {
    fn from_snapshot(snapshot: &GithubMembershipSnapshot) -> Self {
        Self {
            organizations: snapshot
                .organizations()
                .map(|membership| membership.id().get())
                .collect(),
            teams: snapshot
                .teams()
                .map(|team| (team.organization_id().get(), team.id().get()))
                .collect(),
        }
    }
}

fn membership_snapshot_from_rows(
    header: &SnapshotHeaderRow,
    organizations: Vec<OrganizationObservationRow>,
    teams: Vec<TeamObservationRow>,
) -> Result<GithubMembershipSnapshot, GithubMembershipRepositoryError> {
    let observation_count = organizations
        .len()
        .checked_add(teams.len())
        .ok_or(GithubMembershipRepositoryError::CorruptData)?;
    if observation_count > MAX_GITHUB_MEMBERSHIP_OBSERVATIONS {
        return Err(GithubMembershipRepositoryError::CorruptData);
    }
    let mut organization_memberships = Vec::with_capacity(organizations.len());
    let mut organization_logins = std::collections::BTreeMap::new();
    for organization in organizations {
        if organization.tenant_id != header.tenant_id || organization.snapshot_id != header.id {
            return Err(GithubMembershipRepositoryError::CorruptData);
        }
        let id = GithubOrganizationId::new(organization.organization_id)
            .map_err(|_| GithubMembershipRepositoryError::CorruptData)?;
        let login = GithubOrganizationLogin::new(organization.organization_login)
            .map_err(|_| GithubMembershipRepositoryError::CorruptData)?;
        let role = match organization.membership_role.as_str() {
            "member" => GithubOrganizationMembershipRole::Member,
            "admin" => GithubOrganizationMembershipRole::Admin,
            _ => return Err(GithubMembershipRepositoryError::CorruptData),
        };
        organization_logins.insert(id, login.clone());
        organization_memberships.push(GithubOrganizationMembership::new(id, login, role));
    }
    let mut team_memberships = Vec::with_capacity(teams.len());
    for team in teams {
        if team.tenant_id != header.tenant_id || team.snapshot_id != header.id {
            return Err(GithubMembershipRepositoryError::CorruptData);
        }
        let organization_id = GithubOrganizationId::new(team.organization_id)
            .map_err(|_| GithubMembershipRepositoryError::CorruptData)?;
        let organization_login = organization_logins
            .get(&organization_id)
            .cloned()
            .ok_or(GithubMembershipRepositoryError::CorruptData)?;
        team_memberships.push(GithubTeam::new(
            GithubTeamId::new(team.team_id)
                .map_err(|_| GithubMembershipRepositoryError::CorruptData)?,
            organization_id,
            organization_login,
            GithubTeamSlug::new(team.team_slug)
                .map_err(|_| GithubMembershipRepositoryError::CorruptData)?,
        ));
    }
    GithubMembershipSnapshot::new(organization_memberships, team_memberships)
        .map_err(|_| GithubMembershipRepositoryError::CorruptData)
}

async fn load_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    header: SnapshotHeaderRow,
) -> Result<DurableSnapshot, GithubMembershipRepositoryError> {
    let organizations = sqlx::query_as::<_, OrganizationObservationRow>(
        r"
        SELECT tenant_id,snapshot_id,organization_id,organization_login,membership_role
        FROM github_organization_membership_observations
        WHERE tenant_id=$1 AND snapshot_id=$2
        ORDER BY organization_id
        LIMIT 100001
        ",
    )
    .bind(&header.tenant_id)
    .bind(header.id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| GithubMembershipRepositoryError::Unavailable)?;
    let teams = sqlx::query_as::<_, TeamObservationRow>(
        r"
        SELECT tenant_id,snapshot_id,organization_id,team_id,team_slug
        FROM github_team_membership_observations
        WHERE tenant_id=$1 AND snapshot_id=$2
        ORDER BY team_id
        LIMIT 100001
        ",
    )
    .bind(&header.tenant_id)
    .bind(header.id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| GithubMembershipRepositoryError::Unavailable)?;

    let memberships = membership_snapshot_from_rows(&header, organizations, teams)?;
    if header.provider_id != GITHUB_PROVIDER_ID {
        return Err(GithubMembershipRepositoryError::CorruptData);
    }
    let tenant_id = TenantId::new(header.tenant_id)
        .map_err(|_| GithubMembershipRepositoryError::CorruptData)?;
    let principal_id = PrincipalId::new(header.principal_id.hyphenated().to_string())
        .map_err(|_| GithubMembershipRepositoryError::CorruptData)?;
    let provider_subject = ProviderSubject::new(header.provider_subject)
        .map_err(|_| GithubMembershipRepositoryError::CorruptData)?;
    let token_version = u64::try_from(header.provider_token_version)
        .ok()
        .and_then(|version| TokenVersion::new(version).ok())
        .ok_or(GithubMembershipRepositoryError::CorruptData)?;
    let request = PersistGithubMembershipSnapshot::new(
        tenant_id,
        principal_id,
        provider_subject,
        token_version,
        GithubMembershipObservation::new(
            GithubMembershipSnapshotId::from_uuid(header.id)
                .map_err(|_| GithubMembershipRepositoryError::CorruptData)?,
            memberships,
            timestamp_from_milliseconds(header.observed_at_ms)
                .map_err(|()| GithubMembershipRepositoryError::CorruptData)?,
            timestamp_from_milliseconds(header.valid_until_ms)
                .map_err(|()| GithubMembershipRepositoryError::CorruptData)?,
        )
        .map_err(|_| GithubMembershipRepositoryError::CorruptData)?,
    )
    .map_err(|_| GithubMembershipRepositoryError::CorruptData)?;
    Ok(DurableSnapshot { request })
}

fn positive_revision(value: i64) -> Result<u64, GithubMembershipRepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(GithubMembershipRepositoryError::CorruptData)
}

fn insertion_error(error: &sqlx::Error) -> GithubMembershipRepositoryError {
    if is_integrity_violation(error) {
        GithubMembershipRepositoryError::CorruptData
    } else {
        GithubMembershipRepositoryError::Unavailable
    }
}

impl PostgresGithubMembershipRepository {
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn persist_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        request: &PersistGithubMembershipSnapshot,
    ) -> Result<PersistGithubMembershipSnapshotOutcome, GithubMembershipRepositoryError> {
        let observed_at_ms = timestamp_to_milliseconds(request.observed_at())
            .map_err(|()| GithubMembershipRepositoryError::InvalidRequest)?;
        let valid_until_ms = timestamp_to_milliseconds(request.valid_until())
            .map_err(|()| GithubMembershipRepositoryError::InvalidRequest)?;
        let token_version = i64::try_from(request.provider_token_version().value())
            .map_err(|_| GithubMembershipRepositoryError::InvalidRequest)?;

        let principal = sqlx::query_as::<_, PrincipalRow>(
            "SELECT status FROM human_principals WHERE id=$1 FOR UPDATE",
        )
        .bind(request.principal_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| GithubMembershipRepositoryError::Unavailable)?;
        let Some(principal) = principal else {
            return Ok(PersistGithubMembershipSnapshotOutcome::PrincipalNotFound);
        };
        match principal.status.as_str() {
            "active" => {}
            "disabled" => {
                return Ok(PersistGithubMembershipSnapshotOutcome::PrincipalDisabled);
            }
            _ => return Err(GithubMembershipRepositoryError::CorruptData),
        }

        let identity = sqlx::query_as::<_, IdentityRow>(
            r"
                SELECT principal_id,provider_id,provider_subject
                FROM human_provider_identities
                WHERE principal_id=$1 AND provider_id='github' AND provider_subject=$2
                FOR UPDATE
                ",
        )
        .bind(request.principal_uuid())
        .bind(request.provider_subject().as_str())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| GithubMembershipRepositoryError::Unavailable)?;
        let Some(identity) = identity else {
            return Ok(PersistGithubMembershipSnapshotOutcome::IdentityNotFound);
        };
        if identity.principal_id != request.principal_uuid()
            || identity.provider_id != GITHUB_PROVIDER_ID
            || identity.provider_subject != request.provider_subject().as_str()
        {
            return Err(GithubMembershipRepositoryError::CorruptData);
        }

        let membership = sqlx::query_as::<_, MembershipRow>(
            r"
                SELECT tenant_id,principal_id,status,authorization_revision
                FROM tenant_human_memberships
                WHERE tenant_id=$1 AND principal_id=$2
                FOR UPDATE
                ",
        )
        .bind(request.tenant_id().as_str())
        .bind(request.principal_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| GithubMembershipRepositoryError::Unavailable)?;
        let Some(membership) = membership else {
            return Ok(PersistGithubMembershipSnapshotOutcome::MembershipNotFound);
        };
        if membership.tenant_id != request.tenant_id().as_str()
            || membership.principal_id != request.principal_uuid()
        {
            return Err(GithubMembershipRepositoryError::CorruptData);
        }
        match membership.status.as_str() {
            "active" => {}
            "suspended" => {
                return Ok(PersistGithubMembershipSnapshotOutcome::MembershipSuspended);
            }
            _ => return Err(GithubMembershipRepositoryError::CorruptData),
        }
        let current_authorization_revision = positive_revision(membership.authorization_revision)?;

        let provider_token = sqlx::query_as::<_, ProviderTokenRow>(
            r"
                SELECT tenant_id,principal_id,provider_id,provider_subject,version,
                       issued_at_ms,access_expires_at_ms,revoked_at_ms
                FROM human_provider_tokens
                WHERE tenant_id=$1 AND provider_id='github' AND provider_subject=$2
                ORDER BY (revoked_at_ms IS NULL) DESC,version DESC
                LIMIT 1
                FOR UPDATE
                ",
        )
        .bind(request.tenant_id().as_str())
        .bind(request.provider_subject().as_str())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| GithubMembershipRepositoryError::Unavailable)?;
        let Some(provider_token) = provider_token else {
            return Ok(PersistGithubMembershipSnapshotOutcome::ProviderTokenNotFound);
        };
        if provider_token.tenant_id != request.tenant_id().as_str()
            || provider_token.principal_id != request.principal_uuid()
            || provider_token.provider_id != GITHUB_PROVIDER_ID
            || provider_token.provider_subject != request.provider_subject().as_str()
        {
            return Err(GithubMembershipRepositoryError::CorruptData);
        }
        let durable_token_version = u64::try_from(provider_token.version)
            .ok()
            .and_then(|version| TokenVersion::new(version).ok())
            .ok_or(GithubMembershipRepositoryError::CorruptData)?;
        if durable_token_version != request.provider_token_version() {
            return Ok(
                PersistGithubMembershipSnapshotOutcome::ProviderTokenVersionChanged {
                    current_version: durable_token_version,
                },
            );
        }
        if provider_token.revoked_at_ms.is_some() {
            return Ok(PersistGithubMembershipSnapshotOutcome::ProviderTokenRevoked);
        }
        if provider_token.issued_at_ms > observed_at_ms {
            return Ok(PersistGithubMembershipSnapshotOutcome::ProviderTokenNotYetValid);
        }
        if provider_token
            .access_expires_at_ms
            .is_some_and(|expires_at_ms| expires_at_ms <= observed_at_ms)
        {
            return Ok(PersistGithubMembershipSnapshotOutcome::ProviderTokenExpired);
        }

        let existing = sqlx::query_as::<_, SnapshotHeaderRow>(
            r"
                SELECT tenant_id,id,principal_id,provider_id,provider_subject,
                       provider_token_version,observed_at_ms,valid_until_ms
                FROM github_membership_snapshots
                WHERE tenant_id=$1 AND id=$2
                FOR UPDATE
                ",
        )
        .bind(request.tenant_id().as_str())
        .bind(request.snapshot_id().as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| GithubMembershipRepositoryError::Unavailable)?;
        if let Some(existing) = existing {
            let existing = load_snapshot(transaction, existing).await?;
            if &existing.request == request {
                return Ok(PersistGithubMembershipSnapshotOutcome::AlreadyStored {
                    authorization_revision: current_authorization_revision,
                });
            }
            return Ok(PersistGithubMembershipSnapshotOutcome::SnapshotConflict);
        }

        let prior = sqlx::query_as::<_, SnapshotHeaderRow>(
            r"
                SELECT tenant_id,id,principal_id,provider_id,provider_subject,
                       provider_token_version,observed_at_ms,valid_until_ms
                FROM github_membership_snapshots
                WHERE tenant_id=$1 AND principal_id=$2
                  AND provider_id='github' AND provider_subject=$3
                ORDER BY observed_at_ms DESC,id DESC
                LIMIT 1
                FOR UPDATE
                ",
        )
        .bind(request.tenant_id().as_str())
        .bind(request.principal_uuid())
        .bind(request.provider_subject().as_str())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| GithubMembershipRepositoryError::Unavailable)?;
        let prior = match prior {
            Some(header) => Some(load_snapshot(transaction, header).await?),
            None => None,
        };
        if prior
            .as_ref()
            .is_some_and(|snapshot| snapshot.request.observed_at() >= request.observed_at())
        {
            return Ok(PersistGithubMembershipSnapshotOutcome::ObservationOutOfOrder);
        }
        let previous_authority = prior
            .as_ref()
            .filter(|snapshot| snapshot.request.valid_until() > request.observed_at())
            .map_or_else(EffectiveMembershipAuthority::default, |snapshot| {
                snapshot.effective_authority()
            });
        let next_authority = EffectiveMembershipAuthority::from_snapshot(request.memberships());
        let authorization_changed = previous_authority != next_authority;

        sqlx::query(
            r"
                INSERT INTO github_membership_snapshots (
                    tenant_id,id,principal_id,provider_id,provider_subject,
                    provider_token_version,observed_at_ms,valid_until_ms
                ) VALUES ($1,$2,$3,'github',$4,$5,$6,$7)
                ",
        )
        .bind(request.tenant_id().as_str())
        .bind(request.snapshot_id().as_uuid())
        .bind(request.principal_uuid())
        .bind(request.provider_subject().as_str())
        .bind(token_version)
        .bind(observed_at_ms)
        .bind(valid_until_ms)
        .execute(&mut **transaction)
        .await
        .map_err(|error| insertion_error(&error))?;
        let organization_ids: Vec<_> = request
            .memberships()
            .organizations()
            .map(|organization| organization.id().get())
            .collect();
        if !organization_ids.is_empty() {
            let organization_logins: Vec<_> = request
                .memberships()
                .organizations()
                .map(|organization| organization.login().as_str().to_owned())
                .collect();
            let membership_roles: Vec<_> = request
                .memberships()
                .organizations()
                .map(|organization| match organization.role() {
                    GithubOrganizationMembershipRole::Member => "member".to_owned(),
                    GithubOrganizationMembershipRole::Admin => "admin".to_owned(),
                })
                .collect();
            sqlx::query(
                r"
                    INSERT INTO github_organization_membership_observations (
                        tenant_id,snapshot_id,organization_id,organization_login,membership_role
                    )
                    SELECT $1,$2,observation.organization_id,
                           observation.organization_login,observation.membership_role
                    FROM UNNEST($3::BIGINT[],$4::TEXT[],$5::TEXT[]) AS observation(
                        organization_id,organization_login,membership_role
                    )
                    ",
            )
            .bind(request.tenant_id().as_str())
            .bind(request.snapshot_id().as_uuid())
            .bind(organization_ids)
            .bind(organization_logins)
            .bind(membership_roles)
            .execute(&mut **transaction)
            .await
            .map_err(|error| insertion_error(&error))?;
        }
        let team_ids: Vec<_> = request
            .memberships()
            .teams()
            .map(|team| team.id().get())
            .collect();
        if !team_ids.is_empty() {
            let organization_ids: Vec<_> = request
                .memberships()
                .teams()
                .map(|team| team.organization_id().get())
                .collect();
            let team_slugs: Vec<_> = request
                .memberships()
                .teams()
                .map(|team| team.slug().as_str().to_owned())
                .collect();
            sqlx::query(
                r"
                    INSERT INTO github_team_membership_observations (
                        tenant_id,snapshot_id,organization_id,team_id,team_slug
                    )
                    SELECT $1,$2,observation.organization_id,
                           observation.team_id,observation.team_slug
                    FROM UNNEST($3::BIGINT[],$4::BIGINT[],$5::TEXT[]) AS observation(
                        organization_id,team_id,team_slug
                    )
                    ",
            )
            .bind(request.tenant_id().as_str())
            .bind(request.snapshot_id().as_uuid())
            .bind(organization_ids)
            .bind(team_ids)
            .bind(team_slugs)
            .execute(&mut **transaction)
            .await
            .map_err(|error| insertion_error(&error))?;
        }
        let authorization_revision = if authorization_changed {
            let revision: i64 = sqlx::query_scalar(
                r"
                    UPDATE tenant_human_memberships
                    SET authorization_revision=authorization_revision+1
                    WHERE tenant_id=$1 AND principal_id=$2
                    RETURNING authorization_revision
                    ",
            )
            .bind(request.tenant_id().as_str())
            .bind(request.principal_uuid())
            .fetch_one(&mut **transaction)
            .await
            .map_err(|_| GithubMembershipRepositoryError::Unavailable)?;
            positive_revision(revision)?
        } else {
            current_authorization_revision
        };
        Ok(PersistGithubMembershipSnapshotOutcome::Stored {
            authorization_revision,
            authorization_changed,
        })
    }
}

impl GithubMembershipRepository for PostgresGithubMembershipRepository {
    fn persist<'a>(
        &'a self,
        request: &'a PersistGithubMembershipSnapshot,
    ) -> GithubMembershipPersistenceFuture<'a> {
        Box::pin(async move {
            let mut transaction = self
                .pool
                .begin()
                .await
                .map_err(|_| GithubMembershipRepositoryError::Unavailable)?;
            // Locking the exact principal, identity, tenant membership, and
            // provider token serializes refreshes for this authority. Read
            // committed lets a waiter observe the winner exactly.
            sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                .execute(&mut *transaction)
                .await
                .map_err(|_| GithubMembershipRepositoryError::Unavailable)?;
            let outcome = self
                .persist_in_transaction(&mut transaction, request)
                .await?;
            if matches!(
                outcome,
                PersistGithubMembershipSnapshotOutcome::Stored { .. }
                    | PersistGithubMembershipSnapshotOutcome::AlreadyStored { .. }
            ) {
                transaction
                    .commit()
                    .await
                    .map_err(|_| GithubMembershipRepositoryError::Unavailable)?;
            }
            Ok(outcome)
        })
    }
}
