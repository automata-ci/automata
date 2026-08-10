use std::{collections::BTreeSet, fmt};

use automata_ci_auth::{
    authorization::{
        AuthorizationContext, AuthorizationScope, RepositoryResource, RepositoryResourceId,
        RoleName, RunnerGroupResource, RunnerGroupResourceId, ScopedRoleGrant,
    },
    github::{
        GithubOrganizationId, GithubOrganizationLogin, GithubTeamId, GithubTeamSlug,
        MAX_GITHUB_MEMBERSHIP_OBSERVATIONS,
    },
    human::{AuthenticatedHuman, PrincipalId, ProviderId, ProviderSubject, TenantId},
    request_auth::{
        AuthenticatedRequestSnapshot, RequestAuthenticationFuture, RequestAuthenticationResolver,
        RequestAuthenticationResolverError, ResolveAuthenticatedRequest,
        ResolveAuthenticatedRequestOutcome, ViewerDisplayMetadata,
    },
    session::{
        CLI_SESSION_ACTIVATION_LIFETIME_SECONDS, DurableSession, DurableSessionIdentity, SessionId,
        SessionKind, SessionResolutionStatus,
    },
};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::{
    session::{database_time_milliseconds, validate_caller_time},
    support::timestamp_from_milliseconds,
};

const MAX_REQUEST_AUTHORIZATION_ROWS: usize = MAX_GITHUB_MEMBERSHIP_OBSERVATIONS;

/// `PostgreSQL` request-authentication resolver.
///
/// Every resolution takes the tenant management shared lock, locks the exact
/// session/identity authority rows, and samples `PostgreSQL` time before loading
/// grants from the same transaction.
#[derive(Clone)]
pub struct PostgresRequestAuthenticationResolver {
    pool: PgPool,
}

impl PostgresRequestAuthenticationResolver {
    /// Creates a request-authentication resolver backed by `pool`.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl fmt::Debug for PostgresRequestAuthenticationResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresRequestAuthenticationResolver")
            .finish_non_exhaustive()
    }
}

#[derive(FromRow)]
struct RequestIdentityRow {
    session_id: Uuid,
    session_tenant_id: String,
    session_principal_id: Uuid,
    session_provider_id: String,
    session_provider_subject: String,
    session_kind: String,
    session_audience: String,
    lifecycle_status: String,
    activation_deadline_ms: Option<i64>,
    activated_at_ms: Option<i64>,
    session_authorization_revision: i64,
    issued_at_ms: i64,
    last_seen_at_ms: i64,
    idle_expires_at_ms: i64,
    expires_at_ms: i64,
    revoked_at_ms: Option<i64>,
    principal_id: Option<Uuid>,
    principal_status: Option<String>,
    principal_display_name: Option<String>,
    membership_tenant_id: Option<String>,
    membership_principal_id: Option<Uuid>,
    membership_status: Option<String>,
    current_authorization_revision: Option<i64>,
    identity_principal_id: Option<Uuid>,
    identity_provider_id: Option<String>,
    identity_provider_subject: Option<String>,
    provider_login: Option<String>,
    provider_display_name: Option<String>,
    last_authenticated_at_ms: Option<i64>,
}

struct ActiveIdentity {
    session: DurableSession,
    human: AuthenticatedHuman,
    viewer: ViewerDisplayMetadata,
    tenant_id: TenantId,
    principal_id: PrincipalId,
    principal_uuid: Uuid,
}

enum IdentityClassification {
    Active(Box<ActiveIdentity>),
    Closed(ResolveAuthenticatedRequestOutcome),
}

impl RequestIdentityRow {
    fn validate_lifecycle(
        &self,
        now: automata_ci_auth::time::UnixTimestamp,
    ) -> Result<(), RequestAuthenticationResolverError> {
        match (
            self.session_kind.as_str(),
            self.session_audience.as_str(),
            self.lifecycle_status.as_str(),
            self.activation_deadline_ms,
            self.activated_at_ms,
        ) {
            ("browser", "automata.web", "active", None, None) => Ok(()),
            ("cli", "automata.cli", "active", Some(deadline_ms), Some(activated_at_ms)) => {
                let issued_at = timestamp(self.issued_at_ms)?;
                let expires_at = timestamp(self.expires_at_ms)?;
                let deadline = timestamp(deadline_ms)?;
                let activated_at = timestamp(activated_at_ms)?;
                if deadline <= issued_at
                    || deadline > expires_at
                    || deadline.as_seconds() - issued_at.as_seconds()
                        > CLI_SESSION_ACTIVATION_LIFETIME_SECONDS
                    || activated_at < issued_at
                    || activated_at >= deadline
                    || activated_at > now
                {
                    Err(RequestAuthenticationResolverError::CorruptData)
                } else {
                    Ok(())
                }
            }
            _ => Err(RequestAuthenticationResolverError::CorruptData),
        }
    }

    fn classify(
        self,
        expected_kind: SessionKind,
        now: automata_ci_auth::time::UnixTimestamp,
    ) -> Result<IdentityClassification, RequestAuthenticationResolverError> {
        self.validate_lifecycle(now)?;
        let principal_id = required(self.principal_id)?;
        let principal_status = required(self.principal_status.as_deref())?;
        let membership_tenant_id = required(self.membership_tenant_id.as_deref())?;
        let membership_principal_id = required(self.membership_principal_id)?;
        let membership_status = required(self.membership_status.as_deref())?;
        let current_revision = positive_revision(required(self.current_authorization_revision)?)?;
        let identity_principal_id = required(self.identity_principal_id)?;
        let identity_provider_id = required(self.identity_provider_id.as_deref())?;
        let identity_provider_subject = required(self.identity_provider_subject.as_deref())?;

        if principal_id != self.session_principal_id
            || membership_tenant_id != self.session_tenant_id
            || membership_principal_id != self.session_principal_id
            || identity_principal_id != self.session_principal_id
            || identity_provider_id != self.session_provider_id
            || identity_provider_subject != self.session_provider_subject
        {
            return Err(RequestAuthenticationResolverError::CorruptData);
        }

        let tenant_id = TenantId::new(self.session_tenant_id.clone())
            .map_err(|_| RequestAuthenticationResolverError::CorruptData)?;
        let durable_principal_id =
            PrincipalId::new(self.session_principal_id.hyphenated().to_string())
                .map_err(|_| RequestAuthenticationResolverError::CorruptData)?;
        let session = self.to_session(tenant_id.clone(), durable_principal_id.clone())?;
        let human = self.to_human(durable_principal_id.clone())?;
        let viewer_name = self
            .principal_display_name
            .as_deref()
            .filter(|value| !value.is_empty())
            .or_else(|| human.display_name().filter(|value| !value.is_empty()))
            .unwrap_or_else(|| human.login());
        let viewer = ViewerDisplayMetadata::new(viewer_name)
            .map_err(|_| RequestAuthenticationResolverError::CorruptData)?;

        match principal_status {
            "disabled" => {
                return Ok(IdentityClassification::Closed(
                    ResolveAuthenticatedRequestOutcome::PrincipalDisabled,
                ));
            }
            "active" => {}
            _ => return Err(RequestAuthenticationResolverError::CorruptData),
        }
        match membership_status {
            "suspended" => {
                return Ok(IdentityClassification::Closed(
                    ResolveAuthenticatedRequestOutcome::MembershipSuspended,
                ));
            }
            "active" => {}
            _ => return Err(RequestAuthenticationResolverError::CorruptData),
        }

        let closed = match session.resolution_status(expected_kind, now, current_revision) {
            SessionResolutionStatus::Active => None,
            SessionResolutionStatus::WrongKindOrAudience => {
                Some(ResolveAuthenticatedRequestOutcome::WrongKindOrAudience)
            }
            SessionResolutionStatus::Revoked => Some(ResolveAuthenticatedRequestOutcome::Revoked),
            SessionResolutionStatus::Expired => Some(ResolveAuthenticatedRequestOutcome::Expired),
            SessionResolutionStatus::NotYetValid => {
                Some(ResolveAuthenticatedRequestOutcome::NotYetValid)
            }
            SessionResolutionStatus::AuthorizationRevisionChanged {
                session_revision,
                current_revision,
            } => Some(
                ResolveAuthenticatedRequestOutcome::AuthorizationRevisionChanged {
                    session_revision,
                    current_revision,
                },
            ),
        };
        if let Some(outcome) = closed {
            return Ok(IdentityClassification::Closed(outcome));
        }

        Ok(IdentityClassification::Active(Box::new(ActiveIdentity {
            session,
            human,
            viewer,
            tenant_id,
            principal_id: durable_principal_id,
            principal_uuid: principal_id,
        })))
    }

    fn to_session(
        &self,
        tenant_id: TenantId,
        principal_id: PrincipalId,
    ) -> Result<DurableSession, RequestAuthenticationResolverError> {
        let kind = parse_kind(&self.session_kind, &self.session_audience)?;
        let identity = DurableSessionIdentity::new(
            SessionId::new(self.session_id.hyphenated().to_string())
                .map_err(|_| RequestAuthenticationResolverError::CorruptData)?,
            tenant_id,
            principal_id,
            ProviderId::new(self.session_provider_id.clone())
                .map_err(|_| RequestAuthenticationResolverError::CorruptData)?,
            ProviderSubject::new(self.session_provider_subject.clone())
                .map_err(|_| RequestAuthenticationResolverError::CorruptData)?,
            kind,
        )
        .map_err(|_| RequestAuthenticationResolverError::CorruptData)?;
        DurableSession::new(
            identity,
            positive_revision(self.session_authorization_revision)?,
            timestamp(self.issued_at_ms)?,
            timestamp(self.last_seen_at_ms)?,
            timestamp(self.idle_expires_at_ms)?,
            timestamp(self.expires_at_ms)?,
            self.revoked_at_ms.map(timestamp).transpose()?,
        )
        .map_err(|_| RequestAuthenticationResolverError::CorruptData)
    }

    fn to_human(
        &self,
        principal_id: PrincipalId,
    ) -> Result<AuthenticatedHuman, RequestAuthenticationResolverError> {
        AuthenticatedHuman::new(
            principal_id,
            ProviderId::new(required(self.identity_provider_id.clone())?)
                .map_err(|_| RequestAuthenticationResolverError::CorruptData)?,
            ProviderSubject::new(required(self.identity_provider_subject.clone())?)
                .map_err(|_| RequestAuthenticationResolverError::CorruptData)?,
            required(self.provider_login.clone())?,
            self.provider_display_name.clone(),
            timestamp(required(self.last_authenticated_at_ms)?)?,
        )
        .map_err(|_| RequestAuthenticationResolverError::CorruptData)
    }
}

fn required<T>(value: Option<T>) -> Result<T, RequestAuthenticationResolverError> {
    value.ok_or(RequestAuthenticationResolverError::CorruptData)
}

fn one_over_row_limit(maximum: usize) -> Result<i64, RequestAuthenticationResolverError> {
    maximum
        .checked_add(1)
        .and_then(|limit| i64::try_from(limit).ok())
        .ok_or(RequestAuthenticationResolverError::CorruptData)
}

fn enforce_row_limit(
    actual: usize,
    maximum: usize,
) -> Result<(), RequestAuthenticationResolverError> {
    if actual > maximum {
        return Err(RequestAuthenticationResolverError::CorruptData);
    }
    Ok(())
}

fn positive_revision(value: i64) -> Result<u64, RequestAuthenticationResolverError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(RequestAuthenticationResolverError::CorruptData)
}

fn timestamp(
    milliseconds: i64,
) -> Result<automata_ci_auth::time::UnixTimestamp, RequestAuthenticationResolverError> {
    timestamp_from_milliseconds(milliseconds)
        .map_err(|()| RequestAuthenticationResolverError::CorruptData)
}

fn parse_kind(
    kind: &str,
    audience: &str,
) -> Result<SessionKind, RequestAuthenticationResolverError> {
    match (kind, audience) {
        ("browser", "automata.web") => Ok(SessionKind::Browser),
        ("cli", "automata.cli") => Ok(SessionKind::Cli),
        _ => Err(RequestAuthenticationResolverError::CorruptData),
    }
}

const REQUEST_IDENTITY_SELECT: &str = r"
    SELECT s.id AS session_id,
           s.tenant_id AS session_tenant_id,
           s.principal_id AS session_principal_id,
           s.provider_id AS session_provider_id,
           s.provider_subject AS session_provider_subject,
           s.session_kind,
           s.audience AS session_audience,
           s.lifecycle_status,s.activation_deadline_ms,s.activated_at_ms,
           s.authorization_revision AS session_authorization_revision,
           s.issued_at_ms, s.last_seen_at_ms, s.idle_expires_at_ms,
           s.expires_at_ms, s.revoked_at_ms,
           p.id AS principal_id, p.status AS principal_status,
           p.display_name AS principal_display_name,
           m.tenant_id AS membership_tenant_id,
           m.principal_id AS membership_principal_id,
           m.status AS membership_status,
           m.authorization_revision AS current_authorization_revision,
           i.principal_id AS identity_principal_id,
           i.provider_id AS identity_provider_id,
           i.provider_subject AS identity_provider_subject,
           i.provider_login, i.display_name AS provider_display_name,
           i.last_authenticated_at_ms
    FROM human_sessions AS s
    JOIN human_principals AS p ON p.id = s.principal_id
    JOIN tenant_human_memberships AS m
      ON m.tenant_id = s.tenant_id AND m.principal_id = s.principal_id
    JOIN human_provider_identities AS i
      ON i.principal_id = s.principal_id
     AND i.provider_id = s.provider_id
     AND i.provider_subject = s.provider_subject
    WHERE s.token_hash_key_id = $1 AND s.token_hash = $2
      AND s.tenant_id = $3
      AND s.lifecycle_status = 'active'
";

#[derive(FromRow)]
struct ScopedGrantRow {
    binding_tenant_id: String,
    binding_principal_id: Uuid,
    role_tenant_id: Option<String>,
    role_name: Option<String>,
    scope_kind: String,
    repository_id: Option<Uuid>,
    repository_tenant_id: Option<String>,
    runner_group_id: Option<Uuid>,
    runner_group_tenant_id: Option<String>,
}

impl ScopedGrantRow {
    fn to_grant(
        &self,
        expected_tenant_id: &TenantId,
        expected_principal_id: Uuid,
    ) -> Result<ScopedRoleGrant, RequestAuthenticationResolverError> {
        let role_tenant_id = required(self.role_tenant_id.as_deref())?;
        let role_name = required(self.role_name.as_deref())?;
        if self.binding_tenant_id != expected_tenant_id.as_str()
            || role_tenant_id != expected_tenant_id.as_str()
            || self.binding_principal_id != expected_principal_id
        {
            return Err(RequestAuthenticationResolverError::CorruptData);
        }
        let role = RoleName::new(role_name)
            .map_err(|_| RequestAuthenticationResolverError::CorruptData)?;
        let scope = match self.scope_kind.as_str() {
            "tenant"
                if self.repository_id.is_none()
                    && self.repository_tenant_id.is_none()
                    && self.runner_group_id.is_none()
                    && self.runner_group_tenant_id.is_none() =>
            {
                AuthorizationScope::tenant(expected_tenant_id.clone())
            }
            "repository"
                if self.runner_group_id.is_none()
                    && self.runner_group_tenant_id.is_none()
                    && self.repository_tenant_id.as_deref()
                        == Some(expected_tenant_id.as_str()) =>
            {
                let repository_id = required(self.repository_id)?;
                let resource_id = RepositoryResourceId::from_uuid(repository_id)
                    .map_err(|_| RequestAuthenticationResolverError::CorruptData)?;
                AuthorizationScope::repository(RepositoryResource::new(
                    expected_tenant_id.clone(),
                    resource_id,
                ))
            }
            "runner_group"
                if self.repository_id.is_none()
                    && self.repository_tenant_id.is_none()
                    && self.runner_group_tenant_id.as_deref()
                        == Some(expected_tenant_id.as_str()) =>
            {
                let runner_group_id = required(self.runner_group_id)?;
                let resource_id = RunnerGroupResourceId::from_uuid(runner_group_id)
                    .map_err(|_| RequestAuthenticationResolverError::CorruptData)?;
                AuthorizationScope::runner_group(RunnerGroupResource::new(
                    expected_tenant_id.clone(),
                    resource_id,
                ))
            }
            _ => return Err(RequestAuthenticationResolverError::CorruptData),
        };
        Ok(ScopedRoleGrant::new(scope, role))
    }
}

const ACTIVE_GRANTS_SELECT: &str = r"
    SELECT b.tenant_id AS binding_tenant_id,
           b.principal_id AS binding_principal_id,
           r.tenant_id AS role_tenant_id,
           r.name AS role_name,
           b.scope_kind,
           b.repository_id,
           repository.tenant_id AS repository_tenant_id,
           b.runner_group_id,
           runner_group.tenant_id AS runner_group_tenant_id
    FROM rbac_role_bindings AS b
    LEFT JOIN rbac_roles AS r
      ON r.tenant_id = b.tenant_id AND r.id = b.role_id
    LEFT JOIN repositories AS repository
      ON repository.tenant_id = b.tenant_id AND repository.id = b.repository_id
    LEFT JOIN runner_groups AS runner_group
      ON runner_group.tenant_id = b.tenant_id AND runner_group.id = b.runner_group_id
    WHERE b.tenant_id = $1
      AND b.principal_id = $2
      AND b.status = 'active'
      AND (b.valid_until_ms IS NULL OR b.valid_until_ms > $3)
    LIMIT $4
";

#[derive(FromRow)]
struct CurrentGithubSnapshotHeaderRow {
    tenant_id: String,
    id: Uuid,
    principal_id: Uuid,
    provider_id: String,
    provider_subject: String,
    provider_token_version: i64,
    observed_at_ms: i64,
    valid_until_ms: i64,
    identity_principal_id: Option<Uuid>,
    identity_provider_subject: Option<String>,
}

const CURRENT_GITHUB_SNAPSHOT_SELECT: &str = r"
    SELECT snapshot.tenant_id,snapshot.id,snapshot.principal_id,
           snapshot.provider_id,snapshot.provider_subject,
           snapshot.provider_token_version,snapshot.observed_at_ms,
           snapshot.valid_until_ms,
           identity.principal_id AS identity_principal_id,
           identity.provider_subject AS identity_provider_subject
    FROM github_membership_snapshots AS snapshot
    LEFT JOIN human_provider_identities AS identity
      ON identity.principal_id=snapshot.principal_id
     AND identity.provider_id=snapshot.provider_id
     AND identity.provider_subject=snapshot.provider_subject
    WHERE snapshot.tenant_id=$1 AND snapshot.principal_id=$2
      AND snapshot.provider_id='github'
      AND snapshot.provider_subject=$3
      AND snapshot.observed_at_ms <= $4
    ORDER BY snapshot.observed_at_ms DESC,snapshot.id DESC
    LIMIT 2
";

#[derive(FromRow)]
struct GithubObservationSummaryRow {
    observation_count: i64,
    observations_valid: bool,
}

const CURRENT_GITHUB_OBSERVATION_SUMMARY_SELECT: &str = r"
    WITH bounded_observations AS (
        SELECT 1::SMALLINT AS observation_kind,
               organization_id AS observation_id,
               organization_login,
               NULL::BIGINT AS team_organization_id,
               NULL::TEXT AS team_slug,
               (
                   organization_id > 0
                   AND octet_length(organization_login) BETWEEN 1 AND 255
                   AND organization_login !~ '[^A-Za-z0-9_-]'
                   AND membership_role IN ('member', 'admin')
               ) AS observation_valid
        FROM github_organization_membership_observations
        WHERE tenant_id=$1 AND snapshot_id=$2
        UNION ALL
        SELECT 2::SMALLINT AS observation_kind,
               team.team_id AS observation_id,
               NULL::TEXT AS organization_login,
               team.organization_id AS team_organization_id,
               team.team_slug,
               (
                   team.organization_id > 0
                   AND team.team_id > 0
                   AND octet_length(team.team_slug) BETWEEN 1 AND 255
                   AND team.team_slug !~ '[^A-Za-z0-9_-]'
                   AND organization.organization_id IS NOT NULL
               ) AS observation_valid
        FROM github_team_membership_observations AS team
        LEFT JOIN github_organization_membership_observations AS organization
          ON organization.tenant_id=team.tenant_id
         AND organization.snapshot_id=team.snapshot_id
         AND organization.organization_id=team.organization_id
        WHERE team.tenant_id=$1 AND team.snapshot_id=$2
        LIMIT $3
    )
    SELECT COUNT(*) AS observation_count,
           (
               COALESCE(BOOL_AND(observation_valid IS TRUE), TRUE)
               AND COUNT(*) = COUNT(DISTINCT (observation_kind, observation_id))
               AND COUNT(*) FILTER (WHERE observation_kind = 1)
                   = COUNT(DISTINCT lower(organization_login))
                     FILTER (WHERE observation_kind = 1)
               AND COUNT(*) FILTER (WHERE observation_kind = 2)
                   = COUNT(DISTINCT (team_organization_id, lower(team_slug)))
                     FILTER (WHERE observation_kind = 2)
           ) AS observations_valid
    FROM bounded_observations
";

fn current_github_snapshot_is_active(
    headers: &[CurrentGithubSnapshotHeaderRow],
    tenant_id: &TenantId,
    principal_id: Uuid,
    provider_subject: &ProviderSubject,
    now_ms: i64,
) -> Result<bool, RequestAuthenticationResolverError> {
    let header = headers
        .first()
        .ok_or(RequestAuthenticationResolverError::CorruptData)?;
    if headers
        .get(1)
        .is_some_and(|other| other.observed_at_ms == header.observed_at_ms)
        || header.tenant_id != tenant_id.as_str()
        || header.principal_id != principal_id
        || header.provider_id != "github"
        || header.provider_subject != provider_subject.as_str()
        || header.id.is_nil()
        || header.provider_token_version <= 0
        || header.identity_principal_id != Some(principal_id)
        || header.identity_provider_subject.as_deref() != Some(header.provider_subject.as_str())
    {
        return Err(RequestAuthenticationResolverError::CorruptData);
    }
    let provider_subject = header
        .provider_subject
        .parse::<u64>()
        .ok()
        .filter(|subject| *subject > 0)
        .ok_or(RequestAuthenticationResolverError::CorruptData)?;
    if provider_subject.to_string() != header.provider_subject {
        return Err(RequestAuthenticationResolverError::CorruptData);
    }
    let observed_at = timestamp(header.observed_at_ms)?;
    let valid_until = timestamp(header.valid_until_ms)?;
    if header.observed_at_ms > now_ms || valid_until <= observed_at {
        return Err(RequestAuthenticationResolverError::CorruptData);
    }
    Ok(header.valid_until_ms > now_ms)
}

fn validate_github_observation_summary(
    summary: &GithubObservationSummaryRow,
) -> Result<(), RequestAuthenticationResolverError> {
    let observation_count = usize::try_from(summary.observation_count)
        .map_err(|_| RequestAuthenticationResolverError::CorruptData)?;
    enforce_row_limit(observation_count, MAX_GITHUB_MEMBERSHIP_OBSERVATIONS)?;
    if !summary.observations_valid {
        return Err(RequestAuthenticationResolverError::CorruptData);
    }
    Ok(())
}

async fn load_current_github_snapshot(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &TenantId,
    principal_id: Uuid,
    provider_subject: &ProviderSubject,
    now_ms: i64,
) -> Result<Option<Uuid>, RequestAuthenticationResolverError> {
    let headers =
        sqlx::query_as::<_, CurrentGithubSnapshotHeaderRow>(CURRENT_GITHUB_SNAPSHOT_SELECT)
            .bind(tenant_id.as_str())
            .bind(principal_id)
            .bind(provider_subject.as_str())
            .bind(now_ms)
            .fetch_all(&mut **transaction)
            .await
            .map_err(|_| RequestAuthenticationResolverError::Unavailable)?;
    let Some(header) = headers.first() else {
        return Ok(None);
    };
    if !current_github_snapshot_is_active(
        &headers,
        tenant_id,
        principal_id,
        provider_subject,
        now_ms,
    )? {
        return Ok(None);
    }
    let summary =
        sqlx::query_as::<_, GithubObservationSummaryRow>(CURRENT_GITHUB_OBSERVATION_SUMMARY_SELECT)
            .bind(tenant_id.as_str())
            .bind(header.id)
            .bind(one_over_row_limit(MAX_GITHUB_MEMBERSHIP_OBSERVATIONS)?)
            .fetch_one(&mut **transaction)
            .await
            .map_err(|_| RequestAuthenticationResolverError::Unavailable)?;
    validate_github_observation_summary(&summary)?;
    Ok(Some(header.id))
}

#[derive(FromRow)]
struct GithubMappingGrantRow {
    mapping_tenant_id: String,
    mapping_id: Uuid,
    provider_id: String,
    organization_id: i64,
    organization_login: String,
    team_id: Option<i64>,
    team_slug: Option<String>,
    role_id: Option<Uuid>,
    role_tenant_id: Option<String>,
    role_name: Option<String>,
    scope_kind: String,
    repository_id: Option<Uuid>,
    repository_tenant_id: Option<String>,
    runner_group_id: Option<Uuid>,
    runner_group_tenant_id: Option<String>,
}

impl GithubMappingGrantRow {
    fn to_grant(
        &self,
        expected_tenant_id: &TenantId,
        expected_principal_id: Uuid,
    ) -> Result<ScopedRoleGrant, RequestAuthenticationResolverError> {
        if self.mapping_tenant_id != expected_tenant_id.as_str()
            || self.mapping_id.is_nil()
            || self.provider_id != "github"
            || required(self.role_id)?.is_nil()
        {
            return Err(RequestAuthenticationResolverError::CorruptData);
        }
        GithubOrganizationId::new(self.organization_id)
            .map_err(|_| RequestAuthenticationResolverError::CorruptData)?;
        GithubOrganizationLogin::new(self.organization_login.clone())
            .map_err(|_| RequestAuthenticationResolverError::CorruptData)?;
        match (self.team_id, self.team_slug.as_deref()) {
            (None, None) => {}
            (Some(team_id), Some(team_slug)) => {
                GithubTeamId::new(team_id)
                    .map_err(|_| RequestAuthenticationResolverError::CorruptData)?;
                GithubTeamSlug::new(team_slug)
                    .map_err(|_| RequestAuthenticationResolverError::CorruptData)?;
            }
            _ => return Err(RequestAuthenticationResolverError::CorruptData),
        }
        ScopedGrantRow {
            binding_tenant_id: self.mapping_tenant_id.clone(),
            binding_principal_id: expected_principal_id,
            role_tenant_id: self.role_tenant_id.clone(),
            role_name: self.role_name.clone(),
            scope_kind: self.scope_kind.clone(),
            repository_id: self.repository_id,
            repository_tenant_id: self.repository_tenant_id.clone(),
            runner_group_id: self.runner_group_id,
            runner_group_tenant_id: self.runner_group_tenant_id.clone(),
        }
        .to_grant(expected_tenant_id, expected_principal_id)
    }
}

const ACTIVE_GITHUB_MAPPINGS_SELECT: &str = r"
    WITH matching_mappings AS (
        SELECT mapping.*
        FROM github_organization_membership_observations AS observation
        JOIN github_role_mappings AS mapping
          ON mapping.tenant_id=observation.tenant_id
         AND mapping.provider_id='github'
         AND mapping.organization_id=observation.organization_id
         AND mapping.team_id IS NULL
         AND mapping.status='active'
        WHERE observation.tenant_id=$1 AND observation.snapshot_id=$2
        UNION ALL
        SELECT mapping.*
        FROM github_team_membership_observations AS observation
        JOIN github_role_mappings AS mapping
          ON mapping.tenant_id=observation.tenant_id
         AND mapping.provider_id='github'
         AND mapping.organization_id=observation.organization_id
         AND mapping.team_id=observation.team_id
         AND mapping.status='active'
        WHERE observation.tenant_id=$1 AND observation.snapshot_id=$2
    )
    SELECT mapping.tenant_id AS mapping_tenant_id,
           mapping.id AS mapping_id,
           mapping.provider_id,
           mapping.organization_id,
           mapping.organization_login,
           mapping.team_id,
           mapping.team_slug,
           role.id AS role_id,
           role.tenant_id AS role_tenant_id,
           role.name AS role_name,
           mapping.scope_kind,
           mapping.repository_id,
           repository.tenant_id AS repository_tenant_id,
           mapping.runner_group_id,
           runner_group.tenant_id AS runner_group_tenant_id
    FROM matching_mappings AS mapping
    LEFT JOIN rbac_roles AS role
      ON role.tenant_id=mapping.tenant_id AND role.id=mapping.role_id
    LEFT JOIN repositories AS repository
      ON repository.tenant_id=mapping.tenant_id
     AND repository.id=mapping.repository_id
    LEFT JOIN runner_groups AS runner_group
      ON runner_group.tenant_id=mapping.tenant_id
     AND runner_group.id=mapping.runner_group_id
    LIMIT $3
";

// Request authentication runs before the router resolves a trusted resource, so
// direct grants must remain complete here. GitHub mappings can still be scoped
// safely to the principal's exact current numeric membership snapshot.
async fn load_request_authorization_grants(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    active: &ActiveIdentity,
    now_ms: i64,
) -> Result<BTreeSet<ScopedRoleGrant>, RequestAuthenticationResolverError> {
    let rows = sqlx::query_as::<_, ScopedGrantRow>(ACTIVE_GRANTS_SELECT)
        .bind(active.tenant_id.as_str())
        .bind(active.principal_uuid)
        .bind(now_ms)
        .bind(one_over_row_limit(MAX_REQUEST_AUTHORIZATION_ROWS)?)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|_| RequestAuthenticationResolverError::Unavailable)?;
    enforce_row_limit(rows.len(), MAX_REQUEST_AUTHORIZATION_ROWS)?;
    let mut grants = BTreeSet::new();
    for row in rows {
        let grant = row.to_grant(&active.tenant_id, active.principal_uuid)?;
        if !grants.insert(grant) {
            return Err(RequestAuthenticationResolverError::CorruptData);
        }
    }
    if active.human.provider_id().as_str() != "github" {
        return Ok(grants);
    }
    if let Some(snapshot_id) = load_current_github_snapshot(
        transaction,
        &active.tenant_id,
        active.principal_uuid,
        active.human.provider_subject(),
        now_ms,
    )
    .await?
    {
        let remaining_rows = MAX_REQUEST_AUTHORIZATION_ROWS
            .checked_sub(grants.len())
            .ok_or(RequestAuthenticationResolverError::CorruptData)?;
        let mappings = sqlx::query_as::<_, GithubMappingGrantRow>(ACTIVE_GITHUB_MAPPINGS_SELECT)
            .bind(active.tenant_id.as_str())
            .bind(snapshot_id)
            .bind(one_over_row_limit(remaining_rows)?)
            .fetch_all(&mut **transaction)
            .await
            .map_err(|_| RequestAuthenticationResolverError::Unavailable)?;
        enforce_row_limit(mappings.len(), remaining_rows)?;
        for mapping in mappings {
            grants.insert(mapping.to_grant(&active.tenant_id, active.principal_uuid)?);
        }
    }
    Ok(grants)
}

async fn lock_request_authority(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request: &ResolveAuthenticatedRequest,
    tenant_id: &str,
) -> Result<bool, RequestAuthenticationResolverError> {
    // Canonical order after the tenant advisory lock: session, principal,
    // provider identity, membership. Explicit statements keep the order
    // independent of PostgreSQL join planning.
    let locked_session: Option<(Uuid, Uuid, String, String, String)> = sqlx::query_as(
        r"
        SELECT id,principal_id,provider_id,provider_subject,tenant_id
        FROM human_sessions
        WHERE token_hash_key_id=$1 AND token_hash=$2
        FOR SHARE
        ",
    )
    .bind(request.lookup().key_id().as_str())
    .bind(request.lookup().digest().as_bytes().as_slice())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| RequestAuthenticationResolverError::Unavailable)?;
    let Some((_, principal_id, provider_id, provider_subject, locked_tenant_id)) = locked_session
    else {
        return Ok(false);
    };
    if locked_tenant_id != tenant_id {
        return Err(RequestAuthenticationResolverError::CorruptData);
    }
    let locked_principal: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM human_principals WHERE id=$1 FOR SHARE")
            .bind(principal_id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|_| RequestAuthenticationResolverError::Unavailable)?;
    if locked_principal != Some(principal_id) {
        return Ok(false);
    }
    let locked_identity: Option<Uuid> = sqlx::query_scalar(
        r"
        SELECT principal_id FROM human_provider_identities
        WHERE principal_id=$1 AND provider_id=$2 AND provider_subject=$3
        FOR SHARE
        ",
    )
    .bind(principal_id)
    .bind(&provider_id)
    .bind(&provider_subject)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| RequestAuthenticationResolverError::Unavailable)?;
    if locked_identity != Some(principal_id) {
        return Ok(false);
    }
    let locked_membership: Option<Uuid> = sqlx::query_scalar(
        r"
        SELECT principal_id FROM tenant_human_memberships
        WHERE tenant_id=$1 AND principal_id=$2
        FOR SHARE
        ",
    )
    .bind(tenant_id)
    .bind(principal_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| RequestAuthenticationResolverError::Unavailable)?;
    Ok(locked_membership == Some(principal_id))
}

impl RequestAuthenticationResolver for PostgresRequestAuthenticationResolver {
    fn resolve<'a>(
        &'a self,
        request: &'a ResolveAuthenticatedRequest,
    ) -> RequestAuthenticationFuture<'a> {
        Box::pin(async move {
            let mut transaction = self
                .pool
                .begin()
                .await
                .map_err(|_| RequestAuthenticationResolverError::Unavailable)?;
            sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                .execute(&mut *transaction)
                .await
                .map_err(|_| RequestAuthenticationResolverError::Unavailable)?;

            let tenant_id: Option<String> = sqlx::query_scalar(
                r"
                SELECT tenant_id
                FROM human_sessions
                WHERE token_hash_key_id = $1 AND token_hash = $2
                ",
            )
            .bind(request.lookup().key_id().as_str())
            .bind(request.lookup().digest().as_bytes().as_slice())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| RequestAuthenticationResolverError::Unavailable)?;
            let Some(tenant_id) = tenant_id else {
                transaction
                    .commit()
                    .await
                    .map_err(|_| RequestAuthenticationResolverError::Unavailable)?;
                return Ok(ResolveAuthenticatedRequestOutcome::NotFound);
            };
            TenantId::new(tenant_id.clone())
                .map_err(|_| RequestAuthenticationResolverError::CorruptData)?;
            sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 731662009))")
                .bind(&tenant_id)
                .execute(&mut *transaction)
                .await
                .map_err(|_| RequestAuthenticationResolverError::Unavailable)?;

            if !lock_request_authority(&mut transaction, request, &tenant_id).await? {
                return Ok(ResolveAuthenticatedRequestOutcome::NotFound);
            }

            let row = sqlx::query_as::<_, RequestIdentityRow>(REQUEST_IDENTITY_SELECT)
                .bind(request.lookup().key_id().as_str())
                .bind(request.lookup().digest().as_bytes().as_slice())
                .bind(&tenant_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| RequestAuthenticationResolverError::Unavailable)?;
            let Some(row) = row else {
                transaction
                    .commit()
                    .await
                    .map_err(|_| RequestAuthenticationResolverError::Unavailable)?;
                return Ok(ResolveAuthenticatedRequestOutcome::NotFound);
            };

            let database_time_ms = database_time_milliseconds(&mut transaction)
                .await
                .map_err(|_| RequestAuthenticationResolverError::Unavailable)?;
            let database_time = validate_caller_time(request.now(), database_time_ms)
                .map_err(|()| RequestAuthenticationResolverError::InvalidRequest)?;

            let active = match row.classify(request.expected_kind(), database_time)? {
                IdentityClassification::Closed(outcome) => {
                    transaction
                        .commit()
                        .await
                        .map_err(|_| RequestAuthenticationResolverError::Unavailable)?;
                    return Ok(outcome);
                }
                IdentityClassification::Active(active) => *active,
            };
            let grants =
                load_request_authorization_grants(&mut transaction, &active, database_time_ms)
                    .await?;
            let authorization_revision = active.session.authorization_revision();
            let authorization = AuthorizationContext::authenticated_at_revision(
                active.tenant_id,
                active.principal_id,
                grants,
                authorization_revision,
            )
            .map_err(|_| RequestAuthenticationResolverError::CorruptData)?;
            let snapshot = AuthenticatedRequestSnapshot::new(
                active.session,
                active.human,
                active.viewer,
                authorization,
            )
            .map_err(|_| RequestAuthenticationResolverError::CorruptData)?;
            transaction
                .commit()
                .await
                .map_err(|_| RequestAuthenticationResolverError::Unavailable)?;
            Ok(ResolveAuthenticatedRequestOutcome::Authenticated(Box::new(
                snapshot,
            )))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_authorization_row_budget_is_exact_and_uses_one_over_queries() {
        assert_eq!(
            one_over_row_limit(MAX_REQUEST_AUTHORIZATION_ROWS),
            Ok(100_001)
        );
        assert_eq!(
            enforce_row_limit(
                MAX_REQUEST_AUTHORIZATION_ROWS,
                MAX_REQUEST_AUTHORIZATION_ROWS
            ),
            Ok(())
        );
        assert_eq!(
            enforce_row_limit(
                MAX_REQUEST_AUTHORIZATION_ROWS + 1,
                MAX_REQUEST_AUTHORIZATION_ROWS
            ),
            Err(RequestAuthenticationResolverError::CorruptData)
        );
        assert!(ACTIVE_GRANTS_SELECT.contains("LIMIT $4"));
        assert!(CURRENT_GITHUB_OBSERVATION_SUMMARY_SELECT.contains("LIMIT $3"));
        assert!(
            CURRENT_GITHUB_OBSERVATION_SUMMARY_SELECT
                .contains("BOOL_AND(observation_valid IS TRUE)")
        );
        assert!(ACTIVE_GITHUB_MAPPINGS_SELECT.contains("LIMIT $3"));

        let exact = GithubObservationSummaryRow {
            observation_count: i64::try_from(MAX_GITHUB_MEMBERSHIP_OBSERVATIONS)
                .expect("observation limit fits BIGINT"),
            observations_valid: true,
        };
        assert_eq!(validate_github_observation_summary(&exact), Ok(()));
        let one_over = GithubObservationSummaryRow {
            observation_count: exact.observation_count + 1,
            observations_valid: true,
        };
        assert_eq!(
            validate_github_observation_summary(&one_over),
            Err(RequestAuthenticationResolverError::CorruptData)
        );
        let invalid = GithubObservationSummaryRow {
            observation_count: 1,
            observations_valid: false,
        };
        assert_eq!(
            validate_github_observation_summary(&invalid),
            Err(RequestAuthenticationResolverError::CorruptData)
        );
    }

    #[test]
    fn github_snapshot_must_bind_the_session_provider_subject() {
        assert!(CURRENT_GITHUB_SNAPSHOT_SELECT.contains("snapshot.provider_subject=$3"));
        let tenant_id = TenantId::new("tenant-a").expect("tenant");
        let principal_id =
            Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("principal");
        let provider_subject = ProviderSubject::new("42").expect("provider subject");
        let mut header = CurrentGithubSnapshotHeaderRow {
            tenant_id: "tenant-a".to_owned(),
            id: Uuid::new_v4(),
            principal_id,
            provider_id: "github".to_owned(),
            provider_subject: "42".to_owned(),
            provider_token_version: 1,
            observed_at_ms: 100_000,
            valid_until_ms: 300_000,
            identity_principal_id: Some(principal_id),
            identity_provider_subject: Some("42".to_owned()),
        };
        assert_eq!(
            current_github_snapshot_is_active(
                std::slice::from_ref(&header),
                &tenant_id,
                principal_id,
                &provider_subject,
                150_000,
            ),
            Ok(true)
        );

        header.provider_subject = "43".to_owned();
        header.identity_provider_subject = Some("43".to_owned());
        assert_eq!(
            current_github_snapshot_is_active(
                &[header],
                &tenant_id,
                principal_id,
                &provider_subject,
                150_000,
            ),
            Err(RequestAuthenticationResolverError::CorruptData)
        );
    }

    fn row(scope_kind: &str) -> ScopedGrantRow {
        ScopedGrantRow {
            binding_tenant_id: "tenant-a".to_owned(),
            binding_principal_id: Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
                .expect("principal"),
            role_tenant_id: Some("tenant-a".to_owned()),
            role_name: Some("viewer".to_owned()),
            scope_kind: scope_kind.to_owned(),
            repository_id: None,
            repository_tenant_id: None,
            runner_group_id: None,
            runner_group_tenant_id: None,
        }
    }

    fn parse(row: &ScopedGrantRow) -> Result<ScopedRoleGrant, RequestAuthenticationResolverError> {
        row.to_grant(
            &TenantId::new("tenant-a").expect("tenant"),
            Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("principal"),
        )
    }

    #[test]
    fn tenant_repository_and_runner_group_shapes_are_exact() {
        assert!(parse(&row("tenant")).is_ok());

        let mut repository = row("repository");
        repository.repository_id =
            Some(Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").expect("repository"));
        repository.repository_tenant_id = Some("tenant-a".to_owned());
        assert!(matches!(
            parse(&repository).expect("repository").scope(),
            AuthorizationScope::Repository { .. }
        ));
        repository.runner_group_id = Some(Uuid::new_v4());
        assert_eq!(
            parse(&repository),
            Err(RequestAuthenticationResolverError::CorruptData)
        );

        let mut runner_group = row("runner_group");
        runner_group.runner_group_id =
            Some(Uuid::parse_str("cccccccc-cccc-4ccc-8ccc-cccccccccccc").expect("runner group"));
        runner_group.runner_group_tenant_id = Some("tenant-a".to_owned());
        assert!(matches!(
            parse(&runner_group).expect("runner group").scope(),
            AuthorizationScope::RunnerGroup { .. }
        ));
        runner_group.repository_id = Some(Uuid::new_v4());
        assert_eq!(
            parse(&runner_group),
            Err(RequestAuthenticationResolverError::CorruptData)
        );
    }

    #[test]
    fn cross_tenant_nil_resource_and_malformed_role_rows_fail_closed() {
        let mut cross_tenant = row("repository");
        cross_tenant.repository_id = Some(Uuid::new_v4());
        cross_tenant.repository_tenant_id = Some("tenant-b".to_owned());
        assert_eq!(
            parse(&cross_tenant),
            Err(RequestAuthenticationResolverError::CorruptData)
        );

        let mut nil_resource = row("runner_group");
        nil_resource.runner_group_id = Some(Uuid::nil());
        nil_resource.runner_group_tenant_id = Some("tenant-a".to_owned());
        assert_eq!(
            parse(&nil_resource),
            Err(RequestAuthenticationResolverError::CorruptData)
        );

        let mut invalid_role = row("tenant");
        invalid_role.role_name = Some("administrator bypass!".to_owned());
        assert_eq!(
            parse(&invalid_role),
            Err(RequestAuthenticationResolverError::CorruptData)
        );

        let mut missing_role = row("tenant");
        missing_role.role_name = None;
        assert_eq!(
            parse(&missing_role),
            Err(RequestAuthenticationResolverError::CorruptData)
        );
    }

    fn mapping(team_id: Option<i64>) -> GithubMappingGrantRow {
        GithubMappingGrantRow {
            mapping_tenant_id: "tenant-a".to_owned(),
            mapping_id: Uuid::new_v4(),
            provider_id: "github".to_owned(),
            organization_id: 10,
            organization_login: "old-name".to_owned(),
            team_id,
            team_slug: team_id.map(|_| "old-slug".to_owned()),
            role_id: Some(Uuid::new_v4()),
            role_tenant_id: Some("tenant-a".to_owned()),
            role_name: Some("viewer".to_owned()),
            scope_kind: "tenant".to_owned(),
            repository_id: None,
            repository_tenant_id: None,
            runner_group_id: None,
            runner_group_tenant_id: None,
        }
    }

    fn parse_mapping(
        row: &GithubMappingGrantRow,
    ) -> Result<ScopedRoleGrant, RequestAuthenticationResolverError> {
        row.to_grant(
            &TenantId::new("tenant-a").expect("tenant"),
            Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("principal"),
        )
    }

    #[test]
    fn mappings_are_snapshot_scoped_by_numeric_ids_and_validate_joined_rows() {
        assert!(parse_mapping(&mapping(None)).is_ok());
        assert!(parse_mapping(&mapping(Some(20))).is_ok());
        assert!(
            ACTIVE_GITHUB_MAPPINGS_SELECT
                .contains("FROM github_organization_membership_observations AS observation")
        );
        assert!(
            ACTIVE_GITHUB_MAPPINGS_SELECT
                .contains("FROM github_team_membership_observations AS observation")
        );
        assert!(ACTIVE_GITHUB_MAPPINGS_SELECT.contains("observation.snapshot_id=$2"));
        assert!(
            ACTIVE_GITHUB_MAPPINGS_SELECT
                .contains("mapping.organization_id=observation.organization_id")
        );
        assert!(ACTIVE_GITHUB_MAPPINGS_SELECT.contains("mapping.team_id=observation.team_id"));

        let mut invalid_organization = mapping(None);
        invalid_organization.organization_id = 0;
        assert_eq!(
            parse_mapping(&invalid_organization),
            Err(RequestAuthenticationResolverError::CorruptData)
        );
        let mut invalid_team = mapping(Some(0));
        invalid_team.team_slug = Some("maintainers".to_owned());
        assert_eq!(
            parse_mapping(&invalid_team),
            Err(RequestAuthenticationResolverError::CorruptData)
        );
        let mut mismatched_team_shape = mapping(None);
        mismatched_team_shape.team_slug = Some("maintainers".to_owned());
        assert_eq!(
            parse_mapping(&mismatched_team_shape),
            Err(RequestAuthenticationResolverError::CorruptData)
        );

        let mut missing_role = mapping(None);
        missing_role.role_id = None;
        assert_eq!(
            parse_mapping(&missing_role),
            Err(RequestAuthenticationResolverError::CorruptData)
        );
        let mut missing_repository_parent = mapping(None);
        missing_repository_parent.scope_kind = "repository".to_owned();
        missing_repository_parent.repository_id = Some(Uuid::new_v4());
        assert_eq!(
            parse_mapping(&missing_repository_parent),
            Err(RequestAuthenticationResolverError::CorruptData)
        );
        let mut cross_tenant_runner_parent = mapping(None);
        cross_tenant_runner_parent.scope_kind = "runner_group".to_owned();
        cross_tenant_runner_parent.runner_group_id = Some(Uuid::new_v4());
        cross_tenant_runner_parent.runner_group_tenant_id = Some("tenant-b".to_owned());
        assert_eq!(
            parse_mapping(&cross_tenant_runner_parent),
            Err(RequestAuthenticationResolverError::CorruptData)
        );
    }
}
