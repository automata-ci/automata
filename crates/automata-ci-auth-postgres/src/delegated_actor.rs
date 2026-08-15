use std::{collections::BTreeSet, fmt};

use automata_ci_auth::{
    authorization::{
        AuthorizationContext, AuthorizationScope, RepositoryResource, RepositoryResourceId,
        RoleName, RunnerGroupResource, RunnerGroupResourceId, ScopedRoleGrant,
    },
    delegated_actor::{
        DelegatedActorRequestSnapshot, DelegatedActorResolutionFuture, DelegatedActorResolver,
        DelegatedActorResolverError, ResolveDelegatedActorOutcome, ResolveDelegatedActorRequest,
    },
    human::{PrincipalId, TenantId},
    request_auth::ViewerDisplayMetadata,
};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use super::session::database_time_milliseconds;

const MAX_DELEGATED_ACTOR_ROLE_GRANTS: usize = 10_000;

/// `PostgreSQL` resolver for externally delegated actor identities.
///
/// The external assertion is only identity evidence. This adapter always reloads
/// the Core-owned principal, current workspace membership, authorization
/// revision, and direct scoped role grants in one transaction.
#[derive(Clone)]
pub struct PostgresDelegatedActorResolver {
    pool: PgPool,
}

impl PostgresDelegatedActorResolver {
    /// Creates a delegated-actor resolver backed by `pool`.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl fmt::Debug for PostgresDelegatedActorResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresDelegatedActorResolver")
            .finish_non_exhaustive()
    }
}

#[derive(FromRow)]
struct IdentityRow {
    issuer: String,
    subject: Uuid,
    principal_id: Uuid,
    display_name: String,
    principal_status: String,
}

#[derive(FromRow)]
struct MembershipRow {
    tenant_id: String,
    principal_id: Uuid,
    status: String,
    authorization_revision: i64,
}

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
    ) -> Result<ScopedRoleGrant, DelegatedActorResolverError> {
        let role_tenant_id = self
            .role_tenant_id
            .as_deref()
            .ok_or(DelegatedActorResolverError::CorruptData)?;
        let role_name = self
            .role_name
            .as_deref()
            .ok_or(DelegatedActorResolverError::CorruptData)?;
        if self.binding_tenant_id != expected_tenant_id.as_str()
            || role_tenant_id != expected_tenant_id.as_str()
            || self.binding_principal_id != expected_principal_id
        {
            return Err(DelegatedActorResolverError::CorruptData);
        }
        let role =
            RoleName::new(role_name).map_err(|_| DelegatedActorResolverError::CorruptData)?;
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
                let repository_id = self
                    .repository_id
                    .ok_or(DelegatedActorResolverError::CorruptData)?;
                let resource_id = RepositoryResourceId::from_uuid(repository_id)
                    .map_err(|_| DelegatedActorResolverError::CorruptData)?;
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
                let runner_group_id = self
                    .runner_group_id
                    .ok_or(DelegatedActorResolverError::CorruptData)?;
                let resource_id = RunnerGroupResourceId::from_uuid(runner_group_id)
                    .map_err(|_| DelegatedActorResolverError::CorruptData)?;
                AuthorizationScope::runner_group(RunnerGroupResource::new(
                    expected_tenant_id.clone(),
                    resource_id,
                ))
            }
            _ => return Err(DelegatedActorResolverError::CorruptData),
        };
        Ok(ScopedRoleGrant::new(scope, role))
    }
}

const IDENTITY_SELECT: &str = r"
    SELECT identity.issuer, identity.subject, identity.principal_id,
           identity.display_name, principal.status AS principal_status
    FROM delegated_actor_identities AS identity
    JOIN human_principals AS principal ON principal.id = identity.principal_id
    WHERE identity.issuer = $1 AND identity.subject = $2
    FOR SHARE OF identity, principal
";

const MEMBERSHIP_SELECT: &str = r"
    SELECT tenant_id, principal_id, status, authorization_revision
    FROM tenant_human_memberships
    WHERE tenant_id = $1 AND principal_id = $2
    FOR SHARE
";

const ACTIVE_GRANTS_SELECT: &str = r"
    SELECT binding.tenant_id AS binding_tenant_id,
           binding.principal_id AS binding_principal_id,
           role.tenant_id AS role_tenant_id,
           role.name AS role_name,
           binding.scope_kind,
           binding.repository_id,
           repository.tenant_id AS repository_tenant_id,
           binding.runner_group_id,
           runner_group.tenant_id AS runner_group_tenant_id
    FROM rbac_role_bindings AS binding
    LEFT JOIN rbac_roles AS role
      ON role.tenant_id = binding.tenant_id AND role.id = binding.role_id
    LEFT JOIN repositories AS repository
      ON repository.tenant_id = binding.tenant_id
     AND repository.id = binding.repository_id
    LEFT JOIN runner_groups AS runner_group
      ON runner_group.tenant_id = binding.tenant_id
     AND runner_group.id = binding.runner_group_id
    WHERE binding.tenant_id = $1
      AND binding.principal_id = $2
      AND binding.status = 'active'
      AND (binding.valid_until_ms IS NULL OR binding.valid_until_ms > $3)
    LIMIT $4
";

async fn commit(
    transaction: sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), DelegatedActorResolverError> {
    transaction
        .commit()
        .await
        .map_err(|_| DelegatedActorResolverError::Unavailable)
}

fn row_limit_plus_one() -> Result<i64, DelegatedActorResolverError> {
    i64::try_from(MAX_DELEGATED_ACTOR_ROLE_GRANTS + 1)
        .map_err(|_| DelegatedActorResolverError::CorruptData)
}

impl DelegatedActorResolver for PostgresDelegatedActorResolver {
    #[allow(clippy::too_many_lines)]
    fn resolve<'a>(
        &'a self,
        request: &'a ResolveDelegatedActorRequest,
    ) -> DelegatedActorResolutionFuture<'a> {
        Box::pin(async move {
            let mut transaction = self
                .pool
                .begin()
                .await
                .map_err(|_| DelegatedActorResolverError::Unavailable)?;
            sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 731662009))")
                .bind(request.tenant_id().as_str())
                .execute(&mut *transaction)
                .await
                .map_err(|_| DelegatedActorResolverError::Unavailable)?;

            let identity = sqlx::query_as::<_, IdentityRow>(IDENTITY_SELECT)
                .bind(request.assertion().issuer())
                .bind(request.assertion().subject())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| DelegatedActorResolverError::Unavailable)?;
            let Some(identity) = identity else {
                commit(transaction).await?;
                return Ok(ResolveDelegatedActorOutcome::NotFound);
            };
            if identity.issuer != request.assertion().issuer()
                || identity.subject != request.assertion().subject()
                || identity.principal_id.is_nil()
            {
                return Err(DelegatedActorResolverError::CorruptData);
            }
            match identity.principal_status.as_str() {
                "active" => {}
                "disabled" => {
                    commit(transaction).await?;
                    return Ok(ResolveDelegatedActorOutcome::PrincipalDisabled);
                }
                _ => return Err(DelegatedActorResolverError::CorruptData),
            }

            let membership = sqlx::query_as::<_, MembershipRow>(MEMBERSHIP_SELECT)
                .bind(request.tenant_id().as_str())
                .bind(identity.principal_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| DelegatedActorResolverError::Unavailable)?;
            let Some(membership) = membership else {
                commit(transaction).await?;
                return Ok(ResolveDelegatedActorOutcome::NotFound);
            };
            if membership.tenant_id != request.tenant_id().as_str()
                || membership.principal_id != identity.principal_id
            {
                return Err(DelegatedActorResolverError::CorruptData);
            }
            match membership.status.as_str() {
                "active" => {}
                "suspended" => {
                    commit(transaction).await?;
                    return Ok(ResolveDelegatedActorOutcome::MembershipSuspended);
                }
                _ => return Err(DelegatedActorResolverError::CorruptData),
            }
            let authorization_revision = u64::try_from(membership.authorization_revision)
                .ok()
                .filter(|revision| *revision > 0)
                .ok_or(DelegatedActorResolverError::CorruptData)?;
            let database_time_ms = database_time_milliseconds(&mut transaction)
                .await
                .map_err(|_| DelegatedActorResolverError::Unavailable)?;
            let rows = sqlx::query_as::<_, ScopedGrantRow>(ACTIVE_GRANTS_SELECT)
                .bind(request.tenant_id().as_str())
                .bind(identity.principal_id)
                .bind(database_time_ms)
                .bind(row_limit_plus_one()?)
                .fetch_all(&mut *transaction)
                .await
                .map_err(|_| DelegatedActorResolverError::Unavailable)?;
            if rows.len() > MAX_DELEGATED_ACTOR_ROLE_GRANTS {
                return Err(DelegatedActorResolverError::CorruptData);
            }
            let mut grants = BTreeSet::new();
            for row in rows {
                let grant = row.to_grant(request.tenant_id(), identity.principal_id)?;
                if !grants.insert(grant) {
                    return Err(DelegatedActorResolverError::CorruptData);
                }
            }
            let principal_id = PrincipalId::new(identity.principal_id.hyphenated().to_string())
                .map_err(|_| DelegatedActorResolverError::CorruptData)?;
            let authorization = AuthorizationContext::authenticated_at_revision(
                request.tenant_id().clone(),
                principal_id,
                grants,
                authorization_revision,
            )
            .map_err(|_| DelegatedActorResolverError::CorruptData)?;
            let viewer = ViewerDisplayMetadata::new(identity.display_name)
                .map_err(|_| DelegatedActorResolverError::CorruptData)?;
            let snapshot = DelegatedActorRequestSnapshot::new(
                request.assertion().clone(),
                request.tenant_id(),
                viewer,
                authorization,
            )
            .map_err(|_| DelegatedActorResolverError::CorruptData)?;
            commit(transaction).await?;
            Ok(ResolveDelegatedActorOutcome::Authenticated(Box::new(
                snapshot,
            )))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_query_is_bounded_and_scoped_to_the_exact_principal() {
        assert!(ACTIVE_GRANTS_SELECT.contains("binding.tenant_id = $1"));
        assert!(ACTIVE_GRANTS_SELECT.contains("binding.principal_id = $2"));
        assert!(ACTIVE_GRANTS_SELECT.contains("LIMIT $4"));
    }
}
