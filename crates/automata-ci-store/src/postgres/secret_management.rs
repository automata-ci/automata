use std::fmt;

use async_trait::async_trait;
use automata_ci_auth::{
    management::{ManagementActor, ManagementRevision},
    time::UnixTimestamp,
};
use automata_ci_core::UnixMillis;
use sha2::{Digest as _, Sha256};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    ActivateBuiltinSecretProvider, ActivateBuiltinSecretProviderOutcome,
    BUILTIN_SECRET_PROVIDER_ID, BuiltinRepositorySecretVersion, BuiltinSecretCleanupRepository,
    BuiltinSecretCleanupTask, BuiltinSecretProviderHealth, BuiltinSecretProviderInspection,
    BuiltinSecretProviderMetadata, BuiltinSecretProviderState, ClaimBuiltinSecretCleanup,
    ClaimBuiltinSecretCleanupOutcome, ClaimSecretMutationRecovery,
    ClaimSecretMutationRecoveryOutcome, CompleteBuiltinSecretCleanup,
    CompleteBuiltinSecretCleanupOutcome, ConfirmRepositorySecretVersionMutation,
    ConfirmRepositorySecretVersionMutationOutcome, DeleteRepositorySecret,
    DeleteRepositorySecretOutcome, GetRepositorySecretMetadata, GetRepositorySecretMetadataOutcome,
    InspectBuiltinSecretProvider, InspectBuiltinSecretProviderOutcome, ListRepositorySecrets,
    ListRepositorySecretsOutcome, MAX_SECRET_CLEANUP_ATTEMPTS, ManagedSecretProviderId,
    RecoverSecretMutationReservation, RecoverSecretMutationReservationOutcome, RepositoryId,
    RepositorySecretDeletionReceipt, RepositorySecretId, RepositorySecretManagementReadRepository,
    RepositorySecretManagementRepository, RepositorySecretMetadata, RepositorySecretMetadataPage,
    RepositorySecretMutationId, RepositorySecretMutationKind, RepositorySecretName,
    RepositorySecretProviderMutationResult, RepositorySecretState, RepositorySecretVersionId,
    RepositorySecretVersionMutationReceipt, RepositorySecretVersionMutationReservation,
    ReserveRepositorySecretVersionMutation, ReserveRepositorySecretVersionMutationOutcome,
    ResolveGithubRepositorySecretMetadata, ResolveGithubRepositorySecretMetadataOutcome,
    RetryBuiltinSecretCleanup, RetryBuiltinSecretCleanupOutcome,
    SECRET_MUTATION_CONFIRMATION_TTL_MILLIS, SecretCleanupFailureKind, SecretCleanupFence,
    SecretManagementRepositoryError, SecretMutationRecoveryFence,
    SecretMutationRecoveryReconciliation, SecretMutationRecoveryRepository,
    SecretMutationRecoveryTask, StoreError, TenantScope,
};

const BUILTIN_ADAPTER_KIND: &str = "builtin_postgres";
const BUILTIN_STORAGE_KIND: &str = "built_in_ciphertext";
const PROVIDER_READ_PERMISSION: &str = "secret-providers:read";
const PROVIDER_MANAGE_PERMISSION: &str = "secret-providers:manage";
const SECRET_READ_PERMISSION: &str = "secrets:metadata:read";
const SECRET_CREATE_PERMISSION: &str = "secrets:create";
const SECRET_UPDATE_PERMISSION: &str = "secrets:update";
const SECRET_DELETE_PERMISSION: &str = "secrets:delete";
const PROVIDER_ACTIVATE_ACTION: &str = "secret_provider.builtin.activate";
const SECRET_RESERVE_ACTION: &str = "secret.version.reserve";
const SECRET_CONFIRM_ACTION: &str = "secret.version.confirm";
const SECRET_EXPIRE_ACTION: &str = "secret.version.expire";
const SECRET_DELETE_ACTION: &str = "secret.delete";
const PROVIDER_RESOURCE_KIND: &str = "secret_provider";
const SECRET_RESOURCE_KIND: &str = "secret";
const SECRET_MUTATION_RESOURCE_KIND: &str = "secret_mutation";
// foundation-governance: derived-contract owner=store kind=digest-domain
const CLEANUP_OPERATION_DOMAIN: &[u8] = b"automata.store.secret-cleanup-operation.v1\0";
// foundation-governance: derived-contract owner=store kind=digest-domain
const RECOVERY_OPERATION_DOMAIN: &[u8] = b"automata.store.secret-mutation-recovery.v1\0";
const MAX_DELETE_VERSIONS: i64 = 65_535;

/// Transactional `PostgreSQL` adapter for repository secret metadata and cleanup.
///
/// Plaintext never crosses this adapter. Creation is deliberately split around
/// the provider call: reservation commits a provisioning descriptor, the exact
/// runtime provider stages encrypted bytes outside the management transaction,
/// and confirmation atomically promotes that exact staged winner and advances
/// the logical head.
#[derive(Clone)]
pub struct PostgresSecretManagementRepository {
    pool: PgPool,
}

impl PostgresSecretManagementRepository {
    /// Creates the adapter over an existing bounded `PostgreSQL` pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Returns the concrete pool for narrowly scoped integration composition.
    #[must_use]
    pub const fn postgres_pool(&self) -> &PgPool {
        &self.pool
    }
}

impl fmt::Debug for PostgresSecretManagementRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresSecretManagementRepository")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl RepositorySecretManagementReadRepository for PostgresSecretManagementRepository {
    async fn resolve_github_repository_secret_metadata(
        &self,
        request: ResolveGithubRepositorySecretMetadata,
    ) -> Result<ResolveGithubRepositorySecretMetadataOutcome, SecretManagementRepositoryError> {
        let mut transaction = begin(&self.pool).await?;
        let actor = match authenticate_actor(&mut transaction, request.actor()).await? {
            ActorAuthentication::Active(actor) => actor,
            ActorAuthentication::Stale => {
                commit(transaction).await?;
                return Ok(ResolveGithubRepositorySecretMetadataOutcome::SessionStale);
            }
        };
        let (owner, name) = request
            .repository()
            .as_str()
            .split_once('/')
            .ok_or(SecretManagementRepositoryError::InvalidRequest)?;
        let repository_id = sqlx::query_scalar::<_, Uuid>(
            r"
            SELECT id
            FROM repositories
            WHERE tenant_id = $1
              AND scm_provider = 'github'
              AND lower(owner) = lower($2)
              AND lower(name) = lower($3)
            FOR SHARE
            ",
        )
        .bind(&actor.tenant_id)
        .bind(owner)
        .bind(name)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sql_error)?;
        let Some(repository_id) = repository_id else {
            commit(transaction).await?;
            return Ok(ResolveGithubRepositorySecretMetadataOutcome::NotFound);
        };
        if repository_id.is_nil() {
            return Err(SecretManagementRepositoryError::CorruptData);
        }
        if !actor_has_permission(
            &mut transaction,
            &actor,
            SECRET_READ_PERMISSION,
            Some(repository_id),
        )
        .await?
        {
            commit(transaction).await?;
            return Ok(ResolveGithubRepositorySecretMetadataOutcome::NotFound);
        }
        commit(transaction).await?;
        Ok(ResolveGithubRepositorySecretMetadataOutcome::Found(
            RepositoryId::from_uuid(repository_id),
        ))
    }

    async fn get_repository_secret_metadata(
        &self,
        request: GetRepositorySecretMetadata,
    ) -> Result<GetRepositorySecretMetadataOutcome, SecretManagementRepositoryError> {
        let mut transaction = begin(&self.pool).await?;
        let actor = match authenticate_actor(&mut transaction, request.actor()).await? {
            ActorAuthentication::Active(actor) => actor,
            ActorAuthentication::Stale => {
                commit(transaction).await?;
                return Ok(GetRepositorySecretMetadataOutcome::SessionStale);
            }
        };
        if !actor_has_permission(
            &mut transaction,
            &actor,
            SECRET_READ_PERMISSION,
            Some(request.repository_id().as_uuid()),
        )
        .await?
        {
            commit(transaction).await?;
            return Ok(GetRepositorySecretMetadataOutcome::NotFound);
        }
        let row = sqlx::query_as::<_, SecretMetadataRow>(
            r"
            SELECT id, repository_id, canonical_name, provider_id,
                   current_version_id, current_version_number, status,
                   revision, created_at_ms, updated_at_ms
            FROM secrets
            WHERE tenant_id = $1
              AND scope_kind = 'repository'
              AND repository_id = $2
              AND environment_id IS NULL
              AND canonical_name = $3
              AND status <> 'deleted'
            FOR SHARE
            ",
        )
        .bind(&actor.tenant_id)
        .bind(request.repository_id().as_uuid())
        .bind(request.name().as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sql_error)?;
        let Some(row) = row else {
            commit(transaction).await?;
            return Ok(GetRepositorySecretMetadataOutcome::NotFound);
        };
        let metadata = row.into_metadata(request.repository_id())?;
        commit(transaction).await?;
        Ok(GetRepositorySecretMetadataOutcome::Found(metadata))
    }

    async fn inspect_builtin_secret_provider(
        &self,
        request: InspectBuiltinSecretProvider,
    ) -> Result<InspectBuiltinSecretProviderOutcome, SecretManagementRepositoryError> {
        let mut transaction = begin(&self.pool).await?;
        let actor = match authenticate_actor(&mut transaction, request.actor()).await? {
            ActorAuthentication::Active(actor) => actor,
            ActorAuthentication::Stale => {
                commit(transaction).await?;
                return Ok(InspectBuiltinSecretProviderOutcome::SessionStale);
            }
        };
        if !actor_has_permission(&mut transaction, &actor, PROVIDER_READ_PERMISSION, None).await? {
            commit(transaction).await?;
            return Ok(InspectBuiltinSecretProviderOutcome::Forbidden);
        }
        let row = sqlx::query_as::<_, ProviderRow>(
            r"
            SELECT provider_id, adapter_kind, supports_create_version,
                   supports_destroy_version, supports_dynamic_leases,
                   supports_renew_leases, supports_revoke_leases,
                   is_default, status, health, revision, updated_at_ms
            FROM secret_providers
            WHERE tenant_id = $1 AND provider_id = 'builtin'
            FOR SHARE
            ",
        )
        .bind(&actor.tenant_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sql_error)?;
        let Some(row) = row else {
            commit(transaction).await?;
            return Ok(InspectBuiltinSecretProviderOutcome::NotFound);
        };
        validate_builtin_provider(&row)?;
        let actor_can_manage =
            actor_has_permission(&mut transaction, &actor, PROVIDER_MANAGE_PERMISSION, None)
                .await?;
        let inspection = builtin_provider_inspection(&row, actor_can_manage)?;
        commit(transaction).await?;
        Ok(InspectBuiltinSecretProviderOutcome::Found(inspection))
    }
}

#[async_trait]
impl RepositorySecretManagementRepository for PostgresSecretManagementRepository {
    #[allow(clippy::too_many_lines)] // One transaction owns reauthorization, CAS, and audit.
    async fn activate_builtin_secret_provider(
        &self,
        request: ActivateBuiltinSecretProvider,
    ) -> Result<ActivateBuiltinSecretProviderOutcome, SecretManagementRepositoryError> {
        let mut transaction = begin(&self.pool).await?;
        let actor = match authenticate_actor(&mut transaction, request.actor()).await? {
            ActorAuthentication::Active(actor) => actor,
            ActorAuthentication::Stale => {
                commit(transaction).await?;
                return Ok(ActivateBuiltinSecretProviderOutcome::SessionStale);
            }
        };
        if !actor_has_permission(&mut transaction, &actor, PROVIDER_MANAGE_PERMISSION, None).await?
        {
            append_audit(
                &mut transaction,
                &actor,
                PROVIDER_ACTIVATE_ACTION,
                "denied",
                PROVIDER_RESOURCE_KIND,
                BUILTIN_SECRET_PROVIDER_ID,
            )
            .await?;
            commit(transaction).await?;
            return Ok(ActivateBuiltinSecretProviderOutcome::Forbidden);
        }

        let row = sqlx::query_as::<_, ProviderRow>(
            r"
            SELECT provider_id, adapter_kind, supports_create_version,
                   supports_destroy_version, supports_dynamic_leases,
                   supports_renew_leases, supports_revoke_leases,
                   is_default, status, health, revision, updated_at_ms
            FROM secret_providers
            WHERE tenant_id = $1 AND provider_id = 'builtin'
            FOR UPDATE
            ",
        )
        .bind(&actor.tenant_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sql_error)?;
        let Some(row) = row else {
            append_audit(
                &mut transaction,
                &actor,
                PROVIDER_ACTIVATE_ACTION,
                "failed",
                PROVIDER_RESOURCE_KIND,
                BUILTIN_SECRET_PROVIDER_ID,
            )
            .await?;
            commit(transaction).await?;
            return Ok(ActivateBuiltinSecretProviderOutcome::NotFound);
        };
        validate_builtin_provider(&row)?;
        let current_revision = revision(row.revision)?;
        if current_revision != request.expected_revision() {
            append_audit(
                &mut transaction,
                &actor,
                PROVIDER_ACTIVATE_ACTION,
                "failed",
                PROVIDER_RESOURCE_KIND,
                BUILTIN_SECRET_PROVIDER_ID,
            )
            .await?;
            commit(transaction).await?;
            return Ok(ActivateBuiltinSecretProviderOutcome::RevisionConflict {
                current: current_revision,
            });
        }
        if row.status == "active" {
            let metadata = builtin_provider_metadata(&row)?;
            append_audit(
                &mut transaction,
                &actor,
                PROVIDER_ACTIVATE_ACTION,
                "succeeded",
                PROVIDER_RESOURCE_KIND,
                BUILTIN_SECRET_PROVIDER_ID,
            )
            .await?;
            commit(transaction).await?;
            return Ok(ActivateBuiltinSecretProviderOutcome::AlreadyActive(
                metadata,
            ));
        }

        let updated = sqlx::query_as::<_, (i64, i64)>(
            r"
            UPDATE secret_providers
            SET status = 'active', health = 'healthy', revision = revision + 1,
                updated_at_ms = GREATEST(updated_at_ms, $2)
            WHERE tenant_id = $1 AND provider_id = 'builtin' AND revision = $3
            RETURNING revision, updated_at_ms
            ",
        )
        .bind(&actor.tenant_id)
        .bind(actor.now_ms)
        .bind(row.revision)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sql_error)?
        .ok_or(SecretManagementRepositoryError::CorruptData)?;
        let metadata = BuiltinSecretProviderMetadata::new(
            BuiltinSecretProviderState::Active,
            revision(updated.0)?,
            timestamp(updated.1)?,
        );
        append_audit(
            &mut transaction,
            &actor,
            PROVIDER_ACTIVATE_ACTION,
            "succeeded",
            PROVIDER_RESOURCE_KIND,
            BUILTIN_SECRET_PROVIDER_ID,
        )
        .await?;
        commit(transaction).await?;
        Ok(ActivateBuiltinSecretProviderOutcome::Activated(metadata))
    }

    async fn list_repository_secrets(
        &self,
        request: ListRepositorySecrets,
    ) -> Result<ListRepositorySecretsOutcome, SecretManagementRepositoryError> {
        let mut transaction = begin(&self.pool).await?;
        let actor = match authenticate_actor(&mut transaction, request.actor()).await? {
            ActorAuthentication::Active(actor) => actor,
            ActorAuthentication::Stale => {
                commit(transaction).await?;
                return Ok(ListRepositorySecretsOutcome::SessionStale);
            }
        };
        if !actor_has_permission(
            &mut transaction,
            &actor,
            SECRET_READ_PERMISSION,
            Some(request.repository_id().as_uuid()),
        )
        .await?
        {
            commit(transaction).await?;
            return Ok(ListRepositorySecretsOutcome::Forbidden);
        }
        if !repository_exists(
            &mut transaction,
            &actor.tenant_id,
            request.repository_id().as_uuid(),
            false,
        )
        .await?
        {
            commit(transaction).await?;
            return Ok(ListRepositorySecretsOutcome::NotFound);
        }

        let fetch_limit = i64::from(request.limit().get()) + 1;
        let rows = sqlx::query_as::<_, SecretMetadataRow>(
            r"
            SELECT id, repository_id, canonical_name, provider_id,
                   current_version_id, current_version_number, status,
                   revision, created_at_ms, updated_at_ms
            FROM secrets
            WHERE tenant_id = $1
              AND scope_kind = 'repository'
              AND repository_id = $2
              AND environment_id IS NULL
              AND status <> 'deleted'
              AND ($3::UUID IS NULL OR id > $3)
            ORDER BY id
            LIMIT $4
            ",
        )
        .bind(&actor.tenant_id)
        .bind(request.repository_id().as_uuid())
        .bind(request.after().map(RepositorySecretId::as_uuid))
        .bind(fetch_limit)
        .fetch_all(&mut *transaction)
        .await
        .map_err(map_sql_error)?;
        let page_limit = usize::from(request.limit().get());
        let has_more = rows.len() > page_limit;
        let mut records = rows
            .into_iter()
            .take(page_limit)
            .map(|row| row.into_metadata(request.repository_id()))
            .collect::<Result<Vec<_>, _>>()?;
        let next_after = has_more
            .then(|| records.last().map(RepositorySecretMetadata::id))
            .flatten();
        if records.windows(2).any(|pair| pair[0].id() >= pair[1].id()) {
            return Err(SecretManagementRepositoryError::CorruptData);
        }
        records.shrink_to_fit();
        commit(transaction).await?;
        Ok(ListRepositorySecretsOutcome::Found(
            RepositorySecretMetadataPage::new(records, next_after),
        ))
    }

    #[allow(clippy::too_many_lines)] // One transaction owns reauthorization, replay, and audit.
    async fn reserve_repository_secret_version_mutation(
        &self,
        request: ReserveRepositorySecretVersionMutation,
    ) -> Result<ReserveRepositorySecretVersionMutationOutcome, SecretManagementRepositoryError>
    {
        let mut transaction = begin_reservation(&self.pool).await?;
        let actor = match authenticate_actor(&mut transaction, request.actor()).await? {
            ActorAuthentication::Active(actor) => actor,
            ActorAuthentication::Stale => {
                commit(transaction).await?;
                return Ok(ReserveRepositorySecretVersionMutationOutcome::SessionStale);
            }
        };
        let resource_id = request.mutation_id().as_uuid().hyphenated().to_string();
        if !actor_has_permission(
            &mut transaction,
            &actor,
            mutation_permission(request.kind()),
            Some(request.repository_id().as_uuid()),
        )
        .await?
        {
            append_audit(
                &mut transaction,
                &actor,
                SECRET_RESERVE_ACTION,
                "denied",
                SECRET_RESOURCE_KIND,
                &resource_id,
            )
            .await?;
            commit(transaction).await?;
            return Ok(ReserveRepositorySecretVersionMutationOutcome::Forbidden);
        }
        if !repository_exists(
            &mut transaction,
            &actor.tenant_id,
            request.repository_id().as_uuid(),
            true,
        )
        .await?
        {
            append_audit(
                &mut transaction,
                &actor,
                SECRET_RESERVE_ACTION,
                "failed",
                SECRET_RESOURCE_KIND,
                &resource_id,
            )
            .await?;
            commit(transaction).await?;
            return Ok(ReserveRepositorySecretVersionMutationOutcome::NotFound);
        }

        let preliminary = load_secret_mutation(
            &mut transaction,
            &actor.tenant_id,
            request.mutation_id().as_uuid(),
            false,
        )
        .await?;
        let provider_hint = preliminary.as_ref().map_or_else(
            || request.provider_id().map(ManagedSecretProviderId::as_str),
            |row| Some(row.provider_id.as_str()),
        );
        let replace_provider =
            if request.kind() == RepositorySecretMutationKind::Replace && preliminary.is_none() {
                load_secret_provider(
                    &mut transaction,
                    &actor.tenant_id,
                    request.secret_id().as_uuid(),
                )
                .await?
            } else {
                None
            };
        let provider = select_create_provider(
            &mut transaction,
            &actor.tenant_id,
            provider_hint.or(replace_provider.as_deref()),
        )
        .await?;
        let provider_available = provider.as_ref().is_some_and(CreateProviderRow::is_builtin);

        let secret = load_secret_for_update(
            &mut transaction,
            &actor.tenant_id,
            request.secret_id().as_uuid(),
        )
        .await?;
        let existing = load_secret_mutation(
            &mut transaction,
            &actor.tenant_id,
            request.mutation_id().as_uuid(),
            true,
        )
        .await?;
        if let Some(existing) = existing {
            if !existing.matches_reservation(&request, &actor)? {
                audit_failed_mutation(
                    &mut transaction,
                    &actor,
                    SECRET_RESERVE_ACTION,
                    &resource_id,
                )
                .await?;
                commit(transaction).await?;
                return Ok(ReserveRepositorySecretVersionMutationOutcome::Conflict);
            }
            let mut outcome = existing.reserve_outcome()?;
            if matches!(
                outcome,
                ReserveRepositorySecretVersionMutationOutcome::ReconcileRequired(_)
            ) && actor.now_ms >= existing.confirmation_deadline_ms
            {
                outcome = ReserveRepositorySecretVersionMutationOutcome::Expired;
            }
            if matches!(
                outcome,
                ReserveRepositorySecretVersionMutationOutcome::ReconcileRequired(_)
            ) && !provider_available
            {
                commit(transaction).await?;
                return Ok(ReserveRepositorySecretVersionMutationOutcome::ProviderUnavailable);
            }
            append_audit(
                &mut transaction,
                &actor,
                SECRET_RESERVE_ACTION,
                "succeeded",
                SECRET_RESOURCE_KIND,
                &resource_id,
            )
            .await?;
            commit(transaction).await?;
            return Ok(outcome);
        }
        if !provider_available {
            audit_failed_mutation(
                &mut transaction,
                &actor,
                SECRET_RESERVE_ACTION,
                &resource_id,
            )
            .await?;
            commit(transaction).await?;
            return Ok(ReserveRepositorySecretVersionMutationOutcome::ProviderUnavailable);
        }
        let provider = provider.ok_or(SecretManagementRepositoryError::CorruptData)?;
        let provider_id = ManagedSecretProviderId::new(provider.provider_id.clone())
            .map_err(|_| SecretManagementRepositoryError::CorruptData)?;

        let (reserved_revision, predecessor, reserved_version_number) = match request.kind() {
            RepositorySecretMutationKind::Create => {
                if secret.is_some() {
                    audit_failed_mutation(
                        &mut transaction,
                        &actor,
                        SECRET_RESERVE_ACTION,
                        &resource_id,
                    )
                    .await?;
                    commit(transaction).await?;
                    return Ok(ReserveRepositorySecretVersionMutationOutcome::Conflict);
                }
                let reused_logical_id: bool = sqlx::query_scalar(
                    r"
                    SELECT EXISTS (
                        SELECT 1 FROM secret_version_mutations
                        WHERE tenant_id = $1 AND secret_id = $2
                    )
                    ",
                )
                .bind(&actor.tenant_id)
                .bind(request.secret_id().as_uuid())
                .fetch_one(&mut *transaction)
                .await
                .map_err(map_sql_error)?;
                if reused_logical_id {
                    audit_failed_mutation(
                        &mut transaction,
                        &actor,
                        SECRET_RESERVE_ACTION,
                        &resource_id,
                    )
                    .await?;
                    commit(transaction).await?;
                    return Ok(ReserveRepositorySecretVersionMutationOutcome::Conflict);
                }
                let name_conflict: bool = sqlx::query_scalar(
                    r"
                    SELECT EXISTS (
                        SELECT 1 FROM secrets
                        WHERE tenant_id = $1 AND scope_kind = 'repository'
                          AND repository_id = $2 AND environment_id IS NULL
                          AND canonical_name = $3 AND status <> 'deleted'
                    )
                    ",
                )
                .bind(&actor.tenant_id)
                .bind(request.repository_id().as_uuid())
                .bind(request.name().as_str())
                .fetch_one(&mut *transaction)
                .await
                .map_err(map_sql_error)?;
                if name_conflict {
                    audit_failed_mutation(
                        &mut transaction,
                        &actor,
                        SECRET_RESERVE_ACTION,
                        &resource_id,
                    )
                    .await?;
                    commit(transaction).await?;
                    return Ok(ReserveRepositorySecretVersionMutationOutcome::Conflict);
                }
                sqlx::query(
                    r"
                    INSERT INTO secrets (
                        tenant_id, id, canonical_name, scope_kind, repository_id,
                        environment_id, provider_id, status, revision,
                        created_by_principal_id, updated_by_principal_id,
                        created_at_ms, updated_at_ms
                    ) VALUES (
                        $1, $2, $3, 'repository', $4, NULL, $5, 'provisioning', 1,
                        $6, $6, $7, $7
                    )
                    ",
                )
                .bind(&actor.tenant_id)
                .bind(request.secret_id().as_uuid())
                .bind(request.name().as_str())
                .bind(request.repository_id().as_uuid())
                .bind(provider_id.as_str())
                .bind(actor.principal_id)
                .bind(actor.now_ms)
                .execute(&mut *transaction)
                .await
                .map_err(map_sql_error)?;
                (
                    ManagementRevision::new(1).expect("one is valid"),
                    None,
                    1_i64,
                )
            }
            RepositorySecretMutationKind::Replace => {
                let Some(secret) = secret else {
                    audit_failed_mutation(
                        &mut transaction,
                        &actor,
                        SECRET_RESERVE_ACTION,
                        &resource_id,
                    )
                    .await?;
                    commit(transaction).await?;
                    return Ok(ReserveRepositorySecretVersionMutationOutcome::NotFound);
                };
                if !secret.matches_descriptor(&request)
                    || secret.provider_id != BUILTIN_SECRET_PROVIDER_ID
                    || secret.status != "active"
                {
                    audit_failed_mutation(
                        &mut transaction,
                        &actor,
                        SECRET_RESERVE_ACTION,
                        &resource_id,
                    )
                    .await?;
                    commit(transaction).await?;
                    return Ok(ReserveRepositorySecretVersionMutationOutcome::Conflict);
                }
                let current_revision = revision(secret.revision)?;
                if request.expected_revision() != Some(current_revision) {
                    audit_failed_mutation(
                        &mut transaction,
                        &actor,
                        SECRET_RESERVE_ACTION,
                        &resource_id,
                    )
                    .await?;
                    commit(transaction).await?;
                    return Ok(
                        ReserveRepositorySecretVersionMutationOutcome::RevisionConflict {
                            current: current_revision,
                        },
                    );
                }
                let predecessor = builtin_target(
                    request.secret_id(),
                    secret
                        .current_version_id
                        .ok_or(SecretManagementRepositoryError::CorruptData)?,
                    secret
                        .current_version_number
                        .ok_or(SecretManagementRepositoryError::CorruptData)?,
                )?;
                if !is_confirmed_active_predecessor(&mut transaction, &actor.tenant_id, predecessor)
                    .await?
                {
                    audit_failed_mutation(
                        &mut transaction,
                        &actor,
                        SECRET_RESERVE_ACTION,
                        &resource_id,
                    )
                    .await?;
                    commit(transaction).await?;
                    return Ok(ReserveRepositorySecretVersionMutationOutcome::Conflict);
                }
                let greatest_reserved_version_number: Option<i64> = sqlx::query_scalar(
                    r"
                    SELECT max(reserved_version_number)
                    FROM secret_version_mutations
                    WHERE tenant_id = $1 AND secret_id = $2
                    ",
                )
                .bind(&actor.tenant_id)
                .bind(request.secret_id().as_uuid())
                .fetch_one(&mut *transaction)
                .await
                .map_err(map_sql_error)?;
                let predecessor_version_number = i64::try_from(predecessor.version_number())
                    .map_err(|_| SecretManagementRepositoryError::CorruptData)?;
                let greatest_reserved_version_number = greatest_reserved_version_number
                    .filter(|value| *value >= predecessor_version_number)
                    .ok_or(SecretManagementRepositoryError::CorruptData)?;
                let reserved_version_number = greatest_reserved_version_number
                    .checked_add(1)
                    .ok_or(SecretManagementRepositoryError::CorruptData)?;
                if reserved_version_number <= predecessor_version_number {
                    return Err(SecretManagementRepositoryError::CorruptData);
                }
                (current_revision, Some(predecessor), reserved_version_number)
            }
        };
        let confirmation_deadline = actor
            .now_ms
            .checked_add(
                i64::try_from(SECRET_MUTATION_CONFIRMATION_TTL_MILLIS)
                    .expect("confirmation lifetime fits i64"),
            )
            .ok_or(SecretManagementRepositoryError::InvalidRequest)?;
        let request_id = provider_create_request_id(request.mutation_id());
        sqlx::query(
            r"
            INSERT INTO secret_version_mutations (
                tenant_id, mutation_id, secret_id, scope_kind,
                repository_id, environment_id, canonical_name,
                provider_id, requested_provider_id, mutation_kind,
                expected_secret_revision, reserved_secret_revision,
                expected_predecessor_version_id,
                expected_predecessor_version_number,
                reserved_version_number, confirmation_deadline_ms,
                provider_create_request_id, reserved_by_principal_id,
                reserved_by_session_id, reserved_authorization_revision,
                reserved_at_ms
            ) VALUES (
                $1, $2, $3, 'repository', $4, NULL, $5, $6, $7, $8, $9, $10,
                $11, $12, $13, $14, $15, $16, $17, $18, $19
            )
            ",
        )
        .bind(&actor.tenant_id)
        .bind(request.mutation_id().as_uuid())
        .bind(request.secret_id().as_uuid())
        .bind(request.repository_id().as_uuid())
        .bind(request.name().as_str())
        .bind(provider_id.as_str())
        .bind(request.provider_id().map(ManagedSecretProviderId::as_str))
        .bind(mutation_kind(request.kind()))
        .bind(
            request
                .expected_revision()
                .map(ManagementRevision::value)
                .map(i64::try_from)
                .transpose()
                .map_err(|_| SecretManagementRepositoryError::InvalidRequest)?,
        )
        .bind(
            i64::try_from(reserved_revision.value())
                .map_err(|_| SecretManagementRepositoryError::InvalidRequest)?,
        )
        .bind(predecessor.map(|value| value.version_id().as_uuid()))
        .bind(
            predecessor
                .map(BuiltinRepositorySecretVersion::version_number)
                .map(i64::try_from)
                .transpose()
                .map_err(|_| SecretManagementRepositoryError::InvalidRequest)?,
        )
        .bind(reserved_version_number)
        .bind(confirmation_deadline)
        .bind(&request_id)
        .bind(actor.principal_id)
        .bind(actor.session_id)
        .bind(actor.authorization_revision)
        .bind(actor.now_ms)
        .execute(&mut *transaction)
        .await
        .map_err(map_sql_error)?;
        let recovery_operation_id =
            recovery_operation_id(&actor.tenant_id, request.mutation_id().as_uuid());
        sqlx::query(
            r"
            INSERT INTO secret_mutation_recovery_outbox (
                operation_id, tenant_id, mutation_id, status,
                next_attempt_at_ms, created_at_ms
            ) VALUES ($1, $2, $3, 'pending', $4, $5)
            ",
        )
        .bind(recovery_operation_id)
        .bind(&actor.tenant_id)
        .bind(request.mutation_id().as_uuid())
        .bind(confirmation_deadline)
        .bind(actor.now_ms)
        .execute(&mut *transaction)
        .await
        .map_err(map_sql_error)?;
        append_audit(
            &mut transaction,
            &actor,
            SECRET_RESERVE_ACTION,
            "succeeded",
            SECRET_RESOURCE_KIND,
            &resource_id,
        )
        .await?;
        commit(transaction).await?;
        Ok(
            ReserveRepositorySecretVersionMutationOutcome::FreshReservation(
                RepositorySecretVersionMutationReservation::new(
                    request.mutation_id(),
                    request.secret_id(),
                    request.repository_id(),
                    request.name().clone(),
                    provider_id,
                    request.kind(),
                    reserved_revision,
                    positive_u64(reserved_version_number)?,
                    timestamp(confirmation_deadline)?,
                    predecessor,
                    request_id,
                ),
            ),
        )
    }

    #[allow(clippy::too_many_lines)] // One transaction owns reauthorization, replay, and CAS.
    async fn confirm_repository_secret_version_mutation(
        &self,
        request: ConfirmRepositorySecretVersionMutation,
    ) -> Result<ConfirmRepositorySecretVersionMutationOutcome, SecretManagementRepositoryError>
    {
        let mut transaction = begin(&self.pool).await?;
        let actor = match authenticate_actor(&mut transaction, request.actor()).await? {
            ActorAuthentication::Active(actor) => actor,
            ActorAuthentication::Stale => {
                commit(transaction).await?;
                return Ok(ConfirmRepositorySecretVersionMutationOutcome::SessionStale);
            }
        };
        let resource_id = request.mutation_id().as_uuid().hyphenated().to_string();
        let preliminary = load_secret_mutation(
            &mut transaction,
            &actor.tenant_id,
            request.mutation_id().as_uuid(),
            false,
        )
        .await?;
        let Some(preliminary) = preliminary else {
            commit(transaction).await?;
            return Ok(ConfirmRepositorySecretVersionMutationOutcome::NotFound);
        };
        let Some(repository_id) = preliminary.repository_scope()? else {
            commit(transaction).await?;
            return Ok(ConfirmRepositorySecretVersionMutationOutcome::NotFound);
        };
        if !preliminary.reserved_actor_matches(&actor) {
            append_audit(
                &mut transaction,
                &actor,
                SECRET_CONFIRM_ACTION,
                "denied",
                SECRET_RESOURCE_KIND,
                &resource_id,
            )
            .await?;
            commit(transaction).await?;
            return Ok(ConfirmRepositorySecretVersionMutationOutcome::Forbidden);
        }
        if !actor_has_permission(
            &mut transaction,
            &actor,
            mutation_permission(preliminary.kind()?),
            Some(repository_id),
        )
        .await?
        {
            append_audit(
                &mut transaction,
                &actor,
                SECRET_CONFIRM_ACTION,
                "denied",
                SECRET_RESOURCE_KIND,
                &resource_id,
            )
            .await?;
            commit(transaction).await?;
            return Ok(ConfirmRepositorySecretVersionMutationOutcome::Forbidden);
        }

        let secret =
            load_secret_for_update(&mut transaction, &actor.tenant_id, preliminary.secret_id)
                .await?;
        let mutation = load_secret_mutation(
            &mut transaction,
            &actor.tenant_id,
            request.mutation_id().as_uuid(),
            true,
        )
        .await?
        .ok_or(SecretManagementRepositoryError::CorruptData)?;
        if actor.now_ms < mutation.reserved_at_ms {
            return Err(SecretManagementRepositoryError::InvalidRequest);
        }
        if mutation.provider_id != BUILTIN_SECRET_PROVIDER_ID {
            commit(transaction).await?;
            return Ok(ConfirmRepositorySecretVersionMutationOutcome::ProviderUnavailable);
        }
        let Some(secret) = secret else {
            return Err(SecretManagementRepositoryError::CorruptData);
        };
        if mutation.state != "reserved" {
            let outcome = terminal_confirm_outcome(
                &mut transaction,
                &actor.tenant_id,
                &mutation,
                request.provider_result(),
            )
            .await?;
            if outcome == ConfirmRepositorySecretVersionMutationOutcome::Conflict {
                append_audit(
                    &mut transaction,
                    &actor,
                    SECRET_CONFIRM_ACTION,
                    "failed",
                    SECRET_RESOURCE_KIND,
                    &resource_id,
                )
                .await?;
            }
            commit(transaction).await?;
            return Ok(outcome);
        }
        if actor.now_ms >= mutation.confirmation_deadline_ms {
            let exact_expired_result = match request.provider_result() {
                RepositorySecretProviderMutationResult::CasLost => !sqlx::query_scalar::<_, bool>(
                    r"
                        SELECT EXISTS (
                            SELECT 1 FROM secret_versions
                            WHERE tenant_id = $1 AND provider_id = $2
                              AND create_request_id = $3
                        )
                        ",
                )
                .bind(&actor.tenant_id)
                .bind(&mutation.provider_id)
                .bind(&mutation.provider_create_request_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(map_sql_error)?,
                RepositorySecretProviderMutationResult::BuiltinCreated(target) => {
                    verify_staged_mutation_winner(
                        &mut transaction,
                        &actor.tenant_id,
                        &mutation,
                        target,
                        &secret,
                    )
                    .await?
                    .is_some()
                }
            };
            append_audit(
                &mut transaction,
                &actor,
                SECRET_CONFIRM_ACTION,
                "failed",
                SECRET_RESOURCE_KIND,
                &resource_id,
            )
            .await?;
            commit(transaction).await?;
            return Ok(if exact_expired_result {
                ConfirmRepositorySecretVersionMutationOutcome::Expired
            } else {
                ConfirmRepositorySecretVersionMutationOutcome::Conflict
            });
        }
        let outcome = match request.provider_result() {
            RepositorySecretProviderMutationResult::CasLost => {
                let winner_exists: bool = sqlx::query_scalar(
                    r"
                    SELECT EXISTS (
                        SELECT 1 FROM secret_versions
                        WHERE tenant_id = $1 AND provider_id = $2
                          AND create_request_id = $3
                    )
                    ",
                )
                .bind(&actor.tenant_id)
                .bind(&mutation.provider_id)
                .bind(&mutation.provider_create_request_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(map_sql_error)?;
                if winner_exists || !mutation.head_has_changed(&secret)? {
                    audit_failed_mutation(
                        &mut transaction,
                        &actor,
                        SECRET_CONFIRM_ACTION,
                        &resource_id,
                    )
                    .await?;
                    commit(transaction).await?;
                    return Ok(ConfirmRepositorySecretVersionMutationOutcome::Conflict);
                }
                let cancelled = sqlx::query(
                    r"
                    UPDATE secret_version_mutations
                    SET state = 'cancelled', completion_kind = 'cas_lost',
                        confirmed_by_principal_id = $3, confirmed_at_ms = $4,
                        confirmed_by_session_id = $6,
                        confirmed_authorization_revision = $7,
                        terminal_actor_kind = 'human',
                        terminal_reason = 'cas_lost', revision = revision + 1
                    WHERE tenant_id = $1 AND mutation_id = $2
                      AND state = 'reserved' AND revision = $5
                    ",
                )
                .bind(&actor.tenant_id)
                .bind(request.mutation_id().as_uuid())
                .bind(actor.principal_id)
                .bind(actor.now_ms)
                .bind(mutation.revision)
                .bind(actor.session_id)
                .bind(actor.authorization_revision)
                .execute(&mut *transaction)
                .await
                .map_err(map_sql_error)?;
                if cancelled.rows_affected() != 1 {
                    return Err(SecretManagementRepositoryError::CorruptData);
                }
                ConfirmRepositorySecretVersionMutationOutcome::CasLost
            }
            RepositorySecretProviderMutationResult::BuiltinCreated(target) => {
                let Some(staged) = verify_staged_mutation_winner(
                    &mut transaction,
                    &actor.tenant_id,
                    &mutation,
                    target,
                    &secret,
                )
                .await?
                else {
                    audit_failed_mutation(
                        &mut transaction,
                        &actor,
                        SECRET_CONFIRM_ACTION,
                        &resource_id,
                    )
                    .await?;
                    commit(transaction).await?;
                    return Ok(ConfirmRepositorySecretVersionMutationOutcome::Conflict);
                };
                let predecessor = if mutation.kind()? == RepositorySecretMutationKind::Replace {
                    let Some(predecessor) = load_confirmed_predecessor_for_update(
                        &mut transaction,
                        &actor.tenant_id,
                        &mutation,
                    )
                    .await?
                    else {
                        audit_failed_mutation(
                            &mut transaction,
                            &actor,
                            SECRET_CONFIRM_ACTION,
                            &resource_id,
                        )
                        .await?;
                        commit(transaction).await?;
                        return Ok(ConfirmRepositorySecretVersionMutationOutcome::Conflict);
                    };
                    Some(predecessor)
                } else {
                    None
                };

                let promoted = sqlx::query(
                    r"
                    UPDATE secret_version_lifecycle
                    SET status = 'active', revision = revision + 1,
                        changed_by_principal_id = $3,
                        changed_at_ms = GREATEST(changed_at_ms, $4)
                    WHERE tenant_id = $1 AND secret_version_id = $2
                      AND mutation_id = $5 AND status = 'staged'
                      AND revision = $6
                    ",
                )
                .bind(&actor.tenant_id)
                .bind(target.version_id().as_uuid())
                .bind(actor.principal_id)
                .bind(actor.now_ms)
                .bind(request.mutation_id().as_uuid())
                .bind(staged.lifecycle_revision)
                .execute(&mut *transaction)
                .await
                .map_err(map_sql_error)?;
                if promoted.rows_affected() != 1 {
                    return Err(SecretManagementRepositoryError::CorruptData);
                }

                let target_number = i64::try_from(target.version_number())
                    .map_err(|_| SecretManagementRepositoryError::InvalidRequest)?;
                let advanced = match mutation.kind()? {
                    RepositorySecretMutationKind::Create => sqlx::query(
                        r"
                            UPDATE secrets
                            SET status = 'active', current_version_id = $3,
                                current_version_number = $4,
                                revision = revision + 1,
                                updated_by_principal_id = $5,
                                updated_at_ms = GREATEST(updated_at_ms, $6)
                            WHERE tenant_id = $1 AND id = $2
                              AND status = 'provisioning' AND revision = $7
                              AND current_version_id IS NULL
                              AND current_version_number IS NULL
                            ",
                    )
                    .bind(&actor.tenant_id)
                    .bind(mutation.secret_id)
                    .bind(target.version_id().as_uuid())
                    .bind(target_number)
                    .bind(actor.principal_id)
                    .bind(actor.now_ms)
                    .bind(mutation.reserved_secret_revision)
                    .execute(&mut *transaction)
                    .await
                    .map_err(map_sql_error)?,
                    RepositorySecretMutationKind::Replace => sqlx::query(
                        r"
                            UPDATE secrets
                            SET current_version_id = $3,
                                current_version_number = $4,
                                revision = revision + 1,
                                updated_by_principal_id = $5,
                                updated_at_ms = GREATEST(updated_at_ms, $6)
                            WHERE tenant_id = $1 AND id = $2
                              AND status = 'active' AND revision = $7
                              AND current_version_id = $8
                              AND current_version_number = $9
                            ",
                    )
                    .bind(&actor.tenant_id)
                    .bind(mutation.secret_id)
                    .bind(target.version_id().as_uuid())
                    .bind(target_number)
                    .bind(actor.principal_id)
                    .bind(actor.now_ms)
                    .bind(mutation.reserved_secret_revision)
                    .bind(mutation.expected_predecessor_version_id)
                    .bind(mutation.expected_predecessor_version_number)
                    .execute(&mut *transaction)
                    .await
                    .map_err(map_sql_error)?,
                };
                if advanced.rows_affected() != 1 {
                    return Err(SecretManagementRepositoryError::CorruptData);
                }

                if let Some(predecessor) = predecessor {
                    let lifecycle_update = sqlx::query(
                        r"
                        UPDATE secret_version_lifecycle
                        SET status = 'superseded', revision = revision + 1,
                            changed_by_principal_id = $3,
                            changed_at_ms = GREATEST(changed_at_ms, $4)
                        WHERE tenant_id = $1 AND secret_version_id = $2
                          AND status = 'active' AND revision = $5
                        ",
                    )
                    .bind(&actor.tenant_id)
                    .bind(predecessor.version_id)
                    .bind(actor.principal_id)
                    .bind(actor.now_ms)
                    .bind(predecessor.lifecycle_revision)
                    .execute(&mut *transaction)
                    .await
                    .map_err(map_sql_error)?;
                    if lifecycle_update.rows_affected() != 1 {
                        return Err(SecretManagementRepositoryError::CorruptData);
                    }

                    let receipt_update = sqlx::query(
                        r"
                        UPDATE secret_version_mutations
                        SET state = 'superseded',
                            terminal_reason = 'applied_then_superseded',
                            revision = revision + 1
                        WHERE tenant_id = $1 AND mutation_id = $2
                          AND state = 'confirmed' AND revision = $3
                          AND committed_version_id = $4
                        ",
                    )
                    .bind(&actor.tenant_id)
                    .bind(predecessor.mutation_id)
                    .bind(predecessor.mutation_revision)
                    .bind(predecessor.version_id)
                    .execute(&mut *transaction)
                    .await
                    .map_err(map_sql_error)?;
                    if receipt_update.rows_affected() != 1 {
                        return Err(SecretManagementRepositoryError::CorruptData);
                    }
                }

                let confirmed_secret_revision = mutation
                    .reserved_secret_revision
                    .checked_add(1)
                    .ok_or(SecretManagementRepositoryError::CorruptData)?;
                let receipt_update = sqlx::query(
                    r"
                    UPDATE secret_version_mutations
                    SET state = 'confirmed', completion_kind = 'builtin_created',
                        committed_version_id = $3,
                        committed_version_number = $4,
                        confirmed_secret_revision = $5,
                        confirmed_by_principal_id = $6,
                        confirmed_by_session_id = $9,
                        confirmed_authorization_revision = $10,
                        confirmed_at_ms = $7, terminal_actor_kind = 'human',
                        revision = revision + 1
                    WHERE tenant_id = $1 AND mutation_id = $2
                      AND state = 'reserved' AND revision = $8
                    ",
                )
                .bind(&actor.tenant_id)
                .bind(request.mutation_id().as_uuid())
                .bind(target.version_id().as_uuid())
                .bind(target_number)
                .bind(confirmed_secret_revision)
                .bind(actor.principal_id)
                .bind(actor.now_ms)
                .bind(mutation.revision)
                .bind(actor.session_id)
                .bind(actor.authorization_revision)
                .execute(&mut *transaction)
                .await
                .map_err(map_sql_error)?;
                if receipt_update.rows_affected() != 1 {
                    return Err(SecretManagementRepositoryError::CorruptData);
                }
                ConfirmRepositorySecretVersionMutationOutcome::Applied(
                    RepositorySecretVersionMutationReceipt::new(request.mutation_id(), target),
                )
            }
        };
        append_audit(
            &mut transaction,
            &actor,
            SECRET_CONFIRM_ACTION,
            "succeeded",
            SECRET_RESOURCE_KIND,
            &resource_id,
        )
        .await?;
        commit(transaction).await?;
        Ok(outcome)
    }

    #[allow(clippy::too_many_lines)]
    async fn delete_repository_secret(
        &self,
        request: DeleteRepositorySecret,
    ) -> Result<DeleteRepositorySecretOutcome, SecretManagementRepositoryError> {
        let mut transaction = begin(&self.pool).await?;
        let actor = match authenticate_actor(&mut transaction, request.actor()).await? {
            ActorAuthentication::Active(actor) => actor,
            ActorAuthentication::Stale => {
                commit(transaction).await?;
                return Ok(DeleteRepositorySecretOutcome::SessionStale);
            }
        };
        let resource_id = request.secret_id().as_uuid().hyphenated().to_string();
        let row = load_repository_secret_for_update(
            &mut transaction,
            &actor.tenant_id,
            request.repository_id().as_uuid(),
            request.secret_id().as_uuid(),
        )
        .await?;
        let Some(row) = row else {
            append_audit(
                &mut transaction,
                &actor,
                SECRET_DELETE_ACTION,
                "failed",
                SECRET_RESOURCE_KIND,
                &resource_id,
            )
            .await?;
            commit(transaction).await?;
            return Ok(DeleteRepositorySecretOutcome::NotFound);
        };
        let repository_id = exact_repository_scope(&row)?
            .filter(|value| *value == request.repository_id().as_uuid())
            .ok_or(SecretManagementRepositoryError::CorruptData)?;
        if !actor_has_permission(
            &mut transaction,
            &actor,
            SECRET_DELETE_PERMISSION,
            Some(repository_id),
        )
        .await?
        {
            append_audit(
                &mut transaction,
                &actor,
                SECRET_DELETE_ACTION,
                "denied",
                SECRET_RESOURCE_KIND,
                &resource_id,
            )
            .await?;
            commit(transaction).await?;
            return Ok(DeleteRepositorySecretOutcome::Forbidden);
        }
        let current_revision = revision(row.revision)?;
        if current_revision != request.expected_revision() {
            append_audit(
                &mut transaction,
                &actor,
                SECRET_DELETE_ACTION,
                "failed",
                SECRET_RESOURCE_KIND,
                &resource_id,
            )
            .await?;
            commit(transaction).await?;
            return Ok(DeleteRepositorySecretOutcome::RevisionConflict {
                current: current_revision,
            });
        }
        if row.status == "deleted" {
            commit(transaction).await?;
            return Ok(DeleteRepositorySecretOutcome::AlreadyDeleted);
        }

        if !matches!(row.status.as_str(), "provisioning" | "active" | "disabled") {
            return Err(SecretManagementRepositoryError::CorruptData);
        }
        if row.status == "provisioning"
            && (row.current_version_id.is_some() || row.current_version_number.is_some())
        {
            return Err(SecretManagementRepositoryError::CorruptData);
        }
        if matches!(row.status.as_str(), "active" | "disabled")
            && (row.current_version_id.is_none() || row.current_version_number.is_none())
        {
            return Err(SecretManagementRepositoryError::CorruptData);
        }

        let version_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM secret_versions WHERE tenant_id = $1 AND secret_id = $2",
        )
        .bind(&actor.tenant_id)
        .bind(request.secret_id().as_uuid())
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_sql_error)?;
        let valid_version_count = if row.status == "provisioning" {
            (0..=1).contains(&version_count)
        } else {
            (1..=MAX_DELETE_VERSIONS).contains(&version_count)
        };
        if !valid_version_count {
            return Err(SecretManagementRepositoryError::CorruptData);
        }

        sqlx::query(
            r"
            UPDATE secret_version_mutations
            SET state = 'cancelled', completion_kind = 'system_cancelled',
                confirmed_by_principal_id = $3,
                confirmed_by_session_id = $4,
                confirmed_authorization_revision = $5,
                confirmed_at_ms = $6, terminal_actor_kind = 'human',
                terminal_reason = 'secret_deleted', revision = revision + 1
            WHERE tenant_id = $1 AND secret_id = $2 AND state = 'reserved'
            ",
        )
        .bind(&actor.tenant_id)
        .bind(request.secret_id().as_uuid())
        .bind(actor.principal_id)
        .bind(actor.session_id)
        .bind(actor.authorization_revision)
        .bind(actor.now_ms)
        .execute(&mut *transaction)
        .await
        .map_err(map_sql_error)?;

        let update = sqlx::query(
            r"
            UPDATE secrets
            SET status = 'deleted', revision = revision + 1,
                updated_by_principal_id = $3,
                updated_at_ms = GREATEST(updated_at_ms, $4),
                deleted_at_ms = GREATEST(created_at_ms, $4)
            WHERE tenant_id = $1 AND id = $2 AND revision = $5
              AND status = $6
            ",
        )
        .bind(&actor.tenant_id)
        .bind(request.secret_id().as_uuid())
        .bind(actor.principal_id)
        .bind(actor.now_ms)
        .bind(row.revision)
        .bind(&row.status)
        .execute(&mut *transaction)
        .await
        .map_err(map_sql_error)?;
        if update.rows_affected() != 1 {
            return Err(SecretManagementRepositoryError::CorruptData);
        }
        sqlx::query(
            r"
            UPDATE secret_workload_grants
            SET status = 'revoked', revoked_at_ms = GREATEST(issued_at_ms, $3),
                revocation_reason = 'secret_deleted'
            WHERE tenant_id = $1 AND secret_id = $2 AND status = 'active'
            ",
        )
        .bind(&actor.tenant_id)
        .bind(request.secret_id().as_uuid())
        .bind(actor.now_ms)
        .execute(&mut *transaction)
        .await
        .map_err(map_sql_error)?;

        let versions = sqlx::query_as::<_, DeleteVersionRow>(
            r"
            SELECT version.id, version.version_number, version.provider_id,
                   lifecycle.status, lifecycle.destroy_request_id,
                   lifecycle.revision
            FROM secret_versions AS version
            JOIN secret_version_lifecycle AS lifecycle
              ON lifecycle.tenant_id = version.tenant_id
             AND lifecycle.secret_version_id = version.id
            WHERE version.tenant_id = $1 AND version.secret_id = $2
            ORDER BY version.version_number, version.id
            FOR UPDATE OF version, lifecycle
            ",
        )
        .bind(&actor.tenant_id)
        .bind(request.secret_id().as_uuid())
        .fetch_all(&mut *transaction)
        .await
        .map_err(map_sql_error)?;
        if i64::try_from(versions.len()).ok() != Some(version_count) {
            return Err(SecretManagementRepositoryError::CorruptData);
        }
        let mut cleanup_operations = 0_u16;
        for version in versions {
            if version.id.is_nil() || version.version_number <= 0 || version.revision <= 0 {
                return Err(SecretManagementRepositoryError::CorruptData);
            }
            if version.status == "destroyed" {
                continue;
            }
            let destroy_request_id = provider_destroy_request_id(version.id);
            match version.status.as_str() {
                "staged" | "active" | "superseded" | "disabled" => {
                    let transitioned = sqlx::query(
                        r"
                        UPDATE secret_version_lifecycle
                        SET status = 'destroy_pending', destroy_request_id = $3,
                            revision = revision + 1,
                            changed_by_principal_id = $4,
                            changed_at_ms = GREATEST(changed_at_ms, $5)
                        WHERE tenant_id = $1 AND secret_version_id = $2
                          AND revision = $6 AND status = $7
                        ",
                    )
                    .bind(&actor.tenant_id)
                    .bind(version.id)
                    .bind(&destroy_request_id)
                    .bind(actor.principal_id)
                    .bind(actor.now_ms)
                    .bind(version.revision)
                    .bind(&version.status)
                    .execute(&mut *transaction)
                    .await
                    .map_err(map_sql_error)?;
                    if transitioned.rows_affected() != 1 {
                        return Err(SecretManagementRepositoryError::CorruptData);
                    }
                }
                "destroy_pending"
                    if version.destroy_request_id.as_deref() == Some(&destroy_request_id) => {}
                _ => return Err(SecretManagementRepositoryError::CorruptData),
            }
            let operation_id =
                cleanup_operation_id(&actor.tenant_id, request.secret_id().as_uuid(), version.id);
            sqlx::query(
                r"
                INSERT INTO secret_cleanup_outbox (
                    operation_id, tenant_id, provider_id, cleanup_kind,
                    secret_id, secret_version_id, version_number,
                    status, attempts, next_attempt_at_ms, created_at_ms
                ) VALUES (
                    $1, $2, $3, 'destroy_secret_version', $4, $5, $6,
                    'pending', 0, $7, $7
                )
                ON CONFLICT (operation_id) DO NOTHING
                ",
            )
            .bind(operation_id)
            .bind(&actor.tenant_id)
            .bind(&version.provider_id)
            .bind(request.secret_id().as_uuid())
            .bind(version.id)
            .bind(version.version_number)
            .bind(actor.now_ms)
            .execute(&mut *transaction)
            .await
            .map_err(map_sql_error)?;
            verify_cleanup_identity(
                &mut transaction,
                operation_id,
                &actor.tenant_id,
                &version.provider_id,
                request.secret_id().as_uuid(),
                version.id,
                version.version_number,
            )
            .await?;
            cleanup_operations = cleanup_operations
                .checked_add(1)
                .ok_or(SecretManagementRepositoryError::CorruptData)?;
        }
        append_audit(
            &mut transaction,
            &actor,
            SECRET_DELETE_ACTION,
            "succeeded",
            SECRET_RESOURCE_KIND,
            &resource_id,
        )
        .await?;
        commit(transaction).await?;
        Ok(DeleteRepositorySecretOutcome::Deleted(
            RepositorySecretDeletionReceipt::new(request.secret_id(), cleanup_operations),
        ))
    }
}

#[async_trait]
impl BuiltinSecretCleanupRepository for PostgresSecretManagementRepository {
    #[allow(clippy::too_many_lines)] // Claim validation deliberately checks the complete row shape.
    async fn claim_builtin_secret_cleanup(
        &self,
        request: ClaimBuiltinSecretCleanup,
    ) -> Result<ClaimBuiltinSecretCleanupOutcome, SecretManagementRepositoryError> {
        let stale_after = i64::try_from(request.stale_after_millis())
            .map_err(|_| SecretManagementRepositoryError::InvalidRequest)?;
        let stale_before = request.now().get().checked_sub(stale_after).unwrap_or(-1);
        let mut transaction = begin(&self.pool).await?;
        let row = sqlx::query_as::<_, CleanupClaimRow>(
            r"
            SELECT outbox.operation_id, outbox.tenant_id, outbox.provider_id,
                   outbox.cleanup_kind, outbox.provider_lease_record_id,
                   outbox.secret_id, outbox.secret_version_id,
                   outbox.version_number, outbox.envelope_generation,
                   outbox.status AS outbox_status, outbox.attempts,
                   outbox.claim_generation,
                   outbox.next_attempt_at_ms, outbox.locked_by,
                   outbox.locked_at_ms, outbox.completed_at_ms,
                   provider.adapter_kind, provider.supports_destroy_version,
                   secret.canonical_name, secret.scope_kind,
                   secret.repository_id, secret.environment_id,
                   secret.status AS secret_status,
                   secret.current_version_id,
                   lifecycle.status AS lifecycle_status,
                   lifecycle.destroy_request_id,
                   mutation.state AS mutation_state,
                   mutation.completion_kind AS mutation_completion_kind,
                   mutation.terminal_reason AS mutation_terminal_reason,
                   mutation.mutation_kind,
                   mutation.abandoned_version_id,
                   mutation.abandoned_version_number
            FROM secret_cleanup_outbox AS outbox
            JOIN secret_providers AS provider
              ON provider.tenant_id = outbox.tenant_id
             AND provider.provider_id = outbox.provider_id
            JOIN secrets AS secret
              ON secret.tenant_id = outbox.tenant_id
             AND secret.id = outbox.secret_id
            JOIN secret_version_lifecycle AS lifecycle
              ON lifecycle.tenant_id = outbox.tenant_id
             AND lifecycle.secret_version_id = outbox.secret_version_id
            JOIN secret_version_mutations AS mutation
              ON mutation.tenant_id = lifecycle.tenant_id
             AND mutation.mutation_id = lifecycle.mutation_id
            WHERE outbox.provider_id = 'builtin'
              AND outbox.cleanup_kind = 'destroy_secret_version'
              AND outbox.created_at_ms <= $2
              AND (
                  (
                      outbox.status = 'pending'
                      AND outbox.attempts < $1
                      AND outbox.next_attempt_at_ms <= $2
                  )
                  OR (
                      outbox.status = 'in_progress'
                      AND outbox.attempts BETWEEN 1 AND $1
                      AND outbox.locked_at_ms <= $3
                  )
              )
            ORDER BY outbox.next_attempt_at_ms, outbox.sequence
            FOR UPDATE OF outbox SKIP LOCKED
            LIMIT 1
            ",
        )
        .bind(i32::from(MAX_SECRET_CLEANUP_ATTEMPTS))
        .bind(request.now().get())
        .bind(stale_before)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sql_error)?;
        let Some(row) = row else {
            commit(transaction).await?;
            return Ok(ClaimBuiltinSecretCleanupOutcome::NoWork);
        };
        row.validate()?;
        let tenant = TenantScope::from_authenticated_tenant_id(row.tenant_id.clone())
            .map_err(|_| SecretManagementRepositoryError::CorruptData)?;
        let secret_id = RepositorySecretId::from_uuid(
            row.secret_id
                .ok_or(SecretManagementRepositoryError::CorruptData)?,
        )
        .map_err(|_| SecretManagementRepositoryError::CorruptData)?;
        let repository_id = RepositoryId::from_uuid(
            row.repository_id
                .ok_or(SecretManagementRepositoryError::CorruptData)?,
        );
        let version_id = row
            .secret_version_id
            .ok_or(SecretManagementRepositoryError::CorruptData)?;
        let version_number = positive_u64(
            row.version_number
                .ok_or(SecretManagementRepositoryError::CorruptData)?,
        )?;
        let claimed_attempts = if row.outbox_status == "pending" {
            row.attempts.checked_add(1)
        } else {
            Some(row.attempts)
        };
        let attempts = claimed_attempts
            .and_then(|value| u16::try_from(value).ok())
            .filter(|value| (1..=MAX_SECRET_CLEANUP_ATTEMPTS).contains(value))
            .ok_or(SecretManagementRepositoryError::CorruptData)?;
        let claim_generation = row
            .claim_generation
            .checked_add(1)
            .and_then(|value| u64::try_from(value).ok())
            .filter(|value| *value > 0)
            .ok_or(SecretManagementRepositoryError::CorruptData)?;
        let updated = sqlx::query(
            r"
            UPDATE secret_cleanup_outbox
            SET status = 'in_progress',
                attempts = CASE
                    WHEN status = 'pending' THEN attempts + 1
                    ELSE attempts
                END,
                claim_generation = claim_generation + 1,
                locked_by = $2, locked_at_ms = $3, completed_at_ms = NULL
            WHERE operation_id = $1 AND attempts = $4
              AND claim_generation = $7
              AND (
                  (status = 'pending' AND attempts < $6)
                  OR (
                      status = 'in_progress'
                      AND attempts BETWEEN 1 AND $6
                      AND locked_at_ms <= $5
                  )
              )
            ",
        )
        .bind(row.operation_id)
        .bind(request.worker_id().as_str())
        .bind(request.now().get())
        .bind(row.attempts)
        .bind(stale_before)
        .bind(i32::from(MAX_SECRET_CLEANUP_ATTEMPTS))
        .bind(row.claim_generation)
        .execute(&mut *transaction)
        .await
        .map_err(map_sql_error)?;
        if updated.rows_affected() != 1 {
            return Err(SecretManagementRepositoryError::CorruptData);
        }
        let fence = SecretCleanupFence::new(
            row.operation_id,
            request.worker_id().clone(),
            claim_generation,
            request.now(),
        );
        let task = BuiltinSecretCleanupTask::new(
            fence,
            tenant,
            ManagedSecretProviderId::new(row.provider_id)
                .map_err(|_| SecretManagementRepositoryError::CorruptData)?,
            secret_id,
            repository_id,
            RepositorySecretName::new(row.canonical_name)
                .map_err(|_| SecretManagementRepositoryError::CorruptData)?,
            version_id,
            version_number,
            provider_destroy_request_id(version_id),
            attempts,
        );
        commit(transaction).await?;
        Ok(ClaimBuiltinSecretCleanupOutcome::Claimed(task))
    }

    async fn complete_builtin_secret_cleanup(
        &self,
        request: CompleteBuiltinSecretCleanup,
    ) -> Result<CompleteBuiltinSecretCleanupOutcome, SecretManagementRepositoryError> {
        let mut transaction = begin(&self.pool).await?;
        let row = load_cleanup_fence(&mut transaction, request.fence().operation_id()).await?;
        let Some(row) = row else {
            commit(transaction).await?;
            return Ok(CompleteBuiltinSecretCleanupOutcome::NotFound);
        };
        if !row.matches_fence(request.fence()) {
            commit(transaction).await?;
            return Ok(CompleteBuiltinSecretCleanupOutcome::FenceRejected);
        }
        let version_id = row
            .secret_version_id
            .ok_or(SecretManagementRepositoryError::CorruptData)?;
        let lifecycle_status: Option<String> = sqlx::query_scalar(
            r"
            SELECT status FROM secret_version_lifecycle
            WHERE tenant_id = $1 AND secret_version_id = $2
            FOR UPDATE
            ",
        )
        .bind(&row.tenant_id)
        .bind(version_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sql_error)?;
        if lifecycle_status.as_deref() != Some("destroyed")
            || durable_envelope_count(&mut transaction, &row.tenant_id, version_id).await? != 0
        {
            commit(transaction).await?;
            return Ok(CompleteBuiltinSecretCleanupOutcome::ProviderErasureIncomplete);
        }
        let update = sqlx::query(
            r"
            UPDATE secret_cleanup_outbox
            SET status = 'completed', locked_by = NULL, locked_at_ms = NULL,
                completed_at_ms = $4
            WHERE operation_id = $1 AND status = 'in_progress'
              AND locked_by = $2 AND locked_at_ms = $3
              AND claim_generation = $5
            ",
        )
        .bind(request.fence().operation_id())
        .bind(request.fence().worker_id().as_str())
        .bind(request.fence().locked_at().get())
        .bind(request.completed_at().get())
        .bind(
            i64::try_from(request.fence().claim_generation())
                .map_err(|_| SecretManagementRepositoryError::InvalidRequest)?,
        )
        .execute(&mut *transaction)
        .await
        .map_err(map_sql_error)?;
        if update.rows_affected() != 1 {
            return Err(SecretManagementRepositoryError::CorruptData);
        }
        commit(transaction).await?;
        Ok(CompleteBuiltinSecretCleanupOutcome::Completed)
    }

    async fn retry_builtin_secret_cleanup(
        &self,
        request: RetryBuiltinSecretCleanup,
    ) -> Result<RetryBuiltinSecretCleanupOutcome, SecretManagementRepositoryError> {
        let mut transaction = begin(&self.pool).await?;
        let row = load_cleanup_fence(&mut transaction, request.fence().operation_id()).await?;
        let Some(row) = row else {
            commit(transaction).await?;
            return Ok(RetryBuiltinSecretCleanupOutcome::NotFound);
        };
        if !row.matches_fence(request.fence()) {
            commit(transaction).await?;
            return Ok(RetryBuiltinSecretCleanupOutcome::FenceRejected);
        }
        let retryable = cleanup_failure_is_retryable(request.failure_kind());
        let exhausted = !retryable || row.attempts >= i32::from(MAX_SECRET_CLEANUP_ATTEMPTS);
        let status = if exhausted { "dead_letter" } else { "pending" };
        let update = sqlx::query(
            r"
            UPDATE secret_cleanup_outbox
            SET status = $4, next_attempt_at_ms = $5,
                locked_by = NULL, locked_at_ms = NULL,
                last_failure_kind = $6
            WHERE operation_id = $1 AND status = 'in_progress'
              AND locked_by = $2 AND locked_at_ms = $3
              AND claim_generation = $7
            ",
        )
        .bind(request.fence().operation_id())
        .bind(request.fence().worker_id().as_str())
        .bind(request.fence().locked_at().get())
        .bind(status)
        .bind(request.retry_at().get())
        .bind(encode_cleanup_failure(request.failure_kind()))
        .bind(
            i64::try_from(request.fence().claim_generation())
                .map_err(|_| SecretManagementRepositoryError::InvalidRequest)?,
        )
        .execute(&mut *transaction)
        .await
        .map_err(map_sql_error)?;
        if update.rows_affected() != 1 {
            return Err(SecretManagementRepositoryError::CorruptData);
        }
        commit(transaction).await?;
        Ok(if exhausted {
            RetryBuiltinSecretCleanupOutcome::DeadLettered
        } else {
            RetryBuiltinSecretCleanupOutcome::RetryScheduled
        })
    }
}

#[async_trait]
impl SecretMutationRecoveryRepository for PostgresSecretManagementRepository {
    #[allow(clippy::too_many_lines)] // Claim validation checks the complete durable intent shape.
    async fn claim_secret_mutation_recovery(
        &self,
        request: ClaimSecretMutationRecovery,
    ) -> Result<ClaimSecretMutationRecoveryOutcome, SecretManagementRepositoryError> {
        let stale_after = i64::try_from(request.stale_after_millis())
            .map_err(|_| SecretManagementRepositoryError::InvalidRequest)?;
        let stale_before = request.now().get().checked_sub(stale_after).unwrap_or(-1);
        let mut transaction = begin(&self.pool).await?;
        let row = sqlx::query_as::<_, RecoveryClaimRow>(
            r"
            SELECT outbox.operation_id, outbox.tenant_id, outbox.mutation_id,
                   outbox.status, outbox.next_attempt_at_ms,
                   outbox.attempts, outbox.claim_generation,
                   outbox.locked_by, outbox.locked_at_ms,
                   outbox.created_at_ms,
                   mutation.secret_id, mutation.mutation_kind,
                   mutation.provider_id, mutation.scope_kind,
                   mutation.repository_id, mutation.environment_id,
                   mutation.canonical_name, mutation.reserved_version_number,
                   mutation.expected_predecessor_version_id,
                   mutation.expected_predecessor_version_number,
                   mutation.provider_create_request_id,
                   mutation.confirmation_deadline_ms, mutation.state
            FROM secret_mutation_recovery_outbox AS outbox
            JOIN secret_version_mutations AS mutation
              ON mutation.tenant_id = outbox.tenant_id
             AND mutation.mutation_id = outbox.mutation_id
            WHERE outbox.next_attempt_at_ms <= $1
              AND mutation.confirmation_deadline_ms <= $1
              AND mutation.state = 'reserved'
              AND mutation.provider_id = 'builtin'
              AND (
                  outbox.status = 'pending'
                  OR (
                      outbox.status = 'in_progress'
                      AND outbox.locked_at_ms <= $2
                  )
              )
            ORDER BY outbox.next_attempt_at_ms, outbox.sequence
            FOR UPDATE OF outbox SKIP LOCKED
            LIMIT 1
            ",
        )
        .bind(request.now().get())
        .bind(stale_before)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sql_error)?;
        let Some(row) = row else {
            commit(transaction).await?;
            return Ok(ClaimSecretMutationRecoveryOutcome::NoWork);
        };
        row.validate(request.now(), stale_before)?;
        let claim_generation = row
            .claim_generation
            .checked_add(1)
            .and_then(|value| u64::try_from(value).ok())
            .filter(|value| *value > 0)
            .ok_or(SecretManagementRepositoryError::CorruptData)?;
        let updated = sqlx::query(
            r"
            UPDATE secret_mutation_recovery_outbox
            SET status = 'in_progress',
                attempts = CASE WHEN status = 'pending' THEN 1 ELSE attempts END,
                claim_generation = claim_generation + 1,
                locked_by = $2, locked_at_ms = $3
            WHERE operation_id = $1
              AND status = $4
              AND attempts = $5
              AND claim_generation = $6
              AND locked_by IS NOT DISTINCT FROM $7
              AND locked_at_ms IS NOT DISTINCT FROM $8
              AND (
                  (
                      status = 'pending'
                      AND attempts = 0
                      AND claim_generation = 0
                      AND locked_by IS NULL
                      AND locked_at_ms IS NULL
                  )
                  OR (
                      status = 'in_progress'
                      AND locked_at_ms <= $9
                      AND locked_at_ms < $3
                  )
              )
            ",
        )
        .bind(row.operation_id)
        .bind(request.worker_id().as_str())
        .bind(request.now().get())
        .bind(&row.status)
        .bind(row.attempts)
        .bind(row.claim_generation)
        .bind(row.locked_by.as_deref())
        .bind(row.locked_at_ms)
        .bind(stale_before)
        .execute(&mut *transaction)
        .await
        .map_err(map_sql_error)?;
        if updated.rows_affected() != 1 {
            return Err(SecretManagementRepositoryError::CorruptData);
        }
        let task = row.into_task(&request, claim_generation)?;
        commit(transaction).await?;
        Ok(ClaimSecretMutationRecoveryOutcome::Claimed(task))
    }

    #[allow(clippy::too_many_lines)]
    async fn recover_secret_mutation_reservation(
        &self,
        request: RecoverSecretMutationReservation,
    ) -> Result<RecoverSecretMutationReservationOutcome, SecretManagementRepositoryError> {
        let mut transaction = begin(&self.pool).await?;
        let initial =
            load_recovery_fence(&mut transaction, request.fence().operation_id(), false).await?;
        let Some(initial) = initial else {
            commit(transaction).await?;
            return Ok(RecoverSecretMutationReservationOutcome::NotFound);
        };
        let preliminary = load_secret_mutation(
            &mut transaction,
            &initial.tenant_id,
            initial.mutation_id,
            false,
        )
        .await?
        .ok_or(SecretManagementRepositoryError::CorruptData)?;
        if initial.operation_id
            != recovery_operation_id(&initial.tenant_id, preliminary.mutation_id)
            || initial.mutation_id != preliminary.mutation_id
        {
            return Err(SecretManagementRepositoryError::CorruptData);
        }
        if preliminary.state != "reserved" {
            let outcome = terminal_recovery_outcome(
                &initial,
                &preliminary,
                request.fence(),
                request.recovered_at(),
                request.reconciliation(),
            )?;
            commit(transaction).await?;
            return Ok(outcome);
        }
        if request.recovered_at().get() < preliminary.confirmation_deadline_ms {
            return Err(SecretManagementRepositoryError::InvalidRequest);
        }
        let repository_id = preliminary
            .repository_scope()?
            .ok_or(SecretManagementRepositoryError::CorruptData)?;
        let authority_is_current = reserved_actor_has_current_authority(
            &mut transaction,
            &preliminary,
            request.recovered_at().get(),
            repository_id,
        )
        .await?;
        if !repository_exists(&mut transaction, &initial.tenant_id, repository_id, true).await? {
            return Err(SecretManagementRepositoryError::CorruptData);
        }
        let provider_is_builtin: Option<String> = sqlx::query_scalar(
            r"
            SELECT provider_id FROM secret_providers
            WHERE tenant_id = $1 AND provider_id = 'builtin'
            FOR SHARE
            ",
        )
        .bind(&initial.tenant_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sql_error)?;
        if provider_is_builtin.as_deref() != Some(BUILTIN_SECRET_PROVIDER_ID) {
            return Err(SecretManagementRepositoryError::CorruptData);
        }
        let secret =
            load_secret_for_update(&mut transaction, &initial.tenant_id, preliminary.secret_id)
                .await?
                .ok_or(SecretManagementRepositoryError::CorruptData)?;
        let mutation = load_secret_mutation(
            &mut transaction,
            &initial.tenant_id,
            preliminary.mutation_id,
            true,
        )
        .await?
        .ok_or(SecretManagementRepositoryError::CorruptData)?;
        if mutation.state != "reserved" {
            let recovery =
                load_recovery_fence(&mut transaction, request.fence().operation_id(), true)
                    .await?
                    .ok_or(SecretManagementRepositoryError::CorruptData)?;
            let outcome = terminal_recovery_outcome(
                &recovery,
                &mutation,
                request.fence(),
                request.recovered_at(),
                request.reconciliation(),
            )?;
            commit(transaction).await?;
            return Ok(outcome);
        }
        if request.recovered_at().get() < mutation.confirmation_deadline_ms
            || mutation.secret_id != secret.id
            || mutation.provider_id != BUILTIN_SECRET_PROVIDER_ID
        {
            return Err(SecretManagementRepositoryError::CorruptData);
        }
        let recovery = load_recovery_fence(&mut transaction, request.fence().operation_id(), true)
            .await?
            .ok_or(SecretManagementRepositoryError::CorruptData)?;
        if !recovery.matches_live_fence(request.fence())
            || recovery.tenant_id != initial.tenant_id
            || recovery.mutation_id != mutation.mutation_id
        {
            commit(transaction).await?;
            return Ok(RecoverSecretMutationReservationOutcome::FenceRejected);
        }

        let staged = sqlx::query_as::<_, RecoveryStageRow>(
            r"
            SELECT version.id AS version_id, version.version_number,
                   lifecycle.status, lifecycle.revision
            FROM secret_versions AS version
            JOIN secret_version_lifecycle AS lifecycle
              ON lifecycle.tenant_id = version.tenant_id
             AND lifecycle.secret_version_id = version.id
            WHERE version.tenant_id = $1
              AND version.provider_id = $2
              AND version.create_request_id = $3
              AND lifecycle.mutation_id = $4
            FOR UPDATE OF version, lifecycle
            ",
        )
        .bind(&initial.tenant_id)
        .bind(&mutation.provider_id)
        .bind(&mutation.provider_create_request_id)
        .bind(mutation.mutation_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sql_error)?;
        if let Some(stage) = staged.as_ref()
            && (stage.version_id.is_nil()
                || stage.version_number != mutation.reserved_version_number
                || stage.status != "staged"
                || stage.revision <= 0)
        {
            return Err(SecretManagementRepositoryError::CorruptData);
        }
        match (request.reconciliation(), staged.as_ref()) {
            (SecretMutationRecoveryReconciliation::DefinitivelyNotCommitted, None) => {}
            (SecretMutationRecoveryReconciliation::AlreadyCommitted(target), Some(stage))
                if target.secret_id().as_uuid() == mutation.secret_id
                    && target.version_id().as_uuid() == stage.version_id
                    && i64::try_from(target.version_number()).ok()
                        == Some(stage.version_number) => {}
            _ => return Err(SecretManagementRepositoryError::CorruptData),
        }
        let expiration_authority = if authority_is_current {
            "current"
        } else {
            "lost"
        };
        let (terminal_reason, abandoned_version_id, abandoned_version_number) = staged
            .as_ref()
            .map_or(("reservation_expired_no_stage", None, None), |stage| {
                (
                    "reservation_expired_staged",
                    Some(stage.version_id),
                    Some(stage.version_number),
                )
            });
        let expired = sqlx::query(
            r"
            UPDATE secret_version_mutations
            SET state = 'cancelled', completion_kind = 'reservation_expired',
                confirmed_at_ms = $3, terminal_actor_kind = 'system',
                terminal_reason = $4, expiration_authority = $5,
                abandoned_version_id = $6, abandoned_version_number = $7,
                revision = revision + 1
            WHERE tenant_id = $1 AND mutation_id = $2
              AND state = 'reserved' AND revision = $8
              AND confirmation_deadline_ms <= $3
            ",
        )
        .bind(&initial.tenant_id)
        .bind(mutation.mutation_id)
        .bind(request.recovered_at().get())
        .bind(terminal_reason)
        .bind(expiration_authority)
        .bind(abandoned_version_id)
        .bind(abandoned_version_number)
        .bind(mutation.revision)
        .execute(&mut *transaction)
        .await
        .map_err(map_sql_error)?;
        if expired.rows_affected() != 1 {
            return Err(SecretManagementRepositoryError::CorruptData);
        }

        if mutation.kind()? == RepositorySecretMutationKind::Create {
            let deleted = sqlx::query(
                r"
                UPDATE secrets
                SET status = 'deleted', revision = revision + 1,
                    updated_at_ms = GREATEST(updated_at_ms, $3),
                    deleted_at_ms = GREATEST(created_at_ms, $3)
                WHERE tenant_id = $1 AND id = $2
                  AND status = 'provisioning' AND revision = $4
                  AND current_version_id IS NULL
                  AND current_version_number IS NULL
                ",
            )
            .bind(&initial.tenant_id)
            .bind(mutation.secret_id)
            .bind(request.recovered_at().get())
            .bind(mutation.reserved_secret_revision)
            .execute(&mut *transaction)
            .await
            .map_err(map_sql_error)?;
            if deleted.rows_affected() != 1 {
                return Err(SecretManagementRepositoryError::CorruptData);
            }
        }

        if let Some(stage) = staged {
            let destroy_request_id = provider_destroy_request_id(stage.version_id);
            let transitioned = sqlx::query(
                r"
                UPDATE secret_version_lifecycle
                SET status = 'destroy_pending', destroy_request_id = $3,
                    revision = revision + 1, changed_by_principal_id = NULL,
                    changed_at_ms = GREATEST(changed_at_ms, $4)
                WHERE tenant_id = $1 AND secret_version_id = $2
                  AND status = 'staged' AND revision = $5
                ",
            )
            .bind(&initial.tenant_id)
            .bind(stage.version_id)
            .bind(&destroy_request_id)
            .bind(request.recovered_at().get())
            .bind(stage.revision)
            .execute(&mut *transaction)
            .await
            .map_err(map_sql_error)?;
            if transitioned.rows_affected() != 1 {
                return Err(SecretManagementRepositoryError::CorruptData);
            }
            let cleanup_id =
                cleanup_operation_id(&initial.tenant_id, mutation.secret_id, stage.version_id);
            sqlx::query(
                r"
                INSERT INTO secret_cleanup_outbox (
                    operation_id, tenant_id, provider_id, cleanup_kind,
                    secret_id, secret_version_id, version_number,
                    status, attempts, next_attempt_at_ms,
                    claim_generation, created_at_ms
                ) VALUES (
                    $1, $2, $3, 'destroy_secret_version', $4, $5, $6,
                    'pending', 0, $7, 0, $7
                )
                ON CONFLICT (operation_id) DO NOTHING
                ",
            )
            .bind(cleanup_id)
            .bind(&initial.tenant_id)
            .bind(&mutation.provider_id)
            .bind(mutation.secret_id)
            .bind(stage.version_id)
            .bind(stage.version_number)
            .bind(request.recovered_at().get())
            .execute(&mut *transaction)
            .await
            .map_err(map_sql_error)?;
            verify_cleanup_identity(
                &mut transaction,
                cleanup_id,
                &initial.tenant_id,
                &mutation.provider_id,
                mutation.secret_id,
                stage.version_id,
                stage.version_number,
            )
            .await?;
        }
        append_system_audit(
            &mut transaction,
            &initial.tenant_id,
            request.recovered_at().get(),
            SECRET_EXPIRE_ACTION,
            SECRET_MUTATION_RESOURCE_KIND,
            &mutation.mutation_id.hyphenated().to_string(),
        )
        .await?;
        let outcome = if abandoned_version_id.is_some() {
            RecoverSecretMutationReservationOutcome::ExpiredWithCleanup
        } else {
            RecoverSecretMutationReservationOutcome::ExpiredWithoutStage
        };
        commit(transaction).await?;
        Ok(outcome)
    }
}

#[derive(FromRow)]
struct ActorRow {
    session_authorization_revision: i64,
    session_provider_id: String,
    session_provider_subject: String,
    session_kind: String,
    session_audience: String,
    issued_at_ms: i64,
    idle_expires_at_ms: i64,
    expires_at_ms: i64,
    revoked_at_ms: Option<i64>,
    principal_status: String,
    membership_status: String,
    current_authorization_revision: i64,
}

struct AuthorizedActor {
    tenant_id: String,
    principal_id: Uuid,
    session_id: Uuid,
    provider_id: String,
    provider_subject: String,
    authorization_revision: i64,
    now_ms: i64,
}

enum ActorAuthentication {
    Active(AuthorizedActor),
    Stale,
}

/// Exact actor identity retained after transactional session and permission
/// reauthorization for a sibling control-plane mutation.
pub(super) struct AuthorizedHumanRepositoryAction {
    pub(super) tenant_id: String,
    pub(super) principal_id: Uuid,
    pub(super) session_id: Uuid,
    pub(super) authorization_revision: i64,
    pub(super) request_id: Option<String>,
}

/// Reauthorizes one existing human session for an exact repository-scoped
/// permission while retaining the row locks for the caller's transaction.
///
/// `Ok(None)` deliberately combines stale sessions and denied permissions.
pub(super) async fn authorize_human_repository_action(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &ManagementActor,
    permission: &str,
    repository_id: Uuid,
) -> Result<Option<AuthorizedHumanRepositoryAction>, StoreError> {
    // Blob publication precedes logical admission. Refresh lifecycle checks
    // from the database clock at the transactional boundary so a session that
    // expired while immutable evidence was being published cannot authorize a
    // dispatch with its earlier ingress timestamp.
    let now_seconds =
        sqlx::query_scalar::<_, i64>("SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT")
            .fetch_one(&mut **transaction)
            .await
            .map_err(map_sql_error)
            .map_err(map_human_action_error)?;
    let now_seconds = u64::try_from(now_seconds)
        .map_err(|_| StoreError::corrupt_data("database clock is outside the auth time domain"))?;
    let current_actor = ManagementActor::new(
        actor.tenant_id().clone(),
        actor.principal_id().clone(),
        actor.session_id().clone(),
        actor.authorization_revision(),
        actor.request_id().cloned(),
        UnixTimestamp::from_seconds(now_seconds),
    );
    let authenticated = authenticate_actor(transaction, &current_actor)
        .await
        .map_err(map_human_action_error)?;
    let ActorAuthentication::Active(authorized) = authenticated else {
        return Ok(None);
    };
    if !actor_has_permission(transaction, &authorized, permission, Some(repository_id))
        .await
        .map_err(map_human_action_error)?
    {
        return Ok(None);
    }
    Ok(Some(AuthorizedHumanRepositoryAction {
        tenant_id: authorized.tenant_id,
        principal_id: authorized.principal_id,
        session_id: authorized.session_id,
        authorization_revision: authorized.authorization_revision,
        request_id: actor.request_id().map(|value| value.as_str().to_owned()),
    }))
}

fn map_human_action_error(error: SecretManagementRepositoryError) -> StoreError {
    match error {
        SecretManagementRepositoryError::Unavailable => StoreError::operation(error),
        SecretManagementRepositoryError::InvalidRequest => {
            StoreError::corrupt_data("authenticated human action carried invalid actor evidence")
        }
        SecretManagementRepositoryError::CorruptData => {
            StoreError::corrupt_data("durable human authorization evidence is corrupt")
        }
    }
}

async fn reserved_actor_has_current_authority(
    transaction: &mut Transaction<'_, Postgres>,
    mutation: &SecretMutationRow,
    now_ms: i64,
    repository_id: Uuid,
) -> Result<bool, SecretManagementRepositoryError> {
    if now_ms < 0
        || mutation.reserved_by_principal_id.is_nil()
        || mutation.reserved_by_session_id.is_nil()
        || mutation.reserved_authorization_revision <= 0
    {
        return Err(SecretManagementRepositoryError::CorruptData);
    }
    let row = sqlx::query_as::<_, ActorRow>(
        r"
        SELECT session.authorization_revision AS session_authorization_revision,
               session.provider_id AS session_provider_id,
               session.provider_subject AS session_provider_subject,
               session.session_kind, session.audience AS session_audience,
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
        FOR UPDATE OF session, principal, membership
        ",
    )
    .bind(&mutation.tenant_id)
    .bind(mutation.reserved_by_principal_id)
    .bind(mutation.reserved_by_session_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_sql_error)?;
    let Some(row) = row else {
        return Ok(false);
    };
    if row.session_authorization_revision <= 0 || row.current_authorization_revision <= 0 {
        return Err(SecretManagementRepositoryError::CorruptData);
    }
    if !matches!(
        (row.session_kind.as_str(), row.session_audience.as_str()),
        ("browser", "automata.web") | ("cli", "automata.cli")
    ) {
        return Err(SecretManagementRepositoryError::CorruptData);
    }
    if !matches!(
        (
            row.principal_status.as_str(),
            row.membership_status.as_str()
        ),
        ("active", "active")
    ) || row.revoked_at_ms.is_some()
        || row.issued_at_ms > now_ms
        || row.idle_expires_at_ms <= now_ms
        || row.expires_at_ms <= now_ms
        || row.session_authorization_revision != mutation.reserved_authorization_revision
        || row.current_authorization_revision != mutation.reserved_authorization_revision
    {
        return Ok(false);
    }
    let actor = AuthorizedActor {
        tenant_id: mutation.tenant_id.clone(),
        principal_id: mutation.reserved_by_principal_id,
        session_id: mutation.reserved_by_session_id,
        provider_id: row.session_provider_id,
        provider_subject: row.session_provider_subject,
        authorization_revision: row.current_authorization_revision,
        now_ms,
    };
    actor_has_permission(
        transaction,
        &actor,
        mutation_permission(mutation.kind()?),
        Some(repository_id),
    )
    .await
}

async fn authenticate_actor(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &ManagementActor,
) -> Result<ActorAuthentication, SecretManagementRepositoryError> {
    let principal_id = canonical_uuid(actor.principal_id().as_str())?;
    let session_id = canonical_uuid(actor.session_id().as_str())?;
    let now_ms = actor
        .now()
        .as_seconds()
        .checked_mul(1_000)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(SecretManagementRepositoryError::InvalidRequest)?;
    let expected_revision = i64::try_from(actor.authorization_revision().value())
        .map_err(|_| SecretManagementRepositoryError::InvalidRequest)?;
    let row = sqlx::query_as::<_, ActorRow>(
        r"
        SELECT session.authorization_revision AS session_authorization_revision,
               session.provider_id AS session_provider_id,
               session.provider_subject AS session_provider_subject,
               session.session_kind, session.audience AS session_audience,
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
        FOR UPDATE OF session, principal, membership
        ",
    )
    .bind(actor.tenant_id().as_str())
    .bind(principal_id)
    .bind(session_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_sql_error)?;
    let Some(row) = row else {
        return Ok(ActorAuthentication::Stale);
    };
    if row.session_authorization_revision <= 0 || row.current_authorization_revision <= 0 {
        return Err(SecretManagementRepositoryError::CorruptData);
    }
    if !matches!(
        (row.session_kind.as_str(), row.session_audience.as_str()),
        ("browser", "automata.web") | ("cli", "automata.cli")
    ) {
        return Err(SecretManagementRepositoryError::CorruptData);
    }
    match (
        row.principal_status.as_str(),
        row.membership_status.as_str(),
    ) {
        ("active", "active") => {}
        ("disabled", "active" | "suspended") | ("active", "suspended") => {
            return Ok(ActorAuthentication::Stale);
        }
        _ => return Err(SecretManagementRepositoryError::CorruptData),
    }
    if row.revoked_at_ms.is_some()
        || row.issued_at_ms > now_ms
        || row.idle_expires_at_ms <= now_ms
        || row.expires_at_ms <= now_ms
        || row.session_authorization_revision != row.current_authorization_revision
        || expected_revision != row.current_authorization_revision
    {
        return Ok(ActorAuthentication::Stale);
    }
    Ok(ActorAuthentication::Active(AuthorizedActor {
        tenant_id: actor.tenant_id().as_str().to_owned(),
        principal_id,
        session_id,
        provider_id: row.session_provider_id,
        provider_subject: row.session_provider_subject,
        authorization_revision: row.current_authorization_revision,
        now_ms,
    }))
}

async fn actor_has_permission(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &AuthorizedActor,
    permission: &str,
    repository_id: Option<Uuid>,
) -> Result<bool, SecretManagementRepositoryError> {
    let direct: bool = sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM rbac_role_bindings AS binding
            JOIN rbac_role_permissions AS role_permission
              ON role_permission.tenant_id = binding.tenant_id
             AND role_permission.role_id = binding.role_id
            WHERE binding.tenant_id = $1
              AND binding.principal_id = $2
              AND binding.status = 'active'
              AND (binding.valid_until_ms IS NULL OR binding.valid_until_ms > $3)
              AND role_permission.permission_name = $4
              AND (
                  (
                      binding.scope_kind = 'tenant'
                      AND binding.repository_id IS NULL
                      AND binding.runner_group_id IS NULL
                  ) OR (
                      $5::UUID IS NOT NULL
                      AND binding.scope_kind = 'repository'
                      AND binding.repository_id = $5
                      AND binding.runner_group_id IS NULL
                  )
              )
        )
        ",
    )
    .bind(&actor.tenant_id)
    .bind(actor.principal_id)
    .bind(actor.now_ms)
    .bind(permission)
    .bind(repository_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_sql_error)?;
    if direct || actor.provider_id != "github" {
        return Ok(direct);
    }
    actor_has_github_mapping_permission(transaction, actor, permission, repository_id).await
}

#[derive(FromRow)]
struct GithubAuthoritySnapshotRow {
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
    token_principal_id: Option<Uuid>,
    token_version: Option<i64>,
    token_issued_at_ms: Option<i64>,
    token_access_expires_at_ms: Option<i64>,
    token_revoked_at_ms: Option<i64>,
}

#[allow(clippy::too_many_lines)]
async fn actor_has_github_mapping_permission(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &AuthorizedActor,
    permission: &str,
    repository_id: Option<Uuid>,
) -> Result<bool, SecretManagementRepositoryError> {
    let canonical_subject = actor
        .provider_subject
        .parse::<u64>()
        .ok()
        .filter(|subject| *subject > 0)
        .is_some_and(|subject| subject.to_string() == actor.provider_subject);
    if !canonical_subject {
        return Err(SecretManagementRepositoryError::CorruptData);
    }
    let snapshots = sqlx::query_as::<_, GithubAuthoritySnapshotRow>(
        r"
        SELECT snapshot.tenant_id, snapshot.id, snapshot.principal_id,
               snapshot.provider_id, snapshot.provider_subject,
               snapshot.provider_token_version, snapshot.observed_at_ms,
               snapshot.valid_until_ms,
               identity.principal_id AS identity_principal_id,
               identity.provider_subject AS identity_provider_subject,
               token.principal_id AS token_principal_id,
               token.version AS token_version,
               token.issued_at_ms AS token_issued_at_ms,
               token.access_expires_at_ms AS token_access_expires_at_ms,
               token.revoked_at_ms AS token_revoked_at_ms
        FROM github_membership_snapshots AS snapshot
        LEFT JOIN human_provider_identities AS identity
          ON identity.principal_id = snapshot.principal_id
         AND identity.provider_id = snapshot.provider_id
         AND identity.provider_subject = snapshot.provider_subject
        LEFT JOIN LATERAL (
            SELECT provider_token.principal_id, provider_token.version,
                   provider_token.issued_at_ms,
                   provider_token.access_expires_at_ms,
                   provider_token.revoked_at_ms
            FROM human_provider_tokens AS provider_token
            WHERE provider_token.tenant_id = snapshot.tenant_id
              AND provider_token.provider_id = snapshot.provider_id
              AND provider_token.provider_subject = snapshot.provider_subject
            ORDER BY (provider_token.revoked_at_ms IS NULL) DESC,
                     provider_token.version DESC
            LIMIT 1
        ) AS token ON TRUE
        WHERE snapshot.tenant_id = $1
          AND snapshot.principal_id = $2
          AND snapshot.provider_id = 'github'
          AND snapshot.provider_subject = $3
          AND snapshot.observed_at_ms <= $4
        ORDER BY snapshot.observed_at_ms DESC, snapshot.id DESC
        LIMIT 2
        ",
    )
    .bind(&actor.tenant_id)
    .bind(actor.principal_id)
    .bind(&actor.provider_subject)
    .bind(actor.now_ms)
    .fetch_all(&mut **transaction)
    .await
    .map_err(map_sql_error)?;
    let Some(snapshot) = snapshots.first() else {
        return Ok(false);
    };
    if snapshots
        .get(1)
        .is_some_and(|other| other.observed_at_ms == snapshot.observed_at_ms)
        || snapshot.tenant_id != actor.tenant_id
        || snapshot.id.is_nil()
        || snapshot.principal_id != actor.principal_id
        || snapshot.provider_id != "github"
        || snapshot.provider_subject != actor.provider_subject
        || snapshot.provider_token_version <= 0
        || snapshot.observed_at_ms < 0
        || snapshot.valid_until_ms <= snapshot.observed_at_ms
        || snapshot.identity_principal_id != Some(actor.principal_id)
        || snapshot.identity_provider_subject.as_deref() != Some(actor.provider_subject.as_str())
    {
        return Err(SecretManagementRepositoryError::CorruptData);
    }
    if snapshot.valid_until_ms <= actor.now_ms {
        return Ok(false);
    }
    let Some(token_version) = snapshot.token_version else {
        return Ok(false);
    };
    if snapshot.token_revoked_at_ms.is_some() {
        return Ok(false);
    }
    if snapshot.token_principal_id != Some(actor.principal_id)
        || token_version <= 0
        || token_version != snapshot.provider_token_version
        || snapshot
            .token_issued_at_ms
            .is_none_or(|issued| issued < 0 || issued > snapshot.observed_at_ms)
        || snapshot.token_access_expires_at_ms.is_some_and(|expires| {
            expires <= snapshot.observed_at_ms
                || snapshot.valid_until_ms > expires
                || expires <= actor.now_ms
        })
    {
        return Ok(false);
    }

    sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM github_role_mappings AS mapping
            JOIN rbac_role_permissions AS role_permission
              ON role_permission.tenant_id = mapping.tenant_id
             AND role_permission.role_id = mapping.role_id
            WHERE mapping.tenant_id = $1
              AND mapping.provider_id = 'github'
              AND mapping.status = 'active'
              AND role_permission.permission_name = $3
              AND (
                  (
                      mapping.scope_kind = 'tenant'
                      AND mapping.repository_id IS NULL
                      AND mapping.runner_group_id IS NULL
                  ) OR (
                      $4::UUID IS NOT NULL
                      AND mapping.scope_kind = 'repository'
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
    .bind(&actor.tenant_id)
    .bind(snapshot.id)
    .bind(permission)
    .bind(repository_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_sql_error)
}

#[derive(FromRow)]
#[allow(clippy::struct_excessive_bools)] // Exact closed capability columns from the durable row.
struct ProviderRow {
    provider_id: String,
    adapter_kind: String,
    supports_create_version: bool,
    supports_destroy_version: bool,
    supports_dynamic_leases: bool,
    supports_renew_leases: bool,
    supports_revoke_leases: bool,
    is_default: bool,
    status: String,
    health: String,
    revision: i64,
    updated_at_ms: i64,
}

fn validate_builtin_provider(row: &ProviderRow) -> Result<(), SecretManagementRepositoryError> {
    if row.provider_id != BUILTIN_SECRET_PROVIDER_ID
        || row.adapter_kind != BUILTIN_ADAPTER_KIND
        || !row.supports_create_version
        || !row.supports_destroy_version
        || row.supports_dynamic_leases
        || row.supports_renew_leases
        || row.supports_revoke_leases
        || !row.is_default
        || !matches!(row.status.as_str(), "unconfigured" | "active" | "disabled")
        || !matches!(
            row.health.as_str(),
            "unknown" | "healthy" | "degraded" | "unavailable"
        )
    {
        return Err(SecretManagementRepositoryError::CorruptData);
    }
    revision(row.revision)?;
    timestamp(row.updated_at_ms)?;
    Ok(())
}

fn builtin_provider_metadata(
    row: &ProviderRow,
) -> Result<BuiltinSecretProviderMetadata, SecretManagementRepositoryError> {
    Ok(BuiltinSecretProviderMetadata::new(
        builtin_provider_state(row)?,
        revision(row.revision)?,
        timestamp(row.updated_at_ms)?,
    ))
}

fn builtin_provider_inspection(
    row: &ProviderRow,
    actor_can_manage: bool,
) -> Result<BuiltinSecretProviderInspection, SecretManagementRepositoryError> {
    Ok(BuiltinSecretProviderInspection::from_durable_parts(
        builtin_provider_state(row)?,
        builtin_provider_health(row)?,
        revision(row.revision)?,
        actor_can_manage,
    ))
}

fn builtin_provider_state(
    row: &ProviderRow,
) -> Result<BuiltinSecretProviderState, SecretManagementRepositoryError> {
    Ok(match row.status.as_str() {
        "unconfigured" => BuiltinSecretProviderState::Unconfigured,
        "active" => BuiltinSecretProviderState::Active,
        "disabled" => BuiltinSecretProviderState::Disabled,
        _ => return Err(SecretManagementRepositoryError::CorruptData),
    })
}

fn builtin_provider_health(
    row: &ProviderRow,
) -> Result<BuiltinSecretProviderHealth, SecretManagementRepositoryError> {
    Ok(match row.health.as_str() {
        "unknown" => BuiltinSecretProviderHealth::Unknown,
        "healthy" => BuiltinSecretProviderHealth::Healthy,
        "degraded" => BuiltinSecretProviderHealth::Degraded,
        "unavailable" => BuiltinSecretProviderHealth::Unavailable,
        _ => return Err(SecretManagementRepositoryError::CorruptData),
    })
}

#[derive(Clone, FromRow)]
struct SecretMutationRow {
    tenant_id: String,
    mutation_id: Uuid,
    secret_id: Uuid,
    scope_kind: String,
    repository_id: Option<Uuid>,
    environment_id: Option<Uuid>,
    canonical_name: String,
    provider_id: String,
    requested_provider_id: Option<String>,
    mutation_kind: String,
    expected_secret_revision: Option<i64>,
    reserved_secret_revision: i64,
    reserved_version_number: i64,
    confirmation_deadline_ms: i64,
    expected_predecessor_version_id: Option<Uuid>,
    expected_predecessor_version_number: Option<i64>,
    provider_create_request_id: String,
    state: String,
    completion_kind: Option<String>,
    committed_version_id: Option<Uuid>,
    committed_version_number: Option<i64>,
    confirmed_secret_revision: Option<i64>,
    reserved_by_principal_id: Uuid,
    reserved_by_session_id: Uuid,
    reserved_authorization_revision: i64,
    reserved_at_ms: i64,
    confirmed_by_principal_id: Option<Uuid>,
    confirmed_by_session_id: Option<Uuid>,
    confirmed_authorization_revision: Option<i64>,
    confirmed_at_ms: Option<i64>,
    terminal_actor_kind: Option<String>,
    terminal_reason: Option<String>,
    expiration_authority: Option<String>,
    abandoned_version_id: Option<Uuid>,
    abandoned_version_number: Option<i64>,
    revision: i64,
}

impl SecretMutationRow {
    fn reserved_actor_matches(&self, actor: &AuthorizedActor) -> bool {
        self.tenant_id == actor.tenant_id
            && self.reserved_by_principal_id == actor.principal_id
            && self.reserved_by_session_id == actor.session_id
            && self.reserved_authorization_revision == actor.authorization_revision
    }

    fn repository_scope(&self) -> Result<Option<Uuid>, SecretManagementRepositoryError> {
        match (
            self.scope_kind.as_str(),
            self.repository_id,
            self.environment_id,
        ) {
            ("repository", Some(repository_id), None) if !repository_id.is_nil() => {
                Ok(Some(repository_id))
            }
            ("tenant", None, None) => Ok(None),
            ("environment", Some(repository_id), Some(environment_id))
                if !repository_id.is_nil() && !environment_id.is_nil() =>
            {
                Ok(None)
            }
            _ => Err(SecretManagementRepositoryError::CorruptData),
        }
    }

    fn kind(&self) -> Result<RepositorySecretMutationKind, SecretManagementRepositoryError> {
        match self.mutation_kind.as_str() {
            "create" => Ok(RepositorySecretMutationKind::Create),
            "replace" => Ok(RepositorySecretMutationKind::Replace),
            _ => Err(SecretManagementRepositoryError::CorruptData),
        }
    }

    fn mutation_id(
        &self,
        secret_id: RepositorySecretId,
    ) -> Result<RepositorySecretMutationId, SecretManagementRepositoryError> {
        RepositorySecretMutationId::from_uuid(self.mutation_id, secret_id)
            .map_err(|_| SecretManagementRepositoryError::CorruptData)
    }

    fn secret_id(&self) -> Result<RepositorySecretId, SecretManagementRepositoryError> {
        RepositorySecretId::from_uuid(self.secret_id)
            .map_err(|_| SecretManagementRepositoryError::CorruptData)
    }

    fn predecessor(
        &self,
    ) -> Result<Option<BuiltinRepositorySecretVersion>, SecretManagementRepositoryError> {
        match (
            self.kind()?,
            self.expected_predecessor_version_id,
            self.expected_predecessor_version_number,
        ) {
            (RepositorySecretMutationKind::Create, None, None) => Ok(None),
            (RepositorySecretMutationKind::Replace, Some(version_id), Some(version_number)) => {
                Ok(Some(builtin_target(
                    self.secret_id()?,
                    version_id,
                    version_number,
                )?))
            }
            _ => Err(SecretManagementRepositoryError::CorruptData),
        }
    }

    fn receipt(
        &self,
    ) -> Result<RepositorySecretVersionMutationReceipt, SecretManagementRepositoryError> {
        let secret_id = self.secret_id()?;
        let mutation_id = self.mutation_id(secret_id)?;
        let committed = builtin_target(
            secret_id,
            self.committed_version_id
                .ok_or(SecretManagementRepositoryError::CorruptData)?,
            self.committed_version_number
                .ok_or(SecretManagementRepositoryError::CorruptData)?,
        )?;
        Ok(RepositorySecretVersionMutationReceipt::new(
            mutation_id,
            committed,
        ))
    }

    fn matches_reservation(
        &self,
        request: &ReserveRepositorySecretVersionMutation,
        actor: &AuthorizedActor,
    ) -> Result<bool, SecretManagementRepositoryError> {
        let expected_revision = request
            .expected_revision()
            .map(ManagementRevision::value)
            .map(i64::try_from)
            .transpose()
            .map_err(|_| SecretManagementRepositoryError::InvalidRequest)?;
        Ok(self.mutation_id == request.mutation_id().as_uuid()
            && self.secret_id == request.secret_id().as_uuid()
            && self.scope_kind == "repository"
            && self.repository_id == Some(request.repository_id().as_uuid())
            && self.environment_id.is_none()
            && self.canonical_name == request.name().as_str()
            && self.requested_provider_id.as_deref()
                == request.provider_id().map(ManagedSecretProviderId::as_str)
            && self.kind()? == request.kind()
            && self.expected_secret_revision == expected_revision
            && self.reserved_by_principal_id == actor.principal_id
            && self.reserved_by_session_id == actor.session_id
            && self.reserved_authorization_revision == actor.authorization_revision
            && self.provider_create_request_id == provider_create_request_id(request.mutation_id()))
    }

    fn reserve_outcome(
        &self,
    ) -> Result<ReserveRepositorySecretVersionMutationOutcome, SecretManagementRepositoryError>
    {
        match self.state.as_str() {
            "reserved"
                if self.completion_kind.is_none()
                    && self.confirmed_by_principal_id.is_none()
                    && self.confirmed_by_session_id.is_none()
                    && self.confirmed_authorization_revision.is_none()
                    && self.confirmed_at_ms.is_none()
                    && self.confirmed_secret_revision.is_none()
                    && self.terminal_actor_kind.is_none()
                    && self.terminal_reason.is_none()
                    && self.expiration_authority.is_none()
                    && self.abandoned_version_id.is_none()
                    && self.abandoned_version_number.is_none() =>
            {
                let secret_id = self.secret_id()?;
                Ok(
                    ReserveRepositorySecretVersionMutationOutcome::ReconcileRequired(
                        RepositorySecretVersionMutationReservation::new(
                            self.mutation_id(secret_id)?,
                            secret_id,
                            RepositoryId::from_uuid(
                                self.repository_scope()?
                                    .ok_or(SecretManagementRepositoryError::CorruptData)?,
                            ),
                            RepositorySecretName::new(&self.canonical_name)
                                .map_err(|_| SecretManagementRepositoryError::CorruptData)?,
                            ManagedSecretProviderId::new(self.provider_id.clone())
                                .map_err(|_| SecretManagementRepositoryError::CorruptData)?,
                            self.kind()?,
                            revision(self.reserved_secret_revision)?,
                            positive_u64(self.reserved_version_number)?,
                            timestamp(self.confirmation_deadline_ms)?,
                            self.predecessor()?,
                            self.provider_create_request_id.clone(),
                        ),
                    ),
                )
            }
            "confirmed"
                if self.completion_kind.as_deref() == Some("builtin_created")
                    && self.terminal_reason.is_none() =>
            {
                Ok(ReserveRepositorySecretVersionMutationOutcome::Applied(
                    self.receipt()?,
                ))
            }
            "superseded"
                if self.completion_kind.as_deref() == Some("builtin_created")
                    && self.terminal_reason.as_deref() == Some("applied_then_superseded") =>
            {
                Ok(
                    ReserveRepositorySecretVersionMutationOutcome::AppliedThenSuperseded(
                        self.receipt()?,
                    ),
                )
            }
            "superseded"
                if self.completion_kind.as_deref() == Some("builtin_created")
                    && self.terminal_reason.as_deref() == Some("applied_then_deleted") =>
            {
                Ok(
                    ReserveRepositorySecretVersionMutationOutcome::AppliedThenDeleted(
                        self.receipt()?,
                    ),
                )
            }
            "cancelled"
                if self.completion_kind.as_deref() == Some("cas_lost")
                    && self.terminal_reason.as_deref() == Some("cas_lost") =>
            {
                Ok(ReserveRepositorySecretVersionMutationOutcome::CasLost)
            }
            "cancelled"
                if self.completion_kind.as_deref() == Some("system_cancelled")
                    && self.terminal_reason.as_deref() == Some("secret_deleted") =>
            {
                Ok(ReserveRepositorySecretVersionMutationOutcome::Cancelled)
            }
            "cancelled"
                if self.completion_kind.as_deref() == Some("reservation_expired")
                    && matches!(
                        self.expiration_authority.as_deref(),
                        Some("current" | "lost")
                    )
                    && ((self.terminal_reason.as_deref()
                        == Some("reservation_expired_no_stage")
                        && self.abandoned_version_id.is_none()
                        && self.abandoned_version_number.is_none())
                        || (self.terminal_reason.as_deref()
                            == Some("reservation_expired_staged")
                            && self.abandoned_version_id.is_some()
                            && self.abandoned_version_number
                                == Some(self.reserved_version_number))) =>
            {
                Ok(ReserveRepositorySecretVersionMutationOutcome::Expired)
            }
            _ => Err(SecretManagementRepositoryError::CorruptData),
        }
    }

    fn confirm_outcome(
        &self,
        result: RepositorySecretProviderMutationResult,
    ) -> Result<ConfirmRepositorySecretVersionMutationOutcome, SecretManagementRepositoryError>
    {
        match self.reserve_outcome()? {
            ReserveRepositorySecretVersionMutationOutcome::Applied(receipt) => {
                if result
                    == RepositorySecretProviderMutationResult::BuiltinCreated(receipt.committed())
                {
                    Ok(ConfirmRepositorySecretVersionMutationOutcome::Applied(
                        receipt,
                    ))
                } else {
                    Ok(ConfirmRepositorySecretVersionMutationOutcome::Conflict)
                }
            }
            ReserveRepositorySecretVersionMutationOutcome::AppliedThenSuperseded(receipt) => {
                if result
                    == RepositorySecretProviderMutationResult::BuiltinCreated(receipt.committed())
                {
                    Ok(
                        ConfirmRepositorySecretVersionMutationOutcome::AppliedThenSuperseded(
                            receipt,
                        ),
                    )
                } else {
                    Ok(ConfirmRepositorySecretVersionMutationOutcome::Conflict)
                }
            }
            ReserveRepositorySecretVersionMutationOutcome::AppliedThenDeleted(receipt) => {
                if result
                    == RepositorySecretProviderMutationResult::BuiltinCreated(receipt.committed())
                {
                    Ok(ConfirmRepositorySecretVersionMutationOutcome::AppliedThenDeleted(receipt))
                } else {
                    Ok(ConfirmRepositorySecretVersionMutationOutcome::Conflict)
                }
            }
            ReserveRepositorySecretVersionMutationOutcome::CasLost => {
                if result == RepositorySecretProviderMutationResult::CasLost {
                    Ok(ConfirmRepositorySecretVersionMutationOutcome::CasLost)
                } else {
                    Ok(ConfirmRepositorySecretVersionMutationOutcome::Conflict)
                }
            }
            ReserveRepositorySecretVersionMutationOutcome::Cancelled => {
                Ok(ConfirmRepositorySecretVersionMutationOutcome::Cancelled)
            }
            ReserveRepositorySecretVersionMutationOutcome::Expired => {
                Ok(ConfirmRepositorySecretVersionMutationOutcome::Expired)
            }
            ReserveRepositorySecretVersionMutationOutcome::FreshReservation(_)
            | ReserveRepositorySecretVersionMutationOutcome::ReconcileRequired(_)
            | ReserveRepositorySecretVersionMutationOutcome::Forbidden
            | ReserveRepositorySecretVersionMutationOutcome::SessionStale
            | ReserveRepositorySecretVersionMutationOutcome::NotFound
            | ReserveRepositorySecretVersionMutationOutcome::Conflict
            | ReserveRepositorySecretVersionMutationOutcome::RevisionConflict { .. }
            | ReserveRepositorySecretVersionMutationOutcome::ProviderUnavailable => {
                Err(SecretManagementRepositoryError::CorruptData)
            }
        }
    }

    fn head_has_changed(
        &self,
        secret: &LockedSecretRow,
    ) -> Result<bool, SecretManagementRepositoryError> {
        if secret.id != self.secret_id
            || secret.repository_id != self.repository_id
            || secret.environment_id != self.environment_id
            || secret.scope_kind != self.scope_kind
            || secret.canonical_name != self.canonical_name
            || secret.provider_id != self.provider_id
            || secret.status == "deleted"
        {
            return Err(SecretManagementRepositoryError::CorruptData);
        }
        Ok(match self.kind()? {
            RepositorySecretMutationKind::Create => {
                secret.status != "provisioning"
                    || secret.revision != self.reserved_secret_revision
                    || secret.current_version_id.is_some()
                    || secret.current_version_number.is_some()
            }
            RepositorySecretMutationKind::Replace => {
                secret.revision != self.reserved_secret_revision
                    || secret.current_version_id != self.expected_predecessor_version_id
                    || secret.current_version_number != self.expected_predecessor_version_number
            }
        })
    }
}

async fn load_secret_mutation(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    mutation_id: Uuid,
    lock: bool,
) -> Result<Option<SecretMutationRow>, SecretManagementRepositoryError> {
    let statement = if lock {
        r"
        SELECT tenant_id, mutation_id, secret_id, scope_kind, repository_id,
               environment_id, canonical_name,
               provider_id, requested_provider_id, mutation_kind,
               expected_secret_revision, reserved_secret_revision,
               reserved_version_number, confirmation_deadline_ms,
               expected_predecessor_version_id,
               expected_predecessor_version_number,
               provider_create_request_id, state, completion_kind,
               committed_version_id, committed_version_number,
               confirmed_secret_revision, reserved_by_principal_id,
               reserved_by_session_id, reserved_authorization_revision,
               reserved_at_ms, confirmed_by_principal_id,
               confirmed_by_session_id, confirmed_authorization_revision,
               confirmed_at_ms, terminal_actor_kind, terminal_reason,
               expiration_authority, abandoned_version_id,
               abandoned_version_number, revision
        FROM secret_version_mutations
        WHERE tenant_id = $1 AND mutation_id = $2
        FOR UPDATE
        "
    } else {
        r"
        SELECT tenant_id, mutation_id, secret_id, scope_kind, repository_id,
               environment_id, canonical_name,
               provider_id, requested_provider_id, mutation_kind,
               expected_secret_revision, reserved_secret_revision,
               reserved_version_number, confirmation_deadline_ms,
               expected_predecessor_version_id,
               expected_predecessor_version_number,
               provider_create_request_id, state, completion_kind,
               committed_version_id, committed_version_number,
               confirmed_secret_revision, reserved_by_principal_id,
               reserved_by_session_id, reserved_authorization_revision,
               reserved_at_ms, confirmed_by_principal_id,
               confirmed_by_session_id, confirmed_authorization_revision,
               confirmed_at_ms, terminal_actor_kind, terminal_reason,
               expiration_authority, abandoned_version_id,
               abandoned_version_number, revision
        FROM secret_version_mutations
        WHERE tenant_id = $1 AND mutation_id = $2
        "
    };
    sqlx::query_as::<_, SecretMutationRow>(statement)
        .bind(tenant_id)
        .bind(mutation_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(map_sql_error)
}

async fn load_secret_provider(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    secret_id: Uuid,
) -> Result<Option<String>, SecretManagementRepositoryError> {
    sqlx::query_scalar("SELECT provider_id FROM secrets WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(secret_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(map_sql_error)
}

fn mutation_kind(kind: RepositorySecretMutationKind) -> &'static str {
    match kind {
        RepositorySecretMutationKind::Create => "create",
        RepositorySecretMutationKind::Replace => "replace",
    }
}

fn decode_mutation_kind(
    kind: &str,
) -> Result<RepositorySecretMutationKind, SecretManagementRepositoryError> {
    match kind {
        "create" => Ok(RepositorySecretMutationKind::Create),
        "replace" => Ok(RepositorySecretMutationKind::Replace),
        _ => Err(SecretManagementRepositoryError::CorruptData),
    }
}

const fn mutation_permission(kind: RepositorySecretMutationKind) -> &'static str {
    match kind {
        RepositorySecretMutationKind::Create => SECRET_CREATE_PERMISSION,
        RepositorySecretMutationKind::Replace => SECRET_UPDATE_PERMISSION,
    }
}

fn builtin_target(
    secret_id: RepositorySecretId,
    version_id: Uuid,
    version_number: i64,
) -> Result<BuiltinRepositorySecretVersion, SecretManagementRepositoryError> {
    let version_id = RepositorySecretVersionId::from_uuid(version_id)
        .map_err(|_| SecretManagementRepositoryError::CorruptData)?;
    let version_number = positive_u64(version_number)?;
    BuiltinRepositorySecretVersion::new(secret_id, version_id, version_number)
        .map_err(|_| SecretManagementRepositoryError::CorruptData)
}

#[derive(FromRow)]
struct StagedMutationWinnerRow {
    id: Uuid,
    secret_id: Uuid,
    version_number: i64,
    provider_id: String,
    create_request_id: String,
    storage_kind: String,
    lifecycle_status: String,
    lifecycle_mutation_id: Uuid,
    lifecycle_revision: i64,
    adapter_kind: String,
    supports_create_version: bool,
    builtin_envelope_count: i64,
    external_locator_count: i64,
    external_version_count: i64,
}

#[allow(clippy::too_many_lines)]
async fn verify_staged_mutation_winner(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    mutation: &SecretMutationRow,
    target: BuiltinRepositorySecretVersion,
    secret: &LockedSecretRow,
) -> Result<Option<StagedMutationWinnerRow>, SecretManagementRepositoryError> {
    if target.secret_id().as_uuid() != mutation.secret_id {
        return Ok(None);
    }
    if secret.id != mutation.secret_id
        || secret.repository_id != mutation.repository_id
        || secret.environment_id != mutation.environment_id
        || secret.scope_kind != mutation.scope_kind
        || secret.canonical_name != mutation.canonical_name
        || secret.provider_id != mutation.provider_id
    {
        return Err(SecretManagementRepositoryError::CorruptData);
    }
    let row = sqlx::query_as::<_, StagedMutationWinnerRow>(
        r"
        SELECT version.id, version.secret_id, version.version_number,
               version.provider_id, version.create_request_id,
               version.storage_kind, lifecycle.status AS lifecycle_status,
               lifecycle.mutation_id AS lifecycle_mutation_id,
               lifecycle.revision AS lifecycle_revision,
               provider.adapter_kind, provider.supports_create_version,
               (
                   SELECT count(*)
                   FROM secret_version_envelope_heads AS head
                   JOIN secret_version_envelopes AS envelope
                     ON envelope.tenant_id = head.tenant_id
                    AND envelope.secret_version_id = head.secret_version_id
                    AND envelope.envelope_generation = head.envelope_generation
                   WHERE head.tenant_id = version.tenant_id
                     AND head.secret_version_id = version.id
               ) AS builtin_envelope_count,
               (
                   SELECT
                       (SELECT count(*)
                        FROM secret_provider_locator_envelope_heads
                        WHERE tenant_id = version.tenant_id
                          AND secret_id = version.secret_id)
                     + (SELECT count(*)
                        FROM secret_provider_locator_envelopes
                        WHERE tenant_id = version.tenant_id
                          AND secret_id = version.secret_id)
               ) AS external_locator_count,
               (
                   SELECT
                       (SELECT count(*)
                        FROM secret_provider_version_envelope_heads
                        WHERE tenant_id = version.tenant_id
                          AND secret_version_id = version.id)
                     + (SELECT count(*)
                        FROM secret_provider_version_envelopes
                        WHERE tenant_id = version.tenant_id
                          AND secret_version_id = version.id)
               ) AS external_version_count
        FROM secret_versions AS version
        JOIN secret_version_lifecycle AS lifecycle
          ON lifecycle.tenant_id = version.tenant_id
         AND lifecycle.secret_version_id = version.id
        JOIN secret_providers AS provider
          ON provider.tenant_id = version.tenant_id
         AND provider.provider_id = version.provider_id
        WHERE version.tenant_id = $1
          AND version.provider_id = $2
          AND version.create_request_id = $3
        FOR SHARE OF version, lifecycle, provider
        ",
    )
    .bind(tenant_id)
    .bind(&mutation.provider_id)
    .bind(&mutation.provider_create_request_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_sql_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let Ok(target_number) = i64::try_from(target.version_number()) else {
        return Ok(None);
    };
    if row.id != target.version_id().as_uuid() || row.version_number != target_number {
        return Ok(None);
    }
    if row.secret_id != mutation.secret_id
        || row.provider_id != BUILTIN_SECRET_PROVIDER_ID
        || row.create_request_id != mutation.provider_create_request_id
        || row.storage_kind != BUILTIN_STORAGE_KIND
        || row.lifecycle_status != "staged"
        || row.lifecycle_mutation_id != mutation.mutation_id
        || row.lifecycle_revision <= 0
        || row.adapter_kind != BUILTIN_ADAPTER_KIND
        || !row.supports_create_version
        || row.builtin_envelope_count != 1
        || row.external_locator_count != 0
        || row.external_version_count != 0
    {
        return Err(SecretManagementRepositoryError::CorruptData);
    }
    match mutation.kind()? {
        RepositorySecretMutationKind::Create => {
            if row.version_number != 1
                || secret.status != "provisioning"
                || secret.revision != mutation.reserved_secret_revision
                || secret.current_version_id.is_some()
                || secret.current_version_number.is_some()
            {
                return Err(SecretManagementRepositoryError::CorruptData);
            }
        }
        RepositorySecretMutationKind::Replace => {
            if row.version_number != mutation.reserved_version_number
                || mutation
                    .expected_predecessor_version_number
                    .is_none_or(|number| row.version_number <= number)
                || secret.status != "active"
                || secret.revision != mutation.reserved_secret_revision
                || secret.current_version_id != mutation.expected_predecessor_version_id
                || secret.current_version_number != mutation.expected_predecessor_version_number
            {
                return Err(SecretManagementRepositoryError::CorruptData);
            }
        }
    }
    Ok(Some(row))
}

async fn is_confirmed_active_predecessor(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    predecessor: BuiltinRepositorySecretVersion,
) -> Result<bool, SecretManagementRepositoryError> {
    sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM secret_version_lifecycle AS lifecycle
            JOIN secret_version_mutations AS receipt
              ON receipt.tenant_id = lifecycle.tenant_id
             AND receipt.mutation_id = lifecycle.mutation_id
            WHERE lifecycle.tenant_id = $1
              AND lifecycle.secret_version_id = $2
              AND lifecycle.secret_id = $3
              AND lifecycle.version_number = $4
              AND lifecycle.provider_id = 'builtin'
              AND lifecycle.status = 'active'
              AND receipt.secret_id = lifecycle.secret_id
              AND receipt.provider_id = lifecycle.provider_id
              AND receipt.state = 'confirmed'
              AND receipt.completion_kind = 'builtin_created'
              AND receipt.committed_version_id = lifecycle.secret_version_id
              AND receipt.committed_version_number = lifecycle.version_number
              AND receipt.confirmed_secret_revision =
                  receipt.reserved_secret_revision + 1
        )
        ",
    )
    .bind(tenant_id)
    .bind(predecessor.version_id().as_uuid())
    .bind(predecessor.secret_id().as_uuid())
    .bind(
        i64::try_from(predecessor.version_number())
            .map_err(|_| SecretManagementRepositoryError::InvalidRequest)?,
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_sql_error)
}

#[derive(FromRow)]
struct ConfirmedPredecessorRow {
    version_id: Uuid,
    lifecycle_revision: i64,
    mutation_id: Uuid,
    mutation_revision: i64,
}

async fn load_confirmed_predecessor_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    mutation: &SecretMutationRow,
) -> Result<Option<ConfirmedPredecessorRow>, SecretManagementRepositoryError> {
    sqlx::query_as::<_, ConfirmedPredecessorRow>(
        r"
        SELECT lifecycle.secret_version_id AS version_id,
               lifecycle.revision AS lifecycle_revision,
               receipt.mutation_id, receipt.revision AS mutation_revision
        FROM secret_version_lifecycle AS lifecycle
        JOIN secret_version_mutations AS receipt
          ON receipt.tenant_id = lifecycle.tenant_id
         AND receipt.mutation_id = lifecycle.mutation_id
        WHERE lifecycle.tenant_id = $1
          AND lifecycle.secret_version_id = $2
          AND lifecycle.secret_id = $3
          AND lifecycle.version_number = $4
          AND lifecycle.provider_id = $5
          AND lifecycle.status = 'active'
          AND receipt.secret_id = lifecycle.secret_id
          AND receipt.provider_id = lifecycle.provider_id
          AND receipt.state = 'confirmed'
          AND receipt.completion_kind = 'builtin_created'
          AND receipt.committed_version_id = lifecycle.secret_version_id
          AND receipt.committed_version_number = lifecycle.version_number
          AND receipt.confirmed_secret_revision =
              receipt.reserved_secret_revision + 1
        FOR UPDATE OF lifecycle, receipt
        ",
    )
    .bind(tenant_id)
    .bind(mutation.expected_predecessor_version_id)
    .bind(mutation.secret_id)
    .bind(mutation.expected_predecessor_version_number)
    .bind(&mutation.provider_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_sql_error)
}

#[derive(FromRow)]
struct ProviderMutationWinnerRow {
    id: Uuid,
    secret_id: Uuid,
    version_number: i64,
    mutation_id: Option<Uuid>,
    lifecycle_status: Option<String>,
}

async fn load_provider_mutation_winner(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    mutation: &SecretMutationRow,
) -> Result<Option<ProviderMutationWinnerRow>, SecretManagementRepositoryError> {
    sqlx::query_as::<_, ProviderMutationWinnerRow>(
        r"
        SELECT version.id, version.secret_id, version.version_number,
               lifecycle.mutation_id, lifecycle.status AS lifecycle_status
        FROM secret_versions AS version
        LEFT JOIN secret_version_lifecycle AS lifecycle
          ON lifecycle.tenant_id = version.tenant_id
         AND lifecycle.secret_version_id = version.id
        WHERE version.tenant_id = $1
          AND version.provider_id = $2
          AND version.create_request_id = $3
        FOR SHARE OF version
        ",
    )
    .bind(tenant_id)
    .bind(&mutation.provider_id)
    .bind(&mutation.provider_create_request_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_sql_error)
}

fn provider_target_matches_winner(
    mutation: &SecretMutationRow,
    target: BuiltinRepositorySecretVersion,
    winner: &ProviderMutationWinnerRow,
) -> bool {
    i64::try_from(target.version_number()).is_ok_and(|target_number| {
        target.secret_id().as_uuid() == mutation.secret_id
            && winner.id == target.version_id().as_uuid()
            && winner.version_number == target_number
    })
}

fn terminal_expired_confirm_outcome(
    mutation: &SecretMutationRow,
    result: RepositorySecretProviderMutationResult,
    winner: Option<ProviderMutationWinnerRow>,
) -> Result<ConfirmRepositorySecretVersionMutationOutcome, SecretManagementRepositoryError> {
    if mutation.state != "cancelled"
        || mutation.completion_kind.as_deref() != Some("reservation_expired")
    {
        return Err(SecretManagementRepositoryError::CorruptData);
    }
    match mutation.terminal_reason.as_deref() {
        Some("reservation_expired_no_stage")
            if mutation.abandoned_version_id.is_none()
                && mutation.abandoned_version_number.is_none() =>
        {
            if winner.is_some() {
                return Err(SecretManagementRepositoryError::CorruptData);
            }
            Ok(
                if result == RepositorySecretProviderMutationResult::CasLost {
                    ConfirmRepositorySecretVersionMutationOutcome::Expired
                } else {
                    ConfirmRepositorySecretVersionMutationOutcome::Conflict
                },
            )
        }
        Some("reservation_expired_staged")
            if mutation.abandoned_version_id.is_some()
                && mutation.abandoned_version_number == Some(mutation.reserved_version_number) =>
        {
            let winner = winner.ok_or(SecretManagementRepositoryError::CorruptData)?;
            if winner.id.is_nil()
                || Some(winner.id) != mutation.abandoned_version_id
                || winner.secret_id != mutation.secret_id
                || winner.version_number != mutation.reserved_version_number
                || winner.mutation_id != Some(mutation.mutation_id)
                || !matches!(
                    winner.lifecycle_status.as_deref(),
                    Some("destroy_pending" | "destroyed")
                )
            {
                return Err(SecretManagementRepositoryError::CorruptData);
            }
            Ok(match result {
                RepositorySecretProviderMutationResult::BuiltinCreated(target)
                    if provider_target_matches_winner(mutation, target, &winner) =>
                {
                    ConfirmRepositorySecretVersionMutationOutcome::Expired
                }
                _ => ConfirmRepositorySecretVersionMutationOutcome::Conflict,
            })
        }
        _ => Err(SecretManagementRepositoryError::CorruptData),
    }
}

async fn terminal_confirm_outcome(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    mutation: &SecretMutationRow,
    result: RepositorySecretProviderMutationResult,
) -> Result<ConfirmRepositorySecretVersionMutationOutcome, SecretManagementRepositoryError> {
    if mutation.state == "cancelled"
        && mutation.completion_kind.as_deref() == Some("reservation_expired")
    {
        if mutation.reserve_outcome()? != ReserveRepositorySecretVersionMutationOutcome::Expired {
            return Err(SecretManagementRepositoryError::CorruptData);
        }
        let winner = load_provider_mutation_winner(transaction, tenant_id, mutation).await?;
        return terminal_expired_confirm_outcome(mutation, result, winner);
    }
    if mutation.state != "cancelled"
        || mutation.completion_kind.as_deref() != Some("system_cancelled")
        || mutation.terminal_reason.as_deref() != Some("secret_deleted")
    {
        return mutation.confirm_outcome(result);
    }

    let winner = load_provider_mutation_winner(transaction, tenant_id, mutation).await?;

    match (result, winner) {
        (RepositorySecretProviderMutationResult::CasLost, None) => {
            Ok(ConfirmRepositorySecretVersionMutationOutcome::Cancelled)
        }
        (RepositorySecretProviderMutationResult::BuiltinCreated(target), Some(winner)) => {
            let Ok(target_number) = i64::try_from(target.version_number()) else {
                return Ok(ConfirmRepositorySecretVersionMutationOutcome::Conflict);
            };
            if target.secret_id().as_uuid() != mutation.secret_id
                || winner.id != target.version_id().as_uuid()
                || winner.version_number != target_number
            {
                return Ok(ConfirmRepositorySecretVersionMutationOutcome::Conflict);
            }
            if winner.secret_id != mutation.secret_id
                || winner.mutation_id != Some(mutation.mutation_id)
                || !matches!(
                    winner.lifecycle_status.as_deref(),
                    Some("staged" | "destroy_pending" | "destroyed")
                )
            {
                return Err(SecretManagementRepositoryError::CorruptData);
            }
            Ok(ConfirmRepositorySecretVersionMutationOutcome::Cancelled)
        }
        _ => Ok(ConfirmRepositorySecretVersionMutationOutcome::Conflict),
    }
}

async fn audit_failed_mutation(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &AuthorizedActor,
    action: &'static str,
    resource_id: &str,
) -> Result<(), SecretManagementRepositoryError> {
    append_audit(
        transaction,
        actor,
        action,
        "failed",
        SECRET_RESOURCE_KIND,
        resource_id,
    )
    .await
}

#[derive(FromRow)]
struct CreateProviderRow {
    provider_id: String,
    adapter_kind: String,
    status: String,
    supports_create_version: bool,
}

impl CreateProviderRow {
    fn is_builtin(&self) -> bool {
        self.provider_id == BUILTIN_SECRET_PROVIDER_ID
            && self.adapter_kind == BUILTIN_ADAPTER_KIND
            && self.status == "active"
            && self.supports_create_version
    }
}

async fn select_create_provider(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    provider_id: Option<&str>,
) -> Result<Option<CreateProviderRow>, SecretManagementRepositoryError> {
    let row = sqlx::query_as::<_, CreateProviderRow>(
        r"
        SELECT provider_id, adapter_kind, status, supports_create_version
        FROM secret_providers
        WHERE tenant_id = $1
          AND (
              ($2::TEXT IS NOT NULL AND provider_id = $2)
              OR ($2::TEXT IS NULL AND is_default)
          )
        FOR UPDATE
        ",
    )
    .bind(tenant_id)
    .bind(provider_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_sql_error)?;
    Ok(row.filter(|row| row.status == "active" && row.supports_create_version))
}

#[derive(FromRow)]
struct SecretMetadataRow {
    id: Uuid,
    repository_id: Option<Uuid>,
    canonical_name: String,
    provider_id: String,
    current_version_id: Option<Uuid>,
    current_version_number: Option<i64>,
    status: String,
    revision: i64,
    created_at_ms: i64,
    updated_at_ms: i64,
}

impl SecretMetadataRow {
    fn into_metadata(
        self,
        expected_repository_id: RepositoryId,
    ) -> Result<RepositorySecretMetadata, SecretManagementRepositoryError> {
        if self.repository_id != Some(expected_repository_id.as_uuid())
            || self.updated_at_ms < self.created_at_ms
        {
            return Err(SecretManagementRepositoryError::CorruptData);
        }
        let (state, version) = match self.status.as_str() {
            "provisioning"
                if self.current_version_id.is_none() && self.current_version_number.is_none() =>
            {
                (RepositorySecretState::Provisioning, None)
            }
            "active" | "disabled"
                if self.current_version_id.is_some()
                    && self.current_version_number.is_some_and(|value| value > 0) =>
            {
                let state = if self.status == "active" {
                    RepositorySecretState::Active
                } else {
                    RepositorySecretState::Disabled
                };
                (
                    state,
                    Some(positive_u64(
                        self.current_version_number
                            .ok_or(SecretManagementRepositoryError::CorruptData)?,
                    )?),
                )
            }
            _ => return Err(SecretManagementRepositoryError::CorruptData),
        };
        Ok(RepositorySecretMetadata::from_durable_parts(
            RepositorySecretId::from_uuid(self.id)
                .map_err(|_| SecretManagementRepositoryError::CorruptData)?,
            expected_repository_id,
            RepositorySecretName::new(self.canonical_name)
                .map_err(|_| SecretManagementRepositoryError::CorruptData)?,
            ManagedSecretProviderId::new(self.provider_id)
                .map_err(|_| SecretManagementRepositoryError::CorruptData)?,
            state,
            version,
            revision(self.revision)?,
            timestamp(self.created_at_ms)?,
            timestamp(self.updated_at_ms)?,
        ))
    }
}

#[derive(FromRow)]
struct LockedSecretRow {
    id: Uuid,
    canonical_name: String,
    scope_kind: String,
    repository_id: Option<Uuid>,
    environment_id: Option<Uuid>,
    provider_id: String,
    current_version_id: Option<Uuid>,
    current_version_number: Option<i64>,
    status: String,
    revision: i64,
}

impl LockedSecretRow {
    fn matches_descriptor(&self, request: &ReserveRepositorySecretVersionMutation) -> bool {
        self.id == request.secret_id().as_uuid()
            && self.scope_kind == "repository"
            && self.repository_id == Some(request.repository_id().as_uuid())
            && self.environment_id.is_none()
            && self.canonical_name == request.name().as_str()
    }
}

async fn load_secret_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    secret_id: Uuid,
) -> Result<Option<LockedSecretRow>, SecretManagementRepositoryError> {
    sqlx::query_as::<_, LockedSecretRow>(
        r"
        SELECT id, canonical_name, scope_kind, repository_id, environment_id,
               provider_id, current_version_id, current_version_number,
               status, revision
        FROM secrets
        WHERE tenant_id = $1 AND id = $2
        FOR UPDATE
        ",
    )
    .bind(tenant_id)
    .bind(secret_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_sql_error)
}

async fn load_repository_secret_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    repository_id: Uuid,
    secret_id: Uuid,
) -> Result<Option<LockedSecretRow>, SecretManagementRepositoryError> {
    sqlx::query_as::<_, LockedSecretRow>(
        r"
        SELECT id, canonical_name, scope_kind, repository_id, environment_id,
               provider_id, current_version_id, current_version_number,
               status, revision
        FROM secrets
        WHERE tenant_id = $1 AND id = $2
          AND scope_kind = 'repository' AND repository_id = $3
          AND environment_id IS NULL
        FOR UPDATE
        ",
    )
    .bind(tenant_id)
    .bind(secret_id)
    .bind(repository_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_sql_error)
}

fn exact_repository_scope(
    row: &LockedSecretRow,
) -> Result<Option<Uuid>, SecretManagementRepositoryError> {
    match (
        row.scope_kind.as_str(),
        row.repository_id,
        row.environment_id,
    ) {
        ("repository", Some(repository_id), None) if !repository_id.is_nil() => {
            Ok(Some(repository_id))
        }
        ("tenant", None, None) | ("environment", Some(_), Some(_)) => Ok(None),
        _ => Err(SecretManagementRepositoryError::CorruptData),
    }
}

#[derive(FromRow)]
struct DeleteVersionRow {
    id: Uuid,
    version_number: i64,
    provider_id: String,
    status: String,
    destroy_request_id: Option<String>,
    revision: i64,
}

#[derive(FromRow)]
struct RecoveryClaimRow {
    operation_id: Uuid,
    tenant_id: String,
    mutation_id: Uuid,
    status: String,
    next_attempt_at_ms: i64,
    attempts: i32,
    claim_generation: i64,
    locked_by: Option<String>,
    locked_at_ms: Option<i64>,
    created_at_ms: i64,
    secret_id: Uuid,
    mutation_kind: String,
    provider_id: String,
    scope_kind: String,
    repository_id: Option<Uuid>,
    environment_id: Option<Uuid>,
    canonical_name: String,
    reserved_version_number: i64,
    expected_predecessor_version_id: Option<Uuid>,
    expected_predecessor_version_number: Option<i64>,
    provider_create_request_id: String,
    confirmation_deadline_ms: i64,
    state: String,
}

impl RecoveryClaimRow {
    fn validate(
        &self,
        now: UnixMillis,
        stale_before: i64,
    ) -> Result<(), SecretManagementRepositoryError> {
        let lock_shape = match self.status.as_str() {
            "pending" => {
                self.attempts == 0
                    && self.claim_generation == 0
                    && self.locked_by.is_none()
                    && self.locked_at_ms.is_none()
            }
            "in_progress" => {
                self.attempts == 1
                    && self.claim_generation > 0
                    && self.claim_generation < i64::MAX
                    && self.locked_by.as_ref().is_some_and(|value| {
                        !value.is_empty()
                            && value.len() <= 255
                            && !value.chars().any(char::is_control)
                    })
                    && self.locked_at_ms.is_some_and(|value| {
                        value >= self.next_attempt_at_ms
                            && value <= stale_before
                            && value < now.get()
                    })
            }
            _ => false,
        };
        if self.operation_id.is_nil()
            || self.tenant_id.is_empty()
            || self.mutation_id.is_nil()
            || self.secret_id.is_nil()
            || self.state != "reserved"
            || self.provider_id != BUILTIN_SECRET_PROVIDER_ID
            || self.scope_kind != "repository"
            || self.repository_id.is_none_or(|value| value.is_nil())
            || self.environment_id.is_some()
            || RepositorySecretName::new(&self.canonical_name).is_err()
            || self.reserved_version_number <= 0
            || self.provider_create_request_id
                != format!("secret-version:{}", self.mutation_id.hyphenated())
            || !matches!(self.mutation_kind.as_str(), "create" | "replace")
            || self.created_at_ms < 0
            || self.confirmation_deadline_ms <= self.created_at_ms
            || self.next_attempt_at_ms != self.confirmation_deadline_ms
            || self.confirmation_deadline_ms > now.get()
            || !lock_shape
            || self.operation_id != recovery_operation_id(&self.tenant_id, self.mutation_id)
        {
            return Err(SecretManagementRepositoryError::CorruptData);
        }
        match self.mutation_kind.as_str() {
            "create"
                if self.reserved_version_number == 1
                    && self.expected_predecessor_version_id.is_none()
                    && self.expected_predecessor_version_number.is_none() => {}
            "replace"
                if self
                    .expected_predecessor_version_id
                    .is_some_and(|value| !value.is_nil())
                    && self
                        .expected_predecessor_version_number
                        .is_some_and(|value| value > 0 && value < self.reserved_version_number) => {
            }
            _ => return Err(SecretManagementRepositoryError::CorruptData),
        }
        Ok(())
    }

    fn into_task(
        self,
        request: &ClaimSecretMutationRecovery,
        claim_generation: u64,
    ) -> Result<SecretMutationRecoveryTask, SecretManagementRepositoryError> {
        let secret_id = RepositorySecretId::from_uuid(self.secret_id)
            .map_err(|_| SecretManagementRepositoryError::CorruptData)?;
        let mutation_id = RepositorySecretMutationId::from_uuid(self.mutation_id, secret_id)
            .map_err(|_| SecretManagementRepositoryError::CorruptData)?;
        let predecessor = match (
            self.expected_predecessor_version_id,
            self.expected_predecessor_version_number,
        ) {
            (None, None) => None,
            (Some(version_id), Some(version_number)) => {
                Some(builtin_target(secret_id, version_id, version_number)?)
            }
            _ => return Err(SecretManagementRepositoryError::CorruptData),
        };
        let fence = SecretMutationRecoveryFence::new(
            self.operation_id,
            request.worker_id().clone(),
            claim_generation,
            request.now(),
        )
        .map_err(|_| SecretManagementRepositoryError::CorruptData)?;
        Ok(SecretMutationRecoveryTask::new(
            fence,
            TenantScope::from_authenticated_tenant_id(self.tenant_id)
                .map_err(|_| SecretManagementRepositoryError::CorruptData)?,
            mutation_id,
            secret_id,
            ManagedSecretProviderId::new(self.provider_id)
                .map_err(|_| SecretManagementRepositoryError::CorruptData)?,
            RepositoryId::from_uuid(
                self.repository_id
                    .ok_or(SecretManagementRepositoryError::CorruptData)?,
            ),
            RepositorySecretName::new(self.canonical_name)
                .map_err(|_| SecretManagementRepositoryError::CorruptData)?,
            decode_mutation_kind(&self.mutation_kind)?,
            positive_u64(self.reserved_version_number)?,
            predecessor,
            self.provider_create_request_id,
            timestamp(self.confirmation_deadline_ms)?,
        ))
    }
}

#[derive(FromRow)]
struct RecoveryFenceRow {
    operation_id: Uuid,
    tenant_id: String,
    mutation_id: Uuid,
    status: String,
    attempts: i32,
    claim_generation: i64,
    locked_by: Option<String>,
    locked_at_ms: Option<i64>,
    completed_by: Option<String>,
    completed_claim_generation: Option<i64>,
    completed_locked_at_ms: Option<i64>,
    resolution: Option<String>,
    completed_at_ms: Option<i64>,
}

impl RecoveryFenceRow {
    fn matches_live_fence(&self, fence: &SecretMutationRecoveryFence) -> bool {
        self.operation_id == fence.operation_id()
            && self.status == "in_progress"
            && self.attempts == 1
            && u64::try_from(self.claim_generation).ok() == Some(fence.claim_generation())
            && self.locked_by.as_deref() == Some(fence.worker_id().as_str())
            && self.locked_at_ms == Some(fence.locked_at().get())
            && self.completed_by.is_none()
            && self.completed_claim_generation.is_none()
            && self.completed_locked_at_ms.is_none()
            && self.resolution.is_none()
            && self.completed_at_ms.is_none()
    }

    fn completed_recovery_outcome(
        &self,
        fence: &SecretMutationRecoveryFence,
    ) -> Option<RecoverSecretMutationReservationOutcome> {
        if self.operation_id != fence.operation_id()
            || self.status != "completed"
            || self.attempts != 1
            || self.locked_by.is_some()
            || self.locked_at_ms.is_some()
            || self.completed_by.as_deref() != Some(fence.worker_id().as_str())
            || u64::try_from(self.claim_generation).ok() != Some(fence.claim_generation())
            || self.completed_claim_generation != Some(self.claim_generation)
            || self.completed_locked_at_ms != Some(fence.locked_at().get())
            || self.completed_at_ms.is_none()
        {
            return None;
        }
        match self.resolution.as_deref() {
            Some("expired_without_stage") => {
                Some(RecoverSecretMutationReservationOutcome::ExpiredWithoutStage)
            }
            Some("expired_with_cleanup") => {
                Some(RecoverSecretMutationReservationOutcome::ExpiredWithCleanup)
            }
            _ => None,
        }
    }
}

fn terminal_recovery_outcome(
    recovery: &RecoveryFenceRow,
    mutation: &SecretMutationRow,
    fence: &SecretMutationRecoveryFence,
    recovered_at: UnixMillis,
    reconciliation: SecretMutationRecoveryReconciliation,
) -> Result<RecoverSecretMutationReservationOutcome, SecretManagementRepositoryError> {
    if mutation.state == "reserved" {
        return Err(SecretManagementRepositoryError::CorruptData);
    }
    if mutation.completion_kind.as_deref() != Some("reservation_expired") {
        return Ok(RecoverSecretMutationReservationOutcome::AlreadyTerminal);
    }
    let Some(outcome) = recovery.completed_recovery_outcome(fence) else {
        return Ok(RecoverSecretMutationReservationOutcome::FenceRejected);
    };
    if recovery.completed_at_ms != Some(recovered_at.get()) {
        return Ok(RecoverSecretMutationReservationOutcome::FenceRejected);
    }
    if mutation.state != "cancelled"
        || mutation.terminal_actor_kind.as_deref() != Some("system")
        || !matches!(
            mutation.expiration_authority.as_deref(),
            Some("current" | "lost")
        )
        || mutation.confirmed_at_ms != recovery.completed_at_ms
    {
        return Err(SecretManagementRepositoryError::CorruptData);
    }
    let durable_shape = match outcome {
        RecoverSecretMutationReservationOutcome::ExpiredWithoutStage => {
            mutation.terminal_reason.as_deref() == Some("reservation_expired_no_stage")
                && mutation.abandoned_version_id.is_none()
                && mutation.abandoned_version_number.is_none()
        }
        RecoverSecretMutationReservationOutcome::ExpiredWithCleanup => {
            mutation.terminal_reason.as_deref() == Some("reservation_expired_staged")
                && mutation.abandoned_version_id.is_some()
                && mutation.abandoned_version_number == Some(mutation.reserved_version_number)
        }
        RecoverSecretMutationReservationOutcome::AlreadyTerminal
        | RecoverSecretMutationReservationOutcome::FenceRejected
        | RecoverSecretMutationReservationOutcome::NotFound => false,
    };
    if !durable_shape {
        return Err(SecretManagementRepositoryError::CorruptData);
    }
    let evidence_matches = match (outcome, reconciliation) {
        (
            RecoverSecretMutationReservationOutcome::ExpiredWithoutStage,
            SecretMutationRecoveryReconciliation::DefinitivelyNotCommitted,
        ) => true,
        (
            RecoverSecretMutationReservationOutcome::ExpiredWithCleanup,
            SecretMutationRecoveryReconciliation::AlreadyCommitted(target),
        ) => {
            target.secret_id().as_uuid() == mutation.secret_id
                && Some(target.version_id().as_uuid()) == mutation.abandoned_version_id
                && i64::try_from(target.version_number()).ok() == mutation.abandoned_version_number
        }
        _ => false,
    };
    if !evidence_matches {
        return Ok(RecoverSecretMutationReservationOutcome::FenceRejected);
    }
    Ok(outcome)
}

async fn load_recovery_fence(
    transaction: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
    lock: bool,
) -> Result<Option<RecoveryFenceRow>, SecretManagementRepositoryError> {
    let statement = if lock {
        r"
        SELECT operation_id, tenant_id, mutation_id, status, attempts,
               claim_generation, locked_by, locked_at_ms, completed_by,
               completed_claim_generation,
               completed_locked_at_ms, resolution, completed_at_ms
        FROM secret_mutation_recovery_outbox
        WHERE operation_id = $1
        FOR UPDATE
        "
    } else {
        r"
        SELECT operation_id, tenant_id, mutation_id, status, attempts,
               claim_generation, locked_by, locked_at_ms, completed_by,
               completed_claim_generation,
               completed_locked_at_ms, resolution, completed_at_ms
        FROM secret_mutation_recovery_outbox
        WHERE operation_id = $1
        "
    };
    sqlx::query_as::<_, RecoveryFenceRow>(statement)
        .bind(operation_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(map_sql_error)
}

#[derive(FromRow)]
struct RecoveryStageRow {
    version_id: Uuid,
    version_number: i64,
    status: String,
    revision: i64,
}

#[derive(FromRow)]
struct CleanupIdentityRow {
    tenant_id: String,
    provider_id: String,
    cleanup_kind: String,
    provider_lease_record_id: Option<Uuid>,
    secret_id: Option<Uuid>,
    secret_version_id: Option<Uuid>,
    version_number: Option<i64>,
    envelope_generation: Option<i64>,
}

#[allow(clippy::too_many_arguments)]
async fn verify_cleanup_identity(
    transaction: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
    tenant_id: &str,
    provider_id: &str,
    secret_id: Uuid,
    version_id: Uuid,
    version_number: i64,
) -> Result<(), SecretManagementRepositoryError> {
    let row = sqlx::query_as::<_, CleanupIdentityRow>(
        r"
        SELECT tenant_id, provider_id, cleanup_kind,
               provider_lease_record_id, secret_id, secret_version_id,
               version_number, envelope_generation
        FROM secret_cleanup_outbox
        WHERE operation_id = $1
        FOR UPDATE
        ",
    )
    .bind(operation_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_sql_error)?
    .ok_or(SecretManagementRepositoryError::CorruptData)?;
    if row.tenant_id != tenant_id
        || row.provider_id != provider_id
        || row.cleanup_kind != "destroy_secret_version"
        || row.provider_lease_record_id.is_some()
        || row.secret_id != Some(secret_id)
        || row.secret_version_id != Some(version_id)
        || row.version_number != Some(version_number)
        || row.envelope_generation.is_some()
    {
        return Err(SecretManagementRepositoryError::CorruptData);
    }
    Ok(())
}

#[derive(FromRow)]
struct CleanupClaimRow {
    operation_id: Uuid,
    tenant_id: String,
    provider_id: String,
    cleanup_kind: String,
    provider_lease_record_id: Option<Uuid>,
    secret_id: Option<Uuid>,
    secret_version_id: Option<Uuid>,
    version_number: Option<i64>,
    envelope_generation: Option<i64>,
    outbox_status: String,
    attempts: i32,
    claim_generation: i64,
    next_attempt_at_ms: i64,
    locked_by: Option<String>,
    locked_at_ms: Option<i64>,
    completed_at_ms: Option<i64>,
    adapter_kind: String,
    supports_destroy_version: bool,
    canonical_name: String,
    scope_kind: String,
    repository_id: Option<Uuid>,
    environment_id: Option<Uuid>,
    secret_status: String,
    current_version_id: Option<Uuid>,
    lifecycle_status: String,
    destroy_request_id: Option<String>,
    mutation_state: String,
    mutation_completion_kind: Option<String>,
    mutation_terminal_reason: Option<String>,
    mutation_kind: String,
    abandoned_version_id: Option<Uuid>,
    abandoned_version_number: Option<i64>,
}

impl CleanupClaimRow {
    fn validate(&self) -> Result<(), SecretManagementRepositoryError> {
        let version_id = self
            .secret_version_id
            .ok_or(SecretManagementRepositoryError::CorruptData)?;
        let attempts_are_claimable = match self.outbox_status.as_str() {
            "pending" => (0..i32::from(MAX_SECRET_CLEANUP_ATTEMPTS)).contains(&self.attempts),
            "in_progress" => (1..=i32::from(MAX_SECRET_CLEANUP_ATTEMPTS)).contains(&self.attempts),
            _ => false,
        };
        let expired_replacement_cleanup =
            matches!(self.secret_status.as_str(), "active" | "disabled")
                && self.mutation_kind == "replace"
                && self.mutation_state == "cancelled"
                && self.mutation_completion_kind.as_deref() == Some("reservation_expired")
                && self.mutation_terminal_reason.as_deref() == Some("reservation_expired_staged")
                && self.abandoned_version_id == Some(version_id)
                && self.abandoned_version_number == self.version_number
                && self.current_version_id != Some(version_id);
        if self.operation_id.is_nil()
            || self.tenant_id.is_empty()
            || self.provider_id != BUILTIN_SECRET_PROVIDER_ID
            || self.cleanup_kind != "destroy_secret_version"
            || self.provider_lease_record_id.is_some()
            || self.secret_id.is_none_or(|value| value.is_nil())
            || version_id.is_nil()
            || self.version_number.is_none_or(|value| value <= 0)
            || self.envelope_generation.is_some()
            || !attempts_are_claimable
            || self.claim_generation < 0
            || self.next_attempt_at_ms < 0
            || (self.outbox_status == "pending"
                && (self.locked_by.is_some() || self.locked_at_ms.is_some()))
            || (self.outbox_status == "in_progress"
                && (self.locked_by.is_none() || self.locked_at_ms.is_none()))
            || self.completed_at_ms.is_some()
            || self.adapter_kind != BUILTIN_ADAPTER_KIND
            || !self.supports_destroy_version
            || self.scope_kind != "repository"
            || self.repository_id.is_none_or(|value| value.is_nil())
            || self.environment_id.is_some()
            || !(self.secret_status == "deleted" || expired_replacement_cleanup)
            || !matches!(
                self.lifecycle_status.as_str(),
                "destroy_pending" | "destroyed"
            )
            || self.destroy_request_id.as_deref() != Some(&provider_destroy_request_id(version_id))
        {
            return Err(SecretManagementRepositoryError::CorruptData);
        }
        Ok(())
    }
}

#[derive(FromRow)]
struct CleanupFenceRow {
    tenant_id: String,
    provider_id: String,
    cleanup_kind: String,
    secret_version_id: Option<Uuid>,
    status: String,
    attempts: i32,
    claim_generation: i64,
    locked_by: Option<String>,
    locked_at_ms: Option<i64>,
}

impl CleanupFenceRow {
    fn matches_fence(&self, fence: &SecretCleanupFence) -> bool {
        self.provider_id == BUILTIN_SECRET_PROVIDER_ID
            && self.cleanup_kind == "destroy_secret_version"
            && self.status == "in_progress"
            && self.attempts > 0
            && u64::try_from(self.claim_generation).ok() == Some(fence.claim_generation())
            && self.locked_by.as_deref() == Some(fence.worker_id().as_str())
            && self.locked_at_ms == Some(fence.locked_at().get())
    }
}

async fn load_cleanup_fence(
    transaction: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
) -> Result<Option<CleanupFenceRow>, SecretManagementRepositoryError> {
    sqlx::query_as::<_, CleanupFenceRow>(
        r"
        SELECT tenant_id, provider_id, cleanup_kind, secret_version_id,
               status, attempts, claim_generation, locked_by, locked_at_ms
        FROM secret_cleanup_outbox
        WHERE operation_id = $1
        FOR UPDATE
        ",
    )
    .bind(operation_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_sql_error)
}

async fn durable_envelope_count(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    version_id: Uuid,
) -> Result<i64, SecretManagementRepositoryError> {
    sqlx::query_scalar(
        r"
        SELECT
            (SELECT count(*) FROM secret_version_envelopes
             WHERE tenant_id = $1 AND secret_version_id = $2)
          + (SELECT count(*) FROM secret_version_envelope_heads
             WHERE tenant_id = $1 AND secret_version_id = $2)
          + (SELECT count(*) FROM secret_provider_version_envelopes
             WHERE tenant_id = $1 AND secret_version_id = $2)
          + (SELECT count(*) FROM secret_provider_version_envelope_heads
             WHERE tenant_id = $1 AND secret_version_id = $2)
        ",
    )
    .bind(tenant_id)
    .bind(version_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_sql_error)
}

async fn repository_exists(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    repository_id: Uuid,
    lock: bool,
) -> Result<bool, SecretManagementRepositoryError> {
    let query = if lock {
        "SELECT id FROM repositories WHERE tenant_id = $1 AND id = $2 FOR UPDATE"
    } else {
        "SELECT id FROM repositories WHERE tenant_id = $1 AND id = $2 FOR SHARE"
    };
    Ok(sqlx::query_scalar::<_, Uuid>(query)
        .bind(tenant_id)
        .bind(repository_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(map_sql_error)?
        .is_some())
}

async fn append_audit(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &AuthorizedActor,
    action: &'static str,
    outcome: &'static str,
    resource_kind: &'static str,
    resource_id: &str,
) -> Result<(), SecretManagementRepositoryError> {
    sqlx::query(
        r"
        INSERT INTO security_audit_events (
            event_id, tenant_id, occurred_at_ms, actor_kind,
            actor_principal_id, actor_session_id, authorization_revision,
            action, outcome, resource_kind, resource_id, request_id
        ) VALUES ($1, $2, $3, 'human', $4, $5, $6, $7, $8, $9, $10, NULL)
        ",
    )
    .bind(Uuid::new_v4())
    .bind(&actor.tenant_id)
    .bind(actor.now_ms)
    .bind(actor.principal_id)
    .bind(actor.session_id)
    .bind(actor.authorization_revision)
    .bind(action)
    .bind(outcome)
    .bind(resource_kind)
    .bind(resource_id)
    .execute(&mut **transaction)
    .await
    .map_err(map_sql_error)?;
    Ok(())
}

async fn append_system_audit(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    occurred_at_ms: i64,
    action: &str,
    resource_kind: &str,
    resource_id: &str,
) -> Result<(), SecretManagementRepositoryError> {
    sqlx::query(
        r"
        INSERT INTO security_audit_events (
            event_id, tenant_id, occurred_at_ms, actor_kind,
            actor_principal_id, actor_session_id, authorization_revision,
            action, outcome, resource_kind, resource_id, request_id
        ) VALUES (
            $1, $2, $3, 'system', NULL, NULL, NULL,
            $4, 'succeeded', $5, $6, NULL
        )
        ",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(occurred_at_ms)
    .bind(action)
    .bind(resource_kind)
    .bind(resource_id)
    .execute(&mut **transaction)
    .await
    .map_err(map_sql_error)?;
    Ok(())
}

fn provider_create_request_id(mutation_id: RepositorySecretMutationId) -> String {
    format!("secret-version:{}", mutation_id.as_uuid().hyphenated())
}

fn provider_destroy_request_id(version_id: Uuid) -> String {
    format!("secret-destroy:{}", version_id.hyphenated())
}

fn cleanup_operation_id(tenant_id: &str, secret_id: Uuid, version_id: Uuid) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(CLEANUP_OPERATION_DOMAIN);
    hasher.update((tenant_id.len() as u64).to_be_bytes());
    hasher.update(tenant_id.as_bytes());
    hasher.update(secret_id.as_bytes());
    hasher.update(version_id.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn recovery_operation_id(tenant_id: &str, mutation_id: Uuid) -> Uuid {
    let mut digest = Sha256::new();
    digest.update(RECOVERY_OPERATION_DOMAIN);
    digest.update(
        u64::try_from(tenant_id.len())
            .expect("tenant length fits u64")
            .to_be_bytes(),
    );
    digest.update(tenant_id.as_bytes());
    digest.update(mutation_id.as_bytes());
    let bytes: [u8; 32] = digest.finalize().into();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&bytes[..16]);
    id[6] = (id[6] & 0x0f) | 0x80;
    id[8] = (id[8] & 0x3f) | 0x80;
    Uuid::from_bytes(id)
}

fn encode_cleanup_failure(failure: SecretCleanupFailureKind) -> &'static str {
    match failure {
        SecretCleanupFailureKind::InvalidRequest => "invalid_request",
        SecretCleanupFailureKind::Unsupported => "unsupported",
        SecretCleanupFailureKind::Unauthorized => "unauthorized",
        SecretCleanupFailureKind::Forbidden => "forbidden",
        SecretCleanupFailureKind::NotFound => "not_found",
        SecretCleanupFailureKind::Conflict => "conflict",
        SecretCleanupFailureKind::RateLimited => "rate_limited",
        SecretCleanupFailureKind::Unavailable => "unavailable",
        SecretCleanupFailureKind::IntegrityFailure => "integrity_failure",
        SecretCleanupFailureKind::InvalidResponse => "invalid_response",
    }
}

fn cleanup_failure_is_retryable(failure: SecretCleanupFailureKind) -> bool {
    matches!(
        failure,
        SecretCleanupFailureKind::RateLimited | SecretCleanupFailureKind::Unavailable
    )
}

fn canonical_uuid(value: &str) -> Result<Uuid, SecretManagementRepositoryError> {
    let parsed =
        Uuid::parse_str(value).map_err(|_| SecretManagementRepositoryError::InvalidRequest)?;
    if parsed.is_nil() || parsed.hyphenated().to_string() != value {
        return Err(SecretManagementRepositoryError::InvalidRequest);
    }
    Ok(parsed)
}

fn revision(value: i64) -> Result<ManagementRevision, SecretManagementRepositoryError> {
    let value = positive_u64(value)?;
    ManagementRevision::new(value).map_err(|_| SecretManagementRepositoryError::CorruptData)
}

fn positive_u64(value: i64) -> Result<u64, SecretManagementRepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(SecretManagementRepositoryError::CorruptData)
}

fn timestamp(value: i64) -> Result<UnixMillis, SecretManagementRepositoryError> {
    if value < 0 {
        return Err(SecretManagementRepositoryError::CorruptData);
    }
    Ok(UnixMillis::new(value))
}

async fn begin(
    pool: &PgPool,
) -> Result<Transaction<'_, Postgres>, SecretManagementRepositoryError> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| SecretManagementRepositoryError::Unavailable)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *transaction)
        .await
        .map_err(map_sql_error)?;
    Ok(transaction)
}

async fn begin_reservation(
    pool: &PgPool,
) -> Result<Transaction<'_, Postgres>, SecretManagementRepositoryError> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| SecretManagementRepositoryError::Unavailable)?;
    // Authentication write-locks its exact session, principal, and membership;
    // repository, provider, and logical-secret locks then serialize allocation.
    // A waiter needs a fresh statement snapshot after those locks so it sees the
    // preceding transaction's committed mutation ledger rather than reusing MAX.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *transaction)
        .await
        .map_err(map_sql_error)?;
    Ok(transaction)
}

async fn commit(
    transaction: Transaction<'_, Postgres>,
) -> Result<(), SecretManagementRepositoryError> {
    transaction
        .commit()
        .await
        .map_err(|_| SecretManagementRepositoryError::Unavailable)
}

#[allow(clippy::needless_pass_by_value)]
fn map_sql_error(error: sqlx::Error) -> SecretManagementRepositoryError {
    let transient = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|code| {
            code.starts_with("08") || code.starts_with("40") || code == "53P01" || code == "57P01"
        });
    if error.as_database_error().is_none() || transient {
        SecretManagementRepositoryError::Unavailable
    } else {
        SecretManagementRepositoryError::CorruptData
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_cleanup_identity_is_exact_and_uuid_v8() {
        let secret_id = Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap();
        let version_id = Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").unwrap();
        let first = cleanup_operation_id("tenant-a", secret_id, version_id);
        assert_eq!(
            first,
            cleanup_operation_id("tenant-a", secret_id, version_id)
        );
        assert_ne!(
            first,
            cleanup_operation_id("tenant-b", secret_id, version_id)
        );
        assert_eq!(first.get_version_num(), 8);
    }

    #[test]
    fn cleanup_failures_are_closed_codes() {
        assert_eq!(
            encode_cleanup_failure(SecretCleanupFailureKind::IntegrityFailure),
            "integrity_failure"
        );
        assert_eq!(
            encode_cleanup_failure(SecretCleanupFailureKind::Unavailable),
            "unavailable"
        );
        assert!(cleanup_failure_is_retryable(
            SecretCleanupFailureKind::RateLimited
        ));
        assert!(cleanup_failure_is_retryable(
            SecretCleanupFailureKind::Unavailable
        ));
        for terminal in [
            SecretCleanupFailureKind::InvalidRequest,
            SecretCleanupFailureKind::Unsupported,
            SecretCleanupFailureKind::Unauthorized,
            SecretCleanupFailureKind::Forbidden,
            SecretCleanupFailureKind::NotFound,
            SecretCleanupFailureKind::Conflict,
            SecretCleanupFailureKind::IntegrityFailure,
            SecretCleanupFailureKind::InvalidResponse,
        ] {
            assert!(!cleanup_failure_is_retryable(terminal));
        }
    }
}
