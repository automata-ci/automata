use std::{collections::BTreeMap, fmt, sync::Arc};

use automata_ci_core::JobAuthorityProfile;
use automata_ci_core::WorkspaceId;
use automata_ci_key_management::{
    EncryptedEnvelope, EnvelopeCodec, EnvelopeError, KeyEncryptionContext, KeyEncryptionProvider,
    KeyId, KeyPurpose, SecretBytes, WrappedDataKey,
};
use automata_ci_provisioning::{
    ApplyGithubProviderConfigurationCommand, ApplyGithubProviderConfigurationResult,
    ApplyWorkspaceGithubRepositoriesCommand, ApplyWorkspaceGithubRepositoriesResult,
    AuthorizedApplyGithubProviderConfiguration, AuthorizedApplyWorkspaceGithubRepositories,
    GithubProviderConfigurationApplicationFuture, GithubProviderConfigurationApplier,
    GithubProviderConfigurationFailure, GithubProviderConfigurationFailureKind,
    GithubProviderConfigurationRevision, GithubProviderDesiredState,
    GithubProviderDesiredStateFailure, GithubProviderDesiredStateFailureKind,
    GithubProviderDesiredStateLoadFuture, GithubProviderDesiredStateReader,
    GithubProviderDesiredStateVersion, GithubProviderRepositorySelection,
    GithubProviderSchedulePolicy, GithubProviderSecret, GithubProviderTimestamp,
    MAX_GITHUB_PROVIDER_REPOSITORIES, ShardId, WorkspaceGithubRepositoriesApplicationFuture,
    WorkspaceGithubRepositoriesApplier, WorkspaceGithubRepositoriesDesiredState,
    WorkspaceGithubRepositoriesFailure, WorkspaceGithubRepositoriesFailureKind,
    WorkspaceGithubRepositoriesRevision,
};
use automata_ci_store::{
    GithubCheckName, GithubRepositoryName, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceJwtIssuer, ProviderInstallationId,
    ProviderRepositoryId, ProviderRepositoryOwnerId, ProviderRepositoryVisibility,
};
use automata_ci_workflow_service::GithubRunnerPolicy;
use sha2::{Digest as _, Sha256};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use url::Url;
use uuid::Uuid;

const CONFIGURATION_SECRET_PURPOSE: &str = "github-provider/configuration-secret:v1";
const CONFIGURATION_DIGEST_DOMAIN: &[u8] = b"automata-ci/github-provider/configuration/v1\0";
const REPOSITORY_DIGEST_DOMAIN: &[u8] = b"automata-ci/github-provider/repositories/v1\0";
const SYSTEM_ENCRYPTION_TENANT: &str = "automata-system";

/// Replica-safe `PostgreSQL` implementation of shard-wide provider configuration.
///
/// Plaintext credentials are envelope-encrypted under the mandatory control-plane
/// key provider before the transaction starts. `PostgreSQL` retains only hashes,
/// ciphertext, and authenticated envelope metadata.
#[derive(Clone)]
pub struct PostgresGithubProviderConfigurationApplier {
    pool: PgPool,
    envelopes: Arc<EnvelopeCodec>,
}

impl PostgresGithubProviderConfigurationApplier {
    /// Binds provider configuration to a database and wrapping-key provider.
    #[must_use]
    pub fn new(pool: PgPool, key_provider: Arc<dyn KeyEncryptionProvider>) -> Self {
        Self {
            pool,
            envelopes: Arc::new(EnvelopeCodec::new(key_provider)),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one transaction applies one complete provider revision"
    )]
    async fn apply_inner(
        &self,
        request: AuthorizedApplyGithubProviderConfiguration,
    ) -> Result<ApplyGithubProviderConfigurationResult, GithubProviderConfigurationFailure> {
        let (authority, command) = request.into_parts();
        let digest = provider_configuration_digest(&command)?;
        let revision = command.revision();
        let revision_i64 = i64::try_from(revision.get()).map_err(|_| provider_internal())?;
        let authority_id = authority.id().as_str();
        let operation_id = command.operation_id();
        let shard_id = command.shard_id();
        if let Some(stored) =
            load_provider_operation_from_pool(&self.pool, authority_id, operation_id.as_uuid())
                .await?
        {
            if stored.shard_id != shard_id.as_str()
                || stored.revision != revision_i64
                || stored.request_digest.as_slice() != digest.as_slice()
            {
                return Err(provider_failure(
                    GithubProviderConfigurationFailureKind::OperationConflict,
                ));
            }
            return provider_result(
                operation_id,
                shard_id.clone(),
                revision,
                stored.applied_at_ms,
            );
        }
        let private_key_hash =
            Sha256::digest(command.configuration().private_key().expose_secret());
        let webhook_secret_hash =
            Sha256::digest(command.configuration().webhook_secret().expose_secret());
        let private_key = seal_provider_secret(
            self.envelopes.as_ref(),
            revision,
            "app-private-key",
            command.configuration().private_key().expose_secret(),
        )
        .await?;
        let webhook_secret = seal_provider_secret(
            self.envelopes.as_ref(),
            revision,
            "webhook-secret",
            command.configuration().webhook_secret().expose_secret(),
        )
        .await?;
        let runner_policy = command
            .configuration()
            .runner_policy()
            .canonical_bytes()
            .map_err(|_| provider_internal())?;

        let mut transaction = self.pool.begin().await.map_err(provider_database_failure)?;
        lock_provider_registry(&mut transaction)
            .await
            .map_err(provider_database_failure)?;
        let current_revision: Option<i64> = sqlx::query_scalar(
            r"
            SELECT revision FROM github_provider_configuration_current
            WHERE singleton=true
            ",
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(provider_database_failure)?;

        if let Some(stored) =
            load_provider_operation(&mut transaction, authority_id, operation_id.as_uuid()).await?
        {
            if stored.shard_id != shard_id.as_str()
                || stored.revision != revision_i64
                || stored.request_digest.as_slice() != digest.as_slice()
            {
                return Err(provider_failure(
                    GithubProviderConfigurationFailureKind::OperationConflict,
                ));
            }
            return provider_result(
                operation_id,
                shard_id.clone(),
                revision,
                stored.applied_at_ms,
            );
        }
        if current_revision.is_some_and(|current| revision_i64 <= current) {
            return Err(provider_failure(
                GithubProviderConfigurationFailureKind::StaleRevision,
            ));
        }

        let current = match current_revision {
            Some(_) => Some(load_current_provider_evidence(&mut transaction).await?),
            None => None,
        };
        let configuration = command.configuration();
        let app_configuration_revision = next_app_configuration_revision(
            current.as_ref(),
            configuration.app_id().get(),
            configuration.app_client_id().as_str(),
            configuration.jwt_issuer().as_str(),
            private_key_hash.as_slice(),
        )?;
        let webhook_verifier_revision =
            next_webhook_revision(current.as_ref(), webhook_secret_hash.as_slice())?;
        let runner_policy_revision = next_runner_policy_revision(current.as_ref(), &runner_policy)?;
        let applied_at_ms = database_time_milliseconds(&mut transaction)
            .await
            .map_err(provider_database_failure)?;

        sqlx::query(
            r"
            INSERT INTO github_provider_configuration_operations (
                authority_id, operation_id, shard_id, revision,
                request_digest, applied_at_ms
            ) VALUES ($1,$2,$3,$4,$5,$6)
            ",
        )
        .bind(authority_id)
        .bind(operation_id.as_uuid())
        .bind(shard_id.as_str())
        .bind(revision_i64)
        .bind(digest.as_slice())
        .bind(applied_at_ms)
        .execute(&mut *transaction)
        .await
        .map_err(provider_database_failure)?;

        let schedule = configuration.schedule();
        let private_key = EnvelopeParts::from(private_key);
        let webhook_secret = EnvelopeParts::from(webhook_secret);
        sqlx::query("DELETE FROM github_provider_configuration_current WHERE singleton=true")
            .execute(&mut *transaction)
            .await
            .map_err(provider_database_failure)?;
        sqlx::query(
            r"
            INSERT INTO github_provider_configuration_current (
                singleton, shard_id, revision, authority_id, operation_id, dashboard_url,
                github_app_id, github_app_client_id, github_app_jwt_issuer_kind,
                app_configuration_revision, app_private_key_sha256,
                app_private_key_envelope_schema, app_private_key_wrapping_key_id,
                app_private_key_wrapped_data_key, app_private_key_nonce,
                app_private_key_ciphertext, webhook_verifier_revision,
                webhook_secret_sha256, webhook_secret_envelope_schema,
                webhook_secret_wrapping_key_id, webhook_secret_wrapped_data_key,
                webhook_secret_nonce, webhook_secret_ciphertext, check_name,
                runner_policy_revision, runner_policy, schedule_poll_millis,
                schedule_discovery_claim_millis, schedule_fire_claim_millis,
                schedule_retry_millis, schedule_staleness_millis,
                schedule_maximum_manifests, schedule_maximum_fires_per_pass,
                applied_at_ms
            ) VALUES (
                true,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
                $17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33
            )
            ",
        )
        .bind(shard_id.as_str())
        .bind(revision_i64)
        .bind(authority_id)
        .bind(operation_id.as_uuid())
        .bind(configuration.dashboard_url().as_str())
        .bind(i64::try_from(configuration.app_id().get()).map_err(|_| provider_internal())?)
        .bind(configuration.app_client_id().as_str())
        .bind(configuration.jwt_issuer().as_str())
        .bind(app_configuration_revision)
        .bind(private_key_hash.as_slice())
        .bind(private_key.schema)
        .bind(private_key.wrapping_key_id)
        .bind(private_key.wrapped_data_key)
        .bind(private_key.nonce)
        .bind(private_key.ciphertext)
        .bind(webhook_verifier_revision)
        .bind(webhook_secret_hash.as_slice())
        .bind(webhook_secret.schema)
        .bind(webhook_secret.wrapping_key_id)
        .bind(webhook_secret.wrapped_data_key)
        .bind(webhook_secret.nonce)
        .bind(webhook_secret.ciphertext)
        .bind(configuration.check_name().as_str())
        .bind(runner_policy_revision)
        .bind(runner_policy)
        .bind(schedule.poll_millis())
        .bind(schedule.discovery_claim_millis())
        .bind(schedule.fire_claim_millis())
        .bind(schedule.retry_millis())
        .bind(schedule.staleness_millis())
        .bind(i32::from(schedule.maximum_manifests()))
        .bind(i32::from(schedule.maximum_fires_per_pass()))
        .bind(applied_at_ms)
        .execute(&mut *transaction)
        .await
        .map_err(provider_database_failure)?;
        transaction
            .commit()
            .await
            .map_err(provider_database_failure)?;
        provider_result(operation_id, shard_id.clone(), revision, applied_at_ms)
    }
}

impl fmt::Debug for PostgresGithubProviderConfigurationApplier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresGithubProviderConfigurationApplier")
            .field("envelopes", &"[KEY ENCRYPTION PROVIDER]")
            .finish_non_exhaustive()
    }
}

impl GithubProviderConfigurationApplier for PostgresGithubProviderConfigurationApplier {
    fn apply(
        &self,
        request: AuthorizedApplyGithubProviderConfiguration,
    ) -> GithubProviderConfigurationApplicationFuture<'_> {
        Box::pin(self.apply_inner(request))
    }
}

/// Replica-safe `PostgreSQL` implementation of complete workspace repository sets.
#[derive(Clone)]
pub struct PostgresWorkspaceGithubRepositoriesApplier {
    pool: PgPool,
}

impl PostgresWorkspaceGithubRepositoriesApplier {
    /// Binds workspace GitHub repository desired state to `pool`.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one transaction replaces one complete repository set"
    )]
    async fn apply_inner(
        &self,
        request: AuthorizedApplyWorkspaceGithubRepositories,
    ) -> Result<ApplyWorkspaceGithubRepositoriesResult, WorkspaceGithubRepositoriesFailure> {
        let (authority, command) = request.into_parts();
        let digest = workspace_repositories_digest(&command);
        let authority_id = authority.id().as_str();
        let operation_id = command.operation_id();
        let shard_id = command.shard_id();
        let workspace_id = command.workspace_id();
        let workspace_text = workspace_id.to_string();
        let revision = command.revision();
        let revision_i64 = i64::try_from(revision.get()).map_err(|_| workspace_internal())?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(workspace_database_failure)?;

        let binding = sqlx::query_as::<_, WorkspaceBinding>(
            r"
            SELECT authority_id, shard_id FROM workspace_management_bindings
            WHERE workspace_id=$1 FOR UPDATE
            ",
        )
        .bind(&workspace_text)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(workspace_database_failure)?;
        if binding.as_ref().is_none_or(|binding| {
            binding.authority_id != authority_id || binding.shard_id != shard_id.as_str()
        }) {
            return Err(workspace_failure(
                WorkspaceGithubRepositoriesFailureKind::WorkspaceUnavailable,
            ));
        }

        if let Some(stored) =
            load_workspace_operation(&mut transaction, authority_id, operation_id.as_uuid()).await?
        {
            if stored.shard_id != shard_id.as_str()
                || stored.workspace_id != workspace_text
                || stored.revision != revision_i64
                || stored.request_digest.as_slice() != digest.as_slice()
            {
                return Err(workspace_failure(
                    WorkspaceGithubRepositoriesFailureKind::OperationConflict,
                ));
            }
            return workspace_result(
                operation_id,
                shard_id.clone(),
                workspace_id,
                revision,
                stored.applied_at_ms,
            );
        }
        let current_revision: Option<i64> = sqlx::query_scalar(
            "SELECT revision FROM workspace_github_repository_current WHERE workspace_id=$1",
        )
        .bind(&workspace_text)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(workspace_database_failure)?;
        if current_revision.is_some_and(|current| revision_i64 <= current) {
            return Err(workspace_failure(
                WorkspaceGithubRepositoriesFailureKind::StaleRevision,
            ));
        }
        lock_provider_registry(&mut transaction)
            .await
            .map_err(workspace_database_failure)?;
        validate_shard_registry(
            &mut transaction,
            shard_id,
            workspace_id,
            command.repositories(),
        )
        .await?;
        let applied_at_ms = database_time_milliseconds(&mut transaction)
            .await
            .map_err(workspace_database_failure)?;

        sqlx::query(
            r"
            INSERT INTO workspace_github_repository_operations (
                authority_id, operation_id, shard_id, workspace_id, revision,
                request_digest, applied_at_ms
            ) VALUES ($1,$2,$3,$4,$5,$6,$7)
            ",
        )
        .bind(authority_id)
        .bind(operation_id.as_uuid())
        .bind(shard_id.as_str())
        .bind(&workspace_text)
        .bind(revision_i64)
        .bind(digest.as_slice())
        .bind(applied_at_ms)
        .execute(&mut *transaction)
        .await
        .map_err(workspace_database_failure)?;
        sqlx::query("DELETE FROM workspace_github_repository_current WHERE workspace_id=$1")
            .bind(&workspace_text)
            .execute(&mut *transaction)
            .await
            .map_err(workspace_database_failure)?;
        sqlx::query(
            r"
            INSERT INTO workspace_github_repository_current (
                workspace_id, shard_id, revision, authority_id, operation_id, applied_at_ms
            ) VALUES ($1,$2,$3,$4,$5,$6)
            ",
        )
        .bind(&workspace_text)
        .bind(shard_id.as_str())
        .bind(revision_i64)
        .bind(authority_id)
        .bind(operation_id.as_uuid())
        .bind(applied_at_ms)
        .execute(&mut *transaction)
        .await
        .map_err(workspace_database_failure)?;
        for (ordinal, repository) in command.repositories().iter().enumerate() {
            let installation_binding_generation = advance_installation_binding(
                &mut transaction,
                &workspace_text,
                revision_i64,
                repository,
            )
            .await?;
            insert_repository_selection(
                &mut transaction,
                &workspace_text,
                shard_id,
                revision_i64,
                i32::try_from(ordinal).map_err(|_| workspace_internal())?,
                repository,
                installation_binding_generation,
            )
            .await?;
        }
        sqlx::query(
            r"
            INSERT INTO security_audit_events (
                event_id, tenant_id, occurred_at_ms, actor_kind, action,
                outcome, resource_kind, resource_id
            ) VALUES ($1,$2,$3,'system','workspace.github.repositories.applied',
                      'succeeded','workspace',$2)
            ",
        )
        .bind(Uuid::new_v4())
        .bind(&workspace_text)
        .bind(applied_at_ms)
        .execute(&mut *transaction)
        .await
        .map_err(workspace_database_failure)?;
        transaction
            .commit()
            .await
            .map_err(workspace_database_failure)?;
        workspace_result(
            operation_id,
            shard_id.clone(),
            workspace_id,
            revision,
            applied_at_ms,
        )
    }
}

impl fmt::Debug for PostgresWorkspaceGithubRepositoriesApplier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresWorkspaceGithubRepositoriesApplier")
            .finish_non_exhaustive()
    }
}

impl WorkspaceGithubRepositoriesApplier for PostgresWorkspaceGithubRepositoriesApplier {
    fn apply(
        &self,
        request: AuthorizedApplyWorkspaceGithubRepositories,
    ) -> WorkspaceGithubRepositoriesApplicationFuture<'_> {
        Box::pin(self.apply_inner(request))
    }
}

/// Transactionally consistent `PostgreSQL` reader for provider desired state.
#[derive(Clone)]
pub struct PostgresGithubProviderDesiredStateReader {
    pool: PgPool,
    envelopes: Arc<EnvelopeCodec>,
}

impl PostgresGithubProviderDesiredStateReader {
    /// Binds the reader to the database and mandatory control-plane key provider.
    #[must_use]
    pub fn new(pool: PgPool, key_provider: Arc<dyn KeyEncryptionProvider>) -> Self {
        Self {
            pool,
            envelopes: Arc::new(EnvelopeCodec::new(key_provider)),
        }
    }

    async fn load_inner(
        &self,
    ) -> Result<Option<GithubProviderDesiredState>, GithubProviderDesiredStateFailure> {
        let mut transaction = self.pool.begin().await.map_err(desired_database_failure)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *transaction)
            .await
            .map_err(desired_database_failure)?;
        let provider = sqlx::query_as::<_, ProviderDesiredStateRow>(
            r"
            SELECT configuration.*
            FROM github_provider_configuration_current AS configuration
            WHERE configuration.singleton=true
            ",
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(desired_database_failure)?;
        let Some(provider) = provider else {
            transaction
                .commit()
                .await
                .map_err(desired_database_failure)?;
            return Ok(None);
        };
        let workspace_states = sqlx::query_as::<_, WorkspaceCurrentRow>(
            r"
            SELECT current.workspace_id, current.revision, current.applied_at_ms
            FROM workspace_github_repository_current AS current
            WHERE current.shard_id=$1
            ORDER BY current.workspace_id
            ",
        )
        .bind(&provider.shard_id)
        .fetch_all(&mut *transaction)
        .await
        .map_err(desired_database_failure)?;
        let selections = sqlx::query_as::<_, RepositorySelectionRow>(
            r"
            SELECT selections.workspace_id, selections.revision,
                   selections.provider_installation_id,
                   selections.installation_binding_generation,
                   selections.provider_repository_id,
                   selections.provider_repository_owner_id,
                   selections.repository_name, selections.default_branch,
                   selections.repository_visibility, selections.authority_profile
            FROM workspace_github_repository_current AS current
            JOIN workspace_github_repository_selections AS selections
              ON selections.workspace_id=current.workspace_id
             AND selections.shard_id=current.shard_id
             AND selections.revision=current.revision
            WHERE current.shard_id=$1
            ORDER BY selections.workspace_id, selections.ordinal
            ",
        )
        .bind(&provider.shard_id)
        .fetch_all(&mut *transaction)
        .await
        .map_err(desired_database_failure)?;
        transaction
            .commit()
            .await
            .map_err(desired_database_failure)?;
        self.decode_desired_state(provider, workspace_states, selections)
            .await
            .map(Some)
    }

    async fn decode_desired_state(
        &self,
        provider: ProviderDesiredStateRow,
        workspace_states: Vec<WorkspaceCurrentRow>,
        selections: Vec<RepositorySelectionRow>,
    ) -> Result<GithubProviderDesiredState, GithubProviderDesiredStateFailure> {
        let revision = positive_u64(provider.revision)?;
        let private_key = open_provider_secret(
            self.envelopes.as_ref(),
            revision,
            "app-private-key",
            provider.app_private_key_envelope(),
        )
        .await?;
        let webhook_secret = open_provider_secret(
            self.envelopes.as_ref(),
            revision,
            "webhook-secret",
            provider.webhook_secret_envelope(),
        )
        .await?;
        if Sha256::digest(private_key.expose_secret()).as_slice()
            != provider.app_private_key_sha256.as_slice()
            || Sha256::digest(webhook_secret.expose_secret()).as_slice()
                != provider.webhook_secret_sha256.as_slice()
        {
            return Err(desired_corrupt());
        }

        let configuration = automata_ci_provisioning::GithubProviderConfiguration::new(
            Url::parse(&provider.dashboard_url).map_err(|_| desired_corrupt())?,
            GithubServerServiceAppId::new(positive_u64(provider.github_app_id)?)
                .map_err(|_| desired_corrupt())?,
            GithubServerServiceAppClientId::new(provider.github_app_client_id)
                .map_err(|_| desired_corrupt())?,
            decode_jwt_issuer(&provider.github_app_jwt_issuer_kind)?,
            GithubProviderSecret::private_key(private_key.expose_secret().to_vec())
                .map_err(|_| desired_corrupt())?,
            GithubProviderSecret::webhook(webhook_secret.expose_secret().to_vec())
                .map_err(|_| desired_corrupt())?,
            GithubCheckName::new(provider.check_name).map_err(|_| desired_corrupt())?,
            GithubRunnerPolicy::decode_configuration(&provider.runner_policy)
                .map_err(|_| desired_corrupt())?,
            GithubProviderSchedulePolicy::new(
                provider.schedule_poll_millis,
                provider.schedule_discovery_claim_millis,
                provider.schedule_fire_claim_millis,
                provider.schedule_retry_millis,
                provider.schedule_staleness_millis,
                positive_u16(provider.schedule_maximum_manifests)?,
                positive_u16(provider.schedule_maximum_fires_per_pass)?,
            )
            .map_err(|_| desired_corrupt())?,
        )
        .map_err(|_| desired_corrupt())?;

        let mut repositories = BTreeMap::<(String, i64), Vec<_>>::new();
        for selection in selections {
            let key = (selection.workspace_id.clone(), selection.revision);
            repositories
                .entry(key)
                .or_default()
                .push(selection.decode()?);
        }
        let mut workspaces = Vec::with_capacity(workspace_states.len());
        for state in workspace_states {
            let workspace_id =
                WorkspaceId::parse(&state.workspace_id).map_err(|_| desired_corrupt())?;
            let revision = WorkspaceGithubRepositoriesRevision::new(positive_u64(state.revision)?)
                .map_err(|_| desired_corrupt())?;
            let selected = repositories
                .remove(&(state.workspace_id, state.revision))
                .unwrap_or_default();
            workspaces.push(
                WorkspaceGithubRepositoriesDesiredState::new(
                    workspace_id,
                    revision,
                    timestamp(state.applied_at_ms).map_err(|()| desired_corrupt())?,
                    selected,
                )
                .map_err(|_| desired_corrupt())?,
            );
        }
        if !repositories.is_empty() {
            return Err(desired_corrupt());
        }

        GithubProviderDesiredState::new(
            ShardId::new(provider.shard_id).map_err(|_| desired_corrupt())?,
            GithubProviderDesiredStateVersion::new(
                GithubProviderConfigurationRevision::new(revision)
                    .map_err(|_| desired_corrupt())?,
                timestamp(provider.applied_at_ms).map_err(|()| desired_corrupt())?,
                positive_u64(provider.app_configuration_revision)?,
                positive_u64(provider.webhook_verifier_revision)?,
                positive_u64(provider.runner_policy_revision)?,
            )
            .map_err(|_| desired_corrupt())?,
            configuration,
            workspaces,
        )
        .map_err(|_| desired_corrupt())
    }
}

impl fmt::Debug for PostgresGithubProviderDesiredStateReader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresGithubProviderDesiredStateReader")
            .field("envelopes", &"[KEY ENCRYPTION PROVIDER]")
            .finish_non_exhaustive()
    }
}

impl GithubProviderDesiredStateReader for PostgresGithubProviderDesiredStateReader {
    fn load(&self) -> GithubProviderDesiredStateLoadFuture<'_> {
        Box::pin(self.load_inner())
    }
}

#[derive(FromRow)]
struct ProviderDesiredStateRow {
    shard_id: String,
    revision: i64,
    dashboard_url: String,
    github_app_id: i64,
    github_app_client_id: String,
    github_app_jwt_issuer_kind: String,
    app_configuration_revision: i64,
    app_private_key_sha256: Vec<u8>,
    app_private_key_envelope_schema: i16,
    app_private_key_wrapping_key_id: String,
    app_private_key_wrapped_data_key: Vec<u8>,
    app_private_key_nonce: Vec<u8>,
    app_private_key_ciphertext: Vec<u8>,
    webhook_verifier_revision: i64,
    webhook_secret_sha256: Vec<u8>,
    webhook_secret_envelope_schema: i16,
    webhook_secret_wrapping_key_id: String,
    webhook_secret_wrapped_data_key: Vec<u8>,
    webhook_secret_nonce: Vec<u8>,
    webhook_secret_ciphertext: Vec<u8>,
    check_name: String,
    runner_policy_revision: i64,
    runner_policy: Vec<u8>,
    schedule_poll_millis: i64,
    schedule_discovery_claim_millis: i64,
    schedule_fire_claim_millis: i64,
    schedule_retry_millis: i64,
    schedule_staleness_millis: i64,
    schedule_maximum_manifests: i32,
    schedule_maximum_fires_per_pass: i32,
    applied_at_ms: i64,
}

impl ProviderDesiredStateRow {
    fn app_private_key_envelope(&self) -> StoredEnvelope<'_> {
        StoredEnvelope {
            schema: self.app_private_key_envelope_schema,
            wrapping_key_id: &self.app_private_key_wrapping_key_id,
            wrapped_data_key: &self.app_private_key_wrapped_data_key,
            nonce: &self.app_private_key_nonce,
            ciphertext: &self.app_private_key_ciphertext,
        }
    }

    fn webhook_secret_envelope(&self) -> StoredEnvelope<'_> {
        StoredEnvelope {
            schema: self.webhook_secret_envelope_schema,
            wrapping_key_id: &self.webhook_secret_wrapping_key_id,
            wrapped_data_key: &self.webhook_secret_wrapped_data_key,
            nonce: &self.webhook_secret_nonce,
            ciphertext: &self.webhook_secret_ciphertext,
        }
    }
}

#[derive(FromRow)]
struct WorkspaceCurrentRow {
    workspace_id: String,
    revision: i64,
    applied_at_ms: i64,
}

#[derive(FromRow)]
struct RepositorySelectionRow {
    workspace_id: String,
    revision: i64,
    provider_installation_id: i64,
    installation_binding_generation: i64,
    provider_repository_id: i64,
    provider_repository_owner_id: i64,
    repository_name: String,
    default_branch: String,
    repository_visibility: String,
    authority_profile: String,
}

impl RepositorySelectionRow {
    fn decode(
        self,
    ) -> Result<GithubProviderRepositorySelection, GithubProviderDesiredStateFailure> {
        let installation_binding_generation = positive_u64(self.installation_binding_generation)?;
        GithubProviderRepositorySelection::new(
            ProviderInstallationId::new(positive_u64(self.provider_installation_id)?)
                .map_err(|_| desired_corrupt())?,
            ProviderRepositoryId::new(positive_u64(self.provider_repository_id)?)
                .map_err(|_| desired_corrupt())?,
            ProviderRepositoryOwnerId::new(positive_u64(self.provider_repository_owner_id)?)
                .map_err(|_| desired_corrupt())?,
            GithubRepositoryName::new(self.repository_name).map_err(|_| desired_corrupt())?,
            self.default_branch,
            match self.repository_visibility.as_str() {
                "public" => ProviderRepositoryVisibility::Public,
                "private" => ProviderRepositoryVisibility::Private,
                _ => return Err(desired_corrupt()),
            },
            match self.authority_profile.as_str() {
                "standard" => JobAuthorityProfile::Standard,
                "credential_free" => JobAuthorityProfile::CredentialFree,
                _ => return Err(desired_corrupt()),
            },
        )
        .and_then(|selection| {
            selection.with_installation_binding_generation(installation_binding_generation)
        })
        .map_err(|_| desired_corrupt())
    }
}

struct StoredEnvelope<'a> {
    schema: i16,
    wrapping_key_id: &'a str,
    wrapped_data_key: &'a [u8],
    nonce: &'a [u8],
    ciphertext: &'a [u8],
}

async fn open_provider_secret(
    codec: &EnvelopeCodec,
    revision: u64,
    field: &str,
    stored: StoredEnvelope<'_>,
) -> Result<SecretBytes, GithubProviderDesiredStateFailure> {
    let schema = u16::try_from(stored.schema).map_err(|_| desired_corrupt())?;
    let key_id = KeyId::new(stored.wrapping_key_id.to_owned()).map_err(|_| desired_corrupt())?;
    let wrapped = WrappedDataKey::new(key_id, stored.wrapped_data_key.to_vec())
        .map_err(|_| desired_corrupt())?;
    let nonce = stored.nonce.try_into().map_err(|_| desired_corrupt())?;
    let envelope =
        EncryptedEnvelope::from_parts(schema, wrapped, nonce, stored.ciphertext.to_vec())
            .map_err(|_| desired_corrupt())?;
    let purpose = KeyPurpose::new(CONFIGURATION_SECRET_PURPOSE).map_err(|_| desired_corrupt())?;
    let context = KeyEncryptionContext::new(
        SYSTEM_ENCRYPTION_TENANT,
        purpose,
        format!("revision/{revision}/{field}"),
    )
    .map_err(|_| desired_corrupt())?;
    codec
        .open(&context, &envelope)
        .await
        .map_err(|error| match error {
            EnvelopeError::KeyEncryption(_) => {
                desired_failure(GithubProviderDesiredStateFailureKind::TemporarilyUnavailable)
            }
            EnvelopeError::InvalidEnvelope
            | EnvelopeError::UnsupportedSchema
            | EnvelopeError::AuthenticationFailed
            | EnvelopeError::RandomnessUnavailable
            | EnvelopeError::CryptographicFailure => desired_corrupt(),
        })
}

fn decode_jwt_issuer(
    value: &str,
) -> Result<GithubServerServiceJwtIssuer, GithubProviderDesiredStateFailure> {
    match value {
        "app_client_id" => Ok(GithubServerServiceJwtIssuer::AppClientId),
        "app_id" => Ok(GithubServerServiceJwtIssuer::AppId),
        _ => Err(desired_corrupt()),
    }
}

fn positive_u64(value: i64) -> Result<u64, GithubProviderDesiredStateFailure> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(desired_corrupt)
}

fn positive_u16(value: i32) -> Result<u16, GithubProviderDesiredStateFailure> {
    u16::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(desired_corrupt)
}

fn desired_failure(
    kind: GithubProviderDesiredStateFailureKind,
) -> GithubProviderDesiredStateFailure {
    GithubProviderDesiredStateFailure::new(kind)
}

fn desired_corrupt() -> GithubProviderDesiredStateFailure {
    desired_failure(GithubProviderDesiredStateFailureKind::CorruptState)
}

fn desired_database_failure(_: sqlx::Error) -> GithubProviderDesiredStateFailure {
    desired_failure(GithubProviderDesiredStateFailureKind::TemporarilyUnavailable)
}

async fn seal_provider_secret(
    codec: &EnvelopeCodec,
    revision: GithubProviderConfigurationRevision,
    field: &str,
    plaintext: &[u8],
) -> Result<EncryptedEnvelope, GithubProviderConfigurationFailure> {
    let purpose = KeyPurpose::new(CONFIGURATION_SECRET_PURPOSE).map_err(|_| provider_internal())?;
    let context = KeyEncryptionContext::new(
        SYSTEM_ENCRYPTION_TENANT,
        purpose,
        format!("revision/{}/{field}", revision.get()),
    )
    .map_err(|_| provider_internal())?;
    let secret = SecretBytes::new(plaintext.to_vec()).map_err(|_| provider_internal())?;
    codec.seal(&context, secret).await.map_err(|_| {
        provider_failure(GithubProviderConfigurationFailureKind::TemporarilyUnavailable)
    })
}

#[derive(Debug)]
struct EnvelopeParts {
    schema: i16,
    wrapping_key_id: String,
    wrapped_data_key: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl From<EncryptedEnvelope> for EnvelopeParts {
    fn from(envelope: EncryptedEnvelope) -> Self {
        let (schema, wrapped, nonce, ciphertext) = envelope.into_parts();
        let (key_id, wrapped_data_key) = wrapped.into_parts();
        Self {
            schema: i16::try_from(schema).expect("envelope schema fits PostgreSQL SMALLINT"),
            wrapping_key_id: key_id.as_str().to_owned(),
            wrapped_data_key,
            nonce: nonce.to_vec(),
            ciphertext,
        }
    }
}

#[derive(FromRow)]
struct ProviderOperationRow {
    shard_id: String,
    revision: i64,
    request_digest: Vec<u8>,
    applied_at_ms: i64,
}

async fn load_provider_operation(
    transaction: &mut Transaction<'_, Postgres>,
    authority_id: &str,
    operation_id: Uuid,
) -> Result<Option<ProviderOperationRow>, GithubProviderConfigurationFailure> {
    sqlx::query_as(
        r"
        SELECT shard_id, revision, request_digest, applied_at_ms
        FROM github_provider_configuration_operations
        WHERE authority_id=$1 AND operation_id=$2
        ",
    )
    .bind(authority_id)
    .bind(operation_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(provider_database_failure)
}

async fn load_provider_operation_from_pool(
    pool: &PgPool,
    authority_id: &str,
    operation_id: Uuid,
) -> Result<Option<ProviderOperationRow>, GithubProviderConfigurationFailure> {
    sqlx::query_as(
        r"
        SELECT shard_id, revision, request_digest, applied_at_ms
        FROM github_provider_configuration_operations
        WHERE authority_id=$1 AND operation_id=$2
        ",
    )
    .bind(authority_id)
    .bind(operation_id)
    .fetch_optional(pool)
    .await
    .map_err(provider_database_failure)
}

#[derive(FromRow)]
struct CurrentProviderEvidence {
    github_app_id: i64,
    github_app_client_id: String,
    github_app_jwt_issuer_kind: String,
    app_configuration_revision: i64,
    app_private_key_sha256: Vec<u8>,
    webhook_verifier_revision: i64,
    webhook_secret_sha256: Vec<u8>,
    runner_policy_revision: i64,
    runner_policy: Vec<u8>,
}

async fn load_current_provider_evidence(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<CurrentProviderEvidence, GithubProviderConfigurationFailure> {
    sqlx::query_as(
        r"
        SELECT github_app_id, github_app_client_id, github_app_jwt_issuer_kind,
               app_configuration_revision, app_private_key_sha256,
               webhook_verifier_revision, webhook_secret_sha256,
               runner_policy_revision, runner_policy
        FROM github_provider_configuration_current WHERE singleton=true
        ",
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(provider_database_failure)
}

fn next_app_configuration_revision(
    current: Option<&CurrentProviderEvidence>,
    app_id: u64,
    client_id: &str,
    jwt_issuer: &str,
    private_key_sha256: &[u8],
) -> Result<i64, GithubProviderConfigurationFailure> {
    let Some(current) = current else {
        return Ok(1);
    };
    let changed = current.github_app_id
        != i64::try_from(app_id).map_err(|_| provider_internal())?
        || current.github_app_client_id != client_id
        || current.github_app_jwt_issuer_kind != jwt_issuer
        || current.app_private_key_sha256 != private_key_sha256;
    if changed {
        current
            .app_configuration_revision
            .checked_add(1)
            .ok_or_else(provider_internal)
    } else {
        Ok(current.app_configuration_revision)
    }
}

fn next_webhook_revision(
    current: Option<&CurrentProviderEvidence>,
    webhook_secret_sha256: &[u8],
) -> Result<i64, GithubProviderConfigurationFailure> {
    let Some(current) = current else {
        return Ok(1);
    };
    if current.webhook_secret_sha256 == webhook_secret_sha256 {
        Ok(current.webhook_verifier_revision)
    } else {
        current
            .webhook_verifier_revision
            .checked_add(1)
            .ok_or_else(provider_internal)
    }
}

fn next_runner_policy_revision(
    current: Option<&CurrentProviderEvidence>,
    runner_policy: &[u8],
) -> Result<i64, GithubProviderConfigurationFailure> {
    let Some(current) = current else {
        return Ok(1);
    };
    if current.runner_policy == runner_policy {
        Ok(current.runner_policy_revision)
    } else {
        current
            .runner_policy_revision
            .checked_add(1)
            .ok_or_else(provider_internal)
    }
}

#[derive(FromRow)]
struct WorkspaceBinding {
    authority_id: String,
    shard_id: String,
}

#[derive(FromRow)]
struct WorkspaceOperationRow {
    shard_id: String,
    workspace_id: String,
    revision: i64,
    request_digest: Vec<u8>,
    applied_at_ms: i64,
}

async fn load_workspace_operation(
    transaction: &mut Transaction<'_, Postgres>,
    authority_id: &str,
    operation_id: Uuid,
) -> Result<Option<WorkspaceOperationRow>, WorkspaceGithubRepositoriesFailure> {
    sqlx::query_as(
        r"
        SELECT shard_id, workspace_id, revision, request_digest, applied_at_ms
        FROM workspace_github_repository_operations
        WHERE authority_id=$1 AND operation_id=$2
        ",
    )
    .bind(authority_id)
    .bind(operation_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(workspace_database_failure)
}

async fn lock_provider_registry(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "SELECT singleton FROM github_provider_registry_lock WHERE singleton=true FOR UPDATE",
    )
    .fetch_one(&mut **transaction)
    .await?;
    Ok(())
}

async fn validate_shard_registry(
    transaction: &mut Transaction<'_, Postgres>,
    shard_id: &ShardId,
    workspace_id: WorkspaceId,
    repositories: &[GithubProviderRepositorySelection],
) -> Result<(), WorkspaceGithubRepositoriesFailure> {
    let workspace_text = workspace_id.to_string();
    let existing_count: i64 = sqlx::query_scalar(
        r"
        SELECT count(*) FROM workspace_github_repository_selections
        WHERE shard_id=$1 AND workspace_id<>$2
        ",
    )
    .bind(shard_id.as_str())
    .bind(&workspace_text)
    .fetch_one(&mut **transaction)
    .await
    .map_err(workspace_database_failure)?;
    let existing_count = usize::try_from(existing_count).map_err(|_| workspace_internal())?;
    if existing_count
        .checked_add(repositories.len())
        .is_none_or(|count| count > MAX_GITHUB_PROVIDER_REPOSITORIES)
    {
        return Err(workspace_registry_conflict());
    }

    let repository_ids = repositories
        .iter()
        .map(|repository| {
            i64::try_from(repository.repository_id().get()).map_err(|_| workspace_internal())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let repository_names = repositories
        .iter()
        .map(|repository| repository.repository_name().as_str().to_ascii_lowercase())
        .collect::<Vec<_>>();
    let conflicts: bool = sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1 FROM workspace_github_repository_selections
            WHERE shard_id=$1 AND workspace_id<>$2
              AND (
                  provider_repository_id=ANY($3::bigint[])
                  OR lower(repository_name)=ANY($4::text[])
              )
        )
        ",
    )
    .bind(shard_id.as_str())
    .bind(&workspace_text)
    .bind(repository_ids)
    .bind(repository_names)
    .fetch_one(&mut **transaction)
    .await
    .map_err(workspace_database_failure)?;
    if conflicts {
        return Err(workspace_registry_conflict());
    }
    Ok(())
}

async fn insert_repository_selection(
    transaction: &mut Transaction<'_, Postgres>,
    workspace_id: &str,
    shard_id: &ShardId,
    revision: i64,
    ordinal: i32,
    repository: &GithubProviderRepositorySelection,
    installation_binding_generation: i64,
) -> Result<(), WorkspaceGithubRepositoriesFailure> {
    let visibility = match repository.visibility() {
        ProviderRepositoryVisibility::Public => "public",
        ProviderRepositoryVisibility::Private => "private",
    };
    let authority_profile = match repository.authority_profile() {
        JobAuthorityProfile::Standard => "standard",
        JobAuthorityProfile::CredentialFree => "credential_free",
    };
    sqlx::query(
        r"
        INSERT INTO workspace_github_repository_selections (
            workspace_id, shard_id, revision, ordinal, provider_installation_id,
            installation_binding_generation,
            provider_repository_id, provider_repository_owner_id,
            repository_name, default_branch, repository_visibility,
            authority_profile
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
        ",
    )
    .bind(workspace_id)
    .bind(shard_id.as_str())
    .bind(revision)
    .bind(ordinal)
    .bind(i64::try_from(repository.installation_id().get()).map_err(|_| workspace_internal())?)
    .bind(installation_binding_generation)
    .bind(i64::try_from(repository.repository_id().get()).map_err(|_| workspace_internal())?)
    .bind(i64::try_from(repository.repository_owner_id().get()).map_err(|_| workspace_internal())?)
    .bind(repository.repository_name().as_str())
    .bind(repository.default_branch())
    .bind(visibility)
    .bind(authority_profile)
    .execute(&mut **transaction)
    .await
    .map_err(workspace_database_failure)?;
    Ok(())
}

#[derive(FromRow)]
struct InstallationBindingRow {
    provider_installation_id: i64,
    binding_generation: i64,
}

async fn advance_installation_binding(
    transaction: &mut Transaction<'_, Postgres>,
    workspace_id: &str,
    workspace_revision: i64,
    repository: &GithubProviderRepositorySelection,
) -> Result<i64, WorkspaceGithubRepositoriesFailure> {
    let repository_id =
        i64::try_from(repository.repository_id().get()).map_err(|_| workspace_internal())?;
    let installation_id =
        i64::try_from(repository.installation_id().get()).map_err(|_| workspace_internal())?;
    let current = sqlx::query_as::<_, InstallationBindingRow>(
        r"
        SELECT provider_installation_id, binding_generation
        FROM workspace_github_repository_installation_bindings
        WHERE workspace_id=$1 AND provider_repository_id=$2
        FOR UPDATE
        ",
    )
    .bind(workspace_id)
    .bind(repository_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(workspace_database_failure)?;
    let Some(current) = current else {
        sqlx::query(
            r"
            INSERT INTO workspace_github_repository_installation_bindings (
                workspace_id, provider_repository_id, provider_installation_id,
                binding_generation, updated_at_revision
            ) VALUES ($1,$2,$3,1,$4)
            ",
        )
        .bind(workspace_id)
        .bind(repository_id)
        .bind(installation_id)
        .bind(workspace_revision)
        .execute(&mut **transaction)
        .await
        .map_err(workspace_database_failure)?;
        return Ok(1);
    };
    if current.provider_installation_id == installation_id {
        return Ok(current.binding_generation);
    }
    let next_generation = current
        .binding_generation
        .checked_add(1)
        .ok_or_else(workspace_internal)?;
    let updated = sqlx::query(
        r"
        UPDATE workspace_github_repository_installation_bindings
        SET provider_installation_id=$3,
            binding_generation=$4,
            updated_at_revision=$5
        WHERE workspace_id=$1
          AND provider_repository_id=$2
          AND provider_installation_id=$6
          AND binding_generation=$7
        ",
    )
    .bind(workspace_id)
    .bind(repository_id)
    .bind(installation_id)
    .bind(next_generation)
    .bind(workspace_revision)
    .bind(current.provider_installation_id)
    .bind(current.binding_generation)
    .execute(&mut **transaction)
    .await
    .map_err(workspace_database_failure)?;
    if updated.rows_affected() != 1 {
        return Err(workspace_internal());
    }
    Ok(next_generation)
}

fn provider_configuration_digest(
    command: &ApplyGithubProviderConfigurationCommand,
) -> Result<[u8; 32], GithubProviderConfigurationFailure> {
    let configuration = command.configuration();
    let mut digest = Sha256::new();
    digest.update(CONFIGURATION_DIGEST_DOMAIN);
    digest_part(&mut digest, command.shard_id().as_str().as_bytes());
    digest_part(&mut digest, &command.revision().get().to_be_bytes());
    digest_part(
        &mut digest,
        configuration.dashboard_url().as_str().as_bytes(),
    );
    digest_part(&mut digest, &configuration.app_id().get().to_be_bytes());
    digest_part(
        &mut digest,
        configuration.app_client_id().as_str().as_bytes(),
    );
    digest_part(&mut digest, configuration.jwt_issuer().as_str().as_bytes());
    digest_part(&mut digest, configuration.private_key().expose_secret());
    digest_part(&mut digest, configuration.webhook_secret().expose_secret());
    digest_part(&mut digest, configuration.check_name().as_str().as_bytes());
    digest_part(
        &mut digest,
        &configuration
            .runner_policy()
            .canonical_bytes()
            .map_err(|_| provider_internal())?,
    );
    let schedule = configuration.schedule();
    for value in [
        schedule.poll_millis(),
        schedule.discovery_claim_millis(),
        schedule.fire_claim_millis(),
        schedule.retry_millis(),
        schedule.staleness_millis(),
        i64::from(schedule.maximum_manifests()),
        i64::from(schedule.maximum_fires_per_pass()),
    ] {
        digest_part(&mut digest, &value.to_be_bytes());
    }
    Ok(digest.finalize().into())
}

fn workspace_repositories_digest(command: &ApplyWorkspaceGithubRepositoriesCommand) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(REPOSITORY_DIGEST_DOMAIN);
    digest_part(&mut digest, command.shard_id().as_str().as_bytes());
    digest_part(&mut digest, command.workspace_id().as_uuid().as_bytes());
    digest_part(&mut digest, &command.revision().get().to_be_bytes());
    for repository in command.repositories() {
        digest_part(
            &mut digest,
            &repository.installation_id().get().to_be_bytes(),
        );
        digest_part(&mut digest, &repository.repository_id().get().to_be_bytes());
        digest_part(
            &mut digest,
            &repository.repository_owner_id().get().to_be_bytes(),
        );
        digest_part(
            &mut digest,
            repository.repository_name().as_str().as_bytes(),
        );
        digest_part(&mut digest, repository.default_branch().as_bytes());
        digest_part(
            &mut digest,
            match repository.visibility() {
                ProviderRepositoryVisibility::Public => b"public",
                ProviderRepositoryVisibility::Private => b"private",
            },
        );
        digest_part(
            &mut digest,
            match repository.authority_profile() {
                JobAuthorityProfile::Standard => b"standard",
                JobAuthorityProfile::CredentialFree => b"credential_free",
            },
        );
    }
    digest.finalize().into()
}

fn digest_part(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

async fn database_time_milliseconds(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT floor(extract(epoch FROM transaction_timestamp()) * 1000)::bigint")
        .fetch_one(&mut **transaction)
        .await
}

fn provider_result(
    operation_id: automata_ci_provisioning::OperationId,
    shard_id: automata_ci_provisioning::ShardId,
    revision: GithubProviderConfigurationRevision,
    applied_at_ms: i64,
) -> Result<ApplyGithubProviderConfigurationResult, GithubProviderConfigurationFailure> {
    let applied_at = timestamp(applied_at_ms).map_err(|()| provider_internal())?;
    Ok(ApplyGithubProviderConfigurationResult::new(
        operation_id,
        shard_id,
        revision,
        applied_at,
    ))
}

fn workspace_result(
    operation_id: automata_ci_provisioning::OperationId,
    shard_id: automata_ci_provisioning::ShardId,
    workspace_id: WorkspaceId,
    revision: WorkspaceGithubRepositoriesRevision,
    applied_at_ms: i64,
) -> Result<ApplyWorkspaceGithubRepositoriesResult, WorkspaceGithubRepositoriesFailure> {
    let applied_at = timestamp(applied_at_ms).map_err(|()| workspace_internal())?;
    Ok(ApplyWorkspaceGithubRepositoriesResult::new(
        operation_id,
        shard_id,
        workspace_id,
        revision,
        applied_at,
    ))
}

fn timestamp(milliseconds: i64) -> Result<GithubProviderTimestamp, ()> {
    if milliseconds < 0 {
        return Err(());
    }
    GithubProviderTimestamp::new(
        milliseconds / 1_000,
        u32::try_from(milliseconds % 1_000).map_err(|_| ())? * 1_000_000,
    )
    .map_err(|_| ())
}

fn provider_failure(
    kind: GithubProviderConfigurationFailureKind,
) -> GithubProviderConfigurationFailure {
    GithubProviderConfigurationFailure::new(kind)
}

fn provider_internal() -> GithubProviderConfigurationFailure {
    provider_failure(GithubProviderConfigurationFailureKind::Internal)
}

fn provider_database_failure(_: sqlx::Error) -> GithubProviderConfigurationFailure {
    provider_failure(GithubProviderConfigurationFailureKind::TemporarilyUnavailable)
}

fn workspace_failure(
    kind: WorkspaceGithubRepositoriesFailureKind,
) -> WorkspaceGithubRepositoriesFailure {
    WorkspaceGithubRepositoriesFailure::new(kind)
}

fn workspace_internal() -> WorkspaceGithubRepositoriesFailure {
    workspace_failure(WorkspaceGithubRepositoriesFailureKind::Internal)
}

fn workspace_registry_conflict() -> WorkspaceGithubRepositoriesFailure {
    workspace_failure(WorkspaceGithubRepositoriesFailureKind::ShardRegistryConflict)
}

fn workspace_database_failure(_: sqlx::Error) -> WorkspaceGithubRepositoriesFailure {
    workspace_failure(WorkspaceGithubRepositoriesFailureKind::TemporarilyUnavailable)
}
