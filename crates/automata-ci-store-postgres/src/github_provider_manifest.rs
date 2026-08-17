use async_trait::async_trait;
use automata_ci_core::{JobAuthorityProfile, Sha256Digest, UnixMillis};
use sqlx::{AssertSqlSafe, PgConnection, Postgres, Row as _, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::{
    PostgresStore, pg_bigint,
    workflow_runtime_policy::{
        database_now, lock_current as lock_current_runtime_policy,
        register_locked_workflow_runtime_policy,
    },
};
use automata_ci_provider::ProviderConnectionId;
use automata_ci_store::{
    AdmissionObject, BootstrapGithubProviderRepository, GithubCheckName,
    GithubInstallationBindingGeneration, GithubProviderManifest,
    GithubProviderManifestBootstrapReceipt, GithubProviderManifestLimits,
    GithubProviderManifestRecord, GithubProviderManifestRepository, GithubProviderManifestRevision,
    GithubProviderManifestStoreError, GithubProviderOrigins,
    GithubProviderRepositoryBootstrapReceipt, GithubProviderRunnerPolicyObject,
    GithubProviderWebhookVerifierFingerprint, GithubProviderWorkflowSelection,
    GithubRepositoryName, GithubServerServiceAppClientId, GithubServerServiceAppId,
    GithubServerServiceJwtIssuer, GithubServerServiceRevision, ObjectKey, ProviderInstallationId,
    ProviderRepositoryId, ProviderRepositoryOwnerId, ProviderRepositoryVisibility, RepositoryId,
    StoreError, TenantScope, WorkflowRuntimePolicyRevision, WorkflowRuntimePolicyStoreError,
};

const CURRENT_MANIFEST_QUERY: &str = r"
    SELECT
        revision.tenant_id,
        revision.repository_id,
        revision.provider_connection_id,
        revision.manifest_revision,
        revision.manifest_digest,
        revision.provider_installation_id,
        revision.installation_binding_generation,
        revision.github_repository_id,
        revision.github_repository_owner_id,
        revision.github_repository_name,
        revision.repository_visibility,
        revision.github_app_id,
        revision.github_app_client_id,
        revision.github_app_jwt_issuer_kind,
        revision.app_key_spki_sha256,
        revision.app_configuration_revision,
        revision.webhook_verifier_fingerprint_sha256,
        revision.webhook_verifier_revision,
        revision.policy_revision,
        revision.authority_profile,
        revision.runner_policy_digest,
        revision.runner_policy_object_key,
        revision.runner_policy_size_bytes,
        revision.runner_policy_media_type,
        revision.runtime_policy_revision,
        revision.runtime_policy_digest,
        revision.workflow_selection_kind,
        revision.workflow_path,
        revision.event_name,
        revision.git_ref,
        revision.check_subject_key,
        revision.check_name,
        revision.github_web_origin,
        revision.github_api_origin,
        revision.github_archive_origin,
        revision.github_rest_api_version,
        revision.github_rest_accept,
        revision.github_archive_accept,
        revision.repository_source_authentication,
        revision.repository_source_revision,
        revision.repository_archive_format,
        revision.webhook_max_body_bytes,
        revision.webhook_accept_timeout_ms,
        revision.push_webhook_max_commits,
        revision.path_filter_max_commits,
        revision.path_filter_max_changed_files,
        revision.archive_max_compressed_bytes,
        revision.archive_max_decompressed_bytes,
        revision.archive_max_entries,
        revision.archive_max_expanded_bytes,
        revision.archive_max_entry_path_bytes,
        revision.archive_max_workflows,
        revision.workflow_max_bytes,
        revision.registered_at_ms,
        current_manifest.activated_at_ms
    FROM github_provider_manifest_current AS current_manifest
    JOIN github_provider_manifest_revisions AS revision
      ON revision.tenant_id = current_manifest.tenant_id
     AND revision.repository_id = current_manifest.repository_id
     AND revision.provider_connection_id = current_manifest.provider_connection_id
     AND revision.manifest_revision = current_manifest.manifest_revision
     AND revision.manifest_digest = current_manifest.manifest_digest
";

#[async_trait]
impl GithubProviderManifestRepository for PostgresStore {
    async fn bootstrap_github_provider_repository(
        &self,
        request: BootstrapGithubProviderRepository,
    ) -> Result<GithubProviderRepositoryBootstrapReceipt, GithubProviderManifestStoreError> {
        let desired = request.manifest().manifest().clone();
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            .execute(&mut *transaction)
            .await
            .map_err(operation_error)?;

        lock_or_create_tenant(&mut transaction, desired.tenant().as_str()).await?;
        lock_or_create_repository(&mut transaction, &desired).await?;
        let policy_current =
            lock_current_runtime_policy(&mut transaction, request.runtime_policy().pin())
                .await
                .map_err(map_runtime_policy_error)?;
        let manifest_current =
            lock_current_manifest(&mut transaction, desired.connection_id()).await?;
        let authoritative_at = database_now(&mut transaction)
            .await
            .map_err(map_runtime_policy_error)?;
        let policy_receipt = register_locked_workflow_runtime_policy(
            &mut transaction,
            request.runtime_policy(),
            policy_current,
            authoritative_at,
        )
        .await
        .map_err(map_runtime_policy_error)?;
        let manifest_receipt = bootstrap_locked_manifest(
            &mut transaction,
            &desired,
            manifest_current,
            authoritative_at,
        )
        .await?;
        let receipt = automata_ci_store::adapter_spi::github_provider_repository_bootstrap_receipt(
            policy_receipt,
            manifest_receipt,
        )
        .map_err(|_| GithubProviderManifestStoreError::CorruptData)?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }

    async fn load_current_github_provider_manifest(
        &self,
        tenant: &TenantScope,
        connection_id: ProviderConnectionId,
    ) -> Result<GithubProviderManifestRecord, GithubProviderManifestStoreError> {
        let query =
            format!("{CURRENT_MANIFEST_QUERY} WHERE current_manifest.provider_connection_id = $1");
        let row = sqlx::query(AssertSqlSafe(query))
            .bind(connection_id.as_uuid())
            .fetch_optional(&self.pool)
            .await
            .map_err(operation_error)?
            .ok_or(GithubProviderManifestStoreError::NotFound)?;
        let record = decode_manifest_record(&row)?;
        if record.manifest().tenant() != tenant {
            return Err(GithubProviderManifestStoreError::NotFound);
        }
        Ok(record)
    }

    async fn list_current_github_provider_manifests(
        &self,
        limit: u16,
    ) -> Result<Vec<GithubProviderManifestRecord>, GithubProviderManifestStoreError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let query = format!(
            "{CURRENT_MANIFEST_QUERY} ORDER BY revision.tenant_id, revision.provider_connection_id LIMIT $1"
        );
        let rows = sqlx::query(AssertSqlSafe(query))
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await
            .map_err(operation_error)?;
        rows.iter().map(decode_manifest_record).collect()
    }

    async fn load_github_provider_manifest_revision(
        &self,
        tenant: &TenantScope,
        connection_id: ProviderConnectionId,
        revision: GithubProviderManifestRevision,
    ) -> Result<GithubProviderManifestRecord, GithubProviderManifestStoreError> {
        let row = sqlx::query(
            r"
            SELECT
                revision.tenant_id,
                revision.repository_id,
                revision.provider_connection_id,
                revision.manifest_revision,
                revision.manifest_digest,
                revision.provider_installation_id,
                revision.installation_binding_generation,
                revision.github_repository_id,
                revision.github_repository_owner_id,
                revision.github_repository_name,
                revision.repository_visibility,
                revision.github_app_id,
                revision.github_app_client_id,
                revision.github_app_jwt_issuer_kind,
                revision.app_key_spki_sha256,
                revision.app_configuration_revision,
                revision.webhook_verifier_fingerprint_sha256,
                revision.webhook_verifier_revision,
                revision.policy_revision,
                revision.authority_profile,
                revision.runner_policy_digest,
                revision.runner_policy_object_key,
                revision.runner_policy_size_bytes,
                revision.runner_policy_media_type,
                revision.runtime_policy_revision,
                revision.runtime_policy_digest,
                revision.workflow_selection_kind,
                revision.workflow_path,
                revision.event_name,
                revision.git_ref,
                revision.check_subject_key,
                revision.check_name,
                revision.github_web_origin,
                revision.github_api_origin,
                revision.github_archive_origin,
                revision.github_rest_api_version,
                revision.github_rest_accept,
                revision.github_archive_accept,
                revision.repository_source_authentication,
                revision.repository_source_revision,
                revision.repository_archive_format,
                revision.webhook_max_body_bytes,
                revision.webhook_accept_timeout_ms,
                revision.push_webhook_max_commits,
                revision.path_filter_max_commits,
                revision.path_filter_max_changed_files,
                revision.archive_max_compressed_bytes,
                revision.archive_max_decompressed_bytes,
                revision.archive_max_entries,
                revision.archive_max_expanded_bytes,
                revision.archive_max_entry_path_bytes,
                revision.archive_max_workflows,
                revision.workflow_max_bytes,
                revision.registered_at_ms,
                current_manifest.activated_at_ms
            FROM github_provider_manifest_revisions AS revision
            LEFT JOIN github_provider_manifest_current AS current_manifest
              ON current_manifest.tenant_id = revision.tenant_id
             AND current_manifest.repository_id = revision.repository_id
             AND current_manifest.provider_connection_id = revision.provider_connection_id
             AND current_manifest.manifest_revision = revision.manifest_revision
             AND current_manifest.manifest_digest = revision.manifest_digest
            WHERE revision.tenant_id = $1
              AND revision.provider_connection_id = $2
              AND revision.manifest_revision = $3
            ",
        )
        .bind(tenant.as_str())
        .bind(connection_id.as_uuid())
        .bind(pg_bigint(revision.get()))
        .fetch_optional(&self.pool)
        .await
        .map_err(operation_error)?
        .ok_or(GithubProviderManifestStoreError::NotFound)?;
        decode_manifest_record(&row)
    }
}

#[allow(clippy::single_match_else)] // Current and absent pointer states are symmetric.
pub(super) async fn bootstrap_locked_manifest(
    transaction: &mut Transaction<'_, Postgres>,
    desired: &GithubProviderManifest,
    current: Option<GithubProviderManifestRecord>,
    authoritative_at: UnixMillis,
) -> Result<GithubProviderManifestBootstrapReceipt, GithubProviderManifestStoreError> {
    let (record, replay) = match current {
        Some(current) => {
            if current.manifest().tenant() != desired.tenant() {
                return Err(GithubProviderManifestStoreError::ConfigurationDrift);
            }
            if current.manifest() == desired {
                (current, true)
            } else {
                if !automata_ci_store::adapter_spi::github_provider_manifest_valid_successor(
                    desired,
                    current.manifest(),
                ) {
                    if current.manifest().github_repository_owner_id().is_none()
                        && desired.github_repository_owner_id().is_some()
                        && automata_ci_store::adapter_spi::github_provider_manifest_same_connection_identity(
                            desired,
                            current.manifest(),
                        )
                    {
                        return Err(GithubProviderManifestStoreError::OwnerBindingRevisionRequired);
                    }
                    return Err(GithubProviderManifestStoreError::ConfigurationDrift);
                }
                if current
                    .activated_at()
                    .is_none_or(|activated_at| authoritative_at < activated_at)
                {
                    return Err(GithubProviderManifestStoreError::ConfigurationDrift);
                }
                if manifest_revision_exists(
                    transaction,
                    desired.connection_id(),
                    desired.revision(),
                )
                .await?
                {
                    return Err(GithubProviderManifestStoreError::ConfigurationDrift);
                }
                insert_manifest_revision(transaction, desired, authoritative_at).await?;
                advance_current_manifest(
                    transaction,
                    current.manifest(),
                    desired,
                    authoritative_at,
                )
                .await?;
                (
                    automata_ci_store::adapter_spi::github_provider_manifest_record(
                        desired.clone(),
                        authoritative_at,
                        Some(authoritative_at),
                    )
                    .map_err(|_| GithubProviderManifestStoreError::CorruptData)?,
                    false,
                )
            }
        }
        None => {
            if desired.revision().get() != 1
                || desired.installation_binding_generation()
                    != GithubInstallationBindingGeneration::initial()
                || connection_has_manifest_revisions(transaction, desired.connection_id()).await?
            {
                return Err(GithubProviderManifestStoreError::ConfigurationDrift);
            }
            insert_manifest_revision(transaction, desired, authoritative_at).await?;
            insert_current_manifest(transaction, desired, authoritative_at).await?;
            (
                automata_ci_store::adapter_spi::github_provider_manifest_record(
                    desired.clone(),
                    authoritative_at,
                    Some(authoritative_at),
                )
                .map_err(|_| GithubProviderManifestStoreError::CorruptData)?,
                false,
            )
        }
    };
    automata_ci_store::adapter_spi::github_provider_manifest_bootstrap_receipt(record, replay)
        .map_err(|_| GithubProviderManifestStoreError::CorruptData)
}

fn map_runtime_policy_error(
    error: WorkflowRuntimePolicyStoreError,
) -> GithubProviderManifestStoreError {
    match error {
        WorkflowRuntimePolicyStoreError::InvalidTarget
        | WorkflowRuntimePolicyStoreError::Conflict => {
            GithubProviderManifestStoreError::ConfigurationDrift
        }
        WorkflowRuntimePolicyStoreError::Store(StoreError::CorruptData(_)) => {
            GithubProviderManifestStoreError::CorruptData
        }
        WorkflowRuntimePolicyStoreError::Store(error) => {
            GithubProviderManifestStoreError::operation(error)
        }
    }
}

pub(super) async fn lock_or_create_tenant(
    connection: &mut PgConnection,
    tenant: &str,
) -> Result<(), GithubProviderManifestStoreError> {
    sqlx::query(
        r"
        WITH stamp AS (
            SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT AS now_ms
        )
        INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms)
        SELECT $1, $1, now_ms, now_ms FROM stamp
        ON CONFLICT (id) DO NOTHING
        ",
    )
    .bind(tenant)
    .execute(&mut *connection)
    .await
    .map_err(operation_error)?;
    let locked: Option<String> = sqlx::query_scalar(
        r"
        SELECT id
        FROM tenants
        WHERE id = $1
        FOR UPDATE
        ",
    )
    .bind(tenant)
    .fetch_optional(connection)
    .await
    .map_err(operation_error)?;
    if locked.as_deref() != Some(tenant) {
        return Err(GithubProviderManifestStoreError::CorruptData);
    }
    Ok(())
}

pub(super) async fn lock_or_create_repository(
    connection: &mut PgConnection,
    manifest: &GithubProviderManifest,
) -> Result<(), GithubProviderManifestStoreError> {
    let (owner, name) = manifest
        .github_repository_name()
        .as_str()
        .split_once('/')
        .ok_or(GithubProviderManifestStoreError::CorruptData)?;
    let provider_repository_id = manifest.github_repository_id().get().to_string();
    let rows = repository_identity_rows(
        connection,
        manifest.repository_id().as_uuid(),
        manifest.tenant().as_str(),
        &provider_repository_id,
        owner,
        name,
    )
    .await?;

    if rows.is_empty() {
        let inserted = sqlx::query(
            r"
            WITH stamp AS (
                SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT AS now_ms
            )
            INSERT INTO repositories (
                id, tenant_id, scm_provider, provider_repository_id,
                owner, name, created_at_ms, updated_at_ms
            )
            SELECT $1, $2, 'github', $3, $4, $5, now_ms, now_ms FROM stamp
            ",
        )
        .bind(manifest.repository_id().as_uuid())
        .bind(manifest.tenant().as_str())
        .bind(&provider_repository_id)
        .bind(owner)
        .bind(name)
        .execute(&mut *connection)
        .await
        .map_err(configuration_insert_error)?;
        if inserted.rows_affected() != 1 {
            return Err(GithubProviderManifestStoreError::ConfigurationDrift);
        }
        return verify_repository_publication_policy(connection, manifest).await;
    }

    if rows.len() != 1 || !repository_row_is_exact(&rows[0], manifest, &provider_repository_id)? {
        return Err(GithubProviderManifestStoreError::ConfigurationDrift);
    }
    verify_repository_publication_policy(connection, manifest).await
}

async fn repository_identity_rows(
    connection: &mut PgConnection,
    repository_id: Uuid,
    tenant: &str,
    provider_repository_id: &str,
    owner: &str,
    name: &str,
) -> Result<Vec<PgRow>, GithubProviderManifestStoreError> {
    sqlx::query(
        r"
        SELECT id, tenant_id, scm_provider, provider_repository_id, owner, name
        FROM repositories
        WHERE id = $1
           OR (
                tenant_id = $2
                AND scm_provider = 'github'
                AND (
                    provider_repository_id = $3
                    OR (lower(owner) = lower($4) AND lower(name) = lower($5))
                )
           )
        ORDER BY id
        FOR UPDATE
        ",
    )
    .bind(repository_id)
    .bind(tenant)
    .bind(provider_repository_id)
    .bind(owner)
    .bind(name)
    .fetch_all(connection)
    .await
    .map_err(operation_error)
}

fn repository_row_is_exact(
    row: &PgRow,
    manifest: &GithubProviderManifest,
    provider_repository_id: &str,
) -> Result<bool, GithubProviderManifestStoreError> {
    let (owner, name) = manifest
        .github_repository_name()
        .as_str()
        .split_once('/')
        .ok_or(GithubProviderManifestStoreError::CorruptData)?;
    Ok(
        row.try_get::<Uuid, _>("id").map_err(operation_error)?
            == manifest.repository_id().as_uuid()
            && row
                .try_get::<String, _>("tenant_id")
                .map_err(operation_error)?
                == manifest.tenant().as_str()
            && row
                .try_get::<String, _>("scm_provider")
                .map_err(operation_error)?
                == "github"
            && row
                .try_get::<String, _>("provider_repository_id")
                .map_err(operation_error)?
                == provider_repository_id
            && row.try_get::<String, _>("owner").map_err(operation_error)? == owner
            && row.try_get::<String, _>("name").map_err(operation_error)? == name,
    )
}

async fn verify_repository_publication_policy(
    connection: &mut PgConnection,
    manifest: &GithubProviderManifest,
) -> Result<(), GithubProviderManifestStoreError> {
    let count: i64 = sqlx::query_scalar(
        r"
        SELECT COUNT(*)
        FROM repository_publication_policies
        WHERE tenant_id = $1 AND repository_id = $2
        ",
    )
    .bind(manifest.tenant().as_str())
    .bind(manifest.repository_id().as_uuid())
    .fetch_one(connection)
    .await
    .map_err(operation_error)?;
    if count != 1 {
        return Err(GithubProviderManifestStoreError::CorruptData);
    }
    Ok(())
}

pub(super) async fn lock_current_manifest(
    connection: &mut PgConnection,
    connection_id: ProviderConnectionId,
) -> Result<Option<GithubProviderManifestRecord>, GithubProviderManifestStoreError> {
    let query = format!(
        "{CURRENT_MANIFEST_QUERY} WHERE current_manifest.provider_connection_id = $1 FOR UPDATE OF current_manifest"
    );
    sqlx::query(AssertSqlSafe(query))
        .bind(connection_id.as_uuid())
        .fetch_optional(connection)
        .await
        .map_err(operation_error)?
        .map(|row| decode_manifest_record(&row))
        .transpose()
}

async fn connection_has_manifest_revisions(
    connection: &mut PgConnection,
    connection_id: ProviderConnectionId,
) -> Result<bool, GithubProviderManifestStoreError> {
    sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM github_provider_manifest_revisions
            WHERE provider_connection_id = $1
        )
        ",
    )
    .bind(connection_id.as_uuid())
    .fetch_one(connection)
    .await
    .map_err(operation_error)
}

async fn manifest_revision_exists(
    connection: &mut PgConnection,
    connection_id: ProviderConnectionId,
    revision: GithubProviderManifestRevision,
) -> Result<bool, GithubProviderManifestStoreError> {
    sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM github_provider_manifest_revisions
            WHERE provider_connection_id = $1 AND manifest_revision = $2
        )
        ",
    )
    .bind(connection_id.as_uuid())
    .bind(pg_bigint(revision.get()))
    .fetch_one(connection)
    .await
    .map_err(operation_error)
}

#[allow(clippy::too_many_lines)] // Every immutable manifest field is bound explicitly.
async fn insert_manifest_revision(
    connection: &mut PgConnection,
    manifest: &GithubProviderManifest,
    registered_at: UnixMillis,
) -> Result<(), GithubProviderManifestStoreError> {
    let inserted = sqlx::query(
        r"
        INSERT INTO github_provider_manifest_revisions (
            tenant_id, repository_id, provider_connection_id,
            manifest_revision, manifest_digest, provider_installation_id,
            github_repository_id, github_repository_owner_id,
            github_repository_name, repository_visibility,
            github_app_id, github_app_client_id, github_app_jwt_issuer_kind,
            app_key_spki_sha256, app_configuration_revision,
            webhook_verifier_fingerprint_sha256, webhook_verifier_revision,
            policy_revision, authority_profile,
            workflow_selection_kind, workflow_path, event_name, git_ref,
            check_subject_key, check_name,
            github_web_origin, github_api_origin, github_archive_origin,
            github_rest_api_version, github_rest_accept, github_archive_accept,
            repository_source_authentication, repository_source_revision,
            repository_archive_format,
            webhook_max_body_bytes, webhook_accept_timeout_ms,
            push_webhook_max_commits, path_filter_max_commits,
            path_filter_max_changed_files,
            archive_max_compressed_bytes, archive_max_decompressed_bytes,
            archive_max_entries, archive_max_expanded_bytes,
            archive_max_entry_path_bytes, archive_max_workflows,
            workflow_max_bytes,
            runner_policy_digest, runner_policy_object_key,
            runner_policy_size_bytes, runner_policy_media_type,
            runtime_policy_revision, runtime_policy_digest,
            installation_binding_generation,
            registered_at_ms
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            $11, $12, $13, $14, $15, $16, $17, $18, $19,
            $20, $21, $22, $23, $24, $25, $26, $27,
            $28, $29, $30, $31, $32, $33, $34, $35,
            $36, $37, $38, $39, $40, $41, $42, $43, $44, $45,
            $46, $47, $48, $49, $50, $51, $52, $53, $54
        )
        ",
    )
    .bind(manifest.tenant().as_str())
    .bind(manifest.repository_id().as_uuid())
    .bind(manifest.connection_id().as_uuid())
    .bind(pg_bigint(manifest.revision().get()))
    .bind(manifest.digest().as_bytes().as_slice())
    .bind(i64_from_u64(manifest.installation_id().get())?)
    .bind(i64_from_u64(manifest.github_repository_id().get())?)
    .bind(
        manifest
            .github_repository_owner_id()
            .map(|owner| i64_from_u64(owner.get()))
            .transpose()?,
    )
    .bind(manifest.github_repository_name().as_str())
    .bind(provider_repository_visibility_name(
        manifest.repository_visibility(),
    ))
    .bind(pg_bigint(manifest.github_app_id().get()))
    .bind(manifest.app_client_id().as_str())
    .bind(manifest.jwt_issuer().as_str())
    .bind(manifest.app_key_spki_sha256().as_bytes().as_slice())
    .bind(pg_bigint(manifest.app_configuration_revision().get()))
    .bind(
        manifest
            .webhook_verifier_fingerprint()
            .sha256()
            .as_bytes()
            .as_slice(),
    )
    .bind(pg_bigint(manifest.webhook_verifier_revision().get()))
    .bind(pg_bigint(manifest.policy_revision().get()))
    .bind(authority_profile_name(manifest.authority_profile()))
    .bind(manifest.workflow_selection().as_durable_str())
    .bind(manifest.workflow_path())
    .bind(manifest.event_name())
    .bind(manifest.git_ref())
    .bind(manifest.check_subject_key().as_str())
    .bind(manifest.check_name().as_str())
    .bind(manifest.origins().web_origin())
    .bind(manifest.origins().api_origin())
    .bind(manifest.origins().archive_origin())
    .bind(manifest.rest_api_version())
    .bind(manifest.rest_accept())
    .bind(manifest.archive_accept())
    .bind(manifest.source_authentication())
    .bind(manifest.source_revision())
    .bind(manifest.archive_format())
    .bind(i64_from_u64(manifest.limits().webhook_max_body_bytes())?)
    .bind(i64_from_u64(
        manifest.limits().webhook_accept_timeout_millis(),
    )?)
    .bind(i64_from_u64(manifest.limits().push_webhook_max_commits())?)
    .bind(i64_from_u64(manifest.limits().path_filter_max_commits())?)
    .bind(i64_from_u64(
        manifest.limits().path_filter_max_changed_files(),
    )?)
    .bind(i64_from_u64(
        manifest.limits().archive_max_compressed_bytes(),
    )?)
    .bind(i64_from_u64(
        manifest.limits().archive_max_decompressed_bytes(),
    )?)
    .bind(i64_from_u64(manifest.limits().archive_max_entries())?)
    .bind(i64_from_u64(
        manifest.limits().archive_max_expanded_bytes(),
    )?)
    .bind(i64_from_u64(
        manifest.limits().archive_max_entry_path_bytes(),
    )?)
    .bind(i64_from_u64(manifest.limits().archive_max_workflows())?)
    .bind(i64_from_u64(manifest.limits().workflow_max_bytes())?)
    .bind(
        manifest
            .runner_policy()
            .object()
            .digest()
            .as_bytes()
            .as_slice(),
    )
    .bind(manifest.runner_policy().object().object_key().as_str())
    .bind(i64_from_u64(
        manifest.runner_policy().object().encoded_size(),
    )?)
    .bind(manifest.runner_policy().object().media_type())
    .bind(pg_bigint(manifest.runtime_policy_revision().get()))
    .bind(manifest.runtime_policy_digest().as_bytes().as_slice())
    .bind(pg_bigint(manifest.installation_binding_generation().get()))
    .bind(registered_at.get())
    .execute(connection)
    .await
    .map_err(configuration_insert_error)?;
    if inserted.rows_affected() != 1 {
        return Err(GithubProviderManifestStoreError::ConfigurationDrift);
    }
    Ok(())
}

async fn insert_current_manifest(
    connection: &mut PgConnection,
    manifest: &GithubProviderManifest,
    activated_at: UnixMillis,
) -> Result<(), GithubProviderManifestStoreError> {
    let inserted = sqlx::query(
        r"
        INSERT INTO github_provider_manifest_current (
            tenant_id, repository_id, provider_connection_id, manifest_revision,
            manifest_digest, activated_at_ms
        ) VALUES ($1, $2, $3, $4, $5, $6)
        ",
    )
    .bind(manifest.tenant().as_str())
    .bind(manifest.repository_id().as_uuid())
    .bind(manifest.connection_id().as_uuid())
    .bind(pg_bigint(manifest.revision().get()))
    .bind(manifest.digest().as_bytes().as_slice())
    .bind(activated_at.get())
    .execute(connection)
    .await
    .map_err(configuration_insert_error)?;
    if inserted.rows_affected() != 1 {
        return Err(GithubProviderManifestStoreError::ConfigurationDrift);
    }
    Ok(())
}

async fn advance_current_manifest(
    connection: &mut PgConnection,
    prior: &GithubProviderManifest,
    replacement: &GithubProviderManifest,
    activated_at: UnixMillis,
) -> Result<(), GithubProviderManifestStoreError> {
    let updated = sqlx::query(
        r"
        UPDATE github_provider_manifest_current
        SET manifest_revision = $4,
            manifest_digest = $5,
            activated_at_ms = $6
        WHERE tenant_id = $1
          AND repository_id = $8
          AND provider_connection_id = $2
          AND manifest_revision = $3
          AND manifest_digest = $7
        ",
    )
    .bind(prior.tenant().as_str())
    .bind(prior.connection_id().as_uuid())
    .bind(pg_bigint(prior.revision().get()))
    .bind(pg_bigint(replacement.revision().get()))
    .bind(replacement.digest().as_bytes().as_slice())
    .bind(activated_at.get())
    .bind(prior.digest().as_bytes().as_slice())
    .bind(prior.repository_id().as_uuid())
    .execute(connection)
    .await
    .map_err(configuration_insert_error)?;
    if updated.rows_affected() != 1 {
        return Err(GithubProviderManifestStoreError::ConfigurationDrift);
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // Exact rehydration verifies every immutable manifest field.
fn decode_manifest_record(
    row: &PgRow,
) -> Result<GithubProviderManifestRecord, GithubProviderManifestStoreError> {
    let durable_tenant: String = row.try_get("tenant_id").map_err(operation_error)?;
    let tenant = TenantScope::from_authenticated_tenant_id(durable_tenant)
        .map_err(|_| GithubProviderManifestStoreError::CorruptData)?;
    let repository_id =
        RepositoryId::from_uuid(row.try_get("repository_id").map_err(operation_error)?);
    let connection_id = ProviderConnectionId::from_uuid(
        row.try_get("provider_connection_id")
            .map_err(operation_error)?,
    )
    .map_err(|_| GithubProviderManifestStoreError::CorruptData)?;
    let installation_id = ProviderInstallationId::new(positive_u64(
        row.try_get("provider_installation_id")
            .map_err(operation_error)?,
    )?)
    .map_err(|_| GithubProviderManifestStoreError::CorruptData)?;
    let installation_binding_generation = GithubInstallationBindingGeneration::new(positive_u64(
        row.try_get("installation_binding_generation")
            .map_err(operation_error)?,
    )?)
    .map_err(|_| GithubProviderManifestStoreError::CorruptData)?;
    let github_repository_id = ProviderRepositoryId::new(positive_u64(
        row.try_get("github_repository_id")
            .map_err(operation_error)?,
    )?)
    .map_err(|_| GithubProviderManifestStoreError::CorruptData)?;
    let github_repository_owner_id = row
        .try_get::<Option<i64>, _>("github_repository_owner_id")
        .map_err(operation_error)?
        .map(positive_u64)
        .transpose()?
        .map(ProviderRepositoryOwnerId::new)
        .transpose()
        .map_err(|_| GithubProviderManifestStoreError::CorruptData)?;
    let github_repository_name = GithubRepositoryName::new(
        row.try_get::<String, _>("github_repository_name")
            .map_err(operation_error)?,
    )
    .map_err(|_| GithubProviderManifestStoreError::CorruptData)?;
    let repository_visibility = decode_provider_repository_visibility(
        &row.try_get::<String, _>("repository_visibility")
            .map_err(operation_error)?,
    )
    .ok_or(GithubProviderManifestStoreError::CorruptData)?;
    let github_app_id = GithubServerServiceAppId::new(positive_u64(
        row.try_get("github_app_id").map_err(operation_error)?,
    )?)
    .map_err(|_| GithubProviderManifestStoreError::CorruptData)?;
    let app_client_id = GithubServerServiceAppClientId::new(
        row.try_get::<String, _>("github_app_client_id")
            .map_err(operation_error)?,
    )
    .map_err(|_| GithubProviderManifestStoreError::CorruptData)?;
    let jwt_issuer = decode_github_server_service_jwt_issuer(
        &row.try_get::<String, _>("github_app_jwt_issuer_kind")
            .map_err(operation_error)?,
    )
    .ok_or(GithubProviderManifestStoreError::CorruptData)?;
    let app_key_spki_sha256 = decode_sha256(
        row.try_get("app_key_spki_sha256")
            .map_err(operation_error)?,
    )?;
    let app_configuration_revision = GithubServerServiceRevision::new(positive_u64(
        row.try_get("app_configuration_revision")
            .map_err(operation_error)?,
    )?)
    .map_err(|_| GithubProviderManifestStoreError::CorruptData)?;
    let webhook_verifier_fingerprint =
        GithubProviderWebhookVerifierFingerprint::from_sha256(decode_sha256(
            row.try_get("webhook_verifier_fingerprint_sha256")
                .map_err(operation_error)?,
        )?)
        .map_err(|_| GithubProviderManifestStoreError::CorruptData)?;
    let webhook_verifier_revision = GithubServerServiceRevision::new(positive_u64(
        row.try_get("webhook_verifier_revision")
            .map_err(operation_error)?,
    )?)
    .map_err(|_| GithubProviderManifestStoreError::CorruptData)?;
    let policy_revision = GithubServerServiceRevision::new(positive_u64(
        row.try_get("policy_revision").map_err(operation_error)?,
    )?)
    .map_err(|_| GithubProviderManifestStoreError::CorruptData)?;
    let authority_profile = parse_authority_profile(
        &row.try_get::<String, _>("authority_profile")
            .map_err(operation_error)?,
    )?;
    let runner_policy = GithubProviderRunnerPolicyObject::new(
        AdmissionObject::new(
            decode_sha256(
                row.try_get("runner_policy_digest")
                    .map_err(operation_error)?,
            )?,
            ObjectKey::new(
                row.try_get::<String, _>("runner_policy_object_key")
                    .map_err(operation_error)?,
            )
            .map_err(|_| GithubProviderManifestStoreError::CorruptData)?,
            positive_u64(
                row.try_get("runner_policy_size_bytes")
                    .map_err(operation_error)?,
            )?,
            row.try_get::<String, _>("runner_policy_media_type")
                .map_err(operation_error)?,
        )
        .map_err(|_| GithubProviderManifestStoreError::CorruptData)?,
    )
    .map_err(|_| GithubProviderManifestStoreError::CorruptData)?;
    let runtime_policy_revision = WorkflowRuntimePolicyRevision::new(positive_u64(
        row.try_get("runtime_policy_revision")
            .map_err(operation_error)?,
    )?)
    .map_err(|_| GithubProviderManifestStoreError::CorruptData)?;
    let runtime_policy_digest = decode_sha256(
        row.try_get("runtime_policy_digest")
            .map_err(operation_error)?,
    )?;
    let check_name = GithubCheckName::new(
        row.try_get::<String, _>("check_name")
            .map_err(operation_error)?,
    )
    .map_err(|_| GithubProviderManifestStoreError::CorruptData)?;
    let limits = GithubProviderManifestLimits::new(
        positive_u64(
            row.try_get("webhook_max_body_bytes")
                .map_err(operation_error)?,
        )?,
        positive_u64(
            row.try_get("webhook_accept_timeout_ms")
                .map_err(operation_error)?,
        )?,
        positive_u64(
            row.try_get("push_webhook_max_commits")
                .map_err(operation_error)?,
        )?,
        positive_u64(
            row.try_get("path_filter_max_commits")
                .map_err(operation_error)?,
        )?,
        positive_u64(
            row.try_get("path_filter_max_changed_files")
                .map_err(operation_error)?,
        )?,
        positive_u64(
            row.try_get("archive_max_compressed_bytes")
                .map_err(operation_error)?,
        )?,
        positive_u64(
            row.try_get("archive_max_decompressed_bytes")
                .map_err(operation_error)?,
        )?,
        positive_u64(
            row.try_get("archive_max_entries")
                .map_err(operation_error)?,
        )?,
        positive_u64(
            row.try_get("archive_max_expanded_bytes")
                .map_err(operation_error)?,
        )?,
        positive_u64(
            row.try_get("archive_max_entry_path_bytes")
                .map_err(operation_error)?,
        )?,
        positive_u64(
            row.try_get("archive_max_workflows")
                .map_err(operation_error)?,
        )?,
        positive_u64(row.try_get("workflow_max_bytes").map_err(operation_error)?)?,
    )
    .map_err(|_| GithubProviderManifestStoreError::CorruptData)?;
    let revision = GithubProviderManifestRevision::new(positive_u64(
        row.try_get("manifest_revision").map_err(operation_error)?,
    )?)
    .map_err(|_| GithubProviderManifestStoreError::CorruptData)?;

    let workflow_path: String = row.try_get("workflow_path").map_err(operation_error)?;
    let check_subject_key: String = row.try_get("check_subject_key").map_err(operation_error)?;
    if workflow_path != check_subject_key {
        return Err(GithubProviderManifestStoreError::CorruptData);
    }
    require_exact_text(row, "workflow_selection_kind", "all_direct")?;
    if workflow_path != automata_ci_store::GITHUB_PROVIDER_ALL_DIRECT_WORKFLOWS_KEY {
        return Err(GithubProviderManifestStoreError::CorruptData);
    }
    let workflow_selection = GithubProviderWorkflowSelection::all_direct();
    require_exact_text(row, "event_name", automata_ci_store::GITHUB_PROVIDER_EVENT)?;
    let git_ref = automata_ci_store::GithubProviderGitRef::new(
        row.try_get::<String, _>("git_ref")
            .map_err(operation_error)?,
    )
    .map_err(|_| GithubProviderManifestStoreError::CorruptData)?;
    require_exact_text(
        row,
        "github_web_origin",
        automata_ci_store::GITHUB_PROVIDER_WEB_ORIGIN,
    )?;
    require_exact_text(
        row,
        "github_api_origin",
        automata_ci_store::GITHUB_PROVIDER_API_ORIGIN,
    )?;
    require_exact_text(
        row,
        "github_archive_origin",
        automata_ci_store::GITHUB_PROVIDER_ARCHIVE_ORIGIN,
    )?;
    require_exact_text(
        row,
        "github_rest_api_version",
        automata_ci_store::GITHUB_PROVIDER_REST_API_VERSION,
    )?;
    require_exact_text(
        row,
        "github_rest_accept",
        automata_ci_store::GITHUB_PROVIDER_REST_ACCEPT,
    )?;
    require_exact_text(
        row,
        "github_archive_accept",
        automata_ci_store::GITHUB_PROVIDER_ARCHIVE_ACCEPT,
    )?;
    require_exact_text(
        row,
        "repository_source_authentication",
        match repository_visibility {
            ProviderRepositoryVisibility::Public => {
                automata_ci_store::GITHUB_PROVIDER_PUBLIC_SOURCE_AUTHENTICATION
            }
            ProviderRepositoryVisibility::Private => {
                automata_ci_store::GITHUB_PROVIDER_PRIVATE_SOURCE_AUTHENTICATION
            }
        },
    )?;
    require_exact_text(
        row,
        "repository_source_revision",
        automata_ci_store::GITHUB_PROVIDER_SOURCE_REVISION,
    )?;
    require_exact_text(
        row,
        "repository_archive_format",
        automata_ci_store::GITHUB_PROVIDER_ARCHIVE_FORMAT,
    )?;

    let mut manifest = GithubProviderManifest::new_with_workflow_selection_and_git_ref(
        tenant,
        connection_id,
        installation_id,
        github_repository_id,
        github_repository_name,
        repository_visibility,
        github_app_id,
        app_client_id,
        jwt_issuer,
        app_key_spki_sha256,
        app_configuration_revision,
        webhook_verifier_fingerprint,
        webhook_verifier_revision,
        policy_revision,
        authority_profile,
        runner_policy,
        runtime_policy_revision,
        runtime_policy_digest,
        workflow_selection,
        git_ref,
        check_name,
        GithubProviderOrigins::github_dot_com(),
        limits,
        revision,
    )
    .with_installation_binding_generation(installation_binding_generation);
    if let Some(owner_id) = github_repository_owner_id {
        manifest = manifest.with_repository_owner_id(owner_id);
    }
    let expected_digest = decode_sha256(row.try_get("manifest_digest").map_err(operation_error)?)?;
    let manifest = automata_ci_store::adapter_spi::github_provider_manifest(
        manifest,
        repository_id,
        expected_digest,
    )
    .map_err(|_| GithubProviderManifestStoreError::CorruptData)?;
    let registered_at = UnixMillis::new(row.try_get("registered_at_ms").map_err(operation_error)?);
    let activated_at = row
        .try_get::<Option<i64>, _>("activated_at_ms")
        .map_err(operation_error)?
        .map(UnixMillis::new);
    automata_ci_store::adapter_spi::github_provider_manifest_record(
        manifest,
        registered_at,
        activated_at,
    )
    .map_err(|_| GithubProviderManifestStoreError::CorruptData)
}

const fn authority_profile_name(profile: JobAuthorityProfile) -> &'static str {
    match profile {
        JobAuthorityProfile::Standard => "standard",
        JobAuthorityProfile::CredentialFree => "credential_free",
    }
}

fn parse_authority_profile(
    value: &str,
) -> Result<JobAuthorityProfile, GithubProviderManifestStoreError> {
    match value {
        "standard" => Ok(JobAuthorityProfile::Standard),
        "credential_free" => Ok(JobAuthorityProfile::CredentialFree),
        _ => Err(GithubProviderManifestStoreError::CorruptData),
    }
}

const fn provider_repository_visibility_name(
    visibility: ProviderRepositoryVisibility,
) -> &'static str {
    match visibility {
        ProviderRepositoryVisibility::Public => "public",
        ProviderRepositoryVisibility::Private => "private",
    }
}

fn decode_provider_repository_visibility(value: &str) -> Option<ProviderRepositoryVisibility> {
    match value {
        "public" => Some(ProviderRepositoryVisibility::Public),
        "private" => Some(ProviderRepositoryVisibility::Private),
        _ => None,
    }
}

fn decode_github_server_service_jwt_issuer(value: &str) -> Option<GithubServerServiceJwtIssuer> {
    match value {
        "app_client_id" => Some(GithubServerServiceJwtIssuer::AppClientId),
        "app_id" => Some(GithubServerServiceJwtIssuer::AppId),
        _ => None,
    }
}

fn require_exact_text(
    row: &PgRow,
    column: &str,
    expected: &str,
) -> Result<(), GithubProviderManifestStoreError> {
    let actual: String = row.try_get(column).map_err(operation_error)?;
    if actual != expected {
        return Err(GithubProviderManifestStoreError::CorruptData);
    }
    Ok(())
}

fn decode_sha256(bytes: Vec<u8>) -> Result<Sha256Digest, GithubProviderManifestStoreError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| GithubProviderManifestStoreError::CorruptData)?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn positive_u64(value: i64) -> Result<u64, GithubProviderManifestStoreError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(GithubProviderManifestStoreError::CorruptData)
}

fn i64_from_u64(value: u64) -> Result<i64, GithubProviderManifestStoreError> {
    i64::try_from(value).map_err(|_| GithubProviderManifestStoreError::CorruptData)
}

fn configuration_insert_error(error: sqlx::Error) -> GithubProviderManifestStoreError {
    if error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|code| code.starts_with("23"))
    {
        GithubProviderManifestStoreError::ConfigurationDrift
    } else {
        operation_error(error)
    }
}

fn operation_error(error: sqlx::Error) -> GithubProviderManifestStoreError {
    GithubProviderManifestStoreError::operation(error)
}
