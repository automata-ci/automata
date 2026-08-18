use automata_ci_core::WorkspaceId;
use automata_ci_provider::{
    ExternalRepositoryId, ExternalRepositoryIdentity, ProviderArchiveLimits,
    ProviderConfigurationRevision, ProviderConnectionConfiguration, ProviderConnectionId,
    ProviderConnectionManifest, ProviderConnectionPolicyDocument, ProviderConnectionRevision,
    ProviderDefaultBranch, ProviderInstanceId, ProviderRepositoryError, ProviderRepositoryPath,
    ProviderRunnerPolicyBinding, ProviderSaveOutcome, ProviderSchemaVersion,
    ProviderWorkflowSource, RepositoryVisibility,
};
use sqlx::{FromRow, Postgres, Transaction};

use crate::{
    CONNECTION_LOCK_SALT, PostgresProviderManifestRepository, digest, lifecycle, lifecycle_text,
    lock, optional_timestamp, positive_u16, positive_u64, timestamp, unavailable,
};

#[derive(FromRow)]
struct ConnectionRow {
    connection_id: uuid::Uuid,
    revision: i64,
    lifecycle_state: String,
    workspace_id: String,
    provider_instance_id: uuid::Uuid,
    external_repository_id: String,
    provider_revision: i64,
    provider_configuration_digest: Vec<u8>,
    capability_digest: Vec<u8>,
    repository_visibility: String,
    default_branch: String,
    workflow_source_kind: String,
    workflow_source_path: String,
    runner_policy_schema: i16,
    runner_policy_digest: Vec<u8>,
    archive_compressed_bytes: i64,
    archive_expanded_bytes: i64,
    archive_entries: i64,
    archive_entry_path_bytes: i64,
    archive_workflows: i64,
    workflow_bytes: i64,
    adapter_policy_schema: i16,
    adapter_policy_bytes: Vec<u8>,
    adapter_policy_digest: Vec<u8>,
    configuration_digest: Vec<u8>,
    created_at_ms: i64,
    activated_at_ms: Option<i64>,
    retired_at_ms: Option<i64>,
    manifest_digest: Vec<u8>,
}

impl PostgresProviderManifestRepository {
    pub(crate) async fn save_connection_inner(
        &self,
        manifest: ProviderConnectionManifest,
    ) -> Result<ProviderSaveOutcome, ProviderRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(unavailable)?;
        lock(
            &mut transaction,
            &manifest.connection_id().to_string(),
            CONNECTION_LOCK_SALT,
        )
        .await?;
        let current = sqlx::query_as::<_, ConnectionRow>(
            r"
            SELECT revisions.*
            FROM provider_connection_current AS current
            JOIN provider_connection_revisions AS revisions
              ON revisions.connection_id = current.connection_id
             AND revisions.revision = current.revision
            WHERE current.connection_id = $1
            FOR UPDATE OF current
            ",
        )
        .bind(manifest.connection_id().as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?;
        if let Some(current) = current {
            let current = decode_connection(current)?;
            if manifest.revision() == current.revision() {
                if manifest.digest() == current.digest() {
                    return Ok(ProviderSaveOutcome::Unchanged);
                }
                return Err(ProviderRepositoryError::Conflict);
            }
            manifest
                .validate_successor(&current)
                .map_err(|_| ProviderRepositoryError::Conflict)?;
        } else if manifest.revision().get() != 1 {
            return Err(ProviderRepositoryError::Conflict);
        }

        ensure_connection_references(&mut transaction, &manifest).await?;
        insert_connection(&mut transaction, &manifest).await?;
        sqlx::query(
            r"
            INSERT INTO provider_connection_current (connection_id, revision)
            VALUES ($1, $2)
            ON CONFLICT (connection_id) DO UPDATE
            SET revision = EXCLUDED.revision
            ",
        )
        .bind(manifest.connection_id().as_uuid())
        .bind(
            i64::try_from(manifest.revision().get())
                .map_err(|_| ProviderRepositoryError::Corrupt)?,
        )
        .execute(&mut *transaction)
        .await
        .map_err(unavailable)?;
        transaction.commit().await.map_err(unavailable)?;
        Ok(ProviderSaveOutcome::Inserted)
    }

    pub(crate) async fn load_connection_inner(
        &self,
        connection_id: ProviderConnectionId,
        revision: ProviderConnectionRevision,
    ) -> Result<Option<ProviderConnectionManifest>, ProviderRepositoryError> {
        let row = sqlx::query_as::<_, ConnectionRow>(
            "SELECT * FROM provider_connection_revisions WHERE connection_id = $1 AND revision = $2",
        )
        .bind(connection_id.as_uuid())
        .bind(i64::try_from(revision.get()).map_err(|_| ProviderRepositoryError::Corrupt)?)
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable)?;
        row.map(decode_connection).transpose()
    }

    pub(crate) async fn current_connection_inner(
        &self,
        connection_id: ProviderConnectionId,
    ) -> Result<Option<ProviderConnectionManifest>, ProviderRepositoryError> {
        let revision = sqlx::query_scalar::<_, i64>(
            "SELECT revision FROM provider_connection_current WHERE connection_id = $1",
        )
        .bind(connection_id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable)?;
        match revision {
            Some(revision) => {
                let revision = ProviderConnectionRevision::new(positive_u64(revision)?)
                    .map_err(|_| ProviderRepositoryError::Corrupt)?;
                self.load_connection_inner(connection_id, revision)
                    .await
                    .and_then(|record| record.ok_or(ProviderRepositoryError::Corrupt).map(Some))
            }
            None => Ok(None),
        }
    }

    pub(crate) async fn current_connections_inner(
        &self,
        instance_id: ProviderInstanceId,
    ) -> Result<Vec<ProviderConnectionManifest>, ProviderRepositoryError> {
        let rows = sqlx::query_as::<_, ConnectionRow>(
            r"
            SELECT revisions.*
            FROM provider_connection_current AS current
            JOIN provider_connection_revisions AS revisions
              ON revisions.connection_id = current.connection_id
             AND revisions.revision = current.revision
            WHERE revisions.provider_instance_id = $1
            ORDER BY revisions.connection_id
            ",
        )
        .bind(instance_id.as_uuid())
        .fetch_all(&self.pool)
        .await
        .map_err(unavailable)?;
        rows.into_iter().map(decode_connection).collect()
    }

    pub(crate) async fn active_connections_inner(
        &self,
        instance_id: ProviderInstanceId,
        provider_revision: ProviderConfigurationRevision,
    ) -> Result<Vec<ProviderConnectionManifest>, ProviderRepositoryError> {
        let rows = sqlx::query_as::<_, ConnectionRow>(
            r"
            SELECT revisions.*
            FROM provider_connection_current AS current
            JOIN provider_connection_revisions AS revisions
              ON revisions.connection_id = current.connection_id
             AND revisions.revision = current.revision
            WHERE revisions.provider_instance_id = $1
              AND revisions.provider_revision = $2
              AND revisions.lifecycle_state = 'active'
            ORDER BY revisions.connection_id
            ",
        )
        .bind(instance_id.as_uuid())
        .bind(i64::try_from(provider_revision.get()).map_err(|_| ProviderRepositoryError::Corrupt)?)
        .fetch_all(&self.pool)
        .await
        .map_err(unavailable)?;
        rows.into_iter().map(decode_connection).collect()
    }
}

async fn ensure_connection_references(
    transaction: &mut Transaction<'_, Postgres>,
    manifest: &ProviderConnectionManifest,
) -> Result<(), ProviderRepositoryError> {
    let configuration = manifest.configuration();
    let provider_exists = sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS (
            SELECT 1 FROM provider_instance_revisions
            WHERE instance_id = $1 AND revision = $2
              AND configuration_digest = $3 AND capability_digest = $4
        )
        ",
    )
    .bind(configuration.repository().instance_id().as_uuid())
    .bind(
        i64::try_from(configuration.provider_revision().get())
            .map_err(|_| ProviderRepositoryError::Corrupt)?,
    )
    .bind(
        configuration
            .provider_configuration_digest()
            .as_bytes()
            .as_slice(),
    )
    .bind(configuration.capability_digest().as_bytes().as_slice())
    .fetch_one(&mut **transaction)
    .await
    .map_err(unavailable)?;
    let workspace_exists =
        sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM tenants WHERE id = $1)")
            .bind(configuration.workspace_id().to_string())
            .fetch_one(&mut **transaction)
            .await
            .map_err(unavailable)?;
    if !provider_exists || !workspace_exists {
        return Err(ProviderRepositoryError::NotFound);
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // The ordered bindings mirror the immutable SQL record.
async fn insert_connection(
    transaction: &mut Transaction<'_, Postgres>,
    manifest: &ProviderConnectionManifest,
) -> Result<(), ProviderRepositoryError> {
    let configuration = manifest.configuration();
    let (workflow_kind, workflow_path) = match configuration.workflow_source() {
        ProviderWorkflowSource::Directory(path) => ("directory", path.as_str()),
        ProviderWorkflowSource::File(path) => ("file", path.as_str()),
    };
    sqlx::query(
        r"
        INSERT INTO provider_connection_revisions (
            connection_id, revision, lifecycle_state, workspace_id,
            provider_instance_id, external_repository_id, provider_revision,
            provider_configuration_digest, capability_digest,
            repository_visibility, default_branch, workflow_source_kind,
            workflow_source_path, runner_policy_schema, runner_policy_digest,
            archive_compressed_bytes, archive_expanded_bytes, archive_entries,
            archive_entry_path_bytes, archive_workflows, workflow_bytes,
            adapter_policy_schema, adapter_policy_bytes, adapter_policy_digest,
            configuration_digest, created_at_ms, activated_at_ms,
            retired_at_ms, manifest_digest
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
            $16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29
        )
        ",
    )
    .bind(manifest.connection_id().as_uuid())
    .bind(i64::try_from(manifest.revision().get()).map_err(|_| ProviderRepositoryError::Corrupt)?)
    .bind(lifecycle_text(manifest.state()))
    .bind(configuration.workspace_id().to_string())
    .bind(configuration.repository().instance_id().as_uuid())
    .bind(configuration.repository().external_id().as_str())
    .bind(
        i64::try_from(configuration.provider_revision().get())
            .map_err(|_| ProviderRepositoryError::Corrupt)?,
    )
    .bind(
        configuration
            .provider_configuration_digest()
            .as_bytes()
            .as_slice(),
    )
    .bind(configuration.capability_digest().as_bytes().as_slice())
    .bind(visibility_text(configuration.visibility()))
    .bind(configuration.default_branch().as_str())
    .bind(workflow_kind)
    .bind(workflow_path)
    .bind(
        i16::try_from(configuration.runner_policy().schema_version().get())
            .map_err(|_| ProviderRepositoryError::Corrupt)?,
    )
    .bind(configuration.runner_policy().digest().as_bytes().as_slice())
    .bind(
        i64::try_from(configuration.archive_limits().compressed_bytes())
            .map_err(|_| ProviderRepositoryError::Corrupt)?,
    )
    .bind(
        i64::try_from(configuration.archive_limits().expanded_bytes())
            .map_err(|_| ProviderRepositoryError::Corrupt)?,
    )
    .bind(
        i64::try_from(configuration.archive_limits().entries())
            .map_err(|_| ProviderRepositoryError::Corrupt)?,
    )
    .bind(
        i64::try_from(configuration.archive_limits().entry_path_bytes())
            .map_err(|_| ProviderRepositoryError::Corrupt)?,
    )
    .bind(
        i64::try_from(configuration.archive_limits().workflows())
            .map_err(|_| ProviderRepositoryError::Corrupt)?,
    )
    .bind(
        i64::try_from(configuration.archive_limits().workflow_bytes())
            .map_err(|_| ProviderRepositoryError::Corrupt)?,
    )
    .bind(
        i16::try_from(configuration.adapter_policy().schema_version().get())
            .map_err(|_| ProviderRepositoryError::Corrupt)?,
    )
    .bind(configuration.adapter_policy().bytes())
    .bind(
        configuration
            .adapter_policy()
            .digest()
            .as_bytes()
            .as_slice(),
    )
    .bind(configuration.digest().as_bytes().as_slice())
    .bind(manifest.created_at().get())
    .bind(
        manifest
            .activated_at()
            .map(automata_ci_core::UnixMillis::get),
    )
    .bind(manifest.retired_at().map(automata_ci_core::UnixMillis::get))
    .bind(manifest.digest().as_bytes().as_slice())
    .execute(&mut **transaction)
    .await
    .map_err(unavailable)?;
    Ok(())
}

fn decode_connection(
    row: ConnectionRow,
) -> Result<ProviderConnectionManifest, ProviderRepositoryError> {
    let instance_id = ProviderInstanceId::from_uuid(row.provider_instance_id)
        .map_err(|_| ProviderRepositoryError::Corrupt)?;
    let workflow_path = ProviderRepositoryPath::new(row.workflow_source_path)
        .map_err(|_| ProviderRepositoryError::Corrupt)?;
    let workflow_source = match row.workflow_source_kind.as_str() {
        "directory" => ProviderWorkflowSource::Directory(workflow_path),
        "file" => ProviderWorkflowSource::File(workflow_path),
        _ => return Err(ProviderRepositoryError::Corrupt),
    };
    let adapter_policy = ProviderConnectionPolicyDocument::new(
        ProviderSchemaVersion::new(positive_u16(row.adapter_policy_schema)?)
            .map_err(|_| ProviderRepositoryError::Corrupt)?,
        row.adapter_policy_bytes,
    )
    .map_err(|_| ProviderRepositoryError::Corrupt)?;
    if adapter_policy.digest() != digest(row.adapter_policy_digest)? {
        return Err(ProviderRepositoryError::Corrupt);
    }
    let configuration = ProviderConnectionConfiguration::new(
        WorkspaceId::parse(&row.workspace_id).map_err(|_| ProviderRepositoryError::Corrupt)?,
        ExternalRepositoryIdentity::new(
            instance_id,
            ExternalRepositoryId::new(row.external_repository_id)
                .map_err(|_| ProviderRepositoryError::Corrupt)?,
        ),
        ProviderConfigurationRevision::new(positive_u64(row.provider_revision)?)
            .map_err(|_| ProviderRepositoryError::Corrupt)?,
        digest(row.provider_configuration_digest)?,
        digest(row.capability_digest)?,
        visibility(&row.repository_visibility)?,
        ProviderDefaultBranch::new(row.default_branch)
            .map_err(|_| ProviderRepositoryError::Corrupt)?,
        workflow_source,
        ProviderRunnerPolicyBinding::new(
            ProviderSchemaVersion::new(positive_u16(row.runner_policy_schema)?)
                .map_err(|_| ProviderRepositoryError::Corrupt)?,
            digest(row.runner_policy_digest)?,
        ),
        ProviderArchiveLimits::new(
            positive_u64(row.archive_compressed_bytes)?,
            positive_u64(row.archive_expanded_bytes)?,
            positive_u64(row.archive_entries)?,
            positive_u64(row.archive_entry_path_bytes)?,
            positive_u64(row.archive_workflows)?,
            positive_u64(row.workflow_bytes)?,
        )
        .map_err(|_| ProviderRepositoryError::Corrupt)?,
        adapter_policy,
    );
    if configuration.digest() != digest(row.configuration_digest)? {
        return Err(ProviderRepositoryError::Corrupt);
    }
    let manifest = ProviderConnectionManifest::new(
        ProviderConnectionId::from_uuid(row.connection_id)
            .map_err(|_| ProviderRepositoryError::Corrupt)?,
        ProviderConnectionRevision::new(positive_u64(row.revision)?)
            .map_err(|_| ProviderRepositoryError::Corrupt)?,
        lifecycle(&row.lifecycle_state)?,
        configuration,
        timestamp(row.created_at_ms),
        optional_timestamp(row.activated_at_ms),
        optional_timestamp(row.retired_at_ms),
    )
    .map_err(|_| ProviderRepositoryError::Corrupt)?;
    if manifest.digest() != digest(row.manifest_digest)? {
        return Err(ProviderRepositoryError::Corrupt);
    }
    Ok(manifest)
}

const fn visibility_text(value: RepositoryVisibility) -> &'static str {
    match value {
        RepositoryVisibility::Public => "public",
        RepositoryVisibility::Internal => "internal",
        RepositoryVisibility::Private => "private",
    }
}

fn visibility(value: &str) -> Result<RepositoryVisibility, ProviderRepositoryError> {
    match value {
        "public" => Ok(RepositoryVisibility::Public),
        "internal" => Ok(RepositoryVisibility::Internal),
        "private" => Ok(RepositoryVisibility::Private),
        _ => Err(ProviderRepositoryError::Corrupt),
    }
}
