use automata_ci_core::UnixMillis;
use automata_ci_provider::{
    ProviderConfigurationRevision, ProviderConnectionId, ProviderConnectionRevision,
    ProviderDeliveryRepositoryError, ProviderInstanceId, ProviderRepositoryError,
    ProviderSaveOutcome, ProviderSecretGeneration, ProviderSecretName, ProviderTypeId,
    ProviderWebhookEndpointId, ProviderWebhookEndpointManifest, ProviderWebhookEndpointRecord,
    ProviderWebhookEndpointRevision, ProviderWebhookEndpointState, ProviderWebhookSecretCandidates,
    ProviderWebhookSecretReference,
};
use sqlx::{FromRow, Postgres, Transaction};

use crate::{ENDPOINT_LOCK_SALT, PostgresProviderManifestRepository, lock};

#[derive(FromRow)]
struct EndpointRow {
    endpoint_id: uuid::Uuid,
    revision: i64,
    lifecycle_state: String,
    provider_type: String,
    provider_instance_id: uuid::Uuid,
    provider_revision: i64,
    connection_id: uuid::Uuid,
    connection_revision: i64,
    body_limit: i64,
    raw_retention_millis: i64,
    candidate_count: i16,
    created_at_ms: i64,
    retired_at_ms: Option<i64>,
}

#[derive(FromRow)]
struct CandidateRow {
    configuration_revision: i64,
    secret_name: String,
    secret_generation: i64,
}

impl PostgresProviderManifestRepository {
    pub(crate) async fn save_endpoint_inner(
        &self,
        endpoint: ProviderWebhookEndpointManifest,
    ) -> Result<ProviderSaveOutcome, ProviderDeliveryRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(unavailable)?;
        lock(
            &mut transaction,
            &endpoint.endpoint_id().to_string(),
            ENDPOINT_LOCK_SALT,
        )
        .await
        .map_err(map_manifest_error)?;
        let current = sqlx::query_as::<_, EndpointRow>(
            r"
            SELECT revisions.*
            FROM provider_webhook_endpoint_current AS current
            JOIN provider_webhook_endpoint_revisions AS revisions
              ON revisions.endpoint_id = current.endpoint_id
             AND revisions.revision = current.revision
            WHERE current.endpoint_id = $1
            FOR UPDATE OF current
            ",
        )
        .bind(endpoint.endpoint_id().as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?;
        if let Some(current) = current {
            let revision = endpoint_revision(current.revision)?;
            let references =
                load_references(&mut transaction, endpoint.endpoint_id(), revision).await?;
            if usize::try_from(current.candidate_count).ok() != Some(references.len()) {
                return Err(ProviderDeliveryRepositoryError::Corrupt);
            }
            let current = decode_endpoint(current, references)?;
            if endpoint.revision() == current.revision() {
                if endpoint == current {
                    return Ok(ProviderSaveOutcome::Unchanged);
                }
                return Err(ProviderDeliveryRepositoryError::EndpointConflict);
            }
            endpoint
                .validate_successor(&current)
                .map_err(|_| ProviderDeliveryRepositoryError::EndpointConflict)?;
        } else if endpoint.revision().get() != 1 {
            return Err(ProviderDeliveryRepositoryError::EndpointConflict);
        }

        ensure_endpoint_references(&mut transaction, &endpoint).await?;
        insert_endpoint(&mut transaction, &endpoint).await?;
        insert_candidates(&mut transaction, &endpoint).await?;
        sqlx::query(
            r"
            INSERT INTO provider_webhook_endpoint_current (endpoint_id, revision)
            VALUES ($1, $2)
            ON CONFLICT (endpoint_id) DO UPDATE SET revision = EXCLUDED.revision
            ",
        )
        .bind(endpoint.endpoint_id().as_uuid())
        .bind(durable_u64(endpoint.revision().get())?)
        .execute(&mut *transaction)
        .await
        .map_err(unavailable)?;
        transaction.commit().await.map_err(unavailable)?;
        Ok(ProviderSaveOutcome::Inserted)
    }

    pub(crate) async fn resolve_endpoint_inner(
        &self,
        endpoint_id: ProviderWebhookEndpointId,
    ) -> Result<Option<ProviderWebhookEndpointRecord>, ProviderDeliveryRepositoryError> {
        let revision = sqlx::query_scalar::<_, i64>(
            r"
            SELECT endpoint.revision
            FROM provider_webhook_endpoint_current AS current
            JOIN provider_webhook_endpoint_revisions AS endpoint
              ON endpoint.endpoint_id = current.endpoint_id
             AND endpoint.revision = current.revision
            JOIN provider_instance_current AS instance_current
              ON instance_current.instance_id = endpoint.provider_instance_id
             AND instance_current.revision = endpoint.provider_revision
            JOIN provider_instance_revisions AS instance
              ON instance.instance_id = instance_current.instance_id
             AND instance.revision = instance_current.revision
            JOIN provider_connection_current AS connection_current
              ON connection_current.connection_id = endpoint.connection_id
             AND connection_current.revision = endpoint.connection_revision
            JOIN provider_connection_revisions AS connection
              ON connection.connection_id = connection_current.connection_id
             AND connection.revision = connection_current.revision
            WHERE endpoint.endpoint_id = $1
              AND endpoint.lifecycle_state = 'active'
              AND instance.lifecycle_state = 'active'
              AND connection.lifecycle_state = 'active'
            ",
        )
        .bind(endpoint_id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable)?;
        match revision {
            Some(revision) => self
                .load_endpoint_inner(endpoint_id, endpoint_revision(revision)?)
                .await
                .and_then(|record| {
                    record
                        .ok_or(ProviderDeliveryRepositoryError::Corrupt)
                        .map(Some)
                }),
            None => Ok(None),
        }
    }

    pub(crate) async fn load_endpoint_inner(
        &self,
        endpoint_id: ProviderWebhookEndpointId,
        revision: ProviderWebhookEndpointRevision,
    ) -> Result<Option<ProviderWebhookEndpointRecord>, ProviderDeliveryRepositoryError> {
        let row = sqlx::query_as::<_, EndpointRow>(
            "SELECT * FROM provider_webhook_endpoint_revisions WHERE endpoint_id = $1 AND revision = $2",
        )
        .bind(endpoint_id.as_uuid())
        .bind(durable_u64(revision.get())?)
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let references = load_references_pool(self, endpoint_id, revision).await?;
        if usize::try_from(row.candidate_count).ok() != Some(references.len()) {
            return Err(ProviderDeliveryRepositoryError::Corrupt);
        }
        let endpoint = decode_endpoint(row, references.clone())?;
        let mut secrets = Vec::with_capacity(references.len());
        for reference in references {
            let secret = self
                .load_secret_inner(
                    endpoint.instance_id(),
                    reference.configuration_revision(),
                    reference.name().clone(),
                    reference.generation(),
                )
                .await
                .map_err(map_manifest_error)?
                .ok_or(ProviderDeliveryRepositoryError::Corrupt)?;
            secrets.push((reference.configuration_revision(), secret));
        }
        let candidates = ProviderWebhookSecretCandidates::new(&endpoint, secrets)
            .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?;
        Ok(Some(ProviderWebhookEndpointRecord::new(
            endpoint, candidates,
        )))
    }
}

async fn ensure_endpoint_references(
    transaction: &mut Transaction<'_, Postgres>,
    endpoint: &ProviderWebhookEndpointManifest,
) -> Result<(), ProviderDeliveryRepositoryError> {
    let binding_exists = sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM provider_instance_revisions AS instance
            JOIN provider_connection_revisions AS connection
              ON connection.connection_id = $4
             AND connection.revision = $5
             AND connection.provider_instance_id = instance.instance_id
             AND connection.provider_revision = instance.revision
            WHERE instance.instance_id = $1
              AND instance.revision = $2
              AND instance.provider_type = $3
              AND instance.lifecycle_state = 'active'
              AND connection.lifecycle_state = 'active'
        )
        ",
    )
    .bind(endpoint.instance_id().as_uuid())
    .bind(durable_u64(endpoint.provider_revision().get())?)
    .bind(endpoint.provider_type().as_str())
    .bind(endpoint.connection_id().as_uuid())
    .bind(durable_u64(endpoint.connection_revision().get())?)
    .fetch_one(&mut **transaction)
    .await
    .map_err(unavailable)?;
    if !binding_exists {
        return Err(ProviderDeliveryRepositoryError::NotFound);
    }
    for reference in endpoint.secret_references() {
        let exists = sqlx::query_scalar::<_, bool>(
            r"
            SELECT EXISTS (
                SELECT 1 FROM provider_instance_secret_bindings
                WHERE instance_id = $1 AND revision = $2
                  AND secret_name = $3 AND secret_generation = $4
            )
            ",
        )
        .bind(endpoint.instance_id().as_uuid())
        .bind(durable_u64(reference.configuration_revision().get())?)
        .bind(reference.name().as_str())
        .bind(durable_u64(reference.generation().get())?)
        .fetch_one(&mut **transaction)
        .await
        .map_err(unavailable)?;
        if !exists {
            return Err(ProviderDeliveryRepositoryError::NotFound);
        }
    }
    Ok(())
}

async fn insert_endpoint(
    transaction: &mut Transaction<'_, Postgres>,
    endpoint: &ProviderWebhookEndpointManifest,
) -> Result<(), ProviderDeliveryRepositoryError> {
    sqlx::query(
        r"
        INSERT INTO provider_webhook_endpoint_revisions (
            endpoint_id, revision, lifecycle_state, provider_type,
            provider_instance_id, provider_revision, connection_id,
            connection_revision, body_limit, raw_retention_millis,
            candidate_count, created_at_ms, retired_at_ms
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
        ",
    )
    .bind(endpoint.endpoint_id().as_uuid())
    .bind(durable_u64(endpoint.revision().get())?)
    .bind(endpoint_state_text(endpoint.state()))
    .bind(endpoint.provider_type().as_str())
    .bind(endpoint.instance_id().as_uuid())
    .bind(durable_u64(endpoint.provider_revision().get())?)
    .bind(endpoint.connection_id().as_uuid())
    .bind(durable_u64(endpoint.connection_revision().get())?)
    .bind(durable_u64(endpoint.body_limit())?)
    .bind(durable_u64(endpoint.raw_retention_millis())?)
    .bind(
        i16::try_from(endpoint.secret_references().len())
            .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?,
    )
    .bind(endpoint.created_at().get())
    .bind(endpoint.retired_at().map(UnixMillis::get))
    .execute(&mut **transaction)
    .await
    .map_err(unavailable)?;
    Ok(())
}

async fn insert_candidates(
    transaction: &mut Transaction<'_, Postgres>,
    endpoint: &ProviderWebhookEndpointManifest,
) -> Result<(), ProviderDeliveryRepositoryError> {
    for (index, reference) in endpoint.secret_references().iter().enumerate() {
        sqlx::query(
            r"
            INSERT INTO provider_webhook_endpoint_secret_candidates (
                endpoint_id, endpoint_revision, ordinal, provider_instance_id,
                configuration_revision, secret_name, secret_generation
            ) VALUES ($1,$2,$3,$4,$5,$6,$7)
            ",
        )
        .bind(endpoint.endpoint_id().as_uuid())
        .bind(durable_u64(endpoint.revision().get())?)
        .bind(i16::try_from(index + 1).map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?)
        .bind(endpoint.instance_id().as_uuid())
        .bind(durable_u64(reference.configuration_revision().get())?)
        .bind(reference.name().as_str())
        .bind(durable_u64(reference.generation().get())?)
        .execute(&mut **transaction)
        .await
        .map_err(unavailable)?;
    }
    Ok(())
}

async fn load_references(
    transaction: &mut Transaction<'_, Postgres>,
    endpoint_id: ProviderWebhookEndpointId,
    revision: ProviderWebhookEndpointRevision,
) -> Result<Vec<ProviderWebhookSecretReference>, ProviderDeliveryRepositoryError> {
    let rows = sqlx::query_as::<_, CandidateRow>(
        r"
        SELECT configuration_revision, secret_name, secret_generation
        FROM provider_webhook_endpoint_secret_candidates
        WHERE endpoint_id = $1 AND endpoint_revision = $2
        ORDER BY ordinal
        ",
    )
    .bind(endpoint_id.as_uuid())
    .bind(durable_u64(revision.get())?)
    .fetch_all(&mut **transaction)
    .await
    .map_err(unavailable)?;
    decode_references(rows)
}

async fn load_references_pool(
    repository: &PostgresProviderManifestRepository,
    endpoint_id: ProviderWebhookEndpointId,
    revision: ProviderWebhookEndpointRevision,
) -> Result<Vec<ProviderWebhookSecretReference>, ProviderDeliveryRepositoryError> {
    let rows = sqlx::query_as::<_, CandidateRow>(
        r"
        SELECT configuration_revision, secret_name, secret_generation
        FROM provider_webhook_endpoint_secret_candidates
        WHERE endpoint_id = $1 AND endpoint_revision = $2
        ORDER BY ordinal
        ",
    )
    .bind(endpoint_id.as_uuid())
    .bind(durable_u64(revision.get())?)
    .fetch_all(&repository.pool)
    .await
    .map_err(unavailable)?;
    decode_references(rows)
}

fn decode_references(
    rows: Vec<CandidateRow>,
) -> Result<Vec<ProviderWebhookSecretReference>, ProviderDeliveryRepositoryError> {
    rows.into_iter()
        .map(|row| {
            Ok(ProviderWebhookSecretReference::new(
                ProviderConfigurationRevision::new(positive_u64(row.configuration_revision)?)
                    .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?,
                ProviderSecretName::new(row.secret_name)
                    .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?,
                ProviderSecretGeneration::new(positive_u64(row.secret_generation)?)
                    .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?,
            ))
        })
        .collect()
}

fn decode_endpoint(
    row: EndpointRow,
    references: Vec<ProviderWebhookSecretReference>,
) -> Result<ProviderWebhookEndpointManifest, ProviderDeliveryRepositoryError> {
    ProviderWebhookEndpointManifest::new(
        ProviderWebhookEndpointId::from_uuid(row.endpoint_id)
            .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?,
        endpoint_revision(row.revision)?,
        endpoint_state(&row.lifecycle_state)?,
        ProviderTypeId::new(row.provider_type)
            .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?,
        ProviderInstanceId::from_uuid(row.provider_instance_id)
            .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?,
        ProviderConfigurationRevision::new(positive_u64(row.provider_revision)?)
            .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?,
        ProviderConnectionId::from_uuid(row.connection_id)
            .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?,
        ProviderConnectionRevision::new(positive_u64(row.connection_revision)?)
            .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)?,
        positive_u64(row.body_limit)?,
        positive_u64(row.raw_retention_millis)?,
        references,
        UnixMillis::new(row.created_at_ms),
        row.retired_at_ms.map(UnixMillis::new),
    )
    .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)
}

fn endpoint_revision(
    value: i64,
) -> Result<ProviderWebhookEndpointRevision, ProviderDeliveryRepositoryError> {
    ProviderWebhookEndpointRevision::new(positive_u64(value)?)
        .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)
}

fn endpoint_state(
    value: &str,
) -> Result<ProviderWebhookEndpointState, ProviderDeliveryRepositoryError> {
    match value {
        "active" => Ok(ProviderWebhookEndpointState::Active),
        "disabled" => Ok(ProviderWebhookEndpointState::Disabled),
        "retired" => Ok(ProviderWebhookEndpointState::Retired),
        _ => Err(ProviderDeliveryRepositoryError::Corrupt),
    }
}

const fn endpoint_state_text(value: ProviderWebhookEndpointState) -> &'static str {
    match value {
        ProviderWebhookEndpointState::Active => "active",
        ProviderWebhookEndpointState::Disabled => "disabled",
        ProviderWebhookEndpointState::Retired => "retired",
    }
}

fn durable_u64(value: u64) -> Result<i64, ProviderDeliveryRepositoryError> {
    i64::try_from(value).map_err(|_| ProviderDeliveryRepositoryError::Corrupt)
}

fn positive_u64(value: i64) -> Result<u64, ProviderDeliveryRepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(ProviderDeliveryRepositoryError::Corrupt)
}

fn unavailable(_: sqlx::Error) -> ProviderDeliveryRepositoryError {
    ProviderDeliveryRepositoryError::Unavailable
}

const fn map_manifest_error(error: ProviderRepositoryError) -> ProviderDeliveryRepositoryError {
    match error {
        ProviderRepositoryError::NotFound => ProviderDeliveryRepositoryError::NotFound,
        ProviderRepositoryError::Unavailable => ProviderDeliveryRepositoryError::Unavailable,
        ProviderRepositoryError::Conflict
        | ProviderRepositoryError::Corrupt
        | ProviderRepositoryError::SecretCustody => ProviderDeliveryRepositoryError::Corrupt,
    }
}
