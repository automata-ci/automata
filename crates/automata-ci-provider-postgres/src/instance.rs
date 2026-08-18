use automata_ci_key_management::{EnvelopeCodec, EnvelopeError};
use automata_ci_provider::{
    ProviderConfigurationDocument, ProviderConfigurationRevision, ProviderInstanceId,
    ProviderInstanceManifest, ProviderInstanceRecord, ProviderOrigins, ProviderRepositoryError,
    ProviderSaveOutcome, ProviderSchemaVersion, ProviderSecret, ProviderSecretBinding,
    ProviderSecretBindings, ProviderSecretGeneration, ProviderSecretName, ProviderSecretSet,
    ProviderTypeId,
};
use sha2::{Digest as _, Sha256};
use sqlx::{FromRow, Postgres, Transaction};

use crate::{
    EnvelopeParts, INSTANCE_LOCK_SALT, PostgresProviderManifestRepository, digest, envelope,
    lifecycle, lifecycle_text, lock, optional_timestamp, positive_u16, positive_u64,
    secret_context, timestamp, unavailable,
};

#[derive(FromRow)]
struct InstanceRow {
    instance_id: uuid::Uuid,
    revision: i64,
    provider_type: String,
    lifecycle_state: String,
    web_origin: String,
    api_origin: String,
    configuration_schema: i16,
    configuration_bytes: Vec<u8>,
    configuration_digest: Vec<u8>,
    capability_digest: Vec<u8>,
    created_at_ms: i64,
    activated_at_ms: Option<i64>,
    retired_at_ms: Option<i64>,
    manifest_digest: Vec<u8>,
}

#[derive(FromRow)]
struct SecretRow {
    secret_name: String,
    secret_generation: i64,
    plaintext_digest: Vec<u8>,
    envelope_schema: i16,
    wrapping_key_id: String,
    wrapped_data_key: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

struct SealedSecret {
    name: ProviderSecretName,
    generation: ProviderSecretGeneration,
    plaintext_digest: automata_ci_core::Sha256Digest,
    envelope: EnvelopeParts,
}

impl PostgresProviderManifestRepository {
    pub(crate) async fn load_secret_inner(
        &self,
        instance_id: ProviderInstanceId,
        revision: ProviderConfigurationRevision,
        name: ProviderSecretName,
        generation: ProviderSecretGeneration,
    ) -> Result<Option<ProviderSecret>, ProviderRepositoryError> {
        let row = sqlx::query_as::<_, SecretRow>(
            r"
            SELECT secret_name, secret_generation, plaintext_digest,
                   envelope_schema, wrapping_key_id, wrapped_data_key,
                   nonce, ciphertext
            FROM provider_instance_secret_bindings
            WHERE instance_id = $1 AND revision = $2
              AND secret_name = $3 AND secret_generation = $4
            ",
        )
        .bind(instance_id.as_uuid())
        .bind(i64::try_from(revision.get()).map_err(|_| ProviderRepositoryError::Corrupt)?)
        .bind(name.as_str())
        .bind(i64::try_from(generation.get()).map_err(|_| ProviderRepositoryError::Corrupt)?)
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let encrypted = envelope(
            row.envelope_schema,
            row.wrapping_key_id,
            row.wrapped_data_key,
            row.nonce,
            row.ciphertext,
        )?;
        let context = secret_context(instance_id, revision.get(), name.as_str(), generation.get())?;
        let plaintext = self
            .envelopes
            .open(&context, &encrypted)
            .await
            .map_err(encryption_failure)?;
        let plaintext_digest = automata_ci_core::Sha256Digest::from_bytes(
            Sha256::digest(plaintext.expose_secret()).into(),
        );
        if digest(row.plaintext_digest)? != plaintext_digest {
            return Err(ProviderRepositoryError::SecretCustody);
        }
        Ok(Some(ProviderSecret::new(name, generation, plaintext)))
    }

    pub(crate) async fn save_instance_inner(
        &self,
        record: ProviderInstanceRecord,
    ) -> Result<ProviderSaveOutcome, ProviderRepositoryError> {
        let (manifest, secrets) = record.into_parts();
        let sealed = seal_secrets(&self.envelopes, &manifest, secrets).await?;

        let mut transaction = self.pool.begin().await.map_err(unavailable)?;
        lock(
            &mut transaction,
            &manifest.instance_id().to_string(),
            INSTANCE_LOCK_SALT,
        )
        .await?;
        let current = sqlx::query_as::<_, InstanceRow>(
            r"
            SELECT revisions.*
            FROM provider_instance_current AS current
            JOIN provider_instance_revisions AS revisions
              ON revisions.instance_id = current.instance_id
             AND revisions.revision = current.revision
            WHERE current.instance_id = $1
            FOR UPDATE OF current
            ",
        )
        .bind(manifest.instance_id().as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?;

        let prior_bindings = if let Some(current) = current {
            let current_revision =
                ProviderConfigurationRevision::new(positive_u64(current.revision)?)
                    .map_err(|_| ProviderRepositoryError::Corrupt)?;
            let secret_rows =
                load_secret_rows(&mut transaction, manifest.instance_id(), current_revision)
                    .await?;
            let current_manifest = decode_instance(current, bindings_from_rows(&secret_rows)?)?;
            if manifest.revision() == current_manifest.revision() {
                if manifest.digest() == current_manifest.digest() {
                    return Ok(ProviderSaveOutcome::Unchanged);
                }
                return Err(ProviderRepositoryError::Conflict);
            }
            manifest
                .validate_successor(&current_manifest)
                .map_err(|_| ProviderRepositoryError::Conflict)?;
            Some(current_manifest.secrets().clone())
        } else if manifest.revision().get() != 1 {
            return Err(ProviderRepositoryError::Conflict);
        } else {
            None
        };

        validate_historical_generations(&mut transaction, &manifest, prior_bindings.as_ref())
            .await?;
        insert_instance(&mut transaction, &manifest).await?;
        for secret in sealed {
            insert_secret(
                &mut transaction,
                manifest.instance_id(),
                manifest.revision(),
                secret,
            )
            .await?;
        }
        sqlx::query(
            r"
            INSERT INTO provider_instance_current (instance_id, revision)
            VALUES ($1, $2)
            ON CONFLICT (instance_id) DO UPDATE
            SET revision = EXCLUDED.revision
            ",
        )
        .bind(manifest.instance_id().as_uuid())
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

    pub(crate) async fn load_instance_inner(
        &self,
        instance_id: ProviderInstanceId,
        revision: ProviderConfigurationRevision,
    ) -> Result<Option<ProviderInstanceRecord>, ProviderRepositoryError> {
        let row = sqlx::query_as::<_, InstanceRow>(
            "SELECT * FROM provider_instance_revisions WHERE instance_id = $1 AND revision = $2",
        )
        .bind(instance_id.as_uuid())
        .bind(i64::try_from(revision.get()).map_err(|_| ProviderRepositoryError::Corrupt)?)
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let rows = sqlx::query_as::<_, SecretRow>(SECRET_ROWS_SQL)
            .bind(instance_id.as_uuid())
            .bind(i64::try_from(revision.get()).map_err(|_| ProviderRepositoryError::Corrupt)?)
            .fetch_all(&self.pool)
            .await
            .map_err(unavailable)?;
        let bindings = bindings_from_rows(&rows)?;
        let manifest = decode_instance(row, bindings.clone())?;

        let mut secrets = Vec::with_capacity(rows.len());
        for row in rows {
            let name = ProviderSecretName::new(row.secret_name)
                .map_err(|_| ProviderRepositoryError::Corrupt)?;
            let generation = ProviderSecretGeneration::new(positive_u64(row.secret_generation)?)
                .map_err(|_| ProviderRepositoryError::Corrupt)?;
            let encrypted = envelope(
                row.envelope_schema,
                row.wrapping_key_id,
                row.wrapped_data_key,
                row.nonce,
                row.ciphertext,
            )?;
            let context =
                secret_context(instance_id, revision.get(), name.as_str(), generation.get())?;
            let plaintext = self
                .envelopes
                .open(&context, &encrypted)
                .await
                .map_err(encryption_failure)?;
            secrets.push(ProviderSecret::new(name, generation, plaintext));
        }
        let secrets = ProviderSecretSet::new(&bindings, secrets)
            .map_err(|_| ProviderRepositoryError::SecretCustody)?;
        ProviderInstanceRecord::new(manifest, secrets).map(Some)
    }

    pub(crate) async fn current_instance_inner(
        &self,
        instance_id: ProviderInstanceId,
    ) -> Result<Option<ProviderInstanceRecord>, ProviderRepositoryError> {
        let revision = sqlx::query_scalar::<_, i64>(
            "SELECT revision FROM provider_instance_current WHERE instance_id = $1",
        )
        .bind(instance_id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable)?;
        match revision {
            Some(revision) => {
                let revision = ProviderConfigurationRevision::new(positive_u64(revision)?)
                    .map_err(|_| ProviderRepositoryError::Corrupt)?;
                self.load_instance_inner(instance_id, revision)
                    .await
                    .and_then(|record| record.ok_or(ProviderRepositoryError::Corrupt).map(Some))
            }
            None => Ok(None),
        }
    }
}

async fn seal_secrets(
    codec: &EnvelopeCodec,
    manifest: &ProviderInstanceManifest,
    secrets: ProviderSecretSet,
) -> Result<Vec<SealedSecret>, ProviderRepositoryError> {
    let mut sealed = Vec::with_capacity(manifest.secrets().len());
    for secret in secrets.into_secrets() {
        let (name, generation, value) = secret.into_parts();
        let binding = manifest
            .secrets()
            .get(&name)
            .ok_or(ProviderRepositoryError::SecretCustody)?;
        let context = secret_context(
            manifest.instance_id(),
            manifest.revision().get(),
            name.as_str(),
            generation.get(),
        )?;
        let encrypted = codec
            .seal(&context, value)
            .await
            .map_err(encryption_failure)?;
        sealed.push(SealedSecret {
            name,
            generation,
            plaintext_digest: binding.digest(),
            envelope: encrypted.try_into()?,
        });
    }
    Ok(sealed)
}

async fn validate_historical_generations(
    transaction: &mut Transaction<'_, Postgres>,
    manifest: &ProviderInstanceManifest,
    prior: Option<&ProviderSecretBindings>,
) -> Result<(), ProviderRepositoryError> {
    for binding in manifest.secrets().iter() {
        if prior
            .and_then(|bindings| bindings.get(binding.name()))
            .is_some()
        {
            continue;
        }
        let maximum = sqlx::query_scalar::<_, Option<i64>>(
            r"
            SELECT max(secret_generation)
            FROM provider_instance_secret_bindings
            WHERE instance_id = $1 AND secret_name = $2
            ",
        )
        .bind(manifest.instance_id().as_uuid())
        .bind(binding.name().as_str())
        .fetch_one(&mut **transaction)
        .await
        .map_err(unavailable)?;
        let expected = maximum.map_or(Ok(1), |maximum| {
            positive_u64(maximum)?
                .checked_add(1)
                .ok_or(ProviderRepositoryError::Conflict)
        })?;
        if binding.generation().get() != expected {
            return Err(ProviderRepositoryError::Conflict);
        }
    }
    Ok(())
}

async fn insert_instance(
    transaction: &mut Transaction<'_, Postgres>,
    manifest: &ProviderInstanceManifest,
) -> Result<(), ProviderRepositoryError> {
    sqlx::query(
        r"
        INSERT INTO provider_instance_revisions (
            instance_id, revision, provider_type, lifecycle_state,
            web_origin, api_origin, configuration_schema,
            configuration_bytes, configuration_digest, capability_digest,
            created_at_ms, activated_at_ms, retired_at_ms, manifest_digest
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
        ",
    )
    .bind(manifest.instance_id().as_uuid())
    .bind(i64::try_from(manifest.revision().get()).map_err(|_| ProviderRepositoryError::Corrupt)?)
    .bind(manifest.provider_type().as_str())
    .bind(lifecycle_text(manifest.state()))
    .bind(manifest.origins().web())
    .bind(manifest.origins().api())
    .bind(
        i16::try_from(manifest.configuration().schema_version().get())
            .map_err(|_| ProviderRepositoryError::Corrupt)?,
    )
    .bind(manifest.configuration().bytes())
    .bind(manifest.configuration().digest().as_bytes().as_slice())
    .bind(manifest.capability_digest().as_bytes().as_slice())
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

async fn insert_secret(
    transaction: &mut Transaction<'_, Postgres>,
    instance_id: ProviderInstanceId,
    revision: ProviderConfigurationRevision,
    secret: SealedSecret,
) -> Result<(), ProviderRepositoryError> {
    sqlx::query(
        r"
        INSERT INTO provider_instance_secret_bindings (
            instance_id, revision, secret_name, secret_generation,
            plaintext_digest, envelope_schema, wrapping_key_id,
            wrapped_data_key, nonce, ciphertext
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        ",
    )
    .bind(instance_id.as_uuid())
    .bind(i64::try_from(revision.get()).map_err(|_| ProviderRepositoryError::Corrupt)?)
    .bind(secret.name.as_str())
    .bind(i64::try_from(secret.generation.get()).map_err(|_| ProviderRepositoryError::Corrupt)?)
    .bind(secret.plaintext_digest.as_bytes().as_slice())
    .bind(secret.envelope.schema)
    .bind(secret.envelope.wrapping_key_id)
    .bind(secret.envelope.wrapped_data_key)
    .bind(secret.envelope.nonce)
    .bind(secret.envelope.ciphertext)
    .execute(&mut **transaction)
    .await
    .map_err(unavailable)?;
    Ok(())
}

fn decode_instance(
    row: InstanceRow,
    bindings: ProviderSecretBindings,
) -> Result<ProviderInstanceManifest, ProviderRepositoryError> {
    let configuration = ProviderConfigurationDocument::new(
        ProviderSchemaVersion::new(positive_u16(row.configuration_schema)?)
            .map_err(|_| ProviderRepositoryError::Corrupt)?,
        row.configuration_bytes,
    )
    .map_err(|_| ProviderRepositoryError::Corrupt)?;
    if configuration.digest() != digest(row.configuration_digest)? {
        return Err(ProviderRepositoryError::Corrupt);
    }
    let manifest = ProviderInstanceManifest::new(
        ProviderInstanceId::from_uuid(row.instance_id)
            .map_err(|_| ProviderRepositoryError::Corrupt)?,
        ProviderTypeId::new(row.provider_type).map_err(|_| ProviderRepositoryError::Corrupt)?,
        ProviderConfigurationRevision::new(positive_u64(row.revision)?)
            .map_err(|_| ProviderRepositoryError::Corrupt)?,
        lifecycle(&row.lifecycle_state)?,
        ProviderOrigins::new(row.web_origin, row.api_origin)
            .map_err(|_| ProviderRepositoryError::Corrupt)?,
        configuration,
        bindings,
        digest(row.capability_digest)?,
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

fn bindings_from_rows(
    rows: &[SecretRow],
) -> Result<ProviderSecretBindings, ProviderRepositoryError> {
    let bindings = rows
        .iter()
        .map(|row| {
            Ok(ProviderSecretBinding::new(
                ProviderSecretName::new(row.secret_name.clone())
                    .map_err(|_| ProviderRepositoryError::Corrupt)?,
                ProviderSecretGeneration::new(positive_u64(row.secret_generation)?)
                    .map_err(|_| ProviderRepositoryError::Corrupt)?,
                digest(row.plaintext_digest.clone())?,
            ))
        })
        .collect::<Result<Vec<_>, ProviderRepositoryError>>()?;
    ProviderSecretBindings::new(bindings).map_err(|_| ProviderRepositoryError::Corrupt)
}

const SECRET_ROWS_SQL: &str = r"
    SELECT secret_name, secret_generation, plaintext_digest,
           envelope_schema, wrapping_key_id, wrapped_data_key,
           nonce, ciphertext
    FROM provider_instance_secret_bindings
    WHERE instance_id = $1 AND revision = $2
    ORDER BY secret_name
";

async fn load_secret_rows(
    transaction: &mut Transaction<'_, Postgres>,
    instance_id: ProviderInstanceId,
    revision: ProviderConfigurationRevision,
) -> Result<Vec<SecretRow>, ProviderRepositoryError> {
    sqlx::query_as::<_, SecretRow>(SECRET_ROWS_SQL)
        .bind(instance_id.as_uuid())
        .bind(i64::try_from(revision.get()).map_err(|_| ProviderRepositoryError::Corrupt)?)
        .fetch_all(&mut **transaction)
        .await
        .map_err(unavailable)
}

fn encryption_failure(error: EnvelopeError) -> ProviderRepositoryError {
    match error {
        EnvelopeError::KeyEncryption(_)
        | EnvelopeError::RandomnessUnavailable
        | EnvelopeError::CryptographicFailure => ProviderRepositoryError::Unavailable,
        EnvelopeError::InvalidEnvelope
        | EnvelopeError::UnsupportedSchema
        | EnvelopeError::AuthenticationFailed => ProviderRepositoryError::SecretCustody,
    }
}
