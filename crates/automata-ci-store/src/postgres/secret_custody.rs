use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_key_management::{
    ENVELOPE_NONCE_BYTES, EncryptedEnvelope, EnvelopeCodec, KeyEncryptionContext,
    KeyEncryptionProvider, KeyId, KeyPurpose, SecretBytes, WrappedDataKey,
};
use sqlx::{PgPool, Row as _};

use crate::{
    MAX_SECRET_CUSTODY_CONFIGURED_KEYS, SECRET_CUSTODY_CANARY_GENERATION,
    SecretCustodyCanaryBinding, SecretCustodyCanaryGeneration, SecretCustodyKeySet,
    SecretCustodyRepository, SecretCustodyRepositoryError, SecretCustodyRequirements,
    VerifiedSecretCustody, VerifySecretCustody, VerifySecretCustodyOutcome,
};

use super::durable_schema::{current_durable_schemas, is_current_secret_custody_canary_schema};

const CANARY_CONTEXT_TENANT: &str = "automata-ci";
// foundation-governance: derived-contract owner=store kind=cryptographic-context
const CANARY_PURPOSE: &str = "actions/secrets/custody-canary:v1";
// foundation-governance: derived-contract owner=store kind=cryptographic-context
const CANARY_PLAINTEXT: &[u8] = b"automata-ci-secret-custody-canary-v1";
const REQUIRED_KEY_QUERY_BOUND: i64 = 33;
const _: () = assert!(MAX_SECRET_CUSTODY_CONFIGURED_KEYS == 32);
const _: () = assert!(CANARY_PLAINTEXT.len() == 36);

const REQUIREMENTS_QUERY: &str = r#"
    WITH configuration_keys AS (
        SELECT DISTINCT envelope.wrapping_key_id COLLATE "C" AS wrapping_key_id
        FROM secret_provider_configuration_envelopes AS envelope
        JOIN secret_provider_configuration_envelope_heads AS head
          ON head.tenant_id = envelope.tenant_id
         AND head.provider_id = envelope.provider_id
         AND head.envelope_generation = envelope.envelope_generation
        ORDER BY envelope.wrapping_key_id COLLATE "C"
        LIMIT $1
    ), locator_keys AS (
        SELECT DISTINCT envelope.wrapping_key_id COLLATE "C" AS wrapping_key_id
        FROM secret_provider_locator_envelopes AS envelope
        JOIN secret_provider_locator_envelope_heads AS head
          ON head.tenant_id = envelope.tenant_id
         AND head.secret_id = envelope.secret_id
         AND head.envelope_generation = envelope.envelope_generation
        ORDER BY envelope.wrapping_key_id COLLATE "C"
        LIMIT $1
    ), provider_version_keys AS (
        SELECT DISTINCT envelope.wrapping_key_id COLLATE "C" AS wrapping_key_id
        FROM secret_provider_version_envelopes AS envelope
        JOIN secret_provider_version_envelope_heads AS head
          ON head.tenant_id = envelope.tenant_id
         AND head.secret_version_id = envelope.secret_version_id
         AND head.envelope_generation = envelope.envelope_generation
        ORDER BY envelope.wrapping_key_id COLLATE "C"
        LIMIT $1
    ), builtin_version_keys AS (
        SELECT DISTINCT envelope.wrapping_key_id COLLATE "C" AS wrapping_key_id
        FROM secret_version_envelopes AS envelope
        JOIN secret_version_envelope_heads AS head
          ON head.tenant_id = envelope.tenant_id
         AND head.secret_version_id = envelope.secret_version_id
         AND head.envelope_generation = envelope.envelope_generation
        ORDER BY envelope.wrapping_key_id COLLATE "C"
        LIMIT $1
    ), lease_keys AS (
        SELECT DISTINCT envelope.wrapping_key_id COLLATE "C" AS wrapping_key_id
        FROM secret_provider_lease_envelopes AS envelope
        JOIN secret_provider_lease_envelope_heads AS head
          ON head.tenant_id = envelope.tenant_id
         AND head.provider_lease_record_id = envelope.provider_lease_record_id
         AND head.envelope_generation = envelope.envelope_generation
        ORDER BY envelope.wrapping_key_id COLLATE "C"
        LIMIT $1
    ), rotation_from_keys AS (
        SELECT DISTINCT rotation.from_wrapping_key_id COLLATE "C" AS wrapping_key_id
        FROM secret_key_rotations AS rotation
        WHERE rotation.status IN ('pending', 'running', 'failed')
           OR EXISTS (
               SELECT 1
               FROM secret_key_rotation_items AS item
               WHERE item.tenant_id = rotation.tenant_id
                 AND item.rotation_id = rotation.id
                 AND item.status IN ('pending', 'failed')
           )
        ORDER BY rotation.from_wrapping_key_id COLLATE "C"
        LIMIT $1
    ), rotation_to_keys AS (
        SELECT DISTINCT rotation.to_wrapping_key_id COLLATE "C" AS wrapping_key_id
        FROM secret_key_rotations AS rotation
        WHERE rotation.status IN ('pending', 'running', 'failed')
           OR EXISTS (
               SELECT 1
               FROM secret_key_rotation_items AS item
               WHERE item.tenant_id = rotation.tenant_id
                 AND item.rotation_id = rotation.id
                 AND item.status IN ('pending', 'failed')
           )
        ORDER BY rotation.to_wrapping_key_id COLLATE "C"
        LIMIT $1
    ), required_keys AS (
        SELECT wrapping_key_id FROM configuration_keys
        UNION
        SELECT wrapping_key_id FROM locator_keys
        UNION
        SELECT wrapping_key_id FROM provider_version_keys
        UNION
        SELECT wrapping_key_id FROM builtin_version_keys
        UNION
        SELECT wrapping_key_id FROM lease_keys
        UNION
        SELECT wrapping_key_id FROM rotation_from_keys
        UNION
        SELECT wrapping_key_id FROM rotation_to_keys
    )
    SELECT
        EXISTS (
            SELECT 1 FROM secret_providers WHERE status = 'active'
        ) AS active_provider,
        (
            EXISTS (SELECT 1 FROM secret_provider_configuration_envelopes)
            OR EXISTS (SELECT 1 FROM secret_provider_locator_envelopes)
            OR EXISTS (SELECT 1 FROM secret_provider_version_envelopes)
            OR EXISTS (SELECT 1 FROM secret_version_envelopes)
            OR EXISTS (SELECT 1 FROM secret_provider_lease_envelopes)
        ) AS encrypted_envelopes,
        EXISTS (
            SELECT 1 FROM secret_version_mutations WHERE state = 'reserved'
        ) AS open_mutations,
        EXISTS (
            SELECT 1
            FROM secret_provider_leases
            WHERE status IN ('active', 'revocation_pending')
        ) AS open_leases,
        EXISTS (
            SELECT 1
            FROM secret_cleanup_outbox
            WHERE status IN ('pending', 'in_progress', 'dead_letter')
        ) AS open_cleanup,
        EXISTS (
            SELECT 1
            FROM secret_mutation_recovery_outbox
            WHERE status IN ('pending', 'in_progress')
        ) AS open_recovery,
        (
            EXISTS (
                SELECT 1
                FROM secret_key_rotations
                WHERE status IN ('pending', 'running', 'failed')
            )
            OR EXISTS (
                SELECT 1
                FROM secret_key_rotation_items
                WHERE status IN ('pending', 'failed')
            )
        ) AS open_rotation,
        ARRAY(
            SELECT wrapping_key_id
            FROM required_keys
            ORDER BY wrapping_key_id COLLATE "C"
            LIMIT $1
        ) AS required_key_ids
"#;

const KEY_ID_IS_FRESH_QUERY: &str = r"
    SELECT NOT (
        EXISTS (
            SELECT 1 FROM secret_provider_configuration_envelopes
            WHERE wrapping_key_id = $1
        )
        OR EXISTS (
            SELECT 1 FROM secret_provider_locator_envelopes
            WHERE wrapping_key_id = $1
        )
        OR EXISTS (
            SELECT 1 FROM secret_provider_version_envelopes
            WHERE wrapping_key_id = $1
        )
        OR EXISTS (
            SELECT 1 FROM secret_version_envelopes
            WHERE wrapping_key_id = $1
        )
        OR EXISTS (
            SELECT 1 FROM secret_provider_lease_envelopes
            WHERE wrapping_key_id = $1
        )
        OR EXISTS (
            SELECT 1 FROM secret_key_rotations
            WHERE from_wrapping_key_id = $1 OR to_wrapping_key_id = $1
        )
    )
";

/// `PostgreSQL` adapter for authenticated repository-secret custody readiness.
///
/// The adapter can inspect value-free durable requirements without key
/// configuration. Verification additionally requires an injected wrapping-key
/// implementation and never exposes it through diagnostics.
#[derive(Clone)]
pub struct PostgresSecretCustodyRepository {
    pool: PgPool,
    codec: Option<Arc<EnvelopeCodec>>,
}

impl PostgresSecretCustodyRepository {
    /// Creates a requirement-only adapter over an existing bounded pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool, codec: None }
    }

    /// Adds authenticated envelope operations for configured custody checks.
    #[must_use]
    pub fn with_key_encryption_provider(
        mut self,
        provider: Arc<dyn KeyEncryptionProvider>,
    ) -> Self {
        self.codec = Some(Arc::new(EnvelopeCodec::new(provider)));
        self
    }

    /// Returns the concrete pool for narrowly scoped integration composition.
    #[must_use]
    pub const fn postgres_pool(&self) -> &PgPool {
        &self.pool
    }
}

impl fmt::Debug for PostgresSecretCustodyRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresSecretCustodyRepository")
            .field(
                "key_encryption",
                &self.codec.as_ref().map(|_| "[CONFIGURED]"),
            )
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SecretCustodyRepository for PostgresSecretCustodyRepository {
    async fn inspect_secret_custody_requirements(
        &self,
    ) -> Result<SecretCustodyRequirements, SecretCustodyRepositoryError> {
        inspect_requirements(&self.pool).await
    }

    async fn verify_or_create_secret_custody(
        &self,
        request: VerifySecretCustody,
    ) -> Result<VerifySecretCustodyOutcome, SecretCustodyRepositoryError> {
        let initial_requirements = inspect_requirements(&self.pool).await?;
        let Some(configured_keys) = request.configured_keys() else {
            return if initial_requirements.configuration_required() {
                Err(SecretCustodyRepositoryError::ConfigurationRequired)
            } else {
                Ok(VerifySecretCustodyOutcome::NotRequired)
            };
        };
        require_durable_keys_configured(configured_keys, &initial_requirements)?;
        let codec = self
            .codec
            .as_deref()
            .ok_or(SecretCustodyRepositoryError::ConfigurationUnavailable)?;

        ensure_active_canary(&self.pool, codec, configured_keys.active_key_id()).await?;
        let canaries = load_configured_canaries(&self.pool, configured_keys).await?;
        require_missing_keys_are_prestaged(
            &self.pool,
            configured_keys,
            &initial_requirements,
            &canaries,
        )
        .await?;
        let bindings = verify_canaries(codec, canaries).await?;

        // Re-read after provider operations so the receipt binds the latest
        // completed statement snapshot, not the earlier pre-I/O observation.
        let requirements = inspect_requirements(&self.pool).await?;
        require_durable_keys_configured(configured_keys, &requirements)?;
        require_required_canaries(&requirements, &bindings)?;
        let receipt =
            VerifiedSecretCustody::from_verified_parts(configured_keys, &requirements, bindings)
                .map_err(|_| SecretCustodyRepositoryError::CorruptData)?;
        Ok(VerifySecretCustodyOutcome::Verified(receipt))
    }
}

async fn inspect_requirements(
    pool: &PgPool,
) -> Result<SecretCustodyRequirements, SecretCustodyRepositoryError> {
    let row = sqlx::query(REQUIREMENTS_QUERY)
        .bind(REQUIRED_KEY_QUERY_BOUND)
        .fetch_one(pool)
        .await
        .map_err(operation_error)?;
    let encoded_key_ids = row
        .try_get::<Vec<String>, _>("required_key_ids")
        .map_err(|_| SecretCustodyRepositoryError::CorruptData)?;
    let required_key_ids = encoded_key_ids
        .into_iter()
        .map(KeyId::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SecretCustodyRepositoryError::CorruptData)?;
    let states = [
        decode_bool(&row, "active_provider")?,
        decode_bool(&row, "encrypted_envelopes")?,
        decode_bool(&row, "open_mutations")?,
        decode_bool(&row, "open_leases")?,
        decode_bool(&row, "open_cleanup")?,
        decode_bool(&row, "open_recovery")?,
        decode_bool(&row, "open_rotation")?,
    ];
    SecretCustodyRequirements::from_durable_parts(states, required_key_ids)
        .map_err(|_| SecretCustodyRepositoryError::CorruptData)
}

fn decode_bool(
    row: &sqlx::postgres::PgRow,
    column: &'static str,
) -> Result<bool, SecretCustodyRepositoryError> {
    row.try_get(column)
        .map_err(|_| SecretCustodyRepositoryError::CorruptData)
}

fn require_durable_keys_configured(
    configured_keys: &SecretCustodyKeySet,
    requirements: &SecretCustodyRequirements,
) -> Result<(), SecretCustodyRepositoryError> {
    if requirements
        .required_key_ids()
        .iter()
        .any(|required| !configured_keys.contains(required))
    {
        return Err(SecretCustodyRepositoryError::RequiredKeyUnavailable);
    }
    Ok(())
}

async fn ensure_active_canary(
    pool: &PgPool,
    codec: &EnvelopeCodec,
    active_key_id: &KeyId,
) -> Result<(), SecretCustodyRepositoryError> {
    let existing = load_canary(pool, active_key_id).await?;
    if existing.is_none() && !key_id_is_fresh(pool, active_key_id).await? {
        return Err(SecretCustodyRepositoryError::CanaryUnavailable);
    }
    let context = canary_context(active_key_id)?;
    let plaintext = SecretBytes::new(CANARY_PLAINTEXT.to_vec())
        .map_err(|_| SecretCustodyRepositoryError::CorruptData)?;
    let candidate = codec
        .seal(&context, plaintext)
        .await
        .map_err(|_| SecretCustodyRepositoryError::VerificationFailed)?;
    if candidate.wrapping_key_id() != active_key_id {
        return Err(SecretCustodyRepositoryError::ActiveKeyMismatch);
    }
    if existing.is_none() {
        insert_canary(pool, active_key_id, &candidate).await?;
    }
    Ok(())
}

async fn key_id_is_fresh(
    pool: &PgPool,
    key_id: &KeyId,
) -> Result<bool, SecretCustodyRepositoryError> {
    sqlx::query_scalar(KEY_ID_IS_FRESH_QUERY)
        .bind(key_id.as_str())
        .fetch_one(pool)
        .await
        .map_err(operation_error)
}

async fn insert_canary(
    pool: &PgPool,
    key_id: &KeyId,
    envelope: &EncryptedEnvelope,
) -> Result<(), SecretCustodyRepositoryError> {
    let schemas = current_durable_schemas();
    sqlx::query(
        r"
        INSERT INTO secret_custody_key_canaries (
            wrapping_key_id, canary_generation, canary_schema,
            ciphertext, nonce, wrapped_data_key, envelope_schema,
            created_at_ms
        ) VALUES (
            $1, $6, $7, $2, $3, $4, $5,
            floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT
        )
        ON CONFLICT (wrapping_key_id) DO NOTHING
        ",
    )
    .bind(key_id.as_str())
    .bind(envelope.ciphertext())
    .bind(envelope.nonce().as_slice())
    .bind(envelope.wrapped_data_key().ciphertext())
    .bind(i32::from(envelope.schema()))
    .bind(i64::try_from(SECRET_CUSTODY_CANARY_GENERATION).expect("canary generation fits BIGINT"))
    .bind(schemas.secret_custody_canary_i32)
    .execute(pool)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn load_configured_canaries(
    pool: &PgPool,
    configured_keys: &SecretCustodyKeySet,
) -> Result<Vec<StoredCanary>, SecretCustodyRepositoryError> {
    let key_ids = configured_keys
        .key_ids()
        .iter()
        .map(|key_id| key_id.as_str().to_owned())
        .collect::<Vec<_>>();
    let rows = sqlx::query(
        r#"
        SELECT wrapping_key_id, canary_generation, canary_schema,
               ciphertext, nonce, wrapped_data_key, envelope_schema
        FROM secret_custody_key_canaries
        WHERE wrapping_key_id = ANY($1::TEXT[])
        ORDER BY wrapping_key_id COLLATE "C"
        "#,
    )
    .bind(&key_ids)
    .fetch_all(pool)
    .await
    .map_err(operation_error)?;
    let canaries = rows
        .iter()
        .map(decode_canary)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(canaries)
}

async fn require_missing_keys_are_prestaged(
    pool: &PgPool,
    configured_keys: &SecretCustodyKeySet,
    requirements: &SecretCustodyRequirements,
    canaries: &[StoredCanary],
) -> Result<(), SecretCustodyRepositoryError> {
    for key_id in configured_keys.key_ids() {
        if canaries.iter().any(|canary| &canary.key_id == key_id) {
            continue;
        }
        if key_id == configured_keys.active_key_id()
            || requirements.required_key_ids().contains(key_id)
            || !key_id_is_fresh(pool, key_id).await?
        {
            return Err(SecretCustodyRepositoryError::CanaryUnavailable);
        }
    }
    Ok(())
}

fn require_required_canaries(
    requirements: &SecretCustodyRequirements,
    canaries: &[SecretCustodyCanaryBinding],
) -> Result<(), SecretCustodyRepositoryError> {
    if requirements
        .required_key_ids()
        .iter()
        .any(|required| !canaries.iter().any(|binding| binding.key_id() == required))
    {
        return Err(SecretCustodyRepositoryError::CanaryUnavailable);
    }
    Ok(())
}

async fn load_canary(
    pool: &PgPool,
    key_id: &KeyId,
) -> Result<Option<StoredCanary>, SecretCustodyRepositoryError> {
    sqlx::query(
        r"
        SELECT wrapping_key_id, canary_generation, canary_schema,
               ciphertext, nonce, wrapped_data_key, envelope_schema
        FROM secret_custody_key_canaries
        WHERE wrapping_key_id = $1
        ",
    )
    .bind(key_id.as_str())
    .fetch_optional(pool)
    .await
    .map_err(operation_error)?
    .as_ref()
    .map(decode_canary)
    .transpose()
}

async fn verify_canaries(
    codec: &EnvelopeCodec,
    canaries: Vec<StoredCanary>,
) -> Result<Vec<SecretCustodyCanaryBinding>, SecretCustodyRepositoryError> {
    let mut bindings = Vec::with_capacity(canaries.len());
    for canary in canaries {
        let context = canary_context(&canary.key_id)?;
        let plaintext = codec
            .open(&context, &canary.envelope)
            .await
            .map_err(|_| SecretCustodyRepositoryError::VerificationFailed)?;
        if plaintext.expose_secret() != CANARY_PLAINTEXT {
            return Err(SecretCustodyRepositoryError::VerificationFailed);
        }
        bindings.push(SecretCustodyCanaryBinding::new(
            canary.key_id,
            canary.generation,
        ));
    }
    Ok(bindings)
}

fn decode_canary(
    row: &sqlx::postgres::PgRow,
) -> Result<StoredCanary, SecretCustodyRepositoryError> {
    let key_id = KeyId::new(
        row.try_get::<String, _>("wrapping_key_id")
            .map_err(|_| SecretCustodyRepositoryError::CorruptData)?,
    )
    .map_err(|_| SecretCustodyRepositoryError::CorruptData)?;
    let generation = row
        .try_get::<i64, _>("canary_generation")
        .ok()
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(SecretCustodyRepositoryError::CorruptData)
        .and_then(|value| {
            SecretCustodyCanaryGeneration::new(value)
                .map_err(|_| SecretCustodyRepositoryError::CorruptData)
        })?;
    if !is_current_secret_custody_canary_schema(
        row.try_get::<i32, _>("canary_schema")
            .map_err(|_| SecretCustodyRepositoryError::CorruptData)?,
    ) {
        return Err(SecretCustodyRepositoryError::CorruptData);
    }
    let envelope_schema = row
        .try_get::<i32, _>("envelope_schema")
        .ok()
        .and_then(|value| u16::try_from(value).ok())
        .ok_or(SecretCustodyRepositoryError::CorruptData)?;
    let nonce: [u8; ENVELOPE_NONCE_BYTES] = row
        .try_get::<Vec<u8>, _>("nonce")
        .map_err(|_| SecretCustodyRepositoryError::CorruptData)?
        .try_into()
        .map_err(|_: Vec<u8>| SecretCustodyRepositoryError::CorruptData)?;
    let wrapped_data_key = WrappedDataKey::new(
        key_id.clone(),
        row.try_get::<Vec<u8>, _>("wrapped_data_key")
            .map_err(|_| SecretCustodyRepositoryError::CorruptData)?,
    )
    .map_err(|_| SecretCustodyRepositoryError::CorruptData)?;
    let envelope = EncryptedEnvelope::from_parts(
        envelope_schema,
        wrapped_data_key,
        nonce,
        row.try_get::<Vec<u8>, _>("ciphertext")
            .map_err(|_| SecretCustodyRepositoryError::CorruptData)?,
    )
    .map_err(|_| SecretCustodyRepositoryError::CorruptData)?;
    Ok(StoredCanary {
        key_id,
        generation,
        envelope,
    })
}

fn canary_context(key_id: &KeyId) -> Result<KeyEncryptionContext, SecretCustodyRepositoryError> {
    let purpose =
        KeyPurpose::new(CANARY_PURPOSE).map_err(|_| SecretCustodyRepositoryError::CorruptData)?;
    KeyEncryptionContext::new(CANARY_CONTEXT_TENANT, purpose, key_id.as_str())
        .map_err(|_| SecretCustodyRepositoryError::CorruptData)
}

fn operation_error(_: sqlx::Error) -> SecretCustodyRepositoryError {
    SecretCustodyRepositoryError::Unavailable
}

struct StoredCanary {
    key_id: KeyId,
    generation: SecretCustodyCanaryGeneration,
    envelope: EncryptedEnvelope,
}
