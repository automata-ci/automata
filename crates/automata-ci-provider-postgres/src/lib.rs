#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! `PostgreSQL` persistence for provider instance and connection manifests.

use std::{fmt, sync::Arc};

use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_key_management::{
    EncryptedEnvelope, EnvelopeCodec, KeyEncryptionContext, KeyEncryptionProvider, KeyId,
    KeyPurpose, WrappedDataKey,
};
use automata_ci_provider::{
    AcceptProviderDelivery, ClaimProviderProcessing, ClaimedProviderProcessing,
    CompleteProviderProcessing, FailProviderProcessing, ProviderConnectionId,
    ProviderConnectionManifest, ProviderConnectionRevision, ProviderDelivery,
    ProviderDeliveryAcceptOutcome, ProviderDeliveryFuture, ProviderDeliveryId,
    ProviderDeliveryRepository, ProviderInstanceId, ProviderInstanceRecord,
    ProviderManifestRepository, ProviderProcessingFuture, ProviderProcessingReceipt,
    ProviderProcessingRepository, ProviderRepositoryError, ProviderRepositoryFuture,
    ProviderResultFuture, ProviderResultRepository, ProviderResultSaveOutcome, ProviderSaveOutcome,
    ProviderWebhookEndpointId, ProviderWebhookEndpointManifest, ProviderWebhookEndpointRecord,
    ProviderWebhookEndpointRepository, ProviderWebhookEndpointRevision, RenewProviderProcessing,
    RetryProviderProcessing,
};
use sqlx::{PgPool, Postgres, Transaction};

mod connection;
mod delivery;
mod endpoint;
mod instance;
mod result;

const SECRET_PURPOSE: &str = "provider/instance-secret:v1";
const INSTANCE_LOCK_SALT: i64 = 6_692_456_121_835_322_101;
const CONNECTION_LOCK_SALT: i64 = 7_752_013_457_331_067_413;
const ENDPOINT_LOCK_SALT: i64 = 6_747_890_046_912_418_703;
const RESULT_LOCK_SALT: i64 = 5_638_152_860_934_413_377;

/// Atomic `PostgreSQL` provider manifest repository with envelope-encrypted secrets.
#[derive(Clone)]
pub struct PostgresProviderManifestRepository {
    pool: PgPool,
    envelopes: Arc<EnvelopeCodec>,
}

impl PostgresProviderManifestRepository {
    /// Binds the repository to a pool and provider-neutral wrapping-key implementation.
    #[must_use]
    pub fn new(pool: PgPool, keys: Arc<dyn KeyEncryptionProvider>) -> Self {
        Self {
            pool,
            envelopes: Arc::new(EnvelopeCodec::new(keys)),
        }
    }

    /// Returns the exact database pool used by this adapter.
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }
}

impl fmt::Debug for PostgresProviderManifestRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresProviderManifestRepository")
            .field("pool", &"[CONFIGURED]")
            .field("envelope_codec", &"[CONFIGURED]")
            .finish()
    }
}

impl ProviderManifestRepository for PostgresProviderManifestRepository {
    fn save_instance(
        &self,
        record: ProviderInstanceRecord,
    ) -> ProviderRepositoryFuture<'_, ProviderSaveOutcome> {
        Box::pin(self.save_instance_inner(record))
    }

    fn load_instance(
        &self,
        instance_id: ProviderInstanceId,
        revision: automata_ci_provider::ProviderConfigurationRevision,
    ) -> ProviderRepositoryFuture<'_, Option<ProviderInstanceRecord>> {
        Box::pin(self.load_instance_inner(instance_id, revision))
    }

    fn current_instance(
        &self,
        instance_id: ProviderInstanceId,
    ) -> ProviderRepositoryFuture<'_, Option<ProviderInstanceRecord>> {
        Box::pin(self.current_instance_inner(instance_id))
    }

    fn save_connection(
        &self,
        manifest: ProviderConnectionManifest,
    ) -> ProviderRepositoryFuture<'_, ProviderSaveOutcome> {
        Box::pin(self.save_connection_inner(manifest))
    }

    fn load_connection(
        &self,
        connection_id: ProviderConnectionId,
        revision: ProviderConnectionRevision,
    ) -> ProviderRepositoryFuture<'_, Option<ProviderConnectionManifest>> {
        Box::pin(self.load_connection_inner(connection_id, revision))
    }

    fn current_connection(
        &self,
        connection_id: ProviderConnectionId,
    ) -> ProviderRepositoryFuture<'_, Option<ProviderConnectionManifest>> {
        Box::pin(self.current_connection_inner(connection_id))
    }
}

impl ProviderWebhookEndpointRepository for PostgresProviderManifestRepository {
    fn save_endpoint(
        &self,
        endpoint: ProviderWebhookEndpointManifest,
    ) -> ProviderDeliveryFuture<'_, ProviderSaveOutcome> {
        Box::pin(self.save_endpoint_inner(endpoint))
    }

    fn resolve_endpoint(
        &self,
        endpoint_id: ProviderWebhookEndpointId,
    ) -> ProviderDeliveryFuture<'_, Option<ProviderWebhookEndpointRecord>> {
        Box::pin(self.resolve_endpoint_inner(endpoint_id))
    }

    fn load_endpoint(
        &self,
        endpoint_id: ProviderWebhookEndpointId,
        revision: ProviderWebhookEndpointRevision,
    ) -> ProviderDeliveryFuture<'_, Option<ProviderWebhookEndpointRecord>> {
        Box::pin(self.load_endpoint_inner(endpoint_id, revision))
    }
}

impl ProviderDeliveryRepository for PostgresProviderManifestRepository {
    fn accept_delivery(
        &self,
        request: AcceptProviderDelivery,
    ) -> ProviderDeliveryFuture<'_, ProviderDeliveryAcceptOutcome> {
        Box::pin(self.accept_delivery_inner(request))
    }

    fn load_delivery(
        &self,
        delivery_id: ProviderDeliveryId,
    ) -> ProviderDeliveryFuture<'_, Option<ProviderDelivery>> {
        Box::pin(self.load_delivery_inner(delivery_id))
    }
}

impl ProviderProcessingRepository for PostgresProviderManifestRepository {
    fn claim_processing(
        &self,
        request: ClaimProviderProcessing,
    ) -> ProviderProcessingFuture<'_, Option<ClaimedProviderProcessing>> {
        Box::pin(self.claim_processing_inner(request))
    }

    fn bind_processing_source(
        &self,
        request: automata_ci_provider::BindProviderProcessingSource,
    ) -> ProviderProcessingFuture<'_, ClaimedProviderProcessing> {
        Box::pin(self.bind_processing_source_inner(request))
    }

    fn complete_processing(
        &self,
        request: CompleteProviderProcessing,
    ) -> ProviderProcessingFuture<'_, ProviderProcessingReceipt> {
        Box::pin(self.complete_processing_inner(request))
    }

    fn renew_processing(
        &self,
        request: RenewProviderProcessing,
    ) -> ProviderProcessingFuture<'_, automata_ci_provider::ProviderProcessingClaimFence> {
        Box::pin(self.renew_processing_inner(request))
    }

    fn retry_processing(
        &self,
        request: RetryProviderProcessing,
    ) -> ProviderProcessingFuture<'_, ProviderProcessingReceipt> {
        Box::pin(self.retry_processing_inner(request))
    }

    fn fail_processing(
        &self,
        request: FailProviderProcessing,
    ) -> ProviderProcessingFuture<'_, ProviderProcessingReceipt> {
        Box::pin(self.fail_processing_inner(request))
    }
}

impl ProviderResultRepository for PostgresProviderManifestRepository {
    fn save_desired(
        &self,
        request: automata_ci_provider::SaveDesiredProviderResult,
    ) -> ProviderResultFuture<'_, ProviderResultSaveOutcome> {
        Box::pin(self.save_desired_result_inner(request))
    }

    fn claim_result(
        &self,
        request: automata_ci_provider::ClaimProviderResult,
    ) -> ProviderResultFuture<'_, Option<automata_ci_provider::ClaimedProviderResult>> {
        Box::pin(self.claim_result_inner(request))
    }

    fn complete_result(
        &self,
        request: automata_ci_provider::CompleteProviderResult,
    ) -> ProviderResultFuture<'_, ()> {
        Box::pin(self.complete_result_inner(request))
    }

    fn retry_result(
        &self,
        request: automata_ci_provider::RetryProviderResult,
    ) -> ProviderResultFuture<'_, ()> {
        Box::pin(self.retry_result_inner(request))
    }

    fn fail_result(
        &self,
        request: automata_ci_provider::FailProviderResult,
    ) -> ProviderResultFuture<'_, ()> {
        Box::pin(self.fail_result_inner(request))
    }
}

async fn lock(
    transaction: &mut Transaction<'_, Postgres>,
    identity: &str,
    salt: i64,
) -> Result<(), ProviderRepositoryError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, $2))")
        .bind(identity)
        .bind(salt)
        .execute(&mut **transaction)
        .await
        .map_err(unavailable)?;
    Ok(())
}

fn secret_context(
    instance_id: ProviderInstanceId,
    revision: u64,
    name: &str,
    generation: u64,
) -> Result<KeyEncryptionContext, ProviderRepositoryError> {
    KeyEncryptionContext::new(
        instance_id.to_string(),
        KeyPurpose::new(SECRET_PURPOSE).map_err(|_| ProviderRepositoryError::Corrupt)?,
        format!("revision/{revision}/secret/{name}/generation/{generation}"),
    )
    .map_err(|_| ProviderRepositoryError::Corrupt)
}

#[derive(Debug)]
struct EnvelopeParts {
    schema: i16,
    wrapping_key_id: String,
    wrapped_data_key: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl TryFrom<EncryptedEnvelope> for EnvelopeParts {
    type Error = ProviderRepositoryError;

    fn try_from(envelope: EncryptedEnvelope) -> Result<Self, Self::Error> {
        let (schema, wrapped, nonce, ciphertext) = envelope.into_parts();
        let (key_id, wrapped_data_key) = wrapped.into_parts();
        Ok(Self {
            schema: i16::try_from(schema).map_err(|_| ProviderRepositoryError::Corrupt)?,
            wrapping_key_id: key_id.as_str().to_owned(),
            wrapped_data_key,
            nonce: nonce.to_vec(),
            ciphertext,
        })
    }
}

fn envelope(
    schema: i16,
    wrapping_key_id: String,
    wrapped_data_key: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
) -> Result<EncryptedEnvelope, ProviderRepositoryError> {
    let schema = u16::try_from(schema).map_err(|_| ProviderRepositoryError::Corrupt)?;
    let key_id = KeyId::new(wrapping_key_id).map_err(|_| ProviderRepositoryError::Corrupt)?;
    let wrapped = WrappedDataKey::new(key_id, wrapped_data_key)
        .map_err(|_| ProviderRepositoryError::Corrupt)?;
    let nonce = nonce
        .try_into()
        .map_err(|_| ProviderRepositoryError::Corrupt)?;
    EncryptedEnvelope::from_parts(schema, wrapped, nonce, ciphertext)
        .map_err(|_| ProviderRepositoryError::Corrupt)
}

fn digest(value: Vec<u8>) -> Result<Sha256Digest, ProviderRepositoryError> {
    let bytes = value
        .try_into()
        .map_err(|_| ProviderRepositoryError::Corrupt)?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn positive_u64(value: i64) -> Result<u64, ProviderRepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(ProviderRepositoryError::Corrupt)
}

fn positive_u16(value: i16) -> Result<u16, ProviderRepositoryError> {
    u16::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(ProviderRepositoryError::Corrupt)
}

fn timestamp(value: i64) -> UnixMillis {
    UnixMillis::new(value)
}

fn optional_timestamp(value: Option<i64>) -> Option<UnixMillis> {
    value.map(UnixMillis::new)
}

fn lifecycle(
    value: &str,
) -> Result<automata_ci_provider::ProviderLifecycleState, ProviderRepositoryError> {
    match value {
        "disabled" => Ok(automata_ci_provider::ProviderLifecycleState::Disabled),
        "active" => Ok(automata_ci_provider::ProviderLifecycleState::Active),
        "retired" => Ok(automata_ci_provider::ProviderLifecycleState::Retired),
        _ => Err(ProviderRepositoryError::Corrupt),
    }
}

const fn lifecycle_text(value: automata_ci_provider::ProviderLifecycleState) -> &'static str {
    match value {
        automata_ci_provider::ProviderLifecycleState::Disabled => "disabled",
        automata_ci_provider::ProviderLifecycleState::Active => "active",
        automata_ci_provider::ProviderLifecycleState::Retired => "retired",
    }
}

fn unavailable(_: sqlx::Error) -> ProviderRepositoryError {
    ProviderRepositoryError::Unavailable
}
