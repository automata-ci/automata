use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_key_management::{EnvelopeCodec, KeyEncryptionProvider, KeyPurpose, SecretBytes};
use automata_ci_secret::{
    CreateSecretVersionRequest, CreatedSecretVersion, DestroySecretVersionRequest, ProviderError,
    ProviderErrorKind, ProviderHealth, ProviderOperationContext,
    ReconcileCreateSecretVersionOutcome, ReconcileCreateSecretVersionRequest,
    ResolveSecretVersionRequest, ResolvedSecretVersion, SecretAtRestProtection, SecretProvider,
    SecretValue,
};
use automata_ci_secret::{ProviderCapabilities, ProviderCapability, SecretProviderId};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    storage::{
        self, CreateVersionPreflight, CreateVersionPreflightRecord, CreateVersionRecord,
        DestroyVersionRecord, EnvelopeSqlParameters, ReconcileCreateVersion,
        ReconcileCreateVersionRecord, ResolveVersionRecord,
    },
    support::{
        ValidatedSecretDescriptor, canonical_uuid, encryption_context, locator, map_envelope_error,
        version_id,
    },
};

/// Stable provider ID seeded by the secrets schema for the built-in adapter.
pub const BUILTIN_POSTGRES_PROVIDER_ID: &str = "builtin";

/// Domain-separation purpose for encrypted built-in secret values.
pub const BUILTIN_SECRET_VALUE_KEY_PURPOSE: &str = "secrets/builtin-value:v1";

const VERSION_MUTATION_REQUEST_PREFIX: &str = "secret-version:";

/// PostgreSQL-backed built-in implementation of the secret-provider boundary.
pub struct PostgresSecretProvider {
    pool: PgPool,
    codec: EnvelopeCodec,
    purpose: KeyPurpose,
    provider_id: SecretProviderId,
    capabilities: ProviderCapabilities,
}

impl PostgresSecretProvider {
    /// Creates an adapter using the supplied `PostgreSQL` pool and key-encryption
    /// provider.
    ///
    /// # Panics
    ///
    /// Panics only if this crate's compile-time provider ID, key-purpose, or
    /// capability declaration is changed to an invalid value.
    #[must_use]
    pub fn new(pool: PgPool, key_provider: Arc<dyn KeyEncryptionProvider>) -> Self {
        Self {
            pool,
            codec: EnvelopeCodec::new(key_provider),
            purpose: KeyPurpose::new(BUILTIN_SECRET_VALUE_KEY_PURPOSE)
                .expect("the built-in secret key purpose is canonical"),
            provider_id: SecretProviderId::new(BUILTIN_POSTGRES_PROVIDER_ID)
                .expect("the built-in provider ID is canonical"),
            capabilities: ProviderCapabilities::new([
                ProviderCapability::CreateVersion,
                ProviderCapability::ReconcileCreateVersion,
                ProviderCapability::DestroyVersion,
            ])
            .expect("the built-in provider capabilities are internally consistent"),
        }
    }

    fn validate_locator(
        locator_value: &str,
        expected_secret_id: Uuid,
    ) -> Result<Uuid, ProviderError> {
        let locator_id = canonical_uuid(locator_value)?;
        if locator_id != expected_secret_id {
            return Err(ProviderError::new(ProviderErrorKind::InvalidRequest));
        }
        Ok(locator_id)
    }

    fn validate_create_request_id(request_id: &str) -> Result<String, ProviderError> {
        let encoded = request_id
            .strip_prefix(VERSION_MUTATION_REQUEST_PREFIX)
            .ok_or_else(|| ProviderError::new(ProviderErrorKind::InvalidRequest))?;
        let mutation_id = canonical_uuid(encoded)?;
        if mutation_id.is_nil() {
            return Err(ProviderError::new(ProviderErrorKind::InvalidRequest));
        }
        Ok(request_id.to_owned())
    }

    fn validate_reconciliation_locator(
        locator_value: &str,
        expected_secret_id: Uuid,
    ) -> Result<(), ProviderError> {
        if canonical_uuid(locator_value)? == expected_secret_id {
            Ok(())
        } else {
            Err(ProviderError::new(ProviderErrorKind::Conflict))
        }
    }
}

impl fmt::Debug for PostgresSecretProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresSecretProvider")
            .field("provider_id", &self.provider_id)
            .field("capabilities", &self.capabilities)
            .field("encryption", &"envelope")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SecretProvider for PostgresSecretProvider {
    fn provider_id(&self) -> &SecretProviderId {
        &self.provider_id
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }

    fn at_rest_protection(&self) -> SecretAtRestProtection {
        SecretAtRestProtection::AutomataEnvelope
    }

    async fn health(
        &self,
        context: &ProviderOperationContext,
    ) -> Result<ProviderHealth, ProviderError> {
        storage::health(
            &self.pool,
            context.tenant_id().as_str(),
            self.provider_id.as_str(),
        )
        .await
    }

    async fn create_version(
        &self,
        request: CreateSecretVersionRequest,
    ) -> Result<CreatedSecretVersion, ProviderError> {
        let secret = ValidatedSecretDescriptor::from_domain(request.secret())?;
        let expected_current_version_id = request
            .expected_existing_version()
            .map(|existing| {
                Self::validate_locator(existing.locator().as_str(), secret.secret_id())?;
                canonical_uuid(existing.version().as_str())
            })
            .transpose()?;
        let request_id = Self::validate_create_request_id(request.context().request_id().as_str())?;
        match storage::preflight_create_version(
            &self.pool,
            self.provider_id.as_str(),
            CreateVersionPreflightRecord {
                secret: secret.clone(),
                request_id: request_id.clone(),
                expected_current_version_id,
            },
        )
        .await?
        {
            CreateVersionPreflight::Staged(stored) => {
                drop(request);
                return Ok(CreatedSecretVersion::new(
                    locator(stored.secret_id),
                    version_id(stored.version_id),
                ));
            }
            CreateVersionPreflight::Reserved => {}
        }
        let plaintext = SecretBytes::new(request.value().expose_secret().to_vec())
            .map_err(|_| ProviderError::new(ProviderErrorKind::IntegrityFailure))?;
        drop(request);

        let candidate_version_id = Uuid::new_v4();
        let context = encryption_context(
            secret.tenant_id(),
            self.purpose.clone(),
            candidate_version_id,
        )?;
        let envelope = self
            .codec
            .seal(&context, plaintext)
            .await
            .map_err(map_envelope_error)?;
        let envelope = EnvelopeSqlParameters::from_envelope(envelope)?;
        let stored = storage::create_version(
            &self.pool,
            self.provider_id.as_str(),
            CreateVersionRecord {
                secret,
                request_id,
                expected_current_version_id,
                candidate_version_id,
                envelope,
            },
        )
        .await?;
        Ok(CreatedSecretVersion::new(
            locator(stored.secret_id),
            version_id(stored.version_id),
        ))
    }

    async fn reconcile_create_version(
        &self,
        request: ReconcileCreateSecretVersionRequest,
    ) -> Result<ReconcileCreateSecretVersionOutcome, ProviderError> {
        let secret = ValidatedSecretDescriptor::from_domain(request.secret())?;
        let expected_current_version_id = request
            .expected_existing_version()
            .map(|existing| {
                Self::validate_reconciliation_locator(
                    existing.locator().as_str(),
                    secret.secret_id(),
                )?;
                canonical_uuid(existing.version().as_str())
            })
            .transpose()?;
        let request_id = Self::validate_create_request_id(request.context().request_id().as_str())?;
        drop(request);

        Ok(
            match storage::reconcile_create_version(
                &self.pool,
                self.provider_id.as_str(),
                ReconcileCreateVersionRecord {
                    secret,
                    request_id,
                    expected_current_version_id,
                },
            )
            .await?
            {
                ReconcileCreateVersion::AlreadyCommitted(stored) => {
                    ReconcileCreateSecretVersionOutcome::AlreadyCommitted(
                        CreatedSecretVersion::new(
                            locator(stored.secret_id),
                            version_id(stored.version_id),
                        ),
                    )
                }
                ReconcileCreateVersion::DefinitivelyNotCommitted => {
                    ReconcileCreateSecretVersionOutcome::DefinitivelyNotCommitted
                }
            },
        )
    }

    async fn resolve_version(
        &self,
        request: ResolveSecretVersionRequest,
    ) -> Result<ResolvedSecretVersion, ProviderError> {
        let secret = ValidatedSecretDescriptor::from_domain(request.secret())?;
        Self::validate_locator(request.locator().as_str(), secret.secret_id())?;
        let requested_version_id = canonical_uuid(request.version().as_str())?;
        let locked = storage::resolve_version(
            &self.pool,
            self.provider_id.as_str(),
            ResolveVersionRecord {
                secret: secret.clone(),
                version_id: requested_version_id,
            },
        )
        .await?;
        let context = encryption_context(
            secret.tenant_id(),
            self.purpose.clone(),
            requested_version_id,
        )?;
        let plaintext = self
            .codec
            .open(&context, locked.envelope())
            .await
            .map_err(map_envelope_error)?;
        locked.commit().await?;
        let value = SecretValue::new(plaintext.expose_secret().to_vec())
            .map_err(|_| ProviderError::new(ProviderErrorKind::IntegrityFailure))?;
        drop(plaintext);
        Ok(ResolvedSecretVersion::new(
            value,
            version_id(requested_version_id),
            None,
        ))
    }

    async fn destroy_version(
        &self,
        request: DestroySecretVersionRequest,
    ) -> Result<(), ProviderError> {
        let secret = ValidatedSecretDescriptor::from_domain(request.secret())?;
        Self::validate_locator(request.locator().as_str(), secret.secret_id())?;
        let requested_version_id = canonical_uuid(request.version().as_str())?;
        let request_id = request.context().request_id().as_str().to_owned();
        storage::destroy_version(
            &self.pool,
            self.provider_id.as_str(),
            DestroyVersionRecord {
                secret,
                version_id: requested_version_id,
                request_id,
            },
        )
        .await
    }
}
