//! Durable provider configuration and connection repository ports.

use std::{fmt, future::Future, pin::Pin};

use thiserror::Error;

use crate::{
    ProviderConfigurationRevision, ProviderConnectionId, ProviderConnectionManifest,
    ProviderConnectionRevision, ProviderInstanceId, ProviderInstanceManifest, ProviderSecretSet,
};

/// Boxed future returned by provider manifest repository operations.
pub type ProviderRepositoryFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ProviderRepositoryError>> + Send + 'a>>;

/// Decrypted instance manifest returned only at its trusted adapter boundary.
pub struct ProviderInstanceRecord {
    manifest: ProviderInstanceManifest,
    secrets: ProviderSecretSet,
}

impl ProviderInstanceRecord {
    /// Binds an immutable manifest to its exact validated plaintext secret set.
    ///
    /// # Errors
    ///
    /// Rejects secret evidence belonging to another manifest revision.
    pub fn new(
        manifest: ProviderInstanceManifest,
        secrets: ProviderSecretSet,
    ) -> Result<Self, ProviderRepositoryError> {
        if !secrets.matches(manifest.secrets()) {
            return Err(ProviderRepositoryError::SecretCustody);
        }
        Ok(Self { manifest, secrets })
    }

    /// Returns the immutable instance manifest.
    #[must_use]
    pub const fn manifest(&self) -> &ProviderInstanceManifest {
        &self.manifest
    }

    /// Returns the exact plaintext secret set.
    #[must_use]
    pub const fn secrets(&self) -> &ProviderSecretSet {
        &self.secrets
    }

    /// Consumes the record into manifest and secret custody values.
    #[must_use]
    pub fn into_parts(self) -> (ProviderInstanceManifest, ProviderSecretSet) {
        (self.manifest, self.secrets)
    }
}

impl fmt::Debug for ProviderInstanceRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderInstanceRecord")
            .field("manifest", &self.manifest)
            .field("secrets", &self.secrets)
            .finish()
    }
}

/// Result of atomically storing an immutable revision and advancing its pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderSaveOutcome {
    /// A new contiguous revision became current.
    Inserted,
    /// The exact current revision was already durable.
    Unchanged,
}

/// Durable repository for provider instance and connection manifests.
pub trait ProviderManifestRepository: fmt::Debug + Send + Sync {
    /// Atomically stores one first or contiguous instance revision.
    ///
    /// A secret name newly present in the adjacent revision must use one more
    /// than its largest historical generation, or generation one if unseen.
    fn save_instance(
        &self,
        record: ProviderInstanceRecord,
    ) -> ProviderRepositoryFuture<'_, ProviderSaveOutcome>;

    /// Loads and decrypts one exact historical instance revision.
    fn load_instance(
        &self,
        instance_id: ProviderInstanceId,
        revision: ProviderConfigurationRevision,
    ) -> ProviderRepositoryFuture<'_, Option<ProviderInstanceRecord>>;

    /// Loads and decrypts the current instance revision.
    fn current_instance(
        &self,
        instance_id: ProviderInstanceId,
    ) -> ProviderRepositoryFuture<'_, Option<ProviderInstanceRecord>>;

    /// Atomically stores one first or contiguous connection revision.
    fn save_connection(
        &self,
        manifest: ProviderConnectionManifest,
    ) -> ProviderRepositoryFuture<'_, ProviderSaveOutcome>;

    /// Loads one exact historical connection revision.
    fn load_connection(
        &self,
        connection_id: ProviderConnectionId,
        revision: ProviderConnectionRevision,
    ) -> ProviderRepositoryFuture<'_, Option<ProviderConnectionManifest>>;

    /// Loads the current connection revision.
    fn current_connection(
        &self,
        connection_id: ProviderConnectionId,
    ) -> ProviderRepositoryFuture<'_, Option<ProviderConnectionManifest>>;
}

/// Sanitized durable provider repository failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderRepositoryError {
    /// A revision was stale, noncontiguous, or disagreed with durable content.
    #[error("provider manifest revision conflicts with durable state")]
    Conflict,
    /// Required referenced durable state was absent.
    #[error("provider manifest reference does not exist")]
    NotFound,
    /// Durable bytes violated the provider model.
    #[error("provider manifest storage is corrupt")]
    Corrupt,
    /// Encryption, decryption, or plaintext binding validation failed.
    #[error("provider secret custody failed")]
    SecretCustody,
    /// The durable repository was unavailable.
    #[error("provider manifest repository is unavailable")]
    Unavailable,
}
