//! Provider-neutral configuration application through registered adapter factories.

use std::{fmt, sync::Arc};

use automata_ci_provider::{
    ProviderConfigurationRevision, ProviderConnectionDraft, ProviderFactoryRegistry,
    ProviderFactoryRegistryError, ProviderInstanceDraft, ProviderInstanceId,
    ProviderManifestRepository, ProviderRepositoryError, ProviderSaveOutcome,
};
use thiserror::Error;

/// Validates and atomically applies provider instance and connection revisions.
pub struct ProviderConfigurationService {
    factories: ProviderFactoryRegistry,
    manifests: Arc<dyn ProviderManifestRepository>,
}

impl ProviderConfigurationService {
    /// Composes the complete static adapter registry with canonical durable storage.
    #[must_use]
    pub fn new(
        factories: ProviderFactoryRegistry,
        manifests: Arc<dyn ProviderManifestRepository>,
    ) -> Self {
        Self {
            factories,
            manifests,
        }
    }

    /// Validates and stores one first or contiguous provider-instance revision.
    ///
    /// The capability digest is derived exclusively from the selected adapter.
    ///
    /// # Errors
    ///
    /// Returns a closed factory or repository failure without provider secrets.
    pub async fn apply_instance(
        &self,
        draft: ProviderInstanceDraft,
    ) -> Result<ProviderSaveOutcome, ProviderConfigurationServiceError> {
        let record = self
            .factories
            .materialize_instance(draft)
            .map_err(ProviderConfigurationServiceError::Factory)?;
        self.manifests
            .save_instance(record)
            .await
            .map_err(ProviderConfigurationServiceError::Repository)
    }

    /// Loads the current provider revision, validates a connection draft, and stores it.
    ///
    /// Provider configuration and capability digests are copied from the
    /// current decrypted manifest. The caller's expected revision must match
    /// that pointer, preventing a new connection from selecting credentials
    /// superseded by a provider rotation.
    ///
    /// # Errors
    ///
    /// Rejects absent provider evidence, adapter-policy drift, or repository failure.
    pub async fn apply_connection(
        &self,
        instance_id: ProviderInstanceId,
        provider_revision: ProviderConfigurationRevision,
        draft: ProviderConnectionDraft,
    ) -> Result<ProviderSaveOutcome, ProviderConfigurationServiceError> {
        let record = self
            .manifests
            .current_instance(instance_id)
            .await
            .map_err(ProviderConfigurationServiceError::Repository)?
            .ok_or(ProviderConfigurationServiceError::ProviderNotFound)?;
        if record.manifest().revision() != provider_revision {
            return Err(ProviderConfigurationServiceError::ProviderRevisionNotCurrent);
        }
        let descriptor = self
            .factories
            .build_descriptor(record.manifest().clone(), record.secrets())
            .map_err(ProviderConfigurationServiceError::Factory)?;
        let connection = self
            .factories
            .materialize_connection(&descriptor, draft)
            .map_err(ProviderConfigurationServiceError::Factory)?;
        self.manifests
            .save_connection(connection)
            .await
            .map_err(ProviderConfigurationServiceError::Repository)
    }
}

impl fmt::Debug for ProviderConfigurationService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderConfigurationService")
            .field("factories", &self.factories)
            .field("manifests", &self.manifests)
            .finish()
    }
}

/// Sanitized provider-configuration application failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderConfigurationServiceError {
    /// Static adapter selection or validation rejected the draft.
    #[error("provider configuration validation failed")]
    Factory(#[source] ProviderFactoryRegistryError),
    /// The exact provider revision required by a connection does not exist.
    #[error("provider configuration revision was not found")]
    ProviderNotFound,
    /// The connection selected a provider revision superseded by current state.
    #[error("provider configuration revision is not current")]
    ProviderRevisionNotCurrent,
    /// Durable manifest storage rejected or could not complete the operation.
    #[error("provider configuration repository failed")]
    Repository(#[source] ProviderRepositoryError),
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use automata_ci_core::{Sha256Digest, UnixMillis, WorkspaceId};
    use automata_ci_provider::{
        ExternalRepositoryId, ProviderArchiveLimits, ProviderCapabilities,
        ProviderConfigurationDocument, ProviderConfigurationFactory,
        ProviderConnectionFactoryRequest, ProviderConnectionId, ProviderConnectionManifest,
        ProviderConnectionPolicyDocument, ProviderConnectionRevision, ProviderDefaultBranch,
        ProviderFactoryRequest, ProviderFactoryValidationError, ProviderInstanceManifest,
        ProviderInstanceRecord, ProviderLifecycleState, ProviderOrigins, ProviderRepositoryFuture,
        ProviderRepositoryPath, ProviderRunnerPolicyBinding, ProviderSchemaVersion, ProviderSecret,
        ProviderTypeId, ProviderWorkflowSource, RepositoryVisibility,
    };

    use super::*;

    #[derive(Debug)]
    struct RejectingFactory {
        provider_type: ProviderTypeId,
    }

    impl ProviderConfigurationFactory for RejectingFactory {
        fn provider_type(&self) -> &ProviderTypeId {
            &self.provider_type
        }

        fn validate_instance(
            &self,
            _request: ProviderFactoryRequest<'_>,
        ) -> Result<ProviderCapabilities, ProviderFactoryValidationError> {
            Err(ProviderFactoryValidationError::InvalidConfiguration)
        }

        fn validate_connection(
            &self,
            _request: ProviderConnectionFactoryRequest<'_>,
        ) -> Result<(), ProviderFactoryValidationError> {
            unreachable!("an absent provider revision cannot reach adapter validation")
        }
    }

    #[derive(Debug, Default)]
    struct RecordingRepository {
        instance_saves: AtomicUsize,
        current_instance_loads: Mutex<Vec<ProviderInstanceId>>,
        current_revision: Option<ProviderConfigurationRevision>,
    }

    impl ProviderManifestRepository for RecordingRepository {
        fn save_instance(
            &self,
            _record: ProviderInstanceRecord,
        ) -> ProviderRepositoryFuture<'_, ProviderSaveOutcome> {
            self.instance_saves.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(ProviderSaveOutcome::Inserted) })
        }

        fn load_instance(
            &self,
            _instance_id: ProviderInstanceId,
            _revision: ProviderConfigurationRevision,
        ) -> ProviderRepositoryFuture<'_, Option<ProviderInstanceRecord>> {
            Box::pin(async { Ok(None) })
        }

        fn current_instance(
            &self,
            instance_id: ProviderInstanceId,
        ) -> ProviderRepositoryFuture<'_, Option<ProviderInstanceRecord>> {
            self.current_instance_loads
                .lock()
                .expect("current instance loads")
                .push(instance_id);
            let record = self.current_revision.map(|revision| {
                let manifest = ProviderInstanceManifest::new(
                    instance_id,
                    ProviderTypeId::new("github").expect("provider type"),
                    revision,
                    ProviderLifecycleState::Active,
                    ProviderOrigins::new("https://github.com/", "https://api.github.com/")
                        .expect("origins"),
                    ProviderConfigurationDocument::new(
                        ProviderSchemaVersion::new(1).expect("schema"),
                        b"{}".to_vec(),
                    )
                    .expect("configuration"),
                    automata_ci_provider::ProviderSecretBindings::empty(),
                    Sha256Digest::from_bytes([1; 32]),
                    UnixMillis::new(1_000),
                    Some(UnixMillis::new(1_000)),
                    None,
                )
                .expect("manifest");
                ProviderInstanceRecord::new(
                    manifest,
                    automata_ci_provider::ProviderSecretSet::new(
                        &automata_ci_provider::ProviderSecretBindings::empty(),
                        [],
                    )
                    .expect("secrets"),
                )
                .expect("record")
            });
            Box::pin(async move { Ok(record) })
        }

        fn save_connection(
            &self,
            _manifest: ProviderConnectionManifest,
        ) -> ProviderRepositoryFuture<'_, ProviderSaveOutcome> {
            unreachable!("an absent provider revision cannot save a connection")
        }

        fn load_connection(
            &self,
            _connection_id: ProviderConnectionId,
            _revision: ProviderConnectionRevision,
        ) -> ProviderRepositoryFuture<'_, Option<ProviderConnectionManifest>> {
            Box::pin(async { Ok(None) })
        }

        fn current_connection(
            &self,
            _connection_id: ProviderConnectionId,
        ) -> ProviderRepositoryFuture<'_, Option<ProviderConnectionManifest>> {
            Box::pin(async { Ok(None) })
        }
    }

    fn service(repository: Arc<RecordingRepository>) -> ProviderConfigurationService {
        let factory = Arc::new(RejectingFactory {
            provider_type: ProviderTypeId::new("github").expect("provider type"),
        }) as Arc<dyn ProviderConfigurationFactory>;
        ProviderConfigurationService::new(
            ProviderFactoryRegistry::new([factory]).expect("factory registry"),
            repository,
        )
    }

    #[tokio::test]
    async fn invalid_instance_never_reaches_persistence() {
        let repository = Arc::new(RecordingRepository::default());
        let draft = ProviderInstanceDraft::new(
            ProviderInstanceId::new(),
            ProviderTypeId::new("github").expect("provider type"),
            ProviderConfigurationRevision::new(1).expect("revision"),
            ProviderLifecycleState::Active,
            ProviderOrigins::new("https://github.com/", "https://api.github.com/")
                .expect("origins"),
            ProviderConfigurationDocument::new(
                ProviderSchemaVersion::new(1).expect("schema"),
                b"{}".to_vec(),
            )
            .expect("configuration"),
            Vec::<ProviderSecret>::new(),
            UnixMillis::new(1_000),
            Some(UnixMillis::new(1_000)),
            None,
        )
        .expect("draft");

        assert!(matches!(
            service(Arc::clone(&repository)).apply_instance(draft).await,
            Err(ProviderConfigurationServiceError::Factory(
                ProviderFactoryRegistryError::Validation(
                    ProviderFactoryValidationError::InvalidConfiguration
                )
            ))
        ));
        assert_eq!(repository.instance_saves.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn connection_rejects_a_superseded_provider_revision_before_adapter_work() {
        let repository = Arc::new(RecordingRepository {
            current_revision: Some(
                ProviderConfigurationRevision::new(8).expect("current revision"),
            ),
            ..RecordingRepository::default()
        });
        let instance_id = ProviderInstanceId::new();
        let provider_revision = ProviderConfigurationRevision::new(7).expect("revision");
        let draft = ProviderConnectionDraft::new(
            ProviderConnectionId::new(),
            ProviderConnectionRevision::new(1).expect("connection revision"),
            ProviderLifecycleState::Active,
            WorkspaceId::parse("11111111-1111-4111-8111-111111111111").expect("workspace"),
            ExternalRepositoryId::new("42").expect("repository ID"),
            RepositoryVisibility::Private,
            ProviderDefaultBranch::new("main").expect("branch"),
            ProviderWorkflowSource::Directory(
                ProviderRepositoryPath::new(".ci/workflows").expect("workflow path"),
            ),
            ProviderRunnerPolicyBinding::new(
                ProviderSchemaVersion::new(1).expect("runner schema"),
                Sha256Digest::from_bytes([7; 32]),
            ),
            ProviderArchiveLimits::new(1, 1, 1, 1, 1, 1).expect("archive limits"),
            ProviderConnectionPolicyDocument::new(
                ProviderSchemaVersion::new(1).expect("policy schema"),
                b"{}".to_vec(),
            )
            .expect("policy"),
            UnixMillis::new(1_000),
            Some(UnixMillis::new(1_000)),
            None,
        )
        .expect("connection draft");

        assert_eq!(
            service(Arc::clone(&repository))
                .apply_connection(instance_id, provider_revision, draft)
                .await,
            Err(ProviderConfigurationServiceError::ProviderRevisionNotCurrent)
        );
        assert_eq!(
            *repository
                .current_instance_loads
                .lock()
                .expect("current instance loads"),
            vec![instance_id]
        );
    }
}
