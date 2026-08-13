//! Crate-internal product composition used by deterministic conformance adapters.
//!
//! This module has no CLI/configuration entry point. Production builders keep
//! their system defaults; an adapter must construct this factory explicitly with a
//! derived shard plan, a bounded fault plan, and an exact GitHub script.

use std::sync::Arc;

use automata_ci_auth::secret::SecretString;
use automata_ci_blob::ImmutableBlobStore;
use automata_ci_conformance::{FaultPlan, GithubStubScript, ShardPlan};
use automata_ci_credential::RepositoryCredentialBroker;
use automata_ci_github::{GithubHttpEndpoint, GithubHttpLimits};
use automata_ci_github_delivery::GithubChecksCredentialProvider;
use automata_ci_results_github::{
    ArtifactRepository, ArtifactService, ResultsClock, ResultsIdGenerator, ResultsLimits,
};
use automata_ci_runner_runtime::RunnerRuntimeControlClient;
use automata_ci_scm::RepositorySourcePort;
use automata_ci_store::LogicalWorkflowAdmissionRepository;
use automata_ci_workflow_service::{
    AdmissionClock, Sha256AdmissionIdGenerator, WorkflowAdmissionService, WorkflowPlanVerifier,
};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use crate::server::{GithubProviderRuntimeBuilder, GithubProviderRuntimeClocks};

use super::{
    conformance_control::{
        ProductConformanceAdapterError, ProductConformanceAdapters, ProductConformanceClock,
    },
    conformance_fault_ports::{
        ConformanceArtifactRepository, ConformanceBlobStore,
        ConformanceGithubChecksCredentialProvider, ConformanceRepositoryCredentialBroker,
        ConformanceRepositorySource, ConformanceRunnerControlClient,
    },
    conformance_github_stub::{HermeticGithubStubError, HermeticGithubStubServer},
    conformance_shard::{ConformanceShardAdapterError, ProductConformanceShard},
};

const CONFORMANCE_GITHUB_USER_AGENT: &str =
    concat!("automata-ci-conformance/", env!("CARGO_PKG_VERSION"));

/// One explicit product-internal conformance aggregate.
pub struct ProductConformanceComposition {
    adapters: ProductConformanceAdapters,
    github: ProductConformanceGithub,
}

impl ProductConformanceComposition {
    /// Selects one shard, starts its held-listener GitHub server, and builds the
    /// real hardened product HTTP client against that exact origin.
    ///
    /// # Errors
    ///
    /// Returns an error when the shard selection, scoped credential, listener
    /// handoff, stub startup, or hardened GitHub endpoint construction fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn start(
        initial_millis: i64,
        fault_plan: Arc<FaultPlan>,
        shard_plan: &ShardPlan,
        ordinal: u16,
        github_script: GithubStubScript,
        credential_local_id: &str,
        github_token: SecretString,
    ) -> Result<Self, ProductConformanceCompositionError> {
        let adapters =
            ProductConformanceAdapters::for_shard(initial_millis, fault_plan, shard_plan, ordinal)?;
        let mut authorization = Zeroizing::new(format!("Bearer {}", github_token.expose_secret()));
        let authorization = SecretString::new(std::mem::take(&mut *authorization))
            .map_err(|_| ProductConformanceCompositionError::InvalidGithubCredential)?;
        let credential = adapters
            .shard()
            .hermetic_github_credential(credential_local_id, authorization)?;
        let reservation = adapters
            .shard()
            .reserve_loopback_port("github-stub")
            .await?;
        let server = HermeticGithubStubServer::start_with_listener(
            reservation.into_listener(),
            github_script,
            vec![credential],
        )?;
        let mut oauth_origin = Url::parse(server.origin())
            .map_err(|_| ProductConformanceCompositionError::InvalidGithubEndpoint)?;
        oauth_origin.set_path("/");
        let mut api_base = oauth_origin.clone();
        api_base.set_path("/api/");
        let endpoint = GithubHttpEndpoint::new_for_loopback_emulator(
            oauth_origin,
            api_base,
            CONFORMANCE_GITHUB_USER_AGENT,
            GithubHttpLimits::default(),
        )
        .map_err(|_| ProductConformanceCompositionError::InvalidGithubEndpoint)?;
        Ok(Self {
            adapters,
            github: ProductConformanceGithub {
                endpoint,
                token: github_token,
                server,
            },
        })
    }

    /// Returns the single manual clock shared by the composed product ports.
    pub const fn clock(&self) -> &ProductConformanceClock {
        self.adapters.clock()
    }

    /// Returns the selected product provisioning shard.
    pub const fn shard(&self) -> &ProductConformanceShard {
        self.adapters.shard()
    }

    /// Returns the hardened product GitHub endpoint configured for the loopback stub.
    pub fn github_endpoint(&self) -> &GithubHttpEndpoint {
        &self.github.endpoint
    }

    /// Returns the redacting credential used by the composed GitHub client.
    pub fn github_token(&self) -> &SecretString {
        &self.github.token
    }

    /// Wraps the real GitHub repository source client at its typed fault site.
    pub fn github_repository_source(&self) -> Arc<dyn RepositorySourcePort> {
        let source: Arc<dyn RepositorySourcePort> = Arc::new(self.github.endpoint.clone());
        Arc::new(ConformanceRepositorySource::new(
            source,
            Arc::clone(self.adapters.faults()),
        ))
    }

    /// Installs shard translation first and the object fault boundary directly
    /// around the product-facing port.
    ///
    /// # Errors
    ///
    /// Returns an error when the selected shard cannot construct a transparent,
    /// isolated object-store namespace over `store`.
    pub fn objects<Store>(
        &self,
        store: Store,
    ) -> Result<ProductConformanceObjects, ProductConformanceCompositionError>
    where
        Store: ImmutableBlobStore + 'static,
    {
        let scoped: Arc<dyn ImmutableBlobStore> =
            Arc::new(self.adapters.shard().blob_store(store)?);
        Ok(ProductConformanceObjects(Arc::new(
            ConformanceBlobStore::new(scoped, Arc::clone(self.adapters.faults())),
        )))
    }

    /// Composes the actual workflow-admission service with deterministic time
    /// and the factory's already-scoped/faulted object port.
    pub fn workflow_admission(
        &self,
        objects: &ProductConformanceObjects,
        repository: Arc<dyn LogicalWorkflowAdmissionRepository>,
        verifier: Arc<dyn WorkflowPlanVerifier>,
    ) -> WorkflowAdmissionService {
        let clock: Arc<dyn AdmissionClock> = Arc::new(self.adapters.clock().clone());
        WorkflowAdmissionService::new(
            Arc::clone(&objects.0),
            repository,
            verifier,
            Arc::new(Sha256AdmissionIdGenerator),
            clock,
        )
    }

    /// Composes the actual Results artifact service with deterministic time and
    /// independent metadata/object fault boundaries.
    pub fn artifact_service(
        &self,
        objects: &ProductConformanceObjects,
        repository: Arc<dyn ArtifactRepository>,
        ids: Arc<dyn ResultsIdGenerator>,
        limits: ResultsLimits,
    ) -> ArtifactService {
        let repository: Arc<dyn ArtifactRepository> = Arc::new(ConformanceArtifactRepository::new(
            repository,
            Arc::clone(self.adapters.faults()),
        ));
        let clock: Arc<dyn ResultsClock> = Arc::new(self.adapters.clock().clone());
        ArtifactService::new(repository, Arc::clone(&objects.0), clock, ids, limits)
    }

    /// Wraps a repository credential broker with the exact token-issuance fault site.
    pub fn repository_credentials(
        &self,
        broker: Arc<dyn RepositoryCredentialBroker>,
    ) -> Arc<dyn RepositoryCredentialBroker> {
        Arc::new(ConformanceRepositoryCredentialBroker::new(
            broker,
            Arc::clone(self.adapters.faults()),
        ))
    }

    /// Wraps the GitHub Checks credential boundary with its independent fault site.
    pub fn checks_credentials(
        &self,
        provider: Arc<dyn GithubChecksCredentialProvider>,
    ) -> Arc<dyn GithubChecksCredentialProvider> {
        Arc::new(ConformanceGithubChecksCredentialProvider::new(
            provider,
            Arc::clone(self.adapters.faults()),
        ))
    }

    /// Wraps a runner control client with handshake and synchronized-operation fault sites.
    pub fn runner_control(
        &self,
        client: Arc<dyn RunnerRuntimeControlClient>,
    ) -> Arc<dyn RunnerRuntimeControlClient> {
        Arc::new(ConformanceRunnerControlClient::new(
            client,
            Arc::clone(self.adapters.faults()),
        ))
    }

    fn provider_clocks(&self) -> GithubProviderRuntimeClocks {
        let clock = Arc::new(self.adapters.clock().clone());
        GithubProviderRuntimeClocks::new(clock.clone(), clock.clone(), clock.clone(), clock)
    }

    /// Installs the same manual clock into provider delivery, schedule,
    /// credential, runtime-authority, and Checks publication paths.
    #[must_use]
    pub fn configure_github_runtime(
        &self,
        builder: GithubProviderRuntimeBuilder,
    ) -> GithubProviderRuntimeBuilder {
        builder.with_clocks(self.provider_clocks())
    }

    /// Stops the hermetic server and proves that the exact script was consumed.
    ///
    /// # Errors
    ///
    /// Returns an error when the server observed a protocol mismatch or any
    /// scripted exchange remains unconsumed.
    pub async fn finish(self) -> Result<(), ProductConformanceCompositionError> {
        self.github.server.finish().await?;
        Ok(())
    }
}

impl std::fmt::Debug for ProductConformanceComposition {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductConformanceComposition")
            .field("adapters", &self.adapters)
            .field("github", &self.github)
            .finish()
    }
}

struct ProductConformanceGithub {
    endpoint: GithubHttpEndpoint,
    token: SecretString,
    server: HermeticGithubStubServer,
}

impl std::fmt::Debug for ProductConformanceGithub {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductConformanceGithub")
            .field("endpoint", &"[LOOPBACK PRODUCT CLIENT]")
            .field("token", &self.token)
            .field("server", &self.server)
            .finish()
    }
}

/// Opaque proof that an object port has both shard translation and fault gates.
pub struct ProductConformanceObjects(Arc<dyn ImmutableBlobStore>);

impl std::fmt::Debug for ProductConformanceObjects {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProductConformanceObjects([configured])")
    }
}

/// Sanitized failure to build or finish explicit conformance composition.
#[derive(Debug, Error)]
pub enum ProductConformanceCompositionError {
    /// The clock, fault plan, or selected shard was invalid.
    #[error("the product conformance adapters are invalid")]
    Adapter(#[from] ProductConformanceAdapterError),
    /// Provisioning a selected shard resource failed.
    #[error("the product conformance shard adapter failed")]
    Shard(#[from] ConformanceShardAdapterError),
    /// The supplied GitHub credential could not be represented safely.
    #[error("the product conformance GitHub credential is invalid")]
    InvalidGithubCredential,
    /// The held loopback listener could not form a hardened GitHub endpoint.
    #[error("the product conformance GitHub endpoint is invalid")]
    InvalidGithubEndpoint,
    /// The exact-order loopback GitHub server failed.
    #[error("the product conformance GitHub stub failed")]
    GithubStub(#[from] HermeticGithubStubError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::GithubProviderConfig;
    use async_trait::async_trait;
    use automata_ci_auth::github::{GithubCurrentUserRequest, GithubEndpoint as _};
    use automata_ci_blob::{BlobKey, BlobPayload, BlobStoreErrorKind, MediaType, MemoryBlobStore};
    use automata_ci_conformance::{
        DurableTransition, FaultMode, FaultOperation, GithubStubExchange, GithubStubRequest,
        GithubStubResponse,
    };
    use automata_ci_credential::{
        CredentialError, CredentialErrorKind, IssuedRepositoryCredential,
        RepositoryCredentialRequest,
    };
    use automata_ci_github_delivery::{
        GithubChecksCredentialProviderError, GithubChecksCredentialRequest,
        GithubChecksServerServiceCredential,
    };
    use automata_ci_key_management::{
        KeyEncryptionProvider, KeyId, LocalAes256GcmKeyring, LocalKeyMaterial, SecretBytes,
    };
    use automata_ci_results_github::{PostgresArtifactRepository, SystemResultsIdGenerator};
    use automata_ci_runner_runtime::{
        RuntimeControlError, RuntimeControlErrorKind, RuntimeControlFuture, RuntimeControlRetry,
    };
    use automata_ci_runner_transport::PreparedRequest;
    use automata_ci_scm::ScmProviderId;
    use automata_ci_store::PostgresStore;
    use automata_ci_workflow_service::GithubWorkflowPlanVerifier;
    use bytes::Bytes;
    use sqlx::postgres::PgPoolOptions;
    use tokio_util::sync::CancellationToken;

    #[derive(Debug)]
    struct UnavailableRepositoryCredentialBroker(ScmProviderId);

    #[async_trait]
    impl RepositoryCredentialBroker for UnavailableRepositoryCredentialBroker {
        fn provider_id(&self) -> &ScmProviderId {
            &self.0
        }

        async fn issue(
            &self,
            _request: &RepositoryCredentialRequest,
        ) -> Result<IssuedRepositoryCredential, CredentialError> {
            Err(CredentialError::new(CredentialErrorKind::Unavailable))
        }
    }

    #[derive(Debug)]
    struct UnavailableChecksCredentials;

    #[async_trait]
    impl GithubChecksCredentialProvider for UnavailableChecksCredentials {
        async fn acquire(
            &self,
            _request: GithubChecksCredentialRequest<'_>,
        ) -> Result<GithubChecksServerServiceCredential, GithubChecksCredentialProviderError>
        {
            Err(GithubChecksCredentialProviderError::Unavailable)
        }
    }

    #[derive(Debug)]
    struct UnavailableRunnerControl;

    impl RunnerRuntimeControlClient for UnavailableRunnerControl {
        fn exchange<'a>(
            &'a self,
            _request: &'a PreparedRequest,
            _cancellation: CancellationToken,
        ) -> RuntimeControlFuture<'a> {
            Box::pin(async {
                Err(RuntimeControlError::new(
                    RuntimeControlErrorKind::Unavailable,
                    RuntimeControlRetry::SamePreparedRequest,
                ))
            })
        }
    }

    fn assert_internal_product_ports(
        composition: &ProductConformanceComposition,
        objects: &ProductConformanceObjects,
    ) {
        let source = composition.github_repository_source();
        assert_eq!(source.provider_id().as_str(), "github");

        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .expect("syntactically valid lazy PostgreSQL pool");
        let store = Arc::new(PostgresStore::from_postgres_pool(pool.clone()));
        let _workflow = composition.workflow_admission(
            objects,
            store.clone(),
            Arc::new(GithubWorkflowPlanVerifier::new()),
        );
        let _artifacts = composition.artifact_service(
            objects,
            Arc::new(PostgresArtifactRepository::new(pool)),
            Arc::new(SystemResultsIdGenerator),
            ResultsLimits::default(),
        );

        let credential_provider = ScmProviderId::new("github").expect("provider");
        let repository_credentials = composition.repository_credentials(Arc::new(
            UnavailableRepositoryCredentialBroker(credential_provider.clone()),
        ));
        assert_eq!(repository_credentials.provider_id(), &credential_provider);
        let checks_credentials =
            composition.checks_credentials(Arc::new(UnavailableChecksCredentials));
        assert!(format!("{checks_credentials:?}").contains("Conformance"));
        let runner_control = composition.runner_control(Arc::new(UnavailableRunnerControl));
        assert!(format!("{runner_control:?}").contains("Conformance"));

        let active_key = LocalKeyMaterial::new(
            KeyId::new("conformance-provider-builder-v1").expect("key ID"),
            SecretBytes::new(vec![0x5a; 32]).expect("key bytes"),
        )
        .expect("local key material");
        let keyring: Arc<dyn KeyEncryptionProvider> = Arc::new(
            LocalAes256GcmKeyring::new(active_key, Vec::new(), Vec::new()).expect("local keyring"),
        );
        let config = GithubProviderConfig::parse_for_test(include_bytes!(
            "../../config/github-provider.example.json"
        ))
        .expect("strict provider fixture");
        let builder = GithubProviderRuntimeBuilder::new(
            config,
            SecretString::new("unused-test-private-key").expect("test key"),
            Zeroizing::new(b"unused-test-webhook-secret".to_vec()),
            keyring,
            store,
            Arc::new(MemoryBlobStore::default()),
        );
        assert!(format!("{builder:?}").contains("explicit_clocks: false"));
        let builder = composition.configure_github_runtime(builder);
        assert!(format!("{builder:?}").contains("explicit_clocks: true"));
    }

    #[tokio::test]
    async fn factory_uses_shard_listener_scoped_credential_real_client_and_product_ports() {
        let run = format!("composition-factory-{}", std::process::id());
        let shards = ShardPlan::derive(&run, 1).expect("shard plan");
        let expected_credential = format!(
            "{}:provider",
            shards.shard(0).expect("shard").credential_scope()
        );
        let script = GithubStubScript::new(vec![GithubStubExchange {
            request: GithubStubRequest {
                method: "GET".to_owned(),
                path_and_query: "/api/user".to_owned(),
                body_sha256: None,
                credential_id: Some(expected_credential),
            },
            response: GithubStubResponse::Page {
                status: 200,
                body: br#"{"id":42,"login":"octocat","name":"Mona"}"#.to_vec(),
                next: None,
            },
        }])
        .expect("GitHub script");
        let faults = Arc::new(
            FaultPlan::new([(
                FaultOperation::ObjectWrite,
                DurableTransition::Provisioned,
                FaultMode::Unavailable,
            )])
            .expect("fault plan"),
        );
        let composition = ProductConformanceComposition::start(
            10_000,
            faults,
            &shards,
            0,
            script,
            "provider",
            SecretString::new("fixture-token").expect("token"),
        )
        .await
        .expect("product conformance composition");
        assert_eq!(
            composition.shard().identity(),
            shards.shard(0).expect("selected shard")
        );
        let debug = format!("{composition:?}");
        assert!(!debug.contains("fixture-token"));
        assert!(debug.contains("[REDACTED]"));

        let user = composition
            .github_endpoint()
            .current_user(GithubCurrentUserRequest {
                access_token: composition.github_token(),
            })
            .await
            .expect("real product GitHub client response");
        assert_eq!(user.id, 42);
        assert_eq!(user.login, "octocat");

        let objects = composition
            .objects(MemoryBlobStore::default())
            .expect("product object port");
        let payload = BlobPayload::from_bytes(
            BlobKey::new("results/v7/manifests/test").expect("ordinary Results key"),
            MediaType::new("application/json").expect("media type"),
            Bytes::from_static(b"{}"),
        );
        let descriptor = payload.descriptor().clone();
        let first = objects
            .0
            .put_if_absent(payload.clone())
            .await
            .expect_err("scripted object write fault");
        assert_eq!(first.kind(), BlobStoreErrorKind::Unavailable);
        objects
            .0
            .put_if_absent(payload)
            .await
            .expect("fault is one-shot and the real scoped port delegates");
        let verified = objects
            .0
            .get_verified(&descriptor, descriptor.size())
            .await
            .expect("logical descriptor round trip");
        assert_eq!(verified.descriptor(), &descriptor);
        assert_internal_product_ports(&composition, &objects);

        let clocks = composition.provider_clocks();
        assert_eq!(clocks.delivery.now().get(), 10_000);
        assert_eq!(clocks.credential.now().get(), 10_000);
        assert_eq!(clocks.schedule.now().expect("schedule clock").get(), 10_000);
        assert_eq!(clocks.runtime_authority.now().get(), 10_000);
        composition.clock().advance(250).expect("manual advance");
        assert_eq!(clocks.delivery.now().get(), 10_250);
        assert_eq!(clocks.credential.now().get(), 10_250);
        assert_eq!(clocks.schedule.now().expect("schedule clock").get(), 10_250);
        assert_eq!(clocks.runtime_authority.now().get(), 10_250);

        composition
            .finish()
            .await
            .expect("exact GitHub script consumed");
    }
}
