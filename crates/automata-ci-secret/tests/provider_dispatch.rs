#![forbid(unsafe_code)]

use std::{
    fmt,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
};

use async_trait::async_trait;
use automata_ci_secret::{
    CreateSecretVersionRequest, CreatedSecretVersion, DestroySecretVersionRequest,
    ExistingSecretVersion, ProviderCapabilities, ProviderCapability, ProviderError,
    ProviderErrorKind, ProviderHealth, ProviderLease, ProviderLeaseExpiration, ProviderLeaseId,
    ProviderOperationContext, ProviderRequestId, ProviderSecretLocator, ProviderVersionId,
    ReconcileCreateSecretVersionOutcome, ReconcileCreateSecretVersionRequest,
    RenewProviderLeaseRequest, RevokeProviderLeaseRequest, SecretAtRestProtection,
    SecretDescriptor, SecretId, SecretName, SecretProvider, SecretProviderDispatchError,
    SecretProviderId, SecretProviderRegistry, SecretScope, SecretValue, TenantScopeId,
    WorkloadContext, WorkloadId,
};

#[derive(Default)]
struct ProviderCalls {
    health: AtomicUsize,
    create: AtomicUsize,
    reconcile: AtomicUsize,
    resolve: AtomicUsize,
    destroy: AtomicUsize,
    renew: AtomicUsize,
    revoke: AtomicUsize,
}

struct FakeProvider {
    id: SecretProviderId,
    capabilities: ProviderCapabilities,
    calls: Arc<ProviderCalls>,
    failure: Option<ProviderError>,
}

impl fmt::Debug for FakeProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FakeProvider(configuration=must-not-appear)")
    }
}

#[async_trait]
impl SecretProvider for FakeProvider {
    fn provider_id(&self) -> &SecretProviderId {
        &self.id
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }

    fn at_rest_protection(&self) -> SecretAtRestProtection {
        SecretAtRestProtection::ProviderManagedEncryption
    }

    async fn health(
        &self,
        context: &ProviderOperationContext,
    ) -> Result<ProviderHealth, ProviderError> {
        self.calls.health.fetch_add(1, Ordering::Relaxed);
        assert_eq!(context.request_id().as_str(), "request-health");
        self.failure.map_or(Ok(ProviderHealth::Healthy), Err)
    }

    async fn create_version(
        &self,
        request: CreateSecretVersionRequest,
    ) -> Result<CreatedSecretVersion, ProviderError> {
        self.calls.create.fetch_add(1, Ordering::Relaxed);
        assert_eq!(request.context().request_id().as_str(), "request-create");
        assert_eq!(request.value().expose_secret(), b"create-secret");
        match self.failure {
            Some(error) => Err(error),
            None => Ok(created_version()),
        }
    }

    async fn reconcile_create_version(
        &self,
        request: ReconcileCreateSecretVersionRequest,
    ) -> Result<ReconcileCreateSecretVersionOutcome, ProviderError> {
        self.calls.reconcile.fetch_add(1, Ordering::Relaxed);
        assert_eq!(request.context().request_id().as_str(), "request-reconcile");
        match self.failure {
            Some(error) => Err(error),
            None => Ok(ReconcileCreateSecretVersionOutcome::AlreadyCommitted(
                created_version(),
            )),
        }
    }

    async fn resolve_version(
        &self,
        request: automata_ci_secret::ResolveSecretVersionRequest,
    ) -> Result<automata_ci_secret::ResolvedSecretVersion, ProviderError> {
        self.calls.resolve.fetch_add(1, Ordering::Relaxed);
        assert_eq!(request.context().request_id().as_str(), "request-resolve");
        match self.failure {
            Some(error) => Err(error),
            None => Ok(automata_ci_secret::ResolvedSecretVersion::new(
                SecretValue::from_utf8("resolved-secret".to_owned()).expect("secret value"),
                ProviderVersionId::new(request.version().as_str().to_owned()).expect("version ID"),
                None,
            )),
        }
    }

    async fn destroy_version(
        &self,
        request: DestroySecretVersionRequest,
    ) -> Result<(), ProviderError> {
        self.calls.destroy.fetch_add(1, Ordering::Relaxed);
        assert_eq!(request.context().request_id().as_str(), "request-destroy");
        self.failure.map_or(Ok(()), Err)
    }

    async fn renew_lease(
        &self,
        request: RenewProviderLeaseRequest,
    ) -> Result<ProviderLease, ProviderError> {
        self.calls.renew.fetch_add(1, Ordering::Relaxed);
        assert_eq!(request.context().request_id().as_str(), "request-renew");
        match self.failure {
            Some(error) => Err(error),
            None => Ok(provider_lease()),
        }
    }

    async fn revoke_lease(&self, request: RevokeProviderLeaseRequest) -> Result<(), ProviderError> {
        self.calls.revoke.fetch_add(1, Ordering::Relaxed);
        assert_eq!(request.context().request_id().as_str(), "request-revoke");
        self.failure.map_or(Ok(()), Err)
    }
}

struct ProviderFixture {
    id: SecretProviderId,
    adapter: Arc<dyn SecretProvider>,
    calls: Arc<ProviderCalls>,
}

impl ProviderFixture {
    fn new(id: &str, capabilities: &[ProviderCapability], failure: Option<ProviderError>) -> Self {
        let id = SecretProviderId::new(id).expect("provider ID");
        let calls = Arc::new(ProviderCalls::default());
        let adapter: Arc<dyn SecretProvider> = Arc::new(FakeProvider {
            id: id.clone(),
            capabilities: ProviderCapabilities::new(capabilities.iter().copied())
                .expect("capabilities"),
            calls: Arc::clone(&calls),
            failure,
        });
        Self { id, adapter, calls }
    }
}

#[test]
fn health_routes_only_to_the_exact_provider_without_default_fallback() {
    let default = ProviderFixture::new("default", &[], None);
    let target = ProviderFixture::new("target", &[], None);
    let registry = registry(&default, [&target]);

    let health =
        ready(registry.dispatch_health(&target.id, &context("health"))).expect("target health");
    assert_eq!(health, ProviderHealth::Healthy);
    assert_eq!(target.calls.health.load(Ordering::Relaxed), 1);
    assert_eq!(default.calls.health.load(Ordering::Relaxed), 0);

    let missing = SecretProviderId::new("missing-provider").expect("missing ID");
    assert_eq!(
        ready(registry.dispatch_health(&missing, &context("health"))),
        Err(SecretProviderDispatchError::Rejected)
    );
    assert_eq!(default.calls.health.load(Ordering::Relaxed), 0);
    assert_eq!(target.calls.health.load(Ordering::Relaxed), 1);
}

#[test]
fn create_preflights_capability_and_moves_plaintext_once() {
    let unavailable = ProviderFixture::new("unavailable", &[], None);
    let capable = ProviderFixture::new("capable", &[ProviderCapability::CreateVersion], None);
    let registry = registry(&unavailable, [&capable]);

    let created = ready(registry.dispatch_create_version(&capable.id, create_request()))
        .expect("created version");
    assert_eq!(created.locator().as_str(), "created-locator");
    assert_eq!(created.version().as_str(), "created-version");
    assert_eq!(capable.calls.create.load(Ordering::Relaxed), 1);

    assert_eq!(
        ready(registry.dispatch_create_version(&unavailable.id, create_request())),
        Err(SecretProviderDispatchError::Rejected)
    );
    assert_eq!(unavailable.calls.create.load(Ordering::Relaxed), 0);
}

#[test]
fn reconciliation_requires_capability_and_never_delegates_to_create() {
    let create_only =
        ProviderFixture::new("create-only", &[ProviderCapability::CreateVersion], None);
    let capable = ProviderFixture::new(
        "reconciling",
        &[
            ProviderCapability::CreateVersion,
            ProviderCapability::ReconcileCreateVersion,
        ],
        None,
    );
    let registry = registry(&create_only, [&capable]);

    let reconciled =
        ready(registry.dispatch_reconcile_create_version(&capable.id, reconcile_request()))
            .expect("reconciled version");
    assert!(matches!(
        reconciled,
        ReconcileCreateSecretVersionOutcome::AlreadyCommitted(_)
    ));
    assert_eq!(capable.calls.reconcile.load(Ordering::Relaxed), 1);
    assert_eq!(capable.calls.create.load(Ordering::Relaxed), 0);

    assert_eq!(
        ready(registry.dispatch_reconcile_create_version(&create_only.id, reconcile_request(),)),
        Err(SecretProviderDispatchError::Rejected)
    );
    assert_eq!(create_only.calls.reconcile.load(Ordering::Relaxed), 0);
    assert_eq!(create_only.calls.create.load(Ordering::Relaxed), 0);
}

#[test]
fn resolve_is_mandatory_and_routes_without_an_optional_capability() {
    let provider = ProviderFixture::new("resolver", &[], None);
    let registry = registry(&provider, []);

    let resolved = ready(registry.dispatch_resolve_version(&provider.id, resolve_request()))
        .expect("resolved version");
    assert_eq!(resolved.value().expose_secret(), b"resolved-secret");
    assert_eq!(resolved.version().as_str(), "requested-version");
    assert!(resolved.lease().is_none());
    assert_eq!(provider.calls.resolve.load(Ordering::Relaxed), 1);
}

#[test]
fn destroy_preflights_capability_before_provider_io() {
    let unavailable = ProviderFixture::new("unavailable", &[], None);
    let capable = ProviderFixture::new("destroyer", &[ProviderCapability::DestroyVersion], None);
    let registry = registry(&unavailable, [&capable]);

    ready(registry.dispatch_destroy_version(&capable.id, destroy_request()))
        .expect("destroy version");
    assert_eq!(capable.calls.destroy.load(Ordering::Relaxed), 1);
    assert_eq!(
        ready(registry.dispatch_destroy_version(&unavailable.id, destroy_request())),
        Err(SecretProviderDispatchError::Rejected)
    );
    assert_eq!(unavailable.calls.destroy.load(Ordering::Relaxed), 0);
}

#[test]
fn renewal_preflights_dynamic_lease_capabilities_before_provider_io() {
    let dynamic_only =
        ProviderFixture::new("dynamic-only", &[ProviderCapability::DynamicLeases], None);
    let capable = ProviderFixture::new(
        "renewer",
        &[
            ProviderCapability::DynamicLeases,
            ProviderCapability::RenewLeases,
        ],
        None,
    );
    let registry = registry(&dynamic_only, [&capable]);

    let renewed =
        ready(registry.dispatch_renew_lease(&capable.id, renew_request())).expect("renew lease");
    assert_eq!(renewed.id().as_str(), "renewed-lease");
    assert_eq!(renewed.expires_at().as_unix_seconds(), 20_000);
    assert_eq!(capable.calls.renew.load(Ordering::Relaxed), 1);
    assert_eq!(
        ready(registry.dispatch_renew_lease(&dynamic_only.id, renew_request())),
        Err(SecretProviderDispatchError::Rejected)
    );
    assert_eq!(dynamic_only.calls.renew.load(Ordering::Relaxed), 0);
}

#[test]
fn revocation_preflights_dynamic_lease_capabilities_before_provider_io() {
    let dynamic_only =
        ProviderFixture::new("dynamic-only", &[ProviderCapability::DynamicLeases], None);
    let capable = ProviderFixture::new(
        "revoker",
        &[
            ProviderCapability::DynamicLeases,
            ProviderCapability::RevokeLeases,
        ],
        None,
    );
    let registry = registry(&dynamic_only, [&capable]);

    ready(registry.dispatch_revoke_lease(&capable.id, revoke_request())).expect("revoke lease");
    assert_eq!(capable.calls.revoke.load(Ordering::Relaxed), 1);
    assert_eq!(
        ready(registry.dispatch_revoke_lease(&dynamic_only.id, revoke_request())),
        Err(SecretProviderDispatchError::Rejected)
    );
    assert_eq!(dynamic_only.calls.revoke.load(Ordering::Relaxed), 0);
}

#[test]
fn sanitized_provider_errors_pass_through_without_retry_or_adapter_debug() {
    let failure = ProviderError::retryable(ProviderErrorKind::RateLimited, Some(7));
    let provider = ProviderFixture::new("failing", &[], Some(failure));
    let registry = registry(&provider, []);

    let error = ready(registry.dispatch_health(&provider.id, &context("health")))
        .expect_err("provider failure");
    assert_eq!(error, SecretProviderDispatchError::Provider(failure));
    assert_eq!(provider.calls.health.load(Ordering::Relaxed), 1);
    let diagnostic = format!("{error:?} {error}");
    assert!(!diagnostic.contains("must-not-appear"));
    assert!(!diagnostic.contains("failing"));
}

fn registry<const N: usize>(
    default: &ProviderFixture,
    others: [&ProviderFixture; N],
) -> SecretProviderRegistry {
    SecretProviderRegistry::new(
        default.id.clone(),
        std::iter::once(Arc::clone(&default.adapter)).chain(
            others
                .into_iter()
                .map(|provider| Arc::clone(&provider.adapter)),
        ),
    )
    .expect("provider registry")
}

fn ready<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    let mut future = Box::pin(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("in-memory provider unexpectedly yielded"),
    }
}

fn tenant() -> TenantScopeId {
    TenantScopeId::new("tenant-a").expect("tenant ID")
}

fn scope() -> SecretScope {
    SecretScope::repository(
        tenant(),
        automata_ci_secret::RepositoryScopeId::new("repository-a").expect("repository ID"),
    )
}

fn descriptor() -> SecretDescriptor {
    SecretDescriptor::new(
        SecretId::new("secret-a").expect("secret ID"),
        SecretName::new("DEPLOY_TOKEN").expect("secret name"),
        scope(),
    )
}

fn workload() -> WorkloadContext {
    WorkloadContext::new(WorkloadId::new("workload-a").expect("workload ID"), scope())
        .expect("workload context")
}

fn context(operation: &str) -> ProviderOperationContext {
    ProviderOperationContext::new(
        tenant(),
        ProviderRequestId::new(format!("request-{operation}")).expect("request ID"),
    )
}

fn predecessor() -> ExistingSecretVersion {
    ExistingSecretVersion::new(
        ProviderSecretLocator::new("existing-locator").expect("locator"),
        ProviderVersionId::new("existing-version").expect("version"),
    )
}

fn create_request() -> CreateSecretVersionRequest {
    CreateSecretVersionRequest::new(
        context("create"),
        descriptor(),
        Some(predecessor()),
        SecretValue::from_utf8("create-secret".to_owned()).expect("secret value"),
    )
    .expect("create request")
}

fn reconcile_request() -> ReconcileCreateSecretVersionRequest {
    ReconcileCreateSecretVersionRequest::new(
        context("reconcile"),
        descriptor(),
        Some(predecessor()),
    )
    .expect("reconciliation request")
}

fn resolve_request() -> automata_ci_secret::ResolveSecretVersionRequest {
    automata_ci_secret::ResolveSecretVersionRequest::new(
        context("resolve"),
        workload(),
        descriptor(),
        ProviderSecretLocator::new("requested-locator").expect("locator"),
        ProviderVersionId::new("requested-version").expect("version"),
    )
    .expect("resolve request")
}

fn destroy_request() -> DestroySecretVersionRequest {
    DestroySecretVersionRequest::new(
        context("destroy"),
        descriptor(),
        ProviderSecretLocator::new("destroy-locator").expect("locator"),
        ProviderVersionId::new("destroy-version").expect("version"),
    )
    .expect("destroy request")
}

fn renew_request() -> RenewProviderLeaseRequest {
    RenewProviderLeaseRequest::new(
        context("renew"),
        workload(),
        ProviderLeaseId::new("renew-lease").expect("lease ID"),
    )
    .expect("renew request")
}

fn revoke_request() -> RevokeProviderLeaseRequest {
    RevokeProviderLeaseRequest::new(
        context("revoke"),
        ProviderLeaseId::new("revoke-lease").expect("lease ID"),
    )
}

fn created_version() -> CreatedSecretVersion {
    CreatedSecretVersion::new(
        ProviderSecretLocator::new("created-locator").expect("locator"),
        ProviderVersionId::new("created-version").expect("version"),
    )
}

fn provider_lease() -> ProviderLease {
    ProviderLease::new(
        ProviderLeaseId::new("renewed-lease").expect("lease ID"),
        ProviderLeaseExpiration::from_unix_seconds(20_000).expect("lease expiration"),
    )
}
