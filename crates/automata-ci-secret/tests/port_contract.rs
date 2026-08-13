use std::{
    future::Future,
    sync::{
        LazyLock,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
};

use async_trait::async_trait;
use automata_ci_secret::{
    CreateSecretVersionRequest, CreatedSecretVersion, DestroySecretVersionRequest,
    ProviderCapabilities, ProviderCapability, ProviderError, ProviderErrorKind, ProviderHealth,
    ProviderOperationContext, ProviderRequestId, ProviderSecretLocator, ProviderVersionId,
    ReconcileCreateSecretVersionRequest, RepositoryScopeId, ResolveSecretVersionRequest,
    ResolvedSecretVersion, SecretAtRestProtection, SecretDescriptor, SecretId, SecretName,
    SecretProvider, SecretProviderId, SecretScope, TenantScopeId,
};

#[derive(Debug)]
struct DefaultReconciliationProvider {
    id: SecretProviderId,
    create_calls: AtomicUsize,
}

impl DefaultReconciliationProvider {
    fn new() -> Self {
        Self {
            id: SecretProviderId::new("default-reconciliation").expect("provider ID"),
            create_calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl SecretProvider for DefaultReconciliationProvider {
    fn provider_id(&self) -> &SecretProviderId {
        &self.id
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        static CAPABILITIES: LazyLock<ProviderCapabilities> =
            LazyLock::new(ProviderCapabilities::default);
        &CAPABILITIES
    }

    fn at_rest_protection(&self) -> SecretAtRestProtection {
        SecretAtRestProtection::ProviderManagedEncryption
    }

    async fn health(
        &self,
        _context: &ProviderOperationContext,
    ) -> Result<ProviderHealth, ProviderError> {
        Ok(ProviderHealth::Healthy)
    }

    async fn create_version(
        &self,
        _request: CreateSecretVersionRequest,
    ) -> Result<CreatedSecretVersion, ProviderError> {
        self.create_calls.fetch_add(1, Ordering::Relaxed);
        Err(ProviderError::unsupported())
    }

    async fn resolve_version(
        &self,
        _request: ResolveSecretVersionRequest,
    ) -> Result<ResolvedSecretVersion, ProviderError> {
        Err(ProviderError::unsupported())
    }

    async fn destroy_version(
        &self,
        _request: DestroySecretVersionRequest,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::unsupported())
    }
}

fn poll_immediately_ready<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    let mut future = Box::pin(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("default provider reconciliation unexpectedly yielded"),
    }
}

fn reconciliation_request() -> ReconcileCreateSecretVersionRequest {
    let tenant_id = TenantScopeId::new("tenant-a").expect("tenant ID");
    ReconcileCreateSecretVersionRequest::new(
        ProviderOperationContext::new(
            tenant_id.clone(),
            ProviderRequestId::new("durable-create-request").expect("request ID"),
        ),
        SecretDescriptor::new(
            SecretId::new("secret-a").expect("secret ID"),
            SecretName::new("DEPLOY_TOKEN").expect("secret name"),
            SecretScope::repository(
                tenant_id,
                RepositoryScopeId::new("repository-a").expect("repository ID"),
            ),
        ),
        Some(automata_ci_secret::ExistingSecretVersion::new(
            ProviderSecretLocator::new("opaque-locator").expect("locator"),
            ProviderVersionId::new("opaque-version").expect("version"),
        )),
    )
    .expect("reconciliation request")
}

#[test]
fn default_reconciliation_is_closed_and_never_delegates_to_create() {
    let provider = DefaultReconciliationProvider::new();
    let erased: &dyn SecretProvider = &provider;
    assert!(
        !erased
            .capabilities()
            .supports(ProviderCapability::ReconcileCreateVersion)
    );

    for _ in 0..2 {
        let error =
            poll_immediately_ready(erased.reconcile_create_version(reconciliation_request()))
                .expect_err("default reconciliation must fail closed");
        assert_eq!(error.kind(), ProviderErrorKind::Unsupported);
    }
    assert_eq!(provider.create_calls.load(Ordering::Relaxed), 0);
}
