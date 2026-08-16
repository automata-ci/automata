use std::sync::{Arc, LazyLock, atomic::AtomicUsize, atomic::Ordering};
use std::task::{Context, Poll, Waker};
use std::{fmt, future::Future};

use automata_ci_secret::{
    CreateSecretVersionRequest, CreatedSecretVersion, DestroySecretVersionRequest,
    ExistingSecretVersion, ProviderCapabilities, ProviderError, ProviderHealth,
    ProviderOperationContext, ProviderRequestId, ProviderSecretLocator, ProviderVersionId,
    ReconcileCreateSecretVersionRequest, RepositoryScopeId, ResolveSecretVersionRequest,
    ResolvedSecretVersion, SecretAtRestProtection, SecretDescriptor, SecretId, SecretName,
    SecretProvider, SecretProviderId, SecretScope, TenantScopeId,
};

pub(super) struct DefaultMethodProvider {
    id: SecretProviderId,
    create_calls: AtomicUsize,
}

impl DefaultMethodProvider {
    pub(super) fn new(id: &str) -> Self {
        Self {
            id: SecretProviderId::new(id).expect("test provider ID"),
            create_calls: AtomicUsize::new(0),
        }
    }

    pub(super) fn create_call_count(&self) -> usize {
        self.create_calls.load(Ordering::Relaxed)
    }
}

impl fmt::Debug for DefaultMethodProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DefaultMethodProvider(configuration=must-not-appear)")
    }
}

#[async_trait::async_trait]
impl SecretProvider for DefaultMethodProvider {
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

pub(super) fn provider_adapter(id: &str) -> Arc<dyn SecretProvider> {
    Arc::new(DefaultMethodProvider::new(id))
}

pub(super) fn poll_immediately_ready<F: Future>(future: F, pending_message: &str) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    let mut future = Box::pin(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("{pending_message}"),
    }
}

pub(super) fn repository_scope() -> SecretScope {
    let tenant = TenantScopeId::new("tenant-a").expect("tenant ID");
    SecretScope::repository(
        tenant,
        RepositoryScopeId::new("repository-a").expect("repository ID"),
    )
}

pub(super) fn secret_descriptor() -> SecretDescriptor {
    SecretDescriptor::new(
        SecretId::new("secret-a").expect("secret ID"),
        SecretName::new("DEPLOY_TOKEN").expect("secret name"),
        repository_scope(),
    )
}

pub(super) fn provider_context(request_id: &str) -> ProviderOperationContext {
    ProviderOperationContext::new(
        TenantScopeId::new("tenant-a").expect("tenant ID"),
        ProviderRequestId::new(request_id).expect("request ID"),
    )
}

pub(super) fn existing_version(locator: &str, version: &str) -> ExistingSecretVersion {
    ExistingSecretVersion::new(
        ProviderSecretLocator::new(locator).expect("locator"),
        ProviderVersionId::new(version).expect("version"),
    )
}

pub(super) fn reconciliation_request(
    request_id: &str,
    locator: &str,
    version: &str,
) -> ReconcileCreateSecretVersionRequest {
    ReconcileCreateSecretVersionRequest::new(
        provider_context(request_id),
        secret_descriptor(),
        Some(existing_version(locator, version)),
    )
    .expect("reconciliation request")
}
