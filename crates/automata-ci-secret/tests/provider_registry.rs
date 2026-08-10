use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_secret::{
    CreateSecretVersionRequest, CreatedSecretVersion, DestroySecretVersionRequest,
    MAX_REGISTERED_SECRET_PROVIDERS, ProviderError, ProviderHealth, ProviderOperationContext,
    ResolveSecretVersionRequest, ResolvedSecretVersion, SecretAtRestProtection, SecretProvider,
    SecretProviderId, SecretProviderRegistry, SecretProviderRegistryError,
};

struct FakeProvider {
    id: SecretProviderId,
}

impl FakeProvider {
    fn new(id: &str) -> Self {
        Self {
            id: SecretProviderId::new(id).expect("test provider ID"),
        }
    }
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

    fn capabilities(&self) -> &automata_ci_secret::ProviderCapabilities {
        static CAPABILITIES: std::sync::LazyLock<automata_ci_secret::ProviderCapabilities> =
            std::sync::LazyLock::new(automata_ci_secret::ProviderCapabilities::default);
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

fn provider(id: &str) -> Arc<dyn SecretProvider> {
    Arc::new(FakeProvider::new(id))
}

#[test]
fn registry_selects_only_exact_registered_providers() {
    let registry = SecretProviderRegistry::new(
        SecretProviderId::new("builtin").unwrap(),
        [provider("vault"), provider("builtin")],
    )
    .unwrap();

    assert_eq!(registry.len(), 2);
    assert!(!registry.is_empty());
    assert_eq!(
        registry.default_provider().provider_id().as_str(),
        "builtin"
    );
    assert_eq!(
        registry.default_provider().at_rest_protection(),
        SecretAtRestProtection::ProviderManagedEncryption
    );
    assert_eq!(
        registry
            .provider(&SecretProviderId::new("vault").unwrap())
            .unwrap()
            .provider_id()
            .as_str(),
        "vault"
    );
    assert!(
        registry
            .provider(&SecretProviderId::new("missing").unwrap())
            .is_none()
    );
    assert_eq!(
        registry
            .provider_ids()
            .map(SecretProviderId::as_str)
            .collect::<Vec<_>>(),
        ["builtin", "vault"]
    );
}

#[test]
fn registry_rejects_ambiguous_or_unusable_composition() {
    assert_eq!(
        SecretProviderRegistry::new(SecretProviderId::new("builtin").unwrap(), []).unwrap_err(),
        SecretProviderRegistryError::NoProviders
    );
    assert_eq!(
        SecretProviderRegistry::new(
            SecretProviderId::new("missing").unwrap(),
            [provider("builtin")],
        )
        .unwrap_err(),
        SecretProviderRegistryError::MissingDefaultProvider
    );
    assert_eq!(
        SecretProviderRegistry::new(
            SecretProviderId::new("builtin").unwrap(),
            [provider("builtin"), provider("builtin")],
        )
        .unwrap_err(),
        SecretProviderRegistryError::DuplicateProvider
    );

    let providers = (0..=MAX_REGISTERED_SECRET_PROVIDERS)
        .map(|index| provider(&format!("provider-{index}")))
        .collect::<Vec<_>>();
    assert_eq!(
        SecretProviderRegistry::new(SecretProviderId::new("provider-0").unwrap(), providers)
            .unwrap_err(),
        SecretProviderRegistryError::TooManyProviders
    );
}

#[test]
fn registry_debug_never_formats_provider_configuration() {
    let registry = SecretProviderRegistry::new(
        SecretProviderId::new("builtin").unwrap(),
        [provider("builtin")],
    )
    .unwrap();
    let debug = format!("{registry:?}");
    assert!(debug.contains("builtin"));
    assert!(!debug.contains("must-not-appear"));
}
