use automata_ci_secret::{
    MAX_REGISTERED_SECRET_PROVIDERS, SecretAtRestProtection, SecretProviderId,
    SecretProviderRegistry, SecretProviderRegistryError,
};

use crate::support::provider_adapter as provider;

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
