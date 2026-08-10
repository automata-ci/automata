use std::{collections::BTreeMap, fmt, sync::Arc};

use thiserror::Error;

use crate::{SecretProvider, SecretProviderId};

/// Maximum number of provider adapters composed into one process.
pub const MAX_REGISTERED_SECRET_PROVIDERS: usize = 32;

/// Immutable runtime registry for configured secret-provider adapters.
///
/// Provider configuration and credentials remain inside each adapter. The
/// registry stores only adapter objects and their non-secret canonical IDs,
/// and it never formats an adapter through `Debug`.
#[derive(Clone)]
pub struct SecretProviderRegistry {
    default_provider_id: SecretProviderId,
    default_provider: Arc<dyn SecretProvider>,
    providers: BTreeMap<SecretProviderId, Arc<dyn SecretProvider>>,
}

impl SecretProviderRegistry {
    /// Builds a bounded registry with one explicit default provider.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized provider set, duplicate provider IDs, or
    /// a default provider ID that is not present in the set.
    pub fn new(
        default_provider_id: SecretProviderId,
        providers: impl IntoIterator<Item = Arc<dyn SecretProvider>>,
    ) -> Result<Self, SecretProviderRegistryError> {
        let mut registered = BTreeMap::new();
        for provider in providers {
            if registered.len() == MAX_REGISTERED_SECRET_PROVIDERS {
                return Err(SecretProviderRegistryError::TooManyProviders);
            }
            let provider_id = provider.provider_id().clone();
            if registered.insert(provider_id, provider).is_some() {
                return Err(SecretProviderRegistryError::DuplicateProvider);
            }
        }
        if registered.is_empty() {
            return Err(SecretProviderRegistryError::NoProviders);
        }
        let default_provider = registered
            .get(&default_provider_id)
            .cloned()
            .ok_or(SecretProviderRegistryError::MissingDefaultProvider)?;
        Ok(Self {
            default_provider_id,
            default_provider,
            providers: registered,
        })
    }

    /// Returns the configured default provider ID.
    #[must_use]
    pub const fn default_provider_id(&self) -> &SecretProviderId {
        &self.default_provider_id
    }

    /// Returns the configured default provider adapter.
    #[must_use]
    pub fn default_provider(&self) -> Arc<dyn SecretProvider> {
        self.default_provider.clone()
    }

    /// Looks up one exact provider adapter without falling back to the default.
    #[must_use]
    pub fn provider(&self, provider_id: &SecretProviderId) -> Option<Arc<dyn SecretProvider>> {
        self.providers.get(provider_id).cloned()
    }

    /// Iterates the sorted, non-secret provider IDs.
    pub fn provider_ids(&self) -> impl ExactSizeIterator<Item = &SecretProviderId> {
        self.providers.keys()
    }

    /// Returns the number of registered adapters.
    #[must_use]
    pub fn len(&self) -> usize {
        self.providers.len()
    }

    /// Returns whether no adapters are registered.
    ///
    /// A successfully constructed registry is never empty; this method exists
    /// alongside `len` for conventional collection ergonomics.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }
}

impl fmt::Debug for SecretProviderRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretProviderRegistry")
            .field("default_provider_id", &self.default_provider_id)
            .field("default_provider", &"SecretProvider(..)")
            .field("provider_ids", &self.providers.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Closed construction failures for a secret-provider registry.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SecretProviderRegistryError {
    /// Construction received no adapters, so no default can be selected.
    #[error("at least one secret provider is required")]
    NoProviders,
    /// Construction received more than
    /// [`MAX_REGISTERED_SECRET_PROVIDERS`] adapters.
    #[error("too many secret providers were configured")]
    TooManyProviders,
    /// Two adapters returned the same canonical provider identifier.
    #[error("a secret provider ID was configured more than once")]
    DuplicateProvider,
    /// The explicit default identifier does not identify a registered adapter.
    #[error("the configured default secret provider is not registered")]
    MissingDefaultProvider,
}
