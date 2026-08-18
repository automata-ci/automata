//! Provider-neutral dispatch from authenticated controls to fresh trigger invocations.

use std::{collections::BTreeMap, fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_provider::{
    ClaimedProviderProcessing, ProviderDeliveryId, ProviderProcessingFailure,
    ProviderProcessingInput, ProviderTypeId, VerifiedProviderControlDelivery,
};
use thiserror::Error;

use crate::{ProviderProcessingOutcome, ProviderProcessingProcessor};

const MAX_PROVIDER_CONTROL_RESOLVERS: usize = 32;

/// Provider-specific authority that resolves native result identity to its trigger delivery.
#[async_trait]
pub trait ProviderControlResolver: fmt::Debug + Send + Sync {
    /// Returns the exact provider adapter type handled by this resolver.
    fn provider_type(&self) -> &ProviderTypeId;

    /// Reauthorizes and resolves one authenticated control to an immutable trigger.
    async fn resolve(
        &self,
        control: &VerifiedProviderControlDelivery,
    ) -> Result<ProviderDeliveryId, ProviderControlResolutionError>;
}

/// Provider-independent workflow admission invoked only for a resolved trigger.
#[async_trait]
pub trait ProviderTriggerProcessor: fmt::Debug + Send + Sync {
    /// Performs idempotent admission under the invocation's exact live fence.
    async fn process_trigger(
        &self,
        invocation: &ClaimedProviderProcessing,
    ) -> ProviderProcessingOutcome;
}

/// Exact duplicate-free registry of statically linked provider control resolvers.
#[derive(Clone)]
pub struct ProviderControlResolverRegistry {
    resolvers: BTreeMap<ProviderTypeId, Arc<dyn ProviderControlResolver>>,
}

impl ProviderControlResolverRegistry {
    /// Builds a bounded nonempty resolver registry.
    ///
    /// # Errors
    ///
    /// Rejects an empty, excessive, duplicate, or self-inconsistent resolver set.
    pub fn new(
        resolvers: impl IntoIterator<Item = Arc<dyn ProviderControlResolver>>,
    ) -> Result<Self, ProviderControlResolverRegistryError> {
        let mut values = BTreeMap::new();
        for resolver in resolvers {
            let key = resolver.provider_type().clone();
            if values.insert(key, resolver).is_some() {
                return Err(ProviderControlResolverRegistryError::Duplicate);
            }
        }
        if values.is_empty() || values.len() > MAX_PROVIDER_CONTROL_RESOLVERS {
            return Err(ProviderControlResolverRegistryError::InvalidSize);
        }
        if values
            .iter()
            .any(|(key, resolver)| resolver.provider_type() != key)
        {
            return Err(ProviderControlResolverRegistryError::Inconsistent);
        }
        Ok(Self { resolvers: values })
    }

    fn resolve(&self, provider_type: &ProviderTypeId) -> Option<&dyn ProviderControlResolver> {
        self.resolvers.get(provider_type).map(Arc::as_ref)
    }
}

impl fmt::Debug for ProviderControlResolverRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderControlResolverRegistry")
            .field("provider_types", &self.resolvers.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Processing handler that resolves controls before invoking common trigger admission.
pub struct ProviderProcessingDispatcher {
    resolvers: ProviderControlResolverRegistry,
    triggers: Arc<dyn ProviderTriggerProcessor>,
}

impl ProviderProcessingDispatcher {
    /// Composes exact provider control resolution with provider-independent admission.
    #[must_use]
    pub fn new(
        resolvers: ProviderControlResolverRegistry,
        triggers: Arc<dyn ProviderTriggerProcessor>,
    ) -> Self {
        Self {
            resolvers,
            triggers,
        }
    }
}

impl fmt::Debug for ProviderProcessingDispatcher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderProcessingDispatcher")
            .field("resolvers", &self.resolvers)
            .field("triggers", &self.triggers)
            .finish()
    }
}

#[async_trait]
impl ProviderProcessingProcessor for ProviderProcessingDispatcher {
    async fn process(&self, invocation: &ClaimedProviderProcessing) -> ProviderProcessingOutcome {
        let ProviderProcessingInput::Control(control) = invocation.input() else {
            return self.triggers.process_trigger(invocation).await;
        };
        let Some(resolver) = self.resolvers.resolve(control.evidence().provider_type()) else {
            return ProviderProcessingOutcome::Fail(ProviderProcessingFailure::InvalidEvidence);
        };
        match resolver.resolve(control).await {
            Ok(source_delivery_id) => ProviderProcessingOutcome::ResolveControl(source_delivery_id),
            Err(ProviderControlResolutionError::Unavailable) => {
                ProviderProcessingOutcome::Retry(ProviderProcessingFailure::DependencyUnavailable)
            }
            Err(
                ProviderControlResolutionError::Unauthorized
                | ProviderControlResolutionError::NotFound
                | ProviderControlResolutionError::Conflict,
            ) => ProviderProcessingOutcome::Fail(ProviderProcessingFailure::PolicyRejected),
            Err(ProviderControlResolutionError::InvalidEvidence) => {
                ProviderProcessingOutcome::Fail(ProviderProcessingFailure::InvalidEvidence)
            }
        }
    }
}

/// Sanitized provider-native control resolution failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderControlResolutionError {
    /// Provider or durable resolution dependencies were unavailable.
    #[error("provider control resolution is unavailable")]
    Unavailable,
    /// The authenticated actor lacks current Automata authority.
    #[error("provider control actor is unauthorized")]
    Unauthorized,
    /// No exact Automata result subject matched the native target.
    #[error("provider control target was not found")]
    NotFound,
    /// Native identity matched conflicting Automata result evidence.
    #[error("provider control target is ambiguous")]
    Conflict,
    /// Adapter evidence violated the registered control schema.
    #[error("provider control evidence is invalid")]
    InvalidEvidence,
}

/// Invalid control-resolver registry construction.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderControlResolverRegistryError {
    /// Registry was empty or exceeded its hard bound.
    #[error("provider control resolver registry size is invalid")]
    InvalidSize,
    /// Two resolvers registered the same provider type.
    #[error("provider control resolver type is duplicated")]
    Duplicate,
    /// A resolver's declared provider type changed during construction.
    #[error("provider control resolver identity is inconsistent")]
    Inconsistent,
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[derive(Debug)]
    struct Resolver {
        first: ProviderTypeId,
        subsequent: ProviderTypeId,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl ProviderControlResolver for Resolver {
        fn provider_type(&self) -> &ProviderTypeId {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                &self.first
            } else {
                &self.subsequent
            }
        }

        async fn resolve(
            &self,
            _control: &VerifiedProviderControlDelivery,
        ) -> Result<ProviderDeliveryId, ProviderControlResolutionError> {
            unreachable!("registry construction never resolves controls")
        }
    }

    fn resolver(first: &str, subsequent: &str) -> Arc<dyn ProviderControlResolver> {
        Arc::new(Resolver {
            first: ProviderTypeId::new(first).expect("first provider type"),
            subsequent: ProviderTypeId::new(subsequent).expect("subsequent provider type"),
            calls: AtomicUsize::new(0),
        })
    }

    #[test]
    fn registry_rejects_empty_duplicate_oversized_and_changing_identities() {
        assert!(matches!(
            ProviderControlResolverRegistry::new([]),
            Err(ProviderControlResolverRegistryError::InvalidSize)
        ));
        assert!(matches!(
            ProviderControlResolverRegistry::new([
                resolver("github", "github"),
                resolver("github", "github"),
            ]),
            Err(ProviderControlResolverRegistryError::Duplicate)
        ));
        let oversized = (0..=MAX_PROVIDER_CONTROL_RESOLVERS)
            .map(|index| {
                let provider_type = format!("provider-{index}");
                resolver(&provider_type, &provider_type)
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            ProviderControlResolverRegistry::new(oversized),
            Err(ProviderControlResolverRegistryError::InvalidSize)
        ));
        assert!(matches!(
            ProviderControlResolverRegistry::new([resolver("github", "forgejo")]),
            Err(ProviderControlResolverRegistryError::Inconsistent)
        ));
    }
}
