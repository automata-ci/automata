//! Provider-neutral dispatch from authenticated controls to fresh trigger invocations.

use std::{collections::BTreeMap, fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_provider::{
    ClaimedProviderProcessing, ProviderDeliveryId, ProviderProcessingFailure,
    ProviderProcessingInput, ProviderTypeId, VerifiedProviderControlDelivery,
};
use thiserror::Error;

use crate::{ProviderProcessingLease, ProviderProcessingOutcome, ProviderProcessingProcessor};

const MAX_PROVIDER_CONTROL_HANDLERS: usize = 32;

/// Provider-specific authority that idempotently handles one native control.
///
/// Implementations must reauthorize current actor and result identity, perform
/// the requested operation idempotently, and return the originating trigger
/// delivery when one exists. A crash may cause the same control to be handled
/// again before its processing invocation is durably completed.
#[async_trait]
pub trait ProviderControlHandler: fmt::Debug + Send + Sync {
    /// Returns the exact provider adapter type handled by this handler.
    fn provider_type(&self) -> &ProviderTypeId;

    /// Reauthorizes and idempotently executes one authenticated control.
    async fn handle(
        &self,
        control: &VerifiedProviderControlDelivery,
        lease: &ProviderProcessingLease,
    ) -> Result<Option<ProviderDeliveryId>, ProviderControlHandlingError>;
}

/// Provider-independent workflow admission invoked only for a resolved trigger.
#[async_trait]
pub trait ProviderTriggerProcessor: fmt::Debug + Send + Sync {
    /// Performs idempotent admission under the invocation's exact live fence.
    async fn process_trigger(
        &self,
        invocation: &ClaimedProviderProcessing,
        lease: &ProviderProcessingLease,
    ) -> ProviderProcessingOutcome;
}

/// Exact duplicate-free registry of statically linked provider control handlers.
#[derive(Clone)]
pub struct ProviderControlHandlerRegistry {
    handlers: BTreeMap<ProviderTypeId, Arc<dyn ProviderControlHandler>>,
}

impl ProviderControlHandlerRegistry {
    /// Builds a bounded nonempty handler registry.
    ///
    /// # Errors
    ///
    /// Rejects an empty, excessive, duplicate, or self-inconsistent handler set.
    pub fn new(
        handlers: impl IntoIterator<Item = Arc<dyn ProviderControlHandler>>,
    ) -> Result<Self, ProviderControlHandlerRegistryError> {
        let mut values = BTreeMap::new();
        for handler in handlers {
            let key = handler.provider_type().clone();
            if values.insert(key, handler).is_some() {
                return Err(ProviderControlHandlerRegistryError::Duplicate);
            }
        }
        if values.is_empty() || values.len() > MAX_PROVIDER_CONTROL_HANDLERS {
            return Err(ProviderControlHandlerRegistryError::InvalidSize);
        }
        if values
            .iter()
            .any(|(key, handler)| handler.provider_type() != key)
        {
            return Err(ProviderControlHandlerRegistryError::Inconsistent);
        }
        Ok(Self { handlers: values })
    }

    fn handler(&self, provider_type: &ProviderTypeId) -> Option<&dyn ProviderControlHandler> {
        self.handlers.get(provider_type).map(Arc::as_ref)
    }
}

impl fmt::Debug for ProviderControlHandlerRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderControlHandlerRegistry")
            .field("provider_types", &self.handlers.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Processing dispatcher for idempotent controls and ordinary trigger admission.
pub struct ProviderProcessingDispatcher {
    handlers: ProviderControlHandlerRegistry,
    triggers: Arc<dyn ProviderTriggerProcessor>,
}

impl ProviderProcessingDispatcher {
    /// Composes exact provider control handling with provider-independent admission.
    #[must_use]
    pub fn new(
        handlers: ProviderControlHandlerRegistry,
        triggers: Arc<dyn ProviderTriggerProcessor>,
    ) -> Self {
        Self { handlers, triggers }
    }
}

impl fmt::Debug for ProviderProcessingDispatcher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderProcessingDispatcher")
            .field("handlers", &self.handlers)
            .field("triggers", &self.triggers)
            .finish()
    }
}

#[async_trait]
impl ProviderProcessingProcessor for ProviderProcessingDispatcher {
    async fn process(
        &self,
        invocation: &ClaimedProviderProcessing,
        lease: &ProviderProcessingLease,
    ) -> ProviderProcessingOutcome {
        let ProviderProcessingInput::Control(control) = invocation.input() else {
            // A control handler has already performed its idempotent operation.
            // Binding an originating trigger is durable provenance only; it
            // must never replay the original webhook admission side effects.
            let Some(source_delivery_id) = invocation.receipt().source_delivery_id() else {
                return ProviderProcessingOutcome::Fail(ProviderProcessingFailure::InvalidEvidence);
            };
            if invocation.receipt().cause_delivery_id() != source_delivery_id {
                return ProviderProcessingOutcome::Complete;
            }
            return self.triggers.process_trigger(invocation, lease).await;
        };
        let Some(handler) = self.handlers.handler(control.evidence().provider_type()) else {
            return ProviderProcessingOutcome::Fail(ProviderProcessingFailure::InvalidEvidence);
        };
        match handler.handle(control, lease).await {
            Ok(Some(source_delivery_id)) => {
                ProviderProcessingOutcome::ResolveControl(source_delivery_id)
            }
            Ok(None) => ProviderProcessingOutcome::Complete,
            Err(ProviderControlHandlingError::Unavailable) => {
                ProviderProcessingOutcome::Retry(ProviderProcessingFailure::DependencyUnavailable)
            }
            Err(
                ProviderControlHandlingError::Unauthorized
                | ProviderControlHandlingError::NotFound
                | ProviderControlHandlingError::Conflict,
            ) => ProviderProcessingOutcome::Fail(ProviderProcessingFailure::PolicyRejected),
            Err(ProviderControlHandlingError::InvalidEvidence) => {
                ProviderProcessingOutcome::Fail(ProviderProcessingFailure::InvalidEvidence)
            }
        }
    }
}

/// Sanitized provider-native control handling failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderControlHandlingError {
    /// Provider or durable handling dependencies were unavailable.
    #[error("provider control handling is unavailable")]
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

/// Invalid control-handler registry construction.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderControlHandlerRegistryError {
    /// Registry was empty or exceeded its hard bound.
    #[error("provider control handler registry size is invalid")]
    InvalidSize,
    /// Two handlers registered the same provider type.
    #[error("provider control handler type is duplicated")]
    Duplicate,
    /// A handler's declared provider type changed during construction.
    #[error("provider control handler identity is inconsistent")]
    Inconsistent,
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[derive(Debug)]
    struct Handler {
        first: ProviderTypeId,
        subsequent: ProviderTypeId,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl ProviderControlHandler for Handler {
        fn provider_type(&self) -> &ProviderTypeId {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                &self.first
            } else {
                &self.subsequent
            }
        }

        async fn handle(
            &self,
            _control: &VerifiedProviderControlDelivery,
            _lease: &ProviderProcessingLease,
        ) -> Result<Option<ProviderDeliveryId>, ProviderControlHandlingError> {
            unreachable!("registry construction never resolves controls")
        }
    }

    fn handler(first: &str, subsequent: &str) -> Arc<dyn ProviderControlHandler> {
        Arc::new(Handler {
            first: ProviderTypeId::new(first).expect("first provider type"),
            subsequent: ProviderTypeId::new(subsequent).expect("subsequent provider type"),
            calls: AtomicUsize::new(0),
        })
    }

    #[test]
    fn registry_rejects_empty_duplicate_oversized_and_changing_identities() {
        assert!(matches!(
            ProviderControlHandlerRegistry::new([]),
            Err(ProviderControlHandlerRegistryError::InvalidSize)
        ));
        assert!(matches!(
            ProviderControlHandlerRegistry::new([
                handler("github", "github"),
                handler("github", "github"),
            ]),
            Err(ProviderControlHandlerRegistryError::Duplicate)
        ));
        let oversized = (0..=MAX_PROVIDER_CONTROL_HANDLERS)
            .map(|index| {
                let provider_type = format!("provider-{index}");
                handler(&provider_type, &provider_type)
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            ProviderControlHandlerRegistry::new(oversized),
            Err(ProviderControlHandlerRegistryError::InvalidSize)
        ));
        assert!(matches!(
            ProviderControlHandlerRegistry::new([handler("github", "forgejo")]),
            Err(ProviderControlHandlerRegistryError::Inconsistent)
        ));
    }
}
