//! Provider-neutral authenticated webhook ingress and fenced delivery work.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod background;
mod clock;
mod configuration;
mod ingress;
mod result_worker;
mod runtime;
mod trust;
mod worker;

pub use background::{ProviderBackgroundRuntime, ProviderBackgroundRuntimeError};
pub use clock::{ProviderDeliveryClock, ProviderDeliveryClockError, SystemProviderDeliveryClock};
pub use configuration::{ProviderConfigurationService, ProviderConfigurationServiceError};
pub use ingress::{PreparedProviderWebhook, ProviderDeliveryIngress, ProviderDeliveryIngressError};
pub use result_worker::{
    ProviderResultAdapter, ProviderResultAdapterOutcome, ProviderResultAdapterRegistry,
    ProviderResultAdapterRegistryError, ProviderResultLease, ProviderResultObservation,
    ProviderResultWorker, ProviderResultWorkerConfig, ProviderResultWorkerError,
    ProviderResultWorkerOutcome,
};
pub use runtime::{
    ProviderControlHandlingError, ProviderProcessingDispatcher, ProviderRuntimeAdapter,
    ProviderRuntimeAdapterRegistry, ProviderRuntimeAdapterRegistryError, ProviderRuntimeContext,
    ProviderRuntimeContextError, ProviderRuntimeContextResolver, ProviderTriggerOutcome,
};
pub use trust::{ProviderTrustContext, derive_provider_trust_snapshot};
pub use worker::{
    ProviderProcessingLease, ProviderProcessingOutcome, ProviderProcessingProcessor,
    ProviderProcessingWorker, ProviderProcessingWorkerConfig, ProviderProcessingWorkerError,
    ProviderProcessingWorkerOutcome,
};
