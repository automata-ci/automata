//! Provider-neutral authenticated webhook ingress and fenced delivery work.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod clock;
mod ingress;
mod result_worker;
mod runtime;
mod trust;
mod worker;

pub use clock::{ProviderDeliveryClock, ProviderDeliveryClockError, SystemProviderDeliveryClock};
pub use ingress::{PreparedProviderWebhook, ProviderDeliveryIngress, ProviderDeliveryIngressError};
pub use result_worker::{
    ProviderResultAdapter, ProviderResultAdapterRegistry, ProviderResultAdapterRegistryError,
    ProviderResultLease, ProviderResultObservation, ProviderResultWorker,
    ProviderResultWorkerConfig, ProviderResultWorkerError, ProviderResultWorkerOutcome,
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
