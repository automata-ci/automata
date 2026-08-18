//! Provider-neutral authenticated webhook ingress and fenced delivery work.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod clock;
mod ingress;
mod runtime;
mod worker;

pub use clock::{ProviderDeliveryClock, ProviderDeliveryClockError, SystemProviderDeliveryClock};
pub use ingress::{PreparedProviderWebhook, ProviderDeliveryIngress, ProviderDeliveryIngressError};
pub use runtime::{
    ProviderControlHandlingError, ProviderProcessingDispatcher, ProviderRuntimeAdapter,
    ProviderRuntimeAdapterRegistry, ProviderRuntimeAdapterRegistryError, ProviderTriggerOutcome,
};
pub use worker::{
    ProviderProcessingLease, ProviderProcessingOutcome, ProviderProcessingProcessor,
    ProviderProcessingWorker, ProviderProcessingWorkerConfig, ProviderProcessingWorkerError,
    ProviderProcessingWorkerOutcome,
};
