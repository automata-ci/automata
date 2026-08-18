//! Provider-neutral authenticated webhook ingress and fenced delivery work.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod clock;
mod control;
mod ingress;
mod worker;

pub use clock::{ProviderDeliveryClock, ProviderDeliveryClockError, SystemProviderDeliveryClock};
pub use control::{
    ProviderControlResolutionError, ProviderControlResolver, ProviderControlResolverRegistry,
    ProviderControlResolverRegistryError, ProviderProcessingDispatcher, ProviderTriggerProcessor,
};
pub use ingress::{PreparedProviderWebhook, ProviderDeliveryIngress, ProviderDeliveryIngressError};
pub use worker::{
    ProviderProcessingOutcome, ProviderProcessingProcessor, ProviderProcessingWorker,
    ProviderProcessingWorkerConfig, ProviderProcessingWorkerError, ProviderProcessingWorkerOutcome,
};
