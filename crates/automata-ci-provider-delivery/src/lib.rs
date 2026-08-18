//! Provider-neutral authenticated webhook ingress and fenced delivery work.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod clock;
mod ingress;
mod worker;

pub use clock::{ProviderDeliveryClock, ProviderDeliveryClockError, SystemProviderDeliveryClock};
pub use ingress::{PreparedProviderWebhook, ProviderDeliveryIngress, ProviderDeliveryIngressError};
pub use worker::{
    ProviderDeliveryProcessOutcome, ProviderDeliveryProcessor, ProviderDeliveryWorker,
    ProviderDeliveryWorkerConfig, ProviderDeliveryWorkerError, ProviderDeliveryWorkerOutcome,
};
