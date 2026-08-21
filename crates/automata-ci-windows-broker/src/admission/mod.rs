//! Documentation is inherited from the parent crate.
//! Broker admission contracts, application service, and durable adapters.
//!
//! Pure canonical request and policy evaluation live in
//! `automata-ci-windows-broker-core`. Concrete persistence remains namespaced
//! under [`repository`], and custody adapters under [`crate::custody`].

mod authority;
pub mod repository;
mod service;
mod signing;

pub use authority::{
    UnavailableWindowsBrokerAdmissionAuthority, WindowsBrokerAdmissionAuthority,
    WindowsBrokerAdmissionCompletion, WindowsBrokerAdmissionReceipt,
    WindowsBrokerPlacementRenewalReceipt,
};
pub use automata_ci_windows_broker_core::admission::WindowsBrokerAdmissionError;
pub use service::WindowsBrokerAdmissionService;
pub use signing::WindowsBrokerAdmissionSigningKey;
