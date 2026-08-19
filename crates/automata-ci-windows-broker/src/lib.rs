#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Privileged Windows Hyper-V broker lifecycle core.
//!
//! The runner-side sandbox adapter does not link this crate. Lifecycle policy,
//! grant verification, reconciliation, watchdog supervision, and durable-state
//! ports are service-owned; concrete host-compute and file-system adapters are
//! kept behind those ports.

mod guest;
mod service;

pub use guest::*;
pub use service::*;
