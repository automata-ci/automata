#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Scheduling, execution durability, maintenance, observability, and
//! authenticated runner control for Automata.

pub mod attempt;
pub mod cancellation;
pub mod lease;
pub mod maintenance;
pub mod observability;
pub mod runner_auth;
pub mod runner_control;
pub mod scheduling;
pub mod workload_oidc;

/// Unstable construction and inspection hooks for Automata's first-party
/// durable adapters.
///
/// This module is not a supported public API. It is feature-gated so ordinary
/// Control consumers cannot accidentally depend on repository trust-boundary
/// operations, and it may change without notice alongside first-party
/// adapters.
#[cfg(feature = "adapter-spi")]
#[doc(hidden)]
pub mod adapter_spi;
