#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! `PostgreSQL` implementations of Automata's durable control-plane ports.

mod migration;

#[cfg(all(test, not(feature = "test-support")))]
mod test_support;
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod test_support;

/// Human authentication, authorization, and runner-enrollment adapters.
pub mod auth;
/// Atomic external workspace-management adapters.
pub mod provisioning;
/// Durable runner-machine authentication adapter.
pub mod runner_auth;
/// Built-in encrypted secret-provider adapter.
pub mod secret;
/// Durable control-plane storage adapter.
pub mod store;
