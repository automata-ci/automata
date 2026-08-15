#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Compatibility facade for Automata's domain-specific `PostgreSQL` adapters.

#[cfg(all(test, not(feature = "test-support")))]
mod test_support;
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod test_support;

/// Human authentication, authorization, and runner-enrollment adapters.
pub use automata_ci_auth_postgres as auth;
/// Atomic external workspace-management adapters.
pub use automata_ci_provisioning_postgres as provisioning;
/// Durable runner-machine authentication adapter.
pub use automata_ci_runner_auth_postgres as runner_auth;
/// Built-in encrypted secret-provider adapter.
pub use automata_ci_secret_postgres as secret;
/// Durable control-plane storage adapter.
pub use automata_ci_store_postgres as store;
