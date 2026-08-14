#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! `PostgreSQL` implementations of Automata's durable control-plane ports.

mod migration;

/// Human authentication, authorization, and runner-enrollment adapters.
pub mod auth;
/// Atomic workspace-provisioning adapter.
pub mod provisioning;
/// Durable runner-machine authentication adapter.
pub mod runner_auth;
/// Built-in encrypted secret-provider adapter.
pub mod secret;
/// Durable control-plane storage adapter.
pub mod store;
