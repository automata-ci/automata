//! Authentication, identity, sessions, and authorization contracts for Automata.
//!
//! The boundaries in this crate intentionally keep human login, machine identity,
//! session issuance, authorization, and provider-token storage independent.

#![forbid(unsafe_code)]

pub mod authorization;
pub mod github;
pub mod human;
pub mod machine;
pub mod secret;
pub mod session;
pub mod time;
pub mod vault;
