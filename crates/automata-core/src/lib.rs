#![forbid(unsafe_code)]
//! Stable, provider-neutral domain types shared by Automata components.
//!
//! Durable values in this crate use explicit schema versions and serde. JSON is
//! the canonical interchange format for the first schema generation; no Rust
//! memory layout or backend-specific handle is part of the contract.

pub mod capability;
pub mod digest;
pub mod execution;
pub mod id;
pub mod job;
pub mod log;
pub mod time;
pub mod workflow;

pub use capability::*;
pub use digest::*;
pub use execution::*;
pub use id::*;
pub use job::*;
pub use log::*;
pub use time::*;
pub use workflow::*;

/// Current version of independently persisted core-domain envelopes.
pub const CORE_SCHEMA_VERSION: u16 = 1;
