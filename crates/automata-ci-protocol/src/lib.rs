#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Owned wire messages between `automata` and `automata-runner`.
//!
//! These owned, validated messages are the transport-neutral protocol model.
//! Production runner transport is encoded by a separately versioned Protobuf
//! adapter. Rust's in-memory representation is never itself a wire format.

pub mod message;
pub mod negotiation;

pub use message::*;
pub use negotiation::*;

/// Current schema version for the message structs in this crate.
///
/// Version three adds required, protected, per-attempt runtime authorities to
/// lease offers. Protocol v5 peers fail closed instead of silently executing a
/// job without its server-issued authority.
pub const MESSAGE_SCHEMA_VERSION: u16 = 3;
