#![forbid(unsafe_code)]
//! Owned wire messages between `automata` and `automata-runner`.
//!
//! The protocol initially uses serde JSON exclusively. Every post-handshake
//! message carries both the negotiated protocol version and an independent
//! message-schema version; Rust's in-memory representation is not a wire format.

pub mod message;
pub mod negotiation;

pub use message::*;
pub use negotiation::*;

/// Current schema version for the message structs in this crate.
pub const MESSAGE_SCHEMA_VERSION: u16 = 1;
