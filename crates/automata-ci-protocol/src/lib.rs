#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Owned wire messages between `automata` and `automata-runner`.
//!
//! These owned, validated messages are the transport-neutral protocol model.
//! Production runner transport is encoded by a separately versioned Protobuf
//! adapter. Rust's in-memory representation is never itself a wire format.

pub mod message;
pub mod negotiation;
pub mod windows_admission;
pub mod windows_admission_issue;

pub use message::*;
pub use negotiation::*;
pub use windows_admission::*;
pub use windows_admission_issue::*;

/// Current schema version for the message structs in this crate.
///
pub const MESSAGE_SCHEMA_VERSION: u16 = 1;
