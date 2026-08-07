#![forbid(unsafe_code)]
//! G1 application services that compose Automata's pure scheduling policy with
//! durable control-plane ports.
//!
//! This crate owns orchestration only. It does not decode protobuf, serve HTTP,
//! issue SQL, or load `JobIR` object bytes.

mod config;
mod error;
mod lease;
mod port;

pub use config::{LeasePollConfig, LeaseTimeToLive, LeaseTimeToLiveError};
pub use error::{CapabilityDocument, LeasePollError, LeasePollInvariant, RequestCorrelationError};
pub use lease::{AuthenticatedRunnerSession, ClaimedLeasePoll, LeasePollOutcome, LeasePollService};
pub use port::{
    LeaseClock, LeaseIdGenerator, LeasePollRepository, RandomLeaseIdGenerator, SystemLeaseClock,
};
