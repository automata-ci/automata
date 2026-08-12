#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! G1 application services that compose Automata's pure scheduling policy with
//! durable control-plane ports.
//!
//! This crate owns orchestration only. It does not decode protobuf, serve HTTP,
//! issue SQL, or load `JobIR` object bytes.
//!
//! A transport authenticates a runner and supplies an
//! [`AuthenticatedRunnerSession`] alongside its already-decoded lease request.
//! [`LeasePollService`] correlates that request with the authenticated durable
//! fence, consults an existing receipt before doing fresh scheduling work, and
//! commits claims or no-work results through [`LeasePollRepository`]. Exact
//! retries therefore replay the durable receipt instead of minting a second
//! lease.
//!
//! Errors are typed for trusted application diagnostics. Transports must map
//! them to their own bounded, sanitized responses rather than expose error
//! values or their sources directly to an untrusted runner.

mod config;
mod error;
mod lease;
mod observer;
mod port;

pub use config::{LeasePollConfig, LeaseTimeToLive, LeaseTimeToLiveError};
pub use error::{CapabilityDocument, LeasePollError, LeasePollInvariant, RequestCorrelationError};
pub use lease::{AuthenticatedRunnerSession, ClaimedLeasePoll, LeasePollOutcome, LeasePollService};
pub use observer::{
    LeaseClaimRejection, LeasePollFailure, LeasePollObservation, LeasePollObserver,
    NoopLeasePollObserver,
};
pub use port::{
    LeaseClock, LeaseIdGenerator, LeasePollRepository, RandomLeaseIdGenerator, RunnableAttemptGate,
    RunnableAttemptGateDisposition, SystemLeaseClock,
};
