//! G1 application services that compose Automata's pure scheduling policy with
//! durable control-plane ports.
//!
//! This module owns orchestration only. It does not decode protobuf, serve HTTP,
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
mod observer;
mod port;
/// Durable lease polling and runnable-attempt repositories.
pub mod repository;
/// Authoritative runner routing and slot-availability contracts.
pub mod routing;
mod service;

pub use config::{LeasePollConfig, LeaseTimeToLive, LeaseTimeToLiveError};
pub use error::{CapabilityDocument, LeasePollError, LeasePollInvariant, RequestCorrelationError};
pub(crate) use observer::NoopLeasePollObserver;
pub use observer::{
    LeaseClaimRejection, LeasePollFailure, LeasePollObservation, LeasePollObserver,
};
pub use port::{
    LeaseClock, LeaseIdGenerator, LeasePollRepository, RandomLeaseIdGenerator, RunnableAttemptGate,
    RunnableAttemptGateDisposition, SystemLeaseClock,
};
pub use service::{
    AuthenticatedRunnerSession, ClaimedLeasePoll, LeasePollOutcome, LeasePollService,
};
