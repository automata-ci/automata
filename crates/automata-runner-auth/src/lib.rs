//! Durable runner authority composed from an already-validated mTLS peer.
//!
//! # Composition invariant
//!
//! [`MachineAuthenticationEvidence`](automata_auth::machine::MachineAuthenticationEvidence)
//! must come directly from `automata-runner-transport` after rustls has successfully
//! validated the complete client chain against the configured runner trust roots,
//! certificate validity, and client-auth purpose. The first certificate must be the
//! TLS-validated leaf in rustls order. Forwarded headers and runner protocol fields
//! are not authentication evidence.
//!
//! This crate deliberately does not parse X.509 or repeat chain validation. It bounds
//! the validated evidence, hashes only the leaf, and uses that digest solely as a key
//! into server-owned durable registration state. External identity, internal runner
//! identity, generation, certificate expiry, and desired state all come from that
//! directory; none are parsed from certificate contents or runner input.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod authenticator;
mod directory;
mod limits;

pub use authenticator::DurableRunnerMachineAuthenticator;
pub use directory::{
    RunnerMachineDirectory, RunnerMachineDirectoryError, RunnerMachineRecord,
    RunnerMachineRecordError,
};
pub use limits::{RunnerMachineAuthLimits, RunnerMachineAuthLimitsError};
