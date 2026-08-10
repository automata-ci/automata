#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Provider-neutral application domain for scheduling Automata work.
//!
//! This crate contains no database, transport, clock, or executor adapter. It
//! makes the control-plane trust boundary explicit: runner-reported evidence is
//! not schedulable until server policy has reduced it to an [`EffectiveRunner`],
//! and workflow requirements enter scheduling as server-owned
//! [`RoutingRequirements`].
//!
//! Persistence idempotency deliberately stays outside scheduler candidates and
//! decisions: one lease poll may evaluate many mutually exclusive candidates
//! under one durable request key.

mod candidate;
mod capabilities;
mod decision;
mod idempotency;
mod input;
mod policy;
mod routing;
mod runner;

pub use candidate::RunnableCandidate;
pub use capabilities::{RunnerCapabilityIntersectionError, intersect_runner_capabilities};
pub use decision::{
    CandidateCapacity, CandidateDecline, CandidateDeclineReason, Placement, PlacementDecision,
    PlacementDecline, RunnerRequirementDecline,
};
pub use idempotency::{
    IdempotencyGuard, OPERATION_REQUEST_DIGEST_BYTES, OPERATION_REQUEST_DIGEST_HEX_LENGTH,
    OperationRequestDigest, OperationRequestDigestError,
};
pub use input::{PlacementFactoryError, SchedulingInput, SchedulingInputError};
pub use policy::{DeterministicScheduler, SchedulerPolicy, classify_candidate_capacity};
pub use routing::{RoutingRequirements, RoutingRequirementsError};
pub use runner::{
    AuthorizedRunnerRouting, EffectiveRunner, EffectiveRunnerError, RunnerEvidence,
    RunnerEvidenceError, RunnerSlot, RunnerSlotError, SessionGuard,
};
