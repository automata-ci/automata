//! Replica-neutral application handling for the authenticated runner-control transport.
//!
//! The handler deliberately owns no connection or replica-local authorization state. Every
//! operation re-authorizes the mTLS machine and reloads an exact durable session fence.
//!
//! Lease rejection policy is intentionally explicit: `capacity_changed`, `capability_changed`,
//! and `shutting_down` are transient and requeue an attempt while advancing its lease-failure
//! count; `invalid_job` concludes it as failed. Acceptance moves only the exact published,
//! session/slot/guard-correlated offer from leased to preparing. Heartbeats are the authoritative
//! progress channel, so the redundant `JobState` wire variant remains unsupported in G1.
//!
//! Log and result bytes are uploaded under deterministic immutable keys before their `PostgreSQL`
//! metadata transaction. A crash in that interval can leave only an unreachable object; retrying
//! uses the same key, digest, and bytes. `PostgreSQL` then commits the fenced lifecycle/metadata and
//! exact response receipt together, preventing visible partial ingestion.

/// Startup checks for durable runner capabilities used by this control plane.
pub mod capability_admission;
/// Durable models and repositories for authenticated runner-control operations.
pub mod durable;
mod handler;
mod observer;
mod port;
/// Durable runner sessions, operation receipts, and command delivery repositories.
pub mod repository;
mod verify;

pub use automata_ci_protocol::{
    INITIAL_RUNTIME_AUTHORITY_GENERATION, RuntimeAuthorityDeliveryBinding,
};
pub use durable::{
    AcceptedRuntimeAuthorityOffer, AcknowledgeRuntimeAuthorityDelivery,
    AuthorizeRuntimeAuthorityDelivery, CommitRuntimeAuthorityDelivery,
    RuntimeAuthorityDeliveryAdmission, RuntimeAuthorityDeliveryDisposition,
    RuntimeAuthorityDeliveryRepository, RuntimeAuthorityOfferCommand,
};
pub use handler::{
    DurableRunnerControlHandler, LOG_SEGMENT_MEDIA_TYPE, MAX_HEARTBEAT_INTERVAL_MILLIS,
    MAX_LEASE_DURATION_MILLIS, MAX_NO_WORK_RETRY_AFTER_MILLIS, RunnerControlConfig,
    RunnerControlConfigError, RunnerControlPorts, RunnerDurabilityPorts, RunnerIdentityPorts,
    RunnerLeasePorts,
};
pub use observer::{
    LeaseOfferObservation, RunnerControlFailure, RunnerControlMessageKind,
    RunnerControlMessageOutcome, RunnerControlObserver, RunnerDurableDisposition,
    RunnerDurableMessageKind, RunnerHandshakeOutcome, RunnerHandshakeRejection,
    RunnerLeaseRequestStage, RunnerRuntimeAuthorityRequestStage,
};
pub use port::{
    AuthorizedRunnerRegistration, CompositeRuntimeAuthorityIssuer, ControlIdGenerator,
    ControlPortError, DesiredRunnerState, ImmutableBlobJobIrReader, JOB_IR_PROTOBUF_MEDIA_TYPE,
    JobIrObjectReader, LeaseOfferClaim, LeaseOfferClaimStatus, LeaseOfferCommand,
    LeaseOfferCommandError, LeaseOfferCommandPublisher, LeaseOfferPublishOutcome,
    LeaseOfferReplayResolution, LeasePollAdapter, LeasePoller, ManagedSecretBindingIssuer,
    OptionalRuntimeAuthorityIssuer, PublishedCommand, RandomControlIdGenerator,
    RunnerRegistrationAuthorizer, RunnerSessionFenceResolver, RuntimeAuthorityIssueRequest,
    RuntimeAuthorityIssueRequestError, RuntimeAuthorityIssuer, StoreLeaseOfferCommandPublisher,
    StoreRunnerSessionFenceResolver,
};
pub use verify::{JobIrBlobError, verify_job_ir_blob};
