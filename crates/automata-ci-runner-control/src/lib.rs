#![forbid(unsafe_code)]
#![deny(missing_docs)]
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

mod handler;
mod observer;
mod port;
mod verify;

pub use handler::{
    DurableRunnerControlHandler, JOB_RESULT_MEDIA_TYPE, LOG_SEGMENT_MEDIA_TYPE,
    MAX_HEARTBEAT_INTERVAL_MILLIS, MAX_LEASE_DURATION_MILLIS, MAX_NO_WORK_RETRY_AFTER_MILLIS,
    RunnerControlConfig, RunnerControlConfigError, RunnerControlPorts, RunnerDurabilityPorts,
    RunnerIdentityPorts, RunnerLeasePorts,
};
pub use observer::{
    LeaseOfferObservation, NoopRunnerControlObserver, RunnerControlFailure,
    RunnerControlMessageKind, RunnerControlMessageOutcome, RunnerControlObserver,
    RunnerDurableDisposition, RunnerDurableMessageKind, RunnerHandshakeOutcome,
    RunnerHandshakeRejection,
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
