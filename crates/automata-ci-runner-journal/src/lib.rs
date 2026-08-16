#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Crash-durable local state for an Automata runner.
//!
//! The journal stores semantic identifiers, immutable digests, provider
//! operation intentions, and recovery cursors. It deliberately knows nothing
//! about a transport encoding, provider credentials, or job payloads. The file
//! adapter uses a canonical, bounded JSON schema rather than a Rust memory
//! representation.

mod content_retention;
mod error;
mod file;
mod journal;
mod model;
mod observer;

pub use automata_ci_runner_spool::{ContentKind, DurableContentRef};
pub use content_retention::JournalContentRetainSet;
pub use error::{JournalError, JournalInvariantError, StateRootError};
pub use file::{
    CommitFault, CommitFaultInjector, CommitStage, FileJournal, FileJournalOptions, NoCommitFaults,
    StateRoot,
};
pub use journal::RunnerJournal;
pub use model::{
    CancellationRecord, CommandDisposition, CommandIgnoredReason, CommandTombstone, DurableCommand,
    EndpointOperation, EndpointOperationKind, EndpointOperationState, EndpointRequestContentRef,
    EndpointResultContentRef, JobIrContentRef, JournalSnapshot, LeaseOfferRecord, LeaseOfferStatus,
    LeasePollCheckpoint, LeaseRejectionRecord, LogDeliveryCursor, LogSegment,
    LogSegmentAcknowledgement, LogSegmentPublication, OrphanAbandonmentPermissions,
    OrphanAbandonmentReason, OrphanAuthorityError, OrphanAuthorityGrant, OrphanAuthorityProof,
    OrphanAuthorityVerifier, OrphanClaim, OrphanDelivery, OrphanRecord, OutboundOperationCursor,
    OutboundOperationSequence, PendingDeliveryTimestamps, ProviderFailureKind,
    ProviderFailureOutcome, ProviderName, ProviderOperation, ProviderOperationKind,
    ProviderOperationOutcome, RuntimeAuthorityContentRef, RuntimeAuthorityDeliveryRecord,
    SandboxHandle, SandboxIdentity, SessionBinding, SessionSnapshot, SlotSnapshot,
    TerminalResultRecord,
};
pub use observer::{
    JournalMutationDomain, JournalMutationObservation, JournalMutationOutcome, JournalObserver,
    NoopJournalObserver,
};

/// Current and only supported schema of the local runner journal.
///
/// Obsolete or future schemas fail closed rather than being interpreted by
/// compatibility readers.
pub const RUNNER_JOURNAL_SCHEMA_VERSION: u16 = 6;

/// Largest delivery enqueue timestamp accepted by the durable journal.
///
/// The bound is the final millisecond of year 9999 UTC. Together with the
/// Unix-epoch lower bound, it prevents corrupt or untrusted state from
/// producing unbounded metric ages while covering every operational date.
pub const MAX_DELIVERY_ENQUEUED_AT_MILLIS: i64 = 253_402_300_799_999;

/// Hard ceiling applied before allocating or decoding a journal file.
pub const MAX_JOURNAL_BYTES: usize = 16 * 1024 * 1024;

/// Defensive upper bound for configured runner slots.
pub const MAX_JOURNALED_SLOTS: usize = 256;

/// Maximum recent provider operations retained for exact replay.
pub const MAX_PROVIDER_OPERATIONS_PER_SLOT: usize = 32;

/// Maximum protected execution-endpoint request/result references per slot.
pub(crate) const MAX_ENDPOINT_CONTENT_REFS_PER_SLOT: usize =
    automata_ci_execution::MAX_ENDPOINT_OPERATIONS_PER_JOB * 2;

/// Maximum protected result object for one execution-endpoint operation.
pub(crate) const MAX_ENDPOINT_RESULT_CONTENT_BYTES: u64 = 17 * 1024 * 1024;

/// Exact protected request commitment retained for every endpoint operation.
pub(crate) const ENDPOINT_REQUEST_COMMITMENT_BYTES: u64 = 32;

/// Smallest opaque protected allocation retained by an endpoint result.
pub(crate) const MIN_ENDPOINT_RESULT_ALLOCATION_BYTES: u64 = endpoint_result_allocation_or_panic(1);

/// Largest opaque protected allocation retained by an endpoint result.
pub(crate) const MAX_ENDPOINT_RESULT_ALLOCATION_BYTES: u64 =
    endpoint_result_allocation_or_panic(MAX_ENDPOINT_RESULT_CONTENT_BYTES);

/// Maximum aggregate endpoint content charged to one slot.
///
/// This admits the maximum shared endpoint-operation count when every retained
/// result is in the smallest protected allocation class, while still reserving
/// the largest result class for the sole operation allowed to be in flight.
/// Larger cumulative retained output fails closed before a successor backend
/// invocation.
pub(crate) const MAX_ENDPOINT_CONTENT_BYTES_PER_SLOT: u64 = ENDPOINT_REQUEST_COMMITMENT_BYTES
    * automata_ci_execution::MAX_ENDPOINT_OPERATIONS_PER_JOB as u64
    + MIN_ENDPOINT_RESULT_ALLOCATION_BYTES
        * (automata_ci_execution::MAX_ENDPOINT_OPERATIONS_PER_JOB as u64 - 1)
    + MAX_ENDPOINT_RESULT_ALLOCATION_BYTES;

const fn endpoint_result_allocation_or_panic(plaintext_bytes: u64) -> u64 {
    match automata_ci_runner_spool::endpoint_result_allocation(plaintext_bytes) {
        Ok(bytes) => bytes,
        Err(_) => panic!("endpoint result bound must fit the protected spool"),
    }
}

/// Maximum recent server-command digest tombstones retained per session.
pub const MAX_COMMAND_TOMBSTONES: usize = 256;

/// Maximum durable canonical `JobIR` payload size.
pub const MAX_JOB_IR_CONTENT_BYTES: u64 = 16 * 1024 * 1024;

/// Maximum durable protected runtime-authority payload size.
pub const MAX_RUNTIME_AUTHORITY_CONTENT_BYTES: u64 = 512 * 1024;

/// Maximum durable canonical terminal-result payload size.
pub const MAX_TERMINAL_RESULT_CONTENT_BYTES: u64 = 4 * 1024 * 1024;

/// Maximum aggregate durable log-segment content size per slot.
pub const MAX_LOG_SPOOL_CONTENT_BYTES: u64 = 256 * 1024 * 1024;

/// Maximum immutable log segments retained by one slot.
pub const MAX_LOG_SEGMENTS_PER_SLOT: usize = 128;

/// Maximum logical frames described by one immutable segment.
pub const MAX_LOG_SEGMENT_FRAMES: usize = 4_096;

/// Clamps a runner registration to the journal's coherent durable slot bound.
#[must_use]
pub fn clamp_registration_slots(requested: u16) -> u16 {
    requested.min(u16::try_from(MAX_JOURNALED_SLOTS).unwrap_or(u16::MAX))
}

pub(crate) fn validate_delivery_enqueued_at(
    value: automata_ci_core::UnixMillis,
) -> Result<(), JournalInvariantError> {
    if (0..=MAX_DELIVERY_ENQUEUED_AT_MILLIS).contains(&value.get()) {
        Ok(())
    } else {
        Err(JournalInvariantError::InvalidDeliveryEnqueuedAt)
    }
}
