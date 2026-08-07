#![forbid(unsafe_code)]
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

pub use automata_runner_spool::{ContentKind, DurableContentRef};
pub use content_retention::JournalContentRetainSet;
pub use error::{JournalError, JournalInvariantError, StateRootError};
pub use file::{
    CommitFault, CommitFaultInjector, CommitStage, FileJournal, FileJournalOptions, NoCommitFaults,
    StateRoot,
};
pub use journal::RunnerJournal;
pub use model::{
    CancellationRecord, CommandDisposition, CommandIgnoredReason, CommandTombstone, DurableCommand,
    JobIrContentRef, JournalSnapshot, LeaseOfferRecord, LeaseOfferStatus, LeasePollCheckpoint,
    LeaseRejectionRecord, LogDeliveryCursor, LogProductionRecord, OrphanAbandonmentPermissions,
    OrphanAbandonmentReason, OrphanAuthorityError, OrphanAuthorityGrant, OrphanAuthorityProof,
    OrphanAuthorityVerifier, OrphanClaim, OrphanDelivery, OrphanRecord, OutboundOperationCursor,
    OutboundOperationSequence, ProviderFailureKind, ProviderFailureOutcome, ProviderName,
    ProviderOperation, ProviderOperationKind, ProviderOperationOutcome, RuntimeAuthorityContentRef,
    SandboxHandle, SandboxIdentity, SessionBinding, SessionSnapshot, SlotSnapshot,
    TerminalResultRecord,
};

/// Current schema of the local runner journal.
pub const RUNNER_JOURNAL_SCHEMA_VERSION: u16 = 4;

/// Hard ceiling applied before allocating or decoding a journal file.
pub const MAX_JOURNAL_BYTES: usize = 16 * 1024 * 1024;

/// Defensive upper bound for configured runner slots.
pub const MAX_JOURNALED_SLOTS: usize = 256;

/// Maximum recent provider operations retained for exact replay.
pub const MAX_PROVIDER_OPERATIONS_PER_SLOT: usize = 32;

/// Maximum recent server-command digest tombstones retained per session.
pub const MAX_COMMAND_TOMBSTONES: usize = 256;

/// Maximum durable canonical `JobIR` payload size.
pub const MAX_JOB_IR_CONTENT_BYTES: u64 = 16 * 1024 * 1024;

/// Maximum durable protected runtime-authority payload size.
pub const MAX_RUNTIME_AUTHORITY_CONTENT_BYTES: u64 = 512 * 1024;

/// Maximum durable canonical terminal-result payload size.
pub const MAX_TERMINAL_RESULT_CONTENT_BYTES: u64 = 4 * 1024 * 1024;

/// Maximum cumulative durable log-spool payload size per slot.
pub const MAX_LOG_SPOOL_CONTENT_BYTES: u64 = 256 * 1024 * 1024;

/// Clamps a runner registration to the journal's coherent durable slot bound.
#[must_use]
pub fn clamp_registration_slots(requested: u16) -> u16 {
    requested.min(u16::try_from(MAX_JOURNALED_SLOTS).unwrap_or(u16::MAX))
}
