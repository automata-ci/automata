use std::{io, path::PathBuf};

use automata_ci_core::{LeaseGuard, OperationId, RunnerId, RunnerSessionId};
use automata_ci_protocol::{CommandSequence, RunnerSlotOrdinal};
use thiserror::Error;

use crate::{OrphanAuthorityError, OutboundOperationSequence, ProviderOperationKind};

/// Rejected state-root configuration.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum StateRootError {
    /// The configured root was not absolute.
    #[error("runner state root must be an absolute path")]
    Relative,
    /// The configured root was the filesystem root itself.
    #[error("runner state root cannot be the filesystem root")]
    FilesystemRoot,
    /// The configured path contained `.` or `..` traversal syntax.
    #[error("runner state root contains a traversal component")]
    Traversal,
    /// A path component placed durable state in a system temporary hierarchy.
    #[error("runner state root cannot be placed in a system temporary hierarchy")]
    TemporaryHierarchy,
    /// XDG-derived construction received no explicit state-home path.
    #[error("XDG state home must be supplied explicitly and cannot be empty")]
    MissingXdgStateHome,
}

/// A semantic journal mutation would violate a recovery or fencing invariant.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum JournalInvariantError {
    /// A mutation targeted a journal belonging to a different runner.
    #[error("journal belongs to runner {expected}; received {received}")]
    RunnerMismatch {
        /// Runner identity durably bound to the journal.
        expected: RunnerId,
        /// Runner identity supplied by the attempted mutation.
        received: RunnerId,
    },
    /// A session-scoped operation was attempted before a session was recorded.
    #[error("no runner session is currently journaled")]
    NoSession,
    /// A session-scoped operation presented a stale session fence.
    #[error("stale runner session: expected {expected}, received {received}")]
    SessionMismatch {
        /// Session identity currently bound to the journal.
        expected: RunnerSessionId,
        /// Session identity supplied by the attempted mutation.
        received: RunnerSessionId,
    },
    /// Active recoverable slots prevent replacing the durable session.
    #[error("a different session cannot replace active runner slots")]
    SessionHasActiveSlots,
    /// Resumption disagreed with the exact durable protocol or `JobIR` choice.
    #[error("the resumed session disagrees with its durable protocol or JobIR selection")]
    SessionNegotiationMismatch,
    /// No lease-poll checkpoint exists for the requested stable slot.
    #[error("runner slot ordinal {0:?} has no durable lease-poll checkpoint")]
    LeasePollCheckpointMissing(RunnerSlotOrdinal),
    /// Lease-poll advancement did not name the exact durable head operation.
    #[error("lease-poll checkpoint expected operation {expected}; found {received}")]
    LeasePollCheckpointMismatch {
        /// Operation at the current durable checkpoint head.
        expected: OperationId,
        /// Operation presented as the predecessor by the caller.
        received: OperationId,
    },
    /// A proposed lease-poll identity is already bound to another checkpoint.
    #[error("lease-poll operation identity conflicts with another durable checkpoint")]
    LeasePollOperationConflict,
    /// No durable lease occupies the requested stable slot.
    #[error("runner slot ordinal {0:?} is not journaled")]
    SlotNotFound(RunnerSlotOrdinal),
    /// The stable slot already holds a different durable lease.
    #[error("runner slot ordinal {0:?} already contains another lease")]
    SlotOccupied(RunnerSlotOrdinal),
    /// Creating another slot would exceed the journal's fixed slot ceiling.
    #[error("journal already contains the configured maximum number of slots")]
    SlotLimitReached,
    /// A lease-scoped mutation presented a stale attempt fence.
    #[error("stale lease guard: expected {expected:?}, received {received:?}")]
    LeaseGuardMismatch {
        /// Lease guard bound to the occupied slot.
        expected: LeaseGuard,
        /// Lease guard supplied by the attempted mutation.
        received: LeaseGuard,
    },
    /// The offered lease names a runner other than the journal owner.
    #[error("lease offer does not belong to this runner")]
    LeaseRunnerMismatch,
    /// Core lease validation rejected its schema or time interval.
    #[error("lease schema or issued/expires interval is invalid")]
    InvalidLease,
    /// The offered `JobIR` version differs from the session negotiation.
    #[error("lease-offer JobIR version differs from the negotiated session version")]
    JobIrVersionMismatch,
    /// The `JobIR` reference has the wrong content kind, is empty, or is too large.
    #[error("durable JobIR content reference has the wrong kind or exceeds its size limit")]
    InvalidJobIrContent,
    /// Runtime-authority content is empty, oversized, or has the wrong kind.
    #[error("protected runtime authority has the wrong kind or exceeds its size limit")]
    InvalidRuntimeAuthorityContent,
    /// Terminal-result content is empty, oversized, or has the wrong kind.
    #[error("terminal-result content reference has the wrong kind or exceeds its size limit")]
    InvalidTerminalResultContent,
    /// A delivery enqueue timestamp predates the epoch or exceeds year 9999.
    #[error("delivery enqueue timestamp is outside the supported Unix epoch range")]
    InvalidDeliveryEnqueuedAt,
    /// A renewal attempted to shorten the durable lease expiration.
    #[error("lease expiration cannot regress")]
    LeaseExpiryRegression,
    /// A server command did not immediately follow the contiguous durable cursor.
    #[error("server command sequence must be {expected:?}; received {received:?}")]
    CommandSequenceMismatch {
        /// Next contiguous command sequence required by the journal.
        expected: CommandSequence,
        /// Command sequence supplied by the attempted mutation.
        received: CommandSequence,
    },
    /// A replay reused a durable command position with different identity or effect.
    #[error("durable command identity conflicts with an already journaled command")]
    CommandReplayConflict,
    /// A replay predates the bounded retained command-digest window.
    #[error("command replay is older than the bounded digest tombstone window")]
    CommandReplayOutsideWindow,
    /// An operation requiring local lease acceptance was attempted too early.
    #[error("lease must be durably accepted before this operation")]
    OfferNotAccepted,
    /// A durable accepted offer cannot be reclassified as rejected.
    #[error("lease offer was already accepted")]
    OfferAlreadyAccepted,
    /// A durable rejected offer cannot be reclassified as accepted.
    #[error("lease offer was already rejected")]
    OfferAlreadyRejected,
    /// The slot has no durable rejected-offer response.
    #[error("lease offer has no durable rejected response")]
    OfferNotRejected,
    /// A replayed rejection disagrees with its durable reason or operation.
    #[error("rejected-offer response conflicts with the durable rejection")]
    LeaseRejectionReplayConflict,
    /// A rejection ACK did not name the exact durable response operation.
    #[error("rejected-offer response acknowledgement has the wrong operation identity")]
    LeaseRejectionOperationMismatch,
    /// Slot release was attempted before the exact rejection ACK was durable.
    #[error("rejected-offer response is not yet durably acknowledged by the control plane")]
    LeaseRejectionNotAcknowledged,
    /// A lifecycle mutation was attempted after the lease reached a terminal state.
    #[error("lease is already terminal")]
    LeaseTerminal,
    /// The provider recovery state does not permit the requested mutation kind.
    #[error("provider operation {kind:?} is not valid in the current recovery state")]
    InvalidProviderOperation {
        /// Provider mutation kind rejected by the recovery state machine.
        kind: ProviderOperationKind,
    },
    /// A prior provider intent remains unresolved and fences new intents.
    #[error("another provider mutation intent must be completed before a new one is recorded")]
    ProviderOperationPending,
    /// A provider operation identity was replayed with different semantics.
    #[error("provider operation identity conflicts with an existing intent")]
    ProviderOperationReplayConflict,
    /// Sandbox identity was recorded without the exact pending create intent.
    #[error("sandbox creation has no matching durable provider-operation intent")]
    SandboxWithoutCreateIntent,
    /// A replayed create result disagreed with the durable sandbox identity.
    #[error("sandbox identity conflicts with the already journaled identity")]
    SandboxIdentityConflict,
    /// A terminal lifecycle transition omitted its atomically paired result record.
    #[error("terminal lifecycle must be committed atomically with its durable result outbox")]
    TerminalResultRequired,
    /// A terminal-result replay disagreed with its durable operation or content.
    #[error("terminal result conflicts with the already journaled exact outbox record")]
    TerminalResultReplayConflict,
    /// New result input was already marked acknowledged instead of starting pending.
    #[error("a new terminal-result outbox record must begin unacknowledged")]
    TerminalResultAlreadyAcknowledgedInput,
    /// A result ACK did not name the exact durable outbox operation.
    #[error("terminal-result acknowledgement has the wrong operation identity")]
    TerminalResultOperationMismatch,
    /// Slot release was attempted before the result ACK became durable.
    #[error("terminal result has not been durably acknowledged")]
    TerminalResultNotAcknowledged,
    /// An outbound operation did not immediately follow the contiguous cursor.
    #[error("outbound operation sequence must be {expected:?}; received {received:?}")]
    OutboundOperationSequenceMismatch {
        /// Next contiguous outbound sequence required by the journal.
        expected: OutboundOperationSequence,
        /// Outbound sequence supplied by the attempted mutation.
        received: OutboundOperationSequence,
    },
    /// A log mutation named a stream other than the slot's durable stream.
    #[error("log stream identity conflicts with the already journaled stream")]
    LogStreamMismatch,
    /// A repeated log publication disagreed with durable segment metadata.
    #[error("replayed log segment publication conflicts with durable metadata")]
    LogSegmentReplayConflict,
    /// New log data was offered after a terminal frame became durable.
    #[error("log stream already contains its terminal frame")]
    LogStreamClosed,
    /// Log content has the wrong kind or violates the per-slot byte ceiling.
    #[error("log spool content reference has the wrong kind or exceeds its size limit")]
    InvalidLogSpoolContent,
    /// Segment sequences, counts, byte totals, or terminal flags are incoherent.
    #[error("log segment metadata is empty, non-contiguous, or otherwise incoherent")]
    InvalidLogSegment,
    /// Tail replacement or sealing did not name the exact current open content.
    #[error("log segment mutation does not match the exact current open tail")]
    LogSegmentMutationConflict,
    /// Retaining another immutable segment would exceed the per-slot count bound.
    #[error("log segment count exceeds the durable per-slot bound")]
    LogSegmentLimit,
    /// Retaining another log object would exceed the per-slot content-byte bound.
    #[error("durable log backlog exceeds the per-slot byte bound")]
    LogBacklogLimit,
    /// An ACK regressed or named log data not yet produced locally.
    #[error("log acknowledgement regresses or exceeds locally produced data")]
    InvalidLogAcknowledgement,
    /// An ACK did not match the exact sealed head or retained replay witness.
    #[error("log acknowledgement conflicts with the sealed durable head or replay witness")]
    LogAcknowledgementConflict,
    /// Slot release was attempted before a terminal lifecycle was durable.
    #[error("slot cannot be released until its lease is terminal")]
    SlotNotTerminal,
    /// Slot release was attempted before terminal log delivery completed.
    #[error("slot cannot be released until its log stream is closed and fully acknowledged")]
    LogDeliveryIncomplete,
    /// An orphan grant did not match the exact runner/session/slot/lease fence.
    #[error("orphan authorization does not match the exact runner/session/slot/lease claim")]
    OrphanAuthorityMismatch,
    /// A repeated abandonment changed the durable reason for the same delivery.
    #[error("orphan delivery abandonment conflicts with its durable disposition")]
    OrphanAbandonmentConflict,
    /// Old-session reconciliation lacked an authenticated server grant.
    #[error("orphan reconciliation was not authorized by the configured server authority")]
    OrphanNotAuthorized,
    /// A durable revision or operation cursor can no longer advance safely.
    #[error("numeric journal revision or cursor is exhausted")]
    CounterExhausted,
    /// A provider identifier was empty, oversized, or outside its closed syntax.
    #[error("provider name is empty, too long, or contains unsupported characters")]
    InvalidProviderName,
    /// A sandbox handle was empty, oversized, or resembled a path or credential.
    #[error("sandbox handle is empty, too long, or is not an opaque identifier")]
    InvalidSandboxHandle,
    /// An outbound operation sequence was zero or exceeded signed durable storage.
    #[error("outbound operation sequences are one-based and fit signed durable storage")]
    InvalidOutboundOperationSequence,
    /// Decoded data exceeded a fixed collection ceiling before use.
    #[error("decoded journal exceeds a bounded collection limit")]
    DecodedCollectionLimit,
    /// Decoded current-schema data violated an internal recovery invariant.
    #[error("decoded journal state is internally inconsistent")]
    DecodedStateInvalid,
    /// The requested lifecycle edge is not allowed by the shared state machine.
    #[error("job lifecycle transition is invalid")]
    InvalidLifecycleTransition,
}

/// Typed I/O, schema, locking, and semantic failures from a journal.
///
/// Provider and authority failures are deliberately closed, secret-free
/// classifications. The [`Self::Io`] variant retains a local operator path and
/// source error and should be sanitized before crossing an untrusted boundary.
#[derive(Debug, Error)]
pub enum JournalError {
    /// State-root configuration failed before filesystem access.
    #[error(transparent)]
    StateRoot(#[from] StateRootError),
    /// A requested or decoded state transition violated a recovery invariant.
    #[error(transparent)]
    Invariant(#[from] JournalInvariantError),
    /// The configured orphan authority rejected or could not verify a proof.
    #[error(transparent)]
    OrphanAuthority(#[from] OrphanAuthorityError),
    /// Another process holds the exclusive journal lock.
    #[error("another process already owns the runner journal lock")]
    AlreadyLocked,
    /// This target has no containment-preserving file adapter.
    #[error("the runner journal has no filesystem adapter for this platform")]
    UnsupportedPlatform,
    /// Descriptor-relative path validation detected a symlink or root escape.
    #[error("journal path is a symlink, non-directory component, or escaped the configured root")]
    PathSecurity,
    /// The journal file exceeded the pre-allocation decode ceiling.
    #[error("journal file is larger than the {maximum}-byte limit: {received} bytes")]
    Oversized {
        /// Maximum encoded bytes accepted by this build.
        maximum: usize,
        /// Encoded file size observed before allocation or decoding.
        received: u64,
    },
    /// The file uses a future schema for which this build has no decoder.
    #[error("unsupported journal schema {received}; this build supports {supported}")]
    UnsupportedSchema {
        /// Current and only schema accepted by this build.
        supported: u16,
        /// Schema number found in the journal envelope.
        received: u16,
    },
    /// A pre-current schema was found and must be discarded by the operator.
    #[error("an obsolete runner journal file is present; remove the state root before startup")]
    ObsoleteState,
    /// Current-schema bytes were truncated, non-canonical, or structurally invalid.
    #[error("journal file is corrupt, truncated, or not in canonical form")]
    Corrupt,
    /// The opened file belongs to a runner other than the configured runner.
    #[error("journal runner identity mismatch: expected {expected}, received {received}")]
    RunnerIdentityMismatch {
        /// Runner identity read from durable state.
        expected: RunnerId,
        /// Runner identity supplied while opening the adapter.
        received: RunnerId,
    },
    /// Rename occurred but directory durability could not be established.
    ///
    /// The caller must close and reopen instead of retrying through this handle.
    #[error("journal commit outcome is unknown; close and reopen before continuing")]
    CommitOutcomeUnknown,
    /// The handle cannot safely mutate after an uncertain commit or poisoned lock.
    #[error("journal is poisoned after an uncertain commit; close and reopen it")]
    Poisoned,
    /// A trusted test hook interrupted a commit at the named boundary.
    #[error("commit fault injected at {0:?}")]
    InjectedFault(crate::CommitStage),
    /// A local filesystem operation failed with a known pre-publication outcome.
    #[error("journal I/O failed during {operation} at {path:?}: {source}")]
    Io {
        /// Fixed operation label identifying the failed filesystem step.
        operation: &'static str,
        /// Local operator path associated with the failure.
        path: PathBuf,
        /// Underlying operating-system error.
        #[source]
        source: io::Error,
    },
}

impl JournalError {
    pub(crate) fn io(operation: &'static str, path: PathBuf, source: io::Error) -> Self {
        Self::Io {
            operation,
            path,
            source,
        }
    }
}
