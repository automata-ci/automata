use std::{io, path::PathBuf};

use automata_core::{LeaseGuard, OperationId, RunnerId, RunnerSessionId};
use automata_protocol::{CommandSequence, RunnerSlotOrdinal};
use thiserror::Error;

use crate::{OrphanAuthorityError, OutboundOperationSequence, ProviderOperationKind};

/// Rejected state-root configuration.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum StateRootError {
    #[error("runner state root must be an absolute path")]
    Relative,
    #[error("runner state root cannot be the filesystem root")]
    FilesystemRoot,
    #[error("runner state root contains a traversal component")]
    Traversal,
    #[error("runner state root cannot be placed in a system temporary hierarchy")]
    TemporaryHierarchy,
    #[error("XDG state home must be supplied explicitly and cannot be empty")]
    MissingXdgStateHome,
}

/// A semantic journal mutation would violate a recovery or fencing invariant.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum JournalInvariantError {
    #[error("journal belongs to runner {expected}; received {received}")]
    RunnerMismatch {
        expected: RunnerId,
        received: RunnerId,
    },
    #[error("no runner session is currently journaled")]
    NoSession,
    #[error("stale runner session: expected {expected}, received {received}")]
    SessionMismatch {
        expected: RunnerSessionId,
        received: RunnerSessionId,
    },
    #[error("a different session cannot replace active runner slots")]
    SessionHasActiveSlots,
    #[error("the resumed session disagrees with its durable protocol or JobIR selection")]
    SessionNegotiationMismatch,
    #[error("legacy journal state requires a fresh authorized session before lease polling")]
    LeasePollRecoveryRequired,
    #[error("runner slot ordinal {0:?} has no durable lease-poll checkpoint")]
    LeasePollCheckpointMissing(RunnerSlotOrdinal),
    #[error("lease-poll checkpoint expected operation {expected}; found {received}")]
    LeasePollCheckpointMismatch {
        expected: OperationId,
        received: OperationId,
    },
    #[error("lease-poll operation identity conflicts with another durable checkpoint")]
    LeasePollOperationConflict,
    #[error("runner slot ordinal {0:?} is not journaled")]
    SlotNotFound(RunnerSlotOrdinal),
    #[error("runner slot ordinal {0:?} already contains another lease")]
    SlotOccupied(RunnerSlotOrdinal),
    #[error("journal already contains the configured maximum number of slots")]
    SlotLimitReached,
    #[error("stale lease guard: expected {expected:?}, received {received:?}")]
    LeaseGuardMismatch {
        expected: LeaseGuard,
        received: LeaseGuard,
    },
    #[error("lease offer does not belong to this runner")]
    LeaseRunnerMismatch,
    #[error("lease schema or issued/expires interval is invalid")]
    InvalidLease,
    #[error("lease-offer JobIR version differs from the negotiated session version")]
    JobIrVersionMismatch,
    #[error("durable JobIR content reference has the wrong kind or exceeds its size limit")]
    InvalidJobIrContent,
    #[error("protected runtime authority has the wrong kind or exceeds its size limit")]
    InvalidRuntimeAuthorityContent,
    #[error("terminal-result content reference has the wrong kind or exceeds its size limit")]
    InvalidTerminalResultContent,
    #[error("lease expiration cannot regress")]
    LeaseExpiryRegression,
    #[error("server command sequence must be {expected:?}; received {received:?}")]
    CommandSequenceMismatch {
        expected: CommandSequence,
        received: CommandSequence,
    },
    #[error("durable command identity conflicts with an already journaled command")]
    CommandReplayConflict,
    #[error("command replay is older than the bounded digest tombstone window")]
    CommandReplayOutsideWindow,
    #[error("lease must be durably accepted before this operation")]
    OfferNotAccepted,
    #[error("lease offer was already accepted")]
    OfferAlreadyAccepted,
    #[error("lease offer was already rejected")]
    OfferAlreadyRejected,
    #[error("lease offer has no durable rejected response")]
    OfferNotRejected,
    #[error("rejected-offer response conflicts with the durable rejection")]
    LeaseRejectionReplayConflict,
    #[error("rejected-offer response acknowledgement has the wrong operation identity")]
    LeaseRejectionOperationMismatch,
    #[error("rejected-offer response is not yet durably acknowledged by the control plane")]
    LeaseRejectionNotAcknowledged,
    #[error("lease is already terminal")]
    LeaseTerminal,
    #[error("provider operation {kind:?} is not valid in the current recovery state")]
    InvalidProviderOperation { kind: ProviderOperationKind },
    #[error("another provider mutation intent must be completed before a new one is recorded")]
    ProviderOperationPending,
    #[error("provider operation identity conflicts with an existing intent")]
    ProviderOperationReplayConflict,
    #[error("sandbox creation has no matching durable provider-operation intent")]
    SandboxWithoutCreateIntent,
    #[error("sandbox identity conflicts with the already journaled identity")]
    SandboxIdentityConflict,
    #[error("terminal lifecycle must be committed atomically with its durable result outbox")]
    TerminalResultRequired,
    #[error("terminal result conflicts with the already journaled exact outbox record")]
    TerminalResultReplayConflict,
    #[error("a new terminal-result outbox record must begin unacknowledged")]
    TerminalResultAlreadyAcknowledgedInput,
    #[error("terminal-result acknowledgement has the wrong operation identity")]
    TerminalResultOperationMismatch,
    #[error("terminal result has not been durably acknowledged")]
    TerminalResultNotAcknowledged,
    #[error("outbound operation sequence must be {expected:?}; received {received:?}")]
    OutboundOperationSequenceMismatch {
        expected: OutboundOperationSequence,
        received: OutboundOperationSequence,
    },
    #[error("log stream identity conflicts with the already journaled stream")]
    LogStreamMismatch,
    #[error("log production sequence is not contiguous")]
    LogProductionGap,
    #[error("replayed log sequence disagrees about terminal-frame status")]
    LogProductionReplayConflict,
    #[error("log stream already contains its terminal frame")]
    LogStreamClosed,
    #[error("log spool content regressed or did not advance with the produced frame")]
    LogSpoolRegression,
    #[error("log spool content reference has the wrong kind or exceeds its size limit")]
    InvalidLogSpoolContent,
    #[error("log acknowledgement regresses or exceeds locally produced data")]
    InvalidLogAcknowledgement,
    #[error("slot cannot be released until its lease is terminal")]
    SlotNotTerminal,
    #[error("slot cannot be released until its log stream is closed and fully acknowledged")]
    LogDeliveryIncomplete,
    #[error("orphan authorization does not match the exact runner/session/slot/lease claim")]
    OrphanAuthorityMismatch,
    #[error("orphan delivery abandonment conflicts with its durable disposition")]
    OrphanAbandonmentConflict,
    #[error("orphan reconciliation was not authorized by the configured server authority")]
    OrphanNotAuthorized,
    #[error("numeric journal revision or cursor is exhausted")]
    CounterExhausted,
    #[error("provider name is empty, too long, or contains unsupported characters")]
    InvalidProviderName,
    #[error("sandbox handle is empty, too long, or is not an opaque identifier")]
    InvalidSandboxHandle,
    #[error("outbound operation sequences are one-based and fit signed durable storage")]
    InvalidOutboundOperationSequence,
    #[error("decoded journal exceeds a bounded collection limit")]
    DecodedCollectionLimit,
    #[error("decoded journal state is internally inconsistent")]
    DecodedStateInvalid,
    #[error("job lifecycle transition is invalid")]
    InvalidLifecycleTransition,
}

/// Typed I/O, schema, locking, and semantic failures from a journal.
#[derive(Debug, Error)]
pub enum JournalError {
    #[error(transparent)]
    StateRoot(#[from] StateRootError),
    #[error(transparent)]
    Invariant(#[from] JournalInvariantError),
    #[error(transparent)]
    OrphanAuthority(#[from] OrphanAuthorityError),
    #[error("another process already owns the runner journal lock")]
    AlreadyLocked,
    #[error("the runner journal has no filesystem adapter for this platform")]
    UnsupportedPlatform,
    #[error("journal path is a symlink, non-directory component, or escaped the configured root")]
    PathSecurity,
    #[error("journal file is larger than the {maximum}-byte limit: {received} bytes")]
    Oversized { maximum: usize, received: u64 },
    #[error("unsupported journal schema {received}; this build supports {supported}")]
    UnsupportedSchema { supported: u16, received: u16 },
    #[error("journal file is corrupt, truncated, or not in canonical form")]
    Corrupt,
    #[error("journal runner identity mismatch: expected {expected}, received {received}")]
    RunnerIdentityMismatch {
        expected: RunnerId,
        received: RunnerId,
    },
    #[error("journal commit outcome is unknown; close and reopen before continuing")]
    CommitOutcomeUnknown,
    #[error("journal is poisoned after an uncertain commit; close and reopen it")]
    Poisoned,
    #[error("commit fault injected at {0:?}")]
    InjectedFault(crate::CommitStage),
    #[error("journal I/O failed during {operation} at {path:?}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
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
