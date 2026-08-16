use automata_ci_core::{AttemptId, LeaseGuard, RunnerSessionId};
use automata_ci_protocol::{RemoteErrorCode, RunnerSlotOrdinal};
use automata_ci_runner_journal::JournalError;
use automata_ci_runner_spool::SpoolError;
use automata_ci_runner_transport::PrepareError;
use thiserror::Error;

use crate::{
    ExecutionEventError, ExecutorError, RuntimeControlError, content::CapacityReclaimError,
};

/// Protocol operation whose server implementation was explicitly unavailable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemotePhase {
    /// Lease acceptance or rejection.
    LeaseResponse,
    /// Post-accept runtime-authority request or acknowledgement.
    RuntimeAuthorityDelivery,
    /// Active-lease heartbeat and renewal.
    LeaseHeartbeat,
    /// Fenced lifecycle publication.
    JobState,
    /// Ordered log delivery.
    LogDelivery,
    /// Terminal-result commit.
    TerminalResult,
    /// Durable server-command acknowledgement.
    CommandAcknowledgement,
}

/// Sanitized failure from the runner session supervisor.
#[derive(Debug, Error)]
pub enum RunnerRuntimeError {
    /// Local shutdown cancelled the current operation.
    #[error("runner runtime shut down")]
    Shutdown,
    /// The control plane rejected session negotiation.
    #[error("runner handshake was rejected")]
    HandshakeRejected,
    /// A successful handshake returned an unexpected message.
    #[error("runner handshake returned an unexpected response")]
    UnexpectedHandshakeResponse,
    /// A sync operation returned an unexpected message kind.
    #[error("runner sync operation returned an unexpected response")]
    UnexpectedSyncResponse,
    /// A non-retryable transport failure occurred.
    #[error("runner control transport failed")]
    Client(#[source] RuntimeControlError),
    /// A local message could not be prepared canonically.
    #[error("runner request preparation failed")]
    Prepare(#[source] PrepareError),
    /// Durable runner state failed.
    #[error("runner journal operation failed")]
    Journal(#[source] JournalError),
    /// Protected payload storage failed.
    #[error("runner protected content operation failed")]
    Spool(#[source] SpoolError),
    /// Broker-signed Windows placement authority could not be refreshed.
    #[error("Windows placement renewal failed")]
    PlacementRenewal(#[source] crate::PlacementRenewalError),
    /// A standalone or durable protobuf payload was invalid.
    #[error("runner durable protobuf payload is invalid")]
    InvalidDurablePayload,
    /// Server command bytes conflict with their durable identity.
    #[error("server command replay conflicts with durable state")]
    CommandReplayConflict,
    /// The control plane invalidated the session fence.
    #[error("runner session is stale")]
    StaleSession,
    /// The server returned a non-retryable semantic error.
    #[error("control plane rejected a runner operation with {0:?}")]
    Remote(RemoteErrorCode),
    /// The current control-plane slice does not implement a required phase.
    #[error("control plane does not implement required runner phase {0:?}")]
    UnsupportedRemotePhase(RemotePhase),
    /// A new server session cannot replace locally recoverable work.
    #[error("server opened a new session while durable old-session work remains")]
    RecoveryAuthorizationRequired,
    /// A response was not exact authenticated authority for the retained old session.
    #[error("old-session recovery authority is invalid")]
    OrphanRecoveryAuthorityInvalid,
    /// The server did not permit abandoning every undeliverable old-session item.
    #[error("old-session recovery is missing an explicit delivery permission")]
    OrphanRecoveryPermissionMissing,
    /// `JobIR` required environment and executor selection differed exactly.
    #[error("executor environment attestation does not exactly match JobIR requirements")]
    EnvironmentAttestationMismatch,
    /// The executor violated its lifecycle/result contract.
    #[error("job executor violated the runtime contract")]
    ExecutorContract,
    /// An executor adapter failed without exposing raw provider diagnostics.
    #[error("job executor failed")]
    Executor(#[source] ExecutorError),
    /// A durable execution event failed.
    #[error("execution event could not be committed")]
    ExecutionEvent(#[source] ExecutionEventError),
    /// An accepted recovery phase has no safe generic continuation.
    #[error("accepted attempt has an unsupported recovery phase")]
    UnsupportedRecoveryPhase,
    /// An active lease expired according to the local monotonic watchdog.
    #[error("active lease expired locally")]
    LeaseExpired,
    /// Runtime authority was unusable at its fixed local validity boundary.
    #[error("job runtime authority expired locally")]
    AuthorityExpired,
    /// A recovered attempt identity did not match its durable lease.
    #[error("recovered attempt identity does not match its durable lease")]
    RecoveryIdentityMismatch {
        /// Attempt from the durable lease.
        attempt_id: AttemptId,
        /// Lease guard from the durable lease.
        guard: LeaseGuard,
        /// Durable runner session.
        session_id: RunnerSessionId,
        /// Stable local slot.
        slot: RunnerSlotOrdinal,
    },
}

impl From<JournalError> for RunnerRuntimeError {
    fn from(value: JournalError) -> Self {
        Self::Journal(value)
    }
}

impl From<SpoolError> for RunnerRuntimeError {
    fn from(value: SpoolError) -> Self {
        Self::Spool(value)
    }
}

impl From<PrepareError> for RunnerRuntimeError {
    fn from(value: PrepareError) -> Self {
        Self::Prepare(value)
    }
}

impl From<ExecutionEventError> for RunnerRuntimeError {
    fn from(value: ExecutionEventError) -> Self {
        Self::ExecutionEvent(value)
    }
}

impl CapacityReclaimError for RunnerRuntimeError {
    fn is_capacity_exhausted(&self) -> bool {
        matches!(self, Self::Spool(SpoolError::CapacityExhausted))
    }

    fn from_spool(error: SpoolError) -> Self {
        Self::Spool(error)
    }
}
