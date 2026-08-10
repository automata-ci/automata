use std::{fmt, time::Duration};

use automata_ci_core::JobConclusion;
use automata_ci_protocol::{RemoteErrorCode, RunnerToServer};
use automata_ci_runner_transport::PreparedRequest;

use crate::{ExecutorErrorKind, RuntimeControlErrorKind};

/// Finite runner-control exchange kinds visible to runtime observers.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuntimeExchangeKind {
    /// Session negotiation or resumption.
    Handshake,
    /// One stable-slot long poll.
    LeasePoll,
    /// Lease acceptance or rejection delivery.
    LeaseResponse,
    /// Active-lease heartbeat and renewal.
    Heartbeat,
    /// Non-terminal job lifecycle publication.
    JobState,
    /// Terminal job-result delivery.
    JobResult,
    /// Ordered log delivery.
    LogBatch,
    /// Cumulative durable-command acknowledgement.
    CommandAck,
}

impl RuntimeExchangeKind {
    pub(crate) const fn from_prepared(request: &PreparedRequest) -> Self {
        match request.message() {
            RunnerToServer::Hello(_) => Self::Handshake,
            RunnerToServer::LeaseRequest(_) => Self::LeasePoll,
            RunnerToServer::LeaseResponse(_) => Self::LeaseResponse,
            RunnerToServer::Heartbeat(_) => Self::Heartbeat,
            RunnerToServer::JobState(_) => Self::JobState,
            RunnerToServer::JobResult(_) => Self::JobResult,
            RunnerToServer::LogBatch(_) => Self::LogBatch,
            RunnerToServer::CommandAck(_) => Self::CommandAck,
        }
    }
}

/// Sanitized reason for scheduling an exact-request retry backoff.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuntimeRetryCause {
    /// The peer or transport was unavailable.
    Unavailable,
    /// The request deadline elapsed.
    TimedOut,
    /// The response violated the transport or protocol contract.
    InvalidResponse,
    /// The control plane returned a retryable typed error response.
    RemoteResponse,
}

impl RuntimeRetryCause {
    pub(crate) const fn from_control_error(value: RuntimeControlErrorKind) -> Option<Self> {
        match value {
            RuntimeControlErrorKind::Unavailable => Some(Self::Unavailable),
            RuntimeControlErrorKind::TimedOut => Some(Self::TimedOut),
            RuntimeControlErrorKind::Cancelled => None,
            RuntimeControlErrorKind::InvalidResponse => Some(Self::InvalidResponse),
        }
    }
}

/// Bounded operator-facing category for a typed control-plane error response.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuntimeRemoteErrorKind {
    /// The request or stable slot was invalid.
    InvalidRequest,
    /// The peer rejected a protocol or `JobIR` compatibility boundary.
    Compatibility,
    /// Authentication or authorization failed.
    Authentication,
    /// The durable session was absent or stale.
    Session,
    /// Idempotency, command-cursor, or generic state conflict.
    OperationConflict,
    /// The requested lease did not exist.
    LeaseNotFound,
    /// The lease fencing token was stale.
    StaleFencingToken,
    /// The peer explicitly requested a later retry.
    RetryLater,
    /// The peer reported an internal failure.
    Internal,
}

impl From<RemoteErrorCode> for RuntimeRemoteErrorKind {
    fn from(value: RemoteErrorCode) -> Self {
        match value {
            RemoteErrorCode::InvalidMessage | RemoteErrorCode::InvalidSlot => Self::InvalidRequest,
            RemoteErrorCode::UnsupportedProtocol | RemoteErrorCode::UnsupportedJobIr => {
                Self::Compatibility
            }
            RemoteErrorCode::Unauthenticated | RemoteErrorCode::Unauthorized => {
                Self::Authentication
            }
            RemoteErrorCode::SessionNotFound | RemoteErrorCode::StaleSession => Self::Session,
            RemoteErrorCode::OperationKeyReused
            | RemoteErrorCode::CommandCursorConflict
            | RemoteErrorCode::Conflict => Self::OperationConflict,
            RemoteErrorCode::LeaseNotFound => Self::LeaseNotFound,
            RemoteErrorCode::StaleFencingToken => Self::StaleFencingToken,
            RemoteErrorCode::RetryLater => Self::RetryLater,
            RemoteErrorCode::Internal => Self::Internal,
        }
    }
}

/// Whether the runtime will retry or terminate after a typed remote error.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuntimeRemoteErrorDisposition {
    /// The same prepared request will be retried after a bounded delay.
    Retrying,
    /// The current operation or session terminates without a retry.
    Terminal,
}

/// Whether a handshake requested a new session or resumed durable state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuntimeSessionMode {
    /// No durable session claim was sent.
    Fresh,
    /// A durable session and command cursor were presented.
    Resume,
}

/// Closed semantic result of one high-level handshake exchange.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuntimeSessionOutcome {
    /// The server opened a new session.
    Opened,
    /// The server resumed the claimed session.
    Resumed,
    /// The server rejected the handshake.
    Rejected,
    /// A transport-level exchange failed terminally.
    ExchangeError,
    /// The response was valid transport data but not a handshake response.
    UnexpectedResponse,
}

/// Why the runtime abandoned a negotiated session and started another handshake.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuntimeReconnectReason {
    /// The control plane declared the current session stale or missing.
    StaleSession,
}

/// Semantic result of a stable-slot lease poll.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuntimeLeasePollOutcome {
    /// No eligible work was available.
    NoWork,
    /// The response carried a durable lease offer command.
    LeaseOffer,
    /// The response carried a durable cancellation command.
    Cancellation,
}

/// Acknowledged runner disposition for one lease offer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuntimeLeaseDisposition {
    /// The exact offered lease was accepted.
    Accepted,
    /// The exact offered lease was rejected.
    Rejected,
}

/// Durable server-command kind understood by this runtime.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuntimeCommandKind {
    /// A lease offer command.
    LeaseOffer,
    /// A job cancellation command.
    Cancellation,
}

/// Durable classification of one received server command.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuntimeCommandOutcome {
    /// A new command was durably applied.
    Applied,
    /// An already durable command was verified and replayed.
    Replayed,
    /// The command was durably ignored because its content was invalid.
    IgnoredInvalid,
    /// The command was durably ignored because its target slot was unavailable.
    IgnoredSlotUnavailable,
    /// The command was durably ignored because its target lease was stale.
    IgnoredStaleLease,
}

/// Whether an executor invocation starts fresh work or resumes durable work.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuntimeJobStartMode {
    /// Execution began from the preparing lifecycle.
    Fresh,
    /// Execution reattached to a later non-terminal durable lifecycle.
    Recovered,
}

/// Identifier-free terminal job conclusion.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuntimeJobConclusion {
    /// The job succeeded.
    Success,
    /// The job failed.
    Failure,
    /// The job was cancelled.
    Cancelled,
    /// The job timed out.
    TimedOut,
    /// The job was skipped.
    Skipped,
}

impl From<JobConclusion> for RuntimeJobConclusion {
    fn from(value: JobConclusion) -> Self {
        match value {
            JobConclusion::Success => Self::Success,
            JobConclusion::Failure => Self::Failure,
            JobConclusion::Cancelled => Self::Cancelled,
            JobConclusion::TimedOut => Self::TimedOut,
            JobConclusion::Skipped => Self::Skipped,
        }
    }
}

/// Sanitized platform-infrastructure failure category.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuntimeInfrastructureFailure {
    /// The admitted job was invalid.
    InvalidJob,
    /// The executor does not support required semantics.
    Unsupported,
    /// A provider resource limit was exhausted.
    ResourceExhausted,
    /// Provider access was denied.
    PermissionDenied,
    /// A provider dependency was unavailable.
    Unavailable,
    /// Provider work timed out.
    TimedOut,
    /// The executor returned cancellation as an error.
    Cancelled,
    /// An executor invariant failed.
    Internal,
    /// The spawned executor task terminated unexpectedly.
    TaskTerminated,
    /// The executor failed to quiesce during the cancellation grace period.
    CancellationTimeout,
    /// Runtime authority expired before or during executor use.
    AuthorityExpired,
}

impl From<ExecutorErrorKind> for RuntimeInfrastructureFailure {
    fn from(value: ExecutorErrorKind) -> Self {
        match value {
            ExecutorErrorKind::InvalidJob => Self::InvalidJob,
            ExecutorErrorKind::Unsupported => Self::Unsupported,
            ExecutorErrorKind::ResourceExhausted => Self::ResourceExhausted,
            ExecutorErrorKind::PermissionDenied => Self::PermissionDenied,
            ExecutorErrorKind::Unavailable => Self::Unavailable,
            ExecutorErrorKind::TimedOut => Self::TimedOut,
            ExecutorErrorKind::Cancelled => Self::Cancelled,
            ExecutorErrorKind::Internal => Self::Internal,
        }
    }
}

/// Closed reason for signalling a running executor to cancel.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuntimeCancellationReason {
    /// A newly applied server cancellation requested it.
    ServerRequest,
    /// The fixed runtime-authority validity ceiling elapsed.
    AuthorityExpired,
    /// The local monotonic lease watchdog expired.
    LeaseExpired,
    /// The negotiated session became stale.
    SessionLost,
    /// A non-session control-cycle failure forced the executor to quiesce.
    ControlFailure,
    /// The runner process began shutting down.
    Shutdown,
}

/// Stage in the durable terminal-result delivery lifecycle.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuntimeTerminalResultStage {
    /// The canonical result was durably committed to journal and protected spool.
    Committed,
    /// The control plane acknowledged the exact canonical result.
    Acknowledged,
}

/// Closed result shared by cleanup and recovery observations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuntimeOperationOutcome {
    /// The operation completed successfully.
    Success,
    /// The operation returned a sanitized failure.
    Error,
    /// Process shutdown cancelled the operation.
    Cancelled,
}

/// One identifier-free semantic event emitted by the runner runtime.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RunnerRuntimeEvent {
    /// An exact-request retry policy scheduled a delay.
    RetryBackoff {
        /// Stable request kind.
        exchange: RuntimeExchangeKind,
        /// Sanitized retry cause.
        cause: RuntimeRetryCause,
        /// Requested backoff duration.
        delay: Duration,
    },
    /// A previously scheduled retry is about to repeat the same prepared request.
    RetryAttempt {
        /// Stable request kind.
        exchange: RuntimeExchangeKind,
    },
    /// One high-level handshake exchange completed.
    SessionHandshake {
        /// Fresh or resume request mode.
        mode: RuntimeSessionMode,
        /// Semantic response classification.
        outcome: RuntimeSessionOutcome,
        /// Process-monotonic elapsed time, including exact-request retries.
        duration: Duration,
    },
    /// A negotiated session is fully bound to local durable state and usable.
    SessionConnected {
        /// Signed server-minus-local wall-clock offset at handshake completion.
        server_clock_offset_millis: i64,
    },
    /// The previously usable session is no longer serving slot work.
    SessionDisconnected,
    /// The runtime began reconnecting after losing a session.
    Reconnect {
        /// Closed reconnect reason.
        reason: RuntimeReconnectReason,
    },
    /// The peer returned a typed semantic error response.
    RemoteError {
        /// Stable request kind that received the response.
        exchange: RuntimeExchangeKind,
        /// Bounded operator-facing error category.
        kind: RuntimeRemoteErrorKind,
        /// Actual retry-versus-terminal runtime decision.
        disposition: RuntimeRemoteErrorDisposition,
    },
    /// One authorized orphan-recovery pass completed.
    OrphanRecovery {
        /// Closed pass outcome.
        outcome: RuntimeOperationOutcome,
        /// Process-monotonic elapsed time.
        duration: Duration,
    },
    /// One lease poll reached a durable semantic outcome.
    LeasePoll {
        /// Closed poll outcome.
        outcome: RuntimeLeasePollOutcome,
        /// Process-monotonic elapsed time excluding the no-work idle delay.
        duration: Duration,
    },
    /// A lease response was acknowledged and advanced durable state.
    LeaseResponseAcknowledged {
        /// Accepted or rejected disposition.
        disposition: RuntimeLeaseDisposition,
    },
    /// A heartbeat was validated and its lease renewal committed.
    LeaseRenewed {
        /// Process-monotonic heartbeat/renewal elapsed time.
        duration: Duration,
    },
    /// The local lease watchdog expired.
    LeaseExpired,
    /// One durable command was classified.
    Command {
        /// Closed command kind.
        kind: RuntimeCommandKind,
        /// Durable applied/replay/ignored outcome.
        outcome: RuntimeCommandOutcome,
    },
    /// A command handler had to wait for a missing predecessor.
    CommandGapWait,
    /// A cumulative command cursor was acknowledged by the control plane.
    CommandAcknowledged,
    /// One executor invocation started.
    JobStarted {
        /// Fresh or recovered invocation.
        mode: RuntimeJobStartMode,
    },
    /// One newly committed job completion was observed in this process.
    JobCompleted {
        /// Closed job conclusion.
        conclusion: RuntimeJobConclusion,
        /// Process-monotonic executor duration, absent when execution never started.
        duration: Option<Duration>,
    },
    /// A platform/executor failure was isolated to a job.
    InfrastructureFailure {
        /// Sanitized failure kind.
        kind: RuntimeInfrastructureFailure,
    },
    /// A running executor received a cancellation signal.
    Cancellation {
        /// Closed cancellation reason.
        reason: RuntimeCancellationReason,
    },
    /// One immutable log segment was durably removed after acknowledgement.
    LogBatchAcknowledged {
        /// Acknowledged frame count.
        frames: u64,
        /// Acknowledged logical payload bytes.
        bytes: u64,
        /// Process-monotonic delivery duration, including retries.
        duration: Duration,
    },
    /// One durable terminal-result lifecycle stage completed.
    TerminalResult {
        /// Commit or acknowledgement stage.
        stage: RuntimeTerminalResultStage,
        /// Closed job conclusion.
        conclusion: RuntimeJobConclusion,
    },
    /// One sandbox cleanup invocation completed.
    Cleanup {
        /// Closed cleanup outcome.
        outcome: RuntimeOperationOutcome,
        /// Process-monotonic elapsed time.
        duration: Duration,
    },
}

/// Infallible provider-neutral observer for runner semantic events.
///
/// Implementations must keep observation outside durable correctness: they
/// return no error and should perform only bounded in-memory work.
pub trait RunnerRuntimeObserver: fmt::Debug + Send + Sync {
    /// Records one closed, identifier-free runtime event.
    fn observe(&self, event: RunnerRuntimeEvent);
}

/// Observer used when product telemetry is disabled.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopRunnerRuntimeObserver;

impl RunnerRuntimeObserver for NoopRunnerRuntimeObserver {
    fn observe(&self, _event: RunnerRuntimeEvent) {}
}
