use std::{fmt, time::Duration};

/// Closed result of one authenticated handshake attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerHandshakeOutcome {
    /// A new durable runner session opened.
    Opened,
    /// An existing durable runner session resumed.
    Resumed,
    /// The handshake returned a correlated protocol rejection.
    Rejected(RunnerHandshakeRejection),
    /// The handshake failed at the application boundary.
    Failed(RunnerControlFailure),
}

/// Closed handshake rejection codes safe for metric labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerHandshakeRejection {
    /// No supported wire protocol overlapped.
    UnsupportedProtocol,
    /// No supported `JobIR` version overlapped.
    UnsupportedJobIr,
    /// The authenticated machine was not authorized.
    Unauthorized,
    /// The requested old session could not be resumed.
    SessionNotResumable,
}

/// Closed runner-to-server message kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerControlMessageKind {
    /// Lease-poll request.
    LeaseRequest,
    /// Lease-offer acceptance or rejection.
    LeaseResponse,
    /// Lease heartbeat and renewal request.
    Heartbeat,
    /// Redundant job-state update, unsupported in the current application.
    JobState,
    /// Terminal job result.
    JobResult,
    /// Durable log batch.
    LogBatch,
    /// Cumulative durable command acknowledgement.
    CommandAck,
}

/// Closed physical outcome of one post-handshake message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerControlMessageOutcome {
    /// A non-error protocol response was returned.
    Success,
    /// A semantic protocol error was returned inside a successful transport response.
    ProtocolError,
    /// Application handling failed before a protocol response was returned.
    Failed(RunnerControlFailure),
}

/// Sanitized application failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerControlFailure {
    /// The authenticated runner lacks authority for the operation.
    Forbidden,
    /// Durable state rejected a conflict or fence.
    Conflict,
    /// Shared application state is unavailable.
    Unavailable,
    /// An invariant failed without exposing implementation detail.
    Internal,
}

/// Durable runner-control mutation kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerDurableMessageKind {
    /// Lease renewal committed by a heartbeat.
    LeaseRenewal,
    /// Lease acceptance or rejection committed.
    LeaseResponse,
    /// Terminal job result committed.
    JobResult,
    /// Log segment metadata committed.
    LogBatch,
    /// Command cursor acknowledgement committed.
    CommandAck,
}

/// Whether a durable operation was newly committed or replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerDurableDisposition {
    /// This physical attempt committed the durable transition.
    New,
    /// This physical attempt returned the exact prior receipt.
    Replay,
}

/// Closed outcomes of lease-offer publication and recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseOfferObservation {
    /// A new durable lease-offer command was published.
    Published,
    /// An existing durable lease-offer command was replayed.
    Replay,
    /// The exact claim was superseded before publication.
    Superseded,
    /// Offer construction or publication failed.
    Failed,
}

/// Provider-neutral observation seam for the runner-control server.
///
/// No method accepts identities, request bytes, paths, digests, or error text.
pub trait RunnerControlObserver: fmt::Debug + Send + Sync {
    /// Records one physical handshake attempt.
    fn observe_handshake(&self, _outcome: RunnerHandshakeOutcome, _duration: Duration) {}

    /// Records one physical post-handshake request, including protocol errors
    /// returned through an otherwise successful HTTP response.
    fn observe_message(
        &self,
        _kind: RunnerControlMessageKind,
        _outcome: RunnerControlMessageOutcome,
        _duration: Duration,
    ) {
    }

    /// Records a receipt-backed durable transition or replay. `bytes` is an
    /// aggregate payload count and is zero for non-payload operations.
    fn observe_durable(
        &self,
        _kind: RunnerDurableMessageKind,
        _disposition: RunnerDurableDisposition,
        _bytes: u64,
    ) {
    }

    /// Records one bounded lease-offer publication/recovery outcome.
    fn observe_lease_offer(&self, _outcome: LeaseOfferObservation) {}
}

/// Observer used when server semantic metrics are not composed.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopRunnerControlObserver;

impl RunnerControlObserver for NoopRunnerControlObserver {}
