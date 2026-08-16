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
    /// Post-accept request for one runtime-authority generation.
    RuntimeAuthorityRequest,
    /// Protected-spool acknowledgement for one authority generation.
    RuntimeAuthorityAck,
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

/// Closed stages at which a lease-poll request can fail.
///
/// Values intentionally describe only application operations. They never carry
/// runner, session, repository, request, or lease identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerLeaseRequestStage {
    /// Local request invariants and durable-key construction.
    RequestValidation,
    /// Runner authorization and durable session fencing.
    SessionAuthentication,
    /// Admission against the durable per-session, per-slot request head.
    DurableAdmission,
    /// Durable session-liveness refresh.
    SessionHeartbeat,
    /// Resolution of an already-completed request.
    CompletedRequestReplay,
    /// Verification and durable acceptance of canonical lease-authority poll
    /// contributions before scheduling.
    LeaseAuthorityAcceptance,
    /// Durable command replay before polling for work.
    PrePollCommandReplay,
    /// Scheduler polling and attempt claim.
    LeasePoll,
    /// Lease-offer construction and publication.
    OfferBuild,
    /// Existing lease-offer claim inspection.
    OfferClaimInspection,
    /// Decoding a previously published lease offer.
    OfferPublishedClaimDecode,
    /// Reading the claimed job IR object.
    OfferJobIrRead,
    /// Authenticating and decoding the claimed job IR object.
    OfferJobIrVerification,
    /// Constructing the runtime-authority request.
    OfferRuntimeAuthorityRequest,
    /// Issuing runtime authorities.
    OfferRuntimeAuthorityIssue,
    /// Validating issued runtime authorities.
    OfferRuntimeAuthorityValidation,
    /// Issuing managed-secret bindings.
    OfferManagedSecretBindingIssue,
    /// Validating managed-secret bindings.
    OfferManagedSecretBindingValidation,
    /// Constructing the durable lease-offer command.
    OfferCommandConstruction,
    /// Publishing the durable lease-offer command.
    OfferCommandPublication,
    /// Constructing the runner-facing lease offer.
    OfferConstruction,
    /// Durable command replay after polling for work.
    PostPollCommandReplay,
    /// Lease-offer response validation and revocation recovery.
    ResponseValidation,
    /// Durable request completion and response resolution.
    DurableCompletion,
}

/// Closed stages at which a post-accept runtime-authority request can fail.
///
/// Values expose no runner, repository, lease, credential, or provider identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerRuntimeAuthorityRequestStage {
    /// Cancellation, request-key, protocol, or delivery-binding construction.
    RequestValidation,
    /// Durable authorization against the exact accepted lease offer.
    DurableAuthorization,
    /// Reading the immutable job IR selected by that offer.
    JobIrRead,
    /// Authenticating and decoding the selected job IR.
    JobIrVerification,
    /// Issuing the job's exact runtime-authority bundle.
    AuthorityIssue,
    /// Revalidating the issued bundle against the job and lease.
    AuthorityValidation,
    /// Encoding and digesting the validated authority bundle.
    BundleEncoding,
    /// Constructing the exact durable delivery commit.
    CommitConstruction,
    /// Committing the authority delivery before returning it to the runner.
    DurableCommit,
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

    /// Records the sanitized stage and category of one failed lease request.
    fn observe_lease_request_failure(
        &self,
        _stage: RunnerLeaseRequestStage,
        _failure: RunnerControlFailure,
    ) {
    }

    /// Records the sanitized stage and category of one failed runtime-authority request.
    fn observe_runtime_authority_request_failure(
        &self,
        _stage: RunnerRuntimeAuthorityRequestStage,
        _failure: RunnerControlFailure,
    ) {
    }
}

/// Observer used when server semantic metrics are not composed.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct NoopRunnerControlObserver;

impl RunnerControlObserver for NoopRunnerControlObserver {}
