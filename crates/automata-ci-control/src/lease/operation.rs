//! Idempotent lease-poll operation values and durable claim outcomes.

use automata_ci_core::{AttemptId, JobLifecycle, Lease, LeaseId, OperationId, UnixMillis};
use automata_ci_store::{
    AttemptAssignment, AttemptAssignmentError, DocumentSchema, JobIrMetadata,
    LeaseOfferCommandIdentity, RunnerOperationResponse, RunnerSessionFence, Sha256Digest,
    StableRunnerSlot,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use super::runnable::RunnableCursorAdvance;

const LEASE_REQUEST_DIGEST_DOMAIN: &[u8] = b"automata.store.lease-request.v2\0";

/// Canonical identity of one runner lease poll before scheduling selects work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseRequestKey {
    session: RunnerSessionFence,
    operation_id: OperationId,
    slot: StableRunnerSlot,
    acknowledges_operation_id: Option<OperationId>,
}

impl LeaseRequestKey {
    /// Creates the first request in one session-slot chain.
    #[must_use]
    pub const fn first(
        session: RunnerSessionFence,
        operation_id: OperationId,
        slot: StableRunnerSlot,
    ) -> Self {
        Self {
            session,
            operation_id,
            slot,
            acknowledges_operation_id: None,
        }
    }

    /// Creates a request which acknowledges the exact preceding head.
    ///
    /// # Errors
    ///
    /// Rejects a request which acknowledges its own operation identity.
    pub fn successor(
        session: RunnerSessionFence,
        operation_id: OperationId,
        slot: StableRunnerSlot,
        acknowledges_operation_id: OperationId,
    ) -> Result<Self, LeaseRequestKeyError> {
        if acknowledges_operation_id == operation_id {
            return Err(LeaseRequestKeyError::SelfAcknowledgement);
        }
        Ok(Self {
            session,
            operation_id,
            slot,
            acknowledges_operation_id: Some(acknowledges_operation_id),
        })
    }

    /// Returns the authenticated runner-session fence.
    #[must_use]
    pub const fn session(self) -> RunnerSessionFence {
        self.session
    }

    /// Returns this request's idempotency identity.
    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    /// Returns the stable runner slot being polled.
    #[must_use]
    pub const fn slot(self) -> StableRunnerSlot {
        self.slot
    }

    /// Returns the preceding operation acknowledged by this request, if any.
    #[must_use]
    pub const fn acknowledges_operation_id(self) -> Option<OperationId> {
        self.acknowledges_operation_id
    }

    /// Computes the canonical digest of the actual wire poll request. Server
    /// selections are deliberately excluded so a retry can be replayed before
    /// the scheduler reselects a now-non-runnable attempt.
    #[must_use]
    pub fn request_digest(self) -> Sha256Digest {
        let mut digest = Sha256::new();
        digest.update(LEASE_REQUEST_DIGEST_DOMAIN);
        digest.update(self.operation_id.as_uuid().as_bytes());
        digest.update(self.session.session_id().as_uuid().as_bytes());
        digest.update(self.session.runner_id().as_uuid().as_bytes());
        digest.update(self.session.runner_generation().get().to_be_bytes());
        digest.update(self.session.session_epoch().get().to_be_bytes());
        digest.update(self.slot.ordinal().to_be_bytes());
        match self.acknowledges_operation_id {
            Some(operation_id) => {
                digest.update([1]);
                digest.update(operation_id.as_uuid().as_bytes());
            }
            None => digest.update([0]),
        }
        Sha256Digest::from_bytes(digest.finalize().into())
    }
}

/// Invalid lease-request chain identity.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LeaseRequestKeyError {
    /// The request acknowledges its own operation identity.
    #[error("a lease request cannot acknowledge its own operation identity")]
    SelfAcknowledgement,
}

/// Exact request admitted at the durable head of one session-slot chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BeginLeaseRequest {
    request_key: LeaseRequestKey,
    request_digest: Sha256Digest,
}

impl BeginLeaseRequest {
    /// Creates an admitted request from its canonical key and digest.
    #[must_use]
    pub const fn new(request_key: LeaseRequestKey, request_digest: Sha256Digest) -> Self {
        Self {
            request_key,
            request_digest,
        }
    }

    /// Returns the canonical request key.
    #[must_use]
    pub const fn request_key(self) -> LeaseRequestKey {
        self.request_key
    }

    /// Returns the request digest admitted at the durable head.
    #[must_use]
    pub const fn request_digest(self) -> Sha256Digest {
        self.request_digest
    }
}

/// Result of locking and admitting an exact lease request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BegunLeaseRequest {
    request: BeginLeaseRequest,
    completion: Option<LeaseRequestCompletion>,
}

impl BegunLeaseRequest {
    /// Builds an admission result from a legacy response-only completion.
    #[must_use]
    pub fn new(
        request: BeginLeaseRequest,
        completed_response: Option<RunnerOperationResponse>,
    ) -> Self {
        Self {
            request,
            completion: completed_response.map(LeaseRequestCompletion::Response),
        }
    }

    /// Builds an admission result with the exact typed durable completion.
    #[must_use]
    pub const fn completed(request: BeginLeaseRequest, completion: LeaseRequestCompletion) -> Self {
        Self {
            request,
            completion: Some(completion),
        }
    }

    /// Builds an exact retry result whose previously committed offer is no longer live.
    #[must_use]
    pub const fn revoked_offer(
        request: BeginLeaseRequest,
        offer_operation_id: OperationId,
        fallback: RevokedLeaseOfferFallback,
    ) -> Self {
        Self::completed(
            request,
            LeaseRequestCompletion::RevokedLeaseOffer {
                offer_operation_id,
                fallback,
            },
        )
    }

    /// Returns the request that was admitted.
    #[must_use]
    pub const fn request(&self) -> BeginLeaseRequest {
        self.request
    }

    /// Returns a previously completed replayable response, if present.
    #[must_use]
    pub const fn completed_response(&self) -> Option<&RunnerOperationResponse> {
        match &self.completion {
            Some(completion) => completion.response(),
            None => None,
        }
    }

    /// Returns the exact typed durable completion, when this request already completed.
    #[must_use]
    pub const fn completion(&self) -> Option<&LeaseRequestCompletion> {
        self.completion.as_ref()
    }

    /// Returns the exact offer operation whose committed response must be replaced by no work.
    #[must_use]
    pub const fn revoked_offer_operation_id(&self) -> Option<OperationId> {
        match &self.completion {
            Some(LeaseRequestCompletion::RevokedLeaseOffer {
                offer_operation_id, ..
            }) => Some(*offer_operation_id),
            Some(
                LeaseRequestCompletion::Response(_) | LeaseRequestCompletion::LiveLeaseOffer { .. },
            )
            | None => None,
        }
    }
}

/// Version of the canonical structured fallback retained for a revoked lease offer.
const REVOKED_LEASE_OFFER_FALLBACK_VERSION: u16 = 1;

/// Minimal durable data needed to rebuild one canonical revoked-offer `NoWork` response.
///
/// The projection deliberately contains no encrypted response bytes and no reference to
/// replica-local retry configuration. Its schema and digest authenticate the canonical wire
/// response rebuilt by the runner-control boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevokedLeaseOfferFallback {
    representation_version: u16,
    response_operation_id: OperationId,
    retry_after_millis: u32,
    response_schema: DocumentSchema,
    response_digest: Sha256Digest,
}

impl RevokedLeaseOfferFallback {
    /// Builds the current durable fallback representation.
    ///
    /// # Errors
    ///
    /// Rejects a nil response operation identity or a zero retry delay.
    pub fn new(
        response_operation_id: OperationId,
        retry_after_millis: u32,
        response_schema: DocumentSchema,
        response_digest: Sha256Digest,
    ) -> Result<Self, LeaseOfferCompletionError> {
        Self::from_persisted(
            REVOKED_LEASE_OFFER_FALLBACK_VERSION,
            response_operation_id,
            retry_after_millis,
            response_schema,
            response_digest,
        )
    }

    /// Rehydrates and validates a versioned durable fallback representation.
    ///
    /// # Errors
    ///
    /// Rejects an unsupported representation, nil operation identity, or zero
    /// retry delay.
    pub(crate) fn from_persisted(
        representation_version: u16,
        response_operation_id: OperationId,
        retry_after_millis: u32,
        response_schema: DocumentSchema,
        response_digest: Sha256Digest,
    ) -> Result<Self, LeaseOfferCompletionError> {
        if representation_version != REVOKED_LEASE_OFFER_FALLBACK_VERSION {
            return Err(LeaseOfferCompletionError::UnsupportedFallbackVersion);
        }
        if response_operation_id.as_uuid().is_nil() {
            return Err(LeaseOfferCompletionError::NilFallbackOperationId);
        }
        if retry_after_millis == 0 {
            return Err(LeaseOfferCompletionError::ZeroFallbackRetry);
        }
        Ok(Self {
            representation_version,
            response_operation_id,
            retry_after_millis,
            response_schema,
            response_digest,
        })
    }

    /// Returns the durable representation version.
    #[must_use]
    pub const fn representation_version(self) -> u16 {
        self.representation_version
    }

    /// Returns the operation identity used for the rebuilt response.
    #[must_use]
    pub const fn response_operation_id(self) -> OperationId {
        self.response_operation_id
    }

    /// Returns the retry delay carried by the rebuilt response.
    #[must_use]
    pub const fn retry_after_millis(self) -> u32 {
        self.retry_after_millis
    }

    /// Returns the expected canonical response schema.
    #[must_use]
    pub const fn response_schema(self) -> DocumentSchema {
        self.response_schema
    }

    /// Returns the expected canonical response digest.
    #[must_use]
    pub const fn response_digest(self) -> Sha256Digest {
        self.response_digest
    }
}

/// Exact semantic disposition of one durable lease-request completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeaseRequestCompletion {
    /// A response which did not publish a lease offer.
    Response(RunnerOperationResponse),
    /// A still-live lease offer plus the already-persisted fallback needed if it later revokes.
    LiveLeaseOffer {
        /// The replayable live-offer response.
        response: RunnerOperationResponse,
        /// The canonical fallback retained for later revocation.
        fallback: RevokedLeaseOfferFallback,
    },
    /// A lease offer whose bearer response is no longer eligible for replay.
    RevokedLeaseOffer {
        /// The operation identity of the revoked offer.
        offer_operation_id: OperationId,
        /// The canonical replacement response projection.
        fallback: RevokedLeaseOfferFallback,
    },
}

impl LeaseRequestCompletion {
    /// Returns the replayable response when this completion still has one.
    #[must_use]
    pub const fn response(&self) -> Option<&RunnerOperationResponse> {
        match self {
            Self::Response(response) | Self::LiveLeaseOffer { response, .. } => Some(response),
            Self::RevokedLeaseOffer { .. } => None,
        }
    }

    /// Returns the retained revoked-offer fallback, if any.
    #[must_use]
    pub const fn revoked_offer_fallback(&self) -> Option<RevokedLeaseOfferFallback> {
        match self {
            Self::LiveLeaseOffer { fallback, .. } | Self::RevokedLeaseOffer { fallback, .. } => {
                Some(*fallback)
            }
            Self::Response(_) => None,
        }
    }
}

impl PartialEq<RunnerOperationResponse> for LeaseRequestCompletion {
    fn eq(&self, other: &RunnerOperationResponse) -> bool {
        self.response().is_some_and(|response| response == other)
    }
}

impl PartialEq<LeaseRequestCompletion> for RunnerOperationResponse {
    fn eq(&self, other: &LeaseRequestCompletion) -> bool {
        other == self
    }
}

/// Invalid typed composition of a lease offer and its canonical revocation fallback.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LeaseOfferCompletionError {
    /// The offer command belongs to another durable session.
    #[error("lease-offer completion crosses durable sessions")]
    SessionMismatch,
    /// The persisted fallback representation version is unsupported.
    #[error("lease-offer fallback representation version is unsupported")]
    UnsupportedFallbackVersion,
    /// The fallback response operation identity is nil.
    #[error("lease-offer fallback response operation identity is nil")]
    NilFallbackOperationId,
    /// The fallback retry delay is zero.
    #[error("lease-offer fallback retry delay is zero")]
    ZeroFallbackRetry,
    /// The fallback projection disagrees with the canonical response.
    #[error("lease-offer fallback response metadata does not match its canonical bytes")]
    FallbackResponseMismatch,
}

/// Final exact response committed only while the request remains current.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteLeaseRequest {
    request: BeginLeaseRequest,
    response: RunnerOperationResponse,
    completed_at: UnixMillis,
    lease_offer: Option<LeaseOfferCompletion>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LeaseOfferCompletion {
    command: LeaseOfferCommandIdentity,
    revoked_response: RunnerOperationResponse,
    revoked_fallback: RevokedLeaseOfferFallback,
}

impl CompleteLeaseRequest {
    /// Builds a response which does not contain a full lease-offer command.
    #[must_use]
    pub const fn without_lease_offer(
        request: BeginLeaseRequest,
        response: RunnerOperationResponse,
        completed_at: UnixMillis,
    ) -> Self {
        Self {
            request,
            response,
            completed_at,
            lease_offer: None,
        }
    }

    /// Builds a full lease-offer response with its typed canonical revocation fallback.
    ///
    /// # Errors
    ///
    /// Rejects a command from another session or fallback bytes whose schema/digest disagree
    /// with the structured projection.
    pub fn for_lease_offer_with_fallback(
        request: BeginLeaseRequest,
        response: RunnerOperationResponse,
        revoked_response: RunnerOperationResponse,
        revoked_fallback: RevokedLeaseOfferFallback,
        completed_at: UnixMillis,
        command: LeaseOfferCommandIdentity,
    ) -> Result<Self, LeaseOfferCompletionError> {
        if command.session() != request.request_key().session() {
            return Err(LeaseOfferCompletionError::SessionMismatch);
        }
        if revoked_response.schema() != revoked_fallback.response_schema()
            || revoked_response.digest() != revoked_fallback.response_digest()
        {
            return Err(LeaseOfferCompletionError::FallbackResponseMismatch);
        }
        Ok(Self {
            request,
            response,
            completed_at,
            lease_offer: Some(LeaseOfferCompletion {
                command,
                revoked_response,
                revoked_fallback,
            }),
        })
    }

    /// Returns the admitted request being completed.
    #[must_use]
    pub const fn request(&self) -> BeginLeaseRequest {
        self.request
    }

    /// Returns the canonical response being committed.
    #[must_use]
    pub const fn response(&self) -> &RunnerOperationResponse {
        &self.response
    }

    /// Returns the trusted completion time.
    #[must_use]
    pub const fn completed_at(&self) -> UnixMillis {
        self.completed_at
    }

    /// Returns the exact typed offer command carried by this response, when present.
    #[must_use]
    pub const fn lease_offer_command(&self) -> Option<LeaseOfferCommandIdentity> {
        match &self.lease_offer {
            Some(lease_offer) => Some(lease_offer.command),
            None => None,
        }
    }

    /// Returns the response to commit if the typed offer is revoked before
    /// the primary response reaches the durable lease-request ledger.
    #[must_use]
    pub const fn revoked_lease_offer_response(&self) -> Option<&RunnerOperationResponse> {
        match &self.lease_offer {
            Some(lease_offer) => Some(&lease_offer.revoked_response),
            None => None,
        }
    }

    /// Returns the typed canonical revocation projection for a strict offer completion.
    #[must_use]
    pub const fn revoked_lease_offer_fallback(&self) -> Option<RevokedLeaseOfferFallback> {
        match &self.lease_offer {
            Some(lease_offer) => Some(lease_offer.revoked_fallback),
            None => None,
        }
    }
}

/// Idempotent, server-routed attempt claim.
///
/// It intentionally contains no labels, groups, or capability claims. Those
/// are loaded through the session from server-owned durable registration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TryClaimAttempt {
    request_key: LeaseRequestKey,
    attempt_id: AttemptId,
    lease_id: LeaseId,
    observed_at: UnixMillis,
    expires_at: UnixMillis,
    cursor: RunnableCursorAdvance,
}

impl TryClaimAttempt {
    /// Creates a claim with a valid half-open lease interval.
    ///
    /// # Errors
    ///
    /// Rejects expiration at or before trusted observation time.
    pub fn new(
        request_key: LeaseRequestKey,
        attempt_id: AttemptId,
        lease_id: LeaseId,
        observed_at: UnixMillis,
        expires_at: UnixMillis,
        cursor: RunnableCursorAdvance,
    ) -> Result<Self, ClaimCommandError> {
        if expires_at <= observed_at {
            return Err(ClaimCommandError::InvalidLeaseInterval);
        }
        if cursor.session() != request_key.session()
            || cursor.slot() != request_key.slot()
            || cursor
                .through()
                .is_none_or(|key| key.attempt_id() != attempt_id)
        {
            return Err(ClaimCommandError::CursorMismatch);
        }
        Ok(Self {
            request_key,
            attempt_id,
            lease_id,
            observed_at,
            expires_at,
            cursor,
        })
    }

    /// Returns the claim operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.request_key.operation_id()
    }

    /// Returns the target attempt identity.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the authenticated runner-session fence.
    #[must_use]
    pub const fn session(&self) -> RunnerSessionFence {
        self.request_key.session()
    }

    /// Returns the stable runner slot receiving the claim.
    #[must_use]
    pub const fn slot(&self) -> StableRunnerSlot {
        self.request_key.slot()
    }

    /// Returns the proposed lease identity.
    #[must_use]
    pub const fn lease_id(&self) -> LeaseId {
        self.lease_id
    }

    /// Returns the trusted observation time.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }

    /// Returns the proposed lease expiration.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }

    /// Returns the canonical lease-request key.
    #[must_use]
    pub const fn request_key(&self) -> LeaseRequestKey {
        self.request_key
    }

    /// Returns the canonical pre-scheduling lease-request digest.
    #[must_use]
    pub fn request_digest(&self) -> Sha256Digest {
        self.request_key.request_digest()
    }

    /// Returns the opaque authoritative scan cursor used by an adapter.
    #[cfg(feature = "adapter-spi")]
    #[must_use]
    pub(crate) const fn cursor(&self) -> RunnableCursorAdvance {
        self.cursor
    }
}

/// Terminal no-work decision for one exact lease poll.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoWorkLeaseRequest {
    request_key: LeaseRequestKey,
    observed_at: UnixMillis,
    cursor: RunnableCursorAdvance,
}

impl NoWorkLeaseRequest {
    /// Creates a terminal no-work command bound to an authoritative scan.
    ///
    /// # Errors
    ///
    /// Rejects a cursor proof for another session fence or stable slot.
    pub fn new(
        request_key: LeaseRequestKey,
        observed_at: UnixMillis,
        cursor: RunnableCursorAdvance,
    ) -> Result<Self, ClaimCommandError> {
        if cursor.session() != request_key.session() || cursor.slot() != request_key.slot() {
            return Err(ClaimCommandError::CursorMismatch);
        }
        Ok(Self {
            request_key,
            observed_at,
            cursor,
        })
    }

    /// Returns the canonical lease-request key.
    #[must_use]
    pub const fn request_key(&self) -> LeaseRequestKey {
        self.request_key
    }

    /// Returns the trusted no-work observation time.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }

    /// Returns the opaque authoritative scan cursor used by an adapter.
    #[cfg(feature = "adapter-spi")]
    #[must_use]
    pub(crate) const fn cursor(&self) -> RunnableCursorAdvance {
        self.cursor
    }
}

/// Invalid composition of a durable attempt-claim command.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ClaimCommandError {
    /// The proposed lease does not extend past trusted observation time.
    #[error("lease expiration must be strictly later than trusted observation time")]
    InvalidLeaseInterval,
    /// The cursor proof belongs to another request, slot, or attempt.
    #[error("queue cursor proof does not match the lease request")]
    CursorMismatch,
}

/// Successfully fenced claim and its stable connection assignment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedAttempt {
    lease: Lease,
    assignment: AttemptAssignment,
    job_ir: JobIrMetadata,
}

impl ClaimedAttempt {
    /// Constructs a claimed attempt returned by an adapter.
    ///
    /// # Errors
    ///
    /// Rejects a lease owned by another runner.
    pub fn try_new(
        lease: Lease,
        assignment: AttemptAssignment,
        job_ir: JobIrMetadata,
    ) -> Result<Self, AttemptAssignmentError> {
        assignment.validate_lease(&lease)?;
        Ok(Self {
            lease,
            assignment,
            job_ir,
        })
    }

    /// Returns the acquired lease.
    #[must_use]
    pub const fn lease(&self) -> &Lease {
        &self.lease
    }

    /// Returns the stable runner-session assignment.
    #[must_use]
    pub const fn assignment(&self) -> AttemptAssignment {
        self.assignment
    }

    /// Returns the selected job intermediate-representation metadata.
    #[must_use]
    pub const fn job_ir(&self) -> &JobIrMetadata {
        &self.job_ir
    }
}

/// Durable negative claim decision. Retrying the same operation replays it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimRejection {
    /// The selected attempt no longer exists.
    AttemptNotFound,
    /// The selected attempt is no longer queued.
    AttemptNotQueued(JobLifecycle),
    /// Durable execution gates no longer consider the attempt runnable.
    NoLongerRunnable,
    /// The attempt no longer routes to this runner.
    NotRoutable,
    /// The requested stable slot is outside the registered capacity.
    SlotOutOfRange,
    /// The requested stable slot already owns another attempt.
    SlotOccupied {
        /// The attempt currently occupying the stable slot.
        attempt_id: AttemptId,
    },
    /// Another operation advanced this slot's cursor after the page was read.
    ScanSuperseded,
}

/// Exact durable outcome of a claim operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TryClaimOutcome {
    /// The attempt was claimed and fenced successfully.
    Claimed(Box<ClaimedAttempt>),
    /// The durable claim was rejected without a repository failure.
    Rejected(ClaimRejection),
    /// The authoritative scan produced no claimable work.
    NoWork,
}

impl TryClaimOutcome {
    /// Returns selected job metadata for a successful claim.
    #[must_use]
    pub const fn claimed_job_ir(&self) -> Option<&JobIrMetadata> {
        match self {
            Self::Claimed(claimed) => Some(claimed.job_ir()),
            Self::Rejected(_) | Self::NoWork => None,
        }
    }
}

/// Receipt returned for a first execution or an exact retry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TryClaimReceipt {
    request_key: LeaseRequestKey,
    outcome: TryClaimOutcome,
    replayed: bool,
}

impl TryClaimReceipt {
    /// Creates a durable claim receipt.
    #[must_use]
    pub const fn new(
        request_key: LeaseRequestKey,
        outcome: TryClaimOutcome,
        replayed: bool,
    ) -> Self {
        Self {
            request_key,
            outcome,
            replayed,
        }
    }

    /// Returns the runner-session identity owning the request.
    #[must_use]
    pub const fn session_id(&self) -> automata_ci_core::RunnerSessionId {
        self.request_key.session().session_id()
    }

    /// Returns the claim operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.request_key.operation_id()
    }

    /// Returns the canonical lease-request digest.
    #[must_use]
    pub fn request_digest(&self) -> Sha256Digest {
        self.request_key.request_digest()
    }

    /// Returns the canonical lease-request key.
    #[must_use]
    pub const fn request_key(&self) -> LeaseRequestKey {
        self.request_key
    }

    /// Returns the durable claim outcome.
    #[must_use]
    pub const fn outcome(&self) -> &TryClaimOutcome {
        &self.outcome
    }

    /// Reports whether this receipt came from an exact retry.
    #[must_use]
    pub const fn was_replayed(&self) -> bool {
        self.replayed
    }
}
