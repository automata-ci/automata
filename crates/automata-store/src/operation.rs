use async_trait::async_trait;
use automata_core::{
    AttemptId, FencingToken, JobLifecycle, Lease, LeaseId, OperationId, UnixMillis,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    AttemptAssignment, JobIrMetadata, RunnableCursorAdvance, RunnerOperationResponse,
    RunnerSessionFence, Sha256Digest, StableRunnerSlot, StoreError,
};

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

    #[must_use]
    pub const fn session(self) -> RunnerSessionFence {
        self.session
    }

    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn slot(self) -> StableRunnerSlot {
        self.slot
    }

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

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LeaseRequestKeyError {
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
    #[must_use]
    pub const fn new(request_key: LeaseRequestKey, request_digest: Sha256Digest) -> Self {
        Self {
            request_key,
            request_digest,
        }
    }

    #[must_use]
    pub const fn request_key(self) -> LeaseRequestKey {
        self.request_key
    }

    #[must_use]
    pub const fn request_digest(self) -> Sha256Digest {
        self.request_digest
    }
}

/// Result of locking and admitting an exact lease request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BegunLeaseRequest {
    request: BeginLeaseRequest,
    completed_response: Option<RunnerOperationResponse>,
}

impl BegunLeaseRequest {
    #[must_use]
    pub const fn new(
        request: BeginLeaseRequest,
        completed_response: Option<RunnerOperationResponse>,
    ) -> Self {
        Self {
            request,
            completed_response,
        }
    }

    #[must_use]
    pub const fn request(&self) -> BeginLeaseRequest {
        self.request
    }

    #[must_use]
    pub const fn completed_response(&self) -> Option<&RunnerOperationResponse> {
        self.completed_response.as_ref()
    }
}

/// Final exact response committed only while the request remains current.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteLeaseRequest {
    request: BeginLeaseRequest,
    response: RunnerOperationResponse,
    completed_at: UnixMillis,
}

impl CompleteLeaseRequest {
    #[must_use]
    pub const fn new(
        request: BeginLeaseRequest,
        response: RunnerOperationResponse,
        completed_at: UnixMillis,
    ) -> Self {
        Self {
            request,
            response,
            completed_at,
        }
    }

    #[must_use]
    pub const fn request(&self) -> BeginLeaseRequest {
        self.request
    }

    #[must_use]
    pub const fn response(&self) -> &RunnerOperationResponse {
        &self.response
    }

    #[must_use]
    pub const fn completed_at(&self) -> UnixMillis {
        self.completed_at
    }

    pub(crate) fn into_response(self) -> RunnerOperationResponse {
        self.response
    }
}

/// Bounded exact-response ledger for protocol-v4 lease-request chains.
#[async_trait]
pub trait RunnerLeaseRequestRepository: Send + Sync {
    /// Admits a first request, exact retry, or exact completed-head successor.
    async fn begin_lease_request(
        &self,
        request: BeginLeaseRequest,
    ) -> Result<BegunLeaseRequest, StoreError>;

    /// Commits the exact response only if the request is still the slot head.
    async fn complete_lease_request(
        &self,
        request: CompleteLeaseRequest,
    ) -> Result<RunnerOperationResponse, StoreError>;
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

    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.request_key.operation_id()
    }

    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    #[must_use]
    pub const fn session(&self) -> RunnerSessionFence {
        self.request_key.session()
    }

    #[must_use]
    pub const fn slot(&self) -> StableRunnerSlot {
        self.request_key.slot()
    }

    #[must_use]
    pub const fn lease_id(&self) -> LeaseId {
        self.lease_id
    }

    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }

    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }

    #[must_use]
    pub const fn request_key(&self) -> LeaseRequestKey {
        self.request_key
    }

    /// Returns the canonical pre-scheduling lease-request digest.
    #[must_use]
    pub fn request_digest(&self) -> Sha256Digest {
        self.request_key.request_digest()
    }

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

    #[must_use]
    pub const fn request_key(&self) -> LeaseRequestKey {
        self.request_key
    }

    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }

    pub(crate) const fn cursor(&self) -> RunnableCursorAdvance {
        self.cursor
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ClaimCommandError {
    #[error("lease expiration must be strictly later than trusted observation time")]
    InvalidLeaseInterval,
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
    ) -> Result<Self, crate::AttemptAssignmentError> {
        assignment.validate_lease(&lease)?;
        Ok(Self {
            lease,
            assignment,
            job_ir,
        })
    }

    #[must_use]
    pub const fn lease(&self) -> &Lease {
        &self.lease
    }

    #[must_use]
    pub const fn assignment(&self) -> AttemptAssignment {
        self.assignment
    }

    #[must_use]
    pub const fn job_ir(&self) -> &JobIrMetadata {
        &self.job_ir
    }
}

/// Durable negative claim decision. Retrying the same operation replays it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimRejection {
    AttemptNotFound,
    AttemptNotQueued(JobLifecycle),
    NoLongerRunnable,
    NotRoutable,
    SlotOutOfRange,
    SlotOccupied {
        attempt_id: AttemptId,
    },
    /// Another operation advanced this slot's cursor after the page was read.
    ScanSuperseded,
}

/// Exact durable outcome of a claim operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TryClaimOutcome {
    Claimed(Box<ClaimedAttempt>),
    Rejected(ClaimRejection),
    NoWork,
}

impl TryClaimOutcome {
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

    #[must_use]
    pub const fn session_id(&self) -> automata_core::RunnerSessionId {
        self.request_key.session().session_id()
    }

    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.request_key.operation_id()
    }

    #[must_use]
    pub fn request_digest(&self) -> Sha256Digest {
        self.request_key.request_digest()
    }

    #[must_use]
    pub const fn request_key(&self) -> LeaseRequestKey {
        self.request_key
    }

    #[must_use]
    pub const fn outcome(&self) -> &TryClaimOutcome {
        &self.outcome
    }

    #[must_use]
    pub const fn was_replayed(&self) -> bool {
        self.replayed
    }
}

/// Receipt-backed server-side claim port.
#[async_trait]
pub trait RunnerClaimRepository: Send + Sync {
    /// Looks up a terminal receipt before candidate selection. This is the
    /// mandatory first step for an at-least-once lease poll retry.
    async fn lookup_lease_request(
        &self,
        request: LeaseRequestKey,
    ) -> Result<Option<TryClaimReceipt>, StoreError>;

    /// Claims one scheduler-selected candidate and records the answer in the
    /// same transaction. Same-session retries replay; digest changes conflict.
    async fn try_claim(&self, request: TryClaimAttempt) -> Result<TryClaimReceipt, StoreError>;

    /// Durably records that the first execution observed no schedulable work.
    /// A retry of the same key replays no-work even if work arrives later.
    async fn record_no_work(
        &self,
        request: NoWorkLeaseRequest,
    ) -> Result<TryClaimReceipt, StoreError>;
}

pub(crate) fn decode_fencing_token(value: i64) -> Result<FencingToken, StoreError> {
    let value = u64::try_from(value)
        .map_err(|_| StoreError::corrupt_data("negative fencing token in claim receipt"))?;
    FencingToken::new(value)
        .map_err(|error| StoreError::corrupt_data(format!("invalid fencing token: {error}")))
}
