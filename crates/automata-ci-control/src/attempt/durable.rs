//! Durable attempt lifecycle commands and repository ports.

use async_trait::async_trait;
use automata_ci_core::{
    AttemptId, AttemptNumber, JobId, JobLifecycle, Lease, LeaseGuard, LeaseId, RunnerId, UnixMillis,
};
use automata_ci_store::{
    AttemptCommandError, AttemptStoreError, RunnerSessionFence, StableRunnerSlot, TenantScope,
};

use super::{RenewLease, snapshot::AttemptSnapshot, validate_lease_interval};

/// A newly queued durable job attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueuedAttempt {
    pub(crate) attempt_id: AttemptId,
    pub(crate) job_id: JobId,
    pub(crate) attempt_number: AttemptNumber,
    pub(crate) queued_at: UnixMillis,
}

impl QueuedAttempt {
    /// Creates a queued attempt descriptor.
    #[must_use]
    pub const fn new(
        attempt_id: AttemptId,
        job_id: JobId,
        attempt_number: AttemptNumber,
        queued_at: UnixMillis,
    ) -> Self {
        Self {
            attempt_id,
            job_id,
            attempt_number,
            queued_at,
        }
    }

    /// Returns the durable attempt identity.
    #[must_use]
    pub const fn attempt_id(self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the owning job identity.
    #[must_use]
    pub const fn job_id(self) -> JobId {
        self.job_id
    }

    /// Returns the one-based attempt number.
    #[must_use]
    pub const fn attempt_number(self) -> AttemptNumber {
        self.attempt_number
    }

    /// Returns the time at which the attempt entered the queue.
    #[must_use]
    pub const fn queued_at(self) -> UnixMillis {
        self.queued_at
    }
}

/// A request to acquire a lease for a queued attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcquireLease {
    pub(crate) attempt_id: AttemptId,
    pub(crate) lease_id: LeaseId,
    pub(crate) session: RunnerSessionFence,
    pub(crate) slot: StableRunnerSlot,
    /// Time at which the trusted control plane observed this acquisition.
    pub(crate) observed_at: UnixMillis,
    pub(crate) expires_at: UnixMillis,
}

impl AcquireLease {
    /// Creates a lease acquisition observed by the trusted control plane.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptCommandError::InvalidLeaseInterval`] unless expiration
    /// is strictly later than observation.
    pub fn new(
        attempt_id: AttemptId,
        lease_id: LeaseId,
        session: RunnerSessionFence,
        slot: StableRunnerSlot,
        observed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, AttemptCommandError> {
        validate_lease_interval(observed_at, expires_at)?;
        Ok(Self {
            attempt_id,
            lease_id,
            session,
            slot,
            observed_at,
            expires_at,
        })
    }

    /// Returns the target attempt identity.
    #[must_use]
    pub const fn attempt_id(self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the proposed lease identity.
    #[must_use]
    pub const fn lease_id(self) -> LeaseId {
        self.lease_id
    }

    /// Returns the authenticated runner identity.
    #[must_use]
    pub const fn runner_id(self) -> RunnerId {
        self.session.runner_id()
    }

    /// Returns the authenticated runner-session fence.
    #[must_use]
    pub const fn session(self) -> RunnerSessionFence {
        self.session
    }

    /// Returns the stable runner slot receiving the lease.
    #[must_use]
    pub const fn slot(self) -> StableRunnerSlot {
        self.slot
    }

    /// Returns the trusted observation time.
    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }

    /// Returns the proposed lease expiration.
    #[must_use]
    pub const fn expires_at(self) -> UnixMillis {
        self.expires_at
    }
}

/// A request to transition an actively leased attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionAttempt {
    pub(crate) attempt_id: AttemptId,
    /// Identity established by the runner authentication boundary.
    pub(crate) session: RunnerSessionFence,
    pub(crate) guard: LeaseGuard,
    pub(crate) next: JobLifecycle,
    /// Time at which the trusted control plane observed this transition.
    pub(crate) observed_at: UnixMillis,
}

impl TransitionAttempt {
    /// Creates a fenced lifecycle-transition request.
    #[must_use]
    pub const fn new(
        attempt_id: AttemptId,
        session: RunnerSessionFence,
        guard: LeaseGuard,
        next: JobLifecycle,
        observed_at: UnixMillis,
    ) -> Self {
        Self {
            attempt_id,
            session,
            guard,
            next,
            observed_at,
        }
    }

    /// Returns the target attempt identity.
    #[must_use]
    pub const fn attempt_id(self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the authenticated runner identity.
    #[must_use]
    pub const fn runner_id(self) -> RunnerId {
        self.session.runner_id()
    }

    /// Returns the authenticated runner-session fence.
    #[must_use]
    pub const fn session(self) -> RunnerSessionFence {
        self.session
    }

    /// Returns the active lease guard.
    #[must_use]
    pub const fn guard(self) -> LeaseGuard {
        self.guard
    }

    /// Returns the requested lifecycle state.
    #[must_use]
    pub const fn next(self) -> JobLifecycle {
        self.next
    }

    /// Returns the trusted observation time.
    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }
}

/// A control-plane decision that terminates work before it is leased.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConcludeQueuedAttempt {
    pub(crate) attempt_id: AttemptId,
    /// Must be either [`JobLifecycle::Cancelled`] or [`JobLifecycle::Skipped`].
    pub(crate) conclusion: JobLifecycle,
    /// Time at which the trusted control plane observed this conclusion.
    pub(crate) observed_at: UnixMillis,
}

impl ConcludeQueuedAttempt {
    /// Creates a control-plane conclusion for work that has not been leased.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptCommandError::InvalidQueuedConclusion`] unless the
    /// conclusion is `Cancelled` or `Skipped`.
    pub fn new(
        attempt_id: AttemptId,
        conclusion: JobLifecycle,
        observed_at: UnixMillis,
    ) -> Result<Self, AttemptCommandError> {
        if !matches!(conclusion, JobLifecycle::Cancelled | JobLifecycle::Skipped) {
            return Err(AttemptCommandError::InvalidQueuedConclusion(conclusion));
        }
        Ok(Self {
            attempt_id,
            conclusion,
            observed_at,
        })
    }

    /// Returns the target attempt identity.
    #[must_use]
    pub const fn attempt_id(self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the terminal queued-state conclusion.
    #[must_use]
    pub const fn conclusion(self) -> JobLifecycle {
        self.conclusion
    }

    /// Returns the trusted observation time.
    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }
}

/// Internal scheduling port.
///
/// These ID-only operations are intentionally not suitable for tenant-facing
/// HTTP or CLI handlers. Such handlers must use [`TenantAttemptQuery`], which
/// enforces tenant scope in the repository operation itself.
#[async_trait]
pub trait InternalAttemptRepository: Send + Sync {
    /// Inserts a newly queued attempt.
    async fn insert_queued(&self, attempt: QueuedAttempt) -> Result<(), AttemptStoreError>;

    /// Fetches an attempt by its internal identity.
    async fn get_attempt(
        &self,
        attempt_id: AttemptId,
    ) -> Result<AttemptSnapshot, AttemptStoreError>;

    /// Atomically acquires a lease for a queued attempt.
    async fn acquire_lease(&self, request: AcquireLease) -> Result<Lease, AttemptStoreError>;

    /// Concludes an unleased queued attempt.
    async fn conclude_queued(
        &self,
        request: ConcludeQueuedAttempt,
    ) -> Result<(), AttemptStoreError>;

    /// Renews an active, correctly fenced lease.
    async fn renew_lease(&self, request: RenewLease) -> Result<Lease, AttemptStoreError>;

    /// Applies a correctly fenced lifecycle transition.
    async fn transition(&self, request: TransitionAttempt) -> Result<(), AttemptStoreError>;

    /// Requeues expired attempts within the supplied retry and batch bounds.
    async fn requeue_expired(
        &self,
        now: UnixMillis,
        maximum_failures: u32,
        limit: u32,
    ) -> Result<Vec<AttemptId>, AttemptStoreError>;
}

/// Read port for tenant-facing API and CLI handlers.
#[async_trait]
pub trait TenantAttemptQuery: Send + Sync {
    /// Fetches an attempt only when it belongs to the authenticated tenant.
    ///
    /// Missing and cross-tenant identifiers deliberately have the same result
    /// to avoid exposing durable object existence across tenant boundaries.
    async fn get_attempt_for_tenant(
        &self,
        tenant: &TenantScope,
        attempt_id: AttemptId,
    ) -> Result<AttemptSnapshot, AttemptStoreError>;
}
