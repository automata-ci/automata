use async_trait::async_trait;
use automata_ci_core::{
    AttemptId, AttemptNumber, JobId, JobLifecycle, Lease, LeaseGuard, LeaseId, RunnerId, UnixMillis,
};

use crate::{
    AttemptCommandError, AttemptSnapshot, AttemptStoreError, RunnerSessionFence, StableRunnerSlot,
    TenantScope,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueuedAttempt {
    pub(crate) attempt_id: AttemptId,
    pub(crate) job_id: JobId,
    pub(crate) attempt_number: AttemptNumber,
    pub(crate) queued_at: UnixMillis,
}

impl QueuedAttempt {
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

    #[must_use]
    pub const fn attempt_id(self) -> AttemptId {
        self.attempt_id
    }

    #[must_use]
    pub const fn job_id(self) -> JobId {
        self.job_id
    }

    #[must_use]
    pub const fn attempt_number(self) -> AttemptNumber {
        self.attempt_number
    }

    #[must_use]
    pub const fn queued_at(self) -> UnixMillis {
        self.queued_at
    }
}

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

    #[must_use]
    pub const fn attempt_id(self) -> AttemptId {
        self.attempt_id
    }

    #[must_use]
    pub const fn lease_id(self) -> LeaseId {
        self.lease_id
    }

    #[must_use]
    pub const fn runner_id(self) -> RunnerId {
        self.session.runner_id()
    }

    #[must_use]
    pub const fn session(self) -> RunnerSessionFence {
        self.session
    }

    #[must_use]
    pub const fn slot(self) -> StableRunnerSlot {
        self.slot
    }

    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }

    #[must_use]
    pub const fn expires_at(self) -> UnixMillis {
        self.expires_at
    }
}

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

    #[must_use]
    pub const fn attempt_id(self) -> AttemptId {
        self.attempt_id
    }

    #[must_use]
    pub const fn runner_id(self) -> RunnerId {
        self.session.runner_id()
    }

    #[must_use]
    pub const fn session(self) -> RunnerSessionFence {
        self.session
    }

    #[must_use]
    pub const fn guard(self) -> LeaseGuard {
        self.guard
    }

    #[must_use]
    pub const fn next(self) -> JobLifecycle {
        self.next
    }

    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }
}

/// A request to renew an active lease at a control-plane-observed time.
///
/// Carrying `observed_at` prevents a runner from reviving an already expired
/// lease merely because the expiry reaper has not processed it yet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenewLease {
    pub(crate) attempt_id: AttemptId,
    /// Identity established by the runner authentication boundary.
    pub(crate) session: RunnerSessionFence,
    pub(crate) guard: LeaseGuard,
    /// Time at which the trusted control plane observed this renewal.
    pub(crate) observed_at: UnixMillis,
    pub(crate) expires_at: UnixMillis,
}

impl RenewLease {
    /// Creates a lease renewal observed by the trusted control plane.
    ///
    /// The repository additionally verifies that `expires_at` strictly extends
    /// the current durable expiration, except that a credential-bounded lease
    /// already at its immutable authority ceiling may refresh liveness without
    /// extending that ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptCommandError::InvalidLeaseInterval`] unless expiration
    /// is strictly later than observation.
    pub fn new(
        attempt_id: AttemptId,
        session: RunnerSessionFence,
        guard: LeaseGuard,
        observed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, AttemptCommandError> {
        validate_lease_interval(observed_at, expires_at)?;
        Ok(Self {
            attempt_id,
            session,
            guard,
            observed_at,
            expires_at,
        })
    }

    #[must_use]
    pub const fn attempt_id(self) -> AttemptId {
        self.attempt_id
    }

    #[must_use]
    pub const fn runner_id(self) -> RunnerId {
        self.session.runner_id()
    }

    #[must_use]
    pub const fn session(self) -> RunnerSessionFence {
        self.session
    }

    #[must_use]
    pub const fn guard(self) -> LeaseGuard {
        self.guard
    }

    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }

    #[must_use]
    pub const fn expires_at(self) -> UnixMillis {
        self.expires_at
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

    #[must_use]
    pub const fn attempt_id(self) -> AttemptId {
        self.attempt_id
    }

    #[must_use]
    pub const fn conclusion(self) -> JobLifecycle {
        self.conclusion
    }

    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }
}

fn validate_lease_interval(
    observed_at: UnixMillis,
    expires_at: UnixMillis,
) -> Result<(), AttemptCommandError> {
    if expires_at <= observed_at {
        return Err(AttemptCommandError::InvalidLeaseInterval);
    }
    Ok(())
}

/// Internal scheduling port.
///
/// These ID-only operations are intentionally not suitable for tenant-facing
/// HTTP or CLI handlers. Such handlers must use [`TenantAttemptQuery`], which
/// enforces tenant scope in the repository operation itself.
#[async_trait]
pub trait InternalAttemptRepository: Send + Sync {
    async fn insert_queued(&self, attempt: QueuedAttempt) -> Result<(), AttemptStoreError>;

    async fn get_attempt(
        &self,
        attempt_id: AttemptId,
    ) -> Result<AttemptSnapshot, AttemptStoreError>;

    async fn acquire_lease(&self, request: AcquireLease) -> Result<Lease, AttemptStoreError>;

    async fn conclude_queued(
        &self,
        request: ConcludeQueuedAttempt,
    ) -> Result<(), AttemptStoreError>;

    async fn renew_lease(&self, request: RenewLease) -> Result<Lease, AttemptStoreError>;

    async fn transition(&self, request: TransitionAttempt) -> Result<(), AttemptStoreError>;

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
