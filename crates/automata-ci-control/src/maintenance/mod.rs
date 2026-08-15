//! Replica-safe control-plane maintenance values and repository ports.

#[cfg(feature = "adapter-spi")]
pub(crate) mod blocked;

use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};

use async_trait::async_trait;
use automata_ci_core::{AttemptId, RunId, UnixMillis};
use thiserror::Error;

use automata_ci_store::{RunReconciliation, StoreError};

/// Largest number of records handled per work category in one maintenance pass.
const MAX_MAINTENANCE_BATCH_SIZE: u16 = 1_000;

/// Positive, defensively bounded maintenance work limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceBatchSize(NonZeroU16);

impl MaintenanceBatchSize {
    /// Creates a batch size in `1..=1000`.
    ///
    /// # Errors
    ///
    /// Rejects zero and unbounded batch sizes.
    pub fn new(value: u16) -> Result<Self, MaintenanceValueError> {
        if value > MAX_MAINTENANCE_BATCH_SIZE {
            return Err(MaintenanceValueError::InvalidBatchSize);
        }
        NonZeroU16::new(value)
            .map(Self)
            .ok_or(MaintenanceValueError::InvalidBatchSize)
    }

    /// Returns the bounded batch size.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

/// Positive lease-failure budget representable by durable storage adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseFailureLimit(NonZeroU32);

impl LeaseFailureLimit {
    /// Creates a failure limit in `1..=i32::MAX`.
    ///
    /// # Errors
    ///
    /// Rejects zero and values outside the portable durable range.
    pub fn new(value: u32) -> Result<Self, MaintenanceValueError> {
        if value > i32::MAX as u32 {
            return Err(MaintenanceValueError::InvalidLeaseFailureLimit);
        }
        NonZeroU32::new(value)
            .map(Self)
            .ok_or(MaintenanceValueError::InvalidLeaseFailureLimit)
    }

    /// Returns the durable lease-failure limit.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// Minimum missing-heartbeat duration before a runner session is closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaleSessionTimeoutMillis(NonZeroU64);

impl StaleSessionTimeoutMillis {
    /// Creates a positive timeout representable as a signed durable timestamp delta.
    ///
    /// # Errors
    ///
    /// Rejects zero and values larger than `i64::MAX` milliseconds.
    pub fn new(value: u64) -> Result<Self, MaintenanceValueError> {
        if value > i64::MAX as u64 {
            return Err(MaintenanceValueError::InvalidStaleSessionTimeout);
        }
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(MaintenanceValueError::InvalidStaleSessionTimeout)
    }

    /// Returns the stale-session timeout in milliseconds.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    fn cutoff_at(self, observed_at: UnixMillis) -> Result<UnixMillis, MaintenanceValueError> {
        let timeout = i64::try_from(self.get())
            .map_err(|_| MaintenanceValueError::InvalidStaleSessionTimeout)?;
        observed_at
            .get()
            .checked_sub(timeout)
            .map(UnixMillis::new)
            .ok_or(MaintenanceValueError::StaleSessionCutoffOutOfRange)
    }
}

/// One trusted, bounded control-plane maintenance observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlPlaneMaintenanceRequest {
    observed_at: UnixMillis,
    maximum_lease_failures: LeaseFailureLimit,
    batch_size: MaintenanceBatchSize,
    stale_session_cutoff: UnixMillis,
}

impl ControlPlaneMaintenanceRequest {
    /// Creates one validated maintenance request.
    ///
    /// # Errors
    ///
    /// Rejects a timeout whose cutoff cannot be represented at `observed_at`.
    pub fn new(
        observed_at: UnixMillis,
        maximum_lease_failures: LeaseFailureLimit,
        batch_size: MaintenanceBatchSize,
        stale_session_timeout: StaleSessionTimeoutMillis,
    ) -> Result<Self, MaintenanceValueError> {
        let stale_session_cutoff = stale_session_timeout.cutoff_at(observed_at)?;
        Ok(Self {
            observed_at,
            maximum_lease_failures,
            batch_size,
            stale_session_cutoff,
        })
    }

    /// Returns the trusted observation time for this pass.
    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }

    /// Returns the lease-failure budget applied by this pass.
    #[must_use]
    pub const fn maximum_lease_failures(self) -> LeaseFailureLimit {
        self.maximum_lease_failures
    }

    /// Returns the per-category maintenance batch size.
    #[must_use]
    pub const fn batch_size(self) -> MaintenanceBatchSize {
        self.batch_size
    }

    /// Returns the oldest session heartbeat still considered live.
    #[must_use]
    pub const fn stale_session_cutoff(self) -> UnixMillis {
        self.stale_session_cutoff
    }
}

/// Durable outcome selected for an expired active attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpiredAttemptDisposition {
    /// Work had not started and remains within its failure budget.
    Requeued,
    /// Work had started or exhausted its failure budget and failed closed.
    Lost,
}

/// One expired attempt mutation and its atomically reconciled aggregate run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpiredAttemptMaintenance {
    attempt_id: AttemptId,
    disposition: ExpiredAttemptDisposition,
    reconciliation: RunReconciliation,
}

impl ExpiredAttemptMaintenance {
    #[cfg(feature = "adapter-spi")]
    pub(crate) const fn new(
        attempt_id: AttemptId,
        disposition: ExpiredAttemptDisposition,
        reconciliation: RunReconciliation,
    ) -> Self {
        Self {
            attempt_id,
            disposition,
            reconciliation,
        }
    }

    /// Returns the changed attempt identity.
    #[must_use]
    pub const fn attempt_id(self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the atomically reconciled run identity.
    #[must_use]
    pub const fn run_id(self) -> RunId {
        self.reconciliation.run_id()
    }

    /// Returns the durable disposition selected for the attempt.
    #[must_use]
    pub const fn disposition(self) -> ExpiredAttemptDisposition {
        self.disposition
    }

    /// Returns the aggregate run reconciliation committed with the attempt.
    #[must_use]
    pub const fn reconciliation(self) -> RunReconciliation {
        self.reconciliation
    }
}

/// Bounded work performed by one replica maintenance pass.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ControlPlaneMaintenanceReport {
    expired_attempts: Vec<ExpiredAttemptMaintenance>,
    skipped_blocked_attempts: u16,
    closed_stale_sessions: u16,
}

impl ControlPlaneMaintenanceReport {
    #[cfg(feature = "adapter-spi")]
    pub(crate) const fn new(
        expired_attempts: Vec<ExpiredAttemptMaintenance>,
        skipped_blocked_attempts: u16,
        closed_stale_sessions: u16,
    ) -> Self {
        Self {
            expired_attempts,
            skipped_blocked_attempts,
            closed_stale_sessions,
        }
    }

    /// Attempts changed by this pass, in stable expiry/identity order.
    #[must_use]
    pub fn expired_attempts(&self) -> &[ExpiredAttemptMaintenance] {
        &self.expired_attempts
    }

    /// Returns the number of stale sessions closed by this pass.
    #[must_use]
    pub const fn closed_stale_sessions(&self) -> u16 {
        self.closed_stale_sessions
    }

    /// Returns the number of dependency-blocked attempts skipped by this pass.
    #[must_use]
    pub const fn skipped_blocked_attempts(&self) -> u16 {
        self.skipped_blocked_attempts
    }

    /// Returns whether the pass committed no maintenance changes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.expired_attempts.is_empty()
            && self.skipped_blocked_attempts == 0
            && self.closed_stale_sessions == 0
    }
}

/// Invalid provider-neutral maintenance configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MaintenanceValueError {
    /// A batch size was zero or exceeded the portable ceiling.
    #[error("maintenance batch size must be in 1..={MAX_MAINTENANCE_BATCH_SIZE}")]
    InvalidBatchSize,
    /// The lease failure limit was zero or exceeded the portable durable range.
    #[error("maximum lease failures must be in 1..=i32::MAX")]
    InvalidLeaseFailureLimit,
    /// The runner-session timeout was zero or exceeded the portable timestamp range.
    #[error("stale runner-session timeout must be in 1..=i64::MAX milliseconds")]
    InvalidStaleSessionTimeout,
    /// Subtracting the timeout from trusted observation time overflowed.
    #[error("stale runner-session cutoff is outside the durable timestamp range")]
    StaleSessionCutoffOutOfRange,
}

/// Replica-safe durable control-loop boundary.
#[async_trait]
pub trait ControlPlaneMaintenanceRepository: std::fmt::Debug + Send + Sync {
    /// Reaps expired leases, propagates blocked skips, closes stale sessions,
    /// and atomically reconciles every changed attempt's run.
    async fn maintain_control_plane(
        &self,
        request: ControlPlaneMaintenanceRequest,
    ) -> Result<ControlPlaneMaintenanceReport, StoreError>;
}
