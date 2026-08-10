use automata_ci_core::{
    AttemptId, AttemptNumber, FencingToken, JobId, JobLifecycle, Lease, LeaseId, RunnerId,
    UnixMillis,
};

use crate::AttemptAssignment;
use crate::AttemptSnapshotError;

/// A validated, backend-neutral view of one durable job attempt.
///
/// Use [`AttemptSnapshot::builder`] when implementing a storage adapter. The
/// builder accepts an entire [`Lease`] instead of independent optional lease
/// columns, so a caller cannot accidentally publish a partial lease tuple.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptSnapshot {
    pub(crate) attempt_id: AttemptId,
    pub(crate) job_id: JobId,
    pub(crate) attempt_number: AttemptNumber,
    pub(crate) lifecycle: JobLifecycle,
    pub(crate) fencing_token: Option<FencingToken>,
    pub(crate) lease_id: Option<LeaseId>,
    pub(crate) runner_id: Option<RunnerId>,
    pub(crate) assignment: Option<AttemptAssignment>,
    pub(crate) lease_issued_at: Option<UnixMillis>,
    pub(crate) lease_expires_at: Option<UnixMillis>,
    pub(crate) lease_failures: u32,
    pub(crate) queued_at: UnixMillis,
    pub(crate) changed_at: UnixMillis,
}

impl AttemptSnapshot {
    /// Starts a validated snapshot builder with all optional durable state
    /// absent and a zero lease-failure count.
    #[must_use]
    pub const fn builder(
        attempt_id: AttemptId,
        job_id: JobId,
        attempt_number: AttemptNumber,
        lifecycle: JobLifecycle,
        queued_at: UnixMillis,
        changed_at: UnixMillis,
    ) -> AttemptSnapshotBuilder {
        AttemptSnapshotBuilder {
            attempt_id,
            job_id,
            attempt_number,
            lifecycle,
            retained_fencing_token: None,
            active_lease: None,
            active_assignment: None,
            lease_failures: 0,
            queued_at,
            changed_at,
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
    pub const fn lifecycle(self) -> JobLifecycle {
        self.lifecycle
    }

    /// Returns the high-water fencing token, including after a lease is
    /// revoked. `None` means no lease has ever been issued.
    #[must_use]
    pub const fn fencing_token(self) -> Option<FencingToken> {
        self.fencing_token
    }

    #[must_use]
    pub const fn lease_id(self) -> Option<LeaseId> {
        self.lease_id
    }

    #[must_use]
    pub const fn runner_id(self) -> Option<RunnerId> {
        self.runner_id
    }

    /// Returns the complete session/slot fence while the attempt is active.
    #[must_use]
    pub const fn assignment(self) -> Option<AttemptAssignment> {
        self.assignment
    }

    #[must_use]
    pub const fn lease_issued_at(self) -> Option<UnixMillis> {
        self.lease_issued_at
    }

    #[must_use]
    pub const fn lease_expires_at(self) -> Option<UnixMillis> {
        self.lease_expires_at
    }

    #[must_use]
    pub const fn lease_failures(self) -> u32 {
        self.lease_failures
    }

    #[must_use]
    pub const fn queued_at(self) -> UnixMillis {
        self.queued_at
    }

    #[must_use]
    pub const fn changed_at(self) -> UnixMillis {
        self.changed_at
    }
}

/// Builder for an [`AttemptSnapshot`] returned by a durable-storage adapter.
#[derive(Clone, Debug)]
pub struct AttemptSnapshotBuilder {
    attempt_id: AttemptId,
    job_id: JobId,
    attempt_number: AttemptNumber,
    lifecycle: JobLifecycle,
    retained_fencing_token: Option<FencingToken>,
    active_lease: Option<Lease>,
    active_assignment: Option<AttemptAssignment>,
    lease_failures: u32,
    queued_at: UnixMillis,
    changed_at: UnixMillis,
}

impl AttemptSnapshotBuilder {
    /// Records the high-water fencing token for an attempt with no active
    /// lease. Acquiring a lease supersedes this value with that lease's token.
    #[must_use]
    pub const fn with_retained_fencing_token(mut self, fencing_token: FencingToken) -> Self {
        self.retained_fencing_token = Some(fencing_token);
        self
    }

    /// Records one complete, already interval-validated active lease.
    #[must_use]
    pub fn with_active_lease(mut self, lease: Lease, assignment: AttemptAssignment) -> Self {
        self.active_lease = Some(lease);
        self.active_assignment = Some(assignment);
        self
    }

    #[must_use]
    pub const fn with_lease_failures(mut self, lease_failures: u32) -> Self {
        self.lease_failures = lease_failures;
        self
    }

    /// Validates lifecycle, lease ownership, and durable timestamp invariants.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptSnapshotError`] if the lifecycle and active-lease
    /// presence disagree, the lease belongs to another attempt, the lease is
    /// invalid, or durable timestamps are not monotonic and within the lease.
    pub fn build(self) -> Result<AttemptSnapshot, AttemptSnapshotError> {
        if self.changed_at < self.queued_at {
            return Err(AttemptSnapshotError::ChangedBeforeQueued {
                queued_at: self.queued_at,
                changed_at: self.changed_at,
            });
        }

        let lifecycle_requires_lease = lifecycle_requires_lease(self.lifecycle);
        match (lifecycle_requires_lease, self.active_lease.as_ref()) {
            (true, None) => {
                return Err(AttemptSnapshotError::ActiveLifecycleMissingLease(
                    self.lifecycle,
                ));
            }
            (false, Some(_)) => {
                return Err(AttemptSnapshotError::InactiveLifecycleHasLease(
                    self.lifecycle,
                ));
            }
            _ => {}
        }

        match (lifecycle_requires_lease, self.active_assignment) {
            (true, None) => {
                return Err(AttemptSnapshotError::ActiveLifecycleMissingAssignment(
                    self.lifecycle,
                ));
            }
            (false, Some(_)) => {
                return Err(AttemptSnapshotError::InactiveLifecycleHasAssignment(
                    self.lifecycle,
                ));
            }
            _ => {}
        }

        if let Some(lease) = &self.active_lease {
            let assignment = self.active_assignment.ok_or(
                AttemptSnapshotError::ActiveLifecycleMissingAssignment(self.lifecycle),
            )?;
            lease
                .validate()
                .map_err(AttemptSnapshotError::InvalidLease)?;
            if lease.attempt_id() != self.attempt_id {
                return Err(AttemptSnapshotError::LeaseAttemptMismatch {
                    snapshot_attempt_id: self.attempt_id,
                    lease_attempt_id: lease.attempt_id(),
                });
            }
            if lease.issued_at() < self.queued_at {
                return Err(AttemptSnapshotError::LeaseIssuedBeforeQueued {
                    queued_at: self.queued_at,
                    issued_at: lease.issued_at(),
                });
            }
            if self.changed_at < lease.issued_at() {
                return Err(AttemptSnapshotError::ChangedBeforeLeaseIssuance {
                    issued_at: lease.issued_at(),
                    changed_at: self.changed_at,
                });
            }
            if self.changed_at >= lease.expires_at() {
                return Err(AttemptSnapshotError::ChangedOutsideLease {
                    changed_at: self.changed_at,
                    expires_at: lease.expires_at(),
                });
            }
            assignment
                .validate_lease(lease)
                .map_err(AttemptSnapshotError::InvalidAssignment)?;
        }

        let (fencing_token, lease_id, runner_id, lease_issued_at, lease_expires_at) =
            self.active_lease.as_ref().map_or(
                (self.retained_fencing_token, None, None, None, None),
                |lease| {
                    (
                        Some(lease.fencing_token()),
                        Some(lease.lease_id()),
                        Some(lease.runner_id()),
                        Some(lease.issued_at()),
                        Some(lease.expires_at()),
                    )
                },
            );

        Ok(AttemptSnapshot {
            attempt_id: self.attempt_id,
            job_id: self.job_id,
            attempt_number: self.attempt_number,
            lifecycle: self.lifecycle,
            fencing_token,
            lease_id,
            runner_id,
            assignment: self.active_assignment,
            lease_issued_at,
            lease_expires_at,
            lease_failures: self.lease_failures,
            queued_at: self.queued_at,
            changed_at: self.changed_at,
        })
    }
}

const fn lifecycle_requires_lease(lifecycle: JobLifecycle) -> bool {
    matches!(
        lifecycle,
        JobLifecycle::Leased
            | JobLifecycle::Preparing
            | JobLifecycle::Running
            | JobLifecycle::Cancelling
            | JobLifecycle::Finalizing
    )
}
