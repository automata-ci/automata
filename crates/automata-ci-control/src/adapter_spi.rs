//! Unstable trust-boundary operations for Automata's first-party durable adapters.
//!
//! This is deliberately not a general-purpose construction API. Callers must
//! establish the documented durable-row predicates before invoking these hooks.
//! The feature and every item in this module may change without notice.

use automata_ci_core::{AttemptId, OperationId, Sha256Digest, UnixMillis};

pub use crate::attempt::durable::{
    AcquireLease, ConcludeQueuedAttempt, InternalAttemptRepository, QueuedAttempt,
    TenantAttemptQuery, TransitionAttempt,
};
pub use crate::attempt::snapshot::{AttemptSnapshot, AttemptSnapshotBuilder};
pub use crate::maintenance::blocked::{
    BlockedAttempt, BlockedAttemptRepository, BlockedConclusion, ConcludeBlockedAttempt,
};

/// Rehydrates one maintenance mutation from the same committed transaction.
#[must_use]
pub const fn expired_attempt_maintenance(
    attempt_id: AttemptId,
    disposition: crate::maintenance::ExpiredAttemptDisposition,
    reconciliation: automata_ci_store::RunReconciliation,
) -> crate::maintenance::ExpiredAttemptMaintenance {
    crate::maintenance::ExpiredAttemptMaintenance::new(attempt_id, disposition, reconciliation)
}

/// Rehydrates the bounded result of one maintenance pass.
#[must_use]
pub const fn control_plane_maintenance_report(
    expired_attempts: Vec<crate::maintenance::ExpiredAttemptMaintenance>,
    skipped_blocked_attempts: u16,
    closed_stale_sessions: u16,
) -> crate::maintenance::ControlPlaneMaintenanceReport {
    crate::maintenance::ControlPlaneMaintenanceReport::new(
        expired_attempts,
        skipped_blocked_attempts,
        closed_stale_sessions,
    )
}

/// Rehydrates and validates the versioned revoked-lease fallback representation.
pub fn revoked_lease_offer_fallback(
    representation_version: u16,
    response_operation_id: OperationId,
    retry_after_millis: u32,
    response_schema: automata_ci_store::DocumentSchema,
    response_digest: Sha256Digest,
) -> Result<crate::lease::RevokedLeaseOfferFallback, crate::lease::LeaseOfferCompletionError> {
    crate::lease::RevokedLeaseOfferFallback::from_persisted(
        representation_version,
        response_operation_id,
        retry_after_millis,
        response_schema,
        response_digest,
    )
}

/// Read-only durable cursor projection used by first-party adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunnableCursorView {
    cursor: crate::lease::RunnableCursorAdvance,
}

impl RunnableCursorView {
    /// Returns the exact session fence.
    #[must_use]
    pub const fn session(self) -> automata_ci_store::RunnerSessionFence {
        self.cursor.session()
    }

    /// Returns the stable runner slot.
    #[must_use]
    pub const fn slot(self) -> automata_ci_store::StableRunnerSlot {
        self.cursor.slot()
    }

    /// Returns the routing proof root.
    #[must_use]
    pub const fn routing_fingerprint(self) -> Sha256Digest {
        self.cursor.routing_fingerprint()
    }

    /// Returns the compare-and-swap version.
    #[must_use]
    pub const fn expected_version(self) -> u64 {
        self.cursor.expected_version()
    }

    /// Returns the inclusive queue position scanned through.
    #[must_use]
    pub const fn through(self) -> Option<crate::lease::RunnableQueueKey> {
        self.cursor.through()
    }

    /// Returns the cycle upper bound, if a cycle was established.
    #[must_use]
    pub const fn cycle_upper(self) -> Option<crate::lease::RunnableQueueKey> {
        self.cursor.cycle_upper()
    }
}

/// Inspects the cursor embedded in a successful claim request.
#[must_use]
pub const fn try_claim_attempt_cursor(
    request: &crate::lease::TryClaimAttempt,
) -> RunnableCursorView {
    RunnableCursorView {
        cursor: request.cursor(),
    }
}

/// Rebuilds a claim at repository-issued times while preserving its validated
/// request key, target, lease, and opaque authoritative scan cursor.
pub fn rebase_try_claim_attempt(
    request: &crate::lease::TryClaimAttempt,
    observed_at: UnixMillis,
    expires_at: UnixMillis,
) -> Result<crate::lease::TryClaimAttempt, crate::lease::ClaimCommandError> {
    request.rebased(observed_at, expires_at)
}

/// Inspects the cursor embedded in a terminal no-work request.
#[must_use]
pub const fn no_work_lease_request_cursor(
    request: &crate::lease::NoWorkLeaseRequest,
) -> RunnableCursorView {
    RunnableCursorView {
        cursor: request.cursor(),
    }
}
