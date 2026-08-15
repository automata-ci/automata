use automata_ci_core::{AttemptId, LeaseGuard, RunnerId, UnixMillis};
use automata_ci_store::{AttemptCommandError, RunnerSessionFence};

use super::validate_lease_interval;

/// A request to renew an active lease at a control-plane-observed time.
///
/// Carrying `observed_at` prevents a runner from reviving an already expired
/// lease merely because the expiry reaper has not processed it yet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenewLease {
    attempt_id: AttemptId,
    /// Identity established by the runner authentication boundary.
    session: RunnerSessionFence,
    guard: LeaseGuard,
    /// Time at which the trusted control plane observed this renewal.
    observed_at: UnixMillis,
    expires_at: UnixMillis,
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
