//! Durable attempt state and fenced mutations.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{JobLifecycle, Lease, LeaseError, LeaseGuard, TransitionError};
use crate::{
    AttemptId, AttemptNumber, CORE_SCHEMA_VERSION, FencingToken, IdentifierError, JobId, LeaseId,
    RunnerId, UnixMillis,
};

/// Durable state for one attempt. Concrete sandbox/process handles live elsewhere.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JobAttemptState {
    schema_version: u16,
    attempt_id: AttemptId,
    job_id: JobId,
    attempt_number: AttemptNumber,
    lifecycle: JobLifecycle,
    current_fencing_token: Option<FencingToken>,
    active_lease: Option<Lease>,
}

impl JobAttemptState {
    /// Creates a queued attempt with no previously issued fencing token.
    #[must_use]
    pub fn new(attempt_id: AttemptId, job_id: JobId, attempt_number: AttemptNumber) -> Self {
        Self {
            schema_version: CORE_SCHEMA_VERSION,
            attempt_id,
            job_id,
            attempt_number,
            lifecycle: JobLifecycle::Queued,
            current_fencing_token: None,
            active_lease: None,
        }
    }

    /// Returns the durable-state schema encoded by this snapshot.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the durable identity of this job attempt.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the logical job to which this attempt belongs.
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    /// Returns this job's positive, monotonically increasing attempt number.
    #[must_use]
    pub const fn attempt_number(&self) -> AttemptNumber {
        self.attempt_number
    }

    /// Returns the current execution lifecycle state.
    #[must_use]
    pub const fn lifecycle(&self) -> JobLifecycle {
        self.lifecycle
    }

    /// Returns the high-water fencing token, including after lease revocation.
    #[must_use]
    pub const fn current_fencing_token(&self) -> Option<FencingToken> {
        self.current_fencing_token
    }

    /// Returns the exclusive active lease, if this lifecycle requires one.
    #[must_use]
    pub const fn active_lease(&self) -> Option<&Lease> {
        self.active_lease.as_ref()
    }

    /// Issues a new lease and monotonically advances the fencing token.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptStateError`] if the attempt is not queued, the fencing
    /// counter is exhausted, or the requested lease interval is invalid.
    pub fn acquire_lease(
        &mut self,
        lease_id: LeaseId,
        runner_id: RunnerId,
        issued_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Lease, AttemptStateError> {
        self.lifecycle
            .validate_transition(JobLifecycle::Leased)
            .map_err(AttemptStateError::Transition)?;
        let fencing_token = match self.current_fencing_token {
            Some(current) => current.checked_next()?,
            None => FencingToken::new(1)?,
        };
        let lease = Lease::new(
            lease_id,
            self.attempt_id,
            runner_id,
            fencing_token,
            issued_at,
            expires_at,
        )?;
        self.lifecycle = JobLifecycle::Leased;
        self.current_fencing_token = Some(fencing_token);
        self.active_lease = Some(lease.clone());
        Ok(lease)
    }

    /// Rejects stale/future fencing tokens and mismatched lease identities.
    ///
    /// # Errors
    ///
    /// Returns [`FenceError`] unless the guard exactly matches the active lease
    /// and its current fencing token.
    pub fn verify_fence(&self, guard: LeaseGuard) -> Result<(), FenceError> {
        let active = self
            .active_lease
            .as_ref()
            .ok_or(FenceError::NoActiveLease)?;
        let expected = active.fencing_token();
        if guard.fencing_token() < expected {
            return Err(FenceError::StaleFencingToken {
                expected,
                received: guard.fencing_token(),
            });
        }
        if guard.fencing_token() > expected {
            return Err(FenceError::FutureFencingToken {
                expected,
                received: guard.fencing_token(),
            });
        }
        if guard.lease_id() != active.lease_id() {
            return Err(FenceError::LeaseMismatch {
                expected: active.lease_id(),
                received: guard.lease_id(),
            });
        }
        Ok(())
    }

    /// Applies an authorized state transition. Requeue and terminal states revoke
    /// the active lease while retaining the high-water fencing token.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptStateError`] when the guard is not current or the
    /// lifecycle edge is invalid.
    pub fn apply_transition(
        &mut self,
        guard: LeaseGuard,
        next: JobLifecycle,
    ) -> Result<(), AttemptStateError> {
        self.verify_fence(guard)?;
        self.lifecycle
            .validate_transition(next)
            .map_err(AttemptStateError::Transition)?;
        self.lifecycle = next;
        if next == JobLifecycle::Queued || next.is_terminal() {
            self.active_lease = None;
        }
        Ok(())
    }

    /// Extends an active lease after validating its credential and monotonicity.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptStateError`] for an invalid guard or an expiration that
    /// does not strictly extend the active lease.
    pub fn renew_lease(
        &mut self,
        guard: LeaseGuard,
        expires_at: UnixMillis,
    ) -> Result<Lease, AttemptStateError> {
        self.verify_fence(guard)?;
        let active = self
            .active_lease
            .as_mut()
            .ok_or(FenceError::NoActiveLease)?;
        active.renew(expires_at)?;
        Ok(active.clone())
    }

    /// Validates invariants after reading this state from durable storage.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptStateError`] for unsupported schemas or inconsistent
    /// lifecycle, lease, attempt, and fencing fields.
    pub fn validate(&self) -> Result<(), AttemptStateError> {
        if self.schema_version != CORE_SCHEMA_VERSION {
            return Err(AttemptStateError::UnsupportedSchema {
                supported: CORE_SCHEMA_VERSION,
                received: self.schema_version,
            });
        }
        let needs_lease = matches!(
            self.lifecycle,
            JobLifecycle::Leased
                | JobLifecycle::Preparing
                | JobLifecycle::Running
                | JobLifecycle::Cancelling
                | JobLifecycle::Finalizing
        );
        if needs_lease != self.active_lease.is_some() {
            return Err(AttemptStateError::LeaseStateInvariant(self.lifecycle));
        }
        if let Some(lease) = &self.active_lease {
            lease.validate()?;
            if lease.attempt_id() != self.attempt_id {
                return Err(AttemptStateError::LeaseAttemptMismatch);
            }
            if self.current_fencing_token != Some(lease.fencing_token()) {
                return Err(AttemptStateError::LeaseTokenMismatch);
            }
        }
        Ok(())
    }
}

/// Fencing authorization failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FenceError {
    /// The attempt has no lease against which to verify the credential.
    #[error("the attempt has no active lease")]
    NoActiveLease,
    /// The credential names a different lease at the current fence.
    #[error("lease ID mismatch: expected {expected}, received {received}")]
    LeaseMismatch {
        /// Lease currently authorized to mutate the attempt.
        expected: LeaseId,
        /// Lease named by the supplied credential.
        received: LeaseId,
    },
    /// The credential predates the current lease generation.
    #[error("stale fencing token: expected {expected:?}, received {received:?}")]
    StaleFencingToken {
        /// Current high-water fencing token.
        expected: FencingToken,
        /// Older token carried by the supplied credential.
        received: FencingToken,
    },
    /// The credential carries a token this attempt has never issued.
    #[error("unissued future fencing token: expected {expected:?}, received {received:?}")]
    FutureFencingToken {
        /// Current high-water fencing token.
        expected: FencingToken,
        /// Future token carried by the supplied credential.
        received: FencingToken,
    },
}

/// Mutation and durable-state validation errors for attempts.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AttemptStateError {
    /// The requested lifecycle edge is not part of the state machine.
    #[error(transparent)]
    Transition(TransitionError),
    /// The supplied lease credential does not authorize this mutation.
    #[error(transparent)]
    Fence(#[from] FenceError),
    /// The lease interval or renewal is invalid.
    #[error(transparent)]
    Lease(#[from] LeaseError),
    /// A generated positive identifier or fencing token is invalid or exhausted.
    #[error(transparent)]
    Identifier(#[from] IdentifierError),
    /// The durable snapshot uses a schema this build cannot interpret safely.
    #[error("unsupported attempt-state schema {received}; this build supports {supported}")]
    UnsupportedSchema {
        /// Schema understood by this build.
        supported: u16,
        /// Schema carried by the durable snapshot.
        received: u16,
    },
    /// Lease presence disagrees with the lifecycle's authorization needs.
    #[error("lifecycle {0:?} has inconsistent active-lease presence")]
    LeaseStateInvariant(JobLifecycle),
    /// The embedded lease belongs to another attempt.
    #[error("active lease belongs to another attempt")]
    LeaseAttemptMismatch,
    /// The embedded lease does not carry the attempt's high-water token.
    #[error("active lease fencing token differs from the attempt high-water token")]
    LeaseTokenMismatch,
}
