//! Fenced job state, terminal result, and cancellation messages.

use automata_ci_core::{AttemptId, JobLifecycle, JobResult, LeaseGuard, UnixMillis};
use serde::{Deserialize, Serialize};

use super::{MessageHeader, ServerCommandHeader};

/// Fenced runner transition event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JobStateUpdate {
    header: MessageHeader,
    attempt_id: AttemptId,
    guard: LeaseGuard,
    lifecycle: JobLifecycle,
    occurred_at: UnixMillis,
}

impl JobStateUpdate {
    /// Creates an idempotent lifecycle observation for one fenced attempt.
    #[must_use]
    pub const fn new(
        header: MessageHeader,
        attempt_id: AttemptId,
        guard: LeaseGuard,
        lifecycle: JobLifecycle,
        occurred_at: UnixMillis,
    ) -> Self {
        Self {
            header,
            attempt_id,
            guard,
            lifecycle,
            occurred_at,
        }
    }

    #[must_use]
    /// Returns the runner request identity used for replay detection.
    pub const fn header(&self) -> MessageHeader {
        self.header
    }

    #[must_use]
    /// Returns the exact attempt whose state changed.
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    #[must_use]
    /// Returns the lease identity and fencing token authorizing the update.
    pub const fn guard(&self) -> LeaseGuard {
        self.guard
    }

    #[must_use]
    /// Returns the observed lifecycle state.
    pub const fn lifecycle(&self) -> JobLifecycle {
        self.lifecycle
    }

    #[must_use]
    /// Returns the runner-supplied occurrence time in Unix milliseconds.
    pub const fn occurred_at(&self) -> UnixMillis {
        self.occurred_at
    }
}

/// Fenced, idempotent terminal-result commit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JobResultMessage {
    header: MessageHeader,
    guard: LeaseGuard,
    result: JobResult,
}

impl JobResultMessage {
    /// Creates an idempotent terminal-result commit under a lease fence.
    #[must_use]
    pub const fn new(header: MessageHeader, guard: LeaseGuard, result: JobResult) -> Self {
        Self {
            header,
            guard,
            result,
        }
    }

    #[must_use]
    /// Returns the runner request identity used for replay detection.
    pub const fn header(&self) -> MessageHeader {
        self.header
    }

    #[must_use]
    /// Returns the lease identity and fencing token authorizing the result.
    pub const fn guard(&self) -> LeaseGuard {
        self.guard
    }

    #[must_use]
    /// Borrows the terminal result and its exact attempt identity.
    pub const fn result(&self) -> &JobResult {
        &self.result
    }
}

/// Server cancellation request for an active lease.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CancelJob {
    header: ServerCommandHeader,
    attempt_id: AttemptId,
    guard: LeaseGuard,
    reason: String,
    requested_at: UnixMillis,
}

impl CancelJob {
    /// Creates a durable cancellation command for one fenced attempt.
    #[must_use]
    pub fn new(
        header: ServerCommandHeader,
        attempt_id: AttemptId,
        guard: LeaseGuard,
        reason: impl Into<String>,
        requested_at: UnixMillis,
    ) -> Self {
        Self {
            header,
            attempt_id,
            guard,
            reason: reason.into(),
            requested_at,
        }
    }

    #[must_use]
    /// Returns the stable command identity and replay sequence.
    pub const fn header(&self) -> ServerCommandHeader {
        self.header
    }

    #[must_use]
    /// Returns the exact attempt to cancel.
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    #[must_use]
    /// Returns the lease identity and fencing token authorizing cancellation.
    pub const fn guard(&self) -> LeaseGuard {
        self.guard
    }

    #[must_use]
    /// Returns the sanitized operator-facing cancellation reason.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    #[must_use]
    /// Returns when the server requested cancellation, in Unix milliseconds.
    pub const fn requested_at(&self) -> UnixMillis {
        self.requested_at
    }
}
