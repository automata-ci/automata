//! Fenced job state, terminal result, and cancellation messages.

use automata_core::{AttemptId, JobLifecycle, JobResult, LeaseGuard, UnixMillis};
use serde::{Deserialize, Serialize};

use super::MessageHeader;

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
    pub const fn header(&self) -> MessageHeader {
        self.header
    }

    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    #[must_use]
    pub const fn guard(&self) -> LeaseGuard {
        self.guard
    }

    #[must_use]
    pub const fn lifecycle(&self) -> JobLifecycle {
        self.lifecycle
    }

    #[must_use]
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
    #[must_use]
    pub const fn new(header: MessageHeader, guard: LeaseGuard, result: JobResult) -> Self {
        Self {
            header,
            guard,
            result,
        }
    }

    #[must_use]
    pub const fn header(&self) -> MessageHeader {
        self.header
    }

    #[must_use]
    pub const fn guard(&self) -> LeaseGuard {
        self.guard
    }

    #[must_use]
    pub const fn result(&self) -> &JobResult {
        &self.result
    }
}

/// Server cancellation request for an active lease.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CancelJob {
    header: MessageHeader,
    attempt_id: AttemptId,
    guard: LeaseGuard,
    reason: String,
    requested_at: UnixMillis,
}

impl CancelJob {
    #[must_use]
    pub fn new(
        header: MessageHeader,
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
    pub const fn header(&self) -> MessageHeader {
        self.header
    }

    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    #[must_use]
    pub const fn guard(&self) -> LeaseGuard {
        self.guard
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    #[must_use]
    pub const fn requested_at(&self) -> UnixMillis {
        self.requested_at
    }
}
