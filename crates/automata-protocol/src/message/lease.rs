//! Work leasing, acceptance, liveness, and renewal messages.

use automata_core::{
    AttemptId, FencingToken, JobIrEnvelope, JobLifecycle, Lease, LeaseGuard, LeaseId, RunnerId,
    RunnerSessionId, UnixMillis,
};
use serde::{Deserialize, Serialize};

use super::MessageHeader;

/// Runner request for at most `available_slots` assignments.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LeaseRequest {
    header: MessageHeader,
    runner_id: RunnerId,
    session_id: RunnerSessionId,
    available_slots: u16,
}

impl LeaseRequest {
    #[must_use]
    pub const fn new(
        header: MessageHeader,
        runner_id: RunnerId,
        session_id: RunnerSessionId,
        available_slots: u16,
    ) -> Self {
        Self {
            header,
            runner_id,
            session_id,
            available_slots,
        }
    }

    #[must_use]
    pub const fn header(&self) -> MessageHeader {
        self.header
    }

    #[must_use]
    pub const fn runner_id(&self) -> RunnerId {
        self.runner_id
    }

    #[must_use]
    pub const fn session_id(&self) -> RunnerSessionId {
        self.session_id
    }

    #[must_use]
    pub const fn available_slots(&self) -> u16 {
        self.available_slots
    }
}

/// Server offer containing an immutable job and its exclusive lease.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LeaseOffer {
    header: MessageHeader,
    lease: Lease,
    job: JobIrEnvelope,
}

impl LeaseOffer {
    #[must_use]
    pub const fn new(header: MessageHeader, lease: Lease, job: JobIrEnvelope) -> Self {
        Self { header, lease, job }
    }

    #[must_use]
    pub const fn header(&self) -> MessageHeader {
        self.header
    }

    #[must_use]
    pub const fn lease(&self) -> &Lease {
        &self.lease
    }

    #[must_use]
    pub const fn job(&self) -> &JobIrEnvelope {
        &self.job
    }
}

/// Runner's idempotent acceptance or rejection of an offered lease.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LeaseResponse {
    header: MessageHeader,
    lease_id: LeaseId,
    fencing_token: FencingToken,
    disposition: LeaseDisposition,
}

impl LeaseResponse {
    #[must_use]
    pub const fn new(
        header: MessageHeader,
        guard: LeaseGuard,
        disposition: LeaseDisposition,
    ) -> Self {
        Self {
            header,
            lease_id: guard.lease_id(),
            fencing_token: guard.fencing_token(),
            disposition,
        }
    }

    #[must_use]
    pub const fn header(&self) -> MessageHeader {
        self.header
    }

    #[must_use]
    pub const fn guard(&self) -> LeaseGuard {
        LeaseGuard::new(self.lease_id, self.fencing_token)
    }

    #[must_use]
    pub const fn disposition(&self) -> &LeaseDisposition {
        &self.disposition
    }
}

/// Response to a lease offer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "reason", rename_all = "snake_case")]
pub enum LeaseDisposition {
    Accepted,
    Rejected(LeaseRejectionReason),
}

/// Typed runner reasons for declining work.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseRejectionReason {
    CapacityChanged,
    CapabilityChanged,
    ShuttingDown,
    InvalidJob,
}

/// Liveness and progress update for an active lease.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LeaseHeartbeat {
    header: MessageHeader,
    attempt_id: AttemptId,
    guard: LeaseGuard,
    lifecycle: JobLifecycle,
    sent_at: UnixMillis,
}

impl LeaseHeartbeat {
    #[must_use]
    pub const fn new(
        header: MessageHeader,
        attempt_id: AttemptId,
        guard: LeaseGuard,
        lifecycle: JobLifecycle,
        sent_at: UnixMillis,
    ) -> Self {
        Self {
            header,
            attempt_id,
            guard,
            lifecycle,
            sent_at,
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
    pub const fn sent_at(&self) -> UnixMillis {
        self.sent_at
    }
}

/// Server acknowledgement extending an active lease.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LeaseRenewal {
    header: MessageHeader,
    guard: LeaseGuard,
    expires_at: UnixMillis,
}

impl LeaseRenewal {
    #[must_use]
    pub const fn new(header: MessageHeader, guard: LeaseGuard, expires_at: UnixMillis) -> Self {
        Self {
            header,
            guard,
            expires_at,
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
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
}
