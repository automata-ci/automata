//! Work leasing, acceptance, liveness, and renewal messages.

use automata_ci_core::{
    AttemptId, FencingToken, JobIrEnvelope, JobLifecycle, Lease, LeaseGuard, LeaseId, OperationId,
    UnixMillis,
};
use serde::{Deserialize, Serialize};

use super::MessageValidationError;
use super::{MessageHeader, RunnerSlotOrdinal, ServerCommandHeader};

/// Runner request for at most one assignment to one stable slot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LeaseRequest {
    header: MessageHeader,
    slot: RunnerSlotOrdinal,
    acknowledges_operation_id: Option<OperationId>,
}

impl LeaseRequest {
    /// Creates the first lease request in a slot's request chain.
    #[must_use]
    pub const fn first(header: MessageHeader, slot: RunnerSlotOrdinal) -> Self {
        Self {
            header,
            slot,
            acknowledges_operation_id: None,
        }
    }

    /// Creates a successor that acknowledges the preceding request in the
    /// same slot's request chain.
    #[must_use]
    pub const fn successor(
        header: MessageHeader,
        slot: RunnerSlotOrdinal,
        acknowledges_operation_id: OperationId,
    ) -> Self {
        Self {
            header,
            slot,
            acknowledges_operation_id: Some(acknowledges_operation_id),
        }
    }

    #[must_use]
    /// Returns the idempotent request header for this poll.
    pub const fn header(&self) -> MessageHeader {
        self.header
    }

    #[must_use]
    /// Returns the stable runner slot polling for work.
    pub const fn slot(&self) -> RunnerSlotOrdinal {
        self.slot
    }

    /// Returns the immediately preceding lease-request operation implicitly
    /// acknowledged by this successor, or `None` for the first request.
    #[must_use]
    pub const fn acknowledges_operation_id(&self) -> Option<OperationId> {
        self.acknowledges_operation_id
    }

    /// Validates locally provable lease-request invariants.
    ///
    /// # Errors
    ///
    /// Returns [`MessageValidationError`] when the header is not a supported
    /// runner request or a successor acknowledges its own operation ID.
    pub fn validate(&self) -> Result<(), MessageValidationError> {
        self.header.validate_request()?;
        if self.acknowledges_operation_id == Some(self.header.operation_id()) {
            return Err(MessageValidationError::LeaseRequestSelfAcknowledgement {
                operation_id: self.header.operation_id(),
            });
        }
        Ok(())
    }
}

/// Server offer containing an immutable job and its exclusive lease.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LeaseOffer {
    header: ServerCommandHeader,
    slot: RunnerSlotOrdinal,
    lease: Lease,
    job: JobIrEnvelope,
    runtime_authorities: Option<super::JobRuntimeAuthorities>,
    #[serde(default)]
    managed_secret_bindings: Option<super::ManagedSecretBindingOverlay>,
}

impl LeaseOffer {
    /// Creates an offer with required, execution-bound authority.
    #[must_use]
    pub const fn new(
        header: ServerCommandHeader,
        slot: RunnerSlotOrdinal,
        lease: Lease,
        job: JobIrEnvelope,
        runtime_authorities: super::JobRuntimeAuthorities,
    ) -> Self {
        Self {
            header,
            slot,
            lease,
            job,
            runtime_authorities: Some(runtime_authorities),
            managed_secret_bindings: None,
        }
    }

    /// Attaches the value-free secret-binding overlay for this exact lease.
    ///
    /// # Errors
    ///
    /// Rejects an overlay bound to another attempt, lease, or fencing token.
    pub fn with_managed_secret_bindings(
        mut self,
        overlay: super::ManagedSecretBindingOverlay,
    ) -> Result<Self, super::ManagedSecretBindingOverlayError> {
        overlay.validate_for(&self.lease)?;
        self.managed_secret_bindings = Some(overlay);
        Ok(self)
    }

    #[must_use]
    /// Returns the durable command header used for replay and ordering.
    pub const fn header(&self) -> ServerCommandHeader {
        self.header
    }

    #[must_use]
    /// Returns the stable runner slot selected for this assignment.
    pub const fn slot(&self) -> RunnerSlotOrdinal {
        self.slot
    }

    #[must_use]
    /// Borrows the exclusive attempt lease and its fencing token.
    pub const fn lease(&self) -> &Lease {
        &self.lease
    }

    #[must_use]
    /// Borrows the immutable, versioned job description.
    pub const fn job(&self) -> &JobIrEnvelope {
        &self.job
    }

    /// Returns the protected per-job runtime authority, when present.
    #[must_use]
    pub const fn runtime_authorities(&self) -> Option<&super::JobRuntimeAuthorities> {
        self.runtime_authorities.as_ref()
    }

    /// Returns the lease-scoped, value-free secret-binding overlay, if this
    /// command schema carries one.
    #[must_use]
    pub const fn managed_secret_bindings(&self) -> Option<&super::ManagedSecretBindingOverlay> {
        self.managed_secret_bindings.as_ref()
    }
}

/// Runner's idempotent acceptance or rejection of an offered lease.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LeaseResponse {
    header: MessageHeader,
    attempt_id: AttemptId,
    slot: RunnerSlotOrdinal,
    lease_id: LeaseId,
    fencing_token: FencingToken,
    disposition: LeaseDisposition,
}

impl LeaseResponse {
    /// Creates an acceptance or rejection bound to an exact offered lease.
    #[must_use]
    pub const fn new(
        header: MessageHeader,
        attempt_id: AttemptId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        disposition: LeaseDisposition,
    ) -> Self {
        Self {
            header,
            attempt_id,
            slot,
            lease_id: guard.lease_id(),
            fencing_token: guard.fencing_token(),
            disposition,
        }
    }

    #[must_use]
    /// Returns the idempotent runner-operation header.
    pub const fn header(&self) -> MessageHeader {
        self.header
    }

    #[must_use]
    /// Returns the exact attempt accepted or rejected.
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    #[must_use]
    /// Returns the stable slot that received the offer.
    pub const fn slot(&self) -> RunnerSlotOrdinal {
        self.slot
    }

    #[must_use]
    /// Reconstructs the lease identity and fencing token from the response.
    pub const fn guard(&self) -> LeaseGuard {
        LeaseGuard::new(self.lease_id, self.fencing_token)
    }

    #[must_use]
    /// Returns whether the runner accepted the lease or why it declined.
    pub const fn disposition(&self) -> &LeaseDisposition {
        &self.disposition
    }

    /// Validates this response against the durable lease offer.
    ///
    /// # Errors
    ///
    /// Returns [`MessageValidationError`] for protocol, session, attempt,
    /// slot, or lease-guard correlation mismatches.
    pub fn validate_for(&self, offer: &LeaseOffer) -> Result<(), MessageValidationError> {
        self.header.validate_request()?;
        offer
            .header
            .validate_for(self.header.protocol_version(), self.header.session_id())?;
        if self.attempt_id != offer.lease.attempt_id() {
            return Err(MessageValidationError::AttemptCorrelationMismatch {
                expected: offer.lease.attempt_id(),
                received: self.attempt_id,
            });
        }
        if self.slot != offer.slot {
            return Err(MessageValidationError::SlotCorrelationMismatch {
                expected: offer.slot,
                received: self.slot,
            });
        }
        let expected = offer.lease.guard();
        let received = self.guard();
        if received != expected {
            return Err(MessageValidationError::LeaseGuardCorrelationMismatch {
                expected,
                received,
            });
        }
        Ok(())
    }
}

/// Response to a lease offer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "reason", rename_all = "snake_case")]
pub enum LeaseDisposition {
    /// The runner durably accepted the exact offer and may begin execution.
    Accepted,
    /// The runner declined the offer without acquiring execution authority.
    Rejected(LeaseRejectionReason),
}

/// Typed runner reasons for declining work.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseRejectionReason {
    /// Locally available capacity changed after the request was sent.
    CapacityChanged,
    /// The runner's realized capabilities no longer satisfy the job.
    CapabilityChanged,
    /// The runner is draining and will not start new work.
    ShuttingDown,
    /// The immutable job failed local validation or preparation.
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
    /// Creates a liveness observation for one active fenced attempt.
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
    /// Returns the idempotent runner-operation header.
    pub const fn header(&self) -> MessageHeader {
        self.header
    }

    #[must_use]
    /// Returns the attempt whose lease remains active.
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    #[must_use]
    /// Returns the lease identity and fencing token authorizing the heartbeat.
    pub const fn guard(&self) -> LeaseGuard {
        self.guard
    }

    #[must_use]
    /// Returns the runner's current lifecycle observation.
    pub const fn lifecycle(&self) -> JobLifecycle {
        self.lifecycle
    }

    #[must_use]
    /// Returns when the runner sent the heartbeat, in Unix milliseconds.
    pub const fn sent_at(&self) -> UnixMillis {
        self.sent_at
    }
}

/// Server acknowledgement extending an active lease.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LeaseRenewal {
    header: MessageHeader,
    attempt_id: AttemptId,
    guard: LeaseGuard,
    expires_at: UnixMillis,
}

impl LeaseRenewal {
    /// Creates a response extending the exact lease reported by a heartbeat.
    #[must_use]
    pub const fn new(
        header: MessageHeader,
        attempt_id: AttemptId,
        guard: LeaseGuard,
        expires_at: UnixMillis,
    ) -> Self {
        Self {
            header,
            attempt_id,
            guard,
            expires_at,
        }
    }

    #[must_use]
    /// Returns the response header correlated to the heartbeat.
    pub const fn header(&self) -> MessageHeader {
        self.header
    }

    #[must_use]
    /// Returns the attempt whose lease was extended.
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    #[must_use]
    /// Returns the unchanged lease identity and fencing token.
    pub const fn guard(&self) -> LeaseGuard {
        self.guard
    }

    #[must_use]
    /// Returns the new exclusive expiry boundary in Unix milliseconds.
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }

    /// Validates this renewal against the heartbeat operation it answers.
    ///
    /// # Errors
    ///
    /// Returns [`MessageValidationError`] for response, attempt, or lease
    /// correlation mismatches.
    pub fn validate_for(&self, heartbeat: &LeaseHeartbeat) -> Result<(), MessageValidationError> {
        self.header.validate_reply_for(heartbeat.header)?;
        if self.attempt_id != heartbeat.attempt_id {
            return Err(MessageValidationError::AttemptCorrelationMismatch {
                expected: heartbeat.attempt_id,
                received: self.attempt_id,
            });
        }
        if self.guard != heartbeat.guard {
            return Err(MessageValidationError::LeaseGuardCorrelationMismatch {
                expected: heartbeat.guard,
                received: self.guard,
            });
        }
        Ok(())
    }
}
