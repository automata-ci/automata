//! Work leasing, acceptance, liveness, and renewal messages.

use automata_ci_core::{
    AttemptId, FencingToken, JobIrEnvelope, JobLifecycle, Lease, LeaseGuard, LeaseId, OperationId,
    Sha256Digest, UnixMillis,
};
use serde::{Deserialize, Deserializer, Serialize};

use super::{CancelJob, LeaseAuthorityPollContributions, MessageValidationError};
use super::{MessageHeader, RunnerSlotOrdinal, ServerCommandHeader};

/// Runner request for at most one assignment to one stable slot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRequest {
    header: MessageHeader,
    slot: RunnerSlotOrdinal,
    acknowledges_operation_id: Option<OperationId>,
    authority_contributions: LeaseAuthorityPollContributions,
}

impl LeaseRequest {
    /// Creates the first lease request in a slot's request chain.
    #[must_use]
    pub const fn first(
        header: MessageHeader,
        slot: RunnerSlotOrdinal,
        authority_contributions: LeaseAuthorityPollContributions,
    ) -> Self {
        Self {
            header,
            slot,
            acknowledges_operation_id: None,
            authority_contributions,
        }
    }

    /// Creates a successor that acknowledges the preceding request in the
    /// same slot's request chain.
    #[must_use]
    pub const fn successor(
        header: MessageHeader,
        slot: RunnerSlotOrdinal,
        acknowledges_operation_id: OperationId,
        authority_contributions: LeaseAuthorityPollContributions,
    ) -> Self {
        Self {
            header,
            slot,
            acknowledges_operation_id: Some(acknowledges_operation_id),
            authority_contributions,
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

    /// Returns the exact provider-neutral authority contributions carried by this poll.
    #[must_use]
    pub const fn authority_contributions(&self) -> &LeaseAuthorityPollContributions {
        &self.authority_contributions
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

/// Successful result of one lease poll after its authority contributions are durable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LeasePollResponse {
    header: MessageHeader,
    accepted_contributions_sha256: Sha256Digest,
    outcome: LeasePollOutcome,
}

impl LeasePollResponse {
    /// Creates a correlated no-work response with a positive backoff.
    #[must_use]
    pub const fn no_work(
        header: MessageHeader,
        accepted_contributions_sha256: Sha256Digest,
        retry_after_millis: u32,
    ) -> Self {
        Self {
            header,
            accepted_contributions_sha256,
            outcome: LeasePollOutcome::NoWork { retry_after_millis },
        }
    }

    /// Creates a correlated response carrying one durable lease offer command.
    #[must_use]
    pub fn lease_offer(
        header: MessageHeader,
        accepted_contributions_sha256: Sha256Digest,
        offer: LeaseOffer,
    ) -> Self {
        Self {
            header,
            accepted_contributions_sha256,
            outcome: LeasePollOutcome::LeaseOffer(Box::new(offer)),
        }
    }

    /// Creates a correlated response carrying one durable cancellation command.
    #[must_use]
    pub const fn cancel_job(
        header: MessageHeader,
        accepted_contributions_sha256: Sha256Digest,
        cancel: CancelJob,
    ) -> Self {
        Self {
            header,
            accepted_contributions_sha256,
            outcome: LeasePollOutcome::CancelJob(cancel),
        }
    }

    /// Returns the response header correlated to the lease request.
    #[must_use]
    pub const fn header(&self) -> MessageHeader {
        self.header
    }

    /// Returns the exact contribution-bundle digest durably accepted by the server.
    #[must_use]
    pub const fn accepted_contributions_sha256(&self) -> Sha256Digest {
        self.accepted_contributions_sha256
    }

    /// Returns the poll result.
    #[must_use]
    pub const fn outcome(&self) -> &LeasePollOutcome {
        &self.outcome
    }

    /// Validates locally provable response invariants.
    ///
    /// # Errors
    ///
    /// Rejects an invalid reply header, zero backoff, or mismatched nested command session.
    pub fn validate(&self) -> Result<(), MessageValidationError> {
        self.header.validate_reply()?;
        match &self.outcome {
            LeasePollOutcome::NoWork { retry_after_millis } if *retry_after_millis == 0 => {
                Err(MessageValidationError::ZeroValue("retry_after_millis"))
            }
            LeasePollOutcome::NoWork { .. } => Ok(()),
            LeasePollOutcome::LeaseOffer(offer) => offer
                .header()
                .validate_for(self.header.protocol_version(), self.header.session_id()),
            LeasePollOutcome::CancelJob(cancel) => cancel
                .header()
                .validate_for(self.header.protocol_version(), self.header.session_id()),
        }
    }

    /// Validates correlation and exact contribution acceptance for one request.
    ///
    /// # Errors
    ///
    /// Rejects a response to another request, an unequal accepted digest, or
    /// any invalid nested outcome. A durable command may be replayed on a
    /// concurrent slot exchange, so the nested offer's stable slot is not
    /// required to match the poll carrier's slot.
    pub fn validate_for(&self, request: &LeaseRequest) -> Result<(), MessageValidationError> {
        self.validate()?;
        self.header.validate_reply_for(request.header())?;
        if self.accepted_contributions_sha256 != request.authority_contributions().sha256_digest() {
            return Err(MessageValidationError::LeaseAuthorityAcceptanceMismatch);
        }
        Ok(())
    }
}

/// Outcome nested inside one explicitly correlated lease-poll response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum LeasePollOutcome {
    /// No compatible work is available; wait at least this many milliseconds.
    NoWork {
        /// Server-selected positive retry delay.
        retry_after_millis: u32,
    },
    /// One durable job assignment command.
    LeaseOffer(Box<LeaseOffer>),
    /// One durable cancellation command.
    CancelJob(CancelJob),
}

/// Server offer containing an immutable job and its exclusive lease.
///
/// Runtime credentials are deliberately absent. Protocol v3 delivers them
/// only after the runner has durably accepted this exact offer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseOffer {
    header: ServerCommandHeader,
    slot: RunnerSlotOrdinal,
    lease: Lease,
    job: JobIrEnvelope,
    #[serde(deserialize_with = "deserialize_required_option")]
    managed_secret_bindings: Option<super::ManagedSecretBindingOverlay>,
}

fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(deserializer)
}

impl LeaseOffer {
    /// Creates a value-free offer.
    #[must_use]
    pub const fn new(
        header: ServerCommandHeader,
        slot: RunnerSlotOrdinal,
        lease: Lease,
        job: JobIrEnvelope,
    ) -> Self {
        Self {
            header,
            slot,
            lease,
            job,
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
