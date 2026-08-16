use automata_ci_core::{
    Lease, OperationId, RunnerId, RunnerSessionId, Sha256Digest, UnixMillis,
    WindowsHyperVBrokerGrant,
};
use automata_ci_protocol::{
    CommandSequence, LeaseRejectionReason, ManagedSecretBindingOverlay, RunnerSlotOrdinal,
    RuntimeAuthorityDeliveryBinding, RuntimeAuthorityGeneration, runtime_authority_delivery_digest,
};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{JobIrContentRef, JournalInvariantError, RuntimeAuthorityContentRef};

/// Stable identity of one replayable server command.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DurableCommand {
    sequence: CommandSequence,
    operation_id: OperationId,
    digest: Sha256Digest,
}

impl DurableCommand {
    /// Binds a contiguous command position to its idempotency identity and
    /// canonical semantic digest.
    #[must_use]
    pub const fn new(
        sequence: CommandSequence,
        operation_id: OperationId,
        digest: Sha256Digest,
    ) -> Self {
        Self {
            sequence,
            operation_id,
            digest,
        }
    }

    /// Returns the server-session sequence position.
    #[must_use]
    pub const fn sequence(self) -> CommandSequence {
        self.sequence
    }

    /// Returns the operation identity used for exact replay correlation.
    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    /// Returns the digest that detects a conflicting replay at this position.
    #[must_use]
    pub const fn digest(self) -> Sha256Digest {
        self.digest
    }
}

/// Why a durable server command intentionally produced no application effect.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandIgnoredReason {
    /// The command carried an attempt fence that is no longer current.
    StaleLease,
    /// The addressed stable slot does not currently admit the command.
    SlotUnavailable,
    /// This runner does not implement the command kind.
    UnsupportedCommand,
    /// The supported command failed bounded semantic validation.
    InvalidCommand,
}

/// Atomic local disposition recorded with a contiguous command-cursor advance.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "reason")]
pub enum CommandDisposition {
    /// The command's application effect and cursor advance were committed.
    Applied,
    /// The cursor advanced with a durable reason and no application effect.
    Ignored(CommandIgnoredReason),
}

/// Bounded exact-replay tombstone for a durable command.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandTombstone {
    command: DurableCommand,
    disposition: CommandDisposition,
}

impl CommandTombstone {
    pub(crate) const fn new(command: DurableCommand, disposition: CommandDisposition) -> Self {
        Self {
            command,
            disposition,
        }
    }

    /// Returns the exact command identity retained for bounded replay checks.
    #[must_use]
    pub const fn command(self) -> DurableCommand {
        self.command
    }

    /// Returns the immutable disposition committed for the command.
    #[must_use]
    pub const fn disposition(self) -> CommandDisposition {
        self.disposition
    }
}

/// Semantic lease-offer data written before the runner acknowledges or accepts
/// the server command. No transport envelope or inline job payload is persisted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseOfferRecord {
    slot: RunnerSlotOrdinal,
    lease: Lease,
    job_ir: JobIrContentRef,
    #[serde(deserialize_with = "deserialize_required_option")]
    managed_secret_bindings: Option<ManagedSecretBindingOverlay>,
    command: DurableCommand,
}

fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(deserializer)
}

impl LeaseOfferRecord {
    /// Builds a semantic offer only from a fully validated core lease.
    ///
    /// # Errors
    ///
    /// Rejects an unsupported lease schema or invalid issued/expires interval.
    pub fn new(
        slot: RunnerSlotOrdinal,
        lease: Lease,
        job_ir: JobIrContentRef,
        command: DurableCommand,
    ) -> Result<Self, JournalInvariantError> {
        lease
            .validate()
            .map_err(|_| JournalInvariantError::InvalidLease)?;
        job_ir.validate()?;
        Ok(Self {
            slot,
            lease,
            job_ir,
            managed_secret_bindings: None,
            command,
        })
    }

    /// Attaches value-free bindings for the exact offered lease.
    ///
    /// # Errors
    ///
    /// Rejects malformed content or any attempt, lease, or fence mismatch.
    pub fn with_managed_secret_bindings(
        mut self,
        overlay: ManagedSecretBindingOverlay,
    ) -> Result<Self, JournalInvariantError> {
        overlay
            .validate_for(&self.lease)
            .map_err(|_| JournalInvariantError::InvalidManagedSecretBindings)?;
        self.managed_secret_bindings = Some(overlay);
        Ok(self)
    }

    /// Returns the stable execution slot named by the offer.
    #[must_use]
    pub const fn slot(&self) -> RunnerSlotOrdinal {
        self.slot
    }

    /// Returns the validated semantic lease.
    #[must_use]
    pub const fn lease(&self) -> &Lease {
        &self.lease
    }

    /// Returns the original durable lease expiration.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.lease.expires_at()
    }

    /// Returns the version-bound immutable `JobIR` content identity.
    #[must_use]
    pub const fn job_ir(&self) -> &JobIrContentRef {
        &self.job_ir
    }

    /// Returns the lease-scoped value-free bindings, when carried by the offer.
    #[must_use]
    pub const fn managed_secret_bindings(&self) -> Option<&ManagedSecretBindingOverlay> {
        self.managed_secret_bindings.as_ref()
    }

    /// Returns the command whose cursor advancement is atomic with the offer.
    #[must_use]
    pub const fn command(&self) -> DurableCommand {
        self.command
    }

    pub(crate) fn validate(&self) -> Result<(), JournalInvariantError> {
        self.lease
            .validate()
            .map_err(|_| JournalInvariantError::InvalidLease)?;
        self.job_ir.validate()?;
        if let Some(overlay) = &self.managed_secret_bindings {
            overlay
                .validate_for(&self.lease)
                .map_err(|_| JournalInvariantError::InvalidManagedSecretBindings)?;
        }
        Ok(())
    }
}

pub(super) fn validate_windows_hyperv_broker_grant(
    grant: &WindowsHyperVBrokerGrant,
    runner_id: RunnerId,
    session_id: RunnerSessionId,
    delivery_request_operation_id: OperationId,
    binding: RuntimeAuthorityDeliveryBinding,
    lease: &Lease,
    job_ir: &JobIrContentRef,
) -> Result<(), JournalInvariantError> {
    grant
        .claims()
        .validate()
        .map_err(|_| JournalInvariantError::InvalidWindowsHyperVBrokerGrant)?;
    let claims = grant.claims();
    let correlated = claims.runner_id() == runner_id
        && claims.runner_id() == lease.runner_id()
        && claims.runner_session_id() == session_id
        && claims.slot() == binding.slot().get()
        && claims.attempt_id() == binding.attempt_id()
        && claims.attempt_id() == lease.attempt_id()
        && claims.lease_id() == lease.lease_id()
        && claims.fencing_token() == lease.fencing_token()
        && claims.accepted_offer_operation_id() == binding.offer_operation_id()
        && claims.accepted_offer_sequence() == binding.offer_sequence().get()
        && claims.post_accept_operation_id() == delivery_request_operation_id
        && claims.job_ir_version() == job_ir.version()
        && job_ir.content().public_plaintext_bytes() == Some(claims.job_ir_encoded_size())
        && job_ir.content().public_plaintext_sha256() == Some(claims.job_ir_digest())
        && claims.issued_at() == lease.issued_at()
        && claims.expires_at() == lease.expires_at();
    correlated
        .then_some(())
        .ok_or(JournalInvariantError::InvalidWindowsHyperVBrokerGrant)
}

/// Crash-durable adoption state for one post-accept authority grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAuthorityDeliveryRecord {
    binding: RuntimeAuthorityDeliveryBinding,
    request_operation_id: OperationId,
    acknowledgement_operation_id: OperationId,
    bundle_digest: Sha256Digest,
    content: RuntimeAuthorityContentRef,
    #[serde(deserialize_with = "deserialize_required_option")]
    windows_hyperv_broker_grant: Option<WindowsHyperVBrokerGrant>,
    acknowledged: bool,
}

impl RuntimeAuthorityDeliveryRecord {
    /// Creates an unacknowledged delivery from already protected and durable bytes.
    ///
    /// # Errors
    ///
    /// Rejects invalid protected content or a digest that differs from its
    /// plaintext spool identity.
    pub fn new(
        binding: RuntimeAuthorityDeliveryBinding,
        request_operation_id: OperationId,
        acknowledgement_operation_id: OperationId,
        bundle_digest: Sha256Digest,
        content: RuntimeAuthorityContentRef,
        windows_hyperv_broker_grant: Option<WindowsHyperVBrokerGrant>,
    ) -> Result<Self, JournalInvariantError> {
        let record = Self {
            binding,
            request_operation_id,
            acknowledgement_operation_id,
            bundle_digest,
            content,
            windows_hyperv_broker_grant,
            acknowledged: false,
        };
        record.validate()?;
        Ok(record)
    }

    /// Returns the exact offer and delivery-generation binding.
    #[must_use]
    pub const fn binding(&self) -> RuntimeAuthorityDeliveryBinding {
        self.binding
    }

    /// Returns the stable authority-request operation identity.
    #[must_use]
    pub const fn request_operation_id(&self) -> OperationId {
        self.request_operation_id
    }

    /// Returns the stable grant-acknowledgement operation identity.
    #[must_use]
    pub const fn acknowledgement_operation_id(&self) -> OperationId {
        self.acknowledgement_operation_id
    }

    /// Returns the canonical plaintext bundle digest.
    #[must_use]
    pub const fn bundle_digest(&self) -> Sha256Digest {
        self.bundle_digest
    }

    /// Returns the protected spool content identity.
    #[must_use]
    pub const fn content(&self) -> &RuntimeAuthorityContentRef {
        &self.content
    }

    /// Returns the post-accept one-use Windows broker capability, when present.
    #[must_use]
    pub const fn windows_hyperv_broker_grant(&self) -> Option<&WindowsHyperVBrokerGrant> {
        self.windows_hyperv_broker_grant.as_ref()
    }

    /// Reports whether the control plane acknowledged protected adoption.
    #[must_use]
    pub const fn is_acknowledged(&self) -> bool {
        self.acknowledged
    }

    pub(crate) fn acknowledge(
        &mut self,
        generation: RuntimeAuthorityGeneration,
        bundle_digest: Sha256Digest,
        operation_id: OperationId,
    ) -> Result<bool, JournalInvariantError> {
        if self.binding.generation() != generation
            || self.bundle_digest != bundle_digest
            || self.acknowledgement_operation_id != operation_id
        {
            return Err(JournalInvariantError::RuntimeAuthorityDeliveryReplayConflict);
        }
        if self.acknowledged {
            return Ok(false);
        }
        self.acknowledged = true;
        Ok(true)
    }

    pub(crate) fn validate(&self) -> Result<(), JournalInvariantError> {
        self.content.validate()?;
        let authorities_sha256 = self
            .content
            .content()
            .public_plaintext_sha256()
            .ok_or(JournalInvariantError::InvalidRuntimeAuthorityDelivery)?;
        if self.binding.generation().get() == 0
            || runtime_authority_delivery_digest(
                authorities_sha256,
                self.windows_hyperv_broker_grant.as_ref(),
            ) != self.bundle_digest
        {
            return Err(JournalInvariantError::InvalidRuntimeAuthorityDelivery);
        }
        Ok(())
    }
}

/// Durable rejected-offer response retained until the control plane confirms
/// that the exact response operation was accepted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRejectionRecord {
    reason: LeaseRejectionReason,
    response_operation_id: OperationId,
    response_acknowledged: bool,
}

impl LeaseRejectionRecord {
    /// Creates a pending exact-response record.
    #[must_use]
    pub const fn new(reason: LeaseRejectionReason, response_operation_id: OperationId) -> Self {
        Self {
            reason,
            response_operation_id,
            response_acknowledged: false,
        }
    }

    /// Returns the bounded rejection reason sent to the control plane.
    #[must_use]
    pub const fn reason(&self) -> &LeaseRejectionReason {
        &self.reason
    }

    /// Returns the idempotency identity of the exact rejection response.
    #[must_use]
    pub const fn response_operation_id(&self) -> OperationId {
        self.response_operation_id
    }

    /// Reports whether the control plane durably accepted that response.
    #[must_use]
    pub const fn is_response_acknowledged(&self) -> bool {
        self.response_acknowledged
    }

    pub(crate) fn acknowledge_response(&mut self) {
        self.response_acknowledged = true;
    }
}

/// Durable cancellation command correlated to the current lease guard.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CancellationRecord {
    command: DurableCommand,
    requested_at: UnixMillis,
}

impl CancellationRecord {
    /// Binds a cancellation command to its server-supplied request time.
    #[must_use]
    pub const fn new(command: DurableCommand, requested_at: UnixMillis) -> Self {
        Self {
            command,
            requested_at,
        }
    }

    /// Returns the exact cancellation command identity.
    #[must_use]
    pub const fn command(self) -> DurableCommand {
        self.command
    }

    /// Returns the cancellation request time retained for recovery.
    #[must_use]
    pub const fn requested_at(self) -> UnixMillis {
        self.requested_at
    }
}
