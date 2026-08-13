use automata_ci_core::{Lease, OperationId, Sha256Digest, UnixMillis};
use automata_ci_protocol::{
    CommandSequence, LeaseRejectionReason, ManagedSecretBindingOverlay, RunnerSlotOrdinal,
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
    runtime_authorities: RuntimeAuthorityContentRef,
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
        runtime_authorities: RuntimeAuthorityContentRef,
        command: DurableCommand,
    ) -> Result<Self, JournalInvariantError> {
        lease
            .validate()
            .map_err(|_| JournalInvariantError::InvalidLease)?;
        job_ir.validate()?;
        runtime_authorities.validate()?;
        Ok(Self {
            slot,
            lease,
            job_ir,
            runtime_authorities,
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

    /// Returns the protected per-attempt authority content identity.
    #[must_use]
    pub const fn runtime_authorities(&self) -> &RuntimeAuthorityContentRef {
        &self.runtime_authorities
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
        self.runtime_authorities.validate()?;
        if let Some(overlay) = &self.managed_secret_bindings {
            overlay
                .validate_for(&self.lease)
                .map_err(|_| JournalInvariantError::InvalidManagedSecretBindings)?;
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
