use automata_core::{Lease, OperationId, Sha256Digest, UnixMillis};
use automata_protocol::{CommandSequence, LeaseRejectionReason, RunnerSlotOrdinal};
use serde::{Deserialize, Serialize};

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

    #[must_use]
    pub const fn sequence(self) -> CommandSequence {
        self.sequence
    }

    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn digest(self) -> Sha256Digest {
        self.digest
    }
}

/// Why a durable server command intentionally produced no application effect.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandIgnoredReason {
    StaleLease,
    SlotUnavailable,
    UnsupportedCommand,
    InvalidCommand,
}

/// Atomic local disposition recorded with a contiguous command-cursor advance.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "reason")]
pub enum CommandDisposition {
    Applied,
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

    #[must_use]
    pub const fn command(self) -> DurableCommand {
        self.command
    }

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
    command: DurableCommand,
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
            command,
        })
    }

    #[must_use]
    pub const fn slot(&self) -> RunnerSlotOrdinal {
        self.slot
    }

    #[must_use]
    pub const fn lease(&self) -> &Lease {
        &self.lease
    }

    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.lease.expires_at()
    }

    #[must_use]
    pub const fn job_ir(&self) -> &JobIrContentRef {
        &self.job_ir
    }

    /// Returns the protected per-attempt authority content identity.
    #[must_use]
    pub const fn runtime_authorities(&self) -> &RuntimeAuthorityContentRef {
        &self.runtime_authorities
    }

    #[must_use]
    pub const fn command(&self) -> DurableCommand {
        self.command
    }

    pub(crate) fn validate(&self) -> Result<(), JournalInvariantError> {
        self.lease
            .validate()
            .map_err(|_| JournalInvariantError::InvalidLease)?;
        self.job_ir.validate()?;
        self.runtime_authorities.validate()
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
    #[must_use]
    pub const fn new(reason: LeaseRejectionReason, response_operation_id: OperationId) -> Self {
        Self {
            reason,
            response_operation_id,
            response_acknowledged: false,
        }
    }

    #[must_use]
    pub const fn reason(&self) -> &LeaseRejectionReason {
        &self.reason
    }

    #[must_use]
    pub const fn response_operation_id(&self) -> OperationId {
        self.response_operation_id
    }

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
    #[must_use]
    pub const fn new(command: DurableCommand, requested_at: UnixMillis) -> Self {
        Self {
            command,
            requested_at,
        }
    }

    #[must_use]
    pub const fn command(self) -> DurableCommand {
        self.command
    }

    #[must_use]
    pub const fn requested_at(self) -> UnixMillis {
        self.requested_at
    }
}
