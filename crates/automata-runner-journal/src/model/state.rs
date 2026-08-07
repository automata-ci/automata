use std::collections::HashSet;

use automata_core::{
    JobIrVersion, JobIrVersionRange, JobLifecycle, LeaseGuard, LogSequence, LogStreamId,
    OperationId, RunnerId, RunnerSessionId, UnixMillis,
};
use automata_protocol::{
    CommandCursor, CommandSequence, LeaseRejectionReason, ProtocolVersion, RunnerSlotOrdinal,
    SUPPORTED_PROTOCOL_RANGE,
};
use automata_runner_spool::DurableContentRef;
use serde::{Deserialize, Serialize};

use super::{
    CancellationRecord, CommandDisposition, CommandTombstone, DiskSchemaVersion, DurableCommand,
    LeaseOfferRecord, LeaseRejectionRecord, LogDeliveryCursor, LogProductionRecord,
    OrphanAbandonmentReason, OrphanAuthorityGrant, OrphanDelivery, OrphanRecord,
    OutboundOperationCursor, OutboundOperationSequence, ProviderFailureOutcome, ProviderOperation,
    ProviderOperationKind, ProviderOperationOutcome, SandboxIdentity, TerminalResultRecord,
};
use crate::{
    JournalInvariantError, MAX_COMMAND_TOMBSTONES, MAX_JOURNALED_SLOTS,
    MAX_PROVIDER_OPERATIONS_PER_SLOT, RUNNER_JOURNAL_SCHEMA_VERSION,
};

/// Whether a durably recorded offer is awaiting or has received local
/// acceptance. The server command itself is durable in both states.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseOfferStatus {
    Recorded,
    Accepted,
    Rejected,
}

/// Exact protocol and `JobIR` versions selected for a runner session.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionBinding {
    session_id: RunnerSessionId,
    selected_protocol: ProtocolVersion,
    selected_job_ir: JobIrVersion,
}

impl SessionBinding {
    #[must_use]
    pub const fn new(
        session_id: RunnerSessionId,
        selected_protocol: ProtocolVersion,
        selected_job_ir: JobIrVersion,
    ) -> Self {
        Self {
            session_id,
            selected_protocol,
            selected_job_ir,
        }
    }

    #[must_use]
    pub const fn session_id(self) -> RunnerSessionId {
        self.session_id
    }

    #[must_use]
    pub const fn selected_protocol(self) -> ProtocolVersion {
        self.selected_protocol
    }

    #[must_use]
    pub const fn selected_job_ir(self) -> JobIrVersion {
        self.selected_job_ir
    }
}

/// Resumable negotiated session, command cursor, and bounded replay evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionSnapshot {
    session_id: RunnerSessionId,
    selected_protocol: ProtocolVersion,
    selected_job_ir: JobIrVersion,
    command_cursor: CommandCursor,
    command_tombstones: Vec<CommandTombstone>,
    lease_poll_requires_fresh_session: bool,
    lease_poll_checkpoints: Vec<LeasePollCheckpoint>,
}

impl SessionSnapshot {
    #[must_use]
    pub const fn new(binding: SessionBinding) -> Self {
        Self {
            session_id: binding.session_id(),
            selected_protocol: binding.selected_protocol(),
            selected_job_ir: binding.selected_job_ir(),
            command_cursor: CommandCursor::initial(),
            command_tombstones: Vec::new(),
            lease_poll_requires_fresh_session: false,
            lease_poll_checkpoints: Vec::new(),
        }
    }

    pub(crate) fn migrated_v3(
        binding: SessionBinding,
        command_cursor: CommandCursor,
        command_tombstones: Vec<CommandTombstone>,
    ) -> Self {
        Self {
            session_id: binding.session_id(),
            selected_protocol: binding.selected_protocol(),
            selected_job_ir: binding.selected_job_ir(),
            command_cursor,
            command_tombstones,
            lease_poll_requires_fresh_session: true,
            lease_poll_checkpoints: Vec::new(),
        }
    }

    #[must_use]
    pub const fn session_id(&self) -> RunnerSessionId {
        self.session_id
    }

    #[must_use]
    pub const fn selected_protocol(&self) -> ProtocolVersion {
        self.selected_protocol
    }

    #[must_use]
    pub const fn selected_job_ir(&self) -> JobIrVersion {
        self.selected_job_ir
    }

    #[must_use]
    pub const fn command_cursor(&self) -> CommandCursor {
        self.command_cursor
    }

    #[must_use]
    pub fn command_tombstones(&self) -> &[CommandTombstone] {
        &self.command_tombstones
    }

    /// Returns the durable, sorted per-slot lease-poll checkpoints.
    #[must_use]
    pub fn lease_poll_checkpoints(&self) -> &[LeasePollCheckpoint] {
        &self.lease_poll_checkpoints
    }

    /// Returns the durable lease-poll checkpoint for `slot`, when prepared.
    #[must_use]
    pub fn lease_poll_checkpoint(&self, slot: RunnerSlotOrdinal) -> Option<&LeasePollCheckpoint> {
        self.lease_poll_checkpoints
            .binary_search_by_key(&slot, LeasePollCheckpoint::slot)
            .ok()
            .map(|index| &self.lease_poll_checkpoints[index])
    }

    /// Whether a schema-v3 session must be replaced before any protocol-v4
    /// lease poll can be constructed.
    ///
    /// This is only a legacy migration fence. New schema-v4 sessions never
    /// enter this state. Active legacy slots remain recoverable until the
    /// server's existing orphan authority permits their reconciliation.
    #[must_use]
    pub const fn lease_poll_requires_fresh_session(&self) -> bool {
        self.lease_poll_requires_fresh_session
    }

    const fn binding(&self) -> SessionBinding {
        SessionBinding::new(
            self.session_id,
            self.selected_protocol,
            self.selected_job_ir,
        )
    }
}

/// Crash-durable identity of the exact lease request currently owned by one
/// stable runner slot.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LeasePollCheckpoint {
    slot: RunnerSlotOrdinal,
    current_operation_id: OperationId,
    acknowledges_operation_id: Option<OperationId>,
}

impl LeasePollCheckpoint {
    const fn first(slot: RunnerSlotOrdinal, current_operation_id: OperationId) -> Self {
        Self {
            slot,
            current_operation_id,
            acknowledges_operation_id: None,
        }
    }

    #[must_use]
    pub const fn slot(&self) -> RunnerSlotOrdinal {
        self.slot
    }

    #[must_use]
    pub const fn current_operation_id(self) -> OperationId {
        self.current_operation_id
    }

    #[must_use]
    pub const fn acknowledges_operation_id(self) -> Option<OperationId> {
        self.acknowledges_operation_id
    }
}

/// Complete recovery state for one stable, one-based execution slot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SlotSnapshot {
    offer: LeaseOfferRecord,
    offer_status: LeaseOfferStatus,
    rejection: Option<LeaseRejectionRecord>,
    expires_at: UnixMillis,
    lifecycle: JobLifecycle,
    cancellation: Option<CancellationRecord>,
    terminal_result: Option<TerminalResultRecord>,
    provider_checkpoint: ProviderRecoveryState,
    provider_operations: Vec<ProviderOperation>,
    sandbox: Option<SandboxIdentity>,
    outbound_operations: OutboundOperationCursor,
    log_delivery: Option<LogDeliveryCursor>,
    orphan: Option<OrphanRecord>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderRecoveryState {
    compacted_operations: u64,
    sandbox_was_created: bool,
    sandbox_live: bool,
    running: bool,
}

impl ProviderRecoveryState {
    const fn can_begin(self, kind: ProviderOperationKind) -> bool {
        match kind {
            ProviderOperationKind::CreateSandbox => !self.sandbox_was_created && !self.sandbox_live,
            ProviderOperationKind::StartSandbox => self.sandbox_live && !self.running,
            ProviderOperationKind::StopSandbox => self.sandbox_live && self.running,
            ProviderOperationKind::DestroySandbox => self.sandbox_live,
        }
    }

    fn apply(&mut self, operation: ProviderOperation) -> Result<(), JournalInvariantError> {
        if !self.can_begin(operation.kind()) {
            return Err(JournalInvariantError::DecodedStateInvalid);
        }
        if operation.outcome() != ProviderOperationOutcome::Applied {
            return Ok(());
        }
        match operation.kind() {
            ProviderOperationKind::CreateSandbox => {
                self.sandbox_was_created = true;
                self.sandbox_live = true;
            }
            ProviderOperationKind::StartSandbox => self.running = true,
            ProviderOperationKind::StopSandbox => self.running = false,
            ProviderOperationKind::DestroySandbox => {
                self.sandbox_live = false;
                self.running = false;
            }
        }
        Ok(())
    }

    fn compact(&mut self, operation: ProviderOperation) -> Result<(), JournalInvariantError> {
        if operation.is_pending() {
            return Err(JournalInvariantError::ProviderOperationPending);
        }
        self.apply(operation)?;
        self.compacted_operations = self
            .compacted_operations
            .checked_add(1)
            .ok_or(JournalInvariantError::CounterExhausted)?;
        Ok(())
    }

    const fn is_coherent(self) -> bool {
        if self.compacted_operations == 0 {
            !self.sandbox_was_created && !self.sandbox_live && !self.running
        } else {
            (!self.running || self.sandbox_live) && (!self.sandbox_live || self.sandbox_was_created)
        }
    }
}

impl SlotSnapshot {
    fn from_offer(offer: LeaseOfferRecord) -> Self {
        Self {
            expires_at: offer.expires_at(),
            offer,
            offer_status: LeaseOfferStatus::Recorded,
            rejection: None,
            lifecycle: JobLifecycle::Leased,
            cancellation: None,
            terminal_result: None,
            provider_checkpoint: ProviderRecoveryState::default(),
            provider_operations: Vec::new(),
            sandbox: None,
            outbound_operations: OutboundOperationCursor::initial(),
            log_delivery: None,
            orphan: None,
        }
    }

    #[must_use]
    pub const fn slot(&self) -> RunnerSlotOrdinal {
        self.offer.slot()
    }

    #[must_use]
    pub const fn offer(&self) -> &LeaseOfferRecord {
        &self.offer
    }

    #[must_use]
    pub const fn offer_status(&self) -> LeaseOfferStatus {
        self.offer_status
    }

    #[must_use]
    pub const fn rejection(&self) -> Option<&LeaseRejectionRecord> {
        self.rejection.as_ref()
    }

    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }

    #[must_use]
    pub const fn lifecycle(&self) -> JobLifecycle {
        self.lifecycle
    }

    #[must_use]
    pub const fn cancellation(&self) -> Option<CancellationRecord> {
        self.cancellation
    }

    #[must_use]
    pub const fn terminal_result(&self) -> Option<&TerminalResultRecord> {
        self.terminal_result.as_ref()
    }

    #[must_use]
    pub const fn compacted_provider_operations(&self) -> u64 {
        self.provider_checkpoint.compacted_operations
    }

    #[must_use]
    pub fn provider_operations(&self) -> &[ProviderOperation] {
        &self.provider_operations
    }

    #[must_use]
    pub const fn sandbox(&self) -> Option<&SandboxIdentity> {
        self.sandbox.as_ref()
    }

    #[must_use]
    pub const fn outbound_operations(&self) -> OutboundOperationCursor {
        self.outbound_operations
    }

    #[must_use]
    pub const fn log_delivery(&self) -> Option<&LogDeliveryCursor> {
        self.log_delivery.as_ref()
    }

    #[must_use]
    pub const fn orphan(&self) -> Option<OrphanRecord> {
        self.orphan
    }

    fn guard(&self) -> LeaseGuard {
        self.offer.lease().guard()
    }

    fn require_guard(&self, received: LeaseGuard) -> Result<(), JournalInvariantError> {
        let expected = self.guard();
        if expected == received {
            Ok(())
        } else {
            Err(JournalInvariantError::LeaseGuardMismatch { expected, received })
        }
    }

    fn validate(
        &self,
        runner_id: RunnerId,
        session: &SessionSnapshot,
    ) -> Result<(), JournalInvariantError> {
        self.offer.validate()?;
        if self.offer.lease().runner_id() != runner_id {
            return Err(JournalInvariantError::LeaseRunnerMismatch);
        }
        if self.offer.job_ir().version() != session.selected_job_ir() {
            return Err(JournalInvariantError::JobIrVersionMismatch);
        }
        if self.expires_at < self.offer.expires_at() {
            return Err(JournalInvariantError::DecodedStateInvalid);
        }
        if self.provider_operations.len() > MAX_PROVIDER_OPERATIONS_PER_SLOT {
            return Err(JournalInvariantError::DecodedCollectionLimit);
        }
        self.validate_provider_state()?;
        let rejection_consistent = matches!(
            (self.offer_status, self.rejection.as_ref()),
            (
                LeaseOfferStatus::Recorded | LeaseOfferStatus::Accepted,
                None
            ) | (LeaseOfferStatus::Rejected, Some(_))
        );
        if !rejection_consistent {
            return Err(JournalInvariantError::DecodedStateInvalid);
        }
        if self.orphan.is_none()
            && self.offer_status == LeaseOfferStatus::Recorded
            && !matches!(
                self.lifecycle,
                JobLifecycle::Leased | JobLifecycle::Cancelling
            )
        {
            return Err(JournalInvariantError::DecodedStateInvalid);
        }
        if self.orphan.is_none()
            && self.offer_status == LeaseOfferStatus::Rejected
            && !matches!(
                self.lifecycle,
                JobLifecycle::Leased | JobLifecycle::Cancelling
            )
        {
            return Err(JournalInvariantError::DecodedStateInvalid);
        }
        if self.offer_status == LeaseOfferStatus::Rejected && self.log_delivery.is_some() {
            return Err(JournalInvariantError::DecodedStateInvalid);
        }
        if let Some(result) = &self.terminal_result {
            result.validate()?;
            if self.offer_status != LeaseOfferStatus::Accepted || !self.lifecycle.is_terminal() {
                return Err(JournalInvariantError::DecodedStateInvalid);
            }
        }
        if self.offer_status == LeaseOfferStatus::Accepted
            && self.lifecycle.is_terminal()
            && self.terminal_result.is_none()
            && self.orphan.is_none()
        {
            return Err(JournalInvariantError::DecodedStateInvalid);
        }
        if let Some(orphan) = self.orphan
            && (orphan.session_id() != session.session_id()
                || orphan.guard() != self.guard()
                || !self.lifecycle.is_terminal()
                || (orphan.is_abandoned(OrphanDelivery::TerminalResult)
                    && self.terminal_result.is_none())
                || (orphan.is_abandoned(OrphanDelivery::LogStream) && self.log_delivery.is_none())
                || (orphan.is_abandoned(OrphanDelivery::LeaseRejection)
                    && self.rejection.is_none()))
        {
            return Err(JournalInvariantError::DecodedStateInvalid);
        }
        if let Some(cancellation) = self.cancellation
            && cancellation.command().sequence() <= self.offer.command().sequence()
        {
            return Err(JournalInvariantError::DecodedStateInvalid);
        }
        if self.cancellation.is_some()
            && matches!(
                self.lifecycle,
                JobLifecycle::Queued
                    | JobLifecycle::Leased
                    | JobLifecycle::Preparing
                    | JobLifecycle::Running
                    | JobLifecycle::Skipped
            )
        {
            return Err(JournalInvariantError::DecodedStateInvalid);
        }
        self.validate_log_state()?;
        Ok(())
    }

    fn validate_log_state(&self) -> Result<(), JournalInvariantError> {
        let Some(log) = &self.log_delivery else {
            return Ok(());
        };
        let cursor_invalid = log.acknowledged_through().is_some()
            && log.produced_through().is_none()
            || log
                .acknowledged_through()
                .zip(log.produced_through())
                .is_some_and(|(ack, produced)| ack > produced)
            || log
                .end_of_stream()
                .is_some_and(|end| log.produced_through() != Some(end));
        if cursor_invalid {
            return Err(JournalInvariantError::DecodedStateInvalid);
        }
        log.validate()?;
        if log.produced_through().is_some() && log.spool_content().size() == 0 {
            return Err(JournalInvariantError::DecodedStateInvalid);
        }
        Ok(())
    }

    fn validate_provider_state(&self) -> Result<(), JournalInvariantError> {
        if !self.provider_operations.is_empty() && self.offer_status != LeaseOfferStatus::Accepted {
            return Err(JournalInvariantError::DecodedStateInvalid);
        }
        if !self.provider_checkpoint.is_coherent() {
            return Err(JournalInvariantError::DecodedStateInvalid);
        }
        let recovery =
            replay_provider_operations(self.provider_checkpoint, &self.provider_operations)?;
        if self.sandbox.is_some() != recovery.sandbox_live {
            return Err(JournalInvariantError::DecodedStateInvalid);
        }
        Ok(())
    }
}

fn replay_provider_operations(
    checkpoint: ProviderRecoveryState,
    provider_operations: &[ProviderOperation],
) -> Result<ProviderRecoveryState, JournalInvariantError> {
    let mut operation_ids = HashSet::with_capacity(provider_operations.len());
    let mut recovery = checkpoint;
    for (index, operation) in provider_operations.iter().copied().enumerate() {
        if !operation_ids.insert(operation.operation_id())
            || (operation.is_pending() && index + 1 != provider_operations.len())
        {
            return Err(JournalInvariantError::DecodedStateInvalid);
        }
        recovery.apply(operation)?;
    }
    Ok(recovery)
}

fn validate_session(session: &SessionSnapshot) -> Result<(), JournalInvariantError> {
    let protocol_valid = if session.lease_poll_requires_fresh_session {
        session.selected_protocol().get() > 0
            && session.selected_protocol() < SUPPORTED_PROTOCOL_RANGE.min()
            && session.lease_poll_checkpoints.is_empty()
    } else {
        SUPPORTED_PROTOCOL_RANGE.contains(session.selected_protocol())
    };
    if !protocol_valid
        || !JobIrVersionRange::current().supports(session.selected_job_ir())
        || session.command_tombstones.len() > MAX_COMMAND_TOMBSTONES
        || session.lease_poll_checkpoints.len() > MAX_JOURNALED_SLOTS
    {
        return Err(JournalInvariantError::DecodedStateInvalid);
    }
    let mut previous = None;
    let mut operations = HashSet::with_capacity(session.command_tombstones.len());
    for tombstone in &session.command_tombstones {
        let command = tombstone.command();
        if previous.is_some_and(|sequence| sequence >= command.sequence())
            || !operations.insert(command.operation_id())
        {
            return Err(JournalInvariantError::DecodedStateInvalid);
        }
        previous = Some(command.sequence());
    }
    match (
        session.command_cursor.acknowledged_through(),
        session.command_tombstones.last(),
    ) {
        (None, None) => {}
        (Some(cursor), Some(last)) if last.command().sequence() == cursor => {}
        _ => return Err(JournalInvariantError::DecodedStateInvalid),
    }
    let mut previous_slot = None;
    let mut poll_operations = HashSet::with_capacity(session.lease_poll_checkpoints.len() * 2);
    for checkpoint in &session.lease_poll_checkpoints {
        if usize::from(checkpoint.slot().get()) > MAX_JOURNALED_SLOTS
            || previous_slot.is_some_and(|slot| slot >= checkpoint.slot())
            || !poll_operations.insert(checkpoint.current_operation_id())
            || checkpoint
                .acknowledges_operation_id()
                .is_some_and(|operation_id| !poll_operations.insert(operation_id))
        {
            return Err(JournalInvariantError::DecodedStateInvalid);
        }
        previous_slot = Some(checkpoint.slot());
    }
    Ok(())
}

fn command_has_applied_tombstone_or_is_older(
    session: &SessionSnapshot,
    command: DurableCommand,
) -> bool {
    let Some(first) = session.command_tombstones.first() else {
        return false;
    };
    if command.sequence() < first.command().sequence() {
        return true;
    }
    session.command_tombstones.iter().any(|tombstone| {
        tombstone.command() == command && tombstone.disposition() == CommandDisposition::Applied
    })
}

/// Read-only point-in-time view returned by every journal adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalSnapshot {
    revision: u64,
    runner_id: RunnerId,
    session: Option<SessionSnapshot>,
    slots: Vec<SlotSnapshot>,
}

impl JournalSnapshot {
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn runner_id(&self) -> RunnerId {
        self.runner_id
    }

    #[must_use]
    pub const fn session(&self) -> Option<&SessionSnapshot> {
        self.session.as_ref()
    }

    #[must_use]
    pub fn slots(&self) -> &[SlotSnapshot] {
        &self.slots
    }

    #[must_use]
    pub fn slot(&self, ordinal: RunnerSlotOrdinal) -> Option<&SlotSnapshot> {
        self.slots
            .binary_search_by_key(&ordinal, SlotSnapshot::slot)
            .ok()
            .map(|index| &self.slots[index])
    }

    /// Iterates the complete protected-content retain set for this snapshot.
    ///
    /// [`crate::JournalContentRetainSet`] captures this iterator only after the
    /// spool has fenced all payload-first publications, closing the snapshot /
    /// publication reconciliation race.
    pub fn content_references(&self) -> impl Iterator<Item = &DurableContentRef> {
        self.slots.iter().flat_map(|slot| {
            [
                Some(slot.offer.job_ir().content()),
                Some(slot.offer.runtime_authorities().content()),
                slot.terminal_result
                    .as_ref()
                    .map(TerminalResultRecord::content),
                slot.log_delivery
                    .as_ref()
                    .map(LogDeliveryCursor::spool_content),
            ]
            .into_iter()
            .flatten()
        })
    }
}

/// Strict, versioned disk representation. It remains private to prevent the
/// persistence schema from becoming an application construction API.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredJournal {
    schema_version: DiskSchemaVersion,
    revision: u64,
    runner_id: RunnerId,
    session: Option<SessionSnapshot>,
    slots: Vec<SlotSnapshot>,
}

impl StoredJournal {
    pub(crate) const fn new(runner_id: RunnerId) -> Self {
        Self {
            schema_version: DiskSchemaVersion::CURRENT,
            revision: 0,
            runner_id,
            session: None,
            slots: Vec::new(),
        }
    }

    pub(crate) fn migrated_v3(
        revision: u64,
        runner_id: RunnerId,
        session: Option<SessionSnapshot>,
        slots: Vec<SlotSnapshot>,
    ) -> Result<Self, JournalInvariantError> {
        let mut migrated = Self {
            schema_version: DiskSchemaVersion::CURRENT,
            revision,
            runner_id,
            session,
            slots,
        };
        migrated.increment_revision()?;
        migrated.validate()?;
        Ok(migrated)
    }

    pub(crate) fn snapshot(&self) -> JournalSnapshot {
        JournalSnapshot {
            revision: self.revision,
            runner_id: self.runner_id,
            session: self.session.clone(),
            slots: self.slots.clone(),
        }
    }

    pub(crate) const fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) fn increment_revision(&mut self) -> Result<(), JournalInvariantError> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(JournalInvariantError::CounterExhausted)?;
        Ok(())
    }

    pub(crate) fn validate(&self) -> Result<(), JournalInvariantError> {
        if self.schema_version.get() != RUNNER_JOURNAL_SCHEMA_VERSION {
            return Err(JournalInvariantError::DecodedStateInvalid);
        }
        if self.slots.len() > MAX_JOURNALED_SLOTS {
            return Err(JournalInvariantError::DecodedCollectionLimit);
        }
        if !self.slots.is_empty() && self.session.is_none() {
            return Err(JournalInvariantError::DecodedStateInvalid);
        }
        if self.session.is_some() && self.revision == 0 {
            return Err(JournalInvariantError::DecodedStateInvalid);
        }
        let session = self.session.as_ref();
        if let Some(session) = session {
            validate_session(session)?;
        }
        let mut previous = None;
        let mut command_sequences = HashSet::new();
        let mut command_operations = HashSet::new();
        for slot in &self.slots {
            if usize::from(slot.slot().get()) > MAX_JOURNALED_SLOTS
                || previous.is_some_and(|ordinal| ordinal >= slot.slot())
            {
                return Err(JournalInvariantError::DecodedStateInvalid);
            }
            previous = Some(slot.slot());
            let session = session.ok_or(JournalInvariantError::DecodedStateInvalid)?;
            slot.validate(self.runner_id, session)?;
            if !command_sequences.insert(slot.offer.command().sequence())
                || !command_operations.insert(slot.offer.command().operation_id())
                || !command_has_applied_tombstone_or_is_older(session, slot.offer.command())
            {
                return Err(JournalInvariantError::DecodedStateInvalid);
            }
            if let Some(cancellation) = slot.cancellation()
                && (!command_sequences.insert(cancellation.command().sequence())
                    || !command_operations.insert(cancellation.command().operation_id())
                    || !command_has_applied_tombstone_or_is_older(session, cancellation.command()))
            {
                return Err(JournalInvariantError::DecodedStateInvalid);
            }
            let cursor = session.command_cursor().acknowledged_through();
            if cursor.is_none_or(|cursor| slot.offer.command().sequence() > cursor)
                || slot.cancellation().is_some_and(|cancellation| {
                    cursor.is_none_or(|cursor| cancellation.command().sequence() > cursor)
                })
            {
                return Err(JournalInvariantError::DecodedStateInvalid);
            }
        }
        Ok(())
    }

    pub(crate) const fn runner_id(&self) -> RunnerId {
        self.runner_id
    }

    pub(crate) fn begin_session(
        &mut self,
        binding: SessionBinding,
    ) -> Result<bool, JournalInvariantError> {
        match &self.session {
            Some(current) if current.binding() == binding => Ok(false),
            Some(current) if current.session_id() == binding.session_id() => {
                Err(JournalInvariantError::SessionNegotiationMismatch)
            }
            Some(_) if !self.slots.is_empty() => Err(JournalInvariantError::SessionHasActiveSlots),
            None | Some(_) => {
                self.session = Some(SessionSnapshot::new(binding));
                Ok(true)
            }
        }
    }

    pub(crate) fn prepare_lease_poll(
        &mut self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        operation_id: OperationId,
    ) -> Result<bool, JournalInvariantError> {
        self.require_session(session_id)?;
        let session = self
            .session
            .as_mut()
            .ok_or(JournalInvariantError::NoSession)?;
        if session.lease_poll_requires_fresh_session {
            return Err(JournalInvariantError::LeasePollRecoveryRequired);
        }
        match session
            .lease_poll_checkpoints
            .binary_search_by_key(&slot, LeasePollCheckpoint::slot)
        {
            Ok(_) => Ok(false),
            Err(_) if usize::from(slot.get()) > MAX_JOURNALED_SLOTS => {
                Err(JournalInvariantError::SlotLimitReached)
            }
            Err(insertion) => {
                if lease_poll_operation_is_used(session, operation_id) {
                    return Err(JournalInvariantError::LeasePollOperationConflict);
                }
                session
                    .lease_poll_checkpoints
                    .insert(insertion, LeasePollCheckpoint::first(slot, operation_id));
                Ok(true)
            }
        }
    }

    pub(crate) fn advance_lease_poll(
        &mut self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        expected_current: OperationId,
        successor_operation_id: OperationId,
    ) -> Result<bool, JournalInvariantError> {
        self.require_session(session_id)?;
        let session = self
            .session
            .as_mut()
            .ok_or(JournalInvariantError::NoSession)?;
        if session.lease_poll_requires_fresh_session {
            return Err(JournalInvariantError::LeasePollRecoveryRequired);
        }
        let index = session
            .lease_poll_checkpoints
            .binary_search_by_key(&slot, LeasePollCheckpoint::slot)
            .map_err(|_| JournalInvariantError::LeasePollCheckpointMissing(slot))?;
        let checkpoint = session.lease_poll_checkpoints[index];
        if checkpoint.current_operation_id() != expected_current {
            return if checkpoint.acknowledges_operation_id() == Some(expected_current) {
                Ok(false)
            } else {
                Err(JournalInvariantError::LeasePollCheckpointMismatch {
                    expected: expected_current,
                    received: checkpoint.current_operation_id(),
                })
            };
        }
        if lease_poll_operation_is_used(session, successor_operation_id) {
            return Err(JournalInvariantError::LeasePollOperationConflict);
        }
        session.lease_poll_checkpoints[index] = LeasePollCheckpoint {
            slot,
            current_operation_id: successor_operation_id,
            acknowledges_operation_id: Some(expected_current),
        };
        Ok(true)
    }

    fn require_session(
        &self,
        received: RunnerSessionId,
    ) -> Result<SessionBinding, JournalInvariantError> {
        let expected = self
            .session
            .as_ref()
            .ok_or(JournalInvariantError::NoSession)?;
        if expected.session_id() != received {
            return Err(JournalInvariantError::SessionMismatch {
                expected: expected.session_id(),
                received,
            });
        }
        Ok(expected.binding())
    }

    fn command_is_used(&self, command: DurableCommand) -> bool {
        self.session.as_ref().is_some_and(|session| {
            session
                .command_tombstones
                .iter()
                .any(|tombstone| tombstone.command().operation_id() == command.operation_id())
        }) || self.slots.iter().any(|slot| {
            slot.offer.command().operation_id() == command.operation_id()
                || slot
                    .cancellation
                    .is_some_and(|cancel| cancel.command().operation_id() == command.operation_id())
        })
    }

    fn commit_command(
        &mut self,
        session_id: RunnerSessionId,
        command: DurableCommand,
        disposition: CommandDisposition,
    ) -> Result<bool, JournalInvariantError> {
        self.require_session(session_id)?;
        let session = self
            .session
            .as_ref()
            .ok_or(JournalInvariantError::NoSession)?;
        if let Some(current) = session.command_cursor().acknowledged_through()
            && command.sequence() <= current
        {
            let replay = session
                .command_tombstones
                .iter()
                .find(|tombstone| tombstone.command().sequence() == command.sequence())
                .ok_or(JournalInvariantError::CommandReplayOutsideWindow)?;
            return if replay.command() == command && replay.disposition() == disposition {
                Ok(false)
            } else {
                Err(JournalInvariantError::CommandReplayConflict)
            };
        }
        if self.command_is_used(command) {
            return Err(JournalInvariantError::CommandReplayConflict);
        }
        let expected = match session.command_cursor().acknowledged_through() {
            Some(current) => current
                .checked_next()
                .map_err(|_| JournalInvariantError::CounterExhausted)?,
            None => CommandSequence::new(1).map_err(|_| JournalInvariantError::CounterExhausted)?,
        };
        if command.sequence() != expected {
            return Err(JournalInvariantError::CommandSequenceMismatch {
                expected,
                received: command.sequence(),
            });
        }
        let cursor = session
            .command_cursor()
            .advance(command.sequence())
            .map_err(|_| JournalInvariantError::CommandSequenceMismatch {
                expected,
                received: command.sequence(),
            })?;
        let session = self
            .session
            .as_mut()
            .ok_or(JournalInvariantError::NoSession)?;
        session.command_cursor = cursor;
        session
            .command_tombstones
            .push(CommandTombstone::new(command, disposition));
        if session.command_tombstones.len() > MAX_COMMAND_TOMBSTONES {
            session.command_tombstones.remove(0);
        }
        Ok(true)
    }

    pub(crate) fn record_command_disposition(
        &mut self,
        session_id: RunnerSessionId,
        command: DurableCommand,
        disposition: CommandDisposition,
    ) -> Result<bool, JournalInvariantError> {
        self.commit_command(session_id, command, disposition)
    }

    fn slot_index(&self, slot: RunnerSlotOrdinal) -> Result<usize, JournalInvariantError> {
        self.slots
            .binary_search_by_key(&slot, SlotSnapshot::slot)
            .map_err(|_| JournalInvariantError::SlotNotFound(slot))
    }

    fn slot_mut(
        &mut self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
    ) -> Result<&mut SlotSnapshot, JournalInvariantError> {
        self.require_session(session_id)?;
        let index = self.slot_index(slot)?;
        self.slots[index].require_guard(guard)?;
        Ok(&mut self.slots[index])
    }

    pub(crate) fn record_offer(
        &mut self,
        session_id: RunnerSessionId,
        offer: LeaseOfferRecord,
    ) -> Result<bool, JournalInvariantError> {
        let session = self.require_session(session_id)?;
        offer.validate()?;
        if offer.lease().runner_id() != self.runner_id {
            return Err(JournalInvariantError::LeaseRunnerMismatch);
        }
        if offer.job_ir().version() != session.selected_job_ir() {
            return Err(JournalInvariantError::JobIrVersionMismatch);
        }
        if usize::from(offer.slot().get()) > MAX_JOURNALED_SLOTS {
            return Err(JournalInvariantError::SlotLimitReached);
        }
        match self
            .slots
            .binary_search_by_key(&offer.slot(), SlotSnapshot::slot)
        {
            Ok(index) if self.slots[index].offer == offer => return Ok(false),
            Ok(_) => return Err(JournalInvariantError::SlotOccupied(offer.slot())),
            Err(_) if self.slots.len() >= MAX_JOURNALED_SLOTS => {
                return Err(JournalInvariantError::SlotLimitReached);
            }
            Err(_) => {}
        }
        if !self.commit_command(session_id, offer.command(), CommandDisposition::Applied)? {
            return Ok(false);
        }
        let insertion = self
            .slots
            .binary_search_by_key(&offer.slot(), SlotSnapshot::slot)
            .unwrap_or_else(std::convert::identity);
        self.slots
            .insert(insertion, SlotSnapshot::from_offer(offer));
        Ok(true)
    }

    pub(crate) fn accept_offer(
        &mut self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
    ) -> Result<bool, JournalInvariantError> {
        let slot = self.slot_mut(session_id, slot, guard)?;
        if slot.orphan.is_some() {
            return Err(JournalInvariantError::OrphanNotAuthorized);
        }
        match slot.offer_status {
            LeaseOfferStatus::Recorded => {
                slot.offer_status = LeaseOfferStatus::Accepted;
                Ok(true)
            }
            LeaseOfferStatus::Accepted => Ok(false),
            LeaseOfferStatus::Rejected => Err(JournalInvariantError::OfferAlreadyRejected),
        }
    }

    pub(crate) fn reject_offer(
        &mut self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        reason: LeaseRejectionReason,
        response_operation_id: OperationId,
    ) -> Result<bool, JournalInvariantError> {
        let slot = self.slot_mut(session_id, slot, guard)?;
        if slot.orphan.is_some() {
            return Err(JournalInvariantError::OrphanNotAuthorized);
        }
        match slot.offer_status {
            LeaseOfferStatus::Recorded => {
                slot.offer_status = LeaseOfferStatus::Rejected;
                slot.rejection = Some(LeaseRejectionRecord::new(reason, response_operation_id));
                Ok(true)
            }
            LeaseOfferStatus::Accepted => Err(JournalInvariantError::OfferAlreadyAccepted),
            LeaseOfferStatus::Rejected
                if slot.rejection.as_ref().is_some_and(|rejection| {
                    rejection.reason() == &reason
                        && rejection.response_operation_id() == response_operation_id
                }) =>
            {
                Ok(false)
            }
            LeaseOfferStatus::Rejected => Err(JournalInvariantError::LeaseRejectionReplayConflict),
        }
    }

    pub(crate) fn acknowledge_offer_rejection(
        &mut self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        response_operation_id: OperationId,
    ) -> Result<bool, JournalInvariantError> {
        let slot = self.slot_mut(session_id, slot, guard)?;
        if slot.offer_status != LeaseOfferStatus::Rejected {
            return Err(JournalInvariantError::OfferNotRejected);
        }
        let rejection = slot
            .rejection
            .as_mut()
            .ok_or(JournalInvariantError::DecodedStateInvalid)?;
        if rejection.response_operation_id() != response_operation_id {
            return Err(JournalInvariantError::LeaseRejectionOperationMismatch);
        }
        if rejection.is_response_acknowledged() {
            return Ok(false);
        }
        rejection.acknowledge_response();
        Ok(true)
    }

    pub(crate) fn renew_lease(
        &mut self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        expires_at: UnixMillis,
    ) -> Result<bool, JournalInvariantError> {
        let slot = self.slot_mut(session_id, slot, guard)?;
        if slot.orphan.is_some() {
            return Err(JournalInvariantError::OrphanNotAuthorized);
        }
        if slot.offer_status == LeaseOfferStatus::Rejected {
            return Err(JournalInvariantError::OfferAlreadyRejected);
        }
        if expires_at < slot.expires_at {
            return Err(JournalInvariantError::LeaseExpiryRegression);
        }
        if expires_at == slot.expires_at {
            return Ok(false);
        }
        slot.expires_at = expires_at;
        Ok(true)
    }

    pub(crate) fn record_cancellation(
        &mut self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        cancellation: CancellationRecord,
    ) -> Result<bool, JournalInvariantError> {
        self.require_session(session_id)?;
        let index = self.slot_index(slot)?;
        self.slots[index].require_guard(guard)?;
        if self.slots[index].orphan.is_some() {
            return Err(JournalInvariantError::OrphanNotAuthorized);
        }
        if self.slots[index].offer_status == LeaseOfferStatus::Rejected {
            return Err(JournalInvariantError::OfferAlreadyRejected);
        }
        if self.slots[index].cancellation == Some(cancellation) {
            return Ok(false);
        }
        if self.slots[index].cancellation.is_some() {
            return Err(JournalInvariantError::CommandReplayConflict);
        }
        if !self.commit_command(
            session_id,
            cancellation.command(),
            CommandDisposition::Applied,
        )? {
            return Ok(false);
        }
        let current = self.slots[index].lifecycle;
        if current != JobLifecycle::Cancelling {
            current
                .validate_transition(JobLifecycle::Cancelling)
                .map_err(|_| JournalInvariantError::InvalidLifecycleTransition)?;
        }
        self.slots[index].cancellation = Some(cancellation);
        self.slots[index].lifecycle = JobLifecycle::Cancelling;
        Ok(true)
    }

    pub(crate) fn transition_lifecycle(
        &mut self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        next: JobLifecycle,
    ) -> Result<bool, JournalInvariantError> {
        let slot = self.slot_mut(session_id, slot, guard)?;
        if slot.offer_status != LeaseOfferStatus::Accepted {
            return Err(JournalInvariantError::OfferNotAccepted);
        }
        if slot.orphan.is_some() {
            return Err(JournalInvariantError::OrphanNotAuthorized);
        }
        if slot.lifecycle == next {
            return Ok(false);
        }
        if next.is_terminal() {
            return Err(JournalInvariantError::TerminalResultRequired);
        }
        slot.lifecycle
            .validate_transition(next)
            .map_err(|_| JournalInvariantError::InvalidLifecycleTransition)?;
        slot.lifecycle = next;
        Ok(true)
    }

    pub(crate) fn record_terminal_result(
        &mut self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        terminal: JobLifecycle,
        result: TerminalResultRecord,
    ) -> Result<bool, JournalInvariantError> {
        let slot = self.slot_mut(session_id, slot, guard)?;
        if slot.offer_status != LeaseOfferStatus::Accepted {
            return Err(JournalInvariantError::OfferNotAccepted);
        }
        if slot.orphan.is_some() {
            return Err(JournalInvariantError::OrphanNotAuthorized);
        }
        result.validate()?;
        if result.is_acknowledged() {
            return Err(JournalInvariantError::TerminalResultAlreadyAcknowledgedInput);
        }
        if !terminal.is_terminal() {
            return Err(JournalInvariantError::InvalidLifecycleTransition);
        }
        if let Some(existing) = &slot.terminal_result {
            return if existing.matches_unacknowledged(&result) && slot.lifecycle == terminal {
                Ok(false)
            } else {
                Err(JournalInvariantError::TerminalResultReplayConflict)
            };
        }
        slot.lifecycle
            .validate_transition(terminal)
            .map_err(|_| JournalInvariantError::InvalidLifecycleTransition)?;
        slot.lifecycle = terminal;
        slot.terminal_result = Some(result);
        Ok(true)
    }

    pub(crate) fn acknowledge_terminal_result(
        &mut self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        operation_id: OperationId,
    ) -> Result<bool, JournalInvariantError> {
        let slot = self.slot_mut(session_id, slot, guard)?;
        let result = slot
            .terminal_result
            .as_mut()
            .ok_or(JournalInvariantError::TerminalResultRequired)?;
        if result.operation_id() != operation_id {
            return Err(JournalInvariantError::TerminalResultOperationMismatch);
        }
        if result.is_acknowledged() {
            return Ok(false);
        }
        result.acknowledge();
        Ok(true)
    }

    pub(crate) fn record_provider_intent(
        &mut self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        intent: ProviderOperation,
    ) -> Result<bool, JournalInvariantError> {
        let slot = self.slot_mut(session_id, slot, guard)?;
        if slot.offer_status != LeaseOfferStatus::Accepted {
            return Err(JournalInvariantError::OfferNotAccepted);
        }
        if slot.lifecycle.is_terminal()
            && slot.orphan.is_none()
            && intent.kind() != ProviderOperationKind::DestroySandbox
        {
            return Err(JournalInvariantError::LeaseTerminal);
        }
        if slot.orphan.is_some()
            && !matches!(
                intent.kind(),
                ProviderOperationKind::StopSandbox | ProviderOperationKind::DestroySandbox
            )
        {
            return Err(JournalInvariantError::InvalidProviderOperation {
                kind: intent.kind(),
            });
        }
        if intent.outcome() != ProviderOperationOutcome::Pending {
            return Err(JournalInvariantError::InvalidProviderOperation {
                kind: intent.kind(),
            });
        }
        if let Some(existing) = slot
            .provider_operations
            .iter()
            .find(|operation| operation.operation_id() == intent.operation_id())
        {
            return if existing.kind() == intent.kind() {
                Ok(false)
            } else {
                Err(JournalInvariantError::ProviderOperationReplayConflict)
            };
        }
        if slot
            .provider_operations
            .last()
            .is_some_and(|operation| operation.is_pending())
        {
            return Err(JournalInvariantError::ProviderOperationPending);
        }
        if slot.provider_operations.len() >= MAX_PROVIDER_OPERATIONS_PER_SLOT {
            let compacted = slot.provider_operations.remove(0);
            slot.provider_checkpoint.compact(compacted)?;
        }
        let recovery =
            replay_provider_operations(slot.provider_checkpoint, &slot.provider_operations)?;
        let lifecycle_valid = slot.orphan.is_some()
            || match intent.kind() {
                ProviderOperationKind::CreateSandbox => matches!(
                    slot.lifecycle,
                    JobLifecycle::Leased | JobLifecycle::Preparing
                ),
                ProviderOperationKind::StartSandbox => slot.lifecycle == JobLifecycle::Preparing,
                ProviderOperationKind::StopSandbox => matches!(
                    slot.lifecycle,
                    JobLifecycle::Running | JobLifecycle::Cancelling
                ),
                ProviderOperationKind::DestroySandbox => true,
            };
        let valid = lifecycle_valid && recovery.can_begin(intent.kind());
        if !valid {
            return Err(JournalInvariantError::InvalidProviderOperation {
                kind: intent.kind(),
            });
        }
        slot.provider_operations.push(intent);
        Ok(true)
    }

    pub(crate) fn record_sandbox_created(
        &mut self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        operation_id: OperationId,
        sandbox: SandboxIdentity,
    ) -> Result<bool, JournalInvariantError> {
        let slot = self.slot_mut(session_id, slot, guard)?;
        let Some(operation) = slot.provider_operations.last_mut() else {
            return Err(JournalInvariantError::SandboxWithoutCreateIntent);
        };
        if operation.operation_id() != operation_id
            || operation.kind() != ProviderOperationKind::CreateSandbox
        {
            return Err(JournalInvariantError::SandboxWithoutCreateIntent);
        }
        if operation.outcome() == ProviderOperationOutcome::Applied {
            return if slot.sandbox.as_ref() == Some(&sandbox) {
                Ok(false)
            } else {
                Err(JournalInvariantError::SandboxIdentityConflict)
            };
        }
        if slot.sandbox.is_some() {
            return Err(JournalInvariantError::SandboxIdentityConflict);
        }
        let changed = operation.mark_applied()?;
        slot.sandbox = Some(sandbox);
        Ok(changed)
    }

    pub(crate) fn complete_provider_operation(
        &mut self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        operation_id: OperationId,
    ) -> Result<bool, JournalInvariantError> {
        let slot = self.slot_mut(session_id, slot, guard)?;
        let Some(operation) = slot.provider_operations.last_mut() else {
            return Err(JournalInvariantError::ProviderOperationReplayConflict);
        };
        if operation.operation_id() != operation_id {
            return Err(JournalInvariantError::ProviderOperationReplayConflict);
        }
        if operation.kind() == ProviderOperationKind::CreateSandbox {
            return Err(JournalInvariantError::SandboxWithoutCreateIntent);
        }
        let destroyed = operation.kind() == ProviderOperationKind::DestroySandbox;
        let changed = operation.mark_applied()?;
        if changed && destroyed {
            slot.sandbox = None;
        }
        Ok(changed)
    }

    pub(crate) fn fail_provider_operation(
        &mut self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        operation_id: OperationId,
        failure: ProviderFailureOutcome,
    ) -> Result<bool, JournalInvariantError> {
        let slot = self.slot_mut(session_id, slot, guard)?;
        let Some(operation) = slot.provider_operations.last_mut() else {
            return Err(JournalInvariantError::ProviderOperationReplayConflict);
        };
        if operation.operation_id() != operation_id {
            return Err(JournalInvariantError::ProviderOperationReplayConflict);
        }
        operation.resolve_failure(failure)
    }

    pub(crate) fn advance_outbound_operation(
        &mut self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        sequence: OutboundOperationSequence,
    ) -> Result<bool, JournalInvariantError> {
        let slot = self.slot_mut(session_id, slot, guard)?;
        if slot.outbound_operations.contiguous_through() == Some(sequence) {
            return Ok(false);
        }
        slot.outbound_operations.advance(sequence)?;
        Ok(true)
    }

    pub(crate) fn open_log_stream(
        &mut self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        stream_id: LogStreamId,
        spool_content: DurableContentRef,
    ) -> Result<bool, JournalInvariantError> {
        let slot = self.slot_mut(session_id, slot, guard)?;
        if slot.offer_status != LeaseOfferStatus::Accepted {
            return Err(JournalInvariantError::OfferNotAccepted);
        }
        if slot.orphan.is_some() {
            return Err(JournalInvariantError::OrphanNotAuthorized);
        }
        match &slot.log_delivery {
            Some(log) if log.stream_id() == stream_id && log.spool_content() == &spool_content => {
                Ok(false)
            }
            Some(_) => Err(JournalInvariantError::LogStreamMismatch),
            None => {
                slot.log_delivery = Some(LogDeliveryCursor::new(stream_id, spool_content)?);
                Ok(true)
            }
        }
    }

    pub(crate) fn record_log_produced(
        &mut self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        production: &LogProductionRecord,
    ) -> Result<bool, JournalInvariantError> {
        let slot = self.slot_mut(session_id, slot, guard)?;
        if slot.orphan.is_some() {
            return Err(JournalInvariantError::OrphanNotAuthorized);
        }
        let log = slot
            .log_delivery
            .as_mut()
            .ok_or(JournalInvariantError::LogStreamMismatch)?;
        if log.stream_id() != production.stream_id() {
            return Err(JournalInvariantError::LogStreamMismatch);
        }
        if log.produced_through() == Some(production.sequence()) {
            return if log.end_of_stream()
                == production.end_of_stream().then_some(production.sequence())
                && log.spool_content() == production.spool_content()
            {
                Ok(false)
            } else {
                Err(JournalInvariantError::LogProductionReplayConflict)
            };
        }
        log.record_produced(
            production.sequence(),
            production.end_of_stream(),
            production.spool_content().clone(),
        )?;
        Ok(true)
    }

    pub(crate) fn acknowledge_log(
        &mut self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        stream_id: LogStreamId,
        sequence: LogSequence,
    ) -> Result<bool, JournalInvariantError> {
        let slot = self.slot_mut(session_id, slot, guard)?;
        let log = slot
            .log_delivery
            .as_mut()
            .ok_or(JournalInvariantError::LogStreamMismatch)?;
        if log.stream_id() != stream_id {
            return Err(JournalInvariantError::LogStreamMismatch);
        }
        if log.acknowledged_through() == Some(sequence) {
            return Ok(false);
        }
        log.acknowledge(sequence)?;
        Ok(true)
    }

    pub(crate) fn orphan_claim(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
    ) -> Result<super::OrphanClaim, JournalInvariantError> {
        self.require_session(session_id)?;
        let slot = &self.slots[self.slot_index(slot)?];
        slot.require_guard(guard)?;
        Ok(super::OrphanClaim::new(
            self.runner_id,
            session_id,
            slot.slot(),
            guard,
        ))
    }

    pub(crate) fn authorize_orphan(
        &mut self,
        grant: OrphanAuthorityGrant,
    ) -> Result<bool, JournalInvariantError> {
        let claim = grant.claim();
        let expected = self.orphan_claim(claim.session_id(), claim.slot(), claim.guard())?;
        if claim != expected {
            return Err(JournalInvariantError::OrphanAuthorityMismatch);
        }
        let index = self.slot_index(claim.slot())?;
        if let Some(orphan) = self.slots[index].orphan {
            return if orphan.matches_grant(grant) {
                Ok(false)
            } else {
                Err(JournalInvariantError::OrphanAuthorityMismatch)
            };
        }
        self.slots[index].orphan = Some(OrphanRecord::from_grant(grant));
        if !self.slots[index].lifecycle.is_terminal() {
            self.slots[index].lifecycle = JobLifecycle::Lost;
        }
        Ok(true)
    }

    pub(crate) fn abandon_orphan_delivery(
        &mut self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        authority_operation_id: OperationId,
        delivery: OrphanDelivery,
        reason: OrphanAbandonmentReason,
    ) -> Result<bool, JournalInvariantError> {
        let slot = self.slot_mut(session_id, slot, guard)?;
        let exists = match delivery {
            OrphanDelivery::TerminalResult => slot.terminal_result.is_some(),
            OrphanDelivery::LogStream => slot.log_delivery.is_some(),
            OrphanDelivery::LeaseRejection => slot.rejection.is_some(),
        };
        if !exists {
            return Err(JournalInvariantError::OrphanAbandonmentConflict);
        }
        slot.orphan
            .as_mut()
            .ok_or(JournalInvariantError::OrphanNotAuthorized)?
            .abandon(authority_operation_id, delivery, reason)
    }

    pub(crate) fn release_slot(
        &mut self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
    ) -> Result<bool, JournalInvariantError> {
        self.require_session(session_id)?;
        let index = self.slot_index(slot)?;
        self.slots[index].require_guard(guard)?;
        let orphan = self.slots[index].orphan;
        if self.slots[index].offer_status != LeaseOfferStatus::Accepted && orphan.is_none() {
            return Err(JournalInvariantError::OfferNotAccepted);
        }
        if !self.slots[index].lifecycle.is_terminal()
            || self.slots[index]
                .provider_operations
                .last()
                .is_some_and(|operation| operation.is_pending())
            || self.slots[index].sandbox.is_some()
        {
            return Err(JournalInvariantError::SlotNotTerminal);
        }
        let log_complete = self.slots[index]
            .log_delivery
            .as_ref()
            .is_none_or(LogDeliveryCursor::is_fully_delivered)
            || orphan.is_some_and(|record| record.is_abandoned(OrphanDelivery::LogStream));
        if !log_complete {
            return Err(JournalInvariantError::LogDeliveryIncomplete);
        }
        let result_complete = self.slots[index]
            .terminal_result
            .as_ref()
            .is_some_and(TerminalResultRecord::is_acknowledged)
            || orphan.is_some_and(|record| {
                record.is_abandoned(OrphanDelivery::TerminalResult)
                    || self.slots[index].terminal_result.is_none()
            });
        if self.slots[index].offer_status == LeaseOfferStatus::Accepted && !result_complete {
            return Err(JournalInvariantError::TerminalResultNotAcknowledged);
        }
        let rejection_complete = self.slots[index]
            .rejection
            .as_ref()
            .is_none_or(|rejection| {
                rejection.is_response_acknowledged()
                    || orphan
                        .is_some_and(|record| record.is_abandoned(OrphanDelivery::LeaseRejection))
            });
        if !rejection_complete {
            return Err(JournalInvariantError::LeaseRejectionNotAcknowledged);
        }
        self.slots.remove(index);
        Ok(true)
    }

    pub(crate) fn release_rejected_offer(
        &mut self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        response_operation_id: OperationId,
    ) -> Result<bool, JournalInvariantError> {
        self.require_session(session_id)?;
        let index = self.slot_index(slot)?;
        self.slots[index].require_guard(guard)?;
        if self.slots[index].offer_status != LeaseOfferStatus::Rejected {
            return Err(JournalInvariantError::OfferNotRejected);
        }
        let rejection = self.slots[index]
            .rejection
            .as_ref()
            .ok_or(JournalInvariantError::DecodedStateInvalid)?;
        if rejection.response_operation_id() != response_operation_id {
            return Err(JournalInvariantError::LeaseRejectionOperationMismatch);
        }
        if !rejection.is_response_acknowledged() {
            return Err(JournalInvariantError::LeaseRejectionNotAcknowledged);
        }
        self.slots.remove(index);
        Ok(true)
    }
}

fn lease_poll_operation_is_used(session: &SessionSnapshot, operation_id: OperationId) -> bool {
    session.lease_poll_checkpoints.iter().any(|checkpoint| {
        checkpoint.current_operation_id() == operation_id
            || checkpoint.acknowledges_operation_id() == Some(operation_id)
    })
}
