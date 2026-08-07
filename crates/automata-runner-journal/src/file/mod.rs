mod codec;
mod platform;
mod state_root;

use std::{
    fmt,
    sync::{Arc, Mutex},
};

use automata_core::{
    JobLifecycle, LeaseGuard, LogSequence, LogStreamId, OperationId, RunnerId, RunnerSessionId,
    UnixMillis,
};
use automata_protocol::{LeaseRejectionReason, RunnerSlotOrdinal};

use self::{
    codec::{decode, encode},
    platform::PlatformDirectory,
};
use crate::{
    CancellationRecord, CommandDisposition, DurableCommand, DurableContentRef, JournalError,
    JournalSnapshot, LeaseOfferRecord, LogProductionRecord, OrphanAbandonmentReason,
    OrphanAuthorityProof, OrphanAuthorityVerifier, OrphanDelivery, OutboundOperationSequence,
    ProviderFailureOutcome, ProviderOperation, RunnerJournal, SandboxIdentity, SessionBinding,
    TerminalResultRecord, model::StoredJournal,
};

pub use state_root::StateRoot;

/// Atomic-commit boundary exposed to deterministic crash/fault tests.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CommitStage {
    StagingCreated,
    DataWritten,
    FileSynced,
    Renamed,
    DirectorySynced,
}

/// Marker returned by a fault injector at the selected commit boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitFault;

/// Test/application hook for deterministic storage-fault simulation.
/// Production code normally uses [`NoCommitFaults`].
pub trait CommitFaultInjector: Send + Sync {
    /// Interrupts a commit at a deterministic durability boundary.
    ///
    /// # Errors
    ///
    /// Returns [`CommitFault`] when the caller should simulate interruption at
    /// `stage`.
    fn check(&self, stage: CommitStage) -> Result<(), CommitFault>;
}

/// Fault injector that never interrupts commits.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoCommitFaults;

impl CommitFaultInjector for NoCommitFaults {
    fn check(&self, _stage: CommitStage) -> Result<(), CommitFault> {
        Ok(())
    }
}

/// Trusted construction options for the file adapter.
#[derive(Clone)]
pub struct FileJournalOptions {
    fault_injector: Arc<dyn CommitFaultInjector>,
}

impl FileJournalOptions {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_fault_injector(mut self, injector: Arc<dyn CommitFaultInjector>) -> Self {
        self.fault_injector = injector;
        self
    }
}

impl Default for FileJournalOptions {
    fn default() -> Self {
        Self {
            fault_injector: Arc::new(NoCommitFaults),
        }
    }
}

impl fmt::Debug for FileJournalOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileJournalOptions")
            .field("fault_injector", &"configured")
            .finish()
    }
}

#[derive(Debug)]
struct MemoryState {
    state: StoredJournal,
    poisoned: bool,
}

/// Crash-durable single-file runner journal.
///
/// Holding this value retains the process-exclusive advisory lock. All path
/// access is relative to a securely opened state-root directory descriptor.
pub struct FileJournal {
    root: StateRoot,
    directory: PlatformDirectory,
    memory: Mutex<MemoryState>,
    options: FileJournalOptions,
}

impl fmt::Debug for FileJournal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileJournal")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl FileJournal {
    /// Opens and exclusively locks a journal, creating its initial runner
    /// identity if needed.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for unsafe paths, lock contention, corrupt or
    /// oversized data, identity mismatch, or storage failures.
    pub fn open(root: StateRoot, runner_id: RunnerId) -> Result<Self, JournalError> {
        Self::open_with_options(root, runner_id, FileJournalOptions::default())
    }

    /// Opens with trusted fault-injection options.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::open`], plus an injected initialization
    /// fault if the state file does not yet exist.
    pub fn open_with_options(
        root: StateRoot,
        runner_id: RunnerId,
        options: FileJournalOptions,
    ) -> Result<Self, JournalError> {
        let directory = PlatformDirectory::open(&root)?;
        directory.cleanup_staging()?;
        let state = if let Some(bytes) = directory.read_state()? {
            let decoded = decode(&bytes)?;
            let state = decoded.state;
            if state.runner_id() != runner_id {
                return Err(JournalError::RunnerIdentityMismatch {
                    expected: state.runner_id(),
                    received: runner_id,
                });
            }
            if decoded.migrated {
                let encoded = encode(&state)?;
                let failure =
                    directory.commit(state.revision(), &encoded, options.fault_injector.as_ref());
                if let Err(failure) = failure {
                    return Err(if failure.renamed() {
                        JournalError::CommitOutcomeUnknown
                    } else {
                        failure.into_public()
                    });
                }
            }
            state
        } else {
            let state = StoredJournal::new(runner_id);
            let encoded = encode(&state)?;
            let failure =
                directory.commit(state.revision(), &encoded, options.fault_injector.as_ref());
            if let Err(failure) = failure {
                return Err(if failure.renamed() {
                    JournalError::CommitOutcomeUnknown
                } else {
                    failure.into_public()
                });
            }
            state
        };
        Ok(Self {
            root,
            directory,
            memory: Mutex::new(MemoryState {
                state,
                poisoned: false,
            }),
            options,
        })
    }

    #[must_use]
    pub const fn state_root(&self) -> &StateRoot {
        &self.root
    }

    fn mutate<F>(&self, mutation: F) -> Result<JournalSnapshot, JournalError>
    where
        F: FnOnce(&mut StoredJournal) -> Result<bool, crate::JournalInvariantError>,
    {
        let mut memory = self.memory.lock().map_err(|_| JournalError::Poisoned)?;
        if memory.poisoned {
            return Err(JournalError::Poisoned);
        }
        let mut candidate = memory.state.clone();
        if !mutation(&mut candidate)? {
            return Ok(memory.state.snapshot());
        }
        candidate.increment_revision()?;
        let bytes = encode(&candidate)?;
        match self.directory.commit(
            candidate.revision(),
            &bytes,
            self.options.fault_injector.as_ref(),
        ) {
            Ok(()) => {
                memory.state = candidate;
                Ok(memory.state.snapshot())
            }
            Err(failure) if failure.renamed() => {
                memory.poisoned = true;
                Err(JournalError::CommitOutcomeUnknown)
            }
            Err(failure) => Err(failure.into_public()),
        }
    }
}

impl RunnerJournal for FileJournal {
    fn snapshot(&self) -> Result<JournalSnapshot, JournalError> {
        let memory = self.memory.lock().map_err(|_| JournalError::Poisoned)?;
        if memory.poisoned {
            return Err(JournalError::Poisoned);
        }
        Ok(memory.state.snapshot())
    }

    fn begin_session(&self, binding: SessionBinding) -> Result<JournalSnapshot, JournalError> {
        self.mutate(|state| state.begin_session(binding))
    }

    fn prepare_lease_poll(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        operation_id: OperationId,
    ) -> Result<JournalSnapshot, JournalError> {
        self.mutate(|state| state.prepare_lease_poll(session_id, slot, operation_id))
    }

    fn advance_lease_poll(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        expected_current: OperationId,
        successor_operation_id: OperationId,
    ) -> Result<JournalSnapshot, JournalError> {
        self.mutate(|state| {
            state.advance_lease_poll(session_id, slot, expected_current, successor_operation_id)
        })
    }

    fn record_command_disposition(
        &self,
        session_id: RunnerSessionId,
        command: DurableCommand,
        disposition: CommandDisposition,
    ) -> Result<JournalSnapshot, JournalError> {
        self.mutate(|state| state.record_command_disposition(session_id, command, disposition))
    }

    fn record_lease_offer(
        &self,
        session_id: RunnerSessionId,
        offer: LeaseOfferRecord,
    ) -> Result<JournalSnapshot, JournalError> {
        self.mutate(|state| state.record_offer(session_id, offer))
    }

    fn accept_lease(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
    ) -> Result<JournalSnapshot, JournalError> {
        self.mutate(|state| state.accept_offer(session_id, slot, guard))
    }

    fn reject_lease(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        reason: LeaseRejectionReason,
        response_operation_id: OperationId,
    ) -> Result<JournalSnapshot, JournalError> {
        self.mutate(|state| {
            state.reject_offer(session_id, slot, guard, reason, response_operation_id)
        })
    }

    fn acknowledge_lease_rejection(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        response_operation_id: OperationId,
    ) -> Result<JournalSnapshot, JournalError> {
        self.mutate(|state| {
            state.acknowledge_offer_rejection(session_id, slot, guard, response_operation_id)
        })
    }

    fn release_rejected_lease(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        response_operation_id: OperationId,
    ) -> Result<JournalSnapshot, JournalError> {
        self.mutate(|state| {
            state.release_rejected_offer(session_id, slot, guard, response_operation_id)
        })
    }

    fn renew_lease(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        expires_at: UnixMillis,
    ) -> Result<JournalSnapshot, JournalError> {
        self.mutate(|state| state.renew_lease(session_id, slot, guard, expires_at))
    }

    fn record_cancellation(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        cancellation: CancellationRecord,
    ) -> Result<JournalSnapshot, JournalError> {
        self.mutate(|state| state.record_cancellation(session_id, slot, guard, cancellation))
    }

    fn transition_lifecycle(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        next: JobLifecycle,
    ) -> Result<JournalSnapshot, JournalError> {
        self.mutate(|state| state.transition_lifecycle(session_id, slot, guard, next))
    }

    fn record_terminal_result(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        terminal: JobLifecycle,
        result: TerminalResultRecord,
    ) -> Result<JournalSnapshot, JournalError> {
        self.mutate(|state| state.record_terminal_result(session_id, slot, guard, terminal, result))
    }

    fn acknowledge_terminal_result(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        operation_id: OperationId,
    ) -> Result<JournalSnapshot, JournalError> {
        self.mutate(|state| {
            state.acknowledge_terminal_result(session_id, slot, guard, operation_id)
        })
    }

    fn record_provider_intent(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        intent: ProviderOperation,
    ) -> Result<JournalSnapshot, JournalError> {
        self.mutate(|state| state.record_provider_intent(session_id, slot, guard, intent))
    }

    fn record_sandbox_created(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        operation_id: OperationId,
        sandbox: SandboxIdentity,
    ) -> Result<JournalSnapshot, JournalError> {
        self.mutate(|state| {
            state.record_sandbox_created(session_id, slot, guard, operation_id, sandbox)
        })
    }

    fn complete_provider_operation(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        operation_id: OperationId,
    ) -> Result<JournalSnapshot, JournalError> {
        self.mutate(|state| {
            state.complete_provider_operation(session_id, slot, guard, operation_id)
        })
    }

    fn fail_provider_operation(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        operation_id: OperationId,
        failure: ProviderFailureOutcome,
    ) -> Result<JournalSnapshot, JournalError> {
        self.mutate(|state| {
            state.fail_provider_operation(session_id, slot, guard, operation_id, failure)
        })
    }

    fn advance_outbound_operation(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        sequence: OutboundOperationSequence,
    ) -> Result<JournalSnapshot, JournalError> {
        self.mutate(|state| state.advance_outbound_operation(session_id, slot, guard, sequence))
    }

    fn open_log_stream(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        stream_id: LogStreamId,
        spool_content: DurableContentRef,
    ) -> Result<JournalSnapshot, JournalError> {
        self.mutate(|state| {
            state.open_log_stream(session_id, slot, guard, stream_id, spool_content)
        })
    }

    fn record_log_produced(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        production: LogProductionRecord,
    ) -> Result<JournalSnapshot, JournalError> {
        self.mutate(|state| state.record_log_produced(session_id, slot, guard, &production))
    }

    fn acknowledge_log(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        stream_id: LogStreamId,
        sequence: LogSequence,
    ) -> Result<JournalSnapshot, JournalError> {
        self.mutate(|state| state.acknowledge_log(session_id, slot, guard, stream_id, sequence))
    }

    fn authorize_orphan(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        verifier: &dyn OrphanAuthorityVerifier,
        proof: &OrphanAuthorityProof,
    ) -> Result<JournalSnapshot, JournalError> {
        let claim = {
            let memory = self.memory.lock().map_err(|_| JournalError::Poisoned)?;
            if memory.poisoned {
                return Err(JournalError::Poisoned);
            }
            memory.state.orphan_claim(session_id, slot, guard)?
        };
        let grant = verifier.verify(claim, proof)?;
        self.mutate(|state| state.authorize_orphan(grant))
    }

    fn abandon_orphan_delivery(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        authority_operation_id: OperationId,
        delivery: OrphanDelivery,
        reason: OrphanAbandonmentReason,
    ) -> Result<JournalSnapshot, JournalError> {
        self.mutate(|state| {
            state.abandon_orphan_delivery(
                session_id,
                slot,
                guard,
                authority_operation_id,
                delivery,
                reason,
            )
        })
    }

    fn release_slot(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
    ) -> Result<JournalSnapshot, JournalError> {
        self.mutate(|state| state.release_slot(session_id, slot, guard))
    }
}
