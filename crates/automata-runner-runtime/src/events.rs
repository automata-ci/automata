use std::{fmt, sync::Arc};

use automata_core::{
    AttemptId, JobLifecycle, LeaseGuard, LogChannel, LogFrame, LogSequence, LogStreamId,
    OperationId,
};
use automata_protocol::{
    LogBatch, MessageHeader, NegotiatedSession, ProtocolLimits, RunnerSlotOrdinal, RunnerToServer,
};
use automata_runner_journal::{
    LogProductionRecord, ProviderFailureOutcome, ProviderOperation, ProviderOperationKind,
    RunnerJournal, SandboxIdentity,
};
use automata_runner_spool::{ContentKind, DurableContentStore};
use automata_runner_transport::PreparedRequest;

use crate::content::ContentOperationCoordinator;
use crate::outbox::append_record;
use crate::{
    ExecutionEventError, ExecutionEvents, LogEvent, RuntimeClock, RuntimeIdSource, StableIdDomain,
};

pub(crate) struct DurableExecutionEvents {
    journal: Arc<dyn RunnerJournal>,
    spool: Arc<dyn DurableContentStore>,
    ids: Arc<dyn RuntimeIdSource>,
    clock: Arc<dyn RuntimeClock>,
    session: NegotiatedSession,
    slot: RunnerSlotOrdinal,
    attempt_id: AttemptId,
    guard: LeaseGuard,
    limits: ProtocolLimits,
    content_operations: Arc<ContentOperationCoordinator>,
    serial: std::sync::Mutex<()>,
}

impl DurableExecutionEvents {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        journal: Arc<dyn RunnerJournal>,
        spool: Arc<dyn DurableContentStore>,
        ids: Arc<dyn RuntimeIdSource>,
        clock: Arc<dyn RuntimeClock>,
        session: NegotiatedSession,
        slot: RunnerSlotOrdinal,
        attempt_id: AttemptId,
        guard: LeaseGuard,
        limits: ProtocolLimits,
        content_operations: Arc<ContentOperationCoordinator>,
    ) -> Self {
        Self {
            journal,
            spool,
            ids,
            clock,
            session,
            slot,
            attempt_id,
            guard,
            limits,
            content_operations,
            serial: std::sync::Mutex::new(()),
        }
    }

    fn stable_identity(&self, suffix: &[u8]) -> Vec<u8> {
        let mut identity = Vec::with_capacity(16 * 4 + suffix.len());
        identity.extend_from_slice(self.session.session_id().as_uuid().as_bytes());
        identity.extend_from_slice(self.attempt_id.as_uuid().as_bytes());
        identity.extend_from_slice(self.guard.lease_id().as_uuid().as_bytes());
        identity.extend_from_slice(&self.guard.fencing_token().get().to_be_bytes());
        identity.extend_from_slice(suffix);
        identity
    }

    fn stream_id(&self) -> LogStreamId {
        let operation = self
            .ids
            .stable_operation_id(StableIdDomain::LogStream, &self.stable_identity(b"stream"));
        LogStreamId::from_uuid(operation.as_uuid())
    }

    fn ensure_log_stream(
        &self,
        stream_id: LogStreamId,
    ) -> Result<automata_runner_journal::JournalSnapshot, ExecutionEventError> {
        let snapshot = self
            .journal
            .snapshot()
            .map_err(ExecutionEventError::Journal)?;
        let slot = snapshot
            .slot(self.slot)
            .ok_or(ExecutionEventError::InvalidEvent)?;
        if slot.log_delivery().is_some() {
            return Ok(snapshot);
        }
        self.content_operations.publish_reclaiming_capacity(
            self.journal.as_ref(),
            self.spool.as_ref(),
            || self.open_log_stream_once(stream_id),
        )
    }

    fn open_log_stream_once(
        &self,
        stream_id: LogStreamId,
    ) -> Result<automata_runner_journal::JournalSnapshot, ExecutionEventError> {
        let publication = self
            .spool
            .persist(ContentKind::LogSpool, &[])
            .map_err(ExecutionEventError::Spool)?;
        match publication.commit_with(|content| {
            self.journal.open_log_stream(
                self.session.session_id(),
                self.slot,
                self.guard,
                stream_id,
                content.clone(),
            )
        }) {
            Ok(snapshot) => Ok(snapshot),
            Err(failure) => {
                let (error, publication) = failure.into_parts();
                publication.abort();
                Err(ExecutionEventError::Journal(error))
            }
        }
    }

    fn publish_log_cumulative_once(
        &self,
        stream_id: LogStreamId,
        sequence: LogSequence,
        end_of_stream: bool,
        cumulative: &[u8],
    ) -> Result<automata_runner_journal::JournalSnapshot, ExecutionEventError> {
        let publication = self
            .spool
            .persist(ContentKind::LogSpool, cumulative)
            .map_err(ExecutionEventError::Spool)?;
        let production = publication.commit_with(|content| {
            let production =
                LogProductionRecord::new(stream_id, sequence, end_of_stream, content.clone())
                    .map_err(|_| {
                        automata_runner_journal::JournalError::Invariant(
                            automata_runner_journal::JournalInvariantError::InvalidLogSpoolContent,
                        )
                    })?;
            self.journal.record_log_produced(
                self.session.session_id(),
                self.slot,
                self.guard,
                production,
            )
        });
        match production {
            Ok(snapshot) => Ok(snapshot),
            Err(failure) => {
                let (error, publication) = failure.into_parts();
                publication.abort();
                Err(ExecutionEventError::Journal(error))
            }
        }
    }

    fn publish_log_cumulative(
        &self,
        stream_id: LogStreamId,
        sequence: LogSequence,
        end_of_stream: bool,
        cumulative: &[u8],
    ) -> Result<automata_runner_journal::JournalSnapshot, ExecutionEventError> {
        self.content_operations.publish_reclaiming_capacity(
            self.journal.as_ref(),
            self.spool.as_ref(),
            || self.publish_log_cumulative_once(stream_id, sequence, end_of_stream, cumulative),
        )
    }

    fn emit_log_serialized(
        &self,
        channel: LogChannel,
        payload: &[u8],
        end_of_stream: bool,
    ) -> Result<(), ExecutionEventError> {
        let stream_id = self.stream_id();
        let snapshot = self.ensure_log_stream(stream_id)?;
        let delivery = snapshot
            .slot(self.slot)
            .and_then(|slot| slot.log_delivery())
            .ok_or(ExecutionEventError::InvalidEvent)?;
        if delivery.stream_id() != stream_id || delivery.end_of_stream().is_some() {
            return Err(ExecutionEventError::InvalidEvent);
        }
        let sequence = match delivery.produced_through() {
            Some(value) => value
                .checked_next()
                .map_err(|_| ExecutionEventError::InvalidEvent)?,
            None => LogSequence::new(0),
        };
        let frame = LogFrame::new(
            stream_id,
            self.attempt_id,
            sequence,
            self.clock.wall_now(),
            channel,
            payload.to_vec(),
            end_of_stream,
        )
        .map_err(|_| ExecutionEventError::InvalidEvent)?;
        let mut suffix = b"frame".to_vec();
        suffix.extend_from_slice(&sequence.get().to_be_bytes());
        let operation_id = self
            .ids
            .stable_operation_id(StableIdDomain::LogFrame, &self.stable_identity(&suffix));
        let message = RunnerToServer::LogBatch(LogBatch::new(
            MessageHeader::request(
                self.session.selected_protocol(),
                self.session.session_id(),
                operation_id,
            ),
            self.guard,
            vec![frame],
        ));
        let prepared = PreparedRequest::for_session(message, self.session, &self.limits)
            .map_err(|_| ExecutionEventError::InvalidEvent)?;
        let previous = self
            .spool
            .load(delivery.spool_content())
            .map_err(ExecutionEventError::Spool)?;
        let cumulative = append_record(&previous, prepared.canonical_bytes())
            .map_err(|_| ExecutionEventError::InvalidEvent)?;
        self.publish_log_cumulative(stream_id, sequence, end_of_stream, &cumulative)?;
        Ok(())
    }

    pub(crate) fn ensure_log_stream_closed(&self) -> Result<(), ExecutionEventError> {
        let _serial = self
            .serial
            .lock()
            .map_err(|_| ExecutionEventError::InvalidEvent)?;
        let stream_id = self.stream_id();
        let snapshot = self.ensure_log_stream(stream_id)?;
        let delivery = snapshot
            .slot(self.slot)
            .and_then(|slot| slot.log_delivery())
            .ok_or(ExecutionEventError::InvalidEvent)?;
        if delivery.stream_id() != stream_id {
            return Err(ExecutionEventError::InvalidEvent);
        }
        if delivery.end_of_stream().is_some() {
            return Ok(());
        }
        self.emit_log_serialized(LogChannel::System, &[], true)
    }
}

impl fmt::Debug for DurableExecutionEvents {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableExecutionEvents")
            .field("session_id", &self.session.session_id())
            .field("slot", &self.slot)
            .field("attempt_id", &self.attempt_id)
            .field("guard", &self.guard)
            .finish_non_exhaustive()
    }
}

impl ExecutionEvents for DurableExecutionEvents {
    fn transition(&self, next: JobLifecycle) -> Result<(), ExecutionEventError> {
        if next.is_terminal() {
            return Err(ExecutionEventError::InvalidEvent);
        }
        self.journal
            .transition_lifecycle(self.session.session_id(), self.slot, self.guard, next)
            .map(|_| ())
            .map_err(ExecutionEventError::Journal)
    }

    fn emit_log(&self, event: LogEvent) -> Result<(), ExecutionEventError> {
        let _serial = self
            .serial
            .lock()
            .map_err(|_| ExecutionEventError::InvalidEvent)?;
        self.emit_log_serialized(event.channel(), event.payload(), false)
    }

    fn begin_provider_operation(
        &self,
        kind: ProviderOperationKind,
    ) -> Result<OperationId, ExecutionEventError> {
        let _serial = self
            .serial
            .lock()
            .map_err(|_| ExecutionEventError::InvalidEvent)?;
        let snapshot = self
            .journal
            .snapshot()
            .map_err(ExecutionEventError::Journal)?;
        let slot = snapshot
            .slot(self.slot)
            .ok_or(ExecutionEventError::InvalidEvent)?;
        if let Some(existing) = slot.provider_operations().last().copied()
            && existing.is_pending()
        {
            return if existing.kind() == kind {
                Ok(existing.operation_id())
            } else {
                Err(ExecutionEventError::InvalidEvent)
            };
        }
        let operation_id = self.ids.fresh_operation_id();
        self.journal
            .record_provider_intent(
                self.session.session_id(),
                self.slot,
                self.guard,
                ProviderOperation::intent(operation_id, kind),
            )
            .map_err(ExecutionEventError::Journal)?;
        Ok(operation_id)
    }

    fn sandbox_created(
        &self,
        operation_id: OperationId,
        sandbox: SandboxIdentity,
    ) -> Result<(), ExecutionEventError> {
        self.journal
            .record_sandbox_created(
                self.session.session_id(),
                self.slot,
                self.guard,
                operation_id,
                sandbox,
            )
            .map(|_| ())
            .map_err(ExecutionEventError::Journal)
    }

    fn provider_operation_completed(
        &self,
        operation_id: OperationId,
    ) -> Result<(), ExecutionEventError> {
        self.journal
            .complete_provider_operation(
                self.session.session_id(),
                self.slot,
                self.guard,
                operation_id,
            )
            .map(|_| ())
            .map_err(ExecutionEventError::Journal)
    }

    fn provider_operation_failed(
        &self,
        operation_id: OperationId,
        failure: ProviderFailureOutcome,
    ) -> Result<(), ExecutionEventError> {
        self.journal
            .fail_provider_operation(
                self.session.session_id(),
                self.slot,
                self.guard,
                operation_id,
                failure,
            )
            .map(|_| ())
            .map_err(ExecutionEventError::Journal)
    }
}
