use std::{fmt, sync::Arc};

use automata_ci_core::{
    AttemptId, JobLifecycle, LeaseGuard, LogChannel, LogFrame, LogSequence, LogStreamId,
    OperationId,
};
use automata_ci_protocol::{
    LogBatch, MessageHeader, NegotiatedSession, ProtocolLimits, RunnerSlotOrdinal, RunnerToServer,
};
use automata_ci_runner_journal::{
    LogSegment, LogSegmentPublication, MAX_LOG_SEGMENT_FRAMES, ProviderFailureOutcome,
    ProviderOperation, ProviderOperationKind, RunnerJournal, SandboxIdentity,
};
use automata_ci_runner_spool::{ContentKind, DurableContentRef, DurableContentStore};
use automata_ci_runner_transport::PreparedRequest;

use crate::content::ContentOperationCoordinator;
use crate::outbox::{append_record, validate_log_segment_records};
use crate::{
    ExecutionEventError, ExecutionEvents, LogEvent, RuntimeClock, RuntimeIdSource, StableIdDomain,
};

#[derive(Clone)]
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
    serial: Arc<std::sync::Mutex<()>>,
}

struct LoadedLogTail {
    produced_through: Option<LogSequence>,
    open: Option<LogSegment>,
    bytes: Option<Vec<u8>>,
}

struct LogSegmentCandidate {
    stream_id: LogStreamId,
    previous: Option<DurableContentRef>,
    first_sequence: LogSequence,
    last_sequence: LogSequence,
    frame_count: u32,
    payload_bytes: u64,
    end_of_stream: bool,
    encoded: Vec<u8>,
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
            serial: Arc::new(std::sync::Mutex::new(())),
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

    fn stable_log_batch_id(
        &self,
        stream_id: LogStreamId,
        first: LogSequence,
        last: LogSequence,
    ) -> OperationId {
        let mut identity = self.stable_identity(b"");
        identity.extend_from_slice(stream_id.as_uuid().as_bytes());
        identity.extend_from_slice(&first.get().to_be_bytes());
        identity.extend_from_slice(&last.get().to_be_bytes());
        self.ids
            .stable_operation_id(StableIdDomain::LogBatch, &identity)
    }

    fn segment_fits_delivery_batch(
        &self,
        stream_id: LogStreamId,
        mut frames: Vec<LogFrame>,
        frame: &LogFrame,
    ) -> bool {
        let limits = self.limits;
        let payload_bytes = frames.iter().try_fold(0_usize, |total, existing| {
            total.checked_add(existing.payload().len())
        });
        let Some(payload_bytes) =
            payload_bytes.and_then(|total| total.checked_add(frame.payload().len()))
        else {
            return false;
        };
        if frames.len() >= limits.max_log_frames_per_batch()
            || frames.len() >= MAX_LOG_SEGMENT_FRAMES
            || payload_bytes > limits.max_log_payload_bytes_per_batch()
        {
            return false;
        }
        frames.push(frame.clone());
        let first = frames.first().map_or(frame.sequence(), LogFrame::sequence);
        let last = frame.sequence();
        let message = RunnerToServer::LogBatch(LogBatch::new(
            MessageHeader::request(
                self.session.selected_protocol(),
                self.session.session_id(),
                self.stable_log_batch_id(stream_id, first, last),
            ),
            self.guard,
            frames,
        ));
        PreparedRequest::for_session(message, self.session, &limits).is_ok()
    }

    fn publish_log_segment_once(
        &self,
        candidate: &LogSegmentCandidate,
    ) -> Result<automata_ci_runner_journal::JournalSnapshot, ExecutionEventError> {
        let publication = self
            .spool
            .persist(ContentKind::LogSpool, &candidate.encoded)
            .map_err(ExecutionEventError::Spool)?;
        let committed = publication.commit_with(|content| {
            let segment = LogSegment::new(
                candidate.first_sequence,
                candidate.last_sequence,
                candidate.frame_count,
                candidate.payload_bytes,
                content.clone(),
                candidate.end_of_stream,
                candidate.end_of_stream,
            )
            .map_err(automata_ci_runner_journal::JournalError::Invariant)?;
            let publication = LogSegmentPublication::new(
                candidate.stream_id,
                candidate.previous.clone(),
                segment,
            )
            .map_err(automata_ci_runner_journal::JournalError::Invariant)?;
            self.journal.record_log_segment(
                self.session.session_id(),
                self.slot,
                self.guard,
                publication,
                self.clock.wall_now(),
            )
        });
        match committed {
            Ok(snapshot) => {
                if let Some(previous) = candidate.previous.as_ref()
                    && !snapshot
                        .content_references()
                        .any(|content| content == previous)
                {
                    let _removed = self.spool.remove(previous);
                }
                Ok(snapshot)
            }
            Err(failure) => {
                let (error, publication) = failure.into_parts();
                publication.abort();
                Err(ExecutionEventError::Journal(error))
            }
        }
    }

    fn seal_open_segment(
        &self,
        stream_id: LogStreamId,
        content: DurableContentRef,
    ) -> Result<(), ExecutionEventError> {
        self.content_operations
            .run(|| {
                self.journal.seal_log_segment(
                    self.session.session_id(),
                    self.slot,
                    self.guard,
                    stream_id,
                    content,
                )
            })
            .map(|_| ())
            .map_err(ExecutionEventError::Journal)
    }

    fn load_open_log_tail(
        &self,
        stream_id: LogStreamId,
    ) -> Result<LoadedLogTail, ExecutionEventError> {
        self.content_operations.run(|| {
            let mut snapshot = self
                .journal
                .snapshot()
                .map_err(ExecutionEventError::Journal)?;
            if snapshot
                .slot(self.slot)
                .ok_or(ExecutionEventError::InvalidEvent)?
                .log_delivery()
                .is_none()
            {
                snapshot = self
                    .journal
                    .open_log_stream(self.session.session_id(), self.slot, self.guard, stream_id)
                    .map_err(ExecutionEventError::Journal)?;
            }
            let delivery = snapshot
                .slot(self.slot)
                .and_then(|slot| slot.log_delivery())
                .ok_or(ExecutionEventError::InvalidEvent)?;
            if delivery.stream_id() != stream_id || delivery.end_of_stream().is_some() {
                return Err(ExecutionEventError::InvalidEvent);
            }
            let open = delivery.open_segment().cloned();
            let bytes = open
                .as_ref()
                .map(|segment| self.spool.load(segment.content()))
                .transpose()
                .map_err(ExecutionEventError::Spool)?;
            Ok(LoadedLogTail {
                produced_through: delivery.produced_through(),
                open,
                bytes,
            })
        })
    }

    fn prepare_log_segment_candidate(
        &self,
        stream_id: LogStreamId,
        loaded: LoadedLogTail,
        frame: &LogFrame,
        prepared: &PreparedRequest,
    ) -> Result<Option<LogSegmentCandidate>, ExecutionEventError> {
        let (previous, first_sequence, frame_count, payload_bytes, encoded) = if let Some(segment) =
            loaded.open
        {
            let bytes = loaded.bytes.ok_or(ExecutionEventError::InvalidEvent)?;
            let frames = validate_log_segment_records(
                &bytes,
                &segment,
                self.session,
                self.guard,
                self.attempt_id,
                stream_id,
                &self.limits,
            )
            .map_err(|_| ExecutionEventError::InvalidEvent)?;
            if !self.segment_fits_delivery_batch(stream_id, frames, frame) {
                match self.seal_open_segment(stream_id, segment.content().clone()) {
                        Ok(())
                        | Err(ExecutionEventError::Journal(
                            automata_ci_runner_journal::JournalError::Invariant(
                                automata_ci_runner_journal::JournalInvariantError::LogSegmentMutationConflict,
                            ),
                        )) => return Ok(None),
                        Err(error) => return Err(error),
                    }
            }
            let encoded = append_record(&bytes, prepared.canonical_bytes())
                .map_err(|_| ExecutionEventError::InvalidEvent)?;
            (
                Some(segment.content().clone()),
                segment.first_sequence(),
                segment
                    .frame_count()
                    .checked_add(1)
                    .ok_or(ExecutionEventError::InvalidEvent)?,
                segment
                    .payload_bytes()
                    .checked_add(u64::try_from(frame.payload().len()).unwrap_or(u64::MAX))
                    .ok_or(ExecutionEventError::InvalidEvent)?,
                encoded,
            )
        } else {
            (
                None,
                frame.sequence(),
                1,
                u64::try_from(frame.payload().len())
                    .map_err(|_| ExecutionEventError::InvalidEvent)?,
                append_record(&[], prepared.canonical_bytes())
                    .map_err(|_| ExecutionEventError::InvalidEvent)?,
            )
        };
        Ok(Some(LogSegmentCandidate {
            stream_id,
            previous,
            first_sequence,
            last_sequence: frame.sequence(),
            frame_count,
            payload_bytes,
            end_of_stream: frame.is_end_of_stream(),
            encoded,
        }))
    }

    fn emit_log_serialized(
        &self,
        channel: LogChannel,
        payload: &[u8],
        end_of_stream: bool,
    ) -> Result<(), ExecutionEventError> {
        let stream_id = self.stream_id();
        loop {
            let loaded = self.load_open_log_tail(stream_id)?;
            let sequence = loaded.produced_through.map_or_else(
                || Ok(LogSequence::new(0)),
                |value| {
                    value
                        .checked_next()
                        .map_err(|_| ExecutionEventError::InvalidEvent)
                },
            )?;
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
                vec![frame.clone()],
            ));
            let prepared = PreparedRequest::for_session(message, self.session, &self.limits)
                .map_err(|_| ExecutionEventError::InvalidEvent)?;
            let Some(candidate) =
                self.prepare_log_segment_candidate(stream_id, loaded, &frame, &prepared)?
            else {
                continue;
            };
            let result = self.content_operations.publish_reclaiming_capacity(
                self.journal.as_ref(),
                self.spool.as_ref(),
                || self.publish_log_segment_once(&candidate),
            );
            match result {
                Ok(_) => return Ok(()),
                Err(ExecutionEventError::Journal(
                    automata_ci_runner_journal::JournalError::Invariant(
                        automata_ci_runner_journal::JournalInvariantError::LogSegmentMutationConflict,
                    ),
                )) => {}
                Err(error) => return Err(error),
            }
        }
    }

    fn emit_log_blocking(&self, event: &LogEvent) -> Result<(), ExecutionEventError> {
        let _serial = self
            .serial
            .lock()
            .map_err(|_| ExecutionEventError::InvalidEvent)?;
        self.emit_log_serialized(event.channel(), event.payload(), false)
    }

    pub(crate) fn ensure_log_stream_closed(&self) -> Result<(), ExecutionEventError> {
        let _serial = self
            .serial
            .lock()
            .map_err(|_| ExecutionEventError::InvalidEvent)?;
        let stream_id = self.stream_id();
        let snapshot = self
            .journal
            .snapshot()
            .map_err(ExecutionEventError::Journal)?;
        if let Some(delivery) = snapshot
            .slot(self.slot)
            .ok_or(ExecutionEventError::InvalidEvent)?
            .log_delivery()
        {
            if delivery.stream_id() != stream_id {
                return Err(ExecutionEventError::InvalidEvent);
            }
            if delivery.end_of_stream().is_some() {
                return Ok(());
            }
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
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return self.emit_log_blocking(&event);
        };
        // The callback is synchronous so executors know the frame is durable
        // before continuing, but protected file I/O and full-tail decoding do
        // not belong on a Tokio worker.
        let events = self.clone();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        drop(runtime.spawn_blocking(move || {
            drop(sender.send(events.emit_log_blocking(&event)));
        }));
        receiver
            .recv()
            .unwrap_or(Err(ExecutionEventError::InvalidEvent))
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
