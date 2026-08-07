use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use automata_core::{
    AttemptId, JobConclusion, JobIrEnvelope, JobIrVersionRange, JobLifecycle, JobResult,
    LeaseGuard, OperationId, RunnerSessionId, Sha256Digest, UnixMillis,
};
use automata_protocol::{
    CancelJob, CommandAck, ErrorMessage, HandshakeErrorCode, JobRuntimeAuthorities,
    LeaseDisposition, LeaseHeartbeat, LeaseOffer, LeaseRejectionReason, LeaseRequest,
    LeaseResponse, LogBatch, MessageHeader, NegotiatedSession, OperationAck, RemoteErrorCode,
    RunnerHello, RunnerSlotOrdinal, RunnerToServer, SUPPORTED_PROTOCOL_RANGE, ServerHello,
    ServerTiming, ServerToRunner, SessionResume,
};
use automata_protocol_protobuf::{
    decode_job_ir, decode_runner_frame, decode_runtime_authorities, encode_job_ir,
    encode_runtime_authorities,
};
use automata_runner_journal::{
    CancellationRecord, CommandDisposition, CommandIgnoredReason, DurableCommand, JobIrContentRef,
    JournalContentRetainSet, JournalInvariantError, LeaseOfferRecord, LeaseOfferStatus,
    LeasePollCheckpoint, RunnerJournal, RuntimeAuthorityContentRef,
    SessionBinding as JournalSessionBinding, SlotSnapshot, TerminalResultRecord,
};
use automata_runner_spool::{ContentKind, DurableContentStore};
use automata_runner_transport::PreparedRequest;
use sha2::{Digest as _, Sha256};
use tokio::{sync::Mutex as AsyncMutex, task::JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::warn;
use zeroize::Zeroizing;

use crate::content::ContentOperationCoordinator;
use crate::events::DurableExecutionEvents;
use crate::orphan::OrphanRecoveryCoordinator;
use crate::outbox::decode_records;
use crate::retry::{exchange_exact, sleep_or_shutdown};
use crate::{
    AdmissionRejection, CleanupRequest, ExecutionCancellation, ExecutionCancellationReason,
    ExecutionEvents, ExecutionRequest, ExecutorErrorKind, JobExecutor, LeaseWatchdog,
    MonotonicMillis, RemotePhase, RunnerRuntimeConfig, RunnerRuntimeControlClient,
    RunnerRuntimeError, RuntimeClock, RuntimeControlReply, RuntimeIdSource, RuntimeSleeper,
    StableIdDomain,
};

/// Dependency-injected boundaries used by [`RunnerSessionSupervisor`].
pub struct RunnerRuntimePorts {
    client: Arc<dyn RunnerRuntimeControlClient>,
    journal: Arc<dyn RunnerJournal>,
    spool: Arc<dyn DurableContentStore>,
    executor: Arc<dyn JobExecutor>,
    clock: Arc<dyn RuntimeClock>,
    sleeper: Arc<dyn RuntimeSleeper>,
    ids: Arc<dyn RuntimeIdSource>,
}

impl RunnerRuntimePorts {
    /// Binds transport, durable state, execution, time, and identity adapters.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client: Arc<dyn RunnerRuntimeControlClient>,
        journal: Arc<dyn RunnerJournal>,
        spool: Arc<dyn DurableContentStore>,
        executor: Arc<dyn JobExecutor>,
        clock: Arc<dyn RuntimeClock>,
        sleeper: Arc<dyn RuntimeSleeper>,
        ids: Arc<dyn RuntimeIdSource>,
    ) -> Self {
        Self {
            client,
            journal,
            spool,
            executor,
            clock,
            sleeper,
            ids,
        }
    }
}

impl fmt::Debug for RunnerRuntimePorts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunnerRuntimePorts")
            .field("client", &"configured")
            .field("journal", &"configured")
            .field("spool", &"configured")
            .field("executor", &"configured")
            .field("clock", &"configured")
            .field("sleeper", &"configured")
            .field("ids", &"configured")
            .finish()
    }
}

struct SupervisorInner {
    config: RunnerRuntimeConfig,
    ports: RunnerRuntimePorts,
    command_record_lock: AsyncMutex<()>,
    command_ack_receipt: AsyncMutex<Option<CommandAckReceipt>>,
    executions: Mutex<BTreeMap<AttemptId, ExecutionCancellation>>,
    content_operations: Arc<ContentOperationCoordinator>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CommandAckReceipt {
    session_id: RunnerSessionId,
    cursor: automata_protocol::CommandCursor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LeaseOfferRecordPlan {
    RecordNew,
    VerifyAppliedReplay,
    ReplayComplete,
}

impl fmt::Debug for SupervisorInner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SupervisorInner")
            .field("config", &self.config)
            .field("ports", &self.ports)
            .finish_non_exhaustive()
    }
}

/// Long-running crash-recoverable runner control-session supervisor.
#[derive(Clone)]
pub struct RunnerSessionSupervisor {
    inner: Arc<SupervisorInner>,
}

impl RunnerSessionSupervisor {
    /// Creates a supervisor without starting network or execution work.
    #[must_use]
    pub fn new(config: RunnerRuntimeConfig, ports: RunnerRuntimePorts) -> Self {
        Self {
            inner: Arc::new(SupervisorInner {
                config,
                ports,
                command_record_lock: AsyncMutex::new(()),
                command_ack_receipt: AsyncMutex::new(None),
                executions: Mutex::new(BTreeMap::new()),
                content_operations: Arc::new(ContentOperationCoordinator::default()),
            }),
        }
    }

    /// Runs sessions until shutdown or a non-recoverable invariant failure.
    ///
    /// Each advertised stable slot owns at most one long poll or execution.
    /// A stale session cancels every slot and negotiates again; locally
    /// recoverable old-session work is never silently discarded.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for durable-state corruption, unsupported
    /// protocol phases, executor violations, or terminal transport failures.
    pub async fn run(&self, shutdown: CancellationToken) -> Result<(), RunnerRuntimeError> {
        loop {
            if shutdown.is_cancelled() {
                return Ok(());
            }
            let session = match self.handshake(shutdown.clone()).await {
                Ok(session) => session,
                Err(RunnerRuntimeError::Shutdown) if shutdown.is_cancelled() => return Ok(()),
                Err(error) => return Err(error),
            };
            let session_cancel = shutdown.child_token();
            let mut slots = JoinSet::new();
            for ordinal in 1..=self.inner.config.capabilities().max_parallel_jobs() {
                let slot = RunnerSlotOrdinal::new(ordinal)
                    .map_err(|_| RunnerRuntimeError::ExecutorContract)?;
                let runtime = self.clone();
                let session_cancel = session_cancel.clone();
                slots.spawn(async move {
                    Box::pin(runtime.slot_loop(session, slot, session_cancel)).await
                });
            }

            let outcome = slots
                .join_next()
                .await
                .ok_or(RunnerRuntimeError::ExecutorContract)?;
            let reconnect = match outcome {
                Ok(Err(RunnerRuntimeError::StaleSession)) => true,
                Ok(Err(RunnerRuntimeError::Shutdown))
                    if shutdown.is_cancelled() || session_cancel.is_cancelled() =>
                {
                    false
                }
                Ok(Err(error)) => {
                    session_cancel.cancel();
                    while slots.join_next().await.is_some() {}
                    return Err(error);
                }
                Ok(Ok(())) | Err(_) => {
                    session_cancel.cancel();
                    while slots.join_next().await.is_some() {}
                    return Err(RunnerRuntimeError::ExecutorContract);
                }
            };
            session_cancel.cancel();
            while slots.join_next().await.is_some() {}
            if shutdown.is_cancelled() {
                return Ok(());
            }
            if !reconnect {
                return Err(RunnerRuntimeError::ExecutorContract);
            }
        }
    }

    async fn handshake(
        &self,
        cancellation: CancellationToken,
    ) -> Result<RuntimeSession, RunnerRuntimeError> {
        let orphan_recovery = OrphanRecoveryCoordinator::new(
            self.inner.config.capabilities().runner_id(),
            *self.inner.config.protocol_limits(),
            Arc::clone(&self.inner.ports.journal),
            Arc::clone(&self.inner.ports.spool),
            Arc::clone(&self.inner.ports.executor),
            Arc::clone(&self.inner.ports.clock),
            Arc::clone(&self.inner.ports.ids),
            Arc::clone(&self.inner.content_operations),
        );
        orphan_recovery
            .reconcile_authorized(cancellation.clone())
            .await?;
        let snapshot = self.inner.ports.journal.snapshot()?;
        if snapshot.runner_id() != self.inner.config.capabilities().runner_id() {
            return Err(RunnerRuntimeError::ExecutorContract);
        }
        let resume = snapshot
            .session()
            .map(|session| SessionResume::new(session.session_id(), session.command_cursor()));
        let (reply, mut local_wall_at_reply, hello_operation_id) =
            self.exchange_hello(resume, cancellation.clone()).await?;
        let server = match reply.message().message() {
            ServerToRunner::Hello(server) => server.clone(),
            ServerToRunner::HandshakeRejected(rejection)
                if rejection.code() == HandshakeErrorCode::SessionNotResumable =>
            {
                if !snapshot.slots().is_empty() {
                    let expected_session_id = resume
                        .ok_or(RunnerRuntimeError::OrphanRecoveryAuthorityInvalid)?
                        .session_id();
                    orphan_recovery.authorize_from_reply(
                        expected_session_id,
                        hello_operation_id,
                        &reply,
                    )?;
                    orphan_recovery
                        .reconcile_authorized(cancellation.clone())
                        .await?;
                    if !self.inner.ports.journal.snapshot()?.slots().is_empty() {
                        return Err(RunnerRuntimeError::RecoveryAuthorizationRequired);
                    }
                }
                let (fresh_reply, fresh_local_wall, _) =
                    self.exchange_hello(None, cancellation).await?;
                local_wall_at_reply = fresh_local_wall;
                match fresh_reply.message().message() {
                    ServerToRunner::Hello(server) => server.clone(),
                    ServerToRunner::HandshakeRejected(_) => {
                        return Err(RunnerRuntimeError::HandshakeRejected);
                    }
                    _ => return Err(RunnerRuntimeError::UnexpectedHandshakeResponse),
                }
            }
            ServerToRunner::HandshakeRejected(_) => {
                return Err(RunnerRuntimeError::HandshakeRejected);
            }
            _ => return Err(RunnerRuntimeError::UnexpectedHandshakeResponse),
        };
        let binding = JournalSessionBinding::new(
            server.session_id(),
            server.selected_protocol(),
            server.selected_job_ir(),
        );
        if snapshot.session().is_some_and(|legacy| {
            legacy.lease_poll_requires_fresh_session() && legacy.session_id() == server.session_id()
        }) {
            return Err(RunnerRuntimeError::RecoveryAuthorizationRequired);
        }
        let journal = match self.inner.ports.journal.begin_session(binding) {
            Ok(snapshot) => snapshot,
            Err(automata_runner_journal::JournalError::Invariant(
                JournalInvariantError::SessionHasActiveSlots,
            )) => return Err(RunnerRuntimeError::RecoveryAuthorizationRequired),
            Err(error) => return Err(error.into()),
        };
        let durable_session = journal
            .session()
            .ok_or(RunnerRuntimeError::UnexpectedHandshakeResponse)?;
        if durable_session.command_cursor() != server.command_cursor() {
            return Err(RunnerRuntimeError::UnexpectedHandshakeResponse);
        }
        self.inner.content_operations.run(|| {
            self.inner
                .ports
                .spool
                .reconcile(&JournalContentRetainSet::new(
                    self.inner.ports.journal.as_ref(),
                ))
        })?;
        *self.inner.command_ack_receipt.lock().await = server
            .command_cursor()
            .acknowledged_through()
            .map(|_| CommandAckReceipt {
                session_id: server.session_id(),
                cursor: server.command_cursor(),
            });
        Ok(RuntimeSession::new(&server, local_wall_at_reply))
    }

    async fn exchange_hello(
        &self,
        resume: Option<SessionResume>,
        cancellation: CancellationToken,
    ) -> Result<(RuntimeControlReply, UnixMillis, OperationId), RunnerRuntimeError> {
        let mut hello = RunnerHello::new(
            self.inner.ports.ids.fresh_operation_id(),
            SUPPORTED_PROTOCOL_RANGE,
            JobIrVersionRange::current(),
            self.inner.config.capabilities().clone(),
            self.inner.ports.clock.wall_now(),
        );
        if let Some(resume) = resume {
            hello = hello.with_resume(resume);
        }
        let operation_id = hello.operation_id();
        let prepared = PreparedRequest::handshake(hello, self.inner.config.protocol_limits())?;
        let reply = self.exchange(&prepared, cancellation).await?;
        Ok((reply, self.inner.ports.clock.wall_now(), operation_id))
    }

    async fn exchange(
        &self,
        prepared: &PreparedRequest,
        cancellation: CancellationToken,
    ) -> Result<RuntimeControlReply, RunnerRuntimeError> {
        exchange_exact(
            self.inner.ports.client.as_ref(),
            self.inner.ports.sleeper.as_ref(),
            self.inner.config.limits().retry(),
            prepared,
            cancellation,
        )
        .await
    }

    async fn slot_loop(
        &self,
        session: RuntimeSession,
        slot: RunnerSlotOrdinal,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        loop {
            if cancellation.is_cancelled() {
                return Err(RunnerRuntimeError::Shutdown);
            }
            let snapshot = self.inner.ports.journal.snapshot()?;
            let Some(durable) = snapshot.slot(slot).cloned() else {
                self.poll_slot(session, slot, cancellation.clone()).await?;
                continue;
            };
            let result = match durable.offer_status() {
                LeaseOfferStatus::Recorded => {
                    self.respond_to_recorded_offer(session, &durable, cancellation.clone())
                        .await
                }
                LeaseOfferStatus::Rejected => {
                    self.deliver_rejection(session, &durable, cancellation.clone())
                        .await
                }
                LeaseOfferStatus::Accepted if durable.lifecycle().is_terminal() => {
                    self.finish_terminal_slot(session, &durable, cancellation.clone())
                        .await
                }
                LeaseOfferStatus::Accepted => {
                    self.run_accepted_slot(session, &durable, cancellation.clone())
                        .await
                }
            };
            if matches!(result, Err(RunnerRuntimeError::LeaseExpired)) {
                return self.contain_expired_slot(session, slot, cancellation).await;
            }
            result?;
        }
    }

    async fn contain_expired_slot(
        &self,
        session: RuntimeSession,
        slot: RunnerSlotOrdinal,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        let snapshot = self.inner.ports.journal.snapshot()?;
        let durable = snapshot
            .slot(slot)
            .cloned()
            .ok_or(RunnerRuntimeError::ExecutorContract)?;
        warn!(
            stage = "lease_expired",
            runner_id = %self.inner.config.capabilities().runner_id(),
            session_id = %session.negotiated.session_id(),
            attempt_id = %durable.offer().lease().attempt_id(),
            slot = slot.get(),
            action = "isolated_pending_orphan_authority",
            "expired lease was isolated without terminating sibling slots"
        );
        if let Some(sandbox) = durable.sandbox().cloned()
            && let Err(_error) = self
                .cleanup_terminal_sandbox(session, &durable, sandbox, cancellation.clone())
                .await
        {
            warn!(
                stage = "lease_expired_cleanup",
                runner_id = %self.inner.config.capabilities().runner_id(),
                session_id = %session.negotiated.session_id(),
                attempt_id = %durable.offer().lease().attempt_id(),
                slot = slot.get(),
                error_kind = "cleanup_failed",
                "expired lease sandbox cleanup remains durably pending"
            );
        }
        cancellation.cancelled().await;
        Err(RunnerRuntimeError::Shutdown)
    }

    async fn poll_slot(
        &self,
        session: RuntimeSession,
        slot: RunnerSlotOrdinal,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        let (checkpoint, prepared) = self.prepare_lease_poll(session, slot)?;
        loop {
            let reply = self.exchange(&prepared, cancellation.clone()).await?;
            match reply.message().message() {
                ServerToRunner::NoWork(no_work) => {
                    self.advance_lease_poll(session, slot, checkpoint.current_operation_id())?;
                    let delay = Duration::from_millis(u64::from(no_work.retry_after_millis()))
                        .min(self.inner.config.limits().idle_delay_ceiling());
                    sleep_or_shutdown(&self.inner.ports.sleeper, delay, &cancellation).await?;
                    return Ok(());
                }
                ServerToRunner::LeaseOffer(_) | ServerToRunner::CancelJob(_) => {
                    self.process_command(session, &reply, cancellation.clone())
                        .await?;
                    self.advance_lease_poll(session, slot, checkpoint.current_operation_id())?;
                    self.flush_command_ack(session, cancellation.clone())
                        .await?;
                    return Ok(());
                }
                ServerToRunner::Error(error) => {
                    Self::handle_remote_error(error, RemotePhase::LeaseResponse)?;
                    self.remote_retry_delay(error, &cancellation).await?;
                }
                _ => return Err(RunnerRuntimeError::UnexpectedSyncResponse),
            }
        }
    }

    fn prepare_lease_poll(
        &self,
        session: RuntimeSession,
        slot: RunnerSlotOrdinal,
    ) -> Result<(LeasePollCheckpoint, PreparedRequest), RunnerRuntimeError> {
        let snapshot = self.inner.ports.journal.prepare_lease_poll(
            session.negotiated.session_id(),
            slot,
            self.inner.ports.ids.fresh_operation_id(),
        )?;
        let durable_session = snapshot.session().ok_or(RunnerRuntimeError::StaleSession)?;
        if durable_session.session_id() != session.negotiated.session_id() {
            return Err(RunnerRuntimeError::StaleSession);
        }
        let checkpoint = *durable_session
            .lease_poll_checkpoint(slot)
            .ok_or(RunnerRuntimeError::ExecutorContract)?;
        let header = Self::request_header(session, checkpoint.current_operation_id());
        let request = match checkpoint.acknowledges_operation_id() {
            Some(predecessor) => LeaseRequest::successor(header, slot, predecessor),
            None => LeaseRequest::first(header, slot),
        };
        let prepared = PreparedRequest::for_session(
            RunnerToServer::LeaseRequest(request),
            session.negotiated,
            self.inner.config.protocol_limits(),
        )?;
        Ok((checkpoint, prepared))
    }

    fn advance_lease_poll(
        &self,
        session: RuntimeSession,
        slot: RunnerSlotOrdinal,
        expected_current: OperationId,
    ) -> Result<(), RunnerRuntimeError> {
        self.inner.ports.journal.advance_lease_poll(
            session.negotiated.session_id(),
            slot,
            expected_current,
            self.inner.ports.ids.fresh_operation_id(),
        )?;
        Ok(())
    }

    async fn process_command(
        &self,
        session: RuntimeSession,
        reply: &RuntimeControlReply,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        let header = match reply.message().message() {
            ServerToRunner::LeaseOffer(offer) => offer.header(),
            ServerToRunner::CancelJob(cancel) => cancel.header(),
            _ => return Err(RunnerRuntimeError::UnexpectedSyncResponse),
        };
        self.await_command_turn(header.session_id(), header.sequence(), &cancellation)
            .await?;
        // Multiple slot exchanges can carry the same next command. Serialize
        // its semantic classification so a mutable slot cannot yield two
        // competing dispositions before either durable commit is visible.
        let _record_guard = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(RunnerRuntimeError::Shutdown),
            guard = self.inner.command_record_lock.lock() => guard,
        };
        match reply.message().message() {
            ServerToRunner::LeaseOffer(offer) => {
                // Durable commands are ordered per session and may be replayed
                // by any concurrent request. The signed offer is authoritative
                // for its stable slot; the request carrying it is not.
                self.record_lease_offer(session, offer, reply.canonical_bytes())?;
                Ok(())
            }
            ServerToRunner::CancelJob(cancel) => {
                self.record_cancellation(session, cancel, reply.canonical_bytes())
            }
            _ => Err(RunnerRuntimeError::UnexpectedSyncResponse),
        }
    }

    async fn await_command_turn(
        &self,
        session_id: RunnerSessionId,
        sequence: automata_protocol::CommandSequence,
        cancellation: &CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        loop {
            let snapshot = self.inner.ports.journal.snapshot()?;
            let durable = snapshot.session().ok_or(RunnerRuntimeError::StaleSession)?;
            if durable.session_id() != session_id {
                return Err(RunnerRuntimeError::StaleSession);
            }
            match durable.command_cursor().acknowledged_through() {
                Some(current) if sequence <= current => return Ok(()),
                Some(current) if current.checked_next().ok() == Some(sequence) => return Ok(()),
                None if sequence.get() == 1 => return Ok(()),
                _ => {
                    sleep_or_shutdown(
                        &self.inner.ports.sleeper,
                        self.inner.config.limits().command_gap_poll(),
                        cancellation,
                    )
                    .await?;
                }
            }
        }
    }

    fn record_lease_offer(
        &self,
        session: RuntimeSession,
        offer: &LeaseOffer,
        canonical: &[u8],
    ) -> Result<(), RunnerRuntimeError> {
        let header = offer.header();
        let command = durable_command(header, canonical);
        let record_plan =
            self.lease_offer_record_plan(header.session_id(), offer.slot(), command)?;
        if record_plan == LeaseOfferRecordPlan::ReplayComplete {
            return Ok(());
        }
        if offer.slot().get() > self.inner.config.capabilities().max_parallel_jobs() {
            self.inner.ports.journal.record_command_disposition(
                header.session_id(),
                command,
                CommandDisposition::Ignored(CommandIgnoredReason::InvalidCommand),
            )?;
            return Ok(());
        }
        let snapshot = self.inner.ports.journal.snapshot()?;
        if let Some(existing) = snapshot.slot(offer.slot())
            && existing.offer().command() != command
        {
            self.inner.ports.journal.record_command_disposition(
                header.session_id(),
                command,
                CommandDisposition::Ignored(CommandIgnoredReason::SlotUnavailable),
            )?;
            return Ok(());
        }
        let encoded_job = encode_job_ir(offer.job(), self.inner.config.protocol_limits())
            .map_err(|_| RunnerRuntimeError::InvalidDurablePayload)?;
        let authorities = offer
            .runtime_authorities()
            .ok_or(RunnerRuntimeError::InvalidDurablePayload)?;
        let encoded_authorities = Zeroizing::new(
            encode_runtime_authorities(
                authorities,
                offer.job(),
                offer.lease(),
                self.inner.config.protocol_limits(),
            )
            .map_err(|_| RunnerRuntimeError::InvalidDurablePayload)?,
        );
        let (durable, expected_job_ir, expected_authorities) = self.publish_lease_offer_content(
            session,
            offer,
            command,
            &encoded_job,
            &encoded_authorities,
        )?;
        // An active idempotent replay must still bind to these exact bytes. A
        // concurrently released applied replay has no remaining slot to bind.
        match durable.slot(offer.slot()) {
            Some(slot)
                if slot.offer().job_ir() == &expected_job_ir
                    && slot.offer().runtime_authorities() == &expected_authorities => {}
            None if record_plan == LeaseOfferRecordPlan::VerifyAppliedReplay => {}
            Some(_) | None => return Err(RunnerRuntimeError::CommandReplayConflict),
        }
        Ok(())
    }

    fn publish_lease_offer_content(
        &self,
        session: RuntimeSession,
        offer: &LeaseOffer,
        command: DurableCommand,
        encoded_job: &[u8],
        encoded_authorities: &[u8],
    ) -> Result<
        (
            automata_runner_journal::JournalSnapshot,
            JobIrContentRef,
            RuntimeAuthorityContentRef,
        ),
        RunnerRuntimeError,
    > {
        self.inner.content_operations.publish_reclaiming_capacity(
            self.inner.ports.journal.as_ref(),
            self.inner.ports.spool.as_ref(),
            || {
                let job_publication = self
                    .inner
                    .ports
                    .spool
                    .persist(ContentKind::JobIr, encoded_job)?;
                // Both protected objects are payload-first durable before one
                // journal mutation adopts their exact identities. Nested
                // publications retain both fences until that atomic semantic
                // commit succeeds.
                let committed = job_publication.commit_with(|job_content| {
                    let authority_publication = self
                        .inner
                        .ports
                        .spool
                        .persist(ContentKind::RuntimeAuthority, encoded_authorities)
                        .map_err(RunnerRuntimeError::Spool)?;
                    let authority_commit = authority_publication.commit_with(|authority_content| {
                        let job_ir = JobIrContentRef::new(
                            session.negotiated.selected_job_ir(),
                            job_content.clone(),
                        )
                        .map_err(automata_runner_journal::JournalError::Invariant)?;
                        let runtime_authorities =
                            RuntimeAuthorityContentRef::new(authority_content.clone())
                                .map_err(automata_runner_journal::JournalError::Invariant)?;
                        let record = LeaseOfferRecord::new(
                            offer.slot(),
                            offer.lease().clone(),
                            job_ir.clone(),
                            runtime_authorities.clone(),
                            command,
                        )
                        .map_err(automata_runner_journal::JournalError::Invariant)?;
                        self.inner
                            .ports
                            .journal
                            .record_lease_offer(offer.header().session_id(), record)
                            .map(|snapshot| (snapshot, job_ir, runtime_authorities))
                    });
                    match authority_commit {
                        Ok(committed) => Ok(committed),
                        Err(failure) => {
                            let (error, publication) = failure.into_parts();
                            publication.abort();
                            Err(RunnerRuntimeError::Journal(error))
                        }
                    }
                });
                match committed {
                    Ok(committed) => Ok(committed),
                    Err(failure) => {
                        let (error, publication) = failure.into_parts();
                        publication.abort();
                        Err(error)
                    }
                }
            },
        )
    }

    fn lease_offer_record_plan(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        command: DurableCommand,
    ) -> Result<LeaseOfferRecordPlan, RunnerRuntimeError> {
        match self.replayed_command_disposition(session_id, command)? {
            None => Ok(LeaseOfferRecordPlan::RecordNew),
            Some(CommandDisposition::Ignored(_)) => Ok(LeaseOfferRecordPlan::ReplayComplete),
            Some(CommandDisposition::Applied) => {
                let snapshot = self.inner.ports.journal.snapshot()?;
                if snapshot
                    .slot(slot)
                    .is_some_and(|durable| durable.offer().command() == command)
                {
                    Ok(LeaseOfferRecordPlan::VerifyAppliedReplay)
                } else {
                    Ok(LeaseOfferRecordPlan::ReplayComplete)
                }
            }
        }
    }

    fn record_cancellation(
        &self,
        _session: RuntimeSession,
        cancel: &CancelJob,
        canonical: &[u8],
    ) -> Result<(), RunnerRuntimeError> {
        let header = cancel.header();
        let command = durable_command(header, canonical);
        if self
            .replayed_command_disposition(header.session_id(), command)?
            .is_some()
        {
            return Ok(());
        }
        let snapshot = self.inner.ports.journal.snapshot()?;
        let target = snapshot.slots().iter().find(|slot| {
            slot.offer().lease().attempt_id() == cancel.attempt_id()
                && slot.offer().lease().guard() == cancel.guard()
                && !slot.lifecycle().is_terminal()
                && slot.offer_status() != LeaseOfferStatus::Rejected
        });
        let Some(target) = target else {
            self.inner.ports.journal.record_command_disposition(
                header.session_id(),
                command,
                CommandDisposition::Ignored(CommandIgnoredReason::StaleLease),
            )?;
            return Ok(());
        };
        let slot = target.slot();
        self.inner.ports.journal.record_cancellation(
            header.session_id(),
            slot,
            cancel.guard(),
            CancellationRecord::new(command, cancel.requested_at()),
        )?;
        if let Some(signal) = self
            .inner
            .executions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&cancel.attempt_id())
            .cloned()
        {
            signal.signal(ExecutionCancellationReason::ServerRequest);
        }
        Ok(())
    }

    fn replayed_command_disposition(
        &self,
        session_id: RunnerSessionId,
        command: DurableCommand,
    ) -> Result<Option<CommandDisposition>, RunnerRuntimeError> {
        let snapshot = self.inner.ports.journal.snapshot()?;
        let session = snapshot.session().ok_or(RunnerRuntimeError::StaleSession)?;
        if session.session_id() != session_id {
            return Err(RunnerRuntimeError::StaleSession);
        }
        let Some(cursor) = session.command_cursor().acknowledged_through() else {
            return Ok(None);
        };
        if command.sequence() > cursor {
            return Ok(None);
        }
        let tombstone = session
            .command_tombstones()
            .iter()
            .find(|tombstone| tombstone.command().sequence() == command.sequence())
            .ok_or_else(|| {
                RunnerRuntimeError::Journal(
                    JournalInvariantError::CommandReplayOutsideWindow.into(),
                )
            })?;
        if tombstone.command() != command {
            return Err(RunnerRuntimeError::CommandReplayConflict);
        }
        Ok(Some(tombstone.disposition()))
    }

    async fn flush_command_ack(
        &self,
        session: RuntimeSession,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        let mut receipt = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(RunnerRuntimeError::Shutdown),
            guard = self.inner.command_ack_receipt.lock() => guard,
        };
        'acknowledgement: loop {
            let snapshot = self.inner.ports.journal.snapshot()?;
            let durable = snapshot.session().ok_or(RunnerRuntimeError::StaleSession)?;
            let cursor = durable.command_cursor();
            let Some(sequence) = cursor.acknowledged_through() else {
                return Ok(());
            };
            if receipt.as_ref().is_some_and(|acknowledgement| {
                acknowledgement.session_id == session.negotiated.session_id()
                    && acknowledgement.cursor == cursor
            }) {
                return Ok(());
            }
            let mut identity = session
                .negotiated
                .session_id()
                .as_uuid()
                .as_bytes()
                .to_vec();
            identity.extend_from_slice(&sequence.get().to_be_bytes());
            let operation_id = self
                .inner
                .ports
                .ids
                .stable_operation_id(StableIdDomain::CommandAcknowledgement, &identity);
            let message = RunnerToServer::CommandAck(CommandAck::new(
                Self::request_header(session, operation_id),
                cursor,
            ));
            let prepared = PreparedRequest::for_session(
                message,
                session.negotiated,
                self.inner.config.protocol_limits(),
            )?;
            loop {
                let reply = self.exchange(&prepared, cancellation.clone()).await?;
                match reply.message().message() {
                    ServerToRunner::OperationAck(_) => {
                        *receipt = Some(CommandAckReceipt {
                            session_id: session.negotiated.session_id(),
                            cursor,
                        });
                        break;
                    }
                    ServerToRunner::LeaseOffer(_) | ServerToRunner::CancelJob(_) => {
                        self.process_command(session, &reply, cancellation.clone())
                            .await?;
                        // A correlated command reply is definitive: the
                        // control handler commits this cumulative ACK before
                        // selecting a same-session command for the response.
                        *receipt = Some(CommandAckReceipt {
                            session_id: session.negotiated.session_id(),
                            cursor,
                        });
                        // The response completes this exchange but may also
                        // advance the durable command cursor. Rebuild from the
                        // journal so a newly observed command is covered by a
                        // new cumulative ACK. An idempotent replay leaves the
                        // cursor covered by this successful exchange.
                        continue 'acknowledgement;
                    }
                    ServerToRunner::Error(error) => {
                        Self::handle_remote_error(error, RemotePhase::CommandAcknowledgement)?;
                        self.remote_retry_delay(error, &cancellation).await?;
                    }
                    _ => return Err(RunnerRuntimeError::UnexpectedSyncResponse),
                }
            }
            let newest = self.inner.ports.journal.snapshot()?;
            if newest
                .session()
                .is_some_and(|value| value.command_cursor() == cursor)
            {
                return Ok(());
            }
        }
    }

    async fn respond_to_recorded_offer(
        &self,
        session: RuntimeSession,
        durable: &SlotSnapshot,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        let job = self.load_job(durable)?;
        let runtime_authorities = self.load_runtime_authorities(durable, &job)?;
        let admission = if self.runtime_authorities_are_live(session, &runtime_authorities) {
            self.admit_exact_environment(&job)
        } else {
            Err(AdmissionRejection::InvalidJob)
        };
        match admission {
            Ok(_) => {
                self.inner.ports.journal.accept_lease(
                    session.negotiated.session_id(),
                    durable.slot(),
                    durable.offer().lease().guard(),
                )?;
                let accepted = self.inner.ports.journal.snapshot()?;
                let slot = accepted
                    .slot(durable.slot())
                    .ok_or(RunnerRuntimeError::ExecutorContract)?;
                self.ensure_acceptance_ack(session, slot, cancellation)
                    .await
            }
            Err(rejection) => {
                warn!(
                    stage = "admission",
                    runner_id = %self.inner.config.capabilities().runner_id(),
                    session_id = %session.negotiated.session_id(),
                    attempt_id = %durable.offer().lease().attempt_id(),
                    slot = durable.slot().get(),
                    rejection = ?rejection,
                    "job was rejected before lease acceptance"
                );
                self.reject_offer(session, durable, rejection.protocol_reason(), cancellation)
                    .await
            }
        }
    }

    async fn reject_offer(
        &self,
        session: RuntimeSession,
        durable: &SlotSnapshot,
        reason: LeaseRejectionReason,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        let operation_id = self.stable_lease_response_id(durable, StableIdDomain::LeaseRejection);
        let guard = durable.offer().lease().guard();
        self.inner.ports.journal.reject_lease(
            session.negotiated.session_id(),
            durable.slot(),
            guard,
            reason.clone(),
            operation_id,
        )?;
        let current = self.inner.ports.journal.snapshot()?;
        let rejected = current
            .slot(durable.slot())
            .ok_or(RunnerRuntimeError::ExecutorContract)?;
        self.deliver_rejection(session, rejected, cancellation)
            .await
    }

    async fn deliver_rejection(
        &self,
        session: RuntimeSession,
        durable: &SlotSnapshot,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        let rejection = durable
            .rejection()
            .ok_or(RunnerRuntimeError::ExecutorContract)?;
        let lease = durable.offer().lease();
        let operation_id = rejection.response_operation_id();
        let message = RunnerToServer::LeaseResponse(LeaseResponse::new(
            Self::request_header(session, operation_id),
            lease.attempt_id(),
            durable.slot(),
            lease.guard(),
            LeaseDisposition::Rejected(rejection.reason().clone()),
        ));
        let prepared = PreparedRequest::for_session(
            message,
            session.negotiated,
            self.inner.config.protocol_limits(),
        )?;
        self.send_until_operation_ack(session, &prepared, RemotePhase::LeaseResponse, cancellation)
            .await?;
        self.inner.ports.journal.acknowledge_lease_rejection(
            session.negotiated.session_id(),
            durable.slot(),
            lease.guard(),
            operation_id,
        )?;
        self.inner.ports.journal.release_rejected_lease(
            session.negotiated.session_id(),
            durable.slot(),
            lease.guard(),
            operation_id,
        )?;
        Ok(())
    }

    async fn ensure_acceptance_ack(
        &self,
        session: RuntimeSession,
        durable: &SlotSnapshot,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        let operation_id = self.stable_lease_response_id(durable, StableIdDomain::LeaseAcceptance);
        let lease = durable.offer().lease();
        let message = RunnerToServer::LeaseResponse(LeaseResponse::new(
            Self::request_header(session, operation_id),
            lease.attempt_id(),
            durable.slot(),
            lease.guard(),
            LeaseDisposition::Accepted,
        ));
        let prepared = PreparedRequest::for_session(
            message,
            session.negotiated,
            self.inner.config.protocol_limits(),
        )?;
        self.send_until_operation_ack(session, &prepared, RemotePhase::LeaseResponse, cancellation)
            .await?;
        let current = self.inner.ports.journal.snapshot()?;
        let slot = current
            .slot(durable.slot())
            .ok_or(RunnerRuntimeError::ExecutorContract)?;
        if slot.lifecycle() == JobLifecycle::Leased {
            self.inner.ports.journal.transition_lifecycle(
                session.negotiated.session_id(),
                durable.slot(),
                lease.guard(),
                JobLifecycle::Preparing,
            )?;
        }
        Ok(())
    }

    async fn send_until_operation_ack(
        &self,
        session: RuntimeSession,
        prepared: &PreparedRequest,
        phase: RemotePhase,
        cancellation: CancellationToken,
    ) -> Result<OperationAck, RunnerRuntimeError> {
        loop {
            let reply = self.exchange(prepared, cancellation.clone()).await?;
            match reply.message().message() {
                ServerToRunner::OperationAck(ack) => return Ok(*ack),
                ServerToRunner::LeaseOffer(_) | ServerToRunner::CancelJob(_) => {
                    self.process_command(session, &reply, cancellation.clone())
                        .await?;
                    self.flush_command_ack(session, cancellation.clone())
                        .await?;
                }
                ServerToRunner::Error(error) => {
                    Self::handle_remote_error(error, phase)?;
                    self.remote_retry_delay(error, &cancellation).await?;
                }
                _ => return Err(RunnerRuntimeError::UnexpectedSyncResponse),
            }
        }
    }

    fn stable_lease_response_id(
        &self,
        durable: &SlotSnapshot,
        domain: StableIdDomain,
    ) -> OperationId {
        let lease = durable.offer().lease();
        let mut identity = durable
            .offer()
            .command()
            .operation_id()
            .as_uuid()
            .as_bytes()
            .to_vec();
        identity.extend_from_slice(lease.lease_id().as_uuid().as_bytes());
        identity.extend_from_slice(&lease.fencing_token().get().to_be_bytes());
        self.inner.ports.ids.stable_operation_id(domain, &identity)
    }

    fn load_job(&self, durable: &SlotSnapshot) -> Result<JobIrEnvelope, RunnerRuntimeError> {
        let content = durable.offer().job_ir().content();
        let encoded = self.inner.ports.spool.load(content)?;
        if encoded.len() != usize::try_from(content.size()).unwrap_or(usize::MAX) {
            return Err(RunnerRuntimeError::InvalidDurablePayload);
        }
        let job = decode_job_ir(&encoded, self.inner.config.protocol_limits())
            .map_err(|_| RunnerRuntimeError::InvalidDurablePayload)?;
        if job.version() != durable.offer().job_ir().version() {
            return Err(RunnerRuntimeError::InvalidDurablePayload);
        }
        Ok(job)
    }

    fn load_runtime_authorities(
        &self,
        durable: &SlotSnapshot,
        job: &JobIrEnvelope,
    ) -> Result<JobRuntimeAuthorities, RunnerRuntimeError> {
        let content = durable.offer().runtime_authorities().content();
        let encoded = Zeroizing::new(self.inner.ports.spool.load(content)?);
        if encoded.len() != usize::try_from(content.size()).unwrap_or(usize::MAX) {
            return Err(RunnerRuntimeError::InvalidDurablePayload);
        }
        decode_runtime_authorities(
            &encoded,
            job,
            durable.offer().lease(),
            self.inner.config.protocol_limits(),
        )
        .map_err(|_| RunnerRuntimeError::InvalidDurablePayload)
    }

    fn runtime_authorities_are_live(
        &self,
        session: RuntimeSession,
        authorities: &JobRuntimeAuthorities,
    ) -> bool {
        let now = session.estimated_server_now(self.inner.ports.clock.wall_now());
        authorities
            .as_slice()
            .iter()
            .all(|authority| authority.issued_at() <= now && now < authority.expires_at())
    }

    fn admit_exact_environment(
        &self,
        job: &JobIrEnvelope,
    ) -> Result<automata_execution::SandboxEnvironment, AdmissionRejection> {
        let admission = self.inner.ports.executor.admit(job)?;
        let selected = admission.environment();
        let required = job
            .job()
            .requirements()
            .environment_profile()
            .ok_or(AdmissionRejection::InvalidJob)?;
        if selected.attestation() != required
            || !self
                .inner
                .config
                .capabilities()
                .environment_profiles()
                .contains(selected.attestation())
        {
            return Err(AdmissionRejection::CapabilityChanged);
        }
        Ok(selected.clone())
    }

    fn request_header(session: RuntimeSession, operation_id: OperationId) -> MessageHeader {
        MessageHeader::request(
            session.negotiated.selected_protocol(),
            session.negotiated.session_id(),
            operation_id,
        )
    }

    fn handle_remote_error(
        error: &ErrorMessage,
        phase: RemotePhase,
    ) -> Result<(), RunnerRuntimeError> {
        match error.code() {
            RemoteErrorCode::SessionNotFound | RemoteErrorCode::StaleSession => {
                Err(RunnerRuntimeError::StaleSession)
            }
            RemoteErrorCode::InvalidMessage
            | RemoteErrorCode::UnsupportedProtocol
            | RemoteErrorCode::UnsupportedJobIr
                if !error.is_retryable() =>
            {
                Err(RunnerRuntimeError::UnsupportedRemotePhase(phase))
            }
            code if !error.is_retryable() => Err(RunnerRuntimeError::Remote(code)),
            _ => Ok(()),
        }
    }

    async fn remote_retry_delay(
        &self,
        _error: &ErrorMessage,
        cancellation: &CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        sleep_or_shutdown(
            &self.inner.ports.sleeper,
            self.inner.config.limits().retry().delay_after(1),
            cancellation,
        )
        .await
    }
}

impl RunnerSessionSupervisor {
    #[allow(clippy::too_many_lines)]
    async fn run_accepted_slot(
        &self,
        session: RuntimeSession,
        durable: &SlotSnapshot,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        // Replaying this deterministic operation is safe and closes the one
        // acceptance-ack ambiguity left by a process crash at any lifecycle.
        self.ensure_acceptance_ack(session, durable, cancellation.clone())
            .await?;
        let snapshot = self.inner.ports.journal.snapshot()?;
        let durable = snapshot
            .slot(durable.slot())
            .cloned()
            .ok_or(RunnerRuntimeError::ExecutorContract)?;
        if durable.lifecycle().is_terminal() {
            return self
                .finish_terminal_slot(session, &durable, cancellation)
                .await;
        }
        if !matches!(
            durable.lifecycle(),
            JobLifecycle::Preparing
                | JobLifecycle::Running
                | JobLifecycle::Cancelling
                | JobLifecycle::Finalizing
        ) {
            return Err(RunnerRuntimeError::UnsupportedRecoveryPhase);
        }
        let job = self.load_job(&durable)?;
        let runtime_authorities = self.load_runtime_authorities(&durable, &job)?;
        if !self.runtime_authorities_are_live(session, &runtime_authorities) {
            let conclusion = if durable.cancellation().is_some() {
                JobConclusion::Cancelled
            } else {
                JobConclusion::Failure
            };
            warn!(
                stage = "runtime_authority",
                runner_id = %self.inner.config.capabilities().runner_id(),
                session_id = %session.negotiated.session_id(),
                attempt_id = %durable.offer().lease().attempt_id(),
                slot = durable.slot().get(),
                error_kind = "expired",
                terminal_conclusion = ?conclusion,
                "accepted job authority expired before execution"
            );
            let result = JobResult::new(
                durable.offer().lease().attempt_id(),
                conclusion,
                self.inner.ports.clock.wall_now(),
            );
            self.commit_terminal_result(
                session,
                durable.slot(),
                durable.offer().lease().guard(),
                result,
            )?;
            let snapshot = self.inner.ports.journal.snapshot()?;
            let terminal = snapshot
                .slot(durable.slot())
                .cloned()
                .ok_or(RunnerRuntimeError::ExecutorContract)?;
            return self
                .finish_terminal_slot(session, &terminal, cancellation)
                .await;
        }
        let environment = self
            .admit_exact_environment(&job)
            .map_err(|_| RunnerRuntimeError::EnvironmentAttestationMismatch)?;
        let lease = durable.offer().lease().clone();
        let events: Arc<dyn ExecutionEvents> = Arc::new(DurableExecutionEvents::new(
            Arc::clone(&self.inner.ports.journal),
            Arc::clone(&self.inner.ports.spool),
            Arc::clone(&self.inner.ports.ids),
            Arc::clone(&self.inner.ports.clock),
            session.negotiated,
            durable.slot(),
            lease.attempt_id(),
            lease.guard(),
            *self.inner.config.protocol_limits(),
            Arc::clone(&self.inner.content_operations),
        ));
        let signal = ExecutionCancellation::new();
        if durable.cancellation().is_some() {
            signal.signal(ExecutionCancellationReason::ServerRequest);
        }
        {
            let mut executions = self
                .inner
                .executions
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if executions
                .insert(lease.attempt_id(), signal.clone())
                .is_some()
            {
                return Err(RunnerRuntimeError::ExecutorContract);
            }
        }

        let watchdog = Arc::new(LeaseWatchdog::new(
            self.local_lease_deadline(session, durable.expires_at()),
        ));
        let watchdog_stop = CancellationToken::new();
        let lease_expired = CancellationToken::new();
        let watchdog_task = self.spawn_watchdog(
            Arc::clone(&watchdog),
            lease_expired.clone(),
            watchdog_stop.clone(),
        );
        let request = ExecutionRequest::new(
            session.negotiated.session_id(),
            durable.slot(),
            lease.clone(),
            job,
            runtime_authorities,
            durable.offer().job_ir().content().clone(),
            environment,
            durable.lifecycle(),
            durable.sandbox().cloned(),
        );
        let executor = Arc::clone(&self.inner.ports.executor);
        let executor_events = Arc::clone(&events);
        let executor_signal = signal.clone();
        let mut execution = tokio::spawn(async move {
            executor
                .execute(request, executor_events, executor_signal)
                .await
        });

        let heartbeat_interval =
            Duration::from_millis(u64::from(session.timing.heartbeat_interval_millis()));
        let mut heartbeat_schedule = HeartbeatSchedule::new(
            self.inner.ports.clock.monotonic_now(),
            heartbeat_interval,
            watchdog.deadline(),
        );
        let outcome = loop {
            let control_cycle = self.maintain_active_control_slice(
                session,
                durable.slot(),
                lease.guard(),
                Arc::clone(&watchdog),
                &mut heartbeat_schedule,
                cancellation.clone(),
            );
            tokio::pin!(control_cycle);
            let execution_cancelled = signal.token();
            tokio::select! {
                biased;
                joined = &mut execution => {
                    break executor_join_result(joined);
                }
                () = cancellation.cancelled() => {
                    signal.signal(ExecutionCancellationReason::Shutdown);
                    break self.await_cancelled_executor(&mut execution).await;
                }
                () = execution_cancelled.cancelled() => {
                    break self.await_cancelled_executor(&mut execution).await;
                }
                () = lease_expired.cancelled() => {
                    signal.signal(ExecutionCancellationReason::LeaseExpired);
                    break self.await_cancelled_executor(&mut execution).await;
                }
                control_result = &mut control_cycle => {
                    if let Err(error) = control_result {
                        signal.signal(if matches!(error, RunnerRuntimeError::StaleSession) {
                            ExecutionCancellationReason::SessionLost
                        } else {
                            ExecutionCancellationReason::Shutdown
                        });
                        let _ = self.await_cancelled_executor(&mut execution).await;
                        watchdog_stop.cancel();
                        let _ = watchdog_task.await;
                        self.unregister_execution(lease.attempt_id());
                        return Err(error);
                    }
                }
            }
        };
        self.unregister_execution(lease.attempt_id());
        let cancellation_reason = signal.reason();
        match cancellation_reason {
            Some(ExecutionCancellationReason::LeaseExpired) => {
                watchdog_stop.cancel();
                let _ = watchdog_task.await;
                return Err(RunnerRuntimeError::LeaseExpired);
            }
            Some(ExecutionCancellationReason::SessionLost) => {
                watchdog_stop.cancel();
                let _ = watchdog_task.await;
                return Err(RunnerRuntimeError::StaleSession);
            }
            Some(ExecutionCancellationReason::Shutdown) => {
                watchdog_stop.cancel();
                let _ = watchdog_task.await;
                return Err(RunnerRuntimeError::Shutdown);
            }
            Some(ExecutionCancellationReason::ServerRequest) | None => {}
        }
        let result = outcome.unwrap_or_else(|failure| {
            self.executor_failure_result(
                session,
                &durable,
                failure,
                cancellation_reason
                    .is_some_and(|reason| reason == ExecutionCancellationReason::ServerRequest),
            )
        });
        let finished = async {
            let finalization_lifecycle = self.finalization_heartbeat_lifecycle(durable.slot())?;
            self.commit_terminal_result(session, durable.slot(), lease.guard(), result)?;
            let terminal = self.inner.ports.journal.snapshot()?;
            let terminal = terminal
                .slot(durable.slot())
                .cloned()
                .ok_or(RunnerRuntimeError::ExecutorContract)?;
            self.finish_terminal_slot_maintained(
                session,
                &terminal,
                Arc::clone(&watchdog),
                lease_expired,
                finalization_lifecycle,
                cancellation,
            )
            .await
        }
        .await;
        watchdog_stop.cancel();
        let _ = watchdog_task.await;
        finished
    }

    fn unregister_execution(&self, attempt_id: AttemptId) {
        self.inner
            .executions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&attempt_id);
    }

    async fn await_cancelled_executor(
        &self,
        execution: &mut tokio::task::JoinHandle<Result<JobResult, crate::ExecutorError>>,
    ) -> Result<JobResult, ExecutorFailure> {
        let grace_cancel = CancellationToken::new();
        let grace = self.inner.ports.sleeper.sleep(
            self.inner.config.limits().cancellation_grace(),
            grace_cancel,
        );
        tokio::select! {
            biased;
            joined = &mut *execution => executor_join_result(joined),
            () = grace => {
                execution.abort();
                Err(ExecutorFailure::CancellationTimeout)
            }
        }
    }

    fn executor_failure_result(
        &self,
        session: RuntimeSession,
        durable: &SlotSnapshot,
        failure: ExecutorFailure,
        server_cancelled: bool,
    ) -> JobResult {
        let conclusion = failure.conclusion(server_cancelled);
        warn!(
            stage = "execution",
            runner_id = %self.inner.config.capabilities().runner_id(),
            session_id = %session.negotiated.session_id(),
            attempt_id = %durable.offer().lease().attempt_id(),
            slot = durable.slot().get(),
            lifecycle = ?durable.lifecycle(),
            error_kind = failure.code(),
            terminal_conclusion = ?conclusion,
            "job executor failure was isolated to its leased attempt"
        );
        JobResult::new(
            durable.offer().lease().attempt_id(),
            conclusion,
            self.inner.ports.clock.wall_now(),
        )
    }

    fn spawn_watchdog(
        &self,
        watchdog: Arc<LeaseWatchdog>,
        expired: CancellationToken,
        stop: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        let clock = Arc::clone(&self.inner.ports.clock);
        let sleeper = Arc::clone(&self.inner.ports.sleeper);
        let resolution = self.inner.config.limits().watchdog_resolution();
        tokio::spawn(async move {
            loop {
                if stop.is_cancelled() {
                    return;
                }
                let now = clock.monotonic_now();
                if watchdog.is_expired_at(now) {
                    expired.cancel();
                    return;
                }
                let remaining = now.remaining_until(watchdog.deadline());
                sleeper.sleep(remaining.min(resolution), stop.clone()).await;
            }
        })
    }

    fn local_lease_deadline(
        &self,
        session: RuntimeSession,
        remote_expiry: UnixMillis,
    ) -> MonotonicMillis {
        let remote_now = session.estimated_server_now(self.inner.ports.clock.wall_now());
        let remaining_millis = remote_expiry.get().saturating_sub(remote_now.get()).max(0);
        let remaining = Duration::from_millis(
            u64::try_from(remaining_millis)
                .unwrap_or(0)
                .min(u64::from(session.timing.lease_duration_millis())),
        );
        self.inner
            .ports
            .clock
            .monotonic_now()
            .saturating_add(remaining)
    }

    async fn maintain_active_control_slice(
        &self,
        session: RuntimeSession,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        watchdog: Arc<LeaseWatchdog>,
        heartbeat_schedule: &mut HeartbeatSchedule,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        // Keep one exact log delivery alive while its independent heartbeat
        // deadline advances. A retrying or stalled HTTP/2 stream therefore
        // cannot withhold renewal, while a healthy backlog receives only one
        // bounded batch before the execution/cancellation branches are polled
        // again by the caller.
        let log_flush = self.flush_log_batch(session, slot, guard, cancellation.clone());
        tokio::pin!(log_flush);
        let mut log_caught_up = false;

        loop {
            heartbeat_schedule
                .cap_to_lease(self.inner.ports.clock.monotonic_now(), watchdog.deadline());
            let heartbeat_delay =
                heartbeat_schedule.remaining_from(self.inner.ports.clock.monotonic_now());
            let heartbeat_due =
                sleep_or_shutdown(&self.inner.ports.sleeper, heartbeat_delay, &cancellation);
            tokio::pin!(heartbeat_due);

            tokio::select! {
                biased;
                due = &mut heartbeat_due => {
                    due?;
                    self.heartbeat_once(
                        session,
                        slot,
                        guard,
                        Arc::clone(&watchdog),
                        None,
                        cancellation.clone(),
                    )
                    .await?;
                    heartbeat_schedule.renewed(
                        self.inner.ports.clock.monotonic_now(),
                        watchdog.deadline(),
                    );
                    if log_caught_up {
                        return Ok(());
                    }
                }
                status = &mut log_flush, if !log_caught_up => {
                    match status? {
                        LogFlushStatus::CaughtUp => log_caught_up = true,
                        LogFlushStatus::MorePending => {
                            tokio::task::yield_now().await;
                            return Ok(());
                        }
                    }
                }
            }
        }
    }

    async fn heartbeat_once(
        &self,
        session: RuntimeSession,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        watchdog: Arc<LeaseWatchdog>,
        reported_lifecycle: Option<JobLifecycle>,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        let snapshot = self.inner.ports.journal.snapshot()?;
        let durable = snapshot
            .slot(slot)
            .ok_or(RunnerRuntimeError::ExecutorContract)?;
        let lifecycle = reported_lifecycle.unwrap_or_else(|| durable.lifecycle());
        if lifecycle.is_terminal() {
            return Ok(());
        }
        let heartbeat = LeaseHeartbeat::new(
            Self::request_header(session, self.inner.ports.ids.fresh_operation_id()),
            durable.offer().lease().attempt_id(),
            guard,
            lifecycle,
            self.inner.ports.clock.wall_now(),
        );
        let prepared = PreparedRequest::for_session(
            RunnerToServer::Heartbeat(heartbeat.clone()),
            session.negotiated,
            self.inner.config.protocol_limits(),
        )?;
        loop {
            let reply = self.exchange(&prepared, cancellation.clone()).await?;
            match reply.message().message() {
                ServerToRunner::LeaseRenewal(renewal) => {
                    renewal
                        .validate_for(&heartbeat)
                        .map_err(|_| RunnerRuntimeError::UnexpectedSyncResponse)?;
                    self.inner.ports.journal.renew_lease(
                        session.negotiated.session_id(),
                        slot,
                        guard,
                        renewal.expires_at(),
                    )?;
                    watchdog.extend_to(self.local_lease_deadline(session, renewal.expires_at()));
                    return Ok(());
                }
                ServerToRunner::LeaseOffer(_) | ServerToRunner::CancelJob(_) => {
                    self.process_command(session, &reply, cancellation.clone())
                        .await?;
                    self.flush_command_ack(session, cancellation.clone())
                        .await?;
                }
                ServerToRunner::Error(error) => {
                    Self::handle_remote_error(error, RemotePhase::LeaseHeartbeat)?;
                    self.remote_retry_delay(error, &cancellation).await?;
                }
                _ => return Err(RunnerRuntimeError::UnexpectedSyncResponse),
            }
        }
    }

    async fn flush_log_batch(
        &self,
        session: RuntimeSession,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        cancellation: CancellationToken,
    ) -> Result<LogFlushStatus, RunnerRuntimeError> {
        let Some(delivery) = self.prepare_log_batch(session, slot, guard)? else {
            return Ok(LogFlushStatus::CaughtUp);
        };
        loop {
            let reply = self
                .exchange(&delivery.prepared, cancellation.clone())
                .await?;
            match reply.message().message() {
                ServerToRunner::LogAck(ack) => {
                    if ack.ack().stream_id() != delivery.stream_id
                        || ack.ack().contiguous_through() != Some(delivery.delivered_through)
                    {
                        return Err(RunnerRuntimeError::UnexpectedSyncResponse);
                    }
                    self.inner.ports.journal.acknowledge_log(
                        session.negotiated.session_id(),
                        slot,
                        guard,
                        delivery.stream_id,
                        delivery.delivered_through,
                    )?;
                    return if Some(delivery.delivered_through) == delivery.produced_through {
                        Ok(LogFlushStatus::CaughtUp)
                    } else {
                        Ok(LogFlushStatus::MorePending)
                    };
                }
                ServerToRunner::LeaseOffer(_) | ServerToRunner::CancelJob(_) => {
                    self.process_command(session, &reply, cancellation.clone())
                        .await?;
                    self.flush_command_ack(session, cancellation.clone())
                        .await?;
                }
                ServerToRunner::Error(error) => {
                    Self::handle_remote_error(error, RemotePhase::LogDelivery)?;
                    self.remote_retry_delay(error, &cancellation).await?;
                }
                _ => return Err(RunnerRuntimeError::UnexpectedSyncResponse),
            }
        }
    }

    fn load_pending_log_batch(
        &self,
        session: RuntimeSession,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
    ) -> Result<Option<PendingLogBatch>, RunnerRuntimeError> {
        let snapshot = self.inner.ports.journal.snapshot()?;
        let durable = snapshot
            .slot(slot)
            .ok_or(RunnerRuntimeError::ExecutorContract)?;
        let Some(delivery) = durable.log_delivery() else {
            return Ok(None);
        };
        let bytes = self.inner.ports.spool.load(delivery.spool_content())?;
        let records = decode_records(&bytes, self.inner.config.protocol_limits())?;
        let acknowledged = delivery.acknowledged_through();
        let mut frames: Vec<automata_core::LogFrame> = Vec::new();
        let mut payload_bytes = 0_usize;
        for record in records {
            let RunnerToServer::LogBatch(batch) = &record.message else {
                return Err(RunnerRuntimeError::InvalidDurablePayload);
            };
            let [frame] = batch.frames() else {
                return Err(RunnerRuntimeError::InvalidDurablePayload);
            };
            if batch.guard() != guard
                || frame.stream_id() != delivery.stream_id()
                || frame.attempt_id() != durable.offer().lease().attempt_id()
            {
                return Err(RunnerRuntimeError::RecoveryIdentityMismatch {
                    attempt_id: durable.offer().lease().attempt_id(),
                    guard,
                    session_id: session.negotiated.session_id(),
                    slot,
                });
            }
            let original = PreparedRequest::for_session(
                record.message.clone(),
                session.negotiated,
                self.inner.config.protocol_limits(),
            )?;
            if original.canonical_bytes().as_ref() != record.canonical_bytes {
                return Err(RunnerRuntimeError::InvalidDurablePayload);
            }
            if acknowledged.is_some_and(|value| frame.sequence() <= value) {
                continue;
            }
            if let Some(previous) = frames.last()
                && previous
                    .sequence()
                    .checked_next()
                    .map_err(|_| RunnerRuntimeError::InvalidDurablePayload)?
                    != frame.sequence()
            {
                return Err(RunnerRuntimeError::InvalidDurablePayload);
            }
            let next_payload_bytes = payload_bytes
                .checked_add(frame.payload().len())
                .ok_or(RunnerRuntimeError::InvalidDurablePayload)?;
            let limits = self.inner.config.protocol_limits();
            if !frames.is_empty()
                && (frames.len() == limits.max_log_frames_per_batch()
                    || next_payload_bytes > limits.max_log_payload_bytes_per_batch())
            {
                break;
            }
            payload_bytes = next_payload_bytes;
            frames.push(frame.clone());
        }
        if frames.is_empty() {
            return if acknowledged == delivery.produced_through() {
                Ok(None)
            } else {
                Err(RunnerRuntimeError::InvalidDurablePayload)
            };
        }
        Ok(Some(PendingLogBatch {
            attempt_id: durable.offer().lease().attempt_id(),
            stream_id: delivery.stream_id(),
            produced_through: delivery.produced_through(),
            frames,
        }))
    }

    fn prepare_log_batch(
        &self,
        session: RuntimeSession,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
    ) -> Result<Option<PreparedLogBatch>, RunnerRuntimeError> {
        let Some(mut pending) = self.load_pending_log_batch(session, slot, guard)? else {
            return Ok(None);
        };
        // The payload and collection budgets normally make the initial batch
        // fit. A deliberately tight complete-frame ceiling can still require
        // trimming protocol overhead; one original frame is always valid.
        let (prepared, delivered_through) = loop {
            let first = pending
                .frames
                .first()
                .ok_or(RunnerRuntimeError::InvalidDurablePayload)?
                .sequence();
            let last = pending
                .frames
                .last()
                .ok_or(RunnerRuntimeError::InvalidDurablePayload)?
                .sequence();
            let operation_id = self.stable_log_batch_id(
                session,
                pending.attempt_id,
                guard,
                pending.stream_id,
                first,
                last,
            );
            let message = RunnerToServer::LogBatch(LogBatch::new(
                Self::request_header(session, operation_id),
                guard,
                pending.frames.clone(),
            ));
            match PreparedRequest::for_session(
                message,
                session.negotiated,
                self.inner.config.protocol_limits(),
            ) {
                Ok(prepared) => break (prepared, last),
                Err(_error) if pending.frames.len() > 1 => {
                    pending.frames.pop();
                }
                Err(error) => return Err(error.into()),
            }
        };
        Ok(Some(PreparedLogBatch {
            prepared,
            stream_id: pending.stream_id,
            delivered_through,
            produced_through: pending.produced_through,
        }))
    }

    fn stable_log_batch_id(
        &self,
        session: RuntimeSession,
        attempt_id: AttemptId,
        guard: LeaseGuard,
        stream_id: automata_core::LogStreamId,
        first: automata_core::LogSequence,
        last: automata_core::LogSequence,
    ) -> OperationId {
        let mut identity = Vec::with_capacity(16 * 4 + 8 * 3);
        identity.extend_from_slice(session.negotiated.session_id().as_uuid().as_bytes());
        identity.extend_from_slice(attempt_id.as_uuid().as_bytes());
        identity.extend_from_slice(guard.lease_id().as_uuid().as_bytes());
        identity.extend_from_slice(&guard.fencing_token().get().to_be_bytes());
        identity.extend_from_slice(stream_id.as_uuid().as_bytes());
        identity.extend_from_slice(&first.get().to_be_bytes());
        identity.extend_from_slice(&last.get().to_be_bytes());
        self.inner
            .ports
            .ids
            .stable_operation_id(StableIdDomain::LogBatch, &identity)
    }

    fn commit_terminal_result(
        &self,
        session: RuntimeSession,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        result: JobResult,
    ) -> Result<(), RunnerRuntimeError> {
        result
            .validate()
            .map_err(|_| RunnerRuntimeError::ExecutorContract)?;
        let snapshot = self.inner.ports.journal.snapshot()?;
        let durable = snapshot
            .slot(slot)
            .ok_or(RunnerRuntimeError::ExecutorContract)?;
        if result.attempt_id() != durable.offer().lease().attempt_id() {
            return Err(RunnerRuntimeError::ExecutorContract);
        }
        // An executor can fail or resolve a job-level condition before the
        // sandbox reaches Running. Preparing may terminate directly as Failed,
        // TimedOut, or Skipped; forcing it through Finalizing would invent
        // execution progress that never happened.
        match durable.lifecycle() {
            JobLifecycle::Running | JobLifecycle::Cancelling => {
                self.inner.ports.journal.transition_lifecycle(
                    session.negotiated.session_id(),
                    slot,
                    guard,
                    JobLifecycle::Finalizing,
                )?;
            }
            JobLifecycle::Preparing | JobLifecycle::Finalizing => {}
            _ => return Err(RunnerRuntimeError::ExecutorContract),
        }
        let terminal = terminal_lifecycle(result.conclusion());
        let operation_id = self.inner.ports.ids.fresh_operation_id();
        let message = RunnerToServer::JobResult(automata_protocol::JobResultMessage::new(
            Self::request_header(session, operation_id),
            guard,
            result,
        ));
        let prepared = PreparedRequest::for_session(
            message,
            session.negotiated,
            self.inner.config.protocol_limits(),
        )?;
        self.inner.content_operations.publish_reclaiming_capacity(
            self.inner.ports.journal.as_ref(),
            self.inner.ports.spool.as_ref(),
            || {
                let publication = self
                    .inner
                    .ports
                    .spool
                    .persist(ContentKind::TerminalResult, prepared.canonical_bytes())?;
                let committed = publication.commit_with(|content| {
                    let record = TerminalResultRecord::new(operation_id, content.clone())
                        .map_err(automata_runner_journal::JournalError::Invariant)?;
                    self.inner.ports.journal.record_terminal_result(
                        session.negotiated.session_id(),
                        slot,
                        guard,
                        terminal,
                        record,
                    )
                });
                match committed {
                    Ok(_) => Ok(()),
                    Err(failure) => {
                        let (error, publication) = failure.into_parts();
                        publication.abort();
                        Err(error.into())
                    }
                }
            },
        )
    }

    async fn finish_terminal_slot(
        &self,
        session: RuntimeSession,
        durable: &SlotSnapshot,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        if durable
            .terminal_result()
            .is_some_and(TerminalResultRecord::is_acknowledged)
        {
            return self
                .finish_terminal_slot_delivery(session, durable, cancellation)
                .await;
        }
        let watchdog = Arc::new(LeaseWatchdog::new(
            self.local_lease_deadline(session, durable.expires_at()),
        ));
        if watchdog.is_expired_at(self.inner.ports.clock.monotonic_now()) {
            return Err(RunnerRuntimeError::LeaseExpired);
        }
        let lease_expired = CancellationToken::new();
        let watchdog_stop = CancellationToken::new();
        let watchdog_task = self.spawn_watchdog(
            Arc::clone(&watchdog),
            lease_expired.clone(),
            watchdog_stop.clone(),
        );
        let result = self
            .finish_terminal_slot_maintained(
                session,
                durable,
                watchdog,
                lease_expired,
                Self::recovered_finalization_lifecycle(durable),
                cancellation,
            )
            .await;
        watchdog_stop.cancel();
        let _ = watchdog_task.await;
        result
    }

    async fn finish_terminal_slot_maintained(
        &self,
        session: RuntimeSession,
        durable: &SlotSnapshot,
        watchdog: Arc<LeaseWatchdog>,
        lease_expired: CancellationToken,
        reported_lifecycle: JobLifecycle,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        let delivery = self.finish_terminal_slot_delivery(session, durable, cancellation.clone());
        tokio::pin!(delivery);
        let heartbeat_interval =
            Duration::from_millis(u64::from(session.timing.heartbeat_interval_millis()));
        let mut heartbeat_schedule = HeartbeatSchedule::new(
            self.inner.ports.clock.monotonic_now(),
            heartbeat_interval,
            watchdog.deadline(),
        );
        loop {
            heartbeat_schedule
                .cap_to_lease(self.inner.ports.clock.monotonic_now(), watchdog.deadline());
            let heartbeat_delay =
                heartbeat_schedule.remaining_from(self.inner.ports.clock.monotonic_now());
            let heartbeat = async {
                sleep_or_shutdown(&self.inner.ports.sleeper, heartbeat_delay, &cancellation)
                    .await?;
                self.heartbeat_once(
                    session,
                    durable.slot(),
                    durable.offer().lease().guard(),
                    Arc::clone(&watchdog),
                    Some(reported_lifecycle),
                    cancellation.clone(),
                )
                .await
            };
            tokio::pin!(heartbeat);
            tokio::select! {
                biased;
                result = &mut delivery => return result,
                () = cancellation.cancelled() => return Err(RunnerRuntimeError::Shutdown),
                () = lease_expired.cancelled() => return Err(RunnerRuntimeError::LeaseExpired),
                result = &mut heartbeat => {
                    result?;
                    heartbeat_schedule.renewed(
                        self.inner.ports.clock.monotonic_now(),
                        watchdog.deadline(),
                    );
                },
            }
        }
    }

    async fn finish_terminal_slot_delivery(
        &self,
        session: RuntimeSession,
        durable: &SlotSnapshot,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        let slot = durable.slot();
        let guard = durable.offer().lease().guard();
        self.flush_terminal_log_backlog(session, slot, guard, cancellation.clone())
            .await?;
        let snapshot = self.inner.ports.journal.snapshot()?;
        let mut current = snapshot
            .slot(slot)
            .cloned()
            .ok_or(RunnerRuntimeError::ExecutorContract)?;
        if current.sandbox().is_some() {
            self.reconcile_terminal_sandbox(session, slot, guard, cancellation.clone())
                .await?;
            self.flush_terminal_log_backlog(session, slot, guard, cancellation.clone())
                .await?;
            current = self
                .inner
                .ports
                .journal
                .snapshot()?
                .slot(slot)
                .cloned()
                .ok_or(RunnerRuntimeError::ExecutorContract)?;
        }
        self.ensure_terminal_log_stream_closed(session, &current)
            .await?;
        self.drain_terminal_logs(session, slot, guard, cancellation.clone())
            .await?;
        current = self
            .inner
            .ports
            .journal
            .snapshot()?
            .slot(slot)
            .cloned()
            .ok_or(RunnerRuntimeError::ExecutorContract)?;
        self.deliver_terminal_result(session, &current, cancellation.clone())
            .await?;
        self.inner
            .ports
            .journal
            .release_slot(session.negotiated.session_id(), slot, guard)?;
        self.inner.content_operations.run(|| {
            self.inner
                .ports
                .spool
                .reconcile(&JournalContentRetainSet::new(
                    self.inner.ports.journal.as_ref(),
                ))
        })?;
        Ok(())
    }

    async fn reconcile_terminal_sandbox(
        &self,
        session: RuntimeSession,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        let policy = self.inner.config.limits().retry();
        let mut consecutive_failures = 0_u64;
        loop {
            let snapshot = self.inner.ports.journal.snapshot()?;
            let current = snapshot
                .slot(slot)
                .cloned()
                .ok_or(RunnerRuntimeError::ExecutorContract)?;
            if current.offer().lease().guard() != guard {
                return Err(RunnerRuntimeError::RecoveryIdentityMismatch {
                    attempt_id: current.offer().lease().attempt_id(),
                    guard,
                    session_id: session.negotiated.session_id(),
                    slot,
                });
            }
            let Some(sandbox) = current.sandbox().cloned() else {
                return Ok(());
            };
            match self
                .cleanup_terminal_sandbox(session, &current, sandbox, cancellation.clone())
                .await
            {
                Ok(()) => return Ok(()),
                Err(RunnerRuntimeError::Executor(error)) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    let ramp_step = u16::try_from(consecutive_failures)
                        .unwrap_or(u16::MAX)
                        .min(policy.maximum_attempts());
                    let delay = policy.delay_after(ramp_step);
                    let pending_operation = self
                        .inner
                        .ports
                        .journal
                        .snapshot()?
                        .slot(slot)
                        .and_then(|durable| durable.provider_operations().last())
                        .filter(|operation| operation.is_pending())
                        .map(|operation| operation.operation_id());
                    warn!(
                        stage = "terminal_cleanup",
                        runner_id = %self.inner.config.capabilities().runner_id(),
                        session_id = %session.negotiated.session_id(),
                        attempt_id = %current.offer().lease().attempt_id(),
                        slot = slot.get(),
                        error_kind = ?error.kind(),
                        ?pending_operation,
                        retry_delay_millis = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                        "terminal sandbox cleanup remains durably parked for exact retry"
                    );
                    sleep_or_shutdown(&self.inner.ports.sleeper, delay, &cancellation).await?;
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn ensure_terminal_log_stream_closed(
        &self,
        session: RuntimeSession,
        durable: &SlotSnapshot,
    ) -> Result<(), RunnerRuntimeError> {
        let lease = durable.offer().lease();
        let events = DurableExecutionEvents::new(
            Arc::clone(&self.inner.ports.journal),
            Arc::clone(&self.inner.ports.spool),
            Arc::clone(&self.inner.ports.ids),
            Arc::clone(&self.inner.ports.clock),
            session.negotiated,
            durable.slot(),
            lease.attempt_id(),
            lease.guard(),
            *self.inner.config.protocol_limits(),
            Arc::clone(&self.inner.content_operations),
        );
        tokio::task::spawn_blocking(move || events.ensure_log_stream_closed())
            .await
            .map_err(|_| {
                RunnerRuntimeError::ExecutionEvent(crate::ExecutionEventError::InvalidEvent)
            })??;
        Ok(())
    }

    async fn flush_terminal_log_backlog(
        &self,
        session: RuntimeSession,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        loop {
            if self
                .flush_log_batch(session, slot, guard, cancellation.clone())
                .await?
                == LogFlushStatus::CaughtUp
            {
                return Ok(());
            }
        }
    }

    async fn drain_terminal_logs(
        &self,
        session: RuntimeSession,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        self.flush_terminal_log_backlog(session, slot, guard, cancellation)
            .await?;
        let snapshot = self.inner.ports.journal.snapshot()?;
        let current = snapshot
            .slot(slot)
            .ok_or(RunnerRuntimeError::ExecutorContract)?;
        if current
            .log_delivery()
            .is_some_and(|delivery| !delivery.is_fully_delivered())
        {
            return Err(RunnerRuntimeError::ExecutorContract);
        }
        Ok(())
    }

    fn finalization_heartbeat_lifecycle(
        &self,
        slot: RunnerSlotOrdinal,
    ) -> Result<JobLifecycle, RunnerRuntimeError> {
        let lifecycle = self
            .inner
            .ports
            .journal
            .snapshot()?
            .slot(slot)
            .ok_or(RunnerRuntimeError::ExecutorContract)?
            .lifecycle();
        match lifecycle {
            JobLifecycle::Running | JobLifecycle::Cancelling | JobLifecycle::Finalizing => {
                Ok(JobLifecycle::Finalizing)
            }
            JobLifecycle::Preparing => Ok(JobLifecycle::Preparing),
            _ => Err(RunnerRuntimeError::ExecutorContract),
        }
    }

    fn recovered_finalization_lifecycle(durable: &SlotSnapshot) -> JobLifecycle {
        match durable.lifecycle() {
            JobLifecycle::Failed | JobLifecycle::TimedOut
                if durable.sandbox().is_none() && durable.log_delivery().is_none() =>
            {
                JobLifecycle::Preparing
            }
            _ => JobLifecycle::Finalizing,
        }
    }

    async fn deliver_terminal_result(
        &self,
        session: RuntimeSession,
        durable: &SlotSnapshot,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        let terminal = durable
            .terminal_result()
            .ok_or(RunnerRuntimeError::ExecutorContract)?;
        if terminal.is_acknowledged() {
            return Ok(());
        }
        let encoded = self.inner.ports.spool.load(terminal.content())?;
        let decoded = decode_runner_frame(&encoded, self.inner.config.protocol_limits())
            .map_err(|_| RunnerRuntimeError::InvalidDurablePayload)?;
        let message = decoded.into_message();
        let RunnerToServer::JobResult(result) = &message else {
            return Err(RunnerRuntimeError::InvalidDurablePayload);
        };
        if result.header().operation_id() != terminal.operation_id()
            || result.guard() != durable.offer().lease().guard()
            || result.result().attempt_id() != durable.offer().lease().attempt_id()
        {
            return Err(RunnerRuntimeError::RecoveryIdentityMismatch {
                attempt_id: durable.offer().lease().attempt_id(),
                guard: durable.offer().lease().guard(),
                session_id: session.negotiated.session_id(),
                slot: durable.slot(),
            });
        }
        let prepared = PreparedRequest::for_session(
            message,
            session.negotiated,
            self.inner.config.protocol_limits(),
        )?;
        if prepared.canonical_bytes().as_ref() != encoded {
            return Err(RunnerRuntimeError::InvalidDurablePayload);
        }
        self.send_until_operation_ack(
            session,
            &prepared,
            RemotePhase::TerminalResult,
            cancellation,
        )
        .await?;
        self.inner.ports.journal.acknowledge_terminal_result(
            session.negotiated.session_id(),
            durable.slot(),
            durable.offer().lease().guard(),
            terminal.operation_id(),
        )?;
        Ok(())
    }

    async fn cleanup_terminal_sandbox(
        &self,
        session: RuntimeSession,
        durable: &SlotSnapshot,
        sandbox: automata_runner_journal::SandboxIdentity,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        let lease = durable.offer().lease();
        let events: Arc<dyn ExecutionEvents> = Arc::new(DurableExecutionEvents::new(
            Arc::clone(&self.inner.ports.journal),
            Arc::clone(&self.inner.ports.spool),
            Arc::clone(&self.inner.ports.ids),
            Arc::clone(&self.inner.ports.clock),
            session.negotiated,
            durable.slot(),
            lease.attempt_id(),
            lease.guard(),
            *self.inner.config.protocol_limits(),
            Arc::clone(&self.inner.content_operations),
        ));
        let signal = ExecutionCancellation::new();
        let request = CleanupRequest::new(
            session.negotiated.session_id(),
            durable.slot(),
            lease.attempt_id(),
            lease.guard(),
            sandbox,
        );
        let executor = Arc::clone(&self.inner.ports.executor);
        let task_signal = signal.clone();
        let mut cleanup = CleanupTask {
            task: tokio::spawn(async move { executor.cleanup(request, events, task_signal).await }),
            signal,
        };
        tokio::select! {
            result = &mut cleanup.task => match result {
                Ok(result) => result.map_err(RunnerRuntimeError::Executor)?,
                Err(_) => {
                    return Err(RunnerRuntimeError::Executor(crate::ExecutorError::new(
                        ExecutorErrorKind::Internal,
                    )));
                }
            },
            () = cancellation.cancelled() => {
                return Err(RunnerRuntimeError::Shutdown);
            }
        }
        if self
            .inner
            .ports
            .journal
            .snapshot()?
            .slot(durable.slot())
            .is_some_and(|slot| slot.sandbox().is_some())
        {
            return Err(RunnerRuntimeError::ExecutorContract);
        }
        Ok(())
    }
}

struct CleanupTask {
    task: tokio::task::JoinHandle<Result<(), crate::ExecutorError>>,
    signal: ExecutionCancellation,
}

impl Drop for CleanupTask {
    fn drop(&mut self) {
        self.signal.signal(ExecutionCancellationReason::Shutdown);
        self.task.abort();
    }
}

impl fmt::Debug for RunnerSessionSupervisor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunnerSessionSupervisor")
            .field("config", &self.inner.config)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LogFlushStatus {
    CaughtUp,
    MorePending,
}

#[derive(Clone, Copy, Debug)]
struct HeartbeatSchedule {
    interval: Duration,
    due_at: MonotonicMillis,
}

impl HeartbeatSchedule {
    fn new(now: MonotonicMillis, interval: Duration, lease_deadline: MonotonicMillis) -> Self {
        let mut schedule = Self {
            interval,
            due_at: now.saturating_add(interval),
        };
        schedule.cap_to_lease(now, lease_deadline);
        schedule
    }

    fn remaining_from(self, now: MonotonicMillis) -> Duration {
        now.remaining_until(self.due_at)
    }

    fn renewed(&mut self, now: MonotonicMillis, lease_deadline: MonotonicMillis) {
        self.due_at = now.saturating_add(self.interval);
        self.cap_to_lease(now, lease_deadline);
    }

    fn cap_to_lease(&mut self, now: MonotonicMillis, lease_deadline: MonotonicMillis) {
        let interval_millis = u64::try_from(self.interval.as_millis()).unwrap_or(u64::MAX);
        let latest_safe = MonotonicMillis::new(
            lease_deadline
                .get()
                .saturating_sub(interval_millis)
                .max(now.get()),
        );
        if self.due_at > latest_safe {
            self.due_at = latest_safe;
        }
    }
}

struct PendingLogBatch {
    attempt_id: AttemptId,
    stream_id: automata_core::LogStreamId,
    produced_through: Option<automata_core::LogSequence>,
    frames: Vec<automata_core::LogFrame>,
}

struct PreparedLogBatch {
    prepared: PreparedRequest,
    stream_id: automata_core::LogStreamId,
    delivered_through: automata_core::LogSequence,
    produced_through: Option<automata_core::LogSequence>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutorFailure {
    Adapter(ExecutorErrorKind),
    TaskTerminated,
    CancellationTimeout,
}

impl ExecutorFailure {
    const fn code(self) -> &'static str {
        match self {
            Self::Adapter(ExecutorErrorKind::InvalidJob) => "invalid_job",
            Self::Adapter(ExecutorErrorKind::Unsupported) => "unsupported",
            Self::Adapter(ExecutorErrorKind::ResourceExhausted) => "resource_exhausted",
            Self::Adapter(ExecutorErrorKind::PermissionDenied) => "permission_denied",
            Self::Adapter(ExecutorErrorKind::Unavailable) => "unavailable",
            Self::Adapter(ExecutorErrorKind::TimedOut) => "timed_out",
            Self::Adapter(ExecutorErrorKind::Cancelled) => "cancelled",
            Self::Adapter(ExecutorErrorKind::Internal) => "internal",
            Self::TaskTerminated => "task_terminated",
            Self::CancellationTimeout => "cancellation_timeout",
        }
    }

    const fn conclusion(self, server_cancelled: bool) -> JobConclusion {
        if server_cancelled {
            return JobConclusion::Cancelled;
        }
        match self {
            Self::Adapter(ExecutorErrorKind::TimedOut) => JobConclusion::TimedOut,
            Self::Adapter(
                ExecutorErrorKind::InvalidJob
                | ExecutorErrorKind::Unsupported
                | ExecutorErrorKind::ResourceExhausted
                | ExecutorErrorKind::PermissionDenied
                | ExecutorErrorKind::Unavailable
                | ExecutorErrorKind::Cancelled
                | ExecutorErrorKind::Internal,
            )
            | Self::TaskTerminated
            | Self::CancellationTimeout => JobConclusion::Failure,
        }
    }
}

fn executor_join_result(
    joined: Result<Result<JobResult, crate::ExecutorError>, tokio::task::JoinError>,
) -> Result<JobResult, ExecutorFailure> {
    match joined {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(error)) => Err(ExecutorFailure::Adapter(error.kind())),
        Err(_) => Err(ExecutorFailure::TaskTerminated),
    }
}

#[derive(Clone, Copy, Debug)]
struct RuntimeSession {
    negotiated: NegotiatedSession,
    timing: ServerTiming,
    server_wall_offset_millis: i64,
}

impl RuntimeSession {
    fn new(server: &ServerHello, local_wall: UnixMillis) -> Self {
        Self {
            negotiated: server.session(),
            timing: server.timing(),
            server_wall_offset_millis: server.server_time().get().saturating_sub(local_wall.get()),
        }
    }

    fn estimated_server_now(self, local_wall: UnixMillis) -> UnixMillis {
        UnixMillis::new(
            local_wall
                .get()
                .saturating_add(self.server_wall_offset_millis),
        )
    }
}

fn durable_command(
    header: automata_protocol::ServerCommandHeader,
    canonical: &[u8],
) -> DurableCommand {
    let digest: [u8; 32] = Sha256::digest(canonical).into();
    DurableCommand::new(
        header.sequence(),
        header.operation_id(),
        Sha256Digest::from_bytes(digest),
    )
}

const fn terminal_lifecycle(conclusion: JobConclusion) -> JobLifecycle {
    match conclusion {
        JobConclusion::Success => JobLifecycle::Succeeded,
        JobConclusion::Failure => JobLifecycle::Failed,
        JobConclusion::Cancelled => JobLifecycle::Cancelled,
        JobConclusion::TimedOut => JobLifecycle::TimedOut,
        JobConclusion::Skipped => JobLifecycle::Skipped,
    }
}
