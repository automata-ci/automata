use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use automata_ci_core::{
    AttemptId, JobAuthorityProfile, JobConclusion, JobIrEnvelope, JobIrVersionRange, JobLifecycle,
    JobResult, JobSecretExposure, Lease, LeaseGuard, OperationId, RunnerSessionId, Sha256Digest,
    UnixMillis,
};
use automata_ci_protocol::{
    CancelJob, CommandAck, ErrorMessage, HandshakeErrorCode, INITIAL_RUNTIME_AUTHORITY_GENERATION,
    JobRuntimeAuthorities, LeaseDisposition, LeaseHeartbeat, LeaseOffer, LeaseRejectionReason,
    LeaseRequest, LeaseResponse, LogBatch, MessageHeader, NegotiatedSession, OperationAck,
    RemoteErrorCode, RunnerHello, RunnerSlotOrdinal, RunnerToServer, RuntimeAuthorityAck,
    RuntimeAuthorityDeliveryBinding, RuntimeAuthorityRequest, SUPPORTED_PROTOCOL_RANGE,
    ServerHello, ServerTiming, ServerToRunner, SessionDisposition, SessionResume,
};
use automata_ci_protocol_protobuf::{
    decode_job_ir, decode_runner_frame, decode_runtime_authorities, encode_job_ir,
    encode_runtime_authorities,
};
use automata_ci_runner_journal::{
    CancellationRecord, CommandDisposition, CommandIgnoredReason, DurableCommand, JobIrContentRef,
    JournalContentRetainSet, JournalInvariantError, LeaseOfferRecord, LeaseOfferStatus,
    LeasePollCheckpoint, LogSegmentAcknowledgement, ProviderOperationKind, RunnerJournal,
    RuntimeAuthorityContentRef, RuntimeAuthorityDeliveryRecord,
    SessionBinding as JournalSessionBinding, SlotSnapshot, TerminalResultRecord,
};
use automata_ci_runner_spool::{ContentKind, DurableContentStore};
use automata_ci_runner_transport::PreparedRequest;
use sha2::{Digest as _, Sha256};
use tokio::{sync::Mutex as AsyncMutex, task::JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::content::ContentOperationCoordinator;
use crate::events::DurableExecutionEvents;
use crate::orphan::OrphanRecoveryCoordinator;
use crate::outbox::validate_log_segment_records;
use crate::retry::{exchange_exact, sleep_or_shutdown};
use crate::{
    AdmissionRejection, CleanupRequest, ExecutionCancellation, ExecutionCancellationReason,
    ExecutionEvents, ExecutionRequest, ExecutorErrorKind, JobExecutor, LeaseWatchdog,
    MonotonicMillis, NoopRunnerRuntimeObserver, RemotePhase, RunnerRuntimeConfig,
    RunnerRuntimeControlClient, RunnerRuntimeError, RunnerRuntimeEvent, RunnerRuntimeObserver,
    RuntimeCancellationReason, RuntimeClock, RuntimeCommandKind, RuntimeCommandOutcome,
    RuntimeControlReply, RuntimeExchangeKind, RuntimeIdSource, RuntimeInfrastructureFailure,
    RuntimeJobConclusion, RuntimeJobStartMode, RuntimeLeaseDisposition, RuntimeLeasePollOutcome,
    RuntimeOperationOutcome, RuntimeReconnectReason, RuntimeRemoteErrorDisposition,
    RuntimeRemoteErrorKind, RuntimeRetryCause, RuntimeSessionMode, RuntimeSessionOutcome,
    RuntimeSleeper, RuntimeTerminalResultStage, StableIdDomain,
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
    observer: Arc<dyn RunnerRuntimeObserver>,
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
            observer: Arc::new(NoopRunnerRuntimeObserver),
        }
    }

    /// Installs an infallible observer for closed semantic runtime events.
    #[must_use]
    pub fn with_observer(mut self, observer: Arc<dyn RunnerRuntimeObserver>) -> Self {
        self.observer = observer;
        self
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
            .field("observer", &"configured")
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
    cursor: automata_ci_protocol::CommandCursor,
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

    fn observe(&self, event: RunnerRuntimeEvent) {
        self.inner.ports.observer.observe(event);
    }

    fn elapsed_since(&self, started: MonotonicMillis) -> Duration {
        Duration::from_millis(
            self.inner
                .ports
                .clock
                .monotonic_now()
                .get()
                .saturating_sub(started.get()),
        )
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

            self.observe(RunnerRuntimeEvent::SessionConnected {
                server_clock_offset_millis: session.server_wall_offset_millis,
            });
            let Some(outcome) = slots.join_next().await else {
                self.observe(RunnerRuntimeEvent::SessionDisconnected);
                return Err(RunnerRuntimeError::ExecutorContract);
            };
            self.observe(RunnerRuntimeEvent::SessionDisconnected);
            let reconnect = match outcome {
                Ok(Err(RunnerRuntimeError::StaleSession)) => {
                    self.observe(RunnerRuntimeEvent::Reconnect {
                        reason: RuntimeReconnectReason::StaleSession,
                    });
                    true
                }
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
        self.reconcile_orphans(&orphan_recovery, cancellation.clone())
            .await?;
        let snapshot = self.inner.ports.journal.snapshot()?;
        if snapshot.runner_id() != self.inner.config.capabilities().runner_id() {
            return Err(RunnerRuntimeError::ExecutorContract);
        }
        let resume = snapshot
            .session()
            .map(|session| SessionResume::new(session.session_id(), session.command_cursor()));
        let (reply, mut local_wall_at_reply, mut lease_clock_anchor, hello_operation_id) =
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
                    self.reconcile_orphans(&orphan_recovery, cancellation.clone())
                        .await?;
                    if !self.inner.ports.journal.snapshot()?.slots().is_empty() {
                        return Err(RunnerRuntimeError::RecoveryAuthorizationRequired);
                    }
                }
                let (fresh_reply, fresh_local_wall, fresh_lease_clock_anchor, _) =
                    self.exchange_hello(None, cancellation).await?;
                local_wall_at_reply = fresh_local_wall;
                lease_clock_anchor = fresh_lease_clock_anchor;
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
        let journal = match self.inner.ports.journal.begin_session(binding) {
            Ok(snapshot) => snapshot,
            Err(automata_ci_runner_journal::JournalError::Invariant(
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
        Ok(RuntimeSession::new(
            &server,
            local_wall_at_reply,
            lease_clock_anchor,
        ))
    }

    async fn reconcile_orphans(
        &self,
        coordinator: &OrphanRecoveryCoordinator,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        let started = self.inner.ports.clock.monotonic_now();
        let result = coordinator.reconcile_authorized(cancellation).await;
        let outcome = match &result {
            Ok(()) => RuntimeOperationOutcome::Success,
            Err(RunnerRuntimeError::Shutdown) => RuntimeOperationOutcome::Cancelled,
            Err(_) => RuntimeOperationOutcome::Error,
        };
        self.observe(RunnerRuntimeEvent::OrphanRecovery {
            outcome,
            duration: self.elapsed_since(started),
        });
        result
    }

    async fn exchange_hello(
        &self,
        resume: Option<SessionResume>,
        cancellation: CancellationToken,
    ) -> Result<
        (
            RuntimeControlReply,
            UnixMillis,
            MonotonicMillis,
            OperationId,
        ),
        RunnerRuntimeError,
    > {
        let mode = if resume.is_some() {
            RuntimeSessionMode::Resume
        } else {
            RuntimeSessionMode::Fresh
        };
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
        // Bind the later database-time sample to an instant before this exact
        // exchange. Transport and handler delay then advance the lease clock
        // conservatively instead of extending authority.
        let started = self.inner.ports.clock.monotonic_now();
        let result = self.exchange(&prepared, cancellation).await;
        let outcome = match &result {
            Ok(reply) => match reply.message().message() {
                ServerToRunner::Hello(server) => match server.session_disposition() {
                    SessionDisposition::Opened => RuntimeSessionOutcome::Opened,
                    SessionDisposition::Resumed => RuntimeSessionOutcome::Resumed,
                },
                ServerToRunner::HandshakeRejected(_) => RuntimeSessionOutcome::Rejected,
                _ => RuntimeSessionOutcome::UnexpectedResponse,
            },
            Err(_) => RuntimeSessionOutcome::ExchangeError,
        };
        self.observe(RunnerRuntimeEvent::SessionHandshake {
            mode,
            outcome,
            duration: self.elapsed_since(started),
        });
        let reply = result?;
        Ok((
            reply,
            self.inner.ports.clock.wall_now(),
            started,
            operation_id,
        ))
    }

    async fn exchange(
        &self,
        prepared: &PreparedRequest,
        cancellation: CancellationToken,
    ) -> Result<RuntimeControlReply, RunnerRuntimeError> {
        exchange_exact(
            self.inner.ports.client.as_ref(),
            self.inner.ports.sleeper.as_ref(),
            self.inner.ports.observer.as_ref(),
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
                    Box::pin(self.run_accepted_slot(session, &durable, cancellation.clone())).await
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
        self.observe(RunnerRuntimeEvent::LeaseExpired);
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
        let started = self.inner.ports.clock.monotonic_now();
        let (checkpoint, prepared) = self.prepare_lease_poll(session, slot)?;
        loop {
            let reply = self.exchange(&prepared, cancellation.clone()).await?;
            match reply.message().message() {
                ServerToRunner::NoWork(no_work) => {
                    self.advance_lease_poll(session, slot, checkpoint.current_operation_id())?;
                    self.observe(RunnerRuntimeEvent::LeasePoll {
                        outcome: RuntimeLeasePollOutcome::NoWork,
                        duration: self.elapsed_since(started),
                    });
                    let delay = Duration::from_millis(u64::from(no_work.retry_after_millis()))
                        .min(self.inner.config.limits().idle_delay_ceiling());
                    sleep_or_shutdown(&self.inner.ports.sleeper, delay, &cancellation).await?;
                    return Ok(());
                }
                ServerToRunner::LeaseOffer(_) => {
                    self.process_command(session, &reply, cancellation.clone())
                        .await?;
                    self.advance_lease_poll(session, slot, checkpoint.current_operation_id())?;
                    self.flush_command_ack(session, cancellation.clone())
                        .await?;
                    self.observe(RunnerRuntimeEvent::LeasePoll {
                        outcome: RuntimeLeasePollOutcome::LeaseOffer,
                        duration: self.elapsed_since(started),
                    });
                    return Ok(());
                }
                ServerToRunner::CancelJob(_) => {
                    self.process_command(session, &reply, cancellation.clone())
                        .await?;
                    self.advance_lease_poll(session, slot, checkpoint.current_operation_id())?;
                    self.flush_command_ack(session, cancellation.clone())
                        .await?;
                    self.observe(RunnerRuntimeEvent::LeasePoll {
                        outcome: RuntimeLeasePollOutcome::Cancellation,
                        duration: self.elapsed_since(started),
                    });
                    return Ok(());
                }
                ServerToRunner::Error(error) => {
                    self.handle_remote_error(
                        error,
                        RemotePhase::LeaseResponse,
                        RuntimeExchangeKind::LeasePoll,
                    )?;
                    self.remote_retry_delay(RuntimeExchangeKind::LeasePoll, &cancellation)
                        .await?;
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
                // by any concurrent request. The mTLS-authenticated, session-
                // correlated offer is authoritative for its stable slot; the
                // request carrying it is not.
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
        sequence: automata_ci_protocol::CommandSequence,
        cancellation: &CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        let mut observed_gap = false;
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
                    if !observed_gap {
                        self.observe(RunnerRuntimeEvent::CommandGapWait);
                        observed_gap = true;
                    }
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
            self.observe(RunnerRuntimeEvent::Command {
                kind: RuntimeCommandKind::LeaseOffer,
                outcome: RuntimeCommandOutcome::Replayed,
            });
            return Ok(());
        }
        if offer.slot().get() > self.inner.config.capabilities().max_parallel_jobs() {
            self.inner.ports.journal.record_command_disposition(
                header.session_id(),
                command,
                CommandDisposition::Ignored(CommandIgnoredReason::InvalidCommand),
            )?;
            self.observe(RunnerRuntimeEvent::Command {
                kind: RuntimeCommandKind::LeaseOffer,
                outcome: RuntimeCommandOutcome::IgnoredInvalid,
            });
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
            self.observe(RunnerRuntimeEvent::Command {
                kind: RuntimeCommandKind::LeaseOffer,
                outcome: RuntimeCommandOutcome::IgnoredSlotUnavailable,
            });
            return Ok(());
        }
        let encoded_job = encode_job_ir(offer.job(), self.inner.config.protocol_limits())
            .map_err(|_| RunnerRuntimeError::InvalidDurablePayload)?;
        let (durable, expected_job_ir) =
            self.publish_lease_offer_content(session, offer, command, &encoded_job)?;
        // An active idempotent replay must still bind to these exact bytes. A
        // concurrently released applied replay has no remaining slot to bind.
        match durable.slot(offer.slot()) {
            Some(slot)
                if slot.offer().job_ir() == &expected_job_ir
                    && slot.offer().managed_secret_bindings()
                        == offer.managed_secret_bindings() => {}
            None if record_plan == LeaseOfferRecordPlan::VerifyAppliedReplay => {}
            Some(_) | None => return Err(RunnerRuntimeError::CommandReplayConflict),
        }
        self.observe(RunnerRuntimeEvent::Command {
            kind: RuntimeCommandKind::LeaseOffer,
            outcome: if record_plan == LeaseOfferRecordPlan::RecordNew {
                RuntimeCommandOutcome::Applied
            } else {
                RuntimeCommandOutcome::Replayed
            },
        });
        Ok(())
    }

    fn publish_lease_offer_content(
        &self,
        session: RuntimeSession,
        offer: &LeaseOffer,
        command: DurableCommand,
        encoded_job: &[u8],
    ) -> Result<(automata_ci_runner_journal::JournalSnapshot, JobIrContentRef), RunnerRuntimeError>
    {
        self.inner.content_operations.publish_reclaiming_capacity(
            self.inner.ports.journal.as_ref(),
            self.inner.ports.spool.as_ref(),
            || {
                let job_publication = self
                    .inner
                    .ports
                    .spool
                    .persist(ContentKind::JobIr, encoded_job)
                    .map_err(RunnerRuntimeError::from)?;
                let committed = job_publication.commit_with(|job_content| {
                    let job_ir = JobIrContentRef::new(
                        session.negotiated.selected_job_ir(),
                        job_content.clone(),
                    )
                    .map_err(automata_ci_runner_journal::JournalError::Invariant)?;
                    let mut record = LeaseOfferRecord::new(
                        offer.slot(),
                        offer.lease().clone(),
                        job_ir.clone(),
                        command,
                    )
                    .map_err(automata_ci_runner_journal::JournalError::Invariant)?;
                    if let Some(overlay) = offer.managed_secret_bindings() {
                        record = record
                            .with_managed_secret_bindings(overlay.clone())
                            .map_err(automata_ci_runner_journal::JournalError::Invariant)?;
                    }
                    self.inner
                        .ports
                        .journal
                        .record_lease_offer(offer.header().session_id(), record)
                        .map(|snapshot| (snapshot, job_ir))
                });
                match committed {
                    Ok(committed) => Ok::<_, RunnerRuntimeError>(committed),
                    Err(failure) => {
                        let (error, publication) = failure.into_parts();
                        publication.abort();
                        Err(error.into())
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
            self.observe(RunnerRuntimeEvent::Command {
                kind: RuntimeCommandKind::Cancellation,
                outcome: RuntimeCommandOutcome::Replayed,
            });
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
            self.observe(RunnerRuntimeEvent::Command {
                kind: RuntimeCommandKind::Cancellation,
                outcome: RuntimeCommandOutcome::IgnoredStaleLease,
            });
            return Ok(());
        };
        let slot = target.slot();
        self.inner.ports.journal.record_cancellation(
            header.session_id(),
            slot,
            cancel.guard(),
            CancellationRecord::new(command, cancel.requested_at()),
        )?;
        self.observe(RunnerRuntimeEvent::Command {
            kind: RuntimeCommandKind::Cancellation,
            outcome: RuntimeCommandOutcome::Applied,
        });
        if let Some(signal) = self
            .inner
            .executions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&cancel.attempt_id())
            .cloned()
        {
            signal.signal(ExecutionCancellationReason::ServerRequest);
            self.observe(RunnerRuntimeEvent::Cancellation {
                reason: RuntimeCancellationReason::ServerRequest,
            });
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
                        self.observe(RunnerRuntimeEvent::CommandAcknowledged);
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
                        self.observe(RunnerRuntimeEvent::CommandAcknowledged);
                        // The response completes this exchange but may also
                        // advance the durable command cursor. Rebuild from the
                        // journal so a newly observed command is covered by a
                        // new cumulative ACK. An idempotent replay leaves the
                        // cursor covered by this successful exchange.
                        continue 'acknowledgement;
                    }
                    ServerToRunner::Error(error) => {
                        self.handle_remote_error(
                            error,
                            RemotePhase::CommandAcknowledgement,
                            RuntimeExchangeKind::CommandAck,
                        )?;
                        self.remote_retry_delay(RuntimeExchangeKind::CommandAck, &cancellation)
                            .await?;
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
        let admission = self.admit_exact_environment(&job);
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
            self.inner.ports.clock.wall_now(),
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
        let was_acknowledged = rejection.is_response_acknowledged();
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
        if !was_acknowledged {
            self.observe(RunnerRuntimeEvent::LeaseResponseAcknowledged {
                disposition: RuntimeLeaseDisposition::Rejected,
            });
        }
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
            self.observe(RunnerRuntimeEvent::LeaseResponseAcknowledged {
                disposition: RuntimeLeaseDisposition::Accepted,
            });
        }
        Ok(())
    }

    async fn ensure_runtime_authority_delivery(
        &self,
        session: RuntimeSession,
        durable: &SlotSnapshot,
        cancellation: CancellationToken,
    ) -> Result<automata_ci_runner_journal::JournalSnapshot, RunnerRuntimeError> {
        if durable.cancellation().is_some() {
            return self.inner.ports.journal.snapshot().map_err(Into::into);
        }
        let job = self.load_job(durable)?;
        let binding = RuntimeAuthorityDeliveryBinding::new(
            durable.offer().lease().attempt_id(),
            durable.slot(),
            durable.offer().lease().guard(),
            durable.offer().command().operation_id(),
            durable.offer().command().sequence(),
            durable.offer().job_ir().content().sha256(),
            INITIAL_RUNTIME_AUTHORITY_GENERATION,
        );
        if durable.runtime_authority_delivery().is_none() {
            self.request_and_persist_runtime_authority_delivery(
                session,
                durable,
                binding,
                &job,
                cancellation.clone(),
            )
            .await?;
        }
        let snapshot = self.inner.ports.journal.snapshot()?;
        let slot = snapshot
            .slot(durable.slot())
            .ok_or(RunnerRuntimeError::InvalidDurablePayload)?;
        if slot.cancellation().is_some() {
            return Ok(snapshot);
        }
        let delivery = slot
            .runtime_authority_delivery()
            .cloned()
            .ok_or(RunnerRuntimeError::InvalidDurablePayload)?;
        if !delivery.is_acknowledged() {
            if !self
                .send_runtime_authority_ack(session, durable.slot(), &delivery, cancellation)
                .await?
            {
                return self.inner.ports.journal.snapshot().map_err(Into::into);
            }
            self.inner
                .ports
                .journal
                .acknowledge_runtime_authority_delivery(
                    session.negotiated.session_id(),
                    durable.slot(),
                    durable.offer().lease().guard(),
                    delivery.binding().generation(),
                    delivery.bundle_digest(),
                    delivery.acknowledgement_operation_id(),
                )?;
        }
        self.inner.ports.journal.snapshot().map_err(Into::into)
    }

    async fn request_and_persist_runtime_authority_delivery(
        &self,
        session: RuntimeSession,
        durable: &SlotSnapshot,
        binding: RuntimeAuthorityDeliveryBinding,
        job: &JobIrEnvelope,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        let request_operation_id = self.stable_runtime_authority_operation_id(
            durable,
            StableIdDomain::RuntimeAuthorityRequest,
        );
        let acknowledgement_operation_id = self.stable_runtime_authority_operation_id(
            durable,
            StableIdDomain::RuntimeAuthorityAcknowledgement,
        );
        let request = RuntimeAuthorityRequest::new(
            Self::request_header(session, request_operation_id),
            binding,
        );
        let prepared = PreparedRequest::for_session(
            RunnerToServer::RuntimeAuthorityRequest(request),
            session.negotiated,
            self.inner.config.protocol_limits(),
        )?;
        loop {
            let reply = self.exchange(&prepared, cancellation.clone()).await?;
            match reply.message().message() {
                ServerToRunner::RuntimeAuthorityGrant(grant) => {
                    grant
                        .validate_for(request, job, durable.offer().lease())
                        .map_err(|_| RunnerRuntimeError::InvalidDurablePayload)?;
                    let encoded = Zeroizing::new(
                        encode_runtime_authorities(
                            grant.authorities(),
                            job,
                            durable.offer().lease(),
                            self.inner.config.protocol_limits(),
                        )
                        .map_err(|_| RunnerRuntimeError::InvalidDurablePayload)?,
                    );
                    let bundle_digest =
                        Sha256Digest::from_bytes(Sha256::digest(encoded.as_slice()).into());
                    if bundle_digest != grant.bundle_digest() {
                        return Err(RunnerRuntimeError::InvalidDurablePayload);
                    }
                    return self.persist_runtime_authority_delivery(
                        session,
                        durable,
                        binding,
                        request_operation_id,
                        acknowledgement_operation_id,
                        bundle_digest,
                        &encoded,
                    );
                }
                ServerToRunner::LeaseOffer(_) | ServerToRunner::CancelJob(_) => {
                    self.process_command(session, &reply, cancellation.clone())
                        .await?;
                    self.flush_command_ack(session, cancellation.clone())
                        .await?;
                    if self.has_durable_slot_cancellation(durable.slot())? {
                        return Ok(());
                    }
                }
                ServerToRunner::Error(error) => {
                    self.handle_remote_error(
                        error,
                        RemotePhase::RuntimeAuthorityDelivery,
                        RuntimeExchangeKind::RuntimeAuthorityRequest,
                    )?;
                    self.remote_retry_delay(
                        RuntimeExchangeKind::RuntimeAuthorityRequest,
                        &cancellation,
                    )
                    .await?;
                }
                _ => return Err(RunnerRuntimeError::UnexpectedSyncResponse),
            }
        }
    }

    async fn send_runtime_authority_ack(
        &self,
        session: RuntimeSession,
        slot: RunnerSlotOrdinal,
        delivery: &RuntimeAuthorityDeliveryRecord,
        cancellation: CancellationToken,
    ) -> Result<bool, RunnerRuntimeError> {
        let acknowledgement = RuntimeAuthorityAck::new(
            Self::request_header(session, delivery.acknowledgement_operation_id()),
            delivery.binding(),
            delivery.bundle_digest(),
        );
        let prepared = PreparedRequest::for_session(
            RunnerToServer::RuntimeAuthorityAck(acknowledgement),
            session.negotiated,
            self.inner.config.protocol_limits(),
        )?;
        loop {
            let reply = self.exchange(&prepared, cancellation.clone()).await?;
            match reply.message().message() {
                ServerToRunner::OperationAck(_) => return Ok(true),
                ServerToRunner::LeaseOffer(_) | ServerToRunner::CancelJob(_) => {
                    self.process_command(session, &reply, cancellation.clone())
                        .await?;
                    self.flush_command_ack(session, cancellation.clone())
                        .await?;
                    if self.has_durable_slot_cancellation(slot)? {
                        return Ok(false);
                    }
                }
                ServerToRunner::Error(error) => {
                    self.handle_remote_error(
                        error,
                        RemotePhase::RuntimeAuthorityDelivery,
                        RuntimeExchangeKind::RuntimeAuthorityAck,
                    )?;
                    self.remote_retry_delay(
                        RuntimeExchangeKind::RuntimeAuthorityAck,
                        &cancellation,
                    )
                    .await?;
                }
                _ => return Err(RunnerRuntimeError::UnexpectedSyncResponse),
            }
        }
    }

    fn has_durable_slot_cancellation(
        &self,
        slot: RunnerSlotOrdinal,
    ) -> Result<bool, RunnerRuntimeError> {
        Ok(self
            .inner
            .ports
            .journal
            .snapshot()?
            .slot(slot)
            .is_some_and(|slot| slot.cancellation().is_some()))
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_runtime_authority_delivery(
        &self,
        session: RuntimeSession,
        durable: &SlotSnapshot,
        binding: RuntimeAuthorityDeliveryBinding,
        request_operation_id: OperationId,
        acknowledgement_operation_id: OperationId,
        bundle_digest: Sha256Digest,
        encoded: &[u8],
    ) -> Result<(), RunnerRuntimeError> {
        self.inner.content_operations.publish_reclaiming_capacity(
            self.inner.ports.journal.as_ref(),
            self.inner.ports.spool.as_ref(),
            || {
                let publication = self
                    .inner
                    .ports
                    .spool
                    .persist(ContentKind::RuntimeAuthority, encoded)?;
                let committed = publication.commit_with(|content| {
                    let content = RuntimeAuthorityContentRef::new(content.clone())
                        .map_err(automata_ci_runner_journal::JournalError::Invariant)?;
                    let delivery = RuntimeAuthorityDeliveryRecord::new(
                        binding,
                        request_operation_id,
                        acknowledgement_operation_id,
                        bundle_digest,
                        content,
                    )
                    .map_err(automata_ci_runner_journal::JournalError::Invariant)?;
                    self.inner.ports.journal.record_runtime_authority_delivery(
                        session.negotiated.session_id(),
                        durable.slot(),
                        durable.offer().lease().guard(),
                        delivery,
                    )?;
                    Ok(())
                });
                match committed {
                    Ok(()) => Ok(()),
                    Err(failure) => {
                        let (error, publication) = failure.into_parts();
                        publication.abort();
                        Err(RunnerRuntimeError::Journal(error))
                    }
                }
            },
        )
    }

    fn stable_runtime_authority_operation_id(
        &self,
        durable: &SlotSnapshot,
        domain: StableIdDomain,
    ) -> OperationId {
        let binding = durable.offer();
        let mut identity = binding
            .command()
            .operation_id()
            .as_uuid()
            .as_bytes()
            .to_vec();
        identity.extend_from_slice(&binding.command().sequence().get().to_be_bytes());
        identity.extend_from_slice(binding.lease().attempt_id().as_uuid().as_bytes());
        identity.extend_from_slice(binding.lease().lease_id().as_uuid().as_bytes());
        identity.extend_from_slice(&binding.lease().fencing_token().get().to_be_bytes());
        identity.extend_from_slice(binding.job_ir().content().sha256().as_bytes());
        identity.extend_from_slice(&INITIAL_RUNTIME_AUTHORITY_GENERATION.get().to_be_bytes());
        self.inner.ports.ids.stable_operation_id(domain, &identity)
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
                    let exchange = RuntimeExchangeKind::from_prepared(prepared);
                    self.handle_remote_error(error, phase, exchange)?;
                    self.remote_retry_delay(exchange, &cancellation).await?;
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
        let delivery = durable
            .runtime_authority_delivery()
            .filter(|delivery| delivery.is_acknowledged())
            .ok_or(RunnerRuntimeError::InvalidDurablePayload)?;
        let content = delivery.content().content();
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

    fn admit_exact_environment(
        &self,
        job: &JobIrEnvelope,
    ) -> Result<automata_ci_execution::SandboxEnvironment, AdmissionRejection> {
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
        &self,
        error: &ErrorMessage,
        phase: RemotePhase,
        exchange: RuntimeExchangeKind,
    ) -> Result<(), RunnerRuntimeError> {
        let disposition = match error.code() {
            RemoteErrorCode::SessionNotFound | RemoteErrorCode::StaleSession => {
                RuntimeRemoteErrorDisposition::Terminal
            }
            _ if error.is_retryable() => RuntimeRemoteErrorDisposition::Retrying,
            _ => RuntimeRemoteErrorDisposition::Terminal,
        };
        self.observe(RunnerRuntimeEvent::RemoteError {
            exchange,
            kind: RuntimeRemoteErrorKind::from(error.code()),
            disposition,
        });
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
        exchange: RuntimeExchangeKind,
        cancellation: &CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        let delay = self.inner.config.limits().retry().delay_after(1);
        self.observe(RunnerRuntimeEvent::RetryBackoff {
            exchange,
            cause: RuntimeRetryCause::RemoteResponse,
            delay,
        });
        sleep_or_shutdown(&self.inner.ports.sleeper, delay, cancellation).await?;
        self.observe(RunnerRuntimeEvent::RetryAttempt { exchange });
        Ok(())
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
        let snapshot = self
            .ensure_runtime_authority_delivery(session, &durable, cancellation.clone())
            .await?;
        let durable = snapshot
            .slot(durable.slot())
            .cloned()
            .ok_or(RunnerRuntimeError::ExecutorContract)?;
        if durable.cancellation().is_some() {
            return self
                .finish_cancelled_before_execution(session, &durable, cancellation)
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
        let credential_free = job.job().authority_profile() == JobAuthorityProfile::CredentialFree;
        let authority_deadline = match self.local_authority_deadline(session, &runtime_authorities)
        {
            Ok(deadline) => deadline,
            Err(RunnerRuntimeError::AuthorityExpired) => {
                return self
                    .finish_authority_expired_before_execution(session, &durable, cancellation)
                    .await;
            }
            Err(error) => return Err(error),
        };
        let environment = self
            .admit_exact_environment(&job)
            .map_err(|_| RunnerRuntimeError::EnvironmentAttestationMismatch)?;
        if credential_free
            && environment
                .default_environment()
                .values()
                .iter()
                .any(automata_ci_execution::EnvironmentVariable::is_secret)
        {
            return Err(RunnerRuntimeError::EnvironmentAttestationMismatch);
        }
        if authority_deadline.is_some_and(|deadline| {
            self.inner
                .ports
                .clock
                .monotonic_now()
                .is_at_or_after(deadline)
        }) {
            return self
                .finish_authority_expired_before_execution(session, &durable, cancellation)
                .await;
        }
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
            self.observe(RunnerRuntimeEvent::Cancellation {
                reason: RuntimeCancellationReason::ServerRequest,
            });
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

        let watchdog = Arc::new(LeaseWatchdog::new(self.local_lease_deadline(
            session,
            durable.offer().lease(),
            durable.expires_at(),
        )));
        let watchdog_stop = CancellationToken::new();
        let lease_expired = CancellationToken::new();
        let authority_expired = CancellationToken::new();
        let watchdog_task = self.spawn_execution_watchdog(
            Arc::clone(&watchdog),
            lease_expired.clone(),
            authority_deadline,
            authority_expired.clone(),
            watchdog_stop.clone(),
        );
        let mut request = ExecutionRequest::new(
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
        if let Some(overlay) = durable.offer().managed_secret_bindings() {
            request = request
                .with_managed_secret_bindings(overlay.clone())
                .map_err(|_| RunnerRuntimeError::InvalidDurablePayload)?;
        }
        let executor = Arc::clone(&self.inner.ports.executor);
        let executor_events = Arc::clone(&events);
        let executor_signal = signal.clone();
        let execution_started = self.inner.ports.clock.monotonic_now();
        let heartbeat_interval =
            Duration::from_millis(u64::from(session.timing.heartbeat_interval_millis()));
        let initial_lease_deadline = watchdog.deadline();
        info!(
            stage = "execution_supervision",
            runner_id = %self.inner.config.capabilities().runner_id(),
            session_id = %session.negotiated.session_id(),
            attempt_id = %lease.attempt_id(),
            slot = durable.slot().get(),
            lifecycle = ?durable.lifecycle(),
            heartbeat_interval_millis = heartbeat_interval.as_millis(),
            local_lease_remaining_millis = self
                .inner
                .ports
                .clock
                .monotonic_now()
                .remaining_until(initial_lease_deadline)
                .as_millis(),
            "accepted job entering independently renewed execution supervision"
        );
        self.observe(RunnerRuntimeEvent::JobStarted {
            mode: if durable.lifecycle() == JobLifecycle::Preparing {
                RuntimeJobStartMode::Fresh
            } else {
                RuntimeJobStartMode::Recovered
            },
        });
        // A provider-neutral executor may cross synchronous OS, hypervisor, or container-engine
        // boundaries. Mark the whole execution task as blocking so Tokio replaces its worker for
        // async control traffic, while retaining an abortable task whose future is quiesced before
        // sandbox cleanup. Current-thread runtimes are used only by deterministic unit harnesses,
        // where Tokio does not support this scheduling boundary.
        let mut execution = tokio::spawn(async move {
            let runtime = tokio::runtime::Handle::current();
            if runtime.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
                tokio::task::block_in_place(|| {
                    runtime.block_on(executor.execute(request, executor_events, executor_signal))
                })
            } else {
                executor
                    .execute(request, executor_events, executor_signal)
                    .await
            }
        });

        let heartbeat_stop = CancellationToken::new();
        let heartbeat_task = self.spawn_heartbeat_loop(
            session,
            durable.slot(),
            lease.guard(),
            Arc::clone(&watchdog),
            heartbeat_interval,
            heartbeat_stop.clone(),
        );
        tokio::pin!(heartbeat_task);
        let outcome = loop {
            let control_cycle = self.flush_active_log_slice(
                session,
                durable.slot(),
                lease.guard(),
                heartbeat_interval,
                cancellation.clone(),
            );
            tokio::pin!(control_cycle);
            let execution_cancelled = signal.token();
            tokio::select! {
                biased;
                () = execution_cancelled.cancelled() => {
                    break self.await_cancelled_executor(&mut execution).await;
                }
                () = authority_expired.cancelled() => {
                    signal.signal(ExecutionCancellationReason::AuthorityExpired);
                    self.observe(RunnerRuntimeEvent::Cancellation {
                        reason: RuntimeCancellationReason::AuthorityExpired,
                    });
                    let _quiesced = self.await_cancelled_executor(&mut execution).await;
                    break Err(ExecutorFailure::AuthorityExpired);
                }
                joined = &mut execution => {
                    break executor_join_result(joined);
                }
                () = cancellation.cancelled() => {
                    signal.signal(ExecutionCancellationReason::Shutdown);
                    self.observe(RunnerRuntimeEvent::Cancellation {
                        reason: RuntimeCancellationReason::Shutdown,
                    });
                    break self.await_cancelled_executor(&mut execution).await;
                }
                () = lease_expired.cancelled() => {
                    signal.signal(ExecutionCancellationReason::LeaseExpired);
                    self.observe(RunnerRuntimeEvent::Cancellation {
                        reason: RuntimeCancellationReason::LeaseExpired,
                    });
                    break self.await_cancelled_executor(&mut execution).await;
                }
                control_result = &mut control_cycle => {
                    if let Err(error) = control_result {
                        let (execution_reason, metric_reason) = match &error {
                            RunnerRuntimeError::StaleSession => (
                                ExecutionCancellationReason::SessionLost,
                                RuntimeCancellationReason::SessionLost,
                            ),
                            RunnerRuntimeError::LeaseExpired => (
                                ExecutionCancellationReason::LeaseExpired,
                                RuntimeCancellationReason::LeaseExpired,
                            ),
                            _ => (
                                ExecutionCancellationReason::Shutdown,
                                RuntimeCancellationReason::ControlFailure,
                            ),
                        };
                        signal.signal(execution_reason);
                        self.observe(RunnerRuntimeEvent::Cancellation {
                            reason: metric_reason,
                        });
                        let _ = self.await_cancelled_executor(&mut execution).await;
                        heartbeat_stop.cancel();
                        let _ = (&mut heartbeat_task).await;
                        watchdog_stop.cancel();
                        let _ = watchdog_task.await;
                        self.unregister_execution(lease.attempt_id());
                        return Err(error);
                    }
                }
                heartbeat_result = &mut heartbeat_task => {
                    let error = match heartbeat_result {
                        Ok(Err(error)) => error,
                        Ok(Ok(())) | Err(_) => RunnerRuntimeError::ExecutorContract,
                    };
                    let (execution_reason, metric_reason) = match &error {
                        RunnerRuntimeError::StaleSession => (
                            ExecutionCancellationReason::SessionLost,
                            RuntimeCancellationReason::SessionLost,
                        ),
                        RunnerRuntimeError::LeaseExpired => (
                            ExecutionCancellationReason::LeaseExpired,
                            RuntimeCancellationReason::LeaseExpired,
                        ),
                        RunnerRuntimeError::Shutdown if cancellation.is_cancelled() => (
                            ExecutionCancellationReason::Shutdown,
                            RuntimeCancellationReason::Shutdown,
                        ),
                        _ => (
                            ExecutionCancellationReason::Shutdown,
                            RuntimeCancellationReason::ControlFailure,
                        ),
                    };
                    signal.signal(execution_reason);
                    self.observe(RunnerRuntimeEvent::Cancellation {
                        reason: metric_reason,
                    });
                    let _ = self.await_cancelled_executor(&mut execution).await;
                    watchdog_stop.cancel();
                    let _ = watchdog_task.await;
                    self.unregister_execution(lease.attempt_id());
                    return Err(error);
                }
            }
        };
        heartbeat_stop.cancel();
        let _ = (&mut heartbeat_task).await;
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
            Some(
                ExecutionCancellationReason::AuthorityExpired
                | ExecutionCancellationReason::ServerRequest,
            )
            | None => {}
        }
        let result = outcome.unwrap_or_else(|failure| {
            self.executor_failure_result(
                session,
                &durable,
                failure,
                cancellation_reason
                    .is_some_and(|reason| reason == ExecutionCancellationReason::ServerRequest),
                credential_free,
            )
        });
        let conclusion = RuntimeJobConclusion::from(result.conclusion());
        let finished = async {
            let finalization_lifecycle = self.finalization_heartbeat_lifecycle(durable.slot())?;
            self.commit_terminal_result(session, durable.slot(), lease.guard(), result)?;
            self.observe(RunnerRuntimeEvent::JobCompleted {
                conclusion,
                duration: Some(self.elapsed_since(execution_started)),
            });
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

    async fn finish_authority_expired_before_execution(
        &self,
        session: RuntimeSession,
        durable: &SlotSnapshot,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
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
        self.observe(RunnerRuntimeEvent::InfrastructureFailure {
            kind: RuntimeInfrastructureFailure::AuthorityExpired,
        });
        let result = JobResult::new(
            durable.offer().lease().attempt_id(),
            conclusion,
            JobSecretExposure::Secretless,
            self.inner.ports.clock.wall_now(),
        );
        self.commit_terminal_result(
            session,
            durable.slot(),
            durable.offer().lease().guard(),
            result,
        )?;
        self.observe(RunnerRuntimeEvent::JobCompleted {
            conclusion: RuntimeJobConclusion::from(conclusion),
            duration: None,
        });
        let snapshot = self.inner.ports.journal.snapshot()?;
        let terminal = snapshot
            .slot(durable.slot())
            .cloned()
            .ok_or(RunnerRuntimeError::ExecutorContract)?;
        self.finish_terminal_slot(session, &terminal, cancellation)
            .await
    }

    async fn finish_cancelled_before_execution(
        &self,
        session: RuntimeSession,
        durable: &SlotSnapshot,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        self.observe(RunnerRuntimeEvent::Cancellation {
            reason: RuntimeCancellationReason::ServerRequest,
        });
        let result = JobResult::new(
            durable.offer().lease().attempt_id(),
            JobConclusion::Cancelled,
            JobSecretExposure::Secretless,
            self.inner.ports.clock.wall_now(),
        );
        self.commit_terminal_result(
            session,
            durable.slot(),
            durable.offer().lease().guard(),
            result,
        )?;
        self.observe(RunnerRuntimeEvent::JobCompleted {
            conclusion: RuntimeJobConclusion::Cancelled,
            duration: None,
        });
        let snapshot = self.inner.ports.journal.snapshot()?;
        let terminal = snapshot
            .slot(durable.slot())
            .cloned()
            .ok_or(RunnerRuntimeError::ExecutorContract)?;
        self.finish_terminal_slot(session, &terminal, cancellation)
            .await
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
                // Tokio cancellation is asynchronous. Do not allow terminal
                // sandbox reconciliation to overlap the executor future that
                // owned that sandbox and its event stream.
                let _quiesced = (&mut *execution).await;
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
        credential_free: bool,
    ) -> JobResult {
        let conclusion = failure.conclusion(server_cancelled);
        self.observe(RunnerRuntimeEvent::InfrastructureFailure {
            kind: failure.metric_kind(),
        });
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
            if credential_free {
                JobSecretExposure::Secretless
            } else {
                JobSecretExposure::ReadableSecret
            },
            self.inner.ports.clock.wall_now(),
        )
    }

    fn spawn_watchdog(
        &self,
        watchdog: Arc<LeaseWatchdog>,
        expired: CancellationToken,
        stop: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        self.spawn_watchdog_inner(watchdog, expired, None, stop)
    }

    fn spawn_heartbeat_loop(
        &self,
        session: RuntimeSession,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        watchdog: Arc<LeaseWatchdog>,
        heartbeat_interval: Duration,
        stop: CancellationToken,
    ) -> tokio::task::JoinHandle<Result<(), RunnerRuntimeError>> {
        let runtime = self.clone();
        tokio::spawn(async move {
            let mut schedule = HeartbeatSchedule::new(
                runtime.inner.ports.clock.monotonic_now(),
                heartbeat_interval,
                watchdog.deadline(),
            );
            loop {
                schedule.cap_to_lease(
                    runtime.inner.ports.clock.monotonic_now(),
                    watchdog.deadline(),
                );
                let delay = schedule.remaining_from(runtime.inner.ports.clock.monotonic_now());
                let renewal = async {
                    sleep_or_shutdown(&runtime.inner.ports.sleeper, delay, &stop).await?;
                    info!(
                        stage = "lease_heartbeat",
                        runner_id = %runtime.inner.config.capabilities().runner_id(),
                        session_id = %session.negotiated.session_id(),
                        slot = slot.get(),
                        action = "renewal_started",
                        "active lease heartbeat became due"
                    );
                    runtime
                        .heartbeat_once(
                            session,
                            slot,
                            guard,
                            Arc::clone(&watchdog),
                            None,
                            stop.clone(),
                        )
                        .await
                };
                tokio::pin!(renewal);
                tokio::select! {
                    biased;
                    () = stop.cancelled() => return Ok(()),
                    result = &mut renewal => {
                        result?;
                        schedule.renewed(
                            runtime.inner.ports.clock.monotonic_now(),
                            watchdog.deadline(),
                        );
                        info!(
                            stage = "lease_heartbeat",
                            runner_id = %runtime.inner.config.capabilities().runner_id(),
                            session_id = %session.negotiated.session_id(),
                            slot = slot.get(),
                            action = "renewal_committed",
                            "active lease heartbeat committed"
                        );
                    }
                }
            }
        })
    }

    fn spawn_execution_watchdog(
        &self,
        watchdog: Arc<LeaseWatchdog>,
        lease_expired: CancellationToken,
        authority_deadline: Option<MonotonicMillis>,
        authority_expired: CancellationToken,
        stop: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        self.spawn_watchdog_inner(
            watchdog,
            lease_expired,
            authority_deadline.map(|deadline| (deadline, authority_expired)),
            stop,
        )
    }

    fn spawn_watchdog_inner(
        &self,
        watchdog: Arc<LeaseWatchdog>,
        lease_expired: CancellationToken,
        mut authority: Option<(MonotonicMillis, CancellationToken)>,
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
                if authority
                    .as_ref()
                    .is_some_and(|(deadline, _)| now.is_at_or_after(*deadline))
                    && let Some((_, expired)) = authority.take()
                {
                    expired.cancel();
                }
                if watchdog.is_expired_at(now) {
                    lease_expired.cancel();
                    return;
                }
                let lease_remaining = now.remaining_until(watchdog.deadline());
                let remaining = authority.as_ref().map_or(lease_remaining, |(deadline, _)| {
                    lease_remaining.min(now.remaining_until(*deadline))
                });
                sleeper.sleep(remaining.min(resolution), stop.clone()).await;
            }
        })
    }

    fn local_authority_deadline(
        &self,
        session: RuntimeSession,
        authorities: &JobRuntimeAuthorities,
    ) -> Result<Option<MonotonicMillis>, RunnerRuntimeError> {
        if authorities.as_slice().is_empty() {
            return Ok(None);
        }
        let local_monotonic = self.inner.ports.clock.monotonic_now();
        let database_now = session.estimated_lease_database_now(local_monotonic);
        let earliest_expiry = authorities
            .as_slice()
            .iter()
            .map(automata_ci_protocol::JobRuntimeAuthority::expires_at)
            .min()
            .ok_or(RunnerRuntimeError::InvalidDurablePayload)?;
        if authorities
            .as_slice()
            .iter()
            .any(|authority| authority.issued_at() > database_now)
            || database_now >= earliest_expiry
        {
            return Err(RunnerRuntimeError::AuthorityExpired);
        }
        let remaining_millis =
            u64::try_from(earliest_expiry.get().saturating_sub(database_now.get()))
                .map_err(|_| RunnerRuntimeError::AuthorityExpired)?;
        Ok(Some(
            local_monotonic.saturating_add(Duration::from_millis(remaining_millis)),
        ))
    }

    fn local_lease_deadline(
        &self,
        session: RuntimeSession,
        durable_lease: &Lease,
        remote_expiry: UnixMillis,
    ) -> MonotonicMillis {
        let local_monotonic = self.inner.ports.clock.monotonic_now();
        let database_now = session.estimated_lease_database_now(local_monotonic);
        let remaining_millis = remote_expiry
            .get()
            .saturating_sub(database_now.get())
            .max(0);
        let durable_interval_millis = durable_lease
            .expires_at()
            .get()
            .saturating_sub(durable_lease.issued_at().get())
            .max(0);
        // Renewals carry only an absolute expiration. The original exact
        // database-issued lease interval remains a conservative duration cap.
        let remaining = Duration::from_millis(
            u64::try_from(remaining_millis)
                .unwrap_or(0)
                .min(u64::try_from(durable_interval_millis).unwrap_or(0))
                .min(u64::from(session.timing.lease_duration_millis())),
        );
        local_monotonic.saturating_add(remaining)
    }

    async fn flush_active_log_slice(
        &self,
        session: RuntimeSession,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        idle_delay: Duration,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        match self
            .flush_log_batch(session, slot, guard, cancellation.clone())
            .await?
        {
            LogFlushStatus::MorePending => tokio::task::yield_now().await,
            LogFlushStatus::CaughtUp => {
                sleep_or_shutdown(&self.inner.ports.sleeper, idle_delay, &cancellation).await?;
            }
        }
        Ok(())
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
        let started = self.inner.ports.clock.monotonic_now();
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
                    watchdog.extend_to(self.local_lease_deadline(
                        session,
                        durable.offer().lease(),
                        renewal.expires_at(),
                    ));
                    if watchdog.is_expired_at(self.inner.ports.clock.monotonic_now()) {
                        return Err(RunnerRuntimeError::LeaseExpired);
                    }
                    self.observe(RunnerRuntimeEvent::LeaseRenewed {
                        duration: self.elapsed_since(started),
                    });
                    return Ok(());
                }
                ServerToRunner::LeaseOffer(_) | ServerToRunner::CancelJob(_) => {
                    self.process_command(session, &reply, cancellation.clone())
                        .await?;
                    self.flush_command_ack(session, cancellation.clone())
                        .await?;
                }
                ServerToRunner::Error(error) => {
                    self.handle_remote_error(
                        error,
                        RemotePhase::LeaseHeartbeat,
                        RuntimeExchangeKind::Heartbeat,
                    )?;
                    self.remote_retry_delay(RuntimeExchangeKind::Heartbeat, &cancellation)
                        .await?;
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
        let Some(delivery) = self.prepare_log_batch(session, slot, guard).await? else {
            return Ok(LogFlushStatus::CaughtUp);
        };
        let started = self.inner.ports.clock.monotonic_now();
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
                    let more_pending = self
                        .acknowledge_log_segment(
                            session,
                            slot,
                            guard,
                            delivery.stream_id,
                            delivery.delivered_through,
                            delivery.head_content.clone(),
                        )
                        .await?;
                    self.observe(RunnerRuntimeEvent::LogBatchAcknowledged {
                        frames: delivery.frames,
                        bytes: delivery.payload_bytes,
                        duration: self.elapsed_since(started),
                    });
                    return if more_pending {
                        Ok(LogFlushStatus::MorePending)
                    } else {
                        Ok(LogFlushStatus::CaughtUp)
                    };
                }
                ServerToRunner::LeaseOffer(_) | ServerToRunner::CancelJob(_) => {
                    self.process_command(session, &reply, cancellation.clone())
                        .await?;
                    self.flush_command_ack(session, cancellation.clone())
                        .await?;
                }
                ServerToRunner::Error(error) => {
                    self.handle_remote_error(
                        error,
                        RemotePhase::LogDelivery,
                        RuntimeExchangeKind::LogBatch,
                    )?;
                    self.remote_retry_delay(RuntimeExchangeKind::LogBatch, &cancellation)
                        .await?;
                }
                _ => return Err(RunnerRuntimeError::UnexpectedSyncResponse),
            }
        }
    }

    async fn acknowledge_log_segment(
        &self,
        session: RuntimeSession,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        stream_id: automata_ci_core::LogStreamId,
        sequence: automata_ci_core::LogSequence,
        head_content: automata_ci_runner_journal::DurableContentRef,
    ) -> Result<bool, RunnerRuntimeError> {
        let supervisor = self.clone();
        tokio::task::spawn_blocking(move || {
            supervisor.acknowledge_log_segment_blocking(
                session,
                slot,
                guard,
                stream_id,
                sequence,
                &head_content,
            )
        })
        .await
        .map_err(|_| RunnerRuntimeError::ExecutorContract)?
    }

    fn acknowledge_log_segment_blocking(
        &self,
        session: RuntimeSession,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        stream_id: automata_ci_core::LogStreamId,
        sequence: automata_ci_core::LogSequence,
        head_content: &automata_ci_runner_journal::DurableContentRef,
    ) -> Result<bool, RunnerRuntimeError> {
        self.inner.content_operations.run(|| {
            let acknowledgement =
                LogSegmentAcknowledgement::new(stream_id, sequence, head_content.clone())
                    .map_err(automata_ci_runner_journal::JournalError::Invariant)?;
            let snapshot = self.inner.ports.journal.acknowledge_log_segment(
                session.negotiated.session_id(),
                slot,
                guard,
                acknowledgement,
            )?;
            if !snapshot
                .content_references()
                .any(|content| content == head_content)
            {
                self.inner.ports.spool.remove(head_content)?;
            }
            let delivery = snapshot
                .slot(slot)
                .and_then(|durable| durable.log_delivery())
                .ok_or(RunnerRuntimeError::ExecutorContract)?;
            Ok(!delivery.segments().is_empty())
        })
    }

    async fn load_pending_log_batch(
        &self,
        session: RuntimeSession,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
    ) -> Result<Option<PendingLogBatch>, RunnerRuntimeError> {
        let supervisor = self.clone();
        tokio::task::spawn_blocking(move || {
            supervisor.load_pending_log_batch_blocking(session, slot, guard)
        })
        .await
        .map_err(|_| RunnerRuntimeError::ExecutorContract)?
    }

    fn load_pending_log_batch_blocking(
        &self,
        session: RuntimeSession,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
    ) -> Result<Option<PendingLogBatch>, RunnerRuntimeError> {
        let loaded: Result<
            Option<(
                SlotSnapshot,
                automata_ci_runner_journal::LogSegment,
                Vec<u8>,
            )>,
            RunnerRuntimeError,
        > = self.inner.content_operations.run(|| {
            let mut snapshot = self.inner.ports.journal.snapshot()?;
            if let Some(delivery) = snapshot
                .slot(slot)
                .and_then(|durable| durable.log_delivery())
                && let Some(open) = delivery.open_segment()
            {
                snapshot = self.inner.ports.journal.seal_log_segment(
                    session.negotiated.session_id(),
                    slot,
                    guard,
                    delivery.stream_id(),
                    open.content().clone(),
                )?;
            }
            let durable = snapshot
                .slot(slot)
                .cloned()
                .ok_or(RunnerRuntimeError::ExecutorContract)?;
            let Some(delivery) = durable.log_delivery() else {
                return Ok(None);
            };
            let Some(head) = delivery.head_segment().cloned() else {
                return Ok(None);
            };
            if !head.is_sealed() {
                return Err(RunnerRuntimeError::InvalidDurablePayload);
            }
            let bytes = self.inner.ports.spool.load(head.content())?;
            Ok(Some((durable, head, bytes)))
        });
        let Some((durable, head, bytes)) = loaded? else {
            return Ok(None);
        };
        let delivery = durable
            .log_delivery()
            .ok_or(RunnerRuntimeError::InvalidDurablePayload)?;
        let limits = self.inner.config.protocol_limits();
        if usize::try_from(head.frame_count()).unwrap_or(usize::MAX)
            > limits.max_log_frames_per_batch()
            || usize::try_from(head.payload_bytes()).unwrap_or(usize::MAX)
                > limits.max_log_payload_bytes_per_batch()
        {
            return Err(RunnerRuntimeError::InvalidDurablePayload);
        }
        let frames = validate_log_segment_records(
            &bytes,
            &head,
            session.negotiated,
            guard,
            durable.offer().lease().attempt_id(),
            delivery.stream_id(),
            limits,
        )?;
        Ok(Some(PendingLogBatch {
            attempt_id: durable.offer().lease().attempt_id(),
            stream_id: delivery.stream_id(),
            head_content: head.content().clone(),
            frames,
        }))
    }

    async fn prepare_log_batch(
        &self,
        session: RuntimeSession,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
    ) -> Result<Option<PreparedLogBatch>, RunnerRuntimeError> {
        let Some(pending) = self.load_pending_log_batch(session, slot, guard).await? else {
            return Ok(None);
        };
        let first = pending
            .frames
            .first()
            .ok_or(RunnerRuntimeError::InvalidDurablePayload)?
            .sequence();
        let delivered_through = pending
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
            delivered_through,
        );
        let message = RunnerToServer::LogBatch(LogBatch::new(
            Self::request_header(session, operation_id),
            guard,
            pending.frames.clone(),
        ));
        let prepared = PreparedRequest::for_session(
            message,
            session.negotiated,
            self.inner.config.protocol_limits(),
        )
        .map_err(|_| RunnerRuntimeError::InvalidDurablePayload)?;
        let frames = u64::try_from(pending.frames.len()).unwrap_or(u64::MAX);
        let payload_bytes = pending.frames.iter().fold(0_u64, |total, frame| {
            total.saturating_add(u64::try_from(frame.payload().len()).unwrap_or(u64::MAX))
        });
        Ok(Some(PreparedLogBatch {
            prepared,
            stream_id: pending.stream_id,
            delivered_through,
            head_content: pending.head_content,
            frames,
            payload_bytes,
        }))
    }

    fn stable_log_batch_id(
        &self,
        session: RuntimeSession,
        attempt_id: AttemptId,
        guard: LeaseGuard,
        stream_id: automata_ci_core::LogStreamId,
        first: automata_ci_core::LogSequence,
        last: automata_ci_core::LogSequence,
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
        let conclusion = RuntimeJobConclusion::from(result.conclusion());
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
        let message = RunnerToServer::JobResult(automata_ci_protocol::JobResultMessage::new(
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
                        .map_err(automata_ci_runner_journal::JournalError::Invariant)?;
                    self.inner.ports.journal.record_terminal_result(
                        session.negotiated.session_id(),
                        slot,
                        guard,
                        terminal,
                        record,
                        self.inner.ports.clock.wall_now(),
                    )
                });
                match committed {
                    Ok(_) => Ok::<(), RunnerRuntimeError>(()),
                    Err(failure) => {
                        let (error, publication) = failure.into_parts();
                        publication.abort();
                        Err(error.into())
                    }
                }
            },
        )?;
        self.observe(RunnerRuntimeEvent::TerminalResult {
            stage: RuntimeTerminalResultStage::Committed,
            conclusion,
        });
        Ok(())
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
        let watchdog = Arc::new(LeaseWatchdog::new(self.local_lease_deadline(
            session,
            durable.offer().lease(),
            durable.expires_at(),
        )));
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

    fn require_create_cleanup_custody(durable: &SlotSnapshot) -> Result<(), RunnerRuntimeError> {
        let missing_custody = durable.sandbox().is_none()
            && durable
                .provider_operations()
                .last()
                .is_some_and(|operation| {
                    operation.kind() == ProviderOperationKind::CreateSandbox
                        && operation.is_pending()
                });
        if missing_custody {
            Err(RunnerRuntimeError::ExecutorContract)
        } else {
            Ok(())
        }
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
        Self::require_create_cleanup_custody(durable)?;
        let slot = durable.slot();
        let guard = durable.offer().lease().guard();
        self.flush_terminal_log_backlog(session, slot, guard, cancellation.clone())
            .await?;
        let snapshot = self.inner.ports.journal.snapshot()?;
        let mut current = snapshot
            .slot(slot)
            .cloned()
            .ok_or(RunnerRuntimeError::ExecutorContract)?;
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
        if current.sandbox().is_some() {
            self.reconcile_terminal_sandbox(session, slot, guard, cancellation.clone())
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
        let conclusion = RuntimeJobConclusion::from(result.result().conclusion());
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
        self.observe(RunnerRuntimeEvent::TerminalResult {
            stage: RuntimeTerminalResultStage::Acknowledged,
            conclusion,
        });
        Ok(())
    }

    async fn cleanup_terminal_sandbox(
        &self,
        session: RuntimeSession,
        durable: &SlotSnapshot,
        sandbox: automata_ci_runner_journal::SandboxIdentity,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        let started = self.inner.ports.clock.monotonic_now();
        let result = self
            .cleanup_terminal_sandbox_inner(session, durable, sandbox, cancellation)
            .await;
        let outcome = match &result {
            Ok(()) => RuntimeOperationOutcome::Success,
            Err(RunnerRuntimeError::Shutdown) => RuntimeOperationOutcome::Cancelled,
            Err(_) => RuntimeOperationOutcome::Error,
        };
        self.observe(RunnerRuntimeEvent::Cleanup {
            outcome,
            duration: self.elapsed_since(started),
        });
        result
    }

    async fn cleanup_terminal_sandbox_inner(
        &self,
        session: RuntimeSession,
        durable: &SlotSnapshot,
        sandbox: automata_ci_runner_journal::SandboxIdentity,
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
                cleanup.signal.signal(ExecutionCancellationReason::Shutdown);
                cleanup.task.abort();
                let _quiesced = (&mut cleanup.task).await;
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
    stream_id: automata_ci_core::LogStreamId,
    head_content: automata_ci_runner_journal::DurableContentRef,
    frames: Vec<automata_ci_core::LogFrame>,
}

struct PreparedLogBatch {
    prepared: PreparedRequest,
    stream_id: automata_ci_core::LogStreamId,
    delivered_through: automata_ci_core::LogSequence,
    head_content: automata_ci_runner_journal::DurableContentRef,
    frames: u64,
    payload_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutorFailure {
    Adapter(ExecutorErrorKind),
    TaskTerminated,
    CancellationTimeout,
    AuthorityExpired,
}

impl ExecutorFailure {
    const fn metric_kind(self) -> RuntimeInfrastructureFailure {
        match self {
            Self::Adapter(kind) => match kind {
                ExecutorErrorKind::InvalidJob => RuntimeInfrastructureFailure::InvalidJob,
                ExecutorErrorKind::Unsupported => RuntimeInfrastructureFailure::Unsupported,
                ExecutorErrorKind::ResourceExhausted => {
                    RuntimeInfrastructureFailure::ResourceExhausted
                }
                ExecutorErrorKind::PermissionDenied => {
                    RuntimeInfrastructureFailure::PermissionDenied
                }
                ExecutorErrorKind::Unavailable => RuntimeInfrastructureFailure::Unavailable,
                ExecutorErrorKind::TimedOut => RuntimeInfrastructureFailure::TimedOut,
                ExecutorErrorKind::Cancelled => RuntimeInfrastructureFailure::Cancelled,
                ExecutorErrorKind::Internal => RuntimeInfrastructureFailure::Internal,
            },
            Self::TaskTerminated => RuntimeInfrastructureFailure::TaskTerminated,
            Self::CancellationTimeout => RuntimeInfrastructureFailure::CancellationTimeout,
            Self::AuthorityExpired => RuntimeInfrastructureFailure::AuthorityExpired,
        }
    }

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
            Self::AuthorityExpired => "authority_expired",
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
            | Self::CancellationTimeout
            | Self::AuthorityExpired => JobConclusion::Failure,
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
    lease_clock_database_anchor: UnixMillis,
    lease_clock_monotonic_anchor: MonotonicMillis,
}

impl RuntimeSession {
    fn new(
        server: &ServerHello,
        local_wall: UnixMillis,
        lease_clock_monotonic_anchor: MonotonicMillis,
    ) -> Self {
        Self {
            negotiated: server.session(),
            timing: server.timing(),
            server_wall_offset_millis: server.server_time().get().saturating_sub(local_wall.get()),
            lease_clock_database_anchor: server.server_time(),
            lease_clock_monotonic_anchor,
        }
    }

    fn estimated_lease_database_now(self, local_monotonic: MonotonicMillis) -> UnixMillis {
        // A regressing or exhausted adapter clock fails closed at the latest
        // representable server instant.
        let elapsed = local_monotonic
            .get()
            .checked_sub(self.lease_clock_monotonic_anchor.get())
            .and_then(|elapsed| i64::try_from(elapsed).ok())
            .unwrap_or(i64::MAX);
        UnixMillis::new(
            self.lease_clock_database_anchor
                .get()
                .saturating_add(elapsed),
        )
    }
}

fn durable_command(
    header: automata_ci_protocol::ServerCommandHeader,
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
