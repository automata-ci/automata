mod support;

use std::{
    fmt,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use automata_ci_core::{
    JobConclusion, JobIrEnvelope, JobIrVersion, JobLifecycle, JobResult, JobSecretExposure, Lease,
    LogAck, OperationId, RunnerId, RunnerSessionId, Sha256Digest, UnixMillis,
};
use automata_ci_protocol::{
    CommandSequence, ErrorMessage, LeaseRenewal, LogAckMessage, MessageHeader, NegotiatedSession,
    NoWork, OperationAck, ProtocolLimits, RemoteErrorCode, RunnerToServer,
    SUPPORTED_PROTOCOL_RANGE, ServerHello, ServerTiming, ServerToRunner, SessionDisposition,
};
use automata_ci_runner_journal::{CancellationRecord, DurableCommand, RunnerJournal};
use automata_ci_runner_runtime::{
    AdmissionRejection, CleanupFuture, CleanupRequest, ExecutionAdmission, ExecutionCancellation,
    ExecutionCancellationReason, ExecutionEvents, ExecutionRequest, ExecutorFuture, JobExecutor,
    RetryPolicy, RunnerRuntimeControlClient, RunnerRuntimeEvent, RunnerRuntimeObserver,
    RunnerRuntimePorts, RunnerSessionSupervisor, RuntimeCancellationReason, RuntimeCommandKind,
    RuntimeCommandOutcome, RuntimeControlError, RuntimeControlErrorKind, RuntimeControlFuture,
    RuntimeControlReply, RuntimeControlRetry, RuntimeExchangeKind, RuntimeInfrastructureFailure,
    RuntimeJobConclusion, RuntimeLeaseDisposition, RuntimeLeasePollOutcome,
    RuntimeOperationOutcome, RuntimeRemoteErrorDisposition, RuntimeRemoteErrorKind,
    RuntimeRetryCause, RuntimeSessionOutcome, RuntimeTerminalResultStage, SystemRuntimeIds,
};
use automata_ci_runner_transport::PreparedRequest;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Default)]
struct RecordingObserver {
    events: Mutex<Vec<RunnerRuntimeEvent>>,
}

impl RecordingObserver {
    fn events(&self) -> Vec<RunnerRuntimeEvent> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl RunnerRuntimeObserver for RecordingObserver {
    fn observe(&self, event: RunnerRuntimeEvent) {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(event);
    }
}

struct RetryLaterOnceClient {
    inner: Arc<dyn RunnerRuntimeControlClient>,
    injected: AtomicBool,
    limits: ProtocolLimits,
}

impl RetryLaterOnceClient {
    fn new(inner: Arc<dyn RunnerRuntimeControlClient>) -> Self {
        Self {
            inner,
            injected: AtomicBool::new(false),
            limits: ProtocolLimits::default(),
        }
    }
}

impl fmt::Debug for RetryLaterOnceClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetryLaterOnceClient")
            .field("inner", &"configured")
            .finish_non_exhaustive()
    }
}

impl RunnerRuntimeControlClient for RetryLaterOnceClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        if let RunnerToServer::LeaseRequest(poll) = request.message()
            && !self
                .injected
                .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            let request_header = poll.header();
            let reply_header = MessageHeader::reply(
                request_header.protocol_version(),
                request_header.session_id(),
                OperationId::new(),
                request_header.operation_id(),
            );
            return Box::pin(async move {
                RuntimeControlReply::from_message(
                    ServerToRunner::Error(ErrorMessage::new(
                        reply_header,
                        RemoteErrorCode::RetryLater,
                        "retry later",
                        true,
                    )),
                    &self.limits,
                )
                .map_err(|_| {
                    RuntimeControlError::new(
                        RuntimeControlErrorKind::InvalidResponse,
                        RuntimeControlRetry::Never,
                    )
                })
            });
        }
        self.inner.exchange(request, cancellation)
    }
}

#[derive(Debug)]
struct CompletionClient {
    session_id: RunnerSessionId,
    lease: Lease,
    server_time: UnixMillis,
    shutdown: CancellationToken,
    limits: ProtocolLimits,
}

impl CompletionClient {
    fn new(
        session_id: RunnerSessionId,
        lease: Lease,
        server_time: UnixMillis,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            session_id,
            lease,
            server_time,
            shutdown,
            limits: ProtocolLimits::default(),
        }
    }
}

impl RunnerRuntimeControlClient for CompletionClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        _cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            let response = match request.message() {
                RunnerToServer::Hello(hello) => {
                    let resume = hello
                        .resume()
                        .expect("completion flow resumes durable state");
                    ServerToRunner::Hello(ServerHello::new(
                        OperationId::new(),
                        hello.operation_id(),
                        NegotiatedSession::new(
                            SUPPORTED_PROTOCOL_RANGE.max(),
                            JobIrVersion::current(),
                            self.session_id,
                            SessionDisposition::Resumed,
                            resume.command_cursor(),
                        ),
                        ServerTiming::new(self.server_time, 1_000, 30_000),
                    ))
                }
                RunnerToServer::LeaseResponse(response) => {
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(response.header())))
                }
                RunnerToServer::Heartbeat(heartbeat) => {
                    ServerToRunner::LeaseRenewal(LeaseRenewal::new(
                        reply_header(heartbeat.header()),
                        self.lease.attempt_id(),
                        self.lease.guard(),
                        self.lease.expires_at(),
                    ))
                }
                RunnerToServer::JobState(state) => {
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(state.header())))
                }
                RunnerToServer::LogBatch(batch) => {
                    let last = batch
                        .frames()
                        .last()
                        .expect("nonempty completion log batch");
                    ServerToRunner::LogAck(LogAckMessage::new(
                        reply_header(batch.header()),
                        LogAck::new(last.stream_id(), Some(last.sequence())),
                    ))
                }
                RunnerToServer::JobResult(result) => {
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(result.header())))
                }
                RunnerToServer::CommandAck(ack) => {
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(ack.header())))
                }
                RunnerToServer::LeaseRequest(poll) => {
                    self.shutdown.cancel();
                    ServerToRunner::NoWork(NoWork::new(reply_header(poll.header()), 1))
                }
            };
            runtime_reply(response, &self.limits)
        })
    }
}

fn reply_header(request: MessageHeader) -> MessageHeader {
    MessageHeader::reply(
        request.protocol_version(),
        request.session_id(),
        OperationId::new(),
        request.operation_id(),
    )
}

fn runtime_reply(
    response: ServerToRunner,
    limits: &ProtocolLimits,
) -> Result<RuntimeControlReply, RuntimeControlError> {
    RuntimeControlReply::from_message(response, limits).map_err(|_| {
        RuntimeControlError::new(
            RuntimeControlErrorKind::InvalidResponse,
            RuntimeControlRetry::Never,
        )
    })
}

#[derive(Debug)]
struct TerminalHeartbeatClient {
    inner: Arc<CompletionClient>,
}

#[derive(Debug)]
struct RecoveredCancellationExecutor {
    admission_delegate: support::CancellationExecutor,
    observed_reason: Mutex<Option<ExecutionCancellationReason>>,
}

impl RecoveredCancellationExecutor {
    fn new() -> Self {
        Self {
            admission_delegate: support::CancellationExecutor::new(Arc::new(AtomicBool::new(
                false,
            ))),
            observed_reason: Mutex::new(None),
        }
    }

    fn observed_reason(&self) -> Option<ExecutionCancellationReason> {
        *self
            .observed_reason
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl JobExecutor for RecoveredCancellationExecutor {
    fn admit(&self, job: &JobIrEnvelope) -> Result<ExecutionAdmission, AdmissionRejection> {
        self.admission_delegate.admit(job)
    }

    fn execute(
        &self,
        request: ExecutionRequest,
        _events: Arc<dyn ExecutionEvents>,
        cancellation: ExecutionCancellation,
    ) -> ExecutorFuture<'_> {
        Box::pin(async move {
            cancellation.token().cancelled().await;
            *self
                .observed_reason
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = cancellation.reason();
            Ok(JobResult::new(
                request.lease().attempt_id(),
                JobConclusion::Cancelled,
                JobSecretExposure::Secretless,
                UnixMillis::new(10_001),
            ))
        })
    }

    fn cleanup(
        &self,
        request: CleanupRequest,
        events: Arc<dyn ExecutionEvents>,
        cancellation: ExecutionCancellation,
    ) -> CleanupFuture<'_> {
        self.admission_delegate
            .cleanup(request, events, cancellation)
    }
}

impl RunnerRuntimeControlClient for TerminalHeartbeatClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        if matches!(request.message(), RunnerToServer::Heartbeat(_)) {
            return Box::pin(async {
                Err(RuntimeControlError::new(
                    RuntimeControlErrorKind::InvalidResponse,
                    RuntimeControlRetry::Never,
                ))
            });
        }
        self.inner.exchange(request, cancellation)
    }
}

#[tokio::test]
async fn scripted_exact_retries_emit_backoffs_without_counting_physical_attempts() {
    let scratch = support::Scratch::new("semantic-retry-observer");
    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let shutdown = CancellationToken::new();
    let client = Arc::new(support::ScriptedControlClient::new(
        session_id,
        shutdown.clone(),
        2,
        0,
    ));
    let clock = Arc::new(support::ManualClock::new(10_000, 50));
    let sleeper = Arc::new(support::ManualDeadlineSleeper::new(Arc::clone(&clock)));
    let observer = Arc::new(RecordingObserver::default());
    let retry = RetryPolicy::new(2, Duration::from_millis(1), Duration::from_millis(2))
        .expect("short retry ramp");
    let runtime = RunnerSessionSupervisor::new(
        support::config_with_retry(runner_id, retry),
        RunnerRuntimePorts::new(
            client,
            journal,
            spool,
            Arc::new(support::NeverExecutor),
            clock,
            sleeper.clone(),
            Arc::new(SystemRuntimeIds),
        )
        .with_observer(observer.clone()),
    );

    let task = tokio::spawn(async move { runtime.run(shutdown).await });
    for _ in 0..32 {
        sleeper.advance(5);
        tokio::task::yield_now().await;
        if task.is_finished() {
            break;
        }
    }
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("manual clock drives retry and idle delays")
        .expect("runtime task")
        .expect("clean scripted shutdown");

    let events = observer.events();
    let retry_backoffs: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            RunnerRuntimeEvent::RetryBackoff {
                exchange, delay, ..
            } => Some((*exchange, *delay)),
            _ => None,
        })
        .collect();
    assert_eq!(retry_backoffs.len(), 2);
    assert!(
        retry_backoffs
            .iter()
            .all(|(kind, delay)| *kind == RuntimeExchangeKind::Handshake && !delay.is_zero())
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event,
                RunnerRuntimeEvent::RetryAttempt {
                    exchange: RuntimeExchangeKind::Handshake,
                }
            ))
            .count(),
        2,
        "one actual repeated request follows each completed retry backoff"
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event,
                RunnerRuntimeEvent::SessionHandshake {
                    outcome: RuntimeSessionOutcome::Opened,
                    ..
                }
            ))
            .count(),
        1
    );
    assert!(events.iter().any(|event| matches!(
        event,
        RunnerRuntimeEvent::LeasePoll {
            outcome: RuntimeLeasePollOutcome::NoWork,
            ..
        }
    )));
    let connection_states: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            RunnerRuntimeEvent::SessionConnected { .. } => Some(true),
            RunnerRuntimeEvent::SessionDisconnected => Some(false),
            _ => None,
        })
        .collect();
    assert_eq!(connection_states, [true, false]);
}

#[tokio::test]
async fn retryable_remote_error_records_the_decision_and_exact_repeated_attempt() {
    let scratch = support::Scratch::new("semantic-remote-retry");
    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let shutdown = CancellationToken::new();
    let inner: Arc<dyn RunnerRuntimeControlClient> = Arc::new(support::ScriptedControlClient::new(
        session_id,
        shutdown.clone(),
        0,
        0,
    ));
    let client = Arc::new(RetryLaterOnceClient::new(inner));
    let observer = Arc::new(RecordingObserver::default());
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client,
            journal,
            spool,
            Arc::new(support::NeverExecutor),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        )
        .with_observer(observer.clone()),
    );

    runtime
        .run(shutdown)
        .await
        .expect("retry-later response is followed by one successful exact retry");

    let events = observer.events();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event,
                RunnerRuntimeEvent::RemoteError {
                    exchange: RuntimeExchangeKind::LeasePoll,
                    kind: RuntimeRemoteErrorKind::RetryLater,
                    disposition: RuntimeRemoteErrorDisposition::Retrying,
                }
            ))
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event,
                RunnerRuntimeEvent::RetryBackoff {
                    exchange: RuntimeExchangeKind::LeasePoll,
                    cause: RuntimeRetryCause::RemoteResponse,
                    ..
                }
            ))
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event,
                RunnerRuntimeEvent::RetryAttempt {
                    exchange: RuntimeExchangeKind::LeasePoll,
                }
            ))
            .count(),
        1
    );
}

#[tokio::test]
async fn stale_session_disconnects_before_reconnect_and_is_terminal_not_retryable() {
    let scratch = support::Scratch::new("semantic-stale-reconnect");
    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let shutdown = CancellationToken::new();
    let client = Arc::new(support::ScriptedControlClient::new(
        session_id,
        shutdown.clone(),
        0,
        1,
    ));
    let observer = Arc::new(RecordingObserver::default());
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client,
            journal,
            spool,
            Arc::new(support::NeverExecutor),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        )
        .with_observer(observer.clone()),
    );

    runtime
        .run(shutdown)
        .await
        .expect("stale session reconnects and subsequent no-work poll shuts down cleanly");

    let events = observer.events();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event,
                RunnerRuntimeEvent::RemoteError {
                    exchange: RuntimeExchangeKind::LeasePoll,
                    kind: RuntimeRemoteErrorKind::Session,
                    disposition: RuntimeRemoteErrorDisposition::Terminal,
                }
            ))
            .count(),
        1
    );
    let connection_states: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            RunnerRuntimeEvent::SessionConnected { .. } => Some(true),
            RunnerRuntimeEvent::SessionDisconnected => Some(false),
            _ => None,
        })
        .collect();
    assert_eq!(connection_states, [true, false, true, false]);
}

#[tokio::test]
async fn recovered_attempt_at_the_exact_authority_boundary_never_restarts() {
    let scratch = support::Scratch::new("semantic-authority-expired");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer_with_authority_expiries(
        journal.as_ref(),
        spool.as_ref(),
        runner_id,
        100_000,
        &[70_000],
    );
    journal
        .transition_lifecycle(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            JobLifecycle::Preparing,
        )
        .expect("seed recovered preparing state");
    journal
        .transition_lifecycle(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            JobLifecycle::Running,
        )
        .expect("seed recovered running state");
    let shutdown = CancellationToken::new();
    let client = Arc::new(CompletionClient::new(
        fixture.session_id,
        fixture.lease,
        UnixMillis::new(70_000),
        shutdown.clone(),
    ));
    let observer = Arc::new(RecordingObserver::default());
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client,
            journal,
            spool,
            Arc::new(support::NeverExecutor),
            Arc::new(support::FixedClock::new(70_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        )
        .with_observer(observer.clone()),
    );

    runtime
        .run(shutdown)
        .await
        .expect("expired runtime authority commits and delivers one failure");

    let events = observer.events();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event,
                RunnerRuntimeEvent::InfrastructureFailure {
                    kind: RuntimeInfrastructureFailure::AuthorityExpired,
                }
            ))
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event,
                RunnerRuntimeEvent::JobCompleted {
                    conclusion: RuntimeJobConclusion::Failure,
                    duration: None,
                }
            ))
            .count(),
        1
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, RunnerRuntimeEvent::JobStarted { .. }))
    );
}

#[tokio::test]
async fn running_authority_expiry_has_distinct_cancellation_and_failure_observations() {
    let scratch = support::Scratch::new("semantic-running-authority-expired");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer_with_authority_expiries(
        journal.as_ref(),
        spool.as_ref(),
        runner_id,
        40_000,
        &[12_000],
    );
    let shutdown = CancellationToken::new();
    let clock = Arc::new(support::ManualClock::new(10_000, 50));
    let sleeper = Arc::new(support::ManualDeadlineSleeper::new(Arc::clone(&clock)));
    let client = Arc::new(support::FailureIsolationClient::new(fixture.session_id));
    let running = Arc::new(AtomicBool::new(false));
    let executor = Arc::new(support::CancellationExecutor::new(Arc::clone(&running)));
    let observer = Arc::new(RecordingObserver::default());
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client.clone(),
            journal,
            spool,
            executor.clone(),
            clock,
            sleeper.clone(),
            Arc::new(SystemRuntimeIds),
        )
        .with_observer(observer.clone()),
    );
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { runtime.run(task_shutdown).await });

    tokio::time::timeout(Duration::from_secs(1), async {
        while !running.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("executor starts before authority expiry");
    sleeper.advance(1_999);
    tokio::task::yield_now().await;
    assert_eq!(executor.observed_reason(), None);
    sleeper.advance(1);
    tokio::time::timeout(Duration::from_secs(1), async {
        while executor.observed_reason() != Some(ExecutionCancellationReason::AuthorityExpired)
            || client.terminal_results().is_empty()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("exact authority boundary cancels and completes the job");

    let events = observer.events();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event,
                RunnerRuntimeEvent::Cancellation {
                    reason: RuntimeCancellationReason::AuthorityExpired,
                }
            ))
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event,
                RunnerRuntimeEvent::InfrastructureFailure {
                    kind: RuntimeInfrastructureFailure::AuthorityExpired,
                }
            ))
            .count(),
        1
    );
    assert!(events.iter().any(|event| matches!(
        event,
        RunnerRuntimeEvent::JobCompleted {
            conclusion: RuntimeJobConclusion::Failure,
            duration: Some(_),
        }
    )));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, RunnerRuntimeEvent::LeaseExpired))
    );

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("observed authority runtime shutdown")
        .expect("runtime task")
        .expect("clean shutdown");
}

#[tokio::test]
async fn recovered_durable_cancellation_observes_the_actual_executor_signal_once() {
    let scratch = support::Scratch::new("semantic-recovered-cancellation");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);
    journal
        .record_cancellation(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            CancellationRecord::new(
                DurableCommand::new(
                    CommandSequence::new(2).expect("second command"),
                    OperationId::new(),
                    Sha256Digest::from_bytes([0x77; 32]),
                ),
                UnixMillis::new(10_001),
            ),
        )
        .expect("seed already-durable cancellation");
    let shutdown = CancellationToken::new();
    let client = Arc::new(CompletionClient::new(
        fixture.session_id,
        fixture.lease,
        UnixMillis::new(10_000),
        shutdown.clone(),
    ));
    let executor = Arc::new(RecoveredCancellationExecutor::new());
    let observer = Arc::new(RecordingObserver::default());
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client,
            journal,
            spool,
            executor.clone(),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::CancellationAwareSleeper::default()),
            Arc::new(SystemRuntimeIds),
        )
        .with_observer(observer.clone()),
    );

    runtime
        .run(shutdown)
        .await
        .expect("recovered cancellation quiesces and completes the executor");

    assert_eq!(
        executor.observed_reason(),
        Some(ExecutionCancellationReason::ServerRequest)
    );
    assert_eq!(
        observer
            .events()
            .iter()
            .filter(|event| matches!(
                event,
                RunnerRuntimeEvent::Cancellation {
                    reason: RuntimeCancellationReason::ServerRequest,
                }
            ))
            .count(),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn cleanup_attempts_observe_each_real_error_and_success_once() {
    let scratch = support::Scratch::new("semantic-cleanup-attempts");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let failed = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);
    let survivor = support::seed_additional_accepted_offer(
        journal.as_ref(),
        spool.as_ref(),
        runner_id,
        failed.session_id,
        2,
        2,
    );
    let shutdown = CancellationToken::new();
    let executor = Arc::new(support::CleanupIsolationExecutor::default());
    let client = Arc::new(support::CleanupIsolationClient::new(
        failed.session_id,
        failed.lease.attempt_id(),
        survivor.lease.attempt_id(),
    ));
    let observer = Arc::new(RecordingObserver::default());
    let retry = RetryPolicy::new(2, Duration::from_millis(1), Duration::from_millis(2))
        .expect("short cleanup retry ramp");
    let runtime = RunnerSessionSupervisor::new(
        support::config_with_slots_and_retry(runner_id, 2, retry),
        RunnerRuntimePorts::new(
            client.clone(),
            journal,
            spool,
            executor.clone(),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(automata_ci_runner_runtime::TokioRuntimeSleeper),
            Arc::new(SystemRuntimeIds),
        )
        .with_observer(observer.clone()),
    );
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { runtime.run(task_shutdown).await });

    tokio::time::timeout(
        Duration::from_secs(1),
        executor.wait_until_cleanup_is_parked(),
    )
    .await
    .expect("second cleanup attempt parks after the first uncertain error");
    assert_eq!(
        observer
            .events()
            .iter()
            .filter(|event| matches!(
                event,
                RunnerRuntimeEvent::Cleanup {
                    outcome: RuntimeOperationOutcome::Error,
                    ..
                }
            ))
            .count(),
        1
    );
    assert!(!observer.events().iter().any(|event| matches!(
        event,
        RunnerRuntimeEvent::Cleanup {
            outcome: RuntimeOperationOutcome::Success,
            ..
        }
    )));

    executor.release_cleanup();
    tokio::time::timeout(Duration::from_secs(1), client.wait_for_released_slot_poll())
        .await
        .expect("successful cleanup permits terminal acknowledgement and slot release");
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("two-slot runtime shuts down")
        .expect("runtime task")
        .expect("clean shutdown after cleanup observations");

    let events = observer.events();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event,
                RunnerRuntimeEvent::Cleanup {
                    outcome: RuntimeOperationOutcome::Error,
                    ..
                }
            ))
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event,
                RunnerRuntimeEvent::Cleanup {
                    outcome: RuntimeOperationOutcome::Success,
                    ..
                }
            ))
            .count(),
        1
    );
}

#[tokio::test]
async fn terminal_control_cycle_failure_is_not_misreported_as_process_shutdown() {
    let scratch = support::Scratch::new("semantic-control-failure");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);
    let shutdown = CancellationToken::new();
    let inner = Arc::new(CompletionClient::new(
        fixture.session_id,
        fixture.lease,
        UnixMillis::new(10_000),
        shutdown.clone(),
    ));
    let client = Arc::new(TerminalHeartbeatClient { inner });
    let clock = Arc::new(support::ManualClock::new(10_000, 50));
    let sleeper = Arc::new(support::ManualDeadlineSleeper::new(Arc::clone(&clock)));
    let observer = Arc::new(RecordingObserver::default());
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client,
            journal,
            spool,
            Arc::new(support::AdmittingExecutor),
            clock,
            sleeper.clone(),
            Arc::new(SystemRuntimeIds),
        )
        .with_observer(observer.clone()),
    );

    let task = tokio::spawn(async move { runtime.run(shutdown).await });
    for _ in 0..16 {
        sleeper.advance(2_000);
        tokio::task::yield_now().await;
        if task.is_finished() {
            break;
        }
    }
    let result = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("terminal heartbeat failure finishes the runtime")
        .expect("runtime task");
    assert!(result.is_err());

    let events = observer.events();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event,
                RunnerRuntimeEvent::Cancellation {
                    reason: RuntimeCancellationReason::ControlFailure,
                }
            ))
            .count(),
        1
    );
    assert!(!events.iter().any(|event| matches!(
        event,
        RunnerRuntimeEvent::Cancellation {
            reason: RuntimeCancellationReason::Shutdown,
        }
    )));
}

#[tokio::test]
async fn cross_slot_command_replay_observes_one_new_durable_application() {
    let scratch = support::Scratch::new("semantic-command-replay");
    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let shutdown = CancellationToken::new();
    let client = Arc::new(support::CrossSlotReplayClient::new(
        runner_id,
        session_id,
        shutdown.clone(),
    ));
    let observer = Arc::new(RecordingObserver::default());
    let runtime = RunnerSessionSupervisor::new(
        support::config_with_slots_and_retry(runner_id, 2, RetryPolicy::default()),
        RunnerRuntimePorts::new(
            client,
            journal,
            spool,
            Arc::new(support::NeverExecutor),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        )
        .with_observer(observer.clone()),
    );

    tokio::time::timeout(Duration::from_secs(1), runtime.run(shutdown))
        .await
        .expect("scripted replay completes")
        .expect("replay remains valid");

    let events = observer.events();
    let applied = events
        .iter()
        .filter(|event| {
            matches!(
                event,
                RunnerRuntimeEvent::Command {
                    kind: RuntimeCommandKind::LeaseOffer,
                    outcome: RuntimeCommandOutcome::Applied,
                }
            )
        })
        .count();
    let replayed = events
        .iter()
        .filter(|event| {
            matches!(
                event,
                RunnerRuntimeEvent::Command {
                    kind: RuntimeCommandKind::LeaseOffer,
                    outcome: RuntimeCommandOutcome::Replayed,
                }
            )
        })
        .count();
    assert_eq!(applied, 1, "durable command application is counted once");
    assert!(
        replayed >= 1,
        "each verified replay is classified separately"
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn applied_cancellation_and_replay_keep_semantic_transition_exactly_once() {
    let scratch = support::Scratch::new("semantic-cancellation-replay");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);
    let shutdown = CancellationToken::new();
    let running = Arc::new(AtomicBool::new(false));
    let executor = Arc::new(support::CancellationExecutor::new(Arc::clone(&running)));
    let client = Arc::new(support::CancellationFlowClient::new(
        fixture.session_id,
        fixture.lease,
        running,
        shutdown.clone(),
    ));
    let observer = Arc::new(RecordingObserver::default());
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client,
            journal,
            spool,
            executor,
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        )
        .with_observer(observer.clone()),
    );

    runtime
        .run(shutdown)
        .await
        .expect("cancelled job and terminal delivery complete");

    let events = observer.events();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event,
                RunnerRuntimeEvent::Command {
                    kind: RuntimeCommandKind::Cancellation,
                    outcome: RuntimeCommandOutcome::Applied,
                }
            ))
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event,
                RunnerRuntimeEvent::Cancellation {
                    reason: RuntimeCancellationReason::ServerRequest,
                }
            ))
            .count(),
        1,
        "replayed cancellation does not recount the durable transition"
    );
    assert!(events.iter().any(|event| matches!(
        event,
        RunnerRuntimeEvent::Command {
            kind: RuntimeCommandKind::Cancellation,
            outcome: RuntimeCommandOutcome::Replayed,
        }
    )));
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, RunnerRuntimeEvent::JobStarted { .. }))
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event,
                RunnerRuntimeEvent::JobCompleted {
                    conclusion: RuntimeJobConclusion::Cancelled,
                    ..
                }
            ))
            .count(),
        1
    );
    for stage in [
        RuntimeTerminalResultStage::Committed,
        RuntimeTerminalResultStage::Acknowledged,
    ] {
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(
                    event,
                    RunnerRuntimeEvent::TerminalResult {
                        stage: observed_stage,
                        conclusion: RuntimeJobConclusion::Cancelled,
                    } if *observed_stage == stage
                ))
                .count(),
            1,
            "terminal result stage {stage:?} is observed once"
        );
    }
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event,
                RunnerRuntimeEvent::OrphanRecovery {
                    outcome: RuntimeOperationOutcome::Success,
                    ..
                }
            ))
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event,
                RunnerRuntimeEvent::LeaseResponseAcknowledged {
                    disposition: RuntimeLeaseDisposition::Accepted,
                }
            ))
            .count(),
        1
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, RunnerRuntimeEvent::CommandAcknowledged))
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, RunnerRuntimeEvent::LogBatchAcknowledged { .. }))
    );
}
