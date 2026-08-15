use super::support;

use std::{
    fmt, future,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
};

use automata_ci_core::{
    JobIrEnvelope, JobLifecycle, LogSequence, LogStreamId, OperationId, RunnerId, RunnerSessionId,
    UnixMillis,
};
use automata_ci_protocol::{
    CommandCursor, HandshakeErrorCode, HandshakeRejected, NegotiatedSession,
    OrphanDeliveryPermissions, RunnerToServer, SUPPORTED_PROTOCOL_RANGE, ServerHello, ServerTiming,
    ServerToRunner, SessionDisposition, SessionOrphanAuthorization,
};
use automata_ci_runner_journal::{
    EndpointOperation, EndpointOperationKind, EndpointRequestContentRef, LogSegment,
    LogSegmentPublication, ProviderFailureKind, ProviderFailureOutcome, ProviderName,
    ProviderOperation, ProviderOperationKind, RunnerJournal, SandboxHandle, SandboxIdentity,
    TerminalResultRecord,
};
use automata_ci_runner_runtime::{
    AdmissionRejection, CleanupFuture, CleanupRequest, ExecutionAdmission, ExecutionCancellation,
    ExecutionCancellationReason, ExecutionEvents, ExecutionRequest, ExecutorError,
    ExecutorErrorKind, ExecutorFuture, JobExecutor, NoopRunnerRuntimeObserver,
    RunnerRuntimeControlClient, RunnerRuntimeError, RunnerRuntimeEvent, RunnerRuntimeObserver,
    RunnerRuntimePorts, RunnerSessionSupervisor, RuntimeControlError, RuntimeControlErrorKind,
    RuntimeControlFuture, RuntimeControlReply, RuntimeControlRetry, RuntimeOperationOutcome,
    SystemRuntimeIds,
};
use automata_ci_runner_spool::{ContentCommitmentDomain, ContentKind, DurableContentStore};
use automata_ci_runner_transport::PreparedRequest;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug)]
enum AuthorityResponse {
    Exact(OrphanDeliveryPermissions),
    WrongSession,
    Unauthorized,
}

#[derive(Debug)]
struct OrphanControlClient {
    old_session: RunnerSessionId,
    fresh_session: RunnerSessionId,
    authority: AuthorityResponse,
    shutdown: CancellationToken,
    hello_calls: AtomicUsize,
}

impl OrphanControlClient {
    fn new(
        old_session: RunnerSessionId,
        fresh_session: RunnerSessionId,
        authority: AuthorityResponse,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            old_session,
            fresh_session,
            authority,
            shutdown,
            hello_calls: AtomicUsize::new(0),
        }
    }

    fn hello_calls(&self) -> usize {
        self.hello_calls.load(Ordering::SeqCst)
    }

    fn reject(&self, hello: &automata_ci_protocol::RunnerHello) -> ServerToRunner {
        match self.authority {
            AuthorityResponse::Exact(permissions) => {
                ServerToRunner::HandshakeRejected(HandshakeRejected::session_not_resumable(
                    OperationId::new(),
                    hello.operation_id(),
                    SUPPORTED_PROTOCOL_RANGE,
                    SessionOrphanAuthorization::new(self.old_session, permissions),
                    "old session is definitively invalidated",
                ))
            }
            AuthorityResponse::WrongSession => {
                ServerToRunner::HandshakeRejected(HandshakeRejected::session_not_resumable(
                    OperationId::new(),
                    hello.operation_id(),
                    SUPPORTED_PROTOCOL_RANGE,
                    SessionOrphanAuthorization::new(
                        RunnerSessionId::new(),
                        OrphanDeliveryPermissions::new(true, true, true),
                    ),
                    "wrong old session",
                ))
            }
            AuthorityResponse::Unauthorized => {
                ServerToRunner::HandshakeRejected(HandshakeRejected::new(
                    OperationId::new(),
                    hello.operation_id(),
                    HandshakeErrorCode::Unauthorized,
                    SUPPORTED_PROTOCOL_RANGE,
                    "not authorized",
                ))
            }
        }
    }
}

impl RunnerRuntimeControlClient for OrphanControlClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        _cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            let response = match request.message() {
                RunnerToServer::Hello(hello) => {
                    let call = self.hello_calls.fetch_add(1, Ordering::SeqCst);
                    if call == 0 {
                        let resume = hello.resume().expect("old-session resume");
                        assert_eq!(resume.session_id(), self.old_session);
                        self.reject(hello)
                    } else if call == 1 {
                        assert!(hello.resume().is_none(), "fresh hello is one-shot");
                        ServerToRunner::Hello(ServerHello::new(
                            OperationId::new(),
                            hello.operation_id(),
                            NegotiatedSession::new(
                                SUPPORTED_PROTOCOL_RANGE.max(),
                                automata_ci_core::JobIrVersion::current(),
                                self.fresh_session,
                                SessionDisposition::Opened,
                                CommandCursor::initial(),
                            ),
                            ServerTiming::new(
                                automata_ci_core::UnixMillis::new(10_000),
                                1_000,
                                30_000,
                            ),
                        ))
                    } else {
                        panic!("fresh-session negotiation must be one-shot");
                    }
                }
                RunnerToServer::LeaseRequest(request) => {
                    self.shutdown.cancel();
                    ServerToRunner::NoWork(automata_ci_protocol::NoWork::new(
                        automata_ci_protocol::MessageHeader::reply(
                            request.header().protocol_version(),
                            request.header().session_id(),
                            OperationId::new(),
                            request.header().operation_id(),
                        ),
                        1,
                    ))
                }
                _ => return Err(invalid_control_response()),
            };
            RuntimeControlReply::from_message(
                response,
                &automata_ci_protocol::ProtocolLimits::default(),
            )
            .map_err(|_| invalid_control_response())
        })
    }
}

fn invalid_control_response() -> RuntimeControlError {
    RuntimeControlError::new(
        RuntimeControlErrorKind::InvalidResponse,
        RuntimeControlRetry::Never,
    )
}

#[derive(Debug, Default)]
struct OrphanObserver {
    outcomes: Mutex<Vec<RuntimeOperationOutcome>>,
}

impl OrphanObserver {
    fn outcomes(&self) -> Vec<RuntimeOperationOutcome> {
        self.outcomes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl RunnerRuntimeObserver for OrphanObserver {
    fn observe(&self, event: RunnerRuntimeEvent) {
        if let RunnerRuntimeEvent::OrphanRecovery { outcome, .. } = event {
            self.outcomes
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(outcome);
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum CleanupBehavior {
    Block,
    StopThenDestroy,
    Destroy,
    UncertainDestroy,
}

struct OrphanExecutor {
    behavior: CleanupBehavior,
    operations: Mutex<Vec<(ProviderOperationKind, OperationId)>>,
    cleanup_calls: Mutex<Vec<(CleanupRequest, ExecutionCancellation)>>,
    cleanup_started: tokio::sync::Notify,
}

impl OrphanExecutor {
    fn new(behavior: CleanupBehavior) -> Self {
        Self {
            behavior,
            operations: Mutex::new(Vec::new()),
            cleanup_calls: Mutex::new(Vec::new()),
            cleanup_started: tokio::sync::Notify::new(),
        }
    }

    fn operations(&self) -> Vec<(ProviderOperationKind, OperationId)> {
        self.operations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn cleanup_calls(&self) -> Vec<(CleanupRequest, ExecutionCancellation)> {
        self.cleanup_calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    async fn wait_until_cleanup_started(&self) {
        loop {
            let started = self.cleanup_started.notified();
            if !self.cleanup_calls().is_empty() {
                return;
            }
            started.await;
        }
    }

    fn apply(
        &self,
        events: &dyn ExecutionEvents,
        kind: ProviderOperationKind,
    ) -> Result<(), ExecutorError> {
        let operation_id = events
            .begin_provider_operation(kind)
            .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
        self.operations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((kind, operation_id));
        events
            .provider_operation_completed(operation_id)
            .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))
    }
}

impl fmt::Debug for OrphanExecutor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OrphanExecutor")
            .field("behavior", &self.behavior)
            .finish_non_exhaustive()
    }
}

impl JobExecutor for OrphanExecutor {
    fn admit(&self, _job: &JobIrEnvelope) -> Result<ExecutionAdmission, AdmissionRejection> {
        Err(AdmissionRejection::InvalidJob)
    }

    fn execute(
        &self,
        _request: ExecutionRequest,
        _events: Arc<dyn ExecutionEvents>,
        _cancellation: ExecutionCancellation,
    ) -> ExecutorFuture<'_> {
        Box::pin(async { Err(ExecutorError::new(ExecutorErrorKind::Internal)) })
    }

    fn cleanup(
        &self,
        request: CleanupRequest,
        events: Arc<dyn ExecutionEvents>,
        cancellation: ExecutionCancellation,
    ) -> CleanupFuture<'_> {
        Box::pin(async move {
            self.cleanup_calls
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((request, cancellation));
            self.cleanup_started.notify_waiters();
            match self.behavior {
                CleanupBehavior::Block => future::pending().await,
                CleanupBehavior::StopThenDestroy => {
                    self.apply(events.as_ref(), ProviderOperationKind::StopSandbox)?;
                    self.apply(events.as_ref(), ProviderOperationKind::DestroySandbox)
                }
                CleanupBehavior::Destroy => {
                    self.apply(events.as_ref(), ProviderOperationKind::DestroySandbox)
                }
                CleanupBehavior::UncertainDestroy => {
                    let operation_id = events
                        .begin_provider_operation(ProviderOperationKind::DestroySandbox)
                        .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
                    self.operations
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push((ProviderOperationKind::DestroySandbox, operation_id));
                    events
                        .provider_operation_failed(
                            operation_id,
                            ProviderFailureOutcome::Uncertain(ProviderFailureKind::Unavailable),
                        )
                        .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
                    Err(ExecutorError::new(ExecutorErrorKind::Unavailable))
                }
            }
        })
    }
}

fn seed_terminal_sandbox(
    journal: &dyn RunnerJournal,
    spool: &dyn DurableContentStore,
    fixture: &support::AcceptedFixture,
) {
    seed_running_sandbox(journal, fixture);
    seed_undelivered_log(journal, spool, fixture);
    let guard = fixture.lease.guard();
    journal
        .transition_lifecycle(
            fixture.session_id,
            fixture.slot,
            guard,
            JobLifecycle::Finalizing,
        )
        .expect("finalizing");
    let result = spool
        .persist(ContentKind::TerminalResult, b"undelivered terminal result")
        .expect("persist result")
        .commit_with(|content| {
            journal.record_terminal_result(
                fixture.session_id,
                fixture.slot,
                guard,
                JobLifecycle::Failed,
                TerminalResultRecord::new(OperationId::new(), content.clone())?,
                UnixMillis::new(10_000),
            )
        });
    assert!(result.is_ok(), "adopt terminal result");
}

fn seed_running_sandbox(journal: &dyn RunnerJournal, fixture: &support::AcceptedFixture) {
    let guard = fixture.lease.guard();
    journal
        .transition_lifecycle(
            fixture.session_id,
            fixture.slot,
            guard,
            JobLifecycle::Preparing,
        )
        .expect("preparing");
    let create = OperationId::new();
    journal
        .record_provider_intent(
            fixture.session_id,
            fixture.slot,
            guard,
            ProviderOperation::intent(create, ProviderOperationKind::CreateSandbox),
        )
        .expect("create intent");
    journal
        .record_sandbox_created(
            fixture.session_id,
            fixture.slot,
            guard,
            create,
            SandboxIdentity::new(
                ProviderName::new("podman").expect("provider"),
                SandboxHandle::new(format!("sandbox:slot-{}", fixture.slot.get()))
                    .expect("opaque handle"),
            ),
        )
        .expect("created");
    let start = OperationId::new();
    journal
        .record_provider_intent(
            fixture.session_id,
            fixture.slot,
            guard,
            ProviderOperation::intent(start, ProviderOperationKind::StartSandbox),
        )
        .expect("start intent");
    journal
        .complete_provider_operation(fixture.session_id, fixture.slot, guard, start)
        .expect("started");
    journal
        .transition_lifecycle(
            fixture.session_id,
            fixture.slot,
            guard,
            JobLifecycle::Running,
        )
        .expect("running");
}

fn seed_ambiguous_endpoint(
    journal: &dyn RunnerJournal,
    spool: &dyn DurableContentStore,
    fixture: &support::AcceptedFixture,
    cancellation_requested: bool,
) {
    seed_running_sandbox(journal, fixture);
    let operation_id = OperationId::new();
    let commitment = spool
        .create_keyed_commitment(ContentCommitmentDomain::EndpointRequest, &[0x57; 32])
        .expect("keyed request commitment");
    let publication = spool
        .persist(ContentKind::EndpointRequest, commitment.as_bytes())
        .expect("persist request commitment");
    let adopted = publication.commit_with(|content| {
        let request = EndpointRequestContentRef::new(content.clone())?;
        let operation =
            EndpointOperation::accepted(operation_id, EndpointOperationKind::Wait, request, 64)?;
        journal.accept_endpoint_operation(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            operation,
        )
    });
    if let Err(failure) = adopted {
        let (error, publication) = failure.into_parts();
        publication.abort();
        panic!("accept endpoint operation: {error}");
    }
    journal
        .commit_endpoint_invocation(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            operation_id,
        )
        .expect("commit ambiguous invocation");
    if cancellation_requested {
        journal
            .record_endpoint_cancellation(
                fixture.session_id,
                fixture.slot,
                fixture.lease.guard(),
                operation_id,
            )
            .expect("request ambiguous cancellation");
    }
}

fn seed_undelivered_log(
    journal: &dyn RunnerJournal,
    spool: &dyn DurableContentStore,
    fixture: &support::AcceptedFixture,
) {
    let stream = LogStreamId::new();
    let guard = fixture.lease.guard();
    let opened = journal.open_log_stream(fixture.session_id, fixture.slot, guard, stream);
    assert!(opened.is_ok(), "adopt log stream");
    let produced = spool
        .persist(ContentKind::LogSpool, b"undelivered log frame")
        .expect("persist log")
        .commit_with(|content| {
            journal.record_log_segment(
                fixture.session_id,
                fixture.slot,
                guard,
                LogSegmentPublication::new(
                    stream,
                    None,
                    LogSegment::new(
                        LogSequence::new(0),
                        LogSequence::new(0),
                        1,
                        21,
                        content.clone(),
                        true,
                        true,
                    )?,
                )?,
                UnixMillis::new(10_000),
            )
        });
    assert!(produced.is_ok(), "adopt produced log");
}

fn runtime(
    runner_id: RunnerId,
    client: Arc<dyn RunnerRuntimeControlClient>,
    journal: Arc<automata_ci_runner_journal::FileJournal>,
    spool: Arc<automata_ci_runner_spool::FileSpool>,
    executor: Arc<dyn JobExecutor>,
) -> RunnerSessionSupervisor {
    runtime_with_observer(
        runner_id,
        client,
        journal,
        spool,
        executor,
        Arc::new(NoopRunnerRuntimeObserver),
    )
}

fn runtime_with_observer(
    runner_id: RunnerId,
    client: Arc<dyn RunnerRuntimeControlClient>,
    journal: Arc<automata_ci_runner_journal::FileJournal>,
    spool: Arc<automata_ci_runner_spool::FileSpool>,
    executor: Arc<dyn JobExecutor>,
    observer: Arc<dyn RunnerRuntimeObserver>,
) -> RunnerSessionSupervisor {
    RunnerSessionSupervisor::new(
        support::config_with_slots_and_retry(
            runner_id,
            2,
            automata_ci_runner_runtime::RetryPolicy::default(),
        ),
        RunnerRuntimePorts::new(
            client,
            journal,
            spool,
            executor,
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        )
        .with_observer(observer),
    )
}

fn assert_same_cleanup(actual: &CleanupRequest, expected: &CleanupRequest) {
    assert_eq!(actual.session_id(), expected.session_id());
    assert_eq!(actual.slot(), expected.slot());
    assert_eq!(actual.attempt_id(), expected.attempt_id());
    assert_eq!(actual.guard(), expected.guard());
    assert_eq!(actual.sandbox(), expected.sandbox());
}

fn assert_released(journal: &dyn RunnerJournal) {
    assert!(
        journal
            .snapshot()
            .expect("released custody")
            .slots()
            .is_empty()
    );
}

#[tokio::test]
async fn exact_authority_abandons_two_slots_cleans_sandboxes_and_opens_once() {
    let scratch = support::Scratch::new("orphan-two-slot-recovery");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let first = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);
    let second = support::seed_additional_accepted_offer(
        journal.as_ref(),
        spool.as_ref(),
        runner_id,
        first.session_id,
        2,
        2,
    );
    seed_terminal_sandbox(journal.as_ref(), spool.as_ref(), &first);
    seed_terminal_sandbox(journal.as_ref(), spool.as_ref(), &second);
    let shutdown = CancellationToken::new();
    let client = Arc::new(OrphanControlClient::new(
        first.session_id,
        RunnerSessionId::new(),
        AuthorityResponse::Exact(OrphanDeliveryPermissions::new(true, true, true)),
        shutdown.clone(),
    ));
    let executor = Arc::new(OrphanExecutor::new(CleanupBehavior::StopThenDestroy));

    runtime(
        runner_id,
        client.clone(),
        journal.clone(),
        spool,
        executor.clone(),
    )
    .run(shutdown)
    .await
    .expect("authorized recovery and fresh session");

    assert_eq!(client.hello_calls(), 2);
    assert!(journal.snapshot().expect("snapshot").slots().is_empty());
    let operations = executor.operations();
    assert_eq!(operations.len(), 4);
    assert_eq!(operations[0].0, ProviderOperationKind::StopSandbox);
    assert_eq!(operations[1].0, ProviderOperationKind::DestroySandbox);
}

#[tokio::test]
async fn authorized_orphan_restart_resolves_endpoint_ambiguity_after_exact_cleanup() {
    for cancellation_requested in [false, true] {
        let scratch = support::Scratch::new(if cancellation_requested {
            "orphan-endpoint-cancellation"
        } else {
            "orphan-endpoint-abandonment"
        });
        let runner_id = RunnerId::new();
        let old_session;
        {
            let (journal, spool) = support::durable_ports(&scratch, runner_id);
            let fixture = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);
            old_session = fixture.session_id;
            seed_ambiguous_endpoint(
                journal.as_ref(),
                spool.as_ref(),
                &fixture,
                cancellation_requested,
            );
        }

        let (journal, spool) = support::durable_ports(&scratch, runner_id);
        let shutdown = CancellationToken::new();
        let client = Arc::new(OrphanControlClient::new(
            old_session,
            RunnerSessionId::new(),
            AuthorityResponse::Exact(OrphanDeliveryPermissions::new(true, true, true)),
            shutdown.clone(),
        ));
        let executor = Arc::new(OrphanExecutor::new(CleanupBehavior::Destroy));
        runtime(
            runner_id,
            client.clone(),
            journal.clone(),
            spool,
            executor.clone(),
        )
        .run(shutdown)
        .await
        .expect("authorized endpoint recovery and fresh session");

        assert_eq!(client.hello_calls(), 2);
        assert_released(journal.as_ref());
        assert_eq!(executor.operations().len(), 1);
        assert_eq!(
            executor.operations()[0].0,
            ProviderOperationKind::DestroySandbox
        );
    }
}

#[tokio::test]
async fn durable_authority_and_uncertain_destroy_resume_after_reopen() {
    let scratch = support::Scratch::new("orphan-crash-reopen");
    let runner_id = RunnerId::new();
    let old_session;
    let first_operation;
    {
        let (journal, spool) = support::durable_ports(&scratch, runner_id);
        let fixture = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);
        old_session = fixture.session_id;
        seed_terminal_sandbox(journal.as_ref(), spool.as_ref(), &fixture);
        let client = Arc::new(OrphanControlClient::new(
            old_session,
            RunnerSessionId::new(),
            AuthorityResponse::Exact(OrphanDeliveryPermissions::new(true, true, true)),
            CancellationToken::new(),
        ));
        let executor = Arc::new(OrphanExecutor::new(CleanupBehavior::UncertainDestroy));
        let error = runtime(runner_id, client, journal.clone(), spool, executor.clone())
            .run(CancellationToken::new())
            .await
            .expect_err("uncertain destroy simulates process loss");
        assert!(matches!(error, RunnerRuntimeError::Executor(_)));
        let snapshot = journal.snapshot().expect("durable partial recovery");
        assert!(
            snapshot
                .slot(fixture.slot)
                .expect("slot")
                .orphan()
                .is_some()
        );
        first_operation = executor.operations()[0].1;
    }

    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let shutdown = CancellationToken::new();
    let client = Arc::new(OrphanControlClient::new(
        old_session,
        RunnerSessionId::new(),
        AuthorityResponse::Exact(OrphanDeliveryPermissions::new(true, true, true)),
        shutdown.clone(),
    ));
    let executor = Arc::new(OrphanExecutor::new(CleanupBehavior::Destroy));
    runtime(
        runner_id,
        client.clone(),
        journal.clone(),
        spool,
        executor.clone(),
    )
    .run(shutdown)
    .await
    .expect("reopen resumes durable provider intent");

    assert_eq!(client.hello_calls(), 2);
    assert!(journal.snapshot().expect("released").slots().is_empty());
    assert_eq!(executor.operations()[0].1, first_operation);
}

#[tokio::test]
async fn shutdown_during_orphan_cleanup_retains_custody_and_restart_releases_once() {
    let scratch = support::Scratch::new("orphan-cleanup-shutdown-restart");
    let runner_id = RunnerId::new();
    let old_session;
    let expected_cleanup;
    {
        let (journal, spool) = support::durable_ports(&scratch, runner_id);
        let fixture = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);
        old_session = fixture.session_id;
        seed_terminal_sandbox(journal.as_ref(), spool.as_ref(), &fixture);
        let shutdown = CancellationToken::new();
        let client = Arc::new(OrphanControlClient::new(
            old_session,
            RunnerSessionId::new(),
            AuthorityResponse::Exact(OrphanDeliveryPermissions::new(true, true, true)),
            shutdown.clone(),
        ));
        let executor = Arc::new(OrphanExecutor::new(CleanupBehavior::Block));
        let observer = Arc::new(OrphanObserver::default());
        let supervisor = runtime_with_observer(
            runner_id,
            client.clone(),
            journal.clone(),
            spool,
            executor.clone(),
            observer.clone(),
        );
        let task_shutdown = shutdown.clone();
        let task = tokio::spawn(async move { supervisor.run(task_shutdown).await });
        tokio::time::timeout(
            support::TEST_WATCHDOG,
            executor.wait_until_cleanup_started(),
        )
        .await
        .expect("cleanup entered before shutdown");
        shutdown.cancel();
        tokio::time::timeout(support::TEST_WATCHDOG, task)
            .await
            .expect("shutdown interrupts orphan cleanup")
            .expect("orphan supervisor task joins")
            .expect("coordinator shutdown is normalized by the supervisor");
        assert_eq!(client.hello_calls(), 1);
        assert_eq!(
            observer.outcomes(),
            vec![
                RuntimeOperationOutcome::Success,
                RuntimeOperationOutcome::Cancelled,
            ]
        );
        let calls = executor.cleanup_calls();
        assert_eq!(calls.len(), 1);
        assert!(executor.operations().is_empty());
        assert_eq!(
            calls[0].1.reason(),
            Some(ExecutionCancellationReason::Shutdown)
        );
        expected_cleanup = calls[0].0.clone();
        assert_eq!(expected_cleanup.session_id(), fixture.session_id);
        assert_eq!(expected_cleanup.slot(), fixture.slot);
        assert_eq!(expected_cleanup.attempt_id(), fixture.lease.attempt_id());
        assert_eq!(expected_cleanup.guard(), fixture.lease.guard());
        let snapshot = journal.snapshot().expect("shutdown-retained custody");
        assert_eq!(snapshot.slots().len(), 1);
        let slot = snapshot.slot(fixture.slot).expect("shutdown-retained slot");
        assert!(slot.orphan().is_some());
        assert_eq!(slot.sandbox(), Some(expected_cleanup.sandbox()));
    }
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let shutdown = CancellationToken::new();
    let client = Arc::new(OrphanControlClient::new(
        old_session,
        RunnerSessionId::new(),
        AuthorityResponse::Exact(OrphanDeliveryPermissions::new(true, true, true)),
        shutdown.clone(),
    ));
    let executor = Arc::new(OrphanExecutor::new(CleanupBehavior::Destroy));
    let observer = Arc::new(OrphanObserver::default());
    runtime_with_observer(
        runner_id,
        client.clone(),
        journal.clone(),
        spool,
        executor.clone(),
        observer.clone(),
    )
    .run(shutdown)
    .await
    .expect("restart retries authorized orphan cleanup");
    assert_eq!(observer.outcomes(), vec![RuntimeOperationOutcome::Success]);
    assert_eq!(client.hello_calls(), 2);
    let calls = executor.cleanup_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1.reason(), None);
    assert_same_cleanup(&calls[0].0, &expected_cleanup);
    let operations = executor.operations();
    assert_eq!(operations.len(), 1);
    assert_eq!(operations[0].0, ProviderOperationKind::DestroySandbox);
    assert_released(journal.as_ref());
}

#[tokio::test]
async fn wrong_session_or_unauthorized_response_never_mutates_old_slots() {
    for authority in [
        AuthorityResponse::WrongSession,
        AuthorityResponse::Unauthorized,
    ] {
        let scratch = support::Scratch::new("orphan-adversarial-authority");
        let runner_id = RunnerId::new();
        let (journal, spool) = support::durable_ports(&scratch, runner_id);
        let fixture = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);
        let client = Arc::new(OrphanControlClient::new(
            fixture.session_id,
            RunnerSessionId::new(),
            authority,
            CancellationToken::new(),
        ));
        let error = runtime(
            runner_id,
            client.clone(),
            journal.clone(),
            spool,
            Arc::new(OrphanExecutor::new(CleanupBehavior::StopThenDestroy)),
        )
        .run(CancellationToken::new())
        .await
        .expect_err("untrusted response must not recover");
        assert!(matches!(
            error,
            RunnerRuntimeError::OrphanRecoveryAuthorityInvalid
                | RunnerRuntimeError::HandshakeRejected
        ));
        assert_eq!(client.hello_calls(), 1);
        assert!(
            journal
                .snapshot()
                .expect("preserved")
                .slot(fixture.slot)
                .expect("slot")
                .orphan()
                .is_none()
        );
    }
}

#[tokio::test]
async fn missing_delivery_permission_blocks_abandonment_cleanup_and_fresh_session() {
    let scratch = support::Scratch::new("orphan-missing-log-permission");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);
    seed_terminal_sandbox(journal.as_ref(), spool.as_ref(), &fixture);
    let client = Arc::new(OrphanControlClient::new(
        fixture.session_id,
        RunnerSessionId::new(),
        AuthorityResponse::Exact(OrphanDeliveryPermissions::new(true, false, true)),
        CancellationToken::new(),
    ));
    let executor = Arc::new(OrphanExecutor::new(CleanupBehavior::StopThenDestroy));

    let error = runtime(
        runner_id,
        client.clone(),
        journal.clone(),
        spool,
        executor.clone(),
    )
    .run(CancellationToken::new())
    .await
    .expect_err("missing permission is fail-closed");

    assert!(matches!(
        error,
        RunnerRuntimeError::OrphanRecoveryPermissionMissing
    ));
    assert_eq!(client.hello_calls(), 1);
    assert!(executor.operations().is_empty());
    let slot = journal
        .snapshot()
        .expect("preserved")
        .slot(fixture.slot)
        .cloned()
        .expect("slot");
    assert!(slot.orphan().is_some());
    assert!(!slot.log_delivery().expect("log").is_fully_delivered());
}
