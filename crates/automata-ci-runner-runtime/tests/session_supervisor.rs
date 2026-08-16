use super::support;

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

use automata_ci_core::{
    JobConclusion, JobLifecycle, JobSecretExposure, LogAck, LogChannel, OperationId, RunnerId,
    RunnerSessionId, UnixMillis,
};
use automata_ci_protocol::{
    LogAckMessage, MessageHeader, NegotiatedSession, OperationAck, RunnerToServer,
    SUPPORTED_PROTOCOL_RANGE, ServerHello, ServerTiming, ServerToRunner, SessionDisposition,
};
use automata_ci_runner_journal::{
    CommandDisposition, CommandIgnoredReason, ProviderFailureKind, ProviderFailureOutcome,
    ProviderOperation, ProviderOperationKind, RunnerJournal, RuntimeAuthorityDeliveryRecord,
    SessionBinding,
};
use automata_ci_runner_runtime::{
    ExecutionCancellationReason, MonotonicMillis, RetryPolicy, RunnerRuntimeControlClient,
    RunnerRuntimeError, RunnerRuntimePorts, RunnerSessionSupervisor, RuntimeClock,
    RuntimeControlError, RuntimeControlErrorKind, RuntimeControlFuture, RuntimeControlReply,
    RuntimeControlRetry, SystemRuntimeClock, SystemRuntimeIds, TokioRuntimeSleeper,
};
use automata_ci_runner_spool::{DurableContentStore, FileSpool};
use automata_ci_runner_transport::PreparedRequest;
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
struct RegressingWallClock {
    monotonic: Arc<support::ManualClock>,
    regressed: AtomicBool,
}

impl RegressingWallClock {
    fn new(monotonic: Arc<support::ManualClock>) -> Self {
        Self {
            monotonic,
            regressed: AtomicBool::new(false),
        }
    }

    fn delay_hello_and_regress_wall(&self, millis: u64) {
        self.monotonic.advance_monotonic(millis);
        self.regressed.store(true, Ordering::SeqCst);
    }
}

impl RuntimeClock for RegressingWallClock {
    fn wall_now(&self) -> UnixMillis {
        // The database beacon in these probes is 10_000. Keep local wall time
        // observably disjoint from that clock domain, then regress it during
        // the Hello exchange.
        UnixMillis::new(if self.regressed.load(Ordering::SeqCst) {
            60_000
        } else {
            70_000
        })
    }

    fn monotonic_now(&self) -> MonotonicMillis {
        self.monotonic.monotonic_now()
    }
}

#[derive(Debug)]
struct WatchdogProbeClient {
    session_id: RunnerSessionId,
    clock: Arc<RegressingWallClock>,
    hello_delay_millis: u64,
    first_renewal_expiry: Option<UnixMillis>,
    first_renewal_elapsed_millis: u64,
    hello_observed: AtomicBool,
    heartbeat_count: AtomicUsize,
    invalid_job_rejected: AtomicBool,
    lease_response_count: AtomicUsize,
    heartbeat_changed: tokio::sync::Notify,
    lease_response_changed: tokio::sync::Notify,
    limits: automata_ci_protocol::ProtocolLimits,
}

impl WatchdogProbeClient {
    fn new(
        session_id: RunnerSessionId,
        clock: Arc<RegressingWallClock>,
        hello_delay_millis: u64,
        first_renewal_expiry: Option<UnixMillis>,
    ) -> Self {
        Self {
            session_id,
            clock,
            hello_delay_millis,
            first_renewal_expiry,
            first_renewal_elapsed_millis: 0,
            hello_observed: AtomicBool::new(false),
            heartbeat_count: AtomicUsize::new(0),
            invalid_job_rejected: AtomicBool::new(false),
            lease_response_count: AtomicUsize::new(0),
            heartbeat_changed: tokio::sync::Notify::new(),
            lease_response_changed: tokio::sync::Notify::new(),
            limits: automata_ci_protocol::ProtocolLimits::default(),
        }
    }

    fn with_first_renewal_elapsed(mut self, millis: u64) -> Self {
        self.first_renewal_elapsed_millis = millis;
        self
    }

    async fn wait_for_heartbeats(&self, minimum: usize) {
        loop {
            let changed = self.heartbeat_changed.notified();
            if self.heartbeat_count.load(Ordering::SeqCst) >= minimum {
                return;
            }
            changed.await;
        }
    }

    async fn wait_for_lease_responses(&self, minimum: usize) {
        loop {
            let changed = self.lease_response_changed.notified();
            if self.lease_response_count.load(Ordering::SeqCst) >= minimum {
                return;
            }
            changed.await;
        }
    }

    fn invalid_job_rejected(&self) -> bool {
        self.invalid_job_rejected.load(Ordering::SeqCst)
    }

    fn reply_header(request: MessageHeader) -> MessageHeader {
        MessageHeader::reply(
            request.protocol_version(),
            request.session_id(),
            automata_ci_core::OperationId::new(),
            request.operation_id(),
        )
    }

    fn reply(&self, response: ServerToRunner) -> Result<RuntimeControlReply, RuntimeControlError> {
        RuntimeControlReply::from_message(response, &self.limits).map_err(|_| {
            RuntimeControlError::new(
                RuntimeControlErrorKind::InvalidResponse,
                RuntimeControlRetry::Never,
            )
        })
    }
}

impl RunnerRuntimeControlClient for WatchdogProbeClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            match request.message() {
                RunnerToServer::Hello(hello) => {
                    if !self.hello_observed.swap(true, Ordering::SeqCst)
                        && self.hello_delay_millis != 0
                    {
                        self.clock
                            .delay_hello_and_regress_wall(self.hello_delay_millis);
                    }
                    let resume = hello.resume().expect("watchdog recovery hello");
                    self.reply(ServerToRunner::Hello(ServerHello::new(
                        automata_ci_core::OperationId::new(),
                        hello.operation_id(),
                        NegotiatedSession::new(
                            SUPPORTED_PROTOCOL_RANGE.max(),
                            automata_ci_core::JobIrVersion::current(),
                            self.session_id,
                            SessionDisposition::Resumed,
                            resume.command_cursor(),
                        ),
                        ServerTiming::new(UnixMillis::new(10_000), 1_000, 30_000),
                    )))
                }
                RunnerToServer::LeaseResponse(response) => {
                    if matches!(
                        response.disposition(),
                        automata_ci_protocol::LeaseDisposition::Rejected(
                            automata_ci_protocol::LeaseRejectionReason::InvalidJob
                        )
                    ) {
                        self.invalid_job_rejected.store(true, Ordering::SeqCst);
                    }
                    self.lease_response_count.fetch_add(1, Ordering::SeqCst);
                    self.lease_response_changed.notify_waiters();
                    self.reply(ServerToRunner::OperationAck(OperationAck::new(
                        Self::reply_header(response.header()),
                    )))
                }
                RunnerToServer::Heartbeat(heartbeat) => {
                    let index = self.heartbeat_count.fetch_add(1, Ordering::SeqCst);
                    self.heartbeat_changed.notify_waiters();
                    if index == 0
                        && let Some(expires_at) = self.first_renewal_expiry
                    {
                        self.clock
                            .monotonic
                            .advance_monotonic(self.first_renewal_elapsed_millis);
                        return self.reply(ServerToRunner::LeaseRenewal(
                            automata_ci_protocol::LeaseRenewal::new(
                                Self::reply_header(heartbeat.header()),
                                heartbeat.attempt_id(),
                                heartbeat.guard(),
                                expires_at,
                            ),
                        ));
                    }
                    cancellation.cancelled().await;
                    Err(RuntimeControlError::new(
                        RuntimeControlErrorKind::Cancelled,
                        RuntimeControlRetry::Never,
                    ))
                }
                RunnerToServer::LogBatch(batch) => {
                    let last = batch.frames().last().expect("nonempty log batch");
                    self.reply(ServerToRunner::LogAck(LogAckMessage::new(
                        Self::reply_header(batch.header()),
                        LogAck::new(last.stream_id(), Some(last.sequence())),
                    )))
                }
                RunnerToServer::JobResult(result) => self.reply(ServerToRunner::OperationAck(
                    OperationAck::new(Self::reply_header(result.header())),
                )),
                RunnerToServer::LeaseRequest(_) => {
                    cancellation.cancelled().await;
                    Err(RuntimeControlError::new(
                        RuntimeControlErrorKind::Cancelled,
                        RuntimeControlRetry::Never,
                    ))
                }
                _ => Err(RuntimeControlError::new(
                    RuntimeControlErrorKind::InvalidResponse,
                    RuntimeControlRetry::Never,
                )),
            }
        })
    }
}

#[tokio::test]
async fn transport_retry_reuses_exact_prepared_request_bytes_and_identity() {
    let scratch = support::Scratch::new("exact-retry");
    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let shutdown = CancellationToken::new();
    let client = Arc::new(support::ScriptedControlClient::new(
        session_id,
        shutdown.clone(),
        6,
        0,
    ));
    let retry = RetryPolicy::new(2, Duration::from_millis(1), Duration::from_millis(2))
        .expect("short retry ramp");
    let runtime = RunnerSessionSupervisor::new(
        support::config_with_retry(runner_id, retry),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            Arc::new(support::NeverExecutor),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );

    runtime.run(shutdown).await.expect("clean test shutdown");
    let observed = client.observed();
    let hellos: Vec<_> = observed
        .iter()
        .filter(|item| item.is_hello)
        .cloned()
        .collect();
    assert_eq!(hellos.len(), 7);
    assert_exact_retry(&hellos);
    support::assert_session(journal.as_ref(), session_id);
}

#[tokio::test]
async fn outage_beyond_the_backoff_ramp_recovers_without_abandoning_the_poll_or_session() {
    let scratch = support::Scratch::new("extended-poll-outage");
    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let shutdown = CancellationToken::new();
    let client = Arc::new(support::RecoveringPollClient::new(
        session_id,
        6,
        Some(shutdown.clone()),
    ));
    let retry = RetryPolicy::new(2, Duration::from_millis(1), Duration::from_millis(2))
        .expect("short retry ramp");
    let runtime = RunnerSessionSupervisor::new(
        support::config_with_retry(runner_id, retry),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            Arc::new(support::NeverExecutor),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );

    runtime.run(shutdown).await.expect("outage must recover");

    let hellos = client.hellos();
    assert_eq!(hellos.len(), 1, "availability loss does not churn sessions");
    let polls = client.polls();
    assert_eq!(polls.len(), 7);
    assert_exact_retry(&polls);
    support::assert_session(journal.as_ref(), session_id);
}

#[tokio::test]
async fn duplicate_cross_slot_command_cancels_ack_waiters_without_a_convoy() {
    let scratch = support::Scratch::new("cross-slot-command-replay");
    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let shutdown = CancellationToken::new();
    let client = Arc::new(support::CrossSlotReplayClient::new(
        runner_id,
        session_id,
        shutdown.clone(),
    ));
    let runtime = RunnerSessionSupervisor::new(
        support::config_with_slots_and_retry(runner_id, 2, RetryPolicy::default()),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            Arc::new(support::NeverExecutor),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );

    tokio::time::timeout(Duration::from_secs(1), runtime.run(shutdown))
        .await
        .expect("ACK holder and waiter observe cancellation promptly")
        .expect("cross-slot command and exact replay remain idempotent");

    assert_eq!(client.acknowledgement_calls(), 1);
    let snapshot = journal.snapshot().expect("durable cross-slot offer");
    assert!(
        snapshot
            .slot(automata_ci_protocol::RunnerSlotOrdinal::new(1).expect("target slot"))
            .is_some(),
        "the command's embedded stable slot is authoritative"
    );
    assert!(
        snapshot
            .slot(automata_ci_protocol::RunnerSlotOrdinal::new(2).expect("carrier slot"))
            .is_none(),
        "duplicate delivery does not retarget the command"
    );
    let durable_session = snapshot.session().expect("durable session");
    assert_eq!(durable_session.command_tombstones().len(), 1);
    assert_eq!(
        durable_session.command_tombstones()[0].disposition(),
        CommandDisposition::Applied
    );
}

#[tokio::test]
async fn nested_offer_publication_unwinds_before_capacity_reconciliation_and_exact_retry() {
    let scratch = support::Scratch::new("nested-offer-capacity-retry");
    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let journal = Arc::new(
        automata_ci_runner_journal::FileJournal::open(scratch.journal_root(), runner_id)
            .expect("open capacity journal"),
    );
    let spool = Arc::new(support::NestedOfferCapacityProbeSpool::new(
        FileSpool::open(
            scratch.spool_root(),
            Arc::new(support::TestProtector::new()),
        )
        .expect("open capacity spool"),
    ));
    let shutdown = CancellationToken::new();
    let client = Arc::new(support::CrossSlotReplayClient::with_authority_delivery(
        runner_id,
        session_id,
        shutdown.clone(),
    ));
    let runtime = RunnerSessionSupervisor::new(
        support::config_with_slots_and_retry(runner_id, 2, RetryPolicy::default()),
        RunnerRuntimePorts::new(
            client,
            journal.clone(),
            spool.clone(),
            Arc::new(support::AdmittingExecutor),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );

    tokio::time::timeout(Duration::from_secs(2), runtime.run(shutdown))
        .await
        .expect("nested publication retry does not deadlock its abandoned fence")
        .expect("offer remains durable after capacity reclamation");

    assert!(spool.completed_fault_cycle());
    assert_eq!(spool.reconciliations(), 1);
    let snapshot = journal.snapshot().expect("retried offer snapshot");
    let durable = snapshot
        .slot(automata_ci_protocol::RunnerSlotOrdinal::new(1).expect("slot"))
        .expect("offer is adopted exactly once");
    spool
        .load(durable.offer().job_ir().content())
        .expect("retried JobIR content remains available");
    spool
        .load(
            durable
                .runtime_authority_delivery()
                .expect("post-accept authority delivery")
                .content()
                .content(),
        )
        .expect("retried authority content remains available");
}

#[tokio::test]
async fn command_during_command_ack_advances_the_ack_and_both_slots_keep_running() {
    let scratch = support::Scratch::new("command-during-command-ack");
    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let shutdown = CancellationToken::new();
    let client = Arc::new(support::CommandDuringAckClient::new(
        runner_id,
        session_id,
        shutdown.clone(),
    ));
    let executor = Arc::new(support::AckProgressExecutor::default());
    let retry = RetryPolicy::new(2, Duration::from_millis(1), Duration::from_millis(2))
        .expect("short exact ACK retry");
    let runtime = RunnerSessionSupervisor::new(
        support::config_with_slots_and_retry(runner_id, 2, retry),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            executor.clone(),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );

    tokio::time::timeout(Duration::from_secs(2), runtime.run(shutdown))
        .await
        .expect("new command must not livelock the older ACK")
        .expect("runner shuts down after both providers keep working");

    assert_eq!(client.acknowledgement_cursors(), vec![1, 2, 2]);
    let first_ack = client.acknowledgement_requests(1);
    let second_ack = client.acknowledgement_requests(2);
    assert_eq!(first_ack.len(), 1);
    assert_exact_retry(&second_ack);
    assert_ne!(
        first_ack[0].operation_id, second_ack[0].operation_id,
        "advancing the durable cursor creates a new stable ACK identity"
    );
    assert_eq!(executor.started_slots(), 0b11);

    let mut expected_attempts = client.expected_attempts();
    expected_attempts.sort_unstable();
    let mut heartbeat_attempts = client.running_heartbeats();
    heartbeat_attempts.sort_unstable();
    assert_eq!(heartbeat_attempts, expected_attempts);

    let snapshot = journal.snapshot().expect("two durable commands");
    let durable_session = snapshot.session().expect("durable session");
    assert_eq!(
        durable_session
            .command_cursor()
            .acknowledged_through()
            .expect("second command is durable")
            .get(),
        2
    );
    assert_eq!(snapshot.slots().len(), 2);
}

#[tokio::test]
async fn out_of_order_command_waits_for_a_slow_durable_predecessor() {
    let scratch = support::Scratch::new("slow-command-predecessor");
    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let shutdown = CancellationToken::new();
    let sleeper = Arc::new(support::CommandGapSleeper::default());
    let client = Arc::new(support::DelayedPredecessorClient::new(
        runner_id,
        session_id,
        shutdown.clone(),
        sleeper.clone(),
    ));
    let retry = RetryPolicy::new(2, Duration::from_millis(1), Duration::from_millis(2))
        .expect("short retry ramp must not bound command ordering");
    let runtime = RunnerSessionSupervisor::new(
        support::config_with_slots_and_retry(runner_id, 2, retry),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            Arc::new(support::NeverExecutor),
            Arc::new(support::FixedClock::new(10_000, 50)),
            sleeper,
            Arc::new(SystemRuntimeIds),
        ),
    );

    tokio::time::timeout(Duration::from_secs(1), runtime.run(shutdown))
        .await
        .expect("slow predecessor remains cancellation-aware")
        .expect("both commands become durable without a synthetic gap failure");

    let acknowledgement_cursors = client.acknowledgement_cursors();
    assert_eq!(acknowledgement_cursors.last(), Some(&2));
    assert!(
        acknowledgement_cursors
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert_eq!(
        journal
            .snapshot()
            .expect("ordered command snapshot")
            .session()
            .expect("durable session")
            .command_cursor()
            .acknowledged_through()
            .expect("both commands are contiguous")
            .get(),
        2
    );
}

#[tokio::test]
async fn out_of_range_offer_slot_is_consistently_ignored_across_ack_replay() {
    let scratch = support::Scratch::new("out-of-range-slot-replay");
    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let shutdown = CancellationToken::new();
    let client = Arc::new(support::CrossSlotReplayClient::with_out_of_range_target(
        runner_id,
        session_id,
        shutdown.clone(),
    ));
    let runtime = RunnerSessionSupervisor::new(
        support::config_with_slots_and_retry(runner_id, 2, RetryPolicy::default()),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            Arc::new(support::NeverExecutor),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );

    runtime
        .run(shutdown)
        .await
        .expect("out-of-range command replay keeps one ignored disposition");

    assert_eq!(client.acknowledgement_calls(), 1);
    let snapshot = journal.snapshot().expect("durable ignored command");
    assert!(snapshot.slots().is_empty());
    let durable_session = snapshot.session().expect("durable session");
    assert_eq!(durable_session.command_tombstones().len(), 1);
    assert_eq!(
        durable_session.command_tombstones()[0].disposition(),
        CommandDisposition::Ignored(CommandIgnoredReason::InvalidCommand)
    );
}

#[tokio::test]
async fn ignored_slot_unavailable_offer_stays_ignored_after_the_slot_is_released() {
    let scratch = support::Scratch::new("ignored-offer-replay-after-release");
    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let shutdown = CancellationToken::new();
    let client = Arc::new(support::IgnoredOfferReplayClient::new(
        runner_id,
        session_id,
        shutdown.clone(),
    ));
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            Arc::new(support::NeverExecutor),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );

    tokio::time::timeout(support::TEST_WATCHDOG, runtime.run(shutdown))
        .await
        .expect("ignored replay must not wedge the session")
        .expect("durable ignored disposition remains authoritative");

    assert!(client.replay_seen());
    assert_eq!(client.acknowledgement_cursors(), vec![1, 2]);
    let snapshot = journal.snapshot().expect("ignored replay snapshot");
    assert!(snapshot.slots().is_empty());
    let tombstones = snapshot
        .session()
        .expect("durable session")
        .command_tombstones();
    assert_eq!(tombstones.len(), 2);
    assert_eq!(tombstones[0].disposition(), CommandDisposition::Applied);
    assert_eq!(
        tombstones[1].disposition(),
        CommandDisposition::Ignored(CommandIgnoredReason::SlotUnavailable)
    );
}

#[tokio::test]
async fn shutdown_interrupts_an_outage_backoff_without_spinning() {
    let scratch = support::Scratch::new("outage-shutdown");
    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let shutdown = CancellationToken::new();
    let client = Arc::new(support::RecoveringPollClient::new(
        session_id,
        usize::MAX,
        None,
    ));
    let sleeper = Arc::new(support::CancellationAwareSleeper::default());
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            Arc::new(support::NeverExecutor),
            Arc::new(support::FixedClock::new(10_000, 50)),
            sleeper.clone(),
            Arc::new(SystemRuntimeIds),
        ),
    );
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { runtime.run(task_shutdown).await });

    tokio::time::timeout(Duration::from_secs(1), sleeper.wait_until_entered())
        .await
        .expect("runtime enters retry backoff");
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("shutdown is prompt")
        .expect("runtime task")
        .expect("clean shutdown");

    assert_eq!(sleeper.calls(), 1);
    assert_eq!(client.polls().len(), 1);
}

#[tokio::test]
async fn stale_session_reconnects_with_exact_durable_resume_claim() {
    let scratch = support::Scratch::new("stale-resume");
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
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            Arc::new(support::NeverExecutor),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );

    runtime.run(shutdown).await.expect("clean test shutdown");
    let observed = client.observed();
    let hellos: Vec<_> = observed.iter().filter(|item| item.is_hello).collect();
    assert_eq!(hellos.len(), 2);
    assert!(hellos[0].resume.is_none());
    let resume = hellos[1]
        .resume
        .expect("second hello resumes durable session");
    assert_eq!(resume.session_id(), session_id);
    assert_eq!(
        resume.command_cursor(),
        automata_ci_protocol::CommandCursor::initial()
    );
    support::assert_session(journal.as_ref(), session_id);
}

#[tokio::test]
async fn maintenance_reaped_idle_session_opens_one_fresh_session() {
    let scratch = support::Scratch::new("maintenance-reaped-idle-session");
    let runner_id = RunnerId::new();
    let stale_session_id = RunnerSessionId::new();
    let fresh_session_id = RunnerSessionId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let shutdown = CancellationToken::new();
    let client = Arc::new(support::MaintenanceReapClient::new(
        stale_session_id,
        fresh_session_id,
        shutdown.clone(),
    ));
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            Arc::new(support::NeverExecutor),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );

    runtime
        .run(shutdown)
        .await
        .expect("maintenance-reaped idle session must recover");

    assert_eq!(client.hello_calls(), 3);
    assert_eq!(client.poll_calls(), 2);
    support::assert_session(journal.as_ref(), fresh_session_id);
    assert!(
        journal
            .snapshot()
            .expect("fresh snapshot")
            .slots()
            .is_empty()
    );
}

#[tokio::test]
async fn stale_empty_resume_rejection_opens_one_fresh_session() {
    let scratch = support::Scratch::new("stale-empty-resume-fallback");
    let runner_id = RunnerId::new();
    let stale_session_id = RunnerSessionId::new();
    let fresh_session_id = RunnerSessionId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    journal
        .begin_session(SessionBinding::new(
            stale_session_id,
            automata_ci_protocol::SUPPORTED_PROTOCOL_RANGE.max(),
            automata_ci_core::JobIrVersion::current(),
        ))
        .expect("seed stale empty session");
    let shutdown = CancellationToken::new();
    let client = Arc::new(support::ResumeFallbackClient::opens_fresh(
        stale_session_id,
        fresh_session_id,
        shutdown.clone(),
    ));
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            Arc::new(support::NeverExecutor),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );

    runtime
        .run(shutdown)
        .await
        .expect("fresh session opens after stale empty resume");

    assert_eq!(client.hello_calls(), 2);
    support::assert_session(journal.as_ref(), fresh_session_id);
    assert!(
        journal
            .snapshot()
            .expect("fresh snapshot")
            .slots()
            .is_empty()
    );
}

#[tokio::test]
async fn stale_resume_rejection_without_orphan_authority_never_falls_back() {
    let scratch = support::Scratch::new("active-resume-no-fallback");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_recorded_offer(journal.as_ref(), spool.as_ref(), runner_id);
    let client = Arc::new(support::ResumeFallbackClient::opens_fresh(
        fixture.session_id,
        RunnerSessionId::new(),
        CancellationToken::new(),
    ));
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            Arc::new(support::NeverExecutor),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );

    let error = runtime
        .run(CancellationToken::new())
        .await
        .expect_err("active durable work forbids fresh fallback");

    assert!(matches!(
        error,
        RunnerRuntimeError::OrphanRecoveryAuthorityInvalid
    ));
    assert_eq!(client.hello_calls(), 1);
    assert!(
        journal
            .snapshot()
            .expect("preserved recovery state")
            .slot(fixture.slot)
            .is_some()
    );
}

#[tokio::test]
async fn second_handshake_rejection_is_fatal_without_another_fallback() {
    let scratch = support::Scratch::new("fresh-fallback-rejected");
    let runner_id = RunnerId::new();
    let stale_session_id = RunnerSessionId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    journal
        .begin_session(SessionBinding::new(
            stale_session_id,
            automata_ci_protocol::SUPPORTED_PROTOCOL_RANGE.max(),
            automata_ci_core::JobIrVersion::current(),
        ))
        .expect("seed stale empty session");
    let client = Arc::new(support::ResumeFallbackClient::rejects_fresh(
        stale_session_id,
        RunnerSessionId::new(),
        automata_ci_protocol::HandshakeErrorCode::SessionNotResumable,
        CancellationToken::new(),
    ));
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            Arc::new(support::NeverExecutor),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );

    let error = runtime
        .run(CancellationToken::new())
        .await
        .expect_err("second rejection is terminal");

    assert!(matches!(error, RunnerRuntimeError::HandshakeRejected));
    assert_eq!(client.hello_calls(), 2);
    support::assert_session(journal.as_ref(), stale_session_id);
}

#[tokio::test]
async fn authorization_rejection_never_triggers_fresh_fallback() {
    let scratch = support::Scratch::new("unauthorized-resume-no-fallback");
    let runner_id = RunnerId::new();
    let stale_session_id = RunnerSessionId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    journal
        .begin_session(SessionBinding::new(
            stale_session_id,
            automata_ci_protocol::SUPPORTED_PROTOCOL_RANGE.max(),
            automata_ci_core::JobIrVersion::current(),
        ))
        .expect("seed stale empty session");
    let client = Arc::new(support::ResumeFallbackClient::rejects_resume_with(
        stale_session_id,
        automata_ci_protocol::HandshakeErrorCode::Unauthorized,
        CancellationToken::new(),
    ));
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            Arc::new(support::NeverExecutor),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );

    let error = runtime
        .run(CancellationToken::new())
        .await
        .expect_err("authorization rejection is terminal");

    assert!(matches!(error, RunnerRuntimeError::HandshakeRejected));
    assert_eq!(client.hello_calls(), 1);
    support::assert_session(journal.as_ref(), stale_session_id);
}

#[tokio::test]
async fn crash_recovery_reuses_the_exact_deterministic_acceptance() {
    let scratch = support::Scratch::new("accepted-recovery");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);

    let first_shutdown = CancellationToken::new();
    let first_client = Arc::new(support::AcceptanceClient::new(
        fixture.session_id,
        first_shutdown.clone(),
    ));
    RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            first_client.clone(),
            journal.clone(),
            spool.clone(),
            Arc::new(support::AdmittingExecutor),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    )
    .run(first_shutdown)
    .await
    .expect("first process stops after acceptance");
    assert_eq!(
        journal
            .snapshot()
            .expect("snapshot after first process")
            .slot(fixture.slot)
            .expect("durable slot")
            .lifecycle(),
        JobLifecycle::Preparing,
    );

    let second_shutdown = CancellationToken::new();
    let second_client = Arc::new(support::AcceptanceClient::new(
        fixture.session_id,
        second_shutdown.clone(),
    ));
    RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            second_client.clone(),
            journal,
            spool,
            Arc::new(support::AdmittingExecutor),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    )
    .run(second_shutdown)
    .await
    .expect("second process stops after recovered acceptance");

    let first = first_client.acceptance();
    let second = second_client.acceptance();
    assert_eq!(first.operation_id, second.operation_id);
    assert_eq!(first.canonical_bytes, second.canonical_bytes);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_after_protected_authority_resumes_with_only_the_exact_custody_ack() {
    let scratch = support::Scratch::new("authority-custody-ack-restart");
    let runner_id = RunnerId::new();
    let (initial_journal, initial_spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer_with_unacknowledged_runtime_authority(
        initial_journal.as_ref(),
        initial_spool.as_ref(),
        runner_id,
    );
    let expected = initial_journal
        .snapshot()
        .expect("pre-restart snapshot")
        .slot(fixture.slot)
        .and_then(|slot| slot.runtime_authority_delivery())
        .cloned()
        .expect("protected unacknowledged authority delivery");
    assert!(!expected.is_acknowledged());
    drop(initial_journal);
    drop(initial_spool);

    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let shutdown = CancellationToken::new();
    let client = Arc::new(support::AuthorityDeliveryClient::new(
        &fixture,
        support::AuthorityDeliveryReply::Acknowledge,
        shutdown.clone(),
    ));
    let executor = Arc::new(support::AckProgressExecutor::default());
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            executor.clone(),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { runtime.run(task_shutdown).await });

    tokio::time::timeout(support::TEST_WATCHDOG, async {
        while executor.started_slots() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("execution starts only after recovered authority custody is acknowledged");
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("recovered runtime shuts down")
        .expect("recovered runtime task")
        .expect("recovered authority delivery remains executable");

    assert_eq!(
        client.authority_requests(),
        0,
        "protected authority bytes are never re-requested after restart"
    );
    assert_eq!(
        client.authority_acknowledgements(),
        vec![(
            expected.binding(),
            expected.bundle_digest(),
            expected.acknowledgement_operation_id(),
        )],
        "restart replays the exact stable custody acknowledgement"
    );
    assert!(
        journal
            .snapshot()
            .expect("post-restart snapshot")
            .slot(fixture.slot)
            .and_then(|slot| slot.runtime_authority_delivery())
            .is_some_and(RuntimeAuthorityDeliveryRecord::is_acknowledged),
        "the operation ACK is durably committed before execution"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_during_authority_request_or_ack_never_reaches_user_code() {
    for reply in [
        support::AuthorityDeliveryReply::CancelRequest,
        support::AuthorityDeliveryReply::CancelAcknowledgement,
    ] {
        let scratch = support::Scratch::new(match reply {
            support::AuthorityDeliveryReply::CancelRequest => "cancel-authority-request",
            support::AuthorityDeliveryReply::CancelAcknowledgement => "cancel-authority-ack",
            support::AuthorityDeliveryReply::Acknowledge => unreachable!("cancellation cases"),
        });
        let runner_id = RunnerId::new();
        let (journal, spool) = support::durable_ports(&scratch, runner_id);
        let fixture = match reply {
            support::AuthorityDeliveryReply::CancelRequest => {
                support::seed_accepted_offer_without_runtime_authority(
                    journal.as_ref(),
                    spool.as_ref(),
                    runner_id,
                )
            }
            support::AuthorityDeliveryReply::CancelAcknowledgement => {
                support::seed_accepted_offer_with_unacknowledged_runtime_authority(
                    journal.as_ref(),
                    spool.as_ref(),
                    runner_id,
                )
            }
            support::AuthorityDeliveryReply::Acknowledge => unreachable!("cancellation cases"),
        };
        let shutdown = CancellationToken::new();
        let client = Arc::new(support::AuthorityDeliveryClient::new(
            &fixture,
            reply,
            shutdown.clone(),
        ));
        let executor = Arc::new(support::AckProgressExecutor::default());
        let runtime = RunnerSessionSupervisor::new(
            support::config(runner_id),
            RunnerRuntimePorts::new(
                client.clone(),
                journal.clone(),
                spool,
                executor.clone(),
                Arc::new(support::FixedClock::new(10_000, 50)),
                Arc::new(support::ImmediateSleeper),
                Arc::new(SystemRuntimeIds),
            ),
        );

        tokio::time::timeout(support::TEST_WATCHDOG, runtime.run(shutdown))
            .await
            .expect("authority-stage cancellation does not hang")
            .expect("authority-stage cancellation is terminalized locally");

        assert!(client.command_acknowledged());
        assert_eq!(
            executor.started_slots(),
            0,
            "authority-stage cancellation must not admit or execute user code: {reply:?}"
        );
        let snapshot = journal.snapshot().expect("cancelled authority snapshot");
        let durable = snapshot
            .slot(fixture.slot)
            .expect("cancelled slot remains durable");
        assert!(durable.cancellation().is_some());
        assert_eq!(durable.lifecycle(), JobLifecycle::Cancelled);
        assert!(durable.terminal_result().is_some());
        match reply {
            support::AuthorityDeliveryReply::CancelRequest => {
                assert_eq!(client.authority_requests(), 1);
                assert!(client.authority_acknowledgements().is_empty());
                assert!(durable.runtime_authority_delivery().is_none());
            }
            support::AuthorityDeliveryReply::CancelAcknowledgement => {
                assert_eq!(client.authority_requests(), 0);
                assert_eq!(client.authority_acknowledgements().len(), 1);
                assert!(
                    durable
                        .runtime_authority_delivery()
                        .is_some_and(|delivery| !delivery.is_acknowledged()),
                    "cancellation supersedes custody acknowledgement"
                );
            }
            support::AuthorityDeliveryReply::Acknowledge => unreachable!("cancellation cases"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blocked_runtime_authority_request_cannot_withhold_lease_renewal() {
    let scratch = support::Scratch::new("blocked-authority-heartbeat");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer_without_runtime_authority(
        journal.as_ref(),
        spool.as_ref(),
        runner_id,
    );
    let client = Arc::new(support::BlockedAuthorityClient::new(&fixture));
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client.clone(),
            journal,
            spool,
            Arc::new(support::NeverExecutor),
            Arc::new(SystemRuntimeClock::new()),
            Arc::new(TokioRuntimeSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { runtime.run(task_shutdown).await });

    tokio::time::timeout(Duration::from_secs(1), client.wait_for_request())
        .await
        .expect("runtime-authority request remains in flight");
    for minimum in 1..=4 {
        let progressed =
            tokio::time::timeout(Duration::from_secs(1), client.wait_for_heartbeats(minimum)).await;
        assert!(
            progressed.is_ok(),
            "lease renewal {minimum} stalled during runtime authority delivery; observed {:?}",
            client.heartbeat_times(),
        );
    }
    assert_eq!(client.heartbeat_times(), vec![1, 2, 3, 4]);
    assert!(!task.is_finished(), "blocked authority remains slot-local");

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("blocked-authority runner shuts down")
        .expect("runtime task")
        .expect("clean shutdown");
}

#[tokio::test]
async fn admission_rejects_a_non_exact_sandbox_environment_before_execution() {
    let scratch = support::Scratch::new("environment-rejection");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_recorded_offer(journal.as_ref(), spool.as_ref(), runner_id);
    let shutdown = CancellationToken::new();
    let client = Arc::new(support::RejectionClient::new(
        fixture.session_id,
        shutdown.clone(),
    ));
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            Arc::new(support::MismatchedEnvironmentExecutor),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );

    runtime
        .run(shutdown)
        .await
        .expect("mismatched environment is durably rejected");
    assert_eq!(
        client.rejection(),
        Some(automata_ci_protocol::LeaseRejectionReason::CapabilityChanged)
    );
    assert!(
        journal
            .snapshot()
            .expect("snapshot after rejection")
            .slot(fixture.slot)
            .is_none()
    );
}

#[tokio::test]
async fn applied_cancel_replay_after_release_preserves_execution_and_ack_gates() {
    let scratch = support::Scratch::new("durable-cancel");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);
    let shutdown = CancellationToken::new();
    let running = Arc::new(AtomicBool::new(false));
    let executor = Arc::new(support::CancellationExecutor::new(Arc::clone(&running)));
    let client = Arc::new(support::CancellationFlowClient::new(
        fixture.session_id,
        fixture.lease.clone(),
        Arc::clone(&running),
        shutdown.clone(),
    ));
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            executor.clone(),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );

    runtime
        .run(shutdown)
        .await
        .expect("cancelled job delivered");
    assert!(running.load(Ordering::SeqCst));
    assert_eq!(
        executor.observed_reason(),
        Some(ExecutionCancellationReason::ServerRequest)
    );
    let snapshot = journal.snapshot().expect("post-cancellation snapshot");
    assert!(snapshot.slot(fixture.slot).is_none());
    assert_eq!(
        snapshot
            .session()
            .expect("session remains durable")
            .command_cursor()
            .acknowledged_through()
            .expect("cancel tombstone advances cursor")
            .get(),
        2
    );
    assert_exact_retry(&client.log_requests());
    assert_exact_retry(&client.result_requests());
    assert!(client.cancel_replayed_after_release());
}

#[tokio::test]
async fn cancellation_timeout_quiesces_executor_before_sandbox_cleanup() {
    let scratch = support::Scratch::new("cancellation-timeout-quiescence");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);
    let shutdown = CancellationToken::new();
    let running = Arc::new(AtomicBool::new(false));
    let executor = Arc::new(support::CancellationTimeoutExecutor::new(Arc::clone(
        &running,
    )));
    let client = Arc::new(support::CancellationFlowClient::new(
        fixture.session_id,
        fixture.lease,
        Arc::clone(&running),
        shutdown.clone(),
    ));
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client,
            journal.clone(),
            spool,
            executor.clone(),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );

    runtime
        .run(shutdown)
        .await
        .expect("timed-out cancellation is terminalized after quiescence");

    assert!(executor.execution_dropped());
    assert!(executor.cleanup_called());
    assert!(!executor.cleanup_before_drop());
    assert!(
        journal
            .snapshot()
            .expect("post-timeout snapshot")
            .slot(fixture.slot)
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn executor_failure_is_terminalized_per_slot_while_sibling_and_supervisor_continue() {
    let scratch = support::Scratch::new("executor-failure-isolation");
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
    let executor = Arc::new(support::FailureIsolationExecutor::default());
    let client = Arc::new(support::FailureIsolationClient::new(failed.session_id));
    let runtime = RunnerSessionSupervisor::new(
        support::config_with_slots_and_retry(runner_id, 2, RetryPolicy::default()),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            executor.clone(),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { runtime.run(task_shutdown).await });

    tokio::time::timeout(Duration::from_mins(1), client.wait_for_released_slot_poll())
        .await
        .expect("failed slot publishes and releases its terminal result");
    assert!(executor.survivor_started());
    assert!(
        !task.is_finished(),
        "one failed job must not stop the runner"
    );
    assert_eq!(
        client.terminal_results(),
        vec![(failed.lease.attempt_id(), JobConclusion::Failure)]
    );
    let frames = client.log_frames();
    assert_eq!(
        frames.len(),
        support::FAILURE_ISOLATION_LOG_COUNT + 1,
        "runtime appends exactly one terminal frame"
    );
    assert!(
        frames
            .iter()
            .all(|frame| frame.attempt_id() == failed.lease.attempt_id())
    );
    assert_eq!(
        frames
            .iter()
            .map(|frame| frame.sequence().get())
            .collect::<Vec<_>>(),
        (0..=u64::try_from(support::FAILURE_ISOLATION_LOG_COUNT).expect("log count fits u64"))
            .collect::<Vec<_>>(),
        "failed executor logs and runtime EOS remain contiguous"
    );
    assert!(
        frames[..support::FAILURE_ISOLATION_LOG_COUNT]
            .iter()
            .all(|frame| frame.channel() == LogChannel::Stdout
                && !frame.payload().is_empty()
                && !frame.is_end_of_stream())
    );
    let eos = frames.last().expect("runtime EOS");
    assert_eq!(eos.channel(), LogChannel::System);
    assert!(eos.payload().is_empty());
    assert!(eos.is_end_of_stream());
    assert_eq!(
        frames
            .iter()
            .filter(|frame| frame.is_end_of_stream())
            .count(),
        1,
        "runtime never duplicates EOS"
    );
    assert_eq!(
        client.terminal_results_after_eos(),
        vec![true],
        "terminal failure is delivered only after the EOS acknowledgement"
    );
    let snapshot = journal.snapshot().expect("isolated failure snapshot");
    assert!(snapshot.slot(failed.slot).is_none());
    assert!(snapshot.slot(survivor.slot).is_some());

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("runner shutdown")
        .expect("runtime task")
        .expect("clean shutdown after isolated failure");
}

#[tokio::test]
async fn recovered_uncertain_create_without_exact_cleanup_custody_remains_fenced() {
    let scratch = support::Scratch::new("missing-create-cleanup-custody");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);
    let guard = fixture.lease.guard();
    journal
        .transition_lifecycle(
            fixture.session_id,
            fixture.slot,
            guard,
            JobLifecycle::Preparing,
        )
        .expect("begin preparation");
    let create = OperationId::new();
    journal
        .record_provider_intent(
            fixture.session_id,
            fixture.slot,
            guard,
            ProviderOperation::intent(create, ProviderOperationKind::CreateSandbox),
        )
        .expect("record create intent");
    journal
        .fail_provider_operation(
            fixture.session_id,
            fixture.slot,
            guard,
            create,
            ProviderFailureOutcome::Uncertain(ProviderFailureKind::Internal),
        )
        .expect("retain uncertain create");
    support::seed_failed_terminal_without_logs(journal.as_ref(), spool.as_ref(), &fixture);
    let terminal_operation = journal
        .snapshot()
        .expect("terminal snapshot")
        .slot(fixture.slot)
        .and_then(|slot| slot.terminal_result())
        .expect("terminal result")
        .operation_id();
    journal
        .acknowledge_terminal_result(fixture.session_id, fixture.slot, guard, terminal_operation)
        .expect("acknowledge terminal result");

    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            Arc::new(support::FailureIsolationClient::new(fixture.session_id)),
            journal.clone(),
            spool,
            Arc::new(support::FailureIsolationExecutor::default()),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        runtime.run(CancellationToken::new()),
    )
    .await
    .expect("missing custody fails without retrying");
    assert!(matches!(result, Err(RunnerRuntimeError::ExecutorContract)));
    let snapshot = journal.snapshot().expect("fenced snapshot");
    let slot = snapshot.slot(fixture.slot).expect("slot remains fenced");
    assert!(slot.sandbox().is_none());
    assert!(slot.provider_operations().last().is_some_and(|operation| {
        operation.operation_id() == create
            && operation.kind() == ProviderOperationKind::CreateSandbox
            && operation.is_pending()
    }));
}

#[tokio::test]
async fn live_uncertain_create_without_exact_cleanup_custody_fails_before_terminal_delivery() {
    let scratch = support::Scratch::new("live-missing-create-cleanup-custody");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);
    let client = Arc::new(support::FailureIsolationClient::new(fixture.session_id));
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            Arc::new(support::MissingCreateCustodyExecutor),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        runtime.run(CancellationToken::new()),
    )
    .await
    .expect("missing live custody fails without retrying");
    assert!(matches!(result, Err(RunnerRuntimeError::ExecutorContract)));
    assert!(
        client.terminal_results().is_empty(),
        "terminal delivery must not acknowledge a slot without cleanup custody"
    );
    let snapshot = journal.snapshot().expect("fenced live snapshot");
    let slot = snapshot
        .slot(fixture.slot)
        .expect("live slot remains fenced");
    assert!(slot.sandbox().is_none());
    assert!(
        slot.terminal_result()
            .is_some_and(|result| !result.is_acknowledged())
    );
    assert!(slot.provider_operations().last().is_some_and(|operation| {
        operation.kind() == ProviderOperationKind::CreateSandbox && operation.is_pending()
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credential_free_executor_failure_remains_secretless_without_an_authority_deadline() {
    let scratch = support::Scratch::new("credential-free-executor-failure");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture =
        support::seed_accepted_credential_free_offer(journal.as_ref(), spool.as_ref(), runner_id);
    let shutdown = CancellationToken::new();
    let client = Arc::new(support::FailureIsolationClient::new(fixture.session_id));
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            Arc::new(support::FailureIsolationExecutor::default()),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { runtime.run(task_shutdown).await });

    let terminalized =
        tokio::time::timeout(Duration::from_mins(1), client.wait_for_released_slot_poll()).await;
    assert!(
        terminalized.is_ok(),
        "credential-free executor failure is terminalized; task_finished={}; snapshot={:?}",
        task.is_finished(),
        journal.snapshot()
    );

    assert_eq!(
        client.terminal_results(),
        vec![(fixture.lease.attempt_id(), JobConclusion::Failure)]
    );
    assert_eq!(
        client.terminal_secret_exposures(),
        vec![JobSecretExposure::Secretless],
        "zero-credential infrastructure failures remain eligible for public persistence"
    );
    assert!(client.log_frames().iter().any(|frame| {
        frame.channel() == LogChannel::Stdout
            && !frame.payload().is_empty()
            && !frame.is_end_of_stream()
    }));

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("runner shutdown")
        .expect("runtime task")
        .expect("clean shutdown after credential-free failure");
}

#[tokio::test]
async fn runtime_closes_payload_logs_before_success_and_skipped_results() {
    for conclusion in [JobConclusion::Success, JobConclusion::Skipped] {
        let scratch = support::Scratch::new(match conclusion {
            JobConclusion::Success => "runtime-eos-success",
            JobConclusion::Skipped => "runtime-eos-skipped",
            _ => unreachable!("test conclusion is success or skipped"),
        });
        let runner_id = RunnerId::new();
        let (journal, spool) = support::durable_ports(&scratch, runner_id);
        let fixture = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);
        let shutdown = CancellationToken::new();
        let client = Arc::new(support::FailureIsolationClient::new(fixture.session_id));
        let runtime = RunnerSessionSupervisor::new(
            support::config(runner_id),
            RunnerRuntimePorts::new(
                client.clone(),
                journal.clone(),
                spool,
                Arc::new(support::BurstLogExecutor::with_conclusion(1, conclusion)),
                Arc::new(support::FixedClock::new(10_000, 50)),
                Arc::new(support::ImmediateSleeper),
                Arc::new(SystemRuntimeIds),
            ),
        );
        let task_shutdown = shutdown.clone();
        let task = tokio::spawn(async move { runtime.run(task_shutdown).await });

        tokio::time::timeout(Duration::from_secs(5), client.wait_for_terminal_result())
            .await
            .expect("runtime delivers the result after EOS");

        let frames = client.log_frames();
        let executor_payloads = usize::from(conclusion == JobConclusion::Success);
        assert_eq!(
            frames.len(),
            executor_payloads + 1,
            "executor payloads plus exactly one runtime EOS"
        );
        assert!(
            frames[..executor_payloads]
                .iter()
                .all(|frame| !frame.is_end_of_stream())
        );
        let eos = frames.last().expect("runtime EOS");
        assert!(eos.is_end_of_stream());
        assert_eq!(
            eos.sequence().get(),
            u64::try_from(executor_payloads).expect("bounded payload count")
        );
        if conclusion == JobConclusion::Skipped {
            assert!(
                !client
                    .heartbeat_lifecycles()
                    .contains(&JobLifecycle::Running),
                "a skipped job never invents Running progress"
            );
        }
        assert_eq!(client.terminal_results_after_eos(), vec![true]);
        assert_eq!(
            client.terminal_results(),
            vec![(fixture.lease.attempt_id(), conclusion)]
        );
        assert!(
            journal
                .snapshot()
                .expect("post-terminal snapshot")
                .slot(fixture.slot)
                .is_none()
        );

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("runner shutdown")
            .expect("runtime task")
            .expect("clean shutdown after terminal result");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn uncertain_terminal_cleanup_is_parked_and_retried_while_the_sibling_keeps_running() {
    let scratch = support::Scratch::new("cleanup-failure-isolation");
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
    let cleanup_order = Arc::new(support::TerminalCleanupOrderProbe::default());
    let executor = Arc::new(support::CleanupIsolationExecutor::with_order_probe(
        Arc::clone(&cleanup_order),
    ));
    let client = Arc::new(
        support::CleanupIsolationClient::new(
            failed.session_id,
            failed.lease.attempt_id(),
            survivor.lease.attempt_id(),
        )
        .with_order_probe(Arc::clone(&cleanup_order)),
    );
    let retry = RetryPolicy::new(2, Duration::from_millis(1), Duration::from_millis(2))
        .expect("short cleanup retry ramp");
    let runtime = RunnerSessionSupervisor::new(
        support::config_with_slots_and_retry(runner_id, 2, retry),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            executor.clone(),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(automata_ci_runner_runtime::TokioRuntimeSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { runtime.run(task_shutdown).await });

    tokio::time::timeout(Duration::from_secs(15), async {
        executor.wait_until_cleanup_is_parked().await;
        loop {
            if client.finalizing_heartbeats() > 0
                && client.survivor_heartbeats() > 0
                && client.survivor_logs() > 0
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cleanup parks while both slots continue control traffic");

    assert!(executor.survivor_started());
    assert!(!task.is_finished(), "cleanup failure is slot-local");
    assert_parked_cleanup(
        journal.as_ref(),
        &failed,
        &survivor,
        executor.as_ref(),
        client.as_ref(),
    );
    assert_terminal_cleanup_order(cleanup_order.as_ref(), false);

    executor.release_cleanup();
    tokio::time::timeout(
        Duration::from_secs(15),
        client.wait_for_released_slot_poll(),
    )
    .await
    .expect("safe cleanup completes before result ACK and release");
    assert_eq!(
        client.terminal_results(),
        vec![(failed.lease.attempt_id(), JobConclusion::Failure)]
    );
    assert_terminal_cleanup_order(cleanup_order.as_ref(), true);
    let snapshot = journal.snapshot().expect("post-cleanup snapshot");
    assert!(snapshot.slot(failed.slot).is_none());
    assert!(snapshot.slot(survivor.slot).is_some());

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(15), task)
        .await
        .expect("two-slot runner shutdown")
        .expect("runtime task")
        .expect("clean shutdown after cleanup isolation");
}

fn assert_terminal_cleanup_order(probe: &support::TerminalCleanupOrderProbe, completed: bool) {
    let mut expected = vec![
        support::TerminalCleanupStage::PayloadAcknowledged,
        support::TerminalCleanupStage::EosAcknowledged,
        support::TerminalCleanupStage::SandboxDestroyStarted,
        support::TerminalCleanupStage::SandboxDestroyStarted,
    ];
    if completed {
        expected.extend([
            support::TerminalCleanupStage::TerminalResultDelivered,
            support::TerminalCleanupStage::ReleasedSlotPolled,
        ]);
    }
    assert_eq!(
        probe.stages(),
        expected,
        "payload and EOS precede destruction, result delivery, and durable clear"
    );
}

fn assert_parked_cleanup(
    journal: &dyn RunnerJournal,
    failed: &support::AcceptedFixture,
    survivor: &support::AcceptedFixture,
    executor: &support::CleanupIsolationExecutor,
    client: &support::CleanupIsolationClient,
) {
    assert!(client.terminal_results().is_empty());
    let snapshot = journal.snapshot().expect("parked cleanup snapshot");
    let parked = snapshot.slot(failed.slot).expect("failed slot is retained");
    assert!(parked.sandbox().is_some());
    let log_delivery = parked
        .log_delivery()
        .expect("terminal payload and EOS stay durable during cleanup");
    assert!(log_delivery.end_of_stream().is_some());
    assert!(log_delivery.is_fully_delivered());
    assert!(
        parked
            .terminal_result()
            .is_some_and(|result| !result.is_acknowledged())
    );
    let pending = parked
        .provider_operations()
        .last()
        .expect("uncertain destroy operation");
    assert_eq!(
        pending.kind(),
        automata_ci_runner_journal::ProviderOperationKind::DestroySandbox
    );
    assert_eq!(
        pending.outcome(),
        automata_ci_runner_journal::ProviderOperationOutcome::Failed(
            automata_ci_runner_journal::ProviderFailureOutcome::Uncertain(
                automata_ci_runner_journal::ProviderFailureKind::Unavailable,
            ),
        )
    );
    assert!(snapshot.slot(survivor.slot).is_some());
    let operations = executor.cleanup_operations();
    assert_eq!(operations.len(), 2);
    assert_eq!(operations[0], operations[1]);
}

#[tokio::test]
async fn monotonic_watchdog_contains_an_expired_slot_without_stopping_the_supervisor() {
    let scratch = support::Scratch::new("disconnected-watchdog");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);
    let clock = Arc::new(support::ManualClock::new(10_000, 50));
    let client = Arc::new(support::DisconnectedHeartbeatClient::new(
        fixture.session_id,
        clock.clone(),
    ));
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client.clone(),
            journal,
            spool,
            Arc::new(support::AdmittingExecutor),
            clock,
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );

    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { runtime.run(task_shutdown).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while client.heartbeat_requests().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("heartbeat renewal starts before containment");
    let heartbeats = client.heartbeat_requests();
    assert!(!heartbeats.is_empty());
    if heartbeats.len() >= 2 {
        assert_exact_retry(&heartbeats);
    }
    assert!(
        !task.is_finished(),
        "an expired slot remains authority-gated without killing the runner"
    );
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("contained runner shuts down")
        .expect("runtime task")
        .expect("clean shutdown");
}

#[tokio::test]
async fn lease_watchdog_anchors_database_time_before_hello_delay_and_wall_regression() {
    let scratch = support::Scratch::new("lease-clock-anchor");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);
    let monotonic = Arc::new(support::ManualClock::new(10_000, 50));
    let clock = Arc::new(RegressingWallClock::new(Arc::clone(&monotonic)));
    let sleeper = Arc::new(support::ManualDeadlineSleeper::new(Arc::clone(&monotonic)));
    let client = Arc::new(WatchdogProbeClient::new(
        fixture.session_id,
        Arc::clone(&clock),
        10_000,
        None,
    ));
    let running = Arc::new(AtomicBool::new(false));
    let executor = Arc::new(support::CancellationExecutor::new(Arc::clone(&running)));
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client,
            journal,
            spool,
            executor.clone(),
            clock,
            sleeper.clone(),
            Arc::new(SystemRuntimeIds),
        ),
    );
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { runtime.run(task_shutdown).await });

    tokio::time::timeout(Duration::from_secs(1), async {
        while !running.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("executor starts after delayed recovery hello");
    assert_eq!(sleeper.monotonic_now(), MonotonicMillis::new(10_050));

    sleeper.advance(19_999);
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(executor.observed_reason(), None);

    sleeper.advance(1);
    tokio::time::timeout(Duration::from_secs(1), async {
        while executor.observed_reason() != Some(ExecutionCancellationReason::LeaseExpired) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("pre-send monotonic anchor expires at the conservative server boundary");

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("anchored watchdog shuts down")
        .expect("runtime task")
        .expect("clean shutdown");
}

async fn assert_expired_renewal_fails_closed_synchronously(
    scratch_label: &str,
    renewal_elapsed_millis: u64,
    expected_monotonic: u64,
) {
    let scratch = support::Scratch::new(scratch_label);
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);
    let monotonic = Arc::new(support::ManualClock::new(10_000, 50));
    let clock = Arc::new(RegressingWallClock::new(Arc::clone(&monotonic)));
    let sleeper = Arc::new(support::ManualDeadlineSleeper::new(Arc::clone(&monotonic)));
    let client = Arc::new(
        WatchdogProbeClient::new(
            fixture.session_id,
            Arc::clone(&clock),
            0,
            Some(UnixMillis::new(40_001)),
        )
        .with_first_renewal_elapsed(renewal_elapsed_millis),
    );
    let running = Arc::new(AtomicBool::new(false));
    let executor = Arc::new(support::CancellationExecutor::new(Arc::clone(&running)));
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            executor.clone(),
            clock,
            sleeper.clone(),
            Arc::new(SystemRuntimeIds),
        ),
    );
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { runtime.run(task_shutdown).await });

    tokio::time::timeout(Duration::from_secs(1), async {
        while !running.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("executor starts before renewal");

    sleeper.advance(1_000);
    client.wait_for_heartbeats(1).await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while executor.observed_reason().is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("expired renewal fails closed without waiting for the watchdog task");
    assert_eq!(
        executor.observed_reason(),
        Some(ExecutionCancellationReason::LeaseExpired)
    );
    assert_eq!(client.heartbeat_count.load(Ordering::SeqCst), 1);
    assert_eq!(
        sleeper.monotonic_now(),
        MonotonicMillis::new(expected_monotonic)
    );
    assert_eq!(
        journal
            .snapshot()
            .expect("stale renewal snapshot")
            .slot(fixture.slot)
            .expect("expired slot remains isolated")
            .expires_at(),
        UnixMillis::new(40_001),
        "the exact renewal is durable before authority fails closed"
    );
    assert!(!task.is_finished(), "the expired slot remains contained");

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("expired-renewal runner shuts down")
        .expect("runtime task")
        .expect("clean shutdown");
}

#[tokio::test]
async fn lease_renewal_equal_to_resampled_database_time_fails_closed_synchronously() {
    assert_expired_renewal_fails_closed_synchronously("equal-renewal-expiry", 29_001, 30_051).await;
}

#[tokio::test]
async fn lease_renewal_stale_at_resampled_database_time_fails_closed_synchronously() {
    assert_expired_renewal_fails_closed_synchronously("stale-renewal-expiry", 29_002, 30_052).await;
}

#[tokio::test]
async fn acknowledged_delivery_authority_liveness_uses_the_monotonic_database_beacon() {
    let scratch = support::Scratch::new("offer-authority-db-beacon");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer_with_authority_expiries(
        journal.as_ref(),
        spool.as_ref(),
        runner_id,
        80_000,
        &[30_000],
    );
    let monotonic = Arc::new(support::ManualClock::new(10_000, 50));
    let clock = Arc::new(RegressingWallClock::new(Arc::clone(&monotonic)));
    let sleeper = Arc::new(support::ManualDeadlineSleeper::new(Arc::clone(&monotonic)));
    let client = Arc::new(WatchdogProbeClient::new(
        fixture.session_id,
        Arc::clone(&clock),
        60_000,
        None,
    ));
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            Arc::new(support::AdmittingExecutor),
            clock,
            sleeper,
            Arc::new(SystemRuntimeIds),
        ),
    );
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { runtime.run(task_shutdown).await });

    client.wait_for_lease_responses(1).await;
    assert!(
        !client.invalid_job_rejected(),
        "post-accept authority expiry terminalizes the accepted attempt instead of rewriting its admission"
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if journal
                .snapshot()
                .expect("expired authority snapshot")
                .slot(fixture.slot)
                .is_none()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("DB-expired acknowledged authority terminalizes and releases the accepted attempt");

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("authority admission probe shuts down")
        .expect("runtime task")
        .expect("clean shutdown");
}

#[tokio::test]
async fn authority_deadline_uses_the_monotonic_database_beacon_after_wall_regression() {
    let scratch = support::Scratch::new("authority-deadline-db-beacon");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer_with_authority_expiries(
        journal.as_ref(),
        spool.as_ref(),
        runner_id,
        40_000,
        &[30_000],
    );
    let monotonic = Arc::new(support::ManualClock::new(10_000, 50));
    let clock = Arc::new(RegressingWallClock::new(Arc::clone(&monotonic)));
    let sleeper = Arc::new(support::ManualDeadlineSleeper::new(Arc::clone(&monotonic)));
    let client = Arc::new(WatchdogProbeClient::new(
        fixture.session_id,
        Arc::clone(&clock),
        10_000,
        None,
    ));
    let running = Arc::new(AtomicBool::new(false));
    let executor = Arc::new(support::CancellationExecutor::new(Arc::clone(&running)));
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client,
            journal,
            spool,
            executor.clone(),
            clock,
            sleeper.clone(),
            Arc::new(SystemRuntimeIds),
        ),
    );
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { runtime.run(task_shutdown).await });

    tokio::time::timeout(Duration::from_secs(1), async {
        while !running.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("executor starts before the DB-issued authority expires");

    sleeper.advance(9_999);
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(executor.observed_reason(), None);

    sleeper.advance(1);
    tokio::time::timeout(Duration::from_secs(1), async {
        while executor.observed_reason() != Some(ExecutionCancellationReason::AuthorityExpired) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("authority expires at its conservatively translated DB boundary");

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("authority deadline probe shuts down")
        .expect("runtime task")
        .expect("clean shutdown");
}

#[tokio::test]
async fn lease_renewal_watchdog_cannot_exceed_the_durable_lease_interval() {
    let scratch = support::Scratch::new("lease-renewal-duration-cap");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer_expiring_at(
        journal.as_ref(),
        spool.as_ref(),
        runner_id,
        14_000,
    );
    let monotonic = Arc::new(support::ManualClock::new(10_000, 50));
    let clock = Arc::new(RegressingWallClock::new(Arc::clone(&monotonic)));
    let sleeper = Arc::new(support::ManualDeadlineSleeper::new(Arc::clone(&monotonic)));
    let client = Arc::new(WatchdogProbeClient::new(
        fixture.session_id,
        Arc::clone(&clock),
        0,
        Some(UnixMillis::new(100_000)),
    ));
    let running = Arc::new(AtomicBool::new(false));
    let executor = Arc::new(support::CancellationExecutor::new(Arc::clone(&running)));
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            executor.clone(),
            clock,
            sleeper.clone(),
            Arc::new(SystemRuntimeIds),
        ),
    );
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { runtime.run(task_shutdown).await });

    tokio::time::timeout(Duration::from_secs(1), async {
        while !running.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("executor starts under short durable lease");

    sleeper.advance(1_000);
    client.wait_for_heartbeats(1).await;
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if journal
                .snapshot()
                .expect("renewed snapshot")
                .slot(fixture.slot)
                .is_some_and(|slot| slot.expires_at() == UnixMillis::new(100_000))
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first renewal is durable");
    sleeper.advance(1_000);
    client.wait_for_heartbeats(2).await;

    sleeper.advance(3_999);
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(executor.observed_reason(), None);

    sleeper.advance(1);
    tokio::time::timeout(Duration::from_secs(1), async {
        while executor.observed_reason() != Some(ExecutionCancellationReason::LeaseExpired) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("renewal deadline is capped by the five-second durable interval");

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("duration-capped watchdog shuts down")
        .expect("runtime task")
        .expect("clean shutdown");
}

#[tokio::test]
async fn lease_renewal_watchdog_cannot_exceed_the_negotiated_duration() {
    let scratch = support::Scratch::new("lease-renewal-timing-cap");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);
    let monotonic = Arc::new(support::ManualClock::new(10_000, 50));
    let clock = Arc::new(RegressingWallClock::new(Arc::clone(&monotonic)));
    let sleeper = Arc::new(support::ManualDeadlineSleeper::new(Arc::clone(&monotonic)));
    let client = Arc::new(WatchdogProbeClient::new(
        fixture.session_id,
        Arc::clone(&clock),
        0,
        Some(UnixMillis::new(100_000)),
    ));
    let running = Arc::new(AtomicBool::new(false));
    let executor = Arc::new(support::CancellationExecutor::new(Arc::clone(&running)));
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            executor.clone(),
            clock,
            sleeper.clone(),
            Arc::new(SystemRuntimeIds),
        ),
    );
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { runtime.run(task_shutdown).await });

    tokio::time::timeout(Duration::from_secs(1), async {
        while !running.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("executor starts under the database-issued lease");

    sleeper.advance(1_000);
    client.wait_for_heartbeats(1).await;
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if journal
                .snapshot()
                .expect("renewed snapshot")
                .slot(fixture.slot)
                .is_some_and(|slot| slot.expires_at() == UnixMillis::new(100_000))
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("mismatched renewal is durable");
    sleeper.advance(1_000);
    client.wait_for_heartbeats(2).await;

    sleeper.advance(28_999);
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(executor.observed_reason(), None);

    sleeper.advance(1);
    tokio::time::timeout(Duration::from_secs(1), async {
        while executor.observed_reason() != Some(ExecutionCancellationReason::LeaseExpired) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("renewal deadline is capped by the negotiated thirty-second duration");

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("timing-capped watchdog shuts down")
        .expect("runtime task")
        .expect("clean shutdown");
}

#[tokio::test]
async fn one_expired_lease_is_contained_while_a_sibling_slot_keeps_renewing() {
    let scratch = support::Scratch::new("lease-expiry-slot-isolation");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let expired = support::seed_accepted_offer_expiring_at(
        journal.as_ref(),
        spool.as_ref(),
        runner_id,
        11_000,
    );
    let survivor = support::seed_additional_accepted_offer(
        journal.as_ref(),
        spool.as_ref(),
        runner_id,
        expired.session_id,
        2,
        2,
    );
    let clock = Arc::new(support::ManualClock::new(10_000, 50));
    let client = Arc::new(support::LeaseIsolationClient::new(
        expired.session_id,
        expired.lease,
        survivor.lease,
        Arc::clone(&clock),
    ));
    let executor = Arc::new(support::LeaseIsolationExecutor::default());
    let runtime = RunnerSessionSupervisor::new(
        support::config_with_slots_and_retry(runner_id, 2, RetryPolicy::default()),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            executor.clone(),
            clock,
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { runtime.run(task_shutdown).await });

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if executor.expired_reason() == Some(ExecutionCancellationReason::LeaseExpired)
                && client.surviving_heartbeats() > 0
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("one slot expires while its sibling renews");
    assert!(executor.survivor_started());
    assert!(!task.is_finished(), "lease loss is attempt-local");
    let expiring_requests = client.expiring_requests();
    assert!(!expiring_requests.is_empty());
    if expiring_requests.len() >= 2 {
        assert_exact_retry(&expiring_requests);
    }
    let snapshot = journal.snapshot().expect("isolated durable slots");
    assert!(snapshot.slot(expired.slot).is_some());
    assert!(snapshot.slot(survivor.slot).is_some());

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("two-slot runner shutdown")
        .expect("runtime task")
        .expect("clean shutdown");
}

#[tokio::test]
async fn authority_deadline_uses_earliest_expiry_without_a_lease_duration_cap() {
    let scratch = support::Scratch::new("fixed-authority-deadline");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer_with_authority_expiries(
        journal.as_ref(),
        spool.as_ref(),
        runner_id,
        40_000,
        &[45_000, 80_000],
    );
    let clock = Arc::new(support::ManualClock::new(10_000, 50));
    let sleeper = Arc::new(support::ManualDeadlineSleeper::new(Arc::clone(&clock)));
    let client = Arc::new(support::FailureIsolationClient::new(fixture.session_id));
    let running = Arc::new(AtomicBool::new(false));
    let executor = Arc::new(support::CancellationExecutor::new(Arc::clone(&running)));
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
        ),
    );
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { runtime.run(task_shutdown).await });

    tokio::time::timeout(Duration::from_secs(1), async {
        while !running.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("executor starts before authority expiry");

    for minimum_heartbeats in 1..=6 {
        sleeper.advance(5_000);
        tokio::time::timeout(Duration::from_secs(1), async {
            while client.heartbeat_lifecycles().len() < minimum_heartbeats {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("lease renewal before authority deadline");
        assert_eq!(executor.observed_reason(), None);
    }
    assert_eq!(sleeper.monotonic_now(), MonotonicMillis::new(30_050));
    assert_eq!(
        executor.observed_reason(),
        None,
        "the negotiated 30-second lease duration never caps authority"
    );

    sleeper.advance(4_999);
    tokio::time::timeout(Duration::from_secs(1), async {
        while client.heartbeat_lifecycles().len() < 7 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("execution and lease renewal continue beyond the lease-duration cap");
    assert_eq!(sleeper.monotonic_now(), MonotonicMillis::new(35_049));
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
    .expect("earliest exact authority boundary quiesces and terminalizes execution");
    assert_eq!(
        client.terminal_results(),
        vec![(fixture.lease.attempt_id(), JobConclusion::Failure)]
    );
    assert_eq!(client.terminal_results_after_eos(), vec![true]);

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("authority-bounded runtime shutdown")
        .expect("runtime task")
        .expect("clean shutdown");
}

#[tokio::test]
async fn authority_expiry_aborts_an_uncooperative_executor_before_cleanup_and_delivery() {
    let scratch = support::Scratch::new("authority-expiry-quiescence");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer_with_authority_expiries(
        journal.as_ref(),
        spool.as_ref(),
        runner_id,
        40_000,
        &[12_000],
    );
    let clock = Arc::new(support::ManualClock::new(10_000, 50));
    let sleeper = Arc::new(support::ManualDeadlineSleeper::new(Arc::clone(&clock)));
    let client = Arc::new(support::FailureIsolationClient::new(fixture.session_id));
    let running = Arc::new(AtomicBool::new(false));
    let executor = Arc::new(support::CancellationTimeoutExecutor::new(Arc::clone(
        &running,
    )));
    let runtime = RunnerSessionSupervisor::new(
        support::config_with_cancellation_grace(runner_id, Duration::from_millis(100)),
        RunnerRuntimePorts::new(
            client.clone(),
            journal,
            spool,
            executor.clone(),
            clock,
            sleeper.clone(),
            Arc::new(SystemRuntimeIds),
        ),
    );
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { runtime.run(task_shutdown).await });

    tokio::time::timeout(Duration::from_secs(1), async {
        while !running.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("uncooperative executor starts");
    sleeper.advance(2_000);
    tokio::time::timeout(Duration::from_secs(1), async {
        while executor.observed_reason() != Some(ExecutionCancellationReason::AuthorityExpired) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("authority cancellation is signalled at the exact boundary");

    for _ in 0..3 {
        sleeper.advance(100);
        tokio::task::yield_now().await;
        if executor.cleanup_called() {
            break;
        }
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        while !executor.cleanup_called() || client.terminal_results().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("aborted execution is quiesced, cleaned, and then delivered");
    assert!(executor.execution_dropped());
    assert!(!executor.cleanup_before_drop());
    assert_eq!(
        client.terminal_results(),
        vec![(fixture.lease.attempt_id(), JobConclusion::Failure)]
    );

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("quiescence test runtime shutdown")
        .expect("runtime task")
        .expect("clean shutdown");
}

#[tokio::test]
async fn one_authority_expiry_is_slot_local_while_a_sibling_keeps_running() {
    let scratch = support::Scratch::new("authority-expiry-slot-isolation");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let expired = support::seed_accepted_offer_with_authority_expiries(
        journal.as_ref(),
        spool.as_ref(),
        runner_id,
        40_000,
        &[12_000],
    );
    let survivor = support::seed_additional_accepted_offer(
        journal.as_ref(),
        spool.as_ref(),
        runner_id,
        expired.session_id,
        2,
        2,
    );
    let clock = Arc::new(support::ManualClock::new(10_000, 50));
    let sleeper = Arc::new(support::ManualDeadlineSleeper::new(Arc::clone(&clock)));
    let client = Arc::new(support::FailureIsolationClient::new(expired.session_id));
    let executor = Arc::new(support::LeaseIsolationExecutor::default());
    let runtime = RunnerSessionSupervisor::new(
        support::config_with_slots_and_retry(runner_id, 2, RetryPolicy::default()),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            executor.clone(),
            clock,
            sleeper.clone(),
            Arc::new(SystemRuntimeIds),
        ),
    );
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { runtime.run(task_shutdown).await });

    tokio::time::timeout(Duration::from_secs(1), async {
        while !executor.survivor_started() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("sibling executor starts");
    sleeper.advance(2_000);
    tokio::time::timeout(Duration::from_secs(1), async {
        while executor.expired_reason() != Some(ExecutionCancellationReason::AuthorityExpired)
            || client.terminal_results().is_empty()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("only the short-authority slot expires");

    assert!(executor.survivor_started());
    assert!(!task.is_finished(), "authority expiry is attempt-local");
    assert_eq!(
        client.terminal_results(),
        vec![(expired.lease.attempt_id(), JobConclusion::Failure)]
    );
    assert!(
        journal
            .snapshot()
            .expect("sibling snapshot")
            .slot(survivor.slot)
            .is_some()
    );

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("isolated authority runtime shutdown")
        .expect("runtime task")
        .expect("clean shutdown");
}

#[tokio::test]
async fn active_log_backlog_uses_deadline_cadence_instead_of_heartbeat_per_batch() {
    let scratch = support::Scratch::new("active-log-heartbeat-cadence");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);
    let clock = Arc::new(support::ManualClock::new(10_000, 50));
    let sleeper = Arc::new(support::ManualDeadlineSleeper::new(Arc::clone(&clock)));
    let client = Arc::new(support::ActiveBacklogClient::new(
        fixture.session_id,
        fixture.lease,
        Arc::clone(&sleeper),
    ));
    let executor = Arc::new(support::ActiveLogExecutor::new(160));
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            executor.clone(),
            clock,
            sleeper.clone(),
            Arc::new(SystemRuntimeIds),
        ),
    );
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { runtime.run(task_shutdown).await });

    tokio::time::timeout(Duration::from_secs(2), executor.wait_for_emitters(1))
        .await
        .expect("active executor emits its durable backlog");
    sleeper.advance(10_000);
    tokio::time::timeout(Duration::from_secs(2), client.wait_for_log_batches(10))
        .await
        .expect("ten bounded active log batches are delivered");

    let batches = client.log_batches();
    assert_eq!(batches.len(), 10);
    assert!(batches.iter().all(|batch| batch.frame_count == 16));
    assert_eq!(batches.first().expect("first batch").first_sequence, 0);
    assert_eq!(batches.last().expect("last batch").last_sequence, 159);
    let heartbeats = client.heartbeats();
    assert_eq!(
        heartbeats.len(),
        4,
        "a backlog must not emit one heartbeat for every delivered batch"
    );
    assert!(heartbeats.windows(2).all(|pair| {
        let elapsed = pair[1].saturating_sub(pair[0]);
        (10_000..=14_000).contains(&elapsed)
    }));
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let snapshot = journal.snapshot().expect("active segmented log snapshot");
            let delivery = snapshot
                .slot(fixture.slot)
                .and_then(|slot| slot.log_delivery())
                .expect("active log delivery");
            if delivery.acknowledged_through() == delivery.produced_through() {
                assert!(delivery.segments().is_empty());
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("acknowledged active segments are removed");

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("active backlog runner shuts down")
        .expect("runtime task")
        .expect("clean shutdown");
}

#[tokio::test]
async fn active_heartbeat_renews_while_exact_log_request_retries_then_blocks() {
    let scratch = support::Scratch::new("active-blocked-log-heartbeat");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);
    let clock = Arc::new(support::ManualClock::new(10_000, 50));
    let sleeper = Arc::new(support::ManualDeadlineSleeper::new(Arc::clone(&clock)));
    let client = Arc::new(support::BlockedLogClient::new(
        fixture.session_id,
        vec![fixture.lease.clone()],
        fixture.lease.attempt_id(),
        Arc::clone(&sleeper),
        2,
    ));
    let executor = Arc::new(support::ActiveLogExecutor::new(1));
    let retry = RetryPolicy::new(2, Duration::from_millis(1), Duration::from_millis(2))
        .expect("short exact-log retry");
    let runtime = RunnerSessionSupervisor::new(
        support::config_with_retry(runner_id, retry),
        RunnerRuntimePorts::new(
            client.clone(),
            journal,
            spool,
            executor.clone(),
            clock,
            sleeper.clone(),
            Arc::new(SystemRuntimeIds),
        ),
    );
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { runtime.run(task_shutdown).await });

    tokio::time::timeout(Duration::from_secs(1), executor.wait_for_emitters(1))
        .await
        .expect("active executor emits a log frame");
    sleeper.advance(1_000);
    tokio::time::timeout(Duration::from_secs(1), client.wait_for_blocked_requests(1))
        .await
        .expect("first exact log request starts");
    for minimum in 2..=4 {
        sleeper.advance(1_000);
        tokio::time::timeout(
            Duration::from_secs(1),
            client.wait_for_heartbeats(fixture.lease.attempt_id(), minimum),
        )
        .await
        .expect("heartbeat progresses beside blocked log delivery");
    }
    tokio::time::timeout(Duration::from_secs(1), client.wait_for_blocked_requests(3))
        .await
        .expect("log request retries twice and remains in flight");

    let blocked = client.blocked_requests();
    assert_eq!(blocked.len(), 3);
    assert_exact_retry(&blocked);
    let heartbeats = client.heartbeat_times(fixture.lease.attempt_id());
    assert_eq!(heartbeats.len(), 4);
    assert!(
        heartbeats
            .windows(2)
            .all(|pair| pair[1].saturating_sub(pair[0]) == 1_000)
    );
    assert!(
        !task.is_finished(),
        "blocked log delivery remains slot-local"
    );

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("blocked-log runner shuts down")
        .expect("runtime task")
        .expect("clean shutdown");
}

#[tokio::test]
async fn blocked_log_stream_does_not_withhold_a_sibling_slots_heartbeats() {
    let scratch = support::Scratch::new("blocked-log-sibling-heartbeat");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let blocked = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);
    let sibling = support::seed_additional_accepted_offer(
        journal.as_ref(),
        spool.as_ref(),
        runner_id,
        blocked.session_id,
        2,
        2,
    );
    let clock = Arc::new(support::ManualClock::new(10_000, 50));
    let sleeper = Arc::new(support::ManualDeadlineSleeper::new(Arc::clone(&clock)));
    let client = Arc::new(support::BlockedLogClient::new(
        blocked.session_id,
        vec![blocked.lease.clone(), sibling.lease.clone()],
        blocked.lease.attempt_id(),
        Arc::clone(&sleeper),
        0,
    ));
    let executor = Arc::new(support::ActiveLogExecutor::new(1));
    let runtime = RunnerSessionSupervisor::new(
        support::config_with_slots_and_retry(runner_id, 2, RetryPolicy::default()),
        RunnerRuntimePorts::new(
            client.clone(),
            journal,
            spool,
            executor.clone(),
            clock,
            sleeper.clone(),
            Arc::new(SystemRuntimeIds),
        ),
    );
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { runtime.run(task_shutdown).await });

    tokio::time::timeout(Duration::from_secs(1), executor.wait_for_emitters(2))
        .await
        .expect("both active slots emit a log frame");
    sleeper.advance(1_000);
    tokio::time::timeout(Duration::from_secs(1), client.wait_for_blocked_requests(1))
        .await
        .expect("one slot parks an in-flight log request");
    for minimum in 2..=4 {
        sleeper.advance(1_000);
        tokio::time::timeout(
            Duration::from_secs(1),
            client.wait_for_heartbeats(blocked.lease.attempt_id(), minimum),
        )
        .await
        .expect("blocked slot heartbeat");
        tokio::time::timeout(
            Duration::from_secs(1),
            client.wait_for_heartbeats(sibling.lease.attempt_id(), minimum),
        )
        .await
        .expect("sibling slot heartbeat");
    }
    assert_eq!(client.blocked_requests().len(), 1);
    assert_eq!(client.heartbeat_times(blocked.lease.attempt_id()).len(), 4);
    assert_eq!(client.heartbeat_times(sibling.lease.attempt_id()).len(), 4);
    assert!(
        !task.is_finished(),
        "one blocked H2 stream does not stop either slot"
    );

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("two-slot runner shuts down")
        .expect("runtime task")
        .expect("clean shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovered_finalization_renews_short_lease_during_blocked_eos_and_delivery() {
    let scratch = support::Scratch::new("recovered-short-finalization-lease");
    let runner_id = RunnerId::new();
    let journal = Arc::new(
        automata_ci_runner_journal::FileJournal::open(scratch.journal_root(), runner_id)
            .expect("open recovered finalization journal"),
    );
    let spool = Arc::new(support::BlockingEosSpool::new(
        FileSpool::open(
            scratch.spool_root(),
            Arc::new(support::TestProtector::new()),
        )
        .expect("open recovered finalization spool"),
    ));
    let fixture = support::seed_accepted_offer_expiring_at(
        journal.as_ref(),
        spool.as_ref(),
        runner_id,
        10_500,
    );
    support::seed_failed_terminal_without_logs(journal.as_ref(), spool.as_ref(), &fixture);

    let shutdown = CancellationToken::new();
    let clock = Arc::new(support::ManualClock::new(10_000, 50));
    let sleeper = Arc::new(support::ManualDeadlineSleeper::new(clock.clone()));
    let client = Arc::new(support::RecoveredFinalizationClient::new(
        fixture.session_id,
        fixture.lease.clone(),
        sleeper.clone(),
        shutdown.clone(),
    ));
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool.clone(),
            Arc::new(support::NeverExecutor),
            clock,
            sleeper.clone(),
            Arc::new(SystemRuntimeIds),
        ),
    );
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { runtime.run(task_shutdown).await });

    tokio::time::timeout(Duration::from_secs(2), spool.wait_for_eos_publication())
        .await
        .expect("runtime-owned EOS publication blocks deterministically");
    tokio::time::timeout(Duration::from_secs(2), client.wait_for_heartbeats(1))
        .await
        .expect("lease-capped heartbeat precedes the short recovered deadline");
    assert_eq!(client.heartbeat_times(), vec![50]);
    assert!(!task.is_finished());

    spool.release_eos_publication();
    tokio::time::timeout(Duration::from_secs(2), client.wait_for_log_delivery())
        .await
        .expect("EOS reaches deliberately blocked log delivery");
    assert_eq!(client.heartbeat_times(), vec![50], "no heartbeat spam");
    assert_eq!(sleeper.advance(1_000), 1_050);
    tokio::time::timeout(Duration::from_secs(2), client.wait_for_heartbeats(2))
        .await
        .expect("heartbeat continues beside blocked EOS delivery");
    assert_eq!(client.heartbeat_times(), vec![50, 1_050]);
    assert!(!task.is_finished());

    client.release_log_delivery();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("recovered finalization completes")
        .expect("recovered runtime task")
        .expect("clean recovered finalization shutdown");
    assert!(
        journal
            .snapshot()
            .expect("released recovered finalization")
            .slot(fixture.slot)
            .is_none()
    );
}

#[tokio::test]
async fn terminal_log_backlog_is_batched_and_heartbeats_continue_during_slow_delivery() {
    let scratch = support::Scratch::new("slow-batched-finalization");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);
    let shutdown = CancellationToken::new();
    let clock = Arc::new(support::ManualClock::new(10_000, 50));
    let client = Arc::new(support::SlowLogClient::new(
        fixture.session_id,
        fixture.lease,
        Arc::clone(&clock),
        shutdown.clone(),
        false,
        true,
    ));
    let retry = RetryPolicy::new(2, Duration::from_millis(1), Duration::from_millis(2))
        .expect("short exact-log retry");
    let runtime = RunnerSessionSupervisor::new(
        support::config_with_retry(runner_id, retry),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool,
            Arc::new(support::BurstLogExecutor::new(64)),
            clock,
            Arc::new(automata_ci_runner_runtime::TokioRuntimeSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );

    let completed = tokio::time::timeout(Duration::from_secs(15), runtime.run(shutdown)).await;
    assert!(
        completed.is_ok(),
        "slow delivery timed out: batch_count={}, heartbeat_count={}, starved={}",
        client.log_batches().len(),
        client.heartbeats().len(),
        client.starved(),
    );
    completed
        .expect("checked timeout")
        .expect("batched job completes");

    let batches = client.log_batches();
    assert!(batches.len() < 10, "65 frames must not become 65 RPCs");
    assert_eq!(batches[0].first_sequence, 0);
    assert_eq!(batches[0].last_sequence, 15);
    assert_eq!(batches[0].frame_count, 16);
    assert_eq!(
        batches[1].first_sequence, 0,
        "first batch is retried exactly"
    );
    assert_eq!(batches[1].last_sequence, 15);
    assert_eq!(
        batches[0].request.operation_id,
        batches[1].request.operation_id
    );
    assert_eq!(
        batches[0].request.canonical_bytes,
        batches[1].request.canonical_bytes
    );
    assert!(batches.iter().all(|batch| batch.frame_count <= 16));
    assert_eq!(batches.last().expect("terminal batch").last_sequence, 64);
    assert!(
        !client.starved(),
        "log delivery never crosses a lease window"
    );
    let heartbeats = client.heartbeats();
    assert!(
        heartbeats
            .iter()
            .any(|(lifecycle, _, _)| *lifecycle == JobLifecycle::Finalizing),
        "terminal draining reports Finalizing while renewing the lease"
    );
    assert!(
        heartbeats.iter().all(|(_, observed_at, expires_at)| {
            let elapsed = observed_at.saturating_sub(client.lease_clock_anchor());
            let estimated_database_now =
                10_000_i64.saturating_add(i64::try_from(elapsed).unwrap_or(i64::MAX));
            expires_at.get().saturating_sub(estimated_database_now) == 40_000
        }),
        "each slow-delivery renewal preserves the 40-second durable horizon"
    );
    assert!(
        journal
            .snapshot()
            .expect("released finalization")
            .slot(fixture.slot)
            .is_none()
    );
}

#[tokio::test]
async fn crash_during_batched_log_request_reconstructs_the_exact_same_batch() {
    let scratch = support::Scratch::new("batched-log-crash-replay");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);
    let clock = Arc::new(support::ManualClock::new(10_000, 50));
    let first_shutdown = CancellationToken::new();
    let first_client = Arc::new(support::SlowLogClient::new(
        fixture.session_id,
        fixture.lease.clone(),
        Arc::clone(&clock),
        first_shutdown.clone(),
        true,
        false,
    ));
    RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            first_client.clone(),
            journal.clone(),
            spool.clone(),
            Arc::new(support::BurstLogExecutor::new(31)),
            clock.clone(),
            Arc::new(automata_ci_runner_runtime::TokioRuntimeSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    )
    .run(first_shutdown)
    .await
    .expect("first process stops with the batch uncertain");
    let first = first_client.log_batches();
    assert_eq!(first.len(), 1);

    let second_shutdown = CancellationToken::new();
    let second_client = Arc::new(support::SlowLogClient::new(
        fixture.session_id,
        fixture.lease,
        Arc::clone(&clock),
        second_shutdown.clone(),
        false,
        false,
    ));
    RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            second_client.clone(),
            journal.clone(),
            spool,
            Arc::new(support::BurstLogExecutor::new(31)),
            clock,
            Arc::new(automata_ci_runner_runtime::TokioRuntimeSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    )
    .run(second_shutdown)
    .await
    .expect("recovered process completes exact log delivery");
    let second = second_client.log_batches();
    assert!(!second.is_empty());
    assert_eq!(
        first[0].request.operation_id,
        second[0].request.operation_id
    );
    assert_eq!(
        first[0].request.canonical_bytes,
        second[0].request.canonical_bytes
    );
    assert!(
        journal
            .snapshot()
            .expect("released crash replay")
            .slot(fixture.slot)
            .is_none()
    );
}

#[tokio::test]
async fn active_lease_recovers_after_extended_heartbeat_outage_before_shutdown() {
    let scratch = support::Scratch::new("extended-heartbeat-outage");
    let runner_id = RunnerId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);
    let shutdown = CancellationToken::new();
    let running = Arc::new(AtomicBool::new(false));
    let executor = Arc::new(support::CancellationExecutor::new(Arc::clone(&running)));
    let client = Arc::new(support::RecoveringHeartbeatClient::new(
        fixture.session_id,
        fixture.lease,
        6,
    ));
    let retry = RetryPolicy::new(2, Duration::from_millis(1), Duration::from_millis(2))
        .expect("short retry ramp");
    let runtime = RunnerSessionSupervisor::new(
        support::config_with_retry(runner_id, retry),
        RunnerRuntimePorts::new(
            client.clone(),
            journal,
            spool,
            executor.clone(),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { runtime.run(task_shutdown).await });

    tokio::time::timeout(Duration::from_secs(1), client.wait_until_recovered())
        .await
        .expect("heartbeat recovers");
    assert!(running.load(Ordering::SeqCst));
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("active runner shuts down promptly")
        .expect("runtime task")
        .expect("clean shutdown");

    let outage_requests = client.outage_requests();
    assert_eq!(outage_requests.len(), 7);
    assert_exact_retry(&outage_requests);
    assert_eq!(
        executor.observed_reason(),
        Some(ExecutionCancellationReason::Shutdown)
    );
}

fn assert_exact_retry(requests: &[support::ObservedRequest]) {
    assert!(requests.len() >= 2);
    for request in &requests[1..] {
        assert_eq!(request.operation_id, requests[0].operation_id);
        assert_eq!(request.canonical_bytes, requests[0].canonical_bytes);
        assert_eq!(request.address, requests[0].address);
    }
}
