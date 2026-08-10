mod support;

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, PoisonError},
};

use automata_ci_core::{
    AttemptId, FencingToken, Lease, LeaseId, OperationId, RunnerId, RunnerSessionId, UnixMillis,
};
use automata_ci_protocol::{
    CancelJob, CommandCursor, CommandSequence, ErrorMessage, LeaseOffer, MessageHeader,
    NegotiatedSession, NoWork, OperationAck, RemoteErrorCode, RunnerSlotOrdinal, RunnerToServer,
    SUPPORTED_PROTOCOL_RANGE, ServerCommandHeader, ServerHello, ServerTiming, ServerToRunner,
    SessionDisposition,
};
use automata_ci_runner_journal::{
    CommitFault, CommitFaultInjector, CommitStage, FileJournal, FileJournalOptions, JournalError,
    RunnerJournal, SessionBinding,
};
use automata_ci_runner_runtime::{
    RunnerRuntimeControlClient, RunnerRuntimeError, RunnerRuntimePorts, RunnerSessionSupervisor,
    RuntimeControlError, RuntimeControlErrorKind, RuntimeControlFuture, RuntimeControlReply,
    RuntimeControlRetry, SystemRuntimeIds,
};
use automata_ci_runner_spool::FileSpool;
use automata_ci_runner_transport::PreparedRequest;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Eq, PartialEq)]
struct PollObservation {
    slot: RunnerSlotOrdinal,
    operation_id: OperationId,
    acknowledges_operation_id: Option<OperationId>,
    canonical_bytes: Vec<u8>,
}

impl PollObservation {
    fn from_request(request: &PreparedRequest) -> Self {
        let RunnerToServer::LeaseRequest(poll) = request.message() else {
            panic!("expected lease request");
        };
        Self {
            slot: poll.slot(),
            operation_id: poll.header().operation_id(),
            acknowledges_operation_id: poll.acknowledges_operation_id(),
            canonical_bytes: request.canonical_bytes().to_vec(),
        }
    }
}

#[derive(Debug, Default)]
struct NoWorkState {
    observations: Vec<PollObservation>,
    successful_by_slot: BTreeMap<RunnerSlotOrdinal, usize>,
    retryable_errors_remaining: usize,
}

#[derive(Debug)]
struct NoWorkClient {
    session_id: RunnerSessionId,
    shutdown: Option<CancellationToken>,
    slots: u16,
    successes_per_slot: usize,
    state: Mutex<NoWorkState>,
}

impl NoWorkClient {
    fn new(
        session_id: RunnerSessionId,
        slots: u16,
        successes_per_slot: usize,
        retryable_errors: usize,
        shutdown: Option<CancellationToken>,
    ) -> Self {
        Self {
            session_id,
            shutdown,
            slots,
            successes_per_slot,
            state: Mutex::new(NoWorkState {
                retryable_errors_remaining: retryable_errors,
                ..NoWorkState::default()
            }),
        }
    }

    fn observations(&self) -> Vec<PollObservation> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .observations
            .clone()
    }

    fn hello(&self, hello: &automata_ci_protocol::RunnerHello) -> ServerToRunner {
        let (disposition, cursor) = match hello.resume() {
            Some(resume) => {
                assert_eq!(resume.session_id(), self.session_id);
                (SessionDisposition::Resumed, resume.command_cursor())
            }
            None => (SessionDisposition::Opened, CommandCursor::initial()),
        };
        ServerToRunner::Hello(ServerHello::new(
            OperationId::new(),
            hello.operation_id(),
            NegotiatedSession::new(
                SUPPORTED_PROTOCOL_RANGE.max(),
                automata_ci_core::JobIrVersion::current(),
                self.session_id,
                disposition,
                cursor,
            ),
            ServerTiming::new(UnixMillis::new(10_000), 1_000, 30_000),
        ))
    }
}

impl RunnerRuntimeControlClient for NoWorkClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        _cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            let response = match request.message() {
                RunnerToServer::Hello(hello) => self.hello(hello),
                RunnerToServer::LeaseRequest(poll) => {
                    let (retryable_error, should_shutdown) = {
                        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                        state
                            .observations
                            .push(PollObservation::from_request(request));
                        if state.retryable_errors_remaining > 0 {
                            state.retryable_errors_remaining -= 1;
                            (true, false)
                        } else {
                            *state.successful_by_slot.entry(poll.slot()).or_default() += 1;
                            let complete = (1..=self.slots).all(|ordinal| {
                                let slot =
                                    RunnerSlotOrdinal::new(ordinal).expect("configured slot");
                                state.successful_by_slot.get(&slot).copied().unwrap_or(0)
                                    >= self.successes_per_slot
                            });
                            (false, complete)
                        }
                    };
                    if should_shutdown && let Some(shutdown) = &self.shutdown {
                        shutdown.cancel();
                    }
                    if retryable_error {
                        ServerToRunner::Error(ErrorMessage::new(
                            reply_header(poll.header()),
                            RemoteErrorCode::RetryLater,
                            "scripted retryable poll response",
                            true,
                        ))
                    } else {
                        ServerToRunner::NoWork(NoWork::new(reply_header(poll.header()), 1))
                    }
                }
                _ => return Err(invalid_control_response()),
            };
            reply(response)
        })
    }
}

#[derive(Clone, Copy, Debug)]
enum OfferDelivery {
    Direct,
    CrossSlotReplay,
}

#[derive(Debug, Default)]
struct OfferState {
    initial_polls: BTreeMap<RunnerSlotOrdinal, PollObservation>,
    polls: Vec<PollObservation>,
    offer: Option<LeaseOffer>,
}

#[derive(Debug)]
struct OfferClient {
    runner_id: RunnerId,
    session_id: RunnerSessionId,
    delivery: OfferDelivery,
    shutdown: CancellationToken,
    state: Mutex<OfferState>,
    initial_polls_ready: tokio::sync::Notify,
}

impl OfferClient {
    fn new(
        runner_id: RunnerId,
        session_id: RunnerSessionId,
        delivery: OfferDelivery,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            runner_id,
            session_id,
            delivery,
            shutdown,
            state: Mutex::new(OfferState::default()),
            initial_polls_ready: tokio::sync::Notify::new(),
        }
    }

    const fn slots(&self) -> u16 {
        match self.delivery {
            OfferDelivery::Direct => 1,
            OfferDelivery::CrossSlotReplay => 2,
        }
    }

    fn observations(&self) -> Vec<PollObservation> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .polls
            .clone()
    }

    fn build_offer(&self) -> LeaseOffer {
        let lease = Lease::new(
            LeaseId::new(),
            AttemptId::new(),
            self.runner_id,
            FencingToken::new(7).expect("fencing token"),
            UnixMillis::new(9_000),
            UnixMillis::new(40_000),
        )
        .expect("lease");
        let job = support::minimal_job();
        let authorities = support::test_runtime_authorities(&job, &lease);
        LeaseOffer::new(
            ServerCommandHeader::new(
                SUPPORTED_PROTOCOL_RANGE.max(),
                self.session_id,
                OperationId::new(),
                CommandSequence::new(1).expect("first command"),
            ),
            RunnerSlotOrdinal::new(1).expect("offer slot"),
            lease,
            job,
            authorities,
        )
    }

    async fn offer_for_initial_poll(&self, request: &PreparedRequest) -> LeaseOffer {
        let observation = PollObservation::from_request(request);
        let expected = usize::from(self.slots());
        {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.polls.push(observation.clone());
            state
                .initial_polls
                .entry(observation.slot)
                .or_insert(observation);
            if state.initial_polls.len() == expected {
                let offer = self.build_offer();
                assert!(
                    state
                        .initial_polls
                        .values()
                        .all(|poll| { poll.operation_id != offer.header().operation_id() })
                );
                state.offer = Some(offer);
                self.initial_polls_ready.notify_waiters();
            }
        }
        loop {
            let changed = self.initial_polls_ready.notified();
            if let Some(offer) = self
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .offer
                .clone()
            {
                return offer;
            }
            changed.await;
        }
    }
}

impl RunnerRuntimeControlClient for OfferClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        _cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            let response = match request.message() {
                RunnerToServer::Hello(hello) => ServerToRunner::Hello(ServerHello::new(
                    OperationId::new(),
                    hello.operation_id(),
                    NegotiatedSession::new(
                        SUPPORTED_PROTOCOL_RANGE.max(),
                        automata_ci_core::JobIrVersion::current(),
                        self.session_id,
                        SessionDisposition::Opened,
                        CommandCursor::initial(),
                    ),
                    ServerTiming::new(UnixMillis::new(10_000), 1_000, 30_000),
                )),
                RunnerToServer::LeaseRequest(poll) => {
                    let is_initial = !self
                        .state
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .initial_polls
                        .contains_key(&poll.slot());
                    if is_initial {
                        ServerToRunner::LeaseOffer(Box::new(
                            self.offer_for_initial_poll(request).await,
                        ))
                    } else {
                        self.state
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .polls
                            .push(PollObservation::from_request(request));
                        ServerToRunner::NoWork(NoWork::new(reply_header(poll.header()), 1))
                    }
                }
                RunnerToServer::CommandAck(ack) => {
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(ack.header())))
                }
                RunnerToServer::LeaseResponse(response) => {
                    self.shutdown.cancel();
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(response.header())))
                }
                _ => return Err(invalid_control_response()),
            };
            reply(response)
        })
    }
}

#[derive(Debug)]
struct CancelClient {
    session_id: RunnerSessionId,
    shutdown: CancellationToken,
    cancellation: CancelJob,
    poll: Mutex<Option<PollObservation>>,
}

impl CancelClient {
    fn new(runner_id: RunnerId, session_id: RunnerSessionId, shutdown: CancellationToken) -> Self {
        let unrelated = Lease::new(
            LeaseId::new(),
            AttemptId::new(),
            runner_id,
            FencingToken::new(11).expect("fencing token"),
            UnixMillis::new(9_000),
            UnixMillis::new(40_000),
        )
        .expect("unrelated lease");
        Self {
            session_id,
            shutdown,
            cancellation: CancelJob::new(
                ServerCommandHeader::new(
                    SUPPORTED_PROTOCOL_RANGE.max(),
                    session_id,
                    OperationId::new(),
                    CommandSequence::new(1).expect("first command"),
                ),
                unrelated.attempt_id(),
                unrelated.guard(),
                "stale scripted cancellation",
                UnixMillis::new(10_001),
            ),
            poll: Mutex::new(None),
        }
    }

    fn poll(&self) -> PollObservation {
        self.poll
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .expect("observed poll")
    }
}

impl RunnerRuntimeControlClient for CancelClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        _cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            let response = match request.message() {
                RunnerToServer::Hello(hello) => ServerToRunner::Hello(ServerHello::new(
                    OperationId::new(),
                    hello.operation_id(),
                    NegotiatedSession::new(
                        SUPPORTED_PROTOCOL_RANGE.max(),
                        automata_ci_core::JobIrVersion::current(),
                        self.session_id,
                        SessionDisposition::Opened,
                        CommandCursor::initial(),
                    ),
                    ServerTiming::new(UnixMillis::new(10_000), 1_000, 30_000),
                )),
                RunnerToServer::LeaseRequest(_) => {
                    let mut poll = self.poll.lock().unwrap_or_else(PoisonError::into_inner);
                    if poll.is_some() {
                        return Err(invalid_control_response());
                    }
                    *poll = Some(PollObservation::from_request(request));
                    ServerToRunner::CancelJob(self.cancellation.clone())
                }
                RunnerToServer::CommandAck(ack) => {
                    self.shutdown.cancel();
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(ack.header())))
                }
                _ => return Err(invalid_control_response()),
            };
            reply(response)
        })
    }
}

#[derive(Debug)]
struct FailAt(CommitStage);

impl CommitFaultInjector for FailAt {
    fn check(&self, stage: CommitStage) -> Result<(), CommitFault> {
        if stage == self.0 {
            Err(CommitFault)
        } else {
            Ok(())
        }
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

fn invalid_control_response() -> RuntimeControlError {
    RuntimeControlError::new(
        RuntimeControlErrorKind::InvalidResponse,
        RuntimeControlRetry::Never,
    )
}

fn reply(message: ServerToRunner) -> Result<RuntimeControlReply, RuntimeControlError> {
    RuntimeControlReply::from_message(message, &automata_ci_protocol::ProtocolLimits::default())
        .map_err(|_| invalid_control_response())
}

fn runtime(
    runner_id: RunnerId,
    slots: u16,
    client: Arc<dyn RunnerRuntimeControlClient>,
    journal: Arc<dyn RunnerJournal>,
    spool: Arc<FileSpool>,
) -> RunnerSessionSupervisor {
    RunnerSessionSupervisor::new(
        support::config_with_slots_and_retry(
            runner_id,
            slots,
            automata_ci_runner_runtime::RetryPolicy::default(),
        ),
        RunnerRuntimePorts::new(
            client,
            journal,
            spool,
            Arc::new(support::NeverExecutor),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(support::ImmediateSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    )
}

async fn run_one_successful_no_work(
    runner_id: RunnerId,
    session_id: RunnerSessionId,
    journal: Arc<dyn RunnerJournal>,
    spool: Arc<FileSpool>,
) -> Vec<PollObservation> {
    let shutdown = CancellationToken::new();
    let client = Arc::new(NoWorkClient::new(
        session_id,
        1,
        1,
        0,
        Some(shutdown.clone()),
    ));
    runtime(runner_id, 1, client.clone(), journal, spool)
        .run(shutdown)
        .await
        .expect("one successful no-work response");
    client.observations()
}

#[tokio::test]
async fn no_work_forms_unique_per_slot_successor_chains() {
    let scratch = support::Scratch::new("lease-poll-no-work-chain");
    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let shutdown = CancellationToken::new();
    let client = Arc::new(NoWorkClient::new(
        session_id,
        2,
        2,
        0,
        Some(shutdown.clone()),
    ));

    runtime(runner_id, 2, client.clone(), journal.clone(), spool)
        .run(shutdown)
        .await
        .expect("bounded no-work chain");

    let observations = client.observations();
    let mut all_operations = Vec::new();
    for ordinal in 1..=2 {
        let slot = RunnerSlotOrdinal::new(ordinal).expect("slot");
        let polls: Vec<_> = observations
            .iter()
            .filter(|poll| poll.slot == slot)
            .collect();
        assert!(polls.len() >= 2);
        assert_eq!(polls[0].acknowledges_operation_id, None);
        for pair in polls.windows(2) {
            assert_eq!(
                pair[1].acknowledges_operation_id,
                Some(pair[0].operation_id)
            );
            assert_ne!(pair[1].operation_id, pair[0].operation_id);
        }
        all_operations.extend(polls.iter().map(|poll| poll.operation_id));
        let checkpoint = journal
            .snapshot()
            .expect("snapshot")
            .session()
            .expect("session")
            .lease_poll_checkpoint(slot)
            .copied()
            .expect("checkpoint");
        assert_eq!(
            checkpoint.acknowledges_operation_id(),
            Some(polls.last().expect("last poll").operation_id)
        );
    }
    all_operations.sort_unstable();
    all_operations.dedup();
    assert_eq!(all_operations.len(), observations.len());
}

#[tokio::test]
async fn retryable_protocol_errors_reuse_current_exact_request() {
    let scratch = support::Scratch::new("lease-poll-retryable-error");
    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let shutdown = CancellationToken::new();
    let client = Arc::new(NoWorkClient::new(
        session_id,
        1,
        1,
        2,
        Some(shutdown.clone()),
    ));

    runtime(runner_id, 1, client.clone(), journal.clone(), spool)
        .run(shutdown)
        .await
        .expect("retryable errors preserve the poll");

    let observations = client.observations();
    assert_eq!(observations.len(), 3);
    assert!(observations.iter().all(|poll| {
        poll.operation_id == observations[0].operation_id
            && poll.acknowledges_operation_id == observations[0].acknowledges_operation_id
            && poll.canonical_bytes == observations[0].canonical_bytes
    }));
    let slot = RunnerSlotOrdinal::new(1).expect("slot");
    assert_eq!(
        journal
            .snapshot()
            .expect("snapshot")
            .session()
            .expect("session")
            .lease_poll_checkpoint(slot)
            .expect("checkpoint")
            .acknowledges_operation_id(),
        Some(observations[0].operation_id)
    );
}

#[tokio::test]
async fn crashes_before_send_after_response_and_after_rotate_reconstruct_exact_poll() {
    let scratch = support::Scratch::new("lease-poll-crash-boundaries");
    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let slot = RunnerSlotOrdinal::new(1).expect("slot");
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    journal
        .begin_session(SessionBinding::new(
            session_id,
            SUPPORTED_PROTOCOL_RANGE.max(),
            automata_ci_core::JobIrVersion::current(),
        ))
        .expect("seed session");
    let before_send_operation = OperationId::new();
    journal
        .prepare_lease_poll(session_id, slot, before_send_operation)
        .expect("durable checkpoint before first send");
    drop(journal);

    let faulting = Arc::new(
        FileJournal::open_with_options(
            scratch.journal_root(),
            runner_id,
            FileJournalOptions::new()
                .with_fault_injector(Arc::new(FailAt(CommitStage::FileSynced))),
        )
        .expect("faulting journal"),
    );
    let first_client = Arc::new(NoWorkClient::new(session_id, 1, 1, 0, None));
    let first_runtime = runtime(
        runner_id,
        1,
        first_client.clone(),
        faulting.clone(),
        spool.clone(),
    );
    let error = first_runtime
        .run(CancellationToken::new())
        .await
        .expect_err("crash after response before checkpoint rotation");
    assert!(matches!(
        error,
        RunnerRuntimeError::Journal(JournalError::InjectedFault(CommitStage::FileSynced))
    ));
    let first_poll = first_client.observations();
    assert_eq!(first_poll.len(), 1);
    assert_eq!(first_poll[0].operation_id, before_send_operation);
    assert_eq!(first_poll[0].acknowledges_operation_id, None);
    drop(first_runtime);
    drop(faulting);

    let retry_journal = Arc::new(
        FileJournal::open(scratch.journal_root(), runner_id).expect("reopen after failed rotation"),
    );
    let retried_poll =
        run_one_successful_no_work(runner_id, session_id, retry_journal.clone(), spool.clone())
            .await;
    assert_eq!(
        retried_poll, first_poll,
        "operation and canonical bytes retry exactly"
    );
    let rotated = *retry_journal
        .snapshot()
        .expect("rotated snapshot")
        .session()
        .expect("session")
        .lease_poll_checkpoint(slot)
        .expect("rotated checkpoint");
    assert_ne!(rotated.current_operation_id(), before_send_operation);
    assert_eq!(
        rotated.acknowledges_operation_id(),
        Some(before_send_operation)
    );
    drop(retry_journal);

    let resumed_journal = Arc::new(
        FileJournal::open(scratch.journal_root(), runner_id)
            .expect("reopen after durable rotation"),
    );
    let resumed = run_one_successful_no_work(runner_id, session_id, resumed_journal, spool).await;
    assert_eq!(resumed.len(), 1);
    assert_eq!(resumed[0].operation_id, rotated.current_operation_id());
    assert_eq!(
        resumed[0].acknowledges_operation_id,
        rotated.acknowledges_operation_id()
    );
}

#[tokio::test]
async fn direct_and_cross_slot_offer_responses_retire_their_carrier_polls() {
    for delivery in [OfferDelivery::Direct, OfferDelivery::CrossSlotReplay] {
        let scratch = support::Scratch::new(&format!("lease-poll-offer-{delivery:?}"));
        let runner_id = RunnerId::new();
        let session_id = RunnerSessionId::new();
        let (journal, spool) = support::durable_ports(&scratch, runner_id);
        let shutdown = CancellationToken::new();
        let client = Arc::new(OfferClient::new(
            runner_id,
            session_id,
            delivery,
            shutdown.clone(),
        ));
        let slots = client.slots();

        runtime(runner_id, slots, client.clone(), journal.clone(), spool)
            .run(shutdown)
            .await
            .expect("offer command is durable before poll retirement");

        let observations = client.observations();
        assert!(observations.len() >= usize::from(slots));
        let snapshot = journal.snapshot().expect("offer checkpoint snapshot");
        assert!(
            snapshot.slots().is_empty(),
            "rejected fixture offer is delivered and released"
        );
        let durable_session = snapshot.session().expect("session");
        for ordinal in 1..=slots {
            let slot = RunnerSlotOrdinal::new(ordinal).expect("slot");
            let polls: Vec<_> = observations
                .iter()
                .filter(|poll| poll.slot == slot)
                .collect();
            assert!(!polls.is_empty());
            assert_eq!(polls[0].acknowledges_operation_id, None);
            for pair in polls.windows(2) {
                assert_eq!(
                    pair[1].acknowledges_operation_id,
                    Some(pair[0].operation_id)
                );
            }
            let checkpoint = durable_session
                .lease_poll_checkpoint(slot)
                .expect("carrier checkpoint");
            assert_ne!(checkpoint.current_operation_id(), polls[0].operation_id);
            assert_eq!(
                checkpoint.acknowledges_operation_id(),
                Some(polls.last().expect("last poll").operation_id),
                "every exact command response retires its carrier poll"
            );
        }
    }
}

#[tokio::test]
async fn durable_cancel_response_retires_its_carrier_poll() {
    let scratch = support::Scratch::new("lease-poll-cancel-carrier");
    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let shutdown = CancellationToken::new();
    let client = Arc::new(CancelClient::new(runner_id, session_id, shutdown.clone()));

    runtime(runner_id, 1, client.clone(), journal.clone(), spool)
        .run(shutdown)
        .await
        .expect("durable ignored cancellation completes the carrier poll");

    let poll = client.poll();
    let checkpoint = journal
        .snapshot()
        .expect("snapshot")
        .session()
        .expect("session")
        .lease_poll_checkpoint(poll.slot)
        .copied()
        .expect("checkpoint");
    assert_ne!(checkpoint.current_operation_id(), poll.operation_id);
    assert_eq!(
        checkpoint.acknowledges_operation_id(),
        Some(poll.operation_id)
    );
}
