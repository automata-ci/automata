use super::support;

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use automata_ci_core::{
    AttemptId, FencingToken, Lease, LeaseId, OperationId, RunnerId, RunnerSessionId, Sha256Digest,
    UnixMillis,
};
use automata_ci_protocol::{
    CancelJob, CommandCursor, CommandSequence, ErrorMessage, LeaseAuthorityName,
    LeaseAuthorityPollContribution, LeaseAuthorityPollContributions, LeaseAuthorityPollReceipt,
    LeaseOffer, LeasePollResponse, LeaseRequest, MessageHeader, NegotiatedSession, OperationAck,
    RemoteErrorCode, RunnerSlotOrdinal, RunnerToServer, SUPPORTED_PROTOCOL_RANGE,
    ServerCommandHeader, ServerHello, ServerTiming, ServerToRunner, SessionDisposition,
};
use automata_ci_protocol_protobuf::encode_job_ir;
use automata_ci_runner_journal::{
    CommitFault, CommitFaultInjector, CommitStage, DurableCommand, FileJournal, FileJournalOptions,
    JobIrContentRef, JournalError, LeaseOfferRecord, LeasePollCommandRecord, LeasePollCompletion,
    RunnerJournal, SessionBinding,
};
use automata_ci_runner_runtime::{
    LeaseAuthorityAcknowledgementFuture, LeaseAuthorityExtension, LeaseAuthorityExtensionError,
    LeaseAuthorityExtensionRegistry, LeaseAuthorityPollFuture, RunnerRuntimeControlClient,
    RunnerRuntimeError, RunnerRuntimePorts, RunnerSessionSupervisor, RuntimeControlError,
    RuntimeControlErrorKind, RuntimeControlFuture, RuntimeControlReply, RuntimeControlRetry,
    SystemRuntimeIds,
};
use automata_ci_runner_spool::{ContentKind, DurableContentStore, FileSpool};
use automata_ci_runner_transport::PreparedRequest;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Eq, PartialEq)]
struct PollObservation {
    slot: RunnerSlotOrdinal,
    operation_id: OperationId,
    acknowledges_operation_id: Option<OperationId>,
    authority_contributions: LeaseAuthorityPollContributions,
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
            authority_contributions: poll.authority_contributions().clone(),
            canonical_bytes: request.canonical_bytes().to_vec(),
        }
    }
}

#[derive(Debug)]
struct RotatingAuthorityExtension {
    name: LeaseAuthorityName,
    contributions: [LeaseAuthorityPollContribution; 2],
    state: Mutex<RotatingAuthorityState>,
}

#[derive(Debug, Default)]
struct RotatingAuthorityState {
    current: usize,
    acknowledgement_failures_remaining: usize,
    acknowledged: BTreeSet<LeaseAuthorityPollReceipt>,
    acknowledgement_attempts: Vec<LeaseAuthorityPollReceipt>,
    acknowledgements: Vec<LeaseAuthorityPollReceipt>,
}

impl RotatingAuthorityExtension {
    fn new() -> Self {
        Self::named("test.placement")
    }

    fn named(namespace: &str) -> Self {
        let name = LeaseAuthorityName::new(namespace).expect("authority name");
        Self {
            contributions: [
                authority_contribution(name.clone(), 1),
                authority_contribution(name.clone(), 2),
            ],
            name,
            state: Mutex::new(RotatingAuthorityState::default()),
        }
    }

    fn acknowledgements(&self) -> Vec<Sha256Digest> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .acknowledgements
            .iter()
            .map(LeaseAuthorityPollReceipt::payload_sha256)
            .collect()
    }

    fn acknowledgement_attempts(&self) -> Vec<Sha256Digest> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .acknowledgement_attempts
            .iter()
            .map(LeaseAuthorityPollReceipt::payload_sha256)
            .collect()
    }

    fn assert_acknowledgements(&self, expected: &[Sha256Digest]) {
        assert_eq!(self.acknowledgements(), expected);
    }

    fn fail_next_acknowledgement(&self) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .acknowledgement_failures_remaining = 1;
    }
}

impl LeaseAuthorityExtension for RotatingAuthorityExtension {
    fn name(&self) -> &LeaseAuthorityName {
        &self.name
    }

    fn current_or_refresh(
        &self,
        _observed_at: UnixMillis,
        cancellation: CancellationToken,
    ) -> LeaseAuthorityPollFuture<'_> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(LeaseAuthorityExtensionError::Cancelled);
            }
            let current = self
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .current;
            Ok(self.contributions[current].clone())
        })
    }

    fn acknowledge(
        &self,
        receipt: LeaseAuthorityPollReceipt,
        _cancellation: CancellationToken,
    ) -> LeaseAuthorityAcknowledgementFuture<'_> {
        Box::pin(async move {
            let index = self
                .contributions
                .iter()
                .position(|contribution| {
                    LeaseAuthorityPollReceipt::for_contribution(contribution) == receipt
                })
                .ok_or(LeaseAuthorityExtensionError::InvalidState)?;
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            if index > state.current {
                return Err(LeaseAuthorityExtensionError::InvalidState);
            }
            state.acknowledgement_attempts.push(receipt.clone());
            if state.acknowledgement_failures_remaining > 0 {
                state.acknowledgement_failures_remaining -= 1;
                return Err(LeaseAuthorityExtensionError::Unavailable);
            }
            if state.acknowledged.insert(receipt.clone()) {
                state.acknowledgements.push(receipt);
                if index == state.current && state.current + 1 < self.contributions.len() {
                    state.current += 1;
                }
            }
            Ok(())
        })
    }
}

fn authority_contribution(name: LeaseAuthorityName, serial: u8) -> LeaseAuthorityPollContribution {
    LeaseAuthorityPollContribution::new(name, 1, vec![serial; 32]).expect("authority contribution")
}

#[derive(Debug)]
struct BlockingAuthorityExtension {
    name: LeaseAuthorityName,
    contribution: LeaseAuthorityPollContribution,
    acknowledgement_calls: AtomicUsize,
    acknowledgement_calls_changed: tokio::sync::Notify,
    acknowledgement_release: tokio::sync::Semaphore,
}

impl BlockingAuthorityExtension {
    fn new() -> Self {
        let name = LeaseAuthorityName::new("test.blocking").expect("authority name");
        Self {
            contribution: authority_contribution(name.clone(), 0x33),
            name,
            acknowledgement_calls: AtomicUsize::new(0),
            acknowledgement_calls_changed: tokio::sync::Notify::new(),
            acknowledgement_release: tokio::sync::Semaphore::new(0),
        }
    }

    async fn wait_for_acknowledgement_calls(&self, expected: usize) {
        loop {
            let changed = self.acknowledgement_calls_changed.notified();
            if self.acknowledgement_calls.load(Ordering::SeqCst) >= expected {
                return;
            }
            changed.await;
        }
    }

    fn release_acknowledgements(&self, permits: usize) {
        self.acknowledgement_release.add_permits(permits);
    }
}

impl LeaseAuthorityExtension for BlockingAuthorityExtension {
    fn name(&self) -> &LeaseAuthorityName {
        &self.name
    }

    fn current_or_refresh(
        &self,
        _observed_at: UnixMillis,
        _cancellation: CancellationToken,
    ) -> LeaseAuthorityPollFuture<'_> {
        Box::pin(async { Ok(self.contribution.clone()) })
    }

    fn acknowledge(
        &self,
        receipt: LeaseAuthorityPollReceipt,
        _cancellation: CancellationToken,
    ) -> LeaseAuthorityAcknowledgementFuture<'_> {
        Box::pin(async move {
            if receipt != LeaseAuthorityPollReceipt::for_contribution(&self.contribution) {
                return Err(LeaseAuthorityExtensionError::InvalidState);
            }
            self.acknowledgement_calls.fetch_add(1, Ordering::SeqCst);
            self.acknowledgement_calls_changed.notify_waiters();
            self.acknowledgement_release
                .acquire()
                .await
                .map_err(|_| LeaseAuthorityExtensionError::Unavailable)?
                .forget();
            Err(LeaseAuthorityExtensionError::Unavailable)
        })
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
    accepted_contributions_override: Option<Sha256Digest>,
    invalid_poll_response: bool,
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
            accepted_contributions_override: None,
            invalid_poll_response: false,
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

    fn with_accepted_contributions_override(mut self, digest: Sha256Digest) -> Self {
        self.accepted_contributions_override = Some(digest);
        self
    }

    fn with_invalid_poll_response(mut self) -> Self {
        self.invalid_poll_response = true;
        self
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
                    if self.invalid_poll_response {
                        return Err(invalid_control_response());
                    }
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
                        let accepted = self
                            .accepted_contributions_override
                            .unwrap_or_else(|| poll.authority_contributions().sha256_digest());
                        ServerToRunner::LeasePollResponse(Box::new(LeasePollResponse::no_work(
                            reply_header(poll.header()),
                            accepted,
                            1,
                        )))
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
                RunnerToServer::Hello(hello) => {
                    let (disposition, cursor) = hello.resume().map_or(
                        (SessionDisposition::Opened, CommandCursor::initial()),
                        |resume| {
                            assert_eq!(resume.session_id(), self.session_id);
                            (SessionDisposition::Resumed, resume.command_cursor())
                        },
                    );
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
                RunnerToServer::LeaseRequest(poll) => {
                    let is_initial = !self
                        .state
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .initial_polls
                        .contains_key(&poll.slot());
                    if is_initial {
                        lease_poll_offer(poll, self.offer_for_initial_poll(request).await)
                    } else {
                        self.state
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .polls
                            .push(PollObservation::from_request(request));
                        lease_poll_no_work(poll, 1)
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
    direct_poll_response: bool,
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
            direct_poll_response: false,
            poll: Mutex::new(None),
        }
    }

    fn with_direct_poll_response(mut self) -> Self {
        self.direct_poll_response = true;
        self
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
                RunnerToServer::LeaseRequest(poll_request) => {
                    let mut poll = self.poll.lock().unwrap_or_else(PoisonError::into_inner);
                    if poll.is_some() {
                        return Err(invalid_control_response());
                    }
                    *poll = Some(PollObservation::from_request(request));
                    if self.direct_poll_response {
                        ServerToRunner::CancelJob(self.cancellation.clone())
                    } else {
                        lease_poll_cancel(poll_request, self.cancellation.clone())
                    }
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
struct ReceiptGateClient {
    session_id: RunnerSessionId,
    lease_response_seen: AtomicBool,
    lease_response_changed: tokio::sync::Notify,
}

impl ReceiptGateClient {
    fn new(session_id: RunnerSessionId) -> Self {
        Self {
            session_id,
            lease_response_seen: AtomicBool::new(false),
            lease_response_changed: tokio::sync::Notify::new(),
        }
    }

    async fn wait_for_lease_response(&self) {
        loop {
            let changed = self.lease_response_changed.notified();
            if self.lease_response_seen.load(Ordering::SeqCst) {
                return;
            }
            changed.await;
        }
    }
}

impl RunnerRuntimeControlClient for ReceiptGateClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        _cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            let response = match request.message() {
                RunnerToServer::Hello(hello) => {
                    let resume = hello.resume().expect("journaled session must resume");
                    assert_eq!(resume.session_id(), self.session_id);
                    ServerToRunner::Hello(ServerHello::new(
                        OperationId::new(),
                        hello.operation_id(),
                        NegotiatedSession::new(
                            SUPPORTED_PROTOCOL_RANGE.max(),
                            automata_ci_core::JobIrVersion::current(),
                            self.session_id,
                            SessionDisposition::Resumed,
                            resume.command_cursor(),
                        ),
                        ServerTiming::new(UnixMillis::new(10_000), 1_000, 30_000),
                    ))
                }
                RunnerToServer::CommandAck(ack) => {
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(ack.header())))
                }
                RunnerToServer::LeaseResponse(response) => {
                    self.lease_response_seen.store(true, Ordering::SeqCst);
                    self.lease_response_changed.notify_waiters();
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(response.header())))
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

fn lease_poll_no_work(request: &LeaseRequest, retry_after_millis: u32) -> ServerToRunner {
    ServerToRunner::LeasePollResponse(Box::new(LeasePollResponse::no_work(
        reply_header(request.header()),
        request.authority_contributions().sha256_digest(),
        retry_after_millis,
    )))
}

fn lease_poll_offer(request: &LeaseRequest, offer: LeaseOffer) -> ServerToRunner {
    ServerToRunner::LeasePollResponse(Box::new(LeasePollResponse::lease_offer(
        reply_header(request.header()),
        request.authority_contributions().sha256_digest(),
        offer,
    )))
}

fn lease_poll_cancel(request: &LeaseRequest, cancel: CancelJob) -> ServerToRunner {
    ServerToRunner::LeasePollResponse(Box::new(LeasePollResponse::cancel_job(
        reply_header(request.header()),
        request.authority_contributions().sha256_digest(),
        cancel,
    )))
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
    runtime_with_authority(runner_id, slots, client, journal, spool, None)
}

fn runtime_with_authority(
    runner_id: RunnerId,
    slots: u16,
    client: Arc<dyn RunnerRuntimeControlClient>,
    journal: Arc<dyn RunnerJournal>,
    spool: Arc<FileSpool>,
    extension: Option<Arc<dyn LeaseAuthorityExtension>>,
) -> RunnerSessionSupervisor {
    let extensions = extension.map_or_else(LeaseAuthorityExtensionRegistry::empty, |extension| {
        LeaseAuthorityExtensionRegistry::new(vec![extension]).expect("authority registry")
    });
    runtime_with_authority_registry(runner_id, slots, client, journal, spool, extensions)
}

fn runtime_with_authority_registry(
    runner_id: RunnerId,
    slots: u16,
    client: Arc<dyn RunnerRuntimeControlClient>,
    journal: Arc<dyn RunnerJournal>,
    spool: Arc<FileSpool>,
    extensions: LeaseAuthorityExtensionRegistry,
) -> RunnerSessionSupervisor {
    let ports = RunnerRuntimePorts::new(
        client,
        journal,
        spool,
        Arc::new(support::NeverExecutor),
        Arc::new(support::FixedClock::new(10_000, 50)),
        Arc::new(support::ImmediateSleeper),
        Arc::new(SystemRuntimeIds),
    )
    .with_lease_authority_extensions(extensions);
    RunnerSessionSupervisor::new(
        support::config_with_slots_and_retry(
            runner_id,
            slots,
            automata_ci_runner_runtime::RetryPolicy::default(),
        ),
        ports,
    )
}

async fn run_one_successful_no_work(
    runner_id: RunnerId,
    session_id: RunnerSessionId,
    journal: Arc<dyn RunnerJournal>,
    spool: Arc<FileSpool>,
    extension: Arc<dyn LeaseAuthorityExtension>,
) -> Vec<PollObservation> {
    let shutdown = CancellationToken::new();
    let client = Arc::new(NoWorkClient::new(
        session_id,
        1,
        1,
        0,
        Some(shutdown.clone()),
    ));
    runtime_with_authority(
        runner_id,
        1,
        client.clone(),
        journal,
        spool,
        Some(extension),
    )
    .run(shutdown)
    .await
    .expect("one successful no-work response");
    client.observations()
}

fn seed_lease_poll(
    journal: &dyn RunnerJournal,
    session_id: RunnerSessionId,
    slot: RunnerSlotOrdinal,
) -> OperationId {
    journal
        .begin_session(SessionBinding::new(
            session_id,
            SUPPORTED_PROTOCOL_RANGE.max(),
            automata_ci_core::JobIrVersion::current(),
        ))
        .expect("seed session");
    let operation_id = OperationId::new();
    journal
        .prepare_lease_poll(session_id, slot, operation_id)
        .expect("durable checkpoint before first send");
    operation_id
}

fn assert_failed_authority_poll(
    client: &NoWorkClient,
    operation_id: OperationId,
    payload_sha256: Sha256Digest,
    source: &RotatingAuthorityExtension,
) -> Vec<PollObservation> {
    let poll = client.observations();
    assert_eq!(poll.len(), 1);
    assert_eq!(poll[0].operation_id, operation_id);
    assert_eq!(poll[0].acknowledges_operation_id, None);
    assert_eq!(
        poll[0]
            .authority_contributions
            .get("test.placement")
            .map(LeaseAuthorityPollContribution::payload_sha256),
        Some(payload_sha256)
    );
    assert!(
        source.acknowledgements().is_empty(),
        "the authority must not rotate before the poll successor is durable"
    );
    poll
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
            .cloned()
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
    let authority_source = Arc::new(RotatingAuthorityExtension::new());
    let first_payload_sha256 = authority_source.contributions[0].payload_sha256();
    let shutdown = CancellationToken::new();
    let client = Arc::new(NoWorkClient::new(
        session_id,
        1,
        1,
        2,
        Some(shutdown.clone()),
    ));

    runtime_with_authority(
        runner_id,
        1,
        client.clone(),
        journal.clone(),
        spool,
        Some(authority_source.clone()),
    )
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
    authority_source.assert_acknowledgements(&[first_payload_sha256]);
}

#[tokio::test]
async fn crashes_before_send_after_response_and_after_rotate_reconstruct_exact_poll() {
    let scratch = support::Scratch::new("lease-poll-crash-boundaries");
    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let slot = RunnerSlotOrdinal::new(1).expect("slot");
    let authority_source = Arc::new(RotatingAuthorityExtension::new());
    let first_payload_sha256 = authority_source.contributions[0].payload_sha256();
    let second_payload_sha256 = authority_source.contributions[1].payload_sha256();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let before_send_operation = seed_lease_poll(journal.as_ref(), session_id, slot);
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
    let first_runtime = runtime_with_authority(
        runner_id,
        1,
        first_client.clone(),
        faulting.clone(),
        spool.clone(),
        Some(authority_source.clone()),
    );
    let error = first_runtime
        .run(CancellationToken::new())
        .await
        .expect_err("crash after response before checkpoint rotation");
    assert!(matches!(
        error,
        RunnerRuntimeError::Journal(JournalError::InjectedFault(CommitStage::FileSynced))
    ));
    let first_poll = assert_failed_authority_poll(
        first_client.as_ref(),
        before_send_operation,
        first_payload_sha256,
        authority_source.as_ref(),
    );
    drop(first_runtime);
    drop(faulting);

    let retry_journal = Arc::new(
        FileJournal::open(scratch.journal_root(), runner_id).expect("reopen after failed rotation"),
    );
    let retried_poll = run_one_successful_no_work(
        runner_id,
        session_id,
        retry_journal.clone(),
        spool.clone(),
        authority_source.clone(),
    )
    .await;
    assert_eq!(
        retried_poll, first_poll,
        "operation and canonical bytes retry exactly"
    );
    authority_source.assert_acknowledgements(&[first_payload_sha256]);
    let rotated = retry_journal
        .snapshot()
        .expect("rotated snapshot")
        .session()
        .expect("session")
        .lease_poll_checkpoint(slot)
        .expect("rotated checkpoint")
        .clone();
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
    let resumed = run_one_successful_no_work(
        runner_id,
        session_id,
        resumed_journal,
        spool,
        authority_source.clone(),
    )
    .await;
    assert_eq!(resumed.len(), 1);
    assert_eq!(resumed[0].operation_id, rotated.current_operation_id());
    assert_eq!(
        resumed[0].acknowledges_operation_id,
        rotated.acknowledges_operation_id()
    );
    assert_eq!(
        resumed[0]
            .authority_contributions
            .get("test.placement")
            .map(LeaseAuthorityPollContribution::payload_sha256),
        Some(second_payload_sha256)
    );
    authority_source.assert_acknowledgements(&[first_payload_sha256, second_payload_sha256]);
}

#[tokio::test]
async fn accepted_offer_receipt_is_recovered_before_the_durable_slot_runs() {
    let scratch = support::Scratch::new("lease-poll-authority-ack-recovery");
    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let slot = RunnerSlotOrdinal::new(1).expect("slot");
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let authority_source = Arc::new(RotatingAuthorityExtension::new());
    authority_source.fail_next_acknowledgement();
    let receipt = LeaseAuthorityPollReceipt::for_contribution(&authority_source.contributions[0]);
    let shutdown = CancellationToken::new();
    let client = Arc::new(OfferClient::new(
        runner_id,
        session_id,
        OfferDelivery::Direct,
        shutdown.clone(),
    ));

    let first_runtime = runtime_with_authority(
        runner_id,
        1,
        client.clone(),
        journal.clone(),
        spool.clone(),
        Some(authority_source.clone()),
    );
    let error = first_runtime
        .run(shutdown.clone())
        .await
        .expect_err("extension acknowledgement fails after the offer is durable");
    assert!(matches!(
        error,
        RunnerRuntimeError::LeaseAuthority(LeaseAuthorityExtensionError::Unavailable)
    ));
    let snapshot = journal.snapshot().expect("failed-ack snapshot");
    assert!(
        snapshot.slot(slot).is_some(),
        "the accepted offer remains durable while its receipt is pending"
    );
    assert_eq!(
        snapshot
            .session()
            .expect("session")
            .lease_poll_checkpoint(slot)
            .expect("checkpoint")
            .pending_authority_receipts(),
        std::slice::from_ref(&receipt)
    );
    assert!(authority_source.acknowledgements().is_empty());
    drop(first_runtime);
    drop(journal);

    let reopened = Arc::new(
        FileJournal::open(scratch.journal_root(), runner_id)
            .expect("reopen with a pending authority receipt"),
    );
    runtime_with_authority(
        runner_id,
        1,
        client.clone(),
        reopened.clone(),
        spool,
        Some(authority_source.clone()),
    )
    .run(shutdown)
    .await
    .expect("restart drains the receipt before processing the durable offer");

    assert_eq!(
        client.observations().len(),
        1,
        "restart drains the receipt before issuing another lease poll"
    );
    assert_eq!(
        authority_source.acknowledgement_attempts(),
        vec![receipt.payload_sha256(), receipt.payload_sha256()]
    );
    authority_source.assert_acknowledgements(&[receipt.payload_sha256()]);
    let recovered = reopened.snapshot().expect("recovered snapshot");
    assert!(
        recovered
            .session()
            .expect("session")
            .lease_poll_checkpoint(slot)
            .expect("checkpoint")
            .pending_authority_receipts()
            .is_empty(),
        "the receipt is cleared only after the extension acknowledges it"
    );
}

fn assert_cross_slot_receipt_remains_pending(
    journal: &dyn RunnerJournal,
    target_slot: RunnerSlotOrdinal,
    carrier_slot: RunnerSlotOrdinal,
    receipt: &LeaseAuthorityPollReceipt,
) {
    let snapshot = journal.snapshot().expect("gated snapshot");
    assert_eq!(
        snapshot
            .slot(target_slot)
            .expect("target offer")
            .offer_status(),
        automata_ci_runner_journal::LeaseOfferStatus::Recorded
    );
    assert_eq!(
        snapshot
            .session()
            .expect("session")
            .lease_poll_checkpoint(carrier_slot)
            .expect("carrier checkpoint")
            .pending_authority_receipts(),
        std::slice::from_ref(receipt)
    );
}

#[tokio::test]
async fn cross_slot_pending_receipt_gates_target_offer_after_restart() {
    let scratch = support::Scratch::new("lease-poll-cross-slot-receipt-gate");
    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let target_slot = RunnerSlotOrdinal::new(1).expect("target slot");
    let carrier_slot = RunnerSlotOrdinal::new(2).expect("carrier slot");
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    journal
        .begin_session(SessionBinding::new(
            session_id,
            SUPPORTED_PROTOCOL_RANGE.max(),
            automata_ci_core::JobIrVersion::current(),
        ))
        .expect("seed session");
    let carrier_operation = OperationId::new();
    journal
        .prepare_lease_poll(session_id, carrier_slot, carrier_operation)
        .expect("seed carrier poll");

    let authority_source = Arc::new(BlockingAuthorityExtension::new());
    let receipt = LeaseAuthorityPollReceipt::for_contribution(&authority_source.contribution);
    let lease = Lease::new(
        LeaseId::new(),
        AttemptId::new(),
        runner_id,
        FencingToken::new(7).expect("fencing token"),
        UnixMillis::new(9_000),
        UnixMillis::new(40_000),
    )
    .expect("lease");
    let job = support::minimal_job();
    let encoded_job = encode_job_ir(&job, &automata_ci_protocol::ProtocolLimits::default())
        .expect("encode JobIR");
    let command = DurableCommand::new(
        CommandSequence::new(1).expect("command sequence"),
        OperationId::new(),
        Sha256Digest::from_bytes([0x66; 32]),
    );
    {
        let publication = spool
            .persist(ContentKind::JobIr, &encoded_job)
            .expect("persist JobIR");
        let adopted = publication.commit_with(|content| {
            let job_ir = JobIrContentRef::new(job.version(), content.clone())?;
            let offer = LeaseOfferRecord::new(target_slot, lease.clone(), job_ir, command)?;
            journal.complete_lease_poll(
                session_id,
                LeasePollCompletion::new(
                    carrier_slot,
                    carrier_operation,
                    OperationId::new(),
                    vec![receipt.clone()],
                    LeasePollCommandRecord::LeaseOffer(Box::new(offer)),
                ),
            )
        });
        if let Err(failure) = adopted {
            let (error, publication) = failure.into_parts();
            publication.abort();
            panic!("seed atomic cross-slot response: {error}");
        }
    }

    let client = Arc::new(ReceiptGateClient::new(session_id));
    let supervisor = runtime_with_authority(
        runner_id,
        2,
        client.clone(),
        journal.clone(),
        spool,
        Some(authority_source.clone()),
    );
    let mut runtime_task =
        tokio::spawn(async move { supervisor.run(CancellationToken::new()).await });
    tokio::select! {
        () = authority_source.wait_for_acknowledgement_calls(2) => {}
        () = client.wait_for_lease_response() => {
            panic!("target offer ran before its cross-slot authority receipt was acknowledged")
        }
        result = &mut runtime_task => {
            panic!("runtime stopped before both slot loops observed the receipt: {result:?}")
        }
    }
    assert!(
        !client.lease_response_seen.load(Ordering::SeqCst),
        "neither slot may process the target while the carrier receipt is pending"
    );
    authority_source.release_acknowledgements(2);
    let error = runtime_task
        .await
        .expect("runtime task")
        .expect_err("blocked authority acknowledgement fails the resumed session");
    assert!(matches!(
        error,
        RunnerRuntimeError::LeaseAuthority(LeaseAuthorityExtensionError::Unavailable)
    ));

    assert_cross_slot_receipt_remains_pending(
        journal.as_ref(),
        target_slot,
        carrier_slot,
        &receipt,
    );
}

#[tokio::test]
async fn direct_and_cross_slot_offer_responses_retire_their_carrier_polls() {
    for delivery in [OfferDelivery::Direct, OfferDelivery::CrossSlotReplay] {
        let scratch = support::Scratch::new(&format!("lease-poll-offer-{delivery:?}"));
        let runner_id = RunnerId::new();
        let session_id = RunnerSessionId::new();
        let (journal, spool) = support::durable_ports(&scratch, runner_id);
        let authority_source = Arc::new(RotatingAuthorityExtension::new());
        let first_payload_sha256 = authority_source.contributions[0].payload_sha256();
        let shutdown = CancellationToken::new();
        let client = Arc::new(OfferClient::new(
            runner_id,
            session_id,
            delivery,
            shutdown.clone(),
        ));
        let slots = client.slots();

        runtime_with_authority(
            runner_id,
            slots,
            client.clone(),
            journal.clone(),
            spool,
            Some(authority_source.clone()),
        )
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
        assert_eq!(
            authority_source
                .acknowledgement_attempts()
                .into_iter()
                .filter(|digest| *digest == first_payload_sha256)
                .count(),
            usize::from(slots),
            "every concurrent carrier acknowledges the identical source value idempotently"
        );
        assert_eq!(
            authority_source.acknowledgements().first(),
            Some(&first_payload_sha256)
        );
    }
}

#[tokio::test]
async fn durable_cancel_response_retires_its_carrier_poll() {
    let scratch = support::Scratch::new("lease-poll-cancel-carrier");
    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let authority_source = Arc::new(RotatingAuthorityExtension::new());
    let first_payload_sha256 = authority_source.contributions[0].payload_sha256();
    let shutdown = CancellationToken::new();
    let client = Arc::new(CancelClient::new(runner_id, session_id, shutdown.clone()));

    runtime_with_authority(
        runner_id,
        1,
        client.clone(),
        journal.clone(),
        spool,
        Some(authority_source.clone()),
    )
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
        .cloned()
        .expect("checkpoint");
    assert_ne!(checkpoint.current_operation_id(), poll.operation_id);
    assert_eq!(
        checkpoint.acknowledges_operation_id(),
        Some(poll.operation_id)
    );
    authority_source.assert_acknowledgements(&[first_payload_sha256]);
}

#[tokio::test]
async fn lease_authority_registry_canonicalizes_and_acks_every_extension() {
    let scratch = support::Scratch::new("lease-poll-authority-registry");
    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let alpha = Arc::new(RotatingAuthorityExtension::named("alpha.test"));
    let zulu = Arc::new(RotatingAuthorityExtension::named("zulu.test"));
    let alpha_digest = alpha.contributions[0].payload_sha256();
    let zulu_digest = zulu.contributions[0].payload_sha256();
    let registry = LeaseAuthorityExtensionRegistry::new(vec![zulu.clone(), alpha.clone()])
        .expect("canonical authority registry");
    let shutdown = CancellationToken::new();
    let client = Arc::new(NoWorkClient::new(
        session_id,
        1,
        1,
        0,
        Some(shutdown.clone()),
    ));

    runtime_with_authority_registry(runner_id, 1, client.clone(), journal, spool, registry)
        .run(shutdown)
        .await
        .expect("canonical authority poll");

    let observations = client.observations();
    let names = observations[0]
        .authority_contributions
        .as_slice()
        .iter()
        .map(|contribution| contribution.name().as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, ["alpha.test", "zulu.test"]);
    alpha.assert_acknowledgements(&[alpha_digest]);
    zulu.assert_acknowledgements(&[zulu_digest]);
}

#[test]
fn lease_authority_registry_rejects_duplicate_names() {
    let first: Arc<dyn LeaseAuthorityExtension> =
        Arc::new(RotatingAuthorityExtension::named("test.duplicate"));
    let second: Arc<dyn LeaseAuthorityExtension> =
        Arc::new(RotatingAuthorityExtension::named("test.duplicate"));
    assert!(matches!(
        LeaseAuthorityExtensionRegistry::new(vec![first, second]),
        Err(LeaseAuthorityExtensionError::DuplicateName)
    ));
}

#[tokio::test]
async fn mismatched_accepted_bundle_does_not_advance_or_ack() {
    let scratch = support::Scratch::new("lease-poll-authority-mismatch");
    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let authority_source = Arc::new(RotatingAuthorityExtension::new());
    let client = Arc::new(
        NoWorkClient::new(session_id, 1, 1, 0, None)
            .with_accepted_contributions_override(Sha256Digest::from_bytes([0x5a; 32])),
    );

    let error = runtime_with_authority(
        runner_id,
        1,
        client.clone(),
        journal.clone(),
        spool,
        Some(authority_source.clone()),
    )
    .run(CancellationToken::new())
    .await
    .expect_err("a substituted acceptance digest fails closed");
    assert!(matches!(error, RunnerRuntimeError::UnexpectedSyncResponse));

    assert_unretired_poll(journal.as_ref(), &client.observations()[0]);
    assert!(authority_source.acknowledgements().is_empty());
}

#[tokio::test]
async fn missing_acceptance_response_does_not_advance_or_ack() {
    let scratch = support::Scratch::new("lease-poll-authority-missing-response");
    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let authority_source = Arc::new(RotatingAuthorityExtension::new());
    let client =
        Arc::new(NoWorkClient::new(session_id, 1, 1, 0, None).with_invalid_poll_response());

    let error = runtime_with_authority(
        runner_id,
        1,
        client.clone(),
        journal.clone(),
        spool,
        Some(authority_source.clone()),
    )
    .run(CancellationToken::new())
    .await
    .expect_err("a response without a valid acceptance wrapper fails closed");
    assert!(matches!(error, RunnerRuntimeError::Client(_)));

    assert_unretired_poll(journal.as_ref(), &client.observations()[0]);
    assert!(authority_source.acknowledgements().is_empty());
}

#[tokio::test]
async fn direct_command_poll_response_does_not_advance_or_ack() {
    let scratch = support::Scratch::new("lease-poll-direct-command");
    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let (journal, spool) = support::durable_ports(&scratch, runner_id);
    let authority_source = Arc::new(RotatingAuthorityExtension::new());
    let client = Arc::new(
        CancelClient::new(runner_id, session_id, CancellationToken::new())
            .with_direct_poll_response(),
    );

    let error = runtime_with_authority(
        runner_id,
        1,
        client.clone(),
        journal.clone(),
        spool,
        Some(authority_source.clone()),
    )
    .run(CancellationToken::new())
    .await
    .expect_err("a direct legacy command cannot bypass poll acceptance");
    assert!(matches!(error, RunnerRuntimeError::UnexpectedSyncResponse));

    assert_unretired_poll(journal.as_ref(), &client.poll());
    assert!(authority_source.acknowledgements().is_empty());
}

fn assert_unretired_poll(journal: &dyn RunnerJournal, poll: &PollObservation) {
    let checkpoint = journal
        .snapshot()
        .expect("snapshot")
        .session()
        .expect("session")
        .lease_poll_checkpoint(poll.slot)
        .cloned()
        .expect("checkpoint");
    assert_eq!(checkpoint.current_operation_id(), poll.operation_id);
    assert_eq!(
        checkpoint.acknowledges_operation_id(),
        poll.acknowledges_operation_id
    );
}
