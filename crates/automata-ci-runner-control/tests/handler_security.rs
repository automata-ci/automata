mod support;

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use automata_ci_auth::{
    authorization::SecretExposureClass,
    machine::{AuthenticatedMachine, ExternalRunnerIdentity},
    time::UnixTimestamp,
};
use automata_ci_control::{ClaimedLeasePoll, LeasePollOutcome};
use automata_ci_core::{
    Architecture, AttemptId, FencingToken, JobAuthorityProfile, JobConclusion, JobId,
    JobInstanceIdentity, JobIr, JobIrEnvelope, JobIrVersion, JobIrVersionRange, JobLifecycle,
    JobPermissionRequest, JobResult, JobSecretExposure, JobSource, Lease, LeaseGuard, LeaseId,
    LogChannel, LogFrame, LogSequence, LogStreamId, OperatingSystem, OperationId, RunId,
    RunValueTemplates, RunnerCapabilities, RunnerGroup, RunnerId, RunnerLabel, RunnerPlatform,
    RunnerRequirements, RunnerSessionId, RuntimeBoolean, SemanticStep, Sha256Digest, ShellTemplate,
    SecretBinding, StepId, StepIr, UnixMillis, ValueTemplate, WorkflowId,
};
use automata_ci_protocol::{
    CommandAck, CommandCursor, CommandSequence, HandshakeErrorCode, JobRuntimeAuthorities,
    JobRuntimeAuthority, JobStateUpdate, LeaseDisposition, LeaseHeartbeat, LeaseOffer,
    LeaseRejectionReason, LeaseRequest, LeaseResponse, LogBatch, ManagedSecretBindingOverlay,
    MessageHeader, NoWork, ProtocolLimits, ProtocolRange, ProtocolVersion, RemoteErrorCode,
    RunnerHello, RunnerSlotOrdinal, RunnerToServer, RuntimeAuthorityCredential,
    RuntimeAuthorityEndpoint, RuntimeAuthorityName, SUPPORTED_PROTOCOL_RANGE, ServerCommandHeader,
    ServerToRunner, SessionDisposition, SessionResume, ValidatedRunnerToServer,
};
use automata_ci_protocol_protobuf::{encode_job_ir, encode_runner_frame, encode_server_frame};
use automata_ci_runner_control::{
    AuthorizedRunnerRegistration, ControlPortError, DesiredRunnerState,
    DurableRunnerControlHandler, LeaseOfferClaimStatus, LeaseOfferObservation,
    LeaseOfferPublishOutcome, LeaseOfferReplayResolution, PublishedCommand, RunnerControlConfig,
    RunnerControlFailure, RunnerControlMessageKind, RunnerControlMessageOutcome,
    RunnerControlObserver, RunnerControlPorts, RunnerDurabilityPorts, RunnerDurableDisposition,
    RunnerDurableMessageKind, RunnerHandshakeOutcome, RunnerHandshakeRejection,
    RunnerIdentityPorts, RunnerLeasePorts,
};
use automata_ci_runner_transport::ApplicationErrorKind;
use automata_ci_store::{
    BeginLeaseRequest, CANCEL_JOB_COMMAND_KIND, CANCEL_JOB_COMMAND_SCHEMA, CancelJobCommandPayload,
    CommandCursor as StoreCommandCursor, CommandReplayDisposition,
    CommandSequence as StoreCommandSequence, DocumentSchema, DurableRunnerCommand,
    EnqueueRunnerCommand, JobIrMetadata, LeaseOfferCommandIdentity, LeaseRequestCompletion,
    LeaseRequestKey, LeaseResponseAction, ObjectKey, RawLogDisposition, RevokedLeaseOfferFallback,
    RoutingDocument, RunnerCommandOutbox as _, RunnerCommandPayload, RunnerGeneration,
    RunnerOperationKind, RunnerOperationResponse, RunnerProtocolVersion, RunnerSessionFence,
    RunnerSessionSnapshot, SessionEpoch, StableRunnerSlot,
};
use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;

use support::{
    AuthorityIssuer, Authorizer, Clock, Commands, Ids, IngressObjects, Objects, Poller, Publisher,
    Receipts, Resolver, Sessions, Transactions,
};

struct Harness {
    handler: DurableRunnerControlHandler,
    observer: Arc<RecordingRunnerControlObserver>,
    authorizer: Arc<Authorizer>,
    resolver: Arc<Resolver>,
    sessions: Arc<Sessions>,
    poller: Arc<Poller>,
    objects: Arc<Objects>,
    ingress_objects: Arc<IngressObjects>,
    publisher: Arc<Publisher>,
    authority_issuer: Arc<AuthorityIssuer>,
    transactions: Arc<Transactions>,
    receipts: Arc<Receipts>,
    commands: Arc<Commands>,
}

#[derive(Debug, Default)]
struct RecordingRunnerControlObserver {
    handshakes: Mutex<Vec<RunnerHandshakeOutcome>>,
    messages: Mutex<Vec<(RunnerControlMessageKind, RunnerControlMessageOutcome)>>,
    durable: Mutex<Vec<(RunnerDurableMessageKind, RunnerDurableDisposition, u64)>>,
    offers: Mutex<Vec<LeaseOfferObservation>>,
}

impl RunnerControlObserver for RecordingRunnerControlObserver {
    fn observe_handshake(&self, outcome: RunnerHandshakeOutcome, _duration: Duration) {
        self.handshakes
            .lock()
            .expect("handshake observation lock")
            .push(outcome);
    }

    fn observe_message(
        &self,
        kind: RunnerControlMessageKind,
        outcome: RunnerControlMessageOutcome,
        _duration: Duration,
    ) {
        self.messages
            .lock()
            .expect("message observation lock")
            .push((kind, outcome));
    }

    fn observe_durable(
        &self,
        kind: RunnerDurableMessageKind,
        disposition: RunnerDurableDisposition,
        bytes: u64,
    ) {
        self.durable
            .lock()
            .expect("durable observation lock")
            .push((kind, disposition, bytes));
    }

    fn observe_lease_offer(&self, outcome: LeaseOfferObservation) {
        self.offers
            .lock()
            .expect("offer observation lock")
            .push(outcome);
    }
}

fn machine(identity: &ExternalRunnerIdentity, certificate: u8) -> AuthenticatedMachine {
    AuthenticatedMachine::new(
        identity.clone(),
        [certificate; 32],
        UnixTimestamp::from_seconds(100),
        UnixTimestamp::from_seconds(200),
    )
    .expect("machine")
}

fn snapshot(fence: RunnerSessionFence, protocol: u16) -> RunnerSessionSnapshot {
    RunnerSessionSnapshot::try_new(
        fence,
        RunnerProtocolVersion::new(protocol).expect("protocol"),
        JobIrVersion::current(),
        RoutingDocument::new("{}").expect("routing"),
        UnixMillis::new(1_000),
        UnixMillis::new(1_000),
        None,
        StoreCommandCursor::initial(),
    )
    .expect("snapshot")
}

fn harness(
    desired_state: DesiredRunnerState,
) -> (Harness, ExternalRunnerIdentity, RunnerId, RunnerGeneration) {
    let identity = ExternalRunnerIdentity::new("spiffe://automata/runner/one").expect("identity");
    let runner_id = RunnerId::new();
    let generation = RunnerGeneration::new(4).expect("generation");
    let registration = AuthorizedRunnerRegistration::new(
        identity.clone(),
        runner_id,
        generation,
        [7; 32],
        desired_state,
    );
    let authorizer = Arc::new(Authorizer {
        registration: Mutex::new(Some(registration)),
        calls: AtomicUsize::new(0),
    });
    let resolver = Arc::new(Resolver {
        fence: Mutex::new(None),
        calls: AtomicUsize::new(0),
    });
    let sessions = Arc::new(Sessions::default());
    let transactions = Arc::new(Transactions::default());
    let receipts = Arc::new(Receipts::default());
    let commands = Arc::new(Commands::default());
    let poller = Arc::new(Poller::default());
    let objects = Arc::new(Objects::default());
    let ingress_objects = Arc::new(IngressObjects::default());
    let publisher = Arc::new(Publisher::default());
    let authority_issuer = Arc::new(AuthorityIssuer::default());
    let observer = Arc::new(RecordingRunnerControlObserver::default());
    let ports = RunnerControlPorts::new(
        RunnerIdentityPorts::new(authorizer.clone(), resolver.clone(), sessions.clone()),
        RunnerLeasePorts::new(poller.clone(), objects.clone(), publisher.clone()),
        RunnerDurabilityPorts::new(
            ingress_objects.clone(),
            transactions.clone(),
            receipts.clone(),
            receipts.clone(),
            commands.clone(),
        ),
        Arc::new(Clock(UnixMillis::new(2_000))),
        Arc::new(Ids),
    )
    .with_runtime_authority_issuer(authority_issuer.clone());
    (
        Harness {
            handler: DurableRunnerControlHandler::new(ports, RunnerControlConfig::default())
                .with_observer(observer.clone()),
            observer,
            authorizer,
            resolver,
            sessions,
            poller,
            objects,
            ingress_objects,
            publisher,
            authority_issuer,
            transactions,
            receipts,
            commands,
        },
        identity,
        runner_id,
        generation,
    )
}

fn hello(runner_id: RunnerId) -> RunnerHello {
    RunnerHello::new(
        OperationId::new(),
        SUPPORTED_PROTOCOL_RANGE,
        JobIrVersionRange::current(),
        RunnerCapabilities::new(
            runner_id,
            RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
        )
        .with_labels([RunnerLabel::new("untrusted-label").expect("label")])
        .with_groups([RunnerGroup::new("administrators").expect("group")]),
        UnixMillis::new(1_000),
    )
}

fn install_session(
    harness: &Harness,
    runner_id: RunnerId,
    generation: RunnerGeneration,
) -> RunnerSessionFence {
    let fence = RunnerSessionFence::new(
        RunnerSessionId::new(),
        runner_id,
        generation,
        SessionEpoch::new(9).expect("epoch"),
    );
    *harness.resolver.fence.lock().expect("resolver lock") = Some(fence);
    *harness.sessions.snapshot.lock().expect("session lock") =
        Some(snapshot(fence, SUPPORTED_PROTOCOL_RANGE.max().get()));
    fence
}

async fn install_cancel_command(
    harness: &Harness,
    fence: RunnerSessionFence,
) -> (AttemptId, LeaseGuard, CommandSequence) {
    let attempt_id = AttemptId::new();
    let guard = LeaseGuard::new(LeaseId::new(), FencingToken::new(7).expect("fencing token"));
    let payload = CancelJobCommandPayload::new(
        attempt_id,
        guard,
        RunnerProtocolVersion::new(SUPPORTED_PROTOCOL_RANGE.max().get()).expect("protocol"),
        "superseded by a newer workflow run",
        UnixMillis::new(1_500),
    )
    .and_then(|payload| payload.encode_json())
    .expect("cancel payload");
    let command = EnqueueRunnerCommand::new(
        fence,
        OperationId::new(),
        RunnerOperationKind::new(CANCEL_JOB_COMMAND_KIND).expect("command kind"),
        RunnerCommandPayload::new(
            DocumentSchema::new(CANCEL_JOB_COMMAND_SCHEMA).expect("schema"),
            payload,
        )
        .expect("command payload"),
        UnixMillis::new(1_500),
    );
    let durable = harness
        .commands
        .enqueue_command(command)
        .await
        .expect("enqueue command");
    (
        attempt_id,
        guard,
        CommandSequence::new(durable.sequence().get()).expect("sequence"),
    )
}

async fn exchange(
    harness: &Harness,
    identity: &ExternalRunnerIdentity,
    message: &RunnerToServer,
) -> ServerToRunner {
    exchange_result(harness, identity, message)
        .await
        .expect("sync response")
}

fn handler_with_retry(harness: &Harness, retry_after_millis: u32) -> DurableRunnerControlHandler {
    let ports = RunnerControlPorts::new(
        RunnerIdentityPorts::new(
            harness.authorizer.clone(),
            harness.resolver.clone(),
            harness.sessions.clone(),
        ),
        RunnerLeasePorts::new(
            harness.poller.clone(),
            harness.objects.clone(),
            harness.publisher.clone(),
        ),
        RunnerDurabilityPorts::new(
            harness.ingress_objects.clone(),
            harness.transactions.clone(),
            harness.receipts.clone(),
            harness.receipts.clone(),
            harness.commands.clone(),
        ),
        Arc::new(Clock(UnixMillis::new(2_000))),
        Arc::new(Ids),
    )
    .with_runtime_authority_issuer(harness.authority_issuer.clone());
    DurableRunnerControlHandler::new(
        ports,
        RunnerControlConfig::new(
            15_000,
            60_000,
            retry_after_millis,
            ProtocolLimits::default(),
        )
        .expect("test retry policy"),
    )
}

async fn exchange_with_handler(
    handler: &DurableRunnerControlHandler,
    identity: &ExternalRunnerIdentity,
    message: &RunnerToServer,
) -> ServerToRunner {
    let canonical =
        encode_runner_frame(message, &ProtocolLimits::default()).expect("request bytes");
    let validated = ValidatedRunnerToServer::new(message.clone(), &ProtocolLimits::default())
        .expect("valid request");
    handler
        .handle_sync(
            &machine(identity, 7),
            &validated,
            &canonical,
            &CancellationToken::new(),
        )
        .await
        .expect("sync response")
}

async fn exchange_result(
    harness: &Harness,
    identity: &ExternalRunnerIdentity,
    message: &RunnerToServer,
) -> Result<ServerToRunner, automata_ci_runner_transport::ApplicationError> {
    let canonical =
        encode_runner_frame(message, &ProtocolLimits::default()).expect("request bytes");
    let validated = ValidatedRunnerToServer::new(message.clone(), &ProtocolLimits::default())
        .expect("valid request");
    harness
        .handler
        .handle_sync(
            &machine(identity, 7),
            &validated,
            &canonical,
            &CancellationToken::new(),
        )
        .await
}

fn record_test_command_cursor(harness: &Harness, sequence: CommandSequence) {
    let current = harness
        .sessions
        .snapshot
        .lock()
        .expect("session lock")
        .clone()
        .expect("session");
    let acknowledged = RunnerSessionSnapshot::try_new(
        current.fence(),
        current.protocol_version(),
        current.job_ir_version(),
        current.capability_snapshot().clone(),
        current.connected_at(),
        current.heartbeat_at(),
        current.disconnected_at(),
        StoreCommandCursor::through(
            automata_ci_store::CommandSequence::new(sequence.get()).expect("store sequence"),
        ),
    )
    .expect("acknowledged session");
    *harness.sessions.snapshot.lock().expect("session lock") = Some(acknowledged);
}

fn claimed_job() -> JobIrEnvelope {
    JobIrEnvelope::new(
        WorkflowId::new(),
        JobSource::new(
            "github",
            "automata-ci/automata",
            "0123456789abcdef",
            ".github/workflows/ci.yml",
            "push",
        ),
        automata_ci_core::JobExecutionContext::new(
            "CI",
            "refs/heads/main",
            "/__w/automata/automata",
            automata_ci_core::JobContentReference::new(
                "events/push.json",
                Sha256Digest::from_bytes([0x42; 32]),
                2,
                "application/json",
            ),
            automata_ci_core::JobContentReference::new(
                "contexts/claimed-handler.pb",
                Sha256Digest::from_bytes([0x43; 32]),
                2,
                "application/vnd.automata.job-runtime-context.protobuf",
            ),
        ),
        JobIr::new(
            JobId::new(),
            RunId::new(),
            "claimed-handler",
            RunnerRequirements::default(),
            JobInstanceIdentity::new(
                "claimed-handler",
                0,
                1,
                Sha256Digest::from_bytes([0x44; 32]),
            )
            .expect("job instance"),
            false,
            vec![StepIr::new(
                StepId::new("test").expect("step ID"),
                ValueTemplate::literal("Test").expect("step name template"),
                RuntimeBoolean::literal(false),
                SemanticStep::run(RunValueTemplates::new(
                    ValueTemplate::literal("cargo test").expect("command template"),
                    ShellTemplate::default_shell(),
                )),
            )],
        ),
    )
}

fn claimed_credential_free_job() -> JobIrEnvelope {
    let standard = claimed_job();
    JobIrEnvelope::new(
        standard.workflow_id(),
        standard.source().clone(),
        standard.execution().clone(),
        standard
            .job()
            .clone()
            .with_authority_profile(JobAuthorityProfile::CredentialFree)
            .with_permission_request(JobPermissionRequest::Mapping(Vec::new())),
    )
}

fn claimed_runtime_authorities(job: &JobIrEnvelope, lease: &Lease) -> JobRuntimeAuthorities {
    if job.job().authority_profile() == JobAuthorityProfile::CredentialFree {
        return JobRuntimeAuthorities::new(Vec::new(), job, lease)
            .expect("credential-free runtime authorities");
    }
    let authority = JobRuntimeAuthority::new(
        RuntimeAuthorityName::new("github-actions-results").expect("authority name"),
        job.job().run_id(),
        job.job().job_id(),
        lease.attempt_id(),
        lease.fencing_token(),
        RuntimeAuthorityEndpoint::new("https://results.example.test/").expect("endpoint"),
        RuntimeAuthorityCredential::new("fixture-results-token").expect("credential"),
        UnixMillis::new(1_500),
        UnixMillis::new(9_000),
    )
    .expect("runtime authority");
    JobRuntimeAuthorities::new(vec![authority], job, lease).expect("runtime authorities")
}

fn test_offer_command(
    fence: RunnerSessionFence,
    operation_id: OperationId,
    sequence: CommandSequence,
    slot: RunnerSlotOrdinal,
    job: &JobIrEnvelope,
    lease: &Lease,
) -> DurableRunnerCommand {
    let payload = serde_json::to_vec(&serde_json::json!({
        "job": job,
        "lease": lease,
        "protocol_version": SUPPORTED_PROTOCOL_RANGE.max().get(),
        "runtime_authorities": claimed_runtime_authorities(job, lease),
        "schema": 2,
        "slot": slot.get(),
    }))
    .expect("offer payload");
    DurableRunnerCommand::new(
        EnqueueRunnerCommand::new(
            fence,
            operation_id,
            RunnerOperationKind::new("automata.runner.lease-offer.v2").expect("offer kind"),
            RunnerCommandPayload::new(DocumentSchema::new(2).expect("schema"), payload)
                .expect("offer payload"),
            UnixMillis::new(2_000),
        ),
        StoreCommandSequence::new(sequence.get()).expect("sequence"),
        true,
    )
}

fn test_offer_command_v3(
    fence: RunnerSessionFence,
    operation_id: OperationId,
    sequence: CommandSequence,
    slot: RunnerSlotOrdinal,
    job: &JobIrEnvelope,
    lease: &Lease,
    managed_secret_bindings: &ManagedSecretBindingOverlay,
) -> DurableRunnerCommand {
    let payload = serde_json::to_vec(&serde_json::json!({
        "job": job,
        "lease": lease,
        "managed_secret_bindings": managed_secret_bindings,
        "protocol_version": SUPPORTED_PROTOCOL_RANGE.max().get(),
        "runtime_authorities": claimed_runtime_authorities(job, lease),
        "schema": 3,
        "slot": slot.get(),
    }))
    .expect("offer payload");
    DurableRunnerCommand::new(
        EnqueueRunnerCommand::new(
            fence,
            operation_id,
            RunnerOperationKind::new("automata.runner.lease-offer.v3").expect("offer kind"),
            RunnerCommandPayload::new(DocumentSchema::new(3).expect("schema"), payload)
                .expect("offer payload"),
            UnixMillis::new(2_000),
        ),
        StoreCommandSequence::new(sequence.get()).expect("sequence"),
        true,
    )
}

fn test_offer_response(
    fence: RunnerSessionFence,
    operation_id: OperationId,
    sequence: CommandSequence,
    slot: RunnerSlotOrdinal,
    job: JobIrEnvelope,
    lease: Lease,
) -> ServerToRunner {
    let authorities = claimed_runtime_authorities(&job, &lease);
    ServerToRunner::LeaseOffer(Box::new(LeaseOffer::new(
        ServerCommandHeader::new(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            operation_id,
            sequence,
        ),
        slot,
        lease,
        job,
        authorities,
    )))
}

fn durable_test_response(response: &ServerToRunner) -> RunnerOperationResponse {
    let payload = encode_server_frame(response, &ProtocolLimits::default()).expect("server frame");
    RunnerOperationResponse::new(
        DocumentSchema::new(automata_ci_protocol::MESSAGE_SCHEMA_VERSION).expect("schema"),
        payload,
    )
    .expect("durable response")
}

fn revoked_test_completion(
    request: MessageHeader,
    offer_operation_id: OperationId,
    retry_after_millis: u32,
) -> LeaseRequestCompletion {
    let mut digest = Sha256::new();
    digest.update(b"automata.runner.revoked-lease-offer-no-work.v1");
    digest.update(offer_operation_id.as_uuid().as_bytes());
    digest.update(request.operation_id().as_uuid().as_bytes());
    let encoded_operation_id = format!("{:x}", digest.finalize());
    let response_operation_id: OperationId = encoded_operation_id[..32]
        .parse()
        .expect("digest prefix operation ID");
    let durable = durable_test_response(&ServerToRunner::NoWork(NoWork::new(
        MessageHeader::reply(
            request.protocol_version(),
            request.session_id(),
            response_operation_id,
            request.operation_id(),
        ),
        retry_after_millis,
    )));
    let fallback = RevokedLeaseOfferFallback::new(
        response_operation_id,
        retry_after_millis,
        durable.schema(),
        durable.digest(),
    )
    .expect("valid revoked offer fallback");
    LeaseRequestCompletion::RevokedLeaseOffer {
        offer_operation_id,
        fallback,
    }
}

#[derive(Clone, Copy)]
enum ClaimedFailureStage {
    Inspect,
    Publish,
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn observer_records_only_reachable_handshake_and_transport_message_outcomes() {
    let (handshake, identity, runner_id, _generation) = harness(DesiredRunnerState::Active);
    handshake
        .handler
        .handle_handshake(
            &machine(&identity, 7),
            &hello(runner_id),
            &CancellationToken::new(),
        )
        .await
        .expect("opened handshake");

    let version =
        ProtocolVersion::new(SUPPORTED_PROTOCOL_RANGE.max().get() + 1).expect("protocol version");
    let unsupported = RunnerHello::new(
        OperationId::new(),
        ProtocolRange::new(version, version).expect("protocol range"),
        JobIrVersionRange::current(),
        RunnerCapabilities::new(
            runner_id,
            RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
        ),
        UnixMillis::new(1_000),
    );
    handshake
        .handler
        .handle_handshake(
            &machine(&identity, 7),
            &unsupported,
            &CancellationToken::new(),
        )
        .await
        .expect("typed handshake rejection");

    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let error = handshake
        .handler
        .handle_handshake(&machine(&identity, 7), &hello(runner_id), &cancelled)
        .await
        .expect_err("cancelled handshake");
    assert_eq!(error.kind(), ApplicationErrorKind::Unavailable);
    assert_eq!(
        *handshake
            .observer
            .handshakes
            .lock()
            .expect("handshake observation lock"),
        [
            RunnerHandshakeOutcome::Opened,
            RunnerHandshakeOutcome::Rejected(RunnerHandshakeRejection::UnsupportedProtocol),
            RunnerHandshakeOutcome::Failed(RunnerControlFailure::Unavailable),
        ]
    );

    let (transport, identity, _runner_id, _generation) = harness(DesiredRunnerState::Active);
    let message = RunnerToServer::LeaseRequest(LeaseRequest::first(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            RunnerSessionId::new(),
            OperationId::new(),
        ),
        RunnerSlotOrdinal::new(1).expect("slot"),
    ));
    let canonical = encode_runner_frame(&message, &ProtocolLimits::default()).expect("canonical");
    let validated =
        ValidatedRunnerToServer::new(message, &ProtocolLimits::default()).expect("message");

    assert!(matches!(
        transport
            .handler
            .handle_transport_sync(
                &machine(&identity, 7),
                &validated,
                &canonical,
                &CancellationToken::new(),
            )
            .await
            .expect("correlated stale-session response"),
        ServerToRunner::Error(_)
    ));
    let forbidden = transport
        .handler
        .handle_transport_sync(
            &machine(&identity, 8),
            &validated,
            &canonical,
            &CancellationToken::new(),
        )
        .await
        .expect_err("certificate mismatch remains an application failure");
    assert_eq!(forbidden.kind(), ApplicationErrorKind::Forbidden);
    assert_eq!(
        *transport
            .observer
            .messages
            .lock()
            .expect("message observation lock"),
        [
            (
                RunnerControlMessageKind::LeaseRequest,
                RunnerControlMessageOutcome::ProtocolError,
            ),
            (
                RunnerControlMessageKind::LeaseRequest,
                RunnerControlMessageOutcome::Failed(RunnerControlFailure::Forbidden),
            ),
        ]
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn retryable_claim_offer_failures_leave_the_current_poll_head_incomplete() {
    for stage in [ClaimedFailureStage::Inspect, ClaimedFailureStage::Publish] {
        let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
        let fence = install_session(&harness, runner_id, generation);
        let job = claimed_job();
        let encoded = encode_job_ir(&job, &ProtocolLimits::default()).expect("JobIR");
        let metadata = JobIrMetadata::new(
            job.job().job_id(),
            job.job().run_id(),
            job.version(),
            u64::try_from(encoded.len()).expect("size"),
            Sha256Digest::from_bytes(Sha256::digest(&encoded).into()),
            ObjectKey::new("job-ir/claimed-handler.pb").expect("object key"),
        )
        .expect("metadata");
        let lease = Lease::new(
            LeaseId::new(),
            AttemptId::new(),
            runner_id,
            FencingToken::new(5).expect("fencing token"),
            UnixMillis::new(1_500),
            UnixMillis::new(10_000),
        )
        .expect("lease");
        let slot = RunnerSlotOrdinal::new(1).expect("slot");
        *harness.poller.outcome.lock().expect("poll outcome lock") =
            Some(LeasePollOutcome::Claimed(ClaimedLeasePoll::new(
                lease.clone(),
                slot,
                metadata.clone(),
                false,
            )));
        *harness.objects.bytes.lock().expect("object bytes lock") = Some(encoded);
        *harness
            .authority_issuer
            .result
            .lock()
            .expect("authority result lock") = Some(Ok(claimed_runtime_authorities(&job, &lease)));
        *harness
            .publisher
            .inspection
            .lock()
            .expect("inspection result lock") = Some(match stage {
            ClaimedFailureStage::Inspect => Err(ControlPortError::Unavailable),
            ClaimedFailureStage::Publish => Ok(LeaseOfferClaimStatus::Current),
        });
        if matches!(stage, ClaimedFailureStage::Publish) {
            *harness
                .publisher
                .publication
                .lock()
                .expect("publication result lock") = Some(Err(ControlPortError::Unavailable));
        }

        let request = RunnerToServer::LeaseRequest(LeaseRequest::first(
            MessageHeader::request(
                SUPPORTED_PROTOCOL_RANGE.max(),
                fence.session_id(),
                OperationId::new(),
            ),
            slot,
        ));
        for _ in 0..2 {
            let error = exchange_result(&harness, &identity, &request)
                .await
                .expect_err("transient offer failure must remain retryable");
            assert_eq!(error.kind(), ApplicationErrorKind::Unavailable);
        }

        let heads = harness
            .receipts
            .lease_values
            .lock()
            .expect("lease receipt lock");
        assert_eq!(heads.len(), 1);
        assert!(
            heads[0].1.is_none(),
            "Unavailable must not complete the claimed head as NoWork or an offer"
        );
        drop(heads);
        assert_eq!(harness.poller.calls.load(Ordering::SeqCst), 2);
        assert_eq!(harness.receipts.lease_begins.load(Ordering::SeqCst), 2);
        assert_eq!(harness.receipts.lease_completions.load(Ordering::SeqCst), 0);
        assert!(
            harness
                .commands
                .values
                .lock()
                .expect("commands lock")
                .is_empty()
        );
        assert_eq!(harness.publisher.inspections.load(Ordering::SeqCst), 2);
        match stage {
            ClaimedFailureStage::Inspect => {
                assert_eq!(harness.objects.calls.load(Ordering::SeqCst), 0);
                assert_eq!(harness.authority_issuer.calls.load(Ordering::SeqCst), 0);
                assert!(
                    harness
                        .authority_issuer
                        .requests
                        .lock()
                        .expect("authority request lock")
                        .is_empty()
                );
                assert_eq!(harness.publisher.publications.load(Ordering::SeqCst), 0);
            }
            ClaimedFailureStage::Publish => {
                assert_eq!(harness.objects.calls.load(Ordering::SeqCst), 2);
                assert_eq!(harness.authority_issuer.calls.load(Ordering::SeqCst), 2);
                let requests = harness
                    .authority_issuer
                    .requests
                    .lock()
                    .expect("authority request lock");
                assert_eq!(requests.len(), 2);
                for observed in requests.iter() {
                    assert_eq!(observed.job_id, job.job().job_id());
                    assert_eq!(observed.run_id, job.job().run_id());
                    assert_eq!(observed.job_ir_version, job.version());
                    assert_eq!(observed.job_ir_metadata, metadata);
                    assert_eq!(observed.lease, lease);
                    assert_eq!(observed.issued_at, lease.issued_at());
                    assert_eq!(observed.session, fence);
                    assert_eq!(
                        observed.slot,
                        StableRunnerSlot::new(slot.get()).expect("stable slot")
                    );
                }
                drop(requests);
                assert_eq!(harness.publisher.publications.load(Ordering::SeqCst), 2);
            }
        }
        assert_eq!(
            *harness
                .observer
                .offers
                .lock()
                .expect("offer observation lock"),
            [LeaseOfferObservation::Failed, LeaseOfferObservation::Failed]
        );
    }
}

#[tokio::test]
async fn durable_v2_and_v3_offer_replays_decode_their_exact_secret_overlay_shape() {
    for schema in [2_u16, 3] {
        let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
        let fence = install_session(&harness, runner_id, generation);
        let slot = RunnerSlotOrdinal::new(1).expect("slot");
        let job = claimed_job();
        let lease = Lease::new(
            LeaseId::new(),
            AttemptId::new(),
            runner_id,
            FencingToken::new(5).expect("fencing token"),
            UnixMillis::new(1_500),
            UnixMillis::new(10_000),
        )
        .expect("lease");
        let overlay = ManagedSecretBindingOverlay::new(
            &lease,
            [(
                "DATABASE_TOKEN".to_owned(),
                SecretBinding::new("00000000-0000-4000-8000-000000000001")
                    .expect("grant")
                    .with_version_id("00000000-0000-4000-8000-000000000011")
                    .expect("version"),
            )],
        )
        .expect("managed-secret overlay");
        let operation_id = OperationId::new();
        let sequence = CommandSequence::new(1).expect("sequence");
        let command = if schema == 2 {
            test_offer_command(fence, operation_id, sequence, slot, &job, &lease)
        } else {
            test_offer_command_v3(
                fence,
                operation_id,
                sequence,
                slot,
                &job,
                &lease,
                &overlay,
            )
        };
        harness
            .commands
            .values
            .lock()
            .expect("commands lock")
            .push(command.clone());
        *harness.publisher.replay.lock().expect("offer replay lock") =
            Some(Ok(LeaseOfferReplayResolution::Published(command)));
        let request = RunnerToServer::LeaseRequest(LeaseRequest::first(
            MessageHeader::request(
                SUPPORTED_PROTOCOL_RANGE.max(),
                fence.session_id(),
                OperationId::new(),
            ),
            slot,
        ));

        let ServerToRunner::LeaseOffer(replayed) = exchange(&harness, &identity, &request).await
        else {
            panic!("schema {schema} durable lease offer");
        };
        if schema == 2 {
            assert_eq!(replayed.managed_secret_bindings(), None);
        } else {
            assert_eq!(replayed.managed_secret_bindings(), Some(&overlay));
        }
    }
}

#[tokio::test]
async fn pending_offer_replay_requires_two_way_publication_provenance() {
    for published_command_was_corrupted_to_cancel in [false, true] {
        let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
        let fence = install_session(&harness, runner_id, generation);
        let slot = RunnerSlotOrdinal::new(1).expect("slot");
        let job = claimed_job();
        let lease = Lease::new(
            LeaseId::new(),
            AttemptId::new(),
            runner_id,
            FencingToken::new(5).expect("fencing token"),
            UnixMillis::new(1_500),
            UnixMillis::new(10_000),
        )
        .expect("lease");
        if published_command_was_corrupted_to_cancel {
            install_cancel_command(&harness, fence).await;
            let pending = harness
                .commands
                .values
                .lock()
                .expect("commands lock")
                .first()
                .expect("cancel command")
                .clone();
            let sequence = CommandSequence::new(pending.sequence().get()).expect("sequence");
            let published = test_offer_command(
                fence,
                pending.request().operation_id(),
                sequence,
                slot,
                &job,
                &lease,
            );
            *harness.publisher.replay.lock().expect("offer replay lock") =
                Some(Ok(LeaseOfferReplayResolution::Published(published)));
        } else {
            let pending = test_offer_command(
                fence,
                OperationId::new(),
                CommandSequence::new(1).expect("sequence"),
                slot,
                &job,
                &lease,
            );
            harness
                .commands
                .values
                .lock()
                .expect("commands lock")
                .push(pending);
        }
        let request = RunnerToServer::LeaseRequest(LeaseRequest::first(
            MessageHeader::request(
                SUPPORTED_PROTOCOL_RANGE.max(),
                fence.session_id(),
                OperationId::new(),
            ),
            slot,
        ));

        for _ in 0..2 {
            let error = exchange_result(&harness, &identity, &request)
                .await
                .expect_err("the same unproven pending offer must keep failing closed");
            assert_eq!(error.kind(), ApplicationErrorKind::Internal);
        }
        let heads = harness
            .receipts
            .lease_values
            .lock()
            .expect("lease receipt lock");
        assert_eq!(heads.len(), 1);
        assert!(heads[0].1.is_none());
        drop(heads);
        assert_eq!(harness.publisher.replays.load(Ordering::SeqCst), 2);
        assert_eq!(harness.poller.calls.load(Ordering::SeqCst), 0);
        assert_eq!(harness.receipts.lease_completions.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn exact_pending_offer_provenance_completes_without_rebuilding_work() {
    let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
    let fence = install_session(&harness, runner_id, generation);
    let slot = RunnerSlotOrdinal::new(1).expect("slot");
    let job = claimed_job();
    let lease = Lease::new(
        LeaseId::new(),
        AttemptId::new(),
        runner_id,
        FencingToken::new(5).expect("fencing token"),
        UnixMillis::new(1_500),
        UnixMillis::new(10_000),
    )
    .expect("lease");
    let command = test_offer_command(
        fence,
        OperationId::new(),
        CommandSequence::new(1).expect("sequence"),
        slot,
        &job,
        &lease,
    );
    let expected_binding =
        LeaseOfferCommandIdentity::new(fence, command.request().operation_id(), command.sequence());
    harness
        .commands
        .values
        .lock()
        .expect("commands lock")
        .push(command.clone());
    *harness.publisher.replay.lock().expect("offer replay lock") =
        Some(Ok(LeaseOfferReplayResolution::Published(command)));
    let request = RunnerToServer::LeaseRequest(LeaseRequest::first(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        slot,
    ));

    assert!(matches!(
        exchange(&harness, &identity, &request).await,
        ServerToRunner::LeaseOffer(_)
    ));
    assert_eq!(harness.publisher.replays.load(Ordering::SeqCst), 2);
    assert_eq!(harness.poller.calls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.objects.calls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.authority_issuer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.publisher.inspections.load(Ordering::SeqCst), 0);
    assert_eq!(harness.publisher.publications.load(Ordering::SeqCst), 0);
    assert_eq!(harness.receipts.lease_completions.load(Ordering::SeqCst), 1);
    assert_eq!(
        *harness
            .receipts
            .lease_completion_bindings
            .lock()
            .expect("lease completion binding lock"),
        [Some(expected_binding)]
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn post_kms_offer_revocation_commits_no_work_before_admitting_successor() {
    let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
    let fence = install_session(&harness, runner_id, generation);
    let slot = RunnerSlotOrdinal::new(1).expect("slot");
    let job = claimed_job();
    let encoded = encode_job_ir(&job, &ProtocolLimits::default()).expect("JobIR");
    let metadata = JobIrMetadata::new(
        job.job().job_id(),
        job.job().run_id(),
        job.version(),
        u64::try_from(encoded.len()).expect("size"),
        Sha256Digest::from_bytes(Sha256::digest(&encoded).into()),
        ObjectKey::new("job-ir/post-kms-revocation.pb").expect("object key"),
    )
    .expect("metadata");
    let lease = Lease::new(
        LeaseId::new(),
        AttemptId::new(),
        runner_id,
        FencingToken::new(5).expect("fencing token"),
        UnixMillis::new(1_500),
        UnixMillis::new(10_000),
    )
    .expect("lease");
    *harness.poller.outcome.lock().expect("poll outcome lock") = Some(LeasePollOutcome::Claimed(
        ClaimedLeasePoll::new(lease.clone(), slot, metadata, false),
    ));
    *harness.objects.bytes.lock().expect("object bytes lock") = Some(encoded);
    *harness
        .authority_issuer
        .result
        .lock()
        .expect("authority result lock") = Some(Ok(claimed_runtime_authorities(&job, &lease)));
    *harness
        .publisher
        .inspection
        .lock()
        .expect("inspection result lock") = Some(Ok(LeaseOfferClaimStatus::Current));
    let offer_operation_id = OperationId::new();
    let offer_sequence = CommandSequence::new(1).expect("sequence");
    *harness
        .publisher
        .publication
        .lock()
        .expect("publication result lock") = Some(Ok(LeaseOfferPublishOutcome::Published(
        PublishedCommand::new(offer_operation_id, offer_sequence, false),
    )));
    *harness.publisher.replay.lock().expect("offer replay lock") = Some(Ok(
        LeaseOfferReplayResolution::Published(test_offer_command(
            fence,
            offer_operation_id,
            offer_sequence,
            slot,
            &job,
            &lease,
        )),
    ));
    harness
        .receipts
        .revoke_lease_completion
        .store(true, Ordering::SeqCst);
    let request_operation_id = OperationId::new();
    let request = RunnerToServer::LeaseRequest(LeaseRequest::first(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            request_operation_id,
        ),
        slot,
    ));

    let first = exchange(&harness, &identity, &request).await;
    let ServerToRunner::NoWork(no_work) = &first else {
        panic!("receipt-completion revocation must return no work")
    };
    assert_eq!(no_work.header().in_reply_to(), Some(request_operation_id));
    assert_eq!(exchange(&harness, &identity, &request).await, first);
    assert_eq!(harness.publisher.replays.load(Ordering::SeqCst), 1);
    assert_eq!(harness.poller.calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.objects.calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.authority_issuer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.publisher.publications.load(Ordering::SeqCst), 1);
    assert_eq!(harness.receipts.lease_completions.load(Ordering::SeqCst), 1);
    assert_eq!(
        harness
            .receipts
            .lease_completion_bindings
            .lock()
            .expect("lease completion binding lock")[0],
        Some(LeaseOfferCommandIdentity::new(
            fence,
            offer_operation_id,
            StoreCommandSequence::new(offer_sequence.get()).expect("store sequence"),
        ))
    );
    let durable_fallback = harness
        .receipts
        .lease_completion_revocation_responses
        .lock()
        .expect("lease completion revocation response lock")[0]
        .clone()
        .expect("offer completion must carry a durable revocation response");
    assert_eq!(
        durable_test_response(&first),
        durable_fallback,
        "the returned NoWork must be the response committed for the predecessor"
    );

    *harness.poller.outcome.lock().expect("poll outcome lock") =
        Some(LeasePollOutcome::NoWork { replayed: false });
    let successor_operation_id = OperationId::new();
    let successor = RunnerToServer::LeaseRequest(LeaseRequest::successor(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            successor_operation_id,
        ),
        slot,
        request_operation_id,
    ));
    assert!(matches!(
        exchange(&harness, &identity, &successor).await,
        ServerToRunner::NoWork(_)
    ));
    assert_eq!(harness.poller.calls.load(Ordering::SeqCst), 2);
    assert_eq!(harness.receipts.lease_completions.load(Ordering::SeqCst), 2);
    let heads = harness
        .receipts
        .lease_values
        .lock()
        .expect("lease receipt lock");
    assert_eq!(heads.len(), 1);
    assert_eq!(
        heads[0].0.request_key().operation_id(),
        successor_operation_id
    );
    assert!(heads[0].1.is_some());
}

#[tokio::test]
async fn revoked_pending_offer_requires_a_retry_before_later_work_or_polling() {
    for has_later_command in [true, false] {
        let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
        let fence = install_session(&harness, runner_id, generation);
        let slot = RunnerSlotOrdinal::new(1).expect("slot");
        let job = claimed_job();
        let lease = Lease::new(
            LeaseId::new(),
            AttemptId::new(),
            runner_id,
            FencingToken::new(5).expect("fencing token"),
            UnixMillis::new(1_500),
            UnixMillis::new(10_000),
        )
        .expect("lease");
        harness
            .commands
            .values
            .lock()
            .expect("commands lock")
            .push(test_offer_command(
                fence,
                OperationId::new(),
                CommandSequence::new(1).expect("sequence"),
                slot,
                &job,
                &lease,
            ));
        if has_later_command {
            install_cancel_command(&harness, fence).await;
        }
        {
            let mut resolutions = harness
                .publisher
                .replay_sequence
                .lock()
                .expect("offer replay sequence lock");
            resolutions.push_back(Ok(LeaseOfferReplayResolution::Revoked));
            if has_later_command {
                resolutions.push_back(Ok(LeaseOfferReplayResolution::NotPublished));
                resolutions.push_back(Ok(LeaseOfferReplayResolution::NotPublished));
            }
        }
        let request = RunnerToServer::LeaseRequest(LeaseRequest::first(
            MessageHeader::request(
                SUPPORTED_PROTOCOL_RANGE.max(),
                fence.session_id(),
                OperationId::new(),
            ),
            slot,
        ));

        let error = exchange_result(&harness, &identity, &request)
            .await
            .expect_err("a resolver-side revocation requires bounded durable retry");
        assert_eq!(error.kind(), ApplicationErrorKind::Unavailable);
        assert_eq!(harness.publisher.replays.load(Ordering::SeqCst), 1);
        assert_eq!(harness.poller.calls.load(Ordering::SeqCst), 0);
        assert_eq!(harness.receipts.lease_completions.load(Ordering::SeqCst), 0);
        assert_eq!(harness.receipts.records.load(Ordering::SeqCst), 0);
        {
            let heads = harness
                .receipts
                .lease_values
                .lock()
                .expect("lease receipt lock");
            assert_eq!(heads.len(), 1);
            assert!(heads[0].1.is_none());
        }

        harness
            .commands
            .values
            .lock()
            .expect("commands lock")
            .retain(|command| command.sequence().get() != 1);
        let response = exchange(&harness, &identity, &request).await;
        assert_eq!(
            matches!(&response, ServerToRunner::CancelJob(_)),
            has_later_command
        );
        assert_eq!(
            matches!(&response, ServerToRunner::NoWork(_)),
            !has_later_command
        );
        assert_eq!(
            harness.poller.calls.load(Ordering::SeqCst),
            usize::from(!has_later_command)
        );
        assert_eq!(
            harness.publisher.replays.load(Ordering::SeqCst),
            if has_later_command { 3 } else { 1 }
        );
        assert_eq!(harness.receipts.lease_completions.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn saturated_replay_page_is_retryable_without_polling_or_completing() {
    let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
    let fence = install_session(&harness, runner_id, generation);
    harness
        .commands
        .replay_dispositions
        .lock()
        .expect("command replay disposition lock")
        .push_back(CommandReplayDisposition::Saturated);
    let request = RunnerToServer::LeaseRequest(LeaseRequest::first(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        RunnerSlotOrdinal::new(1).expect("slot"),
    ));

    let error = exchange_result(&harness, &identity, &request)
        .await
        .expect_err("a saturated empty replay page is not an empty queue");
    assert_eq!(error.kind(), ApplicationErrorKind::Unavailable);
    assert_eq!(harness.poller.calls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.receipts.lease_completions.load(Ordering::SeqCst), 0);
    assert_eq!(harness.receipts.records.load(Ordering::SeqCst), 0);
    {
        let heads = harness
            .receipts
            .lease_values
            .lock()
            .expect("lease receipt lock");
        assert_eq!(heads.len(), 1);
        assert!(heads[0].1.is_none());
    }

    let (_, _, later_sequence) = install_cancel_command(&harness, fence).await;
    let response = exchange(&harness, &identity, &request).await;
    let ServerToRunner::CancelJob(cancel) = response else {
        panic!("the retry must reach the later durable command")
    };
    assert_eq!(cancel.header().sequence(), later_sequence);
    assert_eq!(harness.poller.calls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.receipts.lease_completions.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn post_poll_saturation_does_not_complete_the_lease_request() {
    let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
    let fence = install_session(&harness, runner_id, generation);
    harness
        .commands
        .replay_dispositions
        .lock()
        .expect("command replay disposition lock")
        .extend([
            CommandReplayDisposition::Exhausted,
            CommandReplayDisposition::Saturated,
        ]);
    let request = RunnerToServer::LeaseRequest(LeaseRequest::first(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        RunnerSlotOrdinal::new(1).expect("slot"),
    ));

    let error = exchange_result(&harness, &identity, &request)
        .await
        .expect_err("post-poll replay saturation must remain retryable");
    assert_eq!(error.kind(), ApplicationErrorKind::Unavailable);
    assert_eq!(harness.poller.calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.receipts.lease_completions.load(Ordering::SeqCst), 0);
    assert!(
        harness
            .receipts
            .lease_values
            .lock()
            .expect("lease receipt lock")[0]
            .1
            .is_none()
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn resolver_revocation_never_scans_a_second_command_in_the_same_exchange() {
    let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
    let fence = install_session(&harness, runner_id, generation);
    let slot = RunnerSlotOrdinal::new(1).expect("slot");
    let job = claimed_job();
    let lease = Lease::new(
        LeaseId::new(),
        AttemptId::new(),
        runner_id,
        FencingToken::new(5).expect("fencing token"),
        UnixMillis::new(1_500),
        UnixMillis::new(10_000),
    )
    .expect("lease");
    {
        harness
            .commands
            .values
            .lock()
            .expect("commands lock")
            .push(test_offer_command(
                fence,
                OperationId::new(),
                CommandSequence::new(1).expect("sequence"),
                slot,
                &job,
                &lease,
            ));
        harness
            .publisher
            .replay_sequence
            .lock()
            .expect("offer replay sequence lock")
            .push_back(Ok(LeaseOfferReplayResolution::Revoked));
    }
    let (_, _, later_sequence) = install_cancel_command(&harness, fence).await;
    assert_eq!(later_sequence.get(), 2);
    let request = RunnerToServer::LeaseRequest(LeaseRequest::first(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        slot,
    ));

    let error = exchange_result(&harness, &identity, &request)
        .await
        .expect_err("resolver revocation must surface bounded saturation");
    assert_eq!(error.kind(), ApplicationErrorKind::Unavailable);
    assert_eq!(harness.publisher.replays.load(Ordering::SeqCst), 1);
    assert_eq!(harness.poller.calls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.receipts.lease_completions.load(Ordering::SeqCst), 0);

    harness
        .commands
        .values
        .lock()
        .expect("commands lock")
        .retain(|command| command.sequence().get() == later_sequence.get());
    let response = exchange(&harness, &identity, &request).await;
    let ServerToRunner::CancelJob(cancel) = response else {
        panic!("the retry must reach the later durable command")
    };
    assert_eq!(cancel.header().sequence(), later_sequence);
    assert_eq!(harness.poller.calls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.receipts.lease_completions.load(Ordering::SeqCst), 1);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn credential_free_offer_bypasses_every_runtime_authority_issuer() {
    let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
    let fence = install_session(&harness, runner_id, generation);
    let job = claimed_credential_free_job();
    job.validate().expect("credential-free JobIR");
    let encoded = encode_job_ir(&job, &ProtocolLimits::default()).expect("JobIR");
    let metadata = JobIrMetadata::new(
        job.job().job_id(),
        job.job().run_id(),
        job.version(),
        u64::try_from(encoded.len()).expect("size"),
        Sha256Digest::from_bytes(Sha256::digest(&encoded).into()),
        ObjectKey::new("job-ir/credential-free-handler.pb").expect("object key"),
    )
    .expect("metadata");
    let lease = Lease::new(
        LeaseId::new(),
        AttemptId::new(),
        runner_id,
        FencingToken::new(5).expect("fencing token"),
        UnixMillis::new(1_500),
        UnixMillis::new(10_000),
    )
    .expect("lease");
    let slot = RunnerSlotOrdinal::new(1).expect("slot");
    *harness.poller.outcome.lock().expect("poll outcome lock") = Some(LeasePollOutcome::Claimed(
        ClaimedLeasePoll::new(lease.clone(), slot, metadata, false),
    ));
    *harness.objects.bytes.lock().expect("object bytes lock") = Some(encoded);
    *harness
        .publisher
        .inspection
        .lock()
        .expect("inspection result lock") = Some(Ok(LeaseOfferClaimStatus::Current));
    let published_operation_id = OperationId::new();
    let published_sequence = CommandSequence::new(1).expect("sequence");
    *harness
        .publisher
        .publication
        .lock()
        .expect("publication result lock") = Some(Ok(LeaseOfferPublishOutcome::Published(
        PublishedCommand::new(published_operation_id, published_sequence, false),
    )));
    *harness.publisher.replay.lock().expect("offer replay lock") = Some(Ok(
        LeaseOfferReplayResolution::Published(test_offer_command(
            fence,
            published_operation_id,
            published_sequence,
            slot,
            &job,
            &lease,
        )),
    ));
    let request = RunnerToServer::LeaseRequest(LeaseRequest::first(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        slot,
    ));

    let response = exchange_result(&harness, &identity, &request)
        .await
        .unwrap_or_else(|error| {
            panic!(
                "credential-free exchange failed: {error:?}; poll={}; objects={}; inspect={}; issue={}; publish={}",
                harness.poller.calls.load(Ordering::SeqCst),
                harness.objects.calls.load(Ordering::SeqCst),
                harness.publisher.inspections.load(Ordering::SeqCst),
                harness.authority_issuer.calls.load(Ordering::SeqCst),
                harness.publisher.publications.load(Ordering::SeqCst),
            )
        });
    let ServerToRunner::LeaseOffer(offer) = response else {
        panic!("credential-free poll must return an offer")
    };
    assert_eq!(
        offer.job().job().authority_profile(),
        JobAuthorityProfile::CredentialFree
    );
    assert!(
        offer
            .runtime_authorities()
            .expect("protected empty bundle")
            .as_slice()
            .is_empty()
    );
    assert_eq!(harness.authority_issuer.calls.load(Ordering::SeqCst), 0);
    assert!(
        harness
            .authority_issuer
            .requests
            .lock()
            .expect("authority request lock")
            .is_empty()
    );
    assert_eq!(harness.publisher.publications.load(Ordering::SeqCst), 1);
    let published = harness
        .publisher
        .published_commands
        .lock()
        .expect("published offer commands lock");
    assert_eq!(published.len(), 1);
    assert_eq!(published[0].offer_valid_until(), lease.expires_at());
}

#[derive(Clone, Copy)]
enum ObservedOfferScenario {
    Published,
    Replay,
    Superseded,
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn observer_distinguishes_published_replayed_and_superseded_lease_offers() {
    for scenario in [
        ObservedOfferScenario::Published,
        ObservedOfferScenario::Replay,
        ObservedOfferScenario::Superseded,
    ] {
        let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
        let fence = install_session(&harness, runner_id, generation);
        let job = claimed_job();
        let encoded = encode_job_ir(&job, &ProtocolLimits::default()).expect("JobIR");
        let metadata = JobIrMetadata::new(
            job.job().job_id(),
            job.job().run_id(),
            job.version(),
            u64::try_from(encoded.len()).expect("size"),
            Sha256Digest::from_bytes(Sha256::digest(&encoded).into()),
            ObjectKey::new("job-ir/observer-offer.pb").expect("object key"),
        )
        .expect("metadata");
        let lease = Lease::new(
            LeaseId::new(),
            AttemptId::new(),
            runner_id,
            FencingToken::new(5).expect("fencing token"),
            UnixMillis::new(1_500),
            UnixMillis::new(10_000),
        )
        .expect("lease");
        let slot = RunnerSlotOrdinal::new(1).expect("slot");
        *harness.poller.outcome.lock().expect("poll outcome lock") = Some(
            LeasePollOutcome::Claimed(ClaimedLeasePoll::new(lease.clone(), slot, metadata, false)),
        );
        *harness.objects.bytes.lock().expect("object bytes lock") = Some(encoded);
        *harness
            .authority_issuer
            .result
            .lock()
            .expect("authority result lock") = Some(Ok(claimed_runtime_authorities(&job, &lease)));
        let operation_id = OperationId::new();
        let sequence = CommandSequence::new(1).expect("sequence");
        let command = test_offer_command(fence, operation_id, sequence, slot, &job, &lease);
        match scenario {
            ObservedOfferScenario::Published => {
                *harness
                    .publisher
                    .inspection
                    .lock()
                    .expect("inspection result lock") = Some(Ok(LeaseOfferClaimStatus::Current));
                *harness
                    .publisher
                    .publication
                    .lock()
                    .expect("publication result lock") =
                    Some(Ok(LeaseOfferPublishOutcome::Published(
                        PublishedCommand::new(operation_id, sequence, false),
                    )));
                *harness.publisher.replay.lock().expect("offer replay lock") =
                    Some(Ok(LeaseOfferReplayResolution::Published(command)));
            }
            ObservedOfferScenario::Replay => {
                *harness
                    .publisher
                    .inspection
                    .lock()
                    .expect("inspection result lock") = Some(Ok(LeaseOfferClaimStatus::Published(
                    Box::new(command.clone()),
                )));
                *harness.publisher.replay.lock().expect("offer replay lock") =
                    Some(Ok(LeaseOfferReplayResolution::Published(command)));
            }
            ObservedOfferScenario::Superseded => {
                *harness
                    .publisher
                    .inspection
                    .lock()
                    .expect("inspection result lock") =
                    Some(Ok(LeaseOfferClaimStatus::ClaimSuperseded));
            }
        }

        let request = RunnerToServer::LeaseRequest(LeaseRequest::first(
            MessageHeader::request(
                SUPPORTED_PROTOCOL_RANGE.max(),
                fence.session_id(),
                operation_id,
            ),
            slot,
        ));
        let response = exchange(&harness, &identity, &request).await;
        assert_eq!(
            matches!(response, ServerToRunner::LeaseOffer(_)),
            !matches!(scenario, ObservedOfferScenario::Superseded)
        );
        assert_eq!(
            *harness
                .observer
                .offers
                .lock()
                .expect("offer observation lock"),
            [match scenario {
                ObservedOfferScenario::Published => LeaseOfferObservation::Published,
                ObservedOfferScenario::Replay => LeaseOfferObservation::Replay,
                ObservedOfferScenario::Superseded => LeaseOfferObservation::Superseded,
            }]
        );
    }
}

#[tokio::test]
async fn persisted_offer_fallback_survives_retry_policy_restart_on_both_replay_paths() {
    for revoke_at_completion in [true, false] {
        let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
        let fence = install_session(&harness, runner_id, generation);
        let slot = RunnerSlotOrdinal::new(1).expect("slot");
        let request_operation_id = OperationId::new();
        let request = RunnerToServer::LeaseRequest(LeaseRequest::first(
            MessageHeader::request(
                SUPPORTED_PROTOCOL_RANGE.max(),
                fence.session_id(),
                request_operation_id,
            ),
            slot,
        ));
        let job = claimed_job();
        let lease = Lease::new(
            LeaseId::new(),
            AttemptId::new(),
            runner_id,
            FencingToken::new(5).expect("fencing token"),
            UnixMillis::new(1_500),
            UnixMillis::new(10_000),
        )
        .expect("lease");
        let offer_operation_id = OperationId::new();
        let sequence = CommandSequence::new(1).expect("sequence");
        let command = test_offer_command(fence, offer_operation_id, sequence, slot, &job, &lease);
        harness
            .commands
            .values
            .lock()
            .expect("commands lock")
            .push(command.clone());
        *harness.publisher.replay.lock().expect("offer replay lock") =
            Some(Ok(LeaseOfferReplayResolution::Published(command)));
        harness
            .receipts
            .revoke_lease_completion
            .store(revoke_at_completion, Ordering::SeqCst);

        let first_handler = handler_with_retry(&harness, 1_750);
        let first = exchange_with_handler(&first_handler, &identity, &request).await;
        if revoke_at_completion {
            let ServerToRunner::NoWork(no_work) = &first else {
                panic!("revoked completion must return its persisted no-work fallback")
            };
            assert_eq!(no_work.retry_after_millis(), 1_750);
        } else {
            assert!(matches!(first, ServerToRunner::LeaseOffer(_)));
            *harness.publisher.replay.lock().expect("offer replay lock") =
                Some(Ok(LeaseOfferReplayResolution::Revoked));
        }

        let fallback = harness
            .receipts
            .lease_values
            .lock()
            .expect("lease receipt lock")[0]
            .1
            .as_ref()
            .and_then(LeaseRequestCompletion::revoked_offer_fallback)
            .expect("offer completion persists a fallback projection");
        assert_eq!(fallback.retry_after_millis(), 1_750);

        let restarted_handler = handler_with_retry(&harness, 9_250);
        let replay = exchange_with_handler(&restarted_handler, &identity, &request).await;
        let ServerToRunner::NoWork(no_work) = &replay else {
            panic!("revoked offer replay must return persisted no work")
        };
        assert_eq!(no_work.retry_after_millis(), 1_750);
        assert_eq!(
            no_work.header().operation_id(),
            fallback.response_operation_id()
        );
        if revoke_at_completion {
            assert_eq!(
                replay, first,
                "normal begin replay is byte-stable after restart"
            );
        }
        assert_eq!(harness.poller.calls.load(Ordering::SeqCst), 0);
        assert_eq!(harness.receipts.lease_completions.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn revoked_completed_and_race_winner_offers_replay_as_no_work() {
    for completed_before_admission in [true, false] {
        let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
        let fence = install_session(&harness, runner_id, generation);
        let slot = RunnerSlotOrdinal::new(1).expect("slot");
        let request_operation_id = OperationId::new();
        let request = RunnerToServer::LeaseRequest(LeaseRequest::first(
            MessageHeader::request(
                SUPPORTED_PROTOCOL_RANGE.max(),
                fence.session_id(),
                request_operation_id,
            ),
            slot,
        ));
        let canonical =
            encode_runner_frame(&request, &ProtocolLimits::default()).expect("canonical request");
        let begin = BeginLeaseRequest::new(
            LeaseRequestKey::first(
                fence,
                request_operation_id,
                StableRunnerSlot::new(slot.get()).expect("stable slot"),
            ),
            Sha256Digest::from_bytes(Sha256::digest(canonical).into()),
        );
        let offer_operation_id = OperationId::new();
        *harness.publisher.replay.lock().expect("offer replay lock") =
            Some(Ok(LeaseOfferReplayResolution::Revoked));
        let revoked_completion = revoked_test_completion(
            MessageHeader::request(
                SUPPORTED_PROTOCOL_RANGE.max(),
                fence.session_id(),
                request_operation_id,
            ),
            offer_operation_id,
            1_000,
        );
        if completed_before_admission {
            harness
                .receipts
                .lease_values
                .lock()
                .expect("lease receipt lock")
                .push((begin, Some(revoked_completion.clone())));
        } else {
            *harness
                .receipts
                .completion_winner
                .lock()
                .expect("completion winner lock") = Some(revoked_completion);
        }

        let first = exchange_result(&harness, &identity, &request)
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "revoked replay failed (completed_before_admission={completed_before_admission}): {error:?}"
                )
            });
        let second = exchange(&harness, &identity, &request).await;
        assert_eq!(first, second);
        let ServerToRunner::NoWork(no_work) = first else {
            panic!("a revoked durable offer must replay as no work")
        };
        assert_ne!(no_work.header().operation_id(), offer_operation_id);
        assert_eq!(no_work.header().in_reply_to(), Some(request_operation_id));
        assert_eq!(harness.publisher.replays.load(Ordering::SeqCst), 0);
        assert_eq!(
            harness.poller.calls.load(Ordering::SeqCst),
            usize::from(!completed_before_admission)
        );
        assert_eq!(
            harness.receipts.lease_completions.load(Ordering::SeqCst),
            usize::from(!completed_before_admission)
        );
        let heads = harness
            .receipts
            .lease_values
            .lock()
            .expect("lease receipt lock");
        assert_eq!(heads.len(), 1);
        assert!(heads[0].1.is_some());
    }
}

#[tokio::test]
async fn exact_completed_and_race_winner_offer_provenance_replays() {
    for completed_before_admission in [true, false] {
        let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
        let fence = install_session(&harness, runner_id, generation);
        let slot = RunnerSlotOrdinal::new(1).expect("slot");
        let request_operation_id = OperationId::new();
        let request = RunnerToServer::LeaseRequest(LeaseRequest::first(
            MessageHeader::request(
                SUPPORTED_PROTOCOL_RANGE.max(),
                fence.session_id(),
                request_operation_id,
            ),
            slot,
        ));
        let canonical =
            encode_runner_frame(&request, &ProtocolLimits::default()).expect("canonical request");
        let begin = BeginLeaseRequest::new(
            LeaseRequestKey::first(
                fence,
                request_operation_id,
                StableRunnerSlot::new(slot.get()).expect("stable slot"),
            ),
            Sha256Digest::from_bytes(Sha256::digest(canonical).into()),
        );
        let job = claimed_job();
        let lease = Lease::new(
            LeaseId::new(),
            AttemptId::new(),
            runner_id,
            FencingToken::new(5).expect("fencing token"),
            UnixMillis::new(1_500),
            UnixMillis::new(10_000),
        )
        .expect("lease");
        let server_operation_id = OperationId::new();
        let sequence = CommandSequence::new(1).expect("sequence");
        let command = test_offer_command(fence, server_operation_id, sequence, slot, &job, &lease);
        let response = durable_test_response(&test_offer_response(
            fence,
            server_operation_id,
            sequence,
            slot,
            job,
            lease,
        ));
        let completion = LeaseRequestCompletion::Response(response);
        *harness.publisher.replay.lock().expect("offer replay lock") =
            Some(Ok(LeaseOfferReplayResolution::Published(command)));
        if completed_before_admission {
            harness
                .receipts
                .lease_values
                .lock()
                .expect("lease receipt lock")
                .push((begin, Some(completion.clone())));
        } else {
            *harness
                .receipts
                .completion_winner
                .lock()
                .expect("completion winner lock") = Some(completion);
        }

        assert!(matches!(
            exchange(&harness, &identity, &request).await,
            ServerToRunner::LeaseOffer(_)
        ));
        assert_eq!(harness.publisher.replays.load(Ordering::SeqCst), 1);
        assert_eq!(
            harness.poller.calls.load(Ordering::SeqCst),
            usize::from(!completed_before_admission)
        );
        assert_eq!(
            harness.receipts.lease_completions.load(Ordering::SeqCst),
            usize::from(!completed_before_admission)
        );
    }
}

#[tokio::test]
async fn in_memory_handler_opens_a_session_then_processes_an_atomic_sync() {
    let (harness, identity, runner_id, _generation) = harness(DesiredRunnerState::Active);
    let response = harness
        .handler
        .handle_handshake(
            &machine(&identity, 7),
            &hello(runner_id),
            &CancellationToken::new(),
        )
        .await
        .expect("handshake");
    let ServerToRunner::Hello(server_hello) = response else {
        panic!("expected server hello")
    };
    let fence = harness
        .sessions
        .snapshot
        .lock()
        .expect("session lock")
        .as_ref()
        .expect("opened session")
        .fence();
    assert_eq!(server_hello.session_id(), fence.session_id());
    *harness.resolver.fence.lock().expect("resolver lock") = Some(fence);

    let message = RunnerToServer::CommandAck(CommandAck::new(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        CommandCursor::through(CommandSequence::new(1).expect("sequence")),
    ));
    let canonical = encode_runner_frame(&message, &ProtocolLimits::default()).expect("canonical");
    let validated =
        ValidatedRunnerToServer::new(message, &ProtocolLimits::default()).expect("message");
    let response = harness
        .handler
        .handle_sync(
            &machine(&identity, 7),
            &validated,
            &canonical,
            &CancellationToken::new(),
        )
        .await
        .expect("atomic sync");
    assert!(matches!(response, ServerToRunner::OperationAck(_)));
    assert_eq!(
        harness.transactions.acknowledgements.load(Ordering::SeqCst),
        1
    );
}

#[tokio::test]
async fn hello_never_promotes_advertised_labels_or_groups() {
    let (harness, identity, runner_id, _generation) = harness(DesiredRunnerState::Active);
    let response = harness
        .handler
        .handle_handshake(
            &machine(&identity, 7),
            &hello(runner_id),
            &CancellationToken::new(),
        )
        .await
        .expect("handshake");
    assert!(matches!(response, ServerToRunner::Hello(_)));
    let durable = harness
        .sessions
        .snapshot
        .lock()
        .expect("session lock")
        .clone()
        .expect("opened");
    let value: serde_json::Value =
        serde_json::from_str(durable.capability_snapshot().as_str()).expect("capability JSON");
    assert_eq!(value["labels"], serde_json::json!([]));
    assert_eq!(value["groups"], serde_json::json!([]));
}

#[tokio::test]
async fn cross_machine_certificate_is_rejected_before_session_mutation() {
    let (harness, identity, runner_id, _generation) = harness(DesiredRunnerState::Active);
    let response = harness
        .handler
        .handle_handshake(
            &machine(&identity, 8),
            &hello(runner_id),
            &CancellationToken::new(),
        )
        .await
        .expect("typed rejection");
    assert!(matches!(
        response,
        ServerToRunner::HandshakeRejected(ref rejection)
            if rejection.code() == HandshakeErrorCode::Unauthorized
    ));
    assert_eq!(harness.sessions.opens.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn negotiation_failure_is_correlated_and_does_not_open_a_session() {
    let (harness, identity, runner_id, _generation) = harness(DesiredRunnerState::Active);
    let version = ProtocolVersion::new(SUPPORTED_PROTOCOL_RANGE.max().get() + 1).expect("version");
    let unsupported = RunnerHello::new(
        OperationId::new(),
        ProtocolRange::new(version, version).expect("range"),
        JobIrVersionRange::current(),
        RunnerCapabilities::new(
            runner_id,
            RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
        ),
        UnixMillis::new(1_000),
    );
    let response = harness
        .handler
        .handle_handshake(
            &machine(&identity, 7),
            &unsupported,
            &CancellationToken::new(),
        )
        .await
        .expect("typed rejection");
    assert!(matches!(
        response,
        ServerToRunner::HandshakeRejected(ref rejection)
            if rejection.code() == HandshakeErrorCode::UnsupportedProtocol
                && rejection.in_reply_to() == unsupported.operation_id()
    ));
    assert_eq!(harness.sessions.opens.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn resume_uses_exact_durable_fence_and_cursor() {
    let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Draining);
    let fence = install_session(&harness, runner_id, generation);
    let resume = hello(runner_id).with_resume(SessionResume::new(
        fence.session_id(),
        CommandCursor::initial(),
    ));
    let response = harness
        .handler
        .handle_handshake(&machine(&identity, 7), &resume, &CancellationToken::new())
        .await
        .expect("resume");
    assert!(matches!(
        response,
        ServerToRunner::Hello(ref value)
            if value.session_disposition() == SessionDisposition::Resumed
                && value.session_id() == fence.session_id()
                && value.command_cursor() == CommandCursor::initial()
    ));
    assert_eq!(harness.sessions.resumes.load(Ordering::SeqCst), 1);
    assert_eq!(harness.sessions.opens.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn authenticated_stale_resume_is_typed_as_not_resumable() {
    let (harness, identity, runner_id, _generation) = harness(DesiredRunnerState::Active);
    let stale_session_id = RunnerSessionId::new();
    let stale = hello(runner_id).with_resume(SessionResume::new(
        stale_session_id,
        CommandCursor::initial(),
    ));

    let response = harness
        .handler
        .handle_handshake(&machine(&identity, 7), &stale, &CancellationToken::new())
        .await
        .expect("typed stale-session rejection");

    assert!(matches!(
        response,
        ServerToRunner::HandshakeRejected(ref rejection)
            if rejection.code() == HandshakeErrorCode::SessionNotResumable
                && rejection.in_reply_to() == stale.operation_id()
                && rejection.orphan_recovery().is_some_and(|authorization| {
                    let permissions = authorization.permissions();
                    authorization.session_id() == stale_session_id
                        && permissions.terminal_result()
                        && permissions.log_delivery()
                        && permissions.lease_rejection()
                })
    ));
    assert_eq!(harness.sessions.opens.load(Ordering::SeqCst), 0);
    assert_eq!(harness.sessions.resumes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn resumed_sync_replays_cancel_exactly_before_poll_until_cumulative_ack() {
    let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
    let fence = install_session(&harness, runner_id, generation);
    let (attempt_id, guard, sequence) = install_cancel_command(&harness, fence).await;
    let resume = hello(runner_id).with_resume(SessionResume::new(
        fence.session_id(),
        CommandCursor::initial(),
    ));
    assert!(matches!(
        harness
            .handler
            .handle_handshake(&machine(&identity, 7), &resume, &CancellationToken::new())
            .await
            .expect("resume"),
        ServerToRunner::Hello(ref value)
            if value.session_disposition() == SessionDisposition::Resumed
    ));

    let poll_operation = OperationId::new();
    let poll = RunnerToServer::LeaseRequest(LeaseRequest::first(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            poll_operation,
        ),
        RunnerSlotOrdinal::new(1).expect("slot"),
    ));
    let first = exchange(&harness, &identity, &poll).await;
    let replay = exchange(&harness, &identity, &poll).await;
    assert_eq!(first, replay);
    assert!(matches!(
        first,
        ServerToRunner::CancelJob(ref cancel)
            if cancel.attempt_id() == attempt_id
                && cancel.guard() == guard
                && cancel.header().sequence() == sequence
    ));
    assert_eq!(harness.poller.calls.load(Ordering::SeqCst), 0);

    let acknowledgement = RunnerToServer::CommandAck(CommandAck::new(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        CommandCursor::through(sequence),
    ));
    assert!(matches!(
        exchange(&harness, &identity, &acknowledgement).await,
        ServerToRunner::OperationAck(_)
    ));
    assert_eq!(
        harness.transactions.acknowledgements.load(Ordering::SeqCst),
        1
    );
    record_test_command_cursor(&harness, sequence);

    let successor = RunnerToServer::LeaseRequest(LeaseRequest::successor(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        RunnerSlotOrdinal::new(1).expect("slot"),
        poll_operation,
    ));
    assert!(matches!(
        exchange(&harness, &identity, &successor).await,
        ServerToRunner::NoWork(_)
    ));
    assert_eq!(harness.poller.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cumulative_command_ack_advances_cursor_and_returns_the_next_command_idempotently() {
    let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
    let fence = install_session(&harness, runner_id, generation);
    let (_first_attempt, _first_guard, first_sequence) =
        install_cancel_command(&harness, fence).await;
    let (second_attempt, second_guard, second_sequence) =
        install_cancel_command(&harness, fence).await;

    let first_ack_header = MessageHeader::request(
        SUPPORTED_PROTOCOL_RANGE.max(),
        fence.session_id(),
        OperationId::new(),
    );
    let first_ack = RunnerToServer::CommandAck(CommandAck::new(
        first_ack_header,
        CommandCursor::through(first_sequence),
    ));

    let first_response = exchange(&harness, &identity, &first_ack).await;
    assert!(matches!(
        first_response,
        ServerToRunner::CancelJob(ref cancel)
            if cancel.attempt_id() == second_attempt
                && cancel.guard() == second_guard
                && cancel.header().sequence() == second_sequence
    ));
    assert_eq!(
        *harness
            .transactions
            .command_cursor
            .lock()
            .expect("command cursor lock"),
        StoreCommandCursor::through(
            automata_ci_store::CommandSequence::new(first_sequence.get()).expect("store sequence")
        )
    );
    assert_eq!(
        harness.transactions.acknowledgements.load(Ordering::SeqCst),
        1
    );

    let replay = exchange(&harness, &identity, &first_ack).await;
    assert_eq!(replay, first_response);
    assert_eq!(
        harness.transactions.acknowledgements.load(Ordering::SeqCst),
        1,
        "the exact ACK retry must replay its receipt without another mutation"
    );
    assert_eq!(
        *harness
            .transactions
            .command_cursor
            .lock()
            .expect("command cursor lock"),
        StoreCommandCursor::through(
            automata_ci_store::CommandSequence::new(first_sequence.get()).expect("store sequence")
        )
    );

    let second_ack_header = MessageHeader::request(
        SUPPORTED_PROTOCOL_RANGE.max(),
        fence.session_id(),
        OperationId::new(),
    );
    let second_ack = RunnerToServer::CommandAck(CommandAck::new(
        second_ack_header,
        CommandCursor::through(second_sequence),
    ));
    let second_response = exchange(&harness, &identity, &second_ack).await;
    assert!(matches!(
        second_response,
        ServerToRunner::OperationAck(ack)
            if ack.header().validate_reply_for(second_ack_header).is_ok()
    ));
    assert_eq!(
        *harness
            .transactions
            .command_cursor
            .lock()
            .expect("command cursor lock"),
        StoreCommandCursor::through(
            automata_ci_store::CommandSequence::new(second_sequence.get()).expect("store sequence")
        )
    );
    assert_eq!(
        harness.transactions.acknowledgements.load(Ordering::SeqCst),
        2
    );
}

#[tokio::test]
async fn stale_generation_or_epoch_is_rejected_on_sync() {
    let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
    let fence = install_session(&harness, runner_id, generation);
    *harness.resolver.fence.lock().expect("resolver lock") = Some(RunnerSessionFence::new(
        fence.session_id(),
        runner_id,
        generation,
        SessionEpoch::new(10).expect("epoch"),
    ));
    let message = RunnerToServer::CommandAck(CommandAck::new(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        CommandCursor::through(CommandSequence::new(1).expect("sequence")),
    ));
    let validated =
        ValidatedRunnerToServer::new(message, &ProtocolLimits::default()).expect("message");
    let error = harness
        .handler
        .handle_sync(
            &machine(&identity, 7),
            &validated,
            b"canonical",
            &CancellationToken::new(),
        )
        .await
        .expect_err("stale epoch");
    assert_eq!(error.kind(), ApplicationErrorKind::StaleSession);
    assert_eq!(
        harness.transactions.acknowledgements.load(Ordering::SeqCst),
        0
    );
}

#[tokio::test]
async fn stale_registration_generation_is_rejected_even_when_epoch_resolves() {
    let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
    let stale_generation = RunnerGeneration::new(generation.get() - 1).expect("generation");
    let fence = RunnerSessionFence::new(
        RunnerSessionId::new(),
        runner_id,
        stale_generation,
        SessionEpoch::new(8).expect("epoch"),
    );
    *harness.resolver.fence.lock().expect("resolver lock") = Some(fence);
    *harness.sessions.snapshot.lock().expect("session lock") =
        Some(snapshot(fence, SUPPORTED_PROTOCOL_RANGE.max().get()));
    let message = RunnerToServer::CommandAck(CommandAck::new(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        CommandCursor::through(CommandSequence::new(1).expect("sequence")),
    ));
    let validated =
        ValidatedRunnerToServer::new(message, &ProtocolLimits::default()).expect("message");
    let error = harness
        .handler
        .handle_sync(
            &machine(&identity, 7),
            &validated,
            b"canonical",
            &CancellationToken::new(),
        )
        .await
        .expect_err("stale generation");
    assert_eq!(error.kind(), ApplicationErrorKind::StaleSession);
    assert_eq!(
        harness.transactions.acknowledgements.load(Ordering::SeqCst),
        0
    );
}

#[tokio::test]
async fn receipt_replay_returns_exact_response_without_repeating_ack_mutation() {
    let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
    let fence = install_session(&harness, runner_id, generation);
    let message = RunnerToServer::CommandAck(CommandAck::new(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        CommandCursor::through(CommandSequence::new(1).expect("sequence")),
    ));
    let canonical = encode_runner_frame(&message, &ProtocolLimits::default()).expect("canonical");
    let validated =
        ValidatedRunnerToServer::new(message, &ProtocolLimits::default()).expect("message");
    let first = harness
        .handler
        .handle_sync(
            &machine(&identity, 7),
            &validated,
            &canonical,
            &CancellationToken::new(),
        )
        .await
        .expect("first ack");
    let second = harness
        .handler
        .handle_sync(
            &machine(&identity, 7),
            &validated,
            &canonical,
            &CancellationToken::new(),
        )
        .await
        .expect("receipt replay");
    assert_eq!(first, second);
    assert_eq!(
        harness.transactions.acknowledgements.load(Ordering::SeqCst),
        1
    );
    assert_eq!(harness.sessions.heartbeats.load(Ordering::SeqCst), 0);
    assert_eq!(
        harness
            .transactions
            .receipts
            .lock()
            .expect("transaction receipts")
            .len(),
        1
    );
    assert_eq!(harness.receipts.records.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn unsupported_current_variant_returns_sanitized_error_without_mutation() {
    let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
    let fence = install_session(&harness, runner_id, generation);
    let request = RunnerToServer::JobState(JobStateUpdate::new(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        automata_ci_core::AttemptId::new(),
        LeaseGuard::new(LeaseId::new(), FencingToken::new(1).expect("fencing token")),
        JobLifecycle::Preparing,
        UnixMillis::new(2_000),
    ));
    let validated =
        ValidatedRunnerToServer::new(request, &ProtocolLimits::default()).expect("message");
    let response = harness
        .handler
        .handle_sync(
            &machine(&identity, 7),
            &validated,
            b"canonical",
            &CancellationToken::new(),
        )
        .await
        .expect("typed response");
    assert!(matches!(response, ServerToRunner::Error(ref value) if !value.is_retryable()));
    assert_eq!(
        harness.transactions.acknowledgements.load(Ordering::SeqCst),
        0
    );
    assert_eq!(harness.sessions.heartbeats.load(Ordering::SeqCst), 0);
    assert_eq!(harness.receipts.records.load(Ordering::SeqCst), 0);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn suppressed_user_and_mixed_log_batches_never_reach_blob_or_sql_commit() {
    let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
    let fence = install_session(&harness, runner_id, generation);
    *harness
        .transactions
        .log_secret_exposure
        .lock()
        .expect("log exposure lock") = SecretExposureClass::ReadableSecret;
    *harness
        .transactions
        .raw_log_disposition
        .lock()
        .expect("raw log disposition lock") = RawLogDisposition::SuppressUserOutput;
    let attempt_id = AttemptId::new();
    let guard = LeaseGuard::new(LeaseId::new(), FencingToken::new(1).expect("fencing token"));
    let cases = [
        vec![LogChannel::Stdout],
        vec![LogChannel::Stderr],
        vec![LogChannel::System, LogChannel::Stdout],
    ];
    for channels in cases {
        let stream_id = LogStreamId::new();
        let last = channels.len() - 1;
        let frames = channels
            .into_iter()
            .enumerate()
            .map(|(index, channel)| {
                LogFrame::new(
                    stream_id,
                    attempt_id,
                    LogSequence::new(u64::try_from(index).expect("sequence")),
                    UnixMillis::new(2_000),
                    channel,
                    b"untrusted user output".to_vec(),
                    index == last,
                )
                .expect("log frame")
            })
            .collect();
        let message = RunnerToServer::LogBatch(LogBatch::new(
            MessageHeader::request(
                SUPPORTED_PROTOCOL_RANGE.max(),
                fence.session_id(),
                OperationId::new(),
            ),
            guard,
            frames,
        ));
        let validated =
            ValidatedRunnerToServer::new(message, &ProtocolLimits::default()).expect("log batch");
        let error = harness
            .handler
            .handle_sync(
                &machine(&identity, 7),
                &validated,
                b"canonical suppressed log batch",
                &CancellationToken::new(),
            )
            .await
            .expect_err("suppressed user output must fail closed");
        assert_eq!(error.kind(), ApplicationErrorKind::Conflict);
    }
    assert_eq!(
        harness.transactions.log_admissions.load(Ordering::SeqCst),
        3
    );
    assert_eq!(harness.ingress_objects.puts.load(Ordering::SeqCst), 0);
    assert_eq!(harness.transactions.log_segments.load(Ordering::SeqCst), 0);
    assert!(
        harness
            .transactions
            .receipts
            .lock()
            .expect("transaction receipts")
            .is_empty()
    );

    let system_stream = LogStreamId::new();
    let system_only = RunnerToServer::LogBatch(LogBatch::new(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        guard,
        vec![
            LogFrame::new(
                system_stream,
                attempt_id,
                LogSequence::new(0),
                UnixMillis::new(2_000),
                LogChannel::System,
                b"trusted runner status".to_vec(),
                true,
            )
            .expect("system log frame"),
        ],
    ));
    let validated = ValidatedRunnerToServer::new(system_only, &ProtocolLimits::default())
        .expect("system log batch");
    let reply = harness
        .handler
        .handle_sync(
            &machine(&identity, 7),
            &validated,
            b"canonical system log batch",
            &CancellationToken::new(),
        )
        .await
        .expect("system-only log acknowledgement");
    assert!(matches!(reply, ServerToRunner::LogAck(_)));
    assert_eq!(harness.ingress_objects.puts.load(Ordering::SeqCst), 1);
    assert_eq!(harness.transactions.log_segments.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn rejected_durable_log_authority_fails_before_blob_or_sql_commit() {
    let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
    let fence = install_session(&harness, runner_id, generation);
    harness
        .transactions
        .reject_log_admission
        .store(true, Ordering::SeqCst);
    let message = RunnerToServer::LogBatch(LogBatch::new(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        LeaseGuard::new(LeaseId::new(), FencingToken::new(1).expect("fencing token")),
        vec![
            LogFrame::new(
                LogStreamId::new(),
                AttemptId::new(),
                LogSequence::new(0),
                UnixMillis::new(2_000),
                LogChannel::Stdout,
                b"untrusted output".to_vec(),
                true,
            )
            .expect("log frame"),
        ],
    ));
    let validated =
        ValidatedRunnerToServer::new(message, &ProtocolLimits::default()).expect("log batch");
    let error = harness
        .handler
        .handle_sync(
            &machine(&identity, 7),
            &validated,
            b"canonical unauthorized log batch",
            &CancellationToken::new(),
        )
        .await
        .expect_err("rejected durable authority must fail closed");
    assert_eq!(error.kind(), ApplicationErrorKind::Conflict);
    assert_eq!(
        harness.transactions.log_admissions.load(Ordering::SeqCst),
        1
    );
    assert_eq!(harness.ingress_objects.puts.load(Ordering::SeqCst), 0);
    assert_eq!(harness.transactions.log_segments.load(Ordering::SeqCst), 0);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn lease_log_and_terminal_ingress_replay_exact_acknowledgements_once() {
    let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
    let fence = install_session(&harness, runner_id, generation);
    *harness
        .transactions
        .log_secret_exposure
        .lock()
        .expect("log exposure lock") = SecretExposureClass::ReadableSecret;
    let attempt_id = AttemptId::new();
    let guard = LeaseGuard::new(LeaseId::new(), FencingToken::new(1).expect("fencing token"));
    let slot = RunnerSlotOrdinal::new(1).expect("slot");
    let lease_response = RunnerToServer::LeaseResponse(LeaseResponse::new(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        attempt_id,
        slot,
        guard,
        LeaseDisposition::Accepted,
    ));
    let validated = ValidatedRunnerToServer::new(lease_response, &ProtocolLimits::default())
        .expect("lease response");
    for _ in 0..2 {
        let reply = harness
            .handler
            .handle_sync(
                &machine(&identity, 7),
                &validated,
                b"canonical lease response",
                &CancellationToken::new(),
            )
            .await
            .expect("lease response acknowledgement");
        assert!(matches!(reply, ServerToRunner::OperationAck(_)));
    }
    assert_eq!(
        harness.transactions.lease_responses.load(Ordering::SeqCst),
        1
    );

    let stream_id = LogStreamId::new();
    let log = RunnerToServer::LogBatch(LogBatch::new(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        guard,
        vec![
            LogFrame::new(
                stream_id,
                attempt_id,
                LogSequence::new(0),
                UnixMillis::new(2_000),
                LogChannel::Stdout,
                b"hello".to_vec(),
                true,
            )
            .expect("log frame"),
        ],
    ));
    let validated =
        ValidatedRunnerToServer::new(log, &ProtocolLimits::default()).expect("log batch");
    for _ in 0..2 {
        let reply = harness
            .handler
            .handle_sync(
                &machine(&identity, 7),
                &validated,
                b"canonical log batch",
                &CancellationToken::new(),
            )
            .await
            .expect("log acknowledgement");
        assert!(matches!(
            reply,
            ServerToRunner::LogAck(ref ack)
                if ack.ack().stream_id() == stream_id
                    && ack.ack().contiguous_through() == Some(LogSequence::new(0))
        ));
    }
    assert_eq!(harness.transactions.log_segments.load(Ordering::SeqCst), 1);

    let result = RunnerToServer::JobResult(automata_ci_protocol::JobResultMessage::new(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        guard,
        JobResult::new(
            attempt_id,
            JobConclusion::Success,
            JobSecretExposure::Secretless,
            UnixMillis::new(2_000),
        ),
    ));
    let validated =
        ValidatedRunnerToServer::new(result, &ProtocolLimits::default()).expect("job result");
    for _ in 0..2 {
        let reply = harness
            .handler
            .handle_sync(
                &machine(&identity, 7),
                &validated,
                b"canonical terminal result",
                &CancellationToken::new(),
            )
            .await
            .expect("terminal acknowledgement");
        assert!(matches!(reply, ServerToRunner::OperationAck(_)));
    }
    assert_eq!(
        harness.transactions.terminal_results.load(Ordering::SeqCst),
        1
    );
    let durable = harness
        .observer
        .durable
        .lock()
        .expect("durable observation lock");
    assert_eq!(durable.len(), 6);
    assert_eq!(
        durable[0],
        (
            RunnerDurableMessageKind::LeaseResponse,
            RunnerDurableDisposition::New,
            0,
        )
    );
    assert_eq!(
        durable[1],
        (
            RunnerDurableMessageKind::LeaseResponse,
            RunnerDurableDisposition::Replay,
            0,
        )
    );
    assert!(matches!(
        durable[2],
        (
            RunnerDurableMessageKind::LogBatch,
            RunnerDurableDisposition::New,
            bytes,
        ) if bytes > 0
    ));
    assert_eq!(
        durable[3],
        (
            RunnerDurableMessageKind::LogBatch,
            RunnerDurableDisposition::Replay,
            0,
        )
    );
    assert!(matches!(
        durable[4],
        (
            RunnerDurableMessageKind::JobResult,
            RunnerDurableDisposition::New,
            bytes,
        ) if bytes > 0
    ));
    assert_eq!(
        durable[5],
        (
            RunnerDurableMessageKind::JobResult,
            RunnerDurableDisposition::Replay,
            0,
        )
    );
}

#[tokio::test]
async fn typed_lease_rejections_map_to_documented_durable_actions() {
    let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
    let fence = install_session(&harness, runner_id, generation);
    let attempt_id = AttemptId::new();
    let guard = LeaseGuard::new(LeaseId::new(), FencingToken::new(1).expect("fencing token"));
    let slot = RunnerSlotOrdinal::new(1).expect("slot");
    for reason in [
        LeaseRejectionReason::CapacityChanged,
        LeaseRejectionReason::CapabilityChanged,
        LeaseRejectionReason::ShuttingDown,
    ] {
        let message = RunnerToServer::LeaseResponse(LeaseResponse::new(
            MessageHeader::request(
                SUPPORTED_PROTOCOL_RANGE.max(),
                fence.session_id(),
                OperationId::new(),
            ),
            attempt_id,
            slot,
            guard,
            LeaseDisposition::Rejected(reason),
        ));
        let validated = ValidatedRunnerToServer::new(message, &ProtocolLimits::default())
            .expect("lease rejection");
        let reply = harness
            .handler
            .handle_sync(
                &machine(&identity, 7),
                &validated,
                b"transient rejection",
                &CancellationToken::new(),
            )
            .await
            .expect("rejection acknowledgement");
        assert!(matches!(reply, ServerToRunner::OperationAck(_)));
        assert_eq!(
            *harness
                .transactions
                .last_lease_action
                .lock()
                .expect("lease action lock"),
            Some(LeaseResponseAction::Requeue)
        );
    }

    let invalid = RunnerToServer::LeaseResponse(LeaseResponse::new(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        attempt_id,
        slot,
        guard,
        LeaseDisposition::Rejected(LeaseRejectionReason::InvalidJob),
    ));
    let validated =
        ValidatedRunnerToServer::new(invalid, &ProtocolLimits::default()).expect("invalid job");
    harness
        .handler
        .handle_sync(
            &machine(&identity, 7),
            &validated,
            b"invalid-job rejection",
            &CancellationToken::new(),
        )
        .await
        .expect("invalid-job acknowledgement");
    assert_eq!(
        *harness
            .transactions
            .last_lease_action
            .lock()
            .expect("lease action lock"),
        Some(LeaseResponseAction::Fail)
    );
}

#[tokio::test]
async fn cancellation_short_circuits_before_authorization_or_mutation() {
    let (harness, identity, runner_id, _generation) = harness(DesiredRunnerState::Active);
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let error = harness
        .handler
        .handle_handshake(&machine(&identity, 7), &hello(runner_id), &cancellation)
        .await
        .expect_err("cancelled");
    assert_eq!(error.kind(), ApplicationErrorKind::Unavailable);
    assert_eq!(harness.authorizer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.sessions.opens.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn every_sync_rejects_a_different_authenticated_machine() {
    let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
    let fence = install_session(&harness, runner_id, generation);
    let message = RunnerToServer::LeaseRequest(LeaseRequest::first(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        RunnerSlotOrdinal::new(1).expect("slot"),
    ));
    let validated =
        ValidatedRunnerToServer::new(message, &ProtocolLimits::default()).expect("message");
    let error = harness
        .handler
        .handle_sync(
            &machine(&identity, 8),
            &validated,
            b"canonical",
            &CancellationToken::new(),
        )
        .await
        .expect_err("wrong certificate");
    assert_eq!(error.kind(), ApplicationErrorKind::Forbidden);
    assert_eq!(harness.sessions.heartbeats.load(Ordering::SeqCst), 0);
    assert_eq!(harness.poller.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn sync_fences_cross_session_and_cross_protocol_claims() {
    let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
    let fence = install_session(&harness, runner_id, generation);
    let cross_session = RunnerToServer::LeaseRequest(LeaseRequest::first(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            RunnerSessionId::new(),
            OperationId::new(),
        ),
        RunnerSlotOrdinal::new(1).expect("slot"),
    ));
    let validated =
        ValidatedRunnerToServer::new(cross_session, &ProtocolLimits::default()).expect("message");
    assert_eq!(
        harness
            .handler
            .handle_sync(
                &machine(&identity, 7),
                &validated,
                b"one",
                &CancellationToken::new()
            )
            .await
            .expect_err("cross session")
            .kind(),
        ApplicationErrorKind::StaleSession,
    );

    *harness.sessions.snapshot.lock().expect("session lock") = Some(snapshot(fence, 1));
    let cross_protocol = RunnerToServer::LeaseRequest(LeaseRequest::first(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        RunnerSlotOrdinal::new(1).expect("slot"),
    ));
    let validated =
        ValidatedRunnerToServer::new(cross_protocol, &ProtocolLimits::default()).expect("message");
    assert_eq!(
        harness
            .handler
            .handle_sync(
                &machine(&identity, 7),
                &validated,
                b"two",
                &CancellationToken::new()
            )
            .await
            .expect_err("cross protocol")
            .kind(),
        ApplicationErrorKind::StaleSession,
    );
    assert_eq!(harness.sessions.heartbeats.load(Ordering::SeqCst), 0);
    assert_eq!(harness.poller.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn closed_or_disabled_session_cannot_refresh_liveness_through_a_lease_poll() {
    let (closed, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
    let fence = install_session(&closed, runner_id, generation);
    *closed.sessions.snapshot.lock().expect("session lock") = Some(
        RunnerSessionSnapshot::try_new(
            fence,
            RunnerProtocolVersion::new(SUPPORTED_PROTOCOL_RANGE.max().get()).expect("protocol"),
            JobIrVersion::current(),
            RoutingDocument::new("{}").expect("routing"),
            UnixMillis::new(1_000),
            UnixMillis::new(1_500),
            Some(UnixMillis::new(1_500)),
            StoreCommandCursor::initial(),
        )
        .expect("closed snapshot"),
    );
    let request = RunnerToServer::LeaseRequest(LeaseRequest::first(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        RunnerSlotOrdinal::new(1).expect("slot"),
    ));
    let validated =
        ValidatedRunnerToServer::new(request, &ProtocolLimits::default()).expect("message");
    let error = closed
        .handler
        .handle_sync(
            &machine(&identity, 7),
            &validated,
            b"closed session",
            &CancellationToken::new(),
        )
        .await
        .expect_err("closed session");
    assert_eq!(error.kind(), ApplicationErrorKind::StaleSession);
    assert_eq!(closed.sessions.heartbeats.load(Ordering::SeqCst), 0);
    assert_eq!(closed.poller.calls.load(Ordering::SeqCst), 0);

    let (disabled, identity, runner_id, generation) = harness(DesiredRunnerState::Disabled);
    let fence = install_session(&disabled, runner_id, generation);
    let request = RunnerToServer::LeaseRequest(LeaseRequest::first(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        RunnerSlotOrdinal::new(1).expect("slot"),
    ));
    let validated =
        ValidatedRunnerToServer::new(request, &ProtocolLimits::default()).expect("message");
    let error = disabled
        .handler
        .handle_sync(
            &machine(&identity, 7),
            &validated,
            b"disabled runner",
            &CancellationToken::new(),
        )
        .await
        .expect_err("disabled runner");
    assert_eq!(error.kind(), ApplicationErrorKind::Forbidden);
    assert_eq!(disabled.sessions.heartbeats.load(Ordering::SeqCst), 0);
    assert_eq!(disabled.poller.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn transport_sync_correlates_only_an_authenticated_stale_session() {
    let (stale, identity, _runner_id, _generation) = harness(DesiredRunnerState::Active);
    let request_header = MessageHeader::request(
        SUPPORTED_PROTOCOL_RANGE.max(),
        RunnerSessionId::new(),
        OperationId::new(),
    );
    let message = RunnerToServer::LeaseRequest(LeaseRequest::first(
        request_header,
        RunnerSlotOrdinal::new(1).expect("slot"),
    ));
    let canonical = encode_runner_frame(&message, &ProtocolLimits::default()).expect("canonical");
    let validated =
        ValidatedRunnerToServer::new(message, &ProtocolLimits::default()).expect("message");

    let response = stale
        .handler
        .handle_transport_sync(
            &machine(&identity, 7),
            &validated,
            &canonical,
            &CancellationToken::new(),
        )
        .await
        .expect("authenticated stale fence is a protocol response");
    let ServerToRunner::Error(error) = response else {
        panic!("expected a correlated stale-session response")
    };
    assert_eq!(error.code(), RemoteErrorCode::StaleSession);
    assert!(!error.is_retryable());
    error
        .header()
        .validate_reply_for(request_header)
        .expect("stale response correlation");
    assert_eq!(stale.sessions.heartbeats.load(Ordering::SeqCst), 0);
    assert_eq!(stale.poller.calls.load(Ordering::SeqCst), 0);

    let forbidden = stale
        .handler
        .handle_transport_sync(
            &machine(&identity, 8),
            &validated,
            &canonical,
            &CancellationToken::new(),
        )
        .await
        .expect_err("wrong certificate remains forbidden");
    assert_eq!(forbidden.kind(), ApplicationErrorKind::Forbidden);

    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let unavailable = stale
        .handler
        .handle_transport_sync(
            &machine(&identity, 7),
            &validated,
            &canonical,
            &cancellation,
        )
        .await
        .expect_err("cancelled request remains unavailable");
    assert_eq!(unavailable.kind(), ApplicationErrorKind::Unavailable);

    let (conflict, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
    let fence = install_session(&conflict, runner_id, generation);
    let message = RunnerToServer::LeaseRequest(LeaseRequest::first(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        RunnerSlotOrdinal::new(1).expect("slot"),
    ));
    let canonical = encode_runner_frame(&message, &ProtocolLimits::default()).expect("canonical");
    let validated =
        ValidatedRunnerToServer::new(message, &ProtocolLimits::default()).expect("message");
    conflict
        .handler
        .handle_transport_sync(
            &machine(&identity, 7),
            &validated,
            &canonical,
            &CancellationToken::new(),
        )
        .await
        .expect("initial no-work response");
    let collision = conflict
        .handler
        .handle_transport_sync(
            &machine(&identity, 7),
            &validated,
            b"same operation id with a conflicting digest",
            &CancellationToken::new(),
        )
        .await
        .expect_err("operation collision remains a conflict");
    assert_eq!(collision.kind(), ApplicationErrorKind::Conflict);
}

#[tokio::test]
async fn lease_poll_no_work_is_correlated_receipted_and_replayed() {
    let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
    let fence = install_session(&harness, runner_id, generation);
    let message = RunnerToServer::LeaseRequest(LeaseRequest::first(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        RunnerSlotOrdinal::new(1).expect("slot"),
    ));
    let canonical = encode_runner_frame(&message, &ProtocolLimits::default()).expect("canonical");
    let validated =
        ValidatedRunnerToServer::new(message, &ProtocolLimits::default()).expect("message");
    let first = harness
        .handler
        .handle_sync(
            &machine(&identity, 7),
            &validated,
            &canonical,
            &CancellationToken::new(),
        )
        .await
        .expect("no work");
    let second = harness
        .handler
        .handle_sync(
            &machine(&identity, 7),
            &validated,
            &canonical,
            &CancellationToken::new(),
        )
        .await
        .expect("replayed no work");
    assert_eq!(first, second);
    assert!(matches!(first, ServerToRunner::NoWork(_)));
    assert_eq!(harness.poller.calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.receipts.lease_completions.load(Ordering::SeqCst), 1);
    assert_eq!(harness.sessions.heartbeats.load(Ordering::SeqCst), 2);
    {
        let heartbeat_requests = harness
            .sessions
            .heartbeat_requests
            .lock()
            .expect("heartbeat requests lock");
        assert_eq!(heartbeat_requests.len(), 2);
        assert!(heartbeat_requests.iter().all(|heartbeat| {
            heartbeat.fence() == fence
                && heartbeat.command_cursor() == StoreCommandCursor::initial()
                && heartbeat.observed_at() == UnixMillis::new(2_000)
        }));
    }

    let collision = harness
        .handler
        .handle_sync(
            &machine(&identity, 7),
            &validated,
            b"same operation id with a different canonical digest",
            &CancellationToken::new(),
        )
        .await
        .expect_err("operation digest collision");
    assert_eq!(collision.kind(), ApplicationErrorKind::Conflict);
    assert_eq!(harness.sessions.heartbeats.load(Ordering::SeqCst), 2);
    assert_eq!(harness.poller.calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.receipts.lease_completions.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn lease_poll_successors_require_the_exact_completed_head_before_liveness_or_polling() {
    let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
    let fence = install_session(&harness, runner_id, generation);
    let slot = RunnerSlotOrdinal::new(1).expect("slot");
    let first_operation = OperationId::new();
    let first = RunnerToServer::LeaseRequest(LeaseRequest::first(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            first_operation,
        ),
        slot,
    ));
    assert!(matches!(
        exchange(&harness, &identity, &first).await,
        ServerToRunner::NoWork(_)
    ));

    let missing_predecessor = RunnerToServer::LeaseRequest(LeaseRequest::first(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        slot,
    ));
    let wrong_predecessor = RunnerToServer::LeaseRequest(LeaseRequest::successor(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        slot,
        OperationId::new(),
    ));
    for invalid in [&missing_predecessor, &wrong_predecessor] {
        let error = exchange_result(&harness, &identity, invalid)
            .await
            .expect_err("invalid predecessor");
        assert_eq!(error.kind(), ApplicationErrorKind::Conflict);
    }
    assert_eq!(harness.sessions.heartbeats.load(Ordering::SeqCst), 1);
    assert_eq!(harness.poller.calls.load(Ordering::SeqCst), 1);

    let successor_operation = OperationId::new();
    let successor = RunnerToServer::LeaseRequest(LeaseRequest::successor(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            successor_operation,
        ),
        slot,
        first_operation,
    ));
    let response = exchange(&harness, &identity, &successor).await;
    assert!(matches!(response, ServerToRunner::NoWork(_)));
    assert_eq!(exchange(&harness, &identity, &successor).await, response);
    assert_eq!(harness.sessions.heartbeats.load(Ordering::SeqCst), 3);
    assert_eq!(harness.poller.calls.load(Ordering::SeqCst), 2);
    assert_eq!(harness.receipts.lease_completions.load(Ordering::SeqCst), 2);

    let error = exchange_result(&harness, &identity, &first)
        .await
        .expect_err("late predecessor handler");
    assert_eq!(error.kind(), ApplicationErrorKind::Conflict);
    assert_eq!(harness.sessions.heartbeats.load(Ordering::SeqCst), 3);
    assert_eq!(harness.poller.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn lease_poll_fails_closed_when_fenced_liveness_refresh_is_rejected() {
    let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
    let fence = install_session(&harness, runner_id, generation);
    harness
        .sessions
        .reject_heartbeats
        .store(true, Ordering::SeqCst);
    let message = RunnerToServer::LeaseRequest(LeaseRequest::first(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        RunnerSlotOrdinal::new(1).expect("slot"),
    ));
    let canonical = encode_runner_frame(&message, &ProtocolLimits::default()).expect("canonical");
    let validated =
        ValidatedRunnerToServer::new(message, &ProtocolLimits::default()).expect("message");
    let error = harness
        .handler
        .handle_sync(
            &machine(&identity, 7),
            &validated,
            &canonical,
            &CancellationToken::new(),
        )
        .await
        .expect_err("closed session must stop the poll");
    assert_eq!(error.kind(), ApplicationErrorKind::StaleSession);
    assert_eq!(harness.sessions.heartbeats.load(Ordering::SeqCst), 1);
    assert_eq!(harness.poller.calls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.receipts.records.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn heartbeat_renews_exact_fence_and_replays_without_second_mutation() {
    let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
    let fence = install_session(&harness, runner_id, generation);
    let attempt_id = automata_ci_core::AttemptId::new();
    let guard = LeaseGuard::new(LeaseId::new(), FencingToken::new(2).expect("fencing token"));
    let message = RunnerToServer::Heartbeat(LeaseHeartbeat::new(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        attempt_id,
        guard,
        JobLifecycle::Running,
        UnixMillis::new(1),
    ));
    let canonical = encode_runner_frame(&message, &ProtocolLimits::default()).expect("canonical");
    let validated =
        ValidatedRunnerToServer::new(message, &ProtocolLimits::default()).expect("message");
    let first = harness
        .handler
        .handle_sync(
            &machine(&identity, 7),
            &validated,
            &canonical,
            &CancellationToken::new(),
        )
        .await
        .expect("renewal");
    *harness.receipts.value.lock().expect("receipt lock") = harness
        .transactions
        .receipts
        .lock()
        .expect("transaction receipt lock")
        .first()
        .cloned();
    let second = harness
        .handler
        .handle_sync(
            &machine(&identity, 7),
            &validated,
            &canonical,
            &CancellationToken::new(),
        )
        .await
        .expect("replayed renewal");
    assert_eq!(first, second);
    assert!(matches!(
        first,
        ServerToRunner::LeaseRenewal(ref renewal)
            if renewal.attempt_id() == attempt_id && renewal.guard() == guard
    ));
    assert_eq!(harness.transactions.heartbeats.load(Ordering::SeqCst), 1);
    assert_eq!(
        harness
            .transactions
            .renewal_authorizations
            .load(Ordering::SeqCst),
        1,
        "durable replay must not re-authorize against mutable authority state"
    );
    assert_eq!(harness.sessions.heartbeats.load(Ordering::SeqCst), 0);
    let renewal = harness
        .transactions
        .last_renewal
        .lock()
        .expect("renewal lock")
        .expect("renewal");
    assert_eq!(renewal.session(), fence);
    assert_eq!(renewal.attempt_id(), attempt_id);
    assert_eq!(renewal.guard(), guard);
    assert_eq!(renewal.expires_at(), UnixMillis::new(62_000));
    assert_eq!(harness.receipts.records.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn heartbeat_uses_the_runtime_authority_ceiling_and_rejects_an_elapsed_ceiling() {
    let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
    let fence = install_session(&harness, runner_id, generation);
    let attempt_id = automata_ci_core::AttemptId::new();
    let guard = LeaseGuard::new(LeaseId::new(), FencingToken::new(3).expect("fencing token"));
    *harness
        .transactions
        .renewal_ceiling
        .lock()
        .expect("renewal ceiling lock") = Some(UnixMillis::new(30_000));
    let bounded = RunnerToServer::Heartbeat(LeaseHeartbeat::new(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        attempt_id,
        guard,
        JobLifecycle::Running,
        UnixMillis::new(1),
    ));
    let response = exchange(&harness, &identity, &bounded).await;
    assert!(matches!(
        response,
        ServerToRunner::LeaseRenewal(ref renewal)
            if renewal.expires_at() == UnixMillis::new(30_000)
    ));
    assert_eq!(
        harness
            .transactions
            .last_renewal
            .lock()
            .expect("renewal lock")
            .expect("renewal")
            .expires_at(),
        UnixMillis::new(30_000)
    );

    *harness
        .transactions
        .renewal_ceiling
        .lock()
        .expect("renewal ceiling lock") = Some(UnixMillis::new(2_000));
    let elapsed = RunnerToServer::Heartbeat(LeaseHeartbeat::new(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        attempt_id,
        guard,
        JobLifecycle::Running,
        UnixMillis::new(2),
    ));
    let error = exchange_result(&harness, &identity, &elapsed)
        .await
        .expect_err("elapsed authority ceiling must reject renewal");
    assert_eq!(error.kind(), ApplicationErrorKind::Conflict);
    assert_eq!(harness.transactions.heartbeats.load(Ordering::SeqCst), 1);

    let finalizing = RunnerToServer::Heartbeat(LeaseHeartbeat::new(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fence.session_id(),
            OperationId::new(),
        ),
        attempt_id,
        guard,
        JobLifecycle::Finalizing,
        UnixMillis::new(3),
    ));
    let response = exchange(&harness, &identity, &finalizing).await;
    assert!(matches!(
        response,
        ServerToRunner::LeaseRenewal(ref renewal)
            if renewal.expires_at() == UnixMillis::new(62_000)
    ));
    assert_eq!(harness.transactions.heartbeats.load(Ordering::SeqCst), 2);
    assert_eq!(
        *harness
            .transactions
            .last_reported_lifecycle
            .lock()
            .expect("reported lifecycle lock"),
        Some(JobLifecycle::Finalizing),
        "the uncapped renewal must commit the quiescent lifecycle atomically"
    );
}

#[tokio::test]
async fn heartbeat_rejects_inactive_lifecycles_before_authority_lookup() {
    let (harness, identity, runner_id, generation) = harness(DesiredRunnerState::Active);
    let fence = install_session(&harness, runner_id, generation);
    let attempt_id = automata_ci_core::AttemptId::new();
    let guard = LeaseGuard::new(LeaseId::new(), FencingToken::new(4).expect("fencing token"));

    for lifecycle in [JobLifecycle::Queued, JobLifecycle::Succeeded] {
        let heartbeat = RunnerToServer::Heartbeat(LeaseHeartbeat::new(
            MessageHeader::request(
                SUPPORTED_PROTOCOL_RANGE.max(),
                fence.session_id(),
                OperationId::new(),
            ),
            attempt_id,
            guard,
            lifecycle,
            UnixMillis::new(1),
        ));
        let error = exchange_result(&harness, &identity, &heartbeat)
            .await
            .expect_err("inactive lifecycle must reject heartbeat renewal");
        assert_eq!(error.kind(), ApplicationErrorKind::Conflict);
    }

    assert_eq!(
        harness
            .transactions
            .renewal_authorizations
            .load(Ordering::SeqCst),
        0
    );
    assert_eq!(harness.transactions.heartbeats.load(Ordering::SeqCst), 0);
}
