use std::collections::BTreeMap;

use automata_ci_core::{
    Architecture, AttemptId, FencingToken, GitObjectId, IsolationLevel, JobAuthorityProfile,
    JobConclusion, JobId, JobInstanceIdentity, JobIr, JobIrEnvelope, JobIrVersion,
    JobIrVersionRange, JobLifecycle, JobPermissionGrant, JobPermissionRequest, JobResult,
    JobSecretExposure, JobSource, Lease, LeaseGuard, LeaseId, LogAck, LogChannel, LogFrame,
    LogSequence, LogStreamId, OperatingSystem, OperationId, PermissionLevel, RunId,
    RunValueTemplates, RunnerCapabilities, RunnerId, RunnerPlatform, RunnerRequirements,
    RunnerSessionId, RuntimeBoolean, SandboxCapabilities, Sha256Digest, ShellTemplate, StepId,
    StepIr, StepResult, TrustActorEvidence, TrustActorKind, TrustAutomationKind, TrustEventKind,
    TrustEvidence, TrustOriginKind, TrustPolicy, TrustRepositoryEvidence, TrustTokenRecursion,
    UnixMillis, ValueTemplate, WorkflowId,
};
use automata_ci_protocol::{
    CancelJob, CommandAck, CommandCursor, CommandSequence, ErrorMessage, HandshakeErrorCode,
    HandshakeRejected, JobResultMessage, JobRuntimeAuthorities, JobRuntimeAuthority,
    JobStateUpdate, LeaseDisposition, LeaseHeartbeat, LeaseOffer, LeaseRenewal, LeaseRequest,
    LeaseResponse, LogAckMessage, LogBatch, MAX_CONFIGURABLE_FRAME_BYTES, MessageHeader,
    MessageValidationError, NegotiatedSession, NoWork, OperationAck, ProtocolLimits,
    ProtocolLimitsError, RemoteErrorCode, RunnerHello, RunnerSlotOrdinal, RunnerToServer,
    RuntimeAuthorityCredential, RuntimeAuthorityEndpoint, RuntimeAuthorityName,
    SUPPORTED_PROTOCOL_RANGE, ServerCommandHeader, ServerHello, ServerTiming, ServerToRunner,
    SessionDisposition, ValidatedRunnerToServer, ValidatedServerToRunner,
};

fn header() -> MessageHeader {
    MessageHeader::request(
        SUPPORTED_PROTOCOL_RANGE.max(),
        RunnerSessionId::new(),
        OperationId::new(),
    )
}

fn reply_header() -> MessageHeader {
    MessageHeader::reply(
        SUPPORTED_PROTOCOL_RANGE.max(),
        RunnerSessionId::new(),
        OperationId::new(),
        OperationId::new(),
    )
}

fn command_header() -> ServerCommandHeader {
    ServerCommandHeader::new(
        SUPPORTED_PROTOCOL_RANGE.max(),
        RunnerSessionId::new(),
        OperationId::new(),
        CommandSequence::new(1).expect("valid command sequence"),
    )
}

fn slot() -> RunnerSlotOrdinal {
    RunnerSlotOrdinal::new(1).expect("valid runner slot")
}

fn guard() -> LeaseGuard {
    LeaseGuard::new(
        LeaseId::new(),
        FencingToken::new(1).expect("valid fencing token"),
    )
}

fn runner_capabilities() -> RunnerCapabilities {
    RunnerCapabilities::new(
        RunnerId::new(),
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
    )
    .with_sandbox(SandboxCapabilities::new(IsolationLevel::SharedKernel, []))
}

fn job_envelope(requirements: RunnerRequirements) -> JobIrEnvelope {
    job_envelope_with_permission(requirements, JobPermissionRequest::ProviderDefault)
}

fn job_envelope_with_permission(
    requirements: RunnerRequirements,
    permission_request: JobPermissionRequest,
) -> JobIrEnvelope {
    job_envelope_with_profile(
        requirements,
        permission_request,
        JobAuthorityProfile::Standard,
    )
}

fn job_envelope_with_profile(
    requirements: RunnerRequirements,
    permission_request: JobPermissionRequest,
    authority_profile: JobAuthorityProfile,
) -> JobIrEnvelope {
    let step = StepIr::new(
        StepId::new("build").expect("valid step ID"),
        ValueTemplate::literal("Build").expect("literal step name"),
        RuntimeBoolean::literal(false),
        automata_ci_core::SemanticStep::run(RunValueTemplates::new(
            ValueTemplate::literal("printf ok").expect("literal command"),
            ShellTemplate::default_shell(),
        )),
    );
    let job = JobIr::new(
        JobId::new(),
        RunId::new(),
        "build",
        requirements,
        JobInstanceIdentity::new("build", 0, 1, Sha256Digest::from_bytes([0x33; 32]))
            .expect("job instance"),
        false,
        vec![step],
    )
    .with_authority_profile(authority_profile)
    .with_permission_request(permission_request)
    .with_trust_snapshot(
        TrustPolicy::current()
            .evaluate(
                TrustEvidence::new(TrustOriginKind::ProviderWebhook, TrustEventKind::Push)
                    .with_original_actor(
                        TrustActorEvidence::new(
                            "actor-1",
                            TrustActorKind::User,
                            TrustAutomationKind::None,
                        )
                        .expect("actor evidence"),
                    )
                    .with_repositories(
                        TrustRepositoryEvidence::new("42", "7").expect("source repository"),
                        TrustRepositoryEvidence::new("42", "7").expect("target repository"),
                    )
                    .with_refs("refs/heads/main", "refs/heads/main", "refs/heads/main")
                    .with_revisions("source-sha", "target-sha", "execution-sha")
                    .with_fork(false)
                    .with_token_recursion(TrustTokenRecursion::Suppressed),
            )
            .expect("trusted snapshot"),
    );
    JobIrEnvelope::new(
        WorkflowId::new(),
        JobSource::new(
            "github",
            "owner/repository",
            GitObjectId::from_provider_hex("0123456789abcdef0123456789abcdef01234567")
                .expect("revision"),
            ".ci/workflows/ci.yml",
            "push",
        ),
        automata_ci_core::JobExecutionContext::new(
            "CI",
            "refs/heads/main",
            "/__w/repository/repository",
            automata_ci_core::JobContentReference::new(
                "events/push.json",
                Sha256Digest::from_bytes([0x42; 32]),
                2,
                "application/json",
            ),
            automata_ci_core::JobContentReference::new(
                "contexts/build.pb",
                Sha256Digest::from_bytes([0x43; 32]),
                2,
                "application/vnd.automata.job-runtime-context.protobuf",
            ),
        ),
        job,
    )
}

#[test]
fn authority_bundle_emptiness_must_match_the_immutable_job_profile() {
    let runner_id = RunnerId::new();
    let attempt_id = AttemptId::new();
    let lease = lease(attempt_id, runner_id);
    let standard = job_envelope(RunnerRequirements::default());
    assert!(matches!(
        JobRuntimeAuthorities::new(Vec::new(), &standard, &lease),
        Err(automata_ci_protocol::RuntimeAuthorityError::AuthorityProfileMismatch)
    ));

    let credential_free = job_envelope_with_profile(
        RunnerRequirements::default(),
        JobPermissionRequest::Mapping(Vec::new()),
        JobAuthorityProfile::CredentialFree,
    );
    credential_free.validate().expect("credential-free JobIR");
    let authority = JobRuntimeAuthority::new(
        RuntimeAuthorityName::new("runner-results").expect("authority name"),
        credential_free.job().run_id(),
        credential_free.job().job_id(),
        lease.attempt_id(),
        lease.fencing_token(),
        RuntimeAuthorityEndpoint::new("https://results.example.test/").expect("endpoint"),
        RuntimeAuthorityCredential::new("header.payload.signature").expect("credential"),
        UnixMillis::new(10),
        UnixMillis::new(19),
    )
    .expect("authority");
    assert!(matches!(
        JobRuntimeAuthorities::new(vec![authority], &credential_free, &lease),
        Err(automata_ci_protocol::RuntimeAuthorityError::AuthorityProfileMismatch)
    ));
    JobRuntimeAuthorities::new(Vec::new(), &credential_free, &lease)
        .expect("credential-free empty authority bundle");
    let offer = LeaseOffer::new(command_header(), slot(), lease, credential_free);
    ValidatedServerToRunner::new(
        ServerToRunner::LeaseOffer(Box::new(offer)),
        &ProtocolLimits::default(),
    )
    .expect("credential-free offer validates");
}

fn lease(attempt_id: AttemptId, runner_id: RunnerId) -> Lease {
    Lease::new(
        LeaseId::new(),
        attempt_id,
        runner_id,
        FencingToken::new(1).expect("valid fencing token"),
        UnixMillis::new(10),
        UnixMillis::new(20),
    )
    .expect("valid lease")
}

fn lease_offer(
    header: ServerCommandHeader,
    slot: RunnerSlotOrdinal,
    lease: Lease,
    job: JobIrEnvelope,
) -> LeaseOffer {
    LeaseOffer::new(header, slot, lease, job)
}

fn result(attempt_id: AttemptId) -> JobResult {
    JobResult::new(
        attempt_id,
        JobConclusion::Success,
        JobSecretExposure::Secretless,
        UnixMillis::new(30),
    )
    .with_steps(vec![StepResult::new(
        StepId::new("build").expect("valid step ID"),
        JobConclusion::Success,
        JobConclusion::Success,
        UnixMillis::new(10),
        UnixMillis::new(20),
    )])
}

fn log_frame(
    stream_id: LogStreamId,
    attempt_id: AttemptId,
    sequence: u64,
    payload: &[u8],
    end_of_stream: bool,
) -> LogFrame {
    if end_of_stream {
        LogFrame::stream_finished(
            stream_id,
            attempt_id,
            LogSequence::new(sequence),
            UnixMillis::new(10),
        )
    } else {
        LogFrame::line(
            stream_id,
            attempt_id,
            LogSequence::new(sequence),
            UnixMillis::new(10),
            automata_ci_core::LogGroupId::new("test").expect("group ID"),
            LogChannel::Stdout,
            payload.to_vec(),
        )
    }
    .expect("valid log frame")
}

#[test]
fn every_runner_envelope_variant_passes_the_validated_boundary() {
    let limits = ProtocolLimits::default();
    let attempt_id = AttemptId::new();
    let lease_guard = guard();
    let stream_id = LogStreamId::new();
    let messages = vec![
        RunnerToServer::Hello(RunnerHello::new(
            OperationId::new(),
            SUPPORTED_PROTOCOL_RANGE,
            JobIrVersionRange::current(),
            runner_capabilities(),
            UnixMillis::new(1),
        )),
        RunnerToServer::LeaseRequest(LeaseRequest::first(header(), slot())),
        RunnerToServer::LeaseResponse(LeaseResponse::new(
            header(),
            attempt_id,
            slot(),
            lease_guard,
            LeaseDisposition::Accepted,
        )),
        RunnerToServer::Heartbeat(LeaseHeartbeat::new(
            header(),
            attempt_id,
            lease_guard,
            JobLifecycle::Running,
            UnixMillis::new(2),
        )),
        RunnerToServer::JobState(JobStateUpdate::new(
            header(),
            attempt_id,
            lease_guard,
            JobLifecycle::Running,
            UnixMillis::new(2),
        )),
        RunnerToServer::JobResult(JobResultMessage::new(
            header(),
            lease_guard,
            result(attempt_id),
        )),
        RunnerToServer::LogBatch(LogBatch::new(
            header(),
            lease_guard,
            vec![log_frame(stream_id, attempt_id, 0, b"ok", false)],
        )),
        RunnerToServer::CommandAck(CommandAck::new(
            header(),
            CommandCursor::through(CommandSequence::new(1).expect("valid command sequence")),
        )),
    ];

    for message in messages {
        let validated =
            ValidatedRunnerToServer::new(message.clone(), &limits).expect("validate message");
        assert_eq!(validated.into_message(), message);
    }
}

#[test]
fn every_server_envelope_variant_passes_the_validated_boundary() {
    let limits = ProtocolLimits::default();
    let attempt_id = AttemptId::new();
    let runner_id = RunnerId::new();
    let active_lease = lease(attempt_id, runner_id);
    let lease_guard = active_lease.guard();
    let stream_id = LogStreamId::new();
    let messages = vec![
        ServerToRunner::Hello(ServerHello::new(
            OperationId::new(),
            OperationId::new(),
            NegotiatedSession::new(
                SUPPORTED_PROTOCOL_RANGE.max(),
                JobIrVersion::current(),
                RunnerSessionId::new(),
                SessionDisposition::Opened,
                CommandCursor::initial(),
            ),
            ServerTiming::new(UnixMillis::new(1), 1_000, 30_000),
        )),
        ServerToRunner::HandshakeRejected(HandshakeRejected::new(
            OperationId::new(),
            OperationId::new(),
            HandshakeErrorCode::UnsupportedProtocol,
            SUPPORTED_PROTOCOL_RANGE,
            "no common protocol",
        )),
        ServerToRunner::LeaseOffer(Box::new(lease_offer(
            command_header(),
            slot(),
            active_lease,
            job_envelope(RunnerRequirements::default()),
        ))),
        ServerToRunner::LeaseRenewal(LeaseRenewal::new(
            reply_header(),
            attempt_id,
            lease_guard,
            UnixMillis::new(30),
        )),
        ServerToRunner::CancelJob(CancelJob::new(
            command_header(),
            attempt_id,
            lease_guard,
            "workflow cancelled",
            UnixMillis::new(2),
        )),
        ServerToRunner::LogAck(LogAckMessage::new(
            reply_header(),
            LogAck::new(stream_id, Some(LogSequence::new(0))),
        )),
        ServerToRunner::OperationAck(OperationAck::new(reply_header())),
        ServerToRunner::NoWork(NoWork::new(reply_header(), 1_000)),
        ServerToRunner::Error(ErrorMessage::new(
            reply_header(),
            RemoteErrorCode::RetryLater,
            "retry later",
            true,
        )),
    ];

    for message in messages {
        let validated =
            ValidatedServerToRunner::new(message.clone(), &limits).expect("validate message");
        assert_eq!(validated.into_message(), message);
    }
}

#[test]
fn trusted_limit_configuration_rejects_zero_excessive_and_incoherent_budgets() {
    assert_eq!(
        ProtocolLimits::new(0, 1, 1, 1, 1),
        Err(ProtocolLimitsError::ZeroLimit)
    );
    assert_eq!(
        ProtocolLimits::new(MAX_CONFIGURABLE_FRAME_BYTES + 1, 1, 1, 1, 1),
        Err(ProtocolLimitsError::FrameLimitTooLarge)
    );
    assert_eq!(
        ProtocolLimits::new(64, 2, 65, 1, 1),
        Err(ProtocolLimitsError::Incoherent)
    );
    assert_eq!(
        ProtocolLimits::new(64, 1, 32, 2, 32),
        Err(ProtocolLimitsError::Incoherent)
    );
}

#[test]
fn unvalidated_message_cannot_enter_the_validated_handler_boundary() {
    let invalid_header = MessageHeader::reply(
        SUPPORTED_PROTOCOL_RANGE.max(),
        RunnerSessionId::new(),
        OperationId::new(),
        OperationId::new(),
    );
    let raw = RunnerToServer::LeaseRequest(LeaseRequest::first(invalid_header, slot()));

    assert!(matches!(
        ValidatedRunnerToServer::try_from(raw),
        Err(MessageValidationError::UnexpectedResponseCorrelation)
    ));
}

#[test]
fn nested_job_and_result_domain_errors_are_rejected() {
    let limits = ProtocolLimits::default();
    let attempt_id = AttemptId::new();
    let runner_id = RunnerId::new();
    let offer = ServerToRunner::LeaseOffer(Box::new(lease_offer(
        command_header(),
        slot(),
        lease(attempt_id, runner_id),
        job_envelope(RunnerRequirements::default()),
    )));
    let mut invalid_job = serde_json::to_value(offer).expect("serialize lease offer");
    invalid_job["payload"]["job"]["job"]["steps"][0]["timeout"] = serde_json::json!({
        "value": { "kind": "literal", "value": 0 },
        "unit": "seconds"
    });
    let invalid_job: ServerToRunner =
        serde_json::from_value(invalid_job).expect("decode invalid job fixture structurally");
    assert!(matches!(
        ValidatedServerToRunner::new(invalid_job, &limits),
        Err(MessageValidationError::Job(_))
    ));

    let result_message =
        RunnerToServer::JobResult(JobResultMessage::new(header(), guard(), result(attempt_id)));
    let mut invalid_result = serde_json::to_value(result_message).expect("serialize job result");
    invalid_result["payload"]["result"]["steps"][0]["completed_at"] = serde_json::json!(40);
    let invalid_result: RunnerToServer =
        serde_json::from_value(invalid_result).expect("decode invalid result fixture structurally");
    assert!(matches!(
        ValidatedRunnerToServer::new(invalid_result, &limits),
        Err(MessageValidationError::JobResult(_))
    ));
}

#[test]
fn current_lease_offer_requires_explicit_managed_secret_bindings() {
    let attempt_id = AttemptId::new();
    let offer = ServerToRunner::LeaseOffer(Box::new(lease_offer(
        command_header(),
        slot(),
        lease(attempt_id, RunnerId::new()),
        job_envelope(RunnerRequirements::default()),
    )));
    let mut incomplete = serde_json::to_value(offer).expect("serialize lease offer");
    incomplete["payload"]
        .as_object_mut()
        .expect("lease-offer payload")
        .remove("managed_secret_bindings");

    assert!(serde_json::from_value::<ServerToRunner>(incomplete).is_err());
}

#[test]
fn nested_requirement_collections_obey_the_configured_budget() {
    use automata_ci_core::RunnerLabel;

    let requirements = RunnerRequirements::default().with_labels([
        RunnerLabel::new("linux").expect("valid label"),
        RunnerLabel::new("x64").expect("valid label"),
    ]);
    let attempt_id = AttemptId::new();
    let message = ServerToRunner::LeaseOffer(Box::new(lease_offer(
        command_header(),
        slot(),
        lease(attempt_id, RunnerId::new()),
        job_envelope(requirements),
    )));
    let limits =
        ProtocolLimits::new(16 * 1024, 1, 1_024, 1, 1_024).expect("coherent collection limits");

    assert!(matches!(
        ValidatedServerToRunner::new(message, &limits),
        Err(MessageValidationError::CollectionTooLarge {
            field: "required runner labels",
            length: 2,
            maximum: 1
        })
    ));
}

#[test]
fn nested_job_and_result_maps_obey_the_configured_budget() {
    let limits =
        ProtocolLimits::new(16 * 1024, 1, 1_024, 1, 1_024).expect("coherent collection limits");
    let attempt_id = AttemptId::new();
    let offer = ServerToRunner::LeaseOffer(Box::new(lease_offer(
        command_header(),
        slot(),
        lease(attempt_id, RunnerId::new()),
        job_envelope(RunnerRequirements::default()),
    )));
    let mut job = serde_json::to_value(offer).expect("serialize lease offer");
    job["payload"]["job"]["job"]["environment"] = serde_json::json!({
        "FIRST": {"kind": "literal", "value": "one"},
        "SECOND": {"kind": "literal", "value": "two"}
    });
    let job: ServerToRunner =
        serde_json::from_value(job).expect("decode oversized map fixture structurally");
    let job_error = ValidatedServerToRunner::new(job, &limits).expect_err("oversized job map");
    assert!(
        matches!(
            job_error,
            MessageValidationError::CollectionTooLarge {
                field: "job environment",
                length: 2,
                maximum: 1
            }
        ),
        "unexpected oversized job error: {job_error:?}"
    );

    let result_message =
        RunnerToServer::JobResult(JobResultMessage::new(header(), guard(), result(attempt_id)));
    let mut result_message = serde_json::to_value(result_message).expect("serialize job result");
    result_message["payload"]["result"]["outputs"] = serde_json::json!({
        "first": {"sensitivity": "public", "value": "one"},
        "second": {"sensitivity": "public", "value": "two"}
    });
    let result_message: RunnerToServer = serde_json::from_value(result_message)
        .expect("decode oversized output map fixture structurally");
    assert!(matches!(
        ValidatedRunnerToServer::new(result_message, &limits),
        Err(MessageValidationError::CollectionTooLarge {
            field: "job outputs",
            length: 2,
            maximum: 1
        })
    ));
}

#[test]
fn job_permission_requests_obey_transport_collection_and_text_budgets() {
    let collection_limits =
        ProtocolLimits::new(16 * 1024, 2, 1_024, 1, 1_024).expect("collection limits");
    let excessive = job_envelope_with_permission(
        RunnerRequirements::default(),
        JobPermissionRequest::mapping([
            JobPermissionGrant::new("actions", PermissionLevel::Read),
            JobPermissionGrant::new("contents", PermissionLevel::Read),
            JobPermissionGrant::new("statuses", PermissionLevel::Write),
        ]),
    );
    assert!(matches!(
        automata_ci_protocol::validate_job_ir_envelope(&excessive, &collection_limits),
        Err(MessageValidationError::CollectionTooLarge {
            field: "job permission grants",
            length: 3,
            maximum: 2,
        })
    ));

    let text_limits = ProtocolLimits::new(16 * 1024, 64, 63, 1, 1).expect("text limits");
    let overlong_for_transport = job_envelope_with_permission(
        RunnerRequirements::default(),
        JobPermissionRequest::mapping([JobPermissionGrant::new(
            "a".repeat(automata_ci_core::MAX_JOB_PERMISSION_NAME_BYTES),
            PermissionLevel::None,
        )]),
    );
    assert!(matches!(
        automata_ci_protocol::validate_job_ir_envelope(&overlong_for_transport, &text_limits),
        Err(MessageValidationError::TextTooLong {
            field: "job permission name",
            length: 64,
            maximum: 63,
        })
    ));
}

#[test]
fn log_batches_are_single_stream_contiguous_and_terminal() {
    let limits = ProtocolLimits::default();
    let attempt_id = AttemptId::new();
    let stream_id = LogStreamId::new();
    let lease_guard = guard();

    let non_contiguous = RunnerToServer::LogBatch(LogBatch::new(
        header(),
        lease_guard,
        vec![
            log_frame(stream_id, attempt_id, 0, b"a", false),
            log_frame(stream_id, attempt_id, 2, b"b", false),
        ],
    ));
    assert!(matches!(
        ValidatedRunnerToServer::new(non_contiguous, &limits),
        Err(MessageValidationError::NonContiguousLogSequence {
            previous: 0,
            received: 2
        })
    ));

    let mixed_streams = RunnerToServer::LogBatch(LogBatch::new(
        header(),
        lease_guard,
        vec![
            log_frame(stream_id, attempt_id, 0, b"a", false),
            log_frame(LogStreamId::new(), attempt_id, 1, b"b", false),
        ],
    ));
    assert!(matches!(
        ValidatedRunnerToServer::new(mixed_streams, &limits),
        Err(MessageValidationError::MixedLogStreams)
    ));

    let after_terminal = RunnerToServer::LogBatch(LogBatch::new(
        header(),
        lease_guard,
        vec![
            log_frame(stream_id, attempt_id, 0, b"", true),
            log_frame(stream_id, attempt_id, 1, b"late", false),
        ],
    ));
    assert!(matches!(
        ValidatedRunnerToServer::new(after_terminal, &limits),
        Err(MessageValidationError::LogFrameAfterEndOfStream)
    ));
}

#[test]
fn log_payload_and_frame_counts_obey_independent_budgets() {
    let attempt_id = AttemptId::new();
    let stream_id = LogStreamId::new();
    let message = RunnerToServer::LogBatch(LogBatch::new(
        header(),
        guard(),
        vec![
            log_frame(stream_id, attempt_id, 0, b"abc", false),
            log_frame(stream_id, attempt_id, 1, b"def", false),
        ],
    ));
    let payload_limits =
        ProtocolLimits::new(4_096, 4, 1_024, 2, 5).expect("coherent payload limits");
    assert!(matches!(
        ValidatedRunnerToServer::new(message.clone(), &payload_limits),
        Err(MessageValidationError::LogBatchPayloadTooLarge {
            size: 6,
            maximum: 5
        })
    ));

    let count_limits =
        ProtocolLimits::new(4_096, 4, 1_024, 1, 8).expect("coherent frame-count limits");
    assert!(matches!(
        ValidatedRunnerToServer::new(message, &count_limits),
        Err(MessageValidationError::CollectionTooLarge {
            field: "log frames",
            length: 2,
            maximum: 1
        })
    ));
}

#[test]
fn cancellation_and_error_detail_text_use_control_plane_limits() {
    let limits =
        ProtocolLimits::new(64 * 1024, 4, 16 * 1024, 4, 1_024).expect("coherent control limits");
    let cancellation = ServerToRunner::CancelJob(CancelJob::new(
        command_header(),
        AttemptId::new(),
        guard(),
        "x".repeat(4_097),
        UnixMillis::new(1),
    ));
    assert!(matches!(
        ValidatedServerToRunner::new(cancellation, &limits),
        Err(MessageValidationError::TextTooLong {
            field: "cancellation reason",
            length: 4_097,
            maximum: 4_096
        })
    ));

    let mut details = BTreeMap::new();
    details.insert("trace".to_owned(), "x".repeat(4_097));
    let error = ServerToRunner::Error(
        ErrorMessage::new(
            reply_header(),
            RemoteErrorCode::Internal,
            "internal error",
            false,
        )
        .with_details(details),
    );
    assert!(matches!(
        ValidatedServerToRunner::new(error, &limits),
        Err(MessageValidationError::TextTooLong {
            field: "error detail value",
            length: 4_097,
            maximum: 4_096
        })
    ));
}

#[test]
fn validated_boundary_checks_nested_log_schema() {
    let limits = ProtocolLimits::default();
    let attempt_id = AttemptId::new();
    let log = RunnerToServer::LogBatch(LogBatch::new(
        header(),
        guard(),
        vec![log_frame(LogStreamId::new(), attempt_id, 0, b"log", false)],
    ));
    let mut invalid_log = serde_json::to_value(log).expect("serialize log batch");
    invalid_log["payload"]["frames"][0]["schema_version"] = serde_json::json!(u16::MAX);
    let invalid_log: RunnerToServer =
        serde_json::from_value(invalid_log).expect("decode invalid log fixture structurally");
    assert!(matches!(
        ValidatedRunnerToServer::new(invalid_log, &limits),
        Err(MessageValidationError::Log(_))
    ));
}
