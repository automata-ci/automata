use std::collections::BTreeMap;

use automata_core::{
    Architecture, AttemptId, FencingToken, IsolationLevel, JobConclusion, JobId, JobIr,
    JobIrEnvelope, JobIrVersion, JobIrVersionRange, JobLifecycle, JobResult, JobSource, Lease,
    LeaseGuard, LeaseId, LogAck, LogChannel, LogFrame, LogSequence, LogStreamId, OperatingSystem,
    OperationId, RunId, RunnerCapabilities, RunnerId, RunnerPlatform, RunnerRequirements,
    RunnerSessionId, SandboxCapabilities, SemanticStep, ShellSpec, StepId, StepIr, StepResult,
    UnixMillis, WorkflowId,
};
use automata_protocol::{
    CancelJob, CommandAck, CommandCursor, CommandSequence, ErrorMessage, HandshakeErrorCode,
    HandshakeRejected, JobResultMessage, JobRuntimeAuthorities, JobRuntimeAuthority,
    JobStateUpdate, LeaseDisposition, LeaseHeartbeat, LeaseOffer, LeaseRenewal, LeaseRequest,
    LeaseResponse, LogAckMessage, LogBatch, MAX_CONFIGURABLE_FRAME_BYTES, MessageHeader,
    MessageValidationError, NegotiatedSession, NoWork, OperationAck, ProtocolDecodeError,
    ProtocolEncodeError, ProtocolLimits, ProtocolLimitsError, RemoteErrorCode, RunnerHello,
    RunnerSlotOrdinal, RunnerToServer, RuntimeAuthorityCredential, RuntimeAuthorityEndpoint,
    RuntimeAuthorityName, SUPPORTED_PROTOCOL_RANGE, ServerCommandHeader, ServerHello, ServerTiming,
    ServerToRunner, SessionDisposition, ValidatedRunnerToServer, decode_runner_frame,
    decode_server_frame, encode_runner_frame, encode_server_frame,
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
    let step = StepIr::new(
        StepId::new("build").expect("valid step ID"),
        "Build",
        SemanticStep::run("printf ok", ShellSpec::Default),
    );
    let job = JobIr::new(
        JobId::new(),
        RunId::new(),
        "build",
        requirements,
        vec![step],
    );
    JobIrEnvelope::new(
        WorkflowId::new(),
        JobSource::new(
            "github",
            "owner/repository",
            "0123456789abcdef",
            ".github/workflows/ci.yml",
            "push",
        ),
        automata_core::JobExecutionContext::new(
            "CI",
            "refs/heads/main",
            "/__w/repository/repository",
            automata_core::JobContentReference::new(
                "events/push.json",
                automata_core::Sha256Digest::from_bytes([0x42; 32]),
                2,
                "application/json",
            ),
        ),
        job,
    )
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
    let authority = JobRuntimeAuthority::new(
        RuntimeAuthorityName::new("github-actions-results").expect("valid authority name"),
        job.job().run_id(),
        job.job().job_id(),
        lease.attempt_id(),
        lease.fencing_token(),
        RuntimeAuthorityEndpoint::new("https://results.example.test/")
            .expect("valid authority endpoint"),
        RuntimeAuthorityCredential::new("header.payload.signature")
            .expect("valid authority credential"),
        UnixMillis::new(10),
        UnixMillis::new(3_600_010),
    )
    .expect("valid runtime authority");
    let authorities =
        JobRuntimeAuthorities::new(vec![authority], &job, &lease).expect("valid authority bundle");
    LeaseOffer::new(header, slot, lease, job, authorities)
}

fn result(attempt_id: AttemptId) -> JobResult {
    JobResult::new(attempt_id, JobConclusion::Success, UnixMillis::new(30)).with_steps(vec![
        StepResult::new(
            StepId::new("build").expect("valid step ID"),
            JobConclusion::Success,
            JobConclusion::Success,
            UnixMillis::new(10),
            UnixMillis::new(20),
        ),
    ])
}

fn log_frame(
    stream_id: LogStreamId,
    attempt_id: AttemptId,
    sequence: u64,
    payload: &[u8],
    end_of_stream: bool,
) -> LogFrame {
    LogFrame::new(
        stream_id,
        attempt_id,
        LogSequence::new(sequence),
        UnixMillis::new(10),
        LogChannel::Stdout,
        payload.to_vec(),
        end_of_stream,
    )
    .expect("valid log frame")
}

#[test]
fn every_runner_envelope_variant_round_trips_through_the_validated_codec() {
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
        let encoded = encode_runner_frame(message.clone(), &limits).expect("encode valid message");
        let decoded = decode_runner_frame(&encoded, &limits).expect("decode valid message");
        assert_eq!(decoded.into_message(), message);
    }
}

#[test]
fn every_server_envelope_variant_round_trips_through_the_validated_codec() {
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
        let encoded = encode_server_frame(message.clone(), &limits).expect("encode valid message");
        let decoded = decode_server_frame(&encoded, &limits).expect("decode valid message");
        assert_eq!(decoded.into_message(), message);
    }
}

#[test]
fn frame_size_is_rejected_before_json_is_examined() {
    let limits = ProtocolLimits::new(128, 8, 64, 4, 64).expect("coherent limits");
    let oversized_malformed = vec![b'{'; 129];

    assert!(matches!(
        decode_runner_frame(&oversized_malformed, &limits),
        Err(ProtocolDecodeError::FrameTooLarge {
            size: 129,
            maximum: 128
        })
    ));
    assert!(matches!(
        decode_server_frame(b"", &limits),
        Err(ProtocolDecodeError::EmptyFrame)
    ));
    assert!(matches!(
        decode_server_frame(b"{", &limits),
        Err(ProtocolDecodeError::MalformedJson(_))
    ));
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
fn raw_deserialization_cannot_enter_the_validated_handler_boundary() {
    let invalid_header = MessageHeader::reply(
        SUPPORTED_PROTOCOL_RANGE.max(),
        RunnerSessionId::new(),
        OperationId::new(),
        OperationId::new(),
    );
    let raw = RunnerToServer::LeaseRequest(LeaseRequest::first(invalid_header, slot()));

    assert!(matches!(
        ValidatedRunnerToServer::try_from(raw.clone()),
        Err(MessageValidationError::UnexpectedResponseCorrelation)
    ));
    assert!(matches!(
        encode_runner_frame(raw, &ProtocolLimits::default()),
        Err(ProtocolEncodeError::InvalidMessage(
            MessageValidationError::UnexpectedResponseCorrelation
        ))
    ));
}

#[test]
fn encoded_output_cannot_exceed_the_frame_budget() {
    let limits = ProtocolLimits::new(128, 8, 64, 4, 64).expect("coherent limits");
    let message = ServerToRunner::Error(ErrorMessage::new(
        reply_header(),
        RemoteErrorCode::Internal,
        "x".repeat(64),
        false,
    ));

    assert!(matches!(
        encode_server_frame(message, &limits),
        Err(ProtocolEncodeError::FrameTooLarge { maximum: 128, .. })
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
    invalid_job["payload"]["job"]["job"]["steps"][0]["timeout_seconds"] = serde_json::json!(0);
    let invalid_job = serde_json::to_vec(&invalid_job).expect("encode invalid job fixture");
    assert!(matches!(
        decode_server_frame(&invalid_job, &limits),
        Err(ProtocolDecodeError::InvalidMessage(
            MessageValidationError::Job(_)
        ))
    ));

    let result_message =
        RunnerToServer::JobResult(JobResultMessage::new(header(), guard(), result(attempt_id)));
    let mut invalid_result = serde_json::to_value(result_message).expect("serialize job result");
    invalid_result["payload"]["result"]["steps"][0]["completed_at"] = serde_json::json!(40);
    let invalid_result =
        serde_json::to_vec(&invalid_result).expect("encode invalid result fixture");
    assert!(matches!(
        decode_runner_frame(&invalid_result, &limits),
        Err(ProtocolDecodeError::InvalidMessage(
            MessageValidationError::JobResult(_)
        ))
    ));
}

#[test]
fn nested_requirement_collections_obey_the_configured_budget() {
    use automata_core::RunnerLabel;

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
        encode_server_frame(message, &limits),
        Err(ProtocolEncodeError::InvalidMessage(
            MessageValidationError::CollectionTooLarge {
                field: "required runner labels",
                length: 2,
                maximum: 1
            }
        ))
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
    let job = serde_json::to_vec(&job).expect("encode oversized map fixture");
    assert!(matches!(
        decode_server_frame(&job, &limits),
        Err(ProtocolDecodeError::InvalidMessage(
            MessageValidationError::CollectionTooLarge {
                field: "job environment",
                length: 2,
                maximum: 1
            }
        ))
    ));

    let result_message =
        RunnerToServer::JobResult(JobResultMessage::new(header(), guard(), result(attempt_id)));
    let mut result_message = serde_json::to_value(result_message).expect("serialize job result");
    result_message["payload"]["result"]["outputs"] = serde_json::json!({
        "first": "one",
        "second": "two"
    });
    let result_message =
        serde_json::to_vec(&result_message).expect("encode oversized output map fixture");
    assert!(matches!(
        decode_runner_frame(&result_message, &limits),
        Err(ProtocolDecodeError::InvalidMessage(
            MessageValidationError::CollectionTooLarge {
                field: "job outputs",
                length: 2,
                maximum: 1
            }
        ))
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
        encode_runner_frame(non_contiguous, &limits),
        Err(ProtocolEncodeError::InvalidMessage(
            MessageValidationError::NonContiguousLogSequence {
                previous: 0,
                received: 2
            }
        ))
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
        encode_runner_frame(mixed_streams, &limits),
        Err(ProtocolEncodeError::InvalidMessage(
            MessageValidationError::MixedLogStreams
        ))
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
        encode_runner_frame(after_terminal, &limits),
        Err(ProtocolEncodeError::InvalidMessage(
            MessageValidationError::LogFrameAfterEndOfStream
        ))
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
        encode_runner_frame(message.clone(), &payload_limits),
        Err(ProtocolEncodeError::InvalidMessage(
            MessageValidationError::LogBatchPayloadTooLarge {
                size: 6,
                maximum: 5
            }
        ))
    ));

    let count_limits =
        ProtocolLimits::new(4_096, 4, 1_024, 1, 8).expect("coherent frame-count limits");
    assert!(matches!(
        encode_runner_frame(message, &count_limits),
        Err(ProtocolEncodeError::InvalidMessage(
            MessageValidationError::CollectionTooLarge {
                field: "log frames",
                length: 2,
                maximum: 1
            }
        ))
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
        encode_server_frame(cancellation, &limits),
        Err(ProtocolEncodeError::InvalidMessage(
            MessageValidationError::TextTooLong {
                field: "cancellation reason",
                length: 4_097,
                maximum: 4_096
            }
        ))
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
        encode_server_frame(error, &limits),
        Err(ProtocolEncodeError::InvalidMessage(
            MessageValidationError::TextTooLong {
                field: "error detail value",
                length: 4_097,
                maximum: 4_096
            }
        ))
    ));
}

#[test]
fn decoded_log_cancellation_and_error_messages_receive_full_nested_validation() {
    let limits =
        ProtocolLimits::new(64 * 1024, 4, 16 * 1024, 4, 1_024).expect("coherent control limits");
    let attempt_id = AttemptId::new();
    let log = RunnerToServer::LogBatch(LogBatch::new(
        header(),
        guard(),
        vec![log_frame(LogStreamId::new(), attempt_id, 0, b"log", false)],
    ));
    let mut invalid_log = serde_json::to_value(log).expect("serialize log batch");
    invalid_log["payload"]["frames"][0]["schema_version"] = serde_json::json!(u16::MAX);
    let invalid_log = serde_json::to_vec(&invalid_log).expect("encode invalid log fixture");
    assert!(matches!(
        decode_runner_frame(&invalid_log, &limits),
        Err(ProtocolDecodeError::InvalidMessage(
            MessageValidationError::Log(_)
        ))
    ));

    let cancellation = ServerToRunner::CancelJob(CancelJob::new(
        command_header(),
        attempt_id,
        guard(),
        "x".repeat(4_097),
        UnixMillis::new(1),
    ));
    let cancellation = serde_json::to_vec(&cancellation).expect("encode cancellation fixture");
    assert!(matches!(
        decode_server_frame(&cancellation, &limits),
        Err(ProtocolDecodeError::InvalidMessage(
            MessageValidationError::TextTooLong {
                field: "cancellation reason",
                ..
            }
        ))
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
    let error = serde_json::to_vec(&error).expect("encode error fixture");
    assert!(matches!(
        decode_server_frame(&error, &limits),
        Err(ProtocolDecodeError::InvalidMessage(
            MessageValidationError::TextTooLong {
                field: "error detail value",
                ..
            }
        ))
    ));
}
