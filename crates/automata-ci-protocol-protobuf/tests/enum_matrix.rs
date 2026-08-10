mod common;

use automata_ci_core::{
    Architecture, AttemptId, IsolationLevel, JobConclusion, JobIrVersion, JobLifecycle, JobResult,
    JobSecretExposure, OperatingSystem, OperationId, RunnerCapabilities, RunnerId, RunnerPlatform,
    RunnerSessionId, SandboxCapabilities, UnixMillis,
};
use automata_ci_protocol::{
    ErrorMessage, HandshakeErrorCode, HandshakeRejected, JobResultMessage, LeaseDisposition,
    LeaseHeartbeat, LeaseRejectionReason, LeaseResponse, NegotiatedSession,
    OrphanDeliveryPermissions, RemoteErrorCode, RunnerHello, RunnerToServer,
    SUPPORTED_PROTOCOL_RANGE, ServerHello, ServerTiming, ServerToRunner, SessionDisposition,
    SessionOrphanAuthorization,
};
use automata_ci_protocol_protobuf::{
    decode_runner_frame, decode_server_frame, encode_runner_frame, encode_server_frame,
};

fn roundtrip_runner(message: &RunnerToServer) {
    let limits = automata_ci_protocol::ProtocolLimits::default();
    let encoded = encode_runner_frame(message, &limits).expect("encode runner enum fixture");
    let decoded = decode_runner_frame(&encoded, &limits).expect("decode runner enum fixture");
    assert_eq!(decoded.message(), message);
}

fn roundtrip_server(message: &ServerToRunner) {
    let limits = automata_ci_protocol::ProtocolLimits::default();
    let encoded = encode_server_frame(message, &limits).expect("encode server enum fixture");
    let decoded = decode_server_frame(&encoded, &limits).expect("decode server enum fixture");
    assert_eq!(decoded.message(), message);
}

#[test]
fn every_platform_and_isolation_variant_round_trips() {
    let platforms = [
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
        RunnerPlatform::new(OperatingSystem::Windows, Architecture::Aarch64),
        RunnerPlatform::new(
            OperatingSystem::Macos,
            Architecture::Other("riscv64".to_owned()),
        ),
        RunnerPlatform::new(
            OperatingSystem::Other("freebsd".to_owned()),
            Architecture::X86_64,
        ),
    ];
    for (index, (platform, isolation)) in platforms
        .into_iter()
        .zip([
            IsolationLevel::Process,
            IsolationLevel::SharedKernel,
            IsolationLevel::VirtualMachine,
            IsolationLevel::Process,
        ])
        .enumerate()
    {
        let capabilities = RunnerCapabilities::new(RunnerId::new(), platform)
            .with_sandbox(SandboxCapabilities::new(isolation, []));
        roundtrip_runner(&RunnerToServer::Hello(RunnerHello::new(
            OperationId::new(),
            SUPPORTED_PROTOCOL_RANGE,
            automata_ci_core::JobIrVersionRange::current(),
            capabilities,
            UnixMillis::new(i64::try_from(index).expect("small fixture index")),
        )));
    }
}

#[test]
fn every_handshake_and_session_disposition_variant_round_trips() {
    for code in [
        HandshakeErrorCode::InvalidHello,
        HandshakeErrorCode::UnsupportedProtocol,
        HandshakeErrorCode::UnsupportedJobIr,
        HandshakeErrorCode::Unauthenticated,
        HandshakeErrorCode::Unauthorized,
        HandshakeErrorCode::SessionNotResumable,
    ] {
        let rejection = if code == HandshakeErrorCode::SessionNotResumable {
            HandshakeRejected::session_not_resumable(
                OperationId::new(),
                OperationId::new(),
                SUPPORTED_PROTOCOL_RANGE,
                SessionOrphanAuthorization::new(
                    RunnerSessionId::new(),
                    OrphanDeliveryPermissions::new(true, false, true),
                ),
                "handshake rejected",
            )
        } else {
            HandshakeRejected::new(
                OperationId::new(),
                OperationId::new(),
                code,
                SUPPORTED_PROTOCOL_RANGE,
                "handshake rejected",
            )
        };
        roundtrip_server(&ServerToRunner::HandshakeRejected(rejection));
    }

    for (disposition, cursor) in [
        (SessionDisposition::Opened, common::sequence(1)),
        (SessionDisposition::Resumed, common::sequence(2)),
    ] {
        let cursor = automata_ci_protocol::CommandCursor::through(cursor);
        roundtrip_server(&ServerToRunner::Hello(ServerHello::new(
            OperationId::new(),
            OperationId::new(),
            NegotiatedSession::new(
                SUPPORTED_PROTOCOL_RANGE.max(),
                JobIrVersion::current(),
                RunnerSessionId::new(),
                disposition,
                cursor,
            ),
            ServerTiming::new(UnixMillis::new(10), 1_000, 30_000),
        )));
    }
}

#[test]
fn every_lease_disposition_and_rejection_reason_round_trips() {
    let attempt = AttemptId::new();
    roundtrip_runner(&RunnerToServer::LeaseResponse(LeaseResponse::new(
        common::request_header(100),
        attempt,
        common::slot(),
        common::guard(),
        LeaseDisposition::Accepted,
    )));
    for reason in [
        LeaseRejectionReason::CapacityChanged,
        LeaseRejectionReason::CapabilityChanged,
        LeaseRejectionReason::ShuttingDown,
        LeaseRejectionReason::InvalidJob,
    ] {
        roundtrip_runner(&RunnerToServer::LeaseResponse(LeaseResponse::new(
            common::request_header(101),
            attempt,
            common::slot(),
            common::guard(),
            LeaseDisposition::Rejected(reason),
        )));
    }
}

#[test]
fn every_job_lifecycle_variant_round_trips() {
    let attempt = AttemptId::new();
    for lifecycle in [
        JobLifecycle::Queued,
        JobLifecycle::Leased,
        JobLifecycle::Preparing,
        JobLifecycle::Running,
        JobLifecycle::Cancelling,
        JobLifecycle::Finalizing,
        JobLifecycle::Succeeded,
        JobLifecycle::Failed,
        JobLifecycle::Cancelled,
        JobLifecycle::TimedOut,
        JobLifecycle::Skipped,
        JobLifecycle::Lost,
    ] {
        roundtrip_runner(&RunnerToServer::Heartbeat(LeaseHeartbeat::new(
            common::request_header(102),
            attempt,
            common::guard(),
            lifecycle,
            UnixMillis::new(10),
        )));
    }
}

#[test]
fn every_job_conclusion_variant_round_trips() {
    for conclusion in [
        JobConclusion::Success,
        JobConclusion::Failure,
        JobConclusion::Cancelled,
        JobConclusion::TimedOut,
        JobConclusion::Skipped,
    ] {
        let attempt = AttemptId::new();
        roundtrip_runner(&RunnerToServer::JobResult(JobResultMessage::new(
            common::request_header(103),
            common::guard(),
            JobResult::new(
                attempt,
                conclusion,
                JobSecretExposure::Secretless,
                UnixMillis::new(10),
            ),
        )));
    }
}

#[test]
fn every_job_secret_exposure_variant_round_trips() {
    for exposure in [
        JobSecretExposure::Secretless,
        JobSecretExposure::CapabilityOnly,
        JobSecretExposure::ReadableSecret,
    ] {
        roundtrip_runner(&RunnerToServer::JobResult(JobResultMessage::new(
            common::request_header(106),
            common::guard(),
            JobResult::new(
                AttemptId::new(),
                JobConclusion::Success,
                exposure,
                UnixMillis::new(10),
            ),
        )));
    }
}

#[test]
fn every_remote_error_code_round_trips() {
    for code in [
        RemoteErrorCode::InvalidMessage,
        RemoteErrorCode::UnsupportedProtocol,
        RemoteErrorCode::UnsupportedJobIr,
        RemoteErrorCode::Unauthenticated,
        RemoteErrorCode::Unauthorized,
        RemoteErrorCode::SessionNotFound,
        RemoteErrorCode::StaleSession,
        RemoteErrorCode::InvalidSlot,
        RemoteErrorCode::OperationKeyReused,
        RemoteErrorCode::CommandCursorConflict,
        RemoteErrorCode::LeaseNotFound,
        RemoteErrorCode::StaleFencingToken,
        RemoteErrorCode::Conflict,
        RemoteErrorCode::RetryLater,
        RemoteErrorCode::Internal,
    ] {
        roundtrip_server(&ServerToRunner::Error(ErrorMessage::new(
            common::reply_header(104, 105),
            code,
            "typed remote error",
            false,
        )));
    }
}
