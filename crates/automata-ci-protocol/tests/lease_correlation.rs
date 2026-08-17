use automata_ci_core::{
    AttemptId, FencingToken, GitObjectId, JobId, JobInstanceIdentity, JobIr, JobIrEnvelope,
    JobLifecycle, JobSource, Lease, LeaseGuard, LeaseId, OperationId, RunId, RunValueTemplates,
    RunnerId, RunnerRequirements, RunnerSessionId, RuntimeBoolean, SemanticStep, Sha256Digest,
    ShellTemplate, StepId, StepIr, UnixMillis, ValueTemplate, WorkflowId,
};
use automata_ci_protocol::{
    CommandSequence, LeaseDisposition, LeaseHeartbeat, LeaseOffer, LeaseRenewal, LeaseResponse,
    MessageHeader, MessageValidationError, RunnerSlotOrdinal, SUPPORTED_PROTOCOL_RANGE,
    ServerCommandHeader,
};

fn slot(ordinal: u16) -> RunnerSlotOrdinal {
    RunnerSlotOrdinal::new(ordinal).expect("positive runner slot")
}

fn job() -> JobIrEnvelope {
    let step = StepIr::new(
        StepId::new("build").expect("valid step ID"),
        ValueTemplate::literal("Build").expect("literal step name"),
        RuntimeBoolean::literal(false),
        SemanticStep::run(RunValueTemplates::new(
            ValueTemplate::literal("printf ok").expect("literal command"),
            ShellTemplate::default_shell(),
        )),
    );
    JobIrEnvelope::new(
        WorkflowId::new(),
        JobSource::new(
            "github",
            "owner/repository",
            GitObjectId::from_provider_hex("0123456789abcdef0123456789abcdef01234567")
                .expect("revision"),
            ".ci/workflows/ci.yml",
            "workflow_dispatch",
        ),
        automata_ci_core::JobExecutionContext::new(
            "CI",
            "refs/heads/main",
            "/__w/repository/repository",
            automata_ci_core::JobContentReference::new(
                "events/dispatch.json",
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
        JobIr::new(
            JobId::new(),
            RunId::new(),
            "build",
            RunnerRequirements::default(),
            JobInstanceIdentity::new("build", 0, 1, Sha256Digest::from_bytes([0x44; 32]))
                .expect("instance"),
            false,
            vec![step],
        ),
    )
}

fn lease(attempt_id: AttemptId, runner_id: RunnerId) -> Lease {
    Lease::new(
        LeaseId::new(),
        attempt_id,
        runner_id,
        FencingToken::new(1).expect("valid fence"),
        UnixMillis::new(10),
        UnixMillis::new(20),
    )
    .expect("valid lease")
}

#[test]
fn acceptance_must_correlate_to_offer_session_slot_attempt_and_guard() {
    let session_id = RunnerSessionId::new();
    let attempt_id = AttemptId::new();
    let active_lease = lease(attempt_id, RunnerId::new());
    let job = job();
    let offer = LeaseOffer::new(
        ServerCommandHeader::new(
            SUPPORTED_PROTOCOL_RANGE.max(),
            session_id,
            OperationId::new(),
            CommandSequence::new(1).expect("command sequence"),
        ),
        slot(1),
        active_lease.clone(),
        job,
    );
    let accepted = LeaseResponse::new(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            session_id,
            OperationId::new(),
        ),
        attempt_id,
        slot(1),
        active_lease.guard(),
        LeaseDisposition::Accepted,
    );
    assert_eq!(accepted.validate_for(&offer), Ok(()));

    let wrong_slot = LeaseResponse::new(
        accepted.header(),
        attempt_id,
        slot(2),
        active_lease.guard(),
        LeaseDisposition::Accepted,
    );
    assert!(matches!(
        wrong_slot.validate_for(&offer),
        Err(MessageValidationError::SlotCorrelationMismatch { .. }),
    ));

    let wrong_guard = LeaseResponse::new(
        accepted.header(),
        attempt_id,
        slot(1),
        LeaseGuard::new(LeaseId::new(), FencingToken::new(1).expect("valid fence")),
        LeaseDisposition::Accepted,
    );
    assert!(matches!(
        wrong_guard.validate_for(&offer),
        Err(MessageValidationError::LeaseGuardCorrelationMismatch { .. }),
    ));
}

#[test]
fn renewal_must_correlate_to_the_exact_heartbeat_operation() {
    let session_id = RunnerSessionId::new();
    let attempt_id = AttemptId::new();
    let active_lease = lease(attempt_id, RunnerId::new());
    let request = MessageHeader::request(
        SUPPORTED_PROTOCOL_RANGE.max(),
        session_id,
        OperationId::new(),
    );
    let heartbeat = LeaseHeartbeat::new(
        request,
        attempt_id,
        active_lease.guard(),
        JobLifecycle::Running,
        UnixMillis::new(15),
    );
    let renewal = LeaseRenewal::new(
        MessageHeader::reply(
            SUPPORTED_PROTOCOL_RANGE.max(),
            session_id,
            OperationId::new(),
            request.operation_id(),
        ),
        attempt_id,
        active_lease.guard(),
        UnixMillis::new(30),
    );
    assert_eq!(renewal.validate_for(&heartbeat), Ok(()));

    let wrong_attempt = LeaseRenewal::new(
        renewal.header(),
        AttemptId::new(),
        active_lease.guard(),
        UnixMillis::new(30),
    );
    assert!(matches!(
        wrong_attempt.validate_for(&heartbeat),
        Err(MessageValidationError::AttemptCorrelationMismatch { .. }),
    ));
}
