use automata_ci_core::{
    Architecture, IsolationLevel, JobIrVersion, JobIrVersionRange, OperatingSystem, OperationId,
    RunnerCapabilities, RunnerId, RunnerPlatform, RunnerSessionId, SandboxCapabilities, UnixMillis,
};
use automata_ci_protocol::{
    CommandAck, CommandCursor, CommandCursorError, CommandSequence, CommandSequenceError,
    LeaseAuthorityPollContributions, LeaseRequest, MessageHeader, MessageValidationError,
    NegotiatedSession, ProtocolLimits, RunnerHello, RunnerSlotOrdinal, RunnerToServer,
    SUPPORTED_PROTOCOL_RANGE, ServerCommandHeader, ServerHello, ServerTiming, SessionDisposition,
    SessionResume, ValidatedRunnerToServer,
};

fn capabilities() -> RunnerCapabilities {
    RunnerCapabilities::new(
        RunnerId::new(),
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
    )
    .with_sandbox(SandboxCapabilities::new(IsolationLevel::SharedKernel, []))
}

fn runner_hello(operation_id: OperationId) -> RunnerHello {
    RunnerHello::new(
        operation_id,
        SUPPORTED_PROTOCOL_RANGE,
        JobIrVersionRange::current(),
        capabilities(),
        UnixMillis::new(10),
    )
}

#[test]
fn slot_ordinals_and_command_sequences_reject_invalid_durable_values() {
    assert!(RunnerSlotOrdinal::new(0).is_err());
    assert_eq!(RunnerSlotOrdinal::new(1).expect("slot one").get(), 1);

    assert_eq!(CommandSequence::new(0), Err(CommandSequenceError::Zero));
    assert_eq!(
        CommandSequence::new(CommandSequence::MAX + 1),
        Err(CommandSequenceError::OutOfRange),
    );
    assert!(serde_json::from_str::<RunnerSlotOrdinal>("0").is_err());
    assert!(serde_json::from_str::<CommandSequence>("0").is_err());
    assert!(
        serde_json::from_str::<CommandSequence>(&(CommandSequence::MAX + 1).to_string()).is_err()
    );
}

#[test]
fn command_cursor_advances_only_through_contiguous_durable_commands() {
    let one = CommandSequence::new(1).expect("sequence one");
    let two = CommandSequence::new(2).expect("sequence two");
    let cursor = CommandCursor::initial()
        .advance(one)
        .expect("first contiguous command");
    assert_eq!(cursor.acknowledged_through(), Some(one));
    assert_eq!(
        cursor.advance(one),
        Err(CommandCursorError::NonContiguous {
            expected: two,
            received: one,
        }),
    );
    assert_eq!(
        CommandCursor::initial().advance(two),
        Err(CommandCursorError::NonContiguous {
            expected: one,
            received: two,
        }),
    );

    let exhausted = CommandCursor::through(
        CommandSequence::new(CommandSequence::MAX).expect("maximum sequence"),
    );
    assert_eq!(
        exhausted.advance(CommandSequence::new(1).expect("sequence one")),
        Err(CommandCursorError::Exhausted),
    );
}

#[test]
fn message_headers_enforce_request_and_reply_direction() {
    let protocol = SUPPORTED_PROTOCOL_RANGE.max();
    let session_id = RunnerSessionId::new();
    let request_id = OperationId::new();
    let request = MessageHeader::request(protocol, session_id, request_id);
    assert_eq!(request.session_id(), session_id);
    assert_eq!(request.in_reply_to(), None);
    assert_eq!(request.validate_request(), Ok(()));
    assert_eq!(
        request.validate_reply(),
        Err(MessageValidationError::MissingResponseCorrelation),
    );

    let reply = MessageHeader::reply(protocol, session_id, OperationId::new(), request_id);
    assert_eq!(reply.in_reply_to(), Some(request_id));
    assert_eq!(reply.validate_reply(), Ok(()));
    assert_eq!(
        reply.validate_request(),
        Err(MessageValidationError::UnexpectedResponseCorrelation),
    );
    assert_eq!(reply.validate_reply_for(request), Ok(()));

    let wrong_session = MessageHeader::reply(
        protocol,
        RunnerSessionId::new(),
        OperationId::new(),
        request_id,
    );
    assert!(matches!(
        wrong_session.validate_reply_for(request),
        Err(MessageValidationError::ResponseSessionMismatch { .. }),
    ));
}

#[test]
fn command_headers_keep_identity_stable_across_transport_replay() {
    let header = ServerCommandHeader::new(
        SUPPORTED_PROTOCOL_RANGE.max(),
        RunnerSessionId::new(),
        OperationId::new(),
        CommandSequence::new(7).expect("command sequence"),
    );
    let first = serde_json::to_vec(&header).expect("serialize command header");
    let replayed = serde_json::to_vec(
        &serde_json::from_slice::<ServerCommandHeader>(&first).expect("decode command header"),
    )
    .expect("re-serialize command header");
    assert_eq!(replayed, first);
    assert_eq!(header.validate(), Ok(()));
}

#[test]
fn resumed_handshake_must_confirm_the_exact_session_and_cursor() {
    let hello_operation = OperationId::new();
    let session_id = RunnerSessionId::new();
    let cursor = CommandCursor::through(CommandSequence::new(3).expect("command sequence"));
    let hello = runner_hello(hello_operation).with_resume(SessionResume::new(session_id, cursor));
    let response = ServerHello::new(
        OperationId::new(),
        hello_operation,
        NegotiatedSession::new(
            SUPPORTED_PROTOCOL_RANGE.max(),
            JobIrVersion::current(),
            session_id,
            SessionDisposition::Resumed,
            cursor,
        ),
        ServerTiming::new(UnixMillis::new(11), 1_000, 30_000),
    );
    assert_eq!(response.validate_for(&hello), Ok(()));

    let wrong_session = ServerHello::new(
        OperationId::new(),
        hello_operation,
        NegotiatedSession::new(
            SUPPORTED_PROTOCOL_RANGE.max(),
            JobIrVersion::current(),
            RunnerSessionId::new(),
            SessionDisposition::Resumed,
            cursor,
        ),
        ServerTiming::new(UnixMillis::new(11), 1_000, 30_000),
    );
    assert_eq!(
        wrong_session.validate_for(&hello),
        Err(MessageValidationError::SessionResumeMismatch),
    );
}

#[test]
fn new_sessions_cannot_inherit_a_command_cursor() {
    let operation_id = OperationId::new();
    let hello = runner_hello(operation_id);
    let response = ServerHello::new(
        OperationId::new(),
        operation_id,
        NegotiatedSession::new(
            SUPPORTED_PROTOCOL_RANGE.max(),
            JobIrVersion::current(),
            RunnerSessionId::new(),
            SessionDisposition::Opened,
            CommandCursor::through(CommandSequence::new(1).expect("command sequence")),
        ),
        ServerTiming::new(UnixMillis::new(11), 1_000, 30_000),
    );
    assert_eq!(
        response.validate_for(&hello),
        Err(MessageValidationError::NewSessionHasCommandCursor),
    );
}

#[test]
fn empty_command_acknowledgement_cannot_reach_a_handler() {
    let header = MessageHeader::request(
        SUPPORTED_PROTOCOL_RANGE.max(),
        RunnerSessionId::new(),
        OperationId::new(),
    );
    let message = RunnerToServer::CommandAck(CommandAck::new(header, CommandCursor::initial()));
    assert_eq!(
        ValidatedRunnerToServer::try_from(message),
        Err(MessageValidationError::EmptyCommandAcknowledgement),
    );
}

#[test]
fn lease_request_constructors_make_chain_position_explicit_and_reject_self_acknowledgement() {
    let protocol = SUPPORTED_PROTOCOL_RANGE.max();
    let session_id = RunnerSessionId::new();
    let slot = RunnerSlotOrdinal::new(2).expect("slot two");

    let first_operation_id = OperationId::new();
    let first = LeaseRequest::first(
        MessageHeader::request(protocol, session_id, first_operation_id),
        slot,
        LeaseAuthorityPollContributions::default(),
    );
    assert_eq!(first.acknowledges_operation_id(), None);
    assert_eq!(first.validate(), Ok(()));

    let successor = LeaseRequest::successor(
        MessageHeader::request(protocol, session_id, OperationId::new()),
        slot,
        first_operation_id,
        LeaseAuthorityPollContributions::default(),
    );
    assert_eq!(
        successor.acknowledges_operation_id(),
        Some(first_operation_id)
    );
    assert_eq!(successor.validate(), Ok(()));

    let self_operation_id = OperationId::new();
    let self_acknowledgement = RunnerToServer::LeaseRequest(LeaseRequest::successor(
        MessageHeader::request(protocol, session_id, self_operation_id),
        slot,
        self_operation_id,
        LeaseAuthorityPollContributions::default(),
    ));
    assert_eq!(
        ValidatedRunnerToServer::try_from(self_acknowledgement),
        Err(MessageValidationError::LeaseRequestSelfAcknowledgement {
            operation_id: self_operation_id,
        })
    );
}

#[test]
fn first_lease_poll_validates_chain_origin_for_one_authenticated_slot() {
    let header = MessageHeader::request(
        SUPPORTED_PROTOCOL_RANGE.max(),
        RunnerSessionId::new(),
        OperationId::new(),
    );
    let message = RunnerToServer::LeaseRequest(LeaseRequest::first(
        header,
        RunnerSlotOrdinal::new(2).expect("slot two"),
        LeaseAuthorityPollContributions::default(),
    ));
    let validated = ValidatedRunnerToServer::new(message, &ProtocolLimits::default())
        .expect("validate first lease poll");
    let RunnerToServer::LeaseRequest(request) = validated.into_message() else {
        panic!("validated a different runner message")
    };
    assert_eq!(request.header(), header);
    assert_eq!(request.slot().get(), 2);
    assert_eq!(request.acknowledges_operation_id(), None);
}
