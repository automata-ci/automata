use automata_core::{
    Architecture, IsolationLevel, OperatingSystem, OperationId, RunnerCapabilities, RunnerId,
    RunnerPlatform, RunnerSessionId, SandboxCapabilities, UnixMillis,
};
use automata_protocol::{
    MessageHeader, MessageValidationError, PROTOCOL_MIN_VERSION, ProtocolVersion, RunnerHello,
    RunnerToServer, SUPPORTED_PROTOCOL_RANGE, ServerHello,
};

fn runner_capabilities() -> RunnerCapabilities {
    RunnerCapabilities::new(
        RunnerId::new(),
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
    )
    .with_sandbox(SandboxCapabilities::new(IsolationLevel::SharedKernel, []))
}

#[test]
fn hello_is_owned_versioned_and_json_round_trippable() {
    let hello = RunnerToServer::Hello(RunnerHello::new(
        OperationId::new(),
        SUPPORTED_PROTOCOL_RANGE,
        runner_capabilities(),
        UnixMillis::new(123),
    ));
    let json = serde_json::to_string(&hello).expect("serialize hello");
    assert!(json.contains("\"message_schema_version\":1"));
    assert_eq!(
        serde_json::from_str::<RunnerToServer>(&json).expect("deserialize hello"),
        hello,
    );
}

#[test]
fn message_header_rejects_unnegotiated_protocol() {
    let unsupported =
        ProtocolVersion::new(PROTOCOL_MIN_VERSION.get() + 1).expect("positive protocol version");
    let header = MessageHeader::new(unsupported, OperationId::new());
    assert!(matches!(
        header.validate(),
        Err(MessageValidationError::UnsupportedProtocol { .. }),
    ));
}

#[test]
fn zero_slot_runner_hello_is_rejected() {
    let mut encoded = serde_json::to_value(runner_capabilities()).expect("serialize capabilities");
    encoded["max_parallel_jobs"] = serde_json::json!(0);
    let capabilities =
        serde_json::from_value(encoded).expect("deserialize boundary-invalid capabilities");
    let hello = RunnerHello::new(
        OperationId::new(),
        SUPPORTED_PROTOCOL_RANGE,
        capabilities,
        UnixMillis::new(0),
    );
    assert_eq!(hello.validate(), Err(MessageValidationError::NoRunnerSlots));
}

#[test]
fn server_selection_must_be_inside_the_runner_offer() {
    let offered = automata_protocol::ProtocolRange::new(
        ProtocolVersion::new(PROTOCOL_MIN_VERSION.get() + 1).expect("positive test version"),
        ProtocolVersion::new(PROTOCOL_MIN_VERSION.get() + 1).expect("positive test version"),
    )
    .expect("ordered test range");
    let hello = RunnerHello::new(
        OperationId::new(),
        offered,
        runner_capabilities(),
        UnixMillis::new(0),
    );
    let selected = PROTOCOL_MIN_VERSION;
    let response = ServerHello::new(
        hello.operation_id(),
        selected,
        RunnerSessionId::new(),
        UnixMillis::new(1),
        1_000,
        30_000,
    );
    assert_eq!(
        response.validate_for(&hello),
        Err(MessageValidationError::SelectionOutsideRunnerRange { selected, offered }),
    );
}
