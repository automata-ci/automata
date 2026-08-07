use automata_core::{
    Architecture, AttemptId, EnvironmentProfile, EnvironmentProfileId, FencingToken, JobId, JobIr,
    JobIrEnvelope, JobIrVersionRange, JobSource, Lease, LeaseId, OperatingSystem, OperationId,
    RequirementMismatch, RunId, RunnerCapabilities, RunnerFeature, RunnerId, RunnerPlatform,
    RunnerRequirements, SemanticStep, Sha256Digest, ShellSpec, StepId, StepIr, UnixMillis,
    WorkflowId,
};
use automata_protocol::{
    CommandSequence, JobRuntimeAuthorities, JobRuntimeAuthority, LeaseOffer,
    MessageValidationError, ProtocolDecodeError, ProtocolEncodeError, ProtocolLimits, RunnerHello,
    RunnerSlotOrdinal, RunnerToServer, RuntimeAuthorityCredential, RuntimeAuthorityEndpoint,
    RuntimeAuthorityName, SUPPORTED_PROTOCOL_RANGE, ServerCommandHeader, ServerToRunner,
    decode_runner_frame, decode_server_frame, encode_runner_frame, encode_server_frame,
};

fn runner() -> RunnerCapabilities {
    RunnerCapabilities::new(
        RunnerId::new(),
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
    )
}

fn profile(digest_byte: u8) -> EnvironmentProfile {
    EnvironmentProfile::new(
        EnvironmentProfileId::new("github.com/ubuntu-24.04").expect("valid profile ID"),
        Sha256Digest::from_bytes([digest_byte; 32]),
    )
}

fn lease_offer(requirements: RunnerRequirements) -> ServerToRunner {
    let runner_id = RunnerId::new();
    let attempt_id = AttemptId::new();
    let lease = Lease::new(
        LeaseId::new(),
        attempt_id,
        runner_id,
        FencingToken::new(1).expect("valid fencing token"),
        UnixMillis::new(10),
        UnixMillis::new(20),
    )
    .expect("valid lease");
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
    let envelope = JobIrEnvelope::new(
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
    );
    let header = ServerCommandHeader::new(
        SUPPORTED_PROTOCOL_RANGE.max(),
        automata_core::RunnerSessionId::new(),
        OperationId::new(),
        CommandSequence::new(1).expect("valid command sequence"),
    );
    let authority = JobRuntimeAuthority::new(
        RuntimeAuthorityName::new("github-actions-results").expect("authority name"),
        envelope.job().run_id(),
        envelope.job().job_id(),
        lease.attempt_id(),
        lease.fencing_token(),
        RuntimeAuthorityEndpoint::new("https://results.example.test/").expect("endpoint"),
        RuntimeAuthorityCredential::new("header.payload.signature").expect("credential"),
        UnixMillis::new(10),
        UnixMillis::new(3_600_010),
    )
    .expect("runtime authority");
    let authorities = JobRuntimeAuthorities::new(vec![authority], &envelope, &lease)
        .expect("runtime authorities");
    ServerToRunner::LeaseOffer(Box::new(LeaseOffer::new(
        header,
        RunnerSlotOrdinal::new(1).expect("valid runner slot"),
        lease,
        envelope,
        authorities,
    )))
}

#[test]
fn handshake_codec_preserves_unknown_optional_advertisements() {
    let future =
        RunnerFeature::new("com.example/future-runtime@v9").expect("valid future feature ID");
    let message = RunnerToServer::Hello(RunnerHello::new(
        OperationId::new(),
        SUPPORTED_PROTOCOL_RANGE,
        JobIrVersionRange::current(),
        runner().with_features([RunnerFeature::SHELL_STEPS, future.clone()]),
        UnixMillis::new(1),
    ));
    let frame = serde_json::to_vec(&message).expect("serialize newer runner frame");

    let decoded = decode_runner_frame(&frame, &ProtocolLimits::default())
        .expect("decode and validate newer optional advertisement");
    let RunnerToServer::Hello(hello) = decoded.into_message() else {
        panic!("decoded a different runner message")
    };
    assert!(hello.runner().features().contains(&future));
    assert_eq!(
        serde_json::to_vec(&RunnerToServer::Hello(hello)).expect("re-serialize decoded hello"),
        frame,
    );
}

#[test]
fn lease_codec_preserves_unknown_required_feature_for_typed_matching() {
    let future =
        RunnerFeature::new("com.example/future-runtime@v9").expect("valid future feature ID");
    let message = lease_offer(RunnerRequirements::default().with_features([future.clone()]));
    let frame =
        encode_server_frame(message, &ProtocolLimits::default()).expect("encode newer lease offer");
    let decoded = decode_server_frame(&frame, &ProtocolLimits::default())
        .expect("decode and validate newer required feature");
    let ServerToRunner::LeaseOffer(offer) = decoded.into_message() else {
        panic!("decoded a different server message")
    };

    let mismatches = runner()
        .satisfies(offer.job().job().requirements())
        .expect_err("older runner does not provide the future required feature");
    assert_eq!(
        mismatches.as_slice(),
        &[RequirementMismatch::MissingRunnerFeature(future)],
    );
}

#[test]
fn lease_codec_preserves_exact_environment_profile_attestation() {
    let required = profile(0x11);
    let message =
        lease_offer(RunnerRequirements::default().with_environment_profile(required.clone()));
    let frame = encode_server_frame(message, &ProtocolLimits::default())
        .expect("encode attested-profile lease offer");
    let decoded = decode_server_frame(&frame, &ProtocolLimits::default())
        .expect("decode attested-profile lease offer");
    let ServerToRunner::LeaseOffer(offer) = decoded.into_message() else {
        panic!("decoded a different server message")
    };
    assert_eq!(
        offer.job().job().requirements().environment_profile(),
        Some(&required)
    );

    let mismatches = runner()
        .with_environment_profiles([profile(0x22)])
        .satisfies(offer.job().job().requirements())
        .expect_err("the same profile ID with a different digest must fail");
    assert!(matches!(
        mismatches.as_slice(),
        [RequirementMismatch::EnvironmentProfile { required: actual, .. }] if actual == &required
    ));
}

#[test]
fn malformed_capability_identifier_is_rejected_during_frame_deserialization() {
    let message = RunnerToServer::Hello(RunnerHello::new(
        OperationId::new(),
        SUPPORTED_PROTOCOL_RANGE,
        JobIrVersionRange::current(),
        runner().with_features([RunnerFeature::SHELL_STEPS]),
        UnixMillis::new(1),
    ));
    let mut value = serde_json::to_value(message).expect("serialize runner hello");
    value["payload"]["runner"]["features"] = serde_json::json!(["vendor/Future@v1"]);
    let frame = serde_json::to_vec(&value).expect("serialize malformed wire fixture");

    assert!(matches!(
        decode_runner_frame(&frame, &ProtocolLimits::default()),
        Err(ProtocolDecodeError::MalformedJson(_)),
    ));
}

#[test]
fn capability_identifiers_obey_the_negotiated_text_budget() {
    let feature = RunnerFeature::new("com.example/feature-longer-than-limit@v1")
        .expect("valid but relatively long feature ID");
    let message = RunnerToServer::Hello(RunnerHello::new(
        OperationId::new(),
        SUPPORTED_PROTOCOL_RANGE,
        JobIrVersionRange::current(),
        runner().with_features([feature.clone()]),
        UnixMillis::new(1),
    ));
    let limits = ProtocolLimits::new(4_096, 32, 16, 4, 1_024).expect("coherent test limits");

    assert!(matches!(
        encode_runner_frame(message, &limits),
        Err(ProtocolEncodeError::InvalidMessage(
            MessageValidationError::TextTooLong {
                field: "runner feature",
                length,
                maximum: 16,
            },
        )) if length == feature.as_str().len(),
    ));
}
