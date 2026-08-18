use automata_ci_core::{
    Architecture, AttemptId, EnvironmentProfile, EnvironmentProfileId, FencingToken, GitObjectId,
    IsolationLevel, JobId, JobInstanceIdentity, JobIr, JobIrEnvelope, JobIrVersionRange, JobSource,
    Lease, LeaseId, OperatingSystem, OperationId, RequirementMismatch, RunId, RunValueTemplates,
    RunnerCapabilities, RunnerFeature, RunnerId, RunnerPlatform, RunnerRequirements,
    RuntimeBoolean, SandboxAuthorizations, SandboxCapabilities, SandboxFeature, Sha256Digest,
    ShellTemplate, StepId, StepIr, UnixMillis, ValueTemplate, WorkflowId,
};
use automata_ci_protocol::{
    CommandSequence, JobRuntimeAuthorities, JobRuntimeAuthority, LeaseOffer,
    MessageValidationError, ProtocolLimits, RUNTIME_AUTHORITY_SCHEMA_VERSION, RunnerHello,
    RunnerSlotOrdinal, RunnerToServer, RuntimeAuthorityCredential, RuntimeAuthorityEndpoint,
    RuntimeAuthorityError, RuntimeAuthorityName, SUPPORTED_PROTOCOL_RANGE, ServerCommandHeader,
    ServerToRunner, ValidatedRunnerToServer, ValidatedServerToRunner,
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
    );
    let envelope = JobIrEnvelope::new(
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
    );
    let header = ServerCommandHeader::new(
        SUPPORTED_PROTOCOL_RANGE.max(),
        automata_ci_core::RunnerSessionId::new(),
        OperationId::new(),
        CommandSequence::new(1).expect("valid command sequence"),
    );
    ServerToRunner::LeaseOffer(Box::new(LeaseOffer::new(
        header,
        RunnerSlotOrdinal::new(1).expect("valid runner slot"),
        lease,
        envelope,
    )))
}

#[test]
fn validated_handshake_preserves_unknown_optional_advertisements() {
    let future =
        RunnerFeature::new("com.example/future-runtime@v9").expect("valid future feature ID");
    let message = RunnerToServer::Hello(RunnerHello::new(
        OperationId::new(),
        SUPPORTED_PROTOCOL_RANGE,
        JobIrVersionRange::current(),
        runner().with_features([RunnerFeature::SHELL_STEPS, future.clone()]),
        UnixMillis::new(1),
    ));
    let validated = ValidatedRunnerToServer::new(message, &ProtocolLimits::default())
        .expect("validate newer optional advertisement");
    let RunnerToServer::Hello(hello) = validated.into_message() else {
        panic!("validated a different runner message")
    };
    assert!(hello.runner().features().contains(&future));
}

#[test]
fn validated_lease_preserves_unknown_required_feature_for_typed_matching() {
    let future =
        RunnerFeature::new("com.example/future-runtime@v9").expect("valid future feature ID");
    let message = lease_offer(RunnerRequirements::default().with_features([future.clone()]));
    let validated = ValidatedServerToRunner::new(message, &ProtocolLimits::default())
        .expect("validate newer required feature");
    let ServerToRunner::LeaseOffer(offer) = validated.into_message() else {
        panic!("validated a different server message")
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
fn validated_lease_preserves_exact_environment_profile_attestation() {
    let required = profile(0x11);
    let message =
        lease_offer(RunnerRequirements::default().with_environment_profile(required.clone()));
    let validated = ValidatedServerToRunner::new(message, &ProtocolLimits::default())
        .expect("validate attested-profile lease offer");
    let ServerToRunner::LeaseOffer(offer) = validated.into_message() else {
        panic!("validated a different server message")
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
fn validated_lease_preserves_exact_windows_hyperv_placement() {
    let message = lease_offer(RunnerRequirements::default().with_windows_hyperv_container());
    let validated = ValidatedServerToRunner::new(message, &ProtocolLimits::default())
        .expect("validate Windows Hyper-V lease offer");
    let ServerToRunner::LeaseOffer(offer) = validated.into_message() else {
        panic!("validated a different server message")
    };
    let requirements = offer.job().job().requirements();
    assert_eq!(
        requirements.operating_system(),
        Some(&OperatingSystem::Windows)
    );
    assert_eq!(
        requirements.minimum_isolation(),
        IsolationLevel::VirtualMachine
    );
    assert!(
        requirements
            .sandbox_features()
            .contains(&SandboxFeature::WINDOWS_HYPERV_CONTAINER)
    );

    let generic_vm = RunnerCapabilities::new(
        RunnerId::new(),
        RunnerPlatform::new(OperatingSystem::Windows, Architecture::X86_64),
    )
    .with_sandbox(SandboxCapabilities::new(IsolationLevel::VirtualMachine, []));
    let mismatches = generic_vm
        .satisfies(requirements)
        .expect_err("generic VM capability cannot accept a Hyper-V-container lease");
    assert_eq!(
        mismatches.as_slice(),
        &[RequirementMismatch::MissingSandboxFeature(
            SandboxFeature::WINDOWS_HYPERV_CONTAINER,
        )]
    );
}

#[test]
fn malformed_capability_identifier_is_rejected_during_domain_deserialization() {
    let message = RunnerToServer::Hello(RunnerHello::new(
        OperationId::new(),
        SUPPORTED_PROTOCOL_RANGE,
        JobIrVersionRange::current(),
        runner().with_features([RunnerFeature::SHELL_STEPS]),
        UnixMillis::new(1),
    ));
    let mut value = serde_json::to_value(message).expect("serialize runner hello");
    value["payload"]["runner"]["features"] = serde_json::json!(["vendor/Future@v1"]);
    assert!(serde_json::from_value::<RunnerToServer>(value).is_err());
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
        ValidatedRunnerToServer::new(message, &limits),
        Err(MessageValidationError::TextTooLong {
            field: "runner feature",
            length,
            maximum: 16,
        }) if length == feature.as_str().len(),
    ));
}

#[test]
fn runtime_authority_bundle_rejects_forward_schema() {
    let ServerToRunner::LeaseOffer(offer) = lease_offer(RunnerRequirements::default()) else {
        panic!("fixture produced a different server message")
    };
    let authority = JobRuntimeAuthority::new(
        RuntimeAuthorityName::new("runner-results").expect("authority name"),
        offer.job().job().run_id(),
        offer.job().job().job_id(),
        offer.lease().attempt_id(),
        offer.lease().fencing_token(),
        RuntimeAuthorityEndpoint::new("https://results.example.test/").expect("endpoint"),
        RuntimeAuthorityCredential::new("header.payload.signature").expect("credential"),
        UnixMillis::new(10),
        UnixMillis::new(3_600_010),
    )
    .expect("runtime authority");
    let authorities = JobRuntimeAuthorities::new(
        vec![authority],
        SandboxAuthorizations::default(),
        offer.job(),
        offer.lease(),
    )
    .expect("runtime authorities");
    let mut value = serde_json::to_value(authorities).expect("serialize authority bundle");
    value["schema_version"] = serde_json::json!(
        RUNTIME_AUTHORITY_SCHEMA_VERSION
            .checked_add(1)
            .expect("test schema")
    );
    let decoded =
        serde_json::from_value::<JobRuntimeAuthorities>(value).expect("decode future bundle");

    assert!(matches!(
        decoded.validate_for(offer.job(), offer.lease()),
        Err(RuntimeAuthorityError::UnsupportedSchema)
    ));
}
