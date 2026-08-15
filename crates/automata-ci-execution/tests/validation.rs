use std::{collections::BTreeMap, time::Duration};

use automata_ci_execution::{
    CancellationDisposition, ENDPOINT_JOB_SETUP_OPERATIONS, ENDPOINT_OPERATIONS_PER_RUN_STEP,
    EnvironmentName, EnvironmentProfile, EnvironmentProfileId, EnvironmentValue,
    EnvironmentVariable, ExecutionArgv, ExecutionCommand, ExecutionEnvironment, ExecutionOutput,
    ExecutionOutputRecord, ExecutionOutputStream, ExecutionTermination, ImmutableImage,
    MAX_ENDPOINT_OPERATIONS_PER_JOB, MAX_EXECUTION_OUTPUT_BYTES, MAX_EXECUTION_OUTPUT_RECORD_BYTES,
    MAX_EXECUTION_OUTPUT_RECORDS, NetworkPolicy, OperationId, ProviderCapabilities, ProviderId,
    ResourceLimits, RootFilesystemPolicy, RunnerId, SandboxCapability, SandboxCustody,
    SandboxEnvironment, SandboxGeneration, SandboxHandle, SandboxPrivilegePolicy, SandboxSpec,
    ServiceContainerBinding, ServiceContainerBindings, ServiceContainerSpec, ServiceContainerSpecs,
    ServiceHealthOverrides, ServiceHealthPolicy, ServiceNetwork, ServicePort, ServicePortBinding,
    ServiceTransportProtocol, Sha256Digest, TargetPath, ValueError,
};

#[test]
fn only_termination_authorizes_backend_quiescence() {
    assert!(!CancellationDisposition::Active.requires_termination());
    assert!(CancellationDisposition::Terminate.requires_termination());
}

#[test]
fn endpoint_operation_budget_admits_every_maximum_run_only_phase() {
    assert_eq!(ENDPOINT_JOB_SETUP_OPERATIONS, 2);
    assert_eq!(ENDPOINT_OPERATIONS_PER_RUN_STEP, 15);
    assert_eq!(
        MAX_ENDPOINT_OPERATIONS_PER_JOB,
        automata_ci_core::MAX_LOGICAL_STEPS * ENDPOINT_OPERATIONS_PER_RUN_STEP
            + ENDPOINT_JOB_SETUP_OPERATIONS
    );
    assert_eq!(MAX_ENDPOINT_OPERATIONS_PER_JOB, 30_722);
}

const IMAGE: &str = "docker.io/library/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn profile() -> SandboxEnvironment {
    SandboxEnvironment::new(
        EnvironmentProfile::new(
            EnvironmentProfileId::new("automata.dev/arch-linux-x86-64-v1").expect("profile ID"),
            Sha256Digest::from_bytes([0x11; 32]),
        ),
        ImmutableImage::new(IMAGE).expect("immutable image"),
        ExecutionArgv::new(
            TargetPath::posix("/bin/sleep").expect("program"),
            vec!["infinity".to_owned()],
        )
        .expect("keepalive argv"),
        TargetPath::posix("/__w").expect("workspace"),
        ExecutionEnvironment::empty(),
    )
    .expect("profile")
}

fn custody() -> SandboxCustody {
    SandboxCustody::ProfileAdmission {
        runner_id: RunnerId::new(),
    }
}

#[test]
fn image_profile_and_spec_are_exact_and_never_resolve_hosted_labels() {
    let image = ImmutableImage::new(IMAGE).expect("immutable image");
    assert_eq!(image.reference(), IMAGE);
    assert!(matches!(
        ImmutableImage::new("docker.io/library/alpine:latest"),
        Err(ValueError::InvalidImmutableImage)
    ));
    assert!(matches!(
        ImmutableImage::new(
            "docker.io/library/alpine@sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ),
        Err(ValueError::InvalidImmutableImage)
    ));
    for invalid in [
        "library/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "Registry.Example/library/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "registry.example/Team/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "registry.example:05000/team/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "registry.example/team//alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "registry.example/team/alpine_@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        assert_eq!(
            ImmutableImage::new(invalid),
            Err(ValueError::InvalidImmutableImage),
            "invalid image reference was accepted: {invalid}"
        );
    }
    for valid in [
        "localhost/team/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "localhost:5000/team/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "registry.example/team/a_b.c--d@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "[2001:db8::1]:5000/team/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        assert_eq!(
            ImmutableImage::new(valid)
                .expect("valid registry-qualified immutable image")
                .reference(),
            valid
        );
    }

    let spec = SandboxSpec::new(
        OperationId::new(),
        SandboxGeneration::new(7).expect("generation"),
        custody(),
        profile(),
        TargetPath::posix("/__w").expect("workspace"),
        NetworkPolicy::Disabled,
        RootFilesystemPolicy::ReadOnly,
        ResourceLimits::new(512 * 1024 * 1024, 2_000, 256).expect("limits"),
    );
    assert_eq!(spec.privilege(), SandboxPrivilegePolicy::Unprivileged);
    let administrative = spec
        .clone()
        .with_privilege(SandboxPrivilegePolicy::Administrator);
    assert_eq!(
        administrative.privilege(),
        SandboxPrivilegePolicy::Administrator
    );
    let host_identity = spec.clone().with_privilege(SandboxPrivilegePolicy::Host);
    assert_eq!(host_identity.privilege(), SandboxPrivilegePolicy::Host);
    assert_eq!(
        spec.profile().id().as_str(),
        "automata.dev/arch-linux-x86-64-v1"
    );
    assert_eq!(
        spec.profile().digest(),
        Sha256Digest::from_bytes([0x11; 32])
    );
    assert_eq!(
        spec.profile().image().expect("container image").reference(),
        IMAGE
    );
    assert_eq!(spec.resources().cpu_millis(), 2_000);
}

#[test]
fn windows_hyperv_container_profile_is_explicit_and_digest_pinned() {
    const WINDOWS_IMAGE: &str = "mcr.microsoft.com/windows/servercore@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let environment = SandboxEnvironment::windows_hyperv_container(
        EnvironmentProfile::new(
            EnvironmentProfileId::new("automata.dev/windows-2025-hyperv-v1").expect("profile ID"),
            Sha256Digest::from_bytes([0x22; 32]),
        ),
        ImmutableImage::new(WINDOWS_IMAGE).expect("immutable Windows image"),
        ExecutionArgv::new(
            TargetPath::windows(r"C:\automata\guest\automata-ci-sandbox-guest.exe")
                .expect("keepalive program"),
            vec!["keepalive".to_owned()],
        )
        .expect("keepalive argv"),
        TargetPath::windows(r"C:\automata\workspaces").expect("workspace root"),
        ExecutionEnvironment::empty(),
    )
    .expect("Hyper-V container profile");
    assert!(matches!(
        environment.launch(),
        automata_ci_execution::SandboxLaunch::WindowsHyperVContainer { .. }
    ));
    assert_eq!(
        environment.image().expect("container image").reference(),
        WINDOWS_IMAGE
    );
    assert!(environment.keepalive().is_some());
}

#[test]
fn handles_and_target_paths_are_bounded_platform_typed_and_opaque_in_debug() {
    let handle = SandboxHandle::new(
        ProviderId::new("podman-rootless-v1").expect("provider"),
        "p1.0123456789abcdef.7",
    )
    .expect("handle");
    assert_eq!(handle.opaque(), "p1.0123456789abcdef.7");
    assert!(!format!("{handle:?}").contains("0123456789abcdef"));
    assert!(TargetPath::posix("/__w/project").is_ok());
    assert!(TargetPath::windows(r"C:\work\project").is_ok());
    assert_eq!(
        TargetPath::windows(r"c:\work\project")
            .expect("lowercase drive is normalized")
            .as_str(),
        r"C:\work\project"
    );
    for invalid in ["/__w/project/", "/__w//project"] {
        assert_eq!(
            TargetPath::posix(invalid),
            Err(ValueError::InvalidTargetPath)
        );
    }
    for invalid in [
        r"C:\work\project\",
        r"C:\work\artifact:stream",
        r"C:\work\trailing.",
        r"C:\work\wild*card",
    ] {
        assert_eq!(
            TargetPath::windows(invalid),
            Err(ValueError::InvalidTargetPath)
        );
    }
    assert!(matches!(
        TargetPath::posix("/__w/../host"),
        Err(ValueError::InvalidTargetPath)
    ));
    assert!(matches!(
        TargetPath::windows(r"\\server\share"),
        Err(ValueError::InvalidTargetPath)
    ));
}

#[test]
fn execution_values_redact_secrets_and_enforce_aggregate_bounds() {
    let secret = "super-secret-token";
    let plain = EnvironmentVariable::new(
        EnvironmentName::new("CI_TOKEN").expect("name"),
        EnvironmentValue::new(secret).expect("value"),
    );
    assert!(!plain.is_secret());
    let sensitive = EnvironmentVariable::secret(
        EnvironmentName::new("SECRET_TOKEN").expect("secret name"),
        EnvironmentValue::new(secret).expect("secret value"),
    );
    assert!(sensitive.is_secret());
    assert!(!format!("{sensitive:?}").contains(secret));
    let environment = ExecutionEnvironment::new(vec![plain]).expect("environment");
    let command = ExecutionCommand::new(
        OperationId::new(),
        ExecutionArgv::new(
            TargetPath::posix("/usr/bin/printf").expect("program"),
            vec![secret.to_owned()],
        )
        .expect("argv"),
        TargetPath::posix("/__w").expect("cwd"),
        environment,
        Duration::from_secs(30),
        4_096,
    )
    .expect("command");
    assert!(!format!("{command:?}").contains(secret));
    assert!(
        ExecutionCommand::new(
            OperationId::new(),
            ExecutionArgv::new(TargetPath::posix("/bin/true").expect("program"), vec![])
                .expect("argv"),
            TargetPath::posix("/").expect("cwd"),
            ExecutionEnvironment::empty(),
            Duration::ZERO,
            1,
        )
        .is_err()
    );
}

#[test]
fn execution_output_requires_one_complete_ordered_sequence() {
    let records = vec![
        ExecutionOutputRecord::data(ExecutionOutputStream::Stdout, b"out-1".to_vec())
            .expect("stdout record"),
        ExecutionOutputRecord::data(ExecutionOutputStream::Stderr, b"err".to_vec())
            .expect("stderr record"),
        ExecutionOutputRecord::data(ExecutionOutputStream::Stdout, b"-out-2".to_vec())
            .expect("stdout record"),
        ExecutionOutputRecord::end_of_stream(ExecutionOutputStream::Stderr),
        ExecutionOutputRecord::end_of_stream(ExecutionOutputStream::Stdout),
    ];
    let output = ExecutionOutput::new(ExecutionTermination::Exited(0), records.clone(), false)
        .expect("complete ordered output");

    assert_eq!(output.records(), records);
    assert_eq!(output.stdout(), b"out-1-out-2");
    assert_eq!(output.stderr(), b"err");

    let missing_end = vec![ExecutionOutputRecord::end_of_stream(
        ExecutionOutputStream::Stdout,
    )];
    assert!(matches!(
        ExecutionOutput::new(ExecutionTermination::Exited(0), missing_end.clone(), false),
        Err(ValueError::InvalidExecutionOutput)
    ));
    assert!(
        ExecutionOutput::new(ExecutionTermination::Exited(0), missing_end, true).is_ok(),
        "incomplete capture is representable only when consumers must reject it"
    );

    let duplicate_end = vec![
        ExecutionOutputRecord::end_of_stream(ExecutionOutputStream::Stdout),
        ExecutionOutputRecord::end_of_stream(ExecutionOutputStream::Stdout),
    ];
    assert!(matches!(
        ExecutionOutput::new(ExecutionTermination::Exited(0), duplicate_end, true),
        Err(ValueError::InvalidExecutionOutput)
    ));

    let data_after_end = vec![
        ExecutionOutputRecord::end_of_stream(ExecutionOutputStream::Stdout),
        ExecutionOutputRecord::data(ExecutionOutputStream::Stdout, b"late".to_vec())
            .expect("bounded data"),
    ];
    assert!(matches!(
        ExecutionOutput::new(ExecutionTermination::Exited(0), data_after_end, true),
        Err(ValueError::InvalidExecutionOutput)
    ));
}

#[test]
fn execution_output_enforces_record_and_aggregate_bounds() {
    assert!(matches!(
        ExecutionOutputRecord::data(ExecutionOutputStream::Stdout, Vec::new()),
        Err(ValueError::InvalidExecutionOutput)
    ));
    assert!(
        ExecutionOutputRecord::data(
            ExecutionOutputStream::Stdout,
            vec![b'x'; MAX_EXECUTION_OUTPUT_RECORD_BYTES]
        )
        .is_ok()
    );
    assert!(matches!(
        ExecutionOutputRecord::data(
            ExecutionOutputStream::Stdout,
            vec![b'x'; MAX_EXECUTION_OUTPUT_RECORD_BYTES + 1]
        ),
        Err(ValueError::InvalidExecutionOutput)
    ));

    let record = ExecutionOutputRecord::data(ExecutionOutputStream::Stdout, vec![b'x'])
        .expect("one-byte record");
    assert!(matches!(
        ExecutionOutput::new(
            ExecutionTermination::Exited(0),
            vec![record; MAX_EXECUTION_OUTPUT_RECORDS + 1],
            true,
        ),
        Err(ValueError::InvalidExecutionOutput)
    ));

    let full_record = ExecutionOutputRecord::data(
        ExecutionOutputStream::Stdout,
        vec![b'x'; MAX_EXECUTION_OUTPUT_RECORD_BYTES],
    )
    .expect("maximum record");
    let mut exact =
        vec![full_record; MAX_EXECUTION_OUTPUT_BYTES / MAX_EXECUTION_OUTPUT_RECORD_BYTES];
    exact.push(ExecutionOutputRecord::end_of_stream(
        ExecutionOutputStream::Stdout,
    ));
    exact.push(ExecutionOutputRecord::end_of_stream(
        ExecutionOutputStream::Stderr,
    ));
    assert!(ExecutionOutput::new(ExecutionTermination::Exited(0), exact, false).is_ok());

    let mut oversized = vec![
        ExecutionOutputRecord::data(
            ExecutionOutputStream::Stdout,
            vec![b'x'; MAX_EXECUTION_OUTPUT_RECORD_BYTES],
        )
        .expect("maximum record");
        MAX_EXECUTION_OUTPUT_BYTES / MAX_EXECUTION_OUTPUT_RECORD_BYTES
    ];
    oversized.push(
        ExecutionOutputRecord::data(ExecutionOutputStream::Stderr, vec![b'y']).expect("one byte"),
    );
    assert!(matches!(
        ExecutionOutput::new(ExecutionTermination::Exited(0), oversized, true),
        Err(ValueError::InvalidByteLimit)
    ));
}

#[test]
fn execution_output_debug_redacts_every_record_and_aggregate() {
    let sentinel = "execution-output-private-sentinel";
    let record =
        ExecutionOutputRecord::data(ExecutionOutputStream::Stdout, sentinel.as_bytes().to_vec())
            .expect("bounded record");
    assert!(!format!("{record:?}").contains(sentinel));
    let output = ExecutionOutput::new(
        ExecutionTermination::Exited(0),
        vec![
            record,
            ExecutionOutputRecord::end_of_stream(ExecutionOutputStream::Stdout),
            ExecutionOutputRecord::end_of_stream(ExecutionOutputStream::Stderr),
        ],
        false,
    )
    .expect("complete output");
    assert!(!format!("{output:?}").contains(sentinel));
}

#[test]
fn environment_names_preserve_github_action_input_keys() {
    let input = EnvironmentName::new("INPUT_FETCH-DEPTH").expect("GitHub input environment name");
    assert_eq!(input.as_str(), "INPUT_FETCH-DEPTH");
    assert!(EnvironmentName::new("INPUT_WITH.DOT").is_ok());
    assert!(EnvironmentName::new("INPUT_ÜNICODE").is_ok());
    for invalid in ["", "BAD=NAME", "BAD\nNAME", "BAD\0NAME"] {
        assert!(matches!(
            EnvironmentName::new(invalid),
            Err(ValueError::InvalidEnvironmentName)
        ));
    }
}

#[test]
fn capability_declarations_are_unique_and_explicit() {
    let capabilities = ProviderCapabilities::new([
        SandboxCapability::WholeJob,
        SandboxCapability::Exec,
        SandboxCapability::ReadOnlyRootFilesystem,
    ])
    .expect("capabilities");
    assert!(capabilities.supports(SandboxCapability::Exec));
    assert!(!capabilities.supports(SandboxCapability::CopyFrom));
    assert!(ProviderCapabilities::new([SandboxCapability::Exec, SandboxCapability::Exec]).is_err());
}

#[test]
fn service_requests_are_exact_redacted_and_discovered_by_requested_port() {
    let image = ImmutableImage::new(format!(
        "docker.io/library/postgres@sha256:{}",
        "b".repeat(64)
    ))
    .expect("immutable service image");
    let secret = "database-secret";
    let environment = ExecutionEnvironment::new(vec![EnvironmentVariable::new(
        EnvironmentName::new("POSTGRES_PASSWORD").expect("environment name"),
        EnvironmentValue::new(secret).expect("environment value"),
    )])
    .expect("service environment");
    let postgres =
        ServicePort::new(5432, Some(5432), ServiceTransportProtocol::Tcp).expect("service port");
    let health = ServiceHealthOverrides::new(
        Some("pg_isready".to_owned()),
        Some(Duration::from_secs(10)),
        Some(Duration::from_secs(5)),
        None,
        Some(5),
    )
    .expect("health overrides");
    let service = ServiceContainerSpec::new(image, environment)
        .with_ports([postgres])
        .expect("unique ports")
        .with_health(ServiceHealthPolicy::Override(health));
    let services = ServiceContainerSpecs::new(BTreeMap::from([("postgres".to_owned(), service)]))
        .expect("service specs");
    let sandbox = SandboxSpec::new(
        OperationId::new(),
        SandboxGeneration::new(9).expect("generation"),
        custody(),
        profile(),
        TargetPath::posix("/__w/project").expect("workspace"),
        NetworkPolicy::PrivateEgress,
        RootFilesystemPolicy::Writable,
        ResourceLimits::new(512 * 1024 * 1024, 1_000, 128).expect("limits"),
    )
    .with_services(services);
    assert_eq!(sandbox.services().len(), 1);
    assert!(!format!("{sandbox:?}").contains(secret));
    assert!(!format!("{sandbox:?}").contains("pg_isready"));

    let binding = ServiceContainerBinding::new(
        automata_ci_execution::ContainerHandle::new("postgres-1").expect("container handle"),
        ServiceNetwork::new("sandbox-network").expect("network"),
        [ServicePortBinding::new(postgres, 5432).expect("binding")],
    )
    .expect("service binding");
    let bindings =
        ServiceContainerBindings::new(BTreeMap::from([("postgres".to_owned(), binding)]))
            .expect("bindings");
    let published = bindings.get("postgres").expect("postgres binding").ports()[0];
    assert_eq!(published.service_port().container_port(), 5432);
    assert_eq!(published.service_port().requested_host_port(), Some(5432));
    assert_eq!(published.host_port(), 5432);
    assert!(ServicePortBinding::new(postgres, 31_337).is_err());
}
