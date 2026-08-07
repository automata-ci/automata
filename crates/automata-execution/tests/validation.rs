use std::time::Duration;

use automata_execution::{
    EnvironmentName, EnvironmentProfile, EnvironmentProfileId, EnvironmentValue,
    EnvironmentVariable, ExecutionArgv, ExecutionCommand, ExecutionEnvironment, ImmutableImage,
    NetworkPolicy, OperationId, ProviderCapabilities, ProviderId, ResourceLimits,
    RootFilesystemPolicy, SandboxCapability, SandboxEnvironment, SandboxGeneration, SandboxHandle,
    SandboxPrivilegePolicy, SandboxSpec, Sha256Digest, TargetPath, ValueError,
};

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

    let spec = SandboxSpec::new(
        OperationId::new(),
        SandboxGeneration::new(7).expect("generation"),
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
    assert_eq!(
        spec.profile().id().as_str(),
        "automata.dev/arch-linux-x86-64-v1"
    );
    assert_eq!(
        spec.profile().digest(),
        Sha256Digest::from_bytes([0x11; 32])
    );
    assert_eq!(spec.profile().image().reference(), IMAGE);
    assert_eq!(spec.resources().cpu_millis(), 2_000);
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
    let environment = ExecutionEnvironment::new(vec![EnvironmentVariable::new(
        EnvironmentName::new("CI_TOKEN").expect("name"),
        EnvironmentValue::new(secret).expect("value"),
    )])
    .expect("environment");
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
