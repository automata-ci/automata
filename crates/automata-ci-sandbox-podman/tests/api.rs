#[cfg(target_os = "linux")]
mod support;

#[cfg(target_os = "linux")]
use std::sync::Arc;

#[cfg(target_os = "linux")]
use automata_ci_execution::{SandboxCapability, SandboxProvider};
#[cfg(target_os = "linux")]
use automata_ci_sandbox_podman::{BuildKitRuntime, CommandOutput, JobContainerEngine};
use automata_ci_sandbox_podman::{
    PodmanCommandExecutor, PodmanConfigurationError, PodmanHostGatewayAlias, RootlessPodmanProvider,
};
use static_assertions::{assert_impl_all, assert_obj_safe};

#[cfg(target_os = "linux")]
use support::{FakePodman, ScratchRoot, options};

assert_impl_all!(RootlessPodmanProvider: Send, Sync);
assert_obj_safe!(PodmanCommandExecutor);

#[cfg(target_os = "linux")]
#[test]
fn docker_api_capability_is_advertised_only_when_explicitly_enabled() {
    let disabled = support::Fixture::new("docker-capability-disabled");
    assert!(
        !disabled
            .provider
            .capabilities()
            .supports(SandboxCapability::DockerCompatibleApi)
    );
    assert!(
        !disabled
            .provider
            .capabilities()
            .supports(SandboxCapability::BuildKit)
    );
    assert!(!disabled.fake.commands().iter().any(|arguments| {
        arguments
            .iter()
            .any(|argument| argument == "--entrypoint=buildkitd")
    }));

    let scratch = ScratchRoot::new("docker-capability-enabled");
    let fake = Arc::new(FakePodman::default());
    let provider = RootlessPodmanProvider::open_with_executor(
        options(scratch.path())
            .with_job_container_engine(JobContainerEngine::AttemptScopedDockerApi),
        fake as Arc<dyn PodmanCommandExecutor>,
    )
    .expect("enabled provider must open");
    assert!(
        provider
            .capabilities()
            .supports(SandboxCapability::DockerCompatibleApi)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn buildkit_capability_requires_the_attempt_api_and_a_successful_local_probe() {
    let scratch = ScratchRoot::new("buildkit-capability-enabled");
    let fake = Arc::new(FakePodman::default());
    let provider = RootlessPodmanProvider::open_with_executor(
        options(scratch.path())
            .with_job_container_engine(JobContainerEngine::AttemptScopedDockerApi)
            .with_buildkit_runtime(BuildKitRuntime::new(support::synthetic_buildkit_image())),
        fake.clone() as Arc<dyn PodmanCommandExecutor>,
    )
    .expect("verified BuildKit provider must open");
    assert!(
        provider
            .capabilities()
            .supports(SandboxCapability::BuildKit)
    );
    let commands = fake.commands();
    let probe = commands
        .iter()
        .find_map(|arguments| {
            arguments
                .iter()
                .position(|argument| argument == "run")
                .map(|position| &arguments[position..])
                .filter(|arguments| {
                    arguments
                        .iter()
                        .any(|argument| argument == "--entrypoint=buildkitd")
                })
        })
        .expect("active BuildKit probe command");
    assert_eq!(
        probe,
        [
            "run",
            "--rm",
            "--pull=never",
            "--network=none",
            "--read-only",
            "--cap-drop=all",
            "--security-opt=no-new-privileges",
            "--pids-limit=64",
            "--memory=268435456",
            "--entrypoint=buildkitd",
            support::synthetic_buildkit_image().reference(),
            "--version",
        ]
    );

    let scratch = ScratchRoot::new("buildkit-capability-without-api");
    let fake = Arc::new(FakePodman::default());
    let error = RootlessPodmanProvider::open_with_executor(
        options(scratch.path())
            .with_buildkit_runtime(BuildKitRuntime::new(support::synthetic_buildkit_image())),
        fake as Arc<dyn PodmanCommandExecutor>,
    )
    .expect_err("BuildKit without the attempt API must fail closed");
    assert!(matches!(
        error,
        automata_ci_sandbox_podman::PodmanOpenError::Configuration(
            PodmanConfigurationError::BuildKitUnavailable
        )
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn buildkit_capability_rejects_missing_mismatched_or_unprobeable_runtimes() {
    fn mismatch_digest(fake: &FakePodman) {
        fake.override_buildkit_digest(&format!("sha256:{}", "77".repeat(32)));
    }

    fn invalidate_probe(fake: &FakePodman) {
        fake.set_buildkit_probe_output(CommandOutput::success(
            b"unexpected local executable\n".to_vec(),
        ));
    }

    fn assert_rejected(case: &str, configure_fake: impl FnOnce(&FakePodman)) {
        let scratch = ScratchRoot::new(&format!("buildkit-capability-{case}"));
        let fake = Arc::new(FakePodman::default());
        configure_fake(&fake);
        let error = RootlessPodmanProvider::open_with_executor(
            options(scratch.path())
                .with_job_container_engine(JobContainerEngine::AttemptScopedDockerApi)
                .with_buildkit_runtime(BuildKitRuntime::new(support::synthetic_buildkit_image())),
            fake as Arc<dyn PodmanCommandExecutor>,
        )
        .expect_err("unverified BuildKit runtime must not be advertised");
        assert!(
            matches!(
                error,
                automata_ci_sandbox_podman::PodmanOpenError::Configuration(
                    PodmanConfigurationError::BuildKitUnavailable
                )
            ),
            "{case}"
        );
    }

    assert_rejected("missing", FakePodman::make_buildkit_image_missing);
    assert_rejected("digest-mismatch", mismatch_digest);
    assert_rejected("invalid-probe", invalidate_probe);
}

#[test]
fn host_gateway_alias_accepts_only_explicit_dns_hostnames() {
    let alias = PodmanHostGatewayAlias::new("automata-git.invalid", 8088).expect("valid DNS alias");
    assert_eq!(alias.as_str(), "automata-git.invalid");
    assert_eq!(alias.port(), 8088);

    for invalid in [
        "localhost",
        "automata-git.localhost",
        "127.0.0.1",
        "::1",
        "*.localhost",
        "automata-git.localhost:8088",
        "automata-git.localhost/path",
        "automata_git.localhost",
        "automata-git.localhost\n--privileged",
        ".localhost",
        "automata-git.localhost.",
    ] {
        assert_eq!(
            PodmanHostGatewayAlias::new(invalid, 8088),
            Err(PodmanConfigurationError::InvalidHostGatewayAlias),
            "{invalid:?} must be rejected"
        );
    }
    assert_eq!(
        PodmanHostGatewayAlias::new("automata-git.invalid", 0),
        Err(PodmanConfigurationError::InvalidHostGatewayAlias)
    );
}
