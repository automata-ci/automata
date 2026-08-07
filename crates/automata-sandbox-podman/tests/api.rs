mod support;

use std::sync::Arc;

use automata_execution::{ExecutionEndpoint, SandboxCapability, SandboxProvider};
use automata_sandbox_podman::{
    JobContainerEngine, PodmanCommandExecutor, PodmanConfigurationError, PodmanHostGatewayAlias,
    RootlessPodmanProvider,
};
use static_assertions::{assert_impl_all, assert_obj_safe};

use support::{FakePodman, ScratchRoot, options};

assert_impl_all!(RootlessPodmanProvider: Send, Sync);
assert_obj_safe!(PodmanCommandExecutor);

#[test]
fn provider_ports_remain_object_safe() {
    fn provider(_provider: &dyn SandboxProvider) {}
    fn endpoint(_endpoint: &dyn ExecutionEndpoint) {}
    fn command_adapter(_adapter: &dyn PodmanCommandExecutor) {}

    let _ = provider;
    let _ = endpoint;
    let _ = command_adapter;
}

#[test]
fn docker_api_capability_is_advertised_only_when_explicitly_enabled() {
    let disabled = support::Fixture::new("docker-capability-disabled");
    assert!(
        !disabled
            .provider
            .capabilities()
            .supports(SandboxCapability::DockerCompatibleApi)
    );

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

#[test]
fn host_gateway_alias_accepts_only_explicit_dns_hostnames() {
    let alias = PodmanHostGatewayAlias::new("automata-git.localhost").expect("valid DNS alias");
    assert_eq!(alias.as_str(), "automata-git.localhost");

    for invalid in [
        "localhost",
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
            PodmanHostGatewayAlias::new(invalid),
            Err(PodmanConfigurationError::InvalidHostGatewayAlias),
            "{invalid:?} must be rejected"
        );
    }
}
