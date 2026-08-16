#![cfg(target_os = "linux")]

mod support;

use std::{
    collections::BTreeMap,
    ffi::OsString,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use automata_ci_execution::{
    Cancellation, CopyFromRequest, CopyToRequest, DestroySandbox, EnvironmentName,
    EnvironmentProfile, EnvironmentProfileId, EnvironmentValue, EnvironmentVariable, ExecutionArgv,
    ExecutionCommand, ExecutionEnvironment, ExecutionErrorKind, ExecutionTermination,
    ImmutableImage, NetworkPolicy, NeverCancelled, OperationId, ProviderErrorKind, ResourceLimits,
    RootFilesystemPolicy, RunnerId, SandboxCustody, SandboxEnvironment, SandboxGeneration,
    SandboxPrivilegePolicy, SandboxProvider, SandboxSpec, ServiceContainerSpec,
    ServiceContainerSpecs, ServiceHealthOverrides, ServiceHealthPolicy, ServicePort,
    ServiceTransportProtocol, Sha256Digest, TargetPath,
};
use automata_ci_sandbox_podman::{
    BuildKitRuntime, CommandRequest, CommandTermination, JobContainerEngine, PodmanBinary,
    PodmanCommandExecutor, PodmanHostGatewayAlias, PodmanLaunchTrust, PodmanLaunchTrustHandle,
    PodmanOptions, PodmanProcessEnvironment, PodmanStateRoot, RootlessPodmanProvider,
    SystemCommandExecutor,
};

use support::ScratchRoot;

#[derive(Debug)]
struct LiveLaunchTrust;

impl PodmanLaunchTrust for LiveLaunchTrust {
    fn revalidate(&self) -> bool {
        true
    }
}

const LIVE_ENABLE: &str = "AUTOMATA_LIVE_ROOTLESS_PODMAN";
const LIVE_IMAGE: &str = "AUTOMATA_PODMAN_TEST_IMAGE";
const LIVE_SERVICE_IMAGE: &str = "AUTOMATA_PODMAN_TEST_SERVICE_IMAGE";
const LIVE_SERVICE_PROXY_IMAGE: &str = "AUTOMATA_PODMAN_TEST_SERVICE_PROXY_IMAGE";
const LIVE_BUILDKIT_ENABLE: &str = "AUTOMATA_LIVE_ROOTLESS_BUILDX";
const LIVE_BUILDKIT_IMAGE: &str = "AUTOMATA_PODMAN_TEST_BUILDKIT_IMAGE";
const CLANG_PACKAGE_VERSION: &str = "1:18.1.3-1ubuntu1";
const DOCKER_DISTRIBUTION_SURFACE: &str = r#"
set -euo pipefail
chmod 0555 /__w/static-http-server
image=automata-docker-live:one
container=automata-docker-live-one
docker build --quiet --file /__w/Containerfile --tag "$image" /__w
test "$(docker run --rm --entrypoint /server "$image" --version)" = "automata-docker-live 1"
docker run --detach --name "$container" --publish 127.0.0.1::8080/tcp "$image" >/dev/null
test "$(docker inspect --format '{{.HostConfig.LogConfig.Type}}' "$container")" = "json-file"
published="$(docker port "$container" 8080/tcp)"
test "$published" = "127.0.0.1:8080"
deadline=$((SECONDS + 20))
until response="$(curl --fail --silent --show-error "http://${published}/")"; do
    if (( SECONDS >= deadline )); then
        docker logs "$container" >&2 || true
        exit 1
    fi
    sleep 0.1
done
test "$response" = "automata-docker-live-ok"
docker logs "$container" | grep -Fx "automata-docker-live ready"
docker rm --force "$container" >/dev/null
docker image rm --force "$image" >/dev/null
printf 'attempt-scoped-docker-ok\n'
"#;

#[derive(Debug, Default)]
struct AtomicCancellation(AtomicBool);

impl Cancellation for AtomicCancellation {
    fn disposition(&self) -> automata_ci_execution::CancellationDisposition {
        if self.0.load(Ordering::Acquire) {
            automata_ci_execution::CancellationDisposition::Terminate
        } else {
            automata_ci_execution::CancellationDisposition::Active
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires explicitly enabled rootless Podman and a local digest-pinned profile image"]
fn opt_in_rootless_contract_leaves_no_owned_resources() {
    let image = live_image();
    let scratch = ScratchRoot::new("live-rootless");
    let (options, environment, binary) = live_options(scratch.path());
    let base_arguments = options.shared_global_arguments();
    let provider = RootlessPodmanProvider::open(options).expect("open live provider");
    let operation_id = OperationId::new();
    let generation = SandboxGeneration::new(1).expect("generation");
    let spec = live_spec(operation_id, generation, image);

    let created = match provider.create(&spec, &NeverCancelled) {
        Ok(created) => created,
        Err(error) => {
            if let Some(handle) = error.recovery_handle() {
                let _ignored = provider.destroy(
                    &DestroySandbox::new(
                        OperationId::new(),
                        handle.clone(),
                        generation,
                        spec.custody(),
                    ),
                    &NeverCancelled,
                );
            }
            panic!("create live sandbox: {error}");
        }
    };
    let mut cleanup = SandboxCleanup::new(
        provider.clone(),
        created.handle().clone(),
        generation,
        spec.custody(),
    );
    let endpoint = provider
        .attach(created.handle(), &NeverCancelled)
        .expect("attach live endpoint");
    let echo = command("/bin/echo", vec!["automata-live".to_owned()], 5);
    let output = endpoint.exec(&echo, &NeverCancelled).expect("live exec");
    assert_eq!(output.termination(), ExecutionTermination::Exited(0));
    assert_eq!(output.stdout(), b"automata-live\n");

    assert_live_environment(endpoint.as_ref());
    assert_live_copy(endpoint.as_ref(), scratch.path());
    assert_live_cancellation(endpoint.as_ref());

    provider
        .destroy(
            &DestroySandbox::new(
                OperationId::new(),
                created.handle().clone(),
                generation,
                spec.custody(),
            ),
            &NeverCancelled,
        )
        .expect("destroy live sandbox");
    cleanup.disarm();
    let absent = provider
        .inspect(created.handle(), &NeverCancelled)
        .expect_err("destroyed handle must be absent");
    assert_eq!(absent.kind(), ProviderErrorKind::NotFound);

    let selector = format!(
        "label=io.automata.sandbox={}",
        operation_id.as_uuid().simple()
    );
    for arguments in [
        vec!["ps", "-a", "--filter", &selector, "--format", "{{.ID}}"],
        vec!["pod", "ps", "--filter", &selector, "--format", "{{.ID}}"],
        vec![
            "network", "ls", "--filter", &selector, "--format", "{{.ID}}",
        ],
    ] {
        assert_no_resources(&binary, &environment, &base_arguments, arguments);
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires explicitly enabled rootless Podman and local digest-pinned job/service images"]
#[allow(clippy::too_many_lines)]
fn opt_in_rootless_services_are_healthy_discoverable_recoverable_and_exactly_removed() {
    let image = live_image();
    let service_image = live_service_image();
    let proxy_image = live_service_proxy_image();
    let scratch = ScratchRoot::new("live-rootless-services");
    let (options, environment, binary) = live_options(scratch.path());
    let options = options.with_service_proxy_image(proxy_image.clone());
    let base_arguments = options.shared_global_arguments();
    let provider = RootlessPodmanProvider::open(options).expect("open live provider");
    let operation_id = OperationId::new();
    let generation = SandboxGeneration::new(1).expect("generation");
    let service = ServiceContainerSpec::new(
        ImmutableImage::new(service_image).expect("digest-pinned live service image"),
        ExecutionEnvironment::empty(),
    )
    .with_ports([
        ServicePort::new(8_080, Some(80), ServiceTransportProtocol::Tcp).expect("service port"),
    ])
    .expect("live service ports")
    .with_health(ServiceHealthPolicy::Override(
        ServiceHealthOverrides::new(
            Some("true".to_owned()),
            Some(Duration::from_secs(1)),
            Some(Duration::from_secs(1)),
            Some(Duration::from_secs(1)),
            Some(3),
        )
        .expect("live service health"),
    ));
    let spec = live_spec_with_network(
        operation_id,
        generation,
        image,
        NetworkPolicy::PrivateEgress,
    )
    .with_services(
        ServiceContainerSpecs::new(BTreeMap::from([("service".to_owned(), service)]))
            .expect("live service specs"),
    );
    let created = match provider.create(&spec, &NeverCancelled) {
        Ok(created) => created,
        Err(error) => {
            if let Some(handle) = error.recovery_handle() {
                let _ignored = provider.destroy(
                    &DestroySandbox::new(
                        OperationId::new(),
                        handle.clone(),
                        generation,
                        spec.custody(),
                    ),
                    &NeverCancelled,
                );
            }
            panic!("create live service sandbox: {error}");
        }
    };
    let first = provider
        .service_bindings(created.handle(), &NeverCancelled)
        .expect("live service bindings");
    let binding = first.get("service").expect("live service binding");
    assert_eq!(binding.ports().len(), 1);
    assert_ne!(binding.ports()[0].host_port(), 0);
    let endpoint = provider
        .attach(created.handle(), &NeverCancelled)
        .expect("attach service job endpoint");
    let request = command(
        "/usr/bin/curl",
        vec![
            "--fail".to_owned(),
            "--silent".to_owned(),
            "--show-error".to_owned(),
            format!("http://127.0.0.1:{}/", binding.ports()[0].host_port()),
        ],
        10,
    );
    let output = endpoint
        .exec(&request, &NeverCancelled)
        .expect("reach service through job-local loopback proxy");
    assert_eq!(output.termination(), ExecutionTermination::Exited(0));
    drop(endpoint);

    let handle = created.handle().clone();
    drop(provider);
    let reopened = RootlessPodmanProvider::open(
        PodmanOptions::new(
            binary.clone(),
            PodmanStateRoot::existing(scratch.path()).expect("reopened live state root"),
            environment.clone(),
        )
        .expect("reopened live Podman options")
        .with_service_proxy_image(proxy_image),
    )
    .expect("reopen live service provider");
    assert_eq!(
        reopened
            .service_bindings(&handle, &NeverCancelled)
            .expect("recovered live service bindings"),
        first
    );
    reopened
        .destroy(
            &DestroySandbox::new(OperationId::new(), handle, generation, spec.custody()),
            &NeverCancelled,
        )
        .expect("destroy live service sandbox");

    let selector = format!(
        "label=io.automata.sandbox={}",
        operation_id.as_uuid().simple()
    );
    for arguments in [
        vec!["ps", "-a", "--filter", &selector, "--format", "{{.ID}}"],
        vec!["pod", "ps", "--filter", &selector, "--format", "{{.ID}}"],
        vec![
            "network", "ls", "--filter", &selector, "--format", "{{.ID}}",
        ],
    ] {
        assert_no_resources(&binary, &environment, &base_arguments, arguments);
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires explicitly enabled rootless Podman and a local digest-pinned profile image"]
fn opt_in_rootless_administrator_is_confined_and_writable() {
    let image = live_image();
    let scratch = ScratchRoot::new("live-rootless-administrator");
    let (options, _, _) = live_options(scratch.path());
    let provider = RootlessPodmanProvider::open(options).expect("open live provider");
    let operation_id = OperationId::new();
    let generation = SandboxGeneration::new(1).expect("generation");
    let spec = live_spec(operation_id, generation, image)
        .with_root_filesystem(RootFilesystemPolicy::Writable)
        .with_privilege(SandboxPrivilegePolicy::Administrator);

    let created = provider
        .create(&spec, &NeverCancelled)
        .expect("create rootless administrator sandbox");
    let mut cleanup = SandboxCleanup::new(
        provider.clone(),
        created.handle().clone(),
        generation,
        spec.custody(),
    );
    let endpoint = provider
        .attach(created.handle(), &NeverCancelled)
        .expect("attach live endpoint");
    let verify = command(
        "/bin/sh",
        vec![
            "-ceu".to_owned(),
            "test \"$(id -u)\" = 0; touch /automata-rootfs-probe; install -o nobody -g nogroup -m 0600 /dev/null /__w/owned-by-nobody; install -d -o nobody -g nogroup -m 0700 /__w/subuid-tree; cd /__w/subuid-tree; sudo -u nobody -- sh -ceu 'mkdir -p nested; touch nested/output; id -u'"
                .to_owned(),
        ],
        10,
    );
    let output = endpoint
        .exec(&verify, &NeverCancelled)
        .expect("execute confined administrator contract");
    assert_eq!(output.termination(), ExecutionTermination::Exited(0));
    assert_eq!(output.stdout(), b"65534\n");

    provider
        .destroy(
            &DestroySandbox::new(
                OperationId::new(),
                created.handle().clone(),
                generation,
                spec.custody(),
            ),
            &NeverCancelled,
        )
        .expect("destroy rootless administrator sandbox");
    cleanup.disarm();
    assert!(
        !scratch.path().join("workspaces").exists()
            || std::fs::read_dir(scratch.path().join("workspaces"))
                .expect("workspace root")
                .next()
                .is_none()
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires explicitly enabled rootless Podman and a local digest-pinned profile image"]
fn opt_in_hosted_profile_exposes_pinned_libclang_to_bindgen() {
    let image = live_image();
    let scratch = ScratchRoot::new("live-libclang-profile");
    let (options, _, _) = live_options(scratch.path());
    let provider = RootlessPodmanProvider::open(options).expect("open live provider");
    let generation = SandboxGeneration::new(1).expect("generation");
    let spec = live_spec(OperationId::new(), generation, image);
    let created = provider
        .create(&spec, &NeverCancelled)
        .expect("create hosted-profile sandbox");
    let mut cleanup = SandboxCleanup::new(
        provider.clone(),
        created.handle().clone(),
        generation,
        spec.custody(),
    );
    let endpoint = provider
        .attach(created.handle(), &NeverCancelled)
        .expect("attach hosted-profile sandbox");
    let script = format!(
        r#"set -eu
test -z "${{LIBCLANG_PATH:-}}${{BINDGEN_EXTRA_CLANG_ARGS:-}}"
version="$(dpkg-query --show --showformat='${{Version}}' libclang1-18)"
test "$version" = "{CLANG_PACKAGE_VERSION}"
version="$(dpkg-query --show --showformat='${{Version}}' clang-18)"
test "$version" = "{CLANG_PACKAGE_VERSION}"
resource_directory="$(clang-18 --print-resource-dir)"
test "$resource_directory" = /usr/lib/llvm-18/lib/clang/18
test -r "$resource_directory/include/stddef.h"
library=/usr/lib/x86_64-linux-gnu/libclang-18.so.18
test -r "$library"
python3 -c 'import ctypes, sys; getattr(ctypes.CDLL(sys.argv[1]), "clang_getClangVersion")' "$library"
printf 'libclang-profile-ok\n'
"#
    );
    let output = endpoint
        .exec(
            &command("/usr/bin/bash", vec!["-c".to_owned(), script], 10),
            &NeverCancelled,
        )
        .expect("execute libclang profile contract");
    assert_eq!(
        output.termination(),
        ExecutionTermination::Exited(0),
        "libclang profile contract failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(output.stdout()),
        String::from_utf8_lossy(output.stderr()),
    );
    assert_eq!(output.stdout(), b"libclang-profile-ok\n");

    provider
        .destroy(
            &DestroySandbox::new(
                OperationId::new(),
                created.handle().clone(),
                generation,
                spec.custody(),
            ),
            &NeverCancelled,
        )
        .expect("destroy hosted-profile sandbox");
    cleanup.disarm();
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires explicitly enabled rootless Podman, the Git bridge, and a local profile image"]
fn opt_in_host_gateway_alias_reaches_local_git_without_a_host_socket() {
    let image = live_image();
    let scratch = ScratchRoot::new("live-host-gateway-alias");
    let (options, _, _) = live_options(scratch.path());
    let alias = PodmanHostGatewayAlias::new("automata-git.ghe.com", 8088).expect("valid alias");
    let provider = RootlessPodmanProvider::open(
        options
            .with_host_gateway_alias(alias)
            .expect("host gateway configuration"),
    )
    .expect("open live provider with explicit host alias");
    let generation = SandboxGeneration::new(1).expect("generation");
    let spec = live_spec_with_network(
        OperationId::new(),
        generation,
        image,
        NetworkPolicy::PrivateEgress,
    );
    let created = provider
        .create(&spec, &NeverCancelled)
        .expect("create host-alias sandbox");
    let mut cleanup = SandboxCleanup::new(
        provider.clone(),
        created.handle().clone(),
        generation,
        spec.custody(),
    );
    let endpoint = provider
        .attach(created.handle(), &NeverCancelled)
        .expect("attach host-alias sandbox");
    let ls_remote = command(
        "/usr/bin/git",
        vec![
            "ls-remote".to_owned(),
            "http://automata-git.ghe.com:8088/automata-ci/automata".to_owned(),
        ],
        20,
    );
    let output = endpoint
        .exec(&ls_remote, &NeverCancelled)
        .expect("execute git ls-remote through mapped host alias");
    assert_eq!(
        output.termination(),
        ExecutionTermination::Exited(0),
        "git ls-remote failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(output.stdout()),
        String::from_utf8_lossy(output.stderr()),
    );
    assert!(contains_bytes(output.stdout(), b"refs/heads/main"));

    provider
        .destroy(
            &DestroySandbox::new(
                OperationId::new(),
                created.handle().clone(),
                generation,
                spec.custody(),
            ),
            &NeverCancelled,
        )
        .expect("destroy host-alias sandbox");
    cleanup.disarm();
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires explicitly enabled rootless Podman and a local Docker-CLI profile image"]
fn opt_in_attempt_scoped_docker_api_runs_the_distribution_command_surface() {
    let image = live_image();
    let scratch = ScratchRoot::new("live-attempt-docker-api");
    let helper = compile_static_http_fixture(scratch.path());
    let (options, _, _) = live_options(scratch.path());
    let provider = RootlessPodmanProvider::open(
        options.with_job_container_engine(JobContainerEngine::AttemptScopedDockerApi),
    )
    .expect("open Docker-compatible live provider");
    let operation_id = OperationId::new();
    let generation = SandboxGeneration::new(1).expect("generation");
    let spec = live_spec(operation_id, generation, image)
        .with_root_filesystem(RootFilesystemPolicy::Writable)
        .with_privilege(SandboxPrivilegePolicy::Administrator);
    let created = match provider.create(&spec, &NeverCancelled) {
        Ok(created) => created,
        Err(error) => {
            if let Some(handle) = error.recovery_handle() {
                let _ignored = provider.destroy(
                    &DestroySandbox::new(
                        OperationId::new(),
                        handle.clone(),
                        generation,
                        spec.custody(),
                    ),
                    &NeverCancelled,
                );
            }
            panic!("create sandbox with attempt-scoped Docker API: {error}");
        }
    };
    let mut cleanup = SandboxCleanup::new(
        provider.clone(),
        created.handle().clone(),
        generation,
        spec.custody(),
    );
    let endpoint = provider
        .attach(created.handle(), &NeverCancelled)
        .expect("attach Docker-compatible sandbox");
    install_docker_live_fixture(endpoint.as_ref(), &helper);
    let execute = docker_distribution_surface_command();
    let output = endpoint
        .exec(&execute, &NeverCancelled)
        .expect("execute Docker-compatible live command");
    assert_eq!(
        output.termination(),
        ExecutionTermination::Exited(0),
        "Docker compatibility command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(output.stdout()),
        String::from_utf8_lossy(output.stderr()),
    );
    assert!(contains_bytes(
        output.stdout(),
        b"attempt-scoped-docker-ok\n"
    ));

    provider
        .destroy(
            &DestroySandbox::new(
                OperationId::new(),
                created.handle().clone(),
                generation,
                spec.custody(),
            ),
            &NeverCancelled,
        )
        .expect("destroy Docker-compatible sandbox");
    cleanup.disarm();
    assert_job_engines_removed(scratch.path());
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the explicit Buildx live gate and local digest-pinned profile/BuildKit images"]
fn opt_in_attempt_scoped_buildx_runs_the_pinned_buildkit_container_driver() {
    require_live_enable();
    if std::env::var(LIVE_BUILDKIT_ENABLE).as_deref() != Ok("1") {
        return;
    }
    let image = live_image();
    let scratch = ScratchRoot::new("live-attempt-buildx");
    let (options, _, _) = live_options(scratch.path());
    let provider = RootlessPodmanProvider::open(
        options
            .with_job_container_engine(JobContainerEngine::AttemptScopedDockerApi)
            .with_buildkit_runtime(BuildKitRuntime::new(live_buildkit_image())),
    )
    .expect("open BuildKit-compatible live provider");
    let generation = SandboxGeneration::new(1).expect("generation");
    let spec = live_spec_with_network(
        OperationId::new(),
        generation,
        image,
        NetworkPolicy::PrivateEgress,
    )
    .with_root_filesystem(RootFilesystemPolicy::Writable)
    .with_privilege(SandboxPrivilegePolicy::Administrator);
    let created = match provider.create(&spec, &NeverCancelled) {
        Ok(created) => created,
        Err(error) => {
            if let Some(handle) = error.recovery_handle() {
                let _ignored = provider.destroy(
                    &DestroySandbox::new(
                        OperationId::new(),
                        handle.clone(),
                        generation,
                        spec.custody(),
                    ),
                    &NeverCancelled,
                );
            }
            panic!("create sandbox with attempt-scoped BuildKit API: {error}");
        }
    };
    let mut cleanup = SandboxCleanup::new(
        provider.clone(),
        created.handle().clone(),
        generation,
        spec.custody(),
    );
    let endpoint = provider
        .attach(created.handle(), &NeverCancelled)
        .expect("attach BuildKit-compatible sandbox");
    install_buildx_live_fixture(endpoint.as_ref());
    let execute = buildx_live_command();
    let output = endpoint
        .exec(&execute, &NeverCancelled)
        .expect("execute Buildx live command");
    assert_eq!(
        output.termination(),
        ExecutionTermination::Exited(0),
        "Buildx compatibility command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(output.stdout()),
        String::from_utf8_lossy(output.stderr()),
    );
    assert!(contains_bytes(
        output.stdout(),
        b"attempt-scoped-buildx-ok\n"
    ));

    provider
        .destroy(
            &DestroySandbox::new(
                OperationId::new(),
                created.handle().clone(),
                generation,
                spec.custody(),
            ),
            &NeverCancelled,
        )
        .expect("destroy BuildKit-compatible sandbox");
    cleanup.disarm();
    assert_job_engines_removed(scratch.path());
}

fn install_buildx_live_fixture(endpoint: &dyn automata_ci_execution::ExecutionEndpoint) {
    for (target, content) in [
        (
            "/__w/Buildxfile",
            b"FROM scratch\nCOPY buildx-payload /payload\n".as_slice(),
        ),
        ("/__w/buildx-payload", b"neutral-buildx-live\n".as_slice()),
    ] {
        endpoint
            .copy_to(
                &CopyToRequest::new(
                    OperationId::new(),
                    TargetPath::posix(target).expect("Buildx fixture target"),
                    content.to_vec(),
                )
                .expect("Buildx fixture copy request"),
                &NeverCancelled,
            )
            .expect("copy Buildx fixture");
    }
}

fn buildx_live_command() -> ExecutionCommand {
    let script = r#"
set -euo pipefail
builder=neutral-live
export DOCKER_CONFIG=/__w/.docker-buildx-live
mkdir -p "$DOCKER_CONFIG"
docker buildx create \
  --name "$builder" \
  --driver docker-container \
  --buildkitd-flags '--allow-insecure-entitlement security.insecure --allow-insecure-entitlement network.host' \
  --use >/dev/null
cleanup() { docker buildx rm --force "$builder" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker buildx inspect --bootstrap "$builder" >/dev/null
rm -rf /__w/buildx-output
docker buildx build \
  --builder "$builder" \
  --file /__w/Buildxfile \
  --progress plain \
  --output type=local,dest=/__w/buildx-output \
  /__w
test "$(cat /__w/buildx-output/payload)" = neutral-buildx-live
docker buildx rm --force "$builder" >/dev/null
trap - EXIT
printf 'attempt-scoped-buildx-ok\n'
"#;
    let environment = ExecutionEnvironment::new(vec![
        environment_variable("HOME", "/root"),
        environment_variable(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ),
    ])
    .expect("Buildx live environment");
    ExecutionCommand::new(
        OperationId::new(),
        ExecutionArgv::new(
            TargetPath::posix("/usr/bin/bash").expect("bash"),
            vec!["-c".to_owned(), script.to_owned()],
        )
        .expect("Buildx live argv"),
        TargetPath::posix("/__w").expect("workspace"),
        environment,
        Duration::from_mins(5),
        2 * 1024 * 1024,
    )
    .expect("Buildx live command")
}

fn live_image() -> String {
    require_live_enable();
    std::env::var(LIVE_IMAGE)
        .expect("ignored rootless Podman tests require a local digest-pinned profile image")
}

fn live_buildkit_image() -> ImmutableImage {
    ImmutableImage::new(
        std::env::var(LIVE_BUILDKIT_IMAGE)
            .expect("Buildx live test requires a local digest-pinned BuildKit image"),
    )
    .expect("live BuildKit image must be digest-pinned")
}

fn assert_job_engines_removed(root: &Path) {
    let engines = root.join("job-engines");
    assert!(
        !engines.exists()
            || std::fs::read_dir(engines)
                .expect("job engine root")
                .next()
                .is_none()
    );
}

fn require_live_enable() {
    assert_eq!(
        std::env::var(LIVE_ENABLE).as_deref(),
        Ok("1"),
        "ignored rootless Podman tests require {LIVE_ENABLE}=1"
    );
}

fn live_service_image() -> String {
    std::env::var(LIVE_SERVICE_IMAGE).expect(
        "ignored rootless Podman service test requires a local digest-pinned, long-running service image",
    )
}

fn live_service_proxy_image() -> ImmutableImage {
    ImmutableImage::new(std::env::var(LIVE_SERVICE_PROXY_IMAGE).expect(
        "ignored rootless Podman service test requires a local digest-pinned service-proxy image",
    ))
    .expect("service-proxy image must be digest-pinned")
}

fn install_docker_live_fixture(
    endpoint: &dyn automata_ci_execution::ExecutionEndpoint,
    helper: &Path,
) {
    let helper_bytes = std::fs::read(helper).expect("read compiled static HTTP fixture");
    endpoint
        .copy_to(
            &CopyToRequest::new(
                OperationId::new(),
                TargetPath::posix("/__w/static-http-server").expect("helper target"),
                helper_bytes,
            )
            .expect("helper copy request"),
            &NeverCancelled,
        )
        .expect("copy static HTTP fixture");
    endpoint
        .copy_to(
            &CopyToRequest::new(
                OperationId::new(),
                TargetPath::posix("/__w/Containerfile").expect("Containerfile target"),
                b"FROM scratch\nCOPY static-http-server /server\nENTRYPOINT [\"/server\"]\n"
                    .to_vec(),
            )
            .expect("Containerfile copy request"),
            &NeverCancelled,
        )
        .expect("copy Containerfile");
}

fn docker_distribution_surface_command() -> ExecutionCommand {
    let environment = ExecutionEnvironment::new(vec![
        environment_variable("HOME", "/root"),
        environment_variable(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ),
    ])
    .expect("Docker live environment");
    ExecutionCommand::new(
        OperationId::new(),
        ExecutionArgv::new(
            TargetPath::posix("/usr/bin/bash").expect("bash"),
            vec!["-c".to_owned(), DOCKER_DISTRIBUTION_SURFACE.to_owned()],
        )
        .expect("Docker live argv"),
        TargetPath::posix("/__w").expect("workspace"),
        environment,
        Duration::from_mins(2),
        1024 * 1024,
    )
    .expect("Docker live command")
}

fn compile_static_http_fixture(scratch: &Path) -> PathBuf {
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/static_http_server.rs");
    let output = scratch.join("static-http-fixture");
    let status = std::process::Command::new("rustc")
        .arg("--edition=2024")
        .arg("--target=x86_64-unknown-linux-musl")
        .arg("-Copt-level=s")
        .arg("-Cstrip=symbols")
        .arg("-o")
        .arg(&output)
        .arg(source)
        .env("TMPDIR", scratch)
        .status()
        .expect("run rustc for static live fixture");
    assert!(status.success(), "compile static live fixture");
    output
}

fn assert_live_environment(endpoint: &dyn automata_ci_execution::ExecutionEndpoint) {
    let environment_command = |environment| {
        ExecutionCommand::new(
            OperationId::new(),
            ExecutionArgv::new(
                TargetPath::posix("/usr/bin/env").expect("env program"),
                Vec::new(),
            )
            .expect("env argv"),
            TargetPath::posix("/__w").expect("working directory"),
            environment,
            Duration::from_secs(5),
            64 * 1024,
        )
        .expect("environment command")
    };
    let job_environment = ExecutionEnvironment::new(vec![
        environment_variable("AUTOMATA_EXACT", "first=second # literal"),
        environment_variable("AUTOMATA_EMPTY", ""),
        environment_variable("HOME", "/__w/_home"),
        environment_variable("PATH", "/automata/tools:/usr/bin"),
    ])
    .expect("live environment");
    let print_environment = environment_command(job_environment);
    let output = endpoint
        .exec(&print_environment, &NeverCancelled)
        .expect("live environment exec");
    assert!(contains_bytes(
        output.stdout(),
        b"AUTOMATA_EXACT=first=second # literal\n"
    ));
    assert!(contains_bytes(output.stdout(), b"AUTOMATA_EMPTY=\n"));
    assert!(contains_bytes(output.stdout(), b"HOME=/__w/_home\n"));
    assert!(contains_bytes(
        output.stdout(),
        b"PATH=/automata/tools:/usr/bin\n"
    ));

    let multiline = ExecutionEnvironment::new(vec![environment_variable(
        "AUTOMATA_MULTILINE",
        "first\nsecond",
    )])
    .expect("core-valid multiline environment");
    let error = endpoint
        .exec(&environment_command(multiline), &NeverCancelled)
        .expect_err("Podman environment documents reject multiline values");
    assert_eq!(error.kind(), ExecutionErrorKind::InvalidEnvironment);
}

fn assert_live_copy(endpoint: &dyn automata_ci_execution::ExecutionEndpoint, state_root: &Path) {
    let copy_path = TargetPath::posix("/__w/automata-copy-contract").expect("copy path");
    let copy_content = b"automata-copy\nexact-bytes\0supported".to_vec();
    endpoint
        .copy_to(
            &CopyToRequest::new(OperationId::new(), copy_path.clone(), copy_content.clone())
                .expect("copy-to request"),
            &NeverCancelled,
        )
        .expect("live copy to");
    let copied = endpoint
        .copy_from(
            &CopyFromRequest::new(OperationId::new(), copy_path, 64 * 1024)
                .expect("copy-from request"),
            &NeverCancelled,
        )
        .expect("live copy from");
    assert_eq!(copied, copy_content);
    assert!(!state_root.join("transfers").exists());
}

fn assert_live_cancellation(endpoint: &dyn automata_ci_execution::ExecutionEndpoint) {
    let cancellation = Arc::new(AtomicCancellation::default());
    let trigger = Arc::clone(&cancellation);
    let worker = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        trigger.0.store(true, Ordering::Release);
    });
    let sleep = command("/bin/sleep", vec!["30".to_owned()], 10);
    let interrupted = endpoint
        .exec(&sleep, cancellation.as_ref())
        .expect("cancelled live exec is a terminal output");
    worker.join().expect("cancellation trigger");
    assert_eq!(interrupted.termination(), ExecutionTermination::Cancelled);
}

#[derive(Debug)]
struct SandboxCleanup {
    provider: RootlessPodmanProvider,
    handle: Option<automata_ci_execution::SandboxHandle>,
    generation: SandboxGeneration,
    custody: SandboxCustody,
}

impl SandboxCleanup {
    fn new(
        provider: RootlessPodmanProvider,
        handle: automata_ci_execution::SandboxHandle,
        generation: SandboxGeneration,
        custody: SandboxCustody,
    ) -> Self {
        Self {
            provider,
            handle: Some(handle),
            generation,
            custody,
        }
    }

    fn disarm(&mut self) {
        self.handle = None;
    }
}

impl Drop for SandboxCleanup {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ignored = self.provider.destroy(
                &DestroySandbox::new(OperationId::new(), handle, self.generation, self.custody),
                &NeverCancelled,
            );
        }
    }
}

fn live_options(root: &Path) -> (PodmanOptions, PodmanProcessEnvironment, PodmanBinary) {
    let binary_path = ["/usr/bin/podman", "/bin/podman"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .expect("Podman executable is required by the opt-in live test");
    let binary = PodmanBinary::new(binary_path).expect("Podman binary path");
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .expect("live rootless Podman requires explicit HOME");
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .expect("live rootless Podman requires explicit XDG_RUNTIME_DIR");
    let helper_directory = std::env::var_os("AUTOMATA_PODMAN_APPROVED_HELPERS")
        .map(PathBuf::from)
        .expect("live test requires an approved helper directory");
    let environment = PodmanProcessEnvironment::new(
        home,
        runtime,
        root,
        helper_directory,
        "/usr/bin/conmon",
        "/usr/bin/crun",
        "/usr/bin/catatonit",
        "/usr/share/containers/seccomp.json",
    )
    .expect("explicit live process environment");
    let state = PodmanStateRoot::existing(root).expect("live state root");
    let options = PodmanOptions::new(binary.clone(), state, environment)
        .expect("coherent live Podman options")
        .with_launch_trust(PodmanLaunchTrustHandle::new(Arc::new(LiveLaunchTrust)));
    let environment = options.process_environment().clone();
    (options, environment, binary)
}

fn live_spec(
    operation_id: OperationId,
    generation: SandboxGeneration,
    image: String,
) -> SandboxSpec {
    live_spec_with_network(operation_id, generation, image, NetworkPolicy::Disabled)
}

fn live_spec_with_network(
    operation_id: OperationId,
    generation: SandboxGeneration,
    image: String,
    network: NetworkPolicy,
) -> SandboxSpec {
    let profile = SandboxEnvironment::new(
        EnvironmentProfile::new(
            EnvironmentProfileId::new("automata.dev/live-linux-rootless-v1").expect("profile id"),
            Sha256Digest::from_bytes([0x22; 32]),
        ),
        ImmutableImage::new(image).expect("digest-pinned live image"),
        ExecutionArgv::new(
            TargetPath::posix("/bin/sleep").expect("keepalive"),
            vec!["infinity".to_owned()],
        )
        .expect("keepalive argv"),
        TargetPath::posix("/__w").expect("workspace"),
        ExecutionEnvironment::empty(),
    )
    .expect("live profile");
    SandboxSpec::new(
        operation_id,
        generation,
        SandboxCustody::ProfileAdmission {
            runner_id: RunnerId::new(),
        },
        profile,
        TargetPath::posix("/__w").expect("workspace"),
        network,
        RootFilesystemPolicy::ReadOnly,
        ResourceLimits::new(512 * 1024 * 1024, 1_000, 256).expect("resources"),
    )
}

fn command(program: &str, arguments: Vec<String>, timeout_seconds: u64) -> ExecutionCommand {
    ExecutionCommand::new(
        OperationId::new(),
        ExecutionArgv::new(TargetPath::posix(program).expect("program"), arguments).expect("argv"),
        TargetPath::posix("/__w").expect("working directory"),
        ExecutionEnvironment::empty(),
        Duration::from_secs(timeout_seconds),
        64 * 1024,
    )
    .expect("execution command")
}

fn environment_variable(name: &str, value: &str) -> EnvironmentVariable {
    EnvironmentVariable::new(
        EnvironmentName::new(name).expect("environment name"),
        EnvironmentValue::new(value).expect("environment value"),
    )
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn assert_no_resources(
    binary: &PodmanBinary,
    environment: &PodmanProcessEnvironment,
    base_arguments: &[OsString],
    arguments: Vec<&str>,
) {
    let mut command = base_arguments.to_vec();
    command.extend(arguments.into_iter().map(OsString::from));
    let request = CommandRequest::new(
        binary.as_path().to_path_buf(),
        command,
        Duration::from_secs(30),
        Instant::now() + Duration::from_secs(30),
        64 * 1024,
    );
    let output = SystemCommandExecutor.execute(&request, environment, &NeverCancelled);
    assert_eq!(output.termination(), CommandTermination::Exited(Some(0)));
    assert!(output.stdout().iter().all(u8::is_ascii_whitespace));
}
