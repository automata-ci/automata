#![cfg(target_os = "linux")]

mod support;

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use automata_execution::{
    Cancellation, CopyFromRequest, CopyToRequest, DestroySandbox, EnvironmentName,
    EnvironmentProfile, EnvironmentProfileId, EnvironmentValue, EnvironmentVariable, ExecutionArgv,
    ExecutionCommand, ExecutionEnvironment, ExecutionTermination, ImmutableImage, NetworkPolicy,
    NeverCancelled, OperationId, ProviderErrorKind, ResourceLimits, RootFilesystemPolicy,
    SandboxEnvironment, SandboxGeneration, SandboxPrivilegePolicy, SandboxProvider, SandboxSpec,
    Sha256Digest, TargetPath,
};
use automata_sandbox_podman::{
    CommandRequest, CommandTermination, JobContainerEngine, PodmanBinary, PodmanCommandExecutor,
    PodmanHostGatewayAlias, PodmanOptions, PodmanProcessEnvironment, PodmanStateRoot,
    RootlessPodmanProvider, SystemCommandExecutor,
};

use support::ScratchRoot;

const LIVE_ENABLE: &str = "AUTOMATA_LIVE_ROOTLESS_PODMAN";
const LIVE_IMAGE: &str = "AUTOMATA_PODMAN_TEST_IMAGE";
const CLANG_PACKAGE_VERSION: &str = "1:18.1.3-1ubuntu1";
const DOCKER_DISTRIBUTION_SURFACE: &str = r#"
set -euo pipefail
chmod 0555 /__w/static-http-server
image=automata-docker-live:one
container=automata-docker-live-one
docker build --quiet --file /__w/Containerfile --tag "$image" /__w
test "$(docker run --rm --entrypoint /server "$image" --version)" = "automata-docker-live 1"
docker run --detach --name "$container" --publish 127.0.0.1::8080/tcp "$image" >/dev/null
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
    fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[cfg(target_os = "linux")]
#[test]
fn opt_in_rootless_contract_leaves_no_owned_resources() {
    if std::env::var(LIVE_ENABLE).as_deref() != Ok("1") {
        return;
    }
    let image = std::env::var(LIVE_IMAGE)
        .expect("opt-in live test requires an already-local digest-pinned image");
    let scratch = ScratchRoot::new("live-rootless");
    let (options, environment, binary) = live_options(scratch.path());
    let provider = RootlessPodmanProvider::open(options).expect("open live provider");
    let operation_id = OperationId::new();
    let generation = SandboxGeneration::new(1).expect("generation");
    let spec = live_spec(operation_id, generation, image);

    let created = match provider.create(&spec, &NeverCancelled) {
        Ok(created) => created,
        Err(error) => {
            if let Some(handle) = error.recovery_handle() {
                let _ignored = provider.destroy(
                    &DestroySandbox::new(OperationId::new(), handle.clone(), generation),
                    &NeverCancelled,
                );
            }
            panic!("create live sandbox: {error}");
        }
    };
    let mut cleanup = SandboxCleanup::new(provider.clone(), created.handle().clone(), generation);
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
            &DestroySandbox::new(OperationId::new(), created.handle().clone(), generation),
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
        assert_no_resources(&binary, &environment, scratch.path(), arguments);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn opt_in_rootless_administrator_is_confined_and_writable() {
    if std::env::var(LIVE_ENABLE).as_deref() != Ok("1") {
        return;
    }
    let image = std::env::var(LIVE_IMAGE)
        .expect("opt-in live test requires an already-local digest-pinned image");
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
    let mut cleanup = SandboxCleanup::new(provider.clone(), created.handle().clone(), generation);
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
            &DestroySandbox::new(OperationId::new(), created.handle().clone(), generation),
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
fn opt_in_hosted_profile_exposes_pinned_libclang_to_bindgen() {
    if std::env::var(LIVE_ENABLE).as_deref() != Ok("1") {
        return;
    }
    let image = std::env::var(LIVE_IMAGE)
        .expect("opt-in live test requires the hosted profile image pinned by digest");
    let scratch = ScratchRoot::new("live-libclang-profile");
    let (options, _, _) = live_options(scratch.path());
    let provider = RootlessPodmanProvider::open(options).expect("open live provider");
    let generation = SandboxGeneration::new(1).expect("generation");
    let spec = live_spec(OperationId::new(), generation, image);
    let created = provider
        .create(&spec, &NeverCancelled)
        .expect("create hosted-profile sandbox");
    let mut cleanup = SandboxCleanup::new(provider.clone(), created.handle().clone(), generation);
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
            &DestroySandbox::new(OperationId::new(), created.handle().clone(), generation),
            &NeverCancelled,
        )
        .expect("destroy hosted-profile sandbox");
    cleanup.disarm();
}

#[cfg(target_os = "linux")]
#[test]
fn opt_in_host_gateway_alias_reaches_local_git_without_a_host_socket() {
    if std::env::var(LIVE_ENABLE).as_deref() != Ok("1") {
        return;
    }
    let image = std::env::var(LIVE_IMAGE)
        .expect("opt-in live test requires the checkout-capable profile image pinned by digest");
    let scratch = ScratchRoot::new("live-host-gateway-alias");
    let (options, _, _) = live_options(scratch.path());
    let alias = PodmanHostGatewayAlias::new("automata-git.ghe.com").expect("valid alias");
    let provider = RootlessPodmanProvider::open(options.with_host_gateway_alias(alias))
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
    let mut cleanup = SandboxCleanup::new(provider.clone(), created.handle().clone(), generation);
    let endpoint = provider
        .attach(created.handle(), &NeverCancelled)
        .expect("attach host-alias sandbox");
    let ls_remote = command(
        "/usr/bin/git",
        vec![
            "ls-remote".to_owned(),
            "http://automata-git.ghe.com:8088/GoNeuralAI/automata".to_owned(),
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
            &DestroySandbox::new(OperationId::new(), created.handle().clone(), generation),
            &NeverCancelled,
        )
        .expect("destroy host-alias sandbox");
    cleanup.disarm();
}

#[cfg(target_os = "linux")]
#[test]
fn opt_in_attempt_scoped_docker_api_runs_the_distribution_command_surface() {
    if std::env::var(LIVE_ENABLE).as_deref() != Ok("1") {
        return;
    }
    let image = std::env::var(LIVE_IMAGE)
        .expect("opt-in live test requires the Docker-CLI profile image pinned by digest");
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
                    &DestroySandbox::new(OperationId::new(), handle.clone(), generation),
                    &NeverCancelled,
                );
            }
            panic!("create sandbox with attempt-scoped Docker API: {error}");
        }
    };
    let mut cleanup = SandboxCleanup::new(provider.clone(), created.handle().clone(), generation);
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
            &DestroySandbox::new(OperationId::new(), created.handle().clone(), generation),
            &NeverCancelled,
        )
        .expect("destroy Docker-compatible sandbox");
    cleanup.disarm();
    assert!(
        !scratch.path().join("job-engines").exists()
            || std::fs::read_dir(scratch.path().join("job-engines"))
                .expect("job engine root")
                .next()
                .is_none()
    );
}

fn install_docker_live_fixture(
    endpoint: &dyn automata_execution::ExecutionEndpoint,
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
    let source =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/static_http_server.rs");
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

fn assert_live_environment(endpoint: &dyn automata_execution::ExecutionEndpoint) {
    let job_environment = ExecutionEnvironment::new(vec![
        environment_variable("AUTOMATA_MULTILINE", "first\nsecond"),
        environment_variable("AUTOMATA_EMPTY", ""),
        environment_variable("HOME", "/__w/_home"),
        environment_variable("PATH", "/automata/tools:/usr/bin"),
    ])
    .expect("live environment");
    let print_environment = ExecutionCommand::new(
        OperationId::new(),
        ExecutionArgv::new(
            TargetPath::posix("/usr/bin/env").expect("env program"),
            Vec::new(),
        )
        .expect("env argv"),
        TargetPath::posix("/__w").expect("working directory"),
        job_environment,
        Duration::from_secs(5),
        64 * 1024,
    )
    .expect("environment command");
    let output = endpoint
        .exec(&print_environment, &NeverCancelled)
        .expect("live environment exec");
    assert!(contains_bytes(
        output.stdout(),
        b"AUTOMATA_MULTILINE=first\nsecond\n"
    ));
    assert!(contains_bytes(output.stdout(), b"AUTOMATA_EMPTY=\n"));
    assert!(contains_bytes(output.stdout(), b"HOME=/__w/_home\n"));
    assert!(contains_bytes(
        output.stdout(),
        b"PATH=/automata/tools:/usr/bin\n"
    ));
}

fn assert_live_copy(endpoint: &dyn automata_execution::ExecutionEndpoint, state_root: &Path) {
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
    assert!(
        std::fs::read_dir(state_root.join("transfers"))
            .expect("transfer staging")
            .next()
            .is_none()
    );
}

fn assert_live_cancellation(endpoint: &dyn automata_execution::ExecutionEndpoint) {
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
    handle: Option<automata_execution::SandboxHandle>,
    generation: SandboxGeneration,
}

impl SandboxCleanup {
    fn new(
        provider: RootlessPodmanProvider,
        handle: automata_execution::SandboxHandle,
        generation: SandboxGeneration,
    ) -> Self {
        Self {
            provider,
            handle: Some(handle),
            generation,
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
                &DestroySandbox::new(OperationId::new(), handle, self.generation),
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
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    let environment = PodmanProcessEnvironment::new(
        home,
        runtime,
        OsString::from("/usr/local/sbin:/usr/local/bin:/usr/bin:/bin"),
    )
    .expect("explicit live process environment");
    let state = PodmanStateRoot::existing(root).expect("live state root");
    let options = PodmanOptions::new(binary.clone(), state, environment);
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
    state_root: &Path,
    arguments: Vec<&str>,
) {
    let mut command = vec![
        OsString::from("--remote=false"),
        format!("--hooks-dir={}", state_root.join("empty-hooks").display()).into(),
    ];
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
