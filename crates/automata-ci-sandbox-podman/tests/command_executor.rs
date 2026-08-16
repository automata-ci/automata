#![cfg(target_os = "linux")]

use crate::support;

use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    os::unix::fs::{PermissionsExt as _, symlink},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use automata_ci_execution::{Cancellation, ExecutionOutputStream, NeverCancelled};
use automata_ci_sandbox_podman::{
    CommandRequest, CommandTermination, PodmanBinary, PodmanCommandExecutor, PodmanLaunchTrust,
    PodmanLaunchTrustHandle, PodmanOptions, PodmanProcessEnvironment, PodmanStateRoot,
    SystemCommandExecutor,
};

use support::ScratchRoot;

#[derive(Debug, Default)]
struct AtomicCancellation(AtomicBool);

impl AtomicCancellation {
    fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
}

impl Cancellation for AtomicCancellation {
    fn disposition(&self) -> automata_ci_execution::CancellationDisposition {
        if self.0.load(Ordering::Acquire) {
            automata_ci_execution::CancellationDisposition::Terminate
        } else {
            automata_ci_execution::CancellationDisposition::Active
        }
    }
}

#[derive(Debug)]
struct TestTrust(Arc<AtomicBool>);

impl PodmanLaunchTrust for TestTrust {
    fn revalidate(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[cfg(unix)]
#[test]
fn system_executor_cancels_and_reaps_without_a_shell() {
    let scratch = ScratchRoot::new("command-cancel");
    let environment = environment(scratch.path());
    let cancellation = Arc::new(AtomicCancellation::default());
    let trigger = Arc::clone(&cancellation);
    let worker = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        trigger.cancel();
    });
    let now = Instant::now();
    let request = CommandRequest::new(
        executable(&["/usr/bin/sleep", "/bin/sleep"]),
        vec![OsString::from("30")],
        Duration::from_secs(5),
        now + Duration::from_secs(5),
        1_024,
    );

    let output = SystemCommandExecutor.execute(&request, &environment, cancellation.as_ref());
    worker.join().expect("cancellation trigger");

    assert_eq!(output.termination(), CommandTermination::Cancelled);
    assert!(now.elapsed() < Duration::from_secs(2));
}

#[cfg(unix)]
#[test]
fn system_executor_kills_descendants_before_reaping_an_exited_leader() {
    let scratch = ScratchRoot::new("command-leader-exit");
    let environment = environment(scratch.path());
    let pid_file = scratch.path().join("descendant.pid");
    let request = CommandRequest::new(
        executable(&["/bin/sh", "/usr/bin/sh"]),
        vec![
            OsString::from("-c"),
            OsString::from("sleep 30 & printf '%s\\n' \"$!\" > \"$1\"; exit 23"),
            OsString::from("automata-command-leader-exit-test"),
            pid_file.as_os_str().to_owned(),
        ],
        Duration::from_secs(5),
        Instant::now() + Duration::from_secs(5),
        1_024,
    );

    let output = SystemCommandExecutor.execute(&request, &environment, &NeverCancelled);

    assert_eq!(output.termination(), CommandTermination::Exited(Some(23)));
    assert_recorded_process_gone(&pid_file, "normal leader exit");
}

#[cfg(unix)]
#[test]
fn system_executor_cancellation_kills_the_full_process_group() {
    let scratch = ScratchRoot::new("command-group-cancel");
    let environment = environment(scratch.path());
    let pid_file = scratch.path().join("descendant.pid");
    let cancellation = Arc::new(AtomicCancellation::default());
    let trigger = Arc::clone(&cancellation);
    let trigger_pid_file = pid_file.clone();
    let worker = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !trigger_pid_file.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        trigger.cancel();
    });
    let request = CommandRequest::new(
        executable(&["/bin/sh", "/usr/bin/sh"]),
        vec![
            OsString::from("-c"),
            OsString::from("sleep 30 & printf '%s\\n' \"$!\" > \"$1\"; wait"),
            OsString::from("automata-command-group-cancel-test"),
            pid_file.as_os_str().to_owned(),
        ],
        Duration::from_secs(5),
        Instant::now() + Duration::from_secs(5),
        1_024,
    );

    let output = SystemCommandExecutor.execute(&request, &environment, cancellation.as_ref());
    worker.join().expect("cancellation trigger must finish");

    assert_eq!(output.termination(), CommandTermination::Cancelled);
    assert_recorded_process_gone(&pid_file, "cancellation");
}

#[cfg(unix)]
#[test]
fn output_is_bounded_across_process_streams_and_debug_is_redacted() {
    let scratch = ScratchRoot::new("command-output");
    let environment = environment(scratch.path());
    let payload = "sensitive-output".repeat(1_024);
    let request = CommandRequest::new(
        executable(&["/usr/bin/printf", "/bin/printf"]),
        vec![OsString::from("%s"), OsString::from(&payload)],
        Duration::from_secs(5),
        Instant::now() + Duration::from_secs(5),
        32,
    );

    let output = SystemCommandExecutor.execute(&request, &environment, &NeverCancelled);

    assert_eq!(output.termination(), CommandTermination::Exited(Some(0)));
    assert_eq!(output.stdout().len() + output.stderr().len(), 32);
    assert!(output.was_truncated());
    assert_ordered_records_reconstruct_split_output(&output);
    assert!(!format!("{request:?}").contains("sensitive-output"));
    assert!(!format!("{output:?}").contains("sensitive-output"));
}

#[cfg(unix)]
#[test]
fn exact_output_limit_is_complete_and_one_extra_byte_is_incomplete() {
    let scratch = ScratchRoot::new("command-output-boundary");
    let environment = environment(scratch.path());
    let exact = CommandRequest::new(
        executable(&["/usr/bin/printf", "/bin/printf"]),
        vec![OsString::from("%s"), OsString::from("12345678")],
        Duration::from_secs(5),
        Instant::now() + Duration::from_secs(5),
        8,
    );
    let one_over = CommandRequest::new(
        executable(&["/usr/bin/printf", "/bin/printf"]),
        vec![OsString::from("%s"), OsString::from("123456789")],
        Duration::from_secs(5),
        Instant::now() + Duration::from_secs(5),
        8,
    );

    let exact = SystemCommandExecutor.execute(&exact, &environment, &NeverCancelled);
    let one_over = SystemCommandExecutor.execute(&one_over, &environment, &NeverCancelled);

    assert_eq!(exact.stdout(), b"12345678");
    assert!(!exact.was_truncated());
    assert_ordered_records_reconstruct_split_output(&exact);
    assert_eq!(one_over.stdout(), b"12345678");
    assert!(one_over.was_truncated());
    assert_ordered_records_reconstruct_split_output(&one_over);
}

#[cfg(unix)]
#[test]
fn anonymous_stdin_is_exact_and_debug_redacted() {
    let scratch = ScratchRoot::new("command-stdin");
    let environment = environment(scratch.path());
    let payload = b"anonymous-stdin-secret\0exact".to_vec();
    let request = CommandRequest::new(
        executable(&["/usr/bin/cat", "/bin/cat"]),
        Vec::new(),
        Duration::from_secs(5),
        Instant::now() + Duration::from_secs(5),
        1_024,
    )
    .with_stdin(payload.clone());

    let output = SystemCommandExecutor.execute(&request, &environment, &NeverCancelled);

    assert_eq!(output.termination(), CommandTermination::Exited(Some(0)));
    assert!(output.stdin_was_fully_written());
    assert_eq!(output.stdout(), payload);
    assert!(!format!("{request:?}").contains("anonymous-stdin-secret"));
    assert!(!format!("{output:?}").contains("anonymous-stdin-secret"));
}

fn assert_ordered_records_reconstruct_split_output(
    output: &automata_ci_sandbox_podman::CommandOutput,
) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut stdout_ends = 0;
    let mut stderr_ends = 0;
    for record in output.records() {
        let (bytes, ends) = match record.stream() {
            ExecutionOutputStream::Stdout => (&mut stdout, &mut stdout_ends),
            ExecutionOutputStream::Stderr => (&mut stderr, &mut stderr_ends),
        };
        if record.is_end_of_stream() {
            *ends += 1;
        } else {
            assert_eq!(*ends, 0, "data cannot follow its stream EOF");
            bytes.extend_from_slice(record.bytes());
        }
    }
    assert_eq!(stdout_ends, 1);
    assert_eq!(stderr_ends, 1);
    assert_eq!(stdout, output.stdout());
    assert_eq!(stderr, output.stderr());
}

#[cfg(unix)]
#[test]
fn early_child_exit_reports_incomplete_stdin_without_deadlock() {
    let scratch = ScratchRoot::new("command-stdin-epipe");
    let environment = environment(scratch.path());
    let request = CommandRequest::new(
        executable(&["/usr/bin/true", "/bin/true"]),
        Vec::new(),
        Duration::from_secs(5),
        Instant::now() + Duration::from_secs(5),
        1_024,
    )
    .with_stdin(vec![0x53; 4 * 1024 * 1024]);
    let started = Instant::now();

    let output = SystemCommandExecutor.execute(&request, &environment, &NeverCancelled);

    assert_eq!(output.termination(), CommandTermination::Exited(Some(0)));
    assert!(!output.stdin_was_fully_written());
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[cfg(unix)]
#[test]
fn blocked_stdin_honors_cancellation_and_timeout_without_deadlock() {
    let scratch = ScratchRoot::new("command-stdin-interrupt");
    let environment = environment(scratch.path());
    let cancellation = Arc::new(AtomicCancellation::default());
    let trigger = Arc::clone(&cancellation);
    let worker = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        trigger.cancel();
    });
    let request = CommandRequest::new(
        executable(&["/usr/bin/sleep", "/bin/sleep"]),
        vec![OsString::from("30")],
        Duration::from_secs(5),
        Instant::now() + Duration::from_secs(5),
        1_024,
    )
    .with_stdin(vec![0x43; 4 * 1024 * 1024]);
    let started = Instant::now();
    let cancelled = SystemCommandExecutor.execute(&request, &environment, cancellation.as_ref());
    worker.join().expect("cancellation trigger");
    assert_eq!(cancelled.termination(), CommandTermination::Cancelled);
    assert!(!cancelled.stdin_was_fully_written());
    assert!(started.elapsed() < Duration::from_secs(2));

    let request = CommandRequest::new(
        executable(&["/usr/bin/sleep", "/bin/sleep"]),
        vec![OsString::from("30")],
        Duration::from_millis(100),
        Instant::now() + Duration::from_millis(100),
        1_024,
    )
    .with_stdin(vec![0x54; 4 * 1024 * 1024]);
    let started = Instant::now();
    let timed_out = SystemCommandExecutor.execute(&request, &environment, &NeverCancelled);
    assert_eq!(timed_out.termination(), CommandTermination::TimedOut);
    assert!(!timed_out.stdin_was_fully_written());
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[cfg(unix)]
#[test]
fn process_environment_is_cleared_to_the_explicit_allowlist() {
    let scratch = ScratchRoot::new("command-environment");
    let environment = environment(scratch.path());
    let request = CommandRequest::new(
        executable(&["/usr/bin/env", "/bin/env"]),
        Vec::new(),
        Duration::from_secs(5),
        Instant::now() + Duration::from_secs(5),
        4_096,
    );

    let output = SystemCommandExecutor.execute(&request, &environment, &NeverCancelled);
    let values = std::str::from_utf8(output.stdout()).expect("environment output is UTF-8");
    let values = values
        .lines()
        .map(|line| line.split_once('=').expect("name-value environment entry"))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(output.termination(), CommandTermination::Exited(Some(0)));
    assert_eq!(
        values.keys().copied().collect::<Vec<_>>(),
        vec![
            "CONTAINERS_CONF",
            "CONTAINERS_POLICY_JSON",
            "CONTAINERS_REGISTRIES_CONF",
            "CONTAINERS_STORAGE_CONF",
            "DBUS_SESSION_BUS_ADDRESS",
            "DISABLE_HC_SYSTEMD",
            "HOME",
            "PATH",
            "REGISTRY_AUTH_FILE",
            "TMPDIR",
            "XDG_RUNTIME_DIR",
        ]
    );
    assert_eq!(
        values.get("PATH").copied(),
        Some(
            environment
                .approved_helper_directory()
                .to_str()
                .expect("text path")
        )
    );
    assert_eq!(values.get("DISABLE_HC_SYSTEMD"), Some(&"true"));
    assert_eq!(
        values.get("DBUS_SESSION_BUS_ADDRESS").copied(),
        Some(
            environment
                .dbus_session_bus_address()
                .to_str()
                .expect("text D-Bus address")
        )
    );
    assert!(!values.contains_key("TOKEN"));
    assert!(!values.contains_key("PROXY"));
}

#[test]
fn launch_validation_rejects_content_mode_links_and_nonempty_control_directories() {
    let scratch = ScratchRoot::new("command-launch-validation");
    let environment = environment(scratch.path());
    let storage = environment.storage_conf_path();
    let expected_storage = b"[storage]\ndriver = \"vfs\"\ntransient_store = false\n";

    fs::write(storage, b"tampered").expect("tamper storage configuration");
    assert!(environment.validate_launch().is_err());
    write_private(storage, expected_storage);

    fs::set_permissions(storage, fs::Permissions::from_mode(0o640))
        .expect("broaden storage configuration mode");
    assert!(environment.validate_launch().is_err());
    fs::set_permissions(storage, fs::Permissions::from_mode(0o600))
        .expect("restore storage configuration mode");

    let second_auth_link = scratch.path().join("second-auth-link");
    fs::hard_link(environment.auth_file_path(), &second_auth_link)
        .expect("create second authentication-file link");
    assert!(environment.validate_launch().is_err());
    fs::remove_file(second_auth_link).expect("remove second authentication-file link");

    let hook = environment.empty_hooks_directory().join("unexpected-hook");
    fs::write(&hook, b"hook").expect("create unexpected hook");
    assert!(environment.validate_launch().is_err());
    fs::remove_file(hook).expect("remove unexpected hook");

    fs::remove_file(environment.mounts_conf_path()).expect("remove mounts configuration");
    symlink("/dev/null", environment.mounts_conf_path())
        .expect("replace mounts configuration with symlink");
    assert!(environment.validate_launch().is_err());
}

#[test]
fn generated_containers_configuration_pins_the_conmon_path_environment() {
    let scratch = ScratchRoot::new("command-conmon-environment");
    let environment = environment(scratch.path());
    let expected = containers_conf_contents(&environment);

    assert_eq!(
        fs::read(environment.containers_conf_path()).expect("read exact containers configuration"),
        expected.as_bytes()
    );
    assert!(expected.contains(&format!(
        "conmon_env_vars = [\"PATH={}\"]\n",
        environment.approved_helper_directory().display()
    )));
}

#[test]
fn launch_validation_requires_a_live_external_trust_snapshot() {
    let missing_scratch = ScratchRoot::new("command-missing-launch-trust");
    let missing = untrusted_environment(missing_scratch.path());
    assert!(missing.validate_launch().is_err());

    let rejected_scratch = ScratchRoot::new("command-rejected-launch-trust");
    let rejected = environment_with_trust(rejected_scratch.path(), false);
    assert!(rejected.validate_launch().is_err());

    let admitted_scratch = ScratchRoot::new("command-admitted-launch-trust");
    let admitted_state = Arc::new(AtomicBool::new(true));
    let admitted =
        environment_with_trust_state(admitted_scratch.path(), Arc::clone(&admitted_state));
    admitted
        .validate_launch()
        .expect("live external trust snapshot");
    admitted_state.store(false, Ordering::Release);
    assert!(admitted.validate_launch().is_err());
}

#[test]
fn helper_path_must_itself_end_in_usr_sbin() {
    let scratch = ScratchRoot::new("command-helper-path");
    let result = PodmanProcessEnvironment::new(
        scratch.path(),
        scratch.path().join("runtime"),
        scratch.path().join("state"),
        scratch.path().join("ordinary-private-bin"),
        scratch.path().join("conmon"),
        scratch.path().join("crun"),
        scratch.path().join("catatonit"),
        scratch.path().join("seccomp.json"),
    );

    assert!(result.is_err());
}

fn environment(home: &Path) -> PodmanProcessEnvironment {
    environment_with_trust(home, true)
}

fn environment_with_trust(home: &Path, revalidates: bool) -> PodmanProcessEnvironment {
    environment_with_trust_state(home, Arc::new(AtomicBool::new(revalidates)))
}

fn environment_with_trust_state(
    home: &Path,
    revalidates: Arc<AtomicBool>,
) -> PodmanProcessEnvironment {
    let environment = untrusted_environment(home);
    let binary = PodmanBinary::new(executable(&["/usr/bin/true", "/bin/true"]))
        .expect("syntactic test Podman binary");
    let state = PodmanStateRoot::existing(environment.state_root())
        .expect("existing private test state root");
    let trust = PodmanLaunchTrustHandle::new(Arc::new(TestTrust(revalidates)));
    let options = PodmanOptions::new(binary, state, environment)
        .expect("coherent test options")
        .with_launch_trust(trust);
    options.process_environment().clone()
}

fn untrusted_environment(home: &Path) -> PodmanProcessEnvironment {
    let runtime = home.join("runtime");
    let state = home.join("state");
    let helper = home.join("approved/usr/sbin");
    let system_config = state.join("podman-system-config");
    let empty_hooks = state.join("empty-hooks");
    let empty_cdi = system_config.join("empty-cdi");
    let process_transient = state.join("process-transient");
    for directory in [
        &runtime,
        &state,
        &helper,
        &system_config,
        &empty_hooks,
        &empty_cdi,
        &process_transient,
    ] {
        fs::create_dir_all(directory).expect("private test directory");
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .expect("private test directory mode");
    }
    let sleep = helper.join("sleep");
    if !sleep.exists() {
        symlink(executable(&["/usr/bin/sleep", "/bin/sleep"]), &sleep)
            .expect("approved sleep helper link");
    }
    let conmon = helper.join("conmon");
    let oci_runtime = helper.join("crun");
    let init = helper.join("catatonit");
    let seccomp = home.join("seccomp.json");
    let environment = PodmanProcessEnvironment::new(
        home,
        &runtime,
        &state,
        &helper,
        &conmon,
        &oci_runtime,
        &init,
        &seccomp,
    )
    .expect("test process environment");
    write_private(
        environment.containers_conf_path(),
        containers_conf_contents(&environment).as_bytes(),
    );
    write_private(
        environment.storage_conf_path(),
        b"[storage]\ndriver = \"vfs\"\ntransient_store = false\n",
    );
    write_private(
        environment.registries_conf_path(),
        b"unqualified-search-registries = []\nshort-name-mode = \"disabled\"\ncredential-helpers = [\"containers-auth.json\"]\n",
    );
    write_private(
        environment.policy_path(),
        b"{\"default\":[{\"type\":\"insecureAcceptAnything\"}]}\n",
    );
    write_private(environment.mounts_conf_path(), b"");
    write_private(environment.auth_file_path(), b"{\"auths\":{}}");
    environment
}

fn containers_conf_contents(environment: &PodmanProcessEnvironment) -> String {
    format!(
        "[containers]\ninit_path = \"{}\"\nlog_driver = \"k8s-file\"\nseccomp_profile = \"{}\"\n\n[engine]\ncdi_spec_dirs = [\"{}\"]\ncompat_api_enforce_docker_hub = true\nconmon_env_vars = [\"PATH={}\"]\nconmon_path = [\"{}\"]\ndatabase_backend = \"sqlite\"\nevents_logger = \"none\"\nhelper_binaries_dir = [\"{}\"]\nhooks_dir = [\"{}\"]\nruntime = \"{}\"\n\n[network]\ndefault_rootless_network_cmd = \"pasta\"\nfirewall_driver = \"nftables\"\nnetavark_plugin_dirs = []\nnetwork_backend = \"netavark\"\nrootless_port_forwarder = \"rootlessport\"\n",
        environment.init_path().display(),
        environment.seccomp_profile_path().display(),
        environment.empty_cdi_directory().display(),
        environment.approved_helper_directory().display(),
        environment.conmon_path().display(),
        environment.approved_helper_directory().display(),
        environment.empty_hooks_directory().display(),
        environment.oci_runtime_path().display(),
    )
}

fn write_private(path: &Path, contents: &[u8]) {
    fs::write(path, contents).expect("write exact test configuration");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("private test configuration mode");
}

fn executable(candidates: &[&str]) -> PathBuf {
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .expect("required test executable")
}

fn assert_recorded_process_gone(pid_file: &Path, circumstance: &str) {
    let process = fs::read_to_string(pid_file)
        .expect("descendant PID must be recorded")
        .trim()
        .parse::<u32>()
        .expect("descendant PID must be numeric");
    let process_path = PathBuf::from(format!("/proc/{process}"));
    let deadline = Instant::now() + Duration::from_secs(2);
    while process_path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let survived = process_path.exists();
    if survived {
        let process = i32::try_from(process)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .expect("descendant PID must fit the platform range");
        let _ = rustix::process::kill_process(process, rustix::process::Signal::KILL);
    }
    assert!(!survived, "descendant survived {circumstance}");
}
