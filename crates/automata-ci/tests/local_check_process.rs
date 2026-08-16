use std::{fs, path::Path, process::Command};

#[cfg(unix)]
use std::{
    os::unix::fs::PermissionsExt as _,
    os::unix::net::UnixListener,
    path::PathBuf,
    process::Stdio,
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use rustix::process::{Pid, Signal, kill_process};

use serde_json::Value;
use uuid::Uuid;

#[test]
fn local_check_process_is_deterministic_read_only_and_redacts_input_values() {
    let fixture = Fixture::new();
    fixture.write(
        ".github/workflows/check.yml",
        r"on:
  workflow_dispatch:
    inputs:
      token_hint:
        type: string
        required: true
jobs:
  check:
    runs-on: linux
    steps:
      - run: echo '${{ secrets.api_token }}' '${{ vars.region }}'
",
    );
    fixture.commit_all();
    fixture.write("dirty.txt", "uncommitted exact bytes\n");
    let status_before = fixture.git_stdout(&["status", "--porcelain=v2", "--untracked-files=all"]);
    let sensitive = "local-input-value-must-not-appear";
    let environment_marker = "local-environment-value-must-not-appear";

    let first = fixture.automata_with_hostile_service_environment(&[
        "local",
        "check",
        "--input",
        &format!("token_hint={sensitive}"),
        "--json",
    ]);
    let repeated = fixture.automata_with_hostile_service_environment(&[
        "local",
        "check",
        "--input",
        &format!("token_hint={sensitive}"),
        "--json",
    ]);

    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(repeated.status.success());
    assert_eq!(first.stdout, repeated.stdout);
    assert!(
        !first
            .stdout
            .windows(sensitive.len())
            .any(|window| window == sensitive.as_bytes())
    );
    assert!(!String::from_utf8_lossy(&first.stdout).contains(environment_marker));
    assert!(!String::from_utf8_lossy(&first.stderr).contains(environment_marker));
    assert!(
        !first
            .stderr
            .windows(sensitive.len())
            .any(|window| window == sensitive.as_bytes())
    );
    assert!(
        !first
            .stdout
            .windows(fixture.path().as_os_str().len())
            .any(|window| window == fixture.path().to_string_lossy().as_bytes())
    );
    let document: Value = serde_json::from_slice(&first.stdout).expect("one JSON document");
    assert_eq!(document["schema"], 1);
    assert_eq!(document["valid"], true);
    assert_eq!(document["source"]["dirty"], true);
    assert_eq!(document["required_root_secrets"][0], "API_TOKEN");
    assert_eq!(
        document["workflows"][0]["jobs"][0]["secrets"][0],
        "API_TOKEN"
    );
    assert_eq!(
        document["workflows"][0]["jobs"][0]["variables"][0],
        "REGION"
    );
    assert_eq!(
        fixture.git_stdout(&["status", "--porcelain=v2", "--untracked-files=all"]),
        status_before,
        "local check must not mutate Git or the worktree"
    );

    let human = fixture.automata_with_hostile_service_environment(&[
        "local",
        "check",
        "--input",
        &format!("token_hint={sensitive}"),
    ]);
    assert!(human.status.success());
    let human_stdout = String::from_utf8_lossy(&human.stdout);
    let human_stderr = String::from_utf8_lossy(&human.stderr);
    assert!(!human_stdout.contains(sensitive));
    assert!(!human_stderr.contains(sensitive));
    assert!(!human_stdout.contains(environment_marker));
    assert!(!human_stderr.contains(environment_marker));
    assert!(!human_stdout.contains(fixture.path().to_string_lossy().as_ref()));
}

#[test]
fn invalid_workflow_still_emits_one_value_free_json_report() {
    let fixture = Fixture::new();
    fixture.write(
        ".github/workflows/check.yml",
        "on: push\njobs:\n  check:\n    runs-on: linux\n    steps:\n      - run: true\n",
    );
    fixture.commit_all();
    let output = fixture.automata(&["local", "check", "--json"]);

    assert!(!output.status.success());
    let document: Value = serde_json::from_slice(&output.stdout).expect("failure JSON document");
    assert_eq!(document["schema"], 1);
    assert_eq!(document["valid"], false);
    assert_eq!(document["issue"]["code"], "compilation");
    assert!(
        !String::from_utf8_lossy(&output.stderr)
            .contains(fixture.path().to_string_lossy().as_ref())
    );
}

#[cfg(unix)]
#[test]
fn hostile_git_environment_cannot_execute_or_mutate_and_never_leaks() {
    let fixture = Fixture::new();
    fixture.write(
        ".github/workflows/check.yml",
        "on: workflow_dispatch\njobs:\n  check:\n    runs-on: linux\n    steps:\n      - run: true\n",
    );
    fixture.commit_all();
    let hostile = HostileGitEnvironment::new(&fixture);
    let status_before = fixture.git_stdout(&["status", "--porcelain=v2", "--untracked-files=all"]);
    let output = hostile.run(&fixture);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!hostile.execution_marker.exists());
    assert!(!hostile.trace.exists());
    assert!(!hostile.trace2.exists());
    assert!(!hostile.trace2_perf.exists());
    assert!(
        matches!(hostile.listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    assert_eq!(
        fixture.git_stdout(&["status", "--porcelain=v2", "--untracked-files=all"]),
        status_before,
    );
    let stdout = String::from_utf8(output.stdout).expect("local check JSON");
    let stderr = String::from_utf8(output.stderr).expect("local check stderr");
    let fixture_path = fixture.path().to_string_lossy();
    let hostile_path = hostile.root.to_string_lossy();
    for private in [
        fixture_path.as_ref(),
        hostile_path.as_ref(),
        HOSTILE_PRIVATE_VALUE,
    ] {
        assert!(!stdout.contains(private));
        assert!(!stderr.contains(private));
    }
}

#[cfg(unix)]
const HOSTILE_PRIVATE_VALUE: &str = "hostile-git-private-environment-value";

#[cfg(unix)]
struct HostileGitEnvironment {
    root: PathBuf,
    fake_bin: PathBuf,
    home: PathBuf,
    xdg: PathBuf,
    global_config: PathBuf,
    system_config: PathBuf,
    helper: PathBuf,
    execution_marker: PathBuf,
    trace: PathBuf,
    trace2: PathBuf,
    trace2_perf: PathBuf,
    socket_path: PathBuf,
    listener: UnixListener,
    _socket_guard: SocketFileGuard,
}

#[cfg(unix)]
impl HostileGitEnvironment {
    fn new(fixture: &Fixture) -> Self {
        let root = fixture.path().join("hostile-git-environment");
        let fake_bin = root.join("bin");
        let home = root.join("home");
        let xdg = root.join("xdg");
        let markers = root.join("markers");
        for directory in [&fake_bin, &home, &xdg, &markers] {
            fs::create_dir_all(directory).expect("create hostile fixture directory");
        }
        let execution_marker = markers.join("executed");
        install_marker_program(&fake_bin.join("git"), &execution_marker);
        let helper = root.join("host-helper");
        install_marker_program(&helper, &execution_marker);
        let hooks = root.join("hooks");
        fs::create_dir(&hooks).expect("create hostile hooks directory");
        install_marker_program(&hooks.join("post-index-change"), &execution_marker);
        let global_config = root.join("global.gitconfig");
        let system_config = root.join("system.gitconfig");
        let config = format!(
            "[core]\n\tfsmonitor = {}\n\thooksPath = {}\n[credential]\n\thelper = !{}\n[maintenance]\n\tauto = true\n",
            helper.display(),
            hooks.display(),
            helper.display(),
        );
        fs::write(&global_config, &config).expect("write hostile global config");
        fs::write(&system_config, &config).expect("write hostile system config");
        let trace = root.join("git-trace-private-path-marker");
        let trace2 = root.join("git-trace2-private-path-marker");
        let trace2_perf = root.join("git-trace2-perf-private-path-marker");
        let socket_path = std::env::temp_dir().join(format!(
            "automata-local-check-{}.socket",
            Uuid::new_v4().simple()
        ));
        let listener = UnixListener::bind(&socket_path).expect("bind hostile trace2 socket");
        listener
            .set_nonblocking(true)
            .expect("make trace2 listener nonblocking");
        let socket_guard = SocketFileGuard(socket_path.clone());
        Self {
            root,
            fake_bin,
            home,
            xdg,
            global_config,
            system_config,
            helper,
            execution_marker,
            trace,
            trace2,
            trace2_perf,
            socket_path,
            listener,
            _socket_guard: socket_guard,
        }
    }

    fn run(&self, fixture: &Fixture) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_automata"))
            .current_dir(fixture.path())
            .args(["local", "check", "--json"])
            .env("PATH", &self.fake_bin)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.xdg)
            .env("GIT_CONFIG_GLOBAL", &self.global_config)
            .env("GIT_CONFIG_SYSTEM", &self.system_config)
            .env("GIT_CONFIG_NOSYSTEM", "0")
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "core.fsmonitor")
            .env("GIT_CONFIG_VALUE_0", &self.helper)
            .env("GIT_DIR", self.root.join("fake.git"))
            .env("GIT_COMMON_DIR", self.root.join("fake-common.git"))
            .env("GIT_WORK_TREE", &self.root)
            .env("GIT_INDEX_FILE", self.root.join("fake-index"))
            .env("GIT_OBJECT_DIRECTORY", self.root.join("fake-objects"))
            .env(
                "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                self.root.join("fake-alternates"),
            )
            .env("GIT_NAMESPACE", HOSTILE_PRIVATE_VALUE)
            .env("GIT_SHALLOW_FILE", self.root.join("fake-shallow"))
            .env("GIT_REPLACE_REF_BASE", HOSTILE_PRIVATE_VALUE)
            .env("GIT_EXEC_PATH", &self.fake_bin)
            .env("GIT_PAGER", &self.helper)
            .env("GIT_EDITOR", &self.helper)
            .env("GIT_SEQUENCE_EDITOR", &self.helper)
            .env("GIT_ASKPASS", &self.helper)
            .env("SSH_ASKPASS", &self.helper)
            .env("GIT_SSH_COMMAND", &self.helper)
            .env("GIT_TRACE", &self.trace)
            .env("GIT_TRACE_PACKET", &self.trace)
            .env("GIT_TRACE_PERFORMANCE", &self.trace)
            .env("GIT_TRACE_SETUP", &self.trace)
            .env("GIT_TRACE_SHALLOW", &self.trace)
            .env("GIT_TRACE_CURL", &self.trace)
            .env("GIT_TRACE2", &self.trace2)
            .env("GIT_TRACE2_PERF", &self.trace2_perf)
            .env(
                "GIT_TRACE2_EVENT",
                format!("af_unix:{}", self.socket_path.display()),
            )
            .env("AUTOMATA_HOSTILE_PRIVATE", HOSTILE_PRIVATE_VALUE)
            .output()
            .expect("run hostile-environment local check")
    }
}

#[cfg(unix)]
#[test]
fn interrupting_large_capture_awaits_shutdown_and_leaves_no_residue() {
    let fixture = Fixture::new();
    fixture.write(
        ".github/workflows/check.yml",
        "on: workflow_dispatch\njobs:\n  check:\n    runs-on: linux\n    steps:\n      - run: true\n",
    );
    fixture.write_binary("large-source.bin", deterministic_bytes(28 * 1024 * 1024));
    fixture.commit_all();
    let status_before = fixture.git_stdout(&["status", "--porcelain=v2", "--untracked-files=all"]);
    let entries_before = fixture.root_entries();

    let mut child = Command::new(env!("CARGO_BIN_EXE_automata"))
        .current_dir(fixture.path())
        .args(["local", "check", "--json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start large local check");
    thread::sleep(Duration::from_millis(20));
    let raw_pid = i32::try_from(child.id()).expect("child PID fits pid_t");
    let pid = Pid::from_raw(raw_pid).expect("nonzero child PID");
    kill_process(pid, Signal::INT).expect("interrupt local check");

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().expect("poll local check").is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("interrupted local check did not await bounded worker shutdown");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child
        .wait_with_output()
        .expect("collect interrupted local check");
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "interruption must not emit partial JSON"
    );
    let stderr = String::from_utf8(output.stderr).expect("interruption diagnostics");
    assert!(stderr.contains("local workflow check interrupted by a process shutdown signal"));
    assert!(!stderr.contains(fixture.path().to_string_lossy().as_ref()));
    assert_eq!(fixture.root_entries(), entries_before);
    assert_eq!(
        fixture.git_stdout(&["status", "--porcelain=v2", "--untracked-files=all"]),
        status_before,
    );
}

#[cfg(unix)]
fn install_marker_program(path: &Path, marker: &Path) {
    fs::write(
        path,
        format!("#!/bin/sh\n: > '{}'\nexit 97\n", marker.display()),
    )
    .expect("write hostile program");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .expect("make hostile program executable");
}

#[cfg(unix)]
fn deterministic_bytes(length: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_u32;
    let mut bytes = Vec::with_capacity(length);
    for _ in 0..length {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        bytes.push(state.to_le_bytes()[0]);
    }
    bytes
}

#[cfg(unix)]
struct SocketFileGuard(std::path::PathBuf);

#[cfg(unix)]
impl Drop for SocketFileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

struct Fixture {
    root: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "automata-local-check-process-{}",
            Uuid::new_v4().simple()
        ));
        fs::create_dir(&root).expect("create fixture");
        let fixture = Self { root };
        fixture.git(&["init", "--quiet"]);
        fixture.git(&["config", "user.name", "Automata Test"]);
        fixture.git(&["config", "user.email", "automata@example.invalid"]);
        fixture
    }

    fn path(&self) -> &Path {
        &self.root
    }

    fn write(&self, path: &str, value: &str) {
        let path = self.root.join(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create fixture parent");
        }
        fs::write(path, value).expect("write fixture");
    }

    #[cfg(unix)]
    fn write_binary(&self, path: &str, value: Vec<u8>) {
        let path = self.root.join(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create fixture parent");
        }
        fs::write(path, value).expect("write binary fixture");
    }

    #[cfg(unix)]
    fn root_entries(&self) -> Vec<String> {
        let mut entries = fs::read_dir(&self.root)
            .expect("read fixture root")
            .map(|entry| {
                entry
                    .expect("read fixture entry")
                    .file_name()
                    .into_string()
                    .expect("Unicode fixture entry")
            })
            .collect::<Vec<_>>();
        entries.sort();
        entries
    }

    fn commit_all(&self) {
        self.git(&["add", "--all"]);
        self.git(&["commit", "--quiet", "--message", "fixture"]);
    }

    fn git(&self, arguments: &[&str]) {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&self.root)
                .args(arguments)
                .status()
                .expect("run Git")
                .success()
        );
    }

    fn git_stdout(&self, arguments: &[&str]) -> Vec<u8> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(arguments)
            .output()
            .expect("run Git");
        assert!(output.status.success());
        output.stdout
    }

    fn automata(&self, arguments: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_automata"))
            .current_dir(&self.root)
            .args(arguments)
            .output()
            .expect("run automata")
    }

    fn automata_with_hostile_service_environment(
        &self,
        arguments: &[&str],
    ) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_automata"))
            .current_dir(&self.root)
            .args(arguments)
            .env("DOCKER_HOST", "tcp://127.0.0.1:1")
            .env("GITHUB_TOKEN", "local-environment-value-must-not-appear")
            .env("GH_TOKEN", "local-environment-value-must-not-appear")
            .env("HTTP_PROXY", "http://127.0.0.1:1")
            .env("HTTPS_PROXY", "http://127.0.0.1:1")
            .output()
            .expect("run service-independent local check")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
