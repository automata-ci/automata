#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use rustix::{
    io::Errno,
    process::{Pid, Signal, kill_process, test_kill_process},
};
use serde_json::Value;
use uuid::Uuid;

const FAILURE_SENTINEL: &str = "FAKE_DOCKER_FAILURE_MUST_NOT_ESCAPE";

#[test]
fn failed_local_doctor_is_typed_actionable_json_and_is_read_only() {
    let fixture = Fixture::new();
    let fake_bin = fixture.path().join("bin");
    fs::create_dir(&fake_bin).expect("create isolated executable directory");
    install_fake_docker(&fake_bin.join("docker"));

    let output = Command::new(env!("CARGO_BIN_EXE_automata"))
        .args(["local", "doctor", "--json"])
        .env_clear()
        .env("PATH", &fake_bin)
        .env("HOME", fixture.path())
        .output()
        .expect("local doctor process must start");

    assert!(!output.status.success());
    let report: Value =
        serde_json::from_slice(&output.stdout).expect("stdout must contain one JSON document");
    assert_eq!(report["schema"], 3);
    assert_eq!(report["ready"], false);
    assert!(report["selected_engine"].is_null());
    assert!(report.get("state_directory").is_none());

    let issues = report["issues"]
        .as_array()
        .expect("doctor issues must be an array");
    assert_issue(
        issues,
        "docker_version",
        "docker_daemon_unavailable",
        "start Docker Engine and allow this user to access its local socket",
    );
    assert_issue(
        issues,
        "docker_info",
        "docker_daemon_unavailable",
        "start Docker Engine and allow this user to access its local socket",
    );
    assert_issue(
        issues,
        "docker_compose",
        "docker_compose_unavailable",
        "install Docker Compose CLI plugin version 2.33.1 or newer",
    );

    let stdout = String::from_utf8(output.stdout).expect("doctor JSON must be UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("doctor diagnostics must be UTF-8");
    assert!(!stdout.contains("Automata local preflight:"));
    assert!(!stdout.contains(FAILURE_SENTINEL));
    assert_eq!(
        stderr,
        "Error: local preflight failed; resolve the unavailable checks above\n"
    );
    assert!(!stderr.contains(FAILURE_SENTINEL));

    let mut fixture_entries = fs::read_dir(fixture.path())
        .expect("read fixture root")
        .map(|entry| {
            entry
                .expect("read fixture entry")
                .file_name()
                .into_string()
                .expect("fixture entry must be Unicode")
        })
        .collect::<Vec<_>>();
    fixture_entries.sort();
    assert_eq!(fixture_entries, ["bin"]);
}

#[test]
fn interrupted_local_doctor_terminates_the_context_probe_process_tree() {
    let fixture = Fixture::new();
    let fake_bin = fixture.path().join("bin");
    let process_directory = fixture.path().join("processes");
    fs::create_dir(&fake_bin).expect("create isolated executable directory");
    fs::create_dir(&process_directory).expect("create process evidence directory");
    install_hanging_fake_docker(&fake_bin.join("docker"));

    let mut command = Command::new(env!("CARGO_BIN_EXE_automata"));
    command
        .args(["local", "doctor", "--json"])
        .env_clear()
        .env("PATH", &fake_bin)
        .env("HOME", fixture.path())
        .env("FAKE_DOCKER_PROCESS_DIRECTORY", &process_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let process = ChildGuard::spawn(&mut command);
    let probe_processes = wait_for_probe_processes(&process_directory, 2, "context probe");
    let mut cleanup = ProcessCleanup::new(probe_processes.clone());

    kill_process(process.pid(), Signal::INT).expect("interrupt local doctor");
    let output = process.wait_for_output(Duration::from_secs(5));
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "an interrupted doctor emits no partial JSON: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8(output.stderr).expect("doctor diagnostics must be UTF-8");
    assert!(
        stderr.contains("local preflight interrupted by a process shutdown signal"),
        "unexpected interrupted-doctor diagnostics: {stderr}"
    );

    wait_for_processes_to_exit(&probe_processes);
    cleanup.disarm();
}

#[test]
fn interrupted_local_doctor_terminates_all_post_context_probe_trees() {
    let fixture = Fixture::new();
    let fake_bin = fixture.path().join("bin");
    let process_directory = fixture.path().join("processes");
    fs::create_dir(&fake_bin).expect("create isolated executable directory");
    fs::create_dir(&process_directory).expect("create process evidence directory");
    install_post_context_hanging_fake_docker(&fake_bin.join("docker"));

    let mut command = Command::new(env!("CARGO_BIN_EXE_automata"));
    command
        .args(["local", "doctor", "--json"])
        .env_clear()
        .env("PATH", &fake_bin)
        .env("HOME", fixture.path())
        .env("FAKE_DOCKER_PROCESS_DIRECTORY", &process_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let process = ChildGuard::spawn(&mut command);
    let probe_processes =
        wait_for_probe_processes(&process_directory, 6, "version, info, and Compose probes");
    let mut cleanup = ProcessCleanup::new(probe_processes.clone());

    kill_process(process.pid(), Signal::INT).expect("interrupt local doctor");
    let output = process.wait_for_output(Duration::from_secs(5));
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "an interrupted doctor emits no partial JSON: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8(output.stderr).expect("doctor diagnostics must be UTF-8");
    assert!(
        stderr.contains("local preflight interrupted by a process shutdown signal"),
        "unexpected interrupted-doctor diagnostics: {stderr}"
    );

    wait_for_processes_to_exit(&probe_processes);
    cleanup.disarm();
}

fn assert_issue(issues: &[Value], probe: &str, code: &str, message: &str) {
    assert!(
        issues.iter().any(|issue| {
            issue["probe"] == probe && issue["code"] == code && issue["message"] == message
        }),
        "missing {probe}/{code} issue in {issues:?}"
    );
}

fn install_fake_docker(path: &Path) {
    fs::write(
        path,
        format!(
            r#"#!/bin/sh
set -eu
case "${{1-}}" in
  context)
    printf '%s\n' '{{"Name":"default","Endpoints":{{"docker":{{"Host":"unix:///var/run/docker.sock","SkipTLSVerify":false}}}}}}'
    ;;
  --host)
    test "${{2-}}" = 'unix:///var/run/docker.sock'
    printf '%s\n' '{FAILURE_SENTINEL}' >&2
    exit 1
    ;;
  compose)
    printf '%s\n' '{FAILURE_SENTINEL}' >&2
    exit 1
    ;;
  *)
    exit 64
    ;;
esac
"#
        ),
    )
    .expect("write fake docker executable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .expect("make fake docker executable owner-only");
}

fn install_hanging_fake_docker(path: &Path) {
    fs::write(
        path,
        r#"#!/bin/sh
set -eu
/bin/sleep 30 &
descendant=$!
printf '%s %s\n' "$$" "$descendant" > "${FAKE_DOCKER_PROCESS_DIRECTORY}/$$"
wait
"#,
    )
    .expect("write hanging fake docker executable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .expect("make hanging fake docker executable owner-only");
}

fn install_post_context_hanging_fake_docker(path: &Path) {
    fs::write(
        path,
        r#"#!/bin/sh
set -eu
if [ "${1-}" = 'context' ]; then
  printf '%s\n' '{"Name":"default","Endpoints":{"docker":{"Host":"unix:///var/run/docker.sock","SkipTLSVerify":false}}}'
  exit 0
fi
/bin/sleep 30 &
descendant=$!
printf '%s %s\n' "$$" "$descendant" > "${FAKE_DOCKER_PROCESS_DIRECTORY}/$$"
wait
"#,
    )
    .expect("write post-context hanging fake docker executable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .expect("make post-context fake docker executable owner-only");
}

fn wait_for_probe_processes(directory: &Path, expected: usize, description: &str) -> Vec<Pid> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let processes = recorded_probe_processes(directory);
        if processes.len() == expected {
            return processes;
        }
        if Instant::now() >= deadline {
            for process in &processes {
                let _ignored = kill_process(*process, Signal::KILL);
            }
            panic!(
                "expected {description} process trees ({expected} processes), found {processes:?}"
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn recorded_probe_processes(directory: &Path) -> Vec<Pid> {
    let mut processes = fs::read_dir(directory)
        .expect("read process evidence directory")
        .filter_map(|entry| fs::read_to_string(entry.ok()?.path()).ok())
        .flat_map(|contents| {
            contents
                .split_whitespace()
                .filter_map(|raw| raw.parse::<i32>().ok())
                .filter_map(Pid::from_raw)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    processes.sort_by_key(|process| process.as_raw_pid());
    processes.dedup_by_key(|process| process.as_raw_pid());
    processes
}

fn wait_for_processes_to_exit(processes: &[Pid]) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let running = processes
            .iter()
            .copied()
            .filter(|process| process_exists(*process))
            .collect::<Vec<_>>();
        if running.is_empty() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "probe processes survived local-doctor interruption: {running:?}"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn process_exists(process: Pid) -> bool {
    match test_kill_process(process) {
        Ok(()) => true,
        Err(Errno::SRCH) => false,
        Err(error) => panic!("could not inspect probe process {process:?}: {error}"),
    }
}

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn spawn(command: &mut Command) -> Self {
        let child = command.spawn().expect("local doctor process must start");
        Self { child: Some(child) }
    }

    fn pid(&self) -> Pid {
        let raw = i32::try_from(self.child.as_ref().expect("live child").id())
            .expect("child process ID must fit pid_t");
        Pid::from_raw(raw).expect("child process ID must be nonzero")
    }

    fn wait_for_output(mut self, timeout: Duration) -> Output {
        let deadline = Instant::now() + timeout;
        loop {
            if self
                .child
                .as_mut()
                .expect("live child")
                .try_wait()
                .expect("inspect local doctor status")
                .is_some()
            {
                return self
                    .child
                    .take()
                    .expect("completed child")
                    .wait_with_output()
                    .expect("collect local doctor output");
            }
            assert!(
                Instant::now() < deadline,
                "local doctor did not exit after its shutdown signal"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ignored = child.kill();
            let _ignored = child.wait();
        }
    }
}

struct ProcessCleanup {
    processes: Vec<Pid>,
}

impl ProcessCleanup {
    fn new(processes: Vec<Pid>) -> Self {
        Self { processes }
    }

    fn disarm(&mut self) {
        self.processes.clear();
    }
}

impl Drop for ProcessCleanup {
    fn drop(&mut self) {
        for process in &self.processes {
            let _ignored = kill_process(*process, Signal::KILL);
        }
    }
}

struct Fixture {
    parent: PathBuf,
    path: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let parent = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("local-doctor-process");
        fs::create_dir_all(&parent).expect("create target-local fixture parent");
        let path = parent.join(format!("fixture-{}", Uuid::new_v4()));
        fs::create_dir(&path).expect("create unique local doctor fixture");
        Self { parent, path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let safe_name = self
            .path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|name| name.starts_with("fixture-"));
        if safe_name && self.path.parent() == Some(self.parent.as_path()) {
            let _ignored = fs::remove_dir_all(&self.path);
        }
    }
}
