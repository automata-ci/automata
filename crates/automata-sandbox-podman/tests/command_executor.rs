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

use automata_execution::{Cancellation, NeverCancelled};
use automata_sandbox_podman::{
    CommandRequest, CommandTermination, PodmanCommandExecutor, PodmanProcessEnvironment,
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
    fn is_cancelled(&self) -> bool {
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
    assert!(!format!("{request:?}").contains("sensitive-output"));
    assert!(!format!("{output:?}").contains("sensitive-output"));
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

    assert_eq!(output.termination(), CommandTermination::Exited(Some(0)));
    assert!(values.lines().all(|line| {
        line.starts_with("HOME=")
            || line.starts_with("PATH=")
            || line.starts_with("XDG_RUNTIME_DIR=")
    }));
    assert!(!values.contains("TOKEN="));
    assert!(!values.contains("PROXY="));
}

fn environment(home: &Path) -> PodmanProcessEnvironment {
    PodmanProcessEnvironment::new(home, None, OsString::from("/usr/bin:/bin"))
        .expect("test process environment")
}

fn executable(candidates: &[&str]) -> PathBuf {
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .expect("required test executable")
}
