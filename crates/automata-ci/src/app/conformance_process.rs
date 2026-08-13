//! Explicit child-process restart probe used only by product conformance support.

use std::{
    collections::BTreeMap,
    ffi::OsString,
    fmt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

use automata_ci_conformance::{
    FixtureControlError, ProductService, ServiceObservation, ServiceRestartProbe, ServiceState,
};
use thiserror::Error;

// foundation-governance: operational-limit
const MAX_CONFORMANCE_PROCESS_ARGUMENTS: usize = 128;
// foundation-governance: operational-limit
const MAX_CONFORMANCE_PROCESS_ENVIRONMENT: usize = 128;
// foundation-governance: operational-limit
const MAX_CONFORMANCE_PROCESS_FIELD_BYTES: usize = 16 * 1_024;
const MAX_CONFORMANCE_PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const PROCESS_WAIT_POLL: Duration = Duration::from_millis(5);

/// Exact, shell-free child process admitted by the conformance restart probe.
///
/// The command inherits no ambient environment. Its executable, arguments,
/// working directory, and complete environment allowlist are all fixed before
/// the first process is started and reused byte-for-byte for every generation.
pub struct ConformanceChildProcessSpec {
    executable: PathBuf,
    arguments: Vec<OsString>,
    environment: BTreeMap<OsString, OsString>,
    working_directory: PathBuf,
    operation_timeout: Duration,
    startup_grace: Duration,
}

impl ConformanceChildProcessSpec {
    /// Validates one exact child command without invoking it.
    ///
    /// # Errors
    ///
    /// Returns [`ConformanceProcessError::InvalidSpec`] when paths, bounds,
    /// environment entries, or timeouts do not satisfy the closed contract.
    pub fn new(
        executable: PathBuf,
        arguments: Vec<OsString>,
        environment: BTreeMap<OsString, OsString>,
        working_directory: PathBuf,
        operation_timeout: Duration,
        startup_grace: Duration,
    ) -> Result<Self, ConformanceProcessError> {
        if !executable.is_absolute()
            || !executable.is_file()
            || !working_directory.is_absolute()
            || !working_directory.is_dir()
            || arguments.len() > MAX_CONFORMANCE_PROCESS_ARGUMENTS
            || environment.len() > MAX_CONFORMANCE_PROCESS_ENVIRONMENT
            || operation_timeout.is_zero()
            || operation_timeout > MAX_CONFORMANCE_PROCESS_TIMEOUT
            || startup_grace.is_zero()
            || startup_grace >= operation_timeout
            || arguments.iter().any(|value| !bounded_field(value))
            || environment
                .iter()
                .any(|(key, value)| !valid_environment_key(key) || !bounded_field(value))
        {
            return Err(ConformanceProcessError::InvalidSpec);
        }
        Ok(Self {
            executable,
            arguments,
            environment,
            working_directory,
            operation_timeout,
            startup_grace,
        })
    }

    fn spawn(&self, generation: u64) -> Result<RunningChild, ConformanceProcessError> {
        let mut command = Command::new(&self.executable);
        command
            .args(&self.arguments)
            .env_clear()
            .envs(&self.environment)
            .current_dir(&self.working_directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command
            .spawn()
            .map_err(|_| ConformanceProcessError::Spawn)?;
        let instance = match process_instance(child.id(), generation) {
            Ok(instance) => instance,
            Err(error) => {
                kill_and_reap(&mut child, self.operation_timeout);
                return Err(error);
            }
        };
        let deadline = Instant::now() + self.startup_grace;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return Err(ConformanceProcessError::ExitedDuringStartup),
                Ok(None) => {}
                Err(_) => {
                    kill_and_reap(&mut child, self.operation_timeout);
                    return Err(ConformanceProcessError::Observe);
                }
            }
            if Instant::now() >= deadline {
                return Ok(RunningChild { child, instance });
            }
            thread::sleep(PROCESS_WAIT_POLL);
        }
    }
}

impl fmt::Debug for ConformanceChildProcessSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConformanceChildProcessSpec")
            .field("executable", &"[EXPLICIT EXECUTABLE]")
            .field("argument_count", &self.arguments.len())
            .field("environment_count", &self.environment.len())
            .field("working_directory", &"[EXPLICIT DIRECTORY]")
            .field("operation_timeout", &self.operation_timeout)
            .field("startup_grace", &self.startup_grace)
            .finish()
    }
}

/// A real OS child process implementing the fixture's stop/start observation port.
///
/// The probe owns exactly one product service. It never invokes a shell, never
/// inherits ambient environment variables, and kills its child on drop.
pub struct ChildProcessRestartProbe {
    service: ProductService,
    spec: ConformanceChildProcessSpec,
    state: Mutex<ChildProcessState>,
}

impl ChildProcessRestartProbe {
    /// Starts generation one and verifies it remains alive through the bounded
    /// startup grace period.
    ///
    /// # Errors
    ///
    /// Returns an error when the process cannot be spawned or exits during its
    /// bounded startup grace period.
    pub fn start(
        service: ProductService,
        spec: ConformanceChildProcessSpec,
    ) -> Result<Self, ConformanceProcessError> {
        let running = spec.spawn(1)?;
        Ok(Self {
            service,
            spec,
            state: Mutex::new(ChildProcessState {
                generation: 1,
                instance: running.instance,
                child: Some(running.child),
            }),
        })
    }

    fn require_service(&self, service: ProductService) -> Result<(), FixtureControlError> {
        if service == self.service {
            Ok(())
        } else {
            Err(FixtureControlError::ProbeFailed)
        }
    }

    fn stop_child(&self, state: &mut ChildProcessState) -> Result<(), FixtureControlError> {
        let Some(child) = state.child.as_mut() else {
            return Err(FixtureControlError::ProbeFailed);
        };
        if child
            .try_wait()
            .map_err(|_| FixtureControlError::ProbeFailed)?
            .is_some()
        {
            state.child = None;
            return Err(FixtureControlError::ProbeFailed);
        }
        child.kill().map_err(|_| FixtureControlError::ProbeFailed)?;
        let deadline = Instant::now() + self.spec.operation_timeout;
        loop {
            if child
                .try_wait()
                .map_err(|_| FixtureControlError::ProbeFailed)?
                .is_some()
            {
                state.child = None;
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(FixtureControlError::ProbeFailed);
            }
            thread::sleep(PROCESS_WAIT_POLL);
        }
    }
}

impl fmt::Debug for ChildProcessRestartProbe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChildProcessRestartProbe")
            .field("service", &self.service)
            .field("spec", &self.spec)
            .finish_non_exhaustive()
    }
}

impl ServiceRestartProbe for ChildProcessRestartProbe {
    fn observe(&self, service: ProductService) -> Result<ServiceObservation, FixtureControlError> {
        self.require_service(service)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| FixtureControlError::ProbeFailed)?;
        let running = match state.child.as_mut() {
            Some(child) => {
                let status = child
                    .try_wait()
                    .map_err(|_| FixtureControlError::ProbeFailed)?;
                if status.is_none() {
                    true
                } else {
                    state.child = None;
                    false
                }
            }
            None => false,
        };
        ServiceObservation::new(
            if running {
                ServiceState::Running
            } else {
                ServiceState::Stopped
            },
            state.generation,
            state.instance.clone(),
        )
    }

    fn stop(&self, service: ProductService) -> Result<(), FixtureControlError> {
        self.require_service(service)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| FixtureControlError::ProbeFailed)?;
        self.stop_child(&mut state)
    }

    fn start(&self, service: ProductService) -> Result<(), FixtureControlError> {
        self.require_service(service)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| FixtureControlError::ProbeFailed)?;
        if state.child.is_some() {
            return Err(FixtureControlError::ProbeFailed);
        }
        let generation = state
            .generation
            .checked_add(1)
            .ok_or(FixtureControlError::ProbeFailed)?;
        let running = self
            .spec
            .spawn(generation)
            .map_err(|_| FixtureControlError::ProbeFailed)?;
        state.generation = generation;
        state.instance = running.instance;
        state.child = Some(running.child);
        Ok(())
    }
}

impl Drop for ChildProcessRestartProbe {
    fn drop(&mut self) {
        if let Ok(state) = self.state.get_mut()
            && let Some(child) = state.child.as_mut()
        {
            kill_and_reap(child, self.spec.operation_timeout);
        }
    }
}

struct RunningChild {
    child: Child,
    instance: String,
}

struct ChildProcessState {
    generation: u64,
    instance: String,
    child: Option<Child>,
}

fn bounded_field(value: &std::ffi::OsStr) -> bool {
    !value.is_empty() && value.as_encoded_bytes().len() <= MAX_CONFORMANCE_PROCESS_FIELD_BYTES
}

fn valid_environment_key(value: &std::ffi::OsStr) -> bool {
    bounded_field(value)
        && value.to_str().is_some_and(|value| {
            value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
}

fn process_instance(process_id: u32, generation: u64) -> Result<String, ConformanceProcessError> {
    if process_id == 0 || generation == 0 {
        return Err(ConformanceProcessError::InvalidProcessIdentity);
    }
    Ok(format!("process-{process_id}-generation-{generation}"))
}

fn kill_and_reap(child: &mut Child, timeout: Duration) {
    let _ = child.kill();
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) | Err(_) => thread::sleep(PROCESS_WAIT_POLL),
        }
    }
}

/// Sanitized construction failure for the shell-free process probe.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ConformanceProcessError {
    /// The executable, paths, environment, or timeout policy was invalid.
    #[error("the conformance child-process specification is invalid")]
    InvalidSpec,
    /// The admitted child could not be spawned.
    #[error("the conformance child process could not be started")]
    Spawn,
    /// The child state could not be observed within the configured bound.
    #[error("the conformance child process could not be observed")]
    Observe,
    /// The child exited before its bounded startup proof completed.
    #[error("the conformance child process exited during its startup proof")]
    ExitedDuringStartup,
    /// The operating system returned an unusable process identity.
    #[error("the conformance child-process identity is invalid")]
    InvalidProcessIdentity,
}

#[cfg(test)]
mod tests {
    use std::{env, path::Path, sync::Arc};

    use automata_ci_conformance::{FaultPlan, FixtureControl, ManualConformanceClock, ShardPlan};

    use super::*;

    const HELPER_ENV: &str = "AUTOMATA_CONFORMANCE_PROCESS_HELPER";

    #[test]
    fn conformance_process_helper() {
        if env::var_os(HELPER_ENV).is_some() {
            assert!(
                env::var_os("PATH").is_none(),
                "the child inherited ambient environment outside its allowlist"
            );
            loop {
                thread::sleep(Duration::from_millis(50));
            }
        }
    }

    #[test]
    fn real_child_process_proves_next_generation_and_new_instance() {
        let executable = env::current_exe().expect("current test executable");
        let working_directory = env::current_dir()
            .expect("current test directory")
            .canonicalize()
            .expect("canonical test directory");
        let arguments = [
            "--exact",
            "app::conformance_process::tests::conformance_process_helper",
            "--nocapture",
        ]
        .map(OsString::from)
        .to_vec();
        let environment = BTreeMap::from([(OsString::from(HELPER_ENV), OsString::from("1"))]);
        let spec = ConformanceChildProcessSpec::new(
            executable,
            arguments,
            environment,
            working_directory,
            Duration::from_secs(3),
            Duration::from_millis(25),
        )
        .expect("exact test child specification");
        let probe = ChildProcessRestartProbe::start(ProductService::Ingress, spec)
            .expect("first test process generation");
        let plan = ShardPlan::derive("child-process-restart-probe", 1).expect("shard plan");
        let control = FixtureControl::for_shard(
            Arc::new(ManualConformanceClock::new(1_000)),
            Arc::new(FaultPlan::default()),
            &plan,
            0,
        )
        .expect("fixture control");
        control
            .restart_with(ProductService::Ingress, &probe)
            .expect("real child stop/start proof");
        let records = control.restart_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].stopped_generation(), 1);
        assert_eq!(records[0].started_generation(), 2);
        assert_ne!(records[0].stopped_instance(), records[0].started_instance());
    }

    #[test]
    fn process_spec_rejects_relative_executable() {
        let error = ConformanceChildProcessSpec::new(
            Path::new("automata-test-helper").to_path_buf(),
            Vec::new(),
            BTreeMap::new(),
            env::current_dir().expect("working directory"),
            Duration::from_secs(1),
            Duration::from_millis(10),
        )
        .expect_err("relative executable must fail closed");
        assert_eq!(error, ConformanceProcessError::InvalidSpec);
    }
}
