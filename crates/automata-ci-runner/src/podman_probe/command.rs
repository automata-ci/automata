use std::{
    ffi::{OsStr, OsString},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, TryRecvError},
    },
    thread,
    time::{Duration, Instant},
};

use automata_ci_sandbox_podman::{PodmanOptions, PodmanProcessEnvironment};

use super::ProbeCancellation;

const POLL_INTERVAL: Duration = Duration::from_millis(20);
const TERMINATION_GRACE: Duration = Duration::from_millis(200);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandPurpose {
    Provisioning,
    Cleanup,
}

/// One bounded process invocation in the active Podman probe lifecycle.
///
/// The system executor supplies null standard input, captures each output
/// stream up to `output_limit`, and terminates the process group on timeout or
/// cancellation.
#[derive(Clone, Debug)]
pub struct CommandRequest {
    program: OsString,
    arguments: Vec<OsString>,
    timeout: Duration,
    output_limit: usize,
    purpose: CommandPurpose,
    aggregate_deadline: Option<Instant>,
}

impl CommandRequest {
    /// Creates a provisioning command with no arguments and explicit time/output ceilings.
    pub fn new(program: impl Into<OsString>, timeout: Duration, output_limit: usize) -> Self {
        Self {
            program: program.into(),
            arguments: Vec::new(),
            timeout,
            output_limit,
            purpose: CommandPurpose::Provisioning,
            aggregate_deadline: None,
        }
    }

    /// Appends one literal argument without shell interpretation.
    pub fn arg(&mut self, argument: impl Into<OsString>) -> &mut Self {
        self.arguments.push(argument.into());
        self
    }

    /// Returns the executable passed directly to the operating system.
    pub fn program(&self) -> &OsStr {
        &self.program
    }

    /// Returns the literal, ordered process arguments.
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    /// Returns this command's individual execution deadline.
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Returns the maximum bytes retained from each output stream.
    pub const fn output_limit(&self) -> usize {
        self.output_limit
    }

    /// Reports whether this request removes probe-owned resources.
    pub const fn is_cleanup(&self) -> bool {
        matches!(self.purpose, CommandPurpose::Cleanup)
    }

    pub(super) fn for_cleanup(mut self, deadline: Instant) -> Self {
        self.purpose = CommandPurpose::Cleanup;
        self.aggregate_deadline = Some(deadline);
        self
    }

    fn cancellation_requested(&self, cancellation: &ProbeCancellation) -> bool {
        match self.purpose {
            CommandPurpose::Provisioning => cancellation.is_cancelled(),
            CommandPurpose::Cleanup => cancellation.is_forced(),
        }
    }
}

/// How a probe command stopped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandTermination {
    /// The process exited normally, optionally with an operating-system status code.
    Exited(Option<i32>),
    /// The command exceeded its individual execution deadline.
    TimedOut,
    /// Shutdown requested cancellation of provisioning or forced cleanup.
    Cancelled,
    /// The aggregate cleanup budget expired.
    CleanupDeadlineExceeded,
    /// The process could not be started.
    FailedToStart,
    /// Process supervision or bounded output capture lost integrity after start.
    ExecutionIntegrityFailed,
}

/// Captured output and termination state from one probe command.
///
/// The system executor applies the request's byte ceiling. Injected executors
/// are responsible for upholding the same boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutput {
    termination: CommandTermination,
    stdout: String,
    stderr: String,
    truncated: bool,
}

impl CommandOutput {
    /// Constructs a successful synthetic result for an injected executor.
    pub fn success(stdout: impl Into<String>) -> Self {
        Self {
            termination: CommandTermination::Exited(Some(0)),
            stdout: stdout.into(),
            stderr: String::new(),
            truncated: false,
        }
    }

    /// Constructs a nonzero-exit synthetic result for an injected executor.
    pub fn failure(code: i32, stderr: impl Into<String>) -> Self {
        Self {
            termination: CommandTermination::Exited(Some(code)),
            stdout: String::new(),
            stderr: stderr.into(),
            truncated: false,
        }
    }

    /// Constructs an individual-deadline synthetic result.
    pub fn timed_out(stderr: impl Into<String>) -> Self {
        Self {
            termination: CommandTermination::TimedOut,
            stdout: String::new(),
            stderr: stderr.into(),
            truncated: false,
        }
    }

    /// Constructs a cancellation synthetic result.
    pub fn cancelled(stderr: impl Into<String>) -> Self {
        Self {
            termination: CommandTermination::Cancelled,
            stdout: String::new(),
            stderr: stderr.into(),
            truncated: false,
        }
    }

    /// Constructs an aggregate-cleanup-deadline synthetic result.
    pub fn cleanup_deadline_exceeded(stderr: impl Into<String>) -> Self {
        Self {
            termination: CommandTermination::CleanupDeadlineExceeded,
            stdout: String::new(),
            stderr: stderr.into(),
            truncated: false,
        }
    }

    /// Constructs a successful synthetic result whose output exceeded its capture limit.
    pub fn truncated_success(stdout: impl Into<String>) -> Self {
        Self {
            termination: CommandTermination::Exited(Some(0)),
            stdout: stdout.into(),
            stderr: String::new(),
            truncated: true,
        }
    }

    /// Constructs a process-start or capture-start synthetic failure.
    pub fn failed_to_start(detail: impl Into<String>) -> Self {
        Self {
            termination: CommandTermination::FailedToStart,
            stdout: String::new(),
            stderr: detail.into(),
            truncated: false,
        }
    }

    /// Constructs a synthetic post-start supervision or capture-integrity failure.
    pub fn execution_integrity_failed(detail: impl Into<String>) -> Self {
        Self {
            termination: CommandTermination::ExecutionIntegrityFailed,
            stdout: String::new(),
            stderr: detail.into(),
            truncated: false,
        }
    }

    /// Returns how the command stopped.
    pub const fn termination(&self) -> &CommandTermination {
        &self.termination
    }

    /// Returns captured standard output.
    pub fn stdout(&self) -> &str {
        &self.stdout
    }

    /// Returns captured standard error.
    pub fn stderr(&self) -> &str {
        &self.stderr
    }

    /// Reports whether the process exited with status zero.
    pub const fn succeeded(&self) -> bool {
        matches!(self.termination, CommandTermination::Exited(Some(0)))
    }

    /// Reports whether either captured stream exceeded its byte ceiling.
    pub const fn was_truncated(&self) -> bool {
        self.truncated
    }

    /// Formats termination and captured output for operator diagnostics.
    ///
    /// This value can contain raw child-process output and is not a
    /// general-purpose secret-redaction boundary.
    pub fn failure_detail(&self) -> String {
        let output = if self.stderr.trim().is_empty() {
            self.stdout.trim()
        } else {
            self.stderr.trim()
        };
        let mut detail = match self.termination {
            CommandTermination::Exited(Some(code)) => format!("exited with status {code}"),
            CommandTermination::Exited(None) => "terminated by a signal".to_owned(),
            CommandTermination::TimedOut => "timed out".to_owned(),
            CommandTermination::Cancelled => "cancelled".to_owned(),
            CommandTermination::CleanupDeadlineExceeded => "cleanup deadline exceeded".to_owned(),
            CommandTermination::FailedToStart => "failed to start".to_owned(),
            CommandTermination::ExecutionIntegrityFailed => "execution integrity failed".to_owned(),
        };
        if !output.is_empty() {
            detail.push_str(": ");
            detail.push_str(output);
        }
        if self.truncated {
            detail.push_str(" [output truncated]");
        }
        detail
    }
}

/// Synchronous adapter for bounded active-probe process execution.
///
/// Implementations must honor cancellation, deadlines, literal arguments, and
/// output ceilings expressed by [`CommandRequest`].
pub trait CommandExecutor: Send + Sync {
    /// Executes one request and returns its bounded termination record.
    fn execute(&self, request: &CommandRequest, cancellation: &ProbeCancellation) -> CommandOutput;
}

/// Operating-system command executor used by the production active probe.
#[derive(Debug, Default)]
pub struct SystemCommandExecutor;

impl CommandExecutor for SystemCommandExecutor {
    fn execute(&self, request: &CommandRequest, cancellation: &ProbeCancellation) -> CommandOutput {
        execute_system_command(request, cancellation, None)
    }
}

/// Operating-system adapter bound to the production Podman binary and clean environment.
///
/// The active probe still constructs literal `podman` requests so injected
/// executors can inspect a stable command contract. This adapter replaces only
/// that exact program with the validated production binary and launches it in
/// the same allowlisted environment used by the sandbox provider.
#[derive(Clone, Debug)]
pub(super) struct ConfiguredSystemCommandExecutor {
    podman_binary: PathBuf,
    base_arguments: Vec<OsString>,
    environment: PodmanProcessEnvironment,
}

impl ConfiguredSystemCommandExecutor {
    #[must_use]
    pub(super) fn from_options(options: &PodmanOptions) -> Self {
        Self {
            podman_binary: options.binary().as_path().to_path_buf(),
            base_arguments: options.shared_global_arguments(),
            environment: options.process_environment().clone(),
        }
    }

    fn configured_request(&self, request: &CommandRequest) -> Option<CommandRequest> {
        if request.program() != OsStr::new("podman")
            || request.arguments().first().map(OsString::as_os_str)
                != Some(OsStr::new("--remote=false"))
        {
            return None;
        }
        let mut configured = request.clone();
        configured
            .arguments
            .splice(0..1, self.base_arguments.iter().cloned());
        Some(configured)
    }
}

impl CommandExecutor for ConfiguredSystemCommandExecutor {
    fn execute(&self, request: &CommandRequest, cancellation: &ProbeCancellation) -> CommandOutput {
        let Some(request) = self.configured_request(request) else {
            return CommandOutput::failed_to_start(
                "the configured probe executor accepts only local Podman requests",
            );
        };
        execute_system_command(&request, cancellation, Some(self))
    }
}

fn execute_system_command(
    request: &CommandRequest,
    cancellation: &ProbeCancellation,
    configured: Option<&ConfiguredSystemCommandExecutor>,
) -> CommandOutput {
    if request.cancellation_requested(cancellation) {
        return CommandOutput::cancelled("shutdown was requested before process creation");
    }
    if request
        .aggregate_deadline
        .is_some_and(|deadline| Instant::now() >= deadline)
    {
        return CommandOutput::cleanup_deadline_exceeded(
            "aggregate cleanup deadline expired before process creation",
        );
    }

    let (mut child, stdout_reader, stderr_reader) = match spawn_child(request, configured) {
        Ok(process) => process,
        Err(output) => return output,
    };
    let deadline = CommandDeadline::new(request, Instant::now());
    let (termination, mut wait_error) =
        wait_for_termination(&mut child, request, cancellation, deadline);

    #[cfg(target_os = "linux")]
    if matches!(termination, CommandTermination::Exited(_)) {
        wait_error = combine_errors(wait_error, terminate_remaining_process_group(&child));
        wait_error = combine_errors(
            wait_error,
            child
                .wait()
                .err()
                .map(|error| format!("could not reap process leader: {error}")),
        );
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    if matches!(termination, CommandTermination::Exited(_)) {
        wait_error = combine_errors(wait_error, terminate_remaining_process_group(&child));
    }

    assemble_output(
        termination,
        wait_error,
        stdout_reader,
        stderr_reader,
        deadline,
        request,
        cancellation,
    )
}

fn spawn_child(
    request: &CommandRequest,
    configured: Option<&ConfiguredSystemCommandExecutor>,
) -> Result<(Child, CappedReader, CappedReader), CommandOutput> {
    let mut command = match configured {
        Some(configured) => Command::new(&configured.podman_binary),
        None => Command::new(request.program()),
    };
    command
        .args(request.arguments())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(configured) = configured {
        configured.environment.apply_to_command(&mut command);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    if let Some(configured) = configured {
        configured
            .environment
            .validate_launch()
            .map_err(|_| CommandOutput::failed_to_start("Podman launch policy changed"))?;
    }
    let mut child = command
        .spawn()
        .map_err(|error| CommandOutput::failed_to_start(error.to_string()))?;
    let stdout = child.stdout.take().ok_or_else(|| {
        let error = terminate_process_group(&mut child, TERMINATION_GRACE);
        CommandOutput::execution_integrity_failed(
            error.unwrap_or_else(|| "spawned process had no stdout pipe".to_owned()),
        )
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        let error = terminate_process_group(&mut child, TERMINATION_GRACE);
        CommandOutput::execution_integrity_failed(
            error.unwrap_or_else(|| "spawned process had no stderr pipe".to_owned()),
        )
    })?;
    let stdout_reader = CappedReader::spawn(stdout, request.output_limit(), "stdout")
        .map_err(|error| output_capture_start_failure(&mut child, "stdout", &error))?;
    let stderr_reader = CappedReader::spawn(stderr, request.output_limit(), "stderr")
        .map_err(|error| output_capture_start_failure(&mut child, "stderr", &error))?;
    Ok((child, stdout_reader, stderr_reader))
}

fn output_capture_start_failure(child: &mut Child, stream: &str, error: &str) -> CommandOutput {
    let termination_error = terminate_process_group(child, TERMINATION_GRACE);
    let detail = combine_errors(
        Some(format!("could not start {stream} capture: {error}")),
        termination_error,
    )
    .expect("capture setup always supplies an error");
    CommandOutput::execution_integrity_failed(detail)
}

fn wait_for_termination(
    child: &mut Child,
    request: &CommandRequest,
    cancellation: &ProbeCancellation,
    deadline: CommandDeadline,
) -> (CommandTermination, Option<String>) {
    loop {
        match poll_child_exit(child) {
            Ok(ChildExitObservation::Exited(status)) => {
                return (CommandTermination::Exited(status), None);
            }
            Ok(ChildExitObservation::Running) if request.cancellation_requested(cancellation) => {
                let error = terminate_process_group(child, TERMINATION_GRACE);
                return (CommandTermination::Cancelled, error);
            }
            Ok(ChildExitObservation::Running) if Instant::now() >= deadline.at => {
                let error = terminate_process_group(child, Duration::ZERO);
                return (deadline.expired_termination(), error);
            }
            Ok(ChildExitObservation::Running) => {
                thread::sleep(
                    POLL_INTERVAL.min(deadline.at.saturating_duration_since(Instant::now())),
                );
            }
            Err(error) => {
                let termination_error = terminate_process_group(child, TERMINATION_GRACE);
                let detail = combine_errors(Some(error), termination_error);
                return (CommandTermination::ExecutionIntegrityFailed, detail);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChildExitObservation {
    Running,
    Exited(Option<i32>),
}

#[cfg(target_os = "linux")]
fn poll_child_exit(child: &mut Child) -> Result<ChildExitObservation, String> {
    let raw_pid = i32::try_from(child.id())
        .map_err(|_error| "child process identifier exceeded the platform range".to_owned())?;
    let pid = rustix::process::Pid::from_raw(raw_pid)
        .ok_or_else(|| "child process identifier was zero".to_owned())?;
    let options = rustix::process::WaitIdOptions::EXITED
        | rustix::process::WaitIdOptions::NOHANG
        | rustix::process::WaitIdOptions::NOWAIT;
    rustix::process::waitid(rustix::process::WaitId::Pid(pid), options)
        .map(|status| match status {
            Some(status) => ChildExitObservation::Exited(status.exit_status()),
            None => ChildExitObservation::Running,
        })
        .map_err(|error| format!("could not observe process leader without reaping it: {error}"))
}

#[cfg(not(target_os = "linux"))]
fn poll_child_exit(child: &mut Child) -> Result<ChildExitObservation, String> {
    child
        .try_wait()
        .map(|status| match status {
            Some(status) => ChildExitObservation::Exited(status.code()),
            None => ChildExitObservation::Running,
        })
        .map_err(|error| error.to_string())
}

fn assemble_output(
    mut termination: CommandTermination,
    wait_error: Option<String>,
    stdout_reader: CappedReader,
    stderr_reader: CappedReader,
    deadline: CommandDeadline,
    request: &CommandRequest,
    cancellation: &ProbeCancellation,
) -> CommandOutput {
    let stdout_capture = stdout_reader.finish("stdout", deadline.at, request, cancellation);
    let stderr_capture = stderr_reader.finish("stderr", deadline.at, request, cancellation);
    if matches!(termination, CommandTermination::Exited(_)) {
        if stdout_capture.cancelled || stderr_capture.cancelled {
            termination = CommandTermination::Cancelled;
        } else if stdout_capture.deadline_exceeded || stderr_capture.deadline_exceeded {
            termination = deadline.expired_termination();
        }
    }

    let stdout = stdout_capture.output;
    let stdout_truncated = stdout_capture.truncated;
    let stdout_error = stdout_capture.error;
    let mut stderr = stderr_capture.output;
    let stderr_truncated = stderr_capture.truncated;
    let stderr_error = stderr_capture.error;
    let integrity_error = combine_errors(wait_error, combine_errors(stdout_error, stderr_error));
    if matches!(termination, CommandTermination::Exited(Some(0))) && integrity_error.is_some() {
        termination = CommandTermination::ExecutionIntegrityFailed;
    }
    if let Some(error) = integrity_error {
        if !stderr.is_empty() {
            stderr.push_str("; ");
        }
        stderr.push_str(&error);
    }

    CommandOutput {
        termination,
        stdout,
        stderr,
        truncated: stdout_truncated || stderr_truncated,
    }
}

#[derive(Clone, Copy, Debug)]
struct CommandDeadline {
    at: Instant,
    aggregate_is_limit: bool,
}

impl CommandDeadline {
    fn new(request: &CommandRequest, started_at: Instant) -> Self {
        let command_deadline = started_at
            .checked_add(request.timeout())
            .unwrap_or(started_at);
        let at = request
            .aggregate_deadline
            .map_or(command_deadline, |aggregate| {
                aggregate.min(command_deadline)
            });
        let aggregate_is_limit = request
            .aggregate_deadline
            .is_some_and(|aggregate| aggregate <= command_deadline);
        Self {
            at,
            aggregate_is_limit,
        }
    }

    const fn expired_termination(self) -> CommandTermination {
        if self.aggregate_is_limit {
            CommandTermination::CleanupDeadlineExceeded
        } else {
            CommandTermination::TimedOut
        }
    }
}

fn combine_errors(first: Option<String>, second: Option<String>) -> Option<String> {
    match (first, second) {
        (Some(first), Some(second)) => Some(format!("{first}; {second}")),
        (Some(error), None) | (None, Some(error)) => Some(error),
        (None, None) => None,
    }
}

#[derive(Debug)]
struct CappedReader {
    receiver: Receiver<Result<(String, bool), String>>,
    completed: Option<Result<(String, bool), String>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl CappedReader {
    #[cfg(unix)]
    fn spawn<R>(reader: R, limit: usize, stream: &str) -> Result<Self, String>
    where
        R: std::io::Read + std::os::fd::AsFd + Send + 'static,
    {
        let flags = rustix::fs::fcntl_getfl(&reader)
            .map_err(|error| format!("could not inspect pipe flags: {error}"))?;
        rustix::fs::fcntl_setfl(&reader, flags | rustix::fs::OFlags::NONBLOCK)
            .map_err(|error| format!("could not enable nonblocking pipe reads: {error}"))?;
        Self::spawn_interruptible(reader, limit, stream)
    }

    #[cfg(not(unix))]
    fn spawn<R>(_reader: R, _limit: usize, _stream: &str) -> Result<Self, String>
    where
        R: std::io::Read + Send + 'static,
    {
        Err("interruptible child output capture is not implemented on this platform".to_owned())
    }

    fn spawn_interruptible<R>(reader: R, limit: usize, stream: &str) -> Result<Self, String>
    where
        R: std::io::Read + Send + 'static,
    {
        let (sender, receiver) = mpsc::sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::Builder::new()
            .name(format!("automata-{stream}"))
            .spawn(move || {
                let output = read_capped(reader, limit, &worker_stop);
                let _ignored = sender.send(output);
            })
            .map_err(|error| format!("could not spawn capture worker: {error}"))?;
        Ok(Self {
            receiver,
            completed: None,
            stop,
            worker: Some(worker),
        })
    }

    fn finish(
        mut self,
        stream: &str,
        deadline: Instant,
        request: &CommandRequest,
        cancellation: &ProbeCancellation,
    ) -> CapturedStream {
        loop {
            self.poll();
            if let Some(result) = self.completed.take() {
                return match result {
                    Ok((output, truncated)) => CapturedStream::complete(output, truncated),
                    Err(error) => CapturedStream::failed(format!(
                        "{stream} capture worker stopped unexpectedly: {error}"
                    )),
                };
            }
            if request.cancellation_requested(cancellation) {
                return CapturedStream::cancelled(format!(
                    "{stream} capture interrupted by shutdown"
                ));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return CapturedStream::deadline_exceeded(format!(
                    "{stream} pipe remained open after the command deadline"
                ));
            }
            match self.receiver.recv_timeout(POLL_INTERVAL.min(remaining)) {
                Ok(output) => self.completed = Some(output),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    self.completed = Some(Err("result channel disconnected".to_owned()));
                }
            }
        }
    }

    fn poll(&mut self) {
        if self.completed.is_some() {
            return;
        }
        match self.receiver.try_recv() {
            Ok(output) => self.completed = Some(output),
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.completed = Some(Err("result channel disconnected".to_owned()));
            }
        }
    }
}

impl Drop for CappedReader {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            let _worker_result = worker.join();
        }
    }
}

#[derive(Debug)]
struct CapturedStream {
    output: String,
    truncated: bool,
    error: Option<String>,
    deadline_exceeded: bool,
    cancelled: bool,
}

impl CapturedStream {
    fn complete(output: String, truncated: bool) -> Self {
        Self {
            output,
            truncated,
            error: None,
            deadline_exceeded: false,
            cancelled: false,
        }
    }

    fn failed(error: String) -> Self {
        Self {
            output: String::new(),
            truncated: true,
            error: Some(error),
            deadline_exceeded: false,
            cancelled: false,
        }
    }

    fn deadline_exceeded(error: String) -> Self {
        Self {
            deadline_exceeded: true,
            ..Self::failed(error)
        }
    }

    fn cancelled(error: String) -> Self {
        Self {
            cancelled: true,
            ..Self::failed(error)
        }
    }
}

fn read_capped<R>(mut reader: R, limit: usize, stop: &AtomicBool) -> Result<(String, bool), String>
where
    R: std::io::Read,
{
    let mut retained = Vec::with_capacity(limit.min(16 * 1024));
    let mut buffer = [0_u8; 8 * 1024];
    let mut truncated = false;
    loop {
        if stop.load(Ordering::Acquire) {
            break;
        }
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                let remaining = limit.saturating_sub(retained.len());
                let keep = remaining.min(count);
                retained.extend_from_slice(&buffer[..keep]);
                truncated |= keep < count;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::park_timeout(POLL_INTERVAL);
            }
            Err(error) => return Err(format!("could not read child output: {error}")),
        }
    }
    Ok((String::from_utf8_lossy(&retained).into_owned(), truncated))
}

#[cfg(unix)]
fn terminate_process_group(child: &mut Child, grace: Duration) -> Option<String> {
    let process_group = child.id();
    let term_error = signal_process_group(process_group, rustix::process::Signal::TERM)
        .err()
        .filter(|error| *error != rustix::io::Errno::SRCH);
    let grace_deadline = Instant::now() + grace;
    let mut leader_exited = false;
    while Instant::now() < grace_deadline {
        match poll_child_exit(child) {
            Ok(ChildExitObservation::Exited(_status)) => {
                leader_exited = true;
                break;
            }
            Ok(ChildExitObservation::Running) => thread::sleep(POLL_INTERVAL),
            Err(_error) => break,
        }
    }

    let kill_error = signal_process_group(process_group, rustix::process::Signal::KILL)
        .err()
        .filter(|error| *error != rustix::io::Errno::SRCH);
    let fallback_error = if leader_exited {
        None
    } else {
        child.kill().err().map(|error| error.to_string())
    };
    let wait_error = child.wait().err().map(|error| error.to_string());

    let mut errors = Vec::new();
    if let Some(error) = term_error {
        errors.push(format!(
            "could not signal process group {process_group} with TERM: {error}"
        ));
    }
    if let Some(error) = kill_error {
        errors.push(format!(
            "could not signal process group {process_group} with KILL: {error}"
        ));
    }
    if let Some(error) = fallback_error {
        errors.push(format!(
            "could not kill process leader {process_group}: {error}"
        ));
    }
    if let Some(error) = wait_error {
        errors.push(format!(
            "could not reap process leader {process_group}: {error}"
        ));
    }
    (!errors.is_empty()).then(|| errors.join("; "))
}

#[cfg(unix)]
fn terminate_remaining_process_group(child: &Child) -> Option<String> {
    let process_group = child.id();
    match signal_process_group(process_group, rustix::process::Signal::KILL) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => None,
        Err(error) => Some(format!(
            "could not terminate descendants in process group {process_group}: {error}"
        )),
    }
}

#[cfg(not(unix))]
fn terminate_process_group(child: &mut Child, _grace: Duration) -> Option<String> {
    let kill_error = child.kill().err().map(|error| error.to_string());
    let wait_error = child.wait().err().map(|error| error.to_string());
    combine_errors(kill_error, wait_error)
}

#[cfg(unix)]
fn signal_process_group(
    process_group: u32,
    signal: rustix::process::Signal,
) -> rustix::io::Result<()> {
    let raw_process_group =
        i32::try_from(process_group).map_err(|_error| rustix::io::Errno::INVAL)?;
    let process_group =
        rustix::process::Pid::from_raw(raw_process_group).ok_or(rustix::io::Errno::INVAL)?;
    rustix::process::kill_process_group(process_group, signal)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{Cursor, Error, Read},
        path::{Path, PathBuf},
    };

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    #[cfg(unix)]
    use automata_ci_sandbox_podman::{
        PodmanBinary, PodmanLaunchTrust, PodmanLaunchTrustHandle, PodmanStateRoot,
    };
    #[cfg(unix)]
    use uuid::Uuid;

    use super::*;

    #[cfg(unix)]
    #[derive(Debug)]
    struct TestLaunchTrust;

    #[cfg(unix)]
    impl PodmanLaunchTrust for TestLaunchTrust {
        fn revalidate(&self) -> bool {
            true
        }
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(Error::other("injected capture failure"))
        }
    }

    #[test]
    fn capture_failure_cannot_preserve_a_successful_termination() {
        let request = CommandRequest::new("unused", Duration::from_secs(1), 128);
        let deadline = CommandDeadline::new(&request, Instant::now());
        let stdout = CappedReader::spawn_interruptible(FailingReader, 128, "stdout")
            .expect("capture worker must start");
        let stderr =
            CappedReader::spawn_interruptible(Cursor::new(Vec::<u8>::new()), 128, "stderr")
                .expect("capture worker must start");

        let output = assemble_output(
            CommandTermination::Exited(Some(0)),
            None,
            stdout,
            stderr,
            deadline,
            &request,
            &ProbeCancellation::default(),
        );

        assert_eq!(
            output.termination(),
            &CommandTermination::ExecutionIntegrityFailed
        );
        assert!(output.stderr().contains("injected capture failure"));
        assert!(!output.succeeded());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn child_exit_observation_keeps_the_leader_waitable() {
        use std::os::unix::process::CommandExt as _;

        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg("exit 23").process_group(0);
        let mut child = command.spawn().expect("test child must start");
        let deadline = Instant::now() + Duration::from_secs(2);
        let observed = loop {
            match poll_child_exit(&mut child).expect("exit observation must succeed") {
                ChildExitObservation::Exited(status) => break status,
                ChildExitObservation::Running if Instant::now() < deadline => {
                    thread::sleep(POLL_INTERVAL);
                }
                ChildExitObservation::Running => {
                    panic!("test child did not exit before the deadline");
                }
            }
        };

        assert_eq!(observed, Some(23));
        let reaped = child
            .try_wait()
            .expect("the observed child must remain waitable")
            .expect("the observed child must have exited");
        assert_eq!(reaped.code(), Some(23));
    }

    #[cfg(unix)]
    #[test]
    fn configured_executor_uses_exact_binary_base_arguments_and_clean_environment() {
        let fixture = TestDirectory::new();
        let home = fixture.child("home");
        let runtime = fixture.child("runtime");
        let state = fixture.child("state");
        let helpers = fixture.child("private/usr/sbin");
        for directory in [&home, &runtime, &state, &helpers] {
            fs::create_dir_all(directory).expect("configured directory must be creatable");
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("configured directory permissions must be private");
        }
        let binary = fixture.child("configured-podman");
        fs::write(
            &binary,
            b"#!/bin/sh\nprintf '%s\\n' \"$HOME\" \"$PATH\" \"$XDG_RUNTIME_DIR\" \"$TMPDIR\" \"${CARGO_HOME-unset}\" \"$@\"\n",
        )
        .expect("configured executable must be writable");
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))
            .expect("configured executable must be executable");

        let environment = PodmanProcessEnvironment::new(
            home.clone(),
            runtime.clone(),
            state.clone(),
            helpers.clone(),
            "/usr/bin/true",
            "/usr/bin/true",
            "/usr/bin/true",
            "/usr/bin/true",
        )
        .expect("configured environment must be valid");
        let options = PodmanOptions::new(
            PodmanBinary::new(binary).expect("configured binary must be valid"),
            PodmanStateRoot::existing(state.clone()).expect("state root must be valid"),
            environment,
        )
        .expect("coherent Podman options")
        .with_launch_trust(PodmanLaunchTrustHandle::new(Arc::new(TestLaunchTrust)));
        options.prepare_state().expect("prepare exact Podman state");
        let executor = ConfiguredSystemCommandExecutor::from_options(&options);
        let mut request = CommandRequest::new("podman", Duration::from_secs(2), 4_096);
        request.arg("--remote=false").arg("--version");

        let output = executor.execute(&request, &ProbeCancellation::default());

        assert_eq!(output.termination(), &CommandTermination::Exited(Some(0)));
        assert_eq!(
            output.stdout().lines().collect::<Vec<_>>(),
            vec![
                home.to_str().expect("home path must be UTF-8"),
                helpers.to_str().expect("helper path must be UTF-8"),
                runtime.to_str().expect("runtime path must be UTF-8"),
                state
                    .join("process-transient")
                    .to_str()
                    .expect("temporary path must be UTF-8"),
                "unset",
                "--remote=false",
                &format!("--root={}", state.join("podman-graph").display()),
                &format!(
                    "--runroot={}",
                    runtime.join("automata-ci-podman/shared-run").display()
                ),
                "--storage-driver=vfs",
                "--storage-opt=",
                "--transient-store=false",
                &format!("--hooks-dir={}", state.join("empty-hooks").display()),
                &format!(
                    "--cdi-spec-dir={}",
                    state.join("podman-system-config/empty-cdi").display()
                ),
                &format!(
                    "--default-mounts-file={}",
                    state.join("podman-system-config/mounts.conf").display()
                ),
                &format!(
                    "--network-config-dir={}",
                    state.join("podman-graph/networks").display()
                ),
                &format!(
                    "--tmpdir={}",
                    runtime.join("automata-ci-podman/shared-tmp").display()
                ),
                &format!(
                    "--volumepath={}",
                    state.join("podman-graph/volumes").display()
                ),
                "--events-backend=none",
                "--conmon=/usr/bin/true",
                "--runtime=/usr/bin/true",
                "--cgroup-manager=cgroupfs",
                "--version",
            ]
        );

        let disallowed = CommandRequest::new("sh", Duration::from_secs(2), 4_096);
        assert_eq!(
            executor
                .execute(&disallowed, &ProbeCancellation::default())
                .termination(),
            &CommandTermination::FailedToStart
        );
    }

    #[cfg(unix)]
    struct TestDirectory {
        root: PathBuf,
    }

    #[cfg(unix)]
    impl TestDirectory {
        fn new() -> Self {
            let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .and_then(Path::parent)
                .expect("runner crate must be nested beneath the workspace root");
            let root = workspace_root
                .join("target/agent-scratch/runner")
                .join(format!("command-test-{}", Uuid::new_v4().simple()));
            fs::create_dir_all(&root).expect("test directory must be creatable");
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("test directory permissions must be private");
            Self { root }
        }

        fn child(&self, name: &str) -> PathBuf {
            self.root.join(name)
        }
    }

    #[cfg(unix)]
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.root);
        }
    }
}
