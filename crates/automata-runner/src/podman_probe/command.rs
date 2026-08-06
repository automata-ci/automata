use std::{
    ffi::{OsStr, OsString},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, TryRecvError},
    },
    thread,
    time::{Duration, Instant},
};

use super::ProbeCancellation;

const POLL_INTERVAL: Duration = Duration::from_millis(20);
const TERMINATION_GRACE: Duration = Duration::from_millis(200);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandPurpose {
    Provisioning,
    Cleanup,
}

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

    pub fn arg(&mut self, argument: impl Into<OsString>) -> &mut Self {
        self.arguments.push(argument.into());
        self
    }

    pub fn program(&self) -> &OsStr {
        &self.program
    }

    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    pub const fn output_limit(&self) -> usize {
        self.output_limit
    }

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandTermination {
    Exited(Option<i32>),
    TimedOut,
    Cancelled,
    CleanupDeadlineExceeded,
    FailedToStart,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutput {
    termination: CommandTermination,
    stdout: String,
    stderr: String,
    truncated: bool,
}

impl CommandOutput {
    pub fn success(stdout: impl Into<String>) -> Self {
        Self {
            termination: CommandTermination::Exited(Some(0)),
            stdout: stdout.into(),
            stderr: String::new(),
            truncated: false,
        }
    }

    pub fn failure(code: i32, stderr: impl Into<String>) -> Self {
        Self {
            termination: CommandTermination::Exited(Some(code)),
            stdout: String::new(),
            stderr: stderr.into(),
            truncated: false,
        }
    }

    pub fn timed_out(stderr: impl Into<String>) -> Self {
        Self {
            termination: CommandTermination::TimedOut,
            stdout: String::new(),
            stderr: stderr.into(),
            truncated: false,
        }
    }

    pub fn cancelled(stderr: impl Into<String>) -> Self {
        Self {
            termination: CommandTermination::Cancelled,
            stdout: String::new(),
            stderr: stderr.into(),
            truncated: false,
        }
    }

    pub fn cleanup_deadline_exceeded(stderr: impl Into<String>) -> Self {
        Self {
            termination: CommandTermination::CleanupDeadlineExceeded,
            stdout: String::new(),
            stderr: stderr.into(),
            truncated: false,
        }
    }

    pub fn failed_to_start(detail: impl Into<String>) -> Self {
        Self {
            termination: CommandTermination::FailedToStart,
            stdout: String::new(),
            stderr: detail.into(),
            truncated: false,
        }
    }

    pub const fn termination(&self) -> &CommandTermination {
        &self.termination
    }

    pub fn stdout(&self) -> &str {
        &self.stdout
    }

    pub fn stderr(&self) -> &str {
        &self.stderr
    }

    pub const fn succeeded(&self) -> bool {
        matches!(self.termination, CommandTermination::Exited(Some(0)))
    }

    pub const fn was_truncated(&self) -> bool {
        self.truncated
    }

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

pub trait CommandExecutor: Send + Sync {
    fn execute(&self, request: &CommandRequest, cancellation: &ProbeCancellation) -> CommandOutput;
}

#[derive(Debug, Default)]
pub struct SystemCommandExecutor;

impl CommandExecutor for SystemCommandExecutor {
    fn execute(&self, request: &CommandRequest, cancellation: &ProbeCancellation) -> CommandOutput {
        execute_system_command(request, cancellation)
    }
}

fn execute_system_command(
    request: &CommandRequest,
    cancellation: &ProbeCancellation,
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

    let (mut child, stdout_reader, stderr_reader) = match spawn_child(request) {
        Ok(process) => process,
        Err(output) => return output,
    };
    let deadline = CommandDeadline::new(request, Instant::now());
    let (termination, mut wait_error) =
        wait_for_termination(&mut child, request, cancellation, deadline);

    #[cfg(unix)]
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
) -> Result<(Child, CappedReader, CappedReader), CommandOutput> {
    let mut command = Command::new(request.program());
    command
        .args(request.arguments())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|error| CommandOutput::failed_to_start(error.to_string()))?;
    let stdout = child.stdout.take().ok_or_else(|| {
        let error = terminate_process_group(&mut child, TERMINATION_GRACE);
        CommandOutput::failed_to_start(
            error.unwrap_or_else(|| "spawned process had no stdout pipe".to_owned()),
        )
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        let error = terminate_process_group(&mut child, TERMINATION_GRACE);
        CommandOutput::failed_to_start(
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
    CommandOutput::failed_to_start(detail)
}

fn wait_for_termination(
    child: &mut Child,
    request: &CommandRequest,
    cancellation: &ProbeCancellation,
    deadline: CommandDeadline,
) -> (CommandTermination, Option<String>) {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return (CommandTermination::Exited(status.code()), None),
            Ok(None) if request.cancellation_requested(cancellation) => {
                let error = terminate_process_group(child, TERMINATION_GRACE);
                return (CommandTermination::Cancelled, error);
            }
            Ok(None) if Instant::now() >= deadline.at => {
                let error = terminate_process_group(child, Duration::ZERO);
                return (deadline.expired_termination(), error);
            }
            Ok(None) => {
                thread::sleep(
                    POLL_INTERVAL.min(deadline.at.saturating_duration_since(Instant::now())),
                );
            }
            Err(error) => {
                let termination_error = terminate_process_group(child, TERMINATION_GRACE);
                let detail = combine_errors(Some(error.to_string()), termination_error);
                return (CommandTermination::FailedToStart, detail);
            }
        }
    }
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
    let wait_error = combine_errors(wait_error, combine_errors(stdout_error, stderr_error));
    if let Some(error) = wait_error {
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
    receiver: Receiver<(String, bool)>,
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
                Ok(output) => self.completed = Some(Ok(output)),
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
            Ok(output) => self.completed = Some(Ok(output)),
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

fn read_capped<R>(mut reader: R, limit: usize, stop: &AtomicBool) -> (String, bool)
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
            Err(_error) => break,
        }
    }
    (String::from_utf8_lossy(&retained).into_owned(), truncated)
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
        match child.try_wait() {
            Ok(Some(_status)) => {
                leader_exited = true;
                break;
            }
            Ok(None) => thread::sleep(POLL_INTERVAL),
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
    let wait_error = if leader_exited {
        None
    } else {
        child.wait().err().map(|error| error.to_string())
    };

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
