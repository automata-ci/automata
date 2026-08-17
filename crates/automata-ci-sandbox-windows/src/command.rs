use std::{
    ffi::OsString,
    fmt,
    io::{Read, Write as _},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use automata_ci_execution::Cancellation;

const POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_RUNTIME_INPUT_BYTES: usize = automata_ci_sandbox_guest::MAX_GUEST_FRAME_BYTES + 4;
const MAX_RUNTIME_OUTPUT_BYTES: usize = automata_ci_sandbox_guest::MAX_GUEST_FRAME_BYTES + 4;
const MAX_RUNTIME_ARGUMENTS: usize = 128;
const MAX_RUNTIME_ARGUMENT_UTF16: usize = 16 * 1024;
const MAX_RUNTIME_PROGRAM_UTF16: usize = 1024;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Sanitized reason a container-runtime command request was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeCommandRequestError {
    /// The executable was not an absolute, NUL-free path.
    InvalidProgram,
    /// The argument vector exceeded its count/UTF-16 bound or contained NUL.
    InvalidArguments,
    /// The deadline was zero or exceeded the lifecycle hard bound.
    InvalidTimeout,
    /// The retained-output limit was zero or exceeded the protocol hard bound.
    InvalidOutputLimit,
    /// Anonymous standard input exceeded the protocol hard bound.
    InputTooLarge,
}

/// One bounded, argv-only invocation of the configured Windows container CLI.
pub struct RuntimeCommandRequest {
    program: PathBuf,
    arguments: Vec<OsString>,
    stdin: Option<Arc<[u8]>>,
    timeout: Duration,
    output_limit: usize,
}

impl RuntimeCommandRequest {
    /// Creates a request without standard-input bytes.
    ///
    /// # Errors
    ///
    /// Rejects a relative executable, empty/oversized timeout, excessive
    /// output, or argument values containing embedded NUL characters.
    pub fn new(
        program: impl Into<PathBuf>,
        arguments: Vec<OsString>,
        timeout: Duration,
        output_limit: usize,
    ) -> Result<Self, RuntimeCommandRequestError> {
        use std::os::windows::ffi::OsStrExt as _;

        let program = program.into();
        let program_units = program.as_os_str().encode_wide().count();
        if !program.is_absolute()
            || program_units == 0
            || program_units > MAX_RUNTIME_PROGRAM_UTF16
            || program.as_os_str().encode_wide().any(|value| value == 0)
        {
            return Err(RuntimeCommandRequestError::InvalidProgram);
        }
        let argument_units = arguments.iter().try_fold(0_usize, |total, argument| {
            let units = argument.encode_wide().count();
            if argument.encode_wide().any(|value| value == 0) {
                None
            } else {
                total.checked_add(units.checked_add(1)?)
            }
        });
        if arguments.len() > MAX_RUNTIME_ARGUMENTS
            || argument_units.is_none_or(|units| units > MAX_RUNTIME_ARGUMENT_UTF16)
        {
            return Err(RuntimeCommandRequestError::InvalidArguments);
        }
        if timeout.is_zero()
            || timeout > Duration::from_hours(24).saturating_add(Duration::from_mins(10))
        {
            return Err(RuntimeCommandRequestError::InvalidTimeout);
        }
        if output_limit == 0 || output_limit > MAX_RUNTIME_OUTPUT_BYTES {
            return Err(RuntimeCommandRequestError::InvalidOutputLimit);
        }
        Ok(Self {
            program,
            arguments,
            stdin: None,
            timeout,
            output_limit,
        })
    }

    /// Supplies bounded anonymous standard-input bytes.
    ///
    /// # Errors
    ///
    /// Rejects input larger than the guest protocol's hard frame bound.
    pub fn with_stdin(mut self, stdin: Vec<u8>) -> Result<Self, RuntimeCommandRequestError> {
        if stdin.len() > MAX_RUNTIME_INPUT_BYTES {
            return Err(RuntimeCommandRequestError::InputTooLarge);
        }
        self.stdin = Some(Arc::from(stdin));
        Ok(self)
    }

    /// Returns the exact executable path.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// Returns the exact runtime argument vector.
    #[must_use]
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    /// Returns the anonymous input bytes, when present.
    #[must_use]
    pub fn stdin(&self) -> Option<&[u8]> {
        self.stdin.as_deref()
    }

    /// Returns the process deadline measured from launch.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Returns the aggregate retained output limit.
    #[must_use]
    pub const fn output_limit(&self) -> usize {
        self.output_limit
    }
}

impl fmt::Debug for RuntimeCommandRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeCommandRequest")
            .field("program", &self.program)
            .field("argument_count", &self.arguments.len())
            .field("arguments", &"[REDACTED]")
            .field("stdin_bytes", &self.stdin.as_ref().map(|value| value.len()))
            .field("stdin", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .field("output_limit", &self.output_limit)
            .finish()
    }
}

/// Bounded termination classification for a container-runtime process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeCommandTermination {
    /// The process exited; `None` means Windows supplied no numeric status.
    Exited(Option<i32>),
    /// The configured deadline expired and the runtime client was reaped.
    TimedOut,
    /// Caller cancellation terminated and reaped the runtime client.
    Cancelled,
    /// The runtime client could not be started or safely observed.
    FailedToStart,
}

/// Bounded runtime output. Debug formatting redacts all bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct RuntimeCommandOutput {
    termination: RuntimeCommandTermination,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    truncated: bool,
    stdin_fully_written: bool,
}

impl RuntimeCommandOutput {
    /// Creates a successful synthetic output for an injected executor.
    #[cfg(test)]
    #[must_use]
    pub fn success(stdout: impl Into<Vec<u8>>) -> Self {
        Self {
            termination: RuntimeCommandTermination::Exited(Some(0)),
            stdout: stdout.into(),
            stderr: Vec::new(),
            truncated: false,
            stdin_fully_written: true,
        }
    }

    /// Creates a failed synthetic output for an injected executor.
    #[cfg(test)]
    #[must_use]
    pub fn failure(code: i32, stderr: impl Into<Vec<u8>>) -> Self {
        Self {
            termination: RuntimeCommandTermination::Exited(Some(code)),
            stdout: Vec::new(),
            stderr: stderr.into(),
            truncated: false,
            stdin_fully_written: true,
        }
    }

    /// Creates a synthetic terminal result without output.
    #[must_use]
    pub const fn terminated(termination: RuntimeCommandTermination) -> Self {
        Self {
            termination,
            stdout: Vec::new(),
            stderr: Vec::new(),
            truncated: false,
            stdin_fully_written: true,
        }
    }

    /// Returns the bounded process termination.
    #[must_use]
    pub const fn termination(&self) -> RuntimeCommandTermination {
        self.termination
    }

    /// Returns retained standard output.
    #[must_use]
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    /// Returns retained standard error.
    #[must_use]
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    /// Returns whether output was incomplete or exceeded its hard bound.
    #[must_use]
    pub const fn was_truncated(&self) -> bool {
        self.truncated
    }

    /// Returns whether every supplied input byte reached the child pipe.
    #[must_use]
    pub const fn stdin_was_fully_written(&self) -> bool {
        self.stdin_fully_written
    }

    /// Returns whether the runtime command exited successfully.
    #[must_use]
    pub const fn succeeded(&self) -> bool {
        matches!(self.termination, RuntimeCommandTermination::Exited(Some(0)))
            && self.stdin_fully_written
            && !self.truncated
    }
}

impl fmt::Debug for RuntimeCommandOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeCommandOutput")
            .field("termination", &self.termination)
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr_bytes", &self.stderr.len())
            .field("output", &"[REDACTED]")
            .field("truncated", &self.truncated)
            .field("stdin_fully_written", &self.stdin_fully_written)
            .finish()
    }
}

/// Injectable boundary for the local Windows container CLI.
pub trait RuntimeCommandExecutor: fmt::Debug + Send + Sync {
    /// Executes one exact request with no inherited environment.
    fn execute(
        &self,
        request: &RuntimeCommandRequest,
        cancellation: &dyn Cancellation,
    ) -> RuntimeCommandOutput;
}

/// Safe-Rust system-process implementation of the runtime boundary.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemRuntimeCommandExecutor;

impl RuntimeCommandExecutor for SystemRuntimeCommandExecutor {
    fn execute(
        &self,
        request: &RuntimeCommandRequest,
        cancellation: &dyn Cancellation,
    ) -> RuntimeCommandOutput {
        execute_system(request, cancellation)
    }
}

fn execute_system(
    request: &RuntimeCommandRequest,
    cancellation: &dyn Cancellation,
) -> RuntimeCommandOutput {
    use std::os::windows::process::CommandExt as _;

    if cancellation.disposition().requires_termination() {
        return RuntimeCommandOutput::terminated(RuntimeCommandTermination::Cancelled);
    }
    let mut command = Command::new(request.program());
    command
        .args(request.arguments())
        .env_clear()
        .stdin(if request.stdin().is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW);
    let Ok(mut child) = command.spawn() else {
        return RuntimeCommandOutput::terminated(RuntimeCommandTermination::FailedToStart);
    };
    capture_child(&mut child, request, cancellation)
}

fn capture_child(
    child: &mut Child,
    request: &RuntimeCommandRequest,
    cancellation: &dyn Cancellation,
) -> RuntimeCommandOutput {
    let Some(stdout) = child.stdout.take() else {
        return failed_child(child, request.stdin().is_some());
    };
    let Some(stderr) = child.stderr.take() else {
        return failed_child(child, request.stdin().is_some());
    };
    let stdout_limit = request.output_limit().saturating_add(1);
    let stderr_limit = stdout_limit;
    let stdout_reader = thread::spawn(move || read_bounded(stdout, stdout_limit));
    let stderr_reader = thread::spawn(move || read_bounded(stderr, stderr_limit));
    let stdin_writer = match (child.stdin.take(), request.stdin.clone()) {
        (Some(mut stdin), Some(bytes)) => Some(thread::spawn(move || {
            stdin.write_all(&bytes).and_then(|()| stdin.flush()).is_ok()
        })),
        (None, None) => None,
        _ => return failed_child(child, request.stdin().is_some()),
    };
    let deadline = Instant::now()
        .checked_add(request.timeout())
        .unwrap_or_else(Instant::now);
    let termination = loop {
        if cancellation.disposition().requires_termination() {
            terminate(child);
            break RuntimeCommandTermination::Cancelled;
        }
        if Instant::now() >= deadline {
            terminate(child);
            break RuntimeCommandTermination::TimedOut;
        }
        match child.try_wait() {
            Ok(Some(status)) => break RuntimeCommandTermination::Exited(status.code()),
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(_) => {
                terminate(child);
                break RuntimeCommandTermination::FailedToStart;
            }
        }
    };
    let stdout = stdout_reader.join().unwrap_or_default();
    let stderr = stderr_reader.join().unwrap_or_default();
    let stdin_fully_written = stdin_writer.is_none_or(|writer| writer.join().unwrap_or(false));
    let mut remaining = request.output_limit();
    let retained_stdout = stdout.len().min(remaining);
    remaining -= retained_stdout;
    let retained_stderr = stderr.len().min(remaining);
    let truncated = retained_stdout != stdout.len() || retained_stderr != stderr.len();
    RuntimeCommandOutput {
        termination,
        stdout: stdout[..retained_stdout].to_vec(),
        stderr: stderr[..retained_stderr].to_vec(),
        truncated,
        stdin_fully_written,
    }
}

fn read_bounded(mut reader: impl Read, limit: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(limit.min(16 * 1024));
    let _ = reader
        .by_ref()
        .take(u64::try_from(limit).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes);
    bytes
}

fn failed_child(child: &mut Child, had_stdin: bool) -> RuntimeCommandOutput {
    terminate(child);
    let mut output = RuntimeCommandOutput::terminated(RuntimeCommandTermination::FailedToStart);
    output.stdin_fully_written = !had_stdin;
    output
}

fn terminate(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_requests_are_bounded_and_debug_redacted() {
        let request = RuntimeCommandRequest::new(
            r"C:\Program Files\Docker\docker.exe",
            vec![OsString::from("secret-argument")],
            Duration::from_secs(1),
            1024,
        )
        .expect("bounded request")
        .with_stdin(b"secret-input".to_vec())
        .expect("bounded input");
        let debug = format!("{request:?}");
        assert!(!debug.contains("secret-argument"));
        assert!(!debug.contains("secret-input"));

        assert_eq!(
            RuntimeCommandRequest::new("relative.exe", Vec::new(), Duration::from_secs(1), 1,)
                .expect_err("relative program"),
            RuntimeCommandRequestError::InvalidProgram
        );
        assert_eq!(
            RuntimeCommandRequest::new(
                r"C:\docker.exe",
                vec![OsString::from("bad\0argument")],
                Duration::from_secs(1),
                1,
            )
            .expect_err("NUL argument"),
            RuntimeCommandRequestError::InvalidArguments
        );
        assert_eq!(
            RuntimeCommandRequest::new(
                r"C:\docker.exe",
                vec![OsString::from("x"); MAX_RUNTIME_ARGUMENTS + 1],
                Duration::from_secs(1),
                1,
            )
            .expect_err("argument count bound"),
            RuntimeCommandRequestError::InvalidArguments
        );
    }
}
