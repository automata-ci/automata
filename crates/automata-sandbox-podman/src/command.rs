use std::{
    ffi::{OsStr, OsString},
    fmt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError},
    },
    thread,
    time::{Duration, Instant},
};

use automata_execution::{Cancellation, ExecutionEnvironment};

use crate::{PodmanConfigurationError, config};

const POLL_INTERVAL: Duration = Duration::from_millis(20);
const TERMINATION_GRACE: Duration = Duration::from_millis(250);

/// Explicit allowlisted environment for local rootless Podman processes.
#[derive(Clone, Eq, PartialEq)]
pub struct PodmanProcessEnvironment {
    home: PathBuf,
    runtime_directory: Option<PathBuf>,
    temporary_directory: Option<PathBuf>,
    executable_search_path: OsString,
}

impl PodmanProcessEnvironment {
    /// Creates the complete environment passed after `env_clear`.
    ///
    /// # Errors
    ///
    /// Rejects relative/traversing paths and empty search paths.
    pub fn new(
        home: impl Into<PathBuf>,
        runtime_directory: Option<PathBuf>,
        executable_search_path: OsString,
    ) -> Result<Self, PodmanConfigurationError> {
        let home = home.into();
        let valid = config::safe_host_path(&home)
            && runtime_directory
                .as_deref()
                .is_none_or(config::safe_host_path)
            && config::safe_search_path(&executable_search_path);
        valid
            .then_some(Self {
                home,
                runtime_directory,
                temporary_directory: None,
                executable_search_path,
            })
            .ok_or(PodmanConfigurationError::InvalidProcessEnvironment)
    }

    #[must_use]
    pub fn home(&self) -> &Path {
        &self.home
    }

    #[must_use]
    pub fn runtime_directory(&self) -> Option<&Path> {
        self.runtime_directory.as_deref()
    }

    #[must_use]
    pub fn executable_search_path(&self) -> &OsStr {
        &self.executable_search_path
    }

    #[must_use]
    pub fn temporary_directory(&self) -> Option<&Path> {
        self.temporary_directory.as_deref()
    }

    pub(crate) fn with_temporary_directory(mut self, path: PathBuf) -> Self {
        self.temporary_directory = Some(path);
        self
    }
}

impl fmt::Debug for PodmanProcessEnvironment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PodmanProcessEnvironment")
            .field("home", &self.home)
            .field("runtime_directory", &self.runtime_directory)
            .field("temporary_directory", &self.temporary_directory)
            .field("executable_search_path", &self.executable_search_path)
            .field("forwarded_credentials", &false)
            .finish()
    }
}

/// One argv-only, bounded Podman process request.
#[derive(Clone)]
pub struct CommandRequest {
    program: PathBuf,
    arguments: Vec<OsString>,
    timeout: Duration,
    aggregate_deadline: Instant,
    output_limit: usize,
    child_environment: ExecutionEnvironment,
}

impl CommandRequest {
    #[must_use]
    pub fn new(
        program: PathBuf,
        arguments: Vec<OsString>,
        timeout: Duration,
        aggregate_deadline: Instant,
        output_limit: usize,
    ) -> Self {
        Self {
            program,
            arguments,
            timeout,
            aggregate_deadline,
            output_limit,
            child_environment: ExecutionEnvironment::empty(),
        }
    }

    pub(crate) fn with_child_environment(mut self, environment: ExecutionEnvironment) -> Self {
        self.child_environment = environment;
        self
    }

    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    #[must_use]
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    #[must_use]
    pub const fn aggregate_deadline(&self) -> Instant {
        self.aggregate_deadline
    }

    #[must_use]
    pub const fn output_limit(&self) -> usize {
        self.output_limit
    }

    /// Environment copied into the Podman child process for name-only
    /// `podman exec --env NAME` forwarding. Values are always redacted by
    /// `Debug` and never form part of argv.
    #[must_use]
    pub const fn child_environment(&self) -> &ExecutionEnvironment {
        &self.child_environment
    }
}

impl fmt::Debug for CommandRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandRequest")
            .field("program", &self.program)
            .field("argument_count", &self.arguments.len())
            .field("arguments", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .field("output_limit", &self.output_limit)
            .field("child_environment", &self.child_environment)
            .finish_non_exhaustive()
    }
}

/// Bounded process termination classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandTermination {
    Exited(Option<i32>),
    TimedOut,
    Cancelled,
    FailedToStart,
}

/// Bounded command output. Debug formatting redacts output bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct CommandOutput {
    termination: CommandTermination,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    truncated: bool,
}

impl CommandOutput {
    #[must_use]
    pub fn success(stdout: impl Into<Vec<u8>>) -> Self {
        Self {
            termination: CommandTermination::Exited(Some(0)),
            stdout: stdout.into(),
            stderr: Vec::new(),
            truncated: false,
        }
    }

    #[must_use]
    pub fn failure(code: i32, stderr: impl Into<Vec<u8>>) -> Self {
        Self {
            termination: CommandTermination::Exited(Some(code)),
            stdout: Vec::new(),
            stderr: stderr.into(),
            truncated: false,
        }
    }

    #[must_use]
    pub fn terminated(termination: CommandTermination) -> Self {
        Self {
            termination,
            stdout: Vec::new(),
            stderr: Vec::new(),
            truncated: false,
        }
    }

    #[must_use]
    pub const fn termination(&self) -> CommandTermination {
        self.termination
    }

    #[must_use]
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    #[must_use]
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    #[must_use]
    pub const fn succeeded(&self) -> bool {
        matches!(self.termination, CommandTermination::Exited(Some(0)))
    }

    #[must_use]
    pub const fn was_truncated(&self) -> bool {
        self.truncated
    }
}

impl fmt::Debug for CommandOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandOutput")
            .field("termination", &self.termination)
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr_bytes", &self.stderr.len())
            .field("output", &"[REDACTED]")
            .field("truncated", &self.truncated)
            .finish()
    }
}

/// Injectable Podman process boundary.
pub trait PodmanCommandExecutor: fmt::Debug + Send + Sync {
    fn execute(
        &self,
        request: &CommandRequest,
        environment: &PodmanProcessEnvironment,
        cancellation: &dyn Cancellation,
    ) -> CommandOutput;
}

/// Safe-Rust local process adapter with process-group cancellation.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCommandExecutor;

impl PodmanCommandExecutor for SystemCommandExecutor {
    fn execute(
        &self,
        request: &CommandRequest,
        environment: &PodmanProcessEnvironment,
        cancellation: &dyn Cancellation,
    ) -> CommandOutput {
        execute_system(request, environment, cancellation)
    }
}

/// Long-running, local Podman subprocess owned by one adapter operation.
pub(crate) struct PersistentPodmanProcess {
    child: Child,
    active: bool,
}

impl fmt::Debug for PersistentPodmanProcess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistentPodmanProcess")
            .field("process_id", &self.child.id())
            .finish_non_exhaustive()
    }
}

impl PersistentPodmanProcess {
    pub(crate) fn spawn(
        program: &Path,
        arguments: &[OsString],
        environment: &PodmanProcessEnvironment,
    ) -> Result<Self, ()> {
        let mut command = Command::new(program);
        command
            .args(arguments)
            .env_clear()
            .env("HOME", environment.home())
            .env("PATH", environment.executable_search_path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(runtime) = environment.runtime_directory() {
            command.env("XDG_RUNTIME_DIR", runtime);
        }
        if let Some(temporary) = environment.temporary_directory() {
            command.env("TMPDIR", temporary);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.process_group(0);
        }
        command
            .spawn()
            .map(|child| Self {
                child,
                active: true,
            })
            .map_err(|_| ())
    }

    pub(crate) fn has_exited(&mut self) -> Result<bool, ()> {
        let exited = self
            .child
            .try_wait()
            .map(|status| status.is_some())
            .map_err(|_| ())?;
        self.active &= !exited;
        Ok(exited)
    }

    pub(crate) fn stop(&mut self) {
        if self.active {
            terminate_process_group(&mut self.child, TERMINATION_GRACE);
            self.active = false;
        }
    }
}

impl Drop for PersistentPodmanProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

fn execute_system(
    request: &CommandRequest,
    environment: &PodmanProcessEnvironment,
    cancellation: &dyn Cancellation,
) -> CommandOutput {
    if cancellation.is_cancelled() {
        return CommandOutput::terminated(CommandTermination::Cancelled);
    }
    let now = Instant::now();
    if now >= request.aggregate_deadline() {
        return CommandOutput::terminated(CommandTermination::TimedOut);
    }
    let deadline = now
        .checked_add(request.timeout())
        .unwrap_or(now)
        .min(request.aggregate_deadline());
    let Ok((mut child, stdout, stderr)) = spawn_child(request, environment) else {
        return CommandOutput::terminated(CommandTermination::FailedToStart);
    };
    let budget = Arc::new(AtomicUsize::new(request.output_limit()));
    let Ok(stdout) = CappedReader::spawn(stdout, Arc::clone(&budget)) else {
        terminate_process_group(&mut child, Duration::ZERO);
        return CommandOutput::terminated(CommandTermination::FailedToStart);
    };
    let Ok(stderr) = CappedReader::spawn(stderr, budget) else {
        terminate_process_group(&mut child, Duration::ZERO);
        return CommandOutput::terminated(CommandTermination::FailedToStart);
    };
    let termination = wait_for_child(&mut child, deadline, cancellation);
    #[cfg(unix)]
    if matches!(termination, CommandTermination::Exited(_)) {
        terminate_remaining_process_group(&child);
    }
    let stdout = stdout.finish(deadline);
    let stderr = stderr.finish(deadline);
    CommandOutput {
        termination,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
        truncated: stdout.truncated || stderr.truncated,
    }
}

fn spawn_child(
    request: &CommandRequest,
    environment: &PodmanProcessEnvironment,
) -> Result<(Child, std::process::ChildStdout, std::process::ChildStderr), ()> {
    if request
        .child_environment()
        .values()
        .iter()
        .any(|variable| !child_environment_name_is_safe(variable.name().as_str()))
    {
        return Err(());
    }
    let mut command = Command::new(request.program());
    command
        .args(request.arguments())
        .env_clear()
        .env("HOME", environment.home())
        .env("PATH", environment.executable_search_path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(runtime) = environment.runtime_directory() {
        command.env("XDG_RUNTIME_DIR", runtime);
    }
    if let Some(temporary) = environment.temporary_directory() {
        command.env("TMPDIR", temporary);
    }
    for variable in request.child_environment().values() {
        command.env(variable.name().as_str(), variable.value().expose());
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let mut child = command.spawn().map_err(|_| ())?;
    let stdout = child.stdout.take().ok_or_else(|| {
        terminate_process_group(&mut child, Duration::ZERO);
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        terminate_process_group(&mut child, Duration::ZERO);
    })?;
    Ok((child, stdout, stderr))
}

pub(crate) fn environment_file_name(name: &str) -> bool {
    matches!(
        name,
        "HOME"
            | "PATH"
            | "TMPDIR"
            | "GCONV_PATH"
            | "GLIBC_TUNABLES"
            | "LOCPATH"
            | "NLSPATH"
            | "HOSTALIASES"
            | "RES_OPTIONS"
            | "LOCALDOMAIN"
            | "GODEBUG"
            | "GOMAXPROCS"
            | "GOMEMLIMIT"
            | "GOTRACEBACK"
            | "SSL_CERT_FILE"
            | "SSL_CERT_DIR"
            | "CURL_CA_BUNDLE"
            | "SSH_AUTH_SOCK"
            | "DBUS_SESSION_BUS_ADDRESS"
            | "NOTIFY_SOCKET"
            | "LISTEN_FDS"
            | "LISTEN_PID"
            | "LISTEN_FDNAMES"
    ) || name.starts_with("LD_")
        || name.starts_with("DYLD_")
        || name.starts_with("MALLOC_")
}

pub(crate) fn provider_control_environment_name(name: &str) -> bool {
    matches!(
        name,
        "XDG_RUNTIME_DIR"
            | "XDG_CONFIG_HOME"
            | "XDG_DATA_HOME"
            | "CONTAINER_HOST"
            | "CONTAINER_CONNECTION"
            | "CONTAINER_SSHKEY"
            | "CONTAINER_CERT_PATH"
            | "CONTAINER_TLSVERIFY"
            | "CONTAINERS_CONF"
            | "CONTAINERS_CONF_OVERRIDE"
            | "CONTAINERS_STORAGE_CONF"
            | "CONTAINERS_REGISTRIES_CONF"
            | "CONTAINERS_POLICY"
            | "PODMAN_CONNECTIONS_CONF"
            | "PODMAN_NO_PAUSE_PROCESS"
            | "_CONTAINERS_USERNS_CONFIGURED"
            | "REGISTRY_AUTH_FILE"
            | "DOCKER_CONFIG"
            | "DOCKER_HOST"
            | "DOCKER_CERT_PATH"
            | "DOCKER_TLS_VERIFY"
            | "STORAGE_DRIVER"
            | "STORAGE_OPTS"
    )
}

fn child_environment_name_is_safe(name: &str) -> bool {
    !environment_file_name(name) && !provider_control_environment_name(name)
}

fn wait_for_child(
    child: &mut Child,
    deadline: Instant,
    cancellation: &dyn Cancellation,
) -> CommandTermination {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return CommandTermination::Exited(status.code()),
            Ok(None) if cancellation.is_cancelled() => {
                terminate_process_group(child, TERMINATION_GRACE);
                return CommandTermination::Cancelled;
            }
            Ok(None) if Instant::now() >= deadline => {
                terminate_process_group(child, Duration::ZERO);
                return CommandTermination::TimedOut;
            }
            Ok(None) => {
                thread::sleep(
                    POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(_) => {
                terminate_process_group(child, Duration::ZERO);
                return CommandTermination::FailedToStart;
            }
        }
    }
}

#[derive(Debug)]
struct CappedReader {
    receiver: Receiver<Captured>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl CappedReader {
    #[cfg(unix)]
    fn spawn<R>(reader: R, remaining: Arc<AtomicUsize>) -> Result<Self, ()>
    where
        R: std::io::Read + std::os::fd::AsFd + Send + 'static,
    {
        let flags = rustix::fs::fcntl_getfl(&reader).map_err(|_| ())?;
        rustix::fs::fcntl_setfl(&reader, flags | rustix::fs::OFlags::NONBLOCK).map_err(|_| ())?;
        Ok(Self::spawn_interruptible(reader, remaining))
    }

    #[cfg(not(unix))]
    fn spawn<R>(_reader: R, _remaining: Arc<AtomicUsize>) -> Result<Self, ()>
    where
        R: std::io::Read + Send + 'static,
    {
        Err(())
    }

    fn spawn_interruptible<R>(reader: R, remaining: Arc<AtomicUsize>) -> Self
    where
        R: std::io::Read + Send + 'static,
    {
        let (sender, receiver) = mpsc::sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let _ = sender.send(read_capped(reader, &remaining, &worker_stop));
        });
        Self {
            receiver,
            stop,
            worker: Some(worker),
        }
    }

    fn finish(mut self, deadline: Instant) -> Captured {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let result = match self.receiver.recv_timeout(remaining.max(POLL_INTERVAL)) {
            Ok(captured) => captured,
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => Captured {
                bytes: Vec::new(),
                truncated: true,
            },
        };
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            let _ = worker.join();
        }
        result
    }
}

impl Drop for CappedReader {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            let _ = worker.join();
        }
    }
}

#[derive(Debug)]
struct Captured {
    bytes: Vec<u8>,
    truncated: bool,
}

fn read_capped<R>(mut reader: R, remaining: &AtomicUsize, stop: &AtomicBool) -> Captured
where
    R: std::io::Read,
{
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    let mut truncated = false;
    while !stop.load(Ordering::Acquire) {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                let keep = take_budget(remaining, count);
                bytes.extend_from_slice(&buffer[..keep]);
                truncated |= keep < count;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::park_timeout(POLL_INTERVAL);
            }
            Err(_) => break,
        }
    }
    Captured { bytes, truncated }
}

fn take_budget(remaining: &AtomicUsize, requested: usize) -> usize {
    let mut current = remaining.load(Ordering::Acquire);
    loop {
        let keep = current.min(requested);
        match remaining.compare_exchange_weak(
            current,
            current - keep,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return keep,
            Err(actual) => current = actual,
        }
    }
}

#[cfg(unix)]
fn terminate_process_group(child: &mut Child, grace: Duration) {
    let group = child.id();
    let _ = signal_group(group, rustix::process::Signal::TERM);
    let grace_deadline = Instant::now()
        .checked_add(grace)
        .unwrap_or_else(Instant::now);
    while Instant::now() < grace_deadline {
        if child.try_wait().ok().flatten().is_some() {
            break;
        }
        thread::sleep(POLL_INTERVAL);
    }
    let _ = signal_group(group, rustix::process::Signal::KILL);
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
fn terminate_remaining_process_group(child: &Child) {
    let _ = signal_group(child.id(), rustix::process::Signal::KILL);
}

#[cfg(unix)]
fn signal_group(group: u32, signal: rustix::process::Signal) -> rustix::io::Result<()> {
    let group = i32::try_from(group).map_err(|_| rustix::io::Errno::INVAL)?;
    let group = rustix::process::Pid::from_raw(group).ok_or(rustix::io::Errno::INVAL)?;
    rustix::process::kill_process_group(group, signal)
}

#[cfg(not(unix))]
fn terminate_process_group(child: &mut Child, _grace: Duration) {
    let _ = child.kill();
    let _ = child.wait();
}
