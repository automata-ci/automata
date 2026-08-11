use std::{
    collections::HashMap,
    fmt, io,
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use automata_ci_execution::{
    Cancellation, CopyFromRequest, CopyToRequest, ExecutionCommand, ExecutionEndpoint,
    ExecutionError, ExecutionErrorKind, ExecutionOutput, ExecutionOutputRecord,
    ExecutionOutputStream, ExecutionStage, ExecutionTermination, MAX_EXECUTION_OUTPUT_RECORD_BYTES,
    MAX_EXECUTION_OUTPUT_RECORDS, OperationId, SandboxCapability, SandboxHandle, SandboxState,
    SignalRequest, WaitRequest,
};
use processkit::{Command, Outcome, OutputBufferPolicy, ProcessRunner as _};
use tokio::io::AsyncWrite;

use crate::{
    filesystem::{
        read_owned_file, require_directory, require_executable, resolve_owned_target,
        write_owned_file,
    },
    provider::{ENDPOINT_CAPABILITIES, ProviderInner, SandboxEntry, case_unique_environment},
};

const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(10);
const KILL_REAP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Default)]
pub(crate) struct EndpointState {
    exec: HashMap<OperationId, ExecReplay>,
    copy_to: HashMap<OperationId, CopyToReplay>,
    copy_from: HashMap<OperationId, CopyFromReplay>,
}

struct ExecReplay {
    request: ExecutionCommand,
    result: Result<ExecutionOutput, ExecutionError>,
}

struct CopyToReplay {
    request: CopyToRequest,
    result: Result<(), ExecutionError>,
}

struct CopyFromReplay {
    request: CopyFromRequest,
    result: Result<Vec<u8>, ExecutionError>,
}

#[derive(Clone)]
pub(crate) struct WindowsExecutionEndpoint {
    _provider: Arc<ProviderInner>,
    entry: Arc<SandboxEntry>,
}

impl WindowsExecutionEndpoint {
    pub(crate) const fn new(provider: Arc<ProviderInner>, entry: Arc<SandboxEntry>) -> Self {
        Self {
            _provider: provider,
            entry,
        }
    }

    fn require_running(&self, stage: ExecutionStage) -> Result<(), ExecutionError> {
        match self.entry.state() {
            Ok(SandboxState::Running) => Ok(()),
            Ok(SandboxState::Absent) => Err(error(ExecutionErrorKind::NotFound, stage)),
            Ok(_) => Err(error(ExecutionErrorKind::InvalidState, stage)),
            Err(()) => Err(error(ExecutionErrorKind::LocalStorage, stage)),
        }
    }
}

impl fmt::Debug for WindowsExecutionEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsExecutionEndpoint")
            .field("handle", &self.entry.handle)
            .field("capabilities", &&ENDPOINT_CAPABILITIES[..])
            .finish_non_exhaustive()
    }
}

impl ExecutionEndpoint for WindowsExecutionEndpoint {
    fn handle(&self) -> &SandboxHandle {
        &self.entry.handle
    }

    fn capabilities(&self) -> &[SandboxCapability] {
        &ENDPOINT_CAPABILITIES
    }

    fn exec(
        &self,
        request: &ExecutionCommand,
        cancellation: &dyn Cancellation,
    ) -> Result<ExecutionOutput, ExecutionError> {
        let _operation = self
            .entry
            .operation_lock
            .lock()
            .map_err(|_| error(ExecutionErrorKind::LocalStorage, ExecutionStage::Exec))?;
        {
            let state = self
                .entry
                .endpoint_state
                .lock()
                .map_err(|_| error(ExecutionErrorKind::LocalStorage, ExecutionStage::Exec))?;
            if let Some(replay) = state.exec.get(&request.operation_id()) {
                return if replay.request == *request {
                    replay.result.clone()
                } else {
                    Err(error(
                        ExecutionErrorKind::BackendRejected,
                        ExecutionStage::Exec,
                    ))
                };
            }
        }
        let result = self.exec_once(request, cancellation);
        let mut state = self
            .entry
            .endpoint_state
            .lock()
            .map_err(|_| error(ExecutionErrorKind::LocalStorage, ExecutionStage::Exec))?;
        state.exec.insert(
            request.operation_id(),
            ExecReplay {
                request: request.clone(),
                result: result.clone(),
            },
        );
        result
    }

    fn signal(
        &self,
        _request: SignalRequest,
        _cancellation: &dyn Cancellation,
    ) -> Result<(), ExecutionError> {
        Err(error(
            ExecutionErrorKind::UnsupportedCapability,
            ExecutionStage::Signal,
        ))
    }

    fn wait(
        &self,
        _request: WaitRequest,
        _cancellation: &dyn Cancellation,
    ) -> Result<i32, ExecutionError> {
        Err(error(
            ExecutionErrorKind::UnsupportedCapability,
            ExecutionStage::Wait,
        ))
    }

    fn copy_to(
        &self,
        request: &CopyToRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ExecutionError> {
        let _operation = self
            .entry
            .operation_lock
            .lock()
            .map_err(|_| error(ExecutionErrorKind::LocalStorage, ExecutionStage::CopyTo))?;
        {
            let state = self
                .entry
                .endpoint_state
                .lock()
                .map_err(|_| error(ExecutionErrorKind::LocalStorage, ExecutionStage::CopyTo))?;
            if let Some(replay) = state.copy_to.get(&request.operation_id()) {
                return if replay.request == *request {
                    replay.result
                } else {
                    Err(error(
                        ExecutionErrorKind::BackendRejected,
                        ExecutionStage::CopyTo,
                    ))
                };
            }
        }
        let result = self.copy_to_once(request, cancellation);
        let mut state = self
            .entry
            .endpoint_state
            .lock()
            .map_err(|_| error(ExecutionErrorKind::LocalStorage, ExecutionStage::CopyTo))?;
        state.copy_to.insert(
            request.operation_id(),
            CopyToReplay {
                request: request.clone(),
                result,
            },
        );
        result
    }

    fn copy_from(
        &self,
        request: &CopyFromRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<Vec<u8>, ExecutionError> {
        let _operation = self
            .entry
            .operation_lock
            .lock()
            .map_err(|_| error(ExecutionErrorKind::LocalStorage, ExecutionStage::CopyFrom))?;
        {
            let state =
                self.entry.endpoint_state.lock().map_err(|_| {
                    error(ExecutionErrorKind::LocalStorage, ExecutionStage::CopyFrom)
                })?;
            if let Some(replay) = state.copy_from.get(&request.operation_id()) {
                return if replay.request == *request {
                    replay.result.clone()
                } else {
                    Err(error(
                        ExecutionErrorKind::BackendRejected,
                        ExecutionStage::CopyFrom,
                    ))
                };
            }
        }
        let result = self.copy_from_once(request, cancellation);
        let mut state = self
            .entry
            .endpoint_state
            .lock()
            .map_err(|_| error(ExecutionErrorKind::LocalStorage, ExecutionStage::CopyFrom))?;
        state.copy_from.insert(
            request.operation_id(),
            CopyFromReplay {
                request: request.clone(),
                result: result.clone(),
            },
        );
        result
    }
}

impl WindowsExecutionEndpoint {
    fn exec_once(
        &self,
        request: &ExecutionCommand,
        cancellation: &dyn Cancellation,
    ) -> Result<ExecutionOutput, ExecutionError> {
        self.require_running(ExecutionStage::Exec)?;
        let program = require_executable(request.argv().program()).map_err(|error| {
            filesystem_error(
                &error,
                ExecutionStage::Exec,
                ExecutionErrorKind::BackendRejected,
            )
        })?;
        let working_directory = resolve_owned_target(
            request.working_directory(),
            &self.entry.workspace,
            &self.entry.scratch,
        )
        .map_err(|error| {
            filesystem_error(
                &error,
                ExecutionStage::Exec,
                ExecutionErrorKind::OwnershipMismatch,
            )
        })?;
        require_directory(&working_directory).map_err(|error| {
            filesystem_error(&error, ExecutionStage::Exec, ExecutionErrorKind::NotFound)
        })?;
        if !case_unique_environment(request.environment()) {
            return Err(error(
                ExecutionErrorKind::InvalidEnvironment,
                ExecutionStage::Exec,
            ));
        }
        if cancellation.is_cancelled() {
            return empty_output(ExecutionTermination::Cancelled);
        }
        let group = self
            .entry
            .group()
            .map_err(|()| error(ExecutionErrorKind::LocalStorage, ExecutionStage::Exec))?
            .ok_or_else(|| error(ExecutionErrorKind::InvalidState, ExecutionStage::Exec))?;

        let request = request.clone();
        let joined = std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| {
                            error(ExecutionErrorKind::LocalStorage, ExecutionStage::Exec)
                        })?;
                    runtime.block_on(run_process(
                        group,
                        request,
                        program,
                        working_directory,
                        cancellation,
                    ))
                })
                .join()
        });
        joined.unwrap_or_else(|_| {
            if let Ok(Some(group)) = self.entry.group() {
                let _ = group.kill_all();
            }
            Err(error(
                ExecutionErrorKind::BackendRejected,
                ExecutionStage::Exec,
            ))
        })
    }

    fn copy_to_once(
        &self,
        request: &CopyToRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ExecutionError> {
        self.require_running(ExecutionStage::CopyTo)?;
        if cancellation.is_cancelled() {
            return Err(error(ExecutionErrorKind::Cancelled, ExecutionStage::CopyTo));
        }
        let path =
            resolve_owned_target(request.target(), &self.entry.workspace, &self.entry.scratch)
                .map_err(|error| {
                    filesystem_error(
                        &error,
                        ExecutionStage::CopyTo,
                        ExecutionErrorKind::OwnershipMismatch,
                    )
                })?;
        write_owned_file(&path, request.content()).map_err(|error| {
            filesystem_error(
                &error,
                ExecutionStage::CopyTo,
                ExecutionErrorKind::LocalStorage,
            )
        })
    }

    fn copy_from_once(
        &self,
        request: &CopyFromRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<Vec<u8>, ExecutionError> {
        self.require_running(ExecutionStage::CopyFrom)?;
        if cancellation.is_cancelled() {
            return Err(error(
                ExecutionErrorKind::Cancelled,
                ExecutionStage::CopyFrom,
            ));
        }
        let path =
            resolve_owned_target(request.source(), &self.entry.workspace, &self.entry.scratch)
                .map_err(|error| {
                    filesystem_error(
                        &error,
                        ExecutionStage::CopyFrom,
                        ExecutionErrorKind::OwnershipMismatch,
                    )
                })?;
        let content = read_owned_file(&path, request.byte_limit()).map_err(|error| {
            filesystem_error(
                &error,
                ExecutionStage::CopyFrom,
                ExecutionErrorKind::LocalStorage,
            )
        })?;
        if cancellation.is_cancelled() {
            return Err(error(
                ExecutionErrorKind::Cancelled,
                ExecutionStage::CopyFrom,
            ));
        }
        Ok(content)
    }
}

async fn run_process(
    group: Arc<processkit::ProcessGroup>,
    request: ExecutionCommand,
    program: PathBuf,
    working_directory: PathBuf,
    cancellation: &dyn Cancellation,
) -> Result<ExecutionOutput, ExecutionError> {
    let reason = Arc::new(AtomicU8::new(StopReason::Natural as u8));
    let capture = Arc::new(Mutex::new(CaptureState::new(request.output_limit())));
    let stdout = CaptureWriter::new(
        ExecutionOutputStream::Stdout,
        Arc::clone(&capture),
        Arc::clone(&group),
        Arc::clone(&reason),
    );
    let stderr = CaptureWriter::new(
        ExecutionOutputStream::Stderr,
        Arc::clone(&capture),
        Arc::clone(&group),
        Arc::clone(&reason),
    );
    let command = build_process_command(&request, program, working_directory, stdout, stderr);
    let Ok(running) = group.start(&command).await else {
        let _ = group.kill_all();
        return Err(error(
            ExecutionErrorKind::BackendRejected,
            ExecutionStage::Exec,
        ));
    };
    let finished = running.output_string();
    tokio::pin!(finished);
    let deadline = tokio::time::sleep(request.timeout());
    tokio::pin!(deadline);
    let mut cancellation_poll = tokio::time::interval(CANCELLATION_POLL_INTERVAL);
    cancellation_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let process_result = loop {
        tokio::select! {
            biased;
            _ = cancellation_poll.tick() => {
                if cancellation.is_cancelled() {
                    reason.store(StopReason::Cancelled as u8, Ordering::SeqCst);
                    group.kill_all().map_err(|_| {
                        error(ExecutionErrorKind::BackendRejected, ExecutionStage::Exec)
                    })?;
                    break tokio::time::timeout(KILL_REAP_TIMEOUT, &mut finished).await.ok();
                }
            }
            () = &mut deadline => {
                let stop = if cancellation.is_cancelled() {
                    StopReason::Cancelled
                } else {
                    StopReason::TimedOut
                };
                reason.store(stop as u8, Ordering::SeqCst);
                group.kill_all().map_err(|_| {
                    error(ExecutionErrorKind::BackendRejected, ExecutionStage::Exec)
                })?;
                break tokio::time::timeout(KILL_REAP_TIMEOUT, &mut finished).await.ok();
            }
            result = &mut finished => {
                if cancellation.is_cancelled() {
                    reason.store(StopReason::Cancelled as u8, Ordering::SeqCst);
                    group.kill_all().map_err(|_| {
                        error(ExecutionErrorKind::BackendRejected, ExecutionStage::Exec)
                    })?;
                }
                break Some(result);
            }
        }
    };

    let stop_reason = StopReason::from_u8(reason.load(Ordering::SeqCst));
    let (termination, complete) = match (stop_reason, process_result) {
        (StopReason::Cancelled, Some(Ok(_))) => (ExecutionTermination::Cancelled, true),
        (StopReason::Cancelled, Some(Err(_)) | None) => (ExecutionTermination::Cancelled, false),
        (StopReason::TimedOut, Some(Ok(_))) => (ExecutionTermination::TimedOut, true),
        (StopReason::TimedOut, Some(Err(_)) | None) => (ExecutionTermination::TimedOut, false),
        (StopReason::OutputLimit, Some(Ok(_))) => (ExecutionTermination::Signalled, true),
        (StopReason::OutputLimit, Some(Err(_)) | None) => (ExecutionTermination::Signalled, false),
        (StopReason::Natural, Some(Ok(result))) => (map_outcome(result.outcome()), true),
        (StopReason::Natural, Some(Err(_)) | None) => {
            let _ = group.kill_all();
            return Err(error(
                ExecutionErrorKind::BackendRejected,
                ExecutionStage::Exec,
            ));
        }
    };
    let mut capture = capture
        .lock()
        .map_err(|_| error(ExecutionErrorKind::LocalStorage, ExecutionStage::Exec))?;
    capture.finish(
        termination,
        complete,
        stop_reason == StopReason::OutputLimit || !complete,
    )
}

fn build_process_command(
    request: &ExecutionCommand,
    program: PathBuf,
    working_directory: PathBuf,
    stdout: CaptureWriter,
    stderr: CaptureWriter,
) -> Command {
    let mut command = Command::new(program)
        .args(request.argv().arguments())
        .current_dir(working_directory)
        .env_clear()
        .no_timeout()
        .create_no_window()
        .stdout_raw_tee(stdout)
        .stderr_raw_tee(stderr)
        .output_buffer(OutputBufferPolicy::bounded(0).with_max_bytes(request.output_limit()));
    for variable in request.environment().values() {
        command = command.env(variable.name().as_str(), variable.value().expose());
    }
    command
}

fn map_outcome(outcome: Outcome) -> ExecutionTermination {
    if let Some(code) = outcome.code() {
        ExecutionTermination::Exited(code)
    } else if outcome.timed_out() {
        ExecutionTermination::TimedOut
    } else {
        ExecutionTermination::Signalled
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
enum StopReason {
    Natural = 0,
    Cancelled = 1,
    TimedOut = 2,
    OutputLimit = 3,
}

impl StopReason {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Cancelled,
            2 => Self::TimedOut,
            3 => Self::OutputLimit,
            _ => Self::Natural,
        }
    }
}

struct CaptureWriter {
    stream: ExecutionOutputStream,
    capture: Arc<Mutex<CaptureState>>,
    group: Arc<processkit::ProcessGroup>,
    reason: Arc<AtomicU8>,
}

impl CaptureWriter {
    const fn new(
        stream: ExecutionOutputStream,
        capture: Arc<Mutex<CaptureState>>,
        group: Arc<processkit::ProcessGroup>,
        reason: Arc<AtomicU8>,
    ) -> Self {
        Self {
            stream,
            capture,
            group,
            reason,
        }
    }
}

impl AsyncWrite for CaptureWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let Ok(mut capture) = self.capture.lock() else {
            return Poll::Ready(Err(io::Error::other("execution output state poisoned")));
        };
        let remaining = capture.limit.saturating_sub(capture.bytes);
        let record_capacity = MAX_EXECUTION_OUTPUT_RECORDS
            .saturating_sub(2)
            .saturating_sub(capture.records.len());
        let record_bytes = record_capacity.saturating_mul(MAX_EXECUTION_OUTPUT_RECORD_BYTES);
        let accepted = remaining.min(record_bytes).min(bytes.len());
        for chunk in bytes[..accepted].chunks(MAX_EXECUTION_OUTPUT_RECORD_BYTES) {
            let record = ExecutionOutputRecord::data(self.stream, chunk.to_vec())
                .map_err(|_| io::Error::other("invalid execution output record"));
            match record {
                Ok(record) => capture.records.push(record),
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        capture.bytes += accepted;
        if accepted != bytes.len() {
            capture.truncated = true;
            if self
                .reason
                .compare_exchange(
                    StopReason::Natural as u8,
                    StopReason::OutputLimit as u8,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_ok()
            {
                let _ = self.group.kill_all();
            }
        }
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct CaptureState {
    records: Vec<ExecutionOutputRecord>,
    bytes: usize,
    limit: usize,
    truncated: bool,
}

impl CaptureState {
    const fn new(limit: usize) -> Self {
        Self {
            records: Vec::new(),
            bytes: 0,
            limit,
            truncated: false,
        }
    }

    fn finish(
        &mut self,
        termination: ExecutionTermination,
        complete: bool,
        force_truncated: bool,
    ) -> Result<ExecutionOutput, ExecutionError> {
        if complete {
            self.records.push(ExecutionOutputRecord::end_of_stream(
                ExecutionOutputStream::Stdout,
            ));
            self.records.push(ExecutionOutputRecord::end_of_stream(
                ExecutionOutputStream::Stderr,
            ));
        }
        let records = std::mem::take(&mut self.records);
        ExecutionOutput::new(termination, records, self.truncated || force_truncated).map_err(
            |_| {
                error(
                    ExecutionErrorKind::OutputLimitExceeded,
                    ExecutionStage::Exec,
                )
            },
        )
    }
}

fn empty_output(termination: ExecutionTermination) -> Result<ExecutionOutput, ExecutionError> {
    ExecutionOutput::new(
        termination,
        vec![
            ExecutionOutputRecord::end_of_stream(ExecutionOutputStream::Stdout),
            ExecutionOutputRecord::end_of_stream(ExecutionOutputStream::Stderr),
        ],
        false,
    )
    .map_err(|_| error(ExecutionErrorKind::BackendRejected, ExecutionStage::Exec))
}

fn filesystem_error(
    source: &io::Error,
    stage: ExecutionStage,
    fallback: ExecutionErrorKind,
) -> ExecutionError {
    let kind = match source.kind() {
        io::ErrorKind::NotFound => ExecutionErrorKind::NotFound,
        io::ErrorKind::PermissionDenied => ExecutionErrorKind::OwnershipMismatch,
        io::ErrorKind::FileTooLarge => ExecutionErrorKind::OutputLimitExceeded,
        _ => fallback,
    };
    error(kind, stage)
}

const fn error(kind: ExecutionErrorKind, stage: ExecutionStage) -> ExecutionError {
    ExecutionError::new(kind, stage)
}
