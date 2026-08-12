use std::{
    io::{self, Read, Write},
    path::Path,
    pin::Pin,
    process::{Child, Command as ProcessCommand, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use automata_ci_execution::{
    Cancellation, EnvironmentName, EnvironmentValue, EnvironmentVariable, ExecutionArgv,
    ExecutionCommand, ExecutionEnvironment, ExecutionError, ExecutionErrorKind, ExecutionOutput,
    ExecutionOutputRecord, ExecutionOutputStream, ExecutionStage, ExecutionTermination,
    MAX_EXECUTION_OUTPUT_BYTES, MAX_EXECUTION_OUTPUT_RECORD_BYTES, MAX_EXECUTION_OUTPUT_RECORDS,
    OperationId, TargetPath,
};
use processkit::{
    Command, Mechanism, Outcome, OutputBufferPolicy, ProcessGroup, ProcessRunner as _,
};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWrite;

use crate::SUPERVISOR_COMMAND;

const REQUEST_MAGIC: [u8; 4] = *b"AMSQ";
const RESPONSE_MAGIC: [u8; 4] = *b"AMSR";
const MAX_REQUEST_BYTES: usize = 6 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize =
    MAX_EXECUTION_OUTPUT_BYTES + MAX_EXECUTION_OUTPUT_RECORDS * 6 + 32;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const SUPERVISOR_GRACE: Duration = Duration::from_secs(5);

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SupervisorRequest {
    program: String,
    arguments: Vec<String>,
    working_directory: String,
    environment: Vec<(String, String)>,
    timeout_millis: u64,
    output_limit: usize,
}

impl SupervisorRequest {
    fn from_command(command: &ExecutionCommand) -> Self {
        Self {
            program: command.argv().program().as_str().to_owned(),
            arguments: command.argv().arguments().to_vec(),
            working_directory: command.working_directory().as_str().to_owned(),
            environment: command
                .environment()
                .values()
                .iter()
                .map(|variable| {
                    (
                        variable.name().as_str().to_owned(),
                        variable.value().expose().to_owned(),
                    )
                })
                .collect(),
            timeout_millis: u64::try_from(command.timeout().as_millis()).unwrap_or(u64::MAX),
            output_limit: command.output_limit(),
        }
    }

    fn validate(self) -> io::Result<ExecutionCommand> {
        let program = TargetPath::posix(self.program).map_err(invalid_data)?;
        let argv = ExecutionArgv::new(program, self.arguments).map_err(invalid_data)?;
        let working_directory = TargetPath::posix(self.working_directory).map_err(invalid_data)?;
        let environment = self
            .environment
            .into_iter()
            .map(|(name, value)| {
                Ok(EnvironmentVariable::new(
                    EnvironmentName::new(name).map_err(invalid_data)?,
                    EnvironmentValue::new(value).map_err(invalid_data)?,
                ))
            })
            .collect::<io::Result<Vec<_>>>()?;
        let environment = ExecutionEnvironment::new(environment).map_err(invalid_data)?;
        ExecutionCommand::new(
            OperationId::new(),
            argv,
            working_directory,
            environment,
            Duration::from_millis(self.timeout_millis),
            self.output_limit,
        )
        .map_err(invalid_data)
    }
}

pub(crate) fn execute(
    executable: &Path,
    request: &ExecutionCommand,
    cancellation: &dyn Cancellation,
) -> Result<ExecutionOutput, ExecutionError> {
    let wire = SupervisorRequest::from_command(request);
    let encoded = serde_json::to_vec(&wire).map_err(|_| local_error())?;
    if encoded.is_empty() || encoded.len() > MAX_REQUEST_BYTES {
        return Err(local_error());
    }
    let mut child = ProcessCommand::new(executable)
        .arg(SUPERVISOR_COMMAND)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| backend_error())?;
    let Some(stdin) = child.stdin.take() else {
        kill_and_reap(&mut child);
        return Err(backend_error());
    };
    let mut control = Some(stdin);
    write_request(control.as_mut().ok_or_else(backend_error)?, &encoded).map_err(|_| {
        kill_and_reap(&mut child);
        backend_error()
    })?;
    let Some(stdout) = child.stdout.take() else {
        kill_and_reap(&mut child);
        return Err(backend_error());
    };
    let reader = std::thread::Builder::new()
        .name("automata-macos-supervisor-output".to_owned())
        .spawn(move || read_bounded(stdout, MAX_RESPONSE_BYTES))
        .map_err(|_| local_error());
    let reader = match reader {
        Ok(reader) => reader,
        Err(error) => {
            kill_and_reap(&mut child);
            return Err(error);
        }
    };

    let deadline = Instant::now() + request.timeout() + SUPERVISOR_GRACE;
    let mut cancellation_sent = false;
    let status = loop {
        if cancellation.is_cancelled() && !cancellation_sent {
            drop(control.take());
            cancellation_sent = true;
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL_INTERVAL),
            Ok(None) | Err(_) => {
                drop(control.take());
                kill_and_reap(&mut child);
                return Err(backend_error());
            }
        }
    };
    drop(control);
    let response = reader
        .join()
        .map_err(|_| backend_error())?
        .map_err(|_| backend_error())?;
    if !status.success() {
        return Err(backend_error());
    }
    decode_response(&response)
}

/// Runs one hidden same-binary supervisor request from standard input.
///
/// The caller keeps stdin open as a liveness channel. EOF cancels the child
/// process group, including when the runner exits abruptly. The bounded result
/// is emitted on stdout using an internal binary frame.
///
/// # Errors
///
/// Rejects malformed or oversized requests and reports process/control I/O
/// failures without including command, environment, or output bytes.
pub fn run_supervisor() -> io::Result<()> {
    std::thread::Builder::new()
        .name("automata-macos-supervisor-runtime".to_owned())
        .spawn(run_supervisor_inner)?
        .join()
        .map_err(|_| io::Error::other("supervisor runtime failed"))?
}

fn run_supervisor_inner() -> io::Result<()> {
    let request = read_request(std::io::stdin().lock())?;
    let request: SupervisorRequest = serde_json::from_slice(&request)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let request = request.validate()?;
    let disconnected = Arc::new(AtomicBool::new(false));
    let watcher_state = Arc::clone(&disconnected);
    std::thread::Builder::new()
        .name("automata-macos-supervisor-liveness".to_owned())
        .spawn(move || {
            let mut byte = [0_u8; 1];
            let _ = std::io::stdin().read(&mut byte);
            watcher_state.store(true, Ordering::Release);
        })?;
    let output = run_supervised(request, disconnected)?;
    write_response(std::io::stdout().lock(), &output)
}

fn run_supervised(
    request: ExecutionCommand,
    disconnected: Arc<AtomicBool>,
) -> io::Result<ExecutionOutput> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let group = Arc::new(ProcessGroup::new().map_err(process_error)?);
        if group.mechanism() != Mechanism::ProcessGroup {
            return Err(io::Error::from(io::ErrorKind::Unsupported));
        }
        run_process(group, request, disconnected).await
    })
}

async fn run_process(
    group: Arc<ProcessGroup>,
    request: ExecutionCommand,
    disconnected: Arc<AtomicBool>,
) -> io::Result<ExecutionOutput> {
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
    let mut command = Command::new(request.argv().program().as_str())
        .args(request.argv().arguments())
        .current_dir(request.working_directory().as_str())
        .env_clear()
        .no_timeout()
        .stdout_raw_tee(stdout)
        .stderr_raw_tee(stderr)
        .output_buffer(OutputBufferPolicy::bounded(0).with_max_bytes(request.output_limit()));
    for variable in request.environment().values() {
        command = command.env(variable.name().as_str(), variable.value().expose());
    }
    let running = group.start(&command).await.map_err(process_error)?;
    let finished = running.output_string();
    tokio::pin!(finished);
    let deadline = tokio::time::sleep(request.timeout());
    tokio::pin!(deadline);
    let mut liveness_poll = tokio::time::interval(POLL_INTERVAL);
    liveness_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let process_result = loop {
        tokio::select! {
            biased;
            _ = liveness_poll.tick() => {
                if disconnected.load(Ordering::Acquire) {
                    reason.store(StopReason::Cancelled as u8, Ordering::SeqCst);
                    group.kill_all().map_err(process_error)?;
                    break tokio::time::timeout(SUPERVISOR_GRACE, &mut finished).await.ok();
                }
            }
            () = &mut deadline => {
                reason.store(StopReason::TimedOut as u8, Ordering::SeqCst);
                group.kill_all().map_err(process_error)?;
                break tokio::time::timeout(SUPERVISOR_GRACE, &mut finished).await.ok();
            }
            result = &mut finished => break Some(result),
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
            return Err(io::Error::other("process failed"));
        }
    };
    capture
        .lock()
        .map_err(|_| io::Error::other("capture state poisoned"))?
        .finish(
            termination,
            complete,
            stop_reason == StopReason::OutputLimit || !complete,
        )
}

fn write_request(mut destination: impl Write, bytes: &[u8]) -> io::Result<()> {
    destination.write_all(&REQUEST_MAGIC)?;
    destination.write_all(
        &u32::try_from(bytes.len())
            .map_err(invalid_data)?
            .to_le_bytes(),
    )?;
    destination.write_all(bytes)?;
    destination.flush()
}

fn read_request(mut source: impl Read) -> io::Result<Vec<u8>> {
    let mut magic = [0_u8; 4];
    source.read_exact(&mut magic)?;
    if magic != REQUEST_MAGIC {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let length = usize::try_from(read_u32(&mut source)?).map_err(invalid_data)?;
    if length == 0 || length > MAX_REQUEST_BYTES {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let mut bytes = vec![0_u8; length];
    source.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn write_response(mut destination: impl Write, output: &ExecutionOutput) -> io::Result<()> {
    destination.write_all(&RESPONSE_MAGIC)?;
    let (termination, code) = match output.termination() {
        ExecutionTermination::Exited(code) => (0_u8, code),
        ExecutionTermination::Signalled => (1, 0),
        ExecutionTermination::TimedOut => (2, 0),
        ExecutionTermination::Cancelled => (3, 0),
    };
    destination.write_all(&[termination, u8::from(output.was_truncated())])?;
    destination.write_all(&code.to_le_bytes())?;
    destination.write_all(
        &u32::try_from(output.records().len())
            .map_err(invalid_data)?
            .to_le_bytes(),
    )?;
    for record in output.records() {
        let stream = match record.stream() {
            ExecutionOutputStream::Stdout => 0_u8,
            ExecutionOutputStream::Stderr => 1_u8,
        };
        destination.write_all(&[stream, u8::from(record.is_end_of_stream())])?;
        destination.write_all(
            &u32::try_from(record.bytes().len())
                .map_err(invalid_data)?
                .to_le_bytes(),
        )?;
        destination.write_all(record.bytes())?;
    }
    destination.flush()
}

fn decode_response(bytes: &[u8]) -> Result<ExecutionOutput, ExecutionError> {
    let mut source = bytes;
    let mut magic = [0_u8; 4];
    source.read_exact(&mut magic).map_err(|_| backend_error())?;
    if magic != RESPONSE_MAGIC {
        return Err(backend_error());
    }
    let mut flags = [0_u8; 2];
    source.read_exact(&mut flags).map_err(|_| backend_error())?;
    let code = read_i32(&mut source).map_err(|_| backend_error())?;
    let termination = match flags[0] {
        0 => ExecutionTermination::Exited(code),
        1 => ExecutionTermination::Signalled,
        2 => ExecutionTermination::TimedOut,
        3 => ExecutionTermination::Cancelled,
        _ => return Err(backend_error()),
    };
    let count = usize::try_from(read_u32(&mut source).map_err(|_| backend_error())?)
        .map_err(|_| backend_error())?;
    if count > MAX_EXECUTION_OUTPUT_RECORDS {
        return Err(backend_error());
    }
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let mut flags = [0_u8; 2];
        source.read_exact(&mut flags).map_err(|_| backend_error())?;
        let stream = match flags[0] {
            0 => ExecutionOutputStream::Stdout,
            1 => ExecutionOutputStream::Stderr,
            _ => return Err(backend_error()),
        };
        let length = usize::try_from(read_u32(&mut source).map_err(|_| backend_error())?)
            .map_err(|_| backend_error())?;
        if length > MAX_EXECUTION_OUTPUT_RECORD_BYTES || flags[1] > 1 {
            return Err(backend_error());
        }
        let mut content = vec![0_u8; length];
        source
            .read_exact(&mut content)
            .map_err(|_| backend_error())?;
        let record = if flags[1] == 1 {
            if !content.is_empty() {
                return Err(backend_error());
            }
            ExecutionOutputRecord::end_of_stream(stream)
        } else {
            ExecutionOutputRecord::data(stream, content).map_err(|_| backend_error())?
        };
        records.push(record);
    }
    if !source.is_empty() {
        return Err(backend_error());
    }
    ExecutionOutput::new(termination, records, flags[1] != 0).map_err(|_| backend_error())
}

fn read_bounded(mut source: impl Read, maximum: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    source
        .by_ref()
        .take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(io::Error::from(io::ErrorKind::FileTooLarge));
    }
    Ok(bytes)
}

fn read_u32(mut source: impl Read) -> io::Result<u32> {
    let mut bytes = [0_u8; 4];
    source.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_i32(mut source: impl Read) -> io::Result<i32> {
    let mut bytes = [0_u8; 4];
    source.read_exact(&mut bytes)?;
    Ok(i32::from_le_bytes(bytes))
}

fn kill_and_reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
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
    group: Arc<ProcessGroup>,
    reason: Arc<AtomicU8>,
}

impl CaptureWriter {
    const fn new(
        stream: ExecutionOutputStream,
        capture: Arc<Mutex<CaptureState>>,
        group: Arc<ProcessGroup>,
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
            return Poll::Ready(Err(io::Error::other("capture state poisoned")));
        };
        let remaining = capture.limit.saturating_sub(capture.bytes);
        let record_capacity = MAX_EXECUTION_OUTPUT_RECORDS
            .saturating_sub(2)
            .saturating_sub(capture.records.len());
        let record_bytes = record_capacity.saturating_mul(MAX_EXECUTION_OUTPUT_RECORD_BYTES);
        let accepted = remaining.min(record_bytes).min(bytes.len());
        for chunk in bytes[..accepted].chunks(MAX_EXECUTION_OUTPUT_RECORD_BYTES) {
            let record = ExecutionOutputRecord::data(self.stream, chunk.to_vec())
                .map_err(|_| io::Error::other("invalid output record"));
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
    ) -> io::Result<ExecutionOutput> {
        if complete {
            self.records.push(ExecutionOutputRecord::end_of_stream(
                ExecutionOutputStream::Stdout,
            ));
            self.records.push(ExecutionOutputRecord::end_of_stream(
                ExecutionOutputStream::Stderr,
            ));
        }
        ExecutionOutput::new(
            termination,
            std::mem::take(&mut self.records),
            self.truncated || force_truncated,
        )
        .map_err(invalid_data)
    }
}

fn process_error(error: impl std::fmt::Display) -> io::Error {
    let _ = error;
    io::Error::other("supervised process failed")
}

fn invalid_data(_error: impl std::fmt::Debug) -> io::Error {
    io::Error::from(io::ErrorKind::InvalidData)
}

const fn local_error() -> ExecutionError {
    ExecutionError::new(ExecutionErrorKind::LocalStorage, ExecutionStage::Exec)
}

const fn backend_error() -> ExecutionError {
    ExecutionError::new(ExecutionErrorKind::BackendRejected, ExecutionStage::Exec)
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, atomic::AtomicBool},
        time::Duration,
    };

    use automata_ci_execution::{
        ExecutionArgv, ExecutionCommand, ExecutionEnvironment, ExecutionTermination, OperationId,
        TargetPath,
    };

    use super::run_supervised;

    #[test]
    fn supervisor_preserves_bounded_stdout_stderr_and_exit_status() {
        let output = run_supervised(
            command(
                "printf stdout; printf stderr >&2; exit 7",
                Duration::from_secs(5),
            ),
            Arc::new(AtomicBool::new(false)),
        )
        .expect("supervise shell command");

        assert_eq!(output.termination(), ExecutionTermination::Exited(7));
        assert_eq!(output.stdout(), b"stdout");
        assert_eq!(output.stderr(), b"stderr");
        assert!(!output.was_truncated());
    }

    #[test]
    fn supervisor_enforces_timeout_and_control_disconnect() {
        let timed_out = run_supervised(
            command("sleep 5", Duration::from_millis(20)),
            Arc::new(AtomicBool::new(false)),
        )
        .expect("timeout is a command termination");
        assert_eq!(timed_out.termination(), ExecutionTermination::TimedOut);

        let disconnected = run_supervised(
            command("sleep 5", Duration::from_secs(5)),
            Arc::new(AtomicBool::new(true)),
        )
        .expect("disconnect is a command termination");
        assert_eq!(disconnected.termination(), ExecutionTermination::Cancelled);
    }

    #[test]
    fn supervisor_kills_the_process_group_at_the_output_bound() {
        let output = run_supervised(
            command_with_limit(
                "printf '%s' 'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz'",
                Duration::from_secs(5),
                32,
            ),
            Arc::new(AtomicBool::new(false)),
        )
        .expect("output overflow is a bounded command termination");

        assert_eq!(output.termination(), ExecutionTermination::Signalled);
        assert!(output.was_truncated());
        assert!(output.stdout().len() <= 32);
    }

    fn command(script: &str, timeout: Duration) -> ExecutionCommand {
        command_with_limit(script, timeout, 1024 * 1024)
    }

    fn command_with_limit(
        script: &str,
        timeout: Duration,
        output_limit: usize,
    ) -> ExecutionCommand {
        ExecutionCommand::new(
            OperationId::new(),
            ExecutionArgv::new(
                TargetPath::posix("/bin/sh").expect("shell"),
                vec!["-c".to_owned(), script.to_owned()],
            )
            .expect("argv"),
            TargetPath::posix("/").expect("working directory"),
            ExecutionEnvironment::empty(),
            timeout,
            output_limit,
        )
        .expect("command")
    }
}
