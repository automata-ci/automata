use std::{collections::BTreeSet, fmt, sync::Arc, time::Duration};

use crate::{
    MAX_COPY_BYTES, MAX_EXECUTION_ARGUMENTS, MAX_EXECUTION_ARGV_BYTES, MAX_EXECUTION_OUTPUT_BYTES,
    MAX_EXECUTION_OUTPUT_RECORD_BYTES, MAX_EXECUTION_OUTPUT_RECORDS, OperationId,
    SandboxCapability, SandboxHandle, TargetPath, ValueError, error::ExecutionError,
};

const MAX_COMMAND_TIMEOUT: Duration = Duration::from_hours(24);
const MAX_ENVIRONMENT_VARIABLES: usize = 1_024;
const MAX_ENVIRONMENT_NAME_BYTES: usize = 128;
const MAX_ENVIRONMENT_VALUE_BYTES: usize = 1024 * 1024;
const MAX_ENVIRONMENT_BYTES: usize = 4 * 1024 * 1024;

/// Meaning of a cooperative cancellation observation at a provider boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationDisposition {
    /// No cancellation has been requested.
    Active,
    /// Request provider-specific termination handling at a checkpoint.
    ///
    /// The durable runner may still require exact sandbox destruction before
    /// it records cancellation as complete.
    Terminate,
}

impl CancellationDisposition {
    /// Reports whether the provider is authorized to terminate backend work.
    #[must_use]
    pub const fn requires_termination(self) -> bool {
        matches!(self, Self::Terminate)
    }
}

/// Cooperative cancellation source shared across provider boundaries.
pub trait Cancellation: Send + Sync {
    /// Returns the current cancellation meaning.
    ///
    /// Adapters observe this at their cancellation checkpoints. Termination
    /// authorizes provider-specific handling; the disposition or an adapter
    /// return does not prove remote work quiesced or an in-flight mutation
    /// rolled back. Durable cancellation is complete only after the exact
    /// sandbox is proven absent.
    #[must_use]
    fn disposition(&self) -> CancellationDisposition;
}

/// Cancellation source that never requests cancellation.
#[derive(Clone, Copy, Debug, Default)]
pub struct NeverCancelled;

impl Cancellation for NeverCancelled {
    fn disposition(&self) -> CancellationDisposition {
        CancellationDisposition::Active
    }
}

/// Endpoint calls made before the first workflow step.
const ENDPOINT_JOB_SETUP_OPERATIONS: usize = 2;

/// Maximum endpoint calls made by one admitted literal run step.
const ENDPOINT_OPERATIONS_PER_RUN_STEP: usize = 15;

/// Hard shared endpoint-operation budget for one admitted job.
///
/// The budget admits the current maximum-size run-only job with no dynamically
/// declared artifact subjects. Composite/action phases and artifact hashing
/// consume this same non-evicting budget; expansions beyond it fail closed
/// before the next provider invocation. This is an execution admission bound,
/// not an independently selected cache size.
pub const MAX_ENDPOINT_OPERATIONS_PER_JOB: usize = automata_ci_core::MAX_LOGICAL_STEPS
    * ENDPOINT_OPERATIONS_PER_RUN_STEP
    + ENDPOINT_JOB_SETUP_OPERATIONS;

/// Validated executable plus literal arguments. No shell command string exists
/// in the execution contract.
#[derive(Clone, Eq, PartialEq)]
pub struct ExecutionArgv {
    program: TargetPath,
    arguments: Vec<String>,
}

impl ExecutionArgv {
    /// Creates a bounded argv vector.
    ///
    /// # Errors
    ///
    /// Rejects nul bytes, too many arguments, and excessive aggregate bytes.
    pub fn new(program: TargetPath, arguments: Vec<String>) -> Result<Self, ValueError> {
        let bytes = arguments
            .iter()
            .try_fold(program.as_str().len(), |sum, argument| {
                if argument.contains('\0') {
                    return None;
                }
                sum.checked_add(argument.len())
            });
        if arguments.len() > MAX_EXECUTION_ARGUMENTS
            || bytes.is_none_or(|bytes| bytes > MAX_EXECUTION_ARGV_BYTES)
        {
            return Err(ValueError::InvalidExecutionArgv);
        }
        Ok(Self { program, arguments })
    }

    /// Returns the absolute target path of the executable.
    #[must_use]
    pub const fn program(&self) -> &TargetPath {
        &self.program
    }

    /// Returns the literal arguments, excluding the executable itself.
    ///
    /// Arguments may contain credentials or other sensitive workflow data and
    /// must not be logged. [`Debug`](fmt::Debug) redacts them.
    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }
}

impl fmt::Debug for ExecutionArgv {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionArgv")
            .field("program", &self.program)
            .field("argument_count", &self.arguments.len())
            .field("arguments", &"[REDACTED]")
            .finish()
    }
}

/// Portable environment-variable name.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EnvironmentName(String);

impl EnvironmentName {
    /// Validates a portable process-environment name.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, `=`-containing, and control-character values.
    ///
    /// Process environments permit names such as `INPUT_FETCH-DEPTH`, which
    /// GitHub's JavaScript toolkit derives from action input keys. Individual
    /// providers may impose stricter platform/control-variable policies at
    /// execution time.
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_ENVIRONMENT_NAME_BYTES
            && !value.contains('=')
            && !value.chars().any(char::is_control);
        valid
            .then_some(Self(value))
            .ok_or(ValueError::InvalidEnvironmentName)
    }

    /// Borrows the validated environment name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for EnvironmentName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("EnvironmentName")
            .field(&self.0)
            .finish()
    }
}

/// Potentially secret process-environment value.
///
/// `Debug` redaction prevents accidental formatting, but this clonable wrapper
/// is neither encrypted nor zeroizing. Secret-origin values belong in
/// [`EnvironmentVariable::secret`] and an ephemeral provider transport.
#[derive(Clone, Eq, PartialEq)]
pub struct EnvironmentValue(String);

impl EnvironmentValue {
    /// Creates a bounded value.
    ///
    /// # Errors
    ///
    /// Rejects nul bytes and values beyond one MiB.
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();
        (value.len() <= MAX_ENVIRONMENT_VALUE_BYTES && !value.contains('\0'))
            .then_some(Self(value))
            .ok_or(ValueError::InvalidEnvironmentValue)
    }

    /// Exposes the underlying environment value.
    ///
    /// This explicit accessor may reveal secret material even when a caller
    /// did not mark its enclosing [`EnvironmentVariable`] as secret. Keep the
    /// result out of logs and durable diagnostics.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for EnvironmentValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EnvironmentValue([REDACTED])")
    }
}

/// One explicit environment variable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentVariable {
    name: EnvironmentName,
    value: EnvironmentValue,
    secret: bool,
}

impl EnvironmentVariable {
    /// Creates a non-secret environment variable.
    #[must_use]
    pub const fn new(name: EnvironmentName, value: EnvironmentValue) -> Self {
        Self {
            name,
            value,
            secret: false,
        }
    }

    /// Creates a variable that requires an ephemeral-only transport.
    ///
    /// The marker is policy metadata; it does not encrypt or zeroize `value`.
    #[must_use]
    pub const fn secret(name: EnvironmentName, value: EnvironmentValue) -> Self {
        Self {
            name,
            value,
            secret: true,
        }
    }

    /// Returns the validated variable name.
    #[must_use]
    pub const fn name(&self) -> &EnvironmentName {
        &self.name
    }

    /// Returns the potentially sensitive variable value.
    #[must_use]
    pub const fn value(&self) -> &EnvironmentValue {
        &self.value
    }

    /// Returns whether this value originated from readable secret authority.
    #[must_use]
    pub const fn is_secret(&self) -> bool {
        self.secret
    }
}

/// Unique, bounded environment with redacted values.
#[derive(Clone, Eq, PartialEq)]
pub struct ExecutionEnvironment(Vec<EnvironmentVariable>);

impl ExecutionEnvironment {
    /// Validates unique names and aggregate size.
    ///
    /// # Errors
    ///
    /// Rejects duplicates and excessive variable count or bytes.
    pub fn new(values: Vec<EnvironmentVariable>) -> Result<Self, ValueError> {
        if values.len() > MAX_ENVIRONMENT_VARIABLES {
            return Err(ValueError::InvalidExecutionEnvironment);
        }
        let mut names = BTreeSet::new();
        let bytes = values.iter().try_fold(0_usize, |sum, variable| {
            if !names.insert(variable.name().clone()) {
                return None;
            }
            sum.checked_add(variable.name().as_str().len())?
                .checked_add(variable.value().expose().len())
        });
        if bytes.is_none_or(|bytes| bytes > MAX_ENVIRONMENT_BYTES) {
            return Err(ValueError::InvalidExecutionEnvironment);
        }
        Ok(Self(values))
    }

    /// Returns an environment containing no variables.
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// Returns variables in their caller-supplied order.
    ///
    /// Values remain explicitly accessible through
    /// [`EnvironmentVariable::value`] and must not be logged.
    #[must_use]
    pub fn values(&self) -> &[EnvironmentVariable] {
        &self.0
    }

    /// Returns whether the environment contains no variables.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for ExecutionEnvironment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<_> = self.0.iter().map(EnvironmentVariable::name).collect();
        formatter
            .debug_struct("ExecutionEnvironment")
            .field("names", &names)
            .field("values", &"[REDACTED]")
            .finish()
    }
}

/// One command execution with a stable correlation identifier.
#[derive(Clone, Eq, PartialEq)]
pub struct ExecutionCommand {
    operation_id: OperationId,
    argv: ExecutionArgv,
    working_directory: TargetPath,
    environment: ExecutionEnvironment,
    timeout: Duration,
    output_limit: usize,
}

impl ExecutionCommand {
    /// Creates a bounded execution request.
    ///
    /// # Errors
    ///
    /// Rejects zero/oversized timeout and output limits.
    pub fn new(
        operation_id: OperationId,
        argv: ExecutionArgv,
        working_directory: TargetPath,
        environment: ExecutionEnvironment,
        timeout: Duration,
        output_limit: usize,
    ) -> Result<Self, ValueError> {
        if timeout.is_zero() || timeout > MAX_COMMAND_TIMEOUT {
            return Err(ValueError::InvalidTimeout);
        }
        if output_limit == 0 || output_limit > MAX_EXECUTION_OUTPUT_BYTES {
            return Err(ValueError::InvalidByteLimit);
        }
        Ok(Self {
            operation_id,
            argv,
            working_directory,
            environment,
            timeout,
            output_limit,
        })
    }

    /// Returns the stable correlation identifier for this exact execution.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the executable and literal arguments.
    #[must_use]
    pub const fn argv(&self) -> &ExecutionArgv {
        &self.argv
    }

    /// Returns the absolute sandbox target directory for the process.
    #[must_use]
    pub const fn working_directory(&self) -> &TargetPath {
        &self.working_directory
    }

    /// Returns the complete per-command environment layer.
    #[must_use]
    pub const fn environment(&self) -> &ExecutionEnvironment {
        &self.environment
    }

    /// Returns the maximum duration allowed for the command.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Returns the aggregate maximum number of captured stdout and stderr bytes.
    #[must_use]
    pub const fn output_limit(&self) -> usize {
        self.output_limit
    }
}

impl fmt::Debug for ExecutionCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionCommand")
            .field("operation_id", &self.operation_id)
            .field("argv", &self.argv)
            .field("working_directory", &self.working_directory)
            .field("environment", &self.environment)
            .field("timeout", &self.timeout)
            .field("output_limit", &self.output_limit)
            .finish()
    }
}

/// Adapter-reported outcome of an execution command.
///
/// This value records the endpoint's observation; it is not evidence that a
/// remotely initiated process has quiesced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionTermination {
    /// The process exited normally with the supplied platform exit status.
    Exited(i32),
    /// The process terminated because it received a signal.
    Signalled,
    /// The endpoint observed the command deadline and reported a timeout.
    TimedOut,
    /// The endpoint observed cooperative cancellation and reported it.
    Cancelled,
}

/// Process pipe represented by an ordered execution-output record.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExecutionOutputStream {
    /// The process standard-output pipe.
    Stdout,
    /// The process standard-error pipe.
    Stderr,
}

/// One adapter-observed process-output event.
///
/// Data records from both pipes share the surrounding [`ExecutionOutput`]
/// sequence. End-of-stream records close one pipe and make trailing partial
/// lines observable at their exact adapter-observed position. Debug formatting
/// never prints captured bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct ExecutionOutputRecord {
    stream: ExecutionOutputStream,
    bytes: Vec<u8>,
    end_of_stream: bool,
}

/// Incremental consumer for one command's ordered process-output records.
///
/// Endpoints call this boundary as each stdout or stderr record is observed,
/// before the command completes. The same ordered records remain present in
/// the terminal [`ExecutionOutput`] for exact durable replay. Implementations
/// must apply secret policy before publishing bytes outside runner custody.
pub trait ExecutionOutputSink: fmt::Debug + Send + Sync {
    /// Accepts the next record in canonical cross-pipe observation order.
    ///
    /// # Errors
    ///
    /// Rejecting a record terminates execution and fails the endpoint call.
    fn observe(&self, record: &ExecutionOutputRecord) -> Result<(), ExecutionOutputSinkError>;
}

/// Sanitized rejection from an [`ExecutionOutputSink`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionOutputSinkError;

/// Output sink used by endpoint operations whose output is consumed only from
/// their terminal result.
#[derive(Clone, Copy, Debug, Default)]
pub struct DiscardExecutionOutput;

impl ExecutionOutputSink for DiscardExecutionOutput {
    fn observe(&self, _record: &ExecutionOutputRecord) -> Result<(), ExecutionOutputSinkError> {
        Ok(())
    }
}

/// Returns a shared sink that deliberately discards incremental observations.
#[must_use]
pub fn discard_execution_output() -> Arc<dyn ExecutionOutputSink> {
    Arc::new(DiscardExecutionOutput)
}

impl ExecutionOutputRecord {
    /// Constructs one non-empty bounded data record.
    ///
    /// # Errors
    ///
    /// Rejects an empty payload or one larger than
    /// [`crate::MAX_EXECUTION_OUTPUT_RECORD_BYTES`].
    pub fn data(
        stream: ExecutionOutputStream,
        bytes: impl Into<Vec<u8>>,
    ) -> Result<Self, ValueError> {
        let bytes = bytes.into();
        if bytes.is_empty() || bytes.len() > MAX_EXECUTION_OUTPUT_RECORD_BYTES {
            return Err(ValueError::InvalidExecutionOutput);
        }
        Ok(Self {
            stream,
            bytes,
            end_of_stream: false,
        })
    }

    /// Constructs the terminal observation for one process pipe.
    #[must_use]
    pub const fn end_of_stream(stream: ExecutionOutputStream) -> Self {
        Self {
            stream,
            bytes: Vec::new(),
            end_of_stream: true,
        }
    }

    /// Returns the pipe observed for this record.
    #[must_use]
    pub const fn stream(&self) -> ExecutionOutputStream {
        self.stream
    }

    /// Borrows captured bytes, or an empty slice for an end-of-stream record.
    ///
    /// Output can contain credentials or other workflow data. Consumers must
    /// apply output policy before persistence.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Reports whether this record closes its pipe.
    #[must_use]
    pub const fn is_end_of_stream(&self) -> bool {
        self.end_of_stream
    }
}

impl fmt::Debug for ExecutionOutputRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionOutputRecord")
            .field("stream", &self.stream)
            .field("bytes", &self.bytes.len())
            .field("output", &"[REDACTED]")
            .field("end_of_stream", &self.end_of_stream)
            .finish()
    }
}

/// Bounded command output. Debug formatting never prints command output.
#[derive(Clone, Eq, PartialEq)]
pub struct ExecutionOutput {
    termination: ExecutionTermination,
    records: Vec<ExecutionOutputRecord>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    truncated: bool,
}

impl ExecutionOutput {
    /// Constructs adapter output after enforcing the request's bound.
    ///
    /// This constructor enforces the global hard limit; because it does not
    /// receive an [`ExecutionCommand`], the adapter must separately enforce
    /// that request's usually smaller [`ExecutionCommand::output_limit`].
    ///
    /// # Errors
    ///
    /// Rejects malformed ordering, missing terminal records for complete
    /// capture, or record and aggregate output beyond global hard limits.
    pub fn new(
        termination: ExecutionTermination,
        records: Vec<ExecutionOutputRecord>,
        truncated: bool,
    ) -> Result<Self, ValueError> {
        if records.len() > MAX_EXECUTION_OUTPUT_RECORDS {
            return Err(ValueError::InvalidExecutionOutput);
        }
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut stdout_ended = false;
        let mut stderr_ended = false;
        for record in &records {
            let ended = match record.stream {
                ExecutionOutputStream::Stdout => &mut stdout_ended,
                ExecutionOutputStream::Stderr => &mut stderr_ended,
            };
            if *ended {
                return Err(ValueError::InvalidExecutionOutput);
            }
            if record.end_of_stream {
                if !record.bytes.is_empty() {
                    return Err(ValueError::InvalidExecutionOutput);
                }
                *ended = true;
                continue;
            }
            if record.bytes.is_empty() || record.bytes.len() > MAX_EXECUTION_OUTPUT_RECORD_BYTES {
                return Err(ValueError::InvalidExecutionOutput);
            }
            let destination = match record.stream {
                ExecutionOutputStream::Stdout => &mut stdout,
                ExecutionOutputStream::Stderr => &mut stderr,
            };
            destination.extend_from_slice(&record.bytes);
            if stdout
                .len()
                .checked_add(stderr.len())
                .is_none_or(|bytes| bytes > MAX_EXECUTION_OUTPUT_BYTES)
            {
                return Err(ValueError::InvalidByteLimit);
            }
        }
        if !(truncated || stdout_ended && stderr_ended) {
            return Err(ValueError::InvalidExecutionOutput);
        }
        Ok(Self {
            termination,
            records,
            stdout,
            stderr,
            truncated,
        })
    }

    /// Returns the endpoint's reported command outcome.
    #[must_use]
    pub const fn termination(&self) -> ExecutionTermination {
        self.termination
    }

    /// Returns process-output observations in their canonical cross-pipe order.
    ///
    /// Consumers interpreting stateful workflow commands must use this sequence
    /// rather than concatenating the per-pipe convenience views.
    #[must_use]
    pub fn records(&self) -> &[ExecutionOutputRecord] {
        &self.records
    }

    /// Returns captured standard output bytes.
    ///
    /// Output can contain credentials or other workflow data and is redacted
    /// from `Debug`; consumers must apply output policy before persistence.
    #[must_use]
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    /// Returns captured standard error bytes.
    ///
    /// Output can contain credentials or other workflow data and is redacted
    /// from `Debug`; consumers must apply output policy before persistence.
    #[must_use]
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    /// Returns whether capture was incomplete or may have omitted bytes.
    ///
    /// This covers output or record limits, pipe-read failure, worker failure,
    /// and capture deadlines. Consumers must not interpret retained user bytes
    /// or workflow commands when this is `true`.
    #[must_use]
    pub const fn was_truncated(&self) -> bool {
        self.truncated
    }
}

impl fmt::Debug for ExecutionOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionOutput")
            .field("termination", &self.termination)
            .field("records", &self.records.len())
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr_bytes", &self.stderr.len())
            .field("output", &"[REDACTED]")
            .field("truncated", &self.truncated)
            .finish()
    }
}

/// Portable signal supported by execution endpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionSignal {
    /// Requests an interrupt suitable for cooperative process cancellation.
    Interrupt,
    /// Requests graceful process termination.
    Terminate,
    /// Requests immediate, non-graceful process termination.
    Kill,
}

/// Signal request with a stable correlation identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalRequest {
    operation_id: OperationId,
    signal: ExecutionSignal,
}

impl SignalRequest {
    /// Creates an operation-identified request for one portable signal.
    #[must_use]
    pub const fn new(operation_id: OperationId, signal: ExecutionSignal) -> Self {
        Self {
            operation_id,
            signal,
        }
    }

    /// Returns the stable correlation identifier for this exact signal request.
    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    /// Returns the portable signal to deliver.
    #[must_use]
    pub const fn signal(self) -> ExecutionSignal {
        self.signal
    }
}

/// Bounded wait request for the sandbox's primary workload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitRequest {
    operation_id: OperationId,
    timeout: Duration,
}

impl WaitRequest {
    /// Creates a bounded wait request.
    ///
    /// # Errors
    ///
    /// Rejects zero and waits longer than 24 hours.
    pub fn new(operation_id: OperationId, timeout: Duration) -> Result<Self, ValueError> {
        if timeout.is_zero() || timeout > MAX_COMMAND_TIMEOUT {
            return Err(ValueError::InvalidTimeout);
        }
        Ok(Self {
            operation_id,
            timeout,
        })
    }

    /// Returns the stable correlation identifier for this exact wait request.
    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    /// Returns the maximum time to wait for workload termination.
    #[must_use]
    pub const fn timeout(self) -> Duration {
        self.timeout
    }
}

/// Bounded copy-into-sandbox request. Debug formatting redacts payload bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct CopyToRequest {
    operation_id: OperationId,
    target: TargetPath,
    content: Vec<u8>,
}

impl CopyToRequest {
    /// Creates a bounded copy request.
    ///
    /// # Errors
    ///
    /// Rejects content beyond 16 MiB.
    pub fn new(
        operation_id: OperationId,
        target: TargetPath,
        content: Vec<u8>,
    ) -> Result<Self, ValueError> {
        if content.len() > MAX_COPY_BYTES {
            return Err(ValueError::InvalidByteLimit);
        }
        Ok(Self {
            operation_id,
            target,
            content,
        })
    }

    /// Returns the stable correlation identifier for this exact copy request.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the absolute target path inside the sandbox.
    #[must_use]
    pub const fn target(&self) -> &TargetPath {
        &self.target
    }

    /// Returns the bytes to copy into the sandbox.
    ///
    /// Payload bytes may be secret and are redacted from `Debug`.
    #[must_use]
    pub fn content(&self) -> &[u8] {
        &self.content
    }
}

impl fmt::Debug for CopyToRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CopyToRequest")
            .field("operation_id", &self.operation_id)
            .field("target", &self.target)
            .field("content_bytes", &self.content.len())
            .field("content", &"[REDACTED]")
            .finish()
    }
}

/// Bounded copy-from-sandbox request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CopyFromRequest {
    operation_id: OperationId,
    source: TargetPath,
    byte_limit: usize,
}

impl CopyFromRequest {
    /// Creates a bounded copy request.
    ///
    /// # Errors
    ///
    /// Rejects zero and limits beyond 16 MiB.
    pub fn new(
        operation_id: OperationId,
        source: TargetPath,
        byte_limit: usize,
    ) -> Result<Self, ValueError> {
        if byte_limit == 0 || byte_limit > MAX_COPY_BYTES {
            return Err(ValueError::InvalidByteLimit);
        }
        Ok(Self {
            operation_id,
            source,
            byte_limit,
        })
    }

    /// Returns the stable correlation identifier for this exact copy request.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the absolute source path inside the sandbox.
    #[must_use]
    pub const fn source(&self) -> &TargetPath {
        &self.source
    }

    /// Returns the maximum number of bytes the endpoint may return.
    #[must_use]
    pub const fn byte_limit(&self) -> usize {
        self.byte_limit
    }
}

/// Attached execution port. Capabilities are explicit; unsupported operations
/// return [`crate::ExecutionErrorKind::UnsupportedCapability`]. Termination is
/// provider-specific authority observed at adapter cancellation checkpoints;
/// the disposition or an endpoint return is not evidence that remotely
/// initiated work has quiesced.
///
/// Operation identifiers are correlation inputs for an exact-request replay
/// boundary. A raw provider endpoint may be attempt-once; callers that can
/// retry must first install a durable decorator that binds each identifier to
/// the complete request and its protected result. A direct caller must never
/// retry a raw operation after an ambiguous return.
pub trait ExecutionEndpoint: fmt::Debug + Send + Sync {
    /// Returns the exact opaque sandbox handle to which this endpoint is bound.
    fn handle(&self) -> &SandboxHandle;
    /// Returns the fixed endpoint operations supported by this attachment.
    fn capabilities(&self) -> &[SandboxCapability];

    /// Executes one literal argv request.
    ///
    /// Implementations must not insert a shell, must enforce the command's
    /// timeout and aggregate output limit. A replay-owning decorator binds the
    /// operation ID to exact request material before invoking a raw endpoint.
    /// Environment values may contain secrets and must not pass through
    /// durable host-side staging.
    ///
    /// # Errors
    ///
    /// Returns a typed endpoint failure.
    fn exec(
        &self,
        request: &ExecutionCommand,
        cancellation: &dyn Cancellation,
        output: Arc<dyn ExecutionOutputSink>,
    ) -> Result<ExecutionOutput, ExecutionError>;

    /// Signals the sandbox's primary workload.
    ///
    /// Implementations must map only the declared portable signal. A
    /// replay-owning decorator binds the operation ID to the exact request
    /// before invoking a raw endpoint.
    ///
    /// # Errors
    ///
    /// Returns a typed endpoint failure.
    fn signal(
        &self,
        request: SignalRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ExecutionError>;

    /// Waits for the primary workload and returns its exit status.
    ///
    /// A successful return reports a stable platform exit status for the
    /// primary workload; timeout and cancellation remain typed errors.
    ///
    /// # Errors
    ///
    /// Returns a typed endpoint failure.
    fn wait(
        &self,
        request: WaitRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<i32, ExecutionError>;

    /// Copies bounded content to a target path.
    ///
    /// The target is absolute in the provider's target namespace. Isolated
    /// providers resolve it inside the guest filesystem. A trusted native
    /// provider serving a `HostFilesystem` capability may map it to host
    /// syntax only after proving that it remains within the sandbox-owned
    /// workspace or scratch root. Content may contain secrets and must use an
    /// anonymous bounded transport rather than durable host-side staging.
    ///
    /// # Errors
    ///
    /// Returns a typed endpoint failure.
    fn copy_to(
        &self,
        request: &CopyToRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ExecutionError>;

    /// Copies bounded content from a target path.
    ///
    /// Implementations must reject or truncate before returning more than
    /// [`CopyFromRequest::byte_limit`]. A trusted native provider serving a
    /// `HostFilesystem` capability may resolve the target against the host
    /// only after proving that it remains within the sandbox-owned workspace
    /// or scratch root. Returned bytes may contain secrets. A durable replay
    /// layer must protect and authenticate them before storage and may journal
    /// only their opaque protected-content identity.
    ///
    /// # Errors
    ///
    /// Returns a typed endpoint failure.
    fn copy_from(
        &self,
        request: &CopyFromRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<Vec<u8>, ExecutionError>;
}
