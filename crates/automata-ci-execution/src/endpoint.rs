use std::{collections::BTreeSet, fmt, time::Duration};

use automata_ci_core::{
    MAX_WINDOWS_ACTION_ARCHIVE_DEFINITION_BYTES, MAX_WINDOWS_ACTION_ARCHIVE_DEPTH,
    MAX_WINDOWS_ACTION_ARCHIVE_ENTRIES, MAX_WINDOWS_ACTION_ARCHIVE_EXPANDED_BYTES,
    MAX_WINDOWS_ACTION_ARCHIVE_FILE_BYTES, MAX_WINDOWS_ACTION_ARCHIVE_PATH_BYTES,
    MAX_WINDOWS_ACTION_ARCHIVE_PATH_INDEX_BYTES, MAX_WINDOWS_ACTION_GRAPH_ARCHIVES,
    MAX_WINDOWS_ACTION_GRAPH_COMPRESSED_BYTES, MAX_WINDOWS_ACTION_GRAPH_EXPANDED_BYTES,
    MAX_WINDOWS_ACTION_GRAPH_REGULAR_FILES, MAX_WINDOWS_ACTION_SUBPATH_BYTES,
    WINDOWS_ACTION_ARCHIVE_MEDIA_TYPE, WINDOWS_ACTION_NAMESPACE_POLICY_VERSION,
    WindowsActionArchiveFacts, WindowsRepositoryActionArchive, WindowsRepositoryActionGraph,
    valid_windows_action_path_component, windows_action_archive_policy_sha256,
};
use sha2::{Digest as _, Sha256};

use crate::{
    MAX_COPY_BYTES, MAX_EXECUTION_ARGUMENTS, MAX_EXECUTION_ARGV_BYTES, MAX_EXECUTION_OUTPUT_BYTES,
    MAX_EXECUTION_OUTPUT_RECORD_BYTES, MAX_EXECUTION_OUTPUT_RECORDS, OperationId,
    SandboxCapability, SandboxGeneration, SandboxHandle, TargetPath, ValueError,
    error::ExecutionError,
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
///
/// Windows repository actions add one whole-graph materialization transaction
/// to the two provider-neutral setup calls. This is a maximum, so non-Windows
/// jobs simply leave that durable-operation slot unused.
const ENDPOINT_JOB_SETUP_OPERATIONS: usize = 3;

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

/// One immutable archive in a complete, ordered action graph.
#[derive(Clone, Eq, PartialEq)]
pub struct ActionArchiveMaterialization {
    planned: WindowsRepositoryActionArchive,
    subpath: String,
    destination: TargetPath,
    content: Vec<u8>,
}

/// Fixed expansion and namespace policy independently enforced by the broker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::struct_field_names)]
pub struct SealedActionArchivePolicy {
    schema_version: u16,
    policy_sha256: crate::Sha256Digest,
    maximum_action_subpath_bytes: u64,
    maximum_entries: u32,
    maximum_file_bytes: u64,
    maximum_expanded_bytes: u64,
    maximum_definition_bytes: u64,
    maximum_depth: u16,
    maximum_path_bytes: u16,
    maximum_path_index_bytes: u64,
}

impl SealedActionArchivePolicy {
    /// Returns the exact current Windows archive namespace and expansion
    /// policy. Providers must reject requests whose version, digest, or fixed
    /// ceilings differ from this value before mutating a sandbox.
    #[must_use]
    pub fn windows_v2() -> Self {
        Self {
            schema_version: WINDOWS_ACTION_NAMESPACE_POLICY_VERSION,
            policy_sha256: windows_action_archive_policy_sha256(),
            maximum_action_subpath_bytes: u64::try_from(MAX_WINDOWS_ACTION_SUBPATH_BYTES)
                .unwrap_or(u64::MAX),
            maximum_entries: MAX_WINDOWS_ACTION_ARCHIVE_ENTRIES,
            maximum_file_bytes: MAX_WINDOWS_ACTION_ARCHIVE_FILE_BYTES,
            maximum_expanded_bytes: MAX_WINDOWS_ACTION_ARCHIVE_EXPANDED_BYTES,
            maximum_definition_bytes: MAX_WINDOWS_ACTION_ARCHIVE_DEFINITION_BYTES,
            maximum_depth: MAX_WINDOWS_ACTION_ARCHIVE_DEPTH,
            maximum_path_bytes: MAX_WINDOWS_ACTION_ARCHIVE_PATH_BYTES,
            maximum_path_index_bytes: u64::try_from(MAX_WINDOWS_ACTION_ARCHIVE_PATH_INDEX_BYTES)
                .unwrap_or(u64::MAX),
        }
    }

    /// Returns the exact namespace-policy schema version.
    #[must_use]
    pub const fn schema_version(self) -> u16 {
        self.schema_version
    }

    /// Returns the canonical namespace and expansion-policy digest.
    #[must_use]
    pub const fn policy_sha256(self) -> crate::Sha256Digest {
        self.policy_sha256
    }

    /// Returns whether this is the complete current Windows policy.
    #[must_use]
    pub fn is_current_windows(self) -> bool {
        self == Self::windows_v2()
    }

    /// Returns the maximum encoded bytes in one repository-action subdirectory.
    #[must_use]
    pub const fn maximum_action_subpath_bytes(self) -> u64 {
        self.maximum_action_subpath_bytes
    }

    /// Returns the maximum tar-entry count, including metadata entries.
    #[must_use]
    pub const fn maximum_entries(self) -> u32 {
        self.maximum_entries
    }

    /// Returns the maximum expanded bytes permitted for one regular file.
    #[must_use]
    pub const fn maximum_file_bytes(self) -> u64 {
        self.maximum_file_bytes
    }

    /// Returns the maximum aggregate declared expanded bytes per archive.
    #[must_use]
    pub const fn maximum_expanded_bytes(self) -> u64 {
        self.maximum_expanded_bytes
    }

    /// Returns the maximum bytes retained for one definition or global PAX record.
    #[must_use]
    pub const fn maximum_definition_bytes(self) -> u64 {
        self.maximum_definition_bytes
    }

    /// Returns the maximum materialized component depth below the archive root.
    #[must_use]
    pub const fn maximum_depth(self) -> u16 {
        self.maximum_depth
    }

    /// Returns the maximum encoded path bytes for one archive entry.
    #[must_use]
    pub const fn maximum_path_bytes(self) -> u16 {
        self.maximum_path_bytes
    }

    /// Returns the maximum aggregate bytes retained by the path index.
    #[must_use]
    pub const fn maximum_path_index_bytes(self) -> u64 {
        self.maximum_path_index_bytes
    }
}

impl ActionArchiveMaterialization {
    /// Builds one graph entry from an already validated immutable archive.
    ///
    /// # Errors
    ///
    /// Rejects non-Windows destinations, empty/oversized archives, or content
    /// which differs from the complete pre-scheduling descriptor.
    pub fn new(
        planned: WindowsRepositoryActionArchive,
        destination: TargetPath,
        content: Vec<u8>,
    ) -> Result<Self, ValueError> {
        let subpath = planned.subpath().replace('/', "\\");
        let content_digest = crate::Sha256Digest::from_bytes(Sha256::digest(&content).into());
        let content_len = u64::try_from(content.len()).ok();
        if destination.platform() != crate::TargetPlatform::Windows
            || !valid_sealed_absolute_path(destination.as_str())
            || content.is_empty()
            || content.len() > MAX_COPY_BYTES
            || planned.archive().media_type() != WINDOWS_ACTION_ARCHIVE_MEDIA_TYPE
            || content_len != Some(planned.archive().encoded_size())
            || content_digest != planned.archive().digest()
            || (!subpath.is_empty() && !valid_sealed_relative_path(&subpath))
        {
            return Err(ValueError::InvalidByteLimit);
        }
        Ok(Self {
            planned,
            subpath,
            destination,
            content,
        })
    }

    /// Returns the complete descriptor committed into the admitted `JobIR`.
    #[must_use]
    pub const fn planned(&self) -> &WindowsRepositoryActionArchive {
        &self.planned
    }

    /// Returns this entry's exact zero-based graph ordinal.
    #[must_use]
    pub const fn ordinal(&self) -> u32 {
        self.planned.ordinal()
    }

    /// Returns the digest of the canonical action reference key.
    #[must_use]
    pub const fn action_key_sha256(&self) -> crate::Sha256Digest {
        self.planned.action_key_sha256()
    }

    /// Returns the validated subpath selected within this immutable archive.
    #[must_use]
    pub fn subpath(&self) -> &str {
        &self.subpath
    }

    /// Returns the new provider-owned destination root.
    #[must_use]
    pub const fn destination(&self) -> &TargetPath {
        &self.destination
    }

    /// Returns the immutable archive bytes.
    #[must_use]
    pub fn content(&self) -> &[u8] {
        &self.content
    }

    /// Returns the archive digest the provider must reproduce before writing.
    #[must_use]
    pub const fn sha256(&self) -> crate::Sha256Digest {
        self.planned.archive().digest()
    }

    /// Returns the expansion facts independently reproduced before scheduling.
    #[must_use]
    pub const fn facts(&self) -> WindowsActionArchiveFacts {
        self.planned.facts()
    }
}

impl fmt::Debug for ActionArchiveMaterialization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActionArchiveMaterialization")
            .field("planned", &self.planned)
            .field("ordinal", &self.ordinal())
            .field("action_key_sha256", &self.action_key_sha256())
            .field("subpath", &self.subpath)
            .field("destination", &self.destination)
            .field("content_bytes", &self.content.len())
            .field("sha256", &self.sha256())
            .field("facts", &self.facts())
            .field("content", &"[REDACTED]")
            .finish()
    }
}

/// Complete immutable action graph materialized in one provider transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionGraphMaterializationRequest {
    operation_id: OperationId,
    sandbox: SandboxHandle,
    generation: SandboxGeneration,
    plan_sha256: crate::Sha256Digest,
    graph_sha256: crate::Sha256Digest,
    archive_policy: SealedActionArchivePolicy,
    archives: Vec<ActionArchiveMaterialization>,
}

impl ActionGraphMaterializationRequest {
    /// Builds one exact ordered graph request.
    ///
    /// # Errors
    ///
    /// Rejects an empty/oversized graph, a graph which does not reconstruct to
    /// the pre-scheduling digest, non-contiguous ordinals, repeated
    /// destinations, or aggregate archive content over 16 MiB.
    pub fn new(
        operation_id: OperationId,
        sandbox: SandboxHandle,
        generation: SandboxGeneration,
        plan_sha256: crate::Sha256Digest,
        archives: Vec<ActionArchiveMaterialization>,
    ) -> Result<Self, ValueError> {
        let archive_policy = SealedActionArchivePolicy::windows_v2();
        let planned_graph = WindowsRepositoryActionGraph::new(
            archives
                .iter()
                .map(|archive| archive.planned().clone())
                .collect(),
        )
        .map_err(|_| ValueError::InvalidByteLimit)?;
        if archives.is_empty()
            || archives.len() > MAX_WINDOWS_ACTION_GRAPH_ARCHIVES
            || plan_sha256.as_bytes().iter().all(|byte| *byte == 0)
            || planned_graph.graph_sha256() != plan_sha256
            || planned_graph.policy_sha256() != archive_policy.policy_sha256()
            || archives
                .iter()
                .enumerate()
                .any(|(index, archive)| usize::try_from(archive.ordinal()) != Ok(index))
            || archives
                .iter()
                .map(|archive| archive.content.len())
                .try_fold(0_usize, usize::checked_add)
                .is_none_or(|bytes| {
                    u64::try_from(bytes)
                        .ok()
                        .is_none_or(|bytes| bytes > MAX_WINDOWS_ACTION_GRAPH_COMPRESSED_BYTES)
                })
            || archives
                .iter()
                .map(|archive| archive.facts().expanded_bytes())
                .try_fold(0_u64, u64::checked_add)
                .is_none_or(|bytes| bytes > MAX_WINDOWS_ACTION_GRAPH_EXPANDED_BYTES)
            || archives
                .iter()
                .map(|archive| u64::from(archive.facts().regular_file_count()))
                .try_fold(0_u64, u64::checked_add)
                .is_none_or(|files| files > MAX_WINDOWS_ACTION_GRAPH_REGULAR_FILES)
        {
            return Err(ValueError::InvalidByteLimit);
        }
        let mut destinations = archives
            .iter()
            .map(|archive| archive.destination.as_str().to_ascii_lowercase())
            .collect::<Vec<_>>();
        destinations.sort_unstable();
        for (index, destination) in destinations.iter().enumerate() {
            if destinations[index + 1..].iter().any(|other| {
                destination == other
                    || other.starts_with(&(destination.clone() + "\\"))
                    || destination.starts_with(&(other.clone() + "\\"))
            }) {
                return Err(ValueError::InvalidTargetPath);
            }
        }
        let graph_sha256 = action_graph_sha256(archive_policy, plan_sha256, &archives);
        Ok(Self {
            operation_id,
            sandbox,
            generation,
            plan_sha256,
            graph_sha256,
            archive_policy,
            archives,
        })
    }

    /// Returns the stable correlation identifier.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the exact sandbox which must own the sealed graph.
    #[must_use]
    pub const fn sandbox(&self) -> &SandboxHandle {
        &self.sandbox
    }

    /// Returns the lease-fencing generation which must own the sealed graph.
    #[must_use]
    pub const fn generation(&self) -> SandboxGeneration {
        self.generation
    }

    /// Returns the pre-scheduling graph identity committed into `JobIR`.
    #[must_use]
    pub const fn plan_sha256(&self) -> crate::Sha256Digest {
        self.plan_sha256
    }

    /// Returns the canonical complete graph digest.
    #[must_use]
    pub const fn graph_sha256(&self) -> crate::Sha256Digest {
        self.graph_sha256
    }

    /// Returns the fixed broker-enforced archive expansion policy.
    #[must_use]
    pub const fn archive_policy(&self) -> SealedActionArchivePolicy {
        self.archive_policy
    }

    /// Returns every archive in deterministic graph order.
    #[must_use]
    pub fn archives(&self) -> &[ActionArchiveMaterialization] {
        &self.archives
    }
}

fn action_graph_sha256(
    policy: SealedActionArchivePolicy,
    plan_sha256: crate::Sha256Digest,
    archives: &[ActionArchiveMaterialization],
) -> crate::Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"automata.windows.sealed-action-graph.v2\0");
    hasher.update(policy.schema_version.to_le_bytes());
    hasher.update(policy.policy_sha256.as_bytes());
    hasher.update(policy.maximum_action_subpath_bytes.to_le_bytes());
    hasher.update(policy.maximum_entries.to_le_bytes());
    hasher.update(policy.maximum_file_bytes.to_le_bytes());
    hasher.update(policy.maximum_expanded_bytes.to_le_bytes());
    hasher.update(policy.maximum_definition_bytes.to_le_bytes());
    hasher.update(policy.maximum_depth.to_le_bytes());
    hasher.update(policy.maximum_path_bytes.to_le_bytes());
    hasher.update(policy.maximum_path_index_bytes.to_le_bytes());
    hasher.update(plan_sha256.as_bytes());
    hasher.update(
        u64::try_from(archives.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for archive in archives {
        hasher.update(archive.ordinal().to_le_bytes());
        hasher.update(archive.action_key_sha256().as_bytes());
        hasher.update(archive.sha256().as_bytes());
        hasher.update(archive.facts().entry_count().to_le_bytes());
        hasher.update(archive.facts().regular_file_count().to_le_bytes());
        hasher.update(archive.facts().expanded_bytes().to_le_bytes());
        hasher.update(archive.facts().maximum_regular_file_bytes().to_le_bytes());
        hasher.update(archive.facts().maximum_depth().to_le_bytes());
        update_graph_string(&mut hasher, archive.planned().archive().object_key());
        hasher.update(archive.planned().archive().encoded_size().to_le_bytes());
        update_graph_string(&mut hasher, archive.planned().archive().media_type());
        update_graph_string(&mut hasher, &archive.subpath);
        update_graph_string(&mut hasher, archive.destination.as_str());
    }
    crate::Sha256Digest::from_bytes(hasher.finalize().into())
}

fn update_graph_string(hasher: &mut Sha256, value: &str) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(value.as_bytes());
}

/// Opaque provider receipt for one immutable, sandbox-bound action tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedActionTree {
    sandbox: SandboxHandle,
    generation: SandboxGeneration,
    graph_opaque: String,
    graph_sha256: crate::Sha256Digest,
    ordinal: u32,
    root: TargetPath,
    receipt_sha256: crate::Sha256Digest,
}

impl SealedActionTree {
    /// Creates a provider result after atomic materialization and sealing.
    ///
    /// # Errors
    ///
    /// Rejects non-portable handles, non-Windows roots, and zero receipts.
    pub fn new(
        sandbox: SandboxHandle,
        generation: SandboxGeneration,
        graph_opaque: impl Into<String>,
        graph_sha256: crate::Sha256Digest,
        ordinal: u32,
        root: TargetPath,
        receipt_sha256: crate::Sha256Digest,
    ) -> Result<Self, ValueError> {
        let graph_opaque = graph_opaque.into();
        let valid_opaque = !graph_opaque.is_empty()
            && graph_opaque.len() <= crate::MAX_SANDBOX_HANDLE_BYTES
            && graph_opaque
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
        if !valid_opaque
            || root.platform() != crate::TargetPlatform::Windows
            || !valid_sealed_absolute_path(root.as_str())
            || graph_sha256.as_bytes().iter().all(|byte| *byte == 0)
            || receipt_sha256.as_bytes().iter().all(|byte| *byte == 0)
        {
            return Err(ValueError::InvalidSandboxHandle);
        }
        Ok(Self {
            sandbox,
            generation,
            graph_opaque,
            graph_sha256,
            ordinal,
            root,
            receipt_sha256,
        })
    }

    /// Returns the exact sandbox ownership binding.
    #[must_use]
    pub const fn sandbox(&self) -> &SandboxHandle {
        &self.sandbox
    }

    /// Returns the lease-fencing generation which owns this tree.
    #[must_use]
    pub const fn generation(&self) -> SandboxGeneration {
        self.generation
    }

    /// Returns the provider-owned opaque seal handle.
    #[must_use]
    pub fn graph_opaque(&self) -> &str {
        &self.graph_opaque
    }

    /// Returns the canonical complete graph digest bound into this tree seal.
    #[must_use]
    pub const fn graph_sha256(&self) -> crate::Sha256Digest {
        self.graph_sha256
    }

    /// Returns this tree's exact ordinal in the sealed graph.
    #[must_use]
    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    /// Returns the published read-only tree root.
    #[must_use]
    pub const fn root(&self) -> &TargetPath {
        &self.root
    }

    /// Returns the authenticated materialization receipt digest.
    #[must_use]
    pub const fn receipt_sha256(&self) -> crate::Sha256Digest {
        self.receipt_sha256
    }
}

/// Provider result proving that a complete graph was sealed before execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedActionGraph {
    sandbox: SandboxHandle,
    generation: SandboxGeneration,
    graph_sha256: crate::Sha256Digest,
    receipt_sha256: crate::Sha256Digest,
    trees: Vec<SealedActionTree>,
}

impl SealedActionGraph {
    /// Creates a provider-authenticated complete graph result.
    ///
    /// # Errors
    ///
    /// Rejects empty graphs, zero digests, mismatched sandbox ownership,
    /// graph handles, or non-contiguous tree ordinals.
    pub fn new(
        sandbox: SandboxHandle,
        generation: SandboxGeneration,
        graph_sha256: crate::Sha256Digest,
        receipt_sha256: crate::Sha256Digest,
        trees: Vec<SealedActionTree>,
    ) -> Result<Self, ValueError> {
        let graph_opaque = trees.first().map(SealedActionTree::graph_opaque);
        if trees.is_empty()
            || graph_sha256.as_bytes().iter().all(|byte| *byte == 0)
            || receipt_sha256.as_bytes().iter().all(|byte| *byte == 0)
            || trees.iter().enumerate().any(|(index, tree)| {
                tree.sandbox() != &sandbox
                    || tree.generation() != generation
                    || tree.graph_sha256() != graph_sha256
                    || usize::try_from(tree.ordinal()) != Ok(index)
                    || Some(tree.graph_opaque()) != graph_opaque
            })
        {
            return Err(ValueError::InvalidSandboxHandle);
        }
        Ok(Self {
            sandbox,
            generation,
            graph_sha256,
            receipt_sha256,
            trees,
        })
    }

    /// Returns the exact sandbox ownership binding.
    #[must_use]
    pub const fn sandbox(&self) -> &SandboxHandle {
        &self.sandbox
    }

    /// Returns the lease-fencing generation which owns the graph.
    #[must_use]
    pub const fn generation(&self) -> SandboxGeneration {
        self.generation
    }

    /// Returns the canonical graph digest reproduced by the provider.
    #[must_use]
    pub const fn graph_sha256(&self) -> crate::Sha256Digest {
        self.graph_sha256
    }

    /// Returns the authenticated whole-graph receipt digest.
    #[must_use]
    pub const fn receipt_sha256(&self) -> crate::Sha256Digest {
        self.receipt_sha256
    }

    /// Returns sealed trees in exact request order.
    #[must_use]
    pub fn trees(&self) -> &[SealedActionTree] {
        &self.trees
    }
}

/// Bounded read through an already validated sealed-tree handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedActionReadRequest {
    operation_id: OperationId,
    tree: SealedActionTree,
    relative_path: String,
    byte_limit: usize,
}

impl SealedActionReadRequest {
    /// Creates a read which cannot name an absolute, alternate-stream, device,
    /// dot-segment, or ambiguous Windows path.
    ///
    /// # Errors
    ///
    /// Rejects invalid relative paths and zero/oversized limits.
    pub fn new(
        operation_id: OperationId,
        tree: SealedActionTree,
        relative_path: impl Into<String>,
        byte_limit: usize,
    ) -> Result<Self, ValueError> {
        let relative_path = relative_path.into();
        if !valid_sealed_relative_path(&relative_path)
            || byte_limit == 0
            || byte_limit > MAX_COPY_BYTES
        {
            return Err(ValueError::InvalidTargetPath);
        }
        Ok(Self {
            operation_id,
            tree,
            relative_path,
            byte_limit,
        })
    }

    /// Returns the stable correlation identifier.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the provider-owned tree seal.
    #[must_use]
    pub const fn tree(&self) -> &SealedActionTree {
        &self.tree
    }

    /// Returns the validated relative target.
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    /// Returns the maximum response bytes.
    #[must_use]
    pub const fn byte_limit(&self) -> usize {
        self.byte_limit
    }
}

fn valid_sealed_relative_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4_096
        && value.is_ascii()
        && !value.contains('/')
        && !value.starts_with('\\')
        && value.split('\\').all(valid_windows_action_path_component)
}

fn valid_sealed_absolute_path(value: &str) -> bool {
    value.is_ascii()
        && value.len() >= 4
        && value.as_bytes()[0].is_ascii_uppercase()
        && &value.as_bytes()[1..3] == b":\\"
        && value
            .split('\\')
            .skip(1)
            .all(valid_windows_action_path_component)
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

    /// Atomically materializes and seals a complete immutable action graph.
    ///
    /// Implementations must reproduce every archive and graph digest before
    /// the first destination write, create all entries beneath a provider-
    /// owned root using no-follow handles, reject reparse points, hard links,
    /// alternate streams and Windows namespace aliases, seal the tree against
    /// the workload identity, and retain ownership handles through execution.
    /// No action process may execute until this transaction has committed.
    ///
    /// # Errors
    ///
    /// Returns a typed endpoint failure. The default fails closed.
    fn materialize_action_graph(
        &self,
        _request: &ActionGraphMaterializationRequest,
        _cancellation: &dyn Cancellation,
    ) -> Result<SealedActionGraph, ExecutionError> {
        Err(ExecutionError::new(
            crate::ExecutionErrorKind::UnsupportedCapability,
            crate::ExecutionStage::MaterializeAction,
        ))
    }

    /// Reads bounded metadata through a provider-owned sealed-tree handle.
    /// Implementations must treat every public value as untrusted and match
    /// the opaque handle, sandbox identity and generation, graph digest, tree
    /// ordinal, root identity, and authenticated receipt against their live
    /// broker ledger before opening the retained handle.
    ///
    /// # Errors
    ///
    /// Returns a typed endpoint failure. The default fails closed.
    fn read_sealed_action(
        &self,
        _request: &SealedActionReadRequest,
        _cancellation: &dyn Cancellation,
    ) -> Result<Vec<u8>, ExecutionError> {
        Err(ExecutionError::new(
            crate::ExecutionErrorKind::UnsupportedCapability,
            crate::ExecutionStage::ReadSealedAction,
        ))
    }

    /// Executes one command while the provider reattests and retains a sealed
    /// tree's root identity, volume, link count, streams, owner and DACL.
    /// Public receipt structs are transport values, not authority: every field
    /// must match the broker's live sandbox-generation and graph ledger.
    ///
    /// # Errors
    ///
    /// Returns a typed endpoint failure. The default fails closed.
    fn exec_sealed_action(
        &self,
        _request: &ExecutionCommand,
        _tree: &SealedActionTree,
        _cancellation: &dyn Cancellation,
    ) -> Result<ExecutionOutput, ExecutionError> {
        Err(ExecutionError::new(
            crate::ExecutionErrorKind::UnsupportedCapability,
            crate::ExecutionStage::ExecSealedAction,
        ))
    }
}

#[cfg(test)]
mod sealed_action_tests {
    use automata_ci_core::{
        WINDOWS_ACTION_ARCHIVE_MEDIA_TYPE, WindowsRepositoryActionArchive,
        WindowsRepositoryActionGraph,
    };
    use sha2::{Digest as _, Sha256};

    use super::*;

    #[derive(Debug)]
    struct ProviderNeutralEndpoint {
        handle: SandboxHandle,
    }

    impl ExecutionEndpoint for ProviderNeutralEndpoint {
        fn handle(&self) -> &SandboxHandle {
            &self.handle
        }

        fn capabilities(&self) -> &[SandboxCapability] {
            &[]
        }

        fn exec(
            &self,
            _request: &ExecutionCommand,
            _cancellation: &dyn Cancellation,
        ) -> Result<ExecutionOutput, ExecutionError> {
            unreachable!("not used by sealed-action default tests")
        }

        fn signal(
            &self,
            _request: SignalRequest,
            _cancellation: &dyn Cancellation,
        ) -> Result<(), ExecutionError> {
            unreachable!("not used by sealed-action default tests")
        }

        fn wait(
            &self,
            _request: WaitRequest,
            _cancellation: &dyn Cancellation,
        ) -> Result<i32, ExecutionError> {
            unreachable!("not used by sealed-action default tests")
        }

        fn copy_to(
            &self,
            _request: &CopyToRequest,
            _cancellation: &dyn Cancellation,
        ) -> Result<(), ExecutionError> {
            unreachable!("not used by sealed-action default tests")
        }

        fn copy_from(
            &self,
            _request: &CopyFromRequest,
            _cancellation: &dyn Cancellation,
        ) -> Result<Vec<u8>, ExecutionError> {
            unreachable!("not used by sealed-action default tests")
        }
    }

    fn digest(bytes: &[u8]) -> crate::Sha256Digest {
        crate::Sha256Digest::from_bytes(Sha256::digest(bytes).into())
    }

    fn sandbox(name: &str) -> SandboxHandle {
        SandboxHandle::new(
            crate::ProviderId::new("windows-hyperv").expect("provider"),
            name,
        )
        .expect("sandbox")
    }

    fn archive(
        ordinal: u32,
        destination: &str,
        subpath: &str,
    ) -> Result<ActionArchiveMaterialization, ValueError> {
        let content = format!("archive-{ordinal}").into_bytes();
        let content_sha256 = digest(&content);
        let planned = WindowsRepositoryActionArchive::new(
            ordinal,
            crate::Sha256Digest::from_bytes([ordinal.to_le_bytes()[0].saturating_add(1); 32]),
            subpath,
            automata_ci_core::JobContentReference::new(
                format!("windows-actions/{ordinal}.tar.gz"),
                content_sha256,
                u64::try_from(content.len()).expect("fixture size"),
                WINDOWS_ACTION_ARCHIVE_MEDIA_TYPE,
            ),
            WindowsActionArchiveFacts::new(1, 1, 1, 1, 1).expect("facts"),
        )
        .map_err(|_| ValueError::InvalidByteLimit)?;
        ActionArchiveMaterialization::new(planned, TargetPath::windows(destination)?, content)
    }

    fn plan_sha256(archives: &[ActionArchiveMaterialization]) -> crate::Sha256Digest {
        WindowsRepositoryActionGraph::new(
            archives
                .iter()
                .map(|archive| archive.planned().clone())
                .collect(),
        )
        .expect("valid planned graph")
        .graph_sha256()
    }

    fn graph_request(operation_id: OperationId) -> ActionGraphMaterializationRequest {
        let archives = vec![archive(0, r"C:\actions\0000", "").expect("archive")];
        let plan_sha256 = plan_sha256(&archives);
        ActionGraphMaterializationRequest::new(
            operation_id,
            sandbox("sandbox-a"),
            SandboxGeneration::new(7).expect("generation"),
            plan_sha256,
            archives,
        )
        .expect("graph request")
    }

    #[test]
    fn endpoint_budget_reserves_one_atomic_graph_setup_operation() {
        assert_eq!(
            MAX_ENDPOINT_OPERATIONS_PER_JOB,
            automata_ci_core::MAX_LOGICAL_STEPS * ENDPOINT_OPERATIONS_PER_RUN_STEP + 3
        );
    }

    #[test]
    fn provider_neutral_endpoint_defaults_fail_closed_for_sealed_actions() {
        let request = graph_request(OperationId::new());
        let tree = SealedActionTree::new(
            request.sandbox().clone(),
            request.generation(),
            "graph-opaque-v1",
            request.graph_sha256(),
            0,
            request.archives()[0].destination().clone(),
            crate::Sha256Digest::from_bytes([0x61; 32]),
        )
        .expect("tree");
        let read =
            SealedActionReadRequest::new(OperationId::new(), tree.clone(), "action.yml", 1024)
                .expect("read request");
        let command = ExecutionCommand::new(
            OperationId::new(),
            ExecutionArgv::new(
                TargetPath::windows(r"C:\Program Files\nodejs\node.exe").expect("program"),
                vec!["main.js".to_owned()],
            )
            .expect("argv"),
            tree.root().clone(),
            ExecutionEnvironment::empty(),
            Duration::from_secs(30),
            1024,
        )
        .expect("command");
        let endpoint = ProviderNeutralEndpoint {
            handle: request.sandbox().clone(),
        };

        for (error, stage) in [
            (
                endpoint
                    .materialize_action_graph(&request, &NeverCancelled)
                    .expect_err("materialization must fail closed"),
                crate::ExecutionStage::MaterializeAction,
            ),
            (
                endpoint
                    .read_sealed_action(&read, &NeverCancelled)
                    .expect_err("sealed read must fail closed"),
                crate::ExecutionStage::ReadSealedAction,
            ),
            (
                endpoint
                    .exec_sealed_action(&command, &tree, &NeverCancelled)
                    .expect_err("sealed execution must fail closed"),
                crate::ExecutionStage::ExecSealedAction,
            ),
        ] {
            assert_eq!(
                error.kind(),
                crate::ExecutionErrorKind::UnsupportedCapability
            );
            assert_eq!(error.stage(), stage);
        }
    }

    #[test]
    fn graph_rejects_case_insensitive_destination_ancestor_overlap() {
        let archives = vec![
            archive(0, r"C:\actions\Foo", "").expect("first"),
            archive(1, r"C:\actions\foo\child", "").expect("second"),
        ];
        let plan_sha256 = plan_sha256(&archives);
        assert_eq!(
            ActionGraphMaterializationRequest::new(
                OperationId::new(),
                sandbox("sandbox-a"),
                SandboxGeneration::new(7).expect("generation"),
                plan_sha256,
                archives,
            ),
            Err(ValueError::InvalidTargetPath)
        );
    }

    #[test]
    fn materialization_binds_the_exact_v2_namespace_policy() {
        let archives = vec![archive(0, r"C:\actions\safe", "").expect("archive")];
        let plan_sha256 = plan_sha256(&archives);
        let request = ActionGraphMaterializationRequest::new(
            OperationId::new(),
            sandbox("sandbox-policy"),
            SandboxGeneration::new(7).expect("generation"),
            plan_sha256,
            archives.clone(),
        )
        .expect("current materialization request");
        let current = request.archive_policy();
        let legacy = SealedActionArchivePolicy {
            schema_version: 1,
            policy_sha256: current.policy_sha256(),
            maximum_action_subpath_bytes: current.maximum_action_subpath_bytes(),
            maximum_entries: current.maximum_entries(),
            maximum_file_bytes: current.maximum_file_bytes(),
            maximum_expanded_bytes: current.maximum_expanded_bytes(),
            maximum_definition_bytes: current.maximum_definition_bytes(),
            maximum_depth: current.maximum_depth(),
            maximum_path_bytes: current.maximum_path_bytes(),
            maximum_path_index_bytes: current.maximum_path_index_bytes(),
        };

        assert_eq!(current.schema_version(), 2);
        assert_eq!(
            current.policy_sha256(),
            windows_action_archive_policy_sha256()
        );
        assert!(current.is_current_windows());
        assert!(!legacy.is_current_windows());
        assert_ne!(
            request.graph_sha256(),
            action_graph_sha256(legacy, plan_sha256, &archives)
        );
    }

    #[test]
    fn materialization_rejects_correct_plan_hash_with_substituted_archive() {
        let admitted = vec![archive(0, r"C:\actions\safe", "").expect("admitted")];
        let plan_sha256 = plan_sha256(&admitted);
        let substituted =
            vec![archive(0, r"C:\actions\safe", "nested").expect("substituted descriptor")];

        assert_eq!(
            ActionGraphMaterializationRequest::new(
                OperationId::new(),
                sandbox("sandbox-substitution"),
                SandboxGeneration::new(7).expect("generation"),
                plan_sha256,
                substituted,
            ),
            Err(ValueError::InvalidByteLimit)
        );
    }

    #[test]
    fn archive_rejects_windows_namespace_aliases() {
        for destination in [
            r"C:\actions\CON.txt",
            r"C:\actions\CONIN$.js",
            r"C:\actions\CONOUT$.js",
            r"C:\actions\file.js:evil",
            r"C:\actions\LONGFI~1.JS",
            r"C:\actions\CLOCK$",
            r"C:\actions\ leading.js",
        ] {
            assert!(archive(0, destination, "").is_err(), "{destination}");
        }
        for subpath in [
            "CON.txt",
            "CONIN$.js",
            "CONOUT$.js",
            r"folder\file.js:evil",
            "LONGFI~1.JS",
            " leading.js",
            r"\\server\share",
            r"\??\C:\device",
        ] {
            assert!(
                archive(0, r"C:\actions\safe", subpath).is_err(),
                "{subpath}"
            );
        }
    }

    #[test]
    fn sealed_graph_rejects_sandbox_generation_and_graph_substitution() {
        let owner = sandbox("sandbox-a");
        let other = sandbox("sandbox-b");
        let generation = SandboxGeneration::new(7).expect("generation");
        let other_generation = SandboxGeneration::new(8).expect("generation");
        let graph_sha256 = crate::Sha256Digest::from_bytes([0x41; 32]);
        let other_graph_sha256 = crate::Sha256Digest::from_bytes([0x42; 32]);
        let receipt_sha256 = crate::Sha256Digest::from_bytes([0x51; 32]);
        let tree = SealedActionTree::new(
            owner.clone(),
            generation,
            "graph-opaque-v1",
            graph_sha256,
            0,
            TargetPath::windows(r"C:\actions\0000").expect("root"),
            crate::Sha256Digest::from_bytes([0x61; 32]),
        )
        .expect("tree");

        assert!(
            SealedActionGraph::new(
                owner.clone(),
                generation,
                graph_sha256,
                receipt_sha256,
                vec![tree.clone()],
            )
            .is_ok()
        );
        assert_eq!(
            SealedActionGraph::new(
                other,
                generation,
                graph_sha256,
                receipt_sha256,
                vec![tree.clone()],
            ),
            Err(ValueError::InvalidSandboxHandle)
        );
        assert_eq!(
            SealedActionGraph::new(
                owner.clone(),
                other_generation,
                graph_sha256,
                receipt_sha256,
                vec![tree.clone()],
            ),
            Err(ValueError::InvalidSandboxHandle)
        );
        assert_eq!(
            SealedActionGraph::new(
                owner,
                generation,
                other_graph_sha256,
                receipt_sha256,
                vec![tree],
            ),
            Err(ValueError::InvalidSandboxHandle)
        );
    }
}
