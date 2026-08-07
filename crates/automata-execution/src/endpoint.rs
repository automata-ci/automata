use std::{collections::BTreeSet, fmt, time::Duration};

use crate::{
    MAX_COPY_BYTES, MAX_EXECUTION_ARGUMENTS, MAX_EXECUTION_ARGV_BYTES, MAX_EXECUTION_OUTPUT_BYTES,
    OperationId, SandboxCapability, SandboxHandle, TargetPath, ValueError, error::ExecutionError,
};

const MAX_COMMAND_TIMEOUT: Duration = Duration::from_hours(24);
const MAX_ENVIRONMENT_VARIABLES: usize = 1_024;
const MAX_ENVIRONMENT_NAME_BYTES: usize = 128;
const MAX_ENVIRONMENT_VALUE_BYTES: usize = 1024 * 1024;
const MAX_ENVIRONMENT_BYTES: usize = 4 * 1024 * 1024;

/// Cooperative cancellation source shared across provider boundaries.
pub trait Cancellation: Send + Sync {
    #[must_use]
    fn is_cancelled(&self) -> bool;
}

/// Cancellation source that never requests cancellation.
#[derive(Clone, Copy, Debug, Default)]
pub struct NeverCancelled;

impl Cancellation for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

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

    #[must_use]
    pub const fn program(&self) -> &TargetPath {
        &self.program
    }

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
}

impl EnvironmentVariable {
    #[must_use]
    pub const fn new(name: EnvironmentName, value: EnvironmentValue) -> Self {
        Self { name, value }
    }

    #[must_use]
    pub const fn name(&self) -> &EnvironmentName {
        &self.name
    }

    #[must_use]
    pub const fn value(&self) -> &EnvironmentValue {
        &self.value
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

    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    #[must_use]
    pub fn values(&self) -> &[EnvironmentVariable] {
        &self.0
    }

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

/// One idempotently identified command execution.
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

    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn argv(&self) -> &ExecutionArgv {
        &self.argv
    }

    #[must_use]
    pub const fn working_directory(&self) -> &TargetPath {
        &self.working_directory
    }

    #[must_use]
    pub const fn environment(&self) -> &ExecutionEnvironment {
        &self.environment
    }

    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

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

/// How an execution command terminated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionTermination {
    Exited(i32),
    Signalled,
    TimedOut,
    Cancelled,
}

/// Bounded command output. Debug formatting never prints command output.
#[derive(Clone, Eq, PartialEq)]
pub struct ExecutionOutput {
    termination: ExecutionTermination,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    truncated: bool,
}

impl ExecutionOutput {
    /// Constructs adapter output after enforcing the request's bound.
    ///
    /// # Errors
    ///
    /// Rejects aggregate output larger than the global hard limit.
    pub fn new(
        termination: ExecutionTermination,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        truncated: bool,
    ) -> Result<Self, ValueError> {
        if stdout
            .len()
            .checked_add(stderr.len())
            .is_none_or(|bytes| bytes > MAX_EXECUTION_OUTPUT_BYTES)
        {
            return Err(ValueError::InvalidByteLimit);
        }
        Ok(Self {
            termination,
            stdout,
            stderr,
            truncated,
        })
    }

    #[must_use]
    pub const fn termination(&self) -> ExecutionTermination {
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
    pub const fn was_truncated(&self) -> bool {
        self.truncated
    }
}

impl fmt::Debug for ExecutionOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionOutput")
            .field("termination", &self.termination)
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
    Interrupt,
    Terminate,
    Kill,
}

/// Idempotently identified signal request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalRequest {
    operation_id: OperationId,
    signal: ExecutionSignal,
}

impl SignalRequest {
    #[must_use]
    pub const fn new(operation_id: OperationId, signal: ExecutionSignal) -> Self {
        Self {
            operation_id,
            signal,
        }
    }

    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

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

    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

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

    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn target(&self) -> &TargetPath {
        &self.target
    }

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

    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn source(&self) -> &TargetPath {
        &self.source
    }

    #[must_use]
    pub const fn byte_limit(&self) -> usize {
        self.byte_limit
    }
}

/// Attached execution port. Capabilities are explicit; unsupported operations
/// return [`crate::ExecutionErrorKind::UnsupportedCapability`].
pub trait ExecutionEndpoint: fmt::Debug + Send + Sync {
    fn handle(&self) -> &SandboxHandle;
    fn capabilities(&self) -> &[SandboxCapability];

    /// Executes one literal argv request.
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
    /// # Errors
    ///
    /// Returns a typed endpoint failure.
    fn copy_from(
        &self,
        request: &CopyFromRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<Vec<u8>, ExecutionError>;
}
