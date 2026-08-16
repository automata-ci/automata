use std::{
    ffi::OsString,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
};

use automata_ci_execution::{
    Cancellation, CopyFromRequest, CopyToRequest, EnvironmentVariable, ExecutionCommand,
    ExecutionEndpoint, ExecutionEnvironment, ExecutionError, ExecutionErrorKind, ExecutionOutput,
    ExecutionSignal, ExecutionStage, ExecutionTermination, NeverCancelled, SandboxCapability,
    SandboxHandle, SandboxState, SignalRequest, TargetPath, TargetPlatform, WaitRequest,
};

use crate::{
    CommandOutput, CommandTermination,
    command::provider_control_environment_name,
    naming::ResourceNames,
    provider::{PodmanInner, endpoint_capabilities, endpoint_error_from_provider},
};

const MAX_PODMAN_ENV_DOCUMENT_LINE_BYTES: usize = 64 * 1024 - 1;
const MAX_PODMAN_INHERITED_ENVIRONMENT_BYTES: usize = 64 * 1024;
const PODMAN_STDIN_ENVIRONMENT_PATH: &str = "/dev/stdin";
const TAR_BLOCK_BYTES: usize = 512;
const TAR_END_BLOCKS: usize = 2;
const TAR_NAME_BYTES: usize = 100;

pub(crate) struct EnvironmentDocument<'environment> {
    variables: &'environment [EnvironmentVariable],
    byte_len: usize,
}

impl EnvironmentDocument<'_> {
    pub(crate) const fn is_empty(&self) -> bool {
        self.variables.is_empty()
    }

    pub(crate) const fn byte_len(&self) -> usize {
        self.byte_len
    }

    pub(crate) const fn has_env_file(&self) -> bool {
        self.byte_len != 0
    }

    pub(crate) fn variables(&self) -> &[EnvironmentVariable] {
        self.variables
    }

    pub(crate) fn inherited_variables(&self) -> impl Iterator<Item = &EnvironmentVariable> {
        self.variables
            .iter()
            .filter(|variable| requires_process_inheritance(variable.value().expose()))
    }
}

impl fmt::Debug for EnvironmentDocument<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvironmentDocument")
            .field("variable_count", &self.variables.len())
            .field("byte_len", &self.byte_len)
            .field("values", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct PodmanExecutionEndpoint {
    inner: Arc<PodmanInner>,
    handle: SandboxHandle,
    names: ResourceNames,
    operation_lock: Arc<Mutex<()>>,
}

impl PodmanExecutionEndpoint {
    pub(crate) const fn new(
        inner: Arc<PodmanInner>,
        handle: SandboxHandle,
        names: ResourceNames,
        operation_lock: Arc<Mutex<()>>,
    ) -> Self {
        Self {
            inner,
            handle,
            names,
            operation_lock,
        }
    }

    fn acquire(&self, stage: ExecutionStage) -> Result<MutexGuard<'_, ()>, ExecutionError> {
        self.operation_lock
            .lock()
            .map_err(|_| ExecutionError::new(ExecutionErrorKind::LocalStorage, stage))
    }

    fn inspect_sandbox(
        &self,
        cancellation: &dyn Cancellation,
        stage: ExecutionStage,
    ) -> Result<SandboxState, ExecutionError> {
        self.inner
            .inspect(&self.handle, cancellation)
            .map(|inspection| inspection.state())
            .map_err(|error| endpoint_error_from_provider(&error, stage))
    }

    fn run(
        &self,
        arguments: Vec<OsString>,
        timeout: std::time::Duration,
        output_limit: usize,
        cancellation: &dyn Cancellation,
        stage: ExecutionStage,
    ) -> Result<CommandOutput, ExecutionError> {
        let output = self
            .inner
            .run_endpoint(arguments, timeout, output_limit, cancellation, stage);
        match output.termination() {
            CommandTermination::FailedToStart => Err(ExecutionError::new(
                ExecutionErrorKind::BackendRejected,
                stage,
            )),
            _ => Ok(output),
        }
    }

    fn run_with_environment(
        &self,
        arguments: Vec<OsString>,
        environment_document: EnvironmentDocument<'_>,
        timeout: std::time::Duration,
        output_limit: usize,
        cancellation: &dyn Cancellation,
        stage: ExecutionStage,
    ) -> Result<CommandOutput, ExecutionError> {
        let output = self.inner.run_endpoint_with_environment(
            arguments,
            environment_document,
            timeout,
            output_limit,
            cancellation,
            stage,
        );
        match output.termination() {
            CommandTermination::FailedToStart => Err(ExecutionError::new(
                ExecutionErrorKind::BackendRejected,
                stage,
            )),
            _ => Ok(output),
        }
    }

    fn run_transport(
        &self,
        arguments: Vec<OsString>,
        stdin: Option<Vec<u8>>,
        output_limit: usize,
        cancellation: &dyn Cancellation,
        stage: ExecutionStage,
    ) -> Result<CommandOutput, ExecutionError> {
        let output = self.inner.run_endpoint_transport(
            arguments,
            stdin,
            self.inner.endpoint_operation_timeout(),
            output_limit,
            cancellation,
            stage,
        );
        match output.termination() {
            CommandTermination::FailedToStart => Err(ExecutionError::new(
                ExecutionErrorKind::BackendRejected,
                stage,
            )),
            _ => Ok(output),
        }
    }

    fn kill_after_interrupted_exec(&self) -> Result<(), ExecutionError> {
        let cancellation = NeverCancelled;
        let state = self.inspect_sandbox(&cancellation, ExecutionStage::Exec)?;
        if state != SandboxState::Running {
            return Ok(());
        }
        let mut arguments = self.inner.base_arguments();
        arguments.extend(os_args(["kill", "--signal", "KILL"]));
        arguments.push(self.names.container().into());
        let output = self.inner.run_endpoint(
            arguments,
            std::time::Duration::from_secs(30),
            64 * 1024,
            &cancellation,
            ExecutionStage::Exec,
        );
        require_zero(&output, ExecutionStage::Exec)
    }

    fn execution_termination(
        &self,
        termination: CommandTermination,
    ) -> Result<ExecutionTermination, ExecutionError> {
        match termination {
            CommandTermination::Exited(Some(code)) => Ok(ExecutionTermination::Exited(code)),
            CommandTermination::Exited(None) => Ok(ExecutionTermination::Signalled),
            CommandTermination::TimedOut => {
                self.kill_after_interrupted_exec()?;
                Ok(ExecutionTermination::TimedOut)
            }
            CommandTermination::Cancelled => {
                self.kill_after_interrupted_exec()?;
                Ok(ExecutionTermination::Cancelled)
            }
            CommandTermination::FailedToStart => Err(ExecutionError::new(
                ExecutionErrorKind::BackendRejected,
                ExecutionStage::Exec,
            )),
        }
    }
}

impl fmt::Debug for PodmanExecutionEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PodmanExecutionEndpoint")
            .field("handle", &self.handle)
            .field("capabilities", &endpoint_capabilities())
            .finish_non_exhaustive()
    }
}

impl ExecutionEndpoint for PodmanExecutionEndpoint {
    fn handle(&self) -> &SandboxHandle {
        &self.handle
    }

    fn capabilities(&self) -> &[SandboxCapability] {
        endpoint_capabilities()
    }

    fn exec(
        &self,
        request: &ExecutionCommand,
        cancellation: &dyn Cancellation,
    ) -> Result<ExecutionOutput, ExecutionError> {
        let _operation = self.acquire(ExecutionStage::Exec)?;
        if request.argv().program().platform() != TargetPlatform::Posix
            || request.working_directory().platform() != TargetPlatform::Posix
        {
            return Err(ExecutionError::new(
                ExecutionErrorKind::UnsupportedCapability,
                ExecutionStage::Exec,
            ));
        }
        if self.inspect_sandbox(cancellation, ExecutionStage::Exec)? != SandboxState::Running {
            return Err(ExecutionError::new(
                ExecutionErrorKind::InvalidState,
                ExecutionStage::Exec,
            ));
        }
        let environment_document = environment_document(request.environment()).map_err(|()| {
            ExecutionError::new(ExecutionErrorKind::InvalidEnvironment, ExecutionStage::Exec)
        })?;
        let mut arguments = self.inner.base_arguments();
        arguments.push("exec".into());
        if environment_document.has_env_file() {
            arguments.push("--env-file".into());
            arguments.push(PODMAN_STDIN_ENVIRONMENT_PATH.into());
        }
        for variable in environment_document.inherited_variables() {
            arguments.push("--env".into());
            arguments.push(variable.name().as_str().into());
        }
        arguments.push("--workdir".into());
        arguments.push(request.working_directory().as_str().into());
        arguments.push(self.names.container().into());
        arguments.push(request.argv().program().as_str().into());
        arguments.extend(request.argv().arguments().iter().map(OsString::from));
        let output = self.run_with_environment(
            arguments,
            environment_document,
            request.timeout(),
            request.output_limit(),
            cancellation,
            ExecutionStage::Exec,
        )?;
        let termination = self.execution_termination(output.termination())?;
        if !output.stdin_was_fully_written()
            && !matches!(
                termination,
                ExecutionTermination::Cancelled | ExecutionTermination::TimedOut
            )
        {
            return Err(ExecutionError::new(
                ExecutionErrorKind::BackendRejected,
                ExecutionStage::Exec,
            ));
        }
        let truncated = output.was_truncated();
        ExecutionOutput::new(termination, output.into_records(), truncated).map_err(|_| {
            ExecutionError::new(
                ExecutionErrorKind::OutputLimitExceeded,
                ExecutionStage::Exec,
            )
        })
    }

    fn signal(
        &self,
        request: SignalRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ExecutionError> {
        let _operation = self.acquire(ExecutionStage::Signal)?;
        let state = self.inspect_sandbox(cancellation, ExecutionStage::Signal)?;
        if state != SandboxState::Running {
            return Err(ExecutionError::new(
                ExecutionErrorKind::InvalidState,
                ExecutionStage::Signal,
            ));
        }
        let signal = match request.signal() {
            ExecutionSignal::Interrupt => "INT",
            ExecutionSignal::Terminate => "TERM",
            ExecutionSignal::Kill => "KILL",
        };
        let mut arguments = self.inner.base_arguments();
        arguments.extend(os_args(["kill", "--signal", signal]));
        arguments.push(self.names.container().into());
        let output = self.run(
            arguments,
            std::time::Duration::from_secs(30),
            64 * 1024,
            cancellation,
            ExecutionStage::Signal,
        )?;
        require_zero(&output, ExecutionStage::Signal)
    }

    fn wait(
        &self,
        request: WaitRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<i32, ExecutionError> {
        let _operation = self.acquire(ExecutionStage::Wait)?;
        let state = self.inspect_sandbox(cancellation, ExecutionStage::Wait)?;
        if !matches!(state, SandboxState::Running | SandboxState::Stopped) {
            return Err(ExecutionError::new(
                ExecutionErrorKind::InvalidState,
                ExecutionStage::Wait,
            ));
        }
        let mut arguments = self.inner.base_arguments();
        arguments.extend(os_args(["wait", "--condition", "exited", "--ignore"]));
        arguments.push(self.names.container().into());
        let output = self.run(
            arguments,
            request.timeout(),
            64 * 1024,
            cancellation,
            ExecutionStage::Wait,
        )?;
        require_zero(&output, ExecutionStage::Wait)?;
        parse_exit_status(output.stdout()).ok_or_else(|| {
            ExecutionError::new(ExecutionErrorKind::BackendRejected, ExecutionStage::Wait)
        })
    }

    fn copy_to(
        &self,
        request: &CopyToRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ExecutionError> {
        let _operation = self.acquire(ExecutionStage::CopyTo)?;
        let (parent, name) = copy_path_parts(request.target(), ExecutionStage::CopyTo)?;
        let state = self.inspect_sandbox(cancellation, ExecutionStage::CopyTo)?;
        if !copyable_state(state) {
            return Err(ExecutionError::new(
                ExecutionErrorKind::InvalidState,
                ExecutionStage::CopyTo,
            ));
        }
        let archive = encode_single_file_tar(name, request.content()).ok_or_else(|| {
            ExecutionError::new(
                ExecutionErrorKind::UnsupportedCapability,
                ExecutionStage::CopyTo,
            )
        })?;
        let mut arguments = self.inner.base_arguments();
        arguments.extend(os_args(["cp", "--overwrite"]));
        arguments.push("-".into());
        arguments.push(format!("{}:{parent}", self.names.container()).into());
        let output = self.run_transport(
            arguments,
            Some(archive),
            64 * 1024,
            cancellation,
            ExecutionStage::CopyTo,
        )?;
        require_zero(&output, ExecutionStage::CopyTo)
    }

    fn copy_from(
        &self,
        request: &CopyFromRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<Vec<u8>, ExecutionError> {
        let _operation = self.acquire(ExecutionStage::CopyFrom)?;
        let (_parent, name) = copy_path_parts(request.source(), ExecutionStage::CopyFrom)?;
        let state = self.inspect_sandbox(cancellation, ExecutionStage::CopyFrom)?;
        if !copyable_state(state) {
            return Err(ExecutionError::new(
                ExecutionErrorKind::InvalidState,
                ExecutionStage::CopyFrom,
            ));
        }
        let output_limit = tar_stream_size(request.byte_limit()).ok_or_else(|| {
            ExecutionError::new(
                ExecutionErrorKind::OutputLimitExceeded,
                ExecutionStage::CopyFrom,
            )
        })?;
        let mut arguments = self.inner.base_arguments();
        arguments.push("cp".into());
        arguments.push(format!("{}:{}", self.names.container(), request.source().as_str()).into());
        arguments.push("-".into());
        let output = self.run_transport(
            arguments,
            None,
            output_limit,
            cancellation,
            ExecutionStage::CopyFrom,
        )?;
        require_zero(&output, ExecutionStage::CopyFrom)?;
        decode_single_file_tar(output.stdout(), name, request.byte_limit()).map_err(|error| {
            let kind = match error {
                TarReadError::Invalid => ExecutionErrorKind::BackendRejected,
                TarReadError::LimitExceeded => ExecutionErrorKind::OutputLimitExceeded,
            };
            ExecutionError::new(kind, ExecutionStage::CopyFrom)
        })
    }
}

pub(crate) fn environment_document(
    environment: &ExecutionEnvironment,
) -> Result<EnvironmentDocument<'_>, ()> {
    let mut byte_len = 0_usize;
    let mut inherited_bytes = 0_usize;
    for variable in environment.values() {
        let name = variable.name().as_str();
        let value = variable.value().expose();
        if matches!(name.as_bytes().first(), Some(b' ' | b'\t' | b'#'))
            || provider_control_environment_name(name)
        {
            return Err(());
        }
        if requires_process_inheritance(value) {
            if provider_process_environment_name(name) {
                return Err(());
            }
            inherited_bytes = inherited_bytes
                .checked_add(name.len())
                .and_then(|bytes| bytes.checked_add(value.len()))
                .and_then(|bytes| bytes.checked_add(2))
                .filter(|bytes| *bytes <= MAX_PODMAN_INHERITED_ENVIRONMENT_BYTES)
                .ok_or(())?;
        } else {
            byte_len = checked_environment_document_length(byte_len, name.len(), value.len())?;
        }
    }
    Ok(EnvironmentDocument {
        variables: environment.values(),
        byte_len,
    })
}

pub(crate) fn requires_process_inheritance(value: &str) -> bool {
    value.contains(['\r', '\n'])
}

fn provider_process_environment_name(name: &str) -> bool {
    matches!(
        name,
        "HOME" | "PATH" | "TMPDIR" | "DBUS_SESSION_BUS_ADDRESS"
    )
}

fn checked_environment_document_length(
    document_bytes: usize,
    name_bytes: usize,
    value_bytes: usize,
) -> Result<usize, ()> {
    let line_bytes = name_bytes
        .checked_add(1)
        .and_then(|bytes| bytes.checked_add(value_bytes))
        .filter(|bytes| *bytes <= MAX_PODMAN_ENV_DOCUMENT_LINE_BYTES)
        .ok_or(())?;
    document_bytes
        .checked_add(line_bytes)
        .and_then(|bytes| bytes.checked_add(1))
        .ok_or(())
}

fn copy_path_parts(
    path: &TargetPath,
    stage: ExecutionStage,
) -> Result<(&str, &str), ExecutionError> {
    let value = path.as_str();
    let parts = value.rsplit_once('/');
    let Some((parent, name)) = parts else {
        return Err(ExecutionError::new(
            ExecutionErrorKind::UnsupportedCapability,
            stage,
        ));
    };
    if path.platform() != TargetPlatform::Posix
        || name.is_empty()
        || name.len() > TAR_NAME_BYTES
        || value.contains(':')
    {
        return Err(ExecutionError::new(
            ExecutionErrorKind::UnsupportedCapability,
            stage,
        ));
    }
    Ok((if parent.is_empty() { "/" } else { parent }, name))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TarReadError {
    Invalid,
    LimitExceeded,
}

fn encode_single_file_tar(name: &str, content: &[u8]) -> Option<Vec<u8>> {
    if name.is_empty() || name.len() > TAR_NAME_BYTES || name.contains('/') {
        return None;
    }
    let stream_size = tar_stream_size(content.len())?;
    let mut archive = vec![0_u8; stream_size];
    let header = archive.get_mut(..TAR_BLOCK_BYTES)?;
    header
        .get_mut(..name.len())?
        .copy_from_slice(name.as_bytes());
    write_octal_field(header.get_mut(100..108)?, 0o600)?;
    write_octal_field(header.get_mut(108..116)?, 0)?;
    write_octal_field(header.get_mut(116..124)?, 0)?;
    write_octal_field(header.get_mut(124..136)?, content.len())?;
    write_octal_field(header.get_mut(136..148)?, 0)?;
    header.get_mut(148..156)?.fill(b' ');
    *header.get_mut(156)? = b'0';
    header.get_mut(257..263)?.copy_from_slice(b"ustar\0");
    header.get_mut(263..265)?.copy_from_slice(b"00");
    write_octal_field(header.get_mut(329..337)?, 0)?;
    write_octal_field(header.get_mut(337..345)?, 0)?;
    write_tar_checksum(header)?;
    archive
        .get_mut(TAR_BLOCK_BYTES..TAR_BLOCK_BYTES.checked_add(content.len())?)?
        .copy_from_slice(content);
    Some(archive)
}

fn decode_single_file_tar(
    archive: &[u8],
    expected_name: &str,
    byte_limit: usize,
) -> Result<Vec<u8>, TarReadError> {
    let maximum_stream = tar_stream_size(byte_limit).ok_or(TarReadError::LimitExceeded)?;
    if archive.len() > maximum_stream {
        return Err(TarReadError::LimitExceeded);
    }
    if archive.len() < TAR_BLOCK_BYTES * (1 + TAR_END_BLOCKS)
        || !archive.len().is_multiple_of(TAR_BLOCK_BYTES)
    {
        return Err(TarReadError::Invalid);
    }
    let header = archive
        .get(..TAR_BLOCK_BYTES)
        .ok_or(TarReadError::Invalid)?;
    validate_tar_header(header, expected_name)?;
    let content_size = parse_octal_field(header.get(124..136).ok_or(TarReadError::Invalid)?)?;
    if content_size > byte_limit {
        return Err(TarReadError::LimitExceeded);
    }
    let padded_size = padded_tar_content_size(content_size).ok_or(TarReadError::LimitExceeded)?;
    let content_end = TAR_BLOCK_BYTES
        .checked_add(content_size)
        .ok_or(TarReadError::LimitExceeded)?;
    let padding_end = TAR_BLOCK_BYTES
        .checked_add(padded_size)
        .ok_or(TarReadError::LimitExceeded)?;
    let expected_end = padding_end
        .checked_add(TAR_BLOCK_BYTES * TAR_END_BLOCKS)
        .ok_or(TarReadError::LimitExceeded)?;
    if archive.len() != expected_end
        || archive
            .get(content_end..padding_end)
            .is_none_or(|padding| padding.iter().any(|byte| *byte != 0))
        || archive
            .get(padding_end..expected_end)
            .is_none_or(|ending| ending.iter().any(|byte| *byte != 0))
    {
        return Err(TarReadError::Invalid);
    }
    archive
        .get(TAR_BLOCK_BYTES..content_end)
        .map(<[u8]>::to_vec)
        .ok_or(TarReadError::Invalid)
}

fn validate_tar_header(header: &[u8], expected_name: &str) -> Result<(), TarReadError> {
    if header.len() != TAR_BLOCK_BYTES
        || expected_name.is_empty()
        || expected_name.len() > TAR_NAME_BYTES
        || !canonical_tar_name(
            header.get(..TAR_NAME_BYTES).ok_or(TarReadError::Invalid)?,
            expected_name,
        )
        || header.get(156).copied() != Some(b'0')
        || header.get(157..257).is_none_or(nonzero)
        || header.get(257..263) != Some(b"ustar\0".as_slice())
        || header.get(263..265) != Some(b"00".as_slice())
        || header.get(265..329).is_none_or(nonzero)
        || header.get(345..TAR_BLOCK_BYTES).is_none_or(nonzero)
    {
        return Err(TarReadError::Invalid);
    }
    for range in [
        100..108,
        108..116,
        116..124,
        124..136,
        136..148,
        329..337,
        337..345,
    ] {
        parse_octal_field(header.get(range).ok_or(TarReadError::Invalid)?)?;
    }
    let checksum_field = header.get(148..156).ok_or(TarReadError::Invalid)?;
    if checksum_field.get(6).copied() != Some(0) || checksum_field.get(7).copied() != Some(b' ') {
        return Err(TarReadError::Invalid);
    }
    let declared = parse_octal_digits(checksum_field.get(..6).ok_or(TarReadError::Invalid)?)?;
    let actual = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                usize::from(b' ')
            } else {
                usize::from(*byte)
            }
        })
        .sum::<usize>();
    (declared == actual)
        .then_some(())
        .ok_or(TarReadError::Invalid)
}

fn canonical_tar_name(field: &[u8], expected: &str) -> bool {
    field.len() == TAR_NAME_BYTES
        && field.get(..expected.len()) == Some(expected.as_bytes())
        && field.get(expected.len()..).is_some_and(|rest| {
            rest.is_empty() || (rest.first() == Some(&0) && rest.iter().all(|byte| *byte == 0))
        })
}

fn nonzero(bytes: &[u8]) -> bool {
    bytes.iter().any(|byte| *byte != 0)
}

fn parse_octal_field(field: &[u8]) -> Result<usize, TarReadError> {
    let (terminator, digits) = field.split_last().ok_or(TarReadError::Invalid)?;
    if *terminator != 0 || digits.is_empty() {
        return Err(TarReadError::Invalid);
    }
    parse_octal_digits(digits)
}

fn parse_octal_digits(digits: &[u8]) -> Result<usize, TarReadError> {
    digits
        .iter()
        .try_fold(0_usize, |value, byte| {
            let digit = byte.checked_sub(b'0').filter(|digit| *digit < 8)?;
            value.checked_mul(8)?.checked_add(usize::from(digit))
        })
        .ok_or(TarReadError::Invalid)
}

fn write_octal_field(field: &mut [u8], value: usize) -> Option<()> {
    let (terminator, digits) = field.split_last_mut()?;
    *terminator = 0;
    digits.fill(b'0');
    let mut remaining = value;
    for digit in digits.iter_mut().rev() {
        *digit = b'0'.checked_add(u8::try_from(remaining % 8).ok()?)?;
        remaining /= 8;
    }
    (remaining == 0).then_some(())
}

fn write_tar_checksum(header: &mut [u8]) -> Option<()> {
    let checksum = header.iter().map(|byte| usize::from(*byte)).sum::<usize>();
    let field = header.get_mut(148..156)?;
    field.fill(b'0');
    *field.get_mut(6)? = 0;
    *field.get_mut(7)? = b' ';
    let mut remaining = checksum;
    for digit in field.get_mut(..6)?.iter_mut().rev() {
        *digit = b'0'.checked_add(u8::try_from(remaining % 8).ok()?)?;
        remaining /= 8;
    }
    (remaining == 0).then_some(())
}

fn padded_tar_content_size(content_size: usize) -> Option<usize> {
    content_size
        .checked_add(TAR_BLOCK_BYTES - 1)?
        .checked_div(TAR_BLOCK_BYTES)?
        .checked_mul(TAR_BLOCK_BYTES)
}

fn tar_stream_size(content_size: usize) -> Option<usize> {
    TAR_BLOCK_BYTES
        .checked_add(padded_tar_content_size(content_size)?)?
        .checked_add(TAR_BLOCK_BYTES * TAR_END_BLOCKS)
}

const fn copyable_state(state: SandboxState) -> bool {
    matches!(
        state,
        SandboxState::Created | SandboxState::Running | SandboxState::Stopped
    )
}

fn require_zero(output: &CommandOutput, stage: ExecutionStage) -> Result<(), ExecutionError> {
    match output.termination() {
        CommandTermination::Exited(Some(0))
            if !output.was_truncated() && output.stdin_was_fully_written() =>
        {
            Ok(())
        }
        CommandTermination::Cancelled => {
            Err(ExecutionError::new(ExecutionErrorKind::Cancelled, stage))
        }
        CommandTermination::TimedOut => {
            Err(ExecutionError::new(ExecutionErrorKind::TimedOut, stage))
        }
        CommandTermination::Exited(_) if output.was_truncated() => Err(ExecutionError::new(
            ExecutionErrorKind::OutputLimitExceeded,
            stage,
        )),
        CommandTermination::Exited(_) | CommandTermination::FailedToStart => Err(
            ExecutionError::new(ExecutionErrorKind::BackendRejected, stage),
        ),
    }
}

fn parse_exit_status(bytes: &[u8]) -> Option<i32> {
    let value = std::str::from_utf8(bytes).ok()?.trim();
    if value.is_empty() || value.lines().count() != 1 {
        return None;
    }
    value.parse().ok()
}

fn os_args<const N: usize>(values: [&str; N]) -> impl Iterator<Item = OsString> {
    values.into_iter().map(OsString::from)
}

#[cfg(test)]
mod tests {
    use automata_ci_execution::{EnvironmentName, EnvironmentValue};

    use super::*;

    fn variable(name: &str, value: &str, secret: bool) -> EnvironmentVariable {
        let name = EnvironmentName::new(name).expect("valid test environment name");
        let value = EnvironmentValue::new(value).expect("valid test environment value");
        if secret {
            EnvironmentVariable::secret(name, value)
        } else {
            EnvironmentVariable::new(name, value)
        }
    }

    fn document_bytes(document: &EnvironmentDocument) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(document.byte_len());
        for variable in document
            .variables()
            .iter()
            .filter(|variable| !requires_process_inheritance(variable.value().expose()))
        {
            bytes.extend_from_slice(variable.name().as_str().as_bytes());
            bytes.push(b'=');
            bytes.extend_from_slice(variable.value().expose().as_bytes());
            bytes.push(b'\n');
        }
        bytes
    }

    #[test]
    fn secret_control_values_use_only_the_anonymous_environment_document() {
        for name in [
            "HOME",
            "PATH",
            "LD_PRELOAD",
            "SSL_CERT_FILE",
            "DBUS_SESSION_BUS_ADDRESS",
        ] {
            let environment = ExecutionEnvironment::new(vec![variable(name, "secret", true)])
                .expect("valid environment");
            let document = environment_document(&environment).expect("secret control environment");
            assert_eq!(
                document_bytes(&document),
                format!("{name}=secret\n").as_bytes()
            );
            assert!(!format!("{environment:?}").contains("secret"));
            assert!(!format!("{document:?}").contains("secret"));
        }
    }

    #[test]
    fn every_workload_value_uses_the_anonymous_environment_document() {
        let environment = ExecutionEnvironment::new(vec![
            variable("ACTIONS_RUNTIME_TOKEN", "secret", true),
            variable("AUTOMATA_EMPTY", "", false),
        ])
        .expect("valid environment");

        let document = environment_document(&environment).expect("representable environment");
        let expected = b"ACTIONS_RUNTIME_TOKEN=secret\nAUTOMATA_EMPTY=\n";
        assert_eq!(document_bytes(&document), expected);
        assert_eq!(document.byte_len(), expected.len());
    }

    #[test]
    fn non_secret_control_values_use_the_bounded_environment_document() {
        let environment = ExecutionEnvironment::new(vec![variable("PATH", "/usr/bin", false)])
            .expect("valid environment");
        let document = environment_document(&environment).expect("plain control environment");
        assert_eq!(document_bytes(&document), b"PATH=/usr/bin\n");
    }

    #[test]
    fn environment_document_accepts_the_exact_line_bound_and_rejects_unrepresentable_values() {
        let exact = "x".repeat(MAX_PODMAN_ENV_DOCUMENT_LINE_BYTES - "NAME=".len());
        let environment = ExecutionEnvironment::new(vec![variable("NAME", &exact, false)])
            .expect("bounded environment");
        assert_eq!(
            environment_document(&environment)
                .expect("exact line bound")
                .byte_len(),
            MAX_PODMAN_ENV_DOCUMENT_LINE_BYTES + 1
        );

        let oversized = format!("{exact}x");
        let environment = ExecutionEnvironment::new(vec![variable("NAME", &oversized, false)])
            .expect("core-valid environment");
        assert!(environment_document(&environment).is_err());
    }

    #[test]
    fn environment_document_preserves_empty_and_nul_policy_without_framing_ambiguity() {
        let environment = ExecutionEnvironment::empty();
        let empty = environment_document(&environment).expect("empty document");
        assert!(empty.is_empty());
        assert_eq!(empty.byte_len(), 0);

        let empty_value =
            ExecutionEnvironment::new(vec![variable("EMPTY", "", false)]).expect("empty value");
        let document = environment_document(&empty_value).expect("empty value document");
        assert_eq!(document_bytes(&document), b"EMPTY=\n");

        assert!(EnvironmentValue::new("nul\0value").is_err());
        for value in ["carriage\rreturn", "line\nfeed"] {
            let environment = ExecutionEnvironment::new(vec![variable("VALUE", value, false)])
                .expect("core-valid framing value");
            let document = environment_document(&environment).expect("inherited environment");
            assert_eq!(document.byte_len(), 0);
            assert_eq!(
                document
                    .inherited_variables()
                    .map(|variable| variable.value().expose())
                    .collect::<Vec<_>>(),
                [value]
            );
        }
    }

    #[test]
    fn inherited_environment_is_bounded_and_cannot_replace_podman_process_control() {
        for name in ["HOME", "PATH", "TMPDIR", "DBUS_SESSION_BUS_ADDRESS"] {
            let environment =
                ExecutionEnvironment::new(vec![variable(name, "first\nsecond", true)])
                    .expect("core-valid environment");
            assert!(environment_document(&environment).is_err(), "{name}");
        }

        let exact = "x".repeat(MAX_PODMAN_INHERITED_ENVIRONMENT_BYTES - "VALUE".len() - 2);
        let environment =
            ExecutionEnvironment::new(vec![variable("VALUE", &format!("{exact}\n"), true)])
                .expect("bounded environment");
        assert!(environment_document(&environment).is_err());

        let exact = "x".repeat(MAX_PODMAN_INHERITED_ENVIRONMENT_BYTES - "VALUE".len() - 3);
        let environment =
            ExecutionEnvironment::new(vec![variable("VALUE", &format!("{exact}\n"), true)])
                .expect("bounded environment");
        assert!(environment_document(&environment).is_ok());
    }

    #[test]
    fn environment_document_length_arithmetic_fails_closed() {
        assert_eq!(
            checked_environment_document_length(0, 4, MAX_PODMAN_ENV_DOCUMENT_LINE_BYTES - 5),
            Ok(MAX_PODMAN_ENV_DOCUMENT_LINE_BYTES + 1)
        );
        assert!(checked_environment_document_length(0, usize::MAX, 0).is_err());
        assert!(checked_environment_document_length(0, 1, usize::MAX).is_err());
        assert!(checked_environment_document_length(usize::MAX, 1, 1).is_err());
    }

    #[test]
    fn environment_document_rejects_names_that_podman_would_trim_or_treat_as_comments() {
        for name in [" LEADING_SPACE", "#COMMENT"] {
            let environment = ExecutionEnvironment::new(vec![variable(name, "value", false)])
                .expect("core-valid environment");
            assert!(environment_document(&environment).is_err(), "{name:?}");
        }
    }

    #[test]
    fn every_provider_control_namespace_is_rejected_prefix_closed() {
        for name in [
            "CONTAINER_FUTURE_CONTROL",
            "CONTAINERS_POLICY_JSON",
            "_CONTAINERS_FUTURE_CONTROL",
            "PODMAN_FUTURE_CONTROL",
            "STORAGE_FUTURE_CONTROL",
            "REGISTRY_FUTURE_CONTROL",
            "REGISTRIES_FUTURE_CONTROL",
            "NETAVARK_FUTURE_CONTROL",
            "AARDVARK_FUTURE_CONTROL",
            "BUILDAH_FUTURE_CONTROL",
            "BUILD_REGISTRY_FUTURE_CONTROL",
            "CONMON_FUTURE_CONTROL",
            "RUN_OCI_FUTURE_CONTROL",
            "DISABLE_HC_SYSTEMD",
            "XDG_FUTURE_CONTROL",
            "DOCKER_FUTURE_CONTROL",
        ] {
            let environment = ExecutionEnvironment::new(vec![variable(name, "override", false)])
                .expect("valid environment");
            assert!(environment_document(&environment).is_err(), "{name}");
        }
    }

    #[test]
    fn canonical_single_file_tar_round_trips_exact_bytes() {
        for content in [
            Vec::new(),
            b"secret\0payload\n".to_vec(),
            vec![0x5a; TAR_BLOCK_BYTES + 1],
        ] {
            let archive = encode_single_file_tar("artifact", &content).expect("canonical tar");
            assert_eq!(archive.len(), tar_stream_size(content.len()).expect("size"));
            assert_eq!(
                decode_single_file_tar(&archive, "artifact", content.len().max(1)).expect("decode"),
                content
            );
        }

        let maximum_name = "n".repeat(TAR_NAME_BYTES);
        let archive = encode_single_file_tar(&maximum_name, b"x").expect("100-byte name");
        assert_eq!(
            decode_single_file_tar(&archive, &maximum_name, 1).expect("decode maximum name"),
            b"x"
        );
        assert!(encode_single_file_tar(&"n".repeat(TAR_NAME_BYTES + 1), b"x").is_none());
    }

    #[test]
    fn tar_decoder_rejects_links_traversal_extensions_and_extra_entries() {
        let canonical = encode_single_file_tar("artifact", b"secret").expect("canonical tar");

        let mut traversal = canonical.clone();
        traversal[..TAR_NAME_BYTES].fill(0);
        traversal[..9].copy_from_slice(b"../escape");
        refresh_test_checksum(&mut traversal);
        assert_eq!(
            decode_single_file_tar(&traversal, "artifact", 4_096),
            Err(TarReadError::Invalid)
        );

        let mut symlink = canonical.clone();
        symlink[156] = b'2';
        symlink[157..163].copy_from_slice(b"target");
        refresh_test_checksum(&mut symlink);
        assert_eq!(
            decode_single_file_tar(&symlink, "artifact", 4_096),
            Err(TarReadError::Invalid)
        );

        let mut extension = canonical.clone();
        extension[156] = b'x';
        refresh_test_checksum(&mut extension);
        assert_eq!(
            decode_single_file_tar(&extension, "artifact", 4_096),
            Err(TarReadError::Invalid)
        );

        let entry_end = canonical.len() - TAR_BLOCK_BYTES * TAR_END_BLOCKS;
        let mut duplicate = canonical[..entry_end].to_vec();
        duplicate.extend_from_slice(&canonical);
        assert_eq!(
            decode_single_file_tar(&duplicate, "artifact", 4_096),
            Err(TarReadError::Invalid)
        );

        let mut extra = canonical[..entry_end].to_vec();
        let other = encode_single_file_tar("other", b"secret").expect("other tar");
        extra.extend_from_slice(&other);
        assert_eq!(
            decode_single_file_tar(&extra, "artifact", 4_096),
            Err(TarReadError::Invalid)
        );
    }

    #[test]
    fn tar_decoder_rejects_malformed_truncated_padded_and_oversized_streams() {
        let canonical = encode_single_file_tar("artifact", b"secret").expect("canonical tar");

        let mut bad_length = canonical.clone();
        bad_length[124..136].copy_from_slice(b"00000000008\0");
        refresh_test_checksum(&mut bad_length);
        assert_eq!(
            decode_single_file_tar(&bad_length, "artifact", 4_096),
            Err(TarReadError::Invalid)
        );

        let mut truncated = canonical.clone();
        truncated.pop();
        assert_eq!(
            decode_single_file_tar(&truncated, "artifact", 4_096),
            Err(TarReadError::Invalid)
        );

        let mut nonzero_padding = canonical.clone();
        nonzero_padding[TAR_BLOCK_BYTES + b"secret".len()] = 1;
        assert_eq!(
            decode_single_file_tar(&nonzero_padding, "artifact", 4_096),
            Err(TarReadError::Invalid)
        );

        let mut padded = canonical.clone();
        padded.extend_from_slice(&[0_u8; TAR_BLOCK_BYTES]);
        assert_eq!(
            decode_single_file_tar(&padded, "artifact", 4_096),
            Err(TarReadError::Invalid)
        );

        let oversized = encode_single_file_tar("artifact", &[0x41; 65]).expect("oversized tar");
        assert_eq!(
            decode_single_file_tar(&oversized, "artifact", 64),
            Err(TarReadError::LimitExceeded)
        );

        let mut actual_oversize =
            encode_single_file_tar("artifact", &[0x41; 64]).expect("bounded tar");
        actual_oversize[TAR_BLOCK_BYTES + 64] = 0x41;
        assert_eq!(
            decode_single_file_tar(&actual_oversize, "artifact", 64),
            Err(TarReadError::Invalid)
        );

        let mut short_declaration = canonical.clone();
        write_octal_field(&mut short_declaration[124..136], 1).expect("size field");
        refresh_test_checksum(&mut short_declaration);
        assert_eq!(
            decode_single_file_tar(&short_declaration, "artifact", 4_096),
            Err(TarReadError::Invalid)
        );

        let mut bad_checksum = canonical.clone();
        bad_checksum[0] ^= 1;
        assert_eq!(
            decode_single_file_tar(&bad_checksum, "artifact", 4_096),
            Err(TarReadError::Invalid)
        );

        let mut prefixed = canonical;
        prefixed[345] = b'x';
        refresh_test_checksum(&mut prefixed);
        assert_eq!(
            decode_single_file_tar(&prefixed, "artifact", 4_096),
            Err(TarReadError::Invalid)
        );
    }

    fn refresh_test_checksum(archive: &mut [u8]) {
        let header = &mut archive[..TAR_BLOCK_BYTES];
        header[148..156].fill(b' ');
        write_tar_checksum(header).expect("checksum");
    }
}
