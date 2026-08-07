use std::{
    ffi::OsString,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
};

use automata_execution::{
    Cancellation, CopyFromRequest, CopyToRequest, EnvironmentVariable, ExecutionCommand,
    ExecutionEndpoint, ExecutionEnvironment, ExecutionError, ExecutionErrorKind, ExecutionOutput,
    ExecutionSignal, ExecutionStage, ExecutionTermination, NeverCancelled, SandboxCapability,
    SandboxHandle, SandboxState, SignalRequest, TargetPath, TargetPlatform, WaitRequest,
};

use crate::{
    CommandOutput, CommandTermination, PodmanStateRootError,
    command::{environment_file_name, provider_control_environment_name},
    naming::ResourceNames,
    provider::{PodmanInner, endpoint_capabilities, endpoint_error_from_provider},
};

const MAX_PODMAN_ENV_FILE_LINE_BYTES: usize = 64 * 1024 - 1;

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
            .run_endpoint(arguments, timeout, output_limit, cancellation);
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
        environment: ExecutionEnvironment,
        timeout: std::time::Duration,
        output_limit: usize,
        cancellation: &dyn Cancellation,
        stage: ExecutionStage,
    ) -> Result<CommandOutput, ExecutionError> {
        let output = self.inner.run_endpoint_with_environment(
            arguments,
            environment,
            timeout,
            output_limit,
            cancellation,
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
        );
        require_zero(&output, ExecutionStage::Exec)
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
        let prepared = prepare_environment(request.environment())?;
        let staged_environment = prepared
            .file_content
            .as_deref()
            .map(|content| {
                self.inner
                    .local_state()
                    .stage_input("exec-env", automata_execution::OperationId::new(), content)
                    .map_err(|error| state_error(&error, ExecutionStage::Exec))
            })
            .transpose()?;
        let mut arguments = self.inner.base_arguments();
        arguments.push("exec".into());
        if let Some(staged) = staged_environment.as_ref() {
            arguments.push("--env-file".into());
            arguments.push(staged.path().into());
        }
        for variable in prepared.child.values() {
            arguments.push("--env".into());
            arguments.push(variable.name().as_str().into());
        }
        arguments.push("--workdir".into());
        arguments.push(request.working_directory().as_str().into());
        arguments.push(self.names.container().into());
        arguments.push(request.argv().program().as_str().into());
        arguments.extend(request.argv().arguments().iter().map(OsString::from));
        let verification = match staged_environment.as_ref() {
            Some(staged) => staged.verify(),
            None => Ok(()),
        };
        if let Err(error) = verification {
            if let Some(staged) = staged_environment
                && let Err(cleanup) = staged.cleanup()
            {
                return Err(state_error(&cleanup, ExecutionStage::Exec));
            }
            return Err(state_error(&error, ExecutionStage::Exec));
        }
        let output = self.run_with_environment(
            arguments,
            prepared.child,
            request.timeout(),
            request.output_limit(),
            cancellation,
            ExecutionStage::Exec,
        );
        if let Some(staged) = staged_environment {
            staged
                .cleanup()
                .map_err(|error| state_error(&error, ExecutionStage::Exec))?;
        }
        let output = output?;
        let termination = match output.termination() {
            CommandTermination::Exited(Some(code)) => ExecutionTermination::Exited(code),
            CommandTermination::Exited(None) => ExecutionTermination::Signalled,
            CommandTermination::TimedOut => {
                self.kill_after_interrupted_exec()?;
                ExecutionTermination::TimedOut
            }
            CommandTermination::Cancelled => {
                self.kill_after_interrupted_exec()?;
                ExecutionTermination::Cancelled
            }
            CommandTermination::FailedToStart => {
                return Err(ExecutionError::new(
                    ExecutionErrorKind::BackendRejected,
                    ExecutionStage::Exec,
                ));
            }
        };
        ExecutionOutput::new(
            termination,
            output.stdout().to_vec(),
            output.stderr().to_vec(),
            output.was_truncated(),
        )
        .map_err(|_| {
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
        validate_copy_path(request.target(), ExecutionStage::CopyTo)?;
        let state = self.inspect_sandbox(cancellation, ExecutionStage::CopyTo)?;
        if !copyable_state(state) {
            return Err(ExecutionError::new(
                ExecutionErrorKind::InvalidState,
                ExecutionStage::CopyTo,
            ));
        }
        let staged = self
            .inner
            .local_state()
            .stage_input(
                "copy-in",
                automata_execution::OperationId::new(),
                request.content(),
            )
            .map_err(|error| state_error(&error, ExecutionStage::CopyTo))?;
        if let Err(error) = staged.verify() {
            let cleanup = staged.cleanup();
            if let Err(cleanup) = cleanup {
                return Err(state_error(&cleanup, ExecutionStage::CopyTo));
            }
            return Err(state_error(&error, ExecutionStage::CopyTo));
        }
        let mut arguments = self.inner.base_arguments();
        arguments.extend(os_args(["cp", "--overwrite"]));
        arguments.push(staged.path().into());
        arguments.push(format!("{}:{}", self.names.container(), request.target().as_str()).into());
        let output = self.run(
            arguments,
            self.inner.endpoint_operation_timeout(),
            64 * 1024,
            cancellation,
            ExecutionStage::CopyTo,
        );
        staged
            .cleanup()
            .map_err(|error| state_error(&error, ExecutionStage::CopyTo))?;
        require_zero(&output?, ExecutionStage::CopyTo)
    }

    fn copy_from(
        &self,
        request: &CopyFromRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<Vec<u8>, ExecutionError> {
        let _operation = self.acquire(ExecutionStage::CopyFrom)?;
        validate_copy_path(request.source(), ExecutionStage::CopyFrom)?;
        let state = self.inspect_sandbox(cancellation, ExecutionStage::CopyFrom)?;
        if !copyable_state(state) {
            return Err(ExecutionError::new(
                ExecutionErrorKind::InvalidState,
                ExecutionStage::CopyFrom,
            ));
        }
        let staged = self
            .inner
            .local_state()
            .stage_output(automata_execution::OperationId::new())
            .map_err(|error| state_error(&error, ExecutionStage::CopyFrom))?;
        if let Err(error) = staged.verify() {
            let cleanup = staged.cleanup();
            if let Err(cleanup) = cleanup {
                return Err(state_error(&cleanup, ExecutionStage::CopyFrom));
            }
            return Err(state_error(&error, ExecutionStage::CopyFrom));
        }
        let mut arguments = self.inner.base_arguments();
        arguments.push("cp".into());
        arguments.push(format!("{}:{}", self.names.container(), request.source().as_str()).into());
        arguments.push(staged.payload_path().into());
        let output = self.run(
            arguments,
            self.inner.endpoint_operation_timeout(),
            64 * 1024,
            cancellation,
            ExecutionStage::CopyFrom,
        );
        let result = output.and_then(|output| {
            require_zero(&output, ExecutionStage::CopyFrom)?;
            staged
                .read_payload(request.byte_limit())
                .map_err(|error| state_error(&error, ExecutionStage::CopyFrom))
        });
        staged
            .cleanup()
            .map_err(|error| state_error(&error, ExecutionStage::CopyFrom))?;
        result
    }
}

struct PreparedEnvironment {
    child: ExecutionEnvironment,
    file_content: Option<Vec<u8>>,
}

fn prepare_environment(
    environment: &ExecutionEnvironment,
) -> Result<PreparedEnvironment, ExecutionError> {
    let mut child = Vec::new();
    let mut file_content = Vec::new();
    for variable in environment.values() {
        let name = variable.name().as_str();
        if provider_control_environment_name(name) {
            return Err(ExecutionError::new(
                ExecutionErrorKind::InvalidEnvironment,
                ExecutionStage::Exec,
            ));
        }
        if environment_file_name(name) {
            append_environment_file_entry(&mut file_content, variable)?;
        } else {
            child.push(variable.clone());
        }
    }
    let child = ExecutionEnvironment::new(child).map_err(|_| {
        ExecutionError::new(ExecutionErrorKind::InvalidEnvironment, ExecutionStage::Exec)
    })?;
    Ok(PreparedEnvironment {
        child,
        file_content: (!file_content.is_empty()).then_some(file_content),
    })
}

fn append_environment_file_entry(
    output: &mut Vec<u8>,
    variable: &EnvironmentVariable,
) -> Result<(), ExecutionError> {
    let value = variable.value().expose();
    let line_bytes = variable
        .name()
        .as_str()
        .len()
        .checked_add(1)
        .and_then(|bytes| bytes.checked_add(value.len()));
    if value.is_empty()
        || value.contains(['\r', '\n'])
        || line_bytes.is_none_or(|bytes| bytes > MAX_PODMAN_ENV_FILE_LINE_BYTES)
    {
        return Err(ExecutionError::new(
            ExecutionErrorKind::InvalidEnvironment,
            ExecutionStage::Exec,
        ));
    }
    output.extend_from_slice(variable.name().as_str().as_bytes());
    output.push(b'=');
    output.extend_from_slice(value.as_bytes());
    output.push(b'\n');
    Ok(())
}

fn validate_copy_path(path: &TargetPath, stage: ExecutionStage) -> Result<(), ExecutionError> {
    let value = path.as_str();
    if path.platform() != TargetPlatform::Posix
        || value == "/"
        || value.ends_with('/')
        || value.contains(':')
    {
        return Err(ExecutionError::new(
            ExecutionErrorKind::UnsupportedCapability,
            stage,
        ));
    }
    Ok(())
}

const fn copyable_state(state: SandboxState) -> bool {
    matches!(
        state,
        SandboxState::Created | SandboxState::Running | SandboxState::Stopped
    )
}

fn state_error(error: &PodmanStateRootError, stage: ExecutionStage) -> ExecutionError {
    let kind = if *error == PodmanStateRootError::TransferLimitExceeded {
        ExecutionErrorKind::OutputLimitExceeded
    } else {
        ExecutionErrorKind::LocalStorage
    };
    ExecutionError::new(kind, stage)
}

fn require_zero(output: &CommandOutput, stage: ExecutionStage) -> Result<(), ExecutionError> {
    match output.termination() {
        CommandTermination::Exited(Some(0)) if !output.was_truncated() => Ok(()),
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
