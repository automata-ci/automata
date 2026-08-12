use std::{collections::HashMap, fmt, sync::Arc};

use automata_ci_execution::{
    Cancellation, CopyFromRequest, CopyToRequest, ExecutionCommand, ExecutionEndpoint,
    ExecutionError, ExecutionErrorKind, ExecutionOutput, ExecutionStage, SandboxCapability,
    SandboxHandle, SandboxState, SignalRequest, WaitRequest,
};

use crate::{
    filesystem::{read_owned_file, require_directory, require_executable, write_owned_file},
    provider::{ENDPOINT_CAPABILITIES, ProviderInner, SandboxEntry},
    supervisor,
};

#[derive(Default)]
pub(crate) struct EndpointState {
    exec: HashMap<automata_ci_execution::OperationId, ExecReplay>,
    copy_to: HashMap<automata_ci_execution::OperationId, CopyToReplay>,
    copy_from: HashMap<automata_ci_execution::OperationId, CopyFromReplay>,
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
pub(crate) struct MacosExecutionEndpoint {
    provider: Arc<ProviderInner>,
    entry: Arc<SandboxEntry>,
}

impl MacosExecutionEndpoint {
    pub(crate) const fn new(provider: Arc<ProviderInner>, entry: Arc<SandboxEntry>) -> Self {
        Self { provider, entry }
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

impl fmt::Debug for MacosExecutionEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosExecutionEndpoint")
            .field("handle", &self.entry.handle)
            .field("capabilities", &&ENDPOINT_CAPABILITIES[..])
            .finish_non_exhaustive()
    }
}

impl ExecutionEndpoint for MacosExecutionEndpoint {
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
        self.entry
            .endpoint_state
            .lock()
            .map_err(|_| error(ExecutionErrorKind::LocalStorage, ExecutionStage::Exec))?
            .exec
            .insert(
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
        self.entry
            .endpoint_state
            .lock()
            .map_err(|_| error(ExecutionErrorKind::LocalStorage, ExecutionStage::CopyTo))?
            .copy_to
            .insert(
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
        self.entry
            .endpoint_state
            .lock()
            .map_err(|_| error(ExecutionErrorKind::LocalStorage, ExecutionStage::CopyFrom))?
            .copy_from
            .insert(
                request.operation_id(),
                CopyFromReplay {
                    request: request.clone(),
                    result: result.clone(),
                },
            );
        result
    }
}

impl MacosExecutionEndpoint {
    fn exec_once(
        &self,
        request: &ExecutionCommand,
        cancellation: &dyn Cancellation,
    ) -> Result<ExecutionOutput, ExecutionError> {
        self.require_running(ExecutionStage::Exec)?;
        require_executable(request.argv().program())
            .map_err(|_| error(ExecutionErrorKind::BackendRejected, ExecutionStage::Exec))?;
        let working_directory = self
            .provider
            .root
            .resolve_owned_target(
                request.working_directory(),
                &self.entry.workspace,
                &self.entry.scratch,
            )
            .and_then(|target| require_directory(&target))
            .map_err(|_| error(ExecutionErrorKind::OwnershipMismatch, ExecutionStage::Exec))?;
        if working_directory != std::path::Path::new(request.working_directory().as_str()) {
            return Err(error(
                ExecutionErrorKind::OwnershipMismatch,
                ExecutionStage::Exec,
            ));
        }
        supervisor::execute(
            self.provider.options.supervisor_executable(),
            request,
            cancellation,
        )
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
        let target = self
            .provider
            .root
            .resolve_owned_target(request.target(), &self.entry.workspace, &self.entry.scratch)
            .map_err(|_| {
                error(
                    ExecutionErrorKind::OwnershipMismatch,
                    ExecutionStage::CopyTo,
                )
            })?;
        write_owned_file(&target, request.content()).map_err(|source| {
            filesystem_error(
                &source,
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
        let target = self
            .provider
            .root
            .resolve_owned_target(request.source(), &self.entry.workspace, &self.entry.scratch)
            .map_err(|_| {
                error(
                    ExecutionErrorKind::OwnershipMismatch,
                    ExecutionStage::CopyFrom,
                )
            })?;
        let content = read_owned_file(&target, request.byte_limit()).map_err(|source| {
            filesystem_error(
                &source,
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

fn filesystem_error(
    source: &std::io::Error,
    stage: ExecutionStage,
    fallback: ExecutionErrorKind,
) -> ExecutionError {
    let kind = match source.kind() {
        std::io::ErrorKind::NotFound => ExecutionErrorKind::NotFound,
        std::io::ErrorKind::PermissionDenied => ExecutionErrorKind::OwnershipMismatch,
        std::io::ErrorKind::FileTooLarge => ExecutionErrorKind::OutputLimitExceeded,
        _ => fallback,
    };
    error(kind, stage)
}

const fn error(kind: ExecutionErrorKind, stage: ExecutionStage) -> ExecutionError {
    ExecutionError::new(kind, stage)
}
