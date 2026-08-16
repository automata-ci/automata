use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    sync::Arc,
    time::Duration,
};

use automata_ci_execution::{
    Cancellation, CopyFromRequest, CopyToRequest, ExecutionCommand, ExecutionEndpoint,
    ExecutionError, ExecutionErrorKind, ExecutionOutput, ExecutionOutputRecord,
    ExecutionOutputStream, ExecutionStage, ExecutionTermination, SandboxCapability, SandboxHandle,
    SandboxState, SignalRequest, TargetPath, TargetPlatform, WaitRequest,
};
use automata_ci_sandbox_guest::{
    GUEST_PROTOCOL_VERSION, GuestOutputStream, GuestRejection, GuestRequest, GuestResponse,
    GuestTermination,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use crate::{
    path::{is_strict_descendant, validate_posix_path},
    provider::{ENDPOINT_CAPABILITIES, ProviderInner, SandboxEntry},
};

const COPY_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

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
pub(crate) struct MacosVirtualizationEndpoint {
    _provider: Arc<ProviderInner>,
    entry: Arc<SandboxEntry>,
}

impl MacosVirtualizationEndpoint {
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

impl fmt::Debug for MacosVirtualizationEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosVirtualizationEndpoint")
            .field("handle", &self.entry.handle)
            .field("capabilities", &&ENDPOINT_CAPABILITIES[..])
            .finish_non_exhaustive()
    }
}

impl ExecutionEndpoint for MacosVirtualizationEndpoint {
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

impl MacosVirtualizationEndpoint {
    fn exec_once(
        &self,
        request: &ExecutionCommand,
        cancellation: &dyn Cancellation,
    ) -> Result<ExecutionOutput, ExecutionError> {
        self.require_running(ExecutionStage::Exec)?;
        if !validate_posix_path(request.argv().program())
            || request.argv().program().platform() != TargetPlatform::Posix
            || !owned_target(&self.entry, request.working_directory())
        {
            return Err(error(
                ExecutionErrorKind::OwnershipMismatch,
                ExecutionStage::Exec,
            ));
        }
        let environment = request
            .environment()
            .values()
            .iter()
            .map(|variable| {
                (
                    variable.name().as_str().to_owned(),
                    variable.value().expose().to_owned(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let timeout_millis = u64::try_from(request.timeout().as_millis())
            .map_err(|_| error(ExecutionErrorKind::BackendRejected, ExecutionStage::Exec))?;
        let guest_request = GuestRequest::Exec {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: request.operation_id().to_string(),
            program: request.argv().program().as_str().to_owned(),
            arguments: request.argv().arguments().to_vec(),
            environment,
            working_directory: request.working_directory().as_str().to_owned(),
            timeout_millis,
            output_limit: request.output_limit(),
            process_limit: None,
        };
        let response = exchange(
            &self.entry,
            &guest_request,
            request.timeout(),
            cancellation,
            ExecutionStage::Exec,
        )?;
        execution_output(response, request.output_limit())
    }

    fn copy_to_once(
        &self,
        request: &CopyToRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ExecutionError> {
        self.require_running(ExecutionStage::CopyTo)?;
        if cancellation.disposition().requires_termination() {
            return Err(error(ExecutionErrorKind::Cancelled, ExecutionStage::CopyTo));
        }
        if !owned_target(&self.entry, request.target()) {
            return Err(error(
                ExecutionErrorKind::OwnershipMismatch,
                ExecutionStage::CopyTo,
            ));
        }
        let guest_request = GuestRequest::WriteFile {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: request.operation_id().to_string(),
            path: request.target().as_str().to_owned(),
            content_base64: BASE64.encode(request.content()),
        };
        match exchange(
            &self.entry,
            &guest_request,
            COPY_OPERATION_TIMEOUT,
            cancellation,
            ExecutionStage::CopyTo,
        )? {
            GuestResponse::WriteFile { .. } => Ok(()),
            response => Err(response_error(&response, ExecutionStage::CopyTo)),
        }
    }

    fn copy_from_once(
        &self,
        request: &CopyFromRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<Vec<u8>, ExecutionError> {
        self.require_running(ExecutionStage::CopyFrom)?;
        if cancellation.disposition().requires_termination() {
            return Err(error(
                ExecutionErrorKind::Cancelled,
                ExecutionStage::CopyFrom,
            ));
        }
        if !owned_target(&self.entry, request.source()) {
            return Err(error(
                ExecutionErrorKind::OwnershipMismatch,
                ExecutionStage::CopyFrom,
            ));
        }
        let guest_request = GuestRequest::ReadFile {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: request.operation_id().to_string(),
            path: request.source().as_str().to_owned(),
            byte_limit: request.byte_limit(),
        };
        match exchange(
            &self.entry,
            &guest_request,
            COPY_OPERATION_TIMEOUT,
            cancellation,
            ExecutionStage::CopyFrom,
        )? {
            GuestResponse::ReadFile { content_base64, .. } => {
                let content = BASE64.decode(content_base64).map_err(|_| {
                    error(
                        ExecutionErrorKind::BackendRejected,
                        ExecutionStage::CopyFrom,
                    )
                })?;
                if content.len() > request.byte_limit() {
                    return Err(error(
                        ExecutionErrorKind::OutputLimitExceeded,
                        ExecutionStage::CopyFrom,
                    ));
                }
                Ok(content)
            }
            response => Err(response_error(&response, ExecutionStage::CopyFrom)),
        }
    }
}

fn exchange(
    entry: &SandboxEntry,
    request: &GuestRequest,
    timeout: Duration,
    cancellation: &dyn Cancellation,
    stage: ExecutionStage,
) -> Result<GuestResponse, ExecutionError> {
    entry
        .vm
        .lock()
        .map_err(|_| error(ExecutionErrorKind::LocalStorage, stage))?
        .as_mut()
        .ok_or_else(|| error(ExecutionErrorKind::InvalidState, stage))?
        .exchange(request, timeout, cancellation, stage)
}

fn owned_target(entry: &SandboxEntry, target: &TargetPath) -> bool {
    validate_posix_path(target)
        && (target == &entry.workspace
            || target == &entry.scratch
            || is_strict_descendant(target, &entry.workspace)
            || is_strict_descendant(target, &entry.scratch))
}

fn execution_output(
    response: GuestResponse,
    output_limit: usize,
) -> Result<ExecutionOutput, ExecutionError> {
    let GuestResponse::Exec {
        termination,
        records,
        truncated,
        ..
    } = response
    else {
        return Err(response_error(&response, ExecutionStage::Exec));
    };
    let records = records
        .into_iter()
        .map(|record| {
            let stream = match record.stream() {
                GuestOutputStream::Stdout => ExecutionOutputStream::Stdout,
                GuestOutputStream::Stderr => ExecutionOutputStream::Stderr,
            };
            if record.is_end_of_stream() {
                Ok(ExecutionOutputRecord::end_of_stream(stream))
            } else {
                let data = record.data().map_err(|_| {
                    error(ExecutionErrorKind::BackendRejected, ExecutionStage::Exec)
                })?;
                ExecutionOutputRecord::data(stream, data).map_err(|_| {
                    error(
                        ExecutionErrorKind::OutputLimitExceeded,
                        ExecutionStage::Exec,
                    )
                })
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let termination = match termination {
        GuestTermination::Exited(code) => ExecutionTermination::Exited(code),
        GuestTermination::Signalled => ExecutionTermination::Signalled,
        GuestTermination::TimedOut => ExecutionTermination::TimedOut,
    };
    let bytes = records.iter().try_fold(0_usize, |total, record| {
        total.checked_add(record.bytes().len())
    });
    if bytes.is_none_or(|bytes| bytes > output_limit) {
        return Err(error(
            ExecutionErrorKind::OutputLimitExceeded,
            ExecutionStage::Exec,
        ));
    }
    ExecutionOutput::new(termination, records, truncated)
        .map_err(|_| error(ExecutionErrorKind::BackendRejected, ExecutionStage::Exec))
}

fn response_error(response: &GuestResponse, stage: ExecutionStage) -> ExecutionError {
    let kind = match response {
        GuestResponse::Rejected {
            kind: GuestRejection::InvalidRequest,
            ..
        } => ExecutionErrorKind::InvalidEnvironment,
        GuestResponse::Rejected { .. }
        | GuestResponse::Ready { .. }
        | GuestResponse::Hello { .. }
        | GuestResponse::Configured { .. }
        | GuestResponse::Exec { .. }
        | GuestResponse::WriteFile { .. }
        | GuestResponse::AtomicCommitFile { .. }
        | GuestResponse::ReadFile { .. }
        | GuestResponse::ReadOptionalFile { .. } => ExecutionErrorKind::BackendRejected,
    };
    error(kind, stage)
}

const fn error(kind: ExecutionErrorKind, stage: ExecutionStage) -> ExecutionError {
    ExecutionError::new(kind, stage)
}
