use std::{collections::BTreeMap, fmt, future::Future, sync::Arc, time::Duration};

use automata_ci_execution::{
    Cancellation, CopyFromRequest, CopyToRequest, ExecutionCommand, ExecutionEndpoint,
    ExecutionError, ExecutionErrorKind, ExecutionOutput, ExecutionOutputRecord,
    ExecutionOutputStream, ExecutionStage, ExecutionTermination, ProviderStage, SandboxCapability,
    SandboxHandle, SignalRequest, WaitRequest,
};
use automata_ci_sandbox_guest::{
    GUEST_PROTOCOL_VERSION, GuestOutputStream, GuestRejection, GuestRequest, GuestResponse,
    GuestTermination, MAX_GUEST_FRAME_BYTES, decode_frame, encode_frame,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use super::engine::{EngineApiError, EngineExecRequest};
use super::{
    AttachedIdentity, ENDPOINT_CAPABILITIES, ENGINE_TRANSPORT_OVERHEAD, HandleOperationLock,
    LocalDockerInner, ResourceNames, cancellation_requested, guest_client_user, lock_handle,
};
use automata_ci_sandbox_guest::LOCAL_CONTROL_CLIENT;

pub(super) struct LocalDockerEndpoint {
    inner: Arc<LocalDockerInner>,
    handle: SandboxHandle,
    names: ResourceNames,
    attached: AttachedIdentity,
    operation_lock: Arc<HandleOperationLock>,
}

impl LocalDockerEndpoint {
    pub(super) fn new(
        inner: Arc<LocalDockerInner>,
        handle: SandboxHandle,
        names: ResourceNames,
        attached: AttachedIdentity,
        operation_lock: Arc<HandleOperationLock>,
    ) -> Self {
        Self {
            inner,
            handle,
            names,
            attached,
            operation_lock,
        }
    }

    fn exchange(
        &self,
        request: &GuestRequest,
        timeout: Duration,
        cancellation: &dyn Cancellation,
        stage: ExecutionStage,
    ) -> Result<GuestResponse, ExecutionError> {
        require_active(cancellation, stage)?;
        let frame = encode_frame(request)
            .map_err(|_| execution_error(ExecutionErrorKind::BackendRejected, stage))?;
        run_execution(stage, async {
            let _operation = lock_handle(Arc::clone(&self.operation_lock), cancellation)
                .await
                .ok_or_else(|| execution_error(ExecutionErrorKind::Cancelled, stage))?;
            let container = self
                .inner
                .verify_attached(&self.names, &self.attached)
                .await
                .map_err(|kind| execution_error(map_provider_kind(kind), stage))?;
            let engine_request = EngineExecRequest {
                container_id: container.id.clone(),
                command: vec![LOCAL_CONTROL_CLIENT.to_owned(), "local-client".to_owned()],
                user: guest_client_user(),
                stdin: frame,
                stdout_limit: MAX_GUEST_FRAME_BYTES + 4,
                stderr_limit: 1_024,
                timeout,
            };
            self.inner
                .verify_boundary_kind()
                .await
                .map_err(|kind| execution_error(map_provider_kind(kind), stage))?;
            require_active(cancellation, stage)?;
            let prepared = self
                .inner
                .engine
                .create_exec(
                    &engine_request.container_id,
                    &engine_request.command,
                    &engine_request.user,
                )
                .await
                .map_err(|error| execution_error(map_engine_error(error), stage))?;
            self.inner
                .verify_boundary_kind()
                .await
                .map_err(|kind| execution_error(map_provider_kind(kind), stage))?;
            let output = tokio::select! {
                biased;
                () = cancellation_requested(cancellation) => {
                    self.cancel_running(&container.id, stage).await?;
                    return Err(execution_error(ExecutionErrorKind::Cancelled, stage));
                }
                output = self.inner.engine.start_exec(&prepared, &engine_request) => output,
            };
            if cancellation.disposition().requires_termination() {
                self.cancel_running(&container.id, stage).await?;
                return Err(execution_error(ExecutionErrorKind::Cancelled, stage));
            }
            let output = match output {
                Ok(output) => output,
                Err(error) => {
                    self.cancel_running(&container.id, stage).await?;
                    return Err(execution_error(map_engine_error(error), stage));
                }
            };
            if output.exit_code != 0
                || !output.stderr.is_empty()
                || output.stdout.len() > MAX_GUEST_FRAME_BYTES + 4
            {
                return Err(execution_error(ExecutionErrorKind::BackendRejected, stage));
            }
            self.inner
                .verify_attached(&self.names, &self.attached)
                .await
                .map_err(|kind| execution_error(map_provider_kind(kind), stage))?;
            if cancellation.disposition().requires_termination() {
                self.cancel_running(&container.id, stage).await?;
                return Err(execution_error(ExecutionErrorKind::Cancelled, stage));
            }
            decode_response(&output.stdout, stage)
        })
    }

    async fn cancel_running(
        &self,
        container_id: &str,
        stage: ExecutionStage,
    ) -> Result<(), ExecutionError> {
        let current = self
            .inner
            .verify_attached(&self.names, &self.attached)
            .await
            .map_err(|kind| execution_error(map_provider_kind(kind), stage))?;
        if current.id != container_id {
            return Err(execution_error(
                ExecutionErrorKind::OwnershipMismatch,
                stage,
            ));
        }
        self.inner
            .stop_exact_running_job(&self.names, &current, &self.handle, ProviderStage::Start)
            .await
            .map_err(|error| execution_error(map_provider_kind(error.kind()), stage))
    }
}

impl fmt::Debug for LocalDockerEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalDockerEndpoint")
            .field("handle", &self.handle)
            .field("capabilities", &ENDPOINT_CAPABILITIES)
            .finish_non_exhaustive()
    }
}

impl ExecutionEndpoint for LocalDockerEndpoint {
    fn handle(&self) -> &SandboxHandle {
        &self.handle
    }

    fn capabilities(&self) -> &[SandboxCapability] {
        &ENDPOINT_CAPABILITIES
    }

    fn exec(
        &self,
        request: &ExecutionCommand,
        cancellation: &dyn Cancellation,
    ) -> Result<ExecutionOutput, ExecutionError> {
        let timeout = request
            .timeout()
            .checked_add(ENGINE_TRANSPORT_OVERHEAD)
            .ok_or_else(|| execution_error(ExecutionErrorKind::TimedOut, ExecutionStage::Exec))?;
        let response = self.exchange(
            &exec_request(request)?,
            timeout,
            cancellation,
            ExecutionStage::Exec,
        )?;
        execution_output(response, request.output_limit())
    }

    fn signal(
        &self,
        _request: SignalRequest,
        _cancellation: &dyn Cancellation,
    ) -> Result<(), ExecutionError> {
        Err(execution_error(
            ExecutionErrorKind::UnsupportedCapability,
            ExecutionStage::Signal,
        ))
    }

    fn wait(
        &self,
        _request: WaitRequest,
        _cancellation: &dyn Cancellation,
    ) -> Result<i32, ExecutionError> {
        Err(execution_error(
            ExecutionErrorKind::UnsupportedCapability,
            ExecutionStage::Wait,
        ))
    }

    fn copy_to(
        &self,
        request: &CopyToRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ExecutionError> {
        let response = self.exchange(
            &GuestRequest::WriteFile {
                protocol: GUEST_PROTOCOL_VERSION,
                operation_id: request.operation_id().to_string(),
                path: request.target().as_str().to_owned(),
                content_base64: BASE64.encode(request.content()),
            },
            ENGINE_TRANSPORT_OVERHEAD,
            cancellation,
            ExecutionStage::CopyTo,
        )?;
        match response {
            GuestResponse::WriteFile { .. } => Ok(()),
            response => Err(response_error(&response, ExecutionStage::CopyTo)),
        }
    }

    fn copy_from(
        &self,
        request: &CopyFromRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<Vec<u8>, ExecutionError> {
        let response = self.exchange(
            &GuestRequest::ReadFile {
                protocol: GUEST_PROTOCOL_VERSION,
                operation_id: request.operation_id().to_string(),
                path: request.source().as_str().to_owned(),
                byte_limit: request.byte_limit(),
            },
            ENGINE_TRANSPORT_OVERHEAD,
            cancellation,
            ExecutionStage::CopyFrom,
        )?;
        let GuestResponse::ReadFile { content_base64, .. } = response else {
            return Err(response_error(&response, ExecutionStage::CopyFrom));
        };
        let content = BASE64.decode(content_base64).map_err(|_| {
            execution_error(
                ExecutionErrorKind::BackendRejected,
                ExecutionStage::CopyFrom,
            )
        })?;
        if content.len() > request.byte_limit() {
            return Err(execution_error(
                ExecutionErrorKind::OutputLimitExceeded,
                ExecutionStage::CopyFrom,
            ));
        }
        Ok(content)
    }
}

fn require_active(
    cancellation: &dyn Cancellation,
    stage: ExecutionStage,
) -> Result<(), ExecutionError> {
    if cancellation.disposition().requires_termination() {
        Err(execution_error(ExecutionErrorKind::Cancelled, stage))
    } else {
        Ok(())
    }
}

fn exec_request(request: &ExecutionCommand) -> Result<GuestRequest, ExecutionError> {
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
        .map_err(|_| execution_error(ExecutionErrorKind::TimedOut, ExecutionStage::Exec))?;
    Ok(GuestRequest::Exec {
        protocol: GUEST_PROTOCOL_VERSION,
        operation_id: request.operation_id().to_string(),
        program: request.argv().program().as_str().to_owned(),
        arguments: request.argv().arguments().to_vec(),
        environment,
        working_directory: request.working_directory().as_str().to_owned(),
        timeout_millis,
        output_limit: request.output_limit(),
        process_limit: None,
    })
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
                    execution_error(ExecutionErrorKind::BackendRejected, ExecutionStage::Exec)
                })?;
                if data.is_empty() {
                    return Err(execution_error(
                        ExecutionErrorKind::BackendRejected,
                        ExecutionStage::Exec,
                    ));
                }
                ExecutionOutputRecord::data(stream, data).map_err(|_| {
                    execution_error(
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
        return Err(execution_error(
            ExecutionErrorKind::OutputLimitExceeded,
            ExecutionStage::Exec,
        ));
    }
    ExecutionOutput::new(termination, records, truncated)
        .map_err(|_| execution_error(ExecutionErrorKind::BackendRejected, ExecutionStage::Exec))
}

fn decode_response(bytes: &[u8], stage: ExecutionStage) -> Result<GuestResponse, ExecutionError> {
    let response: GuestResponse = decode_frame(bytes)
        .map_err(|_| execution_error(ExecutionErrorKind::BackendRejected, stage))?;
    if response.protocol() != GUEST_PROTOCOL_VERSION {
        return Err(execution_error(ExecutionErrorKind::BackendRejected, stage));
    }
    Ok(response)
}

fn response_error(response: &GuestResponse, stage: ExecutionStage) -> ExecutionError {
    let kind = match response {
        GuestResponse::Rejected {
            kind: GuestRejection::InvalidRequest,
            ..
        } => ExecutionErrorKind::InvalidEnvironment,
        GuestResponse::Rejected {
            kind:
                GuestRejection::UnsupportedProtocol
                | GuestRejection::OperationFailed
                | GuestRejection::OperationConflict,
            ..
        }
        | GuestResponse::Ready { .. }
        | GuestResponse::Hello { .. }
        | GuestResponse::Configured { .. }
        | GuestResponse::Exec { .. }
        | GuestResponse::WriteFile { .. }
        | GuestResponse::ReadFile { .. } => ExecutionErrorKind::BackendRejected,
    };
    execution_error(kind, stage)
}

const fn map_provider_kind(kind: automata_ci_execution::ProviderErrorKind) -> ExecutionErrorKind {
    match kind {
        automata_ci_execution::ProviderErrorKind::Cancelled => ExecutionErrorKind::Cancelled,
        automata_ci_execution::ProviderErrorKind::TimedOut => ExecutionErrorKind::TimedOut,
        automata_ci_execution::ProviderErrorKind::NotFound => ExecutionErrorKind::NotFound,
        automata_ci_execution::ProviderErrorKind::OwnershipMismatch => {
            ExecutionErrorKind::OwnershipMismatch
        }
        automata_ci_execution::ProviderErrorKind::InvalidState => ExecutionErrorKind::InvalidState,
        automata_ci_execution::ProviderErrorKind::OutputLimitExceeded => {
            ExecutionErrorKind::OutputLimitExceeded
        }
        automata_ci_execution::ProviderErrorKind::LocalStorage => ExecutionErrorKind::LocalStorage,
        automata_ci_execution::ProviderErrorKind::UnsupportedPlatform
        | automata_ci_execution::ProviderErrorKind::UnsupportedCapability
        | automata_ci_execution::ProviderErrorKind::AdapterUnavailable
        | automata_ci_execution::ProviderErrorKind::InvalidConfiguration
        | automata_ci_execution::ProviderErrorKind::Conflict
        | automata_ci_execution::ProviderErrorKind::BackendRejected => {
            ExecutionErrorKind::BackendRejected
        }
    }
}

const fn map_engine_error(error: EngineApiError) -> ExecutionErrorKind {
    match error {
        EngineApiError::OutputLimit => ExecutionErrorKind::OutputLimitExceeded,
        EngineApiError::RequestFailed | EngineApiError::InvalidResponse => {
            ExecutionErrorKind::BackendRejected
        }
    }
}

const fn execution_error(kind: ExecutionErrorKind, stage: ExecutionStage) -> ExecutionError {
    ExecutionError::new(kind, stage)
}

fn run_execution<T, F>(stage: ExecutionStage, future: F) -> Result<T, ExecutionError>
where
    T: Send,
    F: Future<Output = Result<T, ExecutionError>> + Send,
{
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| execution_error(ExecutionErrorKind::BackendRejected, stage))?
                    .block_on(future)
            })
            .join()
            .map_err(|_| execution_error(ExecutionErrorKind::BackendRejected, stage))?
    })
}
