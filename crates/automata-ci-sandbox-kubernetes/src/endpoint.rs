use std::{collections::BTreeMap, time::Duration};

use automata_ci_execution::{
    Cancellation, CopyFromRequest, CopyToRequest, ExecutionCommand, ExecutionEndpoint,
    ExecutionError, ExecutionErrorKind, ExecutionOutput, ExecutionOutputRecord,
    ExecutionOutputStream, ExecutionStage, ExecutionTermination, SandboxCapability, SandboxHandle,
    SignalRequest, WaitRequest,
};
use automata_ci_sandbox_guest::{
    GUEST_PROTOCOL_VERSION, GuestOutputStream, GuestRejection, GuestRequest, GuestResponse,
    GuestTermination, MAX_GUEST_FRAME_BYTES, decode_frame, encode_frame,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use k8s_openapi::api::core::v1::Pod;
use kube::{Api, Client, ResourceExt as _, api::AttachParams};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    time::timeout,
};

use crate::{
    objects::{GUEST_BINARY, GUEST_SOCKET, MAIN_CONTAINER},
    provider::{block_on, map_kube_error, pod_state, verify_managed},
};

const ENDPOINT_CAPABILITIES: [SandboxCapability; 4] = [
    SandboxCapability::Exec,
    SandboxCapability::CopyTo,
    SandboxCapability::CopyFrom,
    SandboxCapability::EnvironmentInjection,
];

pub(crate) struct KubernetesExecutionEndpoint {
    client: Client,
    namespace: String,
    handle: SandboxHandle,
    uid: String,
    operation_timeout: Duration,
}

impl KubernetesExecutionEndpoint {
    pub(crate) fn new(
        client: Client,
        namespace: String,
        handle: SandboxHandle,
        uid: String,
        operation_timeout: Duration,
    ) -> Self {
        Self {
            client,
            namespace,
            handle,
            uid,
            operation_timeout,
        }
    }

    #[allow(clippy::too_many_lines)] // One select scope owns cancellation and every exec stream.
    fn exchange(
        &self,
        request: &GuestRequest,
        transport_timeout: Duration,
        cancellation: &dyn Cancellation,
        stage: ExecutionStage,
    ) -> Result<GuestResponse, ExecutionError> {
        if cancellation.disposition().requires_termination() {
            return Err(execution_error(ExecutionErrorKind::Cancelled, stage));
        }
        let frame = encode_frame(request)
            .map_err(|_| execution_error(ExecutionErrorKind::BackendRejected, stage))?;
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &self.namespace);
        let name = self.handle.opaque().to_owned();
        let uid = self.uid.clone();
        let operation_timeout = self.operation_timeout;
        let response = block_on(async move {
            let operation = async move {
                let pod = timeout(operation_timeout, pods.get(&name))
                    .await
                    .map_err(|_| automata_ci_execution::ProviderErrorKind::TimedOut)?
                    .map_err(|error| map_kube_error(&error))?;
                verify_managed(&pod, &name, None)?;
                if pod.uid().as_deref() != Some(&uid)
                    || pod_state(&pod) != automata_ci_execution::SandboxState::Running
                {
                    return Err(automata_ci_execution::ProviderErrorKind::OwnershipMismatch);
                }
                let params = AttachParams::default()
                    .container(MAIN_CONTAINER)
                    .stdin(true)
                    .stdout(true)
                    .stderr(true);
                let mut process = timeout(
                    operation_timeout,
                    pods.exec(&name, [GUEST_BINARY, "client", GUEST_SOCKET], &params),
                )
                .await
                .map_err(|_| automata_ci_execution::ProviderErrorKind::TimedOut)?
                .map_err(|error| map_kube_error(&error))?;
                let mut stdin = process
                    .stdin()
                    .ok_or(automata_ci_execution::ProviderErrorKind::BackendRejected)?;
                let stdout = process
                    .stdout()
                    .ok_or(automata_ci_execution::ProviderErrorKind::BackendRejected)?;
                let stderr = process
                    .stderr()
                    .ok_or(automata_ci_execution::ProviderErrorKind::BackendRejected)?;
                let write = async move {
                    stdin.write_all(&frame).await.map_err(|_| {
                        automata_ci_execution::ProviderErrorKind::AdapterUnavailable
                    })?;
                    stdin
                        .shutdown()
                        .await
                        .map_err(|_| automata_ci_execution::ProviderErrorKind::AdapterUnavailable)
                };
                let read_stdout = async move {
                    let mut bytes = Vec::new();
                    stdout
                        .take((MAX_GUEST_FRAME_BYTES + 5) as u64)
                        .read_to_end(&mut bytes)
                        .await
                        .map_err(|_| {
                            automata_ci_execution::ProviderErrorKind::AdapterUnavailable
                        })?;
                    Ok::<_, automata_ci_execution::ProviderErrorKind>(bytes)
                };
                let read_stderr = async move {
                    let mut bytes = Vec::new();
                    stderr
                        .take(1_025)
                        .read_to_end(&mut bytes)
                        .await
                        .map_err(|_| {
                            automata_ci_execution::ProviderErrorKind::AdapterUnavailable
                        })?;
                    Ok::<_, automata_ci_execution::ProviderErrorKind>(bytes)
                };
                let ((), stdout, stderr) = timeout(transport_timeout, async {
                    tokio::try_join!(write, read_stdout, read_stderr)
                })
                .await
                .map_err(|_| automata_ci_execution::ProviderErrorKind::TimedOut)??;
                timeout(operation_timeout, process.join())
                    .await
                    .map_err(|_| automata_ci_execution::ProviderErrorKind::TimedOut)?
                    .map_err(|_| automata_ci_execution::ProviderErrorKind::AdapterUnavailable)?;
                if !stderr.is_empty() || stdout.len() > MAX_GUEST_FRAME_BYTES + 4 {
                    return Err(automata_ci_execution::ProviderErrorKind::BackendRejected);
                }
                Ok(stdout)
            };
            tokio::select! {
                result = operation => result,
                () = cancellation_requested(cancellation) => {
                    Err(automata_ci_execution::ProviderErrorKind::Cancelled)
                }
            }
        })
        .map_err(|kind| execution_error(map_provider_error(kind), stage))?;
        if cancellation.disposition().requires_termination() {
            return Err(execution_error(ExecutionErrorKind::Cancelled, stage));
        }
        let response: GuestResponse = decode_frame(&response)
            .map_err(|_| execution_error(ExecutionErrorKind::BackendRejected, stage))?;
        if response.protocol() != GUEST_PROTOCOL_VERSION {
            return Err(execution_error(ExecutionErrorKind::BackendRejected, stage));
        }
        Ok(response)
    }
}

async fn cancellation_requested(cancellation: &dyn Cancellation) {
    while !cancellation.disposition().requires_termination() {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

impl std::fmt::Debug for KubernetesExecutionEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KubernetesExecutionEndpoint")
            .field("handle", &self.handle)
            .field("capabilities", &ENDPOINT_CAPABILITIES)
            .finish_non_exhaustive()
    }
}

impl ExecutionEndpoint for KubernetesExecutionEndpoint {
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
        let guest_request = exec_request(request)?;
        let response = self.exchange(
            &guest_request,
            request
                .timeout()
                .checked_add(self.operation_timeout)
                .ok_or_else(|| {
                    execution_error(ExecutionErrorKind::TimedOut, ExecutionStage::Exec)
                })?,
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
            &copy_to_request(request),
            self.operation_timeout,
            cancellation,
            ExecutionStage::CopyTo,
        )?;
        copy_to_result(response)
    }

    fn copy_from(
        &self,
        request: &CopyFromRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<Vec<u8>, ExecutionError> {
        let response = self.exchange(
            &copy_from_request(request),
            self.operation_timeout,
            cancellation,
            ExecutionStage::CopyFrom,
        )?;
        copy_from_result(response, request.byte_limit())
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
        .map_err(|_| execution_error(ExecutionErrorKind::BackendRejected, ExecutionStage::Exec))?;
    Ok(GuestRequest::Exec {
        protocol: GUEST_PROTOCOL_VERSION,
        operation_id: request.operation_id().to_string(),
        program: request.argv().program().as_str().into(),
        arguments: request.argv().arguments().to_vec(),
        environment,
        working_directory: request.working_directory().as_str().into(),
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
    let output_bytes = records.iter().try_fold(0_usize, |bytes, record| {
        bytes.checked_add(record.bytes().len())
    });
    if output_bytes.is_none_or(|bytes| bytes > output_limit) {
        return Err(execution_error(
            ExecutionErrorKind::OutputLimitExceeded,
            ExecutionStage::Exec,
        ));
    }
    let output = ExecutionOutput::new(termination, records, truncated)
        .map_err(|_| execution_error(ExecutionErrorKind::BackendRejected, ExecutionStage::Exec))?;
    Ok(output)
}

fn copy_to_request(request: &CopyToRequest) -> GuestRequest {
    GuestRequest::WriteFile {
        protocol: GUEST_PROTOCOL_VERSION,
        operation_id: request.operation_id().to_string(),
        path: request.target().as_str().into(),
        content_base64: BASE64.encode(request.content()),
    }
}

fn copy_to_result(response: GuestResponse) -> Result<(), ExecutionError> {
    match response {
        GuestResponse::WriteFile { .. } => Ok(()),
        response => Err(response_error(&response, ExecutionStage::CopyTo)),
    }
}

fn copy_from_request(request: &CopyFromRequest) -> GuestRequest {
    GuestRequest::ReadFile {
        protocol: GUEST_PROTOCOL_VERSION,
        operation_id: request.operation_id().to_string(),
        path: request.source().as_str().into(),
        byte_limit: request.byte_limit(),
    }
}

fn copy_from_result(response: GuestResponse, byte_limit: usize) -> Result<Vec<u8>, ExecutionError> {
    match response {
        GuestResponse::ReadFile { content_base64, .. } => {
            let content = BASE64.decode(content_base64).map_err(|_| {
                execution_error(
                    ExecutionErrorKind::BackendRejected,
                    ExecutionStage::CopyFrom,
                )
            })?;
            if content.len() > byte_limit {
                return Err(execution_error(
                    ExecutionErrorKind::OutputLimitExceeded,
                    ExecutionStage::CopyFrom,
                ));
            }
            Ok(content)
        }
        response => Err(response_error(&response, ExecutionStage::CopyFrom)),
    }
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
                | GuestRejection::OperationConflict
                | GuestRejection::ReplayCapacityExceeded,
            ..
        }
        | GuestResponse::Ready { .. }
        | GuestResponse::Hello { .. }
        | GuestResponse::Configured { .. }
        | GuestResponse::Exec { .. }
        | GuestResponse::WriteFile { .. }
        | GuestResponse::AtomicCommitFile { .. }
        | GuestResponse::ReadFile { .. }
        | GuestResponse::ReadOptionalFile { .. } => ExecutionErrorKind::BackendRejected,
    };
    execution_error(kind, stage)
}

fn map_provider_error(kind: automata_ci_execution::ProviderErrorKind) -> ExecutionErrorKind {
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
        _ => ExecutionErrorKind::BackendRejected,
    }
}

const fn execution_error(kind: ExecutionErrorKind, stage: ExecutionStage) -> ExecutionError {
    ExecutionError::new(kind, stage)
}
