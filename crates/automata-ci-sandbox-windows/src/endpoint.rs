use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
    sync::{Arc, Mutex},
};

use automata_ci_execution::{
    Cancellation, CopyFromRequest, CopyToRequest, ExecutionCommand, ExecutionEndpoint,
    ExecutionError, ExecutionErrorKind, ExecutionOutput, ExecutionOutputRecord,
    ExecutionOutputStream, ExecutionSignal, ExecutionStage, ExecutionTermination, NeverCancelled,
    OperationId, ProviderErrorKind, ProviderStage, SandboxCapability, SandboxHandle, SignalRequest,
    WaitRequest,
};
use automata_ci_sandbox_guest::{
    GUEST_PROTOCOL_VERSION, GuestOutputStream, GuestRejection, GuestRequest, GuestResponse,
    GuestTermination,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use sha2::{Digest as _, Sha256};

use crate::{error, naming::ResourceName, provider::ProviderInner};

const ENDPOINT_CAPABILITIES: &[SandboxCapability] = &[
    SandboxCapability::Exec,
    SandboxCapability::Signal,
    SandboxCapability::Wait,
    SandboxCapability::CopyTo,
    SandboxCapability::CopyFrom,
    SandboxCapability::EnvironmentInjection,
];
const MAX_REPLAY_ENTRIES: usize = 256;
const MAX_REPLAY_BYTES: usize = 64 * 1024 * 1024;
const REPLAY_ENTRY_OVERHEAD: usize = 256;

#[derive(Default)]
pub(crate) struct EndpointReplayCache {
    entries: BTreeMap<ReplayKey, ReplayEntry>,
    order: VecDeque<ReplayKey>,
    bytes: usize,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct ReplayKey {
    handle: String,
    operation_id: OperationId,
}

struct ReplayEntry {
    fingerprint: [u8; 32],
    result: ReplayResult,
    bytes: usize,
}

#[derive(Clone)]
enum ReplayResult {
    Exec(Result<ExecutionOutput, ExecutionError>),
    Signal(Result<(), ExecutionError>),
    Wait(Result<i32, ExecutionError>),
    CopyTo(Result<(), ExecutionError>),
    CopyFrom(Result<Vec<u8>, ExecutionError>),
}

enum ReplayLookup {
    Miss,
    Conflict,
    Match(ReplayResult),
}

impl EndpointReplayCache {
    fn lookup(
        &self,
        handle: &SandboxHandle,
        operation_id: OperationId,
        fingerprint: &[u8; 32],
    ) -> ReplayLookup {
        let key = ReplayKey {
            handle: handle.opaque().to_owned(),
            operation_id,
        };
        self.entries.get(&key).map_or(ReplayLookup::Miss, |entry| {
            if &entry.fingerprint == fingerprint {
                ReplayLookup::Match(entry.result.clone())
            } else {
                ReplayLookup::Conflict
            }
        })
    }

    fn insert(
        &mut self,
        handle: &SandboxHandle,
        operation_id: OperationId,
        fingerprint: [u8; 32],
        result: ReplayResult,
    ) {
        let bytes = replay_result_bytes(&result).saturating_add(REPLAY_ENTRY_OVERHEAD);
        if bytes > MAX_REPLAY_BYTES {
            return;
        }
        let key = ReplayKey {
            handle: handle.opaque().to_owned(),
            operation_id,
        };
        if let Some(previous) = self.entries.remove(&key) {
            self.bytes = self.bytes.saturating_sub(previous.bytes);
            self.order.retain(|candidate| candidate != &key);
        }
        while self.entries.len() >= MAX_REPLAY_ENTRIES
            || self.bytes.saturating_add(bytes) > MAX_REPLAY_BYTES
        {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if let Some(entry) = self.entries.remove(&oldest) {
                self.bytes = self.bytes.saturating_sub(entry.bytes);
            }
        }
        self.bytes = self.bytes.saturating_add(bytes);
        self.order.push_back(key.clone());
        self.entries.insert(
            key,
            ReplayEntry {
                fingerprint,
                result,
                bytes,
            },
        );
    }

    pub(crate) fn remove_handle(&mut self, handle: &SandboxHandle) {
        self.order.retain(|key| key.handle != handle.opaque());
        self.entries.retain(|key, entry| {
            if key.handle == handle.opaque() {
                self.bytes = self.bytes.saturating_sub(entry.bytes);
                false
            } else {
                true
            }
        });
    }
}

fn replay_result_bytes(result: &ReplayResult) -> usize {
    match result {
        ReplayResult::Exec(Ok(output)) => output
            .stdout()
            .len()
            .saturating_add(output.stderr().len())
            .saturating_mul(2),
        ReplayResult::CopyFrom(Ok(bytes)) => bytes.len(),
        ReplayResult::Exec(Err(_))
        | ReplayResult::Signal(_)
        | ReplayResult::Wait(_)
        | ReplayResult::CopyTo(_)
        | ReplayResult::CopyFrom(Err(_)) => 0,
    }
}

pub(crate) struct WindowsHyperVExecutionEndpoint {
    inner: Arc<ProviderInner>,
    names: ResourceName,
    handle: SandboxHandle,
    operation_lock: Arc<Mutex<()>>,
    process_limit: u32,
}

impl WindowsHyperVExecutionEndpoint {
    pub(crate) fn new(
        inner: Arc<ProviderInner>,
        names: ResourceName,
        operation_lock: Arc<Mutex<()>>,
        process_limit: u32,
    ) -> Self {
        let handle = names.handle();
        Self {
            inner,
            names,
            handle,
            operation_lock,
            process_limit,
        }
    }

    fn request(
        &self,
        request: &GuestRequest,
        timeout: std::time::Duration,
        cancellation: &dyn Cancellation,
        stage: ExecutionStage,
    ) -> Result<GuestResponse, ExecutionError> {
        let inspection = self
            .inner
            .inspect_owned(&self.names, cancellation)
            .map_err(|failure| {
                error::execution(error::provider_to_execution(failure.kind()), stage)
            })?;
        if inspection.state() != automata_ci_execution::SandboxState::Running {
            return Err(error::execution(ExecutionErrorKind::InvalidState, stage));
        }
        self.inner
            .guest_request(
                &self.names,
                request,
                timeout,
                cancellation,
                ProviderStage::Attach,
            )
            .map_err(|failure| {
                if matches!(
                    failure.kind(),
                    ProviderErrorKind::Cancelled | ProviderErrorKind::TimedOut
                ) {
                    let _ = self.inner.terminate_container(&self.names, &NeverCancelled);
                }
                error::execution(error::provider_to_execution(failure.kind()), stage)
            })
    }

    fn replay(
        &self,
        operation_id: OperationId,
        fingerprint: &[u8; 32],
        stage: ExecutionStage,
    ) -> Result<Option<ReplayResult>, ExecutionError> {
        let replay = self
            .inner
            .endpoint_replay
            .lock()
            .map_err(|_| error::execution(ExecutionErrorKind::LocalStorage, stage))?;
        match replay.lookup(&self.handle, operation_id, fingerprint) {
            ReplayLookup::Miss => Ok(None),
            ReplayLookup::Match(result) => Ok(Some(result)),
            ReplayLookup::Conflict => {
                Err(error::execution(ExecutionErrorKind::BackendRejected, stage))
            }
        }
    }

    fn remember(
        &self,
        operation_id: OperationId,
        fingerprint: [u8; 32],
        result: ReplayResult,
        stage: ExecutionStage,
    ) -> Result<(), ExecutionError> {
        self.inner
            .endpoint_replay
            .lock()
            .map_err(|_| error::execution(ExecutionErrorKind::LocalStorage, stage))?
            .insert(&self.handle, operation_id, fingerprint, result);
        Ok(())
    }
}

impl fmt::Debug for WindowsHyperVExecutionEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsHyperVExecutionEndpoint")
            .field("handle", &self.handle)
            .field("capabilities", &ENDPOINT_CAPABILITIES)
            .finish_non_exhaustive()
    }
}

impl ExecutionEndpoint for WindowsHyperVExecutionEndpoint {
    fn handle(&self) -> &SandboxHandle {
        &self.handle
    }

    fn capabilities(&self) -> &[SandboxCapability] {
        ENDPOINT_CAPABILITIES
    }

    fn exec(
        &self,
        request: &ExecutionCommand,
        cancellation: &dyn Cancellation,
    ) -> Result<ExecutionOutput, ExecutionError> {
        let _operation = self.operation_lock.lock().map_err(|_| {
            error::execution(ExecutionErrorKind::LocalStorage, ExecutionStage::Exec)
        })?;
        let fingerprint = exec_fingerprint(request);
        if let Some(replay) =
            self.replay(request.operation_id(), &fingerprint, ExecutionStage::Exec)?
        {
            return match replay {
                ReplayResult::Exec(result) => result,
                ReplayResult::Signal(_)
                | ReplayResult::Wait(_)
                | ReplayResult::CopyTo(_)
                | ReplayResult::CopyFrom(_) => Err(error::execution(
                    ExecutionErrorKind::BackendRejected,
                    ExecutionStage::Exec,
                )),
            };
        }
        let result = self.exec_once(request, cancellation);
        self.remember(
            request.operation_id(),
            fingerprint,
            ReplayResult::Exec(result.clone()),
            ExecutionStage::Exec,
        )?;
        result
    }

    fn signal(
        &self,
        request: SignalRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ExecutionError> {
        let _operation = self.operation_lock.lock().map_err(|_| {
            error::execution(ExecutionErrorKind::LocalStorage, ExecutionStage::Signal)
        })?;
        let fingerprint = signal_fingerprint(request);
        if let Some(replay) =
            self.replay(request.operation_id(), &fingerprint, ExecutionStage::Signal)?
        {
            return match replay {
                ReplayResult::Signal(result) => result,
                ReplayResult::Exec(_)
                | ReplayResult::Wait(_)
                | ReplayResult::CopyTo(_)
                | ReplayResult::CopyFrom(_) => Err(error::execution(
                    ExecutionErrorKind::BackendRejected,
                    ExecutionStage::Signal,
                )),
            };
        }
        let result = self.signal_once(request.signal(), cancellation);
        self.remember(
            request.operation_id(),
            fingerprint,
            ReplayResult::Signal(result),
            ExecutionStage::Signal,
        )?;
        result
    }

    fn wait(
        &self,
        request: WaitRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<i32, ExecutionError> {
        let _operation = self.operation_lock.lock().map_err(|_| {
            error::execution(ExecutionErrorKind::LocalStorage, ExecutionStage::Wait)
        })?;
        let fingerprint = wait_fingerprint(request);
        if let Some(replay) =
            self.replay(request.operation_id(), &fingerprint, ExecutionStage::Wait)?
        {
            return match replay {
                ReplayResult::Wait(result) => result,
                ReplayResult::Exec(_)
                | ReplayResult::Signal(_)
                | ReplayResult::CopyTo(_)
                | ReplayResult::CopyFrom(_) => Err(error::execution(
                    ExecutionErrorKind::BackendRejected,
                    ExecutionStage::Wait,
                )),
            };
        }
        let result = self
            .inner
            .wait_container(&self.names, request.timeout(), cancellation)
            .map_err(|failure| {
                error::execution(
                    error::provider_to_execution(failure.kind()),
                    ExecutionStage::Wait,
                )
            });
        self.remember(
            request.operation_id(),
            fingerprint,
            ReplayResult::Wait(result),
            ExecutionStage::Wait,
        )?;
        result
    }

    fn copy_to(
        &self,
        request: &CopyToRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ExecutionError> {
        let _operation = self.operation_lock.lock().map_err(|_| {
            error::execution(ExecutionErrorKind::LocalStorage, ExecutionStage::CopyTo)
        })?;
        let fingerprint = copy_to_fingerprint(request);
        if let Some(replay) =
            self.replay(request.operation_id(), &fingerprint, ExecutionStage::CopyTo)?
        {
            return match replay {
                ReplayResult::CopyTo(result) => result,
                ReplayResult::Exec(_)
                | ReplayResult::Signal(_)
                | ReplayResult::Wait(_)
                | ReplayResult::CopyFrom(_) => Err(error::execution(
                    ExecutionErrorKind::BackendRejected,
                    ExecutionStage::CopyTo,
                )),
            };
        }
        let result = self.copy_to_once(request, cancellation);
        self.remember(
            request.operation_id(),
            fingerprint,
            ReplayResult::CopyTo(result),
            ExecutionStage::CopyTo,
        )?;
        result
    }

    fn copy_from(
        &self,
        request: &CopyFromRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<Vec<u8>, ExecutionError> {
        let _operation = self.operation_lock.lock().map_err(|_| {
            error::execution(ExecutionErrorKind::LocalStorage, ExecutionStage::CopyFrom)
        })?;
        let fingerprint = copy_from_fingerprint(request);
        if let Some(replay) = self.replay(
            request.operation_id(),
            &fingerprint,
            ExecutionStage::CopyFrom,
        )? {
            return match replay {
                ReplayResult::CopyFrom(result) => result,
                ReplayResult::Exec(_)
                | ReplayResult::Signal(_)
                | ReplayResult::Wait(_)
                | ReplayResult::CopyTo(_) => Err(error::execution(
                    ExecutionErrorKind::BackendRejected,
                    ExecutionStage::CopyFrom,
                )),
            };
        }
        let result = self.copy_from_once(request, cancellation);
        self.remember(
            request.operation_id(),
            fingerprint,
            ReplayResult::CopyFrom(result.clone()),
            ExecutionStage::CopyFrom,
        )?;
        result
    }
}

impl WindowsHyperVExecutionEndpoint {
    fn exec_once(
        &self,
        request: &ExecutionCommand,
        cancellation: &dyn Cancellation,
    ) -> Result<ExecutionOutput, ExecutionError> {
        let mut names = BTreeSet::new();
        let mut environment = BTreeMap::new();
        for variable in request.environment().values() {
            if !names.insert(variable.name().as_str().to_ascii_lowercase()) {
                return Err(error::execution(
                    ExecutionErrorKind::InvalidEnvironment,
                    ExecutionStage::Exec,
                ));
            }
            environment.insert(
                variable.name().as_str().to_owned(),
                variable.value().expose().to_owned(),
            );
        }
        let timeout_millis = u64::try_from(request.timeout().as_millis()).map_err(|_| {
            error::execution(ExecutionErrorKind::InvalidEnvironment, ExecutionStage::Exec)
        })?;
        let guest = GuestRequest::Exec {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: request.operation_id().as_uuid().to_string(),
            program: request.argv().program().as_str().to_owned(),
            arguments: request.argv().arguments().to_vec(),
            environment,
            working_directory: request.working_directory().as_str().to_owned(),
            timeout_millis,
            output_limit: request.output_limit(),
            process_limit: Some(self.process_limit),
        };
        let response = self.request(
            &guest,
            request
                .timeout()
                .saturating_add(self.inner.options.operation_timeout()),
            cancellation,
            ExecutionStage::Exec,
        )?;
        let output = response_to_output(response, request.output_limit())?;
        if output.termination() == ExecutionTermination::TimedOut {
            self.inner
                .terminate_container(&self.names, &NeverCancelled)
                .map_err(|failure| {
                    error::execution(
                        error::provider_to_execution(failure.kind()),
                        ExecutionStage::Exec,
                    )
                })?;
        }
        Ok(output)
    }

    fn signal_once(
        &self,
        signal: ExecutionSignal,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ExecutionError> {
        let inspection = self
            .inner
            .inspect_owned(&self.names, cancellation)
            .map_err(|failure| {
                error::execution(
                    error::provider_to_execution(failure.kind()),
                    ExecutionStage::Signal,
                )
            })?;
        if inspection.state() != automata_ci_execution::SandboxState::Running {
            return Err(error::execution(
                ExecutionErrorKind::InvalidState,
                ExecutionStage::Signal,
            ));
        }
        let result = match signal {
            ExecutionSignal::Interrupt | ExecutionSignal::Terminate => {
                return Err(error::execution(
                    ExecutionErrorKind::UnsupportedCapability,
                    ExecutionStage::Signal,
                ));
            }
            ExecutionSignal::Kill => self.inner.terminate_container(&self.names, cancellation),
        };
        result.map_err(|failure| {
            error::execution(
                error::provider_to_execution(failure.kind()),
                ExecutionStage::Signal,
            )
        })
    }

    fn copy_to_once(
        &self,
        request: &CopyToRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ExecutionError> {
        let guest = GuestRequest::WriteFile {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: request.operation_id().as_uuid().to_string(),
            path: request.target().as_str().to_owned(),
            content_base64: BASE64.encode(request.content()),
        };
        match self.request(
            &guest,
            self.inner.options.operation_timeout(),
            cancellation,
            ExecutionStage::CopyTo,
        )? {
            GuestResponse::WriteFile {
                protocol: GUEST_PROTOCOL_VERSION,
            } => Ok(()),
            response => Err(response_error(&response, ExecutionStage::CopyTo)),
        }
    }

    fn copy_from_once(
        &self,
        request: &CopyFromRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<Vec<u8>, ExecutionError> {
        let guest = GuestRequest::ReadFile {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: request.operation_id().as_uuid().to_string(),
            path: request.source().as_str().to_owned(),
            byte_limit: request.byte_limit(),
        };
        match self.request(
            &guest,
            self.inner.options.operation_timeout(),
            cancellation,
            ExecutionStage::CopyFrom,
        )? {
            GuestResponse::ReadFile {
                protocol: GUEST_PROTOCOL_VERSION,
                content_base64,
            } => {
                let content = BASE64.decode(content_base64).map_err(|_| {
                    error::execution(
                        ExecutionErrorKind::BackendRejected,
                        ExecutionStage::CopyFrom,
                    )
                })?;
                if content.len() > request.byte_limit() {
                    return Err(error::execution(
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

fn exec_fingerprint(request: &ExecutionCommand) -> [u8; 32] {
    let mut hash = replay_hash(b"exec");
    hash_field(
        &mut hash,
        request.operation_id().as_uuid().to_string().as_bytes(),
    );
    hash_field(&mut hash, request.argv().program().as_str().as_bytes());
    for argument in request.argv().arguments() {
        hash_field(&mut hash, argument.as_bytes());
    }
    hash_field(&mut hash, request.working_directory().as_str().as_bytes());
    for variable in request.environment().values() {
        hash_field(&mut hash, variable.name().as_str().as_bytes());
        hash_field(&mut hash, variable.value().expose().as_bytes());
    }
    hash_field(&mut hash, &request.timeout().as_secs().to_be_bytes());
    hash_field(&mut hash, &request.timeout().subsec_nanos().to_be_bytes());
    hash_field(
        &mut hash,
        &u64::try_from(request.output_limit())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hash.finalize().into()
}

fn signal_fingerprint(request: SignalRequest) -> [u8; 32] {
    let mut hash = replay_hash(b"signal");
    hash_field(
        &mut hash,
        request.operation_id().as_uuid().to_string().as_bytes(),
    );
    let signal = match request.signal() {
        ExecutionSignal::Interrupt => b"interrupt".as_slice(),
        ExecutionSignal::Terminate => b"terminate".as_slice(),
        ExecutionSignal::Kill => b"kill".as_slice(),
    };
    hash_field(&mut hash, signal);
    hash.finalize().into()
}

fn wait_fingerprint(request: WaitRequest) -> [u8; 32] {
    let mut hash = replay_hash(b"wait");
    hash_field(
        &mut hash,
        request.operation_id().as_uuid().to_string().as_bytes(),
    );
    hash_field(&mut hash, &request.timeout().as_secs().to_be_bytes());
    hash_field(&mut hash, &request.timeout().subsec_nanos().to_be_bytes());
    hash.finalize().into()
}

fn copy_to_fingerprint(request: &CopyToRequest) -> [u8; 32] {
    let mut hash = replay_hash(b"copy-to");
    hash_field(
        &mut hash,
        request.operation_id().as_uuid().to_string().as_bytes(),
    );
    hash_field(&mut hash, request.target().as_str().as_bytes());
    hash_field(&mut hash, request.content());
    hash.finalize().into()
}

fn copy_from_fingerprint(request: &CopyFromRequest) -> [u8; 32] {
    let mut hash = replay_hash(b"copy-from");
    hash_field(
        &mut hash,
        request.operation_id().as_uuid().to_string().as_bytes(),
    );
    hash_field(&mut hash, request.source().as_str().as_bytes());
    hash_field(
        &mut hash,
        &u64::try_from(request.byte_limit())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hash.finalize().into()
}

fn replay_hash(domain: &[u8]) -> Sha256 {
    let mut hash = Sha256::new();
    hash_field(&mut hash, b"automata.windows.endpoint-replay.v1");
    hash_field(&mut hash, domain);
    hash
}

fn hash_field(hash: &mut Sha256, value: &[u8]) {
    hash.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hash.update(value);
}

fn response_to_output(
    response: GuestResponse,
    output_limit: usize,
) -> Result<ExecutionOutput, ExecutionError> {
    let GuestResponse::Exec {
        protocol: GUEST_PROTOCOL_VERSION,
        termination,
        records,
        truncated,
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
                let bytes = record.data().map_err(|_| {
                    error::execution(ExecutionErrorKind::BackendRejected, ExecutionStage::Exec)
                })?;
                ExecutionOutputRecord::data(stream, bytes).map_err(|_| {
                    error::execution(
                        ExecutionErrorKind::OutputLimitExceeded,
                        ExecutionStage::Exec,
                    )
                })
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    if records
        .iter()
        .try_fold(0_usize, |total, record| {
            total.checked_add(record.bytes().len())
        })
        .is_none_or(|bytes| bytes > output_limit)
    {
        return Err(error::execution(
            ExecutionErrorKind::OutputLimitExceeded,
            ExecutionStage::Exec,
        ));
    }
    let termination = match termination {
        GuestTermination::Exited(code) => ExecutionTermination::Exited(code),
        GuestTermination::Signalled => ExecutionTermination::Signalled,
        GuestTermination::TimedOut => ExecutionTermination::TimedOut,
    };
    ExecutionOutput::new(termination, records, truncated)
        .map_err(|_| error::execution(ExecutionErrorKind::BackendRejected, ExecutionStage::Exec))
}

fn response_error(response: &GuestResponse, stage: ExecutionStage) -> ExecutionError {
    let kind = match response {
        GuestResponse::Rejected {
            kind: GuestRejection::InvalidRequest,
            ..
        } => ExecutionErrorKind::InvalidEnvironment,
        GuestResponse::Ready { .. }
        | GuestResponse::Hello { .. }
        | GuestResponse::Configured { .. }
        | GuestResponse::Exec { .. }
        | GuestResponse::WriteFile { .. }
        | GuestResponse::AtomicCommitFile { .. }
        | GuestResponse::ReadFile { .. }
        | GuestResponse::ReadOptionalFile { .. }
        | GuestResponse::Rejected { .. } => ExecutionErrorKind::BackendRejected,
    };
    error::execution(kind, stage)
}

#[cfg(test)]
mod tests {
    use automata_ci_execution::{ExecutionSignal, SandboxGeneration};

    use super::*;
    use crate::naming::ResourceName;

    #[test]
    fn endpoint_replay_is_exact_bounded_and_generation_scoped() {
        let names = ResourceName::for_create(
            OperationId::new(),
            SandboxGeneration::new(7).expect("generation"),
        );
        let handle = names.handle();
        let operation_id = OperationId::new();
        let request = SignalRequest::new(operation_id, ExecutionSignal::Kill);
        let fingerprint = signal_fingerprint(request);
        let mut replay = EndpointReplayCache::default();
        replay.insert(
            &handle,
            operation_id,
            fingerprint,
            ReplayResult::Signal(Ok(())),
        );
        assert!(matches!(
            replay.lookup(&handle, operation_id, &fingerprint),
            ReplayLookup::Match(ReplayResult::Signal(Ok(())))
        ));
        let changed =
            signal_fingerprint(SignalRequest::new(operation_id, ExecutionSignal::Terminate));
        assert!(matches!(
            replay.lookup(&handle, operation_id, &changed),
            ReplayLookup::Conflict
        ));

        for _ in 0..=MAX_REPLAY_ENTRIES {
            let operation_id = OperationId::new();
            replay.insert(
                &handle,
                operation_id,
                [0_u8; 32],
                ReplayResult::Signal(Ok(())),
            );
        }
        assert!(replay.entries.len() <= MAX_REPLAY_ENTRIES);
        assert!(replay.bytes <= MAX_REPLAY_BYTES);
        replay.remove_handle(&handle);
        assert!(replay.entries.is_empty());
        assert!(replay.order.is_empty());
        assert_eq!(replay.bytes, 0);
    }
}
