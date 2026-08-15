use std::{
    fmt,
    num::NonZeroU16,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use automata_ci_core::{LeaseGuard, OperationId, RunnerSessionId};
use automata_ci_execution::{
    Cancellation, CancellationDisposition, CopyFromRequest, CopyToRequest, ExecutionCommand,
    ExecutionEndpoint, ExecutionError, ExecutionErrorKind, ExecutionOutput, ExecutionSignal,
    ExecutionStage, SandboxCapability, SandboxCustody, SandboxInspection, SandboxProvider,
    SandboxState, SignalRequest, TargetPath, TargetPlatform, WaitRequest,
};
use automata_ci_protocol::RunnerSlotOrdinal;
use automata_ci_runner_journal::{
    EndpointCancellationCompletion, EndpointOperation, EndpointOperationKind,
    EndpointOperationState, EndpointRequestContentRef, EndpointResultContentRef, JournalError,
    JournalInvariantError, RUNNER_JOURNAL_SCHEMA_VERSION, RunnerJournal,
};
use automata_ci_runner_spool::{
    ContentCommitmentDomain, ContentKind, DurableContentStore, KeyedContentCommitment,
};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::{ExecutionEventError, content::ContentOperationCoordinator, endpoint_result};

const ENDPOINT_REPLAY_SCHEMA_VERSION: u16 = 2;
const FINGERPRINT_DOMAIN: &[u8] = b"automata-ci/runner/endpoint-request";

pub(crate) struct DurableExecutionEndpoint {
    journal: Arc<dyn RunnerJournal>,
    spool: Arc<dyn DurableContentStore>,
    content_operations: Arc<ContentOperationCoordinator>,
    serial: Arc<Mutex<()>>,
    session_id: RunnerSessionId,
    slot: RunnerSlotOrdinal,
    guard: LeaseGuard,
    provider: Arc<dyn SandboxProvider>,
    inspection: SandboxInspection,
    inner: Box<dyn ExecutionEndpoint>,
}

enum PreparedOperation {
    Replay(Vec<u8>),
    Invoke { invocation_committed: bool },
}

impl DurableExecutionEndpoint {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn bind(
        journal: Arc<dyn RunnerJournal>,
        spool: Arc<dyn DurableContentStore>,
        content_operations: Arc<ContentOperationCoordinator>,
        serial: Arc<Mutex<()>>,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        provider: Arc<dyn SandboxProvider>,
        inspection: SandboxInspection,
        inner: Box<dyn ExecutionEndpoint>,
    ) -> Result<Self, ExecutionEventError> {
        let snapshot = journal.snapshot().map_err(ExecutionEventError::Journal)?;
        let durable_slot = snapshot
            .slot(slot)
            .ok_or(ExecutionEventError::InvalidEvent)?;
        let durable_sandbox = durable_slot
            .sandbox()
            .ok_or(ExecutionEventError::InvalidEvent)?;
        let expected_slot = NonZeroU16::new(slot.get()).ok_or(ExecutionEventError::InvalidEvent)?;
        let exact = snapshot
            .session()
            .is_some_and(|session| session.session_id() == session_id)
            && durable_slot.offer().lease().guard() == guard
            && inspection.handle() == inner.handle()
            && inspection.handle().provider() == provider.provider_id()
            && provider.provider_id() == inner.handle().provider()
            && inspection.generation().get() == guard.fencing_token().get()
            && inspection.state() == SandboxState::Running
            && inspection.custody()
                == (SandboxCustody::Job {
                    runner_id: snapshot.runner_id(),
                    slot_ordinal: expected_slot,
                })
            && durable_sandbox.provider().as_str() == provider.provider_id().as_str()
            && durable_sandbox.handle().as_str() == inspection.handle().opaque();
        if !exact {
            return Err(ExecutionEventError::InvalidEvent);
        }
        Ok(Self {
            journal,
            spool,
            content_operations,
            serial,
            session_id,
            slot,
            guard,
            provider,
            inspection,
            inner,
        })
    }

    #[allow(
        clippy::needless_pass_by_value,
        clippy::too_many_arguments,
        reason = "the endpoint boundary owns and zeroizes each request digest on every exit"
    )]
    fn run<T>(
        &self,
        operation_id: OperationId,
        kind: EndpointOperationKind,
        request_digest: Zeroizing<[u8; 32]>,
        reservation: u64,
        stage: ExecutionStage,
        cancellation: &dyn Cancellation,
        invoke: impl FnOnce(&dyn Cancellation) -> Result<T, ExecutionError>,
        encode: impl FnOnce(&Result<T, ExecutionError>) -> Result<Vec<u8>, ()>,
        decode: impl FnOnce(&[u8]) -> Result<Result<T, ExecutionError>, ()>,
    ) -> Result<T, ExecutionError> {
        let _serial = self
            .serial
            .lock()
            .map_err(|_| execution_error(ExecutionErrorKind::LocalStorage, stage))?;
        let prepared = self.prepare(operation_id, kind, &request_digest, reservation, stage)?;
        if let PreparedOperation::Replay(bytes) = prepared {
            return decode(&bytes)
                .map_err(|()| execution_error(ExecutionErrorKind::LocalStorage, stage))?;
        }
        let PreparedOperation::Invoke {
            invocation_committed,
        } = prepared
        else {
            unreachable!("replay returned above")
        };
        if self.linearize_pre_invocation_cancellation(operation_id, stage, cancellation)? {
            return Err(execution_error(ExecutionErrorKind::Cancelled, stage));
        }
        let binding_cancellation = LinearizedCancellation::new(
            cancellation,
            self.journal.as_ref(),
            self.session_id,
            self.slot,
            self.guard,
            operation_id,
        );
        let binding = self.verify_live_binding(stage, invocation_committed, &binding_cancellation);
        if binding_cancellation.storage_failed() {
            return Err(execution_error(ExecutionErrorKind::LocalStorage, stage));
        }
        if binding_cancellation.cancellation_won()
            || self.linearize_pre_invocation_cancellation(operation_id, stage, cancellation)?
        {
            return Err(execution_error(ExecutionErrorKind::Cancelled, stage));
        }
        binding?;
        if !invocation_committed
            && let Err(error) = self.journal.commit_endpoint_invocation(
                self.session_id,
                self.slot,
                self.guard,
                operation_id,
            )
        {
            let kind = if matches!(
                error,
                JournalError::Invariant(JournalInvariantError::EndpointOperationCancelled)
            ) {
                ExecutionErrorKind::Cancelled
            } else {
                ExecutionErrorKind::LocalStorage
            };
            return Err(execution_error(kind, stage));
        }
        let observed = LinearizedCancellation::new(
            cancellation,
            self.journal.as_ref(),
            self.session_id,
            self.slot,
            self.guard,
            operation_id,
        );
        let result = invoke(&observed);
        if observed.storage_failed() {
            return Err(execution_error(ExecutionErrorKind::LocalStorage, stage));
        }
        if observed.cancellation_won() {
            self.complete_cancellation(operation_id, stage)?;
            return Err(execution_error(ExecutionErrorKind::Cancelled, stage));
        }
        if self.linearize_returned_cancellation(operation_id, stage, cancellation)? {
            return Err(execution_error(ExecutionErrorKind::Cancelled, stage));
        }
        let encoded = encode(&result)
            .map_err(|()| execution_error(ExecutionErrorKind::InvalidState, stage))?;
        if u64::try_from(encoded.len()).map_or(true, |bytes| bytes > reservation) {
            return Err(execution_error(ExecutionErrorKind::InvalidState, stage));
        }
        self.publish_result(operation_id, &encoded, stage)?;
        result
    }

    fn prepare(
        &self,
        operation_id: OperationId,
        kind: EndpointOperationKind,
        request_digest: &[u8; 32],
        reservation: u64,
        stage: ExecutionStage,
    ) -> Result<PreparedOperation, ExecutionError> {
        let snapshot = self
            .journal
            .snapshot()
            .map_err(|_| execution_error(ExecutionErrorKind::LocalStorage, stage))?;
        let slot = snapshot
            .slot(self.slot)
            .ok_or_else(|| execution_error(ExecutionErrorKind::InvalidState, stage))?;
        if let Some(operation) = slot
            .endpoint_operations()
            .iter()
            .find(|operation| operation.operation_id() == operation_id)
        {
            if operation.kind() != kind || operation.reserved_result_bytes() != reservation {
                return Err(execution_error(ExecutionErrorKind::InvalidState, stage));
            }
            let expected = self
                .spool
                .recreate_keyed_commitment(
                    operation.request().content().protection_id(),
                    ContentCommitmentDomain::EndpointRequest,
                    request_digest,
                )
                .map_err(|_| execution_error(ExecutionErrorKind::LocalStorage, stage))?;
            let stored = self
                .spool
                .load(operation.request().content())
                .map_err(|_| execution_error(ExecutionErrorKind::LocalStorage, stage))?;
            if !bool::from(stored.as_slice().ct_eq(expected.as_bytes().as_slice())) {
                return Err(execution_error(ExecutionErrorKind::InvalidState, stage));
            }
            match operation.state() {
                EndpointOperationState::Accepted => {
                    return Ok(PreparedOperation::Invoke {
                        invocation_committed: false,
                    });
                }
                EndpointOperationState::InvocationCommitted => {
                    return Ok(PreparedOperation::Invoke {
                        invocation_committed: true,
                    });
                }
                EndpointOperationState::CancellationRequested
                | EndpointOperationState::Cancelled => {
                    return Err(execution_error(ExecutionErrorKind::Cancelled, stage));
                }
                EndpointOperationState::Abandoned => {
                    return Err(execution_error(ExecutionErrorKind::InvalidState, stage));
                }
                EndpointOperationState::Completed { result } => {
                    let bytes = self
                        .spool
                        .load(result.content())
                        .map_err(|_| execution_error(ExecutionErrorKind::LocalStorage, stage))?;
                    return Ok(PreparedOperation::Replay(bytes));
                }
            }
        }
        let commitment = self
            .spool
            .create_keyed_commitment(ContentCommitmentDomain::EndpointRequest, request_digest)
            .map_err(|_| execution_error(ExecutionErrorKind::LocalStorage, stage))?;
        self.publish_request(operation_id, kind, &commitment, reservation)
            .map_err(|error| map_event_error(&error, stage))?;
        Ok(PreparedOperation::Invoke {
            invocation_committed: false,
        })
    }

    fn publish_request(
        &self,
        operation_id: OperationId,
        kind: EndpointOperationKind,
        commitment: &KeyedContentCommitment,
        reservation: u64,
    ) -> Result<(), ExecutionEventError> {
        self.content_operations.publish_reclaiming_capacity(
            self.journal.as_ref(),
            self.spool.as_ref(),
            || {
                let publication = self
                    .spool
                    .persist(ContentKind::EndpointRequest, commitment.as_bytes())
                    .map_err(ExecutionEventError::Spool)?;
                match publication.commit_with(|content| {
                    if content.protection_id() != commitment.protection_id() {
                        return Err(JournalError::Invariant(
                            JournalInvariantError::InvalidEndpointRequestContent,
                        ));
                    }
                    let request = EndpointRequestContentRef::new(content.clone())?;
                    let operation =
                        EndpointOperation::accepted(operation_id, kind, request, reservation)?;
                    self.journal.accept_endpoint_operation(
                        self.session_id,
                        self.slot,
                        self.guard,
                        operation,
                    )
                }) {
                    Ok(_) => Ok(()),
                    Err(failure) => {
                        let (error, publication) = failure.into_parts();
                        publication.abort();
                        Err(ExecutionEventError::Journal(error))
                    }
                }
            },
        )
    }

    fn publish_result(
        &self,
        operation_id: OperationId,
        encoded: &[u8],
        stage: ExecutionStage,
    ) -> Result<(), ExecutionError> {
        let committed = self.content_operations.publish_reclaiming_capacity(
            self.journal.as_ref(),
            self.spool.as_ref(),
            || {
                let publication = self
                    .spool
                    .persist(ContentKind::EndpointResult, encoded)
                    .map_err(ExecutionEventError::Spool)?;
                match publication.commit_with(|content| {
                    let result = EndpointResultContentRef::new(content.clone())?;
                    self.journal.record_endpoint_result(
                        self.session_id,
                        self.slot,
                        self.guard,
                        operation_id,
                        result,
                    )
                }) {
                    Ok(_) => Ok(()),
                    Err(failure) => {
                        let (error, publication) = failure.into_parts();
                        publication.abort();
                        Err(ExecutionEventError::Journal(error))
                    }
                }
            },
        );
        match committed {
            Ok(()) => Ok(()),
            Err(ExecutionEventError::Journal(JournalError::Invariant(
                JournalInvariantError::EndpointOperationCancelled,
            ))) => Err(execution_error(ExecutionErrorKind::Cancelled, stage)),
            Err(_) => Err(execution_error(ExecutionErrorKind::LocalStorage, stage)),
        }
    }

    fn linearize_pre_invocation_cancellation(
        &self,
        operation_id: OperationId,
        stage: ExecutionStage,
        cancellation: &dyn Cancellation,
    ) -> Result<bool, ExecutionError> {
        match cancellation.disposition() {
            CancellationDisposition::Active => Ok(false),
            CancellationDisposition::Terminate => {
                let snapshot = self
                    .journal
                    .record_endpoint_cancellation(
                        self.session_id,
                        self.slot,
                        self.guard,
                        operation_id,
                    )
                    .map_err(|_| execution_error(ExecutionErrorKind::LocalStorage, stage))?;
                let operation = snapshot
                    .slot(self.slot)
                    .and_then(|slot| {
                        slot.endpoint_operations()
                            .iter()
                            .find(|operation| operation.operation_id() == operation_id)
                    })
                    .ok_or_else(|| execution_error(ExecutionErrorKind::LocalStorage, stage))?;
                match operation.state() {
                    EndpointOperationState::CancellationRequested => Ok(true),
                    EndpointOperationState::Cancelled | EndpointOperationState::Abandoned => {
                        Ok(true)
                    }
                    EndpointOperationState::Completed { .. } => Ok(false),
                    EndpointOperationState::Accepted
                    | EndpointOperationState::InvocationCommitted => {
                        Err(execution_error(ExecutionErrorKind::LocalStorage, stage))
                    }
                }
            }
        }
    }

    fn linearize_returned_cancellation(
        &self,
        operation_id: OperationId,
        stage: ExecutionStage,
        cancellation: &dyn Cancellation,
    ) -> Result<bool, ExecutionError> {
        match cancellation.disposition() {
            CancellationDisposition::Active => Ok(false),
            CancellationDisposition::Terminate => {
                let snapshot = self
                    .journal
                    .record_endpoint_cancellation(
                        self.session_id,
                        self.slot,
                        self.guard,
                        operation_id,
                    )
                    .map_err(|_| execution_error(ExecutionErrorKind::LocalStorage, stage))?;
                let operation = snapshot
                    .slot(self.slot)
                    .and_then(|slot| {
                        slot.endpoint_operations()
                            .iter()
                            .find(|operation| operation.operation_id() == operation_id)
                    })
                    .ok_or_else(|| execution_error(ExecutionErrorKind::LocalStorage, stage))?;
                match operation.state() {
                    EndpointOperationState::CancellationRequested => {
                        self.complete_cancellation(operation_id, stage)?;
                        Ok(true)
                    }
                    EndpointOperationState::Cancelled | EndpointOperationState::Abandoned => {
                        Ok(true)
                    }
                    EndpointOperationState::Completed { .. } => Ok(false),
                    EndpointOperationState::Accepted
                    | EndpointOperationState::InvocationCommitted => {
                        Err(execution_error(ExecutionErrorKind::LocalStorage, stage))
                    }
                }
            }
        }
    }

    fn complete_cancellation(
        &self,
        operation_id: OperationId,
        stage: ExecutionStage,
    ) -> Result<(), ExecutionError> {
        self.journal
            .complete_endpoint_cancellation(
                self.session_id,
                self.slot,
                self.guard,
                operation_id,
                EndpointCancellationCompletion::BackendReturned,
            )
            .map(|_| ())
            .map_err(|_| execution_error(ExecutionErrorKind::LocalStorage, stage))
    }

    fn verify_live_binding(
        &self,
        stage: ExecutionStage,
        invocation_committed: bool,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ExecutionError> {
        if invocation_committed
            && !self
                .provider
                .capabilities()
                .supports(SandboxCapability::RestartSafeEndpointReplay)
        {
            return Err(execution_error(ExecutionErrorKind::InvalidState, stage));
        }
        let current = self
            .provider
            .inspect(self.inspection.handle(), cancellation)
            .map_err(|_| execution_error(ExecutionErrorKind::InvalidState, stage))?;
        if current.handle() != self.inspection.handle()
            || current.generation() != self.inspection.generation()
            || current.custody() != self.inspection.custody()
            || current.profile() != self.inspection.profile()
            || current.state() != SandboxState::Running
        {
            return Err(execution_error(ExecutionErrorKind::InvalidState, stage));
        }
        Ok(())
    }

    fn fingerprint(&self, kind: EndpointOperationKind, operation_id: OperationId) -> Fingerprint {
        let mut fingerprint = Fingerprint::new();
        fingerprint.bytes(FINGERPRINT_DOMAIN);
        fingerprint.u16(RUNNER_JOURNAL_SCHEMA_VERSION);
        fingerprint.u16(ENDPOINT_REPLAY_SCHEMA_VERSION);
        fingerprint.text(self.inspection.handle().provider().as_str());
        fingerprint.text(self.inspection.handle().opaque());
        fingerprint.u64(self.inspection.generation().get());
        match self.inspection.custody() {
            SandboxCustody::ProfileAdmission { runner_id } => {
                fingerprint.byte(0);
                fingerprint.bytes(runner_id.as_uuid().as_bytes());
            }
            SandboxCustody::Job {
                runner_id,
                slot_ordinal,
            } => {
                fingerprint.byte(1);
                fingerprint.bytes(runner_id.as_uuid().as_bytes());
                fingerprint.u16(slot_ordinal.get());
            }
        }
        fingerprint.text(self.inspection.profile().id().as_str());
        fingerprint.bytes(self.inspection.profile().digest().as_bytes());
        fingerprint.byte(operation_kind_tag(kind));
        fingerprint.bytes(operation_id.as_uuid().as_bytes());
        fingerprint
    }
}

impl fmt::Debug for DurableExecutionEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableExecutionEndpoint")
            .field("session_id", &self.session_id)
            .field("slot", &self.slot)
            .field("guard", &self.guard)
            .field("provider", &self.provider.provider_id())
            .finish_non_exhaustive()
    }
}

impl ExecutionEndpoint for DurableExecutionEndpoint {
    fn handle(&self) -> &automata_ci_execution::SandboxHandle {
        self.inner.handle()
    }

    fn capabilities(&self) -> &[SandboxCapability] {
        self.inner.capabilities()
    }

    fn exec(
        &self,
        request: &ExecutionCommand,
        cancellation: &dyn Cancellation,
    ) -> Result<ExecutionOutput, ExecutionError> {
        let mut fingerprint = self.fingerprint(EndpointOperationKind::Exec, request.operation_id());
        fingerprint.target_path(request.argv().program());
        fingerprint.usize(request.argv().arguments().len());
        for argument in request.argv().arguments() {
            fingerprint.text(argument);
        }
        fingerprint.target_path(request.working_directory());
        fingerprint.usize(request.environment().values().len());
        for variable in request.environment().values() {
            fingerprint.text(variable.name().as_str());
            fingerprint.text(variable.value().expose());
            fingerprint.byte(u8::from(variable.is_secret()));
        }
        fingerprint.duration(request.timeout());
        fingerprint.usize(request.output_limit());
        let request_digest = fingerprint.finish();
        let reservation = endpoint_result::exec_reservation(request).ok_or_else(|| {
            execution_error(ExecutionErrorKind::InvalidState, ExecutionStage::Exec)
        })?;
        self.run(
            request.operation_id(),
            EndpointOperationKind::Exec,
            request_digest,
            reservation,
            ExecutionStage::Exec,
            cancellation,
            |observed| self.inner.exec(request, observed),
            |result| endpoint_result::encode_exec(result, request),
            |encoded| endpoint_result::decode_exec(encoded, request),
        )
    }

    fn signal(
        &self,
        request: SignalRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ExecutionError> {
        let mut fingerprint =
            self.fingerprint(EndpointOperationKind::Signal, request.operation_id());
        fingerprint.byte(match request.signal() {
            ExecutionSignal::Interrupt => 0,
            ExecutionSignal::Terminate => 1,
            ExecutionSignal::Kill => 2,
        });
        self.run(
            request.operation_id(),
            EndpointOperationKind::Signal,
            fingerprint.finish(),
            endpoint_result::small_reservation(),
            ExecutionStage::Signal,
            cancellation,
            |observed| self.inner.signal(request, observed),
            |result| endpoint_result::encode_unit(1, ExecutionStage::Signal, *result),
            |encoded| endpoint_result::decode_unit(encoded, 1, ExecutionStage::Signal),
        )
    }

    fn wait(
        &self,
        request: WaitRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<i32, ExecutionError> {
        let mut fingerprint = self.fingerprint(EndpointOperationKind::Wait, request.operation_id());
        fingerprint.duration(request.timeout());
        self.run(
            request.operation_id(),
            EndpointOperationKind::Wait,
            fingerprint.finish(),
            endpoint_result::small_reservation(),
            ExecutionStage::Wait,
            cancellation,
            |observed| self.inner.wait(request, observed),
            |result| endpoint_result::encode_wait(*result),
            endpoint_result::decode_wait,
        )
    }

    fn copy_to(
        &self,
        request: &CopyToRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ExecutionError> {
        let mut fingerprint =
            self.fingerprint(EndpointOperationKind::CopyTo, request.operation_id());
        fingerprint.target_path(request.target());
        fingerprint.usize(request.content().len());
        let payload_digest = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(request.content())));
        fingerprint.bytes(payload_digest.as_slice());
        self.run(
            request.operation_id(),
            EndpointOperationKind::CopyTo,
            fingerprint.finish(),
            endpoint_result::small_reservation(),
            ExecutionStage::CopyTo,
            cancellation,
            |observed| self.inner.copy_to(request, observed),
            |result| endpoint_result::encode_unit(3, ExecutionStage::CopyTo, *result),
            |encoded| endpoint_result::decode_unit(encoded, 3, ExecutionStage::CopyTo),
        )
    }

    fn copy_from(
        &self,
        request: &CopyFromRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<Vec<u8>, ExecutionError> {
        let mut fingerprint =
            self.fingerprint(EndpointOperationKind::CopyFrom, request.operation_id());
        fingerprint.target_path(request.source());
        fingerprint.usize(request.byte_limit());
        let reservation = endpoint_result::copy_from_reservation(request).ok_or_else(|| {
            execution_error(ExecutionErrorKind::InvalidState, ExecutionStage::CopyFrom)
        })?;
        self.run(
            request.operation_id(),
            EndpointOperationKind::CopyFrom,
            fingerprint.finish(),
            reservation,
            ExecutionStage::CopyFrom,
            cancellation,
            |observed| self.inner.copy_from(request, observed),
            |result| endpoint_result::encode_bytes(result, request),
            |encoded| endpoint_result::decode_bytes(encoded, request),
        )
    }
}

struct LinearizedCancellation<'a> {
    source: &'a dyn Cancellation,
    journal: &'a dyn RunnerJournal,
    session_id: RunnerSessionId,
    slot: RunnerSlotOrdinal,
    guard: LeaseGuard,
    operation_id: OperationId,
    cancellation_won: AtomicBool,
    storage_failed: AtomicBool,
}

impl<'a> LinearizedCancellation<'a> {
    fn new(
        source: &'a dyn Cancellation,
        journal: &'a dyn RunnerJournal,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        operation_id: OperationId,
    ) -> Self {
        Self {
            source,
            journal,
            session_id,
            slot,
            guard,
            operation_id,
            cancellation_won: AtomicBool::new(false),
            storage_failed: AtomicBool::new(false),
        }
    }

    fn cancellation_won(&self) -> bool {
        self.cancellation_won.load(Ordering::Acquire)
    }

    fn storage_failed(&self) -> bool {
        self.storage_failed.load(Ordering::Acquire)
    }
}

impl Cancellation for LinearizedCancellation<'_> {
    fn disposition(&self) -> CancellationDisposition {
        match self.source.disposition() {
            CancellationDisposition::Active => CancellationDisposition::Active,
            CancellationDisposition::Terminate => {
                let committed = self.journal.record_endpoint_cancellation(
                    self.session_id,
                    self.slot,
                    self.guard,
                    self.operation_id,
                );
                if let Ok(snapshot) = committed {
                    let cancelled = snapshot.slot(self.slot).and_then(|slot| {
                        slot.endpoint_operations()
                            .iter()
                            .find(|operation| operation.operation_id() == self.operation_id)
                    });
                    if cancelled.is_some_and(|operation| {
                        matches!(
                            operation.state(),
                            EndpointOperationState::CancellationRequested
                                | EndpointOperationState::Cancelled
                        )
                    }) {
                        self.cancellation_won.store(true, Ordering::Release);
                        CancellationDisposition::Terminate
                    } else {
                        CancellationDisposition::Active
                    }
                } else {
                    self.storage_failed.store(true, Ordering::Release);
                    CancellationDisposition::Active
                }
            }
        }
    }
}

struct Fingerprint(Sha256);

impl Fingerprint {
    fn new() -> Self {
        Self(Sha256::new())
    }

    fn byte(&mut self, value: u8) {
        self.0.update([value]);
    }

    fn u16(&mut self, value: u16) {
        self.0.update(value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.0.update(value.to_be_bytes());
    }

    fn usize(&mut self, value: usize) {
        self.u64(u64::try_from(value).expect("execution request bounds fit u64"));
    }

    fn bytes(&mut self, value: &[u8]) {
        self.usize(value.len());
        self.0.update(value);
    }

    fn text(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    fn duration(&mut self, value: Duration) {
        self.u64(value.as_secs());
        self.0.update(value.subsec_nanos().to_be_bytes());
    }

    fn target_path(&mut self, value: &TargetPath) {
        self.byte(match value.platform() {
            TargetPlatform::Posix => 0,
            TargetPlatform::Windows => 1,
        });
        self.text(value.as_str());
    }

    fn finish(self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.finalize().into())
    }
}

const fn operation_kind_tag(kind: EndpointOperationKind) -> u8 {
    match kind {
        EndpointOperationKind::Exec => 0,
        EndpointOperationKind::Signal => 1,
        EndpointOperationKind::Wait => 2,
        EndpointOperationKind::CopyTo => 3,
        EndpointOperationKind::CopyFrom => 4,
    }
}

const fn execution_error(kind: ExecutionErrorKind, stage: ExecutionStage) -> ExecutionError {
    ExecutionError::new(kind, stage)
}

fn map_event_error(error: &ExecutionEventError, stage: ExecutionStage) -> ExecutionError {
    let kind = match error {
        ExecutionEventError::Journal(JournalError::Invariant(_))
        | ExecutionEventError::InvalidEvent => ExecutionErrorKind::InvalidState,
        ExecutionEventError::Journal(_) | ExecutionEventError::Spool(_) => {
            ExecutionErrorKind::LocalStorage
        }
    };
    execution_error(kind, stage)
}
