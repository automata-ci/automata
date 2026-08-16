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
    ActionGraphMaterializationRequest, Cancellation, CancellationDisposition, CopyFromRequest,
    CopyToRequest, ExecutionCommand, ExecutionEndpoint, ExecutionError, ExecutionErrorKind,
    ExecutionOutput, ExecutionSignal, ExecutionStage, SandboxCapability, SandboxCustody,
    SandboxInspection, SandboxProvider, SandboxState, SealedActionReadRequest, SealedActionTree,
    SignalRequest, TargetPath, TargetPlatform, WaitRequest,
};
use automata_ci_protocol::RunnerSlotOrdinal;
use automata_ci_runner_journal::{
    EndpointOperation, EndpointOperationKind, EndpointOperationState, EndpointRequestContentRef,
    EndpointResultContentRef, JournalError, JournalInvariantError, RUNNER_JOURNAL_SCHEMA_VERSION,
    RunnerJournal,
};
use automata_ci_runner_spool::{
    ContentCommitmentDomain, ContentKind, DurableContentStore, EndpointResultCapacityReservation,
    KeyedContentCommitment,
};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::{ExecutionEventError, content::ContentOperationCoordinator, endpoint_result};

const ENDPOINT_REPLAY_SCHEMA_VERSION: u16 = 3;
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
    Invoke,
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
        let PreparedOperation::Invoke = prepared else {
            unreachable!("replay returned above")
        };
        if self.linearize_pre_invocation_cancellation(operation_id, stage, cancellation)? {
            return Err(execution_error(ExecutionErrorKind::Cancelled, stage));
        }
        let result_capacity = self
            .content_operations
            .reserve_endpoint_result(self.journal.as_ref(), self.spool.as_ref(), reservation)
            .map_err(|_| execution_error(ExecutionErrorKind::LocalStorage, stage))?;
        let binding_cancellation = LinearizedCancellation::new(
            cancellation,
            self.journal.as_ref(),
            self.session_id,
            self.slot,
            self.guard,
            operation_id,
        );
        let binding = self.verify_live_binding(stage, &binding_cancellation);
        if binding_cancellation.storage_failed() {
            return Err(execution_error(ExecutionErrorKind::LocalStorage, stage));
        }
        if binding_cancellation.cancellation_won()
            || self.linearize_pre_invocation_cancellation(operation_id, stage, cancellation)?
        {
            return Err(execution_error(ExecutionErrorKind::Cancelled, stage));
        }
        binding?;
        if let Err(error) = self.journal.commit_endpoint_invocation(
            self.session_id,
            self.slot,
            self.guard,
            operation_id,
        ) {
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
        self.publish_result(operation_id, &encoded, result_capacity, stage)?;
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
                    return Ok(PreparedOperation::Invoke);
                }
                EndpointOperationState::CancellationRequested
                | EndpointOperationState::Cancelled => {
                    return Err(execution_error(ExecutionErrorKind::Cancelled, stage));
                }
                EndpointOperationState::InvocationCommitted | EndpointOperationState::Abandoned => {
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
        Ok(PreparedOperation::Invoke)
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
        capacity: Box<dyn EndpointResultCapacityReservation<'_> + '_>,
        stage: ExecutionStage,
    ) -> Result<(), ExecutionError> {
        let committed = self.content_operations.run(|| {
            let publication = capacity
                .persist(encoded)
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
        });
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

    fn verify_live_binding(
        &self,
        stage: ExecutionStage,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ExecutionError> {
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

    fn exact_sandbox_binding(
        &self,
        sandbox: &automata_ci_execution::SandboxHandle,
        generation: automata_ci_execution::SandboxGeneration,
    ) -> bool {
        sandbox == self.inspection.handle() && generation == self.inspection.generation()
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
        fingerprint.command(request);
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

    fn materialize_action_graph(
        &self,
        request: &ActionGraphMaterializationRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<automata_ci_execution::SealedActionGraph, ExecutionError> {
        if !self.exact_sandbox_binding(request.sandbox(), request.generation()) {
            return Err(execution_error(
                ExecutionErrorKind::InvalidState,
                ExecutionStage::MaterializeAction,
            ));
        }
        let mut fingerprint = self.fingerprint(
            EndpointOperationKind::MaterializeActionGraph,
            request.operation_id(),
        );
        fingerprint.action_graph(request);
        let reservation = endpoint_result::sealed_graph_reservation(request).ok_or_else(|| {
            execution_error(
                ExecutionErrorKind::InvalidState,
                ExecutionStage::MaterializeAction,
            )
        })?;
        self.run(
            request.operation_id(),
            EndpointOperationKind::MaterializeActionGraph,
            fingerprint.finish(),
            reservation,
            ExecutionStage::MaterializeAction,
            cancellation,
            |observed| self.inner.materialize_action_graph(request, observed),
            |result| endpoint_result::encode_sealed_graph(result, request),
            |encoded| endpoint_result::decode_sealed_graph(encoded, request),
        )
    }

    fn read_sealed_action(
        &self,
        request: &SealedActionReadRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<Vec<u8>, ExecutionError> {
        if !self.exact_sandbox_binding(request.tree().sandbox(), request.tree().generation()) {
            return Err(execution_error(
                ExecutionErrorKind::InvalidState,
                ExecutionStage::ReadSealedAction,
            ));
        }
        let mut fingerprint = self.fingerprint(
            EndpointOperationKind::ReadSealedAction,
            request.operation_id(),
        );
        fingerprint.sealed_tree(request.tree());
        fingerprint.text(request.relative_path());
        fingerprint.usize(request.byte_limit());
        let reservation = endpoint_result::sealed_read_reservation(request).ok_or_else(|| {
            execution_error(
                ExecutionErrorKind::InvalidState,
                ExecutionStage::ReadSealedAction,
            )
        })?;
        self.run(
            request.operation_id(),
            EndpointOperationKind::ReadSealedAction,
            fingerprint.finish(),
            reservation,
            ExecutionStage::ReadSealedAction,
            cancellation,
            |observed| self.inner.read_sealed_action(request, observed),
            |result| endpoint_result::encode_sealed_read(result, request),
            |encoded| endpoint_result::decode_sealed_read(encoded, request),
        )
    }

    fn exec_sealed_action(
        &self,
        request: &ExecutionCommand,
        tree: &SealedActionTree,
        cancellation: &dyn Cancellation,
    ) -> Result<ExecutionOutput, ExecutionError> {
        if !self.exact_sandbox_binding(tree.sandbox(), tree.generation()) {
            return Err(execution_error(
                ExecutionErrorKind::InvalidState,
                ExecutionStage::ExecSealedAction,
            ));
        }
        let mut fingerprint = self.fingerprint(
            EndpointOperationKind::ExecSealedAction,
            request.operation_id(),
        );
        fingerprint.command(request);
        fingerprint.sealed_tree(tree);
        let reservation = endpoint_result::sealed_exec_reservation(request).ok_or_else(|| {
            execution_error(
                ExecutionErrorKind::InvalidState,
                ExecutionStage::ExecSealedAction,
            )
        })?;
        self.run(
            request.operation_id(),
            EndpointOperationKind::ExecSealedAction,
            fingerprint.finish(),
            reservation,
            ExecutionStage::ExecSealedAction,
            cancellation,
            |observed| self.inner.exec_sealed_action(request, tree, observed),
            |result| endpoint_result::encode_sealed_exec(result, request),
            |encoded| endpoint_result::decode_sealed_exec(encoded, request),
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
                if self.cancellation_won.load(Ordering::Acquire)
                    || self.storage_failed.load(Ordering::Acquire)
                {
                    return CancellationDisposition::Terminate;
                }
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
                    // Durable cancellation could not be recorded. Terminate
                    // backend work so the caller reaches fail-closed recovery,
                    // but leave the invocation unresolved for exact sandbox
                    // destruction rather than claiming durable quiescence.
                    CancellationDisposition::Terminate
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

    fn digest(&mut self, value: automata_ci_core::Sha256Digest) {
        self.bytes(value.as_bytes());
    }

    fn sandbox(&mut self, value: &automata_ci_execution::SandboxHandle) {
        self.text(value.provider().as_str());
        self.text(value.opaque());
    }

    fn command(&mut self, request: &ExecutionCommand) {
        self.target_path(request.argv().program());
        self.usize(request.argv().arguments().len());
        for argument in request.argv().arguments() {
            self.text(argument);
        }
        self.target_path(request.working_directory());
        self.usize(request.environment().values().len());
        for variable in request.environment().values() {
            self.text(variable.name().as_str());
            self.text(variable.value().expose());
            self.byte(u8::from(variable.is_secret()));
        }
        self.duration(request.timeout());
        self.usize(request.output_limit());
    }

    fn action_graph(&mut self, request: &ActionGraphMaterializationRequest) {
        self.sandbox(request.sandbox());
        self.u64(request.generation().get());
        self.digest(request.plan_sha256());
        self.digest(request.graph_sha256());
        let policy = request.archive_policy();
        self.u64(u64::from(policy.maximum_entries()));
        self.u64(policy.maximum_file_bytes());
        self.u64(policy.maximum_expanded_bytes());
        self.u16(policy.maximum_depth());
        self.u16(policy.maximum_path_bytes());
        self.usize(request.archives().len());
        for archive in request.archives() {
            self.u64(u64::from(archive.ordinal()));
            self.digest(archive.action_key_sha256());
            self.text(archive.subpath());
            self.target_path(archive.destination());
            self.usize(archive.content().len());
            self.digest(archive.sha256());
            let facts = archive.facts();
            self.u64(u64::from(facts.entry_count()));
            self.u64(u64::from(facts.regular_file_count()));
            self.u64(facts.expanded_bytes());
            self.u64(facts.maximum_regular_file_bytes());
            self.u16(facts.maximum_depth());
        }
    }

    fn sealed_tree(&mut self, tree: &SealedActionTree) {
        self.sandbox(tree.sandbox());
        self.u64(tree.generation().get());
        self.text(tree.graph_opaque());
        self.digest(tree.graph_sha256());
        self.u64(u64::from(tree.ordinal()));
        self.target_path(tree.root());
        self.digest(tree.receipt_sha256());
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
        EndpointOperationKind::MaterializeActionGraph => 5,
        EndpointOperationKind::ReadSealedAction => 6,
        EndpointOperationKind::ExecSealedAction => 7,
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

#[cfg(test)]
mod tests {
    use automata_ci_core::{
        JobContentReference, Sha256Digest, WINDOWS_ACTION_ARCHIVE_MEDIA_TYPE,
        WindowsActionArchiveFacts, WindowsRepositoryActionArchive, WindowsRepositoryActionGraph,
    };
    use automata_ci_execution::{
        ActionArchiveMaterialization, ProviderId, SandboxGeneration, SandboxHandle,
    };

    use super::*;

    fn digest(bytes: &[u8]) -> Sha256Digest {
        Sha256Digest::from_bytes(Sha256::digest(bytes).into())
    }

    fn graph_request(
        content: &[u8],
        sandbox_opaque: &str,
        generation: u64,
        plan_marker: u8,
        action_marker: u8,
        subpath: &str,
        destination: &str,
    ) -> ActionGraphMaterializationRequest {
        let action_key_sha256 = Sha256Digest::from_bytes([action_marker; 32]);
        let content_sha256 = digest(content);
        let facts = WindowsActionArchiveFacts::new(1, 1, 16, 16, 1).expect("facts");
        let planned = WindowsRepositoryActionArchive::new(
            0,
            action_key_sha256,
            subpath,
            JobContentReference::new(
                format!("windows-actions/{plan_marker:02x}.tar.gz"),
                content_sha256,
                u64::try_from(content.len()).expect("archive size"),
                WINDOWS_ACTION_ARCHIVE_MEDIA_TYPE,
            ),
            facts,
        )
        .expect("planned archive");
        let plan_sha256 = WindowsRepositoryActionGraph::new(vec![planned.clone()])
            .expect("planned graph")
            .graph_sha256();
        let archive = ActionArchiveMaterialization::new(
            planned,
            TargetPath::windows(destination).expect("destination"),
            content.to_vec(),
        )
        .expect("archive");
        ActionGraphMaterializationRequest::new(
            OperationId::new(),
            SandboxHandle::new(
                ProviderId::new("windows-hyperv").expect("provider"),
                sandbox_opaque,
            )
            .expect("sandbox"),
            SandboxGeneration::new(generation).expect("generation"),
            plan_sha256,
            vec![archive],
        )
        .expect("graph request")
    }

    fn graph_fingerprint(request: &ActionGraphMaterializationRequest) -> [u8; 32] {
        let mut fingerprint = Fingerprint::new();
        fingerprint.action_graph(request);
        *fingerprint.finish()
    }

    fn tree(
        request: &ActionGraphMaterializationRequest,
        graph_opaque: &str,
        root: &str,
        receipt_marker: u8,
    ) -> SealedActionTree {
        SealedActionTree::new(
            request.sandbox().clone(),
            request.generation(),
            graph_opaque,
            request.graph_sha256(),
            0,
            TargetPath::windows(root).expect("tree root"),
            Sha256Digest::from_bytes([receipt_marker; 32]),
        )
        .expect("tree")
    }

    fn sealed_read_fingerprint(tree: &SealedActionTree, path: &str, limit: usize) -> [u8; 32] {
        let mut fingerprint = Fingerprint::new();
        fingerprint.sealed_tree(tree);
        fingerprint.text(path);
        fingerprint.usize(limit);
        *fingerprint.finish()
    }

    fn command(argument: &str) -> ExecutionCommand {
        ExecutionCommand::new(
            OperationId::new(),
            automata_ci_execution::ExecutionArgv::new(
                TargetPath::windows(r"C:\Program Files\nodejs\node.exe").expect("program"),
                vec![argument.to_owned()],
            )
            .expect("argv"),
            TargetPath::windows(r"C:\actions\0000").expect("working directory"),
            automata_ci_execution::ExecutionEnvironment::empty(),
            Duration::from_secs(30),
            4096,
        )
        .expect("command")
    }

    fn sealed_exec_fingerprint(command: &ExecutionCommand, tree: &SealedActionTree) -> [u8; 32] {
        let mut fingerprint = Fingerprint::new();
        fingerprint.command(command);
        fingerprint.sealed_tree(tree);
        *fingerprint.finish()
    }

    #[test]
    fn sealed_action_operation_tags_are_closed_and_disjoint() {
        assert_eq!(
            [
                EndpointOperationKind::Exec,
                EndpointOperationKind::Signal,
                EndpointOperationKind::Wait,
                EndpointOperationKind::CopyTo,
                EndpointOperationKind::CopyFrom,
                EndpointOperationKind::MaterializeActionGraph,
                EndpointOperationKind::ReadSealedAction,
                EndpointOperationKind::ExecSealedAction,
            ]
            .map(operation_kind_tag),
            [0, 1, 2, 3, 4, 5, 6, 7]
        );
    }

    #[test]
    fn graph_replay_fingerprint_binds_content_and_sandbox_generation() {
        let baseline = graph_request(
            b"first archive",
            "sandbox-a",
            7,
            0x31,
            0x41,
            "",
            r"C:\actions\0000",
        );
        let changed_content = graph_request(
            b"other archive",
            "sandbox-a",
            7,
            0x31,
            0x41,
            "",
            r"C:\actions\0000",
        );
        let changed_binding = graph_request(
            b"first archive",
            "sandbox-b",
            8,
            0x31,
            0x41,
            "",
            r"C:\actions\0000",
        );
        let changed_identity = graph_request(
            b"first archive",
            "sandbox-a",
            7,
            0x32,
            0x42,
            "nested",
            r"C:\actions\0001",
        );
        let baseline = graph_fingerprint(&baseline);

        assert_ne!(baseline, graph_fingerprint(&changed_content));
        assert_ne!(baseline, graph_fingerprint(&changed_binding));
        assert_ne!(baseline, graph_fingerprint(&changed_identity));
    }

    #[test]
    fn sealed_tree_replay_fingerprint_binds_handle_receipt_path_and_limit() {
        let graph = graph_request(
            b"first archive",
            "sandbox-a",
            7,
            0x31,
            0x41,
            "",
            r"C:\actions\0000",
        );
        let baseline_tree = tree(&graph, "sealed-graph-a", r"C:\actions\0000", 0x51);
        let changed_handle = tree(&graph, "sealed-graph-b", r"C:\actions\0000", 0x51);
        let changed_receipt = tree(&graph, "sealed-graph-a", r"C:\actions\0000", 0x52);
        let changed_root = tree(&graph, "sealed-graph-a", r"C:\actions\0001", 0x51);
        let baseline = sealed_read_fingerprint(&baseline_tree, "action.yml", 4096);

        for changed in [
            sealed_read_fingerprint(&changed_handle, "action.yml", 4096),
            sealed_read_fingerprint(&changed_receipt, "action.yml", 4096),
            sealed_read_fingerprint(&changed_root, "action.yml", 4096),
            sealed_read_fingerprint(&baseline_tree, "action.yaml", 4096),
            sealed_read_fingerprint(&baseline_tree, "action.yml", 2048),
        ] {
            assert_ne!(baseline, changed);
        }
    }

    #[test]
    fn sealed_exec_replay_fingerprint_binds_command_and_tree() {
        let graph = graph_request(
            b"first archive",
            "sandbox-a",
            7,
            0x31,
            0x41,
            "",
            r"C:\actions\0000",
        );
        let baseline_tree = tree(&graph, "sealed-graph-a", r"C:\actions\0000", 0x51);
        let changed_tree = tree(&graph, "sealed-graph-a", r"C:\actions\0000", 0x52);
        let baseline_command = command("main.js");
        let baseline = sealed_exec_fingerprint(&baseline_command, &baseline_tree);

        assert_ne!(
            baseline,
            sealed_exec_fingerprint(&command("post.js"), &baseline_tree)
        );
        assert_ne!(
            baseline,
            sealed_exec_fingerprint(&baseline_command, &changed_tree)
        );
    }
}
