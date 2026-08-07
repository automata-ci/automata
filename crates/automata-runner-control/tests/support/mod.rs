#![allow(dead_code)]

use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use async_trait::async_trait;
use automata_auth::machine::AuthenticatedMachine;
use automata_control::{AuthenticatedRunnerSession, LeaseClock, LeasePollError, LeasePollOutcome};
use automata_core::{OperationId, RunnerId, RunnerSessionId, UnixMillis};
use automata_protocol::{
    CommandSequence as ProtocolCommandSequence, JobRuntimeAuthorities, LeaseRequest,
};
use automata_runner_control::{
    AuthorizedRunnerRegistration, ControlIdGenerator, ControlPortError, JobIrObjectReader,
    LeaseOfferClaim, LeaseOfferClaimStatus, LeaseOfferCommand, LeaseOfferCommandPublisher,
    LeaseOfferPublishOutcome, LeasePoller, RunnerRegistrationAuthorizer,
    RunnerSessionFenceResolver, RuntimeAuthorityIssueRequest, RuntimeAuthorityIssuer,
};
use automata_store::{
    AcknowledgeRunnerCommands, BeginLeaseRequest, BegunLeaseRequest, CommandCursor,
    CommandReplayLimit, CommandSequence, CommitCommandAcknowledgement, CommitLeaseHeartbeat,
    CommitLeaseResponse, CommitRunnerLogSegment, CommitRunnerTerminalResult, CompleteLeaseRequest,
    DurableRunnerCommand, EnqueueRunnerCommand, HeartbeatRunnerSession, JobIrMetadata,
    LeaseResponseAction, OpenRunnerSession, RenewLease, ResumeRunnerSession, RunnerCommandOutbox,
    RunnerControlTransactionRepository, RunnerLeaseRequestRepository, RunnerOperationReceipt,
    RunnerOperationReceiptRepository, RunnerOperationRequest, RunnerOperationResponse,
    RunnerSessionFence, RunnerSessionRepository, RunnerSessionSnapshot, StoreError,
};

#[derive(Debug)]
pub struct Authorizer {
    pub registration: Mutex<Option<AuthorizedRunnerRegistration>>,
    pub calls: AtomicUsize,
}

#[async_trait]
impl RunnerRegistrationAuthorizer for Authorizer {
    async fn authorize(
        &self,
        _machine: &AuthenticatedMachine,
    ) -> Result<Option<AuthorizedRunnerRegistration>, ControlPortError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.registration.lock().expect("authorizer lock").clone())
    }
}

#[derive(Debug)]
pub struct Resolver {
    pub fence: Mutex<Option<RunnerSessionFence>>,
    pub calls: AtomicUsize,
}

#[async_trait]
impl RunnerSessionFenceResolver for Resolver {
    async fn resolve_current(
        &self,
        _runner_id: RunnerId,
        _generation: automata_store::RunnerGeneration,
        _session_id: RunnerSessionId,
    ) -> Result<Option<RunnerSessionFence>, ControlPortError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(*self.fence.lock().expect("resolver lock"))
    }
}

#[derive(Debug, Default)]
pub struct Sessions {
    pub snapshot: Mutex<Option<RunnerSessionSnapshot>>,
    pub opens: AtomicUsize,
    pub resumes: AtomicUsize,
    pub heartbeats: AtomicUsize,
    pub heartbeat_requests: Mutex<Vec<HeartbeatRunnerSession>>,
    pub reject_heartbeats: AtomicBool,
}

impl Sessions {
    fn snapshot_for_open(request: &OpenRunnerSession) -> RunnerSessionSnapshot {
        RunnerSessionSnapshot::try_new(
            RunnerSessionFence::new(
                request.session_id(),
                request.runner_id(),
                request.expected_generation(),
                automata_store::SessionEpoch::new(1).expect("epoch"),
            ),
            request.protocol_version(),
            request.job_ir_version(),
            request.capability_snapshot().clone(),
            request.observed_at(),
            request.observed_at(),
            None,
            CommandCursor::initial(),
        )
        .expect("snapshot")
    }
}

#[async_trait]
impl RunnerSessionRepository for Sessions {
    async fn open_session(
        &self,
        request: OpenRunnerSession,
    ) -> Result<RunnerSessionSnapshot, StoreError> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        let snapshot = Self::snapshot_for_open(&request);
        *self.snapshot.lock().expect("sessions lock") = Some(snapshot.clone());
        Ok(snapshot)
    }

    async fn close_session(
        &self,
        _request: automata_store::CloseRunnerSession,
    ) -> Result<(), StoreError> {
        panic!("close is not expected")
    }

    async fn heartbeat_session(
        &self,
        request: HeartbeatRunnerSession,
    ) -> Result<RunnerSessionSnapshot, StoreError> {
        self.heartbeats.fetch_add(1, Ordering::SeqCst);
        self.heartbeat_requests
            .lock()
            .expect("heartbeat requests lock")
            .push(request);
        if self.reject_heartbeats.load(Ordering::SeqCst) {
            return Err(StoreError::SessionClosed(request.fence().session_id()));
        }
        let current = self
            .snapshot
            .lock()
            .expect("sessions lock")
            .clone()
            .ok_or(StoreError::SessionNotFound(request.fence().session_id()))?;
        if current.fence() != request.fence() {
            return Err(StoreError::SessionFenceRejected(
                request.fence().session_id(),
            ));
        }
        Ok(current)
    }

    async fn resume_session(
        &self,
        request: ResumeRunnerSession,
    ) -> Result<RunnerSessionSnapshot, StoreError> {
        self.resumes.fetch_add(1, Ordering::SeqCst);
        let current = self
            .snapshot
            .lock()
            .expect("sessions lock")
            .clone()
            .ok_or(StoreError::SessionNotFound(request.session_id()))?;
        if current.fence().runner_id() != request.runner_id()
            || current.fence().runner_generation() != request.expected_generation()
            || current.fence().session_id() != request.session_id()
        {
            return Err(StoreError::SessionFenceRejected(request.session_id()));
        }
        Ok(current)
    }

    async fn get_session(
        &self,
        fence: RunnerSessionFence,
    ) -> Result<RunnerSessionSnapshot, StoreError> {
        let current = self
            .snapshot
            .lock()
            .expect("sessions lock")
            .clone()
            .ok_or(StoreError::SessionNotFound(fence.session_id()))?;
        if current.fence() != fence {
            return Err(StoreError::SessionFenceRejected(fence.session_id()));
        }
        Ok(current)
    }
}

#[derive(Debug, Default)]
pub struct Poller {
    pub calls: AtomicUsize,
    pub outcome: Mutex<Option<LeasePollOutcome>>,
}

#[async_trait]
impl LeasePoller for Poller {
    async fn poll(
        &self,
        _authenticated: AuthenticatedRunnerSession,
        _request: &LeaseRequest,
    ) -> Result<LeasePollOutcome, LeasePollError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .outcome
            .lock()
            .expect("poll outcome lock")
            .clone()
            .unwrap_or(LeasePollOutcome::NoWork { replayed: false }))
    }
}

#[derive(Debug, Default)]
pub struct Objects {
    pub calls: AtomicUsize,
    pub bytes: Mutex<Option<Vec<u8>>>,
}

#[async_trait]
impl JobIrObjectReader for Objects {
    async fn read_job_ir(
        &self,
        _metadata: &JobIrMetadata,
        _maximum_bytes: u64,
    ) -> Result<Vec<u8>, ControlPortError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .bytes
            .lock()
            .expect("object bytes lock")
            .clone()
            .expect("object read is not expected"))
    }
}

#[derive(Debug, Default)]
pub struct Publisher {
    pub inspections: AtomicUsize,
    pub publications: AtomicUsize,
    pub replays: AtomicUsize,
    pub inspection: Mutex<Option<Result<LeaseOfferClaimStatus, ControlPortError>>>,
    pub publication: Mutex<Option<Result<LeaseOfferPublishOutcome, ControlPortError>>>,
    pub replay: Mutex<Option<Result<Option<DurableRunnerCommand>, ControlPortError>>>,
}

#[async_trait]
impl LeaseOfferCommandPublisher for Publisher {
    async fn inspect(
        &self,
        _claim: LeaseOfferClaim,
    ) -> Result<LeaseOfferClaimStatus, ControlPortError> {
        self.inspections.fetch_add(1, Ordering::SeqCst);
        self.inspection
            .lock()
            .expect("offer inspection lock")
            .clone()
            .expect("offer inspection is not expected")
    }

    async fn publish(
        &self,
        _command: LeaseOfferCommand,
    ) -> Result<LeaseOfferPublishOutcome, ControlPortError> {
        self.publications.fetch_add(1, Ordering::SeqCst);
        (*self.publication.lock().expect("offer publication lock"))
            .expect("offer publication is not expected")
    }

    async fn resolve_replay(
        &self,
        _session: RunnerSessionFence,
        _operation_id: OperationId,
        _sequence: ProtocolCommandSequence,
    ) -> Result<Option<DurableRunnerCommand>, ControlPortError> {
        self.replays.fetch_add(1, Ordering::SeqCst);
        self.replay
            .lock()
            .expect("offer replay lock")
            .clone()
            .unwrap_or(Ok(None))
    }
}

#[derive(Debug, Default)]
pub struct AuthorityIssuer {
    pub calls: AtomicUsize,
    pub result: Mutex<Option<Result<JobRuntimeAuthorities, ControlPortError>>>,
}

#[async_trait]
impl RuntimeAuthorityIssuer for AuthorityIssuer {
    async fn issue(
        &self,
        _request: RuntimeAuthorityIssueRequest<'_>,
    ) -> Result<JobRuntimeAuthorities, ControlPortError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.result
            .lock()
            .expect("authority result lock")
            .clone()
            .expect("authority issuance is not expected")
    }
}

#[derive(Debug, Default)]
pub struct Commands {
    pub values: Mutex<Vec<DurableRunnerCommand>>,
}

#[async_trait]
impl RunnerCommandOutbox for Commands {
    async fn enqueue_command(
        &self,
        command: EnqueueRunnerCommand,
    ) -> Result<DurableRunnerCommand, StoreError> {
        let mut values = self.values.lock().expect("command lock");
        let sequence = CommandSequence::new(
            u64::try_from(values.len() + 1).expect("test command count fits u64"),
        )
        .expect("positive sequence");
        let durable = DurableRunnerCommand::new(command, sequence, false);
        values.push(durable.clone());
        Ok(durable)
    }

    async fn replay_commands(
        &self,
        session: RunnerSessionFence,
        after: CommandCursor,
        limit: CommandReplayLimit,
    ) -> Result<Vec<DurableRunnerCommand>, StoreError> {
        let after = after.durable_value();
        Ok(self
            .values
            .lock()
            .expect("command lock")
            .iter()
            .filter(|command| {
                command.request().session() == session && command.sequence().get() > after
            })
            .take(usize::from(limit.get()))
            .cloned()
            .collect())
    }

    async fn acknowledge_commands(
        &self,
        acknowledgement: AcknowledgeRunnerCommands,
    ) -> Result<CommandCursor, StoreError> {
        Ok(acknowledgement.cursor())
    }
}

#[derive(Debug)]
pub struct Clock(pub UnixMillis);

impl LeaseClock for Clock {
    fn now(&self) -> UnixMillis {
        self.0
    }
}

#[derive(Debug)]
pub struct Ids;

impl ControlIdGenerator for Ids {
    fn next_operation_id(&self) -> OperationId {
        OperationId::new()
    }
    fn next_session_id(&self) -> RunnerSessionId {
        RunnerSessionId::new()
    }
}

#[derive(Debug, Default)]
pub struct Transactions {
    pub acknowledgements: AtomicUsize,
    pub command_cursor: Mutex<CommandCursor>,
    pub heartbeats: AtomicUsize,
    pub lease_responses: AtomicUsize,
    pub terminal_results: AtomicUsize,
    pub log_segments: AtomicUsize,
    pub last_lease_action: Mutex<Option<LeaseResponseAction>>,
    pub last_renewal: Mutex<Option<RenewLease>>,
    pub receipts: Mutex<Vec<RunnerOperationReceipt>>,
}

#[async_trait]
impl RunnerControlTransactionRepository for Transactions {
    async fn commit_lease_response(
        &self,
        request: CommitLeaseResponse,
    ) -> Result<RunnerOperationReceipt, StoreError> {
        let (receipt, inserted) = record_transaction_receipt(
            &self.receipts,
            request.request(),
            request.response(),
            request.observed_at(),
        )?;
        if inserted {
            self.lease_responses.fetch_add(1, Ordering::SeqCst);
            *self.last_lease_action.lock().expect("lease action lock") = Some(request.action());
        }
        Ok(receipt)
    }

    async fn commit_lease_heartbeat(
        &self,
        request: CommitLeaseHeartbeat,
    ) -> Result<RunnerOperationReceipt, StoreError> {
        let (receipt, inserted) = record_transaction_receipt(
            &self.receipts,
            request.request(),
            request.response(),
            request.renewal().observed_at(),
        )?;
        if inserted {
            self.heartbeats.fetch_add(1, Ordering::SeqCst);
            *self.last_renewal.lock().expect("renewal lock") = Some(request.renewal());
        }
        Ok(receipt)
    }

    async fn commit_command_acknowledgement(
        &self,
        request: CommitCommandAcknowledgement,
    ) -> Result<RunnerOperationReceipt, StoreError> {
        let cursor = request.acknowledgement().cursor();
        let (receipt, inserted) = record_transaction_receipt(
            &self.receipts,
            request.request(),
            request.response(),
            request.acknowledgement().observed_at(),
        )?;
        if inserted {
            self.acknowledgements.fetch_add(1, Ordering::SeqCst);
            *self.command_cursor.lock().expect("command cursor lock") = cursor;
        }
        Ok(receipt)
    }

    async fn commit_runner_terminal_result(
        &self,
        request: CommitRunnerTerminalResult,
    ) -> Result<RunnerOperationReceipt, StoreError> {
        let (receipt, inserted) = record_transaction_receipt(
            &self.receipts,
            request.request(),
            request.response(),
            request.committed_at(),
        )?;
        if inserted {
            self.terminal_results.fetch_add(1, Ordering::SeqCst);
        }
        Ok(receipt)
    }

    async fn commit_runner_log_segment(
        &self,
        request: CommitRunnerLogSegment,
    ) -> Result<RunnerOperationReceipt, StoreError> {
        let (receipt, inserted) = record_transaction_receipt(
            &self.receipts,
            request.request(),
            request.response(),
            request.stored_at(),
        )?;
        if inserted {
            self.log_segments.fetch_add(1, Ordering::SeqCst);
        }
        Ok(receipt)
    }
}

fn record_transaction_receipt(
    receipts: &Mutex<Vec<RunnerOperationReceipt>>,
    request: &RunnerOperationRequest,
    response: &RunnerOperationResponse,
    committed_at: UnixMillis,
) -> Result<(RunnerOperationReceipt, bool), StoreError> {
    let mut receipts = receipts.lock().expect("transaction receipt lock");
    if let Some(existing) = receipts.iter().find(|receipt| {
        receipt.request().session() == request.session()
            && receipt.request().operation_id() == request.operation_id()
    }) {
        if existing.request() != request {
            return Err(StoreError::OperationConflict {
                session_id: request.session().session_id(),
                operation_id: request.operation_id(),
            });
        }
        return Ok((existing.clone(), false));
    }
    let receipt =
        RunnerOperationReceipt::new(request.clone(), response.clone(), committed_at, false);
    receipts.push(receipt.clone());
    Ok((receipt, true))
}

#[derive(Debug, Default)]
pub struct Receipts {
    pub value: Mutex<Option<RunnerOperationReceipt>>,
    pub records: AtomicUsize,
    pub lease_values: Mutex<Vec<(BeginLeaseRequest, Option<RunnerOperationResponse>)>>,
    pub lease_begins: AtomicUsize,
    pub lease_completions: AtomicUsize,
    pub completion_winner: Mutex<Option<RunnerOperationResponse>>,
}

#[async_trait]
impl RunnerOperationReceiptRepository for Receipts {
    async fn lookup_operation(
        &self,
        request: &RunnerOperationRequest,
    ) -> Result<Option<RunnerOperationReceipt>, StoreError> {
        let value = self.value.lock().expect("receipt lock").clone();
        if value
            .as_ref()
            .is_some_and(|receipt| receipt.request() != request)
        {
            return Err(StoreError::OperationConflict {
                session_id: request.session().session_id(),
                operation_id: request.operation_id(),
            });
        }
        Ok(value)
    }

    async fn record_operation(
        &self,
        request: RunnerOperationRequest,
        response: RunnerOperationResponse,
        committed_at: UnixMillis,
    ) -> Result<RunnerOperationReceipt, StoreError> {
        self.records.fetch_add(1, Ordering::SeqCst);
        let mut slot = self.value.lock().expect("receipt lock");
        if let Some(existing) = slot.clone() {
            return Ok(existing);
        }
        let receipt = RunnerOperationReceipt::new(request, response, committed_at, false);
        *slot = Some(receipt.clone());
        Ok(receipt)
    }
}

#[async_trait]
impl RunnerLeaseRequestRepository for Receipts {
    async fn begin_lease_request(
        &self,
        request: BeginLeaseRequest,
    ) -> Result<BegunLeaseRequest, StoreError> {
        self.lease_begins.fetch_add(1, Ordering::SeqCst);
        let key = request.request_key();
        let mut values = self.lease_values.lock().expect("lease receipt lock");
        let current = values.iter().position(|(current, _)| {
            current.request_key().session() == key.session()
                && current.request_key().slot() == key.slot()
        });
        let Some(index) = current else {
            if key.acknowledges_operation_id().is_some() {
                return Err(StoreError::OperationConflict {
                    session_id: key.session().session_id(),
                    operation_id: key.operation_id(),
                });
            }
            values.push((request, None));
            return Ok(BegunLeaseRequest::new(request, None));
        };
        let (current, response) = &values[index];
        if current.request_key().operation_id() == key.operation_id() {
            if *current != request {
                return Err(StoreError::OperationConflict {
                    session_id: key.session().session_id(),
                    operation_id: key.operation_id(),
                });
            }
            return Ok(BegunLeaseRequest::new(request, response.clone()));
        }
        if key.acknowledges_operation_id() != Some(current.request_key().operation_id())
            || response.is_none()
        {
            return Err(StoreError::OperationConflict {
                session_id: key.session().session_id(),
                operation_id: key.operation_id(),
            });
        }
        values[index] = (request, None);
        Ok(BegunLeaseRequest::new(request, None))
    }

    async fn complete_lease_request(
        &self,
        request: CompleteLeaseRequest,
    ) -> Result<RunnerOperationResponse, StoreError> {
        self.lease_completions.fetch_add(1, Ordering::SeqCst);
        let begin = request.request();
        let key = begin.request_key();
        let mut values = self.lease_values.lock().expect("lease receipt lock");
        let Some((current, response)) = values.iter_mut().find(|(current, _)| {
            current.request_key().session() == key.session()
                && current.request_key().slot() == key.slot()
        }) else {
            return Err(StoreError::OperationConflict {
                session_id: key.session().session_id(),
                operation_id: key.operation_id(),
            });
        };
        if *current != begin {
            return Err(StoreError::OperationConflict {
                session_id: key.session().session_id(),
                operation_id: key.operation_id(),
            });
        }
        if let Some(response) = response {
            return Ok(response.clone());
        }
        if let Some(winner) = self
            .completion_winner
            .lock()
            .expect("completion winner lock")
            .take()
        {
            *response = Some(winner.clone());
            return Ok(winner);
        }
        let completed = request.response().clone();
        *response = Some(completed.clone());
        Ok(completed)
    }
}
