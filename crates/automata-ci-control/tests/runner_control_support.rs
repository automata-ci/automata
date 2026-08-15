#![allow(dead_code)]

use std::collections::VecDeque;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use async_trait::async_trait;
use automata_ci_auth::{
    authorization::SecretExposureClass, human::TenantId, machine::AuthenticatedMachine,
};
use automata_ci_blob::{
    BlobDescriptor, BlobPayload, BlobStoreError, ImmutableBlobStore, MemoryBlobStore,
    PutBlobOutcome, VerifiedBlob,
};
use automata_ci_control::attempt::RenewLease;
use automata_ci_control::lease::{
    AuthenticatedRunnerSession, BeginLeaseRequest, BegunLeaseRequest, CompleteLeaseRequest,
    LeaseClock, LeasePollError, LeasePollOutcome, LeaseRequestCompletion,
    repository::RunnerLeaseRequestRepository,
};
use automata_ci_control::runner_control::{
    AuthorizedRunnerRegistration, ControlIdGenerator, ControlPortError, JobIrObjectReader,
    LeaseOfferClaim, LeaseOfferClaimStatus, LeaseOfferCommand, LeaseOfferCommandPublisher,
    LeaseOfferPublishOutcome, LeaseOfferReplayResolution, LeasePoller,
    RunnerRegistrationAuthorizer, RunnerSessionFenceResolver, RuntimeAuthorityIssueRequest,
    RuntimeAuthorityIssuer,
    durable::{
        CommitCommandAcknowledgement, CommitLeaseHeartbeat, CommitLeaseResponse,
        CommitRunnerLogSegment, CommitRunnerTerminalResult, LeaseResponseAction, RawLogDisposition,
        RunnerControlTransactionRepository, RunnerLogAdmission, RunnerLogAdmissionRequest,
    },
    repository::{RunnerCommandOutbox, RunnerOperationReceiptRepository, RunnerSessionRepository},
};
use automata_ci_core::{
    AttemptId, JobId, JobIrVersion, Lease, OperationId, RunId, RunnerId, RunnerSessionId,
    TrustActorEvidence, TrustActorKind, TrustAutomationKind, TrustEventKind, TrustEvidence,
    TrustOriginKind, TrustPolicy, TrustRepositoryEvidence, TrustSnapshot, TrustTokenRecursion,
    UnixMillis,
};
use automata_ci_protocol::{
    CommandSequence as ProtocolCommandSequence, JobRuntimeAuthorities, LeaseRequest,
};
use automata_ci_store::{
    AcknowledgeRunnerCommands, CommandCursor, CommandReplayDisposition, CommandReplayLimit,
    CommandReplayPage, CommandSequence, DurableRunnerCommand, EnqueueRunnerCommand,
    HeartbeatRunnerSession, JobIrMetadata, LeaseOfferCommandIdentity, OpenRunnerSession,
    ResumeRunnerSession, RunnerOperationReceipt, RunnerOperationRequest, RunnerOperationResponse,
    RunnerSessionFence, RunnerSessionSnapshot, StableRunnerSlot, StoreError,
};

pub fn trusted_snapshot() -> TrustSnapshot {
    TrustPolicy::current()
        .evaluate(
            TrustEvidence::new(TrustOriginKind::ProviderWebhook, TrustEventKind::Push)
                .with_original_actor(
                    TrustActorEvidence::new(
                        "actor-1",
                        TrustActorKind::User,
                        TrustAutomationKind::None,
                    )
                    .expect("actor evidence"),
                )
                .with_repositories(
                    TrustRepositoryEvidence::new("42", "7").expect("source repository"),
                    TrustRepositoryEvidence::new("42", "7").expect("target repository"),
                )
                .with_refs("refs/heads/main", "refs/heads/main", "refs/heads/main")
                .with_revisions("source-sha", "target-sha", "execution-sha")
                .with_fork(false)
                .with_token_recursion(TrustTokenRecursion::Suppressed),
        )
        .expect("trusted snapshot")
}

#[derive(Debug, Default)]
pub struct IngressObjects {
    inner: MemoryBlobStore,
    pub puts: AtomicUsize,
}

#[async_trait]
impl ImmutableBlobStore for IngressObjects {
    async fn put_if_absent(&self, payload: BlobPayload) -> Result<PutBlobOutcome, BlobStoreError> {
        self.puts.fetch_add(1, Ordering::SeqCst);
        self.inner.put_if_absent(payload).await
    }

    async fn get_verified(
        &self,
        descriptor: &BlobDescriptor,
        maximum_bytes: u64,
    ) -> Result<VerifiedBlob, BlobStoreError> {
        self.inner.get_verified(descriptor, maximum_bytes).await
    }
}

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
        _generation: automata_ci_store::RunnerGeneration,
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
                automata_ci_store::SessionEpoch::new(1).expect("epoch"),
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
        _request: automata_ci_store::CloseRunnerSession,
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
    pub published_commands: Mutex<Vec<LeaseOfferCommand>>,
    pub inspection: Mutex<Option<Result<LeaseOfferClaimStatus, ControlPortError>>>,
    pub publication: Mutex<Option<Result<LeaseOfferPublishOutcome, ControlPortError>>>,
    pub replay: Mutex<Option<Result<LeaseOfferReplayResolution, ControlPortError>>>,
    pub replay_sequence: Mutex<VecDeque<Result<LeaseOfferReplayResolution, ControlPortError>>>,
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
        command: LeaseOfferCommand,
    ) -> Result<LeaseOfferPublishOutcome, ControlPortError> {
        self.publications.fetch_add(1, Ordering::SeqCst);
        self.published_commands
            .lock()
            .expect("published offer commands lock")
            .push(command);
        (*self.publication.lock().expect("offer publication lock"))
            .expect("offer publication is not expected")
    }

    async fn resolve_replay(
        &self,
        _session: RunnerSessionFence,
        _operation_id: OperationId,
        _sequence: ProtocolCommandSequence,
    ) -> Result<LeaseOfferReplayResolution, ControlPortError> {
        self.replays.fetch_add(1, Ordering::SeqCst);
        if let Some(result) = self
            .replay_sequence
            .lock()
            .expect("offer replay sequence lock")
            .pop_front()
        {
            return result;
        }
        self.replay
            .lock()
            .expect("offer replay lock")
            .clone()
            .unwrap_or(Ok(LeaseOfferReplayResolution::NotPublished))
    }
}

#[derive(Debug, Default)]
pub struct AuthorityIssuer {
    pub calls: AtomicUsize,
    pub result: Mutex<Option<Result<JobRuntimeAuthorities, ControlPortError>>>,
    pub requests: Mutex<Vec<AuthorityIssueObservation>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityIssueObservation {
    pub job_id: JobId,
    pub run_id: RunId,
    pub job_ir_version: JobIrVersion,
    pub job_ir_metadata: JobIrMetadata,
    pub lease: Lease,
    pub issued_at: UnixMillis,
    pub session: RunnerSessionFence,
    pub slot: StableRunnerSlot,
}

#[async_trait]
impl RuntimeAuthorityIssuer for AuthorityIssuer {
    async fn issue(
        &self,
        request: RuntimeAuthorityIssueRequest<'_>,
    ) -> Result<JobRuntimeAuthorities, ControlPortError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.requests
            .lock()
            .expect("authority request lock")
            .push(AuthorityIssueObservation {
                job_id: request.job().job().job_id(),
                run_id: request.job().job().run_id(),
                job_ir_version: request.job().version(),
                job_ir_metadata: request.job_ir_metadata().clone(),
                lease: request.lease().clone(),
                issued_at: request.issued_at(),
                session: request.session(),
                slot: request.slot(),
            });
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
    pub replay_dispositions: Mutex<VecDeque<CommandReplayDisposition>>,
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
    ) -> Result<CommandReplayPage, StoreError> {
        let after = after.durable_value();
        let commands = self
            .values
            .lock()
            .expect("command lock")
            .iter()
            .filter(|command| {
                command.request().session() == session && command.sequence().get() > after
            })
            .take(usize::from(limit.get()))
            .cloned()
            .collect();
        let disposition = self
            .replay_dispositions
            .lock()
            .expect("command replay disposition lock")
            .pop_front()
            .unwrap_or(CommandReplayDisposition::Exhausted);
        Ok(CommandReplayPage::new(commands, disposition))
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

#[derive(Debug)]
pub struct Transactions {
    pub acknowledgements: AtomicUsize,
    pub command_cursor: Mutex<CommandCursor>,
    pub heartbeats: AtomicUsize,
    pub renewal_authorizations: AtomicUsize,
    pub renewal_ceiling: Mutex<Option<UnixMillis>>,
    pub lease_responses: AtomicUsize,
    pub terminal_results: AtomicUsize,
    pub log_admissions: AtomicUsize,
    pub log_segments: AtomicUsize,
    pub reject_log_admission: AtomicBool,
    pub log_secret_exposure: Mutex<SecretExposureClass>,
    pub raw_log_disposition: Mutex<RawLogDisposition>,
    pub last_lease_action: Mutex<Option<LeaseResponseAction>>,
    pub last_renewal: Mutex<Option<RenewLease>>,
    pub last_reported_lifecycle: Mutex<Option<automata_ci_core::JobLifecycle>>,
    pub receipts: Mutex<Vec<RunnerOperationReceipt>>,
}

impl Default for Transactions {
    fn default() -> Self {
        Self {
            acknowledgements: AtomicUsize::new(0),
            command_cursor: Mutex::new(CommandCursor::initial()),
            heartbeats: AtomicUsize::new(0),
            renewal_authorizations: AtomicUsize::new(0),
            renewal_ceiling: Mutex::new(None),
            lease_responses: AtomicUsize::new(0),
            terminal_results: AtomicUsize::new(0),
            log_admissions: AtomicUsize::new(0),
            log_segments: AtomicUsize::new(0),
            reject_log_admission: AtomicBool::new(false),
            log_secret_exposure: Mutex::new(SecretExposureClass::Secretless),
            raw_log_disposition: Mutex::new(RawLogDisposition::Persist),
            last_lease_action: Mutex::new(None),
            last_renewal: Mutex::new(None),
            last_reported_lifecycle: Mutex::new(None),
            receipts: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl RunnerControlTransactionRepository for Transactions {
    async fn admit_runner_log_segment(
        &self,
        request: RunnerLogAdmissionRequest,
    ) -> Result<RunnerLogAdmission, StoreError> {
        self.log_admissions.fetch_add(1, Ordering::SeqCst);
        if self.reject_log_admission.load(Ordering::SeqCst) {
            return Err(StoreError::AttemptFenceRejected(request.attempt_id()));
        }
        RunnerLogAdmission::new(
            request,
            TenantId::new("tenant-a").expect("tenant"),
            StableRunnerSlot::new(1).expect("slot"),
            *self.log_secret_exposure.lock().expect("log exposure lock"),
            *self
                .raw_log_disposition
                .lock()
                .expect("raw log disposition lock"),
        )
        .map_err(|error| StoreError::corrupt_data(error.to_string()))
    }

    async fn authorize_lease_renewal(
        &self,
        request: RenewLease,
        reported_lifecycle: automata_ci_core::JobLifecycle,
    ) -> Result<RenewLease, StoreError> {
        self.renewal_authorizations.fetch_add(1, Ordering::SeqCst);
        if reported_lifecycle == automata_ci_core::JobLifecycle::Finalizing {
            return Ok(request);
        }
        let ceiling = *self.renewal_ceiling.lock().expect("renewal ceiling lock");
        let Some(ceiling) = ceiling else {
            return Ok(request);
        };
        RenewLease::new(
            request.attempt_id(),
            request.session(),
            request.guard(),
            request.observed_at(),
            request.expires_at().min(ceiling),
        )
        .map_err(|_| StoreError::AttemptFenceRejected(request.attempt_id()))
    }

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
            *self
                .last_reported_lifecycle
                .lock()
                .expect("reported lifecycle lock") = request.reported_lifecycle();
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
        if request.admission().secret_exposure()
            != *self.log_secret_exposure.lock().expect("log exposure lock")
            || request.admission().raw_log_disposition()
                != *self
                    .raw_log_disposition
                    .lock()
                    .expect("raw log disposition lock")
        {
            return Err(StoreError::AttemptFenceRejected(request.attempt_id()));
        }
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
        return Ok((
            RunnerOperationReceipt::new(
                existing.request().clone(),
                existing.response().clone(),
                existing.committed_at(),
                true,
            ),
            false,
        ));
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
    pub lease_values: Mutex<Vec<(BeginLeaseRequest, Option<LeaseRequestCompletion>)>>,
    pub lease_begins: AtomicUsize,
    pub lease_completions: AtomicUsize,
    pub revoke_lease_completion: AtomicBool,
    pub lease_completion_bindings: Mutex<Vec<Option<LeaseOfferCommandIdentity>>>,
    pub lease_completion_revocation_responses: Mutex<Vec<Option<RunnerOperationResponse>>>,
    pub completion_winner: Mutex<Option<LeaseRequestCompletion>>,
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
        let (current, completion) = &values[index];
        if current.request_key().operation_id() == key.operation_id() {
            if *current != request {
                return Err(StoreError::OperationConflict {
                    session_id: key.session().session_id(),
                    operation_id: key.operation_id(),
                });
            }
            return Ok(match completion.clone() {
                Some(completion) => BegunLeaseRequest::completed(request, completion),
                None => BegunLeaseRequest::new(request, None),
            });
        }
        if key.acknowledges_operation_id() != Some(current.request_key().operation_id())
            || completion.is_none()
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
    ) -> Result<LeaseRequestCompletion, StoreError> {
        self.lease_completions.fetch_add(1, Ordering::SeqCst);
        self.lease_completion_bindings
            .lock()
            .expect("lease completion binding lock")
            .push(request.lease_offer_command());
        self.lease_completion_revocation_responses
            .lock()
            .expect("lease completion revocation response lock")
            .push(request.revoked_lease_offer_response().cloned());
        let completed = if self.revoke_lease_completion.swap(false, Ordering::SeqCst) {
            let identity = request
                .lease_offer_command()
                .ok_or_else(|| StoreError::AttemptFenceRejected(AttemptId::new()))?;
            let fallback = request
                .revoked_lease_offer_fallback()
                .ok_or_else(|| StoreError::AttemptFenceRejected(AttemptId::new()))?;
            LeaseRequestCompletion::RevokedLeaseOffer {
                offer_operation_id: identity.operation_id(),
                fallback,
            }
        } else if request.lease_offer_command().is_some() {
            LeaseRequestCompletion::LiveLeaseOffer {
                response: request.response().clone(),
                fallback: request
                    .revoked_lease_offer_fallback()
                    .ok_or_else(|| StoreError::AttemptFenceRejected(AttemptId::new()))?,
            }
        } else {
            LeaseRequestCompletion::Response(request.response().clone())
        };
        let begin = request.request();
        let key = begin.request_key();
        let mut values = self.lease_values.lock().expect("lease receipt lock");
        let Some((current, stored_completion)) = values.iter_mut().find(|(current, _)| {
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
        if let Some(completion) = stored_completion {
            return Ok(completion.clone());
        }
        if let Some(winner) = self
            .completion_winner
            .lock()
            .expect("completion winner lock")
            .take()
        {
            *stored_completion = Some(winner.clone());
            return Ok(winner);
        }
        *stored_completion = Some(completed.clone());
        Ok(completed)
    }
}
