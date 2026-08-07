use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use async_trait::async_trait;
use automata_core::{
    AttemptId, FencingToken, JobId, JobIr, JobIrEnvelope, JobSource, Lease, LeaseId, OperationId,
    RunId, RunnerId, RunnerRequirements, RunnerSessionId, SemanticStep, Sha256Digest, ShellSpec,
    StepId, StepIr, UnixMillis, WorkflowId,
};
use automata_protocol::{
    JobRuntimeAuthorities, JobRuntimeAuthority, ProtocolLimits, ProtocolVersion, RunnerSlotOrdinal,
    RuntimeAuthorityCredential, RuntimeAuthorityEndpoint, RuntimeAuthorityName,
};
use automata_protocol_protobuf::encode_job_ir;
use automata_runner_control::{
    ControlIdGenerator, ControlPortError, LeaseOfferClaim as ControlLeaseOfferClaim,
    LeaseOfferClaimStatus as ControlLeaseOfferClaimStatus, LeaseOfferCommand,
    LeaseOfferCommandPublisher as _, LeaseOfferPublishOutcome, RunnerSessionFenceResolver as _,
    StoreLeaseOfferCommandPublisher, StoreRunnerSessionFenceResolver,
};
use automata_store::{
    CANCEL_JOB_COMMAND_KIND, CommandSequence, CurrentRunnerSession, CurrentRunnerSessionRepository,
    DocumentSchema, DurableRunnerCommand, EnqueueRunnerCommand, JobIrMetadata, LeaseOfferClaim,
    LeaseOfferClaimStatus, LeaseOfferCommandIdentity, ObjectKey, PublishLeaseOffer,
    PublishedLeaseOffer, RunnerCommandPayload, RunnerGeneration, RunnerLeaseOfferRepository,
    RunnerOperationKind, RunnerSessionFence, SessionEpoch, StoreError,
};
use sha2::{Digest as _, Sha256};

#[derive(Debug)]
struct FixedIds {
    operation_id: OperationId,
    session_id: RunnerSessionId,
}

impl ControlIdGenerator for FixedIds {
    fn next_operation_id(&self) -> OperationId {
        self.operation_id
    }

    fn next_session_id(&self) -> RunnerSessionId {
        self.session_id
    }
}

#[derive(Debug, Default)]
struct LeaseOffers {
    captured: Mutex<Vec<PublishLeaseOffer>>,
    resolved_override: Mutex<Option<PublishedLeaseOffer>>,
}

#[async_trait]
impl RunnerLeaseOfferRepository for LeaseOffers {
    async fn inspect_lease_offer_claim(
        &self,
        request: LeaseOfferClaim,
    ) -> Result<LeaseOfferClaimStatus, StoreError> {
        let captured = self.captured.lock().expect("captured offers");
        let Some(published) = captured.last() else {
            return Ok(LeaseOfferClaimStatus::Current);
        };
        if published.claim() != &request {
            return Err(StoreError::OperationConflict {
                session_id: request.request().session().session_id(),
                operation_id: request.request().operation_id(),
            });
        }
        Ok(LeaseOfferClaimStatus::Published(Box::new(
            PublishedLeaseOffer::new(
                published.request().clone(),
                published.protocol_version(),
                published.slot(),
                published.lease().clone(),
                published.job_ir().clone(),
                DurableRunnerCommand::new(
                    published.command().clone(),
                    CommandSequence::new(7).expect("sequence"),
                    true,
                ),
            ),
        )))
    }

    async fn publish_lease_offer(
        &self,
        request: PublishLeaseOffer,
    ) -> Result<PublishedLeaseOffer, StoreError> {
        let publication = PublishedLeaseOffer::new(
            request.request().clone(),
            request.protocol_version(),
            request.slot(),
            request.lease().clone(),
            request.job_ir().clone(),
            DurableRunnerCommand::new(
                request.command().clone(),
                CommandSequence::new(7).expect("sequence"),
                false,
            ),
        );
        self.captured.lock().expect("captured offers").push(request);
        Ok(publication)
    }

    async fn resolve_lease_offer_command(
        &self,
        identity: LeaseOfferCommandIdentity,
    ) -> Result<Option<PublishedLeaseOffer>, StoreError> {
        if let Some(publication) = self
            .resolved_override
            .lock()
            .expect("resolved override")
            .clone()
        {
            return Ok(Some(publication));
        }
        let captured = self.captured.lock().expect("captured offers");
        let Some(published) = captured.last() else {
            return Ok(None);
        };
        if identity.session() != published.command().session()
            || identity.operation_id() != published.command().operation_id()
            || identity.sequence().get() != 7
        {
            return Ok(None);
        }
        Ok(Some(PublishedLeaseOffer::new(
            published.request().clone(),
            published.protocol_version(),
            published.slot(),
            published.lease().clone(),
            published.job_ir().clone(),
            DurableRunnerCommand::new(
                published.command().clone(),
                CommandSequence::new(7).expect("sequence"),
                true,
            ),
        )))
    }
}

#[derive(Debug)]
struct SupersededLeaseOffers;

#[async_trait]
impl RunnerLeaseOfferRepository for SupersededLeaseOffers {
    async fn inspect_lease_offer_claim(
        &self,
        _request: LeaseOfferClaim,
    ) -> Result<LeaseOfferClaimStatus, StoreError> {
        Ok(LeaseOfferClaimStatus::ClaimSuperseded)
    }

    async fn publish_lease_offer(
        &self,
        request: PublishLeaseOffer,
    ) -> Result<PublishedLeaseOffer, StoreError> {
        Err(StoreError::AttemptFenceRejected(
            request.lease().attempt_id(),
        ))
    }

    async fn resolve_lease_offer_command(
        &self,
        _identity: LeaseOfferCommandIdentity,
    ) -> Result<Option<PublishedLeaseOffer>, StoreError> {
        Ok(None)
    }
}

#[derive(Clone, Copy, Debug)]
enum LeaseOfferFailure {
    Draining,
    Conflict,
}

#[derive(Debug)]
struct FailingLeaseOffers {
    failure: LeaseOfferFailure,
    inspections: AtomicUsize,
    publications: AtomicUsize,
}

impl FailingLeaseOffers {
    const fn new(failure: LeaseOfferFailure) -> Self {
        Self {
            failure,
            inspections: AtomicUsize::new(0),
            publications: AtomicUsize::new(0),
        }
    }

    fn error(&self, request: &LeaseOfferClaim) -> StoreError {
        match self.failure {
            LeaseOfferFailure::Draining => {
                StoreError::RunnerNotAcceptingWork(request.request().session().runner_id())
            }
            LeaseOfferFailure::Conflict => StoreError::OperationConflict {
                session_id: request.request().session().session_id(),
                operation_id: request.request().operation_id(),
            },
        }
    }
}

#[async_trait]
impl RunnerLeaseOfferRepository for FailingLeaseOffers {
    async fn inspect_lease_offer_claim(
        &self,
        request: LeaseOfferClaim,
    ) -> Result<LeaseOfferClaimStatus, StoreError> {
        self.inspections.fetch_add(1, Ordering::SeqCst);
        Err(self.error(&request))
    }

    async fn publish_lease_offer(
        &self,
        request: PublishLeaseOffer,
    ) -> Result<PublishedLeaseOffer, StoreError> {
        self.publications.fetch_add(1, Ordering::SeqCst);
        Err(self.error(request.claim()))
    }

    async fn resolve_lease_offer_command(
        &self,
        identity: LeaseOfferCommandIdentity,
    ) -> Result<Option<PublishedLeaseOffer>, StoreError> {
        Err(match self.failure {
            LeaseOfferFailure::Draining => {
                StoreError::RunnerNotAcceptingWork(identity.session().runner_id())
            }
            LeaseOfferFailure::Conflict => StoreError::OperationConflict {
                session_id: identity.session().session_id(),
                operation_id: identity.operation_id(),
            },
        })
    }
}

#[derive(Debug)]
struct MismatchedPublishedLeaseOffer {
    job: JobIrEnvelope,
    lease: Lease,
    runtime_authorities: JobRuntimeAuthorities,
    slot: u16,
    extra_field: bool,
    nested_extra_field: bool,
}

#[async_trait]
impl RunnerLeaseOfferRepository for MismatchedPublishedLeaseOffer {
    async fn inspect_lease_offer_claim(
        &self,
        request: LeaseOfferClaim,
    ) -> Result<LeaseOfferClaimStatus, StoreError> {
        let mut payload = serde_json::json!({
            "job": self.job,
            "lease": self.lease,
            "protocol_version": request.protocol_version().get(),
            "runtime_authorities": self.runtime_authorities,
            "schema": 2,
            "slot": self.slot,
        });
        if self.extra_field {
            payload["unexpected"] = serde_json::json!(true);
        }
        if self.nested_extra_field {
            payload["lease"]["unexpected"] = serde_json::json!(true);
        }
        let payload = serde_json::to_vec(&payload).expect("offer payload");
        let command = EnqueueRunnerCommand::new(
            request.request().session(),
            OperationId::new(),
            RunnerOperationKind::new("automata.runner.lease-offer.v2").expect("command kind"),
            RunnerCommandPayload::new(DocumentSchema::new(2).expect("schema"), payload)
                .expect("command payload"),
            UnixMillis::new(20),
        );
        Ok(LeaseOfferClaimStatus::Published(Box::new(
            PublishedLeaseOffer::new(
                request.request().clone(),
                request.protocol_version(),
                request.slot(),
                request.lease().clone(),
                request.job_ir().clone(),
                DurableRunnerCommand::new(
                    command,
                    CommandSequence::new(7).expect("sequence"),
                    true,
                ),
            ),
        )))
    }

    async fn publish_lease_offer(
        &self,
        _request: PublishLeaseOffer,
    ) -> Result<PublishedLeaseOffer, StoreError> {
        panic!("publication is not expected")
    }

    async fn resolve_lease_offer_command(
        &self,
        _identity: LeaseOfferCommandIdentity,
    ) -> Result<Option<PublishedLeaseOffer>, StoreError> {
        Ok(None)
    }
}

#[derive(Debug)]
struct CurrentSessions {
    captured: Mutex<Vec<CurrentRunnerSession>>,
    result: Option<RunnerSessionFence>,
}

#[async_trait]
impl CurrentRunnerSessionRepository for CurrentSessions {
    async fn resolve_current_session(
        &self,
        request: CurrentRunnerSession,
    ) -> Result<Option<RunnerSessionFence>, StoreError> {
        self.captured
            .lock()
            .expect("captured lookups")
            .push(request);
        Ok(self.result)
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn durable_offer_adapter_publishes_exact_typed_body_and_identity() {
    let runner_id = RunnerId::new();
    let fence = RunnerSessionFence::new(
        RunnerSessionId::new(),
        runner_id,
        RunnerGeneration::new(3).expect("generation"),
        SessionEpoch::new(4).expect("epoch"),
    );
    let job = job();
    let encoded = encode_job_ir(&job, &ProtocolLimits::default()).expect("JobIR");
    let metadata = JobIrMetadata::new(
        job.job().job_id(),
        job.job().run_id(),
        job.version(),
        u64::try_from(encoded.len()).expect("size"),
        Sha256Digest::from_bytes(Sha256::digest(encoded).into()),
        ObjectKey::new("job-ir/adapter.pb").expect("key"),
    )
    .expect("metadata");
    let lease = Lease::new(
        LeaseId::new(),
        AttemptId::new(),
        runner_id,
        FencingToken::new(5).expect("fence"),
        UnixMillis::new(10),
        UnixMillis::new(100),
    )
    .expect("lease");
    let runner_operation_id = OperationId::new();
    let server_operation_id = OperationId::new();
    let digest = Sha256Digest::from_bytes([9; 32]);
    let runtime_authorities = runtime_authorities(&job, &lease);
    let repository = Arc::new(LeaseOffers::default());
    let publisher = StoreLeaseOfferCommandPublisher::new(
        repository.clone(),
        Arc::new(FixedIds {
            operation_id: server_operation_id,
            session_id: RunnerSessionId::new(),
        }),
    );
    let claim = ControlLeaseOfferClaim::new(
        fence,
        runner_operation_id,
        digest,
        ProtocolVersion::new(1).expect("protocol"),
        RunnerSlotOrdinal::new(2).expect("slot"),
        lease.clone(),
        metadata.clone(),
    );
    assert_eq!(
        publisher.inspect(claim.clone()).await.expect("inspection"),
        ControlLeaseOfferClaimStatus::Current
    );
    let publication = publisher
        .publish(LeaseOfferCommand::new(
            fence,
            runner_operation_id,
            digest,
            ProtocolVersion::new(1).expect("protocol"),
            RunnerSlotOrdinal::new(2).expect("slot"),
            lease.clone(),
            metadata.clone(),
            job.clone(),
            runtime_authorities.clone(),
            UnixMillis::new(20),
        ))
        .await
        .expect("publication");
    let LeaseOfferPublishOutcome::Published(durable_identity) = publication else {
        panic!("current claim must publish");
    };
    assert_eq!(durable_identity.operation_id(), server_operation_id);
    assert_eq!(durable_identity.sequence().get(), 7);
    let resolved = publisher
        .resolve_replay(
            fence,
            server_operation_id,
            automata_protocol::CommandSequence::new(7).expect("sequence"),
        )
        .await
        .expect("replay resolution")
        .expect("typed publication");
    assert_eq!(resolved.request().operation_id(), server_operation_id);
    assert_eq!(resolved.sequence().get(), 7);
    assert!(resolved.was_replayed());
    assert!(
        publisher
            .resolve_replay(
                fence,
                OperationId::new(),
                automata_protocol::CommandSequence::new(8).expect("sequence"),
            )
            .await
            .expect("missing replay resolution")
            .is_none()
    );
    let captured_publication = repository
        .captured
        .lock()
        .expect("captured offers")
        .first()
        .expect("publication")
        .clone();
    *repository
        .resolved_override
        .lock()
        .expect("resolved override") = Some(PublishedLeaseOffer::new(
        captured_publication.request().clone(),
        captured_publication.protocol_version(),
        captured_publication.slot(),
        captured_publication.lease().clone(),
        captured_publication.job_ir().clone(),
        DurableRunnerCommand::new(
            EnqueueRunnerCommand::new(
                fence,
                server_operation_id,
                RunnerOperationKind::new(CANCEL_JOB_COMMAND_KIND).expect("cancel kind"),
                RunnerCommandPayload::new(
                    DocumentSchema::new(1).expect("schema"),
                    b"validly shaped alternate command body".to_vec(),
                )
                .expect("alternate payload"),
                UnixMillis::new(20),
            ),
            CommandSequence::new(7).expect("sequence"),
            true,
        ),
    ));
    assert_eq!(
        publisher
            .resolve_replay(
                fence,
                server_operation_id,
                automata_protocol::CommandSequence::new(7).expect("sequence"),
            )
            .await
            .expect_err("publication-linked cancellation must fail closed"),
        ControlPortError::Corrupt
    );
    *repository
        .resolved_override
        .lock()
        .expect("resolved override") = None;
    let ControlLeaseOfferClaimStatus::Published(replayed) =
        publisher.inspect(claim).await.expect("recovery inspection")
    else {
        panic!("published command must be recovered");
    };
    assert_eq!(replayed.request().operation_id(), server_operation_id);
    assert_eq!(replayed.sequence().get(), 7);
    assert!(replayed.was_replayed());

    {
        let captured = repository.captured.lock().expect("captured offers");
        let request = captured.first().expect("one offer");
        assert_eq!(captured.len(), 1);
        assert_eq!(request.request().session(), fence);
        assert_eq!(request.request().operation_id(), runner_operation_id);
        assert_eq!(request.request().request_digest(), digest);
        assert_eq!(
            request.request().kind().as_str(),
            "automata.runner.lease-request.v1"
        );
        assert_eq!(request.protocol_version().get(), 1);
        assert_eq!(request.slot().get(), 2);
        assert_eq!(request.lease(), &lease);
        assert_eq!(request.job_ir(), &metadata);
        assert!(!format!("{request:?}").contains("fixture-results-token"));
        assert_eq!(request.command().operation_id(), server_operation_id);
        assert_eq!(
            request.command().kind().as_str(),
            "automata.runner.lease-offer.v2"
        );
        let body: serde_json::Value =
            serde_json::from_slice(request.command().payload().bytes()).expect("offer JSON");
        assert_eq!(body["schema"], 2);
        assert_eq!(body["protocol_version"], 1);
        assert_eq!(body["slot"], 2);
        assert_eq!(
            body["lease"],
            serde_json::to_value(&lease).expect("lease JSON")
        );
        assert_eq!(body["job"], serde_json::to_value(&job).expect("job JSON"));
        assert_eq!(
            body["runtime_authorities"],
            serde_json::to_value(&runtime_authorities).expect("runtime authorities JSON")
        );
    }

    let superseded = StoreLeaseOfferCommandPublisher::new(
        Arc::new(SupersededLeaseOffers),
        Arc::new(FixedIds {
            operation_id: OperationId::new(),
            session_id: RunnerSessionId::new(),
        }),
    );
    assert_eq!(
        superseded
            .inspect(ControlLeaseOfferClaim::new(
                fence,
                runner_operation_id,
                digest,
                ProtocolVersion::new(1).expect("protocol"),
                RunnerSlotOrdinal::new(2).expect("slot"),
                lease.clone(),
                metadata.clone(),
            ))
            .await
            .expect("superseded inspection"),
        ControlLeaseOfferClaimStatus::ClaimSuperseded
    );
    assert_eq!(
        superseded
            .publish(LeaseOfferCommand::new(
                fence,
                runner_operation_id,
                digest,
                ProtocolVersion::new(1).expect("protocol"),
                RunnerSlotOrdinal::new(2).expect("slot"),
                lease,
                metadata,
                job,
                runtime_authorities,
                UnixMillis::new(21),
            ))
            .await
            .expect("superseded publication"),
        LeaseOfferPublishOutcome::ClaimSuperseded
    );
}

#[tokio::test]
async fn lease_offer_adapter_maps_only_draining_races_to_unavailable() {
    let runner_id = RunnerId::new();
    let fence = RunnerSessionFence::new(
        RunnerSessionId::new(),
        runner_id,
        RunnerGeneration::new(3).expect("generation"),
        SessionEpoch::new(4).expect("epoch"),
    );
    let job = job();
    let encoded = encode_job_ir(&job, &ProtocolLimits::default()).expect("JobIR");
    let metadata = JobIrMetadata::new(
        job.job().job_id(),
        job.job().run_id(),
        job.version(),
        u64::try_from(encoded.len()).expect("size"),
        Sha256Digest::from_bytes(Sha256::digest(encoded).into()),
        ObjectKey::new("job-ir/draining-adapter.pb").expect("key"),
    )
    .expect("metadata");
    let lease = Lease::new(
        LeaseId::new(),
        AttemptId::new(),
        runner_id,
        FencingToken::new(5).expect("fence"),
        UnixMillis::new(10),
        UnixMillis::new(100),
    )
    .expect("lease");
    let request_operation_id = OperationId::new();
    let digest = Sha256Digest::from_bytes([9; 32]);
    let claim = ControlLeaseOfferClaim::new(
        fence,
        request_operation_id,
        digest,
        ProtocolVersion::new(1).expect("protocol"),
        RunnerSlotOrdinal::new(2).expect("slot"),
        lease.clone(),
        metadata.clone(),
    );
    let command = LeaseOfferCommand::new(
        fence,
        request_operation_id,
        digest,
        ProtocolVersion::new(1).expect("protocol"),
        RunnerSlotOrdinal::new(2).expect("slot"),
        lease.clone(),
        metadata,
        job.clone(),
        runtime_authorities(&job, &lease),
        UnixMillis::new(20),
    );

    for (failure, expected) in [
        (LeaseOfferFailure::Draining, ControlPortError::Unavailable),
        (LeaseOfferFailure::Conflict, ControlPortError::Conflict),
    ] {
        let repository = Arc::new(FailingLeaseOffers::new(failure));
        let publisher = StoreLeaseOfferCommandPublisher::new(
            repository.clone(),
            Arc::new(FixedIds {
                operation_id: OperationId::new(),
                session_id: RunnerSessionId::new(),
            }),
        );
        assert_eq!(
            publisher
                .inspect(claim.clone())
                .await
                .expect_err("inspection must preserve the mapped failure"),
            expected
        );
        assert_eq!(
            publisher
                .publish(command.clone())
                .await
                .expect_err("publication must preserve the mapped failure"),
            expected
        );
        assert_eq!(repository.inspections.load(Ordering::SeqCst), 1);
        assert_eq!(repository.publications.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn recovered_offer_payload_must_match_its_publication_columns() {
    let runner_id = RunnerId::new();
    let fence = RunnerSessionFence::new(
        RunnerSessionId::new(),
        runner_id,
        RunnerGeneration::new(3).expect("generation"),
        SessionEpoch::new(4).expect("epoch"),
    );
    let expected_job = job();
    let encoded = encode_job_ir(&expected_job, &ProtocolLimits::default()).expect("JobIR");
    let metadata = JobIrMetadata::new(
        expected_job.job().job_id(),
        expected_job.job().run_id(),
        expected_job.version(),
        u64::try_from(encoded.len()).expect("size"),
        Sha256Digest::from_bytes(Sha256::digest(encoded).into()),
        ObjectKey::new("job-ir/recovered-adapter.pb").expect("key"),
    )
    .expect("metadata");
    let lease = Lease::new(
        LeaseId::new(),
        AttemptId::new(),
        runner_id,
        FencingToken::new(5).expect("fence"),
        UnixMillis::new(10),
        UnixMillis::new(100),
    )
    .expect("lease");
    let claim = ControlLeaseOfferClaim::new(
        fence,
        OperationId::new(),
        Sha256Digest::from_bytes([9; 32]),
        ProtocolVersion::new(1).expect("protocol"),
        RunnerSlotOrdinal::new(2).expect("slot"),
        lease.clone(),
        metadata,
    );
    let mismatched_job = job();
    let same_identity_mismatched_job = JobIrEnvelope::new(
        expected_job.workflow_id(),
        expected_job.source().clone(),
        expected_job.execution().clone(),
        JobIr::new(
            expected_job.job().job_id(),
            expected_job.job().run_id(),
            "adapter-with-corrupt-body",
            RunnerRequirements::default(),
            vec![StepIr::new(
                StepId::new("test").expect("step"),
                "Test",
                SemanticStep::run("cargo test --workspace", ShellSpec::Default),
            )],
        ),
    );
    let mismatched_lease = Lease::new(
        LeaseId::new(),
        AttemptId::new(),
        runner_id,
        FencingToken::new(6).expect("fence"),
        UnixMillis::new(11),
        UnixMillis::new(101),
    )
    .expect("mismatched lease");
    for repository in [
        MismatchedPublishedLeaseOffer {
            job: expected_job.clone(),
            lease: lease.clone(),
            runtime_authorities: runtime_authorities(&expected_job, &lease),
            slot: 3,
            extra_field: false,
            nested_extra_field: false,
        },
        MismatchedPublishedLeaseOffer {
            runtime_authorities: runtime_authorities(&mismatched_job, &lease),
            job: mismatched_job,
            lease: lease.clone(),
            slot: 2,
            extra_field: false,
            nested_extra_field: false,
        },
        MismatchedPublishedLeaseOffer {
            runtime_authorities: runtime_authorities(&same_identity_mismatched_job, &lease),
            job: same_identity_mismatched_job,
            lease: lease.clone(),
            slot: 2,
            extra_field: false,
            nested_extra_field: false,
        },
        MismatchedPublishedLeaseOffer {
            job: expected_job.clone(),
            lease: mismatched_lease.clone(),
            runtime_authorities: runtime_authorities(&expected_job, &mismatched_lease),
            slot: 2,
            extra_field: false,
            nested_extra_field: false,
        },
        MismatchedPublishedLeaseOffer {
            job: expected_job.clone(),
            lease: lease.clone(),
            runtime_authorities: runtime_authorities(&expected_job, &lease),
            slot: 2,
            extra_field: true,
            nested_extra_field: false,
        },
        MismatchedPublishedLeaseOffer {
            job: expected_job.clone(),
            lease: lease.clone(),
            runtime_authorities: runtime_authorities(&expected_job, &lease),
            slot: 2,
            extra_field: false,
            nested_extra_field: true,
        },
    ] {
        let publisher = StoreLeaseOfferCommandPublisher::new(
            Arc::new(repository),
            Arc::new(FixedIds {
                operation_id: OperationId::new(),
                session_id: RunnerSessionId::new(),
            }),
        );
        assert_eq!(
            publisher
                .inspect(claim.clone())
                .await
                .expect_err("mismatched durable offer must fail closed"),
            ControlPortError::Corrupt
        );
    }
}

#[tokio::test]
async fn durable_session_resolver_forwards_exact_server_owned_identity() {
    let fence = RunnerSessionFence::new(
        RunnerSessionId::new(),
        RunnerId::new(),
        RunnerGeneration::new(8).expect("generation"),
        SessionEpoch::new(9).expect("epoch"),
    );
    let repository = Arc::new(CurrentSessions {
        captured: Mutex::new(Vec::new()),
        result: Some(fence),
    });
    let resolver = StoreRunnerSessionFenceResolver::new(repository.clone());
    assert_eq!(
        resolver
            .resolve_current(
                fence.runner_id(),
                fence.runner_generation(),
                fence.session_id(),
            )
            .await
            .expect("lookup"),
        Some(fence)
    );
    let captured = repository.captured.lock().expect("captured lookups");
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].runner_id(), fence.runner_id());
    assert_eq!(captured[0].generation(), fence.runner_generation());
    assert_eq!(captured[0].session_id(), fence.session_id());
}

fn job() -> JobIrEnvelope {
    JobIrEnvelope::new(
        WorkflowId::new(),
        JobSource::new(
            "github",
            "GoNeuralAI/automata",
            "0123456789abcdef",
            ".github/workflows/ci.yml",
            "push",
        ),
        automata_core::JobExecutionContext::new(
            "CI",
            "refs/heads/main",
            "/__w/automata/automata",
            automata_core::JobContentReference::new(
                "events/push.json",
                automata_core::Sha256Digest::from_bytes([0x42; 32]),
                2,
                "application/json",
            ),
        ),
        JobIr::new(
            JobId::new(),
            RunId::new(),
            "adapter",
            RunnerRequirements::default(),
            vec![StepIr::new(
                StepId::new("test").expect("step"),
                "Test",
                SemanticStep::run("cargo test", ShellSpec::Default),
            )],
        ),
    )
}

fn runtime_authorities(job: &JobIrEnvelope, lease: &Lease) -> JobRuntimeAuthorities {
    let authority = JobRuntimeAuthority::new(
        RuntimeAuthorityName::new("github-actions-results").expect("authority name"),
        job.job().run_id(),
        job.job().job_id(),
        lease.attempt_id(),
        lease.fencing_token(),
        RuntimeAuthorityEndpoint::new("https://results.example.test/").expect("authority endpoint"),
        RuntimeAuthorityCredential::new("fixture-results-token").expect("authority token"),
        UnixMillis::new(10),
        UnixMillis::new(100),
    )
    .expect("runtime authority");
    JobRuntimeAuthorities::new(vec![authority], job, lease).expect("runtime authority bundle")
}
