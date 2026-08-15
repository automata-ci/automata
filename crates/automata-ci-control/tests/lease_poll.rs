use std::{sync::Mutex, time::Duration};

use async_trait::async_trait;
use automata_ci_control::lease::{
    AuthenticatedPlacementTrust, AuthenticatedRunnerSession, ClaimedAttempt, LeaseClock,
    LeaseIdGenerator, LeasePollConfig, LeasePollObservation, LeasePollObserver, LeasePollOutcome,
    LeasePollRepository, LeasePollService, LeaseRequestKey, LeaseTimeToLive, NoWorkLeaseRequest,
    RunnableAttempt, RunnableAttemptError, RunnableAttemptGate, RunnableAttemptGateDisposition,
    RunnableScanLimit, RunnableScanPage, RunnableScanRequest, TryClaimAttempt, TryClaimOutcome,
    TryClaimReceipt, WindowsHyperVPlacementGrant,
    repository::{RunnableAttemptRepository, RunnerClaimRepository},
    routing::{
        RunnerGroupId, RunnerRoutingRepository, RunnerRoutingSnapshot, RunnerSlotAvailability,
        RunnerSlotAvailabilityRepository,
    },
};
use automata_ci_control::scheduling::DeterministicScheduler;
use automata_ci_core::{
    Architecture, AttemptId, ContainerCapabilities, ContainerFeature, EnvironmentProfile,
    EnvironmentProfileId, FencingToken, JobAuthorityProfile, JobId, JobIrVersion, Lease, LeaseId,
    OperatingSystem, OperationId, ResourceCapacity, RunId, RunnerCapabilities, RunnerFeature,
    RunnerGroup, RunnerId, RunnerLabel, RunnerPlatform, RunnerRequirements, RunnerSessionId,
    SandboxCapabilities, SandboxFeature, Sha256Digest, TrustActorEvidence, TrustActorKind,
    TrustAutomationKind, TrustEventKind, TrustEvidence, TrustOriginKind, TrustPolicy,
    TrustRepositoryEvidence, TrustSnapshot, TrustTokenRecursion, UnixMillis,
};
use automata_ci_protocol::{LeaseRequest, MessageHeader, PROTOCOL_MAX_VERSION, RunnerSlotOrdinal};
use automata_ci_store::{
    AttemptAssignment, JobIrMetadata, ObjectKey, RoutingDocument, RoutingLabel, RunnerGeneration,
    RunnerSessionFence, RunnerSlotCount, SessionEpoch, StableRunnerSlot, StoreError,
};

#[derive(Debug)]
struct FixedClock(UnixMillis);

impl LeaseClock for FixedClock {
    fn now(&self) -> UnixMillis {
        self.0
    }
}

#[derive(Debug)]
struct FixedLeaseIds(LeaseId);

impl LeaseIdGenerator for FixedLeaseIds {
    fn next_lease_id(&self) -> LeaseId {
        self.0
    }
}

#[derive(Debug, Default)]
struct RecordingObserver {
    polls: Mutex<Vec<LeasePollObservation>>,
    candidates: Mutex<Vec<usize>>,
    queue_waits: Mutex<Vec<Duration>>,
}

impl LeasePollObserver for RecordingObserver {
    fn observe_poll(&self, outcome: LeasePollObservation, _duration: Duration) {
        self.polls.lock().expect("poll observations").push(outcome);
    }

    fn observe_candidates(&self, count: usize) {
        self.candidates
            .lock()
            .expect("candidate observations")
            .push(count);
    }

    fn observe_queue_wait(&self, duration: Duration) {
        self.queue_waits
            .lock()
            .expect("queue-wait observations")
            .push(duration);
    }
}

#[derive(Debug)]
struct IneligibleAttemptGate {
    ineligible: AttemptId,
    evaluations: Mutex<Vec<(AttemptId, UnixMillis)>>,
}

#[async_trait]
impl RunnableAttemptGate for IneligibleAttemptGate {
    async fn evaluate(
        &self,
        attempt_id: AttemptId,
        observed_at: UnixMillis,
    ) -> Result<RunnableAttemptGateDisposition, StoreError> {
        self.evaluations
            .lock()
            .expect("gate evaluations")
            .push((attempt_id, observed_at));
        Ok(if attempt_id == self.ineligible {
            RunnableAttemptGateDisposition::Ineligible
        } else {
            RunnableAttemptGateDisposition::Ready
        })
    }
}

#[derive(Debug)]
struct FakeRepository {
    calls: Mutex<Vec<&'static str>>,
    lease_keys: Mutex<Vec<LeaseRequestKey>>,
    lookup: Option<TryClaimReceipt>,
    routing: RunnerRoutingSnapshot,
    availability: RunnerSlotAvailability,
    candidates: Vec<RunnableAttempt>,
    metadata: JobIrMetadata,
    windows_grants: Mutex<Vec<Option<WindowsHyperVPlacementGrant>>>,
}

impl FakeRepository {
    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().expect("call log lock").clone()
    }

    fn called(&self, name: &'static str) {
        self.calls.lock().expect("call log lock").push(name);
    }
}

#[async_trait]
impl RunnerClaimRepository for FakeRepository {
    async fn lookup_lease_request(
        &self,
        request: LeaseRequestKey,
    ) -> Result<Option<TryClaimReceipt>, StoreError> {
        self.called("lookup");
        self.lease_keys
            .lock()
            .expect("lease key lock")
            .push(request);
        Ok(self.lookup.clone())
    }

    async fn try_claim(&self, request: TryClaimAttempt) -> Result<TryClaimReceipt, StoreError> {
        self.called("claim");
        self.windows_grants
            .lock()
            .expect("Windows grant observations")
            .push(request.windows_placement_grant().cloned());
        let lease = Lease::new(
            request.lease_id(),
            request.attempt_id(),
            request.session().runner_id(),
            FencingToken::new(1).expect("fence"),
            request.observed_at(),
            request.expires_at(),
        )
        .expect("fake claim interval");
        let claimed = ClaimedAttempt::try_new(
            lease,
            AttemptAssignment::new(request.session(), request.slot()),
            self.metadata.clone(),
        )
        .expect("fake assignment");
        Ok(TryClaimReceipt::new(
            request.request_key(),
            TryClaimOutcome::Claimed(Box::new(claimed)),
            false,
        ))
    }

    async fn record_no_work(
        &self,
        request: NoWorkLeaseRequest,
    ) -> Result<TryClaimReceipt, StoreError> {
        self.called("no_work");
        Ok(TryClaimReceipt::new(
            request.request_key(),
            TryClaimOutcome::NoWork,
            false,
        ))
    }
}

#[async_trait]
impl RunnerRoutingRepository for FakeRepository {
    async fn routing_for_session(
        &self,
        _fence: RunnerSessionFence,
    ) -> Result<RunnerRoutingSnapshot, StoreError> {
        self.called("routing");
        Ok(self.routing.clone())
    }
}

#[async_trait]
impl RunnerSlotAvailabilityRepository for FakeRepository {
    async fn slot_availability(
        &self,
        _fence: RunnerSessionFence,
        _slot: StableRunnerSlot,
        _observed_at: UnixMillis,
    ) -> Result<RunnerSlotAvailability, StoreError> {
        self.called("availability");
        Ok(self.availability)
    }
}

#[async_trait]
impl RunnableAttemptRepository for FakeRepository {
    async fn scan_runnable(
        &self,
        request: RunnableScanRequest,
    ) -> Result<RunnableScanPage, StoreError> {
        self.called("scan");
        let upper = self.candidates.last().map(RunnableAttempt::queue_key);
        RunnableScanPage::try_new(
            request.session(),
            request.slot(),
            Sha256Digest::from_bytes([41; 32]),
            0,
            upper,
            self.candidates.clone(),
        )
        .map_err(|error| StoreError::corrupt_data(error.to_string()))
    }
}

struct Fixture {
    repository: FakeRepository,
    authenticated: AuthenticatedRunnerSession,
    request: LeaseRequest,
    expected_attempt: AttemptId,
    lease_id: LeaseId,
    clock: FixedClock,
    lease_ids: FixedLeaseIds,
    scheduler: DeterministicScheduler,
}

#[allow(clippy::too_many_lines)]
fn fixture(availability: RunnerSlotAvailability, with_candidates: bool) -> Fixture {
    let runner_id = RunnerId::new();
    let fence = RunnerSessionFence::new(
        RunnerSessionId::new(),
        runner_id,
        RunnerGeneration::new(1).expect("generation"),
        SessionEpoch::new(1).expect("epoch"),
    );
    let platform = RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64);
    let registered = RunnerCapabilities::new(runner_id, platform.clone())
        .with_max_parallel_jobs(2)
        .expect("slots")
        .with_resources_per_job(ResourceCapacity::new(4_000, 8_000, 10_000, 1))
        .with_sandbox(SandboxCapabilities::new(
            automata_ci_core::IsolationLevel::SharedKernel,
            [
                SandboxFeature::CLEAN_WORKSPACE,
                SandboxFeature::NETWORK_ISOLATION,
            ],
        ))
        .with_containers(ContainerCapabilities::new([
            ContainerFeature::JOB_CONTAINERS,
            ContainerFeature::CONTAINER_ACTIONS,
        ]))
        .with_features([RunnerFeature::SHELL_STEPS, RunnerFeature::COMPOSITE_ACTIONS])
        .with_labels([RunnerLabel::new("self-promoted").expect("label")])
        .with_groups([RunnerGroup::new("self-group").expect("group")]);
    let negotiated = RunnerCapabilities::new(runner_id, platform)
        .with_max_parallel_jobs(2)
        .expect("slots")
        .with_resources_per_job(ResourceCapacity::new(2_000, 4_000, 5_000, 0))
        .with_sandbox(SandboxCapabilities::new(
            automata_ci_core::IsolationLevel::Process,
            [SandboxFeature::CLEAN_WORKSPACE],
        ))
        .with_containers(ContainerCapabilities::new([
            ContainerFeature::JOB_CONTAINERS,
        ]))
        .with_features([RunnerFeature::SHELL_STEPS, RunnerFeature::OIDC_TOKENS])
        .with_labels([RunnerLabel::new("self-promoted").expect("label")])
        .with_groups([RunnerGroup::new("self-group").expect("group")]);
    let routing = RunnerRoutingSnapshot::try_new(
        fence,
        Some((
            RunnerGroupId::from_uuid(runner_id.as_uuid()),
            "trusted-group".into(),
        )),
        [RoutingLabel::new("trusted").expect("routing label")],
        capability_document(&registered),
        capability_document(&negotiated),
        RunnerSlotCount::new(2).expect("slot count"),
        JobIrVersion::current(),
    )
    .expect("routing snapshot");

    let run_id = RunId::new();
    let rejected_self = runnable(
        run_id,
        10,
        ["self-promoted"],
        Some("self-group"),
        RunnerRequirements::default(),
    );
    let rejected_observed_extra = runnable(
        run_id,
        20,
        ["trusted"],
        Some("trusted-group"),
        RunnerRequirements::default().with_features([RunnerFeature::OIDC_TOKENS]),
    );
    let rejected_registered_extra = runnable(
        run_id,
        30,
        ["trusted"],
        Some("trusted-group"),
        RunnerRequirements::default().with_features([RunnerFeature::COMPOSITE_ACTIONS]),
    );
    let expected = runnable(
        run_id,
        40,
        ["trusted"],
        Some("trusted-group"),
        RunnerRequirements::default().with_features([RunnerFeature::SHELL_STEPS]),
    );
    let expected_attempt = expected.attempt_id();
    let metadata = expected.job_ir().clone();
    let candidates = if with_candidates {
        vec![
            rejected_self,
            rejected_observed_extra,
            rejected_registered_extra,
            expected,
        ]
    } else {
        Vec::new()
    };
    let operation_id = OperationId::new();
    let request = LeaseRequest::first(
        MessageHeader::request(PROTOCOL_MAX_VERSION, fence.session_id(), operation_id),
        RunnerSlotOrdinal::new(1).expect("slot"),
    );
    let lease_id = LeaseId::new();
    Fixture {
        repository: FakeRepository {
            calls: Mutex::new(Vec::new()),
            lease_keys: Mutex::new(Vec::new()),
            lookup: None,
            routing,
            availability,
            candidates,
            metadata,
            windows_grants: Mutex::new(Vec::new()),
        },
        authenticated: AuthenticatedRunnerSession::new(
            fence,
            PROTOCOL_MAX_VERSION,
            JobIrVersion::current(),
        ),
        request,
        expected_attempt,
        lease_id,
        clock: FixedClock(UnixMillis::new(1_000)),
        lease_ids: FixedLeaseIds(lease_id),
        scheduler: DeterministicScheduler,
    }
}

fn runnable<const N: usize>(
    run_id: RunId,
    queued_at: i64,
    labels: [&str; N],
    group: Option<&str>,
    requirements: RunnerRequirements,
) -> RunnableAttempt {
    let attempt_id = AttemptId::new();
    let job_id = JobId::new();
    let metadata = JobIrMetadata::new(
        job_id,
        run_id,
        JobIrVersion::current(),
        128,
        Sha256Digest::from_bytes([u8::try_from(queued_at).expect("small queue time"); 32]),
        ObjectKey::new(format!("jobs/{job_id}")).expect("object key"),
    )
    .expect("metadata");
    let requirements = requirements
        .with_labels(
            labels
                .into_iter()
                .map(|label| RunnerLabel::new(label).expect("runner label")),
        )
        .with_eligible_groups(
            group
                .into_iter()
                .map(|group| RunnerGroup::new(group).expect("runner group")),
        );
    RunnableAttempt::try_new(
        attempt_id,
        job_id,
        run_id,
        UnixMillis::new(queued_at),
        requirements,
        metadata,
        None,
    )
    .expect("runnable")
}

fn trusted_snapshot(actor: &str) -> TrustSnapshot {
    TrustPolicy::current()
        .evaluate(
            TrustEvidence::new(TrustOriginKind::ProviderWebhook, TrustEventKind::Push)
                .with_original_actor(
                    TrustActorEvidence::new(actor, TrustActorKind::User, TrustAutomationKind::None)
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

fn windows_fixture(with_trust: bool) -> Fixture {
    let mut fixture = fixture(RunnerSlotAvailability::Available, false);
    let fence = fixture.authenticated.fence();
    let profile = EnvironmentProfile::new(
        EnvironmentProfileId::new("automata.test/windows-2025").expect("profile ID"),
        Sha256Digest::from_bytes([0x25; 32]),
    );
    let capabilities = RunnerCapabilities::new(
        fence.runner_id(),
        RunnerPlatform::new(OperatingSystem::Windows, Architecture::X86_64),
    )
    .with_max_parallel_jobs(1)
    .expect("single Windows slot")
    .with_sandbox(SandboxCapabilities::new(
        automata_ci_core::IsolationLevel::VirtualMachine,
        [
            SandboxFeature::CLEAN_WORKSPACE,
            SandboxFeature::NETWORK_ISOLATION,
            SandboxFeature::WINDOWS_HYPERV_CONTAINER,
        ],
    ))
    .with_environment_profiles([profile.clone()])
    .with_features([RunnerFeature::SHELL_STEPS]);
    fixture.repository.routing = RunnerRoutingSnapshot::try_new(
        fence,
        Some((
            RunnerGroupId::from_uuid(fence.runner_id().as_uuid()),
            "trusted-group".into(),
        )),
        [RoutingLabel::new("trusted").expect("routing label")],
        capability_document(&capabilities),
        capability_document(&capabilities),
        RunnerSlotCount::new(1).expect("slot count"),
        JobIrVersion::current(),
    )
    .expect("Windows routing snapshot");
    let run_id = RunId::new();
    let attempt_id = AttemptId::new();
    let job_id = JobId::new();
    let metadata = JobIrMetadata::new(
        job_id,
        run_id,
        JobIrVersion::current(),
        256,
        Sha256Digest::from_bytes([0x44; 32]),
        ObjectKey::new(format!("jobs/{job_id}")).expect("object key"),
    )
    .expect("metadata");
    let requirements = RunnerRequirements::default()
        .with_labels([RunnerLabel::new("trusted").expect("label")])
        .with_eligible_groups([RunnerGroup::new("trusted-group").expect("group")])
        .with_windows_hyperv_container()
        .with_architecture(Architecture::X86_64)
        .with_environment_profile(profile);
    let placement_trust = with_trust.then(|| {
        AuthenticatedPlacementTrust::try_new(
            &trusted_snapshot("actor-1"),
            JobAuthorityProfile::Standard,
            &requirements,
        )
        .expect("placement trust")
    });
    let candidate = RunnableAttempt::try_new(
        attempt_id,
        job_id,
        run_id,
        UnixMillis::new(40),
        requirements,
        metadata.clone(),
        placement_trust,
    )
    .expect("Windows candidate");
    fixture.expected_attempt = attempt_id;
    fixture.repository.metadata = metadata;
    fixture.repository.candidates = vec![candidate];
    fixture
}

fn capability_document(capabilities: &RunnerCapabilities) -> RoutingDocument {
    RoutingDocument::new(serde_json::to_string(capabilities).expect("capability JSON"))
        .expect("routing document")
}

fn windows_claim_request(
    fixture: &Fixture,
    candidate: &RunnableAttempt,
    operation_id: OperationId,
) -> TryClaimAttempt {
    let page = RunnableScanPage::try_new(
        fixture.authenticated.fence(),
        StableRunnerSlot::new(1).expect("slot"),
        Sha256Digest::from_bytes([0x52; 32]),
        0,
        Some(candidate.queue_key()),
        vec![candidate.clone()],
    )
    .expect("page");
    let request_key = LeaseRequestKey::first(
        fixture.authenticated.fence(),
        operation_id,
        StableRunnerSlot::new(1).expect("slot"),
    );
    TryClaimAttempt::for_candidate(
        request_key,
        candidate,
        fixture.lease_id,
        UnixMillis::new(1_000),
        UnixMillis::new(1_500),
        page.claim_advance(candidate.attempt_id())
            .expect("claim cursor"),
    )
    .expect("Windows claim")
}

fn service(fixture: &Fixture) -> LeasePollService<'_> {
    LeasePollService::new(
        &fixture.repository,
        &fixture.scheduler,
        &fixture.clock,
        &fixture.lease_ids,
        LeasePollConfig::new(
            RunnableScanLimit::new(10).expect("scan limit"),
            LeaseTimeToLive::from_millis(500).expect("lease TTL"),
        ),
    )
}

#[tokio::test]
async fn receipt_routing_capacity_scan_and_claim_are_ordered_and_least_authority() {
    let fixture = fixture(RunnerSlotAvailability::Available, true);

    let outcome = service(&fixture)
        .poll(fixture.authenticated, &fixture.request)
        .await
        .expect("poll succeeds");

    let LeasePollOutcome::Claimed(claimed) = outcome else {
        panic!("matching least-authority candidate should be claimed");
    };
    assert_eq!(claimed.lease().attempt_id(), fixture.expected_attempt);
    assert_eq!(claimed.lease().lease_id(), fixture.lease_id);
    assert_eq!(claimed.lease().issued_at(), UnixMillis::new(1_000));
    assert_eq!(claimed.lease().expires_at(), UnixMillis::new(1_500));
    assert_eq!(
        claimed.job_ir().job_id(),
        fixture.repository.metadata.job_id()
    );
    assert!(!claimed.was_replayed());
    assert_eq!(
        fixture.repository.calls(),
        ["lookup", "routing", "availability", "scan", "claim"]
    );
}

#[tokio::test]
async fn temporarily_no_eligible_runner_for_admitted_features_remains_no_work() {
    let mut fixture = fixture(RunnerSlotAvailability::Available, true);
    fixture.repository.candidates = vec![runnable(
        RunId::new(),
        50,
        ["trusted"],
        Some("trusted-group"),
        RunnerRequirements::default().with_features([
            RunnerFeature::REPOSITORY_ACTIONS,
            RunnerFeature::JAVASCRIPT_ACTIONS,
            RunnerFeature::NODE24_ACTIONS,
        ]),
    )];

    let outcome = service(&fixture)
        .poll(fixture.authenticated, &fixture.request)
        .await
        .expect("temporary runner-capability absence is a normal no-work result");

    assert_eq!(outcome, LeasePollOutcome::NoWork { replayed: false });
    assert_eq!(
        fixture.repository.calls(),
        ["lookup", "routing", "availability", "scan", "no_work"]
    );
}

#[tokio::test]
async fn windows_claim_carries_one_use_trust_profile_and_generation_binding() {
    let fixture = windows_fixture(true);

    let outcome = service(&fixture)
        .poll(fixture.authenticated, &fixture.request)
        .await
        .expect("authenticated Windows placement succeeds");

    let LeasePollOutcome::Claimed(claimed) = outcome else {
        panic!("authenticated exact-profile Windows work must be claimed");
    };
    let grants = fixture
        .repository
        .windows_grants
        .lock()
        .expect("Windows grant observations");
    let grant = grants[0].as_ref().expect("Windows placement grant");
    assert_eq!(grant.attempt_id(), claimed.lease().attempt_id());
    assert_eq!(
        grant.operation_id(),
        fixture.request.header().operation_id()
    );
    assert_eq!(grant.session(), fixture.authenticated.fence());
    assert_eq!(grant.lease_id(), fixture.lease_id);
    assert_eq!(grant.expires_at(), UnixMillis::new(1_500));
    assert_eq!(
        grant.environment_profile().id().as_str(),
        "automata.test/windows-2025"
    );
    assert_ne!(grant.binding_digest(), Sha256Digest::from_bytes([0; 32]));
}

#[tokio::test]
async fn windows_candidate_without_authenticated_trust_is_no_work_before_claim() {
    let fixture = windows_fixture(false);

    let outcome = service(&fixture)
        .poll(fixture.authenticated, &fixture.request)
        .await
        .expect("missing Windows trust is a fail-closed no-work result");

    assert_eq!(outcome, LeasePollOutcome::NoWork { replayed: false });
    assert_eq!(
        fixture.repository.calls(),
        ["lookup", "routing", "availability", "scan", "no_work"]
    );
    assert!(
        fixture
            .repository
            .windows_grants
            .lock()
            .expect("Windows grant observations")
            .is_empty()
    );
}

#[tokio::test]
async fn unavailable_service_container_requirement_never_creates_a_lease() {
    let mut fixture = fixture(RunnerSlotAvailability::Available, true);
    fixture.repository.candidates = vec![runnable(
        RunId::new(),
        50,
        ["trusted"],
        Some("trusted-group"),
        RunnerRequirements::default()
            .with_container_features([ContainerFeature::SERVICE_CONTAINERS]),
    )];

    let outcome = service(&fixture)
        .poll(fixture.authenticated, &fixture.request)
        .await
        .expect("unsupported service containers are a normal pre-lease no-work result");

    assert_eq!(outcome, LeasePollOutcome::NoWork { replayed: false });
    assert_eq!(
        fixture.repository.calls(),
        ["lookup", "routing", "availability", "scan", "no_work"]
    );
}

#[test]
fn windows_grant_changes_across_operations_and_trust_snapshots() {
    let fixture = windows_fixture(true);
    let candidate = &fixture.repository.candidates[0];
    let first = windows_claim_request(&fixture, candidate, OperationId::new());
    let second = windows_claim_request(&fixture, candidate, OperationId::new());
    assert_ne!(
        first
            .windows_placement_grant()
            .expect("first Windows grant")
            .binding_digest(),
        second
            .windows_placement_grant()
            .expect("second Windows grant")
            .binding_digest()
    );

    let changed_trust = AuthenticatedPlacementTrust::try_new(
        &trusted_snapshot("actor-2"),
        JobAuthorityProfile::Standard,
        candidate.requirements(),
    )
    .expect("changed placement trust");
    let changed_candidate = RunnableAttempt::try_new(
        candidate.attempt_id(),
        candidate.job_id(),
        candidate.run_id(),
        candidate.queued_at(),
        candidate.requirements().clone(),
        candidate.job_ir().clone(),
        Some(changed_trust),
    )
    .expect("changed candidate");
    let changed = windows_claim_request(&fixture, &changed_candidate, first.operation_id());
    assert_ne!(
        first
            .windows_placement_grant()
            .expect("first Windows grant")
            .binding_digest(),
        changed
            .windows_placement_grant()
            .expect("changed Windows grant")
            .binding_digest()
    );
    #[cfg(feature = "adapter-spi")]
    {
        assert!(
            automata_ci_control::adapter_spi::try_claim_attempt_matches_runnable(&first, candidate)
        );
        assert!(
            !automata_ci_control::adapter_spi::try_claim_attempt_matches_runnable(
                &first,
                &changed_candidate,
            )
        );
    }
}

#[test]
fn windows_candidate_rejects_stale_materialization_requirements() {
    let fixture = windows_fixture(true);
    let candidate = &fixture.repository.candidates[0];

    let error = RunnableAttempt::try_new(
        candidate.attempt_id(),
        candidate.job_id(),
        candidate.run_id(),
        candidate.queued_at(),
        candidate
            .requirements()
            .clone()
            .with_labels([RunnerLabel::new("changed-routing").expect("changed label")]),
        candidate.job_ir().clone(),
        candidate.placement_trust().cloned(),
    )
    .expect_err("stale materialization requirements must be rejected");

    assert_eq!(error, RunnableAttemptError::PlacementRequirementsMismatch);
}

#[tokio::test]
async fn ineligible_attempts_never_reach_scheduling_or_claim() {
    let fixture = fixture(RunnerSlotAvailability::Available, true);
    let expected_evaluations = fixture
        .repository
        .candidates
        .iter()
        .map(|candidate| (candidate.attempt_id(), UnixMillis::new(1_000)))
        .collect::<Vec<_>>();
    let gate = IneligibleAttemptGate {
        ineligible: fixture.expected_attempt,
        evaluations: Mutex::new(Vec::new()),
    };

    let outcome = service(&fixture)
        .with_attempt_gate(&gate)
        .poll(fixture.authenticated, &fixture.request)
        .await
        .expect("ineligible candidate is a normal no-work result");

    assert_eq!(outcome, LeasePollOutcome::NoWork { replayed: false });
    assert_eq!(
        *gate.evaluations.lock().expect("gate evaluations"),
        expected_evaluations
    );
    assert_eq!(
        fixture.repository.calls(),
        ["lookup", "routing", "availability", "scan", "no_work"]
    );
}

#[tokio::test]
async fn occupied_exact_slot_is_not_offered_and_no_work_is_durable() {
    let fixture = fixture(
        RunnerSlotAvailability::Occupied {
            attempt_id: AttemptId::new(),
        },
        true,
    );

    let outcome = service(&fixture)
        .poll(fixture.authenticated, &fixture.request)
        .await
        .expect("poll succeeds");

    assert_eq!(outcome, LeasePollOutcome::NoWork { replayed: false });
    assert_eq!(
        fixture.repository.calls(),
        ["lookup", "routing", "availability", "scan", "no_work"]
    );
}

#[tokio::test]
async fn configured_slot_beyond_negotiated_capacity_is_no_work_not_corrupt_state() {
    let mut fixture = fixture(RunnerSlotAvailability::Available, true);
    let fence = fixture.authenticated.fence();
    let registered = fixture.repository.routing.registered_capabilities().clone();
    let weaker = RunnerCapabilities::new(
        fence.runner_id(),
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
    )
    .with_max_parallel_jobs(1)
    .expect("one negotiated slot")
    .with_features([RunnerFeature::SHELL_STEPS]);
    fixture.repository.routing = RunnerRoutingSnapshot::try_new(
        fence,
        Some((
            RunnerGroupId::from_uuid(fence.runner_id().as_uuid()),
            "trusted-group".into(),
        )),
        [RoutingLabel::new("trusted").expect("routing label")],
        registered,
        capability_document(&weaker),
        RunnerSlotCount::new(2).expect("registered slots"),
        JobIrVersion::current(),
    )
    .expect("routing snapshot");
    fixture.request = LeaseRequest::first(
        fixture.request.header(),
        RunnerSlotOrdinal::new(2).expect("second slot"),
    );

    let outcome = service(&fixture)
        .poll(fixture.authenticated, &fixture.request)
        .await
        .expect("weaker capacity is a normal decline");

    assert_eq!(outcome, LeasePollOutcome::NoWork { replayed: false });
    assert_eq!(
        fixture.repository.calls(),
        ["lookup", "routing", "availability", "scan", "no_work"]
    );
}

#[tokio::test]
async fn exact_no_work_retry_returns_before_every_scheduling_read() {
    let mut fixture = fixture(RunnerSlotAvailability::Available, true);
    let key = LeaseRequestKey::first(
        fixture.authenticated.fence(),
        fixture.request.header().operation_id(),
        StableRunnerSlot::new(fixture.request.slot().get()).expect("slot"),
    );
    fixture.repository.lookup = Some(TryClaimReceipt::new(key, TryClaimOutcome::NoWork, false));

    let outcome = service(&fixture)
        .poll(fixture.authenticated, &fixture.request)
        .await
        .expect("receipt replay succeeds");

    assert_eq!(outcome, LeasePollOutcome::NoWork { replayed: true });
    assert_eq!(fixture.repository.calls(), ["lookup"]);
}

#[tokio::test]
async fn protocol_successor_is_carried_into_the_durable_key_and_digest() {
    let mut fixture = fixture(RunnerSlotAvailability::Available, false);
    let predecessor = OperationId::new();
    fixture.request = LeaseRequest::successor(
        fixture.request.header(),
        fixture.request.slot(),
        predecessor,
    );
    let first = LeaseRequestKey::first(
        fixture.authenticated.fence(),
        fixture.request.header().operation_id(),
        StableRunnerSlot::new(fixture.request.slot().get()).expect("slot"),
    );

    let outcome = service(&fixture)
        .poll(fixture.authenticated, &fixture.request)
        .await
        .expect("successor no-work poll");
    assert_eq!(outcome, LeasePollOutcome::NoWork { replayed: false });
    let key = fixture
        .repository
        .lease_keys
        .lock()
        .expect("lease key lock")[0];
    assert_eq!(key.acknowledges_operation_id(), Some(predecessor));
    assert_ne!(key.request_digest(), first.request_digest());
}

#[tokio::test]
async fn exact_claim_retry_uses_self_contained_receipt_and_never_reschedules() {
    let mut fixture = fixture(RunnerSlotAvailability::Available, true);
    let key = LeaseRequestKey::first(
        fixture.authenticated.fence(),
        fixture.request.header().operation_id(),
        StableRunnerSlot::new(fixture.request.slot().get()).expect("slot"),
    );
    let issued_at = UnixMillis::new(900);
    let expires_at = UnixMillis::new(2_000);
    let lease = Lease::new(
        fixture.lease_id,
        fixture.expected_attempt,
        fixture.authenticated.fence().runner_id(),
        FencingToken::new(7).expect("fence"),
        issued_at,
        expires_at,
    )
    .expect("lease");
    let assignment = AttemptAssignment::new(
        fixture.authenticated.fence(),
        StableRunnerSlot::new(1).expect("slot"),
    );
    let claimed = ClaimedAttempt::try_new(lease, assignment, fixture.repository.metadata.clone())
        .expect("claimed attempt");
    fixture.repository.lookup = Some(TryClaimReceipt::new(
        key,
        TryClaimOutcome::Claimed(Box::new(claimed)),
        false,
    ));

    let outcome = service(&fixture)
        .poll(fixture.authenticated, &fixture.request)
        .await
        .expect("claim replay succeeds");

    let LeasePollOutcome::Claimed(claimed) = outcome else {
        panic!("claimed receipt must replay");
    };
    assert!(claimed.was_replayed());
    assert_eq!(claimed.job_ir(), &fixture.repository.metadata);
    assert_eq!(fixture.repository.calls(), ["lookup"]);
}

#[tokio::test]
async fn observer_separates_physical_replay_from_one_new_claim_transition() {
    let fresh = fixture(RunnerSlotAvailability::Available, true);
    let observer = RecordingObserver::default();
    let outcome = service(&fresh)
        .with_observer(&observer)
        .poll(fresh.authenticated, &fresh.request)
        .await
        .expect("fresh claim");
    assert!(matches!(outcome, LeasePollOutcome::Claimed(_)));

    let mut replay = fixture(RunnerSlotAvailability::Available, true);
    let key = LeaseRequestKey::first(
        replay.authenticated.fence(),
        replay.request.header().operation_id(),
        StableRunnerSlot::new(replay.request.slot().get()).expect("slot"),
    );
    let lease = Lease::new(
        replay.lease_id,
        replay.expected_attempt,
        replay.authenticated.fence().runner_id(),
        FencingToken::new(8).expect("fence"),
        UnixMillis::new(900),
        UnixMillis::new(2_000),
    )
    .expect("lease");
    let claimed = ClaimedAttempt::try_new(
        lease,
        AttemptAssignment::new(
            replay.authenticated.fence(),
            StableRunnerSlot::new(1).expect("slot"),
        ),
        replay.repository.metadata.clone(),
    )
    .expect("claimed attempt");
    replay.repository.lookup = Some(TryClaimReceipt::new(
        key,
        TryClaimOutcome::Claimed(Box::new(claimed)),
        false,
    ));
    service(&replay)
        .with_observer(&observer)
        .poll(replay.authenticated, &replay.request)
        .await
        .expect("claim replay");

    assert_eq!(
        *observer.polls.lock().expect("poll observations"),
        [
            LeasePollObservation::Claimed,
            LeasePollObservation::ClaimedReplay,
        ]
    );
    assert_eq!(
        *observer.candidates.lock().expect("candidate observations"),
        [4]
    );
    assert_eq!(
        *observer
            .queue_waits
            .lock()
            .expect("queue-wait observations"),
        [Duration::from_millis(960)]
    );
}

#[test]
fn application_repository_remains_object_safe() {
    fn require_object_safe(_: &dyn LeasePollRepository) {}
    let fixture = fixture(RunnerSlotAvailability::Available, false);
    require_object_safe(&fixture.repository);
}
