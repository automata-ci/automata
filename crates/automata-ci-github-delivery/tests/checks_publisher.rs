use std::{
    collections::VecDeque,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use automata_ci_auth::secret::SecretString;
use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_github::{GithubHttpEndpoint, GithubHttpLimits};
use automata_ci_github_delivery::{
    GithubChecksCredentialProvider, GithubChecksCredentialProviderError,
    GithubChecksCredentialRequest, GithubChecksCredentialValueError, GithubChecksPublisher,
    GithubChecksPublisherConfig, GithubChecksPublisherError, GithubChecksPublisherOutcome,
    GithubChecksServerServiceCredential, GithubServerServiceCredentialRelease,
};
use automata_ci_scm::RepositoryId as ScmRepositoryId;
use automata_ci_store::{
    BeginGithubCheckRunCreate, BindGithubCheckRun, BindGithubCheckSuite,
    BlockGithubCheckProjectionForCredentialRejection, ClaimGithubCheckProjection,
    ClaimedGithubCheckProjection, CompleteGithubCheckProjection, GithubCheckAppId,
    GithubCheckCreateReconciliation, GithubCheckDesiredProjection, GithubCheckHeadSha,
    GithubCheckName, GithubCheckProjectionAction, GithubCheckProjectionClaimFence,
    GithubCheckProjectionOutbox, GithubCheckProjectionWorkerId, GithubCheckRunBindingFence,
    GithubCheckRunCreateFence, GithubCheckRunId, GithubCheckStoreError, GithubCheckSubjectId,
    GithubCheckSubjectIdentity, GithubCheckSubjectKey, GithubCheckSubjectReceipt,
    GithubCheckSuiteId, GithubCheckTerminalCause, GithubRepositoryName, GithubServerServiceAction,
    GithubServerServiceAuthorityId, GithubServerServiceAuthoritySelector,
    GithubServerServiceClaimFence, GithubServerServiceConsumerClaim, GithubServerServiceConsumerId,
    GithubServerServiceHandoffId, GithubServerServiceRevision, GithubServerServiceWorkerId,
    ProviderConnectionId, ProviderDeliveryId, ProviderInstallationId, ProviderRepositoryId,
    ReleaseUnissuedGithubCheckRunCreate, RepositoryId, ResolveGithubCheckRunCreate,
    RetryGithubCheckProjection, TenantScope,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
    task::JoinHandle,
};
use uuid::Uuid;

const TOKEN: &str = "github_pat_checks_publisher_secret";
const SHA: &str = "1111111111111111111111111111111111111111";
const NAME: &str = "Automata CI / verify";
const SUBJECT_UUID: u128 = 0x00000000_0000_4000_8000_000000000101;
const CONNECTION_UUID: u128 = 0x00000000_0000_4000_8000_000000000102;
const WORKER_UUID: u128 = 0x00000000_0000_4000_8000_000000000103;

#[derive(Debug)]
struct StepClock(AtomicI64);

impl StepClock {
    fn new(start: i64) -> Self {
        Self(AtomicI64::new(start))
    }

    fn set(&self, now: i64) {
        self.0.store(now, Ordering::SeqCst);
    }
}

impl automata_ci_github_delivery::GithubDeliveryClock for StepClock {
    fn now(&self) -> UnixMillis {
        UnixMillis::new(self.0.fetch_add(1, Ordering::SeqCst))
    }
}

#[derive(Clone, Copy, Debug)]
struct ClaimTemplate {
    action: GithubCheckProjectionAction,
    attempts: u16,
    desired: GithubCheckDesiredProjection,
    revision: u64,
    suite_id: Option<GithubCheckSuiteId>,
    run_id: Option<GithubCheckRunId>,
}

#[derive(Debug)]
struct FakeOutbox {
    identity: GithubCheckSubjectIdentity,
    claims: Mutex<VecDeque<ClaimTemplate>>,
    next_fence: AtomicUsize,
    mismatch_create_fence: AtomicBool,
    clock: Arc<StepClock>,
    clock_after_begin: AtomicI64,
    begin_delay_millis: AtomicUsize,
    claim_time_offset: AtomicI64,
    claim_delay_millis: AtomicUsize,
    credential_rejection_blocks: Mutex<Vec<BlockGithubCheckProjectionForCredentialRejection>>,
    events: Arc<Mutex<Vec<String>>>,
}

impl FakeOutbox {
    fn new(
        claims: impl IntoIterator<Item = ClaimTemplate>,
        clock: Arc<StepClock>,
        events: Arc<Mutex<Vec<String>>>,
    ) -> Self {
        Self {
            identity: subject_identity(),
            claims: Mutex::new(claims.into_iter().collect()),
            next_fence: AtomicUsize::new(1),
            mismatch_create_fence: AtomicBool::new(false),
            clock,
            clock_after_begin: AtomicI64::new(0),
            begin_delay_millis: AtomicUsize::new(0),
            claim_time_offset: AtomicI64::new(0),
            claim_delay_millis: AtomicUsize::new(0),
            credential_rejection_blocks: Mutex::new(Vec::new()),
            events,
        }
    }

    fn event(&self, event: impl Into<String>) {
        self.events.lock().expect("events lock").push(event.into());
    }

    fn receipt(
        subject_id: GithubCheckSubjectId,
        desired: GithubCheckDesiredProjection,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError> {
        GithubCheckSubjectReceipt::from_durable_parts(subject_id, external_id(), None, desired, 1)
            .map_err(|_| GithubCheckStoreError::CorruptData)
    }
}

#[async_trait]
impl GithubCheckProjectionOutbox for FakeOutbox {
    async fn claim_github_check_projection(
        &self,
        request: ClaimGithubCheckProjection,
    ) -> Result<Option<ClaimedGithubCheckProjection>, GithubCheckStoreError> {
        self.event("store:claim");
        let claim_delay_millis = self.claim_delay_millis.load(Ordering::SeqCst);
        if claim_delay_millis > 0 {
            tokio::time::sleep(Duration::from_millis(
                u64::try_from(claim_delay_millis)
                    .map_err(|_| GithubCheckStoreError::CorruptData)?,
            ))
            .await;
        }
        let Some(template) = self.claims.lock().expect("claims lock").pop_front() else {
            return Ok(None);
        };
        let duration = request
            .expires_at()
            .get()
            .checked_sub(request.observed_at().get())
            .ok_or(GithubCheckStoreError::CorruptData)?;
        let claimed_at = UnixMillis::new(
            request
                .observed_at()
                .get()
                .checked_add(self.claim_time_offset.load(Ordering::SeqCst))
                .ok_or(GithubCheckStoreError::CorruptData)?,
        );
        let expires_at = UnixMillis::new(
            claimed_at
                .get()
                .checked_add(duration)
                .ok_or(GithubCheckStoreError::CorruptData)?,
        );
        let fence = u64::try_from(self.next_fence.fetch_add(1, Ordering::SeqCst))
            .map_err(|_| GithubCheckStoreError::FenceExhausted)?;
        let claim = GithubCheckProjectionClaimFence::from_durable_parts(
            subject_id(),
            request.owner(),
            fence,
        )
        .map_err(|_| GithubCheckStoreError::CorruptData)?;
        ClaimedGithubCheckProjection::from_durable_parts(
            claim,
            template.action,
            template.attempts,
            self.identity.clone(),
            checks_authority(),
            external_id(),
            template.desired,
            template.revision,
            template.suite_id,
            template.run_id,
            claimed_at,
            expires_at,
        )
        .map(Some)
        .map_err(|_| GithubCheckStoreError::CorruptData)
    }

    async fn bind_github_check_suite(
        &self,
        request: BindGithubCheckSuite,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError> {
        self.event(format!("store:bind_suite:{}", request.suite_id().get()));
        Self::receipt(
            request.claim().subject_id(),
            GithubCheckDesiredProjection::Queued,
        )
    }

    async fn begin_github_check_run_create(
        &self,
        request: BeginGithubCheckRunCreate,
    ) -> Result<GithubCheckRunCreateFence, GithubCheckStoreError> {
        self.event("store:begin_run_create");
        let begin_delay_millis = self.begin_delay_millis.load(Ordering::SeqCst);
        if begin_delay_millis > 0 {
            tokio::time::sleep(Duration::from_millis(
                u64::try_from(begin_delay_millis)
                    .map_err(|_| GithubCheckStoreError::CorruptData)?,
            ))
            .await;
        }
        let clock_after_begin = self.clock_after_begin.load(Ordering::SeqCst);
        if clock_after_begin > 0 {
            self.clock.set(clock_after_begin);
        }
        if self.mismatch_create_fence.load(Ordering::SeqCst) {
            let claim = GithubCheckProjectionClaimFence::from_durable_parts(
                request.claim().subject_id(),
                request.claim().owner(),
                request
                    .claim()
                    .fence()
                    .checked_add(1)
                    .ok_or(GithubCheckStoreError::FenceExhausted)?,
            )
            .map_err(|_| GithubCheckStoreError::FenceExhausted)?;
            GithubCheckRunCreateFence::from_durable_parts(
                claim,
                request.started_at(),
                request.issue_expires_at(),
                request.reconcile_not_before(),
            )
            .map_err(|_| GithubCheckStoreError::CorruptData)
        } else {
            Ok(request.fence())
        }
    }

    async fn release_unissued_github_check_run_create(
        &self,
        request: ReleaseUnissuedGithubCheckRunCreate,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError> {
        self.event(format!(
            "store:release_unissued:{}",
            request.retry_at().get() - request.released_at().get()
        ));
        Self::receipt(
            request.fence().claim().subject_id(),
            GithubCheckDesiredProjection::Queued,
        )
    }

    async fn bind_github_check_run(
        &self,
        request: BindGithubCheckRun,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError> {
        let (claim, source) = match request.fence() {
            GithubCheckRunBindingFence::Create(fence) => (fence.claim(), "create"),
            GithubCheckRunBindingFence::Reconciliation(claim) => (claim, "reconcile"),
        };
        self.event(format!(
            "store:bind_run:{source}:{}",
            request.run_id().get()
        ));
        Self::receipt(claim.subject_id(), GithubCheckDesiredProjection::Queued)
    }

    async fn resolve_github_check_run_create(
        &self,
        request: ResolveGithubCheckRunCreate,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError> {
        let outcome = match request.outcome() {
            GithubCheckCreateReconciliation::Missing => format!(
                "missing:{}",
                request
                    .retry_at()
                    .ok_or(GithubCheckStoreError::CorruptData)?
                    .get()
                    - request.observed_at().get()
            ),
            GithubCheckCreateReconciliation::Ambiguous => "ambiguous".to_owned(),
        };
        self.event(format!("store:resolve:{outcome}"));
        Self::receipt(
            request.claim().subject_id(),
            GithubCheckDesiredProjection::Queued,
        )
    }

    async fn complete_github_check_projection(
        &self,
        request: CompleteGithubCheckProjection,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError> {
        self.event(format!("store:complete:{:?}", request.observed()));
        Self::receipt(request.claim().subject_id(), request.observed())
    }

    async fn block_github_check_projection_for_credential_rejection(
        &self,
        request: BlockGithubCheckProjectionForCredentialRejection,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError> {
        self.event("store:block:credential_rejected");
        self.credential_rejection_blocks
            .lock()
            .expect("credential rejection blocks lock")
            .push(request);
        Self::receipt(
            request.claim().subject_id(),
            GithubCheckDesiredProjection::Queued,
        )
    }

    async fn retry_github_check_projection(
        &self,
        request: RetryGithubCheckProjection,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError> {
        self.event(format!(
            "store:retry:{}:{}",
            request.failure_kind(),
            request.retry_at().get() - request.failed_at().get()
        ));
        Self::receipt(
            request.claim().subject_id(),
            GithubCheckDesiredProjection::Queued,
        )
    }
}

#[derive(Clone, Copy, Debug)]
enum CredentialMode {
    Exact,
    Delayed(Duration),
    BlockedRelease(Duration),
    WrongApp,
    WrongRepository,
    WrongAuthority,
    WrongAuthorityDigest,
    WrongAuthorityRevision,
    WrongConsumer,
    StaleAcquisition,
    FutureAcquisition,
    TooShort,
    Unavailable,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CredentialClaimEvidence {
    claim: GithubCheckProjectionClaimFence,
    action: GithubCheckProjectionAction,
    desired_revision: u64,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
    credential_observed_at: UnixMillis,
    authority_id: Uuid,
    authority_digest: Sha256Digest,
    consumer_id: Uuid,
    consumer_owner: Uuid,
    consumer_fence: u64,
    consumer_action: GithubServerServiceAction,
    consumer_revision: u64,
}

#[derive(Debug)]
struct FakeCredentials {
    mode: CredentialMode,
    calls: AtomicUsize,
    release_calls: Arc<AtomicUsize>,
    last_required_through: AtomicI64,
    last_claim: Mutex<Option<CredentialClaimEvidence>>,
    events: Arc<Mutex<Vec<String>>>,
}

impl FakeCredentials {
    fn event(&self, event: &str) {
        self.events
            .lock()
            .expect("events lock")
            .push(event.to_owned());
    }

    fn record_claim(
        &self,
        request: &GithubChecksCredentialRequest<'_>,
        consumer: GithubServerServiceConsumerClaim,
    ) {
        *self.last_claim.lock().expect("claim evidence lock") = Some(CredentialClaimEvidence {
            claim: request.claim(),
            action: request.action(),
            desired_revision: request.desired_revision(),
            claimed_at: request.claimed_at(),
            expires_at: request.claim_expires_at(),
            credential_observed_at: request.observed_at(),
            authority_id: request.authority_selector().authority_id().as_uuid(),
            authority_digest: request.authority_selector().identity_digest(),
            consumer_id: consumer.consumer_id().as_uuid(),
            consumer_owner: consumer.owner().as_uuid(),
            consumer_fence: consumer.fence().get(),
            consumer_action: consumer.action(),
            consumer_revision: consumer.revision().get(),
        });
    }
}

#[derive(Debug)]
struct FakeCredentialRelease {
    invoked: AtomicBool,
    calls: Arc<AtomicUsize>,
    events: Arc<Mutex<Vec<String>>>,
    delay: Duration,
}

impl FakeCredentialRelease {
    fn new(calls: Arc<AtomicUsize>, events: Arc<Mutex<Vec<String>>>, delay: Duration) -> Self {
        Self {
            invoked: AtomicBool::new(false),
            calls,
            events,
            delay,
        }
    }
}

#[async_trait]
impl GithubServerServiceCredentialRelease for FakeCredentialRelease {
    async fn release(self: Box<Self>) {
        assert!(
            !self.invoked.swap(true, Ordering::SeqCst),
            "one move-only release capability must not be invoked twice"
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.events
            .lock()
            .expect("events lock")
            .push("credential:release".to_owned());
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
    }
}

#[async_trait]
impl GithubChecksCredentialProvider for FakeCredentials {
    async fn acquire(
        &self,
        request: GithubChecksCredentialRequest<'_>,
    ) -> Result<GithubChecksServerServiceCredential, GithubChecksCredentialProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.last_required_through
            .store(request.required_through().get(), Ordering::SeqCst);
        let requested_consumer = request
            .consumer_claim()
            .map_err(|_| GithubChecksCredentialProviderError::InvariantViolation)?;
        self.record_claim(&request, requested_consumer);
        self.event("credential:acquire");
        if let CredentialMode::Delayed(delay) = self.mode {
            tokio::time::sleep(delay).await;
        }
        if matches!(self.mode, CredentialMode::Unavailable) {
            return Err(GithubChecksCredentialProviderError::Unavailable);
        }
        if matches!(self.mode, CredentialMode::Rejected) {
            return Err(GithubChecksCredentialProviderError::Rejected);
        }
        let identity = request.identity();
        let authority_selector = match self.mode {
            CredentialMode::WrongAuthority => wrong_checks_authority(),
            CredentialMode::WrongAuthorityDigest => wrong_checks_authority_digest(),
            CredentialMode::WrongAuthorityRevision => wrong_checks_authority_revision(),
            _ => request.authority_selector().clone(),
        };
        let consumer = if matches!(self.mode, CredentialMode::WrongConsumer) {
            GithubServerServiceConsumerClaim::new(
                requested_consumer.consumer_id(),
                requested_consumer.owner(),
                requested_consumer.fence(),
                requested_consumer.action(),
                GithubServerServiceRevision::new(requested_consumer.revision().get() + 1)
                    .expect("different consumer revision"),
            )
        } else {
            requested_consumer
        };
        let acquired_at = match self.mode {
            CredentialMode::StaleAcquisition => UnixMillis::new(
                request
                    .observed_at()
                    .get()
                    .checked_sub(1)
                    .ok_or(GithubChecksCredentialProviderError::InvariantViolation)?,
            ),
            CredentialMode::FutureAcquisition => UnixMillis::new(
                request
                    .observed_at()
                    .get()
                    .checked_add(100)
                    .ok_or(GithubChecksCredentialProviderError::InvariantViolation)?,
            ),
            _ => request.observed_at(),
        };
        let required_through = request.required_through();
        let app_id = if matches!(self.mode, CredentialMode::WrongApp) {
            GithubCheckAppId::new(18).expect("wrong App ID")
        } else {
            identity.app_id()
        };
        let conservative_expires_at = if matches!(self.mode, CredentialMode::TooShort) {
            request.required_through()
        } else {
            UnixMillis::new(request.required_through().get() + 10_000)
        };
        let repository = if matches!(self.mode, CredentialMode::WrongRepository) {
            ScmRepositoryId::new("acme/widget").expect("wrong repository route")
        } else {
            ScmRepositoryId::new(identity.github_repository_name().as_str())
                .expect("exact repository route")
        };
        let release_delay = match self.mode {
            CredentialMode::BlockedRelease(delay) => delay,
            _ => Duration::ZERO,
        };
        GithubChecksServerServiceCredential::new(
            authority_selector,
            GithubServerServiceHandoffId::from_uuid(Uuid::new_v4()).expect("handoff ID"),
            consumer,
            required_through,
            acquired_at,
            identity.tenant().clone(),
            identity.repository_id(),
            identity.connection_id(),
            identity.installation_id(),
            identity.github_repository_id(),
            app_id,
            repository,
            SecretString::new(TOKEN).expect("token"),
            conservative_expires_at,
            Box::new(FakeCredentialRelease::new(
                Arc::clone(&self.release_calls),
                Arc::clone(&self.events),
                release_delay,
            )),
        )
        .map_err(|_| GithubChecksCredentialProviderError::InvariantViolation)
    }
}

#[derive(Clone, Debug)]
struct RecordedRequest {
    method: String,
    target: String,
    raw: String,
}

#[derive(Clone, Debug)]
struct ResponseSpec {
    status: u16,
    body: String,
    headers: Vec<(&'static str, &'static str)>,
    delay: Duration,
}

impl ResponseSpec {
    fn json(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
            headers: Vec::new(),
            delay: Duration::ZERO,
        }
    }

    fn header(mut self, name: &'static str, value: &'static str) -> Self {
        self.headers.push((name, value));
        self
    }

    fn delayed(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

struct FixtureServer {
    endpoint: GithubHttpEndpoint,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    task: JoinHandle<()>,
}

impl FixtureServer {
    async fn spawn(responses: Vec<ResponseSpec>, events: Arc<Mutex<Vec<String>>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fixture");
        let address = listener.local_addr().expect("fixture address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let task_requests = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            for response in responses {
                let (mut stream, _) = listener.accept().await.expect("accept request");
                let request = read_request(&mut stream).await;
                events
                    .lock()
                    .expect("events lock")
                    .push(format!("http:{} {}", request.method, request.target));
                task_requests.lock().expect("requests lock").push(request);
                if !response.delay.is_zero() {
                    tokio::time::sleep(response.delay).await;
                }
                events
                    .lock()
                    .expect("events lock")
                    .push("http:respond".to_owned());
                write_response(&mut stream, response).await;
            }
        });
        let oauth_origin = format!("http://{address}/").parse().expect("OAuth URL");
        let api_base = format!("http://{address}/api/").parse().expect("API URL");
        let endpoint = GithubHttpEndpoint::new_for_loopback_emulator(
            oauth_origin,
            api_base,
            "automata-checks-publisher-test",
            GithubHttpLimits::default(),
        )
        .expect("test endpoint");
        Self {
            endpoint,
            requests,
            task,
        }
    }

    fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().expect("requests lock").clone()
    }
}

impl Drop for FixtureServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Harness {
    publisher: GithubChecksPublisher,
    outbox: Arc<FakeOutbox>,
    credentials: Arc<FakeCredentials>,
    server: FixtureServer,
    events: Arc<Mutex<Vec<String>>>,
}

impl Harness {
    async fn new(
        claims: impl IntoIterator<Item = ClaimTemplate>,
        responses: Vec<ResponseSpec>,
        credential_mode: CredentialMode,
    ) -> Self {
        Self::new_with_config(
            claims,
            responses,
            credential_mode,
            GithubChecksPublisherConfig::new(1_000, 50, 10).expect("publisher config"),
        )
        .await
    }

    async fn new_with_config(
        claims: impl IntoIterator<Item = ClaimTemplate>,
        responses: Vec<ResponseSpec>,
        credential_mode: CredentialMode,
        config: GithubChecksPublisherConfig,
    ) -> Self {
        let events = Arc::new(Mutex::new(Vec::new()));
        let server = FixtureServer::spawn(responses, Arc::clone(&events)).await;
        let clock = Arc::new(StepClock::new(1_000));
        let outbox = Arc::new(FakeOutbox::new(
            claims,
            Arc::clone(&clock),
            Arc::clone(&events),
        ));
        let release_calls = Arc::new(AtomicUsize::new(0));
        let credentials = Arc::new(FakeCredentials {
            mode: credential_mode,
            calls: AtomicUsize::new(0),
            release_calls,
            last_required_through: AtomicI64::new(0),
            last_claim: Mutex::new(None),
            events: Arc::clone(&events),
        });
        let publisher = GithubChecksPublisher::new(
            server.endpoint.clone(),
            outbox.clone(),
            credentials.clone(),
            clock,
            config,
        );
        Self {
            publisher,
            outbox,
            credentials,
            server,
            events,
        }
    }

    async fn run(&self) -> Result<GithubChecksPublisherOutcome, GithubChecksPublisherError> {
        self.publisher.run_once(connection_id(), worker_id()).await
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().expect("events lock").clone()
    }

    fn release_calls(&self) -> usize {
        self.credentials.release_calls.load(Ordering::SeqCst)
    }
}

#[tokio::test]
async fn successful_provider_action_releases_once_after_the_action_finishes() {
    let harness = Harness::new(
        [claim(
            GithubCheckProjectionAction::EnsureSuite,
            queued(),
            1,
            None,
            None,
        )],
        vec![ResponseSpec::json(201, suite_json())],
        CredentialMode::Exact,
    )
    .await;

    assert!(matches!(
        harness.run().await.expect("successful provider action"),
        GithubChecksPublisherOutcome::Advanced(_)
    ));
    assert_eq!(harness.release_calls(), 1);
    let events = harness.events();
    assert!(
        position(&events, "http:respond") < position(&events, "store:bind_suite:23")
            && position(&events, "store:bind_suite:23") < position(&events, "credential:release")
    );
    assert_eq!(
        events.last().map(String::as_str),
        Some("credential:release")
    );
}

#[tokio::test]
async fn exact_database_issued_claim_times_are_retained_in_the_handoff() {
    for database_offset in [-500, 30_000] {
        let harness = Harness::new(
            [claim(
                GithubCheckProjectionAction::EnsureSuite,
                queued(),
                7,
                None,
                None,
            )],
            Vec::new(),
            CredentialMode::WrongApp,
        )
        .await;
        harness
            .outbox
            .claim_time_offset
            .store(database_offset, Ordering::SeqCst);

        assert!(matches!(
            harness.run().await,
            Err(GithubChecksPublisherError::CredentialMismatch)
        ));
        let evidence = harness
            .credentials
            .last_claim
            .lock()
            .expect("claim evidence lock")
            .expect("credential request");
        assert_eq!(
            evidence.claimed_at,
            UnixMillis::new(1_000 + database_offset)
        );
        assert_eq!(evidence.expires_at.get() - evidence.claimed_at.get(), 1_000);
        assert!(
            evidence.credential_observed_at >= evidence.claimed_at
                && evidence.credential_observed_at < evidence.expires_at
        );
    }
}

#[tokio::test(start_paused = true)]
async fn slow_claim_response_cannot_extend_a_blocked_provider_past_the_claim_horizon() {
    let harness = Harness::new(
        [claim(
            GithubCheckProjectionAction::EnsureSuite,
            queued(),
            1,
            None,
            None,
        )],
        vec![ResponseSpec::json(201, suite_json()).delayed(Duration::from_secs(2))],
        CredentialMode::Exact,
    )
    .await;
    harness
        .outbox
        .claim_delay_millis
        .store(900, Ordering::SeqCst);

    assert!(matches!(
        harness.run().await,
        Err(GithubChecksPublisherError::ProviderDeadlineExceeded)
    ));
    assert_eq!(harness.release_calls(), 1);
    assert!(
        harness
            .events()
            .iter()
            .any(|event| event.starts_with("http:POST "))
    );
    assert!(!harness.events().iter().any(|event| event == "http:respond"));
}

#[tokio::test]
async fn blocked_exact_release_is_detached_at_the_same_durable_horizon() {
    let harness = Harness::new_with_config(
        [claim(
            GithubCheckProjectionAction::EnsureSuite,
            queued(),
            1,
            None,
            None,
        )],
        vec![ResponseSpec::json(201, suite_json())],
        CredentialMode::BlockedRelease(Duration::from_secs(2)),
        GithubChecksPublisherConfig::new(1_000, 50, 10).expect("short claim horizon"),
    )
    .await;

    assert!(matches!(
        harness
            .run()
            .await
            .expect("provider result remains classified"),
        GithubChecksPublisherOutcome::Advanced(_)
    ));
    assert_eq!(harness.release_calls(), 1);
    let events = harness.events();
    assert!(position(&events, "store:bind_suite:23") < position(&events, "credential:release"));
}

#[tokio::test]
async fn failed_provider_action_releases_once_after_retry_is_durable() {
    let harness = Harness::new(
        [claim(
            GithubCheckProjectionAction::EnsureSuite,
            queued(),
            1,
            None,
            None,
        )],
        vec![ResponseSpec::json(503, "{}")],
        CredentialMode::Exact,
    )
    .await;

    assert!(matches!(
        harness.run().await.expect("provider failure is retryable"),
        GithubChecksPublisherOutcome::RetryScheduled(_)
    ));
    assert_eq!(harness.release_calls(), 1);
    let events = harness.events();
    assert!(
        position(&events, "http:respond")
            < position_prefix(&events, "store:retry:suite_create_unavailable:")
            && position_prefix(&events, "store:retry:suite_create_unavailable:")
                < position(&events, "credential:release")
    );
    assert_eq!(
        events.last().map(String::as_str),
        Some("credential:release")
    );
}

#[tokio::test(start_paused = true)]
async fn timed_out_provider_action_releases_once_after_the_future_ends() {
    let harness = Harness::new(
        [claim(
            GithubCheckProjectionAction::EnsureSuite,
            queued(),
            1,
            None,
            None,
        )],
        vec![ResponseSpec::json(201, suite_json()).delayed(Duration::from_millis(20_001))],
        CredentialMode::Exact,
    )
    .await;

    assert!(matches!(
        harness.run().await,
        Err(GithubChecksPublisherError::ProviderDeadlineExceeded)
    ));
    assert_eq!(harness.release_calls(), 1);
    let events = harness.events();
    assert!(events.iter().any(|event| event.starts_with("http:POST ")));
    assert!(!events.iter().any(|event| event == "http:respond"));
    assert!(!events.iter().any(|event| event.starts_with("store:retry:")));
    assert_eq!(
        events.last().map(String::as_str),
        Some("credential:release")
    );
}

#[tokio::test]
async fn create_cutoff_and_state_publication_follow_exact_durable_actions() {
    let harness = Harness::new(
        [
            claim(
                GithubCheckProjectionAction::EnsureSuite,
                queued(),
                1,
                None,
                None,
            ),
            claim(
                GithubCheckProjectionAction::PrepareRunCreate,
                queued(),
                1,
                Some(suite_id()),
                None,
            ),
            claim(
                GithubCheckProjectionAction::Publish,
                GithubCheckDesiredProjection::InProgress,
                2,
                Some(suite_id()),
                Some(run_id()),
            ),
            claim(
                GithubCheckProjectionAction::Publish,
                terminal_success(),
                3,
                Some(suite_id()),
                Some(run_id()),
            ),
        ],
        vec![
            ResponseSpec::json(201, suite_json()),
            ResponseSpec::json(201, run_json(41, "queued", None)),
            ResponseSpec::json(200, run_json(41, "queued", None)),
            ResponseSpec::json(200, run_json(41, "in_progress", None)),
            ResponseSpec::json(200, run_json(41, "in_progress", None)),
            ResponseSpec::json(200, run_json(41, "completed", Some("success"))),
        ],
        CredentialMode::Exact,
    )
    .await;

    for _ in 0..4 {
        assert!(matches!(
            harness.run().await.expect("publisher advances"),
            GithubChecksPublisherOutcome::Advanced(_)
        ));
    }
    let requests = harness.server.requests();
    assert_eq!(
        methods(&requests),
        ["POST", "POST", "GET", "PATCH", "GET", "PATCH"]
    );
    assert!(requests[3].raw.contains(r#""status":"in_progress""#));
    assert!(requests[5].raw.contains(r#""status":"completed""#));
    assert!(requests[5].raw.contains(r#""conclusion":"success""#));
    let events = harness.events();
    assert!(
        position(&events, "store:begin_run_create")
            < position(
                &events,
                "http:POST /api/repos/automata-ci/automata/check-runs",
            )
    );
    assert_eq!(harness.credentials.calls.load(Ordering::SeqCst), 4);
    assert!(Arc::strong_count(&harness.outbox) >= 2);
}

#[tokio::test]
async fn missing_create_remains_reconcile_only_until_exact_visibility() {
    let harness = Harness::new(
        [
            claim(
                GithubCheckProjectionAction::PrepareRunCreate,
                queued(),
                1,
                Some(suite_id()),
                None,
            ),
            claim(
                GithubCheckProjectionAction::ReconcileRunCreate,
                queued(),
                1,
                Some(suite_id()),
                None,
            ),
            claim(
                GithubCheckProjectionAction::ReconcileRunCreate,
                queued(),
                1,
                Some(suite_id()),
                None,
            ),
        ],
        vec![
            ResponseSpec::json(503, "{}").header("retry-after", "1"),
            ResponseSpec::json(200, r#"{"total_count":0,"check_runs":[]}"#),
            ResponseSpec::json(
                200,
                format!(
                    r#"{{"total_count":1,"check_runs":[{}]}}"#,
                    run_json(41, "queued", None)
                ),
            ),
        ],
        CredentialMode::Exact,
    )
    .await;

    assert!(matches!(
        harness.run().await.expect("uncertain create"),
        GithubChecksPublisherOutcome::ReconciliationRequired(_)
    ));
    assert!(matches!(
        harness.run().await.expect("missing reconciliation"),
        GithubChecksPublisherOutcome::RetryScheduled(_)
    ));
    assert!(matches!(
        harness.run().await.expect("eventually visible exact run"),
        GithubChecksPublisherOutcome::Advanced(_)
    ));
    assert!(matches!(
        harness.run().await.expect("exact run is bound"),
        GithubChecksPublisherOutcome::Idle
    ));
    let requests = harness.server.requests();
    assert_eq!(methods(&requests), ["POST", "GET", "GET"]);
    assert!(requests[1].target.contains("/check-suites/23/check-runs"));
    let events = harness.events();
    let first_post = position(
        &events,
        "http:POST /api/repos/automata-ci/automata/check-runs",
    );
    let reconcile = position_prefix(
        &events,
        "http:GET /api/repos/automata-ci/automata/check-suites/23/check-runs",
    );
    let missing = position_prefix(&events, "store:resolve:missing:");
    assert!(first_post < reconcile && reconcile < missing);
    assert_eq!(
        events
            .iter()
            .filter(|event| event.starts_with("http:POST"))
            .count(),
        1
    );
}

#[tokio::test]
async fn final_missing_reconciliation_reports_the_explicit_attempt_block() {
    let harness = Harness::new(
        [claim_at_attempt(
            GithubCheckProjectionAction::ReconcileRunCreate,
            64,
            queued(),
            1,
            Some(suite_id()),
            None,
        )],
        vec![ResponseSpec::json(
            200,
            r#"{"total_count":0,"check_runs":[]}"#,
        )],
        CredentialMode::Exact,
    )
    .await;

    assert!(matches!(
        harness.run().await.expect("attempt ceiling is durable"),
        GithubChecksPublisherOutcome::Blocked(_)
    ));
    assert_eq!(methods(&harness.server.requests()), ["GET"]);
    assert!(
        harness
            .events()
            .iter()
            .any(|event| event.starts_with("store:resolve:missing:"))
    );
}

#[tokio::test]
async fn ambiguous_reconciliation_blocks_without_another_create() {
    let harness = Harness::new(
        [claim(
            GithubCheckProjectionAction::ReconcileRunCreate,
            queued(),
            1,
            Some(suite_id()),
            None,
        )],
        vec![ResponseSpec::json(200, ambiguous_list_json())],
        CredentialMode::Exact,
    )
    .await;

    assert!(matches!(
        harness.run().await.expect("ambiguous reconciliation"),
        GithubChecksPublisherOutcome::Blocked(_)
    ));
    let requests = harness.server.requests();
    assert_eq!(methods(&requests), ["GET"]);
    assert!(
        harness
            .events()
            .contains(&"store:resolve:ambiguous".to_owned())
    );
}

#[test]
fn credential_constructor_distinguishes_authority_tenant_from_invalid_lifetime() {
    let construct = |authority_selector: GithubServerServiceAuthoritySelector,
                     acquired_at: UnixMillis,
                     required_through: UnixMillis,
                     conservative_expires_at: UnixMillis| {
        let identity = subject_identity();
        GithubChecksServerServiceCredential::new(
            authority_selector,
            GithubServerServiceHandoffId::from_uuid(Uuid::from_u128(
                0x00000000_0000_4000_8000_00000000010b,
            ))
            .expect("handoff ID"),
            GithubServerServiceConsumerClaim::new(
                GithubServerServiceConsumerId::from_uuid(subject_id().as_uuid())
                    .expect("consumer ID"),
                GithubServerServiceWorkerId::from_uuid(worker_id().as_uuid())
                    .expect("consumer owner"),
                GithubServerServiceClaimFence::new(1).expect("consumer fence"),
                GithubServerServiceAction::EnsureCheckSuite,
                GithubServerServiceRevision::new(1).expect("consumer revision"),
            ),
            required_through,
            acquired_at,
            identity.tenant().clone(),
            identity.repository_id(),
            identity.connection_id(),
            identity.installation_id(),
            identity.github_repository_id(),
            identity.app_id(),
            ScmRepositoryId::new(identity.github_repository_name().as_str())
                .expect("exact repository route"),
            SecretString::new(TOKEN).expect("token"),
            conservative_expires_at,
            Box::new(FakeCredentialRelease::new(
                Arc::new(AtomicUsize::new(0)),
                Arc::new(Mutex::new(Vec::new())),
                Duration::ZERO,
            )),
        )
    };
    let exact = checks_authority();
    let cross_tenant = GithubServerServiceAuthoritySelector::from_durable_parts(
        TenantScope::from_authenticated_tenant_id("other-tenant").expect("other tenant"),
        exact.authority_id(),
        exact.identity_digest(),
        exact.app_configuration_revision(),
        exact.policy_revision(),
    );

    let authority_error = construct(
        cross_tenant,
        UnixMillis::new(1_000),
        UnixMillis::new(2_000),
        UnixMillis::new(3_000),
    )
    .expect_err("cross-tenant authority selector");
    assert_eq!(
        authority_error,
        GithubChecksCredentialValueError::AuthorityTenantMismatch
    );
    assert!(!authority_error.to_string().contains("other-tenant"));

    let lifetime_error = construct(
        exact,
        UnixMillis::new(1_000),
        UnixMillis::new(2_000),
        UnixMillis::new(2_000),
    )
    .expect_err("credential lifetime must extend beyond its required horizon");
    assert_eq!(
        lifetime_error,
        GithubChecksCredentialValueError::InvalidExpiration
    );
}

#[tokio::test]
async fn mismatched_credential_fails_before_provider_io() {
    let harness = Harness::new(
        [claim(
            GithubCheckProjectionAction::EnsureSuite,
            queued(),
            1,
            None,
            None,
        )],
        Vec::new(),
        CredentialMode::WrongApp,
    )
    .await;

    let error = harness.run().await.expect_err("wrong App binding");
    assert!(matches!(
        error,
        GithubChecksPublisherError::CredentialMismatch
    ));
    assert_eq!(harness.release_calls(), 1);
    assert!(harness.server.requests().is_empty());
    assert_eq!(
        harness.events(),
        [
            "store:claim".to_owned(),
            "credential:acquire".to_owned(),
            "credential:release".to_owned(),
        ]
    );
    let debug = format!("{error:?} {error}");
    assert!(!debug.contains(TOKEN));
    assert!(!debug.contains("acme/widget"));
}

#[tokio::test]
async fn mismatched_authority_or_consumer_handoff_never_reaches_provider_io() {
    for mode in [
        CredentialMode::WrongAuthority,
        CredentialMode::WrongAuthorityDigest,
        CredentialMode::WrongAuthorityRevision,
        CredentialMode::WrongConsumer,
        CredentialMode::StaleAcquisition,
        CredentialMode::FutureAcquisition,
    ] {
        let harness = Harness::new(
            [claim(
                GithubCheckProjectionAction::EnsureSuite,
                queued(),
                7,
                None,
                None,
            )],
            Vec::new(),
            mode,
        )
        .await;

        assert!(matches!(
            harness.run().await,
            Err(GithubChecksPublisherError::CredentialMismatch)
        ));
        assert!(harness.server.requests().is_empty());
    }
}

#[tokio::test(start_paused = true)]
async fn credential_return_after_provider_deadline_never_polls_the_endpoint() {
    let harness = Harness::new(
        [claim(
            GithubCheckProjectionAction::EnsureSuite,
            queued(),
            1,
            None,
            None,
        )],
        vec![ResponseSpec::json(201, suite_json())],
        CredentialMode::Delayed(Duration::from_millis(301_001)),
    )
    .await;

    let error = harness
        .run()
        .await
        .expect_err("provider action must not be polled after its monotonic horizon");
    assert!(matches!(
        error,
        GithubChecksPublisherError::ProviderDeadlineExceeded
    ));
    assert_eq!(
        harness.release_calls(),
        0,
        "a credential that never returned cannot expose a release capability"
    );
    assert!(harness.server.requests().is_empty());
    assert_eq!(
        harness.events(),
        ["store:claim".to_owned(), "credential:acquire".to_owned(),]
    );
}

#[tokio::test]
async fn mismatched_canonical_repository_fails_before_provider_io() {
    let harness = Harness::new(
        [claim(
            GithubCheckProjectionAction::EnsureSuite,
            queued(),
            1,
            None,
            None,
        )],
        Vec::new(),
        CredentialMode::WrongRepository,
    )
    .await;

    let error = harness.run().await.expect_err("wrong repository binding");
    assert!(matches!(
        error,
        GithubChecksPublisherError::CredentialMismatch
    ));
    assert!(harness.server.requests().is_empty());
}

#[tokio::test]
async fn credential_request_carries_the_exact_consumer_fence_action_and_revision() {
    let harness = Harness::new(
        [claim(
            GithubCheckProjectionAction::EnsureSuite,
            queued(),
            7,
            None,
            None,
        )],
        Vec::new(),
        CredentialMode::WrongApp,
    )
    .await;

    let error = harness.run().await.expect_err("wrong App binding");
    assert!(matches!(
        error,
        GithubChecksPublisherError::CredentialMismatch
    ));
    assert_eq!(
        *harness
            .credentials
            .last_claim
            .lock()
            .expect("claim evidence lock"),
        Some(CredentialClaimEvidence {
            claim: GithubCheckProjectionClaimFence::from_durable_parts(
                subject_id(),
                worker_id(),
                1,
            )
            .expect("claim"),
            action: GithubCheckProjectionAction::EnsureSuite,
            desired_revision: 7,
            claimed_at: UnixMillis::new(1_000),
            expires_at: UnixMillis::new(2_000),
            credential_observed_at: UnixMillis::new(1_001),
            authority_id: checks_authority().authority_id().as_uuid(),
            authority_digest: checks_authority().identity_digest(),
            consumer_id: subject_id().as_uuid(),
            consumer_owner: worker_id().as_uuid(),
            consumer_fence: 1,
            consumer_action: GithubServerServiceAction::EnsureCheckSuite,
            consumer_revision: 7,
        })
    );
    assert_eq!(
        harness
            .credentials
            .last_required_through
            .load(Ordering::SeqCst),
        302_000
    );
    assert!(harness.server.requests().is_empty());
}

#[tokio::test]
async fn publish_credential_covers_two_bounded_provider_request_tails() {
    let harness = Harness::new(
        [claim(
            GithubCheckProjectionAction::Publish,
            queued(),
            7,
            Some(suite_id()),
            Some(run_id()),
        )],
        Vec::new(),
        CredentialMode::WrongApp,
    )
    .await;

    let error = harness.run().await.expect_err("wrong App binding");
    assert!(matches!(
        error,
        GithubChecksPublisherError::CredentialMismatch
    ));
    assert_eq!(
        harness
            .credentials
            .last_required_through
            .load(Ordering::SeqCst),
        602_000
    );
    assert!(harness.server.requests().is_empty());
}

#[tokio::test]
async fn create_credential_must_cover_the_bounded_http_uncertainty_window() {
    let harness = Harness::new(
        [claim(
            GithubCheckProjectionAction::PrepareRunCreate,
            queued(),
            1,
            Some(suite_id()),
            None,
        )],
        Vec::new(),
        CredentialMode::TooShort,
    )
    .await;

    let error = harness
        .run()
        .await
        .expect_err("credential expiring at the request deadline");
    assert!(matches!(
        error,
        GithubChecksPublisherError::CredentialMismatch
    ));
    assert!(harness.server.requests().is_empty());
    assert!(
        harness
            .credentials
            .last_required_through
            .load(Ordering::SeqCst)
            > 2_000
    );
}

#[tokio::test]
async fn mismatched_create_cutoff_fence_fails_before_provider_io() {
    let harness = Harness::new(
        [claim(
            GithubCheckProjectionAction::PrepareRunCreate,
            queued(),
            1,
            Some(suite_id()),
            None,
        )],
        Vec::new(),
        CredentialMode::Exact,
    )
    .await;
    harness
        .outbox
        .mismatch_create_fence
        .store(true, Ordering::SeqCst);

    let error = harness.run().await.expect_err("mismatched create fence");
    assert!(matches!(error, GithubChecksPublisherError::InvalidClaim));
    assert!(harness.server.requests().is_empty());
    assert_eq!(
        harness.events(),
        [
            "store:claim".to_owned(),
            "credential:acquire".to_owned(),
            "store:begin_run_create".to_owned(),
            "credential:release".to_owned(),
        ]
    );
}

#[tokio::test]
async fn forward_wall_clock_step_does_not_replace_the_monotonic_claim_horizon() {
    let harness = Harness::new(
        [claim(
            GithubCheckProjectionAction::PrepareRunCreate,
            queued(),
            1,
            Some(suite_id()),
            None,
        )],
        vec![ResponseSpec::json(201, run_json(41, "queued", None))],
        CredentialMode::Exact,
    )
    .await;
    harness
        .outbox
        .clock_after_begin
        .store(2_000, Ordering::SeqCst);

    assert!(matches!(
        harness
            .run()
            .await
            .expect("database-issued claim remains live"),
        GithubChecksPublisherOutcome::Advanced(_)
    ));
    assert_eq!(methods(&harness.server.requests()), ["POST"]);
    assert_eq!(
        harness.events(),
        [
            "store:claim".to_owned(),
            "credential:acquire".to_owned(),
            "store:begin_run_create".to_owned(),
            "http:POST /api/repos/automata-ci/automata/check-runs".to_owned(),
            "http:respond".to_owned(),
            "store:bind_run:create:41".to_owned(),
            "credential:release".to_owned(),
        ]
    );
}

#[tokio::test]
async fn any_polled_create_response_remains_reconcile_only() {
    let harness = Harness::new(
        [claim(
            GithubCheckProjectionAction::PrepareRunCreate,
            queued(),
            1,
            Some(suite_id()),
            None,
        )],
        vec![ResponseSpec::json(429, "{}").header("retry-after", "1")],
        CredentialMode::Exact,
    )
    .await;

    assert!(matches!(
        harness.run().await.expect("polled create is uncertain"),
        GithubChecksPublisherOutcome::ReconciliationRequired(_)
    ));
    assert_eq!(methods(&harness.server.requests()), ["POST"]);
    assert!(!harness.events().iter().any(|event| {
        event.starts_with("store:retry") || event.starts_with("store:release_unissued")
    }));
}

#[tokio::test]
async fn monotonic_deadline_prevents_late_create_future_from_starting() {
    let harness = Harness::new_with_config(
        [claim(
            GithubCheckProjectionAction::PrepareRunCreate,
            queued(),
            1,
            Some(suite_id()),
            None,
        )],
        Vec::new(),
        CredentialMode::Exact,
        GithubChecksPublisherConfig::new(50, 50, 10).expect("short issue deadline"),
    )
    .await;
    harness
        .outbox
        .begin_delay_millis
        .store(100, Ordering::SeqCst);

    assert!(matches!(
        harness.run().await,
        Err(GithubChecksPublisherError::ProviderDeadlineExceeded)
    ));
    assert!(harness.server.requests().is_empty());
    assert_eq!(harness.release_calls(), 1);
    assert!(
        !harness
            .events()
            .iter()
            .any(|event| event.starts_with("store:release_unissued:"))
    );
}

#[tokio::test]
async fn conflicting_terminal_provider_state_never_becomes_success() {
    let harness = Harness::new(
        [claim(
            GithubCheckProjectionAction::Publish,
            terminal_success(),
            3,
            Some(suite_id()),
            Some(run_id()),
        )],
        vec![ResponseSpec::json(
            200,
            run_json(41, "completed", Some("failure")),
        )],
        CredentialMode::Exact,
    )
    .await;

    let error = harness.run().await.expect_err("conflicting conclusion");
    assert!(matches!(
        error,
        GithubChecksPublisherError::ProviderStateMismatch
    ));
    assert_eq!(methods(&harness.server.requests()), ["GET"]);
    assert!(
        !harness
            .events()
            .iter()
            .any(|event| event.starts_with("store:complete"))
    );
}

#[tokio::test]
async fn rate_and_credential_unavailability_use_bounded_durable_retry() {
    let rate = Harness::new(
        [claim(
            GithubCheckProjectionAction::Publish,
            queued(),
            1,
            Some(suite_id()),
            Some(run_id()),
        )],
        vec![ResponseSpec::json(429, "{}").header("retry-after", "86400")],
        CredentialMode::Exact,
    )
    .await;
    assert!(matches!(
        rate.run().await.expect("rate retry"),
        GithubChecksPublisherOutcome::RetryScheduled(_)
    ));
    assert!(
        rate.events()
            .contains(&"store:retry:github_rate_limited:86400000".to_owned())
    );

    let credential = Harness::new(
        [claim(
            GithubCheckProjectionAction::EnsureSuite,
            queued(),
            1,
            None,
            None,
        )],
        Vec::new(),
        CredentialMode::Unavailable,
    )
    .await;
    assert!(matches!(
        credential.run().await.expect("credential retry"),
        GithubChecksPublisherOutcome::RetryScheduled(_)
    ));
    assert!(
        credential
            .events()
            .contains(&"store:retry:credential_unavailable:10".to_owned())
    );
    assert!(credential.server.requests().is_empty());
}

#[tokio::test]
async fn locally_rejected_credential_blocks_the_exact_claim_without_provider_io() {
    let harness = Harness::new(
        [claim(
            GithubCheckProjectionAction::EnsureSuite,
            queued(),
            1,
            None,
            None,
        )],
        Vec::new(),
        CredentialMode::Rejected,
    )
    .await;

    assert!(matches!(
        harness.run().await.expect("credential rejection is closed"),
        GithubChecksPublisherOutcome::Blocked(_)
    ));
    assert_eq!(harness.release_calls(), 0);
    assert!(harness.server.requests().is_empty());
    let credential_claim = harness
        .credentials
        .last_claim
        .lock()
        .expect("claim evidence lock")
        .expect("credential request");
    let blocks = harness
        .outbox
        .credential_rejection_blocks
        .lock()
        .expect("credential rejection blocks lock");
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].claim(), credential_claim.claim);
    assert!(
        blocks[0].blocked_at() >= credential_claim.claimed_at
            && blocks[0].blocked_at() < credential_claim.expires_at
    );
    assert_eq!(
        harness.events(),
        [
            "store:claim".to_owned(),
            "credential:acquire".to_owned(),
            "store:block:credential_rejected".to_owned(),
        ]
    );
}

#[tokio::test]
async fn provider_unauthorized_after_exact_handoff_remains_fatal() {
    let harness = Harness::new(
        [claim(
            GithubCheckProjectionAction::EnsureSuite,
            queued(),
            1,
            None,
            None,
        )],
        vec![ResponseSpec::json(401, "{}")],
        CredentialMode::Exact,
    )
    .await;

    assert!(matches!(
        harness.run().await,
        Err(GithubChecksPublisherError::CredentialRejected)
    ));
    assert_eq!(harness.release_calls(), 1);
    assert_eq!(methods(&harness.server.requests()), ["POST"]);
    assert!(
        !harness
            .events()
            .iter()
            .any(|event| event == "store:block:credential_rejected")
    );
}

fn claim(
    action: GithubCheckProjectionAction,
    desired: GithubCheckDesiredProjection,
    revision: u64,
    suite_id: Option<GithubCheckSuiteId>,
    run_id: Option<GithubCheckRunId>,
) -> ClaimTemplate {
    ClaimTemplate {
        action,
        attempts: 1,
        desired,
        revision,
        suite_id,
        run_id,
    }
}

fn claim_at_attempt(
    action: GithubCheckProjectionAction,
    attempts: u16,
    desired: GithubCheckDesiredProjection,
    revision: u64,
    suite_id: Option<GithubCheckSuiteId>,
    run_id: Option<GithubCheckRunId>,
) -> ClaimTemplate {
    ClaimTemplate {
        action,
        attempts,
        desired,
        revision,
        suite_id,
        run_id,
    }
}

const fn queued() -> GithubCheckDesiredProjection {
    GithubCheckDesiredProjection::Queued
}

const fn terminal_success() -> GithubCheckDesiredProjection {
    GithubCheckDesiredProjection::Terminal(GithubCheckTerminalCause::WorkflowSuccess)
}

fn subject_id() -> GithubCheckSubjectId {
    GithubCheckSubjectId::from_uuid(Uuid::from_u128(SUBJECT_UUID)).expect("subject ID")
}

fn connection_id() -> ProviderConnectionId {
    ProviderConnectionId::from_uuid(Uuid::from_u128(CONNECTION_UUID)).expect("connection ID")
}

fn worker_id() -> GithubCheckProjectionWorkerId {
    GithubCheckProjectionWorkerId::from_uuid(Uuid::from_u128(WORKER_UUID)).expect("worker ID")
}

fn suite_id() -> GithubCheckSuiteId {
    GithubCheckSuiteId::new(23).expect("suite ID")
}

fn run_id() -> GithubCheckRunId {
    GithubCheckRunId::new(41).expect("run ID")
}

fn external_id() -> String {
    format!("automata-check:{}", subject_id().as_uuid())
}

fn subject_identity() -> GithubCheckSubjectIdentity {
    GithubCheckSubjectIdentity::new(
        TenantScope::from_authenticated_tenant_id("tenant").expect("tenant"),
        RepositoryId::from_uuid(Uuid::from_u128(0x00000000_0000_4000_8000_000000000104)),
        ProviderDeliveryId::from_uuid(Uuid::from_u128(0x00000000_0000_4000_8000_000000000105))
            .expect("delivery ID"),
        GithubCheckSubjectKey::new(".github/workflows/ci.yml").expect("subject key"),
        connection_id(),
        ProviderInstallationId::new(11).expect("installation ID"),
        ProviderRepositoryId::new(13).expect("provider repository ID"),
        GithubRepositoryName::new("automata-ci/automata").expect("repository name"),
        GithubCheckAppId::new(17).expect("App ID"),
        GithubCheckHeadSha::new([0x11; 20]).expect("head SHA"),
        GithubCheckName::new(NAME).expect("Check name"),
    )
    .expect("subject identity")
}

fn checks_authority() -> GithubServerServiceAuthoritySelector {
    GithubServerServiceAuthoritySelector::from_durable_parts(
        TenantScope::from_authenticated_tenant_id("tenant").expect("tenant"),
        GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(
            0x00000000_0000_4000_8000_000000000109,
        ))
        .expect("authority ID"),
        Sha256Digest::from_bytes([9; 32]),
        GithubServerServiceRevision::new(3).expect("App configuration revision"),
        GithubServerServiceRevision::new(5).expect("policy revision"),
    )
}

fn wrong_checks_authority() -> GithubServerServiceAuthoritySelector {
    GithubServerServiceAuthoritySelector::from_durable_parts(
        TenantScope::from_authenticated_tenant_id("tenant").expect("tenant"),
        GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(
            0x00000000_0000_4000_8000_00000000010a,
        ))
        .expect("wrong authority ID"),
        Sha256Digest::from_bytes([10; 32]),
        GithubServerServiceRevision::new(3).expect("App configuration revision"),
        GithubServerServiceRevision::new(5).expect("policy revision"),
    )
}

fn wrong_checks_authority_digest() -> GithubServerServiceAuthoritySelector {
    let exact = checks_authority();
    GithubServerServiceAuthoritySelector::from_durable_parts(
        exact.tenant().clone(),
        exact.authority_id(),
        Sha256Digest::from_bytes([10; 32]),
        exact.app_configuration_revision(),
        exact.policy_revision(),
    )
}

fn wrong_checks_authority_revision() -> GithubServerServiceAuthoritySelector {
    let exact = checks_authority();
    GithubServerServiceAuthoritySelector::from_durable_parts(
        exact.tenant().clone(),
        exact.authority_id(),
        exact.identity_digest(),
        GithubServerServiceRevision::new(exact.app_configuration_revision().get() + 1)
            .expect("different App configuration revision"),
        exact.policy_revision(),
    )
}

fn suite_json() -> String {
    format!(r#"{{"id":23,"head_sha":"{SHA}","app":{{"id":17}}}}"#)
}

fn run_json(id: u64, status: &str, conclusion: Option<&str>) -> String {
    let conclusion = conclusion.map_or_else(|| "null".to_owned(), |value| format!(r#""{value}""#));
    format!(
        r#"{{"id":{id},"head_sha":"{SHA}","external_id":"{}","status":"{status}","conclusion":{conclusion},"name":"{NAME}","check_suite":{{"id":23}},"app":{{"id":17}}}}"#,
        external_id()
    )
}

fn ambiguous_list_json() -> String {
    format!(
        r#"{{"total_count":2,"check_runs":[{},{}]}}"#,
        run_json(41, "queued", None),
        run_json(42, "queued", None)
    )
}

fn methods(requests: &[RecordedRequest]) -> Vec<&str> {
    requests
        .iter()
        .map(|request| request.method.as_str())
        .collect()
}

fn position(events: &[String], exact: &str) -> usize {
    events
        .iter()
        .position(|event| event == exact)
        .expect("event exists")
}

fn position_prefix(events: &[String], prefix: &str) -> usize {
    events
        .iter()
        .position(|event| event.starts_with(prefix))
        .expect("event prefix exists")
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> RecordedRequest {
    let mut bytes = Vec::new();
    let header_end = loop {
        let mut chunk = [0_u8; 4_096];
        let read = stream.read(&mut chunk).await.expect("read request");
        assert!(read > 0, "request ended before headers");
        bytes.extend_from_slice(&chunk[..read]);
        assert!(bytes.len() <= 1_048_576, "request exceeds fixture bound");
        if let Some(index) = find_bytes(&bytes, b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = std::str::from_utf8(&bytes[..header_end]).expect("ASCII request headers");
    let content_length = headers
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().expect("content length"))
            })
        })
        .unwrap_or_default();
    while bytes.len() < header_end + content_length {
        let mut chunk = [0_u8; 4_096];
        let read = stream.read(&mut chunk).await.expect("read request body");
        assert!(read > 0, "request body truncated");
        bytes.extend_from_slice(&chunk[..read]);
    }
    let raw = String::from_utf8(bytes).expect("UTF-8 request");
    let first_line = raw.lines().next().expect("request line");
    let mut components = first_line.split_ascii_whitespace();
    RecordedRequest {
        method: components.next().expect("method").to_owned(),
        target: components.next().expect("target").to_owned(),
        raw,
    }
}

async fn write_response(stream: &mut tokio::net::TcpStream, response: ResponseSpec) {
    let reason = match response.status {
        401 => "Unauthorized",
        200 => "OK",
        201 => "Created",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Fixture",
    };
    let mut head = format!(
        "HTTP/1.1 {} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
        response.status,
        response.body.len()
    );
    for (name, value) in response.headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream
        .write_all(head.as_bytes())
        .await
        .expect("write response head");
    stream
        .write_all(response.body.as_bytes())
        .await
        .expect("write response body");
    stream.shutdown().await.expect("close response");
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

impl fmt::Debug for FixtureServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixtureServer")
            .field("endpoint", &"[configured]")
            .field("requests", &self.requests().len())
            .finish()
    }
}
