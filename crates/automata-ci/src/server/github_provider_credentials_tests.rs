use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicI64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use automata_ci_store::{
    GithubCheckAppId, GithubCheckHeadSha, GithubCheckName, GithubCheckSubjectIdentity,
    GithubCheckSubjectKey, GithubRepositoryName, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity,
    GithubServerServiceAuthoritySelector, GithubServerServiceClaimFence,
    GithubServerServiceConsumerClaim, GithubServerServiceConsumerId, GithubServerServiceGeneration,
    GithubServerServiceHandoffId, GithubServerServiceIssuanceKey, GithubServerServiceJwtIssuer,
    GithubServerServiceRevision, GithubServerServiceScope, GithubServerServiceWorkerId,
    ProviderConnectionId, ProviderDeliveryId, ProviderDeliveryIdentity, ProviderInstallationId,
    ProviderRepositoryCoordinates, ProviderRepositoryId, ProviderRepositoryOwnerId,
    ProviderRepositoryVisibility, RepositoryId, Sha256Digest, TenantScope,
};

use super::*;

const OBSERVED_AT: i64 = 1_000;
const REQUIRED_THROUGH: i64 = 2_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FakeHandoffMode {
    Exact,
    Rejected,
    WrongSelector,
    WrongConsumer,
    WrongHorizon,
    WrongAcquiredAt,
    WrongIssuanceAuthority,
}

struct FakeHandoffs {
    mode: FakeHandoffMode,
    calls: AtomicUsize,
    requests: Mutex<Vec<AcquireGithubServerServiceHandoff>>,
    releases: Arc<AtomicUsize>,
}

impl FakeHandoffs {
    fn new(mode: FakeHandoffMode) -> Self {
        Self {
            mode,
            calls: AtomicUsize::new(0),
            requests: Mutex::new(Vec::new()),
            releases: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn requests(&self) -> Vec<AcquireGithubServerServiceHandoff> {
        self.requests.lock().expect("request lock").clone()
    }
}

impl fmt::Debug for FakeHandoffs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeHandoffs")
            .field("mode", &self.mode)
            .field("calls", &self.calls.load(Ordering::SeqCst))
            .field("requests", &"[REDACTED]")
            .field("releases", &self.releases.load(Ordering::SeqCst))
            .finish()
    }
}

#[async_trait]
impl GithubProviderCredentialHandoffIssuer for FakeHandoffs {
    async fn acquire(
        &self,
        request: AcquireGithubServerServiceHandoff,
    ) -> Result<GithubProviderCredentialHandoff, GithubProviderCredentialHandoffError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.requests
            .lock()
            .expect("request lock")
            .push(request.clone());
        if self.mode == FakeHandoffMode::Rejected {
            return Err(GithubProviderCredentialHandoffError::Rejected);
        }
        let selector = if self.mode == FakeHandoffMode::WrongSelector {
            GithubServerServiceAuthoritySelector::from_durable_parts(
                request.selector().tenant().clone(),
                authority_id(0xff),
                request.selector().identity_digest(),
                request.selector().app_configuration_revision(),
                request.selector().policy_revision(),
            )
        } else {
            request.selector().clone()
        };
        let requested_consumer = request.consumer();
        let consumer = if self.mode == FakeHandoffMode::WrongConsumer {
            GithubServerServiceConsumerClaim::new(
                requested_consumer.consumer_id(),
                requested_consumer.owner(),
                requested_consumer.fence(),
                requested_consumer.action(),
                GithubServerServiceRevision::new(requested_consumer.revision().get() + 1)
                    .expect("different revision"),
            )
        } else {
            requested_consumer
        };
        let key_authority = if self.mode == FakeHandoffMode::WrongIssuanceAuthority {
            authority_id(0xfe)
        } else {
            request.authority_id()
        };
        Ok(GithubProviderCredentialHandoff {
            selector,
            handoff_id: GithubServerServiceHandoffId::from_uuid(Uuid::from_u128(0x70))
                .expect("handoff ID"),
            consumer,
            key: GithubServerServiceIssuanceKey::new(
                key_authority,
                GithubServerServiceGeneration::new(1).expect("generation"),
            ),
            required_through: if self.mode == FakeHandoffMode::WrongHorizon {
                UnixMillis::new(request.required_through().get() + 1)
            } else {
                request.required_through()
            },
            acquired_at: if self.mode == FakeHandoffMode::WrongAcquiredAt {
                UnixMillis::new(request.observed_at().get() + 1)
            } else {
                request.observed_at()
            },
            usable_until: UnixMillis::new(request.required_through().get() + 10_000),
            token: SecretString::new("github-provider-adapter-test-token")
                .expect("fixture credential"),
            release: Box::new(FakeDeliveryRelease {
                calls: Arc::clone(&self.releases),
            }),
            drop_release_arm: None,
        })
    }
}

#[derive(Debug)]
struct FakeDeliveryRelease {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl GithubServerServiceCredentialRelease for FakeDeliveryRelease {
    async fn release(self: Box<Self>) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Debug)]
struct FakeClock(AtomicI64);

impl FakeClock {
    fn new(now: i64) -> Self {
        Self(AtomicI64::new(now))
    }

    fn set(&self, now: i64) {
        self.0.store(now, Ordering::SeqCst);
    }
}

impl GithubServerServiceCoordinatorClock for FakeClock {
    fn now(&self) -> UnixMillis {
        UnixMillis::new(self.0.load(Ordering::SeqCst))
    }
}

struct FakeExactRelease {
    attempts: Arc<AtomicUsize>,
    outcome: Mutex<Option<GithubProviderExactReleaseOutcome>>,
}

impl fmt::Debug for FakeExactRelease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeExactRelease")
            .field("attempts", &self.attempts.load(Ordering::SeqCst))
            .field("outcome", &"[REDACTED]")
            .finish()
    }
}

#[async_trait]
impl GithubProviderExactHandoffRelease for FakeExactRelease {
    async fn release(self: Box<Self>) -> GithubProviderExactReleaseOutcome {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        self.outcome
            .lock()
            .expect("release outcome lock")
            .take()
            .expect("one exact release attempt")
    }
}

#[derive(Debug)]
struct FakePendingRelease {
    attempts: Arc<AtomicUsize>,
    confirm_on: usize,
}

#[derive(Debug)]
struct GatedExactRelease {
    attempts: Arc<AtomicUsize>,
    finish: Arc<Semaphore>,
}

#[async_trait]
impl GithubProviderExactHandoffRelease for GatedExactRelease {
    async fn release(self: Box<Self>) -> GithubProviderExactReleaseOutcome {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        let permit = self.finish.acquire().await.expect("test gate remains open");
        permit.forget();
        GithubProviderExactReleaseOutcome::Released
    }
}

#[async_trait]
impl GithubProviderPendingHandoffRelease for FakePendingRelease {
    async fn replay(&self) -> bool {
        self.attempts.fetch_add(1, Ordering::SeqCst) + 1 >= self.confirm_on
    }
}

fn tenant() -> TenantScope {
    TenantScope::from_authenticated_tenant_id("tenant").expect("tenant")
}

fn authority_id(value: u128) -> GithubServerServiceAuthorityId {
    GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(value)).expect("authority ID")
}

fn connection_id() -> ProviderConnectionId {
    ProviderConnectionId::from_uuid(Uuid::from_u128(0x20)).expect("connection ID")
}

fn repository_id() -> RepositoryId {
    RepositoryId::from_uuid(Uuid::from_u128(0x30))
}

fn authority(scope: GithubServerServiceScope, id: u128) -> GithubServerServiceAuthorityIdentity {
    GithubServerServiceAuthorityIdentity::new(
        tenant(),
        authority_id(id),
        repository_id(),
        connection_id(),
        ProviderInstallationId::new(11).expect("installation ID"),
        GithubServerServiceAppId::new(17).expect("App ID"),
        ProviderRepositoryId::new(13).expect("provider repository ID"),
        GithubRepositoryName::new("automata-ci/automata").expect("repository name"),
        scope,
        GithubServerServiceAppClientId::new("Iv1.automata-test").expect("App client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        Sha256Digest::from_bytes([0x51; 32]),
        GithubServerServiceRevision::new(3).expect("App revision"),
        GithubServerServiceRevision::new(5).expect("policy revision"),
        Sha256Digest::from_bytes([0x61; 32]),
    )
    .expect("authority")
}

#[derive(Clone, Copy)]
enum ChecksIdentityDrift {
    Exact,
    Tenant,
    InternalRepository,
    Connection,
    Installation,
    ProviderRepository,
    RepositoryName,
    App,
}

fn checks_identity(drift: ChecksIdentityDrift) -> GithubCheckSubjectIdentity {
    GithubCheckSubjectIdentity::new(
        if matches!(drift, ChecksIdentityDrift::Tenant) {
            TenantScope::from_authenticated_tenant_id("other-tenant").expect("other tenant")
        } else {
            tenant()
        },
        if matches!(drift, ChecksIdentityDrift::InternalRepository) {
            RepositoryId::from_uuid(Uuid::from_u128(0x31))
        } else {
            repository_id()
        },
        ProviderDeliveryId::from_uuid(Uuid::from_u128(0x40)).expect("delivery ID"),
        GithubCheckSubjectKey::new(".github/workflows/ci.yml").expect("subject key"),
        if matches!(drift, ChecksIdentityDrift::Connection) {
            ProviderConnectionId::from_uuid(Uuid::from_u128(0x21)).expect("other connection")
        } else {
            connection_id()
        },
        ProviderInstallationId::new(if matches!(drift, ChecksIdentityDrift::Installation) {
            12
        } else {
            11
        })
        .expect("installation ID"),
        ProviderRepositoryId::new(
            if matches!(drift, ChecksIdentityDrift::ProviderRepository) {
                14
            } else {
                13
            },
        )
        .expect("provider repository ID"),
        GithubRepositoryName::new(if matches!(drift, ChecksIdentityDrift::RepositoryName) {
            "automata-ci/other"
        } else {
            "automata-ci/automata"
        })
        .expect("repository name"),
        GithubCheckAppId::new(if matches!(drift, ChecksIdentityDrift::App) {
            18
        } else {
            17
        })
        .expect("App ID"),
        GithubCheckHeadSha::new([0x11; 20]).expect("head SHA"),
        GithubCheckName::new("Automata CI").expect("Check name"),
    )
    .expect("Checks identity")
}

#[derive(Clone, Copy)]
enum PrivateIdentityDrift {
    Exact,
    Provider,
    Visibility,
    Tenant,
    Connection,
    Installation,
    ProviderRepository,
    RepositoryName,
}

fn private_identity(drift: PrivateIdentityDrift) -> ProviderDeliveryIdentity {
    let coordinates = ProviderRepositoryCoordinates::new(
        ProviderRepositoryId::new(
            if matches!(drift, PrivateIdentityDrift::ProviderRepository) {
                14
            } else {
                13
            },
        )
        .expect("provider repository ID"),
        if matches!(drift, PrivateIdentityDrift::Visibility) {
            ProviderRepositoryVisibility::Public
        } else {
            ProviderRepositoryVisibility::Private
        },
        if matches!(drift, PrivateIdentityDrift::RepositoryName) {
            "automata-ci/other"
        } else {
            "automata-ci/automata"
        },
    )
    .expect("repository coordinates");
    ProviderDeliveryIdentity::new(
        if matches!(drift, PrivateIdentityDrift::Tenant) {
            TenantScope::from_authenticated_tenant_id("other-tenant").expect("other tenant")
        } else {
            tenant()
        },
        if matches!(drift, PrivateIdentityDrift::Provider) {
            "gitlab"
        } else {
            "github"
        },
        if matches!(drift, PrivateIdentityDrift::Connection) {
            ProviderConnectionId::from_uuid(Uuid::from_u128(0x21)).expect("other connection")
        } else {
            connection_id()
        },
        ProviderInstallationId::new(if matches!(drift, PrivateIdentityDrift::Installation) {
            12
        } else {
            11
        })
        .expect("installation ID"),
        coordinates,
        "delivery-1",
    )
    .expect("delivery identity")
}

fn consumer(action: GithubServerServiceAction) -> GithubServerServiceConsumerClaim {
    GithubServerServiceConsumerClaim::new(
        GithubServerServiceConsumerId::from_uuid(Uuid::from_u128(0x50)).expect("consumer ID"),
        GithubServerServiceWorkerId::from_uuid(Uuid::from_u128(0x51)).expect("worker ID"),
        GithubServerServiceClaimFence::new(7).expect("claim fence"),
        action,
        GithubServerServiceRevision::new(2).expect("consumer revision"),
    )
}

fn checks_context(authority: &GithubServerServiceAuthorityIdentity) -> ChecksCredentialContext {
    ChecksCredentialContext {
        identity: checks_identity(ChecksIdentityDrift::Exact),
        selector: GithubServerServiceAuthoritySelector::from_identity(authority),
        consumer: consumer(GithubServerServiceAction::CreateCheckRun),
        observed_at: UnixMillis::new(OBSERVED_AT),
        required_through: UnixMillis::new(REQUIRED_THROUGH),
    }
}

fn private_context(
    authority: &GithubServerServiceAuthorityIdentity,
    drift: PrivateIdentityDrift,
    action: GithubDeliveryPrivateRepositoryAction,
) -> PrivateSourceCredentialContext {
    PrivateSourceCredentialContext {
        identity: private_identity(drift),
        repository_owner_id: ProviderRepositoryOwnerId::new(19).expect("repository owner ID"),
        selector: GithubServerServiceAuthoritySelector::from_identity(authority),
        action,
        consumer: consumer(private_action(action)),
        observed_at: UnixMillis::new(OBSERVED_AT),
        required_through: UnixMillis::new(REQUIRED_THROUGH),
    }
}

fn adapters(
    handoffs: Arc<FakeHandoffs>,
    authorities: &[GithubServerServiceAuthorityIdentity],
) -> GithubProviderCredentialAdapters {
    GithubProviderCredentialAdapters::with_handoffs(handoffs, authorities).expect("adapters")
}

#[test]
fn registry_is_bounded_unique_and_implements_both_delivery_ports() {
    fn assert_ports<T: GithubChecksCredentialProvider + GithubDeliverySourceCredentialProvider>() {}
    assert_ports::<GithubProviderCredentialAdapters>();

    let checks = authority(GithubServerServiceScope::ChecksWrite, 0x60);
    let private = authority(GithubServerServiceScope::PrivateRepositorySourceRead, 0x61);
    let fake = Arc::new(FakeHandoffs::new(FakeHandoffMode::Rejected));
    let configured = adapters(Arc::clone(&fake), &[checks.clone(), private]);
    assert_eq!(configured.authorities.len(), 2);
    assert!(matches!(
        GithubProviderCredentialAdapters::with_handoffs(fake.clone(), &[]),
        Err(GithubProviderCredentialAdapterConfigurationError::InvalidAuthorityRegistry)
    ));
    assert!(matches!(
        GithubProviderCredentialAdapters::with_handoffs(fake, &[checks.clone(), checks]),
        Err(GithubProviderCredentialAdapterConfigurationError::InvalidAuthorityRegistry)
    ));
}

#[tokio::test]
async fn full_checks_coordinates_are_rejected_before_handoff_io() {
    let checks = authority(GithubServerServiceScope::ChecksWrite, 0x60);
    let fake = Arc::new(FakeHandoffs::new(FakeHandoffMode::Exact));
    let adapters = adapters(Arc::clone(&fake), std::slice::from_ref(&checks));
    for drift in [
        ChecksIdentityDrift::Tenant,
        ChecksIdentityDrift::InternalRepository,
        ChecksIdentityDrift::Connection,
        ChecksIdentityDrift::Installation,
        ChecksIdentityDrift::ProviderRepository,
        ChecksIdentityDrift::RepositoryName,
        ChecksIdentityDrift::App,
    ] {
        let mut context = checks_context(&checks);
        context.identity = checks_identity(drift);
        assert_eq!(
            adapters
                .acquire_checks(context)
                .await
                .expect_err("reject coordinate drift"),
            GithubChecksCredentialProviderError::Rejected
        );
    }
    let mut changed_selector = checks_context(&checks);
    changed_selector.selector = GithubServerServiceAuthoritySelector::from_durable_parts(
        tenant(),
        checks.authority_id(),
        Sha256Digest::from_bytes([0x7f; 32]),
        checks.app_configuration_revision(),
        checks.policy_revision(),
    );
    assert_eq!(
        adapters
            .acquire_checks(changed_selector)
            .await
            .expect_err("reject selector drift"),
        GithubChecksCredentialProviderError::Rejected
    );
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn public_source_and_wrong_scope_never_enter_handoff_io() {
    let private = authority(GithubServerServiceScope::PrivateRepositorySourceRead, 0x61);
    let fake = Arc::new(FakeHandoffs::new(FakeHandoffMode::Exact));
    let adapters = adapters(Arc::clone(&fake), std::slice::from_ref(&private));
    for drift in [
        PrivateIdentityDrift::Provider,
        PrivateIdentityDrift::Visibility,
        PrivateIdentityDrift::Tenant,
        PrivateIdentityDrift::Connection,
        PrivateIdentityDrift::Installation,
        PrivateIdentityDrift::ProviderRepository,
        PrivateIdentityDrift::RepositoryName,
    ] {
        assert_eq!(
            adapters
                .acquire_private_source(private_context(
                    &private,
                    drift,
                    GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryRevision,
                ))
                .await
                .expect_err("source coordinate drift"),
            GithubDeliverySourceCredentialProviderError::Rejected
        );
    }

    let mut wrong_action = private_context(
        &private,
        PrivateIdentityDrift::Exact,
        GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryRevision,
    );
    wrong_action.consumer = consumer(GithubServerServiceAction::CreateCheckRun);
    assert_eq!(
        adapters
            .acquire_private_source(wrong_action)
            .await
            .expect_err("Checks action cannot authorize source"),
        GithubDeliverySourceCredentialProviderError::Rejected
    );
    let mut changed_selector = private_context(
        &private,
        PrivateIdentityDrift::Exact,
        GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryRevision,
    );
    changed_selector.selector = GithubServerServiceAuthoritySelector::from_durable_parts(
        tenant(),
        private.authority_id(),
        Sha256Digest::from_bytes([0x7f; 32]),
        private.app_configuration_revision(),
        private.policy_revision(),
    );
    assert_eq!(
        adapters
            .acquire_private_source(changed_selector)
            .await
            .expect_err("App-bound selector drift"),
        GithubDeliverySourceCredentialProviderError::Rejected
    );
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn private_revision_and_changed_files_use_distinct_exact_consumers() {
    let private = authority(GithubServerServiceScope::PrivateRepositorySourceRead, 0x61);
    let fake = Arc::new(FakeHandoffs::new(FakeHandoffMode::Rejected));
    let adapters = adapters(Arc::clone(&fake), std::slice::from_ref(&private));
    for action in [
        GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryRevision,
        GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryChangedFiles,
    ] {
        let error = adapters
            .acquire_private_source(private_context(
                &private,
                PrivateIdentityDrift::Exact,
                action,
            ))
            .await
            .expect_err("fake rejects after recording exact request");
        assert_eq!(error, GithubDeliverySourceCredentialProviderError::Rejected);
    }
    let requests = fake.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].consumer().action(),
        GithubServerServiceAction::FetchPrivateRepositoryRevision
    );
    assert_eq!(
        requests[1].consumer().action(),
        GithubServerServiceAction::FetchPrivateRepositoryChangedFiles
    );
    assert_ne!(requests[0].consumer(), requests[1].consumer());
    assert_eq!(requests[0].observed_at(), UnixMillis::new(OBSERVED_AT));
    assert_eq!(
        requests[0].required_through(),
        UnixMillis::new(REQUIRED_THROUGH)
    );
}

#[tokio::test]
async fn inconsistent_returned_binding_is_released_and_never_delivered() {
    let checks = authority(GithubServerServiceScope::ChecksWrite, 0x60);
    for mode in [
        FakeHandoffMode::WrongSelector,
        FakeHandoffMode::WrongConsumer,
        FakeHandoffMode::WrongHorizon,
        FakeHandoffMode::WrongAcquiredAt,
        FakeHandoffMode::WrongIssuanceAuthority,
    ] {
        let fake = Arc::new(FakeHandoffs::new(mode));
        let adapters = adapters(Arc::clone(&fake), std::slice::from_ref(&checks));
        assert_eq!(
            adapters
                .acquire_checks(checks_context(&checks))
                .await
                .expect_err("inconsistent handoff"),
            GithubChecksCredentialProviderError::InvariantViolation
        );
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fake.releases.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn pending_release_is_replayed_exactly_and_drain_waits_for_confirmation() {
    let clock = Arc::new(FakeClock::new(OBSERVED_AT));
    let supervisor = Arc::new(
        GithubProviderCredentialReleaseSupervisor::new(
            clock,
            Handle::current(),
            1,
            Duration::from_millis(1),
        )
        .expect("release supervisor"),
    );
    let release_attempts = Arc::new(AtomicUsize::new(0));
    let replay_attempts = Arc::new(AtomicUsize::new(0));
    let reservation = supervisor.try_reserve().expect("release reservation");
    let initial_attempt = supervisor.supervise(
        reservation,
        Box::new(FakeExactRelease {
            attempts: Arc::clone(&release_attempts),
            outcome: Mutex::new(Some(GithubProviderExactReleaseOutcome::Pending(Box::new(
                FakePendingRelease {
                    attempts: Arc::clone(&replay_attempts),
                    confirm_on: 2,
                },
            )))),
        }),
        UnixMillis::new(REQUIRED_THROUGH),
    );
    initial_attempt.await.expect("initial release classified");

    tokio::time::timeout(Duration::from_secs(1), supervisor.wait_for_idle())
        .await
        .expect("release drain completes");
    assert_eq!(release_attempts.load(Ordering::SeqCst), 1);
    assert_eq!(replay_attempts.load(Ordering::SeqCst), 2);
    assert_eq!(supervisor.pending_release_count(), 0);
    assert_eq!(supervisor.available_capacity(), 1);
    assert_eq!(supervisor.expired_unconfirmed_release_count(), 0);
}

#[tokio::test]
async fn delivery_release_awaits_the_first_exact_attempt_without_owning_the_task() {
    let supervisor = Arc::new(
        GithubProviderCredentialReleaseSupervisor::new(
            Arc::new(FakeClock::new(OBSERVED_AT)),
            Handle::current(),
            1,
            Duration::from_millis(1),
        )
        .expect("release supervisor"),
    );
    let attempts = Arc::new(AtomicUsize::new(0));
    let finish = Arc::new(Semaphore::new(0));
    let capability: Box<dyn GithubServerServiceCredentialRelease> =
        Box::new(SupervisedCredentialRelease {
            supervisor: Arc::clone(&supervisor),
            reservation: Some(supervisor.try_reserve().expect("release reservation")),
            operation: Some(Box::new(GatedExactRelease {
                attempts: Arc::clone(&attempts),
                finish: Arc::clone(&finish),
            })),
            required_through: UnixMillis::new(REQUIRED_THROUGH),
            drop_release_armed: Arc::new(AtomicBool::new(true)),
        });
    let release = tokio::spawn(async move { capability.release().await });
    while attempts.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    assert!(!release.is_finished());
    finish.add_permits(1);
    release.await.expect("delivery release task");
    supervisor.wait_for_idle().await;
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn dropped_delivery_release_capability_keeps_exact_binding_supervised() {
    let supervisor = Arc::new(
        GithubProviderCredentialReleaseSupervisor::new(
            Arc::new(FakeClock::new(OBSERVED_AT)),
            Handle::current(),
            1,
            Duration::from_millis(1),
        )
        .expect("release supervisor"),
    );
    let attempts = Arc::new(AtomicUsize::new(0));
    let capability: Box<dyn GithubServerServiceCredentialRelease> =
        Box::new(SupervisedCredentialRelease {
            supervisor: Arc::clone(&supervisor),
            reservation: Some(supervisor.try_reserve().expect("release reservation")),
            operation: Some(Box::new(FakeExactRelease {
                attempts: Arc::clone(&attempts),
                outcome: Mutex::new(Some(GithubProviderExactReleaseOutcome::Released)),
            })),
            required_through: UnixMillis::new(REQUIRED_THROUGH),
            drop_release_armed: Arc::new(AtomicBool::new(true)),
        });
    drop(capability);
    supervisor.wait_for_idle().await;
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn unconfirmed_release_remains_observable_when_its_horizon_closes() {
    let clock = Arc::new(FakeClock::new(OBSERVED_AT));
    let supervisor = Arc::new(
        GithubProviderCredentialReleaseSupervisor::new(
            Arc::clone(&clock) as Arc<dyn GithubServerServiceCoordinatorClock>,
            Handle::current(),
            1,
            Duration::from_millis(1),
        )
        .expect("release supervisor"),
    );
    let replay_attempts = Arc::new(AtomicUsize::new(0));
    let reservation = supervisor.try_reserve().expect("release reservation");
    let initial_attempt = supervisor.supervise(
        reservation,
        Box::new(FakeExactRelease {
            attempts: Arc::new(AtomicUsize::new(0)),
            outcome: Mutex::new(Some(GithubProviderExactReleaseOutcome::Pending(Box::new(
                FakePendingRelease {
                    attempts: Arc::clone(&replay_attempts),
                    confirm_on: usize::MAX,
                },
            )))),
        }),
        UnixMillis::new(REQUIRED_THROUGH),
    );
    initial_attempt.await.expect("initial release classified");
    while supervisor.pending_release_count() == 0 {
        tokio::task::yield_now().await;
    }
    clock.set(REQUIRED_THROUGH);
    tokio::time::timeout(Duration::from_secs(1), supervisor.wait_for_idle())
        .await
        .expect("expired release drain completes");
    assert_eq!(supervisor.pending_release_count(), 0);
    assert_eq!(supervisor.expired_unconfirmed_release_count(), 1);
    assert_eq!(supervisor.available_capacity(), 1);
}

#[tokio::test]
async fn release_supervision_configuration_is_hard_bounded() {
    let runtime = Handle::current();
    let clock: Arc<dyn GithubServerServiceCoordinatorClock> = Arc::new(FakeClock::new(OBSERVED_AT));
    assert!(matches!(
        GithubProviderCredentialReleaseSupervisor::new(
            Arc::clone(&clock),
            runtime.clone(),
            0,
            Duration::from_millis(1),
        ),
        Err(GithubProviderCredentialAdapterConfigurationError::InvalidReleaseCapacity)
    ));
    assert!(matches!(
        GithubProviderCredentialReleaseSupervisor::new(clock, runtime, 1, Duration::ZERO,),
        Err(GithubProviderCredentialAdapterConfigurationError::InvalidReleaseRetryInterval)
    ));
}
