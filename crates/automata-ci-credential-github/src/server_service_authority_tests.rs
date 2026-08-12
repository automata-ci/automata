use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
    },
};

use automata_ci_auth::{secret::SecretString, time::UnixTimestamp};
use automata_ci_credential::{CredentialProvenance, ProviderResourceId};
use automata_ci_key_management::{
    EncryptedEnvelope, KeyId, LocalAes256GcmKeyring, LocalKeyMaterial, SecretBytes,
};
use automata_ci_store::{
    GITHUB_SERVICE_SAFE_ERASE_SKEW_MILLIS, GITHUB_SERVICE_TOKEN_LIFETIME_MILLIS,
    GithubRepositoryName, GithubServerServiceAction, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceAuthorityId, GithubServerServiceClaim,
    GithubServerServiceClaimFence, GithubServerServiceConsumerId,
    GithubServerServiceEnvelopeMetadata, GithubServerServiceGeneration,
    GithubServerServiceIssuanceState, GithubServerServiceJwtIssuer, GithubServerServiceRevision,
    ProviderConnectionId, ProviderInstallationId, ProviderRepositoryId, RepositoryId,
};
use uuid::Uuid;

use crate::{
    GithubInstallationTokenRevokePending, GithubReadyInstallationToken,
    runtime_authority::GithubInstallationTokenRevocationFailure,
};

use super::*;

const REQUESTED_AT: i64 = 1_000_000;
const REQUEST_DEADLINE: i64 = 1_120_000;
const CONSERVATIVE_EXPIRY: i64 =
    REQUEST_DEADLINE + GITHUB_SERVICE_TOKEN_LIFETIME_MILLIS + 60_000 + 120_000;
const PROVIDER_EXPIRES_AT: i64 = 4_600_000;
const SAFE_ERASE_AFTER: i64 = PROVIDER_EXPIRES_AT + GITHUB_SERVICE_SAFE_ERASE_SKEW_MILLIS;
const TOKEN: &str = "ghs_server-service-test-token_123";
const INSTALLATION_ID: u64 = 17;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BeginMode {
    Started = 0,
    AlreadyStarted = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BrokerMode {
    Rejected,
    RevokeUnknown,
    Ready,
    RevocationRetry,
}

#[derive(Debug)]
struct ScriptedClock {
    values: Mutex<VecDeque<i64>>,
    last: Mutex<i64>,
}

impl ScriptedClock {
    fn new(values: impl IntoIterator<Item = i64>) -> Self {
        let values = values.into_iter().collect::<VecDeque<_>>();
        let last = *values.back().expect("clock needs one value");
        Self {
            values: Mutex::new(values),
            last: Mutex::new(last),
        }
    }
}

impl GithubServerServiceCoordinatorClock for ScriptedClock {
    fn now(&self) -> UnixMillis {
        if let Some(value) = self.values.lock().expect("clock values").pop_front() {
            *self.last.lock().expect("clock last") = value;
            UnixMillis::new(value)
        } else {
            UnixMillis::new(*self.last.lock().expect("clock last"))
        }
    }
}

#[derive(Debug)]
struct ExactResolver;

#[async_trait]
impl GithubServerServiceCredentialRequestResolver for ExactResolver {
    async fn resolve_github_server_service_credential_request(
        &self,
        identity: &GithubServerServiceAuthorityIdentity,
    ) -> Result<
        Option<ResolvedGithubServerServiceCredentialRequest>,
        GithubServerServiceResolutionError,
    > {
        Ok(Some(
            ResolvedGithubServerServiceCredentialRequest::new(
                identity.clone(),
                github_server_service_credential_request(identity)
                    .expect("canonical service request"),
            )
            .expect("exact resolution"),
        ))
    }
}

struct FakeBroker {
    mode: BrokerMode,
    installation_id: u64,
    maximum_request_duration: Duration,
    mint_calls: AtomicUsize,
    revoke_calls: AtomicUsize,
}

impl FakeBroker {
    fn new(mode: BrokerMode) -> Self {
        Self::for_installation(mode, INSTALLATION_ID)
    }

    fn for_installation(mode: BrokerMode, installation_id: u64) -> Self {
        Self {
            mode,
            installation_id,
            maximum_request_duration: Duration::from_secs(1),
            mint_calls: AtomicUsize::new(0),
            revoke_calls: AtomicUsize::new(0),
        }
    }

    fn with_maximum_request_duration(mut self, maximum_request_duration: Duration) -> Self {
        self.maximum_request_duration = maximum_request_duration;
        self
    }

    fn candidate() -> GithubInstallationTokenRevocationCandidate {
        GithubInstallationTokenRevocationCandidate::new(
            SecretString::new(TOKEN).expect("test token"),
        )
    }
}

impl fmt::Debug for FakeBroker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FakeBroker([REDACTED])")
    }
}

#[async_trait]
impl GithubServerServiceCredentialBroker for FakeBroker {
    fn maximum_request_duration(&self, installation_id: u64) -> Option<Duration> {
        (installation_id == self.installation_id).then_some(self.maximum_request_duration)
    }

    async fn mint_once(
        &self,
        installation_id: u64,
        request: &RepositoryCredentialRequest,
    ) -> GithubInstallationTokenMintOutcome {
        assert_eq!(installation_id, self.installation_id);
        self.mint_calls.fetch_add(1, Ordering::SeqCst);
        match self.mode {
            BrokerMode::Rejected | BrokerMode::RevocationRetry => {
                GithubInstallationTokenMintOutcome::Rejected(CredentialError::new(
                    CredentialErrorKind::Forbidden,
                ))
            }
            BrokerMode::RevokeUnknown => GithubInstallationTokenMintOutcome::RevokePending(
                GithubInstallationTokenRevokePending::new(
                    Self::candidate(),
                    CredentialError::new(CredentialErrorKind::InvalidResponse),
                    None,
                    None,
                ),
            ),
            BrokerMode::Ready => {
                GithubInstallationTokenMintOutcome::Ready(GithubReadyInstallationToken::new(
                    Self::candidate(),
                    request.clone(),
                    UnixTimestamp::from_seconds(1_002),
                    UnixTimestamp::from_seconds(4_600),
                    UnixTimestamp::from_seconds(4_540),
                    CredentialProvenance::new(
                        ScmProviderId::new("github").expect("provider"),
                        ProviderResourceId::new("Iv1.server-service-test").expect("issuer"),
                        ProviderResourceId::new(self.installation_id.to_string())
                            .expect("installation"),
                    ),
                ))
            }
        }
    }

    async fn revoke(
        &self,
        installation_id: u64,
        _candidate: &GithubInstallationTokenRevocationCandidate,
    ) -> GithubInstallationTokenRevocationOutcome {
        assert_eq!(installation_id, self.installation_id);
        self.revoke_calls.fetch_add(1, Ordering::SeqCst);
        match self.mode {
            BrokerMode::RevocationRetry => GithubInstallationTokenRevocationOutcome::Unconfirmed(
                GithubInstallationTokenRevocationFailure::new(
                    GithubInstallationTokenRevocationFailureKind::Retryable,
                ),
            ),
            BrokerMode::Rejected | BrokerMode::RevokeUnknown | BrokerMode::Ready => {
                GithubInstallationTokenRevocationOutcome::Confirmed
            }
        }
    }
}

struct FakeRepository {
    begin_mode: AtomicU8,
    checks_identity: GithubServerServiceAuthorityIdentity,
    private_identity: GithubServerServiceAuthorityIdentity,
    codec: Arc<EnvelopeCodec>,
    corrupt_handoff: AtomicBool,
    begin_calls: AtomicUsize,
    acquire_calls: AtomicUsize,
    quarantine_calls: Mutex<Vec<QuarantineGithubServerServiceCredential>>,
    release_calls: Mutex<Vec<ReleaseGithubServerServiceHandoff>>,
    fail_next_quarantine: AtomicBool,
    fail_next_release: AtomicBool,
    mint_dispositions: Mutex<Vec<(&'static str, Option<UnixMillis>)>>,
    revocation_dispositions: Mutex<Vec<&'static str>>,
}

impl FakeRepository {
    fn new(codec: Arc<EnvelopeCodec>) -> Self {
        Self {
            begin_mode: AtomicU8::new(BeginMode::Started as u8),
            checks_identity: identity(GithubServerServiceScope::ChecksWrite, 0x101),
            private_identity: identity(
                GithubServerServiceScope::PrivateRepositorySourceRead,
                0x102,
            ),
            codec,
            corrupt_handoff: AtomicBool::new(false),
            begin_calls: AtomicUsize::new(0),
            acquire_calls: AtomicUsize::new(0),
            quarantine_calls: Mutex::new(Vec::new()),
            release_calls: Mutex::new(Vec::new()),
            fail_next_quarantine: AtomicBool::new(false),
            fail_next_release: AtomicBool::new(false),
            mint_dispositions: Mutex::new(Vec::new()),
            revocation_dispositions: Mutex::new(Vec::new()),
        }
    }

    fn identity_for_action(
        &self,
        action: GithubServerServiceAction,
    ) -> &GithubServerServiceAuthorityIdentity {
        match action.required_scope() {
            GithubServerServiceScope::ChecksWrite => &self.checks_identity,
            GithubServerServiceScope::PrivateRepositorySourceRead => &self.private_identity,
        }
    }
}

#[async_trait]
impl GithubServerServiceCredentialRepository for FakeRepository {
    async fn claim_next_github_server_service_maintenance(
        &self,
        _request: ClaimNextGithubServerServiceMaintenance,
    ) -> Result<Option<GithubServerServiceMaintenanceOutcome>, GithubServerServiceStoreError> {
        Ok(None)
    }

    async fn begin_github_server_service_mint(
        &self,
        request: BeginGithubServerServiceMint,
    ) -> Result<GithubServerServiceMintCutoffOutcome, GithubServerServiceStoreError> {
        self.begin_calls.fetch_add(1, Ordering::SeqCst);
        let evidence = GithubServerServiceMintCutoffEvidence {
            receipt: minting_receipt(&request),
            claim_expires_at: request.claim_expires_at(),
            request_deadline: request.request_deadline(),
            started_at: request.started_at(),
        };
        if self.begin_mode.load(Ordering::SeqCst) == BeginMode::AlreadyStarted as u8 {
            Ok(GithubServerServiceMintCutoffOutcome::AlreadyStarted(
                evidence,
            ))
        } else {
            Ok(GithubServerServiceMintCutoffOutcome::Started(evidence))
        }
    }

    async fn finish_github_server_service_mint(
        &self,
        request: &FinishGithubServerServiceMint,
    ) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError> {
        let (disposition, provider_expiry, receipt) = match request {
            FinishGithubServerServiceMint::Ready {
                protected,
                committed_at,
                ..
            } => (
                "ready",
                protected.metadata().provider_expires_at(),
                receipt_from_protected(
                    protected,
                    GithubServerServiceIssuanceState::Ready,
                    Some(*committed_at),
                    *committed_at,
                    0,
                ),
            ),
            FinishGithubServerServiceMint::RevokeOnly {
                protected,
                committed_at,
                ..
            } => (
                "revoke_only",
                protected.metadata().provider_expires_at(),
                receipt_from_protected(
                    protected,
                    GithubServerServiceIssuanceState::RevokePending,
                    None,
                    *committed_at,
                    0,
                ),
            ),
            FinishGithubServerServiceMint::Retry {
                claim, observed_at, ..
            } => (
                "retry",
                None,
                plain_receipt(
                    claim.key(),
                    GithubServerServiceIssuanceState::MintRetryPending,
                    *observed_at,
                    0,
                ),
            ),
            FinishGithubServerServiceMint::Indeterminate {
                claim, observed_at, ..
            } => (
                "indeterminate",
                None,
                plain_receipt(
                    claim.key(),
                    GithubServerServiceIssuanceState::Indeterminate,
                    *observed_at,
                    0,
                ),
            ),
            FinishGithubServerServiceMint::Rejected {
                claim, observed_at, ..
            } => (
                "rejected",
                None,
                plain_receipt(
                    claim.key(),
                    GithubServerServiceIssuanceState::Rejected,
                    *observed_at,
                    0,
                ),
            ),
        };
        self.mint_dispositions
            .lock()
            .expect("mint dispositions")
            .push((disposition, provider_expiry));
        Ok(receipt)
    }

    async fn finish_github_server_service_revocation(
        &self,
        request: FinishGithubServerServiceRevocation,
    ) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError> {
        let (disposition, claim, observed_at, state) = match request {
            FinishGithubServerServiceRevocation::Confirmed {
                claim,
                confirmed_at,
            } => (
                "confirmed",
                claim,
                confirmed_at,
                GithubServerServiceIssuanceState::Revoked,
            ),
            FinishGithubServerServiceRevocation::Retry {
                claim, observed_at, ..
            } => (
                "retry",
                claim,
                observed_at,
                GithubServerServiceIssuanceState::RevokeRetryPending,
            ),
            FinishGithubServerServiceRevocation::Quarantined {
                claim, observed_at, ..
            } => (
                "quarantined",
                claim,
                observed_at,
                GithubServerServiceIssuanceState::Quarantined,
            ),
        };
        self.revocation_dispositions
            .lock()
            .expect("revocation dispositions")
            .push(disposition);
        Ok(provider_receipt(claim.key(), state, observed_at, 1))
    }

    async fn acquire_github_server_service_handoff(
        &self,
        request: AcquireGithubServerServiceHandoff,
    ) -> Result<GithubServerServiceCredentialHandoff, GithubServerServiceStoreError> {
        self.acquire_calls.fetch_add(1, Ordering::SeqCst);
        let identity = self
            .identity_for_action(request.consumer().action())
            .clone();
        if request.selector() != &GithubServerServiceAuthoritySelector::from_identity(&identity) {
            return Err(GithubServerServiceStoreError::HandoffRejected);
        }
        let protected = protected(
            &self.codec,
            identity.clone(),
            self.corrupt_handoff.load(Ordering::SeqCst),
        )
        .await;
        GithubServerServiceCredentialHandoff::from_durable_parts(
            action_handoff_id(request.consumer().action()),
            request.consumer(),
            identity,
            ready_receipt(protected.metadata()),
            request.required_through(),
            UnixMillis::new(request.observed_at().get() - 10),
            request.observed_at(),
            protected,
        )
        .map_err(|_| GithubServerServiceStoreError::CorruptData)
    }

    async fn release_github_server_service_handoff(
        &self,
        request: ReleaseGithubServerServiceHandoff,
    ) -> Result<(), GithubServerServiceStoreError> {
        self.release_calls
            .lock()
            .expect("release calls")
            .push(request);
        if self.fail_next_release.swap(false, Ordering::SeqCst) {
            Err(GithubServerServiceStoreError::operation(
                std::io::Error::other("lost release response"),
            ))
        } else {
            Ok(())
        }
    }

    async fn quarantine_github_server_service_credential(
        &self,
        request: QuarantineGithubServerServiceCredential,
    ) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError> {
        self.quarantine_calls
            .lock()
            .expect("quarantine calls")
            .push(request.clone());
        if self.fail_next_quarantine.swap(false, Ordering::SeqCst) {
            return Err(GithubServerServiceStoreError::operation(
                std::io::Error::other("lost quarantine response"),
            ));
        }
        Ok(provider_receipt(
            request.key(),
            GithubServerServiceIssuanceState::Quarantined,
            request.observed_at(),
            0,
        ))
    }
}

#[tokio::test]
async fn already_started_and_finally_late_cutoffs_never_poll_the_provider() {
    let codec = codec();
    let repository = Arc::new(FakeRepository::new(codec.clone()));
    repository
        .begin_mode
        .store(BeginMode::AlreadyStarted as u8, Ordering::SeqCst);
    let broker = Arc::new(FakeBroker::new(BrokerMode::Rejected));
    let first_coordinator = coordinator(
        repository.clone(),
        broker.clone(),
        codec.clone(),
        Arc::new(ScriptedClock::new([1_001_000])),
    );
    let outcome = first_coordinator
        .coordinate_claimed_mint(claimed_mint(repository.checks_identity.clone(), 1_120_000))
        .await
        .expect("already-started outcome");
    assert!(matches!(
        outcome,
        GithubServerServiceCoordinationOutcome::MintAlreadyStarted(_)
    ));
    assert_eq!(broker.mint_calls.load(Ordering::SeqCst), 0);

    repository
        .begin_mode
        .store(BeginMode::Started as u8, Ordering::SeqCst);
    let late_broker = Arc::new(FakeBroker::new(BrokerMode::Rejected));
    let coordinator = coordinator(
        repository.clone(),
        late_broker.clone(),
        codec,
        Arc::new(ScriptedClock::new([1_001_000, 1_119_500])),
    );
    let outcome = coordinator
        .coordinate_claimed_mint(claimed_mint(repository.checks_identity.clone(), 1_120_000))
        .await
        .expect("late started outcome");
    assert!(matches!(
        outcome,
        GithubServerServiceCoordinationOutcome::MintStartedWindowExhausted(_)
    ));
    assert_eq!(late_broker.mint_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn fractional_broker_duration_never_reaches_mint_cutoff_or_provider() {
    let codec = codec();
    let repository = Arc::new(FakeRepository::new(codec.clone()));
    let broker = Arc::new(
        FakeBroker::new(BrokerMode::Rejected)
            .with_maximum_request_duration(Duration::from_micros(1_500)),
    );
    let coordinator = coordinator(
        repository.clone(),
        broker.clone(),
        codec,
        Arc::new(ScriptedClock::new([1_001_000])),
    );

    assert_eq!(
        coordinator
            .coordinate_claimed_mint(claimed_mint(repository.checks_identity.clone(), 1_120_000,))
            .await
            .expect_err("fractional broker duration must fail closed"),
        GithubServerServiceCoordinatorError::Inconsistent
    );
    assert_eq!(repository.begin_calls.load(Ordering::SeqCst), 0);
    assert_eq!(broker.mint_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn fractional_broker_duration_never_reaches_revocation_provider() {
    let codec = codec();
    let repository = Arc::new(FakeRepository::new(codec.clone()));
    let broker = Arc::new(
        FakeBroker::new(BrokerMode::RevocationRetry)
            .with_maximum_request_duration(Duration::from_micros(1_500)),
    );
    let coordinator = coordinator(
        repository.clone(),
        broker.clone(),
        codec.clone(),
        Arc::new(ScriptedClock::new([1_030_000])),
    );
    let claimed = claimed_revocation(&codec, repository.private_identity.clone()).await;

    let outcome = coordinator
        .coordinate_maintenance(GithubServerServiceMaintenanceOutcome::Revocation(Box::new(
            claimed,
        )))
        .await
        .expect("fractional duration retains a closed retry result");
    assert!(matches!(
        outcome,
        GithubServerServiceCoordinationOutcome::RevocationCommitPending(_)
    ));
    assert_eq!(broker.revoke_calls.load(Ordering::SeqCst), 0);
    assert!(
        repository
            .revocation_dispositions
            .lock()
            .expect("revocation dispositions")
            .is_empty(),
        "the retained Finish request must remain unpolled"
    );
}

#[tokio::test]
async fn unique_unknown_expiry_is_protected_as_revoke_only() {
    let codec = codec();
    let repository = Arc::new(FakeRepository::new(codec.clone()));
    let broker = Arc::new(FakeBroker::new(BrokerMode::RevokeUnknown));
    let coordinator = coordinator(
        repository.clone(),
        broker,
        codec,
        Arc::new(ScriptedClock::new([1_001_000, 1_002_000, 1_003_000])),
    );
    let outcome = coordinator
        .coordinate_claimed_mint(claimed_mint(repository.checks_identity.clone(), 1_110_000))
        .await
        .expect("revoke-only result");
    let GithubServerServiceCoordinationOutcome::MintCommitPending(pending) = outcome else {
        panic!("expected an unpolled exact mint Finish request");
    };
    assert!(
        repository
            .mint_dispositions
            .lock()
            .expect("mint dispositions")
            .is_empty(),
        "the Finish request must be retained before its first Store poll"
    );
    pending
        .replay(repository.as_ref())
        .await
        .expect("first supervised Finish poll");
    assert_eq!(
        repository
            .mint_dispositions
            .lock()
            .expect("mint dispositions")
            .as_slice(),
        &[("revoke_only", None)]
    );
}

#[tokio::test]
async fn exact_ready_response_is_protected_with_known_expiry() {
    let codec = codec();
    let repository = Arc::new(FakeRepository::new(codec.clone()));
    let broker = Arc::new(FakeBroker::new(BrokerMode::Ready));
    let coordinator = coordinator(
        repository.clone(),
        broker,
        codec,
        Arc::new(ScriptedClock::new([1_001_000, 1_002_000, 1_003_000])),
    );
    let outcome = coordinator
        .coordinate_claimed_mint(claimed_mint(repository.checks_identity.clone(), 1_110_000))
        .await
        .expect("ready result");
    let GithubServerServiceCoordinationOutcome::MintCommitPending(pending) = outcome else {
        panic!("expected an unpolled exact mint Finish request");
    };
    assert!(
        repository
            .mint_dispositions
            .lock()
            .expect("mint dispositions")
            .is_empty(),
        "the Finish request must be retained before its first Store poll"
    );
    pending
        .replay(repository.as_ref())
        .await
        .expect("first supervised Finish poll");
    assert_eq!(
        repository
            .mint_dispositions
            .lock()
            .expect("mint dispositions")
            .as_slice(),
        &[("ready", Some(UnixMillis::new(PROVIDER_EXPIRES_AT)))]
    );
}

#[tokio::test]
async fn installation_router_rejects_ambiguity_and_has_no_default() {
    assert_eq!(
        GithubServerServiceInstallationRouter::new(Vec::new()).expect_err("empty router"),
        GithubServerServiceInstallationRouterError::Empty
    );
    let broker = Arc::new(FakeBroker::new(BrokerMode::Rejected));
    let erased: Arc<dyn GithubServerServiceCredentialBroker> = broker.clone();
    assert_eq!(
        GithubServerServiceInstallationRouter::new([
            (INSTALLATION_ID, erased.clone()),
            (INSTALLATION_ID, erased.clone()),
        ])
        .expect_err("duplicate installation"),
        GithubServerServiceInstallationRouterError::DuplicateInstallationId
    );
    let fractional: Arc<dyn GithubServerServiceCredentialBroker> = Arc::new(
        FakeBroker::new(BrokerMode::Rejected)
            .with_maximum_request_duration(Duration::from_micros(1_500)),
    );
    assert_eq!(
        GithubServerServiceInstallationRouter::new([(INSTALLATION_ID, fractional)])
            .expect_err("fractional broker duration"),
        GithubServerServiceInstallationRouterError::BrokerMismatch
    );
    let router = GithubServerServiceInstallationRouter::new([(INSTALLATION_ID, erased)])
        .expect("exact router");
    assert_eq!(router.len(), 1);
    assert!(router.maximum_request_duration(INSTALLATION_ID).is_some());
    assert!(router.maximum_request_duration(999).is_none());
    let request = github_server_service_credential_request(&identity(
        GithubServerServiceScope::ChecksWrite,
        0x210,
    ))
    .expect("request");
    assert!(matches!(
        router.mint_once(999, &request).await,
        GithubInstallationTokenMintOutcome::Rejected(error)
            if error.kind() == CredentialErrorKind::InvalidRequest
    ));
    assert_eq!(broker.mint_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn protected_handoffs_round_trip_and_replay_the_natural_key_winner() {
    let codec = codec();
    let repository = Arc::new(FakeRepository::new(codec.clone()));
    let issuer = GithubServerServiceCredentialIssuer::new(
        repository.clone(),
        codec,
        Arc::new(ScriptedClock::new([1_030_000])),
    );
    let consumer = consumer(
        GithubServerServiceAction::FetchPrivateRepositoryRevision,
        0x501,
    );
    let first_proposed = handoff_id(0x601);
    let second_proposed = handoff_id(0x602);
    let first = issuer
        .acquire(acquire_request(
            &repository.private_identity,
            first_proposed,
            consumer,
        ))
        .await
        .expect("first handoff");
    let second = issuer
        .acquire(acquire_request(
            &repository.private_identity,
            second_proposed,
            consumer,
        ))
        .await
        .expect("lost-response replay");
    assert_eq!(first.secret().expose_secret(), TOKEN);
    assert_eq!(second.secret().expose_secret(), TOKEN);
    assert_ne!(first_proposed, second_proposed);
    assert_eq!(first.binding().handoff_id(), second.binding().handoff_id());
    assert_ne!(first.binding().handoff_id(), second_proposed);
    assert_eq!(first.binding().consumer(), consumer);
    assert_eq!(
        first.binding().required_through(),
        UnixMillis::new(2_000_000)
    );
    assert_eq!(
        first.binding().usable_until(),
        UnixMillis::new(PROVIDER_EXPIRES_AT - 60_000)
    );
    assert_eq!(repository.acquire_calls.load(Ordering::SeqCst), 2);

    repository.fail_next_release.store(true, Ordering::SeqCst);
    let GithubServerServiceHandoffReleaseOutcome::Pending(pending) =
        issuer.release(first).await.expect("pending exact release")
    else {
        panic!("expected pending release");
    };
    pending
        .replay(repository.as_ref())
        .await
        .expect("release replay");
    {
        let calls = repository.release_calls.lock().expect("release calls");
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], calls[1]);
    }
    assert!(matches!(
        issuer.release(second).await.expect("second release"),
        GithubServerServiceHandoffReleaseOutcome::Released
    ));
}

#[tokio::test]
async fn prepared_handoff_release_replays_one_frozen_timestamp_after_clock_advance() {
    let codec = codec();
    let repository = Arc::new(FakeRepository::new(codec.clone()));
    let clock = Arc::new(ScriptedClock::new([1_030_000, 1_040_000]));
    let issuer = GithubServerServiceCredentialIssuer::new(repository.clone(), codec, clock.clone());
    let credential = issuer
        .acquire(acquire_request(
            &repository.private_identity,
            handoff_id(0x603),
            consumer(
                GithubServerServiceAction::FetchPrivateRepositoryRevision,
                0x503,
            ),
        ))
        .await
        .expect("exact handoff");
    let (secret, binding) = credential.into_secret_and_binding();
    drop(secret);
    let pending = issuer
        .prepare_release_binding(binding)
        .expect("frozen release request");
    assert_eq!(clock.now(), UnixMillis::new(1_040_000));

    pending
        .replay(repository.as_ref())
        .await
        .expect("first exact release");
    pending
        .replay(repository.as_ref())
        .await
        .expect("same exact release replay");
    let releases = repository.release_calls.lock().expect("release calls");
    assert_eq!(releases.len(), 2);
    assert_eq!(releases[0], releases[1]);
}

#[tokio::test]
async fn revision_and_changed_files_have_distinct_exact_handoffs() {
    let codec = codec();
    let repository = Arc::new(FakeRepository::new(codec.clone()));
    let issuer = GithubServerServiceCredentialIssuer::new(
        repository.clone(),
        codec,
        Arc::new(ScriptedClock::new([1_030_000])),
    );
    let revision = issuer
        .acquire(acquire_request(
            &repository.private_identity,
            handoff_id(0x610),
            consumer(
                GithubServerServiceAction::FetchPrivateRepositoryRevision,
                0x510,
            ),
        ))
        .await
        .expect("revision handoff");
    let changed = issuer
        .acquire(acquire_request(
            &repository.private_identity,
            handoff_id(0x611),
            consumer(
                GithubServerServiceAction::FetchPrivateRepositoryChangedFiles,
                0x511,
            ),
        ))
        .await
        .expect("changed-files handoff");
    assert_ne!(
        revision.binding().handoff_id(),
        changed.binding().handoff_id()
    );
    assert_eq!(
        revision.binding().consumer().action(),
        GithubServerServiceAction::FetchPrivateRepositoryRevision
    );
    assert_eq!(
        changed.binding().consumer().action(),
        GithubServerServiceAction::FetchPrivateRepositoryChangedFiles
    );
}

#[tokio::test]
async fn corrupt_current_custody_is_quarantined_and_released() {
    let codec = codec();
    let repository = Arc::new(FakeRepository::new(codec.clone()));
    repository.corrupt_handoff.store(true, Ordering::SeqCst);
    let issuer = GithubServerServiceCredentialIssuer::new(
        repository.clone(),
        codec,
        Arc::new(ScriptedClock::new([1_030_000])),
    );
    let result = issuer
        .acquire(acquire_request(
            &repository.private_identity,
            handoff_id(0x620),
            consumer(
                GithubServerServiceAction::FetchPrivateRepositoryRevision,
                0x520,
            ),
        ))
        .await;
    assert_eq!(
        result.expect_err("corrupt handoff"),
        GithubServerServiceHandoffError::Corrupt
    );
    assert_eq!(
        repository
            .quarantine_calls
            .lock()
            .expect("quarantine calls")
            .len(),
        1
    );
    assert_eq!(
        repository
            .release_calls
            .lock()
            .expect("release calls")
            .len(),
        1
    );
}

async fn pending_corrupt_cleanup(
    fail_quarantine: bool,
    fail_release: bool,
) -> (
    Arc<FakeRepository>,
    Box<PendingGithubServerServiceCorruptionCleanup>,
) {
    let codec = codec();
    let repository = Arc::new(FakeRepository::new(codec.clone()));
    repository.corrupt_handoff.store(true, Ordering::SeqCst);
    repository
        .fail_next_quarantine
        .store(fail_quarantine, Ordering::SeqCst);
    repository
        .fail_next_release
        .store(fail_release, Ordering::SeqCst);
    let issuer = GithubServerServiceCredentialIssuer::new(
        repository.clone(),
        codec,
        Arc::new(ScriptedClock::new([1_030_000])),
    );
    let error = issuer
        .acquire(acquire_request(
            &repository.private_identity,
            handoff_id(0x621),
            consumer(
                GithubServerServiceAction::FetchPrivateRepositoryRevision,
                0x521,
            ),
        ))
        .await
        .expect_err("uncertain corruption cleanup");
    assert_eq!(
        format!("{error:?}"),
        "CorruptCleanupPending(PendingGithubServerServiceCorruptionCleanup { .. })"
    );
    let GithubServerServiceHandoffError::CorruptCleanupPending(pending) = error else {
        panic!("expected replayable corruption cleanup");
    };
    (repository, pending)
}

#[tokio::test]
async fn lost_quarantine_response_retains_exact_cleanup_before_release() {
    let (repository, pending) = pending_corrupt_cleanup(true, false).await;
    assert!(
        repository
            .release_calls
            .lock()
            .expect("release calls")
            .is_empty()
    );
    pending
        .replay(repository.as_ref())
        .await
        .expect("exact cleanup replay");
    let quarantine_calls = repository
        .quarantine_calls
        .lock()
        .expect("quarantine calls");
    assert_eq!(quarantine_calls.len(), 2);
    assert_eq!(quarantine_calls[0], quarantine_calls[1]);
    assert_eq!(
        repository
            .release_calls
            .lock()
            .expect("release calls")
            .len(),
        1
    );
}

#[tokio::test]
async fn lost_release_response_retains_both_exact_cleanup_requests() {
    let (repository, pending) = pending_corrupt_cleanup(false, true).await;
    pending
        .replay(repository.as_ref())
        .await
        .expect("exact cleanup replay");
    let quarantine_calls = repository
        .quarantine_calls
        .lock()
        .expect("quarantine calls");
    assert_eq!(quarantine_calls.len(), 2);
    assert_eq!(quarantine_calls[0], quarantine_calls[1]);
    let release_calls = repository.release_calls.lock().expect("release calls");
    assert_eq!(release_calls.len(), 2);
    assert_eq!(release_calls[0], release_calls[1]);
}

#[tokio::test]
async fn unconfirmed_revocation_is_retained_as_a_bounded_retry() {
    let codec = codec();
    let repository = Arc::new(FakeRepository::new(codec.clone()));
    let broker = Arc::new(FakeBroker::new(BrokerMode::RevocationRetry));
    let coordinator = coordinator(
        repository.clone(),
        broker.clone(),
        codec.clone(),
        Arc::new(ScriptedClock::new([1_030_000, 1_031_000])),
    );
    let claimed = claimed_revocation(&codec, repository.private_identity.clone()).await;
    let outcome = coordinator
        .coordinate_maintenance(GithubServerServiceMaintenanceOutcome::Revocation(Box::new(
            claimed,
        )))
        .await
        .expect("revocation retry");
    let GithubServerServiceCoordinationOutcome::RevocationCommitPending(pending) = outcome else {
        panic!("expected an unpolled exact revocation Finish request");
    };
    assert!(
        repository
            .revocation_dispositions
            .lock()
            .expect("revocation dispositions")
            .is_empty(),
        "the Finish request must be retained before its first Store poll"
    );
    pending
        .replay(repository.as_ref())
        .await
        .expect("first supervised Finish poll");
    assert_eq!(broker.revoke_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        repository
            .revocation_dispositions
            .lock()
            .expect("revocation dispositions")
            .as_slice(),
        &["retry"]
    );
}

#[test]
fn service_core_has_only_authenticated_checks_and_private_source_scopes() {
    let checks = github_server_service_credential_request(&identity(
        GithubServerServiceScope::ChecksWrite,
        0x201,
    ))
    .expect("checks request");
    let private = github_server_service_credential_request(&identity(
        GithubServerServiceScope::PrivateRepositorySourceRead,
        0x202,
    ))
    .expect("private request");
    assert_eq!(
        checks
            .permissions()
            .iter()
            .map(|(name, level)| (name.as_str(), level))
            .collect::<Vec<_>>(),
        vec![("checks", PermissionLevel::Write)]
    );
    assert_eq!(
        private
            .permissions()
            .iter()
            .map(|(name, level)| (name.as_str(), level))
            .collect::<Vec<_>>(),
        vec![("contents", PermissionLevel::Read)]
    );
    assert!(
        [
            GithubServerServiceScope::ChecksWrite,
            GithubServerServiceScope::PrivateRepositorySourceRead,
        ]
        .into_iter()
        .all(|scope| !scope.as_str().contains("public"))
    );
}

fn coordinator(
    repository: Arc<FakeRepository>,
    broker: Arc<FakeBroker>,
    codec: Arc<EnvelopeCodec>,
    clock: Arc<dyn GithubServerServiceCoordinatorClock>,
) -> GithubServerServiceCredentialCoordinator {
    GithubServerServiceCredentialCoordinator::new(
        repository,
        Arc::new(ExactResolver),
        broker,
        codec,
        clock,
        worker(0x301),
    )
}

fn identity(
    scope: GithubServerServiceScope,
    authority_uuid: u128,
) -> GithubServerServiceAuthorityIdentity {
    GithubServerServiceAuthorityIdentity::new(
        TenantScope::from_authenticated_tenant_id("tenant-a").expect("tenant"),
        GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(authority_uuid))
            .expect("authority"),
        RepositoryId::from_uuid(Uuid::from_u128(0x401)),
        ProviderConnectionId::from_uuid(Uuid::from_u128(0x402)).expect("connection"),
        ProviderInstallationId::new(INSTALLATION_ID).expect("installation"),
        GithubServerServiceAppId::new(19).expect("App"),
        ProviderRepositoryId::new(23).expect("repository"),
        GithubRepositoryName::new("automata-ci/automata").expect("repository name"),
        scope,
        GithubServerServiceAppClientId::new("Iv1.server-service-test").expect("client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        Sha256Digest::from_bytes([7; 32]),
        GithubServerServiceRevision::new(3).expect("App revision"),
        GithubServerServiceRevision::new(5).expect("policy revision"),
        Sha256Digest::from_bytes([8; 32]),
    )
    .expect("authority identity")
}

fn claimed_mint(
    identity: GithubServerServiceAuthorityIdentity,
    claim_expires_at: i64,
) -> ClaimedGithubServerServiceMint {
    let key = GithubServerServiceIssuanceKey::new(
        identity.authority_id(),
        GithubServerServiceGeneration::new(1).expect("generation"),
    );
    let receipt = plain_receipt(
        key,
        GithubServerServiceIssuanceState::Claimed,
        UnixMillis::new(REQUESTED_AT),
        0,
    );
    let claim = GithubServerServiceClaim::from_durable_parts(
        GithubServerServiceAuthoritySelector::from_identity(&identity),
        key,
        worker(0x302),
        GithubServerServiceClaimFence::new(1).expect("claim fence"),
    )
    .expect("claim");
    ClaimedGithubServerServiceMint::from_durable_parts(
        identity,
        receipt,
        claim,
        UnixMillis::new(REQUESTED_AT),
        UnixMillis::new(claim_expires_at),
    )
    .expect("claimed mint")
}

async fn claimed_revocation(
    codec: &Arc<EnvelopeCodec>,
    identity: GithubServerServiceAuthorityIdentity,
) -> ClaimedGithubServerServiceRevocation {
    let protected = protected(codec, identity.clone(), false).await;
    let claimed_at = UnixMillis::new(1_020_000);
    let receipt = receipt_from_protected(
        &protected,
        GithubServerServiceIssuanceState::RevokeClaimed,
        Some(UnixMillis::new(1_005_000)),
        claimed_at,
        1,
    );
    let claim = GithubServerServiceClaim::from_durable_parts(
        GithubServerServiceAuthoritySelector::from_identity(&identity),
        receipt.key(),
        worker(0x303),
        GithubServerServiceClaimFence::new(2).expect("claim fence"),
    )
    .expect("revocation claim");
    ClaimedGithubServerServiceRevocation::from_durable_parts(
        claim,
        identity,
        receipt,
        claimed_at,
        UnixMillis::new(1_100_000),
        protected,
    )
    .expect("claimed revocation")
}

fn minting_receipt(request: &BeginGithubServerServiceMint) -> GithubServerServiceIssuanceReceipt {
    plain_receipt(
        request.claim().key(),
        GithubServerServiceIssuanceState::Minting,
        request.started_at(),
        0,
    )
}

fn plain_receipt(
    key: GithubServerServiceIssuanceKey,
    state: GithubServerServiceIssuanceState,
    state_updated_at: UnixMillis,
    revoke_attempts: u16,
) -> GithubServerServiceIssuanceReceipt {
    GithubServerServiceIssuanceReceipt::from_durable_parts(
        key,
        state,
        1,
        revoke_attempts,
        UnixMillis::new(REQUESTED_AT),
        UnixMillis::new(REQUEST_DEADLINE),
        UnixMillis::new(CONSERVATIVE_EXPIRY),
        None,
        UnixMillis::new(CONSERVATIVE_EXPIRY),
        None,
        state_updated_at,
    )
    .expect("plain receipt")
}

fn provider_receipt(
    key: GithubServerServiceIssuanceKey,
    state: GithubServerServiceIssuanceState,
    state_updated_at: UnixMillis,
    revoke_attempts: u16,
) -> GithubServerServiceIssuanceReceipt {
    GithubServerServiceIssuanceReceipt::from_durable_parts(
        key,
        state,
        1,
        revoke_attempts,
        UnixMillis::new(REQUESTED_AT),
        UnixMillis::new(REQUEST_DEADLINE),
        UnixMillis::new(CONSERVATIVE_EXPIRY),
        Some(UnixMillis::new(PROVIDER_EXPIRES_AT)),
        UnixMillis::new(SAFE_ERASE_AFTER),
        Some(UnixMillis::new(1_005_000)),
        state_updated_at,
    )
    .expect("provider receipt")
}

fn receipt_from_protected(
    protected: &ProtectedGithubServerServiceCredential,
    state: GithubServerServiceIssuanceState,
    ready_at: Option<UnixMillis>,
    state_updated_at: UnixMillis,
    revoke_attempts: u16,
) -> GithubServerServiceIssuanceReceipt {
    let metadata = protected.metadata();
    GithubServerServiceIssuanceReceipt::from_durable_parts(
        GithubServerServiceIssuanceKey::new(
            metadata.identity().authority_id(),
            metadata.generation(),
        ),
        state,
        1,
        revoke_attempts,
        metadata.requested_at(),
        metadata.request_deadline(),
        UnixMillis::new(CONSERVATIVE_EXPIRY),
        metadata.provider_expires_at(),
        metadata.safe_erase_after(),
        ready_at,
        state_updated_at,
    )
    .expect("protected receipt")
}

fn ready_receipt(
    metadata: &GithubServerServiceEnvelopeMetadata,
) -> GithubServerServiceIssuanceReceipt {
    GithubServerServiceIssuanceReceipt::from_durable_parts(
        GithubServerServiceIssuanceKey::new(
            metadata.identity().authority_id(),
            metadata.generation(),
        ),
        GithubServerServiceIssuanceState::Ready,
        1,
        0,
        metadata.requested_at(),
        metadata.request_deadline(),
        UnixMillis::new(CONSERVATIVE_EXPIRY),
        metadata.provider_expires_at(),
        metadata.safe_erase_after(),
        Some(UnixMillis::new(1_005_000)),
        UnixMillis::new(1_005_000),
    )
    .expect("ready receipt")
}

async fn protected(
    codec: &Arc<EnvelopeCodec>,
    identity: GithubServerServiceAuthorityIdentity,
    corrupt: bool,
) -> ProtectedGithubServerServiceCredential {
    let candidate = FakeBroker::candidate();
    let frame = ServerServiceTokenFrame::new(&candidate);
    let metadata = GithubServerServiceEnvelopeMetadata::new(
        identity.clone(),
        GithubServerServiceGeneration::new(1).expect("generation"),
        UnixMillis::new(REQUESTED_AT),
        UnixMillis::new(REQUEST_DEADLINE),
        UnixMillis::new(PROVIDER_EXPIRES_AT),
        frame.size_bytes,
        frame.digest,
    )
    .expect("metadata");
    let wrapping = identity
        .wrapping_encryption_context(metadata.generation())
        .expect("wrapping context");
    let payload = metadata.encryption_context().expect("payload context");
    let prepared = codec.prepare(&wrapping).await.expect("prepare envelope");
    let envelope = prepared.seal_prepared(&payload, frame.plaintext);
    drop(candidate);
    let envelope = if corrupt {
        let (schema, wrapped, nonce, mut ciphertext) = envelope.into_parts();
        ciphertext[0] ^= 0x80;
        EncryptedEnvelope::from_parts(schema, wrapped, nonce, ciphertext)
            .expect("shape-valid corrupt envelope")
    } else {
        envelope
    };
    ProtectedGithubServerServiceCredential::new(metadata, envelope).expect("protected credential")
}

fn codec() -> Arc<EnvelopeCodec> {
    let key = LocalKeyMaterial::new(
        KeyId::new("server-service-test-key-v1").expect("key ID"),
        SecretBytes::new(vec![0x5a; 32]).expect("key material"),
    )
    .expect("local key material");
    let keys = LocalAes256GcmKeyring::new(key, Vec::new(), Vec::new()).expect("local keyring");
    Arc::new(EnvelopeCodec::new(Arc::new(keys)))
}

fn acquire_request(
    identity: &GithubServerServiceAuthorityIdentity,
    proposed: GithubServerServiceHandoffId,
    consumer: GithubServerServiceConsumerClaim,
) -> AcquireGithubServerServiceHandoff {
    AcquireGithubServerServiceHandoff::new(
        GithubServerServiceAuthoritySelector::from_identity(identity),
        proposed,
        consumer,
        UnixMillis::new(1_020_000),
        UnixMillis::new(2_000_000),
    )
    .expect("handoff request")
}

fn consumer(action: GithubServerServiceAction, id: u128) -> GithubServerServiceConsumerClaim {
    GithubServerServiceConsumerClaim::new(
        GithubServerServiceConsumerId::from_uuid(Uuid::from_u128(id)).expect("consumer"),
        worker(id + 1),
        GithubServerServiceClaimFence::new(7).expect("consumer fence"),
        action,
        GithubServerServiceRevision::new(9).expect("consumer revision"),
    )
}

fn action_handoff_id(action: GithubServerServiceAction) -> GithubServerServiceHandoffId {
    let value = match action {
        GithubServerServiceAction::EnsureCheckSuite => 0x701,
        GithubServerServiceAction::CreateCheckRun => 0x702,
        GithubServerServiceAction::ReconcileCheckRun => 0x703,
        GithubServerServiceAction::PublishCheckRun => 0x704,
        GithubServerServiceAction::FetchPrivateRepositoryRevision => 0x705,
        GithubServerServiceAction::FetchPrivateRepositoryChangedFiles => 0x706,
    };
    handoff_id(value)
}

fn handoff_id(value: u128) -> GithubServerServiceHandoffId {
    GithubServerServiceHandoffId::from_uuid(Uuid::from_u128(value)).expect("handoff ID")
}

fn worker(value: u128) -> GithubServerServiceWorkerId {
    GithubServerServiceWorkerId::from_uuid(Uuid::from_u128(value)).expect("worker")
}
