mod support;

use std::{
    collections::BTreeMap,
    sync::{
        Arc, Barrier, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use automata_ci_auth::{
    github::{
        DeviceCodeResponse, GithubAppAuthenticationProvider, GithubAppProtocol,
        GithubBrowserBindingCookie, GithubDeviceLoginPollOutcome, GithubDeviceLoginStart,
        GithubDevicePollCredential, GithubDevicePollResponse, GithubEndpointError,
        GithubInstallationAuthentication, GithubInstallationDevicePollOutcome,
        GithubLoginCompletion, GithubLoginConfigurationError, GithubLoginError,
        GithubLoginProofKey, GithubLoginProofKeyring, GithubLoginService,
        GithubLoginSessionLifetimes, GithubMembershipSnapshot, GithubWebCallback,
        GithubWebCallbackPurpose, GithubWebLoginStart, MAX_GITHUB_LOGIN_COLLISION_ATTEMPTS,
    },
    human::{
        AuthenticationFuture, AuthenticationProvider, AuthenticationProviderError, PrincipalId,
        ProviderCredential, ProviderId, TenantId,
    },
    login::{
        ConsumeLoginTransaction, ConsumeLoginTransactionOutcome, CreateLoginTransactionOutcome,
        LoadLoginTransactionOutcome, LoginBindingDigestKeyId, LoginReturnPath, LoginTransaction,
        LoginTransactionAccess, LoginTransactionFlow, LoginTransactionRepository,
        LoginTransactionRepositoryError, LoginTransactionRepositoryFuture, LoginTransactionState,
        LoginTransactionVersion, ReplaceLoginTransactionOutcome, ReplaceLoginTransactionState,
        VersionedLoginTransaction,
    },
    secret::{SecretBytes, SecretString},
    session::{
        CreateSession, CreateSessionOutcome, DurableSession, DurableSessionIdentity,
        HumanSessionRepository, ResolveSession, ResolveSessionOutcome, RevokeOwnSession,
        RevokeOwnSessionOutcome, RevokePrincipalSessions, RevokePrincipalSessionsOutcome,
        SessionId, SessionKind, SessionRepositoryFuture, SessionTokenLookup, TouchSession,
        TouchSessionOutcome,
    },
    session_credential::{
        SessionCredentialKey, SessionCredentialKeyring, SessionCredentialService,
    },
    sign_in::{
        FinalizeSignIn, FinalizeSignInOutcome, HumanSignInFinalizer, PendingSessionConflict,
        SignInFinalizerFuture,
    },
    time::{Clock, UnixTimestamp},
};
use futures::executor::block_on;
use static_assertions::assert_not_impl_any;
use url::Url;

use support::{DeterministicRandom, MockGithubEndpoint, config, secret, token_response};

assert_not_impl_any!(GithubLoginProofKey: Clone, serde::Serialize);
assert_not_impl_any!(GithubLoginProofKeyring: Clone, serde::Serialize);
assert_not_impl_any!(GithubBrowserBindingCookie: Clone, serde::Serialize);
assert_not_impl_any!(GithubDevicePollCredential: Clone, serde::Serialize);
assert_not_impl_any!(GithubWebLoginStart: Clone, serde::Serialize);
assert_not_impl_any!(GithubDeviceLoginStart: Clone, serde::Serialize);
assert_not_impl_any!(GithubDeviceLoginPollOutcome: Clone, serde::Serialize);
assert_not_impl_any!(GithubInstallationAuthentication: Clone, serde::Serialize);
assert_not_impl_any!(GithubInstallationDevicePollOutcome: Clone, serde::Serialize);
assert_not_impl_any!(GithubLoginCompletion: Clone, serde::Serialize);
assert_not_impl_any!(GithubLoginService: Clone, serde::Serialize);

const PRINCIPAL_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

#[derive(Debug)]
struct MutableClock(AtomicU64);

impl MutableClock {
    const fn new(seconds: u64) -> Self {
        Self(AtomicU64::new(seconds))
    }

    fn set(&self, seconds: u64) {
        self.0.store(seconds, Ordering::SeqCst);
    }
}

impl Clock for MutableClock {
    fn now(&self) -> UnixTimestamp {
        UnixTimestamp::from_seconds(self.0.load(Ordering::SeqCst))
    }
}

#[derive(Debug)]
struct StoredLogin {
    version: LoginTransactionVersion,
    transaction: LoginTransaction,
    consumed: bool,
}

#[derive(Debug, Default)]
struct MemoryLoginRepository {
    records: Mutex<BTreeMap<String, StoredLogin>>,
    load_barrier: Mutex<Option<Arc<Barrier>>>,
    replacements: AtomicUsize,
}

impl MemoryLoginRepository {
    fn set_load_barrier(&self, barrier: Arc<Barrier>) {
        *self.load_barrier.lock().expect("load barrier") = Some(barrier);
    }

    fn replacement_count(&self) -> usize {
        self.replacements.load(Ordering::SeqCst)
    }

    fn tamper_state(&self, id: &str) {
        let mut records = self.records.lock().expect("login records");
        let record = records.get_mut(id).expect("stored login");
        record.transaction = copy_transaction_with_state(
            &record.transaction,
            LoginTransactionState::new(
                SecretBytes::new(b"not-a-github-state-codec".to_vec()).expect("tamper bytes"),
            ),
            None,
            None,
        );
    }
}

impl LoginTransactionRepository for MemoryLoginRepository {
    fn create(
        &self,
        transaction: LoginTransaction,
    ) -> LoginTransactionRepositoryFuture<'_, CreateLoginTransactionOutcome> {
        let id = transaction.id().as_str().to_owned();
        let mut records = self.records.lock().expect("login records");
        let outcome = if let std::collections::btree_map::Entry::Vacant(entry) = records.entry(id) {
            entry.insert(StoredLogin {
                version: LoginTransactionVersion::new(1).expect("initial version"),
                transaction,
                consumed: false,
            });
            CreateLoginTransactionOutcome::Created(
                LoginTransactionVersion::new(1).expect("initial version"),
            )
        } else {
            CreateLoginTransactionOutcome::AlreadyExists
        };
        Box::pin(async move { Ok(outcome) })
    }

    fn load<'a>(
        &'a self,
        access: &'a LoginTransactionAccess,
        now: UnixTimestamp,
    ) -> LoginTransactionRepositoryFuture<'a, LoadLoginTransactionOutcome> {
        let outcome = {
            let records = self.records.lock().expect("login records");
            match records.get(access.id().as_str()) {
                None => LoadLoginTransactionOutcome::NotFound,
                Some(record) if !matches_access(&record.transaction, access) => {
                    LoadLoginTransactionOutcome::NotFound
                }
                Some(record) if record.consumed => LoadLoginTransactionOutcome::Consumed,
                Some(record) if now >= record.transaction.expires_at() => {
                    LoadLoginTransactionOutcome::Expired
                }
                Some(record) => {
                    LoadLoginTransactionOutcome::Active(Box::new(VersionedLoginTransaction::new(
                        record.version,
                        copy_transaction(&record.transaction),
                    )))
                }
            }
        };
        let load_barrier = self.load_barrier.lock().expect("load barrier").clone();
        if matches!(outcome, LoadLoginTransactionOutcome::Active(_))
            && let Some(barrier) = load_barrier
        {
            barrier.wait();
        }
        Box::pin(async move { Ok(outcome) })
    }

    fn replace_state(
        &self,
        request: ReplaceLoginTransactionState,
        now: UnixTimestamp,
    ) -> LoginTransactionRepositoryFuture<'_, ReplaceLoginTransactionOutcome> {
        if request.validate().is_err() {
            return Box::pin(async { Err(LoginTransactionRepositoryError::InvalidRequest) });
        }
        let (access, expected, replacement, next_poll_at, poll_interval) = request.into_parts();
        let mut records = self.records.lock().expect("login records");
        let outcome = match records.get_mut(access.id().as_str()) {
            None => ReplaceLoginTransactionOutcome::NotFound,
            Some(record) if !matches_access(&record.transaction, &access) => {
                ReplaceLoginTransactionOutcome::NotFound
            }
            Some(record) if record.consumed => ReplaceLoginTransactionOutcome::Consumed,
            Some(record) if now >= record.transaction.expires_at() => {
                ReplaceLoginTransactionOutcome::Expired
            }
            Some(record) if record.version != expected => {
                ReplaceLoginTransactionOutcome::VersionConflict
            }
            Some(record) => {
                record.transaction = copy_transaction_with_state(
                    &record.transaction,
                    replacement,
                    next_poll_at,
                    poll_interval,
                );
                record.version = next_version(record.version);
                self.replacements.fetch_add(1, Ordering::SeqCst);
                ReplaceLoginTransactionOutcome::Replaced(record.version)
            }
        };
        Box::pin(async move { Ok(outcome) })
    }

    fn consume(
        &self,
        request: ConsumeLoginTransaction,
    ) -> LoginTransactionRepositoryFuture<'_, ConsumeLoginTransactionOutcome> {
        let mut records = self.records.lock().expect("login records");
        let outcome = match records.get_mut(request.access().id().as_str()) {
            None => ConsumeLoginTransactionOutcome::NotFound,
            Some(record) if !matches_access(&record.transaction, request.access()) => {
                ConsumeLoginTransactionOutcome::NotFound
            }
            Some(record) if record.consumed => ConsumeLoginTransactionOutcome::AlreadyConsumed,
            Some(record) if request.now() >= record.transaction.expires_at() => {
                ConsumeLoginTransactionOutcome::Expired
            }
            Some(record)
                if request
                    .expected_version()
                    .is_some_and(|expected| expected != record.version) =>
            {
                ConsumeLoginTransactionOutcome::VersionConflict
            }
            Some(record) => {
                let transaction = copy_transaction(&record.transaction);
                record.version = next_version(record.version);
                record.consumed = true;
                ConsumeLoginTransactionOutcome::Consumed(Box::new(transaction))
            }
        };
        Box::pin(async move { Ok(outcome) })
    }
}

fn matches_access(transaction: &LoginTransaction, access: &LoginTransactionAccess) -> bool {
    if transaction.id() != access.id()
        || transaction.purpose() != access.purpose()
        || transaction.provider_id() != access.provider_id()
        || transaction.kind() != access.kind()
    {
        return false;
    }
    match (transaction.flow(), access.proof()) {
        (
            LoginTransactionFlow::Browser {
                state,
                client_binding,
            },
            automata_ci_auth::login::LoginTransactionProof::Browser {
                state: supplied_state,
                client_binding: supplied_client,
            },
        ) => state == supplied_state && client_binding == supplied_client,
        (
            LoginTransactionFlow::Device { poll_proof, .. },
            automata_ci_auth::login::LoginTransactionProof::Device {
                poll_proof: supplied,
            },
        ) => poll_proof == supplied,
        _ => false,
    }
}

fn copy_transaction(transaction: &LoginTransaction) -> LoginTransaction {
    let state = LoginTransactionState::new(
        SecretBytes::new(transaction.state().expose_secret().to_vec()).expect("copied state"),
    );
    copy_transaction_with_state(transaction, state, None, None)
}

fn copy_transaction_with_state(
    transaction: &LoginTransaction,
    state: LoginTransactionState,
    next_poll_at: Option<UnixTimestamp>,
    poll_interval_milliseconds: Option<u64>,
) -> LoginTransaction {
    let flow = match transaction.flow() {
        LoginTransactionFlow::Browser {
            state,
            client_binding,
        } => LoginTransactionFlow::browser(state.clone(), client_binding.clone())
            .expect("copied browser flow"),
        LoginTransactionFlow::Device {
            poll_proof,
            user_code,
            verification_uri,
            poll_interval_milliseconds: current_interval,
            next_poll_at: current_next_poll,
        } => LoginTransactionFlow::device(
            poll_proof.clone(),
            SecretString::new(user_code.expose_secret()).expect("copied user code"),
            verification_uri.clone(),
            poll_interval_milliseconds.unwrap_or(*current_interval),
            next_poll_at.unwrap_or(*current_next_poll),
        )
        .expect("copied device flow"),
    };
    LoginTransaction::new(
        transaction.id().clone(),
        transaction.purpose().clone(),
        transaction.provider_id().clone(),
        flow,
        transaction.return_path().cloned(),
        state,
        transaction.created_at(),
        transaction.expires_at(),
    )
    .expect("copied transaction")
}

fn next_version(version: LoginTransactionVersion) -> LoginTransactionVersion {
    LoginTransactionVersion::new(version.value() + 1).expect("next version")
}

#[derive(Debug)]
struct UnusedSessionRepository;

impl HumanSessionRepository for UnusedSessionRepository {
    fn create(&self, _request: CreateSession) -> SessionRepositoryFuture<'_, CreateSessionOutcome> {
        panic!("coordinator preparation must not create outside the finalizer")
    }

    fn resolve<'a>(
        &'a self,
        _request: &'a ResolveSession,
    ) -> SessionRepositoryFuture<'a, ResolveSessionOutcome> {
        panic!("unused session resolve")
    }

    fn touch<'a>(
        &'a self,
        _request: &'a TouchSession,
    ) -> SessionRepositoryFuture<'a, TouchSessionOutcome> {
        panic!("unused session touch")
    }

    fn revoke_own<'a>(
        &'a self,
        _request: &'a RevokeOwnSession,
    ) -> SessionRepositoryFuture<'a, RevokeOwnSessionOutcome> {
        panic!("unused session revoke")
    }

    fn revoke_principal<'a>(
        &'a self,
        _request: &'a RevokePrincipalSessions,
    ) -> SessionRepositoryFuture<'a, RevokePrincipalSessionsOutcome> {
        panic!("unused principal revoke")
    }
}

#[derive(Debug, Default)]
struct FinalizerObservations {
    calls: usize,
    session_ids: Vec<SessionId>,
    session_lookups: Vec<SessionTokenLookup>,
    kind: Option<SessionKind>,
    provider_subject: Option<String>,
    token_subject: Option<String>,
    expected_version: Option<u64>,
    membership_count: Option<usize>,
}

#[derive(Debug)]
struct AdmittingFinalizer {
    observations: Mutex<FinalizerObservations>,
    collisions_remaining: Mutex<usize>,
    return_path: Option<LoginReturnPath>,
}

impl AdmittingFinalizer {
    fn new(collisions: usize, return_path: Option<LoginReturnPath>) -> Self {
        Self {
            observations: Mutex::new(FinalizerObservations::default()),
            collisions_remaining: Mutex::new(collisions),
            return_path,
        }
    }

    fn calls(&self) -> usize {
        self.observations
            .lock()
            .expect("finalizer observations")
            .calls
    }
}

impl HumanSignInFinalizer for AdmittingFinalizer {
    fn finalize(&self, request: FinalizeSignIn) -> SignInFinalizerFuture<'_> {
        let mut observations = self.observations.lock().expect("finalizer observations");
        observations.calls += 1;
        observations
            .session_ids
            .push(request.session().session_id().clone());
        observations
            .session_lookups
            .push(request.session().lookup().clone());
        observations.kind = Some(request.session().kind());
        observations.provider_subject = Some(request.identity().provider_subject().as_str().into());
        observations.token_subject = request
            .provider_tokens()
            .metadata()
            .provider_subject()
            .map(|subject| subject.as_str().to_owned());
        observations.expected_version = Some(request.expected_version().value());
        observations.membership_count = Some(
            request.membership().memberships().organizations().len()
                + request.membership().memberships().teams().len(),
        );
        drop(observations);

        let mut collisions = self.collisions_remaining.lock().expect("collision counter");
        if *collisions > 0 {
            *collisions -= 1;
            let (retry, _collided_candidate) = request.into_retry_parts();
            return Box::pin(async move {
                Ok(FinalizeSignInOutcome::SessionConflict {
                    conflict: PendingSessionConflict::SessionId,
                    retry: Box::new(retry),
                })
            });
        }
        drop(collisions);

        let tenant_id = request
            .access()
            .tenant_id()
            .expect("sign-in tenant")
            .clone();
        let identity = request.identity().clone();
        let (retry, candidate) = request.into_retry_parts();
        drop(retry);
        let human = identity
            .into_authenticated_human(PrincipalId::new(PRINCIPAL_ID).expect("principal UUID"));
        let (session_id, _lookup, kind, issued_at, idle_expires_at, expires_at) =
            candidate.into_parts();
        let durable_identity = DurableSessionIdentity::new(
            session_id,
            tenant_id,
            human.principal_id().clone(),
            human.provider_id().clone(),
            human.provider_subject().clone(),
            kind,
        )
        .expect("durable identity");
        let session = DurableSession::new(
            durable_identity,
            7,
            issued_at,
            issued_at,
            idle_expires_at,
            expires_at,
            None,
        )
        .expect("durable session");
        let return_path = self.return_path.clone();
        Box::pin(async move {
            Ok(FinalizeSignInOutcome::Admitted {
                human,
                session: Box::new(session),
                current_authorization_revision: 7,
                return_path,
            })
        })
    }
}

struct Fixture {
    endpoint: Arc<MockGithubEndpoint>,
    repository: Arc<MemoryLoginRepository>,
    clock: Arc<MutableClock>,
    random: Arc<DeterministicRandom>,
    sessions: Arc<SessionCredentialService>,
    finalizer: Arc<AdmittingFinalizer>,
}

impl Fixture {
    fn new(collisions: usize) -> Self {
        let endpoint = MockGithubEndpoint::shared();
        let repository = Arc::new(MemoryLoginRepository::default());
        let clock = Arc::new(MutableClock::new(100));
        let random = Arc::new(DeterministicRandom::new(1));
        let session_key = SessionCredentialKey::new(
            automata_ci_auth::session::SessionTokenDigestKeyId::new("session-v1")
                .expect("session key ID"),
            SecretBytes::new(vec![0x91; 32]).expect("session key material"),
        )
        .expect("session credential key");
        let sessions = Arc::new(SessionCredentialService::new(
            SessionCredentialKeyring::new(session_key, Vec::new()).expect("session keyring"),
            Arc::new(UnusedSessionRepository),
            random.clone(),
            clock.clone(),
        ));
        let finalizer = Arc::new(AdmittingFinalizer::new(
            collisions,
            Some(LoginReturnPath::new("/projects").expect("return path")),
        ));
        Self {
            endpoint,
            repository,
            clock,
            random,
            sessions,
            finalizer,
        }
    }

    fn service(
        &self,
        active_id: &str,
        active_byte: u8,
        verify_only: &[(&str, u8)],
    ) -> Arc<GithubLoginService> {
        let authentication = Arc::new(GithubAppAuthenticationProvider::new(
            ProviderId::new("github").expect("provider"),
            self.endpoint.clone(),
            self.clock.clone(),
        ));
        let proof_keys = GithubLoginProofKeyring::new(
            proof_key(active_id, active_byte),
            verify_only
                .iter()
                .map(|(id, byte)| proof_key(id, *byte))
                .collect(),
        )
        .expect("proof keyring");
        Arc::new(
            GithubLoginService::new(
                GithubAppProtocol::new(config()),
                self.endpoint.clone(),
                authentication,
                self.repository.clone(),
                self.sessions.clone(),
                self.finalizer.clone(),
                proof_keys,
                self.random.clone(),
                self.clock.clone(),
                GithubLoginSessionLifetimes::new(
                    Duration::from_mins(30),
                    Duration::from_hours(8),
                    Duration::from_hours(1),
                    Duration::from_hours(720),
                )
                .expect("login lifetimes"),
            )
            .expect("GitHub login service"),
        )
    }
}

fn proof_key(id: &str, byte: u8) -> GithubLoginProofKey {
    GithubLoginProofKey::new(
        LoginBindingDigestKeyId::new(id).expect("proof key ID"),
        SecretBytes::new(vec![byte; 32]).expect("proof key material"),
    )
    .expect("proof key")
}

fn tenant(value: &str) -> TenantId {
    TenantId::new(value).expect("tenant")
}

fn return_path() -> LoginReturnPath {
    LoginReturnPath::new("/projects").expect("return path")
}

fn authorization_state(url: &Url) -> String {
    url.query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .expect("OAuth state query")
}

fn authorized_callback(state: &str) -> GithubWebCallback {
    GithubWebCallback::Authorized {
        code: secret("one-use-code-never-return"),
        state: secret(state),
    }
}

fn callback_purpose(
    service: &GithubLoginService,
    tenant_id: &str,
    cookie: &str,
    state: &str,
) -> Result<GithubWebCallbackPurpose, GithubLoginError> {
    block_on(service.classify_web_callback_purpose(
        &tenant(tenant_id),
        &GithubBrowserBindingCookie::from_raw(cookie).expect("browser binding cookie"),
        &authorized_callback(state),
    ))
}

fn device_response() -> DeviceCodeResponse {
    DeviceCodeResponse {
        device_code: secret("device-code-never-return"),
        user_code: secret("ABCD-EFGH"),
        verification_uri: Url::parse("https://github.com/login/device").expect("verification URI"),
        expires_in: 900,
        interval: 5,
    }
}

fn push_identity(endpoint: &MockGithubEndpoint, id: u64) {
    endpoint.push_user(Ok(automata_ci_auth::github::GithubUser {
        id,
        login: "renamed-user".to_owned(),
        name: Some("Renamed User".to_owned()),
    }));
    endpoint.push_memberships(Ok(GithubMembershipSnapshot::default()));
}

fn assert_fresh_finalizer_candidates(
    observations: &FinalizerObservations,
    sessions: &SessionCredentialService,
    completion: &GithubLoginCompletion,
) {
    let returned_lookup = sessions
        .derive_lookup_raw(
            completion.credential().expose_secret(),
            SessionKind::Browser,
        )
        .expect("returned credential lookup");
    assert_eq!(observations.calls, 3);
    assert_eq!(observations.session_ids.len(), 3);
    assert_ne!(observations.session_ids[0], observations.session_ids[1]);
    assert_ne!(observations.session_ids[0], observations.session_ids[2]);
    assert_ne!(observations.session_ids[1], observations.session_ids[2]);
    assert_eq!(observations.session_lookups.len(), 3);
    assert_ne!(
        observations.session_lookups[0],
        observations.session_lookups[1]
    );
    assert_ne!(
        observations.session_lookups[0],
        observations.session_lookups[2]
    );
    assert_ne!(
        observations.session_lookups[1],
        observations.session_lookups[2]
    );
    assert_eq!(observations.session_lookups.last(), Some(&returned_lookup));
    assert_eq!(
        observations.session_ids.last(),
        Some(completion.session().identity().session_id())
    );
}

#[test]
fn web_sign_in_rotates_proof_keys_retries_safe_collisions_and_rejects_replay() {
    let fixture = Fixture::new(2);
    let issuing_service = fixture.service("login-old", 0x41, &[]);
    let started = block_on(issuing_service.begin_web(tenant("tenant-a"), return_path()))
        .expect("begin web login");
    let state = authorization_state(started.authorization_url());
    let cookie_raw = started.binding_cookie().expose_secret().to_owned();
    let cookie_debug = format!("{:?}", started.binding_cookie());
    assert!(!cookie_debug.contains(cookie_raw.rsplit('~').next().expect("proof")));
    assert!(GithubDevicePollCredential::from_raw(&cookie_raw).is_err());

    let rotated_service = fixture.service("login-new", 0x42, &[("login-old", 0x41)]);
    assert_eq!(
        callback_purpose(&rotated_service, "tenant-a", &cookie_raw, &state)
            .expect("classify ordinary web callback"),
        GithubWebCallbackPurpose::SignIn
    );
    fixture.endpoint.push_web(Ok(token_response()));
    push_identity(&fixture.endpoint, 42);
    fixture.clock.set(110);
    let completion = block_on(rotated_service.complete_web(
        tenant("tenant-a"),
        GithubBrowserBindingCookie::from_raw(&cookie_raw).expect("old binding cookie"),
        &authorized_callback(&state),
    ))
    .expect("complete rotated web login");

    assert_eq!(completion.session().identity().kind(), SessionKind::Browser);
    assert_eq!(completion.human().provider_subject().as_str(), "42");
    assert_eq!(completion.current_authorization_revision(), 7);
    assert_eq!(
        completion.return_path().map(LoginReturnPath::as_str),
        Some("/projects")
    );
    assert!(
        completion
            .credential()
            .expose_secret()
            .starts_with("v1~session-v1~")
    );
    assert!(
        !completion
            .credential()
            .expose_secret()
            .contains("ghu_access_token_value")
    );
    let completion_debug = format!("{completion:?}");
    assert!(!completion_debug.contains(completion.credential().expose_secret()));
    assert!(!completion_debug.contains("ghu_access_token_value"));

    let observed = fixture
        .endpoint
        .observed
        .lock()
        .expect("endpoint observations");
    assert_eq!(observed.web_calls, 1);
    assert_eq!(observed.current_user_calls, 1);
    assert_eq!(observed.membership_calls, 1);
    assert_eq!(
        observed.membership_token.as_deref(),
        Some("ghu_access_token_value")
    );
    drop(observed);
    let finalizer = fixture
        .finalizer
        .observations
        .lock()
        .expect("finalizer observations");
    assert_fresh_finalizer_candidates(&finalizer, fixture.sessions.as_ref(), &completion);
    assert_eq!(finalizer.kind, Some(SessionKind::Browser));
    assert_eq!(finalizer.provider_subject.as_deref(), Some("42"));
    assert_eq!(finalizer.token_subject.as_deref(), Some("42"));
    assert_eq!(finalizer.expected_version, Some(2));
    assert_eq!(finalizer.membership_count, Some(0));
    drop(finalizer);

    let replay = block_on(rotated_service.complete_web(
        tenant("tenant-a"),
        GithubBrowserBindingCookie::from_raw(&cookie_raw).expect("replay cookie"),
        &authorized_callback(&state),
    ));
    assert_eq!(
        replay.expect_err("callback replay must fail"),
        GithubLoginError::Replay
    );
    assert_eq!(
        callback_purpose(&rotated_service, "tenant-a", &cookie_raw, &state)
            .expect_err("consumed callback cannot be dispatched again"),
        GithubLoginError::Replay
    );
    let observed = fixture
        .endpoint
        .observed
        .lock()
        .expect("endpoint observations");
    assert_eq!(
        observed.web_calls, 1,
        "replay must not exchange another code"
    );
    assert_eq!(
        observed.current_user_calls, 1,
        "replay must not re-fetch identity"
    );
}

#[test]
fn web_sign_in_stops_after_exact_session_collision_budget() {
    let fixture = Fixture::new(MAX_GITHUB_LOGIN_COLLISION_ATTEMPTS);
    let service = fixture.service("login-v1", 0x43, &[]);
    let started =
        block_on(service.begin_web(tenant("tenant-a"), return_path())).expect("begin web login");
    let state = authorization_state(started.authorization_url());
    let cookie_raw = started.binding_cookie().expose_secret().to_owned();

    fixture.endpoint.push_web(Ok(token_response()));
    push_identity(&fixture.endpoint, 42);
    fixture.clock.set(110);
    let result = block_on(service.complete_web(
        tenant("tenant-a"),
        GithubBrowserBindingCookie::from_raw(&cookie_raw).expect("browser binding cookie"),
        &authorized_callback(&state),
    ));

    assert_eq!(
        result.expect_err("collision budget must be enforced"),
        GithubLoginError::CollisionLimitExceeded
    );
    let finalizer = fixture
        .finalizer
        .observations
        .lock()
        .expect("finalizer observations");
    assert_eq!(finalizer.calls, MAX_GITHUB_LOGIN_COLLISION_ATTEMPTS);
    assert_eq!(
        finalizer.session_ids.len(),
        MAX_GITHUB_LOGIN_COLLISION_ATTEMPTS
    );
    assert_eq!(
        finalizer.session_lookups.len(),
        MAX_GITHUB_LOGIN_COLLISION_ATTEMPTS
    );
}

#[test]
fn installation_web_flow_is_purpose_bound_consumed_and_returns_no_session() {
    let fixture = Fixture::new(0);
    let service = fixture.service("setup-v1", 0x61, &[]);
    let started = block_on(service.begin_installation_web(return_path()))
        .expect("begin installation web login");
    assert_eq!(
        started
            .authorization_url()
            .query_pairs()
            .find_map(|(key, value)| (key == "redirect_uri").then(|| value.into_owned()))
            .as_deref(),
        Some("https://automata.example/auth/github/callback"),
        "setup must return through the one provider-configured shared callback"
    );
    let state = authorization_state(started.authorization_url());
    let cookie_raw = started.binding_cookie().expose_secret().to_owned();

    for _ in 0..2 {
        assert_eq!(
            callback_purpose(&service, "tenant-a", &cookie_raw, &state)
                .expect("classify installation callback"),
            GithubWebCallbackPurpose::InstallationSetup
        );
    }

    let wrong_purpose = block_on(service.complete_web(
        tenant("tenant-a"),
        GithubBrowserBindingCookie::from_raw(&cookie_raw).expect("binding cookie"),
        &authorized_callback(&state),
    ));
    assert_eq!(
        wrong_purpose.expect_err("setup proof cannot be replayed as sign-in"),
        GithubLoginError::Invalid
    );
    assert_eq!(
        callback_purpose(&service, "tenant-a", &cookie_raw, &state)
            .expect("wrong-purpose attempt must not consume setup"),
        GithubWebCallbackPurpose::InstallationSetup
    );

    fixture.endpoint.push_web(Ok(token_response()));
    push_identity(&fixture.endpoint, 42);
    fixture.clock.set(110);
    let completed = block_on(service.complete_installation_web(
        GithubBrowserBindingCookie::from_raw(&cookie_raw).expect("binding cookie"),
        &authorized_callback(&state),
    ))
    .expect("complete installation web authentication");
    assert_eq!(completed.identity().provider_subject().as_str(), "42");
    assert_eq!(
        completed.return_path().map(LoginReturnPath::as_str),
        Some("/projects")
    );
    let debug = format!("{completed:?}");
    assert!(!debug.contains("ghu_access_token_value"));
    assert!(!debug.contains("refresh-token-value"));
    let (_, identity, tokens, membership, _) = completed.into_parts();
    assert_eq!(
        tokens.metadata().provider_subject(),
        Some(identity.provider_subject())
    );
    assert_eq!(membership.memberships().organizations().len(), 0);

    let observations = fixture
        .finalizer
        .observations
        .lock()
        .expect("finalizer observations");
    assert_eq!(
        observations.calls, 0,
        "setup must not call sign-in finalizer"
    );
    drop(observations);
    let replay = block_on(service.complete_installation_web(
        GithubBrowserBindingCookie::from_raw(&cookie_raw).expect("replay binding"),
        &authorized_callback(&state),
    ));
    assert_eq!(replay.unwrap_err(), GithubLoginError::Replay);
    assert_eq!(
        callback_purpose(&service, "tenant-a", &cookie_raw, &state)
            .expect_err("consumed setup cannot be dispatched again"),
        GithubLoginError::Replay
    );
}

#[test]
fn shared_callback_classifier_rejects_tenant_state_and_client_proof_steering() {
    let fixture = Fixture::new(0);
    let service = fixture.service("login-v1", 0x63, &[]);
    let sign_in = block_on(service.begin_web(tenant("tenant-a"), return_path()))
        .expect("begin sign-in callback");
    let sign_in_state = authorization_state(sign_in.authorization_url());
    let sign_in_cookie = sign_in.binding_cookie().expose_secret().to_owned();
    let setup = block_on(service.begin_installation_web(return_path()))
        .expect("begin installation callback");
    let setup_state = authorization_state(setup.authorization_url());
    let setup_cookie = setup.binding_cookie().expose_secret().to_owned();

    let wrong_tenant = callback_purpose(&service, "tenant-b", &sign_in_cookie, &sign_in_state)
        .expect_err("another tenant cannot classify a sign-in callback");
    assert_eq!(wrong_tenant, GithubLoginError::Invalid);

    let mixed_state = callback_purpose(&service, "tenant-a", &setup_cookie, &sign_in_state)
        .expect_err("another transaction's state cannot select setup");
    assert_eq!(mixed_state, GithubLoginError::Invalid);

    let mut forged_cookie = setup_cookie.clone();
    let proof_start = forged_cookie.rfind('~').expect("proof separator") + 1;
    let replacement = if forged_cookie.as_bytes()[proof_start] == b'A' {
        "B"
    } else {
        "A"
    };
    forged_cookie.replace_range(proof_start..=proof_start, replacement);
    let forged = callback_purpose(&service, "tenant-a", &forged_cookie, &setup_state)
        .expect_err("forged client proof cannot select setup");
    assert_eq!(forged, GithubLoginError::Invalid);

    fixture.clock.set(sign_in.expires_at().as_seconds());
    let expired = callback_purpose(&service, "tenant-a", &sign_in_cookie, &sign_in_state)
        .expect_err("expired callback cannot be dispatched");
    assert_eq!(expired, GithubLoginError::Expired);
    assert_eq!(
        fixture
            .endpoint
            .observed
            .lock()
            .expect("endpoint observations")
            .web_calls,
        0,
        "classification must not exchange a provider code"
    );
    let rendered = format!("{wrong_tenant:?}{mixed_state:?}{forged:?}{expired:?}");
    assert!(!rendered.contains(&sign_in_state));
    assert!(!rendered.contains(&setup_state));
    assert!(!rendered.contains(&sign_in_cookie));
    assert!(!rendered.contains(&setup_cookie));
}

#[test]
fn installation_device_flow_is_purpose_bound_and_returns_linear_authentication() {
    let fixture = Fixture::new(0);
    let service = fixture.service("setup-v1", 0x62, &[]);
    fixture.endpoint.push_device_code(Ok(device_response()));
    let started = block_on(service.begin_installation_device(Some(return_path())))
        .expect("begin installation device login");
    let poll_raw = started.poll_credential().expose_secret().to_owned();

    fixture.clock.set(105);
    let wrong_purpose = block_on(service.poll_device(
        tenant("tenant-a"),
        GithubDevicePollCredential::from_raw(&poll_raw).expect("poll credential"),
    ));
    assert_eq!(
        wrong_purpose.expect_err("setup proof cannot be replayed as sign-in"),
        GithubLoginError::Invalid
    );

    fixture
        .endpoint
        .push_device_poll(Ok(GithubDevicePollResponse::Token(token_response())));
    push_identity(&fixture.endpoint, 42);
    let completed = block_on(service.poll_installation_device(
        GithubDevicePollCredential::from_raw(&poll_raw).expect("poll credential"),
    ))
    .expect("complete installation device authentication");
    let GithubInstallationDevicePollOutcome::Complete(authentication) = completed else {
        panic!("expected installation device completion");
    };
    assert_eq!(authentication.identity().provider_subject().as_str(), "42");
    assert_eq!(
        authentication.return_path().map(LoginReturnPath::as_str),
        Some("/projects")
    );
    assert!(!format!("{authentication:?}").contains("ghu_access_token_value"));
    let (_, identity, tokens, membership, _) = authentication.into_parts();
    assert_eq!(
        tokens.metadata().provider_subject(),
        Some(identity.provider_subject())
    );
    assert_eq!(membership.memberships().teams().len(), 0);
    assert_eq!(
        fixture
            .finalizer
            .observations
            .lock()
            .expect("finalizer observations")
            .calls,
        0,
        "setup must not call sign-in finalizer"
    );

    let replay = block_on(service.poll_installation_device(
        GithubDevicePollCredential::from_raw(&poll_raw).expect("replay poll credential"),
    ));
    assert_eq!(replay.unwrap_err(), GithubLoginError::Replay);
}

#[test]
fn state_binding_tenant_key_and_durable_codec_fail_before_provider_io() {
    let fixture = Fixture::new(0);
    let service = fixture.service("login-v1", 0x51, &[]);
    let first =
        block_on(service.begin_web(tenant("tenant-a"), return_path())).expect("first web start");
    let first_state = authorization_state(first.authorization_url());
    let first_cookie = first.binding_cookie().expose_secret().to_owned();
    let second =
        block_on(service.begin_web(tenant("tenant-a"), return_path())).expect("second web start");
    let second_cookie = second.binding_cookie().expose_secret().to_owned();

    let mixed = block_on(service.complete_web(
        tenant("tenant-a"),
        GithubBrowserBindingCookie::from_raw(&second_cookie).expect("second cookie"),
        &authorized_callback(&first_state),
    ));
    assert_eq!(
        mixed.expect_err("mixed state and binding"),
        GithubLoginError::Invalid
    );

    let wrong_tenant = block_on(service.complete_web(
        tenant("tenant-b"),
        GithubBrowserBindingCookie::from_raw(&first_cookie).expect("first cookie"),
        &authorized_callback(&first_state),
    ));
    assert_eq!(
        wrong_tenant.expect_err("wrong tenant"),
        GithubLoginError::Invalid
    );

    let removed_key_service = fixture.service("login-v2", 0x52, &[]);
    let removed_key = block_on(removed_key_service.complete_web(
        tenant("tenant-a"),
        GithubBrowserBindingCookie::from_raw(&first_cookie).expect("old cookie"),
        &authorized_callback(&first_state),
    ));
    assert_eq!(
        removed_key.expect_err("removed key"),
        GithubLoginError::Invalid
    );
    assert_eq!(
        fixture
            .endpoint
            .observed
            .lock()
            .expect("endpoint observations")
            .web_calls,
        0
    );

    let tampered_fixture = Fixture::new(0);
    let tampered_service = tampered_fixture.service("login-v1", 0x61, &[]);
    let tampered = block_on(tampered_service.begin_web(tenant("tenant-a"), return_path()))
        .expect("tampered web start");
    let tampered_state = authorization_state(tampered.authorization_url());
    let tampered_cookie = tampered.binding_cookie().expose_secret().to_owned();
    tampered_fixture
        .repository
        .tamper_state(tampered.binding_cookie().transaction_id().as_str());
    let result = block_on(tampered_service.complete_web(
        tenant("tenant-a"),
        GithubBrowserBindingCookie::from_raw(&tampered_cookie).expect("tampered cookie"),
        &authorized_callback(&tampered_state),
    ));
    assert_eq!(
        result.expect_err("tampered durable codec"),
        GithubLoginError::IntegrityFailure
    );
    assert_eq!(
        tampered_fixture
            .endpoint
            .observed
            .lock()
            .expect("endpoint observations")
            .web_calls,
        0
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn device_poll_persists_failure_and_slowdown_then_returns_only_cli_credential() {
    let fixture = Fixture::new(0);
    let service = fixture.service("login-v1", 0x71, &[]);
    fixture.endpoint.push_device_code(Ok(device_response()));
    let started =
        block_on(service.begin_device(tenant("tenant-a"), None)).expect("begin device login");
    assert_eq!(started.user_code(), "ABCD-EFGH");
    assert_eq!(started.poll_interval(), Duration::from_secs(5));
    let poll_raw = started.poll_credential().expose_secret().to_owned();
    assert!(GithubBrowserBindingCookie::from_raw(&poll_raw).is_err());
    assert!(!format!("{started:?}").contains("device-code-never-return"));

    fixture.clock.set(105);
    fixture
        .endpoint
        .push_device_poll(Err(GithubEndpointError::Unavailable));
    let failed = block_on(service.poll_device(
        tenant("tenant-a"),
        GithubDevicePollCredential::from_raw(&poll_raw).expect("poll credential"),
    ));
    assert_eq!(
        failed.expect_err("provider failure"),
        GithubLoginError::ProviderUnavailable
    );
    assert_eq!(fixture.repository.replacement_count(), 1);

    let too_early = block_on(service.poll_device(
        tenant("tenant-a"),
        GithubDevicePollCredential::from_raw(&poll_raw).expect("poll credential"),
    ));
    assert!(matches!(
        too_early,
        Err(GithubLoginError::PollTooEarly { next_poll_at })
            if next_poll_at == UnixTimestamp::from_seconds(110)
    ));

    fixture.clock.set(110);
    fixture
        .endpoint
        .push_device_poll(Ok(GithubDevicePollResponse::SlowDown));
    let slowed = block_on(service.poll_device(
        tenant("tenant-a"),
        GithubDevicePollCredential::from_raw(&poll_raw).expect("poll credential"),
    ))
    .expect("slow-down outcome");
    assert!(matches!(
        slowed,
        GithubDeviceLoginPollOutcome::SlowDown { next_poll_at }
            if next_poll_at == UnixTimestamp::from_seconds(120)
    ));
    assert_eq!(fixture.repository.replacement_count(), 2);

    fixture.clock.set(115);
    let persisted_interval = block_on(service.poll_device(
        tenant("tenant-a"),
        GithubDevicePollCredential::from_raw(&poll_raw).expect("poll credential"),
    ));
    assert!(matches!(
        persisted_interval,
        Err(GithubLoginError::PollTooEarly { next_poll_at })
            if next_poll_at == UnixTimestamp::from_seconds(120)
    ));

    fixture.clock.set(120);
    fixture
        .endpoint
        .push_device_poll(Ok(GithubDevicePollResponse::AuthorizationPending));
    let pending = block_on(service.poll_device(
        tenant("tenant-a"),
        GithubDevicePollCredential::from_raw(&poll_raw).expect("poll credential"),
    ))
    .expect("pending device outcome");
    assert!(matches!(
        pending,
        GithubDeviceLoginPollOutcome::Pending { next_poll_at }
            if next_poll_at == UnixTimestamp::from_seconds(130)
    ));
    assert_eq!(fixture.repository.replacement_count(), 3);

    fixture.clock.set(130);
    fixture
        .endpoint
        .push_device_poll(Ok(GithubDevicePollResponse::Token(token_response())));
    push_identity(&fixture.endpoint, 84);
    let complete = block_on(service.poll_device(
        tenant("tenant-a"),
        GithubDevicePollCredential::from_raw(&poll_raw).expect("poll credential"),
    ))
    .expect("complete device login");
    let GithubDeviceLoginPollOutcome::Complete(completion) = complete else {
        panic!("expected device completion");
    };
    assert_eq!(completion.session().identity().kind(), SessionKind::Cli);
    assert_eq!(completion.human().provider_subject().as_str(), "84");
    assert!(
        !completion
            .credential()
            .expose_secret()
            .contains("ghu_access_token_value")
    );
    let replay = block_on(service.poll_device(
        tenant("tenant-a"),
        GithubDevicePollCredential::from_raw(&poll_raw).expect("poll credential"),
    ));
    assert_eq!(replay.expect_err("device replay"), GithubLoginError::Replay);
    let observed = fixture
        .endpoint
        .observed
        .lock()
        .expect("endpoint observations");
    assert_eq!(observed.device_poll_calls, 4);
    assert_eq!(observed.current_user_calls, 1);
    assert_eq!(observed.membership_calls, 1);
}

#[test]
fn denied_expired_rate_limited_and_unavailable_device_states_remain_distinct() {
    let denied_fixture = Fixture::new(0);
    let denied_service = denied_fixture.service("login-v1", 0x75, &[]);
    denied_fixture
        .endpoint
        .push_device_code(Ok(device_response()));
    let denied_start = block_on(denied_service.begin_device(tenant("tenant-a"), None))
        .expect("denied device start");
    let denied_raw = denied_start.poll_credential().expose_secret().to_owned();
    denied_fixture.clock.set(105);
    denied_fixture
        .endpoint
        .push_device_poll(Ok(GithubDevicePollResponse::AccessDenied));
    let denied = block_on(denied_service.poll_device(
        tenant("tenant-a"),
        GithubDevicePollCredential::from_raw(&denied_raw).expect("denied poll credential"),
    ))
    .expect("denied outcome");
    assert!(matches!(denied, GithubDeviceLoginPollOutcome::Denied));
    assert_eq!(
        block_on(denied_service.poll_device(
            tenant("tenant-a"),
            GithubDevicePollCredential::from_raw(&denied_raw).expect("denied replay credential"),
        ))
        .expect_err("denied transaction is terminal"),
        GithubLoginError::Replay
    );

    let expired_fixture = Fixture::new(0);
    let expired_service = expired_fixture.service("login-v1", 0x76, &[]);
    expired_fixture
        .endpoint
        .push_device_code(Ok(device_response()));
    let expired_start = block_on(expired_service.begin_device(tenant("tenant-a"), None))
        .expect("expired device start");
    let expired_raw = expired_start.poll_credential().expose_secret().to_owned();
    expired_fixture.clock.set(105);
    expired_fixture
        .endpoint
        .push_device_poll(Ok(GithubDevicePollResponse::ExpiredToken));
    let expired = block_on(expired_service.poll_device(
        tenant("tenant-a"),
        GithubDevicePollCredential::from_raw(&expired_raw).expect("expired poll credential"),
    ))
    .expect("expired outcome");
    assert!(matches!(expired, GithubDeviceLoginPollOutcome::Expired));
    assert_eq!(
        block_on(expired_service.poll_device(
            tenant("tenant-a"),
            GithubDevicePollCredential::from_raw(&expired_raw).expect("expired replay credential"),
        ))
        .expect_err("expired provider transaction is terminal"),
        GithubLoginError::Replay
    );

    let limited_fixture = Fixture::new(0);
    let limited_service = limited_fixture.service("login-v1", 0x77, &[]);
    limited_fixture
        .endpoint
        .push_device_code(Err(GithubEndpointError::RateLimited {
            retry_after_seconds: Some(17),
        }));
    let limited = block_on(limited_service.begin_device(tenant("tenant-a"), None));
    assert_eq!(
        limited.expect_err("rate limited device begin"),
        GithubLoginError::RateLimited {
            retry_after_seconds: Some(17)
        }
    );
    limited_fixture
        .endpoint
        .push_device_code(Err(GithubEndpointError::Unavailable));
    let unavailable = block_on(limited_service.begin_device(tenant("tenant-a"), None));
    assert_eq!(
        unavailable.expect_err("unavailable device begin"),
        GithubLoginError::ProviderUnavailable
    );
}

#[test]
fn concurrent_device_completion_has_one_consumer_identity_fetch_and_session() {
    let fixture = Fixture::new(0);
    let service = fixture.service("login-v1", 0x81, &[]);
    fixture.endpoint.push_device_code(Ok(device_response()));
    let started =
        block_on(service.begin_device(tenant("tenant-a"), None)).expect("begin device login");
    let poll_raw = started.poll_credential().expose_secret().to_owned();
    fixture.clock.set(105);
    fixture
        .endpoint
        .push_device_poll(Ok(GithubDevicePollResponse::Token(token_response())));
    fixture
        .endpoint
        .push_device_poll(Ok(GithubDevicePollResponse::Token(token_response())));
    push_identity(&fixture.endpoint, 96);
    fixture
        .repository
        .set_load_barrier(Arc::new(Barrier::new(2)));

    let first_service = service.clone();
    let first_raw = poll_raw.clone();
    let first = std::thread::spawn(move || {
        block_on(first_service.poll_device(
            tenant("tenant-a"),
            GithubDevicePollCredential::from_raw(&first_raw).expect("first poll credential"),
        ))
    });
    let second_service = service.clone();
    let second = std::thread::spawn(move || {
        block_on(second_service.poll_device(
            tenant("tenant-a"),
            GithubDevicePollCredential::from_raw(&poll_raw).expect("second poll credential"),
        ))
    });
    let results = [
        first.join().expect("first poll thread"),
        second.join().expect("second poll thread"),
    ];
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Ok(GithubDeviceLoginPollOutcome::Complete(_))))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(GithubLoginError::Replay)))
            .count(),
        1
    );
    let observed = fixture
        .endpoint
        .observed
        .lock()
        .expect("endpoint observations");
    assert_eq!(observed.device_poll_calls, 2);
    assert_eq!(observed.current_user_calls, 1);
    assert_eq!(observed.membership_calls, 1);
    drop(observed);
    assert_eq!(fixture.finalizer.calls(), 1);
}

#[derive(Debug)]
struct WrongAuthenticationProvider(ProviderId);

impl AuthenticationProvider for WrongAuthenticationProvider {
    fn provider_id(&self) -> &ProviderId {
        &self.0
    }

    fn authenticate<'a>(&'a self, _credential: &'a ProviderCredential) -> AuthenticationFuture<'a> {
        Box::pin(async { Err(AuthenticationProviderError::WrongProvider) })
    }
}

#[test]
fn configuration_and_proof_parsers_reject_wrong_provider_unsafe_keys_and_cross_kind_values() {
    let unsafe_id = LoginBindingDigestKeyId::new("unsafe:key").expect("domain key ID");
    let unsafe_key = GithubLoginProofKey::new(
        unsafe_id,
        SecretBytes::new(vec![0x11; 32]).expect("key material"),
    );
    assert!(unsafe_key.is_err());
    let short_key = GithubLoginProofKey::new(
        LoginBindingDigestKeyId::new("safe-key").expect("key ID"),
        SecretBytes::new(vec![0x11; 31]).expect("short key material"),
    );
    assert!(short_key.is_err());
    assert!(GithubBrowserBindingCookie::from_raw("bw1~missing").is_err());
    assert!(GithubDevicePollCredential::from_raw("dp2~future~format").is_err());
    assert!(
        GithubLoginSessionLifetimes::new(
            Duration::ZERO,
            Duration::from_hours(1),
            Duration::from_hours(1),
            Duration::from_hours(1),
        )
        .is_err()
    );

    let fixture = Fixture::new(0);
    let proof_keys = GithubLoginProofKeyring::new(proof_key("login-v1", 0x21), Vec::new())
        .expect("proof keyring");
    let result = GithubLoginService::new(
        GithubAppProtocol::new(config()),
        fixture.endpoint.clone(),
        Arc::new(WrongAuthenticationProvider(
            ProviderId::new("gitlab").expect("wrong provider"),
        )),
        fixture.repository.clone(),
        fixture.sessions.clone(),
        fixture.finalizer.clone(),
        proof_keys,
        fixture.random.clone(),
        fixture.clock.clone(),
        GithubLoginSessionLifetimes::new(
            Duration::from_hours(1),
            Duration::from_hours(1),
            Duration::from_hours(1),
            Duration::from_hours(1),
        )
        .expect("lifetimes"),
    );
    assert!(matches!(
        result,
        Err(GithubLoginConfigurationError::WrongAuthenticationProvider)
    ));
}

#[test]
fn browser_and_device_proofs_reject_forward_versions_with_valid_remaining_fields() {
    let suffix = format!(
        "login-v1~aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa~{}",
        "A".repeat(43)
    );
    assert!(GithubBrowserBindingCookie::from_raw(&format!("bw1~{suffix}")).is_ok());
    assert!(GithubDevicePollCredential::from_raw(&format!("dp1~{suffix}")).is_ok());

    assert!(GithubBrowserBindingCookie::from_raw(&format!("bw2~{suffix}")).is_err());
    assert!(GithubDevicePollCredential::from_raw(&format!("dp2~{suffix}")).is_err());
}
