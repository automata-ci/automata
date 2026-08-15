mod support;

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use automata_ci_auth::{
    human::{AuthenticatedHuman, PrincipalId, ProviderId, ProviderSubject, TenantId},
    secret::{CsrfToken, RandomnessError, SecretBytes, SecureRandom},
    session::{
        ActivateCliSession, ActivateCliSessionOutcome, DurableSession, HumanSessionRepository,
        ResolveSession, ResolveSessionOutcome, RevokeOwnSession, RevokeOwnSessionOutcome,
        RevokePrincipalSessions, RevokePrincipalSessionsOutcome, SessionKind,
        SessionRepositoryError, SessionRepositoryFuture, SessionTokenDigestKeyId, TouchSession,
        TouchSessionOutcome,
    },
    session_credential::{
        InvalidSessionCredential, MAX_SESSION_CREDENTIAL_KEYS, PreparedSessionCredential,
        SESSION_CREDENTIAL_SECRET_BYTES, SessionCredential, SessionCredentialKey,
        SessionCredentialKeyring, SessionCredentialKeyringError, SessionCredentialService,
        SessionCredentialServiceError,
    },
    sign_in::PendingSessionCandidate,
    time::UnixTimestamp,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::executor::block_on;
use static_assertions::assert_not_impl_any;

use support::{DeterministicRandom, FixedClock};

assert_not_impl_any!(SessionCredential: Clone, serde::Serialize);
assert_not_impl_any!(SessionCredentialKey: Clone, serde::Serialize);
assert_not_impl_any!(SessionCredentialKeyring: Clone, serde::Serialize);
assert_not_impl_any!(PreparedSessionCredential: Clone, serde::Serialize);
assert_not_impl_any!(PendingSessionCandidate: Clone, serde::Serialize);
assert_not_impl_any!(SessionCredentialService: Clone, serde::Serialize);
assert_not_impl_any!(CsrfToken: Clone, serde::Serialize);

const PRINCIPAL_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

#[derive(Debug, Default)]
struct RepositoryState {
    resolve_results: VecDeque<Result<ResolveSessionOutcome, SessionRepositoryError>>,
    activation_results: VecDeque<Result<ActivateCliSessionOutcome, SessionRepositoryError>>,
    touch_results: VecDeque<Result<TouchSessionOutcome, SessionRepositoryError>>,
    revoke_results: VecDeque<Result<RevokeOwnSessionOutcome, SessionRepositoryError>>,
    resolve_requests: Vec<ResolveSession>,
    activation_requests: Vec<ActivateCliSession>,
    touch_requests: Vec<TouchSession>,
    revoke_requests: Vec<RevokeOwnSession>,
}

#[derive(Debug, Default)]
struct RecordingRepository {
    state: Mutex<RepositoryState>,
}

impl RecordingRepository {
    fn push_resolve(&self, result: Result<ResolveSessionOutcome, SessionRepositoryError>) {
        self.state
            .lock()
            .expect("repository state")
            .resolve_results
            .push_back(result);
    }

    fn push_touch(&self, result: Result<TouchSessionOutcome, SessionRepositoryError>) {
        self.state
            .lock()
            .expect("repository state")
            .touch_results
            .push_back(result);
    }

    fn push_activation(&self, result: Result<ActivateCliSessionOutcome, SessionRepositoryError>) {
        self.state
            .lock()
            .expect("repository state")
            .activation_results
            .push_back(result);
    }

    fn push_revoke(&self, result: Result<RevokeOwnSessionOutcome, SessionRepositoryError>) {
        self.state
            .lock()
            .expect("repository state")
            .revoke_results
            .push_back(result);
    }
}

impl HumanSessionRepository for RecordingRepository {
    fn resolve<'a>(
        &'a self,
        request: &'a ResolveSession,
    ) -> SessionRepositoryFuture<'a, ResolveSessionOutcome> {
        let response = {
            let mut state = self.state.lock().expect("repository state");
            state.resolve_requests.push(request.clone());
            state
                .resolve_results
                .pop_front()
                .expect("queued resolve outcome")
        };
        Box::pin(async move { response })
    }

    fn activate_cli<'a>(
        &'a self,
        request: &'a ActivateCliSession,
    ) -> SessionRepositoryFuture<'a, ActivateCliSessionOutcome> {
        let response = {
            let mut state = self.state.lock().expect("repository state");
            state.activation_requests.push(request.clone());
            state
                .activation_results
                .pop_front()
                .expect("queued activation outcome")
        };
        Box::pin(async move { response })
    }

    fn touch<'a>(
        &'a self,
        request: &'a TouchSession,
    ) -> SessionRepositoryFuture<'a, TouchSessionOutcome> {
        let response = {
            let mut state = self.state.lock().expect("repository state");
            state.touch_requests.push(request.clone());
            state
                .touch_results
                .pop_front()
                .expect("queued touch outcome")
        };
        Box::pin(async move { response })
    }

    fn revoke_own<'a>(
        &'a self,
        request: &'a RevokeOwnSession,
    ) -> SessionRepositoryFuture<'a, RevokeOwnSessionOutcome> {
        let response = {
            let mut state = self.state.lock().expect("repository state");
            state.revoke_requests.push(request.clone());
            state
                .revoke_results
                .pop_front()
                .expect("queued revoke outcome")
        };
        Box::pin(async move { response })
    }

    fn revoke_principal<'a>(
        &'a self,
        _request: &'a RevokePrincipalSessions,
    ) -> SessionRepositoryFuture<'a, RevokePrincipalSessionsOutcome> {
        Box::pin(async { Ok(RevokePrincipalSessionsOutcome::new(0)) })
    }
}

#[derive(Debug)]
struct FailingRandom;

impl SecureRandom for FailingRandom {
    fn fill(&self, _destination: &mut [u8]) -> Result<(), RandomnessError> {
        Err(RandomnessError)
    }
}

fn key_id(value: &str) -> SessionTokenDigestKeyId {
    SessionTokenDigestKeyId::new(value).expect("test key ID")
}

fn key(value: &str, byte: u8) -> SessionCredentialKey {
    SessionCredentialKey::new(
        key_id(value),
        SecretBytes::new(vec![byte; SESSION_CREDENTIAL_SECRET_BYTES]).expect("test key"),
    )
    .expect("valid credential key")
}

fn keyring(active_id: &str, active_byte: u8) -> SessionCredentialKeyring {
    SessionCredentialKeyring::new(key(active_id, active_byte), Vec::new()).expect("keyring")
}

fn human() -> AuthenticatedHuman {
    AuthenticatedHuman::new(
        PrincipalId::new(PRINCIPAL_ID).expect("principal ID"),
        ProviderId::new("github").expect("provider ID"),
        ProviderSubject::new("42").expect("provider subject"),
        "octocat",
        Some("The Octocat".into()),
        UnixTimestamp::from_seconds(90),
    )
    .expect("human")
}

fn service(
    repository: Arc<RecordingRepository>,
    keyring: SessionCredentialKeyring,
    now: u64,
    random_first: u8,
) -> SessionCredentialService {
    SessionCredentialService::new(
        keyring,
        repository,
        Arc::new(DeterministicRandom::new(random_first)),
        Arc::new(FixedClock(UnixTimestamp::from_seconds(now))),
    )
}

fn raw_credential(id: &str, secret_byte: u8) -> String {
    format!(
        "v1~{id}~{}",
        URL_SAFE_NO_PAD.encode([secret_byte; SESSION_CREDENTIAL_SECRET_BYTES])
    )
}

#[test]
fn parser_accepts_only_one_bounded_canonical_format() {
    let raw = raw_credential("session.2026-blue", 0xa5);
    let credential = SessionCredential::from_raw(&raw).expect("canonical credential");
    assert_eq!(credential.key_id().as_str(), "session.2026-blue");
    assert_eq!(credential.expose_secret(), raw);
    let rendered = format!("{credential:?}");
    assert!(rendered.contains("session.2026-blue"));
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains(credential.expose_secret()));
    assert!(!rendered.contains(&URL_SAFE_NO_PAD.encode([0xa5; 32])));

    let valid_secret = URL_SAFE_NO_PAD.encode([7_u8; 32]);
    let invalid = [
        String::new(),
        format!("v2~key~{valid_secret}"),
        format!("V1~key~{valid_secret}"),
        format!("v1~~{valid_secret}"),
        format!("v1~-leading~{valid_secret}"),
        format!("v1~_leading~{valid_secret}"),
        format!("v1~:leading~{valid_secret}"),
        format!("v1~.leading~{valid_secret}"),
        format!("v1~key with space~{valid_secret}"),
        format!("v1~key:colon~{valid_secret}"),
        format!("v1~key~{valid_secret}~extra"),
        format!("v1~key~{valid_secret}="),
        format!("v1~key~{}", &valid_secret[..42]),
        format!("v1~key~+{}", &valid_secret[1..]),
        format!("v1~key~{valid_secret}\n"),
        format!("v1~kéy~{valid_secret}"),
        format!("v1~{}~{valid_secret}", "a".repeat(129)),
        "x".repeat(176),
    ];
    for candidate in invalid {
        assert_eq!(
            SessionCredential::from_raw(&candidate).expect_err("must reject"),
            InvalidSessionCredential
        );
    }
}

#[test]
fn keyring_requires_unique_exact_length_bounded_keys_and_redacts_material() {
    for length in [1, 31, 33, 64] {
        assert_eq!(
            SessionCredentialKey::new(
                key_id("bad-length"),
                SecretBytes::new(vec![0x5a; length]).expect("nonempty"),
            )
            .expect_err("wrong length"),
            SessionCredentialKeyringError::InvalidKeyLength
        );
    }
    assert_eq!(
        SessionCredentialKey::new(
            key_id(":leading"),
            SecretBytes::new(vec![1; 32]).expect("material"),
        )
        .expect_err("database-incompatible ID"),
        SessionCredentialKeyringError::InvalidKeyId
    );

    let configured = key("redaction-key", 0x66);
    let key_debug = format!("{configured:?}");
    assert!(key_debug.contains("[REDACTED]"));
    assert!(!key_debug.contains("102, 102"));
    let ring = SessionCredentialKeyring::new(configured, vec![key("old-key", 0x77)])
        .expect("rotation keyring");
    assert_eq!(ring.active_key_id().as_str(), "redaction-key");
    let ring_debug = format!("{ring:?}");
    assert!(ring_debug.contains("old-key"));
    assert!(ring_debug.contains("[REDACTED]"));
    assert!(!ring_debug.contains("119, 119"));

    assert_eq!(
        SessionCredentialKeyring::new(key("same", 1), vec![key("same", 2)]).expect_err("duplicate"),
        SessionCredentialKeyringError::DuplicateKeyId
    );

    let maximum_verify_only = (0..MAX_SESSION_CREDENTIAL_KEYS - 1)
        .map(|index| {
            key(
                &format!("old-{index}"),
                u8::try_from(index).expect("bounded index"),
            )
        })
        .collect();
    SessionCredentialKeyring::new(key("active", 0xff), maximum_verify_only)
        .expect("maximum bounded keyring");
    let too_many = (0..MAX_SESSION_CREDENTIAL_KEYS)
        .map(|index| {
            key(
                &format!("excess-{index}"),
                u8::try_from(index).expect("bounded index"),
            )
        })
        .collect();
    assert_eq!(
        SessionCredentialKeyring::new(key("active", 0xff), too_many)
            .expect_err("over the key bound"),
        SessionCredentialKeyringError::TooManyKeys
    );
}

#[test]
fn nonpersisting_preparation_linearly_binds_raw_credential_to_safe_candidate() {
    let repository = Arc::new(RecordingRepository::default());
    let service = service(repository.clone(), keyring("current.1", 0x19), 100, 1);
    let prepared = service
        .prepare(
            SessionKind::Browser,
            Duration::from_mins(5),
            Duration::from_hours(1),
        )
        .expect("prepared session credential");
    let raw = prepared.credential().expose_secret();
    assert!(raw.starts_with("v1~current.1~"));
    assert_eq!(prepared.kind(), SessionKind::Browser);
    assert_eq!(prepared.issued_at().as_seconds(), 100);
    assert_eq!(prepared.idle_expires_at().as_seconds(), 400);
    assert_eq!(prepared.expires_at().as_seconds(), 3_700);
    let parsed_id = uuid::Uuid::parse_str(prepared.session_id().as_str()).expect("session UUID");
    assert_eq!(
        parsed_id.hyphenated().to_string(),
        prepared.session_id().as_str()
    );
    assert!(!parsed_id.is_nil());
    let rendered = format!("{prepared:?}");
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains(raw));
    let (credential, candidate) = prepared.into_parts();
    let derived_lookup = service
        .derive_lookup_raw(credential.expose_secret(), SessionKind::Browser)
        .expect("paired lookup");
    assert_eq!(candidate.lookup(), &derived_lookup);
    assert_eq!(
        candidate.session_id().as_str(),
        parsed_id.hyphenated().to_string()
    );
    assert_eq!(candidate.kind(), SessionKind::Browser);
    assert_eq!(candidate.issued_at().as_seconds(), 100);
    assert_eq!(candidate.idle_expires_at().as_seconds(), 400);
    assert_eq!(candidate.expires_at().as_seconds(), 3_700);
    assert!(!format!("{candidate:?}").contains(credential.expose_secret()));
}

#[test]
fn preparation_domain_separates_lookup_and_csrf_before_safe_resolution() {
    let repository = Arc::new(RecordingRepository::default());
    let service = service(repository.clone(), keyring("current.1", 0x11), 100, 1);
    let tenant = TenantId::new("tenant-1").expect("tenant");
    let human = human();
    let prepared = service
        .prepare(
            SessionKind::Browser,
            Duration::from_mins(5),
            Duration::from_hours(1),
        )
        .expect("prepared browser credential");
    let (credential, candidate) = prepared.into_parts();
    let raw = credential.expose_secret();
    assert!(raw.starts_with("v1~current.1~"));
    assert_eq!(candidate.kind(), SessionKind::Browser);
    assert_eq!(candidate.issued_at().as_seconds(), 100);
    assert_eq!(candidate.idle_expires_at().as_seconds(), 400);
    assert_eq!(candidate.expires_at().as_seconds(), 3_700);
    let session_id = candidate.session_id().as_str();
    let parsed_id = uuid::Uuid::parse_str(session_id).expect("UUID session ID");
    assert_eq!(parsed_id.hyphenated().to_string(), session_id);
    assert!(!parsed_id.is_nil());
    assert_eq!(session_id.as_bytes()[14], b'4');
    assert!(matches!(
        session_id.as_bytes()[19],
        b'8' | b'9' | b'a' | b'b'
    ));

    assert_eq!(candidate.lookup().key_id().as_str(), "current.1");
    let candidate_debug = format!("{candidate:?}");
    assert!(!candidate_debug.contains(raw));
    assert!(candidate_debug.contains("[REDACTED]"));
    let prepared_lookup = candidate.lookup().clone();
    let lookup_digest = *candidate.lookup().digest().as_bytes();

    let derived_lookup = service
        .derive_lookup_raw(raw, SessionKind::Browser)
        .expect("safe lookup derivation");
    assert_eq!(derived_lookup, prepared_lookup);
    assert!(!format!("{derived_lookup:?}").contains(raw));

    let csrf = service
        .derive_csrf_raw(raw, SessionKind::Browser)
        .expect("browser CSRF derivation");
    let csrf_bytes = URL_SAFE_NO_PAD
        .decode(csrf.expose_secret())
        .expect("CSRF base64url");
    assert_eq!(csrf_bytes.len(), 32);
    assert_ne!(csrf_bytes.as_slice(), lookup_digest);
    let cli_csrf = service
        .derive_csrf_raw(raw, SessionKind::Cli)
        .expect("audience-bound CLI derivation");
    assert_ne!(csrf.expose_secret(), cli_csrf.expose_secret());
    assert!(!format!("{csrf:?}").contains(csrf.expose_secret()));

    repository.push_resolve(Ok(ResolveSessionOutcome::Active(Box::new(
        browser_session_at_100(&tenant, &human),
    ))));
    repository.push_resolve(Ok(ResolveSessionOutcome::NotFound));
    assert!(matches!(
        block_on(service.resolve_raw(raw, SessionKind::Browser)).expect("browser resolution"),
        ResolveSessionOutcome::Active(_)
    ));
    assert_eq!(
        block_on(service.resolve_raw(raw, SessionKind::Cli)).expect("CLI rejection"),
        ResolveSessionOutcome::NotFound
    );
    let state = repository.state.lock().expect("repository state");
    assert_eq!(state.resolve_requests.len(), 2);
    assert_eq!(
        state.resolve_requests[0].lookup().digest().as_bytes(),
        &lookup_digest
    );
    assert_ne!(
        state.resolve_requests[1].lookup().digest().as_bytes(),
        &lookup_digest
    );
    assert_eq!(
        state.resolve_requests[0].expected_kind(),
        SessionKind::Browser
    );
    assert_eq!(state.resolve_requests[1].expected_kind(), SessionKind::Cli);
}

#[test]
fn active_rotation_prepares_only_current_but_verify_only_key_resolves_old() {
    let repository = Arc::new(RecordingRepository::default());
    let old_service = service(repository.clone(), keyring("old.1", 0x21), 100, 5);
    let tenant = TenantId::new("tenant-1").expect("tenant");
    let human = human();
    let old = old_service
        .prepare(
            SessionKind::Cli,
            Duration::from_mins(5),
            Duration::from_hours(1),
        )
        .expect("old prepared credential");
    let old_raw = old.credential().expose_secret().to_owned();
    assert!(old_raw.starts_with("v1~old.1~"));

    let rotated = SessionCredentialKeyring::new(key("new.2", 0x22), vec![key("old.1", 0x21)])
        .expect("rotated keyring");
    let rotated_service = service(repository.clone(), rotated, 100, 20);
    repository.push_resolve(Ok(ResolveSessionOutcome::Active(Box::new(
        cli_session_at_100(&tenant, &human),
    ))));
    assert!(matches!(
        block_on(rotated_service.resolve_raw(&old_raw, SessionKind::Cli))
            .expect("verify-only resolution"),
        ResolveSessionOutcome::Active(_)
    ));
    let new = rotated_service
        .prepare(
            SessionKind::Cli,
            Duration::from_mins(5),
            Duration::from_hours(1),
        )
        .expect("new prepared credential");
    assert!(new.credential().expose_secret().starts_with("v1~new.2~"));

    let before_rejections = repository
        .state
        .lock()
        .expect("repository state")
        .resolve_requests
        .len();
    let retired_service = service(repository.clone(), keyring("new.2", 0x22), 100, 40);
    assert_eq!(
        block_on(retired_service.resolve_raw(&old_raw, SessionKind::Cli))
            .expect_err("retired key must fail before repository"),
        SessionCredentialServiceError::InvalidCredential
    );
    let unknown_raw = old_raw.replacen("v1~old.1~", "v1~unknown~", 1);
    assert_eq!(
        block_on(rotated_service.resolve_raw(&unknown_raw, SessionKind::Cli))
            .expect_err("unknown direct key selection"),
        SessionCredentialServiceError::InvalidCredential
    );
    assert_eq!(
        repository
            .state
            .lock()
            .expect("repository state")
            .resolve_requests
            .len(),
        before_rejections
    );
}

#[test]
fn preparation_lifetime_and_overflow_fail_closed_before_storage() {
    let repository = Arc::new(RecordingRepository::default());
    let service = service(repository.clone(), keyring("active", 0x41), u64::MAX - 5, 1);
    for (idle, absolute) in [
        (Duration::ZERO, Duration::from_secs(1)),
        (Duration::from_nanos(1), Duration::from_secs(1)),
        (Duration::from_secs(2), Duration::from_secs(1)),
    ] {
        assert_eq!(
            service
                .prepare(SessionKind::Browser, idle, absolute)
                .expect_err("invalid preparation lifetime"),
            SessionCredentialServiceError::InvalidLifetime
        );
    }

    assert_eq!(
        service
            .prepare(
                SessionKind::Browser,
                Duration::from_secs(2),
                Duration::from_secs(10),
            )
            .expect_err("preparation overflow"),
        SessionCredentialServiceError::LifetimeOverflow
    );
    let raw = raw_credential("active", 9);
    assert_eq!(
        block_on(service.touch_raw(&raw, SessionKind::Browser, Duration::from_secs(10),))
            .expect_err("touch overflow"),
        SessionCredentialServiceError::LifetimeOverflow
    );
    assert_eq!(
        block_on(service.touch_raw(&raw, SessionKind::Browser, Duration::from_millis(500),))
            .expect_err("fractional touch"),
        SessionCredentialServiceError::InvalidLifetime
    );
}

#[test]
fn randomness_failure_never_reaches_session_storage() {
    let random_repository = Arc::new(RecordingRepository::default());
    let random_service = SessionCredentialService::new(
        keyring("active", 0x41),
        random_repository.clone(),
        Arc::new(FailingRandom),
        Arc::new(FixedClock(UnixTimestamp::from_seconds(100))),
    );
    assert_eq!(
        random_service
            .prepare(
                SessionKind::Browser,
                Duration::from_mins(5),
                Duration::from_hours(1),
            )
            .expect_err("random failure"),
        SessionCredentialServiceError::RandomnessUnavailable
    );
}

#[test]
fn cli_activation_derives_only_the_cli_lookup_and_validates_success_metadata() {
    let repository = Arc::new(RecordingRepository::default());
    let service = service(repository.clone(), keyring("active", 0x49), 100, 1);
    let tenant = TenantId::new("tenant-1").expect("tenant");
    let human = human();
    let prepared = service
        .prepare(
            SessionKind::Cli,
            Duration::from_mins(5),
            Duration::from_hours(1),
        )
        .expect("prepared CLI credential");
    let raw = prepared.credential().expose_secret().to_owned();
    let expected_lookup = service
        .derive_lookup_raw(&raw, SessionKind::Cli)
        .expect("CLI lookup");

    repository.push_activation(Ok(ActivateCliSessionOutcome::Activated(Box::new(
        cli_session_at_100(&tenant, &human),
    ))));
    assert!(matches!(
        block_on(service.activate_cli_raw(&raw)).expect("activation"),
        ActivateCliSessionOutcome::Activated(_)
    ));
    let state = repository.state.lock().expect("repository state");
    assert_eq!(state.activation_requests.len(), 1);
    assert_eq!(state.activation_requests[0].lookup(), &expected_lookup);
    assert_eq!(state.activation_requests[0].now().as_seconds(), 100);
    assert!(!format!("{:?}", state.activation_requests[0]).contains(&raw));
    drop(state);

    repository.push_activation(Ok(ActivateCliSessionOutcome::AlreadyActive(Box::new(
        browser_session_at_100(&tenant, &human),
    ))));
    assert_eq!(
        block_on(service.activate_cli_raw(&raw)).expect_err("wrong success kind"),
        SessionCredentialServiceError::InternalFailure
    );
    repository.push_activation(Err(SessionRepositoryError::Unavailable));
    assert_eq!(
        block_on(service.activate_cli_raw(&raw)).expect_err("storage failure"),
        SessionCredentialServiceError::RepositoryUnavailable
    );
    assert_eq!(
        block_on(service.activate_cli_raw("invalid")).expect_err("malformed bearer"),
        SessionCredentialServiceError::InvalidCredential
    );
}

#[test]
fn raw_helpers_touch_and_revoke_without_crossing_the_repository_boundary() {
    let repository = Arc::new(RecordingRepository::default());
    let service = service(repository.clone(), keyring("active", 0x51), 100, 1);
    let tenant = TenantId::new("tenant-1").expect("tenant");
    let human = human();
    let prepared = service
        .prepare(
            SessionKind::Browser,
            Duration::from_mins(5),
            Duration::from_hours(1),
        )
        .expect("prepared browser credential");
    let raw = prepared.credential().expose_secret().to_owned();
    let active = browser_session_at_100(&tenant, &human);
    let expected_session_id = active.identity().session_id().clone();
    repository.push_touch(Ok(TouchSessionOutcome::Unchanged(Box::new(active.clone()))));
    repository.push_resolve(Ok(ResolveSessionOutcome::Active(Box::new(active))));
    repository.push_revoke(Ok(RevokeOwnSessionOutcome::Revoked));

    assert!(matches!(
        block_on(service.touch_raw(&raw, SessionKind::Browser, Duration::from_mins(2)))
            .expect("touch"),
        TouchSessionOutcome::Unchanged(_)
    ));
    assert_eq!(
        block_on(service.revoke_raw(&raw, SessionKind::Browser)).expect("revoke"),
        RevokeOwnSessionOutcome::Revoked
    );
    let state = repository.state.lock().expect("repository state");
    assert_eq!(state.touch_requests.len(), 1);
    assert_eq!(state.touch_requests[0].observed_at().as_seconds(), 100);
    assert_eq!(state.touch_requests[0].idle_expires_at().as_seconds(), 220);
    assert_eq!(state.revoke_requests.len(), 1);
    let revoke = &state.revoke_requests[0];
    assert_eq!(revoke.tenant_id(), &tenant);
    assert_eq!(revoke.principal_id().as_str(), PRINCIPAL_ID);
    assert_eq!(revoke.session_id(), &expected_session_id);
    assert!(!format!("{:?}", state.touch_requests[0]).contains(&raw));
    assert!(!format!("{revoke:?}").contains(&raw));
    drop(state);

    repository.push_resolve(Ok(ResolveSessionOutcome::NotFound));
    assert_eq!(
        block_on(service.revoke_raw(&raw, SessionKind::Cli)).expect("wrong audience"),
        RevokeOwnSessionOutcome::NotFound
    );
    repository.push_resolve(Ok(ResolveSessionOutcome::Revoked));
    assert_eq!(
        block_on(service.revoke_raw(&raw, SessionKind::Browser)).expect("idempotent revoked"),
        RevokeOwnSessionOutcome::AlreadyRevoked
    );
}

#[test]
fn repository_failures_and_inconsistent_active_records_are_sanitized() {
    let repository = Arc::new(RecordingRepository::default());
    let service = service(repository.clone(), keyring("active", 0x61), 100, 1);
    let tenant = TenantId::new("tenant-1").expect("tenant");
    let human = human();
    let prepared = service
        .prepare(
            SessionKind::Browser,
            Duration::from_mins(5),
            Duration::from_hours(1),
        )
        .expect("prepared browser credential");
    let raw = prepared.credential().expose_secret().to_owned();
    repository.push_resolve(Err(SessionRepositoryError::Unavailable));
    assert_eq!(
        block_on(service.resolve_raw(&raw, SessionKind::Browser)).expect_err("resolve unavailable"),
        SessionCredentialServiceError::RepositoryUnavailable
    );
    repository.push_touch(Err(SessionRepositoryError::CorruptData));
    assert_eq!(
        block_on(service.touch_raw(&raw, SessionKind::Browser, Duration::from_secs(30)))
            .expect_err("touch corruption"),
        SessionCredentialServiceError::InternalFailure
    );
    repository.push_resolve(Ok(ResolveSessionOutcome::Active(Box::new(
        cli_session_at_100(&tenant, &human),
    ))));
    assert_eq!(
        block_on(service.resolve_raw(&raw, SessionKind::Browser))
            .expect_err("inconsistent active audience"),
        SessionCredentialServiceError::InternalFailure
    );
    repository.push_resolve(Ok(ResolveSessionOutcome::Active(Box::new(
        browser_session_at_100(&tenant, &human),
    ))));
    repository.push_revoke(Err(SessionRepositoryError::Unavailable));
    assert_eq!(
        block_on(service.revoke_raw(&raw, SessionKind::Browser)).expect_err("revoke unavailable"),
        SessionCredentialServiceError::RepositoryUnavailable
    );

    let raw_error = block_on(service.resolve_raw("not-a-credential", SessionKind::Browser))
        .expect_err("malformed bearer");
    assert_eq!(raw_error, SessionCredentialServiceError::InvalidCredential);
    assert!(!raw_error.to_string().contains("not-a-credential"));
}

fn cli_session_at_100(tenant: &TenantId, human: &AuthenticatedHuman) -> DurableSession {
    use automata_ci_auth::session::{DurableSessionIdentity, SessionId};

    DurableSession::new(
        DurableSessionIdentity::new(
            SessionId::new("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("session ID"),
            tenant.clone(),
            human.principal_id().clone(),
            human.provider_id().clone(),
            human.provider_subject().clone(),
            SessionKind::Cli,
        )
        .expect("identity"),
        7,
        UnixTimestamp::from_seconds(100),
        UnixTimestamp::from_seconds(100),
        UnixTimestamp::from_seconds(400),
        UnixTimestamp::from_seconds(3_700),
        None,
    )
    .expect("CLI session")
}

fn browser_session_at_100(tenant: &TenantId, human: &AuthenticatedHuman) -> DurableSession {
    use automata_ci_auth::session::{DurableSessionIdentity, SessionId};

    DurableSession::new(
        DurableSessionIdentity::new(
            SessionId::new("cccccccc-cccc-4ccc-8ccc-cccccccccccc").expect("session ID"),
            tenant.clone(),
            human.principal_id().clone(),
            human.provider_id().clone(),
            human.provider_subject().clone(),
            SessionKind::Browser,
        )
        .expect("identity"),
        7,
        UnixTimestamp::from_seconds(100),
        UnixTimestamp::from_seconds(100),
        UnixTimestamp::from_seconds(400),
        UnixTimestamp::from_seconds(3_700),
        None,
    )
    .expect("session")
}
