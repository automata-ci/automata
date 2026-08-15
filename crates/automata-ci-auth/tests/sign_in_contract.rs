mod support;

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use automata_ci_auth::{
    github::{GithubMembershipObservation, GithubMembershipSnapshot, GithubMembershipSnapshotId},
    human::{ProviderId, ProviderIdentityAssertion, ProviderSubject, TenantId},
    login::{
        LoginBindingDigest, LoginBindingDigestKeyId, LoginTransactionAccess,
        LoginTransactionBinding, LoginTransactionId, LoginTransactionPurpose,
        LoginTransactionVersion,
    },
    secret::{SecretBytes, SecretString},
    session::{
        HumanSessionRepository, ResolveSession, ResolveSessionOutcome, RevokeOwnSession,
        RevokeOwnSessionOutcome, RevokePrincipalSessions, RevokePrincipalSessionsOutcome,
        SessionKind, SessionRepositoryFuture, TouchSession, TouchSessionOutcome,
    },
    session_credential::{
        SessionCredentialKey, SessionCredentialKeyring, SessionCredentialService,
    },
    sign_in::{
        FinalizeSignIn, FinalizeSignInOutcome, PendingSessionCandidate, RetryFinalizeSignIn,
        SignInValueError,
    },
    time::UnixTimestamp,
    vault::{
        ProviderAccessToken, ProviderGrantKind, ProviderRefreshToken, ProviderTokenMetadata,
        ProviderTokenSet,
    },
};
use static_assertions::assert_not_impl_any;

use support::{DeterministicRandom, FixedClock};

assert_not_impl_any!(FinalizeSignIn: Clone, serde::Serialize);
assert_not_impl_any!(PendingSessionCandidate: Clone, serde::Serialize);
assert_not_impl_any!(RetryFinalizeSignIn: Clone, serde::Serialize);
assert_not_impl_any!(FinalizeSignInOutcome: Clone, serde::Serialize);

const LOGIN_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

#[derive(Debug)]
struct UnusedSessionRepository;

impl HumanSessionRepository for UnusedSessionRepository {
    fn resolve<'a>(
        &'a self,
        _request: &'a ResolveSession,
    ) -> SessionRepositoryFuture<'a, ResolveSessionOutcome> {
        panic!("not used by sign-in preparation")
    }

    fn touch<'a>(
        &'a self,
        _request: &'a TouchSession,
    ) -> SessionRepositoryFuture<'a, TouchSessionOutcome> {
        panic!("not used by sign-in preparation")
    }

    fn revoke_own<'a>(
        &'a self,
        _request: &'a RevokeOwnSession,
    ) -> SessionRepositoryFuture<'a, RevokeOwnSessionOutcome> {
        panic!("not used by sign-in preparation")
    }

    fn revoke_principal<'a>(
        &'a self,
        _request: &'a RevokePrincipalSessions,
    ) -> SessionRepositoryFuture<'a, RevokePrincipalSessionsOutcome> {
        panic!("not used by sign-in preparation")
    }
}

fn provider(value: &str) -> ProviderId {
    ProviderId::new(value).expect("provider ID")
}

fn subject(value: &str) -> ProviderSubject {
    ProviderSubject::new(value).expect("provider subject")
}

fn binding(key: &str, byte: u8) -> LoginTransactionBinding {
    LoginTransactionBinding::new(
        LoginBindingDigestKeyId::new(key).expect("binding key"),
        LoginBindingDigest::new([byte; 32]),
    )
}

fn browser_access(
    purpose: LoginTransactionPurpose,
    provider_id: ProviderId,
) -> LoginTransactionAccess {
    LoginTransactionAccess::browser(
        LoginTransactionId::new(LOGIN_ID).expect("login ID"),
        purpose,
        provider_id,
        binding("state-v1", 0x11),
        binding("client-v1", 0x22),
    )
    .expect("independent browser proofs")
}

fn device_access(provider_id: ProviderId) -> LoginTransactionAccess {
    LoginTransactionAccess::device(
        LoginTransactionId::new(LOGIN_ID).expect("login ID"),
        LoginTransactionPurpose::SignIn {
            tenant_id: TenantId::new("tenant-a").expect("tenant"),
        },
        provider_id,
        binding("poll-v1", 0x33),
    )
}

fn identity(
    provider_id: &str,
    provider_subject: &str,
    authenticated_at: u64,
) -> ProviderIdentityAssertion {
    ProviderIdentityAssertion::new(
        provider(provider_id),
        subject(provider_subject),
        "renamed-login",
        Some("Renamed User".to_owned()),
        UnixTimestamp::from_seconds(authenticated_at),
    )
    .expect("identity assertion")
}

#[allow(clippy::too_many_arguments)]
fn tokens(
    provider_id: &str,
    provider_subject: Option<&str>,
    grant_kind: ProviderGrantKind,
    issued_at: u64,
    access_expires_at: Option<u64>,
    refresh_expires_at: Option<u64>,
    access_secret: &str,
) -> ProviderTokenSet {
    let metadata = ProviderTokenMetadata::builder(
        provider(provider_id),
        grant_kind,
        "Bearer",
        UnixTimestamp::from_seconds(issued_at),
    )
    .provider_subject(provider_subject.map(subject))
    .scopes(BTreeSet::from(["read:org".to_owned()]))
    .access_expires_at(access_expires_at.map(UnixTimestamp::from_seconds))
    .refresh_expires_at(refresh_expires_at.map(UnixTimestamp::from_seconds))
    .build()
    .expect("token metadata");
    ProviderTokenSet::new(
        ProviderAccessToken::new(SecretString::new(access_secret).expect("access token")),
        Some(ProviderRefreshToken::new(
            SecretString::new("refresh-secret-sentinel").expect("refresh token"),
        )),
        metadata,
    )
    .expect("provider tokens")
}

fn candidate(kind: SessionKind, issued_at: u64) -> PendingSessionCandidate {
    let key = SessionCredentialKey::new(
        automata_ci_auth::session::SessionTokenDigestKeyId::new("session-hmac-v1")
            .expect("session key ID"),
        SecretBytes::new(vec![0x5a; 32]).expect("session key"),
    )
    .expect("session credential key");
    let keyring = SessionCredentialKeyring::new(key, Vec::new()).expect("session keyring");
    let service = SessionCredentialService::new(
        keyring,
        Arc::new(UnusedSessionRepository),
        Arc::new(DeterministicRandom::new(0x44)),
        Arc::new(FixedClock(UnixTimestamp::from_seconds(issued_at))),
    );
    let prepared = service
        .prepare(kind, Duration::from_mins(1), Duration::from_mins(10))
        .expect("prepared session credential");
    let (_credential, candidate) = prepared.into_parts();
    candidate
}

fn membership(observed_at: u64) -> GithubMembershipObservation {
    membership_until(observed_at, observed_at + 100)
}

fn membership_until(observed_at: u64, valid_until: u64) -> GithubMembershipObservation {
    GithubMembershipObservation::new(
        GithubMembershipSnapshotId::new(LOGIN_ID).expect("snapshot ID"),
        GithubMembershipSnapshot::default(),
        UnixTimestamp::from_seconds(observed_at),
        UnixTimestamp::from_seconds(valid_until),
    )
    .expect("membership observation")
}

fn valid_browser_request(access_secret: &str) -> FinalizeSignIn {
    FinalizeSignIn::new(
        browser_access(
            LoginTransactionPurpose::SignIn {
                tenant_id: TenantId::new("tenant-a").expect("tenant"),
            },
            provider("github"),
        ),
        LoginTransactionVersion::new(2).expect("consumed version"),
        identity("github", "42", 110),
        tokens(
            "github",
            Some("42"),
            ProviderGrantKind::BrowserAuthorizationCode,
            100,
            Some(300),
            Some(400),
            access_secret,
        ),
        membership(115),
        candidate(SessionKind::Browser, 120),
        UnixTimestamp::from_seconds(125),
    )
    .expect("valid browser finalization")
}

#[test]
fn valid_consumed_browser_and_device_requests_preserve_only_safe_session_material() {
    let request = valid_browser_request("access-secret-sentinel");
    assert_eq!(request.expected_version().value(), 2);
    assert_eq!(request.session().kind(), SessionKind::Browser);
    let debug = format!("{request:?}");
    assert!(debug.contains("FinalizeSignIn"));
    assert!(!debug.contains("access-secret-sentinel"));
    assert!(!debug.contains("refresh-secret-sentinel"));
    let (retry, collided_candidate) = request.into_retry_parts();
    drop(collided_candidate);
    let retry_debug = format!("{retry:?}");
    assert!(retry_debug.contains("RetryFinalizeSignIn"));
    assert!(!retry_debug.contains("access-secret-sentinel"));
    assert!(!retry_debug.contains("refresh-secret-sentinel"));
    let retried = retry
        .with_session(
            candidate(SessionKind::Browser, 130),
            UnixTimestamp::from_seconds(135),
        )
        .expect("a later collision retry remains valid");
    assert_eq!(retried.now(), UnixTimestamp::from_seconds(135));
    assert_eq!(
        retried.membership().snapshot_id(),
        GithubMembershipSnapshotId::new(LOGIN_ID).expect("snapshot ID")
    );

    let (retry, collided_candidate) = valid_browser_request("regression-secret").into_retry_parts();
    drop(collided_candidate);
    assert_eq!(
        retry
            .with_session(
                candidate(SessionKind::Browser, 120),
                UnixTimestamp::from_seconds(124),
            )
            .unwrap_err(),
        SignInValueError::InvalidTimeOrder
    );

    let device = FinalizeSignIn::new(
        device_access(provider("github")),
        LoginTransactionVersion::new(7).expect("consumed version"),
        identity("github", "42", 110),
        tokens(
            "github",
            Some("42"),
            ProviderGrantKind::DeviceAuthorization,
            100,
            Some(300),
            Some(400),
            "device-access-secret",
        ),
        membership(115),
        candidate(SessionKind::Cli, 120),
        UnixTimestamp::from_seconds(125),
    )
    .expect("valid device finalization");
    assert_eq!(device.session().kind(), SessionKind::Cli);
}

#[test]
#[allow(clippy::too_many_lines)]
fn purpose_flow_identity_and_subject_bound_credentials_must_match_exactly() {
    let installation = FinalizeSignIn::new(
        browser_access(
            LoginTransactionPurpose::InstallationSetup,
            provider("github"),
        ),
        LoginTransactionVersion::new(2).expect("version"),
        identity("github", "42", 110),
        tokens(
            "github",
            Some("42"),
            ProviderGrantKind::BrowserAuthorizationCode,
            100,
            Some(300),
            Some(400),
            "access",
        ),
        membership(115),
        candidate(SessionKind::Browser, 120),
        UnixTimestamp::from_seconds(125),
    );
    assert_eq!(installation.unwrap_err(), SignInValueError::InvalidPurpose);

    let wrong_kind = FinalizeSignIn::new(
        device_access(provider("github")),
        LoginTransactionVersion::new(2).expect("version"),
        identity("github", "42", 110),
        tokens(
            "github",
            Some("42"),
            ProviderGrantKind::DeviceAuthorization,
            100,
            Some(300),
            Some(400),
            "access",
        ),
        membership(115),
        candidate(SessionKind::Browser, 120),
        UnixTimestamp::from_seconds(125),
    );
    assert_eq!(wrong_kind.unwrap_err(), SignInValueError::WrongSessionKind);

    let wrong_grant = FinalizeSignIn::new(
        device_access(provider("github")),
        LoginTransactionVersion::new(2).expect("version"),
        identity("github", "42", 110),
        tokens(
            "github",
            Some("42"),
            ProviderGrantKind::BrowserAuthorizationCode,
            100,
            Some(300),
            Some(400),
            "access",
        ),
        membership(115),
        candidate(SessionKind::Cli, 120),
        UnixTimestamp::from_seconds(125),
    );
    assert_eq!(
        wrong_grant.unwrap_err(),
        SignInValueError::WrongProviderGrantKind
    );

    for mismatched in [
        tokens(
            "gitlab",
            Some("42"),
            ProviderGrantKind::BrowserAuthorizationCode,
            100,
            Some(300),
            Some(400),
            "access",
        ),
        tokens(
            "github",
            Some("43"),
            ProviderGrantKind::BrowserAuthorizationCode,
            100,
            Some(300),
            Some(400),
            "access",
        ),
        tokens(
            "github",
            None,
            ProviderGrantKind::BrowserAuthorizationCode,
            100,
            Some(300),
            Some(400),
            "access",
        ),
    ] {
        let result = FinalizeSignIn::new(
            browser_access(
                LoginTransactionPurpose::SignIn {
                    tenant_id: TenantId::new("tenant-a").expect("tenant"),
                },
                provider("github"),
            ),
            LoginTransactionVersion::new(2).expect("version"),
            identity("github", "42", 110),
            mismatched,
            membership(115),
            candidate(SessionKind::Browser, 120),
            UnixTimestamp::from_seconds(125),
        );
        assert_eq!(
            result.unwrap_err(),
            SignInValueError::IdentityCredentialMismatch
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn token_session_and_authentication_times_are_half_open_and_monotonic() {
    let expired_membership = FinalizeSignIn::new(
        browser_access(
            LoginTransactionPurpose::SignIn {
                tenant_id: TenantId::new("tenant-a").expect("tenant"),
            },
            provider("github"),
        ),
        LoginTransactionVersion::new(2).expect("version"),
        identity("github", "42", 110),
        tokens(
            "github",
            Some("42"),
            ProviderGrantKind::BrowserAuthorizationCode,
            100,
            Some(300),
            Some(400),
            "access",
        ),
        membership_until(115, 125),
        candidate(SessionKind::Browser, 120),
        UnixTimestamp::from_seconds(125),
    );
    assert_eq!(
        expired_membership.unwrap_err(),
        SignInValueError::ExpiredMembershipObservation
    );

    let no_access_expiry = FinalizeSignIn::new(
        browser_access(
            LoginTransactionPurpose::SignIn {
                tenant_id: TenantId::new("tenant-a").expect("tenant"),
            },
            provider("github"),
        ),
        LoginTransactionVersion::new(2).expect("version"),
        identity("github", "42", 110),
        tokens(
            "github",
            Some("42"),
            ProviderGrantKind::BrowserAuthorizationCode,
            100,
            None,
            None,
            "access",
        ),
        membership(115),
        candidate(SessionKind::Browser, 120),
        UnixTimestamp::from_seconds(125),
    );
    assert_eq!(
        no_access_expiry.unwrap_err(),
        SignInValueError::InvalidProviderTokenLifetime
    );

    let membership_outlives_access = FinalizeSignIn::new(
        browser_access(
            LoginTransactionPurpose::SignIn {
                tenant_id: TenantId::new("tenant-a").expect("tenant"),
            },
            provider("github"),
        ),
        LoginTransactionVersion::new(2).expect("version"),
        identity("github", "42", 110),
        tokens(
            "github",
            Some("42"),
            ProviderGrantKind::BrowserAuthorizationCode,
            100,
            Some(200),
            Some(400),
            "access",
        ),
        membership_until(115, 201),
        candidate(SessionKind::Browser, 120),
        UnixTimestamp::from_seconds(125),
    );
    assert_eq!(
        membership_outlives_access.unwrap_err(),
        SignInValueError::InvalidProviderTokenLifetime
    );

    for (access_expiry, refresh_expiry) in [(125, 400), (300, 300)] {
        let result = FinalizeSignIn::new(
            browser_access(
                LoginTransactionPurpose::SignIn {
                    tenant_id: TenantId::new("tenant-a").expect("tenant"),
                },
                provider("github"),
            ),
            LoginTransactionVersion::new(2).expect("version"),
            identity("github", "42", 110),
            tokens(
                "github",
                Some("42"),
                ProviderGrantKind::BrowserAuthorizationCode,
                100,
                Some(access_expiry),
                Some(refresh_expiry),
                "access",
            ),
            membership(115),
            candidate(SessionKind::Browser, 120),
            UnixTimestamp::from_seconds(125),
        );
        assert_eq!(
            result.unwrap_err(),
            SignInValueError::InvalidProviderTokenLifetime
        );
    }

    let invalid_order = FinalizeSignIn::new(
        browser_access(
            LoginTransactionPurpose::SignIn {
                tenant_id: TenantId::new("tenant-a").expect("tenant"),
            },
            provider("github"),
        ),
        LoginTransactionVersion::new(2).expect("version"),
        identity("github", "42", 105),
        tokens(
            "github",
            Some("42"),
            ProviderGrantKind::BrowserAuthorizationCode,
            110,
            Some(300),
            Some(400),
            "access",
        ),
        membership(115),
        candidate(SessionKind::Browser, 120),
        UnixTimestamp::from_seconds(125),
    );
    assert_eq!(
        invalid_order.unwrap_err(),
        SignInValueError::InvalidTimeOrder
    );

    let expired_session = FinalizeSignIn::new(
        browser_access(
            LoginTransactionPurpose::SignIn {
                tenant_id: TenantId::new("tenant-a").expect("tenant"),
            },
            provider("github"),
        ),
        LoginTransactionVersion::new(2).expect("version"),
        identity("github", "42", 110),
        tokens(
            "github",
            Some("42"),
            ProviderGrantKind::BrowserAuthorizationCode,
            100,
            Some(1_000),
            Some(2_000),
            "access",
        ),
        membership(115),
        candidate(SessionKind::Browser, 120),
        UnixTimestamp::from_seconds(720),
    );
    assert_eq!(
        expired_session.unwrap_err(),
        SignInValueError::InvalidSessionLifetime
    );
}

#[test]
fn consumed_version_must_leave_room_for_the_succeeded_revision() {
    let maximum = FinalizeSignIn::new(
        browser_access(
            LoginTransactionPurpose::SignIn {
                tenant_id: TenantId::new("tenant-a").expect("tenant"),
            },
            provider("github"),
        ),
        LoginTransactionVersion::new(i64::MAX as u64).expect("maximum version"),
        identity("github", "42", 110),
        tokens(
            "github",
            Some("42"),
            ProviderGrantKind::BrowserAuthorizationCode,
            100,
            Some(300),
            Some(400),
            "access",
        ),
        membership(115),
        candidate(SessionKind::Browser, 120),
        UnixTimestamp::from_seconds(125),
    );
    assert_eq!(maximum.unwrap_err(), SignInValueError::InvalidVersion);

    assert_eq!(
        valid_browser_request("another-secret")
            .expected_version()
            .value(),
        2
    );
}
