mod support;

use automata_ci_auth::{
    human::{PrincipalId, ProviderId, ProviderSubject, TenantId},
    login::{
        LoginBindingDigest, LoginBindingDigestKeyId, LoginTransaction, LoginTransactionAccess,
        LoginTransactionBinding, LoginTransactionFlow, LoginTransactionId, LoginTransactionPurpose,
        LoginTransactionState, LoginTransactionValueError, LoginTransactionVersion,
    },
    secret::{SecretBytes, SecretString, SessionToken},
    session::{
        ActivateCliSession, BROWSER_SESSION_AUDIENCE, CLI_SESSION_ACTIVATION_LIFETIME_SECONDS,
        CLI_SESSION_AUDIENCE, DurableSession, DurableSessionIdentity, SessionId, SessionKind,
        SessionResolutionStatus, SessionTokenDigest, SessionTokenDigestKeyId, SessionTokenLookup,
    },
    time::UnixTimestamp,
};
use static_assertions::assert_not_impl_any;

use support::secret;

assert_not_impl_any!(SessionToken: serde::Serialize, Clone);
assert_not_impl_any!(LoginTransactionState: serde::Serialize, Clone);
assert_not_impl_any!(LoginTransaction: serde::Serialize, Clone);
assert_not_impl_any!(ActivateCliSession: serde::Serialize);

const SESSION_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const PRINCIPAL_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const LOGIN_ID: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

fn durable_session(
    kind: SessionKind,
    revision: u64,
    idle_expires_at: u64,
    revoked_at: Option<u64>,
) -> DurableSession {
    DurableSession::new(
        DurableSessionIdentity::new(
            SessionId::new(SESSION_ID).expect("session ID"),
            TenantId::new("tenant-1").expect("tenant ID"),
            PrincipalId::new(PRINCIPAL_ID).expect("principal ID"),
            ProviderId::new("github").expect("provider ID"),
            ProviderSubject::new("42").expect("provider subject"),
            kind,
        )
        .expect("durable identity"),
        revision,
        UnixTimestamp::from_seconds(100),
        UnixTimestamp::from_seconds(120),
        UnixTimestamp::from_seconds(idle_expires_at),
        UnixTimestamp::from_seconds(300),
        revoked_at.map(UnixTimestamp::from_seconds),
    )
    .expect("durable session")
}

fn binding(key: &str, byte: u8) -> LoginTransactionBinding {
    LoginTransactionBinding::new(
        LoginBindingDigestKeyId::new(key).expect("binding key ID"),
        LoginBindingDigest::new([byte; 32]),
    )
}

#[test]
fn raw_bearers_never_enter_serializable_session_lookup_material() {
    let raw = SessionToken::from_secret(secret("raw-session-bearer"));
    let lookup = SessionTokenLookup::new(
        SessionTokenDigestKeyId::new("session-hmac-v1").expect("digest key ID"),
        SessionTokenDigest::new([9; 32]),
    );

    let encoded = serde_json::to_string(&lookup).expect("serialize safe lookup");
    assert!(!encoded.contains(raw.expose_secret()));
    assert!(!format!("{lookup:?}").contains("9, 9"));
    assert_eq!(
        serde_json::from_str::<SessionTokenLookup>(&encoded).expect("deserialize lookup"),
        lookup
    );
}

#[test]
fn cli_activation_request_is_raw_free_and_has_one_short_bound() {
    let lookup = SessionTokenLookup::new(
        SessionTokenDigestKeyId::new("activation-hmac-v1").expect("digest key ID"),
        SessionTokenDigest::new([0x71; 32]),
    );
    let request = ActivateCliSession::new(lookup.clone(), UnixTimestamp::from_seconds(150));
    assert_eq!(request.lookup(), &lookup);
    assert_eq!(request.now(), UnixTimestamp::from_seconds(150));
    assert_eq!(CLI_SESSION_ACTIVATION_LIFETIME_SECONDS, 300);
    assert!(!format!("{request:?}").contains("71, 71"));
}

#[test]
fn browser_and_cli_kind_audiences_cannot_be_confused() {
    assert_eq!(BROWSER_SESSION_AUDIENCE, "automata.web");
    assert_eq!(CLI_SESSION_AUDIENCE, "automata.cli");
    assert_ne!(BROWSER_SESSION_AUDIENCE, CLI_SESSION_AUDIENCE);
    let browser = durable_session(SessionKind::Browser, 3, 200, None);

    assert_eq!(browser.identity().audience(), BROWSER_SESSION_AUDIENCE);
    assert_eq!(
        browser.resolution_status(SessionKind::Cli, UnixTimestamp::from_seconds(150), 3),
        SessionResolutionStatus::WrongKindOrAudience
    );
}

#[test]
fn durable_session_resolution_checks_revocation_idle_expiry_and_current_revision() {
    let active = durable_session(SessionKind::Browser, 3, 180, None);
    assert_eq!(
        active.resolution_status(SessionKind::Browser, UnixTimestamp::from_seconds(150), 3),
        SessionResolutionStatus::Active
    );
    assert_eq!(
        active.resolution_status(SessionKind::Browser, UnixTimestamp::from_seconds(150), 4),
        SessionResolutionStatus::AuthorizationRevisionChanged {
            session_revision: 3,
            current_revision: 4,
        }
    );
    assert_eq!(
        active.resolution_status(SessionKind::Browser, UnixTimestamp::from_seconds(180), 3),
        SessionResolutionStatus::Expired
    );

    let revoked = durable_session(SessionKind::Browser, 3, 200, Some(140));
    assert_eq!(
        revoked.resolution_status(SessionKind::Browser, UnixTimestamp::from_seconds(150), 3),
        SessionResolutionStatus::Revoked
    );
}

#[test]
fn durable_session_metadata_round_trips_without_bearer_or_role_snapshot() {
    let session = durable_session(SessionKind::Cli, 11, 240, None);
    let encoded = serde_json::to_value(&session).expect("serialize session metadata");
    assert_eq!(encoded["identity"]["kind"], "cli");
    assert!(encoded.get("token").is_none());
    assert!(encoded.get("roles").is_none());
    assert_eq!(
        serde_json::from_value::<DurableSession>(encoded).expect("restore session metadata"),
        session
    );
}

#[test]
fn browser_login_round_trip_requires_independent_state_and_client_binding() {
    let state = binding("oauth-state-v1", 7);
    let client_binding = binding("browser-cookie-v1", 8);
    let transaction = LoginTransaction::new(
        LoginTransactionId::new(LOGIN_ID).expect("transaction ID"),
        LoginTransactionPurpose::SignIn {
            tenant_id: TenantId::new("tenant-1").expect("tenant ID"),
        },
        ProviderId::new("github").expect("provider ID"),
        LoginTransactionFlow::browser(state.clone(), client_binding.clone()).expect("flow"),
        None,
        LoginTransactionState::new(
            SecretBytes::new(b"provider-state-secret".to_vec()).expect("state"),
        ),
        UnixTimestamp::from_seconds(100),
        UnixTimestamp::from_seconds(700),
    )
    .expect("valid transaction");
    let rendered = format!("{transaction:?}");
    assert!(!rendered.contains("provider-state-secret"));
    assert!(!rendered.contains("7, 7"));

    let (id, purpose, provider, flow, return_path, state_secret, created_at, expires_at) =
        transaction.into_parts();
    let restored = LoginTransaction::new(
        id,
        purpose.clone(),
        provider.clone(),
        flow,
        return_path,
        state_secret,
        created_at,
        expires_at,
    )
    .expect("restore transaction");
    assert_eq!(restored.id().as_str(), LOGIN_ID);
    assert_eq!(restored.state().expose_secret(), b"provider-state-secret");

    let access = LoginTransactionAccess::browser(
        LoginTransactionId::new(LOGIN_ID).expect("transaction ID"),
        purpose,
        provider,
        state.clone(),
        client_binding,
    )
    .expect("two-proof access");
    assert!(access.proof().browser_proofs().is_some());
    assert!(
        LoginTransactionAccess::browser(
            LoginTransactionId::new(LOGIN_ID).expect("transaction ID"),
            LoginTransactionPurpose::InstallationSetup,
            ProviderId::new("github").expect("provider ID"),
            state.clone(),
            state,
        )
        .is_err()
    );
}

#[test]
fn installation_setup_device_transactions_have_no_tenant_and_validate_polling() {
    let transaction = LoginTransaction::new(
        LoginTransactionId::new(LOGIN_ID).expect("transaction ID"),
        LoginTransactionPurpose::InstallationSetup,
        ProviderId::new("github").expect("provider ID"),
        LoginTransactionFlow::device(
            binding("device-poll-v1", 9),
            SecretString::new("ABCD-EFGH").expect("user code"),
            "https://github.com/login/device",
            5_000,
            UnixTimestamp::from_seconds(110),
        )
        .expect("device flow"),
        None,
        LoginTransactionState::new(SecretBytes::new(vec![1]).expect("state")),
        UnixTimestamp::from_seconds(100),
        UnixTimestamp::from_seconds(700),
    )
    .expect("setup transaction");

    assert_eq!(transaction.tenant_id(), None);
    assert_eq!(transaction.purpose().database_value(), "installation_setup");
    assert!(!format!("{transaction:?}").contains("ABCD-EFGH"));
    assert!(LoginTransactionId::new("portable-but-not-a-uuid").is_err());
    assert!(LoginTransactionVersion::new(0).is_err());
    assert!(serde_json::from_value::<LoginTransactionVersion>(serde_json::json!(0)).is_err());
}

#[test]
fn device_verification_uri_requires_a_credential_free_https_origin() {
    let flow = |uri| {
        LoginTransactionFlow::device(
            binding("device-poll-v1", 9),
            SecretString::new("ABCD-EFGH").expect("user code"),
            uri,
            5_000,
            UnixTimestamp::from_seconds(110),
        )
    };

    assert!(flow("https://github.com/login/device?source=cli").is_ok());
    for invalid in [
        "https://",
        "http://github.com/login/device",
        "https://user@github.com/login/device",
        "https://github.com/login/device#code",
        "https://github.com\\attacker.example",
    ] {
        assert_eq!(
            flow(invalid).unwrap_err(),
            LoginTransactionValueError::InvalidVerificationUri,
            "{invalid}"
        );
    }
}
