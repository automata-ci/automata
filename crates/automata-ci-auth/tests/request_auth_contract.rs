use std::collections::BTreeSet;

use automata_ci_auth::{
    authorization::{AuthorizationContext, AuthorizationScope, RoleName, ScopedRoleGrant},
    human::{AuthenticatedHuman, PrincipalId, ProviderId, ProviderSubject, TenantId},
    request_auth::{
        AuthenticatedRequestSnapshot, ResolveAuthenticatedRequest, ViewerDisplayMetadata,
    },
    session::{
        DurableSession, DurableSessionIdentity, SessionId, SessionKind, SessionTokenDigest,
        SessionTokenDigestKeyId, SessionTokenLookup,
    },
    time::UnixTimestamp,
};

const SESSION_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const PRINCIPAL_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

fn tenant(value: &str) -> TenantId {
    TenantId::new(value).expect("tenant")
}

fn principal(value: &str) -> PrincipalId {
    PrincipalId::new(value).expect("principal")
}

fn session() -> DurableSession {
    DurableSession::new(
        DurableSessionIdentity::new(
            SessionId::new(SESSION_ID).expect("session ID"),
            tenant("tenant-a"),
            principal(PRINCIPAL_ID),
            ProviderId::new("github").expect("provider"),
            ProviderSubject::new("sensitive-stable-subject").expect("subject"),
            SessionKind::Browser,
        )
        .expect("identity"),
        4,
        UnixTimestamp::from_seconds(100),
        UnixTimestamp::from_seconds(110),
        UnixTimestamp::from_seconds(200),
        UnixTimestamp::from_seconds(300),
        None,
    )
    .expect("session")
}

fn human(principal_id: &str) -> AuthenticatedHuman {
    AuthenticatedHuman::new(
        principal(principal_id),
        ProviderId::new("github").expect("provider"),
        ProviderSubject::new("sensitive-stable-subject").expect("subject"),
        "octocat",
        Some("Octo Cat".to_owned()),
        UnixTimestamp::from_seconds(100),
    )
    .expect("human")
}

#[test]
fn snapshot_requires_exact_session_human_and_authorization_identities() {
    let grant = ScopedRoleGrant::new(
        AuthorizationScope::tenant(tenant("tenant-a")),
        RoleName::new("viewer").expect("role"),
    );
    let authorization = AuthorizationContext::authenticated(
        tenant("tenant-a"),
        principal(PRINCIPAL_ID),
        BTreeSet::from([grant]),
    )
    .expect("authorization");
    let viewer = ViewerDisplayMetadata::new("Octo Cat").expect("viewer");
    let snapshot =
        AuthenticatedRequestSnapshot::new(session(), human(PRINCIPAL_ID), viewer, authorization)
            .expect("snapshot");
    assert_eq!(snapshot.human().login(), "octocat");
    assert_eq!(snapshot.viewer().display_name(), "Octo Cat");
    assert_eq!(
        snapshot.authorization().role_grants().map(BTreeSet::len),
        Some(1)
    );

    let mismatch = AuthenticatedRequestSnapshot::new(
        session(),
        human("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
        ViewerDisplayMetadata::new("Octo Cat").expect("viewer"),
        AuthorizationContext::authenticated(
            tenant("tenant-a"),
            principal(PRINCIPAL_ID),
            BTreeSet::new(),
        )
        .expect("authorization"),
    );
    assert!(mismatch.is_err());

    let anonymous = AuthenticatedRequestSnapshot::new(
        session(),
        human(PRINCIPAL_ID),
        ViewerDisplayMetadata::new("Octo Cat").expect("viewer"),
        AuthorizationContext::anonymous(),
    );
    assert!(anonymous.is_err());
}

#[test]
fn viewer_metadata_is_bounded_and_control_free() {
    assert!(ViewerDisplayMetadata::new("").is_err());
    assert!(ViewerDisplayMetadata::new("bad\nname").is_err());
    assert!(ViewerDisplayMetadata::new("x".repeat(1_025)).is_err());
    assert_eq!(
        ViewerDisplayMetadata::new("x".repeat(1_024))
            .expect("maximum viewer")
            .display_name()
            .len(),
        1_024
    );
}

#[test]
fn request_and_snapshot_debug_omit_lookup_and_provider_subject_material() {
    let request = ResolveAuthenticatedRequest::new(
        SessionTokenLookup::new(
            SessionTokenDigestKeyId::new("lookup-secret-key-id").expect("key ID"),
            SessionTokenDigest::new([0x5a; 32]),
        ),
        SessionKind::Browser,
        UnixTimestamp::from_seconds(150),
    );
    let request_debug = format!("{request:?}");
    assert!(request_debug.contains("[REDACTED]"));
    assert!(!request_debug.contains("lookup-secret-key-id"));
    assert!(!request_debug.contains("90, 90"));

    let snapshot = AuthenticatedRequestSnapshot::new(
        session(),
        human(PRINCIPAL_ID),
        ViewerDisplayMetadata::new("Octo Cat").expect("viewer"),
        AuthorizationContext::authenticated(
            tenant("tenant-a"),
            principal(PRINCIPAL_ID),
            BTreeSet::new(),
        )
        .expect("authorization"),
    )
    .expect("snapshot");
    let snapshot_debug = format!("{snapshot:?}");
    assert!(!snapshot_debug.contains("sensitive-stable-subject"));
    assert!(!snapshot_debug.contains("octocat"));
}
