mod support;

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use automata_ci_auth::{
    github::{
        GithubMembershipObservation, GithubMembershipSnapshot, GithubMembershipSnapshotId,
        GithubOrganizationId, GithubOrganizationLogin, GithubOrganizationMembership,
        GithubOrganizationMembershipRole,
    },
    human::{PrincipalId, ProviderId, ProviderIdentityAssertion, ProviderSubject, TenantId},
    installation::{
        ArmInstallationSetup, CompleteInstallationSetup, CompletedInstallation, InstallationProof,
        InstallationProofDigest, InstallationProofKeyId, InstallationProviderAuthentication,
        InstallationRevision, InstallationTenant, InstallationValueError,
    },
    login::LoginTransactionId,
    secret::{SecretBytes, SecretString},
    session::{
        DurableSession, DurableSessionIdentity, HumanSessionRepository, ResolveSession,
        ResolveSessionOutcome, RevokeOwnSession, RevokeOwnSessionOutcome, RevokePrincipalSessions,
        RevokePrincipalSessionsOutcome, SessionId, SessionKind, SessionRepositoryFuture,
        SessionTokenDigestKeyId, TouchSession, TouchSessionOutcome,
    },
    session_credential::{
        SessionCredentialKey, SessionCredentialKeyring, SessionCredentialService,
    },
    sign_in::PendingSessionCandidate,
    time::UnixTimestamp,
    vault::{
        ProviderAccessToken, ProviderGrantKind, ProviderRefreshToken, ProviderTokenMetadata,
        ProviderTokenSet,
    },
};

use support::{DeterministicRandom, FixedClock};

#[derive(Debug)]
struct UnusedSessionRepository;

impl HumanSessionRepository for UnusedSessionRepository {
    fn resolve<'a>(
        &'a self,
        _request: &'a ResolveSession,
    ) -> SessionRepositoryFuture<'a, ResolveSessionOutcome> {
        panic!("not used by installation session preparation")
    }

    fn touch<'a>(
        &'a self,
        _request: &'a TouchSession,
    ) -> SessionRepositoryFuture<'a, TouchSessionOutcome> {
        panic!("not used by installation session preparation")
    }

    fn revoke_own<'a>(
        &'a self,
        _request: &'a RevokeOwnSession,
    ) -> SessionRepositoryFuture<'a, RevokeOwnSessionOutcome> {
        panic!("not used by installation session preparation")
    }

    fn revoke_principal<'a>(
        &'a self,
        _request: &'a RevokePrincipalSessions,
    ) -> SessionRepositoryFuture<'a, RevokePrincipalSessionsOutcome> {
        panic!("not used by installation session preparation")
    }
}

fn proof(byte: u8) -> InstallationProof {
    InstallationProof::new(
        InstallationProofKeyId::new("bootstrap-hmac-v1").expect("proof key ID"),
        InstallationProofDigest::new([byte; 32]),
    )
}

fn identity(subject: &str, authenticated_at: u64) -> ProviderIdentityAssertion {
    ProviderIdentityAssertion::new(
        ProviderId::new("github").expect("provider"),
        ProviderSubject::new(subject).expect("subject"),
        "octocat",
        Some("The Octocat".to_owned()),
        UnixTimestamp::from_seconds(authenticated_at),
    )
    .expect("identity")
}

fn unbound_tokens(provider: &str, issued_at: u64) -> ProviderTokenSet {
    let metadata = ProviderTokenMetadata::builder(
        ProviderId::new(provider).expect("provider"),
        ProviderGrantKind::BrowserAuthorizationCode,
        "Bearer",
        UnixTimestamp::from_seconds(issued_at),
    )
    .scopes(BTreeSet::from(["read:org".to_owned()]))
    .access_expires_at(Some(UnixTimestamp::from_seconds(300)))
    .refresh_expires_at(Some(UnixTimestamp::from_seconds(400)))
    .build()
    .expect("metadata");
    ProviderTokenSet::new(
        ProviderAccessToken::new(SecretString::new("access-secret").expect("access token")),
        Some(ProviderRefreshToken::new(
            SecretString::new("refresh-secret").expect("refresh token"),
        )),
        metadata,
    )
    .expect("token set")
}

fn tenant() -> InstallationTenant {
    InstallationTenant::new(TenantId::new("tenant-a").expect("tenant"), "Tenant A")
        .expect("installation tenant")
}

fn candidate() -> PendingSessionCandidate {
    let key = SessionCredentialKey::new(
        SessionTokenDigestKeyId::new("installation-session-hmac-v1").expect("session key ID"),
        SecretBytes::new(vec![0x5a; 32]).expect("session key"),
    )
    .expect("session credential key");
    let service = SessionCredentialService::new(
        SessionCredentialKeyring::new(key, Vec::new()).expect("session keyring"),
        Arc::new(UnusedSessionRepository),
        Arc::new(DeterministicRandom::new(0x44)),
        Arc::new(FixedClock(UnixTimestamp::from_seconds(148))),
    );
    let prepared = service
        .prepare(
            SessionKind::Browser,
            Duration::from_mins(1),
            Duration::from_mins(10),
        )
        .expect("prepared installation session");
    let (_credential, candidate) = prepared.into_parts();
    candidate
}

fn membership() -> GithubMembershipObservation {
    membership_until(300)
}

fn membership_until(valid_until: u64) -> GithubMembershipObservation {
    let organization_id = GithubOrganizationId::new(10).expect("organization ID");
    GithubMembershipObservation::new(
        GithubMembershipSnapshotId::new("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
            .expect("snapshot ID"),
        GithubMembershipSnapshot::new(
            [GithubOrganizationMembership::new(
                organization_id,
                GithubOrganizationLogin::new("automata-ci").expect("organization login"),
                GithubOrganizationMembershipRole::Admin,
            )],
            [],
        )
        .expect("membership snapshot"),
        UnixTimestamp::from_seconds(145),
        UnixTimestamp::from_seconds(valid_until),
    )
    .expect("membership observation")
}

fn durable_session(tenant_id: &str) -> DurableSession {
    let identity = DurableSessionIdentity::new(
        SessionId::new("cccccccc-cccc-4ccc-8ccc-cccccccccccc").expect("session ID"),
        TenantId::new(tenant_id).expect("tenant"),
        PrincipalId::new("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("principal"),
        ProviderId::new("github").expect("provider"),
        ProviderSubject::new("42").expect("subject"),
        SessionKind::Browser,
    )
    .expect("durable identity");
    DurableSession::new(
        identity,
        2,
        UnixTimestamp::from_seconds(148),
        UnixTimestamp::from_seconds(148),
        UnixTimestamp::from_seconds(208),
        UnixTimestamp::from_seconds(748),
        None,
    )
    .expect("durable session")
}

#[test]
fn proof_verifiers_are_redacted_and_key_ids_match_database_shape() {
    assert!(InstallationProofKeyId::new(":invalid").is_err());
    assert!(InstallationProofKeyId::new(".invalid").is_err());
    assert!(InstallationProofKeyId::new("-invalid").is_err());
    assert!(InstallationProofKeyId::new("_invalid").is_err());
    assert!(InstallationProofKeyId::new("bootstrap:v1").is_ok());

    let verifier = proof(0x41);
    let rendered = format!("{verifier:?}");
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains("65"));
    assert_eq!(verifier, proof(0x41));
    assert_ne!(verifier, proof(0x42));
}

#[test]
fn setup_lifetimes_and_completed_session_identity_are_strictly_bounded() {
    let now = UnixTimestamp::from_seconds(100);
    assert!(
        ArmInstallationSetup::new(
            tenant(),
            proof(1),
            ProviderId::new("github").expect("provider"),
            ProviderSubject::new("42").expect("subject"),
            now,
            now,
        )
        .is_err()
    );
    assert!(
        ArmInstallationSetup::new(
            tenant(),
            proof(1),
            ProviderId::new("github").expect("provider"),
            ProviderSubject::new("42").expect("subject"),
            now,
            UnixTimestamp::from_seconds(3_701),
        )
        .is_err()
    );
    let completed = CompletedInstallation::new(
        TenantId::new("tenant-a").expect("tenant"),
        PrincipalId::new("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("principal"),
        InstallationRevision::new(4).expect("revision"),
        Box::new(durable_session("tenant-a")),
    )
    .expect("consistent completed installation");
    assert_eq!(completed.authorization_revision(), 2);
    assert_eq!(
        completed.session().identity().tenant_id(),
        completed.tenant_id()
    );
    assert_eq!(
        CompletedInstallation::new(
            TenantId::new("tenant-a").expect("tenant"),
            PrincipalId::new("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("principal"),
            InstallationRevision::new(4).expect("revision"),
            Box::new(durable_session("tenant-b")),
        ),
        Err(InstallationValueError::InvalidCompletedSession)
    );
}

#[test]
fn completion_binds_pre_identity_tokens_to_the_proven_stable_subject() {
    let authentication = InstallationProviderAuthentication::new(
        LoginTransactionId::new("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").expect("login"),
        identity("42", 140),
        unbound_tokens("github", 130),
        membership(),
    )
    .expect("consistent provider authentication");
    let request = CompleteInstallationSetup::new(
        InstallationRevision::new(3).expect("revision"),
        tenant(),
        authentication,
        candidate(),
        UnixTimestamp::from_seconds(150),
    )
    .expect("consistent completion");
    let (retry, session) = request.into_retry_parts();
    assert_eq!(
        retry.provider_tokens().metadata().provider_subject(),
        Some(retry.identity().provider_subject())
    );
    assert!(!format!("{:?}", retry.provider_tokens()).contains("access-secret"));
    assert!(!format!("{:?}", retry.provider_tokens()).contains("refresh-secret"));
    assert_eq!(retry.membership().memberships().organizations().len(), 1);
    assert_eq!(session.kind(), SessionKind::Browser);

    assert_eq!(
        InstallationProviderAuthentication::new(
            LoginTransactionId::new("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").expect("login"),
            identity("42", 140),
            unbound_tokens("gitlab", 130),
            membership(),
        )
        .expect_err("wrong provider must fail"),
        InstallationValueError::IdentityCredentialMismatch
    );

    let outliving_authentication = InstallationProviderAuthentication::new(
        LoginTransactionId::new("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").expect("login"),
        identity("42", 140),
        unbound_tokens("github", 130),
        membership_until(301),
    )
    .expect("provider authentication");
    assert_eq!(
        CompleteInstallationSetup::new(
            InstallationRevision::new(3).expect("revision"),
            tenant(),
            outliving_authentication,
            candidate(),
            UnixTimestamp::from_seconds(150),
        )
        .expect_err("membership authority cannot outlive its provider credential"),
        InstallationValueError::InvalidProviderTokenLifetime
    );
}
