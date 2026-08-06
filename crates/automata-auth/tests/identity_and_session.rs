mod support;

use std::{collections::BTreeSet, sync::Arc};

use automata_auth::{
    authorization::RoleName,
    github::{GithubAppAuthenticationProvider, GithubUser},
    human::{
        AuthenticatedHuman, AuthenticationProvider, AuthenticationProviderError, PrincipalId,
        ProviderCredential, ProviderId, ProviderSubject, TenantId,
    },
    machine::{ExternalRunnerIdentity, MachineAuthenticationEvidence},
    session::{AutomataSessionClaims, SessionId, SessionValidationError},
    time::UnixTimestamp,
};
use futures::executor::block_on;

use support::{FixedClock, MockGithubEndpoint, secret};

#[test]
fn github_provider_revalidates_the_stable_user_id() {
    let endpoint = MockGithubEndpoint::shared();
    endpoint.push_user(Ok(GithubUser {
        id: 42,
        login: "octocat".to_owned(),
        name: Some("The Octocat".to_owned()),
    }));
    let provider = GithubAppAuthenticationProvider::new(
        ProviderId::new("github").expect("provider ID"),
        endpoint.clone(),
        Arc::new(FixedClock(UnixTimestamp::from_seconds(123))),
    );
    let credential = ProviderCredential::new(
        ProviderId::new("github").expect("provider ID"),
        secret("ghu_user_token"),
    );

    let human = block_on(provider.authenticate(&credential)).expect("authenticate user");
    assert_eq!(human.principal_id().as_str(), "github:42");
    assert_eq!(human.provider_subject().as_str(), "42");
    assert_eq!(human.login(), "octocat");
    assert_eq!(human.authenticated_at(), UnixTimestamp::from_seconds(123));
    let observed = endpoint.observed.lock().expect("observations");
    assert_eq!(observed.current_user_calls, 1);
    assert_eq!(
        observed.current_user_token.as_deref(),
        Some("ghu_user_token")
    );
}

#[test]
fn credential_cannot_cross_provider_boundaries() {
    let endpoint = MockGithubEndpoint::shared();
    let provider = GithubAppAuthenticationProvider::new(
        ProviderId::new("github").expect("provider ID"),
        endpoint.clone(),
        Arc::new(FixedClock(UnixTimestamp::from_seconds(1))),
    );
    let credential = ProviderCredential::new(
        ProviderId::new("oidc").expect("provider ID"),
        secret("credential"),
    );

    let result = block_on(provider.authenticate(&credential));
    assert_eq!(result, Err(AuthenticationProviderError::WrongProvider));
    assert_eq!(
        endpoint
            .observed
            .lock()
            .expect("observations")
            .current_user_calls,
        0
    );
}

#[test]
fn malformed_provider_identity_is_rejected() {
    let endpoint = MockGithubEndpoint::shared();
    endpoint.push_user(Ok(GithubUser {
        id: 0,
        login: "octocat".to_owned(),
        name: None,
    }));
    let provider = GithubAppAuthenticationProvider::new(
        ProviderId::new("github").expect("provider ID"),
        endpoint,
        Arc::new(FixedClock(UnixTimestamp::from_seconds(1))),
    );
    let credential = ProviderCredential::new(
        ProviderId::new("github").expect("provider ID"),
        secret("credential"),
    );
    assert_eq!(
        block_on(provider.authenticate(&credential)),
        Err(AuthenticationProviderError::InvalidResponse)
    );
}

fn claims() -> AutomataSessionClaims {
    AutomataSessionClaims::new(
        SessionId::new("session-1").expect("session ID"),
        TenantId::new("tenant-1").expect("tenant ID"),
        PrincipalId::new("github:42").expect("principal ID"),
        ProviderId::new("github").expect("provider ID"),
        ProviderSubject::new("42").expect("provider subject"),
        BTreeSet::from([RoleName::new("viewer").expect("role")]),
        "automata-api",
        UnixTimestamp::from_seconds(100),
        UnixTimestamp::from_seconds(200),
        7,
    )
    .expect("valid claims")
}

#[test]
fn sessions_validate_audience_and_half_open_lifetime() {
    let claims = claims();
    assert!(
        claims
            .validate(UnixTimestamp::from_seconds(199), "automata-api")
            .is_ok()
    );
    assert_eq!(
        claims.validate(UnixTimestamp::from_seconds(200), "automata-api"),
        Err(SessionValidationError::Expired)
    );
    assert_eq!(
        claims.validate(UnixTimestamp::from_seconds(150), "another-service"),
        Err(SessionValidationError::WrongAudience)
    );
}

#[test]
fn safe_session_claims_are_serializable_without_a_bearer_token() {
    let serialized = serde_json::to_value(claims()).expect("serialize claims");
    assert_eq!(serialized["principal_id"], "github:42");
    assert!(serialized.get("token").is_none());
    assert!(serialized.get("access_token").is_none());
}

#[test]
fn machine_evidence_is_a_separate_redacted_boundary() {
    let evidence =
        MachineAuthenticationEvidence::new(vec![vec![1, 2, 3]]).expect("certificate evidence");
    let rendered = format!("{evidence:?}");
    assert!(rendered.contains("certificate_count"));
    assert!(!rendered.contains("1, 2, 3"));
    assert!(ExternalRunnerIdentity::new("").is_err());
}

#[test]
fn human_authentication_result_contains_no_machine_identity() {
    let human = AuthenticatedHuman::new(
        PrincipalId::new("github:42").expect("principal ID"),
        ProviderId::new("github").expect("provider ID"),
        ProviderSubject::new("42").expect("provider subject"),
        "octocat",
        None,
        UnixTimestamp::from_seconds(1),
    )
    .expect("valid human identity");
    let serialized = serde_json::to_value(human).expect("serialize human identity");
    assert!(serialized.get("runner_id").is_none());
    assert!(serialized.get("certificate_sha256").is_none());
}
