mod support;

use std::collections::BTreeMap;

use automata_ci_auth::{
    github::{
        GithubAppConfig, GithubAppProtocol, GithubClientId, GithubConfigurationError,
        GithubEndpoints, GithubFlowError, GithubWebCallback,
    },
    human::ProviderId,
    secret::{OAuthState, PkceVerifier},
    time::UnixTimestamp,
};
use futures::executor::block_on;
use url::Url;

use support::{DeterministicRandom, MockGithubEndpoint, config, secret, token_response};

#[test]
fn browser_authorization_requires_state_and_s256_pkce() {
    let protocol = GithubAppProtocol::new(config());
    let authorization = protocol
        .begin_web(
            &DeterministicRandom::new(1),
            UnixTimestamp::from_seconds(100),
        )
        .expect("begin web authorization");
    let state = authorization.transaction().state_secret().to_owned();
    let query = authorization
        .authorization_url()
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(
        query.get("client_id").map(String::as_str),
        Some("Iv1abc123")
    );
    assert_eq!(
        query.get("redirect_uri").map(String::as_str),
        Some("https://automata.example/auth/github/callback")
    );
    assert_eq!(query.get("state"), Some(&state));
    assert_eq!(
        query.get("code_challenge_method").map(String::as_str),
        Some("S256")
    );
    assert_eq!(query.get("code_challenge").map(String::len), Some(43));
    assert_eq!(query.get("allow_signup").map(String::as_str), Some("false"));

    let rendered = format!("{authorization:?}");
    assert!(!rendered.contains(&state));
    assert!(!rendered.contains(query["code_challenge"].as_str()));
}

#[test]
fn state_is_checked_before_the_code_exchange() {
    let protocol = GithubAppProtocol::new(config());
    let authorization = protocol
        .begin_web(
            &DeterministicRandom::new(2),
            UnixTimestamp::from_seconds(100),
        )
        .expect("begin web authorization");
    let callback = GithubWebCallback::Authorized {
        code: secret("authorization-code"),
        state: secret("attacker-controlled-state"),
    };
    let endpoint = MockGithubEndpoint::default();

    let result = block_on(protocol.complete_web(
        &endpoint,
        authorization.into_transaction(),
        &callback,
        UnixTimestamp::from_seconds(101),
    ));

    assert!(matches!(result, Err(GithubFlowError::StateMismatch)));
    assert_eq!(endpoint.observed.lock().expect("observations").web_calls, 0);
}

#[test]
fn expired_and_denied_callbacks_never_exchange_a_code() {
    let protocol = GithubAppProtocol::new(config());
    let endpoint = MockGithubEndpoint::default();

    let expired = protocol
        .begin_web(
            &DeterministicRandom::new(3),
            UnixTimestamp::from_seconds(100),
        )
        .expect("begin expired flow");
    let expired_state = expired.transaction().state_secret().to_owned();
    let expired_callback = GithubWebCallback::Authorized {
        code: secret("authorization-code"),
        state: secret(&expired_state),
    };
    let result = block_on(protocol.complete_web(
        &endpoint,
        expired.into_transaction(),
        &expired_callback,
        UnixTimestamp::from_seconds(700),
    ));
    assert!(matches!(
        result,
        Err(GithubFlowError::WebTransactionExpired)
    ));

    let denied = protocol
        .begin_web(
            &DeterministicRandom::new(4),
            UnixTimestamp::from_seconds(100),
        )
        .expect("begin denied flow");
    let denied_state = denied.transaction().state_secret().to_owned();
    let denied_callback = GithubWebCallback::Denied {
        error: "access_denied".to_owned(),
        state: secret(&denied_state),
    };
    let result = block_on(protocol.complete_web(
        &endpoint,
        denied.into_transaction(),
        &denied_callback,
        UnixTimestamp::from_seconds(101),
    ));
    assert!(matches!(result, Err(GithubFlowError::AuthorizationDenied)));
    assert_eq!(endpoint.observed.lock().expect("observations").web_calls, 0);
}

#[test]
fn successful_exchange_carries_expiration_and_rotation_metadata() {
    let protocol = GithubAppProtocol::new(config());
    let endpoint = MockGithubEndpoint::default();
    endpoint.push_web(Ok(token_response()));
    let authorization = protocol
        .begin_web(
            &DeterministicRandom::new(5),
            UnixTimestamp::from_seconds(100),
        )
        .expect("begin flow");
    let state = authorization.transaction().state_secret().to_owned();
    let callback = GithubWebCallback::Authorized {
        code: secret("one-use-code"),
        state: secret(&state),
    };

    let tokens = block_on(protocol.complete_web(
        &endpoint,
        authorization.into_transaction(),
        &callback,
        UnixTimestamp::from_seconds(120),
    ))
    .expect("complete flow");

    assert_eq!(
        tokens.metadata().access_expires_at(),
        Some(UnixTimestamp::from_seconds(28_920))
    );
    assert_eq!(
        tokens.metadata().refresh_expires_at(),
        Some(UnixTimestamp::from_seconds(15_897_720))
    );
    assert!(tokens.refresh_token().is_some());
    assert_eq!(tokens.metadata().provider_subject(), None);
    let observed = endpoint.observed.lock().expect("observations");
    assert_eq!(observed.web_code.as_deref(), Some("one-use-code"));
    assert_eq!(observed.web_verifier.as_ref().map(String::len), Some(43));

    let rendered = format!("{tokens:?}");
    assert!(!rendered.contains("ghu_access_token_value"));
    assert!(!rendered.contains("ghr_refresh_token_value"));
}

#[test]
fn malformed_token_pairs_are_rejected() {
    let protocol = GithubAppProtocol::new(config());
    let endpoint = MockGithubEndpoint::default();
    let mut response = token_response();
    response.refresh_token_expires_in = None;
    endpoint.push_web(Ok(response));
    let authorization = protocol
        .begin_web(
            &DeterministicRandom::new(6),
            UnixTimestamp::from_seconds(100),
        )
        .expect("begin flow");
    let state = authorization.transaction().state_secret().to_owned();
    let callback = GithubWebCallback::Authorized {
        code: secret("code"),
        state: secret(&state),
    };

    let result = block_on(protocol.complete_web(
        &endpoint,
        authorization.into_transaction(),
        &callback,
        UnixTimestamp::from_seconds(101),
    ));
    assert!(matches!(
        result,
        Err(GithubFlowError::InvalidProviderResponse)
    ));
}

#[test]
fn configuration_rejects_untrusted_origins_and_callback_urls() {
    let result = GithubEndpoints::new(
        Url::parse("https://github.example/login/oauth/authorize").expect("authorize URL"),
        Url::parse("https://evil.example/login/device/code").expect("device URL"),
        Url::parse("https://github.example/login/oauth/access_token").expect("token URL"),
    );
    assert!(matches!(
        result,
        Err(GithubConfigurationError::EndpointOriginMismatch)
    ));

    let result = GithubAppConfig::new(
        ProviderId::new("github").expect("provider ID"),
        GithubClientId::new("Iv1abc").expect("client ID"),
        secret("client-secret"),
        Url::parse("http://automata.example/callback").expect("callback URL"),
        GithubEndpoints::github_dot_com().expect("GitHub endpoints"),
        600,
    );
    assert!(matches!(
        result,
        Err(GithubConfigurationError::InvalidCallbackUri)
    ));
}

#[test]
fn encrypted_web_transaction_parts_round_trip_without_losing_expiry_or_secrets() {
    let protocol = GithubAppProtocol::new(config());
    let endpoint = MockGithubEndpoint::default();
    endpoint.push_web(Ok(token_response()));
    let authorization = protocol
        .begin_web(
            &DeterministicRandom::new(9),
            UnixTimestamp::from_seconds(100),
        )
        .expect("begin flow");
    let parts = authorization.into_transaction().into_parts();
    let state = parts.state().expose_secret().to_owned();
    let verifier = parts.verifier().expose_secret().to_owned();
    assert_eq!(parts.created_at(), UnixTimestamp::from_seconds(100));
    assert_eq!(parts.expires_at(), UnixTimestamp::from_seconds(700));
    let rendered = format!("{parts:?}");
    assert!(!rendered.contains(&state));
    assert!(!rendered.contains(&verifier));

    let restored = automata_ci_auth::github::WebAuthorizationTransaction::from_parts(parts)
        .expect("restore web transaction");
    let callback = GithubWebCallback::Authorized {
        code: secret("one-use-code"),
        state: secret(&state),
    };
    block_on(protocol.complete_web(
        &endpoint,
        restored,
        &callback,
        UnixTimestamp::from_seconds(101),
    ))
    .expect("complete restored transaction");
    let observed = endpoint.observed.lock().expect("observations");
    assert_eq!(observed.web_verifier.as_deref(), Some(verifier.as_str()));
}

#[test]
fn restored_web_transactions_revalidate_state_shape_and_lifetime() {
    let verifier = PkceVerifier::from_secret(secret("0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"))
        .expect("PKCE verifier");
    let weak_state = OAuthState::from_secret(secret("attacker-selected-state"));
    let parts = automata_ci_auth::github::WebAuthorizationTransactionParts::new(
        weak_state,
        verifier,
        UnixTimestamp::from_seconds(100),
        UnixTimestamp::from_seconds(700),
    );
    assert!(automata_ci_auth::github::WebAuthorizationTransaction::from_parts(parts).is_err());
}
