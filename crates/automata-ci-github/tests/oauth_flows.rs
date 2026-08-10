mod support;

use automata_ci_auth::{
    github::{
        DeviceCodeRequest, DeviceTokenPollRequest, GithubClientId, GithubDevicePollResponse,
        GithubEndpoint, RefreshTokenRequest, WebTokenExchangeRequest,
    },
    secret::{PkceVerifier, SecretString},
    vault::ProviderRefreshToken,
};
use axum::http::StatusCode;
use support::{FixtureServer, ResponseSpec};

fn secret(value: &str) -> SecretString {
    SecretString::new(value).unwrap()
}

fn client_id() -> GithubClientId {
    GithubClientId::new("Iv1Automata123").unwrap()
}

#[tokio::test]
async fn web_exchange_sends_pkce_and_returns_a_redacted_token_set() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        r#"{
            "access_token":"ghu_response_secret",
            "expires_in":28800,
            "refresh_token":"ghr_response_secret",
            "refresh_token_expires_in":15897600,
            "scope":"",
            "token_type":"bearer"
        }"#,
    ));
    let endpoint = fixture.endpoint();
    let client_id = client_id();
    let client_secret = secret("client-secret-value");
    let code = secret("authorization-code-value");
    let verifier =
        PkceVerifier::from_secret(secret("0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")).unwrap();
    let redirect_uri = fixture.url("auth/github/callback");
    let token = endpoint
        .exchange_web_code(WebTokenExchangeRequest {
            endpoint: &fixture.url("login/oauth/access_token"),
            client_id: &client_id,
            client_secret: &client_secret,
            code: &code,
            redirect_uri: &redirect_uri,
            code_verifier: &verifier,
        })
        .await
        .unwrap();

    assert_eq!(token.access_token.expose_secret(), "ghu_response_secret");
    assert_eq!(token.expires_in, Some(28_800));
    assert_eq!(
        token.refresh_token.as_ref().unwrap().expose_secret(),
        "ghr_response_secret"
    );
    let debug = format!("{token:?}");
    assert!(!debug.contains("ghu_response_secret"));
    assert!(!debug.contains("ghr_response_secret"));

    let requests = fixture.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method, "POST");
    assert_eq!(request.uri, "/login/oauth/access_token");
    assert_eq!(request.headers["user-agent"], "automata-tests/0.1.0");
    assert_eq!(request.headers["accept"], "application/json");
    assert_eq!(request.headers["x-github-api-version"], "2026-03-10");
    assert_eq!(
        request.headers["content-type"],
        "application/x-www-form-urlencoded"
    );
    let form = request.form();
    assert_eq!(form["client_id"], "Iv1Automata123");
    assert_eq!(form["client_secret"], "client-secret-value");
    assert_eq!(form["code"], "authorization-code-value");
    assert_eq!(form["redirect_uri"], redirect_uri.as_str());
    assert_eq!(form["code_verifier"], verifier.expose_secret());
}

#[tokio::test]
async fn device_code_and_all_poll_states_are_complete() {
    let fixture = FixtureServer::spawn().await;
    let verification_uri = fixture.url("login/device");
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        format!(
            r#"{{
                "device_code":"device-code-secret",
                "user_code":"ABCD-EFGH",
                "verification_uri":"{verification_uri}",
                "expires_in":900,
                "interval":5
            }}"#
        ),
    ));
    for error in [
        "authorization_pending",
        "slow_down",
        "access_denied",
        "expired_token",
        "bad_verification_code",
    ] {
        fixture.enqueue(ResponseSpec::json(
            StatusCode::OK,
            format!(r#"{{"error":"{error}"}}"#),
        ));
    }
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        r#"{
            "access_token":"ghu_device_token",
            "expires_in":28800,
            "refresh_token":"ghr_device_refresh",
            "refresh_token_expires_in":15897600,
            "scope":"",
            "token_type":"bearer"
        }"#,
    ));
    let endpoint = fixture.endpoint();
    let client_id = client_id();
    let oauth_endpoint = fixture.url("login/oauth/access_token");
    let device = endpoint
        .request_device_code(DeviceCodeRequest {
            endpoint: &fixture.url("login/device/code"),
            client_id: &client_id,
        })
        .await
        .unwrap();
    assert_eq!(device.device_code.expose_secret(), "device-code-secret");
    assert_eq!(device.user_code.expose_secret(), "ABCD-EFGH");
    assert_eq!(device.verification_uri, verification_uri);

    let expected = [
        "AuthorizationPending",
        "SlowDown",
        "AccessDenied",
        "ExpiredToken",
        "IncorrectDeviceCode",
    ];
    for expected in expected {
        let outcome = endpoint
            .poll_device_token(DeviceTokenPollRequest {
                endpoint: &oauth_endpoint,
                client_id: &client_id,
                device_code: &device.device_code,
            })
            .await
            .unwrap();
        assert_eq!(format!("{outcome:?}"), expected);
    }
    let outcome = endpoint
        .poll_device_token(DeviceTokenPollRequest {
            endpoint: &oauth_endpoint,
            client_id: &client_id,
            device_code: &device.device_code,
        })
        .await
        .unwrap();
    let GithubDevicePollResponse::Token(token) = outcome else {
        panic!("expected device token");
    };
    assert_eq!(token.access_token.expose_secret(), "ghu_device_token");

    let requests = fixture.requests();
    assert_eq!(requests.len(), 7);
    let poll_form = requests[1].form();
    assert_eq!(poll_form["device_code"], "device-code-secret");
    assert_eq!(
        poll_form["grant_type"],
        "urn:ietf:params:oauth:grant-type:device_code"
    );
}

#[tokio::test]
async fn refresh_grant_rotates_tokens_without_requiring_a_device_client_secret() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        r#"{
            "access_token":"ghu_refreshed",
            "expires_in":28800,
            "refresh_token":"ghr_rotated",
            "refresh_token_expires_in":15897600,
            "scope":"",
            "token_type":"bearer"
        }"#,
    ));
    let endpoint = fixture.endpoint();
    let client_id = client_id();
    let oauth_endpoint = fixture.url("login/oauth/access_token");
    let refresh_token = ProviderRefreshToken::new(secret("old-refresh-secret"));
    let refreshed = endpoint
        .refresh_token(RefreshTokenRequest {
            endpoint: &oauth_endpoint,
            client_id: &client_id,
            client_secret: None,
            refresh_token: &refresh_token,
        })
        .await
        .unwrap();
    assert_eq!(refreshed.access_token.expose_secret(), "ghu_refreshed");
    assert_eq!(
        refreshed.refresh_token.unwrap().expose_secret(),
        "ghr_rotated"
    );

    let requests = fixture.requests();
    assert_eq!(requests.len(), 1);
    let refresh_form = requests[0].form();
    assert_eq!(refresh_form["grant_type"], "refresh_token");
    assert_eq!(refresh_form["refresh_token"], "old-refresh-secret");
    assert!(!refresh_form.contains_key("client_secret"));
}

#[tokio::test]
async fn oauth_errors_are_typed_and_never_echo_secrets_or_bodies() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::json(
        StatusCode::BAD_REQUEST,
        r#"{"error":"incorrect_client_credentials","error_description":"client-secret-value"}"#,
    ));
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        r#"{"access_token":"sensitive-response-token""#,
    ));
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        r#"{"error":"incorrect_client_credentials"}"#,
    ));
    let endpoint = fixture.endpoint();
    let client_id = client_id();
    let client_secret = secret("client-secret-value");
    let code = secret("authorization-code-value");
    let verifier =
        PkceVerifier::from_secret(secret("0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")).unwrap();
    let oauth_endpoint = fixture.url("login/oauth/access_token");
    let redirect_uri = fixture.url("callback");

    let make_request = || WebTokenExchangeRequest {
        endpoint: &oauth_endpoint,
        client_id: &client_id,
        client_secret: &client_secret,
        code: &code,
        redirect_uri: &redirect_uri,
        code_verifier: &verifier,
    };
    let unauthorized = endpoint
        .exchange_web_code(make_request())
        .await
        .unwrap_err();
    assert_eq!(
        unauthorized,
        automata_ci_auth::github::GithubEndpointError::Unauthorized
    );
    let invalid = endpoint
        .exchange_web_code(make_request())
        .await
        .unwrap_err();
    assert_eq!(
        invalid,
        automata_ci_auth::github::GithubEndpointError::InvalidResponse
    );
    let rendered = format!("{unauthorized:?} {unauthorized} {invalid:?} {invalid}");
    for secret in [
        "client-secret-value",
        "authorization-code-value",
        "sensitive-response-token",
    ] {
        assert!(!rendered.contains(secret));
    }

    assert_eq!(
        endpoint
            .request_device_code(DeviceCodeRequest {
                endpoint: &fixture.url("login/device/code"),
                client_id: &client_id,
            })
            .await
            .unwrap_err(),
        automata_ci_auth::github::GithubEndpointError::Unauthorized
    );
}
