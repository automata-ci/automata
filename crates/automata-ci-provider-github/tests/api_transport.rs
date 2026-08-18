use crate::support;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use automata_ci_auth::{
    github::{GithubCurrentUserRequest, GithubEndpoint, GithubEndpointError},
    secret::SecretString,
};
use automata_ci_provider_github::GithubHttpLimits;
use axum::http::StatusCode;
use support::{FixtureServer, ResponseSpec};

fn token() -> SecretString {
    SecretString::new("ghu_request_secret").unwrap()
}

#[tokio::test]
async fn current_user_uses_versioned_bearer_api_request() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        r#"{"id":42,"login":"octocat","name":"Mona Lisa"}"#,
    ));
    let endpoint = fixture.endpoint();
    let token = token();
    let user = endpoint
        .current_user(GithubCurrentUserRequest {
            access_token: &token,
        })
        .await
        .unwrap();
    assert_eq!(user.id, 42);
    assert_eq!(user.login, "octocat");

    let requests = fixture.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].uri, "/api/user");
    assert_eq!(
        requests[0].headers["authorization"],
        "Bearer ghu_request_secret"
    );
    assert_eq!(requests[0].headers["accept"], "application/vnd.github+json");
    assert_eq!(requests[0].headers["x-github-api-version"], "2026-03-10");
}

#[tokio::test]
async fn authentication_and_rate_limit_statuses_are_mapped_without_reading_bodies() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::status(StatusCode::UNAUTHORIZED));
    fixture.enqueue(ResponseSpec::status(StatusCode::FORBIDDEN));
    fixture
        .enqueue(ResponseSpec::status(StatusCode::FORBIDDEN).header("x-ratelimit-remaining", "0"));
    fixture
        .enqueue(ResponseSpec::status(StatusCode::TOO_MANY_REQUESTS).header("retry-after", "17"));
    let reset_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs()
        + 120;
    fixture.enqueue(
        ResponseSpec::status(StatusCode::FORBIDDEN)
            .header("x-ratelimit-remaining", "0")
            .header("x-ratelimit-reset", reset_at.to_string()),
    );
    let endpoint = fixture.endpoint();
    let token = token();
    let request = || GithubCurrentUserRequest {
        access_token: &token,
    };

    assert_eq!(
        endpoint.current_user(request()).await.unwrap_err(),
        GithubEndpointError::Unauthorized
    );
    assert_eq!(
        endpoint.current_user(request()).await.unwrap_err(),
        GithubEndpointError::Forbidden
    );
    assert_eq!(
        endpoint.current_user(request()).await.unwrap_err(),
        GithubEndpointError::RateLimited {
            retry_after_seconds: None
        }
    );
    assert_eq!(
        endpoint.current_user(request()).await.unwrap_err(),
        GithubEndpointError::RateLimited {
            retry_after_seconds: Some(17)
        }
    );
    let GithubEndpointError::RateLimited {
        retry_after_seconds: Some(delay),
    } = endpoint.current_user(request()).await.unwrap_err()
    else {
        panic!("expected a reset-aware rate-limit error");
    };
    assert!((115..=121).contains(&delay), "unexpected delay: {delay}");
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(
        ResponseSpec::status(StatusCode::FOUND).header("location", fixture.url("sink").as_str()),
    );
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        r#"{"id":99,"login":"attacker","name":null}"#,
    ));
    let endpoint = fixture.endpoint();
    let token = token();
    let error = endpoint
        .current_user(GithubCurrentUserRequest {
            access_token: &token,
        })
        .await
        .unwrap_err();
    assert_eq!(error, GithubEndpointError::InvalidResponse);
    assert_eq!(fixture.requests().len(), 1);
    assert_eq!(fixture.remaining_responses(), 1);
}

#[tokio::test]
async fn response_bytes_content_type_and_json_are_strictly_bounded() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        format!(r#"{{"id":1,"login":"{}","name":null}}"#, "x".repeat(256)),
    ));
    fixture.enqueue(
        ResponseSpec::json(StatusCode::OK, r#"{"id":1,"login":"octocat","name":null}"#)
            .content_type("text/plain"),
    );
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        r#"{"id":1,"login":"body-secret","name":null"#,
    ));
    let limits =
        GithubHttpLimits::new(128, 10, 100, Duration::from_secs(1), Duration::from_secs(2))
            .unwrap();
    let endpoint = fixture.endpoint_with_limits(limits);
    let token = token();
    let request = || GithubCurrentUserRequest {
        access_token: &token,
    };
    for _ in 0..3 {
        let error = endpoint.current_user(request()).await.unwrap_err();
        assert_eq!(error, GithubEndpointError::InvalidResponse);
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("ghu_request_secret"));
        assert!(!rendered.contains("body-secret"));
    }
}
