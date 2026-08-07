mod support;

use std::time::Duration;

use automata_credential::{CredentialErrorKind, RepositoryCredentialBroker};
use automata_credential_github::GithubAppHttpLimits;
use axum::http::StatusCode;
use support::{FixtureServer, ResponseSpec, request, success_response};

#[tokio::test]
async fn redirects_are_not_followed_and_assertions_are_not_forwarded() {
    let source = FixtureServer::spawn().await;
    let sink = FixtureServer::spawn().await;
    source.enqueue(
        ResponseSpec::status(StatusCode::TEMPORARY_REDIRECT)
            .header("location", sink.url("credential-sink").as_str()),
    );
    sink.enqueue(success_response());
    let broker = source.broker();
    let error = broker.issue(&request()).await.unwrap_err();
    assert_eq!(error.kind(), CredentialErrorKind::InvalidResponse);
    assert_eq!(source.requests().len(), 1);
    assert!(source.requests()[0].headers.contains_key("authorization"));
    assert!(sink.requests().is_empty());
    assert_eq!(sink.remaining_responses(), 1);
}

#[tokio::test]
async fn response_length_content_type_and_streaming_are_bounded() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::json(StatusCode::CREATED, "x".repeat(512)));
    fixture.enqueue(success_response().content_type("text/plain"));
    fixture.enqueue(ResponseSpec::json(StatusCode::CREATED, "x".repeat(512)).streamed());
    let limits =
        GithubAppHttpLimits::new(128, Duration::from_millis(50), Duration::from_secs(1)).unwrap();
    let broker = fixture.broker_with_limits(limits);
    for _ in 0..3 {
        assert_eq!(
            broker.issue(&request()).await.unwrap_err().kind(),
            CredentialErrorKind::InvalidResponse
        );
    }
}

#[tokio::test]
async fn complete_request_timeout_is_enforced() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(success_response().delayed(Duration::from_millis(150)));
    let limits =
        GithubAppHttpLimits::new(1_024, Duration::from_millis(10), Duration::from_millis(40))
            .unwrap();
    let broker = fixture.broker_with_limits(limits);
    let error = broker.issue(&request()).await.unwrap_err();
    assert_eq!(error.kind(), CredentialErrorKind::Unavailable);
}

#[tokio::test]
async fn statuses_are_sanitized_and_rate_limit_hints_are_bounded() {
    let fixture = FixtureServer::spawn().await;
    let cases = [
        (
            ResponseSpec::json(StatusCode::UNAUTHORIZED, r#"{"token":"body-secret"}"#),
            CredentialErrorKind::Unauthorized,
            None,
        ),
        (
            ResponseSpec::json(StatusCode::FORBIDDEN, r#"{"token":"body-secret"}"#),
            CredentialErrorKind::Forbidden,
            None,
        ),
        (
            ResponseSpec::json(StatusCode::NOT_FOUND, r#"{"token":"body-secret"}"#),
            CredentialErrorKind::NotFound,
            None,
        ),
        (
            ResponseSpec::json(
                StatusCode::UNPROCESSABLE_ENTITY,
                r#"{"token":"body-secret"}"#,
            ),
            CredentialErrorKind::InvalidRequest,
            None,
        ),
        (
            ResponseSpec::json(StatusCode::TOO_MANY_REQUESTS, r#"{"token":"body-secret"}"#)
                .header("retry-after", "17"),
            CredentialErrorKind::RateLimited,
            Some(17),
        ),
        (
            ResponseSpec::json(StatusCode::TOO_MANY_REQUESTS, r#"{"token":"body-secret"}"#)
                .header("retry-after", "999999"),
            CredentialErrorKind::RateLimited,
            None,
        ),
        (
            ResponseSpec::json(
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"token":"body-secret"}"#,
            ),
            CredentialErrorKind::Unavailable,
            None,
        ),
    ];
    let broker = fixture.broker();
    for (response, expected, retry_after) in cases {
        fixture.enqueue(response);
        let error = broker.issue(&request()).await.unwrap_err();
        assert_eq!(error.kind(), expected);
        assert_eq!(error.retry_after_seconds(), retry_after);
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("body-secret"));
        assert!(!rendered.contains("eyJ"));
    }
}
