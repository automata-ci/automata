mod support;

use std::time::Duration;

use automata_ci_credential_github::{
    GithubAppHttpLimits, GithubInstallationTokenErrorKind,
    GithubInstallationTokenIndeterminateReason, GithubInstallationTokenMintOutcome,
};
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
    let outcome = broker.mint_once(&request()).await;
    let GithubInstallationTokenMintOutcome::Indeterminate(outcome) = outcome else {
        panic!("expected redirect ambiguity: {outcome:?}");
    };
    assert_eq!(
        outcome.reason(),
        GithubInstallationTokenIndeterminateReason::UnexpectedStatus
    );
    assert_eq!(source.requests().len(), 1);
    assert!(source.requests()[0].headers.contains_key("authorization"));
    assert!(sink.requests().is_empty());
    assert_eq!(sink.remaining_responses(), 1);
}

#[tokio::test]
async fn response_length_content_type_and_streaming_are_bounded() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::json(StatusCode::CREATED, "x".repeat(2_048)));
    fixture.enqueue(success_response().content_type("text/plain"));
    fixture.enqueue(ResponseSpec::json(StatusCode::CREATED, "x".repeat(2_048)).streamed());
    let limits =
        GithubAppHttpLimits::new(1_024, Duration::from_millis(50), Duration::from_secs(1)).unwrap();
    let broker = fixture.broker_with_limits(limits);
    assert!(matches!(
        broker.mint_once(&request()).await,
        GithubInstallationTokenMintOutcome::Indeterminate(outcome)
            if outcome.reason() == GithubInstallationTokenIndeterminateReason::ResponseTooLarge
    ));
    assert!(matches!(
        broker.mint_once(&request()).await,
        GithubInstallationTokenMintOutcome::RevokePending(pending)
            if pending.reason().kind() == GithubInstallationTokenErrorKind::InvalidResponse
    ));
    assert!(matches!(
        broker.mint_once(&request()).await,
        GithubInstallationTokenMintOutcome::Indeterminate(outcome)
            if outcome.reason() == GithubInstallationTokenIndeterminateReason::ResponseTooLarge
    ));
}

#[tokio::test]
async fn complete_request_timeout_is_enforced() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(success_response().delayed(Duration::from_millis(150)));
    let limits =
        GithubAppHttpLimits::new(1_024, Duration::from_millis(10), Duration::from_millis(40))
            .unwrap();
    let broker = fixture.broker_with_limits(limits);
    assert!(matches!(
        broker.mint_once(&request()).await,
        GithubInstallationTokenMintOutcome::Indeterminate(outcome)
            if outcome.reason() == GithubInstallationTokenIndeterminateReason::Transport
    ));
}

#[tokio::test]
async fn statuses_are_sanitized_and_rate_limit_hints_are_bounded() {
    let fixture = FixtureServer::spawn().await;
    let cases = [
        (
            ResponseSpec::json(StatusCode::UNAUTHORIZED, r#"{"token":"body-secret"}"#),
            GithubInstallationTokenErrorKind::Unauthorized,
            None,
        ),
        (
            ResponseSpec::json(StatusCode::FORBIDDEN, r#"{"token":"body-secret"}"#),
            GithubInstallationTokenErrorKind::Forbidden,
            None,
        ),
        (
            ResponseSpec::json(StatusCode::NOT_FOUND, r#"{"token":"body-secret"}"#),
            GithubInstallationTokenErrorKind::NotFound,
            None,
        ),
        (
            ResponseSpec::json(
                StatusCode::UNPROCESSABLE_ENTITY,
                r#"{"token":"body-secret"}"#,
            ),
            GithubInstallationTokenErrorKind::InvalidRequest,
            None,
        ),
        (
            ResponseSpec::json(StatusCode::TOO_MANY_REQUESTS, r#"{"token":"body-secret"}"#)
                .header("retry-after", "17"),
            GithubInstallationTokenErrorKind::RateLimited,
            Some(17),
        ),
        (
            ResponseSpec::json(StatusCode::TOO_MANY_REQUESTS, r#"{"token":"body-secret"}"#)
                .header("retry-after", "999999"),
            GithubInstallationTokenErrorKind::RateLimited,
            None,
        ),
        (
            ResponseSpec::json(
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"token":"body-secret"}"#,
            ),
            GithubInstallationTokenErrorKind::Unavailable,
            None,
        ),
    ];
    let broker = fixture.broker();
    for (response, expected, retry_after) in cases {
        fixture.enqueue(response);
        let outcome = broker.mint_once(&request()).await;
        let rendered = format!("{outcome:?}");
        if expected == GithubInstallationTokenErrorKind::Unavailable {
            assert!(matches!(
                outcome,
                GithubInstallationTokenMintOutcome::Indeterminate(indeterminate)
                    if indeterminate.reason()
                        == GithubInstallationTokenIndeterminateReason::ProviderUnavailable
            ));
        } else {
            let GithubInstallationTokenMintOutcome::Rejected(error) = outcome else {
                panic!("expected definite rejection: {outcome:?}");
            };
            assert_eq!(error.kind(), expected);
            assert_eq!(error.retry_after_seconds(), retry_after);
        }
        assert!(!rendered.contains("body-secret"));
        assert!(!rendered.contains("eyJ"));
    }
}
