mod support;

use std::time::Duration;

use automata_ci_auth::secret::SecretString;
use automata_ci_credential::CredentialErrorKind;
use automata_ci_credential_github::{
    GithubAppCredentialBroker, GithubAppHttpLimits, GithubInstallationTokenIndeterminateReason,
    GithubInstallationTokenMintOutcome, GithubInstallationTokenRevocationCandidate,
    GithubInstallationTokenRevocationFailureKind, GithubInstallationTokenRevocationOutcome,
};
use axum::http::StatusCode;
use support::{
    EXPIRATION, FixtureServer, NOW, REPOSITORY_ID, ResponseSpec, request, token_response,
};

const SENTINEL: &str = "ghs_revocation_sentinel_never_render_me";

#[tokio::test]
async fn semantic_or_malformed_201_with_a_unique_token_retains_a_candidate() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(token_response(
        SENTINEL,
        EXPIRATION,
        r#"{"contents":"read","statuses":"write"}"#,
        REPOSITORY_ID + 1,
        "automata-ci/automata",
        "selected",
    ));
    fixture.enqueue(ResponseSpec::json(
        StatusCode::CREATED,
        format!(r#"{{"token":"{SENTINEL}"}} trailing"#),
    ));
    let broker = fixture.broker();

    let semantic = broker.mint_once(&request()).await;
    let GithubInstallationTokenMintOutcome::RevokePending(semantic) = semantic else {
        panic!("expected semantic revocation candidate");
    };
    assert_eq!(
        semantic.reason().kind(),
        CredentialErrorKind::RepositoryMismatch
    );
    assert_eq!(semantic.candidate().secret().expose_secret(), SENTINEL);
    assert_eq!(
        semantic
            .provider_expires_at()
            .expect("provider expiry")
            .as_seconds(),
        NOW + 3_600
    );
    assert_eq!(
        semantic
            .conservative_expires_at()
            .expect("conservative horizon")
            .as_seconds(),
        NOW + 3_540
    );
    assert_sanitized(&semantic);

    let malformed = broker.mint_once(&request()).await;
    let GithubInstallationTokenMintOutcome::RevokePending(malformed) = malformed else {
        panic!("expected malformed response revocation candidate");
    };
    assert_eq!(
        malformed.reason().kind(),
        CredentialErrorKind::InvalidResponse
    );
    assert_eq!(malformed.candidate().secret().expose_secret(), SENTINEL);
    assert_sanitized(&malformed);
}

#[tokio::test]
async fn truncated_duplicate_and_missing_tokens_are_indeterminate() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::json(
        StatusCode::CREATED,
        format!(r#"{{"token":"{SENTINEL}"#),
    ));
    fixture.enqueue(ResponseSpec::json(
        StatusCode::CREATED,
        format!(
            r#"{{"token":"{SENTINEL}","token":"ghs_second","expires_at":"{EXPIRATION}","permissions":{{"contents":"read","statuses":"write"}},"repository_selection":"selected","repositories":[{{"id":{REPOSITORY_ID},"full_name":"automata-ci/automata"}}]}}"#
        ),
    ));
    fixture.enqueue(ResponseSpec::json(
        StatusCode::CREATED,
        format!(
            r#"{{"expires_at":"{EXPIRATION}","permissions":{{"contents":"read","statuses":"write"}},"repository_selection":"selected","repositories":[{{"id":{REPOSITORY_ID},"full_name":"automata-ci/automata"}}]}}"#
        ),
    ));
    let broker = fixture.broker();

    let expected = [
        GithubInstallationTokenIndeterminateReason::MalformedResponse,
        GithubInstallationTokenIndeterminateReason::AmbiguousToken,
        GithubInstallationTokenIndeterminateReason::MissingToken,
    ];
    for reason in expected {
        let outcome = broker.mint_once(&request()).await;
        let GithubInstallationTokenMintOutcome::Indeterminate(outcome) = outcome else {
            panic!("expected indeterminate mint");
        };
        assert_eq!(outcome.reason(), reason);
        assert!(!format!("{outcome:?} {}", outcome.reason()).contains(SENTINEL));
    }
}

#[tokio::test]
async fn revocation_uses_only_the_candidate_on_the_exact_trusted_endpoint() {
    let fixture = FixtureServer::spawn().await;
    let broker = fixture.broker();
    let candidate = mint_candidate(&fixture, &broker).await;
    fixture.enqueue(ResponseSpec::status(StatusCode::NO_CONTENT));

    assert_eq!(
        broker.revoke(&candidate).await,
        GithubInstallationTokenRevocationOutcome::Confirmed
    );
    let requests = fixture.requests();
    assert_eq!(requests.len(), 2);
    let revoke = &requests[1];
    assert_eq!(revoke.method, "DELETE");
    assert_eq!(revoke.uri, "/api/v3/installation/token");
    assert_eq!(
        revoke.headers["authorization"],
        format!("Bearer {SENTINEL}")
    );
    assert_eq!(revoke.headers["accept"], "application/vnd.github+json");
    assert_eq!(revoke.headers["x-github-api-version"], "2026-03-10");
    assert!(revoke.body.is_empty());
}

#[tokio::test]
async fn unauthorized_and_rate_limited_revocations_retain_for_retry() {
    let fixture = FixtureServer::spawn().await;
    let broker = fixture.broker();
    let candidate = mint_candidate(&fixture, &broker).await;
    fixture.enqueue(ResponseSpec::json(
        StatusCode::UNAUTHORIZED,
        format!(r#"{{"message":"{SENTINEL}"}}"#),
    ));
    fixture.enqueue(
        ResponseSpec::json(
            StatusCode::TOO_MANY_REQUESTS,
            format!(r#"{{"message":"{SENTINEL}"}}"#),
        )
        .header("retry-after", "17"),
    );

    let unauthorized = unconfirmed(broker.revoke(&candidate).await);
    assert_eq!(
        unauthorized.kind(),
        GithubInstallationTokenRevocationFailureKind::Unauthorized
    );
    assert!(unauthorized.is_retryable());
    assert_eq!(candidate.secret().expose_secret(), SENTINEL);

    let limited = unconfirmed(broker.revoke(&candidate).await);
    assert_eq!(
        limited.kind(),
        GithubInstallationTokenRevocationFailureKind::RateLimited
    );
    assert_eq!(limited.retry_after_seconds(), Some(17));
    assert!(limited.is_retryable());
    assert_eq!(candidate.secret().expose_secret(), SENTINEL);
    assert!(!format!("{unauthorized:?} {unauthorized} {limited:?} {limited}").contains(SENTINEL));
}

#[tokio::test]
async fn server_failure_and_timeout_are_retryable_without_secret_disclosure() {
    let fixture = FixtureServer::spawn().await;
    let limits =
        GithubAppHttpLimits::new(4_096, Duration::from_millis(10), Duration::from_millis(40))
            .expect("limits");
    let broker = fixture.broker_with_limits(limits);
    let candidate = mint_candidate(&fixture, &broker).await;
    fixture.enqueue(ResponseSpec::json(
        StatusCode::INTERNAL_SERVER_ERROR,
        format!(r#"{{"message":"{SENTINEL}"}}"#),
    ));
    fixture
        .enqueue(ResponseSpec::status(StatusCode::NO_CONTENT).delayed(Duration::from_millis(150)));

    for _ in 0..2 {
        let failure = unconfirmed(broker.revoke(&candidate).await);
        assert_eq!(
            failure.kind(),
            GithubInstallationTokenRevocationFailureKind::Retryable
        );
        assert!(failure.is_retryable());
        assert!(!format!("{failure:?} {failure}").contains(SENTINEL));
    }
    assert_eq!(candidate.secret().expose_secret(), SENTINEL);
}

#[tokio::test]
async fn revocation_redirect_is_not_followed_or_forwarded() {
    let source = FixtureServer::spawn().await;
    let sink = FixtureServer::spawn().await;
    let broker = source.broker();
    let candidate = mint_candidate(&source, &broker).await;
    source.enqueue(
        ResponseSpec::status(StatusCode::TEMPORARY_REDIRECT)
            .header("location", sink.url("credential-sink").as_str()),
    );
    sink.enqueue(ResponseSpec::status(StatusCode::NO_CONTENT));

    let failure = unconfirmed(broker.revoke(&candidate).await);
    assert_eq!(
        failure.kind(),
        GithubInstallationTokenRevocationFailureKind::InvalidResponse
    );
    assert_eq!(source.requests().len(), 2);
    assert!(sink.requests().is_empty());
    assert_eq!(sink.remaining_responses(), 1);
    assert_eq!(candidate.secret().expose_secret(), SENTINEL);
}

#[test]
fn protected_candidate_restore_is_bounded_and_sanitized() {
    let candidate = GithubInstallationTokenRevocationCandidate::from_protected_secret(
        SecretString::new(SENTINEL).expect("secret"),
    )
    .expect("candidate");
    assert_eq!(candidate.secret().expose_secret(), SENTINEL);
    assert!(!format!("{candidate:?}").contains(SENTINEL));

    let invalid = GithubInstallationTokenRevocationCandidate::from_protected_secret(
        SecretString::new("token with whitespace").expect("secret"),
    )
    .expect_err("invalid bearer");
    assert!(!format!("{invalid:?} {invalid}").contains("token with whitespace"));
}

async fn mint_candidate(
    fixture: &FixtureServer,
    broker: &GithubAppCredentialBroker,
) -> GithubInstallationTokenRevocationCandidate {
    fixture.enqueue(token_response(
        SENTINEL,
        EXPIRATION,
        r#"{"contents":"read","statuses":"write"}"#,
        REPOSITORY_ID + 1,
        "automata-ci/automata",
        "selected",
    ));
    let outcome = broker.mint_once(&request()).await;
    let GithubInstallationTokenMintOutcome::RevokePending(pending) = outcome else {
        panic!("expected revocation candidate");
    };
    pending.into_candidate()
}

fn unconfirmed(
    outcome: GithubInstallationTokenRevocationOutcome,
) -> automata_ci_credential_github::GithubInstallationTokenRevocationFailure {
    let GithubInstallationTokenRevocationOutcome::Unconfirmed(failure) = outcome else {
        panic!("revocation unexpectedly confirmed");
    };
    failure
}

fn assert_sanitized(value: &impl std::fmt::Debug) {
    assert!(!format!("{value:?}").contains(SENTINEL));
}
