mod support;

use std::sync::Arc;

use automata_ci_core::PermissionLevel;
use automata_ci_credential_github::{
    GithubInstallationTokenErrorKind, GithubInstallationTokenIndeterminateReason,
    GithubInstallationTokenMintOutcome, GithubInstallationTokenRequest,
    GithubWorkloadCredentialProvider,
};
use automata_ci_provider::{ProviderPermission, ProviderPermissionSet};
use automata_ci_provider::{
    WorkloadCredentialIssueOutcome, WorkloadCredentialProvider,
    WorkloadCredentialProviderErrorKind, WorkloadCredentialRetirement,
    WorkloadCredentialRevocationOutcome,
};
use automata_ci_store::GithubRepositoryName;
use axum::http::StatusCode;
use serde_json::Value;
use support::{
    EXPIRATION, FixtureServer, INSTALLATION_ID, NOW, REPOSITORY_ID, ResponseSpec, request,
    success_response, workload_connection, workload_connection_for, workload_request,
    workload_request_for,
};

#[tokio::test]
async fn common_workload_port_preserves_revocation_ownership() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(success_response());
    fixture.enqueue(ResponseSpec::status(StatusCode::INTERNAL_SERVER_ERROR));
    fixture.enqueue(ResponseSpec::status(StatusCode::NO_CONTENT));
    let broker = Arc::new(fixture.broker());
    let request = workload_request();
    let provider = GithubWorkloadCredentialProvider::new(broker, &workload_connection()).unwrap();
    let provider: &dyn WorkloadCredentialProvider = &provider;

    let outcome = provider.issue_once(&request).await;
    let WorkloadCredentialIssueOutcome::Ready(ready) = outcome else {
        panic!("expected common ready token: {outcome:?}");
    };
    assert_eq!(ready.request_digest(), request.digest());
    assert_eq!(
        ready.expose_secret(),
        b"ghs_998877_variable_length_stateless_token_value"
    );
    let WorkloadCredentialRetirement::Revoke(candidate) = ready.retire() else {
        panic!("GitHub installation tokens require explicit revocation");
    };
    let unconfirmed = provider.revoke(candidate).await;
    let WorkloadCredentialRevocationOutcome::Unconfirmed { candidate, .. } = unconfirmed else {
        panic!("server failure must retain candidate: {unconfirmed:?}");
    };
    assert_eq!(
        candidate.expose_secret(),
        b"ghs_998877_variable_length_stateless_token_value"
    );
    assert!(matches!(
        provider.revoke(candidate).await,
        WorkloadCredentialRevocationOutcome::Confirmed
    ));

    let requests = fixture.requests();
    assert_eq!(requests.len(), 3);
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["repository_ids"], serde_json::json!([REPOSITORY_ID]));
    assert_eq!(
        body["permissions"],
        serde_json::json!({"contents":"read","statuses":"write"})
    );
}

#[tokio::test]
async fn common_workload_port_rejects_a_foreign_connection_before_network_access() {
    let fixture = FixtureServer::spawn().await;
    let provider =
        GithubWorkloadCredentialProvider::new(Arc::new(fixture.broker()), &workload_connection())
            .unwrap();
    let foreign_connection = workload_connection_for(47);
    let foreign_request = workload_request_for(&foreign_connection);
    let outcome = provider.issue_once(&foreign_request).await;
    let WorkloadCredentialIssueOutcome::Rejected(error) = outcome else {
        panic!("foreign connection must be rejected: {outcome:?}");
    };
    assert_eq!(error.kind(), WorkloadCredentialProviderErrorKind::Conflict);
    assert!(fixture.requests().is_empty());
}

#[tokio::test]
async fn issues_one_exact_repository_and_permission_scope() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(success_response());
    let broker = fixture.broker();
    let request = request();
    let outcome = broker.mint_once(&request).await;
    let GithubInstallationTokenMintOutcome::Ready(ready) = outcome else {
        panic!("expected ready token: {outcome:?}");
    };

    assert_eq!(
        ready.secret().expose_secret(),
        "ghs_998877_variable_length_stateless_token_value"
    );
    assert_eq!(ready.request().repository_id(), REPOSITORY_ID);
    assert_eq!(
        ready.request().repository_name().as_str(),
        "automata-ci/automata"
    );
    assert_eq!(ready.request().minimum_validity_millis(), 300_000);
    assert_eq!(ready.request().permissions().len(), 2);
    assert_eq!(ready.issued_at().as_seconds(), NOW);
    assert_eq!(ready.provider_expires_at().as_seconds(), NOW + 3_600);
    assert_eq!(ready.conservative_expires_at().as_seconds(), NOW + 3_540);
    assert_eq!(ready.installation_id(), INSTALLATION_ID);

    let requests = fixture.requests();
    assert_eq!(requests.len(), 1);
    let captured = &requests[0];
    assert_eq!(captured.method, "POST");
    assert_eq!(
        captured.uri,
        format!("/api/v3/app/installations/{INSTALLATION_ID}/access_tokens")
    );
    assert_eq!(captured.headers["accept"], "application/vnd.github+json");
    assert_eq!(captured.headers["content-type"], "application/json");
    assert_eq!(captured.headers["x-github-api-version"], "2026-03-10");
    let body: Value = serde_json::from_slice(&captured.body).unwrap();
    assert_eq!(body["repository_ids"], serde_json::json!([REPOSITORY_ID]));
    assert_eq!(
        body["permissions"],
        serde_json::json!({"contents":"read","statuses":"write"})
    );
    assert!(!String::from_utf8_lossy(&captured.body).contains("tenant/run"));

    let rendered = format!("{broker:?} {ready:?}");
    assert!(rendered.contains("[redacted]"));
    assert!(!rendered.contains("ghs_998877_variable_length_stateless_token_value"));
    assert!(!rendered.contains("BEGIN PRIVATE KEY"));

    let candidate = ready.into_revocation_candidate();
    assert_eq!(
        candidate.secret().expose_secret(),
        "ghs_998877_variable_length_stateless_token_value"
    );
}

#[tokio::test]
async fn provider_and_repository_inputs_fail_before_network_access() {
    let fixture = FixtureServer::spawn().await;
    let permissions =
        ProviderPermissionSet::new([
            ProviderPermission::new("contents", PermissionLevel::Read).unwrap()
        ])
        .unwrap();
    assert!(
        GithubInstallationTokenRequest::new(
            0,
            GithubRepositoryName::new("owner/repository").unwrap(),
            permissions.clone(),
            300_000,
        )
        .is_err()
    );
    assert!(GithubRepositoryName::new("owner/repo.git").is_err());
    assert!(
        GithubInstallationTokenRequest::new(
            REPOSITORY_ID,
            GithubRepositoryName::new("owner/repository").unwrap(),
            permissions,
            0,
        )
        .is_err()
    );
    assert!(fixture.requests().is_empty());
}

#[tokio::test]
async fn repository_scope_drift_is_rejected() {
    let fixture = FixtureServer::spawn().await;
    let responses = [
        support::token_response(
            "ghs_secret",
            EXPIRATION,
            r#"{"contents":"read","statuses":"write"}"#,
            REPOSITORY_ID + 1,
            "automata-ci/automata",
            "selected",
        ),
        support::token_response(
            "ghs_secret",
            EXPIRATION,
            r#"{"contents":"read","statuses":"write"}"#,
            REPOSITORY_ID,
            "attacker/automata",
            "selected",
        ),
        support::token_response(
            "ghs_secret",
            EXPIRATION,
            r#"{"contents":"read","statuses":"write"}"#,
            REPOSITORY_ID,
            "automata-ci/automata",
            "all",
        ),
    ];
    let broker = fixture.broker();
    for response in responses {
        fixture.enqueue(response);
        let outcome = broker.mint_once(&request()).await;
        let GithubInstallationTokenMintOutcome::RevokePending(pending) = outcome else {
            panic!("expected revocation candidate: {outcome:?}");
        };
        assert_eq!(
            pending.reason().kind(),
            GithubInstallationTokenErrorKind::RepositoryMismatch
        );
        assert_eq!(pending.candidate().secret().expose_secret(), "ghs_secret");
    }
}

#[tokio::test]
async fn permission_drift_and_duplicate_keys_are_rejected() {
    let fixture = FixtureServer::spawn().await;
    for permissions in [
        r#"{"contents":"read"}"#,
        r#"{"contents":"write","statuses":"write"}"#,
        r#"{"contents":"read","statuses":"write","issues":"read"}"#,
        r#"{"contents":"read","contents":"write","statuses":"write"}"#,
    ] {
        fixture.enqueue(support::token_response(
            "ghs_response_body_secret",
            EXPIRATION,
            permissions,
            REPOSITORY_ID,
            "automata-ci/automata",
            "selected",
        ));
    }
    let broker = fixture.broker();
    for _ in 0..4 {
        let outcome = broker.mint_once(&request()).await;
        let GithubInstallationTokenMintOutcome::RevokePending(pending) = outcome else {
            panic!("expected revocation candidate: {outcome:?}");
        };
        assert!(matches!(
            pending.reason().kind(),
            GithubInstallationTokenErrorKind::PermissionMismatch
                | GithubInstallationTokenErrorKind::InvalidResponse
        ));
        assert_eq!(
            pending.candidate().secret().expose_secret(),
            "ghs_response_body_secret"
        );
        assert!(!format!("{pending:?}").contains("ghs_response_body_secret"));
    }
}

#[tokio::test]
async fn accepts_only_github_implicit_metadata_read_permission() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(support::token_response(
        "ghs_implicit_metadata",
        EXPIRATION,
        r#"{"contents":"read","metadata":"read","statuses":"write"}"#,
        REPOSITORY_ID,
        "automata-ci/automata",
        "selected",
    ));
    for permissions in [
        r#"{"contents":"read","metadata":"write","statuses":"write"}"#,
        r#"{"contents":"read","issues":"read","metadata":"read","statuses":"write"}"#,
    ] {
        fixture.enqueue(support::token_response(
            "ghs_excess_permission",
            EXPIRATION,
            permissions,
            REPOSITORY_ID,
            "automata-ci/automata",
            "selected",
        ));
    }

    let broker = fixture.broker();
    let accepted = broker.mint_once(&request()).await;
    let GithubInstallationTokenMintOutcome::Ready(accepted) = accepted else {
        panic!("expected GitHub implicit metadata permission to be accepted: {accepted:?}");
    };
    assert_eq!(accepted.secret().expose_secret(), "ghs_implicit_metadata");

    for _ in 0..2 {
        let rejected = broker.mint_once(&request()).await;
        let GithubInstallationTokenMintOutcome::RevokePending(rejected) = rejected else {
            panic!("expected excess permission to require revocation: {rejected:?}");
        };
        assert_eq!(
            rejected.reason().kind(),
            GithubInstallationTokenErrorKind::PermissionMismatch
        );
        assert_eq!(
            rejected.candidate().secret().expose_secret(),
            "ghs_excess_permission"
        );
    }
}

#[tokio::test]
async fn expiration_and_token_format_fail_closed() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(support::token_response(
        "ghs_secret",
        "2027-01-15T08:04:59Z",
        r#"{"contents":"read","statuses":"write"}"#,
        REPOSITORY_ID,
        "automata-ci/automata",
        "selected",
    ));
    fixture.enqueue(support::token_response(
        "ghs_secret",
        "2027-01-15T09:01:01Z",
        r#"{"contents":"read","statuses":"write"}"#,
        REPOSITORY_ID,
        "automata-ci/automata",
        "selected",
    ));
    fixture.enqueue(support::token_response(
        "ghs_secret with whitespace",
        EXPIRATION,
        r#"{"contents":"read","statuses":"write"}"#,
        REPOSITORY_ID,
        "automata-ci/automata",
        "selected",
    ));
    let broker = fixture.broker();

    let too_short = broker.mint_once(&request()).await;
    let GithubInstallationTokenMintOutcome::RevokePending(too_short) = too_short else {
        panic!("expected short token to require revocation: {too_short:?}");
    };
    assert_eq!(
        too_short.reason().kind(),
        GithubInstallationTokenErrorKind::Expired
    );

    let too_long = broker.mint_once(&request()).await;
    let GithubInstallationTokenMintOutcome::RevokePending(too_long) = too_long else {
        panic!("expected long token to require revocation: {too_long:?}");
    };
    assert_eq!(
        too_long.reason().kind(),
        GithubInstallationTokenErrorKind::InvalidResponse
    );

    let malformed_token = broker.mint_once(&request()).await;
    let GithubInstallationTokenMintOutcome::Indeterminate(malformed_token) = malformed_token else {
        panic!("expected unrecoverable token: {malformed_token:?}");
    };
    assert_eq!(
        malformed_token.reason(),
        GithubInstallationTokenIndeterminateReason::MalformedResponse
    );
}

#[tokio::test]
async fn malformed_or_ambiguous_response_shapes_are_rejected() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::json(
        StatusCode::CREATED,
        r#"{"token":"ghs_secret","token":"ghs_other","expires_at":"2027-01-15T09:00:00Z","permissions":{"contents":"read","statuses":"write"},"repository_selection":"selected","repositories":[{"id":81234567,"full_name":"automata-ci/automata"}]}"#,
    ));
    fixture.enqueue(ResponseSpec::json(
        StatusCode::CREATED,
        r#"{"token":"ghs_secret","expires_at":"2027-01-15T09:00:00Z","permissions":{"contents":"read","statuses":"write"},"repository_selection":"selected","repositories":[{"id":81234567,"full_name":"automata-ci/automata"}]} trailing"#,
    ));
    let broker = fixture.broker();
    let duplicate = broker.mint_once(&request()).await;
    let GithubInstallationTokenMintOutcome::Indeterminate(duplicate) = duplicate else {
        panic!("expected duplicate token ambiguity: {duplicate:?}");
    };
    assert_eq!(
        duplicate.reason(),
        GithubInstallationTokenIndeterminateReason::AmbiguousToken
    );

    let trailing = broker.mint_once(&request()).await;
    let GithubInstallationTokenMintOutcome::RevokePending(trailing) = trailing else {
        panic!("expected recovered malformed response token: {trailing:?}");
    };
    assert_eq!(
        trailing.reason().kind(),
        GithubInstallationTokenErrorKind::InvalidResponse
    );
    assert_eq!(trailing.candidate().secret().expose_secret(), "ghs_secret");
}
