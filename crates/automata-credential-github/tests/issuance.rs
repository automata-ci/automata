mod support;

use automata_credential::RepositoryCredentialBroker;
use axum::http::StatusCode;
use serde_json::Value;
use support::{
    EXPIRATION, FixtureServer, INSTALLATION_ID, ISSUER, NOW, REPOSITORY_ID, ResponseSpec, request,
    request_for, success_response,
};

#[tokio::test]
async fn issues_one_exact_repository_and_permission_scope() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(success_response());
    let broker = fixture.broker();
    let request = request();
    let issued = broker.issue(&request).await.unwrap();

    assert_eq!(
        issued.secret().expose_secret(),
        "ghs_998877_variable_length_stateless_token_value"
    );
    assert_eq!(issued.repository(), request.repository());
    assert_eq!(issued.permissions(), request.permissions());
    assert_eq!(issued.issued_at().as_seconds(), NOW);
    assert_eq!(issued.expires_at().as_seconds(), NOW + 3_600);
    assert_eq!(issued.provenance().issuer().as_str(), ISSUER);
    assert_eq!(
        issued.provenance().subject().as_str(),
        INSTALLATION_ID.to_string()
    );

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

    let rendered = format!("{broker:?} {issued:?}");
    assert!(rendered.contains("[redacted]"));
    assert!(!rendered.contains("ghs_998877_variable_length_stateless_token_value"));
    assert!(!rendered.contains("BEGIN PRIVATE KEY"));
}

#[tokio::test]
async fn provider_and_repository_inputs_fail_before_network_access() {
    let fixture = FixtureServer::spawn().await;
    let broker = fixture.broker();
    let wrong_provider = request_for("gitlab", REPOSITORY_ID.to_string(), "owner/repository");
    let invalid_stable_id = request_for("github", "not-numeric", "owner/repository");
    let invalid_repository = request_for("github", REPOSITORY_ID.to_string(), "owner/repo.git");

    for invalid in [&wrong_provider, &invalid_stable_id, &invalid_repository] {
        assert!(broker.issue(invalid).await.is_err());
    }
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
            "GoNeuralAI/automata",
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
            "GoNeuralAI/automata",
            "all",
        ),
    ];
    let broker = fixture.broker();
    for response in responses {
        fixture.enqueue(response);
        let error = broker.issue(&request()).await.unwrap_err();
        assert_eq!(
            error.kind(),
            automata_credential::CredentialErrorKind::RepositoryMismatch
        );
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
            "GoNeuralAI/automata",
            "selected",
        ));
    }
    let broker = fixture.broker();
    for _ in 0..4 {
        let error = broker.issue(&request()).await.unwrap_err();
        assert!(matches!(
            error.kind(),
            automata_credential::CredentialErrorKind::PermissionMismatch
                | automata_credential::CredentialErrorKind::InvalidResponse
        ));
        assert!(!format!("{error:?} {error}").contains("ghs_response_body_secret"));
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
        "GoNeuralAI/automata",
        "selected",
    ));
    fixture.enqueue(support::token_response(
        "ghs_secret",
        "2027-01-15T09:01:01Z",
        r#"{"contents":"read","statuses":"write"}"#,
        REPOSITORY_ID,
        "GoNeuralAI/automata",
        "selected",
    ));
    fixture.enqueue(support::token_response(
        "ghs_secret with whitespace",
        EXPIRATION,
        r#"{"contents":"read","statuses":"write"}"#,
        REPOSITORY_ID,
        "GoNeuralAI/automata",
        "selected",
    ));
    let broker = fixture.broker();

    let too_short = broker.issue(&request()).await.unwrap_err();
    assert_eq!(
        too_short.kind(),
        automata_credential::CredentialErrorKind::Expired
    );
    for _ in 0..2 {
        assert_eq!(
            broker.issue(&request()).await.unwrap_err().kind(),
            automata_credential::CredentialErrorKind::InvalidResponse
        );
    }
}

#[tokio::test]
async fn malformed_or_ambiguous_response_shapes_are_rejected() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::json(
        StatusCode::CREATED,
        r#"{"token":"ghs_secret","token":"ghs_other","expires_at":"2027-01-15T09:00:00Z","permissions":{"contents":"read","statuses":"write"},"repository_selection":"selected","repositories":[{"id":81234567,"full_name":"GoNeuralAI/automata"}]}"#,
    ));
    fixture.enqueue(ResponseSpec::json(
        StatusCode::CREATED,
        r#"{"token":"ghs_secret","expires_at":"2027-01-15T09:00:00Z","permissions":{"contents":"read","statuses":"write"},"repository_selection":"selected","repositories":[{"id":81234567,"full_name":"GoNeuralAI/automata"}]} trailing"#,
    ));
    let broker = fixture.broker();
    for _ in 0..2 {
        assert_eq!(
            broker.issue(&request()).await.unwrap_err().kind(),
            automata_credential::CredentialErrorKind::InvalidResponse
        );
    }
}
