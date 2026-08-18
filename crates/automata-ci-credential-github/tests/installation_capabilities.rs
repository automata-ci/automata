mod support;

use automata_ci_credential_github::{
    GithubAppInstallationObservationError, GithubAppInstallationPermission,
};
use axum::http::StatusCode;
use support::{FixtureServer, INSTALLATION_ID, ResponseSpec};

const APP_ID: u64 = 4_558_711;

fn installation(installation_id: u64, events: &str, permissions: &str) -> ResponseSpec {
    ResponseSpec::json(
        StatusCode::OK,
        format!(
            r#"{{"id":{installation_id},"app_id":{APP_ID},"events":{events},"permissions":{permissions}}}"#
        ),
    )
}

#[tokio::test]
async fn observes_bounded_effective_installation_capabilities() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(installation(
        INSTALLATION_ID,
        r#"["pull_request","push","merge_group"]"#,
        r#"{"checks":"write","merge_queues":"read"}"#,
    ));

    let capabilities = fixture
        .broker()
        .observe_installation_capabilities()
        .await
        .expect("valid capability observation");

    assert_eq!(capabilities.installation_id(), INSTALLATION_ID);
    assert_eq!(capabilities.app_id(), APP_ID);
    assert!(capabilities.has_event("merge_group"));
    assert!(!capabilities.has_event("repository_dispatch"));
    assert_eq!(
        capabilities.permission("merge_queues"),
        Some(GithubAppInstallationPermission::Read)
    );
    assert_eq!(
        capabilities.permission("checks"),
        Some(GithubAppInstallationPermission::Write)
    );

    let requests = fixture.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(
        requests[0].uri,
        format!("/api/v3/app/installations/{INSTALLATION_ID}")
    );
    assert_eq!(requests[0].headers["accept"], "application/vnd.github+json");
    assert!(
        requests[0].headers["authorization"]
            .to_str()
            .expect("authorization header")
            .starts_with("Bearer ")
    );
    assert!(requests[0].body.is_empty());
}

#[tokio::test]
async fn capability_observation_does_not_embed_product_policy() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(installation(
        INSTALLATION_ID,
        r#"["pull_request","push"]"#,
        r#"{"checks":"write"}"#,
    ));

    let capabilities = fixture
        .broker()
        .observe_installation_capabilities()
        .await
        .expect("well-formed capabilities remain observable");
    assert!(!capabilities.has_event("merge_group"));
    assert_eq!(capabilities.permission("merge_queues"), None);
}

#[tokio::test]
async fn rejects_installation_identity_drift() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(installation(
        INSTALLATION_ID + 1,
        r#"["merge_group"]"#,
        r#"{"merge_queues":"read"}"#,
    ));

    assert_eq!(
        fixture.broker().observe_installation_capabilities().await,
        Err(GithubAppInstallationObservationError::IdentityMismatch)
    );
}
