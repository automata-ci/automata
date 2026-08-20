mod support;

use automata_ci_credential_github::GithubAppWebhookUpdateError;
use axum::http::StatusCode;
use serde_json::Value;
use support::{FixtureServer, ResponseSpec};

#[tokio::test]
async fn app_webhook_update_is_app_authenticated_and_exact() {
    let server = FixtureServer::spawn().await;
    let webhook_url = url::Url::parse(
        "https://hooks.automata-ci.com/webhooks/providers/13c64af9-66a7-5c2b-ab8b-f45728967c05",
    )
    .unwrap();
    server.enqueue(ResponseSpec::json(
        StatusCode::OK,
        format!(
            r#"{{"url":"{webhook_url}","content_type":"json","insecure_ssl":"0","secret":"********"}}"#
        ),
    ));

    server
        .broker()
        .update_app_webhook_configuration(&webhook_url, b"fixture-webhook-secret")
        .await
        .expect("exact webhook configuration must converge");

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "PATCH");
    assert_eq!(requests[0].uri, "/api/v3/app/hook/config");
    assert_eq!(requests[0].headers["accept"], "application/vnd.github+json");
    assert!(
        requests[0].headers["authorization"]
            .to_str()
            .unwrap()
            .starts_with("Bearer eyJ")
    );
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["url"], webhook_url.as_str());
    assert_eq!(body["content_type"], "json");
    assert_eq!(body["insecure_ssl"], "0");
    assert_eq!(body["secret"], "fixture-webhook-secret");
}

#[tokio::test]
async fn app_webhook_update_rejects_mismatched_provider_response() {
    let server = FixtureServer::spawn().await;
    let webhook_url = url::Url::parse(
        "https://hooks.automata-ci.com/webhooks/providers/13c64af9-66a7-5c2b-ab8b-f45728967c05",
    )
    .unwrap();
    server.enqueue(ResponseSpec::json(
        StatusCode::OK,
        r#"{"url":"https://elsewhere.example/hook","content_type":"json","insecure_ssl":"0"}"#,
    ));

    let error = server
        .broker()
        .update_app_webhook_configuration(&webhook_url, b"fixture-webhook-secret")
        .await
        .expect_err("mismatched endpoint must fail closed");

    assert_eq!(error, GithubAppWebhookUpdateError::InvalidResponse);
}
