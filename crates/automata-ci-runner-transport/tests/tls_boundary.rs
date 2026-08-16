use crate::support;

use std::time::Duration;

use automata_ci_runner_transport::{HANDSHAKE_PATH, PROTOBUF_CONTENT_TYPE, TransportLimits};
use http::{HeaderValue, Method, StatusCode, Version};
use http_body_util::{BodyExt as _, Full};
use tokio::time::timeout;

use support::{
    HandlerMode, RecordingVerifier, TestHandler, TestPki, hello_request, raw_h2_sender,
    raw_request, spawn_server,
};

#[tokio::test]
async fn missing_client_certificate_is_rejected_before_http() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let handler = TestHandler::new(HandlerMode::Reply);
    let running = spawn_server(
        &pki,
        verifier.clone(),
        handler.clone(),
        &TransportLimits::default(),
    )
    .await;

    assert!(connection_rejected(running.address, pki.raw_client_config(None)).await);
    assert_eq!(verifier.calls(), 0);
    assert_eq!(handler.calls(), 0);
    running.stop().await;
}

#[tokio::test]
async fn untrusted_client_certificate_is_rejected_before_http() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let handler = TestHandler::new(HandlerMode::Reply);
    let running = spawn_server(
        &pki,
        verifier.clone(),
        handler.clone(),
        &TransportLimits::default(),
    )
    .await;

    assert!(
        connection_rejected(
            running.address,
            pki.raw_client_config(Some(&pki.untrusted_client))
        )
        .await
    );
    assert_eq!(verifier.calls(), 0);
    assert_eq!(handler.calls(), 0);
    running.stop().await;
}

#[tokio::test]
async fn wrong_purpose_client_certificate_is_rejected_before_http() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let handler = TestHandler::new(HandlerMode::Reply);
    let running = spawn_server(
        &pki,
        verifier.clone(),
        handler.clone(),
        &TransportLimits::default(),
    )
    .await;

    assert!(
        connection_rejected(
            running.address,
            pki.raw_client_config(Some(&pki.wrong_purpose_client))
        )
        .await
    );
    assert_eq!(verifier.calls(), 0);
    assert_eq!(handler.calls(), 0);
    running.stop().await;
}

#[tokio::test]
async fn expired_client_certificate_is_rejected_before_http() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let handler = TestHandler::new(HandlerMode::Reply);
    let running = spawn_server(
        &pki,
        verifier.clone(),
        handler.clone(),
        &TransportLimits::default(),
    )
    .await;

    assert!(
        connection_rejected(
            running.address,
            pki.raw_client_config(Some(&pki.expired_client))
        )
        .await
    );
    assert_eq!(verifier.calls(), 0);
    assert_eq!(handler.calls(), 0);
    running.stop().await;
}

#[tokio::test]
async fn forwarded_certificate_header_cannot_replace_rustls_evidence() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let handler = TestHandler::new(HandlerMode::Reply);
    let running = spawn_server(&pki, verifier.clone(), handler, &TransportLimits::default()).await;
    let (mut sender, connection) =
        raw_h2_sender(running.address, pki.raw_client_config(Some(&pki.client)))
            .await
            .expect("valid raw h2 client");
    let body = hello_request().canonical_bytes().clone();
    let mut request = raw_request(
        running.address,
        Method::POST,
        HANDSHAKE_PATH,
        Version::HTTP_11,
        Full::new(body.clone()).boxed_unsync(),
        Some(HeaderValue::from_static(PROTOBUF_CONTENT_TYPE)),
        Some(body.len().into()),
    );
    request.headers_mut().insert(
        "x-forwarded-client-cert",
        HeaderValue::from_static("forged-certificate"),
    );

    let response = sender.send_request(request).await.expect("h2 response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(verifier.chains(), vec![pki.client.chain_bytes()]);

    drop(sender);
    connection.abort();
    running.stop().await;
}

async fn connection_rejected(address: std::net::SocketAddr, config: rustls::ClientConfig) -> bool {
    let connected = timeout(Duration::from_secs(2), raw_h2_sender(address, config))
        .await
        .expect("TLS attempt deadline");
    let Ok((mut sender, connection)) = connected else {
        return true;
    };
    let body = hello_request().canonical_bytes().clone();
    let request = raw_request(
        address,
        Method::POST,
        HANDSHAKE_PATH,
        Version::HTTP_11,
        Full::new(body.clone()).boxed_unsync(),
        Some(HeaderValue::from_static(PROTOBUF_CONTENT_TYPE)),
        Some(body.len().into()),
    );
    let rejected = timeout(Duration::from_secs(2), sender.send_request(request))
        .await
        .expect("HTTP attempt deadline")
        .is_err();
    connection.abort();
    rejected
}
