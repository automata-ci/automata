mod support;

use std::{convert::Infallible, net::SocketAddr, time::Duration};

use automata_ci_auth::machine::MachineAuthenticationError;
use automata_ci_runner_transport::{HANDSHAKE_PATH, PROTOBUF_CONTENT_TYPE, TransportLimits};
use bytes::Bytes;
use http::{Method, Request, StatusCode, Version, header::CONTENT_TYPE};
use http_body_util::{BodyExt as _, Channel, Full};

use support::{
    HandlerMode, RawBody, RawSender, RecordingVerifier, RunningServer, TestHandler, TestPki,
    hello_request, raw_h2_sender, spawn_server,
};

#[tokio::test]
async fn declared_oversized_body_is_rejected_before_authentication_or_reading() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let handler = TestHandler::new(HandlerMode::Reply);
    let limits = TransportLimits::default()
        .with_body_limits(32, 32)
        .expect("small body limits");
    let running = spawn_server(&pki, verifier.clone(), handler.clone(), &limits).await;
    let (mut sender, connection) = connected_sender(&running, &pki).await;
    let (_body_sender, body) = Channel::<Bytes, Infallible>::new(1);
    let request = request(
        running.address,
        body.boxed_unsync(),
        Some(33),
        PROTOBUF_CONTENT_TYPE,
    );

    let response = sender.send_request(request).await.expect("error response");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(verifier.calls(), 0);
    assert_eq!(handler.calls(), 0);

    connection.abort();
    running.stop().await;
}

#[tokio::test]
async fn streamed_body_without_content_length_is_rejected() {
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
    let (mut sender, connection) = connected_sender(&running, &pki).await;
    let (mut body_sender, body) = Channel::<Bytes, Infallible>::new(1);
    body_sender
        .send_data(hello_request().canonical_bytes().clone())
        .await
        .expect("stream body");
    drop(body_sender);
    let request = request(
        running.address,
        body.boxed_unsync(),
        None,
        PROTOBUF_CONTENT_TYPE,
    );

    let response = sender.send_request(request).await.expect("error response");
    assert_eq!(response.status(), StatusCode::LENGTH_REQUIRED);
    assert_eq!(verifier.calls(), 0);
    assert_eq!(handler.calls(), 0);

    connection.abort();
    running.stop().await;
}

#[tokio::test]
async fn stalled_body_hits_incremental_read_deadline_without_handler_invocation() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let handler = TestHandler::new(HandlerMode::Reply);
    let limits = TransportLimits::default()
        .with_server_request_timeouts(
            Duration::from_millis(100),
            Duration::from_millis(50),
            Duration::from_millis(100),
            Duration::from_millis(200),
        )
        .expect("short read timeout");
    let running = spawn_server(&pki, verifier.clone(), handler.clone(), &limits).await;
    let (mut sender, connection) = connected_sender(&running, &pki).await;
    let (_body_sender, body) = Channel::<Bytes, Infallible>::new(1);
    let request = request(
        running.address,
        body.boxed_unsync(),
        Some(16),
        PROTOBUF_CONTENT_TYPE,
    );

    let response = sender
        .send_request(request)
        .await
        .expect("timeout response");
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    assert_eq!(verifier.calls(), 1);
    assert_eq!(handler.calls(), 0);

    connection.abort();
    running.stop().await;
}

#[tokio::test]
async fn malformed_protobuf_never_reaches_handler() {
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
    let (mut sender, connection) = connected_sender(&running, &pki).await;
    let malformed = Bytes::from_static(&[0xff, 0xff, 0xff]);
    let request = request(
        running.address,
        Full::new(malformed.clone()).boxed_unsync(),
        Some(malformed.len()),
        PROTOBUF_CONTENT_TYPE,
    );

    let response = sender
        .send_request(request)
        .await
        .expect("bad request response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(verifier.calls(), 1);
    assert_eq!(handler.calls(), 0);

    connection.abort();
    running.stop().await;
}

#[tokio::test]
async fn machine_authentication_finishes_before_a_stalled_body_is_polled() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::rejecting(MachineAuthenticationError::Untrusted);
    let handler = TestHandler::new(HandlerMode::Reply);
    let limits = TransportLimits::default()
        .with_server_request_timeouts(
            Duration::from_millis(100),
            Duration::from_secs(1),
            Duration::from_millis(100),
            Duration::from_millis(200),
        )
        .expect("request timeouts");
    let running = spawn_server(&pki, verifier.clone(), handler.clone(), &limits).await;
    let (mut sender, connection) = connected_sender(&running, &pki).await;
    let (_body_sender, body) = Channel::<Bytes, Infallible>::new(1);
    let request = request(
        running.address,
        body.boxed_unsync(),
        Some(16),
        PROTOBUF_CONTENT_TYPE,
    );

    let response = tokio::time::timeout(Duration::from_millis(250), sender.send_request(request))
        .await
        .expect("authentication precedes body timeout")
        .expect("unauthorized response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(verifier.calls(), 1);
    assert_eq!(handler.calls(), 0);

    connection.abort();
    running.stop().await;
}

#[tokio::test]
async fn content_type_must_match_exactly() {
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
    let (mut sender, connection) = connected_sender(&running, &pki).await;
    let body = hello_request().canonical_bytes().clone();
    let request = request(
        running.address,
        Full::new(body.clone()).boxed_unsync(),
        Some(body.len()),
        "application/protobuf; charset=binary",
    );

    let response = sender.send_request(request).await.expect("media response");
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(verifier.calls(), 0);
    assert_eq!(handler.calls(), 0);

    connection.abort();
    running.stop().await;
}

#[tokio::test]
async fn admission_is_bounded_before_a_second_body_is_read() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let handler = TestHandler::new(HandlerMode::Delay(Duration::from_millis(100)));
    let limits = TransportLimits::default()
        .with_concurrency_limits(8, 1, 8)
        .expect("single request admission")
        .with_server_request_timeouts(
            Duration::from_millis(25),
            Duration::from_secs(1),
            Duration::from_millis(250),
            Duration::from_millis(300),
        )
        .expect("admission timeout");
    let running = spawn_server(&pki, verifier, handler.clone(), &limits).await;
    let (mut second_sender, connection) = connected_sender(&running, &pki).await;
    let mut first_sender = second_sender.clone();
    let first_body = hello_request().canonical_bytes().clone();
    let first_request = request(
        running.address,
        Full::new(first_body.clone()).boxed_unsync(),
        Some(first_body.len()),
        PROTOBUF_CONTENT_TYPE,
    );
    let first_task = tokio::spawn(async move { first_sender.send_request(first_request).await });
    handler.wait_until_started().await;

    let (_stalled_sender, stalled_body) = Channel::<Bytes, Infallible>::new(1);
    let second_request = request(
        running.address,
        stalled_body.boxed_unsync(),
        Some(16),
        PROTOBUF_CONTENT_TYPE,
    );
    let second_response = second_sender
        .send_request(second_request)
        .await
        .expect("admission response");
    assert_eq!(second_response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(handler.calls(), 1);
    assert_eq!(
        first_task
            .await
            .expect("first request task")
            .expect("first response")
            .status(),
        StatusCode::OK
    );

    connection.abort();
    running.stop().await;
}

async fn connected_sender(
    running: &RunningServer,
    pki: &TestPki,
) -> (RawSender, tokio::task::JoinHandle<()>) {
    raw_h2_sender(running.address, pki.raw_client_config(Some(&pki.client)))
        .await
        .expect("valid raw h2 client")
}

fn request(
    address: SocketAddr,
    body: RawBody,
    content_length: Option<usize>,
    content_type: &'static str,
) -> Request<RawBody> {
    let mut request = Request::new(body);
    *request.method_mut() = Method::POST;
    *request.version_mut() = Version::HTTP_2;
    *request.uri_mut() = format!("https://{address}{HANDSHAKE_PATH}")
        .parse()
        .expect("request URI");
    request
        .headers_mut()
        .insert(CONTENT_TYPE, http::HeaderValue::from_static(content_type));
    if let Some(content_length) = content_length {
        request
            .headers_mut()
            .insert(http::header::CONTENT_LENGTH, content_length.into());
    }
    request
}
