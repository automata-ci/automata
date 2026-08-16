use crate::support;

use std::{convert::Infallible, sync::Arc, time::Duration};

use automata_ci_auth::machine::MachineAuthenticationError;
use automata_ci_protocol::ProtocolLimits;
use automata_ci_runner_transport::{
    HANDSHAKE_PATH, HyperRunnerControlClient, PROTOBUF_CONTENT_TYPE, RunnerControlClient,
    RunnerTransportAuthenticationRejection, RunnerTransportByteDirection,
    RunnerTransportDecodeRejection, RunnerTransportHeadRejection,
    RunnerTransportRequestObservation, RunnerTransportRoute, RunnerTransportTlsOutcome,
    TransportLimits,
};
use bytes::Bytes;
use http::{HeaderValue, Method, StatusCode, Version};
use http_body_util::{BodyExt as _, Channel, Full};
use tokio_util::sync::CancellationToken;

use support::{
    HandlerMode, RecordingTransportObserver, RecordingVerifier, TestHandler, TestPki,
    hello_request, raw_h2_sender, raw_hello_request, raw_request, spawn_server_with_observer,
};

#[tokio::test]
async fn observer_covers_head_decode_success_and_balanced_in_flight() {
    let pki = TestPki::new();
    let observer = Arc::new(RecordingTransportObserver::default());
    let handler = TestHandler::new(HandlerMode::Reply);
    let limits = TransportLimits::default()
        .with_body_limits(512, 512)
        .expect("small bounded bodies");
    let running = spawn_server_with_observer(
        &pki,
        RecordingVerifier::accepting(),
        handler.clone(),
        &limits,
        observer.clone(),
    )
    .await;
    let (mut sender, connection) =
        raw_h2_sender(running.address, pki.raw_client_config(Some(&pki.client)))
            .await
            .expect("valid HTTP/2 client");

    let (_oversized_sender, oversized_body) = Channel::<Bytes, Infallible>::new(1);
    let oversized = raw_request(
        running.address,
        Method::POST,
        HANDSHAKE_PATH,
        Version::HTTP_2,
        oversized_body.boxed_unsync(),
        Some(HeaderValue::from_static(PROTOBUF_CONTENT_TYPE)),
        Some(513_usize.into()),
    );
    assert_eq!(
        sender
            .send_request(oversized)
            .await
            .expect("oversize response")
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );

    let malformed_bytes = Bytes::from_static(&[0xff, 0xff, 0xff]);
    let malformed = raw_request(
        running.address,
        Method::POST,
        HANDSHAKE_PATH,
        Version::HTTP_2,
        Full::new(malformed_bytes.clone()).boxed_unsync(),
        Some(HeaderValue::from_static(PROTOBUF_CONTENT_TYPE)),
        Some(malformed_bytes.len().into()),
    );
    assert_eq!(
        sender
            .send_request(malformed)
            .await
            .expect("decode response")
            .status(),
        StatusCode::BAD_REQUEST
    );

    let hello_bytes = hello_request().canonical_bytes().clone();
    let valid = raw_request(
        running.address,
        Method::POST,
        HANDSHAKE_PATH,
        Version::HTTP_2,
        Full::new(hello_bytes.clone()).boxed_unsync(),
        Some(HeaderValue::from_static(PROTOBUF_CONTENT_TYPE)),
        Some(hello_bytes.len().into()),
    );
    assert_eq!(
        sender
            .send_request(valid)
            .await
            .expect("success response")
            .status(),
        StatusCode::OK
    );
    assert_eq!(handler.calls(), 1);
    connection.abort();
    running.stop().await;

    assert_primary_request_observations(&observer, malformed_bytes.len(), hello_bytes.len());
}

fn assert_primary_request_observations(
    observer: &RecordingTransportObserver,
    malformed_length: usize,
    hello_length: usize,
) {
    assert_eq!(
        observer.request_observations(),
        [
            RunnerTransportRequestObservation::HeadRejected {
                route: RunnerTransportRoute::Handshake,
                reason: RunnerTransportHeadRejection::BodyTooLarge,
            },
            RunnerTransportRequestObservation::DecodeRejected {
                route: RunnerTransportRoute::Handshake,
                reason: RunnerTransportDecodeRejection::InvalidProtobuf,
            },
            RunnerTransportRequestObservation::Succeeded {
                route: RunnerTransportRoute::Handshake,
            },
        ]
    );
    assert_eq!(
        observer.request_starts(),
        [
            RunnerTransportRoute::Handshake,
            RunnerTransportRoute::Handshake
        ]
    );
    assert_eq!(
        observer.request_finishes(),
        [
            RunnerTransportRoute::Handshake,
            RunnerTransportRoute::Handshake
        ]
    );
    assert_eq!(
        observer.tls_outcomes(),
        [RunnerTransportTlsOutcome::Accepted]
    );
    let bytes = observer.bytes();
    assert!(bytes.contains(&(
        RunnerTransportRoute::Handshake,
        RunnerTransportByteDirection::Request,
        u64::try_from(malformed_length).expect("small length"),
    )));
    assert!(bytes.contains(&(
        RunnerTransportRoute::Handshake,
        RunnerTransportByteDirection::Request,
        u64::try_from(hello_length).expect("small length"),
    )));
    assert!(bytes.iter().any(|(route, direction, count)| {
        *route == RunnerTransportRoute::Handshake
            && *direction == RunnerTransportByteDirection::Response
            && *count > 0
    }));
}

#[tokio::test]
async fn observer_records_authentication_rejection() {
    let pki = TestPki::new();
    let auth_observer = Arc::new(RecordingTransportObserver::default());
    let auth_handler = TestHandler::new(HandlerMode::Reply);
    let auth_running = spawn_server_with_observer(
        &pki,
        RecordingVerifier::rejecting(MachineAuthenticationError::Untrusted),
        auth_handler.clone(),
        &TransportLimits::default(),
        auth_observer.clone(),
    )
    .await;
    let (mut auth_sender, auth_connection) = raw_h2_sender(
        auth_running.address,
        pki.raw_client_config(Some(&pki.client)),
    )
    .await
    .expect("valid HTTP/2 client");
    let response = auth_sender
        .send_request(raw_hello_request(auth_running.address))
        .await
        .expect("authentication response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(auth_handler.calls(), 0);
    auth_connection.abort();
    auth_running.stop().await;
    assert_eq!(
        auth_observer.request_observations(),
        [RunnerTransportRequestObservation::AuthenticationRejected {
            route: RunnerTransportRoute::Handshake,
            reason: RunnerTransportAuthenticationRejection::Untrusted,
        }]
    );
}

#[tokio::test]
async fn observer_records_tls_rejection() {
    let pki = TestPki::new();
    let tls_observer = Arc::new(RecordingTransportObserver::default());
    let tls_running = spawn_server_with_observer(
        &pki,
        RecordingVerifier::accepting(),
        TestHandler::new(HandlerMode::Reply),
        &TransportLimits::default(),
        tls_observer.clone(),
    )
    .await;
    let rejected = match raw_h2_sender(
        tls_running.address,
        pki.raw_client_config(Some(&pki.untrusted_client)),
    )
    .await
    {
        Err(()) => true,
        Ok((mut sender, connection)) => {
            let rejected = tokio::time::timeout(
                Duration::from_secs(1),
                sender.send_request(raw_hello_request(tls_running.address)),
            )
            .await
            .expect("TLS rejection request deadline")
            .is_err();
            connection.abort();
            rejected
        }
    };
    assert!(rejected);
    tls_observer
        .wait_for(
            RunnerTransportTlsOutcome::Rejected,
            1,
            Duration::from_secs(1),
        )
        .await;
    tls_running.stop().await;
    assert_eq!(
        tls_observer.tls_outcomes(),
        [RunnerTransportTlsOutcome::Rejected]
    );
}

#[tokio::test]
async fn observer_records_bounded_request_admission_overload() {
    let pki = TestPki::new();
    let observer = Arc::new(RecordingTransportObserver::default());
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
        .expect("short admission timeout");
    let running = spawn_server_with_observer(
        &pki,
        RecordingVerifier::accepting(),
        handler.clone(),
        &limits,
        observer.clone(),
    )
    .await;
    let (mut sender, connection) =
        raw_h2_sender(running.address, pki.raw_client_config(Some(&pki.client)))
            .await
            .expect("valid HTTP/2 client");
    let mut first_sender = sender.clone();
    let first = raw_hello_request(running.address);
    let first_task = tokio::spawn(async move { first_sender.send_request(first).await });
    handler.wait_until_started().await;

    let second = raw_hello_request(running.address);
    assert_eq!(
        sender
            .send_request(second)
            .await
            .expect("overload response")
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        first_task
            .await
            .expect("first task")
            .expect("first response")
            .status(),
        StatusCode::OK
    );
    connection.abort();
    running.stop().await;
    let requests = observer.request_observations();
    assert!(requests.contains(&RunnerTransportRequestObservation::AdmissionOverloaded));
    assert!(
        requests.contains(&RunnerTransportRequestObservation::Succeeded {
            route: RunnerTransportRoute::Handshake,
        })
    );
}

#[tokio::test]
async fn dropped_stream_records_cancelled_and_balances_in_flight() {
    let pki = TestPki::new();
    let observer = Arc::new(RecordingTransportObserver::default());
    let handler = TestHandler::new(HandlerMode::WaitForCancellation);
    let running = spawn_server_with_observer(
        &pki,
        RecordingVerifier::accepting(),
        handler.clone(),
        &TransportLimits::default(),
        observer.clone(),
    )
    .await;
    let endpoint = format!("https://{}/", running.address)
        .parse()
        .expect("control endpoint");
    let client = Arc::new(
        HyperRunnerControlClient::new(
            &endpoint,
            &pki.client_tls(&pki.client),
            ProtocolLimits::default(),
            TransportLimits::default(),
        )
        .expect("runner client"),
    );
    let prepared = Arc::new(hello_request());
    let cancellation = CancellationToken::new();
    let task_cancellation = cancellation.clone();
    let task = tokio::spawn(async move { client.exchange(&prepared, task_cancellation).await });
    handler.wait_until_started().await;
    cancellation.cancel();
    let _ = task.await.expect("client task");
    observer
        .wait_for(
            RunnerTransportRequestObservation::Cancelled {
                route: RunnerTransportRoute::Handshake,
            },
            1,
            Duration::from_secs(1),
        )
        .await;
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if handler.cancellation_seen() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("server cancellation observation");
    running.stop().await;
    assert_eq!(observer.request_starts(), observer.request_finishes());
}
