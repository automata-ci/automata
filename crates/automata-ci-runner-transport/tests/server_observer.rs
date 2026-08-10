mod support;

use std::{
    convert::Infallible,
    fmt,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use automata_ci_auth::machine::{MachineAuthenticationError, MachineIdentityVerifier};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_runner_transport::{
    HANDSHAKE_PATH, HyperRunnerControlClient, PROTOBUF_CONTENT_TYPE, RunnerControlClient,
    RunnerControlHandler, RunnerControlServer, RunnerTransportAuthenticationRejection,
    RunnerTransportByteDirection, RunnerTransportConnectionEvent, RunnerTransportDecodeRejection,
    RunnerTransportHeadRejection, RunnerTransportObserver, RunnerTransportRequestObservation,
    RunnerTransportRoute, RunnerTransportTlsOutcome, ServeError, TransportLimits,
};
use bytes::Bytes;
use http::{Method, Request, StatusCode, Version, header::CONTENT_TYPE};
use http_body_util::{BodyExt as _, Channel, Full};
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use support::{
    HandlerMode, RawBody, RecordingVerifier, TestHandler, TestPki, hello_request, raw_h2_sender,
};

#[derive(Default)]
struct RecordingObserver {
    connections: Mutex<Vec<RunnerTransportConnectionEvent>>,
    tls: Mutex<Vec<RunnerTransportTlsOutcome>>,
    requests: Mutex<Vec<RunnerTransportRequestObservation>>,
    starts: Mutex<Vec<RunnerTransportRoute>>,
    finishes: Mutex<Vec<RunnerTransportRoute>>,
    bytes: Mutex<Vec<(RunnerTransportRoute, RunnerTransportByteDirection, u64)>>,
}

impl fmt::Debug for RecordingObserver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("RecordingObserver").finish()
    }
}

impl RunnerTransportObserver for RecordingObserver {
    fn observe_connection(&self, event: RunnerTransportConnectionEvent) {
        self.connections
            .lock()
            .expect("connection lock")
            .push(event);
    }

    fn observe_tls(&self, outcome: RunnerTransportTlsOutcome, _duration: Duration) {
        self.tls.lock().expect("TLS lock").push(outcome);
    }

    fn observe_request(&self, observation: RunnerTransportRequestObservation, _duration: Duration) {
        self.requests
            .lock()
            .expect("request lock")
            .push(observation);
    }

    fn request_started(&self, route: RunnerTransportRoute) {
        self.starts.lock().expect("start lock").push(route);
    }

    fn request_finished(&self, route: RunnerTransportRoute) {
        self.finishes.lock().expect("finish lock").push(route);
    }

    fn observe_bytes(
        &self,
        route: RunnerTransportRoute,
        direction: RunnerTransportByteDirection,
        bytes: u64,
    ) {
        self.bytes
            .lock()
            .expect("byte lock")
            .push((route, direction, bytes));
    }
}

#[tokio::test]
async fn observer_covers_head_decode_success_and_balanced_in_flight() {
    let pki = TestPki::new();
    let observer = Arc::new(RecordingObserver::default());
    let handler = TestHandler::new(HandlerMode::Reply);
    let limits = TransportLimits::default()
        .with_body_limits(512, 512)
        .expect("small bounded bodies");
    let running = spawn_observed(
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
    let oversized = request(running.address, oversized_body.boxed_unsync(), 513);
    assert_eq!(
        sender
            .send_request(oversized)
            .await
            .expect("oversize response")
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );

    let malformed_bytes = Bytes::from_static(&[0xff, 0xff, 0xff]);
    let malformed = request(
        running.address,
        Full::new(malformed_bytes.clone()).boxed_unsync(),
        malformed_bytes.len(),
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
    let valid = request(
        running.address,
        Full::new(hello_bytes.clone()).boxed_unsync(),
        hello_bytes.len(),
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
    observer: &RecordingObserver,
    malformed_length: usize,
    hello_length: usize,
) {
    assert_eq!(
        *observer.requests.lock().expect("request lock"),
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
        *observer.starts.lock().expect("start lock"),
        [
            RunnerTransportRoute::Handshake,
            RunnerTransportRoute::Handshake
        ]
    );
    assert_eq!(
        *observer.finishes.lock().expect("finish lock"),
        [
            RunnerTransportRoute::Handshake,
            RunnerTransportRoute::Handshake
        ]
    );
    assert_eq!(
        *observer.tls.lock().expect("TLS lock"),
        [RunnerTransportTlsOutcome::Accepted]
    );
    let bytes = observer.bytes.lock().expect("byte lock");
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
    let auth_observer = Arc::new(RecordingObserver::default());
    let auth_handler = TestHandler::new(HandlerMode::Reply);
    let auth_running = spawn_observed(
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
    let body = hello_request().canonical_bytes().clone();
    let response = auth_sender
        .send_request(request(
            auth_running.address,
            Full::new(body.clone()).boxed_unsync(),
            body.len(),
        ))
        .await
        .expect("authentication response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(auth_handler.calls(), 0);
    auth_connection.abort();
    auth_running.stop().await;
    assert_eq!(
        *auth_observer.requests.lock().expect("auth request lock"),
        [RunnerTransportRequestObservation::AuthenticationRejected {
            route: RunnerTransportRoute::Handshake,
            reason: RunnerTransportAuthenticationRejection::Untrusted,
        }]
    );
}

#[tokio::test]
async fn observer_records_tls_rejection() {
    let pki = TestPki::new();
    let tls_observer = Arc::new(RecordingObserver::default());
    let tls_running = spawn_observed(
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
            let body = hello_request().canonical_bytes().clone();
            let rejected = tokio::time::timeout(
                Duration::from_secs(1),
                sender.send_request(request(
                    tls_running.address,
                    Full::new(body.clone()).boxed_unsync(),
                    body.len(),
                )),
            )
            .await
            .expect("TLS rejection request deadline")
            .is_err();
            connection.abort();
            rejected
        }
    };
    assert!(rejected);
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if !tls_observer.tls.lock().expect("TLS lock").is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("TLS rejection observation");
    tls_running.stop().await;
    assert_eq!(
        *tls_observer.tls.lock().expect("TLS lock"),
        [RunnerTransportTlsOutcome::Rejected]
    );
}

#[tokio::test]
async fn observer_records_bounded_request_admission_overload() {
    let pki = TestPki::new();
    let observer = Arc::new(RecordingObserver::default());
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
    let running = spawn_observed(
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
    let first_body = hello_request().canonical_bytes().clone();
    let first = request(
        running.address,
        Full::new(first_body.clone()).boxed_unsync(),
        first_body.len(),
    );
    let first_task = tokio::spawn(async move { first_sender.send_request(first).await });
    handler.wait_until_started().await;

    let second_body = hello_request().canonical_bytes().clone();
    let second = request(
        running.address,
        Full::new(second_body.clone()).boxed_unsync(),
        second_body.len(),
    );
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
    let requests = observer.requests.lock().expect("request lock");
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
    let observer = Arc::new(RecordingObserver::default());
    let handler = TestHandler::new(HandlerMode::WaitForCancellation);
    let running = spawn_observed(
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
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if handler.cancellation_seen()
                && observer.requests.lock().expect("request lock").contains(
                    &RunnerTransportRequestObservation::Cancelled {
                        route: RunnerTransportRoute::Handshake,
                    },
                )
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("server cancellation observation");
    running.stop().await;
    assert_eq!(
        *observer.starts.lock().expect("start lock"),
        *observer.finishes.lock().expect("finish lock")
    );
}

struct ObservedServer {
    address: SocketAddr,
    shutdown: CancellationToken,
    task: JoinHandle<Result<(), ServeError>>,
}

impl ObservedServer {
    async fn stop(self) {
        self.shutdown.cancel();
        self.task
            .await
            .expect("server task")
            .expect("server result");
    }
}

async fn spawn_observed(
    pki: &TestPki,
    verifier: Arc<dyn MachineIdentityVerifier>,
    handler: Arc<dyn RunnerControlHandler>,
    limits: &TransportLimits,
    observer: Arc<RecordingObserver>,
) -> ObservedServer {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind observer server");
    let address = listener.local_addr().expect("observer server address");
    let server = RunnerControlServer::new(
        listener,
        &pki.server_tls(),
        verifier,
        handler,
        ProtocolLimits::default(),
        *limits,
    )
    .expect("observer server")
    .with_observer(observer);
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(server.serve(shutdown.clone()));
    ObservedServer {
        address,
        shutdown,
        task,
    }
}

fn request(address: SocketAddr, body: RawBody, content_length: usize) -> Request<RawBody> {
    let mut request = Request::new(body);
    *request.method_mut() = Method::POST;
    *request.version_mut() = Version::HTTP_2;
    *request.uri_mut() = format!("https://{address}{HANDSHAKE_PATH}")
        .parse()
        .expect("request URI");
    request.headers_mut().insert(
        CONTENT_TYPE,
        PROTOBUF_CONTENT_TYPE.parse().expect("media type"),
    );
    request
        .headers_mut()
        .insert(http::header::CONTENT_LENGTH, content_length.into());
    request
}
