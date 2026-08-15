use crate::support;

use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use automata_ci_core::{OperationId, RunnerSessionId};
use automata_ci_protocol::{MessageHeader, NoWork, ServerToRunner};
use automata_ci_runner_transport::{
    AuthenticatedRunnerRequest, ClientErrorKind, HandlerFuture, PROTOBUF_CONTENT_TYPE, RetryClass,
    RunnerControlClient, RunnerControlClientByteDirection, RunnerControlClientObserver,
    RunnerControlHandler, SYNC_PATH, TransportLimits,
};
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, Uri, Version, header::CONTENT_TYPE};
use http_body_util::{BodyExt as _, Full};
use hyper::{server::conn::http2, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::{net::TcpListener, time::timeout};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use support::{
    HandlerMode, RecordingVerifier, TestHandler, TestPki, client, heartbeat_request, hello_request,
    poll_request, raw_h2_sender, spawn_server,
};

#[derive(Debug, Default)]
struct RecordingClientObserver {
    bytes: Mutex<Vec<(RunnerControlClientByteDirection, u64)>>,
}

impl RecordingClientObserver {
    fn bytes(&self) -> Vec<(RunnerControlClientByteDirection, u64)> {
        self.bytes.lock().expect("client observer lock").clone()
    }
}

impl RunnerControlClientObserver for RecordingClientObserver {
    fn observe_bytes(&self, direction: RunnerControlClientByteDirection, bytes: u64) {
        self.bytes
            .lock()
            .expect("client observer lock")
            .push((direction, bytes));
    }
}

fn observed_client(
    running: &support::RunningServer,
    pki: &TestPki,
    limits: &TransportLimits,
    observer: Arc<RecordingClientObserver>,
) -> automata_ci_runner_transport::HyperRunnerControlClient {
    automata_ci_runner_transport::HyperRunnerControlClient::new_with_observer(
        &running.endpoint,
        &pki.client_tls(&pki.client),
        automata_ci_protocol::ProtocolLimits::default(),
        *limits,
        observer,
    )
    .expect("observed runner client")
}

#[tokio::test]
async fn client_bytes_are_observed_only_after_dispatch_and_valid_acceptance() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let handler = TestHandler::new(HandlerMode::Reply);
    let running = spawn_server(&pki, verifier, handler, &TransportLimits::default()).await;
    let observer = Arc::new(RecordingClientObserver::default());
    let client = observed_client(
        &running,
        &pki,
        &TransportLimits::default(),
        Arc::clone(&observer),
    );
    let request = hello_request();
    let request_bytes = u64::try_from(request.canonical_bytes().len()).expect("request byte count");

    let reply = client
        .exchange(&request, CancellationToken::new())
        .await
        .expect("valid exchange");
    let response_bytes = u64::try_from(reply.canonical_bytes().len()).expect("response byte count");

    assert_eq!(
        observer.bytes(),
        [
            (RunnerControlClientByteDirection::Request, request_bytes),
            (RunnerControlClientByteDirection::Response, response_bytes,),
        ]
    );
    running.stop().await;
}

#[tokio::test]
async fn client_pre_cancellation_and_request_limit_rejection_do_not_observe_sent_bytes() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let handler = TestHandler::new(HandlerMode::Reply);
    let running = spawn_server(&pki, verifier, handler, &TransportLimits::default()).await;

    let cancelled_observer = Arc::new(RecordingClientObserver::default());
    let cancelled_client = observed_client(
        &running,
        &pki,
        &TransportLimits::default(),
        Arc::clone(&cancelled_observer),
    );
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let error = cancelled_client
        .exchange(&hello_request(), cancellation)
        .await
        .expect_err("pre-cancelled exchange");
    assert_eq!(error.kind(), ClientErrorKind::Cancelled);
    assert!(cancelled_observer.bytes().is_empty());

    let bounded_observer = Arc::new(RecordingClientObserver::default());
    let bounded_limits = TransportLimits::default()
        .with_body_limits(1, 16 * 1024 * 1024)
        .expect("one-byte request ceiling");
    let bounded_client = observed_client(
        &running,
        &pki,
        &bounded_limits,
        Arc::clone(&bounded_observer),
    );
    let error = bounded_client
        .exchange(&hello_request(), CancellationToken::new())
        .await
        .expect_err("oversized request");
    assert_eq!(error.kind(), ClientErrorKind::Transport);
    assert!(bounded_observer.bytes().is_empty());

    running.stop().await;
}

#[tokio::test]
async fn client_admission_rejection_does_not_observe_a_second_dispatch() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let handler = TestHandler::new(HandlerMode::WaitForCancellation);
    let limits = TransportLimits::default()
        .with_concurrency_limits(16, 16, 1)
        .expect("one client request")
        .with_client_timeouts(
            Duration::from_secs(1),
            Duration::from_millis(20),
            Duration::from_secs(2),
            Duration::from_secs(1),
        )
        .expect("bounded client admission timeout");
    let server_handler = Arc::clone(&handler);
    let running = spawn_server(&pki, verifier, server_handler, &limits).await;
    let observer = Arc::new(RecordingClientObserver::default());
    let client = Arc::new(observed_client(
        &running,
        &pki,
        &limits,
        Arc::clone(&observer),
    ));
    let first_request = Arc::new(hello_request());
    let first_cancellation = CancellationToken::new();
    let task_client = Arc::clone(&client);
    let task_request = Arc::clone(&first_request);
    let task_cancellation = first_cancellation.clone();
    let first =
        tokio::spawn(async move { task_client.exchange(&task_request, task_cancellation).await });
    handler.wait_until_started().await;

    let error = client
        .exchange(&hello_request(), CancellationToken::new())
        .await
        .expect_err("second request must time out in client admission");
    assert_eq!(error.kind(), ClientErrorKind::Timeout);
    assert_eq!(
        observer.bytes().len(),
        1,
        "admission rejection must not cross the dispatch boundary"
    );

    first_cancellation.cancel();
    let error = first
        .await
        .expect("first client task")
        .expect_err("first request cancelled");
    assert_eq!(error.kind(), ClientErrorKind::Cancelled);
    running.stop().await;
}

#[tokio::test]
async fn invalid_and_timed_out_responses_record_dispatch_but_not_acceptance() {
    let pki = TestPki::new();
    let invalid_body = Bytes::from_static(b"not a protobuf frame");
    let (endpoint, invalid_server) = spawn_fixed_response_server(&pki, invalid_body).await;
    let invalid_observer = Arc::new(RecordingClientObserver::default());
    let client_observer = Arc::clone(&invalid_observer);
    let invalid_client = automata_ci_runner_transport::HyperRunnerControlClient::new_with_observer(
        &endpoint,
        &pki.client_tls(&pki.client),
        automata_ci_protocol::ProtocolLimits::default(),
        TransportLimits::default(),
        client_observer,
    )
    .expect("invalid-response client");
    let error = invalid_client
        .exchange(&hello_request(), CancellationToken::new())
        .await
        .expect_err("invalid protobuf response");
    assert_eq!(error.kind(), ClientErrorKind::InvalidProtobuf);
    assert!(matches!(
        invalid_observer.bytes().as_slice(),
        [(RunnerControlClientByteDirection::Request, _)]
    ));
    invalid_server.abort();

    let verifier = RecordingVerifier::accepting();
    let handler = TestHandler::new(HandlerMode::Delay(Duration::from_secs(2)));
    let limits = TransportLimits::default()
        .with_client_timeouts(
            Duration::from_millis(250),
            Duration::from_millis(250),
            Duration::from_millis(500),
            Duration::from_millis(250),
        )
        .expect("short total client timeout");
    let running = spawn_server(&pki, verifier, handler, &TransportLimits::default()).await;
    let timeout_observer = Arc::new(RecordingClientObserver::default());
    let timeout_client = observed_client(&running, &pki, &limits, Arc::clone(&timeout_observer));
    let error = timeout_client
        .exchange(&hello_request(), CancellationToken::new())
        .await
        .expect_err("response timeout");
    assert_eq!(error.kind(), ClientErrorKind::Timeout);
    assert!(matches!(
        timeout_observer.bytes().as_slice(),
        [(RunnerControlClientByteDirection::Request, _)]
    ));
    running.stop().await;
}

#[tokio::test]
async fn active_sync_timeout_is_shorter_than_the_long_poll_budget() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let handler = TestHandler::new(HandlerMode::Delay(Duration::from_millis(200)));
    let client_limits = TransportLimits::default()
        .with_client_timeouts(
            Duration::from_millis(250),
            Duration::from_millis(250),
            Duration::from_millis(500),
            Duration::from_millis(40),
        )
        .expect("distinct active and long-poll deadlines");
    let running = spawn_server(&pki, verifier, handler, &TransportLimits::default()).await;
    let client = client(&running, &pki, &client_limits);

    let started = Instant::now();
    let error = client
        .exchange(&heartbeat_request(), CancellationToken::new())
        .await
        .expect_err("active heartbeat must not consume the long-poll budget");
    assert_eq!(error.kind(), ClientErrorKind::Timeout);
    assert_eq!(error.retry_class(), RetryClass::RetrySameRequest);
    assert!(started.elapsed() < Duration::from_millis(150));

    client
        .exchange(&poll_request(), CancellationToken::new())
        .await
        .expect("lease long poll retains the total request budget");
    running.stop().await;
}

#[tokio::test]
async fn one_h2_connection_runs_concurrent_long_polls_without_affinity() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let handler = TestHandler::new(HandlerMode::Delay(Duration::from_millis(100)));
    let running = spawn_server(
        &pki,
        verifier.clone(),
        handler.clone(),
        &TransportLimits::default(),
    )
    .await;
    let (mut first_sender, connection) =
        raw_h2_sender(running.address, pki.raw_client_config(Some(&pki.client)))
            .await
            .expect("one h2 connection");
    let mut second_sender = first_sender.clone();
    let first = poll_request();
    let second = poll_request();

    let first_response = first_sender.send_request(raw_request(
        running.address,
        SYNC_PATH,
        first.canonical_bytes().clone(),
    ));
    let second_response = second_sender.send_request(raw_request(
        running.address,
        SYNC_PATH,
        second.canonical_bytes().clone(),
    ));
    let (first_response, second_response) = tokio::join!(first_response, second_response);
    assert_eq!(first_response.expect("first poll").status(), StatusCode::OK);
    assert_eq!(
        second_response.expect("second poll").status(),
        StatusCode::OK
    );
    assert_eq!(handler.max_active(), 2);
    assert_eq!(verifier.calls(), 2);

    drop(first_sender);
    drop(second_sender);
    connection.abort();
    running.stop().await;
}

#[tokio::test]
async fn client_cancellation_drops_poll_and_notifies_handler_work() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let handler = TestHandler::new(HandlerMode::WaitForCancellation);
    let running = spawn_server(&pki, verifier, handler.clone(), &TransportLimits::default()).await;
    let client = Arc::new(client(&running, &pki, &TransportLimits::default()));
    let prepared = Arc::new(hello_request());
    let cancellation = CancellationToken::new();
    let task_cancellation = cancellation.clone();
    let task = tokio::spawn(async move { client.exchange(&prepared, task_cancellation).await });
    handler.wait_until_started().await;
    cancellation.cancel();

    let error = task
        .await
        .expect("client task")
        .expect_err("cancelled request");
    assert_eq!(error.kind(), ClientErrorKind::Cancelled);
    assert_eq!(error.retry_class(), RetryClass::Never);
    timeout(Duration::from_secs(1), async {
        while !handler.cancellation_seen() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("handler cancellation propagation");

    running.stop().await;
}

#[tokio::test]
async fn client_rejects_declared_oversized_success_response_before_reading_it() {
    let pki = TestPki::new();
    let oversized = Bytes::from(vec![0u8; 64]);
    let (endpoint, server_task) = spawn_fixed_response_server(&pki, oversized).await;
    let limits = TransportLimits::default()
        .with_body_limits(16 * 1024 * 1024, 32)
        .expect("response limit");
    let client = automata_ci_runner_transport::HyperRunnerControlClient::new(
        &endpoint,
        &pki.client_tls(&pki.client),
        automata_ci_protocol::ProtocolLimits::default(),
        limits,
    )
    .expect("bounded client");

    let error = client
        .exchange(&hello_request(), CancellationToken::new())
        .await
        .expect_err("oversized response");
    assert_eq!(error.kind(), ClientErrorKind::ResponseTooLarge);
    assert_eq!(error.retry_class(), RetryClass::Never);
    server_task.abort();
}

#[tokio::test]
async fn client_rejects_a_tls_peer_that_does_not_select_h2_alpn() {
    let pki = TestPki::new();
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind no-ALPN server");
    let address = listener.local_addr().expect("no-ALPN server address");
    let mut server_config = pki.raw_server_config();
    server_config.alpn_protocols.clear();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept no-ALPN client");
        let tls = acceptor.accept(tcp).await.expect("complete TLS handshake");
        assert_eq!(tls.get_ref().1.alpn_protocol(), None);
        tokio::time::sleep(Duration::from_millis(50)).await;
    });
    let endpoint: Uri = format!("https://{address}/")
        .parse()
        .expect("no-ALPN endpoint");
    let client = automata_ci_runner_transport::HyperRunnerControlClient::new(
        &endpoint,
        &pki.client_tls(&pki.client),
        automata_ci_protocol::ProtocolLimits::default(),
        TransportLimits::default(),
    )
    .expect("runner client");

    let error = client
        .exchange(&hello_request(), CancellationToken::new())
        .await
        .expect_err("missing h2 ALPN selection");
    assert_eq!(error.kind(), ClientErrorKind::Transport);
    assert_eq!(error.retry_class(), RetryClass::RetrySameRequest);
    server_task.await.expect("no-ALPN server task");
}

#[tokio::test]
async fn server_rejects_cross_session_handler_response_before_sending_it() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let handler: Arc<dyn RunnerControlHandler> = Arc::new(WrongSessionHandler);
    let running = spawn_server(&pki, verifier, handler, &TransportLimits::default()).await;
    let client = client(&running, &pki, &TransportLimits::default());

    let error = client
        .exchange(&poll_request(), CancellationToken::new())
        .await
        .expect_err("cross-session handler response");
    assert_eq!(
        error.kind(),
        ClientErrorKind::HttpStatus(StatusCode::INTERNAL_SERVER_ERROR)
    );
    assert_eq!(error.retry_class(), RetryClass::RetrySameRequest);

    running.stop().await;
}

#[tokio::test]
async fn long_poll_handler_has_an_independent_deadline() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let handler = TestHandler::new(HandlerMode::Delay(Duration::from_millis(150)));
    let server_limits = TransportLimits::default()
        .with_server_request_timeouts(
            Duration::from_millis(100),
            Duration::from_millis(100),
            Duration::from_millis(25),
            Duration::from_millis(50),
        )
        .expect("long-poll deadline");
    let running = spawn_server(&pki, verifier, handler, &server_limits).await;
    let client = client(&running, &pki, &TransportLimits::default());

    let error = client
        .exchange(&poll_request(), CancellationToken::new())
        .await
        .expect_err("long poll timeout");
    assert_eq!(
        error.kind(),
        ClientErrorKind::HttpStatus(StatusCode::GATEWAY_TIMEOUT)
    );
    assert_eq!(error.retry_class(), RetryClass::RetrySameRequest);

    running.stop().await;
}

#[derive(Debug)]
struct WrongSessionHandler;

impl RunnerControlHandler for WrongSessionHandler {
    fn handshake(&self, _request: AuthenticatedRunnerRequest) -> HandlerFuture<'_> {
        Box::pin(async {
            Err(automata_ci_runner_transport::ApplicationError::new(
                automata_ci_runner_transport::ApplicationErrorKind::Internal,
            ))
        })
    }

    fn sync(&self, request: AuthenticatedRunnerRequest) -> HandlerFuture<'_> {
        Box::pin(async move {
            let automata_ci_protocol::RunnerToServer::LeaseRequest(poll) =
                request.message().message()
            else {
                return Err(automata_ci_runner_transport::ApplicationError::new(
                    automata_ci_runner_transport::ApplicationErrorKind::Internal,
                ));
            };
            let request_header = poll.header();
            Ok(ServerToRunner::NoWork(NoWork::new(
                MessageHeader::reply(
                    request_header.protocol_version(),
                    RunnerSessionId::new(),
                    OperationId::new(),
                    request_header.operation_id(),
                ),
                10,
            )))
        })
    }
}

fn raw_request(
    address: std::net::SocketAddr,
    path: &str,
    body: Bytes,
) -> Request<support::RawBody> {
    let body_len = body.len();
    let mut request = Request::new(Full::new(body).boxed_unsync());
    *request.method_mut() = Method::POST;
    *request.version_mut() = Version::HTTP_2;
    *request.uri_mut() = format!("https://{address}{path}")
        .parse()
        .expect("request URI");
    request.headers_mut().insert(
        CONTENT_TYPE,
        http::HeaderValue::from_static(PROTOBUF_CONTENT_TYPE),
    );
    request
        .headers_mut()
        .insert(http::header::CONTENT_LENGTH, body_len.into());
    request
}

async fn spawn_fixed_response_server(
    pki: &TestPki,
    body: Bytes,
) -> (Uri, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind fixed response server");
    let address = listener.local_addr().expect("fixed response address");
    let acceptor = TlsAcceptor::from(Arc::new(pki.raw_server_config()));
    let task = tokio::spawn(async move {
        let Ok((tcp, _)) = listener.accept().await else {
            return;
        };
        let Ok(tls) = acceptor.accept(tcp).await else {
            return;
        };
        let service = service_fn(move |_request| {
            let body = body.clone();
            async move {
                let mut response = Response::new(Full::new(body.clone()));
                response.headers_mut().insert(
                    CONTENT_TYPE,
                    http::HeaderValue::from_static(PROTOBUF_CONTENT_TYPE),
                );
                response
                    .headers_mut()
                    .insert(http::header::CONTENT_LENGTH, body.len().into());
                Ok::<_, Infallible>(response)
            }
        });
        let mut builder = http2::Builder::new(TokioExecutor::new());
        builder.timer(TokioTimer::new());
        let _ = builder.serve_connection(TokioIo::new(tls), service).await;
    });
    let endpoint = format!("https://{address}/")
        .parse()
        .expect("fixed response endpoint");
    (endpoint, task)
}
