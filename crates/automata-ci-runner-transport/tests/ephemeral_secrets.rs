use crate::support;

use std::{
    collections::VecDeque,
    convert::Infallible,
    fmt, future,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use automata_ci_auth::machine::{MachineAuthenticationError, MachineIdentityVerifier};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_runner_transport::{
    ApplicationError, ApplicationErrorKind, AuthenticatedRunnerEphemeralRequest, ClientErrorKind,
    EPHEMERAL_SECRETS_CONTENT_TYPE, EPHEMERAL_SECRETS_PATH, EphemeralHandlerFuture,
    HyperRunnerEphemeralClient, MAX_EPHEMERAL_REQUEST_BYTES, MAX_EPHEMERAL_RESPONSE_BYTES,
    PrepareEphemeralError, PreparedEphemeralRequest, RetryClass, RunnerControlHandler,
    RunnerControlServer, RunnerEphemeralClient, RunnerEphemeralHandler, RunnerEphemeralReply,
    RunnerTransportApplicationRejection, RunnerTransportBodyRejection,
    RunnerTransportByteDirection, RunnerTransportHeadRejection, RunnerTransportObserver,
    RunnerTransportRequestObservation, RunnerTransportResponseRejection, RunnerTransportRoute,
    ServeError, TransportLimits,
};
use bytes::Bytes;
use http::{
    HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri, Version,
    header::{ACCEPT, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE},
};
use http_body_util::{BodyExt as _, Channel, Full};
use hyper::{
    body::{Body, Frame, SizeHint},
    server::conn::http2,
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use support::{
    HandlerMode, RawBody, RawSender, RecordingVerifier, TestHandler, TestPki, raw_h2_sender,
};

const REQUEST_VALUE: &[u8] = b"one-use request bearer";
const RESPONSE_VALUE: &[u8] = b"one-use response value";

enum HandlerAction {
    Reply(Vec<u8>),
    Fail(ApplicationErrorKind),
    WaitForCancellation,
}

struct RecordingEphemeralHandler {
    actions: Mutex<VecDeque<HandlerAction>>,
    calls: AtomicUsize,
    bodies: Mutex<Vec<Vec<u8>>>,
    request_debug: Mutex<Vec<String>>,
    identities: Mutex<Vec<String>>,
    cancellation_seen: Arc<AtomicBool>,
}

impl RecordingEphemeralHandler {
    fn new(actions: impl IntoIterator<Item = HandlerAction>) -> Arc<Self> {
        Arc::new(Self {
            actions: Mutex::new(actions.into_iter().collect()),
            calls: AtomicUsize::new(0),
            bodies: Mutex::new(Vec::new()),
            request_debug: Mutex::new(Vec::new()),
            identities: Mutex::new(Vec::new()),
            cancellation_seen: Arc::new(AtomicBool::new(false)),
        })
    }

    fn push(&self, action: HandlerAction) {
        self.actions.lock().expect("action lock").push_back(action);
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn bodies(&self) -> Vec<Vec<u8>> {
        self.bodies.lock().expect("body lock").clone()
    }

    fn request_debug(&self) -> Vec<String> {
        self.request_debug.lock().expect("debug lock").clone()
    }

    fn identities(&self) -> Vec<String> {
        self.identities.lock().expect("identity lock").clone()
    }

    fn cancellation_seen(&self) -> bool {
        self.cancellation_seen.load(Ordering::SeqCst)
    }
}

impl fmt::Debug for RecordingEphemeralHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingEphemeralHandler")
            .field("calls", &self.calls())
            .finish_non_exhaustive()
    }
}

impl RunnerEphemeralHandler for RecordingEphemeralHandler {
    fn handle(&self, request: AuthenticatedRunnerEphemeralRequest) -> EphemeralHandlerFuture<'_> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.bodies
            .lock()
            .expect("body lock")
            .push(request.expose_body().to_vec());
        self.request_debug
            .lock()
            .expect("debug lock")
            .push(format!("{request:?}"));
        self.identities
            .lock()
            .expect("identity lock")
            .push(request.machine().external_identity().as_str().to_owned());
        let cancellation = request.cancellation_token();
        let action = self
            .actions
            .lock()
            .expect("action lock")
            .pop_front()
            .expect("one configured ephemeral handler action per call");
        match action {
            HandlerAction::Reply(body) => Box::pin(async move { RunnerEphemeralReply::new(body) }),
            HandlerAction::Fail(kind) => Box::pin(async move { Err(ApplicationError::new(kind)) }),
            HandlerAction::WaitForCancellation => {
                let cancellation_seen = Arc::clone(&self.cancellation_seen);
                tokio::spawn(async move {
                    cancellation.cancelled().await;
                    cancellation_seen.store(true, Ordering::SeqCst);
                });
                Box::pin(future::pending())
            }
        }
    }
}

#[derive(Default)]
struct RecordingObserver {
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

struct RunningEphemeralServer {
    address: SocketAddr,
    endpoint: Uri,
    shutdown: CancellationToken,
    task: JoinHandle<Result<(), ServeError>>,
}

impl RunningEphemeralServer {
    async fn stop(self) {
        self.shutdown.cancel();
        self.task
            .await
            .expect("ephemeral server task")
            .expect("ephemeral server result");
    }
}

async fn spawn_ephemeral_server(
    pki: &TestPki,
    verifier: Arc<dyn MachineIdentityVerifier>,
    ephemeral_handler: Option<Arc<dyn RunnerEphemeralHandler>>,
    observer: Option<Arc<dyn RunnerTransportObserver>>,
    limits: &TransportLimits,
) -> RunningEphemeralServer {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind ephemeral server");
    let address = listener.local_addr().expect("ephemeral server address");
    let control_handler: Arc<dyn RunnerControlHandler> = TestHandler::new(HandlerMode::Reply);
    let mut server = RunnerControlServer::new(
        listener,
        &pki.server_tls(),
        verifier,
        control_handler,
        ProtocolLimits::default(),
        *limits,
    )
    .expect("ephemeral server configuration");
    if let Some(handler) = ephemeral_handler {
        server = server.with_ephemeral_handler(
            address
                .to_string()
                .parse()
                .expect("canonical ephemeral authority"),
            handler,
        );
    }
    if let Some(observer) = observer {
        server = server.with_observer(observer);
    }
    let endpoint = format!("https://{address}/")
        .parse()
        .expect("ephemeral endpoint");
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(server.serve(shutdown.clone()));
    RunningEphemeralServer {
        address,
        endpoint,
        shutdown,
        task,
    }
}

struct FramedBody {
    frames: VecDeque<Frame<Bytes>>,
}

impl FramedBody {
    fn data(chunks: impl IntoIterator<Item = Bytes>) -> Self {
        Self {
            frames: chunks.into_iter().map(Frame::data).collect(),
        }
    }

    fn data_then_trailers(data: Bytes, headers: HeaderMap) -> Self {
        Self {
            frames: VecDeque::from([Frame::data(data), Frame::trailers(headers)]),
        }
    }
}

impl Body for FramedBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.frames.pop_front().map(Ok))
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

fn raw_request(
    address: SocketAddr,
    method: Method,
    target: &str,
    body: RawBody,
    content_length: Option<&str>,
    content_type: Option<&str>,
) -> Request<RawBody> {
    let mut request = Request::new(body);
    *request.method_mut() = method;
    *request.version_mut() = Version::HTTP_2;
    *request.uri_mut() = format!("https://{address}{target}")
        .parse()
        .expect("raw ephemeral request URI");
    if let Some(content_length) = content_length {
        request.headers_mut().insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(content_length).expect("test content length"),
        );
    }
    if let Some(content_type) = content_type {
        request.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_str(content_type).expect("test content type"),
        );
        request.headers_mut().insert(
            ACCEPT,
            HeaderValue::from_static(EPHEMERAL_SECRETS_CONTENT_TYPE),
        );
        request
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    request
}

fn valid_request(address: SocketAddr, body: Bytes) -> Request<RawBody> {
    let length = body.len().to_string();
    raw_request(
        address,
        Method::POST,
        EPHEMERAL_SECRETS_PATH,
        Full::new(body).boxed_unsync(),
        Some(&length),
        Some(EPHEMERAL_SECRETS_CONTENT_TYPE),
    )
}

async fn raw_sender(
    running: &RunningEphemeralServer,
    pki: &TestPki,
) -> (RawSender, JoinHandle<()>) {
    raw_h2_sender(running.address, pki.raw_client_config(Some(&pki.client)))
        .await
        .expect("authenticated raw h2 client")
}

async fn response_status(sender: &mut RawSender, request: Request<RawBody>) -> StatusCode {
    sender
        .send_request(request)
        .await
        .expect("ephemeral HTTP response")
        .status()
}

async fn wait_until(predicate: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !predicate() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("condition before deterministic deadline");
}

#[test]
fn ephemeral_aggregates_are_nonempty_bounded_and_redacted() {
    assert_eq!(
        PreparedEphemeralRequest::new(Vec::new()).expect_err("empty request"),
        PrepareEphemeralError
    );
    let prepared = PreparedEphemeralRequest::new(REQUEST_VALUE.to_vec()).expect("request");
    let prepared_debug = format!("{prepared:?}");
    assert!(prepared_debug.contains("[REDACTED]"));
    assert!(!prepared_debug.contains("one-use request bearer"));
    assert!(PreparedEphemeralRequest::new(vec![0x41; MAX_EPHEMERAL_REQUEST_BYTES]).is_ok());
    assert!(PreparedEphemeralRequest::new(vec![0x41; MAX_EPHEMERAL_REQUEST_BYTES + 1]).is_err());

    assert!(RunnerEphemeralReply::new(Vec::new()).is_err());
    let reply = RunnerEphemeralReply::new(RESPONSE_VALUE.to_vec()).expect("reply");
    assert_eq!(format!("{reply:?}"), "RunnerEphemeralReply([REDACTED])");
    assert!(RunnerEphemeralReply::new(vec![0x42; MAX_EPHEMERAL_RESPONSE_BYTES]).is_ok());
    assert!(RunnerEphemeralReply::new(vec![0x42; MAX_EPHEMERAL_RESPONSE_BYTES + 1]).is_err());
}

#[tokio::test]
async fn absent_handler_is_a_true_404_without_authentication_or_dispatch() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let running = spawn_ephemeral_server(
        &pki,
        verifier.clone(),
        None,
        None,
        &TransportLimits::default(),
    )
    .await;
    let (mut sender, connection) = raw_sender(&running, &pki).await;

    assert_eq!(
        response_status(
            &mut sender,
            valid_request(running.address, Bytes::from_static(REQUEST_VALUE)),
        )
        .await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(verifier.calls(), 0);

    connection.abort();
    running.stop().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Keep the complete HTTP head rejection matrix in one connection.
async fn request_head_contract_is_exact_and_rejected_before_authentication() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let handler = RecordingEphemeralHandler::new([]);
    let running = spawn_ephemeral_server(
        &pki,
        verifier.clone(),
        Some(handler.clone()),
        None,
        &TransportLimits::default(),
    )
    .await;
    let (mut sender, connection) = raw_sender(&running, &pki).await;
    let body = || Full::new(Bytes::from_static(b"x")).boxed_unsync();
    let mut wrong_host = raw_request(
        running.address,
        Method::POST,
        EPHEMERAL_SECRETS_PATH,
        body(),
        Some("1"),
        Some(EPHEMERAL_SECRETS_CONTENT_TYPE),
    );
    *wrong_host.uri_mut() = format!(
        "https://localhost:{}{EPHEMERAL_SECRETS_PATH}",
        running.address.port()
    )
    .parse()
    .expect("wrong-host URI");
    let alternate_port = if running.address.port() == u16::MAX {
        running.address.port() - 1
    } else {
        running.address.port() + 1
    };
    let mut alternate_authority = raw_request(
        running.address,
        Method::POST,
        EPHEMERAL_SECRETS_PATH,
        body(),
        Some("1"),
        Some(EPHEMERAL_SECRETS_CONTENT_TYPE),
    );
    *alternate_authority.uri_mut() = format!(
        "https://{}:{alternate_port}{EPHEMERAL_SECRETS_PATH}",
        running.address.ip()
    )
    .parse()
    .expect("alternate-port URI");
    let mut missing_content_type = valid_request(running.address, Bytes::from_static(b"x"));
    missing_content_type.headers_mut().remove(CONTENT_TYPE);

    let cases = [
        (wrong_host, StatusCode::NOT_FOUND),
        (alternate_authority, StatusCode::NOT_FOUND),
        (
            raw_request(
                running.address,
                Method::GET,
                EPHEMERAL_SECRETS_PATH,
                body(),
                Some("1"),
                Some(EPHEMERAL_SECRETS_CONTENT_TYPE),
            ),
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            raw_request(
                running.address,
                Method::POST,
                &format!("{EPHEMERAL_SECRETS_PATH}/"),
                body(),
                Some("1"),
                Some(EPHEMERAL_SECRETS_CONTENT_TYPE),
            ),
            StatusCode::NOT_FOUND,
        ),
        (
            raw_request(
                running.address,
                Method::POST,
                &format!("{EPHEMERAL_SECRETS_PATH}?retry=1"),
                body(),
                Some("1"),
                Some(EPHEMERAL_SECRETS_CONTENT_TYPE),
            ),
            StatusCode::NOT_FOUND,
        ),
        (missing_content_type, StatusCode::UNSUPPORTED_MEDIA_TYPE),
        (
            raw_request(
                running.address,
                Method::POST,
                EPHEMERAL_SECRETS_PATH,
                body(),
                Some("1"),
                Some("application/vnd.automata.runner-ephemeral-secrets.v1; charset=binary"),
            ),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            raw_request(
                running.address,
                Method::POST,
                EPHEMERAL_SECRETS_PATH,
                FramedBody::data([]).boxed_unsync(),
                Some("0"),
                Some(EPHEMERAL_SECRETS_CONTENT_TYPE),
            ),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
        (
            raw_request(
                running.address,
                Method::POST,
                EPHEMERAL_SECRETS_PATH,
                body(),
                Some("01"),
                Some(EPHEMERAL_SECRETS_CONTENT_TYPE),
            ),
            StatusCode::BAD_REQUEST,
        ),
    ];
    for (index, (request, expected)) in cases.into_iter().enumerate() {
        assert_eq!(response_status(&mut sender, request).await, expected);
        assert_eq!(handler.calls(), 0, "handler reached by head case {index}");
    }

    let missing_length = raw_request(
        running.address,
        Method::POST,
        EPHEMERAL_SECRETS_PATH,
        FramedBody::data([Bytes::from_static(b"x")]).boxed_unsync(),
        None,
        Some(EPHEMERAL_SECRETS_CONTENT_TYPE),
    );
    assert_eq!(
        response_status(&mut sender, missing_length).await,
        StatusCode::LENGTH_REQUIRED
    );

    let (_oversized_sender, oversized_body) = Channel::<Bytes, Infallible>::new(1);
    let oversized = raw_request(
        running.address,
        Method::POST,
        EPHEMERAL_SECRETS_PATH,
        oversized_body.boxed_unsync(),
        Some(&(MAX_EPHEMERAL_REQUEST_BYTES + 1).to_string()),
        Some(EPHEMERAL_SECRETS_CONTENT_TYPE),
    );
    assert_eq!(
        response_status(&mut sender, oversized).await,
        StatusCode::PAYLOAD_TOO_LARGE
    );

    let mut duplicate_type = raw_request(
        running.address,
        Method::POST,
        EPHEMERAL_SECRETS_PATH,
        body(),
        Some("1"),
        Some(EPHEMERAL_SECRETS_CONTENT_TYPE),
    );
    duplicate_type.headers_mut().append(
        CONTENT_TYPE,
        HeaderValue::from_static(EPHEMERAL_SECRETS_CONTENT_TYPE),
    );
    assert_eq!(
        response_status(&mut sender, duplicate_type).await,
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );

    for header in [ACCEPT, CACHE_CONTROL] {
        let mut missing = valid_request(running.address, Bytes::from_static(b"x"));
        missing.headers_mut().remove(&header);
        assert_eq!(
            response_status(&mut sender, missing).await,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );

        let mut wrong = valid_request(running.address, Bytes::from_static(b"x"));
        wrong.headers_mut().insert(
            header.clone(),
            HeaderValue::from_static("not-the-required-value"),
        );
        assert_eq!(
            response_status(&mut sender, wrong).await,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );

        let mut duplicate = valid_request(running.address, Bytes::from_static(b"x"));
        let value = duplicate
            .headers()
            .get(&header)
            .expect("canonical header")
            .clone();
        duplicate.headers_mut().append(header, value);
        assert_eq!(
            response_status(&mut sender, duplicate).await,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }

    let mut encoded = raw_request(
        running.address,
        Method::POST,
        EPHEMERAL_SECRETS_PATH,
        body(),
        Some("1"),
        Some(EPHEMERAL_SECRETS_CONTENT_TYPE),
    );
    encoded
        .headers_mut()
        .insert(CONTENT_ENCODING, HeaderValue::from_static("identity"));
    assert_eq!(
        response_status(&mut sender, encoded).await,
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    assert_eq!(verifier.calls(), 0);
    assert_eq!(handler.calls(), 0);

    // Hyper rejects a numeric length that cannot fit its HTTP/2 representation
    // before service dispatch.
    let overflowing_length = raw_request(
        running.address,
        Method::POST,
        EPHEMERAL_SECRETS_PATH,
        body(),
        Some("184467440737095516160"),
        Some(EPHEMERAL_SECRETS_CONTENT_TYPE),
    );
    assert!(sender.send_request(overflowing_length).await.is_err());

    // The protocol-level reset is isolated to its stream.
    let reusable = raw_request(
        running.address,
        Method::GET,
        EPHEMERAL_SECRETS_PATH,
        body(),
        Some("1"),
        Some(EPHEMERAL_SECRETS_CONTENT_TYPE),
    );
    assert_eq!(
        response_status(&mut sender, reusable).await,
        StatusCode::METHOD_NOT_ALLOWED
    );

    connection.abort();
    running.stop().await;
}

#[tokio::test]
async fn authentication_completes_before_a_stalled_body_is_polled() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::rejecting(MachineAuthenticationError::Untrusted);
    let handler = RecordingEphemeralHandler::new([HandlerAction::Reply(RESPONSE_VALUE.to_vec())]);
    let limits = TransportLimits::default()
        .with_server_request_timeouts(
            Duration::from_millis(100),
            Duration::from_secs(30),
            Duration::from_millis(100),
            Duration::from_millis(200),
        )
        .expect("request timeouts");
    let running =
        spawn_ephemeral_server(&pki, verifier.clone(), Some(handler.clone()), None, &limits).await;
    let (mut sender, connection) = raw_sender(&running, &pki).await;
    let (_body_sender, body) = Channel::<Bytes, Infallible>::new(1);
    let request = raw_request(
        running.address,
        Method::POST,
        EPHEMERAL_SECRETS_PATH,
        body.boxed_unsync(),
        Some("1"),
        Some(EPHEMERAL_SECRETS_CONTENT_TYPE),
    );

    let response = tokio::time::timeout(Duration::from_secs(5), sender.send_request(request))
        .await
        .expect("authentication precedes the body deadline")
        .expect("unauthorized response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(verifier.calls(), 1);
    assert_eq!(handler.calls(), 0);

    connection.abort();
    running.stop().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One connection proves every streamed-body failure is reusable.
async fn streamed_and_boundary_bodies_are_exact_and_failures_leave_the_connection_reusable() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let handler = RecordingEphemeralHandler::new([
        HandlerAction::Reply(RESPONSE_VALUE.to_vec()),
        HandlerAction::Reply(RESPONSE_VALUE.to_vec()),
        HandlerAction::Reply(RESPONSE_VALUE.to_vec()),
        HandlerAction::Reply(RESPONSE_VALUE.to_vec()),
    ]);
    let running = spawn_ephemeral_server(
        &pki,
        verifier.clone(),
        Some(handler.clone()),
        None,
        &TransportLimits::default(),
    )
    .await;
    let (mut sender, connection) = raw_sender(&running, &pki).await;

    let streamed_value = Bytes::from_static(b"streamed-private-value");
    let streamed = raw_request(
        running.address,
        Method::POST,
        EPHEMERAL_SECRETS_PATH,
        FramedBody::data([
            streamed_value.slice(..4),
            streamed_value.slice(4..11),
            streamed_value.slice(11..),
        ])
        .boxed_unsync(),
        Some(&streamed_value.len().to_string()),
        Some(EPHEMERAL_SECRETS_CONTENT_TYPE),
    );
    let response = sender
        .send_request(streamed)
        .await
        .expect("streamed success response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), Version::HTTP_2);
    assert_eq!(
        response.headers().get(CONTENT_TYPE),
        Some(&HeaderValue::from_static(EPHEMERAL_SECRETS_CONTENT_TYPE))
    );
    assert_eq!(
        response.headers().get(CONTENT_LENGTH),
        Some(&HeaderValue::from(RESPONSE_VALUE.len()))
    );
    assert_eq!(
        response.headers().get(CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store, private"))
    );
    assert_eq!(
        response
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes(),
        RESPONSE_VALUE
    );

    let truncated = raw_request(
        running.address,
        Method::POST,
        EPHEMERAL_SECRETS_PATH,
        FramedBody::data([Bytes::from_static(b"ab")]).boxed_unsync(),
        Some("3"),
        Some(EPHEMERAL_SECRETS_CONTENT_TYPE),
    );
    assert!(sender.send_request(truncated).await.is_err());
    assert_eq!(
        response_status(
            &mut sender,
            valid_request(running.address, Bytes::from_static(b"after-truncation")),
        )
        .await,
        StatusCode::OK
    );

    let overrun = raw_request(
        running.address,
        Method::POST,
        EPHEMERAL_SECRETS_PATH,
        FramedBody::data([Bytes::from_static(b"abc")]).boxed_unsync(),
        Some("2"),
        Some(EPHEMERAL_SECRETS_CONTENT_TYPE),
    );
    assert!(sender.send_request(overrun).await.is_err());
    assert_eq!(
        response_status(
            &mut sender,
            valid_request(running.address, Bytes::from_static(b"after-overrun")),
        )
        .await,
        StatusCode::OK
    );

    let malformed = raw_request(
        running.address,
        Method::POST,
        EPHEMERAL_SECRETS_PATH,
        FramedBody::data_then_trailers(Bytes::from_static(b"x"), HeaderMap::new()).boxed_unsync(),
        Some("1"),
        Some(EPHEMERAL_SECRETS_CONTENT_TYPE),
    );
    assert_eq!(
        response_status(&mut sender, malformed).await,
        StatusCode::BAD_REQUEST
    );

    let maximum = Bytes::from(vec![0x5a; MAX_EPHEMERAL_REQUEST_BYTES]);
    assert_eq!(
        response_status(&mut sender, valid_request(running.address, maximum.clone())).await,
        StatusCode::OK
    );
    assert_eq!(handler.calls(), 4);
    assert_eq!(verifier.calls(), 7);
    assert_eq!(
        handler.bodies(),
        [
            streamed_value.to_vec(),
            b"after-truncation".to_vec(),
            b"after-overrun".to_vec(),
            maximum.to_vec(),
        ]
    );
    assert_eq!(
        handler.identities(),
        ["runner.test", "runner.test", "runner.test", "runner.test"]
    );
    for debug in handler.request_debug() {
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("runner.test"));
        assert!(!debug.contains("private-value"));
    }

    connection.abort();
    running.stop().await;
}

#[tokio::test]
async fn typed_application_failures_timeout_and_release_the_request_permit() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let kinds = [
        ApplicationErrorKind::Forbidden,
        ApplicationErrorKind::StaleSession,
        ApplicationErrorKind::Conflict,
        ApplicationErrorKind::Unavailable,
        ApplicationErrorKind::Internal,
    ];
    let handler =
        RecordingEphemeralHandler::new(kinds.into_iter().map(HandlerAction::Fail).chain([
            HandlerAction::WaitForCancellation,
            HandlerAction::Reply(RESPONSE_VALUE.to_vec()),
        ]));
    let limits = TransportLimits::default()
        .with_concurrency_limits(8, 1, 8)
        .expect("single server request permit")
        .with_server_request_timeouts(
            Duration::from_millis(50),
            Duration::from_millis(100),
            Duration::from_millis(40),
            Duration::from_millis(80),
        )
        .expect("short handler timeout");
    let running =
        spawn_ephemeral_server(&pki, verifier.clone(), Some(handler.clone()), None, &limits).await;
    let (mut sender, connection) = raw_sender(&running, &pki).await;

    for expected in [
        StatusCode::FORBIDDEN,
        StatusCode::CONFLICT,
        StatusCode::CONFLICT,
        StatusCode::SERVICE_UNAVAILABLE,
        StatusCode::INTERNAL_SERVER_ERROR,
    ] {
        assert_eq!(
            response_status(
                &mut sender,
                valid_request(running.address, Bytes::from_static(REQUEST_VALUE)),
            )
            .await,
            expected
        );
    }
    assert_eq!(
        response_status(
            &mut sender,
            valid_request(running.address, Bytes::from_static(REQUEST_VALUE)),
        )
        .await,
        StatusCode::GATEWAY_TIMEOUT
    );
    wait_until(|| handler.cancellation_seen()).await;
    assert_eq!(
        response_status(
            &mut sender,
            valid_request(running.address, Bytes::from_static(b"permit-reused")),
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(handler.calls(), 7);
    assert_eq!(verifier.calls(), 7);

    connection.abort();
    running.stop().await;
}

#[tokio::test]
async fn configured_response_ceiling_rejects_before_bytes_and_then_reuses_the_server() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let observer = Arc::new(RecordingObserver::default());
    let handler = RecordingEphemeralHandler::new([
        HandlerAction::Reply(vec![0x51; 9]),
        HandlerAction::Reply(vec![0x52; 8]),
    ]);
    let limits = TransportLimits::default()
        .with_body_limits(64, 8)
        .expect("small response ceiling");
    let running = spawn_ephemeral_server(
        &pki,
        verifier,
        Some(handler),
        Some(observer.clone()),
        &limits,
    )
    .await;
    let (mut sender, connection) = raw_sender(&running, &pki).await;

    assert_eq!(
        response_status(
            &mut sender,
            valid_request(running.address, Bytes::from_static(b"first")),
        )
        .await,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        response_status(
            &mut sender,
            valid_request(running.address, Bytes::from_static(b"second")),
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        *observer.requests.lock().expect("request lock"),
        [
            RunnerTransportRequestObservation::ResponseRejected {
                route: RunnerTransportRoute::EphemeralSecrets,
                reason: RunnerTransportResponseRejection::TooLarge,
            },
            RunnerTransportRequestObservation::Succeeded {
                route: RunnerTransportRoute::EphemeralSecrets,
            },
        ]
    );
    assert_eq!(
        *observer.starts.lock().expect("start lock"),
        [
            RunnerTransportRoute::EphemeralSecrets,
            RunnerTransportRoute::EphemeralSecrets,
        ]
    );
    assert_eq!(
        *observer.finishes.lock().expect("finish lock"),
        *observer.starts.lock().expect("start lock")
    );
    assert_eq!(
        *observer.bytes.lock().expect("byte lock"),
        [
            (
                RunnerTransportRoute::EphemeralSecrets,
                RunnerTransportByteDirection::Request,
                5,
            ),
            (
                RunnerTransportRoute::EphemeralSecrets,
                RunnerTransportByteDirection::Request,
                6,
            ),
            (
                RunnerTransportRoute::EphemeralSecrets,
                RunnerTransportByteDirection::Response,
                8,
            ),
        ]
    );

    connection.abort();
    running.stop().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Exact ordered observer events are clearer as one scenario.
async fn observer_has_exact_route_stage_byte_and_balanced_in_flight_semantics() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let observer = Arc::new(RecordingObserver::default());
    let handler = RecordingEphemeralHandler::new([
        HandlerAction::Fail(ApplicationErrorKind::Forbidden),
        HandlerAction::Reply(RESPONSE_VALUE.to_vec()),
    ]);
    let running = spawn_ephemeral_server(
        &pki,
        verifier.clone(),
        Some(handler),
        Some(observer.clone()),
        &TransportLimits::default(),
    )
    .await;
    let (mut sender, connection) = raw_sender(&running, &pki).await;

    let query = raw_request(
        running.address,
        Method::POST,
        &format!("{EPHEMERAL_SECRETS_PATH}?forbidden=query"),
        Full::new(Bytes::from_static(b"x")).boxed_unsync(),
        Some("1"),
        Some(EPHEMERAL_SECRETS_CONTENT_TYPE),
    );
    assert_eq!(
        response_status(&mut sender, query).await,
        StatusCode::NOT_FOUND
    );

    let malformed = raw_request(
        running.address,
        Method::POST,
        EPHEMERAL_SECRETS_PATH,
        FramedBody::data_then_trailers(Bytes::from_static(b"x"), HeaderMap::new()).boxed_unsync(),
        Some("1"),
        Some(EPHEMERAL_SECRETS_CONTENT_TYPE),
    );
    assert_eq!(
        response_status(&mut sender, malformed).await,
        StatusCode::BAD_REQUEST
    );

    assert_eq!(
        response_status(
            &mut sender,
            valid_request(running.address, Bytes::from_static(b"denied")),
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        response_status(
            &mut sender,
            valid_request(running.address, Bytes::from_static(b"accepted")),
        )
        .await,
        StatusCode::OK
    );

    assert_eq!(
        *observer.requests.lock().expect("request lock"),
        [
            RunnerTransportRequestObservation::HeadRejected {
                route: RunnerTransportRoute::EphemeralSecrets,
                reason: RunnerTransportHeadRejection::NotFound,
            },
            RunnerTransportRequestObservation::BodyRejected {
                route: RunnerTransportRoute::EphemeralSecrets,
                reason: RunnerTransportBodyRejection::Invalid,
            },
            RunnerTransportRequestObservation::ApplicationRejected {
                route: RunnerTransportRoute::EphemeralSecrets,
                reason: RunnerTransportApplicationRejection::Forbidden,
            },
            RunnerTransportRequestObservation::Succeeded {
                route: RunnerTransportRoute::EphemeralSecrets,
            },
        ]
    );
    assert_eq!(
        *observer.starts.lock().expect("start lock"),
        [
            RunnerTransportRoute::EphemeralSecrets,
            RunnerTransportRoute::EphemeralSecrets,
            RunnerTransportRoute::EphemeralSecrets,
        ]
    );
    assert_eq!(
        *observer.finishes.lock().expect("finish lock"),
        *observer.starts.lock().expect("start lock")
    );
    assert_eq!(
        *observer.bytes.lock().expect("byte lock"),
        [
            (
                RunnerTransportRoute::EphemeralSecrets,
                RunnerTransportByteDirection::Request,
                6,
            ),
            (
                RunnerTransportRoute::EphemeralSecrets,
                RunnerTransportByteDirection::Request,
                8,
            ),
            (
                RunnerTransportRoute::EphemeralSecrets,
                RunnerTransportByteDirection::Response,
                u64::try_from(RESPONSE_VALUE.len()).expect("small response"),
            ),
        ]
    );
    assert_eq!(verifier.calls(), 3);
    let observations = format!("{:?}", *observer.requests.lock().expect("request lock"));
    assert!(!observations.contains("denied"));
    assert!(!observations.contains("accepted"));
    assert!(!observations.contains("one-use"));

    connection.abort();
    running.stop().await;
}

#[tokio::test]
async fn typed_client_succeeds_redacts_and_classifies_application_statuses() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let handler = RecordingEphemeralHandler::new([
        HandlerAction::Reply(RESPONSE_VALUE.to_vec()),
        HandlerAction::Fail(ApplicationErrorKind::Forbidden),
        HandlerAction::Fail(ApplicationErrorKind::Unavailable),
    ]);
    let running = spawn_ephemeral_server(
        &pki,
        verifier.clone(),
        Some(handler.clone()),
        None,
        &TransportLimits::default(),
    )
    .await;
    let client = HyperRunnerEphemeralClient::new(
        &running.endpoint,
        &pki.client_tls(&pki.client),
        TransportLimits::default(),
    )
    .expect("ephemeral client");
    let prepared = PreparedEphemeralRequest::new(REQUEST_VALUE.to_vec()).expect("prepared request");

    let response = client
        .exchange(&prepared, CancellationToken::new())
        .await
        .expect("typed ephemeral response");
    let debug = format!("{response:?}");
    assert_eq!(debug, "RunnerEphemeralResponse([REDACTED])");
    assert!(!debug.contains("one-use response value"));
    assert_eq!(response.expose_body(), RESPONSE_VALUE);
    assert_eq!(&*response.into_body(), RESPONSE_VALUE);

    let forbidden = client
        .exchange(&prepared, CancellationToken::new())
        .await
        .expect_err("forbidden response");
    assert_eq!(
        forbidden.kind(),
        ClientErrorKind::HttpStatus(StatusCode::FORBIDDEN)
    );
    assert_eq!(forbidden.retry_class(), RetryClass::Never);

    let unavailable = client
        .exchange(&prepared, CancellationToken::new())
        .await
        .expect_err("unavailable response");
    assert_eq!(
        unavailable.kind(),
        ClientErrorKind::HttpStatus(StatusCode::SERVICE_UNAVAILABLE)
    );
    assert_eq!(unavailable.retry_class(), RetryClass::RetrySameRequest);
    assert_eq!(handler.bodies(), vec![REQUEST_VALUE.to_vec(); 3]);
    assert_eq!(verifier.calls(), 3);

    running.stop().await;
}

#[tokio::test]
async fn typed_client_enforces_its_smaller_response_ceiling() {
    let pki = TestPki::new();
    let handler = RecordingEphemeralHandler::new([HandlerAction::Reply(vec![0x61; 9])]);
    let running = spawn_ephemeral_server(
        &pki,
        RecordingVerifier::accepting(),
        Some(handler),
        None,
        &TransportLimits::default(),
    )
    .await;
    let limits = TransportLimits::default()
        .with_body_limits(64, 8)
        .expect("small client response ceiling");
    let client =
        HyperRunnerEphemeralClient::new(&running.endpoint, &pki.client_tls(&pki.client), limits)
            .expect("bounded client");
    let prepared = PreparedEphemeralRequest::new(REQUEST_VALUE.to_vec()).expect("prepared request");

    let error = client
        .exchange(&prepared, CancellationToken::new())
        .await
        .expect_err("oversized response");
    assert_eq!(error.kind(), ClientErrorKind::ResponseTooLarge);
    assert_eq!(error.retry_class(), RetryClass::Never);

    running.stop().await;
}

#[tokio::test]
async fn typed_client_rejects_noncanonical_ephemeral_response_heads() {
    let pki = TestPki::new();
    let cases = [
        FixedResponseHead {
            content_type: Some("application/octet-stream"),
            cache_control: Some("no-store, private"),
            duplicate_cache_control: false,
            content_encoding: None,
        },
        FixedResponseHead {
            content_type: Some(EPHEMERAL_SECRETS_CONTENT_TYPE),
            cache_control: None,
            duplicate_cache_control: false,
            content_encoding: None,
        },
        FixedResponseHead {
            content_type: Some(EPHEMERAL_SECRETS_CONTENT_TYPE),
            cache_control: Some("no-store, private"),
            duplicate_cache_control: true,
            content_encoding: None,
        },
        FixedResponseHead {
            content_type: Some(EPHEMERAL_SECRETS_CONTENT_TYPE),
            cache_control: Some("no-store, private"),
            duplicate_cache_control: false,
            content_encoding: Some("identity"),
        },
    ];

    for response_head in cases {
        let (endpoint, request_checked, server) =
            spawn_fixed_ephemeral_response_server(&pki, response_head).await;
        let client = HyperRunnerEphemeralClient::new(
            &endpoint,
            &pki.client_tls(&pki.client),
            TransportLimits::default(),
        )
        .expect("fixed-peer client");
        let prepared =
            PreparedEphemeralRequest::new(REQUEST_VALUE.to_vec()).expect("prepared request");

        let error = client
            .exchange(&prepared, CancellationToken::new())
            .await
            .expect_err("noncanonical response head");
        assert_eq!(error.kind(), ClientErrorKind::InvalidResponse);
        assert_eq!(error.retry_class(), RetryClass::Never);
        tokio::time::timeout(Duration::from_secs(5), request_checked)
            .await
            .expect("fixed peer request check deadline")
            .expect("fixed peer validated the typed request");
        server.abort();
        let _ = server.await;
    }
}

#[tokio::test]
async fn typed_client_cancellation_resets_the_stream_and_balances_server_observation() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let observer = Arc::new(RecordingObserver::default());
    let handler = RecordingEphemeralHandler::new([HandlerAction::WaitForCancellation]);
    let limits = TransportLimits::default()
        .with_server_request_timeouts(
            Duration::from_millis(100),
            Duration::from_secs(10),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .expect("long server handler deadline");
    let running = spawn_ephemeral_server(
        &pki,
        verifier,
        Some(handler.clone()),
        Some(observer.clone()),
        &limits,
    )
    .await;
    let client = Arc::new(
        HyperRunnerEphemeralClient::new(&running.endpoint, &pki.client_tls(&pki.client), limits)
            .expect("ephemeral client"),
    );
    let cancellation = CancellationToken::new();
    let task_client = Arc::clone(&client);
    let task_cancellation = cancellation.clone();
    let task = tokio::spawn(async move {
        let prepared =
            PreparedEphemeralRequest::new(REQUEST_VALUE.to_vec()).expect("prepared request");
        task_client.exchange(&prepared, task_cancellation).await
    });
    wait_until(|| handler.calls() == 1).await;

    cancellation.cancel();
    let error = task
        .await
        .expect("client cancellation task")
        .expect_err("cancelled request");
    assert_eq!(error.kind(), ClientErrorKind::Cancelled);
    assert_eq!(error.retry_class(), RetryClass::Never);
    wait_until(|| handler.cancellation_seen()).await;
    wait_until(|| observer.requests.lock().expect("request lock").len() == 1).await;
    assert_eq!(
        *observer.requests.lock().expect("request lock"),
        [RunnerTransportRequestObservation::Cancelled {
            route: RunnerTransportRoute::EphemeralSecrets,
        }]
    );
    assert_eq!(
        *observer.starts.lock().expect("start lock"),
        [RunnerTransportRoute::EphemeralSecrets]
    );
    assert_eq!(
        *observer.finishes.lock().expect("finish lock"),
        [RunnerTransportRoute::EphemeralSecrets]
    );

    handler.push(HandlerAction::Reply(RESPONSE_VALUE.to_vec()));
    let prepared = PreparedEphemeralRequest::new(b"after-cancellation".to_vec()).expect("request");
    assert_eq!(
        client
            .exchange(&prepared, CancellationToken::new())
            .await
            .expect("permit and server reuse")
            .expose_body(),
        RESPONSE_VALUE
    );

    running.stop().await;
}

#[derive(Clone, Copy)]
struct FixedResponseHead {
    content_type: Option<&'static str>,
    cache_control: Option<&'static str>,
    duplicate_cache_control: bool,
    content_encoding: Option<&'static str>,
}

async fn spawn_fixed_ephemeral_response_server(
    pki: &TestPki,
    response_head: FixedResponseHead,
) -> (Uri, tokio::sync::oneshot::Receiver<()>, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind fixed ephemeral peer");
    let address = listener.local_addr().expect("fixed peer address");
    let acceptor = TlsAcceptor::from(Arc::new(pki.raw_server_config()));
    let (request_checked, request_checked_rx) = tokio::sync::oneshot::channel();
    let request_checked = Arc::new(Mutex::new(Some(request_checked)));
    let task = tokio::spawn(async move {
        let Ok((tcp, _)) = listener.accept().await else {
            return;
        };
        let Ok(tls) = acceptor.accept(tcp).await else {
            return;
        };
        let service_request_checked = Arc::clone(&request_checked);
        let service = service_fn(move |request: Request<hyper::body::Incoming>| {
            let request_checked = Arc::clone(&service_request_checked);
            async move {
                assert_eq!(request.method(), Method::POST);
                assert_eq!(request.version(), Version::HTTP_2);
                assert_eq!(request.uri().scheme_str(), Some("https"));
                assert!(request.uri().authority().is_some());
                assert_eq!(request.uri().path(), EPHEMERAL_SECRETS_PATH);
                assert_eq!(request.uri().query(), None);
                assert_eq!(
                    request.headers().get(CONTENT_TYPE),
                    Some(&HeaderValue::from_static(EPHEMERAL_SECRETS_CONTENT_TYPE))
                );
                assert_eq!(
                    request.headers().get(ACCEPT),
                    Some(&HeaderValue::from_static(EPHEMERAL_SECRETS_CONTENT_TYPE))
                );
                assert_eq!(
                    request.headers().get(CACHE_CONTROL),
                    Some(&HeaderValue::from_static("no-store"))
                );
                assert_eq!(
                    request.headers().get(CONTENT_LENGTH),
                    Some(&HeaderValue::from(REQUEST_VALUE.len()))
                );
                if let Some(request_checked) = request_checked
                    .lock()
                    .expect("request check notification lock")
                    .take()
                {
                    let _ = request_checked.send(());
                }

                let body = Bytes::from_static(RESPONSE_VALUE);
                let mut response = Response::new(Full::new(body.clone()));
                if let Some(content_type) = response_head.content_type {
                    response
                        .headers_mut()
                        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
                }
                if let Some(cache_control) = response_head.cache_control {
                    response
                        .headers_mut()
                        .insert(CACHE_CONTROL, HeaderValue::from_static(cache_control));
                    if response_head.duplicate_cache_control {
                        response
                            .headers_mut()
                            .append(CACHE_CONTROL, HeaderValue::from_static(cache_control));
                    }
                }
                if let Some(content_encoding) = response_head.content_encoding {
                    response
                        .headers_mut()
                        .insert(CONTENT_ENCODING, HeaderValue::from_static(content_encoding));
                }
                response
                    .headers_mut()
                    .insert(CONTENT_LENGTH, HeaderValue::from(body.len()));
                Ok::<_, Infallible>(response)
            }
        });
        let mut builder = http2::Builder::new(TokioExecutor::new());
        builder.timer(TokioTimer::new());
        let _ = builder.serve_connection(TokioIo::new(tls), service).await;
    });
    let endpoint = format!("https://{address}/")
        .parse()
        .expect("fixed peer endpoint");
    (endpoint, request_checked_rx, task)
}
