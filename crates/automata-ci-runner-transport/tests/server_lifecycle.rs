mod support;

use std::{
    fmt,
    io::ErrorKind,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use automata_ci_auth::machine::MachineIdentityVerifier;
use automata_ci_protocol::ProtocolLimits;
use automata_ci_runner_transport::{
    ApplicationError, ApplicationErrorKind, AuthenticatedRunnerRequest, HANDSHAKE_PATH,
    HandlerFuture, PROTOBUF_CONTENT_TYPE, RunnerControlHandler, RunnerControlServer,
    RunnerTransportConnectionEvent, RunnerTransportObserver, RunnerTransportTlsOutcome, ServeError,
    TransportLimits,
};
use http::{Method, Request, StatusCode, Version, header::CONTENT_TYPE};
use http_body_util::{BodyExt as _, Full};
use tokio::{
    io::AsyncReadExt as _,
    net::{TcpListener, TcpStream},
    sync::Notify,
    task::JoinHandle,
    time::{advance, timeout},
};
use tokio_util::sync::CancellationToken;

use support::{
    HandlerMode, RawBody, RecordingVerifier, TestHandler, TestPki, hello_request, raw_h2_sender,
};

const TEST_WATCHDOG: Duration = Duration::from_secs(5);

#[derive(Default)]
struct LifecycleObserver {
    connections: Mutex<Vec<RunnerTransportConnectionEvent>>,
    tls: Mutex<Vec<RunnerTransportTlsOutcome>>,
    changed: Notify,
}

impl fmt::Debug for LifecycleObserver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("LifecycleObserver").finish()
    }
}

impl LifecycleObserver {
    fn connection_events(&self) -> Vec<RunnerTransportConnectionEvent> {
        self.connections
            .lock()
            .expect("connection event lock")
            .clone()
    }

    fn tls_outcomes(&self) -> Vec<RunnerTransportTlsOutcome> {
        self.tls.lock().expect("TLS outcome lock").clone()
    }

    async fn wait_for_connection(&self, expected: RunnerTransportConnectionEvent, count: usize) {
        timeout(TEST_WATCHDOG, async {
            loop {
                let changed = self.changed.notified();
                let observed = self
                    .connections
                    .lock()
                    .expect("connection event lock")
                    .iter()
                    .filter(|event| **event == expected)
                    .count();
                if observed >= count {
                    return;
                }
                changed.await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!("connection observer did not record {count} {expected:?} events")
        });
    }

    async fn wait_for_http2_terminal_count(&self, count: usize) {
        timeout(TEST_WATCHDOG, async {
            loop {
                let changed = self.changed.notified();
                let observed = self
                    .connections
                    .lock()
                    .expect("connection event lock")
                    .iter()
                    .filter(|event| {
                        matches!(
                            event,
                            RunnerTransportConnectionEvent::Http2Closed
                                | RunnerTransportConnectionEvent::Http2Error
                        )
                    })
                    .count();
                if observed >= count {
                    return;
                }
                changed.await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("connection observer did not record {count} HTTP/2 terminals"));
    }
}

impl RunnerTransportObserver for LifecycleObserver {
    fn observe_connection(&self, event: RunnerTransportConnectionEvent) {
        self.connections
            .lock()
            .expect("connection event lock")
            .push(event);
        self.changed.notify_waiters();
    }

    fn observe_tls(&self, outcome: RunnerTransportTlsOutcome, _duration: Duration) {
        self.tls.lock().expect("TLS outcome lock").push(outcome);
        self.changed.notify_waiters();
    }
}

struct LifecycleServer {
    address: SocketAddr,
    shutdown: CancellationToken,
    task: JoinHandle<Result<(), ServeError>>,
}

impl LifecycleServer {
    async fn finish(self) {
        timeout(TEST_WATCHDOG, self.task)
            .await
            .expect("server task watchdog")
            .expect("server task")
            .expect("server serve result");
    }

    async fn stop(self) {
        self.shutdown.cancel();
        self.finish().await;
    }
}

async fn spawn_lifecycle_server(
    pki: &TestPki,
    verifier: Arc<dyn MachineIdentityVerifier>,
    handler: Arc<dyn RunnerControlHandler>,
    limits: &TransportLimits,
    observer: Arc<LifecycleObserver>,
) -> LifecycleServer {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind lifecycle server");
    let address = listener.local_addr().expect("lifecycle server address");
    let server = RunnerControlServer::new(
        listener,
        &pki.server_tls(),
        verifier,
        handler,
        ProtocolLimits::default(),
        *limits,
    )
    .expect("lifecycle server")
    .with_observer(observer);
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(server.serve(shutdown.clone()));
    LifecycleServer {
        address,
        shutdown,
        task,
    }
}

#[tokio::test]
async fn connection_limit_rejects_excess_and_reuses_released_permit() {
    let pki = TestPki::new();
    let observer = Arc::new(LifecycleObserver::default());
    let handler = TestHandler::new(HandlerMode::Reply);
    let limits = TransportLimits::default()
        .with_concurrency_limits(1, 16, 16)
        .expect("one concurrent connection");
    let running = spawn_lifecycle_server(
        &pki,
        RecordingVerifier::accepting(),
        handler.clone(),
        &limits,
        Arc::clone(&observer),
    )
    .await;

    let (first_sender, first_connection) =
        raw_h2_sender(running.address, pki.raw_client_config(Some(&pki.client)))
            .await
            .expect("first admitted H2 connection");
    observer
        .wait_for_connection(RunnerTransportConnectionEvent::Admitted, 1)
        .await;

    let rejected = raw_h2_sender(running.address, pki.raw_client_config(Some(&pki.client)));
    assert!(
        timeout(TEST_WATCHDOG, rejected)
            .await
            .expect("overload rejection watchdog")
            .is_err(),
        "the excess TCP connection must be closed before TLS/H2 admission"
    );
    observer
        .wait_for_connection(RunnerTransportConnectionEvent::Overloaded, 1)
        .await;
    assert_eq!(
        observer.tls_outcomes(),
        [RunnerTransportTlsOutcome::Accepted],
        "an overloaded socket must not enter the TLS task"
    );

    drop(first_sender);
    first_connection.abort();
    let _ = first_connection.await;
    observer.wait_for_http2_terminal_count(1).await;

    let (mut reused_sender, reused_connection) =
        raw_h2_sender(running.address, pki.raw_client_config(Some(&pki.client)))
            .await
            .expect("released connection permit must be reusable");
    let response = reused_sender
        .send_request(raw_hello_request(running.address))
        .await
        .expect("request over reused connection permit");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(handler.calls(), 1);
    assert_eq!(
        observer.tls_outcomes(),
        [
            RunnerTransportTlsOutcome::Accepted,
            RunnerTransportTlsOutcome::Accepted,
        ]
    );

    drop(response);
    drop(reused_sender);
    reused_connection.abort();
    let _ = reused_connection.await;
    observer.wait_for_http2_terminal_count(2).await;
    running.stop().await;

    let events = observer.connection_events();
    assert_eq!(
        events
            .iter()
            .filter(|event| **event == RunnerTransportConnectionEvent::Admitted)
            .count(),
        2
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| **event == RunnerTransportConnectionEvent::Overloaded)
            .count(),
        1
    );
}

#[tokio::test]
async fn shutdown_cancels_in_flight_handler_and_drains_its_response() {
    let pki = TestPki::new();
    let observer = Arc::new(LifecycleObserver::default());
    let handler = CancellationCompletingHandler::new();
    let limits = TransportLimits::default()
        .with_graceful_shutdown_timeout(Duration::from_hours(1))
        .expect("long graceful shutdown watchdog");
    let running = spawn_lifecycle_server(
        &pki,
        RecordingVerifier::accepting(),
        handler.clone(),
        &limits,
        Arc::clone(&observer),
    )
    .await;
    let (sender, connection) =
        raw_h2_sender(running.address, pki.raw_client_config(Some(&pki.client)))
            .await
            .expect("cooperative-shutdown H2 connection");
    let mut request_sender = sender.clone();
    let request = raw_hello_request(running.address);
    let response_task = tokio::spawn(async move {
        let response = request_sender
            .send_request(request)
            .await
            .expect("shutdown response");
        let status = response.status();
        response
            .into_body()
            .collect()
            .await
            .expect("collect shutdown response");
        status
    });
    handler.wait_until_started().await;

    running.shutdown.cancel();
    handler.wait_until_completed().await;
    assert_eq!(
        timeout(TEST_WATCHDOG, response_task)
            .await
            .expect("cooperative response watchdog")
            .expect("cooperative response task"),
        StatusCode::SERVICE_UNAVAILABLE
    );

    running.finish().await;
    assert!(handler.cancellation_seen());
    assert_eq!(
        observer.connection_events(),
        [
            RunnerTransportConnectionEvent::Admitted,
            RunnerTransportConnectionEvent::Shutdown,
        ]
    );

    drop(sender);
    connection.abort();
    let _ = connection.await;
}

#[tokio::test]
async fn grace_timeout_aborts_a_connection_stalled_before_tls() {
    const GRACE: Duration = Duration::from_secs(1);

    let pki = TestPki::new();
    let observer = Arc::new(LifecycleObserver::default());
    let handler = TestHandler::new(HandlerMode::Reply);
    let limits = TransportLimits::default()
        .with_graceful_shutdown_timeout(GRACE)
        .expect("one-second grace period");
    let running = spawn_lifecycle_server(
        &pki,
        RecordingVerifier::accepting(),
        handler.clone(),
        &limits,
        Arc::clone(&observer),
    )
    .await;
    let mut stalled = TcpStream::connect(running.address)
        .await
        .expect("stalled TCP connection");
    observer
        .wait_for_connection(RunnerTransportConnectionEvent::Admitted, 1)
        .await;

    tokio::time::pause();
    let shutdown_started = tokio::time::Instant::now();
    running.shutdown.cancel();
    yield_to_shutdown_drain().await;

    advance(
        GRACE
            .checked_sub(Duration::from_millis(1))
            .expect("grace exceeds one millisecond"),
    )
    .await;
    assert!(!running.task.is_finished());
    assert!(observer.tls_outcomes().is_empty());

    advance(Duration::from_millis(2)).await;
    for _ in 0..8 {
        if running.task.is_finished() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        running.task.is_finished(),
        "the listener must abort a connection that exceeds its grace period"
    );
    assert_eq!(
        tokio::time::Instant::now() - shutdown_started,
        GRACE + Duration::from_millis(1)
    );

    running.finish().await;
    assert_tcp_closed_without_data(&mut stalled).await;
    assert_eq!(handler.calls(), 0);
    assert_eq!(
        observer.connection_events().first(),
        Some(&RunnerTransportConnectionEvent::Admitted)
    );
}

fn raw_hello_request(address: SocketAddr) -> Request<RawBody> {
    let body = hello_request().canonical_bytes().clone();
    let body_length = body.len();
    let mut request = Request::new(Full::new(body).boxed_unsync());
    *request.method_mut() = Method::POST;
    *request.version_mut() = Version::HTTP_2;
    *request.uri_mut() = format!("https://{address}{HANDSHAKE_PATH}")
        .parse()
        .expect("hello request URI");
    request.headers_mut().insert(
        CONTENT_TYPE,
        PROTOBUF_CONTENT_TYPE.parse().expect("protobuf media type"),
    );
    request
        .headers_mut()
        .insert(http::header::CONTENT_LENGTH, body_length.into());
    request
}

#[derive(Debug)]
struct CancellationCompletingHandler {
    started: AtomicBool,
    cancellation_seen: AtomicBool,
    completed: AtomicBool,
    changed: Notify,
}

impl CancellationCompletingHandler {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            started: AtomicBool::new(false),
            cancellation_seen: AtomicBool::new(false),
            completed: AtomicBool::new(false),
            changed: Notify::new(),
        })
    }

    async fn wait_until_started(&self) {
        wait_for_flag(&self.started, &self.changed).await;
    }

    async fn wait_until_completed(&self) {
        wait_for_flag(&self.completed, &self.changed).await;
    }

    fn cancellation_seen(&self) -> bool {
        self.cancellation_seen.load(Ordering::SeqCst)
    }

    async fn run(
        &self,
        request: AuthenticatedRunnerRequest,
    ) -> Result<automata_ci_protocol::ServerToRunner, ApplicationError> {
        self.started.store(true, Ordering::SeqCst);
        self.changed.notify_waiters();
        let cancellation = request.cancellation_token();
        cancellation.cancelled().await;
        self.cancellation_seen.store(true, Ordering::SeqCst);
        self.completed.store(true, Ordering::SeqCst);
        self.changed.notify_waiters();
        Err(ApplicationError::new(ApplicationErrorKind::Unavailable))
    }
}

impl RunnerControlHandler for CancellationCompletingHandler {
    fn handshake(&self, request: AuthenticatedRunnerRequest) -> HandlerFuture<'_> {
        Box::pin(self.run(request))
    }

    fn sync(&self, request: AuthenticatedRunnerRequest) -> HandlerFuture<'_> {
        Box::pin(self.run(request))
    }
}

async fn wait_for_flag(flag: &AtomicBool, changed: &Notify) {
    timeout(TEST_WATCHDOG, async {
        loop {
            let notified = changed.notified();
            if flag.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    })
    .await
    .expect("handler lifecycle flag watchdog");
}

async fn yield_to_shutdown_drain() {
    // The public server observer deliberately has no pre-TLS drain event, so a
    // stalled handshake cannot expose a stronger test-side gate. Tokio time is
    // frozen here; bounded scheduler turns let the cancellation-woken accept
    // loop install its grace timer without consuming any of that grace period.
    const SCHEDULER_TURNS: usize = 32;
    for _ in 0..SCHEDULER_TURNS {
        tokio::task::yield_now().await;
    }
}

async fn assert_tcp_closed_without_data(stream: &mut TcpStream) {
    let mut byte = [0_u8; 1];
    let read = timeout(TEST_WATCHDOG, stream.read(&mut byte))
        .await
        .expect("closed-socket read watchdog");
    match read {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
            ) => {}
        Ok(count) => panic!("aborted connection delivered {count} unexpected bytes"),
        Err(error) => panic!(
            "aborted connection returned unexpected read error {:?}: {error}",
            error.kind()
        ),
    }
}
