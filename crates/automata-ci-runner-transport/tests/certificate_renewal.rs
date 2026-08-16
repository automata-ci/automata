use crate::support;

use std::{
    collections::VecDeque,
    convert::Infallible,
    fmt,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use automata_ci_auth::machine::MachineIdentityVerifier;
use automata_ci_protocol::ProtocolLimits;
use automata_ci_runner_transport::{
    ApplicationError, ApplicationErrorKind, AuthenticatedRunnerCertificateRenewalRequest,
    CERTIFICATE_RENEWAL_CONTENT_TYPE, CERTIFICATE_RENEWAL_PATH, CertificateRenewalHandlerFuture,
    ClientErrorKind, HyperRunnerCertificateRenewalClient, MAX_CERTIFICATE_RENEWAL_REQUEST_BYTES,
    MAX_CERTIFICATE_RENEWAL_RESPONSE_BYTES, PrepareCertificateRenewalError,
    PreparedCertificateRenewalRequest, RetryClass, RunnerCertificateRenewalClient,
    RunnerCertificateRenewalHandler, RunnerCertificateRenewalReply, RunnerControlHandler,
    RunnerControlServer, ServeError, TransportLimits,
};
use bytes::Bytes;
use http::{
    HeaderValue, Method, Request, StatusCode, Version,
    header::{ACCEPT, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE},
};
use http_body_util::{BodyExt as _, Channel, Full};
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use support::{HandlerMode, RawBody, RecordingVerifier, TestHandler, TestPki, raw_h2_sender};

const REQUEST: &[u8] =
    br#"{"operation_id":"00000000-0000-4000-8000-000000000001","csr_pem":"redacted"}"#;
const RESPONSE: &[u8] =
    br#"{"operation_id":"00000000-0000-4000-8000-000000000001","certificate":"redacted"}"#;

enum HandlerAction {
    Reply(Vec<u8>),
    Fail(ApplicationErrorKind),
    Delay(Duration, Vec<u8>),
}

struct RecordingRenewalHandler {
    actions: Mutex<VecDeque<HandlerAction>>,
    calls: AtomicUsize,
    bodies: Mutex<Vec<Vec<u8>>>,
}

impl RecordingRenewalHandler {
    fn new(actions: impl IntoIterator<Item = HandlerAction>) -> Arc<Self> {
        Arc::new(Self {
            actions: Mutex::new(actions.into_iter().collect()),
            calls: AtomicUsize::new(0),
            bodies: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn bodies(&self) -> Vec<Vec<u8>> {
        self.bodies.lock().expect("body lock").clone()
    }
}

impl fmt::Debug for RecordingRenewalHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingRenewalHandler")
            .field("calls", &self.calls())
            .finish_non_exhaustive()
    }
}

impl RunnerCertificateRenewalHandler for RecordingRenewalHandler {
    fn handle(
        &self,
        request: AuthenticatedRunnerCertificateRenewalRequest,
    ) -> CertificateRenewalHandlerFuture<'_> {
        let debug = format!("{request:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("runner.test"));
        let (_, body, _) = request.into_parts();
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.bodies.lock().expect("body lock").push(body.to_vec());
        let action = self
            .actions
            .lock()
            .expect("action lock")
            .pop_front()
            .expect("one renewal action per request");
        match action {
            HandlerAction::Reply(body) => {
                Box::pin(async move { RunnerCertificateRenewalReply::new(body) })
            }
            HandlerAction::Fail(kind) => Box::pin(async move { Err(ApplicationError::new(kind)) }),
            HandlerAction::Delay(duration, body) => Box::pin(async move {
                tokio::time::sleep(duration).await;
                RunnerCertificateRenewalReply::new(body)
            }),
        }
    }
}

struct RunningRenewalServer {
    address: SocketAddr,
    endpoint: http::Uri,
    shutdown: CancellationToken,
    task: JoinHandle<Result<(), ServeError>>,
}

impl RunningRenewalServer {
    async fn stop(self) {
        self.shutdown.cancel();
        self.task
            .await
            .expect("renewal server task")
            .expect("renewal server result");
    }
}

async fn spawn_server(
    pki: &TestPki,
    verifier: Arc<dyn MachineIdentityVerifier>,
    handler: Option<Arc<dyn RunnerCertificateRenewalHandler>>,
    limits: &TransportLimits,
) -> RunningRenewalServer {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind renewal server");
    let address = listener.local_addr().expect("renewal server address");
    let control: Arc<dyn RunnerControlHandler> = TestHandler::new(HandlerMode::Reply);
    let mut server = RunnerControlServer::new(
        listener,
        &pki.server_tls(),
        verifier,
        control,
        ProtocolLimits::default(),
        *limits,
    )
    .expect("renewal server");
    if let Some(handler) = handler {
        server = server.with_certificate_renewal_handler(
            address.to_string().parse().expect("renewal authority"),
            handler,
        );
    }
    let endpoint = format!("https://{address}/")
        .parse()
        .expect("renewal endpoint");
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(server.serve(shutdown.clone()));
    RunningRenewalServer {
        address,
        endpoint,
        shutdown,
        task,
    }
}

fn raw_request(address: SocketAddr, body: RawBody, content_length: usize) -> Request<RawBody> {
    let mut request = Request::new(body);
    *request.method_mut() = Method::POST;
    *request.version_mut() = Version::HTTP_2;
    *request.uri_mut() = format!("https://{address}{CERTIFICATE_RENEWAL_PATH}")
        .parse()
        .expect("renewal request URI");
    request.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static(CERTIFICATE_RENEWAL_CONTENT_TYPE),
    );
    request.headers_mut().insert(
        ACCEPT,
        HeaderValue::from_static(CERTIFICATE_RENEWAL_CONTENT_TYPE),
    );
    request
        .headers_mut()
        .insert(CONTENT_LENGTH, HeaderValue::from(content_length));
    request
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    request
}

#[test]
fn renewal_aggregates_are_bounded_and_redacted() {
    assert_eq!(
        PreparedCertificateRenewalRequest::new(Vec::new()).expect_err("empty request"),
        PrepareCertificateRenewalError
    );
    let prepared = PreparedCertificateRenewalRequest::new(REQUEST.to_vec()).expect("request");
    let debug = format!("{prepared:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("csr_pem"));
    assert!(
        PreparedCertificateRenewalRequest::new(vec![0x41; MAX_CERTIFICATE_RENEWAL_REQUEST_BYTES])
            .is_ok()
    );
    assert!(
        PreparedCertificateRenewalRequest::new(vec![
            0x41;
            MAX_CERTIFICATE_RENEWAL_REQUEST_BYTES + 1
        ])
        .is_err()
    );
    assert!(RunnerCertificateRenewalReply::new(vec![0x42]).is_ok());
    assert!(
        RunnerCertificateRenewalReply::new(vec![0x42; MAX_CERTIFICATE_RENEWAL_RESPONSE_BYTES + 1])
            .is_err()
    );
}

#[tokio::test]
async fn absent_authority_is_a_true_404_without_machine_authentication() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let running = spawn_server(&pki, verifier.clone(), None, &TransportLimits::default()).await;
    let (mut sender, connection) =
        raw_h2_sender(running.address, pki.raw_client_config(Some(&pki.client)))
            .await
            .expect("authenticated h2 client");
    let response = sender
        .send_request(raw_request(
            running.address,
            Full::new(Bytes::from_static(REQUEST)).boxed_unsync(),
            REQUEST.len(),
        ))
        .await
        .expect("absent-route response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(verifier.calls(), 0);
    connection.abort();
    running.stop().await;
}

#[tokio::test]
async fn typed_client_exact_retries_not_due_then_succeeds_and_keeps_conflict_terminal() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let handler = RecordingRenewalHandler::new([
        HandlerAction::Fail(ApplicationErrorKind::TooEarly),
        HandlerAction::Reply(RESPONSE.to_vec()),
        HandlerAction::Fail(ApplicationErrorKind::Conflict),
    ]);
    let running = spawn_server(
        &pki,
        verifier.clone(),
        Some(handler.clone()),
        &TransportLimits::default(),
    )
    .await;
    let client = HyperRunnerCertificateRenewalClient::new(
        &running.endpoint,
        &pki.client_tls(&pki.client),
        TransportLimits::default(),
    )
    .expect("renewal client");
    let prepared = PreparedCertificateRenewalRequest::new(REQUEST.to_vec()).expect("request");

    let not_due = client
        .exchange(&prepared, CancellationToken::new())
        .await
        .expect_err("certificate is not due yet");
    assert_eq!(
        not_due.kind(),
        ClientErrorKind::HttpStatus(StatusCode::TOO_EARLY)
    );
    assert_eq!(not_due.retry_class(), RetryClass::RetrySameRequest);
    let response = client
        .exchange(&prepared, CancellationToken::new())
        .await
        .expect("exact replay response");
    assert_eq!(
        format!("{response:?}"),
        "RunnerCertificateRenewalResponse([REDACTED])"
    );
    assert_eq!(response.into_body().as_slice(), RESPONSE);
    let conflict = client
        .exchange(&prepared, CancellationToken::new())
        .await
        .expect_err("terminal conflict");
    assert_eq!(conflict.retry_class(), RetryClass::Never);
    assert_eq!(handler.bodies(), vec![REQUEST.to_vec(); 3]);
    assert_eq!(verifier.calls(), 3);
    running.stop().await;
}

#[tokio::test]
async fn one_renewal_deadline_covers_body_read_and_database_handler_work() {
    let pki = TestPki::new();
    let handler = RecordingRenewalHandler::new([HandlerAction::Delay(
        Duration::from_millis(70),
        RESPONSE.to_vec(),
    )]);
    let limits = TransportLimits::default()
        .with_server_request_timeouts(
            Duration::from_millis(100),
            Duration::from_millis(500),
            Duration::from_millis(100),
            Duration::from_millis(200),
        )
        .expect("renewal deadlines");
    let running = spawn_server(
        &pki,
        RecordingVerifier::accepting(),
        Some(handler.clone()),
        &limits,
    )
    .await;
    let (mut sender, connection) =
        raw_h2_sender(running.address, pki.raw_client_config(Some(&pki.client)))
            .await
            .expect("authenticated h2 client");
    let (mut body_sender, body) = Channel::<Bytes, Infallible>::new(1);
    let request = raw_request(running.address, body.boxed_unsync(), REQUEST.len());
    let response = tokio::spawn(async move { sender.send_request(request).await });
    tokio::time::sleep(Duration::from_millis(70)).await;
    body_sender
        .send_data(Bytes::from_static(REQUEST))
        .await
        .expect("finish renewal body");
    drop(body_sender);
    let response = response
        .await
        .expect("response task")
        .expect("deadline response");
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(handler.calls(), 1);
    connection.abort();
    running.stop().await;
}
