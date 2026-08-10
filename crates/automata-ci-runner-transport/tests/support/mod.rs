#![allow(dead_code)]

use std::{
    convert::Infallible,
    fmt, future,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use automata_ci_auth::{
    machine::{
        AuthenticatedMachine, ExternalRunnerIdentity, MachineAuthenticationError,
        MachineAuthenticationEvidence, MachineAuthenticationFuture, MachineIdentityVerifier,
    },
    time::UnixTimestamp,
};
use automata_ci_core::{
    Architecture, JobIrVersion, JobIrVersionRange, OperatingSystem, OperationId,
    RunnerCapabilities, RunnerId, RunnerPlatform, RunnerSessionId, UnixMillis,
};
use automata_ci_protocol::{
    CommandCursor, ErrorMessage, LeaseRequest, MessageHeader, NegotiatedSession, NoWork,
    ProtocolLimits, RemoteErrorCode, RunnerHello, RunnerSlotOrdinal, RunnerToServer,
    SUPPORTED_PROTOCOL_RANGE, ServerHello, ServerTiming, ServerToRunner, SessionDisposition,
};
use automata_ci_runner_transport::{
    ApplicationError, ApplicationErrorKind, AuthenticatedRunnerRequest, ClientTlsConfig,
    HandlerFuture, HyperRunnerControlClient, PreparedRequest, RunnerControlHandler,
    RunnerControlServer, ServerTlsConfig, TransportLimits,
};
use bytes::Bytes;
use http::Uri;
use http_body_util::combinators::UnsyncBoxBody;
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, date_time_ymd,
};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    crypto::ring,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    server::WebPkiClientVerifier,
    version::TLS13,
};
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

pub type RawBody = UnsyncBoxBody<Bytes, Infallible>;
pub type RawSender = SendRequest<RawBody>;
type CalendarDate = (i32, u8, u8);
type Validity = (CalendarDate, CalendarDate);

pub struct Identity {
    certificates: Vec<Vec<u8>>,
    private_key: Vec<u8>,
}

impl Identity {
    pub fn certificate_chain(&self) -> Vec<CertificateDer<'static>> {
        self.certificates
            .iter()
            .cloned()
            .map(CertificateDer::from)
            .collect()
    }

    pub fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivatePkcs8KeyDer::from(self.private_key.clone()).into()
    }

    pub fn chain_bytes(&self) -> Vec<Vec<u8>> {
        self.certificates.clone()
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Identity")
            .field("certificate_count", &self.certificates.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct TestPki {
    root: Vec<u8>,
    pub server: Identity,
    pub client: Identity,
    pub wrong_purpose_client: Identity,
    pub expired_client: Identity,
    pub untrusted_client: Identity,
}

impl TestPki {
    pub fn new() -> Self {
        let root = certificate_authority("automata test root");
        let intermediate = intermediate_authority("automata runner intermediate", &root);
        let server = leaf_identity(
            "automata test server",
            vec!["127.0.0.1".to_owned(), "localhost".to_owned()],
            vec![ExtendedKeyUsagePurpose::ServerAuth],
            &intermediate,
            None,
        );
        let client = leaf_identity(
            "runner.test",
            Vec::new(),
            vec![ExtendedKeyUsagePurpose::ClientAuth],
            &intermediate,
            None,
        );
        let wrong_purpose_client = leaf_identity(
            "wrong-purpose.test",
            Vec::new(),
            vec![ExtendedKeyUsagePurpose::ServerAuth],
            &intermediate,
            None,
        );
        let expired_client = leaf_identity(
            "expired.test",
            Vec::new(),
            vec![ExtendedKeyUsagePurpose::ClientAuth],
            &intermediate,
            Some(((1999, 1, 1), (2000, 1, 1))),
        );

        let other_root = certificate_authority("untrusted test root");
        let untrusted_client = leaf_identity(
            "untrusted.test",
            Vec::new(),
            vec![ExtendedKeyUsagePurpose::ClientAuth],
            &other_root,
            None,
        );
        Self {
            root: root.der().as_ref().to_vec(),
            server,
            client,
            wrong_purpose_client,
            expired_client,
            untrusted_client,
        }
    }

    pub fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(self.root.clone()))
            .expect("generated root is valid");
        roots
    }

    pub fn server_tls(&self) -> ServerTlsConfig {
        ServerTlsConfig::new(
            self.roots(),
            self.server.certificate_chain(),
            self.server.private_key(),
        )
        .expect("generated server TLS config")
    }

    pub fn client_tls(&self, identity: &Identity) -> ClientTlsConfig {
        ClientTlsConfig::new(
            self.roots(),
            identity.certificate_chain(),
            identity.private_key(),
        )
        .expect("generated client TLS config")
    }

    pub fn raw_client_config(&self, identity: Option<&Identity>) -> ClientConfig {
        let provider = Arc::new(ring::default_provider());
        let builder = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&TLS13])
            .expect("TLS 1.3 provider")
            .with_root_certificates(self.roots());
        let mut config = match identity {
            Some(identity) => builder
                .with_client_auth_cert(identity.certificate_chain(), identity.private_key())
                .expect("generated client identity"),
            None => builder.with_no_client_auth(),
        };
        config.alpn_protocols = vec![b"h2".to_vec()];
        config
    }

    pub fn raw_server_config(&self) -> ServerConfig {
        let provider = Arc::new(ring::default_provider());
        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(self.roots()),
            Arc::clone(&provider),
        )
        .build()
        .expect("generated client roots");
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&TLS13])
            .expect("TLS 1.3 provider")
            .with_client_cert_verifier(verifier)
            .with_single_cert(self.server.certificate_chain(), self.server.private_key())
            .expect("generated server identity");
        config.alpn_protocols = vec![b"h2".to_vec()];
        config
    }
}

fn certificate_authority(name: &str) -> CertifiedIssuer<'static, KeyPair> {
    let key = KeyPair::generate().expect("test CA key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    CertifiedIssuer::self_signed(params, key).expect("self-signed test CA")
}

fn intermediate_authority(
    name: &str,
    issuer: &CertifiedIssuer<'_, KeyPair>,
) -> CertifiedIssuer<'static, KeyPair> {
    let key = KeyPair::generate().expect("test intermediate key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("intermediate params");
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    CertifiedIssuer::signed_by(params, key, issuer).expect("signed test intermediate")
}

fn leaf_identity(
    name: &str,
    subject_alt_names: Vec<String>,
    purposes: Vec<ExtendedKeyUsagePurpose>,
    issuer: &CertifiedIssuer<'_, KeyPair>,
    validity: Option<Validity>,
) -> Identity {
    let key = KeyPair::generate().expect("test leaf key");
    let mut params = CertificateParams::new(subject_alt_names).expect("leaf params");
    params.distinguished_name.push(DnType::CommonName, name);
    params.extended_key_usages = purposes;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    if let Some((before, after)) = validity {
        params.not_before = date_time_ymd(before.0, before.1, before.2);
        params.not_after = date_time_ymd(after.0, after.1, after.2);
    }
    let certificate = params.signed_by(&key, issuer).expect("signed test leaf");
    Identity {
        certificates: vec![
            certificate.der().as_ref().to_vec(),
            issuer.der().as_ref().to_vec(),
        ],
        private_key: key.serialize_der(),
    }
}

#[derive(Clone, Copy, Debug)]
pub enum VerifierOutcome {
    Accept,
    Reject(MachineAuthenticationError),
}

#[derive(Debug)]
pub struct RecordingVerifier {
    outcome: VerifierOutcome,
    calls: AtomicUsize,
    chains: Mutex<Vec<Vec<Vec<u8>>>>,
}

impl RecordingVerifier {
    pub fn accepting() -> Arc<Self> {
        Arc::new(Self {
            outcome: VerifierOutcome::Accept,
            calls: AtomicUsize::new(0),
            chains: Mutex::new(Vec::new()),
        })
    }

    pub fn rejecting(error: MachineAuthenticationError) -> Arc<Self> {
        Arc::new(Self {
            outcome: VerifierOutcome::Reject(error),
            calls: AtomicUsize::new(0),
            chains: Mutex::new(Vec::new()),
        })
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    pub fn chains(&self) -> Vec<Vec<Vec<u8>>> {
        self.chains.lock().expect("chain lock").clone()
    }
}

impl MachineIdentityVerifier for RecordingVerifier {
    fn authenticate<'a>(
        &'a self,
        evidence: &'a MachineAuthenticationEvidence,
    ) -> MachineAuthenticationFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.chains
            .lock()
            .expect("chain lock")
            .push(evidence.certificate_chain_der().to_vec());
        Box::pin(async move {
            match self.outcome {
                VerifierOutcome::Accept => AuthenticatedMachine::new(
                    ExternalRunnerIdentity::new("runner.test").expect("external identity"),
                    [0x5a; 32],
                    UnixTimestamp::from_seconds(1_700_000_000),
                    UnixTimestamp::from_seconds(4_000_000_000),
                )
                .map_err(|_| MachineAuthenticationError::Unavailable),
                VerifierOutcome::Reject(error) => Err(error),
            }
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub enum HandlerMode {
    Reply,
    ReplyStaleSession,
    Delay(Duration),
    WaitForCancellation,
    Fail(ApplicationErrorKind),
}

#[derive(Debug)]
pub struct TestHandler {
    mode: HandlerMode,
    calls: AtomicUsize,
    active: AtomicUsize,
    max_active: AtomicUsize,
    cancellation_seen: Arc<AtomicBool>,
    started: tokio::sync::Notify,
}

impl TestHandler {
    pub fn new(mode: HandlerMode) -> Arc<Self> {
        Arc::new(Self {
            mode,
            calls: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
            cancellation_seen: Arc::new(AtomicBool::new(false)),
            started: tokio::sync::Notify::new(),
        })
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    pub fn max_active(&self) -> usize {
        self.max_active.load(Ordering::SeqCst)
    }

    pub fn cancellation_seen(&self) -> bool {
        self.cancellation_seen.load(Ordering::SeqCst)
    }

    pub async fn wait_until_started(&self) {
        if self.calls() == 0 {
            self.started.notified().await;
        }
    }

    async fn run(
        &self,
        request: AuthenticatedRunnerRequest,
    ) -> Result<ServerToRunner, ApplicationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_active.fetch_max(active, Ordering::SeqCst);
        self.started.notify_waiters();
        let _active = ActiveRequest(&self.active);
        match self.mode {
            HandlerMode::Reply => reply_to(request.message().message()),
            HandlerMode::ReplyStaleSession => stale_session_reply_to(request.message().message()),
            HandlerMode::Delay(duration) => {
                tokio::time::sleep(duration).await;
                reply_to(request.message().message())
            }
            HandlerMode::WaitForCancellation => {
                let cancellation = request.cancellation_token();
                let seen = Arc::clone(&self.cancellation_seen);
                tokio::spawn(async move {
                    cancellation.cancelled().await;
                    seen.store(true, Ordering::SeqCst);
                });
                future::pending().await
            }
            HandlerMode::Fail(kind) => Err(ApplicationError::new(kind)),
        }
    }
}

struct ActiveRequest<'a>(&'a AtomicUsize);

impl Drop for ActiveRequest<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl RunnerControlHandler for TestHandler {
    fn handshake(&self, request: AuthenticatedRunnerRequest) -> HandlerFuture<'_> {
        Box::pin(self.run(request))
    }

    fn sync(&self, request: AuthenticatedRunnerRequest) -> HandlerFuture<'_> {
        Box::pin(self.run(request))
    }
}

fn stale_session_reply_to(message: &RunnerToServer) -> Result<ServerToRunner, ApplicationError> {
    let RunnerToServer::LeaseRequest(request) = message else {
        return Err(ApplicationError::new(ApplicationErrorKind::Internal));
    };
    let header = request.header();
    Ok(ServerToRunner::Error(ErrorMessage::new(
        MessageHeader::reply(
            header.protocol_version(),
            header.session_id(),
            OperationId::new(),
            header.operation_id(),
        ),
        RemoteErrorCode::StaleSession,
        "runner session is stale",
        false,
    )))
}

fn reply_to(message: &RunnerToServer) -> Result<ServerToRunner, ApplicationError> {
    match message {
        RunnerToServer::Hello(hello) => Ok(ServerToRunner::Hello(ServerHello::new(
            OperationId::new(),
            hello.operation_id(),
            NegotiatedSession::new(
                SUPPORTED_PROTOCOL_RANGE.max(),
                JobIrVersion::current(),
                RunnerSessionId::new(),
                SessionDisposition::Opened,
                CommandCursor::initial(),
            ),
            ServerTiming::new(UnixMillis::new(1_700_000_000_000), 5_000, 30_000),
        ))),
        RunnerToServer::LeaseRequest(request) => {
            let header = request.header();
            Ok(ServerToRunner::NoWork(NoWork::new(
                MessageHeader::reply(
                    header.protocol_version(),
                    header.session_id(),
                    OperationId::new(),
                    header.operation_id(),
                ),
                25,
            )))
        }
        _ => Err(ApplicationError::new(ApplicationErrorKind::Internal)),
    }
}

pub fn hello_request() -> PreparedRequest {
    PreparedRequest::handshake(
        RunnerHello::new(
            OperationId::new(),
            SUPPORTED_PROTOCOL_RANGE,
            JobIrVersionRange::current(),
            RunnerCapabilities::new(
                RunnerId::new(),
                RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
            ),
            UnixMillis::new(1_700_000_000_000),
        ),
        &ProtocolLimits::default(),
    )
    .expect("valid hello")
}

pub fn poll_request() -> PreparedRequest {
    let session_id = RunnerSessionId::new();
    let header = MessageHeader::request(
        SUPPORTED_PROTOCOL_RANGE.max(),
        session_id,
        OperationId::new(),
    );
    PreparedRequest::for_session(
        RunnerToServer::LeaseRequest(LeaseRequest::first(
            header,
            RunnerSlotOrdinal::new(1).expect("slot"),
        )),
        NegotiatedSession::new(
            SUPPORTED_PROTOCOL_RANGE.max(),
            JobIrVersion::current(),
            session_id,
            SessionDisposition::Opened,
            CommandCursor::initial(),
        ),
        &ProtocolLimits::default(),
    )
    .expect("valid poll")
}

pub struct RunningServer {
    pub address: SocketAddr,
    pub endpoint: Uri,
    shutdown: CancellationToken,
    task: JoinHandle<Result<(), automata_ci_runner_transport::ServeError>>,
}

impl RunningServer {
    pub async fn stop(self) {
        self.shutdown.cancel();
        self.task
            .await
            .expect("server task")
            .expect("server serve result");
    }
}

pub async fn spawn_server(
    pki: &TestPki,
    verifier: Arc<dyn MachineIdentityVerifier>,
    handler: Arc<dyn RunnerControlHandler>,
    limits: &TransportLimits,
) -> RunningServer {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test server");
    let address = listener.local_addr().expect("test listener address");
    let tls = pki.server_tls();
    let server = RunnerControlServer::new(
        listener,
        &tls,
        verifier,
        handler,
        ProtocolLimits::default(),
        *limits,
    )
    .expect("runner control server");
    let endpoint: Uri = format!("https://{address}/")
        .parse()
        .expect("test endpoint");
    let shutdown = CancellationToken::new();
    let serve_shutdown = shutdown.clone();
    let task = tokio::spawn(server.serve(serve_shutdown));
    RunningServer {
        address,
        endpoint,
        shutdown,
        task,
    }
}

pub fn client(
    running: &RunningServer,
    pki: &TestPki,
    limits: &TransportLimits,
) -> HyperRunnerControlClient {
    HyperRunnerControlClient::new(
        &running.endpoint,
        &pki.client_tls(&pki.client),
        ProtocolLimits::default(),
        *limits,
    )
    .expect("runner client")
}

pub async fn raw_h2_sender(
    address: SocketAddr,
    config: ClientConfig,
) -> Result<(RawSender, JoinHandle<()>), ()> {
    let tcp = TcpStream::connect(address).await.map_err(|_| ())?;
    let server_name = ServerName::try_from("127.0.0.1".to_owned()).map_err(|_| ())?;
    let tls = TlsConnector::from(Arc::new(config))
        .connect(server_name, tcp)
        .await
        .map_err(|_| ())?;
    if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
        return Err(());
    }
    let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
    builder.timer(TokioTimer::new());
    let (sender, connection) = builder
        .handshake::<_, RawBody>(TokioIo::new(tls))
        .await
        .map_err(|_| ())?;
    let task = tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok((sender, task))
}
