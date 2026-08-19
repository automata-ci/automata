use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use automata_ci_auth::{
    secret::SecretString,
    time::{Clock, UnixTimestamp},
};
use automata_ci_core::PermissionLevel;
use automata_ci_provider::{ProviderPermission, ProviderPermissionSet};
use automata_ci_scm::credential::ProviderResourceId;
use automata_ci_store::GithubRepositoryName;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::{JoinHandle, JoinSet},
};
use url::Url;

use super::{GithubAppCredentialBroker, github_http_client_builder};
use crate::{
    GithubAppCredentialConfig, GithubAppHttpLimits, GithubInstallationId,
    GithubInstallationTokenIndeterminateReason, GithubInstallationTokenMintOutcome,
    GithubInstallationTokenRequest,
};

const CLIENT_CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FRAME_HEADER_BYTES: usize = 9;
const FRAME_HEADERS: u8 = 1;
const FRAME_RST_STREAM: u8 = 3;
const FRAME_SETTINGS: u8 = 4;
const FRAME_PING: u8 = 6;
const FLAG_ACK: u8 = 1;
const REFUSED_STREAM: u32 = 7;
const MAX_FIXTURE_FRAME_BYTES: usize = 64 * 1024;
const NOW: u64 = 1_800_000_000;
const REPOSITORY_ID: u64 = 81_234_567;
const INSTALLATION_ID: u64 = 998_877;
const PUBLISHED_TEST_KEY_PKCS1_DER: &[u8] =
    include_bytes!("../fixtures/rsa2048-test-key.pkcs1.der");

#[derive(Clone, Copy, Debug)]
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> UnixTimestamp {
        UnixTimestamp::from_seconds(NOW)
    }
}

#[derive(Debug)]
struct ProtocolNackServer {
    origin: Url,
    connections: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl ProtocolNackServer {
    async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind protocol-NACK fixture");
        let address = listener.local_addr().expect("protocol-NACK address");
        let connections = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(run_server(
            listener,
            Arc::clone(&connections),
            Arc::clone(&requests),
            receiver,
        ));
        Self {
            origin: Url::parse(&format!("http://{address}/api/v3/")).expect("protocol-NACK origin"),
            connections,
            requests,
            shutdown: Some(shutdown),
            task,
        }
    }

    async fn stop(mut self) -> (usize, usize) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.await.expect("join protocol-NACK fixture");
        (
            self.connections.load(Ordering::Relaxed),
            self.requests.load(Ordering::Relaxed),
        )
    }
}

async fn run_server(
    listener: TcpListener,
    connections: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
    mut shutdown: oneshot::Receiver<()>,
) {
    let mut connections_in_flight = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted.expect("accept protocol-NACK connection");
                connections.fetch_add(1, Ordering::Relaxed);
                let requests = Arc::clone(&requests);
                connections_in_flight.spawn(async move {
                    refuse_every_request(stream, &requests).await;
                });
            }
        }
    }
    connections_in_flight.abort_all();
    while connections_in_flight.join_next().await.is_some() {}
}

async fn refuse_every_request(mut stream: TcpStream, requests: &AtomicUsize) {
    let mut preface = [0_u8; CLIENT_CONNECTION_PREFACE.len()];
    stream
        .read_exact(&mut preface)
        .await
        .expect("read HTTP/2 client preface");
    assert_eq!(preface, CLIENT_CONNECTION_PREFACE);
    write_frame(&mut stream, FRAME_SETTINGS, 0, 0, &[]).await;

    while let Some(frame) = read_frame(&mut stream).await {
        match frame.kind {
            FRAME_SETTINGS if frame.flags & FLAG_ACK == 0 => {
                write_frame(&mut stream, FRAME_SETTINGS, FLAG_ACK, 0, &[]).await;
            }
            FRAME_PING if frame.flags & FLAG_ACK == 0 => {
                write_frame(&mut stream, FRAME_PING, FLAG_ACK, 0, &frame.payload).await;
            }
            FRAME_HEADERS => {
                requests.fetch_add(1, Ordering::Relaxed);
                write_frame(
                    &mut stream,
                    FRAME_RST_STREAM,
                    0,
                    frame.stream_id,
                    &REFUSED_STREAM.to_be_bytes(),
                )
                .await;
            }
            _ => {}
        }
    }
}

struct Frame {
    kind: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

async fn read_frame(stream: &mut TcpStream) -> Option<Frame> {
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    if stream.read_exact(&mut header).await.is_err() {
        return None;
    }
    let length =
        usize::from(header[0]) << 16 | usize::from(header[1]) << 8 | usize::from(header[2]);
    assert!(
        length <= MAX_FIXTURE_FRAME_BYTES,
        "fixture frame is bounded"
    );
    let mut payload = vec![0_u8; length];
    stream
        .read_exact(&mut payload)
        .await
        .expect("read HTTP/2 frame payload");
    Some(Frame {
        kind: header[3],
        flags: header[4],
        stream_id: u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff,
        payload,
    })
}

async fn write_frame(stream: &mut TcpStream, kind: u8, flags: u8, stream_id: u32, payload: &[u8]) {
    let length = u32::try_from(payload.len()).expect("fixture payload length");
    assert!(length <= 0x00ff_ffff, "fixture frame length");
    let length_bytes = length.to_be_bytes();
    let stream_bytes = stream_id.to_be_bytes();
    let header = [
        length_bytes[1],
        length_bytes[2],
        length_bytes[3],
        kind,
        flags,
        stream_bytes[0] & 0x7f,
        stream_bytes[1],
        stream_bytes[2],
        stream_bytes[3],
    ];
    stream
        .write_all(&header)
        .await
        .expect("write HTTP/2 frame header");
    stream
        .write_all(payload)
        .await
        .expect("write HTTP/2 frame payload");
    stream.flush().await.expect("flush HTTP/2 frame");
}

fn private_key() -> SecretString {
    let pem = pem_rfc7468::encode_string(
        "RSA PRIVATE KEY",
        pem_rfc7468::LineEnding::LF,
        PUBLISHED_TEST_KEY_PKCS1_DER,
    )
    .expect("encode published RSA test fixture");
    SecretString::new(pem).expect("published RSA test fixture is non-empty")
}

fn request() -> GithubInstallationTokenRequest {
    GithubInstallationTokenRequest::new(
        REPOSITORY_ID,
        GithubRepositoryName::new("automata-ci/automata").expect("repository name"),
        ProviderPermissionSet::new([
            ProviderPermission::new("contents", PermissionLevel::Read).expect("permission")
        ])
        .expect("permission set"),
        300_000,
    )
    .expect("installation-token request")
}

#[tokio::test]
async fn mint_does_not_replay_a_protocol_nack() {
    let server = ProtocolNackServer::spawn().await;
    let limits =
        GithubAppHttpLimits::new(1_024, Duration::from_millis(100), Duration::from_secs(2))
            .expect("HTTP limits");
    let config = GithubAppCredentialConfig::new_for_loopback_emulator(
        server.origin.clone(),
        ProviderResourceId::new("Iv1.automata-test").expect("App issuer"),
        GithubInstallationId::new(INSTALLATION_ID).expect("installation ID"),
        "automata-ci-protocol-nack-test/0.1.0",
        limits,
    )
    .expect("loopback config");
    let client = github_http_client_builder(&config)
        .http2_prior_knowledge()
        .build()
        .expect("HTTP/2 fixture client");
    let mut broker =
        GithubAppCredentialBroker::with_clock(config, &private_key(), Arc::new(FixedClock))
            .expect("credential broker");
    broker.client = client;

    let outcome = broker.mint_once(&request()).await;
    assert!(matches!(
        outcome,
        GithubInstallationTokenMintOutcome::Indeterminate(indeterminate)
            if indeterminate.reason()
                == GithubInstallationTokenIndeterminateReason::Transport
    ));
    drop(broker);
    let (connections, requests) = server.stop().await;
    assert_eq!(connections, 1, "the NACK must not open a retry connection");
    assert_eq!(requests, 1, "the side-effectful POST must run exactly once");
}
