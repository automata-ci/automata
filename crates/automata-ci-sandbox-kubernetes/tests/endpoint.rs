use std::{
    collections::{BTreeMap, VecDeque},
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use automata_ci_execution::{
    Cancellation, CopyFromRequest, CopyToRequest, EnvironmentName, EnvironmentValue,
    EnvironmentVariable, ExecutionArgv, ExecutionCommand, ExecutionEndpoint, ExecutionEnvironment,
    ExecutionError, ExecutionErrorKind, ExecutionOutputStream, ExecutionSignal, ExecutionStage,
    ExecutionTermination, ImmutableImage, MAX_EXECUTION_OUTPUT_RECORD_BYTES, NeverCancelled,
    OperationId, ProviderId, SandboxCapability, SandboxHandle, SandboxProvider, SignalRequest,
    TargetPath, WaitRequest,
};
use automata_ci_sandbox_guest::{
    GUEST_PROTOCOL_VERSION, GuestRejection, GuestRequest, GuestResponse, decode_frame, encode_frame,
};
use automata_ci_sandbox_kubernetes::{
    KUBERNETES_PROVIDER_ID, KubernetesSandboxConfig, KubernetesSandboxProvider,
    VerifiedNetworkIsolation,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use futures::{SinkExt as _, StreamExt as _};
use http::{HeaderValue, Uri};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{
        Message,
        handshake::server::{
            ErrorResponse, Request as WebSocketRequest, Response as WebSocketResponse,
        },
    },
};

const NAMESPACE: &str = "automata-runners";
const HANDLE: &str = "a-endpoint-contract-7";

#[derive(Clone, Debug)]
struct TestCancellation(Arc<AtomicBool>);

impl TestCancellation {
    fn pending() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    fn cancelled() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }
}

impl Cancellation for TestCancellation {
    fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

struct ServerReply {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    cancel_after_response: Option<Arc<AtomicBool>>,
}

impl ServerReply {
    fn guest(response: &GuestResponse) -> Self {
        Self {
            stdout: encode_frame(response).expect("encode guest response"),
            stderr: Vec::new(),
            cancel_after_response: None,
        }
    }

    fn raw(stdout: impl Into<Vec<u8>>) -> Self {
        Self {
            stdout: stdout.into(),
            stderr: Vec::new(),
            cancel_after_response: None,
        }
    }

    fn with_stderr(mut self, stderr: impl Into<Vec<u8>>) -> Self {
        self.stderr = stderr.into();
        self
    }

    fn cancelling(mut self, cancellation: &TestCancellation) -> Self {
        self.cancel_after_response = Some(Arc::clone(&cancellation.0));
        self
    }
}

#[derive(Default)]
struct ServerState {
    replies: VecDeque<ServerReply>,
    guest_requests: Vec<GuestRequest>,
    websocket_uris: Vec<String>,
    plain_uris: Vec<String>,
    stale_pod_identity: bool,
    failure: Option<String>,
}

struct FakeExecServer {
    address: std::net::SocketAddr,
    state: Arc<Mutex<ServerState>>,
    task: JoinHandle<()>,
}

struct CaptureWebSocketUri(Arc<Mutex<ServerState>>);

impl tokio_tungstenite::tungstenite::handshake::server::Callback for CaptureWebSocketUri {
    fn on_request(
        self,
        request: &WebSocketRequest,
        mut response: WebSocketResponse,
    ) -> Result<WebSocketResponse, ErrorResponse> {
        self.0
            .lock()
            .expect("server state lock")
            .websocket_uris
            .push(request.uri().to_string());
        response.headers_mut().insert(
            http::header::SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static("v5.channel.k8s.io"),
        );
        Ok(response)
    }
}

impl FakeExecServer {
    async fn start(replies: impl IntoIterator<Item = ServerReply>) -> Self {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind fake Kubernetes server");
        let address = listener.local_addr().expect("fake server address");
        let state = Arc::new(Mutex::new(ServerState {
            replies: replies.into_iter().collect(),
            ..ServerState::default()
        }));
        let server_state = Arc::clone(&state);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let connection_state = Arc::clone(&server_state);
                tokio::spawn(async move {
                    if let Err(error) =
                        handle_connection(stream, Arc::clone(&connection_state)).await
                    {
                        connection_state.lock().expect("server state lock").failure =
                            Some(error.to_string());
                    }
                });
            }
        });
        Self {
            address,
            state,
            task,
        }
    }

    fn client(&self) -> kube::Client {
        let uri: Uri = format!("http://{}", self.address)
            .parse()
            .expect("fake server URI");
        let mut config = kube::Config::new(uri);
        config.default_namespace = NAMESPACE.into();
        config.default_retry = false;
        config.connect_timeout = Some(Duration::from_secs(2));
        config.read_timeout = Some(Duration::from_secs(2));
        config.write_timeout = Some(Duration::from_secs(2));
        kube::Client::try_from(config).expect("fake Kubernetes client")
    }

    fn guest_requests(&self) -> Vec<GuestRequest> {
        self.state
            .lock()
            .expect("server state lock")
            .guest_requests
            .clone()
    }

    fn websocket_uris(&self) -> Vec<String> {
        self.state
            .lock()
            .expect("server state lock")
            .websocket_uris
            .clone()
    }

    fn plain_request_count(&self) -> usize {
        self.state
            .lock()
            .expect("server state lock")
            .plain_uris
            .len()
    }

    fn make_pod_identity_stale(&self) {
        self.state
            .lock()
            .expect("server state lock")
            .stale_pod_identity = true;
    }

    fn assert_finished(&self) {
        let state = self.state.lock().expect("server state lock");
        assert_eq!(state.failure, None, "fake exec server failed");
        assert!(state.replies.is_empty(), "unused guest replies remain");
    }
}

impl Drop for FakeExecServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    state: Arc<Mutex<ServerState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut preview = [0_u8; 8 * 1024];
    let request_head = loop {
        let bytes = stream.peek(&mut preview).await?;
        if bytes == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "empty HTTP request").into());
        }
        if preview[..bytes]
            .windows(4)
            .any(|window| window == b"\r\n\r\n")
        {
            break String::from_utf8_lossy(&preview[..bytes]).into_owned();
        }
        tokio::task::yield_now().await;
    };
    if request_head
        .to_ascii_lowercase()
        .contains("upgrade: websocket")
    {
        handle_websocket(stream, state).await
    } else {
        handle_plain_http(&mut stream, state).await
    }
}

async fn handle_plain_http(
    stream: &mut TcpStream,
    state: Arc<Mutex<ServerState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut request = Vec::new();
    let mut byte = [0_u8; 1];
    while !request.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await?;
        request.push(byte[0]);
        if request.len() > 8 * 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "oversized HTTP head").into());
        }
    }
    let request = String::from_utf8(request)?;
    let uri = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request URI"))?;
    let stale_pod_identity = {
        let mut state = state.lock().expect("server state lock");
        state.plain_uris.push(uri.into());
        state.stale_pod_identity
    };
    let body =
        serde_json::to_vec(&owned_running_pod(stale_pod_identity)).expect("serialize owned Pod");
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn handle_websocket(
    stream: TcpStream,
    state: Arc<Mutex<ServerState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut websocket = accept_hdr_async(stream, CaptureWebSocketUri(Arc::clone(&state))).await?;
    let mut frame = Vec::new();
    while let Some(message) = websocket.next().await {
        match message? {
            Message::Binary(bytes) if bytes.as_ref() == [255, 0] => break,
            Message::Binary(bytes) if bytes.first() == Some(&0) => {
                frame.extend_from_slice(&bytes[1..]);
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
    let request = decode_frame::<GuestRequest>(&frame)?;
    let reply = {
        let mut state = state.lock().expect("server state lock");
        state.guest_requests.push(request);
        state
            .replies
            .pop_front()
            .ok_or_else(|| io::Error::other("unexpected exec request"))?
    };
    if let Some(cancellation) = reply.cancel_after_response {
        cancellation.store(true, Ordering::SeqCst);
    }
    if !reply.stdout.is_empty() {
        let mut stdout = Vec::with_capacity(reply.stdout.len() + 1);
        stdout.push(1);
        stdout.extend_from_slice(&reply.stdout);
        websocket.send(Message::Binary(stdout.into())).await?;
    }
    if !reply.stderr.is_empty() {
        let mut stderr = Vec::with_capacity(reply.stderr.len() + 1);
        stderr.push(2);
        stderr.extend_from_slice(&reply.stderr);
        websocket.send(Message::Binary(stderr.into())).await?;
    }
    let mut status = vec![3];
    status.extend_from_slice(br#"{"apiVersion":"v1","kind":"Status","status":"Success"}"#);
    websocket.send(Message::Binary(status.into())).await?;
    websocket.close(None).await?;
    Ok(())
}

fn owned_running_pod(stale_identity: bool) -> serde_json::Value {
    let mut pod = json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": HANDLE,
            "namespace": NAMESPACE,
            "uid": "endpoint-pod-uid",
            "labels": {
                "ci.automata.dev/managed": "true",
                "ci.automata.dev/sandbox": HANDLE
            }
        },
        "status": {
            "phase": "Running",
            "containerStatuses": [{
                "name": "job",
                "ready": true,
                "restartCount": 0,
                "image": "immutable",
                "imageID": "immutable-id"
            }]
        }
    });
    if stale_identity {
        pod["metadata"]["uid"] = json!("replacement-pod-uid");
    }
    pod
}

fn immutable_image() -> ImmutableImage {
    ImmutableImage::new(format!("registry.example/guest@sha256:{}", "01".repeat(32)))
        .expect("immutable image")
}

fn attach_endpoint(server: &FakeExecServer) -> Box<dyn ExecutionEndpoint> {
    let config =
        KubernetesSandboxConfig::new(NAMESPACE, immutable_image(), VerifiedNetworkIsolation)
            .expect("Kubernetes config")
            .with_timeouts(Duration::from_secs(2), Duration::from_secs(2))
            .expect("timeouts");
    let provider =
        KubernetesSandboxProvider::new(server.client(), config).expect("Kubernetes provider");
    let handle = SandboxHandle::new(
        ProviderId::new(KUBERNETES_PROVIDER_ID).expect("provider id"),
        HANDLE,
    )
    .expect("sandbox handle");
    provider
        .attach(&handle, &NeverCancelled)
        .expect("attach endpoint")
}

fn execution_command(output_limit: usize) -> ExecutionCommand {
    let environment = ExecutionEnvironment::new(vec![
        EnvironmentVariable::new(
            EnvironmentName::new("PUBLIC_VALUE").expect("environment name"),
            EnvironmentValue::new("visible").expect("environment value"),
        ),
        EnvironmentVariable::secret(
            EnvironmentName::new("SECRET_TOKEN").expect("environment name"),
            EnvironmentValue::new("sensitive-value").expect("environment value"),
        ),
    ])
    .expect("execution environment");
    ExecutionCommand::new(
        OperationId::new(),
        ExecutionArgv::new(
            TargetPath::posix("/usr/bin/example").expect("program"),
            vec!["literal argument".into(), "$(never-a-shell)".into()],
        )
        .expect("argv"),
        TargetPath::posix("/workspace/subdir").expect("working directory"),
        environment,
        Duration::from_millis(1_250),
        output_limit,
    )
    .expect("execution command")
}

fn guest_response(value: serde_json::Value) -> GuestResponse {
    serde_json::from_value(value).expect("guest response fixture")
}

fn assert_execution_error(error: ExecutionError, kind: ExecutionErrorKind, stage: ExecutionStage) {
    assert_eq!(error.kind(), kind);
    assert_eq!(error.stage(), stage);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_and_copy_round_trips_preserve_exact_guest_requests_and_results() {
    let exec_response = guest_response(json!({
        "result": "exec",
        "protocol": GUEST_PROTOCOL_VERSION,
        "termination": {"kind": "exited", "code": 17},
        "records": [
            {"stream": "stdout", "data_base64": BASE64.encode(b"out"), "end_of_stream": false},
            {"stream": "stderr", "data_base64": BASE64.encode(b"err"), "end_of_stream": false},
            {"stream": "stdout", "data_base64": "", "end_of_stream": true},
            {"stream": "stderr", "data_base64": "", "end_of_stream": true}
        ],
        "truncated": false
    }));
    let server = FakeExecServer::start([
        ServerReply::guest(&exec_response),
        ServerReply::guest(&GuestResponse::WriteFile {
            protocol: GUEST_PROTOCOL_VERSION,
        }),
        ServerReply::guest(&GuestResponse::ReadFile {
            protocol: GUEST_PROTOCOL_VERSION,
            content_base64: BASE64.encode(b"copied bytes"),
        }),
    ])
    .await;
    let endpoint = attach_endpoint(&server);
    let command = execution_command(1_024);
    let copy_to = CopyToRequest::new(
        OperationId::new(),
        TargetPath::posix("/workspace/input.bin").expect("copy target"),
        vec![0, 1, 2, 255],
    )
    .expect("copy-to request");
    let copy_from = CopyFromRequest::new(
        OperationId::new(),
        TargetPath::posix("/workspace/output.bin").expect("copy source"),
        64,
    )
    .expect("copy-from request");

    let output = endpoint
        .exec(&command, &NeverCancelled)
        .expect("execute command");
    endpoint
        .copy_to(&copy_to, &NeverCancelled)
        .expect("copy into sandbox");
    let copied = endpoint
        .copy_from(&copy_from, &NeverCancelled)
        .expect("copy from sandbox");

    assert_eq!(output.termination(), ExecutionTermination::Exited(17));
    assert_eq!(output.stdout(), b"out");
    assert_eq!(output.stderr(), b"err");
    assert_eq!(output.records().len(), 4);
    assert_eq!(output.records()[0].stream(), ExecutionOutputStream::Stdout);
    assert_eq!(output.records()[1].stream(), ExecutionOutputStream::Stderr);
    assert_eq!(copied, b"copied bytes");
    let requests = server.guest_requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests[0],
        GuestRequest::Exec {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: command.operation_id().to_string(),
            program: "/usr/bin/example".into(),
            arguments: vec!["literal argument".into(), "$(never-a-shell)".into()],
            environment: BTreeMap::from([
                ("PUBLIC_VALUE".into(), "visible".into()),
                ("SECRET_TOKEN".into(), "sensitive-value".into()),
            ]),
            working_directory: "/workspace/subdir".into(),
            timeout_millis: 1_250,
            output_limit: 1_024,
        }
    );
    assert_eq!(
        requests[1],
        GuestRequest::WriteFile {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: copy_to.operation_id().to_string(),
            path: "/workspace/input.bin".into(),
            content_base64: BASE64.encode([0, 1, 2, 255]),
        }
    );
    assert_eq!(
        requests[2],
        GuestRequest::ReadFile {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: copy_from.operation_id().to_string(),
            path: "/workspace/output.bin".into(),
            byte_limit: 64,
        }
    );
    assert!(server.websocket_uris().iter().all(|uri| {
        uri.starts_with(&format!(
            "/api/v1/namespaces/{NAMESPACE}/pods/{HANDLE}/exec?"
        )) && uri.contains("container=job")
            && uri.contains("command=%2Fautomata%2Fbin%2Fautomata-ci-sandbox-guest")
            && !uri.contains("sensitive-value")
            && !uri.contains("literal%20argument")
    }));
    server.assert_finished();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protocol_frames_and_copy_payloads_fail_closed() {
    let replies = [
        ServerReply::guest(&GuestResponse::WriteFile { protocol: 999 }),
        ServerReply::raw(b"malformed-frame".to_vec()),
        ServerReply::guest(&GuestResponse::ReadFile {
            protocol: GUEST_PROTOCOL_VERSION,
            content_base64: "not-base64!".into(),
        }),
        ServerReply::guest(&GuestResponse::ReadFile {
            protocol: GUEST_PROTOCOL_VERSION,
            content_base64: BASE64.encode(b"five"),
        }),
        ServerReply::guest(&GuestResponse::WriteFile {
            protocol: GUEST_PROTOCOL_VERSION,
        }),
    ];
    let server = FakeExecServer::start(replies).await;
    let endpoint = attach_endpoint(&server);
    let copy_to = CopyToRequest::new(
        OperationId::new(),
        TargetPath::posix("/workspace/file").expect("path"),
        vec![1],
    )
    .expect("copy request");

    assert_execution_error(
        endpoint
            .copy_to(&copy_to, &NeverCancelled)
            .expect_err("wrong protocol must reject"),
        ExecutionErrorKind::BackendRejected,
        ExecutionStage::CopyTo,
    );
    assert_execution_error(
        endpoint
            .copy_to(&copy_to, &NeverCancelled)
            .expect_err("malformed frame must reject"),
        ExecutionErrorKind::BackendRejected,
        ExecutionStage::CopyTo,
    );
    for (limit, expected) in [
        (16, ExecutionErrorKind::BackendRejected),
        (3, ExecutionErrorKind::OutputLimitExceeded),
    ] {
        let request = CopyFromRequest::new(
            OperationId::new(),
            TargetPath::posix("/workspace/file").expect("path"),
            limit,
        )
        .expect("copy request");
        assert_execution_error(
            endpoint
                .copy_from(&request, &NeverCancelled)
                .expect_err("malformed or oversized copy response"),
            expected,
            ExecutionStage::CopyFrom,
        );
    }
    let wrong_variant = CopyFromRequest::new(
        OperationId::new(),
        TargetPath::posix("/workspace/file").expect("path"),
        16,
    )
    .expect("copy request");
    assert_execution_error(
        endpoint
            .copy_from(&wrong_variant, &NeverCancelled)
            .expect_err("wrong copy response variant"),
        ExecutionErrorKind::BackendRejected,
        ExecutionStage::CopyFrom,
    );
    server.assert_finished();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_exec_response_shapes_fail_closed() {
    let invalid_record = guest_response(json!({
        "result": "exec",
        "protocol": GUEST_PROTOCOL_VERSION,
        "termination": {"kind": "signalled"},
        "records": [{
            "stream": "stdout",
            "data_base64": "not-base64!",
            "end_of_stream": false
        }],
        "truncated": true
    }));
    let empty_record = guest_response(json!({
        "result": "exec",
        "protocol": GUEST_PROTOCOL_VERSION,
        "termination": {"kind": "signalled"},
        "records": [{"stream": "stdout", "data_base64": "", "end_of_stream": false}],
        "truncated": true
    }));
    let invalid_sequence = guest_response(json!({
        "result": "exec",
        "protocol": GUEST_PROTOCOL_VERSION,
        "termination": {"kind": "exited", "code": 0},
        "records": [
            {"stream": "stdout", "data_base64": "", "end_of_stream": true},
            {"stream": "stdout", "data_base64": "", "end_of_stream": true},
            {"stream": "stderr", "data_base64": "", "end_of_stream": true}
        ],
        "truncated": false
    }));
    let replies = [
        ServerReply::guest(&GuestResponse::Rejected {
            protocol: GUEST_PROTOCOL_VERSION,
            kind: automata_ci_sandbox_guest::GuestRejection::InvalidRequest,
        }),
        ServerReply::guest(&GuestResponse::WriteFile {
            protocol: GUEST_PROTOCOL_VERSION,
        }),
        ServerReply::guest(&invalid_record),
        ServerReply::guest(&empty_record),
        ServerReply::guest(&invalid_sequence),
    ];
    let server = FakeExecServer::start(replies).await;
    let endpoint = attach_endpoint(&server);
    for (limit, expected, message) in [
        (
            64,
            ExecutionErrorKind::InvalidEnvironment,
            "invalid request rejection",
        ),
        (64, ExecutionErrorKind::BackendRejected, "wrong variant"),
        (
            64,
            ExecutionErrorKind::BackendRejected,
            "invalid base64 record",
        ),
        (64, ExecutionErrorKind::BackendRejected, "empty data record"),
        (
            64,
            ExecutionErrorKind::BackendRejected,
            "invalid record sequence",
        ),
    ] {
        assert_execution_error(
            endpoint
                .exec(&execution_command(limit), &NeverCancelled)
                .expect_err(message),
            expected,
            ExecutionStage::Exec,
        );
    }
    server.assert_finished();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operational_guest_rejections_remain_bounded_backend_failures() {
    let rejections = [
        GuestRejection::UnsupportedProtocol,
        GuestRejection::OperationFailed,
        GuestRejection::OperationConflict,
    ];
    let server = FakeExecServer::start(rejections.map(|kind| {
        ServerReply::guest(&GuestResponse::Rejected {
            protocol: GUEST_PROTOCOL_VERSION,
            kind,
        })
    }))
    .await;
    let endpoint = attach_endpoint(&server);

    for _ in rejections {
        assert_execution_error(
            endpoint
                .exec(&execution_command(64), &NeverCancelled)
                .expect_err("operational guest rejection"),
            ExecutionErrorKind::BackendRejected,
            ExecutionStage::Exec,
        );
    }
    server.assert_finished();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requested_exec_limit_and_transport_stderr_fail_closed() {
    let oversized_record = guest_response(json!({
        "result": "exec",
        "protocol": GUEST_PROTOCOL_VERSION,
        "termination": {"kind": "signalled"},
        "records": [{
            "stream": "stdout",
            "data_base64": BASE64.encode(vec![7; MAX_EXECUTION_OUTPUT_RECORD_BYTES + 1]),
            "end_of_stream": false
        }],
        "truncated": true
    }));
    let over_limit = guest_response(json!({
        "result": "exec",
        "protocol": GUEST_PROTOCOL_VERSION,
        "termination": {"kind": "timed_out"},
        "records": [
            {"stream": "stdout", "data_base64": BASE64.encode(b"too many"), "end_of_stream": false},
            {"stream": "stdout", "data_base64": "", "end_of_stream": true},
            {"stream": "stderr", "data_base64": "", "end_of_stream": true}
        ],
        "truncated": false
    }));
    let server = FakeExecServer::start([
        ServerReply::guest(&oversized_record),
        ServerReply::guest(&over_limit),
        ServerReply::guest(&GuestResponse::WriteFile {
            protocol: GUEST_PROTOCOL_VERSION,
        })
        .with_stderr("unexpected remote diagnostic"),
    ])
    .await;
    let endpoint = attach_endpoint(&server);
    assert_execution_error(
        endpoint
            .exec(&execution_command(1024 * 1024), &NeverCancelled)
            .expect_err("one guest record must respect its hard bound"),
        ExecutionErrorKind::OutputLimitExceeded,
        ExecutionStage::Exec,
    );
    assert_execution_error(
        endpoint
            .exec(&execution_command(3), &NeverCancelled)
            .expect_err("guest must not exceed the caller output limit"),
        ExecutionErrorKind::OutputLimitExceeded,
        ExecutionStage::Exec,
    );
    let copy_to = CopyToRequest::new(
        OperationId::new(),
        TargetPath::posix("/workspace/file").expect("path"),
        vec![1],
    )
    .expect("copy request");
    assert_execution_error(
        endpoint
            .copy_to(&copy_to, &NeverCancelled)
            .expect_err("stderr must fail closed"),
        ExecutionErrorKind::BackendRejected,
        ExecutionStage::CopyTo,
    );
    server.assert_finished();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_exchange_revalidates_pod_identity_and_observes_late_cancellation() {
    let server = FakeExecServer::start([]).await;
    let endpoint = attach_endpoint(&server);
    server.make_pod_identity_stale();
    let copy = CopyToRequest::new(
        OperationId::new(),
        TargetPath::posix("/workspace/file").expect("path"),
        vec![1],
    )
    .expect("copy request");
    assert_execution_error(
        endpoint
            .copy_to(&copy, &NeverCancelled)
            .expect_err("replacement Pod UID must reject the endpoint"),
        ExecutionErrorKind::OwnershipMismatch,
        ExecutionStage::CopyTo,
    );
    assert!(server.websocket_uris().is_empty());
    server.assert_finished();

    let cancellation = TestCancellation::pending();
    let server = FakeExecServer::start([ServerReply::guest(&GuestResponse::WriteFile {
        protocol: GUEST_PROTOCOL_VERSION,
    })
    .cancelling(&cancellation)])
    .await;
    let endpoint = attach_endpoint(&server);
    assert_execution_error(
        endpoint
            .copy_to(&copy, &cancellation)
            .expect_err("cancellation after transport completion"),
        ExecutionErrorKind::Cancelled,
        ExecutionStage::CopyTo,
    );
    assert_eq!(server.guest_requests().len(), 1);
    server.assert_finished();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_and_unsupported_operations_stop_before_exec_transport() {
    let server = FakeExecServer::start([]).await;
    let endpoint = attach_endpoint(&server);
    assert_eq!(
        endpoint.capabilities(),
        [
            SandboxCapability::Exec,
            SandboxCapability::CopyTo,
            SandboxCapability::CopyFrom,
            SandboxCapability::EnvironmentInjection,
        ]
    );
    let debug = format!("{endpoint:?}");
    assert!(debug.contains("[OPAQUE]"));
    assert!(!debug.contains(HANDLE));
    assert!(!debug.contains("endpoint-pod-uid"));
    let baseline = server.plain_request_count();
    let cancellation = TestCancellation::cancelled();
    assert_execution_error(
        endpoint
            .exec(&execution_command(64), &cancellation)
            .expect_err("cancelled exec"),
        ExecutionErrorKind::Cancelled,
        ExecutionStage::Exec,
    );
    assert_execution_error(
        endpoint
            .copy_to(
                &CopyToRequest::new(
                    OperationId::new(),
                    TargetPath::posix("/workspace/file").expect("path"),
                    vec![1],
                )
                .expect("copy request"),
                &cancellation,
            )
            .expect_err("cancelled copy"),
        ExecutionErrorKind::Cancelled,
        ExecutionStage::CopyTo,
    );
    assert_execution_error(
        endpoint
            .signal(
                SignalRequest::new(OperationId::new(), ExecutionSignal::Terminate),
                &NeverCancelled,
            )
            .expect_err("signals are unsupported"),
        ExecutionErrorKind::UnsupportedCapability,
        ExecutionStage::Signal,
    );
    assert_execution_error(
        endpoint
            .wait(
                WaitRequest::new(OperationId::new(), Duration::from_secs(1)).expect("wait request"),
                &NeverCancelled,
            )
            .expect_err("wait is unsupported"),
        ExecutionErrorKind::UnsupportedCapability,
        ExecutionStage::Wait,
    );
    assert_eq!(server.plain_request_count(), baseline);
    assert!(server.websocket_uris().is_empty());
    assert!(server.guest_requests().is_empty());
    server.assert_finished();
}
