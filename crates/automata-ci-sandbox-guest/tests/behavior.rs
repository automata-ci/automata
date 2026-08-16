#![cfg(unix)]

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    io,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    process::Stdio,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

#[cfg(target_os = "linux")]
use std::os::{
    linux::net::SocketAddrExt as _,
    unix::{
        net::{SocketAddr as StdSocketAddr, UnixStream as StdUnixStream},
        process::ExitStatusExt as _,
    },
};

use automata_ci_sandbox_guest::{
    GUEST_PROTOCOL_VERSION, GuestAtomicCommitOutcome, GuestFileExpectation, GuestOptionalFile,
    GuestOutputStream, GuestProtocolError, GuestRejection, GuestRequest, GuestResponse,
    GuestTermination, MAX_GUEST_FRAME_BYTES, decode_frame, encode_frame, probe, serve,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Serialize, ser::Error as _};
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _},
    net::UnixStream,
    process::Command,
    task::JoinHandle,
    time::{sleep, timeout},
};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const FIRST_OPERATION: &str = "00000000-0000-4000-8000-000000000001";
const GUEST_BINARY: &str = env!("CARGO_BIN_EXE_automata-ci-sandbox-guest");
const LIVE_DOCKER_ENABLE: &str = "AUTOMATA_SANDBOX_GUEST_LIVE_DOCKER";
const LIVE_DOCKER_HOST: &str = "AUTOMATA_SANDBOX_GUEST_LIVE_DOCKER_HOST";
const LIVE_DOCKER_IMAGE: &str = "AUTOMATA_SANDBOX_GUEST_LIVE_IMAGE";
const LIVE_DOCKER_VOLUME_LABEL: &str = "io.automata.test.sandbox-guest-volume";
static NEXT_TEMP_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(_label: &str) -> Self {
        let sequence = NEXT_TEMP_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        // CI deliberately uses a repository-local TMPDIR. Keep the socket's
        // child name short enough for Linux's fixed-size Unix path field.
        let path = std::env::temp_dir().join(format!(".asg-{:x}-{sequence:x}", std::process::id()));
        std::fs::create_dir(&path).expect("create isolated test directory");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let is_owned_test_directory = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(".asg-"));
        if is_owned_test_directory {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

struct GuestServer {
    temp: TempDir,
    socket: PathBuf,
    task: JoinHandle<Result<(), GuestProtocolError>>,
}

struct GuestProcess {
    temp: TempDir,
    socket: PathBuf,
    child: tokio::process::Child,
}

impl GuestProcess {
    async fn start(label: &str) -> Self {
        let temp = TempDir::new(label);
        let socket = temp.path().join("guest.sock");
        let mut child = Command::new(GUEST_BINARY)
            .arg("serve")
            .arg(&socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("start guest process");
        timeout(TEST_TIMEOUT, async {
            loop {
                assert!(
                    child.try_wait().expect("inspect guest process").is_none(),
                    "guest process stopped during startup"
                );
                if probe(&socket) {
                    return;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("guest process becomes ready");
        Self {
            temp,
            socket,
            child,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.temp.path().join(name)
    }
}

impl Drop for GuestProcess {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

impl GuestServer {
    async fn start(label: &str) -> Self {
        let temp = TempDir::new(label);
        let socket = temp.path().join("guest.sock");
        let task = spawn_server(socket.clone()).await;
        Self { temp, socket, task }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.temp.path().join(name)
    }
}

impl Drop for GuestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn spawn_server(socket: PathBuf) -> JoinHandle<Result<(), GuestProtocolError>> {
    let server_socket = socket.clone();
    let task = tokio::spawn(async move { serve(&server_socket).await });
    timeout(TEST_TIMEOUT, async {
        loop {
            assert!(!task.is_finished(), "guest listener stopped during startup");
            if probe(&socket) {
                return;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("guest listener becomes ready");
    task
}

async fn read_wire_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut header = [0_u8; 4];
    reader.read_exact(&mut header).await?;
    let length = u32::from_be_bytes(header) as usize;
    let mut frame = Vec::with_capacity(length + 4);
    frame.extend_from_slice(&header);
    frame.resize(length + 4, 0);
    reader.read_exact(&mut frame[4..]).await?;
    Ok(frame)
}

async fn exchange(socket: &Path, request: &GuestRequest) -> GuestResponse {
    timeout(TEST_TIMEOUT, async {
        let mut stream = connect_guest(socket).await.expect("connect to guest");
        stream
            .write_all(&encode_frame(request).expect("encode request"))
            .await
            .expect("write request");
        stream.shutdown().await.expect("finish request frame");
        let frame = read_wire_frame(&mut stream).await.expect("read response");
        decode_frame(&frame).expect("decode response")
    })
    .await
    .expect("guest exchange completes")
}

async fn stdio_once(request: &GuestRequest) -> GuestResponse {
    let mut child = Command::new(GUEST_BINARY)
        .arg("stdio-once")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("start one-shot guest");
    child
        .stdin
        .take()
        .expect("one-shot guest stdin")
        .write_all(&encode_frame(request).expect("encode one-shot request"))
        .await
        .expect("write one-shot request");
    let output = timeout(TEST_TIMEOUT, child.wait_with_output())
        .await
        .expect("one-shot guest completes")
        .expect("wait for one-shot guest");
    assert!(
        output.status.success(),
        "one-shot guest failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    decode_frame(&output.stdout).expect("one-shot guest writes one exact response frame")
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut encoded, byte| {
            write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
            encoded
        })
}

fn directory_entries(path: &Path) -> Vec<String> {
    let mut entries = std::fs::read_dir(path)
        .expect("read test directory")
        .map(|entry| {
            entry
                .expect("read test directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    entries.sort_unstable();
    entries
}

fn docker_command(host: &str) -> std::process::Command {
    let mut command = std::process::Command::new("docker");
    command.args(["--host", host]);
    command
}

fn assert_registry_digest_image(image: &str) {
    let Some((repository, digest)) = image.rsplit_once("@sha256:") else {
        panic!("{LIVE_DOCKER_IMAGE} must be a registry-qualified sha256 digest reference");
    };
    let registry = repository.split('/').next().unwrap_or_default();
    assert!(
        repository.contains('/')
            && (registry == "localhost" || registry.contains('.') || registry.contains(':')),
        "{LIVE_DOCKER_IMAGE} must be registry-qualified"
    );
    assert!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{LIVE_DOCKER_IMAGE} must contain one lowercase sha256 digest"
    );
}

struct DockerLiveResources {
    host: String,
    volume: String,
    nonce: String,
    armed: bool,
}

impl DockerLiveResources {
    fn is_owned_volume(&self) -> bool {
        let output = match docker_command(&self.host)
            .args(["volume", "inspect", &self.volume])
            .output()
        {
            Ok(output) if output.status.success() => output,
            Ok(_) | Err(_) => return false,
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&output.stdout) else {
            return false;
        };
        let Some(volume) = value
            .as_array()
            .and_then(|volumes| (volumes.len() == 1).then(|| volumes.first()).flatten())
        else {
            return false;
        };
        let labels = volume.get("Labels").and_then(serde_json::Value::as_object);
        volume.get("Name").and_then(serde_json::Value::as_str) == Some(self.volume.as_str())
            && volume.get("Driver").and_then(serde_json::Value::as_str) == Some("local")
            && volume.get("Scope").and_then(serde_json::Value::as_str) == Some("local")
            && volume.get("Options").is_some_and(|options| {
                options.is_null() || options.as_object().is_some_and(serde_json::Map::is_empty)
            })
            && labels.is_some_and(|labels| {
                labels
                    .get(LIVE_DOCKER_VOLUME_LABEL)
                    .and_then(serde_json::Value::as_str)
                    == Some(self.nonce.as_str())
                    && labels.iter().all(|(key, value)| {
                        key == LIVE_DOCKER_VOLUME_LABEL
                            || (key == "com.docker.volume.anonymous" && value.as_str() == Some(""))
                    })
            })
    }

    fn has_attachments(&self) -> bool {
        let filter = format!("volume={}", self.volume);
        match docker_command(&self.host)
            .args([
                "container",
                "ls",
                "--all",
                "--filter",
                &filter,
                "--format",
                "{{.ID}}",
            ])
            .output()
        {
            Ok(output) if output.status.success() => {
                !output.stdout.iter().all(u8::is_ascii_whitespace)
            }
            Ok(_) | Err(_) => true,
        }
    }

    fn remove(&mut self) {
        assert!(
            self.is_owned_volume(),
            "refusing to remove an unowned test volume"
        );
        assert!(
            !self.has_attachments(),
            "refusing to remove an attached test volume"
        );
        let output = docker_command(&self.host)
            .args(["volume", "rm", &self.volume])
            .output()
            .expect("remove live-test volume");
        assert!(
            output.status.success(),
            "remove live-test volume: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let inspect = docker_command(&self.host)
            .args(["volume", "inspect", &self.volume])
            .output()
            .expect("verify live-test volume removal");
        assert!(
            !inspect.status.success(),
            "live-test volume was not removed"
        );
        self.armed = false;
    }
}

impl Drop for DockerLiveResources {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if self.is_owned_volume() && !self.has_attachments() {
            let _ = docker_command(&self.host)
                .args(["volume", "rm", &self.volume])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

fn docker_stdio_once(
    resources: &DockerLiveResources,
    image: &str,
    request: &GuestRequest,
) -> GuestResponse {
    let mount = format!(
        "type=volume,src={},dst=/var/lib/automata-local",
        resources.volume
    );
    let mut child = docker_command(&resources.host)
        .args([
            "run",
            "--rm",
            "--interactive",
            "--pull",
            "never",
            "--user",
            "65532:65532",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--mount",
            &mount,
            image,
            "stdio-once",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start digest-pinned sandbox-guest container");
    let mut stdin = child.stdin.take().expect("sandbox-guest container stdin");
    std::io::Write::write_all(
        &mut stdin,
        &encode_frame(request).expect("encode Docker live request"),
    )
    .expect("write Docker live request");
    drop(stdin);
    let output = child
        .wait_with_output()
        .expect("wait for sandbox-guest container");
    assert!(
        output.status.success(),
        "sandbox-guest container failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    decode_frame(&output.stdout).expect("container writes one exact guest response frame")
}

async fn connect_guest(socket: &Path) -> io::Result<UnixStream> {
    #[cfg(target_os = "linux")]
    if let Some(name) = socket.to_str().and_then(|value| value.strip_prefix('@')) {
        let address = StdSocketAddr::from_abstract_name(name.as_bytes())?;
        let stream = StdUnixStream::connect_addr(&address)?;
        stream.set_nonblocking(true)?;
        return UnixStream::from_std(stream);
    }
    UnixStream::connect(socket).await
}

#[cfg(target_os = "linux")]
fn namespace_without_proc() -> std::process::Command {
    let mut command = std::process::Command::new("unshare");
    command.args([
        "--user",
        "--map-root-user",
        "--mount",
        "bash",
        "-lc",
        "mount -t tmpfs tmpfs /proc && exec \"$@\"",
        "sandbox-guest-no-proc",
    ]);
    command
}

fn exec_request(
    operation_id: impl Into<String>,
    program: impl Into<String>,
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
    working_directory: impl Into<String>,
    timeout_millis: u64,
    output_limit: usize,
) -> GuestRequest {
    GuestRequest::Exec {
        protocol: GUEST_PROTOCOL_VERSION,
        operation_id: operation_id.into(),
        program: program.into(),
        arguments,
        environment,
        working_directory: working_directory.into(),
        timeout_millis,
        output_limit,
        process_limit: None,
    }
}

fn operation_id(index: usize) -> String {
    format!("operation-{index:04}")
}

#[allow(clippy::needless_pass_by_value)]
fn assert_rejected(response: GuestResponse, expected: GuestRejection) {
    assert_eq!(
        response,
        GuestResponse::Rejected {
            protocol: GUEST_PROTOCOL_VERSION,
            kind: expected,
        }
    );
}

fn exec_parts(
    response: GuestResponse,
) -> (
    GuestTermination,
    Vec<automata_ci_sandbox_guest::GuestOutputRecord>,
    bool,
) {
    let GuestResponse::Exec {
        protocol,
        termination,
        records,
        truncated,
    } = response
    else {
        panic!("expected execution response, got {response:?}");
    };
    assert_eq!(protocol, GUEST_PROTOCOL_VERSION);
    (termination, records, truncated)
}

fn output_for(
    records: &[automata_ci_sandbox_guest::GuestOutputRecord],
    stream: GuestOutputStream,
) -> Vec<u8> {
    records
        .iter()
        .filter(|record| record.stream() == stream && !record.is_end_of_stream())
        .flat_map(|record| record.data().expect("valid output base64"))
        .collect()
}

fn assert_complete_streams(records: &[automata_ci_sandbox_guest::GuestOutputRecord]) {
    for stream in [GuestOutputStream::Stdout, GuestOutputStream::Stderr] {
        assert_eq!(
            records
                .iter()
                .filter(|record| record.stream() == stream && record.is_end_of_stream())
                .count(),
            1
        );
    }
}

fn payload_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("payload test frame length fits u32")
            .to_be_bytes(),
    );
    frame.extend_from_slice(payload);
    frame
}

struct SerializationFailure;

impl Serialize for SerializationFailure {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Err(S::Error::custom("intentionally unencodable"))
    }
}

#[test]
fn framing_is_exact_bounded_and_sanitized() {
    let response = GuestResponse::WriteFile {
        protocol: GUEST_PROTOCOL_VERSION,
    };
    let frame = encode_frame(&response).expect("encode ordinary frame");
    assert_eq!(decode_frame::<GuestResponse>(&frame).unwrap(), response);

    for invalid in [
        Vec::new(),
        vec![0, 0, 0],
        vec![0, 0, 0, 0],
        (u32::try_from(MAX_GUEST_FRAME_BYTES + 1).expect("frame maximum fits u32"))
            .to_be_bytes()
            .to_vec(),
        payload_frame(b"{"),
    ] {
        assert!(matches!(
            decode_frame::<GuestResponse>(&invalid),
            Err(GuestProtocolError::InvalidFrame)
        ));
    }

    let mut trailing = frame.clone();
    trailing.push(0);
    assert!(decode_frame::<GuestResponse>(&trailing).is_err());
    let mut truncated = frame;
    truncated.pop();
    assert!(decode_frame::<GuestResponse>(&truncated).is_err());
    assert!(matches!(
        encode_frame(&SerializationFailure),
        Err(GuestProtocolError::InvalidFrame)
    ));
    assert!(matches!(
        encode_frame(&"x".repeat(MAX_GUEST_FRAME_BYTES)),
        Err(GuestProtocolError::InvalidFrame)
    ));

    let unknown_field = payload_frame(br#"{"result":"write_file","protocol":1,"unexpected":true}"#);
    assert!(decode_frame::<GuestResponse>(&unknown_field).is_err());

    let invalid_record = payload_frame(
        br#"{"result":"exec","protocol":1,"termination":{"kind":"exited","code":0},"records":[{"stream":"stdout","data_base64":"%%%","end_of_stream":false}],"truncated":false}"#,
    );
    let GuestResponse::Exec { records, .. } =
        decode_frame::<GuestResponse>(&invalid_record).expect("shape is valid")
    else {
        panic!("expected execution response");
    };
    assert!(matches!(
        records[0].data(),
        Err(GuestProtocolError::InvalidFrame)
    ));

    assert_eq!(
        GuestProtocolError::InvalidFrame.to_string(),
        "guest frame is invalid"
    );
    assert_eq!(
        GuestProtocolError::Io(io::Error::other("sensitive transport detail")).to_string(),
        "guest transport failed"
    );
}

#[test]
fn debug_views_redact_request_response_and_output_payloads() {
    let requests = [
        exec_request(
            FIRST_OPERATION,
            "/secret/program",
            vec!["secret-argument".into()],
            BTreeMap::from([("SECRET_NAME".into(), "secret-value".into())]),
            "/secret/working-directory",
            1,
            1,
        ),
        GuestRequest::WriteFile {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: "write-operation".into(),
            path: "/secret/write-path".into(),
            content_base64: BASE64.encode(b"secret-file-content"),
        },
        GuestRequest::ReadFile {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: "read-operation".into(),
            path: "/secret/read-path".into(),
            byte_limit: 64,
        },
        GuestRequest::AtomicCommitFile {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: "atomic-operation".into(),
            path: "/secret/atomic-path".into(),
            content_base64: BASE64.encode(b"secret-atomic-content"),
            expected: GuestFileExpectation::Sha256 {
                digest: sha256(b"secret-previous-content"),
            },
        },
        GuestRequest::ReadOptionalFile {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: "optional-read-operation".into(),
            path: "/secret/optional-read-path".into(),
            byte_limit: 64,
        },
    ];
    let mut rendered = String::new();
    for request in requests {
        write!(&mut rendered, "{request:?}").expect("debug formatting into a string succeeds");
    }
    for secret in [
        "secret/program",
        "secret-argument",
        "secret-value",
        "secret/working-directory",
        "secret/write-path",
        "secret-file-content",
        "secret/read-path",
        "secret/atomic-path",
        "secret-atomic-content",
        "secret/optional-read-path",
    ] {
        assert!(!rendered.contains(secret));
    }
    assert!(rendered.contains("[REDACTED]"));

    let framed = payload_frame(
        format!(
            "{{\"result\":\"exec\",\"protocol\":1,\"termination\":{{\"kind\":\"exited\",\"code\":0}},\"records\":[{{\"stream\":\"stdout\",\"data_base64\":\"{}\",\"end_of_stream\":false}}],\"truncated\":false}}",
            BASE64.encode(b"secret-command-output")
        )
        .as_bytes(),
    );
    let response: GuestResponse = decode_frame(&framed).expect("decode response fixture");
    let GuestResponse::Exec { records, .. } = &response else {
        panic!("expected execution response");
    };
    assert!(!format!("{response:?}").contains("secret-command-output"));
    assert!(!format!("{:?}", records[0]).contains("secret-command-output"));

    let read_response = GuestResponse::ReadFile {
        protocol: GUEST_PROTOCOL_VERSION,
        content_base64: BASE64.encode(b"secret-read-content"),
    };
    assert!(!format!("{read_response:?}").contains("secret-read-content"));

    let optional_read_response = GuestResponse::ReadOptionalFile {
        protocol: GUEST_PROTOCOL_VERSION,
        file: GuestOptionalFile::Present {
            content_base64: BASE64.encode(b"secret-optional-read-content"),
        },
    };
    assert!(!format!("{optional_read_response:?}").contains("secret-optional-read-content"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guest_protocol_v1_is_rejected() {
    let server = GuestServer::start("guest-protocol-v1-rejection").await;
    let socket = server.socket.clone();
    let unsupported_protocol = 1;
    let unsupported = GuestRequest::Probe {
        protocol: unsupported_protocol,
        operation_id: FIRST_OPERATION.into(),
    };
    let expected_rejection = GuestRejection::UnsupportedProtocol;
    assert_rejected(exchange(&socket, &unsupported).await, expected_rejection);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guest_protocol_v2_is_rejected() {
    let server = GuestServer::start("guest-protocol-v2-rejection").await;
    let socket = server.socket.clone();
    let unsupported_protocol = 2;
    let unsupported = GuestRequest::Probe {
        protocol: unsupported_protocol,
        operation_id: FIRST_OPERATION.into(),
    };
    let expected_rejection = GuestRejection::UnsupportedProtocol;
    assert_rejected(exchange(&socket, &unsupported).await, expected_rejection);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guest_protocol_v3_is_rejected() {
    let server = GuestServer::start("guest-protocol-v3-rejection").await;
    let unsupported = GuestRequest::Probe {
        protocol: 3,
        operation_id: FIRST_OPERATION.into(),
    };
    assert_rejected(
        exchange(&server.socket, &unsupported).await,
        GuestRejection::UnsupportedProtocol,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listener_lifecycle_protocol_and_malformed_connections_fail_closed() {
    let temp = TempDir::new("listener-lifecycle");
    let socket = temp.path().join("guest.sock");
    assert!(!probe(&socket));
    std::fs::write(&socket, b"stale socket path").expect("create stale path");
    let task = spawn_server(socket.clone()).await;
    assert!(probe(&socket));

    let expected_rejection = GuestRejection::UnsupportedProtocol;
    for unsupported_protocol in [1, 2, 3, 4, GUEST_PROTOCOL_VERSION + 1] {
        let unsupported = GuestRequest::ReadFile {
            protocol: unsupported_protocol,
            operation_id: FIRST_OPERATION.into(),
            path: "/tmp/unreached".into(),
            byte_limit: 1,
        };
        assert_rejected(exchange(&socket, &unsupported).await, expected_rejection);
    }

    for operation_id in ["", "contains space", "line\nbreak"] {
        let request = GuestRequest::ReadFile {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: operation_id.into(),
            path: "/tmp/unreached".into(),
            byte_limit: 1,
        };
        assert_rejected(
            exchange(&socket, &request).await,
            GuestRejection::InvalidRequest,
        );
    }
    let request = GuestRequest::ReadFile {
        protocol: GUEST_PROTOCOL_VERSION,
        operation_id: "x".repeat(129),
        path: "/tmp/unreached".into(),
        byte_limit: 1,
    };
    assert_rejected(
        exchange(&socket, &request).await,
        GuestRejection::InvalidRequest,
    );

    for header in [
        0_u32,
        u32::try_from(MAX_GUEST_FRAME_BYTES + 1).expect("oversized test frame fits u32"),
    ] {
        let mut stream = UnixStream::connect(&socket)
            .await
            .expect("connect malformed client");
        stream
            .write_all(&header.to_be_bytes())
            .await
            .expect("write malformed header");
        stream.shutdown().await.expect("close malformed request");
        let mut response = Vec::new();
        timeout(TEST_TIMEOUT, stream.read_to_end(&mut response))
            .await
            .expect("malformed connection closes")
            .expect("read malformed connection close");
        assert!(response.is_empty());
    }

    let mut stream = UnixStream::connect(&socket)
        .await
        .expect("connect truncated client");
    stream.write_all(&8_u32.to_be_bytes()).await.unwrap();
    stream.write_all(b"{}").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert!(response.is_empty());

    task.abort();
    let _ = task.await;
    timeout(TEST_TIMEOUT, async {
        while probe(&socket) {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("listener stops accepting after cancellation");

    let missing_parent = temp.path().join("missing").join("guest.sock");
    assert!(matches!(
        serve(&missing_parent).await,
        Err(GuestProtocolError::Io(_))
    ));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_abstract_socket_serves_and_probes_without_filesystem_state() {
    let socket = PathBuf::from(format!(
        "@automata-sandbox-guest-test-{}-{}",
        std::process::id(),
        NEXT_TEMP_DIRECTORY.fetch_add(1, Ordering::Relaxed)
    ));
    let task = spawn_server(socket.clone()).await;
    assert!(probe(&socket));
    let request = exec_request(
        FIRST_OPERATION,
        "/bin/true",
        Vec::new(),
        BTreeMap::new(),
        "/tmp",
        1_000,
        1,
    );
    let (termination, records, truncated) = exec_parts(exchange(&socket, &request).await);
    assert_eq!(termination, GuestTermination::Exited(0));
    assert!(!truncated);
    assert_complete_streams(&records);
    task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn execute_preserves_environment_cwd_streams_and_termination() {
    let server = GuestServer::start("execute-contract").await;
    let request = exec_request(
        operation_id(1),
        "/bin/sh",
        vec![
            "-c".into(),
            "printf '%s' \"$VISIBLE_VALUE\"; printf stderr-value >&2".into(),
        ],
        BTreeMap::from([("VISIBLE_VALUE".into(), "environment-value".into())]),
        server.temp.path().to_string_lossy(),
        2_000,
        1_024,
    );
    let (termination, records, truncated) = exec_parts(exchange(&server.socket, &request).await);
    assert_eq!(termination, GuestTermination::Exited(0));
    assert_eq!(
        output_for(&records, GuestOutputStream::Stdout),
        b"environment-value"
    );
    assert_eq!(
        output_for(&records, GuestOutputStream::Stderr),
        b"stderr-value"
    );
    assert!(!truncated);
    assert_complete_streams(&records);

    let pwd = exec_request(
        operation_id(2),
        "/bin/pwd",
        Vec::new(),
        BTreeMap::new(),
        server.temp.path().to_string_lossy(),
        2_000,
        1_024,
    );
    let (termination, records, _) = exec_parts(exchange(&server.socket, &pwd).await);
    assert_eq!(termination, GuestTermination::Exited(0));
    let expected_working_directory = std::fs::canonicalize(server.temp.path())
        .expect("canonical guest test working directory")
        .to_string_lossy()
        .into_owned();
    assert_eq!(
        String::from_utf8(output_for(&records, GuestOutputStream::Stdout))
            .unwrap()
            .trim_end(),
        expected_working_directory
    );

    let nonzero = exec_request(
        operation_id(3),
        "/bin/sh",
        vec!["-c".into(), "exit 23".into()],
        BTreeMap::new(),
        "/tmp",
        2_000,
        1,
    );
    let (termination, records, truncated) = exec_parts(exchange(&server.socket, &nonzero).await);
    assert_eq!(termination, GuestTermination::Exited(23));
    assert!(!truncated);
    assert_complete_streams(&records);

    let signalled = exec_request(
        operation_id(4),
        "/bin/sh",
        vec!["-c".into(), "kill -TERM $$".into()],
        BTreeMap::new(),
        "/tmp",
        2_000,
        1,
    );
    let (termination, _, _) = exec_parts(exchange(&server.socket, &signalled).await);
    assert_eq!(termination, GuestTermination::Signalled);

    let spawn_failure = exec_request(
        operation_id(5),
        "/definitely/missing/program",
        Vec::new(),
        BTreeMap::new(),
        "/tmp",
        2_000,
        1,
    );
    assert_rejected(
        exchange(&server.socket, &spawn_failure).await,
        GuestRejection::OperationFailed,
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn execute_enforces_request_and_output_bounds_exactly() {
    let server = GuestServer::start("execute-bounds").await;
    let exact = exec_request(
        operation_id(10),
        "/bin/sh",
        vec!["-c".into(), "printf 12345".into()],
        BTreeMap::new(),
        "/tmp",
        2_000,
        5,
    );
    let (_, records, truncated) = exec_parts(exchange(&server.socket, &exact).await);
    assert_eq!(output_for(&records, GuestOutputStream::Stdout), b"12345");
    assert!(!truncated);
    assert_complete_streams(&records);

    let over = exec_request(
        operation_id(11),
        "/bin/sh",
        vec!["-c".into(), "printf 123456".into()],
        BTreeMap::new(),
        "/tmp",
        2_000,
        5,
    );
    let (_, records, truncated) = exec_parts(exchange(&server.socket, &over).await);
    assert_eq!(output_for(&records, GuestOutputStream::Stdout), b"12345");
    assert!(truncated);
    assert!(
        !records
            .iter()
            .any(automata_ci_sandbox_guest::GuestOutputRecord::is_end_of_stream)
    );

    let timeout_request = exec_request(
        operation_id(12),
        "/bin/sh",
        vec!["-c".into(), "printf retained; exec /bin/sleep 5".into()],
        BTreeMap::new(),
        "/tmp",
        75,
        64,
    );
    let (termination, records, truncated) =
        exec_parts(exchange(&server.socket, &timeout_request).await);
    assert_eq!(termination, GuestTermination::TimedOut);
    assert_eq!(output_for(&records, GuestOutputStream::Stdout), b"retained");
    assert!(
        !truncated,
        "a deadline is not evidence of an output-limit overrun"
    );
    assert_complete_streams(&records);

    let invalid_requests = [
        exec_request(
            operation_id(13),
            "bin/true",
            Vec::new(),
            BTreeMap::new(),
            "/tmp",
            1,
            1,
        ),
        exec_request(
            operation_id(14),
            "/bin/true",
            Vec::new(),
            BTreeMap::new(),
            "tmp",
            1,
            1,
        ),
        exec_request(
            operation_id(15),
            "/bin/true",
            vec!["nul\0argument".into()],
            BTreeMap::new(),
            "/tmp",
            1,
            1,
        ),
        exec_request(
            operation_id(16),
            "/bin/true",
            Vec::new(),
            BTreeMap::from([("BAD=NAME".into(), "value".into())]),
            "/tmp",
            1,
            1,
        ),
        exec_request(
            operation_id(17),
            "/bin/true",
            Vec::new(),
            BTreeMap::from([("GOOD_NAME".into(), "nul\0value".into())]),
            "/tmp",
            1,
            1,
        ),
        exec_request(
            operation_id(18),
            "/bin/true",
            Vec::new(),
            BTreeMap::new(),
            "/tmp",
            0,
            1,
        ),
        exec_request(
            operation_id(19),
            "/bin/true",
            Vec::new(),
            BTreeMap::new(),
            "/tmp",
            u64::MAX,
            1,
        ),
        exec_request(
            operation_id(20),
            "/bin/true",
            Vec::new(),
            BTreeMap::new(),
            "/tmp",
            1,
            0,
        ),
        exec_request(
            operation_id(21),
            "/bin/true",
            Vec::new(),
            BTreeMap::new(),
            "/tmp",
            1,
            usize::MAX,
        ),
    ];
    for request in invalid_requests {
        assert_rejected(
            exchange(&server.socket, &request).await,
            GuestRejection::InvalidRequest,
        );
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn write_and_read_file_validate_paths_base64_and_exact_byte_limits() {
    let server = GuestServer::start("file-contract").await;
    let path = server.path("payload.bin");
    let content = b"\0binary\xffpayload";
    let write = GuestRequest::WriteFile {
        protocol: GUEST_PROTOCOL_VERSION,
        operation_id: operation_id(30),
        path: path.to_string_lossy().into_owned(),
        content_base64: BASE64.encode(content),
    };
    assert_eq!(
        exchange(&server.socket, &write).await,
        GuestResponse::WriteFile {
            protocol: GUEST_PROTOCOL_VERSION
        }
    );
    assert_eq!(tokio::fs::read(&path).await.unwrap(), content);

    let read = GuestRequest::ReadFile {
        protocol: GUEST_PROTOCOL_VERSION,
        operation_id: operation_id(31),
        path: path.to_string_lossy().into_owned(),
        byte_limit: content.len(),
    };
    let GuestResponse::ReadFile {
        protocol,
        content_base64,
    } = exchange(&server.socket, &read).await
    else {
        panic!("expected read response");
    };
    assert_eq!(protocol, GUEST_PROTOCOL_VERSION);
    assert_eq!(BASE64.decode(content_base64).unwrap(), content);

    let too_small = GuestRequest::ReadFile {
        protocol: GUEST_PROTOCOL_VERSION,
        operation_id: operation_id(32),
        path: path.to_string_lossy().into_owned(),
        byte_limit: content.len() - 1,
    };
    assert_rejected(
        exchange(&server.socket, &too_small).await,
        GuestRejection::InvalidRequest,
    );

    let invalid_writes = [
        ("relative/path", BASE64.encode(b"content")),
        ("/tmp/../escape", BASE64.encode(b"content")),
        ("/tmp//double", BASE64.encode(b"content")),
        ("/tmp/nul\0path", BASE64.encode(b"content")),
        (path.to_str().unwrap(), "%%%".into()),
    ];
    for (index, (invalid_path, content_base64)) in invalid_writes.into_iter().enumerate() {
        let request = GuestRequest::WriteFile {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: operation_id(40 + index),
            path: invalid_path.into(),
            content_base64,
        };
        assert_rejected(
            exchange(&server.socket, &request).await,
            GuestRejection::InvalidRequest,
        );
    }

    let write_directory = GuestRequest::WriteFile {
        protocol: GUEST_PROTOCOL_VERSION,
        operation_id: operation_id(50),
        path: server.temp.path().to_string_lossy().into_owned(),
        content_base64: BASE64.encode(b"content"),
    };
    assert_rejected(
        exchange(&server.socket, &write_directory).await,
        GuestRejection::OperationFailed,
    );

    for (index, (invalid_path, byte_limit)) in [
        ("relative/path", 1),
        ("/tmp/./dot", 1),
        ("/tmp//double", 1),
        ("/tmp/nul\0path", 1),
        ("/tmp/missing-automata-sandbox-guest-file", 1),
        (path.to_str().unwrap(), 0),
        (path.to_str().unwrap(), usize::MAX),
    ]
    .into_iter()
    .enumerate()
    {
        let request = GuestRequest::ReadFile {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: operation_id(60 + index),
            path: invalid_path.into(),
            byte_limit,
        };
        let expected = if invalid_path.starts_with("/tmp/missing-") {
            GuestRejection::OperationFailed
        } else {
            GuestRejection::InvalidRequest
        };
        assert_rejected(exchange(&server.socket, &request).await, expected);
    }

    let accepted_length_missing_path = format!("/{}", "a".repeat(4_094));
    assert_eq!(accepted_length_missing_path.len(), 4_095);
    let request = GuestRequest::ReadFile {
        protocol: GUEST_PROTOCOL_VERSION,
        operation_id: operation_id(70),
        path: accepted_length_missing_path,
        byte_limit: 1,
    };
    assert_rejected(
        exchange(&server.socket, &request).await,
        GuestRejection::OperationFailed,
    );
    let overlong_path = format!("/{}", "a".repeat(4_096));
    let request = GuestRequest::ReadFile {
        protocol: GUEST_PROTOCOL_VERSION,
        operation_id: operation_id(71),
        path: overlong_path,
        byte_limit: 1,
    };
    assert_rejected(
        exchange(&server.socket, &request).await,
        GuestRejection::InvalidRequest,
    );
}

#[tokio::test]
async fn stdio_once_optional_read_distinguishes_missing_from_other_io_failures() {
    let temp = TempDir::new("stdio-once-optional-read");
    let missing = GuestRequest::ReadOptionalFile {
        protocol: GUEST_PROTOCOL_VERSION,
        operation_id: operation_id(72),
        path: temp.path().join("missing").to_string_lossy().into_owned(),
        byte_limit: 64,
    };
    assert_eq!(
        stdio_once(&missing).await,
        GuestResponse::ReadOptionalFile {
            protocol: GUEST_PROTOCOL_VERSION,
            file: GuestOptionalFile::Missing {},
        }
    );

    let present_path = temp.path().join("present");
    tokio::fs::write(&present_path, b"present bytes")
        .await
        .unwrap();
    let present = GuestRequest::ReadOptionalFile {
        protocol: GUEST_PROTOCOL_VERSION,
        operation_id: operation_id(73),
        path: present_path.to_string_lossy().into_owned(),
        byte_limit: 64,
    };
    assert_eq!(
        stdio_once(&present).await,
        GuestResponse::ReadOptionalFile {
            protocol: GUEST_PROTOCOL_VERSION,
            file: GuestOptionalFile::Present {
                content_base64: BASE64.encode(b"present bytes"),
            },
        }
    );

    let directory = GuestRequest::ReadOptionalFile {
        protocol: GUEST_PROTOCOL_VERSION,
        operation_id: operation_id(74),
        path: temp.path().to_string_lossy().into_owned(),
        byte_limit: 64,
    };
    assert_rejected(
        stdio_once(&directory).await,
        GuestRejection::OperationFailed,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdio_once_atomic_commit_replaces_whole_bytes_and_cas_is_idempotent() {
    let temp = TempDir::new("stdio-once-atomic-commit");
    let path = temp.path().join("desired-spec.json");
    let old = vec![b'a'; 2 * 1024 * 1024];
    let new = vec![b'b'; 2 * 1024 * 1024];
    tokio::fs::write(&path, &old).await.unwrap();
    let inode_before = tokio::fs::metadata(&path).await.unwrap().ino();

    let request = GuestRequest::AtomicCommitFile {
        protocol: GUEST_PROTOCOL_VERSION,
        operation_id: operation_id(75),
        path: path.to_string_lossy().into_owned(),
        content_base64: BASE64.encode(&new),
        expected: GuestFileExpectation::Sha256 {
            digest: sha256(&old),
        },
    };
    let watched_path = path.clone();
    let watched_old = old.clone();
    let watched_new = new.clone();
    let watcher = tokio::spawn(async move {
        loop {
            let observed = tokio::fs::read(&watched_path)
                .await
                .expect("read file while it is replaced");
            assert!(
                observed == watched_old || observed == watched_new,
                "atomic replacement exposed partial file bytes"
            );
            if observed == watched_new {
                return;
            }
            tokio::task::yield_now().await;
        }
    });

    assert_eq!(
        stdio_once(&request).await,
        GuestResponse::AtomicCommitFile {
            protocol: GUEST_PROTOCOL_VERSION,
            outcome: GuestAtomicCommitOutcome::Committed,
        }
    );
    timeout(TEST_TIMEOUT, watcher)
        .await
        .expect("concurrent reader observes committed bytes")
        .expect("concurrent reader completes");
    assert_eq!(tokio::fs::read(&path).await.unwrap(), new);
    let committed_metadata = tokio::fs::metadata(&path).await.unwrap();
    assert_ne!(
        committed_metadata.ino(),
        inode_before,
        "commit must replace rather than truncate the destination"
    );

    let entries_after_commit = directory_entries(temp.path());
    assert_eq!(
        stdio_once(&request).await,
        GuestResponse::AtomicCommitFile {
            protocol: GUEST_PROTOCOL_VERSION,
            outcome: GuestAtomicCommitOutcome::AlreadyCurrent,
        }
    );
    assert_eq!(tokio::fs::read(&path).await.unwrap(), new);
    assert_eq!(
        tokio::fs::metadata(&path).await.unwrap().ino(),
        committed_metadata.ino(),
        "an identical ambiguous-outcome retry must not replace current bytes"
    );
    assert_eq!(directory_entries(temp.path()), entries_after_commit);

    let conflict = GuestRequest::AtomicCommitFile {
        protocol: GUEST_PROTOCOL_VERSION,
        operation_id: operation_id(76),
        path: path.to_string_lossy().into_owned(),
        content_base64: BASE64.encode(b"conflicting bytes"),
        expected: GuestFileExpectation::Absent,
    };
    assert_eq!(
        stdio_once(&conflict).await,
        GuestResponse::AtomicCommitFile {
            protocol: GUEST_PROTOCOL_VERSION,
            outcome: GuestAtomicCommitOutcome::Conflict,
        }
    );
    assert_eq!(tokio::fs::read(&path).await.unwrap(), new);
    assert_eq!(
        tokio::fs::metadata(&path).await.unwrap().ino(),
        committed_metadata.ino(),
        "a compare-and-swap conflict must not mutate the destination"
    );
    assert_eq!(directory_entries(temp.path()), entries_after_commit);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn atomic_stdio_once_requires_clean_eof_before_mutating() {
    let temp = TempDir::new("atomic-stdio-eof");
    let path = temp.path().join("committed-after-eof");
    let request = GuestRequest::AtomicCommitFile {
        protocol: GUEST_PROTOCOL_VERSION,
        operation_id: operation_id(77),
        path: path.to_string_lossy().into_owned(),
        content_base64: BASE64.encode(b"committed bytes"),
        expected: GuestFileExpectation::Absent,
    };
    let mut child = Command::new(GUEST_BINARY)
        .arg("stdio-once")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("start one-shot atomic guest");
    let mut stdin = child.stdin.take().expect("one-shot atomic stdin");
    stdin
        .write_all(&encode_frame(&request).unwrap())
        .await
        .unwrap();
    sleep(Duration::from_millis(200)).await;
    assert!(
        !path.exists(),
        "atomic request mutated before standard-input EOF"
    );
    assert!(
        child
            .try_wait()
            .expect("poll one-shot atomic guest")
            .is_none(),
        "atomic request did not wait for standard-input EOF"
    );
    drop(stdin);
    let output = timeout(TEST_TIMEOUT, child.wait_with_output())
        .await
        .expect("atomic request completes after EOF")
        .expect("wait for one-shot atomic guest");
    assert!(output.status.success());
    assert_eq!(
        decode_frame::<GuestResponse>(&output.stdout).unwrap(),
        GuestResponse::AtomicCommitFile {
            protocol: GUEST_PROTOCOL_VERSION,
            outcome: GuestAtomicCommitOutcome::Committed,
        }
    );
    assert_eq!(tokio::fs::read(&path).await.unwrap(), b"committed bytes");

    let trailing_path = temp.path().join("must-not-be-created");
    let trailing_request = GuestRequest::AtomicCommitFile {
        protocol: GUEST_PROTOCOL_VERSION,
        operation_id: operation_id(78),
        path: trailing_path.to_string_lossy().into_owned(),
        content_base64: BASE64.encode(b"unreachable bytes"),
        expected: GuestFileExpectation::Absent,
    };
    let mut child = Command::new(GUEST_BINARY)
        .arg("stdio-once")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("start one-shot trailing-input guest");
    let mut stdin = child.stdin.take().expect("one-shot trailing-input stdin");
    stdin
        .write_all(&encode_frame(&trailing_request).unwrap())
        .await
        .unwrap();
    stdin.write_all(b"unexpected trailing byte").await.unwrap();
    drop(stdin);
    let output = timeout(TEST_TIMEOUT, child.wait_with_output())
        .await
        .expect("trailing-input guest exits")
        .expect("wait for trailing-input guest");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        !trailing_path.exists(),
        "atomic request with trailing input must not mutate"
    );
}

#[test]
#[ignore = "requires an explicit Docker daemon and a preloaded digest-pinned guest image"]
#[allow(clippy::too_many_lines)]
fn opt_in_docker_fresh_named_volume_is_writable_by_nonroot_guest() {
    assert_eq!(
        std::env::var(LIVE_DOCKER_ENABLE).as_deref(),
        Ok("1"),
        "ignored Docker test requires {LIVE_DOCKER_ENABLE}=1"
    );
    let host = std::env::var(LIVE_DOCKER_HOST)
        .expect("ignored Docker test requires an explicit Docker daemon endpoint");
    assert!(
        !host.trim().is_empty(),
        "{LIVE_DOCKER_HOST} must not be empty"
    );
    let image = std::env::var(LIVE_DOCKER_IMAGE)
        .expect("ignored Docker test requires a preloaded sandbox-guest image digest");
    assert_registry_digest_image(&image);

    let inspect = docker_command(&host)
        .args(["image", "inspect", &image])
        .output()
        .expect("inspect preloaded sandbox-guest image");
    assert!(
        inspect.status.success(),
        "{LIVE_DOCKER_IMAGE} must already exist at the selected daemon: {}",
        String::from_utf8_lossy(&inspect.stderr)
    );

    let mut nonce_bytes = [0_u8; 16];
    getrandom::fill(&mut nonce_bytes).expect("obtain a live-test ownership nonce");
    let nonce = nonce_bytes
        .iter()
        .fold(String::with_capacity(32), |mut encoded, byte| {
            write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
            encoded
        });
    let label = format!("{LIVE_DOCKER_VOLUME_LABEL}={nonce}");
    let created = docker_command(&host)
        .args(["volume", "create", "--driver", "local", "--label", &label])
        .output()
        .expect("create fresh named Docker volume");
    assert!(
        created.status.success(),
        "create fresh named Docker volume: {}",
        String::from_utf8_lossy(&created.stderr)
    );
    let volume = String::from_utf8(created.stdout)
        .expect("Docker volume name is UTF-8")
        .trim()
        .to_owned();
    assert!(
        !volume.is_empty()
            && volume.len() <= 255
            && volume
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)),
        "Docker returned an invalid volume name"
    );
    let mut resources = DockerLiveResources {
        host,
        volume,
        nonce,
        armed: false,
    };
    assert!(
        resources.is_owned_volume(),
        "created volume did not retain the exact test ownership contract"
    );
    resources.armed = true;
    assert!(
        !resources.has_attachments(),
        "new test volume unexpectedly has a container attachment"
    );

    let content = b"nonroot named-volume write";
    let commit = GuestRequest::AtomicCommitFile {
        protocol: GUEST_PROTOCOL_VERSION,
        operation_id: operation_id(79),
        path: "/var/lib/automata-local/desired-spec.json".into(),
        content_base64: BASE64.encode(content),
        expected: GuestFileExpectation::Absent,
    };
    assert_eq!(
        docker_stdio_once(&resources, &image, &commit),
        GuestResponse::AtomicCommitFile {
            protocol: GUEST_PROTOCOL_VERSION,
            outcome: GuestAtomicCommitOutcome::Committed,
        }
    );

    let read = GuestRequest::ReadOptionalFile {
        protocol: GUEST_PROTOCOL_VERSION,
        operation_id: operation_id(80),
        path: "/var/lib/automata-local/desired-spec.json".into(),
        byte_limit: 1_024,
    };
    assert_eq!(
        docker_stdio_once(&resources, &image, &read),
        GuestResponse::ReadOptionalFile {
            protocol: GUEST_PROTOCOL_VERSION,
            file: GuestOptionalFile::Present {
                content_base64: BASE64.encode(content),
            },
        }
    );

    resources.remove();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replay_is_exact_conflicting_and_single_effect_under_concurrency() {
    let server = GuestServer::start("replay-contract").await;
    let marker = server.path("side-effect");
    let request = exec_request(
        "shared-operation",
        "/bin/sh",
        vec![
            "-c".into(),
            "printf x >> \"$1\"; exec /bin/sleep 0.15".into(),
            "guest-test".into(),
            marker.to_string_lossy().into_owned(),
        ],
        BTreeMap::new(),
        "/tmp",
        2_000,
        1,
    );
    let (first, second) = tokio::join!(
        exchange(&server.socket, &request),
        exchange(&server.socket, &request)
    );
    assert_eq!(first, second);
    assert_eq!(tokio::fs::read(&marker).await.unwrap(), b"x");

    let changed = exec_request(
        "shared-operation",
        "/bin/true",
        Vec::new(),
        BTreeMap::new(),
        "/tmp",
        1_000,
        1,
    );
    assert_rejected(
        exchange(&server.socket, &changed).await,
        GuestRejection::OperationConflict,
    );

    tokio::fs::write(&marker, b"outside-change").await.unwrap();
    assert_eq!(exchange(&server.socket, &request).await, first);
    assert_eq!(tokio::fs::read(&marker).await.unwrap(), b"outside-change");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn distinct_exec_operations_execute_concurrently() {
    let server = GuestServer::start("distinct-concurrency").await;
    assert_eq!(
        exchange(
            &server.socket,
            &GuestRequest::Probe {
                protocol: GUEST_PROTOCOL_VERSION,
                operation_id: operation_id(79),
            },
        )
        .await,
        GuestResponse::Ready {
            protocol: GUEST_PROTOCOL_VERSION,
        }
    );
    let release = server.path("release");
    let waiter = exec_request(
        operation_id(80),
        "/bin/sh",
        vec![
            "-c".into(),
            "while [ ! -f \"$1\" ]; do /bin/sleep 0.01; done; printf released".into(),
            "guest-test".into(),
            release.to_string_lossy().into_owned(),
        ],
        BTreeMap::new(),
        "/tmp",
        1_000,
        64,
    );
    let releaser = exec_request(
        operation_id(81),
        "/bin/sh",
        vec![
            "-c".into(),
            "printf release > \"$1\"".into(),
            "guest-test".into(),
            release.to_string_lossy().into_owned(),
        ],
        BTreeMap::new(),
        "/tmp",
        1_000,
        64,
    );
    let waiter_exchange = tokio::spawn({
        let socket = server.socket.clone();
        async move { exchange(&socket, &waiter).await }
    });
    sleep(Duration::from_millis(50)).await;
    let (release_termination, release_records, release_truncated) =
        exec_parts(exchange(&server.socket, &releaser).await);
    assert_eq!(release_termination, GuestTermination::Exited(0));
    assert_complete_streams(&release_records);
    assert!(!release_truncated);
    let (termination, records, truncated) = exec_parts(waiter_exchange.await.unwrap());
    assert_eq!(termination, GuestTermination::Exited(0));
    assert_eq!(output_for(&records, GuestOutputStream::Stdout), b"released");
    assert!(!truncated);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepted_request_completes_and_caches_after_response_transport_is_lost() {
    let server = GuestServer::start("disconnect-replay").await;
    let started = server.path("started");
    let completed = server.path("completed");
    let request = exec_request(
        operation_id(90),
        "/bin/sh",
        vec![
            "-c".into(),
            "printf x >> \"$1\"; /bin/sleep 0.2; printf done > \"$2\"".into(),
            "guest-test".into(),
            started.to_string_lossy().into_owned(),
            completed.to_string_lossy().into_owned(),
        ],
        BTreeMap::new(),
        "/tmp",
        2_000,
        1,
    );
    let mut stream = UnixStream::connect(&server.socket).await.unwrap();
    stream
        .write_all(&encode_frame(&request).unwrap())
        .await
        .unwrap();
    stream.shutdown().await.unwrap();
    timeout(TEST_TIMEOUT, async {
        while !started.exists() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("process starts before client cancellation");
    drop(stream);
    timeout(TEST_TIMEOUT, async {
        while !completed.exists() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("accepted operation completes after response loss");
    assert_eq!(tokio::fs::read(&started).await.unwrap(), b"x");
    let replay = exchange(&server.socket, &request).await;
    let (termination, records, truncated) = exec_parts(replay);
    assert_eq!(termination, GuestTermination::Exited(0));
    assert_complete_streams(&records);
    assert!(!truncated);
    assert_eq!(
        tokio::fs::read(&started).await.unwrap(),
        b"x",
        "lost response retry re-executed the accepted operation"
    );
}

#[tokio::test]
async fn guest_process_replay_capacity_is_non_evicting_and_precedes_execution() {
    let guest = GuestProcess::start("replay-capacity").await;
    let first = GuestRequest::Probe {
        protocol: GUEST_PROTOCOL_VERSION,
        operation_id: operation_id(0),
    };
    let first_response = exchange(&guest.socket, &first).await;
    assert_eq!(
        first_response,
        GuestResponse::Ready {
            protocol: GUEST_PROTOCOL_VERSION,
        }
    );
    for index in 1..256 {
        let request = GuestRequest::Probe {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: operation_id(index),
        };
        assert_eq!(
            exchange(&guest.socket, &request).await,
            GuestResponse::Ready {
                protocol: GUEST_PROTOCOL_VERSION,
            }
        );
    }

    let path = guest.path("must-not-exist");
    let rejected = GuestRequest::WriteFile {
        protocol: GUEST_PROTOCOL_VERSION,
        operation_id: operation_id(256),
        path: path.to_string_lossy().into_owned(),
        content_base64: BASE64.encode(b"must-not-run"),
    };
    assert_rejected(
        exchange(&guest.socket, &rejected).await,
        GuestRejection::ReplayCapacityExceeded,
    );
    assert!(!path.exists(), "capacity rejection must precede execution");
    assert_eq!(exchange(&guest.socket, &first).await, first_response);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn command_line_install_serve_probe_and_stdio_client_are_real() {
    let temp = TempDir::new("command-line");
    for arguments in [
        Vec::<&str>::new(),
        vec!["unknown"],
        vec!["install"],
        vec!["serve"],
        vec!["client"],
        vec!["probe"],
    ] {
        assert!(
            !std::process::Command::new(GUEST_BINARY)
                .args(arguments)
                .status()
                .expect("run invalid command line")
                .success()
        );
    }
    for arguments in [
        vec!["install", "/tmp/automata-unused", "extra"],
        vec!["serve", "/tmp/automata-unused.sock", "extra"],
        vec![
            "serve-vm",
            "/tmp/automata-unused.sock",
            "/tmp/unused",
            "extra",
        ],
        vec!["client", "/tmp/automata-unused.sock", "extra"],
        vec!["stdio-once", "extra"],
        vec!["keepalive", "extra"],
        vec!["probe", "/tmp/automata-unused.sock", "extra"],
    ] {
        assert!(
            !std::process::Command::new(GUEST_BINARY)
                .args(arguments)
                .status()
                .expect("run command line with trailing arguments")
                .success()
        );
    }
    #[cfg(target_os = "linux")]
    for arguments in [
        vec!["serve-local", "extra"],
        vec!["bootstrap-local-client", "extra"],
        vec!["seal-local-client", "extra"],
        vec!["local-client", "extra"],
    ] {
        assert!(
            !std::process::Command::new(GUEST_BINARY)
                .args(arguments)
                .status()
                .expect("run local command line with trailing arguments")
                .success()
        );
    }

    let installed = temp.path().join("installed-guest");
    assert!(
        std::process::Command::new(GUEST_BINARY)
            .args(["install", installed.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        std::fs::read(&installed).unwrap(),
        std::fs::read(GUEST_BINARY).unwrap()
    );
    assert!(
        !std::process::Command::new(GUEST_BINARY)
            .args(["install", temp.path().to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );

    let missing_socket = temp.path().join("missing.sock");
    assert!(
        !std::process::Command::new(GUEST_BINARY)
            .args(["probe", missing_socket.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        !std::process::Command::new(GUEST_BINARY)
            .args([
                "serve",
                temp.path().join("missing/guest.sock").to_str().unwrap(),
            ])
            .status()
            .unwrap()
            .success()
    );

    let socket = temp.path().join("guest.sock");
    let mut server = Command::new(&installed)
        .args(["serve", socket.to_str().unwrap()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("start command-line server");
    timeout(TEST_TIMEOUT, async {
        while !probe(&socket) {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("command-line server becomes ready");
    assert!(
        std::process::Command::new(&installed)
            .args(["probe", socket.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );

    let request = exec_request(
        FIRST_OPERATION,
        "/bin/sh",
        vec!["-c".into(), "printf client-output".into()],
        BTreeMap::new(),
        "/tmp",
        1_000,
        64,
    );
    let mut client = Command::new(&installed)
        .args(["client", socket.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("start stdio forwarding client");
    let mut stdin = client.stdin.take().unwrap();
    stdin
        .write_all(&encode_frame(&request).unwrap())
        .await
        .unwrap();
    drop(stdin);
    let output = timeout(TEST_TIMEOUT, client.wait_with_output())
        .await
        .expect("client completes")
        .expect("wait for client");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let (termination, records, truncated) =
        exec_parts(decode_frame(&output.stdout).expect("client writes one exact frame"));
    assert_eq!(termination, GuestTermination::Exited(0));
    assert_eq!(
        output_for(&records, GuestOutputStream::Stdout),
        b"client-output"
    );
    assert!(!truncated);

    let mut unavailable = Command::new(&installed)
        .args(["client", missing_socket.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    unavailable
        .stdin
        .take()
        .unwrap()
        .write_all(&encode_frame(&request).unwrap())
        .await
        .unwrap();
    assert!(!unavailable.wait().await.unwrap().success());

    server.kill().await.expect("stop command-line server");
    let _ = server.wait().await;
}

#[cfg(target_os = "linux")]
#[test]
fn command_line_install_fails_when_current_exe_cannot_be_resolved() {
    let temp = TempDir::new("command-line-install-current-exe-failure");
    let installed = temp.path().join("installed-guest");
    let status = namespace_without_proc()
        .arg(GUEST_BINARY)
        .arg("install")
        .arg(&installed)
        .status()
        .expect("run install without /proc/self/exe");
    assert!(
        !status.success(),
        "install should fail when current_exe cannot resolve without /proc"
    );
    assert!(!installed.exists());
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn command_line_serve_stops_accepting_after_sigterm() {
    let temp = TempDir::new("command-line-serve-sigterm");
    let socket = temp.path().join("guest.sock");
    let mut server = Command::new(GUEST_BINARY)
        .args(["serve", socket.to_str().unwrap()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start command-line server");
    timeout(TEST_TIMEOUT, async {
        while !probe(&socket) {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("command-line server becomes ready");

    std::process::Command::new("/usr/bin/kill")
        .args([
            "-TERM",
            &server.id().expect("running server pid").to_string(),
        ])
        .status()
        .expect("send SIGTERM to command-line server");
    let status = timeout(TEST_TIMEOUT, server.wait())
        .await
        .expect("server exits after SIGTERM")
        .expect("wait for terminated server");
    assert_eq!(status.signal(), Some(15));
    timeout(TEST_TIMEOUT, async {
        while probe(&socket) {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("probe stops succeeding after SIGTERM");
}
