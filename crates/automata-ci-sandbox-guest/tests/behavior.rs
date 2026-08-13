#![cfg(unix)]

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    io,
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
    GUEST_PROTOCOL_VERSION, GuestOutputStream, GuestProtocolError, GuestRejection, GuestRequest,
    GuestResponse, GuestTermination, MAX_GUEST_FRAME_BYTES, decode_frame, encode_frame, probe,
    serve,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Serialize, ser::Error as _};
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
        let frame = read_wire_frame(&mut stream).await.expect("read response");
        decode_frame(&frame).expect("decode response")
    })
    .await
    .expect("guest exchange completes")
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
        panic!("expected execution response");
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
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listener_lifecycle_protocol_and_malformed_connections_fail_closed() {
    let temp = TempDir::new("listener-lifecycle");
    let socket = temp.path().join("guest.sock");
    assert!(!probe(&socket));
    std::fs::write(&socket, b"stale socket path").expect("create stale path");
    let task = spawn_server(socket.clone()).await;
    assert!(probe(&socket));

    let unsupported = GuestRequest::ReadFile {
        protocol: GUEST_PROTOCOL_VERSION + 1,
        operation_id: FIRST_OPERATION.into(),
        path: "/tmp/unreached".into(),
        byte_limit: 1,
    };
    assert_rejected(
        exchange(&socket, &unsupported).await,
        GuestRejection::UnsupportedProtocol,
    );

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
async fn distinct_operations_execute_concurrently() {
    let server = GuestServer::start("distinct-concurrency").await;
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
    let releaser = GuestRequest::WriteFile {
        protocol: GUEST_PROTOCOL_VERSION,
        operation_id: operation_id(81),
        path: release.to_string_lossy().into_owned(),
        content_base64: BASE64.encode(b"release"),
    };
    let waiter_exchange = tokio::spawn({
        let socket = server.socket.clone();
        async move { exchange(&socket, &waiter).await }
    });
    sleep(Duration::from_millis(50)).await;
    assert_eq!(
        exchange(&server.socket, &releaser).await,
        GuestResponse::WriteFile {
            protocol: GUEST_PROTOCOL_VERSION
        }
    );
    let (termination, records, truncated) = exec_parts(waiter_exchange.await.unwrap());
    assert_eq!(termination, GuestTermination::Exited(0));
    assert_eq!(output_for(&records, GuestOutputStream::Stdout), b"released");
    assert!(!truncated);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnect_cancels_the_in_flight_process_group() {
    let server = GuestServer::start("disconnect-cancellation").await;
    let started = server.path("started");
    let leaked = server.path("leaked");
    let request = exec_request(
        operation_id(90),
        "/bin/sh",
        vec![
            "-c".into(),
            "printf started > \"$1\"; /bin/sleep 0.4; printf leaked > \"$2\"".into(),
            "guest-test".into(),
            started.to_string_lossy().into_owned(),
            leaked.to_string_lossy().into_owned(),
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
    timeout(TEST_TIMEOUT, async {
        while !started.exists() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("process starts before client cancellation");
    drop(stream);
    sleep(Duration::from_millis(650)).await;
    assert!(
        !leaked.exists(),
        "a disconnected client left its process running"
    );
}

#[tokio::test]
async fn completed_replay_entries_are_bounded_and_oldest_first() {
    let server = GuestServer::start("replay-eviction").await;
    let path = server.path("replay-value");
    let mut first = None;
    for index in 0..=256 {
        let request = GuestRequest::WriteFile {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: format!("eviction-{index:03}"),
            path: path.to_string_lossy().into_owned(),
            content_base64: BASE64.encode(index.to_string()),
        };
        if index == 0 {
            first = Some(request.clone());
        }
        assert!(matches!(
            exchange(&server.socket, &request).await,
            GuestResponse::WriteFile { .. }
        ));
    }
    tokio::fs::write(&path, b"outside").await.unwrap();
    assert!(matches!(
        exchange(&server.socket, &first.unwrap()).await,
        GuestResponse::WriteFile { .. }
    ));
    assert_eq!(tokio::fs::read(path).await.unwrap(), b"0");
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
