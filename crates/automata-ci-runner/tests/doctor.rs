use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    thread::{self, JoinHandle},
    time::Duration,
};

#[cfg(not(target_os = "linux"))]
use automata_ci_runner::capability_probe::{
    PODMAN_NETWORK_ISOLATION, ProbeReasonCode, ProbeStatus,
};
#[cfg(not(target_os = "linux"))]
use automata_ci_runner::doctor::inspect_with_options;
use automata_ci_runner::doctor::{
    ServerHttpPolicy, ServerHttpPolicyError, ServerStatus, inspect, probe_server_with_policy,
};

#[test]
fn server_policy_rejects_zero_limits() {
    assert_eq!(
        ServerHttpPolicy::new(Duration::ZERO, Duration::from_secs(1), 1),
        Err(ServerHttpPolicyError::ZeroConnectTimeout)
    );
    assert_eq!(
        ServerHttpPolicy::new(Duration::from_secs(1), Duration::ZERO, 1),
        Err(ServerHttpPolicyError::ZeroRequestTimeout)
    );
    assert_eq!(
        ServerHttpPolicy::new(Duration::from_secs(1), Duration::from_secs(1), 0),
        Err(ServerHttpPolicyError::ZeroResponseLimit)
    );
}

#[tokio::test]
async fn reports_a_healthy_server_with_structured_status() {
    let (server, worker) = serve_once("200 OK");

    let report = inspect(Some(&server)).await;
    let server_probe = report.server().expect("server probe must be included");
    assert_eq!(server_probe.status(), ServerStatus::Healthy);
    assert!(server_probe.is_healthy());
    assert!(server_probe.detail().is_none());
    assert!(report.is_healthy());

    worker.join().expect("mock server must finish");
}

#[tokio::test]
async fn distinguishes_an_unhealthy_http_response_from_unreachability() {
    let (server, worker) = serve_once("503 Service Unavailable");

    let report = inspect(Some(&server)).await;
    let server_probe = report.server().expect("server probe must be included");
    assert_eq!(server_probe.status(), ServerStatus::Unhealthy);
    assert!(!server_probe.is_healthy());
    assert!(!report.is_healthy());
    assert!(server_probe.detail().is_some());

    worker.join().expect("mock server must finish");
}

#[tokio::test]
async fn rejects_an_oversized_declared_health_body_before_waiting_for_it() {
    let (server, worker) = serve_reply(Reply::declared_then_stall(65, Duration::from_millis(150)));
    let policy = ServerHttpPolicy::new(Duration::from_millis(100), Duration::from_millis(50), 64)
        .expect("test policy must be valid");

    let probe = probe_server_with_policy(&server, policy).await;

    assert_eq!(probe.status(), ServerStatus::Unhealthy);
    assert_eq!(
        probe.detail(),
        Some("server health response exceeds the 64-byte limit")
    );
    worker.join().expect("mock server must finish");
}

#[tokio::test]
async fn counts_chunked_health_bodies_while_streaming() {
    let secret_body = b"body-secret-that-must-not-appear";
    let (server, worker) = serve_reply(Reply::chunked("200 OK", secret_body));
    let policy = ServerHttpPolicy::new(Duration::from_secs(1), Duration::from_secs(1), 8)
        .expect("test policy must be valid");

    let probe = probe_server_with_policy(&server, policy).await;

    assert_eq!(probe.status(), ServerStatus::Unhealthy);
    let detail = probe.detail().expect("failure detail must be present");
    assert!(detail.contains("8-byte limit"));
    assert!(!detail.contains("body-secret"));
    worker.join().expect("mock server must finish");
}

#[tokio::test]
async fn total_request_timeout_covers_a_stalled_health_body() {
    let (server, worker) = serve_reply(Reply::body_after_delay(
        "200 OK",
        b"ok",
        Duration::from_millis(150),
    ));
    let policy = ServerHttpPolicy::new(Duration::from_millis(100), Duration::from_millis(30), 64)
        .expect("test policy must be valid");

    let probe = probe_server_with_policy(&server, policy).await;

    assert_eq!(probe.status(), ServerStatus::Unreachable);
    let detail = probe.detail().expect("failure detail must be present");
    assert!(detail.contains("timed out"));
    worker.join().expect("mock server must finish");
}

#[tokio::test]
async fn rejects_untrusted_server_origins_without_disclosing_the_input() {
    let policy = ServerHttpPolicy::new(Duration::from_millis(10), Duration::from_millis(10), 64)
        .expect("test policy must be valid");

    for server in [
        "http://runner:server-secret@127.0.0.1:1",
        "http://localhost:1",
        "http://192.0.2.1:8080",
        "http://127.0.0.1:1/base",
        "http://127.0.0.1:1/?query=secret",
        "http://127.0.0.1:1/#fragment-secret",
        "https://example.invalid/base",
        "ftp://127.0.0.1/",
        "relative-server",
    ] {
        let probe = probe_server_with_policy(server, policy).await;

        assert_eq!(probe.status(), ServerStatus::Unreachable, "{server}");
        assert_eq!(probe.endpoint(), "invalid control-plane health endpoint");
        assert_eq!(
            probe.detail(),
            Some("server health endpoint failed transport policy")
        );
        assert!(!probe.endpoint().contains("secret"));
        assert!(!probe.detail().unwrap_or_default().contains("secret"));
    }
}

#[tokio::test]
async fn does_not_follow_server_health_redirects() {
    let unused_listener = TcpListener::bind("127.0.0.1:0").expect("unused port must be reservable");
    let redirect_target = format!(
        "http://{}/healthz",
        unused_listener
            .local_addr()
            .expect("unused address must exist")
    );
    drop(unused_listener);
    let (server, worker) = serve_reply(Reply::Redirect {
        location: redirect_target,
    });
    let policy = ServerHttpPolicy::new(Duration::from_secs(1), Duration::from_secs(1), 64)
        .expect("test policy must be valid");

    let probe = probe_server_with_policy(&server, policy).await;

    assert_eq!(probe.status(), ServerStatus::Unhealthy);
    assert_eq!(probe.detail(), Some("server returned HTTP 302 Found"));
    worker.join().expect("mock server must finish");
}

#[tokio::test]
async fn serializes_capability_evidence_separately_from_advertised_capabilities() {
    let report = inspect(None).await;
    let json = serde_json::to_value(&report).expect("doctor report must serialize");

    assert!(json["capabilities"].is_array());
    assert!(json["capability_probes"].is_array());
    assert!(
        json["capability_probes"]
            .as_array()
            .expect("probes must be an array")
            .iter()
            .all(|probe| probe["status"].is_string() && probe["detail"].is_string())
    );
}

#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn active_doctor_reports_unsupported_platform_without_advertising_isolation() {
    let report = inspect_with_options(None, true).await;
    let probe = report
        .capability_probes()
        .iter()
        .find(|probe| probe.capability() == PODMAN_NETWORK_ISOLATION)
        .expect("active diagnostics must include Podman isolation evidence");

    assert_eq!(probe.status(), ProbeStatus::Unavailable);
    assert_eq!(
        probe
            .reason()
            .expect("unsupported evidence must include a reason")
            .code(),
        ProbeReasonCode::ActiveProbeUnsupportedPlatform
    );
    assert!(!probe.is_usable());
    assert!(!report.capabilities().contains(PODMAN_NETWORK_ISOLATION));
    assert!(!report.is_healthy());
}

fn serve_once(status: &'static str) -> (String, JoinHandle<()>) {
    serve_reply(Reply::complete(status, b"ok"))
}

enum Reply {
    Complete {
        status: &'static str,
        body: &'static [u8],
    },
    Chunked {
        status: &'static str,
        body: &'static [u8],
    },
    DeclaredThenStall {
        length: usize,
        delay: Duration,
    },
    BodyAfterDelay {
        status: &'static str,
        body: &'static [u8],
        delay: Duration,
    },
    Redirect {
        location: String,
    },
}

impl Reply {
    const fn complete(status: &'static str, body: &'static [u8]) -> Self {
        Self::Complete { status, body }
    }

    const fn chunked(status: &'static str, body: &'static [u8]) -> Self {
        Self::Chunked { status, body }
    }

    const fn declared_then_stall(length: usize, delay: Duration) -> Self {
        Self::DeclaredThenStall { length, delay }
    }

    const fn body_after_delay(status: &'static str, body: &'static [u8], delay: Duration) -> Self {
        Self::BodyAfterDelay {
            status,
            body,
            delay,
        }
    }
}

fn serve_reply(reply: Reply) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("mock server must bind");
    let address = listener.local_addr().expect("mock address must exist");
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("mock server must accept");
        let mut request = [0_u8; 2048];
        let _bytes_read = stream.read(&mut request).expect("request must be readable");

        match reply {
            Reply::Complete { status, body } => {
                write_headers(&mut stream, status, Some(body.len()), false);
                stream.write_all(body).expect("body must be writable");
            }
            Reply::Chunked { status, body } => {
                write_headers(&mut stream, status, None, true);
                write!(&mut stream, "{:x}\r\n", body.len()).expect("chunk size must be writable");
                stream.write_all(body).expect("chunk must be writable");
                stream
                    .write_all(b"\r\n0\r\n\r\n")
                    .expect("chunk terminator must be writable");
            }
            Reply::DeclaredThenStall { length, delay } => {
                write_headers(&mut stream, "200 OK", Some(length), false);
                thread::sleep(delay);
            }
            Reply::BodyAfterDelay {
                status,
                body,
                delay,
            } => {
                write_headers(&mut stream, status, Some(body.len()), false);
                thread::sleep(delay);
                let _client_may_have_timed_out = stream.write_all(body);
            }
            Reply::Redirect { location } => {
                write!(
                    &mut stream,
                    "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .expect("redirect must be writable");
                stream.flush().expect("redirect must be flushed");
            }
        }
    });

    (format!("http://{address}"), worker)
}

fn write_headers(
    stream: &mut std::net::TcpStream,
    status: &str,
    content_length: Option<usize>,
    chunked: bool,
) {
    write!(stream, "HTTP/1.1 {status}\r\n").expect("status must be writable");
    if let Some(length) = content_length {
        write!(stream, "Content-Length: {length}\r\n").expect("length must be writable");
    }
    if chunked {
        stream
            .write_all(b"Transfer-Encoding: chunked\r\n")
            .expect("transfer encoding must be writable");
    }
    stream
        .write_all(b"Connection: close\r\n\r\n")
        .expect("header terminator must be writable");
    stream.flush().expect("headers must be flushed");
}
