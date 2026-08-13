use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    process::Command,
    thread::{self, JoinHandle},
    time::Duration,
};

use automata_ci::cli::{
    StatusHttpPolicy, StatusHttpPolicyError, StatusRequestError, fetch_control_plane_status,
};

#[test]
fn status_policy_has_bounded_defaults_and_rejects_zero_limits() {
    let policy = StatusHttpPolicy::default();
    assert_eq!(policy.connect_timeout(), Duration::from_secs(5));
    assert_eq!(policy.request_timeout(), Duration::from_secs(10));
    assert_eq!(policy.max_response_bytes(), 64 * 1024);

    assert_eq!(
        StatusHttpPolicy::new(Duration::ZERO, Duration::from_secs(1), 1),
        Err(StatusHttpPolicyError::ZeroConnectTimeout)
    );
    assert_eq!(
        StatusHttpPolicy::new(Duration::from_secs(1), Duration::ZERO, 1),
        Err(StatusHttpPolicyError::ZeroRequestTimeout)
    );
    assert_eq!(
        StatusHttpPolicy::new(Duration::from_secs(1), Duration::from_secs(1), 0),
        Err(StatusHttpPolicyError::ZeroResponseLimit)
    );
}

#[tokio::test]
async fn fetches_a_health_document_within_the_limit() {
    let body = br#"{"status":"ok","version":"0.1.0-test","commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
    let (server, worker) = serve_replies(vec![
        Reply::complete("200 OK", body),
        Reply::complete("200 OK", b"ready\n"),
    ]);

    let status = fetch_control_plane_status(&server, StatusHttpPolicy::default())
        .await
        .expect("bounded status documents must be accepted");

    assert_eq!(
        status,
        serde_json::json!({
            "health": {
                "status": "ok",
                "version": "0.1.0-test",
                "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            },
            "readiness": {"ready": true}
        })
    );
    worker.join().expect("mock server must finish");
}

#[test]
fn admin_status_process_has_exact_success_streams_and_exit_status() {
    let body = br#"{"status":"ok","version":"0.1.0-test","commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
    let (server, worker) = serve_replies(vec![
        Reply::complete("200 OK", body),
        Reply::complete("200 OK", b"ready\n"),
    ]);

    let output = Command::new(env!("CARGO_BIN_EXE_automata"))
        .args(["admin", "--server-url", &server, "status"])
        .env_remove("RUST_LOG")
        .output()
        .expect("admin status process must run");

    assert!(output.status.success(), "stderr: {:?}", output.stderr);
    assert_eq!(
        output.stdout,
        b"health.status\tok\nhealth.version\t0.1.0-test\nhealth.commit\taaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nreadiness.ready\ttrue\n"
    );
    assert!(output.stderr.is_empty());
    worker.join().expect("mock server must finish");
}

#[test]
fn admin_status_process_keeps_not_ready_inspectable() {
    let body = br#"{"status":"ok","version":"0.1.0-test","commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
    let (server, worker) = serve_replies(vec![
        Reply::complete("200 OK", body),
        Reply::complete("503 Service Unavailable", b"not ready\n"),
    ]);

    let output = Command::new(env!("CARGO_BIN_EXE_automata"))
        .args([
            "admin",
            "--server-url",
            &server,
            "status",
            "--output",
            "json",
        ])
        .env_remove("RUST_LOG")
        .output()
        .expect("admin status process must run");

    assert!(output.status.success(), "stderr: {:?}", output.stderr);
    assert_eq!(
        output.stdout,
        b"{\"health\":{\"commit\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"status\":\"ok\",\"version\":\"0.1.0-test\"},\"readiness\":{\"ready\":false}}\n"
    );
    assert!(output.stderr.is_empty());
    worker.join().expect("mock server must finish");
}

#[tokio::test]
async fn reports_exact_dependency_not_ready_truth_without_hiding_process_identity() {
    let body = br#"{"status":"ok","version":"0.1.0-test","commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
    let (server, worker) = serve_replies(vec![
        Reply::complete("200 OK", body),
        Reply::complete("503 Service Unavailable", b"not ready\n"),
    ]);

    let status = fetch_control_plane_status(&server, StatusHttpPolicy::default())
        .await
        .expect("exact not-ready document must remain inspectable");

    assert_eq!(status["health"]["status"], "ok");
    assert_eq!(status["readiness"]["ready"], false);
    assert_eq!(status["health"]["version"], "0.1.0-test");
    worker.join().expect("mock server must finish");
}

#[tokio::test]
async fn rejects_a_readiness_status_and_body_disagreement() {
    let body = br#"{"status":"ok","version":"0.1.0-test","commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
    let (server, worker) = serve_replies(vec![
        Reply::complete("200 OK", body),
        Reply::complete("200 OK", b"not ready\n"),
    ]);

    let error = fetch_control_plane_status(&server, StatusHttpPolicy::default())
        .await
        .expect_err("readiness status and body must agree exactly");

    assert!(matches!(error, StatusRequestError::InvalidDocument));
    worker.join().expect("mock server must finish");
}

#[tokio::test]
async fn rejects_non_200_health_and_noncanonical_status_headers() {
    let body = br#"{"status":"ok","version":"0.1.0-test","commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
    let (server, worker) = serve_once(Reply::complete("204 No Content", b""));
    let error = fetch_control_plane_status(&server, StatusHttpPolicy::default())
        .await
        .expect_err("health must be exactly HTTP 200");
    assert!(matches!(
        error,
        StatusRequestError::Unhealthy(reqwest::StatusCode::NO_CONTENT)
    ));
    worker.join().expect("mock server must finish");

    for policy in [
        HeaderPolicy::MissingContentType,
        HeaderPolicy::DuplicateContentType,
        HeaderPolicy::WrongCacheControl,
        HeaderPolicy::WrongNosniff,
    ] {
        let (server, worker) = serve_once(Reply::complete_with_headers("200 OK", body, policy));
        let error = fetch_control_plane_status(&server, StatusHttpPolicy::default())
            .await
            .expect_err("noncanonical health headers must fail closed");
        assert!(matches!(error, StatusRequestError::InvalidDocument));
        worker.join().expect("mock server must finish");
    }

    let (server, worker) = serve_replies(vec![
        Reply::complete("200 OK", body),
        Reply::complete_with_headers("200 OK", b"ready\n", HeaderPolicy::WrongCacheControl),
    ]);
    let error = fetch_control_plane_status(&server, StatusHttpPolicy::default())
        .await
        .expect_err("noncanonical readiness headers must fail closed");
    assert!(matches!(error, StatusRequestError::InvalidDocument));
    worker.join().expect("mock server must finish");
}

#[test]
fn admin_status_process_fails_without_stdout_or_response_reflection() {
    let body = b"status-process-secret";
    let (server, worker) = serve_once(Reply::complete_with_headers(
        "200 OK",
        body,
        HeaderPolicy::WrongCacheControl,
    ));

    let output = Command::new(env!("CARGO_BIN_EXE_automata"))
        .args(["admin", "--server-url", &server, "status"])
        .env_remove("RUST_LOG")
        .output()
        .expect("admin status process must run");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("stderr must be UTF-8");
    assert!(stderr.contains("failed to retrieve control-plane status"));
    assert!(stderr.contains("invalid status document"));
    assert!(!stderr.contains("status-process-secret"));
    worker.join().expect("mock server must finish");
}

#[tokio::test]
async fn rejects_an_oversized_declared_body_before_waiting_for_it() {
    let (server, worker) = serve_once(Reply::declared_then_stall(65, Duration::from_millis(150)));
    let policy = StatusHttpPolicy::new(Duration::from_millis(100), Duration::from_millis(50), 64)
        .expect("test policy must be valid");

    let error = fetch_control_plane_status(&server, policy)
        .await
        .expect_err("oversized declared body must be rejected");

    assert!(matches!(
        error,
        StatusRequestError::ResponseTooLarge { limit: 64 }
    ));
    worker.join().expect("mock server must finish");
}

#[tokio::test]
async fn counts_chunked_responses_while_streaming() {
    let secret_body = b"body-secret-that-must-not-appear";
    let (server, worker) = serve_once(Reply::chunked("200 OK", secret_body));
    let policy = StatusHttpPolicy::new(Duration::from_secs(1), Duration::from_secs(1), 8)
        .expect("test policy must be valid");

    let error = fetch_control_plane_status(&server, policy)
        .await
        .expect_err("oversized chunked body must be rejected");

    assert!(matches!(
        &error,
        StatusRequestError::ResponseTooLarge { limit: 8 }
    ));
    assert!(!error.to_string().contains("body-secret"));
    worker.join().expect("mock server must finish");
}

#[tokio::test]
async fn total_request_timeout_covers_a_stalled_response_body() {
    let (server, worker) = serve_once(Reply::body_after_delay(
        "200 OK",
        b"{}",
        Duration::from_millis(150),
    ));
    let policy = StatusHttpPolicy::new(Duration::from_millis(100), Duration::from_millis(30), 64)
        .expect("test policy must be valid");

    let error = fetch_control_plane_status(&server, policy)
        .await
        .expect_err("stalled body must time out");
    let display = error.to_string();

    assert!(matches!(error, StatusRequestError::ResponseRead(_)));
    assert!(display.contains("timed out"));
    assert!(!display.contains("server-secret"));
    worker.join().expect("mock server must finish");
}

#[tokio::test]
async fn rejects_unreviewed_origins_without_reflecting_credentials() {
    for server in [
        "http://control.example.test",
        "http://localhost:8080",
        "https://operator:server-secret@control.example.test",
        "https://control.example.test/base",
        "https://control.example.test/?secret=query-secret",
    ] {
        let error = fetch_control_plane_status(server, StatusHttpPolicy::default())
            .await
            .expect_err("unreviewed status origin must fail before transport");
        assert!(matches!(error, StatusRequestError::EndpointPolicy));
        for surface in [error.to_string(), format!("{error:?}")] {
            assert!(!surface.contains("server-secret"));
            assert!(!surface.contains("query-secret"));
        }
    }
}

#[tokio::test]
async fn invalid_json_errors_do_not_echo_response_content() {
    let secret_body = b"invalid-document-secret";
    let (server, worker) = serve_once(Reply::complete("200 OK", secret_body));

    let error = fetch_control_plane_status(&server, StatusHttpPolicy::default())
        .await
        .expect_err("invalid JSON must be rejected");

    assert!(matches!(&error, StatusRequestError::InvalidDocument));
    assert!(!error.to_string().contains("invalid-document-secret"));
    worker.join().expect("mock server must finish");
}

enum Reply {
    Complete {
        status: &'static str,
        body: &'static [u8],
        headers: HeaderPolicy,
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
}

#[derive(Clone, Copy)]
enum HeaderPolicy {
    Current,
    MissingContentType,
    DuplicateContentType,
    WrongCacheControl,
    WrongNosniff,
}

impl Reply {
    const fn complete(status: &'static str, body: &'static [u8]) -> Self {
        Self::Complete {
            status,
            body,
            headers: HeaderPolicy::Current,
        }
    }

    const fn complete_with_headers(
        status: &'static str,
        body: &'static [u8],
        headers: HeaderPolicy,
    ) -> Self {
        Self::Complete {
            status,
            body,
            headers,
        }
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

fn serve_once(reply: Reply) -> (String, JoinHandle<()>) {
    serve_replies(vec![reply])
}

fn serve_replies(replies: Vec<Reply>) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("mock server must bind");
    let address = listener.local_addr().expect("mock address must exist");
    let worker = thread::spawn(move || {
        for (index, reply) in replies.into_iter().enumerate() {
            let (mut stream, _) = listener.accept().expect("mock server must accept");
            let mut request = [0_u8; 2048];
            let bytes_read = stream.read(&mut request).expect("request must be readable");
            let request = String::from_utf8_lossy(&request[..bytes_read]);
            let expected_target = if index == 0 { "/healthz" } else { "/readyz" };
            assert!(
                request.starts_with(&format!("GET {expected_target} HTTP/1.1\r\n")),
                "unexpected status request target: {request:?}"
            );
            let lowercase_request = request.to_ascii_lowercase();
            assert!(!lowercase_request.contains("\r\nauthorization:"));
            assert!(!lowercase_request.contains("\r\ncookie:"));
            write_reply(&mut stream, &reply, index);
        }
    });

    (format!("http://{address}"), worker)
}

fn write_reply(stream: &mut std::net::TcpStream, reply: &Reply, request_index: usize) {
    match reply {
        Reply::Complete {
            status,
            body,
            headers,
        } => {
            write_headers(
                stream,
                status,
                Some(body.len()),
                false,
                request_index,
                *headers,
            );
            stream.write_all(body).expect("body must be writable");
        }
        Reply::Chunked { status, body } => {
            write_headers(
                stream,
                status,
                None,
                true,
                request_index,
                HeaderPolicy::Current,
            );
            write!(stream, "{:x}\r\n", body.len()).expect("chunk size must be writable");
            stream.write_all(body).expect("chunk must be writable");
            stream
                .write_all(b"\r\n0\r\n\r\n")
                .expect("chunk terminator must be writable");
        }
        Reply::DeclaredThenStall { length, delay } => {
            write_headers(
                stream,
                "200 OK",
                Some(*length),
                false,
                request_index,
                HeaderPolicy::Current,
            );
            thread::sleep(*delay);
        }
        Reply::BodyAfterDelay {
            status,
            body,
            delay,
        } => {
            write_headers(
                stream,
                status,
                Some(body.len()),
                false,
                request_index,
                HeaderPolicy::Current,
            );
            thread::sleep(*delay);
            let _client_may_have_timed_out = stream.write_all(body);
        }
    }
}

fn write_headers(
    stream: &mut std::net::TcpStream,
    status: &str,
    content_length: Option<usize>,
    chunked: bool,
    request_index: usize,
    policy: HeaderPolicy,
) {
    write!(stream, "HTTP/1.1 {status}\r\n").expect("status must be writable");
    let content_type = if request_index == 0 {
        "application/json"
    } else {
        "text/plain; charset=utf-8"
    };
    if !matches!(policy, HeaderPolicy::MissingContentType) {
        write!(stream, "Content-Type: {content_type}\r\n").expect("content type must be writable");
    }
    if matches!(policy, HeaderPolicy::DuplicateContentType) {
        write!(stream, "Content-Type: {content_type}\r\n")
            .expect("duplicate content type must be writable");
    }
    let cache_control = if matches!(policy, HeaderPolicy::WrongCacheControl) {
        "public"
    } else {
        "no-store"
    };
    write!(stream, "Cache-Control: {cache_control}\r\n").expect("cache control must be writable");
    let nosniff = if matches!(policy, HeaderPolicy::WrongNosniff) {
        "no"
    } else {
        "nosniff"
    };
    write!(stream, "X-Content-Type-Options: {nosniff}\r\n").expect("nosniff must be writable");
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
