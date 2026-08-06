use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    thread::{self, JoinHandle},
    time::Duration,
};

use automata::cli::{
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
    let body = br#"{"status":"ok","version":"test","commit":"abc"}"#;
    let (server, worker) = serve_once(Reply::complete("200 OK", body));

    let health = fetch_control_plane_status(&server, StatusHttpPolicy::default())
        .await
        .expect("bounded health document must be accepted");

    assert_eq!(health["status"], "ok");
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
    let credentialed_server = server.replacen("http://", "http://operator:server-secret@", 1);
    let policy = StatusHttpPolicy::new(Duration::from_millis(100), Duration::from_millis(30), 64)
        .expect("test policy must be valid");

    let error = fetch_control_plane_status(&credentialed_server, policy)
        .await
        .expect_err("stalled body must time out");
    let display = error.to_string();

    assert!(matches!(error, StatusRequestError::ResponseRead(_)));
    assert!(display.contains("timed out"));
    assert!(!display.contains("server-secret"));
    worker.join().expect("mock server must finish");
}

#[tokio::test]
async fn invalid_json_errors_do_not_echo_response_content() {
    let secret_body = b"invalid-document-secret";
    let (server, worker) = serve_once(Reply::complete("200 OK", secret_body));

    let error = fetch_control_plane_status(&server, StatusHttpPolicy::default())
        .await
        .expect_err("invalid JSON must be rejected");

    assert!(matches!(&error, StatusRequestError::InvalidDocument(_)));
    assert!(!error.to_string().contains("invalid-document-secret"));
    worker.join().expect("mock server must finish");
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

fn serve_once(reply: Reply) -> (String, JoinHandle<()>) {
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
