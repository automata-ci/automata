#![cfg(unix)]

use std::{
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    net::TcpListener,
    os::unix::fs::OpenOptionsExt as _,
    path::PathBuf,
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use uuid::Uuid;

#[test]
fn internal_command_initializes_the_exact_bucket_through_production_s3() {
    let fixture = SecureSources::new();
    let access_key = fixture.write("access-key", b"test-access");
    let secret_key = fixture.write("secret-key", b"test-secret");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind internal S3 fixture");
    let address = listener.local_addr().expect("internal S3 fixture address");
    listener
        .set_nonblocking(true)
        .expect("nonblocking internal S3 fixture");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let task_requests = Arc::clone(&requests);
    let task = thread::spawn(move || {
        let statuses = ["404 Not Found", "200 OK", "200 OK"];
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut served = 0;
        while served < statuses.len() && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(10)))
                        .expect("internal S3 read timeout");
                    let mut request = Vec::new();
                    let mut buffer = [0_u8; 4 * 1_024];
                    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                        let received = stream.read(&mut buffer).expect("internal S3 request");
                        if received == 0 {
                            break;
                        }
                        request.extend_from_slice(&buffer[..received]);
                    }
                    let request = String::from_utf8(request).expect("internal S3 request text");
                    let first_line = request
                        .lines()
                        .next()
                        .and_then(|line| line.strip_suffix(" HTTP/1.1"))
                        .expect("internal S3 request line");
                    task_requests
                        .lock()
                        .expect("internal S3 request lock")
                        .push(first_line.to_owned());
                    write!(
                        stream,
                        "HTTP/1.1 {}\r\ncontent-length: 0\r\nconnection: close\r\nx-amz-request-id: process-fixture\r\n\r\n",
                        statuses[served]
                    )
                    .expect("internal S3 response");
                    served += 1;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("internal S3 accept failed: {error}"),
            }
        }
        assert_eq!(served, statuses.len(), "internal S3 request count");
    });

    let output = Command::new(env!("CARGO_BIN_EXE_automata"))
        .args([
            "internal",
            "object-store",
            "ensure-bucket",
            "--s3-endpoint",
            &format!("http://{address}/"),
            "--s3-bucket",
            "automata-tests",
            "--s3-allow-loopback-http",
            "--s3-operation-timeout-seconds",
            "5",
            "--s3-access-key-source",
            &format!("file:{}", access_key.display()),
            "--s3-secret-key-source",
            &format!("file:{}", secret_key.display()),
        ])
        .output()
        .expect("run internal object-store initializer");
    task.join().expect("internal S3 fixture task");

    assert!(
        output.status.success(),
        "internal initializer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"object-store bucket ready\n");
    assert!(output.stderr.is_empty());
    assert_eq!(
        *requests.lock().expect("internal S3 request lock"),
        [
            "HEAD /automata-tests/",
            "PUT /automata-tests/",
            "HEAD /automata-tests/"
        ]
    );
}

#[test]
fn internal_private_ca_load_failure_is_bounded_and_sanitized() {
    let fixture = SecureSources::new();
    let marker = "private-ca-content-must-never-escape";
    let ca = fixture.write("private-ca", marker.as_bytes());
    let output = Command::new(env!("CARGO_BIN_EXE_automata"))
        .args([
            "internal",
            "object-store",
            "ensure-bucket",
            "--s3-endpoint",
            "https://127.0.0.1:1/",
            "--s3-tls-trust",
            "private-ca",
            "--s3-private-ca-source",
            &format!("file:{}", ca.display()),
        ])
        .output()
        .expect("run invalid private-CA initializer");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("referenced certificate is invalid"));
    assert!(!stderr.contains(marker));
    assert!(!stderr.contains(&ca.display().to_string()));
}

struct SecureSources {
    directory: PathBuf,
}

impl SecureSources {
    fn new() -> Self {
        let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join("internal-object-store")
            .join(Uuid::new_v4().to_string());
        fs::create_dir_all(&directory).expect("create secure source directory");
        Self { directory }
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.directory.join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("create secure source");
        file.write_all(bytes).expect("write secure source");
        path
    }
}

impl Drop for SecureSources {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.directory);
    }
}
