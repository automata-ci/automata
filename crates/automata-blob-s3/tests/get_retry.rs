use std::{
    collections::VecDeque,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use automata_blob::{
    BlobDescriptor, BlobKey, BlobPayload, BlobStoreErrorKind, ImmutableBlobStore, MediaType,
};
use automata_blob_s3::{S3BlobStore, S3BlobStoreConfig, StaticS3Credentials};
use bytes::Bytes;
use tokio::{
    net::{TcpListener, TcpStream},
    task::{JoinHandle, JoinSet},
    time::Instant,
};
use url::Url;

const TOTAL_ATTEMPTS: usize = 3;

#[tokio::test]
async fn retries_a_fresh_get_after_a_mid_body_fin() {
    let body = fixture_body();
    let descriptor = descriptor(&body);
    let fixture = S3Fixture::spawn(
        descriptor.clone(),
        body.clone(),
        [ResponseSpec::Truncated, ResponseSpec::Complete],
    )
    .await;
    let store = fixture.store(Duration::from_secs(3));

    let loaded = store
        .get_verified(&descriptor, descriptor.size())
        .await
        .expect("a fresh GET must recover a truncated transient response");

    assert_eq!(loaded.bytes(), &body);
    assert_eq!(fixture.request_count(), 2);
}

#[tokio::test]
async fn retries_a_fresh_get_after_a_mid_body_stall() {
    let body = fixture_body();
    let descriptor = descriptor(&body);
    let fixture = S3Fixture::spawn(
        descriptor.clone(),
        body.clone(),
        [ResponseSpec::Stalled, ResponseSpec::Complete],
    )
    .await;
    let store = fixture.store(Duration::from_millis(600));
    let started = Instant::now();

    let loaded = store
        .get_verified(&descriptor, descriptor.size())
        .await
        .expect("a fresh GET must recover a stalled transient response");

    assert_eq!(loaded.bytes(), &body);
    assert_eq!(fixture.request_count(), 2);
    assert!(
        started.elapsed() >= Duration::from_millis(150),
        "the first partial body must consume its deterministic attempt budget"
    );
}

#[tokio::test]
async fn repeated_stalls_exhaust_one_total_operation_deadline() {
    let body = fixture_body();
    let descriptor = descriptor(&body);
    let fixture = S3Fixture::spawn(
        descriptor.clone(),
        body,
        std::iter::repeat_n(ResponseSpec::Stalled, TOTAL_ATTEMPTS),
    )
    .await;
    let operation_timeout = Duration::from_millis(450);
    let store = fixture.store(operation_timeout);
    let started = Instant::now();

    let error = store
        .get_verified(&descriptor, descriptor.size())
        .await
        .expect_err("every body attempt stalls");
    let elapsed = started.elapsed();

    assert_eq!(error.kind(), BlobStoreErrorKind::Unavailable);
    assert_eq!(fixture.request_count(), TOTAL_ATTEMPTS);
    assert!(elapsed >= Duration::from_millis(350));
    assert!(
        elapsed < Duration::from_secs(2),
        "all attempts must share the original total deadline; elapsed={elapsed:?}"
    );
}

#[tokio::test]
async fn does_not_retry_non_transient_provider_or_integrity_failures() {
    for (response, expected) in [
        (ResponseSpec::NotFound, BlobStoreErrorKind::NotFound),
        (ResponseSpec::Forbidden, BlobStoreErrorKind::Unauthorized),
        (ResponseSpec::InvalidMetadata, BlobStoreErrorKind::Integrity),
    ] {
        let body = fixture_body();
        let descriptor = descriptor(&body);
        let fixture = S3Fixture::spawn(descriptor.clone(), body, [response]).await;
        let store = fixture.store(Duration::from_secs(1));

        let error = store
            .get_verified(&descriptor, descriptor.size())
            .await
            .expect_err("fixture response must fail");

        assert_eq!(error.kind(), expected);
        assert_eq!(fixture.request_count(), 1, "{expected:?} was retried");
    }
}

fn fixture_body() -> Bytes {
    let mut body = Vec::with_capacity(192 * 1_024);
    for value in 0_u32..(48 * 1_024) {
        body.extend_from_slice(&value.to_le_bytes());
    }
    Bytes::from(body)
}

fn descriptor(body: &Bytes) -> BlobDescriptor {
    BlobPayload::from_bytes(
        BlobKey::new("actions/v1/sha256/retry-fixture.tar.gz").expect("blob key"),
        MediaType::new("application/octet-stream").expect("media type"),
        body.clone(),
    )
    .descriptor()
    .clone()
}

#[derive(Clone, Copy, Debug)]
enum ResponseSpec {
    Complete,
    Truncated,
    Stalled,
    NotFound,
    Forbidden,
    InvalidMetadata,
}

struct S3Fixture {
    endpoint: Url,
    requests: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl S3Fixture {
    async fn spawn(
        descriptor: BlobDescriptor,
        body: Bytes,
        responses: impl IntoIterator<Item = ResponseSpec>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind S3 fixture");
        let address = listener.local_addr().expect("fixture address");
        let requests = Arc::new(AtomicUsize::new(0));
        let responses = Arc::new(Mutex::new(responses.into_iter().collect::<VecDeque<_>>()));
        let task_requests = Arc::clone(&requests);
        let task_responses = Arc::clone(&responses);
        let task_descriptor = descriptor.clone();
        let task = tokio::spawn(async move {
            let mut handlers = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.expect("accept fixture request");
                        let response = task_responses
                            .lock()
                            .expect("response lock")
                            .pop_front()
                            .unwrap_or(ResponseSpec::NotFound);
                        task_requests.fetch_add(1, Ordering::SeqCst);
                        let descriptor = task_descriptor.clone();
                        let body = body.clone();
                        handlers.spawn(async move {
                            serve_response(stream, response, &descriptor, &body)
                                .await
                                .expect("serve fixture response");
                        });
                    }
                    completed = handlers.join_next(), if !handlers.is_empty() => {
                        completed.expect("fixture handler join").expect("fixture handler");
                    }
                }
            }
        });
        Self {
            endpoint: Url::parse(&format!("http://{address}/")).expect("fixture URL"),
            requests,
            task,
        }
    }

    fn store(&self, operation_timeout: Duration) -> S3BlobStore {
        let config = S3BlobStoreConfig::loopback_development(
            self.endpoint.clone(),
            "us-east-1",
            "automata-tests",
            None,
            operation_timeout,
        )
        .expect("fixture S3 config");
        let credentials = StaticS3Credentials::new("test-access", "test-secret", None)
            .expect("fixture credentials");
        S3BlobStore::new(config.client(credentials), &config)
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

impl Drop for S3Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_response(
    stream: TcpStream,
    response: ResponseSpec,
    descriptor: &BlobDescriptor,
    body: &Bytes,
) -> io::Result<()> {
    read_request_head(&stream).await?;
    match response {
        ResponseSpec::Complete => {
            write_object_response(&stream, descriptor, body, false, true).await
        }
        ResponseSpec::Truncated => {
            write_object_response(&stream, descriptor, body, true, true).await
        }
        ResponseSpec::Stalled => {
            write_object_response(&stream, descriptor, body, true, true).await?;
            std::future::pending::<io::Result<()>>().await
        }
        ResponseSpec::NotFound => write_status(&stream, "404 Not Found").await,
        ResponseSpec::Forbidden => write_status(&stream, "403 Forbidden").await,
        ResponseSpec::InvalidMetadata => {
            write_object_response(&stream, descriptor, body, false, false).await
        }
    }
}

async fn read_request_head(stream: &TcpStream) -> io::Result<()> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4 * 1_024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        stream.readable().await?;
        match stream.try_read(&mut buffer) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(received) => {
                request.extend_from_slice(&buffer[..received]);
                if request.len() > 32 * 1_024 {
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

async fn write_object_response(
    stream: &TcpStream,
    descriptor: &BlobDescriptor,
    body: &Bytes,
    partial: bool,
    valid_metadata: bool,
) -> io::Result<()> {
    let digest = if valid_metadata {
        descriptor.digest().to_string()
    } else {
        "0".repeat(64)
    };
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\ncontent-type: {}\r\nx-amz-meta-automata-sha256: {}\r\nx-amz-meta-automata-size: {}\r\nconnection: close\r\n\r\n",
        descriptor.size(),
        descriptor.media_type().as_str(),
        digest,
        descriptor.size(),
    );
    write_all(stream, head.as_bytes()).await?;
    let bytes = if partial {
        &body[..body.len() / 2]
    } else {
        body.as_ref()
    };
    write_all(stream, bytes).await
}

async fn write_status(stream: &TcpStream, status: &str) -> io::Result<()> {
    let response = format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
    write_all(stream, response.as_bytes()).await
}

async fn write_all(stream: &TcpStream, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.writable().await?;
        match stream.try_write(bytes) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
