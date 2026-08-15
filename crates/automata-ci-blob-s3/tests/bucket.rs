use std::{
    collections::VecDeque,
    io,
    sync::{Arc, Mutex},
    time::Duration,
};

use automata_ci_blob_s3::{
    EnsureBucketError, EnsureBucketOutcome, S3BlobStoreConfig, StaticS3Credentials,
};
use aws_sdk_s3::types::BucketLocationConstraint;
use tokio::{
    net::{TcpListener, TcpStream},
    task::{JoinHandle, JoinSet},
    time::Instant,
};
use url::Url;

#[tokio::test]
async fn existing_bucket_needs_only_one_exact_head() {
    let fixture = S3Fixture::spawn([Response::Status("200 OK")]).await;

    let outcome = fixture.ensure(Duration::from_secs(1)).await;

    assert_eq!(outcome, Ok(EnsureBucketOutcome::AlreadyExists));
    assert_eq!(fixture.requests(), ["HEAD /automata-tests/"]);
}

#[tokio::test]
async fn absent_bucket_is_created_then_reinspected() {
    let fixture = S3Fixture::spawn([
        Response::Status("404 Not Found"),
        Response::Status("200 OK"),
        Response::Status("200 OK"),
    ])
    .await;

    let outcome = fixture.ensure(Duration::from_secs(1)).await;

    assert_eq!(outcome, Ok(EnsureBucketOutcome::Created));
    assert_eq!(
        fixture.requests(),
        [
            "HEAD /automata-tests/",
            "PUT /automata-tests/",
            "HEAD /automata-tests/"
        ]
    );
    assert!(fixture.create_body().is_empty());
}

#[tokio::test]
async fn every_non_us_east_1_region_is_the_exact_create_location_constraint() {
    let regions = BucketLocationConstraint::values()
        .iter()
        .copied()
        .chain(["future-region-1"]);
    for region in regions {
        let fixture = S3Fixture::spawn([
            Response::Status("404 Not Found"),
            Response::Status("200 OK"),
            Response::Status("200 OK"),
        ])
        .await;

        assert_eq!(
            fixture
                .ensure_in_region(region, Duration::from_secs(1))
                .await,
            Ok(EnsureBucketOutcome::Created),
            "region {region}"
        );
        assert_eq!(
            fixture.create_body(),
            format!(
                "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LocationConstraint>{region}</LocationConstraint></CreateBucketConfiguration>"
            )
            .as_bytes(),
            "region {region}"
        );
    }
}

#[tokio::test]
async fn create_conflict_is_accepted_only_after_a_successful_final_head() {
    let accepted = S3Fixture::spawn([
        Response::Status("404 Not Found"),
        Response::Status("409 Conflict"),
        Response::Status("200 OK"),
    ])
    .await;
    assert_eq!(
        accepted.ensure(Duration::from_secs(1)).await,
        Ok(EnsureBucketOutcome::AlreadyExists)
    );
    assert_eq!(accepted.requests().len(), 3);

    let rejected = S3Fixture::spawn([
        Response::Status("404 Not Found"),
        Response::Status("409 Conflict"),
        Response::Status("403 Forbidden"),
    ])
    .await;
    assert_eq!(
        rejected.ensure(Duration::from_secs(1)).await,
        Err(EnsureBucketError::FinalInspection)
    );
    assert_eq!(rejected.requests().len(), 3);
}

#[tokio::test]
async fn non_not_found_inspection_never_authorizes_creation() {
    for status in ["401 Unauthorized", "403 Forbidden"] {
        let fixture = S3Fixture::spawn([Response::Status(status)]).await;

        assert_eq!(
            fixture.ensure(Duration::from_millis(500)).await,
            Err(EnsureBucketError::InitialInspection)
        );
        assert!(
            fixture
                .requests()
                .iter()
                .all(|request| request.starts_with("HEAD "))
        );
    }
}

#[tokio::test]
async fn every_stage_shares_one_total_deadline() {
    let fixture = S3Fixture::spawn([Response::Status("404 Not Found"), Response::Stall]).await;
    let started = Instant::now();

    let outcome = fixture.ensure(Duration::from_millis(150)).await;

    assert_eq!(outcome, Err(EnsureBucketError::Deadline));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(
        fixture.requests(),
        ["HEAD /automata-tests/", "PUT /automata-tests/"]
    );
}

#[derive(Clone, Copy)]
enum Response {
    Status(&'static str),
    Stall,
}

struct S3Fixture {
    endpoint: Url,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    task: JoinHandle<()>,
}

impl S3Fixture {
    async fn spawn(responses: impl IntoIterator<Item = Response>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind bucket fixture");
        let endpoint = Url::parse(&format!(
            "http://{}/",
            listener.local_addr().expect("bucket fixture address")
        ))
        .expect("bucket fixture URL");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let responses = Arc::new(Mutex::new(responses.into_iter().collect::<VecDeque<_>>()));
        let task_requests = Arc::clone(&requests);
        let task_responses = Arc::clone(&responses);
        let task = tokio::spawn(async move {
            let mut handlers = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.expect("accept bucket request");
                        let requests = Arc::clone(&task_requests);
                        let response = task_responses
                            .lock()
                            .expect("bucket response lock")
                            .pop_front()
                            .expect("unexpected bucket request");
                        handlers.spawn(async move {
                            serve(stream, requests, response)
                                .await
                                .expect("serve bucket response");
                        });
                    }
                    completed = handlers.join_next(), if !handlers.is_empty() => {
                        completed.expect("bucket handler join").expect("bucket handler");
                    }
                }
            }
        });
        Self {
            endpoint,
            requests,
            task,
        }
    }

    async fn ensure(
        &self,
        operation_timeout: Duration,
    ) -> Result<EnsureBucketOutcome, EnsureBucketError> {
        self.ensure_in_region("us-east-1", operation_timeout).await
    }

    async fn ensure_in_region(
        &self,
        region: &str,
        operation_timeout: Duration,
    ) -> Result<EnsureBucketOutcome, EnsureBucketError> {
        let config = S3BlobStoreConfig::loopback_development(
            self.endpoint.clone(),
            region,
            "automata-tests",
            None,
            operation_timeout,
        )
        .expect("bucket fixture config");
        let credentials = StaticS3Credentials::new("test-access", "test-secret", None)
            .expect("bucket fixture credentials");
        config
            .connect(credentials)
            .expect("bucket fixture S3 store")
            .ensure_bucket()
            .await
    }

    fn requests(&self) -> Vec<String> {
        self.requests
            .lock()
            .expect("bucket request lock")
            .iter()
            .map(|request| request.target.clone())
            .collect()
    }

    fn create_body(&self) -> Vec<u8> {
        self.requests
            .lock()
            .expect("bucket request lock")
            .iter()
            .find(|request| request.target.starts_with("PUT "))
            .expect("create request")
            .body
            .clone()
    }
}

impl Drop for S3Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(
    stream: TcpStream,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    response: Response,
) -> io::Result<()> {
    let request = read_request(&stream).await?;
    requests.lock().expect("bucket request lock").push(request);
    match response {
        Response::Status(status) => {
            stream.writable().await?;
            let body = format!(
                "HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\nx-amz-request-id: fixture\r\n\r\n"
            );
            stream.try_write(body.as_bytes())?;
            Ok(())
        }
        Response::Stall => std::future::pending().await,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RecordedRequest {
    target: String,
    body: Vec<u8>,
}

async fn read_request(stream: &TcpStream) -> io::Result<RecordedRequest> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4 * 1_024];
    let header_end = loop {
        if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
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
    };
    let head = std::str::from_utf8(&request[..header_end])
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    let target = head
        .split("\r\n")
        .next()
        .and_then(|line| line.strip_suffix(" HTTP/1.1"))
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?
        .to_owned();
    let content_length = head
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>())
        .transpose()
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?
        .unwrap_or(0);
    let complete_length = header_end
        .checked_add(content_length)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    while request.len() < complete_length {
        stream.readable().await?;
        match stream.try_read(&mut buffer) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(received) => {
                request.extend_from_slice(&buffer[..received]);
                if request.len() > 64 * 1_024 {
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(RecordedRequest {
        target,
        body: request[header_end..complete_length].to_vec(),
    })
}
