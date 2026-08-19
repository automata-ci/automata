use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{HeaderMap, Request, Response, StatusCode},
    routing::any,
};
use bytes::Bytes;
use flate2::{Compression, write::GzEncoder};
use tar::{Builder, EntryType, Header};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use url::Url;

const MAX_FIXTURE_REQUEST_BYTES: usize = 1_048_576;

pub(super) const BEFORE: &str = "fedcba9876543210fedcba9876543210fedcba98";
pub(super) const AFTER: &str = "0123456789abcdef0123456789abcdef01234567";

#[derive(Clone, Debug)]
pub(super) struct HttpResponse {
    status: StatusCode,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpResponse {
    pub(super) fn status(status: StatusCode) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub(super) fn json(status: StatusCode, body: impl Into<Vec<u8>>) -> Self {
        Self::status(status)
            .header("content-type", "application/json")
            .body(body)
    }

    pub(super) fn binary(status: StatusCode, media_type: &str, body: impl Into<Vec<u8>>) -> Self {
        Self::status(status)
            .header("content-type", media_type)
            .body(body)
    }

    pub(super) fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_owned(), value.into()));
        self
    }

    fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }
}

#[derive(Clone, Debug)]
pub(super) struct HttpRequest {
    pub(super) method: String,
    pub(super) uri: String,
    pub(super) headers: HeaderMap,
    pub(super) body: Vec<u8>,
}

#[derive(Clone, Debug)]
struct HttpState {
    responses: Arc<Mutex<VecDeque<HttpResponse>>>,
    requests: Arc<Mutex<Vec<HttpRequest>>>,
}

#[derive(Debug)]
pub(super) struct HttpServer {
    origin: Url,
    state: HttpState,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl HttpServer {
    pub(super) async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind HTTP fixture");
        let address = listener.local_addr().expect("HTTP fixture address");
        let state = HttpState {
            responses: Arc::new(Mutex::new(VecDeque::new())),
            requests: Arc::new(Mutex::new(Vec::new())),
        };
        let router = Router::new()
            .fallback(any(handle_http_request))
            .with_state(state.clone());
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = receiver.await;
                })
                .await
                .expect("serve HTTP fixture");
        });
        Self {
            origin: Url::parse(&format!("http://{address}/")).expect("HTTP fixture origin"),
            state,
            shutdown: Some(shutdown),
            task,
        }
    }

    pub(super) fn origin(&self) -> Url {
        self.origin.clone()
    }

    pub(super) fn url(&self, relative: &str) -> Url {
        self.origin.join(relative).expect("HTTP fixture URL")
    }

    pub(super) fn enqueue(&self, response: HttpResponse) {
        self.state
            .responses
            .lock()
            .expect("HTTP response lock")
            .push_back(response);
    }

    pub(super) fn requests(&self) -> Vec<HttpRequest> {
        self.state
            .requests
            .lock()
            .expect("HTTP request lock")
            .clone()
    }
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.abort();
    }
}

async fn handle_http_request(
    State(state): State<HttpState>,
    request: Request<Body>,
) -> Response<Body> {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, MAX_FIXTURE_REQUEST_BYTES)
        .await
        .expect("bounded HTTP fixture body");
    state
        .requests
        .lock()
        .expect("HTTP request lock")
        .push(HttpRequest {
            method: parts.method.to_string(),
            uri: parts.uri.to_string(),
            headers: parts.headers,
            body: body.to_vec(),
        });
    let response = state
        .responses
        .lock()
        .expect("HTTP response lock")
        .pop_front()
        .expect("queued HTTP fixture response");
    let mut builder = Response::builder().status(response.status);
    for (name, value) in response.headers {
        builder = builder.header(name, value);
    }
    builder
        .body(Body::from(response.body))
        .expect("HTTP fixture response")
}

pub(super) fn archive<T: AsRef<[u8]>>(files: BTreeMap<&str, T>) -> Bytes {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = Builder::new(encoder);
    append_archive_entry(&mut builder, "repository-root", EntryType::Directory, &[]);
    for (path, bytes) in files {
        append_archive_entry(
            &mut builder,
            &format!("repository-root/{path}"),
            EntryType::Regular,
            bytes.as_ref(),
        );
    }
    let encoder = builder.into_inner().expect("finish tar");
    Bytes::from(encoder.finish().expect("finish gzip"))
}

fn append_archive_entry(
    builder: &mut Builder<GzEncoder<Vec<u8>>>,
    path: &str,
    entry_type: EntryType,
    bytes: &[u8],
) {
    let mut header = Header::new_gnu();
    header.set_entry_type(entry_type);
    header.set_mode(if entry_type.is_dir() { 0o755 } else { 0o644 });
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(u64::try_from(bytes.len()).expect("entry size"));
    header.set_cksum();
    builder
        .append_data(&mut header, path, bytes)
        .expect("append archive entry");
}
