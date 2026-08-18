#![allow(dead_code)]

use std::{
    collections::{BTreeMap, VecDeque},
    fmt::Write as _,
    sync::{Arc, Mutex},
};

use automata_ci_provider_github::{
    GithubHttpEndpoint, GithubHttpLimits, GithubWebhookBodyDigest, X_GITHUB_DELIVERY,
    X_GITHUB_EVENT, X_HUB_SIGNATURE_256,
};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{HeaderMap, HeaderValue, Request, Response, StatusCode},
    routing::any,
};
use ring::{digest, hmac};
use serde_json::{Value, json};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use url::Url;

const MAX_FIXTURE_REQUEST_BYTES: usize = 1_048_576;
pub(crate) const BASE_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
pub(crate) const HEAD_SHA: &str = "89abcdef0123456789abcdef0123456789abcdef";
pub(crate) const MERGE_SHA: &str = "76543210fedcba9876543210fedcba9876543210";
pub(crate) const GROUP_SHA: &str = "fedcba9876543210fedcba9876543210fedcba98";

pub(crate) fn json_body(payload: &Value) -> Vec<u8> {
    serde_json::to_vec(payload).expect("JSON fixture")
}

pub(crate) fn webhook_body_digest(body: &[u8]) -> GithubWebhookBodyDigest {
    let digest = digest::digest(&digest::SHA256, body);
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(digest.as_ref());
    GithubWebhookBodyDigest::from_bytes(bytes)
}

pub(crate) fn signed_webhook_headers(
    secret: &[u8],
    body: &[u8],
    event: &str,
    delivery: &str,
) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        X_HUB_SIGNATURE_256,
        HeaderValue::from_str(&webhook_signature(secret, body)).expect("signature header"),
    );
    headers.insert(
        X_GITHUB_EVENT,
        HeaderValue::from_str(event).expect("event header"),
    );
    headers.insert(
        X_GITHUB_DELIVERY,
        HeaderValue::from_str(delivery).expect("delivery header"),
    );
    headers
}

pub(crate) fn base_repository() -> Value {
    repository(41, 11, "example", "base-repository")
}

pub(crate) fn head_repository() -> Value {
    repository(42, 12, "contributor", "head-repository")
}

fn webhook_signature(secret: &[u8], body: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let tag = hmac::sign(&key, body);
    let mut encoded = String::from("sha256=");
    for byte in tag.as_ref() {
        write!(encoded, "{byte:02x}").expect("write signature");
    }
    encoded
}

fn repository(id: u64, owner_id: u64, owner: &str, name: &str) -> Value {
    json!({
        "id": id,
        "private": false,
        "visibility": "public",
        "name": name,
        "full_name": format!("{owner}/{name}"),
        "owner": { "id": owner_id, "login": owner }
    })
}

#[derive(Clone, Debug)]
pub struct ResponseSpec {
    status: StatusCode,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl ResponseSpec {
    pub fn json(status: StatusCode, body: impl Into<String>) -> Self {
        Self {
            status,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: body.into().into_bytes(),
        }
    }

    pub fn status(status: StatusCode) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn binary(status: StatusCode, media_type: &str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: vec![("content-type".to_owned(), media_type.to_owned())],
            body: body.into(),
        }
    }

    pub fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_owned(), value.into()));
        self
    }

    pub fn content_type(mut self, value: &str) -> Self {
        self.headers
            .retain(|(name, _)| !name.eq_ignore_ascii_case("content-type"));
        self.header("content-type", value)
    }
}

#[derive(Clone, Debug)]
pub struct CapturedRequest {
    pub method: String,
    pub uri: String,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl CapturedRequest {
    pub fn form(&self) -> BTreeMap<String, String> {
        url::form_urlencoded::parse(&self.body)
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect()
    }
}

#[derive(Clone, Debug)]
struct FixtureState {
    responses: Arc<Mutex<VecDeque<ResponseSpec>>>,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
}

#[derive(Debug)]
pub struct FixtureServer {
    origin: Url,
    state: FixtureState,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl FixtureServer {
    pub async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fixture server");
        let address = listener.local_addr().expect("fixture address");
        let state = FixtureState {
            responses: Arc::new(Mutex::new(VecDeque::new())),
            requests: Arc::new(Mutex::new(Vec::new())),
        };
        let application = Router::new()
            .fallback(any(handle_request))
            .with_state(state.clone());
        let (shutdown, shutdown_receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, application)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_receiver.await;
                })
                .await
                .expect("serve fixture requests");
        });
        let origin = Url::parse(&format!("http://{address}/")).expect("fixture URL");
        Self {
            origin,
            state,
            shutdown: Some(shutdown),
            task,
        }
    }

    pub fn origin(&self) -> Url {
        self.origin.clone()
    }

    pub fn url(&self, relative: &str) -> Url {
        self.origin.join(relative).expect("fixture endpoint URL")
    }

    pub fn enqueue(&self, response: ResponseSpec) {
        self.state
            .responses
            .lock()
            .expect("response queue lock")
            .push_back(response);
    }

    pub fn requests(&self) -> Vec<CapturedRequest> {
        self.state
            .requests
            .lock()
            .expect("request log lock")
            .clone()
    }

    pub fn remaining_responses(&self) -> usize {
        self.state
            .responses
            .lock()
            .expect("response queue lock")
            .len()
    }

    pub fn endpoint(&self) -> GithubHttpEndpoint {
        self.endpoint_with_limits(GithubHttpLimits::default())
    }

    pub fn endpoint_with_limits(&self, limits: GithubHttpLimits) -> GithubHttpEndpoint {
        GithubHttpEndpoint::new_for_loopback_emulator(
            self.origin(),
            self.url("api/"),
            "automata-tests/0.1.0",
            limits,
        )
        .expect("loopback fixture configuration")
    }
}

impl Drop for FixtureServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.abort();
    }
}

async fn handle_request(
    State(state): State<FixtureState>,
    request: Request<Body>,
) -> Response<Body> {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, MAX_FIXTURE_REQUEST_BYTES)
        .await
        .expect("bounded fixture request body");
    state
        .requests
        .lock()
        .expect("request log lock")
        .push(CapturedRequest {
            method: parts.method.to_string(),
            uri: parts.uri.to_string(),
            headers: parts.headers,
            body: body.to_vec(),
        });
    let response = state
        .responses
        .lock()
        .expect("response queue lock")
        .pop_front()
        .unwrap_or_else(|| {
            ResponseSpec::json(
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"fixture response queue exhausted"}"#,
            )
        });
    let mut builder = Response::builder().status(response.status);
    for (name, value) in response.headers {
        builder = builder.header(name, value);
    }
    builder
        .body(Body::from(response.body))
        .expect("fixture response")
}
