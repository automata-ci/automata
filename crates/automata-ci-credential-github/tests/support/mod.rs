#![allow(dead_code)]

use std::{
    collections::VecDeque,
    convert::Infallible,
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};

use automata_ci_auth::{
    secret::SecretString,
    time::{Clock, UnixTimestamp},
};
use automata_ci_credential::{
    MinimumValidity, PermissionLevel, PermissionName, PermissionSet, ProviderResourceId,
    RepositoryCredentialRequest, RepositoryScope, WorkloadIdentity,
};
use automata_ci_credential_github::{
    GithubAppCredentialBroker, GithubAppCredentialConfig, GithubAppHttpLimits, GithubInstallationId,
};
use automata_ci_scm::{RepositoryId, ScmProviderId};
use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::State,
    http::{HeaderMap, Request, Response, StatusCode},
    routing::any,
};
use futures::stream;
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use url::Url;

pub const NOW: u64 = 1_800_000_000;
pub const EXPIRATION: &str = "2027-01-15T09:00:00Z";
pub const REPOSITORY_ID: u64 = 81_234_567;
pub const INSTALLATION_ID: u64 = 998_877;
pub const ISSUER: &str = "Iv1.automata-test";
const MAX_FIXTURE_REQUEST_BYTES: usize = 32 * 1_024;
const PUBLISHED_TEST_KEY_PKCS1_DER: &[u8] =
    include_bytes!("../fixtures/rsa2048-test-key.pkcs1.der");
const PUBLISHED_TEST_KEY_PKCS8_DER: &[u8] =
    include_bytes!("../fixtures/rsa2048-test-key.pkcs8.der");

#[derive(Clone, Copy, Debug)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now(&self) -> UnixTimestamp {
        UnixTimestamp::from_seconds(self.0)
    }
}

#[derive(Clone, Debug)]
pub struct ResponseSpec {
    status: StatusCode,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    delay: Duration,
    streamed: bool,
}

impl ResponseSpec {
    pub fn json(status: StatusCode, body: impl Into<String>) -> Self {
        Self {
            status,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: body.into().into_bytes(),
            delay: Duration::ZERO,
            streamed: false,
        }
    }

    pub fn status(status: StatusCode) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
            delay: Duration::ZERO,
            streamed: false,
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

    pub fn delayed(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    pub fn streamed(mut self) -> Self {
        self.streamed = true;
        self
    }
}

#[derive(Clone, Debug)]
pub struct CapturedRequest {
    pub method: String,
    pub uri: String,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
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
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, application)
                .with_graceful_shutdown(async move {
                    let _ = receiver.await;
                })
                .await
                .expect("serve fixture");
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
        self.origin.join(relative).expect("fixture endpoint")
    }

    pub fn enqueue(&self, response: ResponseSpec) {
        self.state
            .responses
            .lock()
            .expect("response lock")
            .push_back(response);
    }

    pub fn requests(&self) -> Vec<CapturedRequest> {
        self.state.requests.lock().expect("request lock").clone()
    }

    pub fn remaining_responses(&self) -> usize {
        self.state.responses.lock().expect("response lock").len()
    }

    pub fn broker(&self) -> GithubAppCredentialBroker {
        self.broker_with_limits(GithubAppHttpLimits::default())
    }

    pub fn broker_with_limits(&self, limits: GithubAppHttpLimits) -> GithubAppCredentialBroker {
        let config = GithubAppCredentialConfig::new_for_loopback_emulator(
            self.url("api/v3/"),
            ProviderResourceId::new(ISSUER).unwrap(),
            GithubInstallationId::new(INSTALLATION_ID).unwrap(),
            "automata-ci-credential-tests/0.1.0",
            limits,
        )
        .expect("fixture config");
        GithubAppCredentialBroker::with_clock(config, &private_key(), Arc::new(FixedClock(NOW)))
            .expect("fixture broker")
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
        .expect("bounded fixture request");
    state
        .requests
        .lock()
        .expect("request lock")
        .push(CapturedRequest {
            method: parts.method.to_string(),
            uri: parts.uri.to_string(),
            headers: parts.headers,
            body: body.to_vec(),
        });
    let response = state
        .responses
        .lock()
        .expect("response lock")
        .pop_front()
        .unwrap_or_else(|| {
            ResponseSpec::json(
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"fixture exhausted"}"#,
            )
        });
    if !response.delay.is_zero() {
        tokio::time::sleep(response.delay).await;
    }
    let mut builder = Response::builder().status(response.status);
    for (name, value) in response.headers {
        builder = builder.header(name, value);
    }
    let body = if response.streamed {
        let chunks = response
            .body
            .chunks(31)
            .map(|chunk| Ok::<Bytes, Infallible>(Bytes::copy_from_slice(chunk)))
            .collect::<Vec<_>>();
        Body::from_stream(stream::iter(chunks))
    } else {
        Body::from(response.body)
    };
    builder.body(body).expect("fixture response")
}

pub fn private_key() -> SecretString {
    published_test_key_pem("RSA PRIVATE KEY", PUBLISHED_TEST_KEY_PKCS1_DER)
}

pub fn pkcs8_private_key() -> SecretString {
    published_test_key_pem("PRIVATE KEY", PUBLISHED_TEST_KEY_PKCS8_DER)
}

fn published_test_key_pem(label: &str, der: &[u8]) -> SecretString {
    let pem = pem_rfc7468::encode_string(label, pem_rfc7468::LineEnding::LF, der)
        .expect("published RSA test fixture must encode as RFC 7468 PEM");
    SecretString::new(pem).expect("published RSA test fixture must be non-empty")
}

pub fn request() -> RepositoryCredentialRequest {
    request_for("github", REPOSITORY_ID.to_string(), "automata-ci/automata")
}

pub fn request_for(
    provider: &str,
    stable_id: impl Into<String>,
    repository: &str,
) -> RepositoryCredentialRequest {
    RepositoryCredentialRequest::new(
        WorkloadIdentity::new("tenant/run-42/verify/attempt-1").unwrap(),
        RepositoryScope::new(
            ScmProviderId::new(provider).unwrap(),
            RepositoryId::new(repository).unwrap(),
            ProviderResourceId::new(stable_id).unwrap(),
        ),
        PermissionSet::new([
            (
                PermissionName::new("contents").unwrap(),
                PermissionLevel::Read,
            ),
            (
                PermissionName::new("statuses").unwrap(),
                PermissionLevel::Write,
            ),
        ])
        .unwrap(),
        MinimumValidity::from_seconds(300).unwrap(),
    )
}

pub fn success_response() -> ResponseSpec {
    token_response(
        "ghs_998877_variable_length_stateless_token_value",
        EXPIRATION,
        r#"{"contents":"read","statuses":"write"}"#,
        REPOSITORY_ID,
        "automata-ci/automata",
        "selected",
    )
}

pub fn token_response(
    token: &str,
    expiration: &str,
    permissions: &str,
    repository_id: u64,
    full_name: &str,
    selection: &str,
) -> ResponseSpec {
    ResponseSpec::json(
        StatusCode::CREATED,
        format!(
            r#"{{"token":"{token}","expires_at":"{expiration}","permissions":{permissions},"repository_selection":"{selection}","repositories":[{{"id":{repository_id},"full_name":"{full_name}"}}]}}"#
        ),
    )
}

impl fmt::Display for FixedClock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}
