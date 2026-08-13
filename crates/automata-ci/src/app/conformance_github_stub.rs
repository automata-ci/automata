//! Loopback-only HTTP adapter for deterministic GitHub provider fixtures.

use std::{
    fmt::Write as _,
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
};

use automata_ci_auth::secret::SecretString;
use automata_ci_conformance::{
    GithubMutationOutcome, GithubStubError, GithubStubRequest, GithubStubResponse, GithubStubScript,
};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE, LINK, RETRY_AFTER},
    },
    response::Response,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio::{
    net::TcpListener,
    sync::oneshot,
    task::{JoinError, JoinHandle},
};

/// Maximum request body accepted by the hermetic GitHub adapter.
// foundation-governance: operational-limit
pub const MAX_GITHUB_STUB_REQUEST_BODY_BYTES: usize = 16 * 1_048_576;
/// Response header retaining the scripted certainty of a GitHub mutation.
pub const X_AUTOMATA_GITHUB_MUTATION_OUTCOME: &str =
    "x-automata-conformance-github-mutation-outcome";

// foundation-governance: operational-limit
const MAX_GITHUB_STUB_CREDENTIALS: usize = 256;
const X_RATE_LIMIT_REMAINING: &str = "x-ratelimit-remaining";

/// One redacted authorization value mapped to a non-secret fixture identity.
pub struct HermeticGithubCredential {
    id: String,
    authorization: SecretString,
}

impl HermeticGithubCredential {
    /// Creates an exact `Authorization` header mapping.
    ///
    /// `authorization` contains the complete header value, including its
    /// scheme (for example, `Bearer fixture-token`).
    ///
    /// # Errors
    ///
    /// Rejects an unsafe identity or a value that cannot be represented as an
    /// HTTP header.
    pub fn new(
        id: impl Into<String>,
        authorization: SecretString,
    ) -> Result<Self, HermeticGithubStubError> {
        let id = id.into();
        if invalid_identity(&id) || HeaderValue::from_str(authorization.expose_secret()).is_err() {
            return Err(HermeticGithubStubError::InvalidCredentialRegistry);
        }
        Ok(Self { id, authorization })
    }

    /// Returns the non-secret identity placed in exact request evidence.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl std::fmt::Debug for HermeticGithubCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HermeticGithubCredential")
            .field("id", &self.id)
            .field("authorization", &self.authorization)
            .finish()
    }
}

/// First fail-closed request failure observed by the loopback adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HermeticGithubStubFailure {
    /// An `Authorization` header was malformed, duplicated, or unregistered.
    UnknownCredential,
    /// A request exceeded the adapter's bounded body budget.
    RequestBodyTooLarge,
    /// The exact-order script rejected the observed request.
    Script(GithubStubError),
    /// A validated script response could not be represented by the HTTP stack.
    ResponseConstruction,
}

/// Running loopback GitHub server that owns one exact-order script.
///
/// Call [`Self::finish`] to prove every exchange was consumed and the adapter
/// observed no malformed, extra, or reordered request.
pub struct HermeticGithubStubServer {
    local_addr: SocketAddr,
    origin: String,
    state: Arc<StubState>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl HermeticGithubStubServer {
    /// Binds an ephemeral IPv4 loopback port and begins serving the script.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid credential registry or when the
    /// loopback listener cannot be created.
    pub async fn start(
        script: GithubStubScript,
        credentials: Vec<HermeticGithubCredential>,
    ) -> Result<Self, HermeticGithubStubError> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(HermeticGithubStubError::Bind)?;
        Self::start_with_listener(listener, script, credentials)
    }

    /// Begins serving on an already-bound loopback listener.
    ///
    /// This consumes a shard-owned listener without releasing and rebinding its
    /// numeric port, preserving the reservation's bind/use guarantee.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid credential registry, a listener that
    /// cannot be inspected, or a non-loopback listener.
    pub fn start_with_listener(
        listener: TcpListener,
        script: GithubStubScript,
        credentials: Vec<HermeticGithubCredential>,
    ) -> Result<Self, HermeticGithubStubError> {
        validate_credentials(&credentials)?;
        let local_addr = listener
            .local_addr()
            .map_err(HermeticGithubStubError::Bind)?;
        if !local_addr.ip().is_loopback() {
            return Err(HermeticGithubStubError::NonLoopbackListener);
        }
        let origin = format!("http://{local_addr}");
        let state = Arc::new(StubState {
            script: Arc::new(script),
            credentials,
            origin: origin.clone(),
            first_failure: Mutex::new(None),
        });
        let router = Router::new()
            .fallback(handle_request)
            .with_state(Arc::clone(&state));
        let (shutdown, shutdown_receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_receiver.await;
                })
                .await
        });
        Ok(Self {
            local_addr,
            origin,
            state,
            shutdown: Some(shutdown),
            task: Some(task),
        })
    }

    /// Returns the bound loopback address.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns the HTTP origin to configure on a product GitHub client.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Stops the server and proves the script was consumed exactly.
    ///
    /// # Errors
    ///
    /// Returns the first observed request failure, an incomplete script, or a
    /// server task failure.
    pub async fn finish(mut self) -> Result<(), HermeticGithubStubError> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.await.map_err(|error| {
                if error.is_cancelled() {
                    HermeticGithubStubError::UnexpectedCancellation
                } else {
                    HermeticGithubStubError::Join(error)
                }
            })??;
        }
        if let Some(failure) = self
            .state
            .first_failure
            .lock()
            .map_err(|_| HermeticGithubStubError::StatePoisoned)?
            .as_ref()
            .copied()
        {
            return Err(HermeticGithubStubError::Observed(failure));
        }
        self.state
            .script
            .finish()
            .map_err(HermeticGithubStubError::IncompleteScript)
    }
}

impl std::fmt::Debug for HermeticGithubStubServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HermeticGithubStubServer")
            .field("local_addr", &self.local_addr)
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl Drop for HermeticGithubStubServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[derive(Debug)]
struct StubState {
    script: Arc<GithubStubScript>,
    credentials: Vec<HermeticGithubCredential>,
    origin: String,
    first_failure: Mutex<Option<HermeticGithubStubFailure>>,
}

impl StubState {
    fn record_failure(&self, failure: HermeticGithubStubFailure) {
        if let Ok(mut first_failure) = self.first_failure.lock() {
            first_failure.get_or_insert(failure);
        }
    }

    fn credential_id(&self, headers: &HeaderMap) -> Result<Option<String>, ()> {
        let mut values = headers.get_all(AUTHORIZATION).iter();
        let Some(value) = values.next() else {
            return Ok(None);
        };
        if values.next().is_some() {
            return Err(());
        }
        let value = value.to_str().map_err(|_| ())?;
        self.credentials
            .iter()
            .find(|credential| credential.authorization.constant_time_eq(value))
            .map(|credential| Some(credential.id.clone()))
            .ok_or(())
    }
}

async fn handle_request(State(state): State<Arc<StubState>>, request: Request) -> Response {
    let Ok(credential_id) = state.credential_id(request.headers()) else {
        state.record_failure(HermeticGithubStubFailure::UnknownCredential);
        return json_response(
            StatusCode::UNAUTHORIZED,
            br#"{"message":"Bad credentials"}"#,
        );
    };
    let method = request.method().as_str().to_owned();
    let path_and_query = request
        .uri()
        .path_and_query()
        .map_or_else(|| "/".to_owned(), |value| value.as_str().to_owned());
    let Ok(body) = to_bytes(request.into_body(), MAX_GITHUB_STUB_REQUEST_BODY_BYTES).await else {
        state.record_failure(HermeticGithubStubFailure::RequestBodyTooLarge);
        return json_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            br#"{"message":"request body too large"}"#,
        );
    };
    let body_sha256 = (!body.is_empty()).then(|| sha256(&body));
    let observed = GithubStubRequest {
        method,
        path_and_query,
        body_sha256,
        credential_id,
    };
    let scripted = match state.script.respond(&observed) {
        Ok(response) => response,
        Err(error) => {
            state.record_failure(HermeticGithubStubFailure::Script(error));
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                br#"{"message":"hermetic GitHub script mismatch"}"#,
            );
        }
    };
    let Ok(response) = scripted_response(&state.origin, scripted) else {
        state.record_failure(HermeticGithubStubFailure::ResponseConstruction);
        return json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            br#"{"message":"invalid hermetic GitHub response"}"#,
        );
    };
    response
}

fn scripted_response(origin: &str, response: GithubStubResponse) -> Result<Response, ()> {
    let mut builder = Response::builder().header(CONTENT_TYPE, "application/json");
    let body = match response {
        GithubStubResponse::Page { status, body, next } => {
            builder = builder.status(status);
            if let Some(next) = next {
                let link = format!("<{origin}{next}>; rel=\"next\"");
                builder = builder.header(LINK, HeaderValue::from_str(&link).map_err(|_| ())?);
            }
            body
        }
        GithubStubResponse::RateLimited { retry_after_millis } => {
            let retry_after_seconds = retry_after_millis.saturating_add(999) / 1_000;
            builder = builder
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header(RETRY_AFTER, retry_after_seconds.to_string())
                .header(X_RATE_LIMIT_REMAINING, "0");
            br#"{"message":"API rate limit exceeded"}"#.to_vec()
        }
        GithubStubResponse::CredentialFailure { status } => {
            builder = builder.status(status);
            br#"{"message":"Bad credentials"}"#.to_vec()
        }
        GithubStubResponse::Mutation {
            status,
            outcome,
            body,
        } => {
            let outcome = match outcome {
                GithubMutationOutcome::NotApplied => "not_applied",
                GithubMutationOutcome::Applied => "applied",
                GithubMutationOutcome::Indeterminate => "indeterminate",
            };
            builder = builder
                .status(status)
                .header(X_AUTOMATA_GITHUB_MUTATION_OUTCOME, outcome);
            body
        }
    };
    builder.body(Body::from(body)).map_err(|_| ())
}

fn json_response(status: StatusCode, body: &'static [u8]) -> Response {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("static response status and headers are valid")
}

fn validate_credentials(
    credentials: &[HermeticGithubCredential],
) -> Result<(), HermeticGithubStubError> {
    if credentials.len() > MAX_GITHUB_STUB_CREDENTIALS {
        return Err(HermeticGithubStubError::InvalidCredentialRegistry);
    }
    for (index, credential) in credentials.iter().enumerate() {
        for other in &credentials[index + 1..] {
            if credential.id == other.id
                || credential
                    .authorization
                    .constant_time_eq(other.authorization.expose_secret())
            {
                return Err(HermeticGithubStubError::InvalidCredentialRegistry);
            }
        }
    }
    Ok(())
}

fn invalid_identity(value: &str) -> bool {
    value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
}

fn sha256(value: &[u8]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in Sha256::digest(value) {
        write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    encoded
}

/// Failure to start, serve, or verify the hermetic GitHub adapter.
#[derive(Debug, Error)]
pub enum HermeticGithubStubError {
    /// Credential identities or authorization values were invalid or duplicated.
    #[error("the hermetic GitHub credential registry is invalid")]
    InvalidCredentialRegistry,
    /// A listener unexpectedly resolved outside the loopback interface.
    #[error("the hermetic GitHub server refused a non-loopback listener")]
    NonLoopbackListener,
    /// The loopback listener could not be created or inspected.
    #[error("the hermetic GitHub loopback listener could not be bound")]
    Bind(#[source] io::Error),
    /// The HTTP server returned an I/O error.
    #[error("the hermetic GitHub HTTP server failed")]
    Serve(#[from] io::Error),
    /// The HTTP task was cancelled before the adapter requested shutdown.
    #[error("the hermetic GitHub HTTP server was cancelled unexpectedly")]
    UnexpectedCancellation,
    /// The HTTP server task could not be joined.
    #[error("the hermetic GitHub HTTP server task failed")]
    Join(#[source] JoinError),
    /// The adapter's failure ledger could not be inspected.
    #[error("the hermetic GitHub failure ledger was poisoned")]
    StatePoisoned,
    /// The server observed a fail-closed request failure.
    #[error("the hermetic GitHub server observed a request failure: {0:?}")]
    Observed(HermeticGithubStubFailure),
    /// The server stopped before consuming the complete exact-order script.
    #[error("the hermetic GitHub server left an incomplete script")]
    IncompleteScript(#[source] GithubStubError),
}
