//! Origin-bound one-time live-log tickets and the reference SSE transport.

use std::{
    collections::{BTreeSet, VecDeque},
    convert::Infallible,
    fmt,
    str::FromStr as _,
    sync::Arc,
    time::{Duration, Instant},
};

use automata_ci_auth::secret::SecretString;
use automata_ci_core::{JobId, RunId, UnixMillis};
use automata_ci_store::{
    HUMAN_LIVE_LOG_PROTOCOL_VERSION, HumanLiveLogBrowserOrigin, HumanLiveLogScope,
    HumanLiveLogTicketRepository, HumanLogCommitNotificationHub, HumanLogCommitSubscription,
    IssueHumanLiveLogTicket, IssueHumanLiveLogTicketOutcome, MAX_HUMAN_LIVE_LOG_TICKET_LIFETIME,
    RedeemHumanLiveLogTicket,
};
use axum::{
    Json, Router,
    body::{Body, Bytes, to_bytes},
    extract::{Extension, Path, Request, State},
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode,
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, ORIGIN, VARY},
    },
    response::{IntoResponse as _, Response},
    routing::post,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::stream;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use tracing::error;
use zeroize::{Zeroize as _, Zeroizing};

use super::web::{
    LiveLogBatch, LiveLogRecord, LogChannel, LogGroup, LogGroupKind, LogRecord, RepositoryPath,
    RequestContext, WebData, WebDataError,
};

/// Authenticated browser endpoint that issues a capability for one exact log.
pub(crate) const BROWSER_LIVE_LOG_TICKET_PATH: &str =
    "/{owner}/{repository}/actions/runs/{run_id}/jobs/{job_id}/live-ticket";
/// Credential-only public endpoint used by the reference streaming transport.
pub(crate) const LIVE_LOG_SSE_PATH: &str = "/live/v3/logs";

const TICKET_PREFIX: &str = "allt_v3_";
const TICKET_RANDOM_BYTES: usize = 32;
const TICKET_ENCODED_BYTES: usize = 43;
const TICKET_LENGTH: usize = TICKET_PREFIX.len() + TICKET_ENCODED_BYTES;
const MAX_TICKET_GENERATION_ATTEMPTS: usize = 3;
const MAX_CHECKPOINT_BYTES: usize = 512;
const MAX_REQUEST_BODY_BYTES: usize = 0;
const DURABLE_RECHECK_INTERVAL: Duration = Duration::from_secs(1);
const SSE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const SSE_CONNECTION_LIFETIME: Duration = Duration::from_mins(5);
const LAST_EVENT_ID: HeaderName = HeaderName::from_static("last-event-id");
const ACCESS_CONTROL_ALLOW_ORIGIN: HeaderName =
    HeaderName::from_static("access-control-allow-origin");
const ACCESS_CONTROL_ALLOW_METHODS: HeaderName =
    HeaderName::from_static("access-control-allow-methods");
const ACCESS_CONTROL_ALLOW_HEADERS: HeaderName =
    HeaderName::from_static("access-control-allow-headers");
const ACCESS_CONTROL_MAX_AGE: HeaderName = HeaderName::from_static("access-control-max-age");
const ACCESS_CONTROL_REQUEST_METHOD: HeaderName =
    HeaderName::from_static("access-control-request-method");
const ACCESS_CONTROL_REQUEST_HEADERS: HeaderName =
    HeaderName::from_static("access-control-request-headers");
const X_ACCEL_BUFFERING: HeaderName = HeaderName::from_static("x-accel-buffering");

/// Identifies the exact browser endpoint whose POST is a read capability
/// acquisition rather than an account or repository mutation.
///
/// The human-auth middleware uses this classifier to admit anonymous viewers
/// of public logs and to avoid requiring a CSRF token for authenticated
/// viewers. The endpoint itself still requires the configured exact Origin,
/// an empty body, durable log authorization, and a one-time ticket.
pub(crate) fn is_browser_live_log_ticket_request(method: &Method, path: &str) -> bool {
    if method != Method::POST {
        return false;
    }
    let mut segments = path.strip_prefix('/').unwrap_or_default().split('/');
    let (
        Some(owner),
        Some(repository),
        Some("actions"),
        Some("runs"),
        Some(run_id),
        Some("jobs"),
        Some(job_id),
        Some("live-ticket"),
        None,
    ) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    )
    else {
        return false;
    };
    valid_route_segment(owner)
        && valid_route_segment(repository)
        && parse_run_id(run_id).is_some()
        && parse_job_id(job_id).is_some()
}

/// Shared ticket, authorization, replay, and notification dependencies.
#[derive(Clone)]
pub(crate) struct LiveLogService {
    data: Arc<dyn WebData>,
    tickets: Arc<dyn HumanLiveLogTicketRepository>,
    notifications: Arc<HumanLogCommitNotificationHub>,
}

impl LiveLogService {
    #[must_use]
    pub(crate) const fn new(
        data: Arc<dyn WebData>,
        tickets: Arc<dyn HumanLiveLogTicketRepository>,
        notifications: Arc<HumanLogCommitNotificationHub>,
    ) -> Self {
        Self {
            data,
            tickets,
            notifications,
        }
    }

    /// Reuses Core's exact human log authorization and issues one random ticket.
    pub(crate) async fn issue(
        &self,
        context: &RequestContext,
        repository: &RepositoryPath,
        run_id: RunId,
        job_id: JobId,
        browser_origin: HumanLiveLogBrowserOrigin,
    ) -> Result<Option<IssuedLiveLogAccess>, LiveLogServiceError> {
        let Some(authorized) = self
            .data
            .authorize_live_log(context, repository, run_id, job_id)
            .await
            .map_err(LiveLogServiceError::Data)?
        else {
            return Ok(None);
        };
        for _ in 0..MAX_TICKET_GENERATION_ATTEMPTS {
            let credential = generate_ticket()?;
            let digest = ticket_digest(credential.expose_secret())?;
            let request = IssueHumanLiveLogTicket::new(
                digest,
                authorized.scope.clone(),
                browser_origin.clone(),
                MAX_HUMAN_LIVE_LOG_TICKET_LIFETIME,
            )
            .map_err(|_| LiveLogServiceError::Internal)?;
            match self.tickets.issue(&request).await {
                Ok(IssueHumanLiveLogTicketOutcome::Issued(receipt)) => {
                    return Ok(Some(IssuedLiveLogAccess {
                        credential,
                        expires_at: receipt.expires_at(),
                    }));
                }
                Ok(IssueHumanLiveLogTicketOutcome::DigestCollision) => {}
                Err(error) => {
                    error!(%error, "failed to persist a live-log ticket");
                    return Err(LiveLogServiceError::Unavailable);
                }
            }
        }
        Err(LiveLogServiceError::Internal)
    }

    async fn redeem(
        &self,
        raw_ticket: &str,
        browser_origin: HumanLiveLogBrowserOrigin,
    ) -> Result<Option<HumanLiveLogScope>, LiveLogServiceError> {
        let digest = ticket_digest(raw_ticket)?;
        let request = RedeemHumanLiveLogTicket::new(digest, browser_origin);
        match self.tickets.redeem(&request).await {
            Ok(Some(redeemed)) => Ok(Some(redeemed.scope().clone())),
            Ok(None) => Ok(None),
            Err(error) => {
                error!(%error, "failed to redeem a live-log ticket");
                Err(LiveLogServiceError::Unavailable)
            }
        }
    }

    async fn read(
        &self,
        scope: &HumanLiveLogScope,
        checkpoint: Option<&str>,
        replay_checkpoint: bool,
    ) -> Result<Option<LiveLogBatch>, LiveLogServiceError> {
        self.data
            .read_live_log(scope, checkpoint, replay_checkpoint)
            .await
            .map_err(LiveLogServiceError::Data)
    }

    fn subscribe(&self, scope: &HumanLiveLogScope) -> HumanLogCommitSubscription {
        self.notifications.subscribe(scope.stream_id())
    }
}

impl fmt::Debug for LiveLogService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LiveLogService")
            .field("data", &self.data)
            .field("tickets", &"[REDACTED]")
            .field("notifications", &self.notifications)
            .finish()
    }
}

#[derive(Debug)]
pub(crate) struct IssuedLiveLogAccess {
    credential: SecretString,
    expires_at: UnixMillis,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveLogServiceError {
    InvalidCredential,
    Data(WebDataError),
    Unavailable,
    Internal,
}

#[derive(Clone)]
struct BrowserTicketState {
    service: Arc<LiveLogService>,
    origin: HumanLiveLogBrowserOrigin,
}

impl fmt::Debug for BrowserTicketState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserTicketState")
            .field("service", &self.service)
            .field("origin", &self.origin)
            .finish()
    }
}

/// Builds the session- and CSRF-protected browser ticket endpoint.
pub(crate) fn browser_ticket_router(
    service: Arc<LiveLogService>,
    origin: HumanLiveLogBrowserOrigin,
) -> Router {
    Router::new()
        .route(BROWSER_LIVE_LOG_TICKET_PATH, post(issue_browser_ticket))
        .with_state(BrowserTicketState { service, origin })
}

async fn issue_browser_ticket(
    State(state): State<BrowserTicketState>,
    Extension(context): Extension<RequestContext>,
    Path((owner, repository, run_id, job_id)): Path<(String, String, String, String)>,
    request: Request,
) -> Response {
    if request.uri().query().is_some()
        || request_origin(request.headers()) != Some(state.origin.as_str())
        || !request_body_is_empty(request).await
    {
        return json_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let Some(repository) = repository_path(owner, repository) else {
        return json_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let (Some(run_id), Some(job_id)) = (parse_run_id(&run_id), parse_job_id(&job_id)) else {
        return json_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    match state
        .service
        .issue(&context, &repository, run_id, job_id, state.origin)
        .await
    {
        Ok(Some(issued)) => issued_response(&issued),
        Ok(None) => json_error(StatusCode::NOT_FOUND, "not_found"),
        Err(error) => service_error_response(error),
    }
}

#[derive(Clone)]
struct StreamState {
    service: Arc<LiveLogService>,
    allowed_origins: Arc<BTreeSet<String>>,
}

impl fmt::Debug for StreamState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StreamState")
            .field("service", &self.service)
            .field("allowed_origins", &self.allowed_origins)
            .finish()
    }
}

/// Builds the credential-only SSE endpoint outside ordinary human middleware.
pub(crate) fn stream_router(
    service: Arc<LiveLogService>,
    allowed_origins: BTreeSet<String>,
) -> Router {
    Router::new()
        .route(LIVE_LOG_SSE_PATH, post(stream_sse).options(preflight_sse))
        .with_state(StreamState {
            service,
            allowed_origins: Arc::new(allowed_origins),
        })
}

async fn preflight_sse(State(state): State<StreamState>, headers: HeaderMap) -> Response {
    let Some(origin) = allowed_request_origin(&state, &headers) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if exact_header(&headers, &ACCESS_CONTROL_REQUEST_METHOD) != Some("POST")
        || !valid_preflight_headers(exact_header(&headers, &ACCESS_CONTROL_REQUEST_HEADERS))
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    insert_cors_headers(response.headers_mut(), origin);
    response.headers_mut().insert(
        ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("POST"),
    );
    response.headers_mut().insert(
        ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("authorization, last-event-id"),
    );
    response
        .headers_mut()
        .insert(ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("300"));
    response
}

async fn stream_sse(State(state): State<StreamState>, request: Request) -> Response {
    if request.method() != Method::POST || request.uri().query().is_some() {
        return stream_error(StatusCode::BAD_REQUEST, "invalid_request", None);
    }
    let Some(origin) = allowed_request_origin(&state, request.headers()) else {
        return stream_error(StatusCode::FORBIDDEN, "forbidden", None);
    };
    let Ok(origin) = HumanLiveLogBrowserOrigin::new(origin.to_owned()) else {
        return stream_error(StatusCode::FORBIDDEN, "forbidden", None);
    };
    let Some(ticket) = authorization_ticket(request.headers()) else {
        return stream_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            Some(origin.as_str()),
        );
    };
    let Ok(ticket) = SecretString::new(ticket.to_owned()) else {
        return stream_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            Some(origin.as_str()),
        );
    };
    let checkpoint = match checkpoint_header(request.headers()) {
        Ok(checkpoint) => checkpoint.map(str::to_owned),
        Err(()) => {
            return stream_error(
                StatusCode::BAD_REQUEST,
                "invalid_checkpoint",
                Some(origin.as_str()),
            );
        }
    };
    if !request_body_is_empty(request).await {
        return stream_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some(origin.as_str()),
        );
    }
    let scope = match state
        .service
        .redeem(ticket.expose_secret(), origin.clone())
        .await
    {
        Ok(Some(scope)) => scope,
        Ok(None) | Err(LiveLogServiceError::InvalidCredential) => {
            return stream_error(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                Some(origin.as_str()),
            );
        }
        Err(error) => {
            return stream_service_error(error, Some(origin.as_str()));
        }
    };
    let tail = SseTail::new(Arc::clone(&state.service), scope, checkpoint);
    let body = Body::from_stream(stream::unfold(tail, SseTail::next));
    let mut response = Response::new(body);
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream; charset=utf-8"),
    );
    headers.insert(X_ACCEL_BUFFERING, HeaderValue::from_static("no"));
    insert_cors_headers(headers, origin.as_str());
    response
}

struct SseTail {
    service: Arc<LiveLogService>,
    scope: HumanLiveLogScope,
    subscription: HumanLogCommitSubscription,
    checkpoint: Option<String>,
    replay_checkpoint: bool,
    pending: VecDeque<Bytes>,
    deadline: Instant,
    last_write: Instant,
    finished: bool,
}

impl SseTail {
    fn new(
        service: Arc<LiveLogService>,
        scope: HumanLiveLogScope,
        checkpoint: Option<String>,
    ) -> Self {
        let subscription = service.subscribe(&scope);
        let now = Instant::now();
        let mut pending = VecDeque::new();
        pending.push_back(Bytes::from_static(b": connected\nretry: 1000\n\n"));
        Self {
            service,
            scope,
            subscription,
            checkpoint,
            replay_checkpoint: true,
            pending,
            deadline: now + SSE_CONNECTION_LIFETIME,
            last_write: now,
            finished: false,
        }
    }

    async fn next(mut self) -> Option<(Result<Bytes, Infallible>, Self)> {
        loop {
            if let Some(bytes) = self.pending.pop_front() {
                self.last_write = Instant::now();
                return Some((Ok(bytes), self));
            }
            if self.finished {
                return None;
            }
            if Instant::now() >= self.deadline {
                self.pending.push_back(sse_reconnect_event());
                self.finished = true;
                continue;
            }
            let batch = match self
                .service
                .read(
                    &self.scope,
                    self.checkpoint.as_deref(),
                    self.replay_checkpoint,
                )
                .await
            {
                Ok(Some(batch)) => batch,
                Ok(None) => {
                    self.pending.push_back(sse_error_event("stream_changed"));
                    self.finished = true;
                    continue;
                }
                Err(error) => {
                    error!(?error, "live-log durable tail failed");
                    self.pending.push_back(sse_error_event("unavailable"));
                    self.finished = true;
                    continue;
                }
            };
            self.replay_checkpoint = false;
            self.checkpoint.clone_from(&batch.checkpoint);
            for record in batch.records {
                if let Ok(event) = sse_log_event(&self.scope, &record) {
                    self.pending.push_back(event);
                } else {
                    self.pending.push_back(sse_error_event("internal_error"));
                    self.finished = true;
                    break;
                }
            }
            if batch.stream_closed && !batch.more_available && !self.finished {
                if let Some(checkpoint) = self.checkpoint.as_deref() {
                    self.pending.push_back(sse_complete_event(checkpoint));
                } else {
                    self.pending.push_back(sse_error_event("internal_error"));
                }
                self.finished = true;
            }
            if !self.pending.is_empty() || self.finished {
                continue;
            }
            if batch.more_available {
                continue;
            }
            let wait = self
                .deadline
                .saturating_duration_since(Instant::now())
                .min(DURABLE_RECHECK_INTERVAL);
            if wait.is_zero() {
                continue;
            }
            let _wake = self.subscription.wait_or_recheck(wait).await;
            if self.last_write.elapsed() >= SSE_HEARTBEAT_INTERVAL {
                self.pending
                    .push_back(Bytes::from_static(b": keepalive\n\n"));
            }
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TicketResponse<'a> {
    protocol_version: u16,
    ticket: &'a str,
    expires_at_ms: i64,
    transports: [TransportCapability; 1],
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
struct TransportCapability {
    kind: &'static str,
    method: &'static str,
    path: &'static str,
}

pub(crate) fn issued_response(issued: &IssuedLiveLogAccess) -> Response {
    let response = TicketResponse {
        protocol_version: HUMAN_LIVE_LOG_PROTOCOL_VERSION,
        ticket: issued.credential.expose_secret(),
        expires_at_ms: issued.expires_at.get(),
        transports: [TransportCapability {
            kind: "sse",
            method: "POST",
            path: LIVE_LOG_SSE_PATH,
        }],
    };
    ([(CACHE_CONTROL, "no-store")], Json(response)).into_response()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SseLogDocument<'a> {
    protocol_version: u16,
    stream_id: String,
    /// Decimal text preserves the complete u64 identity in JavaScript.
    sequence: String,
    emitted_at_ms: i64,
    #[serde(flatten)]
    record: SseLogRecord<'a>,
}

#[derive(Serialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum SseLogRecord<'a> {
    GroupStarted {
        group: SseLogGroup<'a>,
    },
    Output {
        group_id: &'a str,
        channel: &'static str,
        part: u32,
        data_base64: &'a str,
    },
    GroupFinished {
        group_id: &'a str,
        conclusion: &'static str,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SseLogGroup<'a> {
    id: &'a str,
    parent_id: Option<&'a str>,
    name: &'a str,
    kind: &'static str,
    ordinal: u32,
}

fn sse_log_event(scope: &HumanLiveLogScope, record: &LiveLogRecord) -> Result<Bytes, ()> {
    let (sequence, emitted_at_ms, payload) = match &record.record {
        LogRecord::GroupStarted {
            sequence,
            emitted_at,
            group,
        } => (
            *sequence,
            emitted_at.get(),
            SseLogRecord::GroupStarted {
                group: sse_log_group(group),
            },
        ),
        LogRecord::Output(output) => (
            output.sequence,
            output.emitted_at.get(),
            SseLogRecord::Output {
                group_id: &output.group_id,
                channel: match output.channel {
                    LogChannel::Stdout => "stdout",
                    LogChannel::Stderr => "stderr",
                    LogChannel::System => "system",
                },
                part: output.part,
                data_base64: &output.data_base64,
            },
        ),
        LogRecord::GroupFinished {
            sequence,
            emitted_at,
            group_id,
            conclusion,
        } => (
            *sequence,
            emitted_at.get(),
            SseLogRecord::GroupFinished {
                group_id,
                conclusion: match conclusion {
                    automata_ci_core::JobConclusion::Success => "success",
                    automata_ci_core::JobConclusion::Failure => "failure",
                    automata_ci_core::JobConclusion::Cancelled => "cancelled",
                    automata_ci_core::JobConclusion::TimedOut => "timed_out",
                    automata_ci_core::JobConclusion::Skipped => "skipped",
                },
            },
        ),
    };
    let document = SseLogDocument {
        protocol_version: HUMAN_LIVE_LOG_PROTOCOL_VERSION,
        stream_id: scope.stream_id().to_string(),
        sequence: sequence.to_string(),
        emitted_at_ms,
        record: payload,
    };
    let json = serde_json::to_string(&document).map_err(|_| ())?;
    Ok(Bytes::from(format!(
        "id: {}\nevent: log\ndata: {json}\n\n",
        record.checkpoint
    )))
}

fn sse_log_group(group: &LogGroup) -> SseLogGroup<'_> {
    SseLogGroup {
        id: &group.id,
        parent_id: group.parent_id.as_deref(),
        name: &group.name,
        kind: match group.kind {
            LogGroupKind::Setup => "setup",
            LogGroupKind::Step => "step",
            LogGroupKind::ActionPre => "action_pre",
            LogGroupKind::ActionPost => "action_post",
            LogGroupKind::Cleanup => "cleanup",
        },
        ordinal: group.ordinal,
    }
}

fn sse_complete_event(checkpoint: &str) -> Bytes {
    Bytes::from(format!(
        "id: {checkpoint}\nevent: complete\ndata: {{\"protocolVersion\":{HUMAN_LIVE_LOG_PROTOCOL_VERSION}}}\n\n"
    ))
}

fn sse_reconnect_event() -> Bytes {
    Bytes::from(format!(
        "event: reconnect\ndata: {{\"protocolVersion\":{HUMAN_LIVE_LOG_PROTOCOL_VERSION}}}\n\n"
    ))
}

fn sse_error_event(error: &'static str) -> Bytes {
    Bytes::from(format!(
        "event: error\ndata: {{\"protocolVersion\":{HUMAN_LIVE_LOG_PROTOCOL_VERSION},\"error\":\"{error}\"}}\n\n"
    ))
}

fn generate_ticket() -> Result<SecretString, LiveLogServiceError> {
    let mut entropy = Zeroizing::new([0_u8; TICKET_RANDOM_BYTES]);
    getrandom::fill(entropy.as_mut()).map_err(|_| LiveLogServiceError::Internal)?;
    let encoded = URL_SAFE_NO_PAD.encode(entropy.as_ref());
    SecretString::new(format!("{TICKET_PREFIX}{encoded}"))
        .map_err(|_| LiveLogServiceError::Internal)
}

fn ticket_digest(raw: &str) -> Result<[u8; 32], LiveLogServiceError> {
    if raw.len() != TICKET_LENGTH || !raw.starts_with(TICKET_PREFIX) {
        return Err(LiveLogServiceError::InvalidCredential);
    }
    let encoded = &raw[TICKET_PREFIX.len()..];
    let mut decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| LiveLogServiceError::InvalidCredential)?;
    let canonical =
        decoded.len() == TICKET_RANDOM_BYTES && URL_SAFE_NO_PAD.encode(&decoded) == encoded;
    decoded.zeroize();
    if !canonical {
        return Err(LiveLogServiceError::InvalidCredential);
    }
    Ok(Sha256::digest(raw.as_bytes()).into())
}

fn authorization_ticket(headers: &HeaderMap) -> Option<&str> {
    let value = exact_header(headers, &AUTHORIZATION)?;
    let ticket = value.strip_prefix("AutomataLogTicket ")?;
    (ticket.len() == TICKET_LENGTH && !ticket.bytes().any(|byte| byte.is_ascii_whitespace()))
        .then_some(ticket)
}

fn checkpoint_header(headers: &HeaderMap) -> Result<Option<&str>, ()> {
    let Some(value) = exact_optional_header(headers, &LAST_EVENT_ID)? else {
        return Ok(None);
    };
    if value.is_empty()
        || value.len() > MAX_CHECKPOINT_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(());
    }
    Ok(Some(value))
}

fn request_origin(headers: &HeaderMap) -> Option<&str> {
    exact_header(headers, &ORIGIN)
}

fn allowed_request_origin<'a>(state: &StreamState, headers: &'a HeaderMap) -> Option<&'a str> {
    let origin = request_origin(headers)?;
    state.allowed_origins.contains(origin).then_some(origin)
}

fn exact_header<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<&'a str> {
    exact_optional_header(headers, name).ok().flatten()
}

fn exact_optional_header<'a>(
    headers: &'a HeaderMap,
    name: &HeaderName,
) -> Result<Option<&'a str>, ()> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    value.to_str().map(Some).map_err(|_| ())
}

fn valid_preflight_headers(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let mut saw_authorization = false;
    for header in value.split(',').map(str::trim) {
        if header.eq_ignore_ascii_case("authorization") {
            if saw_authorization {
                return false;
            }
            saw_authorization = true;
        } else if !header.eq_ignore_ascii_case("last-event-id") {
            return false;
        }
    }
    saw_authorization
}

fn insert_cors_headers(headers: &mut HeaderMap, origin: &str) {
    if let Ok(origin) = HeaderValue::from_str(origin) {
        headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    }
    headers.append(VARY, HeaderValue::from_static("Origin"));
}

async fn request_body_is_empty(request: Request) -> bool {
    if request
        .headers()
        .get(CONTENT_LENGTH)
        .is_some_and(|length| length != "0")
    {
        return false;
    }
    to_bytes(request.into_body(), MAX_REQUEST_BODY_BYTES)
        .await
        .is_ok_and(|bytes| bytes.is_empty())
}

pub(crate) fn repository_path(owner: String, name: String) -> Option<RepositoryPath> {
    (valid_route_segment(&owner) && valid_route_segment(&name))
        .then_some(RepositoryPath { owner, name })
}

fn valid_route_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !matches!(value, "." | "..")
        && !value.chars().any(char::is_control)
}

pub(crate) fn parse_run_id(value: &str) -> Option<RunId> {
    let id = RunId::from_str(value).ok()?;
    (!id.as_uuid().is_nil() && id.to_string() == value).then_some(id)
}

pub(crate) fn parse_job_id(value: &str) -> Option<JobId> {
    let id = JobId::from_str(value).ok()?;
    (!id.as_uuid().is_nil() && id.to_string() == value).then_some(id)
}

pub(crate) fn service_error_response(error: LiveLogServiceError) -> Response {
    match error {
        LiveLogServiceError::InvalidCredential => {
            json_error(StatusCode::UNAUTHORIZED, "unauthorized")
        }
        LiveLogServiceError::Data(WebDataError::InvalidRequest) => {
            json_error(StatusCode::BAD_REQUEST, "invalid_request")
        }
        LiveLogServiceError::Data(WebDataError::Unavailable) | LiveLogServiceError::Unavailable => {
            json_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
        }
        LiveLogServiceError::Data(WebDataError::Corrupt) | LiveLogServiceError::Internal => {
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
        }
    }
}

fn stream_service_error(error: LiveLogServiceError, origin: Option<&str>) -> Response {
    match error {
        LiveLogServiceError::InvalidCredential => {
            stream_error(StatusCode::UNAUTHORIZED, "unauthorized", origin)
        }
        LiveLogServiceError::Data(WebDataError::InvalidRequest) => {
            stream_error(StatusCode::BAD_REQUEST, "invalid_request", origin)
        }
        LiveLogServiceError::Data(WebDataError::Unavailable) | LiveLogServiceError::Unavailable => {
            stream_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", origin)
        }
        LiveLogServiceError::Data(WebDataError::Corrupt) | LiveLogServiceError::Internal => {
            stream_error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", origin)
        }
    }
}

fn json_error(status: StatusCode, code: &'static str) -> Response {
    (
        status,
        [(CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({ "error": code })),
    )
        .into_response()
}

fn stream_error(status: StatusCode, code: &'static str, origin: Option<&str>) -> Response {
    let mut response = json_error(status, code);
    if let Some(origin) = origin {
        insert_cors_headers(response.headers_mut(), origin);
    }
    response
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use automata_ci_core::{AttemptId, LogStreamId};
    use automata_ci_store::{RedeemedHumanLiveLogTicket, RepositoryId, StoreError, TenantScope};
    use tokio::sync::Mutex;
    use tower::ServiceExt as _;
    use uuid::Uuid;

    use super::*;
    use crate::app::web::EmptyWebData;

    #[derive(Debug)]
    struct OneTicketRepository {
        entry: Mutex<Option<([u8; 32], HumanLiveLogBrowserOrigin, HumanLiveLogScope)>>,
    }

    #[async_trait]
    impl HumanLiveLogTicketRepository for OneTicketRepository {
        async fn issue(
            &self,
            _request: &IssueHumanLiveLogTicket,
        ) -> Result<IssueHumanLiveLogTicketOutcome, StoreError> {
            Ok(IssueHumanLiveLogTicketOutcome::DigestCollision)
        }

        async fn redeem(
            &self,
            request: &RedeemHumanLiveLogTicket,
        ) -> Result<Option<RedeemedHumanLiveLogTicket>, StoreError> {
            let mut entry = self.entry.lock().await;
            let Some((digest, origin, _)) = entry.as_ref() else {
                return Ok(None);
            };
            if digest != request.token_sha256() || origin != request.browser_origin() {
                return Ok(None);
            }
            let (_, _, scope) = entry.take().expect("matched ticket remains present");
            Ok(Some(RedeemedHumanLiveLogTicket::new(
                scope,
                UnixMillis::new(1),
                UnixMillis::new(2),
            )))
        }
    }

    fn fixture_scope() -> HumanLiveLogScope {
        HumanLiveLogScope::new(
            TenantScope::from_authenticated_tenant_id("workspace".to_owned()).expect("tenant"),
            RepositoryId::from_uuid(Uuid::from_u128(1)),
            RunId::from_uuid(Uuid::from_u128(2)),
            JobId::from_uuid(Uuid::from_u128(3)),
            AttemptId::from_uuid(Uuid::from_u128(4)),
            LogStreamId::from_uuid(Uuid::from_u128(5)),
        )
        .expect("live-log scope")
    }

    fn stream_request(origin: &str, ticket: &str) -> Request {
        Request::builder()
            .method(Method::POST)
            .uri(LIVE_LOG_SSE_PATH)
            .header(ORIGIN, origin)
            .header(AUTHORIZATION, format!("AutomataLogTicket {ticket}"))
            .body(Body::empty())
            .expect("stream request")
    }

    #[test]
    fn generated_ticket_is_strictly_canonical_and_redacted() {
        let ticket = generate_ticket().expect("random ticket");
        assert!(ticket.expose_secret().starts_with(TICKET_PREFIX));
        assert_eq!(ticket.expose_secret().len(), TICKET_LENGTH);
        assert!(ticket_digest(ticket.expose_secret()).is_ok());
        assert!(ticket_digest("allt_v3_not-canonical").is_err());
        assert!(!format!("{ticket:?}").contains(ticket.expose_secret()));
    }

    #[test]
    fn sse_log_sequences_remain_lossless_for_javascript_clients() {
        let document = SseLogDocument {
            protocol_version: HUMAN_LIVE_LOG_PROTOCOL_VERSION,
            stream_id: Uuid::from_u128(5).to_string(),
            sequence: u64::MAX.to_string(),
            emitted_at_ms: 1_777_890_010_000,
            record: SseLogRecord::Output {
                group_id: "phase/1",
                channel: "stdout",
                part: 0,
                data_base64: "Y29tcGxldGU",
            },
        };

        let json = serde_json::to_string(&document).expect("SSE JSON");

        assert!(json.contains(r#""sequence":"18446744073709551615""#));
        assert!(json.contains(r#""groupId":"phase/1""#));
        assert!(!json.contains(r#""group_id""#));
        assert!(!json.contains(r#""sequence":18446744073709551615"#));
    }

    #[test]
    fn every_sse_record_uses_the_browser_protocol_field_names() {
        let finished = SseLogDocument {
            protocol_version: HUMAN_LIVE_LOG_PROTOCOL_VERSION,
            stream_id: Uuid::from_u128(5).to_string(),
            sequence: "2".to_owned(),
            emitted_at_ms: 1_777_890_010_000,
            record: SseLogRecord::GroupFinished {
                group_id: "phase/1",
                conclusion: "success",
            },
        };

        let json = serde_json::to_string(&finished).expect("SSE JSON");

        assert!(json.contains(r#""groupId":"phase/1""#));
        assert!(!json.contains(r#""group_id""#));
    }

    #[test]
    fn sse_completion_carries_the_terminal_checkpoint() {
        assert_eq!(
            sse_complete_event("checkpoint_terminal"),
            Bytes::from_static(
                b"id: checkpoint_terminal\nevent: complete\ndata: {\"protocolVersion\":3}\n\n",
            ),
        );
    }

    #[test]
    fn preflight_requires_only_the_bounded_supported_headers() {
        assert!(valid_preflight_headers(Some("authorization")));
        assert!(valid_preflight_headers(Some(
            "Authorization, Last-Event-ID"
        )));
        assert!(!valid_preflight_headers(Some("last-event-id")));
        assert!(!valid_preflight_headers(Some("authorization, cookie")));
    }

    #[tokio::test]
    async fn sse_ticket_is_origin_bound_one_time_and_never_placed_in_the_url() {
        let ticket = format!("{TICKET_PREFIX}{}", URL_SAFE_NO_PAD.encode([9_u8; 32]));
        let digest = ticket_digest(&ticket).expect("ticket digest");
        let expected_origin =
            HumanLiveLogBrowserOrigin::new("https://cloud.automata.example").expect("origin");
        let wrong_origin =
            HumanLiveLogBrowserOrigin::new("https://other.automata.example").expect("origin");
        let repository = Arc::new(OneTicketRepository {
            entry: Mutex::new(Some((digest, expected_origin.clone(), fixture_scope()))),
        });
        let service = Arc::new(LiveLogService::new(
            Arc::new(EmptyWebData),
            repository,
            Arc::new(HumanLogCommitNotificationHub::default()),
        ));
        let origins = BTreeSet::from([
            expected_origin.as_str().to_owned(),
            wrong_origin.as_str().to_owned(),
        ]);
        let app = stream_router(service, origins);

        let wrong = app
            .clone()
            .oneshot(stream_request(wrong_origin.as_str(), &ticket))
            .await
            .expect("wrong-origin response");
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);

        let accepted = app
            .clone()
            .oneshot(stream_request(expected_origin.as_str(), &ticket))
            .await
            .expect("accepted stream");
        assert_eq!(accepted.status(), StatusCode::OK);
        assert_eq!(
            accepted.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN),
            Some(&HeaderValue::from_static("https://cloud.automata.example"))
        );
        let body = to_bytes(accepted.into_body(), 4 * 1024)
            .await
            .expect("bounded stream body");
        let body = String::from_utf8(body.to_vec()).expect("UTF-8 SSE");
        assert!(body.contains(": connected"));
        assert!(body.contains("event: error"));
        assert!(!body.contains(&ticket));

        let replay = app
            .oneshot(stream_request(expected_origin.as_str(), &ticket))
            .await
            .expect("replay response");
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    }
}
