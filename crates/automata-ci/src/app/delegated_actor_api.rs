//! Hosted Core HTTP ingress for short-lived Cloud actor assertions.

use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr as _,
    sync::Arc,
    time::{Duration, Instant},
};

use automata_ci_auth::{
    authorization::Permission,
    delegated_actor::{
        DelegatedActorAssertion, DelegatedActorRequestSnapshot, DelegatedActorResolver,
        DelegatedActorResolverError, DelegatedRepositoryMutationActor,
        MAX_DELEGATED_TENANT_PERMISSION_CHECKS, ResolveDelegatedActorOutcome,
        ResolveDelegatedActorRequest,
    },
    human::TenantId,
    time::UnixTimestamp,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::StreamExt as _;
use reqwest::Client;
use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use url::Url;
use uuid::Uuid;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, RawQuery, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::{get, post},
};

use super::web::{
    ArtifactSummary, CollectionVisibility, JobLogPage, JobSummary, REPOSITORY_PAGE_SIZE,
    RUN_JOB_PAGE_SIZE, RUN_PAGE_SIZE, Repository, RepositoryDirectoryItem, RepositoryDirectoryPage,
    RepositoryDirectoryRequest, RepositorySettingsDestination, RunDetailPage, RunDetailRequest,
    RunListPage, RunListRequest, RunSummary, Status, StatusFilter, WebData, WebDataError, Workflow,
    WorkflowDefinition,
};
use super::{
    live_log::{
        LiveLogService, issued_response, parse_job_id, parse_run_id, repository_path,
        service_error_response,
    },
    web::{RequestContext, Viewer},
    workflow_dispatch_api::{WorkflowDispatchApiBackend, dispatch_delegated_workflow},
};
use automata_ci_core::WorkflowId;
use automata_ci_store::HumanLiveLogBrowserOrigin;

/// Protected Core endpoint used by Cloud to resolve the current viewer.
pub const DELEGATED_ACTOR_VIEWER_PATH: &str = "/internal/v2/tenants/{tenant_id}/viewer";
/// Protected Core endpoint used by Cloud to check current tenant permissions.
pub const DELEGATED_ACTOR_AUTHORIZATION_CHECK_PATH: &str =
    "/internal/v2/tenants/{tenant_id}/authorization-checks";
/// Protected Core endpoint used by Cloud to list repositories visible to one actor.
pub const DELEGATED_ACTOR_REPOSITORIES_PATH: &str = "/internal/v2/tenants/{tenant_id}/repositories";
/// Protected Core endpoint used by Cloud to list repository workflow runs.
pub const DELEGATED_ACTOR_RUNS_PATH: &str =
    "/internal/v2/tenants/{tenant_id}/repositories/{owner}/{repository}/runs";
/// Protected Core endpoint used by Cloud to read one run and its current jobs.
pub const DELEGATED_ACTOR_RUN_PATH: &str =
    "/internal/v2/tenants/{tenant_id}/repositories/{owner}/{repository}/runs/{run_id}";
/// Protected Core endpoint used by Cloud to read job and structured-stream metadata.
pub const DELEGATED_ACTOR_JOB_LOG_PATH: &str = "/internal/v2/tenants/{tenant_id}/repositories/{owner}/{repository}/runs/{run_id}/jobs/{job_id}";
/// Protected Core endpoint used by Cloud to authorize one browser log tail.
pub const DELEGATED_ACTOR_LIVE_LOG_TICKET_PATH: &str = "/internal/v2/tenants/{tenant_id}/repositories/{owner}/{repository}/runs/{run_id}/jobs/{job_id}/live-ticket";
/// Protected Core endpoint used by Cloud to dispatch one exact durable workflow source.
pub const DELEGATED_ACTOR_WORKFLOW_DISPATCH_PATH: &str = "/internal/v2/tenants/{tenant_id}/repositories/{repository_id}/workflows/{workflow_id}/dispatches";

const MAX_ASSERTION_BYTES: usize = 8 * 1024;
const MAX_JWT_SEGMENT_BYTES: usize = 6 * 1024;
const MAX_JWKS_BYTES: usize = 64 * 1024;
const MAX_JWKS_KEYS: usize = 32;
const MAX_KEY_ID_BYTES: usize = 128;
const MAX_AUTHORIZATION_CHECK_BODY_BYTES: usize = 4 * 1024;
const ALLOWED_CLOCK_SKEW_SECONDS: u64 = 30;
const JWKS_CACHE_LIFETIME: Duration = Duration::from_mins(5);

/// Exact trust configuration for Cloud delegated actor assertions.
#[derive(Clone, Debug)]
pub(crate) struct DelegatedActorVerifierConfig {
    pub(crate) issuer: String,
    pub(crate) audience: String,
    pub(crate) jwks_url: Url,
}

/// Cached ES256 verifier for one explicitly configured Cloud authority.
pub(crate) struct DelegatedActorVerifier {
    config: DelegatedActorVerifierConfig,
    client: Client,
    cache: Mutex<Option<CachedJwks>>,
}

impl std::fmt::Debug for DelegatedActorVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DelegatedActorVerifier")
            .field("issuer", &self.config.issuer)
            .field("audience", &self.config.audience)
            .field("jwks_url", &self.config.jwks_url)
            .finish_non_exhaustive()
    }
}

impl DelegatedActorVerifier {
    /// Constructs an outbound client that never follows authority redirects.
    pub(crate) fn new(
        config: DelegatedActorVerifierConfig,
    ) -> Result<Self, DelegatedActorVerificationError> {
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| DelegatedActorVerificationError::Unavailable)?;
        Ok(Self {
            config,
            client,
            cache: Mutex::new(None),
        })
    }

    async fn verify(
        &self,
        token: &str,
        now: UnixTimestamp,
    ) -> Result<VerifiedDelegatedActor, DelegatedActorVerificationError> {
        if token.is_empty() || token.len() > MAX_ASSERTION_BYTES || !token.is_ascii() {
            return Err(DelegatedActorVerificationError::Rejected);
        }
        let mut segments = token.split('.');
        let encoded_header = segments
            .next()
            .ok_or(DelegatedActorVerificationError::Rejected)?;
        let encoded_claims = segments
            .next()
            .ok_or(DelegatedActorVerificationError::Rejected)?;
        let encoded_signature = segments
            .next()
            .ok_or(DelegatedActorVerificationError::Rejected)?;
        if segments.next().is_some()
            || encoded_header.len() > MAX_JWT_SEGMENT_BYTES
            || encoded_claims.len() > MAX_JWT_SEGMENT_BYTES
            || encoded_signature.len() > MAX_JWT_SEGMENT_BYTES
        {
            return Err(DelegatedActorVerificationError::Rejected);
        }
        let header: ProtectedHeader = parse_canonical_segment(encoded_header)?;
        if header.alg != "ES256" || header.typ != "at+jwt" || !valid_key_id(&header.kid) {
            return Err(DelegatedActorVerificationError::Rejected);
        }
        let signature = decode_canonical_segment(encoded_signature)?;
        if signature.len() != 64 {
            return Err(DelegatedActorVerificationError::Rejected);
        }
        let public_key = self.public_key(&header.kid).await?;
        let signing_input = format!("{encoded_header}.{encoded_claims}");
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key)
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| DelegatedActorVerificationError::Rejected)?;

        let claims: DelegatedActorClaims = parse_canonical_segment(encoded_claims)?;
        if claims.ver != 1
            || claims.iss != self.config.issuer
            || claims.aud != self.config.audience
            || claims.iat > now.as_seconds().saturating_add(ALLOWED_CLOCK_SKEW_SECONDS)
            || claims.exp <= now.as_seconds().saturating_sub(ALLOWED_CLOCK_SKEW_SECONDS)
        {
            return Err(DelegatedActorVerificationError::Rejected);
        }
        let subject = canonical_uuid(&claims.sub)?;
        let tenant_id = canonical_uuid(&claims.tenant_id)?;
        let session_id = canonical_uuid(&claims.session_id)?;
        let assertion_id = canonical_uuid(&claims.jti)?;
        let assertion = DelegatedActorAssertion::new(
            claims.iss,
            subject,
            session_id,
            assertion_id,
            UnixTimestamp::from_seconds(claims.auth_time),
            UnixTimestamp::from_seconds(claims.iat),
            UnixTimestamp::from_seconds(claims.exp),
        )
        .map_err(|_| DelegatedActorVerificationError::Rejected)?;
        Ok(VerifiedDelegatedActor {
            assertion,
            tenant_id,
        })
    }

    async fn public_key(&self, key_id: &str) -> Result<[u8; 65], DelegatedActorVerificationError> {
        let mut cache = self.cache.lock().await;
        if let Some(cached) = cache.as_ref()
            && cached.fetched_at.elapsed() < JWKS_CACHE_LIFETIME
        {
            return cached
                .keys
                .get(key_id)
                .copied()
                .ok_or(DelegatedActorVerificationError::Rejected);
        }
        let fetched = self.fetch_jwks().await?;
        let key = fetched.keys.get(key_id).copied();
        *cache = Some(fetched);
        key.ok_or(DelegatedActorVerificationError::Rejected)
    }

    async fn fetch_jwks(&self) -> Result<CachedJwks, DelegatedActorVerificationError> {
        let response = self
            .client
            .get(self.config.jwks_url.clone())
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| DelegatedActorVerificationError::Unavailable)?;
        if response.status() != StatusCode::OK
            || response
                .content_length()
                .is_some_and(|length| length > MAX_JWKS_BYTES as u64)
            || response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_none_or(|value| !is_json_content_type(value))
        {
            return Err(DelegatedActorVerificationError::Unavailable);
        }
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| DelegatedActorVerificationError::Unavailable)?;
            if body.len().saturating_add(chunk.len()) > MAX_JWKS_BYTES {
                return Err(DelegatedActorVerificationError::Unavailable);
            }
            body.extend_from_slice(&chunk);
        }
        parse_jwks(&body)
    }
}

#[derive(Debug)]
struct VerifiedDelegatedActor {
    assertion: DelegatedActorAssertion,
    tenant_id: Uuid,
}

#[derive(Debug)]
struct CachedJwks {
    fetched_at: Instant,
    keys: BTreeMap<String, [u8; 65]>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedHeader {
    alg: String,
    kid: String,
    typ: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DelegatedActorClaims {
    ver: u8,
    iss: String,
    sub: String,
    aud: String,
    tenant_id: String,
    session_id: String,
    auth_time: u64,
    iat: u64,
    exp: u64,
    jti: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JwkSet {
    keys: Vec<PublicJwk>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicJwk {
    kty: String,
    crv: String,
    alg: String,
    #[serde(rename = "use")]
    usage: String,
    kid: String,
    x: String,
    y: String,
}

fn parse_jwks(body: &[u8]) -> Result<CachedJwks, DelegatedActorVerificationError> {
    let document: JwkSet =
        serde_json::from_slice(body).map_err(|_| DelegatedActorVerificationError::Unavailable)?;
    if document.keys.is_empty() || document.keys.len() > MAX_JWKS_KEYS {
        return Err(DelegatedActorVerificationError::Unavailable);
    }
    let mut keys = BTreeMap::new();
    for key in document.keys {
        if key.kty != "EC"
            || key.crv != "P-256"
            || key.alg != "ES256"
            || key.usage != "sig"
            || !valid_key_id(&key.kid)
        {
            return Err(DelegatedActorVerificationError::Unavailable);
        }
        let x = decode_canonical_segment(&key.x)
            .map_err(|_| DelegatedActorVerificationError::Unavailable)?;
        let y = decode_canonical_segment(&key.y)
            .map_err(|_| DelegatedActorVerificationError::Unavailable)?;
        if x.len() != 32 || y.len() != 32 {
            return Err(DelegatedActorVerificationError::Unavailable);
        }
        let mut public_key = [0_u8; 65];
        public_key[0] = 4;
        public_key[1..33].copy_from_slice(&x);
        public_key[33..].copy_from_slice(&y);
        if keys.insert(key.kid, public_key).is_some() {
            return Err(DelegatedActorVerificationError::Unavailable);
        }
    }
    Ok(CachedJwks {
        fetched_at: Instant::now(),
        keys,
    })
}

fn parse_canonical_segment<T: for<'de> Deserialize<'de>>(
    segment: &str,
) -> Result<T, DelegatedActorVerificationError> {
    let decoded = decode_canonical_segment(segment)?;
    serde_json::from_slice(&decoded).map_err(|_| DelegatedActorVerificationError::Rejected)
}

fn decode_canonical_segment(segment: &str) -> Result<Vec<u8>, DelegatedActorVerificationError> {
    if segment.is_empty() || segment.len() > MAX_JWT_SEGMENT_BYTES {
        return Err(DelegatedActorVerificationError::Rejected);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| DelegatedActorVerificationError::Rejected)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != segment {
        return Err(DelegatedActorVerificationError::Rejected);
    }
    Ok(decoded)
}

fn canonical_uuid(value: &str) -> Result<Uuid, DelegatedActorVerificationError> {
    let parsed = Uuid::parse_str(value).map_err(|_| DelegatedActorVerificationError::Rejected)?;
    if parsed.is_nil() || parsed.hyphenated().to_string() != value {
        return Err(DelegatedActorVerificationError::Rejected);
    }
    Ok(parsed)
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_KEY_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-'))
}

fn is_json_content_type(value: &str) -> bool {
    value
        .split_once(';')
        .map_or(value, |(media_type, _)| media_type)
        .trim()
        .eq_ignore_ascii_case("application/json")
}

/// Sanitized assertion verification result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DelegatedActorVerificationError {
    Rejected,
    Unavailable,
}

#[derive(Clone)]
struct DelegatedActorApiState {
    verifier: Arc<DelegatedActorVerifier>,
    resolver: Arc<dyn DelegatedActorResolver>,
    web_data: Arc<dyn WebData>,
    live_logs: Arc<LiveLogService>,
    browser_origin: HumanLiveLogBrowserOrigin,
    workflow_dispatch: Option<Arc<dyn WorkflowDispatchApiBackend>>,
}

impl std::fmt::Debug for DelegatedActorApiState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DelegatedActorApiState")
            .field("verifier", &self.verifier)
            .field("resolver", &self.resolver)
            .field("web_data", &self.web_data)
            .field("live_logs", &self.live_logs)
            .field("browser_origin", &self.browser_origin)
            .field(
                "workflow_dispatch",
                &self.workflow_dispatch.as_ref().map(|_| "[configured]"),
            )
            .finish()
    }
}

#[derive(Serialize)]
struct TenantViewerResponse {
    protocol_version: u8,
    tenant_id: String,
    principal_id: String,
    display_name: String,
    authorization_revision: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantAuthorizationCheckRequest {
    protocol_version: u8,
    permissions: Vec<String>,
}

#[derive(Serialize)]
struct TenantAuthorizationCheckResponse {
    protocol_version: u8,
    tenant_id: String,
    principal_id: String,
    authorization_revision: u64,
    decisions: Vec<TenantPermissionDecisionResponse>,
}

#[derive(Serialize)]
struct TenantPermissionDecisionResponse {
    permission: String,
    allowed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RepositoryDirectoryQuery {
    cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunListQuery {
    workflow_id: Option<String>,
    workflow_cursor: Option<String>,
    status: Option<String>,
    branch: Option<String>,
    cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunDetailQuery {
    job_cursor: Option<String>,
}

#[derive(Serialize)]
struct RepositoryDirectoryResponse {
    protocol_version: u8,
    tenant_id: String,
    repositories: Vec<RepositoryDirectoryItemResponse>,
    next_cursor: Option<String>,
}

#[derive(Serialize)]
struct RepositoryDirectoryItemResponse {
    repository: RepositoryResponse,
    actions_visible: bool,
    settings_destination: Option<&'static str>,
}

#[derive(Serialize)]
struct RepositoryResponse {
    id: String,
    scm_provider: String,
    owner: String,
    name: String,
    settings_visible: bool,
}

#[derive(Serialize)]
struct RunListResponse {
    protocol_version: u8,
    tenant_id: String,
    repository: RepositoryResponse,
    workflows: Vec<WorkflowDefinitionResponse>,
    selected_workflow: Option<WorkflowDefinitionResponse>,
    workflow_previous_cursor: Option<String>,
    workflow_next_cursor: Option<String>,
    runs: Vec<RunSummaryResponse>,
    previous_cursor: Option<String>,
    next_cursor: Option<String>,
}

#[derive(Serialize)]
struct WorkflowDefinitionResponse {
    id: String,
    name: String,
    enabled: bool,
}

#[derive(Serialize)]
struct WorkflowResponse {
    id: String,
    name: String,
    path: String,
}

#[derive(Serialize)]
struct RunSummaryResponse {
    id: String,
    number: String,
    attempt: u32,
    title: Option<String>,
    workflow: WorkflowResponse,
    status: &'static str,
    git_ref: Option<String>,
    event: String,
    actor: Option<String>,
    head_sha: String,
    commit_subject: Option<String>,
    created_at_ms: i64,
    finished_at_ms: Option<i64>,
}

#[derive(Serialize)]
struct RunDetailResponse {
    protocol_version: u8,
    tenant_id: String,
    repository: RepositoryResponse,
    run: RunSummaryResponse,
    jobs: VisibleCollectionResponse<JobSummaryResponse>,
    job_previous_cursor: Option<String>,
    job_next_cursor: Option<String>,
    artifacts: VisibleCollectionResponse<ArtifactSummaryResponse>,
}

#[derive(Serialize)]
struct VisibleCollectionResponse<T> {
    visibility: &'static str,
    items: Vec<T>,
}

#[derive(Serialize)]
struct JobSummaryResponse {
    id: String,
    name: String,
    attempt: Option<u32>,
    runner_label: Option<String>,
    status: &'static str,
    started_at_ms: Option<i64>,
    finished_at_ms: Option<i64>,
    logs_available: bool,
}

#[derive(Serialize)]
struct ArtifactSummaryResponse {
    id: String,
    name: String,
    size_bytes: String,
    digest: String,
    expires_at_seconds: Option<i64>,
    downloadable: bool,
}

#[derive(Serialize)]
struct JobLogResponse {
    protocol_version: u8,
    tenant_id: String,
    repository: RepositoryResponse,
    run: RunSummaryResponse,
    jobs: Vec<JobNavigationItemResponse>,
    previous_navigation_job_id: Option<String>,
    next_navigation_job_id: Option<String>,
    job: JobSummaryResponse,
    log_visibility: &'static str,
    live_available: bool,
}

#[derive(Serialize)]
struct JobNavigationItemResponse {
    id: String,
    name: String,
    status: &'static str,
    logs_available: bool,
}

/// Builds the Cloud-authenticated hosted Core API surface.
pub(crate) fn router(
    verifier: Arc<DelegatedActorVerifier>,
    resolver: Arc<dyn DelegatedActorResolver>,
    web_data: Arc<dyn WebData>,
    live_logs: Arc<LiveLogService>,
    browser_origin: HumanLiveLogBrowserOrigin,
    workflow_dispatch: Option<Arc<dyn WorkflowDispatchApiBackend>>,
) -> Router {
    let mut router = Router::new()
        .route(DELEGATED_ACTOR_VIEWER_PATH, get(tenant_viewer))
        .route(
            DELEGATED_ACTOR_AUTHORIZATION_CHECK_PATH,
            post(tenant_authorization_check)
                .layer(DefaultBodyLimit::max(MAX_AUTHORIZATION_CHECK_BODY_BYTES)),
        )
        .route(DELEGATED_ACTOR_REPOSITORIES_PATH, get(tenant_repositories))
        .route(DELEGATED_ACTOR_RUNS_PATH, get(tenant_runs))
        .route(DELEGATED_ACTOR_RUN_PATH, get(tenant_run))
        .route(DELEGATED_ACTOR_JOB_LOG_PATH, get(tenant_job_log))
        .route(
            DELEGATED_ACTOR_LIVE_LOG_TICKET_PATH,
            post(tenant_live_log_ticket),
        );
    if workflow_dispatch.is_some() {
        router = router.route(
            DELEGATED_ACTOR_WORKFLOW_DISPATCH_PATH,
            post(tenant_workflow_dispatch),
        );
    }
    router.with_state(DelegatedActorApiState {
        verifier,
        resolver,
        web_data,
        live_logs,
        browser_origin,
        workflow_dispatch,
    })
}

async fn tenant_authorization_check(
    State(state): State<DelegatedActorApiState>,
    Path(tenant_id): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<TenantAuthorizationCheckRequest>, JsonRejection>,
) -> Response {
    let Ok(tenant_uuid) = canonical_uuid(&tenant_id) else {
        return status_response(StatusCode::NOT_FOUND);
    };
    let Ok(Json(request)) = payload else {
        return status_response(StatusCode::BAD_REQUEST);
    };
    let Some(permissions) = authorization_check_permissions(request) else {
        return status_response(StatusCode::BAD_REQUEST);
    };
    let requested_permissions = permissions.iter().cloned().collect();
    let snapshot = match resolve_actor_with_tenant_permissions(
        &state,
        tenant_uuid,
        &headers,
        requested_permissions,
    )
    .await
    {
        Ok(snapshot) => snapshot,
        Err(response) => return response,
    };
    let authorization = snapshot.authorization();
    let (Some(principal_id), Some(authorization_revision)) = (
        authorization.principal_id(),
        authorization.authorization_revision(),
    ) else {
        return status_response(StatusCode::INTERNAL_SERVER_ERROR);
    };
    json_response(TenantAuthorizationCheckResponse {
        protocol_version: 2,
        tenant_id,
        principal_id: principal_id.as_str().to_owned(),
        authorization_revision,
        decisions: permissions
            .into_iter()
            .map(|permission| TenantPermissionDecisionResponse {
                allowed: snapshot.allows_tenant_permission(&permission),
                permission: permission.into(),
            })
            .collect(),
    })
}

fn authorization_check_permissions(
    request: TenantAuthorizationCheckRequest,
) -> Option<Vec<Permission>> {
    if request.protocol_version != 2
        || request.permissions.is_empty()
        || request.permissions.len() > MAX_DELEGATED_TENANT_PERMISSION_CHECKS
    {
        return None;
    }
    let mut unique = BTreeSet::new();
    let mut permissions = Vec::with_capacity(request.permissions.len());
    for value in request.permissions {
        let permission = Permission::new(value).ok()?;
        if !unique.insert(permission.clone()) {
            return None;
        }
        permissions.push(permission);
    }
    Some(permissions)
}

async fn tenant_workflow_dispatch(
    State(state): State<DelegatedActorApiState>,
    Path((tenant_id, repository_id, workflow_id)): Path<(String, String, String)>,
    request: axum::extract::Request,
) -> Response {
    let Ok(tenant_uuid) = canonical_uuid(&tenant_id) else {
        return status_response(StatusCode::NOT_FOUND);
    };
    let snapshot = match resolve_actor(&state, tenant_uuid, request.headers()).await {
        Ok(snapshot) => snapshot,
        Err(response) => return response,
    };
    let actor = match DelegatedRepositoryMutationActor::from_snapshot(&snapshot) {
        Ok(actor) => actor.into(),
        Err(_) => return status_response(StatusCode::INTERNAL_SERVER_ERROR),
    };
    let Some(backend) = state.workflow_dispatch.as_ref() else {
        return status_response(StatusCode::SERVICE_UNAVAILABLE);
    };
    dispatch_delegated_workflow(
        backend,
        actor,
        tenant_uuid,
        repository_id,
        workflow_id,
        request,
    )
    .await
}

async fn tenant_viewer(
    State(state): State<DelegatedActorApiState>,
    Path(tenant_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Ok(tenant_uuid) = canonical_uuid(&tenant_id) else {
        return status_response(StatusCode::NOT_FOUND);
    };
    let snapshot = match resolve_actor(&state, tenant_uuid, &headers).await {
        Ok(snapshot) => snapshot,
        Err(response) => return response,
    };
    let authorization = snapshot.authorization();
    let Some(principal_id) = authorization.principal_id() else {
        return status_response(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let Some(authorization_revision) = authorization.authorization_revision() else {
        return status_response(StatusCode::INTERNAL_SERVER_ERROR);
    };
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::CONTENT_TYPE, "application/json"),
        ],
        Json(TenantViewerResponse {
            protocol_version: 2,
            tenant_id,
            principal_id: principal_id.as_str().to_owned(),
            display_name: snapshot.viewer().display_name().to_owned(),
            authorization_revision,
        }),
    )
        .into_response()
}

async fn tenant_repositories(
    State(state): State<DelegatedActorApiState>,
    Path(tenant_id): Path<String>,
    Query(query): Query<RepositoryDirectoryQuery>,
    headers: HeaderMap,
) -> Response {
    if !valid_cursor(query.cursor.as_deref()) {
        return status_response(StatusCode::BAD_REQUEST);
    }
    let context = match resolve_context(&state, &tenant_id, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let request = RepositoryDirectoryRequest {
        cursor: query.cursor,
        limit: REPOSITORY_PAGE_SIZE,
    };
    match state.web_data.repository_page(&context, &request).await {
        Ok(page) => json_response(repository_directory_response(tenant_id, page)),
        Err(error) => web_data_error_response(error),
    }
}

async fn tenant_runs(
    State(state): State<DelegatedActorApiState>,
    Path((tenant_id, owner, repository)): Path<(String, String, String)>,
    Query(query): Query<RunListQuery>,
    headers: HeaderMap,
) -> Response {
    let Some(repository) = repository_path(owner, repository) else {
        return status_response(StatusCode::NOT_FOUND);
    };
    if !valid_cursor(query.workflow_cursor.as_deref())
        || !valid_cursor(query.cursor.as_deref())
        || !valid_branch(query.branch.as_deref())
    {
        return status_response(StatusCode::BAD_REQUEST);
    }
    let workflow_id = match query.workflow_id.as_deref() {
        Some(value) => match parse_workflow_id(value) {
            Some(value) => Some(value),
            None => return status_response(StatusCode::BAD_REQUEST),
        },
        None => None,
    };
    let status = match query.status.as_deref().unwrap_or("all") {
        "all" => StatusFilter::All,
        "queued" => StatusFilter::Queued,
        "in_progress" => StatusFilter::InProgress,
        "completed" => StatusFilter::Completed,
        _ => return status_response(StatusCode::BAD_REQUEST),
    };
    let context = match resolve_context(&state, &tenant_id, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let request = RunListRequest {
        workflow_id,
        workflow_cursor: query.workflow_cursor,
        status,
        git_ref: query.branch,
        cursor: query.cursor,
        limit: RUN_PAGE_SIZE,
    };
    match state
        .web_data
        .list_runs(&context, &repository, &request)
        .await
    {
        Ok(Some(page)) => json_response(run_list_response(tenant_id, page)),
        Ok(None) => status_response(StatusCode::NOT_FOUND),
        Err(error) => web_data_error_response(error),
    }
}

async fn tenant_run(
    State(state): State<DelegatedActorApiState>,
    Path((tenant_id, owner, repository, run_id)): Path<(String, String, String, String)>,
    Query(query): Query<RunDetailQuery>,
    headers: HeaderMap,
) -> Response {
    let Some(repository) = repository_path(owner, repository) else {
        return status_response(StatusCode::NOT_FOUND);
    };
    let Some(run_id) = parse_run_id(&run_id) else {
        return status_response(StatusCode::NOT_FOUND);
    };
    if !valid_cursor(query.job_cursor.as_deref()) {
        return status_response(StatusCode::BAD_REQUEST);
    }
    let context = match resolve_context(&state, &tenant_id, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let request = RunDetailRequest {
        job_cursor: query.job_cursor,
        limit: RUN_JOB_PAGE_SIZE,
    };
    match state
        .web_data
        .run_detail(&context, &repository, run_id, &request)
        .await
    {
        Ok(Some(page)) => json_response(run_detail_response(tenant_id, page)),
        Ok(None) => status_response(StatusCode::NOT_FOUND),
        Err(error) => web_data_error_response(error),
    }
}

async fn tenant_job_log(
    State(state): State<DelegatedActorApiState>,
    Path((tenant_id, owner, repository, run_id, job_id)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
) -> Response {
    if raw_query.is_some() {
        return status_response(StatusCode::BAD_REQUEST);
    }
    let Some(repository) = repository_path(owner, repository) else {
        return status_response(StatusCode::NOT_FOUND);
    };
    let (Some(run_id), Some(job_id)) = (parse_run_id(&run_id), parse_job_id(&job_id)) else {
        return status_response(StatusCode::NOT_FOUND);
    };
    let context = match resolve_context(&state, &tenant_id, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    match state
        .web_data
        .job_log(&context, &repository, run_id, job_id)
        .await
    {
        Ok(Some(page)) => json_response(job_log_response(tenant_id, page)),
        Ok(None) => status_response(StatusCode::NOT_FOUND),
        Err(error) => web_data_error_response(error),
    }
}

async fn tenant_live_log_ticket(
    State(state): State<DelegatedActorApiState>,
    Path((tenant_id, owner, repository, run_id, job_id)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    headers: HeaderMap,
) -> Response {
    let Ok(tenant_uuid) = canonical_uuid(&tenant_id) else {
        return status_response(StatusCode::NOT_FOUND);
    };
    let snapshot = match resolve_actor(&state, tenant_uuid, &headers).await {
        Ok(snapshot) => snapshot,
        Err(response) => return response,
    };
    let Some(repository) = repository_path(owner, repository) else {
        return status_response(StatusCode::NOT_FOUND);
    };
    let (Some(run_id), Some(job_id)) = (parse_run_id(&run_id), parse_job_id(&job_id)) else {
        return status_response(StatusCode::NOT_FOUND);
    };
    let Ok(tenant_id) = TenantId::new(tenant_id) else {
        return status_response(StatusCode::NOT_FOUND);
    };
    let Ok(context) = RequestContext::new(
        tenant_id,
        snapshot.authorization().clone(),
        Some(Viewer {
            display_name: snapshot.viewer().display_name().to_owned(),
        }),
        None,
    ) else {
        return status_response(StatusCode::INTERNAL_SERVER_ERROR);
    };
    match state
        .live_logs
        .issue(
            &context,
            &repository,
            run_id,
            job_id,
            state.browser_origin.clone(),
        )
        .await
    {
        Ok(Some(issued)) => issued_response(&issued),
        Ok(None) => status_response(StatusCode::NOT_FOUND),
        Err(error) => service_error_response(error),
    }
}

async fn resolve_context(
    state: &DelegatedActorApiState,
    tenant_id: &str,
    headers: &HeaderMap,
) -> Result<RequestContext, Response> {
    let tenant_uuid =
        canonical_uuid(tenant_id).map_err(|_| status_response(StatusCode::NOT_FOUND))?;
    let snapshot = resolve_actor(state, tenant_uuid, headers).await?;
    let tenant_id =
        TenantId::new(tenant_id.to_owned()).map_err(|_| status_response(StatusCode::NOT_FOUND))?;
    RequestContext::new(
        tenant_id,
        snapshot.authorization().clone(),
        Some(Viewer {
            display_name: snapshot.viewer().display_name().to_owned(),
        }),
        None,
    )
    .map_err(|_| status_response(StatusCode::INTERNAL_SERVER_ERROR))
}

fn repository_directory_response(
    tenant_id: String,
    page: RepositoryDirectoryPage,
) -> RepositoryDirectoryResponse {
    RepositoryDirectoryResponse {
        protocol_version: 2,
        tenant_id,
        repositories: page
            .repositories
            .into_iter()
            .map(repository_directory_item_response)
            .collect(),
        next_cursor: page.next_cursor,
    }
}

fn repository_directory_item_response(
    item: RepositoryDirectoryItem,
) -> RepositoryDirectoryItemResponse {
    RepositoryDirectoryItemResponse {
        repository: repository_response(item.repository),
        actions_visible: item.actions_visible,
        settings_destination: item
            .settings_destination
            .map(|destination| match destination {
                RepositorySettingsDestination::Access => "access",
                RepositorySettingsDestination::Secrets => "secrets",
            }),
    }
}

fn repository_response(repository: Repository) -> RepositoryResponse {
    RepositoryResponse {
        id: repository.id,
        scm_provider: repository.scm_provider,
        owner: repository.owner,
        name: repository.name,
        settings_visible: repository.settings_visible,
    }
}

fn run_list_response(tenant_id: String, page: RunListPage) -> RunListResponse {
    RunListResponse {
        protocol_version: 2,
        tenant_id,
        repository: repository_response(page.repository),
        workflows: page
            .workflows
            .into_iter()
            .map(workflow_definition_response)
            .collect(),
        selected_workflow: page.selected_workflow.map(workflow_definition_response),
        workflow_previous_cursor: page.workflow_previous_cursor,
        workflow_next_cursor: page.workflow_next_cursor,
        runs: page.runs.into_iter().map(run_summary_response).collect(),
        previous_cursor: page.previous_cursor,
        next_cursor: page.next_cursor,
    }
}

fn workflow_definition_response(workflow: WorkflowDefinition) -> WorkflowDefinitionResponse {
    WorkflowDefinitionResponse {
        id: workflow.id.to_string(),
        name: workflow.name,
        enabled: workflow.enabled,
    }
}

fn workflow_response(workflow: Workflow) -> WorkflowResponse {
    WorkflowResponse {
        id: workflow.id.to_string(),
        name: workflow.name,
        path: workflow.path,
    }
}

fn run_summary_response(run: RunSummary) -> RunSummaryResponse {
    RunSummaryResponse {
        id: run.id.to_string(),
        number: run.number.to_string(),
        attempt: run.attempt,
        title: run.title,
        workflow: workflow_response(run.workflow),
        status: status_name(run.status),
        git_ref: run.git_ref,
        event: run.event,
        actor: run.actor,
        head_sha: run.head_sha,
        commit_subject: run.commit_subject,
        created_at_ms: run.created_at.get(),
        finished_at_ms: run.finished_at.map(automata_ci_core::UnixMillis::get),
    }
}

fn run_detail_response(tenant_id: String, page: RunDetailPage) -> RunDetailResponse {
    RunDetailResponse {
        protocol_version: 2,
        tenant_id,
        repository: repository_response(page.repository),
        run: run_summary_response(page.run),
        jobs: VisibleCollectionResponse {
            visibility: collection_visibility(page.jobs.visibility),
            items: page
                .jobs
                .items
                .into_iter()
                .map(job_summary_response)
                .collect(),
        },
        job_previous_cursor: page.job_previous_cursor,
        job_next_cursor: page.job_next_cursor,
        artifacts: VisibleCollectionResponse {
            visibility: collection_visibility(page.artifacts.visibility),
            items: page
                .artifacts
                .items
                .into_iter()
                .map(artifact_summary_response)
                .collect(),
        },
    }
}

fn job_summary_response(job: JobSummary) -> JobSummaryResponse {
    JobSummaryResponse {
        id: job.id.to_string(),
        name: job.name,
        attempt: job.attempt,
        runner_label: job.runner_label,
        status: status_name(job.status),
        started_at_ms: job.started_at.map(automata_ci_core::UnixMillis::get),
        finished_at_ms: job.finished_at.map(automata_ci_core::UnixMillis::get),
        logs_available: job.logs_available,
    }
}

fn artifact_summary_response(artifact: ArtifactSummary) -> ArtifactSummaryResponse {
    ArtifactSummaryResponse {
        id: artifact.id.to_string(),
        name: artifact.name,
        size_bytes: artifact.size.to_string(),
        digest: artifact.digest,
        expires_at_seconds: artifact.expires_at_seconds,
        downloadable: artifact.downloadable,
    }
}

fn job_log_response(tenant_id: String, page: JobLogPage) -> JobLogResponse {
    JobLogResponse {
        protocol_version: 2,
        tenant_id,
        repository: repository_response(page.repository),
        run: run_summary_response(page.run),
        jobs: page
            .jobs
            .into_iter()
            .map(|job| JobNavigationItemResponse {
                id: job.id.to_string(),
                name: job.name,
                status: status_name(job.status),
                logs_available: job.logs_available,
            })
            .collect(),
        previous_navigation_job_id: page.previous_navigation_job_id.map(|id| id.to_string()),
        next_navigation_job_id: page.next_navigation_job_id.map(|id| id.to_string()),
        job: job_summary_response(page.job),
        log_visibility: collection_visibility(page.log_visibility),
        live_available: page.live_available,
    }
}

const fn status_name(status: Status) -> &'static str {
    match status {
        Status::Queued => "queued",
        Status::InProgress => "in_progress",
        Status::Succeeded => "succeeded",
        Status::Failed => "failed",
        Status::Cancelled => "cancelled",
        Status::TimedOut => "timed_out",
        Status::Skipped => "skipped",
        Status::Lost => "lost",
    }
}

const fn collection_visibility(visibility: CollectionVisibility) -> &'static str {
    match visibility {
        CollectionVisibility::Full => "full",
        CollectionVisibility::Restricted => "restricted",
    }
}

fn parse_workflow_id(value: &str) -> Option<WorkflowId> {
    let id = WorkflowId::from_str(value).ok()?;
    (id.to_string() == value).then_some(id)
}

fn valid_cursor(value: Option<&str>) -> bool {
    value.is_none_or(|value| {
        !value.is_empty() && value.len() <= 4_096 && !value.chars().any(char::is_control)
    })
}

fn valid_branch(value: Option<&str>) -> bool {
    value.is_none_or(|value| {
        !value.is_empty() && value.len() <= 1_024 && !value.chars().any(char::is_control)
    })
}

fn json_response(value: impl Serialize) -> Response {
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::CONTENT_TYPE, "application/json"),
        ],
        Json(value),
    )
        .into_response()
}

fn web_data_error_response(error: WebDataError) -> Response {
    status_response(match error {
        WebDataError::InvalidRequest => StatusCode::BAD_REQUEST,
        WebDataError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        WebDataError::Corrupt => StatusCode::INTERNAL_SERVER_ERROR,
    })
}

async fn resolve_actor(
    state: &DelegatedActorApiState,
    tenant_uuid: Uuid,
    headers: &HeaderMap,
) -> Result<Box<DelegatedActorRequestSnapshot>, Response> {
    resolve_actor_with_tenant_permissions(state, tenant_uuid, headers, BTreeSet::new()).await
}

async fn resolve_actor_with_tenant_permissions(
    state: &DelegatedActorApiState,
    tenant_uuid: Uuid,
    headers: &HeaderMap,
    requested_tenant_permissions: BTreeSet<Permission>,
) -> Result<Box<DelegatedActorRequestSnapshot>, Response> {
    let Some(token) = bearer_token(headers) else {
        return Err(unauthorized());
    };
    let now = unix_time();
    let verified = match state.verifier.verify(token, now).await {
        Ok(value) if value.tenant_id == tenant_uuid => value,
        Ok(_) | Err(DelegatedActorVerificationError::Rejected) => return Err(unauthorized()),
        Err(DelegatedActorVerificationError::Unavailable) => {
            return Err(status_response(StatusCode::SERVICE_UNAVAILABLE));
        }
    };
    let Ok(tenant_id) = TenantId::new(tenant_uuid.hyphenated().to_string()) else {
        return Err(status_response(StatusCode::NOT_FOUND));
    };
    let request = ResolveDelegatedActorRequest::new(verified.assertion, tenant_id)
        .with_tenant_permissions(requested_tenant_permissions)
        .map_err(|_| status_response(StatusCode::BAD_REQUEST))?;
    match state.resolver.resolve(&request).await {
        Ok(ResolveDelegatedActorOutcome::Authenticated(snapshot)) => Ok(snapshot),
        Ok(
            ResolveDelegatedActorOutcome::NotFound
            | ResolveDelegatedActorOutcome::PrincipalDisabled
            | ResolveDelegatedActorOutcome::MembershipSuspended,
        ) => Err(status_response(StatusCode::FORBIDDEN)),
        Err(DelegatedActorResolverError::Unavailable) => {
            Err(status_response(StatusCode::SERVICE_UNAVAILABLE))
        }
        Err(DelegatedActorResolverError::CorruptData) => {
            Err(status_response(StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let token = value.strip_prefix("Bearer ")?;
    if token.is_empty() || token.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return None;
    }
    Some(token)
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [
            (header::WWW_AUTHENTICATE, "Bearer"),
            (header::CACHE_CONTROL, "no-store"),
        ],
    )
        .into_response()
}

fn status_response(status: StatusCode) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")]).into_response()
}

fn unix_time() -> UnixTimestamp {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    UnixTimestamp::from_seconds(seconds)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use super::*;
    use automata_ci_auth::{
        authorization::AuthorizationContext, delegated_actor::DelegatedActorResolutionFuture,
        human::PrincipalId, request_auth::ViewerDisplayMetadata,
    };
    use automata_ci_core::{RunId, UnixMillis};
    use automata_ci_store::{
        HumanLiveLogTicketRepository, HumanLogCommitNotificationHub, IssueHumanLiveLogTicket,
        IssueHumanLiveLogTicketOutcome, RedeemHumanLiveLogTicket, RedeemedHumanLiveLogTicket,
        StoreError,
    };
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use ring::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _},
    };
    use tower::ServiceExt as _;

    #[derive(Debug)]
    struct RecordingPermissionResolver {
        observed: StdMutex<Vec<(TenantId, BTreeSet<Permission>)>>,
        granted: BTreeSet<Permission>,
    }

    impl DelegatedActorResolver for RecordingPermissionResolver {
        fn resolve<'a>(
            &'a self,
            request: &'a ResolveDelegatedActorRequest,
        ) -> DelegatedActorResolutionFuture<'a> {
            Box::pin(async move {
                self.observed
                    .lock()
                    .expect("resolver observation lock")
                    .push((
                        request.tenant_id().clone(),
                        request.requested_tenant_permissions().clone(),
                    ));
                let principal_id =
                    PrincipalId::new("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee".to_owned())
                        .map_err(|_| DelegatedActorResolverError::CorruptData)?;
                let authorization = AuthorizationContext::authenticated_at_revision(
                    request.tenant_id().clone(),
                    principal_id,
                    BTreeSet::new(),
                    17,
                )
                .map_err(|_| DelegatedActorResolverError::CorruptData)?;
                let granted = request
                    .requested_tenant_permissions()
                    .intersection(&self.granted)
                    .cloned()
                    .collect();
                let snapshot = DelegatedActorRequestSnapshot::new(
                    request.assertion().clone(),
                    request.tenant_id(),
                    ViewerDisplayMetadata::new("Cloud User")
                        .map_err(|_| DelegatedActorResolverError::CorruptData)?,
                    authorization,
                    granted,
                )
                .map_err(|_| DelegatedActorResolverError::CorruptData)?;
                Ok(ResolveDelegatedActorOutcome::Authenticated(Box::new(
                    snapshot,
                )))
            })
        }
    }

    #[derive(Debug)]
    struct UnusedLiveLogTickets;

    #[async_trait::async_trait]
    impl HumanLiveLogTicketRepository for UnusedLiveLogTickets {
        async fn issue(
            &self,
            _request: &IssueHumanLiveLogTicket,
        ) -> Result<IssueHumanLiveLogTicketOutcome, StoreError> {
            Ok(IssueHumanLiveLogTicketOutcome::DigestCollision)
        }

        async fn redeem(
            &self,
            _request: &RedeemHumanLiveLogTicket,
        ) -> Result<Option<RedeemedHumanLiveLogTicket>, StoreError> {
            Ok(None)
        }
    }

    #[test]
    fn jwks_parser_accepts_only_unique_exact_es256_keys() {
        let coordinate = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let body = serde_json::json!({
            "keys": [{
                "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig",
                "kid": "key_1", "x": coordinate, "y": coordinate
            }]
        });
        let parsed = parse_jwks(&serde_json::to_vec(&body).expect("JWKS JSON"));
        assert!(parsed.is_ok());

        let duplicate = serde_json::json!({"keys": [body["keys"][0], body["keys"][0]]});
        assert!(parse_jwks(&serde_json::to_vec(&duplicate).expect("JWKS JSON")).is_err());
    }

    #[test]
    fn bearer_parser_rejects_ambiguous_or_whitespace_bearing_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer a.b.c".parse().expect("header"),
        );
        assert_eq!(bearer_token(&headers), Some("a.b.c"));
        headers.append(
            header::AUTHORIZATION,
            "Bearer d.e.f".parse().expect("header"),
        );
        assert_eq!(bearer_token(&headers), None);
        headers.clear();
        headers.insert(header::AUTHORIZATION, "Bearer a b".parse().expect("header"));
        assert_eq!(bearer_token(&headers), None);
    }

    #[test]
    fn uuid_parser_requires_canonical_non_nil_text() {
        let canonical = "2c097e58-e4d0-4de2-b79b-bcf059b9b00a";
        assert!(canonical_uuid(canonical).is_ok());
        assert!(canonical_uuid(&canonical.to_uppercase()).is_err());
        assert!(canonical_uuid("00000000-0000-0000-0000-000000000000").is_err());
    }

    #[test]
    fn delegated_read_projection_keeps_large_values_lossless() {
        let workflow_id = WorkflowId::new();
        let run_id = RunId::new();
        let run = RunSummary {
            id: run_id,
            number: u64::MAX,
            attempt: 2,
            title: Some("Release".to_owned()),
            workflow: Workflow {
                id: workflow_id,
                name: "CI".to_owned(),
                path: ".github/workflows/ci.yml".to_owned(),
            },
            status: Status::InProgress,
            git_ref: Some("refs/heads/main".to_owned()),
            event: "push".to_owned(),
            actor: Some("octocat".to_owned()),
            head_sha: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            commit_subject: Some("Ship it".to_owned()),
            created_at: UnixMillis::new(1_765_000_000_000),
            finished_at: None,
        };
        let response = serde_json::to_value(run_summary_response(run)).expect("run JSON");
        assert_eq!(response["id"], run_id.to_string());
        assert_eq!(response["number"], u64::MAX.to_string());
        assert_eq!(response["status"], "in_progress");
        assert_eq!(response["workflow"]["id"], workflow_id.to_string());

        let artifact = ArtifactSummary {
            id: i64::MAX,
            name: "release".to_owned(),
            size: u64::MAX,
            digest: "sha256:fixture".to_owned(),
            expires_at_seconds: None,
            downloadable: true,
        };
        let response =
            serde_json::to_value(artifact_summary_response(artifact)).expect("artifact JSON");
        assert_eq!(response["id"], i64::MAX.to_string());
        assert_eq!(response["size_bytes"], u64::MAX.to_string());
    }

    #[test]
    fn delegated_read_query_values_are_canonical_and_bounded() {
        let workflow_id = WorkflowId::new().to_string();
        assert_eq!(
            parse_workflow_id(&workflow_id).map(|id| id.to_string()),
            Some(workflow_id.clone())
        );
        assert!(parse_workflow_id(&workflow_id.to_uppercase()).is_none());
        assert!(valid_cursor(None));
        assert!(valid_cursor(Some("opaque-page-position")));
        assert!(!valid_cursor(Some("")));
        assert!(!valid_cursor(Some("line\nbreak")));
        assert!(!valid_cursor(Some(&"x".repeat(4_097))));
        assert!(valid_branch(Some("refs/heads/main")));
        assert!(!valid_branch(Some("")));
    }

    #[test]
    fn authorization_check_accepts_one_exact_bounded_permission_set() {
        let parsed = authorization_check_permissions(TenantAuthorizationCheckRequest {
            protocol_version: 2,
            permissions: vec!["billing:read".to_owned(), "billing:manage".to_owned()],
        })
        .expect("authorization permissions");
        assert_eq!(
            parsed.iter().map(Permission::as_str).collect::<Vec<_>>(),
            ["billing:read", "billing:manage"]
        );

        for rejected in [
            TenantAuthorizationCheckRequest {
                protocol_version: 1,
                permissions: vec!["billing:read".to_owned()],
            },
            TenantAuthorizationCheckRequest {
                protocol_version: 2,
                permissions: Vec::new(),
            },
            TenantAuthorizationCheckRequest {
                protocol_version: 2,
                permissions: vec!["billing:read".to_owned(), "billing:read".to_owned()],
            },
            TenantAuthorizationCheckRequest {
                protocol_version: 2,
                permissions: vec!["billing/read".to_owned()],
            },
            TenantAuthorizationCheckRequest {
                protocol_version: 2,
                permissions: (0..=MAX_DELEGATED_TENANT_PERMISSION_CHECKS)
                    .map(|index| format!("billing:test-{index}"))
                    .collect(),
            },
        ] {
            assert!(authorization_check_permissions(rejected).is_none());
        }
    }

    #[tokio::test]
    async fn authorization_check_route_resolves_and_returns_exact_permission_decisions() {
        let random = SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &random)
            .expect("test key document");
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, document.as_ref(), &random)
                .expect("test signing key");
        let mut public_key = [0_u8; 65];
        public_key.copy_from_slice(key.public_key().as_ref());
        let verifier = Arc::new(
            DelegatedActorVerifier::new(DelegatedActorVerifierConfig {
                issuer: "https://cloud.automata.example".to_owned(),
                audience: "prod-us-east-1".to_owned(),
                jwks_url: Url::parse("https://cloud.automata.example/.well-known/jwks.json")
                    .expect("JWKS URL"),
            })
            .expect("verifier"),
        );
        *verifier.cache.lock().await = Some(CachedJwks {
            fetched_at: Instant::now(),
            keys: BTreeMap::from([("key_1".to_owned(), public_key)]),
        });

        let billing_read = Permission::new("billing:read").expect("read permission");
        let billing_manage = Permission::new("billing:manage").expect("manage permission");
        let resolver = Arc::new(RecordingPermissionResolver {
            observed: StdMutex::new(Vec::new()),
            granted: BTreeSet::from([billing_read.clone()]),
        });
        let web_data: Arc<dyn WebData> = Arc::new(crate::app::web::EmptyWebData);
        let live_logs = Arc::new(LiveLogService::new(
            Arc::clone(&web_data),
            Arc::new(UnusedLiveLogTickets),
            Arc::new(HumanLogCommitNotificationHub::default()),
        ));
        let application = router(
            verifier,
            resolver.clone(),
            web_data,
            live_logs,
            HumanLiveLogBrowserOrigin::new("https://cloud.automata.example")
                .expect("browser origin"),
            None,
        );

        let tenant_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        let token = sign_current_test_token(&key, &random, tenant_id);
        let request = Request::builder()
            .method("POST")
            .uri(format!(
                "/internal/v2/tenants/{tenant_id}/authorization-checks"
            ))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "protocol_version": 2,
                    "permissions": [billing_manage.as_str(), billing_read.as_str()]
                }))
                .expect("request JSON"),
            ))
            .expect("request");

        let response = application.oneshot(request).await.expect("route response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        let body = to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("response body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("response JSON");
        assert_eq!(
            body,
            serde_json::json!({
                "protocol_version": 2,
                "tenant_id": tenant_id,
                "principal_id": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
                "authorization_revision": 17,
                "decisions": [
                    {"permission": "billing:manage", "allowed": false},
                    {"permission": "billing:read", "allowed": true}
                ]
            })
        );
        assert_eq!(
            *resolver.observed.lock().expect("resolver observation lock"),
            vec![(
                TenantId::new(tenant_id).expect("tenant ID"),
                BTreeSet::from([billing_manage, billing_read])
            )]
        );
    }

    #[tokio::test]
    async fn verifier_accepts_only_the_configured_signed_claim_shape() {
        let random = SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &random)
            .expect("test key document");
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, document.as_ref(), &random)
                .expect("test signing key");
        let mut public_key = [0_u8; 65];
        public_key.copy_from_slice(key.public_key().as_ref());
        let verifier = DelegatedActorVerifier::new(DelegatedActorVerifierConfig {
            issuer: "https://cloud.automata.example".to_owned(),
            audience: "prod-us-east-1".to_owned(),
            jwks_url: Url::parse("https://cloud.automata.example/.well-known/jwks.json")
                .expect("JWKS URL"),
        })
        .expect("verifier");
        *verifier.cache.lock().await = Some(CachedJwks {
            fetched_at: Instant::now(),
            keys: BTreeMap::from([("key_1".to_owned(), public_key)]),
        });
        let header = serde_json::json!({"alg": "ES256", "kid": "key_1", "typ": "at+jwt"});
        let claims = serde_json::json!({
            "ver": 1,
            "iss": "https://cloud.automata.example",
            "sub": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "aud": "prod-us-east-1",
            "tenant_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "session_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            "auth_time": 900,
            "iat": 1_000,
            "exp": 1_120,
            "jti": "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
        });
        let token = sign_test_token(&key, &random, &header, &claims);
        let verified_actor = verifier
            .verify(&token, UnixTimestamp::from_seconds(1_010))
            .await
            .expect("valid assertion");
        assert_eq!(
            verified_actor.tenant_id,
            Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").expect("tenant")
        );

        let mut wrong_audience = claims.clone();
        wrong_audience["aud"] = serde_json::json!("another-shard");
        let token = sign_test_token(&key, &random, &header, &wrong_audience);
        assert!(matches!(
            verifier
                .verify(&token, UnixTimestamp::from_seconds(1_010))
                .await,
            Err(DelegatedActorVerificationError::Rejected)
        ));
        let mut authorization_claim = claims;
        authorization_claim["roles"] = serde_json::json!(["owner"]);
        let token = sign_test_token(&key, &random, &header, &authorization_claim);
        assert!(matches!(
            verifier
                .verify(&token, UnixTimestamp::from_seconds(1_010))
                .await,
            Err(DelegatedActorVerificationError::Rejected)
        ));
    }

    fn sign_test_token(
        key: &EcdsaKeyPair,
        random: &SystemRandom,
        header: &serde_json::Value,
        claims: &serde_json::Value,
    ) -> String {
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).expect("header JSON"));
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims JSON"));
        let signing_input = format!("{header}.{claims}");
        let signature = key
            .sign(random, signing_input.as_bytes())
            .expect("test signature");
        format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        )
    }

    fn sign_current_test_token(
        key: &EcdsaKeyPair,
        random: &SystemRandom,
        tenant_id: &str,
    ) -> String {
        let now = unix_time().as_seconds();
        let header = serde_json::json!({"alg": "ES256", "kid": "key_1", "typ": "at+jwt"});
        let claims = serde_json::json!({
            "ver": 1,
            "iss": "https://cloud.automata.example",
            "sub": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "aud": "prod-us-east-1",
            "tenant_id": tenant_id,
            "session_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            "auth_time": now.saturating_sub(10),
            "iat": now,
            "exp": now.saturating_add(120),
            "jti": "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
        });
        sign_test_token(key, random, &header, &claims)
    }
}
