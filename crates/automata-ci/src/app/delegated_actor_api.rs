//! Hosted Core HTTP ingress for short-lived Cloud actor assertions.

use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};

use automata_ci_auth::{
    delegated_actor::{
        DelegatedActorAssertion, DelegatedActorRequestSnapshot, DelegatedActorResolver,
        DelegatedActorResolverError, ResolveDelegatedActorOutcome, ResolveDelegatedActorRequest,
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
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::{get, post},
};

use super::{
    live_log::{
        LiveLogService, issued_response, parse_job_id, parse_run_id, repository_path,
        service_error_response,
    },
    web::{RequestContext, Viewer},
};
use automata_ci_store::HumanLiveLogBrowserOrigin;

/// Protected Core endpoint used by Cloud to resolve the current viewer.
pub const DELEGATED_ACTOR_VIEWER_PATH: &str = "/internal/v1/workspaces/{workspace_id}/viewer";
/// Protected Core endpoint used by Cloud to authorize one browser log tail.
pub const DELEGATED_ACTOR_LIVE_LOG_TICKET_PATH: &str = "/internal/v1/workspaces/{workspace_id}/repositories/{owner}/{repository}/runs/{run_id}/jobs/{job_id}/live-ticket";

const MAX_ASSERTION_BYTES: usize = 8 * 1024;
const MAX_JWT_SEGMENT_BYTES: usize = 6 * 1024;
const MAX_JWKS_BYTES: usize = 64 * 1024;
const MAX_JWKS_KEYS: usize = 32;
const MAX_KEY_ID_BYTES: usize = 128;
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
        let workspace_id = canonical_uuid(&claims.workspace_id)?;
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
            workspace_id,
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
    workspace_id: Uuid,
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
    workspace_id: String,
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
    live_logs: Arc<LiveLogService>,
    browser_origin: HumanLiveLogBrowserOrigin,
}

impl std::fmt::Debug for DelegatedActorApiState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DelegatedActorApiState")
            .field("verifier", &self.verifier)
            .field("resolver", &self.resolver)
            .field("live_logs", &self.live_logs)
            .field("browser_origin", &self.browser_origin)
            .finish()
    }
}

#[derive(Serialize)]
struct WorkspaceViewerResponse {
    protocol_version: u8,
    workspace_id: String,
    principal_id: String,
    display_name: String,
    authorization_revision: u64,
}

/// Builds the Cloud-authenticated hosted Core API surface.
pub(crate) fn router(
    verifier: Arc<DelegatedActorVerifier>,
    resolver: Arc<dyn DelegatedActorResolver>,
    live_logs: Arc<LiveLogService>,
    browser_origin: HumanLiveLogBrowserOrigin,
) -> Router {
    Router::new()
        .route(DELEGATED_ACTOR_VIEWER_PATH, get(workspace_viewer))
        .route(
            DELEGATED_ACTOR_LIVE_LOG_TICKET_PATH,
            post(workspace_live_log_ticket),
        )
        .with_state(DelegatedActorApiState {
            verifier,
            resolver,
            live_logs,
            browser_origin,
        })
}

async fn workspace_viewer(
    State(state): State<DelegatedActorApiState>,
    Path(workspace_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Ok(workspace_uuid) = canonical_uuid(&workspace_id) else {
        return status_response(StatusCode::NOT_FOUND);
    };
    let snapshot = match resolve_actor(&state, workspace_uuid, &headers).await {
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
        Json(WorkspaceViewerResponse {
            protocol_version: 1,
            workspace_id,
            principal_id: principal_id.as_str().to_owned(),
            display_name: snapshot.viewer().display_name().to_owned(),
            authorization_revision,
        }),
    )
        .into_response()
}

async fn workspace_live_log_ticket(
    State(state): State<DelegatedActorApiState>,
    Path((workspace_id, owner, repository, run_id, job_id)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    headers: HeaderMap,
) -> Response {
    let Ok(workspace_uuid) = canonical_uuid(&workspace_id) else {
        return status_response(StatusCode::NOT_FOUND);
    };
    let snapshot = match resolve_actor(&state, workspace_uuid, &headers).await {
        Ok(snapshot) => snapshot,
        Err(response) => return response,
    };
    let Some(repository) = repository_path(owner, repository) else {
        return status_response(StatusCode::NOT_FOUND);
    };
    let (Some(run_id), Some(job_id)) = (parse_run_id(&run_id), parse_job_id(&job_id)) else {
        return status_response(StatusCode::NOT_FOUND);
    };
    let Ok(tenant_id) = TenantId::new(workspace_id) else {
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

async fn resolve_actor(
    state: &DelegatedActorApiState,
    workspace_uuid: Uuid,
    headers: &HeaderMap,
) -> Result<Box<DelegatedActorRequestSnapshot>, Response> {
    let Some(token) = bearer_token(headers) else {
        return Err(unauthorized());
    };
    let now = unix_time();
    let verified = match state.verifier.verify(token, now).await {
        Ok(value) if value.workspace_id == workspace_uuid => value,
        Ok(_) | Err(DelegatedActorVerificationError::Rejected) => return Err(unauthorized()),
        Err(DelegatedActorVerificationError::Unavailable) => {
            return Err(status_response(StatusCode::SERVICE_UNAVAILABLE));
        }
    };
    let Ok(tenant_id) = TenantId::new(workspace_uuid.hyphenated().to_string()) else {
        return Err(status_response(StatusCode::NOT_FOUND));
    };
    let request = ResolveDelegatedActorRequest::new(verified.assertion, tenant_id);
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
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _},
    };

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
            "workspace_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
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
            verified_actor.workspace_id,
            Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").expect("workspace")
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
}
