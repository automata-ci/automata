use std::{fmt, sync::Arc};

use axum::{
    Json, Router,
    body::{Body, HttpBody as _},
    extract::{RawQuery, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use thiserror::Error;

use crate::{OidcAudience, OidcService, OidcServiceErrorKind};

/// GitHub Actions-compatible ID-token request path.
pub const OIDC_TOKEN_PATH: &str = "/oidc/token";
/// Exact path and query injected into `ACTIONS_ID_TOKEN_REQUEST_URL`.
///
/// `@actions/core` appends an optional `&audience=...` parameter to this URL.
pub const OIDC_TOKEN_REQUEST_PATH_AND_QUERY: &str = "/oidc/token?api-version=2.0";
/// `OpenID` Provider metadata path.
pub const OIDC_DISCOVERY_PATH: &str = "/.well-known/openid-configuration";
/// JSON Web Key Set path advertised by provider metadata.
pub const OIDC_JWKS_PATH: &str = "/.well-known/jwks";
/// Public cache horizon advertised on discovery and JWKS responses.
pub const OIDC_JWKS_CACHE_SECONDS: u64 = 300;

const MAXIMUM_RAW_QUERY_BYTES: usize = 8 * 1_024;
const MAXIMUM_AUTHORIZATION_HEADER_BYTES: usize = 8 * 1_024;
const API_VERSION: &str = "2.0";

/// Sanitized failure to obtain a trusted wall-clock second.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("OIDC server clock is unavailable")]
pub struct OidcClockError;

/// Trusted wall-clock boundary for HTTP token issuance.
pub trait OidcClock: fmt::Debug + Send + Sync {
    /// Returns current whole seconds since the Unix epoch.
    ///
    /// # Errors
    ///
    /// Fails when the time source is unavailable or predates the epoch.
    fn now_seconds(&self) -> Result<u64, OidcClockError>;
}

#[derive(Clone)]
struct OidcHttpState {
    service: Arc<OidcService>,
    clock: Arc<dyn OidcClock>,
}

impl fmt::Debug for OidcHttpState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcHttpState")
            .field("service", &"[configured]")
            .field("clock", &"[injected]")
            .finish()
    }
}

/// Strict Axum adapter for discovery, JWKS, and toolkit-compatible minting.
#[derive(Clone, Debug)]
pub struct WorkloadOidcApi {
    state: OidcHttpState,
}

impl WorkloadOidcApi {
    /// Composes an HTTP adapter from the isolated service and trusted clock.
    #[must_use]
    pub fn new(service: Arc<OidcService>, clock: Arc<dyn OidcClock>) -> Self {
        Self {
            state: OidcHttpState { service, clock },
        }
    }

    /// Returns routes suitable for merging into a TLS product listener.
    ///
    /// The router itself does not terminate TLS. Production composition must
    /// expose the exact HTTPS issuer origin configured on [`OidcService`].
    pub fn router(self) -> Router {
        Router::new()
            .route(OIDC_DISCOVERY_PATH, get(discovery))
            .route(OIDC_JWKS_PATH, get(jwks))
            .route(OIDC_TOKEN_PATH, get(mint))
            .with_state(self.state)
    }
}

#[derive(Debug, Serialize)]
struct DiscoveryDocument<'a> {
    issuer: &'a str,
    jwks_uri: String,
    subject_types_supported: [&'static str; 1],
    response_types_supported: [&'static str; 1],
    claims_supported: &'a [String],
    id_token_signing_alg_values_supported: [&'static str; 1],
    scopes_supported: [&'static str; 1],
}

async fn discovery(State(state): State<OidcHttpState>) -> Response {
    let mut jwks_uri = state.service.issuer().url().clone();
    jwks_uri.set_path(OIDC_JWKS_PATH);
    metadata_response(Json(DiscoveryDocument {
        issuer: state.service.issuer().as_str(),
        jwks_uri: jwks_uri.to_string(),
        subject_types_supported: ["public"],
        response_types_supported: ["id_token"],
        claims_supported: state.service.supported_claims().as_slice(),
        id_token_signing_alg_values_supported: ["RS256"],
        scopes_supported: ["openid"],
    }))
}

async fn jwks(State(state): State<OidcHttpState>) -> Response {
    metadata_response(Json(state.service.jwks()))
}

async fn mint(
    State(state): State<OidcHttpState>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if !request_headers_allow_empty_body(&headers) || !body_has_exactly_zero_bytes(&body) {
        return request_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let Ok(query) = parse_mint_query(raw_query.as_deref()) else {
        return request_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let Ok(bearer) = parse_bearer(&headers) else {
        return unauthorized_error();
    };
    let Ok(now_seconds) = state.clock.now_seconds() else {
        return request_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    match state
        .service
        .mint(bearer, query.requested_audience, now_seconds)
        .await
    {
        Ok(token) => {
            let response = Json(TokenResponse {
                value: token.expose_secret(),
            })
            .into_response();
            private_response(response)
        }
        Err(error) => match error.kind() {
            OidcServiceErrorKind::Unauthorized => unauthorized_error(),
            OidcServiceErrorKind::ResourceExhausted | OidcServiceErrorKind::Unavailable => {
                request_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
            }
            OidcServiceErrorKind::Internal => {
                request_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
            }
        },
    }
}

#[derive(Debug)]
struct MintQuery {
    requested_audience: Option<OidcAudience>,
}

fn parse_mint_query(raw_query: Option<&str>) -> Result<MintQuery, ()> {
    let raw_query = raw_query.ok_or(())?;
    if raw_query.is_empty() || raw_query.len() > MAXIMUM_RAW_QUERY_BYTES {
        return Err(());
    }
    let mut version = None;
    let mut audience = None;
    for pair in raw_query.split('&') {
        let (raw_name, raw_value) = pair.split_once('=').ok_or(())?;
        if raw_name.is_empty() {
            return Err(());
        }
        let name = decode_form_component(raw_name)?;
        let value = decode_form_component(raw_value)?;
        match name.as_str() {
            "api-version" if version.is_none() => version = Some(value),
            "audience" if audience.is_none() => {
                audience = Some(OidcAudience::new(value).map_err(|_| ())?);
            }
            _ => return Err(()),
        }
    }
    if version.as_deref() != Some(API_VERSION) {
        return Err(());
    }
    Ok(MintQuery {
        requested_audience: audience,
    })
}

fn decode_form_component(encoded: &str) -> Result<String, ()> {
    let input = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(input.len());
    let mut offset = 0;
    while offset < input.len() {
        match input[offset] {
            b'+' => {
                decoded.push(b' ');
                offset += 1;
            }
            b'%' => {
                let high = *input.get(offset + 1).ok_or(())?;
                let low = *input.get(offset + 2).ok_or(())?;
                decoded.push((hex_value(high)? << 4) | hex_value(low)?);
                offset += 3;
            }
            byte if byte.is_ascii() => {
                decoded.push(byte);
                offset += 1;
            }
            _ => return Err(()),
        }
    }
    String::from_utf8(decoded).map_err(|_| ())
}

const fn hex_value(byte: u8) -> Result<u8, ()> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(()),
    }
}

fn parse_bearer(headers: &HeaderMap) -> Result<&str, ()> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next().ok_or(())?;
    if values.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?;
    if value.len() > MAXIMUM_AUTHORIZATION_HEADER_BYTES {
        return Err(());
    }
    let (scheme, token) = value.split_once(' ').ok_or(())?;
    if !scheme.eq_ignore_ascii_case("Bearer")
        || token.is_empty()
        || token.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(());
    }
    Ok(token)
}

fn request_headers_allow_empty_body(headers: &HeaderMap) -> bool {
    if headers.contains_key(header::TRANSFER_ENCODING) {
        return false;
    }
    let mut lengths = headers.get_all(header::CONTENT_LENGTH).iter();
    let Some(length) = lengths.next() else {
        return true;
    };
    lengths.next().is_none() && length.as_bytes() == b"0"
}

fn body_has_exactly_zero_bytes(body: &Body) -> bool {
    let size = body.size_hint();
    size.lower() == 0 && size.upper() == Some(0)
}

#[derive(Serialize)]
struct TokenResponse<'a> {
    value: &'a str,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: &'static str,
}

fn unauthorized_error() -> Response {
    let mut response = request_error(StatusCode::UNAUTHORIZED, "unauthorized");
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"oidc\""),
    );
    response
}

fn request_error(status: StatusCode, error: &'static str) -> Response {
    let mut response = (status, Json(ErrorResponse { error })).into_response();
    apply_private_headers(response.headers_mut());
    response
}

fn private_response(mut response: Response) -> Response {
    apply_private_headers(response.headers_mut());
    response
}

fn apply_private_headers(headers: &mut HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
}

fn metadata_response(response: impl IntoResponse) -> Response {
    let mut response = response.into_response();
    let cache_control =
        HeaderValue::from_str(&format!("public, max-age={OIDC_JWKS_CACHE_SECONDS}"))
            .unwrap_or_else(|_| HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, cache_control);
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}
