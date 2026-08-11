//! Per-request browser and CLI session authentication for the human surface.
//!
//! Raw credentials are parsed and reduced to keyed lookups before crossing the
//! durable resolver boundary. Browser mutation checks run before the downstream
//! handler can parse a request body.

use std::{fmt, sync::Arc, time::Duration};

use automata_ci_auth::{
    human::TenantId,
    request_auth::{
        AuthenticatedRequestSnapshot, RequestAuthenticationResolver,
        RequestAuthenticationResolverError, ResolveAuthenticatedRequest,
        ResolveAuthenticatedRequestOutcome,
    },
    secret::CsrfToken,
    session::{SessionKind, TouchSessionOutcome},
    session_credential::{SessionCredentialService, SessionCredentialServiceError},
    time::Clock,
};
use axum::{
    body::{Body, to_bytes},
    extract::State,
    http::{
        HeaderValue, Method, Request, StatusCode,
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, SET_COOKIE, VARY, WWW_AUTHENTICATE},
    },
    middleware::Next,
    response::Response,
};
use thiserror::Error;

use super::{
    github_auth::{
        BrowserLogoutCompleted, BrowserLogoutCredential, CliSessionCredential,
        GITHUB_WEB_BEGIN_PATH, MAX_BROWSER_LOGOUT_FORM_BYTES, browser_logout_csrf_token,
        is_browser_logout_form, is_cli_session_activation, is_cli_session_logout,
    },
    human_auth::{
        HumanAuthOrigin, HumanCookieMode, PresentedHumanCredential, auth_error_response,
        clear_csrf_cookie, clear_login_cookie, clear_session_cookie, csrf_set_cookie,
        extract_human_credential, verify_browser_mutation,
    },
    publication_settings::{
        MAX_PUBLICATION_SETTINGS_FORM_BYTES, PublicationSettingsFormSubmission,
        is_publication_settings_form, parse_publication_settings_form,
        publication_settings_csrf_token,
    },
    rbac_management::{
        MAX_RBAC_MANAGEMENT_FORM_BYTES, RbacManagementFormSubmission, is_rbac_management_form,
        parse_rbac_management_form, rbac_management_csrf_token,
    },
    repository_secrets::{
        RepositorySecretFormError, collect_repository_secret_form, is_repository_secret_form,
    },
    web::{RequestContext, Viewer},
};

#[cfg(test)]
use super::{
    github_auth::GITHUB_WEB_LOGOUT_PATH,
    repository_secrets::{
        MAX_REPOSITORY_SECRET_FORM_BYTES, RepositorySecretFormSubmission,
        VerifiedRepositorySecretForm,
    },
};

/// Dependencies and bounded idle policies for human request authentication.
#[derive(Clone)]
pub(crate) struct HumanRequestAuthentication {
    sessions: Arc<SessionCredentialService>,
    resolver: Arc<dyn RequestAuthenticationResolver>,
    clock: Arc<dyn Clock>,
    origin: HumanAuthOrigin,
    anonymous_tenant: TenantId,
    browser_idle_lifetime: Duration,
    cli_idle_lifetime: Duration,
}

impl HumanRequestAuthentication {
    /// Builds the middleware state after validating exact whole-second idle windows.
    pub(crate) fn new(
        sessions: Arc<SessionCredentialService>,
        resolver: Arc<dyn RequestAuthenticationResolver>,
        clock: Arc<dyn Clock>,
        origin: HumanAuthOrigin,
        anonymous_tenant: TenantId,
        browser_idle_lifetime: Duration,
        cli_idle_lifetime: Duration,
    ) -> Result<Self, HumanRequestAuthenticationConfigError> {
        if !valid_lifetime(browser_idle_lifetime) || !valid_lifetime(cli_idle_lifetime) {
            return Err(HumanRequestAuthenticationConfigError);
        }
        Ok(Self {
            sessions,
            resolver,
            clock,
            origin,
            anonymous_tenant,
            browser_idle_lifetime,
            cli_idle_lifetime,
        })
    }

    const fn cookie_mode(&self) -> HumanCookieMode {
        self.origin.cookie_mode()
    }

    const fn idle_lifetime(&self, kind: SessionKind) -> Duration {
        match kind {
            SessionKind::Browser => self.browser_idle_lifetime,
            SessionKind::Cli => self.cli_idle_lifetime,
        }
    }
}

impl fmt::Debug for HumanRequestAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HumanRequestAuthentication")
            .field("sessions", &self.sessions)
            .field("resolver", &self.resolver)
            .field("clock", &self.clock)
            .field("origin", &self.origin)
            .field("anonymous_tenant", &self.anonymous_tenant)
            .field("browser_idle_lifetime", &self.browser_idle_lifetime)
            .field("cli_idle_lifetime", &self.cli_idle_lifetime)
            .finish()
    }
}

fn valid_lifetime(lifetime: Duration) -> bool {
    !lifetime.is_zero() && lifetime.subsec_nanos() == 0
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("human request authentication configuration is invalid")]
pub(crate) struct HumanRequestAuthenticationConfigError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HumanRequestSurface {
    Bypass,
    Browser,
    Cli,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HumanRequestApiError {
    InvalidRequest,
    Unauthorized,
    Forbidden,
    UnsupportedMediaType,
    PayloadTooLarge,
    Unavailable,
    Internal,
}

impl HumanRequestApiError {
    const fn document(self) -> &'static str {
        match self {
            Self::InvalidRequest => r#"{"error":"invalid_request"}"#,
            Self::Unauthorized => r#"{"error":"unauthorized"}"#,
            Self::Forbidden => r#"{"error":"forbidden"}"#,
            Self::UnsupportedMediaType => r#"{"error":"unsupported_media_type"}"#,
            Self::PayloadTooLarge => r#"{"error":"payload_too_large"}"#,
            Self::Unavailable => r#"{"error":"unavailable"}"#,
            Self::Internal => r#"{"error":"internal_error"}"#,
        }
    }
}

fn request_auth_error_response(
    surface: HumanRequestSurface,
    status: StatusCode,
    browser_body: &'static str,
    api_error: HumanRequestApiError,
    cli_bearer_challenge: bool,
) -> Response {
    if surface != HumanRequestSurface::Cli {
        return auth_error_response(status, browser_body, false);
    }
    let mut response = Response::new(Body::from(api_error.document()));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    if cli_bearer_challenge {
        response.headers_mut().insert(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"automata\""),
        );
    }
    response
}

fn request_surface(path: &str) -> HumanRequestSurface {
    if matches!(
        path,
        "/healthz"
            | "/readyz"
            | "/auth/github/login"
            | "/auth/github/callback"
            | "/setup/auth/github"
    ) || path.starts_with("/assets/")
        || matches!(
            path,
            "/api/v1/auth/device"
                | "/api/v1/auth/device/poll"
                | "/api/v1/setup/device"
                | "/api/v1/setup/device/poll"
        )
    {
        HumanRequestSurface::Bypass
    } else if path == "/api/v1" || path.starts_with("/api/v1/") {
        HumanRequestSurface::Cli
    } else {
        HumanRequestSurface::Browser
    }
}

fn request_surface_for(method: &Method, path: &str) -> HumanRequestSurface {
    if method == Method::GET && path == "/setup" {
        HumanRequestSurface::Bypass
    } else {
        request_surface(path)
    }
}

/// Authenticates one human request and injects its revision-safe identity snapshot.
#[allow(clippy::too_many_lines)]
pub(crate) async fn authenticate_human_request(
    State(state): State<HumanRequestAuthentication>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    if is_cli_session_activation(request.method(), request.uri().path()) {
        // Pending CLI sessions intentionally fail ordinary request resolution.
        // The exact POST activation handler owns strict bearer parsing and is
        // itself covered by the outer combined-router deadline.
        return next.run(request).await;
    }
    let surface = request_surface_for(request.method(), request.uri().path());
    if surface == HumanRequestSurface::Bypass {
        return next.run(request).await;
    }
    if surface == HumanRequestSurface::Cli
        && request.uri().path() == crate::app::github_auth::CLI_SESSION_PATH
        && request.uri().query().is_some()
    {
        return request_auth_error_response(
            surface,
            StatusCode::BAD_REQUEST,
            "Invalid request.\n",
            HumanRequestApiError::InvalidRequest,
            false,
        );
    }

    let Ok(presented) = extract_human_credential(request.headers(), state.cookie_mode()) else {
        return rejected_credential(surface, state.cookie_mode());
    };
    let Some(presented) = presented else {
        if surface == HumanRequestSurface::Cli {
            return request_auth_error_response(
                surface,
                StatusCode::UNAUTHORIZED,
                "Unauthorized.\n",
                HumanRequestApiError::Unauthorized,
                true,
            );
        }
        if !is_safe_method(request.method()) {
            return request_auth_error_response(
                surface,
                StatusCode::UNAUTHORIZED,
                "Unauthorized.\n",
                HumanRequestApiError::Unauthorized,
                false,
            );
        }
        if insert_anonymous_context(&state, &mut request).is_err() {
            return request_auth_error_response(
                surface,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error.\n",
                HumanRequestApiError::Internal,
                false,
            );
        }
        let mut response = next.run(request).await;
        response
            .headers_mut()
            .append(VARY, axum::http::HeaderValue::from_static("Cookie"));
        return response;
    };

    if !surface_accepts(surface, presented.kind()) {
        return rejected_credential(surface, state.cookie_mode());
    }

    let expected_kind = presented.kind();
    if expected_kind == SessionKind::Cli {
        // Parsing produced the one owned credential needed below. Drop the
        // generic header copy before any database await and never expose it to
        // downstream handlers.
        drop(request.headers_mut().remove(AUTHORIZATION));
    }
    let browser_logout = is_browser_logout_form(request.method(), request.uri().path());
    let cli_logout = request.uri().query().is_none()
        && is_cli_session_logout(request.method(), request.uri().path());
    let raw = presented.expose_secret();
    let safe_method = is_safe_method(request.method());
    let mut pending_rbac_form_body = None;
    let browser_csrf = if expected_kind == SessionKind::Browser {
        let csrf = match state.sessions.derive_csrf_raw(raw, expected_kind) {
            Ok(csrf) => csrf,
            Err(error) => return credential_service_error(error, surface, state.cookie_mode()),
        };
        let csrf = Arc::new(csrf);
        if !safe_method {
            match verify_browser_mutation_request(&mut request, &state.origin, &csrf).await {
                Ok(rbac_form_body) => pending_rbac_form_body = rbac_form_body,
                Err(BrowserMutationRequestError::Forbidden) => {
                    return request_auth_error_response(
                        surface,
                        StatusCode::FORBIDDEN,
                        "Forbidden.\n",
                        HumanRequestApiError::Forbidden,
                        false,
                    );
                }
                Err(BrowserMutationRequestError::UnsupportedMediaType) => {
                    return request_auth_error_response(
                        surface,
                        StatusCode::UNSUPPORTED_MEDIA_TYPE,
                        "Unsupported media type.\n",
                        HumanRequestApiError::UnsupportedMediaType,
                        false,
                    );
                }
                Err(BrowserMutationRequestError::PayloadTooLarge) => {
                    return request_auth_error_response(
                        surface,
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "Request too large.\n",
                        HumanRequestApiError::PayloadTooLarge,
                        false,
                    );
                }
            }
        }
        Some(csrf)
    } else {
        None
    };

    let lookup = match state.sessions.derive_lookup_raw(raw, expected_kind) {
        Ok(lookup) => lookup,
        Err(error) => return credential_service_error(error, surface, state.cookie_mode()),
    };
    let now = state.clock.now();
    let resolution = ResolveAuthenticatedRequest::new(lookup, expected_kind, now);
    let snapshot = match state.resolver.resolve(&resolution).await {
        Ok(ResolveAuthenticatedRequestOutcome::Authenticated(snapshot)) => snapshot,
        Ok(
            ResolveAuthenticatedRequestOutcome::NotFound
            | ResolveAuthenticatedRequestOutcome::WrongKindOrAudience
            | ResolveAuthenticatedRequestOutcome::Revoked
            | ResolveAuthenticatedRequestOutcome::Expired
            | ResolveAuthenticatedRequestOutcome::NotYetValid
            | ResolveAuthenticatedRequestOutcome::PrincipalDisabled
            | ResolveAuthenticatedRequestOutcome::MembershipSuspended
            | ResolveAuthenticatedRequestOutcome::AuthorizationRevisionChanged { .. },
        ) => return rejected_credential(surface, state.cookie_mode()),
        Err(error) => return resolver_error(error, surface),
    };

    if let Some(body) = pending_rbac_form_body {
        let submission = parse_rbac_management_form(request.uri().path(), &body, now).map_or(
            RbacManagementFormSubmission::Invalid,
            RbacManagementFormSubmission::Valid,
        );
        request.extensions_mut().insert(submission);
    }

    let touched = match state
        .sessions
        .touch_raw(raw, expected_kind, state.idle_lifetime(expected_kind))
        .await
    {
        Ok(TouchSessionOutcome::Touched(session) | TouchSessionOutcome::Unchanged(session)) => {
            session
        }
        Ok(
            TouchSessionOutcome::NotFound
            | TouchSessionOutcome::WrongKindOrAudience
            | TouchSessionOutcome::Revoked
            | TouchSessionOutcome::Expired
            | TouchSessionOutcome::NotYetValid
            | TouchSessionOutcome::PrincipalDisabled
            | TouchSessionOutcome::MembershipSuspended
            | TouchSessionOutcome::AuthorizationRevisionChanged { .. },
        ) => return rejected_credential(surface, state.cookie_mode()),
        Err(error) => return credential_service_error(error, surface, state.cookie_mode()),
    };

    if insert_authenticated_context(&mut request, &snapshot).is_err() {
        return request_auth_error_response(
            surface,
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal server error.\n",
            HumanRequestApiError::Internal,
            false,
        );
    }
    request.extensions_mut().insert((*snapshot).clone());
    if let Some(csrf) = browser_csrf.as_ref() {
        request.extensions_mut().insert(Arc::clone(csrf));
    }
    if browser_logout {
        let PresentedHumanCredential::Browser(credential) = presented else {
            return rejected_credential(surface, state.cookie_mode());
        };
        request
            .extensions_mut()
            .insert(Arc::new(BrowserLogoutCredential::new(credential)));
    } else if cli_logout {
        let PresentedHumanCredential::Cli(credential) = presented else {
            return rejected_credential(surface, state.cookie_mode());
        };
        request
            .extensions_mut()
            .insert(Arc::new(CliSessionCredential::new(credential)));
    } else {
        drop(presented);
    }
    // An unsafe browser request reaches this point only after its Origin and
    // double-submit token were verified. Refreshing the cookie together with
    // every successful idle-deadline touch keeps it from expiring before an
    // otherwise active mutation-only session.
    let csrf_cookie = if let Some(csrf) = browser_csrf {
        let deadline = touched.idle_expires_at().min(touched.expires_at());
        let Some(seconds) = deadline.as_seconds().checked_sub(now.as_seconds()) else {
            return rejected_credential(surface, state.cookie_mode());
        };
        match csrf_set_cookie(state.cookie_mode(), &csrf, Duration::from_secs(seconds)) {
            Ok(cookie) => Some(cookie),
            Err(_) => {
                return request_auth_error_response(
                    surface,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error.\n",
                    HumanRequestApiError::Internal,
                    false,
                );
            }
        }
    } else {
        None
    };
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().append(
        VARY,
        axum::http::HeaderValue::from_static(match expected_kind {
            SessionKind::Browser => "Cookie",
            SessionKind::Cli => "Authorization",
        }),
    );
    if response
        .extensions()
        .get::<BrowserLogoutCompleted>()
        .is_some()
    {
        for cookie in [
            clear_session_cookie(state.cookie_mode()),
            clear_csrf_cookie(state.cookie_mode()),
            clear_login_cookie(state.cookie_mode()),
        ] {
            let Ok(cookie) = cookie else {
                continue;
            };
            response
                .headers_mut()
                .append(SET_COOKIE, cookie.into_header_value());
        }
    } else if response.status() == StatusCode::UNAUTHORIZED && expected_kind == SessionKind::Browser
    {
        if let Ok(cookie) = clear_session_cookie(state.cookie_mode()) {
            response
                .headers_mut()
                .append(SET_COOKIE, cookie.into_header_value());
        }
        if let Ok(cookie) = clear_csrf_cookie(state.cookie_mode()) {
            response
                .headers_mut()
                .append(SET_COOKIE, cookie.into_header_value());
        }
    } else if let Some(cookie) = csrf_cookie {
        response
            .headers_mut()
            .append(SET_COOKIE, cookie.into_header_value());
    }
    response
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BrowserMutationRequestError {
    Forbidden,
    UnsupportedMediaType,
    PayloadTooLarge,
}

async fn verify_browser_mutation_request(
    request: &mut Request<Body>,
    origin: &HumanAuthOrigin,
    expected_csrf: &CsrfToken,
) -> Result<Option<bytes::Bytes>, BrowserMutationRequestError> {
    let publication_form = is_publication_settings_form(request.method(), request.uri().path());
    let rbac_form = is_rbac_management_form(request.method(), request.uri().path());
    let repository_secret_form = is_repository_secret_form(request.method(), request.uri().path());
    let logout_form = is_browser_logout_form(request.method(), request.uri().path());
    if !publication_form && !rbac_form && !repository_secret_form && !logout_form {
        return verify_browser_mutation(request.headers(), origin, expected_csrf)
            .map(|()| None)
            .map_err(|_| BrowserMutationRequestError::Forbidden);
    }
    let mut content_types = request.headers().get_all(CONTENT_TYPE).iter();
    let content_type = content_types
        .next()
        .ok_or(BrowserMutationRequestError::UnsupportedMediaType)?;
    if content_types.next().is_some()
        || content_type
            .to_str()
            .map_err(|_| BrowserMutationRequestError::UnsupportedMediaType)?
            != "application/x-www-form-urlencoded"
    {
        return Err(BrowserMutationRequestError::UnsupportedMediaType);
    }
    if request.headers().contains_key("x-automata-csrf-token") {
        return Err(BrowserMutationRequestError::Forbidden);
    }
    if repository_secret_form {
        let body = std::mem::replace(request.body_mut(), Body::empty());
        let parsed = collect_repository_secret_form(request.uri().path(), body)
            .await
            .map_err(|error| match error {
                RepositorySecretFormError::Invalid => BrowserMutationRequestError::Forbidden,
                RepositorySecretFormError::TooLarge => BrowserMutationRequestError::PayloadTooLarge,
            })?;
        let (csrf_token, submission) = parsed.into_parts();
        let mut headers = request.headers().clone();
        let mut csrf_header = axum::http::HeaderValue::from_str(csrf_token.expose_secret())
            .map_err(|_| BrowserMutationRequestError::Forbidden)?;
        csrf_header.set_sensitive(true);
        headers.insert("x-automata-csrf-token", csrf_header);
        verify_browser_mutation(&headers, origin, expected_csrf)
            .map_err(|_| BrowserMutationRequestError::Forbidden)?;
        request.extensions_mut().insert(submission);
        return Ok(None);
    }
    let maximum_body_bytes = match (logout_form, publication_form, rbac_form) {
        (true, false, false) => MAX_BROWSER_LOGOUT_FORM_BYTES,
        (false, true, false) => MAX_PUBLICATION_SETTINGS_FORM_BYTES,
        (false, false, true) => MAX_RBAC_MANAGEMENT_FORM_BYTES,
        _ => return Err(BrowserMutationRequestError::Forbidden),
    };
    let body = std::mem::replace(request.body_mut(), Body::empty());
    let bytes = to_bytes(body, maximum_body_bytes)
        .await
        .map_err(|_| BrowserMutationRequestError::PayloadTooLarge)?;
    let csrf_token = match (logout_form, publication_form, rbac_form) {
        (true, false, false) => {
            browser_logout_csrf_token(&bytes).ok_or(BrowserMutationRequestError::Forbidden)?
        }
        (false, true, false) => publication_settings_csrf_token(&bytes)
            .map_err(|_| BrowserMutationRequestError::Forbidden)?,
        (false, false, true) => rbac_management_csrf_token(&bytes)
            .map_err(|_| BrowserMutationRequestError::Forbidden)?,
        _ => return Err(BrowserMutationRequestError::Forbidden),
    };
    let mut headers = request.headers().clone();
    let mut csrf_header = axum::http::HeaderValue::from_str(csrf_token.expose_secret())
        .map_err(|_| BrowserMutationRequestError::Forbidden)?;
    csrf_header.set_sensitive(true);
    headers.insert("x-automata-csrf-token", csrf_header);
    verify_browser_mutation(&headers, origin, expected_csrf)
        .map_err(|_| BrowserMutationRequestError::Forbidden)?;
    if publication_form {
        let submission = parse_publication_settings_form(&bytes)
            .map_or(PublicationSettingsFormSubmission::Invalid, |parsed| {
                PublicationSettingsFormSubmission::Valid(parsed.into_verified())
            });
        request.extensions_mut().insert(submission);
    } else if rbac_form {
        return Ok(Some(bytes));
    }
    Ok(None)
}

fn is_safe_method(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD)
}

const fn surface_accepts(surface: HumanRequestSurface, kind: SessionKind) -> bool {
    matches!(
        (surface, kind),
        (HumanRequestSurface::Browser, SessionKind::Browser)
            | (HumanRequestSurface::Cli, SessionKind::Cli)
    )
}

fn insert_anonymous_context(
    state: &HumanRequestAuthentication,
    request: &mut Request<Body>,
) -> Result<(), ()> {
    let context = RequestContext::new(
        state.anonymous_tenant.clone(),
        automata_ci_auth::authorization::AuthorizationContext::anonymous(),
        None,
        Some(GITHUB_WEB_BEGIN_PATH.to_owned()),
    )
    .map_err(|_| ())?;
    request.extensions_mut().insert(context);
    Ok(())
}

fn insert_authenticated_context(
    request: &mut Request<Body>,
    snapshot: &AuthenticatedRequestSnapshot,
) -> Result<(), ()> {
    let context = RequestContext::new(
        snapshot.session().identity().tenant_id().clone(),
        snapshot.authorization().clone(),
        Some(Viewer {
            display_name: snapshot.viewer().display_name().to_owned(),
        }),
        None,
    )
    .map_err(|_| ())?;
    request.extensions_mut().insert(context);
    Ok(())
}

fn rejected_credential(surface: HumanRequestSurface, mode: HumanCookieMode) -> Response {
    let mut response = request_auth_error_response(
        surface,
        StatusCode::UNAUTHORIZED,
        "Unauthorized.\n",
        HumanRequestApiError::Unauthorized,
        surface == HumanRequestSurface::Cli,
    );
    if surface == HumanRequestSurface::Browser {
        if let Ok(cookie) = clear_session_cookie(mode) {
            response
                .headers_mut()
                .append(SET_COOKIE, cookie.into_header_value());
        }
        if let Ok(cookie) = clear_csrf_cookie(mode) {
            response
                .headers_mut()
                .append(SET_COOKIE, cookie.into_header_value());
        }
    }
    response
}

fn credential_service_error(
    error: SessionCredentialServiceError,
    surface: HumanRequestSurface,
    mode: HumanCookieMode,
) -> Response {
    match error {
        SessionCredentialServiceError::InvalidCredential => rejected_credential(surface, mode),
        SessionCredentialServiceError::RepositoryUnavailable => request_auth_error_response(
            surface,
            StatusCode::SERVICE_UNAVAILABLE,
            "Authentication temporarily unavailable.\n",
            HumanRequestApiError::Unavailable,
            false,
        ),
        SessionCredentialServiceError::RandomnessUnavailable
        | SessionCredentialServiceError::CollisionLimitExceeded
        | SessionCredentialServiceError::InvalidLifetime
        | SessionCredentialServiceError::LifetimeOverflow
        | SessionCredentialServiceError::InternalFailure => request_auth_error_response(
            surface,
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal server error.\n",
            HumanRequestApiError::Internal,
            false,
        ),
    }
}

fn resolver_error(
    error: RequestAuthenticationResolverError,
    surface: HumanRequestSurface,
) -> Response {
    match error {
        RequestAuthenticationResolverError::Unavailable => request_auth_error_response(
            surface,
            StatusCode::SERVICE_UNAVAILABLE,
            "Authentication temporarily unavailable.\n",
            HumanRequestApiError::Unavailable,
            false,
        ),
        RequestAuthenticationResolverError::InvalidRequest
        | RequestAuthenticationResolverError::CorruptData => request_auth_error_response(
            surface,
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal server error.\n",
            HumanRequestApiError::Internal,
            false,
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        sync::{
            Mutex,
            atomic::{AtomicU64, Ordering},
        },
    };

    use automata_ci_auth::{
        authorization::{AuthorizationContext, OutputVisibility},
        human::{AuthenticatedHuman, PrincipalId, ProviderId, ProviderSubject},
        request_auth::{RequestAuthenticationFuture, ViewerDisplayMetadata},
        secret::{SecretBytes, SystemSecureRandom},
        session::{
            CreateSession, CreateSessionOutcome, DurableSession, DurableSessionIdentity,
            HumanSessionRepository, ResolveSession, ResolveSessionOutcome, RevokeOwnSession,
            RevokeOwnSessionOutcome, RevokePrincipalSessions, RevokePrincipalSessionsOutcome,
            SessionRepositoryError, SessionRepositoryFuture, SessionTokenDigestKeyId, TouchSession,
        },
        session_credential::{SessionCredentialKey, SessionCredentialKeyring},
        time::UnixTimestamp,
    };
    use axum::{
        Extension, Router, middleware,
        routing::{delete, get, post},
    };
    use tower::ServiceExt as _;
    use url::Url;

    use super::*;
    use crate::app::rbac_management::VerifiedRbacManagementForm;

    const SESSION: &str = "v1~test-key~AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[derive(Debug)]
    struct MutableClock(AtomicU64);

    impl MutableClock {
        fn new(now: u64) -> Self {
            Self(AtomicU64::new(now))
        }

        fn set(&self, now: u64) {
            self.0.store(now, Ordering::SeqCst);
        }
    }

    impl Clock for MutableClock {
        fn now(&self) -> UnixTimestamp {
            UnixTimestamp::from_seconds(self.0.load(Ordering::SeqCst))
        }
    }

    #[derive(Debug)]
    struct TouchingSessionRepository {
        identity: DurableSessionIdentity,
        observations: Mutex<Vec<u64>>,
    }

    impl HumanSessionRepository for TouchingSessionRepository {
        fn create(
            &self,
            _request: CreateSession,
        ) -> SessionRepositoryFuture<'_, CreateSessionOutcome> {
            Box::pin(async { Err(SessionRepositoryError::InvalidRequest) })
        }

        fn resolve<'a>(
            &'a self,
            _request: &'a ResolveSession,
        ) -> SessionRepositoryFuture<'a, ResolveSessionOutcome> {
            Box::pin(async { Err(SessionRepositoryError::InvalidRequest) })
        }

        fn touch<'a>(
            &'a self,
            request: &'a TouchSession,
        ) -> SessionRepositoryFuture<'a, TouchSessionOutcome> {
            Box::pin(async move {
                self.observations
                    .lock()
                    .expect("touch observations")
                    .push(request.observed_at().as_seconds());
                let session = DurableSession::new(
                    self.identity.clone(),
                    1,
                    UnixTimestamp::from_seconds(1),
                    request.observed_at(),
                    request.idle_expires_at(),
                    UnixTimestamp::from_seconds(1_000),
                    None,
                )
                .expect("touched session");
                Ok(TouchSessionOutcome::Touched(Box::new(session)))
            })
        }

        fn revoke_own<'a>(
            &'a self,
            _request: &'a RevokeOwnSession,
        ) -> SessionRepositoryFuture<'a, RevokeOwnSessionOutcome> {
            Box::pin(async { Err(SessionRepositoryError::InvalidRequest) })
        }

        fn revoke_principal<'a>(
            &'a self,
            _request: &'a RevokePrincipalSessions,
        ) -> SessionRepositoryFuture<'a, RevokePrincipalSessionsOutcome> {
            Box::pin(async { Err(SessionRepositoryError::InvalidRequest) })
        }
    }

    #[derive(Debug)]
    struct FixedResolver(AuthenticatedRequestSnapshot);

    impl RequestAuthenticationResolver for FixedResolver {
        fn resolve<'a>(
            &'a self,
            _request: &'a ResolveAuthenticatedRequest,
        ) -> RequestAuthenticationFuture<'a> {
            Box::pin(async move {
                Ok(ResolveAuthenticatedRequestOutcome::Authenticated(Box::new(
                    self.0.clone(),
                )))
            })
        }
    }

    fn session_identity(
        kind: SessionKind,
    ) -> (
        TenantId,
        PrincipalId,
        ProviderId,
        ProviderSubject,
        DurableSessionIdentity,
    ) {
        let tenant_id = TenantId::new("tenant-a").expect("tenant");
        let principal_id =
            PrincipalId::new("11111111-1111-4111-8111-111111111111").expect("principal");
        let provider_id = ProviderId::new("github").expect("provider");
        let provider_subject = ProviderSubject::new("123").expect("subject");
        let identity = DurableSessionIdentity::new(
            automata_ci_auth::session::SessionId::new("22222222-2222-4222-8222-222222222222")
                .expect("session ID"),
            tenant_id.clone(),
            principal_id.clone(),
            provider_id.clone(),
            provider_subject.clone(),
            kind,
        )
        .expect("session identity");
        (
            tenant_id,
            principal_id,
            provider_id,
            provider_subject,
            identity,
        )
    }

    fn browser_snapshot(
        tenant_id: &TenantId,
        principal_id: &PrincipalId,
        provider_id: &ProviderId,
        provider_subject: &ProviderSubject,
        identity: DurableSessionIdentity,
    ) -> AuthenticatedRequestSnapshot {
        let session = DurableSession::new(
            identity,
            1,
            UnixTimestamp::from_seconds(1),
            UnixTimestamp::from_seconds(1),
            UnixTimestamp::from_seconds(900),
            UnixTimestamp::from_seconds(1_000),
            None,
        )
        .expect("session");
        let human = AuthenticatedHuman::new(
            principal_id.clone(),
            provider_id.clone(),
            provider_subject.clone(),
            "octocat",
            Some("Octocat".to_owned()),
            UnixTimestamp::from_seconds(1),
        )
        .expect("human");
        let authorization = AuthorizationContext::authenticated_at_revision(
            tenant_id.clone(),
            principal_id.clone(),
            BTreeSet::new(),
            1,
        )
        .expect("authorization");
        AuthenticatedRequestSnapshot::new(
            session,
            human,
            ViewerDisplayMetadata::new("Octocat").expect("viewer"),
            authorization,
        )
        .expect("request snapshot")
    }

    fn mutation_request(csrf: &str) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri("/mutate")
            .header(
                axum::http::header::COOKIE,
                format!("automata-dev-session={SESSION}; automata-dev-csrf={csrf}"),
            )
            .header("origin", "http://127.0.0.1:8080")
            .header("sec-fetch-site", "same-origin")
            .header("x-automata-csrf-token", csrf)
            .body(Body::empty())
            .expect("request")
    }

    fn middleware_fixture(
        clock: Arc<MutableClock>,
    ) -> (
        HumanRequestAuthentication,
        Arc<TouchingSessionRepository>,
        String,
    ) {
        let (state, repository, csrf) = middleware_fixture_for(clock, SessionKind::Browser);
        (state, repository, csrf.expect("browser CSRF"))
    }

    fn middleware_fixture_for(
        clock: Arc<MutableClock>,
        kind: SessionKind,
    ) -> (
        HumanRequestAuthentication,
        Arc<TouchingSessionRepository>,
        Option<String>,
    ) {
        let (tenant_id, principal_id, provider_id, provider_subject, identity) =
            session_identity(kind);
        let repository = Arc::new(TouchingSessionRepository {
            identity: identity.clone(),
            observations: Mutex::new(Vec::new()),
        });
        let key = SessionCredentialKey::new(
            SessionTokenDigestKeyId::new("test-key").expect("key ID"),
            SecretBytes::new(vec![0x5a; 32]).expect("key material"),
        )
        .expect("session key");
        let keyring = SessionCredentialKeyring::new(key, Vec::new()).expect("keyring");
        let sessions = Arc::new(SessionCredentialService::new(
            keyring,
            repository.clone(),
            Arc::new(SystemSecureRandom),
            clock.clone(),
        ));
        let csrf = (kind == SessionKind::Browser).then(|| {
            sessions
                .derive_csrf_raw(SESSION, SessionKind::Browser)
                .expect("CSRF token")
                .expose_secret()
                .to_owned()
        });
        let snapshot = browser_snapshot(
            &tenant_id,
            &principal_id,
            &provider_id,
            &provider_subject,
            identity,
        );
        let origin = HumanAuthOrigin::new(
            &Url::parse("http://127.0.0.1:8080/").expect("application origin"),
        )
        .expect("human auth origin");
        let state = HumanRequestAuthentication::new(
            sessions,
            Arc::new(FixedResolver(snapshot)),
            clock,
            origin,
            tenant_id,
            Duration::from_mins(5),
            Duration::from_mins(5),
        )
        .expect("middleware state");
        (state, repository, csrf)
    }

    #[test]
    fn only_anonymous_auth_surfaces_bypass_session_parsing() {
        for path in [
            "/healthz",
            "/readyz",
            "/assets/client.js",
            "/auth/github/login",
            "/auth/github/callback",
            "/setup/auth/github",
            "/api/v1/auth/device",
            "/api/v1/auth/device/poll",
            "/api/v1/setup/device",
            "/api/v1/setup/device/poll",
        ] {
            assert_eq!(request_surface(path), HumanRequestSurface::Bypass);
        }
        assert_eq!(
            request_surface("/api/v1/local/workflow-runs"),
            HumanRequestSurface::Cli
        );
        assert_eq!(request_surface("/api/v1/users"), HumanRequestSurface::Cli);
        assert_eq!(request_surface("/api/v1"), HumanRequestSurface::Cli);
        assert_eq!(
            request_surface("/api/v1/local/future-route"),
            HumanRequestSurface::Cli
        );
        assert_eq!(
            request_surface("/webhooks/github"),
            HumanRequestSurface::Browser
        );
        assert_eq!(request_surface("/"), HumanRequestSurface::Browser);
        assert_eq!(request_surface("/api/v10"), HumanRequestSurface::Browser);
        assert_eq!(
            request_surface("/admin/users"),
            HumanRequestSurface::Browser
        );
        assert_eq!(
            request_surface_for(&Method::GET, "/setup"),
            HumanRequestSurface::Bypass
        );
        for (method, path) in [
            (Method::POST, "/setup"),
            (Method::HEAD, "/setup"),
            (Method::GET, "/setup/"),
        ] {
            assert_eq!(
                request_surface_for(&method, path),
                HumanRequestSurface::Browser
            );
        }
    }

    #[test]
    fn credential_kinds_cannot_cross_browser_and_cli_surfaces() {
        assert!(surface_accepts(
            HumanRequestSurface::Browser,
            SessionKind::Browser
        ));
        assert!(surface_accepts(HumanRequestSurface::Cli, SessionKind::Cli));
        assert!(!surface_accepts(
            HumanRequestSurface::Browser,
            SessionKind::Cli
        ));
        assert!(!surface_accepts(
            HumanRequestSurface::Cli,
            SessionKind::Browser
        ));
    }

    #[tokio::test]
    async fn every_api_authentication_error_uses_the_closed_json_envelope() {
        for (status, error, expected) in [
            (
                StatusCode::BAD_REQUEST,
                HumanRequestApiError::InvalidRequest,
                r#"{"error":"invalid_request"}"#,
            ),
            (
                StatusCode::UNAUTHORIZED,
                HumanRequestApiError::Unauthorized,
                r#"{"error":"unauthorized"}"#,
            ),
            (
                StatusCode::FORBIDDEN,
                HumanRequestApiError::Forbidden,
                r#"{"error":"forbidden"}"#,
            ),
            (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                HumanRequestApiError::UnsupportedMediaType,
                r#"{"error":"unsupported_media_type"}"#,
            ),
            (
                StatusCode::PAYLOAD_TOO_LARGE,
                HumanRequestApiError::PayloadTooLarge,
                r#"{"error":"payload_too_large"}"#,
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                HumanRequestApiError::Unavailable,
                r#"{"error":"unavailable"}"#,
            ),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                HumanRequestApiError::Internal,
                r#"{"error":"internal_error"}"#,
            ),
        ] {
            let response = request_auth_error_response(
                HumanRequestSurface::Cli,
                status,
                "must not appear",
                error,
                false,
            );
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
            assert_eq!(
                response.headers()[CONTENT_TYPE],
                "application/json; charset=utf-8"
            );
            assert_eq!(
                to_bytes(response.into_body(), 128)
                    .await
                    .expect("bounded API auth body"),
                expected
            );
        }
    }

    #[tokio::test]
    async fn api_authentication_failures_are_json_while_browser_failures_stay_plain() {
        let clock = Arc::new(MutableClock::new(100));
        let (state, repository, _csrf) = middleware_fixture(clock);
        let app = Router::new()
            .route("/api/v1/users", get(|| async { StatusCode::NO_CONTENT }))
            .route("/repositories", get(|| async { StatusCode::NO_CONTENT }))
            .layer(middleware::from_fn_with_state(
                state,
                authenticate_human_request,
            ));

        let api = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/users")
                    .header(AUTHORIZATION, "Bearer deliberately-invalid")
                    .body(Body::empty())
                    .expect("API request"),
            )
            .await
            .expect("API response");
        assert_eq!(api.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(api.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            api.headers()[CONTENT_TYPE],
            "application/json; charset=utf-8"
        );
        assert_eq!(api.headers()[WWW_AUTHENTICATE], "Bearer realm=\"automata\"");
        assert_eq!(
            to_bytes(api.into_body(), 128).await.expect("API body"),
            r#"{"error":"unauthorized"}"#
        );

        let browser = app
            .oneshot(
                Request::builder()
                    .uri("/repositories")
                    .header(AUTHORIZATION, "Bearer deliberately-invalid")
                    .body(Body::empty())
                    .expect("browser request"),
            )
            .await
            .expect("browser response");
        assert_eq!(browser.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(browser.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(browser.headers()[CONTENT_TYPE], "text/plain; charset=utf-8");
        assert!(browser.headers().get(WWW_AUTHENTICATE).is_none());
        assert_eq!(
            to_bytes(browser.into_body(), 128)
                .await
                .expect("browser body"),
            "Unauthorized.\n"
        );
        assert!(
            repository
                .observations
                .lock()
                .expect("touch observations")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn exact_api_root_uses_cli_auth_without_capturing_neighbor_prefixes() {
        let clock = Arc::new(MutableClock::new(100));
        let (state, repository, csrf) = middleware_fixture_for(clock, SessionKind::Cli);
        assert!(csrf.is_none());
        let app = Router::new()
            .route("/api/v1", get(|| async { StatusCode::NO_CONTENT }))
            .route("/api/v10", get(|| async { StatusCode::NO_CONTENT }))
            .layer(middleware::from_fn_with_state(
                state,
                authenticate_human_request,
            ));

        let unauthenticated = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1")
                    .header(AUTHORIZATION, "Bearer deliberately-invalid")
                    .body(Body::empty())
                    .expect("exact API root request"),
            )
            .await
            .expect("exact API root response");
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            unauthenticated.headers()[CONTENT_TYPE],
            "application/json; charset=utf-8"
        );
        assert_eq!(
            to_bytes(unauthenticated.into_body(), 128)
                .await
                .expect("exact API root body"),
            r#"{"error":"unauthorized"}"#
        );

        let authenticated = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1")
                    .header(AUTHORIZATION, format!("Bearer {SESSION}"))
                    .body(Body::empty())
                    .expect("authenticated exact API root request"),
            )
            .await
            .expect("authenticated exact API root response");
        assert_eq!(authenticated.status(), StatusCode::NO_CONTENT);

        let neighbor = app
            .oneshot(
                Request::builder()
                    .uri("/api/v10")
                    .header(AUTHORIZATION, "Bearer deliberately-invalid")
                    .body(Body::empty())
                    .expect("neighbor browser request"),
            )
            .await
            .expect("neighbor browser response");
        assert_eq!(neighbor.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            neighbor.headers()[CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            *repository.observations.lock().expect("touch observations"),
            [100]
        );
    }

    #[tokio::test]
    async fn only_the_exact_setup_get_bypasses_browser_session_parsing() {
        let clock = Arc::new(MutableClock::new(100));
        let (state, repository, _csrf) = middleware_fixture(clock);
        let app = Router::new()
            .route(
                "/setup",
                get(|| async { StatusCode::NO_CONTENT }).post(|| async { StatusCode::NO_CONTENT }),
            )
            .layer(middleware::from_fn_with_state(
                state,
                authenticate_human_request,
            ));

        let anonymous_get = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/setup")
                    .header(AUTHORIZATION, "Bearer deliberately-invalid")
                    .body(Body::empty())
                    .expect("setup GET request"),
            )
            .await
            .expect("setup GET response");
        assert_eq!(anonymous_get.status(), StatusCode::NO_CONTENT);

        let classified_post = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/setup")
                    .header(AUTHORIZATION, "Bearer deliberately-invalid")
                    .body(Body::empty())
                    .expect("setup POST request"),
            )
            .await
            .expect("setup POST response");
        assert_eq!(classified_post.status(), StatusCode::UNAUTHORIZED);
        assert!(
            repository
                .observations
                .lock()
                .expect("touch observations")
                .is_empty()
        );
    }

    #[test]
    fn unsafe_methods_are_fail_closed_for_browser_csrf() {
        assert!(is_safe_method(&Method::GET));
        assert!(is_safe_method(&Method::HEAD));
        for method in [
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ] {
            assert!(!is_safe_method(&method));
        }
    }

    #[tokio::test]
    async fn cli_session_delete_receives_only_the_authenticated_redacted_bearer() {
        let clock = Arc::new(MutableClock::new(100));
        let (state, repository, csrf) = middleware_fixture_for(clock, SessionKind::Cli);
        assert!(csrf.is_none());
        let app = Router::new()
            .route(
                crate::app::github_auth::CLI_SESSION_PATH,
                delete(
                    |headers: axum::http::HeaderMap,
                     Extension(credential): Extension<Arc<CliSessionCredential>>| async move {
                        assert!(headers.get(AUTHORIZATION).is_none());
                        assert_eq!(
                            format!("{credential:?}"),
                            "CliSessionCredential([REDACTED])"
                        );
                        StatusCode::NO_CONTENT
                    },
                ),
            )
            .layer(middleware::from_fn_with_state(
                state,
                authenticate_human_request,
            ));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri(crate::app::github_auth::CLI_SESSION_PATH)
                    .header(
                        axum::http::header::AUTHORIZATION,
                        format!("Bearer {SESSION}"),
                    )
                    .body(Body::empty())
                    .expect("CLI logout request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let rejected_query = app
            .oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri(format!(
                        "{}?unexpected=1",
                        crate::app::github_auth::CLI_SESSION_PATH
                    ))
                    .header(
                        axum::http::header::AUTHORIZATION,
                        format!("Bearer {SESSION}"),
                    )
                    .body(Body::empty())
                    .expect("CLI logout request with query"),
            )
            .await
            .expect("query rejection response");
        assert_eq!(rejected_query.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            *repository.observations.lock().expect("touch observations"),
            [100]
        );
    }

    #[tokio::test]
    async fn exact_cli_activation_post_bypasses_normal_pending_session_resolution() {
        let clock = Arc::new(MutableClock::new(100));
        let (state, repository, csrf) = middleware_fixture_for(clock, SessionKind::Cli);
        assert!(csrf.is_none());
        let app = Router::new()
            .route(
                crate::app::github_auth::CLI_SESSION_PATH,
                post(|headers: axum::http::HeaderMap| async move {
                    assert!(headers.get(AUTHORIZATION).is_some());
                    StatusCode::NO_CONTENT
                }),
            )
            .layer(middleware::from_fn_with_state(
                state,
                authenticate_human_request,
            ));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(crate::app::github_auth::CLI_SESSION_PATH)
                    .header(AUTHORIZATION, format!("Bearer {SESSION}"))
                    .body(Body::empty())
                    .expect("CLI activation request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(
            repository
                .observations
                .lock()
                .expect("touch observations")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn successful_mutations_refresh_csrf_through_each_touched_idle_deadline() {
        let clock = Arc::new(MutableClock::new(100));
        let (state, repository, csrf) = middleware_fixture(clock.clone());
        let app = Router::new()
            .route("/mutate", post(|| async { StatusCode::NO_CONTENT }))
            .layer(middleware::from_fn_with_state(
                state,
                authenticate_human_request,
            ));

        for now in [100, 200] {
            clock.set(now);
            let response = app
                .clone()
                .oneshot(mutation_request(&csrf))
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            let cookies: Vec<_> = response.headers().get_all(SET_COOKIE).iter().collect();
            assert_eq!(cookies.len(), 1);
            assert!(cookies[0].is_sensitive());
            assert!(
                cookies[0]
                    .to_str()
                    .expect("cookie header")
                    .contains("; Path=/; Max-Age=300; SameSite=Strict")
            );
        }
        assert_eq!(
            *repository.observations.lock().expect("touch observations"),
            [100, 200]
        );
    }

    #[tokio::test]
    async fn downstream_stale_session_response_clears_browser_credentials() {
        let clock = Arc::new(MutableClock::new(100));
        let (state, _repository, csrf) = middleware_fixture(clock);
        let app = Router::new()
            .route("/mutate", post(|| async { StatusCode::UNAUTHORIZED }))
            .layer(middleware::from_fn_with_state(
                state,
                authenticate_human_request,
            ));

        let response = app
            .oneshot(mutation_request(&csrf))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let cookies = response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .map(|value| value.to_str().expect("cookie header"))
            .collect::<Vec<_>>();
        assert_eq!(cookies.len(), 2);
        assert!(cookies.iter().all(|cookie| cookie.contains("Max-Age=0")));
        assert!(
            cookies
                .iter()
                .any(|cookie| cookie.starts_with("automata-dev-session="))
        );
        assert!(
            cookies
                .iter()
                .any(|cookie| cookie.starts_with("automata-dev-csrf="))
        );
    }

    #[tokio::test]
    async fn logout_rejects_missing_and_bearer_credentials_before_dispatch() {
        let clock = Arc::new(MutableClock::new(100));
        let (state, repository, csrf) = middleware_fixture(clock);
        let dispatches = Arc::new(AtomicU64::new(0));
        let observed_dispatches = Arc::clone(&dispatches);
        let app = Router::new()
            .route(
                GITHUB_WEB_LOGOUT_PATH,
                post(move || {
                    let dispatches = Arc::clone(&observed_dispatches);
                    async move {
                        dispatches.fetch_add(1, Ordering::SeqCst);
                        StatusCode::NO_CONTENT
                    }
                }),
            )
            .layer(middleware::from_fn_with_state(
                state,
                authenticate_human_request,
            ));
        for authorization in [None, Some(format!("Bearer {SESSION}"))] {
            let mut builder = Request::builder()
                .method(Method::POST)
                .uri(GITHUB_WEB_LOGOUT_PATH)
                .header("origin", "http://127.0.0.1:8080")
                .header("sec-fetch-site", "same-origin")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded");
            if let Some(authorization) = authorization {
                builder = builder.header(axum::http::header::AUTHORIZATION, authorization);
            }
            let response = app
                .clone()
                .oneshot(
                    builder
                        .body(Body::from(format!("csrf_token={csrf}")))
                        .expect("logout request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        assert_eq!(dispatches.load(Ordering::SeqCst), 0);
        assert!(
            repository
                .observations
                .lock()
                .expect("touch observations")
                .is_empty()
        );
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table covers the complete native logout rejection matrix"
    )]
    async fn native_logout_form_is_verified_before_dispatch_and_clears_all_auth_cookies() {
        let clock = Arc::new(MutableClock::new(100));
        let (state, repository, csrf) = middleware_fixture(clock);
        let dispatches = Arc::new(AtomicU64::new(0));
        let observed_dispatches = Arc::clone(&dispatches);
        let app = Router::new()
            .route(
                GITHUB_WEB_LOGOUT_PATH,
                post(
                    move |Extension(credential): Extension<Arc<BrowserLogoutCredential>>| {
                        let dispatches = Arc::clone(&observed_dispatches);
                        async move {
                            assert_eq!(
                                format!("{credential:?}"),
                                "BrowserLogoutCredential([REDACTED])"
                            );
                            dispatches.fetch_add(1, Ordering::SeqCst);
                            let mut response = Response::new(Body::empty());
                            *response.status_mut() = StatusCode::SEE_OTHER;
                            response.extensions_mut().insert(BrowserLogoutCompleted);
                            response
                        }
                    },
                ),
            )
            .layer(middleware::from_fn_with_state(
                state,
                authenticate_human_request,
            ));

        let request = |body: String,
                       content_type: Option<&str>,
                       origin: &str,
                       fetch_site: &str,
                       add_header: bool| {
            let mut builder = Request::builder()
                .method(Method::POST)
                .uri(GITHUB_WEB_LOGOUT_PATH)
                .header(
                    axum::http::header::COOKIE,
                    format!(
                        "automata-dev-session={SESSION}; automata-dev-csrf={csrf}; \
                         automata-dev-login=stale-binding"
                    ),
                )
                .header("origin", origin)
                .header("sec-fetch-site", fetch_site);
            if let Some(content_type) = content_type {
                builder = builder.header(CONTENT_TYPE, content_type);
            }
            if add_header {
                builder = builder.header("x-automata-csrf-token", &csrf);
            }
            builder.body(Body::from(body)).expect("logout request")
        };
        let valid_body = format!("csrf_token={csrf}");

        for (invalid, expected) in [
            (
                request(
                    valid_body.clone(),
                    Some("application/x-www-form-urlencoded"),
                    "http://127.0.0.1:8080",
                    "same-origin",
                    true,
                ),
                StatusCode::FORBIDDEN,
            ),
            (
                request(
                    valid_body.clone(),
                    None,
                    "http://127.0.0.1:8080",
                    "same-origin",
                    false,
                ),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                request(
                    valid_body.clone(),
                    Some("application/x-www-form-urlencoded; charset=utf-8"),
                    "http://127.0.0.1:8080",
                    "same-origin",
                    false,
                ),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                request(
                    "csrf_token=x&csrf_token=y".to_owned(),
                    Some("application/x-www-form-urlencoded"),
                    "http://127.0.0.1:8080",
                    "same-origin",
                    false,
                ),
                StatusCode::FORBIDDEN,
            ),
            (
                request(
                    valid_body.clone(),
                    Some("application/x-www-form-urlencoded"),
                    "http://attacker.example",
                    "same-origin",
                    false,
                ),
                StatusCode::FORBIDDEN,
            ),
            (
                request(
                    valid_body.clone(),
                    Some("application/x-www-form-urlencoded"),
                    "http://127.0.0.1:8080",
                    "cross-site",
                    false,
                ),
                StatusCode::FORBIDDEN,
            ),
            (
                request(
                    "x".repeat(MAX_BROWSER_LOGOUT_FORM_BYTES + 1),
                    Some("application/x-www-form-urlencoded"),
                    "http://127.0.0.1:8080",
                    "same-origin",
                    false,
                ),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
        ] {
            let response = app.clone().oneshot(invalid).await.expect("response");
            assert_eq!(response.status(), expected);
        }
        assert_eq!(dispatches.load(Ordering::SeqCst), 0);
        assert!(
            repository
                .observations
                .lock()
                .expect("touch observations")
                .is_empty()
        );

        let response = app
            .oneshot(request(
                valid_body,
                Some("application/x-www-form-urlencoded"),
                "http://127.0.0.1:8080",
                "same-origin",
                false,
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(dispatches.load(Ordering::SeqCst), 1);
        assert_eq!(
            *repository.observations.lock().expect("touch observations"),
            [100]
        );
        let cookies = response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .map(|value| value.to_str().expect("cookie header"))
            .collect::<Vec<_>>();
        assert_eq!(cookies.len(), 3);
        assert!(cookies.iter().all(|cookie| cookie.contains("Max-Age=0")));
        for name in [
            "automata-dev-session=",
            "automata-dev-csrf=",
            "automata-dev-login=",
        ] {
            assert!(cookies.iter().any(|cookie| cookie.starts_with(name)));
        }
    }

    #[tokio::test]
    async fn failed_logout_keeps_auth_cookies_and_refreshes_only_csrf() {
        let clock = Arc::new(MutableClock::new(100));
        let (state, _repository, csrf) = middleware_fixture(clock);
        let app = Router::new()
            .route(
                GITHUB_WEB_LOGOUT_PATH,
                post(
                    |Extension(_credential): Extension<Arc<BrowserLogoutCredential>>| async {
                        StatusCode::SERVICE_UNAVAILABLE
                    },
                ),
            )
            .layer(middleware::from_fn_with_state(
                state,
                authenticate_human_request,
            ));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(GITHUB_WEB_LOGOUT_PATH)
                    .header(
                        axum::http::header::COOKIE,
                        format!("automata-dev-session={SESSION}; automata-dev-csrf={csrf}"),
                    )
                    .header("origin", "http://127.0.0.1:8080")
                    .header("sec-fetch-site", "same-origin")
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!("csrf_token={csrf}")))
                    .expect("logout request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let cookies = response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .collect::<Vec<_>>();
        assert_eq!(cookies.len(), 1);
        let cookie = cookies[0].to_str().expect("cookie header");
        assert!(cookie.starts_with("automata-dev-csrf="));
        assert!(!cookie.contains("Max-Age=0"));
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table covers the complete publication-form rejection matrix"
    )]
    async fn no_javascript_settings_form_is_bounded_verified_and_typed_before_dispatch() {
        let clock = Arc::new(MutableClock::new(100));
        let (state, repository, csrf) = middleware_fixture(clock);
        let dispatches = Arc::new(AtomicU64::new(0));
        let observed_dispatches = Arc::clone(&dispatches);
        let app = Router::new()
            .route(
                "/{owner}/{repository}/settings/access",
                post(
                    move |Extension(submission): Extension<PublicationSettingsFormSubmission>,
                          Extension(derived): Extension<Arc<CsrfToken>>| {
                        let dispatches = Arc::clone(&observed_dispatches);
                        async move {
                            let PublicationSettingsFormSubmission::Valid(form) = submission else {
                                return StatusCode::BAD_REQUEST;
                            };
                            assert_eq!(form.expected_revision().value(), 7);
                            assert_eq!(form.policy().dashboard(), OutputVisibility::Public);
                            assert_eq!(form.policy().logs(), OutputVisibility::Authenticated);
                            assert_eq!(form.policy().artifacts(), OutputVisibility::Private);
                            assert!(derived.has_generated_shape());
                            dispatches.fetch_add(1, Ordering::SeqCst);
                            StatusCode::NO_CONTENT
                        }
                    },
                ),
            )
            .layer(middleware::from_fn_with_state(
                state,
                authenticate_human_request,
            ));

        let valid_body = format!(
            "csrf_token={csrf}&expected_revision=7&dashboard_audience=public&\
             log_audience=authenticated&artifact_audience=private"
        );
        let request = |body: String, add_header: bool, content_type: Option<&str>| {
            let mut builder = Request::builder()
                .method(Method::POST)
                .uri("/acme/payments/settings/access")
                .header(
                    axum::http::header::COOKIE,
                    format!("automata-dev-session={SESSION}; automata-dev-csrf={csrf}"),
                )
                .header("origin", "http://127.0.0.1:8080")
                .header("sec-fetch-site", "same-origin");
            if let Some(content_type) = content_type {
                builder = builder.header(CONTENT_TYPE, content_type);
            }
            if add_header {
                builder = builder.header("x-automata-csrf-token", &csrf);
            }
            builder.body(Body::from(body)).expect("request")
        };

        for (invalid, expected) in [
            (
                request(
                    valid_body.clone(),
                    true,
                    Some("application/x-www-form-urlencoded"),
                ),
                StatusCode::FORBIDDEN,
            ),
            (
                request(valid_body.clone(), false, None),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                request(
                    valid_body.clone(),
                    false,
                    Some("application/x-www-form-urlencoded; charset=utf-8"),
                ),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                request(
                    format!("{valid_body}&csrf_token={csrf}"),
                    false,
                    Some("application/x-www-form-urlencoded"),
                ),
                StatusCode::FORBIDDEN,
            ),
            (
                request(
                    "x".repeat(MAX_PUBLICATION_SETTINGS_FORM_BYTES + 1),
                    false,
                    Some("application/x-www-form-urlencoded"),
                ),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
        ] {
            let response = app.clone().oneshot(invalid).await.expect("response");
            assert_eq!(response.status(), expected);
        }
        assert_eq!(dispatches.load(Ordering::SeqCst), 0);
        assert!(
            repository
                .observations
                .lock()
                .expect("touch observations")
                .is_empty()
        );

        let response = app
            .clone()
            .oneshot(request(
                valid_body.replace("expected_revision=7", "expected_revision=07"),
                false,
                Some("application/x-www-form-urlencoded"),
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(dispatches.load(Ordering::SeqCst), 0);
        assert_eq!(
            *repository.observations.lock().expect("touch observations"),
            [100]
        );

        let response = app
            .oneshot(request(
                valid_body,
                false,
                Some("application/x-www-form-urlencoded"),
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(dispatches.load(Ordering::SeqCst), 1);
        assert_eq!(
            *repository.observations.lock().expect("touch observations"),
            [100, 100]
        );
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one matrix proves the secret form's browser and plaintext boundary"
    )]
    async fn repository_secret_form_preserves_browser_authority_and_move_only_ingress() {
        let clock = Arc::new(MutableClock::new(100));
        let (state, repository, csrf) = middleware_fixture(clock);
        let dispatches = Arc::new(AtomicU64::new(0));
        let observed_dispatches = Arc::clone(&dispatches);
        let path = "/acme/payments/settings/secrets";
        let app = Router::new()
            .route(
                path,
                post(
                    move |Extension(submission): Extension<RepositorySecretFormSubmission>,
                          Extension(derived): Extension<Arc<CsrfToken>>| {
                        let dispatches = Arc::clone(&observed_dispatches);
                        async move {
                            let Some(Ok(form)) = submission.take_for_test() else {
                                return StatusCode::BAD_REQUEST;
                            };
                            let VerifiedRepositorySecretForm::Create {
                                expected_authorization_revision,
                                secret_id,
                                mutation_id,
                                name,
                                value: _,
                            } = form
                            else {
                                return StatusCode::BAD_REQUEST;
                            };
                            assert_eq!(expected_authorization_revision.value(), 1);
                            assert_eq!(
                                secret_id.as_uuid().hyphenated().to_string(),
                                "77777777-7777-4777-8777-777777777777"
                            );
                            assert_eq!(
                                mutation_id.as_uuid().hyphenated().to_string(),
                                "88888888-8888-4888-8888-888888888888"
                            );
                            assert_eq!(name.as_str(), "DEPLOY_TOKEN");
                            assert!(derived.has_generated_shape());
                            dispatches.fetch_add(1, Ordering::SeqCst);
                            StatusCode::NO_CONTENT
                        }
                    },
                ),
            )
            .layer(middleware::from_fn_with_state(
                state,
                authenticate_human_request,
            ));
        let valid_body = format!(
            "csrf_token={csrf}&expected_authorization_revision=1&\
             secret_id=77777777-7777-4777-8777-777777777777&\
             mutation_id=88888888-8888-4888-8888-888888888888&\
             name=DEPLOY_TOKEN&value=private%25value"
        );
        let request = |body: String,
                       content_type: Option<&str>,
                       origin: &str,
                       fetch_site: &str,
                       add_header: bool| {
            let mut builder = Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(
                    axum::http::header::COOKIE,
                    format!("automata-dev-session={SESSION}; automata-dev-csrf={csrf}"),
                )
                .header("origin", origin)
                .header("sec-fetch-site", fetch_site);
            if let Some(content_type) = content_type {
                builder = builder.header(CONTENT_TYPE, content_type);
            }
            if add_header {
                builder = builder.header("x-automata-csrf-token", &csrf);
            }
            builder.body(Body::from(body)).expect("secret form request")
        };

        for (invalid, expected) in [
            (
                request(
                    valid_body.clone(),
                    Some("application/x-www-form-urlencoded"),
                    "http://127.0.0.1:8080",
                    "same-origin",
                    true,
                ),
                StatusCode::FORBIDDEN,
            ),
            (
                request(
                    valid_body.clone(),
                    Some("application/x-www-form-urlencoded; charset=utf-8"),
                    "http://127.0.0.1:8080",
                    "same-origin",
                    false,
                ),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                request(
                    valid_body.clone(),
                    Some("application/x-www-form-urlencoded"),
                    "http://attacker.example",
                    "same-origin",
                    false,
                ),
                StatusCode::FORBIDDEN,
            ),
            (
                request(
                    valid_body.clone(),
                    Some("application/x-www-form-urlencoded"),
                    "http://127.0.0.1:8080",
                    "cross-site",
                    false,
                ),
                StatusCode::FORBIDDEN,
            ),
            (
                request(
                    format!("{valid_body}&csrf_token={csrf}"),
                    Some("application/x-www-form-urlencoded"),
                    "http://127.0.0.1:8080",
                    "same-origin",
                    false,
                ),
                StatusCode::FORBIDDEN,
            ),
            (
                request(
                    "x".repeat(MAX_REPOSITORY_SECRET_FORM_BYTES + 1),
                    Some("application/x-www-form-urlencoded"),
                    "http://127.0.0.1:8080",
                    "same-origin",
                    false,
                ),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
        ] {
            let response = app.clone().oneshot(invalid).await.expect("response");
            assert_eq!(response.status(), expected);
        }
        assert_eq!(dispatches.load(Ordering::SeqCst), 0);
        assert!(
            repository
                .observations
                .lock()
                .expect("touch observations")
                .is_empty()
        );

        let invalid_business = request(
            valid_body.replace(
                "expected_authorization_revision=1",
                "expected_authorization_revision=01",
            ),
            Some("application/x-www-form-urlencoded"),
            "http://127.0.0.1:8080",
            "same-origin",
            false,
        );
        let response = app
            .clone()
            .oneshot(invalid_business)
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(dispatches.load(Ordering::SeqCst), 0);

        let response = app
            .oneshot(request(
                valid_body,
                Some("application/x-www-form-urlencoded"),
                "http://127.0.0.1:8080",
                "same-origin",
                false,
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(dispatches.load(Ordering::SeqCst), 1);
        assert_eq!(
            *repository.observations.lock().expect("touch observations"),
            [100, 100]
        );
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table covers the complete RBAC native-form rejection matrix"
    )]
    async fn exact_rbac_forms_preserve_origin_double_submit_and_typed_business_parsing() {
        let clock = Arc::new(MutableClock::new(100));
        let (state, repository, csrf) = middleware_fixture(clock);
        let dispatches = Arc::new(AtomicU64::new(0));
        let observed_dispatches = Arc::clone(&dispatches);
        let path =
            "/settings/access/roles/cccccccc-cccc-4ccc-8ccc-cccccccccccc/permissions/runs:read";
        let app = Router::new()
            .route(
                path,
                post(
                    move |Extension(submission): Extension<RbacManagementFormSubmission>| {
                        let dispatches = Arc::clone(&observed_dispatches);
                        async move {
                            let RbacManagementFormSubmission::Valid(
                                VerifiedRbacManagementForm::SetRolePermission {
                                    role_id,
                                    permission,
                                    expected_authorization_revision,
                                    expected_revision,
                                    present,
                                },
                            ) = submission
                            else {
                                return StatusCode::BAD_REQUEST;
                            };
                            assert_eq!(role_id.to_string(), "cccccccc-cccc-4ccc-8ccc-cccccccccccc");
                            assert_eq!(permission.as_str(), "runs:read");
                            assert_eq!(expected_authorization_revision.value(), 1);
                            assert_eq!(expected_revision.value(), 7);
                            assert!(present);
                            dispatches.fetch_add(1, Ordering::SeqCst);
                            StatusCode::NO_CONTENT
                        }
                    },
                ),
            )
            .layer(middleware::from_fn_with_state(
                state,
                authenticate_human_request,
            ));

        let valid_body = format!(
            "csrf_token={csrf}&expected_authorization_revision=1&expected_revision=7&operation=add"
        );
        let request = |body: String,
                       content_type: Option<&str>,
                       origin: &str,
                       fetch_site: &str,
                       add_header: bool| {
            let mut builder = Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(
                    axum::http::header::COOKIE,
                    format!("automata-dev-session={SESSION}; automata-dev-csrf={csrf}"),
                )
                .header("origin", origin)
                .header("sec-fetch-site", fetch_site);
            if let Some(content_type) = content_type {
                builder = builder.header(CONTENT_TYPE, content_type);
            }
            if add_header {
                builder = builder.header("x-automata-csrf-token", &csrf);
            }
            builder.body(Body::from(body)).expect("RBAC form request")
        };

        for (invalid, expected) in [
            (
                request(
                    valid_body.clone(),
                    Some("application/x-www-form-urlencoded"),
                    "http://127.0.0.1:8080",
                    "same-origin",
                    true,
                ),
                StatusCode::FORBIDDEN,
            ),
            (
                request(
                    valid_body.clone(),
                    Some("application/x-www-form-urlencoded; charset=utf-8"),
                    "http://127.0.0.1:8080",
                    "same-origin",
                    false,
                ),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                request(
                    format!("{valid_body}&csrf_token={csrf}"),
                    Some("application/x-www-form-urlencoded"),
                    "http://127.0.0.1:8080",
                    "same-origin",
                    false,
                ),
                StatusCode::FORBIDDEN,
            ),
            (
                request(
                    valid_body.clone(),
                    Some("application/x-www-form-urlencoded"),
                    "http://attacker.example",
                    "same-origin",
                    false,
                ),
                StatusCode::FORBIDDEN,
            ),
            (
                request(
                    "x".repeat(MAX_RBAC_MANAGEMENT_FORM_BYTES + 1),
                    Some("application/x-www-form-urlencoded"),
                    "http://127.0.0.1:8080",
                    "same-origin",
                    false,
                ),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
        ] {
            let response = app.clone().oneshot(invalid).await.expect("response");
            assert_eq!(response.status(), expected);
        }
        assert_eq!(dispatches.load(Ordering::SeqCst), 0);
        assert!(
            repository
                .observations
                .lock()
                .expect("touch observations")
                .is_empty()
        );

        let malformed = app
            .clone()
            .oneshot(request(
                format!("{valid_body}&secret=must-not-be-reflected"),
                Some("application/x-www-form-urlencoded"),
                "http://127.0.0.1:8080",
                "same-origin",
                false,
            ))
            .await
            .expect("malformed response");
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(malformed.into_body(), 1_024)
            .await
            .expect("bounded error body");
        assert!(
            !body
                .windows(b"must-not-be-reflected".len())
                .any(|window| { window == b"must-not-be-reflected" })
        );

        let response = app
            .oneshot(request(
                valid_body,
                Some("application/x-www-form-urlencoded"),
                "http://127.0.0.1:8080",
                "same-origin",
                false,
            ))
            .await
            .expect("valid response");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(dispatches.load(Ordering::SeqCst), 1);
        assert_eq!(
            *repository.observations.lock().expect("touch observations"),
            [100, 100]
        );
    }

    #[tokio::test]
    async fn direct_grant_expiry_uses_the_authenticated_request_observation() {
        let clock = Arc::new(MutableClock::new(100));
        let (state, repository, csrf) = middleware_fixture(Arc::clone(&clock));
        let observed_expiries = Arc::new(Mutex::new(Vec::new()));
        let handler_expiries = Arc::clone(&observed_expiries);
        let path = "/settings/access/direct-bindings";
        let app = Router::new()
            .route(
                path,
                post(
                    move |Extension(submission): Extension<RbacManagementFormSubmission>| {
                        let observed_expiries = Arc::clone(&handler_expiries);
                        async move {
                            let RbacManagementFormSubmission::Valid(
                                VerifiedRbacManagementForm::GrantRole { valid_until, .. },
                            ) = submission
                            else {
                                return StatusCode::BAD_REQUEST;
                            };
                            observed_expiries
                                .lock()
                                .expect("observed expiries")
                                .push(valid_until.map(UnixTimestamp::as_seconds));
                            StatusCode::NO_CONTENT
                        }
                    },
                ),
            )
            .layer(middleware::from_fn_with_state(
                state,
                authenticate_human_request,
            ));
        let request = |valid_until: &str| {
            let body = format!(
                "csrf_token={csrf}&expected_authorization_revision=1&principal_id=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa&role_id=bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb&scope=tenant&valid_until={valid_until}"
            );
            Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(
                    axum::http::header::COOKIE,
                    format!("automata-dev-session={SESSION}; automata-dev-csrf={csrf}"),
                )
                .header("origin", "http://127.0.0.1:8080")
                .header("sec-fetch-site", "same-origin")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("direct-grant request")
        };

        let future = app
            .clone()
            .oneshot(request("1970-01-01T00%3A02"))
            .await
            .expect("future-expiry response");
        assert_eq!(future.status(), StatusCode::NO_CONTENT);

        clock.set(120);
        let current = app
            .clone()
            .oneshot(request("1970-01-01T00%3A02"))
            .await
            .expect("current-expiry response");
        assert_eq!(current.status(), StatusCode::BAD_REQUEST);
        let blank = app.oneshot(request("")).await.expect("no-expiry response");
        assert_eq!(blank.status(), StatusCode::NO_CONTENT);

        assert_eq!(
            *observed_expiries.lock().expect("observed expiries"),
            [Some(120), None]
        );
        assert_eq!(
            *repository.observations.lock().expect("touch observations"),
            [100, 120, 120]
        );
    }
}
