//! Non-cacheable HTTP boundary for operational GitHub human sign-in.
//!
//! The handlers in this module never receive provider access or refresh tokens.
//! OAuth state, callback codes, login bindings, device poll proofs, and Automata
//! credentials cross only their explicit HTTP boundary and are never formatted or
//! logged here.

use std::{
    fmt,
    future::Future,
    io,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use automata_ci_auth::{
    github::{
        GithubBrowserBindingCookie, GithubDeviceLoginPollOutcome, GithubDevicePollCredential,
        GithubLoginError, GithubLoginService, GithubWebCallback, GithubWebCallbackPurpose,
    },
    human::TenantId,
    login::LoginReturnPath,
    request_auth::AuthenticatedRequestSnapshot,
    secret::{CsrfToken, SecretString},
    session::{ActivateCliSessionOutcome, RevokeOwnSessionOutcome, SessionKind},
    session_credential::{
        SessionCredential, SessionCredentialService, SessionCredentialServiceError,
    },
    time::{Clock, UnixTimestamp},
};
use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::{Request, State},
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, CONTENT_TYPE, LOCATION, ORIGIN, SET_COOKIE, WWW_AUTHENTICATE},
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures::StreamExt as _;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use url::{Position, Url};
use zeroize::Zeroizing;

use super::{
    form,
    human_auth::{
        HumanAuthOrigin, PresentedHumanCredential, clear_login_cookie, csrf_set_cookie,
        extract_human_credential, extract_login_binding_cookie, login_set_cookie,
        session_set_cookie,
    },
    web::error_page_response,
};
use crate::server::installation_setup::{
    InstallationDevicePollOutcome, InstallationSetupError, InstallationSetupService,
};

pub(crate) const GITHUB_WEB_BEGIN_PATH: &str = "/auth/github/login";
pub(crate) const GITHUB_WEB_CALLBACK_PATH: &str = "/auth/github/callback";
pub(crate) const GITHUB_WEB_LOGOUT_PATH: &str = "/auth/logout";
pub(crate) const GITHUB_DEVICE_BEGIN_PATH: &str = "/api/v1/auth/device";
pub(crate) const GITHUB_DEVICE_POLL_PATH: &str = "/api/v1/auth/device/poll";
pub(crate) const CLI_SESSION_PATH: &str = "/api/v1/session";
pub(crate) const GITHUB_SETUP_WEB_BEGIN_PATH: &str = "/setup/auth/github";
pub(crate) const GITHUB_SETUP_DEVICE_BEGIN_PATH: &str = "/api/v1/setup/device";
pub(crate) const GITHUB_SETUP_DEVICE_POLL_PATH: &str = "/api/v1/setup/device/poll";

const MAX_JSON_REQUEST_BYTES: usize = 4 * 1_024;
const MAX_LOGIN_FORM_BYTES: usize = 8 * 1_024;
const MAX_SETUP_BOOTSTRAP_TOKEN_BYTES: usize = 4 * 1_024;
const MAX_SETUP_RETURN_PATH_BYTES: usize = 2 * 1_024;
const MAX_SETUP_FORM_BYTES: usize = b"bootstrap_token=".len()
    + (3 * MAX_SETUP_BOOTSTRAP_TOKEN_BYTES)
    + b"&return_path=".len()
    + (3 * MAX_SETUP_RETURN_PATH_BYTES);
pub(crate) const MAX_BROWSER_LOGOUT_FORM_BYTES: usize = 64;
const MAX_CALLBACK_QUERY_BYTES: usize = 8 * 1_024;
const MAX_CALLBACK_CODE_BYTES: usize = 4 * 1_024;
const MAX_CALLBACK_ERROR_BYTES: usize = 128;
const MAX_CALLBACK_DESCRIPTION_BYTES: usize = 1_024;
const MAX_CALLBACK_ERROR_URI_BYTES: usize = 2 * 1_024;
const OAUTH_STATE_BYTES: usize = 43;
const MAX_CONCURRENT_GITHUB_BEGINS: usize = 8;
const GITHUB_BEGIN_BURST: u64 = 20;
const GITHUB_BEGIN_REFILL_INTERVAL: Duration = Duration::from_secs(1);

const SEC_FETCH_SITE: HeaderName = HeaderName::from_static("sec-fetch-site");
const RETRY_AFTER: HeaderName = HeaderName::from_static("retry-after");
const REFERRER_POLICY: HeaderName = HeaderName::from_static("referrer-policy");
const X_CONTENT_TYPE_OPTIONS: HeaderName = HeaderName::from_static("x-content-type-options");

trait MonotonicClock: fmt::Debug + Send + Sync {
    fn elapsed(&self) -> Duration;
}

#[derive(Debug)]
struct ProcessMonotonicClock(Instant);

impl ProcessMonotonicClock {
    fn new() -> Self {
        Self(Instant::now())
    }
}

impl MonotonicClock for ProcessMonotonicClock {
    fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }
}

#[derive(Debug)]
struct GithubBeginBucket {
    tokens: u64,
    last_refill: Duration,
}

/// Per-replica overload protection for provider-backed anonymous starts.
///
/// This gate deliberately has no client-identity or address dimension and is
/// not a distributed quota. Durable provider and setup services remain the
/// authority for identity-, proof-, and provider-specific rate decisions.
struct GithubBeginAdmission {
    in_flight: Arc<Semaphore>,
    bucket: Mutex<GithubBeginBucket>,
    clock: Arc<dyn MonotonicClock>,
}

impl GithubBeginAdmission {
    fn new(clock: Arc<dyn MonotonicClock>) -> Self {
        let now = clock.elapsed();
        Self {
            in_flight: Arc::new(Semaphore::new(MAX_CONCURRENT_GITHUB_BEGINS)),
            bucket: Mutex::new(GithubBeginBucket {
                tokens: GITHUB_BEGIN_BURST,
                last_refill: now,
            }),
            clock,
        }
    }

    fn try_acquire(&self) -> Result<GithubBeginPermit, GithubBeginRejection> {
        let in_flight = Arc::clone(&self.in_flight)
            .try_acquire_owned()
            .map_err(|_| GithubBeginRejection::Concurrency)?;
        let now = self.clock.elapsed();
        let mut bucket = self
            .bucket
            .try_lock()
            .map_err(|_| GithubBeginRejection::Rate { retry_after: 1 })?;
        refill_github_begin_bucket(&mut bucket, now);
        if bucket.tokens == 0 {
            return Err(GithubBeginRejection::Rate {
                retry_after: github_begin_retry_after(&bucket, now),
            });
        }
        bucket.tokens -= 1;
        drop(bucket);
        Ok(GithubBeginPermit {
            _in_flight: in_flight,
        })
    }
}

impl fmt::Debug for GithubBeginAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubBeginAdmission")
            .field("maximum_in_flight", &MAX_CONCURRENT_GITHUB_BEGINS)
            .field("burst", &GITHUB_BEGIN_BURST)
            .field("refill_interval", &GITHUB_BEGIN_REFILL_INTERVAL)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct GithubBeginPermit {
    _in_flight: OwnedSemaphorePermit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GithubBeginRejection {
    Concurrency,
    Rate { retry_after: u64 },
}

impl GithubBeginRejection {
    const fn retry_after(self) -> u64 {
        match self {
            Self::Concurrency => 1,
            Self::Rate { retry_after } => retry_after,
        }
    }
}

fn refill_github_begin_bucket(bucket: &mut GithubBeginBucket, now: Duration) {
    let elapsed = now.saturating_sub(bucket.last_refill);
    let refills = elapsed.as_secs();
    if refills == 0 {
        return;
    }
    bucket.tokens = bucket
        .tokens
        .saturating_add(refills)
        .min(GITHUB_BEGIN_BURST);
    bucket.last_refill = now.saturating_sub(Duration::new(0, elapsed.subsec_nanos()));
}

fn github_begin_retry_after(bucket: &GithubBeginBucket, now: Duration) -> u64 {
    let elapsed = now.saturating_sub(bucket.last_refill);
    let remaining = GITHUB_BEGIN_REFILL_INTERVAL.saturating_sub(elapsed);
    remaining
        .as_secs()
        .saturating_add(u64::from(remaining.subsec_nanos() != 0))
        .max(1)
}

fn process_github_begin_admission() -> Arc<GithubBeginAdmission> {
    static ADMISSION: OnceLock<Arc<GithubBeginAdmission>> = OnceLock::new();
    Arc::clone(ADMISSION.get_or_init(|| {
        Arc::new(GithubBeginAdmission::new(Arc::new(
            ProcessMonotonicClock::new(),
        )))
    }))
}

/// Trusted HTTPS origin for provider-owned authorization and verification URLs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GithubProviderOrigin(String);

impl GithubProviderOrigin {
    /// Pins redirects to the origin of one configured provider endpoint.
    pub(crate) fn new(endpoint: &Url) -> Result<Self, GithubProviderOriginError> {
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
        {
            return Err(GithubProviderOriginError);
        }
        Ok(Self(endpoint.origin().ascii_serialization()))
    }

    fn trusts(&self, target: &Url) -> bool {
        target.scheme() == "https"
            && target.host_str().is_some()
            && target.username().is_empty()
            && target.password().is_none()
            && target.fragment().is_none()
            && target.origin().ascii_serialization() == self.0
    }
}

/// Invalid provider-origin configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GithubProviderOriginError;

impl fmt::Display for GithubProviderOriginError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GitHub provider origin must be HTTPS without credentials")
    }
}

impl std::error::Error for GithubProviderOriginError {}

/// The operational coordinator paired with the session-key service needed to
/// derive the browser double-submit CSRF value.
#[derive(Clone)]
pub(crate) struct OperationalGithubAuthBackend {
    login: Arc<GithubLoginService>,
    sessions: Arc<SessionCredentialService>,
    setup: Option<Arc<InstallationSetupService>>,
}

impl OperationalGithubAuthBackend {
    pub(crate) const fn new(
        login: Arc<GithubLoginService>,
        sessions: Arc<SessionCredentialService>,
        setup: Option<Arc<InstallationSetupService>>,
    ) -> Self {
        Self {
            login,
            sessions,
            setup,
        }
    }
}

impl fmt::Debug for OperationalGithubAuthBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationalGithubAuthBackend")
            .field("login", &self.login)
            .field("sessions", &self.sessions)
            .field("setup", &self.setup.as_ref().map(|_| "configured"))
            .finish()
    }
}

struct WebLoginStart {
    authorization_url: Url,
    binding: SecretString,
    expires_at: UnixTimestamp,
}

impl fmt::Debug for WebLoginStart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebLoginStart")
            .field("authorization_origin", &self.authorization_url.origin())
            .field("authorization_path", &self.authorization_url.path())
            .field("authorization_query", &"[REDACTED]")
            .field("binding", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

struct DeviceLoginStart {
    poll_credential: SecretString,
    user_code: SecretString,
    verification_uri: Url,
    expires_at: UnixTimestamp,
    poll_interval: Duration,
}

impl fmt::Debug for DeviceLoginStart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceLoginStart")
            .field("poll_credential", &"[REDACTED]")
            .field("user_code", &"[REDACTED]")
            .field("verification_origin", &self.verification_uri.origin())
            .field("verification_path", &self.verification_uri.path())
            .field("verification_query", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("poll_interval", &self.poll_interval)
            .finish()
    }
}

struct WebLoginCompletion {
    credential: SessionCredential,
    csrf: CsrfToken,
    expires_at: UnixTimestamp,
    return_path: Option<LoginReturnPath>,
}

impl fmt::Debug for WebLoginCompletion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebLoginCompletion")
            .field("credential", &"[REDACTED]")
            .field("csrf", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("return_path", &self.return_path)
            .finish()
    }
}

#[derive(Debug)]
enum WebCallbackCompletion {
    SignIn(WebLoginCompletion),
    InstallationSetup(WebLoginCompletion),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WebCallbackError {
    SignIn(GithubLoginError),
    InstallationSetup(InstallationSetupError),
}

struct DeviceLoginCompletion {
    credential: SessionCredential,
    expires_at: UnixTimestamp,
    return_path: Option<LoginReturnPath>,
}

impl fmt::Debug for DeviceLoginCompletion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceLoginCompletion")
            .field("credential", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("return_path", &self.return_path)
            .finish()
    }
}

/// Exact authenticated browser credential admitted by the logout CSRF boundary.
///
/// The credential is non-cloneable; Axum shares it with the handler behind an
/// `Arc`, and its debug representation never exposes the bearer.
pub(crate) struct BrowserLogoutCredential(SessionCredential);

impl BrowserLogoutCredential {
    pub(crate) const fn new(credential: SessionCredential) -> Self {
        Self(credential)
    }

    fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for BrowserLogoutCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BrowserLogoutCredential([REDACTED])")
    }
}

/// Response-only evidence consumed by the outer human-auth middleware.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BrowserLogoutCompleted;

/// Exact authenticated CLI credential admitted only to the session-delete route.
///
/// The request middleware moves the parsed bearer into this redacted wrapper
/// after authentication and inserts it only for `DELETE /api/v1/session`.
pub(crate) struct CliSessionCredential(SessionCredential);

impl CliSessionCredential {
    pub(crate) const fn new(credential: SessionCredential) -> Self {
        Self(credential)
    }

    fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for CliSessionCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CliSessionCredential([REDACTED])")
    }
}

#[derive(Debug)]
enum DevicePollOutcome {
    Pending { next_poll_at: UnixTimestamp },
    SlowDown { next_poll_at: UnixTimestamp },
    Complete(DeviceLoginCompletion),
    Denied,
    Expired,
}

/// Testable application seam around the operational coordinator. Every secret
/// output remains a non-serializable redacted value until a response is built.
#[async_trait]
trait GithubAuthBackend: fmt::Debug + Send + Sync {
    async fn revoke_browser(
        &self,
        raw_credential: &str,
    ) -> Result<RevokeOwnSessionOutcome, SessionCredentialServiceError>;

    async fn revoke_cli(
        &self,
        raw_credential: &str,
    ) -> Result<RevokeOwnSessionOutcome, SessionCredentialServiceError>;

    async fn activate_cli(
        &self,
        raw_credential: &str,
    ) -> Result<ActivateCliSessionOutcome, SessionCredentialServiceError>;

    async fn begin_web(
        &self,
        tenant_id: TenantId,
        return_path: LoginReturnPath,
    ) -> Result<WebLoginStart, GithubLoginError>;

    async fn complete_web(
        &self,
        tenant_id: TenantId,
        binding: GithubBrowserBindingCookie,
        callback: GithubWebCallback,
    ) -> Result<WebCallbackCompletion, WebCallbackError>;

    async fn begin_device(
        &self,
        tenant_id: TenantId,
        return_path: Option<LoginReturnPath>,
    ) -> Result<DeviceLoginStart, GithubLoginError>;

    async fn poll_device(
        &self,
        tenant_id: TenantId,
        credential: GithubDevicePollCredential,
    ) -> Result<DevicePollOutcome, GithubLoginError>;
}

#[async_trait]
impl GithubAuthBackend for OperationalGithubAuthBackend {
    async fn revoke_browser(
        &self,
        raw_credential: &str,
    ) -> Result<RevokeOwnSessionOutcome, SessionCredentialServiceError> {
        self.sessions
            .revoke_raw(raw_credential, SessionKind::Browser)
            .await
    }

    async fn revoke_cli(
        &self,
        raw_credential: &str,
    ) -> Result<RevokeOwnSessionOutcome, SessionCredentialServiceError> {
        self.sessions
            .revoke_raw(raw_credential, SessionKind::Cli)
            .await
    }

    async fn activate_cli(
        &self,
        raw_credential: &str,
    ) -> Result<ActivateCliSessionOutcome, SessionCredentialServiceError> {
        self.sessions.activate_cli_raw(raw_credential).await
    }

    async fn begin_web(
        &self,
        tenant_id: TenantId,
        return_path: LoginReturnPath,
    ) -> Result<WebLoginStart, GithubLoginError> {
        let started = self.login.begin_web(tenant_id, return_path).await?;
        let (authorization_url, binding, expires_at) = started.into_parts();
        let binding = SecretString::new(binding.expose_secret().to_owned())
            .map_err(|_| GithubLoginError::IntegrityFailure)?;
        Ok(WebLoginStart {
            authorization_url,
            binding,
            expires_at,
        })
    }

    async fn complete_web(
        &self,
        tenant_id: TenantId,
        binding: GithubBrowserBindingCookie,
        callback: GithubWebCallback,
    ) -> Result<WebCallbackCompletion, WebCallbackError> {
        let purpose = self
            .login
            .classify_web_callback_purpose(&tenant_id, &binding, &callback)
            .await
            .map_err(WebCallbackError::SignIn)?;
        match purpose {
            GithubWebCallbackPurpose::SignIn => {
                let completion = self
                    .login
                    .complete_web(tenant_id.clone(), binding, &callback)
                    .await
                    .map_err(WebCallbackError::SignIn)?;
                if completion.session().identity().kind() != SessionKind::Browser
                    || completion.session().identity().tenant_id() != &tenant_id
                {
                    return Err(WebCallbackError::SignIn(GithubLoginError::IntegrityFailure));
                }
                let csrf = self
                    .sessions
                    .derive_csrf_raw(
                        completion.credential().expose_secret(),
                        SessionKind::Browser,
                    )
                    .map_err(|_| WebCallbackError::SignIn(GithubLoginError::IntegrityFailure))?;
                let (credential, _, session, _, return_path) = completion.into_parts();
                Ok(WebCallbackCompletion::SignIn(WebLoginCompletion {
                    credential,
                    csrf,
                    expires_at: session.expires_at(),
                    return_path,
                }))
            }
            GithubWebCallbackPurpose::InstallationSetup => {
                let setup = self
                    .setup
                    .as_ref()
                    .ok_or(WebCallbackError::InstallationSetup(
                        InstallationSetupError::AlreadyConfigured,
                    ))?;
                let completion = setup
                    .complete_web(binding, &callback)
                    .await
                    .map_err(WebCallbackError::InstallationSetup)?;
                let (credential, _, session, return_path) = completion.into_parts();
                if session.identity().kind() != SessionKind::Browser
                    || session.identity().tenant_id() != &tenant_id
                {
                    return Err(WebCallbackError::InstallationSetup(
                        InstallationSetupError::IntegrityFailure,
                    ));
                }
                let csrf = self
                    .sessions
                    .derive_csrf_raw(credential.expose_secret(), SessionKind::Browser)
                    .map_err(|_| {
                        WebCallbackError::InstallationSetup(
                            InstallationSetupError::IntegrityFailure,
                        )
                    })?;
                Ok(WebCallbackCompletion::InstallationSetup(
                    WebLoginCompletion {
                        credential,
                        csrf,
                        expires_at: session.expires_at(),
                        return_path,
                    },
                ))
            }
        }
    }

    async fn begin_device(
        &self,
        tenant_id: TenantId,
        return_path: Option<LoginReturnPath>,
    ) -> Result<DeviceLoginStart, GithubLoginError> {
        let started = self.login.begin_device(tenant_id, return_path).await?;
        let poll_credential =
            SecretString::new(started.poll_credential().expose_secret().to_owned())
                .map_err(|_| GithubLoginError::IntegrityFailure)?;
        let user_code = SecretString::new(started.user_code().to_owned())
            .map_err(|_| GithubLoginError::IntegrityFailure)?;
        Ok(DeviceLoginStart {
            poll_credential,
            user_code,
            verification_uri: started.verification_uri().clone(),
            expires_at: started.expires_at(),
            poll_interval: started.poll_interval(),
        })
    }

    async fn poll_device(
        &self,
        tenant_id: TenantId,
        credential: GithubDevicePollCredential,
    ) -> Result<DevicePollOutcome, GithubLoginError> {
        match self
            .login
            .poll_device(tenant_id.clone(), credential)
            .await?
        {
            GithubDeviceLoginPollOutcome::Pending { next_poll_at } => {
                Ok(DevicePollOutcome::Pending { next_poll_at })
            }
            GithubDeviceLoginPollOutcome::SlowDown { next_poll_at } => {
                Ok(DevicePollOutcome::SlowDown { next_poll_at })
            }
            GithubDeviceLoginPollOutcome::Complete(completion) => {
                if completion.session().identity().kind() != SessionKind::Cli
                    || completion.session().identity().tenant_id() != &tenant_id
                {
                    return Err(GithubLoginError::IntegrityFailure);
                }
                let (credential, _, session, _, return_path) = completion.into_parts();
                Ok(DevicePollOutcome::Complete(DeviceLoginCompletion {
                    credential,
                    expires_at: session.expires_at(),
                    return_path,
                }))
            }
            GithubDeviceLoginPollOutcome::Denied => Ok(DevicePollOutcome::Denied),
            GithubDeviceLoginPollOutcome::Expired => Ok(DevicePollOutcome::Expired),
        }
    }
}

/// Cloneable dependencies for one tenant-specific GitHub auth router.
#[derive(Clone)]
pub(crate) struct GithubAuthHttpState {
    backend: Arc<dyn GithubAuthBackend>,
    begin_admission: Arc<GithubBeginAdmission>,
    tenant_id: TenantId,
    application_origin: HumanAuthOrigin,
    provider_origin: GithubProviderOrigin,
    default_return_path: LoginReturnPath,
    clock: Arc<dyn Clock>,
}

impl GithubAuthHttpState {
    /// The clock must be the same logical clock supplied to the coordinator.
    pub(crate) fn new(
        backend: Arc<OperationalGithubAuthBackend>,
        tenant_id: TenantId,
        application_origin: HumanAuthOrigin,
        provider_origin: GithubProviderOrigin,
        default_return_path: LoginReturnPath,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self::from_backend_and_admission(
            backend,
            process_github_begin_admission(),
            tenant_id,
            application_origin,
            provider_origin,
            default_return_path,
            clock,
        )
    }

    #[cfg(test)]
    fn from_backend(
        backend: Arc<dyn GithubAuthBackend>,
        tenant_id: TenantId,
        application_origin: HumanAuthOrigin,
        provider_origin: GithubProviderOrigin,
        default_return_path: LoginReturnPath,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self::from_backend_and_admission(
            backend,
            Arc::new(GithubBeginAdmission::new(Arc::new(
                ProcessMonotonicClock::new(),
            ))),
            tenant_id,
            application_origin,
            provider_origin,
            default_return_path,
            clock,
        )
    }

    fn from_backend_and_admission(
        backend: Arc<dyn GithubAuthBackend>,
        begin_admission: Arc<GithubBeginAdmission>,
        tenant_id: TenantId,
        application_origin: HumanAuthOrigin,
        provider_origin: GithubProviderOrigin,
        default_return_path: LoginReturnPath,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            backend,
            begin_admission,
            tenant_id,
            application_origin,
            provider_origin,
            default_return_path,
            clock,
        }
    }
}

impl fmt::Debug for GithubAuthHttpState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubAuthHttpState")
            .field("backend", &self.backend)
            .field("begin_admission", &self.begin_admission)
            .field("tenant_id", &self.tenant_id)
            .field("application_origin", &self.application_origin)
            .field("provider_origin", &self.provider_origin)
            .field("default_return_path", &self.default_return_path)
            .field("clock", &self.clock)
            .finish()
    }
}

/// Cloneable dependencies for the one-use installation setup routes.
#[derive(Clone)]
pub(crate) struct GithubSetupHttpState {
    service: Arc<InstallationSetupService>,
    begin_admission: Arc<GithubBeginAdmission>,
    application_origin: HumanAuthOrigin,
    provider_origin: GithubProviderOrigin,
    default_return_path: LoginReturnPath,
    clock: Arc<dyn Clock>,
}

impl GithubSetupHttpState {
    pub(crate) fn new(
        service: Arc<InstallationSetupService>,
        application_origin: HumanAuthOrigin,
        provider_origin: GithubProviderOrigin,
        default_return_path: LoginReturnPath,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            service,
            begin_admission: process_github_begin_admission(),
            application_origin,
            provider_origin,
            default_return_path,
            clock,
        }
    }
}

impl fmt::Debug for GithubSetupHttpState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubSetupHttpState")
            .field("service", &self.service)
            .field("begin_admission", &self.begin_admission)
            .field("application_origin", &self.application_origin)
            .field("provider_origin", &self.provider_origin)
            .field("default_return_path", &self.default_return_path)
            .field("clock", &self.clock)
            .finish()
    }
}

/// Builds isolated browser/device sign-in and current-session lifecycle routes.
pub(crate) fn router(state: GithubAuthHttpState) -> Router {
    Router::new()
        .route(GITHUB_WEB_BEGIN_PATH, post(begin_web))
        .route(
            GITHUB_WEB_CALLBACK_PATH,
            get(complete_web).head(reject_callback_head),
        )
        .route(GITHUB_WEB_LOGOUT_PATH, post(logout_browser))
        .route(GITHUB_DEVICE_BEGIN_PATH, post(begin_device))
        .route(GITHUB_DEVICE_POLL_PATH, post(poll_device))
        .route(
            CLI_SESSION_PATH,
            get(cli_session)
                .post(activate_cli_session)
                .delete(logout_cli),
        )
        .with_state(state)
        .layer(middleware::from_fn(harden_auth_response))
}

#[derive(Serialize)]
struct CliSessionDocument<'a> {
    authenticated: bool,
    tenant_id: &'a str,
    principal_id: &'a str,
    provider_id: &'a str,
    provider_subject: &'a str,
    provider_login: &'a str,
    display_name: &'a str,
    session_id: &'a str,
    kind: &'static str,
    authorization_revision: u64,
    issued_at: u64,
    expires_at: u64,
}

async fn cli_session(
    axum::extract::Extension(snapshot): axum::extract::Extension<AuthenticatedRequestSnapshot>,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    request: Request,
) -> Response {
    if original_uri.query().is_some() {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request");
    }
    if require_empty_request(request).await.is_err() {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let session = snapshot.session();
    let identity = session.identity();
    if identity.kind() != SessionKind::Cli {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
    }
    json_response(
        StatusCode::OK,
        &CliSessionDocument {
            authenticated: true,
            tenant_id: identity.tenant_id().as_str(),
            principal_id: identity.principal_id().as_str(),
            provider_id: identity.provider_id().as_str(),
            provider_subject: identity.provider_subject().as_str(),
            provider_login: snapshot.human().login(),
            display_name: snapshot.viewer().display_name(),
            session_id: identity.session_id().as_str(),
            kind: "cli",
            authorization_revision: session.authorization_revision(),
            issued_at: session.issued_at().as_seconds(),
            expires_at: session.expires_at().as_seconds(),
        },
    )
}

async fn activate_cli_session(
    State(state): State<GithubAuthHttpState>,
    request: Request,
) -> Response {
    if request.uri().query().is_some() || request.headers().contains_key(CONTENT_TYPE) {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let (parts, body) = request.into_parts();
    let presented =
        match extract_human_credential(&parts.headers, state.application_origin.cookie_mode()) {
            Ok(Some(PresentedHumanCredential::Cli(credential))) => credential,
            Ok(None | Some(PresentedHumanCredential::Browser(_))) | Err(_) => {
                return cli_unauthorized_response();
            }
        };
    // Drop the ordinary HeaderMap bearer copy before the body read or durable
    // activation await. The typed credential is redacted and zeroizing.
    drop(parts);
    let body = match to_bytes(body, 1).await {
        Ok(body) if body.is_empty() => body,
        Ok(_) | Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    drop(body);
    match state.backend.activate_cli(presented.expose_secret()).await {
        Ok(
            ActivateCliSessionOutcome::Activated(_) | ActivateCliSessionOutcome::AlreadyActive(_),
        ) => (StatusCode::NO_CONTENT, Body::empty()).into_response(),
        Ok(
            ActivateCliSessionOutcome::NotFound
            | ActivateCliSessionOutcome::WrongKindOrAudience
            | ActivateCliSessionOutcome::Revoked
            | ActivateCliSessionOutcome::Expired
            | ActivateCliSessionOutcome::NotYetValid
            | ActivateCliSessionOutcome::ActivationExpired
            | ActivateCliSessionOutcome::PrincipalDisabled
            | ActivateCliSessionOutcome::MembershipSuspended
            | ActivateCliSessionOutcome::AuthorizationRevisionChanged { .. },
        )
        | Err(SessionCredentialServiceError::InvalidCredential) => cli_unauthorized_response(),
        Err(SessionCredentialServiceError::RepositoryUnavailable) => {
            let mut response =
                error_response(StatusCode::SERVICE_UNAVAILABLE, "dependency_unavailable");
            set_retry_after(&mut response, 1);
            response
        }
        Err(
            SessionCredentialServiceError::InvalidLifetime
            | SessionCredentialServiceError::LifetimeOverflow
            | SessionCredentialServiceError::RandomnessUnavailable
            | SessionCredentialServiceError::CollisionLimitExceeded
            | SessionCredentialServiceError::InternalFailure,
        ) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
    }
}

fn cli_unauthorized_response() -> Response {
    let mut response = error_response(StatusCode::UNAUTHORIZED, "invalid_session");
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"automata\""),
    );
    response
}

async fn logout_cli(
    State(state): State<GithubAuthHttpState>,
    axum::extract::Extension(credential): axum::extract::Extension<Arc<CliSessionCredential>>,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    request: Request,
) -> Response {
    if original_uri.query().is_some() {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request");
    }
    if require_empty_request(request).await.is_err() {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request");
    }
    match state.backend.revoke_cli(credential.expose_secret()).await {
        Ok(
            RevokeOwnSessionOutcome::Revoked
            | RevokeOwnSessionOutcome::AlreadyRevoked
            | RevokeOwnSessionOutcome::NotFound,
        ) => (StatusCode::NO_CONTENT, Body::empty()).into_response(),
        Err(SessionCredentialServiceError::RepositoryUnavailable) => {
            let mut response =
                error_response(StatusCode::SERVICE_UNAVAILABLE, "dependency_unavailable");
            set_retry_after(&mut response, 1);
            response
        }
        Err(
            SessionCredentialServiceError::InvalidCredential
            | SessionCredentialServiceError::InvalidLifetime
            | SessionCredentialServiceError::LifetimeOverflow
            | SessionCredentialServiceError::RandomnessUnavailable
            | SessionCredentialServiceError::CollisionLimitExceeded
            | SessionCredentialServiceError::InternalFailure,
        ) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
    }
}

async fn require_empty_request(request: Request) -> Result<(), ()> {
    if request.headers().contains_key(CONTENT_TYPE) {
        return Err(());
    }
    match to_bytes(request.into_body(), 1).await {
        Ok(body) if body.is_empty() => Ok(()),
        Ok(_) | Err(_) => Err(()),
    }
}

async fn logout_browser(
    State(state): State<GithubAuthHttpState>,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    axum::extract::Extension(credential): axum::extract::Extension<Arc<BrowserLogoutCredential>>,
) -> Response {
    if original_uri.query().is_some() {
        return error_page_response(
            StatusCode::BAD_REQUEST,
            "Invalid sign-out request",
            "Return to repositories and try signing out again.",
        );
    }
    match state
        .backend
        .revoke_browser(credential.expose_secret())
        .await
    {
        Ok(
            RevokeOwnSessionOutcome::Revoked
            | RevokeOwnSessionOutcome::AlreadyRevoked
            | RevokeOwnSessionOutcome::NotFound,
        ) => {
            let mut response = redirect_response(StatusCode::SEE_OTHER, "/repositories", &[]);
            response.extensions_mut().insert(BrowserLogoutCompleted);
            response
        }
        Err(SessionCredentialServiceError::RepositoryUnavailable) => {
            let mut response = error_page_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Sign out temporarily unavailable",
                "Your session is still active. Try signing out again in a moment.",
            );
            set_retry_after(&mut response, 1);
            response
        }
        Err(
            SessionCredentialServiceError::InvalidCredential
            | SessionCredentialServiceError::InvalidLifetime
            | SessionCredentialServiceError::LifetimeOverflow
            | SessionCredentialServiceError::RandomnessUnavailable
            | SessionCredentialServiceError::CollisionLimitExceeded
            | SessionCredentialServiceError::InternalFailure,
        ) => error_page_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to sign out",
            "An unexpected error prevented sign-out. Your session is still active.",
        ),
    }
}

pub(crate) fn is_browser_logout_form(method: &axum::http::Method, path: &str) -> bool {
    method == axum::http::Method::POST && path == GITHUB_WEB_LOGOUT_PATH
}

pub(crate) fn is_cli_session_logout(method: &axum::http::Method, path: &str) -> bool {
    method == axum::http::Method::DELETE && path == CLI_SESSION_PATH
}

pub(crate) fn is_cli_session_activation(method: &axum::http::Method, path: &str) -> bool {
    method == axum::http::Method::POST && path == CLI_SESSION_PATH
}

pub(crate) fn browser_logout_csrf_token(body: &[u8]) -> Option<SecretString> {
    if body.is_empty() || body.len() > MAX_BROWSER_LOGOUT_FORM_BYTES {
        return None;
    }
    let mut pairs = body.split(|byte| *byte == b'&');
    let pair = pairs.next()?;
    if pairs.next().is_some() {
        return None;
    }
    let separator = pair.iter().position(|byte| *byte == b'=')?;
    let name = decode_form_component(&pair[..separator]).ok()?;
    let value = decode_form_component(&pair[separator + 1..]).ok()?;
    if name != "csrf_token" {
        return None;
    }
    SecretString::new(value).ok()
}

/// Builds operator-proof-bound installation setup routes.
pub(crate) fn setup_router(state: GithubSetupHttpState) -> Router {
    Router::new()
        .route(GITHUB_SETUP_WEB_BEGIN_PATH, post(begin_setup_web))
        .route(GITHUB_SETUP_DEVICE_BEGIN_PATH, post(begin_setup_device))
        .route(GITHUB_SETUP_DEVICE_POLL_PATH, post(poll_setup_device))
        .with_state(state)
        .layer(middleware::from_fn(harden_auth_response))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginStartDocument {
    return_path: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupLoginStartDocument {
    bootstrap_token: SecretString,
    return_path: Option<String>,
}

async fn begin_setup_web(State(state): State<GithubSetupHttpState>, request: Request) -> Response {
    let service = Arc::clone(&state.service);
    begin_setup_web_request(
        SetupWebRequestContext {
            application_origin: &state.application_origin,
            provider_origin: &state.provider_origin,
            default_return_path: &state.default_return_path,
            clock: state.clock.as_ref(),
            begin_admission: &state.begin_admission,
        },
        request,
        move |bootstrap_token, return_path| async move {
            let started = service
                .begin_web(bootstrap_token.expose_secret(), return_path)
                .await?;
            let (authorization_url, binding_cookie, expires_at) = started.into_parts();
            Ok(SetupWebLoginStart {
                authorization_url,
                binding_cookie,
                expires_at,
            })
        },
    )
    .await
}

struct SetupWebRequestContext<'a> {
    application_origin: &'a HumanAuthOrigin,
    provider_origin: &'a GithubProviderOrigin,
    default_return_path: &'a LoginReturnPath,
    clock: &'a dyn Clock,
    begin_admission: &'a Arc<GithubBeginAdmission>,
}

struct SetupWebLoginStart {
    authorization_url: Url,
    binding_cookie: GithubBrowserBindingCookie,
    expires_at: UnixTimestamp,
}

async fn begin_setup_web_request<Begin, BeginFuture>(
    context: SetupWebRequestContext<'_>,
    request: Request,
    begin: Begin,
) -> Response
where
    Begin: FnOnce(SecretString, LoginReturnPath) -> BeginFuture,
    BeginFuture: Future<Output = Result<SetupWebLoginStart, InstallationSetupError>>,
{
    if !valid_login_initiation(request.headers(), context.application_origin) {
        return error_response(StatusCode::FORBIDDEN, "browser_security_check_failed");
    }
    let document = match parse_setup_login_start_request(request).await {
        Ok(document) => document,
        Err(error) => return request_error_response(error),
    };
    let SetupLoginStartDocument {
        bootstrap_token,
        return_path: requested_return_path,
    } = document;
    let Ok(return_path) = parse_return_path(
        requested_return_path.as_deref(),
        context.default_return_path,
        context.application_origin,
    ) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request");
    };
    drop(requested_return_path);
    let _begin_permit = match context.begin_admission.try_acquire() {
        Ok(permit) => permit,
        Err(rejection) => return browser_begin_overload_response(rejection),
    };
    match begin(bootstrap_token, return_path).await {
        Ok(started) => setup_web_start_response(&context, &started),
        Err(error) => setup_error_response(error, context.clock.now()),
    }
}

fn setup_web_start_response(
    context: &SetupWebRequestContext<'_>,
    started: &SetupWebLoginStart,
) -> Response {
    if !context.provider_origin.trusts(&started.authorization_url) {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
    }
    let Some(lifetime) = remaining_lifetime(started.expires_at, context.clock.now()) else {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
    };
    let cookie = match login_set_cookie(
        context.application_origin.cookie_mode(),
        started.binding_cookie.expose_secret(),
        lifetime,
    ) {
        Ok(cookie) => cookie.into_header_value(),
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
    };
    redirect_response(
        StatusCode::SEE_OTHER,
        started.authorization_url.as_str(),
        &[cookie],
    )
}

async fn begin_web(State(state): State<GithubAuthHttpState>, request: Request) -> Response {
    if !valid_login_initiation(request.headers(), &state.application_origin) {
        return error_response(StatusCode::FORBIDDEN, "browser_security_check_failed");
    }
    let document = match parse_login_start_request(request).await {
        Ok(document) => document,
        Err(error) => return request_error_response(error),
    };
    let Ok(return_path) = parse_return_path(
        document.return_path.as_deref(),
        &state.default_return_path,
        &state.application_origin,
    ) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let _begin_permit = match state.begin_admission.try_acquire() {
        Ok(permit) => permit,
        Err(rejection) => return browser_begin_overload_response(rejection),
    };
    match state
        .backend
        .begin_web(state.tenant_id.clone(), return_path)
        .await
    {
        Ok(start) => web_start_response(&state, &start),
        Err(error) => login_error_response(error, state.clock.now()),
    }
}

async fn parse_setup_login_start_request(
    request: Request,
) -> Result<SetupLoginStartDocument, RequestDocumentError> {
    if request.uri().query().is_some() {
        return Err(RequestDocumentError::Invalid);
    }
    if has_json_content_type(request.headers()) {
        return parse_json_request(request).await;
    }
    if !has_form_content_type(request.headers()) {
        return Err(RequestDocumentError::UnsupportedMediaType);
    }
    let body = collect_setup_form_body(request.into_body()).await?;
    parse_setup_login_start_form(&body)
}

async fn collect_setup_form_body(body: Body) -> Result<Zeroizing<Vec<u8>>, RequestDocumentError> {
    const CAPACITY: usize = MAX_SETUP_FORM_BYTES + 1;

    let mut stream = body.into_data_stream();
    let mut body = Zeroizing::new(Vec::with_capacity(CAPACITY));
    let initial_capacity = body.capacity();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| RequestDocumentError::Invalid)?;
        let available = CAPACITY.saturating_sub(body.len());
        let copied = chunk.len().min(available);
        body.extend_from_slice(&chunk[..copied]);
        let chunk_exceeded_capacity = copied != chunk.len();
        wipe_body_chunk(chunk);
        debug_assert_eq!(body.capacity(), initial_capacity);
        if chunk_exceeded_capacity || body.len() > MAX_SETUP_FORM_BYTES {
            return Err(RequestDocumentError::TooLarge);
        }
    }
    Ok(body)
}

fn parse_setup_login_start_form(
    body: &[u8],
) -> Result<SetupLoginStartDocument, RequestDocumentError> {
    if body.is_empty() {
        return Err(RequestDocumentError::Invalid);
    }
    let mut bootstrap_token = None;
    let mut return_path = None;
    for pair in body.split(|byte| *byte == b'&') {
        let separator = pair
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or(RequestDocumentError::Invalid)?;
        let (name, encoded_value) = (&pair[..separator], &pair[separator + 1..]);
        match name {
            b"bootstrap_token" if bootstrap_token.is_none() => {
                bootstrap_token = Some(decode_bootstrap_token(encoded_value)?);
            }
            b"return_path" if return_path.is_none() => {
                let path =
                    decode_bounded_form_component(encoded_value, MAX_SETUP_RETURN_PATH_BYTES)?;
                if path.is_empty() {
                    return Err(RequestDocumentError::Invalid);
                }
                return_path = Some(path);
            }
            _ => {
                return Err(RequestDocumentError::Invalid);
            }
        }
    }
    Ok(SetupLoginStartDocument {
        bootstrap_token: bootstrap_token.ok_or(RequestDocumentError::Invalid)?,
        return_path: Some(return_path.ok_or(RequestDocumentError::Invalid)?),
    })
}

fn decode_bootstrap_token(value: &[u8]) -> Result<SecretString, RequestDocumentError> {
    let mut decoded = Zeroizing::new(Vec::with_capacity(
        value.len().min(MAX_SETUP_BOOTSTRAP_TOKEN_BYTES),
    ));
    form::decode_into(value, &mut decoded, MAX_SETUP_BOOTSTRAP_TOKEN_BYTES)
        .map_err(|_| RequestDocumentError::Invalid)?;
    if decoded.is_empty() {
        return Err(RequestDocumentError::Invalid);
    }
    let decoded = match String::from_utf8(std::mem::take(&mut *decoded)) {
        Ok(decoded) => decoded,
        Err(error) => {
            let mut invalid = error.into_bytes();
            invalid.fill(0);
            return Err(RequestDocumentError::Invalid);
        }
    };
    SecretString::new(decoded).map_err(|_| RequestDocumentError::Invalid)
}

fn decode_bounded_form_component(
    value: &[u8],
    maximum: usize,
) -> Result<String, RequestDocumentError> {
    let mut decoded = Vec::with_capacity(value.len().min(maximum));
    form::decode_into(value, &mut decoded, maximum).map_err(|_| RequestDocumentError::Invalid)?;
    String::from_utf8(decoded).map_err(|_| RequestDocumentError::Invalid)
}

async fn parse_login_start_request(
    request: Request,
) -> Result<LoginStartDocument, RequestDocumentError> {
    if request.uri().query().is_some() {
        return Err(RequestDocumentError::Invalid);
    }
    if has_json_content_type(request.headers()) {
        return parse_json_request(request).await;
    }
    if !has_form_content_type(request.headers()) {
        return Err(RequestDocumentError::UnsupportedMediaType);
    }
    let body = to_bytes(request.into_body(), MAX_LOGIN_FORM_BYTES)
        .await
        .map_err(|_| RequestDocumentError::TooLarge)?;
    if body.is_empty() {
        return Err(RequestDocumentError::Invalid);
    }
    let mut pairs = body.split(|byte| *byte == b'&');
    let pair = pairs.next().ok_or(RequestDocumentError::Invalid)?;
    if pairs.next().is_some() {
        return Err(RequestDocumentError::Invalid);
    }
    let separator = pair
        .iter()
        .position(|byte| *byte == b'=')
        .ok_or(RequestDocumentError::Invalid)?;
    let name = decode_form_component(&pair[..separator])?;
    let return_path = decode_form_component(&pair[separator + 1..])?;
    if name != "return_path" || return_path.is_empty() {
        return Err(RequestDocumentError::Invalid);
    }
    Ok(LoginStartDocument {
        return_path: Some(return_path),
    })
}

fn decode_form_component(value: &[u8]) -> Result<String, RequestDocumentError> {
    form::decode_text(value, value.len()).map_err(|_| RequestDocumentError::Invalid)
}

fn web_start_response(state: &GithubAuthHttpState, start: &WebLoginStart) -> Response {
    if !state.provider_origin.trusts(&start.authorization_url) {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
    }
    let Some(lifetime) = remaining_lifetime(start.expires_at, state.clock.now()) else {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
    };
    let Ok(cookie) = login_set_cookie(
        state.application_origin.cookie_mode(),
        start.binding.expose_secret(),
        lifetime,
    ) else {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
    };
    redirect_response(
        StatusCode::SEE_OTHER,
        start.authorization_url.as_str(),
        &[cookie.into_header_value()],
    )
}

async fn complete_web(State(state): State<GithubAuthHttpState>, request: Request) -> Response {
    let clear = match clear_login_cookie(state.application_origin.cookie_mode()) {
        Ok(cookie) => cookie.into_header_value(),
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
    };
    let mut response = complete_web_inner(&state, request).await;
    response.headers_mut().append(SET_COOKIE, clear);
    response
}

async fn reject_callback_head() -> Response {
    let mut response = StatusCode::METHOD_NOT_ALLOWED.into_response();
    response
        .headers_mut()
        .insert(axum::http::header::ALLOW, HeaderValue::from_static("GET"));
    apply_auth_security_headers(&mut response);
    response
}

async fn complete_web_inner(state: &GithubAuthHttpState, request: Request) -> Response {
    let Ok(callback) = parse_web_callback(request.uri().query()) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_callback");
    };
    let binding = match extract_login_binding_cookie(
        request.headers(),
        state.application_origin.cookie_mode(),
    ) {
        Ok(Some(binding)) => {
            let binding = Zeroizing::new(binding);
            match GithubBrowserBindingCookie::from_raw(binding.as_str()) {
                Ok(binding) => binding,
                Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid_callback"),
            }
        }
        Ok(None) | Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid_callback"),
    };
    drop(request);
    match state
        .backend
        .complete_web(state.tenant_id.clone(), binding, callback)
        .await
    {
        Ok(
            WebCallbackCompletion::SignIn(completion)
            | WebCallbackCompletion::InstallationSetup(completion),
        ) => web_completion_response(state, &completion),
        Err(WebCallbackError::SignIn(error)) => login_error_response(error, state.clock.now()),
        Err(WebCallbackError::InstallationSetup(error)) => {
            setup_error_response(error, state.clock.now())
        }
    }
}

fn web_completion_response(
    state: &GithubAuthHttpState,
    completion: &WebLoginCompletion,
) -> Response {
    let Some(lifetime) = remaining_lifetime(completion.expires_at, state.clock.now()) else {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
    };
    let session = match session_set_cookie(
        state.application_origin.cookie_mode(),
        &completion.credential,
        lifetime,
    ) {
        Ok(cookie) => cookie.into_header_value(),
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
    };
    let csrf = match csrf_set_cookie(
        state.application_origin.cookie_mode(),
        &completion.csrf,
        lifetime,
    ) {
        Ok(cookie) => cookie.into_header_value(),
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
    };
    let location = completion
        .return_path
        .as_ref()
        .unwrap_or(&state.default_return_path)
        .as_str();
    let Some(location) = canonical_local_return_path(&state.application_origin, location) else {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
    };
    redirect_response(StatusCode::SEE_OTHER, location.as_str(), &[session, csrf])
}

async fn begin_device(State(state): State<GithubAuthHttpState>, request: Request) -> Response {
    let document = match parse_json_request::<LoginStartDocument>(request).await {
        Ok(document) => document,
        Err(error) => return request_error_response(error),
    };
    let return_path = match document.return_path {
        Some(path) => match canonical_local_return_path(&state.application_origin, &path) {
            Some(path) => Some(path),
            None => return error_response(StatusCode::BAD_REQUEST, "invalid_request"),
        },
        None => None,
    };
    let _begin_permit = match state.begin_admission.try_acquire() {
        Ok(permit) => permit,
        Err(rejection) => return device_begin_overload_response(rejection),
    };
    match state
        .backend
        .begin_device(state.tenant_id.clone(), return_path)
        .await
    {
        Ok(start) => device_start_response(&state, &start),
        Err(error) => login_error_response(error, state.clock.now()),
    }
}

async fn begin_setup_device(
    State(state): State<GithubSetupHttpState>,
    request: Request,
) -> Response {
    let service = Arc::clone(&state.service);
    begin_setup_device_request(
        SetupDeviceRequestContext {
            application_origin: &state.application_origin,
            provider_origin: &state.provider_origin,
            clock: state.clock.as_ref(),
            begin_admission: &state.begin_admission,
        },
        request,
        move |bootstrap_token, return_path| async move {
            service
                .begin_device(bootstrap_token.expose_secret(), return_path)
                .await
        },
    )
    .await
}

struct SetupDeviceRequestContext<'a> {
    application_origin: &'a HumanAuthOrigin,
    provider_origin: &'a GithubProviderOrigin,
    clock: &'a dyn Clock,
    begin_admission: &'a Arc<GithubBeginAdmission>,
}

async fn begin_setup_device_request<Begin, BeginFuture>(
    context: SetupDeviceRequestContext<'_>,
    request: Request,
    begin: Begin,
) -> Response
where
    Begin: FnOnce(SecretString, Option<LoginReturnPath>) -> BeginFuture,
    BeginFuture: Future<
        Output = Result<automata_ci_auth::github::GithubDeviceLoginStart, InstallationSetupError>,
    >,
{
    let document = match parse_json_request::<SetupLoginStartDocument>(request).await {
        Ok(document) => document,
        Err(error) => return request_error_response(error),
    };
    let return_path = match document.return_path {
        Some(path) => match canonical_local_return_path(context.application_origin, &path) {
            Some(path) => Some(path),
            None => return error_response(StatusCode::BAD_REQUEST, "invalid_request"),
        },
        None => None,
    };
    let _begin_permit = match context.begin_admission.try_acquire() {
        Ok(permit) => permit,
        Err(rejection) => return device_begin_overload_response(rejection),
    };
    match begin(document.bootstrap_token, return_path).await {
        Ok(started) => setup_device_start_response(&context, &started),
        Err(error) => setup_error_response(error, context.clock.now()),
    }
}

fn setup_device_start_response(
    context: &SetupDeviceRequestContext<'_>,
    started: &automata_ci_auth::github::GithubDeviceLoginStart,
) -> Response {
    if !context.provider_origin.trusts(started.verification_uri())
        || started.poll_interval().is_zero()
        || started.poll_interval().subsec_nanos() != 0
        || started.expires_at() <= context.clock.now()
    {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
    }
    let Some(expires_in_seconds) = started
        .expires_at()
        .as_seconds()
        .checked_sub(context.clock.now().as_seconds())
        .filter(|seconds| *seconds > 0)
    else {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
    };
    json_response(
        StatusCode::OK,
        &DeviceStartDocument {
            poll_credential: started.poll_credential().expose_secret(),
            user_code: started.user_code(),
            verification_uri: started.verification_uri().as_str(),
            expires_at: started.expires_at().as_seconds(),
            expires_in_seconds,
            poll_interval_seconds: started.poll_interval().as_secs(),
        },
    )
}

#[derive(Serialize)]
struct DeviceStartDocument<'a> {
    poll_credential: &'a str,
    user_code: &'a str,
    verification_uri: &'a str,
    expires_at: u64,
    expires_in_seconds: u64,
    poll_interval_seconds: u64,
}

fn device_start_response(state: &GithubAuthHttpState, start: &DeviceLoginStart) -> Response {
    if !state.provider_origin.trusts(&start.verification_uri)
        || start.poll_interval.is_zero()
        || start.poll_interval.subsec_nanos() != 0
        || start.expires_at <= state.clock.now()
    {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
    }
    let Some(expires_in_seconds) = start
        .expires_at
        .as_seconds()
        .checked_sub(state.clock.now().as_seconds())
        .filter(|seconds| *seconds > 0)
    else {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
    };
    json_response(
        StatusCode::OK,
        &DeviceStartDocument {
            poll_credential: start.poll_credential.expose_secret(),
            user_code: start.user_code.expose_secret(),
            verification_uri: start.verification_uri.as_str(),
            expires_at: start.expires_at.as_seconds(),
            expires_in_seconds,
            poll_interval_seconds: start.poll_interval.as_secs(),
        },
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DevicePollRequest {
    poll_credential: SecretString,
}

async fn poll_device(State(state): State<GithubAuthHttpState>, request: Request) -> Response {
    let document = match parse_json_request::<DevicePollRequest>(request).await {
        Ok(document) => document,
        Err(error) => return request_error_response(error),
    };
    let Ok(credential) =
        GithubDevicePollCredential::from_raw(document.poll_credential.expose_secret())
    else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request");
    };
    drop(document);
    match state
        .backend
        .poll_device(state.tenant_id.clone(), credential)
        .await
    {
        Ok(outcome) => device_poll_response(&state, outcome, state.clock.now()),
        Err(error) => {
            if matches!(
                error,
                GithubLoginError::ProviderUnavailable
                    | GithubLoginError::StorageUnavailable
                    | GithubLoginError::RandomnessUnavailable
                    | GithubLoginError::CollisionLimitExceeded
                    | GithubLoginError::IntegrityFailure
            ) {
                tracing::warn!(
                    error = ?error,
                    "GitHub device authorization poll failed"
                );
            }
            login_error_response(error, state.clock.now())
        }
    }
}

async fn poll_setup_device(
    State(state): State<GithubSetupHttpState>,
    request: Request,
) -> Response {
    let document = match parse_json_request::<DevicePollRequest>(request).await {
        Ok(document) => document,
        Err(error) => return request_error_response(error),
    };
    let Ok(credential) =
        GithubDevicePollCredential::from_raw(document.poll_credential.expose_secret())
    else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request");
    };
    drop(document);
    match state.service.poll_device(credential).await {
        Ok(outcome) => setup_device_poll_response(&state, outcome, state.clock.now()),
        Err(error) => {
            tracing::warn!(
                error = ?error,
                "installation setup device authorization poll failed"
            );
            setup_error_response(error, state.clock.now())
        }
    }
}

#[derive(Serialize)]
struct DevicePollDocument<'a> {
    status: &'static str,
    next_poll_at: Option<u64>,
    credential: Option<&'a str>,
    expires_at: Option<u64>,
    return_path: Option<&'a str>,
}

fn device_poll_response(
    state: &GithubAuthHttpState,
    outcome: DevicePollOutcome,
    now: UnixTimestamp,
) -> Response {
    match outcome {
        DevicePollOutcome::Pending { next_poll_at } => {
            let mut response = json_response(
                StatusCode::ACCEPTED,
                &DevicePollDocument {
                    status: "pending",
                    next_poll_at: Some(next_poll_at.as_seconds()),
                    credential: None,
                    expires_at: None,
                    return_path: None,
                },
            );
            set_retry_after(&mut response, retry_seconds(next_poll_at, now));
            response
        }
        DevicePollOutcome::SlowDown { next_poll_at } => {
            let mut response = json_response(
                StatusCode::ACCEPTED,
                &DevicePollDocument {
                    status: "slow_down",
                    next_poll_at: Some(next_poll_at.as_seconds()),
                    credential: None,
                    expires_at: None,
                    return_path: None,
                },
            );
            set_retry_after(&mut response, retry_seconds(next_poll_at, now));
            response
        }
        DevicePollOutcome::Complete(completion)
            if completion.expires_at > now
                && completion.return_path.as_ref().is_none_or(|path| {
                    trusted_local_return_path(&state.application_origin, path.as_str())
                }) =>
        {
            json_response(
                StatusCode::OK,
                &DevicePollDocument {
                    status: "complete",
                    next_poll_at: None,
                    credential: Some(completion.credential.expose_secret()),
                    expires_at: Some(completion.expires_at.as_seconds()),
                    return_path: completion.return_path.as_ref().map(LoginReturnPath::as_str),
                },
            )
        }
        DevicePollOutcome::Complete(_) => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
        }
        DevicePollOutcome::Denied => error_response(StatusCode::FORBIDDEN, "authorization_denied"),
        DevicePollOutcome::Expired => error_response(StatusCode::GONE, "authorization_expired"),
    }
}

fn setup_device_poll_response(
    state: &GithubSetupHttpState,
    outcome: InstallationDevicePollOutcome,
    now: UnixTimestamp,
) -> Response {
    match outcome {
        InstallationDevicePollOutcome::Pending { next_poll_at } => {
            let mut response = json_response(
                StatusCode::ACCEPTED,
                &DevicePollDocument {
                    status: "pending",
                    next_poll_at: Some(next_poll_at.as_seconds()),
                    credential: None,
                    expires_at: None,
                    return_path: None,
                },
            );
            set_retry_after(&mut response, retry_seconds(next_poll_at, now));
            response
        }
        InstallationDevicePollOutcome::SlowDown { next_poll_at } => {
            let mut response = json_response(
                StatusCode::ACCEPTED,
                &DevicePollDocument {
                    status: "slow_down",
                    next_poll_at: Some(next_poll_at.as_seconds()),
                    credential: None,
                    expires_at: None,
                    return_path: None,
                },
            );
            set_retry_after(&mut response, retry_seconds(next_poll_at, now));
            response
        }
        InstallationDevicePollOutcome::Complete(completion) => {
            let (credential, _, session, return_path) = completion.into_parts();
            if session.identity().kind() != SessionKind::Cli
                || session.expires_at() <= now
                || return_path.as_ref().is_some_and(|path| {
                    !trusted_local_return_path(&state.application_origin, path.as_str())
                })
            {
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
            }
            json_response(
                StatusCode::OK,
                &DevicePollDocument {
                    status: "complete",
                    next_poll_at: None,
                    credential: Some(credential.expose_secret()),
                    expires_at: Some(session.expires_at().as_seconds()),
                    return_path: return_path.as_ref().map(LoginReturnPath::as_str),
                },
            )
        }
        InstallationDevicePollOutcome::Denied => {
            error_response(StatusCode::FORBIDDEN, "authorization_denied")
        }
        InstallationDevicePollOutcome::Expired => {
            error_response(StatusCode::GONE, "authorization_expired")
        }
    }
}

fn parse_return_path(
    requested: Option<&str>,
    default: &LoginReturnPath,
    origin: &HumanAuthOrigin,
) -> Result<LoginReturnPath, ()> {
    let path = requested.unwrap_or(default.as_str());
    canonical_local_return_path(origin, path).ok_or(())
}

fn trusted_local_return_path(origin: &HumanAuthOrigin, path: &str) -> bool {
    canonical_local_return_path(origin, path).is_some()
}

fn canonical_local_return_path(origin: &HumanAuthOrigin, path: &str) -> Option<LoginReturnPath> {
    let path = LoginReturnPath::new(path.to_owned()).ok()?;
    let Ok(base) = Url::parse(&format!("{}/", origin.as_str())) else {
        return None;
    };
    let target = base.join(path.as_str()).ok()?;
    if target.origin().ascii_serialization() != origin.as_str() {
        return None;
    }
    LoginReturnPath::new(target[Position::BeforePath..].to_owned()).ok()
}

fn valid_login_initiation(headers: &HeaderMap, expected: &HumanAuthOrigin) -> bool {
    let Some(origin) = exactly_one_header(headers, &ORIGIN) else {
        return false;
    };
    if origin != expected.as_str() {
        return false;
    }
    let mut fetch_sites = headers.get_all(&SEC_FETCH_SITE).iter();
    let fetch_site = fetch_sites.next();
    if fetch_sites.next().is_some() {
        return false;
    }
    fetch_site.is_none_or(|site| {
        site.to_str()
            .is_ok_and(|site| !site.eq_ignore_ascii_case("cross-site"))
    })
}

fn exactly_one_header<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestDocumentError {
    UnsupportedMediaType,
    TooLarge,
    Invalid,
}

async fn parse_json_request<T: DeserializeOwned>(
    request: Request,
) -> Result<T, RequestDocumentError> {
    if request.uri().query().is_some() {
        return Err(RequestDocumentError::Invalid);
    }
    if !has_json_content_type(request.headers()) {
        return Err(RequestDocumentError::UnsupportedMediaType);
    }
    let mut stream = request.into_body().into_data_stream();
    let mut body = Zeroizing::new(Vec::with_capacity(MAX_JSON_REQUEST_BYTES));
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| RequestDocumentError::Invalid)?;
        let within_limit = body
            .len()
            .checked_add(chunk.len())
            .is_some_and(|length| length <= MAX_JSON_REQUEST_BYTES);
        if within_limit {
            body.extend_from_slice(&chunk);
        }
        wipe_body_chunk(chunk);
        if !within_limit {
            return Err(RequestDocumentError::TooLarge);
        }
    }
    serde_json::from_slice(&body).map_err(|_| RequestDocumentError::Invalid)
}

fn wipe_body_chunk(chunk: Bytes) {
    if let Ok(mut chunk) = chunk.try_into_mut() {
        chunk.as_mut().fill(0);
    }
}

fn has_json_content_type(headers: &HeaderMap) -> bool {
    has_exact_content_type(headers, "application/json")
}

fn has_form_content_type(headers: &HeaderMap) -> bool {
    has_exact_content_type(headers, "application/x-www-form-urlencoded")
}

fn has_exact_content_type(headers: &HeaderMap, expected_media_type: &str) -> bool {
    let Some(value) = exactly_one_header(headers, &CONTENT_TYPE) else {
        return false;
    };
    let mut parts = value.split(';');
    if !parts
        .next()
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case(expected_media_type))
    {
        return false;
    }
    let Some(parameter) = parts.next() else {
        return true;
    };
    parts.next().is_none()
        && parameter
            .trim()
            .split_once('=')
            .is_some_and(|(name, value)| {
                name.trim().eq_ignore_ascii_case("charset")
                    && value.trim().eq_ignore_ascii_case("utf-8")
            })
}

fn request_error_response(error: RequestDocumentError) -> Response {
    match error {
        RequestDocumentError::UnsupportedMediaType => {
            error_response(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type")
        }
        RequestDocumentError::TooLarge => {
            error_response(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large")
        }
        RequestDocumentError::Invalid => error_response(StatusCode::BAD_REQUEST, "invalid_request"),
    }
}

fn parse_web_callback(query: Option<&str>) -> Result<GithubWebCallback, ()> {
    let query = query.ok_or(())?;
    if query.is_empty()
        || query.len() > MAX_CALLBACK_QUERY_BYTES
        || !query.is_ascii()
        || !valid_percent_encoding(query.as_bytes())
    {
        return Err(());
    }
    let mut code = None;
    let mut state = None;
    let mut error = None;
    let mut description_seen = false;
    let mut error_uri_seen = false;
    for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match name.as_ref() {
            "code" if code.is_none() && valid_callback_code(&value) => {
                code = Some(SecretString::new(value.into_owned()).map_err(|_| ())?);
            }
            "state" if state.is_none() && valid_oauth_state(&value) => {
                state = Some(SecretString::new(value.into_owned()).map_err(|_| ())?);
            }
            "error" if error.is_none() && valid_error_token(&value) => {
                error = Some(value.into_owned());
            }
            "error_description"
                if !description_seen
                    && valid_bounded_text(&value, MAX_CALLBACK_DESCRIPTION_BYTES) =>
            {
                description_seen = true;
            }
            "error_uri"
                if !error_uri_seen && valid_bounded_text(&value, MAX_CALLBACK_ERROR_URI_BYTES) =>
            {
                error_uri_seen = true;
            }
            _ => return Err(()),
        }
    }
    let state = state.ok_or(())?;
    match (code, error) {
        (Some(code), None) if !description_seen && !error_uri_seen => {
            Ok(GithubWebCallback::Authorized { code, state })
        }
        (None, Some(error)) => Ok(GithubWebCallback::Denied { error, state }),
        _ => Err(()),
    }
}

fn valid_percent_encoding(value: &[u8]) -> bool {
    let mut index = 0;
    while index < value.len() {
        if value[index] == b'%' {
            if index + 2 >= value.len()
                || !value[index + 1].is_ascii_hexdigit()
                || !value[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

fn valid_callback_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CALLBACK_CODE_BYTES
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn valid_oauth_state(value: &str) -> bool {
    value.len() == OAUTH_STATE_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_error_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CALLBACK_ERROR_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.is_ascii()
        && !value.chars().any(char::is_control)
}

fn remaining_lifetime(expires_at: UnixTimestamp, now: UnixTimestamp) -> Option<Duration> {
    expires_at
        .as_seconds()
        .checked_sub(now.as_seconds())
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
}

fn retry_seconds(next_poll_at: UnixTimestamp, now: UnixTimestamp) -> u64 {
    next_poll_at
        .as_seconds()
        .saturating_sub(now.as_seconds())
        .max(1)
}

fn login_error_response(error: GithubLoginError, now: UnixTimestamp) -> Response {
    match error {
        GithubLoginError::Invalid => error_response(StatusCode::BAD_REQUEST, "invalid_request"),
        GithubLoginError::Replay => error_response(StatusCode::CONFLICT, "request_replayed"),
        GithubLoginError::Expired => error_response(StatusCode::GONE, "request_expired"),
        GithubLoginError::Denied => error_response(StatusCode::FORBIDDEN, "authorization_denied"),
        GithubLoginError::PollTooEarly { next_poll_at } => {
            let mut response = error_response(StatusCode::TOO_MANY_REQUESTS, "poll_too_early");
            set_retry_after(&mut response, retry_seconds(next_poll_at, now));
            response
        }
        GithubLoginError::RateLimited {
            retry_after_seconds,
        } => {
            let mut response = error_response(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
            if let Some(seconds) = retry_after_seconds {
                set_retry_after(&mut response, seconds.max(1));
            }
            response
        }
        GithubLoginError::ProviderUnavailable
        | GithubLoginError::StorageUnavailable
        | GithubLoginError::RandomnessUnavailable
        | GithubLoginError::CollisionLimitExceeded => {
            let mut response = error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
            set_retry_after(&mut response, 1);
            response
        }
        GithubLoginError::NotAuthorized => error_response(StatusCode::FORBIDDEN, "not_authorized"),
        GithubLoginError::IntegrityFailure => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
        }
    }
}

fn setup_error_response(error: InstallationSetupError, now: UnixTimestamp) -> Response {
    match error {
        InstallationSetupError::InvalidRequest => {
            error_response(StatusCode::BAD_REQUEST, "invalid_request")
        }
        InstallationSetupError::InvalidProof => {
            error_response(StatusCode::FORBIDDEN, "setup_proof_rejected")
        }
        InstallationSetupError::NotArmed => error_response(StatusCode::CONFLICT, "setup_not_armed"),
        InstallationSetupError::StateConflict | InstallationSetupError::Replay => {
            error_response(StatusCode::CONFLICT, "request_replayed")
        }
        InstallationSetupError::Expired => error_response(StatusCode::GONE, "request_expired"),
        InstallationSetupError::Denied => {
            error_response(StatusCode::FORBIDDEN, "authorization_denied")
        }
        InstallationSetupError::PollTooEarly { next_poll_at } => {
            let mut response = error_response(StatusCode::TOO_MANY_REQUESTS, "poll_too_early");
            set_retry_after(&mut response, retry_seconds(next_poll_at, now));
            response
        }
        InstallationSetupError::RateLimited {
            retry_after_seconds,
        } => {
            let mut response = error_response(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
            if let Some(seconds) = retry_after_seconds {
                set_retry_after(&mut response, seconds.max(1));
            }
            response
        }
        InstallationSetupError::ProviderUnavailable
        | InstallationSetupError::StorageUnavailable
        | InstallationSetupError::RandomnessUnavailable
        | InstallationSetupError::CollisionLimitExceeded => {
            let mut response = error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
            set_retry_after(&mut response, 1);
            response
        }
        InstallationSetupError::NotAuthorized => {
            error_response(StatusCode::FORBIDDEN, "not_authorized")
        }
        InstallationSetupError::AlreadyConfigured => {
            error_response(StatusCode::GONE, "setup_complete")
        }
        InstallationSetupError::IntegrityFailure => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
        }
    }
}

fn browser_begin_overload_response(rejection: GithubBeginRejection) -> Response {
    let mut response = error_page_response(
        StatusCode::TOO_MANY_REQUESTS,
        "Sign-in temporarily busy",
        "Too many sign-in requests are starting. Wait a moment and try again.",
    );
    set_retry_after(&mut response, rejection.retry_after());
    response
}

fn device_begin_overload_response(rejection: GithubBeginRejection) -> Response {
    let mut response = error_response(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    set_retry_after(&mut response, rejection.retry_after());
    response
}

#[derive(Serialize)]
struct ErrorDocument {
    error: &'static str,
}

fn error_response(status: StatusCode, code: &'static str) -> Response {
    json_response(status, &ErrorDocument { error: code })
}

fn json_response<T: Serialize>(status: StatusCode, document: &T) -> Response {
    let mut body = BoundedJsonBuffer::new();
    match serde_json::to_writer(&mut body, document) {
        Ok(()) => response(
            status,
            "application/json; charset=utf-8",
            Body::from(Bytes::from_owner(body.into_inner())),
        ),
        Err(_) => response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "application/json; charset=utf-8",
            Body::from(r#"{"error":"internal_error"}"#),
        ),
    }
}

struct BoundedJsonBuffer {
    bytes: Zeroizing<Vec<u8>>,
}

impl BoundedJsonBuffer {
    fn new() -> Self {
        Self {
            bytes: Zeroizing::new(Vec::with_capacity(MAX_JSON_REQUEST_BYTES)),
        }
    }

    fn into_inner(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}

impl io::Write for BoundedJsonBuffer {
    fn write(&mut self, source: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .len()
            .checked_add(source.len())
            .filter(|length| *length <= MAX_JSON_REQUEST_BYTES)
            .ok_or_else(|| io::Error::other("authentication response exceeded its limit"))?;
        debug_assert!(next <= self.bytes.capacity());
        self.bytes.extend_from_slice(source);
        Ok(source.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn redirect_response(status: StatusCode, location: &str, set_cookies: &[HeaderValue]) -> Response {
    let Ok(mut location) = HeaderValue::from_str(location) else {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
    };
    location.set_sensitive(true);
    let mut response = response(status, "text/plain; charset=utf-8", Body::empty());
    response.headers_mut().insert(LOCATION, location);
    for cookie in set_cookies {
        response.headers_mut().append(SET_COOKIE, cookie.clone());
    }
    response
}

fn response(status: StatusCode, content_type: &'static str, body: Body) -> Response {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    apply_auth_security_headers(&mut response);
    response
}

async fn harden_auth_response(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    apply_auth_security_headers(&mut response);
    response
}

fn apply_auth_security_headers(response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
}

fn set_retry_after(response: &mut Response, seconds: u64) {
    if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
        response.headers_mut().insert(RETRY_AFTER, value);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        convert::Infallible,
        sync::{
            Mutex,
            atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        },
        task::Poll,
    };

    use automata_ci_auth::{
        authorization::AuthorizationContext,
        human::{AuthenticatedHuman, PrincipalId, ProviderId, ProviderSubject},
        request_auth::{AuthenticatedRequestSnapshot, ViewerDisplayMetadata},
        secret::SecretString,
        session::{DurableSession, DurableSessionIdentity, SessionId},
        time::{Clock, UnixTimestamp},
    };
    use axum::{
        Extension,
        body::{Body, to_bytes},
        http::{Request, header::COOKIE},
    };
    use tokio::sync::Notify;
    use tower::ServiceExt as _;

    use super::*;

    const NOW: u64 = 10_000;
    const STATE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const BINDING: &str = "bw1~key-1~11111111-1111-4111-8111-111111111111~AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
    const POLL: &str = "dp1~key-1~22222222-2222-4222-8222-222222222222~AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI";
    const SESSION: &str = "v1~key-1~AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const CSRF: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
    const BOOTSTRAP_SENTINEL: &str = "setup-bootstrap-sentinel-0123456789abcdef";

    #[derive(Debug)]
    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> UnixTimestamp {
            UnixTimestamp::from_seconds(NOW)
        }
    }

    #[derive(Debug)]
    struct MutableMonotonicClock(AtomicU64);

    impl MutableMonotonicClock {
        fn new(milliseconds: u64) -> Self {
            Self(AtomicU64::new(milliseconds))
        }

        fn set_milliseconds(&self, milliseconds: u64) {
            self.0.store(milliseconds, Ordering::SeqCst);
        }
    }

    impl MonotonicClock for MutableMonotonicClock {
        fn elapsed(&self) -> Duration {
            Duration::from_millis(self.0.load(Ordering::SeqCst))
        }
    }

    #[derive(Debug)]
    struct BeginBlocker {
        entered: AtomicUsize,
        changed: Notify,
        release: Semaphore,
    }

    impl BeginBlocker {
        fn new() -> Self {
            Self {
                entered: AtomicUsize::new(0),
                changed: Notify::new(),
                release: Semaphore::new(0),
            }
        }

        async fn enter(&self) {
            self.entered.fetch_add(1, Ordering::SeqCst);
            self.changed.notify_waiters();
            self.release
                .acquire()
                .await
                .expect("begin blocker remains open")
                .forget();
        }

        async fn wait_for_entries(&self, expected: usize) {
            tokio::time::timeout(Duration::from_secs(1), async {
                while self.entered.load(Ordering::SeqCst) != expected {
                    self.changed.notified().await;
                }
            })
            .await
            .expect("backend begin entries");
        }
    }

    struct FakeBackend {
        browser_revoke:
            Mutex<Option<Result<RevokeOwnSessionOutcome, SessionCredentialServiceError>>>,
        cli_revoke: Mutex<Option<Result<RevokeOwnSessionOutcome, SessionCredentialServiceError>>>,
        cli_activation:
            Mutex<Option<Result<ActivateCliSessionOutcome, SessionCredentialServiceError>>>,
        revoked_credentials: Mutex<Vec<String>>,
        activated_credentials: Mutex<Vec<String>>,
        web_start: Mutex<Option<Result<WebLoginStart, GithubLoginError>>>,
        web_return_paths: Mutex<Vec<LoginReturnPath>>,
        web_begin_blocker: Mutex<Option<Arc<BeginBlocker>>>,
        web_completion: Mutex<Option<Result<WebCallbackCompletion, WebCallbackError>>>,
        device_start: Mutex<Option<Result<DeviceLoginStart, GithubLoginError>>>,
        device_begin_calls: AtomicUsize,
        device_poll: Mutex<Option<Result<DevicePollOutcome, GithubLoginError>>>,
    }

    impl fmt::Debug for FakeBackend {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("FakeBackend([REDACTED])")
        }
    }

    impl FakeBackend {
        fn empty() -> Self {
            Self {
                browser_revoke: Mutex::new(None),
                cli_revoke: Mutex::new(None),
                cli_activation: Mutex::new(None),
                revoked_credentials: Mutex::new(Vec::new()),
                activated_credentials: Mutex::new(Vec::new()),
                web_start: Mutex::new(None),
                web_return_paths: Mutex::new(Vec::new()),
                web_begin_blocker: Mutex::new(None),
                web_completion: Mutex::new(None),
                device_start: Mutex::new(None),
                device_begin_calls: AtomicUsize::new(0),
                device_poll: Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl GithubAuthBackend for FakeBackend {
        async fn revoke_browser(
            &self,
            raw_credential: &str,
        ) -> Result<RevokeOwnSessionOutcome, SessionCredentialServiceError> {
            self.revoked_credentials
                .lock()
                .unwrap()
                .push(raw_credential.to_owned());
            self.browser_revoke
                .lock()
                .unwrap()
                .take()
                .unwrap_or(Err(SessionCredentialServiceError::InternalFailure))
        }

        async fn revoke_cli(
            &self,
            raw_credential: &str,
        ) -> Result<RevokeOwnSessionOutcome, SessionCredentialServiceError> {
            self.revoked_credentials
                .lock()
                .unwrap()
                .push(raw_credential.to_owned());
            self.cli_revoke
                .lock()
                .unwrap()
                .take()
                .unwrap_or(Err(SessionCredentialServiceError::InternalFailure))
        }

        async fn activate_cli(
            &self,
            raw_credential: &str,
        ) -> Result<ActivateCliSessionOutcome, SessionCredentialServiceError> {
            self.activated_credentials
                .lock()
                .unwrap()
                .push(raw_credential.to_owned());
            self.cli_activation
                .lock()
                .unwrap()
                .take()
                .unwrap_or(Err(SessionCredentialServiceError::InternalFailure))
        }

        async fn begin_web(
            &self,
            _tenant_id: TenantId,
            return_path: LoginReturnPath,
        ) -> Result<WebLoginStart, GithubLoginError> {
            self.web_return_paths.lock().unwrap().push(return_path);
            let blocker = self.web_begin_blocker.lock().unwrap().clone();
            if let Some(blocker) = blocker {
                blocker.enter().await;
            }
            self.web_start
                .lock()
                .unwrap()
                .take()
                .unwrap_or(Err(GithubLoginError::Invalid))
        }

        async fn complete_web(
            &self,
            _tenant_id: TenantId,
            _binding: GithubBrowserBindingCookie,
            _callback: GithubWebCallback,
        ) -> Result<WebCallbackCompletion, WebCallbackError> {
            self.web_completion
                .lock()
                .unwrap()
                .take()
                .unwrap_or(Err(WebCallbackError::SignIn(GithubLoginError::Invalid)))
        }

        async fn begin_device(
            &self,
            _tenant_id: TenantId,
            _return_path: Option<LoginReturnPath>,
        ) -> Result<DeviceLoginStart, GithubLoginError> {
            self.device_begin_calls.fetch_add(1, Ordering::SeqCst);
            self.device_start
                .lock()
                .unwrap()
                .take()
                .unwrap_or(Err(GithubLoginError::Invalid))
        }

        async fn poll_device(
            &self,
            _tenant_id: TenantId,
            _credential: GithubDevicePollCredential,
        ) -> Result<DevicePollOutcome, GithubLoginError> {
            self.device_poll
                .lock()
                .unwrap()
                .take()
                .unwrap_or(Err(GithubLoginError::Invalid))
        }
    }

    fn state(backend: Arc<FakeBackend>) -> GithubAuthHttpState {
        GithubAuthHttpState::from_backend(
            backend,
            TenantId::new("tenant-a").unwrap(),
            HumanAuthOrigin::new(&Url::parse("https://ci.example/").unwrap()).unwrap(),
            GithubProviderOrigin::new(&Url::parse("https://github.example/login").unwrap())
                .unwrap(),
            LoginReturnPath::new("/").unwrap(),
            Arc::new(FixedClock),
        )
    }

    fn state_with_admission(
        backend: Arc<FakeBackend>,
        begin_admission: Arc<GithubBeginAdmission>,
    ) -> GithubAuthHttpState {
        GithubAuthHttpState::from_backend_and_admission(
            backend,
            begin_admission,
            TenantId::new("tenant-a").unwrap(),
            HumanAuthOrigin::new(&Url::parse("https://ci.example/").unwrap()).unwrap(),
            GithubProviderOrigin::new(&Url::parse("https://github.example/login").unwrap())
                .unwrap(),
            LoginReturnPath::new("/").unwrap(),
            Arc::new(FixedClock),
        )
    }

    fn cli_snapshot() -> AuthenticatedRequestSnapshot {
        let tenant = TenantId::new("tenant-a").unwrap();
        let principal = PrincipalId::new("33333333-3333-4333-8333-333333333333").unwrap();
        let provider = ProviderId::new("github").unwrap();
        let subject = ProviderSubject::new("1234567").unwrap();
        let identity = DurableSessionIdentity::new(
            SessionId::new("44444444-4444-4444-8444-444444444444").unwrap(),
            tenant.clone(),
            principal.clone(),
            provider.clone(),
            subject.clone(),
            SessionKind::Cli,
        )
        .unwrap();
        let session = DurableSession::new(
            identity,
            7,
            UnixTimestamp::from_seconds(NOW - 1_000),
            UnixTimestamp::from_seconds(NOW - 10),
            UnixTimestamp::from_seconds(NOW + 1_000),
            UnixTimestamp::from_seconds(NOW + 2_000),
            None,
        )
        .unwrap();
        let human = AuthenticatedHuman::new(
            principal.clone(),
            provider,
            subject,
            "octocat",
            Some("The Octocat".to_owned()),
            UnixTimestamp::from_seconds(NOW - 1_000),
        )
        .unwrap();
        let authorization =
            AuthorizationContext::authenticated_at_revision(tenant, principal, BTreeSet::new(), 7)
                .unwrap();
        AuthenticatedRequestSnapshot::new(
            session,
            human,
            ViewerDisplayMetadata::new("The Octocat").unwrap(),
            authorization,
        )
        .unwrap()
    }

    fn json_post(path: &str, body: impl Into<Body>) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header(CONTENT_TYPE, "application/json")
            .body(body.into())
            .unwrap()
    }

    fn browser_begin_request() -> Request<Body> {
        let mut request = json_post(GITHUB_WEB_BEGIN_PATH, r#"{"return_path":null}"#);
        request
            .headers_mut()
            .insert(ORIGIN, HeaderValue::from_static("https://ci.example"));
        request
            .headers_mut()
            .insert(SEC_FETCH_SITE, HeaderValue::from_static("same-origin"));
        request
    }

    #[derive(Default)]
    struct SetupBeginProbe {
        calls: AtomicUsize,
        device_calls: AtomicUsize,
        received_sentinel: AtomicBool,
        return_paths: Mutex<Vec<LoginReturnPath>>,
    }

    #[derive(Clone)]
    struct SetupBeginHarnessState {
        application_origin: HumanAuthOrigin,
        provider_origin: GithubProviderOrigin,
        default_return_path: LoginReturnPath,
        clock: Arc<dyn Clock>,
        begin_admission: Arc<GithubBeginAdmission>,
        probe: Arc<SetupBeginProbe>,
    }

    async fn setup_begin_harness_handler(
        State(state): State<SetupBeginHarnessState>,
        request: Request<Body>,
    ) -> Response {
        let probe = Arc::clone(&state.probe);
        begin_setup_web_request(
            SetupWebRequestContext {
                application_origin: &state.application_origin,
                provider_origin: &state.provider_origin,
                default_return_path: &state.default_return_path,
                clock: state.clock.as_ref(),
                begin_admission: &state.begin_admission,
            },
            request,
            move |bootstrap_token, return_path| async move {
                probe.calls.fetch_add(1, Ordering::SeqCst);
                probe.received_sentinel.store(
                    bootstrap_token.constant_time_eq(BOOTSTRAP_SENTINEL),
                    Ordering::SeqCst,
                );
                probe.return_paths.lock().unwrap().push(return_path);
                drop(bootstrap_token);
                Ok(SetupWebLoginStart {
                    authorization_url: Url::parse(&format!(
                        "https://github.example/login/oauth?state={STATE}"
                    ))
                    .unwrap(),
                    binding_cookie: GithubBrowserBindingCookie::from_raw(BINDING).unwrap(),
                    expires_at: UnixTimestamp::from_seconds(NOW + 300),
                })
            },
        )
        .await
    }

    async fn setup_device_begin_harness_handler(
        State(state): State<SetupBeginHarnessState>,
        request: Request<Body>,
    ) -> Response {
        let probe = Arc::clone(&state.probe);
        begin_setup_device_request(
            SetupDeviceRequestContext {
                application_origin: &state.application_origin,
                provider_origin: &state.provider_origin,
                clock: state.clock.as_ref(),
                begin_admission: &state.begin_admission,
            },
            request,
            move |bootstrap_token, _return_path| async move {
                probe.device_calls.fetch_add(1, Ordering::SeqCst);
                drop(bootstrap_token);
                Err(InstallationSetupError::InvalidRequest)
            },
        )
        .await
    }

    fn setup_begin_harness() -> (Router, Arc<SetupBeginProbe>) {
        setup_begin_harness_with_admission(Arc::new(GithubBeginAdmission::new(Arc::new(
            ProcessMonotonicClock::new(),
        ))))
    }

    fn setup_begin_harness_with_admission(
        begin_admission: Arc<GithubBeginAdmission>,
    ) -> (Router, Arc<SetupBeginProbe>) {
        let probe = Arc::new(SetupBeginProbe::default());
        let state = SetupBeginHarnessState {
            application_origin: HumanAuthOrigin::new(&Url::parse("https://ci.example/").unwrap())
                .unwrap(),
            provider_origin: GithubProviderOrigin::new(
                &Url::parse("https://github.example/login").unwrap(),
            )
            .unwrap(),
            default_return_path: LoginReturnPath::new("/").unwrap(),
            clock: Arc::new(FixedClock),
            begin_admission,
            probe: Arc::clone(&probe),
        };
        (
            Router::new()
                .route(
                    GITHUB_SETUP_WEB_BEGIN_PATH,
                    post(setup_begin_harness_handler),
                )
                .route(
                    GITHUB_SETUP_DEVICE_BEGIN_PATH,
                    post(setup_device_begin_harness_handler),
                )
                .with_state(state),
            probe,
        )
    }

    fn setup_begin_request(
        uri: &str,
        content_type: &'static str,
        body: impl Into<Body>,
    ) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header(CONTENT_TYPE, content_type)
            .header(ORIGIN, "https://ci.example")
            .header(SEC_FETCH_SITE, "same-origin")
            .body(body.into())
            .unwrap()
    }

    fn logout_app(backend: Arc<FakeBackend>) -> Router {
        let credential = SessionCredential::from_raw(SESSION).expect("browser credential");
        router(state(backend)).layer(Extension(Arc::new(BrowserLogoutCredential::new(
            credential,
        ))))
    }

    #[test]
    fn native_logout_form_is_exact_and_bounded() {
        assert!(is_browser_logout_form(
            &axum::http::Method::POST,
            GITHUB_WEB_LOGOUT_PATH
        ));
        assert!(!is_browser_logout_form(
            &axum::http::Method::GET,
            GITHUB_WEB_LOGOUT_PATH
        ));
        assert!(!is_browser_logout_form(
            &axum::http::Method::POST,
            "/auth/logout/"
        ));

        let body = format!("csrf_token={CSRF}");
        let parsed = browser_logout_csrf_token(body.as_bytes()).expect("valid CSRF field");
        assert_eq!(parsed.expose_secret(), CSRF);
        for invalid in [
            "",
            "csrf_token=",
            "other=value",
            "csrf_token=value&other=value",
            "csrf_token=value&csrf_token=value",
            "csrf_token=%",
            "csrf_token=%FF",
        ] {
            assert!(
                browser_logout_csrf_token(invalid.as_bytes()).is_none(),
                "accepted {invalid:?}"
            );
        }
        assert!(browser_logout_csrf_token(&[b'x'; MAX_BROWSER_LOGOUT_FORM_BYTES + 1]).is_none());
    }

    #[tokio::test]
    async fn browser_logout_revokes_exact_session_and_redirects_idempotently() {
        for outcome in [
            RevokeOwnSessionOutcome::Revoked,
            RevokeOwnSessionOutcome::AlreadyRevoked,
            RevokeOwnSessionOutcome::NotFound,
        ] {
            let backend = Arc::new(FakeBackend::empty());
            *backend.browser_revoke.lock().unwrap() = Some(Ok(outcome));
            let response = logout_app(Arc::clone(&backend))
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(GITHUB_WEB_LOGOUT_PATH)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            assert_eq!(response.headers()[LOCATION], "/repositories");
            assert!(
                response
                    .extensions()
                    .get::<BrowserLogoutCompleted>()
                    .is_some()
            );
            assert!(!response.headers().contains_key(SET_COOKIE));
            assert_eq!(
                *backend.revoked_credentials.lock().unwrap(),
                [SESSION.to_owned()]
            );
        }
    }

    #[tokio::test]
    async fn browser_logout_errors_are_branded_and_do_not_claim_completion() {
        for (error, expected_status, expected_heading) in [
            (
                SessionCredentialServiceError::RepositoryUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "Sign out temporarily unavailable",
            ),
            (
                SessionCredentialServiceError::InternalFailure,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to sign out",
            ),
        ] {
            let backend = Arc::new(FakeBackend::empty());
            *backend.browser_revoke.lock().unwrap() = Some(Err(error));
            let response = logout_app(backend)
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(GITHUB_WEB_LOGOUT_PATH)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), expected_status);
            assert!(
                response
                    .extensions()
                    .get::<BrowserLogoutCompleted>()
                    .is_none()
            );
            assert!(!response.headers().contains_key(SET_COOKIE));
            if expected_status == StatusCode::SERVICE_UNAVAILABLE {
                assert_eq!(response.headers()[RETRY_AFTER], "1");
            }
            let body = to_bytes(response.into_body(), 32 * 1_024).await.unwrap();
            assert!(
                String::from_utf8(body.to_vec())
                    .unwrap()
                    .contains(expected_heading)
            );
        }

        let backend = Arc::new(FakeBackend::empty());
        let response = logout_app(Arc::clone(&backend))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/logout?return_path=%2Fsettings")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(backend.revoked_credentials.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn browser_logout_never_revokes_without_middleware_authority_or_post_method() {
        for method in ["POST", "GET"] {
            let backend = Arc::new(FakeBackend::empty());
            *backend.browser_revoke.lock().unwrap() = Some(Ok(RevokeOwnSessionOutcome::Revoked));
            let response = router(state(Arc::clone(&backend)))
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(GITHUB_WEB_LOGOUT_PATH)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(
                response.status(),
                if method == "POST" {
                    StatusCode::INTERNAL_SERVER_ERROR
                } else {
                    StatusCode::METHOD_NOT_ALLOWED
                }
            );
            assert!(backend.revoked_credentials.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn github_begin_gate_bounds_concurrency_and_refills_one_token_per_second() {
        assert!(Arc::ptr_eq(
            &process_github_begin_admission(),
            &process_github_begin_admission()
        ));

        let clock = Arc::new(MutableMonotonicClock::new(0));
        let admission = Arc::new(GithubBeginAdmission::new(clock.clone()));
        let held = (0..MAX_CONCURRENT_GITHUB_BEGINS)
            .map(|_| admission.try_acquire().expect("initial concurrency slot"))
            .collect::<Vec<_>>();
        assert_eq!(
            admission.try_acquire().unwrap_err(),
            GithubBeginRejection::Concurrency
        );
        drop(held);

        let initially_consumed =
            u64::try_from(MAX_CONCURRENT_GITHUB_BEGINS).expect("concurrency limit fits u64");
        for _ in initially_consumed..GITHUB_BEGIN_BURST {
            drop(admission.try_acquire().expect("remaining burst token"));
        }
        assert_eq!(
            admission.try_acquire().unwrap_err(),
            GithubBeginRejection::Rate { retry_after: 1 }
        );
        clock.set_milliseconds(999);
        assert_eq!(
            admission.try_acquire().unwrap_err(),
            GithubBeginRejection::Rate { retry_after: 1 }
        );
        clock.set_milliseconds(1_000);
        drop(admission.try_acquire().expect("refilled token"));
        assert_eq!(
            admission.try_acquire().unwrap_err(),
            GithubBeginRejection::Rate { retry_after: 1 }
        );
    }

    #[tokio::test]
    async fn browser_begin_rejects_the_ninth_in_flight_call_and_recovers_without_queueing() {
        let backend = Arc::new(FakeBackend::empty());
        let blocker = Arc::new(BeginBlocker::new());
        *backend.web_begin_blocker.lock().unwrap() = Some(Arc::clone(&blocker));
        let admission = Arc::new(GithubBeginAdmission::new(Arc::new(
            MutableMonotonicClock::new(0),
        )));
        let app = router(state_with_admission(
            Arc::clone(&backend),
            Arc::clone(&admission),
        ));

        let mut starts = Vec::new();
        for _ in 0..MAX_CONCURRENT_GITHUB_BEGINS {
            let app = app.clone();
            starts.push(tokio::spawn(async move {
                app.oneshot(browser_begin_request()).await.unwrap()
            }));
        }
        blocker.wait_for_entries(MAX_CONCURRENT_GITHUB_BEGINS).await;

        let overloaded = app.clone().oneshot(browser_begin_request()).await.unwrap();
        assert_eq!(overloaded.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(overloaded.headers()[RETRY_AFTER], "1");
        assert_eq!(overloaded.headers()[CACHE_CONTROL], "no-store");
        assert!(
            overloaded.headers()[CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        let body = to_bytes(overloaded.into_body(), 64 * 1_024).await.unwrap();
        assert!(
            body.windows(b"Sign-in temporarily busy".len())
                .any(|window| window == b"Sign-in temporarily busy")
        );
        assert_eq!(
            backend.web_return_paths.lock().unwrap().len(),
            MAX_CONCURRENT_GITHUB_BEGINS
        );

        blocker.release.add_permits(MAX_CONCURRENT_GITHUB_BEGINS);
        for start in starts {
            assert_eq!(start.await.unwrap().status(), StatusCode::BAD_REQUEST);
        }
        *backend.web_begin_blocker.lock().unwrap() = None;
        let recovered = app.oneshot(browser_begin_request()).await.unwrap();
        assert_eq!(recovered.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            backend.web_return_paths.lock().unwrap().len(),
            MAX_CONCURRENT_GITHUB_BEGINS + 1
        );
    }

    #[tokio::test]
    async fn all_four_begin_routes_reject_after_envelope_checks_and_before_backend_io() {
        let backend = Arc::new(FakeBackend::empty());
        let admission = Arc::new(GithubBeginAdmission::new(Arc::new(
            MutableMonotonicClock::new(0),
        )));
        for _ in 0..GITHUB_BEGIN_BURST {
            drop(admission.try_acquire().expect("burst token"));
        }
        let app = router(state_with_admission(
            Arc::clone(&backend),
            Arc::clone(&admission),
        ));
        let (setup_app, setup_probe) = setup_begin_harness_with_admission(admission);

        let mut invalid_origin = browser_begin_request();
        invalid_origin
            .headers_mut()
            .insert(ORIGIN, HeaderValue::from_static("https://attacker.example"));
        let invalid = app.clone().oneshot(invalid_origin).await.unwrap();
        assert_eq!(invalid.status(), StatusCode::FORBIDDEN);

        let browser_overload = app.clone().oneshot(browser_begin_request()).await.unwrap();
        assert_eq!(browser_overload.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            browser_overload.headers()[CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );

        let device_overload = app
            .oneshot(json_post(
                GITHUB_DEVICE_BEGIN_PATH,
                r#"{"return_path":null}"#,
            ))
            .await
            .unwrap();
        assert_eq!(device_overload.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(device_overload.headers()[RETRY_AFTER], "1");
        assert_eq!(
            device_overload.headers()[CONTENT_TYPE],
            "application/json; charset=utf-8"
        );
        assert_eq!(
            to_bytes(device_overload.into_body(), 128).await.unwrap(),
            r#"{"error":"rate_limited"}"#
        );

        let mut setup_browser_request = json_post(
            GITHUB_SETUP_WEB_BEGIN_PATH,
            format!(r#"{{"bootstrap_token":"{BOOTSTRAP_SENTINEL}","return_path":null}}"#),
        );
        setup_browser_request
            .headers_mut()
            .insert(ORIGIN, HeaderValue::from_static("https://ci.example"));
        setup_browser_request
            .headers_mut()
            .insert(SEC_FETCH_SITE, HeaderValue::from_static("same-origin"));
        let setup_browser_overload = setup_app
            .clone()
            .oneshot(setup_browser_request)
            .await
            .unwrap();
        assert_eq!(
            setup_browser_overload.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert!(
            setup_browser_overload.headers()[CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );

        let setup_device_overload = setup_app
            .oneshot(json_post(
                GITHUB_SETUP_DEVICE_BEGIN_PATH,
                format!(r#"{{"bootstrap_token":"{BOOTSTRAP_SENTINEL}","return_path":null}}"#),
            ))
            .await
            .unwrap();
        assert_eq!(
            setup_device_overload.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(setup_device_overload.headers()[RETRY_AFTER], "1");
        assert_eq!(
            to_bytes(setup_device_overload.into_body(), 128)
                .await
                .unwrap(),
            r#"{"error":"rate_limited"}"#
        );
        assert!(backend.web_return_paths.lock().unwrap().is_empty());
        assert_eq!(backend.device_begin_calls.load(Ordering::SeqCst), 0);
        assert_eq!(setup_probe.calls.load(Ordering::SeqCst), 0);
        assert_eq!(setup_probe.device_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn browser_begin_requires_exact_origin_and_sets_only_bound_trusted_redirect() {
        let backend = Arc::new(FakeBackend::empty());
        *backend.web_start.lock().unwrap() = Some(Ok(WebLoginStart {
            authorization_url: Url::parse(&format!(
                "https://github.example/login/oauth?state={STATE}"
            ))
            .unwrap(),
            binding: SecretString::new(BINDING).unwrap(),
            expires_at: UnixTimestamp::from_seconds(NOW + 300),
        }));
        let app = router(state(backend));
        let mut request = json_post(GITHUB_WEB_BEGIN_PATH, r#"{"return_path":"/repositories"}"#);
        request
            .headers_mut()
            .insert(ORIGIN, HeaderValue::from_static("https://ci.example"));
        request
            .headers_mut()
            .insert(SEC_FETCH_SITE, HeaderValue::from_static("same-origin"));
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            response.headers()[LOCATION],
            format!("https://github.example/login/oauth?state={STATE}")
        );
        assert!(response.headers()[LOCATION].is_sensitive());
        let cookie = response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .next()
            .unwrap();
        assert!(cookie.is_sensitive());
        let cookie = cookie.to_str().unwrap();
        assert!(cookie.contains(BINDING));
        assert!(cookie.contains("Secure; HttpOnly; SameSite=Lax"));
    }

    #[tokio::test]
    async fn browser_begin_accepts_one_native_return_path_and_binds_it_to_login() {
        let backend = Arc::new(FakeBackend::empty());
        *backend.web_start.lock().unwrap() = Some(Ok(WebLoginStart {
            authorization_url: Url::parse(&format!(
                "https://github.example/login/oauth?state={STATE}"
            ))
            .unwrap(),
            binding: SecretString::new(BINDING).unwrap(),
            expires_at: UnixTimestamp::from_seconds(NOW + 300),
        }));
        let app = router(state(Arc::clone(&backend)));
        let request = Request::builder()
            .method("POST")
            .uri(GITHUB_WEB_BEGIN_PATH)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(ORIGIN, "https://ci.example")
            .header(SEC_FETCH_SITE, "same-origin")
            .body(Body::from(
                "return_path=%2Facme%2Fcaf%C3%A9%2Factions%3Fstatus%3Dfailed",
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers()[LOCATION],
            format!("https://github.example/login/oauth?state={STATE}")
        );
        assert_eq!(
            *backend.web_return_paths.lock().unwrap(),
            vec![LoginReturnPath::new("/acme/caf%C3%A9/actions?status=failed").unwrap()]
        );
    }

    #[tokio::test]
    async fn browser_begin_rejects_empty_duplicate_unknown_and_untrusted_native_forms() {
        for body in [
            "",
            "return_path=%2Fruns&return_path=%2Fother",
            "next=%2Fruns",
            "return_path=https%3A%2F%2Fevil.example%2F",
            "return_path=%",
            "return_path=%2F%FF",
        ] {
            let backend = Arc::new(FakeBackend::empty());
            let app = router(state(Arc::clone(&backend)));
            let request = Request::builder()
                .method("POST")
                .uri(GITHUB_WEB_BEGIN_PATH)
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(ORIGIN, "https://ci.example")
                .header(SEC_FETCH_SITE, "same-origin")
                .body(Body::from(body))
                .unwrap();
            let response = app.oneshot(request).await.unwrap();

            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "body {body:?}");
            assert!(backend.web_return_paths.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn browser_begin_rejects_cross_origin_before_state_creation() {
        let backend = Arc::new(FakeBackend::empty());
        let app = router(state(Arc::clone(&backend)));
        let mut request = json_post(GITHUB_WEB_BEGIN_PATH, r#"{"return_path":null}"#);
        request
            .headers_mut()
            .insert(ORIGIN, HeaderValue::from_static("https://attacker.example"));
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(backend.web_start.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn setup_browser_begin_accepts_native_form_and_preserves_json_contract() {
        for (content_type, body) in [
            (
                "application/x-www-form-urlencoded",
                format!("bootstrap_token={BOOTSTRAP_SENTINEL}&return_path=%2Frepositories"),
            ),
            (
                "application/json",
                format!(
                    r#"{{"bootstrap_token":"{BOOTSTRAP_SENTINEL}","return_path":"/repositories"}}"#
                ),
            ),
        ] {
            let (app, probe) = setup_begin_harness();
            let response = app
                .oneshot(setup_begin_request(
                    GITHUB_SETUP_WEB_BEGIN_PATH,
                    content_type,
                    body,
                ))
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            assert_eq!(
                response.headers()[LOCATION],
                format!("https://github.example/login/oauth?state={STATE}")
            );
            assert!(response.headers()[LOCATION].is_sensitive());
            assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
            assert!(probe.received_sentinel.load(Ordering::SeqCst));
            assert_eq!(
                *probe.return_paths.lock().unwrap(),
                vec![LoginReturnPath::new("/repositories").unwrap()]
            );
            let response_debug = format!("{response:?}");
            assert!(!response_debug.contains(BOOTSTRAP_SENTINEL));
            for cookie in response.headers().get_all(SET_COOKIE) {
                assert!(!cookie.to_str().unwrap().contains(BOOTSTRAP_SENTINEL));
            }
            let response_body = to_bytes(response.into_body(), 64).await.unwrap();
            assert!(!String::from_utf8_lossy(&response_body).contains(BOOTSTRAP_SENTINEL));
        }
    }

    #[tokio::test]
    async fn setup_browser_form_rejects_closed_grammar_before_backend_use() {
        for body in [
            String::new(),
            format!("bootstrap_token={BOOTSTRAP_SENTINEL}"),
            "return_path=%2Fruns".to_owned(),
            "bootstrap_token=&return_path=%2Fruns".to_owned(),
            format!("bootstrap_token={BOOTSTRAP_SENTINEL}&return_path="),
            format!(
                "bootstrap_token={BOOTSTRAP_SENTINEL}&bootstrap_token={BOOTSTRAP_SENTINEL}&return_path=%2Fruns"
            ),
            format!(
                "bootstrap_token={BOOTSTRAP_SENTINEL}&return_path=%2Fruns&return_path=%2Fother"
            ),
            format!("bootstrap_token={BOOTSTRAP_SENTINEL}&return_path=%2Fruns&unknown=x"),
            format!("%62ootstrap_token={BOOTSTRAP_SENTINEL}&return_path=%2Fruns"),
            "bootstrap_token=%&return_path=%2Fruns".to_owned(),
            "bootstrap_token=%FF&return_path=%2Fruns".to_owned(),
            format!("bootstrap_token={BOOTSTRAP_SENTINEL}&return_path=%"),
            format!("bootstrap_token={BOOTSTRAP_SENTINEL}&return_path=%2F%FF"),
            format!(
                "bootstrap_token={BOOTSTRAP_SENTINEL}&return_path=https%3A%2F%2Fevil.example%2F"
            ),
        ] {
            let (app, probe) = setup_begin_harness();
            let response = app
                .oneshot(setup_begin_request(
                    GITHUB_SETUP_WEB_BEGIN_PATH,
                    "application/x-www-form-urlencoded",
                    body,
                ))
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
        }

        let (app, probe) = setup_begin_harness();
        let response = app
            .oneshot(setup_begin_request(
                &format!("{GITHUB_SETUP_WEB_BEGIN_PATH}?unexpected=1"),
                "application/x-www-form-urlencoded",
                format!("bootstrap_token={BOOTSTRAP_SENTINEL}&return_path=%2Fruns"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn setup_browser_form_enforces_the_worst_case_encoded_limit() {
        let token = "%78".repeat(MAX_SETUP_BOOTSTRAP_TOKEN_BYTES);
        let return_path = format!(
            "%2F{}",
            "%61".repeat(MAX_SETUP_RETURN_PATH_BYTES.saturating_sub(1))
        );
        let exact = format!("bootstrap_token={token}&return_path={return_path}");
        assert_eq!(exact.len(), MAX_SETUP_FORM_BYTES);

        let (app, probe) = setup_begin_harness();
        let response = app
            .oneshot(setup_begin_request(
                GITHUB_SETUP_WEB_BEGIN_PATH,
                "application/x-www-form-urlencoded",
                exact.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            probe.return_paths.lock().unwrap()[0].as_str().len(),
            MAX_SETUP_RETURN_PATH_BYTES
        );

        let (app, probe) = setup_begin_harness();
        let response = app
            .oneshot(setup_begin_request(
                GITHUB_SETUP_WEB_BEGIN_PATH,
                "application/x-www-form-urlencoded",
                format!("{exact}x"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn setup_browser_origin_rejection_precedes_body_poll_and_backend() {
        let (app, probe) = setup_begin_harness();
        let polls = Arc::new(AtomicUsize::new(0));
        let observed_polls = Arc::clone(&polls);
        let mut emitted = false;
        let body = Body::from_stream(futures::stream::poll_fn(move |_| {
            observed_polls.fetch_add(1, Ordering::SeqCst);
            if std::mem::replace(&mut emitted, true) {
                Poll::Ready(None)
            } else {
                Poll::Ready(Some(Ok::<_, Infallible>(Bytes::from_static(
                    b"bootstrap_token=body-secret&return_path=%2Fruns",
                ))))
            }
        }));
        let request = Request::builder()
            .method("POST")
            .uri(GITHUB_SETUP_WEB_BEGIN_PATH)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(ORIGIN, "https://attacker.example")
            .header(SEC_FETCH_SITE, "cross-site")
            .body(body)
            .unwrap();
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn setup_browser_errors_never_reflect_decoded_bootstrap_secret() {
        let (app, probe) = setup_begin_harness();
        let response = app
            .oneshot(setup_begin_request(
                GITHUB_SETUP_WEB_BEGIN_PATH,
                "application/x-www-form-urlencoded",
                format!(
                    "bootstrap_token={BOOTSTRAP_SENTINEL}&return_path=%2Fruns&unknown={BOOTSTRAP_SENTINEL}"
                ),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
        assert!(!format!("{response:?}").contains(BOOTSTRAP_SENTINEL));
        let body = to_bytes(response.into_body(), 1_024).await.unwrap();
        assert_eq!(body, r#"{"error":"invalid_request"}"#);
        assert!(!String::from_utf8_lossy(&body).contains(BOOTSTRAP_SENTINEL));
    }

    #[tokio::test]
    async fn callback_head_is_hardened_and_never_consumes_sign_in_or_setup_state() {
        for (purpose, completion, expected_location) in [
            (
                "sign-in",
                WebCallbackCompletion::SignIn(WebLoginCompletion {
                    credential: SessionCredential::from_raw(SESSION).unwrap(),
                    csrf: CsrfToken::from_generated_secret(SecretString::new(CSRF).unwrap())
                        .unwrap(),
                    expires_at: UnixTimestamp::from_seconds(NOW + 3_600),
                    return_path: Some(LoginReturnPath::new("/callback-head-sign-in").unwrap()),
                }),
                "/callback-head-sign-in",
            ),
            (
                "installation-setup",
                WebCallbackCompletion::InstallationSetup(WebLoginCompletion {
                    credential: SessionCredential::from_raw(SESSION).unwrap(),
                    csrf: CsrfToken::from_generated_secret(SecretString::new(CSRF).unwrap())
                        .unwrap(),
                    expires_at: UnixTimestamp::from_seconds(NOW + 3_600),
                    return_path: Some(LoginReturnPath::new("/settings/access/users").unwrap()),
                }),
                "/settings/access/users",
            ),
        ] {
            let backend = Arc::new(FakeBackend::empty());
            *backend.web_completion.lock().unwrap() = Some(Ok(completion));
            let app = router(state(Arc::clone(&backend)));
            let callback_uri =
                format!("{GITHUB_WEB_CALLBACK_PATH}?code=provider-secret&state={STATE}");
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("HEAD")
                        .uri(&callback_uri)
                        .header(COOKIE, format!("__Host-automata-login={BINDING}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(
                response.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "{purpose} HEAD status"
            );
            assert_eq!(response.headers()[axum::http::header::ALLOW], "GET");
            assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
            assert_eq!(response.headers()[REFERRER_POLICY], "no-referrer");
            assert_eq!(response.headers()[X_CONTENT_TYPE_OPTIONS], "nosniff");
            assert!(response.headers().get(SET_COOKIE).is_none());
            assert!(backend.web_completion.lock().unwrap().is_some());
            assert!(!format!("{response:?}").contains("provider-secret"));
            assert!(to_bytes(response.into_body(), 1).await.unwrap().is_empty());

            let response = app
                .oneshot(
                    Request::builder()
                        .uri(callback_uri)
                        .header(COOKIE, format!("__Host-automata-login={BINDING}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SEE_OTHER, "{purpose} GET");
            assert_eq!(response.headers()[LOCATION], expected_location);
            assert!(backend.web_completion.lock().unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn callback_clears_binding_on_failure_without_reflecting_query_secrets() {
        let app = router(state(Arc::new(FakeBackend::empty())));
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "{GITHUB_WEB_CALLBACK_PATH}?code=provider-secret&state={STATE}&state={STATE}"
                    ))
                    .header(COOKIE, format!("__Host-automata-login={BINDING}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let clear = response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .next()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let body = to_bytes(response.into_body(), 1_024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();

        assert_eq!(body, r#"{"error":"invalid_callback"}"#);
        assert!(!body.contains("provider-secret"));
        assert!(clear.starts_with("__Host-automata-login=;"));
        assert!(clear.contains("Max-Age=0"));
    }

    #[tokio::test]
    async fn successful_callback_issues_session_and_csrf_then_redirects_locally() {
        let backend = Arc::new(FakeBackend::empty());
        *backend.web_completion.lock().unwrap() =
            Some(Ok(WebCallbackCompletion::SignIn(WebLoginCompletion {
                credential: SessionCredential::from_raw(SESSION).unwrap(),
                csrf: CsrfToken::from_generated_secret(SecretString::new(CSRF).unwrap()).unwrap(),
                expires_at: UnixTimestamp::from_seconds(NOW + 3_600),
                return_path: Some(LoginReturnPath::new("/café/runs?q=failed build").unwrap()),
            })));
        let app = router(state(backend));
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "{GITHUB_WEB_CALLBACK_PATH}?code=provider-code&state={STATE}"
                    ))
                    .header(COOKIE, format!("__Host-automata-login={BINDING}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers()[LOCATION],
            "/caf%C3%A9/runs?q=failed%20build"
        );
        assert!(response.headers()[LOCATION].is_sensitive());
        assert!(
            response
                .headers()
                .get_all(SET_COOKIE)
                .iter()
                .all(HeaderValue::is_sensitive)
        );
        let cookies: Vec<_> = response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        assert_eq!(cookies.len(), 3);
        assert_eq!(
            cookies
                .iter()
                .filter(|cookie| cookie.contains(SESSION))
                .count(),
            1
        );
        assert_eq!(
            cookies
                .iter()
                .filter(|cookie| cookie.contains(CSRF))
                .count(),
            1
        );
        assert!(cookies.iter().any(|cookie| {
            cookie.starts_with("__Host-automata-login=;") && cookie.contains("Max-Age=0")
        }));
    }

    #[tokio::test]
    async fn shared_callback_preserves_installation_completion_and_setup_errors() {
        let backend = Arc::new(FakeBackend::empty());
        *backend.web_completion.lock().unwrap() = Some(Ok(
            WebCallbackCompletion::InstallationSetup(WebLoginCompletion {
                credential: SessionCredential::from_raw(SESSION).unwrap(),
                csrf: CsrfToken::from_generated_secret(SecretString::new(CSRF).unwrap()).unwrap(),
                expires_at: UnixTimestamp::from_seconds(NOW + 3_600),
                return_path: Some(LoginReturnPath::new("/settings/access/users").unwrap()),
            }),
        ));
        let response = router(state(backend))
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "{GITHUB_WEB_CALLBACK_PATH}?code=provider-code&state={STATE}"
                    ))
                    .header(COOKIE, format!("__Host-automata-login={BINDING}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[LOCATION], "/settings/access/users");
        let cookies: Vec<_> = response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        assert_eq!(cookies.len(), 3);
        assert!(cookies.iter().any(|cookie| cookie.contains(SESSION)));
        assert!(cookies.iter().any(|cookie| cookie.contains(CSRF)));
        assert!(cookies.iter().any(|cookie| {
            cookie.starts_with("__Host-automata-login=;") && cookie.contains("Max-Age=0")
        }));

        let backend = Arc::new(FakeBackend::empty());
        *backend.web_completion.lock().unwrap() = Some(Err(WebCallbackError::InstallationSetup(
            InstallationSetupError::AlreadyConfigured,
        )));
        let response = router(state(backend))
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "{GITHUB_WEB_CALLBACK_PATH}?code=provider-code&state={STATE}"
                    ))
                    .header(COOKIE, format!("__Host-automata-login={BINDING}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::GONE);
        assert!(response.headers().get_all(SET_COOKIE).iter().any(|value| {
            let cookie = value.to_str().unwrap();
            cookie.starts_with("__Host-automata-login=;") && cookie.contains("Max-Age=0")
        }));
        assert_eq!(
            to_bytes(response.into_body(), 1_024).await.unwrap(),
            r#"{"error":"setup_complete"}"#
        );
    }

    #[tokio::test]
    async fn device_begin_and_poll_expose_secrets_only_in_success_documents() {
        let backend = Arc::new(FakeBackend::empty());
        *backend.device_start.lock().unwrap() = Some(Ok(DeviceLoginStart {
            poll_credential: SecretString::new(POLL).unwrap(),
            user_code: SecretString::new("ABCD-EFGH").unwrap(),
            verification_uri: Url::parse("https://github.example/login/device").unwrap(),
            expires_at: UnixTimestamp::from_seconds(NOW + 900),
            poll_interval: Duration::from_secs(5),
        }));
        *backend.device_poll.lock().unwrap() =
            Some(Ok(DevicePollOutcome::Complete(DeviceLoginCompletion {
                credential: SessionCredential::from_raw(SESSION).unwrap(),
                expires_at: UnixTimestamp::from_seconds(NOW + 86_400),
                return_path: None,
            })));
        let app = router(state(backend));

        let begin = app
            .clone()
            .oneshot(json_post(
                GITHUB_DEVICE_BEGIN_PATH,
                r#"{"return_path":null}"#,
            ))
            .await
            .unwrap();
        assert_eq!(begin.status(), StatusCode::OK);
        assert_eq!(begin.headers()[CACHE_CONTROL], "no-store");
        let begin_body = to_bytes(begin.into_body(), 4_096).await.unwrap();
        let begin_body = String::from_utf8(begin_body.to_vec()).unwrap();
        assert!(begin_body.contains(POLL));
        assert!(begin_body.contains("ABCD-EFGH"));

        let poll_body = format!(r#"{{"poll_credential":"{POLL}"}}"#);
        let poll = app
            .oneshot(json_post(GITHUB_DEVICE_POLL_PATH, poll_body))
            .await
            .unwrap();
        assert_eq!(poll.status(), StatusCode::OK);
        let poll_body = to_bytes(poll.into_body(), 4_096).await.unwrap();
        let poll_body = String::from_utf8(poll_body.to_vec()).unwrap();
        assert_eq!(poll_body.matches(SESSION).count(), 1);
        assert!(!poll_body.contains(POLL));
    }

    #[tokio::test]
    async fn device_completions_fail_closed_on_expiry_and_untrusted_return_paths() {
        let state = state(Arc::new(FakeBackend::empty()));
        let responses = [
            device_poll_response(
                &state,
                DevicePollOutcome::Complete(DeviceLoginCompletion {
                    credential: SessionCredential::from_raw(SESSION).unwrap(),
                    expires_at: UnixTimestamp::from_seconds(NOW),
                    return_path: None,
                }),
                UnixTimestamp::from_seconds(NOW),
            ),
            device_poll_response(
                &state,
                DevicePollOutcome::Complete(DeviceLoginCompletion {
                    credential: SessionCredential::from_raw(SESSION).unwrap(),
                    expires_at: UnixTimestamp::from_seconds(NOW + 60),
                    return_path: Some(LoginReturnPath::new(r"/\attacker.example").unwrap()),
                }),
                UnixTimestamp::from_seconds(NOW),
            ),
        ];
        for response in responses {
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            let body = to_bytes(response.into_body(), 1_024).await.unwrap();
            assert!(!String::from_utf8(body.to_vec()).unwrap().contains(SESSION));
        }
    }

    #[tokio::test]
    async fn no_query_routes_reject_queries_before_backend_dispatch() {
        let backend = Arc::new(FakeBackend::empty());
        let app = router(state(Arc::clone(&backend)));
        for suffix in ["?ignored=1", "?"] {
            let response = app
                .clone()
                .oneshot(json_post(
                    &format!("{GITHUB_DEVICE_BEGIN_PATH}{suffix}"),
                    r#"{"return_path":null}"#,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        assert!(backend.device_start.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn router_generated_responses_keep_auth_security_headers() {
        let app = router(state(Arc::new(FakeBackend::empty())));
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(GITHUB_DEVICE_BEGIN_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[REFERRER_POLICY], "no-referrer");
        assert_eq!(response.headers()[X_CONTENT_TYPE_OPTIONS], "nosniff");
    }

    #[tokio::test]
    async fn cli_session_status_exposes_only_safe_current_metadata() {
        let app = router(state(Arc::new(FakeBackend::empty()))).layer(Extension(cli_snapshot()));
        for request in [
            Request::builder()
                .method("GET")
                .uri(CLI_SESSION_PATH)
                .body(Body::from("ignored"))
                .unwrap(),
            Request::builder()
                .method("GET")
                .uri(CLI_SESSION_PATH)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::empty())
                .unwrap(),
        ] {
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(CLI_SESSION_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        let body = to_bytes(response.into_body(), 8 * 1_024).await.unwrap();
        let document: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(document["authenticated"], true);
        assert_eq!(document["kind"], "cli");
        assert_eq!(document["provider_id"], "github");
        assert_eq!(document["provider_login"], "octocat");
        assert_eq!(document["authorization_revision"], 7);
        assert!(!String::from_utf8_lossy(&body).contains(SESSION));
    }

    #[tokio::test]
    async fn cli_activation_accepts_only_an_exact_empty_bearer_post() {
        let backend = Arc::new(FakeBackend::empty());
        *backend.cli_activation.lock().unwrap() = Some(Ok(ActivateCliSessionOutcome::Activated(
            Box::new(cli_snapshot().session().clone()),
        )));
        let app = router(state(Arc::clone(&backend)));

        let query = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("{CLI_SESSION_PATH}?unexpected=1"))
                    .header(
                        axum::http::header::AUTHORIZATION,
                        format!("Bearer {SESSION}"),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(query.status(), StatusCode::BAD_REQUEST);
        assert!(backend.activated_credentials.lock().unwrap().is_empty());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(CLI_SESSION_PATH)
                    .header(
                        axum::http::header::AUTHORIZATION,
                        format!("Bearer {SESSION}"),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            *backend.activated_credentials.lock().unwrap(),
            vec![SESSION.to_owned()]
        );
        let body = to_bytes(response.into_body(), 64).await.unwrap();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn cli_logout_revokes_only_the_middleware_admitted_bearer() {
        let backend = Arc::new(FakeBackend::empty());
        *backend.cli_revoke.lock().unwrap() = Some(Ok(RevokeOwnSessionOutcome::Revoked));
        let credential = SessionCredential::from_raw(SESSION).unwrap();
        let app = router(state(Arc::clone(&backend)))
            .layer(Extension(Arc::new(CliSessionCredential::new(credential))));

        let query = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("{CLI_SESSION_PATH}?unexpected=1"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(query.status(), StatusCode::BAD_REQUEST);
        assert!(backend.revoked_credentials.lock().unwrap().is_empty());

        let payload = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(CLI_SESSION_PATH)
                    .body(Body::from("ignored"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(payload.status(), StatusCode::BAD_REQUEST);
        assert!(backend.revoked_credentials.lock().unwrap().is_empty());

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(CLI_SESSION_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            *backend.revoked_credentials.lock().unwrap(),
            vec![SESSION.to_owned()]
        );
    }

    #[test]
    fn request_content_types_are_unambiguous() {
        for (value, json, form) in [
            ("application/json", true, false),
            ("application/json; charset=utf-8", true, false),
            ("application/x-www-form-urlencoded", false, true),
            (
                "application/x-www-form-urlencoded; charset=UTF-8",
                false,
                true,
            ),
            (
                "application/json; charset=utf-8; charset=utf-8",
                false,
                false,
            ),
            (
                "application/x-www-form-urlencoded; charset=utf-8; charset=utf-8",
                false,
                false,
            ),
            ("application/json; profile=compat", false, false),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, HeaderValue::from_str(value).unwrap());
            assert_eq!(has_json_content_type(&headers), json, "{value}");
            assert_eq!(has_form_content_type(&headers), form, "{value}");
        }

        let mut duplicate = HeaderMap::new();
        duplicate.append(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        duplicate.append(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        assert!(!has_json_content_type(&duplicate));
    }

    #[test]
    fn device_debug_redacts_secrets_and_verification_query() {
        let start = DeviceLoginStart {
            poll_credential: SecretString::new(POLL).unwrap(),
            user_code: SecretString::new("ABCD-EFGH").unwrap(),
            verification_uri: Url::parse(
                "https://github.example/login/device?user_code=query-secret",
            )
            .unwrap(),
            expires_at: UnixTimestamp::from_seconds(NOW + 60),
            poll_interval: Duration::from_secs(5),
        };
        let debug = format!("{start:?}");
        assert!(!debug.contains(POLL));
        assert!(!debug.contains("ABCD-EFGH"));
        assert!(!debug.contains("query-secret"));
        assert!(debug.contains("verification_query: \"[REDACTED]\""));
    }

    #[test]
    fn callback_parser_rejects_ambiguous_unknown_and_malformed_inputs() {
        assert!(parse_web_callback(Some(&format!("code=x&state={STATE}"))).is_ok());
        assert!(parse_web_callback(Some(&format!("error=access_denied&state={STATE}"))).is_ok());
        for query in [
            format!("code=x&state={STATE}&state={STATE}"),
            format!("code=x&state={STATE}&extra=1"),
            format!("code=x&error=access_denied&state={STATE}"),
            format!("code=%zz&state={STATE}"),
        ] {
            assert!(parse_web_callback(Some(&query)).is_err());
        }
    }

    #[test]
    fn return_paths_are_resolved_before_redirect_to_block_backslash_authorities() {
        let origin = HumanAuthOrigin::new(&Url::parse("https://ci.example/").unwrap()).unwrap();
        assert!(trusted_local_return_path(
            &origin,
            "/automata-ci/automata/actions?status=all#latest"
        ));
        for invalid in [
            "runs",
            "?view=all",
            "#latest",
            "//attacker.example",
            r"/\attacker.example",
        ] {
            assert!(!trusted_local_return_path(&origin, invalid), "{invalid}");
        }
        assert_eq!(
            canonical_local_return_path(&origin, "/café?q=failed build")
                .expect("local Unicode paths are canonicalized")
                .as_str(),
            "/caf%C3%A9?q=failed%20build"
        );
    }

    #[test]
    fn typed_errors_have_sanitized_stable_statuses_and_retry_headers() {
        let response = login_error_response(
            GithubLoginError::PollTooEarly {
                next_poll_at: UnixTimestamp::from_seconds(NOW + 7),
            },
            UnixTimestamp::from_seconds(NOW),
        );
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[RETRY_AFTER], "7");
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");

        let internal = login_error_response(
            GithubLoginError::IntegrityFailure,
            UnixTimestamp::from_seconds(NOW),
        );
        assert_eq!(internal.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
