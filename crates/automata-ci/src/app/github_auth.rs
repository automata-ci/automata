//! Non-cacheable HTTP boundary for operational GitHub human sign-in.
//!
//! The handlers in this module never receive provider access or refresh tokens.
//! OAuth state, callback codes, login bindings, device poll proofs, and Automata
//! credentials cross only their explicit HTTP boundary and are never formatted or
//! logged here.

use std::{
    fmt, io,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use automata_ci_auth::{
    github::{
        GithubBrowserBindingCookie, GithubDeviceLoginPollOutcome, GithubDeviceLoginStart,
        GithubDevicePollCredential, GithubLoginError, GithubLoginService, GithubWebCallback,
        GithubWebCallbackPurpose, GithubWebLoginStart,
    },
    human::TenantId,
    login::LoginReturnPath,
    request_auth::AuthenticatedRequestSnapshot,
    secret::{CsrfToken, SecretString},
    session::{ActivateCliSessionOutcome, DurableSession, RevokeOwnSessionOutcome, SessionKind},
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

    fn setup_enabled(&self) -> bool {
        self.setup.is_some()
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

struct WebLoginStartRef<'a> {
    authorization_url: &'a Url,
    binding_secret: &'a str,
    expires_at: UnixTimestamp,
}

trait WebLoginStartView: Send + Sync {
    fn view(&self) -> WebLoginStartRef<'_>;
}

impl WebLoginStartView for GithubWebLoginStart {
    fn view(&self) -> WebLoginStartRef<'_> {
        WebLoginStartRef {
            authorization_url: self.authorization_url(),
            binding_secret: self.binding_cookie().expose_secret(),
            expires_at: self.expires_at(),
        }
    }
}

struct DeviceLoginStartRef<'a> {
    poll_credential_secret: &'a str,
    user_code_secret: &'a str,
    verification_uri: &'a Url,
    expires_at: UnixTimestamp,
    poll_interval: Duration,
}

trait DeviceLoginStartView: Send + Sync {
    fn view(&self) -> DeviceLoginStartRef<'_>;
}

impl DeviceLoginStartView for GithubDeviceLoginStart {
    fn view(&self) -> DeviceLoginStartRef<'_> {
        DeviceLoginStartRef {
            poll_credential_secret: self.poll_credential().expose_secret(),
            user_code_secret: self.user_code(),
            verification_uri: self.verification_uri(),
            expires_at: self.expires_at(),
            poll_interval: self.poll_interval(),
        }
    }
}

struct RedactedDeviceLoginStart<T>(T);

impl<T: DeviceLoginStartView> DeviceLoginStartView for RedactedDeviceLoginStart<T> {
    fn view(&self) -> DeviceLoginStartRef<'_> {
        self.0.view()
    }
}

impl<T: DeviceLoginStartView> fmt::Debug for RedactedDeviceLoginStart<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let start = self.view();
        formatter
            .debug_struct("DeviceLoginStart")
            .field("poll_credential", &"[REDACTED]")
            .field("user_code", &"[REDACTED]")
            .field("verification_origin", &start.verification_uri.origin())
            .field("verification_path", &start.verification_uri.path())
            .field("verification_query", &"[REDACTED]")
            .field("expires_at", &start.expires_at)
            .field("poll_interval", &start.poll_interval)
            .finish()
    }
}

type BoxedWebLoginStart = Box<dyn WebLoginStartView>;
type BoxedDeviceLoginStart = Box<dyn DeviceLoginStartView>;

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
    InvalidCompletion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GithubAuthFailure {
    SignIn(GithubLoginError),
    InstallationSetup(InstallationSetupError),
}

type DevicePollResult = Result<DevicePollOutcome, GithubAuthFailure>;

/// Testable application seam around the operational coordinator. Every secret
/// output remains behind a borrowed, non-serializable view until response
/// construction.
#[async_trait]
trait GithubAuthBackend: fmt::Debug + Send + Sync {
    async fn begin_web(
        &self,
        tenant_id: TenantId,
        return_path: LoginReturnPath,
    ) -> Result<BoxedWebLoginStart, GithubLoginError>;

    async fn begin_device(
        &self,
        tenant_id: TenantId,
        return_path: Option<LoginReturnPath>,
    ) -> Result<BoxedDeviceLoginStart, GithubLoginError>;

    async fn poll_device(
        &self,
        tenant_id: TenantId,
        credential: GithubDevicePollCredential,
    ) -> DevicePollResult;

    async fn begin_setup_web(
        &self,
        bootstrap_token: SecretString,
        return_path: LoginReturnPath,
    ) -> Result<BoxedWebLoginStart, InstallationSetupError>;

    async fn begin_setup_device(
        &self,
        bootstrap_token: SecretString,
        return_path: Option<LoginReturnPath>,
    ) -> Result<BoxedDeviceLoginStart, InstallationSetupError>;

    async fn poll_setup_device(&self, credential: GithubDevicePollCredential) -> DevicePollResult;

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

    async fn complete_web(
        &self,
        tenant_id: TenantId,
        binding: GithubBrowserBindingCookie,
        callback: GithubWebCallback,
    ) -> Result<WebCallbackCompletion, WebCallbackError>;
}

#[async_trait]
impl GithubAuthBackend for OperationalGithubAuthBackend {
    async fn begin_web(
        &self,
        tenant_id: TenantId,
        return_path: LoginReturnPath,
    ) -> Result<BoxedWebLoginStart, GithubLoginError> {
        let started = self.login.begin_web(tenant_id, return_path).await?;
        Ok(Box::new(started))
    }

    async fn begin_device(
        &self,
        tenant_id: TenantId,
        return_path: Option<LoginReturnPath>,
    ) -> Result<BoxedDeviceLoginStart, GithubLoginError> {
        let started = self.login.begin_device(tenant_id, return_path).await?;
        Ok(Box::new(RedactedDeviceLoginStart(started)))
    }

    async fn poll_device(
        &self,
        tenant_id: TenantId,
        credential: GithubDevicePollCredential,
    ) -> DevicePollResult {
        match self
            .login
            .poll_device(tenant_id.clone(), credential)
            .await
            .map_err(GithubAuthFailure::SignIn)?
        {
            GithubDeviceLoginPollOutcome::Pending { next_poll_at } => {
                Ok(DevicePollOutcome::Pending { next_poll_at })
            }
            GithubDeviceLoginPollOutcome::SlowDown { next_poll_at } => {
                Ok(DevicePollOutcome::SlowDown { next_poll_at })
            }
            GithubDeviceLoginPollOutcome::Complete(completion) => {
                let (credential, _, session, _, return_path) = completion.into_parts();
                map_sign_in_device_completion(&tenant_id, credential, &session, return_path)
            }
            GithubDeviceLoginPollOutcome::Denied => Ok(DevicePollOutcome::Denied),
            GithubDeviceLoginPollOutcome::Expired => Ok(DevicePollOutcome::Expired),
        }
    }

    async fn begin_setup_web(
        &self,
        bootstrap_token: SecretString,
        return_path: LoginReturnPath,
    ) -> Result<BoxedWebLoginStart, InstallationSetupError> {
        let setup = self
            .setup
            .as_ref()
            .ok_or(InstallationSetupError::AlreadyConfigured)?;
        let started = setup
            .begin_web(bootstrap_token.expose_secret(), return_path)
            .await;
        drop(bootstrap_token);
        Ok(Box::new(started?))
    }

    async fn begin_setup_device(
        &self,
        bootstrap_token: SecretString,
        return_path: Option<LoginReturnPath>,
    ) -> Result<BoxedDeviceLoginStart, InstallationSetupError> {
        let setup = self
            .setup
            .as_ref()
            .ok_or(InstallationSetupError::AlreadyConfigured)?;
        let started = setup
            .begin_device(bootstrap_token.expose_secret(), return_path)
            .await;
        drop(bootstrap_token);
        Ok(Box::new(RedactedDeviceLoginStart(started?)))
    }

    async fn poll_setup_device(&self, credential: GithubDevicePollCredential) -> DevicePollResult {
        let setup = self
            .setup
            .as_ref()
            .ok_or(InstallationSetupError::AlreadyConfigured)
            .map_err(GithubAuthFailure::InstallationSetup)?;
        match setup
            .poll_device(credential)
            .await
            .map_err(GithubAuthFailure::InstallationSetup)?
        {
            InstallationDevicePollOutcome::Pending { next_poll_at } => {
                Ok(DevicePollOutcome::Pending { next_poll_at })
            }
            InstallationDevicePollOutcome::SlowDown { next_poll_at } => {
                Ok(DevicePollOutcome::SlowDown { next_poll_at })
            }
            InstallationDevicePollOutcome::Complete(completion) => {
                let (credential, _, session, return_path) = completion.into_parts();
                let outcome = map_setup_device_completion(credential, &session, return_path);
                Ok(outcome)
            }
            InstallationDevicePollOutcome::Denied => Ok(DevicePollOutcome::Denied),
            InstallationDevicePollOutcome::Expired => Ok(DevicePollOutcome::Expired),
        }
    }

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
                if !session_identity_matches(completion.session(), SessionKind::Browser, &tenant_id)
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
                if !session_identity_matches(&session, SessionKind::Browser, &tenant_id) {
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
}

fn map_sign_in_device_completion(
    tenant_id: &TenantId,
    credential: SessionCredential,
    session: &DurableSession,
    return_path: Option<LoginReturnPath>,
) -> DevicePollResult {
    if !session_identity_matches(session, SessionKind::Cli, tenant_id) {
        return Err(GithubAuthFailure::SignIn(
            GithubLoginError::IntegrityFailure,
        ));
    }
    Ok(DevicePollOutcome::Complete(DeviceLoginCompletion {
        credential,
        expires_at: session.expires_at(),
        return_path,
    }))
}

fn map_setup_device_completion(
    credential: SessionCredential,
    session: &DurableSession,
    return_path: Option<LoginReturnPath>,
) -> DevicePollOutcome {
    if session.identity().kind() != SessionKind::Cli {
        return DevicePollOutcome::InvalidCompletion;
    }
    DevicePollOutcome::Complete(DeviceLoginCompletion {
        credential,
        expires_at: session.expires_at(),
        return_path,
    })
}

fn session_identity_matches(
    session: &DurableSession,
    expected_kind: SessionKind,
    expected_tenant: &TenantId,
) -> bool {
    session.identity().kind() == expected_kind && session.identity().tenant_id() == expected_tenant
}

#[derive(Clone)]
struct GithubAuthTransportState {
    backend: Arc<dyn GithubAuthBackend>,
    begin_admission: Arc<GithubBeginAdmission>,
    application_origin: HumanAuthOrigin,
    provider_origin: GithubProviderOrigin,
    default_return_path: LoginReturnPath,
    clock: Arc<dyn Clock>,
}

impl GithubAuthTransportState {
    fn new(
        backend: Arc<dyn GithubAuthBackend>,
        begin_admission: Arc<GithubBeginAdmission>,
        application_origin: HumanAuthOrigin,
        provider_origin: GithubProviderOrigin,
        default_return_path: LoginReturnPath,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            backend,
            begin_admission,
            application_origin,
            provider_origin,
            default_return_path,
            clock,
        }
    }
}

impl fmt::Debug for GithubAuthTransportState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubAuthTransportState")
            .field("backend", &self.backend)
            .field("begin_admission", &self.begin_admission)
            .field("application_origin", &self.application_origin)
            .field("provider_origin", &self.provider_origin)
            .field("default_return_path", &self.default_return_path)
            .field("clock", &self.clock)
            .finish()
    }
}

/// Cloneable dependencies for one tenant-specific GitHub auth router.
#[derive(Clone)]
pub(crate) struct GithubAuthHttpState {
    transport: GithubAuthTransportState,
    tenant_id: TenantId,
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
        Self {
            transport: GithubAuthTransportState::new(
                backend,
                process_github_begin_admission(),
                application_origin,
                provider_origin,
                default_return_path,
                clock,
            ),
            tenant_id,
        }
    }
}

impl fmt::Debug for GithubAuthHttpState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubAuthHttpState")
            .field("transport", &self.transport)
            .field("tenant_id", &self.tenant_id)
            .finish()
    }
}

/// Cloneable dependencies for the one-use installation setup routes.
#[derive(Clone)]
pub(crate) struct GithubSetupHttpState {
    transport: GithubAuthTransportState,
}

impl GithubSetupHttpState {
    pub(crate) fn new(
        backend: Arc<OperationalGithubAuthBackend>,
        application_origin: HumanAuthOrigin,
        provider_origin: GithubProviderOrigin,
        default_return_path: LoginReturnPath,
        clock: Arc<dyn Clock>,
    ) -> Option<Self> {
        if !backend.setup_enabled() {
            return None;
        }
        Some(Self {
            transport: GithubAuthTransportState::new(
                backend,
                process_github_begin_admission(),
                application_origin,
                provider_origin,
                default_return_path,
                clock,
            ),
        })
    }
}

impl fmt::Debug for GithubSetupHttpState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubSetupHttpState")
            .field("transport", &self.transport)
            .field("capability", &"enabled")
            .finish()
    }
}

enum GithubAuthFlow<'a> {
    SignIn(&'a GithubAuthHttpState),
    InstallationSetup(&'a GithubSetupHttpState),
}

impl<'a> GithubAuthFlow<'a> {
    fn transport(&self) -> &'a GithubAuthTransportState {
        match self {
            Self::SignIn(state) => &state.transport,
            Self::InstallationSetup(state) => &state.transport,
        }
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
    let presented = match extract_human_credential(
        &parts.headers,
        state.transport.application_origin.cookie_mode(),
    ) {
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
    match state
        .transport
        .backend
        .activate_cli(presented.expose_secret())
        .await
    {
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
    match state
        .transport
        .backend
        .revoke_cli(credential.expose_secret())
        .await
    {
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
        .transport
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
    begin_web_request(GithubAuthFlow::InstallationSetup(&state), request).await
}

async fn begin_web(State(state): State<GithubAuthHttpState>, request: Request) -> Response {
    begin_web_request(GithubAuthFlow::SignIn(&state), request).await
}

async fn begin_web_request(flow: GithubAuthFlow<'_>, request: Request) -> Response {
    let transport = flow.transport();
    if !valid_login_initiation(request.headers(), &transport.application_origin) {
        return error_response(StatusCode::FORBIDDEN, "browser_security_check_failed");
    }
    match &flow {
        GithubAuthFlow::SignIn(state) => {
            let document = match parse_login_start_request(request).await {
                Ok(document) => document,
                Err(error) => return request_error_response(error),
            };
            let Ok(return_path) = parse_return_path(
                document.return_path.as_deref(),
                &transport.default_return_path,
                &transport.application_origin,
            ) else {
                return error_response(StatusCode::BAD_REQUEST, "invalid_request");
            };
            let _begin_permit = match transport.begin_admission.try_acquire() {
                Ok(permit) => permit,
                Err(rejection) => return browser_begin_overload_response(rejection),
            };
            match transport
                .backend
                .begin_web(state.tenant_id.clone(), return_path)
                .await
            {
                Ok(start) => web_start_response(transport, start.as_ref()),
                Err(error) => login_error_response(error, transport.clock.now()),
            }
        }
        GithubAuthFlow::InstallationSetup(_) => {
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
                &transport.default_return_path,
                &transport.application_origin,
            ) else {
                return error_response(StatusCode::BAD_REQUEST, "invalid_request");
            };
            drop(requested_return_path);
            let _begin_permit = match transport.begin_admission.try_acquire() {
                Ok(permit) => permit,
                Err(rejection) => return browser_begin_overload_response(rejection),
            };
            match transport
                .backend
                .begin_setup_web(bootstrap_token, return_path)
                .await
            {
                Ok(start) => web_start_response(transport, start.as_ref()),
                Err(error) => setup_error_response(error, transport.clock.now()),
            }
        }
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

fn web_start_response(
    transport: &GithubAuthTransportState,
    start: &dyn WebLoginStartView,
) -> Response {
    let start = start.view();
    if !transport.provider_origin.trusts(start.authorization_url) {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
    }
    let Some(lifetime) = remaining_lifetime(start.expires_at, transport.clock.now()) else {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
    };
    let Ok(cookie) = login_set_cookie(
        transport.application_origin.cookie_mode(),
        start.binding_secret,
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
    let clear = match clear_login_cookie(state.transport.application_origin.cookie_mode()) {
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
        state.transport.application_origin.cookie_mode(),
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
        .transport
        .backend
        .complete_web(state.tenant_id.clone(), binding, callback)
        .await
    {
        Ok(
            WebCallbackCompletion::SignIn(completion)
            | WebCallbackCompletion::InstallationSetup(completion),
        ) => web_completion_response(state, &completion),
        Err(WebCallbackError::SignIn(error)) => {
            login_error_response(error, state.transport.clock.now())
        }
        Err(WebCallbackError::InstallationSetup(error)) => {
            tracing::warn!(
                error_kind = ?error,
                "GitHub installation setup callback failed"
            );
            setup_error_response(error, state.transport.clock.now())
        }
    }
}

fn web_completion_response(
    state: &GithubAuthHttpState,
    completion: &WebLoginCompletion,
) -> Response {
    let Some(lifetime) = remaining_lifetime(completion.expires_at, state.transport.clock.now())
    else {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
    };
    let session = match session_set_cookie(
        state.transport.application_origin.cookie_mode(),
        &completion.credential,
        lifetime,
    ) {
        Ok(cookie) => cookie.into_header_value(),
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
    };
    let csrf = match csrf_set_cookie(
        state.transport.application_origin.cookie_mode(),
        &completion.csrf,
        lifetime,
    ) {
        Ok(cookie) => cookie.into_header_value(),
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
    };
    let location = completion
        .return_path
        .as_ref()
        .unwrap_or(&state.transport.default_return_path)
        .as_str();
    let Some(location) = canonical_local_return_path(&state.transport.application_origin, location)
    else {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
    };
    redirect_response(StatusCode::SEE_OTHER, location.as_str(), &[session, csrf])
}

async fn begin_device(State(state): State<GithubAuthHttpState>, request: Request) -> Response {
    begin_device_request(GithubAuthFlow::SignIn(&state), request).await
}

async fn begin_setup_device(
    State(state): State<GithubSetupHttpState>,
    request: Request,
) -> Response {
    begin_device_request(GithubAuthFlow::InstallationSetup(&state), request).await
}

async fn begin_device_request(flow: GithubAuthFlow<'_>, request: Request) -> Response {
    let transport = flow.transport();
    match &flow {
        GithubAuthFlow::SignIn(state) => {
            let document = match parse_json_request::<LoginStartDocument>(request).await {
                Ok(document) => document,
                Err(error) => return request_error_response(error),
            };
            let Ok(return_path) =
                parse_optional_return_path(document.return_path, &transport.application_origin)
            else {
                return error_response(StatusCode::BAD_REQUEST, "invalid_request");
            };
            let _begin_permit = match transport.begin_admission.try_acquire() {
                Ok(permit) => permit,
                Err(rejection) => return device_begin_overload_response(rejection),
            };
            match transport
                .backend
                .begin_device(state.tenant_id.clone(), return_path)
                .await
            {
                Ok(start) => device_start_response(transport, start.as_ref()),
                Err(error) => login_error_response(error, transport.clock.now()),
            }
        }
        GithubAuthFlow::InstallationSetup(_) => {
            let document = match parse_json_request::<SetupLoginStartDocument>(request).await {
                Ok(document) => document,
                Err(error) => return request_error_response(error),
            };
            let SetupLoginStartDocument {
                bootstrap_token,
                return_path,
            } = document;
            let Ok(return_path) =
                parse_optional_return_path(return_path, &transport.application_origin)
            else {
                return error_response(StatusCode::BAD_REQUEST, "invalid_request");
            };
            let _begin_permit = match transport.begin_admission.try_acquire() {
                Ok(permit) => permit,
                Err(rejection) => return device_begin_overload_response(rejection),
            };
            match transport
                .backend
                .begin_setup_device(bootstrap_token, return_path)
                .await
            {
                Ok(start) => device_start_response(transport, start.as_ref()),
                Err(error) => setup_error_response(error, transport.clock.now()),
            }
        }
    }
}

fn parse_optional_return_path(
    requested: Option<String>,
    origin: &HumanAuthOrigin,
) -> Result<Option<LoginReturnPath>, ()> {
    requested
        .map(|path| canonical_local_return_path(origin, &path).ok_or(()))
        .transpose()
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

fn device_start_response(
    transport: &GithubAuthTransportState,
    start: &dyn DeviceLoginStartView,
) -> Response {
    let start = start.view();
    if !transport.provider_origin.trusts(start.verification_uri)
        || start.poll_interval.is_zero()
        || start.poll_interval.subsec_nanos() != 0
        || start.expires_at <= transport.clock.now()
    {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
    }
    let Some(expires_in_seconds) = start
        .expires_at
        .as_seconds()
        .checked_sub(transport.clock.now().as_seconds())
        .filter(|seconds| *seconds > 0)
    else {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
    };
    json_response(
        StatusCode::OK,
        &DeviceStartDocument {
            poll_credential: start.poll_credential_secret,
            user_code: start.user_code_secret,
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
    poll_device_request(GithubAuthFlow::SignIn(&state), request).await
}

async fn poll_setup_device(
    State(state): State<GithubSetupHttpState>,
    request: Request,
) -> Response {
    poll_device_request(GithubAuthFlow::InstallationSetup(&state), request).await
}

async fn poll_device_request(flow: GithubAuthFlow<'_>, request: Request) -> Response {
    let transport = flow.transport();
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
    let result = match &flow {
        GithubAuthFlow::SignIn(state) => {
            transport
                .backend
                .poll_device(state.tenant_id.clone(), credential)
                .await
        }
        GithubAuthFlow::InstallationSetup(_) => {
            transport.backend.poll_setup_device(credential).await
        }
    };
    match result {
        Ok(outcome) => device_poll_response(transport, outcome, transport.clock.now()),
        Err(error) => {
            log_device_poll_failure(error);
            github_auth_failure_response(error, transport.clock.now())
        }
    }
}

fn log_device_poll_failure(failure: GithubAuthFailure) {
    match failure {
        GithubAuthFailure::SignIn(
            error @ (GithubLoginError::ProviderUnavailable
            | GithubLoginError::StorageUnavailable
            | GithubLoginError::RandomnessUnavailable
            | GithubLoginError::CollisionLimitExceeded
            | GithubLoginError::IntegrityFailure),
        ) => {
            tracing::warn!(
                error = ?error,
                "GitHub device authorization poll failed"
            );
        }
        GithubAuthFailure::SignIn(_) => {}
        GithubAuthFailure::InstallationSetup(error) => {
            tracing::warn!(
                error = ?error,
                "installation setup device authorization poll failed"
            );
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
    transport: &GithubAuthTransportState,
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
                    trusted_local_return_path(&transport.application_origin, path.as_str())
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
        DevicePollOutcome::Complete(_) | DevicePollOutcome::InvalidCompletion => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
        }
        DevicePollOutcome::Denied => error_response(StatusCode::FORBIDDEN, "authorization_denied"),
        DevicePollOutcome::Expired => error_response(StatusCode::GONE, "authorization_expired"),
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
    let mut fetch_sites = headers.get_all(&SEC_FETCH_SITE).iter();
    let fetch_site = fetch_sites.next();
    if fetch_sites.next().is_some() {
        return false;
    }
    match fetch_site.and_then(|site| site.to_str().ok()) {
        // Fetch Metadata is browser-controlled and cannot be forged by a
        // cross-origin form. Prefer it when the browser provides the exact
        // same-origin signal; privacy modes are permitted to omit or redact
        // Origin independently.
        Some(site) if site.eq_ignore_ascii_case("same-origin") => true,
        Some(site) if site.eq_ignore_ascii_case("cross-site") => false,
        Some(_) | None => {
            exactly_one_header(headers, &ORIGIN).is_some_and(|origin| origin == expected.as_str())
        }
    }
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
    github_auth_failure_response(GithubAuthFailure::SignIn(error), now)
}

fn setup_error_response(error: InstallationSetupError, now: UnixTimestamp) -> Response {
    github_auth_failure_response(GithubAuthFailure::InstallationSetup(error), now)
}

fn github_auth_failure_response(error: GithubAuthFailure, now: UnixTimestamp) -> Response {
    let (status, code, retry_after) = match error {
        GithubAuthFailure::SignIn(GithubLoginError::Invalid)
        | GithubAuthFailure::InstallationSetup(InstallationSetupError::InvalidRequest) => {
            (StatusCode::BAD_REQUEST, "invalid_request", None)
        }
        GithubAuthFailure::InstallationSetup(InstallationSetupError::InvalidProof) => {
            (StatusCode::FORBIDDEN, "setup_proof_rejected", None)
        }
        GithubAuthFailure::InstallationSetup(InstallationSetupError::NotArmed) => {
            (StatusCode::CONFLICT, "setup_not_armed", None)
        }
        GithubAuthFailure::InstallationSetup(InstallationSetupError::StateConflict) => {
            (StatusCode::CONFLICT, "setup_state_conflict", None)
        }
        GithubAuthFailure::SignIn(GithubLoginError::Replay)
        | GithubAuthFailure::InstallationSetup(InstallationSetupError::Replay) => {
            (StatusCode::CONFLICT, "request_replayed", None)
        }
        GithubAuthFailure::SignIn(GithubLoginError::Expired)
        | GithubAuthFailure::InstallationSetup(InstallationSetupError::Expired) => {
            (StatusCode::GONE, "request_expired", None)
        }
        GithubAuthFailure::SignIn(GithubLoginError::Denied)
        | GithubAuthFailure::InstallationSetup(InstallationSetupError::Denied) => {
            (StatusCode::FORBIDDEN, "authorization_denied", None)
        }
        GithubAuthFailure::SignIn(GithubLoginError::PollTooEarly { next_poll_at })
        | GithubAuthFailure::InstallationSetup(InstallationSetupError::PollTooEarly {
            next_poll_at,
        }) => (
            StatusCode::TOO_MANY_REQUESTS,
            "poll_too_early",
            Some(retry_seconds(next_poll_at, now)),
        ),
        GithubAuthFailure::SignIn(GithubLoginError::RateLimited {
            retry_after_seconds,
        })
        | GithubAuthFailure::InstallationSetup(InstallationSetupError::RateLimited {
            retry_after_seconds,
        }) => (
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            retry_after_seconds.map(|seconds| seconds.max(1)),
        ),
        GithubAuthFailure::SignIn(
            GithubLoginError::ProviderUnavailable
            | GithubLoginError::StorageUnavailable
            | GithubLoginError::RandomnessUnavailable
            | GithubLoginError::CollisionLimitExceeded,
        )
        | GithubAuthFailure::InstallationSetup(
            InstallationSetupError::ProviderUnavailable
            | InstallationSetupError::StorageUnavailable
            | InstallationSetupError::RandomnessUnavailable
            | InstallationSetupError::CollisionLimitExceeded,
        ) => (StatusCode::SERVICE_UNAVAILABLE, "unavailable", Some(1)),
        GithubAuthFailure::SignIn(GithubLoginError::NotAuthorized)
        | GithubAuthFailure::InstallationSetup(InstallationSetupError::NotAuthorized) => {
            (StatusCode::FORBIDDEN, "not_authorized", None)
        }
        GithubAuthFailure::InstallationSetup(InstallationSetupError::AlreadyConfigured) => {
            (StatusCode::GONE, "setup_complete", None)
        }
        GithubAuthFailure::SignIn(GithubLoginError::IntegrityFailure)
        | GithubAuthFailure::InstallationSetup(InstallationSetupError::IntegrityFailure) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", None)
        }
    };
    let mut response = error_response(status, code);
    if let Some(seconds) = retry_after {
        set_retry_after(&mut response, seconds);
    }
    response
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
            atomic::{AtomicU64, AtomicUsize, Ordering},
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
    struct FixedClock(u64);

    impl Clock for FixedClock {
        fn now(&self) -> UnixTimestamp {
            UnixTimestamp::from_seconds(self.0)
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

    struct TestWebLoginStart(Url, SecretString, UnixTimestamp);

    impl WebLoginStartView for TestWebLoginStart {
        fn view(&self) -> WebLoginStartRef<'_> {
            WebLoginStartRef {
                authorization_url: &self.0,
                binding_secret: self.1.expose_secret(),
                expires_at: self.2,
            }
        }
    }

    struct TestDeviceLoginStart(SecretString, SecretString, Url, UnixTimestamp, Duration);

    impl DeviceLoginStartView for TestDeviceLoginStart {
        fn view(&self) -> DeviceLoginStartRef<'_> {
            DeviceLoginStartRef {
                poll_credential_secret: self.0.expose_secret(),
                user_code_secret: self.1.expose_secret(),
                verification_uri: &self.2,
                expires_at: self.3,
                poll_interval: self.4,
            }
        }
    }

    /// Non-secret `(matches_sentinel, decoded_len, all_x)` probe evidence.
    type BootstrapObservation = (bool, usize, bool);

    fn observe_bootstrap(token: &SecretString) -> BootstrapObservation {
        let exposed = token.expose_secret();
        let matches_sentinel = token.constant_time_eq(BOOTSTRAP_SENTINEL);
        let all_x = exposed.bytes().all(|byte| byte == b'x');
        (matches_sentinel, exposed.len(), all_x)
    }

    #[derive(Default)]
    struct TransportProbes {
        begin_web: Vec<(TenantId, LoginReturnPath)>,
        begin_setup_web: Vec<(BootstrapObservation, LoginReturnPath)>,
        begin_device: Vec<(TenantId, Option<LoginReturnPath>)>,
        begin_setup_device: Vec<(BootstrapObservation, Option<LoginReturnPath>)>,
        poll_device: Vec<(TenantId, bool)>,
        poll_setup_device: Vec<bool>,
    }

    type SignResult<T> = Result<T, GithubLoginError>;
    type SetupResult<T> = Result<T, InstallationSetupError>;
    type SessionResult<T> = Result<T, SessionCredentialServiceError>;

    #[derive(Default)]
    struct FakeBackend {
        browser_revoke: Mutex<Option<SessionResult<RevokeOwnSessionOutcome>>>,
        cli_revoke: Mutex<Option<SessionResult<RevokeOwnSessionOutcome>>>,
        cli_activation: Mutex<Option<SessionResult<ActivateCliSessionOutcome>>>,
        revoked_credentials: Mutex<Vec<String>>,
        activated_credentials: Mutex<Vec<String>>,
        web_start: Mutex<Option<TestWebLoginStart>>,
        web_begin_blocker: Mutex<Option<Arc<BeginBlocker>>>,
        web_completion: Mutex<Option<Result<WebCallbackCompletion, WebCallbackError>>>,
        device_start: Mutex<Option<TestDeviceLoginStart>>,
        device_poll: Mutex<Option<DevicePollOutcome>>,
        probes: Mutex<TransportProbes>,
    }

    impl fmt::Debug for FakeBackend {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("FakeBackend([REDACTED])")
        }
    }

    fn take_slot<T>(slot: &Mutex<Option<T>>) -> Option<T> {
        slot.lock().unwrap().take()
    }

    impl FakeBackend {
        fn empty() -> Self {
            Self::default()
        }

        async fn wait_for_web_begin(&self) {
            let blocker = self.web_begin_blocker.lock().unwrap().clone();
            if let Some(blocker) = blocker {
                blocker.enter().await;
            }
        }

        fn probes(&self) -> std::sync::MutexGuard<'_, TransportProbes> {
            self.probes.lock().unwrap()
        }

        fn take_web_start(&self) -> Option<BoxedWebLoginStart> {
            take_slot(&self.web_start).map(|start| Box::new(start) as BoxedWebLoginStart)
        }

        fn take_device_start(&self) -> Option<BoxedDeviceLoginStart> {
            take_slot(&self.device_start)
                .map(|start| Box::new(RedactedDeviceLoginStart(start)) as BoxedDeviceLoginStart)
        }

        fn transport_call_count(&self) -> usize {
            let probes = self.probes();
            probes.begin_web.len()
                + probes.begin_setup_web.len()
                + probes.begin_device.len()
                + probes.begin_setup_device.len()
                + probes.poll_device.len()
                + probes.poll_setup_device.len()
        }
    }

    #[async_trait]
    impl GithubAuthBackend for FakeBackend {
        async fn begin_web(
            &self,
            tenant_id: TenantId,
            return_path: LoginReturnPath,
        ) -> SignResult<BoxedWebLoginStart> {
            self.probes().begin_web.push((tenant_id, return_path));
            self.wait_for_web_begin().await;
            self.take_web_start().ok_or(GithubLoginError::Invalid)
        }

        async fn begin_device(
            &self,
            tenant_id: TenantId,
            return_path: Option<LoginReturnPath>,
        ) -> SignResult<BoxedDeviceLoginStart> {
            self.probes().begin_device.push((tenant_id, return_path));
            self.take_device_start().ok_or(GithubLoginError::Invalid)
        }

        async fn poll_device(
            &self,
            tenant_id: TenantId,
            credential: GithubDevicePollCredential,
        ) -> DevicePollResult {
            let credential_matches = credential.expose_secret() == POLL;
            drop(credential);
            self.probes()
                .poll_device
                .push((tenant_id, credential_matches));
            take_slot(&self.device_poll).ok_or(GithubAuthFailure::SignIn(GithubLoginError::Invalid))
        }

        async fn begin_setup_web(
            &self,
            bootstrap_token: SecretString,
            return_path: LoginReturnPath,
        ) -> SetupResult<BoxedWebLoginStart> {
            let observation = observe_bootstrap(&bootstrap_token);
            drop(bootstrap_token);
            self.probes()
                .begin_setup_web
                .push((observation, return_path));
            self.wait_for_web_begin().await;
            self.take_web_start()
                .ok_or(InstallationSetupError::InvalidRequest)
        }

        async fn begin_setup_device(
            &self,
            bootstrap_token: SecretString,
            return_path: Option<LoginReturnPath>,
        ) -> SetupResult<BoxedDeviceLoginStart> {
            let observation = observe_bootstrap(&bootstrap_token);
            drop(bootstrap_token);
            self.probes()
                .begin_setup_device
                .push((observation, return_path));
            self.take_device_start()
                .ok_or(InstallationSetupError::InvalidRequest)
        }

        async fn poll_setup_device(
            &self,
            credential: GithubDevicePollCredential,
        ) -> DevicePollResult {
            let credential_matches = credential.expose_secret() == POLL;
            drop(credential);
            self.probes().poll_setup_device.push(credential_matches);
            take_slot(&self.device_poll).ok_or(GithubAuthFailure::InstallationSetup(
                InstallationSetupError::InvalidRequest,
            ))
        }

        async fn revoke_browser(
            &self,
            raw_credential: &str,
        ) -> SessionResult<RevokeOwnSessionOutcome> {
            self.revoked_credentials
                .lock()
                .unwrap()
                .push(raw_credential.to_owned());
            take_slot(&self.browser_revoke)
                .unwrap_or(Err(SessionCredentialServiceError::InternalFailure))
        }

        async fn revoke_cli(&self, raw_credential: &str) -> SessionResult<RevokeOwnSessionOutcome> {
            self.revoked_credentials
                .lock()
                .unwrap()
                .push(raw_credential.to_owned());
            take_slot(&self.cli_revoke)
                .unwrap_or(Err(SessionCredentialServiceError::InternalFailure))
        }

        async fn activate_cli(
            &self,
            raw_credential: &str,
        ) -> SessionResult<ActivateCliSessionOutcome> {
            self.activated_credentials
                .lock()
                .unwrap()
                .push(raw_credential.to_owned());
            take_slot(&self.cli_activation)
                .unwrap_or(Err(SessionCredentialServiceError::InternalFailure))
        }

        async fn complete_web(
            &self,
            _tenant_id: TenantId,
            _binding: GithubBrowserBindingCookie,
            _callback: GithubWebCallback,
        ) -> Result<WebCallbackCompletion, WebCallbackError> {
            take_slot(&self.web_completion)
                .unwrap_or(Err(WebCallbackError::SignIn(GithubLoginError::Invalid)))
        }
    }

    fn test_transport(
        backend: Arc<dyn GithubAuthBackend>,
        begin_admission: Arc<GithubBeginAdmission>,
    ) -> GithubAuthTransportState {
        GithubAuthTransportState::new(
            backend,
            begin_admission,
            HumanAuthOrigin::new(&Url::parse("https://ci.example/").unwrap()).unwrap(),
            GithubProviderOrigin::new(&Url::parse("https://github.example/login").unwrap())
                .unwrap(),
            LoginReturnPath::new("/").unwrap(),
            Arc::new(FixedClock(NOW)),
        )
    }

    fn begin_admission() -> Arc<GithubBeginAdmission> {
        Arc::new(GithubBeginAdmission::new(Arc::new(
            ProcessMonotonicClock::new(),
        )))
    }

    fn state(backend: Arc<FakeBackend>) -> GithubAuthHttpState {
        state_with_admission(backend, begin_admission())
    }

    fn state_with_admission(
        backend: Arc<FakeBackend>,
        begin_admission: Arc<GithubBeginAdmission>,
    ) -> GithubAuthHttpState {
        GithubAuthHttpState {
            transport: test_transport(backend, begin_admission),
            tenant_id: TenantId::new("tenant-a").unwrap(),
        }
    }

    fn durable_session(
        tenant: &TenantId,
        principal: &PrincipalId,
        kind: SessionKind,
    ) -> DurableSession {
        let identity = DurableSessionIdentity::new(
            SessionId::new("44444444-4444-4444-8444-444444444444").unwrap(),
            tenant.clone(),
            principal.clone(),
            ProviderId::new("github").unwrap(),
            ProviderSubject::new("1234567").unwrap(),
            kind,
        )
        .unwrap();
        DurableSession::new(
            identity,
            7,
            UnixTimestamp::from_seconds(NOW - 1_000),
            UnixTimestamp::from_seconds(NOW - 10),
            UnixTimestamp::from_seconds(NOW + 1_000),
            UnixTimestamp::from_seconds(NOW + 2_000),
            None,
        )
        .unwrap()
    }

    fn cli_snapshot() -> AuthenticatedRequestSnapshot {
        let tenant = TenantId::new("tenant-a").unwrap();
        let principal = PrincipalId::new("33333333-3333-4333-8333-333333333333").unwrap();
        let provider = ProviderId::new("github").unwrap();
        let subject = ProviderSubject::new("1234567").unwrap();
        let session = durable_session(&tenant, &principal, SessionKind::Cli);
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

    fn request(
        method: &str,
        path: &str,
        content_type: Option<&str>,
        body: impl Into<Body>,
    ) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(content_type) = content_type {
            builder = builder.header(CONTENT_TYPE, content_type);
        }
        builder.body(body.into()).unwrap()
    }

    fn json_post(path: &str, body: impl Into<Body>) -> Request<Body> {
        request("POST", path, Some("application/json"), body)
    }

    fn empty_request(method: &str, path: &str) -> Request<Body> {
        request(method, path, None, Body::empty())
    }

    async fn send(app: &Router, request: Request<Body>) -> Response {
        app.clone().oneshot(request).await.unwrap()
    }

    fn browser_post(path: &str, content_type: &str, body: impl Into<Body>) -> Request<Body> {
        let mut request = request("POST", path, Some(content_type), body);
        request
            .headers_mut()
            .insert(ORIGIN, HeaderValue::from_static("https://ci.example"));
        request
            .headers_mut()
            .insert(SEC_FETCH_SITE, HeaderValue::from_static("same-origin"));
        request
    }

    fn browser_begin_request() -> Request<Body> {
        browser_post(
            GITHUB_WEB_BEGIN_PATH,
            "application/json",
            r#"{"return_path":null}"#,
        )
    }

    fn browser_form_request(body: impl Into<Body>) -> Request<Body> {
        browser_post(
            GITHUB_WEB_BEGIN_PATH,
            "application/x-www-form-urlencoded",
            body,
        )
    }

    async fn setup_form_response(app: &Router, body: impl Into<Body>) -> Response {
        send(
            app,
            browser_post(
                GITHUB_SETUP_WEB_BEGIN_PATH,
                "application/x-www-form-urlencoded",
                body,
            ),
        )
        .await
    }

    fn bearer_request(method: &str, path: &str) -> Request<Body> {
        let mut request = empty_request(method, path);
        request.headers_mut().insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {SESSION}")).unwrap(),
        );
        request
    }

    fn setup_state(backend: Arc<FakeBackend>) -> GithubSetupHttpState {
        setup_state_with_admission(backend, begin_admission())
    }

    fn setup_state_with_admission(
        backend: Arc<FakeBackend>,
        begin_admission: Arc<GithubBeginAdmission>,
    ) -> GithubSetupHttpState {
        GithubSetupHttpState {
            transport: test_transport(backend, begin_admission),
        }
    }

    fn renderer_flow_transports() -> [(GithubAuthTransportState, String, u64); 2] {
        [("sign", NOW), ("setup", NOW + 1_000)].map(|(flow, now)| {
            let application = format!("https://{flow}.example");
            let provider = format!("https://github-{flow}.example/login");
            let mut transport = test_transport(Arc::new(FakeBackend::empty()), begin_admission());
            transport.application_origin =
                HumanAuthOrigin::new(&Url::parse(&format!("{application}/")).unwrap()).unwrap();
            transport.provider_origin =
                GithubProviderOrigin::new(&Url::parse(&provider).unwrap()).unwrap();
            transport.clock = Arc::new(FixedClock(now));
            let selected_provider = Url::parse(&format!("{provider}/selection")).unwrap();
            assert_eq!(transport.application_origin.as_str(), application);
            assert!(transport.provider_origin.trusts(&selected_provider));
            assert_eq!(transport.clock.now().as_seconds(), now);
            (transport, provider, now)
        })
    }

    fn web_start(url: &str, expires_at: u64) -> TestWebLoginStart {
        TestWebLoginStart(
            Url::parse(url).unwrap(),
            SecretString::new(BINDING).unwrap(),
            UnixTimestamp::from_seconds(expires_at),
        )
    }

    fn trusted_web_start() -> TestWebLoginStart {
        web_start(
            &format!("https://github.example/login/oauth?state={STATE}"),
            NOW + 300,
        )
    }

    fn device_start(uri: &str, interval: Duration, expires_at: u64) -> TestDeviceLoginStart {
        TestDeviceLoginStart(
            SecretString::new(POLL).unwrap(),
            SecretString::new("ABCD-EFGH").unwrap(),
            Url::parse(uri).unwrap(),
            UnixTimestamp::from_seconds(expires_at),
            interval,
        )
    }

    fn trusted_device_start() -> TestDeviceLoginStart {
        device_start(
            "https://github.example/login/device",
            Duration::from_secs(5),
            NOW + 900,
        )
    }

    fn device_completion(path: Option<&str>, expires_at: u64) -> DevicePollOutcome {
        DevicePollOutcome::Complete(DeviceLoginCompletion {
            credential: SessionCredential::from_raw(SESSION).unwrap(),
            expires_at: UnixTimestamp::from_seconds(expires_at),
            return_path: path.map(|path| LoginReturnPath::new(path).unwrap()),
        })
    }

    fn device_start_body(uri: &str, now: u64) -> String {
        format!(
            r#"{{"poll_credential":"{POLL}","user_code":"ABCD-EFGH","verification_uri":"{uri}","expires_at":{},"expires_in_seconds":900,"poll_interval_seconds":5}}"#,
            now + 900
        )
    }

    fn device_completion_body(path: Option<&str>, expires_at: u64) -> String {
        let path = path.map_or_else(|| "null".to_owned(), |path| format!(r#""{path}""#));
        format!(
            r#"{{"status":"complete","next_poll_at":null,"credential":"{SESSION}","expires_at":{expires_at},"return_path":{path}}}"#
        )
    }

    fn callback_request(method: &str, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(COOKIE, format!("__Host-automata-login={BINDING}"))
            .body(Body::empty())
            .unwrap()
    }

    fn callback_completion(setup: bool, return_path: &str) -> WebCallbackCompletion {
        let completion = WebLoginCompletion {
            credential: SessionCredential::from_raw(SESSION).unwrap(),
            csrf: CsrfToken::from_generated_secret(SecretString::new(CSRF).unwrap()).unwrap(),
            expires_at: UnixTimestamp::from_seconds(NOW + 3_600),
            return_path: Some(LoginReturnPath::new(return_path).unwrap()),
        };
        if setup {
            WebCallbackCompletion::InstallationSetup(completion)
        } else {
            WebCallbackCompletion::SignIn(completion)
        }
    }

    async fn response_text(response: Response) -> String {
        let body = to_bytes(response.into_body(), 64 * 1_024).await.unwrap();
        String::from_utf8(body.to_vec()).unwrap()
    }

    fn assert_auth_security_headers(response: &Response) {
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[REFERRER_POLICY], "no-referrer");
        assert_eq!(response.headers()[X_CONTENT_TYPE_OPTIONS], "nosniff");
    }

    async fn assert_exact_json(response: Response, status: u16, retry: Option<&str>, body: &str) {
        assert_eq!(response.status().as_u16(), status);
        let headers = response.headers();
        assert_eq!(headers[CONTENT_TYPE], "application/json; charset=utf-8");
        assert_auth_security_headers(&response);
        assert_eq!(
            headers
                .get(RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            retry
        );
        assert_eq!(response_text(response).await, body);
    }

    fn assert_web_start_redirect(response: &Response, expected_location: &str) {
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = &response.headers()[LOCATION];
        assert_eq!(location, expected_location);
        assert!(location.is_sensitive());
        let cookie = &response.headers()[SET_COOKIE];
        assert!(cookie.is_sensitive());
        let cookie = cookie.to_str().unwrap();
        assert!(cookie.contains(BINDING));
        assert!(cookie.contains("Secure; HttpOnly; SameSite=Lax"));
        assert_auth_security_headers(response);
    }

    fn assert_callback_cookies(response: &Response) {
        let cookies = response.headers().get_all(SET_COOKIE);
        assert_eq!(cookies.iter().count(), 3);
        assert!(cookies.iter().all(HeaderValue::is_sensitive));
        for secret in [SESSION, CSRF] {
            assert_eq!(
                cookies
                    .iter()
                    .filter(|cookie| cookie.to_str().unwrap().contains(secret))
                    .count(),
                1
            );
        }
        assert!(cookies.iter().any(|cookie| {
            let cookie = cookie.to_str().unwrap();
            cookie.starts_with("__Host-automata-login=;") && cookie.contains("Max-Age=0")
        }));
    }

    fn logout_app(backend: Arc<FakeBackend>) -> Router {
        let credential = SessionCredential::from_raw(SESSION).expect("browser credential");
        router(state(backend)).layer(Extension(Arc::new(BrowserLogoutCredential::new(
            credential,
        ))))
    }

    #[test]
    fn native_logout_form_is_exact_and_bounded() {
        use axum::http::Method;
        for (method, path, valid) in [
            (Method::POST, GITHUB_WEB_LOGOUT_PATH, true),
            (Method::GET, GITHUB_WEB_LOGOUT_PATH, false),
            (Method::POST, "/auth/logout/", false),
        ] {
            assert_eq!(is_browser_logout_form(&method, path), valid);
        }

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
    async fn browser_logout_outcomes_preserve_exact_authority_and_representation() {
        use RevokeOwnSessionOutcome as R;
        use SessionCredentialServiceError as E;
        use StatusCode as S;

        let cases = [
            (Ok(R::Revoked), S::SEE_OTHER, None),
            (Ok(R::AlreadyRevoked), S::SEE_OTHER, None),
            (Ok(R::NotFound), S::SEE_OTHER, None),
            (
                Err(E::RepositoryUnavailable),
                S::SERVICE_UNAVAILABLE,
                Some("Sign out temporarily unavailable"),
            ),
            (
                Err(E::InternalFailure),
                S::INTERNAL_SERVER_ERROR,
                Some("Unable to sign out"),
            ),
        ];
        for (outcome, status, heading) in cases {
            let backend = Arc::new(FakeBackend::empty());
            *backend.browser_revoke.lock().unwrap() = Some(outcome);
            let response = send(
                &logout_app(Arc::clone(&backend)),
                empty_request("POST", GITHUB_WEB_LOGOUT_PATH),
            )
            .await;

            assert_eq!(response.status(), status);
            let completed = response
                .extensions()
                .get::<BrowserLogoutCompleted>()
                .is_some();
            assert_eq!(completed, heading.is_none());
            assert!(!response.headers().contains_key(SET_COOKIE));
            assert_eq!(
                *backend.revoked_credentials.lock().unwrap(),
                [SESSION.to_owned()]
            );
            if status == S::SEE_OTHER {
                assert_eq!(response.headers()[LOCATION], "/repositories");
            } else if status == S::SERVICE_UNAVAILABLE {
                assert_eq!(response.headers()[RETRY_AFTER], "1");
            }
            if let Some(heading) = heading {
                assert!(response_text(response).await.contains(heading));
            }
        }

        for (authorized, method, path, status) in [
            (
                true,
                "POST",
                "/auth/logout?return_path=%2Fsettings",
                S::BAD_REQUEST,
            ),
            (
                false,
                "POST",
                GITHUB_WEB_LOGOUT_PATH,
                S::INTERNAL_SERVER_ERROR,
            ),
            (false, "GET", GITHUB_WEB_LOGOUT_PATH, S::METHOD_NOT_ALLOWED),
        ] {
            let backend = Arc::new(FakeBackend::empty());
            *backend.browser_revoke.lock().unwrap() = Some(Ok(R::Revoked));
            let app = if authorized {
                logout_app(Arc::clone(&backend))
            } else {
                router(state(Arc::clone(&backend)))
            };
            let response = send(&app, empty_request(method, path)).await;
            assert_eq!(response.status(), status);
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
        let sign_app = router(state_with_admission(
            Arc::clone(&backend),
            Arc::clone(&admission),
        ));

        let mut starts = Vec::new();
        for _ in 0..MAX_CONCURRENT_GITHUB_BEGINS {
            let app = sign_app.clone();
            starts.push(tokio::spawn(async move {
                send(&app, browser_begin_request()).await
            }));
        }
        blocker.wait_for_entries(MAX_CONCURRENT_GITHUB_BEGINS).await;

        let overloaded = send(&sign_app, browser_begin_request()).await;
        assert_eq!(overloaded.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            backend.probes.lock().unwrap().begin_web.len(),
            MAX_CONCURRENT_GITHUB_BEGINS
        );

        blocker.release.add_permits(MAX_CONCURRENT_GITHUB_BEGINS);
        for start in starts {
            assert_eq!(start.await.unwrap().status(), StatusCode::BAD_REQUEST);
        }
        *backend.web_begin_blocker.lock().unwrap() = None;
        let recovered = send(&sign_app, browser_begin_request()).await;
        assert_eq!(recovered.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            backend.probes.lock().unwrap().begin_web.len(),
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
        let sign_app = router(state_with_admission(
            Arc::clone(&backend),
            Arc::clone(&admission),
        ));
        let setup_app = setup_router(setup_state_with_admission(Arc::clone(&backend), admission));

        let mut invalid_origin = browser_begin_request();
        invalid_origin.headers_mut().remove(SEC_FETCH_SITE);
        invalid_origin
            .headers_mut()
            .insert(ORIGIN, HeaderValue::from_static("https://attacker.example"));
        let invalid = send(&sign_app, invalid_origin).await;
        assert_eq!(invalid.status(), StatusCode::FORBIDDEN);
        let setup_document =
            format!(r#"{{"bootstrap_token":"{BOOTSTRAP_SENTINEL}","return_path":null}}"#);
        let cases = [
            (sign_app.clone(), GITHUB_WEB_BEGIN_PATH, true, false),
            (sign_app, GITHUB_DEVICE_BEGIN_PATH, false, false),
            (setup_app.clone(), GITHUB_SETUP_WEB_BEGIN_PATH, true, true),
            (setup_app, GITHUB_SETUP_DEVICE_BEGIN_PATH, false, true),
        ];
        for (app, path, browser, setup) in cases {
            let body = if setup {
                setup_document.clone()
            } else {
                r#"{"return_path":null}"#.to_owned()
            };
            let request = if browser {
                browser_post(path, "application/json", body)
            } else {
                json_post(path, body)
            };
            let response = send(&app, request).await;
            if browser {
                assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
                assert_eq!(response.headers()[RETRY_AFTER], "1");
                assert!(
                    response.headers()[CONTENT_TYPE]
                        .to_str()
                        .unwrap()
                        .starts_with("text/html")
                );
            } else {
                assert_exact_json(response, 429, Some("1"), r#"{"error":"rate_limited"}"#).await;
            }
        }
        assert_eq!(backend.transport_call_count(), 0);
    }

    #[tokio::test]
    async fn start_renderers_select_each_flow_and_share_one_integrity_matrix() {
        for (transport, provider, now) in renderer_flow_transports() {
            let trusted_web = format!("{provider}/oauth?state={STATE}");
            let trusted_device = format!("{provider}/device");
            let credentialed = provider.replacen("https://", "https://user@", 1);
            let device_body = device_start_body(&trusted_device, now);
            let cases = [
                (provider.as_str(), "", now + 900, true),
                ("https://evil.example", "", now + 900, false),
                (credentialed.as_str(), "", now + 900, false),
                (provider.as_str(), "#secret", now + 900, false),
                (provider.as_str(), "", now, false),
            ];
            for (authority, fragment, expires_at, valid) in cases {
                let web_url = format!("{authority}/oauth?state={STATE}{fragment}");
                let start = web_start(&web_url, expires_at);
                let response = web_start_response(&transport, &start);
                if valid {
                    assert_web_start_redirect(&response, &trusted_web);
                } else {
                    assert_exact_json(response, 500, None, r#"{"error":"internal_error"}"#).await;
                }

                let device_url = format!("{authority}/device{fragment}");
                let start = device_start(&device_url, Duration::from_secs(5), expires_at);
                let response = device_start_response(&transport, &start);
                let (status, body) = if valid {
                    (200, device_body.as_str())
                } else {
                    (500, r#"{"error":"internal_error"}"#)
                };
                assert_exact_json(response, status, None, body).await;
            }
            for interval in [Duration::ZERO, Duration::new(5, 1)] {
                let start = device_start(&trusted_device, interval, now + 900);
                let response = device_start_response(&transport, &start);
                assert_exact_json(response, 500, None, r#"{"error":"internal_error"}"#).await;
            }
        }
    }

    #[tokio::test]
    async fn browser_begin_success_matrix_routes_exact_paths_and_authority() {
        for setup in [false, true] {
            let backend = Arc::new(FakeBackend::empty());
            *backend.web_start.lock().unwrap() = Some(trusted_web_start());
            let (app, request, expected_path) = if setup {
                (
                    setup_router(setup_state(Arc::clone(&backend))),
                    browser_post(
                        GITHUB_SETUP_WEB_BEGIN_PATH,
                        "application/json",
                        format!(
                            r#"{{"bootstrap_token":"{BOOTSTRAP_SENTINEL}","return_path":null}}"#
                        ),
                    ),
                    "/",
                )
            } else {
                (
                    router(state(Arc::clone(&backend))),
                    browser_form_request(
                        "return_path=%2Facme%2Fcaf%C3%A9%2Factions%3Fstatus%3Dfailed",
                    ),
                    "/acme/caf%C3%A9/actions?status=failed",
                )
            };
            let response = send(&app, request).await;

            assert_web_start_redirect(
                &response,
                &format!("https://github.example/login/oauth?state={STATE}"),
            );
            assert!(!format!("{response:?}").contains(BOOTSTRAP_SENTINEL));
            let body = response_text(response).await;
            let probes = backend.probes();
            let expected = LoginReturnPath::new(expected_path).unwrap();
            if setup {
                assert_eq!(probes.begin_setup_web.len(), 1);
                assert!(probes.begin_setup_web[0].0.0);
                assert_eq!(probes.begin_setup_web[0].1, expected);
            } else {
                assert_eq!(
                    probes.begin_web,
                    [(TenantId::new("tenant-a").unwrap(), expected)]
                );
            }
            assert!(!body.contains(BOOTSTRAP_SENTINEL));
        }
    }

    #[tokio::test]
    async fn browser_begin_rejects_empty_duplicate_unknown_and_untrusted_native_forms() {
        let backend = Arc::new(FakeBackend::empty());
        let app = router(state(Arc::clone(&backend)));
        for body in [
            "",
            "return_path=%2Fruns&return_path=%2Fother",
            "next=%2Fruns",
            "return_path=https%3A%2F%2Fevil.example%2F",
            "return_path=%",
            "return_path=%2F%FF",
        ] {
            let response = send(&app, browser_form_request(body)).await;

            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "body {body:?}");
        }
        assert_eq!(backend.transport_call_count(), 0);
    }

    #[tokio::test]
    async fn browser_origin_rejection_precedes_body_for_both_flows() {
        let backend = Arc::new(FakeBackend::empty());
        let cases = [
            (router(state(Arc::clone(&backend))), GITHUB_WEB_BEGIN_PATH),
            (
                setup_router(setup_state(Arc::clone(&backend))),
                GITHUB_SETUP_WEB_BEGIN_PATH,
            ),
        ];
        for (app, path) in cases {
            let polls = Arc::new(AtomicUsize::new(0));
            let observed_polls = Arc::clone(&polls);
            let body = Body::from_stream(futures::stream::poll_fn(move |_| {
                observed_polls.fetch_add(1, Ordering::SeqCst);
                Poll::Ready(Some(Ok::<_, Infallible>(Bytes::from_static(
                    b"body-secret",
                ))))
            }));
            let mut request = browser_post(path, "application/x-www-form-urlencoded", body);
            request
                .headers_mut()
                .insert(ORIGIN, HeaderValue::from_static("https://attacker.example"));
            request
                .headers_mut()
                .insert(SEC_FETCH_SITE, HeaderValue::from_static("cross-site"));
            let response = send(&app, request).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_eq!(polls.load(Ordering::SeqCst), 0);
        }
        assert_eq!(backend.transport_call_count(), 0);
    }

    #[test]
    fn browser_login_initiation_accepts_either_browser_same_origin_or_exact_origin() {
        let expected = HumanAuthOrigin::new(&Url::parse("https://ci.example/").unwrap()).unwrap();
        for (site, origin, valid) in [
            (Some("same-origin"), None, true),
            (None, Some("https://ci.example"), true),
            (Some("cross-site"), Some("https://ci.example"), false),
            (Some("same-site"), Some("https://other.example"), false),
            (None, None, false),
        ] {
            let mut headers = HeaderMap::new();
            if let Some(site) = site {
                headers.insert(SEC_FETCH_SITE, HeaderValue::from_str(site).unwrap());
            }
            if let Some(origin) = origin {
                headers.insert(ORIGIN, HeaderValue::from_str(origin).unwrap());
            }
            assert_eq!(valid_login_initiation(&headers, &expected), valid);
        }
    }

    #[tokio::test]
    async fn setup_browser_form_rejects_closed_grammar_before_backend_use() {
        let backend = Arc::new(FakeBackend::empty());
        let app = setup_router(setup_state(Arc::clone(&backend)));
        let token = BOOTSTRAP_SENTINEL;
        for body in [
            String::new(),
            format!("bootstrap_token={token}"),
            "return_path=%2Fruns".to_owned(),
            "bootstrap_token=&return_path=%2Fruns".to_owned(),
            format!("bootstrap_token={token}&return_path="),
            format!("bootstrap_token={token}&bootstrap_token={token}&return_path=%2Fruns"),
            format!("bootstrap_token={token}&return_path=%2Fruns&return_path=%2Fother"),
            format!("bootstrap_token={token}&return_path=%2Fruns&unknown={token}"),
            format!("%62ootstrap_token={token}&return_path=%2Fruns"),
            "bootstrap_token=%&return_path=%2Fruns".to_owned(),
            "bootstrap_token=%FF&return_path=%2Fruns".to_owned(),
            format!("bootstrap_token={token}&return_path=%"),
            format!("bootstrap_token={token}&return_path=%2F%FF"),
            format!("bootstrap_token={token}&return_path=https%3A%2F%2Fevil.example%2F"),
        ] {
            let response = setup_form_response(&app, body).await;

            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert!(!format!("{response:?}").contains(BOOTSTRAP_SENTINEL));
            assert!(!response_text(response).await.contains(BOOTSTRAP_SENTINEL));
        }

        let response = send(
            &app,
            browser_post(
                &format!("{GITHUB_SETUP_WEB_BEGIN_PATH}?unexpected=1"),
                "application/x-www-form-urlencoded",
                format!("bootstrap_token={BOOTSTRAP_SENTINEL}&return_path=%2Fruns"),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(backend.transport_call_count(), 0);
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

        let backend = Arc::new(FakeBackend::empty());
        *backend.web_start.lock().unwrap() = Some(trusted_web_start());
        let app = setup_router(setup_state(Arc::clone(&backend)));
        let response = setup_form_response(&app, exact.clone()).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let oversized = setup_form_response(&app, format!("{exact}x")).await;
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(backend.transport_call_count(), 1);
        let probes = backend.probes.lock().unwrap();
        assert_eq!(probes.begin_setup_web.len(), 1);
        let (matches_sentinel, decoded_len, all_x) = probes.begin_setup_web[0].0;
        assert!(!matches_sentinel);
        assert_eq!(decoded_len, MAX_SETUP_BOOTSTRAP_TOKEN_BYTES);
        assert!(all_x);
        assert_eq!(
            probes.begin_setup_web[0].1.as_str().len(),
            MAX_SETUP_RETURN_PATH_BYTES
        );
    }

    #[tokio::test]
    async fn callback_head_is_hardened_and_never_consumes_sign_in_or_setup_state() {
        let callback_uri = format!("{GITHUB_WEB_CALLBACK_PATH}?code=provider-secret&state={STATE}");
        for (setup, return_path, expected_location) in [
            (
                false,
                "/café/runs?q=failed build",
                "/caf%C3%A9/runs?q=failed%20build",
            ),
            (true, "/settings/access/users", "/settings/access/users"),
        ] {
            let backend = Arc::new(FakeBackend::empty());
            *backend.web_completion.lock().unwrap() =
                Some(Ok(callback_completion(setup, return_path)));
            let app = router(state(Arc::clone(&backend)));
            let response = send(&app, callback_request("HEAD", &callback_uri)).await;

            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(response.headers()[axum::http::header::ALLOW], "GET");
            assert_auth_security_headers(&response);
            assert!(response.headers().get(SET_COOKIE).is_none());
            assert!(backend.web_completion.lock().unwrap().is_some());
            assert!(!format!("{response:?}").contains("provider-secret"));
            assert!(to_bytes(response.into_body(), 1).await.unwrap().is_empty());

            let response = send(&app, callback_request("GET", &callback_uri)).await;
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            assert_eq!(response.headers()[LOCATION], expected_location);
            assert!(response.headers()[LOCATION].is_sensitive());
            assert_callback_cookies(&response);
            assert!(backend.web_completion.lock().unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn callback_failures_clear_binding_and_keep_exact_redacted_codes() {
        let setup_error = Err(WebCallbackError::InstallationSetup(
            InstallationSetupError::AlreadyConfigured,
        ));
        for (completion, query, status, expected_body) in [
            (
                None,
                format!("code=provider-secret&state={STATE}&state={STATE}"),
                400,
                r#"{"error":"invalid_callback"}"#,
            ),
            (
                Some(setup_error),
                format!("code=provider-secret&state={STATE}"),
                410,
                r#"{"error":"setup_complete"}"#,
            ),
        ] {
            let backend = Arc::new(FakeBackend::empty());
            *backend.web_completion.lock().unwrap() = completion;
            let uri = format!("{GITHUB_WEB_CALLBACK_PATH}?{query}");
            let response = send(&router(state(backend)), callback_request("GET", &uri)).await;
            assert!(response.headers().get_all(SET_COOKIE).iter().any(|value| {
                let cookie = value.to_str().unwrap();
                cookie.starts_with("__Host-automata-login=;") && cookie.contains("Max-Age=0")
            }));
            assert_exact_json(response, status, None, expected_body).await;
        }
    }

    #[tokio::test]
    async fn device_routes_dispatch_exact_methods_and_setup_poll_completes() {
        let backend = Arc::new(FakeBackend::empty());
        for setup in [false, true] {
            *backend.device_start.lock().unwrap() = Some(trusted_device_start());
            *backend.device_poll.lock().unwrap() = Some(device_completion(
                setup.then_some("/setup-finished"),
                NOW + 86_400,
            ));
            let (begin_path, poll_path) = if setup {
                (
                    GITHUB_SETUP_DEVICE_BEGIN_PATH,
                    GITHUB_SETUP_DEVICE_POLL_PATH,
                )
            } else {
                (GITHUB_DEVICE_BEGIN_PATH, GITHUB_DEVICE_POLL_PATH)
            };
            let begin_body = if setup {
                format!(
                    r#"{{"bootstrap_token":"{BOOTSTRAP_SENTINEL}","return_path":"/setup-cli"}}"#
                )
            } else {
                r#"{"return_path":null}"#.to_owned()
            };
            let app = if setup {
                setup_router(setup_state(Arc::clone(&backend)))
            } else {
                router(state(Arc::clone(&backend)))
            };

            let begin = send(&app, json_post(begin_path, begin_body)).await;
            assert_exact_json(
                begin,
                200,
                None,
                &device_start_body("https://github.example/login/device", NOW),
            )
            .await;

            let poll = send(
                &app,
                json_post(poll_path, format!(r#"{{"poll_credential":"{POLL}"}}"#)),
            )
            .await;
            assert_exact_json(
                poll,
                200,
                None,
                &device_completion_body(setup.then_some("/setup-finished"), NOW + 86_400),
            )
            .await;
        }

        let probes = backend.probes();
        let tenant = TenantId::new("tenant-a").unwrap();
        assert_eq!(probes.begin_device, [(tenant.clone(), None)]);
        assert_eq!(probes.poll_device, [(tenant, true)]);
        assert_eq!(probes.begin_setup_device.len(), 1);
        assert!(probes.begin_setup_device[0].0.0);
        assert_eq!(
            probes.begin_setup_device[0].1,
            Some(LoginReturnPath::new("/setup-cli").unwrap())
        );
        assert_eq!(probes.poll_setup_device, [true]);
    }

    #[tokio::test]
    async fn device_poll_outcomes_have_one_exact_matrix_for_both_flows() {
        type Case = (DevicePollOutcome, u16, Option<&'static str>, String);
        fn waiting(slow: bool, next: u64, retry: &'static str) -> Case {
            let status = if slow { "slow_down" } else { "pending" };
            let next_poll_at = UnixTimestamp::from_seconds(next);
            let outcome = if slow {
                DevicePollOutcome::SlowDown { next_poll_at }
            } else {
                DevicePollOutcome::Pending { next_poll_at }
            };
            let body = format!(
                r#"{{"status":"{status}","next_poll_at":{next},"credential":null,"expires_at":null,"return_path":null}}"#
            );
            (outcome, 202, Some(retry), body)
        }
        fn completed(expires: u64, path: Option<&str>, valid: bool) -> Case {
            let body = if valid {
                device_completion_body(path, expires)
            } else {
                r#"{"error":"internal_error"}"#.to_owned()
            };
            let status = if valid { 200 } else { 500 };
            (device_completion(path, expires), status, None, body)
        }
        fn terminal(outcome: DevicePollOutcome, status: u16, code: &'static str) -> Case {
            (outcome, status, None, format!(r#"{{"error":"{code}"}}"#))
        }

        for (transport, _provider, now) in renderer_flow_transports() {
            let cases = [
                waiting(false, now + 5, "5"),
                waiting(true, now + 9, "9"),
                completed(now + 60, None, true),
                completed(now + 60, Some("/stored?x=1"), true),
                terminal(DevicePollOutcome::Denied, 403, "authorization_denied"),
                terminal(DevicePollOutcome::Expired, 410, "authorization_expired"),
                completed(now, None, false),
                completed(now + 60, Some(r"/\attacker.example"), false),
                terminal(DevicePollOutcome::InvalidCompletion, 500, "internal_error"),
            ];
            for (outcome, status, retry, body) in cases {
                let response = device_poll_response(&transport, outcome, transport.clock.now());
                assert_exact_json(response, status, retry, &body).await;
            }
        }
    }

    #[tokio::test]
    async fn no_query_routes_reject_queries_before_backend_dispatch() {
        let backend = Arc::new(FakeBackend::empty());
        let app = router(state(Arc::clone(&backend)));
        for suffix in ["?ignored=1", "?"] {
            let response = send(
                &app,
                json_post(
                    &format!("{GITHUB_DEVICE_BEGIN_PATH}{suffix}"),
                    r#"{"return_path":null}"#,
                ),
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        assert_eq!(backend.transport_call_count(), 0);
    }

    #[tokio::test]
    async fn router_generated_responses_keep_auth_security_headers() {
        let app = router(state(Arc::new(FakeBackend::empty())));
        let response = send(&app, empty_request("GET", GITHUB_DEVICE_BEGIN_PATH)).await;

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_auth_security_headers(&response);
    }

    #[tokio::test]
    async fn cli_session_status_exposes_only_safe_current_metadata() {
        let app = router(state(Arc::new(FakeBackend::empty()))).layer(Extension(cli_snapshot()));
        for request in [
            request("GET", CLI_SESSION_PATH, None, "ignored"),
            request(
                "GET",
                CLI_SESSION_PATH,
                Some("application/json"),
                Body::empty(),
            ),
        ] {
            let response = send(&app, request).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        let response = send(&app, empty_request("GET", CLI_SESSION_PATH)).await;

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

        let query = send(
            &app,
            bearer_request("POST", &format!("{CLI_SESSION_PATH}?unexpected=1")),
        )
        .await;
        assert_eq!(query.status(), StatusCode::BAD_REQUEST);
        assert!(backend.activated_credentials.lock().unwrap().is_empty());

        let response = send(&app, bearer_request("POST", CLI_SESSION_PATH)).await;
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

        let query = send(
            &app,
            empty_request("DELETE", &format!("{CLI_SESSION_PATH}?unexpected=1")),
        )
        .await;
        assert_eq!(query.status(), StatusCode::BAD_REQUEST);
        assert!(backend.revoked_credentials.lock().unwrap().is_empty());

        let payload = send(&app, request("DELETE", CLI_SESSION_PATH, None, "ignored")).await;
        assert_eq!(payload.status(), StatusCode::BAD_REQUEST);
        assert!(backend.revoked_credentials.lock().unwrap().is_empty());

        let response = send(&app, empty_request("DELETE", CLI_SESSION_PATH)).await;
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
        let start = device_start(
            "https://github.example/login/device?user_code=query-secret",
            Duration::from_secs(5),
            NOW + 60,
        );
        let debug = format!("{:?}", RedactedDeviceLoginStart(start));
        assert!(!debug.contains(POLL));
        assert!(!debug.contains("ABCD-EFGH"));
        assert!(!debug.contains("query-secret"));
        assert!(debug.contains("verification_query: \"[REDACTED]\""));
    }

    #[test]
    fn completion_mappers_preserve_authority_and_failure_logging_boundary() {
        let tenant = TenantId::new("tenant-a").unwrap();
        let other = TenantId::new("tenant-b").unwrap();
        let principal = PrincipalId::new("33333333-3333-4333-8333-333333333333").unwrap();
        for (setup, session_tenant, kind, expected) in [
            (false, &tenant, SessionKind::Cli, "complete"),
            (false, &other, SessionKind::Cli, "sign_in_integrity"),
            (false, &tenant, SessionKind::Browser, "sign_in_integrity"),
            (true, &other, SessionKind::Cli, "complete"),
            (true, &tenant, SessionKind::Browser, "invalid_completion"),
        ] {
            let credential = SessionCredential::from_raw(SESSION).unwrap();
            let session = Box::new(durable_session(session_tenant, &principal, kind));
            let result = if setup {
                Ok(map_setup_device_completion(credential, &session, None))
            } else {
                map_sign_in_device_completion(&tenant, credential, &session, None)
            };
            let enters_failure_logging = result.is_err();
            let actual = match result {
                Ok(DevicePollOutcome::Complete(_)) => "complete",
                Ok(DevicePollOutcome::InvalidCompletion) => "invalid_completion",
                Err(GithubAuthFailure::SignIn(GithubLoginError::IntegrityFailure)) => {
                    "sign_in_integrity"
                }
                other => panic!("unexpected completion mapping: {other:?}"),
            };
            assert_eq!(actual, expected);
            assert_eq!(enters_failure_logging, expected == "sign_in_integrity");
        }
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

    #[tokio::test]
    async fn auth_failures_have_one_exact_wire_matrix() {
        use GithubAuthFailure::{InstallationSetup as Setup, SignIn};
        use GithubLoginError as G;
        use InstallationSetupError as I;

        macro_rules! poll {
            ($error:ident, $at:expr) => {
                $error::PollTooEarly {
                    next_poll_at: UnixTimestamp::from_seconds($at),
                }
            };
        }
        macro_rules! rate {
            ($error:ident, $retry:expr) => {
                $error::RateLimited {
                    retry_after_seconds: $retry,
                }
            };
        }

        let sign_in = [
            (G::Invalid, 400, "invalid_request", None),
            (G::Replay, 409, "request_replayed", None),
            (G::Expired, 410, "request_expired", None),
            (G::Denied, 403, "authorization_denied", None),
            (poll!(G, NOW - 1), 429, "poll_too_early", Some("1")),
            (poll!(G, NOW + 7), 429, "poll_too_early", Some("7")),
            (rate!(G, None), 429, "rate_limited", None),
            (rate!(G, Some(0)), 429, "rate_limited", Some("1")),
            (rate!(G, Some(9)), 429, "rate_limited", Some("9")),
            (G::ProviderUnavailable, 503, "unavailable", Some("1")),
            (G::StorageUnavailable, 503, "unavailable", Some("1")),
            (G::RandomnessUnavailable, 503, "unavailable", Some("1")),
            (G::CollisionLimitExceeded, 503, "unavailable", Some("1")),
            (G::NotAuthorized, 403, "not_authorized", None),
            (G::IntegrityFailure, 500, "internal_error", None),
        ];
        let setup = [
            (I::InvalidRequest, 400, "invalid_request", None),
            (I::InvalidProof, 403, "setup_proof_rejected", None),
            (I::NotArmed, 409, "setup_not_armed", None),
            (I::StateConflict, 409, "setup_state_conflict", None),
            (I::Replay, 409, "request_replayed", None),
            (I::Expired, 410, "request_expired", None),
            (I::Denied, 403, "authorization_denied", None),
            (poll!(I, NOW - 1), 429, "poll_too_early", Some("1")),
            (poll!(I, NOW + 3), 429, "poll_too_early", Some("3")),
            (rate!(I, None), 429, "rate_limited", None),
            (rate!(I, Some(0)), 429, "rate_limited", Some("1")),
            (rate!(I, Some(9)), 429, "rate_limited", Some("9")),
            (I::ProviderUnavailable, 503, "unavailable", Some("1")),
            (I::StorageUnavailable, 503, "unavailable", Some("1")),
            (I::RandomnessUnavailable, 503, "unavailable", Some("1")),
            (I::CollisionLimitExceeded, 503, "unavailable", Some("1")),
            (I::NotAuthorized, 403, "not_authorized", None),
            (I::AlreadyConfigured, 410, "setup_complete", None),
            (I::IntegrityFailure, 500, "internal_error", None),
        ];
        let cases = sign_in
            .map(|(error, status, code, retry)| (SignIn(error), status, code, retry))
            .into_iter()
            .chain(setup.map(|(error, status, code, retry)| (Setup(error), status, code, retry)));
        for (failure, status, code, retry) in cases {
            let body = format!(r#"{{"error":"{code}"}}"#);
            assert_exact_json(
                github_auth_failure_response(failure, UnixTimestamp::from_seconds(NOW)),
                status,
                retry,
                &body,
            )
            .await;
        }
    }
}
