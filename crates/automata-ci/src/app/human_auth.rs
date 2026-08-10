//! Strict HTTP credential, cookie, origin, and CSRF primitives for human auth.
//!
//! This module performs no authentication or authorization by itself. It turns
//! untrusted HTTP syntax into one unambiguous browser/CLI credential and enforces
//! the browser mutation boundary before a handler parses a request body.

use std::{fmt, time::Duration};

use automata_ci_auth::{
    secret::CsrfToken, session::SessionKind, session_credential::SessionCredential,
};
use axum::{
    body::Body,
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode,
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, COOKIE, WWW_AUTHENTICATE},
    },
    response::Response,
};
use thiserror::Error;
use url::{Host, Url};

pub const PRODUCTION_SESSION_COOKIE: &str = "__Host-automata-session";
pub const PRODUCTION_LOGIN_COOKIE: &str = "__Host-automata-login";
pub const PRODUCTION_CSRF_COOKIE: &str = "__Host-automata-csrf";
pub const DEVELOPMENT_SESSION_COOKIE: &str = "automata-dev-session";
pub const DEVELOPMENT_LOGIN_COOKIE: &str = "automata-dev-login";
pub const DEVELOPMENT_CSRF_COOKIE: &str = "automata-dev-csrf";

const ORIGIN: HeaderName = HeaderName::from_static("origin");
const SEC_FETCH_SITE: HeaderName = HeaderName::from_static("sec-fetch-site");
const CSRF_HEADER: HeaderName = HeaderName::from_static("x-automata-csrf-token");
const MAX_BINDING_COOKIE_BYTES: usize = 1_024;

/// Production credentials can never be silently downgraded onto loopback HTTP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanCookieMode {
    ProductionSecure,
    LoopbackDevelopment,
}

impl HumanCookieMode {
    #[must_use]
    pub const fn session_cookie_name(self) -> &'static str {
        match self {
            Self::ProductionSecure => PRODUCTION_SESSION_COOKIE,
            Self::LoopbackDevelopment => DEVELOPMENT_SESSION_COOKIE,
        }
    }

    #[must_use]
    pub const fn login_cookie_name(self) -> &'static str {
        match self {
            Self::ProductionSecure => PRODUCTION_LOGIN_COOKIE,
            Self::LoopbackDevelopment => DEVELOPMENT_LOGIN_COOKIE,
        }
    }

    #[must_use]
    pub const fn csrf_cookie_name(self) -> &'static str {
        match self {
            Self::ProductionSecure => PRODUCTION_CSRF_COOKIE,
            Self::LoopbackDevelopment => DEVELOPMENT_CSRF_COOKIE,
        }
    }

    const fn secure_attribute(self) -> &'static str {
        match self {
            Self::ProductionSecure => "; Secure",
            Self::LoopbackDevelopment => "",
        }
    }
}

/// Exact configured browser origin and its non-downgrade cookie policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanAuthOrigin {
    serialized: String,
    cookie_mode: HumanCookieMode,
}

impl HumanAuthOrigin {
    /// Validates one canonical HTTPS origin or explicit literal-loopback HTTP origin.
    ///
    /// # Errors
    ///
    /// Rejects credentials, paths, queries, fragments, noncanonical text, and
    /// non-loopback cleartext origins.
    pub fn new(url: &Url) -> Result<Self, HumanAuthOriginError> {
        if !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(HumanAuthOriginError);
        }
        let cookie_mode = match url.scheme() {
            "https" => HumanCookieMode::ProductionSecure,
            "http" if is_literal_loopback(url.host().as_ref()) => {
                HumanCookieMode::LoopbackDevelopment
            }
            _ => return Err(HumanAuthOriginError),
        };
        let serialized = url.origin().ascii_serialization();
        let expected = format!("{serialized}/");
        if url.as_str() != expected {
            return Err(HumanAuthOriginError);
        }
        Ok(Self {
            serialized,
            cookie_mode,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.serialized
    }

    #[must_use]
    pub const fn cookie_mode(&self) -> HumanCookieMode {
        self.cookie_mode
    }
}

fn is_literal_loopback(host: Option<&Host<&str>>) -> bool {
    match host {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(_)) | None => false,
    }
}

/// Sanitized invalid-origin configuration failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error(
    "human authentication external URL must be a canonical HTTPS origin or literal-loopback HTTP origin"
)]
pub struct HumanAuthOriginError;

/// One and only one presented Automata human credential.
pub enum PresentedHumanCredential {
    Browser(SessionCredential),
    Cli(SessionCredential),
}

impl PresentedHumanCredential {
    #[must_use]
    pub const fn kind(&self) -> SessionKind {
        match self {
            Self::Browser(_) => SessionKind::Browser,
            Self::Cli(_) => SessionKind::Cli,
        }
    }

    /// Explicitly exposes the raw credential at the session-derivation boundary.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        match self {
            Self::Browser(credential) | Self::Cli(credential) => credential.expose_secret(),
        }
    }
}

impl fmt::Debug for PresentedHumanCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PresentedHumanCredential")
            .field("kind", &self.kind())
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

/// Extracts an optional human credential while rejecting duplicates, mixed
/// cookie/bearer authority, malformed syntax, and production/dev cookie mixing.
///
/// # Errors
///
/// Returns a sanitized classification without reflecting credential bytes.
pub fn extract_human_credential(
    headers: &HeaderMap,
    mode: HumanCookieMode,
) -> Result<Option<PresentedHumanCredential>, HumanCredentialHeaderError> {
    let browser = extract_session_cookie(headers, mode)?;
    let cli = extract_bearer(headers)?;
    match (browser, cli) {
        (None, None) => Ok(None),
        (Some(_), Some(_)) => Err(HumanCredentialHeaderError::Ambiguous),
        (Some(credential), None) => Ok(Some(PresentedHumanCredential::Browser(credential))),
        (None, Some(credential)) => Ok(Some(PresentedHumanCredential::Cli(credential))),
    }
}

fn extract_session_cookie(
    headers: &HeaderMap,
    mode: HumanCookieMode,
) -> Result<Option<SessionCredential>, HumanCredentialHeaderError> {
    let current_name = mode.session_cookie_name();
    let other_name = match mode {
        HumanCookieMode::ProductionSecure => DEVELOPMENT_SESSION_COOKIE,
        HumanCookieMode::LoopbackDevelopment => PRODUCTION_SESSION_COOKIE,
    };
    let current = extract_named_cookie(headers, current_name)?;
    if extract_named_cookie(headers, other_name)?.is_some() {
        return Err(HumanCredentialHeaderError::WrongCookieMode);
    }
    current
        .as_deref()
        .map(SessionCredential::from_raw)
        .transpose()
        .map_err(|_| HumanCredentialHeaderError::Invalid)
}

fn extract_bearer(
    headers: &HeaderMap,
) -> Result<Option<SessionCredential>, HumanCredentialHeaderError> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(HumanCredentialHeaderError::Duplicate);
    }
    let value = value
        .to_str()
        .map_err(|_| HumanCredentialHeaderError::Invalid)?;
    let (scheme, raw) = value
        .split_once(' ')
        .ok_or(HumanCredentialHeaderError::Invalid)?;
    if !scheme.eq_ignore_ascii_case("Bearer")
        || raw.is_empty()
        || raw
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == b',')
    {
        return Err(HumanCredentialHeaderError::Invalid);
    }
    SessionCredential::from_raw(raw)
        .map(Some)
        .map_err(|_| HumanCredentialHeaderError::Invalid)
}

/// Extracts the exact transient OAuth binding cookie and rejects cookie-mode mixing.
///
/// # Errors
///
/// Rejects duplicates, malformed cookie syntax, or a credential from the other mode.
pub fn extract_login_binding_cookie(
    headers: &HeaderMap,
    mode: HumanCookieMode,
) -> Result<Option<String>, HumanCredentialHeaderError> {
    let current = extract_named_cookie(headers, mode.login_cookie_name())?;
    let other = match mode {
        HumanCookieMode::ProductionSecure => DEVELOPMENT_LOGIN_COOKIE,
        HumanCookieMode::LoopbackDevelopment => PRODUCTION_LOGIN_COOKIE,
    };
    if extract_named_cookie(headers, other)?.is_some() {
        return Err(HumanCredentialHeaderError::WrongCookieMode);
    }
    if current
        .as_ref()
        .is_some_and(|value| !valid_cookie_value(value))
    {
        return Err(HumanCredentialHeaderError::Invalid);
    }
    Ok(current)
}

fn extract_named_cookie(
    headers: &HeaderMap,
    target: &str,
) -> Result<Option<String>, HumanCredentialHeaderError> {
    let mut found = None;
    for header in headers.get_all(COOKIE) {
        let header = header
            .to_str()
            .map_err(|_| HumanCredentialHeaderError::Invalid)?;
        for field in header.split(';') {
            let field = field.trim();
            if field.is_empty() {
                continue;
            }
            let (name, value) = field
                .split_once('=')
                .ok_or(HumanCredentialHeaderError::Invalid)?;
            if name.is_empty() || name.trim() != name || value.trim() != value {
                return Err(HumanCredentialHeaderError::Invalid);
            }
            if name == target && found.replace(value.to_owned()).is_some() {
                return Err(HumanCredentialHeaderError::Duplicate);
            }
        }
    }
    Ok(found)
}

fn valid_cookie_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_BINDING_COOKIE_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
}

/// Sanitized credential-header failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum HumanCredentialHeaderError {
    #[error("human credential syntax is invalid")]
    Invalid,
    #[error("human credential was presented more than once")]
    Duplicate,
    #[error("browser and CLI credentials cannot be combined")]
    Ambiguous,
    #[error("a production and development cookie mode cannot be mixed")]
    WrongCookieMode,
}

/// Verifies exact Origin, Fetch Metadata, and derived double-submit CSRF values.
///
/// Call this before parsing any unsafe browser request body. OAuth callbacks are
/// cross-site GET requests and use the independently bound OAuth state/cookie
/// contract instead.
///
/// # Errors
///
/// Returns one sanitized failure for missing, duplicate, or mismatched evidence.
pub fn verify_browser_mutation(
    headers: &HeaderMap,
    origin: &HumanAuthOrigin,
    expected_csrf: &CsrfToken,
) -> Result<(), BrowserMutationError> {
    let presented_origin = exactly_one_header(headers, &ORIGIN)?;
    if presented_origin != origin.as_str() {
        return Err(BrowserMutationError);
    }
    if let Some(fetch_site) = optional_single_header(headers, &SEC_FETCH_SITE)?
        && fetch_site.eq_ignore_ascii_case("cross-site")
    {
        return Err(BrowserMutationError);
    }
    let csrf_cookie = extract_named_cookie(headers, origin.cookie_mode().csrf_cookie_name())
        .map_err(|_| BrowserMutationError)?
        .ok_or(BrowserMutationError)?;
    let other_csrf_cookie = match origin.cookie_mode() {
        HumanCookieMode::ProductionSecure => DEVELOPMENT_CSRF_COOKIE,
        HumanCookieMode::LoopbackDevelopment => PRODUCTION_CSRF_COOKIE,
    };
    if extract_named_cookie(headers, other_csrf_cookie)
        .map_err(|_| BrowserMutationError)?
        .is_some()
    {
        return Err(BrowserMutationError);
    }
    let csrf_header = exactly_one_header(headers, &CSRF_HEADER)?;
    if !expected_csrf.matches(&csrf_cookie) || !expected_csrf.matches(csrf_header) {
        return Err(BrowserMutationError);
    }
    Ok(())
}

fn exactly_one_header<'a>(
    headers: &'a HeaderMap,
    name: &HeaderName,
) -> Result<&'a str, BrowserMutationError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(BrowserMutationError)?;
    if values.next().is_some() {
        return Err(BrowserMutationError);
    }
    value.to_str().map_err(|_| BrowserMutationError)
}

fn optional_single_header<'a>(
    headers: &'a HeaderMap,
    name: &HeaderName,
) -> Result<Option<&'a str>, BrowserMutationError> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(BrowserMutationError);
    }
    value.to_str().map(Some).map_err(|_| BrowserMutationError)
}

/// Sanitized browser mutation-boundary failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("browser mutation security checks failed")]
pub struct BrowserMutationError;

/// A Set-Cookie header that deliberately redacts its value from Debug output.
pub struct SensitiveSetCookie(HeaderValue);

impl SensitiveSetCookie {
    /// Explicitly exposes the complete Set-Cookie value at the response boundary.
    #[cfg(test)]
    #[must_use]
    pub const fn header_value(&self) -> &HeaderValue {
        &self.0
    }

    #[must_use]
    pub fn into_header_value(self) -> HeaderValue {
        self.0
    }
}

impl fmt::Debug for SensitiveSetCookie {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SensitiveSetCookie([REDACTED])")
    }
}

/// Builds a host-scoped browser session cookie.
///
/// # Errors
///
/// Rejects a zero/fractional lifetime or an unrepresentable header value.
pub fn session_set_cookie(
    mode: HumanCookieMode,
    credential: &SessionCredential,
    lifetime: Duration,
) -> Result<SensitiveSetCookie, SetCookieError> {
    set_cookie(
        mode.session_cookie_name(),
        credential.expose_secret(),
        lifetime,
        mode,
        true,
        "Lax",
    )
}

/// Builds the transient `HttpOnly` OAuth client-binding cookie.
///
/// # Errors
///
/// Rejects invalid cookie-value syntax or lifetime.
pub fn login_set_cookie(
    mode: HumanCookieMode,
    binding: &str,
    lifetime: Duration,
) -> Result<SensitiveSetCookie, SetCookieError> {
    if !valid_cookie_value(binding) {
        return Err(SetCookieError);
    }
    set_cookie(
        mode.login_cookie_name(),
        binding,
        lifetime,
        mode,
        true,
        "Lax",
    )
}

/// Builds the readable, session-derived double-submit CSRF cookie.
///
/// # Errors
///
/// Rejects invalid lifetime or header construction.
pub fn csrf_set_cookie(
    mode: HumanCookieMode,
    csrf: &CsrfToken,
    lifetime: Duration,
) -> Result<SensitiveSetCookie, SetCookieError> {
    set_cookie(
        mode.csrf_cookie_name(),
        csrf.expose_secret(),
        lifetime,
        mode,
        false,
        "Strict",
    )
}

/// Clears the session cookie with exactly the attributes used during issuance.
///
/// # Errors
///
/// Returns an error only if the fixed header cannot be represented.
pub fn clear_session_cookie(mode: HumanCookieMode) -> Result<SensitiveSetCookie, SetCookieError> {
    clear_cookie(mode, mode.session_cookie_name(), true, "Lax")
}

/// Clears the transient login cookie with exactly its issuance attributes.
///
/// # Errors
///
/// Returns an error only if the fixed header cannot be represented.
pub fn clear_login_cookie(mode: HumanCookieMode) -> Result<SensitiveSetCookie, SetCookieError> {
    clear_cookie(mode, mode.login_cookie_name(), true, "Lax")
}

/// Clears the readable CSRF cookie with exactly its issuance attributes.
///
/// # Errors
///
/// Returns an error only if the fixed header cannot be represented.
pub fn clear_csrf_cookie(mode: HumanCookieMode) -> Result<SensitiveSetCookie, SetCookieError> {
    clear_cookie(mode, mode.csrf_cookie_name(), false, "Strict")
}

fn clear_cookie(
    mode: HumanCookieMode,
    cookie_name: &'static str,
    http_only: bool,
    same_site: &'static str,
) -> Result<SensitiveSetCookie, SetCookieError> {
    let mut value = format!("{cookie_name}=; Path=/; Max-Age=0");
    value.push_str(mode.secure_attribute());
    if http_only {
        value.push_str("; HttpOnly");
    }
    value.push_str("; SameSite=");
    value.push_str(same_site);
    sensitive_set_cookie(&value)
}

fn set_cookie(
    name: &str,
    value: &str,
    lifetime: Duration,
    mode: HumanCookieMode,
    http_only: bool,
    same_site: &str,
) -> Result<SensitiveSetCookie, SetCookieError> {
    if lifetime.is_zero() || lifetime.subsec_nanos() != 0 {
        return Err(SetCookieError);
    }
    let mut header = format!("{name}={value}; Path=/; Max-Age={}", lifetime.as_secs());
    header.push_str(mode.secure_attribute());
    if http_only {
        header.push_str("; HttpOnly");
    }
    header.push_str("; SameSite=");
    header.push_str(same_site);
    sensitive_set_cookie(&header)
}

fn sensitive_set_cookie(value: &str) -> Result<SensitiveSetCookie, SetCookieError> {
    let mut value = HeaderValue::from_str(value).map_err(|_| SetCookieError)?;
    value.set_sensitive(true);
    Ok(SensitiveSetCookie(value))
}

/// Sanitized cookie-construction failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("authentication cookie could not be constructed")]
pub struct SetCookieError;

/// Creates a sanitized, non-cacheable auth response. CLI challenges never
/// include provider details or credential material.
#[must_use]
pub fn auth_error_response(
    status: StatusCode,
    body: &'static str,
    cli_bearer_challenge: bool,
) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    if cli_bearer_challenge {
        response.headers_mut().insert(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"automata\""),
        );
    }
    response
}

#[cfg(test)]
mod tests {
    use automata_ci_auth::secret::SecretString;
    use axum::http::header::{AUTHORIZATION, COOKIE};

    use super::*;

    const SESSION: &str = "v1~key-1~AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const CSRF: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

    fn origin() -> HumanAuthOrigin {
        HumanAuthOrigin::new(&Url::parse("https://ci.example/").unwrap()).unwrap()
    }

    fn csrf() -> CsrfToken {
        CsrfToken::from_generated_secret(SecretString::new(CSRF).unwrap()).unwrap()
    }

    #[test]
    fn origin_policy_never_downgrades_production_cookie_names() {
        assert_eq!(origin().cookie_mode(), HumanCookieMode::ProductionSecure);
        let dev = HumanAuthOrigin::new(&Url::parse("http://127.0.0.1:8080/").unwrap()).unwrap();
        assert_eq!(dev.cookie_mode(), HumanCookieMode::LoopbackDevelopment);
        for invalid in [
            "http://ci.example/",
            "http://localhost:8080/",
            "https://user@ci.example/",
            "https://ci.example/path",
            "https://ci.example/?query=1",
        ] {
            assert!(HumanAuthOrigin::new(&Url::parse(invalid).unwrap()).is_err());
        }
    }

    #[test]
    fn credential_extraction_rejects_duplicates_ambiguity_and_mode_mix() {
        let mut headers = HeaderMap::new();
        headers.append(
            COOKIE,
            HeaderValue::from_str(&format!("{PRODUCTION_SESSION_COOKIE}={SESSION}")).unwrap(),
        );
        let credential = extract_human_credential(&headers, HumanCookieMode::ProductionSecure)
            .unwrap()
            .unwrap();
        assert_eq!(credential.kind(), SessionKind::Browser);
        assert!(!format!("{credential:?}").contains(SESSION));

        headers.append(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {SESSION}")).unwrap(),
        );
        assert_eq!(
            extract_human_credential(&headers, HumanCookieMode::ProductionSecure).unwrap_err(),
            HumanCredentialHeaderError::Ambiguous
        );

        let mut duplicate = HeaderMap::new();
        duplicate.append(
            COOKIE,
            HeaderValue::from_str(&format!(
                "{PRODUCTION_SESSION_COOKIE}={SESSION}; {PRODUCTION_SESSION_COOKIE}={SESSION}"
            ))
            .unwrap(),
        );
        assert_eq!(
            extract_human_credential(&duplicate, HumanCookieMode::ProductionSecure).unwrap_err(),
            HumanCredentialHeaderError::Duplicate
        );

        let mut mixed = HeaderMap::new();
        mixed.insert(
            COOKIE,
            HeaderValue::from_str(&format!("{DEVELOPMENT_SESSION_COOKIE}={SESSION}")).unwrap(),
        );
        assert_eq!(
            extract_human_credential(&mixed, HumanCookieMode::ProductionSecure).unwrap_err(),
            HumanCredentialHeaderError::WrongCookieMode
        );
    }

    #[test]
    fn bearer_parser_accepts_one_exact_rfc_scheme_and_rejects_lists() {
        for scheme in ["Bearer", "bearer", "BEARER"] {
            let mut headers = HeaderMap::new();
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("{scheme} {SESSION}")).unwrap(),
            );
            assert_eq!(
                extract_human_credential(&headers, HumanCookieMode::ProductionSecure)
                    .unwrap()
                    .unwrap()
                    .kind(),
                SessionKind::Cli
            );
        }
        for invalid in [
            format!("Bearer  {SESSION}"),
            format!("Bearer {SESSION},other"),
            format!("Basic {SESSION}"),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(AUTHORIZATION, HeaderValue::from_str(&invalid).unwrap());
            assert_eq!(
                extract_human_credential(&headers, HumanCookieMode::ProductionSecure).unwrap_err(),
                HumanCredentialHeaderError::Invalid
            );
        }
    }

    #[test]
    fn browser_mutation_requires_exact_origin_and_both_csrf_values() {
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, HeaderValue::from_static("https://ci.example"));
        headers.insert(SEC_FETCH_SITE, HeaderValue::from_static("same-origin"));
        headers.insert(CSRF_HEADER, HeaderValue::from_static(CSRF));
        headers.insert(
            COOKIE,
            HeaderValue::from_str(&format!("{PRODUCTION_CSRF_COOKIE}={CSRF}")).unwrap(),
        );
        verify_browser_mutation(&headers, &origin(), &csrf()).unwrap();

        headers.insert(SEC_FETCH_SITE, HeaderValue::from_static("cross-site"));
        assert_eq!(
            verify_browser_mutation(&headers, &origin(), &csrf()),
            Err(BrowserMutationError)
        );
        headers.insert(SEC_FETCH_SITE, HeaderValue::from_static("same-origin"));
        headers.insert(CSRF_HEADER, HeaderValue::from_static("wrong"));
        assert_eq!(
            verify_browser_mutation(&headers, &origin(), &csrf()),
            Err(BrowserMutationError)
        );
    }

    #[test]
    fn cookies_have_exact_security_attributes_and_clear_with_same_scope() {
        let credential = SessionCredential::from_raw(SESSION).unwrap();
        let session = session_set_cookie(
            HumanCookieMode::ProductionSecure,
            &credential,
            Duration::from_mins(5),
        )
        .unwrap();
        let value = session.header_value().to_str().unwrap();
        assert!(value.starts_with(&format!("{PRODUCTION_SESSION_COOKIE}=")));
        assert!(value.contains("; Path=/; Max-Age=300; Secure; HttpOnly; SameSite=Lax"));
        assert!(session.header_value().is_sensitive());
        assert!(!format!("{session:?}").contains(SESSION));
        assert!(!format!("{:?}", session.header_value()).contains(SESSION));

        let csrf_cookie = csrf_set_cookie(
            HumanCookieMode::ProductionSecure,
            &csrf(),
            Duration::from_mins(5),
        )
        .unwrap();
        let csrf_value = csrf_cookie.header_value().to_str().unwrap();
        assert!(csrf_value.contains("; Secure; SameSite=Strict"));
        assert!(!csrf_value.contains("HttpOnly"));
        assert!(csrf_cookie.header_value().is_sensitive());

        let cleared = clear_session_cookie(HumanCookieMode::ProductionSecure).unwrap();
        assert!(cleared.header_value().is_sensitive());
        assert_eq!(
            cleared.header_value(),
            "__Host-automata-session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax"
        );
    }

    #[test]
    fn auth_errors_are_non_cacheable_and_cli_challenge_is_sanitized() {
        let response = auth_error_response(StatusCode::UNAUTHORIZED, "Unauthorized.\n", true);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            response.headers()[WWW_AUTHENTICATE],
            "Bearer realm=\"automata\""
        );
    }
}
