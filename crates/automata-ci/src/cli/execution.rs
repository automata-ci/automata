use std::{error::Error, fmt, time::Duration};

use anyhow::{Context as _, Result, bail};
use bytes::Bytes;
use reqwest::{Client, StatusCode, header};
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use url::{Host, Url};
use zeroize::Zeroizing;

use super::{
    AdminCommand, Command, OutputFormat, auth::execute_auth_command,
    environment_review::execute_environment_review_command, rerun::execute_rerun_command,
    runner::execute_runner_command, secret::execute_secret_command,
};

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_MAX_RESPONSE_BYTES: usize = 64 * 1024;
const X_CONTENT_TYPE_OPTIONS: header::HeaderName =
    header::HeaderName::from_static("x-content-type-options");

/// Resource limits applied independently to each administration-status observation.
///
/// The request timeout covers receipt of both headers and the complete body of
/// one health or readiness request. The command makes one request of each kind.
/// Response bodies are rejected before reading when their declared length is
/// too large, and are also counted while streaming for chunked responses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatusHttpPolicy {
    connect_timeout: Duration,
    request_timeout: Duration,
    max_response_bytes: usize,
}

impl StatusHttpPolicy {
    /// Constructs a validated status-request policy.
    ///
    /// # Errors
    ///
    /// Returns an error when either timeout or the response limit is zero.
    pub const fn new(
        connect_timeout: Duration,
        request_timeout: Duration,
        max_response_bytes: usize,
    ) -> Result<Self, StatusHttpPolicyError> {
        if connect_timeout.is_zero() {
            return Err(StatusHttpPolicyError::ZeroConnectTimeout);
        }
        if request_timeout.is_zero() {
            return Err(StatusHttpPolicyError::ZeroRequestTimeout);
        }
        if max_response_bytes == 0 {
            return Err(StatusHttpPolicyError::ZeroResponseLimit);
        }

        Ok(Self {
            connect_timeout,
            request_timeout,
            max_response_bytes,
        })
    }

    /// Returns the deadline for establishing the HTTP connection.
    pub const fn connect_timeout(self) -> Duration {
        self.connect_timeout
    }

    /// Returns the per-observation deadline covering request and complete response body.
    pub const fn request_timeout(self) -> Duration {
        self.request_timeout
    }

    /// Returns the inclusive maximum accepted response-body size in bytes.
    pub const fn max_response_bytes(self) -> usize {
        self.max_response_bytes
    }
}

impl Default for StatusHttpPolicy {
    fn default() -> Self {
        Self {
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }
}

/// Invalid status-request policy configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusHttpPolicyError {
    /// The connection timeout was zero.
    ZeroConnectTimeout,
    /// The per-observation request timeout was zero.
    ZeroRequestTimeout,
    /// The response-body byte limit was zero.
    ZeroResponseLimit,
}

impl fmt::Display for StatusHttpPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ZeroConnectTimeout => "status connect timeout must be greater than zero",
            Self::ZeroRequestTimeout => "status request timeout must be greater than zero",
            Self::ZeroResponseLimit => "status response limit must be greater than zero",
        };
        formatter.write_str(message)
    }
}

impl Error for StatusHttpPolicyError {}

/// Failure to retrieve or decode a control-plane status observation.
///
/// Error messages deliberately exclude the request URL and response content.
#[derive(Debug)]
pub enum StatusRequestError {
    /// The supplied control-plane origin was not an exact reviewed origin.
    EndpointPolicy,
    /// The bounded HTTP client could not be constructed.
    ClientConfiguration(reqwest::Error),
    /// Sending the request or receiving its headers failed.
    Request(reqwest::Error),
    /// The control plane returned an unexpected HTTP status.
    Unhealthy(StatusCode),
    /// The declared or streamed body exceeded the configured ceiling.
    ResponseTooLarge {
        /// Inclusive response-body ceiling in bytes.
        limit: usize,
    },
    /// Memory for the bounded response body could not be reserved.
    ResponseBufferUnavailable {
        /// Inclusive response-body ceiling in bytes.
        limit: usize,
    },
    /// Streaming the response body failed.
    ResponseRead(reqwest::Error),
    /// Response headers or the bounded body were not the exact current observation contract.
    InvalidDocument,
}

impl fmt::Display for StatusRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EndpointPolicy => formatter.write_str(
                "control-plane status requires an HTTPS origin or literal-IP loopback HTTP origin",
            ),
            Self::ClientConfiguration(_) => {
                formatter.write_str("could not configure the status HTTP client")
            }
            Self::Request(error) if error.is_timeout() => {
                formatter.write_str("control-plane status request timed out")
            }
            Self::Request(_) => formatter.write_str("control-plane status request failed"),
            Self::Unhealthy(status) => {
                write!(formatter, "control plane returned HTTP {status}")
            }
            Self::ResponseTooLarge { limit } => write!(
                formatter,
                "control-plane status document exceeds the {limit}-byte limit"
            ),
            Self::ResponseBufferUnavailable { limit } => write!(
                formatter,
                "could not allocate the bounded {limit}-byte status-document buffer"
            ),
            Self::ResponseRead(error) if error.is_timeout() => {
                formatter.write_str("control-plane status document timed out")
            }
            Self::ResponseRead(_) => {
                formatter.write_str("could not read the control-plane status document")
            }
            Self::InvalidDocument => {
                formatter.write_str("control plane returned an invalid status document")
            }
        }
    }
}

impl Error for StatusRequestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ClientConfiguration(error) | Self::Request(error) | Self::ResponseRead(error) => {
                Some(error)
            }
            Self::EndpointPolicy
            | Self::InvalidDocument
            | Self::Unhealthy(_)
            | Self::ResponseTooLarge { .. }
            | Self::ResponseBufferUnavailable { .. } => None,
        }
    }
}

/// Executes a command that talks to a running control plane.
///
/// Control-plane status, GitHub device authentication, CLI-session lifecycle,
/// repository-secret management, protected-environment review, and workflow
/// reruns are operational.
///
/// # Errors
///
/// Returns an error if a reviewed endpoint policy rejects the server URL,
/// secure credential custody is unavailable, or the control plane cannot
/// complete the requested operation.
pub async fn execute_control_plane_command(
    server_url: &str,
    output: OutputFormat,
    command: &Command,
) -> Result<()> {
    match command {
        Command::Admin(admin) => match admin.command {
            AdminCommand::Status => print_status(server_url, output).await,
        },
        Command::Auth(auth) => execute_auth_command(server_url, output, &auth.command).await,
        Command::Secret(secret) => {
            execute_secret_command(server_url, output, &secret.command).await
        }
        Command::EnvironmentReview(args) => {
            execute_environment_review_command(server_url, output, args).await
        }
        Command::Rerun(args) => execute_rerun_command(server_url, output, args).await,
        Command::Runner(args) => execute_runner_command(server_url, output, args).await,
        Command::Server(_) | Command::Preview(_) | Command::Local(_) => {
            bail!("local and service commands cannot be sent to a running control plane")
        }
    }
}

fn control_plane_client(
    connect_timeout: Duration,
    request_timeout: Duration,
) -> std::result::Result<Client, reqwest::Error> {
    Client::builder()
        .connect_timeout(connect_timeout)
        .timeout(request_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .no_proxy()
        .build()
        .map_err(reqwest::Error::without_url)
}

struct ZeroizingString(Zeroizing<String>);

impl ZeroizingString {
    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl<'de> Deserialize<'de> for ZeroizingString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(|value| Self(Zeroizing::new(value)))
    }
}

fn exact_single_header(
    headers: &header::HeaderMap,
    name: &header::HeaderName,
    value: &[u8],
) -> bool {
    let mut values = headers.get_all(name).iter();
    values
        .next()
        .is_some_and(|actual| actual.as_bytes() == value)
        && values.next().is_none()
}

fn control_plane_endpoint(server_url: &str, path: &str) -> Result<Url, ControlPlaneEndpointError> {
    let mut endpoint = Url::parse(server_url).map_err(|_| ControlPlaneEndpointError)?;
    if endpoint.host().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || endpoint.path() != "/"
    {
        return Err(ControlPlaneEndpointError);
    }
    let transport_is_allowed = match endpoint.scheme() {
        "https" => true,
        "http" => match endpoint.host() {
            Some(Host::Ipv4(address)) => address.is_loopback(),
            Some(Host::Ipv6(address)) => address.is_loopback(),
            Some(Host::Domain(_)) | None => false,
        },
        _ => false,
    };
    if !transport_is_allowed {
        return Err(ControlPlaneEndpointError);
    }
    endpoint.set_path(path);
    Ok(endpoint)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ControlPlaneEndpointError;

impl fmt::Display for ControlPlaneEndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("control-plane requests require HTTPS or literal loopback HTTP")
    }
}

impl Error for ControlPlaneEndpointError {}

async fn print_status(server_url: &str, output: OutputFormat) -> Result<()> {
    let status_document = fetch_control_plane_status(server_url, StatusHttpPolicy::default())
        .await
        .context("failed to retrieve control-plane status")?;

    match output {
        OutputFormat::Table => {
            let status = status_document
                .pointer("/health/status")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let ready = status_document
                .pointer("/readiness/ready")
                .and_then(Value::as_bool)
                .map_or("unknown", |ready| if ready { "true" } else { "false" });
            let version = status_document
                .pointer("/health/version")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let commit = status_document
                .pointer("/health/commit")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            println!("health.status\t{status}");
            println!("health.version\t{version}");
            println!("health.commit\t{commit}");
            println!("readiness.ready\t{ready}");
        }
        OutputFormat::Json | OutputFormat::JsonLines => {
            println!("{}", serde_json::to_string(&status_document)?);
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlPlaneHealthWire {
    status: ZeroizingString,
    version: ZeroizingString,
    commit: ZeroizingString,
}

impl ControlPlaneHealthWire {
    fn into_value(self) -> std::result::Result<Value, StatusRequestError> {
        let status = self.status.as_str();
        let version = self.version.as_str();
        let commit = self.commit.as_str();
        if status != "ok" || !valid_health_version(version) || !valid_health_commit(commit) {
            return Err(StatusRequestError::InvalidDocument);
        }
        Ok(serde_json::json!({
            "status": status,
            "version": version,
            "commit": commit,
        }))
    }
}

fn valid_health_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
}

fn valid_health_commit(value: &str) -> bool {
    value == "unknown"
        || matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn decode_control_plane_health(body: &[u8]) -> Result<Value, StatusRequestError> {
    serde_json::from_slice::<ControlPlaneHealthWire>(body)
        .map_err(|_| StatusRequestError::InvalidDocument)?
        .into_value()
}

/// Retrieves separate bounded health and readiness observations from a control-plane origin.
///
/// # Errors
///
/// Returns a typed error if the origin is outside the reviewed transport
/// policy, the client cannot be built, the request fails or times out, the
/// server returns an unexpected status, either response exceeds the configured
/// limit, or either response lacks its exact media, cache, nosniff, and body
/// contract.
pub async fn fetch_control_plane_status(
    server_url: &str,
    policy: StatusHttpPolicy,
) -> Result<Value, StatusRequestError> {
    let health_endpoint = control_plane_endpoint(server_url, "/healthz")
        .map_err(|_| StatusRequestError::EndpointPolicy)?;
    let readiness_endpoint = control_plane_endpoint(server_url, "/readyz")
        .map_err(|_| StatusRequestError::EndpointPolicy)?;
    let client = control_plane_client(policy.connect_timeout(), policy.request_timeout())
        .map_err(StatusRequestError::ClientConfiguration)?;
    let health_response = client
        .get(health_endpoint)
        .send()
        .await
        .map_err(|error| StatusRequestError::Request(error.without_url()))?;

    if health_response.status() != StatusCode::OK {
        return Err(StatusRequestError::Unhealthy(health_response.status()));
    }
    validate_status_response_headers(&health_response, b"application/json")?;
    let health_body = read_bounded_body(health_response, policy.max_response_bytes()).await?;
    let health = decode_control_plane_health(&health_body)?;

    let readiness_response = client
        .get(readiness_endpoint)
        .send()
        .await
        .map_err(|error| StatusRequestError::Request(error.without_url()))?;
    let readiness_status = readiness_response.status();
    if !matches!(
        readiness_status,
        StatusCode::OK | StatusCode::SERVICE_UNAVAILABLE
    ) {
        return Err(StatusRequestError::Unhealthy(readiness_status));
    }
    validate_status_response_headers(&readiness_response, b"text/plain; charset=utf-8")?;
    let readiness_body = read_bounded_body(readiness_response, policy.max_response_bytes()).await?;
    let ready = match (readiness_status, readiness_body.as_slice()) {
        (StatusCode::OK, b"ready\n") => true,
        (StatusCode::SERVICE_UNAVAILABLE, b"not ready\n") => false,
        _ => return Err(StatusRequestError::InvalidDocument),
    };
    Ok(serde_json::json!({
        "health": health,
        "readiness": {"ready": ready},
    }))
}

fn validate_status_response_headers(
    response: &reqwest::Response,
    content_type: &[u8],
) -> Result<(), StatusRequestError> {
    let headers = response.headers();
    if exact_single_header(headers, &header::CONTENT_TYPE, content_type)
        && exact_single_header(headers, &header::CACHE_CONTROL, b"no-store")
        && exact_single_header(headers, &X_CONTENT_TYPE_OPTIONS, b"nosniff")
    {
        Ok(())
    } else {
        Err(StatusRequestError::InvalidDocument)
    }
}

async fn read_bounded_body(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, StatusRequestError> {
    if response
        .content_length()
        .is_some_and(|length| length > usize_to_u64_saturating(limit))
    {
        return Err(StatusRequestError::ResponseTooLarge { limit });
    }

    let mut body = Zeroizing::new(Vec::new());
    body.try_reserve_exact(limit)
        .map_err(|_| StatusRequestError::ResponseBufferUnavailable { limit })?;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| StatusRequestError::ResponseRead(error.without_url()))?
    {
        let within_limit = body
            .len()
            .checked_add(chunk.len())
            .is_some_and(|length| length <= limit);
        if !within_limit {
            wipe_response_chunk(chunk);
            return Err(StatusRequestError::ResponseTooLarge { limit });
        }
        body.extend_from_slice(&chunk);
        wipe_response_chunk(chunk);
    }
    Ok(body)
}

fn wipe_response_chunk(chunk: Bytes) {
    if let Ok(mut chunk) = chunk.try_into_mut() {
        chunk.as_mut().fill(0);
    }
}

fn usize_to_u64_saturating(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOSTILE_SENTINEL: &str = "ATTACKER_STATUS_RESPONSE_SENTINEL";
    const TEST_COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn control_plane_endpoint_accepts_only_reviewed_origins() {
        for (server_url, expected) in [
            (
                "https://control.example.test/",
                "https://control.example.test/healthz",
            ),
            ("http://127.0.0.1:8080/", "http://127.0.0.1:8080/healthz"),
            ("http://[::1]:8080/", "http://[::1]:8080/healthz"),
        ] {
            assert_eq!(
                control_plane_endpoint(server_url, "/healthz")
                    .expect("reviewed control-plane endpoint")
                    .as_str(),
                expected
            );
        }
    }

    #[test]
    fn control_plane_endpoint_rejects_ambiguous_or_insecure_urls() {
        for server_url in [
            "http://control.example.test/",
            "http://localhost:8080/",
            "https://operator:unique-secret@control.example.test/",
            "https://control.example.test/base/",
            "https://control.example.test/?destination=elsewhere",
            "https://control.example.test/#unique-fragment",
            "ftp://control.example.test/",
            "control.example.test",
        ] {
            let error = control_plane_endpoint(server_url, "/healthz")
                .expect_err("control-plane endpoint must fail closed");
            let display = error.to_string();
            assert!(!display.contains("unique-secret"));
            assert!(!display.contains("unique-fragment"));
        }
    }

    #[test]
    fn health_document_is_exact_bounded_and_never_reflected_on_failure() {
        let accepted =
            format!(r#"{{"status":"ok","version":"0.1.0-test+local","commit":"{TEST_COMMIT}"}}"#);
        let value = decode_control_plane_health(accepted.as_bytes()).expect("current health shape");
        assert_eq!(value["status"], "ok");
        assert_eq!(value["version"], "0.1.0-test+local");
        assert_eq!(value["commit"], TEST_COMMIT);

        for body in [
            format!(
                r#"{{"status":"{HOSTILE_SENTINEL}","version":"0.1.0","commit":"{TEST_COMMIT}"}}"#
            ),
            format!(
                r#"{{"status":"ok","version":"{HOSTILE_SENTINEL}\u001b[2J","commit":"{TEST_COMMIT}"}}"#
            ),
            format!(
                r#"{{"status":"ok","version":"{}","commit":"{TEST_COMMIT}"}}"#,
                "v".repeat(129)
            ),
            format!(r#"{{"status":"ok","version":"0.1.0","commit":"{HOSTILE_SENTINEL}"}}"#),
            format!(
                r#"{{"status":"ok","version":"0.1.0","commit":"{TEST_COMMIT}","{HOSTILE_SENTINEL}":true}}"#
            ),
            format!(r#"{{"value":"{HOSTILE_SENTINEL}"}}"#),
        ] {
            let error = decode_control_plane_health(body.as_bytes())
                .expect_err("non-current health shape must fail closed");
            assert!(matches!(error, StatusRequestError::InvalidDocument));
            for surface in [error.to_string(), format!("{error:?}")] {
                assert!(!surface.contains(HOSTILE_SENTINEL));
                assert!(!surface.contains('\u{1b}'));
            }
            assert!(error.source().is_none());
        }
    }
}
