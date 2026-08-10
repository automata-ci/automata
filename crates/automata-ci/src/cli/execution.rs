use std::{error::Error, fmt, fs::File, io::Read as _, path::Path, time::Duration};

use anyhow::{Context as _, Result, bail};
use bytes::Bytes;
use reqwest::{Client, StatusCode, header};
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use url::{Host, Url};
use zeroize::Zeroizing;

use super::{
    AdminCommand, Command, OutputFormat, WorkflowAdmissionArgs, WorkflowCommand,
    auth::execute_auth_command, secret::execute_secret_command,
};
use crate::app::workflow_api::{
    LOCAL_WORKFLOW_ADMISSION_PATH, LocalWorkflowAdmissionErrorDocument,
    LocalWorkflowAdmissionRequest, LocalWorkflowAdmissionResponse,
};

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_WORKFLOW_SOURCE_BYTES: usize = 2 * 1024 * 1024;
const MAX_EVENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_LOCAL_TOKEN_BYTES: usize = 4 * 1024;
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
/// repository-secret management, and credentialed local workflow admission are
/// operational.
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
        Command::Workflow(workflow) => match &workflow.command {
            WorkflowCommand::Admit(args) => admit_workflow(server_url, output, args).await,
        },
        Command::Auth(auth) => execute_auth_command(server_url, output, &auth.command).await,
        Command::Secret(secret) => {
            execute_secret_command(server_url, output, &secret.command).await
        }
        Command::Server(_) | Command::Preview(_) => {
            bail!("service commands cannot be sent to a running control plane")
        }
    }
}

async fn admit_workflow(
    server_url: &str,
    output: OutputFormat,
    args: &WorkflowAdmissionArgs,
) -> Result<()> {
    let endpoint = workflow_admission_endpoint(server_url)
        .context("workflow admission endpoint policy rejected the server URL")?;
    let source = read_bounded_utf8(&args.source_file, MAX_WORKFLOW_SOURCE_BYTES)
        .context("failed to read workflow source")?;
    let event = match &args.event_file {
        Some(path) => {
            read_bounded_utf8(path, MAX_EVENT_BYTES).context("failed to read workflow event")?
        }
        None => "{}".to_owned(),
    };
    serde_json::from_str::<Value>(&event).context("workflow event is not valid JSON")?;
    let token = args
        .token_source
        .load_scalar(MAX_LOCAL_TOKEN_BYTES)
        .context("failed to load local admission token")?;
    let document = LocalWorkflowAdmissionRequest::new(
        &args.provider_repository_id,
        args.repository.owner(),
        args.repository.name(),
        &args.workflow,
        source,
        event,
        &args.event_name,
        &args.delivery_id,
        &args.commit_sha,
        &args.git_ref,
        &args.workflow_name,
    );
    let client = control_plane_client(DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT)
        .context("failed to configure workflow admission client")?;
    let authorization = workflow_bearer_header(token.as_str())
        .context("failed to encode local admission credential")?;
    drop(token);
    let response = client
        .post(endpoint)
        .header(header::AUTHORIZATION, authorization)
        .json(&document)
        .send()
        .await
        .map_err(reqwest::Error::without_url)
        .context("workflow admission request failed")?;
    let status = response.status();
    validate_workflow_response_headers(status, response.headers())?;
    let body = read_bounded_body(response, DEFAULT_MAX_RESPONSE_BYTES)
        .await
        .context("failed to read workflow admission response")?;
    let rendered = workflow_admission_terminal_output(status, &body, output)?;
    println!("{rendered}");
    Ok(())
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

fn workflow_bearer_header(
    credential: &str,
) -> std::result::Result<header::HeaderValue, WorkflowCredentialError> {
    const PREFIX: &[u8] = b"Bearer ";
    let mut encoded = Zeroizing::new(Vec::with_capacity(PREFIX.len() + credential.len()));
    encoded.extend_from_slice(PREFIX);
    encoded.extend_from_slice(credential.as_bytes());
    let mut value = header::HeaderValue::from_maybe_shared(Bytes::from_owner(encoded))
        .map_err(|_| WorkflowCredentialError)?;
    value.set_sensitive(true);
    Ok(value)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WorkflowCredentialError;

impl fmt::Display for WorkflowCredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("local admission credential is not an HTTP bearer value")
    }
}

impl Error for WorkflowCredentialError {}

#[derive(Clone, Debug, Eq, PartialEq)]
enum WorkflowAdmissionResponseError {
    Http(StatusCode),
    InvalidResponse,
    Rejected {
        status: StatusCode,
        document: LocalWorkflowAdmissionErrorDocument,
    },
}

impl fmt::Display for WorkflowAdmissionResponseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(status) => write!(formatter, "workflow admission returned HTTP {status}"),
            Self::InvalidResponse => {
                formatter.write_str("control plane returned an invalid workflow admission response")
            }
            Self::Rejected { status, document } => {
                write!(
                    formatter,
                    "workflow admission was rejected with {} (HTTP {status})",
                    document.error()
                )?;
                if !document.diagnostics().is_empty() {
                    write!(
                        formatter,
                        "; diagnostics: {}",
                        document.diagnostics().join(", ")
                    )?;
                }
                Ok(())
            }
        }
    }
}

impl Error for WorkflowAdmissionResponseError {}

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

fn workflow_admission_terminal_output(
    status: StatusCode,
    body: &[u8],
    output: OutputFormat,
) -> std::result::Result<String, WorkflowAdmissionResponseError> {
    if !status.is_success() {
        let Ok(document) = serde_json::from_slice::<LocalWorkflowAdmissionErrorDocument>(body)
        else {
            return Err(WorkflowAdmissionResponseError::Http(status));
        };
        if !document.is_current_for_status(status) {
            return Err(WorkflowAdmissionResponseError::InvalidResponse);
        }
        return Err(WorkflowAdmissionResponseError::Rejected { status, document });
    }
    let admitted = serde_json::from_slice::<LocalWorkflowAdmissionResponse>(body)
        .map_err(|_| WorkflowAdmissionResponseError::InvalidResponse)?;
    match (status, admitted.is_replay()) {
        (StatusCode::OK, true) | (StatusCode::CREATED, false) => {}
        _ => return Err(WorkflowAdmissionResponseError::InvalidResponse),
    }
    match output {
        OutputFormat::Table => Ok(format!(
            "run\t{}\nnumber\t{}\nreplayed\t{}",
            admitted.run_id(),
            admitted.run_number(),
            admitted.is_replay()
        )),
        OutputFormat::Json | OutputFormat::JsonLines => serde_json::to_string(&admitted)
            .map_err(|_| WorkflowAdmissionResponseError::InvalidResponse),
    }
}

fn validate_workflow_response_headers(
    status: StatusCode,
    headers: &header::HeaderMap,
) -> std::result::Result<(), WorkflowAdmissionResponseError> {
    let standard_json = exact_single_header(headers, &header::CONTENT_TYPE, b"application/json");
    let middleware_json = matches!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR | StatusCode::GATEWAY_TIMEOUT
    ) && exact_single_header(
        headers,
        &header::CONTENT_TYPE,
        b"application/json; charset=utf-8",
    );
    if !(standard_json || middleware_json)
        || !exact_single_header(headers, &header::CACHE_CONTROL, b"no-store")
        || !exact_single_header(headers, &X_CONTENT_TYPE_OPTIONS, b"nosniff")
    {
        return Err(WorkflowAdmissionResponseError::InvalidResponse);
    }
    if status == StatusCode::SERVICE_UNAVAILABLE {
        if !exact_single_header(headers, &header::RETRY_AFTER, b"1") {
            return Err(WorkflowAdmissionResponseError::InvalidResponse);
        }
    } else if headers.contains_key(header::RETRY_AFTER) {
        return Err(WorkflowAdmissionResponseError::InvalidResponse);
    }
    Ok(())
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

fn workflow_admission_endpoint(server_url: &str) -> Result<Url, WorkflowEndpointError> {
    control_plane_endpoint(server_url, LOCAL_WORKFLOW_ADMISSION_PATH)
}

fn control_plane_endpoint(server_url: &str, path: &str) -> Result<Url, WorkflowEndpointError> {
    let mut endpoint = Url::parse(server_url).map_err(|_| WorkflowEndpointError)?;
    if endpoint.host().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || endpoint.path() != "/"
    {
        return Err(WorkflowEndpointError);
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
        return Err(WorkflowEndpointError);
    }
    endpoint.set_path(path);
    Ok(endpoint)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WorkflowEndpointError;

impl fmt::Display for WorkflowEndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "workflow admission requires an HTTPS origin or a literal loopback HTTP origin",
        )
    }
}

impl Error for WorkflowEndpointError {}

fn read_bounded_utf8(path: &Path, maximum: usize) -> Result<String> {
    let file = File::open(path).context("input file could not be opened")?;
    let metadata = file
        .metadata()
        .context("input file metadata could not be read")?;
    if metadata.len() > u64::try_from(maximum).unwrap_or(u64::MAX) {
        bail!("input file exceeds its byte limit");
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(maximum)
            .min(maximum),
    );
    file.take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .context("input file could not be read")?;
    if bytes.len() > maximum {
        bail!("input file exceeds its byte limit");
    }
    String::from_utf8(bytes).context("input file is not valid UTF-8")
}

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

    const RUN_ID: &str = "0198d5f4-e92e-7c13-8b5d-b507d48627c3";
    const HOSTILE_SENTINEL: &str = "ATTACKER_WORKFLOW_RESPONSE_SENTINEL";
    const TEST_COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn workflow_response_headers(status: StatusCode) -> header::HeaderMap {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/json"),
        );
        headers.insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        );
        headers.insert(
            header::HeaderName::from_static("x-content-type-options"),
            header::HeaderValue::from_static("nosniff"),
        );
        if status == StatusCode::SERVICE_UNAVAILABLE {
            headers.insert(header::RETRY_AFTER, header::HeaderValue::from_static("1"));
        }
        headers
    }

    #[test]
    fn credentialed_workflow_endpoint_accepts_only_reviewed_origins() {
        for (server_url, expected) in [
            (
                "https://control.example.test/",
                "https://control.example.test/api/v1/local/workflow-runs",
            ),
            (
                "http://127.0.0.1:8080/",
                "http://127.0.0.1:8080/api/v1/local/workflow-runs",
            ),
            (
                "http://[::1]:8080/",
                "http://[::1]:8080/api/v1/local/workflow-runs",
            ),
        ] {
            assert_eq!(
                workflow_admission_endpoint(server_url)
                    .expect("reviewed workflow endpoint")
                    .as_str(),
                expected
            );
        }
    }

    #[test]
    fn credentialed_workflow_endpoint_rejects_ambiguous_or_insecure_urls() {
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
            let error = workflow_admission_endpoint(server_url)
                .expect_err("credentialed endpoint must fail closed");
            let display = error.to_string();
            assert!(!display.contains("unique-secret"));
            assert!(!display.contains("unique-fragment"));
        }
    }

    #[test]
    fn workflow_bearer_storage_is_sensitive_and_diagnostics_are_redacted() {
        let header = workflow_bearer_header(HOSTILE_SENTINEL).expect("valid bearer bytes");
        assert!(header.is_sensitive());
        assert_eq!(
            header
                .to_str()
                .expect("test credential is visible only here"),
            format!("Bearer {HOSTILE_SENTINEL}")
        );
        assert!(!format!("{header:?}").contains(HOSTILE_SENTINEL));

        let error = workflow_bearer_header("invalid\ncredential")
            .expect_err("control bytes must not enter an HTTP header");
        assert_eq!(
            error.to_string(),
            "local admission credential is not an HTTP bearer value"
        );
        assert!(!format!("{error:?}").contains("invalid"));
    }

    #[test]
    fn workflow_response_headers_and_retry_signal_are_closed() {
        for status in [
            StatusCode::OK,
            StatusCode::CREATED,
            StatusCode::BAD_REQUEST,
            StatusCode::UNPROCESSABLE_ENTITY,
            StatusCode::CONFLICT,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            validate_workflow_response_headers(status, &workflow_response_headers(status))
                .expect("current workflow response headers");
        }

        for status in [
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            let mut headers = workflow_response_headers(status);
            headers.insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/json; charset=utf-8"),
            );
            validate_workflow_response_headers(status, &headers)
                .expect("current outer-middleware JSON headers");
        }

        let mut cases = Vec::new();
        let mut missing_content_type = workflow_response_headers(StatusCode::CREATED);
        missing_content_type.remove(header::CONTENT_TYPE);
        cases.push((StatusCode::CREATED, missing_content_type));

        let mut duplicate_content_type = workflow_response_headers(StatusCode::CREATED);
        duplicate_content_type.append(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/json"),
        );
        cases.push((StatusCode::CREATED, duplicate_content_type));

        let mut cacheable = workflow_response_headers(StatusCode::CREATED);
        cacheable.insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("public"),
        );
        cases.push((StatusCode::CREATED, cacheable));

        let mut missing_retry = workflow_response_headers(StatusCode::SERVICE_UNAVAILABLE);
        missing_retry.remove(header::RETRY_AFTER);
        cases.push((StatusCode::SERVICE_UNAVAILABLE, missing_retry));

        let mut unsolicited_retry = workflow_response_headers(StatusCode::CONFLICT);
        unsolicited_retry.insert(header::RETRY_AFTER, header::HeaderValue::from_static("1"));
        cases.push((StatusCode::CONFLICT, unsolicited_retry));

        for (status, headers) in cases {
            assert_eq!(
                validate_workflow_response_headers(status, &headers),
                Err(WorkflowAdmissionResponseError::InvalidResponse)
            );
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

    #[test]
    fn workflow_admission_outputs_only_revalidated_current_receipts() {
        let created = format!(r#"{{"run_id":"{RUN_ID}","run_number":41,"replayed":false}}"#);
        assert_eq!(
            workflow_admission_terminal_output(
                StatusCode::CREATED,
                created.as_bytes(),
                OutputFormat::Table,
            )
            .expect("current created receipt"),
            format!("run\t{RUN_ID}\nnumber\t41\nreplayed\tfalse")
        );

        let replayed = format!(r#"{{"run_id":"{RUN_ID}","run_number":41,"replayed":true}}"#);
        let expected_json = format!(r#"{{"run_id":"{RUN_ID}","run_number":41,"replayed":true}}"#);
        for output in [OutputFormat::Json, OutputFormat::JsonLines] {
            assert_eq!(
                workflow_admission_terminal_output(StatusCode::OK, replayed.as_bytes(), output,)
                    .expect("current replay receipt"),
                expected_json
            );
        }
    }

    #[test]
    fn workflow_admission_rejects_every_malformed_wire_invariant() {
        let uppercase_run_id = RUN_ID.to_ascii_uppercase();
        let braced_run_id = format!("{{{RUN_ID}}}");
        let cases = [
            (
                StatusCode::CREATED,
                format!(r#"{{"run_id":"{uppercase_run_id}","run_number":1,"replayed":false}}"#),
            ),
            (
                StatusCode::CREATED,
                format!(r#"{{"run_id":"{braced_run_id}","run_number":1,"replayed":false}}"#),
            ),
            (
                StatusCode::CREATED,
                r#"{"run_id":"not-a-run-id\n","run_number":1,"replayed":false}"#.to_owned(),
            ),
            (
                StatusCode::CREATED,
                r#"{"run_id":"00000000-0000-0000-0000-000000000000","run_number":1,"replayed":false}"#
                    .to_owned(),
            ),
            (
                StatusCode::CREATED,
                format!(r#"{{"run_id":"{RUN_ID}","run_number":0,"replayed":false}}"#),
            ),
            (
                StatusCode::CREATED,
                format!(r#"{{"run_id":"{RUN_ID}","run_number":1,"replayed":false,"extra":true}}"#),
            ),
            (
                StatusCode::CREATED,
                format!(r#"{{"run_id":"{RUN_ID}","run_number":1}}"#),
            ),
            (
                StatusCode::CREATED,
                format!(r#"{{"run_id":"{RUN_ID}","run_number":-1,"replayed":false}}"#),
            ),
            (
                StatusCode::OK,
                format!(r#"{{"run_id":"{RUN_ID}","run_number":1,"replayed":false}}"#),
            ),
            (
                StatusCode::CREATED,
                format!(r#"{{"run_id":"{RUN_ID}","run_number":1,"replayed":true}}"#),
            ),
            (
                StatusCode::ACCEPTED,
                format!(r#"{{"run_id":"{RUN_ID}","run_number":1,"replayed":false}}"#),
            ),
        ];

        for (status, body) in cases {
            let error =
                workflow_admission_terminal_output(status, body.as_bytes(), OutputFormat::Json)
                    .expect_err("malformed receipt must fail closed");
            assert_eq!(error, WorkflowAdmissionResponseError::InvalidResponse);
            assert_eq!(
                error.to_string(),
                "control plane returned an invalid workflow admission response"
            );
            assert!(error.source().is_none());
        }
    }

    #[test]
    fn hostile_workflow_error_documents_never_reach_terminal_or_error_surfaces() {
        let body =
            format!(r#"{{"code":"{HOSTILE_SENTINEL}\u001b[31m","message":"{HOSTILE_SENTINEL}"}}"#);
        let result = workflow_admission_terminal_output(
            StatusCode::UNPROCESSABLE_ENTITY,
            body.as_bytes(),
            OutputFormat::Table,
        );
        let stdout = result.as_ref().ok().cloned().unwrap_or_default();
        let error = result.expect_err("server failure must remain a failure");
        assert_eq!(
            error,
            WorkflowAdmissionResponseError::Http(StatusCode::UNPROCESSABLE_ENTITY)
        );
        let stderr = error.to_string();
        let debug_log = format!("{error:?}");
        let wrapped = anyhow::Error::new(error).context("workflow admission failed");
        let wrapped_display = format!("{wrapped:#}");
        let wrapped_debug = format!("{wrapped:?}");

        assert!(stdout.is_empty());
        assert_eq!(
            stderr,
            "workflow admission returned HTTP 422 Unprocessable Entity"
        );
        for surface in [stdout, stderr, debug_log, wrapped_display, wrapped_debug] {
            assert!(!surface.contains(HOSTILE_SENTINEL));
            assert!(!surface.contains('\u{1b}'));
        }
    }

    #[test]
    fn workflow_admission_surfaces_only_exact_sanitized_rejections() {
        let body = br#"{"error":"compilation_rejected","diagnostics":["github.compile.invalid_expression","github.invalid_permissions"]}"#;
        let error = workflow_admission_terminal_output(
            StatusCode::UNPROCESSABLE_ENTITY,
            body,
            OutputFormat::Table,
        )
        .expect_err("rejection must remain a failure");
        assert_eq!(
            error.to_string(),
            "workflow admission was rejected with compilation_rejected (HTTP 422 Unprocessable Entity); diagnostics: github.compile.invalid_expression, github.invalid_permissions"
        );
        let WorkflowAdmissionResponseError::Rejected { status, document } = error else {
            panic!("exact error document must be retained");
        };
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(document.error(), "compilation_rejected");
        assert_eq!(
            document.diagnostics(),
            [
                "github.compile.invalid_expression",
                "github.invalid_permissions"
            ]
        );

        let error = workflow_admission_terminal_output(
            StatusCode::GATEWAY_TIMEOUT,
            br#"{"error":"request_timeout"}"#,
            OutputFormat::Json,
        )
        .expect_err("transport timeout must remain a failure");
        assert_eq!(
            error.to_string(),
            "workflow admission was rejected with request_timeout (HTTP 504 Gateway Timeout)"
        );
    }

    #[test]
    fn workflow_admission_rejects_non_current_error_documents_without_reflection() {
        for body in [
            r#"{"error":"compilation_rejected","diagnostics":[]}"#,
            r#"{"error":"compilation_rejected","diagnostics":["github.z","github.a"]}"#,
            r#"{"error":"compilation_rejected","diagnostics":["github.a","github.a"]}"#,
            r#"{"error":"compilation_rejected","diagnostics":["github.bad\u001b[2J"]}"#,
            r#"{"error":"invalid_request","diagnostics":["github.a"]}"#,
        ] {
            let error = workflow_admission_terminal_output(
                StatusCode::UNPROCESSABLE_ENTITY,
                body.as_bytes(),
                OutputFormat::Json,
            )
            .expect_err("non-current error document must fail closed");
            assert_eq!(
                error,
                WorkflowAdmissionResponseError::Http(StatusCode::UNPROCESSABLE_ENTITY)
            );
            assert!(!error.to_string().contains("github."));
            assert!(!format!("{error:?}").contains('\u{1b}'));
        }

        let error = workflow_admission_terminal_output(
            StatusCode::UNPROCESSABLE_ENTITY,
            br#"{"error":"invalid_request"}"#,
            OutputFormat::Json,
        )
        .expect_err("status and error code must agree exactly");
        assert_eq!(error, WorkflowAdmissionResponseError::InvalidResponse);
    }

    #[test]
    fn hostile_success_documents_leave_only_sanitized_parser_failures() {
        let body = format!(
            r#"{{"run_id":"{HOSTILE_SENTINEL}\u001b[2J","run_number":1,"replayed":false}}"#
        );
        let result = workflow_admission_terminal_output(
            StatusCode::CREATED,
            body.as_bytes(),
            OutputFormat::Json,
        );
        let stdout = result.as_ref().ok().cloned().unwrap_or_default();
        let error = result.expect_err("hostile receipt must fail closed");
        let stderr = error.to_string();
        let debug_log = format!("{error:?}");

        assert!(stdout.is_empty());
        assert_eq!(error, WorkflowAdmissionResponseError::InvalidResponse);
        assert!(error.source().is_none());
        for surface in [stdout, stderr, debug_log] {
            assert!(!surface.contains(HOSTILE_SENTINEL));
            assert!(!surface.contains('\u{1b}'));
        }
    }
}
