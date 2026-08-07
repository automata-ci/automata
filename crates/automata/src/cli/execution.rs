use std::{error::Error, fmt, fs::File, io::Read as _, path::Path, time::Duration};

use anyhow::{Context as _, Result, bail};
use reqwest::StatusCode;
use serde_json::Value;

use super::{AdminCommand, Command, OutputFormat, WorkflowCommand, WorkflowDispatchArgs};
use crate::app::workflow_api::{LocalWorkflowAdmissionRequest, LocalWorkflowAdmissionResponse};

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_WORKFLOW_SOURCE_BYTES: usize = 2 * 1024 * 1024;
const MAX_EVENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_LOCAL_TOKEN_BYTES: usize = 4 * 1024;

/// Resource limits applied to an administration status request.
///
/// The request timeout covers receipt of both headers and the complete body.
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

    pub const fn connect_timeout(self) -> Duration {
        self.connect_timeout
    }

    pub const fn request_timeout(self) -> Duration {
        self.request_timeout
    }

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
    ZeroConnectTimeout,
    ZeroRequestTimeout,
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

/// Failure to retrieve or decode the control-plane health document.
///
/// Error messages deliberately exclude the request URL and response content.
#[derive(Debug)]
pub enum StatusRequestError {
    ClientConfiguration(reqwest::Error),
    Request(reqwest::Error),
    Unhealthy(StatusCode),
    ResponseTooLarge { limit: usize },
    ResponseBufferUnavailable { limit: usize },
    ResponseRead(reqwest::Error),
    InvalidDocument(serde_json::Error),
}

impl fmt::Display for StatusRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
                "control-plane health document exceeds the {limit}-byte limit"
            ),
            Self::ResponseBufferUnavailable { limit } => write!(
                formatter,
                "could not allocate the bounded {limit}-byte health-document buffer"
            ),
            Self::ResponseRead(error) if error.is_timeout() => {
                formatter.write_str("control-plane health document timed out")
            }
            Self::ResponseRead(_) => {
                formatter.write_str("could not read the control-plane health document")
            }
            Self::InvalidDocument(_) => {
                formatter.write_str("control plane returned an invalid health document")
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
            Self::InvalidDocument(error) => Some(error),
            Self::Unhealthy(_)
            | Self::ResponseTooLarge { .. }
            | Self::ResponseBufferUnavailable { .. } => None,
        }
    }
}

/// Executes a command that talks to a running control plane.
///
/// Only the status operation is enabled during bootstrap. Other command
/// shapes are intentionally present now so their stable interface can be
/// reviewed without claiming that their server-side semantics exist.
///
/// # Errors
///
/// Returns an error if the operation is not implemented, the control plane
/// cannot be reached, or its health document is invalid.
pub async fn execute_control_plane_command(
    server_url: &str,
    output: OutputFormat,
    command: &Command,
) -> Result<()> {
    match command {
        Command::Admin(admin) if matches!(admin.command, AdminCommand::Status) => {
            print_status(server_url, output).await
        }
        Command::Workflow(workflow) => match &workflow.command {
            WorkflowCommand::Dispatch(args) => dispatch_workflow(server_url, output, args).await,
        },
        _ => bail!(
            "{} is not available in this bootstrap build",
            command.operation_name()
        ),
    }
}

async fn dispatch_workflow(
    server_url: &str,
    output: OutputFormat,
    args: &WorkflowDispatchArgs,
) -> Result<()> {
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
    let endpoint = format!(
        "{}/api/v1/local/workflow-runs",
        server_url.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
        .timeout(DEFAULT_REQUEST_TIMEOUT)
        .build()
        .context("failed to configure workflow admission client")?;
    let response = client
        .post(endpoint)
        .bearer_auth(token.as_str())
        .json(&document)
        .send()
        .await
        .map_err(reqwest::Error::without_url)
        .context("workflow admission request failed")?;
    let status = response.status();
    let body = read_bounded_body(response, DEFAULT_MAX_RESPONSE_BYTES)
        .await
        .context("failed to read workflow admission response")?;
    if !status.is_success() {
        let code = serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|document| {
                document
                    .get("code")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "invalid_response".to_owned());
        bail!("workflow admission returned HTTP {status} ({code})");
    }
    let admitted = serde_json::from_slice::<LocalWorkflowAdmissionResponse>(&body)
        .context("control plane returned an invalid workflow admission response")?;
    match output {
        OutputFormat::Table => {
            println!("run\t{}", admitted.run_id());
            println!("number\t{}", admitted.run_number());
            println!("replayed\t{}", admitted.is_replay());
        }
        OutputFormat::Json | OutputFormat::JsonLines => {
            println!("{}", serde_json::to_string(&admitted)?);
        }
    }
    Ok(())
}

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
    let health = fetch_control_plane_status(server_url, StatusHttpPolicy::default())
        .await
        .context("failed to retrieve control-plane status")?;

    match output {
        OutputFormat::Table => {
            let status = health
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let version = health
                .get("version")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let commit = health
                .get("commit")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            println!("status\t{status}");
            println!("version\t{version}");
            println!("commit\t{commit}");
        }
        OutputFormat::Json | OutputFormat::JsonLines => {
            println!("{}", serde_json::to_string(&health)?);
        }
    }
    Ok(())
}

/// Retrieves a bounded JSON health document from a control plane.
///
/// # Errors
///
/// Returns a typed error if the client cannot be built, the request fails or
/// times out, the server is unhealthy, the response exceeds the configured
/// limit, or the body is not valid JSON.
pub async fn fetch_control_plane_status(
    server_url: &str,
    policy: StatusHttpPolicy,
) -> Result<Value, StatusRequestError> {
    let endpoint = format!("{}/healthz", server_url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .connect_timeout(policy.connect_timeout())
        .timeout(policy.request_timeout())
        .build()
        .map_err(|error| StatusRequestError::ClientConfiguration(error.without_url()))?;
    let response = client
        .get(endpoint)
        .send()
        .await
        .map_err(|error| StatusRequestError::Request(error.without_url()))?;

    if !response.status().is_success() {
        return Err(StatusRequestError::Unhealthy(response.status()));
    }

    let body = read_bounded_body(response, policy.max_response_bytes()).await?;
    serde_json::from_slice(&body).map_err(StatusRequestError::InvalidDocument)
}

async fn read_bounded_body(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, StatusRequestError> {
    if response
        .content_length()
        .is_some_and(|length| length > usize_to_u64_saturating(limit))
    {
        return Err(StatusRequestError::ResponseTooLarge { limit });
    }

    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| StatusRequestError::ResponseRead(error.without_url()))?
    {
        let next_length = body
            .len()
            .checked_add(chunk.len())
            .filter(|length| *length <= limit)
            .ok_or(StatusRequestError::ResponseTooLarge { limit })?;
        body.try_reserve_exact(next_length - body.len())
            .map_err(|_| StatusRequestError::ResponseBufferUnavailable { limit })?;
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn usize_to_u64_saturating(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
