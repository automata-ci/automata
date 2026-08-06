use std::{collections::BTreeSet, error::Error, fmt, time::Duration};

use anyhow::{Result, bail};
use reqwest::StatusCode;
use serde::Serialize;
use tracing::info;

use crate::{
    build_info::BuildInfo,
    capability_probe::{
        self, CapabilityProbe, PODMAN_NETWORK_ISOLATION, PROCESS_EXECUTION, ProbeStatus,
    },
    cli::DoctorArgs,
    podman_probe,
};

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Resource limits applied to the runner's control-plane health probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerHttpPolicy {
    connect_timeout: Duration,
    request_timeout: Duration,
    max_response_bytes: usize,
}

impl ServerHttpPolicy {
    /// Constructs a validated server-probe policy.
    ///
    /// # Errors
    ///
    /// Returns an error when either timeout or the response limit is zero.
    pub const fn new(
        connect_timeout: Duration,
        request_timeout: Duration,
        max_response_bytes: usize,
    ) -> Result<Self, ServerHttpPolicyError> {
        if connect_timeout.is_zero() {
            return Err(ServerHttpPolicyError::ZeroConnectTimeout);
        }
        if request_timeout.is_zero() {
            return Err(ServerHttpPolicyError::ZeroRequestTimeout);
        }
        if max_response_bytes == 0 {
            return Err(ServerHttpPolicyError::ZeroResponseLimit);
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

impl Default for ServerHttpPolicy {
    fn default() -> Self {
        Self {
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }
}

/// Invalid server-probe policy configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerHttpPolicyError {
    ZeroConnectTimeout,
    ZeroRequestTimeout,
    ZeroResponseLimit,
}

impl fmt::Display for ServerHttpPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ZeroConnectTimeout => "server-probe connect timeout must be greater than zero",
            Self::ZeroRequestTimeout => "server-probe request timeout must be greater than zero",
            Self::ZeroResponseLimit => "server-probe response limit must be greater than zero",
        };
        formatter.write_str(message)
    }
}

impl Error for ServerHttpPolicyError {}

/// A bounded server health request failed.
///
/// The display representation never includes the request URL or response
/// content, so it is safe to include in runner diagnostics.
#[derive(Debug)]
enum ServerProbeError {
    ClientConfiguration(reqwest::Error),
    Request(reqwest::Error),
    HttpStatus(StatusCode),
    ResponseTooLarge { limit: usize },
    ResponseRead(reqwest::Error),
}

impl ServerProbeError {
    const fn server_status(&self) -> ServerStatus {
        match self {
            Self::HttpStatus(_) | Self::ResponseTooLarge { .. } => ServerStatus::Unhealthy,
            Self::ClientConfiguration(_) | Self::Request(_) | Self::ResponseRead(_) => {
                ServerStatus::Unreachable
            }
        }
    }
}

impl fmt::Display for ServerProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientConfiguration(_) => {
                formatter.write_str("could not configure the server-probe HTTP client")
            }
            Self::Request(error) if error.is_timeout() => {
                formatter.write_str("server health request timed out")
            }
            Self::Request(_) => formatter.write_str("server health request failed"),
            Self::HttpStatus(status) => write!(formatter, "server returned HTTP {status}"),
            Self::ResponseTooLarge { limit } => {
                write!(
                    formatter,
                    "server health response exceeds the {limit}-byte limit"
                )
            }
            Self::ResponseRead(error) if error.is_timeout() => {
                formatter.write_str("server health response timed out")
            }
            Self::ResponseRead(_) => formatter.write_str("could not read server health response"),
        }
    }
}

impl Error for ServerProbeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ClientConfiguration(error) | Self::Request(error) | Self::ResponseRead(error) => {
                Some(error)
            }
            Self::HttpStatus(_) | Self::ResponseTooLarge { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerStatus {
    Healthy,
    Unhealthy,
    Unreachable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ServerProbe {
    endpoint: String,
    status: ServerStatus,
    detail: Option<String>,
}

impl ServerProbe {
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub const fn status(&self) -> ServerStatus {
        self.status
    }

    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }

    pub const fn is_healthy(&self) -> bool {
        matches!(self.status, ServerStatus::Healthy)
    }
}

#[derive(Debug, Serialize)]
pub struct DoctorReport {
    #[serde(flatten)]
    build: BuildInfo,
    os: &'static str,
    arch: &'static str,
    capabilities: BTreeSet<&'static str>,
    capability_probes: Vec<CapabilityProbe>,
    server: Option<ServerProbe>,
    active: bool,
}

impl DoctorReport {
    pub fn capabilities(&self) -> &BTreeSet<&'static str> {
        &self.capabilities
    }

    pub fn capability_probes(&self) -> &[CapabilityProbe] {
        &self.capability_probes
    }

    pub const fn server(&self) -> Option<&ServerProbe> {
        self.server.as_ref()
    }

    pub fn is_healthy(&self) -> bool {
        self.capabilities.contains(PROCESS_EXECUTION)
            && (!self.active || self.capabilities.contains(PODMAN_NETWORK_ISOLATION))
            && self.server.as_ref().is_none_or(ServerProbe::is_healthy)
    }
}

pub async fn inspect(server: Option<&str>) -> DoctorReport {
    inspect_with_options(server, false).await
}

pub async fn inspect_with_options(server: Option<&str>, active: bool) -> DoctorReport {
    let mut capability_probes = capability_probe::probe_capabilities();
    if active {
        let network_probe = capability_probes
            .iter_mut()
            .find(|probe| probe.capability() == PODMAN_NETWORK_ISOLATION);
        match network_probe {
            Some(probe) if probe.status() == ProbeStatus::Detected => {
                *probe = podman_probe::probe_current_executable().await;
            }
            Some(_) => {}
            None => capability_probes.push(podman_probe::probe_current_executable().await),
        }
    }
    let capabilities = capability_probe::usable_capabilities(&capability_probes);
    let server = match server {
        Some(server) => Some(probe_server(server).await),
        None => None,
    };

    DoctorReport {
        build: BuildInfo::current(),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        capabilities,
        capability_probes,
        server,
        active,
    }
}

pub(crate) async fn run(args: DoctorArgs) -> Result<()> {
    let report = inspect_with_options(args.server.as_deref(), args.active).await;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        info!(
            os = report.os,
            arch = report.arch,
            version = report.build.version,
            commit = report.build.commit,
            capabilities = ?report.capabilities,
            capability_probes = ?report.capability_probes,
            server = ?report.server,
            active = report.active,
            "runner diagnostics"
        );
    }

    if !report.capabilities.contains(PROCESS_EXECUTION) {
        bail!("child process execution probe failed");
    }
    if report.active && !report.capabilities.contains(PODMAN_NETWORK_ISOLATION) {
        bail!("active Podman network isolation probe failed");
    }
    if let Some(server) = &report.server
        && !server.is_healthy()
    {
        bail!("server health check failed: {}", server.endpoint());
    }

    Ok(())
}

async fn probe_server(server: &str) -> ServerProbe {
    probe_server_with_policy(server, ServerHttpPolicy::default()).await
}

/// Probes a control plane using explicit HTTP resource limits.
pub async fn probe_server_with_policy(server: &str, policy: ServerHttpPolicy) -> ServerProbe {
    let request_endpoint = format!("{}/healthz", server.trim_end_matches('/'));
    let endpoint = endpoint_for_diagnostics(&request_endpoint);
    match check_server_health(&request_endpoint, policy).await {
        Ok(()) => ServerProbe {
            endpoint,
            status: ServerStatus::Healthy,
            detail: None,
        },
        Err(error) => ServerProbe {
            endpoint,
            status: error.server_status(),
            detail: Some(error.to_string()),
        },
    }
}

fn endpoint_for_diagnostics(endpoint: &str) -> String {
    let Ok(mut endpoint) = reqwest::Url::parse(endpoint) else {
        return "invalid control-plane health endpoint".to_owned();
    };
    let _username_removed = endpoint.set_username("");
    let _password_removed = endpoint.set_password(None);
    endpoint.set_query(None);
    endpoint.set_fragment(None);
    endpoint.to_string()
}

async fn check_server_health(
    endpoint: &str,
    policy: ServerHttpPolicy,
) -> Result<(), ServerProbeError> {
    let client = reqwest::Client::builder()
        .connect_timeout(policy.connect_timeout())
        .timeout(policy.request_timeout())
        .build()
        .map_err(|error| ServerProbeError::ClientConfiguration(error.without_url()))?;
    let response = client
        .get(endpoint)
        .send()
        .await
        .map_err(|error| ServerProbeError::Request(error.without_url()))?;
    if !response.status().is_success() {
        return Err(ServerProbeError::HttpStatus(response.status()));
    }

    drain_bounded_body(response, policy.max_response_bytes()).await
}

async fn drain_bounded_body(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<(), ServerProbeError> {
    if response
        .content_length()
        .is_some_and(|length| length > usize_to_u64_saturating(limit))
    {
        return Err(ServerProbeError::ResponseTooLarge { limit });
    }

    let mut bytes_read = 0_usize;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| ServerProbeError::ResponseRead(error.without_url()))?
    {
        bytes_read = bytes_read
            .checked_add(chunk.len())
            .filter(|length| *length <= limit)
            .ok_or(ServerProbeError::ResponseTooLarge { limit })?;
    }
    Ok(())
}

fn usize_to_u64_saturating(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
