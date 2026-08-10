use std::{collections::BTreeSet, error::Error, fmt, net::IpAddr, time::Duration};

use anyhow::{Result, bail};
use reqwest::{StatusCode, Url, redirect::Policy};
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

    /// Returns the deadline for establishing the control-plane connection.
    pub const fn connect_timeout(self) -> Duration {
        self.connect_timeout
    }

    /// Returns the aggregate deadline for sending and reading the health request.
    pub const fn request_timeout(self) -> Duration {
        self.request_timeout
    }

    /// Returns the maximum number of health-response bytes accepted from the server.
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
    /// The connection deadline was zero.
    ZeroConnectTimeout,
    /// The aggregate request deadline was zero.
    ZeroRequestTimeout,
    /// The response-byte ceiling was zero.
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
    InvalidEndpoint,
    ClientConfiguration(reqwest::Error),
    Request(reqwest::Error),
    HttpStatus(StatusCode),
    ResponseTooLarge { limit: usize },
    ResponseRead(reqwest::Error),
}

impl ServerProbeError {
    const fn server_status(&self) -> ServerStatus {
        match self {
            Self::InvalidEndpoint => ServerStatus::Unreachable,
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
            Self::InvalidEndpoint => {
                formatter.write_str("server health endpoint failed transport policy")
            }
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
            Self::InvalidEndpoint | Self::HttpStatus(_) | Self::ResponseTooLarge { .. } => None,
        }
    }
}

/// Health classification for a probed control-plane endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerStatus {
    /// The bounded request completed with the expected successful response.
    Healthy,
    /// The server responded, but its status or response size failed policy.
    Unhealthy,
    /// A client, connection, timeout, or response-read failure prevented a response.
    Unreachable,
}

/// Sanitized result of one bounded control-plane health request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ServerProbe {
    endpoint: String,
    status: ServerStatus,
    detail: Option<String>,
}

impl ServerProbe {
    /// Returns the diagnostic endpoint with credentials, query, and fragment removed.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Returns the health classification.
    pub const fn status(&self) -> ServerStatus {
        self.status
    }

    /// Returns sanitized failure detail, or `None` for a healthy response.
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }

    /// Reports whether the health request satisfied every policy check.
    pub const fn is_healthy(&self) -> bool {
        matches!(self.status, ServerStatus::Healthy)
    }
}

/// Build, platform, capability, and optional control-plane diagnostics.
///
/// Passive reports advertise only capabilities proven usable. Active reports
/// additionally require the rootless-Podman isolation lifecycle to succeed.
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
    /// Returns the exact versioned capability identifiers safe to advertise.
    pub fn capabilities(&self) -> &BTreeSet<&'static str> {
        &self.capabilities
    }

    /// Returns all capability evidence, including degraded and indeterminate results.
    pub fn capability_probes(&self) -> &[CapabilityProbe] {
        &self.capability_probes
    }

    /// Returns the optional control-plane health result.
    pub const fn server(&self) -> Option<&ServerProbe> {
        self.server.as_ref()
    }

    /// Reports whether required process, active-isolation, and server checks passed.
    pub fn is_healthy(&self) -> bool {
        self.capabilities.contains(PROCESS_EXECUTION)
            && (!self.active || self.capabilities.contains(PODMAN_NETWORK_ISOLATION))
            && self.server.as_ref().is_none_or(ServerProbe::is_healthy)
    }
}

/// Collects passive host evidence and optionally probes a control-plane health endpoint.
///
/// This does not create Podman resources; use [`inspect_with_options`] with
/// `active` set to `true` when launch-time isolation proof is required.
pub async fn inspect(server: Option<&str>) -> DoctorReport {
    inspect_with_options(server, false).await
}

/// Collects host and optional server diagnostics, with opt-in active isolation proof.
///
/// When `active` is true and host prerequisites permit, a non-root Linux
/// process creates uniquely owned, bounded Podman resources and removes them
/// before returning. Failures are represented in the report rather than
/// returned as an error.
pub async fn inspect_with_options(server: Option<&str>, active: bool) -> DoctorReport {
    inspect_with_options_and_cancellation(
        server,
        active,
        &podman_probe::ProbeCancellation::default(),
    )
    .await
}

async fn inspect_with_options_and_cancellation(
    server: Option<&str>,
    active: bool,
    cancellation: &podman_probe::ProbeCancellation,
) -> DoctorReport {
    let mut capability_probes = capability_probe::probe_capabilities();
    if active {
        let network_probe = capability_probes
            .iter_mut()
            .find(|probe| probe.capability() == PODMAN_NETWORK_ISOLATION);
        match network_probe {
            Some(probe) if probe.status() == ProbeStatus::Detected => {
                *probe =
                    podman_probe::probe_current_executable_with_cancellation(cancellation).await;
            }
            Some(_) => {}
            None => capability_probes
                .push(podman_probe::probe_current_executable_with_cancellation(cancellation).await),
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

pub(crate) async fn run(
    args: DoctorArgs,
    cancellation: &podman_probe::ProbeCancellation,
) -> Result<()> {
    let report =
        inspect_with_options_and_cancellation(args.server.as_deref(), args.active, cancellation)
            .await;

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
///
/// The configured server must be an HTTPS root origin, or an HTTP root origin
/// whose host is a literal loopback IP address. Credentials, queries,
/// fragments, base paths, and redirects are rejected.
pub async fn probe_server_with_policy(server: &str, policy: ServerHttpPolicy) -> ServerProbe {
    let (request_endpoint, loopback_http) = match health_endpoint(server) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            return ServerProbe {
                endpoint: "invalid control-plane health endpoint".to_owned(),
                status: error.server_status(),
                detail: Some(error.to_string()),
            };
        }
    };
    let endpoint = request_endpoint.to_string();
    match check_server_health(request_endpoint, loopback_http, policy).await {
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

fn health_endpoint(server: &str) -> Result<(Url, bool), ServerProbeError> {
    let mut endpoint = Url::parse(server).map_err(|_| ServerProbeError::InvalidEndpoint)?;
    if !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || endpoint.path() != "/"
    {
        return Err(ServerProbeError::InvalidEndpoint);
    }
    let host = endpoint
        .host_str()
        .ok_or(ServerProbeError::InvalidEndpoint)?;
    let loopback_http = endpoint.scheme() == "http"
        && host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if endpoint.scheme() != "https" && !loopback_http {
        return Err(ServerProbeError::InvalidEndpoint);
    }
    endpoint.set_path("/healthz");
    Ok((endpoint, loopback_http))
}

async fn check_server_health(
    endpoint: Url,
    loopback_http: bool,
    policy: ServerHttpPolicy,
) -> Result<(), ServerProbeError> {
    let mut client = reqwest::Client::builder()
        .redirect(Policy::none())
        .connect_timeout(policy.connect_timeout())
        .timeout(policy.request_timeout());
    if loopback_http {
        client = client.no_proxy();
    }
    let client = client
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
