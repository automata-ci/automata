use std::{fmt, net::SocketAddr, path::PathBuf, str::FromStr};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use automata_ci_local::InstallationName;
use clap::{Args, Subcommand, ValueEnum};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::num::NonZeroU16;
use uuid::Uuid;

use super::{OutputFormat, RepositoryRef, SecretScope};
use crate::server::{SecretSource, VersionedSecretSource};

#[derive(Debug, Subcommand)]
/// Top-level service and operator command selection.
///
/// Server, authentication, repository-secret, environment-review, workflow
/// priority, workflow-rerun, and administrative status operations are implemented.
pub enum Command {
    /// Run the human API, runner control, Results gateway, and SSR interface.
    Server(Box<ServerArgs>),
    /// Inspect or manage a disposable local Automata installation.
    Local(LocalArgs),
    /// Authenticate the operator CLI and manage its server-scoped session.
    Auth(AuthArgs),
    /// Manage encrypted Actions secrets.
    Secret(SecretArgs),
    /// Approve or reject one protected-environment gate.
    EnvironmentReview(EnvironmentReviewArgs),
    /// Create an authenticated rerun of one completed workflow run.
    Rerun(RerunArgs),
    /// Set the priority of one queued workflow run.
    Priority(PriorityArgs),
    /// Manage self-hosted runners and one-time enrollment tokens.
    Runner(RunnerArgs),
    /// Inspect control-plane status.
    Admin(AdminArgs),
    /// Run image-internal service initialization operations.
    #[command(hide = true)]
    Internal(InternalArgs),
}

impl Command {
    /// Returns connection and presentation options for an operator command.
    #[must_use]
    pub const fn operator(&self) -> Option<&OperatorArgs> {
        match self {
            Self::Auth(args) => Some(&args.operator),
            Self::Secret(args) => Some(&args.operator),
            Self::EnvironmentReview(args) => Some(&args.operator),
            Self::Rerun(args) => Some(&args.operator),
            Self::Priority(args) => Some(&args.operator),
            Self::Runner(args) => Some(&args.operator),
            Self::Admin(args) => Some(&args.operator),
            Self::Server(_) | Self::Local(_) | Self::Internal(_) => None,
        }
    }
}

#[derive(Debug, Args)]
/// Image-internal service initialization namespace.
pub struct InternalArgs {
    /// Internal service boundary to initialize.
    #[command(subcommand)]
    pub command: InternalCommand,
}

#[derive(Debug, Subcommand)]
/// Closed image-internal service initialization boundaries.
pub enum InternalCommand {
    /// Initialize the configured object-store boundary.
    ObjectStore(Box<InternalObjectStoreArgs>),
    /// Materialize one fixed local-installation epoch inside its helper.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    Local(InternalLocalArgs),
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Debug, Args)]
/// Fixed image-internal local-installation operations.
pub struct InternalLocalArgs {
    /// Exact fixed local-installation helper operation.
    #[command(subcommand)]
    pub command: InternalLocalCommand,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Debug, Subcommand)]
/// Closed one-shot local-installation helper boundary.
pub enum InternalLocalCommand {
    /// Materialize and seal the fixed mounted epoch volumes.
    Materialize,
}

#[derive(Debug, Args)]
/// Image-internal object-store initialization operations.
pub struct InternalObjectStoreArgs {
    /// Exact object-store initialization operation.
    #[command(subcommand)]
    pub command: InternalObjectStoreCommand,
}

#[derive(Debug, Subcommand)]
/// Current object-store initialization operations.
pub enum InternalObjectStoreCommand {
    /// Ensure the exact configured bucket exists and is accessible.
    EnsureBucket(InternalEnsureBucketArgs),
}

#[derive(Debug, Args)]
/// Exact bucket initialization inputs.
pub struct InternalEnsureBucketArgs {
    /// Production S3 connection, trust, deadline, and credential-source inputs.
    #[command(flatten)]
    pub s3: S3ConnectionArgs,
}

#[derive(Debug, Args)]
/// Disposable local-installation commands.
pub struct LocalArgs {
    /// Local-installation operation to perform.
    #[command(subcommand)]
    pub command: LocalCommand,
}

#[derive(Debug, Subcommand)]
/// Operations supported by the local-installation supervisor.
pub enum LocalCommand {
    /// Check this host without creating containers or local state.
    Doctor(LocalDoctorArgs),
    /// Validate one exact local workflow without admission or execution.
    Check(LocalCheckArgs),
    /// Seal or replay one x86-64 Linux epoch without starting services.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    Init(LocalInitArgs),
    /// Inspect recorded custody or reset progress without changing host or Engine state.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    Status(LocalStatusArgs),
    /// Remove exact sealed Engine custody while retaining images and the state root.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    Reset(LocalResetArgs),
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Debug, Args)]
/// Immutable local-installation initialization inputs.
pub struct LocalInitArgs {
    /// Explicit absolute host directory for private installation custody.
    #[arg(long, value_name = "ABS", value_parser = parse_absolute_state_directory)]
    pub state_directory: PathBuf,
    /// Canonical local installation selector.
    #[arg(long, default_value = "default")]
    pub installation: InstallationName,
    /// Immutable ordinary-runner capacity for this epoch.
    #[arg(long, default_value = "1")]
    pub workers: NonZeroU16,
    /// Operator-selected canonical release evidence; init verifies structure and digests, not OIDC authenticity.
    #[arg(long, value_name = "file:ABS", value_parser = parse_catalog_source)]
    pub catalog_source: String,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Debug, Args)]
/// Read-only sealed-installation status inputs.
pub struct LocalStatusArgs {
    /// Explicit absolute host directory containing installation custody.
    #[arg(long, value_name = "ABS", value_parser = parse_absolute_state_directory)]
    pub state_directory: PathBuf,
    /// Render one stable redacted JSON document instead of human text.
    #[arg(long)]
    pub json: bool,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Debug, Args)]
/// Exact destructive local-installation reset inputs.
pub struct LocalResetArgs {
    /// Explicit absolute host directory containing installation custody.
    #[arg(long, value_name = "ABS", value_parser = parse_absolute_state_directory)]
    pub state_directory: PathBuf,
    /// Confirm deletion without an interactive prompt.
    #[arg(long, required = true)]
    pub yes: bool,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn parse_absolute_state_directory(value: &str) -> Result<PathBuf, &'static str> {
    if !valid_absolute_unix_path(value) {
        return Err("state directory must be one canonical absolute Unix path");
    }
    Ok(PathBuf::from(value))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn parse_catalog_source(value: &str) -> Result<String, &'static str> {
    let Some(path) = value.strip_prefix("file:") else {
        return Err("catalog source must use file:/absolute/path");
    };
    if !valid_absolute_unix_path(path) {
        return Err("catalog source must use one canonical absolute Unix path");
    }
    Ok(value.to_owned())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn valid_absolute_unix_path(value: &str) -> bool {
    value.starts_with('/')
        && value != "/"
        && !value.ends_with('/')
        && !value.contains("//")
        && value
            .split('/')
            .skip(1)
            .all(|part| !part.is_empty() && !matches!(part, "." | ".."))
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum, serde::Serialize)]
#[serde(rename_all = "snake_case")]
#[value(rename_all = "kebab-case")]
/// Container engine selected for the disposable local installation.
pub enum LocalContainerEngine {
    /// Select the portable Docker Engine path.
    #[default]
    Auto,
    /// Require Docker Engine and Compose plugin version 2.20.0 or newer.
    Docker,
}

#[derive(Debug, Args)]
/// Read-only local-installation preflight options.
pub struct LocalDoctorArgs {
    /// Container engine to inspect.
    #[arg(long, env = "AUTOMATA_LOCAL_ENGINE", value_enum, default_value_t)]
    pub engine: LocalContainerEngine,
    /// Render one stable JSON document instead of a human-readable report.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
/// Read-only exact-snapshot workflow validation options.
pub struct LocalCheckArgs {
    /// Canonical repository-relative workflow path; omit only when exactly one exists.
    pub workflow: Option<String>,
    /// Manual-dispatch input in `NAME=VALUE` form.
    #[arg(long = "input", value_name = "NAME=VALUE")]
    pub inputs: Vec<LocalWorkflowInput>,
    /// Render one stable JSON document instead of a human-readable report.
    #[arg(long)]
    pub json: bool,
}

/// One redacted local manual-dispatch input parsed from the command line.
#[derive(Clone, Eq, PartialEq)]
pub struct LocalWorkflowInput {
    name: String,
    value: String,
}

impl LocalWorkflowInput {
    /// Returns the canonical input name candidate.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn value(&self) -> &str {
        &self.value
    }
}

impl FromStr for LocalWorkflowInput {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (name, value) = value
            .split_once('=')
            .ok_or("local workflow inputs must use NAME=VALUE")?;
        if name.is_empty() {
            return Err("local workflow input names must not be empty");
        }
        Ok(Self {
            name: name.to_owned(),
            value: value.to_owned(),
        })
    }
}

impl fmt::Debug for LocalWorkflowInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalWorkflowInput")
            .field("name", &self.name)
            .field("value", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Args)]
/// Authenticated runner administration commands.
pub struct RunnerArgs {
    /// Connection and output policy for this operator command.
    #[command(flatten)]
    pub operator: OperatorArgs,
    /// Runner operation to perform.
    #[command(subcommand)]
    pub command: RunnerCommand,
}

#[derive(Debug, Subcommand)]
/// Runner operations supported by the operator CLI.
pub enum RunnerCommand {
    /// Create a short-lived, one-use runner enrollment token.
    Token(RunnerTokenArgs),
}

#[derive(Debug, Args)]
/// Scope and lifetime for a new one-use enrollment token.
pub struct RunnerTokenArgs {
    /// Discard the pending local create receipt and exit without issuing a token.
    #[arg(long)]
    pub discard_pending: bool,
    /// Canonical runner group to create or select.
    #[arg(long, default_value = "default")]
    pub group: String,
    /// Token lifetime in seconds (60-3600).
    #[arg(long, default_value_t = 900, value_parser = clap::value_parser!(u64).range(60..=3600))]
    pub expires_in_seconds: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum, serde::Serialize)]
#[serde(rename_all = "snake_case")]
#[value(rename_all = "kebab-case")]
/// Exact decision recorded for a protected-environment gate.
pub enum EnvironmentReviewDecision {
    /// Count this reviewer toward the environment's approval threshold.
    Approve,
    /// Reject the protected-environment request.
    Reject,
}

#[cfg(unix)]
impl EnvironmentReviewDecision {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
        }
    }
}

#[derive(Debug, Args)]
/// Authenticated protected-environment review request.
pub struct EnvironmentReviewArgs {
    /// Connection and output policy for this operator command.
    #[command(flatten)]
    pub operator: OperatorArgs,
    /// Exact canonical repository UUID containing the gated attempt.
    #[arg(value_parser = parse_canonical_uuid)]
    pub repository_id: Uuid,
    /// Exact canonical gated job-attempt UUID.
    #[arg(value_parser = parse_canonical_uuid)]
    pub attempt_id: Uuid,
    /// Approval decision to record for the current reviewer.
    #[arg(long, value_enum)]
    pub decision: EnvironmentReviewDecision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "kebab-case")]
/// Exact workflow subset selected for a rerun.
pub enum RerunSelection {
    /// Re-execute every job in the workflow.
    EntireWorkflow,
    /// Re-execute failed or timed-out jobs and their dependents.
    FailedJobsAndDependents,
    /// Re-execute one logical job and all of its dependents.
    JobAndDependents,
}

#[derive(Debug, Args)]
/// Authenticated workflow-rerun request.
pub struct RerunArgs {
    /// Connection and output policy for this operator command.
    #[command(flatten)]
    pub operator: OperatorArgs,
    /// GitHub repository in canonical OWNER/REPOSITORY form.
    pub repository: RepositoryRef,
    /// Exact canonical completed source-run UUID.
    #[arg(value_parser = parse_canonical_uuid)]
    pub source_run_id: Uuid,
    /// Workflow subset to re-execute.
    #[arg(long, value_enum)]
    pub selection: RerunSelection,
    /// Exact canonical logical-job UUID; required only for job-and-dependents.
    #[arg(
        long,
        value_parser = parse_canonical_uuid,
        required_if_eq("selection", "job-and-dependents")
    )]
    pub job_id: Option<Uuid>,
    /// Stable operation UUID for an exact retry; generated once when omitted.
    #[arg(long, value_parser = parse_canonical_uuid)]
    pub operation_id: Option<Uuid>,
}

#[derive(Debug, Args)]
/// Authenticated workflow-priority request.
pub struct PriorityArgs {
    /// Connection and output policy for this operator command.
    #[command(flatten)]
    pub operator: OperatorArgs,
    /// GitHub repository in canonical OWNER/REPOSITORY form.
    pub repository: RepositoryRef,
    /// Exact canonical queued workflow-run UUID.
    #[arg(value_parser = parse_canonical_uuid)]
    pub run_id: Uuid,
    /// Exact user-controlled priority in 0..=99; larger values run first.
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=99))]
    pub level: u8,
}

fn parse_canonical_uuid(value: &str) -> Result<Uuid, String> {
    let parsed = Uuid::parse_str(value).map_err(|_| "expected a canonical UUID".to_owned())?;
    if parsed.is_nil() || parsed.hyphenated().to_string() != value {
        return Err("expected a non-nil lowercase hyphenated UUID".to_owned());
    }
    Ok(parsed)
}

#[derive(Debug, Args)]
/// Connection and presentation options shared only by operator commands.
pub struct OperatorArgs {
    /// Automata control-plane URL used by this operator command.
    #[arg(
        long,
        global = true,
        env = "AUTOMATA_SERVER_URL",
        default_value = "http://127.0.0.1:8080"
    )]
    pub server_url: String,

    /// Output format for this operator command.
    #[arg(long, global = true, value_enum, default_value_t)]
    pub output: OutputFormat,
}

/// `PostgreSQL` transport policy selected at the product boundary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum DatabaseTransport {
    /// Verify TLS through the compiled Web PKI roots.
    #[default]
    WebPkiVerifyFull,
    /// Verify TLS through Web PKI plus one deployment-provided CA.
    WebPkiPlusPrivateCaVerifyFull,
    /// Disable TLS only for a literal loopback TCP address.
    LoopbackPlaintext,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "kebab-case")]
/// Exact HTTPS trust policy for the S3 endpoint.
pub enum S3TlsTrustMode {
    /// Authenticate through the platform Web PKI root store.
    #[default]
    WebPki,
    /// Authenticate through exactly one deployment-provided private CA.
    PrivateCa,
}

#[derive(Debug, Args)]
/// Shared S3 endpoint, trust, deadline, and credential-source inputs.
pub struct S3ConnectionArgs {
    /// Credential-free S3-compatible endpoint origin.
    #[arg(
        long,
        env = "AUTOMATA_S3_ENDPOINT",
        default_value = "https://s3.amazonaws.com/"
    )]
    pub s3_endpoint: String,

    /// S3 signing region.
    #[arg(long, env = "AUTOMATA_S3_REGION", default_value = "us-east-1")]
    pub s3_region: String,

    /// Exact S3 bucket owned by this Automata installation.
    #[arg(long, env = "AUTOMATA_S3_BUCKET", default_value = "automata")]
    pub s3_bucket: String,

    /// Use path-style bucket addressing for the S3 adapter.
    #[arg(long, env = "AUTOMATA_S3_FORCE_PATH_STYLE")]
    pub s3_force_path_style: bool,

    /// Exact HTTPS server trust policy.
    #[arg(long, env = "AUTOMATA_S3_TLS_TRUST", value_enum, default_value_t)]
    pub s3_tls_trust: S3TlsTrustMode,

    /// Exact private-CA PEM reference, required only with `private-ca` trust.
    #[arg(
        long,
        env = "AUTOMATA_S3_PRIVATE_CA_SOURCE",
        value_name = "env:NAME|file:PATH"
    )]
    pub s3_private_ca_source: Option<SecretSource>,

    /// Permit plaintext only for a literal-loopback HTTP endpoint.
    #[arg(long, env = "AUTOMATA_S3_ALLOW_LOOPBACK_HTTP")]
    pub s3_allow_loopback_http: bool,

    /// Total wall-clock deadline for one object-store operation.
    #[arg(
        long,
        env = "AUTOMATA_S3_OPERATION_TIMEOUT_SECONDS",
        default_value_t = 30,
        value_parser = clap::value_parser!(u64).range(1..=300)
    )]
    pub s3_operation_timeout_seconds: u64,

    /// S3 access-key reference; secret values are never accepted in argv.
    #[arg(
        long,
        env = "AUTOMATA_S3_ACCESS_KEY_SOURCE",
        default_value = "env:AUTOMATA_S3_ACCESS_KEY",
        value_name = "env:NAME|file:PATH"
    )]
    pub s3_access_key_source: SecretSource,

    /// S3 secret-key reference; secret values are never accepted in argv.
    #[arg(
        long,
        env = "AUTOMATA_S3_SECRET_KEY_SOURCE",
        default_value = "env:AUTOMATA_S3_SECRET_KEY",
        value_name = "env:NAME|file:PATH"
    )]
    pub s3_secret_key_source: SecretSource,

    /// Optional S3 session-token reference.
    #[arg(
        long,
        env = "AUTOMATA_S3_SESSION_TOKEN_SOURCE",
        value_name = "env:NAME|file:PATH"
    )]
    pub s3_session_token_source: Option<SecretSource>,
}

#[derive(Debug, Args)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent opt-in security and development policies map directly to CLI flags"
)]
/// Deployment inputs for one control-plane replica.
///
/// Credential-bearing values are accepted only through [`SecretSource`]
/// references. [`crate::server::ServerConfig::from_args`] performs the final
/// cross-field, transport, duration, and listener validation before startup.
pub struct ServerArgs {
    /// Human API and SSR TCP listen address.
    #[arg(long, env = "AUTOMATA_LISTEN", default_value = "127.0.0.1:8080")]
    pub listen: SocketAddr,

    /// Optional loopback-only Prometheus/OpenMetrics listen address.
    ///
    /// Metrics are disabled when this option is omitted. Production deployments
    /// should keep this listener private and scrape it through a node-local agent.
    #[arg(long, env = "AUTOMATA_METRICS_LISTEN", value_name = "LOOPBACK_ADDR")]
    pub metrics_listen: Option<SocketAddr>,

    /// Canonical public origin for browser authentication and same-origin checks.
    ///
    /// The URL must be an HTTPS origin with a root path. Literal-loopback HTTP
    /// is available only with `--auth-allow-loopback-http`.
    #[arg(long, env = "AUTOMATA_EXTERNAL_URL", value_name = "URL")]
    pub external_url: Option<String>,

    /// Permit plain HTTP authentication only on a literal-loopback origin and listener.
    #[arg(long, env = "AUTOMATA_AUTH_ALLOW_LOOPBACK_HTTP")]
    pub auth_allow_loopback_http: bool,

    /// Trust an upstream reverse proxy to isolate a non-loopback human/webhook bind.
    ///
    /// The product listener itself is HTTP. This explicit deployment assertion
    /// is required when an HTTPS browser origin is paired with a non-loopback bind.
    #[arg(
        long,
        env = "AUTOMATA_HUMAN_TRUSTED_REVERSE_PROXY",
        conflicts_with = "auth_allow_loopback_http"
    )]
    pub human_trusted_reverse_proxy: bool,

    /// GitHub App OAuth client identifier used for human login.
    #[arg(long, env = "AUTOMATA_GITHUB_CLIENT_ID")]
    pub github_client_id: Option<String>,

    /// GitHub App OAuth client-secret reference; values are never accepted in argv.
    #[arg(
        long,
        env = "AUTOMATA_GITHUB_CLIENT_SECRET_SOURCE",
        value_name = "env:NAME|file:PATH"
    )]
    pub github_client_secret_source: Option<SecretSource>,

    /// HMAC key reference used to hash opaque browser and CLI session tokens.
    #[arg(
        long,
        env = "AUTOMATA_AUTH_SESSION_HASH_KEY_SOURCE",
        value_name = "env:NAME|file:PATH"
    )]
    pub auth_session_hash_key_source: Option<SecretSource>,

    /// Envelope-encryption key reference for durable human GitHub OAuth tokens.
    #[arg(
        long,
        env = "AUTOMATA_AUTH_ENCRYPTION_KEY_SOURCE",
        value_name = "env:NAME|file:PATH"
    )]
    pub auth_encryption_key_source: Option<SecretSource>,

    /// Deployment-scoped bearer for the private conformance export.
    ///
    /// This machine-only authority is accepted only when the human listener is
    /// loopback-bound and human authentication is disabled.
    #[arg(
        long,
        env = "AUTOMATA_CONFORMANCE_EXPORT_TOKEN_SOURCE",
        value_name = "env:NAME|file:PATH"
    )]
    pub conformance_export_token_source: Option<SecretSource>,

    /// Stable identity for the active human-authentication token wrapping key.
    #[arg(long, env = "AUTOMATA_AUTH_KEY_ID", default_value = "primary")]
    pub auth_key_id: String,

    /// Decrypt-only old human-authentication token key retained during rotation.
    #[arg(
        long = "auth-decryption-key",
        env = "AUTOMATA_AUTH_DECRYPTION_KEYS",
        value_name = "KEY_ID=env:NAME|file:PATH",
        value_delimiter = ','
    )]
    pub auth_decryption_keys: Vec<VersionedSecretSource>,

    /// Active 32-byte wrapping-key reference for the built-in secret provider.
    #[arg(
        long,
        env = "AUTOMATA_SECRET_ENCRYPTION_KEY_SOURCE",
        value_name = "env:NAME|file:PATH"
    )]
    pub secret_encryption_key_source: Option<SecretSource>,

    /// Stable identity for the active built-in secret-provider wrapping key.
    #[arg(
        long,
        env = "AUTOMATA_SECRET_ENCRYPTION_KEY_ID",
        default_value = "primary"
    )]
    pub secret_encryption_key_id: String,

    /// Decrypt-only old wrapping key retained during online key rotation.
    #[arg(
        long = "secret-decryption-key",
        env = "AUTOMATA_SECRET_DECRYPTION_KEYS",
        value_name = "KEY_ID=env:NAME|file:PATH",
        value_delimiter = ','
    )]
    pub secret_decryption_keys: Vec<VersionedSecretSource>,

    /// Mandatory key for runner messages and GitHub App service credentials.
    #[arg(
        long,
        env = "AUTOMATA_CONTROL_PLANE_ENCRYPTION_KEY_SOURCE",
        default_value = "env:AUTOMATA_CONTROL_PLANE_ENCRYPTION_KEY",
        value_name = "env:NAME|file:PATH"
    )]
    pub control_plane_encryption_key_source: SecretSource,

    /// Stable identity for the active control-plane payload wrapping key.
    #[arg(
        long,
        env = "AUTOMATA_CONTROL_PLANE_ENCRYPTION_KEY_ID",
        default_value = "primary"
    )]
    pub control_plane_encryption_key_id: String,

    /// Decrypt-only old control-plane key retained while every payload rotates.
    #[arg(
        long = "control-plane-decryption-key",
        env = "AUTOMATA_CONTROL_PLANE_DECRYPTION_KEYS",
        value_name = "KEY_ID=env:NAME|file:PATH",
        value_delimiter = ','
    )]
    pub control_plane_decryption_keys: Vec<VersionedSecretSource>,

    /// Browser-session absolute lifetime.
    #[arg(
        long,
        env = "AUTOMATA_AUTH_BROWSER_SESSION_TTL_SECONDS",
        default_value_t = 28_800,
        value_parser = clap::value_parser!(u64).range(300..=86_400)
    )]
    pub auth_browser_session_ttl_seconds: u64,

    /// CLI-session absolute lifetime.
    #[arg(
        long,
        env = "AUTOMATA_AUTH_CLI_SESSION_TTL_SECONDS",
        default_value_t = 2_592_000,
        value_parser = clap::value_parser!(u64).range(300..=7_776_000)
    )]
    pub auth_cli_session_ttl_seconds: u64,

    /// Optional one-use installation bootstrap-token reference.
    #[arg(
        long,
        env = "AUTOMATA_BOOTSTRAP_TOKEN_SOURCE",
        value_name = "env:NAME|file:PATH"
    )]
    pub bootstrap_token_source: Option<SecretSource>,

    /// Exact stable numeric GitHub user ID permitted to complete initial setup.
    #[arg(long, env = "AUTOMATA_BOOTSTRAP_GITHUB_USER_ID")]
    pub bootstrap_github_user_id: Option<u64>,

    /// Exact tenant identifier to create during one-use installation setup.
    #[arg(long, env = "AUTOMATA_BOOTSTRAP_TENANT_ID")]
    pub bootstrap_tenant_id: Option<String>,

    /// Human-readable tenant name durably bound before installation setup begins.
    #[arg(long, env = "AUTOMATA_BOOTSTRAP_TENANT_DISPLAY_NAME")]
    pub bootstrap_tenant_display_name: Option<String>,

    /// Dedicated direct-mTLS HTTP/2 runner-control listen address.
    #[arg(long, env = "AUTOMATA_RUNNER_LISTEN", default_value = "127.0.0.1:9090")]
    pub runner_listen: SocketAddr,

    /// Public HTTPS runner-control origin used by direct mTLS clients.
    #[arg(long, env = "AUTOMATA_RUNNER_PUBLIC_URL", value_name = "URL")]
    pub runner_public_url: Option<String>,

    /// Publish presentation-safe runner health and capacity at `/runners`.
    /// Without this flag the page requires current `runners:read` authority.
    #[arg(long, env = "AUTOMATA_RUNNER_DIRECTORY_PUBLIC")]
    pub runner_directory_public: bool,

    /// Dedicated GitHub Actions Results HTTP listen address.
    ///
    /// Production HTTPS is normally terminated by a trusted reverse proxy in
    /// front of this listener. Plain HTTP requires the explicit development
    /// option and an exact loopback or private-interface bind.
    #[arg(
        long,
        env = "AUTOMATA_RESULTS_LISTEN",
        default_value = "127.0.0.1:8081"
    )]
    pub results_listen: SocketAddr,

    /// Public Results origin injected into each job, including its trailing slash.
    #[arg(long, env = "AUTOMATA_RESULTS_PUBLIC_URL", value_name = "URL")]
    pub results_public_url: Option<String>,

    /// Trust an upstream reverse proxy to isolate a non-loopback Results bind and terminate TLS.
    ///
    /// The product listener itself is HTTP. This explicit deployment assertion
    /// is required when an HTTPS public URL is paired with a non-loopback bind.
    #[arg(
        long,
        env = "AUTOMATA_RESULTS_TRUSTED_REVERSE_PROXY",
        conflicts_with = "results_allow_development_http"
    )]
    pub results_trusted_reverse_proxy: bool,

    /// Permit a credential-free plain-HTTP Results origin for local development.
    #[arg(long, env = "AUTOMATA_RESULTS_ALLOW_DEVELOPMENT_HTTP")]
    pub results_allow_development_http: bool,

    /// Exact public host asserted to map to a private development listener.
    #[arg(
        long,
        env = "AUTOMATA_RESULTS_TRUSTED_PRIVATE_HOST",
        requires = "results_allow_development_http"
    )]
    pub results_trusted_private_host: Option<String>,

    /// HMAC signing-key reference for per-attempt Results credentials.
    #[arg(
        long,
        env = "AUTOMATA_RESULTS_SIGNING_KEY_SOURCE",
        default_value = "env:AUTOMATA_RESULTS_SIGNING_KEY",
        value_name = "env:NAME|file:PATH"
    )]
    pub results_signing_key_source: SecretSource,

    /// Stable Results signing-key identity used for audited key rotation.
    #[arg(long, env = "AUTOMATA_RESULTS_KEY_ID", default_value = "primary")]
    pub results_key_id: String,

    /// Optional strict manifest reference enabling Actions-compatible workload OIDC.
    ///
    /// The manifest contains only bounded public policy plus environment or file
    /// references for private key material; raw keys are never accepted in argv.
    #[arg(
        long,
        env = "AUTOMATA_WORKLOAD_OIDC_CONFIG_SOURCE",
        value_name = "env:NAME|file:PATH"
    )]
    pub workload_oidc_config_source: Option<SecretSource>,

    /// Optional strict trust registry for broker-signed Windows runner admission.
    ///
    /// Each issuer is independently pinned to one broker host, one exact
    /// environment profile, and one image-promotion trust bundle. Omitting this
    /// option keeps Windows runner enrollment fail-closed.
    #[arg(
        long,
        env = "AUTOMATA_WINDOWS_RUNNER_ADMISSION_CONFIG_SOURCE",
        value_name = "env:NAME|file:PATH"
    )]
    pub windows_runner_admission_config_source: Option<SecretSource>,

    /// `PostgreSQL` URL reference; secret values are never accepted in argv.
    #[arg(
        long,
        env = "AUTOMATA_DATABASE_URL_SOURCE",
        default_value = "env:AUTOMATA_DATABASE_URL",
        value_name = "env:NAME|file:PATH"
    )]
    pub database_url_source: SecretSource,

    /// Maximum `PostgreSQL` connections owned by this replica.
    #[arg(
        long,
        env = "AUTOMATA_DATABASE_MAX_CONNECTIONS",
        default_value_t = 20,
        value_parser = clap::value_parser!(u32).range(1..=1024)
    )]
    pub database_max_connections: u32,

    /// Explicit database transport policy.
    #[arg(long, env = "AUTOMATA_DATABASE_TRANSPORT", value_enum, default_value_t)]
    pub database_transport: DatabaseTransport,

    /// Additive private CA used only with `web-pki-plus-private-ca-verify-full`.
    ///
    /// `SQLx` retains its compiled Web PKI roots in this mode; the supplied
    /// canonical CA certificate augments that root set and does not replace it.
    #[arg(
        long,
        env = "AUTOMATA_DATABASE_PRIVATE_CA_SOURCE",
        value_name = "env:NAME|file:PATH"
    )]
    pub database_private_ca_source: Option<SecretSource>,

    /// S3 endpoint, trust, deadline, and credential-source inputs.
    #[command(flatten)]
    pub s3: S3ConnectionArgs,

    /// Optional key prefix reserved for this Automata installation.
    #[arg(long, env = "AUTOMATA_S3_PREFIX")]
    pub s3_prefix: Option<String>,

    /// Exact KMS key identity for S3 server-side encryption.
    ///
    /// Omitting this option selects provider-managed AES-256 (`SSE-S3`).
    /// Supplying it selects `SSE-KMS`, and every read must report this exact
    /// key identity as well as the expected encryption algorithm.
    #[arg(long, env = "AUTOMATA_S3_KMS_KEY_ID", value_name = "KEY_ID")]
    pub s3_kms_key_id: Option<String>,

    /// PEM certificate for the CA that authenticates runner clients.
    #[arg(
        long = "runner-client-ca-cert-source",
        env = "AUTOMATA_RUNNER_CLIENT_CA_CERT_SOURCE",
        default_value = "env:AUTOMATA_RUNNER_CLIENT_CA_CERT_PEM",
        value_name = "env:NAME|file:PATH"
    )]
    pub runner_client_ca_certificate_source: SecretSource,

    /// PEM private key for issuing runner client certificates.
    #[arg(
        long,
        env = "AUTOMATA_RUNNER_CLIENT_CA_KEY_SOURCE",
        default_value = "env:AUTOMATA_RUNNER_CLIENT_CA_KEY_PEM",
        value_name = "env:NAME|file:PATH"
    )]
    pub runner_client_ca_key_source: SecretSource,

    /// PEM trust-anchor bundle installed on enrolled runners for server authentication.
    #[arg(
        long,
        env = "AUTOMATA_RUNNER_SERVER_CA_SOURCE",
        default_value = "env:AUTOMATA_RUNNER_SERVER_CA_PEM",
        value_name = "env:NAME|file:PATH"
    )]
    pub runner_server_ca_source: SecretSource,

    /// PEM chain reference for the runner-control server identity.
    #[arg(
        long = "runner-server-cert-source",
        env = "AUTOMATA_RUNNER_SERVER_CERT_SOURCE",
        default_value = "env:AUTOMATA_RUNNER_SERVER_CERT_PEM",
        value_name = "env:NAME|file:PATH"
    )]
    pub runner_server_certificate_source: SecretSource,

    /// PEM private-key reference for the runner-control server identity.
    #[arg(
        long,
        env = "AUTOMATA_RUNNER_SERVER_KEY_SOURCE",
        default_value = "env:AUTOMATA_RUNNER_SERVER_KEY_PEM",
        value_name = "env:NAME|file:PATH"
    )]
    pub runner_server_key_source: SecretSource,

    /// Optional private mTLS gRPC listen address for shard management.
    ///
    /// Omitting this option disables the management listener and preserves the
    /// standalone self-hosted topology. Enabling it requires every related
    /// authority, fingerprint, and TLS option below.
    #[arg(long, env = "AUTOMATA_MANAGEMENT_LISTEN", value_name = "ADDR")]
    pub management_listen: Option<SocketAddr>,

    /// Immutable identity of the Core shard served by this deployment.
    #[arg(long, env = "AUTOMATA_MANAGEMENT_SHARD_ID", value_name = "SHARD")]
    pub management_shard_id: Option<String>,

    /// Stable identity of the workload allowed to provision this shard.
    #[arg(
        long,
        env = "AUTOMATA_MANAGEMENT_AUTHORITY_ID",
        value_name = "AUTHORITY"
    )]
    pub management_authority_id: Option<String>,

    /// Exact HTTPS issuer accepted for delegated actor identities.
    #[arg(
        long,
        env = "AUTOMATA_MANAGEMENT_DELEGATED_ACTOR_ISSUER",
        value_name = "ORIGIN"
    )]
    pub management_delegated_actor_issuer: Option<String>,

    /// Exact JWKS endpoint used to verify delegated actor assertions.
    #[arg(
        long,
        env = "AUTOMATA_MANAGEMENT_DELEGATED_ACTOR_JWKS_URL",
        value_name = "URL"
    )]
    pub management_delegated_actor_jwks_url: Option<String>,

    /// Permit a literal loopback HTTP JWKS endpoint for local development.
    #[arg(
        long,
        env = "AUTOMATA_MANAGEMENT_DELEGATED_ACTOR_JWKS_ALLOW_LOOPBACK_HTTP",
        default_value_t = false
    )]
    pub management_delegated_actor_jwks_allow_loopback_http: bool,

    /// SHA-256 fingerprint of an allowed leaf client certificate, in hex.
    ///
    /// Repeat the option, or provide a comma-separated environment value, to
    /// overlap old and new certificates during rotation.
    #[arg(
        long = "management-client-cert-sha256",
        env = "AUTOMATA_MANAGEMENT_CLIENT_CERT_SHA256",
        value_name = "HEX",
        value_delimiter = ','
    )]
    pub management_client_certificate_sha256: Vec<String>,

    /// PEM CA bundle used exclusively to authenticate management clients.
    #[arg(
        long = "management-client-ca-cert-source",
        env = "AUTOMATA_MANAGEMENT_CLIENT_CA_CERT_SOURCE",
        value_name = "env:NAME|file:PATH"
    )]
    pub management_client_ca_certificate_source: Option<SecretSource>,

    /// PEM chain reference for the private management server identity.
    #[arg(
        long = "management-server-cert-source",
        env = "AUTOMATA_MANAGEMENT_SERVER_CERT_SOURCE",
        value_name = "env:NAME|file:PATH"
    )]
    pub management_server_certificate_source: Option<SecretSource>,

    /// PEM private-key reference for the private management server identity.
    #[arg(
        long,
        env = "AUTOMATA_MANAGEMENT_SERVER_KEY_SOURCE",
        value_name = "env:NAME|file:PATH"
    )]
    pub management_server_key_source: Option<SecretSource>,

    /// Interval between database and immutable object-store readiness probes.
    #[arg(
        long,
        env = "AUTOMATA_READINESS_PROBE_INTERVAL_SECONDS",
        default_value_t = 30,
        value_parser = clap::value_parser!(u64).range(1..=300)
    )]
    pub readiness_probe_interval_seconds: u64,

    /// Delay between bounded expired-lease and stale-session maintenance passes.
    #[arg(
        long,
        env = "AUTOMATA_MAINTENANCE_INTERVAL_SECONDS",
        default_value_t = 5,
        value_parser = clap::value_parser!(u64).range(1..=300)
    )]
    pub maintenance_interval_seconds: u64,

    /// Maximum attempts and sessions considered by each maintenance pass.
    #[arg(
        long,
        env = "AUTOMATA_MAINTENANCE_BATCH_SIZE",
        default_value_t = 100,
        value_parser = clap::value_parser!(u16).range(1..=1000)
    )]
    pub maintenance_batch_size: u16,

    /// Lease expirations permitted before unstarted work is marked lost.
    #[arg(
        long,
        env = "AUTOMATA_MAXIMUM_LEASE_FAILURES",
        default_value_t = 3,
        value_parser = clap::value_parser!(u32).range(1..=2_147_483_647)
    )]
    pub maximum_lease_failures: u32,

    /// Missing-heartbeat duration after which a runner session is closed.
    /// Must be greater than the maintenance interval.
    #[arg(
        long,
        env = "AUTOMATA_STALE_RUNNER_SESSION_TIMEOUT_SECONDS",
        default_value_t = 300,
        value_parser = clap::value_parser!(u64).range(30..=86_400)
    )]
    pub stale_runner_session_timeout_seconds: u64,

    /// Tenant used by unauthenticated UI and provider scope when human auth is disabled.
    #[arg(
        long = "fallback-tenant-id",
        env = "AUTOMATA_FALLBACK_TENANT_ID",
        default_value = "local"
    )]
    pub fallback_tenant_id: String,
}

#[derive(Debug, Args)]
/// Server-scoped human-authentication commands.
pub struct AuthArgs {
    /// Connection and output policy for this operator command.
    #[command(flatten)]
    pub operator: OperatorArgs,
    /// Authentication operation to perform.
    #[command(subcommand)]
    pub command: AuthCommand,
}

#[derive(Debug, Subcommand)]
/// Human-authentication operations supported by the CLI.
pub enum AuthCommand {
    /// Authenticate with GitHub using a device authorization flow.
    Login,
    /// Show the current server-scoped CLI session.
    Status,
    /// Revoke and remove the current server-scoped CLI session.
    Logout,
}

#[derive(Debug, Args)]
/// Secret metadata and mutation command selection.
pub struct SecretArgs {
    /// Connection and output policy for this operator command.
    #[command(flatten)]
    pub operator: OperatorArgs,
    /// Secret operation to perform.
    #[command(subcommand)]
    pub command: SecretCommand,
}

#[derive(Debug, Subcommand)]
/// Secret operations represented by the CLI.
pub enum SecretCommand {
    /// Create with `secrets:metadata:read` plus `secrets:create` authority.
    Create(SecretCreateArgs),
    /// List secret metadata with `secrets:metadata:read`; values are never returned.
    List(SecretListArgs),
    /// Delete with `secrets:metadata:read` plus `secrets:delete` authority.
    Delete(SecretDeleteArgs),
    /// Inspect or activate the built-in encrypted provider.
    Provider(SecretProviderArgs),
}

#[derive(Debug, Args)]
/// Scope, name, and protected input source for secret creation.
pub struct SecretCreateArgs {
    /// Canonical secret name.
    pub name: String,
    /// Exact repository scope in repo:OWNER/REPOSITORY form.
    #[arg(long)]
    pub scope: SecretScope,
    /// Read the value from a safe owner-only file. Omit to read redirected stdin.
    #[arg(long, value_name = "PATH")]
    pub from_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
/// Scope selector for a value-free secret metadata listing.
pub struct SecretListArgs {
    /// Exact secret scope to list.
    #[arg(long)]
    pub scope: SecretScope,
}

#[derive(Debug, Args)]
/// Exact secret selector and confirmation policy for deletion.
pub struct SecretDeleteArgs {
    /// Canonical secret name.
    pub name: String,
    /// Exact secret scope containing the name.
    #[arg(long)]
    pub scope: SecretScope,
    /// Skip the interactive confirmation prompt.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
/// Built-in secret-provider operation selection.
pub struct SecretProviderArgs {
    /// Provider operation to perform.
    #[command(subcommand)]
    pub command: SecretProviderCommand,
}

#[derive(Debug, Subcommand)]
/// Value-free built-in secret-provider operations.
pub enum SecretProviderCommand {
    /// Show sanitized provider state with `secret-providers:read` authority.
    Status,
    /// Activate with `secret-providers:read` plus `secret-providers:manage`.
    Activate,
}

#[derive(Debug, Args)]
/// Administrative inspection command selection.
pub struct AdminArgs {
    /// Connection and output policy for this operator command.
    #[command(flatten)]
    pub operator: OperatorArgs,
    /// Administrative operation to perform.
    #[command(subcommand)]
    pub command: AdminCommand,
}

#[derive(Debug, Subcommand)]
/// Value-free administrative operations represented by the CLI.
pub enum AdminCommand {
    /// Show separate process-health identity and dependency-readiness observations.
    Status,
}
