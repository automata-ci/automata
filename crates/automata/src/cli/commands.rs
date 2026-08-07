use std::{net::SocketAddr, path::PathBuf};

use clap::{Args, Subcommand, ValueEnum};

use super::{RepositoryRef, SecretScope};
use crate::server::SecretSource;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the API, scheduler, results gateway, and SSR user interface.
    #[command(alias = "serve")]
    Server(Box<ServerArgs>),
    /// Serve only dependency-free health checks and the SSR user interface.
    ///
    /// This explicit mode is intended for release-image smoke tests and local
    /// UI previews. It never starts the scheduler or runner-control services.
    Preview(PreviewArgs),
    /// Authenticate this CLI with an Automata installation.
    Auth(AuthArgs),
    /// Inspect, monitor, cancel, or rerun workflow runs.
    Run(RunArgs),
    /// Dispatch and inspect workflow definitions.
    Workflow(WorkflowArgs),
    /// Inspect jobs and stream their logs.
    Job(JobArgs),
    /// Manage encrypted Actions secrets.
    Secret(SecretArgs),
    /// Manage registered runners.
    Runner(RunnerArgs),
    /// Manage runner routing and access groups.
    #[command(name = "runner-group")]
    RunnerGroup(RunnerGroupArgs),
    /// Inspect or retrieve run artifacts.
    Artifact(ArtifactArgs),
    /// Inspect or evict Actions caches.
    Cache(CacheArgs),
    /// Inspect control-plane status and administrative state.
    Admin(AdminArgs),
}

impl Command {
    pub const fn operation_name(&self) -> &'static str {
        match self {
            Self::Server(_) => "server",
            Self::Preview(_) => "preview",
            Self::Auth(_) => "auth command",
            Self::Run(_) => "run command",
            Self::Workflow(_) => "workflow command",
            Self::Job(_) => "job command",
            Self::Secret(_) => "secret command",
            Self::Runner(_) => "runner command",
            Self::RunnerGroup(_) => "runner-group command",
            Self::Artifact(_) => "artifact command",
            Self::Cache(_) => "cache command",
            Self::Admin(_) => "admin command",
        }
    }
}

#[derive(Debug, Args)]
pub struct PreviewArgs {
    /// Health and SSR TCP listen address.
    #[arg(
        long,
        env = "AUTOMATA_PREVIEW_LISTEN",
        default_value = "127.0.0.1:8080"
    )]
    pub listen: SocketAddr,
}

#[derive(Debug, Args)]
pub struct ServerArgs {
    /// Human API and SSR TCP listen address.
    #[arg(long, env = "AUTOMATA_LISTEN", default_value = "127.0.0.1:8080")]
    pub listen: SocketAddr,

    /// Dedicated direct-mTLS HTTP/2 runner-control listen address.
    #[arg(long, env = "AUTOMATA_RUNNER_LISTEN", default_value = "127.0.0.1:9090")]
    pub runner_listen: SocketAddr,

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

    /// S3 bucket containing immutable Automata objects.
    #[arg(long, env = "AUTOMATA_S3_BUCKET", default_value = "automata")]
    pub s3_bucket: String,

    /// Optional key prefix reserved for this Automata installation.
    #[arg(long, env = "AUTOMATA_S3_PREFIX")]
    pub s3_prefix: Option<String>,

    /// Use path-style bucket addressing for the S3 adapter.
    #[arg(long, env = "AUTOMATA_S3_FORCE_PATH_STYLE")]
    pub s3_force_path_style: bool,

    /// Permit plain HTTP only when the S3 endpoint is a literal loopback host.
    #[arg(long, env = "AUTOMATA_S3_ALLOW_LOOPBACK_HTTP")]
    pub s3_allow_loopback_http: bool,

    /// All-attempt timeout for one immutable object-store operation.
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

    /// PEM bundle reference containing trusted runner client certificate roots.
    #[arg(
        long,
        env = "AUTOMATA_RUNNER_CLIENT_CA_SOURCE",
        default_value = "env:AUTOMATA_RUNNER_CLIENT_CA_PEM",
        value_name = "env:NAME|file:PATH"
    )]
    pub runner_client_ca_source: SecretSource,

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
    #[arg(
        long,
        env = "AUTOMATA_STALE_RUNNER_SESSION_TIMEOUT_SECONDS",
        default_value_t = 300,
        value_parser = clap::value_parser!(u64).range(30..=86_400)
    )]
    pub stale_runner_session_timeout_seconds: u64,

    /// Enable the loopback-only local workflow ingress with a bearer-token reference.
    #[arg(
        long = "local-admission-token-source",
        env = "AUTOMATA_LOCAL_ADMISSION_TOKEN_SOURCE",
        value_name = "env:NAME|file:PATH"
    )]
    pub local_admission_token_source: Option<SecretSource>,

    /// Authenticated tenant bound to the local workflow ingress.
    #[arg(long, env = "AUTOMATA_LOCAL_ADMISSION_TENANT", default_value = "local")]
    pub local_admission_tenant: String,
}

#[derive(Debug, Args)]
pub struct AuthArgs {
    #[command(subcommand)]
    pub command: AuthCommand,
}

#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    /// Start an interactive provider login.
    Login(AuthLoginArgs),
    /// Show the current principal and session expiry.
    Status,
    /// Revoke and remove the current local session.
    Logout,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum AuthLoginMode {
    /// GitHub's device flow, suitable for terminals and headless hosts.
    #[default]
    Device,
    /// Open a browser and complete a web authorization flow.
    Web,
}

#[derive(Debug, Args)]
pub struct AuthLoginArgs {
    /// Authentication provider configured on the server.
    #[arg(long, default_value = "github")]
    pub provider: String,
    /// Interactive flow to use.
    #[arg(long, value_enum, default_value_t)]
    pub mode: AuthLoginMode,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    #[command(subcommand)]
    pub command: RunCommand,
}

#[derive(Debug, Args)]
pub struct WorkflowArgs {
    #[command(subcommand)]
    pub command: WorkflowCommand,
}

#[derive(Debug, Subcommand)]
pub enum WorkflowCommand {
    /// Dispatch an exact workflow snapshot through the local bootstrap ingress.
    Dispatch(WorkflowDispatchArgs),
}

#[derive(Debug, Args)]
pub struct WorkflowDispatchArgs {
    /// Repository in OWNER/NAME form.
    #[arg(short = 'R', long)]
    pub repository: RepositoryRef,

    /// Stable repository identifier assigned by the provider.
    #[arg(long)]
    pub provider_repository_id: String,

    /// Repository-relative workflow path.
    #[arg(long, default_value = ".github/workflows/ci.yml")]
    pub workflow: String,

    /// Exact workflow source to dispatch.
    #[arg(long, value_name = "PATH", default_value = ".github/workflows/ci.yml")]
    pub source_file: PathBuf,

    /// Exact provider event JSON. Omit to dispatch an empty object.
    #[arg(long, value_name = "PATH")]
    pub event_file: Option<PathBuf>,

    /// GitHub-compatible event name.
    #[arg(long, default_value = "workflow_dispatch")]
    pub event_name: String,

    /// Stable provider delivery identifier used for exact retry replay.
    #[arg(long)]
    pub delivery_id: String,

    /// Immutable 40- or 64-character commit SHA selected for this run.
    #[arg(long)]
    pub commit_sha: String,

    /// Fully-qualified Git ref selected for this run.
    #[arg(long = "ref", default_value = "refs/heads/main")]
    pub git_ref: String,

    /// Display name of the selected workflow.
    #[arg(long, default_value = "CI")]
    pub workflow_name: String,

    /// Local admission bearer-token reference; the value never enters argv.
    #[arg(
        long = "local-admission-token-source",
        env = "AUTOMATA_LOCAL_ADMISSION_TOKEN_SOURCE",
        default_value = "env:AUTOMATA_LOCAL_ADMISSION_TOKEN",
        value_name = "env:NAME|file:PATH"
    )]
    pub token_source: SecretSource,
}

#[derive(Debug, Subcommand)]
pub enum RunCommand {
    /// List workflow runs for a repository.
    List(RunListArgs),
    /// Show a workflow run and its jobs.
    View(RunTargetArgs),
    /// Follow a run until it reaches a terminal state.
    Watch(RunWatchArgs),
    /// Request cancellation of a run.
    Cancel(RunMutationArgs),
    /// Create a new attempt for a run.
    Rerun(RerunArgs),
}

#[derive(Debug, Args)]
pub struct RunListArgs {
    #[arg(short = 'R', long)]
    pub repository: RepositoryRef,
    #[arg(long)]
    pub status: Option<String>,
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u16).range(1..=1000))]
    pub limit: u16,
}

#[derive(Debug, Args)]
pub struct RunTargetArgs {
    pub run_id: String,
    #[arg(short = 'R', long)]
    pub repository: RepositoryRef,
}

#[derive(Debug, Args)]
pub struct RunWatchArgs {
    #[command(flatten)]
    pub target: RunTargetArgs,
    /// Poll interval in seconds when streaming transport is unavailable.
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u16).range(1..=300))]
    pub interval: u16,
}

#[derive(Debug, Args)]
pub struct RunMutationArgs {
    #[command(flatten)]
    pub target: RunTargetArgs,
    /// Skip the interactive confirmation prompt.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct RerunArgs {
    #[command(flatten)]
    pub target: RunTargetArgs,
    /// Rerun only failed jobs and their dependants.
    #[arg(long)]
    pub failed: bool,
}

#[derive(Debug, Args)]
pub struct JobArgs {
    #[command(subcommand)]
    pub command: JobCommand,
}

#[derive(Debug, Subcommand)]
pub enum JobCommand {
    /// Show one job attempt.
    View(JobTargetArgs),
    /// Stream or print one job's logs.
    Logs(JobLogsArgs),
    /// Request cancellation of one job.
    Cancel(JobMutationArgs),
}

#[derive(Debug, Args)]
pub struct JobTargetArgs {
    pub job_id: String,
    #[arg(short = 'R', long)]
    pub repository: RepositoryRef,
}

#[derive(Debug, Args)]
pub struct JobLogsArgs {
    #[command(flatten)]
    pub target: JobTargetArgs,
    /// Continue following newly acknowledged log frames.
    #[arg(short, long)]
    pub follow: bool,
}

#[derive(Debug, Args)]
pub struct JobMutationArgs {
    #[command(flatten)]
    pub target: JobTargetArgs,
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct SecretArgs {
    #[command(subcommand)]
    pub command: SecretCommand,
}

#[derive(Debug, Subcommand)]
pub enum SecretCommand {
    /// Read a value securely and create or replace a secret.
    Set(SecretSetArgs),
    /// List secret metadata; values are never returned.
    List(SecretListArgs),
    /// Delete a secret.
    Delete(SecretDeleteArgs),
}

#[derive(Debug, Args)]
pub struct SecretSetArgs {
    pub name: String,
    /// Secret scope, for example repo:OWNER/REPO or env:OWNER/REPO/production.
    #[arg(long)]
    pub scope: SecretScope,
    /// Read the value from a file. Omit to read from a hidden prompt or stdin.
    #[arg(long, value_name = "PATH")]
    pub from_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct SecretListArgs {
    #[arg(long)]
    pub scope: SecretScope,
}

#[derive(Debug, Args)]
pub struct SecretDeleteArgs {
    pub name: String,
    #[arg(long)]
    pub scope: SecretScope,
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct RunnerArgs {
    #[command(subcommand)]
    pub command: RunnerCommand,
}

#[derive(Debug, Subcommand)]
pub enum RunnerCommand {
    List(RunnerListArgs),
    View(IdArgs),
    Remove(DestructiveIdArgs),
    /// Mint a short-lived, one-use runner enrollment token.
    EnrollmentToken(RunnerEnrollmentTokenArgs),
}

#[derive(Debug, Args)]
pub struct RunnerListArgs {
    #[arg(long)]
    pub group: Option<String>,
    #[arg(long)]
    pub label: Vec<String>,
}

#[derive(Debug, Args)]
pub struct RunnerEnrollmentTokenArgs {
    #[arg(long)]
    pub group: String,
    /// Token lifetime in seconds.
    #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u32).range(30..=3600))]
    pub ttl: u32,
}

#[derive(Debug, Args)]
pub struct RunnerGroupArgs {
    #[command(subcommand)]
    pub command: RunnerGroupCommand,
}

#[derive(Debug, Subcommand)]
pub enum RunnerGroupCommand {
    List,
    View(NameArgs),
    Create(RunnerGroupCreateArgs),
    Delete(DestructiveNameArgs),
}

#[derive(Debug, Args)]
pub struct RunnerGroupCreateArgs {
    pub name: String,
    #[arg(long)]
    pub repository: Vec<RepositoryRef>,
}

#[derive(Debug, Args)]
pub struct ArtifactArgs {
    #[command(subcommand)]
    pub command: ArtifactCommand,
}

#[derive(Debug, Subcommand)]
pub enum ArtifactCommand {
    List(RunTargetArgs),
    Download(ArtifactDownloadArgs),
    Delete(DestructiveIdArgs),
}

#[derive(Debug, Args)]
pub struct ArtifactDownloadArgs {
    pub artifact_id: String,
    #[arg(long, default_value = ".")]
    pub directory: PathBuf,
}

#[derive(Debug, Args)]
pub struct CacheArgs {
    #[command(subcommand)]
    pub command: CacheCommand,
}

#[derive(Debug, Subcommand)]
pub enum CacheCommand {
    List(CacheListArgs),
    Delete(CacheDeleteArgs),
}

#[derive(Debug, Args)]
pub struct CacheListArgs {
    #[arg(short = 'R', long)]
    pub repository: RepositoryRef,
    #[arg(long)]
    pub key: Option<String>,
    #[arg(long)]
    pub r#ref: Option<String>,
}

#[derive(Debug, Args)]
pub struct CacheDeleteArgs {
    pub cache_id: String,
    #[arg(short = 'R', long)]
    pub repository: RepositoryRef,
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct AdminArgs {
    #[command(subcommand)]
    pub command: AdminCommand,
}

#[derive(Debug, Subcommand)]
pub enum AdminCommand {
    /// Show dependency health, version skew, and replica status.
    Status,
    /// Show queued work and scheduler admission reasons.
    Queue,
}

#[derive(Debug, Args)]
pub struct IdArgs {
    pub id: String,
}

#[derive(Debug, Args)]
pub struct NameArgs {
    pub name: String,
}

#[derive(Debug, Args)]
pub struct DestructiveIdArgs {
    pub id: String,
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct DestructiveNameArgs {
    pub name: String,
    #[arg(long)]
    pub yes: bool,
}
