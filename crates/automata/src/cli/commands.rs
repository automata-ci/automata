use std::{net::SocketAddr, path::PathBuf};

use clap::{Args, Subcommand, ValueEnum};

use super::{RepositoryRef, SecretScope};

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the API, scheduler, results gateway, and SSR user interface.
    Server(ServerArgs),
    /// Authenticate this CLI with an Automata installation.
    Auth(AuthArgs),
    /// Inspect, monitor, cancel, or rerun workflow runs.
    Run(RunArgs),
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
            Self::Auth(_) => "auth command",
            Self::Run(_) => "run command",
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
pub struct ServerArgs {
    /// TCP address on which to listen.
    #[arg(long, env = "AUTOMATA_LISTEN", default_value = "127.0.0.1:8080")]
    pub listen: SocketAddr,
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
