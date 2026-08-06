//! Command-line interface for both control-plane service roles and operators.

mod commands;
mod execution;
mod output;
mod values;

use clap::Parser;

pub use commands::{
    AdminArgs, AdminCommand, ArtifactArgs, ArtifactCommand, AuthArgs, AuthCommand, AuthLoginArgs,
    AuthLoginMode, CacheArgs, CacheCommand, Command, JobArgs, JobCommand, RunArgs, RunCommand,
    RunnerArgs, RunnerCommand, RunnerGroupArgs, RunnerGroupCommand, SecretArgs, SecretCommand,
    ServerArgs,
};
pub use output::OutputFormat;
pub use values::{RepositoryRef, SecretScope};

pub use execution::{
    StatusHttpPolicy, StatusHttpPolicyError, StatusRequestError, execute_control_plane_command,
    fetch_control_plane_status,
};

#[derive(Debug, Parser)]
#[command(
    name = "automata",
    version,
    long_version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("AUTOMATA_BUILD_GIT_SHA"), ")"),
    about = "GitHub Actions-compatible orchestration and administration"
)]
pub struct Cli {
    /// Automata control-plane URL used by administration commands.
    #[arg(
        long,
        global = true,
        env = "AUTOMATA_SERVER_URL",
        default_value = "http://127.0.0.1:8080"
    )]
    pub server_url: String,

    /// Machine-readable output mode for administration commands.
    #[arg(long, global = true, value_enum, default_value_t)]
    pub output: OutputFormat,

    #[command(subcommand)]
    pub command: Command,
}
