//! Command-line interface for both control-plane service roles and operators.

#[cfg(unix)]
mod auth;
#[cfg(not(unix))]
#[path = "auth_unsupported.rs"]
mod auth;
mod commands;
#[cfg(unix)]
mod credential_store;
#[cfg(unix)]
mod environment_review;
#[cfg(not(unix))]
#[path = "environment_review_unsupported.rs"]
mod environment_review;
mod execution;
mod output;
#[cfg(unix)]
mod rerun;
#[cfg(not(unix))]
#[path = "rerun_unsupported.rs"]
mod rerun;
#[cfg(unix)]
mod runner;
#[cfg(not(unix))]
#[path = "runner_unsupported.rs"]
mod runner;
#[cfg(unix)]
mod secret;
#[cfg(not(unix))]
#[path = "secret_unsupported.rs"]
mod secret;
mod values;

use clap::{CommandFactory, FromArgMatches, Parser, error::ErrorKind};

pub use commands::{
    AdminArgs, AdminCommand, AuthArgs, AuthCommand, Command, DatabaseTransport,
    EnvironmentReviewArgs, EnvironmentReviewDecision, InternalArgs, InternalCommand,
    InternalEnsureBucketArgs, InternalObjectStoreArgs, InternalObjectStoreCommand, LocalArgs,
    LocalCheckArgs, LocalCommand, LocalContainerEngine, LocalDoctorArgs, LocalWorkflowInput,
    OperatorArgs, RerunArgs, RerunSelection, RunnerArgs, RunnerCommand, RunnerTokenArgs,
    S3ConnectionArgs, S3TlsTrustMode, SecretArgs, SecretCommand, SecretCreateArgs,
    SecretDeleteArgs, SecretListArgs, SecretProviderArgs, SecretProviderCommand, ServerArgs,
};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use commands::{
    InternalBootstrapFileSource, InternalBootstrapRunnerArgs, InternalEngineArgs,
    InternalEngineCommand, InternalLocalArgs, InternalLocalCommand, LocalInitArgs, LocalResetArgs,
    LocalStatusArgs,
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
    about = "CI control-plane services and administration"
)]
struct ParsedCli {
    /// Service role or operator operation to execute.
    #[command(subcommand)]
    command: Command,
}

/// Parsed and cross-field-validated top-level command-line request.
#[derive(Debug)]
pub struct Cli {
    /// Service role or operator operation to execute.
    pub command: Command,
}

impl CommandFactory for Cli {
    fn command() -> clap::Command {
        ParsedCli::command()
    }

    fn command_for_update() -> clap::Command {
        ParsedCli::command_for_update()
    }
}

impl FromArgMatches for Cli {
    fn from_arg_matches(matches: &clap::ArgMatches) -> Result<Self, clap::Error> {
        let parsed = ParsedCli::from_arg_matches(matches)?;
        validate_command(&parsed.command)?;
        Ok(Self {
            command: parsed.command,
        })
    }

    fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches) -> Result<(), clap::Error> {
        *self = Self::from_arg_matches(matches)?;
        Ok(())
    }
}

impl Parser for Cli {}

fn validate_command(command: &Command) -> Result<(), clap::Error> {
    if let Command::Rerun(args) = command
        && args.selection != RerunSelection::JobAndDependents
        && args.job_id.is_some()
    {
        return Err(clap::Error::raw(
            ErrorKind::ArgumentConflict,
            "--job-id is valid only with --selection job-and-dependents",
        ));
    }
    Ok(())
}
