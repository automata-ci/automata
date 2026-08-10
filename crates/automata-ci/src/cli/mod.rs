//! Command-line interface for both control-plane service roles and operators.

#[cfg(unix)]
mod auth;
#[cfg(not(unix))]
#[path = "auth_unsupported.rs"]
mod auth;
mod commands;
#[cfg(unix)]
mod credential_store;
mod execution;
mod output;
#[cfg(unix)]
mod secret;
#[cfg(not(unix))]
#[path = "secret_unsupported.rs"]
mod secret;
mod values;

use clap::Parser;

pub use commands::{
    AdminArgs, AdminCommand, AuthArgs, AuthCommand, Command, DatabaseTransport, OperatorArgs,
    PreviewArgs, SecretArgs, SecretCommand, SecretCreateArgs, SecretDeleteArgs, SecretListArgs,
    SecretProviderArgs, SecretProviderCommand, ServerArgs,
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
/// Parsed top-level command-line request.
pub struct Cli {
    /// Service role or operator operation to execute.
    #[command(subcommand)]
    pub command: Command,
}
