//! Command-line interface for both control-plane service roles and operators.

mod auth;
mod commands;
mod credential_store;
mod execution;
mod output;
mod secret;
mod values;

use clap::Parser;

pub use commands::{
    AdminArgs, AdminCommand, AuthArgs, AuthCommand, Command, DatabaseTransport, OperatorArgs,
    PreviewArgs, SecretArgs, SecretCommand, SecretCreateArgs, SecretDeleteArgs, SecretListArgs,
    SecretProviderArgs, SecretProviderCommand, ServerArgs, WorkflowAdmissionArgs, WorkflowArgs,
    WorkflowCommand,
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
    /// Leading control-plane URL retained for operator-command compatibility.
    #[arg(long, value_name = "URL")]
    pub server_url: Option<String>,

    /// Leading output format retained for operator-command compatibility.
    #[arg(long, value_enum)]
    pub output: Option<OutputFormat>,

    /// Service role or operator operation to execute.
    #[command(subcommand)]
    pub command: Command,
}

impl Cli {
    /// Resolves leading compatibility options over command-scoped defaults.
    #[must_use]
    pub fn operator_options(&self) -> Option<(&str, OutputFormat)> {
        let nested = self.command.operator()?;
        Some((
            self.server_url.as_deref().unwrap_or(&nested.server_url),
            self.output.unwrap_or(nested.output),
        ))
    }

    /// Reports whether leading operator options were supplied to a service command.
    #[must_use]
    pub const fn service_has_operator_options(&self) -> bool {
        self.command.operator().is_none() && (self.server_url.is_some() || self.output.is_some())
    }
}
