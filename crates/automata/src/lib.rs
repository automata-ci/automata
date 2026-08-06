#![forbid(unsafe_code)]

pub mod app;
pub mod build_info;
pub mod cli;
pub mod shutdown;

use anyhow::Result;
use clap::Parser as _;
use tracing_subscriber::EnvFilter;

use crate::cli::{Cli, Command};

/// Parses process arguments and runs the control plane.
///
/// # Errors
///
/// Returns an error when the selected service cannot bind or exits with an
/// HTTP serving failure.
pub async fn run() -> Result<()> {
    init_tracing();
    execute(Cli::parse()).await
}

async fn execute(cli: Cli) -> Result<()> {
    match &cli.command {
        Command::Server(args) => app::serve(args.listen).await,
        command => cli::execute_control_plane_command(&cli.server_url, cli.output, command).await,
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ignored = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
