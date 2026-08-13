//! Automata control-plane service and administration CLI.
//!
//! The crate composes workflow admission, durable coordination, runner control,
//! Results-compatible endpoints, and the web application behind the `automata`
//! executable. [`run`] is the process entry point; the public modules expose
//! the same typed configuration and command boundaries for embedding and tests.

#![forbid(unsafe_code)]

/// Human HTTP application, health endpoints, and authenticated provider ingress.
pub mod app;
/// Immutable executable version and source-revision metadata.
pub mod build_info;
pub mod cli;
mod local_demo;
pub mod preview;
pub mod server;
/// Cooperative process-shutdown coordination.
pub mod shutdown;

use anyhow::{Result, bail};
use clap::{Parser as _, error::ErrorKind};
use tracing_subscriber::EnvFilter;

use crate::cli::{Cli, Command};

/// Parses process arguments and runs the control plane.
///
/// # Errors
///
/// Returns an error when the selected service cannot bind or exits with an
/// HTTP serving failure.
pub async fn run() -> Result<()> {
    let Some(cli) = parse_process_arguments()? else {
        return Ok(());
    };
    init_tracing();
    Box::pin(execute(cli)).await
}

fn parse_process_arguments() -> Result<Option<Cli>> {
    match Cli::try_parse() {
        Ok(cli) => Ok(Some(cli)),
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            error.print()?;
            Ok(None)
        }
        Err(_) => bail!("invalid command-line arguments; run `automata --help`"),
    }
}

async fn execute(cli: Cli) -> Result<()> {
    match &cli.command {
        Command::Server(args) => Box::pin(server::serve(args)).await,
        Command::Preview(args) => preview::serve(args).await,
        Command::Demo(args) => local_demo::run(args),
        command => {
            let operator = command
                .operator()
                .expect("service commands are handled before operator dispatch");
            cli::execute_control_plane_command(&operator.server_url, operator.output, command).await
        }
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ignored = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
