#![forbid(unsafe_code)]

pub mod build_info;
pub mod capability_probe;
pub mod cli;
pub mod doctor;
pub mod podman_probe;
mod probe_http;
pub mod product;

use anyhow::Result;
use clap::Parser as _;
use tracing_subscriber::EnvFilter;

use crate::cli::{Cli, Command};

/// Parses process arguments and runs the runner supervisor command.
///
/// # Errors
///
/// Returns an error when production runner startup/supervision fails, a
/// requested diagnostic cannot be serialized, or a required capability or
/// server health check fails.
pub async fn run() -> Result<()> {
    init_tracing();
    execute(Cli::parse()).await
}

async fn execute(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Run(args) => product::run(&args.config).await.map_err(Into::into),
        Command::Doctor(args) => doctor::run(args).await,
        Command::InternalProbeHttp(args) => probe_http::serve(args).await,
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ignored = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
