use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "automata-runner",
    version,
    long_version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("AUTOMATA_BUILD_GIT_SHA"), ")"),
    about = "Automata cross-platform runner"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Inspect local capabilities; read-only unless --active is supplied.
    Doctor(DoctorArgs),
    /// Internal one-shot readiness server used by the isolated network probe.
    #[command(name = "__probe-http-ready", hide = true)]
    InternalProbeHttp(InternalProbeHttpArgs),
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Optionally verify an Automata server health endpoint.
    #[arg(long, env = "AUTOMATA_SERVER_URL")]
    pub server: Option<String>,
    /// Render the report as JSON.
    #[arg(long)]
    pub json: bool,
    /// Create short-lived, isolated resources to verify Podman networking.
    #[arg(long)]
    pub active: bool,
}

#[derive(Debug, Args)]
pub struct InternalProbeHttpArgs {
    /// Container port for the one-shot readiness listener.
    #[arg(long, hide = true)]
    pub port: u16,
    /// Collision-resistant token required in the readiness request path.
    #[arg(long, hide = true)]
    pub token: String,
}
