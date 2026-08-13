//! Unsupported-platform runner administration adapter.

use anyhow::{Result, bail};

use super::{OutputFormat, RunnerArgs};

pub(crate) async fn execute_runner_command(
    _server_url: &str,
    _output: OutputFormat,
    _args: &RunnerArgs,
) -> Result<()> {
    bail!("runner enrollment token administration is unavailable on this platform")
}
