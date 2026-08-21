use anyhow::{Result, bail};

use super::{OutputFormat, PriorityArgs};

pub(crate) async fn execute_priority_command(
    _server_url: &str,
    _output: OutputFormat,
    _args: &PriorityArgs,
) -> Result<()> {
    bail!("CLI workflow priority updates are not supported on this platform")
}
