use anyhow::{Result, bail};

use super::{OutputFormat, SecretCommand};

#[allow(
    clippy::unused_async,
    reason = "the platform implementation must preserve the async dispatch contract"
)]
pub(crate) async fn execute_secret_command(
    _server_url: &str,
    _output: OutputFormat,
    _command: &SecretCommand,
) -> Result<()> {
    bail!("CLI secret management is not supported on this platform")
}
