use anyhow::{Result, bail};

use super::{AuthCommand, OutputFormat};

#[allow(
    clippy::unused_async,
    reason = "the platform implementation must preserve the async dispatch contract"
)]
pub(crate) async fn execute_auth_command(
    _server_url: &str,
    _output: OutputFormat,
    _command: &AuthCommand,
) -> Result<()> {
    bail!("CLI authentication is not supported on this platform")
}
