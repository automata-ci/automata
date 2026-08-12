use anyhow::{Result, bail};

use super::{EnvironmentReviewArgs, OutputFormat};

#[allow(
    clippy::unused_async,
    reason = "the platform implementation must preserve the async dispatch contract"
)]
pub(crate) async fn execute_environment_review_command(
    _server_url: &str,
    _output: OutputFormat,
    _args: &EnvironmentReviewArgs,
) -> Result<()> {
    bail!("CLI environment review is not supported on this platform")
}
