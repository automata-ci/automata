//! Bounded CLI client for idempotent workflow-priority updates.

use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use automata_ci_auth::session_credential::SessionCredential;
use reqwest::{Client, Method, Request, Response, StatusCode, header};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use super::{
    OutputFormat, PriorityArgs,
    auth::{
        CliServerOrigin, auth_client, bearer_header, decode_json_response,
        discard_bounded_response, retry_after_seconds,
    },
    credential_store::{CliAuthProcessLock, CliCredentialStore, PlatformCredentialStore},
};

const MAX_REQUEST_ATTEMPTS: usize = 3;
const MAX_RETRY_DELAY_SECONDS: u64 = 5;
const SERVER_RETRY_DELAY: Duration = Duration::from_secs(1);
const TRANSPORT_RETRY_DELAY: Duration = Duration::from_millis(100);

pub(crate) async fn execute_priority_command(
    server_url: &str,
    output: OutputFormat,
    args: &PriorityArgs,
) -> Result<()> {
    let origin = CliServerOrigin::new(server_url)
        .context("priority endpoint policy rejected the server URL")?;
    let _process_lock = CliAuthProcessLock::acquire(origin.as_str())
        .context("CLI priority operation could not be serialized")?;
    let store =
        PlatformCredentialStore::discover().context("CLI session custody is unavailable")?;
    let completed = execute_priority_command_with(origin, args, &store).await?;
    print_priority(output, &completed)
}

async fn execute_priority_command_with(
    origin: CliServerOrigin,
    args: &PriorityArgs,
    store: &dyn CliCredentialStore,
) -> Result<CompletedPriority> {
    let client = auth_client().context("failed to configure the workflow priority client")?;
    let credential = store
        .load(origin.as_str())
        .await
        .context("could not load the CLI session securely")?
        .ok_or_else(|| anyhow::anyhow!("no CLI session exists; run `automata auth login`"))?;
    submit_priority(&client, &origin, &credential, args).await
}

async fn submit_priority(
    client: &Client,
    origin: &CliServerOrigin,
    credential: &SessionCredential,
    args: &PriorityArgs,
) -> Result<CompletedPriority> {
    let mut endpoint = origin.endpoint("/api/v1/repositories");
    let run_id = args.run_id.hyphenated().to_string();
    endpoint
        .path_segments_mut()
        .map_err(|()| anyhow::anyhow!("workflow priority endpoint could not be constructed"))?
        .extend([
            args.repository.owner(),
            args.repository.name(),
            "runs",
            &run_id,
            "priority",
        ]);
    let request = client
        .request(Method::PUT, endpoint)
        .header(header::AUTHORIZATION, bearer_header(credential)?)
        .json(&PriorityRequest {
            priority: args.level,
        })
        .build()
        .context("workflow priority request could not be built")?;
    let response = send_with_retries(client, &request).await?;
    let status = response.status();
    if status == StatusCode::OK {
        let document: PriorityResponse = decode_json_response(response).await?;
        if document.priority != args.level {
            bail!("control plane returned inconsistent workflow priority metadata");
        }
        return Ok(CompletedPriority {
            run_id: run_id.clone(),
            priority: document.priority,
        });
    }
    response_error(response, status).await
}

async fn send_with_retries(client: &Client, request: &Request) -> Result<Response> {
    for attempt in 0..MAX_REQUEST_ATTEMPTS {
        let replay = request
            .try_clone()
            .context("workflow priority request could not be replayed")?;
        match client.execute(replay).await {
            Ok(response)
                if attempt + 1 < MAX_REQUEST_ATTEMPTS
                    && matches!(
                        response.status(),
                        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
                    ) =>
            {
                let delay = match retry_after_seconds(&response) {
                    Some(seconds) if seconds <= MAX_RETRY_DELAY_SECONDS => {
                        Duration::from_secs(seconds)
                    }
                    Some(_) => bail!("control plane returned an invalid retry response"),
                    None => SERVER_RETRY_DELAY,
                };
                discard_bounded_response(response)
                    .await
                    .context("could not discard retry response")?;
                sleep(delay).await;
            }
            Ok(response) => return Ok(response),
            Err(_error) if attempt + 1 < MAX_REQUEST_ATTEMPTS => {
                sleep(TRANSPORT_RETRY_DELAY).await;
            }
            Err(error) => return Err(error).context("workflow priority request failed"),
        }
    }
    bail!("workflow priority request failed")
}

async fn response_error<T>(response: Response, status: StatusCode) -> Result<T> {
    discard_bounded_response(response).await?;
    match status {
        StatusCode::UNAUTHORIZED => bail!("CLI session is no longer authorized"),
        StatusCode::FORBIDDEN => {
            bail!("workflow priority update requires runs:priority:update authority")
        }
        StatusCode::NOT_FOUND => bail!("workflow run is unavailable"),
        StatusCode::CONFLICT => {
            bail!("workflow priority is immutable for the run's current state")
        }
        StatusCode::BAD_REQUEST
        | StatusCode::PAYLOAD_TOO_LARGE
        | StatusCode::UNSUPPORTED_MEDIA_TYPE => {
            bail!("control plane rejected the workflow priority request")
        }
        _ => bail!("workflow priority request returned HTTP {status}"),
    }
}

fn print_priority(output: OutputFormat, completed: &CompletedPriority) -> Result<()> {
    match output {
        OutputFormat::Table => {
            println!("run_id\t{}", completed.run_id);
            println!("priority\t{}", completed.priority);
        }
        OutputFormat::Json | OutputFormat::JsonLines => {
            println!("{}", serde_json::to_string(completed)?);
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct PriorityRequest {
    priority: u8,
}

#[derive(Debug, Deserialize)]
struct PriorityResponse {
    priority: u8,
}

#[derive(Debug, Serialize)]
struct CompletedPriority {
    run_id: String,
    priority: u8,
}
