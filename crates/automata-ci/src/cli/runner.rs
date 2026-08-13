//! Authenticated client for one-time runner enrollment tokens.

use anyhow::{Context as _, Result, bail};
use automata_ci_auth::session_credential::SessionCredential;
use automata_ci_core::RunnerGroup;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Client, StatusCode, header};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    OutputFormat, RunnerArgs, RunnerCommand,
    auth::{CliServerOrigin, auth_client, bearer_header, decode_json_response},
    credential_store::{CliAuthProcessLock, CliCredentialStore, SecretServiceCredentialStore},
};

const ENROLLMENTS_PATH: &str = "/api/v1/runner-enrollments";
const TOKEN_PREFIX: &str = "atm_re_";

pub(crate) async fn execute_runner_command(
    server_url: &str,
    output: OutputFormat,
    args: &RunnerArgs,
) -> Result<()> {
    match &args.command {
        RunnerCommand::Token(args) => {
            let group = RunnerGroup::new(&args.group).context("runner group is invalid")?;
            let origin = CliServerOrigin::new(server_url)
                .context("runner enrollment endpoint policy rejected the server URL")?;
            let _process_lock = CliAuthProcessLock::acquire(origin.as_str())
                .context("runner enrollment token creation could not be serialized")?;
            let store = SecretServiceCredentialStore::discover()
                .context("CLI session custody is unavailable")?;
            let issued =
                create_token(&origin, &store, group.as_str(), args.expires_in_seconds).await?;
            print_token(output, &issued)
        }
    }
}

async fn create_token(
    origin: &CliServerOrigin,
    store: &dyn CliCredentialStore,
    group: &str,
    expires_in_seconds: u64,
) -> Result<IssuedToken> {
    let credential = store
        .load(origin.as_str())
        .await
        .context("could not load the CLI session securely")?
        .ok_or_else(|| anyhow::anyhow!("no CLI session exists; run `automata auth login`"))?;
    let token = generate_token()?;
    let operation_id = Uuid::new_v4();
    let body = CreateTokenRequest {
        operation_id,
        token: token.as_str(),
        runner_group: group,
        expires_in_seconds,
    };
    let client = auth_client().context("failed to configure the runner enrollment client")?;
    let response = send(&client, origin, &credential, &body).await?;
    let status = response.status();
    if status != StatusCode::CREATED {
        bail!("control plane rejected runner enrollment token creation with HTTP {status}");
    }
    let document: CreateTokenResponse = decode_json_response(response)
        .await
        .context("control plane returned an invalid runner enrollment token response")?;
    if document.enrollment_id != operation_id
        || document.token != token.as_str()
        || document.runner_group != group
        || document.expires_at_ms <= 0
        || document.redeem_url != "/api/v1/runner-enrollments/redeem"
    {
        bail!("control plane returned inconsistent runner enrollment token metadata");
    }
    Ok(IssuedToken {
        enrollment_id: document.enrollment_id,
        token,
        runner_group: document.runner_group,
        expires_at_ms: document.expires_at_ms,
    })
}

async fn send(
    client: &Client,
    origin: &CliServerOrigin,
    credential: &SessionCredential,
    body: &CreateTokenRequest<'_>,
) -> Result<reqwest::Response> {
    client
        .post(origin.endpoint(ENROLLMENTS_PATH))
        .header(header::AUTHORIZATION, bearer_header(credential)?)
        .header(header::CONTENT_TYPE, "application/json")
        .json(body)
        .send()
        .await
        .map_err(reqwest::Error::without_url)
        .context("runner enrollment token request failed")
}

fn generate_token() -> Result<Zeroizing<String>> {
    let mut entropy = Zeroizing::new([0_u8; 32]);
    getrandom::fill(&mut *entropy).context("runner enrollment token entropy is unavailable")?;
    Ok(Zeroizing::new(format!(
        "{TOKEN_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(entropy.as_slice())
    )))
}

fn print_token(output: OutputFormat, issued: &IssuedToken) -> Result<()> {
    match output {
        OutputFormat::Table => {
            println!("token\t{}", issued.token.as_str());
            println!("runner_group\t{}", issued.runner_group);
            println!("expires_at_ms\t{}", issued.expires_at_ms);
        }
        OutputFormat::Json | OutputFormat::JsonLines => {
            println!(
                "{}",
                serde_json::to_string(&IssuedTokenOutput {
                    enrollment_id: issued.enrollment_id,
                    token: issued.token.as_str(),
                    runner_group: &issued.runner_group,
                    expires_at_ms: issued.expires_at_ms,
                })?
            );
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct CreateTokenRequest<'a> {
    operation_id: Uuid,
    token: &'a str,
    runner_group: &'a str,
    expires_in_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateTokenResponse {
    enrollment_id: Uuid,
    token: String,
    runner_group: String,
    expires_at_ms: i64,
    redeem_url: String,
}

struct IssuedToken {
    enrollment_id: Uuid,
    token: Zeroizing<String>,
    runner_group: String,
    expires_at_ms: i64,
}

#[derive(Serialize)]
struct IssuedTokenOutput<'a> {
    enrollment_id: Uuid,
    token: &'a str,
    runner_group: &'a str,
    expires_at_ms: i64,
}
