//! Authenticated client for one-time runner enrollment tokens.

use std::io::Write as _;

use anyhow::{Context as _, Result, bail};
use automata_ci_auth::session_credential::SessionCredential;
use automata_ci_core::RunnerGroup;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
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
const TOKEN_ENCODED_BYTES: usize = 43;
const CREATE_ATTEMPTS: usize = 3;

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
            let process_lock = CliAuthProcessLock::acquire(origin.as_str())
                .context("runner enrollment token creation could not be serialized")?;
            if args.discard_pending {
                process_lock
                    .remove_runner_enrollment_receipt()
                    .context("pending runner enrollment token receipt could not be discarded")?;
                println!("discarded the pending runner enrollment token receipt");
                return Ok(());
            }
            let store = SecretServiceCredentialStore::discover()
                .context("CLI session custody is unavailable")?;
            let issued = create_token(
                &origin,
                &store,
                &process_lock,
                group.as_str(),
                args.expires_in_seconds,
            )
            .await?;
            print_token(output, &issued)?;
            process_lock
                .remove_runner_enrollment_receipt()
                .context("runner enrollment token receipt could not be completed")
        }
    }
}

async fn create_token(
    origin: &CliServerOrigin,
    store: &dyn CliCredentialStore,
    process_lock: &CliAuthProcessLock,
    group: &str,
    expires_in_seconds: u64,
) -> Result<IssuedToken> {
    let credential = store
        .load(origin.as_str())
        .await
        .context("could not load the CLI session securely")?
        .ok_or_else(|| anyhow::anyhow!("no CLI session exists; run `automata auth login`"))?;
    let pending = load_or_create_pending(process_lock, group, expires_in_seconds)?;
    let body = CreateTokenRequest {
        operation_id: pending.operation_id,
        token: pending.token.as_str(),
        runner_group: group,
        expires_in_seconds,
    };
    let client = auth_client().context("failed to configure the runner enrollment client")?;
    let document = send_idempotent(&client, origin, &credential, &body).await?;
    if document.enrollment_id != pending.operation_id
        || document.runner_group != group
        || document.expires_at_ms <= 0
        || document.redeem_url != "/api/v1/runner-enrollments/redeem"
    {
        bail!("control plane returned inconsistent runner enrollment token metadata");
    }
    Ok(IssuedToken {
        enrollment_id: document.enrollment_id,
        token: pending.token,
        runner_group: document.runner_group,
        expires_at_ms: document.expires_at_ms,
    })
}

fn load_or_create_pending(
    process_lock: &CliAuthProcessLock,
    runner_group: &str,
    expires_in_seconds: u64,
) -> Result<PendingTokenCreate> {
    if let Some(bytes) = process_lock
        .load_runner_enrollment_receipt()
        .context("runner enrollment token receipt could not be loaded")?
    {
        let pending: PendingTokenCreate = serde_json::from_slice(&bytes)
            .context("runner enrollment token receipt is invalid")?;
        if pending.schema != 1
            || pending.operation_id.is_nil()
            || pending.runner_group != runner_group
            || pending.expires_in_seconds != expires_in_seconds
            || !valid_generated_token(pending.token.as_str())
        {
            bail!("runner enrollment token receipt does not match this request");
        }
        return Ok(pending);
    }
    let pending = PendingTokenCreate {
        schema: 1,
        operation_id: Uuid::new_v4(),
        token: generate_token()?,
        runner_group: runner_group.to_owned(),
        expires_in_seconds,
    };
    let encoded = Zeroizing::new(
        serde_json::to_vec(&pending).context("runner enrollment token receipt is invalid")?,
    );
    process_lock
        .store_runner_enrollment_receipt(&encoded)
        .context("runner enrollment token receipt could not be staged")?;
    Ok(pending)
}

async fn send_idempotent(
    client: &Client,
    origin: &CliServerOrigin,
    credential: &SessionCredential,
    body: &CreateTokenRequest<'_>,
) -> Result<CreateTokenResponse> {
    for attempt in 1..=CREATE_ATTEMPTS {
        let response = match send(client, origin, credential, body).await {
            Ok(response) => response,
            Err(_) if attempt < CREATE_ATTEMPTS => continue,
            Err(error) => return Err(error),
        };
        let status = response.status();
        if status != StatusCode::CREATED {
            if status.is_server_error() && attempt < CREATE_ATTEMPTS {
                continue;
            }
            bail!("control plane rejected runner enrollment token creation with HTTP {status}");
        }
        match decode_json_response(response).await {
            Ok(document) => return Ok(document),
            Err(_) if attempt < CREATE_ATTEMPTS => {}
            Err(error) => {
                return Err(error)
                    .context("control plane returned an invalid runner enrollment token response");
            }
        }
    }
    unreachable!("the bounded create-attempt loop always returns on its final attempt")
}

async fn send(
    client: &Client,
    origin: &CliServerOrigin,
    credential: &SessionCredential,
    body: &CreateTokenRequest<'_>,
) -> Result<reqwest::Response> {
    let request_body = Zeroizing::new(
        serde_json::to_vec(body).context("runner enrollment token request could not be encoded")?,
    );
    client
        .post(origin.endpoint(ENROLLMENTS_PATH))
        .header(header::AUTHORIZATION, bearer_header(credential)?)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Bytes::from_owner(request_body))
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

fn valid_generated_token(token: &str) -> bool {
    token
        .strip_prefix(TOKEN_PREFIX)
        .filter(|encoded| encoded.len() == TOKEN_ENCODED_BYTES)
        .and_then(|encoded| URL_SAFE_NO_PAD.decode(encoded).ok())
        .is_some_and(|decoded| decoded.len() == 32)
}

fn print_token(output: OutputFormat, issued: &IssuedToken) -> Result<()> {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    match output {
        OutputFormat::Table => {
            writeln!(stdout, "token\t{}", issued.token.as_str())?;
            writeln!(stdout, "runner_group\t{}", issued.runner_group)?;
            writeln!(stdout, "expires_at_ms\t{}", issued.expires_at_ms)?;
        }
        OutputFormat::Json | OutputFormat::JsonLines => {
            writeln!(
                stdout,
                "{}",
                serde_json::to_string(&IssuedTokenOutput {
                    enrollment_id: issued.enrollment_id,
                    token: issued.token.as_str(),
                    runner_group: &issued.runner_group,
                    expires_at_ms: issued.expires_at_ms,
                })?
            )?;
        }
    }
    stdout
        .flush()
        .context("runner enrollment token output could not be flushed")
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
    runner_group: String,
    expires_at_ms: i64,
    redeem_url: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingTokenCreate {
    schema: u8,
    operation_id: Uuid,
    #[serde(
        deserialize_with = "deserialize_zeroizing",
        serialize_with = "serialize_zeroizing"
    )]
    token: Zeroizing<String>,
    runner_group: String,
    expires_in_seconds: u64,
}

fn serialize_zeroizing<S>(value: &Zeroizing<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(value.as_str())
}

fn deserialize_zeroizing<'de, D>(deserializer: D) -> Result<Zeroizing<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Zeroizing::new)
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
