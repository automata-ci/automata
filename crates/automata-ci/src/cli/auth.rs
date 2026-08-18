//! Operational GitHub device authentication for the operator CLI.

use std::{
    error::Error,
    fmt,
    fs::File,
    io::{IsTerminal as _, Write as _},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context as _, Result, bail};
use automata_ci_auth::{
    github::GithubDevicePollCredential,
    human::{PrincipalId, ProviderId, ProviderSubject, TenantId},
    secret::SecretString,
    session::SessionId,
    session_credential::SessionCredential,
};
use bytes::Bytes;
use reqwest::{Client, Response, StatusCode, header};
use rustix::fs::{FileType, Mode, OFlags, fstat, open};
use serde::{Deserialize, Serialize};
use tokio::time::{Instant, sleep_until, timeout_at};
use url::{Host, Url};
use zeroize::Zeroizing;

use super::{
    AuthCommand, OutputFormat,
    credential_store::{CliAuthProcessLock, CliCredentialStore, PlatformCredentialStore},
    output::escaped_table_value,
};
use crate::app::github_auth::{
    CLI_SESSION_PATH, GITHUB_DEVICE_BEGIN_PATH, GITHUB_DEVICE_POLL_PATH,
};

const MAX_AUTH_RESPONSE_BYTES: usize = 16 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_POLL_DELAY_SECONDS: u64 = 300;
const MAX_DEVICE_FLOW_SECONDS: u64 = 3_600;
const MAX_DISPLAY_TEXT_BYTES: usize = 1_024;

pub(crate) async fn execute_auth_command(
    server_url: &str,
    output: OutputFormat,
    command: &AuthCommand,
) -> Result<()> {
    let origin = CliServerOrigin::new(server_url)
        .context("authentication endpoint policy rejected the server URL")?;
    let _process_lock = CliAuthProcessLock::acquire(origin.as_str())
        .context("CLI authentication operation could not be serialized")?;
    let store = Arc::new(
        PlatformCredentialStore::discover().context("CLI session custody is unavailable")?,
    );
    let prompt: Box<dyn DeviceAuthorizationPrompt> = match command {
        AuthCommand::Login => Box::new(
            ControllingTerminalPrompt::open()
                .context("a controlling terminal is required for device authorization")?,
        ),
        AuthCommand::Status | AuthCommand::Logout => Box::new(UnavailableDevicePrompt),
    };
    execute_auth_command_with(origin, output, command, store, prompt.as_ref()).await
}

async fn execute_auth_command_with(
    origin: CliServerOrigin,
    output: OutputFormat,
    command: &AuthCommand,
    store: Arc<dyn CliCredentialStore>,
    prompt: &dyn DeviceAuthorizationPrompt,
) -> Result<()> {
    let client = auth_client().context("failed to configure authentication client")?;
    match command {
        AuthCommand::Login => login(&client, &origin, output, store.as_ref(), prompt).await,
        AuthCommand::Status => status(&client, &origin, output, store.as_ref()).await,
        AuthCommand::Logout => logout(&client, &origin, output, store.as_ref()).await,
    }
}

#[allow(clippy::too_many_lines)] // One bounded device-flow state machine is easier to audit intact.
async fn login(
    client: &Client,
    origin: &CliServerOrigin,
    output: OutputFormat,
    store: &dyn CliCredentialStore,
    prompt: &dyn DeviceAuthorizationPrompt,
) -> Result<()> {
    if let Some(existing) = store
        .load(origin.as_str())
        .await
        .context("could not inspect existing CLI session custody")?
    {
        match activate_remote(client, origin, &existing).await {
            Ok(RemoteActivation::Active) => {
                bail!(
                    "a CLI session already exists for this server; log out before signing in again"
                );
            }
            Ok(RemoteActivation::Rejected) => {
                store
                    .remove(origin.as_str())
                    .await
                    .context("could not remove a rejected local CLI session")?;
            }
            Err(error) => {
                return Err(error).context(
                    "existing CLI session activation is indeterminate; local custody was retained",
                );
            }
        }
    }

    let response = client
        .post(origin.endpoint(GITHUB_DEVICE_BEGIN_PATH))
        .header(header::CONTENT_TYPE, "application/json")
        .body(r#"{"return_path":null}"#)
        .send()
        .await
        .map_err(reqwest::Error::without_url)
        .context("could not start GitHub device authorization")?;
    let start: DeviceStartDocument = successful_json(response, StatusCode::OK)
        .await
        .context("control plane returned an invalid device authorization")?;
    let verification_uri = validate_verification_uri(&start.verification_uri)
        .context("control plane returned an untrusted GitHub verification URL")?;
    if start.expires_at == 0
        || start.expires_in_seconds == 0
        || start.expires_in_seconds > MAX_DEVICE_FLOW_SECONDS
        || start.poll_interval_seconds == 0
        || start.poll_interval_seconds > MAX_POLL_DELAY_SECONDS
        || !valid_device_user_code(start.user_code.expose_secret())
    {
        bail!("control plane returned an invalid device authorization lifetime");
    }
    let poll_credential = GithubDevicePollCredential::from_raw(
        start.poll_credential.expose_secret(),
    )
    .map_err(|_| anyhow::anyhow!("control plane returned an invalid device authorization"))?;
    let flow_deadline = Instant::now()
        .checked_add(Duration::from_secs(start.expires_in_seconds))
        .ok_or_else(|| anyhow::anyhow!("device authorization deadline overflowed"))?;

    prompt
        .show(&verification_uri, &start.user_code)
        .context("could not present GitHub device authorization securely")?;

    let mut next_delay = start.poll_interval_seconds;
    // The typed proof is the sole credential copy needed by the poll loop.
    // Prompting is complete, so promptly zeroize the original proof and user
    // code instead of retaining the start document until login completes.
    drop(start);
    loop {
        let poll_at = checked_poll_instant(next_delay, flow_deadline)?;
        sleep_until(poll_at).await;
        if Instant::now() >= flow_deadline {
            bail!("GitHub device authorization expired");
        }
        let body = poll_request_body(&poll_credential);
        let response = timeout_at(
            flow_deadline,
            client
                .post(origin.endpoint(GITHUB_DEVICE_POLL_PATH))
                .header(header::CONTENT_TYPE, "application/json")
                .body(body)
                .send(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("GitHub device authorization expired"))?
        .map_err(reqwest::Error::without_url)
        .context("GitHub device authorization poll failed")?;
        let retry_after = retry_after_seconds(&response);
        match response.status() {
            StatusCode::OK => {
                let complete: DevicePollDocument =
                    timeout_at(flow_deadline, decode_json_response(response))
                        .await
                        .map_err(|_| anyhow::anyhow!("GitHub device authorization expired"))??;
                let Some(expires_at) = complete.expires_at else {
                    bail!("control plane returned an invalid completed device authorization");
                };
                if Instant::now() >= flow_deadline
                    || complete.status != DevicePollStatus::Complete
                    || complete.next_poll_at.is_some()
                    || expires_at == 0
                    || complete.return_path.is_some()
                {
                    bail!("control plane returned an invalid completed device authorization");
                }
                let credential = complete
                    .credential
                    .ok_or_else(|| {
                        anyhow::anyhow!("completed device authorization omitted the session")
                    })
                    .and_then(|credential| {
                        SessionCredential::parse(credential).map_err(|_| {
                            anyhow::anyhow!(
                                "completed device authorization returned an invalid session"
                            )
                        })
                    })?;
                if let Err(error) = store.store(origin.as_str(), &credential).await {
                    return match revoke_remote(client, origin, &credential).await {
                        Ok(()) => Err(error).context("could not store the CLI session securely"),
                        Err(_) => bail!(
                            "secure CLI session custody failed and remote revocation could not be confirmed"
                        ),
                    };
                }
                match activate_remote(client, origin, &credential).await {
                    Ok(RemoteActivation::Active) => {}
                    Ok(RemoteActivation::Rejected) => {
                        store
                            .remove(origin.as_str())
                            .await
                            .context("could not remove the rejected CLI session")?;
                        bail!("control plane rejected CLI session activation");
                    }
                    Err(error) => {
                        return Err(error).context(
                            "CLI session is stored securely but activation is indeterminate; retry auth status or auth logout",
                        );
                    }
                }
                print_login_complete(output, expires_at)?;
                return Ok(());
            }
            StatusCode::ACCEPTED => {
                let pending: DevicePollDocument =
                    timeout_at(flow_deadline, decode_json_response(response))
                        .await
                        .map_err(|_| anyhow::anyhow!("GitHub device authorization expired"))??;
                if !matches!(
                    pending.status,
                    DevicePollStatus::Pending | DevicePollStatus::SlowDown
                ) || pending.credential.is_some()
                    || pending.expires_at.is_some()
                    || pending.return_path.is_some()
                {
                    bail!("control plane returned an invalid pending device authorization");
                }
                if !matches!(pending.next_poll_at, Some(1..)) {
                    bail!("control plane returned an invalid next device poll time");
                }
                next_delay = required_poll_delay(retry_after)?;
            }
            StatusCode::TOO_MANY_REQUESTS => {
                discard_bounded_response(response).await?;
                next_delay = required_poll_delay(retry_after)?;
            }
            StatusCode::FORBIDDEN => {
                discard_bounded_response(response).await?;
                bail!("GitHub device authorization was denied");
            }
            StatusCode::GONE => {
                discard_bounded_response(response).await?;
                bail!("GitHub device authorization expired");
            }
            status => {
                discard_bounded_response(response).await?;
                bail!("device authorization returned HTTP {status}");
            }
        }
    }
}

async fn status(
    client: &Client,
    origin: &CliServerOrigin,
    output: OutputFormat,
    store: &dyn CliCredentialStore,
) -> Result<()> {
    let Some(credential) = store
        .load(origin.as_str())
        .await
        .context("could not load the CLI session securely")?
    else {
        print_signed_out(output);
        return Ok(());
    };
    match activate_remote(client, origin, &credential).await {
        Ok(RemoteActivation::Active) => {}
        Ok(RemoteActivation::Rejected) => {
            store
                .remove(origin.as_str())
                .await
                .context("could not remove the rejected CLI session")?;
            print_signed_out(output);
            return Ok(());
        }
        Err(error) => {
            return Err(error)
                .context("CLI session activation is indeterminate; local custody was retained");
        }
    }
    let response = client
        .get(origin.endpoint(CLI_SESSION_PATH))
        .header(header::AUTHORIZATION, bearer_header(&credential)?)
        .send()
        .await
        .map_err(reqwest::Error::without_url)
        .context("session status request failed")?;
    if response.status() == StatusCode::UNAUTHORIZED {
        drop(response);
        store
            .remove(origin.as_str())
            .await
            .context("could not remove the expired CLI session")?;
        print_signed_out(output);
        return Ok(());
    }
    let document: CliSessionDocument = successful_json(response, StatusCode::OK)
        .await
        .context("control plane returned an invalid session document")?;
    if !valid_session_document(&document) {
        bail!("control plane returned an inconsistent session document");
    }
    print_session(output, &document)
}

async fn logout(
    client: &Client,
    origin: &CliServerOrigin,
    output: OutputFormat,
    store: &dyn CliCredentialStore,
) -> Result<()> {
    let Some(credential) = store
        .load(origin.as_str())
        .await
        .context("could not load the CLI session securely")?
    else {
        print_signed_out(output);
        return Ok(());
    };
    revoke_remote(client, origin, &credential)
        .await
        .context("session logout request failed")?;
    store
        .remove(origin.as_str())
        .await
        .context("could not remove the local CLI session")?;
    print_signed_out(output);
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RemoteActivation {
    Active,
    Rejected,
}

async fn activate_remote(
    client: &Client,
    origin: &CliServerOrigin,
    credential: &SessionCredential,
) -> Result<RemoteActivation> {
    const ATTEMPTS: usize = 3;
    for attempt in 0..ATTEMPTS {
        let response = client
            .post(origin.endpoint(CLI_SESSION_PATH))
            .header(header::AUTHORIZATION, bearer_header(credential)?)
            .body(Bytes::new())
            .send()
            .await;
        let response = match response {
            Ok(response) => response,
            Err(error) if attempt + 1 < ATTEMPTS => {
                drop(error);
                sleep_until(
                    Instant::now()
                        .checked_add(Duration::from_secs(1))
                        .ok_or_else(|| anyhow::anyhow!("activation retry deadline overflowed"))?,
                )
                .await;
                continue;
            }
            Err(error) => {
                return Err(reqwest::Error::without_url(error))
                    .context("CLI session activation request failed");
            }
        };
        let status = response.status();
        match status {
            StatusCode::NO_CONTENT => {
                drop(response);
                return Ok(RemoteActivation::Active);
            }
            StatusCode::UNAUTHORIZED => {
                drop(response);
                return Ok(RemoteActivation::Rejected);
            }
            StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
                if attempt + 1 < ATTEMPTS =>
            {
                let retry = retry_after_seconds(&response);
                discard_bounded_response(response).await?;
                let delay = required_poll_delay(retry)?;
                let wake = Instant::now()
                    .checked_add(Duration::from_secs(delay))
                    .ok_or_else(|| anyhow::anyhow!("activation retry deadline overflowed"))?;
                sleep_until(wake).await;
            }
            _ => {
                discard_bounded_response(response).await?;
                bail!("CLI session activation returned HTTP {status}");
            }
        }
    }
    unreachable!("bounded activation loop returns on every terminal attempt")
}

async fn revoke_remote(
    client: &Client,
    origin: &CliServerOrigin,
    credential: &SessionCredential,
) -> Result<()> {
    const ATTEMPTS: usize = 3;
    for attempt in 0..ATTEMPTS {
        let response = client
            .delete(origin.endpoint(CLI_SESSION_PATH))
            .header(header::AUTHORIZATION, bearer_header(credential)?)
            .send()
            .await;
        let response = match response {
            Ok(response) => response,
            Err(error) if attempt + 1 < ATTEMPTS => {
                drop(error);
                sleep_until(
                    Instant::now()
                        .checked_add(Duration::from_secs(1))
                        .ok_or_else(|| anyhow::anyhow!("revocation retry deadline overflowed"))?,
                )
                .await;
                continue;
            }
            Err(error) => {
                return Err(reqwest::Error::without_url(error))
                    .context("remote session revocation was not confirmed");
            }
        };
        let status = response.status();
        if matches!(status, StatusCode::NO_CONTENT | StatusCode::UNAUTHORIZED) {
            drop(response);
            return Ok(());
        }
        let retry = retry_after_seconds(&response);
        discard_bounded_response(response).await?;
        if attempt + 1 == ATTEMPTS
            || !matches!(
                status,
                StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
            )
        {
            bail!("remote session revocation was not confirmed");
        }
        let delay = required_poll_delay(retry)?;
        sleep_until(Instant::now() + Duration::from_secs(delay)).await;
    }
    unreachable!("bounded revocation loop returns on every terminal attempt")
}

fn print_login_complete(output: OutputFormat, expires_at: u64) -> Result<()> {
    match output {
        OutputFormat::Table => {
            println!("authenticated\ttrue");
            println!("expires_at\t{expires_at}");
        }
        OutputFormat::Json | OutputFormat::JsonLines => println!(
            "{}",
            serde_json::to_string(&LoginCompleteDocument {
                authenticated: true,
                expires_at,
            })?
        ),
    }
    Ok(())
}

fn print_signed_out(output: OutputFormat) {
    match output {
        OutputFormat::Table => println!("authenticated\tfalse"),
        OutputFormat::Json | OutputFormat::JsonLines => {
            println!(r#"{{"authenticated":false}}"#);
        }
    }
}

fn print_session(output: OutputFormat, document: &CliSessionDocument) -> Result<()> {
    match output {
        OutputFormat::Table => {
            println!("authenticated\ttrue");
            println!("tenant\t{}", escaped_table_value(&document.tenant_id));
            println!("user\t{}", escaped_table_value(&document.provider_login));
            println!("provider\t{}", escaped_table_value(&document.provider_id));
            println!("expires_at\t{}", document.expires_at);
        }
        OutputFormat::Json | OutputFormat::JsonLines => {
            println!("{}", serde_json::to_string(document)?);
        }
    }
    Ok(())
}

pub(super) fn auth_client() -> Result<Client, reqwest::Error> {
    let builder = Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .no_proxy();
    builder.build().map_err(reqwest::Error::without_url)
}

async fn successful_json<T: for<'de> Deserialize<'de>>(
    response: Response,
    expected: StatusCode,
) -> Result<T> {
    let status = response.status();
    if status != expected {
        discard_bounded_response(response).await?;
        bail!("control plane returned HTTP {status}");
    }
    decode_json_response(response).await
}

pub(super) async fn decode_json_response<T: for<'de> Deserialize<'de>>(
    response: Response,
) -> Result<T> {
    if !is_json_response(&response) {
        discard_bounded_response(response).await?;
        bail!("control plane returned an unsupported response type");
    }
    let body = read_bounded_auth_body(response).await?;
    decode_json_document(&body)
}

fn decode_json_document<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body).map_err(|_| anyhow::anyhow!("control plane returned invalid JSON"))
}

pub(super) async fn discard_bounded_response(response: Response) -> Result<()> {
    let _ = read_bounded_auth_body(response).await?;
    Ok(())
}

async fn read_bounded_auth_body(mut response: Response) -> Result<Zeroizing<Vec<u8>>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_AUTH_RESPONSE_BYTES as u64)
    {
        bail!("authentication response exceeded its byte limit");
    }
    let mut body = Zeroizing::new(Vec::with_capacity(MAX_AUTH_RESPONSE_BYTES));
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(reqwest::Error::without_url)
        .context("could not read authentication response")?
    {
        let within_limit = body
            .len()
            .checked_add(chunk.len())
            .is_some_and(|length| length <= MAX_AUTH_RESPONSE_BYTES);
        if within_limit {
            body.extend_from_slice(&chunk);
        }
        wipe_response_chunk(chunk);
        if !within_limit {
            bail!("authentication response exceeded its byte limit");
        }
    }
    Ok(body)
}

fn is_json_response(response: &Response) -> bool {
    let mut values = response.headers().get_all(header::CONTENT_TYPE).iter();
    let Some(value) = values.next().and_then(|value| value.to_str().ok()) else {
        return false;
    };
    values.next().is_none()
        && value
            .split(';')
            .next()
            .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
}

pub(super) fn retry_after_seconds(response: &Response) -> Option<u64> {
    let mut values = response.headers().get_all(header::RETRY_AFTER).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some()
        || value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    value.parse().ok()
}

fn poll_request_body(credential: &GithubDevicePollCredential) -> Bytes {
    const PREFIX: &[u8] = b"{\"poll_credential\":\"";
    const SUFFIX: &[u8] = b"\"}";
    // The typed proof parser admits only the JSON-safe ASCII alphabet used by
    // canonical device proofs, so this bounded construction needs no escaping
    // serializer or reallocating intermediate plaintext buffer.
    let value = credential.expose_secret().as_bytes();
    let mut body = Zeroizing::new(Vec::with_capacity(
        PREFIX.len() + value.len() + SUFFIX.len(),
    ));
    body.extend_from_slice(PREFIX);
    body.extend_from_slice(value);
    body.extend_from_slice(SUFFIX);
    Bytes::from_owner(body)
}

pub(super) fn bearer_header(credential: &SessionCredential) -> Result<header::HeaderValue> {
    const PREFIX: &[u8] = b"Bearer ";
    let value = credential.expose_secret().as_bytes();
    let mut encoded = Zeroizing::new(Vec::with_capacity(PREFIX.len() + value.len()));
    encoded.extend_from_slice(PREFIX);
    encoded.extend_from_slice(value);
    let mut header = header::HeaderValue::from_maybe_shared(Bytes::from_owner(encoded))
        .map_err(|_| anyhow::anyhow!("CLI session could not be encoded as an HTTP credential"))?;
    header.set_sensitive(true);
    Ok(header)
}

fn wipe_response_chunk(chunk: Bytes) {
    if let Ok(mut chunk) = chunk.try_into_mut() {
        chunk.as_mut().fill(0);
    }
}

fn required_poll_delay(delay: Option<u64>) -> Result<u64> {
    delay
        .filter(|delay| *delay > 0 && *delay <= MAX_POLL_DELAY_SECONDS)
        .ok_or_else(|| anyhow::anyhow!("control plane returned an invalid retry delay"))
}

fn checked_poll_instant(delay: u64, deadline: Instant) -> Result<Instant> {
    let delay = required_poll_delay(Some(delay))?;
    let poll_at = Instant::now()
        .checked_add(Duration::from_secs(delay))
        .ok_or_else(|| anyhow::anyhow!("device poll deadline overflowed"))?;
    if poll_at >= deadline {
        bail!("GitHub device authorization expired");
    }
    Ok(poll_at)
}

fn validate_verification_uri(value: &str) -> Result<Url, InvalidVerificationUri> {
    let parsed = Url::parse(value).map_err(|_| InvalidVerificationUri)?;
    if parsed.scheme() != "https"
        || parsed.host_str() != Some("github.com")
        || parsed.port().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/login/device"
    {
        return Err(InvalidVerificationUri);
    }
    Ok(parsed)
}

fn valid_device_user_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn valid_session_document(document: &CliSessionDocument) -> bool {
    document.authenticated
        && document.kind == "cli"
        && document.authorization_revision > 0
        && TenantId::new(&document.tenant_id).is_ok()
        && PrincipalId::new(&document.principal_id).is_ok()
        && ProviderId::new(&document.provider_id).is_ok()
        && ProviderSubject::new(&document.provider_subject).is_ok()
        && SessionId::new(&document.session_id).is_ok()
        && valid_display_text(&document.provider_login, false)
        && valid_display_text(&document.display_name, true)
        && document.issued_at < document.expires_at
}

fn valid_display_text(value: &str, allow_empty: bool) -> bool {
    (allow_empty || !value.is_empty())
        && value.len() <= MAX_DISPLAY_TEXT_BYTES
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
fn unix_now() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .context("system clock precedes the Unix epoch")
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CliServerOrigin {
    url: Url,
    attribute: String,
}

impl CliServerOrigin {
    pub(super) fn new(value: &str) -> Result<Self, InvalidCliServerOrigin> {
        let mut url = Url::parse(value).map_err(|_| InvalidCliServerOrigin)?;
        if url.host().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err(InvalidCliServerOrigin);
        }
        let allowed = match url.scheme() {
            "https" => true,
            "http" => match url.host() {
                Some(Host::Ipv4(address)) => address.is_loopback(),
                Some(Host::Ipv6(address)) => address.is_loopback(),
                Some(Host::Domain(_)) | None => false,
            },
            _ => false,
        };
        if !allowed {
            return Err(InvalidCliServerOrigin);
        }
        url.set_path("/");
        let attribute = url.origin().ascii_serialization();
        Ok(Self { url, attribute })
    }

    pub(super) fn endpoint(&self, path: &str) -> Url {
        let mut endpoint = self.url.clone();
        endpoint.set_path(path);
        endpoint
    }

    pub(super) fn as_str(&self) -> &str {
        &self.attribute
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct InvalidCliServerOrigin;

impl fmt::Display for InvalidCliServerOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "CLI authentication requires an HTTPS origin or literal-IP loopback HTTP origin",
        )
    }
}

impl Error for InvalidCliServerOrigin {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InvalidVerificationUri;

impl fmt::Display for InvalidVerificationUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GitHub verification URL is invalid")
    }
}

impl Error for InvalidVerificationUri {}

trait DeviceAuthorizationPrompt: fmt::Debug + Send + Sync {
    fn show(&self, verification_uri: &Url, user_code: &SecretString) -> Result<()>;
}

struct ControllingTerminalPrompt {
    terminal: Mutex<File>,
}

impl ControllingTerminalPrompt {
    fn open() -> Result<Self> {
        let descriptor = open(
            "/dev/tty",
            OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| anyhow::anyhow!("controlling terminal is unavailable"))?;
        let metadata = fstat(&descriptor)
            .map_err(|_| anyhow::anyhow!("controlling terminal could not be verified"))?;
        if !FileType::from_raw_mode(metadata.st_mode).is_char_device() {
            bail!("controlling terminal is not a character device");
        }
        let terminal = File::from(descriptor);
        if !terminal.is_terminal() {
            bail!("controlling terminal is not a TTY");
        }
        Ok(Self {
            terminal: Mutex::new(terminal),
        })
    }
}

impl fmt::Debug for ControllingTerminalPrompt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ControllingTerminalPrompt([REDACTED])")
    }
}

impl DeviceAuthorizationPrompt for ControllingTerminalPrompt {
    fn show(&self, verification_uri: &Url, user_code: &SecretString) -> Result<()> {
        let mut terminal = self
            .terminal
            .lock()
            .map_err(|_| anyhow::anyhow!("controlling terminal lock is unavailable"))?;
        writeln!(terminal, "Open {verification_uri}")?;
        writeln!(terminal, "Enter code {}", user_code.expose_secret())?;
        writeln!(terminal, "Waiting for GitHub authorization…")?;
        terminal.flush()?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct UnavailableDevicePrompt;

impl DeviceAuthorizationPrompt for UnavailableDevicePrompt {
    fn show(&self, _verification_uri: &Url, _user_code: &SecretString) -> Result<()> {
        bail!("device authorization prompt is unavailable")
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceStartDocument {
    poll_credential: SecretString,
    user_code: SecretString,
    verification_uri: String,
    expires_at: u64,
    expires_in_seconds: u64,
    poll_interval_seconds: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum DevicePollStatus {
    Pending,
    SlowDown,
    Complete,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DevicePollDocument {
    status: DevicePollStatus,
    next_poll_at: Option<u64>,
    credential: Option<SecretString>,
    expires_at: Option<u64>,
    return_path: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CliSessionDocument {
    authenticated: bool,
    tenant_id: String,
    principal_id: String,
    provider_id: String,
    provider_subject: String,
    provider_login: String,
    display_name: String,
    session_id: String,
    kind: String,
    authorization_revision: u64,
    issued_at: u64,
    expires_at: u64,
}

#[derive(Debug, Serialize)]
struct LoginCompleteDocument {
    authenticated: bool,
    expires_at: u64,
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    };

    use axum::{
        Router,
        http::StatusCode,
        routing::{get, post},
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    const SESSION: &str = "v1~key-1~AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const POLL: &str = "dp1~key-1~22222222-2222-4222-8222-222222222222~AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI";

    #[derive(Default)]
    struct FakeCredentialStore {
        credential: Mutex<Option<String>>,
    }

    impl fmt::Debug for FakeCredentialStore {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("FakeCredentialStore([REDACTED])")
        }
    }

    #[async_trait::async_trait]
    impl CliCredentialStore for FakeCredentialStore {
        async fn load(
            &self,
            _server_origin: &str,
        ) -> std::result::Result<
            Option<SessionCredential>,
            super::super::credential_store::CredentialStoreError,
        > {
            self.credential
                .lock()
                .unwrap()
                .as_deref()
                .map(SessionCredential::from_raw)
                .transpose()
                .map_err(|_| {
                    super::super::credential_store::CredentialStoreError::InvalidCredential
                })
        }

        async fn store(
            &self,
            _server_origin: &str,
            credential: &SessionCredential,
        ) -> std::result::Result<(), super::super::credential_store::CredentialStoreError> {
            *self.credential.lock().unwrap() = Some(credential.expose_secret().to_owned());
            Ok(())
        }

        async fn remove(
            &self,
            _server_origin: &str,
        ) -> std::result::Result<(), super::super::credential_store::CredentialStoreError> {
            *self.credential.lock().unwrap() = None;
            Ok(())
        }
    }

    #[derive(Debug)]
    struct FakeDevicePrompt;

    impl DeviceAuthorizationPrompt for FakeDevicePrompt {
        fn show(&self, verification_uri: &Url, user_code: &SecretString) -> Result<()> {
            assert_eq!(verification_uri.as_str(), "https://github.com/login/device");
            assert_eq!(user_code.expose_secret(), "ABCD-EFGH");
            Ok(())
        }
    }

    async fn test_server(app: Router) -> (CliServerOrigin, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (
            CliServerOrigin::new(&format!("http://{address}/")).unwrap(),
            task,
        )
    }

    #[test]
    fn credentialed_auth_origins_are_canonical_and_fail_closed() {
        for (input, expected) in [
            ("https://ci.example/", "https://ci.example"),
            ("http://127.0.0.1:8080/", "http://127.0.0.1:8080"),
            ("http://[::1]:8080/", "http://[::1]:8080"),
        ] {
            assert_eq!(CliServerOrigin::new(input).unwrap().as_str(), expected);
        }
        for invalid in [
            "http://ci.example/",
            "http://localhost:8080/",
            "https://user:secret@ci.example/",
            "https://ci.example/base/",
            "https://ci.example/?x=secret",
            "ftp://ci.example/",
        ] {
            let error = CliServerOrigin::new(invalid).unwrap_err().to_string();
            assert!(!error.contains("secret"));
        }
    }

    #[test]
    fn github_verification_uri_is_exact() {
        assert!(validate_verification_uri("https://github.com/login/device").is_ok());
        for invalid in [
            "http://github.com/login/device",
            "https://github.example/login/device",
            "https://github.com/login/device?code=secret",
            "https://user@github.com/login/device",
            "https://github.com/other",
        ] {
            assert!(validate_verification_uri(invalid).is_err());
        }
    }

    #[test]
    fn poll_request_is_bounded_json_without_debug_exposure() {
        let credential = GithubDevicePollCredential::from_raw(POLL).unwrap();
        let body = poll_request_body(&credential);
        assert_eq!(
            body.as_ref(),
            format!(r#"{{"poll_credential":"{POLL}"}}"#).as_bytes()
        );
        assert!(!format!("{credential:?}").contains(POLL));
    }

    #[test]
    fn hostile_json_values_are_not_retained_in_diagnostics() {
        const SENTINEL: &str = "managed-response-secret-sentinel";
        let body = format!(r#"{{"status":"{SENTINEL}"}}"#);
        let error = decode_json_document::<DevicePollDocument>(body.as_bytes()).unwrap_err();
        let display = format!("{error:#}");
        let debug = format!("{error:?}");
        assert_eq!(display, "control plane returned invalid JSON");
        assert!(!display.contains(SENTINEL));
        assert!(!debug.contains(SENTINEL));
    }

    #[tokio::test]
    async fn device_login_stores_only_the_automata_session() {
        let expires_at = unix_now().unwrap() + 60;
        let app = Router::new()
            .route(
                GITHUB_DEVICE_BEGIN_PATH,
                post(move || async move {
                    axum::Json(serde_json::json!({
                        "poll_credential": POLL,
                        "user_code": "ABCD-EFGH",
                        "verification_uri": "https://github.com/login/device",
                        "expires_at": expires_at,
                        "expires_in_seconds": 60,
                        "poll_interval_seconds": 1
                    }))
                }),
            )
            .route(
                GITHUB_DEVICE_POLL_PATH,
                post(move || async move {
                    axum::Json(serde_json::json!({
                        "status": "complete",
                        "next_poll_at": null,
                        "credential": SESSION,
                        "expires_at": expires_at,
                        "return_path": null
                    }))
                }),
            )
            .route(CLI_SESSION_PATH, post(|| async { StatusCode::NO_CONTENT }));
        let (origin, server) = test_server(app).await;
        let store = Arc::new(FakeCredentialStore::default());
        execute_auth_command_with(
            origin,
            OutputFormat::Json,
            &AuthCommand::Login,
            store.clone(),
            &FakeDevicePrompt,
        )
        .await
        .unwrap();
        assert_eq!(store.credential.lock().unwrap().as_deref(), Some(SESSION));
        server.abort();
    }

    #[tokio::test]
    async fn status_and_logout_use_and_then_remove_the_server_scoped_session() {
        let expires_at = unix_now().unwrap() + 60;
        let activations = Arc::new(AtomicU64::new(0));
        let observed_activations = Arc::clone(&activations);
        let app = Router::new().route(
            CLI_SESSION_PATH,
            get(move || async move {
                axum::Json(serde_json::json!({
                    "authenticated": true,
                    "tenant_id": "tenant-a",
                    "principal_id": "33333333-3333-4333-8333-333333333333",
                    "provider_id": "github",
                    "provider_subject": "1234567",
                    "provider_login": "octocat",
                    "display_name": "The Octocat",
                    "session_id": "44444444-4444-4444-8444-444444444444",
                    "kind": "cli",
                    "authorization_revision": 7,
                    "issued_at": expires_at - 60,
                    "expires_at": expires_at
                }))
            })
            .post(move || {
                let activations = Arc::clone(&observed_activations);
                async move {
                    activations.fetch_add(1, Ordering::SeqCst);
                    StatusCode::NO_CONTENT
                }
            })
            .delete(|| async { StatusCode::NO_CONTENT }),
        );
        let (origin, server) = test_server(app).await;
        let store = Arc::new(FakeCredentialStore::default());
        *store.credential.lock().unwrap() = Some(SESSION.to_owned());
        execute_auth_command_with(
            origin.clone(),
            OutputFormat::Json,
            &AuthCommand::Status,
            store.clone(),
            &FakeDevicePrompt,
        )
        .await
        .unwrap();
        assert!(store.credential.lock().unwrap().is_some());
        assert_eq!(activations.load(Ordering::SeqCst), 1);
        execute_auth_command_with(
            origin,
            OutputFormat::Json,
            &AuthCommand::Logout,
            store.clone(),
            &FakeDevicePrompt,
        )
        .await
        .unwrap();
        assert!(store.credential.lock().unwrap().is_none());
        server.abort();
    }

    #[tokio::test]
    async fn rejected_pending_activation_removes_local_custody_without_authenticating() {
        let app = Router::new().route(
            CLI_SESSION_PATH,
            post(|| async { StatusCode::UNAUTHORIZED }),
        );
        let (origin, server) = test_server(app).await;
        let store = Arc::new(FakeCredentialStore::default());
        *store.credential.lock().unwrap() = Some(SESSION.to_owned());
        execute_auth_command_with(
            origin,
            OutputFormat::Json,
            &AuthCommand::Status,
            store.clone(),
            &FakeDevicePrompt,
        )
        .await
        .unwrap();
        assert!(store.credential.lock().unwrap().is_none());
        server.abort();
    }

    #[tokio::test]
    async fn logout_retries_one_transport_failure_before_removing_local_custody() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            for attempt in 0..2 {
                let (mut socket, _) = listener.accept().await.expect("connection");
                let mut request = [0_u8; 4_096];
                let mut received = 0;
                while !request[..received]
                    .windows(4)
                    .any(|window| window == b"\r\n\r\n")
                {
                    let read = socket
                        .read(&mut request[received..])
                        .await
                        .expect("request read");
                    assert_ne!(read, 0, "request ended before its headers");
                    received += read;
                    assert!(received < request.len(), "request headers are bounded");
                }
                let expected_request_line = format!("DELETE {CLI_SESSION_PATH} ");
                assert!(request[..received].starts_with(expected_request_line.as_bytes()));
                if attempt == 1 {
                    socket
                        .write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await
                        .expect("response write");
                }
            }
        });
        let origin = CliServerOrigin::new(&format!("http://{address}/")).expect("origin");
        let store = FakeCredentialStore::default();
        *store.credential.lock().expect("credential lock") = Some(SESSION.to_owned());
        logout(
            &auth_client().expect("client"),
            &origin,
            OutputFormat::Json,
            &store,
        )
        .await
        .expect("logout retry");
        server.await.expect("server");
        assert!(store.credential.lock().expect("credential lock").is_none());
    }

    #[test]
    fn status_documents_reject_terminal_controls_and_invalid_lifetimes() {
        let mut document = CliSessionDocument {
            authenticated: true,
            tenant_id: "tenant-a".to_owned(),
            principal_id: "33333333-3333-4333-8333-333333333333".to_owned(),
            provider_id: "github".to_owned(),
            provider_subject: "1234567".to_owned(),
            provider_login: "octocat".to_owned(),
            display_name: "The Octocat".to_owned(),
            session_id: "44444444-4444-4444-8444-444444444444".to_owned(),
            kind: "cli".to_owned(),
            authorization_revision: 7,
            issued_at: 10,
            expires_at: 40,
        };
        assert!(valid_session_document(&document));
        document.provider_login = "octocat\u{1b}[31m".to_owned();
        assert!(!valid_session_document(&document));
        document.provider_login = "octocat".to_owned();
        document.expires_at = document.issued_at;
        assert!(!valid_session_document(&document));
    }
}
