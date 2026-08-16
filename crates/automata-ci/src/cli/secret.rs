//! Operational repository-secret CLI over authenticated, value-free management reads.

use std::{
    collections::BTreeSet,
    ffi::OsString,
    fmt,
    fs::File,
    io::{IsTerminal as _, Read, Write as _},
    os::fd::OwnedFd,
    path::{Component, Path},
    time::Duration,
};

use anyhow::{Context as _, Result, bail};
use automata_ci_auth::session_credential::SessionCredential;
use automata_ci_core::RunId;
use automata_ci_store::{
    BUILTIN_SECRET_PROVIDER_ID, GithubRepositoryName, ManagedSecretProviderId, RepositorySecretName,
};
use bytes::Bytes;
use reqwest::{Client, Method, Request, Response, StatusCode, header};
use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use url::Url;
use zeroize::{Zeroize as _, Zeroizing};

use super::{
    OutputFormat, RepositoryRef, SecretCommand, SecretCreateArgs, SecretDeleteArgs, SecretListArgs,
    SecretProviderCommand, SecretScope,
    auth::{
        CliServerOrigin, auth_client, bearer_header, decode_json_response,
        discard_bounded_response, retry_after_seconds,
    },
    credential_store::{CliAuthProcessLock, CliCredentialStore, SecretServiceCredentialStore},
    output::escaped_table_value,
};
use crate::app::secret_api::{
    BUILTIN_SECRET_PROVIDER_ACTIVATION_PATH, BUILTIN_SECRET_PROVIDER_PATH, MAX_SECRET_INGRESS_BYTES,
};

const REPOSITORY_RESOLUTION_BASE: &str = "/api/v1/repository-targets/github";
const REPOSITORY_SECRETS_BASE: &str = "/api/v1/repositories";
const LIST_PAGE_SIZE: usize = 20;
const MAX_LIST_PAGES: usize = 500;
const MAX_REQUEST_ATTEMPTS: usize = 3;
const MAX_RETRY_DELAY_SECONDS: u64 = 5;
const TRANSPORT_RETRY_DELAY: Duration = Duration::from_millis(100);
const MAX_CONFIRMATION_BYTES: usize = 32;
const SECRET_CREATE_AUTHORITY: &str =
    "secret create requires secrets:metadata:read and secrets:create authority";
const SECRET_DELETE_AUTHORITY: &str =
    "secret delete requires secrets:metadata:read and secrets:delete authority";
const PROVIDER_ACTIVATE_AUTHORITY: &str =
    "provider activation requires secret-providers:read and secret-providers:manage authority";

pub(crate) async fn execute_secret_command(
    server_url: &str,
    output: OutputFormat,
    command: &SecretCommand,
) -> Result<()> {
    let origin = CliServerOrigin::new(server_url)
        .context("secret endpoint policy rejected the server URL")?;
    let _process_lock = CliAuthProcessLock::acquire(origin.as_str())
        .context("CLI secret operation could not be serialized")?;
    let store =
        SecretServiceCredentialStore::discover().context("CLI session custody is unavailable")?;
    execute_secret_command_with(origin, output, command, &store).await
}

async fn execute_secret_command_with(
    origin: CliServerOrigin,
    output: OutputFormat,
    command: &SecretCommand,
    store: &dyn CliCredentialStore,
) -> Result<()> {
    let client = auth_client().context("failed to configure the secret management client")?;
    let credential = store
        .load(origin.as_str())
        .await
        .context("could not load the CLI session securely")?
        .ok_or_else(|| anyhow::anyhow!("no CLI session exists; run `automata auth login`"))?;
    match command {
        SecretCommand::List(args) => list(&client, &origin, &credential, output, args).await,
        SecretCommand::Create(args) => {
            create_secret_command(&client, &origin, &credential, output, args).await
        }
        SecretCommand::Delete(args) => delete(&client, &origin, &credential, output, args).await,
        SecretCommand::Provider(args) => match &args.command {
            SecretProviderCommand::Status => {
                let provider = inspect_provider(&client, &origin, &credential).await?;
                print_provider(output, &provider)
            }
            SecretProviderCommand::Activate => {
                activate_provider(&client, &origin, &credential, output).await
            }
        },
    }
}

async fn list(
    client: &Client,
    origin: &CliServerOrigin,
    credential: &SessionCredential,
    output: OutputFormat,
    args: &SecretListArgs,
) -> Result<()> {
    let repository = repository_scope(&args.scope)?;
    let repository_id = resolve_repository(client, origin, credential, repository).await?;
    let mut after = None;
    let mut records = Vec::new();
    let mut seen_ids = BTreeSet::new();
    let mut seen_names = BTreeSet::new();
    for _ in 0..MAX_LIST_PAGES {
        let endpoint = list_endpoint(origin, &repository_id, after.as_deref())?;
        let request = authenticated_request(client, Method::GET, endpoint, credential)?.build()?;
        let response = send_with_retries(client, &request)
            .await
            .map_err(anyhow::Error::new)
            .context("secret metadata request outcome is indeterminate")?;
        match response.status() {
            StatusCode::OK => {
                let page: SecretPageDocument = decode_json_response(response).await?;
                validate_page(&page, &repository_id, after.as_deref())?;
                for record in &page.items {
                    if !seen_ids.insert(record.id.clone())
                        || !seen_names.insert(record.name.clone())
                    {
                        bail!("control plane returned duplicate secret metadata");
                    }
                }
                let next = page.next_after.clone().into_option();
                records.extend(page.items);
                if let Some(cursor) = next {
                    after = Some(cursor);
                } else {
                    print_secret_list(output, repository, &records)?;
                    return Ok(());
                }
            }
            status => return response_error(response, status, "secret metadata").await,
        }
    }
    bail!("secret metadata exceeded the bounded page limit")
}

async fn create_secret_command(
    client: &Client,
    origin: &CliServerOrigin,
    credential: &SessionCredential,
    output: OutputFormat,
    args: &SecretCreateArgs,
) -> Result<()> {
    create_with_combined_authority(client, origin, credential, output, args)
        .await
        .context(SECRET_CREATE_AUTHORITY)
}

async fn create_with_combined_authority(
    client: &Client,
    origin: &CliServerOrigin,
    credential: &SessionCredential,
    output: OutputFormat,
    args: &SecretCreateArgs,
) -> Result<()> {
    let repository = repository_scope(&args.scope)?;
    let name = RepositorySecretName::new(&args.name)
        .map_err(|_| anyhow::anyhow!("secret name is invalid or reserved"))?;
    let repository_id = resolve_repository(client, origin, credential, repository).await?;
    if get_by_name(client, origin, credential, &repository_id, name.as_str())
        .await?
        .is_some()
    {
        bail!("secret already exists; repository-secret replacement is not operational");
    }
    let value = read_secret_value(args.from_file.as_deref())?;
    let secret_id = create_repository_secret(
        client,
        origin,
        credential,
        &repository_id,
        name.as_str(),
        value,
    )
    .await?;
    let created = get_by_name(client, origin, credential, &repository_id, name.as_str())
        .await?
        .ok_or_else(|| anyhow::anyhow!("created secret metadata is unavailable"))?;
    validate_created_secret(&created, &secret_id)?;
    print_mutation(output, "created", repository, name.as_str())
}

async fn delete(
    client: &Client,
    origin: &CliServerOrigin,
    credential: &SessionCredential,
    output: OutputFormat,
    args: &SecretDeleteArgs,
) -> Result<()> {
    delete_with_combined_authority(client, origin, credential, output, args)
        .await
        .context(SECRET_DELETE_AUTHORITY)
}

async fn delete_with_combined_authority(
    client: &Client,
    origin: &CliServerOrigin,
    credential: &SessionCredential,
    output: OutputFormat,
    args: &SecretDeleteArgs,
) -> Result<()> {
    let repository = repository_scope(&args.scope)?;
    let name = RepositorySecretName::new(&args.name)
        .map_err(|_| anyhow::anyhow!("secret name is invalid or reserved"))?;
    let repository_id = resolve_repository(client, origin, credential, repository).await?;
    let metadata = get_by_name(client, origin, credential, &repository_id, name.as_str())
        .await?
        .ok_or_else(|| anyhow::anyhow!("secret is unavailable"))?;
    if !args.yes && !confirm_delete(repository, name.as_str())? {
        bail!("secret deletion was not confirmed")
    }
    let endpoint = secret_id_endpoint(origin, &repository_id, &metadata.id)?;
    let request = authenticated_request(client, Method::DELETE, endpoint, credential)?
        .header(header::IF_MATCH, quoted_revision(metadata.revision)?)
        .build()?;
    let send_result = send_with_retries(client, &request).await;
    drop(request);
    let response = match send_result {
        Ok(response) => response,
        Err(error) => {
            if deleted_name_is_absent(client, origin, credential, &repository_id, name.as_str())
                .await
            {
                return print_mutation(output, "deleted", repository, name.as_str());
            }
            return Err(anyhow::Error::new(error))
                .context("secret deletion outcome is indeterminate");
        }
    };
    let status = response.status();
    match status {
        StatusCode::NO_CONTENT => {
            discard_bounded_response(response).await?;
            if get_by_name(client, origin, credential, &repository_id, name.as_str())
                .await?
                .is_some()
            {
                bail!("control plane returned inconsistent secret deletion state")
            }
            print_mutation(output, "deleted", repository, name.as_str())
        }
        StatusCode::CONFLICT => {
            discard_bounded_response(response).await?;
            if deleted_name_is_absent(client, origin, credential, &repository_id, name.as_str())
                .await
            {
                return print_mutation(output, "deleted", repository, name.as_str());
            }
            bail!("secret metadata changed; inspect it and retry deletion")
        }
        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE => {
            discard_bounded_response(response).await?;
            if deleted_name_is_absent(client, origin, credential, &repository_id, name.as_str())
                .await
            {
                return print_mutation(output, "deleted", repository, name.as_str());
            }
            bail!("secret deletion outcome is indeterminate")
        }
        _ => response_error(response, status, "secret deletion").await,
    }
}

async fn deleted_name_is_absent(
    client: &Client,
    origin: &CliServerOrigin,
    credential: &SessionCredential,
    repository_id: &str,
    name: &str,
) -> bool {
    matches!(
        get_by_name(client, origin, credential, repository_id, name).await,
        Ok(None)
    )
}

async fn activate_provider(
    client: &Client,
    origin: &CliServerOrigin,
    credential: &SessionCredential,
    output: OutputFormat,
) -> Result<()> {
    activate_provider_with_combined_authority(client, origin, credential, output)
        .await
        .context(PROVIDER_ACTIVATE_AUTHORITY)
}

async fn activate_provider_with_combined_authority(
    client: &Client,
    origin: &CliServerOrigin,
    credential: &SessionCredential,
    output: OutputFormat,
) -> Result<()> {
    let inspected = inspect_provider(client, origin, credential).await?;
    let prior_state = inspected.state;
    let expected_revision = inspected.revision;
    if prior_state != ProviderState::Active {
        inspected
            .activation
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("built-in provider activation is unavailable"))?;
    }
    let endpoint = origin.endpoint(BUILTIN_SECRET_PROVIDER_ACTIVATION_PATH);
    let request = authenticated_request(client, Method::POST, endpoint, credential)?
        .header(header::IF_MATCH, quoted_revision(expected_revision)?)
        .build()?;
    let response = match send_with_retries(client, &request).await {
        Ok(response) => response,
        Err(error) => match inspect_provider(client, origin, credential).await {
            Ok(provider)
                if provider_activation_matches(&provider, expected_revision, prior_state) =>
            {
                return print_provider(output, &provider);
            }
            Ok(_) | Err(_) => {
                return Err(anyhow::Error::new(error))
                    .context("built-in provider activation outcome is indeterminate");
            }
        },
    };
    let status = response.status();
    let activated_revision = match status {
        StatusCode::OK => {
            let activated: ProviderMutationDocument = decode_json_response(response).await?;
            validate_provider_mutation(&activated, expected_revision, prior_state)?;
            activated.revision
        }
        StatusCode::CONFLICT => {
            discard_bounded_response(response).await?;
            let provider = inspect_provider(client, origin, credential).await?;
            if !provider_activation_matches(&provider, expected_revision, prior_state) {
                bail!("built-in provider state changed; inspect it and retry activation")
            }
            return print_provider(output, &provider);
        }
        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE => {
            discard_bounded_response(response).await?;
            let provider = inspect_provider(client, origin, credential).await?;
            if !provider_activation_matches(&provider, expected_revision, prior_state) {
                bail!("built-in provider activation outcome is indeterminate")
            }
            return print_provider(output, &provider);
        }
        _ => return response_error(response, status, "built-in provider activation").await,
    };
    let provider = inspect_provider(client, origin, credential).await?;
    if provider.state != ProviderState::Active || provider.revision != activated_revision {
        bail!("control plane returned inconsistent provider activation state")
    }
    print_provider(output, &provider)
}

async fn resolve_repository(
    client: &Client,
    origin: &CliServerOrigin,
    credential: &SessionCredential,
    repository: &RepositoryRef,
) -> Result<String> {
    let endpoint = repository_resolution_endpoint(origin, repository)?;
    let request = authenticated_request(client, Method::GET, endpoint, credential)?.build()?;
    let response = send_with_retries(client, &request)
        .await
        .map_err(anyhow::Error::new)
        .context("repository resolution outcome is indeterminate")?;
    let status = response.status();
    match status {
        StatusCode::OK => {
            let document: RepositoryResolutionDocument = decode_json_response(response).await?;
            canonical_uuid(&document.repository_id)
                .context("control plane returned invalid repository metadata")
        }
        _ => response_error(response, status, "repository").await,
    }
}

async fn get_by_name(
    client: &Client,
    origin: &CliServerOrigin,
    credential: &SessionCredential,
    repository_id: &str,
    name: &str,
) -> Result<Option<SecretMetadataDocument>> {
    let endpoint = secret_name_endpoint(origin, repository_id)?;
    let request = authenticated_request(client, Method::GET, endpoint, credential)?
        .header("x-automata-secret-name", secret_name_header(name)?)
        .build()?;
    let response = send_with_retries(client, &request)
        .await
        .map_err(anyhow::Error::new)
        .context("secret lookup outcome is indeterminate")?;
    let status = response.status();
    match status {
        StatusCode::OK => {
            let document: SecretMetadataDocument = decode_json_response(response).await?;
            validate_secret_metadata(&document, repository_id, Some(name))?;
            Ok(Some(document))
        }
        StatusCode::NOT_FOUND => {
            discard_bounded_response(response).await?;
            Ok(None)
        }
        _ => response_error(response, status, "secret lookup").await,
    }
}

async fn inspect_provider(
    client: &Client,
    origin: &CliServerOrigin,
    credential: &SessionCredential,
) -> Result<ProviderInspectionDocument> {
    let request = authenticated_request(
        client,
        Method::GET,
        origin.endpoint(BUILTIN_SECRET_PROVIDER_PATH),
        credential,
    )?
    .build()?;
    let response = send_with_retries(client, &request)
        .await
        .map_err(anyhow::Error::new)
        .context("built-in provider inspection outcome is indeterminate")?;
    let status = response.status();
    match status {
        StatusCode::OK => {
            let document: ProviderInspectionDocument = decode_json_response(response).await?;
            validate_provider_inspection(&document)?;
            Ok(document)
        }
        _ => response_error(response, status, "built-in provider").await,
    }
}

async fn create_repository_secret(
    client: &Client,
    origin: &CliServerOrigin,
    credential: &SessionCredential,
    repository_id: &str,
    name: &str,
    value: Zeroizing<Vec<u8>>,
) -> Result<String> {
    if value.is_empty() || value.len() > MAX_SECRET_INGRESS_BYTES {
        bail!("secret value must be non-empty and within its byte limit")
    }
    let secret_id = RunId::new().to_string();
    let mutation_id = loop {
        let candidate = RunId::new().to_string();
        if candidate != secret_id {
            break candidate;
        }
    };
    let endpoint = secret_id_endpoint(origin, repository_id, &secret_id)?;
    let body = Bytes::from_owner(value);
    let request = authenticated_request(client, Method::PUT, endpoint, credential)?
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header("x-automata-secret-mutation-id", mutation_id)
        .header("x-automata-secret-name", secret_name_header(name)?)
        .header("x-automata-secret-provider", BUILTIN_SECRET_PROVIDER_ID)
        .body(body)
        .build()?;
    let send_result = send_with_retries(client, &request).await;
    drop(request);
    let response = match send_result {
        Ok(response) => response,
        Err(error) => {
            if created_secret_matches(client, origin, credential, repository_id, name, &secret_id)
                .await
            {
                return Ok(secret_id);
            }
            return Err(anyhow::Error::new(error))
                .context("secret creation outcome is indeterminate");
        }
    };
    let status = response.status();
    match status {
        StatusCode::NO_CONTENT => {
            discard_bounded_response(response).await?;
            Ok(secret_id)
        }
        StatusCode::CONFLICT => {
            discard_bounded_response(response).await?;
            if created_secret_matches(client, origin, credential, repository_id, name, &secret_id)
                .await
            {
                return Ok(secret_id);
            }
            bail!("secret creation conflicted with current metadata")
        }
        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE => {
            discard_bounded_response(response).await?;
            if created_secret_matches(client, origin, credential, repository_id, name, &secret_id)
                .await
            {
                return Ok(secret_id);
            }
            bail!("secret creation outcome is indeterminate")
        }
        _ => response_error(response, status, "secret creation").await,
    }
}

async fn created_secret_matches(
    client: &Client,
    origin: &CliServerOrigin,
    credential: &SessionCredential,
    repository_id: &str,
    name: &str,
    secret_id: &str,
) -> bool {
    matches!(
        get_by_name(client, origin, credential, repository_id, name).await,
        Ok(Some(metadata)) if validate_created_secret(&metadata, secret_id).is_ok()
    )
}

fn authenticated_request(
    client: &Client,
    method: Method,
    endpoint: Url,
    credential: &SessionCredential,
) -> Result<reqwest::RequestBuilder> {
    Ok(client
        .request(method, endpoint)
        .header(header::AUTHORIZATION, bearer_header(credential)?))
}

async fn send_with_retries(
    client: &Client,
    request: &Request,
) -> std::result::Result<Response, SecretRequestError> {
    for attempt in 0..MAX_REQUEST_ATTEMPTS {
        let request = request
            .try_clone()
            .ok_or(SecretRequestError::NonReplayableRequest)?;
        match client.execute(request).await {
            Ok(response)
                if attempt + 1 < MAX_REQUEST_ATTEMPTS
                    && matches!(
                        response.status(),
                        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
                    ) =>
            {
                let delay = retry_after_seconds(&response).unwrap_or(1);
                discard_bounded_response(response)
                    .await
                    .map_err(|_| SecretRequestError::InvalidRetryResponse)?;
                if delay == 0 || delay > MAX_RETRY_DELAY_SECONDS {
                    return Err(SecretRequestError::InvalidRetryResponse);
                }
                sleep(Duration::from_secs(delay)).await;
            }
            Ok(response) => return Ok(response),
            Err(_) if attempt + 1 < MAX_REQUEST_ATTEMPTS => sleep(TRANSPORT_RETRY_DELAY).await,
            Err(_) => return Err(SecretRequestError::Transport),
        }
    }
    Err(SecretRequestError::Transport)
}

async fn response_error<T>(response: Response, status: StatusCode, noun: &str) -> Result<T> {
    discard_bounded_response(response).await?;
    match status {
        StatusCode::UNAUTHORIZED => bail!("CLI session is no longer authorized"),
        StatusCode::NOT_FOUND => bail!("{noun} is unavailable"),
        StatusCode::BAD_REQUEST => bail!("control plane rejected the {noun} request"),
        StatusCode::CONFLICT => bail!("{noun} changed concurrently"),
        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE => {
            bail!("{noun} service is temporarily unavailable")
        }
        _ => bail!("{noun} request returned HTTP {status}"),
    }
}

fn repository_scope(scope: &SecretScope) -> Result<&RepositoryRef> {
    let SecretScope::Repository(repository) = scope;
    GithubRepositoryName::new(repository.to_string())
        .map_err(|_| anyhow::anyhow!("GitHub repository coordinate is invalid"))?;
    Ok(repository)
}

fn repository_resolution_endpoint(
    origin: &CliServerOrigin,
    repository: &RepositoryRef,
) -> Result<Url> {
    endpoint_with_segments(
        origin.endpoint(REPOSITORY_RESOLUTION_BASE),
        &[repository.owner(), repository.name()],
    )
}

fn list_endpoint(
    origin: &CliServerOrigin,
    repository_id: &str,
    after: Option<&str>,
) -> Result<Url> {
    let mut endpoint = endpoint_with_segments(
        origin.endpoint(REPOSITORY_SECRETS_BASE),
        &[repository_id, "secrets"],
    )?;
    {
        let mut query = endpoint.query_pairs_mut();
        query.append_pair("limit", &LIST_PAGE_SIZE.to_string());
        if let Some(after) = after {
            query.append_pair("after", after);
        }
    }
    Ok(endpoint)
}

fn secret_name_endpoint(origin: &CliServerOrigin, repository_id: &str) -> Result<Url> {
    endpoint_with_segments(
        origin.endpoint(REPOSITORY_SECRETS_BASE),
        &[repository_id, "secrets", "lookup"],
    )
}

fn secret_id_endpoint(
    origin: &CliServerOrigin,
    repository_id: &str,
    secret_id: &str,
) -> Result<Url> {
    endpoint_with_segments(
        origin.endpoint(REPOSITORY_SECRETS_BASE),
        &[repository_id, "secrets", secret_id],
    )
}

fn endpoint_with_segments(mut endpoint: Url, segments: &[&str]) -> Result<Url> {
    endpoint
        .path_segments_mut()
        .map_err(|()| anyhow::anyhow!("secret endpoint could not be constructed"))?
        .extend(segments);
    Ok(endpoint)
}

fn quoted_revision(revision: u64) -> Result<header::HeaderValue> {
    if revision == 0 || revision > i64::MAX as u64 {
        bail!("control plane returned an invalid metadata revision")
    }
    header::HeaderValue::from_str(&format!("\"{revision}\""))
        .map_err(|_| anyhow::anyhow!("metadata revision could not be encoded"))
}

fn secret_name_header(name: &str) -> Result<header::HeaderValue> {
    let mut value = header::HeaderValue::from_str(name)
        .map_err(|_| anyhow::anyhow!("secret name could not be encoded"))?;
    value.set_sensitive(true);
    Ok(value)
}

fn canonical_uuid(value: &str) -> Result<String> {
    let id = value
        .parse::<RunId>()
        .map_err(|_| anyhow::anyhow!("invalid durable identifier"))?;
    if id.as_uuid().is_nil() || id.to_string() != value {
        bail!("invalid durable identifier")
    }
    Ok(value.to_owned())
}

fn validate_page(
    page: &SecretPageDocument,
    repository_id: &str,
    after: Option<&str>,
) -> Result<()> {
    if page.items.len() > LIST_PAGE_SIZE || page.items.is_empty() && page.next_after.is_some() {
        bail!("control plane returned an invalid secret metadata page")
    }
    let mut previous = after.map(str::to_owned);
    for item in &page.items {
        validate_secret_metadata(item, repository_id, None)?;
        if previous.as_ref().is_some_and(|value| value >= &item.id) {
            bail!("control plane returned unordered secret metadata")
        }
        previous = Some(item.id.clone());
    }
    if let Some(next) = page.next_after.as_ref() {
        canonical_uuid(next)?;
        if page.items.len() != LIST_PAGE_SIZE
            || page.items.last().map(|item| &item.id) != Some(next)
        {
            bail!("control plane returned an invalid secret metadata cursor")
        }
    }
    Ok(())
}

fn validate_secret_metadata(
    document: &SecretMetadataDocument,
    repository_id: &str,
    expected_name: Option<&str>,
) -> Result<()> {
    canonical_uuid(&document.id)?;
    if canonical_uuid(&document.repository_id)? != repository_id {
        bail!("control plane returned cross-repository secret metadata")
    }
    let name = RepositorySecretName::new(&document.name)
        .map_err(|_| anyhow::anyhow!("control plane returned an invalid secret name"))?;
    if name.as_str() != document.name
        || expected_name.is_some_and(|expected| name.as_str() != expected)
    {
        bail!("control plane returned mismatched secret metadata")
    }
    ManagedSecretProviderId::new(document.provider_id.clone())
        .map_err(|_| anyhow::anyhow!("control plane returned invalid provider metadata"))?;
    if document.revision == 0
        || document.revision > i64::MAX as u64
        || document.current_version_number.as_ref() == Some(&0)
        || document.state == SecretState::Provisioning && document.current_version_number.is_some()
        || document.state != SecretState::Provisioning && document.current_version_number.is_none()
        || document.created_at_milliseconds < 0
        || document.updated_at_milliseconds < document.created_at_milliseconds
    {
        bail!("control plane returned invalid secret lifecycle metadata")
    }
    Ok(())
}

fn validate_created_secret(document: &SecretMetadataDocument, secret_id: &str) -> Result<()> {
    if document.id != secret_id
        || document.provider_id != BUILTIN_SECRET_PROVIDER_ID
        || document.state != SecretState::Active
        || document.current_version_number.as_ref() != Some(&1)
        || document.revision != 2
        || document.created_at_milliseconds < 0
        || document.updated_at_milliseconds < document.created_at_milliseconds
    {
        bail!("control plane returned an invalid created-secret transition")
    }
    Ok(())
}

fn validate_provider_inspection(document: &ProviderInspectionDocument) -> Result<()> {
    if document.id != BUILTIN_SECRET_PROVIDER_ID
        || document.revision == 0
        || document.revision > i64::MAX as u64
        || document
            .activation
            .as_ref()
            .is_some_and(|value| value.expected_revision != document.revision)
        || (document.state == ProviderState::Active && document.activation.is_some())
    {
        bail!("control plane returned invalid built-in provider metadata")
    }
    Ok(())
}

fn validate_provider_mutation(
    document: &ProviderMutationDocument,
    prior_revision: u64,
    prior_state: ProviderState,
) -> Result<()> {
    let expected_revision = expected_provider_revision(prior_revision, prior_state)?;
    if document.id != BUILTIN_SECRET_PROVIDER_ID
        || document.state != ProviderState::Active
        || document.revision != expected_revision
        || document.updated_at_milliseconds < 0
    {
        bail!("control plane returned invalid provider activation metadata")
    }
    Ok(())
}

fn provider_activation_matches(
    document: &ProviderInspectionDocument,
    prior_revision: u64,
    prior_state: ProviderState,
) -> bool {
    expected_provider_revision(prior_revision, prior_state).is_ok_and(|revision| {
        document.state == ProviderState::Active && document.revision == revision
    })
}

fn expected_provider_revision(prior_revision: u64, prior_state: ProviderState) -> Result<u64> {
    if prior_state == ProviderState::Active {
        return Ok(prior_revision);
    }
    prior_revision
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("provider revision overflowed"))
}

fn read_secret_value(path: Option<&Path>) -> Result<Zeroizing<Vec<u8>>> {
    let value = if let Some(path) = path {
        read_secret_file(path)?
    } else {
        let stdin = std::io::stdin();
        if stdin.is_terminal() {
            bail!("interactive secret entry is unavailable; redirect stdin or use --from-file")
        }
        read_bounded_value(stdin.lock()).context("could not read secret value from stdin")?
    };
    if value.is_empty() {
        bail!("secret value must not be empty")
    }
    Ok(value)
}

fn read_secret_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    if !path.is_absolute() {
        bail!("secret input file is unavailable or unsafe")
    }
    let mut components = Vec::<OsString>::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) => {}
            Component::Normal(value) => components.push(value.to_os_string()),
            Component::CurDir | Component::ParentDir => {
                bail!("secret input file is unavailable or unsafe")
            }
        }
    }
    let (filename, parents) = components
        .split_last()
        .ok_or_else(|| anyhow::anyhow!("secret input file is unavailable or unsafe"))?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let mut directory: OwnedFd = open("/", directory_flags, Mode::empty())
        .map_err(|_| anyhow::anyhow!("secret input file is unavailable or unsafe"))?;
    for component in parents {
        directory = openat(&directory, component, directory_flags, Mode::empty())
            .map_err(|_| anyhow::anyhow!("secret input file is unavailable or unsafe"))?;
        let metadata = fstat(&directory)
            .map_err(|_| anyhow::anyhow!("secret input file is unavailable or unsafe"))?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory {
            bail!("secret input file is unavailable or unsafe")
        }
    }
    let descriptor = openat(
        &directory,
        filename,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| anyhow::anyhow!("secret input file is unavailable or unsafe"))?;
    let metadata = fstat(&descriptor)
        .map_err(|_| anyhow::anyhow!("secret input file is unavailable or unsafe"))?;
    let permissions = metadata.st_mode & 0o777;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_nlink != 1
        || !matches!(permissions, 0o400 | 0o600)
        || u64::try_from(metadata.st_size).unwrap_or(u64::MAX)
            > u64::try_from(MAX_SECRET_INGRESS_BYTES).unwrap_or(u64::MAX)
    {
        bail!("secret input file is unavailable or unsafe")
    }
    let value = read_bounded_value(File::from(descriptor))
        .context("secret input file could not be read safely")?;
    if value.len() != usize::try_from(metadata.st_size).unwrap_or(usize::MAX) {
        bail!("secret input file changed while it was read")
    }
    Ok(value)
}

fn read_bounded_value(mut reader: impl Read) -> Result<Zeroizing<Vec<u8>>> {
    const SCRATCH_BYTES: usize = 8 * 1_024;
    let capacity = MAX_SECRET_INGRESS_BYTES
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("secret input byte limit is invalid"))?;
    let mut allocation = Vec::new();
    allocation
        .try_reserve_exact(capacity)
        .map_err(|_| anyhow::anyhow!("secret input buffer is unavailable"))?;
    let mut value = Zeroizing::new(allocation);
    let mut scratch = Zeroizing::new([0_u8; SCRATCH_BYTES]);
    while value.len() < capacity {
        let remaining = capacity - value.len();
        let received = reader.read(&mut scratch[..remaining.min(SCRATCH_BYTES)])?;
        if received == 0 {
            break;
        }
        value.extend_from_slice(&scratch[..received]);
        scratch[..received].zeroize();
    }
    if value.len() > MAX_SECRET_INGRESS_BYTES {
        bail!("secret value exceeds its byte limit")
    }
    Ok(value)
}

fn confirm_delete(repository: &RepositoryRef, name: &str) -> Result<bool> {
    let descriptor = open(
        "/dev/tty",
        OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| anyhow::anyhow!("a controlling terminal is required for confirmation"))?;
    let metadata = fstat(&descriptor)
        .map_err(|_| anyhow::anyhow!("the controlling terminal could not be verified"))?;
    if !FileType::from_raw_mode(metadata.st_mode).is_char_device() {
        bail!("the controlling terminal could not be verified")
    }
    let mut terminal = File::from(descriptor);
    if !terminal.is_terminal() {
        bail!("the controlling terminal could not be verified")
    }
    write!(
        terminal,
        "Delete {name} from {repository}? Type DELETE to confirm: "
    )?;
    terminal.flush()?;
    read_delete_confirmation(&mut terminal)
}

fn read_delete_confirmation(mut reader: impl Read) -> Result<bool> {
    let mut answer = Zeroizing::new(Vec::with_capacity(MAX_CONFIRMATION_BYTES));
    let mut byte = [0_u8; 1];
    let mut line_terminated = false;
    let mut overlong = false;
    loop {
        match reader.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => {
                line_terminated = true;
                break;
            }
            Ok(_) if answer.len() == MAX_CONFIRMATION_BYTES => overlong = true,
            Ok(_) if !overlong => answer.push(byte[0]),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    byte.zeroize();
    if !line_terminated || overlong {
        return Ok(false);
    }
    if answer.last() == Some(&b'\r') {
        answer.pop();
    }
    let answer = std::str::from_utf8(answer.as_slice())
        .map_err(|_| anyhow::anyhow!("delete confirmation was invalid"))?;
    Ok(answer == "DELETE")
}

fn print_secret_list(
    output: OutputFormat,
    repository: &RepositoryRef,
    records: &[SecretMetadataDocument],
) -> Result<()> {
    match output {
        OutputFormat::Table => {
            println!("NAME\tSTATE\tPROVIDER\tVERSION\tUPDATED_MS");
            for record in records {
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    escaped_table_value(&record.name),
                    record.state.as_str(),
                    escaped_table_value(&record.provider_id),
                    record
                        .current_version_number
                        .as_ref()
                        .map_or_else(|| "-".to_owned(), ToString::to_string),
                    record.updated_at_milliseconds,
                );
            }
        }
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string(&SecretListOutput {
                repository: repository.to_string(),
                items: records,
            })?
        ),
        OutputFormat::JsonLines => {
            for record in records {
                println!("{}", serde_json::to_string(record)?);
            }
        }
    }
    Ok(())
}

fn print_mutation(
    output: OutputFormat,
    operation: &'static str,
    repository: &RepositoryRef,
    name: &str,
) -> Result<()> {
    let document = SecretMutationOutput {
        operation,
        repository: repository.to_string(),
        name,
    };
    match output {
        OutputFormat::Table => {
            println!("operation\t{operation}");
            println!("repository\t{repository}");
            println!("name\t{}", escaped_table_value(name));
        }
        OutputFormat::Json | OutputFormat::JsonLines => {
            println!("{}", serde_json::to_string(&document)?);
        }
    }
    Ok(())
}

fn print_provider(output: OutputFormat, provider: &ProviderInspectionDocument) -> Result<()> {
    match output {
        OutputFormat::Table => {
            println!("provider\t{}", provider.id);
            println!("state\t{}", provider.state.as_str());
            println!("health\t{}", provider.health.as_str());
            println!("revision\t{}", provider.revision);
            println!("activation_available\t{}", provider.activation.is_some());
        }
        OutputFormat::Json | OutputFormat::JsonLines => {
            println!("{}", serde_json::to_string(provider)?);
        }
    }
    Ok(())
}

#[derive(Debug)]
enum SecretRequestError {
    NonReplayableRequest,
    InvalidRetryResponse,
    Transport,
}

impl fmt::Display for SecretRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NonReplayableRequest => "secret request body cannot be replayed safely",
            Self::InvalidRetryResponse => "control plane returned an invalid retry response",
            Self::Transport => "secret request transport failed",
        })
    }
}

impl std::error::Error for SecretRequestError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepositoryResolutionDocument {
    repository_id: String,
}

#[derive(Clone, Debug)]
struct ExplicitNullable<T>(Option<T>);

impl<T> ExplicitNullable<T> {
    const fn as_ref(&self) -> Option<&T> {
        self.0.as_ref()
    }

    const fn is_some(&self) -> bool {
        self.0.is_some()
    }

    const fn is_none(&self) -> bool {
        self.0.is_none()
    }

    fn into_option(self) -> Option<T> {
        self.0
    }
}

impl<T> From<Option<T>> for ExplicitNullable<T> {
    fn from(value: Option<T>) -> Self {
        Self(value)
    }
}

impl<'de, T> Deserialize<'de> for ExplicitNullable<T>
where
    T: serde::de::DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        serde_json::from_value(value)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

impl<T> Serialize for ExplicitNullable<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretPageDocument {
    items: Vec<SecretMetadataDocument>,
    next_after: ExplicitNullable<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SecretMetadataDocument {
    id: String,
    repository_id: String,
    name: String,
    provider_id: String,
    state: SecretState,
    current_version_number: ExplicitNullable<u64>,
    revision: u64,
    created_at_milliseconds: i64,
    updated_at_milliseconds: i64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SecretState {
    Provisioning,
    Active,
    Disabled,
}

impl SecretState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Provisioning => "provisioning",
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderInspectionDocument {
    id: String,
    state: ProviderState,
    health: ProviderHealth,
    revision: u64,
    activation: ExplicitNullable<ProviderActivationDocument>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderActivationDocument {
    expected_revision: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProviderState {
    Unconfigured,
    Active,
    Disabled,
}

impl ProviderState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Unconfigured => "unconfigured",
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProviderHealth {
    Unknown,
    Healthy,
    Degraded,
    Unavailable,
}

impl ProviderHealth {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderMutationDocument {
    id: String,
    state: ProviderState,
    revision: u64,
    updated_at_milliseconds: i64,
}

#[derive(Serialize)]
struct SecretListOutput<'a> {
    repository: String,
    items: &'a [SecretMetadataDocument],
}

#[derive(Serialize)]
struct SecretMutationOutput<'a> {
    operation: &'static str,
    repository: String,
    name: &'a str,
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, OpenOptions},
        io::{Cursor, Write as _},
        os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _, symlink},
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };

    use axum::{
        Router,
        body::Bytes as AxumBytes,
        extract::{Path as AxumPath, State},
        http::{HeaderMap, StatusCode},
        response::Response as AxumResponse,
        routing::{delete as axum_delete, get, post, put},
    };
    use sha2::{Digest as _, Sha256};

    use super::*;

    #[test]
    fn secret_input_is_bounded_and_debug_surfaces_do_not_contain_it() {
        let marker = b"unique-secret-marker";
        let value = read_bounded_value(Cursor::new(marker)).expect("bounded value");
        assert_eq!(value.as_slice(), marker);
        assert!(value.capacity() > MAX_SECRET_INGRESS_BYTES);
        assert!(!format!("{:?}", SecretRequestError::Transport).contains("unique-secret"));

        let oversized = vec![b'X'; MAX_SECRET_INGRESS_BYTES + 1];
        let error = read_bounded_value(Cursor::new(oversized)).expect_err("oversized value");
        assert!(!error.to_string().contains("XXXXXXXX"));
    }

    #[test]
    fn delete_confirmation_stops_at_one_bounded_utf8_line() {
        assert!(
            read_delete_confirmation(Cursor::new(b"DELETE\nignored")).expect("valid confirmation")
        );
        assert!(
            read_delete_confirmation(Cursor::new(b"DELETE\r\nignored"))
                .expect("valid CRLF confirmation")
        );
        assert!(!read_delete_confirmation(Cursor::new(b"DELETE")).expect("unterminated input"));
        let mut sequential = vec![b'X'; MAX_CONFIRMATION_BYTES + 1];
        sequential.extend_from_slice(b"\nDELETE\n");
        let mut sequential = Cursor::new(sequential);
        assert!(!read_delete_confirmation(&mut sequential).expect("oversized confirmation"));
        assert!(read_delete_confirmation(&mut sequential).expect("next confirmation line"));
        let error = read_delete_confirmation(Cursor::new([0xff, b'\n']))
            .expect_err("non-UTF-8 confirmation");
        assert_eq!(error.to_string(), "delete confirmation was invalid");
    }

    #[test]
    fn mutation_authority_errors_are_fixed_and_non_enumerating() {
        assert_eq!(
            SECRET_CREATE_AUTHORITY,
            "secret create requires secrets:metadata:read and secrets:create authority"
        );
        assert_eq!(
            SECRET_DELETE_AUTHORITY,
            "secret delete requires secrets:metadata:read and secrets:delete authority"
        );
        assert_eq!(
            PROVIDER_ACTIVATE_AUTHORITY,
            "provider activation requires secret-providers:read and secret-providers:manage authority"
        );
        for message in [
            SECRET_CREATE_AUTHORITY,
            SECRET_DELETE_AUTHORITY,
            PROVIDER_ACTIVATE_AUTHORITY,
        ] {
            assert!(!message.contains("owner/"));
            assert!(!message.contains("DEPLOY_TOKEN"));
        }
    }

    #[test]
    fn secret_file_input_is_absolute_owner_only_regular_and_nofollow() {
        const MARKER: &[u8] = b"unique-file-secret-marker";
        let directory = std::env::temp_dir().join(format!("automata-secret-{}", RunId::new()));
        fs::create_dir(&directory).expect("test directory");
        let path = directory.join("value");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("secret input");
        file.write_all(MARKER).expect("write input");
        drop(file);

        let value = read_secret_file(&path).expect("safe file");
        assert_eq!(value.as_slice(), MARKER);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("permissions");
        let error = read_secret_file(&path).expect_err("public file");
        assert!(!error.to_string().contains("unique-file"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("permissions");
        let link = directory.join("link");
        symlink(&path, &link).expect("symlink");
        assert!(read_secret_file(&link).is_err());

        fs::remove_file(&link).expect("remove symlink");
        fs::remove_file(&path).expect("remove input");
        fs::remove_dir(&directory).expect("remove directory");
    }

    #[test]
    fn dynamic_endpoints_percent_encode_segments_and_keep_values_out_of_urls() {
        let origin = CliServerOrigin::new("https://ci.example.test/").expect("origin");
        let repository: RepositoryRef = "automata-ci/automata".parse().expect("repository");
        assert_eq!(
            repository_resolution_endpoint(&origin, &repository)
                .expect("resolution endpoint")
                .as_str(),
            "https://ci.example.test/api/v1/repository-targets/github/automata-ci/automata"
        );
        assert_eq!(
            secret_name_endpoint(&origin, "10000000-0000-4000-8000-000000000001",)
                .expect("lookup endpoint")
                .as_str(),
            "https://ci.example.test/api/v1/repositories/10000000-0000-4000-8000-000000000001/secrets/lookup"
        );
    }

    #[test]
    fn metadata_and_provider_documents_are_strictly_validated() {
        let repository = "10000000-0000-4000-8000-000000000001";
        let mut document = SecretMetadataDocument {
            id: "20000000-0000-4000-8000-000000000002".to_owned(),
            repository_id: repository.to_owned(),
            name: "DEPLOY_TOKEN".to_owned(),
            provider_id: "builtin".to_owned(),
            state: SecretState::Active,
            current_version_number: Some(1).into(),
            revision: 2,
            created_at_milliseconds: 1,
            updated_at_milliseconds: 2,
        };
        validate_secret_metadata(&document, repository, Some("DEPLOY_TOKEN")).expect("metadata");
        validate_created_secret(&document, "20000000-0000-4000-8000-000000000002")
            .expect("created transition");
        document.provider_id = "external".to_owned();
        assert!(
            validate_created_secret(&document, "20000000-0000-4000-8000-000000000002").is_err()
        );

        let provider = ProviderInspectionDocument {
            id: "builtin".to_owned(),
            state: ProviderState::Unconfigured,
            health: ProviderHealth::Healthy,
            revision: 3,
            activation: Some(ProviderActivationDocument {
                expected_revision: 3,
            })
            .into(),
        };
        validate_provider_inspection(&provider).expect("provider");
        validate_provider_mutation(
            &ProviderMutationDocument {
                id: "builtin".to_owned(),
                state: ProviderState::Active,
                revision: 4,
                updated_at_milliseconds: 4,
            },
            3,
            ProviderState::Unconfigured,
        )
        .expect("activation transition");
        validate_provider_mutation(
            &ProviderMutationDocument {
                id: "builtin".to_owned(),
                state: ProviderState::Active,
                revision: 3,
                updated_at_milliseconds: 4,
            },
            3,
            ProviderState::Active,
        )
        .expect("already-active transition");
    }

    #[test]
    fn nullable_response_fields_require_explicit_presence() {
        assert!(
            serde_json::from_str::<SecretPageDocument>(r#"{"items":[]}"#).is_err(),
            "missing pagination cursor must not decode as an explicit null"
        );
        serde_json::from_str::<SecretPageDocument>(r#"{"items":[],"next_after":null}"#)
            .expect("explicit null pagination cursor");

        let metadata_without_version = serde_json::json!({
            "id": "20000000-0000-4000-8000-000000000002",
            "repository_id": "10000000-0000-4000-8000-000000000001",
            "name": "DEPLOY_TOKEN",
            "provider_id": "builtin",
            "state": "provisioning",
            "revision": 1,
            "created_at_milliseconds": 1,
            "updated_at_milliseconds": 1
        });
        assert!(
            serde_json::from_value::<SecretMetadataDocument>(metadata_without_version).is_err(),
            "missing current version must not decode as an explicit null"
        );

        let provider_without_activation = serde_json::json!({
            "id": "builtin",
            "state": "active",
            "health": "healthy",
            "revision": 3
        });
        assert!(
            serde_json::from_value::<ProviderInspectionDocument>(provider_without_activation)
                .is_err(),
            "missing activation capability must not decode as an explicit null"
        );
    }

    #[derive(Debug, Default)]
    struct ActiveActivationEvidence {
        inspections: AtomicUsize,
        activations: AtomicUsize,
        exact_revision: AtomicBool,
    }

    async fn inspect_active_provider(
        State(evidence): State<Arc<ActiveActivationEvidence>>,
    ) -> AxumResponse {
        evidence.inspections.fetch_add(1, Ordering::Relaxed);
        AxumResponse::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({
                    "id": "builtin",
                    "state": "active",
                    "health": "healthy",
                    "revision": 4,
                    "activation": null
                })
                .to_string(),
            ))
            .expect("response")
    }

    async fn confirm_already_active_provider(
        State(evidence): State<Arc<ActiveActivationEvidence>>,
        headers: HeaderMap,
    ) -> AxumResponse {
        evidence.activations.fetch_add(1, Ordering::Relaxed);
        evidence.exact_revision.store(
            headers
                .get(header::IF_MATCH)
                .and_then(|value| value.to_str().ok())
                == Some("\"4\""),
            Ordering::Relaxed,
        );
        AxumResponse::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({
                    "id": "builtin",
                    "state": "active",
                    "revision": 4,
                    "updated_at_milliseconds": 4
                })
                .to_string(),
            ))
            .expect("response")
    }

    #[tokio::test]
    async fn active_provider_still_crosses_revision_guarded_manage_boundary() {
        const SESSION: &str = "v1~key-1~AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let evidence = Arc::new(ActiveActivationEvidence::default());
        let app = Router::new()
            .route(BUILTIN_SECRET_PROVIDER_PATH, get(inspect_active_provider))
            .route(
                BUILTIN_SECRET_PROVIDER_ACTIVATION_PATH,
                post(confirm_already_active_provider),
            )
            .with_state(Arc::clone(&evidence));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test server");
        });
        let origin = CliServerOrigin::new(&format!("http://{address}/")).expect("origin");
        let credential = SessionCredential::from_raw(SESSION).expect("credential");

        activate_provider_with_combined_authority(
            &auth_client().expect("client"),
            &origin,
            &credential,
            OutputFormat::Json,
        )
        .await
        .expect("already-active confirmation");
        server.abort();

        assert_eq!(evidence.inspections.load(Ordering::Relaxed), 2);
        assert_eq!(evidence.activations.load(Ordering::Relaxed), 1);
        assert!(evidence.exact_revision.load(Ordering::Relaxed));
    }

    #[derive(Debug, Default)]
    struct RetryEvidence {
        attempts: AtomicUsize,
        authorized: AtomicBool,
        mutation_ids: Mutex<Vec<String>>,
        body_digests: Mutex<Vec<Vec<u8>>>,
    }

    async fn retriable_create(
        State(evidence): State<Arc<RetryEvidence>>,
        headers: HeaderMap,
        body: AxumBytes,
    ) -> AxumResponse {
        evidence.authorized.store(
            headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                == Some("Bearer v1~key-1~AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            Ordering::Relaxed,
        );
        evidence.mutation_ids.lock().expect("mutation IDs").push(
            headers
                .get("x-automata-secret-mutation-id")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned(),
        );
        evidence
            .body_digests
            .lock()
            .expect("body digests")
            .push(Sha256::digest(&body).to_vec());
        if let Ok(mut body) = body.try_into_mut() {
            body.as_mut().fill(0);
        }
        let attempt = evidence.attempts.fetch_add(1, Ordering::Relaxed);
        if attempt == 0 {
            AxumResponse::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header(header::RETRY_AFTER, "1")
                .body(axum::body::Body::empty())
                .expect("response")
        } else {
            AxumResponse::builder()
                .status(StatusCode::NO_CONTENT)
                .body(axum::body::Body::empty())
                .expect("response")
        }
    }

    #[derive(Debug, Default)]
    struct ReconciledCreateEvidence {
        secret_id: Mutex<Option<String>>,
        attempts: AtomicUsize,
    }

    async fn indeterminate_create(
        State(evidence): State<Arc<ReconciledCreateEvidence>>,
        AxumPath((_repository_id, secret_id)): AxumPath<(String, String)>,
        body: AxumBytes,
    ) -> AxumResponse {
        evidence.attempts.fetch_add(1, Ordering::Relaxed);
        *evidence.secret_id.lock().expect("secret ID") = Some(secret_id);
        if let Ok(mut body) = body.try_into_mut() {
            body.as_mut().fill(0);
        }
        AxumResponse::builder()
            .status(StatusCode::CONFLICT)
            .body(axum::body::Body::empty())
            .expect("response")
    }

    async fn reconciled_create_lookup(
        State(evidence): State<Arc<ReconciledCreateEvidence>>,
    ) -> AxumResponse {
        let secret_id = evidence
            .secret_id
            .lock()
            .expect("secret ID")
            .clone()
            .expect("created secret ID");
        let body = serde_json::json!({
            "id": secret_id,
            "repository_id": "10000000-0000-4000-8000-000000000001",
            "name": "DEPLOY_TOKEN",
            "provider_id": "builtin",
            "state": "active",
            "current_version_number": 1,
            "revision": 2,
            "created_at_milliseconds": 1,
            "updated_at_milliseconds": 2
        })
        .to_string();
        AxumResponse::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body))
            .expect("response")
    }

    #[derive(Debug, Default)]
    struct ReconciledDeleteEvidence {
        lookups: AtomicUsize,
        attempts: AtomicUsize,
    }

    async fn delete_repository_resolution() -> AxumResponse {
        AxumResponse::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                r#"{"repository_id":"10000000-0000-4000-8000-000000000001"}"#,
            ))
            .expect("response")
    }

    async fn delete_lookup(State(evidence): State<Arc<ReconciledDeleteEvidence>>) -> AxumResponse {
        if evidence.lookups.fetch_add(1, Ordering::Relaxed) == 0 {
            AxumResponse::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({
                        "id": "20000000-0000-4000-8000-000000000002",
                        "repository_id": "10000000-0000-4000-8000-000000000001",
                        "name": "DEPLOY_TOKEN",
                        "provider_id": "builtin",
                        "state": "active",
                        "current_version_number": 1,
                        "revision": 2,
                        "created_at_milliseconds": 1,
                        "updated_at_milliseconds": 2
                    })
                    .to_string(),
                ))
                .expect("response")
        } else {
            AxumResponse::builder()
                .status(StatusCode::NOT_FOUND)
                .body(axum::body::Body::empty())
                .expect("response")
        }
    }

    async fn replayed_delete(
        State(evidence): State<Arc<ReconciledDeleteEvidence>>,
    ) -> AxumResponse {
        evidence.attempts.fetch_add(1, Ordering::Relaxed);
        AxumResponse::builder()
            .status(StatusCode::CONFLICT)
            .body(axum::body::Body::empty())
            .expect("response")
    }

    #[tokio::test]
    async fn create_retries_the_same_zeroizing_body_and_mutation_identity() {
        const SESSION: &str = "v1~key-1~AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        const MARKER: &[u8] = b"unique-retry-secret-marker";
        let evidence = Arc::new(RetryEvidence::default());
        let app = Router::new()
            .route(
                "/api/v1/repositories/{repository_id}/secrets/{secret_id}",
                put(retriable_create),
            )
            .with_state(Arc::clone(&evidence));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test server");
        });
        let origin = CliServerOrigin::new(&format!("http://{address}/")).expect("origin");
        let credential = SessionCredential::from_raw(SESSION).expect("credential");
        create_repository_secret(
            &auth_client().expect("client"),
            &origin,
            &credential,
            "10000000-0000-4000-8000-000000000001",
            "DEPLOY_TOKEN",
            Zeroizing::new(MARKER.to_vec()),
        )
        .await
        .expect("create");
        server.abort();

        assert_eq!(evidence.attempts.load(Ordering::Relaxed), 2);
        assert!(evidence.authorized.load(Ordering::Relaxed));
        let mutation_ids = evidence.mutation_ids.lock().expect("mutation IDs");
        assert_eq!(mutation_ids.len(), 2);
        assert!(!mutation_ids[0].is_empty());
        assert_eq!(mutation_ids[0], mutation_ids[1]);
        let body_digests = evidence.body_digests.lock().expect("body digests");
        assert_eq!(body_digests.len(), 2);
        assert_eq!(body_digests[0], body_digests[1]);
        assert_eq!(body_digests[0], Sha256::digest(MARKER).to_vec());
    }

    #[tokio::test]
    async fn create_reconciles_an_exact_committed_result_after_an_ambiguous_status() {
        const SESSION: &str = "v1~key-1~AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let evidence = Arc::new(ReconciledCreateEvidence::default());
        let app = Router::new()
            .route(
                "/api/v1/repositories/{repository_id}/secrets/{secret_id}",
                put(indeterminate_create),
            )
            .route(
                "/api/v1/repositories/{repository_id}/secrets/lookup",
                get(reconciled_create_lookup),
            )
            .with_state(Arc::clone(&evidence));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test server");
        });
        let origin = CliServerOrigin::new(&format!("http://{address}/")).expect("origin");
        let credential = SessionCredential::from_raw(SESSION).expect("credential");
        let secret_id = create_repository_secret(
            &auth_client().expect("client"),
            &origin,
            &credential,
            "10000000-0000-4000-8000-000000000001",
            "DEPLOY_TOKEN",
            Zeroizing::new(b"reconciled-secret-value".to_vec()),
        )
        .await
        .expect("reconciled create");
        server.abort();

        assert_eq!(evidence.attempts.load(Ordering::Relaxed), 1);
        assert_eq!(
            evidence.secret_id.lock().expect("secret ID").as_deref(),
            Some(secret_id.as_str())
        );
    }

    #[tokio::test]
    async fn delete_reconciles_absence_after_a_committed_response_is_lost() {
        const SESSION: &str = "v1~key-1~AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let evidence = Arc::new(ReconciledDeleteEvidence::default());
        let app = Router::new()
            .route(
                "/api/v1/repository-targets/github/automata-ci/automata",
                get(delete_repository_resolution),
            )
            .route(
                "/api/v1/repositories/{repository_id}/secrets/lookup",
                get(delete_lookup),
            )
            .route(
                "/api/v1/repositories/{repository_id}/secrets/{secret_id}",
                axum_delete(replayed_delete),
            )
            .with_state(Arc::clone(&evidence));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test server");
        });
        let origin = CliServerOrigin::new(&format!("http://{address}/")).expect("origin");
        let credential = SessionCredential::from_raw(SESSION).expect("credential");
        let args = SecretDeleteArgs {
            name: "DEPLOY_TOKEN".to_owned(),
            scope: "repo:automata-ci/automata".parse().expect("scope"),
            yes: true,
        };
        delete_with_combined_authority(
            &auth_client().expect("client"),
            &origin,
            &credential,
            OutputFormat::Json,
            &args,
        )
        .await
        .expect("reconciled delete");
        server.abort();

        assert_eq!(evidence.attempts.load(Ordering::Relaxed), 1);
        assert_eq!(evidence.lookups.load(Ordering::Relaxed), 2);
    }
}
