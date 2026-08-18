use automata_ci_auth::{github::GithubEndpointError, secret::SecretString};
use automata_ci_core::GitObjectId;
use automata_ci_scm::{
    ArchiveFormat, RepositorySnapshot, RepositorySource, RepositorySourceArchive,
    RepositorySourceRedirectPolicy, RepositorySourceRequest, ScmError, ScmErrorKind, ScmProvider,
    ScmProviderId, SnapshotRequest,
};
use bytes::{Bytes, BytesMut};
use reqwest::{
    Response, StatusCode,
    header::{ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, LOCATION, RETRY_AFTER},
};
use serde::Deserialize;
use url::Url;

use crate::{
    config::same_origin,
    endpoint::{GithubHttpEndpoint, authorization_header},
    repository_path::{self, has_ascii_case_insensitive_suffix},
    response::{decode_json, read_json_response},
};

const ACCEPT_API_JSON: &str = "application/vnd.github+json";
const ACCEPT_ARCHIVE: &str = "application/octet-stream";
const X_RATE_LIMIT_REMAINING: &str = "x-ratelimit-remaining";

#[derive(Deserialize)]
struct CommitResponse {
    sha: String,
}

#[derive(Deserialize)]
struct RepositoryResponse {
    id: u64,
    full_name: String,
}

impl GithubHttpEndpoint {
    fn repository_url(
        &self,
        repository: &automata_ci_scm::RepositoryId,
        tail: &[&str],
    ) -> Result<Url, ScmError> {
        let (owner, name) = repository_path::split(repository.as_str())
            .ok_or_else(|| ScmError::new(ScmErrorKind::InvalidResponse))?;
        let mut endpoint = self.trusted.api_base().clone();
        let mut segments = endpoint
            .path_segments_mut()
            .map_err(|()| ScmError::new(ScmErrorKind::InvalidResponse))?;
        segments.pop_if_empty();
        segments.push("repos");
        segments.push(owner);
        segments.push(name);
        for component in tail {
            segments.push(component);
        }
        drop(segments);
        if !self.trusted.trusts_api_url(&endpoint) {
            return Err(ScmError::new(ScmErrorKind::InvalidResponse));
        }
        Ok(endpoint)
    }

    fn authenticated_get(
        &self,
        endpoint: Url,
        credential: Option<&SecretString>,
    ) -> Result<reqwest::RequestBuilder, ScmError> {
        let mut request = self.client.get(endpoint).header(ACCEPT, ACCEPT_API_JSON);
        if let Some(credential) = credential {
            let authorization = authorization_header(credential).map_err(map_endpoint_error)?;
            request = request.header(AUTHORIZATION, authorization);
        }
        Ok(request)
    }

    async fn resolve_revision(
        &self,
        request: &SnapshotRequest<'_>,
    ) -> Result<GitObjectId, ScmError> {
        validate_github_revision(request.revision().as_str())?;
        let endpoint = self.repository_url(
            request.repository(),
            &["commits", request.revision().as_str()],
        )?;
        let response = self
            .authenticated_get(endpoint, request.credential())?
            .send()
            .await
            .map_err(|_| ScmError::new(ScmErrorKind::Unavailable))?;
        reject_api_status(&response)?;
        let response =
            read_json_response(response, self.trusted.limits().max_response_bytes, false)
                .await
                .map_err(map_endpoint_error)?;
        let commit: CommitResponse = decode_json(&response.body).map_err(map_endpoint_error)?;
        validate_commit_sha(&commit.sha)
    }

    async fn prove_exact_revision(
        &self,
        request: &RepositorySourceRequest<'_>,
    ) -> Result<(), ScmError> {
        let revision = request.revision().to_string();
        let endpoint = self.repository_url(request.repository(), &["commits", &revision])?;
        let response = self
            .authenticated_get(endpoint, request.credential())?
            .send()
            .await
            .map_err(|_| ScmError::new(ScmErrorKind::Unavailable))?;
        reject_api_status(&response)?;
        let response =
            read_json_response(response, self.trusted.limits().max_response_bytes, false)
                .await
                .map_err(map_endpoint_error)?;
        let commit: CommitResponse = decode_json(&response.body).map_err(map_endpoint_error)?;
        let resolved = GitObjectId::from_provider_hex(commit.sha)
            .map_err(|_| ScmError::new(ScmErrorKind::InvalidResponse))?;
        if &resolved != request.revision() {
            return Err(ScmError::new(ScmErrorKind::InvalidResponse));
        }
        Ok(())
    }

    async fn prove_repository_identity(
        &self,
        request: &RepositorySourceRequest<'_>,
    ) -> Result<(), ScmError> {
        let endpoint = self.repository_url(request.repository(), &[])?;
        let response = self
            .authenticated_get(endpoint, request.credential())?
            .send()
            .await
            .map_err(|_| ScmError::new(ScmErrorKind::Unavailable))?;
        reject_api_status(&response)?;
        let response =
            read_json_response(response, self.trusted.limits().max_response_bytes, false)
                .await
                .map_err(map_endpoint_error)?;
        let repository: RepositoryResponse =
            decode_json(&response.body).map_err(map_endpoint_error)?;
        if repository.id == 0
            || repository.id.to_string() != request.connection().external_repository_id().as_str()
            || repository.full_name != request.repository().as_str()
        {
            return Err(ScmError::new(ScmErrorKind::InvalidResponse));
        }
        Ok(())
    }

    async fn archive_redirect(
        &self,
        request: &SnapshotRequest<'_>,
        resolved_revision: &GitObjectId,
    ) -> Result<Url, ScmError> {
        let resolved_revision = resolved_revision.to_string();
        let endpoint =
            self.repository_url(request.repository(), &["tarball", &resolved_revision])?;
        let response = self
            .authenticated_get(endpoint, request.credential())?
            .send()
            .await
            .map_err(|_| ScmError::new(ScmErrorKind::Unavailable))?;
        if response.status() != StatusCode::FOUND {
            return Err(map_status(&response));
        }
        unique_location(&response).and_then(|location| self.validate_archive_location(location))
    }

    async fn exact_archive_redirect(
        &self,
        request: &RepositorySourceRequest<'_>,
    ) -> Result<Url, ScmError> {
        if request.redirect_policy() != RepositorySourceRedirectPolicy::ConfiguredArchiveOrigin {
            return Err(ScmError::new(ScmErrorKind::InvalidResponse));
        }
        let revision = request.revision().to_string();
        let endpoint = self.repository_url(request.repository(), &["tarball", &revision])?;
        let response = self
            .authenticated_get(endpoint, request.credential())?
            .send()
            .await
            .map_err(|_| ScmError::new(ScmErrorKind::Unavailable))?;
        if response.status() != StatusCode::FOUND {
            return Err(map_status(&response));
        }
        unique_location(&response).and_then(|location| self.validate_archive_location(location))
    }

    fn validate_archive_location(&self, location: Url) -> Result<Url, ScmError> {
        if !same_origin(&self.archive_origin, &location)
            || location.username() != ""
            || location.password().is_some()
            || location.fragment().is_some()
            || location.path().is_empty()
            || location.path() == "/"
        {
            return Err(ScmError::new(ScmErrorKind::InvalidResponse));
        }
        Ok(location)
    }

    async fn download_archive(&self, location: Url, maximum_bytes: u64) -> Result<Bytes, ScmError> {
        let response = self
            .client
            .get(location)
            .header(ACCEPT, ACCEPT_ARCHIVE)
            .send()
            .await
            .map_err(|_| ScmError::new(ScmErrorKind::Unavailable))?;
        reject_archive_status(&response)?;
        validate_archive_content_type(&response)?;
        validate_content_length(&response, maximum_bytes)?;
        read_archive(response, maximum_bytes).await
    }

    fn exact_public_archive_location(
        &self,
        repository: &automata_ci_scm::RepositoryId,
        revision: &GitObjectId,
    ) -> Result<Url, ScmError> {
        let (owner, name) = repository_path::split(repository.as_str())
            .ok_or_else(|| ScmError::new(ScmErrorKind::InvalidResponse))?;
        let mut location = self.archive_origin.clone();
        let mut segments = location
            .path_segments_mut()
            .map_err(|()| ScmError::new(ScmErrorKind::InvalidResponse))?;
        segments.pop_if_empty();
        segments.push(owner);
        segments.push(name);
        segments.push("legacy.tar.gz");
        let revision = revision.to_string();
        segments.push(&revision);
        drop(segments);
        self.validate_archive_location(location)
    }
}

#[async_trait::async_trait]
impl ScmProvider for GithubHttpEndpoint {
    fn provider_id(&self) -> &ScmProviderId {
        &self.scm_provider_id
    }

    async fn fetch_snapshot(
        &self,
        request: SnapshotRequest<'_>,
    ) -> Result<RepositorySnapshot, ScmError> {
        if request.credential().is_none()
            && let Ok(exact) = GitObjectId::from_provider_hex(request.revision().as_str())
        {
            let location = self.exact_public_archive_location(request.repository(), &exact)?;
            let bytes = self
                .download_archive(location, request.limits().maximum_bytes())
                .await?;
            return Ok(RepositorySnapshot::from_bytes(
                self.scm_provider_id.clone(),
                request.repository().clone(),
                request.revision().clone(),
                exact,
                ArchiveFormat::TarGzip,
                bytes,
            ));
        }
        let resolved = self.resolve_revision(&request).await?;
        let location = self.archive_redirect(&request, &resolved).await?;
        let bytes = self
            .download_archive(location, request.limits().maximum_bytes())
            .await?;
        Ok(RepositorySnapshot::from_bytes(
            self.scm_provider_id.clone(),
            request.repository().clone(),
            request.revision().clone(),
            resolved,
            ArchiveFormat::TarGzip,
            bytes,
        ))
    }
}

#[async_trait::async_trait]
impl RepositorySource for GithubHttpEndpoint {
    async fn fetch_repository_source(
        &self,
        request: RepositorySourceRequest<'_>,
    ) -> Result<RepositorySourceArchive, ScmError> {
        if request.credential().is_none() {
            let location =
                self.exact_public_archive_location(request.repository(), request.revision())?;
            let bytes = self
                .download_archive(location, request.limits().maximum_bytes())
                .await?;
            return Ok(RepositorySourceArchive::from_bytes(
                request.connection().clone(),
                *request.revision(),
                ArchiveFormat::TarGzip,
                bytes,
            ));
        }
        self.prove_repository_identity(&request).await?;
        self.prove_exact_revision(&request).await?;
        let location = self.exact_archive_redirect(&request).await?;
        let bytes = self
            .download_archive(location, request.limits().maximum_bytes())
            .await?;
        Ok(RepositorySourceArchive::from_bytes(
            request.connection().clone(),
            *request.revision(),
            ArchiveFormat::TarGzip,
            bytes,
        ))
    }
}

fn validate_github_revision(revision: &str) -> Result<(), ScmError> {
    let invalid = revision == "@"
        || revision.starts_with(['/', '.'])
        || revision.ends_with(['/', '.'])
        || revision.contains("..")
        || revision.contains("@{")
        || revision.contains("//")
        || revision.split('/').any(|component| {
            component.is_empty()
                || component.starts_with('.')
                || has_ascii_case_insensitive_suffix(component, ".lock")
        })
        || revision.bytes().any(|byte| {
            byte.is_ascii_control()
                || byte == b' '
                || matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        });
    if invalid {
        return Err(ScmError::new(ScmErrorKind::InvalidResponse));
    }
    Ok(())
}

fn validate_commit_sha(value: &str) -> Result<GitObjectId, ScmError> {
    GitObjectId::from_provider_hex(value).map_err(|_| ScmError::new(ScmErrorKind::InvalidResponse))
}

fn unique_location(response: &Response) -> Result<Url, ScmError> {
    let mut values = response.headers().get_all(LOCATION).iter();
    let value = values
        .next()
        .filter(|_| values.next().is_none())
        .ok_or_else(|| ScmError::new(ScmErrorKind::InvalidResponse))?;
    let value = value
        .to_str()
        .map_err(|_| ScmError::new(ScmErrorKind::InvalidResponse))?;
    Url::parse(value).map_err(|_| ScmError::new(ScmErrorKind::InvalidResponse))
}

fn reject_api_status(response: &Response) -> Result<(), ScmError> {
    if response.status() == StatusCode::OK {
        return Ok(());
    }
    Err(map_status(response))
}

fn reject_archive_status(response: &Response) -> Result<(), ScmError> {
    if response.status() == StatusCode::OK {
        return Ok(());
    }
    Err(map_status(response))
}

fn map_status(response: &Response) -> ScmError {
    let status = response.status();
    match status {
        StatusCode::NOT_FOUND => ScmError::new(ScmErrorKind::NotFound),
        StatusCode::UNAUTHORIZED => ScmError::new(ScmErrorKind::Unauthorized),
        StatusCode::FORBIDDEN if is_rate_limited(response) => {
            ScmError::rate_limited(retry_after_seconds(response))
        }
        StatusCode::FORBIDDEN => ScmError::new(ScmErrorKind::Forbidden),
        StatusCode::TOO_MANY_REQUESTS => ScmError::rate_limited(retry_after_seconds(response)),
        StatusCode::REQUEST_TIMEOUT => ScmError::new(ScmErrorKind::Unavailable),
        _ if status.is_server_error() => ScmError::new(ScmErrorKind::Unavailable),
        _ => ScmError::new(ScmErrorKind::InvalidResponse),
    }
}

fn is_rate_limited(response: &Response) -> bool {
    response.headers().contains_key(RETRY_AFTER)
        || response
            .headers()
            .get(X_RATE_LIMIT_REMAINING)
            .is_some_and(|value| value.as_bytes() == b"0")
}

fn retry_after_seconds(response: &Response) -> Option<u64> {
    response
        .headers()
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
}

fn validate_archive_content_type(response: &Response) -> Result<(), ScmError> {
    let mut values = response.headers().get_all(CONTENT_TYPE).iter();
    let value = values
        .next()
        .filter(|_| values.next().is_none())
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ScmError::new(ScmErrorKind::InvalidResponse))?;
    let media_type = value.split(';').next().unwrap_or_default().trim();
    if !matches!(
        media_type,
        "application/gzip" | "application/octet-stream" | "application/x-gzip"
    ) {
        return Err(ScmError::new(ScmErrorKind::InvalidResponse));
    }
    Ok(())
}

fn validate_content_length(response: &Response, maximum_bytes: u64) -> Result<(), ScmError> {
    let mut values = response.headers().get_all(CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err(ScmError::new(ScmErrorKind::InvalidResponse));
    }
    let length = value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| ScmError::new(ScmErrorKind::InvalidResponse))?;
    if length == 0 {
        return Err(ScmError::new(ScmErrorKind::InvalidResponse));
    }
    if length > maximum_bytes {
        return Err(ScmError::new(ScmErrorKind::TooLarge));
    }
    Ok(())
}

async fn read_archive(mut response: Response, maximum_bytes: u64) -> Result<Bytes, ScmError> {
    let initial_capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .map(|length| length.min(1024 * 1024))
        .unwrap_or_default();
    let mut bytes = BytesMut::with_capacity(initial_capacity);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| ScmError::new(ScmErrorKind::Unavailable))?
    {
        let next_length = u64::try_from(bytes.len())
            .ok()
            .and_then(|length| length.checked_add(u64::try_from(chunk.len()).ok()?))
            .ok_or_else(|| ScmError::new(ScmErrorKind::TooLarge))?;
        if next_length > maximum_bytes {
            return Err(ScmError::new(ScmErrorKind::TooLarge));
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.len() < 2 || bytes[..2] != [0x1f, 0x8b] {
        return Err(ScmError::new(ScmErrorKind::Integrity));
    }
    Ok(bytes.freeze())
}

fn map_endpoint_error(error: GithubEndpointError) -> ScmError {
    match error {
        GithubEndpointError::Unauthorized => ScmError::new(ScmErrorKind::Unauthorized),
        GithubEndpointError::Forbidden => ScmError::new(ScmErrorKind::Forbidden),
        GithubEndpointError::RateLimited {
            retry_after_seconds,
        } => ScmError::rate_limited(retry_after_seconds),
        GithubEndpointError::Unavailable => ScmError::new(ScmErrorKind::Unavailable),
        GithubEndpointError::InvalidResponse => ScmError::new(ScmErrorKind::InvalidResponse),
    }
}
