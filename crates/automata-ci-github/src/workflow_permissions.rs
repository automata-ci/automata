use std::{fmt, time::Instant};

use automata_ci_auth::{github::GithubEndpointError, secret::SecretString};
pub use automata_ci_github_permissions::GithubDefaultWorkflowPermission;
use automata_ci_scm::RepositoryId;
use reqwest::header::{ACCEPT, AUTHORIZATION};
use serde::Deserialize;
use url::Url;

use crate::{
    endpoint::{GithubHttpEndpoint, authorization_header},
    repository_path,
    response::{decode_json, read_json_response},
};

const ACCEPT_API_JSON: &str = "application/vnd.github+json";

/// Exact effective repository workflow-permission settings observed from GitHub.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GithubWorkflowPermissionDefaults {
    default_workflow_permissions: GithubDefaultWorkflowPermission,
    can_approve_pull_request_reviews: bool,
}

impl GithubWorkflowPermissionDefaults {
    /// Returns the effective default applied when a workflow omits `permissions`.
    #[must_use]
    pub const fn default_workflow_permissions(self) -> GithubDefaultWorkflowPermission {
        self.default_workflow_permissions
    }

    /// Returns whether Actions may create or approve pull-request reviews.
    #[must_use]
    pub const fn can_approve_pull_request_reviews(self) -> bool {
        self.can_approve_pull_request_reviews
    }
}

/// One least-authority request for the effective repository workflow defaults.
pub struct GithubWorkflowPermissionDefaultsRequest<'request> {
    repository: &'request RepositoryId,
    credential: &'request SecretString,
    deadline: Instant,
}

impl<'request> GithubWorkflowPermissionDefaultsRequest<'request> {
    /// Binds the request to an exact repository, Administration-read credential, and deadline.
    #[must_use]
    pub const fn new(
        repository: &'request RepositoryId,
        credential: &'request SecretString,
        deadline: Instant,
    ) -> Self {
        Self {
            repository,
            credential,
            deadline,
        }
    }
}

impl fmt::Debug for GithubWorkflowPermissionDefaultsRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubWorkflowPermissionDefaultsRequest")
            .field("repository", &self.repository)
            .field("credential", &"[REDACTED]")
            .field("deadline", &self.deadline)
            .finish()
    }
}

impl GithubHttpEndpoint {
    /// Observes GitHub's effective default `GITHUB_TOKEN` policy for one repository.
    ///
    /// GitHub resolves any enterprise and organization restrictions before returning
    /// this repository-scoped value. The caller must supply an installation token
    /// containing exactly repository `Administration: read`; this adapter never
    /// substitutes a broader token or a configured default.
    ///
    /// # Errors
    ///
    /// Returns a sanitized endpoint error for expired deadlines, authentication or
    /// authorization failures, transport/rate-limit failures, redirects, oversized
    /// bodies, and any response outside the closed two-field schema.
    pub async fn workflow_permission_defaults(
        &self,
        request: GithubWorkflowPermissionDefaultsRequest<'_>,
    ) -> Result<GithubWorkflowPermissionDefaults, GithubEndpointError> {
        let remaining = request
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or(GithubEndpointError::Unavailable)?;
        let endpoint = self.workflow_permission_defaults_url(request.repository)?;
        let authorization = authorization_header(request.credential)?;
        let response = self
            .client
            .get(endpoint)
            .header(ACCEPT, ACCEPT_API_JSON)
            .header(AUTHORIZATION, authorization)
            .timeout(remaining.min(self.trusted.limits().request_timeout()))
            .send()
            .await
            .map_err(|_| GithubEndpointError::Unavailable)?;
        let response =
            read_json_response(response, self.trusted.limits().max_response_bytes, false).await?;
        decode_json(&response.body)
    }

    fn workflow_permission_defaults_url(
        &self,
        repository: &RepositoryId,
    ) -> Result<Url, GithubEndpointError> {
        let (owner, name) = repository_path::split(repository.as_str())
            .ok_or(GithubEndpointError::InvalidResponse)?;
        let mut endpoint = self.trusted.api_base().clone();
        let mut segments = endpoint
            .path_segments_mut()
            .map_err(|()| GithubEndpointError::InvalidResponse)?;
        segments.pop_if_empty();
        for segment in ["repos", owner, name, "actions", "permissions", "workflow"] {
            segments.push(segment);
        }
        drop(segments);
        if !self.trusted.trusts_api_url(&endpoint) {
            return Err(GithubEndpointError::InvalidResponse);
        }
        Ok(endpoint)
    }
}
