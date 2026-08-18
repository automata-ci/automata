use std::collections::{BTreeMap, BTreeSet};

use reqwest::{Response, StatusCode, header::CONTENT_TYPE};
use serde::Deserialize;
use thiserror::Error;

const MAX_INSTALLATION_EVENTS: usize = 64;
const MAX_INSTALLATION_PERMISSIONS: usize = 128;

/// Effective permission level reported for a GitHub App installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubAppInstallationPermission {
    /// Read-only repository permission.
    Read,
    /// Read-write repository permission.
    Write,
}

/// Bounded effective capabilities of one authenticated GitHub App installation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubAppInstallationCapabilities {
    installation_id: u64,
    app_id: u64,
    events: BTreeSet<String>,
    permissions: BTreeMap<String, GithubAppInstallationPermission>,
}

impl GithubAppInstallationCapabilities {
    /// Returns the observed installation identity.
    #[must_use]
    pub const fn installation_id(&self) -> u64 {
        self.installation_id
    }

    /// Returns the observed GitHub App identity.
    #[must_use]
    pub const fn app_id(&self) -> u64 {
        self.app_id
    }

    /// Reports whether the installation subscribes to an exact webhook event.
    #[must_use]
    pub fn has_event(&self, event: &str) -> bool {
        self.events.contains(event)
    }

    /// Returns the effective level of an exact repository permission.
    #[must_use]
    pub fn permission(&self, permission: &str) -> Option<GithubAppInstallationPermission> {
        self.permissions.get(permission).copied()
    }
}

/// Sanitized failure to observe effective GitHub App installation capabilities.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubAppInstallationObservationError {
    /// GitHub could not be reached within the configured transport policy.
    #[error("the GitHub App installation capabilities could not be observed")]
    Transport,
    /// The configured App assertion could not be produced or represented.
    #[error("the GitHub App installation observation could not be authenticated")]
    Authentication,
    /// GitHub rejected the authenticated installation observation.
    #[error("GitHub rejected the App installation capability observation")]
    ProviderRejected,
    /// GitHub returned an unbounded or malformed installation representation.
    #[error("GitHub returned invalid App installation capabilities")]
    InvalidResponse,
    /// The observed installation identity differed from the selected broker.
    #[error("the GitHub App installation identity does not match configuration")]
    IdentityMismatch,
}

#[derive(Deserialize)]
struct InstallationCapabilitiesResponse {
    id: u64,
    app_id: u64,
    events: Vec<String>,
    permissions: BTreeMap<String, String>,
}

pub(crate) async fn observe_installation_response(
    mut response: Response,
    max_response_bytes: usize,
    expected_installation_id: u64,
) -> Result<GithubAppInstallationCapabilities, GithubAppInstallationObservationError> {
    if response.status() != StatusCode::OK {
        return Err(GithubAppInstallationObservationError::ProviderRejected);
    }
    if !response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|media_type| media_type.trim() == "application/json")
        })
    {
        return Err(GithubAppInstallationObservationError::InvalidResponse);
    }
    if response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .is_some_and(|length| length > max_response_bytes)
    {
        return Err(GithubAppInstallationObservationError::InvalidResponse);
    }

    let mut body = Vec::new();
    loop {
        let chunk = response
            .chunk()
            .await
            .map_err(|_| GithubAppInstallationObservationError::Transport)?;
        let Some(chunk) = chunk else { break };
        if chunk.len() > max_response_bytes.saturating_sub(body.len()) {
            return Err(GithubAppInstallationObservationError::InvalidResponse);
        }
        body.extend_from_slice(&chunk);
    }
    let observed: InstallationCapabilitiesResponse = serde_json::from_slice(&body)
        .map_err(|_| GithubAppInstallationObservationError::InvalidResponse)?;
    if observed.events.len() > MAX_INSTALLATION_EVENTS
        || observed.permissions.len() > MAX_INSTALLATION_PERMISSIONS
        || observed
            .events
            .iter()
            .any(|event| event.is_empty() || event.len() > 128 || !event.is_ascii())
        || observed.permissions.iter().any(|(name, level)| {
            name.is_empty()
                || name.len() > 128
                || !name.is_ascii()
                || !matches!(level.as_str(), "read" | "write")
        })
    {
        return Err(GithubAppInstallationObservationError::InvalidResponse);
    }
    if observed.id != expected_installation_id || observed.app_id == 0 {
        return Err(GithubAppInstallationObservationError::IdentityMismatch);
    }
    let events = observed.events.into_iter().collect::<BTreeSet<_>>();
    let permissions = observed
        .permissions
        .into_iter()
        .map(|(name, level)| {
            let level = match level.as_str() {
                "read" => GithubAppInstallationPermission::Read,
                "write" => GithubAppInstallationPermission::Write,
                _ => unreachable!("levels were validated above"),
            };
            (name, level)
        })
        .collect();
    Ok(GithubAppInstallationCapabilities {
        installation_id: observed.id,
        app_id: observed.app_id,
        events,
        permissions,
    })
}
