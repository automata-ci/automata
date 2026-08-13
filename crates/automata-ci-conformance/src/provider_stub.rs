use std::{collections::VecDeque, sync::Mutex};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Exact request expected by the hermetic GitHub HTTP stub.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GithubStubRequest {
    pub method: String,
    pub path_and_query: String,
    pub body_sha256: Option<String>,
    pub credential_id: Option<String>,
}

/// Provider mutation certainty retained by a scripted response.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubMutationOutcome {
    NotApplied,
    Applied,
    Indeterminate,
}

/// Closed response classes needed by deterministic provider-failure scenarios.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GithubStubResponse {
    Page {
        status: u16,
        body: Vec<u8>,
        next: Option<String>,
    },
    RateLimited {
        retry_after_millis: u64,
    },
    CredentialFailure {
        status: u16,
    },
    Mutation {
        status: u16,
        outcome: GithubMutationOutcome,
        body: Vec<u8>,
    },
}

/// One ordered request/response exchange.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GithubStubExchange {
    pub request: GithubStubRequest,
    pub response: GithubStubResponse,
}

/// Fail-closed exact-order script consumed by a hermetic HTTP adapter.
#[derive(Debug)]
pub struct GithubStubScript(Mutex<VecDeque<GithubStubExchange>>);

impl GithubStubScript {
    /// Validates and constructs an exact provider script.
    ///
    /// # Errors
    ///
    /// Rejects an empty/unbounded script or malformed HTTP coordinates.
    pub fn new(exchanges: Vec<GithubStubExchange>) -> Result<Self, GithubStubError> {
        if exchanges.is_empty() || exchanges.len() > 4_096 {
            return Err(GithubStubError::InvalidScriptSize);
        }
        for exchange in &exchanges {
            validate_request(&exchange.request)?;
            validate_response(&exchange.response)?;
        }
        Ok(Self(Mutex::new(exchanges.into())))
    }

    /// Consumes the next response only when the observed request is exact.
    ///
    /// # Errors
    ///
    /// Rejects extra, reordered, or mutated requests.
    pub fn respond(
        &self,
        request: &GithubStubRequest,
    ) -> Result<GithubStubResponse, GithubStubError> {
        let mut exchanges = self.0.lock().map_err(|_| GithubStubError::Poisoned)?;
        let expected = exchanges
            .front()
            .ok_or(GithubStubError::UnexpectedRequest)?;
        if &expected.request != request {
            return Err(GithubStubError::RequestMismatch);
        }
        exchanges
            .pop_front()
            .map(|exchange| exchange.response)
            .ok_or(GithubStubError::UnexpectedRequest)
    }

    /// Fails when the product did not make every expected request.
    ///
    /// # Errors
    ///
    /// Returns an error when an expected exchange remains.
    pub fn finish(&self) -> Result<(), GithubStubError> {
        if self
            .0
            .lock()
            .map_err(|_| GithubStubError::Poisoned)?
            .is_empty()
        {
            Ok(())
        } else {
            Err(GithubStubError::UnconsumedExchange)
        }
    }
}

fn validate_request(value: &GithubStubRequest) -> Result<(), GithubStubError> {
    if !matches!(
        value.method.as_str(),
        "GET" | "POST" | "PATCH" | "PUT" | "DELETE"
    ) || !value.path_and_query.starts_with('/')
        || value.path_and_query.len() > 8_192
        || value.path_and_query.chars().any(char::is_control)
    {
        return Err(GithubStubError::InvalidRequest);
    }
    if let Some(digest) = &value.body_sha256
        && (digest.len() != 64 || !lower_hex(digest))
    {
        return Err(GithubStubError::InvalidRequest);
    }
    if value.credential_id.as_ref().is_some_and(|identity| {
        identity.is_empty()
            || identity.len() > 256
            || identity.trim() != identity
            || identity.chars().any(char::is_control)
    }) {
        return Err(GithubStubError::InvalidRequest);
    }
    Ok(())
}

fn validate_response(value: &GithubStubResponse) -> Result<(), GithubStubError> {
    match value {
        GithubStubResponse::Page { status, body, next } => {
            if !(200..300).contains(status)
                || body.len() > 16 * 1_048_576
                || next.as_ref().is_some_and(|next| {
                    !next.starts_with('/')
                        || next.len() > 8_192
                        || next.chars().any(char::is_control)
                })
            {
                return Err(GithubStubError::InvalidResponse);
            }
        }
        GithubStubResponse::RateLimited { retry_after_millis } => {
            if *retry_after_millis == 0 {
                return Err(GithubStubError::InvalidResponse);
            }
        }
        GithubStubResponse::CredentialFailure { status } => {
            if !matches!(status, 401 | 403) {
                return Err(GithubStubError::InvalidResponse);
            }
        }
        GithubStubResponse::Mutation { status, body, .. } => {
            if !(200..600).contains(status) || body.len() > 16 * 1_048_576 {
                return Err(GithubStubError::InvalidResponse);
            }
        }
    }
    Ok(())
}

fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubStubError {
    #[error("GitHub stub script size is invalid")]
    InvalidScriptSize,
    #[error("GitHub stub request is invalid")]
    InvalidRequest,
    #[error("GitHub stub response is invalid")]
    InvalidResponse,
    #[error("GitHub stub observed an unexpected extra request")]
    UnexpectedRequest,
    #[error("GitHub stub request does not match the next exact exchange")]
    RequestMismatch,
    #[error("GitHub stub has an expected exchange that was not consumed")]
    UnconsumedExchange,
    #[error("GitHub stub lock was poisoned")]
    Poisoned,
}
