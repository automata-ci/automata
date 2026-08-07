use std::{collections::BTreeMap, fmt};

use automata_auth::secret::SecretString;
use automata_credential::{PermissionLevel, PermissionName, PermissionSet};
use reqwest::{
    Response, StatusCode,
    header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderMap, RETRY_AFTER},
};
use serde::{Deserialize, Deserializer, de::MapAccess, de::Visitor};
use zeroize::Zeroizing;

use automata_credential::{CredentialError, CredentialErrorKind};

const X_RATE_LIMIT_REMAINING: &str = "x-ratelimit-remaining";
const MAX_RETRY_AFTER_SECONDS: u64 = 86_400;
const MAX_RESPONSE_PERMISSIONS: usize = 64;

#[derive(Deserialize)]
pub(crate) struct InstallationTokenResponse {
    pub(crate) token: SecretString,
    pub(crate) expires_at: String,
    pub(crate) permissions: ResponsePermissions,
    pub(crate) repository_selection: String,
    pub(crate) repositories: Vec<ResponseRepository>,
}

#[derive(Deserialize)]
pub(crate) struct ResponseRepository {
    pub(crate) id: u64,
    pub(crate) full_name: String,
}

pub(crate) struct ResponsePermissions(PermissionSet);

impl ResponsePermissions {
    pub(crate) fn into_inner(self) -> PermissionSet {
        self.0
    }
}

impl<'de> Deserialize<'de> for ResponsePermissions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(PermissionVisitor)
    }
}

struct PermissionVisitor;

impl<'de> Visitor<'de> for PermissionVisitor {
    type Value = ResponsePermissions;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded, duplicate-free GitHub permission map")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut permissions = BTreeMap::new();
        while let Some((raw_name, raw_level)) = map.next_entry::<String, String>()? {
            if permissions.len() >= MAX_RESPONSE_PERMISSIONS {
                return Err(serde::de::Error::custom("too many permissions"));
            }
            let name = PermissionName::new(raw_name)
                .map_err(|_| serde::de::Error::custom("invalid permission name"))?;
            let level = PermissionLevel::parse(&raw_level)
                .map_err(|_| serde::de::Error::custom("invalid permission level"))?;
            if permissions.insert(name, level).is_some() {
                return Err(serde::de::Error::custom("duplicate permission"));
            }
        }
        PermissionSet::new(permissions)
            .map(ResponsePermissions)
            .map_err(|_| serde::de::Error::custom("invalid permission set"))
    }
}

pub(crate) async fn require_created_and_read(
    mut response: Response,
    max_response_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, CredentialError> {
    if response.status() != StatusCode::CREATED {
        return Err(map_status(response.status(), response.headers()));
    }
    validate_content_type(response.headers())?;
    if content_length_exceeds(response.headers(), max_response_bytes)? {
        return Err(CredentialError::new(CredentialErrorKind::InvalidResponse));
    }
    let mut body = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| CredentialError::new(CredentialErrorKind::Unavailable))?
    {
        let next_length = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| CredentialError::new(CredentialErrorKind::InvalidResponse))?;
        if next_length > max_response_bytes {
            return Err(CredentialError::new(CredentialErrorKind::InvalidResponse));
        }
        body.extend_from_slice(&chunk);
    }
    if body.is_empty() {
        return Err(CredentialError::new(CredentialErrorKind::InvalidResponse));
    }
    Ok(body)
}

pub(crate) fn decode_token_response(
    body: &[u8],
) -> Result<InstallationTokenResponse, CredentialError> {
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let decoded = InstallationTokenResponse::deserialize(&mut deserializer)
        .map_err(|_| CredentialError::new(CredentialErrorKind::InvalidResponse))?;
    deserializer
        .end()
        .map_err(|_| CredentialError::new(CredentialErrorKind::InvalidResponse))?;
    Ok(decoded)
}

fn content_length_exceeds(headers: &HeaderMap, maximum: usize) -> Result<bool, CredentialError> {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return Ok(false);
    };
    if values.next().is_some() {
        return Err(CredentialError::new(CredentialErrorKind::InvalidResponse));
    }
    let length = value
        .to_str()
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .ok_or_else(|| CredentialError::new(CredentialErrorKind::InvalidResponse))?;
    Ok(length > maximum)
}

fn validate_content_type(headers: &HeaderMap) -> Result<(), CredentialError> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let value = values
        .next()
        .ok_or_else(|| CredentialError::new(CredentialErrorKind::InvalidResponse))?;
    if values.next().is_some() {
        return Err(CredentialError::new(CredentialErrorKind::InvalidResponse));
    }
    let raw = value
        .to_str()
        .map_err(|_| CredentialError::new(CredentialErrorKind::InvalidResponse))?;
    let mut parts = raw.split(';');
    let media_type = parts.next().unwrap_or_default().trim();
    let json = media_type.eq_ignore_ascii_case("application/json")
        || (media_type.len() > "application/+json".len()
            && media_type
                .get(.."application/".len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("application/"))
            && media_type
                .get(media_type.len() - "+json".len()..)
                .is_some_and(|suffix| suffix.eq_ignore_ascii_case("+json")));
    if !json {
        return Err(CredentialError::new(CredentialErrorKind::InvalidResponse));
    }
    let mut saw_charset = false;
    for parameter in parts {
        let (name, value) = parameter
            .split_once('=')
            .ok_or_else(|| CredentialError::new(CredentialErrorKind::InvalidResponse))?;
        let value = parse_charset_value(value.trim())?;
        if saw_charset
            || !name.trim().eq_ignore_ascii_case("charset")
            || !value.eq_ignore_ascii_case("utf-8")
        {
            return Err(CredentialError::new(CredentialErrorKind::InvalidResponse));
        }
        saw_charset = true;
    }
    Ok(())
}

fn parse_charset_value(value: &str) -> Result<&str, CredentialError> {
    if let Some(quoted) = value.strip_prefix('"') {
        let quoted = quoted
            .strip_suffix('"')
            .ok_or_else(|| CredentialError::new(CredentialErrorKind::InvalidResponse))?;
        if quoted.contains('"') || quoted.contains('\\') {
            return Err(CredentialError::new(CredentialErrorKind::InvalidResponse));
        }
        return Ok(quoted);
    }
    if value.is_empty() || value.contains('"') {
        return Err(CredentialError::new(CredentialErrorKind::InvalidResponse));
    }
    Ok(value)
}

fn map_status(status: StatusCode, headers: &HeaderMap) -> CredentialError {
    match status {
        StatusCode::UNAUTHORIZED => CredentialError::new(CredentialErrorKind::Unauthorized),
        StatusCode::FORBIDDEN if is_rate_limited(headers) => {
            CredentialError::rate_limited(retry_after_seconds(headers))
        }
        StatusCode::FORBIDDEN => CredentialError::new(CredentialErrorKind::Forbidden),
        StatusCode::NOT_FOUND => CredentialError::new(CredentialErrorKind::NotFound),
        StatusCode::TOO_MANY_REQUESTS => {
            CredentialError::rate_limited(retry_after_seconds(headers))
        }
        StatusCode::UNPROCESSABLE_ENTITY => {
            CredentialError::new(CredentialErrorKind::InvalidRequest)
        }
        StatusCode::REQUEST_TIMEOUT => CredentialError::new(CredentialErrorKind::Unavailable),
        _ if status.is_server_error() => CredentialError::new(CredentialErrorKind::Unavailable),
        _ => CredentialError::new(CredentialErrorKind::InvalidResponse),
    }
}

fn is_rate_limited(headers: &HeaderMap) -> bool {
    headers.contains_key(RETRY_AFTER)
        || headers
            .get(X_RATE_LIMIT_REMAINING)
            .is_some_and(|value| value.as_bytes() == b"0")
}

fn retry_after_seconds(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| *seconds <= MAX_RETRY_AFTER_SECONDS)
}
