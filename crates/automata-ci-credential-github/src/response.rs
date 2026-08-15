use std::{collections::BTreeMap, fmt, ops::Range};

use automata_ci_auth::secret::SecretString;
use automata_ci_scm::credential::{
    CredentialError, CredentialErrorKind, PermissionLevel, PermissionName, PermissionSet,
};
use reqwest::{
    Response, StatusCode,
    header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderMap, RETRY_AFTER},
};
use serde::{Deserialize, Deserializer, de::IgnoredAny, de::MapAccess, de::Visitor};
use zeroize::Zeroizing;

const X_RATE_LIMIT_REMAINING: &str = "x-ratelimit-remaining";
const MAX_RETRY_AFTER_SECONDS: u64 = 86_400;
const MAX_RESPONSE_PERMISSIONS: usize = 64;
const MAX_TOKEN_BYTES: usize = 16 * 1_024;

#[derive(Deserialize)]
pub(crate) struct InstallationTokenResponse {
    #[serde(rename = "token")]
    _token: IgnoredAny,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreatedBodyCompletion {
    Complete,
    Truncated,
    TooLarge,
}

pub(crate) struct CreatedResponseBody {
    pub(crate) body: Zeroizing<Vec<u8>>,
    pub(crate) completion: CreatedBodyCompletion,
    pub(crate) metadata_valid: bool,
}

pub(crate) async fn read_created_response(
    mut response: Response,
    max_response_bytes: usize,
) -> CreatedResponseBody {
    let content_length = content_length(response.headers());
    let metadata_valid = validate_content_type(response.headers()) && content_length.is_ok();
    if matches!(content_length, Ok(Some(length)) if length > max_response_bytes) {
        return CreatedResponseBody {
            body: Zeroizing::new(Vec::new()),
            completion: CreatedBodyCompletion::TooLarge,
            metadata_valid,
        };
    }

    let mut body = Zeroizing::new(Vec::new());
    loop {
        let chunk = match response.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => {
                return CreatedResponseBody {
                    body,
                    completion: CreatedBodyCompletion::Complete,
                    metadata_valid,
                };
            }
            Err(_) => {
                return CreatedResponseBody {
                    body,
                    completion: CreatedBodyCompletion::Truncated,
                    metadata_valid,
                };
            }
        };
        let remaining = max_response_bytes.saturating_sub(body.len());
        if chunk.len() > remaining {
            body.extend_from_slice(&chunk[..remaining]);
            return CreatedResponseBody {
                body,
                completion: CreatedBodyCompletion::TooLarge,
                metadata_valid,
            };
        }
        body.extend_from_slice(&chunk);
    }
}

pub(crate) enum RecoveredInstallationToken {
    Unique(SecretString),
    Missing,
    Unrecoverable,
    Ambiguous,
}

pub(crate) fn recover_installation_token(body: &[u8]) -> RecoveredInstallationToken {
    match recover_top_level_string(body, "token") {
        RecoveredTopLevelString::Unique(range) => recover_token_string(&body[range])
            .map_or(RecoveredInstallationToken::Unrecoverable, |secret| {
                RecoveredInstallationToken::Unique(secret)
            }),
        RecoveredTopLevelString::Missing => RecoveredInstallationToken::Missing,
        RecoveredTopLevelString::Unrecoverable => RecoveredInstallationToken::Unrecoverable,
        RecoveredTopLevelString::Ambiguous => RecoveredInstallationToken::Ambiguous,
    }
}

pub(crate) fn recover_expiration(body: &[u8]) -> Option<String> {
    let RecoveredTopLevelString::Unique(range) = recover_top_level_string(body, "expires_at")
    else {
        return None;
    };
    serde_json::from_slice(&body[range]).ok()
}

enum RecoveredTopLevelString {
    Unique(Range<usize>),
    Missing,
    Unrecoverable,
    Ambiguous,
}

fn recover_top_level_string(body: &[u8], field: &str) -> RecoveredTopLevelString {
    let mut cursor = skip_whitespace(body, 0);
    if body.get(cursor) != Some(&b'{') {
        return RecoveredTopLevelString::Missing;
    }
    cursor += 1;
    let mut matching_fields = 0_usize;
    let mut recovered = None;

    loop {
        cursor = skip_whitespace(body, cursor);
        if body.get(cursor) != Some(&b'"') {
            break;
        }
        let Some(key_end) = scan_json_string(body, cursor) else {
            break;
        };
        let key = serde_json::from_slice::<String>(&body[cursor..key_end]);
        cursor = skip_whitespace(body, key_end);
        if body.get(cursor) != Some(&b':') {
            break;
        }
        cursor = skip_whitespace(body, cursor + 1);

        if matches!(key.as_deref(), Ok(key) if key == field) {
            matching_fields = matching_fields.saturating_add(1);
            if matching_fields > 1 {
                return RecoveredTopLevelString::Ambiguous;
            }
            if body.get(cursor) == Some(&b'"') {
                let Some(value_end) = scan_json_string(body, cursor) else {
                    break;
                };
                recovered = Some(cursor..value_end);
                cursor = value_end;
            } else {
                let Some(value_end) = skip_json_value(body, cursor) else {
                    break;
                };
                cursor = value_end;
            }
        } else {
            let Some(value_end) = skip_json_value(body, cursor) else {
                break;
            };
            cursor = value_end;
        }

        cursor = skip_whitespace(body, cursor);
        if body.get(cursor) == Some(&b',') {
            cursor += 1;
        } else {
            break;
        }
    }

    match (matching_fields, recovered) {
        (0, _) => RecoveredTopLevelString::Missing,
        (1, Some(range)) => RecoveredTopLevelString::Unique(range),
        (1, None) => RecoveredTopLevelString::Unrecoverable,
        _ => RecoveredTopLevelString::Ambiguous,
    }
}

fn recover_token_string(encoded: &[u8]) -> Option<SecretString> {
    let mut token = Zeroizing::new(serde_json::from_slice::<String>(encoded).ok()?);
    if token.len() > MAX_TOKEN_BYTES || !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return None;
    }
    SecretString::new(std::mem::take(&mut *token)).ok()
}

fn scan_json_string(input: &[u8], start: usize) -> Option<usize> {
    if input.get(start) != Some(&b'"') {
        return None;
    }
    let mut cursor = start + 1;
    while let Some(byte) = input.get(cursor).copied() {
        match byte {
            b'"' => return Some(cursor + 1),
            b'\\' => {
                cursor += 1;
                let escaped = input.get(cursor).copied()?;
                if escaped == b'u' {
                    let digits = input.get(cursor + 1..cursor + 5)?;
                    if !digits.iter().all(u8::is_ascii_hexdigit) {
                        return None;
                    }
                    cursor += 4;
                } else if !matches!(
                    escaped,
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't'
                ) {
                    return None;
                }
            }
            0x00..=0x1f => return None,
            _ => {}
        }
        cursor += 1;
    }
    None
}

fn skip_json_value(input: &[u8], start: usize) -> Option<usize> {
    let cursor = skip_whitespace(input, start);
    match input.get(cursor).copied()? {
        b'"' => scan_json_string(input, cursor),
        b'{' => skip_json_container(input, cursor, b'}'),
        b'[' => skip_json_container(input, cursor, b']'),
        _ => skip_json_primitive(input, cursor),
    }
}

fn skip_json_container(input: &[u8], start: usize, closing: u8) -> Option<usize> {
    let mut expected = vec![closing];
    let mut cursor = start + 1;
    while let Some(byte) = input.get(cursor).copied() {
        match byte {
            b'"' => cursor = scan_json_string(input, cursor)?,
            b'{' => {
                expected.push(b'}');
                cursor += 1;
            }
            b'[' => {
                expected.push(b']');
                cursor += 1;
            }
            b'}' | b']' => {
                if expected.pop() != Some(byte) {
                    return None;
                }
                cursor += 1;
                if expected.is_empty() {
                    return Some(cursor);
                }
            }
            _ => cursor += 1,
        }
    }
    None
}

fn skip_json_primitive(input: &[u8], start: usize) -> Option<usize> {
    let mut end = start;
    while let Some(byte) = input.get(end) {
        if byte.is_ascii_whitespace() || matches!(byte, b',' | b'}' | b']') {
            break;
        }
        end += 1;
    }
    if end == start || serde_json::from_slice::<IgnoredAny>(&input[start..end]).is_err() {
        return None;
    }
    Some(end)
}

fn skip_whitespace(input: &[u8], mut cursor: usize) -> usize {
    while let Some(byte) = input.get(cursor) {
        if !byte.is_ascii_whitespace() {
            break;
        }
        cursor += 1;
    }
    cursor
}

pub(crate) fn decode_token_response(
    body: &[u8],
) -> Result<InstallationTokenResponse, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let decoded = InstallationTokenResponse::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(decoded)
}

pub(crate) fn definitive_mint_rejection(
    status: StatusCode,
    headers: &HeaderMap,
) -> Option<CredentialError> {
    let error = match status {
        StatusCode::UNAUTHORIZED => CredentialError::new(CredentialErrorKind::Unauthorized),
        StatusCode::FORBIDDEN if is_rate_limited(headers) => {
            CredentialError::rate_limited(retry_after_seconds(headers))
        }
        StatusCode::FORBIDDEN => CredentialError::new(CredentialErrorKind::Forbidden),
        StatusCode::NOT_FOUND => CredentialError::new(CredentialErrorKind::NotFound),
        StatusCode::TOO_MANY_REQUESTS => {
            CredentialError::rate_limited(retry_after_seconds(headers))
        }
        StatusCode::UNPROCESSABLE_ENTITY | StatusCode::BAD_REQUEST => {
            CredentialError::new(CredentialErrorKind::InvalidRequest)
        }
        StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_EARLY => return None,
        _ if status.is_client_error() => CredentialError::new(CredentialErrorKind::InvalidResponse),
        _ => return None,
    };
    Some(error)
}

pub(crate) fn is_rate_limited(headers: &HeaderMap) -> bool {
    headers.contains_key(RETRY_AFTER)
        || headers
            .get(X_RATE_LIMIT_REMAINING)
            .is_some_and(|value| value.as_bytes() == b"0")
}

pub(crate) fn retry_after_seconds(headers: &HeaderMap) -> Option<u64> {
    let mut values = headers.get_all(RETRY_AFTER).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| *seconds <= MAX_RETRY_AFTER_SECONDS)
}

fn content_length(headers: &HeaderMap) -> Result<Option<usize>, ()> {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    value
        .to_str()
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .map(Some)
        .ok_or(())
}

fn validate_content_type(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    let Ok(raw) = value.to_str() else {
        return false;
    };
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
        return false;
    }
    let mut saw_charset = false;
    for parameter in parts {
        let Some((name, value)) = parameter.split_once('=') else {
            return false;
        };
        let Some(value) = parse_charset_value(value.trim()) else {
            return false;
        };
        if saw_charset
            || !name.trim().eq_ignore_ascii_case("charset")
            || !value.eq_ignore_ascii_case("utf-8")
        {
            return false;
        }
        saw_charset = true;
    }
    true
}

fn parse_charset_value(value: &str) -> Option<&str> {
    if let Some(quoted) = value.strip_prefix('"') {
        let quoted = quoted.strip_suffix('"')?;
        if quoted.contains('"') || quoted.contains('\\') {
            return None;
        }
        return Some(quoted);
    }
    if value.is_empty() || value.contains('"') {
        return None;
    }
    Some(value)
}
