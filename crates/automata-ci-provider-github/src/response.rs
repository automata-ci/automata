use automata_ci_auth::github::GithubEndpointError;
use reqwest::{
    Response, StatusCode,
    header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderMap},
};
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use crate::rate_limit::{is_rate_limited, retry_delay_seconds};

pub(crate) struct JsonResponse {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Zeroizing<Vec<u8>>,
}

pub(crate) async fn read_json_response(
    mut response: Response,
    max_response_bytes: usize,
    permit_oauth_bad_request: bool,
) -> Result<JsonResponse, GithubEndpointError> {
    let status = response.status();
    if !(status.is_success() || (permit_oauth_bad_request && status == StatusCode::BAD_REQUEST)) {
        return Err(map_status(status, response.headers()));
    }
    validate_content_type(response.headers())?;
    if content_length_exceeds(response.headers(), max_response_bytes)? {
        return Err(GithubEndpointError::InvalidResponse);
    }

    let headers = response.headers().clone();
    let mut body = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| GithubEndpointError::Unavailable)?
    {
        let next_length = body
            .len()
            .checked_add(chunk.len())
            .ok_or(GithubEndpointError::InvalidResponse)?;
        if next_length > max_response_bytes {
            return Err(GithubEndpointError::InvalidResponse);
        }
        body.extend_from_slice(&chunk);
    }
    if body.is_empty() {
        return Err(GithubEndpointError::InvalidResponse);
    }
    Ok(JsonResponse {
        status,
        headers,
        body,
    })
}

pub(crate) fn decode_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, GithubEndpointError> {
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let decoded =
        T::deserialize(&mut deserializer).map_err(|_| GithubEndpointError::InvalidResponse)?;
    deserializer
        .end()
        .map_err(|_| GithubEndpointError::InvalidResponse)?;
    Ok(decoded)
}

fn content_length_exceeds(
    headers: &HeaderMap,
    maximum: usize,
) -> Result<bool, GithubEndpointError> {
    let values = headers.get_all(CONTENT_LENGTH);
    let mut values = values.iter();
    let Some(value) = values.next() else {
        return Ok(false);
    };
    if values.next().is_some() {
        return Err(GithubEndpointError::InvalidResponse);
    }
    let value = value
        .to_str()
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .ok_or(GithubEndpointError::InvalidResponse)?;
    Ok(value > maximum)
}

fn validate_content_type(headers: &HeaderMap) -> Result<(), GithubEndpointError> {
    let values = headers.get_all(CONTENT_TYPE);
    let mut values = values.iter();
    let value = values.next().ok_or(GithubEndpointError::InvalidResponse)?;
    if values.next().is_some() {
        return Err(GithubEndpointError::InvalidResponse);
    }
    let raw = value
        .to_str()
        .map_err(|_| GithubEndpointError::InvalidResponse)?;
    let mut parts = raw.split(';');
    let media_type = parts
        .next()
        .map(str::trim)
        .ok_or(GithubEndpointError::InvalidResponse)?;
    let is_json = media_type.eq_ignore_ascii_case("application/json")
        || (media_type.len() > "application/+json".len()
            && media_type
                .get(.."application/".len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("application/"))
            && media_type
                .get(media_type.len() - "+json".len()..)
                .is_some_and(|suffix| suffix.eq_ignore_ascii_case("+json")));
    if !is_json {
        return Err(GithubEndpointError::InvalidResponse);
    }

    let mut saw_charset = false;
    for parameter in parts {
        let (name, value) = parameter
            .split_once('=')
            .ok_or(GithubEndpointError::InvalidResponse)?;
        let value = parse_charset_value(value.trim())?;
        if saw_charset
            || !name.trim().eq_ignore_ascii_case("charset")
            || !value.eq_ignore_ascii_case("utf-8")
        {
            return Err(GithubEndpointError::InvalidResponse);
        }
        saw_charset = true;
    }
    Ok(())
}

fn parse_charset_value(value: &str) -> Result<&str, GithubEndpointError> {
    if let Some(quoted) = value.strip_prefix('"') {
        let quoted = quoted
            .strip_suffix('"')
            .ok_or(GithubEndpointError::InvalidResponse)?;
        if quoted.contains('"') || quoted.contains('\\') {
            return Err(GithubEndpointError::InvalidResponse);
        }
        return Ok(quoted);
    }
    if value.is_empty() || value.contains('"') {
        return Err(GithubEndpointError::InvalidResponse);
    }
    Ok(value)
}

fn map_status(status: StatusCode, headers: &HeaderMap) -> GithubEndpointError {
    if status == StatusCode::REQUEST_TIMEOUT || status.is_server_error() {
        return GithubEndpointError::Unavailable;
    }
    match status {
        StatusCode::UNAUTHORIZED => GithubEndpointError::Unauthorized,
        StatusCode::FORBIDDEN if is_rate_limited(headers) => GithubEndpointError::RateLimited {
            retry_after_seconds: retry_delay_seconds(headers),
        },
        StatusCode::FORBIDDEN => GithubEndpointError::Forbidden,
        StatusCode::TOO_MANY_REQUESTS => GithubEndpointError::RateLimited {
            retry_after_seconds: retry_delay_seconds(headers),
        },
        _ => GithubEndpointError::InvalidResponse,
    }
}
