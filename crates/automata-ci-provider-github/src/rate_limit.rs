use std::time::{SystemTime, UNIX_EPOCH};

use reqwest::header::{HeaderMap, RETRY_AFTER};

pub(crate) const MAX_RETRY_AFTER_SECONDS: u64 = 86_400;
pub(crate) const MAX_RATE_LIMIT_RESET_SECONDS: u64 = 253_402_300_799;
const X_RATE_LIMIT_REMAINING: &str = "x-ratelimit-remaining";
const X_RATE_LIMIT_RESET: &str = "x-ratelimit-reset";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct GithubRateLimitHeaders {
    pub(crate) retry_after_seconds: Option<u64>,
    pub(crate) rate_limit_reset_at: Option<u64>,
    pub(crate) rate_limit_remaining_zero: bool,
}

pub(crate) fn is_rate_limited(headers: &HeaderMap) -> bool {
    headers.contains_key(RETRY_AFTER)
        || unique_header(headers, X_RATE_LIMIT_REMAINING)
            .is_some_and(|value| value.as_bytes() == b"0")
}

pub(crate) fn rate_limit_headers(headers: &HeaderMap) -> GithubRateLimitHeaders {
    let retry_after_seconds = unique_header(headers, RETRY_AFTER.as_str())
        .and_then(|value| parse_bounded_decimal(value.as_bytes(), MAX_RETRY_AFTER_SECONDS));
    let rate_limit_reset_at = unique_header(headers, X_RATE_LIMIT_RESET)
        .and_then(|value| parse_bounded_decimal(value.as_bytes(), MAX_RATE_LIMIT_RESET_SECONDS));
    let rate_limit_remaining_zero = unique_header(headers, X_RATE_LIMIT_REMAINING)
        .is_some_and(|value| value.as_bytes() == b"0");
    GithubRateLimitHeaders {
        retry_after_seconds,
        rate_limit_reset_at,
        rate_limit_remaining_zero,
    }
}

pub(crate) fn retry_delay_seconds(headers: &HeaderMap) -> Option<u64> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    retry_delay_seconds_at(headers, now)
}

fn retry_delay_seconds_at(headers: &HeaderMap, now: u64) -> Option<u64> {
    let evidence = rate_limit_headers(headers);
    if let Some(retry_after_seconds) = evidence.retry_after_seconds {
        return Some(retry_after_seconds);
    }
    if !evidence.rate_limit_remaining_zero {
        return None;
    }
    evidence
        .rate_limit_reset_at?
        .checked_sub(now)?
        .checked_add(1)
        .filter(|delay| *delay <= MAX_RETRY_AFTER_SECONDS)
}

fn unique_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Option<&'a reqwest::header::HeaderValue> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    values.next().is_none().then_some(first)
}

fn parse_bounded_decimal(bytes: &[u8], maximum: u64) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 15 || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let raw = std::str::from_utf8(bytes).ok()?;
    let value = raw.parse::<u64>().ok()?;
    (value <= maximum && value.to_string() == raw).then_some(value)
}

#[cfg(test)]
mod tests {
    use reqwest::header::{HeaderMap, HeaderValue};

    use super::{
        GithubRateLimitHeaders, is_rate_limited, rate_limit_headers, retry_delay_seconds_at,
    };

    #[test]
    fn primary_limit_reset_becomes_a_relative_delay_with_boundary_margin() {
        let mut headers = HeaderMap::new();
        headers.insert("x-ratelimit-remaining", HeaderValue::from_static("0"));
        headers.insert("x-ratelimit-reset", HeaderValue::from_static("230"));

        assert!(is_rate_limited(&headers));
        assert_eq!(retry_delay_seconds_at(&headers, 200), Some(31));
    }

    #[test]
    fn retry_after_takes_precedence_over_primary_limit_reset() {
        let mut headers = HeaderMap::new();
        headers.insert("retry-after", HeaderValue::from_static("17"));
        headers.insert("x-ratelimit-remaining", HeaderValue::from_static("0"));
        headers.insert("x-ratelimit-reset", HeaderValue::from_static("230"));

        assert_eq!(retry_delay_seconds_at(&headers, 200), Some(17));
    }

    #[test]
    fn malformed_duplicate_and_stale_evidence_is_not_trusted() {
        let mut malformed = HeaderMap::new();
        malformed.insert("retry-after", HeaderValue::from_static("017"));
        malformed.insert("x-ratelimit-remaining", HeaderValue::from_static("0"));
        malformed.insert("x-ratelimit-reset", HeaderValue::from_static("199"));
        assert_eq!(retry_delay_seconds_at(&malformed, 200), None);

        let mut duplicate = HeaderMap::new();
        duplicate.append("retry-after", HeaderValue::from_static("17"));
        duplicate.append("retry-after", HeaderValue::from_static("18"));
        assert_eq!(
            rate_limit_headers(&duplicate),
            GithubRateLimitHeaders::default()
        );
    }
}
