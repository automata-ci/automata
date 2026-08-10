use std::{
    borrow::Cow,
    fmt,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{
        HeaderMap, HeaderValue, Method, Request, StatusCode,
        header::{
            ACCEPT, ALLOW, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING,
            X_CONTENT_TYPE_OPTIONS,
        },
    },
    response::{IntoResponse, Response},
    routing::any,
};
use prometheus_client::{
    encoding::{prometheus_protobuf, text::encode},
    registry::Registry,
};
use prost::Message as _;
use thiserror::Error;
use tokio::{sync::Semaphore, task::JoinError, time::timeout};

use crate::common::{CommonMetrics, ScrapeOutcome};

/// Exact content type emitted for successful `OpenMetrics` 1.0 responses.
pub const OPENMETRICS_CONTENT_TYPE: &str =
    "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=underscores";

/// Exact content type emitted for successful Prometheus protobuf responses.
pub const PROMETHEUS_PROTOBUF_CONTENT_TYPE: &str = concat!(
    "application/vnd.google.protobuf; ",
    "proto=io.prometheus.client.MetricFamily; encoding=delimited",
);

const OPENMETRICS_CONTENT_TYPE_ALLOW_UTF8: &str =
    "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=allow-utf-8";

const CACHE_CONTROL_NO_STORE: HeaderValue = HeaderValue::from_static("no-store");
const ALLOW_GET: HeaderValue = HeaderValue::from_static("GET");
const NOSNIFF: HeaderValue = HeaderValue::from_static("nosniff");
const TEXT_CONTENT_TYPE: HeaderValue = HeaderValue::from_static("text/plain; charset=utf-8");
const MAX_CONFIGURED_CONCURRENCY: usize = 16;
const MAX_CONFIGURED_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONFIGURED_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Validated resource limits for one metrics endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExporterLimits {
    max_concurrent_scrapes: NonZeroUsize,
    scrape_timeout: Duration,
    max_response_bytes: NonZeroUsize,
}

impl ExporterLimits {
    /// Creates limits within the foundation's hard safety ceilings.
    ///
    /// # Errors
    ///
    /// Returns an error when concurrency exceeds 16, timeout is zero or above
    /// 30 seconds, or the response ceiling is above 16 MiB.
    pub fn try_new(
        max_concurrent_scrapes: NonZeroUsize,
        scrape_timeout: Duration,
        max_response_bytes: NonZeroUsize,
    ) -> Result<Self, ExporterLimitsError> {
        if max_concurrent_scrapes.get() > MAX_CONFIGURED_CONCURRENCY {
            return Err(ExporterLimitsError::Concurrency);
        }
        if scrape_timeout.is_zero() || scrape_timeout > MAX_CONFIGURED_TIMEOUT {
            return Err(ExporterLimitsError::Timeout);
        }
        if max_response_bytes.get() > MAX_CONFIGURED_RESPONSE_BYTES {
            return Err(ExporterLimitsError::ResponseSize);
        }

        Ok(Self {
            max_concurrent_scrapes,
            scrape_timeout,
            max_response_bytes,
        })
    }

    /// Maximum number of simultaneous encodings.
    #[must_use]
    pub const fn max_concurrent_scrapes(self) -> NonZeroUsize {
        self.max_concurrent_scrapes
    }

    /// Maximum time the HTTP request waits for one encoding.
    #[must_use]
    pub const fn scrape_timeout(self) -> Duration {
        self.scrape_timeout
    }

    /// Maximum completely encoded response size.
    #[must_use]
    pub const fn max_response_bytes(self) -> NonZeroUsize {
        self.max_response_bytes
    }
}

impl Default for ExporterLimits {
    fn default() -> Self {
        Self {
            max_concurrent_scrapes: NonZeroUsize::new(2).expect("two is non-zero"),
            scrape_timeout: Duration::from_secs(5),
            max_response_bytes: NonZeroUsize::new(2 * 1024 * 1024)
                .expect("two mebibytes is non-zero"),
        }
    }
}

/// Exporter limit validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ExporterLimitsError {
    /// Concurrent scrape count exceeds the hard bound.
    #[error("metrics scrape concurrency exceeds the hard safety ceiling")]
    Concurrency,
    /// Timeout is zero or exceeds the hard bound.
    #[error("metrics scrape timeout is outside the hard safety bounds")]
    Timeout,
    /// Response limit exceeds the hard bound.
    #[error("metrics response limit exceeds the hard safety ceiling")]
    ResponseSize,
}

/// A complete bounded `OpenMetrics` 1.0 text exposition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedMetrics(String);

impl EncodedMetrics {
    /// Complete `OpenMetrics` text including the terminal EOF marker.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Encoded byte length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the exposition is empty. A valid exposition is never empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consumes the exposition into its UTF-8 bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0.into_bytes()
    }
}

#[derive(Debug)]
struct EncodedExposition {
    body: Vec<u8>,
    representation: Representation,
}

impl EncodedExposition {
    fn len(&self) -> usize {
        self.body.len()
    }
}

/// Complete exposition encoding failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EncodeError {
    /// The registry exceeded the configured complete-response limit.
    #[error("metrics exposition exceeds the configured response limit")]
    TooLarge,
    /// The registry could not be encoded.
    #[error("metrics exposition could not be encoded")]
    Encoding,
}

/// Immutable cloneable registry and bounded HTTP exporter.
#[derive(Clone, Debug)]
pub struct Metrics {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    registry: Registry,
    common: CommonMetrics,
    limits: ExporterLimits,
    semaphore: Arc<Semaphore>,
}

impl Metrics {
    pub(crate) fn new(registry: Registry, common: CommonMetrics, limits: ExporterLimits) -> Self {
        Self {
            inner: Arc::new(Inner {
                registry,
                common,
                limits,
                semaphore: Arc::new(Semaphore::new(limits.max_concurrent_scrapes.get())),
            }),
        }
    }

    /// Returns a router exposing only the fixed `/metrics` operation.
    pub fn router(&self) -> Router {
        Router::new()
            .route("/metrics", any(metrics_request))
            .fallback(unknown_metrics_path)
            .with_state(self.clone())
    }

    /// Encodes a complete bounded `OpenMetrics` 1.0 exposition synchronously.
    ///
    /// This utility enforces the response-size bound but intentionally does
    /// not acquire the HTTP concurrency permit or apply the HTTP wait timeout.
    /// Product listeners should serve [`Self::router`] rather than calling this
    /// method in an async request task.
    ///
    /// # Errors
    ///
    /// Returns an error when encoding fails or exceeds the response limit.
    pub fn encode_openmetrics(&self) -> Result<EncodedMetrics, EncodeError> {
        encode_bounded(
            &self.inner.registry,
            self.inner.limits.max_response_bytes.get(),
        )
    }

    /// Configured exporter limits.
    #[must_use]
    pub fn limits(&self) -> ExporterLimits {
        self.inner.limits
    }
}

async fn metrics_request(State(metrics): State<Metrics>, request: Request<Body>) -> Response {
    let started = Instant::now();

    if request.method() != Method::GET {
        metrics.inner.common.record(
            ScrapeOutcome::MethodNotAllowed,
            started.elapsed().as_secs_f64(),
        );
        let mut response = plain_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n");
        response.headers_mut().insert(ALLOW, ALLOW_GET);
        return response;
    }

    if request.uri().query().is_some() {
        metrics.inner.common.record(
            ScrapeOutcome::InvalidRequest,
            started.elapsed().as_secs_f64(),
        );
        return plain_response(StatusCode::BAD_REQUEST, "invalid metrics request\n");
    }

    if request_has_body(request.headers()) {
        metrics.inner.common.record(
            ScrapeOutcome::InvalidRequest,
            started.elapsed().as_secs_f64(),
        );
        return plain_response(StatusCode::BAD_REQUEST, "invalid metrics request\n");
    }

    let Some(representation) = negotiate_exposition(request.headers()) else {
        metrics.inner.common.record(
            ScrapeOutcome::NotAcceptable,
            started.elapsed().as_secs_f64(),
        );
        return plain_response(StatusCode::NOT_ACCEPTABLE, "not acceptable\n");
    };

    let Ok(permit) = Arc::clone(&metrics.inner.semaphore).try_acquire_owned() else {
        metrics
            .inner
            .common
            .record(ScrapeOutcome::Overloaded, started.elapsed().as_secs_f64());
        return plain_response(StatusCode::SERVICE_UNAVAILABLE, "metrics unavailable\n");
    };

    let inner = Arc::clone(&metrics.inner);
    let encoding = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _in_flight = inner.common.begin_encoding();
        encode_representation_bounded(
            &inner.registry,
            inner.limits.max_response_bytes.get(),
            representation,
        )
    });

    let result = timeout(metrics.inner.limits.scrape_timeout, encoding).await;
    match result {
        Ok(Ok(Ok(exposition))) => {
            metrics
                .inner
                .common
                .record(ScrapeOutcome::Success, started.elapsed().as_secs_f64());
            metrics
                .inner
                .common
                .record_success(exposition.len(), unix_timestamp_seconds(SystemTime::now()));
            exposition_response(exposition)
        }
        Ok(Ok(Err(EncodeError::TooLarge))) => {
            metrics
                .inner
                .common
                .record(ScrapeOutcome::TooLarge, started.elapsed().as_secs_f64());
            plain_response(StatusCode::SERVICE_UNAVAILABLE, "metrics unavailable\n")
        }
        Ok(Ok(Err(EncodeError::Encoding))) => {
            metrics
                .inner
                .common
                .record(ScrapeOutcome::EncodeError, started.elapsed().as_secs_f64());
            plain_response(StatusCode::INTERNAL_SERVER_ERROR, "metrics unavailable\n")
        }
        Ok(Err(error)) => task_error_response(&metrics, error, started),
        Err(_) => {
            metrics
                .inner
                .common
                .record(ScrapeOutcome::Timeout, started.elapsed().as_secs_f64());
            plain_response(StatusCode::SERVICE_UNAVAILABLE, "metrics unavailable\n")
        }
    }
}

async fn unknown_metrics_path(State(metrics): State<Metrics>) -> Response {
    let started = Instant::now();
    metrics.inner.common.record(
        ScrapeOutcome::InvalidRequest,
        started.elapsed().as_secs_f64(),
    );
    plain_response(StatusCode::NOT_FOUND, "not found\n")
}

fn request_has_body(headers: &HeaderMap) -> bool {
    if headers.contains_key(TRANSFER_ENCODING) {
        return true;
    }
    headers.get_all(CONTENT_LENGTH).iter().any(|value| {
        value
            .to_str()
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            != Some(0)
    })
}

fn task_error_response(metrics: &Metrics, _error: JoinError, started: Instant) -> Response {
    metrics
        .inner
        .common
        .record(ScrapeOutcome::TaskError, started.elapsed().as_secs_f64());
    plain_response(StatusCode::INTERNAL_SERVER_ERROR, "metrics unavailable\n")
}

fn exposition_response(exposition: EncodedExposition) -> Response {
    let mut response = Response::new(Body::from(exposition.body));
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static(exposition.representation.content_type()),
    );
    add_common_headers(&mut response);
    response
}

fn plain_response(status: StatusCode, message: &'static str) -> Response {
    let mut response = (status, message).into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, TEXT_CONTENT_TYPE);
    add_common_headers(&mut response);
    response
}

fn add_common_headers(response: &mut Response) {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, CACHE_CONTROL_NO_STORE);
    response
        .headers_mut()
        .insert(X_CONTENT_TYPE_OPTIONS, NOSNIFF);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EscapingScheme {
    AllowUtf8,
    Underscores,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Representation {
    OpenMetrics(EscapingScheme),
    PrometheusProtobuf,
}

impl Representation {
    const fn content_type(self) -> &'static str {
        match self {
            Self::OpenMetrics(escaping) => escaping.content_type(),
            Self::PrometheusProtobuf => PROMETHEUS_PROTOBUF_CONTENT_TYPE,
        }
    }
}

impl EscapingScheme {
    const fn content_type(self) -> &'static str {
        match self {
            Self::AllowUtf8 => OPENMETRICS_CONTENT_TYPE_ALLOW_UTF8,
            Self::Underscores => OPENMETRICS_CONTENT_TYPE,
        }
    }
}

fn negotiate_exposition(headers: &HeaderMap) -> Option<Representation> {
    if headers.get_all(ACCEPT).iter().next().is_none() {
        return Some(Representation::OpenMetrics(EscapingScheme::Underscores));
    }

    let mut selected: Option<(u16, AcceptPrecedence, Representation)> = None;
    for representation in [
        Representation::OpenMetrics(EscapingScheme::Underscores),
        Representation::OpenMetrics(EscapingScheme::AllowUtf8),
        Representation::PrometheusProtobuf,
    ] {
        let Some((precedence, quality)) = candidate_preference(headers, representation) else {
            continue;
        };
        if quality == 0 {
            continue;
        }
        if selected.is_none_or(|(current_quality, current_precedence, _)| {
            quality > current_quality
                || (quality == current_quality && precedence > current_precedence)
        }) {
            selected = Some((quality, precedence, representation));
        }
    }

    selected.map(|(_, _, representation)| representation)
}

fn candidate_preference(
    headers: &HeaderMap,
    candidate: Representation,
) -> Option<(AcceptPrecedence, u16)> {
    let mut selected: Option<(AcceptPrecedence, u16)> = None;
    for value in headers.get_all(ACCEPT) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        let Some(ranges) = split_quoted(value, ',') else {
            continue;
        };
        for range in ranges {
            let parsed = match candidate {
                Representation::OpenMetrics(escaping) => parse_openmetrics_range(range, escaping),
                Representation::PrometheusProtobuf => parse_prometheus_protobuf_range(range),
            };
            let Some((precedence, quality)) = parsed else {
                continue;
            };
            if selected.is_none_or(|(current, current_quality)| {
                precedence > current || (precedence == current && quality > current_quality)
            }) {
                selected = Some((precedence, quality));
            }
        }
    }
    selected
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct AcceptPrecedence {
    media_specificity: u8,
    parameter_count: u8,
}

fn parse_openmetrics_range(
    range: &str,
    candidate: EscapingScheme,
) -> Option<(AcceptPrecedence, u16)> {
    let components = split_quoted(range, ';')?;
    let media_type = components.first()?.trim();
    let (kind, subtype) = media_type.split_once('/')?;
    let media_specificity = if kind.trim().eq_ignore_ascii_case("application")
        && subtype.trim().eq_ignore_ascii_case("openmetrics-text")
    {
        2
    } else if kind.trim().eq_ignore_ascii_case("application") && subtype.trim() == "*" {
        1
    } else if kind.trim() == "*" && subtype.trim() == "*" {
        0
    } else {
        return None;
    };

    let mut quality = 1_000_u16;
    let mut parameter_count = 0_u8;
    let mut quality_seen = false;
    let mut version_seen = false;
    let mut charset_seen = false;
    let mut escaping_seen = false;
    let mut requested_escaping = None;

    for parameter in components.iter().skip(1) {
        let (name, value) = parameter.trim().split_once('=')?;
        let name = name.trim();
        let value = parameter_value(value)?;
        if name.eq_ignore_ascii_case("q") {
            if quality_seen {
                return None;
            }
            quality = parse_quality(&value)?;
            quality_seen = true;
            continue;
        }

        if name.eq_ignore_ascii_case("version") {
            if version_seen || value != "1.0.0" {
                return None;
            }
            version_seen = true;
        } else if name.eq_ignore_ascii_case("charset") {
            if charset_seen || !value.eq_ignore_ascii_case("utf-8") {
                return None;
            }
            charset_seen = true;
        } else if name.eq_ignore_ascii_case("escaping") {
            if escaping_seen {
                return None;
            }
            requested_escaping = Some(if value.eq_ignore_ascii_case("allow-utf-8") {
                EscapingScheme::AllowUtf8
            } else if value.eq_ignore_ascii_case("underscores") {
                EscapingScheme::Underscores
            } else {
                // Dots and value encoding would require transforming this
                // registry's names, so this exporter does not claim them.
                return None;
            });
            escaping_seen = true;
        } else {
            // The sole representation has no other media parameters.
            return None;
        }
        parameter_count = parameter_count.checked_add(1)?;
    }

    if requested_escaping.is_some_and(|requested| requested != candidate) {
        return None;
    }

    Some((
        AcceptPrecedence {
            media_specificity,
            parameter_count,
        },
        quality,
    ))
}

fn parse_prometheus_protobuf_range(range: &str) -> Option<(AcceptPrecedence, u16)> {
    let components = split_quoted(range, ';')?;
    let media_type = components.first()?.trim();
    let (kind, subtype) = media_type.split_once('/')?;
    let media_specificity = if kind.trim().eq_ignore_ascii_case("application")
        && subtype.trim().eq_ignore_ascii_case("vnd.google.protobuf")
    {
        2
    } else if kind.trim().eq_ignore_ascii_case("application") && subtype.trim() == "*" {
        1
    } else if kind.trim() == "*" && subtype.trim() == "*" {
        0
    } else {
        return None;
    };

    let mut quality = 1_000_u16;
    let mut parameter_count = 0_u8;
    let mut quality_seen = false;
    let mut proto_seen = false;
    let mut encoding_seen = false;

    for parameter in components.iter().skip(1) {
        let (name, value) = parameter.trim().split_once('=')?;
        let name = name.trim();
        let value = parameter_value(value)?;
        if name.eq_ignore_ascii_case("q") {
            if quality_seen {
                return None;
            }
            quality = parse_quality(&value)?;
            quality_seen = true;
            continue;
        }

        if name.eq_ignore_ascii_case("proto") {
            if proto_seen || value != "io.prometheus.client.MetricFamily" {
                return None;
            }
            proto_seen = true;
        } else if name.eq_ignore_ascii_case("encoding") {
            if encoding_seen || !value.eq_ignore_ascii_case("delimited") {
                return None;
            }
            encoding_seen = true;
        } else {
            return None;
        }
        parameter_count = parameter_count.checked_add(1)?;
    }

    // This media type is meaningful only together with the exact message and
    // framing parameters. Wildcard ranges may still select it without naming
    // those parameters, as required by HTTP Accept semantics.
    if media_specificity == 2 && (!proto_seen || !encoding_seen) {
        return None;
    }

    Some((
        AcceptPrecedence {
            media_specificity,
            parameter_count,
        },
        quality,
    ))
}

fn split_quoted(value: &str, delimiter: char) -> Option<Vec<&str>> {
    let mut segments = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;

    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
        } else if quoted && character == '\\' {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if character == delimiter && !quoted {
            segments.push(&value[start..index]);
            start = index + character.len_utf8();
        }
    }
    if quoted || escaped {
        return None;
    }
    segments.push(&value[start..]);
    Some(segments)
}

fn parameter_value(value: &str) -> Option<Cow<'_, str>> {
    let value = value.trim();
    if !value.starts_with('"') {
        return (!value.is_empty() && !value.contains(['"', '\\', '\r', '\n']))
            .then_some(Cow::Borrowed(value));
    }
    if value.len() < 2 || !value.ends_with('"') {
        return None;
    }

    let inner = &value[1..value.len() - 1];
    if !inner.contains('\\') {
        return (!inner.contains(['"', '\r', '\n'])).then_some(Cow::Borrowed(inner));
    }

    let mut decoded = String::with_capacity(inner.len());
    let mut characters = inner.chars();
    while let Some(character) = characters.next() {
        if character == '\\' {
            let escaped = characters.next()?;
            if matches!(escaped, '\r' | '\n') {
                return None;
            }
            decoded.push(escaped);
        } else if matches!(character, '"' | '\r' | '\n') {
            return None;
        } else {
            decoded.push(character);
        }
    }
    Some(Cow::Owned(decoded))
}

fn parse_quality(value: &str) -> Option<u16> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if fraction.len() > 3 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    match whole {
        "0" => {
            let padded = format!("{fraction:0<3}");
            padded.parse().ok()
        }
        "1" if fraction.bytes().all(|byte| byte == b'0') => Some(1_000),
        _ => None,
    }
}

fn encode_representation_bounded(
    registry: &Registry,
    max_bytes: usize,
    representation: Representation,
) -> Result<EncodedExposition, EncodeError> {
    let body = match representation {
        Representation::OpenMetrics(_) => encode_bounded(registry, max_bytes)?.into_bytes(),
        Representation::PrometheusProtobuf => {
            encode_prometheus_protobuf_bounded(registry, max_bytes)?
        }
    };
    Ok(EncodedExposition {
        body,
        representation,
    })
}

fn encode_prometheus_protobuf_bounded(
    registry: &Registry,
    max_bytes: usize,
) -> Result<Vec<u8>, EncodeError> {
    let families = prometheus_protobuf::encode(registry).map_err(|_| EncodeError::Encoding)?;
    let encoded_len = families.iter().try_fold(0_usize, |total, family| {
        let family_len = family.encoded_len();
        let framed_len = family_len.checked_add(prost::length_delimiter_len(family_len))?;
        total.checked_add(framed_len)
    });
    let Some(encoded_len) = encoded_len else {
        return Err(EncodeError::TooLarge);
    };
    if encoded_len > max_bytes {
        return Err(EncodeError::TooLarge);
    }

    let mut body = Vec::with_capacity(encoded_len);
    for family in families {
        family
            .encode_length_delimited(&mut body)
            .map_err(|_| EncodeError::Encoding)?;
    }
    if body.len() != encoded_len {
        return Err(EncodeError::Encoding);
    }
    Ok(body)
}

fn encode_bounded(registry: &Registry, max_bytes: usize) -> Result<EncodedMetrics, EncodeError> {
    let mut writer = BoundedWriter::new(max_bytes);
    match encode(&mut writer, registry) {
        Ok(()) => Ok(EncodedMetrics(writer.buffer)),
        Err(_) if writer.exceeded => Err(EncodeError::TooLarge),
        Err(_) => Err(EncodeError::Encoding),
    }
}

#[derive(Debug)]
struct BoundedWriter {
    buffer: String,
    max_bytes: usize,
    exceeded: bool,
}

impl BoundedWriter {
    fn new(max_bytes: usize) -> Self {
        Self {
            buffer: String::with_capacity(max_bytes.min(16 * 1024)),
            max_bytes,
            exceeded: false,
        }
    }
}

impl fmt::Write for BoundedWriter {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let Some(new_len) = self.buffer.len().checked_add(value.len()) else {
            self.exceeded = true;
            return Err(fmt::Error);
        };
        if new_len > self.max_bytes {
            self.exceeded = true;
            return Err(fmt::Error);
        }
        self.buffer.push_str(value);
        Ok(())
    }
}

fn unix_timestamp_seconds(time: SystemTime) -> f64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0.0, |duration| duration.as_secs_f64())
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus_client::metrics::counter::Counter;

    #[test]
    fn bounded_encoding_is_exact_and_never_partial() {
        let mut registry = Registry::with_prefix("automata_ci");
        let counter: Counter = Counter::default();
        counter.inc();
        registry.register("example", "Stable example", counter);

        let expected = concat!(
            "# HELP automata_ci_example Stable example.\n",
            "# TYPE automata_ci_example counter\n",
            "automata_ci_example_total 1\n",
            "# EOF\n",
        );
        let encoded = encode_bounded(&registry, expected.len()).expect("exact fit");
        assert_eq!(encoded.as_str(), expected);
        assert_eq!(
            encode_bounded(&registry, expected.len() - 1),
            Err(EncodeError::TooLarge)
        );
    }

    #[test]
    fn bounded_prometheus_protobuf_encoding_is_exact_and_never_partial() {
        let mut registry = Registry::with_prefix("automata_ci");
        let counter: Counter = Counter::default();
        counter.inc();
        registry.register("example", "Stable example", counter);

        let encoded = encode_prometheus_protobuf_bounded(&registry, usize::MAX)
            .expect("unrestricted test encoding");
        let exact = encode_prometheus_protobuf_bounded(&registry, encoded.len())
            .expect("exact protobuf fit");
        assert_eq!(exact, encoded);
        assert_eq!(
            encode_prometheus_protobuf_bounded(&registry, encoded.len() - 1),
            Err(EncodeError::TooLarge)
        );
    }

    #[test]
    fn accept_contract_is_finite() {
        for accepted in [
            "application/openmetrics-text",
            "application/openmetrics-text; version=1.0.0",
            "application/openmetrics-text; version=\"1.0.0\"; charset=UTF-8",
            "application/openmetrics-text;version=1.0.0;q=0.9,*/*;q=0.1",
            "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited",
            "application/*",
            "*/*",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(ACCEPT, accepted.parse().expect("valid header"));
            assert!(negotiate_exposition(&headers).is_some(), "{accepted}");
        }

        for rejected in [
            "application/json",
            "text/plain; version=0.0.4",
            "application/openmetrics-text; version=2.0.0",
            "application/openmetrics-text; charset=iso-8859-1",
            "application/openmetrics-text;q=1;charset=iso-8859-1",
            "application/openmetrics-text; version=1.0.0; q=0",
            "application/openmetrics-text;q=1.001",
            "application/openmetrics-text;q=NaN",
            "application/vnd.google.protobuf",
            "application/vnd.google.protobuf;proto=private.MetricFamily;encoding=delimited",
            "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=gzip",
            "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited;encoding=delimited",
            "garbage",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(ACCEPT, rejected.parse().expect("valid header"));
            assert!(negotiate_exposition(&headers).is_none(), "{rejected}");
        }

        for (header, accepted) in [
            ("application/openmetrics-text;q=0, */*;q=1", true),
            ("application/openmetrics-text;q=0, application/*;q=1", true),
            ("application/*;q=0, */*;q=1", false),
            ("application/json;q=1, application/*;q=0.5", true),
            (
                "application/openmetrics-text;q=0, application/openmetrics-text;version=1.0.0;q=1",
                true,
            ),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(ACCEPT, header.parse().expect("valid header"));
            assert_eq!(
                negotiate_exposition(&headers).is_some(),
                accepted,
                "{header}"
            );
        }

        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            "application/openmetrics-text;version=1.0.0;escaping=allow-utf-8;q=0.5,application/openmetrics-text;version=0.0.1;q=0.4,text/plain;version=1.0.0;escaping=allow-utf-8;q=0.3,text/plain;version=0.0.4;q=0.2,*/*;q=0.1"
                .parse()
                .expect("current Prometheus Accept header"),
        );
        assert_eq!(
            negotiate_exposition(&headers),
            Some(Representation::OpenMetrics(EscapingScheme::AllowUtf8))
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            concat!(
                "application/vnd.google.protobuf;",
                "proto=io.prometheus.client.MetricFamily;",
                "encoding=delimited;q=0.5,",
                "application/openmetrics-text;version=1.0.0;",
                "escaping=allow-utf-8;q=0.4,*/*;q=0.1",
            )
            .parse()
            .expect("native-histogram Prometheus Accept header"),
        );
        assert_eq!(
            negotiate_exposition(&headers),
            Some(Representation::PrometheusProtobuf)
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            "application/openmetrics-text;q=0, application/openmetrics-text;q=0.8"
                .parse()
                .expect("duplicate weighted ranges"),
        );
        assert_eq!(
            negotiate_exposition(&headers),
            Some(Representation::OpenMetrics(EscapingScheme::Underscores))
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            "application/openmetrics-text;escaping=allow-utf-8;q=0, */*;q=1"
                .parse()
                .expect("one escaping representation excluded"),
        );
        assert_eq!(
            negotiate_exposition(&headers),
            Some(Representation::OpenMetrics(EscapingScheme::Underscores))
        );
    }
}
