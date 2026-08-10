use std::{
    fmt,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
};

use automata_ci_metrics::{
    BuildInfo, Counter, ExporterLimits, MetricsBuilder, NATIVE_HISTOGRAM_MAX_BUCKETS,
    NATIVE_HISTOGRAM_MIN_RESET_DURATION, OPENMETRICS_CONTENT_TYPE,
    PROMETHEUS_PROTOBUF_CONTENT_TYPE, ProcessRole, classic_and_native_histogram,
};
use axum::{
    body::Body,
    http::{
        Method, Request, StatusCode,
        header::{ACCEPT, ALLOW, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING},
    },
};
use http_body_util::BodyExt as _;
use prometheus_client::{
    collector::Collector,
    encoding::{DescriptorEncoder, EncodeMetric as _, prometheus_protobuf::prometheus_data_model},
    metrics::{counter::ConstCounter, exemplar::CounterWithExemplar},
};
use prost::Message as _;
use tower::ServiceExt as _;

fn metrics_builder() -> MetricsBuilder {
    MetricsBuilder::new(BuildInfo::new(ProcessRole::Runner, "1.2.3-test", "unknown"))
        .expect("valid build provenance")
}

async fn body_text(response: axum::response::Response) -> String {
    String::from_utf8(body_bytes(response).await).expect("UTF-8 response")
}

async fn body_bytes(response: axum::response::Response) -> Vec<u8> {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collect response")
        .to_bytes();
    bytes.to_vec()
}

fn decode_metric_families(mut bytes: &[u8]) -> Vec<prometheus_data_model::MetricFamily> {
    let mut families = Vec::new();
    while !bytes.is_empty() {
        families.push(
            prometheus_data_model::MetricFamily::decode_length_delimited(&mut bytes)
                .expect("valid delimited MetricFamily"),
        );
    }
    families
}

fn scrape_request() -> Request<Body> {
    Request::builder()
        .uri("/metrics")
        .body(Body::empty())
        .expect("scrape request")
}

fn assert_security_headers(response: &axum::response::Response) {
    assert_eq!(
        response
            .headers()
            .get(CACHE_CONTROL)
            .expect("cache control"),
        "no-store"
    );
    assert_eq!(
        response
            .headers()
            .get("x-content-type-options")
            .expect("content type options"),
        "nosniff"
    );
}

#[tokio::test]
async fn get_exposes_complete_openmetrics_with_exact_headers() {
    let metrics = metrics_builder().finish(ExporterLimits::default());
    let response = metrics
        .router()
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .header(ACCEPT, "application/openmetrics-text; version=1.0.0")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(CONTENT_TYPE).expect("content type"),
        OPENMETRICS_CONTENT_TYPE
    );
    assert_security_headers(&response);
    let body = body_text(response).await;
    assert!(body.ends_with("# EOF\n"));
    assert_eq!(body.matches("# EOF\n").count(), 1);
    assert!(body.contains("automata_ci_build_info"));
    assert!(body.contains("role=\"runner\""));
    assert!(body.contains("version=\"1.2.3-test\""));
    assert!(body.contains("revision=\"unknown\""));
    #[cfg(target_os = "linux")]
    {
        assert!(body.contains("process_start_time_seconds"));
        assert!(!body.contains("automata_ci_process_start_time_seconds"));
    }
    assert!(!body.contains("private/tenant"));
}

#[tokio::test]
async fn prometheus_protobuf_exposes_native_buckets_and_exemplars_with_text_fallback() {
    let mut builder = metrics_builder();
    let histogram = classic_and_native_histogram([0.1, 1.0, 10.0]);
    for observation in [-4.0, 0.0, 8.0] {
        histogram.observe(observation);
    }
    builder.registry_mut().register(
        "native_probe",
        "Bounded native histogram negotiation probe",
        histogram,
    );

    let exemplar: CounterWithExemplar<Vec<(String, String)>> = CounterWithExemplar::default();
    exemplar.inc_by(
        7,
        Some(vec![("trace_id".to_owned(), "0123456789abcdef".to_owned())]),
        Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
    );
    builder.registry_mut().register(
        "exemplar_probe",
        "Bounded exemplar negotiation probe",
        exemplar,
    );
    let metrics = builder.finish(ExporterLimits::default());

    let protobuf_first = concat!(
        "application/vnd.google.protobuf;",
        "proto=io.prometheus.client.MetricFamily;",
        "encoding=delimited;q=0.5,",
        "application/openmetrics-text;version=1.0.0;",
        "escaping=allow-utf-8;q=0.4,*/*;q=0.1",
    );
    let response = metrics
        .router()
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .header(ACCEPT, protobuf_first)
                .body(Body::empty())
                .expect("protobuf scrape request"),
        )
        .await
        .expect("protobuf scrape response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(CONTENT_TYPE).expect("content type"),
        PROMETHEUS_PROTOBUF_CONTENT_TYPE
    );
    assert_security_headers(&response);
    let families = decode_metric_families(&body_bytes(response).await);

    let native = families
        .iter()
        .find(|family| family.name == "automata_ci_native_probe")
        .expect("native histogram family")
        .metric
        .first()
        .and_then(|metric| metric.histogram.as_ref())
        .expect("native histogram sample");
    assert_eq!(native.sample_count, 3);
    assert_eq!(native.schema, 3);
    assert!(!native.bucket.is_empty(), "classic fallback buckets");
    assert!(!native.positive_span.is_empty(), "positive native span");
    assert!(!native.negative_span.is_empty(), "negative native span");
    assert!(native.start_timestamp.is_some(), "native start timestamp");

    let encoded_exemplar = families
        .iter()
        .find(|family| family.name == "automata_ci_exemplar_probe_total")
        .expect("exemplar counter family")
        .metric
        .first()
        .and_then(|metric| metric.counter.as_ref())
        .and_then(|counter| counter.exemplar.as_ref())
        .expect("counter exemplar");
    assert!((encoded_exemplar.value - 7.0).abs() < f64::EPSILON);
    assert_eq!(encoded_exemplar.label[0].name, "trace_id");
    assert_eq!(encoded_exemplar.label[0].value, "0123456789abcdef");
    assert!(encoded_exemplar.timestamp.is_some());

    let text_response = metrics
        .router()
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .header(ACCEPT, "application/openmetrics-text;version=1.0.0")
                .body(Body::empty())
                .expect("OpenMetrics scrape request"),
        )
        .await
        .expect("OpenMetrics scrape response");
    assert_eq!(text_response.status(), StatusCode::OK);
    assert_eq!(
        text_response
            .headers()
            .get(CONTENT_TYPE)
            .expect("content type"),
        OPENMETRICS_CONTENT_TYPE
    );
    let text = body_text(text_response).await;
    assert!(text.contains("automata_ci_native_probe_bucket"));
    assert!(text.contains("trace_id=\"0123456789abcdef\""));
    assert!(text.ends_with("# EOF\n"));
}

#[tokio::test]
async fn shared_native_histogram_bounds_the_full_nonnegative_f64_range() {
    let mut builder = metrics_builder();
    let histogram = classic_and_native_histogram([0.1, 1.0, 10.0]);
    for exponent in (-1_022..=1_023).step_by(8) {
        histogram.observe(2_f64.powi(exponent));
    }
    histogram.observe(f64::from_bits(1));
    histogram.observe(f64::MAX);
    builder.registry_mut().register(
        "native_range_probe",
        "Full nonnegative floating-point range probe",
        histogram,
    );
    let metrics = builder.finish(ExporterLimits::default());

    let response = metrics
        .router()
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .header(
                    ACCEPT,
                    "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited",
                )
                .body(Body::empty())
                .expect("bounded native scrape request"),
        )
        .await
        .expect("bounded native scrape response");
    assert_eq!(response.status(), StatusCode::OK);
    let families = decode_metric_families(&body_bytes(response).await);
    let native = families
        .iter()
        .find(|family| family.name == "automata_ci_native_range_probe")
        .expect("bounded native histogram family")
        .metric
        .first()
        .and_then(|metric| metric.histogram.as_ref())
        .expect("bounded native histogram sample");
    assert!(native.negative_delta.is_empty());
    assert!(native.positive_delta.len() <= NATIVE_HISTOGRAM_MAX_BUCKETS);
    assert_eq!(native.schema, 3);
    assert_eq!(NATIVE_HISTOGRAM_MIN_RESET_DURATION, Duration::from_hours(1));
}

#[tokio::test]
async fn endpoint_is_get_only_and_rejects_unsupported_formats() {
    let metrics = metrics_builder().finish(ExporterLimits::default());

    for method in [Method::POST, Method::PUT, Method::HEAD, Method::OPTIONS] {
        let response = metrics
            .router()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri("/metrics")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers().get(ALLOW).expect("allow"), "GET");
        assert_security_headers(&response);
    }

    let sentinel = "application/private-tenant-secret";
    let response = metrics
        .router()
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .header(ACCEPT, sentinel)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
    assert_security_headers(&response);
    assert!(!body_text(response).await.contains(sentinel));

    let exposition = metrics.encode_openmetrics().expect("encode after errors");
    assert!(!exposition.as_str().contains(sentinel));
    assert!(
        exposition
            .as_str()
            .contains("outcome=\"method_not_allowed\"")
    );
    assert!(exposition.as_str().contains("outcome=\"not_acceptable\""));

    let response = metrics
        .router()
        .oneshot(
            Request::builder()
                .uri("/metrics?tenant=private-sentinel")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_security_headers(&response);
    assert!(!body_text(response).await.contains("private-sentinel"));
    let exposition = metrics.encode_openmetrics().expect("encode after query");
    assert!(exposition.as_str().contains("outcome=\"invalid_request\""));
    assert!(!exposition.as_str().contains("private-sentinel"));
}

#[tokio::test]
async fn endpoint_rejects_unknown_paths_and_request_bodies_without_echoing_them() {
    let metrics = metrics_builder().finish(ExporterLimits::default());

    for path in ["/", "/metrics/", "/private-tenant-secret"] {
        let response = metrics
            .router()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert_security_headers(&response);
        assert!(!body_text(response).await.contains("private-tenant-secret"));
    }

    for (header, value) in [(CONTENT_LENGTH, "1"), (TRANSFER_ENCODING, "chunked")] {
        let response = metrics
            .router()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .header(header, value)
                    .body(Body::from("private-body-secret"))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_security_headers(&response);
        assert!(!body_text(response).await.contains("private-body-secret"));
    }

    let exposition = metrics.encode_openmetrics().expect("encode after rejects");
    assert!(!exposition.as_str().contains("private-tenant-secret"));
    assert!(!exposition.as_str().contains("private-body-secret"));
    let duration_sum = exposition
        .as_str()
        .lines()
        .find_map(|line| {
            line.strip_prefix("automata_ci_metrics_scrape_duration_seconds_sum ")
                .and_then(|value| value.parse::<f64>().ok())
        })
        .expect("scrape duration sum");
    assert!(
        duration_sum > 0.0,
        "unknown-path requests must be timed from a monotonic clock"
    );
}

#[tokio::test]
async fn accept_precedence_selects_only_supported_exact_representations() {
    let metrics = metrics_builder().finish(ExporterLimits::default());

    for (accept, expected) in [
        ("application/*", StatusCode::OK),
        (
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
            StatusCode::OK,
        ),
        ("application/openmetrics-text;q=0, */*;q=1", StatusCode::OK),
        (
            "application/openmetrics-text;version=1.0.0;q=0, application/*;q=1",
            StatusCode::OK,
        ),
        (
            "application/openmetrics-text;version=2.0.0",
            StatusCode::NOT_ACCEPTABLE,
        ),
        (
            "application/openmetrics-text;charset=iso-8859-1",
            StatusCode::NOT_ACCEPTABLE,
        ),
        (
            "application/openmetrics-text;q=1;charset=iso-8859-1",
            StatusCode::NOT_ACCEPTABLE,
        ),
        (
            "application/openmetrics-text;version=1.0.0;escaping=dots",
            StatusCode::NOT_ACCEPTABLE,
        ),
        (
            "application/vnd.google.protobuf",
            StatusCode::NOT_ACCEPTABLE,
        ),
        (
            "application/vnd.google.protobuf;proto=private.MetricFamily;encoding=delimited",
            StatusCode::NOT_ACCEPTABLE,
        ),
        (
            "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=gzip",
            StatusCode::NOT_ACCEPTABLE,
        ),
    ] {
        let response = metrics
            .router()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .header(ACCEPT, accept)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), expected, "{accept}");
        assert_security_headers(&response);
    }

    let modern_prometheus_accept = concat!(
        "application/openmetrics-text;version=1.0.0;",
        "escaping=allow-utf-8;q=0.5,",
        "application/openmetrics-text;version=0.0.1;q=0.4,",
        "text/plain;version=1.0.0;escaping=allow-utf-8;q=0.3,",
        "text/plain;version=0.0.4;q=0.2,*/*;q=0.1",
    );
    let response = metrics
        .router()
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .header(ACCEPT, modern_prometheus_accept)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_security_headers(&response);
    assert_eq!(
        response.headers().get(CONTENT_TYPE).expect("content type"),
        "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=allow-utf-8"
    );

    let response = metrics
        .router()
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .header(
                    ACCEPT,
                    "application/openmetrics-text;escaping=allow-utf-8;q=0, */*;q=1",
                )
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_security_headers(&response);
    assert_eq!(
        response.headers().get(CONTENT_TYPE).expect("content type"),
        OPENMETRICS_CONTENT_TYPE
    );
}

#[derive(Debug)]
struct BlockingCollector {
    entered: Arc<AtomicBool>,
    release: Arc<AtomicBool>,
}

impl Collector for BlockingCollector {
    fn encode(&self, mut encoder: DescriptorEncoder<'_>) -> fmt::Result {
        self.entered.store(true, Ordering::Release);
        while !self.release.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        let metric = ConstCounter::new(1_u64);
        let metric_encoder = encoder.encode_descriptor(
            "blocking_collector",
            "Test-only bounded collector",
            None,
            metric.metric_type(),
        )?;
        metric.encode(metric_encoder)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_scrapes_are_rejected_without_queueing() {
    let entered = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let mut builder = metrics_builder();
    builder
        .registry_mut()
        .register_collector(Box::new(BlockingCollector {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        }));
    let limits = ExporterLimits::try_new(
        NonZeroUsize::new(1).expect("one"),
        Duration::from_secs(2),
        NonZeroUsize::new(2 * 1024 * 1024).expect("size"),
    )
    .expect("limits");
    let metrics = builder.finish(limits);

    let first = tokio::spawn(metrics.router().oneshot(scrape_request()));
    tokio::time::timeout(Duration::from_secs(1), async {
        while !entered.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("collector entered");

    let overloaded = metrics
        .router()
        .oneshot(scrape_request())
        .await
        .expect("overload response");
    assert_eq!(overloaded.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_security_headers(&overloaded);

    release.store(true, Ordering::Release);
    let completed = first.await.expect("request task").expect("response");
    assert_eq!(completed.status(), StatusCode::OK);
    assert_security_headers(&completed);
    assert!(
        metrics
            .encode_openmetrics()
            .expect("final encode")
            .as_str()
            .contains("outcome=\"overloaded\"")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scrape_timeout_returns_without_releasing_the_active_encoding_slot() {
    let entered = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let mut builder = metrics_builder();
    builder
        .registry_mut()
        .register_collector(Box::new(BlockingCollector {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        }));
    let limits = ExporterLimits::try_new(
        NonZeroUsize::new(1).expect("one"),
        Duration::from_millis(10),
        NonZeroUsize::new(2 * 1024 * 1024).expect("size"),
    )
    .expect("limits");
    let metrics = builder.finish(limits);

    let response = metrics
        .router()
        .oneshot(scrape_request())
        .await
        .expect("timeout response");
    assert!(entered.load(Ordering::Acquire));
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_security_headers(&response);

    let overloaded = metrics
        .router()
        .oneshot(scrape_request())
        .await
        .expect("overload response");
    assert_eq!(overloaded.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_security_headers(&overloaded);

    release.store(true, Ordering::Release);
    let exposition = metrics.encode_openmetrics().expect("encoding released");
    assert!(exposition.as_str().contains("outcome=\"timeout\""));
    assert!(exposition.as_str().contains("outcome=\"overloaded\""));
}

#[tokio::test]
async fn complete_response_size_limit_returns_no_partial_exposition() {
    let mut builder = metrics_builder();
    let counter: Counter = Counter::default();
    builder
        .registry_mut()
        .register("oversized_test", "x".repeat(16_384), counter);
    let limits = ExporterLimits::try_new(
        NonZeroUsize::new(1).expect("one"),
        Duration::from_secs(1),
        NonZeroUsize::new(512).expect("size"),
    )
    .expect("limits");
    let metrics = builder.finish(limits);

    assert_eq!(
        metrics.encode_openmetrics(),
        Err(automata_ci_metrics::EncodeError::TooLarge)
    );
    for accept in [
        "application/openmetrics-text;version=1.0.0",
        "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited",
    ] {
        let response = metrics
            .router()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .header(ACCEPT, accept)
                    .body(Body::empty())
                    .expect("bounded scrape request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_security_headers(&response);
        assert_eq!(body_text(response).await, "metrics unavailable\n");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_metric_updates_and_encodings_remain_complete() {
    let mut builder = metrics_builder();
    let counter: Counter = Counter::default();
    builder.registry_mut().register(
        "concurrent_updates",
        "Concurrent update probe",
        counter.clone(),
    );
    let metrics = builder.finish(ExporterLimits::default());

    let updater = tokio::spawn(async move {
        for _ in 0..10_000 {
            counter.inc();
            tokio::task::yield_now().await;
        }
    });
    let mut scrapes = Vec::new();
    for _ in 0..32 {
        let metrics = metrics.clone();
        scrapes.push(tokio::spawn(async move {
            loop {
                let response = metrics
                    .router()
                    .oneshot(scrape_request())
                    .await
                    .expect("response");
                if response.status() == StatusCode::SERVICE_UNAVAILABLE {
                    tokio::task::yield_now().await;
                    continue;
                }
                assert_eq!(response.status(), StatusCode::OK);
                return body_text(response).await;
            }
        }));
    }

    updater.await.expect("updater");
    for scrape in scrapes {
        let body = scrape.await.expect("scrape task");
        assert!(body.ends_with("# EOF\n"));
        assert_eq!(body.matches("# EOF\n").count(), 1);
    }
}

#[test]
fn common_metric_cardinality_is_bounded_and_has_no_dynamic_identity_labels() {
    let metrics = metrics_builder().finish(ExporterLimits::default());
    let exposition = metrics.encode_openmetrics().expect("encode");
    let sample_lines = exposition
        .as_str()
        .lines()
        .filter(|line| !line.starts_with('#'))
        .count();
    assert!(sample_lines <= 64, "common series grew to {sample_lines}");

    for forbidden in [
        "tenant=",
        "repository=",
        "workflow=",
        "job=",
        "attempt=",
        "runner_id=",
        "session=",
        "lease=",
        "url=",
        "error=",
    ] {
        assert!(!exposition.as_str().contains(forbidden), "{forbidden}");
    }
}

#[tokio::test]
async fn finalized_registries_are_isolated_in_both_encodings() {
    let mut first_builder = metrics_builder();
    let first_counter: Counter = Counter::default();
    first_builder
        .registry_mut()
        .register("only_first", "First registry sentinel", first_counter);
    let first = first_builder.finish(ExporterLimits::default());

    let mut second_builder = metrics_builder();
    let second_counter: Counter = Counter::default();
    second_builder.registry_mut().register(
        "only_second",
        "Second registry sentinel",
        second_counter,
    );
    let second = second_builder.finish(ExporterLimits::default());

    let first_text = first.encode_openmetrics().expect("first encode");
    let second_text = second.encode_openmetrics().expect("second encode");
    assert!(first_text.as_str().contains("automata_ci_only_first"));
    assert!(!first_text.as_str().contains("automata_ci_only_second"));
    assert!(second_text.as_str().contains("automata_ci_only_second"));
    assert!(!second_text.as_str().contains("automata_ci_only_first"));

    for (metrics, present, absent) in [
        (
            first,
            "automata_ci_only_first_total",
            "automata_ci_only_second_total",
        ),
        (
            second,
            "automata_ci_only_second_total",
            "automata_ci_only_first_total",
        ),
    ] {
        let response = metrics
            .router()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .header(
                        ACCEPT,
                        "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited",
                    )
                    .body(Body::empty())
                    .expect("isolated protobuf request"),
            )
            .await
            .expect("isolated protobuf response");
        let families = decode_metric_families(&body_bytes(response).await);
        assert!(families.iter().any(|family| family.name == present));
        assert!(!families.iter().any(|family| family.name == absent));
    }
}
