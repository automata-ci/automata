# automata-ci-metrics

`automata-ci-metrics` provides the shared Prometheus registry and bounded
OpenMetrics 1.0 exporter used by the Automata orchestrator and runner. It owns
the process registry lifecycle, immutable build provenance, truthful process
start time where supported, and exporter self-observation.

The exporter serves only `GET /metrics` and negotiates either OpenMetrics 1.0
text or the length-delimited `io.prometheus.client.MetricFamily` Prometheus
protobuf protocol. It encodes a complete response before returning success and
enforces fixed concurrency, timeout, and response-size limits. OpenMetrics text
remains the default when `Accept` is absent and the deterministic fallback when
the two protocols have equal preference. Product crates register their own
closed, finite metric families before finalizing the registry.

Native histogram buckets require the Prometheus protobuf protocol; OpenMetrics
1.0 text can expose only classic buckets. A histogram that must retain the text
fallback therefore needs both classic and bounded native buckets rather than a
native-only constructor. Prometheus must request `PrometheusProto` and enable
native-histogram ingestion to store the native sample. The pinned Rust client
supports exemplars on counters and classic histogram buckets, but does not yet
emit the native histogram exemplar list.

Product metrics use `classic_and_native_histogram(...)` when native storage is
desired. Its native side starts at bucket factor 1.1, retains at most 160
populated buckets for Automata's nonnegative observations, and permits a reset
only after one hour when resolution had to be reduced. The zero threshold stays
at the client's unit-neutral default; the shared helper does not widen it
across unlike seconds, bytes, and count domains.

- [Observability documentation](https://github.com/automata-ci/automata/blob/main/docs/observability.md)
- API documentation: run `cargo doc -p automata-ci-metrics --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
