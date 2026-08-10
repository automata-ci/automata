#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Bounded Prometheus and `OpenMetrics` telemetry for Automata product binaries.
//!
//! A [`MetricsBuilder`] owns the only mutable registry during composition.
//! Product-specific metric handles are registered through
//! [`MetricsBuilder::registry_mut`] before [`MetricsBuilder::finish`] freezes
//! the registry behind an immutable, cloneable [`Metrics`] value.
//!
//! The upstream label derive macros expand through the absolute
//! `prometheus_client` crate path. A downstream crate deriving
//! [`EncodeLabelSet`] or [`EncodeLabelValue`] must therefore declare its own
//! `prometheus-client` dependency even though this crate re-exports the
//! primitives and owns the registry lifecycle.

mod common;
mod endpoint;
mod process;

pub use common::{BuildInfo, BuildInfoError, ProcessRole};
pub use endpoint::{
    EncodeError, EncodedMetrics, ExporterLimits, ExporterLimitsError, Metrics,
    OPENMETRICS_CONTENT_TYPE, PROMETHEUS_PROTOBUF_CONTENT_TYPE,
};
pub use process::{PROCESS_SNAPSHOT_INTERVAL, ProcessMetricsSampler};
pub use prometheus_client::{
    encoding::{EncodeLabelSet, EncodeLabelValue},
    metrics::{
        counter::Counter,
        family::{Family, MetricConstructor},
        gauge::Gauge,
        histogram::Histogram,
        info::Info,
    },
    registry::{Registry, Unit},
};

use common::CommonMetrics;

/// Product-wide metric namespace.
pub const METRIC_NAMESPACE: &str = "automata_ci";

/// Initial native-histogram bucket growth-factor ceiling.
pub const NATIVE_HISTOGRAM_BUCKET_FACTOR: f64 = 1.1;

/// Maximum populated native buckets retained by one nonnegative histogram.
pub const NATIVE_HISTOGRAM_MAX_BUCKETS: usize = 160;

/// Minimum interval between native-histogram resets after bucket degradation.
pub const NATIVE_HISTOGRAM_MIN_RESET_DURATION: std::time::Duration =
    std::time::Duration::from_hours(1);

/// Creates a histogram with classic buckets and the shared bounded native buckets.
///
/// Automata histogram observations are nonnegative durations, sizes, ages, or
/// counts. The classic buckets preserve the `OpenMetrics` 1.0 text contract. The
/// native side starts at the Prometheus-recommended 1.1 factor, retains at most
/// 160 populated buckets, and may reset no more often than hourly after it has
/// reduced resolution to enforce that bound.
pub fn classic_and_native_histogram(classic_buckets: impl IntoIterator<Item = f64>) -> Histogram {
    Histogram::new_classic_and_native(
        classic_buckets,
        prometheus_client::metrics::histogram::NativeHistogramConfig::new(
            NATIVE_HISTOGRAM_BUCKET_FACTOR,
        )
        .max_buckets(NATIVE_HISTOGRAM_MAX_BUCKETS)
        .min_reset_duration(NATIVE_HISTOGRAM_MIN_RESET_DURATION),
    )
}

/// Mutable composition-time owner of one Prometheus registry.
#[derive(Debug)]
pub struct MetricsBuilder {
    registry: Registry,
    common: CommonMetrics,
    process_sampler: ProcessMetricsSampler,
}

impl MetricsBuilder {
    /// Creates a registry and registers the common build, process, and exporter
    /// metrics.
    ///
    /// # Errors
    ///
    /// Returns an error when build labels do not satisfy the finite public
    /// provenance contract.
    pub fn new(build: BuildInfo) -> Result<Self, BuildInfoError> {
        build.validate()?;

        let mut registry = Registry::default();
        let process_sampler = ProcessMetricsSampler::register(&mut registry);
        process_sampler.refresh_at(std::time::SystemTime::now());
        let common = CommonMetrics::register(&mut registry, build);
        Ok(Self {
            registry,
            common,
            process_sampler,
        })
    }

    /// Attaches and returns a product-prefixed subregistry during process
    /// composition.
    ///
    /// Metric names registered here are automatically prefixed with
    /// `automata_ci_`. Callers should request one subregistry, register their
    /// complete product schema through it, and retain cloned typed metric
    /// handles before finalizing the builder. Standard unprefixed `process_*`
    /// metrics remain in the private root registry.
    pub fn registry_mut(&mut self) -> &mut Registry {
        self.registry.sub_registry_with_prefix(METRIC_NAMESPACE)
    }

    /// Returns the cached process-resource sampler for product supervision.
    ///
    /// The builder performs one best-effort initial refresh. When the metrics
    /// listener is enabled, product composition must retain this handle and
    /// supervise [`ProcessMetricsSampler::run_until_cancelled`] so cached
    /// values continue refreshing independently of scrapes.
    #[must_use]
    pub fn process_sampler(&self) -> ProcessMetricsSampler {
        self.process_sampler.clone()
    }

    /// Freezes the registry and constructs a bounded exporter.
    #[must_use]
    pub fn finish(self, limits: ExporterLimits) -> Metrics {
        Metrics::new(self.registry, self.common, limits)
    }
}
