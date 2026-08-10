use std::{fmt, sync::atomic::AtomicU64};

use prometheus_client::{
    encoding::{EncodeLabelSet, EncodeLabelValue, LabelValueEncoder},
    metrics::{counter::Counter, family::Family, gauge::Gauge, histogram::Histogram, info::Info},
    registry::{Registry, Unit},
};
use thiserror::Error;

use crate::classic_and_native_histogram;

pub(crate) type FloatGauge = Gauge<f64, AtomicU64>;

const SCRAPE_DURATION_BUCKETS_SECONDS: [f64; 11] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0,
];
const EXPOSITION_SIZE_BUCKETS_BYTES: [f64; 9] = [
    1_024.0,
    4_096.0,
    16_384.0,
    65_536.0,
    262_144.0,
    524_288.0,
    1_048_576.0,
    2_097_152.0,
    4_194_304.0,
];

/// Closed product role exported by the build information metric.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProcessRole {
    /// Orchestrator and control-plane product process.
    ControlPlane,
    /// Outbound runner product process.
    Runner,
    /// Repository-only real-scrape validation fixture.
    MetricsFixture,
}

impl EncodeLabelValue for ProcessRole {
    fn encode(&self, encoder: &mut LabelValueEncoder<'_>) -> fmt::Result {
        use fmt::Write as _;

        encoder.write_str(match self {
            Self::ControlPlane => "control_plane",
            Self::Runner => "runner",
            Self::MetricsFixture => "metrics_fixture",
        })
    }
}

/// Immutable public build provenance attached once per process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildInfo {
    role: ProcessRole,
    version: &'static str,
    revision: &'static str,
}

impl BuildInfo {
    /// Constructs build provenance. Validation happens when the metrics
    /// registry is built.
    #[must_use]
    pub const fn new(role: ProcessRole, version: &'static str, revision: &'static str) -> Self {
        Self {
            role,
            version,
            revision,
        }
    }

    /// Product role.
    #[must_use]
    pub const fn role(self) -> ProcessRole {
        self.role
    }

    /// Package version.
    #[must_use]
    pub const fn version(self) -> &'static str {
        self.version
    }

    /// Full source revision or `unknown` for a non-release development build.
    #[must_use]
    pub const fn revision(self) -> &'static str {
        self.revision
    }

    pub(crate) fn validate(self) -> Result<(), BuildInfoError> {
        if self.version.is_empty()
            || self.version.len() > 64
            || !self.version.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'_')
            })
        {
            return Err(BuildInfoError::InvalidVersion);
        }

        let revision_is_hash = matches!(self.revision.len(), 40 | 64)
            && self.revision.bytes().all(|byte| byte.is_ascii_hexdigit());
        if self.revision != "unknown" && !revision_is_hash {
            return Err(BuildInfoError::InvalidRevision);
        }

        Ok(())
    }
}

/// Build provenance validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BuildInfoError {
    /// Package version is empty, oversized, or outside the public allowlist.
    #[error("build version is outside the public metrics allowlist")]
    InvalidVersion,
    /// Revision is neither `unknown` nor a complete hexadecimal object ID.
    #[error("build revision is not a complete public object ID")]
    InvalidRevision,
}

#[derive(Clone, Debug, EncodeLabelSet, Eq, Hash, PartialEq)]
struct BuildLabels {
    role: ProcessRole,
    version: &'static str,
    revision: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum ScrapeOutcome {
    Success,
    MethodNotAllowed,
    InvalidRequest,
    NotAcceptable,
    Overloaded,
    Timeout,
    TooLarge,
    EncodeError,
    TaskError,
}

impl ScrapeOutcome {
    const ALL: [Self; 9] = [
        Self::Success,
        Self::MethodNotAllowed,
        Self::InvalidRequest,
        Self::NotAcceptable,
        Self::Overloaded,
        Self::Timeout,
        Self::TooLarge,
        Self::EncodeError,
        Self::TaskError,
    ];
}

impl EncodeLabelValue for ScrapeOutcome {
    fn encode(&self, encoder: &mut LabelValueEncoder<'_>) -> fmt::Result {
        use fmt::Write as _;

        encoder.write_str(match self {
            Self::Success => "success",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::InvalidRequest => "invalid_request",
            Self::NotAcceptable => "not_acceptable",
            Self::Overloaded => "overloaded",
            Self::Timeout => "timeout",
            Self::TooLarge => "too_large",
            Self::EncodeError => "encode_error",
            Self::TaskError => "task_error",
        })
    }
}

#[derive(Clone, Debug, EncodeLabelSet, Eq, Hash, PartialEq)]
struct ScrapeLabels {
    outcome: ScrapeOutcome,
}

#[derive(Clone, Debug)]
pub(crate) struct CommonMetrics {
    scrapes: Family<ScrapeLabels, Counter>,
    scrape_duration: Histogram,
    exposition_size: Histogram,
    scrapes_in_flight: Gauge,
    last_success_timestamp: FloatGauge,
}

impl CommonMetrics {
    pub(crate) fn register(root_registry: &mut Registry, build: BuildInfo) -> Self {
        let registry = root_registry.sub_registry_with_prefix(crate::METRIC_NAMESPACE);
        registry.register(
            "build",
            "Immutable build provenance for this Automata process",
            Info::new(BuildLabels {
                role: build.role,
                version: build.version,
                revision: build.revision,
            }),
        );

        let scrapes = Family::<ScrapeLabels, Counter>::default();
        for outcome in ScrapeOutcome::ALL {
            let _ = scrapes.get_or_create(&ScrapeLabels { outcome });
        }
        registry.register(
            "metrics_scrapes",
            "Metrics endpoint requests by bounded outcome",
            scrapes.clone(),
        );

        let scrape_duration = classic_and_native_histogram(SCRAPE_DURATION_BUCKETS_SECONDS);
        registry.register_with_unit(
            "metrics_scrape_duration",
            "Metrics endpoint request duration",
            Unit::Seconds,
            scrape_duration.clone(),
        );

        let exposition_size = classic_and_native_histogram(EXPOSITION_SIZE_BUCKETS_BYTES);
        registry.register_with_unit(
            "metrics_exposition_size",
            "Completely encoded successful metrics exposition size",
            Unit::Bytes,
            exposition_size.clone(),
        );

        let scrapes_in_flight = Gauge::default();
        registry.register(
            "metrics_scrapes_in_flight",
            "Metrics encodings currently executing",
            scrapes_in_flight.clone(),
        );

        let last_success_timestamp = FloatGauge::default();
        registry.register_with_unit(
            "metrics_last_success_timestamp",
            "Unix timestamp of the last completely encoded exposition",
            Unit::Seconds,
            last_success_timestamp.clone(),
        );

        Self {
            scrapes,
            scrape_duration,
            exposition_size,
            scrapes_in_flight,
            last_success_timestamp,
        }
    }

    pub(crate) fn record(&self, outcome: ScrapeOutcome, duration_seconds: f64) {
        self.scrapes.get_or_create(&ScrapeLabels { outcome }).inc();
        self.scrape_duration.observe(duration_seconds);
    }

    pub(crate) fn record_success(&self, exposition_size_bytes: usize, timestamp: f64) {
        let bounded_size = u32::try_from(exposition_size_bytes)
            .expect("the exporter hard limit is below the u32 range");
        self.exposition_size.observe(f64::from(bounded_size));
        self.last_success_timestamp.set(timestamp);
    }

    pub(crate) fn begin_encoding(&self) -> EncodingGuard {
        self.scrapes_in_flight.inc();
        EncodingGuard {
            in_flight: self.scrapes_in_flight.clone(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct EncodingGuard {
    in_flight: Gauge,
}

impl Drop for EncodingGuard {
    fn drop(&mut self) {
        self.in_flight.dec();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_labels_are_strict_and_errors_do_not_echo_input() {
        let secret = "private/tenant/repository";
        let error = BuildInfo::new(ProcessRole::Runner, secret, "unknown")
            .validate()
            .expect_err("private version must be rejected");
        assert_eq!(error, BuildInfoError::InvalidVersion);
        assert!(!error.to_string().contains(secret));

        let error = BuildInfo::new(ProcessRole::Runner, "1.0.0", secret)
            .validate()
            .expect_err("private revision must be rejected");
        assert_eq!(error, BuildInfoError::InvalidRevision);
        assert!(!error.to_string().contains(secret));
    }
}
